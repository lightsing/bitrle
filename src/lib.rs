//! # RLE Encoding Scheme
//!
//! ```
//!         MSB              LSB
//!          │                │
//!          ▼                ▼
//!         0XXX XXXX XXXX XXXX
//!         ▲
//! NOT_RLE─┘
//! ```
//!
//! When not using RLE, encode 15 bits.
//!
//! ```
//!          MSB             LSB
//!           │               │
//!           ▼               ▼
//!         1XXX XXXX XXXX XXXX
//!         ▲▲
//!  IS_RLE─┘│
//!         0/1
//! ```
//!
//! Treat last 14 bits as unsigned integer N.
//! since we won't use RLE when there's less than 15 bits to encode,
//! the actual bits encoded will be N + 16.
//!
//! Thus, in best case, 2 bytes can encode 2^14 + 16 - 1 (16399) bits (actually 16398, see below),
//! efficiency is ~1024.
//! In worst case, 2 bytes can encode 15 bits, efficiency is 0.9375.
//!
//! The encoding did not include size.
//! The decoder MUST know the payload size since encoder pads zero on tail
//!
//! # Streaming Scheme
//!
//! Trade off using 0xFFFF as starting flag, this will reduce the RLE cap to 16399 bits.
//!
//! The stream is made up with frames.
//! The encoded length of a frame is fixed to N bytes.
//!
//! A frame MUST start with 0xFFFF.
//!
//! If a frame is ended with non-RLE 16bits, any excess bits will be discarded.
//! If a frame is ended with RLE 16bits, the length MUST match otherwise the frame will be treated as malformed.
//!
//! A frame MUST end with a CRC-16-CCITT of every RLE/non-RLE 16bits data (0xFFFF is excluded).
//! If the checksum mismatches, the frame will be treated as malformed.
//!
//! Any malformed frame will be discarded.
//!
//! Total 4 bytes overhead of each frame is introduced.
#![allow(clippy::upper_case_acronyms)]

#[macro_use]
extern crate log;

mod derle;
mod rle;

pub use derle::DeRle;
pub use rle::Rle;

/// how many bits will be encoded
const NON_RLE_ENCODE_BITS: u16 = 2 * 8 - 1;
const MIN_RLE_ENCODE_BITS: u16 = 2 * 8;
const MAX_RLE_ENCODE_BITS: u16 = 0b11111111111110 + MIN_RLE_ENCODE_BITS;

#[cfg(test)]
const TEST_VECTOR: [(&str, &str); 76] = [
    (
        "FFFFFFFFF21cad8766dec123488d4c386770951b9022d3",
        "c01410e5361d4dbd41232446530e0cee09515c810b4c",
    ),
    ("FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFF", "c0308030c018"),
    (
        "F0F0F0F0F0F0F0F0F0F0F0F0F0F0FFFFFFFFFFFFFFFF0000000000FFFFFFFFFFFFFF",
        "78783c3c1e1e0f0f078743c361e170ffc0288018c028",
    ),
    ("FF00000000000000000000", "7f808039"),
    ("00FFFFFFFFFFFFFF0000000000", "007fc0218018"),
    (
        "FFFF00FFFFFFFFFFFFFFFFFF00000000000000000000",
        "c000007fc0318040",
    ),
    ("0F0F0F0F0F0F0F0F0F0F", "078743c361e170f078783c00"),
    (
        "FFFFFFFF000000000000000000FFFFFFFFFFFFFFFFFF",
        "c0108038c038",
    ),
    ("00000000", "8010"),
    (
        "0F0F0F0F0F0FFFFFFFFFFFFFFFFFFF00000000000000000000F0F0F0",
        "078743c361e1c03b804078783c00",
    ),
    (
        "FFFFFFFFFFFFFF0F0F0F0F0F0F0F0F0F0FFFFFFFFFFFFFFFFFFFFFFFFF00000000",
        "c028078743c361e170f078783fffc0468010",
    ),
    (
        "0000000000FFFFFFFFFFFFFFFF000000000000000000FFFFFFFFFFFFFFFFFFFF",
        "8018c0308038c040",
    ),
    (
        "000000000000FFFFFFFFFFFFFFFFFF0F0F0F0F00000000",
        "8020c038078743c360008003",
    ),
    (
        "000000000000F0F0F0F0F000000000000000FFFFFFFFFFFFFFFFFF",
        "802078783c3c1e008023c038",
    ),
    (
        "000000000000000000000000FFFFFFFFFFFFFFFFF0F0F0F0F0F0F0F0F0F0",
        "8050c034078743c361e170f078780000",
    ),
    (
        "FFFFFFFFFFFFFFFFFFFFFFFF0F0F00000000FFFFFFFFFF",
        "c050078740008002c018",
    ),
    (
        "FFFFFFFFFFFFFFFFFF0000000000FFFF000000000000000000000000000000000000000000",
        "c0388018c0008098",
    ),
    ("000000000000000000000000", "8050"),
    ("F0F0F0F0F0F0FFFFFFFF000000", "78783c3c1e1e0fffc0048008"),
    (
        "00000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "8088c070",
    ),
    ("FFFFFF000000FFFFFFFFFFFFFFFFFFFF", "c0088008c040"),
    ("000000000000000000000000000000000000", "8080"),
    (
        "000000000000FFFFFFFFFFFFFFFFFFFF0000000000000000",
        "8020c0408030",
    ),
    ("00000000000000000000", "8040"),
    ("FFFFFFFFFFFFFFFFFFFFFFFFFFFF", "c060"),
    ("0000000000000000", "8030"),
    (
        "FFFF00000000000000F0F0F00F0F0F0F0F0F0000FFFFFF",
        "c000802878783c0361e170f078780003c006",
    ),
    ("0000000000FFFFFFFFFFFFFFFFFF", "8018c038"),
    (
        "FFFFFFFFFF0000000000000000000000000000000000000000",
        "c0188090",
    ),
    ("0F0F0F0F0F0F0000FFFFFFFFFFFFFF", "078743c361e1700007ffc01d"),
    (
        "0F0F0F0F0F0F0F0F0000000000000000",
        "078743c361e170f078008025",
    ),
    ("FFFFFFFFFFFFF0F0F0F0F0F0F0", "c024078743c361e17000"),
    ("0000000000", "8018"),
    (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0F0F0F0F0F0F0",
        "c06c078743c361e17000",
    ),
    (
        "000000000000000000000000000000000000FFFF000000000000000000",
        "8080c0008038",
    ),
    ("00000000000000000000", "8040"),
    (
        "FFFFFF0F0F0F0F0F0F0000000000000000000000000000FFFFFFFFFFFFFFFF",
        "c008078743c361e170008054c030",
    ),
    ("F0F0F0F0F0F0F0F0F0F0", "78783c3c1e1e0f0f07874000"),
    ("F0F0F0F0F0F0F0F0F0000F0F0F", "78783c3c1e1e0f0f0780003c1e1e"),
    (
        "00000000000000FFFFFFF0F0F0F0F0F0F0F0F0",
        "8028c00c078743c361e170f07800",
    ),
    ("FFFFFFFFFFFFFFFFFF00000000000000", "c0388028"),
    (
        "F0F00F000000000000000000000000000000000000FF00000000000F0F000000000000000000",
        "787803c0807a7f80801578788035",
    ),
    (
        "0F0F0F0F0F0F0F00FFFFFFFF0F000000000000",
        "078743c361e170f007ffc00507808019",
    ),
    (
        "FFFFFFFFFFFFFFF00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "c02c007fc09d",
    ),
    (
        "0F0F0F0F0FF0F0F0F0F0F0F0F0F0F0",
        "078743c361fe0f0f078743c361e170f0",
    ),
    (
        "000000000000000000F0F0F0F0F0F0F0F0F0F0",
        "803878783c3c1e1e0f0f07874000",
    ),
    (
        "FF0000FFFFFF00000000000000000000F0F0000000",
        "7f80003fc002804078788009",
    ),
    (
        "0F0FFFFFFFFFFFFF0F0F0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "0787c021078743ffc06a",
    ),
    ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "c088"),
    (
        "FFFFFFFFFFFFFFF0F000000000FFFFFFFFFFFF0000000000000000",
        "c02c0780800dc0208030",
    ),
    ("FFFFFFFFFFFFFFFFFFFFFFFFFF", "c058"),
    (
        "F0F0F0F0F0F0F0F0F0F0FFFFFFFF00FFFFFFFFFFFFFFFFFFFFFF00000000000000",
        "78783c3c1e1e0f0f078743ffc006007fc0418028",
    ),
    (
        "F0F0F00000FFFFFFFFFFFFFFFF0FFFFF000000000F0F0F0F",
        "78783c00001fc02b07ff7fc0800e78783c3c",
    ),
    (
        "00000000000000FFFFF0F0F0F0F0F0F0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "8028c004078743c361e170ffc080",
    ),
    ("0000000000000000000000000000", "8060"),
    ("F0F0F0F0000000000000000000", "78783c3c803a"),
    ("00FFFFFFFFFFFFFFFFFFFF00000000", "007fc0398010"),
    (
        "FFFFFFFFFF000000000000000000FFFFFFFFFFFFFF0000000000FFFFFFFFFFFFFF",
        "c0188038c0288018c028",
    ),
    (
        "00000F0F0F0F0F0F0F0F0F0F0F000000000000000000",
        "800478783c3c1e1e0f0f078743c08032",
    ),
    ("FFFFF0F0F0F0F0F0F0F0000000", "c004078743c361e170f08008"),
    (
        "00000000000000000000000000000000000000FFFFFFFFFFFFFFFF0F0F0F0F0F",
        "8088c030078743c361e0",
    ),
    ("FFFFFFFF000000", "c0108008"),
    (
        "FFFF0000000000000000F0F0F0F0F0F0F0F0",
        "c000803078783c3c1e1e0f0f0000",
    ),
    (
        "0FFFFFFFFFFFFFFFF0F0F0FFFFFFFFFFFFFFFFFFFFFFFF000000000000000000",
        "07ffc025078743ffc0468038",
    ),
    (
        "FFFFFFFFFFFFFFFFFFFF0F0F0F0F0F0F0F0F0F0FFFFFFFFFFFFFFFFFFF0F0F0F0F0F0F0F0F",
        "c040078743c361e170f078783fffc02e078743c361e170f07800",
    ),
    ("FFFFFF", "c008"),
    ("F0F0F0F0F0F0F0F0F0", "78783c3c1e1e0f0f0780"),
    (
        "0000000000000000000F0F0F0FF0F0F0F0F0F0F0F0F0",
        "803c78783c3f61e170f078783c3c1e00",
    ),
    ("FFFFFFFFFFFFFFFFFFFF", "c040"),
    (
        "0FFFFFFFFFFFFFFFFF0000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000",
        "07ffc0298018c0688010",
    ),
    ("000000000000FFFFFFFFFFFFFFFF", "8020c030"),
    (
        "FFFFFFFFFF0000000000000000F0F0F0FFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFF",
        "c018803078783c3fc0428000c030",
    ),
    ("000000000000000000", "8038"),
    ("FFFFFF", "c008"),
    ("000000000000000000FFFFFFFFFF000000000000", "8038c0188020"),
    ("0000000000F0F0F0F0F0F0F0F0F0", "801878783c3c1e1e0f0f0780"),
];
