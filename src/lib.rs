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

#[macro_use]
extern crate log;

mod rle;
pub use rle::{Rle, RleStatus};

/// how many bits will be encoded
const NON_RLE_ENCODE_BITS: u16 = 2 * 8 - 1;
const MIN_RLE_ENCODE_BITS: u16 = 2 * 8;
const MAX_RLE_ENCODE_BITS: u16 = 0b11111111111110 + MIN_RLE_ENCODE_BITS;
