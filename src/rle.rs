use crate::{MAX_RLE_ENCODE_BITS, MIN_RLE_ENCODE_BITS, NON_RLE_ENCODE_BITS};
use std::fmt::Debug;
use std::{fmt, io};

pub struct Rle<W> {
    status: RleStatus,
    writer: W,
}

#[derive(Copy, Clone)]
enum RleStatus {
    RLE { is_one: bool, counter: u16 },
    MayRLE { is_one: bool, counter: u16 },
    NonRLE { buf: u16, len: u8 },
    Wait,
}

impl<W: io::Write> Rle<W> {
    pub fn new(writer: W) -> Self {
        Rle {
            status: RleStatus::Wait,
            writer,
        }
    }

    #[inline(always)]
    pub fn update(&mut self, byte: u8) -> io::Result<()> {
        trace!("update byte {byte:b}");
        trace!("current status {:?}", self.status);
        match self.status {
            RleStatus::Wait => {
                if byte == 0 {
                    self.status = RleStatus::MayRLE {
                        is_one: false,
                        counter: 8,
                    };
                    trace!("transit to {:?}", self.status);
                } else if byte == 0xFF {
                    self.status = RleStatus::MayRLE {
                        is_one: true,
                        counter: 8,
                    };
                    trace!("transit to {:?}", self.status);
                } else {
                    self.status = RleStatus::NonRLE {
                        buf: byte as u16,
                        len: 8,
                    };
                    trace!("transit to {:?}", self.status);
                }
                Ok(())
            }
            RleStatus::MayRLE { is_one, counter } => {
                let repeats = if is_one {
                    byte.leading_ones()
                } else {
                    byte.leading_zeros()
                };
                let new_counter = counter + repeats as u16;
                trace!("repeats: {repeats}, new_counter: {new_counter}");
                if new_counter >= MIN_RLE_ENCODE_BITS {
                    self.status = RleStatus::RLE {
                        is_one,
                        counter: new_counter,
                    };
                    trace!("transit to {:?}", self.status);
                    if repeats != 8 {
                        self.writer.write_all(&self.status.try_encode().unwrap())?;
                        self.transit_uncompleted(byte, 8 - repeats as u8);
                    }
                } else if repeats == 8 {
                    self.status = RleStatus::MayRLE {
                        is_one,
                        counter: new_counter,
                    };
                    trace!("transit to {:?}", self.status);
                } else {
                    trace!("cannot RLE, convert to non-RLE");
                    debug_assert!(counter < MIN_RLE_ENCODE_BITS);
                    debug_assert!(counter <= NON_RLE_ENCODE_BITS);
                    self.status = self.status.finalize();
                    trace!("transit to {:?}, refeed", self.status);
                    self.update(byte)?;
                }
                Ok(())
            }
            RleStatus::RLE { is_one, counter } => {
                let repeats = if is_one {
                    byte.leading_ones()
                } else {
                    byte.leading_zeros()
                };
                trace!("repeats: {repeats}");
                let mut new_counter = counter + repeats as u16;
                trace!("new_counter: {new_counter}");
                if new_counter >= MAX_RLE_ENCODE_BITS {
                    new_counter = MAX_RLE_ENCODE_BITS;
                    trace!("cut! new_counter: {new_counter}");
                }
                self.status = RleStatus::RLE {
                    is_one,
                    counter: new_counter,
                };
                trace!("transit to {:?}", self.status);

                let read_len = new_counter - counter;
                trace!("read_len: {read_len}");
                if read_len != 8 {
                    // ends here
                    self.writer.write_all(&self.status.try_encode().unwrap())?;

                    if read_len == 0 {
                        self.status = RleStatus::Wait;
                        trace!("transit to {:?}, refeed", self.status);
                        return self.update(byte);
                    }

                    let unread_len = 8 - read_len;
                    trace!("unread_len: {unread_len}");
                    if unread_len == 0 {
                        self.status = RleStatus::Wait;
                        trace!("transit to {:?}", self.status);
                    } else {
                        self.transit_uncompleted(byte, unread_len as u8);
                    }
                }
                Ok(())
            }
            RleStatus::NonRLE { mut buf, len } => {
                // handle transit from MayRLE with full buffer
                if len == NON_RLE_ENCODE_BITS as u8 {
                    self.writer.write_all(&self.status.try_encode().unwrap())?;
                    self.status = RleStatus::Wait;
                    trace!("transit to {:?}", self.status);
                    return self.update(byte);
                }

                let mut new_len = len + 8;
                trace!("new_len: {new_len}");
                if new_len > NON_RLE_ENCODE_BITS as u8 {
                    new_len = NON_RLE_ENCODE_BITS as u8;
                    trace!("cut! new_len: {new_len}");
                }
                let read_len = new_len - len;
                let unread_len = 8 - read_len;
                trace!("unread_len: {unread_len}");
                buf = (buf << read_len) | (byte >> unread_len) as u16;
                self.status = RleStatus::NonRLE {
                    buf,
                    len: new_len,
                };
                trace!("transit to {:?}", self.status);
                if new_len < NON_RLE_ENCODE_BITS as u8 {
                    debug_assert_eq!(unread_len, 0);
                } else {
                    debug_assert_eq!(new_len, NON_RLE_ENCODE_BITS as u8);
                    self.writer.write_all(&self.status.try_encode().unwrap())?;
                    if unread_len != 0 {
                        self.transit_uncompleted(byte, unread_len);
                    } else {
                        self.status = RleStatus::Wait;
                        trace!("transit to {:?}", self.status);
                    }
                }
                Ok(())
            }
        }
    }

    #[inline(always)]
    fn transit_uncompleted(&mut self, byte: u8, unread_len: u8) {
        let mask = (1 << unread_len) - 1;
        let byte = byte & mask;
        trace!("mask: {mask:b}, byte: {byte:b}");
        if byte == 0 {
            self.status = RleStatus::MayRLE {
                is_one: false,
                counter: unread_len as u16,
            };
            trace!("transit to {:?}", self.status);
        } else if byte == mask {
            self.status = RleStatus::MayRLE {
                is_one: true,
                counter: unread_len as u16,
            };
            trace!("transit to {:?}", self.status);
        } else {
            self.status = RleStatus::NonRLE {
                buf: byte as u16,
                len: unread_len,
            };
            trace!("transit to {:?}", self.status);
        }
    }

    pub fn finalize(mut self) -> io::Result<()> {
        self.status = self.status.finalize();
        trace!("last block: {:?}", self.status);
        if let Some(encode) = self.status.try_encode() {
            self.writer.write_all(&encode)?;
        }
        self.writer.flush()
    }
}

impl RleStatus {
    #[inline(always)]
    fn try_encode(self) -> Option<[u8; 2]> {
        match self {
            RleStatus::Wait => None,
            RleStatus::MayRLE { .. } => None,
            RleStatus::NonRLE { mut buf, len } => {
                buf <<= NON_RLE_ENCODE_BITS - len as u16;
                trace!("encode NonRLE {buf:016b}");
                Some([(buf >> 8) as u8, (buf & 0xFF) as u8])
            }
            RleStatus::RLE { is_one, counter } => {
                debug_assert!(counter >= MIN_RLE_ENCODE_BITS);
                debug_assert!(counter <= MAX_RLE_ENCODE_BITS);
                let enc = (1 << 15) | ((is_one as u16) << 14) | (counter - MIN_RLE_ENCODE_BITS);
                debug_assert!(enc != 0xFFFF);
                trace!("encode RLE {enc:016b}");
                Some([(enc >> 8) as u8, (enc & 0xFF) as u8])
            }
        }
    }

    // converting MayRLE to NonRLE
    #[inline(always)]
    fn finalize(self) -> Self {
        match self {
            RleStatus::MayRLE { is_one, counter } => {
                debug_assert!(counter < MIN_RLE_ENCODE_BITS);
                debug_assert!(counter <= NON_RLE_ENCODE_BITS);
                let bits = if is_one { (1 << counter) - 1 } else { 0 };
                let new = RleStatus::NonRLE {
                    buf: bits as u16,
                    len: counter as u8,
                };
                trace!("convert {:?} to {:?}", self, new);
                new
            }
            _ => self,
        }
    }
}

impl Debug for RleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RleStatus::RLE { is_one, counter } => f
                .debug_struct("RLE")
                .field("is_one", &is_one)
                .field("counter", &counter)
                .finish(),
            RleStatus::MayRLE { is_one, counter } => f
                .debug_struct("MayRLE")
                .field("is_one", &is_one)
                .field("counter", &counter)
                .finish(),
            RleStatus::NonRLE { buf, len } => f
                .debug_struct("NonRLE")
                .field("buf", &format!("{buf:0width$b}", width = (*len as usize)))
                .field("len", &len)
                .finish(),
            RleStatus::Wait => f.write_str("Any"),
        }
    }
}

impl<W: io::Write> io::Write for Rle<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for byte in buf.iter() {
            self.update(*byte)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Rle;
    use std::io::Write;
    use std::sync::Once;

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

    static INIT: Once = Once::new();

    /// Setup function that is only run once, even if called multiple times.
    fn setup() {
        INIT.call_once(|| {
            pretty_env_logger::init();
        });
    }

    #[test]
    fn test_rle_encode() {
        setup();
        for (input, expected) in TEST_VECTOR.into_iter() {
            let input = hex::decode(input).unwrap();
            let expected = hex::decode(expected).unwrap();
            let mut out = vec![];
            let mut rle = Rle::new(&mut out);
            rle.write(&input).unwrap();
            rle.finalize().unwrap();
            assert_eq!(expected, out);
        }
    }
}
