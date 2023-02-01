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
                self.status = RleStatus::NonRLE { buf, len: new_len };
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
    use crate::TEST_VECTOR;
    use std::io::Write;
    use std::sync::Once;

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
