#![allow(clippy::collapsible_else_if)]

use crate::{MIN_RLE_ENCODE_BITS, NON_RLE_ENCODE_BITS};
use std::io;

pub struct DeRle<W> {
    buf: u8,
    bit_len: u8,
    writer: W,
}

impl<W: io::Write> DeRle<W> {
    pub fn new(writer: W) -> DeRle<W> {
        DeRle {
            buf: 0,
            bit_len: 0,
            writer,
        }
    }

    #[inline(always)]
    pub fn update(&mut self, enc: u16) -> io::Result<()> {
        trace!("buf: {:08b}, bit_len: {}", self.buf, self.bit_len);
        let is_rle = (enc >> 15) == 1;
        if is_rle {
            let is_one = ((enc >> 14) & 1) == 1;
            let mut length = (enc & 0x3FFF) + MIN_RLE_ENCODE_BITS; // low 14 bits
            trace!("rle encoding: is_one={is_one}, length={length}");
            if self.bit_len != 0 {
                let take = 8 - self.bit_len;
                length -= take as u16;
                trace!("rle encoding: complete incomplete take={take}");
                if is_one {
                    self.buf |= (1 << take) - 1;
                } else {
                    self.buf &= ((1 << self.bit_len) - 1) << take;
                }
                trace!("decode: 0x{:02X}", self.buf);
                self.writer.write_all(&[self.buf])?;
                self.buf = 0;
                self.bit_len = 0;
            }
            let bytes = length / 8;
            trace!("rle encoding: bytes={bytes}");
            for _ in 0..bytes {
                if is_one {
                    trace!("decode: 0xFF");
                    self.writer.write_all(&[0xFF])?;
                } else {
                    trace!("decode: 0x00");
                    self.writer.write_all(&[0])?;
                }
            }
            let rem = length % 8;
            if rem != 0 {
                debug_assert_eq!(self.buf, 0);
                if is_one {
                    self.buf = ((1 << rem) - 1) << (8 - rem);
                }
                trace!(
                    "rle encoding: rem bytes={rem}, buf={:08b}, bit_len={}",
                    self.buf,
                    self.bit_len
                );
                self.bit_len = rem as u8;
            }
        } else {
            if self.bit_len != 0 {
                let take_bits = 8 - self.bit_len;
                trace!("rle encoding: complete incomplete take={take_bits}");
                let offset = NON_RLE_ENCODE_BITS as u8 - take_bits;
                self.buf |= (enc >> offset) as u8;
                trace!("decode: 0x{:02X}", self.buf);

                let mask = (1 << offset) - 1;
                let enc = enc & mask;

                self.writer
                    .write_all(&[self.buf, (enc >> (offset - 8)) as u8])?;
                self.buf = 0;
                self.bit_len = 0;

                let offset = offset - 8;
                if offset > 0 {
                    debug_assert!(offset < 8);
                    self.buf = ((enc & ((1 << offset) - 1)) << (8 - offset)) as u8;
                    self.bit_len = offset;
                }
            } else {
                self.writer.write_all(&[(enc >> 7) as u8])?;
                debug_assert_eq!(self.buf, 0);
                self.buf = ((enc & 0x7F) << 1) as u8;
                self.bit_len = 7;
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn finalize(mut self) -> io::Result<()> {
        debug_assert_eq!(self.buf << self.bit_len, 0);
        if self.bit_len != 0 {
            self.writer.write_all(&[self.buf])?;
        }
        Ok(())
    }
}

impl<W: io::Write> io::Write for DeRle<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let iter = buf.chunks_exact(2);
        let rem = iter.remainder().len();
        for bytes in iter {
            self.update(((bytes[0] as u16) << 8) | (bytes[1] as u16))?;
        }
        if rem == 0 {
            Ok(buf.len())
        } else {
            debug_assert_eq!(rem, 1);
            Ok(buf.len() - 1)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.len() % 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DeRLE do not have buffer",
            ));
        }
        let wrote = self.write(buf).unwrap();
        debug_assert_eq!(wrote, buf.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{DeRle, TEST_VECTOR};
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
    fn test_derle_encode() {
        setup();
        for (expected, input) in TEST_VECTOR.into_iter() {
            let input = hex::decode(input).unwrap();
            let expected = hex::decode(expected).unwrap();
            let mut out = vec![];
            let mut derle = DeRle::new(&mut out);
            derle.write(&input).unwrap();
            derle.finalize().unwrap();
            assert_eq!(expected, out[..expected.len()]);
        }
    }
}
