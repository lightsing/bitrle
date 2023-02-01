use std::io;

pub struct DeRle<W> {
    writer: W,
}

enum DeRleStatus {

}

impl<W: io::Write> DeRle<W> {
    pub fn new(writer: W) -> DeRle<W> {
        DeRle { writer }
    }

    pub fn update(&mut self, enc: u16) {

    }
}

impl<W: io::Write> io::Write for DeRle<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {

    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}