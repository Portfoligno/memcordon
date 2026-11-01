//! Relay experiment only: bypass stdio buffering without owning its descriptors.
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};

struct Writer<'a>(BorrowedFd<'a>);

impl Write for Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        rustix::io::write(self.0, bytes).map_err(io::Error::from)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn emit() -> io::Result<()> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    super::binary_streams::large(&mut Writer(stdout.as_fd()), &mut Writer(stderr.as_fd()))
}
