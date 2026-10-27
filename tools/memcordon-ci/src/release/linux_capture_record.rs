//! A committed prefix of a continuing capture, never an immutable whole-file claim.
use std::{
    fs::{File, Metadata, OpenOptions},
    io,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

pub const RECORD_BOUND: usize = 16 * 1024 * 1024;
pub struct Record {
    reader: File,
    path: PathBuf,
    original: Metadata,
    bytes: Vec<u8>,
}
pub struct Publisher {
    bytes: Vec<u8>,
    sender: Option<std::sync::mpsc::SyncSender<io::Result<Record>>>,
}
pub fn channel() -> (Publisher, std::sync::mpsc::Receiver<io::Result<Record>>) {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    (
        Publisher {
            bytes: Vec::new(),
            sender: Some(sender),
        },
        receiver,
    )
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    (a.dev(), a.ino(), a.uid(), a.gid(), a.mode(), a.nlink())
        == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode(), b.nlink())
}
fn policy(m: &Metadata, uid: u32) -> bool {
    m.is_file() && m.uid() == uid && m.nlink() == 1 && m.mode() & 0o022 == 0
}
impl Publisher {
    /// Called only after the capture writer successfully writes and flushes this chunk.
    pub fn flushed(&mut self, writer: &File, path: &Path, chunk: &[u8]) -> io::Result<()> {
        if self.sender.is_none() {
            return Ok(());
        }
        let count = chunk
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(chunk.len(), |end| end + 1);
        if self
            .bytes
            .len()
            .checked_add(count)
            .is_none_or(|len| len > RECORD_BOUND)
        {
            return Err(invalid("capture first record exceeds bound"));
        }
        self.bytes.extend_from_slice(&chunk[..count]);
        if self.bytes.last() != Some(&b'\n') {
            return Ok(());
        }
        let original = writer.metadata()?;
        let reader = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if !same(&original, &reader.metadata()?) || !policy(&original, original.uid()) {
            return Err(invalid("capture first record original owner differs"));
        }
        let record = Record {
            reader,
            path: path.to_owned(),
            original,
            bytes: std::mem::take(&mut self.bytes),
        };
        self.sender
            .take()
            .expect("publication sender")
            .try_send(Ok(record))
            .map_err(|_| invalid("capture first record receiver lost"))
    }
    pub fn fail(&mut self, error: io::Error) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.try_send(Err(error));
        }
    }
    pub fn eof(&mut self) {
        self.fail(invalid("capture EOF before complete first record"));
    }
}
impl Record {
    pub fn read(&self, deadline: Instant, required_uid: u32) -> io::Result<Vec<u8>> {
        let verify = || -> io::Result<()> {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original capture record cutoff elapsed",
                ));
            }
            let held = self.reader.metadata()?;
            let named = std::fs::symlink_metadata(&self.path)?;
            if !same(&held, &self.original)
                || !same(&named, &self.original)
                || !policy(&held, required_uid)
                || !policy(&named, required_uid)
                || held.len() < self.bytes.len() as u64
                || named.len() < self.bytes.len() as u64
            {
                return Err(invalid("capture committed prefix custody differs"));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original capture record cutoff elapsed",
                ));
            }
            Ok(())
        };
        verify()?;
        let mut bytes = vec![0; self.bytes.len()];
        self.reader.read_exact_at(&mut bytes, 0)?;
        verify()?;
        if bytes != self.bytes {
            return Err(invalid("capture committed prefix bytes changed"));
        }
        Ok(bytes)
    }
}
