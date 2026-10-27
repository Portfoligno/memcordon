//! Custody checks for a launch-selected frontend output, not launch authority.
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::{
    ffi::OsStrExt,
    fs::{FileExt, MetadataExt},
};
use std::time::Instant;

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl From<&Metadata> for Stamp {
    fn from(value: &Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            uid: value.uid(),
            gid: value.gid(),
            mode: value.mode(),
            links: value.nlink(),
            length: value.len(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}
fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "frontend output original cutoff elapsed",
        ))
    }
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "frontend output custody differs",
    )
}
fn admit(metadata: &Metadata, uid: u32, gid: u32, bound: u64) -> io::Result<Stamp> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() > bound
    {
        return Err(refused());
    }
    Ok(Stamp::from(metadata))
}
fn open(directory: &File, leaf: &OsStr, deadline: Instant) -> io::Result<File> {
    live(deadline)?;
    let owner = File::from(rustix::fs::openat(
        directory,
        leaf,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    live(deadline)?;
    Ok(owner)
}

pub(super) fn read(
    directory: &File,
    leaf: &OsStr,
    expected_uid: u32,
    expected_gid: u32,
    bound: u64,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    live(deadline)?;
    let bytes = leaf.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|byte| matches!(*byte, b'/' | 0))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frontend output requires one native leaf",
        ));
    }
    let directory_metadata = directory.metadata()?;
    if !directory_metadata.is_dir() {
        return Err(refused());
    }
    let directory_before = Stamp::from(&directory_metadata);
    live(deadline)?;
    let owner = open(directory, leaf, deadline)?;
    let before = admit(&owner.metadata()?, expected_uid, expected_gid, bound)?;
    live(deadline)?;
    let capacity = usize::try_from(before.length).map_err(|_| refused())?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| io::Error::other("frontend output allocation bound"))?;
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < before.length {
        live(deadline)?;
        let count = usize::try_from((before.length - offset).min(buffer.len() as u64))
            .map_err(|_| refused())?;
        let received = owner.read_at(&mut buffer[..count], offset)?;
        live(deadline)?;
        if received == 0 {
            return Err(refused());
        }
        output.extend_from_slice(&buffer[..received]);
        offset = offset.checked_add(received as u64).ok_or_else(refused)?;
    }
    live(deadline)?;
    if before != admit(&owner.metadata()?, expected_uid, expected_gid, bound)? {
        return Err(refused());
    }
    let named = open(directory, leaf, deadline)?;
    if before != admit(&named.metadata()?, expected_uid, expected_gid, bound)?
        || before != admit(&owner.metadata()?, expected_uid, expected_gid, bound)?
        || directory_before != Stamp::from(&directory.metadata()?)
    {
        return Err(refused());
    }
    let mut offset = 0usize;
    while offset < output.len() {
        live(deadline)?;
        let count = (output.len() - offset).min(buffer.len());
        let received = named.read_at(&mut buffer[..count], offset as u64)?;
        live(deadline)?;
        if received == 0 || buffer[..received] != output[offset..offset + received] {
            return Err(refused());
        }
        offset = offset.checked_add(received).ok_or_else(refused)?;
    }
    if before != admit(&named.metadata()?, expected_uid, expected_gid, bound)?
        || before != admit(&owner.metadata()?, expected_uid, expected_gid, bound)?
        || directory_before != Stamp::from(&directory.metadata()?)
    {
        return Err(refused());
    }
    live(deadline)?;
    Ok(output)
}
