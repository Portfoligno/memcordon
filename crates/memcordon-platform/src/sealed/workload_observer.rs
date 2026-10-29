//! Caller-owned held directory publication. These bytes never carry native ownership.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) fn open(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("workload observation directory must be absolute".into());
    }
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    observation_directory(&held).map_err(|error| error.to_string())?;
    Ok(held)
}

pub(super) fn acknowledgment(
    directory: &File,
    name: &str,
    expected: &[u8],
) -> Result<bool, String> {
    observation_directory(directory).map_err(|error| error.to_string())?;
    let mut held = match member(directory, name, false) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = held.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 64 * 1024
    {
        return Err(
            "workload prepared acknowledgement has another caller-owned inode or size".into(),
        );
    }
    let mut bytes = vec![0; usize::try_from(metadata.len()).map_err(|error| error.to_string())?];
    held.read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    let mut extra = [0];
    if held.read(&mut extra).map_err(|error| error.to_string())? != 0 {
        return Err("workload prepared acknowledgement grew during readback".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
    let actual: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let expected: serde_json::Value =
        serde_json::from_slice(expected).map_err(|error| error.to_string())?;
    if actual != expected {
        return Err(
            "workload prepared acknowledgement differs from exact native association/digest".into(),
        );
    }
    verify_observation(directory, name, &held, &metadata, &bytes)
        .map_err(|error| error.to_string())?;
    Ok(true)
}
pub(super) fn member(root: &File, name: &str, write: bool) -> Result<File, std::io::Error> {
    let name = std::ffi::CString::new(name).expect("fixed validated attempt filename");
    let flags = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if write {
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
        } else {
            libc::O_RDONLY
        };
    let fd = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// A pending member is private evidence, never an observation-ready flag. Any
/// failure retains its exclusive inode/name (or the atomically published final
/// name); recovery must not guess that a partially completed publish is absent.
struct PendingObservation {
    file: File,
    staging: String,
    final_name: String,
    complete: std::fs::Metadata,
}

fn observation_directory(root: &File) -> std::io::Result<()> {
    let metadata = root.metadata()?;
    // SAFETY: geteuid has no arguments and only observes this process's identity.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() == 0
    {
        return Err(std::io::Error::other(
            "held observation directory custody differs",
        ));
    }
    Ok(())
}

fn observation_stamp(
    metadata: &std::fs::Metadata,
) -> (u64, u64, u64, u64, u32, u32, u32, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.nlink(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn verify_observation(
    root: &File,
    name: &str,
    held: &File,
    expected: &std::fs::Metadata,
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    observation_directory(root)?;
    let named = member(root, name, false)?;
    let before = held.metadata()?;
    // SAFETY: geteuid only observes the current process's effective identity.
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() != bytes.len() as u64
        || observation_stamp(&before) != observation_stamp(expected)
        || observation_stamp(&named.metadata()?) != observation_stamp(expected)
    {
        return Err(std::io::Error::other(
            "observation held/named inode, size or custody differs",
        ));
    }
    let mut held_chunk = [0; 65536];
    let mut named_chunk = [0; 65536];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = held_chunk.len().min(bytes.len() - offset);
        held.read_exact_at(&mut held_chunk[..count], offset as u64)?;
        named.read_exact_at(&mut named_chunk[..count], offset as u64)?;
        let expected_bytes = &bytes[offset..offset + count];
        if &held_chunk[..count] != expected_bytes || &named_chunk[..count] != expected_bytes {
            return Err(std::io::Error::other(
                "observation complete held/named byte readback differs",
            ));
        }
        offset += count;
    }
    if observation_stamp(&held.metadata()?) != observation_stamp(expected)
        || observation_stamp(&named.metadata()?) != observation_stamp(expected)
    {
        return Err(std::io::Error::other(
            "observation custody changed during complete readback",
        ));
    }
    observation_directory(root)
}

impl PendingObservation {
    fn prepare(root: &File, name: &str, bytes: &[u8]) -> std::io::Result<Self> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(std::io::Error::other("observation final basename differs"));
        }
        observation_directory(root)?;
        let staging = format!(".memcordon-observation-{name}.pending");
        let mut file = member(root, &staging, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let complete = file.metadata()?;
        verify_observation(root, &staging, &file, &complete, bytes)?;
        Ok(Self {
            file,
            staging,
            final_name: name.to_owned(),
            complete,
        })
    }

    fn publish(self, root: &File, bytes: &[u8]) -> std::io::Result<()> {
        verify_observation(root, &self.staging, &self.file, &self.complete, bytes)?;
        let staging =
            std::ffi::CString::new(self.staging.as_str()).expect("validated private basename");
        let final_name =
            std::ffi::CString::new(self.final_name.as_str()).expect("validated final basename");
        // SAFETY: both NUL-terminated basenames belong to the same retained
        // directory descriptor. RENAME_NOREPLACE atomically preserves existing
        // evidence, without exposing the link-count transition of link/unlink.
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                root.as_raw_fd(),
                staging.as_ptr(),
                root.as_raw_fd(),
                final_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        root.sync_all()?;
        let published = self.file.metadata()?;
        // Rename may change ctime. Every other held native fact and all bytes
        // must remain unchanged, and final readback pins the new ctime too.
        let stable = |metadata: &std::fs::Metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.nlink(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            )
        };
        if stable(&published) != stable(&self.complete) {
            return Err(std::io::Error::other(
                "observation native owner changed across atomic publication",
            ));
        }
        verify_observation(root, &self.final_name, &self.file, &published, bytes)
    }
}

pub(super) fn publish_observation(root: &File, name: &str, bytes: &[u8]) -> Result<(), String> {
    PendingObservation::prepare(root, name, bytes)
        .and_then(|pending| pending.publish(root, bytes))
        .map_err(|error| format!("observation publication failed; final={name}; private staging/final evidence retained: {error}"))
}

#[cfg(test)]
#[path = "../../tests/support/workload_observer.rs"]
mod tests;
