//! Narrow read-only authority for content identity of protected system files.
use std::io;
use std::path::{Path, PathBuf};

use sha2::Sha256;
use sha2::digest::OutputSizeUser;

/// Only privileged fallback execution takes this gate. Ordinary readers keep
/// their independent executor credits and never hold it.
#[derive(Default)]
pub struct ProtectedDigestGate(std::sync::Mutex<()>);

impl ProtectedDigestGate {
    pub fn run<T>(
        &self,
        cancellation: &crate::inventory_progress::CancellationToken,
        action: impl FnOnce() -> crate::Result<T>,
    ) -> crate::Result<T> {
        cancellation.check()?;
        let _guard = self
            .0
            .lock()
            .map_err(|_| crate::CiError::Message("protected digest gate poisoned".into()))?;
        cancellation.check()?;
        let result = action();
        cancellation.check()?;
        result
    }
}

pub fn validate_system_path(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::other("system digest requires an absolute path"));
    }
    let canonical = path.canonicalize()?;
    if !["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/lib"]
        .iter()
        .any(|root| canonical.starts_with(root) && canonical != Path::new(root))
    {
        return Err(io::Error::other(
            "system digest path is outside native system roots",
        ));
    }
    Ok(canonical)
}

pub fn parse_digest_output(bytes: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
    let digest = text
        .strip_suffix('\n')
        .ok_or_else(|| io::Error::other("system digest response lacks terminator"))?;
    if digest.len() != <Sha256 as OutputSizeUser>::output_size() * 2
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::other("invalid system digest response"));
    }
    Ok(digest.to_owned())
}

#[cfg(target_os = "macos")]
pub fn protected_digest(path: &Path) -> io::Result<String> {
    use sha2::Digest;
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let canonical = validate_system_path(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&canonical)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other(
            "system digest requires a root-owned non-writable regular file",
        ));
    }
    let descriptor_path = memcordon_testkit::macos_read_only_descriptor_path(&file)?;
    if validate_system_path(&descriptor_path)? != canonical {
        return Err(io::Error::other(
            "system digest descriptor escaped selected path",
        ));
    }
    let selected = fs::symlink_metadata(&canonical)?;
    if !selected.is_file() || selected.dev() != metadata.dev() || selected.ino() != metadata.ino() {
        return Err(io::Error::other(
            "system digest input changed while opening",
        ));
    }
    let limit = 1024 * 1024 * 1024;
    if metadata.len() > limit {
        return Err(io::Error::other("system digest input exceeds byte limit"));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    let mut total = 0;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > limit {
            return Err(io::Error::other("system digest input exceeds byte limit"));
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if total != metadata.len()
        || after.len() != metadata.len()
        || after.mtime() != metadata.mtime()
        || after.mtime_nsec() != metadata.mtime_nsec()
        || after.ctime() != metadata.ctime()
        || after.ctime_nsec() != metadata.ctime_nsec()
    {
        return Err(io::Error::other(
            "system digest input changed while reading",
        ));
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(not(target_os = "macos"))]
pub fn protected_digest(_path: &Path) -> io::Result<String> {
    Err(io::Error::other(
        "protected system digest is supported only on macOS",
    ))
}
