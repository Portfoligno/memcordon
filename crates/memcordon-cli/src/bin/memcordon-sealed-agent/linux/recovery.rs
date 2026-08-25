use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use super::{CGROUP_ROOT, STATE_ROOT};
use sha2::{Digest, Sha256};

const MAX_RECORD_BYTES: u64 = 16 * 1024;

pub fn recover() -> Result<Vec<String>, String> {
    recover_roots(Path::new(STATE_ROOT), Path::new(CGROUP_ROOT))
}

#[cfg(feature = "test-support")]
pub fn recover_test_roots(state_root: &Path, cgroup_root: &Path) -> Result<Vec<String>, String> {
    recover_roots(state_root, cgroup_root)
}

fn recover_roots(state_root: &Path, cgroup_root: &Path) -> Result<Vec<String>, String> {
    let mut ambiguous = Vec::new();
    let mut authenticated = BTreeSet::new();
    match fs::symlink_metadata(state_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            recover_records(state_root, cgroup_root, &mut authenticated, &mut ambiguous)?;
        }
        Ok(_) => {
            return Err("MCSEALED-RECOVERY: state root is not a no-follow directory".to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("MCSEALED-RECOVERY: {error}")),
    }
    inspect_cgroup_root(cgroup_root, &authenticated, &mut ambiguous)?;
    ambiguous.sort();
    ambiguous.dedup();
    Ok(ambiguous)
}

fn recover_records(
    state_root: &Path,
    cgroup_root: &Path,
    authenticated: &mut BTreeSet<OsString>,
    ambiguous: &mut Vec<String>,
) -> Result<(), String> {
    let entries = fs::read_dir(state_root)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let mut blocked_by_temporary = BTreeSet::new();
    for entry in &entries {
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        let Some(identity) = name_text
            .strip_suffix(".new")
            .filter(|name| super::cgroup::valid_attempt_identity(name))
        else {
            continue;
        };
        if interrupted_transition_is_recoverable(state_root, cgroup_root, identity, entry)? {
            fs::remove_file(entry.path()).map_err(|error| {
                format!("MCSEALED-RECOVERY: interrupted transition rollback failed: {error}")
            })?;
            File::open(state_root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?;
        } else {
            ambiguous.push(name_text.to_owned());
            blocked_by_temporary.insert(identity.to_owned());
        }
    }

    for entry in entries {
        let name = entry.file_name();
        if name.to_str().is_some_and(|name| {
            name.strip_suffix(".new")
                .is_some_and(super::cgroup::valid_attempt_identity)
        }) {
            continue;
        }
        let Some(identity) = name
            .to_str()
            .filter(|name| super::cgroup::valid_attempt_identity(name))
        else {
            ambiguous.push(name.to_string_lossy().into_owned());
            continue;
        };
        if blocked_by_temporary.contains(identity) {
            ambiguous.push(identity.to_owned());
            continue;
        }
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if !file_type.is_file() {
            ambiguous.push(identity.to_owned());
            continue;
        }
        let record = read_record_no_follow(&entry.path())?;
        if !integrity_valid(&record)
            || record.lines().find_map(|line| line.strip_prefix("cgroup=")) != Some(identity)
        {
            ambiguous.push(identity.to_owned());
            continue;
        }
        authenticated.insert(name.clone());
        if record
            .lines()
            .find_map(|line| line.strip_prefix("frontend-pid="))
            .and_then(|value| value.parse::<libc::pid_t>().ok())
            .is_some_and(process_is_live)
        {
            ambiguous.push(identity.to_owned());
            continue;
        }
        let cgroup_path = cgroup_root.join(&name);
        match fs::symlink_metadata(&cgroup_path) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                super::cgroup::AttemptCgroup::authenticated(cgroup_path)
                    .kill_and_retire(Instant::now() + Duration::from_secs(10))?;
            }
            Ok(_) => {
                return Err(format!(
                    "MCSEALED-RECOVERY: authenticated boundary {identity} is not a directory"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("MCSEALED-RECOVERY: {error}")),
        }
        fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn interrupted_transition_is_recoverable(
    state_root: &Path,
    cgroup_root: &Path,
    identity: &str,
    temporary: &fs::DirEntry,
) -> Result<bool, String> {
    let canonical_path = state_root.join(identity);
    let canonical_metadata = match fs::symlink_metadata(&canonical_path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) | Err(_) => return Ok(false),
    };
    let temporary_metadata = fs::symlink_metadata(temporary.path())
        .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?;
    if !temporary
        .file_type()
        .map_err(|error| error.to_string())?
        .is_file()
        || temporary_metadata.uid() != canonical_metadata.uid()
        || temporary_metadata.permissions().mode() & 0o777 != 0o600
        || temporary_metadata.nlink() != 1
        || temporary_metadata.len() > MAX_RECORD_BYTES
    {
        return Ok(false);
    }

    let canonical = match read_record_no_follow(&canonical_path) {
        Ok(record) => record,
        Err(_) => return Ok(false),
    };
    if !integrity_valid(&canonical)
        || canonical
            .lines()
            .find_map(|line| line.strip_prefix("cgroup="))
            != Some(identity)
    {
        return Ok(false);
    }
    if canonical
        .lines()
        .find_map(|line| line.strip_prefix("frontend-pid="))
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .is_some_and(process_is_live)
    {
        return Ok(false);
    }

    let interrupted = match read_record_no_follow(&temporary.path()) {
        Ok(record) => record,
        Err(_) => return Ok(false),
    };
    if interrupted
        .lines()
        .find_map(|line| line.strip_prefix("cgroup="))
        .is_some_and(|bound| bound != identity)
    {
        return Ok(false);
    }

    let cgroup_path = cgroup_root.join(identity);
    match fs::symlink_metadata(&cgroup_path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            super::cgroup::AttemptCgroup::authenticated(cgroup_path)
                .kill_and_retire(Instant::now() + Duration::from_secs(10))?;
        }
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("MCSEALED-RECOVERY: {error}")),
    }
    Ok(true)
}

fn process_is_live(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal zero does not mutate the target process; `pid` is a validated positive
    // scalar, and errno is inspected only when libc reports failure.
    let status = unsafe { libc::kill(pid, 0) };
    status == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn inspect_cgroup_root(
    cgroup_root: &Path,
    authenticated: &BTreeSet<OsString>,
    ambiguous: &mut Vec<String>,
) -> Result<(), String> {
    match fs::symlink_metadata(cgroup_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err("MCSEALED-RECOVERY: cgroup root is not a no-follow directory".to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("MCSEALED-RECOVERY: {error}")),
    }
    for entry in fs::read_dir(cgroup_root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        match super::cgroup::classify_attempt_root_entry(&entry)
            .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?
        {
            super::cgroup::AttemptRootEntry::KernelControl => continue,
            super::cgroup::AttemptRootEntry::Attempt { name, .. } => {
                if !authenticated.contains(&name) {
                    ambiguous.push(name.to_string_lossy().into_owned());
                }
            }
            super::cgroup::AttemptRootEntry::InvalidDirectory(name) => {
                return Err(format!(
                    "MCSEALED-RECOVERY: invalid attempt directory {}",
                    name.to_string_lossy()
                ));
            }
            super::cgroup::AttemptRootEntry::Unsafe(name) => {
                return Err(format!(
                    "MCSEALED-RECOVERY: unsafe cgroup entry {}",
                    name.to_string_lossy()
                ));
            }
        }
    }
    Ok(())
}

fn read_record_no_follow(path: &Path) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?
        .file_type()
        .is_file()
    {
        return Err("MCSEALED-RECOVERY: attempt record is not a regular file".to_owned());
    }
    let mut record = String::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_string(&mut record)
        .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?;
    if record.len() as u64 > MAX_RECORD_BYTES {
        return Err("MCSEALED-RECOVERY: attempt record exceeds size limit".to_owned());
    }
    Ok(record)
}

fn integrity_valid(record: &str) -> bool {
    let Some((body, digest)) = record.rsplit_once("digest=") else {
        return false;
    };
    let expected: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    digest.trim() == expected
}
