use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::CommandSpec;
use crate::{CiError, Result};

pub const CONTEXT_BYTE_LIMIT: u64 = 64 * 1024;

/// Preserve the child result unless cleanup adds a failure. Cleanup failure
/// cannot promote a failed child or publish a successful certificate.
pub fn finish_delegation<T>(
    execution: Result<T>,
    retirement: Result<()>,
    context_cleanup: std::io::Result<()>,
) -> Result<T> {
    if retirement.is_ok() && context_cleanup.is_ok() {
        return execution;
    }
    let execution_status = match &execution {
        Ok(_) => "succeeded".to_owned(),
        Err(error) => format!("failed: {error}"),
    };
    let retirement_status = match retirement {
        Ok(()) => "succeeded".to_owned(),
        Err(error) => format!("failed: {error}"),
    };
    let context_status = match context_cleanup {
        Ok(()) => "succeeded".to_owned(),
        Err(error) => format!("failed: {error}"),
    };
    Err(CiError::Message(format!(
        "delegation execution {execution_status}; retirement {retirement_status}; context cleanup {context_status}"
    )))
}

pub fn read_bounded_regular(path: &Path) -> Result<Vec<u8>> {
    read_bounded_regular_owned(path, None)
}

pub fn read_bounded_regular_owned(path: &Path, expected_uid: Option<u32>) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(CiError::Message(
            "expected regular standard evidence file".into(),
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 1;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if expected_uid.is_some_and(|uid| metadata.uid() != uid) {
            return Err(CiError::Message(
                "standard context belongs to another user".into(),
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || expected_uid.is_some()
        {
            return Err(CiError::Message(
                "standard context is a reparse point or has unsupported Unix ownership".into(),
            ));
        }
    }
    if !file.metadata()?.is_file() || file.metadata()?.len() > CONTEXT_BYTE_LIMIT {
        return Err(CiError::Message(
            "standard evidence file exceeds bound".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(CONTEXT_BYTE_LIMIT + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > CONTEXT_BYTE_LIMIT) {
        return Err(CiError::Message(
            "standard evidence grew beyond bound".into(),
        ));
    }
    Ok(bytes)
}

pub fn publish_candidate(
    candidate: &Path,
    destination: &Path,
    validated_bytes: &[u8],
) -> Result<()> {
    let directory = destination
        .parent()
        .ok_or_else(|| CiError::Message("candidate destination has no parent".into()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    std::io::Write::write_all(&mut temporary, validated_bytes)?;
    temporary.as_file().sync_all()?;
    // All fallible candidate cleanup precedes publication. A failed cleanup can
    // never leave a success artifact behind.
    fs::remove_file(candidate)?;
    temporary
        .persist_noclobber(destination)
        .map_err(|error| CiError::Io(error.error))?;
    Ok(())
}

/// Native operations required by an owned transient-unit lease. Query returns
/// raw systemctl bytes so the lease always applies the production state parser.
pub trait UnitControl {
    fn query(&self, root: &Path, unit: &OsStr) -> Result<Vec<u8>>;
    fn stop(&self, root: &Path, unit: &OsStr) -> Result<()>;
}

/// Production control uses native argv and bounded CommandSpec execution.
pub struct NativeUnitControl;

impl UnitControl for NativeUnitControl {
    fn stop(&self, root: &Path, unit: &OsStr) -> Result<()> {
        CommandSpec::new("/usr/bin/sudo", root, Duration::from_secs(60))
            .args([
                OsString::from("--non-interactive"),
                "--".into(),
                "/usr/bin/systemctl".into(),
                "stop".into(),
                unit.to_os_string(),
            ])
            .run()?;
        Ok(())
    }
    fn query(&self, root: &Path, unit: &OsStr) -> Result<Vec<u8>> {
        CommandSpec::new("/usr/bin/systemctl", root, Duration::from_secs(30))
            .args([
                OsString::from("show"),
                "--property".into(),
                "LoadState".into(),
                "--property".into(),
                "ActiveState".into(),
                unit.to_os_string(),
            ])
            .run()
    }
}

/// Owns precisely one transient unit. The systemd runtime limit remains a
/// second cleanup boundary if the coordinator is killed before Drop runs.
pub struct DelegatedUnitLease<C: UnitControl = NativeUnitControl> {
    root: PathBuf,
    unit: OsString,
    armed: bool,
    control: C,
}

impl DelegatedUnitLease<NativeUnitControl> {
    pub fn new(root: &Path, unit: OsString) -> Result<Self> {
        Self::with_control(root, unit, NativeUnitControl)
    }
}

impl<C: UnitControl> DelegatedUnitLease<C> {
    pub fn with_control(root: &Path, unit: OsString, control: C) -> Result<Self> {
        let name = unit
            .to_str()
            .ok_or_else(|| CiError::Message("invalid unit encoding".into()))?;
        if !name.starts_with("memcordon-standard-")
            || !name.ends_with(".service")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(CiError::Message("invalid owned standard unit name".into()));
        }
        Ok(Self {
            root: root.into(),
            unit,
            armed: true,
            control,
        })
    }
    fn stop(&self) -> Result<()> {
        self.control.stop(&self.root, &self.unit)
    }
    fn retired(&self) -> Result<bool> {
        let bytes = self.control.query(&self.root, &self.unit)?;
        retired_state(&bytes)
    }
    pub fn retire(&mut self) -> Result<()> {
        match self.retired() {
            Ok(true) => {
                self.armed = false;
                return Ok(());
            }
            Ok(false) | Err(_) => self.stop()?,
        }
        if !self.retired()? {
            return Err(CiError::Message(
                "owned standard unit remains active after stop".into(),
            ));
        }
        self.armed = false;
        Ok(())
    }
}

impl<C: UnitControl> Drop for DelegatedUnitLease<C> {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = self.stop()
        {
            eprintln!("owned standard unit emergency cleanup failed: {error}");
        }
    }
}

pub fn retired_state(bytes: &[u8]) -> Result<bool> {
    let text = std::str::from_utf8(bytes).map_err(|error| CiError::Message(error.to_string()))?;
    let mut active = None;
    let mut load = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("ActiveState=") {
            if active.replace(value).is_some() {
                return Err(CiError::Message("duplicate unit active state".into()));
            }
        } else if let Some(value) = line.strip_prefix("LoadState=") {
            if load.replace(value).is_some() {
                return Err(CiError::Message("duplicate unit load state".into()));
            }
        } else {
            return Err(CiError::Message("unrecognized unit state".into()));
        }
    }
    match (load, active) {
        (Some("not-found" | "loaded"), Some("inactive" | "failed")) => Ok(true),
        (Some("loaded"), Some("active" | "activating" | "deactivating" | "reloading")) => Ok(false),
        _ => Err(CiError::Message(
            "unrecognized or incomplete unit retirement state".into(),
        )),
    }
}
