//! Optional recording around one authoritative inventory invocation.
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;

#[cfg(windows)]
#[path = "ci-inventory-trace-windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::{Session, qualify_volume, qualify_volume_worker, worker};

/// A readiness marker is bounded and bound to this recorder invocation.
pub fn ready(path: &Path, token: &[u8]) -> io::Result<bool> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(129).read_to_end(&mut bytes)?;
    if token.is_empty() || token.len() > 128 || bytes != token {
        return Err(io::Error::other("invalid recorder handshake"));
    }
    Ok(true)
}

pub fn signal(path: &Path, token: &[u8]) -> io::Result<()> {
    if token.is_empty() || token.len() > 128 {
        return Err(io::Error::other("invalid recorder handshake token"));
    }
    let provisional = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&provisional)?;
    file.write_all(token)?;
    file.sync_all()?;
    std::fs::hard_link(&provisional, path)
}

pub enum WprOperation {
    Start(PathBuf),
    Status,
    Stop(PathBuf),
    Cancel,
}

pub struct WprInvocation {
    arguments: Vec<OsString>,
    working_directory: PathBuf,
}
impl WprInvocation {
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }
}

/// Present the OS-created, extent-verified temporary drive mapping to format.com.
/// Syntax is not authority: the caller must establish native mapping ownership.
pub fn formatter_arguments(volume: &OsStr) -> io::Result<Vec<OsString>> {
    let spelling = volume
        .to_str()
        .ok_or_else(|| io::Error::other("formatter requires an owned drive mapping"))?;
    let mut letters = spelling.strip_suffix(':').unwrap_or_default().chars();
    if !letters
        .next()
        .is_some_and(|letter| letter.is_ascii_uppercase())
        || letters.next().is_some()
    {
        return Err(io::Error::other(
            "formatter requires the verified temporary drive operand",
        ));
    }
    Ok([
        volume.to_owned(),
        "/FS:NTFS".into(),
        "/Q".into(),
        "/Y".into(),
        "/X".into(),
        "/V:MemCordonTrace".into(),
    ]
    .into())
}
impl WprOperation {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Start(_) => "start",
            Self::Status => "status",
            Self::Stop(_) => "stop",
            Self::Cancel => "cancel",
        }
    }
    pub fn arguments(self, instance: &OsStr) -> io::Result<Vec<OsString>> {
        if instance.is_empty() {
            return Err(io::Error::other("an owned WPR instance is required"));
        }
        let mut arguments: Vec<OsString> = match self {
            Self::Start(directory) => vec![
                "-start".into(),
                "ci/inventory.wprp!Inventory.Verbose".into(),
                "-recordtempto".into(),
                directory.into_os_string(),
            ],
            Self::Status => vec!["-status".into(), "collectors".into(), "-details".into()],
            Self::Stop(trace) => vec!["-stop".into(), trace.into_os_string(), "-skipPdbGen".into()],
            Self::Cancel => vec!["-cancel".into()],
        };
        arguments.push("-instancename".into());
        arguments.push(instance.into());
        Ok(arguments)
    }

    pub fn invocation(
        self,
        instance: &OsStr,
        working_directory: &Path,
    ) -> io::Result<WprInvocation> {
        if !working_directory.is_absolute() {
            return Err(io::Error::other(
                "WPR working directory must be an absolute contained path",
            ));
        }
        Ok(WprInvocation {
            arguments: self.arguments(instance)?,
            working_directory: working_directory.into(),
        })
    }
}

pub trait Recording {
    fn start(&mut self) -> io::Result<()>;
    fn finish(&mut self) -> io::Result<()>;
    fn cancel(&mut self) -> io::Result<()>;
    fn observe(&mut self, phase: &str, result: &io::Result<()>);
}

/// Diagnostics cannot retry the workload or replace its authoritative result.
pub fn around<T>(recording: &mut impl Recording, workload: impl FnOnce() -> T) -> T {
    let start = recording.start();
    recording.observe("start", &start);
    let started = start.is_ok();
    if !started {
        let cleanup = recording.cancel();
        recording.observe("cancel_after_start", &cleanup);
    }
    let outcome = workload();
    if started {
        let finish = recording.finish();
        recording.observe("finish", &finish);
        if finish.is_err() {
            let cleanup = recording.cancel();
            recording.observe("cancel_after_finish", &cleanup);
        }
    }
    outcome
}

/// Admit complete ETL files only within the fixed export bound; log prefixes
/// may be retained without treating a truncated log as complete loss evidence.
pub fn copy_bounded(
    source: &Path,
    destination: &Path,
    limit: u64,
    require_complete: bool,
) -> io::Result<u64> {
    if !std::fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(io::Error::other("trace artifact must be a regular file"));
    }
    let mut source = File::open(source)?;
    let length = source.metadata()?.len();
    if require_complete && (length == 0 || length > limit) {
        return Err(io::Error::other(
            "trace export is empty or exceeds volume budget",
        ));
    }
    let mut destination = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let bytes = io::copy(&mut (&mut source).take(limit), &mut destination)?;
    destination.flush()?;
    if require_complete && (bytes != length || source.read(&mut [0_u8; 1])? != 0) {
        return Err(io::Error::other(
            "trace export changed while being retained",
        ));
    }
    Ok(bytes)
}
