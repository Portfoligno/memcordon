//! An owned empty peer output product, never a host NUL dependency.
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Instant,
};

pub const OUTPUT: &str = "tcp-peer-stdout.bin";
pub const RECORD: &str = "tcp-peer-stdout.json";
const PREFIX_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Identity {
    volume: u64,
    index: u64,
    attributes: u32,
    links: u64,
}
impl Identity {
    fn same_object(&self, other: &Self) -> bool {
        self.volume == other.volume && self.index == other.index
    }
}

#[derive(Debug)]
struct Failure {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; peer stdout: {}", self.primary, self.secondary)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
pub fn preserve(primary: io::Error, secondary: io::Result<()>) -> io::Error {
    match secondary {
        Ok(()) => primary,
        Err(secondary) => io::Error::new(primary.kind(), Failure { primary, secondary }),
    }
}

fn live(cutoff: Option<Instant>) -> io::Result<()> {
    if cutoff.is_some_and(|cutoff| Instant::now() >= cutoff) {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "peer stdout original cutoff reached",
        ))
    } else {
        Ok(())
    }
}

fn within<T>(cutoff: Option<Instant>, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    live(cutoff)?;
    #[cfg(windows)]
    let timer = cutoff
        .map(memcordon_platform::WindowsSynchronousIoDeadline::start)
        .transpose()
        .map_err(io::Error::other)?;
    let result = operation();
    #[cfg(windows)]
    let settled = match timer {
        Some(timer) => timer.finish().map_err(io::Error::other),
        None => Ok(()),
    };
    #[cfg(not(windows))]
    let settled = Ok(());
    match (result, settled) {
        (Err(primary), secondary) => Err(preserve(primary, secondary)),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => {
            live(cutoff)?;
            Ok(value)
        }
    }
}

#[cfg(windows)]
fn inspect(file: &File, cutoff: Option<Instant>) -> io::Result<(Identity, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // The original owned File remains live; no path is reopened for identity.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    live(cutoff)?;
    // FILE_TYPE_UNKNOWN is ambiguous; clear the documented error slot before
    // the one query so an unknown type cannot inherit a stale native failure.
    unsafe { windows_sys::Win32::Foundation::SetLastError(0) };
    let kind = unsafe { GetFileType(file.as_raw_handle()) };
    let kind_error = (kind == 0).then(io::Error::last_os_error);
    if let Some(error) = kind_error {
        return Err(if error.raw_os_error() == Some(0) {
            io::Error::other("held peer stdout file type is unknown")
        } else {
            error
        });
    }
    live(cutoff)?;
    if info.dwFileAttributes
        & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)
        != 0
        || info.nNumberOfLinks != 1
        || kind != FILE_TYPE_DISK
    {
        return Err(io::Error::other(
            "peer stdout is not a single-link ordinary disk file",
        ));
    }
    Ok((
        Identity {
            volume: u64::from(info.dwVolumeSerialNumber),
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            attributes: info.dwFileAttributes,
            links: u64::from(info.nNumberOfLinks),
        },
        (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
    ))
}

#[cfg(unix)]
fn inspect(file: &File, cutoff: Option<Instant>) -> io::Result<(Identity, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    live(cutoff)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::other(
            "peer stdout is not a single-link ordinary file",
        ));
    }
    Ok((
        Identity {
            volume: metadata.dev(),
            index: metadata.ino(),
            attributes: 0,
            links: metadata.nlink(),
        },
        metadata.len(),
    ))
}

fn new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        // Keep original namespace custody without granting deletion sharing.
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    options.open(path)
}

fn close(file: File) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawHandle, IntoRawHandle};
        let raw = file.into_raw_handle();
        // Exactly this owned handle, never a remote or recycled scalar.
        if unsafe { windows_sys::Win32::Foundation::CloseHandle(raw) } == 0 {
            let error = io::Error::last_os_error();
            // An unsuccessful close cannot justify relinquishing the owner.
            std::mem::forget(unsafe { File::from_raw_handle(raw) });
            return Err(error);
        }
    }
    #[cfg(not(windows))]
    drop(file);
    Ok(())
}

pub struct Owned {
    file: File,
    identity: Identity,
    record: PathBuf,
    cutoff: Option<Instant>,
}

impl Owned {
    pub fn create(root: &Path, cutoff: Option<Instant>) -> io::Result<Self> {
        within(cutoff, || {
            let file = new_file(&root.join(OUTPUT))?;
            live(cutoff)?;
            let (identity, size) = inspect(&file, cutoff)?;
            live(cutoff)?;
            if size != 0 {
                return Err(io::Error::other("fresh peer stdout is nonempty"));
            }
            Ok(Self {
                file,
                identity,
                record: root.join(RECORD),
                cutoff,
            })
        })
    }

    pub fn stdio(&self) -> io::Result<Stdio> {
        within(self.cutoff, || self.file.try_clone().map(Stdio::from))
    }

    fn publish(&self, mut state: Value) -> io::Result<()> {
        state["format"] = json!("memcordon.owned-peer-stdout");
        state["revision"] = json!(1);
        state["original_held_identity"] = json!(self.identity);
        state["identity_from_path_reopen"] = json!(false);
        state["acceptance_authority"] = json!(false);
        let bytes = serde_json::to_vec(&state).map_err(io::Error::other)?;
        if bytes.len() > 8192 {
            return Err(io::Error::other("peer stdout record exceeds8KiB"));
        }
        within(self.cutoff, || {
            let mut file = new_file(&self.record)?;
            file.write_all(&bytes)?;
            live(self.cutoff)?;
            file.sync_all()?;
            close(file)
        })
    }

    /// No content/metadata observation can substitute for actual peer retirement.
    pub fn unresolved(&self) -> io::Result<()> {
        self.publish(
            json!({"state":"peer-retirement-unproved","peer_retired":false,
            "observed_bytes":null,"observed_sha256":null,"content_complete":false}),
        )
    }

    pub fn finish(mut self) -> io::Result<()> {
        let observed = within(self.cutoff, || {
            let (identity, size) = inspect(&self.file, self.cutoff)?;
            live(self.cutoff)?;
            if !identity.same_object(&self.identity) {
                return Err(io::Error::other("held peer stdout identity changed"));
            }
            self.file.seek(SeekFrom::Start(0))?;
            live(self.cutoff)?;
            let mut prefix = vec![0; size.min(PREFIX_BYTES as u64) as usize];
            let count = if prefix.is_empty() {
                0
            } else {
                self.file.read(&mut prefix)?
            };
            live(self.cutoff)?;
            let (after, after_size) = inspect(&self.file, self.cutoff)?;
            live(self.cutoff)?;
            if !after.same_object(&identity)
                || after_size != size
                || count != prefix.len()
                || prefix.len() as u64 != size.min(PREFIX_BYTES as u64)
            {
                return Err(io::Error::other(
                    "held peer stdout changed during observation",
                ));
            }
            let hash = Sha256::digest(&prefix)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            Ok((after, size, prefix, hash))
        });
        let (state, result) = match observed {
            Ok((identity, size, prefix, hash)) => (
                json!({"state":if size==0 {"empty"} else {"unexpected-output"},
                "observed_held_identity":identity,
                "peer_retired":true,"observed_bytes":size,"observed_prefix":prefix,
                "observed_prefix_sha256":hash,"observed_sha256":(size<=PREFIX_BYTES as u64).then_some(hash.clone()),
                "content_complete":size<=PREFIX_BYTES as u64,"prefix_ceiling_bytes":PREFIX_BYTES}),
                if size == 0 {
                    Ok(())
                } else {
                    Err(io::Error::other("TCP peer stdout is nonempty"))
                },
            ),
            Err(error) => (
                json!({"state":"held-readback-error","peer_retired":true,
                "native_error":error.raw_os_error(),"observed_bytes":null,"content_complete":false}),
                Err(error),
            ),
        };
        let published = self.publish(state);
        let closed = close(self.file);
        match result {
            Err(primary) => Err(preserve(preserve(primary, published), closed)),
            Ok(()) => match published {
                Err(primary) => Err(preserve(primary, closed)),
                Ok(()) => closed,
            },
        }
    }
}
