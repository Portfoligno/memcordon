//! Actual mutation attempts against only the separately declared private inputs.
use super::descriptor::ControlClock;
use sha2::{Digest, Sha256};
use std::os::windows::ffi::OsStrExt;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE, SetLastError},
    Networking::WinSock::{WSAGetLastError, WSASetLastError},
    Storage::FileSystem::{
        CreateFileW, DeleteFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
        MOVEFILE_REPLACE_EXISTING, MoveFileExW, OPEN_EXISTING, WRITE_DAC, WRITE_OWNER,
    },
};

struct Errors(u32, i32);
#[derive(Debug)]
struct Failure {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; private probe cleanup/publication: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn preserve<T>(primary: io::Result<T>, secondary: io::Result<()>) -> io::Result<T> {
    match (primary, secondary) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Err(secondary)) => Err(io::Error::new(
            primary.kind(),
            Failure { primary, secondary },
        )),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(secondary)) => Err(secondary),
    }
}
impl Errors {
    fn capture() -> Self {
        Self(unsafe { GetLastError() }, unsafe { WSAGetLastError() })
    }
}
impl Drop for Errors {
    fn drop(&mut self) {
        unsafe {
            WSASetLastError(self.1);
            SetLastError(self.0);
        }
    }
}
fn live(work: Instant) -> io::Result<()> {
    if Instant::now() >= work {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "private input mutation original cutoff expired",
        ))
    } else {
        Ok(())
    }
}
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut result = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if result.is_empty() || result.len() > 32768 || result.contains(&0) {
        return Err(io::Error::other("private mutation path extent is invalid"));
    }
    result.push(0);
    Ok(result)
}
fn denied(success: bool) -> io::Result<i32> {
    if success {
        return Err(io::Error::other(
            "private input mutation unexpectedly succeeded",
        ));
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code @ (5 | 32)) => Ok(code),
        _ => Err(error),
    }
}
fn denied_authority(path: &Path, access: u32, work: Instant) -> io::Result<i32> {
    let name = wide(path)?;
    live(work)?;
    // SAFETY: only an independently constrained owned private input/directory.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
        return Err(io::Error::other(
            "private input security-changing handle acquired",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(5) {
        return Err(error);
    }
    Ok(5)
}

/// These attempts are experiment assertions, never permission or product authority.
pub fn run(
    paths: &[PathBuf],
    clock: &ControlClock,
    output_root: &Path,
    peer: bool,
) -> io::Result<()> {
    let _errors = Errors::capture();
    let work = super::controller_start_input::deadline_from_clock(clock)?;
    live(work)?;
    let executable = std::env::current_exe()?;
    let parent = executable
        .parent()
        .ok_or_else(|| io::Error::other("private fixture parent absent"))?;
    let mut directory = executable
        .file_name()
        .ok_or_else(|| io::Error::other("private fixture leaf absent"))?
        .to_os_string();
    directory.push(".local");
    let directory = parent.join(directory);
    if paths.len() < 2
        || paths.len() > 9
        || !paths.contains(&executable)
        || !output_root.is_absolute()
        || output_root.starts_with(&directory)
        || output_root.starts_with(parent)
        || paths.iter().any(|path| {
            !path.is_absolute()
                || path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || (path != &executable && path.parent() != Some(directory.as_path()))
        })
    {
        return Err(io::Error::other(
            "mutation targets are not the exact private fixture and immediate .local leaves",
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    if paths.iter().any(|path| !unique.insert(path)) {
        return Err(io::Error::other("duplicate private mutation target"));
    }
    let token: super::descriptor::gate_precondition::TokenObservation =
        serde_json::from_slice(&super::native::effective_token_observation()?)
            .map_err(io::Error::other)?;
    if !token.restricted {
        let bytes=serde_json::to_vec(&serde_json::json!({"format":"memcordon.private-provider-input-mutation-probes","revision":1,"diagnostic_only":true,"acceptance_authority":false,"pid":std::process::id(),"peer":peer,"restricted":false,"performed":false,"state":"not-required-for-ordinary-baseline","complete":false,"rows":[]})).map_err(io::Error::other)?;
        live(work)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_root.join(if peer {
                "peer-provider-input-probes.json"
            } else {
                "provider-input-probes.json"
            }))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        return live(work);
    }
    let mut rows = Vec::new();
    let mut directory_authority = Vec::new();
    let attempted = (|| -> io::Result<()> {
        for (index, path) in paths.iter().enumerate() {
            live(work)?;
            let name = wide(path)?;
            let write_dac_error = denied_authority(path, WRITE_DAC, work)?;
            let write_owner_error = denied_authority(path, WRITE_OWNER, work)?;
            live(work)?;
            // SAFETY: complete bounded path and no creation/truncation or write.
            let opened = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    FILE_WRITE_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };
            let write_error = if opened == INVALID_HANDLE_VALUE {
                denied(false)?
            } else {
                unsafe { CloseHandle(opened) };
                return Err(io::Error::other(
                    "private input writable handle unexpectedly acquired",
                ));
            };
            live(work)?;
            // SAFETY: only a declared experiment-owned input, never a host source.
            let delete_error = denied(unsafe { DeleteFileW(name.as_ptr()) } != 0)?;
            live(work)?;
            let rename =
                output_root.join(format!("provider-rename-{}-{index}", std::process::id()));
            if rename.try_exists()? {
                return Err(io::Error::other(
                    "private rename destination already exists",
                ));
            }
            let rename_name = wide(&rename)?;
            live(work)?;
            // SAFETY: source is a declared owned input and destination is a fresh output leaf.
            let rename_error =
                denied(unsafe { MoveFileExW(name.as_ptr(), rename_name.as_ptr(), 0) } != 0)?;
            live(work)?;
            let replacement = output_root.join(format!(
                "provider-substitute-{}-{index}",
                std::process::id()
            ));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&replacement)?;
            file.write_all(b"declared private input substitution probe")?;
            file.sync_all()?;
            drop(file);
            let replacement_name = wide(&replacement)?;
            // SAFETY: the replacement is this call's newly created output file;
            // the destination is exactly this experiment's private immutable input.
            let substitution = live(work).and_then(|_| {
                let substituted = unsafe {
                    MoveFileExW(
                        replacement_name.as_ptr(),
                        name.as_ptr(),
                        MOVEFILE_REPLACE_EXISTING,
                    )
                };
                denied(substituted != 0)
            });
            let cleanup = std::fs::remove_file(&replacement);
            let substitution_error = preserve(substitution, cleanup)?;
            let path_bytes = path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            let path_sha256 = Sha256::digest(&path_bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            rows.push(serde_json::json!({"path_sha256":path_sha256,"write_dac_error":write_dac_error,"write_owner_error":write_owner_error,"write_error":write_error,"delete_error":delete_error,"rename_error":rename_error,"substitution_error":substitution_error,"all_mutations_refused":true}));
        }
        for path in [parent, directory.as_path()] {
            let write_dac_error = denied_authority(path, WRITE_DAC, work)?;
            let write_owner_error = denied_authority(path, WRITE_OWNER, work)?;
            directory_authority.push(serde_json::json!({"write_dac_error":write_dac_error,"write_owner_error":write_owner_error}));
        }
        live(work)
    })();
    let report=serde_json::to_vec(&serde_json::json!({"format":"memcordon.private-provider-input-mutation-probes","revision":1,"diagnostic_only":true,"acceptance_authority":false,"pid":std::process::id(),"peer":peer,"restricted":true,"performed":true,"complete":attempted.is_ok(),"rows":rows,"directory_authority":directory_authority,"failure":attempted.as_ref().err().map(|error|error.to_string())})).map_err(io::Error::other);
    let retained = report.and_then(|bytes| {
        if bytes.len() > 16 * 1024 {
            return Err(io::Error::other("private mutation report bound"));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_root.join(if peer {
                "peer-provider-input-probes.json"
            } else {
                "provider-input-probes.json"
            }))?;
        file.write_all(&bytes)?;
        file.sync_all()
    });
    preserve(attempted, retained)
}
