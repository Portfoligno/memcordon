//! Bounded diagnostic state; never a compiler retirement or admission receipt.
use std::io;

pub const RECORD_BOUND: usize = 128 * 1024;
pub const INVENTORY_BOUND: usize = 64;

#[derive(Clone, serde::Serialize)]
pub struct CreationIdentity {
    pub pid: u32,
    pub birth: u64,
    pub parent_pid: u32,
    pub parent_birth: u64,
    pub image_sha256: String,
    pub held_process_owner: bool,
    pub image_observation: &'static str,
}

#[derive(Clone, serde::Serialize)]
pub struct ExitObservation {
    pub sequence: u64,
    pub kind: &'static str,
    pub pid: u32,
    pub tid: u32,
    pub native_exit_status: u32,
    pub creation: Option<CreationIdentity>,
    pub original_compiler: bool,
    pub continuation: &'static str,
    pub continuation_raw_os_error: Option<i32>,
}

pub struct ExitState {
    original_pid: u32,
    original_creation: Option<CreationIdentity>,
    original_exit: Option<ExitObservation>,
    members: Vec<ExitObservation>,
    observed: u64,
}

impl ExitState {
    pub fn new(original_pid: u32) -> Self {
        Self {
            original_pid,
            original_creation: None,
            original_exit: None,
            members: Vec::new(),
            observed: 0,
        }
    }

    pub fn created(&mut self, creation: &CreationIdentity) {
        if creation.pid == self.original_pid && self.original_creation.is_none() {
            self.original_creation = Some(creation.clone());
        }
    }

    pub fn observe_exit(
        &mut self,
        pid: u32,
        tid: u32,
        native_exit_status: u32,
        creation: Option<&CreationIdentity>,
    ) -> ExitObservation {
        self.observed += 1; // The existing debug loop admits at most 131,072 events.
        let creation = creation.filter(|creation| {
            creation.pid == pid && creation.birth != 0 && creation.held_process_owner
        });
        let original_compiler =
            creation
                .zip(self.original_creation.as_ref())
                .is_some_and(|(current, original)| {
                    current.pid == original.pid && current.birth == original.birth
                });
        let event = ExitObservation {
            sequence: self.observed,
            kind: "exit-process",
            pid,
            tid,
            native_exit_status,
            creation: creation.cloned(),
            original_compiler,
            continuation: "pending",
            continuation_raw_os_error: None,
        };
        if original_compiler && self.original_exit.is_none() {
            self.original_exit = Some(event.clone());
        }
        if self.members.len() < INVENTORY_BOUND {
            self.members.push(event.clone());
        }
        event
    }

    pub fn continuation_result(
        &mut self,
        event: &mut ExitObservation,
        result: Result<(), Option<i32>>,
    ) {
        event.continuation = if result.is_ok() {
            "continued"
        } else {
            "failed"
        };
        event.continuation_raw_os_error = result.err().flatten();
        if let Some(retained) = self
            .members
            .iter_mut()
            .find(|retained| retained.sequence == event.sequence)
        {
            *retained = event.clone();
        }
        if let Some(retained) = self
            .original_exit
            .as_mut()
            .filter(|retained| retained.sequence == event.sequence)
        {
            *retained = event.clone();
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"original_compiler_creation":self.original_creation,
            "original_compiler_exit":self.original_exit,"original_compiler_exit_observation":if self.original_exit.is_some(){"observed"}else{"not-observed"},
            "exited_members":self.members,"observed_count":self.observed,"omitted_count":self.observed.saturating_sub(self.members.len() as u64),
            "whole_family_retirement_proof":false})
    }
}

pub fn socket_error(stage: &'static str, port: u16, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{error}; tcp-peer-stage={stage}; peer-pid={}; endpoint=127.0.0.1:{port}; original-raw-os-error={:?}",
            std::process::id(),
            error.raw_os_error()
        ),
    )
}

pub fn publication_error(phase: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{error}; toolchain-diagnostic-publication={phase}; original-raw-os-error={:?}",
            error.raw_os_error()
        ),
    )
}

pub fn observer_gate_error(name: &str, error: io::Error) -> io::Error {
    use sha2::Digest;
    // This call site has an infallible ready callback. Native-code errors come
    // from OpenEvent; its finite wait returns a separate code-free error.
    let operation = if error.raw_os_error().is_some() {
        "open-toolchain-observer-gate"
    } else {
        "wait-toolchain-observer-gate"
    };
    let digest = String::from(memcordon_core::DiagnosticSha256::from_bytes(
        sha2::Sha256::digest(name.as_bytes()).into(),
    ));
    io::Error::new(
        error.kind(),
        format!(
            "{error}; toolchain-operation={operation}; name-bytes={}; name-sha256={digest}; original-raw-os-error={:?}",
            name.len(),
            error.raw_os_error()
        ),
    )
}

#[cfg(windows)]
#[derive(Eq, PartialEq)]
struct FileIdentity {
    volume: u32,
    index: u64,
    attributes: u32,
    links: u32,
    length: u64,
}

#[cfg(windows)]
fn file_identity(file: &std::fs::File, directory: bool) -> io::Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::*;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the original File retains the live handle and info is a full native output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(io::Error::other(
            "toolchain diagnostic native type/link custody differs",
        ));
    }
    Ok(FileIdentity {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        attributes: info.dwFileAttributes,
        links: info.nNumberOfLinks,
        length: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
    })
}

pub fn encode(
    binding: &serde_json::Value,
    sequence: u64,
    phase: &str,
    state: &serde_json::Value,
) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.windows-toolchain-current-state", "revision":1,
        "diagnostic_only":true,"transition_snapshot_not_live_probe":true,
        "nonboundary_debug_events_not_logged":true,"transition_sequence":sequence,
        "binding":binding,"phase":phase,"state":state
    }))
    .map_err(io::Error::other)?;
    if bytes.len() > RECORD_BOUND {
        return Err(io::Error::other(
            "toolchain diagnostic state exceeds finite bound",
        ));
    }
    Ok(bytes)
}

pub fn inventory<'a, T: serde::Serialize + 'a>(
    members: impl Iterator<Item = &'a T>,
    count: usize,
) -> serde_json::Value {
    let retained: Vec<_> = members.take(INVENTORY_BOUND).collect();
    serde_json::json!({"members":retained,"active_count":count,
        "omitted_count":count.saturating_sub(retained.len()),"complete":count==retained.len()})
}

#[cfg(windows)]
pub struct Publisher {
    directory: std::fs::File,
    root: std::path::PathBuf,
    binding: serde_json::Value,
    sequence: std::cell::Cell<u64>,
}

#[cfg(windows)]
impl Publisher {
    pub fn new(root: &std::path::Path, binding: serde_json::Value) -> io::Result<Self> {
        Self::retain_parent(root, binding)
            .map_err(|error| publication_error("retain-parent", error))
    }

    fn retain_parent(root: &std::path::Path, binding: serde_json::Value) -> io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root)?;
        file_identity(&directory, true)?;
        Ok(Self {
            directory,
            root: root.to_owned(),
            binding,
            sequence: std::cell::Cell::new(0),
        })
    }

    pub fn publish(&self, debug: bool, phase: &str, state: &serde_json::Value) -> io::Result<()> {
        self.publish_record(debug, phase, state)
            .map_err(|error| publication_error(phase, error))
    }

    fn publish_record(
        &self,
        debug: bool,
        phase: &str,
        state: &serde_json::Value,
    ) -> io::Result<()> {
        use std::io::{Read, Seek, Write};
        use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::*;
        let sequence = self
            .sequence
            .get()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("toolchain diagnostic sequence overflow"))?;
        let bytes = encode(&self.binding, sequence, phase, state)?;
        let original = file_identity(&self.directory, true)?;
        let named = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.root)?;
        let current = file_identity(&named, true)?;
        if (original.volume, original.index) != (current.volume, current.index) {
            return Err(io::Error::other(
                "toolchain diagnostic parent custody differs",
            ));
        }
        let name = if debug {
            "toolchain-current-debug.json"
        } else {
            "toolchain-current-phase.json"
        };
        let path = self.root.join(name);
        let temporary = path.with_extension("pending");
        // The parent is held against deletion. A partial stage remains explicit evidence;
        // it is never mistaken for the complete atomically published current record.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        file.rewind()?;
        let mut actual = Vec::new();
        (&mut file)
            .take(RECORD_BOUND as u64 + 1)
            .read_to_end(&mut actual)?;
        if actual != bytes {
            return Err(io::Error::other(
                "toolchain diagnostic staged readback differs",
            ));
        }
        let source: Vec<_> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both terminated native paths live through the atomic same-directory move.
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let held = file_identity(&file, false)?;
        let final_file = std::fs::OpenOptions::new()
            .read(true)
            // The original stage handle still owns write access. It denies
            // other writers; this read handle must permit that existing access.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        if held != file_identity(&final_file, false)? || held.length != bytes.len() as u64 {
            return Err(io::Error::other(
                "toolchain diagnostic final custody differs",
            ));
        }
        self.sequence.set(sequence);
        Ok(())
    }
}
