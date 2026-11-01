//! Bounded diagnostic state; never a compiler retirement or admission receipt.
use std::io;

#[cfg(all(windows, feature = "test-fixtures"))]
#[path = "toolchain_publication_error.rs"]
mod publication;

#[cfg(all(windows, feature = "test-fixtures"))]
#[path = "toolchain_publication_policy.rs"]
mod publication_policy;

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
        PublicationPhaseError {
            phase: (phase.len() <= 256).then(|| phase.to_owned()),
            original: error,
        },
    )
}

#[derive(Debug)]
struct PublicationPhaseError {
    phase: Option<String>,
    original: io::Error,
}
impl std::fmt::Display for PublicationPhaseError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "{}; toolchain-diagnostic-publication={}",
            self.original,
            self.phase
                .as_deref()
                .unwrap_or("phase-exceeds-display-bound")
        )?;
        if let Some(code) = self.original.raw_os_error() {
            write!(out, "; original-raw-os-error=Some({code})")?;
        }
        Ok(())
    }
}
impl std::error::Error for PublicationPhaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

pub fn observer_gate_error(name: &str, error: io::Error) -> io::Error {
    use sha2::Digest;
    let digest = String::from(memcordon_core::DiagnosticSha256::from_bytes(
        sha2::Sha256::digest(name.as_bytes()).into(),
    ));
    io::Error::new(
        error.kind(),
        ObserverGateError {
            original: error,
            name_bytes: name.len(),
            name_sha256: digest,
        },
    )
}

#[derive(Debug)]
struct ObserverGateError {
    original: io::Error,
    name_bytes: usize,
    name_sha256: String,
}

impl std::fmt::Display for ObserverGateError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use super::controller_gate_error::{BoundaryError, Stage};
        let boundary = self
            .original
            .get_ref()
            .and_then(|error| error.downcast_ref::<BoundaryError>())
            .map(BoundaryError::observation);
        let (operation, native_code) = match boundary {
            Some((Stage::Open, code)) => ("open-toolchain-observer-gate", code),
            Some((Stage::Wait, code)) => ("wait-toolchain-observer-gate", code),
            Some((Stage::PublishRelease, code)) => ("publish-toolchain-observer-release", code),
            None => ("toolchain-observer-gate", self.original.raw_os_error()),
        };
        write!(
            out,
            "{}; toolchain-operation={operation}; name-bytes={}; name-sha256={}; original-raw-os-error={native_code:?}",
            self.original, self.name_bytes, self.name_sha256
        )
    }
}

impl std::error::Error for ObserverGateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

#[cfg(all(windows, feature = "test-fixtures"))]
use publication::FileObservation as FileIdentity;

#[cfg(all(windows, feature = "test-fixtures"))]
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

#[cfg(all(windows, feature = "test-fixtures"))]
struct OwnedCurrent {
    file: std::fs::File,
    identity: publication::FileObservation,
}

#[cfg(all(windows, feature = "test-fixtures"))]
pub struct PublicationOwner {
    directory: std::fs::File,
    root: std::path::PathBuf,
    deadline: std::time::Instant,
    current: std::cell::RefCell<[Option<OwnedCurrent>; 2]>,
}

#[cfg(all(windows, feature = "test-fixtures"))]
pub struct Publisher<'a> {
    owner: &'a PublicationOwner,
    binding: serde_json::Value,
    sequence: std::cell::Cell<u64>,
}

#[cfg(all(windows, feature = "test-fixtures"))]
fn publication_parent_hash(root: &std::path::Path) -> String {
    use sha2::Digest;
    use std::os::windows::ffi::OsStrExt;
    let path: Vec<u8> = root
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    String::from(memcordon_core::DiagnosticSha256::from_bytes(
        sha2::Sha256::digest(&path).into(),
    ))
}

#[cfg(all(windows, feature = "test-fixtures"))]
fn publication_failure(
    context: &publication::Context,
    stage: publication::Stage,
    original: io::Error,
    file: Option<&std::fs::File>,
) -> io::Error {
    let mut context = context.clone();
    if let Some(file) = file {
        // The primary error is already owned. Query only this retained stage
        // handle; an observation error is secondary and never replaces it.
        match file_identity(file, false) {
            Ok(observed) => context.stage_file = Some(observed),
            Err(error) => {
                context.stage_observation_error = Some(publication::ObservationError {
                    kind: format!("{:?}", error.kind()),
                    native_code: error.raw_os_error(),
                })
            }
        }
    }
    context.failure(stage, original)
}

#[cfg(all(windows, feature = "test-fixtures"))]
impl PublicationOwner {
    pub fn new(root: &std::path::Path, deadline: std::time::Instant) -> io::Result<Self> {
        use publication::{Context, Stage};
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "toolchain publication cutoff expired",
            ));
        }
        let mut context = Context::new("retain-parent", None, 0, &serde_json::Value::Null);
        context.parent_path_sha256 = Some(publication_parent_hash(root));
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root)
            .map_err(|error| context.failure(Stage::RetainParentOpen, error))?;
        file_identity(&directory, true)
            .map_err(|error| context.failure(Stage::RetainParentIdentity, error))?;
        Ok(Self {
            directory,
            root: root.to_owned(),
            deadline,
            current: std::cell::RefCell::new([None, None]),
        })
    }

    fn check(&self) -> io::Result<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "toolchain publication cutoff expired",
            ));
        }
        Ok(())
    }
}

#[cfg(all(windows, feature = "test-fixtures"))]
impl<'a> Publisher<'a> {
    pub fn new(owner: &'a PublicationOwner, binding: serde_json::Value) -> io::Result<Self> {
        owner.check()?;
        Ok(Self {
            owner,
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
        use publication::{Context, Stage};
        use std::io::{Read, Seek, Write};
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        self.owner.check()?;
        let mut context = Context::new(phase, Some(debug), self.sequence.get(), &self.binding);
        let parent_path_sha256 = Some(publication_parent_hash(&self.owner.root));
        context.parent_path_sha256 = parent_path_sha256.clone();
        let sequence = self.sequence.get().checked_add(1).ok_or_else(|| {
            context.failure(
                Stage::Sequence,
                io::Error::other("toolchain diagnostic sequence overflow"),
            )
        })?;
        context = Context::new(phase, Some(debug), sequence, &self.binding);
        context.parent_path_sha256 = parent_path_sha256;
        let bytes = encode(&self.binding, sequence, phase, state)
            .map_err(|error| context.failure(Stage::Encode, error))?;
        macro_rules! live {
            ($stage:expr) => {
                self.owner
                    .check()
                    .map_err(|error| context.failure($stage, error))?
            };
        }
        live!(Stage::ParentIdentity);
        let original = file_identity(&self.owner.directory, true)
            .map_err(|error| context.failure(Stage::ParentIdentity, error))?;
        context.parent = Some(original.clone());
        live!(Stage::ParentOpen);
        let named = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.owner.root)
            .map_err(|error| context.failure(Stage::ParentOpen, error))?;
        let current = file_identity(&named, true)
            .map_err(|error| context.failure(Stage::NamedParentIdentity, error))?;
        if (original.volume, original.index) != (current.volume, current.index) {
            return Err(context.failure(
                Stage::ParentVerification,
                io::Error::other("toolchain diagnostic parent custody differs"),
            ));
        }
        let name = if debug {
            "toolchain-current-debug.json"
        } else {
            "toolchain-current-phase.json"
        };
        let path = self.owner.root.join(name);
        let temporary = path.with_extension("pending");
        context.same_parent_paths = temporary.parent() == path.parent();
        let slot = usize::from(debug);
        let prior = self.owner.current.borrow();
        live!(Stage::DestinationIdentity);
        let expected = prior[slot]
            .as_ref()
            .map(|owned| {
                let current = file_identity(&owned.file, false)?;
                if current != owned.identity {
                    return Err(io::Error::other("original held destination changed"));
                }
                Ok(owned.identity.clone())
            })
            .transpose()
            .map_err(|error| context.failure(Stage::DestinationIdentity, error))?;
        live!(Stage::DestinationOpen);
        let destination = match std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
        {
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(context.failure(Stage::DestinationOpen, error)),
        };
        let observed = destination
            .as_ref()
            .map(|file| file_identity(file, false))
            .transpose()
            .map_err(|error| context.failure(Stage::DestinationIdentity, error))?;
        context.expected_destination = expected.clone();
        context.destination_before_stage = observed.clone();
        let facts = |identity: &publication::FileObservation| publication_policy::Identity {
            volume: identity.volume,
            index: identity.index,
            attributes: identity.attributes,
            links: identity.links,
            length: identity.length,
        };
        publication_policy::destination(
            expected.as_ref().map(facts).as_ref(),
            observed.as_ref().map(facts).as_ref(),
        )
        .map_err(|error| context.failure(Stage::DestinationOwnership, io::Error::other(error)))?;
        // The parent is held against deletion. A partial stage remains explicit evidence;
        // it is never mistaken for the complete atomically published current record.
        live!(Stage::PendingCreate);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temporary)
            .map_err(|error| context.failure(Stage::PendingCreate, error))?;
        live!(Stage::PendingWrite);
        file.write_all(&bytes).map_err(|error| {
            publication_failure(&context, Stage::PendingWrite, error, Some(&file))
        })?;
        live!(Stage::PendingFlush);
        file.sync_all().map_err(|error| {
            publication_failure(&context, Stage::PendingFlush, error, Some(&file))
        })?;
        live!(Stage::PendingRewind);
        file.rewind().map_err(|error| {
            publication_failure(&context, Stage::PendingRewind, error, Some(&file))
        })?;
        let mut actual = Vec::new();
        live!(Stage::PendingReadback);
        (&mut file)
            .take(RECORD_BOUND as u64 + 1)
            .read_to_end(&mut actual)
            .map_err(|error| {
                publication_failure(&context, Stage::PendingReadback, error, Some(&file))
            })?;
        if actual != bytes {
            return Err(publication_failure(
                &context,
                Stage::PendingReadbackVerification,
                io::Error::other("toolchain diagnostic staged readback differs"),
                Some(&file),
            ));
        }
        context.readback_verified = true;
        live!(Stage::ReadbackOpen);
        let readback = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temporary)
            .map_err(|error| context.failure(Stage::ReadbackOpen, error))?;
        let staged = file_identity(&file, false)
            .map_err(|error| context.failure(Stage::PendingIdentity, error))?;
        if file_identity(&readback, false)
            .map_err(|error| context.failure(Stage::PendingIdentity, error))?
            != staged
        {
            return Err(context.failure(
                Stage::PendingReadbackVerification,
                io::Error::other("toolchain diagnostic readback handle differs"),
            ));
        }
        // The data writer is closed before the synchronous metadata/DELETE open.
        // The independently verified original readback remains held throughout.
        drop(file);
        let rename = memcordon_platform::test_support::windows_open_synchronous_rename_source(
            &self.owner.directory,
            temporary
                .file_name()
                .ok_or_else(|| io::Error::other("diagnostic stage name missing"))?,
            &readback,
            self.owner.deadline,
        )
        .map_err(|error| {
            publication_failure(&context, Stage::RenameSourceOpen, error, Some(&readback))
        })?;
        memcordon_platform::test_support::windows_prepare_persistent_stage(
            rename.as_file(),
            self.owner.deadline,
        )
        .map_err(|error| {
            publication_failure(&context, Stage::SourcePreparation, error, Some(&readback))
        })?;
        let mut verified = Vec::new();
        live!(Stage::PendingReadback);
        (&readback)
            .take(RECORD_BOUND as u64 + 1)
            .read_to_end(&mut verified)
            .map_err(|error| {
                publication_failure(&context, Stage::PendingReadback, error, Some(&readback))
            })?;
        if verified != bytes {
            return Err(context.failure(
                Stage::PendingReadbackVerification,
                io::Error::other("toolchain diagnostic prepared source bytes differ"),
            ));
        }
        // Recheck the actual current name after stage preparation, immediately
        // before replacing it. The old handles stay pinned across the commit.
        live!(Stage::DestinationOpen);
        let current = match std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
        {
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(context.failure(Stage::DestinationOpen, error)),
        };
        let actual = current
            .as_ref()
            .map(|file| file_identity(file, false))
            .transpose()
            .map_err(|error| context.failure(Stage::DestinationIdentity, error))?;
        context.destination_before_commit = actual.clone();
        publication_policy::destination(
            expected.as_ref().map(facts).as_ref(),
            actual.as_ref().map(facts).as_ref(),
        )
        .map_err(|error| context.failure(Stage::DestinationOwnership, io::Error::other(error)))?;
        let committed = rename
            .rename(std::ffi::OsStr::new(name), self.owner.deadline)
            .map_err(|error| {
                publication_failure(&context, Stage::Replace, error, Some(&readback))
            })?;
        // No pending-name cleanup exists: after commit that name no longer
        // denotes our file, even if the following verification fails.
        committed.verify(self.owner.deadline).map_err(|error| {
            publication_failure(&context, Stage::CommitVerification, error, Some(&readback))
        })?;
        drop(rename);
        let held = file_identity(&readback, false)
            .map_err(|error| context.failure(Stage::PendingIdentity, error))?;
        context.stage_file = Some(held.clone());
        live!(Stage::FinalOpen);
        let final_file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(|error| context.failure(Stage::FinalOpen, error))?;
        let final_identity = file_identity(&final_file, false)
            .map_err(|error| context.failure(Stage::FinalIdentity, error))?;
        if held != final_identity {
            return Err(context.failure(
                Stage::FinalVerification,
                io::Error::other("toolchain diagnostic final custody differs"),
            ));
        }
        if held.length != bytes.len() as u64 {
            return Err(context.failure(
                Stage::FinalLength,
                io::Error::other("toolchain diagnostic final custody differs"),
            ));
        }
        let mut final_bytes = Vec::new();
        live!(Stage::FinalVerification);
        (&final_file)
            .take(RECORD_BOUND as u64 + 1)
            .read_to_end(&mut final_bytes)
            .map_err(|error| context.failure(Stage::FinalVerification, error))?;
        if final_bytes != bytes {
            return Err(context.failure(
                Stage::FinalVerification,
                io::Error::other("toolchain diagnostic final bytes differ"),
            ));
        }
        self.owner
            .check()
            .map_err(|error| context.failure(Stage::CommitVerification, error))?;
        drop(prior);
        self.owner.current.borrow_mut()[slot] = Some(OwnedCurrent {
            file: final_file,
            identity: final_identity,
        });
        self.sequence.set(sequence);
        Ok(())
    }
}
