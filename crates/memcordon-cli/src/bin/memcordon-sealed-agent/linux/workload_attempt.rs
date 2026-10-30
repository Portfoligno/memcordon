//! Factual journal for request-based attempts. A parsed record never owns native resources.
use super::native_process::{PrivateAttemptPhase, ProcessIdentityV4};
use super::private_lifecycle::PrivateNativeJournal;
use memcordon_core::result_v3::ReleaseKnowledgeV3;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) const MAX_RECORD_BYTES: usize = 512 * 1024;
pub(super) const JOURNAL_ROOT: &str = "/var/lib/memcordon/workload-attempts";
pub(super) const INPUT_ROOT: &str = "/var/lib/memcordon/workload-inputs";
pub(super) fn input_path(attempt: &str) -> Result<std::path::PathBuf, String> {
    if !super::cgroup::valid_attempt_identity(attempt) {
        return Err("invalid input attempt identity".into());
    }
    Ok(Path::new(INPUT_ROOT).join(attempt))
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationIntentsV1 {
    pub cgroup: bool,
    pub input_staging: bool,
    pub root_staging: bool,
    pub footprint: bool,
    pub guardian: bool,
    pub namespace_init: bool,
    pub target: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadAttemptRecordV1 {
    pub format: String,
    pub revision: u32,
    pub attempt_id: BoundedText<32>,
    pub boot_id: BoundedText<64>,
    pub phase: PrivateAttemptPhase,
    pub release: ReleaseKnowledgeV3,
    pub cleanup_cutoff_nanos: Option<u64>,
    pub cleanup_boot_id: Option<BoundedText<64>>,
    pub request_sha256: DiagnosticSha256,
    pub association: memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    pub request: memcordon_core::result_v3::WorkloadRequestAssociationV1,
    pub native: Option<memcordon_core::result_v3::LinuxNativeExecutionV3>,
    pub outcome: Option<memcordon_core::result_v3::NativeWorkloadOutcomeV1>,
    pub terminal: Option<memcordon_core::result_v3::LinuxWorkloadTerminalV1>,
    pub caller_uid: u32,
    pub frontend: ProcessIdentityV4,
    pub worker: ProcessIdentityV4,
    pub control: ProcessIdentityV4,
    pub intents: AllocationIntentsV1,
    pub guardian: Option<ProcessIdentityV4>,
    pub namespace_init: Option<ProcessIdentityV4>,
    pub target: Option<ProcessIdentityV4>,
    pub cgroup: Option<DirectoryIdentity>,
    pub staging: Option<DirectoryIdentity>,
    pub input_staging: Option<DirectoryIdentity>,
    pub root: Option<DirectoryIdentity>,
    pub network_namespace_inode: Option<u64>,
    pub output_files: BoundedVec<memcordon_core::workload_request::RootRelativePath, 64>,
    pub outstanding: BoundedVec<memcordon_core::result_v3::CleanupResourceV3, 32>,
    pub errors: BoundedVec<BoundedText<4096>, 32>,
}
impl WorkloadAttemptRecordV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("workload journal exceeds bound".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.association.validate().map_err(|e| e.to_string())?;
        if self.association.control.pid != self.control.pid
            || self.association.control.birth != self.control.start_time
        {
            return Err("workload journal control process binding differs".into());
        }
        let assigned: String = self
            .association
            .attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if assigned != self.attempt_id.as_str()
            || self.association.boot_id != self.boot_id
            || self.association.request_sha256 != self.request_sha256
            || self.request.request_sha256 != self.request_sha256
            || self.cleanup_boot_id.is_some() != self.cleanup_cutoff_nanos.is_some()
        {
            return Err("workload journal request/native association differs".into());
        }
        if let Some(native) = &self.native {
            if native.boot_id != self.boot_id {
                return Err("workload journal native boot differs".into());
            }
        }
        if let Some(terminal) = &self.terminal {
            terminal.validate()?;
            if terminal.association != self.association {
                return Err("retained terminal native session differs".into());
            }
        }
        if self.format != "memcordon.private-workload-journal"
            || self.revision != 1
            || !super::cgroup::valid_attempt_identity(self.attempt_id.as_str())
            || self.boot_id.as_str().is_empty()
            || self.frontend.pid == 0
            || self.worker.pid == 0
        {
            return Err("invalid factual workload journal".into());
        }
        if self.release == ReleaseKnowledgeV3::Released
            && (self.target.is_none()
                || self.namespace_init.is_none()
                || self.guardian.is_none()
                || self.cgroup.is_none())
        {
            return Err("released journal lacks original native identities".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for resource in self.outstanding.as_slice() {
            if !seen.insert(resource) {
                return Err("duplicate cleanup resource".into());
            }
        }
        Ok(())
    }
}

/// Move-only journal custody. Native resources remain in PrivateAttemptOwner.
pub struct DurableWorkloadAttempt {
    directory: File,
    record: WorkloadAttemptRecordV1,
}
/// Physical retained evidence is bounded independently of input-image charges.
pub(crate) const MAX_RETAINED_ATTEMPTS: usize = 128;
pub(super) const CAPACITY_LOCK_NAME: &str = ".capacity-lock";
fn hold_journal_capacity(directory: &File) -> Result<File, String> {
    let name = std::ffi::CString::new(CAPACITY_LOCK_NAME).expect("fixed lock name");
    // SAFETY: a fixed relative name is created beneath the held protected directory.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: successful openat transfers unique descriptor ownership.
    let lock = unsafe { File::from_raw_fd(raw) };
    let metadata = lock.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != 0
    {
        return Err("journal capacity lock custody differs".into());
    }
    // SAFETY: flock operates only on the held protected lock descriptor.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("journal capacity allocator temporarily unavailable".into());
    }
    let mut attempts = std::collections::BTreeSet::new();
    let path = Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string());
    for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
        let name = entry.map_err(|e| e.to_string())?.file_name();
        let name = name.to_str().ok_or("non-UTF8 journal allocation")?;
        if name == CAPACITY_LOCK_NAME {
            continue;
        }
        let attempt = name
            .strip_suffix(".recovery-lock")
            .or_else(|| name.strip_suffix(".recovery-update"))
            .or_else(|| name.strip_suffix(".update"))
            .unwrap_or(name);
        if !super::cgroup::valid_attempt_identity(attempt) {
            return Err("unrecognized journal allocation retained".into());
        }
        attempts.insert(attempt.to_owned());
        if attempts.len() >= MAX_RETAINED_ATTEMPTS {
            return Err("retained workload evidence capacity unavailable".into());
        }
    }
    Ok(lock)
}
impl DurableWorkloadAttempt {
    pub fn create(directory: File, record: WorkloadAttemptRecordV1) -> Result<Self, String> {
        record.validate()?;
        if record.phase != PrivateAttemptPhase::Allocated
            || record.release != ReleaseKnowledgeV3::NotReleased
        {
            return Err("new journal must precede native allocation".into());
        }
        let metadata = directory.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
            return Err("workload journal directory custody differs".into());
        }
        let _capacity = hold_journal_capacity(&directory)?;
        let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        super::atomic_publication::publish(
            &directory,
            std::ffi::OsStr::new(record.attempt_id.as_str()),
            &bytes,
            0o600,
            MAX_RECORD_BYTES,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self { directory, record })
    }
    pub fn record(&self) -> &WorkloadAttemptRecordV1 {
        &self.record
    }
    fn replace(&mut self, next: WorkloadAttemptRecordV1) -> Result<(), String> {
        next.validate()?;
        let bytes = serde_json::to_vec(&next).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("workload journal exceeds bound".into());
        }
        let name = std::ffi::CString::new(next.attempt_id.as_str()).map_err(|e| e.to_string())?;
        let temporary = Path::new(next.attempt_id.as_str()).with_extension("update");
        use std::os::unix::ffi::OsStrExt;
        let temporary =
            std::ffi::CString::new(temporary.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        self.read_back()?;
        // Create-new prevents adopting a crashed writer's file.
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                self.directory.as_raw_fd(),
                name.as_ptr(),
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        self.directory.sync_all().map_err(|e| e.to_string())?;
        self.record = next;
        Ok(())
    }
    pub fn read_back(&self) -> Result<(), String> {
        let name =
            std::ffi::CString::new(self.record.attempt_id.as_str()).map_err(|e| e.to_string())?;
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("workload journal custody changed".into());
        }
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_RECORD_BYTES + 1).expect("bound fits u64"))
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if WorkloadAttemptRecordV1::parse(&bytes)? != self.record {
            return Err("workload journal differs from owned state".into());
        }
        Ok(())
    }
    pub fn record_cgroup(&mut self, identity: DirectoryIdentity) -> Result<(), String> {
        let mut next = self.record.clone();
        next.cgroup = Some(identity);
        self.replace(next)
    }
    pub fn record_staging(&mut self, identity: DirectoryIdentity) -> Result<(), String> {
        let mut next = self.record.clone();
        next.staging = Some(identity);
        self.replace(next)
    }
    pub fn root_staging_intent(&mut self) -> Result<(), String> {
        let mut next = self.record.clone();
        if next.intents.root_staging {
            return Err("root staging allocation is single-use".into());
        }
        next.intents.root_staging = true;
        self.replace(next)
    }
    pub fn input_staging_intent(&mut self) -> Result<(), String> {
        let mut next = self.record.clone();
        if next.intents.input_staging {
            return Err("input staging allocation is single-use".into());
        }
        next.intents.input_staging = true;
        next.intents.footprint = true;
        self.replace(next)
    }
    pub fn record_input_staging(&mut self, identity: DirectoryIdentity) -> Result<(), String> {
        let mut next = self.record.clone();
        next.input_staging = Some(identity);
        self.replace(next)
    }
    pub fn publish_native(
        &mut self,
        native: Option<memcordon_core::result_v3::LinuxNativeExecutionV3>,
    ) -> Result<(), String> {
        let mut next = self.record.clone();
        next.native = native;
        self.replace(next)
    }
    pub fn publish_outcome(
        &mut self,
        native: Option<memcordon_core::result_v3::LinuxNativeExecutionV3>,
        outcome: memcordon_core::result_v3::NativeWorkloadOutcomeV1,
    ) -> Result<(), String> {
        let mut next = self.record.clone();
        next.native = native;
        next.outcome = Some(outcome);
        self.replace(next)
    }
    pub fn release_sent(
        &mut self,
        native: Option<memcordon_core::result_v3::LinuxNativeExecutionV3>,
    ) -> Result<(), String> {
        if self.record.release != ReleaseKnowledgeV3::Unknown {
            return Err("native release-send transition differs".into());
        }
        let mut next = self.record.clone();
        next.release = ReleaseKnowledgeV3::Released;
        next.native = native;
        self.replace(next)
    }
    pub fn finish(
        &mut self,
        terminal: memcordon_core::result_v3::LinuxWorkloadTerminalV1,
    ) -> Result<(), String> {
        terminal.validate()?;
        let mut next = self.record.clone();
        next.release = terminal.release;
        next.native = terminal.native.clone();
        next.outcome = Some(terminal.outcome.clone());
        next.terminal = Some(terminal.clone());
        if terminal.cleanup.state == memcordon_core::execution_facts::CleanupStateV1::Complete {
            next.phase = PrivateAttemptPhase::Retired;
            next.outstanding = BoundedVec::default();
        } else {
            next.phase = PrivateAttemptPhase::CleanupIncomplete;
        }
        self.replace(next)
    }
    pub fn begin_cleanup(&mut self, cutoff_nanos: u64) -> Result<u64, String> {
        if let Some(original) = self.record.cleanup_cutoff_nanos {
            return Ok(original);
        }
        let mut next = self.record.clone();
        next.cleanup_cutoff_nanos = Some(cutoff_nanos);
        next.cleanup_boot_id = Some(next.boot_id.clone());
        self.replace(next)?;
        Ok(cutoff_nanos)
    }
    pub fn release_intent(&mut self) -> Result<(), String> {
        if self.record.release != ReleaseKnowledgeV3::NotReleased
            || self.record.phase != PrivateAttemptPhase::TargetGated
        {
            return Err("workload release is not at original gate".into());
        }
        let mut next = self.record.clone();
        next.release = ReleaseKnowledgeV3::Unknown;
        next.phase = PrivateAttemptPhase::ReleaseIntent;
        self.replace(next)
    }
}
impl PrivateNativeJournal for DurableWorkloadAttempt {
    fn namespace_intent(&mut self) -> Result<(), String> {
        let mut next = self.record.clone();
        if next.intents.namespace_init || next.intents.target {
            return Err("native namespace allocation is single-use".into());
        }
        next.intents.namespace_init = true;
        next.intents.target = true;
        self.replace(next)
    }
    fn guardian_intent(&mut self) -> Result<(), String> {
        let mut next = self.record.clone();
        if next.intents.guardian {
            return Err("native guardian allocation is single-use".into());
        }
        next.intents.guardian = true;
        self.replace(next)
    }
    fn boundary_intent(&mut self) -> Result<(), String> {
        let mut next = self.record.clone();
        if next.intents.cgroup {
            return Err("cgroup allocation is single-use".into());
        }
        next.intents.cgroup = true;
        self.replace(next)
    }
    fn root_received(&mut self, device: u64, inode: u64) -> Result<(), String> {
        let mut next = self.record.clone();
        next.root = Some(DirectoryIdentity { device, inode });
        self.replace(next)
    }
    fn phase(&self) -> PrivateAttemptPhase {
        self.record.phase
    }
    fn read_back_native(&self) -> Result<(), String> {
        self.read_back()
    }
    fn attempt_id(&self) -> &str {
        self.record.attempt_id.as_str()
    }
    fn frontend(&self) -> &ProcessIdentityV4 {
        &self.record.frontend
    }
    fn target(&self) -> Option<&ProcessIdentityV4> {
        self.record.target.as_ref()
    }
    fn namespace_init(&self) -> Option<&ProcessIdentityV4> {
        self.record.namespace_init.as_ref()
    }
    fn network_namespace_inode(&self) -> Option<u64> {
        self.record.network_namespace_inode
    }
    fn boundary_created(&mut self) -> Result<(), String> {
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::BoundaryCreated;
        self.replace(next)
    }
    fn guardian_ready(&mut self, guardian: ProcessIdentityV4) -> Result<(), String> {
        let mut next = self.record.clone();
        next.guardian = Some(guardian);
        next.phase = PrivateAttemptPhase::GuardianReady;
        self.replace(next)
    }
    fn target_gated(
        &mut self,
        init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network: u64,
    ) -> Result<(), String> {
        let mut next = self.record.clone();
        next.namespace_init = Some(init);
        next.target = Some(target);
        next.network_namespace_inode = Some(network);
        next.phase = PrivateAttemptPhase::TargetGated;
        self.replace(next)
    }
    fn execution_observed_at(&mut self, millis: u64) -> Result<(), String> {
        let mut next = self.record.clone();
        let native = next
            .native
            .as_mut()
            .ok_or("native exec observation lacks gated native facts")?;
        native.exec_observed = true;
        native.exec_observed_monotonic_millis = Some(millis);
        next.release = ReleaseKnowledgeV3::Released;
        next.phase = PrivateAttemptPhase::ExecutionObserved;
        self.replace(next)
    }
    fn retiring(&mut self) -> Result<(), String> {
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retiring;
        self.replace(next)
    }
    fn cleanup_incomplete(&mut self, detail: &str) -> Result<(), String> {
        let mut next = self.record.clone();
        next.errors
            .try_push(BoundedText::new(detail).map_err(str::to_owned)?)
            .map_err(|_| "too many journal errors")?;
        self.replace(next)
    }
}

pub fn open_journal_directory(root: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|e| e.to_string())
}

/// Acquires journal custody only. This cannot construct a prepared/running
/// workload; process and allocation reacquisition remains the recovery caller's
/// independent native work.
pub(super) struct RecoveryJournal {
    directory: File,
    _lock: File,
    record: WorkloadAttemptRecordV1,
}

pub(super) enum RecoveryJournalError {
    CallerMismatch,
    NativeState(String),
}

impl From<String> for RecoveryJournalError {
    fn from(detail: String) -> Self {
        Self::NativeState(detail)
    }
}
impl From<&str> for RecoveryJournalError {
    fn from(detail: &str) -> Self {
        Self::NativeState(detail.into())
    }
}

pub(super) fn protected_directory_path(path: &Path) -> Result<File, String> {
    use std::os::unix::ffi::OsStrExt;
    if !path.is_absolute() {
        return Err("protected directory path is not absolute".into());
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| error.to_string())?;
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            if component == std::path::Component::RootDir {
                continue;
            }
            return Err("protected directory path is not normalized".into());
        };
        let name =
            std::ffi::CString::new(component.as_bytes()).map_err(|error| error.to_string())?;
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        directory = unsafe { File::from_raw_fd(raw) };
        let metadata = directory.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("protected directory ancestry custody differs".into());
        }
    }
    Ok(directory)
}

fn recovery_open_at(directory: &File, name: &std::ffi::OsStr, flags: i32) -> Result<File, String> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|error| error.to_string())?;
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let file = unsafe { File::from_raw_fd(raw) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("recovered journal object custody differs".into());
    }
    Ok(file)
}

pub(super) fn recovery_read_record(
    directory: &File,
    attempt: &str,
) -> Result<WorkloadAttemptRecordV1, String> {
    let file = recovery_open_at(directory, std::ffi::OsStr::new(attempt), libc::O_RDONLY)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_RECORD_BYTES + 1).expect("journal ceiling fits u64"))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let record = WorkloadAttemptRecordV1::parse(&bytes)?;
    if record.attempt_id.as_str() != attempt {
        return Err("recovered record filename binding differs".into());
    }
    Ok(record)
}

impl RecoveryJournal {
    pub(super) fn acquire(
        association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
        caller_uid: u32,
    ) -> Result<Self, RecoveryJournalError> {
        association.validate().map_err(|error| error.to_string())?;
        let attempt: String = association
            .attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let directory = protected_directory_path(Path::new(JOURNAL_ROOT))?;
        if directory
            .metadata()
            .map_err(|error| error.to_string())?
            .mode()
            & 0o777
            != 0o700
        {
            return Err("recovery journal root protection differs".into());
        }
        let record = recovery_read_record(&directory, &attempt)?;
        if record.association != *association || record.caller_uid != caller_uid {
            return Err(RecoveryJournalError::CallerMismatch);
        }
        let name = Path::new(&attempt).with_extension("recovery-lock");
        let lock = recovery_open_at(&directory, name.as_os_str(), libc::O_RDWR | libc::O_CREAT)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("original attempt recovery is already owned".into());
        }
        let current = recovery_read_record(&directory, &attempt)?;
        if current.association != *association || current.caller_uid != caller_uid {
            return Err(RecoveryJournalError::CallerMismatch);
        }
        Ok(Self {
            directory,
            _lock: lock,
            record: current,
        })
    }

    pub(super) fn record(&self) -> &WorkloadAttemptRecordV1 {
        &self.record
    }

    pub(super) fn retire_completed(
        self,
        guard: &crate::package::PackageDrainGuard<'_>,
    ) -> Result<(), String> {
        guard.validate()?;
        self.retire_metadata()
    }

    pub(super) fn retire_acknowledged(
        self,
        association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    ) -> Result<(), String> {
        if &self.record.association != association {
            return Err("acknowledged journal association differs".into());
        }
        self.retire_metadata()
    }

    fn retire_metadata(self) -> Result<(), String> {
        use std::os::unix::ffi::OsStrExt;
        if self.record.phase != PrivateAttemptPhase::Retired
            || !self.record.terminal.as_ref().is_some_and(|terminal| {
                terminal.cleanup.state == memcordon_core::execution_facts::CleanupStateV1::Complete
            })
            || recovery_read_record(&self.directory, self.record.attempt_id.as_str())?
                != self.record
        {
            return Err("package drain cannot retire an incomplete or substituted journal".into());
        }
        let attempt = Path::new(self.record.attempt_id.as_str());
        for path in [
            attempt.with_extension("update"),
            attempt.with_extension("recovery-update"),
        ] {
            let name = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|error| error.to_string())?;
            let raw = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                return Err(std::io::Error::last_os_error().to_string());
            }
            let file = unsafe { File::from_raw_fd(raw) };
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() > MAX_RECORD_BYTES as u64
            {
                return Err("package drain scratch custody differs".into());
            }
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        let name = std::ffi::CString::new(self.record.attempt_id.as_str())
            .map_err(|error| error.to_string())?;
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let lock_path = attempt.with_extension("recovery-lock");
        let named = recovery_open_at(&self.directory, lock_path.as_os_str(), libc::O_RDONLY)?;
        let expected = self._lock.metadata().map_err(|error| error.to_string())?;
        let current = named.metadata().map_err(|error| error.to_string())?;
        if (expected.dev(), expected.ino()) != (current.dev(), current.ino()) {
            return Err("package drain recovery lock was substituted".into());
        }
        let name = std::ffi::CString::new(lock_path.as_os_str().as_bytes())
            .map_err(|error| error.to_string())?;
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        self.directory.sync_all().map_err(|error| error.to_string())
    }

    /// Caller must first prove the original worker is dead, and independently
    /// reacquire every native allocation before mutating it.
    pub(super) fn update(&mut self, next: WorkloadAttemptRecordV1) -> Result<(), String> {
        use std::os::unix::ffi::OsStrExt;
        next.validate()?;
        if next.association != self.record.association
            || next.caller_uid != self.record.caller_uid
            || recovery_read_record(&self.directory, self.record.attempt_id.as_str())?
                != self.record
        {
            return Err("recovery journal association/custody changed".into());
        }
        let bytes = serde_json::to_vec(&next).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("recovered journal exceeds ceiling".into());
        }
        let path = Path::new(next.attempt_id.as_str()).with_extension("recovery-update");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|error| error.to_string())?;
        let record_name =
            std::ffi::CString::new(next.attempt_id.as_str()).map_err(|error| error.to_string())?;
        let existing = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if existing >= 0 {
            let file = unsafe { File::from_raw_fd(existing) };
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() > MAX_RECORD_BYTES as u64
            {
                return Err("interrupted recovery scratch custody differs".into());
            }
            // This exact reserved scratch is never an allocation owner. The
            // stable recovery lock excludes every writer that could use it.
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut file = recovery_open_at(
            &self.directory,
            path.as_os_str(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                self.directory.as_raw_fd(),
                record_name.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        self.directory
            .sync_all()
            .map_err(|error| error.to_string())?;
        self.record = next;
        Ok(())
    }
}
