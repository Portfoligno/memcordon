//! Strict version-four private attempt state. A checksum detects torn writes;
//! protected directory ownership and exact native resource binding remain
//! separate requirements. Recovery never interprets this as a V1 attempt.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
#[cfg(feature = "test-support")]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use memcordon_core::workload_admission_v2::{AttemptBindingV2, ProviderAdmissionSnapshotV2};
use memcordon_core::workload_evidence_v2::PrivateTcpCheckpointV2;
use memcordon_core::workload_evidence_v2::TargetIdentityKindV2;
use memcordon_core::{BoundedText, DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::STATE_ROOT;

pub(crate) const MAX_PRIVATE_RECORD_BYTES: usize = memcordon_core::workload_limits::REGISTRY_BYTES
    + memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateAttemptPhase {
    Allocated,
    AuthorityFrozen,
    BoundaryCreated,
    GuardianReady,
    TargetGated,
    CheckpointCommitted,
    ReleaseIntent,
    ExecutionObserved,
    Retiring,
    Retired,
    CleanupIncomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseKnowledge {
    NotReleased,
    PossiblyReleased,
    ExecObserved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentityV4 {
    pub pid: u32,
    pub start_time: u64,
}

impl ProcessIdentityV4 {
    /// Capture process identity from a live pidfd and kernel process start
    /// time. A numeric PID received in a message is never enough authority.
    pub fn observe(pid: libc::pid_t, pidfd: BorrowedFd<'_>) -> Result<Self, String> {
        if pid <= 0 {
            return Err("V4 process PID is invalid".into());
        }
        let fdinfo = Path::new("/proc/self/fdinfo").join(pidfd.as_raw_fd().to_string());
        let text = fs::read_to_string(fdinfo).map_err(|error| error.to_string())?;
        let bound_pid = text
            .lines()
            .find_map(|line| line.strip_prefix("Pid:").map(str::trim))
            .ok_or("V4 pidfd lacks kernel PID binding")?
            .parse::<libc::pid_t>()
            .map_err(|_| "V4 pidfd PID binding is invalid")?;
        if bound_pid != pid {
            return Err("V4 pidfd differs from selected process".into());
        }
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized descriptor record and a zero timeout.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
        if ready != 0 || pollfd.revents != 0 {
            return Err("V4 selected process is no longer live".into());
        }
        let start_time = super::envelope::process_start_time(pid)?;
        pollfd.revents = 0;
        // SAFETY: the same owned pidfd remains valid for this read-only poll.
        if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 0 || pollfd.revents != 0 {
            return Err("V4 selected process exited during identity readback".into());
        }
        let identity = Self {
            pid: pid as u32,
            start_time,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), String> {
        if self.pid == 0 || self.start_time == 0 {
            return Err("V4 process identity is incomplete".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateAttemptRecordV4 {
    pub attempt_id: BoundedText<64>,
    pub boot_identity: BoundedText<128>,
    pub frontend: ProcessIdentityV4,
    pub caller_envelope_digest: DiagnosticSha256,
    pub phase: PrivateAttemptPhase,
    pub release_knowledge: ReleaseKnowledge,
    pub admission: Option<ProviderAdmissionSnapshotV2>,
    pub binding: Option<AttemptBindingV2>,
    pub guardian: Option<ProcessIdentityV4>,
    pub namespace_init: Option<ProcessIdentityV4>,
    pub target: Option<ProcessIdentityV4>,
    pub network_namespace_inode: Option<u64>,
    pub checkpoint: Option<PrivateTcpCheckpointV2>,
    pub checkpoint_digest: Option<DiagnosticSha256>,
    pub cleanup_error: Option<BoundedText<4096>>,
}

impl PrivateAttemptRecordV4 {
    pub fn allocated(
        attempt_id: BoundedText<64>,
        boot_identity: BoundedText<128>,
        frontend: ProcessIdentityV4,
        caller_envelope_digest: DiagnosticSha256,
    ) -> Result<Self, String> {
        let record = Self {
            attempt_id,
            boot_identity,
            frontend,
            caller_envelope_digest,
            phase: PrivateAttemptPhase::Allocated,
            release_knowledge: ReleaseKnowledge::NotReleased,
            admission: None,
            binding: None,
            guardian: None,
            namespace_init: None,
            target: None,
            network_namespace_inode: None,
            checkpoint: None,
            checkpoint_digest: None,
            cleanup_error: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn freeze_authority(
        mut self,
        admission: ProviderAdmissionSnapshotV2,
    ) -> Result<Self, String> {
        if self.phase != PrivateAttemptPhase::Allocated
            || self.caller_envelope_digest != admission.caller_envelope_digest
        {
            return Err("V4 authority differs from allocated caller envelope".into());
        }
        let binding = AttemptBindingV2::from_admission(self.attempt_id.clone(), &admission)?;
        self.admission = Some(admission);
        self.binding = Some(binding);
        self.phase = PrivateAttemptPhase::AuthorityFrozen;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        let identity = self.attempt_id.as_str();
        if !super::cgroup::valid_attempt_identity(identity)
            || self.boot_identity.as_str().is_empty()
        {
            return Err("V4 attempt or boot identity invalid".into());
        }
        self.frontend.validate()?;
        for process in [&self.guardian, &self.namespace_init, &self.target]
            .into_iter()
            .flatten()
        {
            process.validate()?;
        }
        if self.network_namespace_inode == Some(0) {
            return Err("V4 network namespace inode is zero".into());
        }
        match (&self.admission, &self.binding) {
            (None, None)
                if matches!(
                    self.phase,
                    PrivateAttemptPhase::Allocated
                        | PrivateAttemptPhase::Retiring
                        | PrivateAttemptPhase::Retired
                        | PrivateAttemptPhase::CleanupIncomplete
                ) && self.guardian.is_none()
                    && self.namespace_init.is_none()
                    && self.target.is_none()
                    && self.network_namespace_inode.is_none()
                    && self.checkpoint.is_none() => {}
            (Some(admission), Some(binding)) => {
                admission.validate()?;
                if !binding.matches_admission(admission)
                    || binding.attempt_id != self.attempt_id
                    || self.caller_envelope_digest != admission.caller_envelope_digest
                {
                    return Err("V4 frozen attempt binding differs".into());
                }
            }
            _ => return Err("V4 admission and binding must be frozen together".into()),
        }
        let boundary = matches!(
            self.phase,
            PrivateAttemptPhase::BoundaryCreated
                | PrivateAttemptPhase::GuardianReady
                | PrivateAttemptPhase::TargetGated
                | PrivateAttemptPhase::CheckpointCommitted
                | PrivateAttemptPhase::ReleaseIntent
                | PrivateAttemptPhase::ExecutionObserved
                | PrivateAttemptPhase::Retiring
                | PrivateAttemptPhase::Retired
        );
        if boundary
            && self.admission.is_none()
            && !matches!(
                self.phase,
                PrivateAttemptPhase::Retiring | PrivateAttemptPhase::Retired
            )
        {
            return Err("V4 boundary lacks frozen authority".into());
        }
        match self.phase {
            PrivateAttemptPhase::Allocated | PrivateAttemptPhase::AuthorityFrozen
                if self.guardian.is_some()
                    || self.namespace_init.is_some()
                    || self.target.is_some()
                    || self.network_namespace_inode.is_some()
                    || self.checkpoint.is_some() =>
            {
                return Err("V4 preboundary phase contains native resources".into());
            }
            PrivateAttemptPhase::BoundaryCreated
                if self.guardian.is_some()
                    || self.namespace_init.is_some()
                    || self.target.is_some()
                    || self.network_namespace_inode.is_some()
                    || self.checkpoint.is_some() =>
            {
                return Err("V4 boundary phase contains later resources".into());
            }
            PrivateAttemptPhase::GuardianReady
                if self.guardian.is_none()
                    || self.namespace_init.is_some()
                    || self.target.is_some()
                    || self.network_namespace_inode.is_some()
                    || self.checkpoint.is_some() =>
            {
                return Err("V4 guardian phase resource inventory differs".into());
            }
            PrivateAttemptPhase::TargetGated if self.checkpoint.is_some() => {
                return Err("V4 gated phase contains uncommitted checkpoint".into());
            }
            _ => {}
        }
        let gated = matches!(
            self.phase,
            PrivateAttemptPhase::TargetGated
                | PrivateAttemptPhase::CheckpointCommitted
                | PrivateAttemptPhase::ReleaseIntent
                | PrivateAttemptPhase::ExecutionObserved
        );
        if gated
            && (self.guardian.is_none()
                || self.namespace_init.is_none()
                || self.target.is_none()
                || self.network_namespace_inode.is_none())
        {
            return Err("V4 gated target lacks native resource identities".into());
        }
        let committed = matches!(
            self.phase,
            PrivateAttemptPhase::CheckpointCommitted
                | PrivateAttemptPhase::ReleaseIntent
                | PrivateAttemptPhase::ExecutionObserved
        );
        if committed && (self.checkpoint.is_none() || self.checkpoint_digest.is_none()) {
            return Err("V4 committed phase lacks checkpoint".into());
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate().map_err(str::to_owned)?;
            let binding = self.binding.as_ref().ok_or("V4 checkpoint lacks binding")?;
            if checkpoint.attempt_binding != binding.canonical_digest()?
                || self.checkpoint_digest != Some(checkpoint.canonical_digest()?)
            {
                return Err("V4 checkpoint digest or attempt binding differs".into());
            }
        } else if self.checkpoint_digest.is_some() {
            return Err("V4 checkpoint digest lacks payload".into());
        }
        if self.release_knowledge != ReleaseKnowledge::NotReleased && self.checkpoint.is_none() {
            return Err("V4 release knowledge lacks committed checkpoint".into());
        }
        match self.phase {
            PrivateAttemptPhase::Allocated
            | PrivateAttemptPhase::AuthorityFrozen
            | PrivateAttemptPhase::BoundaryCreated
            | PrivateAttemptPhase::GuardianReady
            | PrivateAttemptPhase::TargetGated
            | PrivateAttemptPhase::CheckpointCommitted
                if self.release_knowledge != ReleaseKnowledge::NotReleased =>
            {
                return Err("V4 release knowledge precedes release intent".into());
            }
            PrivateAttemptPhase::ReleaseIntent
                if self.release_knowledge != ReleaseKnowledge::PossiblyReleased =>
            {
                return Err("V4 release intent lacks uncertainty".into());
            }
            PrivateAttemptPhase::ExecutionObserved
                if self.release_knowledge != ReleaseKnowledge::ExecObserved =>
            {
                return Err("V4 exec phase lacks observation".into());
            }
            _ => {}
        }
        if self.phase == PrivateAttemptPhase::CleanupIncomplete && self.cleanup_error.is_none() {
            return Err("V4 incomplete cleanup lacks an error".into());
        }
        if self.cleanup_error.is_some() && self.phase != PrivateAttemptPhase::CleanupIncomplete {
            return Err("V4 cleanup error appears outside incomplete phase".into());
        }
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_PRIVATE_RECORD_BYTES {
            return Err("V4 record exceeds bound".into());
        }
        let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
        let (body, digest) = text
            .rsplit_once("digest=")
            .ok_or("V4 record checksum absent")?;
        let expected: String = hash_bytes(body.as_bytes()).into();
        if digest != format!("{expected}\n") {
            return Err("V4 record checksum differs".into());
        }
        let mut lines = body.lines();
        if lines.next() != Some("version=4") {
            return Err("V4 record version differs".into());
        }
        let identity = lines
            .next()
            .and_then(|line| line.strip_prefix("cgroup="))
            .ok_or("V4 cgroup binding absent")?;
        let payload = lines
            .next()
            .and_then(|line| line.strip_prefix("payload="))
            .ok_or("V4 payload absent")?;
        if lines.next().is_some() {
            return Err("V4 record has extra fields".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(payload.as_bytes())?;
        let record: Self = serde_json::from_str(payload).map_err(|error| error.to_string())?;
        record.validate()?;
        if record.attempt_id.as_str() != identity {
            return Err("V4 cgroup and payload identity differ".into());
        }
        Ok(record)
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let payload = serde_json::to_string(self).map_err(|error| error.to_string())?;
        let body = format!(
            "version=4\ncgroup={}\npayload={payload}\n",
            self.attempt_id.as_str()
        );
        let digest: String = hash_bytes(body.as_bytes()).into();
        let bytes = format!("{body}digest={digest}\n").into_bytes();
        if bytes.len() > MAX_PRIVATE_RECORD_BYTES {
            return Err("V4 record exceeds bound".into());
        }
        Ok(bytes)
    }
}

/// Owns only the durable record. Native cgroup/process/descriptor custody is
/// established by the separate lifecycle owner before any release capability.
pub struct DurablePrivateAttempt {
    path: PathBuf,
    directory: File,
    record: PrivateAttemptRecordV4,
}

/// This capability exists only after file and containing-directory sync of
/// the exact checkpoint. It is process-local and cannot be deserialized.
pub struct CommittedPrivateCheckpoint {
    attempt_id: BoundedText<64>,
    checkpoint_digest: DiagnosticSha256,
}

/// A release-intent record has been committed before this one-use sender can
/// write the sole authorization byte. A write error remains possibly released.
pub struct PrivateReleasePermit {
    attempt_id: BoundedText<64>,
    checkpoint_digest: DiagnosticSha256,
}

impl PrivateReleasePermit {
    pub fn send(
        self,
        control: &mut File,
        attempt_id: &str,
        checkpoint_digest: &DiagnosticSha256,
    ) -> Result<(), String> {
        if self.attempt_id.as_str() != attempt_id || &self.checkpoint_digest != checkpoint_digest {
            return Err("V4 release permit belongs to a different checkpoint".into());
        }
        send_private_release_byte(control)
    }
}

pub(super) fn send_private_release_byte(control: &mut File) -> Result<(), String> {
    control
        .write_all(&[1])
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: {error}"))
}

impl DurablePrivateAttempt {
    pub fn create(record: PrivateAttemptRecordV4) -> Result<Self, String> {
        super::attempt::secure_state_root()?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?;
        if record.boot_identity.as_str() != boot.trim() {
            return Err("V4 record boot identity differs from host".into());
        }
        Self::create_in(Path::new(STATE_ROOT), record)
    }

    #[cfg(feature = "test-support")]
    pub fn create_for_test(root: &Path, record: PrivateAttemptRecordV4) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|error| error.to_string())?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        Self::create_in(root, record)
    }

    fn create_in(root: &Path, record: PrivateAttemptRecordV4) -> Result<Self, String> {
        if record.phase != PrivateAttemptPhase::Allocated {
            return Err("V4 record creation requires allocated phase".into());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)
            .map_err(|error| error.to_string())?;
        let metadata = directory.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err("V4 state directory permissions differ".into());
        }
        let path = root.join(record.attempt_id.as_str());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.write_all(&record.encode()?)
            .and_then(|()| file.sync_all())
            .and_then(|()| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(Self {
            path,
            directory,
            record,
        })
    }

    pub fn record(&self) -> &PrivateAttemptRecordV4 {
        &self.record
    }

    pub fn freeze_authority(
        &mut self,
        admission: ProviderAdmissionSnapshotV2,
    ) -> Result<(), String> {
        let next = self.record.clone().freeze_authority(admission)?;
        self.replace(next)
    }

    pub fn boundary_created(&mut self) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::AuthorityFrozen {
            return Err("V4 boundary requires frozen authority".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::BoundaryCreated;
        self.replace(next)
    }

    pub fn guardian_ready(&mut self, guardian: ProcessIdentityV4) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::BoundaryCreated {
            return Err("V4 guardian requires dedicated boundary".into());
        }
        let mut next = self.record.clone();
        next.guardian = Some(guardian);
        next.phase = PrivateAttemptPhase::GuardianReady;
        self.replace(next)
    }

    pub fn target_gated(
        &mut self,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
    ) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::GuardianReady {
            return Err("V4 target requires live guardian".into());
        }
        let mut next = self.record.clone();
        next.namespace_init = Some(namespace_init);
        next.target = Some(target);
        next.network_namespace_inode = Some(network_namespace_inode);
        next.phase = PrivateAttemptPhase::TargetGated;
        self.replace(next)
    }

    pub fn commit_checkpoint(
        &mut self,
        checkpoint: PrivateTcpCheckpointV2,
    ) -> Result<CommittedPrivateCheckpoint, String> {
        if self.record.phase != PrivateAttemptPhase::TargetGated {
            return Err("V4 checkpoint requires an observed gated target".into());
        }
        let admission = self
            .record
            .admission
            .as_ref()
            .ok_or("V4 admission absent")?;
        let binding = self
            .record
            .binding
            .as_ref()
            .ok_or("V4 attempt binding absent")?;
        if checkpoint.attempt_binding != binding.canonical_digest()?
            || checkpoint.profile != admission.profile.reference
            || checkpoint.caller_envelope_reference != admission.caller_envelope_reference
            || checkpoint.native_abi != admission.native_abi
            || checkpoint.identity.kind
                != (TargetIdentityKindV2::AdministratorProfile {
                    reference: admission.identity.reference.clone(),
                })
            || !admission
                .identity
                .entrypoints
                .as_slice()
                .iter()
                .any(|entrypoint| entrypoint.sha256 == checkpoint.identity.entrypoint_digest)
            || checkpoint
                .target_network_namespace
                .target_network_inode
                .get()
                != self
                    .record
                    .network_namespace_inode
                    .ok_or("V4 network namespace absent")?
        {
            return Err("V4 checkpoint differs from exact frozen native authority".into());
        }
        checkpoint.validate().map_err(str::to_owned)?;
        let checkpoint_digest = checkpoint.canonical_digest()?;
        let mut next = self.record.clone();
        next.checkpoint = Some(checkpoint);
        next.checkpoint_digest = Some(checkpoint_digest.clone());
        next.phase = PrivateAttemptPhase::CheckpointCommitted;
        self.replace(next)?;
        // The readback must equal the in-memory state after the directory sync.
        self.read_back()?;
        Ok(CommittedPrivateCheckpoint {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest,
        })
    }

    pub fn release_intent(
        &mut self,
        committed: CommittedPrivateCheckpoint,
    ) -> Result<PrivateReleasePermit, String> {
        if self.record.phase != PrivateAttemptPhase::CheckpointCommitted
            || self.record.attempt_id != committed.attempt_id
            || self.record.checkpoint_digest.as_ref() != Some(&committed.checkpoint_digest)
        {
            return Err("V4 release token differs from committed checkpoint".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::ReleaseIntent;
        next.release_knowledge = ReleaseKnowledge::PossiblyReleased;
        self.replace(next)?;
        self.read_back()?;
        Ok(PrivateReleasePermit {
            attempt_id: committed.attempt_id,
            checkpoint_digest: committed.checkpoint_digest,
        })
    }

    pub fn retiring(&mut self) -> Result<(), String> {
        if matches!(
            self.record.phase,
            PrivateAttemptPhase::Retired | PrivateAttemptPhase::CleanupIncomplete
        ) {
            return Err("V4 record is already terminal".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retiring;
        self.replace(next)
    }

    pub fn execution_observed(&mut self) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::ReleaseIntent {
            return Err("V4 exec observation requires release intent".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::ExecutionObserved;
        next.release_knowledge = ReleaseKnowledge::ExecObserved;
        self.replace(next)
    }

    pub fn cleanup_incomplete(&mut self, detail: &str) -> Result<(), String> {
        if self.record.phase == PrivateAttemptPhase::Retired {
            return Err("V4 retired record cannot become incomplete".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::CleanupIncomplete;
        next.cleanup_error = Some(BoundedText::new(detail).map_err(str::to_owned)?);
        self.replace(next)
    }

    /// An allocated or authority-frozen record has never created a native
    /// boundary. Its strict phase validator forbids every resource identity
    /// and checkpoint, so this is the only direct early-retirement path.
    pub fn retire_unallocated(mut self) -> Result<(), String> {
        if !matches!(
            self.record.phase,
            PrivateAttemptPhase::Allocated | PrivateAttemptPhase::AuthorityFrozen
        ) {
            return Err("V4 direct retirement requires a pre-boundary record".into());
        }
        self.retiring()?;
        self.remove_retired()
    }

    /// Only the native owner can construct the opaque permit after its full
    /// resource ledger has completed. The directory sync releases the durable
    /// V2 policy snapshot reference.
    pub(super) fn retire_after_native_cleanup(
        self,
        permit: super::private_lifecycle::VerifiedPrivateRetirement,
    ) -> Result<(), String> {
        if !permit.matches(&self.record) {
            return Err("V4 retirement permit differs from durable attempt".into());
        }
        self.remove_retired()
    }

    fn remove_retired(mut self) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::Retiring {
            return Err("V4 record removal requires retiring phase".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retired;
        self.replace(next)?;
        fs::remove_file(&self.path).map_err(|error| error.to_string())?;
        self.directory.sync_all().map_err(|error| error.to_string())
    }

    fn replace(&mut self, next: PrivateAttemptRecordV4) -> Result<(), String> {
        let temporary = self.path.with_extension("new");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        let bytes = next.encode()?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, &self.path).map_err(|error| error.to_string())?;
        self.directory
            .sync_all()
            .map_err(|error| error.to_string())?;
        self.record = next;
        Ok(())
    }

    pub fn read_back(&self) -> Result<PrivateAttemptRecordV4, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.uid()
                != self
                    .directory
                    .metadata()
                    .map_err(|error| error.to_string())?
                    .uid()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("V4 record ownership or mode differs".into());
        }
        let mut bytes = Vec::new();
        file.take((MAX_PRIVATE_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        let record = PrivateAttemptRecordV4::parse(&bytes)?;
        if record != self.record {
            return Err("V4 durable record differs from owned state".into());
        }
        Ok(record)
    }
}
