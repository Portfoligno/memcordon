//! Native process and cleanup observations in a separately named journal format.
//! A checksum detects torn writes; ownership and native custody remain separate.
//! Parsed records never authorize execution.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
#[cfg(feature = "test-support")]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use memcordon_core::workload_admission_v2::AttemptBindingV2;
use memcordon_core::workload_evidence_v2::PrivateTcpCheckpointV2;
use memcordon_core::{BoundedText, DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::STATE_ROOT;

pub(crate) const MAX_PRIVATE_RECORD_BYTES: usize = memcordon_core::workload_limits::REGISTRY_BYTES
    + memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateAttemptPhase {
    Allocated,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedDirectoryIdentityV2 {
    pub device: u64,
    pub inode: u64,
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
    pub admission_metadata:
        Option<memcordon_core::workload_admission_v2::RuntimePrivateAdmissionSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_admission_metadata:
        Option<memcordon_core::workload_admission_v3::RuntimeMixedAdmissionSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_export_intent: Option<BoundedText<1024>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_root_staging_intent: Option<BoundedText<1024>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_worker: Option<ProcessIdentityV4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_cgroup_identity: Option<MixedDirectoryIdentityV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_staging_identity: Option<MixedDirectoryIdentityV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_export_identity: Option<MixedDirectoryIdentityV2>,
    pub phase: PrivateAttemptPhase,
    pub release_knowledge: ReleaseKnowledge,
    pub binding: Option<AttemptBindingV2>,
    pub guardian: Option<ProcessIdentityV4>,
    pub namespace_init: Option<ProcessIdentityV4>,
    pub target: Option<ProcessIdentityV4>,
    pub network_namespace_inode: Option<u64>,
    pub checkpoint: Option<PrivateTcpCheckpointV2>,
    pub checkpoint_digest: Option<DiagnosticSha256>,
    pub(super) gated_facts: Option<OperationalGatedFacts>,
    pub cleanup_error: Option<BoundedText<4096>>,
}

/// Actual pre-release observations. No post-exec claim is made at this stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationalGatedFacts {
    pub format: String,
    pub revision: u32,
    pub attempt_binding: DiagnosticSha256,
    pub target: ProcessIdentityV4,
    pub init: ProcessIdentityV4,
    pub network_namespace_inode: u64,
    pub entrypoint_sha256: DiagnosticSha256,
    pub filter_sha256: DiagnosticSha256,
    pub topology_sha256: DiagnosticSha256,
    pub gated_descriptor_count: u8,
}

impl OperationalGatedFacts {
    fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.private-gated-observation"
            || self.revision != 1
            || self.gated_descriptor_count != 5
            || self.network_namespace_inode == 0
        {
            return Err("private gated observation format or inventory differs".into());
        }
        self.target.validate()?;
        self.init.validate()
    }
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
            admission_metadata: None,
            mixed_admission_metadata: None,
            mixed_export_intent: None,
            mixed_export_identity: None,
            mixed_root_staging_intent: None,
            mixed_worker: None,
            mixed_cgroup_identity: None,
            mixed_staging_identity: None,
            phase: PrivateAttemptPhase::Allocated,
            release_knowledge: ReleaseKnowledge::NotReleased,
            binding: None,
            guardian: None,
            namespace_init: None,
            target: None,
            network_namespace_inode: None,
            checkpoint: None,
            checkpoint_digest: None,
            gated_facts: None,
            cleanup_error: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), String> {
        let identity = self.attempt_id.as_str();
        if !super::cgroup::valid_attempt_identity(identity)
            || self.boot_identity.as_str().is_empty()
        {
            return Err("V4 attempt or boot identity invalid".into());
        }
        self.frontend.validate()?;
        if self.admission_metadata.is_some() && self.mixed_admission_metadata.is_some() {
            return Err("native journal has conflicting admission revisions".into());
        }
        if self.mixed_worker.is_some()
            || self.mixed_cgroup_identity.is_some()
            || self.mixed_staging_identity.is_some()
        {
            if self.mixed_admission_metadata.is_none() {
                return Err("mixed native ownership appears without matching admission".into());
            }
            if let Some(worker) = &self.mixed_worker {
                worker.validate()?;
                if worker == &self.frontend {
                    return Err("mixed worker aliases frontend".into());
                }
            }
            if [&self.mixed_cgroup_identity, &self.mixed_staging_identity]
                .into_iter()
                .flatten()
                .any(|identity| identity.inode == 0)
            {
                return Err("mixed directory ownership has zero inode".into());
            }
            if self.mixed_staging_identity.is_some() && self.mixed_root_staging_intent.is_none() {
                return Err("mixed staging identity lacks original intent".into());
            }
        }
        if let Some(path) = &self.mixed_export_intent {
            if self.mixed_admission_metadata.is_none()
                || path.as_str()
                    != format!("/run/memcordon/private-export-{}", self.attempt_id.as_str())
            {
                return Err("mixed export journal intent differs from attempt".into());
            }
        }
        if let Some(identity) = &self.mixed_export_identity {
            if identity.inode == 0 || self.mixed_export_intent.is_none() {
                return Err("mixed export identity lacks original intent".into());
            }
        }
        if let Some(path) = &self.mixed_root_staging_intent {
            if self.mixed_admission_metadata.is_none()
                || path.as_str()
                    != format!("/run/memcordon/private-root-{}", self.attempt_id.as_str())
            {
                return Err("mixed root staging intent differs from attempt".into());
            }
        }
        if let Some(metadata) = &self.mixed_admission_metadata {
            metadata.validate()?;
            if metadata.attempt_id != self.attempt_id {
                return Err("mixed journal attempt association differs".into());
            }
            if let Some(binding) = &self.binding {
                if binding.admission_digest != metadata.canonical_digest()?
                    || binding.native_invocation_digest != metadata.invocation_sha256
                {
                    return Err("mixed journal admission association differs".into());
                }
            }
        }
        if let Some(metadata) = &self.admission_metadata {
            metadata.validate()?;
            if let Some(binding) = &self.binding {
                if binding.admission_digest != metadata.canonical_digest()?
                    || binding.native_invocation_digest != metadata.invocation_sha256
                {
                    return Err("private journal local admission association differs".into());
                }
            }
        }
        for process in [&self.guardian, &self.namespace_init, &self.target]
            .into_iter()
            .flatten()
        {
            process.validate()?;
        }
        if self.network_namespace_inode == Some(0) {
            return Err("V4 network namespace inode is zero".into());
        }
        if let Some(binding) = &self.binding {
            if binding.attempt_id != self.attempt_id
                || binding.caller_envelope_digest != self.caller_envelope_digest
            {
                return Err("native journal attempt correlation differs".into());
            }
        }
        match self.phase {
            PrivateAttemptPhase::Allocated
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
        if committed && self.gated_facts.is_none() {
            return Err("private committed phase lacks actual gated observations".into());
        }
        if let Some(facts) = &self.gated_facts {
            facts.validate()?;
            if self
                .binding
                .as_ref()
                .map(AttemptBindingV2::canonical_digest)
                .transpose()?
                != Some(facts.attempt_binding.clone())
                || self.target.as_ref() != Some(&facts.target)
                || self.namespace_init.as_ref() != Some(&facts.init)
                || self.network_namespace_inode != Some(facts.network_namespace_inode)
            {
                return Err("private gated observations differ from native journal".into());
            }
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
        if self.release_knowledge != ReleaseKnowledge::NotReleased && self.gated_facts.is_none() {
            return Err("private release knowledge lacks native gated observations".into());
        }
        match self.phase {
            PrivateAttemptPhase::Allocated
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
        if lines.next() != Some("format=memcordon.private-native-journal")
            || lines.next() != Some("revision=1")
        {
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
            "format=memcordon.private-native-journal\nrevision=1\ncgroup={}\npayload={payload}\n",
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
    retirement_file: Option<File>,
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
            retirement_file: None,
        })
    }

    pub fn record(&self) -> &PrivateAttemptRecordV4 {
        &self.record
    }

    pub(super) fn attach_admission_metadata(
        &mut self,
        metadata: memcordon_core::workload_admission_v2::RuntimePrivateAdmissionSnapshot,
    ) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::Allocated
            || self.record.admission_metadata.is_some()
            || self.record.mixed_admission_metadata.is_some()
        {
            return Err("private admission metadata must precede native allocation".into());
        }
        metadata.validate()?;
        let mut next = self.record.clone();
        next.binding = Some(AttemptBindingV2 {
            attempt_id: next.attempt_id.clone(),
            admission_digest: metadata.canonical_digest()?,
            caller_envelope_digest: next.caller_envelope_digest.clone(),
            native_invocation_digest: metadata.invocation_sha256.clone(),
        });
        next.admission_metadata = Some(metadata);
        self.replace(next)
    }

    pub(super) fn attach_mixed_admission_metadata(
        &mut self,
        metadata: memcordon_core::workload_admission_v3::RuntimeMixedAdmissionSnapshot,
    ) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::Allocated
            || self.record.admission_metadata.is_some()
            || self.record.mixed_admission_metadata.is_some()
        {
            return Err("mixed admission must precede native allocation".into());
        }
        metadata.validate()?;
        let mut next = self.record.clone();
        next.binding = Some(AttemptBindingV2 {
            attempt_id: next.attempt_id.clone(),
            admission_digest: metadata.canonical_digest()?,
            caller_envelope_digest: next.caller_envelope_digest.clone(),
            native_invocation_digest: metadata.invocation_sha256.clone(),
        });
        next.mixed_admission_metadata = Some(metadata);
        self.replace(next)
    }

    pub fn boundary_created(&mut self) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::Allocated {
            return Err("native boundary requires an allocated journal".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::BoundaryCreated;
        self.replace(next)
    }

    pub(super) fn commit_gated_facts(
        &mut self,
        facts: OperationalGatedFacts,
    ) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::TargetGated
            || (self.record.admission_metadata.is_none()
                && self.record.mixed_admission_metadata.is_none())
        {
            return Err(
                "private commit requires actual gated target and descriptive local metadata".into(),
            );
        }
        let mut next = self.record.clone();
        next.gated_facts = Some(facts);
        next.phase = PrivateAttemptPhase::CheckpointCommitted;
        self.replace(next)?;
        if self.read_back()? != self.record {
            return Err("private gated journal durable readback differs".into());
        }
        Ok(())
    }

    pub(super) fn release_intent(&mut self) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::CheckpointCommitted {
            return Err("private release requires durable gated observations".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::ReleaseIntent;
        next.release_knowledge = ReleaseKnowledge::PossiblyReleased;
        self.replace(next)
    }

    #[cfg(test)]
    pub fn release_intent_for_component_test(&mut self) -> Result<(), String> {
        self.release_intent()
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
        next.namespace_init = Some(namespace_init.clone());
        next.target = Some(target.clone());
        next.network_namespace_inode = Some(network_namespace_inode);
        next.phase = PrivateAttemptPhase::TargetGated;
        self.replace(next)
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

    /// An allocated record has never created a native
    /// boundary. Its strict phase validator forbids every resource identity
    /// and checkpoint, so this is the only direct early-retirement path.
    pub fn retire_unallocated(mut self) -> Result<(), String> {
        if !matches!(self.record.phase, PrivateAttemptPhase::Allocated) {
            return Err("V4 direct retirement requires a pre-boundary record".into());
        }
        self.retiring()?;
        self.remove_retired()
    }

    /// Only the native owner can construct the opaque permit after its full
    /// resource ledger has completed. The directory sync releases the durable
    /// journal after actual native cleanup.
    pub(super) fn retire_after_native_cleanup(
        self,
        permit: super::private_lifecycle::VerifiedPrivateRetirement,
    ) -> Result<(), String> {
        if !permit.matches(&self.record) {
            return Err("V4 retirement permit differs from durable attempt".into());
        }
        self.remove_retired()
    }
    pub(super) fn begin_mixed_retirement(&mut self) -> Result<(), String> {
        if self.record.mixed_admission_metadata.is_none() {
            return Err("mixed retirement journal metadata absent".into());
        }
        if self.record.phase == PrivateAttemptPhase::Retired {
            return if self.retirement_file.is_some() {
                Ok(())
            } else {
                Err("retired mixed journal lacks held finalization custody".into())
            };
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retiring;
        self.replace(next)
    }
    pub(super) fn record_mixed_export_intent(&mut self, path: &Path) -> Result<(), String> {
        let path = path.to_str().ok_or("mixed export path is not UTF-8")?;
        if self.record.phase != PrivateAttemptPhase::Retiring
            || self.record.mixed_admission_metadata.is_none()
        {
            return Err("mixed export intent requires native retiring phase".into());
        }
        if let Some(existing) = &self.record.mixed_export_intent {
            return if existing.as_str() == path {
                Ok(())
            } else {
                Err("mixed export intent changed".into())
            };
        }
        let mut next = self.record.clone();
        next.mixed_export_intent = Some(BoundedText::new(path).map_err(str::to_owned)?);
        self.replace(next)
    }
    pub(super) fn record_mixed_root_staging_intent(&mut self, path: &Path) -> Result<(), String> {
        let path = path.to_str().ok_or("mixed staging path is not UTF-8")?;
        if self.record.phase != PrivateAttemptPhase::BoundaryCreated
            || self.record.mixed_admission_metadata.is_none()
        {
            return Err("mixed staging intent requires owned boundary".into());
        }
        if let Some(existing) = &self.record.mixed_root_staging_intent {
            return if existing.as_str() == path {
                Ok(())
            } else {
                Err("mixed staging intent changed".into())
            };
        }
        let mut next = self.record.clone();
        next.mixed_root_staging_intent = Some(BoundedText::new(path).map_err(str::to_owned)?);
        self.replace(next)
    }
    pub(super) fn record_mixed_worker(&mut self, worker: ProcessIdentityV4) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::Allocated
            || self.record.mixed_admission_metadata.is_none()
        {
            return Err("mixed worker must precede native allocation".into());
        }
        let mut next = self.record.clone();
        next.mixed_worker = Some(worker);
        self.replace(next)
    }
    pub(super) fn record_mixed_export_identity(
        &mut self,
        identity: MixedDirectoryIdentityV2,
    ) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::Retiring
            || self.record.mixed_export_intent.is_none()
        {
            return Err("mixed export ownership phase differs".into());
        }
        if self
            .record
            .mixed_export_identity
            .as_ref()
            .is_some_and(|prior| prior != &identity)
        {
            return Err("mixed export directory identity changed".into());
        }
        let mut next = self.record.clone();
        next.mixed_export_identity = Some(identity);
        self.replace(next)
    }
    pub(super) fn record_mixed_directory(
        &mut self,
        staging: bool,
        identity: MixedDirectoryIdentityV2,
    ) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::BoundaryCreated
            || self.record.mixed_admission_metadata.is_none()
        {
            return Err("mixed native directory ownership phase differs".into());
        }
        let mut next = self.record.clone();
        let slot = if staging {
            &mut next.mixed_staging_identity
        } else {
            &mut next.mixed_cgroup_identity
        };
        if let Some(prior) = slot {
            if prior != &identity {
                return Err("mixed native directory identity changed".into());
            }
        }
        *slot = Some(identity);
        self.replace(next)
    }
    /// Retain the exact final journal inode until unlink and directory sync
    /// succeed. A retry after successful unlink checks the held zero-link
    /// inode and path absence, rather than recreating or adopting a journal.
    pub(super) fn retire_mixed_after_native_cleanup(
        &mut self,
        permit: super::private_lifecycle::VerifiedPrivateRetirement,
    ) -> Result<(), String> {
        if !permit.matches(&self.record) || self.record.mixed_admission_metadata.is_none() {
            return Err("mixed native retirement permit differs".into());
        }
        if self.record.phase == PrivateAttemptPhase::Retiring {
            let mut next = self.record.clone();
            next.phase = PrivateAttemptPhase::Retired;
            self.replace(next)?;
        }
        if self.record.phase != PrivateAttemptPhase::Retired {
            return Err("mixed journal finalization phase differs".into());
        }
        if self.retirement_file.is_none() {
            if self.read_back()? != self.record {
                return Err("mixed final journal content changed".into());
            }
            self.retirement_file = Some(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                    .open(&self.path)
                    .map_err(|error| error.to_string())?,
            );
        }
        let held = self
            .retirement_file
            .as_ref()
            .expect("held final journal")
            .metadata()
            .map_err(|error| error.to_string())?;
        match fs::symlink_metadata(&self.path) {
            Ok(current) => {
                if !current.is_file()
                    || current.uid() != 0
                    || current.nlink() != 1
                    || current.mode() & 0o7777 != 0o600
                    || (current.dev(), current.ino()) != (held.dev(), held.ino())
                {
                    return Err("mixed final journal native inode differs".into());
                }
                fs::remove_file(&self.path).map_err(|error| error.to_string())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && held.nlink() == 0 => {}
            Err(error) => return Err(error.to_string()),
        }
        if self
            .retirement_file
            .as_ref()
            .expect("held final journal")
            .metadata()
            .map_err(|error| error.to_string())?
            .nlink()
            != 0
        {
            return Err("mixed final journal retains unexpected links".into());
        }
        self.directory.sync_all().map_err(|error| error.to_string())
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
        let bytes = next.encode()?;
        let temporary = self.path.with_extension("new");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
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
    #[cfg(test)]
    pub fn component_native_bytes(&self) -> Result<Vec<u8>, String> {
        self.component_native_observation().map(|(bytes, _)| bytes)
    }
    #[cfg(test)]
    pub fn component_native_observation(&self) -> Result<(Vec<u8>, serde_json::Value), String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if !before.is_file()
            || before.uid() != 0
            || before.nlink() != 1
            || before.mode() & 0o7777 != 0o600
            || before.len() > MAX_PRIVATE_RECORD_BYTES as u64
        {
            return Err("component native journal custody differs".into());
        }
        let mut bytes = Vec::new();
        (&file)
            .take((MAX_PRIVATE_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if PrivateAttemptRecordV4::parse(&bytes)? != self.record {
            return Err("component native journal differs from actual owner".into());
        }
        let stamp = |m: &std::fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.len(),
                m.ctime(),
                m.ctime_nsec(),
                m.nlink(),
                m.uid(),
                m.mode(),
            )
        };
        if stamp(&before) != stamp(&file.metadata().map_err(|e| e.to_string())?) {
            return Err("component native journal changed while read".into());
        }
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        if stamp(&before) != stamp(&named.metadata().map_err(|e| e.to_string())?) {
            return Err("component native journal named inode differs".into());
        }
        let mut readback = Vec::new();
        (&named)
            .take((MAX_PRIVATE_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut readback)
            .map_err(|e| e.to_string())?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path.parent().ok_or("journal parent absent")?)
            .map_err(|e| e.to_string())?
            .metadata()
            .map_err(|e| e.to_string())?;
        let held = self.directory.metadata().map_err(|e| e.to_string())?;
        if readback != bytes
            || (parent.dev(), parent.ino(), parent.uid(), parent.mode())
                != (held.dev(), held.ino(), held.uid(), held.mode())
            || !parent.is_dir()
            || !held.is_dir()
            || held.uid() != 0
            || held.mode() & 0o022 != 0
            || stamp(&before) != stamp(&file.metadata().map_err(|error| error.to_string())?)
            || stamp(&before) != stamp(&named.metadata().map_err(|error| error.to_string())?)
        {
            return Err("component journal named byte/parent readback differs".into());
        }
        let observation = serde_json::json!({"path":self.path,"device":before.dev(),"inode":before.ino(),"length":before.len(),"links":before.nlink(),"uid":before.uid(),"mode":before.mode(),
            "parent_path":self.path.parent(),"parent_device":held.dev(),"parent_inode":held.ino(),"parent_uid":held.uid(),"parent_mode":held.mode()});
        Ok((bytes, observation))
    }
}
