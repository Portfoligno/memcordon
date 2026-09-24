//! Move-only ownership for one private attempt. Every acquired native handle
//! enters this ledger before another fallible step. Only `retire` can produce
//! terminal evidence; dropping the owner starts best-effort containment.

use std::fs::File;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::report_v11::{
    PrivateExecutionReportV11, PrivateTerminalOutcomeV11, TrustedPrivateExecutionV11,
};
use memcordon_core::workload_admission_v2::AttemptBindingV2;
use memcordon_core::workload_evidence_v2::{
    EntryResourceObservationV2, NamespaceObservationV2, PrivatePortPolicyV1,
    PrivateTcpCheckpointV2, PrivateTcpRetiredV2, QualifiedNativeAbiV2, TargetIdentityKindV2,
    TargetIdentityObservationV2, VerifiedTrue,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::cgroup::AttemptCgroup;
use super::descriptor_custody::{
    ExpectedGatedDescriptorInventory, GatedDescriptorProof, ProviderPipeStdio,
    verify_private_exec_entry,
};
use super::execution_identity::ResolvedTargetIdentity;
use super::launch::PrivateGatedPrelaunch;
use super::namespace::{
    CallerMountContext, NamespaceInit, NamespaceMode, clone_into_cgroup_from_caller_with_mode,
};
use super::network_filter::NativeAbi;
use super::network_profile::PrivateNetworkSetup;
use super::private_attempt::{
    DurablePrivateAttempt, PrivateAttemptPhase, PrivateAttemptRecordV4, ProcessIdentityV4,
};
use super::private_guardian::PrivateGuardian;
use super::private_namespace_init::{
    PrivateNamespaceStartupProvider, observe_private_namespace_startup,
    private_namespace_startup_channel, run_private_namespace_init,
};
use super::private_relay::PrivateRelay;
use super::private_target::{
    PRIVATE_EXEC_ARMED_PACKET, PrivateControlObservation, PrivateGatedReadback, PrivateGatedTarget,
    PrivateNetworkNamespaceOwner, decode_private_control_packet, observe_private_gated_target,
};
use crate::policy_registry::native::Lease;
use crate::request::NamespaceIdentity;

pub struct PrivateObservedTarget {
    native: PrivateGatedReadback,
    network: PrivateNetworkSetup,
    target: ProcessIdentityV4,
    namespace_init: ProcessIdentityV4,
    caller_network_namespace: NamespaceIdentity,
}

pub enum PrivateExecObservation {
    ArmedAndControlClosed,
    Failed { phase: u8, detail: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PrivateMonitorOutcome {
    Completed,
    DeadlineExceeded,
    FrontendLost,
    Revoked,
    MemoryOom,
}

pub struct PrivateRetirementObservation {
    attempt_id: String,
    retired: Option<PrivateTcpRetiredV2>,
    candidate_exit_code: Option<i32>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrivateCandidateTerminalV4 {
    Exited { code: i32 },
    NativeFailure { phase: u8, detail: String },
    Interrupted { reason: PrivateMonitorOutcome },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTerminalReceiptV4 {
    schema_version: u8,
    attempt_id: String,
    attempt: AttemptBindingV2,
    checkpoint: PrivateTcpCheckpointV2,
    retirement: PrivateTcpRetiredV2,
    candidate: PrivateCandidateTerminalV4,
}

impl PrivateTerminalReceiptV4 {
    /// Only a completed owner ledger can supply retirement; candidate outcome
    /// remains independent of cleanup success and is never inferred from it.
    pub fn observed(
        attempt: AttemptBindingV2,
        checkpoint: PrivateTcpCheckpointV2,
        exec: PrivateExecObservation,
        monitor: Option<PrivateMonitorOutcome>,
        retirement: PrivateRetirementObservation,
    ) -> Result<Self, String> {
        let retired = retirement
            .retired
            .ok_or("MCSEALED-PRIVATE-RECEIPT: checkpoint retirement absent")?;
        if attempt.canonical_digest()? != checkpoint.attempt_binding
            || attempt.attempt_id.as_str() != retirement.attempt_id
            || !retired.terminal_success(&checkpoint)
        {
            return Err("MCSEALED-PRIVATE-RECEIPT: retirement differs from checkpoint".into());
        }
        let candidate = match (exec, monitor) {
            (PrivateExecObservation::Failed { phase, detail }, None) => {
                PrivateCandidateTerminalV4::NativeFailure { phase, detail }
            }
            (
                PrivateExecObservation::ArmedAndControlClosed,
                Some(PrivateMonitorOutcome::Completed),
            ) => PrivateCandidateTerminalV4::Exited {
                code: retirement
                    .candidate_exit_code
                    .ok_or("MCSEALED-PRIVATE-RECEIPT: completed exit status absent")?,
            },
            (PrivateExecObservation::ArmedAndControlClosed, Some(reason)) => {
                PrivateCandidateTerminalV4::Interrupted { reason }
            }
            _ => return Err("MCSEALED-PRIVATE-RECEIPT: native result and monitor differ".into()),
        };
        Ok(Self {
            schema_version: 4,
            attempt_id: retirement.attempt_id,
            attempt,
            checkpoint,
            retirement: retired,
            candidate,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn digest(&self) -> Result<DiagnosticSha256, String> {
        Ok(memcordon_core::workload_codec::hash_bytes(&self.encode()?))
    }

    /// The authenticated control service reads this exact internal frame,
    /// never treating successful JSON parsing as public V2 policy evidence.
    pub fn parse_verified(bytes: &[u8], expected_attempt: [u8; 16]) -> Result<Self, String> {
        if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("MCSEALED-PRIVATE-RECEIPT: terminal exceeds byte bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let receipt: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        let identity = expected_attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if receipt.schema_version != 4
            || receipt.attempt_id != identity
            || receipt.attempt.attempt_id.as_str() != identity
            || receipt.attempt.canonical_digest()? != receipt.checkpoint.attempt_binding
            || !receipt.retirement.terminal_success(&receipt.checkpoint)
            || matches!(
                &receipt.candidate,
                PrivateCandidateTerminalV4::Interrupted {
                    reason: PrivateMonitorOutcome::Completed
                }
            )
            || matches!(
                &receipt.candidate,
                PrivateCandidateTerminalV4::NativeFailure { detail, .. } if detail.is_empty()
            )
        {
            return Err("MCSEALED-PRIVATE-RECEIPT: internal terminal binding differs".into());
        }
        Ok(receipt)
    }

    /// Project an authenticated native terminal into the distinct V11 report
    /// contract using the move-only installed generation retained at release.
    /// This does not publish the report or qualify the host by itself.
    #[allow(dead_code)] // The public V2 service route stays closed pending native qualification.
    pub fn project_v11(
        &self,
        installed: &crate::package::VerifiedInstalledPrivateReportBinding,
    ) -> Result<PrivateExecutionReportV11, String> {
        if self.schema_version != 4
            || self.attempt_id != self.attempt.attempt_id.as_str()
            || self.attempt.canonical_digest()? != self.checkpoint.attempt_binding
            || !self.retirement.terminal_success(&self.checkpoint)
            || self.checkpoint.filter_digest != *installed.filter_digest()
            || !matches!(
                (self.checkpoint.native_abi, installed.filter_abi()),
                (QualifiedNativeAbiV2::X86_64LinuxGnu, NativeAbi::X86_64)
                    | (QualifiedNativeAbiV2::Aarch64LinuxGnu, NativeAbi::Aarch64)
            )
        {
            return Err("MCSEALED-PRIVATE-V11: installed/native terminal binding differs".into());
        }
        let outcome = match &self.candidate {
            PrivateCandidateTerminalV4::Exited { code } => {
                PrivateTerminalOutcomeV11::Exited { code: *code }
            }
            PrivateCandidateTerminalV4::NativeFailure { phase, detail } => {
                let phase = match phase {
                    1 => "entrypoint",
                    2 => "identity",
                    3 => "filter",
                    4 => "authorization",
                    5 => "exec",
                    _ => return Err("MCSEALED-PRIVATE-V11: unknown native failure phase".into()),
                };
                PrivateTerminalOutcomeV11::NativeFailure {
                    phase: phase.into(),
                    detail: detail.clone(),
                }
            }
            PrivateCandidateTerminalV4::Interrupted { reason } => {
                let reason = match reason {
                    PrivateMonitorOutcome::DeadlineExceeded => "deadline-exceeded",
                    PrivateMonitorOutcome::FrontendLost => "frontend-lost",
                    PrivateMonitorOutcome::Revoked => "revoked",
                    PrivateMonitorOutcome::MemoryOom => "memory-oom",
                    PrivateMonitorOutcome::Completed => {
                        return Err(
                            "MCSEALED-PRIVATE-V11: completed monitor is not interrupted".into()
                        );
                    }
                };
                PrivateTerminalOutcomeV11::Interrupted {
                    reason: reason.into(),
                }
            }
        };
        let checkpoint_digest = self.checkpoint.canonical_digest()?;
        let retirement_digest = self.retirement.canonical_digest()?;
        let terminal_digest = self.digest()?;
        let trusted = TrustedPrivateExecutionV11 {
            source_commit: installed.source_commit(),
            native_abi: self.checkpoint.native_abi,
            runtime_manifest_sha256: installed.runtime_manifest_sha256(),
            installed_qualification_sha256: installed.qualification_digest(),
            attempt: &self.attempt,
            checkpoint_sha256: &checkpoint_digest,
            retirement_sha256: &retirement_digest,
            terminal_receipt_sha256: &terminal_digest,
            outcome: &outcome,
        };
        PrivateExecutionReportV11::from_trusted_native(
            self.checkpoint.clone(),
            self.retirement.clone(),
            &trusted,
        )
    }
}

/// Constructible only after the native owner has independently closed or
/// retired every resource. A parsed durable record cannot mint this permit.
pub(super) struct VerifiedPrivateRetirement {
    attempt_id: String,
    checkpoint_digest: Option<memcordon_core::DiagnosticSha256>,
}

impl VerifiedPrivateRetirement {
    fn observed(record: &PrivateAttemptRecordV4) -> Self {
        Self {
            attempt_id: record.attempt_id.as_str().to_owned(),
            checkpoint_digest: record.checkpoint_digest.clone(),
        }
    }

    pub(super) fn matches(&self, record: &PrivateAttemptRecordV4) -> bool {
        self.attempt_id == record.attempt_id.as_str()
            && self.checkpoint_digest == record.checkpoint_digest
    }
}

pub struct PrivateAttemptOwner {
    record: Option<DurablePrivateAttempt>,
    cgroup: Option<AttemptCgroup>,
    namespace_init: Option<NamespaceInit>,
    guardian: Option<PrivateGuardian>,
    target_pidfd: Option<OwnedFd>,
    network: Option<PrivateNetworkNamespaceOwner>,
    stdio: Option<ProviderPipeStdio>,
    relay: Option<PrivateRelay>,
    control: Option<File>,
    startup: Option<PrivateNamespaceStartupProvider>,
    status: Option<File>,
    expected_descriptors: Option<ExpectedGatedDescriptorInventory>,
    entrypoint_digest: Option<DiagnosticSha256>,
    gated_descriptors: Option<GatedDescriptorProof>,
    monitor_outcome: Option<PrivateMonitorOutcome>,
}

impl PrivateAttemptOwner {
    pub fn new(record: DurablePrivateAttempt) -> Result<Self, String> {
        if record.record().phase != PrivateAttemptPhase::AuthorityFrozen {
            return Err("MCSEALED-PRIVATE-OWNER: authority must be frozen".into());
        }
        record.read_back()?;
        Ok(Self {
            record: Some(record),
            cgroup: None,
            namespace_init: None,
            guardian: None,
            target_pidfd: None,
            network: None,
            stdio: None,
            relay: None,
            control: None,
            startup: None,
            status: None,
            expected_descriptors: None,
            entrypoint_digest: None,
            gated_descriptors: None,
            monitor_outcome: None,
        })
    }

    fn record_mut(&mut self) -> &mut DurablePrivateAttempt {
        self.record
            .as_mut()
            .expect("private owner retains durable record")
    }

    pub fn possibly_released(&self) -> bool {
        self.record.as_ref().is_some_and(|record| {
            record.record().release_knowledge
                != super::private_attempt::ReleaseKnowledge::NotReleased
        })
    }

    pub fn create_boundary(
        &mut self,
        memory_max: Option<u64>,
        swap_limit: crate::request::SwapLimit,
    ) -> Result<(), String> {
        if self.cgroup.is_some() {
            return Err("MCSEALED-PRIVATE-OWNER: boundary already owned".into());
        }
        let identity = self.record_mut().record().attempt_id.as_str().to_owned();
        let cgroup = AttemptCgroup::create(&identity, memory_max, swap_limit)?;
        self.cgroup = Some(cgroup);
        self.record_mut().boundary_created()
    }

    /// The target stub is transferred to the exact cgroup clone path. Its
    /// provider endpoints remain owned here for authenticated readback and
    /// bounded relay cleanup.
    pub fn take_target_for_clone(
        &mut self,
        prelaunch: PrivateGatedPrelaunch,
    ) -> Result<PrivateGatedTarget, String> {
        if self.cgroup.is_none() || self.stdio.is_some() || self.control.is_some() {
            return Err("MCSEALED-PRIVATE-OWNER: prelaunch transfer phase differs".into());
        }
        self.stdio = Some(prelaunch.provider_stdio);
        self.control = Some(prelaunch.provider_control);
        self.expected_descriptors = Some(prelaunch.expected_descriptors);
        self.entrypoint_digest = Some(prelaunch.entrypoint_digest);
        Ok(prelaunch.target)
    }

    pub fn hold_startup(&mut self, startup: PrivateNamespaceStartupProvider) -> Result<(), String> {
        if self.startup.is_some() {
            return Err("MCSEALED-PRIVATE-OWNER: startup channel already owned".into());
        }
        self.startup = Some(startup);
        Ok(())
    }

    /// Clone the trusted init into the recorded cgroup through the caller
    /// mount-context bootstrap. Its target remains gated. Provider-only
    /// endpoint copies are closed in the init before target setup.
    pub fn spawn_namespace(
        &mut self,
        prelaunch: PrivateGatedPrelaunch,
        caller_mount: CallerMountContext,
        caller_cwd: OwnedFd,
        caller_namespace: NamespaceIdentity,
        provider_namespace: NamespaceIdentity,
    ) -> Result<(), String> {
        if self.record_mut().record().phase != PrivateAttemptPhase::BoundaryCreated
            || self.namespace_init.is_some()
        {
            return Err("MCSEALED-PRIVATE-OWNER: namespace clone phase differs".into());
        }
        let (provider_startup, init_startup) = private_namespace_startup_channel()?;
        self.hold_startup(provider_startup)?;
        let mut status_fds = [-1_i32; 2];
        // SAFETY: pipe2 initializes two unique owned descriptors on success.
        if unsafe { libc::pipe2(status_fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-OWNER: status pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful pipe2 initialized both unique descriptors.
        let status_read = unsafe { File::from_raw_fd(status_fds[0]) };
        // SAFETY: successful pipe2 initialized both unique descriptors.
        let status_write = unsafe { File::from_raw_fd(status_fds[1]) };
        self.status = Some(status_read);
        let target = self.take_target_for_clone(prelaunch)?;
        let startup_fd = self
            .startup
            .as_ref()
            .expect("startup was stored")
            .as_fd()
            .as_raw_fd();
        let control_fd = self
            .control
            .as_ref()
            .expect("control was stored")
            .as_raw_fd();
        let status_read_fd = self.status.as_ref().expect("status was stored").as_raw_fd();
        let provider_pipe_fds = self
            .stdio
            .as_ref()
            .expect("stdio was stored")
            .descriptor_numbers();
        let cgroup = self.cgroup_file()?;
        let init = clone_into_cgroup_from_caller_with_mode(
            &cgroup,
            caller_mount,
            NamespaceMode::PrivateTcp4,
            move || {
                // SAFETY: these are inherited provider-only copies in the
                // clone child; the parent retains its owned descriptors.
                unsafe {
                    libc::close(status_read_fd);
                    for fd in provider_pipe_fds {
                        libc::close(fd);
                    }
                }
                // SAFETY: both borrowed descriptors are live inherited copies
                // until run_private_namespace_init closes them in this child.
                let startup = unsafe { BorrowedFd::borrow_raw(startup_fd) };
                let control = unsafe { BorrowedFd::borrow_raw(control_fd) };
                run_private_namespace_init(
                    target,
                    init_startup,
                    startup,
                    control,
                    status_write,
                    caller_cwd,
                    caller_namespace,
                    provider_namespace,
                    true,
                )
            },
        )?;
        self.attach_init(init)
    }

    pub fn cgroup_file(&self) -> Result<File, String> {
        self.cgroup
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-OWNER: cgroup absent")?
            .open()
    }

    pub fn clone_mode(&self) -> NamespaceMode {
        NamespaceMode::PrivateTcp4
    }

    pub fn attach_init(&mut self, init: NamespaceInit) -> Result<(), String> {
        if self.namespace_init.is_some() || self.cgroup.is_none() {
            return Err("MCSEALED-PRIVATE-OWNER: namespace init transfer differs".into());
        }
        self.namespace_init = Some(init);
        let init = self.namespace_init.as_ref().expect("init was just stored");
        ProcessIdentityV4::observe(init.host_pid, init.pidfd.as_fd())?;
        Ok(())
    }

    pub fn start_guardian(
        &mut self,
        attempt_id: [u8; 16],
        frontend_pidfd: BorrowedFd<'_>,
        worker_pidfd: BorrowedFd<'_>,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.guardian.is_some()
            || self.record_mut().record().phase != PrivateAttemptPhase::BoundaryCreated
        {
            return Err("MCSEALED-PRIVATE-OWNER: guardian phase differs".into());
        }
        let hex_identity = attempt_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let record = self.record.as_ref().expect("owner retains record").record();
        if record.attempt_id.as_str() != hex_identity {
            return Err("MCSEALED-PRIVATE-OWNER: guardian attempt identity differs".into());
        }
        let frontend =
            ProcessIdentityV4::observe(record.frontend.pid as libc::pid_t, frontend_pidfd)?;
        if frontend != record.frontend {
            return Err("MCSEALED-PRIVATE-OWNER: frontend process identity changed".into());
        }
        // SAFETY: getpid has no pointer preconditions and names this exact
        // per-connection worker, never the shared listener service.
        let worker_pid = unsafe { libc::getpid() };
        ProcessIdentityV4::observe(worker_pid, worker_pidfd)?;
        let init = self
            .namespace_init
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-OWNER: init absent")?;
        let cgroup = self
            .cgroup
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-OWNER: cgroup absent")?;
        let guardian = PrivateGuardian::spawn(
            attempt_id,
            frontend_pidfd,
            worker_pidfd,
            init.pidfd.as_fd(),
            cgroup.clone(),
            deadline,
        )?;
        self.guardian = Some(guardian);
        let identity = self
            .guardian
            .as_ref()
            .expect("guardian was just stored")
            .identity()?;
        if cgroup
            .member_pids()?
            .contains(&(identity.pid as libc::pid_t))
        {
            return Err("MCSEALED-PRIVATE-OWNER: guardian entered candidate cgroup".into());
        }
        self.record_mut().guardian_ready(identity)
    }

    /// Consume authenticated startup and independently read back target
    /// descriptors, credentials, filter and cgroup membership while it is
    /// still gated. Any failure leaves all acquired handles in this owner.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_gated_target(
        &mut self,
        caller_namespace: NamespaceIdentity,
        provider_namespace: NamespaceIdentity,
        target_identity: &ResolvedTargetIdentity,
        abi: NativeAbi,
        filter_digest: [u8; 32],
        deadline: Instant,
    ) -> Result<PrivateObservedTarget, String> {
        if self.record_mut().record().phase != PrivateAttemptPhase::GuardianReady
            || !self.guardian.as_ref().is_some_and(PrivateGuardian::is_live)
        {
            return Err("MCSEALED-PRIVATE-OWNER: guardian is not live".into());
        }
        let init = self
            .namespace_init
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-OWNER: init absent")?;
        let startup = self
            .startup
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-OWNER: startup absent")?;
        let observed = observe_private_namespace_startup(
            startup,
            init.host_pid,
            init.pidfd.as_fd(),
            caller_namespace,
            provider_namespace,
            deadline,
        )?;
        let target_pid = observed.target_pid;
        let network = observed.network;
        self.target_pidfd = Some(observed.target_pidfd);
        self.network = Some(observed.namespace_owner);
        let cgroup = self
            .cgroup
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-OWNER: cgroup absent")?;
        let members = cgroup.member_pids()?;
        if !members.contains(&init.host_pid) || !members.contains(&target_pid) {
            return Err("MCSEALED-PRIVATE-OWNER: target or init escaped attempt cgroup".into());
        }
        let expected = self
            .expected_descriptors
            .take()
            .ok_or("MCSEALED-PRIVATE-OWNER: descriptor expectation absent")?;
        let control = self
            .control
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-OWNER: control absent")?;
        let readback = observe_private_gated_target(
            target_pid,
            self.target_pidfd
                .as_ref()
                .expect("target pidfd was just stored")
                .as_fd(),
            init.host_pid,
            expected,
            control.as_fd(),
            target_identity,
            caller_namespace,
            provider_namespace,
            self.network
                .as_ref()
                .expect("network owner was just stored"),
            abi,
            filter_digest,
            deadline,
        )?;
        let target = ProcessIdentityV4::observe(
            target_pid,
            self.target_pidfd
                .as_ref()
                .expect("target pidfd remains owned")
                .as_fd(),
        )?;
        let namespace_init = ProcessIdentityV4::observe(init.host_pid, init.pidfd.as_fd())?;
        self.record_mut().target_gated(
            namespace_init.clone(),
            target.clone(),
            readback.network_namespace.inode,
        )?;
        Ok(PrivateObservedTarget {
            native: readback,
            network,
            target,
            namespace_init,
            caller_network_namespace: caller_namespace,
        })
    }

    /// Transfer the provider pipe halves into a bounded, cancellable relay
    /// before any release is possible. Frontend endpoints must already be
    /// nonblocking pipe/socket descriptors, so this never changes a caller's
    /// shared file-description flags.
    pub fn prepare_relay(&mut self, frontend: [OwnedFd; 3]) -> Result<(), String> {
        if self.record_mut().record().phase != PrivateAttemptPhase::TargetGated
            || self.relay.is_some()
        {
            return Err("MCSEALED-PRIVATE-RELAY: target is not gated".into());
        }
        let provider = self
            .stdio
            .take()
            .ok_or("MCSEALED-PRIVATE-RELAY: provider pipes absent")?;
        self.relay = Some(PrivateRelay::prepare(provider, frontend)?);
        Ok(())
    }

    /// The caller must hold a stable installed-generation lease before the
    /// activation lease. This consumes the unforgeable native readback and
    /// gives the target exactly one release byte only after durable commit.
    pub fn commit_and_release(
        &mut self,
        observed: PrivateObservedTarget,
        authority: &crate::package::VerifiedInstalledPrivateAuthorityLease,
    ) -> Result<PrivateTcpCheckpointV2, String> {
        if self.record_mut().record().phase != PrivateAttemptPhase::TargetGated
            || !self.guardian.as_ref().is_some_and(PrivateGuardian::is_live)
            || self.relay.is_none()
        {
            return Err(
                "MCSEALED-PRIVATE-CHECKPOINT: target or guardian is not gated and live".into(),
            );
        }
        let record = self.record.as_ref().expect("owner retains record").record();
        let admission = record
            .admission
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-CHECKPOINT: admission absent")?;
        let binding = record
            .binding
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-CHECKPOINT: binding absent")?;
        if record.target.as_ref() != Some(&observed.target)
            || record.namespace_init.as_ref() != Some(&observed.namespace_init)
            || record.network_namespace_inode != Some(observed.native.network_namespace.inode)
            || self
                .network
                .as_ref()
                .map(PrivateNetworkNamespaceOwner::identity)
                != Some(observed.native.network_namespace)
            || admission.package_generation_digest != *authority.generation_digest()
            || admission.qualification_digest != *authority.qualification_digest()
            || observed.native.ready.filter_digest != *authority.filter_digest().bytes()
            || !matches!(
                (
                    admission.native_abi,
                    authority.filter_abi(),
                    observed.native.ready.native_abi
                ),
                (
                    QualifiedNativeAbiV2::X86_64LinuxGnu,
                    NativeAbi::X86_64,
                    NativeAbi::X86_64
                ) | (
                    QualifiedNativeAbiV2::Aarch64LinuxGnu,
                    NativeAbi::Aarch64,
                    NativeAbi::Aarch64
                )
            )
        {
            return Err("MCSEALED-PRIVATE-CHECKPOINT: installed/native authority differs".into());
        }
        // Lock order is package generation, then policy activation. The
        // package lease is supplied by the caller and remains live through
        // the one-byte release; the policy lease is local to this method.
        let lease = Lease::acquire()?;
        crate::admission::revalidate_linux_v2(admission, &lease)?;
        let entrypoint_digest = self
            .entrypoint_digest
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-CHECKPOINT: pinned entrypoint absent")?;
        if !admission
            .identity
            .entrypoints
            .as_slice()
            .iter()
            .any(|entrypoint| &entrypoint.sha256 == entrypoint_digest)
        {
            return Err("MCSEALED-PRIVATE-CHECKPOINT: pinned entrypoint not authorized".into());
        }
        let caller_inode = NonZeroU64::new(observed.caller_network_namespace.inode)
            .ok_or("MCSEALED-PRIVATE-CHECKPOINT: caller network inode zero")?;
        let target_inode = NonZeroU64::new(observed.native.network_namespace.inode)
            .ok_or("MCSEALED-PRIVATE-CHECKPOINT: target network inode zero")?;
        let port = observed.network.port_policy;
        let checkpoint = PrivateTcpCheckpointV2 {
            attempt_binding: binding.canonical_digest()?,
            profile: admission.profile.reference.clone(),
            identity: TargetIdentityObservationV2 {
                kind: TargetIdentityKindV2::AdministratorProfile {
                    reference: admission.identity.reference.clone(),
                },
                entrypoint_digest: entrypoint_digest.clone(),
                exact_credentials_verified: verified()?,
                no_new_privileges_verified: verified()?,
                capability_sets_empty: verified()?,
                bounding_set_empty: verified()?,
            },
            caller_envelope_reference: admission.caller_envelope_reference,
            target_network_namespace: NamespaceObservationV2::observed(
                caller_inode,
                target_inode,
                true,
                true,
            )
            .map_err(str::to_owned)?,
            topology_digest: private_topology_digest(&observed),
            filter_digest: authority.filter_digest().clone(),
            native_abi: admission.native_abi,
            port_policy: PrivatePortPolicyV1::observed(
                port.unprivileged_port_start,
                port.local_port_range.0,
                port.local_port_range.1,
                port.reserved_ports_empty,
            )
            .map_err(str::to_owned)?,
            resources: EntryResourceObservationV2::observed(5, 3, true, true, true, true, true)
                .map_err(str::to_owned)?,
            guardian_verified: verified()?,
            epoch_revalidated: verified()?,
            checkpoint_durable: verified()?,
        };
        let digest = checkpoint.canonical_digest()?;
        let attempt_id = record.attempt_id.as_str().to_owned();
        let committed = self.record_mut().commit_checkpoint(checkpoint.clone())?;
        let permit = self.record_mut().release_intent(committed)?;
        self.gated_descriptors = Some(observed.native.descriptors);
        let control = self
            .control
            .as_mut()
            .ok_or("MCSEALED-PRIVATE-RELEASE: control absent")?;
        permit.send(control, &attempt_id, &digest)?;
        drop(lease);
        Ok(checkpoint)
    }

    pub fn observe_exec(&mut self, deadline: Instant) -> Result<PrivateExecObservation, String> {
        if self.record_mut().record().phase != PrivateAttemptPhase::ReleaseIntent {
            return Err("MCSEALED-PRIVATE-EXEC: release intent absent".into());
        }
        let control = self
            .control
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-EXEC: control absent")?;
        let first = receive_control_packet(control.as_fd(), deadline)?
            .ok_or("MCSEALED-PRIVATE-EXEC: target closed before exec-armed packet")?;
        if first != PRIVATE_EXEC_ARMED_PACKET {
            return match decode_private_control_packet(&first)? {
                PrivateControlObservation::Failed { phase, detail } => {
                    Ok(PrivateExecObservation::Failed { phase, detail })
                }
                PrivateControlObservation::Ready(_) => {
                    Err("MCSEALED-PRIVATE-EXEC: unexpected ready packet after release".into())
                }
            };
        }
        match receive_control_packet(control.as_fd(), deadline)? {
            None => {
                let gated = self
                    .gated_descriptors
                    .take()
                    .ok_or("MCSEALED-PRIVATE-EXEC: gated descriptor proof absent")?;
                verify_private_exec_entry(gated, control.as_fd())
                    .map_err(|error| format!("MCSEALED-PRIVATE-EXEC: {error}"))?;
                self.record_mut().execution_observed()?;
                Ok(PrivateExecObservation::ArmedAndControlClosed)
            }
            Some(bytes) => match decode_private_control_packet(&bytes)? {
                PrivateControlObservation::Failed { phase, detail } => {
                    Ok(PrivateExecObservation::Failed { phase, detail })
                }
                PrivateControlObservation::Ready(_) => {
                    Err("MCSEALED-PRIVATE-EXEC: unexpected ready packet after arming".into())
                }
            },
        }
    }

    /// Polls every endpoint in bounded intervals and returns a distinct
    /// native stop reason. No stop reason is itself terminal cleanup proof;
    /// the caller must still invoke `retire` and preserve candidate outcome.
    pub fn monitor(
        &mut self,
        frontend_pidfd: BorrowedFd<'_>,
        deadline: Option<Instant>,
    ) -> Result<PrivateMonitorOutcome, String> {
        if self.record_mut().record().phase != PrivateAttemptPhase::ExecutionObserved {
            return Err("MCSEALED-PRIVATE-MONITOR: exec observation absent".into());
        }
        let admission = self
            .record
            .as_ref()
            .expect("owner retains record")
            .record()
            .admission
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-MONITOR: admission absent")?;
        let outcome = loop {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                break PrivateMonitorOutcome::DeadlineExceeded;
            }
            if pidfd_exited(frontend_pidfd)? {
                break PrivateMonitorOutcome::FrontendLost;
            }
            if crate::admission::revoked_linux_v2(admission)? {
                break PrivateMonitorOutcome::Revoked;
            }
            let cgroup = self
                .cgroup
                .as_ref()
                .ok_or("MCSEALED-PRIVATE-MONITOR: cgroup absent")?;
            if cgroup.memory_oom_killed()? {
                break PrivateMonitorOutcome::MemoryOom;
            }
            let target = self
                .target_pidfd
                .as_ref()
                .ok_or("MCSEALED-PRIVATE-MONITOR: target pidfd absent")?;
            let target_exited = pidfd_exited(target.as_fd())?;
            let relay = self
                .relay
                .as_mut()
                .ok_or("MCSEALED-PRIVATE-MONITOR: relay absent")?;
            if target_exited {
                relay.close_stdin_after_target_exit();
            }
            if relay.completed() && cgroup.member_pids()?.is_empty() {
                break PrivateMonitorOutcome::Completed;
            }
            relay.tick(Duration::from_millis(100))?;
        };
        self.monitor_outcome = Some(outcome);
        Ok(outcome)
    }

    /// Cleanup success is emitted only after each resource was explicitly
    /// observed empty, reaped or closed and the durable record was retired.
    pub fn retire(mut self, deadline: Instant) -> Result<PrivateRetirementObservation, String> {
        self.record_mut().retiring()?;
        let checkpoint: Option<PrivateTcpCheckpointV2> =
            self.record_mut().record().checkpoint.clone();
        let completed = (|| -> Result<Option<i32>, String> {
            if let Some(cgroup) = self.cgroup.as_ref() {
                cgroup.clone().kill_and_retire(deadline)?;
                self.cgroup.take();
            }
            if let Some(target) = self.target_pidfd.as_ref() {
                wait_pidfd(target.as_fd(), deadline)?;
            }
            self.target_pidfd.take();
            if let Some(init) = self.namespace_init.as_ref() {
                wait_exact_child(init.host_pid, init.pidfd.as_fd(), deadline)?;
            }
            self.namespace_init.take();
            self.startup.take();
            let candidate_exit_code = self
                .status
                .take()
                .map(|status| read_status_until(status, deadline))
                .transpose()?
                .flatten();
            if self.monitor_outcome == Some(PrivateMonitorOutcome::Completed)
                && candidate_exit_code.is_none()
            {
                return Err("MCSEALED-PRIVATE-OWNER: completed target status absent".into());
            }
            self.control.take();
            self.expected_descriptors.take();
            self.stdio.take();
            self.relay.take();
            self.network.take();
            if let Some(guardian) = self.guardian.take() {
                guardian.stop(deadline)?;
            }
            Ok(candidate_exit_code)
        })();
        let candidate_exit_code = match completed {
            Ok(code) => code,
            Err(error) => {
                if let Some(record) = self.record.as_mut() {
                    let _ = record.cleanup_incomplete(&error);
                }
                return Err(error);
            }
        };
        // The V2 policy snapshot is retained by this durable record. Hold the
        // activation lease across its removal and independently enumerate
        // live references before claiming that reference was released.
        let lease = Lease::acquire()?;
        let attempt_id = self.record_mut().record().attempt_id.as_str().to_owned();
        if !lease
            .versioned_live_bindings()?
            .iter()
            .any(|(identity, _)| identity == &attempt_id)
        {
            return Err("MCSEALED-PRIVATE-OWNER: frozen policy reference was not live".into());
        }
        let permit = VerifiedPrivateRetirement::observed(self.record_mut().record());
        self.record
            .take()
            .expect("private owner retains record")
            .retire_after_native_cleanup(permit)?;
        // Versioned live references are exactly the protected record entries.
        // Its removal and parent-directory sync occur while this lease excludes
        // activation/GC; no post-delete read is needed or allowed to strand an
        // unjournaled failure after the record has been removed.
        drop(lease);
        let retired = checkpoint
            .as_ref()
            .map(|checkpoint| {
                PrivateTcpRetiredV2::observed(checkpoint, true, true, true, true, true, true)
            })
            .transpose()?;
        Ok(PrivateRetirementObservation {
            attempt_id,
            retired,
            candidate_exit_code,
        })
    }
}

impl Drop for PrivateAttemptOwner {
    fn drop(&mut self) {
        // Closing provider copies cannot certify retirement. The guardian
        // remains armed until its lease closes and initiates containment.
        self.control.take();
        self.startup.take();
        self.status.take();
        self.stdio.take();
        self.relay.take();
        self.network.take();
        self.target_pidfd.take();
        self.guardian.take();
        if let Some(cgroup) = self.cgroup.take() {
            let _ = cgroup.kill_and_retire(Instant::now() + Duration::from_secs(10));
        }
        if let Some(init) = self.namespace_init.take() {
            let _ = wait_exact_child(
                init.host_pid,
                init.pidfd.as_fd(),
                Instant::now() + Duration::from_secs(2),
            );
        }
        if let Some(record) = self.record.as_mut() {
            let _ = record
                .cleanup_incomplete("private owner dropped without verified terminal retirement");
        }
    }
}

fn verified() -> Result<VerifiedTrue, String> {
    VerifiedTrue::observed(true).map_err(str::to_owned)
}

/// Hash the authenticated init's bounded network observation in a fixed
/// typed order. This digest never substitutes for the underlying topology
/// and sysctl readback, which happens before the startup packet is accepted.
fn private_topology_digest(observed: &PrivateObservedTarget) -> DiagnosticSha256 {
    let mut digest = Sha256::new();
    digest.update(b"private-network-topology-v2\0");
    digest.update(observed.caller_network_namespace.device.to_be_bytes());
    digest.update(observed.caller_network_namespace.inode.to_be_bytes());
    digest.update(observed.native.network_namespace.device.to_be_bytes());
    digest.update(observed.native.network_namespace.inode.to_be_bytes());
    digest.update(observed.network.loopback_index.to_be_bytes());
    digest.update((observed.network.address_count as u64).to_be_bytes());
    digest.update((observed.network.route_count as u64).to_be_bytes());
    digest.update(
        observed
            .network
            .port_policy
            .unprivileged_port_start
            .to_be_bytes(),
    );
    digest.update(
        observed
            .network
            .port_policy
            .local_port_range
            .0
            .to_be_bytes(),
    );
    digest.update(
        observed
            .network
            .port_policy
            .local_port_range
            .1
            .to_be_bytes(),
    );
    digest.update([u8::from(observed.network.port_policy.reserved_ports_empty)]);
    DiagnosticSha256::from_bytes(digest.finalize().into())
}

fn wait_pidfd(pidfd: BorrowedFd<'_>, deadline: Instant) -> Result<(), String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("MCSEALED-PRIVATE-OWNER: target exit deadline expired".into());
        }
        let timeout = deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows the exact owned pidfd.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if ready > 0 && pollfd.revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if ready == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        if ready <= 0 {
            return Err("MCSEALED-PRIVATE-OWNER: target pidfd poll failed".into());
        }
    }
}

fn pidfd_exited(pidfd: BorrowedFd<'_>) -> Result<bool, String> {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll synchronously borrows the exact live pidfd.
    let result = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
    if result == -1 || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-MONITOR: pidfd poll: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(result > 0 && pollfd.revents & libc::POLLIN != 0)
}

fn read_status_until(status: File, deadline: Instant) -> Result<Option<i32>, String> {
    let fd = status.as_raw_fd();
    // SAFETY: F_GETFL/F_SETFL act on the provider-only status read end. The
    // init holds a separate write-end file description.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-OWNER: status nonblocking: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut bytes = [0_u8; 4];
    let mut read_bytes = 0_usize;
    while read_bytes < bytes.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err("MCSEALED-PRIVATE-OWNER: status deadline expired".into());
        }
        let timeout = deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: poll synchronously borrows one live status descriptor.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if ready == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        if ready <= 0 || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("MCSEALED-PRIVATE-OWNER: status poll failed".into());
        }
        // SAFETY: read writes only the remaining initialized stack buffer.
        let count = unsafe {
            libc::read(
                fd,
                bytes[read_bytes..].as_mut_ptr().cast(),
                bytes.len() - read_bytes,
            )
        };
        if count > 0 {
            read_bytes += count as usize;
        } else if count == 0 {
            return if read_bytes == 0 {
                Ok(None)
            } else {
                Err("MCSEALED-PRIVATE-OWNER: partial target status".into())
            };
        } else if !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN | libc::EINTR)
        ) {
            return Err(format!(
                "MCSEALED-PRIVATE-OWNER: status read: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(Some(i32::from_be_bytes(bytes)))
}

fn receive_control_packet(
    control: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("MCSEALED-PRIVATE-EXEC: control deadline expired".into());
        }
        let timeout = deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: poll borrows the exact provider control descriptor.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if ready == -1 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!(
                "MCSEALED-PRIVATE-EXEC: poll: {}",
                std::io::Error::last_os_error()
            ));
        }
        if ready == 0 {
            continue;
        }
        if pollfd.revents & libc::POLLIN == 0 {
            if pollfd.revents & libc::POLLHUP != 0 {
                return Ok(None);
            }
            return Err("MCSEALED-PRIVATE-EXEC: control poll state differs".into());
        }
        let mut packet = [0_u8; 1024];
        // SAFETY: recv writes no more than the bounded initialized packet.
        let received = unsafe {
            libc::recv(
                control.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received == -1 {
            if matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(format!(
                "MCSEALED-PRIVATE-EXEC: recv: {}",
                std::io::Error::last_os_error()
            ));
        }
        if received == 0 {
            return Ok(None);
        }
        if received as usize > packet.len() {
            return Err("MCSEALED-PRIVATE-EXEC: truncated control packet".into());
        }
        return Ok(Some(packet[..received as usize].to_vec()));
    }
}

fn wait_exact_child(
    pid: libc::pid_t,
    pidfd: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(), String> {
    wait_pidfd(pidfd, deadline)?;
    loop {
        let mut status = 0;
        // SAFETY: pid is the exact namespace init child retained by this owner.
        let reaped = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if reaped == pid {
            return Ok(());
        }
        if reaped == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-OWNER: waitpid: {}",
                std::io::Error::last_os_error()
            ));
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-PRIVATE-OWNER: init reap deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
