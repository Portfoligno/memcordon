//! Move-only ownership for one private attempt. Every acquired native handle
//! enters this ledger before another fallible step. Only `retire` can produce
//! terminal evidence; dropping the owner starts best-effort containment.

use std::fs::File;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
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
    ReleaseKnowledge,
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
use crate::request::NamespaceIdentity;

pub struct PrivateObservedTarget {
    native: PrivateGatedReadback,
    network: PrivateNetworkSetup,
    target: ProcessIdentityV4,
    namespace_init: ProcessIdentityV4,
    caller_network_namespace: NamespaceIdentity,
    identity: ResolvedTargetIdentity,
}

impl PrivateObservedTarget {
    pub(crate) fn network_namespace_identity(&self) -> NamespaceIdentity {
        self.native.network_namespace
    }

    pub(crate) fn network_namespace_inode(&self) -> u64 {
        self.native.network_namespace.inode
    }

    pub(crate) fn target_identity(&self) -> &ProcessIdentityV4 {
        &self.target
    }
}

pub enum PrivateExecObservation {
    ExecObservedAndDetached,
    Failed { phase: u8, detail: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateMonitorOutcome {
    Completed,
    DeadlineExceeded,
    FrontendLost,
    Revoked,
    MemoryOom,
}

#[derive(Serialize)]
pub struct PrivateRetirementObservation {
    attempt_id: String,
    retired: Option<PrivateTcpRetiredV2>,
    candidate_exit_code: Option<i32>,
}

impl PrivateRetirementObservation {
    pub(super) fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    pub(super) fn native_wait_status(&self) -> Option<i32> {
        self.candidate_exit_code
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

/// Domain-specific durable journals share the same physical V4 custody
/// sequence. Implementing this trait cannot itself authorize the release
/// byte; production and probe checkpoints remain distinct sealed adapters.
pub trait PrivateNativeJournal {
    fn phase(&self) -> PrivateAttemptPhase;
    fn read_back_native(&self) -> Result<(), String>;
    fn attempt_id(&self) -> &str;
    fn frontend(&self) -> &ProcessIdentityV4;
    fn target(&self) -> Option<&ProcessIdentityV4>;
    fn namespace_init(&self) -> Option<&ProcessIdentityV4>;
    fn network_namespace_inode(&self) -> Option<u64>;
    fn possibly_released(&self) -> bool;
    fn boundary_created(&mut self) -> Result<(), String>;
    fn guardian_ready(&mut self, guardian: ProcessIdentityV4) -> Result<(), String>;
    fn target_gated(
        &mut self,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
    ) -> Result<(), String>;
    fn execution_observed(&mut self) -> Result<(), String>;
    fn retiring(&mut self) -> Result<(), String>;
    fn cleanup_incomplete(&mut self, detail: &str) -> Result<(), String>;
}

impl PrivateNativeJournal for DurablePrivateAttempt {
    fn phase(&self) -> PrivateAttemptPhase {
        self.record().phase
    }

    fn read_back_native(&self) -> Result<(), String> {
        self.read_back().map(|_| ())
    }

    fn attempt_id(&self) -> &str {
        self.record().attempt_id.as_str()
    }

    fn frontend(&self) -> &ProcessIdentityV4 {
        &self.record().frontend
    }

    fn target(&self) -> Option<&ProcessIdentityV4> {
        self.record().target.as_ref()
    }

    fn namespace_init(&self) -> Option<&ProcessIdentityV4> {
        self.record().namespace_init.as_ref()
    }

    fn network_namespace_inode(&self) -> Option<u64> {
        self.record().network_namespace_inode
    }

    fn possibly_released(&self) -> bool {
        self.record().release_knowledge != ReleaseKnowledge::NotReleased
    }

    fn boundary_created(&mut self) -> Result<(), String> {
        DurablePrivateAttempt::boundary_created(self)
    }

    fn guardian_ready(&mut self, guardian: ProcessIdentityV4) -> Result<(), String> {
        DurablePrivateAttempt::guardian_ready(self, guardian)
    }

    fn target_gated(
        &mut self,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
    ) -> Result<(), String> {
        DurablePrivateAttempt::target_gated(self, namespace_init, target, network_namespace_inode)
    }

    fn execution_observed(&mut self) -> Result<(), String> {
        DurablePrivateAttempt::execution_observed(self)
    }

    fn retiring(&mut self) -> Result<(), String> {
        DurablePrivateAttempt::retiring(self)
    }

    fn cleanup_incomplete(&mut self, detail: &str) -> Result<(), String> {
        DurablePrivateAttempt::cleanup_incomplete(self, detail)
    }
}

pub struct PrivateAttemptOwner<J: PrivateNativeJournal = DurablePrivateAttempt> {
    record: Option<J>,
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
    observed_native_wait_status: Option<i32>,
    expected_descriptors: Option<ExpectedGatedDescriptorInventory>,
    entrypoint_digest: Option<DiagnosticSha256>,
    entrypoint_device_inode: Option<(u64, u64)>,
    gated_descriptors: Option<GatedDescriptorProof>,
    monitor_outcome: Option<PrivateMonitorOutcome>,
    cgroup_retirement_raw: Option<super::cgroup::CgroupRetirementRawV1>,
}

impl<J: PrivateNativeJournal> PrivateAttemptOwner<J> {
    pub fn new(record: J) -> Result<Self, String> {
        if record.phase() != PrivateAttemptPhase::Allocated {
            return Err("MCSEALED-PRIVATE-OWNER: allocated native journal required".into());
        }
        record.read_back_native()?;
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
            observed_native_wait_status: None,
            expected_descriptors: None,
            entrypoint_digest: None,
            entrypoint_device_inode: None,
            gated_descriptors: None,
            monitor_outcome: None,
            cgroup_retirement_raw: None,
        })
    }

    fn record_mut(&mut self) -> &mut J {
        self.record
            .as_mut()
            .expect("private owner retains durable record")
    }

    pub fn possibly_released(&self) -> bool {
        self.record
            .as_ref()
            .is_some_and(PrivateNativeJournal::possibly_released)
    }

    pub(crate) fn require_live_target_identity(
        &self,
        target: &ProcessIdentityV4,
    ) -> Result<(), String> {
        let pidfd = self
            .target_pidfd
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-RELEASE: retained target pidfd absent")?;
        if ProcessIdentityV4::observe(target.pid as libc::pid_t, pidfd.as_fd())? != *target {
            return Err("MCSEALED-PRIVATE-RELEASE: retained target identity changed".into());
        }
        Ok(())
    }

    pub(crate) fn tick_relay_for_unix_observer(&mut self) -> Result<(), String> {
        self.relay
            .as_mut()
            .ok_or("MCSEALED-PRIVATE-RELEASE: Unix observer relay absent")?
            .tick(Duration::from_millis(10))
    }

    pub fn create_boundary(
        &mut self,
        memory_max: Option<u64>,
        swap_limit: crate::request::SwapLimit,
    ) -> Result<(), String> {
        if self.cgroup.is_some() {
            return Err("MCSEALED-PRIVATE-OWNER: boundary already owned".into());
        }
        let identity = self.record_mut().attempt_id().to_owned();
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
        self.entrypoint_device_inode =
            Some((prelaunch.entrypoint_device, prelaunch.entrypoint_inode));
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
        if self.record_mut().phase() != PrivateAttemptPhase::BoundaryCreated
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
            || self.record_mut().phase() != PrivateAttemptPhase::BoundaryCreated
        {
            return Err("MCSEALED-PRIVATE-OWNER: guardian phase differs".into());
        }
        let hex_identity = attempt_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let record = self.record.as_ref().expect("owner retains record");
        if record.attempt_id() != hex_identity {
            return Err("MCSEALED-PRIVATE-OWNER: guardian attempt identity differs".into());
        }
        let frontend =
            ProcessIdentityV4::observe(record.frontend().pid as libc::pid_t, frontend_pidfd)?;
        if frontend != *record.frontend() {
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
        if self.record_mut().phase() != PrivateAttemptPhase::GuardianReady
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
        self.entrypoint_device_inode
            .ok_or("MCSEALED-PRIVATE-OWNER: pinned entrypoint object identity absent")?;
        self.entrypoint_digest
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-OWNER: pinned entrypoint digest absent")?;
        Ok(PrivateObservedTarget {
            native: readback,
            network,
            target,
            namespace_init,
            caller_network_namespace: caller_namespace,
            identity: target_identity.clone(),
        })
    }

    /// Transfer the provider pipe halves into a bounded, cancellable relay
    /// before any release is possible. Frontend endpoints must already be
    /// nonblocking pipe/socket descriptors, so this never changes a caller's
    /// shared file-description flags.
    pub fn prepare_relay(&mut self, frontend: [OwnedFd; 3]) -> Result<(), String> {
        if self.record_mut().phase() != PrivateAttemptPhase::TargetGated || self.relay.is_some() {
            return Err("MCSEALED-PRIVATE-RELAY: target is not gated".into());
        }
        let provider = self
            .stdio
            .take()
            .ok_or("MCSEALED-PRIVATE-RELAY: provider pipes absent")?;
        self.relay = Some(PrivateRelay::prepare(provider, frontend)?);
        Ok(())
    }
}

fn join_loss_cleanup<T, U>(
    observation: Result<T, String>,
    cleanup: Result<U, String>,
) -> Result<(T, U), String> {
    match (observation, cleanup) {
        (Ok(observation), Ok(cleanup)) => Ok((observation, cleanup)),
        (Err(observation), Ok(_)) => Err(observation),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(observation), Err(cleanup)) => {
            Err(format!("{observation}; native cleanup: {cleanup}"))
        }
    }
}

impl<J: PrivateNativeJournal> PrivateAttemptOwner<J> {
    /// Checks only observed native resource custody. A separate sealed
    /// authorization adapter must still validate the production grant or an
    /// exact protected probe case before any durable checkpoint or release.
    fn validate_gated_native_resources(
        &self,
        observed: &PrivateObservedTarget,
    ) -> Result<(), String> {
        if self.record.as_ref().expect("owner retains record").phase()
            != PrivateAttemptPhase::TargetGated
            || !self.guardian.as_ref().is_some_and(PrivateGuardian::is_live)
            || self.relay.is_none()
        {
            return Err(
                "MCSEALED-PRIVATE-CHECKPOINT: target or guardian is not gated and live".into(),
            );
        }
        let record = self.record.as_ref().expect("owner retains record");
        if record.target() != Some(&observed.target)
            || record.namespace_init() != Some(&observed.namespace_init)
            || record.network_namespace_inode() != Some(observed.native.network_namespace.inode)
            || self
                .network
                .as_ref()
                .map(PrivateNetworkNamespaceOwner::identity)
                != Some(observed.native.network_namespace)
        {
            return Err("MCSEALED-PRIVATE-CHECKPOINT: observed native custody differs".into());
        }
        Ok(())
    }

    pub fn observe_exec(&mut self, deadline: Instant) -> Result<PrivateExecObservation, String> {
        if self.record_mut().phase() != PrivateAttemptPhase::ReleaseIntent {
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
                // EOF closes the target setup channel but is not executable
                // transition evidence. The task-affine owning init separately
                // reports its kernel exec-event readback and actual detach.
                let init = self
                    .namespace_init
                    .as_ref()
                    .ok_or("MCSEALED-PRIVATE-EXEC: init owner absent")?;
                let startup = self
                    .startup
                    .as_ref()
                    .ok_or("MCSEALED-PRIVATE-EXEC: init channel absent")?;
                let event = startup.receive(init.host_pid, deadline)?;
                match event.observation {
                    super::private_namespace_init::PrivateNamespaceStartupObservation::ExecObservedAndDetached { target_host_pid }
                        if self.record.as_ref().and_then(PrivateNativeJournal::target).is_some_and(|target| target.pid == target_host_pid as u32) => {}
                    super::private_namespace_init::PrivateNamespaceStartupObservation::Failed { phase, detail } => {
                        return Ok(PrivateExecObservation::Failed { phase: match phase {
                            super::private_namespace_init::PrivateNamespaceStartupPhase::NamespaceSetup => 1,
                            super::private_namespace_init::PrivateNamespaceStartupPhase::TargetFork => 2,
                            super::private_namespace_init::PrivateNamespaceStartupPhase::ExecObservation => 3,
                        }, detail });
                    }
                    _ => return Err("MCSEALED-PRIVATE-EXEC: init exec-event association differs".into()),
                }
                self.record_mut().execution_observed()?;
                Ok(PrivateExecObservation::ExecObservedAndDetached)
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
}

impl<J: PrivateNativeJournal> PrivateAttemptOwner<J> {
    /// Monitor actual owned resources and the live local grant.
    fn monitor_native(
        &mut self,
        frontend_pidfd: BorrowedFd<'_>,
        deadline: Option<Instant>,
        mut revoked: impl FnMut() -> Result<bool, String>,
        broker_stream: &std::os::unix::net::UnixStream,
    ) -> Result<PrivateMonitorOutcome, String> {
        let outcome = loop {
            if super::private_runtime::cancellation_requested(broker_stream)? {
                break PrivateMonitorOutcome::FrontendLost;
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                break PrivateMonitorOutcome::DeadlineExceeded;
            }
            if pidfd_exited(frontend_pidfd)? {
                break PrivateMonitorOutcome::FrontendLost;
            }
            let init_exited = pidfd_exited(
                self.namespace_init
                    .as_ref()
                    .ok_or("MCSEALED-PRIVATE-MONITOR: retained namespace init absent")?
                    .pidfd
                    .as_fd(),
            )?;
            if init_exited && self.status.is_some() {
                let observation_limit = Instant::now() + Duration::from_secs(1);
                let observation_deadline = deadline.map_or(observation_limit, |original| {
                    original.min(observation_limit)
                });
                self.observed_native_wait_status = read_status_until(
                    self.status.take().expect("status is held"),
                    observation_deadline,
                )?;
                if self.observed_native_wait_status.is_none() {
                    return Err("MCSEALED-PRIVATE-MONITOR: retained namespace init exited without actual target wait status".into());
                }
            }
            if self
                .guardian
                .as_ref()
                .is_some_and(|guardian| !guardian.is_live())
            {
                return Err(
                    "MCSEALED-PRIVATE-MONITOR: pinned guardian exited while target active".into(),
                );
            }
            if revoked()? {
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
}

impl PrivateAttemptOwner<DurablePrivateAttempt> {
    /// Persist actual gated observations before acquiring the final policy
    /// lock. Sync/readback never runs inside activation-versus-release exclusion.
    pub(super) fn prepare_operational_release(
        &mut self,
        observed: &PrivateObservedTarget,
    ) -> Result<(), String> {
        self.validate_gated_native_resources(observed)?;
        let binding = self
            .record_mut()
            .record()
            .binding
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-COMMIT: descriptive attempt binding absent")?
            .canonical_digest()?;
        let facts = super::private_attempt::OperationalGatedFacts {
            format: "memcordon.private-gated-observation".into(),
            revision: 1,
            attempt_binding: binding,
            target: observed.target.clone(),
            init: observed.namespace_init.clone(),
            network_namespace_inode: observed.native.network_namespace.inode,
            entrypoint_sha256: self
                .entrypoint_digest
                .clone()
                .ok_or("MCSEALED-PRIVATE-COMMIT: held executable digest absent")?,
            filter_sha256: DiagnosticSha256::from_bytes(observed.native.ready.filter_digest),
            topology_sha256: private_topology_digest(observed),
            gated_descriptor_count: 5,
        };
        self.record_mut().commit_gated_facts(facts)?;
        // Record uncertainty before any instruction can transfer. A later
        // epoch rejection remains conservative and still retires the target.
        self.record_mut().release_intent()
    }

    pub(super) fn release_operational(
        &mut self,
        admission: &mut super::operational_admission::OperationalAdmission,
        observed: &PrivateObservedTarget,
        release_observed: &mut Option<Instant>,
        release_monotonic_millis: &mut Option<u64>,
    ) -> Result<(), String> {
        if self.record_mut().phase() != PrivateAttemptPhase::ReleaseIntent {
            return Err("MCSEALED-PRIVATE-RELEASE: durable release intent absent".into());
        }
        self.require_live_target_identity(&observed.target)?;
        if !self.guardian.as_ref().is_some_and(PrivateGuardian::is_live) {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian no longer live".into());
        }
        let control = self
            .control
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-RELEASE: setup channel absent")?;
        admission.release(|| {
            let sampled_monotonic_millis = super::clock::monotonic_millis()?;
            let sampled_release = Instant::now();
            let byte = [1_u8];
            // SAFETY: one bounded nonblocking seqpacket send, no borrowed
            // pointer escapes. All preparation/durable I/O precedes this lock.
            let sent = unsafe {
                libc::send(
                    control.as_raw_fd(),
                    byte.as_ptr().cast(),
                    byte.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent != byte.len() as isize {
                return Err(format!(
                    "MCSEALED-PRIVATE-RELEASE: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // The one-shot admission is consumed even if send fails, but a
            // successful release observation requires the actual byte transfer.
            *release_monotonic_millis = Some(sampled_monotonic_millis);
            *release_observed = Some(sampled_release);
            Ok(())
        })
    }

    pub(super) fn monitor_operational(
        &mut self,
        admission: &mut super::operational_admission::OperationalAdmission,
        deadline: Option<Instant>,
        broker_stream: &std::os::unix::net::UnixStream,
    ) -> Result<PrivateMonitorOutcome, String> {
        let frontend = admission
            .frontend_pidfd
            .try_clone()
            .map_err(|error| error.to_string())?;
        self.monitor_native(
            frontend.as_fd(),
            deadline,
            || admission.revoked(),
            broker_stream,
        )
    }

    /// Cleanup success is emitted only after each resource was explicitly
    /// observed empty, reaped or closed and the durable record was retired.
    pub fn retire(mut self, deadline: Instant) -> Result<PrivateRetirementObservation, String> {
        self.record_mut().retiring()?;
        let checkpoint: Option<PrivateTcpCheckpointV2> =
            self.record_mut().record().checkpoint.clone();
        let completed = self.settle_native_resources(deadline);
        let candidate_exit_code = match completed {
            Ok(code) => code,
            Err(error) => {
                if let Some(record) = self.record.as_mut() {
                    let _ = record.cleanup_incomplete(&error);
                }
                return Err(error);
            }
        };
        let attempt_id = self.record_mut().record().attempt_id.as_str().to_owned();
        let permit = VerifiedPrivateRetirement::observed(self.record_mut().record());
        self.record
            .take()
            .expect("private owner retains record")
            .retire_after_native_cleanup(permit)?;
        let retired = checkpoint
            .as_ref()
            .map(|checkpoint| {
                PrivateTcpRetiredV2::observed(checkpoint, true, true, true, true, true, true)
            })
            .transpose()?;
        let retirement = PrivateRetirementObservation {
            attempt_id,
            retired,
            candidate_exit_code,
        };
        Ok(retirement)
    }
}

impl<J: PrivateNativeJournal> PrivateAttemptOwner<J> {
    /// This consumes only observed native resources. It does not remove a
    /// durable record, release a policy reference, or claim terminal success.
    fn settle_native_resources(&mut self, deadline: Instant) -> Result<Option<i32>, String> {
        if let Some(cgroup) = self.cgroup.as_ref() {
            let observed = cgroup.clone().kill_and_retire_observed(deadline)?;
            self.cgroup_retirement_raw = Some(observed);
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
        let candidate_exit_code = self.observed_native_wait_status.or(self
            .status
            .take()
            .map(|status| read_status_until(status, deadline))
            .transpose()?
            .flatten());
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
            if self.monitor_outcome == Some(PrivateMonitorOutcome::FrontendLost) {
                guardian.finish_after_loss(deadline)?;
            } else {
                guardian.stop(deadline)?;
            }
        }
        Ok(candidate_exit_code)
    }
}

impl<J: PrivateNativeJournal> Drop for PrivateAttemptOwner<J> {
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
    let status = i32::from_be_bytes(bytes);
    if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
        return Err(
            "MCSEALED-PRIVATE-OWNER: target status is not a native terminal wait status".into(),
        );
    }
    Ok(Some(status))
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
