//! Move-only ownership for one private attempt. Every acquired native handle
//! enters this ledger before another fallible step. Only `retire` can produce
//! terminal evidence; dropping the owner starts best-effort containment.

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_evidence_v2::{
    PrivateTcpCheckpointV2, PrivateTcpRetiredV2, VerifiedTrue,
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
use super::private_pid_identity::PrivateNamespaceTargetIdentity;
use super::private_relay::PrivateRelay;
use super::private_target::{
    PRIVATE_EXEC_ARMED_PACKET, PrivateControlObservation, PrivateGatedReadback, PrivateGatedTarget,
    PrivateNetworkNamespaceOwner, decode_private_control_packet, observe_private_gated_target,
};
use super::private_wait_status::{read_status_until, require_target_status};
use crate::request::NamespaceIdentity;

pub struct PrivateObservedTarget {
    native: PrivateGatedReadback,
    network: PrivateNetworkSetup,
    target: ProcessIdentityV4,
    namespace_init: ProcessIdentityV4,
    caller_network_namespace: NamespaceIdentity,
    identity: ResolvedTargetIdentity,
}

struct MixedGatedFacts {
    caller: ProcessIdentityV4,
    target: ProcessIdentityV4,
    init: ProcessIdentityV4,
    guardian: ProcessIdentityV4,
    caller_namespaces: [memcordon_core::result_v2::NativeNamespaceV2; 5],
    target_namespaces: [memcordon_core::result_v2::NativeNamespaceV2; 5],
    root: (u64, u64),
    identity: ResolvedTargetIdentity,
    ready: super::private_target::PrivateReadyObservation,
    init_nondumpable: bool,
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
    ControlledCancellation,
    FrontendLost,
    Revoked,
    MemoryOom,
}

#[cfg(test)]
impl PrivateAttemptOwner<super::private_attempt::DurablePrivateAttempt> {
    pub(crate) fn component_native_journal_bytes(&self) -> Result<Vec<u8>, String> {
        self.record
            .as_ref()
            .ok_or("component journal owner absent")?
            .component_native_bytes()
    }
    #[cfg(test)]
    pub(crate) fn component_account_ownership(
        &self,
        admission: &super::mixed_admission::MixedOperationalAdmission,
    ) -> Result<serde_json::Value, String> {
        let (bytes, journal) = self
            .record
            .as_ref()
            .ok_or("component journal owner absent")?
            .component_native_observation()?;
        let account = admission.component_account_ownership()?;
        Ok(
            serde_json::json!({"journal":journal,"journal_sha256":DiagnosticSha256::from_bytes(Sha256::digest(&bytes).into()),"account":account}),
        )
    }
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
    target_pid_identity: Option<PrivateNamespaceTargetIdentity>,
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
    mixed_root: Option<super::private_root::MountedPrivateRoot>,
    mixed_staging: Option<super::private_root::NativeRootStaging>,
    mixed_root_retired: Option<super::private_root::PrivateRootRetirement>,
    mixed_native_retired: Option<PrivateRetirementObservation>,
    mixed_export_path: Option<std::path::PathBuf>,
    mixed_export_destination: Option<super::private_root::NativeExportDirectory>,
    mixed_stdout_sha256: Option<DiagnosticSha256>,
    mixed_facts: Option<MixedGatedFacts>,
    native_exec_observed: bool,
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
            target_pid_identity: None,
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
            mixed_root: None,
            mixed_staging: None,
            mixed_root_retired: None,
            mixed_native_retired: None,
            mixed_export_path: None,
            mixed_export_destination: None,
            mixed_stdout_sha256: None,
            mixed_facts: None,
            native_exec_observed: false,
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
        lifetime: crate::request::Lifetime,
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
                    lifetime,
                )
            },
        )?;
        self.attach_init(init)
    }

    /// The mixed profile clones from the protected provider context; it never
    /// joins caller mount/root/cwd authority. Original staging and received root
    /// capabilities enter the ledger before any subsequent fallible operation.
    #[expect(
        clippy::too_many_arguments,
        reason = "The protected clone binds original root channel, independent namespaces, lifetime and finite deadline"
    )]
    pub(super) fn spawn_mixed_namespace(
        &mut self,
        prelaunch: PrivateGatedPrelaunch,
        preparation: super::private_namespace_init::MixedNamespacePreparation,
        provider_root_channel: std::os::unix::net::UnixStream,
        caller_namespace: NamespaceIdentity,
        provider_namespace: NamespaceIdentity,
        lifetime: crate::request::Lifetime,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.record_mut().phase() != PrivateAttemptPhase::BoundaryCreated
            || self.namespace_init.is_some()
            || self.mixed_staging.is_none()
        {
            return Err("mixed clone ownership phase differs".into());
        }
        let layout = preparation.layout.clone();
        let entry = preparation.entry.clone();
        let root_identity = preparation.identity.clone();
        let nonce = preparation.nonce;
        let attempt = preparation.attempt;
        let (provider_startup, init_startup) = private_namespace_startup_channel()?;
        self.hold_startup(provider_startup)?;
        let mut fds = [-1_i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        self.status = Some(unsafe { File::from_raw_fd(fds[0]) });
        let status_write = unsafe { File::from_raw_fd(fds[1]) };
        let target = self.take_target_for_clone(prelaunch)?;
        let startup_fd = self
            .startup
            .as_ref()
            .expect("stored mixed startup")
            .as_fd()
            .as_raw_fd();
        let control_fd = self
            .control
            .as_ref()
            .expect("stored mixed control")
            .as_raw_fd();
        let status_read_fd = self
            .status
            .as_ref()
            .expect("stored mixed status")
            .as_raw_fd();
        let provider_pipe_fds = self
            .stdio
            .as_ref()
            .expect("stored mixed stdio")
            .descriptor_numbers();
        let provider_root_fd = provider_root_channel.as_raw_fd();
        let cgroup = self.cgroup_file()?;
        let init = super::namespace::clone_into_cgroup_with_mode(
            &cgroup,
            NamespaceMode::PrivateTcp4,
            move || {
                unsafe {
                    libc::close(status_read_fd);
                    libc::close(provider_root_fd);
                    for fd in provider_pipe_fds {
                        libc::close(fd);
                    }
                }
                let startup = unsafe { BorrowedFd::borrow_raw(startup_fd) };
                let control = unsafe { BorrowedFd::borrow_raw(control_fd) };
                super::private_namespace_init::run_mixed_namespace_init(
                    target,
                    init_startup,
                    startup,
                    control,
                    status_write,
                    preparation,
                    caller_namespace,
                    provider_namespace,
                    lifetime,
                )
            },
        )?;
        self.attach_init(init)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("mixed root startup deadline elapsed".into());
        }
        provider_root_channel
            .set_read_timeout(Some(remaining))
            .map_err(|error| error.to_string())?;
        let init = self.namespace_init.as_ref().expect("stored mixed init");
        let identity = ProcessIdentityV4::observe(init.host_pid, init.pidfd.as_fd())?;
        let (root, executable) = super::private_root::MountedPrivateRoot::receive_from_init(
            &provider_root_channel,
            &identity,
            init.pidfd.as_fd(),
            nonce,
            attempt,
            layout,
            root_identity,
            &entry,
        )?;
        self.mixed_root = Some(root);
        self.expected_descriptors
            .as_mut()
            .ok_or("mixed descriptor expectations absent")?
            .rebind_private_root_executable(executable.as_fd())
            .map_err(|error| error.to_string())?;
        let identity = executable.identity();
        self.entrypoint_digest = Some(DiagnosticSha256::from_bytes(identity.sha256));
        self.entrypoint_device_inode = Some((identity.device, identity.inode));
        drop(executable);
        drop(provider_root_channel);
        Ok(())
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
        let target_pid = observed.target_identity.host_pid();
        self.target_pid_identity = Some(observed.target_identity);
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
        if self.mixed_root.is_some() {
            self.relay
                .as_mut()
                .expect("stored relay")
                .hash_mixed_stdout();
        }
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
                    super::private_namespace_init::PrivateNamespaceStartupObservation::ExecObservedAndDetached { target_namespace_pid } => {
                        let identity = self.target_pid_identity
                            .ok_or("MCSEALED-PRIVATE-EXEC: pinned target PID mapping absent")?;
                        let target = self.record.as_ref().and_then(PrivateNativeJournal::target)
                            .ok_or("MCSEALED-PRIVATE-EXEC: journal target identity absent")?;
                        identity.require_exec_pid(target.pid, target_namespace_pid)?;
                    }
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
                self.native_exec_observed = true;
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
            if let Some(cancellation) =
                super::private_cancellation::observe_cancellation(broker_stream, || {
                    pidfd_exited(frontend_pidfd)
                })?
            {
                break match cancellation {
                    super::private_cancellation::PrivateCancellation::Controlled => {
                        PrivateMonitorOutcome::ControlledCancellation
                    }
                    super::private_cancellation::PrivateCancellation::FrontendLost => {
                        PrivateMonitorOutcome::FrontendLost
                    }
                };
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
                require_target_status(
                    &mut self.observed_native_wait_status,
                    &mut self.status,
                    deadline,
                )?;
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
                // Init may have exited since the first pidfd observation. Empty
                // resources alone cannot supply its actual target wait status.
                require_target_status(
                    &mut self.observed_native_wait_status,
                    &mut self.status,
                    deadline,
                )?;
                break PrivateMonitorOutcome::Completed;
            }
            relay.tick(Duration::from_millis(100))?;
        };
        self.monitor_outcome = Some(outcome);
        Ok(outcome)
    }
}

impl PrivateAttemptOwner<DurablePrivateAttempt> {
    pub(super) fn retire_mixed_unreleased_without_root(
        &mut self,
        admission: &mut super::mixed_admission::MixedOperationalAdmission,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.mixed_root.is_some() || self.possibly_released() || self.native_exec_observed {
            return Err(
                "unmaterialized cleanup cannot retire a rooted or possibly released attempt".into(),
            );
        }
        self.record_mut().begin_mixed_retirement()?;
        if self.mixed_native_retired.is_none() {
            let candidate_exit_code = self.settle_native_resources(deadline)?;
            self.mixed_native_retired = Some(PrivateRetirementObservation {
                attempt_id: self.record_mut().record().attempt_id.as_str().to_owned(),
                retired: None,
                candidate_exit_code,
            });
        }
        if let Some(staging) = self.mixed_staging.as_mut() {
            staging.retire_path()?;
            self.mixed_staging.take();
        } else if self
            .record_mut()
            .record()
            .mixed_root_staging_intent
            .is_some()
            && self.mixed_root_retired.is_none()
        {
            return Err("staging creation/readback remains unresolved under durable intent".into());
        }
        if self.mixed_root_retired.is_none() {
            self.mixed_root_retired = Some(
                super::private_root::PrivateRootRetirement::unmaterialized_after_native_retirement(
                    self.mixed_native_retired
                        .as_ref()
                        .expect("observed native retirement"),
                    admission.contract.root_layout.clone(),
                    admission.contract.execution_identity.clone(),
                ),
            );
        }
        admission.retire_after_native_root_and_account_quiescence(
            self.mixed_native_retired
                .as_ref()
                .expect("observed native retirement"),
            self.mixed_root_retired
                .as_ref()
                .expect("observed unmaterialized retirement"),
        )?;
        let permit = VerifiedPrivateRetirement::observed(self.record_mut().record());
        self.record_mut()
            .retire_mixed_after_native_cleanup(permit)?;
        self.record.take();
        Ok(())
    }
    pub(super) fn has_mixed_root(&self) -> bool {
        self.mixed_root.is_some()
    }
    pub(super) fn prepare_mixed_launch(
        &mut self,
        admission: &mut super::mixed_admission::MixedOperationalAdmission,
        attempt: [u8; 16],
    ) -> Result<super::mixed_admission::PreparedMixedLaunch, String> {
        use std::os::unix::fs::MetadataExt;
        let cgroup = self
            .cgroup
            .as_ref()
            .ok_or("mixed cgroup owner absent")?
            .open()?;
        let metadata = cgroup.metadata().map_err(|error| error.to_string())?;
        self.record_mut().record_mixed_directory(
            false,
            super::private_attempt::MixedDirectoryIdentityV2 {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        )?;
        let identity = attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = super::private_root::NativeRootStaging::intended_path(&identity)?;
        self.record_mut().record_mixed_root_staging_intent(&path)?;
        if self.mixed_staging.is_some() {
            return Err("mixed staging allocation is single-use".into());
        }
        self.mixed_staging = Some(super::private_root::NativeRootStaging::create(&identity)?);
        let native_staging = self
            .mixed_staging
            .as_ref()
            .expect("owned mixed staging")
            .native_identity()?;
        self.record_mut()
            .record_mixed_directory(true, native_staging)?;
        let child = self
            .mixed_staging
            .as_ref()
            .expect("owned mixed staging")
            .for_namespace_child()?;
        admission.prepare_native_root_launch(attempt, child)
    }
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

    pub(super) fn release_mixed(
        &mut self,
        admission: &mut super::mixed_admission::MixedOperationalAdmission,
        observed: &PrivateObservedTarget,
        release_observed: &mut Option<Instant>,
        release_monotonic_millis: &mut Option<u64>,
    ) -> Result<(), super::mixed_admission::MixedReleaseFailure> {
        if self.record_mut().phase() != PrivateAttemptPhase::ReleaseIntent
            || self.mixed_root.is_none()
        {
            return Err("mixed release lacks durable intent/root custody".into());
        }
        self.require_live_target_identity(&observed.target)?;
        if !self.guardian.as_ref().is_some_and(PrivateGuardian::is_live) {
            return Err("mixed guardian is not live before release".into());
        }
        let control = self
            .control
            .as_ref()
            .ok_or("mixed release setup channel absent")?;
        admission.release_with_native_gate(observed.target.pid, || {
            let monotonic = super::clock::monotonic_millis()?;
            let sampled = Instant::now();
            let authorization = [1_u8];
            let sent = unsafe {
                libc::send(
                    control.as_raw_fd(),
                    authorization.as_ptr().cast(),
                    authorization.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent != authorization.len() as isize {
                return Err(format!(
                    "mixed native authorization send: {}",
                    std::io::Error::last_os_error()
                ));
            }
            *release_observed = Some(sampled);
            *release_monotonic_millis = Some(monotonic);
            Ok(())
        })
    }

    pub(super) fn capture_mixed_gated_facts(
        &mut self,
        admission: &super::mixed_admission::MixedOperationalAdmission,
        observed: &PrivateObservedTarget,
    ) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        fn namespaces(
            pid: u32,
        ) -> Result<[memcordon_core::result_v2::NativeNamespaceV2; 5], String> {
            let mut values = Vec::new();
            for name in ["user", "mnt", "pid", "net", "ipc"] {
                let metadata = std::fs::metadata(
                    std::path::Path::new("/proc")
                        .join(pid.to_string())
                        .join("ns")
                        .join(name),
                )
                .map_err(|error| error.to_string())?;
                values.push(memcordon_core::result_v2::NativeNamespaceV2 {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                });
            }
            values
                .try_into()
                .map_err(|_| "native namespace tuple length differs".into())
        }
        self.require_live_target_identity(&observed.target)?;
        let caller = ProcessIdentityV4::observe(
            admission.caller.envelope.pid,
            admission.frontend_pidfd.as_fd(),
        )?;
        if caller != admission.frontend {
            return Err("mixed caller birth changed during native observation".into());
        }
        let init = self
            .namespace_init
            .as_ref()
            .ok_or("mixed init owner absent")?;
        let init_identity = ProcessIdentityV4::observe(init.host_pid, init.pidfd.as_fd())?;
        if init_identity != observed.namespace_init {
            return Err("mixed init birth changed".into());
        }
        let guardian = self
            .guardian
            .as_ref()
            .ok_or("mixed guardian owner absent")?
            .identity()?;
        let caller_namespaces = namespaces(caller.pid)?;
        let target_namespaces = namespaces(observed.target.pid)?;
        let init_namespaces = namespaces(init_identity.pid)?;
        if target_namespaces != init_namespaces
            || target_namespaces[0] != caller_namespaces[0]
            || (1..5).any(|index| target_namespaces[index] == caller_namespaces[index])
        {
            return Err("mixed target/init/caller namespace separation differs".into());
        }
        let root = self.mixed_root.as_ref().ok_or("mixed held root absent")?;
        let metadata = std::fs::File::from(
            root.as_fd()
                .try_clone_to_owned()
                .map_err(|error| error.to_string())?,
        )
        .metadata()
        .map_err(|error| error.to_string())?;
        if !root.init_nondumpable() {
            return Err("mixed namespace init dumpability was not observed".into());
        }
        self.require_live_target_identity(&observed.target)?;
        if ProcessIdentityV4::observe(
            admission.caller.envelope.pid,
            admission.frontend_pidfd.as_fd(),
        )? != caller
            || ProcessIdentityV4::observe(init.host_pid, init.pidfd.as_fd())? != init_identity
        {
            return Err("mixed native process identity changed during observation".into());
        }
        self.mixed_facts = Some(MixedGatedFacts {
            caller,
            target: observed.target.clone(),
            init: init_identity,
            guardian,
            caller_namespaces,
            target_namespaces,
            root: (metadata.dev(), metadata.ino()),
            identity: observed.identity.clone(),
            ready: observed.native.ready,
            init_nondumpable: true,
        });
        Ok(())
    }

    pub(super) fn mixed_prepared_observation(
        &self,
        admission: &super::mixed_admission::MixedOperationalAdmission,
        provider: memcordon_core::PublicProviderBindingV1,
    ) -> Result<memcordon_core::mixed_observation::MixedPreparedObservationV2, String> {
        use memcordon_core::result_v2::NativeProcessV2;
        let facts = self
            .mixed_facts
            .as_ref()
            .ok_or("mixed gated native facts absent")?;
        let process = |identity: &ProcessIdentityV4| NativeProcessV2 {
            pid: identity.pid,
            birth: identity.start_time,
        };
        let value = memcordon_core::mixed_observation::MixedPreparedObservationV2 {
            format: "memcordon.mixed-prepared-observation".into(),
            revision: 2,
            provider,
            admission: admission.metadata().clone(),
            caller: process(&facts.caller),
            target: process(&facts.target),
            namespace_init: process(&facts.init),
            guardian: process(&facts.guardian),
            user_namespace: facts.target_namespaces[0].clone(),
            mount_namespace: facts.target_namespaces[1].clone(),
            pid_namespace: facts.target_namespaces[2].clone(),
            network_namespace: facts.target_namespaces[3].clone(),
            ipc_namespace: facts.target_namespaces[4].clone(),
            root_device: facts.root.0,
            root_inode: facts.root.1,
            authorizes_launch: false,
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn mixed_execution_after_retirement(
        &self,
        admission: &super::mixed_admission::MixedOperationalAdmission,
        retired: &MixedNativeRetirement,
        origin: memcordon_core::result_v2::MixedOutcomeOriginV2,
        authorization_monotonic_millis: u64,
    ) -> Result<memcordon_core::result_v2::MixedNativeExecutionV2, String> {
        use memcordon_core::result_v2::*;
        if !self.native_exec_observed
            || self.record.is_some()
            || self.mixed_root_retired.is_none()
            || self.guardian.is_some()
        {
            return Err("mixed native execution/retirement proof is incomplete".into());
        }
        let facts = self
            .mixed_facts
            .as_ref()
            .ok_or("mixed gated native facts absent")?;
        let status = retired
            .native
            .native_wait_status()
            .ok_or("mixed native target wait status absent")?;
        let observed = VerifiedTrue::observed(true).map_err(str::to_owned)?;
        let process = |value: &ProcessIdentityV4| NativeProcessV2 {
            pid: value.pid,
            birth: value.start_time,
        };
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?;
        let caller = &facts.caller_namespaces;
        let target = &facts.target_namespaces;
        let mut groups = memcordon_core::BoundedVec::default();
        for group in facts.identity.groups() {
            groups
                .try_push(*group)
                .map_err(|_| "mixed native groups exceed finite bound")?;
        }
        Ok(MixedNativeExecutionV2 {
            host_target: memcordon_core::BoundedText::new(super::runtime_manifest::target()?)
                .map_err(str::to_owned)?,
            boot_id: memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
            caller: process(&facts.caller),
            target: process(&facts.target),
            namespace_init: process(&facts.init),
            guardian: process(&facts.guardian),
            caller_uid: admission.caller.envelope.uid,
            caller_gid: admission.caller.envelope.gid,
            caller_user_namespace: caller[0].clone(),
            caller_mount_namespace: caller[1].clone(),
            caller_pid_namespace: caller[2].clone(),
            caller_network_namespace: caller[3].clone(),
            caller_ipc_namespace: caller[4].clone(),
            user_namespace: target[0].clone(),
            mount_namespace: target[1].clone(),
            pid_namespace: target[2].clone(),
            network_namespace: target[3].clone(),
            ipc_namespace: target[4].clone(),
            root_device: facts.root.0,
            root_inode: facts.root.1,
            runtime_image: admission.contract.runtime_image.clone(),
            input_image: admission.contract.input_image.clone(),
            root_layout: admission.contract.root_layout.clone(),
            execution_identity: admission.contract.execution_identity.clone(),
            target_uid: facts.identity.uid(),
            target_gid: facts.identity.gid(),
            supplementary_groups: groups,
            init_uid: 0,
            init_nondumpable: VerifiedTrue::observed(facts.init_nondumpable)
                .map_err(str::to_owned)?,
            no_new_privileges: observed,
            capabilities_empty: observed,
            filter_abi: match facts.ready.native_abi {
                NativeAbi::X86_64 => MixedFilterAbiV2::X86_64,
                NativeAbi::Aarch64 => MixedFilterAbiV2::Aarch64,
            },
            filter_instruction_sha256: DiagnosticSha256::from_bytes(facts.ready.filter_digest),
            target_authorized: observed,
            exec_observed: observed,
            authorization_monotonic_millis,
            post_exec_descriptor_count: 3,
            native_wait_status: status,
            outcome_origin: origin,
        })
    }

    pub(super) fn monitor_mixed(
        &mut self,
        admission: &mut super::mixed_admission::MixedOperationalAdmission,
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

    pub(super) fn retire_mixed(
        &mut self,
        admission: &mut super::mixed_admission::MixedOperationalAdmission,
        deadline: Instant,
    ) -> Result<MixedNativeRetirement, String> {
        self.retire_mixed_inner(
            admission,
            deadline,
            #[cfg(test)]
            None,
        )
    }

    /// Internal native-harness boundary only. No provider request selects it.
    #[cfg(test)]
    pub(super) fn retire_mixed_before_account_for_component(
        &mut self,
        admission: &mut super::mixed_admission::MixedOperationalAdmission,
        deadline: Instant,
        callback: &mut dyn FnMut(
            &Self,
            &super::mixed_admission::MixedOperationalAdmission,
        ) -> Result<(), String>,
    ) -> Result<MixedNativeRetirement, String> {
        self.retire_mixed_inner(admission, deadline, Some(callback))
    }

    #[cfg(test)]
    pub(crate) fn component_pre_account_observation(
        &self,
        admission: &super::mixed_admission::MixedOperationalAdmission,
    ) -> Result<serde_json::Value, String> {
        let native = self
            .mixed_native_retired
            .as_ref()
            .ok_or("component boundary lacks actual native retirement")?;
        let root = self
            .mixed_root_retired
            .as_ref()
            .ok_or("component boundary lacks actual root retirement")?;
        let cgroup = self
            .cgroup_retirement_raw
            .as_ref()
            .ok_or("component boundary lacks actual cgroup-empty/removal observations")?;
        root.require_binding(
            native.attempt_id(),
            &admission.contract.root_layout,
            &admission.contract.execution_identity,
        )?;
        if !self.native_exec_observed
            || self.cgroup.is_some()
            || self.namespace_init.is_some()
            || self.guardian.is_some()
            || self.target_pidfd.is_some()
            || self.mixed_root.is_some()
            || self.mixed_staging.is_some()
        {
            return Err("component boundary still retains native workload/root owners".into());
        }
        let export = self
            .mixed_export_path
            .as_ref()
            .ok_or("component boundary lacks native export path")?;
        let receipt = super::protected_read::read_protected_absolute(
            &export.join("export-receipt.json"),
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            None,
        )?;
        Ok(
            serde_json::json!({"attempt_id":native.attempt_id(),"native_wait_status":native.native_wait_status(),"cgroup_retirement":cgroup,"root_layout":admission.contract.root_layout,"execution_identity":admission.contract.execution_identity,"export_path":export,"export_receipt_sha256":DiagnosticSha256::from_bytes(Sha256::digest(&receipt).into()),"admission_reference":admission.component_reference_observation()?}),
        )
    }

    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "The native component probe retains original admission, worker, owned streams, separate deadlines and pre-account callback"
    )]
    pub(crate) fn component_execute_to_pre_account(
        &mut self,
        admission: &mut super::mixed_admission::MixedOperationalAdmission,
        attempt: [u8; 16],
        worker: BorrowedFd<'_>,
        streams: [OwnedFd; 3],
        work: Instant,
        cleanup: Instant,
        callback: &mut dyn FnMut(
            &Self,
            &super::mixed_admission::MixedOperationalAdmission,
            &memcordon_core::mixed_observation::MixedPreparedObservationV2,
        ) -> Result<(), String>,
    ) -> Result<
        (
            memcordon_core::result_v2::MixedNativeExecutionV2,
            memcordon_core::result_v2::MixedRetirementV2,
        ),
        String,
    > {
        let (control, _peer) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
        let setup = (|| -> Result<_, String> {
            self.create_boundary(
                admission.launch.policy.memory_limit_bytes,
                admission.launch.policy.swap_limit,
            )?;
            let identity = admission.identity.clone();
            let prepared = self.prepare_mixed_launch(admission, attempt)?;
            use std::os::unix::fs::MetadataExt;
            let network = std::fs::metadata("/proc/self/ns/net").map_err(|e| e.to_string())?;
            let provider_namespace = NamespaceIdentity {
                device: network.dev(),
                inode: network.ino(),
            };
            self.spawn_mixed_namespace(
                prepared.prelaunch,
                prepared.preparation,
                prepared.provider_root_channel,
                admission.caller.envelope.network_namespace_identity,
                provider_namespace,
                admission.launch.policy.lifetime,
                work,
            )?;
            self.start_guardian(attempt, admission.frontend_pidfd.as_fd(), worker, work)?;
            let observed = self.observe_gated_target(
                admission.caller.envelope.network_namespace_identity,
                provider_namespace,
                &identity,
                prepared.abi,
                prepared.filter,
                work,
            )?;
            self.capture_mixed_gated_facts(admission, &observed)?;
            self.prepare_relay(streams)?;
            self.prepare_operational_release(&observed)?;
            let snapshot = self.mixed_prepared_observation(
                admission,
                super::runtime_manifest::installed_binding()?,
            )?;
            let mut released = None;
            let mut clock = None;
            self.release_mixed(admission, &observed, &mut released, &mut clock)
                .map_err(|failure| failure.detail)?;
            if !matches!(
                self.observe_exec(work)?,
                PrivateExecObservation::ExecObservedAndDetached
            ) {
                return Err("component native exec not observed".into());
            }
            if !matches!(
                self.monitor_mixed(admission, Some(work), &control)?,
                PrivateMonitorOutcome::Completed
            ) {
                return Err("component workload did not complete naturally".into());
            }
            let retired = self.retire_mixed_before_account_for_component(
                admission,
                cleanup,
                &mut |owner, admission| callback(owner, admission, &snapshot),
            )?;
            let execution = self.mixed_execution_after_retirement(
                admission,
                &retired,
                memcordon_core::result_v2::MixedOutcomeOriginV2::NativeExit,
                clock.ok_or("actual component authorization clock absent")?,
            )?;
            Ok((execution, retired.retirement))
        })();
        if setup.is_ok() {
            return setup;
        }
        let retirement = if self.has_mixed_root()
            || self.mixed_root_retired.is_some()
            || self.possibly_released()
        {
            self.retire_mixed(admission, cleanup).map(|_| ())
        } else {
            self.retire_mixed_unreleased_without_root(admission, cleanup)
        };
        match (setup, retirement) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => {
                Err(format!("{error}; component native cleanup: {cleanup}"))
            }
        }
    }

    #[cfg_attr(
        test,
        expect(
            clippy::type_complexity,
            reason = "The test-only pre-account boundary observes the original lifecycle owner and operational admission together"
        )
    )]
    fn retire_mixed_inner(
        &mut self,
        admission: &mut super::mixed_admission::MixedOperationalAdmission,
        deadline: Instant,
        #[cfg(test)] mut before_account: Option<
            &mut dyn FnMut(
                &Self,
                &super::mixed_admission::MixedOperationalAdmission,
            ) -> Result<(), String>,
        >,
    ) -> Result<MixedNativeRetirement, String> {
        self.record_mut().begin_mixed_retirement()?;
        let cleanup = (|| -> Result<_, String> {
            if self.mixed_native_retired.is_none() {
                let candidate_exit_code = self.settle_native_resources(deadline)?;
                self.mixed_native_retired = Some(PrivateRetirementObservation {
                    attempt_id: self.record_mut().record().attempt_id.as_str().to_owned(),
                    retired: None,
                    candidate_exit_code,
                });
            }
            if self.mixed_root_retired.is_none() {
                let identity = admission
                    .activation
                    .registry
                    .resolve(
                        &admission.contract,
                        admission.caller.envelope.uid,
                        &admission.activation.epoch,
                    )
                    .map_err(|reason| {
                        format!("mixed retirement original binding differs: {reason:?}")
                    })?
                    .identity
                    .clone();
                if self.mixed_export_destination.is_none() {
                    self.mixed_export_destination =
                        Some(super::private_root::NativeExportDirectory::intended(
                            self.mixed_native_retired
                                .as_ref()
                                .expect("observed native retirement")
                                .attempt_id(),
                        )?);
                }
                let intended = self
                    .mixed_export_destination
                    .as_ref()
                    .expect("owned export destination")
                    .path()
                    .to_path_buf();
                self.record_mut().record_mixed_export_intent(&intended)?;
                self.mixed_export_destination
                    .as_mut()
                    .expect("owned export destination")
                    .allocate()?;
                let export_identity = self
                    .mixed_export_destination
                    .as_ref()
                    .expect("owned export destination")
                    .native_identity()?;
                self.record_mut()
                    .record_mixed_export_identity(export_identity)?;
                let root=self.mixed_root.take().ok_or("mixed retirement lacks held root; retain account and native journal for recovery")?;
                let staging = match self.mixed_staging.take() {
                    Some(staging) => staging,
                    None => {
                        self.mixed_root = Some(root);
                        return Err("mixed retirement staging owner absent".into());
                    }
                };
                let destination = self
                    .mixed_export_destination
                    .take()
                    .expect("owned export destination");
                let (root_retired, destination) = match root.export_and_close(
                    self.mixed_native_retired
                        .as_ref()
                        .expect("observed native retirement"),
                    &identity,
                    staging,
                    destination,
                ) {
                    Ok(retired) => retired,
                    Err(failure) => {
                        self.mixed_root = Some(failure.root);
                        self.mixed_staging = Some(failure.staging);
                        self.mixed_export_path = failure.exported;
                        self.mixed_export_destination = Some(failure.destination);
                        return Err(failure.detail);
                    }
                };
                self.mixed_root_retired = Some(root_retired);
                self.mixed_export_path = Some(destination.path().to_path_buf());
                self.mixed_export_destination = Some(destination);
            }
            let native = self
                .mixed_native_retired
                .as_ref()
                .expect("observed native retirement");
            let root_retired = self
                .mixed_root_retired
                .as_ref()
                .expect("observed root retirement");
            let export_path = self
                .mixed_export_path
                .as_ref()
                .ok_or("retired mixed export path absent")?;
            let receipt = super::protected_read::read_protected_absolute(
                &export_path.join("export-receipt.json"),
                memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
                None,
            )?;
            #[cfg(test)]
            if let Some(callback) = before_account.as_mut() {
                callback(self, admission)?;
            }
            admission.retire_after_native_root_and_account_quiescence(native, root_retired)?;
            // Reached only after every owned native retirement operation above
            // returned its observed-success proof; none is inferred from JSON.
            let retired_fact = VerifiedTrue::observed(true).map_err(str::to_owned)?;
            let retirement = memcordon_core::result_v2::MixedRetirementV2 {
                attempt_id: memcordon_core::BoundedText::new(native.attempt_id())
                    .map_err(str::to_owned)?,
                workload_empty: retired_fact,
                init_reaped: retired_fact,
                guardian_reaped: retired_fact,
                relays_drained_and_closed: retired_fact,
                namespace_references_closed: retired_fact,
                root_references_closed: retired_fact,
                staging_removed: retired_fact,
                account_quiescent: retired_fact,
                reservation_retired: retired_fact,
                export_receipt_sha256: memcordon_core::workload_codec::hash_bytes(&receipt),
            };
            let permit = VerifiedPrivateRetirement::observed(self.record_mut().record());
            self.record_mut()
                .retire_mixed_after_native_cleanup(permit)?;
            self.record.take();
            let native = self
                .mixed_native_retired
                .take()
                .expect("observed native retirement");
            let export_path = self
                .mixed_export_path
                .take()
                .expect("observed export publication");
            Ok(MixedNativeRetirement {
                native,
                retirement,
                export_path,
            })
        })();
        if let Err(detail) = &cleanup {
            if let Some(record) = self.record.as_mut() {
                if record.record().phase != PrivateAttemptPhase::Retired {
                    let _ = record.cleanup_incomplete(detail);
                }
            }
        }
        cleanup
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

pub(super) struct MixedNativeRetirement {
    pub native: PrivateRetirementObservation,
    pub retirement: memcordon_core::result_v2::MixedRetirementV2,
    pub export_path: std::path::PathBuf,
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
        if self.mixed_staging.is_some() {
            if let Some(relay) = self.relay.as_mut() {
                relay.close_stdin_after_target_exit();
                while !relay.completed() {
                    if Instant::now() >= deadline {
                        return Err("mixed relay retirement drain deadline elapsed".into());
                    }
                    relay.tick(Duration::from_millis(10))?;
                }
                self.mixed_stdout_sha256 = Some(relay.mixed_stdout_digest()?);
            }
        }
        self.relay.take();
        self.network.take();
        if self.mixed_staging.is_some() {
            if let Some(guardian) = self.guardian.as_mut() {
                guardian.retire_mixed_observed(
                    self.monitor_outcome == Some(PrivateMonitorOutcome::FrontendLost),
                    deadline,
                )?;
            }
            self.guardian.take();
        } else if let Some(guardian) = self.guardian.take() {
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
