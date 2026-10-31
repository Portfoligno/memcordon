//! Move-only ownership for one private attempt. Every acquired native handle
//! enters this ledger before another fallible step. Only `retire` can produce
//! terminal evidence; dropping the owner starts best-effort containment.

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use serde::{Deserialize, Serialize};

use super::cgroup::AttemptCgroup;
use super::descriptor_custody::{
    ExpectedGatedDescriptorInventory, GatedDescriptorProof, ProviderPipeStdio,
};
use super::execution_identity::ResolvedTargetIdentity;
use super::launch::PrivateGatedPrelaunch;

/// Held native preparation; it conveys no caller authorization or registry state.
pub(super) struct PreparedPrivateLaunch {
    pub prelaunch: PrivateGatedPrelaunch,
    pub preparation: super::private_namespace_init::MixedNamespacePreparation,
    pub provider_root_channel: std::os::unix::net::UnixStream,
    pub abi: super::network_filter::NativeAbi,
    pub filter: [u8; 32],
}
use super::namespace::{NamespaceInit, NamespaceMode};
use super::native_process::{PrivateAttemptPhase, ProcessIdentityV4, ReleaseCheckpoint};
use super::network_filter::NativeAbi;
use super::network_profile::PrivateNetworkSetup;
use super::private_guardian::PrivateGuardian;
use super::private_namespace_init::{
    PrivateNamespaceStartupProvider, observe_private_namespace_startup,
    private_namespace_startup_channel,
};
use super::private_pid_identity::PrivateNamespaceTargetIdentity;
use super::private_relay::PrivateRelay;
use super::private_target::{
    PRIVATE_EXEC_ARMED_PACKET, PrivateControlObservation, PrivateGatedReadback, PrivateGatedTarget,
    PrivateNetworkNamespaceOwner, decode_private_control_packet, observe_private_gated_target,
};
use super::private_wait_status::{
    bounded_retirement_detail, capture_target_status_until, preserve_status_through_containment,
    require_target_status,
};
use crate::request::NamespaceIdentity;

pub(super) struct MixedNamespaceContext {
    pub caller_namespace: NamespaceIdentity,
    pub provider_namespace: NamespaceIdentity,
    pub lifetime: crate::request::Lifetime,
}

pub(super) struct WorkloadExecutionInputs {
    pub start: memcordon_core::workload_request::WorkloadStartV1,
    pub launch: crate::request::LaunchRequestV2,
    pub caller: super::envelope::CapturedCallerEnvelopeV2,
    pub account: super::workload_account::VerifiedPackageAccount,
    pub worker: OwnedFd,
    pub frontend: OwnedFd,
    pub streams: [OwnedFd; 3],
    pub association: memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    pub inputs: super::workload_inputs::HeldWorkloadInputs,
    pub setup_cutoff: Instant,
}

pub(super) struct WorkloadLaunchInputs {
    pub identity: ResolvedTargetIdentity,
    pub runtime: super::workload_snapshot::HeldSnapshot,
    pub input: super::workload_snapshot::HeldSnapshot,
    pub working_directory: Option<memcordon_core::workload_request::RootRelativePath>,
    pub attempt: [u8; 16],
    pub challenge: [u8; 16],
    pub cutoff: Instant,
}

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
    caller_namespaces: [memcordon_core::execution_facts::NativeNamespaceV2; 5],
    target_namespaces: [memcordon_core::execution_facts::NativeNamespaceV2; 5],
    root: (u64, u64),
    identity: ResolvedTargetIdentity,
    ready: super::private_target::PrivateReadyObservation,
    init_nondumpable: bool,
}

fn observe_gated_facts<J: PrivateNativeJournal>(
    owner: &PrivateAttemptOwner<J>,
    frontend: &ProcessIdentityV4,
    frontend_pidfd: BorrowedFd<'_>,
    observed: &PrivateObservedTarget,
) -> Result<MixedGatedFacts, String> {
    fn namespaces(
        pid: u32,
    ) -> Result<[memcordon_core::execution_facts::NativeNamespaceV2; 5], String> {
        let mut values = Vec::new();
        for name in ["user", "mnt", "pid", "net", "ipc"] {
            let metadata = std::fs::metadata(
                std::path::Path::new("/proc")
                    .join(pid.to_string())
                    .join("ns")
                    .join(name),
            )
            .map_err(|e| e.to_string())?;
            values.push(memcordon_core::execution_facts::NativeNamespaceV2 {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        }
        values
            .try_into()
            .map_err(|_| "native namespace tuple differs".into())
    }
    owner.require_live_target_identity(&observed.target)?;
    let caller = ProcessIdentityV4::observe(
        i32::try_from(frontend.pid).map_err(|_| "frontend PID exceeds native range")?,
        frontend_pidfd,
    )?;
    if caller != *frontend {
        return Err("original caller birth changed during native observation".into());
    }
    let init = owner
        .namespace_init
        .as_ref()
        .ok_or("native init owner absent")?;
    let init_identity = ProcessIdentityV4::observe(init.host_pid, init.pidfd.as_fd())?;
    if init_identity != observed.namespace_init {
        return Err("native init birth changed".into());
    }
    let guardian = owner
        .guardian
        .as_ref()
        .ok_or("native guardian owner absent")?
        .identity()?;
    let caller_namespaces = namespaces(caller.pid)?;
    let target_namespaces = namespaces(observed.target.pid)?;
    if target_namespaces != namespaces(init_identity.pid)?
        || target_namespaces[0] != caller_namespaces[0]
        || (1..5).any(|index| target_namespaces[index] == caller_namespaces[index])
    {
        return Err("target/init/caller namespace separation differs".into());
    }
    let root = owner
        .mixed_root
        .as_ref()
        .ok_or("held private root absent")?;
    let metadata = File::from(
        root.as_fd()
            .try_clone_to_owned()
            .map_err(|e| e.to_string())?,
    )
    .metadata()
    .map_err(|e| e.to_string())?;
    if !root.init_nondumpable() {
        return Err("original native init was dumpable".into());
    }
    owner.require_live_target_identity(&observed.target)?;
    if ProcessIdentityV4::observe(
        i32::try_from(frontend.pid).map_err(|_| "frontend PID exceeds native range")?,
        frontend_pidfd,
    )? != caller
        || ProcessIdentityV4::observe(init.host_pid, init.pidfd.as_fd())? != init_identity
    {
        return Err("original native process identity changed during observation".into());
    }
    Ok(MixedGatedFacts {
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
    })
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
    MemoryOom,
}

pub trait PrivateNativeJournal {
    fn namespace_intent(&mut self) -> Result<(), String>;
    fn init_acquired(&mut self, init: ProcessIdentityV4) -> Result<(), String>;
    fn target_acquired(
        &mut self,
        init: ProcessIdentityV4,
        target: ProcessIdentityV4,
    ) -> Result<(), String>;
    fn guardian_intent(&mut self) -> Result<(), String>;
    fn boundary_intent(&mut self) -> Result<(), String>;
    fn root_received(&mut self, device: u64, inode: u64) -> Result<(), String>;
    fn phase(&self) -> PrivateAttemptPhase;
    fn read_back_native(&self) -> Result<(), String>;
    fn attempt_id(&self) -> &str;
    fn frontend(&self) -> &ProcessIdentityV4;
    fn target(&self) -> Option<&ProcessIdentityV4>;
    fn namespace_init(&self) -> Option<&ProcessIdentityV4>;
    fn network_namespace_inode(&self) -> Option<u64>;
    fn boundary_created(&mut self) -> Result<(), String>;
    fn guardian_ready(&mut self, guardian: ProcessIdentityV4) -> Result<(), String>;
    fn target_gated(
        &mut self,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
    ) -> Result<(), String>;
    fn execution_observed_at(&mut self, millis: u64) -> Result<(), String>;
    fn retiring(&mut self) -> Result<(), String>;
    fn cleanup_incomplete(&mut self, detail: &str) -> Result<(), String>;
}

pub struct PrivateAttemptOwner<
    J: PrivateNativeJournal = super::workload_attempt::DurableWorkloadAttempt,
> {
    record: Option<J>,
    cgroup: Option<AttemptCgroup>,
    namespace_init: Option<NamespaceInit>,
    init_exit_diagnostic: InitExitDiagnostic,
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
    mixed_stdout_sha256: Option<DiagnosticSha256>,
    mixed_facts: Option<MixedGatedFacts>,
    native_exec_observed: bool,
    release_monotonic_millis: Option<u64>,
    exec_observed_monotonic_millis: Option<u64>,
    memory_oom_kill_count: Option<u64>,
    memory_oom_event_count: Option<u64>,
    memory_max_bytes: Option<u64>,
    drop_cutoff: Option<Instant>,
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
            init_exit_diagnostic: InitExitDiagnostic::default(),
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
            mixed_stdout_sha256: None,
            mixed_facts: None,
            native_exec_observed: false,
            release_monotonic_millis: None,
            exec_observed_monotonic_millis: None,
            memory_oom_kill_count: None,
            memory_oom_event_count: None,
            memory_max_bytes: None,
            drop_cutoff: None,
        })
    }

    fn record_mut(&mut self) -> &mut J {
        self.record
            .as_mut()
            .expect("private owner retains durable record")
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
        self.record_mut().boundary_intent()?;
        let cgroup = AttemptCgroup::create(&identity, memory_max, swap_limit)?;
        self.cgroup = Some(cgroup);
        self.memory_max_bytes = self
            .cgroup
            .as_ref()
            .expect("new native cgroup owned before readback")
            .applied_memory_max()?;
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
    pub(super) fn spawn_mixed_namespace(
        &mut self,
        prelaunch: PrivateGatedPrelaunch,
        preparation: super::private_namespace_init::MixedNamespacePreparation,
        provider_root_channel: std::os::unix::net::UnixStream,
        context: MixedNamespaceContext,
        deadline: Instant,
    ) -> Result<(), String> {
        let MixedNamespaceContext {
            caller_namespace,
            provider_namespace,
            lifetime,
        } = context;
        if self.record_mut().phase() != PrivateAttemptPhase::BoundaryCreated
            || self.namespace_init.is_some()
            || self.mixed_staging.is_none()
        {
            return Err("mixed clone ownership phase differs".into());
        }
        self.record_mut().namespace_intent()?;
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
        let diagnostic_fd = self
            .startup
            .as_ref()
            .expect("stored mixed startup")
            .diagnostic_fd()
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
                init_startup.progress(super::private_init_diagnostic::Phase::ChildClosureEntered);
                unsafe {
                    libc::close(status_read_fd);
                    libc::close(provider_root_fd);
                    libc::close(diagnostic_fd);
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
            deadline,
        )
        .map_err(|root_error| {
            let initial_exit = observe_init_exit(init);
            self.init_exit_diagnostic.initial = Some(initial_exit.clone());
            let startup = self.startup.as_ref().ok_or_else(|| "mixed startup channel absent".to_owned())
                .and_then(|startup| startup.receive(init.host_pid, deadline));
            match startup {
                Ok(observed) => format!(
                    "{root_error}; authenticated namespace startup after root-transfer failure: {:?}",
                    observed.observation
                ),
                Err(startup_error) => format!(
                    "{root_error}; authenticated namespace startup unavailable: {startup_error}; original-init-exit={}",
                    initial_exit,
                ),
            }
        })?;
        self.mixed_root = Some(root);
        let root_metadata = File::from(
            self.mixed_root
                .as_ref()
                .expect("held root")
                .as_fd()
                .try_clone_to_owned()
                .map_err(|e| e.to_string())?,
        )
        .metadata()
        .map_err(|e| e.to_string())?;
        self.record_mut()
            .root_received(root_metadata.dev(), root_metadata.ino())?;
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
        let identity = ProcessIdentityV4::observe(init.host_pid, init.pidfd.as_fd())?;
        self.record_mut().init_acquired(identity)
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
        self.record_mut().guardian_intent()?;
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
        self.record_mut()
            .target_acquired(namespace_init.clone(), target.clone())?;
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
    /// Checks observed native resource custody before the current request's
    /// durable preparation checkpoint and single target release.
    fn validate_gated_native_resources(
        &self,
        observed: &PrivateObservedTarget,
        checkpoint: ReleaseCheckpoint,
    ) -> Result<(), String> {
        checkpoint.validate(self.record.as_ref().expect("owner retains record").phase())?;
        if !self.guardian.as_ref().is_some_and(PrivateGuardian::is_live) || self.relay.is_none() {
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
                let observed = super::clock::monotonic_millis()?;
                self.exec_observed_monotonic_millis = Some(observed);
                self.record_mut().execution_observed_at(observed)?;
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
    fn monitor_lifecycle(
        &mut self,
        frontend_pidfd: BorrowedFd<'_>,
        deadline: Option<Instant>,
        mut lifecycle_event: impl FnMut() -> Result<Option<PrivateMonitorOutcome>, String>,
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
            if let Some(event) = lifecycle_event()? {
                break event;
            }
            let cgroup = self
                .cgroup
                .as_ref()
                .ok_or("MCSEALED-PRIVATE-MONITOR: cgroup absent")?;
            self.memory_oom_kill_count = cgroup.memory_oom_kill_count()?;
            self.memory_oom_event_count = cgroup.memory_oom_event_count()?;
            if self.memory_max_bytes.is_some()
                && self.memory_oom_event_count.is_some_and(|count| count > 0)
                && self.memory_oom_kill_count.is_some_and(|count| count > 0)
            {
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

impl<J: PrivateNativeJournal> PrivateAttemptOwner<J> {
    /// This consumes only observed native resources. It does not remove a
    /// durable record, release a policy reference, or claim terminal success.
    fn settle_native_resources(&mut self, deadline: Instant) -> Result<Option<i32>, String> {
        let captured = if self.native_exec_observed {
            let captured = (|| {
                if self.observed_native_wait_status.is_none() {
                    let target = self.target_pidfd.as_ref().ok_or("MCSEALED-PRIVATE-OWNER: executed target pidfd absent before status capture")?;
                    if !pidfd_exited(target.as_fd())? {
                        // SAFETY: authenticated startup transferred this exact
                        // held target pidfd; no numeric PID/group lookup occurs.
                        if unsafe {
                            libc::syscall(
                                libc::SYS_pidfd_send_signal,
                                target.as_raw_fd(),
                                libc::SIGKILL,
                                std::ptr::null::<libc::siginfo_t>(),
                                0,
                            )
                        } == -1
                        {
                            let error = std::io::Error::last_os_error();
                            if error.raw_os_error() != Some(libc::ESRCH) {
                                return Err(format!(
                                    "MCSEALED-PRIVATE-OWNER: signal held target before status capture: errno={:?}; {error}",
                                    error.raw_os_error()
                                ));
                            }
                        }
                    }
                }
                let status = capture_target_status_until(
                    &mut self.observed_native_wait_status,
                    &mut self.status,
                    deadline,
                )?;
                if self.mixed_staging.is_some() && status.is_none() {
                    return Err("MCSEALED-PRIVATE-OWNER: executed mixed target status absent before containment".into());
                }
                Ok(status)
            })();
            Some(captured)
        } else {
            None
        };
        let candidate = match captured {
            Some(captured) => preserve_status_through_containment(captured, || {
                self.contain_native_resources(deadline)
            })?,
            None => {
                self.contain_native_resources(deadline)?;
                capture_target_status_until(
                    &mut self.observed_native_wait_status,
                    &mut self.status,
                    deadline,
                )?
            }
        };
        if self.monitor_outcome == Some(PrivateMonitorOutcome::Completed) && candidate.is_none() {
            return Err("MCSEALED-PRIVATE-OWNER: completed target status absent".into());
        }
        Ok(candidate)
    }

    fn contain_native_resources(&mut self, deadline: Instant) -> Result<(), String> {
        let mut failures = Vec::new();
        if self.init_exit_diagnostic.before_containment.is_none() {
            self.init_exit_diagnostic.before_containment =
                self.namespace_init.as_ref().map(observe_init_exit);
        }
        if let Some(cgroup) = self.cgroup.as_ref() {
            self.init_exit_diagnostic.containment_attempted = true;
            match cgroup.clone().kill_and_retire_observed(deadline) {
                Ok(observed) => {
                    self.cgroup_retirement_raw = Some(observed);
                    self.cgroup.take();
                }
                Err(error) => failures.push(format!(
                    "cgroup containment: {}",
                    bounded_retirement_detail(&error, 256)
                )),
            }
        }
        if let Some(target) = self.target_pidfd.as_ref() {
            match wait_pidfd(target.as_fd(), deadline) {
                Ok(()) => {
                    self.target_pidfd.take();
                }
                Err(error) => failures.push(format!(
                    "held target settlement: {}",
                    bounded_retirement_detail(&error, 256)
                )),
            }
        }
        if let Some(init) = self.namespace_init.as_ref() {
            match wait_exact_child(init.host_pid, init.pidfd.as_fd(), deadline) {
                Ok(status) => {
                    self.init_exit_diagnostic.reaped = Some((init.host_pid, status));
                    self.namespace_init.take();
                }
                Err(error) => failures.push(format!(
                    "exact init settlement: {}",
                    bounded_retirement_detail(&error, 256)
                )),
            }
        }
        if !failures.is_empty() {
            // Keep failed owners and the armed guardian; no downstream proof
            // or authority release is available from partial containment.
            return Err(format!(
                "{}; {}",
                failures.join("; "),
                self.init_exit_detail()
            ));
        }
        self.startup.take();
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
        Ok(())
    }

    pub(super) fn init_exit_detail(&self) -> String {
        self.init_exit_diagnostic.detail()
    }
}

pub(super) struct WorkloadProcessesRetired {
    attempt: String,
    target_uid: u32,
    wait_status: Option<i32>,
}
impl WorkloadProcessesRetired {
    pub(super) fn attempt(&self) -> &str {
        &self.attempt
    }
    pub(super) fn target_uid(&self) -> u32 {
        self.target_uid
    }
    pub(super) fn wait_status(&self) -> Option<i32> {
        self.wait_status
    }
}

impl PrivateAttemptOwner<super::workload_attempt::DurableWorkloadAttempt> {
    pub(super) fn execute_workload(
        mut self,
        stream: &mut std::os::unix::net::UnixStream,
        execution: WorkloadExecutionInputs,
    ) -> Result<memcordon_core::result_v3::LinuxWorkloadTerminalV1, String> {
        use memcordon_core::execution_facts::CleanupStateV1;
        use memcordon_core::result_v3::*;
        let WorkloadExecutionInputs {
            start,
            launch,
            caller,
            account,
            worker,
            frontend,
            streams,
            association,
            inputs,
            setup_cutoff,
        } = execution;
        self.drop_cutoff = Some(setup_cutoff);
        let identity = ResolvedTargetIdentity::package_account(&account, caller.envelope.uid)?;
        let super::workload_inputs::HeldWorkloadInputs {
            runtime,
            input,
            staging,
            footprint,
        } = inputs;
        let attempt = self.record_mut().attempt_id().to_owned();
        let mut failures = Vec::<String>::new();
        let mut pre_release_cancel = None;
        let work = (|| -> Result<PrivateMonitorOutcome, String> {
            let current = super::workload_account::verify()?;
            if (current.uid(), current.gid()) != (account.uid(), account.gid()) {
                return Err("installed workload credentials changed during input transfer".into());
            }
            if start.attempt_deadline_millis.is_some()
                && (launch.policy.deadline_scope != crate::request::DeadlineScope::Attempt
                    || launch.policy.absolute_deadline_millis.is_some())
            {
                return Err("attempt duration conflicts with native deadline scope".into());
            }
            self.create_boundary(launch.policy.memory_limit_bytes, launch.policy.swap_limit)?;
            let prepared = self.prepare_workload_launch(
                &start.request,
                &launch,
                WorkloadLaunchInputs {
                    identity: identity.clone(),
                    runtime,
                    input,
                    working_directory: start.working_directory.clone(),
                    attempt: association.attempt,
                    challenge: association.challenge,
                    cutoff: setup_cutoff,
                },
            )?;
            let metadata = std::fs::metadata("/proc/self/ns/net").map_err(|e| e.to_string())?;
            let provider_namespace = NamespaceIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            self.spawn_mixed_namespace(
                prepared.prelaunch,
                prepared.preparation,
                prepared.provider_root_channel,
                MixedNamespaceContext {
                    caller_namespace: caller.envelope.network_namespace_identity,
                    provider_namespace,
                    lifetime: launch.policy.lifetime,
                },
                setup_cutoff,
            )?;
            self.start_guardian(
                association.attempt,
                frontend.as_fd(),
                worker.as_fd(),
                setup_cutoff,
            )?;
            let observed = self.observe_gated_target(
                caller.envelope.network_namespace_identity,
                provider_namespace,
                &identity,
                prepared.abi,
                prepared.filter,
                setup_cutoff,
            )?;
            self.capture_workload_gated(&observed, frontend.as_fd())?;
            self.prepare_relay(streams)?;
            let native = self
                .workload_native_observation()?
                .ok_or("original gated native observation absent")?;
            let prepared = LinuxWorkloadPreparedV1 {
                format: "memcordon.linux-workload-prepared".into(),
                revision: 1,
                association: association.clone(),
                request: self.record_mut().record().request.clone(),
                native,
            };
            prepared.validate()?;
            let payload = serde_json::to_vec(&prepared).map_err(|e| e.to_string())?;
            let expected = memcordon_core::hash_bytes(&payload);
            super::workload_runtime::write_frame_until(
                stream,
                &crate::protocol::Frame {
                    kind: crate::protocol::MessageKind::WorkloadPrepared,
                    nonce: association.challenge,
                    attempt_id: association.attempt,
                    payload,
                },
                setup_cutoff,
            )?;
            let acknowledgment =
                match super::workload_inputs::read_frame_until(stream, setup_cutoff) {
                    Ok(frame) => frame,
                    Err(error) => {
                        if pidfd_exited(frontend.as_fd())? {
                            pre_release_cancel = Some(
                                super::private_cancellation::PrivateCancellation::FrontendLost,
                            );
                        }
                        return Err(error);
                    }
                };
            if acknowledgment.nonce != association.challenge
                || acknowledgment.attempt_id != association.attempt
            {
                return Err("prepared acknowledgment crossed original native attempt".into());
            }
            if acknowledgment.kind == crate::protocol::MessageKind::WorkloadCancel
                && acknowledgment.payload.is_empty()
            {
                pre_release_cancel =
                    Some(super::private_cancellation::PrivateCancellation::Controlled);
                return Err("original owner cancelled while native target remained gated".into());
            }
            if acknowledgment.kind != crate::protocol::MessageKind::WorkloadPreparedAck {
                return Err(
                    "native target remains gated without its prepared acknowledgment".into(),
                );
            }
            let acknowledgment = WorkloadPreparedAckV1::parse(&acknowledgment.payload)?;
            if acknowledgment.association != association
                || acknowledgment.prepared_sha256 != expected
            {
                return Err(
                    "prepared acknowledgment does not bind exact original native observation bytes"
                        .into(),
                );
            }
            if let Some(cancel) = super::private_cancellation::observe_cancellation(stream, || {
                pidfd_exited(frontend.as_fd())
            })? {
                pre_release_cancel = Some(cancel);
                return Err(
                    "owner cancellation/loss observed while the target gate remained held".into(),
                );
            }
            let released = self.release_workload(&observed, frontend.as_fd(), setup_cutoff)?;
            let target_cutoff = if let Some(duration) = start.attempt_deadline_millis {
                Some(
                    released
                        .checked_add(Duration::from_millis(duration))
                        .ok_or("original attempt duration exceeds native range")?,
                )
            } else {
                launch
                    .policy
                    .absolute_deadline_millis
                    .map(|absolute| {
                        super::clock::monotonic_millis().and_then(|now| {
                            Instant::now()
                                .checked_add(Duration::from_millis(absolute.saturating_sub(now)))
                                .ok_or("original run deadline exceeds native range".into())
                        })
                    })
                    .transpose()?
            };
            let exec_cutoff = target_cutoff.map_or(setup_cutoff, |cutoff| cutoff.min(setup_cutoff));
            match self.observe_exec(exec_cutoff)? {
                PrivateExecObservation::ExecObservedAndDetached => {}
                PrivateExecObservation::Failed { phase, detail } => {
                    return Err(format!("native exec failed at phase {phase}: {detail}"));
                }
            }
            let native = self.workload_native_observation()?;
            self.record_mut().publish_native(native)?;
            self.monitor_workload(frontend.as_fd(), target_cutoff, stream)
        })();
        let mut outcome = match work {
            Ok(PrivateMonitorOutcome::Completed) => NativeWorkloadOutcomeV1::Unknown,
            Ok(PrivateMonitorOutcome::DeadlineExceeded) => NativeWorkloadOutcomeV1::Deadline,
            Ok(PrivateMonitorOutcome::ControlledCancellation) => {
                NativeWorkloadOutcomeV1::ControlledCancellation
            }
            Ok(PrivateMonitorOutcome::FrontendLost) => NativeWorkloadOutcomeV1::FrontendLost,
            Ok(PrivateMonitorOutcome::MemoryOom) => NativeWorkloadOutcomeV1::MemoryLimit,
            Err(error) => {
                failures.push(error);
                match pre_release_cancel {
                    Some(super::private_cancellation::PrivateCancellation::Controlled) => {
                        NativeWorkloadOutcomeV1::ControlledCancellation
                    }
                    Some(super::private_cancellation::PrivateCancellation::FrontendLost) => {
                        NativeWorkloadOutcomeV1::FrontendLost
                    }
                    None if self.release_monotonic_millis.is_none() => {
                        NativeWorkloadOutcomeV1::SetupFailure
                    }
                    None => NativeWorkloadOutcomeV1::NativeFailure,
                }
            }
        };
        let cleanup_nanos = self.record_mut().begin_cleanup(
            super::clock::monotonic_nanos()?
                .checked_add(10_000_000_000)
                .ok_or("original cleanup cutoff overflow")?,
        )?;
        let cleanup_cutoff = Instant::now()
            .checked_add(Duration::from_nanos(
                cleanup_nanos.saturating_sub(super::clock::monotonic_nanos()?),
            ))
            .ok_or("original cleanup cutoff exceeds native range")?;
        self.drop_cutoff = Some(cleanup_cutoff);
        let retired = match self.retire_workload_processes(&identity, cleanup_cutoff) {
            Ok(retired) => Some(retired),
            Err(error) => {
                failures.push(error);
                None
            }
        };
        if outcome == NativeWorkloadOutcomeV1::Unknown {
            outcome = match retired
                .as_ref()
                .and_then(WorkloadProcessesRetired::wait_status)
            {
                Some(status) if self.native_exec_observed && libc::WIFEXITED(status) => {
                    NativeWorkloadOutcomeV1::Exited {
                        code: libc::WEXITSTATUS(status),
                    }
                }
                Some(status) if self.native_exec_observed && libc::WIFSIGNALED(status) => {
                    NativeWorkloadOutcomeV1::Signaled {
                        signal: libc::WTERMSIG(status),
                    }
                }
                _ => NativeWorkloadOutcomeV1::Unknown,
            };
        }
        let native = self.workload_native_observation()?;
        self.record_mut()
            .publish_outcome(native.clone(), outcome.clone())?;
        let mut output_delivery = OutputDeliveryStateV3::Incomplete;
        let processes = retired.is_some();
        let mut roots_closed = false;
        let mut root_staging_retired = false;
        if let Some(retired) = retired.as_ref() {
            if let Some(root) = self.mixed_root.as_ref() {
                let output = (|| -> Result<(), String> {
                    let export = super::workload_runtime::create_export_directory(&staging)?;
                    let inventory = root.export_workload(retired, &export, cleanup_cutoff)?;
                    super::workload_runtime::send_outputs(
                        stream,
                        &association,
                        &export,
                        &inventory,
                        cleanup_cutoff,
                    )
                })();
                match output {
                    Ok(()) => output_delivery = OutputDeliveryStateV3::Complete,
                    Err(error) => failures.push(error),
                }
            }
            drop(self.mixed_root.take());
            roots_closed = true;
            if let Some(stage) = self.mixed_staging.as_mut() {
                match stage.retire_path() {
                    Ok(()) => {
                        drop(self.mixed_staging.take());
                        root_staging_retired = true;
                    }
                    Err(error) => failures.push(error),
                }
            } else {
                root_staging_retired = !self.record_mut().record().intents.root_staging;
            }
        }
        let mut inputs_retired = false;
        let mut footprint_retired = false;
        if processes && roots_closed && root_staging_retired {
            match super::workload_runtime::retire_input_staging(staging, &attempt, cleanup_cutoff) {
                Ok(()) => inputs_retired = true,
                Err(error) => failures.push(error),
            }
            if inputs_retired {
                match footprint.retire() {
                    Ok(()) => footprint_retired = true,
                    Err(error) => failures.push(error),
                }
            }
        }
        let complete = processes
            && roots_closed
            && root_staging_retired
            && inputs_retired
            && footprint_retired;
        let mut obligations = memcordon_core::BoundedVec::default();
        for (resource, settled) in [
            (CleanupResourceV3::Target, processes),
            (CleanupResourceV3::Aggregate, processes),
            (CleanupResourceV3::Guardian, processes),
            (CleanupResourceV3::NamespaceInit, processes),
            (CleanupResourceV3::Relays, processes),
            (CleanupResourceV3::RootReferences, roots_closed),
            (
                CleanupResourceV3::Staging,
                root_staging_retired && inputs_retired,
            ),
            (CleanupResourceV3::Footprint, footprint_retired),
            (CleanupResourceV3::Outputs, inputs_retired),
            (CleanupResourceV3::Record, complete),
        ] {
            obligations
                .try_push(CleanupObligationV3 { resource, settled })
                .map_err(|_| "cleanup obligations exceed bound")?;
        }
        let mut errors = memcordon_core::BoundedVec::default();
        for failure in failures {
            errors
                .try_push(memcordon_core::BoundedText::new(&failure).map_err(str::to_owned)?)
                .map_err(|_| "ordered native failures exceed bound")?;
        }
        let release = if self.release_monotonic_millis.is_some() {
            ReleaseKnowledgeV3::Released
        } else {
            self.record_mut().record().release
        };
        let terminal = LinuxWorkloadTerminalV1 {
            format: LINUX_WORKLOAD_TERMINAL_FORMAT.into(),
            revision: 1,
            association,
            request: self.record_mut().record().request.clone(),
            release,
            native,
            outcome,
            cleanup: CleanupV3 {
                state: if complete {
                    CleanupStateV1::Complete
                } else {
                    CleanupStateV1::Incomplete
                },
                obligations,
            },
            output_delivery,
            failures: errors,
        };
        self.record_mut().finish(terminal.clone())?;
        // The retained tombstone is factual replay state, never an admission owner.
        self.record.take();
        Ok(terminal)
    }
    pub(super) fn capture_workload_gated(
        &mut self,
        observed: &PrivateObservedTarget,
        frontend_pidfd: BorrowedFd<'_>,
    ) -> Result<(), String> {
        let frontend = self
            .record
            .as_ref()
            .ok_or("native journal owner absent")?
            .record()
            .frontend
            .clone();
        self.mixed_facts = Some(observe_gated_facts(
            self,
            &frontend,
            frontend_pidfd,
            observed,
        )?);
        let native = self.workload_native_observation()?;
        self.record_mut().publish_native(native)?;
        Ok(())
    }
    pub(super) fn workload_native_observation(
        &self,
    ) -> Result<Option<memcordon_core::result_v3::LinuxNativeExecutionV3>, String> {
        use memcordon_core::execution_facts::{MixedFilterAbiV2, NativeProcessV2};
        let Some(facts) = self.mixed_facts.as_ref() else {
            return Ok(None);
        };
        let record = self
            .record
            .as_ref()
            .ok_or("native journal owner absent during observation")?
            .record();
        let cgroup = record
            .cgroup
            .as_ref()
            .ok_or("native cgroup identity absent")?;
        let process = |p: &ProcessIdentityV4| NativeProcessV2 {
            pid: p.pid,
            birth: p.start_time,
        };
        let mut groups = memcordon_core::BoundedVec::default();
        for group in facts.identity.groups() {
            groups
                .try_push(*group)
                .map_err(|_| "native group inventory exceeds bound")?;
        }
        Ok(Some(memcordon_core::result_v3::LinuxNativeExecutionV3 {
            caller_namespaces: facts.caller_namespaces.clone(),
            user_namespace: facts.target_namespaces[0].clone(),
            target_namespace_pid: u32::try_from(
                self.target_pid_identity
                    .ok_or("held target namespace mapping absent")?
                    .namespace_pid(),
            )
            .map_err(|e| e.to_string())?,
            boot_id: record.boot_id.clone(),
            caller: process(&facts.caller),
            target: process(&facts.target),
            namespace_init: process(&facts.init),
            guardian: process(&facts.guardian),
            caller_uid: record.caller_uid,
            target_uid: facts.identity.uid(),
            target_gid: facts.identity.gid(),
            cgroup_device: cgroup.device,
            cgroup_inode: cgroup.inode,
            init_uid: 0,
            init_nondumpable: facts.init_nondumpable,
            mount_namespace: facts.target_namespaces[1].clone(),
            pid_namespace: facts.target_namespaces[2].clone(),
            network_namespace: facts.target_namespaces[3].clone(),
            ipc_namespace: facts.target_namespaces[4].clone(),
            root_device: facts.root.0,
            root_inode: facts.root.1,
            filter_abi: match facts.ready.native_abi {
                NativeAbi::X86_64 => MixedFilterAbiV2::X86_64,
                NativeAbi::Aarch64 => MixedFilterAbiV2::Aarch64,
            },
            filter_instruction_sha256: DiagnosticSha256::from_bytes(facts.ready.filter_digest),
            entrypoint_sha256: self
                .entrypoint_digest
                .clone()
                .ok_or("native held executable digest absent")?,
            supplementary_groups: groups,
            no_new_privileges: true,
            capabilities_empty: true,
            exec_observed: self.native_exec_observed,
            release_monotonic_millis: self.release_monotonic_millis,
            exec_observed_monotonic_millis: self.exec_observed_monotonic_millis,
            native_wait_status: self.observed_native_wait_status,
            memory_oom_kill_count: self.memory_oom_kill_count,
            memory_oom_event_count: self.memory_oom_event_count,
            memory_max_bytes: self.memory_max_bytes,
        }))
    }
    pub(super) fn retire_workload_processes(
        &mut self,
        identity: &ResolvedTargetIdentity,
        deadline: Instant,
    ) -> Result<WorkloadProcessesRetired, String> {
        let attempt = self.record_mut().attempt_id().to_owned();
        let record = self.record_mut().record().clone();
        let unpublished_helper = (record.intents.guardian
            && record.guardian.is_none()
            && self.guardian.is_none())
            || (record.intents.namespace_init
                && record.namespace_init.is_none()
                && self.namespace_init.is_none())
            || (record.intents.target && record.target.is_none() && self.target_pidfd.is_none());
        self.record_mut().retiring()?;
        let wait_status = self.settle_native_resources(deadline)?;
        if unpublished_helper {
            return Err(
                "native helper creation intent lacks a published or held exact owner".into(),
            );
        }
        if self.cgroup.is_some()
            || self.namespace_init.is_some()
            || self.guardian.is_some()
            || self.target_pidfd.is_some()
            || self.relay.is_some()
            || self.network.is_some()
        {
            return Err("native workload resources remain after settlement".into());
        }
        Ok(WorkloadProcessesRetired {
            attempt,
            target_uid: identity.uid(),
            wait_status,
        })
    }
    /// Prepare the same native root/filter machinery from held caller bytes and
    /// package credentials. No historical contract or registry enters this path.
    pub(super) fn prepare_workload_launch(
        &mut self,
        request: &memcordon_core::workload_request::WorkloadRequestV1,
        launch: &crate::request::LaunchRequestV2,
        inputs: WorkloadLaunchInputs,
    ) -> Result<PreparedPrivateLaunch, String> {
        use memcordon_core::workload_request::RuntimeRequestV1;
        use std::os::unix::fs::MetadataExt;
        let WorkloadLaunchInputs {
            identity,
            runtime,
            input,
            working_directory,
            attempt,
            challenge,
            cutoff,
        } = inputs;
        request.validate().map_err(|e| e.to_string())?;
        let RuntimeRequestV1::LinuxPrivate { inputs, layout, .. } = &request.runtime else {
            return Err("unsupported Linux workload profile".into());
        };
        if *runtime.digest() != inputs.runtime_digest || *input.digest() != inputs.input_digest {
            return Err("held input request binding differs".into());
        }
        let entrypoint = runtime
            .definition()
            .entrypoints
            .as_slice()
            .iter()
            .find(|entry| entry.id == inputs.entrypoint)
            .ok_or("selected caller image entrypoint absent")?;
        let entry = runtime
            .definition()
            .entries
            .as_slice()
            .iter()
            .find(|entry| entry.path() == &entrypoint.path)
            .ok_or("entrypoint bytes absent")?
            .clone();
        runtime.revalidate()?;
        input.revalidate()?;
        let library_path = super::image_elf_closure::validate(&runtime, &input, layout, cutoff)?;
        let initial_launch = super::image_elf_closure::initial_launch(launch, library_path)?;
        let executable = super::entrypoint::VerifiedEntrypoint::from_private_root_image(
            File::from(
                runtime
                    .object(entry.path())?
                    .try_clone_to_owned()
                    .map_err(|e| e.to_string())?,
            ),
            &entry,
            cutoff,
        )?;
        let executable_digest = DiagnosticSha256::from_bytes(executable.identity().sha256);
        let abi = match (std::env::consts::ARCH, cfg!(target_env = "gnu")) {
            ("x86_64", true) => NativeAbi::X86_64,
            ("aarch64", true) => NativeAbi::Aarch64,
            _ => return Err("unsupported native private-workload ABI".into()),
        };
        let filter = super::network_filter::filter_instruction_digest(
            &super::network_filter::compile_mixed_seqpacket_filter(abi),
        )
        .map_err(str::to_owned)?;
        let arguments =
            super::private_target::PrivateExecArguments::from_native_launch(&initial_launch)?;
        let prelaunch = super::launch::build_private_gated_prelaunch(
            identity.clone(),
            executable,
            executable_digest,
            arguments,
            abi,
            filter,
        )?;
        let layout = layout.clone();
        let cgroup = self
            .cgroup
            .as_ref()
            .ok_or("workload cgroup absent")?
            .open()?;
        let native = cgroup.metadata().map_err(|e| e.to_string())?;
        self.record_mut()
            .record_cgroup(super::workload_attempt::DirectoryIdentity {
                device: native.dev(),
                inode: native.ino(),
            })?;
        let identity_text: String = attempt.iter().map(|byte| format!("{byte:02x}")).collect();
        if identity_text != self.record_mut().attempt_id() || self.mixed_staging.is_some() {
            return Err("workload preparation is single-use and attempt-bound".into());
        }
        self.record_mut().root_staging_intent()?;
        self.mixed_staging = Some(super::private_root::NativeRootStaging::create(
            &identity_text,
        )?);
        let staging = self.mixed_staging.as_ref().expect("new staging owner");
        let native = staging.native_identity()?;
        let child = staging.for_namespace_child()?;
        self.record_mut()
            .record_staging(super::workload_attempt::DirectoryIdentity {
                device: native.device,
                inode: native.inode,
            })?;
        let (provider_root_channel, root_channel) = super::private_root::native_root_channel()?;
        let preparation = super::private_namespace_init::MixedNamespacePreparation {
            runtime,
            input,
            layout,
            staging: child,
            entry,
            working_directory,
            root_channel,
            nonce: challenge,
            attempt,
            identity: super::private_root::RootOwnership::Workload {
                request_sha256: request.digest().map_err(|e| e.to_string())?,
                target_uid: identity.uid(),
            },
        };
        Ok(PreparedPrivateLaunch {
            prelaunch,
            preparation,
            provider_root_channel,
            abi,
            filter,
        })
    }

    /// Called under the attempt's cancellation/release mutex. Durable uncertainty
    /// precedes the one release byte; repeated calls cannot release again.
    pub(super) fn release_workload(
        &mut self,
        observed: &PrivateObservedTarget,
        frontend: BorrowedFd<'_>,
        deadline: Instant,
    ) -> Result<Instant, String> {
        self.validate_gated_native_resources(observed, ReleaseCheckpoint::BeforeIntent)?;
        if Instant::now() >= deadline || pidfd_exited(frontend)? {
            return Err("workload original owner/deadline lost before release".into());
        }
        self.require_live_target_identity(&observed.target)?;
        if self.mixed_root.is_none()
            || !self.guardian.as_ref().is_some_and(PrivateGuardian::is_live)
        {
            return Err("workload root/guardian custody absent before release".into());
        }
        self.record_mut().release_intent()?;
        self.record_mut().read_back_native()?;
        // Durable publication may block. Recheck the original owners and cutoff
        // after it, before the only release byte can leave this process.
        self.validate_gated_native_resources(observed, ReleaseCheckpoint::AfterIntent)?;
        self.require_live_target_identity(&observed.target)?;
        if self.mixed_root.is_none()
            || !self.guardian.as_ref().is_some_and(PrivateGuardian::is_live)
            || Instant::now() >= deadline
            || pidfd_exited(frontend)?
        {
            return Err("workload original owner/deadline lost after release intent".into());
        }
        let control = self.control.as_ref().ok_or("workload target gate absent")?;
        let byte = [1_u8];
        let release_monotonic_millis = super::clock::monotonic_millis()?;
        let released_at = Instant::now();
        if released_at >= deadline {
            return Err("workload original cutoff expired before release byte".into());
        }
        let sent = unsafe {
            libc::send(
                control.as_raw_fd(),
                byte.as_ptr().cast(),
                byte.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent != isize::try_from(byte.len()).expect("one byte fits isize") {
            return Err(std::io::Error::last_os_error().to_string());
        }
        self.release_monotonic_millis = Some(release_monotonic_millis);
        let native = self.workload_native_observation()?;
        self.record_mut().release_sent(native)?;
        Ok(released_at)
    }

    pub(super) fn monitor_workload(
        &mut self,
        frontend: BorrowedFd<'_>,
        deadline: Option<Instant>,
        channel: &std::os::unix::net::UnixStream,
    ) -> Result<PrivateMonitorOutcome, String> {
        self.monitor_lifecycle(frontend, deadline, || Ok(None), channel)
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
            let _ = cgroup.kill_and_retire(
                self.drop_cutoff
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(10)),
            );
        }
        if let Some(init) = self.namespace_init.take() {
            let _ = wait_exact_child(
                init.host_pid,
                init.pidfd.as_fd(),
                self.drop_cutoff
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(2)),
            );
        }
        if let Some(record) = self.record.as_mut() {
            let _ = record
                .cleanup_incomplete("private owner dropped without verified terminal retirement");
        }
    }
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

#[derive(Default)]
struct InitExitDiagnostic {
    initial: Option<String>,
    before_containment: Option<String>,
    containment_attempted: bool,
    reaped: Option<(libc::pid_t, i32)>,
}

impl InitExitDiagnostic {
    fn detail(&self) -> String {
        let reaped = match self.reaped {
            None => "unavailable".to_owned(),
            Some((pid, raw)) => format!(
                "pid={pid},raw={raw},exit={:?},signal={:?},core={}",
                libc::WIFEXITED(raw).then(|| libc::WEXITSTATUS(raw)),
                libc::WIFSIGNALED(raw).then(|| libc::WTERMSIG(raw)),
                libc::WIFSIGNALED(raw) && libc::WCOREDUMP(raw),
            ),
        };
        format!(
            "original-init-status: initial=[{}],pre-containment=[{}],containment-attempted={},reaped=[{reaped}]",
            self.initial.as_deref().unwrap_or("not-sampled"),
            self.before_containment.as_deref().unwrap_or("not-sampled"),
            self.containment_attempted,
        )
    }
}

fn observe_init_exit(init: &NamespaceInit) -> String {
    // Observe only the original held child. WNOWAIT leaves its status and
    // ownership intact for the existing retirement path; WNOHANG never waits.
    // SAFETY: zero is the required empty output state for nonblocking waitid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: the live pidfd is owned by this original child owner, and info
    // is writable for one siginfo_t. These flags never reap or block.
    let observed = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            init.pidfd.as_raw_fd() as libc::id_t,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if observed == -1 {
        let error = std::io::Error::last_os_error();
        return format!(
            "query-error: kind={:?},raw={:?}",
            error.kind(),
            error.raw_os_error()
        );
    }
    // SAFETY: successful waitid initialized the child-status siginfo fields.
    let pid = unsafe { info.si_pid() };
    if pid == 0 {
        return "not-observed".into();
    }
    if pid != init.host_pid {
        return format!(
            "identity-mismatch: expected={} observed={pid}",
            init.host_pid
        );
    }
    // SAFETY: the same successful child-status waitid initialized si_status.
    format!("pid={pid},code={},status={}", info.si_code, unsafe {
        info.si_status()
    })
}

fn wait_exact_child(
    pid: libc::pid_t,
    pidfd: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<i32, String> {
    wait_pidfd(pidfd, deadline)?;
    loop {
        let mut status = 0;
        // SAFETY: pid is the exact namespace init child retained by this owner.
        let reaped = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if reaped == pid {
            return Ok(status);
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

#[cfg(test)]
#[path = "../../../../tests/private/linux_init_exit.rs"]
mod init_exit_tests;
