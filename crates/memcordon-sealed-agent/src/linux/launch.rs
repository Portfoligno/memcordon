use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(feature = "test-support")]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::PathBuf};

use crate::rejection::{RejectionCleanupV1, RejectionPhaseV1, RejectionV1};
use crate::request::LaunchRequestV1;

use super::attempt::AttemptRecord;
use super::cgroup::{AttemptCgroup, AttemptRetirementObservation};

const EXEC_CONTROL_VERSION: u8 = 1;
const EXEC_CONTROL_ARMED: [u8; 4] = [EXEC_CONTROL_VERSION, 1, 1, 0];
const EXEC_CONTROL_FAILURE_KIND: u8 = 2;
const EXEC_CONTROL_TARGET_EXEC_PHASE: u8 = 1;
const EXEC_FAILURE_RECORD_LENGTH: usize = 8;
const EXEC_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const NAMESPACE_STARTUP_VERSION: u8 = 1;
const NAMESPACE_STARTUP_READY_KIND: u8 = 1;
const NAMESPACE_STARTUP_FAILURE_KIND: u8 = 2;
const NAMESPACE_STARTUP_RECORD_LENGTH: usize = 8;
const GUARDIAN_TERMINAL_VERSION: u8 = 1;
const GUARDIAN_TERMINAL_RECORD_LENGTH: usize = 24;
const GUARDIAN_KILL_INVOKED: u8 = 1 << 0;
const GUARDIAN_POPULATED_ZERO: u8 = 1 << 1;
const GUARDIAN_CONTAINMENT_REMOVED: u8 = 1 << 2;
const GUARDIAN_RECORD_RETIRED: u8 = 1 << 3;
const GUARDIAN_KNOWN_FLAGS: u8 = GUARDIAN_KILL_INVOKED
    | GUARDIAN_POPULATED_ZERO
    | GUARDIAN_CONTAINMENT_REMOVED
    | GUARDIAN_RECORD_RETIRED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespaceStartupStatus {
    TargetForked,
    Failed(super::namespace::NamespaceInitError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespaceStartupObservation {
    Pending,
    Closed,
    Status(NamespaceStartupStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecFailureClass {
    NotFound,
    NotExecutable,
    Other,
}

impl ExecFailureClass {
    pub const fn receipt_name(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::NotExecutable => "not-executable",
            Self::Other => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetExecStatus {
    Succeeded,
    Failed {
        class: ExecFailureClass,
        os_code: i32,
    },
}

#[derive(Debug)]
pub struct TerminalFacts {
    pub child_status: i32,
    pub exec_status: TargetExecStatus,
    pub spawn_error_reported: bool,
    pub target_pid: u32,
    pub authorization_offset_millis: u64,
    pub cgroup_empty: bool,
    pub init_reaped: bool,
    pub guardian_reaped: bool,
    pub boundary_retired: bool,
    pub assignment_verified: bool,
    pub namespaces_verified: bool,
    pub credentials_verified: bool,
    pub capabilities_empty: bool,
    pub descriptors_verified: bool,
    pub cgroup_view_denied: bool,
    pub guardian_ready_before_authorization: bool,
    pub frontend_loss_authority_verified: bool,
    pub cgroup_kill_invoked: bool,
    pub memory_limit_exceeded: bool,
    pub deadline_exceeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementOwner {
    Guardian,
    Provider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultExecutionOutcome {
    pub attempt_id: [u8; 16],
    pub rejection: RejectionV1,
    pub retirement_owner: RetirementOwner,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultReady {
    pub path: PathBuf,
    pub expected: Vec<u8>,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultPlan {
    pub point: FaultPoint,
    pub postauthorization_ready: Option<FaultReady>,
    pub provider_loss_claim_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardianTrigger {
    FrontendLoss,
    ProviderLoss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardianTerminalClaim {
    pub trigger: GuardianTrigger,
    pub attempt_id: [u8; 16],
    pub cgroup_kill_invoked: bool,
    pub populated_zero_observed: bool,
    pub containment_removed: bool,
    pub record_retired: bool,
}

#[derive(Clone)]
struct TargetCredentials {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

struct NamespaceStartupChannel {
    init: File,
    provider_fd: i32,
    inject_failure_before_target: bool,
}

struct AttemptCleanupGuard {
    record: AttemptRecord,
    cgroup: Option<AttemptCgroup>,
    init_pid: Option<libc::pid_t>,
    guardian_pid: Option<libc::pid_t>,
    guardian_control: Option<File>,
    guardian_terminal: Option<File>,
    attempt_id: [u8; 16],
    armed: bool,
}

impl AttemptCleanupGuard {
    fn new(record: AttemptRecord, attempt_id: [u8; 16]) -> Self {
        Self {
            record,
            cgroup: None,
            init_pid: None,
            guardian_pid: None,
            guardian_control: None,
            guardian_terminal: None,
            attempt_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn set_cgroup(&mut self, cgroup: AttemptCgroup) {
        self.cgroup = Some(cgroup);
    }

    fn set_guardian_channels(&mut self, control: File, terminal: File) {
        self.guardian_control = Some(control);
        self.guardian_terminal = Some(terminal);
    }

    fn finalize_failure(&mut self) -> Result<(), String> {
        if !self.armed {
            return Ok(());
        }

        let provider_retired = self.cgroup.as_ref().is_none_or(|cgroup| {
            cgroup
                .clone()
                .kill_and_retire(Instant::now() + Duration::from_secs(30))
                .is_ok()
        });
        if provider_retired {
            self.cgroup = None;
        }

        let guardian_was_never_started = self.guardian_pid.is_none();
        let disarmed = provider_retired
            && (guardian_was_never_started
                || self
                    .guardian_control
                    .as_mut()
                    .is_some_and(|control| control.write_all(&[1]).is_ok()));
        drop(self.guardian_control.take());

        let guardian_reaped = self.guardian_pid.is_none_or(wait_pid);
        if guardian_reaped {
            self.guardian_pid = None;
        }
        let guardian_claim = if guardian_reaped && !disarmed {
            self.guardian_terminal.as_mut().and_then(|terminal| {
                read_guardian_terminal(terminal, Instant::now() + Duration::from_secs(1)).ok()
            })
        } else {
            None
        };
        let guardian_owned = guardian_claim.is_some_and(|claim| {
            verified_guardian_retirement(
                claim,
                GuardianTrigger::ProviderLoss,
                self.attempt_id,
                true,
            )
        });
        let provider_owned_after_frontend_loss = guardian_claim.is_some_and(|claim| {
            verified_guardian_retirement(
                claim,
                GuardianTrigger::FrontendLoss,
                self.attempt_id,
                false,
            )
        });
        let provider_owned_after_guardian_observed_absence = provider_retired
            && guardian_claim.is_some_and(|claim| {
                verified_guardian_observed_provider_retirement(claim, self.attempt_id)
            });
        let containment_retired = (provider_retired && disarmed)
            || guardian_owned
            || provider_owned_after_frontend_loss
            || provider_owned_after_guardian_observed_absence;
        if containment_retired {
            self.cgroup = None;
        }

        let init_reaped = self.init_pid.is_none_or(terminate_and_reap);
        if init_reaped {
            self.init_pid = None;
        }
        if !(containment_retired && init_reaped && guardian_reaped) {
            if guardian_reaped {
                let _ = self.record.transition("cleanup-incomplete");
            }
            return Err(
                "guardian/provider cleanup did not prove complete attempt retirement".to_owned(),
            );
        }

        if !guardian_owned {
            self.record.transition("retired-after-failure")?;
            self.record.clone().retire()?;
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for AttemptCleanupGuard {
    fn drop(&mut self) {
        let _ = self.finalize_failure();
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    FrontendLossBeforeAuthorization,
    FrontendLossAfterAuthorization,
    ProviderWorkerLossAfterGuardianCreation,
    GuardianLossBeforeAuthorization,
    GuardianLossAfterAuthorization,
    NamespaceInitFailureBeforeTarget,
    CgroupKillFailureAfterAuthorization,
    PersistentPopulatedAfterAuthorization,
    NamespaceInitReapDelayAfterAuthorization,
    GuardianReapFailureAfterAuthorization,
}

fn encode_guardian_terminal(claim: GuardianTerminalClaim) -> [u8; GUARDIAN_TERMINAL_RECORD_LENGTH] {
    let mut encoded = [0_u8; GUARDIAN_TERMINAL_RECORD_LENGTH];
    encoded[0] = GUARDIAN_TERMINAL_VERSION;
    encoded[1] = match claim.trigger {
        GuardianTrigger::FrontendLoss => 1,
        GuardianTrigger::ProviderLoss => 2,
    };
    if claim.cgroup_kill_invoked {
        encoded[2] |= GUARDIAN_KILL_INVOKED;
    }
    if claim.populated_zero_observed {
        encoded[2] |= GUARDIAN_POPULATED_ZERO;
    }
    if claim.containment_removed {
        encoded[2] |= GUARDIAN_CONTAINMENT_REMOVED;
    }
    if claim.record_retired {
        encoded[2] |= GUARDIAN_RECORD_RETIRED;
    }
    encoded[4..20].copy_from_slice(&claim.attempt_id);
    encoded
}

fn decode_guardian_terminal(encoded: &[u8]) -> Result<GuardianTerminalClaim, String> {
    if encoded.len() != GUARDIAN_TERMINAL_RECORD_LENGTH
        || encoded[0] != GUARDIAN_TERMINAL_VERSION
        || encoded[2] & !GUARDIAN_KNOWN_FLAGS != 0
        || encoded[3] != 0
        || encoded[20..].iter().any(|byte| *byte != 0)
    {
        return Err("MCSEALED-GUARDIAN-TERMINAL: invalid terminal record".to_owned());
    }
    let trigger = match encoded[1] {
        1 => GuardianTrigger::FrontendLoss,
        2 => GuardianTrigger::ProviderLoss,
        _ => return Err("MCSEALED-GUARDIAN-TERMINAL: invalid trigger".to_owned()),
    };
    let mut attempt_id = [0_u8; 16];
    attempt_id.copy_from_slice(&encoded[4..20]);
    let flags = encoded[2];
    let kill_invoked = flags & GUARDIAN_KILL_INVOKED != 0;
    let populated_zero_observed = flags & GUARDIAN_POPULATED_ZERO != 0;
    let containment_removed = flags & GUARDIAN_CONTAINMENT_REMOVED != 0;
    let record_retired = flags & GUARDIAN_RECORD_RETIRED != 0;
    let provider_absence_observed = trigger == GuardianTrigger::ProviderLoss
        && !kill_invoked
        && !populated_zero_observed
        && containment_removed
        && !record_retired;
    if (populated_zero_observed && !kill_invoked)
        || (containment_removed && !populated_zero_observed && !provider_absence_observed)
        || (record_retired && (trigger != GuardianTrigger::ProviderLoss || !containment_removed))
    {
        return Err("MCSEALED-GUARDIAN-TERMINAL: contradictory terminal facts".to_owned());
    }
    Ok(GuardianTerminalClaim {
        trigger,
        attempt_id,
        cgroup_kill_invoked: kill_invoked,
        populated_zero_observed,
        containment_removed,
        record_retired,
    })
}

#[cfg(feature = "test-support")]
pub fn encode_guardian_terminal_for_test(
    claim: GuardianTerminalClaim,
) -> [u8; GUARDIAN_TERMINAL_RECORD_LENGTH] {
    encode_guardian_terminal(claim)
}

#[cfg(feature = "test-support")]
pub fn decode_guardian_terminal_for_test(encoded: &[u8]) -> Result<GuardianTerminalClaim, String> {
    decode_guardian_terminal(encoded)
}

#[cfg(feature = "test-support")]
pub fn verified_guardian_observed_provider_retirement_for_test(
    claim: GuardianTerminalClaim,
    attempt_id: [u8; 16],
) -> bool {
    verified_guardian_observed_provider_retirement(claim, attempt_id)
}

fn read_guardian_terminal(
    reader: &mut File,
    deadline: Instant,
) -> Result<GuardianTerminalClaim, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
    let mut pollfd = libc::pollfd {
        fd: reader.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    // SAFETY: poll receives one initialized descriptor and a bounded timeout.
    let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
    if ready <= 0 || pollfd.revents & libc::POLLIN == 0 {
        return Err("MCSEALED-GUARDIAN-TERMINAL: terminal claim unavailable".to_owned());
    }
    let mut encoded = [0_u8; GUARDIAN_TERMINAL_RECORD_LENGTH];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| format!("MCSEALED-GUARDIAN-TERMINAL: {error}"))?;
    decode_guardian_terminal(&encoded)
}

fn verified_guardian_retirement(
    claim: GuardianTerminalClaim,
    trigger: GuardianTrigger,
    attempt_id: [u8; 16],
    record_retired: bool,
) -> bool {
    claim.trigger == trigger
        && claim.attempt_id == attempt_id
        && claim.cgroup_kill_invoked
        && claim.populated_zero_observed
        && claim.containment_removed
        && claim.record_retired == record_retired
}

fn verified_guardian_observed_provider_retirement(
    claim: GuardianTerminalClaim,
    attempt_id: [u8; 16],
) -> bool {
    claim.trigger == GuardianTrigger::ProviderLoss
        && claim.attempt_id == attempt_id
        && !claim.cgroup_kill_invoked
        && !claim.populated_zero_observed
        && claim.containment_removed
        && !claim.record_retired
}

fn retired_cleanup() -> RejectionCleanupV1 {
    RejectionCleanupV1 {
        attempted: true,
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        sealed_boundary_retired: true,
        errors: Vec::new(),
    }
}

fn rejection_for_launch_error(error: &str, attempt_id: [u8; 16]) -> RejectionV1 {
    let exact = if error.starts_with("MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION") {
        Some((
            "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION",
            RejectionPhaseV1::Authorization,
            false,
        ))
    } else if error.starts_with("MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION") {
        Some((
            "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION",
            RejectionPhaseV1::Authorization,
            false,
        ))
    } else if error.starts_with("MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION") {
        Some((
            "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION",
            RejectionPhaseV1::Monitoring,
            true,
        ))
    } else if error.starts_with("MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION") {
        Some((
            "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION",
            RejectionPhaseV1::Monitoring,
            true,
        ))
    } else {
        None
    };
    if let Some((code, phase, released)) = exact {
        return RejectionV1::from_launch_facts(
            code,
            phase,
            error,
            true,
            released,
            retired_cleanup(),
        )
        .unwrap_or_else(|failure| panic!("invalid internal loss receipt: {failure}"));
    }
    RejectionV1::from_launch_error(error, attempt_id)
}

#[cfg(feature = "test-support")]
fn fault_outcome(attempt_id: [u8; 16], point: FaultPoint, detail: &str) -> FaultExecutionOutcome {
    if !matches!(
        point,
        FaultPoint::FrontendLossBeforeAuthorization
            | FaultPoint::FrontendLossAfterAuthorization
            | FaultPoint::GuardianLossBeforeAuthorization
            | FaultPoint::GuardianLossAfterAuthorization
    ) {
        return FaultExecutionOutcome {
            attempt_id,
            rejection: rejection_for_launch_error(detail, attempt_id),
            retirement_owner: RetirementOwner::Provider,
        };
    }
    let (code, phase, released, owner) = match point {
        FaultPoint::FrontendLossBeforeAuthorization => (
            "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION",
            RejectionPhaseV1::Authorization,
            false,
            RetirementOwner::Guardian,
        ),
        FaultPoint::FrontendLossAfterAuthorization => (
            "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION",
            RejectionPhaseV1::Monitoring,
            true,
            RetirementOwner::Guardian,
        ),
        FaultPoint::GuardianLossBeforeAuthorization => (
            "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION",
            RejectionPhaseV1::Authorization,
            false,
            RetirementOwner::Provider,
        ),
        FaultPoint::GuardianLossAfterAuthorization => (
            "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION",
            RejectionPhaseV1::Monitoring,
            true,
            RetirementOwner::Provider,
        ),
        _ => unreachable!("loss variants were exhaustively selected"),
    };
    if !detail.starts_with(code) {
        return FaultExecutionOutcome {
            attempt_id,
            rejection: rejection_for_launch_error(detail, attempt_id),
            retirement_owner: RetirementOwner::Provider,
        };
    }
    FaultExecutionOutcome {
        attempt_id,
        rejection: RejectionV1::from_launch_facts(
            code,
            phase,
            detail,
            true,
            released,
            retired_cleanup(),
        )
        .unwrap_or_else(|failure| panic!("invalid internal fault receipt: {failure}")),
        retirement_owner: owner,
    }
}

#[cfg(feature = "test-support")]
fn wait_for_fault_ready(ready: &FaultReady, deadline: Instant) -> Result<(), String> {
    if ready.expected.is_empty() || ready.expected.len() > 4096 {
        return Err("MCSEALED-FAULT-READY: invalid expected marker bound".to_owned());
    }
    loop {
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&ready.path)
        {
            Ok(mut file) => {
                let length = usize::try_from(
                    file.metadata()
                        .map_err(|error| format!("MCSEALED-FAULT-READY: {error}"))?
                        .len(),
                )
                .map_err(|_| "MCSEALED-FAULT-READY: marker length overflow".to_owned())?;
                if length == ready.expected.len() {
                    let mut observed = vec![0_u8; length];
                    file.read_exact(&mut observed)
                        .map_err(|error| format!("MCSEALED-FAULT-READY: {error}"))?;
                    if observed == ready.expected {
                        return Ok(());
                    }
                    return Err("MCSEALED-FAULT-READY: marker bytes differed".to_owned());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("MCSEALED-FAULT-READY: {error}")),
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-FAULT-READY: marker deadline expired".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(feature = "test-support")]
fn persist_guardian_claim_for_test(path: &std::path::Path, encoded: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("MCSEALED-GUARDIAN-TERMINAL: {error}"))?;
    file.write_all(encoded)
        .map_err(|error| format!("MCSEALED-GUARDIAN-TERMINAL: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("MCSEALED-GUARDIAN-TERMINAL: {error}"))
}

pub fn execute(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    attempt: [u8; 16],
    frontend_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
) -> Result<TerminalFacts, String> {
    execute_inner(
        request,
        descriptors,
        attempt,
        frontend_pid,
        uid,
        gid,
        groups,
        None,
        None,
        None,
    )
}

pub fn execute_typed(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    attempt: [u8; 16],
    frontend_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
) -> Result<TerminalFacts, RejectionV1> {
    execute(
        request,
        descriptors,
        attempt,
        frontend_pid,
        uid,
        gid,
        groups,
    )
    .map_err(|error| rejection_for_launch_error(&error, attempt))
}

#[cfg(feature = "test-support")]
#[allow(clippy::too_many_arguments)]
pub fn execute_with_fault(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    attempt: [u8; 16],
    frontend_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    fault: FaultPoint,
) -> Result<TerminalFacts, String> {
    execute_inner(
        request,
        descriptors,
        attempt,
        frontend_pid,
        uid,
        gid,
        groups,
        Some(fault),
        None,
        None,
    )
}

#[cfg(feature = "test-support")]
#[allow(clippy::too_many_arguments)]
pub fn execute_with_fault_typed(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    attempt: [u8; 16],
    frontend_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    plan: FaultPlan,
) -> Result<TerminalFacts, FaultExecutionOutcome> {
    let point = plan.point;
    execute_inner(
        request,
        descriptors,
        attempt,
        frontend_pid,
        uid,
        gid,
        groups,
        Some(point),
        plan.postauthorization_ready,
        plan.provider_loss_claim_path,
    )
    .map_err(|detail| fault_outcome(attempt, point, &detail))
}

#[allow(clippy::too_many_arguments)]
fn execute_inner(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    attempt: [u8; 16],
    frontend_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    #[cfg(feature = "test-support")] fault: Option<FaultPoint>,
    #[cfg(not(feature = "test-support"))] _fault: Option<()>,
    #[cfg(feature = "test-support")] postauthorization_ready: Option<FaultReady>,
    #[cfg(not(feature = "test-support"))] _postauthorization_ready: Option<()>,
    #[cfg(feature = "test-support")] provider_loss_claim_path: Option<PathBuf>,
    #[cfg(not(feature = "test-support"))] _provider_loss_claim_path: Option<()>,
) -> Result<TerminalFacts, String> {
    let started = Instant::now();
    if descriptors.len() != 5 {
        return Err(
            "MCSEALED-LAUNCH-DESCRIPTOR-SET: exact descriptor inventory required".to_owned(),
        );
    }
    let identity = attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record = AttemptRecord::create(identity.clone(), frontend_pid)
        .map_err(|error| format!("MCSEALED-RECORD-ALLOCATE: {error}"))?;
    let mut cleanup_guard = AttemptCleanupGuard::new(record.clone(), attempt);
    let cgroup = AttemptCgroup::create(
        &identity,
        request.policy.memory_limit_bytes,
        request.policy.swap_limit,
    )?;
    cleanup_guard.set_cgroup(cgroup.clone());
    let monitoring_policy = request.policy.clone();
    record
        .transition("boundary-created")
        .map_err(|error| format!("MCSEALED-RECORD-BOUNDARY: {error}"))?;
    let (target_control, mut provider_control) =
        control_socketpair().map_err(|error| format!("MCSEALED-TARGET-CONTROL: {error}"))?;
    let target_control_inode = descriptor_inode(&target_control)
        .map_err(|error| format!("MCSEALED-TARGET-CONTROL: {error}"))?;
    let (mut status_read, status_write) =
        pipe().map_err(|error| format!("MCSEALED-TARGET-STATUS: {error}"))?;
    let (namespace_startup, init_startup) =
        control_socketpair().map_err(|error| format!("MCSEALED-NAMESPACE-INIT-STATUS: {error}"))?;
    let frontend_pidfd =
        duplicate(&descriptors[4]).map_err(|error| format!("MCSEALED-FRONTEND-PIDFD: {error}"))?;
    let cgroup_file = cgroup
        .open()
        .map_err(|error| format!("MCSEALED-CGROUP-OPEN: {error}"))?;
    let target_credentials = TargetCredentials { uid, gid, groups };
    let expected_credentials = target_credentials.clone();
    let provider_control_fd = provider_control.as_raw_fd();
    let provider_startup_fd = namespace_startup.as_raw_fd();
    #[cfg(feature = "test-support")]
    let inject_namespace_init_failure = fault == Some(FaultPoint::NamespaceInitFailureBeforeTarget);
    #[cfg(not(feature = "test-support"))]
    let inject_namespace_init_failure = false;
    let init = super::namespace::clone_into_cgroup(&cgroup_file, move || {
        namespace_init(
            request,
            descriptors,
            target_control,
            provider_control_fd,
            status_write,
            target_credentials,
            NamespaceStartupChannel {
                init: init_startup,
                provider_fd: provider_startup_fd,
                inject_failure_before_target: inject_namespace_init_failure,
            },
        )
    })?;
    cleanup_guard.init_pid = Some(init.host_pid);
    let (mut guardian_read, guardian_write) =
        pipe().map_err(|error| format!("MCSEALED-GUARDIAN-CONTROL: {error}"))?;
    let (mut guardian_ready_read, mut guardian_ready_write) =
        pipe().map_err(|error| format!("MCSEALED-GUARDIAN-READY: {error}"))?;
    let (guardian_terminal_read, mut guardian_terminal_write) =
        pipe().map_err(|error| format!("MCSEALED-GUARDIAN-TERMINAL: {error}"))?;
    let guardian_cgroup = cgroup.clone();
    let guardian_record = record.clone();
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let guardian_pid = unsafe { libc::fork() };
    if guardian_pid == -1 {
        return Err(format!(
            "MCSEALED-GUARDIAN: {}",
            std::io::Error::last_os_error()
        ));
    }
    if guardian_pid == 0 {
        drop(guardian_write);
        drop(guardian_ready_read);
        drop(guardian_terminal_read);
        let mut pollfds = [
            libc::pollfd {
                fd: frontend_pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: guardian_read.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
        ];
        if guardian_ready_write.write_all(&[1]).is_err() {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::_exit(125) };
        }
        drop(guardian_ready_write);
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let ready_count = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, -1) };
        let disarmed = if ready_count > 0 && pollfds[1].revents & libc::POLLIN != 0 {
            let mut byte = [0_u8; 1];
            guardian_read.read_exact(&mut byte).is_ok() && byte[0] == 1
        } else {
            false
        };
        if disarmed {
            // SAFETY: this fork child owns no Rust runtime state that may be unwound.
            unsafe { libc::_exit(0) };
        }
        let trigger = if ready_count > 0 && pollfds[0].revents & libc::POLLIN != 0 {
            GuardianTrigger::FrontendLoss
        } else {
            GuardianTrigger::ProviderLoss
        };
        let retirement = if trigger == GuardianTrigger::ProviderLoss {
            guardian_cgroup
                .kill_and_retire_after_provider_loss(Instant::now() + Duration::from_secs(30))
                .ok()
        } else {
            guardian_cgroup
                .kill_and_retire(Instant::now() + Duration::from_secs(30))
                .ok()
                .map(|()| AttemptRetirementObservation {
                    cgroup_kill_invoked: true,
                    populated_zero_observed: true,
                    containment_removed: true,
                })
        };
        let retirement = retirement.unwrap_or(AttemptRetirementObservation {
            cgroup_kill_invoked: false,
            populated_zero_observed: false,
            containment_removed: false,
        });
        let strict_retirement = retirement.cgroup_kill_invoked
            && retirement.populated_zero_observed
            && retirement.containment_removed;
        let record_retired = if trigger == GuardianTrigger::ProviderLoss && strict_retirement {
            guardian_record.transition("retired-by-guardian").is_ok()
                && guardian_record.retire().is_ok()
        } else {
            false
        };
        let claim = GuardianTerminalClaim {
            trigger,
            attempt_id: attempt,
            cgroup_kill_invoked: retirement.cgroup_kill_invoked,
            populated_zero_observed: retirement.populated_zero_observed,
            containment_removed: retirement.containment_removed,
            record_retired,
        };
        let encoded_claim = encode_guardian_terminal(claim);
        #[cfg(feature = "test-support")]
        if trigger == GuardianTrigger::ProviderLoss {
            if let Some(path) = provider_loss_claim_path.as_ref() {
                let _ = persist_guardian_claim_for_test(path, &encoded_claim);
            }
        }
        let _ = guardian_terminal_write.write_all(&encoded_claim);
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(i32::from(!retirement.containment_removed)) };
    }
    cleanup_guard.guardian_pid = Some(guardian_pid);
    cleanup_guard.set_guardian_channels(guardian_write, guardian_terminal_read);
    drop(guardian_read);
    drop(guardian_ready_write);
    drop(guardian_terminal_write);
    let outcome = (|| -> Result<TerminalFacts, String> {
        let mut ready = [0_u8; 1];
        guardian_ready_read
            .read_exact(&mut ready)
            .map_err(|error| format!("MCSEALED-GUARDIAN: {error}"))?;
        let guardian_membership = cgroup
            .member_pids()
            .map_err(|error| format!("MCSEALED-GUARDIAN-PLACEMENT: {error}"))?;
        if ready != [1] || guardian_membership.contains(&guardian_pid) {
            return Err(
                "MCSEALED-GUARDIAN: guardian readiness or placement verification failed".to_owned(),
            );
        }
        drop(guardian_ready_read);
        record
            .transition("guardian-ready")
            .map_err(|error| format!("MCSEALED-RECORD-GUARDIAN: {error}"))?;
        #[cfg(feature = "test-support")]
        if fault == Some(FaultPoint::ProviderWorkerLossAfterGuardianCreation) {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::_exit(86) };
        }
        let target_pid = wait_for_target(
            &cgroup,
            init.host_pid,
            &init.pidfd,
            &namespace_startup,
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(|error| {
            if error.starts_with("MCSEALED-") {
                error
            } else {
                format!("MCSEALED-TARGET-WAIT: {error}")
            }
        })?;
        let target_pidfd = pidfd_open(target_pid)?;
        record
            .transition("target-created-gated")
            .map_err(|error| format!("MCSEALED-RECORD-TARGET: {error}"))?;
        verify_gated_target(
            target_pid,
            init.host_pid,
            &identity,
            expected_credentials.uid,
            expected_credentials.gid,
            &expected_credentials.groups,
            target_control_inode,
        )?;
        record
            .transition("assignment-verified")
            .map_err(|error| format!("MCSEALED-RECORD-ASSIGNMENT: {error}"))?;
        record
            .transition("resource-inheritance-verified")
            .map_err(|error| format!("MCSEALED-RECORD-RESOURCE: {error}"))?;
        #[cfg(feature = "test-support")]
        if matches!(
            fault,
            Some(FaultPoint::FrontendLossBeforeAuthorization)
                | Some(FaultPoint::GuardianLossBeforeAuthorization)
        ) {
            let frontend_loss = fault == Some(FaultPoint::FrontendLossBeforeAuthorization);
            if frontend_loss {
                signal_pidfd(&frontend_pidfd, libc::SIGKILL)?;
            } else {
                // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
                unsafe { libc::kill(guardian_pid, libc::SIGKILL) };
            }
            drop(provider_control);
            let boundary_retired = if frontend_loss {
                let claim = read_guardian_terminal(
                    cleanup_guard
                        .guardian_terminal
                        .as_mut()
                        .expect("guardian terminal channel remains lifecycle-owned"),
                    Instant::now() + Duration::from_secs(30),
                )?;
                verified_guardian_retirement(claim, GuardianTrigger::FrontendLoss, attempt, false)
                    && fault_boundary_retired(&identity)
            } else {
                cgroup
                    .clone()
                    .kill_and_retire(Instant::now() + Duration::from_secs(30))
                    .is_ok()
            };
            if boundary_retired {
                cleanup_guard.cgroup = None;
            }
            let init_reaped = wait_pid(init.host_pid);
            if init_reaped {
                cleanup_guard.init_pid = None;
            }
            let guardian_reaped = wait_pid(guardian_pid);
            if guardian_reaped {
                cleanup_guard.guardian_pid = None;
            }
            if !(boundary_retired && init_reaped && guardian_reaped) {
                return Err("MCSEALED-BOUNDARY-NOT-RETIRED: preauthorization loss".to_owned());
            }
            record.transition("retired")?;
            record.clone().retire()?;
            cleanup_guard.disarm();
            return Err(if frontend_loss {
                "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION: authenticated guardian retirement"
                    .to_owned()
            } else {
                "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION: provider retirement".to_owned()
            });
        }
        if let Some(deadline) = monitoring_policy.absolute_deadline_millis {
            let now = super::clock::monotonic_millis()
                .map_err(|error| format!("MCSEALED-AUTHORIZATION-CLOCK: {error}"))?;
            if now >= deadline {
                return Err("MCSEALED-AUTHORIZATION: deadline expired before authorization; target was not authorized".to_owned());
            }
        }
        provider_control
            .write_all(&[1])
            .map_err(|error| format!("MCSEALED-AUTHORIZATION: {error}"))?;
        let authorization_offset_millis = started.elapsed().as_millis() as u64;
        record
            .transition("authorized")
            .map_err(|error| format!("MCSEALED-AUTHORIZATION-RECORD: {error}"))?;
        #[cfg(feature = "test-support")]
        if matches!(
            fault,
            Some(FaultPoint::FrontendLossAfterAuthorization)
                | Some(FaultPoint::GuardianLossAfterAuthorization)
        ) {
            if let Some(ready) = postauthorization_ready.as_ref() {
                wait_for_fault_ready(ready, Instant::now() + Duration::from_secs(5))?;
            }
            let frontend_loss = fault == Some(FaultPoint::FrontendLossAfterAuthorization);
            if frontend_loss {
                signal_pidfd(&frontend_pidfd, libc::SIGKILL)?;
            } else {
                // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
                unsafe { libc::kill(guardian_pid, libc::SIGKILL) };
            }
            let boundary_retired = if frontend_loss {
                let claim = read_guardian_terminal(
                    cleanup_guard
                        .guardian_terminal
                        .as_mut()
                        .expect("guardian terminal channel remains lifecycle-owned"),
                    Instant::now() + Duration::from_secs(30),
                )?;
                verified_guardian_retirement(claim, GuardianTrigger::FrontendLoss, attempt, false)
                    && fault_boundary_retired(&identity)
            } else {
                cgroup
                    .clone()
                    .kill_and_retire(Instant::now() + Duration::from_secs(30))
                    .is_ok()
            };
            if boundary_retired {
                cleanup_guard.cgroup = None;
            }
            let init_reaped = wait_pid(init.host_pid);
            if init_reaped {
                cleanup_guard.init_pid = None;
            }
            let guardian_reaped = wait_pid(guardian_pid);
            if guardian_reaped {
                cleanup_guard.guardian_pid = None;
            }
            if !(boundary_retired && init_reaped && guardian_reaped) {
                return Err("MCSEALED-BOUNDARY-NOT-RETIRED: postauthorization loss".to_owned());
            }
            record.transition("retired")?;
            record.clone().retire()?;
            cleanup_guard.disarm();
            return Err(if frontend_loss {
                "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION: authenticated guardian retirement"
                    .to_owned()
            } else {
                "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION: provider retirement".to_owned()
            });
        }
        #[cfg(feature = "test-support")]
        if matches!(
            fault,
            Some(FaultPoint::CgroupKillFailureAfterAuthorization)
                | Some(FaultPoint::PersistentPopulatedAfterAuthorization)
                | Some(FaultPoint::NamespaceInitReapDelayAfterAuthorization)
                | Some(FaultPoint::GuardianReapFailureAfterAuthorization)
        ) {
            let ready = postauthorization_ready.as_ref().ok_or_else(|| {
                "MCSEALED-FAULT-READY: retirement fault omitted target rendezvous".to_owned()
            })?;
            wait_for_fault_ready(ready, Instant::now() + Duration::from_secs(5))?;
            let detail = match fault.expect("retirement fault was matched") {
                FaultPoint::CgroupKillFailureAfterAuthorization => {
                    if !cgroup.member_pids()?.contains(&target_pid) {
                        return Err(
                            "MCSEALED-CGROUP-KILL-FAILURE: live target membership was not observed"
                                .to_owned(),
                        );
                    }
                    "MCSEALED-CGROUP-KILL-FAILURE: injected native cgroup.kill failure"
                }
                FaultPoint::PersistentPopulatedAfterAuthorization => {
                    if cgroup.member_pids()?.is_empty() {
                        return Err(
                        "MCSEALED-CGROUP-NOT-EMPTY: populated-state injection had no live member"
                            .to_owned(),
                    );
                    }
                    "MCSEALED-CGROUP-NOT-EMPTY: injected persistent populated state"
                }
                FaultPoint::NamespaceInitReapDelayAfterAuthorization => {
                    if pidfd_has_exited(&init.pidfd)? {
                        return Err(
                        "MCSEALED-NAMESPACE-INIT-REAP-DELAY: namespace init exited before fault observation"
                            .to_owned(),
                    );
                    }
                    "MCSEALED-NAMESPACE-INIT-REAP-DELAY: live namespace init blocked terminal proof"
                }
                FaultPoint::GuardianReapFailureAfterAuthorization => {
                    let mut status = 0;
                    // SAFETY: guardian_pid is a live direct child and status points to initialized storage.
                    let observed =
                        unsafe { libc::waitpid(guardian_pid, &raw mut status, libc::WNOHANG) };
                    if observed != 0 {
                        return Err(
                        "MCSEALED-GUARDIAN-REAP-FAILURE: guardian was not live at fault observation"
                            .to_owned(),
                    );
                    }
                    "MCSEALED-GUARDIAN-REAP-FAILURE: live guardian blocked terminal proof"
                }
                _ => unreachable!("retirement fault variants were exhaustively selected"),
            };
            let disarm_result = cleanup_guard
                .guardian_control
                .as_mut()
                .expect("guardian control channel remains lifecycle-owned")
                .write_all(&[1]);
            drop(cleanup_guard.guardian_control.take());
            let guardian_reaped = wait_pid(guardian_pid);
            if guardian_reaped {
                cleanup_guard.guardian_pid = None;
            }
            let boundary_retired = cgroup
                .clone()
                .kill_and_retire(Instant::now() + Duration::from_secs(30))
                .is_ok();
            if boundary_retired {
                cleanup_guard.cgroup = None;
            }
            let init_reaped = wait_pid(init.host_pid);
            if init_reaped {
                cleanup_guard.init_pid = None;
            }
            if disarm_result.is_err() || !(guardian_reaped && boundary_retired && init_reaped) {
                return Err(format!("{detail}; fallback retirement was incomplete"));
            }
            record.transition("retired")?;
            record.clone().retire()?;
            cleanup_guard.disarm();
            return Err(detail.to_owned());
        }
        let exec_status_deadline = exec_status_deadline(&monitoring_policy)?;
        let exec_status = receive_exec_status(&mut provider_control, exec_status_deadline)?;
        drop(provider_control);
        let mut deadline_exceeded = false;
        let mut status = [0_u8; 4];
        loop {
            let mut pollfd = libc::pollfd {
                fd: status_read.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            let ready = unsafe {
                libc::poll(
                    &raw mut pollfd,
                    1,
                    i32::try_from(monitoring_policy.poll_interval_millis.max(1))
                        .unwrap_or(i32::MAX),
                )
            };
            if ready == -1 {
                return Err(format!(
                    "MCSEALED-MONITOR-POLL: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if ready > 0 {
                break;
            }
            if let Some(deadline) = monitoring_policy.absolute_deadline_millis {
                let now = super::clock::monotonic_millis()
                    .map_err(|error| format!("MCSEALED-MONITOR-CLOCK: {error}"))?;
                if now >= deadline {
                    deadline_exceeded = true;
                    break;
                }
            }
        }
        let child_status = if deadline_exceeded {
            125
        } else {
            status_read
                .read_exact(&mut status)
                .map_err(|error| format!("MCSEALED-MONITOR-STATUS: {error}"))?;
            i32::from_be_bytes(status)
        };
        let memory_limit_exceeded = cgroup
            .memory_oom_killed()
            .map_err(|error| format!("MCSEALED-MEMORY-READBACK: {error}"))?;
        if !deadline_exceeded
            && !memory_limit_exceeded
            && monitoring_policy.lifetime == crate::request::Lifetime::Command
            && monitoring_policy.command_exit_grace_millis > 0
        {
            deadline_exceeded = wait_command_exit_grace(&cgroup, &monitoring_policy)?;
        }
        if deadline_exceeded || memory_limit_exceeded {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    target_pidfd.as_raw_fd(),
                    libc::SIGTERM,
                    0,
                    0,
                )
            };
            let grace = if memory_limit_exceeded {
                monitoring_policy.limit_grace_millis
            } else {
                monitoring_policy.signal_grace_millis
            };
            if grace > 0 {
                std::thread::sleep(Duration::from_millis(grace));
            }
        }
        let provider_retired = cgroup
            .clone()
            .kill_and_retire(Instant::now() + Duration::from_secs(30))
            .is_ok();
        let disarm_result = cleanup_guard
            .guardian_control
            .as_mut()
            .expect("guardian control channel remains lifecycle-owned")
            .write_all(&[1]);
        drop(cleanup_guard.guardian_control.take());
        let guardian_reaped = wait_pid(guardian_pid);
        if guardian_reaped {
            cleanup_guard.guardian_pid = None;
        }
        let guardian_claim = read_guardian_terminal(
            cleanup_guard
                .guardian_terminal
                .as_mut()
                .expect("guardian terminal channel remains lifecycle-owned"),
            Instant::now(),
        )
        .ok();
        let guardian_retired = guardian_claim.is_some_and(|claim| {
            verified_guardian_retirement(claim, GuardianTrigger::FrontendLoss, attempt, false)
                && fault_boundary_retired(&identity)
        });
        let frontend_loss_observed = guardian_claim.is_some_and(|claim| {
            claim.trigger == GuardianTrigger::FrontendLoss && claim.attempt_id == attempt
        });
        if disarm_result.is_err() && !(provider_retired || guardian_retired) {
            return Err(
                "MCSEALED-GUARDIAN-DISARM: guardian did not authenticate retirement".to_owned(),
            );
        }
        let cgroup_empty = provider_retired || guardian_retired;
        if cgroup_empty {
            cleanup_guard.cgroup = None;
        }
        let init_reaped = wait_pid(init.host_pid);
        if init_reaped {
            cleanup_guard.init_pid = None;
        }
        if !(cgroup_empty && init_reaped && guardian_reaped) {
            return Err("MCSEALED-BOUNDARY-NOT-RETIRED: incomplete terminal proof".to_owned());
        }
        record
            .transition("retired")
            .map_err(|error| format!("MCSEALED-BOUNDARY-NOT-RETIRED: {error}"))?;
        record
            .retire()
            .map_err(|error| format!("MCSEALED-BOUNDARY-NOT-RETIRED: {error}"))?;
        cleanup_guard.disarm();
        if frontend_loss_observed {
            return Err(
            "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION: authenticated loss with complete retirement"
                .to_owned(),
        );
        }
        Ok(TerminalFacts {
            child_status,
            exec_status,
            spawn_error_reported: true,
            target_pid: target_pid as u32,
            authorization_offset_millis,
            cgroup_empty,
            init_reaped,
            guardian_reaped,
            boundary_retired: true,
            assignment_verified: true,
            namespaces_verified: true,
            credentials_verified: true,
            capabilities_empty: true,
            descriptors_verified: true,
            cgroup_view_denied: true,
            guardian_ready_before_authorization: true,
            frontend_loss_authority_verified: true,
            cgroup_kill_invoked: true,
            memory_limit_exceeded,
            deadline_exceeded,
        })
    })();
    match outcome {
        Ok(facts) => Ok(facts),
        Err(error) => match cleanup_guard.finalize_failure() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "MCSEALED-BOUNDARY-NOT-RETIRED: primary={error}; cleanup={cleanup}"
            )),
        },
    }
}

fn wait_command_exit_grace(
    cgroup: &AttemptCgroup,
    policy: &crate::request::LaunchPolicyV1,
) -> Result<bool, String> {
    let grace = Duration::from_millis(policy.command_exit_grace_millis);
    let started = Instant::now();
    let mut wait_deadline = started
        .checked_add(grace)
        .ok_or_else(|| "MCSEALED-COMMAND-EXIT-GRACE: grace deadline overflow".to_owned())?;
    let mut attempt_deadline_is_bound = false;
    if let Some(absolute_deadline) = policy.absolute_deadline_millis {
        let now = super::clock::monotonic_millis()
            .map_err(|error| format!("MCSEALED-COMMAND-EXIT-GRACE-CLOCK: {error}"))?;
        if now >= absolute_deadline {
            return Ok(true);
        }
        let remaining = Duration::from_millis(absolute_deadline - now);
        if remaining <= grace {
            wait_deadline = started.checked_add(remaining).ok_or_else(|| {
                "MCSEALED-COMMAND-EXIT-GRACE: attempt deadline overflow".to_owned()
            })?;
            attempt_deadline_is_bound = true;
        }
    }
    let emptied = cgroup
        .wait_until_empty(
            wait_deadline,
            Duration::from_millis(policy.poll_interval_millis.max(1)),
        )
        .map_err(|error| format!("MCSEALED-COMMAND-EXIT-GRACE: {error}"))?;
    Ok(!emptied && attempt_deadline_is_bound)
}

#[cfg(feature = "test-support")]
pub fn wait_command_exit_grace_for_test(
    cgroup: &AttemptCgroup,
    policy: &crate::request::LaunchPolicyV1,
) -> Result<bool, String> {
    wait_command_exit_grace(cgroup, policy)
}

fn namespace_init(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    control: File,
    provider_control_fd: i32,
    mut status: File,
    credentials: TargetCredentials,
    startup: NamespaceStartupChannel,
) -> i32 {
    let NamespaceStartupChannel {
        init: startup,
        provider_fd: provider_startup_fd,
        inject_failure_before_target,
    } = startup;
    // SAFETY: this namespace-init child inherited a duplicate of the provider endpoint during
    // clone3. It never owns that endpoint logically, and closing only its local descriptor copy
    // ensures peer EOF reflects the gated target endpoint rather than an init-held reference.
    unsafe { libc::close(provider_control_fd) };
    // SAFETY: this namespace-init child likewise inherited the provider side of its startup
    // channel. Closing only the local duplicate makes EOF and packet provenance attempt-local.
    unsafe { libc::close(provider_startup_fd) };
    if inject_failure_before_target {
        let error = super::namespace::NamespaceInitError {
            phase: super::namespace::NamespaceInitPhase::TargetFork,
            os_code: libc::EAGAIN,
        };
        let _ = report_namespace_startup(&startup, NamespaceStartupStatus::Failed(error));
        return 125;
    }
    if let Err(error) = super::namespace::prepare_namespace_init() {
        let _ = report_namespace_startup(&startup, NamespaceStartupStatus::Failed(error));
        return 125;
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let target = unsafe { libc::fork() };
    if target == -1 {
        let error = super::namespace::NamespaceInitError::last(
            super::namespace::NamespaceInitPhase::TargetFork,
        );
        let _ = report_namespace_startup(&startup, NamespaceStartupStatus::Failed(error));
        return 125;
    }
    if target == 0 {
        drop(startup);
        target_exec(
            request,
            descriptors,
            control,
            status.as_raw_fd(),
            credentials,
        );
    }
    if report_namespace_startup(&startup, NamespaceStartupStatus::TargetForked).is_err() {
        return 125;
    }
    drop(startup);
    drop(control);
    drop(descriptors);
    let mut raw = 0_i32;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::waitpid(target, &raw mut raw, 0) } == -1 {
        return 125;
    }
    if request.policy.lifetime == crate::request::Lifetime::Workload {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } > 0 {}
    } else {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
    }
    let code = if libc::WIFEXITED(raw) {
        libc::WEXITSTATUS(raw)
    } else {
        128 + libc::WTERMSIG(raw)
    };
    let _ = status.write_all(&code.to_be_bytes());
    0
}

fn target_exec(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    control: File,
    status_fd: i32,
    credentials: TargetCredentials,
) -> ! {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::fchdir(descriptors[0].as_raw_fd()) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    for (source, target) in descriptors[1..4].iter().zip(0..3) {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        if unsafe { libc::dup2(source.as_raw_fd(), target) } == -1 {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::_exit(125) };
        }
    }
    drop(descriptors);
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    unsafe { libc::close(status_fd) };
    let control_fd = control.as_raw_fd();
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if control_fd != 3 && unsafe { libc::dup3(control_fd, 3, libc::O_CLOEXEC) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    if control_fd != 3 {
        drop(control);
    } else {
        std::mem::forget(control);
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let mut control = unsafe { File::from_raw_fd(3) };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::setgroups(credentials.groups.len(), credentials.groups.as_ptr()) } == -1
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        || unsafe { libc::setresgid(credentials.gid, credentials.gid, credentials.gid) } == -1
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        || unsafe { libc::setresuid(credentials.uid, credentials.uid, credentials.uid) } == -1
    {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } == -1
        || clear_capabilities().is_err()
    {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    let mut command = Command::new(OsString::from_vec(request.program));
    command.args(request.arguments.into_iter().map(OsString::from_vec));
    command.env_clear();
    for (name, value) in request.environment {
        command.env(OsString::from_vec(name), OsString::from_vec(value));
    }
    let mut authorization = [0_u8; 1];
    if control.read_exact(&mut authorization).is_err() || authorization != [1] {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    if control.write_all(&EXEC_CONTROL_ARMED).is_err() {
        // SAFETY: the provider cannot prove that the target reached the exec boundary, so this
        // single-threaded target terminates without invoking caller code; cleanup remains owned by
        // namespace init, the provider cleanup guard, and the external guardian.
        unsafe { libc::_exit(125) };
    }
    let error = command.exec();
    let os_code = error.raw_os_error().unwrap_or(0);
    let class = classify_exec_error(os_code);
    let record = encode_exec_failure(class, os_code);
    let reported = control.write_all(&record).is_ok();
    let code = exec_failure_exit_code(class);
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    unsafe { libc::_exit(if reported { code } else { 125 }) }
}

fn clear_capabilities() -> Result<(), ()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) } == -1 {
        Err(())
    } else {
        Ok(())
    }
}

fn classify_exec_error(os_code: i32) -> ExecFailureClass {
    match os_code {
        libc::ENOENT | libc::ENOTDIR => ExecFailureClass::NotFound,
        libc::EACCES | libc::EPERM | libc::ENOEXEC | libc::EISDIR => {
            ExecFailureClass::NotExecutable
        }
        _ => ExecFailureClass::Other,
    }
}

const fn exec_failure_exit_code(class: ExecFailureClass) -> i32 {
    match class {
        ExecFailureClass::NotFound => 127,
        ExecFailureClass::NotExecutable | ExecFailureClass::Other => 126,
    }
}

fn encode_exec_failure(class: ExecFailureClass, os_code: i32) -> [u8; EXEC_FAILURE_RECORD_LENGTH] {
    let class = match class {
        ExecFailureClass::NotFound => 1,
        ExecFailureClass::NotExecutable => 2,
        ExecFailureClass::Other => 3,
    };
    let bytes = os_code.to_be_bytes();
    [
        EXEC_CONTROL_VERSION,
        EXEC_CONTROL_FAILURE_KIND,
        EXEC_CONTROL_TARGET_EXEC_PHASE,
        class,
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
    ]
}

fn decode_exec_failure(
    record: [u8; EXEC_FAILURE_RECORD_LENGTH],
) -> Result<TargetExecStatus, String> {
    if record[0] != EXEC_CONTROL_VERSION
        || record[1] != EXEC_CONTROL_FAILURE_KIND
        || record[2] != EXEC_CONTROL_TARGET_EXEC_PHASE
    {
        return Err("MCSEALED-TARGET-EXEC-STATUS: invalid record header".to_owned());
    }
    let os_code = i32::from_be_bytes([record[4], record[5], record[6], record[7]]);
    if os_code <= 0 {
        return Err("MCSEALED-TARGET-EXEC-STATUS: native errno missing".to_owned());
    }
    let class = match record[3] {
        1 => ExecFailureClass::NotFound,
        2 => ExecFailureClass::NotExecutable,
        3 => ExecFailureClass::Other,
        _ => return Err("MCSEALED-TARGET-EXEC-STATUS: invalid failure class".to_owned()),
    };
    if classify_exec_error(os_code) != class {
        return Err("MCSEALED-TARGET-EXEC-STATUS: errno classification mismatch".to_owned());
    }
    Ok(TargetExecStatus::Failed { class, os_code })
}

fn exec_status_deadline(policy: &crate::request::LaunchPolicyV1) -> Result<Instant, String> {
    let mut remaining = EXEC_STATUS_TIMEOUT;
    if let Some(deadline) = policy.absolute_deadline_millis {
        let now = super::clock::monotonic_millis()
            .map_err(|error| format!("MCSEALED-TARGET-EXEC-STATUS-CLOCK: {error}"))?;
        if now >= deadline {
            return Err(
                "MCSEALED-TARGET-EXEC-STATUS: deadline expired before exec result".to_owned(),
            );
        }
        remaining = remaining.min(Duration::from_millis(deadline - now));
    }
    Ok(Instant::now() + remaining)
}

fn receive_exec_status(control: &mut File, deadline: Instant) -> Result<TargetExecStatus, String> {
    let armed = read_control_packet(control, deadline)?.ok_or_else(|| {
        "MCSEALED-TARGET-EXEC-STATUS: target closed before armed record".to_owned()
    })?;
    if armed.as_slice() != EXEC_CONTROL_ARMED {
        return Err("MCSEALED-TARGET-EXEC-STATUS: invalid armed record".to_owned());
    }
    match read_control_packet(control, deadline)? {
        None => Ok(TargetExecStatus::Succeeded),
        Some(bytes) => {
            let record: [u8; EXEC_FAILURE_RECORD_LENGTH] = bytes.try_into().map_err(|_| {
                "MCSEALED-TARGET-EXEC-STATUS: failure record length mismatch".to_owned()
            })?;
            let status = decode_exec_failure(record)?;
            if read_control_packet(control, deadline)?.is_some() {
                return Err("MCSEALED-TARGET-EXEC-STATUS: trailing record".to_owned());
            }
            Ok(status)
        }
    }
}

fn read_control_packet(control: &File, deadline: Instant) -> Result<Option<Vec<u8>>, String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("MCSEALED-TARGET-EXEC-STATUS: timed out".to_owned());
        }
        let remaining = deadline.saturating_duration_since(now);
        let timeout = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        let mut pollfd = libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: poll receives a live pointer to one initialized pollfd for the synchronous call;
        // the descriptor is borrowed from `control`, and the bounded timeout prevents an
        // unresponsive target from extending provider authorization indefinitely.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if ready == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("MCSEALED-TARGET-EXEC-STATUS: {error}"));
        }
        if ready == 0 {
            continue;
        }
        if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("MCSEALED-TARGET-EXEC-STATUS: control socket failed".to_owned());
        }
        let mut packet = [0_u8; EXEC_FAILURE_RECORD_LENGTH + 1];
        // SAFETY: recv writes at most `packet.len()` bytes into a live initialized buffer and
        // borrows the verified control socket without transferring descriptor ownership.
        let count = unsafe {
            libc::recv(
                control.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                0,
            )
        };
        if count == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("MCSEALED-TARGET-EXEC-STATUS: {error}"));
        }
        if count == 0 {
            return Ok(None);
        }
        let count = usize::try_from(count)
            .map_err(|_| "MCSEALED-TARGET-EXEC-STATUS: invalid packet length".to_owned())?;
        return Ok(Some(packet[..count].to_vec()));
    }
}

fn control_socketpair() -> Result<(File, File), String> {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: socketpair receives storage for exactly two descriptors. SOCK_CLOEXEC establishes
    // close-on-exec on both uniquely owned endpoints, and ownership is transferred to `File` only
    // after the syscall reports success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: successful socketpair returned two distinct new descriptors. These are transferred
    // exactly once into Files, which close their respective endpoints on drop.
    Ok(unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    })
}

fn descriptor_inode(descriptor: &File) -> Result<u64, String> {
    descriptor
        .metadata()
        .map(|metadata| metadata.ino())
        .map_err(|error| error.to_string())
}

#[cfg(feature = "test-support")]
pub fn control_socketpair_for_test() -> Result<(File, File), String> {
    control_socketpair()
}

#[cfg(feature = "test-support")]
pub const fn exec_armed_record_for_test() -> [u8; 4] {
    EXEC_CONTROL_ARMED
}

#[cfg(feature = "test-support")]
pub fn exec_failure_record_for_test(os_code: i32) -> [u8; EXEC_FAILURE_RECORD_LENGTH] {
    encode_exec_failure(classify_exec_error(os_code), os_code)
}

#[cfg(feature = "test-support")]
pub fn receive_exec_status_for_test(control: &mut File) -> Result<TargetExecStatus, String> {
    receive_exec_status(control, Instant::now() + Duration::from_secs(1))
}

fn pipe() -> Result<(File, File), String> {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    Ok(unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    })
}

fn duplicate(descriptor: &OwnedFd) -> Result<OwnedFd, String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let duplicated = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd, String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if descriptor == -1 {
        Err(format!(
            "MCSEALED-TARGET-IDENTITY: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

#[cfg(feature = "test-support")]
fn signal_pidfd(pidfd: &OwnedFd, signal: i32) -> Result<(), String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), signal, 0, 0) } == -1
    {
        Err(format!(
            "MCSEALED-FAULT: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn fault_boundary_retired(identity: &str) -> bool {
    let path = std::path::Path::new(super::CGROUP_ROOT).join(identity);
    matches!(
        std::fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

fn encode_namespace_startup(
    status: NamespaceStartupStatus,
) -> [u8; NAMESPACE_STARTUP_RECORD_LENGTH] {
    let (kind, phase, os_code) = match status {
        NamespaceStartupStatus::TargetForked => (
            NAMESPACE_STARTUP_READY_KIND,
            super::namespace::NamespaceInitPhase::TargetFork,
            0_i32,
        ),
        NamespaceStartupStatus::Failed(error) => {
            (NAMESPACE_STARTUP_FAILURE_KIND, error.phase, error.os_code)
        }
    };
    let os_code = os_code.to_be_bytes();
    [
        NAMESPACE_STARTUP_VERSION,
        kind,
        phase.code(),
        0,
        os_code[0],
        os_code[1],
        os_code[2],
        os_code[3],
    ]
}

fn decode_namespace_startup(bytes: &[u8]) -> Result<NamespaceStartupStatus, String> {
    let record: [u8; NAMESPACE_STARTUP_RECORD_LENGTH] = bytes
        .try_into()
        .map_err(|_| "MCSEALED-NAMESPACE-INIT-STATUS: record length mismatch".to_owned())?;
    if record[0] != NAMESPACE_STARTUP_VERSION || record[3] != 0 {
        return Err("MCSEALED-NAMESPACE-INIT-STATUS: invalid record header".to_owned());
    }
    let phase = super::namespace::NamespaceInitPhase::from_code(record[2])
        .ok_or_else(|| "MCSEALED-NAMESPACE-INIT-STATUS: invalid phase".to_owned())?;
    let os_code = i32::from_be_bytes([record[4], record[5], record[6], record[7]]);
    match record[1] {
        NAMESPACE_STARTUP_READY_KIND
            if phase == super::namespace::NamespaceInitPhase::TargetFork && os_code == 0 =>
        {
            Ok(NamespaceStartupStatus::TargetForked)
        }
        NAMESPACE_STARTUP_READY_KIND => {
            Err("MCSEALED-NAMESPACE-INIT-STATUS: invalid readiness record".to_owned())
        }
        NAMESPACE_STARTUP_FAILURE_KIND if os_code > 0 => Ok(NamespaceStartupStatus::Failed(
            super::namespace::NamespaceInitError { phase, os_code },
        )),
        NAMESPACE_STARTUP_FAILURE_KIND => {
            Err("MCSEALED-NAMESPACE-INIT-STATUS: native errno missing".to_owned())
        }
        _ => Err("MCSEALED-NAMESPACE-INIT-STATUS: invalid record kind".to_owned()),
    }
}

fn report_namespace_startup(startup: &File, status: NamespaceStartupStatus) -> Result<(), String> {
    let record = encode_namespace_startup(status);
    // SAFETY: send borrows a live packet socket and reads the exact fixed record from a live
    // buffer. MSG_NOSIGNAL keeps a lost provider endpoint from terminating namespace init.
    let written = unsafe {
        libc::send(
            startup.as_raw_fd(),
            record.as_ptr().cast(),
            record.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if written == isize::try_from(record.len()).expect("startup record length fits isize") {
        Ok(())
    } else if written == -1 {
        Err(format!(
            "MCSEALED-NAMESPACE-INIT-STATUS: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Err("MCSEALED-NAMESPACE-INIT-STATUS: short record write".to_owned())
    }
}

fn observe_namespace_startup(startup: &File) -> Result<NamespaceStartupObservation, String> {
    let mut pollfd = libc::pollfd {
        fd: startup.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    // SAFETY: poll receives one initialized pollfd and a zero timeout, and it does not retain
    // the pointer or descriptor after returning.
    let ready = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
    if ready == -1 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::Interrupted {
            Ok(NamespaceStartupObservation::Pending)
        } else {
            Err(format!("MCSEALED-NAMESPACE-INIT-STATUS: {error}"))
        };
    }
    if ready == 0 {
        return Ok(NamespaceStartupObservation::Pending);
    }
    if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err("MCSEALED-NAMESPACE-INIT-STATUS: startup socket failed".to_owned());
    }
    if pollfd.revents & libc::POLLIN != 0 {
        let mut packet = [0_u8; NAMESPACE_STARTUP_RECORD_LENGTH + 1];
        // SAFETY: recv writes at most packet.len() bytes to a live buffer and borrows the
        // verified startup packet socket without transferring ownership.
        let count = unsafe {
            libc::recv(
                startup.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if count == -1 {
            let error = std::io::Error::last_os_error();
            return if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                Ok(NamespaceStartupObservation::Pending)
            } else {
                Err(format!("MCSEALED-NAMESPACE-INIT-STATUS: {error}"))
            };
        }
        if count == 0 {
            return Ok(NamespaceStartupObservation::Closed);
        }
        let count = usize::try_from(count)
            .map_err(|_| "MCSEALED-NAMESPACE-INIT-STATUS: invalid packet length".to_owned())?;
        return decode_namespace_startup(&packet[..count]).map(NamespaceStartupObservation::Status);
    }
    if pollfd.revents & libc::POLLHUP != 0 {
        Ok(NamespaceStartupObservation::Closed)
    } else {
        Ok(NamespaceStartupObservation::Pending)
    }
}

fn pidfd_has_exited(pidfd: &OwnedFd) -> Result<bool, String> {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll receives one initialized pollfd and a zero timeout, and it does not retain
    // the pointer or descriptor after returning.
    let ready = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
    if ready == -1 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(format!("MCSEALED-NAMESPACE-INIT-PIDFD: {error}"))
        }
    } else if ready == 0 {
        Ok(false)
    } else if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        Err("MCSEALED-NAMESPACE-INIT-PIDFD: invalid pidfd state".to_owned())
    } else {
        Ok(pollfd.revents & libc::POLLIN != 0)
    }
}

fn wait_for_target(
    cgroup: &AttemptCgroup,
    init_pid: libc::pid_t,
    init_pidfd: &OwnedFd,
    startup: &File,
    deadline: Instant,
) -> Result<libc::pid_t, String> {
    let mut startup_ready = false;
    while Instant::now() < deadline {
        if !startup_ready {
            match observe_namespace_startup(startup)? {
                NamespaceStartupObservation::Pending => {}
                NamespaceStartupObservation::Closed => {
                    return Err(
                        "MCSEALED-NAMESPACE-INIT-STATUS: channel closed before target creation"
                            .to_owned(),
                    );
                }
                NamespaceStartupObservation::Status(NamespaceStartupStatus::TargetForked) => {
                    startup_ready = true;
                }
                NamespaceStartupObservation::Status(NamespaceStartupStatus::Failed(error)) => {
                    return Err(error.to_string());
                }
            }
        }
        let members = cgroup.member_pids()?;
        if let Some(pid) = target_after_startup_ready(startup_ready, init_pid, &members) {
            return Ok(pid);
        }
        if pidfd_has_exited(init_pidfd)? {
            return Err(
                "MCSEALED-NAMESPACE-INIT-EXIT: init exited before target observation".to_owned(),
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err("gated target not observed".to_owned())
}

fn target_after_startup_ready(
    startup_ready: bool,
    init_pid: libc::pid_t,
    members: &[libc::pid_t],
) -> Option<libc::pid_t> {
    if startup_ready {
        members.iter().copied().find(|pid| *pid != init_pid)
    } else {
        None
    }
}

#[cfg(feature = "test-support")]
pub fn target_after_startup_ready_for_test(
    startup_ready: bool,
    init_pid: libc::pid_t,
    members: &[libc::pid_t],
) -> Option<libc::pid_t> {
    target_after_startup_ready(startup_ready, init_pid, members)
}

#[cfg(feature = "test-support")]
pub fn namespace_startup_failure_record_for_test(
    phase: super::namespace::NamespaceInitPhase,
    os_code: i32,
) -> [u8; NAMESPACE_STARTUP_RECORD_LENGTH] {
    encode_namespace_startup(NamespaceStartupStatus::Failed(
        super::namespace::NamespaceInitError { phase, os_code },
    ))
}

#[cfg(feature = "test-support")]
pub fn namespace_startup_ready_record_for_test() -> [u8; NAMESPACE_STARTUP_RECORD_LENGTH] {
    encode_namespace_startup(NamespaceStartupStatus::TargetForked)
}

#[cfg(feature = "test-support")]
pub fn decode_namespace_startup_record_for_test(
    bytes: &[u8],
) -> Result<Option<super::namespace::NamespaceInitError>, String> {
    decode_namespace_startup(bytes).map(|status| match status {
        NamespaceStartupStatus::TargetForked => None,
        NamespaceStartupStatus::Failed(error) => Some(error),
    })
}

fn verify_gated_target(
    pid: libc::pid_t,
    init_pid: libc::pid_t,
    identity: &str,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
    target_control_inode: u64,
) -> Result<(), String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| format!("MCSEALED-TARGET-CREDENTIAL-READBACK: {error}"))?;
    if !status.lines().any(|line| line == "NoNewPrivs:\t1") {
        return Err("MCSEALED-TARGET-IDENTITY: no_new_privs not verified".to_owned());
    }
    for field in [
        "CapInh:\t0000000000000000",
        "CapPrm:\t0000000000000000",
        "CapEff:\t0000000000000000",
        "CapAmb:\t0000000000000000",
    ] {
        if !status.lines().any(|line| line == field) {
            return Err("MCSEALED-TARGET-IDENTITY: capabilities are not empty".to_owned());
        }
    }
    let uid_line = format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}");
    let gid_line = format!("Gid:\t{gid}\t{gid}\t{gid}\t{gid}");
    if !status.lines().any(|line| line == uid_line) || !status.lines().any(|line| line == gid_line)
    {
        return Err("MCSEALED-TARGET-IDENTITY: caller credentials not verified".to_owned());
    }
    let mut actual_groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:\t"))
        .ok_or_else(|| "MCSEALED-TARGET-IDENTITY: supplementary groups missing".to_owned())?
        .split_whitespace()
        .map(|group| {
            group
                .parse::<libc::gid_t>()
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected_groups = groups.to_vec();
    actual_groups.sort_unstable();
    expected_groups.sort_unstable();
    if actual_groups != expected_groups {
        return Err("MCSEALED-TARGET-IDENTITY: supplementary groups not verified".to_owned());
    }
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|error| format!("MCSEALED-TARGET-CGROUP-READBACK: {error}"))?;
    if !cgroup.contains(identity) {
        return Err("MCSEALED-TARGET-IDENTITY: cgroup membership mismatch".to_owned());
    }
    let mut descriptors = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|error| format!("MCSEALED-TARGET-DESCRIPTORS-READBACK: {error}"))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| format!("MCSEALED-TARGET-DESCRIPTORS-READBACK: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    descriptors.sort();
    if descriptors != ["0", "1", "2", "3"].map(OsString::from) {
        return Err(
            "MCSEALED-DESCRIPTOR-SET: gated target descriptor inventory mismatch".to_owned(),
        );
    }
    let control_path = format!("/proc/{pid}/fd/3");
    let control_metadata = std::fs::metadata(&control_path)
        .map_err(|error| format!("MCSEALED-TARGET-CONTROL-READBACK: {error}"))?;
    if control_metadata.ino() != target_control_inode {
        return Err("MCSEALED-TARGET-CONTROL-READBACK: fd 3 socket identity mismatch".to_owned());
    }
    let control_link = std::fs::read_link(&control_path)
        .map_err(|error| format!("MCSEALED-TARGET-CONTROL-READBACK: {error}"))?;
    if !control_link.to_string_lossy().starts_with("socket:[") {
        return Err("MCSEALED-TARGET-CONTROL-READBACK: fd 3 is not a socket".to_owned());
    }
    let descriptor_info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/3"))
        .map_err(|error| format!("MCSEALED-TARGET-CONTROL-READBACK: {error}"))?;
    let descriptor_flags = descriptor_info
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .ok_or_else(|| "MCSEALED-TARGET-CONTROL-READBACK: fd flags missing".to_owned())?;
    let descriptor_flags = u32::from_str_radix(descriptor_flags, 8)
        .map_err(|error| format!("MCSEALED-TARGET-CONTROL-READBACK: {error}"))?;
    if descriptor_flags & libc::O_CLOEXEC as u32 == 0 {
        return Err("MCSEALED-TARGET-CONTROL-READBACK: fd 3 is not close-on-exec".to_owned());
    }
    for namespace in ["pid", "mnt", "cgroup"] {
        let target = std::fs::read_link(format!("/proc/{pid}/ns/{namespace}"))
            .map_err(|error| format!("MCSEALED-TARGET-NAMESPACE-READBACK: {error}"))?;
        let init = std::fs::read_link(format!("/proc/{init_pid}/ns/{namespace}"))
            .map_err(|error| format!("MCSEALED-TARGET-NAMESPACE-READBACK: {error}"))?;
        let provider = std::fs::read_link(format!("/proc/self/ns/{namespace}"))
            .map_err(|error| format!("MCSEALED-TARGET-NAMESPACE-READBACK: {error}"))?;
        if target != init || target == provider {
            return Err("MCSEALED-TARGET-IDENTITY: namespace membership mismatch".to_owned());
        }
    }
    let mountinfo = std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))
        .map_err(|error| format!("MCSEALED-CGROUP-VIEW: mountinfo unavailable: {error}"))?;
    if cgroup_mount_visible(&mountinfo)? {
        return Err("MCSEALED-CGROUP-VIEW: target can still see host cgroup mount".to_owned());
    }
    Ok(())
}

pub fn cgroup_mount_visible(mountinfo: &str) -> Result<bool, String> {
    for line in mountinfo.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or_else(|| "MCSEALED-CGROUP-VIEW: malformed mountinfo separator".to_owned())?;
        let filesystem = fields
            .get(separator + 1)
            .ok_or_else(|| "MCSEALED-CGROUP-VIEW: malformed mountinfo filesystem".to_owned())?;
        if matches!(*filesystem, "cgroup" | "cgroup2") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn wait_pid(pid: libc::pid_t) -> bool {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    (unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) }) == pid
}

fn terminate_and_reap(pid: libc::pid_t) -> bool {
    // SAFETY: `pid` is a positive child process id recorded from clone/fork; SIGKILL has no
    // pointer or buffer arguments, and cleanup below still verifies that the child was reaped.
    let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: waitpid writes no status because the status pointer is null; WNOHANG keeps this
        // failure cleanup bounded, and this process exclusively owns the child-reaping duty.
        let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        if result == pid {
            return true;
        }
        if result == -1 || Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
