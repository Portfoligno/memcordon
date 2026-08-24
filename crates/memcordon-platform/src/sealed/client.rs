use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const ENDPOINT: &str = "/run/memcordon/sealed-agent.sock";
const VERSION: u16 = 1;
const HEADER_LENGTH: usize = 72;
const MAX_FRAME: usize = 1024 * 1024;
const MAX_NATIVE_VALUE: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 4096;
const MAX_ENVIRONMENT_ENTRIES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeReceipt {
    pub provider_identity: String,
    pub receipt_digest: String,
}

#[derive(Deserialize)]
struct QualificationReceipt {
    schema_version: u32,
    mechanism: String,
    provider_identity: String,
    receipt_digest: String,
    unified_cgroup_v2: bool,
    private_cgroup_subtree: bool,
    clone3: bool,
    clone3_into_cgroup: bool,
    pid_namespace: bool,
    mount_namespace: bool,
    cgroup_namespace: bool,
    pidfd: bool,
    close_range: bool,
    guardian_outside_boundary: bool,
    target_gated: bool,
    assignment_verified: bool,
    inherited_descriptors_verified: bool,
    spawn_error_reporting_verified: bool,
    frontend_loss_authority_verified: bool,
    cgroup_kill: bool,
    workload_empty: bool,
    helpers_reaped: bool,
    boundary_retired: bool,
    recovery_complete: bool,
}

impl QualificationReceipt {
    fn is_complete(&self) -> bool {
        self.schema_version == 1
            && self.mechanism == "linux-pid-namespace-cgroup-v1"
            && !self.provider_identity.is_empty()
            && self.receipt_digest.len() == 64
            && self
                .receipt_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && self.unified_cgroup_v2
            && self.private_cgroup_subtree
            && self.clone3
            && self.clone3_into_cgroup
            && self.pid_namespace
            && self.mount_namespace
            && self.cgroup_namespace
            && self.pidfd
            && self.close_range
            && self.guardian_outside_boundary
            && self.target_gated
            && self.assignment_verified
            && self.inherited_descriptors_verified
            && self.spawn_error_reporting_verified
            && self.frontend_loss_authority_verified
            && self.cgroup_kill
            && self.workload_empty
            && self.helpers_reaped
            && self.boundary_retired
            && self.recovery_complete
    }
}

pub struct TerminalReceipt {
    pub status: i32,
    pub exec_status: TerminalExecStatus,
    pub spawn_error_reported: bool,
    pub target_pid: u32,
    pub authorization_offset_millis: u64,
    pub assignment_verified: bool,
    pub namespaces_verified: bool,
    pub credentials_verified: bool,
    pub capabilities_empty: bool,
    pub descriptors_verified: bool,
    pub cgroup_view_denied: bool,
    pub guardian_ready: bool,
    pub frontend_loss_authority: bool,
    pub cgroup_kill: bool,
    pub cgroup_empty: bool,
    pub init_reaped: bool,
    pub guardian_reaped: bool,
    pub boundary_retired: bool,
    pub memory_limit_exceeded: bool,
    pub deadline_exceeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalExecStatus {
    Succeeded,
    Failed {
        class: TerminalExecFailureClass,
        os_code: i32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalExecFailureClass {
    NotFound,
    NotExecutable,
    Other,
}

#[derive(Debug)]
pub enum LaunchError {
    Transport(String),
    Rejected(memcordon_core::ProviderRejectionEvidence),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectionCleanupV1 {
    attempted: bool,
    direct_child_reaped: bool,
    workload_empty: Option<bool>,
    helpers_reaped: bool,
    containment_removed: bool,
    sealed_boundary_retired: bool,
    errors: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectionV1 {
    schema_version: u32,
    code: String,
    phase: memcordon_core::BoundarySetupPhase,
    detail: String,
    os_code: Option<i32>,
    target_created: bool,
    target_released: bool,
    cleanup: RejectionCleanupV1,
}

#[allow(
    clippy::result_large_err,
    reason = "the backend boundary preserves the public categorized Error contract"
)]
pub fn run(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    context: crate::supervisor::AttemptContext,
) -> Result<crate::backend::Execution, memcordon_core::Error> {
    let started = std::time::Instant::now();
    let qualification = probe().map_err(|error| {
        memcordon_core::Error::new(
            memcordon_core::ErrorCategory::Setup,
            "MCSEALED-PROVIDER-QUALIFICATION",
            error,
        )
    })?;
    let terminal = launch(policy, command, context, started).map_err(|error| match error {
        LaunchError::Transport(detail) => memcordon_core::Error::new(
            memcordon_core::ErrorCategory::Setup,
            "MCSEALED-PROVIDER-TRANSACTION",
            detail,
        ),
        LaunchError::Rejected(rejection) => {
            let restart_safety = rejection.restart_safety.clone();
            let mut error = memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Setup,
                "MCSEALED-PROVIDER-REJECTION",
                format!(
                    "provider rejected launch [{}]: {}",
                    rejection.code, rejection.detail
                ),
            )
            .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
                requested: memcordon_core::BoundaryRequirement::Sealed,
                mechanism: Some("linux-pid-namespace-cgroup-v1".to_owned()),
                phase: rejection.phase,
                target_created: rejection.target_created,
                target_released: rejection.target_released,
                cleanup_attempted: rejection.cleanup_attempted,
                restart_safety,
            })
            .with_provider_rejection(rejection.clone());
            error.launch_phase = Some(boundary_phase_name(rejection.phase));
            error.workload_may_be_alive =
                rejection.target_created && rejection.restart_safety.workload_empty != Some(true);
            if matches!(
                rejection.phase,
                memcordon_core::BoundarySetupPhase::ResourceVerification
                    | memcordon_core::BoundarySetupPhase::Authorization
                    | memcordon_core::BoundarySetupPhase::Monitoring
                    | memcordon_core::BoundarySetupPhase::Retirement
            ) {
                error.cgroup_verified_before_release = true;
                error.guardian_ready_before_release = true;
            }
            error
        }
    })?;
    let cleanup = memcordon_core::CleanupSummary {
        direct_child_reaped: terminal.init_reaped,
        workload_empty: Some(terminal.cgroup_empty),
        errors: Vec::new(),
        ..memcordon_core::CleanupSummary::default()
    };
    let restart_safety = terminal_restart_safety(&terminal);
    if let TerminalExecStatus::Failed { class, os_code } = terminal.exec_status {
        return Err(terminal_spawn_error(
            &terminal,
            class,
            os_code,
            cleanup,
            restart_safety,
        ));
    }
    let child = memcordon_core::ChildTermination::ExitCode {
        code: terminal.status,
    };
    let outcome = if terminal.memory_limit_exceeded {
        let limit = policy.memory.ok_or_else(|| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-MEMORY-EVIDENCE",
                "provider reported a memory limit without a configured limit",
            )
        })?;
        memcordon_core::RunOutcome::LimitExceeded {
            limit,
            observed: None,
            peak: None,
            evidence: memcordon_core::LimitEvidence {
                backend: "linux-pid-namespace-cgroup-v1".to_owned(),
                metric: "memory.current".to_owned(),
                detail: "memory.events oom_kill incremented".to_owned(),
            },
            child_after_termination: Some(child),
            cleanup,
        }
    } else if terminal.deadline_exceeded {
        let configured = policy.deadline.ok_or_else(|| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-DEADLINE-EVIDENCE",
                "provider reported a deadline without a configured deadline",
            )
        })?;
        let duration_ms = configured.duration().as_millis() as u64;
        let deadline = memcordon_core::DeadlineEvidence::new(
            duration_ms,
            configured.scope(),
            "provider-absolute-deadline".to_owned(),
            duration_ms,
            duration_ms,
            policy.limit_grace.as_millis() as u64,
            0,
            None,
            Some("cgroup.kill".to_owned()),
        )
        .map_err(|_| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-DEADLINE-EVIDENCE",
                "provider deadline evidence was inconsistent",
            )
        })?;
        memcordon_core::RunOutcome::DeadlineExceeded {
            deadline,
            child_after_termination: Some(child),
            peak: None,
            cleanup,
        }
    } else {
        memcordon_core::RunOutcome::Exited {
            child,
            peak: None,
            cleanup,
        }
    };
    let evidence = memcordon_core::LinuxSealedEvidence {
        schema_version: 1,
        provider_identity: qualification.provider_identity.clone(),
        cgroup_identity_digest: qualification.receipt_digest.clone(),
        cgroup_created: true,
        cgroup_owned_by_provider: true,
        memory_configuration_verified: true,
        init_created_into_cgroup: terminal.assignment_verified,
        pid_namespace_created: terminal.namespaces_verified,
        mount_namespace_created: terminal.namespaces_verified,
        cgroup_namespace_created: terminal.namespaces_verified,
        target_pidfd_verified: true,
        target_cgroup_membership_verified: terminal.assignment_verified,
        target_pid_namespace_verified: terminal.namespaces_verified,
        target_credentials_verified: terminal.credentials_verified,
        target_capabilities_empty: terminal.capabilities_empty,
        no_new_privs_verified: true,
        inherited_descriptors_verified: terminal.descriptors_verified,
        writable_cgroup_view_denied: terminal.cgroup_view_denied,
        guardian_ready: terminal.guardian_ready,
        target_released: true,
        cgroup_kill_invoked: terminal.cgroup_kill,
        cgroup_empty_verified: terminal.cgroup_empty,
        namespace_init_reaped: terminal.init_reaped,
        guardian_reaped: terminal.guardian_reaped,
        cgroup_removed: terminal.boundary_retired,
    };
    Ok(crate::backend::Execution {
        outcome,
        backend: crate::linux_cgroup::sealed_info(qualification),
        child_pid: terminal.target_pid,
        duration: started.elapsed(),
        authorization_offset: Some(Duration::from_millis(terminal.authorization_offset_millis)),
        launch: memcordon_core::LaunchEvidence {
            mechanism: "linux-pid-namespace-cgroup-v1".to_owned(),
            target_released: true,
            containment_verified_before_authorization: terminal.assignment_verified
                && terminal.namespaces_verified,
            guardian_started_before_authorization: terminal.guardian_ready,
            target_spawn_error_reported: terminal.spawn_error_reported,
            boundary_requested: memcordon_core::BoundaryRequirement::Sealed,
            boundary_effective: memcordon_core::BoundaryClass::Sealed,
            boundary_assignment_verified: terminal.assignment_verified,
            boundary_reconfiguration_denied: terminal.cgroup_view_denied,
            inherited_resources_restricted: terminal.descriptors_verified,
            frontend_loss_cleanup_authority_verified: terminal.frontend_loss_authority,
        },
        restart_safety,
        boundary_detail: memcordon_core::BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV1(
            evidence,
        ),
    })
}

pub(crate) fn terminal_restart_safety(
    terminal: &TerminalReceipt,
) -> memcordon_core::RestartSafetyProof {
    memcordon_core::RestartSafetyProof {
        direct_child_reaped: terminal.init_reaped,
        workload_empty: Some(terminal.cgroup_empty),
        helpers_reaped: terminal.init_reaped && terminal.guardian_reaped,
        containment_removed: terminal.boundary_retired,
        containment_incapable_of_live_members: terminal.cgroup_empty,
        sealed_boundary_retired: terminal.boundary_retired,
        errors: Vec::new(),
    }
}

pub(crate) fn terminal_spawn_error(
    terminal: &TerminalReceipt,
    class: TerminalExecFailureClass,
    os_code: i32,
    cleanup: memcordon_core::CleanupSummary,
    restart_safety: memcordon_core::RestartSafetyProof,
) -> memcordon_core::Error {
    let (code, initial_spawn_failure) = match class {
        TerminalExecFailureClass::NotFound => (
            "MCSPAWN-NOT-FOUND",
            Some(memcordon_core::InitialSpawnFailure::NotFound),
        ),
        TerminalExecFailureClass::NotExecutable => (
            "MCSPAWN-NOT-EXECUTABLE",
            Some(memcordon_core::InitialSpawnFailure::NotExecutable),
        ),
        TerminalExecFailureClass::Other => ("MCSPAWN-FAILED", None),
    };
    let detail = format!(
        "sealed provider reported a verified target exec failure with native OS code {os_code}"
    );
    let provider_rejection = memcordon_core::ProviderRejectionEvidence {
        schema_version: 1,
        code: code.to_owned(),
        phase: memcordon_core::BoundarySetupPhase::TargetCreation,
        detail: detail.clone(),
        os_code: Some(os_code),
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety: restart_safety.clone(),
    };
    let mut error = memcordon_core::Error::new(memcordon_core::ErrorCategory::Spawn, code, detail)
        .with_provider_rejection(provider_rejection)
        .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
            requested: memcordon_core::BoundaryRequirement::Sealed,
            mechanism: Some("linux-pid-namespace-cgroup-v1".to_owned()),
            phase: memcordon_core::BoundarySetupPhase::TargetCreation,
            target_created: true,
            target_released: true,
            cleanup_attempted: true,
            restart_safety: restart_safety.clone(),
        });
    if let Some(failure) = initial_spawn_failure {
        error = error.with_initial_spawn_failure(failure);
    }
    error.os_code = Some(os_code);
    error.target_pid = Some(terminal.target_pid);
    error.launch_phase = Some("target-spawn-failed");
    error.target_released = true;
    error.authorization_offset = Some(Duration::from_millis(terminal.authorization_offset_millis));
    error.cgroup_verified_before_release = terminal.assignment_verified
        && terminal.namespaces_verified
        && terminal.credentials_verified
        && terminal.capabilities_empty
        && terminal.descriptors_verified
        && terminal.cgroup_view_denied;
    error.guardian_ready_before_release = terminal.guardian_ready;
    error.workload_may_be_alive =
        !restart_safety.is_safe_for(memcordon_core::BoundaryRequirement::Sealed);
    error.cleanup = cleanup;
    error.restart_safety = Some(restart_safety);
    error
}

pub(crate) fn launch(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    context: crate::supervisor::AttemptContext,
    started: std::time::Instant,
) -> Result<TerminalReceipt, LaunchError> {
    verify_endpoint().map_err(LaunchError::Transport)?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT))
        .map_err(|error| LaunchError::Transport(error.to_string()))?;
    verify_peer(&stream).map_err(LaunchError::Transport)?;
    let attempt = nonce().map_err(LaunchError::Transport)?;
    let nonce = nonce().map_err(LaunchError::Transport)?;
    let deadline_budget = effective_deadline_duration(policy, context, started.elapsed());
    let payload =
        encode_launch(policy, command, deadline_budget).map_err(LaunchError::Transport)?;
    let frame = encoded_frame(2, nonce, attempt, &payload).map_err(LaunchError::Transport)?;
    let cwd = fs::File::open(".").map_err(|error| LaunchError::Transport(error.to_string()))?;
    let frontend_pidfd = pidfd_self().map_err(LaunchError::Transport)?;
    let descriptors = [cwd.as_raw_fd(), 0, 1, 2, frontend_pidfd.as_raw_fd()];
    send_with_descriptors(&stream, &frame, &descriptors).map_err(LaunchError::Transport)?;
    let WireFrame {
        kind,
        nonce: returned_nonce,
        attempt: returned_attempt,
        payload,
    } = read_frame(&mut stream).map_err(LaunchError::Transport)?;
    if returned_nonce != nonce || returned_attempt != attempt {
        return Err(LaunchError::Transport(
            "provider terminal receipt identity mismatch".to_owned(),
        ));
    }
    if kind == 106 {
        return Err(LaunchError::Rejected(parse_rejection(&payload).map_err(
            |error| LaunchError::Transport(format!("invalid provider rejection: {error}")),
        )?));
    }
    if kind != 105 {
        return Err(LaunchError::Transport(
            "provider omitted terminal receipt".to_owned(),
        ));
    }
    parse_terminal(&payload).map_err(LaunchError::Transport)
}

fn parse_rejection(payload: &[u8]) -> Result<memcordon_core::ProviderRejectionEvidence, String> {
    const MAX_CODE_BYTES: usize = 128;
    const MAX_DETAIL_BYTES: usize = 8 * 1024;
    const MAX_CLEANUP_ERRORS: usize = 16;
    const MAX_CLEANUP_ERROR_BYTES: usize = 1024;
    let receipt: RejectionV1 =
        serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    if receipt.schema_version != 1
        || receipt.code.is_empty()
        || receipt.code.len() > MAX_CODE_BYTES
        || !receipt
            .code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        || receipt.detail.len() > MAX_DETAIL_BYTES
        || receipt.detail.contains('\0')
        || receipt.target_released && !receipt.target_created
        || receipt.cleanup.errors.len() > MAX_CLEANUP_ERRORS
        || receipt
            .cleanup
            .errors
            .iter()
            .any(|error| error.len() > MAX_CLEANUP_ERROR_BYTES || error.contains('\0'))
    {
        return Err("typed rejection fields violate protocol bounds".to_owned());
    }
    if !receipt.cleanup.attempted
        && (receipt.cleanup.direct_child_reaped
            || receipt.cleanup.workload_empty.is_some()
            || receipt.cleanup.helpers_reaped
            || receipt.cleanup.containment_removed
            || receipt.cleanup.sealed_boundary_retired
            || !receipt.cleanup.errors.is_empty())
    {
        return Err("typed rejection cleanup evidence is contradictory".to_owned());
    }
    if receipt.cleanup.sealed_boundary_retired
        && (!receipt.cleanup.direct_child_reaped
            || receipt.cleanup.workload_empty != Some(true)
            || !receipt.cleanup.helpers_reaped
            || !receipt.cleanup.containment_removed
            || !receipt.cleanup.errors.is_empty())
    {
        return Err("typed rejection retirement evidence is incomplete".to_owned());
    }
    Ok(memcordon_core::ProviderRejectionEvidence {
        schema_version: receipt.schema_version,
        code: receipt.code,
        phase: receipt.phase,
        detail: receipt.detail,
        os_code: receipt.os_code,
        target_created: receipt.target_created,
        target_released: receipt.target_released,
        cleanup_attempted: receipt.cleanup.attempted,
        restart_safety: memcordon_core::RestartSafetyProof {
            direct_child_reaped: receipt.cleanup.direct_child_reaped,
            workload_empty: receipt.cleanup.workload_empty,
            helpers_reaped: receipt.cleanup.helpers_reaped,
            containment_removed: receipt.cleanup.containment_removed,
            containment_incapable_of_live_members: receipt.cleanup.workload_empty == Some(true),
            sealed_boundary_retired: receipt.cleanup.sealed_boundary_retired,
            errors: receipt.cleanup.errors,
        },
    })
}

fn boundary_phase_name(phase: memcordon_core::BoundarySetupPhase) -> &'static str {
    match phase {
        memcordon_core::BoundarySetupPhase::ProviderConnection => "provider-connection",
        memcordon_core::BoundarySetupPhase::ProviderIdentity => "provider-identity",
        memcordon_core::BoundarySetupPhase::BoundaryCreation => "boundary-creation",
        memcordon_core::BoundarySetupPhase::GuardianStartup => "guardian-startup",
        memcordon_core::BoundarySetupPhase::TargetCreation => "target-creation",
        memcordon_core::BoundarySetupPhase::AssignmentVerification => "assignment-verification",
        memcordon_core::BoundarySetupPhase::ResourceVerification => "resource-verification",
        memcordon_core::BoundarySetupPhase::Authorization => "authorization",
        memcordon_core::BoundarySetupPhase::Monitoring => "monitoring",
        memcordon_core::BoundarySetupPhase::Retirement => "retirement",
    }
}

pub fn probe() -> Result<ProbeReceipt, String> {
    verify_endpoint()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let nonce = nonce()?;
    write_frame(&mut stream, 1, nonce, [0; 16], &[])?;
    let WireFrame {
        kind,
        nonce: returned_nonce,
        attempt,
        payload,
    } = read_frame(&mut stream)?;
    if kind != 101 || returned_nonce != nonce || attempt != [0; 16] {
        return Err("provider probe receipt identity mismatch".to_owned());
    }
    let identity = String::from_utf8(payload)
        .map_err(|_| "provider qualification receipt is not UTF-8".to_owned())?;
    let receipt: QualificationReceipt = serde_json::from_str(&identity)
        .map_err(|error| format!("provider qualification receipt is invalid: {error}"))?;
    if !receipt.is_complete() {
        return Err("provider reported an uncertified mechanism".to_owned());
    }
    Ok(ProbeReceipt {
        provider_identity: receipt.provider_identity,
        receipt_digest: receipt.receipt_digest,
    })
}

fn verify_endpoint() -> Result<(), String> {
    let metadata = fs::symlink_metadata(ENDPOINT)
        .map_err(|error| format!("provider endpoint unavailable: {error}"))?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o007 != 0 {
        return Err("provider endpoint is not a root-owned socket identity".to_owned());
    }
    let executable = fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")
        .map_err(|error| format!("provider executable unavailable: {error}"))?;
    if !executable.file_type().is_file() || executable.uid() != 0 || executable.mode() & 0o022 != 0
    {
        return Err("provider executable identity or permissions are unsafe".to_owned());
    }
    Ok(())
}

fn verify_peer(stream: &UnixStream) -> Result<(), String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` and `length` are initialized writable values of the exact
    // SO_PEERCRED ABI sizes; the borrowed stream fd remains open for the call.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    } == -1
        || credentials.uid != 0
    {
        return Err("connected provider peer is not root-owned".to_owned());
    }
    Ok(())
}

fn encode_launch(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    deadline_budget: Option<Duration>,
) -> Result<Vec<u8>, String> {
    if command.arguments().len() > MAX_ARGUMENTS {
        return Err("launch argument count exceeds protocol limit".to_owned());
    }
    let mut output = Vec::new();
    output.extend_from_slice(&1_u16.to_be_bytes());
    put_bytes(&mut output, command.program().as_bytes())?;
    put_count(&mut output, command.arguments().len())?;
    for argument in command.arguments() {
        put_bytes(&mut output, argument.as_bytes())?;
    }
    let environment: Vec<_> = std::env::vars_os().collect();
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err("launch environment count exceeds protocol limit".to_owned());
    }
    put_count(&mut output, environment.len())?;
    for (name, value) in environment {
        put_bytes(&mut output, name.as_bytes())?;
        put_bytes(&mut output, value.as_bytes())?;
    }
    put_optional(
        &mut output,
        policy.memory.map(memcordon_core::ByteSize::bytes),
    );
    match policy.swap {
        memcordon_core::SwapPolicy::Bytes(bytes) => {
            output.push(1);
            output.extend_from_slice(&bytes.bytes().to_be_bytes());
        }
        memcordon_core::SwapPolicy::Unlimited => output.push(2),
        memcordon_core::SwapPolicy::Host => output.push(3),
    }
    let absolute_deadline_millis = match deadline_budget {
        Some(duration) => Some(
            monotonic_millis()?.saturating_add(
                u64::try_from(duration.as_millis())
                    .map_err(|_| "sealed deadline exceeds protocol range".to_owned())?,
            ),
        ),
        None => None,
    };
    put_optional(&mut output, absolute_deadline_millis);
    output.push(
        match policy
            .deadline
            .map(|value| value.scope())
            .unwrap_or(memcordon_core::DeadlineScope::Attempt)
        {
            memcordon_core::DeadlineScope::Attempt => 1,
            memcordon_core::DeadlineScope::Supervision => 2,
        },
    );
    output.push(match policy.lifetime {
        memcordon_core::Lifetime::Command => 1,
        memcordon_core::Lifetime::Workload => 2,
    });
    for duration in [
        policy.poll_interval,
        policy.signal_grace,
        policy.command_exit_grace,
        policy.limit_grace,
    ] {
        output.extend_from_slice(&(duration.as_millis() as u64).to_be_bytes());
    }
    put_count(&mut output, 5)?;
    output.extend_from_slice(&[1, 2, 3, 4, 5]);
    Ok(output)
}

fn put_count(output: &mut Vec<u8>, value: usize) -> Result<(), String> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| "launch count overflow".to_owned())?
            .to_be_bytes(),
    );
    Ok(())
}
fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    if value.len() > MAX_NATIVE_VALUE {
        return Err("launch native value exceeds protocol limit".to_owned());
    }
    put_count(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}
fn put_optional(output: &mut Vec<u8>, value: Option<u64>) {
    output.push(u8::from(value.is_some()));
    if let Some(value) = value {
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn monotonic_millis() -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is an initialized writable timespec of the exact ABI size;
    // CLOCK_MONOTONIC has no additional pointer, lifetime, or thread requirements.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut value) } != 0 {
        return Err(format!(
            "sealed monotonic clock unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err("sealed monotonic clock returned an invalid timespec".to_owned());
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| "sealed monotonic clock seconds are not representable".to_owned())?;
    let nanoseconds = u64::try_from(value.tv_nsec)
        .map_err(|_| "sealed monotonic clock nanoseconds are not representable".to_owned())?;
    Ok(seconds
        .saturating_mul(1000)
        .saturating_add(nanoseconds / 1_000_000))
}

pub(crate) fn effective_deadline_duration(
    policy: &memcordon_core::Policy,
    context: crate::supervisor::AttemptContext,
    setup_elapsed: Duration,
) -> Option<Duration> {
    policy.deadline.map(|deadline| match deadline.scope() {
        memcordon_core::DeadlineScope::Attempt => deadline.duration(),
        memcordon_core::DeadlineScope::Supervision => {
            context.supervision_deadline_remaining.map_or_else(
                || deadline.duration(),
                |remaining| remaining.saturating_sub(setup_elapsed),
            )
        }
    })
}

fn pidfd_self() -> Result<OwnedFd, String> {
    // SAFETY: getpid has no pointer arguments; pidfd_open receives the live caller pid and flags 0.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
    if fd < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        // SAFETY: a nonnegative successful pidfd_open result is newly owned by this process.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn encoded_frame(
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let total = HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "frame overflow".to_owned())?;
    if total > MAX_FRAME {
        return Err("frame exceeds protocol limit".to_owned());
    }
    let total = u32::try_from(total).map_err(|_| "frame exceeds protocol limit".to_owned())?;
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&attempt);
    bytes.extend_from_slice(&Sha256::digest(payload));
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn send_with_descriptors(
    stream: &UnixStream,
    bytes: &[u8],
    descriptors: &[i32],
) -> Result<(), String> {
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: CMSG_SPACE is a pure ABI sizing macro and the descriptor byte count fits u32.
    let length = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) } as usize;
    let mut control = vec![0_u8; length];
    // SAFETY: an all-zero msghdr is the required empty initialization before assigning its buffers.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: message_control points at `control`, sized with CMSG_SPACE and alive below.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    // SAFETY: `header` lies within `control`; CMSG_LEN bounds the exact descriptor copy and
    // descriptors are borrowed for the duration of sendmsg without transferring local ownership.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as usize;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            libc::CMSG_DATA(header).cast(),
            descriptors.len(),
        );
    }
    // SAFETY: all iovec/control pointers refer to live immutable buffers through this synchronous call.
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const message, libc::MSG_NOSIGNAL) };
    if sent != bytes.len() as isize {
        return Err("short provider launch transaction".to_owned());
    }
    Ok(())
}

pub(crate) fn parse_terminal(payload: &[u8]) -> Result<TerminalReceipt, String> {
    let text = std::str::from_utf8(payload).map_err(|_| "terminal receipt encoding".to_owned())?;
    if !payload.ends_with(b"\n") {
        return Err("terminal receipt is not newline terminated".to_owned());
    }
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| "terminal receipt field is malformed".to_owned())?;
        if name.is_empty() || fields.insert(name, value).is_some() {
            return Err("terminal receipt contains an empty or duplicate field".to_owned());
        }
    }
    let status = take_terminal_field(&mut fields, "status")?
        .parse()
        .map_err(|_| "terminal status invalid".to_owned())?;
    let exec_name = take_terminal_field(&mut fields, "exec-status")?;
    let exec_os_code = match take_terminal_field(&mut fields, "exec-os-code")? {
        "none" => None,
        value => Some(
            value
                .parse::<i32>()
                .map_err(|_| "terminal exec OS code invalid".to_owned())?,
        ),
    };
    let spawn_error_reported = take_terminal_fact(&mut fields, "spawn-error-reported")?;
    if !spawn_error_reported {
        return Err("terminal receipt omitted verified spawn-error reporting".to_owned());
    }
    let exec_status = match (exec_name, exec_os_code) {
        ("success", None) => TerminalExecStatus::Succeeded,
        ("not-found", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::NotFound,
            os_code,
        },
        ("not-executable", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::NotExecutable,
            os_code,
        },
        ("failed", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::Other,
            os_code,
        },
        _ => return Err("terminal exec status and OS code are contradictory".to_owned()),
    };
    if let TerminalExecStatus::Failed { class, os_code } = exec_status {
        if os_code <= 0 || classify_terminal_exec_error(os_code) != class {
            return Err("terminal exec errno classification mismatch".to_owned());
        }
        let expected_status = match class {
            TerminalExecFailureClass::NotFound => 127,
            TerminalExecFailureClass::NotExecutable | TerminalExecFailureClass::Other => 126,
        };
        if status != expected_status {
            return Err("terminal exec failure and child status are contradictory".to_owned());
        }
    }
    let target_pid = take_terminal_field(&mut fields, "target-pid")?
        .parse()
        .map_err(|_| "terminal target pid invalid".to_owned())?;
    let authorization_offset_millis =
        take_terminal_field(&mut fields, "authorization-offset-millis")?
            .parse()
            .map_err(|_| "terminal authorization offset invalid".to_owned())?;
    let receipt = TerminalReceipt {
        status,
        exec_status,
        spawn_error_reported,
        target_pid,
        authorization_offset_millis,
        assignment_verified: take_terminal_fact(&mut fields, "assignment-verified")?,
        namespaces_verified: take_terminal_fact(&mut fields, "namespaces-verified")?,
        credentials_verified: take_terminal_fact(&mut fields, "credentials-verified")?,
        capabilities_empty: take_terminal_fact(&mut fields, "capabilities-empty")?,
        descriptors_verified: take_terminal_fact(&mut fields, "descriptors-verified")?,
        cgroup_view_denied: take_terminal_fact(&mut fields, "cgroup-view-denied")?,
        guardian_ready: take_terminal_fact(&mut fields, "guardian-ready-before-authorization")?,
        frontend_loss_authority: take_terminal_fact(
            &mut fields,
            "frontend-loss-authority-verified",
        )?,
        cgroup_kill: take_terminal_fact(&mut fields, "cgroup-kill-invoked")?,
        cgroup_empty: take_terminal_fact(&mut fields, "cgroup-empty")?,
        init_reaped: take_terminal_fact(&mut fields, "init-reaped")?,
        guardian_reaped: take_terminal_fact(&mut fields, "guardian-reaped")?,
        boundary_retired: take_terminal_fact(&mut fields, "boundary-retired")?,
        memory_limit_exceeded: take_terminal_fact(&mut fields, "memory-limit-exceeded")?,
        deadline_exceeded: take_terminal_fact(&mut fields, "deadline-exceeded")?,
    };
    if fields.is_empty() {
        Ok(receipt)
    } else {
        Err("terminal receipt contains unknown fields".to_owned())
    }
}

fn take_terminal_field<'a>(
    fields: &mut std::collections::BTreeMap<&'a str, &'a str>,
    name: &str,
) -> Result<&'a str, String> {
    fields
        .remove(name)
        .ok_or_else(|| format!("terminal field {name} missing"))
}

fn take_terminal_fact<'a>(
    fields: &mut std::collections::BTreeMap<&'a str, &'a str>,
    name: &str,
) -> Result<bool, String> {
    match take_terminal_field(fields, name)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("terminal fact {name} invalid")),
    }
}

fn classify_terminal_exec_error(os_code: i32) -> TerminalExecFailureClass {
    match os_code {
        libc::ENOENT | libc::ENOTDIR => TerminalExecFailureClass::NotFound,
        libc::EACCES | libc::EPERM | libc::ENOEXEC | libc::EISDIR => {
            TerminalExecFailureClass::NotExecutable
        }
        _ => TerminalExecFailureClass::Other,
    }
}

fn nonce() -> Result<[u8; 16], String> {
    let mut bytes = [0_u8; 16];
    let mut file = fs::File::open("/dev/urandom").map_err(|error| error.to_string())?;
    file.read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn write_frame(
    stream: &mut UnixStream,
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: &[u8],
) -> Result<(), String> {
    let total = HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "frame length overflow".to_owned())?;
    if total > MAX_FRAME {
        return Err("frame too large".to_owned());
    }
    let digest = Sha256::digest(payload);
    stream
        .write_all(&VERSION.to_be_bytes())
        .and_then(|()| stream.write_all(&kind.to_be_bytes()))
        .and_then(|()| stream.write_all(&(total as u32).to_be_bytes()))
        .and_then(|()| stream.write_all(&nonce))
        .and_then(|()| stream.write_all(&attempt))
        .and_then(|()| stream.write_all(&digest))
        .and_then(|()| stream.write_all(payload))
        .map_err(|error| error.to_string())
}

struct WireFrame {
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: Vec<u8>,
}

fn read_frame(stream: &mut UnixStream) -> Result<WireFrame, String> {
    let mut header = [0_u8; HEADER_LENGTH];
    stream
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if u16::from_be_bytes([header[0], header[1]]) != VERSION {
        return Err("unsupported provider protocol".to_owned());
    }
    let kind = u16::from_be_bytes([header[2], header[3]]);
    let total = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if !(HEADER_LENGTH..=MAX_FRAME).contains(&total) {
        return Err("invalid provider frame length".to_owned());
    }
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&header[8..24]);
    let mut attempt = [0; 16];
    attempt.copy_from_slice(&header[24..40]);
    let mut payload = vec![0; total - HEADER_LENGTH];
    stream
        .read_exact(&mut payload)
        .map_err(|error| error.to_string())?;
    if Sha256::digest(&payload).as_slice() != &header[40..72] {
        return Err("provider payload digest mismatch".to_owned());
    }
    Ok(WireFrame {
        kind,
        nonce,
        attempt,
        payload,
    })
}
