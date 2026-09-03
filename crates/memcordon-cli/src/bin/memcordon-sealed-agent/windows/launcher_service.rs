use std::io;
use std::ptr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use memcordon_core::{
    BoundaryMechanismEvidence, ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary,
    CredentialTransitionDisposition, DeadlineEvidence, DeadlineScope, Interruption, LimitEvidence,
    RestartSafetyProof, RunOutcome, WINDOWS_CONTROL_SERVICE_NAME, WINDOWS_LAUNCHER_PIPE,
    WINDOWS_LAUNCHER_SERVICE_NAME, WINDOWS_PRIVATE_PROTOCOL_VERSION,
    WindowsCleanupProcessCreationEvidenceV1, WindowsLaunchBrokerRequestV1,
    WindowsLauncherRequestV1, WindowsLauncherResponseV1, WindowsSealedEvidenceV2,
    WindowsSealedFault, WindowsTerminalReceiptV1,
};
use windows_sys::Win32::Foundation::{
    GetLastError, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, SetEvent,
    TerminateProcess, WaitForMultipleObjects, WaitForSingleObject,
};

use super::job::{Job, JobNotification};
use super::pipe::{self, OwnedHandle, PipeListener, PipePreparationError};
use super::process::{StreamSet, SuspendedTarget};
use super::security::{SecurityDescriptor, private_pipe_sddl};

const LIMIT_STATUS: u32 = 0xC000_0017;
const CANCEL_STATUS: u32 = 0xC000_013A;
const DEADLINE_STATUS: u32 = 0xC000_0102;
const GUARDIAN_STARTUP_TIMEOUT_MILLIS: u32 = 10_000;

struct LaunchAttemptError {
    code: &'static str,
    detail: String,
    os_code: Option<i32>,
    phase: Option<memcordon_core::BoundarySetupPhase>,
    connection_must_close: bool,
    mutant_observation: Option<Box<memcordon_core::WindowsMutantNativeObservationV1>>,
    terminal_candidate: Option<Box<WindowsTerminalReceiptV1>>,
}

impl From<String> for LaunchAttemptError {
    fn from(detail: String) -> Self {
        Self {
            code: "MCSEALED-WINDOWS-LAUNCH",
            detail,
            os_code: None,
            phase: None,
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }
}

impl LaunchAttemptError {
    fn guardian_bootstrap(error: super::process::GuardianBootstrapError) -> Self {
        let role = error
            .role
            .map_or("none", super::guardian::GuardianHandleRole::name);
        let identity = error.guardian_identity.as_ref();
        let loader_context = error.loader_subphase.map_or(
            "none",
            super::process::GuardianLoaderPreparationSubphase::name,
        );
        Self {
            code: "MCSEALED-WINDOWS-GUARDIAN-BOOTSTRAP",
            detail: format!(
                "outcome={} loader_context={loader_context} subphase={} role={role} guardian_pid={} guardian_creation_time_100ns={} elapsed_millis={} exit_code={} detail={}",
                error.outcome.name(),
                error.subphase.name(),
                identity.map_or(0, |value| value.process_id),
                identity.map_or(0, |value| value.creation_time_100ns),
                error.elapsed_millis,
                error
                    .exit_code
                    .map_or_else(|| "none".to_owned(), |code| code.to_string()),
                error.detail,
            ),
            os_code: error.native_code,
            phase: Some(memcordon_core::BoundarySetupPhase::GuardianStartup),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn guardian_startup(diagnostic: GuardianStartupDiagnostic) -> Self {
        let role = diagnostic
            .role
            .map_or("none", super::guardian::GuardianHandleRole::name);
        Self {
            code: "MCSEALED-WINDOWS-GUARDIAN-STARTUP",
            detail: format!(
                "outcome={} subphase={} role={role} guardian_pid={} guardian_creation_time_100ns={} elapsed_millis={} exit_code={}",
                diagnostic.outcome.name(),
                diagnostic.subphase.name(),
                diagnostic.guardian_identity.process_id,
                diagnostic.guardian_identity.creation_time_100ns,
                diagnostic.elapsed_millis,
                diagnostic
                    .exit_code
                    .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            ),
            os_code: diagnostic.native_code,
            phase: Some(memcordon_core::BoundarySetupPhase::GuardianStartup),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn target_create(error: super::process::TargetCreateError) -> Self {
        let code = match error.os_code {
            Some(2 | 3) => "MCSPAWN-NOT-FOUND",
            Some(5 | 193) => "MCSPAWN-NOT-EXECUTABLE",
            _ => "MCSPAWN-FAILED",
        };
        Self {
            code,
            detail: error.detail,
            os_code: error.os_code,
            phase: Some(memcordon_core::BoundarySetupPhase::TargetCreation),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn process_inventory(error: super::process::ProcessIdentityObservationError) -> Self {
        Self {
            code: "MCSEALED-WINDOWS-PROCESS-INVENTORY",
            detail: error.to_string(),
            os_code: error.os_code(),
            phase: Some(memcordon_core::BoundarySetupPhase::Monitoring),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn cleanup_marker(
        subphase: &'static str,
        path: &std::path::Path,
        error: std::io::Error,
    ) -> Self {
        Self {
            code: "MCSEALED-WINDOWS-CLEANUP-MARKER",
            detail: format!("subphase={subphase} path={} detail={error}", path.display()),
            os_code: error.raw_os_error(),
            phase: Some(memcordon_core::BoundarySetupPhase::Retirement),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn cleanup_producer_failure(
        failure: super::qualification::CleanupProcessCreationProducerFailureV1,
    ) -> Self {
        let code = match failure.code.as_str() {
            "MCSEALED-WINDOWS-CLEANUP-PRODUCER-IO" => "MCSEALED-WINDOWS-CLEANUP-PRODUCER-IO",
            _ => "MCSEALED-WINDOWS-CLEANUP-PRODUCER",
        };
        Self {
            code,
            detail: format!(
                "producer_phase={:?} attempted_phase={:?} operation={:?} path_role={:?} io_error_kind={:?} detail={} secondary_publication_failure={:?}",
                failure.last_completed_phase,
                failure.attempted_phase,
                failure.operation,
                failure.path_role,
                failure.io_error_kind,
                failure.detail,
                failure.secondary_publication_failure,
            ),
            os_code: failure.os_code,
            phase: Some(memcordon_core::BoundarySetupPhase::Retirement),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn cleanup_child_spawn(
        code: String,
        phase: super::qualification::CleanupProcessCreationFailurePhaseV1,
        os_code: Option<i32>,
        detail: String,
    ) -> Self {
        Self {
            code: if code == "MCSEALED-WINDOWS-CLEANUP-CHILD-SPAWN" {
                "MCSEALED-WINDOWS-CLEANUP-CHILD-SPAWN"
            } else {
                "MCSEALED-WINDOWS-CLEANUP-PRODUCER"
            },
            detail: format!("producer_phase={phase:?} detail={detail}"),
            os_code,
            phase: Some(memcordon_core::BoundarySetupPhase::Retirement),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn cleanup_producer_abrupt(detail: String) -> Self {
        Self {
            code: "MCSEALED-WINDOWS-CLEANUP-PRODUCER-ABRUPT",
            detail,
            os_code: None,
            phase: Some(memcordon_core::BoundarySetupPhase::Retirement),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn cleanup_producer_timeout(detail: String) -> Self {
        Self {
            code: "MCSEALED-WINDOWS-CLEANUP-PRODUCER-TIMEOUT",
            detail,
            os_code: None,
            phase: Some(memcordon_core::BoundarySetupPhase::Retirement),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn certification_fault(
        fault: WindowsSealedFault,
        phase: memcordon_core::BoundarySetupPhase,
    ) -> Self {
        let rendered = serde_json::to_value(fault)
            .map_or_else(|_| "unknown".to_owned(), |value| value.to_string());
        Self {
            code: "MCSEALED-WINDOWS-CERTIFICATION-FAULT",
            detail: format!("injected certification fault: {rendered}"),
            os_code: None,
            phase: Some(phase),
            connection_must_close: false,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn mutant_observed(
        observation: memcordon_core::WindowsMutantNativeObservationV1,
        phase: memcordon_core::BoundarySetupPhase,
    ) -> Self {
        Self {
            code: "MCSEALED-WINDOWS-MUTANT-OBSERVED",
            detail: "an executable mutant produced a native invariant violation".to_owned(),
            os_code: None,
            phase: Some(phase),
            connection_must_close: false,
            mutant_observation: Some(Box::new(observation)),
            terminal_candidate: None,
        }
    }

    fn mutant_candidate(
        observation: memcordon_core::WindowsMutantNativeObservationV1,
        candidate: WindowsTerminalReceiptV1,
    ) -> Self {
        Self::mutant_observed(observation, memcordon_core::BoundarySetupPhase::Retirement)
            .with_terminal_candidate(candidate)
    }

    fn with_terminal_candidate(mut self, candidate: WindowsTerminalReceiptV1) -> Self {
        self.terminal_candidate = Some(Box::new(candidate));
        self
    }

    fn terminal_transport(subphase: &'static str, detail: String) -> Self {
        Self {
            code: "MCSEALED-WINDOWS-TERMINAL-TRANSPORT",
            detail: format!("subphase={subphase} detail={detail}"),
            os_code: None,
            phase: Some(memcordon_core::BoundarySetupPhase::Retirement),
            connection_must_close: true,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }

    fn authority_loss(detail: String) -> Self {
        Self {
            code: "MCSEALED-WINDOWS-AUTHORITY-LOSS",
            detail,
            os_code: None,
            phase: Some(memcordon_core::BoundarySetupPhase::Retirement),
            connection_must_close: true,
            mutant_observation: None,
            terminal_candidate: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardianStartupOutcome {
    GuardianExited,
    GuardianLiveTimeout,
    WaitFailed,
    ReadyThenExited,
    ImpossibleResult,
}

impl GuardianStartupOutcome {
    const fn name(self) -> &'static str {
        match self {
            Self::GuardianExited => "guardian-exited",
            Self::GuardianLiveTimeout => "guardian-live-timeout",
            Self::WaitFailed => "wait-failed",
            Self::ReadyThenExited => "ready-then-exited",
            Self::ImpossibleResult => "impossible-result",
        }
    }
}

#[derive(Debug)]
struct GuardianStartupDiagnostic {
    outcome: GuardianStartupOutcome,
    subphase: super::guardian::GuardianStartupSubphase,
    role: Option<super::guardian::GuardianHandleRole>,
    guardian_identity: memcordon_core::WindowsProcessIdentityV1,
    exit_code: Option<u32>,
    native_code: Option<i32>,
    elapsed_millis: u64,
}

fn inject_fault(
    request: &WindowsLaunchBrokerRequestV1,
    faults: &[WindowsSealedFault],
    phase: memcordon_core::BoundarySetupPhase,
) -> Result<(), LaunchAttemptError> {
    if let Some(fault) = request
        .certification_fault
        .filter(|fault| faults.contains(fault))
    {
        Err(LaunchAttemptError::certification_fault(fault, phase))
    } else {
        Ok(())
    }
}

struct ActiveJob {
    attempt_id: String,
    job: JobView,
}

struct JobView(OwnedHandle);

impl JobView {
    fn contains(&self, process: HANDLE) -> Result<bool, String> {
        let mut inside = 0;
        // SAFETY: both process and duplicated active Job handles are live.
        if unsafe {
            windows_sys::Win32::System::JobObjects::IsProcessInJob(
                process,
                self.0.raw(),
                &raw mut inside,
            )
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(inside != 0)
        }
    }

    fn terminate(&self) -> Result<(), String> {
        // SAFETY: the active registry owns this duplicated Job handle until
        // the per-attempt worker unregisters it after cleanup.
        if unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0.raw(), CANCEL_STATUS)
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }
}

static ACTIVE_JOBS: LazyLock<Mutex<Vec<ActiveJob>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static FALLBACK_CLEANUP_FAILURES: LazyLock<Mutex<std::collections::BTreeMap<String, Vec<String>>>> =
    LazyLock::new(|| Mutex::new(std::collections::BTreeMap::new()));

const STARTUP_PROCESS_PROTECTION: u32 = 0x4d43_0201;
const STARTUP_STATE_RECOVERY: u32 = 0x4d43_0202;
const STARTUP_PIPE_PREPARATION: u32 = 0x4d43_0203;
const STARTUP_RUNNING_ANNOUNCEMENT: u32 = 0x4d43_0204;
const STARTUP_SERVICE_LOOP: u32 = 0x4d43_0205;
const STARTUP_PIPE_SECURITY_READBACK: u32 = 0x4d43_0206;
const STARTUP_PIPE_SECURITY_MISMATCH: u32 = 0x4d43_0207;

pub fn run() -> Result<(), String> {
    super::service::dispatch(WINDOWS_LAUNCHER_SERVICE_NAME, 2, service_main)
}

unsafe extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
    if let Err(error) = unsafe { super::service::announce_starting(WINDOWS_LAUNCHER_SERVICE_NAME) }
    {
        eprintln!("{error}");
        return;
    }
    let startup = (|| -> Result<(PipeListener, OwnedHandle), (u32, String)> {
        super::security::protect_current_service_process(WINDOWS_LAUNCHER_SERVICE_NAME)
            .map_err(|error| (STARTUP_PROCESS_PROTECTION, error))?;
        let token_policy = super::security::converge_current_service_token_peer_query(
            WINDOWS_LAUNCHER_SERVICE_NAME,
        );
        token_policy.map_err(|error| {
            super::security::token_dacl_startup_error(WINDOWS_LAUNCHER_SERVICE_NAME, error)
        })?;
        // Recovery is a capability gate: SCM must not observe RUNNING until
        // every durable attempt has been reconciled or quarantined.
        super::process::recover_guardian_slots()
            .map_err(|error| (STARTUP_STATE_RECOVERY, error))?;
        super::record::recover().map_err(|error| (STARTUP_STATE_RECOVERY, error))?;
        let listener = PipeListener::new(
            WINDOWS_LAUNCHER_PIPE,
            SecurityDescriptor::from_sddl(
                &private_pipe_sddl().map_err(|error| (STARTUP_PIPE_PREPARATION, error))?,
            )
            .map_err(|error| (STARTUP_PIPE_PREPARATION, error))?,
        );
        let first = listener.prepare().map_err(pipe_startup_error)?;
        super::service::announce_running()
            .map_err(|error| (STARTUP_RUNNING_ANNOUNCEMENT, error))?;
        Ok((listener, first))
    })();
    let result = startup.and_then(|(listener, first)| {
        serve(listener, first).map_err(|error| (STARTUP_SERVICE_LOOP, error))
    });
    if let Err((code, error)) = result {
        eprintln!("{error}");
        super::service::announce_startup_failed(code);
    } else {
        super::service::announce_stopped(0);
    }
}

pub(crate) fn pipe_startup_error(error: PipePreparationError) -> (u32, String) {
    let phase = match &error {
        PipePreparationError::Certification(_) => STARTUP_PIPE_PREPARATION,
        PipePreparationError::Creation(_) => STARTUP_PIPE_PREPARATION,
        PipePreparationError::SecurityReadback(_) => STARTUP_PIPE_SECURITY_READBACK,
        PipePreparationError::SecurityMismatch(mismatch) => {
            STARTUP_PIPE_SECURITY_MISMATCH + mismatch.scm_offset()
        }
    };
    (phase, error.to_string())
}

fn serve(listener: PipeListener, first: OwnedHandle) -> Result<(), String> {
    let mut first = Some(first);
    while !super::service::stop_requested() {
        let connection = if let Some(prepared) = first.take() {
            listener.accept_prepared(prepared)?
        } else {
            listener.accept()?
        };
        if super::service::stop_requested() {
            break;
        }
        std::thread::spawn(move || {
            let response_written = handle_control(connection.raw())
                .map_err(|error| {
                    eprintln!("MCSEALED-WINDOWS-LAUNCHER-CONNECTION: {error}");
                    error
                })
                .is_ok();
            if response_written {
                if let Err(error) = pipe::finish_server_response(connection.raw()) {
                    eprintln!("MCSEALED-WINDOWS-LAUNCHER-RESPONSE-DRAIN: {error}");
                }
            } else {
                pipe::disconnect(connection.raw());
            }
        });
    }
    Ok(())
}

fn handle_control(connection: HANDLE) -> Result<(), String> {
    // Authenticate the kernel-bound pipe peer before deserializing any request
    // or adopting any peer-supplied handle value.
    if let Err(error) = authenticate_control(connection) {
        eprintln!("MCSEALED-WINDOWS-LAUNCHER-PEER-AUTHENTICATION: {error}");
        let mut rejection = super::record::pretarget_rejection_at(
            error.code(),
            memcordon_core::BoundarySetupPhase::LauncherServiceAuthentication,
            format!(
                "control peer authentication failed at {}",
                control_authentication_subphase(error.code()).unwrap_or("unknown")
            ),
        );
        rejection.os_code = error.os_code;
        return pipe::write_frame(
            connection,
            &WindowsLauncherResponseV1::Reject {
                schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                attempt_id: String::new(),
                nonce: String::new(),
                request_sha256: String::new(),
                rejection,
            },
        );
    }
    let first: WindowsLauncherRequestV1 = pipe::read_frame(connection)?;
    match first {
        WindowsLauncherRequestV1::Probe {
            schema_version,
            challenge,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION => {
            let attestation = super::token::current_service_self_attestation(
                "launcher-service",
                WINDOWS_LAUNCHER_SERVICE_NAME,
                super::package::LAUNCHER_PRIVILEGES,
                &challenge,
            )
            .map_err(|error| error.to_string())?;
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::Probe {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    attestation,
                },
            )
        }
        WindowsLauncherRequestV1::CertificationMachineRestart { schema_version }
            if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION =>
        {
            let recovered = super::record::certify_machine_restart_recovery()?;
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::CertificationMachineRestart {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    recovered,
                },
            )
        }
        WindowsLauncherRequestV1::PackageCleanup {
            schema_version,
            deadline_millis,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION && deadline_millis != 0 => {
            let result = converge_package_cleanup(deadline_millis);
            let (status, attempts_empty, detail) = match result {
                Ok(()) => (
                    memcordon_core::WindowsControlRequestStatusV1::Ready,
                    Some(true),
                    "launcher package cleanup converged".to_owned(),
                ),
                Err(error)
                    if error
                        .strip_prefix("MCSEALED-WINDOWS-PACKAGE-ACTIVE:")
                        .is_some()
                        || error
                            .strip_prefix("MCSEALED-WINDOWS-RECOVERY-AMBIGUOUS:")
                            .is_some() =>
                {
                    let detail = if error
                        .strip_prefix("MCSEALED-WINDOWS-PACKAGE-ACTIVE:")
                        .is_some()
                    {
                        error
                    } else {
                        format!("MCSEALED-WINDOWS-PACKAGE-ACTIVE: {error}")
                    };
                    (
                        memcordon_core::WindowsControlRequestStatusV1::Active,
                        Some(false),
                        detail,
                    )
                }
                Err(error) => (
                    memcordon_core::WindowsControlRequestStatusV1::Failed,
                    None,
                    error,
                ),
            };
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::PackageCleanup {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    status,
                    attempts_empty,
                    detail,
                },
            )
        }
        WindowsLauncherRequestV1::ReplayTerminal {
            schema_version,
            attempt_id,
            nonce,
            request_sha256,
            relay_phase,
            caller_process_identity,
            caller_token_sha256,
            terminalization_error,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
            && !attempt_id.is_empty()
            && !nonce.is_empty()
            && !request_sha256.is_empty()
            && caller_process_identity.process_id != 0
            && caller_process_identity.creation_time_100ns != 0
            && !caller_token_sha256.is_empty() =>
        {
            if let Some(error) = terminalization_error {
                super::record::record_terminalization_diagnostic(&attempt_id, error)?;
            }
            let pending_terminal = super::record::pending_terminal_response(
                &attempt_id,
                &nonce,
                &request_sha256,
                &caller_process_identity,
                &caller_token_sha256,
            );
            let Some(response) = (match pending_terminal {
                Ok(response) => response,
                Err(error) => {
                    return pipe::write_frame(
                        connection,
                        &bound_launcher_replay_failure_response(
                            &attempt_id,
                            &nonce,
                            &request_sha256,
                            relay_phase,
                            error,
                        ),
                    );
                }
            }) else {
                let pending = match super::record::replay_unstaged_evidence(
                    &attempt_id,
                    &nonce,
                    &request_sha256,
                    relay_phase,
                    &caller_process_identity,
                    &caller_token_sha256,
                ) {
                    Ok(pending) => pending,
                    Err(error) => {
                        return pipe::write_frame(
                            connection,
                            &bound_launcher_replay_failure_response(
                                &attempt_id,
                                &nonce,
                                &request_sha256,
                                relay_phase,
                                error,
                            ),
                        );
                    }
                };
                if let Some(evidence) = pending {
                    let response = match evidence {
                        super::record::ReplayUnstagedEvidence::Pending(pending) => {
                            WindowsLauncherResponseV1::ReplayPending(pending)
                        }
                        super::record::ReplayUnstagedEvidence::Retained(retained) => {
                            WindowsLauncherResponseV1::AttemptRetained(retained)
                        }
                    };
                    return pipe::write_frame(connection, &response);
                }
                let retained = match super::record::replay_unavailable_evidence(
                    &attempt_id,
                    &nonce,
                    &request_sha256,
                    relay_phase,
                    &caller_process_identity,
                    &caller_token_sha256,
                ) {
                    Ok(retained) => retained,
                    Err(error) => {
                        return pipe::write_frame(
                            connection,
                            &bound_launcher_replay_failure_response(
                                &attempt_id,
                                &nonce,
                                &request_sha256,
                                relay_phase,
                                error,
                            ),
                        );
                    }
                };
                return pipe::write_frame(
                    connection,
                    &WindowsLauncherResponseV1::AttemptRetained(retained),
                );
            };
            let terminal_response_sha256 = super::record::digest(
                serde_json::to_string(&response)
                    .map_err(|error| error.to_string())?
                    .as_bytes(),
            );
            pipe::write_frame(connection, &response)?;
            wait_for_terminal_acknowledgment(
                connection,
                &attempt_id,
                &nonce,
                &request_sha256,
                &terminal_response_sha256,
            )?;
            let retired =
                super::record::acknowledge_terminal_response(&attempt_id, &nonce, &request_sha256)?;
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::TerminalRetired(retired),
            )
        }
        WindowsLauncherRequestV1::Membership {
            schema_version,
            attempt_id,
            nonce,
            request_sha256,
            remote_process_handle,
        } => {
            let process = OwnedHandle::new(remote_process_handle as usize as HANDLE)?;
            if schema_version != WINDOWS_PRIVATE_PROTOCOL_VERSION
                || attempt_id.is_empty()
                || nonce.is_empty()
                || request_sha256.is_empty()
            {
                return Err("membership request has an invalid binding".to_owned());
            }
            let inside_active_job = ACTIVE_JOBS
                .lock()
                .map_err(|_| "active Job registry is poisoned".to_owned())?
                .iter()
                .try_fold(false, |inside, active| {
                    if inside {
                        Ok(true)
                    } else {
                        active.job.contains(process.raw())
                    }
                })?;
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::Membership {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    attempt_id: attempt_id.clone(),
                    nonce: nonce.clone(),
                    request_sha256: request_sha256.clone(),
                    inside_active_job,
                },
            )?;
            let launch: WindowsLauncherRequestV1 = pipe::read_frame(connection)?;
            match launch {
                WindowsLauncherRequestV1::Launch(request) => {
                    let certification_mutant = request.certification_mutant;
                    match launch_attempt(connection, request, &attempt_id, &nonce, &request_sha256)
                    {
                        Ok(()) => Ok(()),
                        Err(mut failure) => {
                            if let Some(cleanup_failures) =
                                take_fallback_cleanup_failures(&attempt_id)
                            {
                                failure.detail = format!(
                                    "{}; fallback_cleanup_failures={}",
                                    failure.detail,
                                    cleanup_failures.join(" | ")
                                );
                            }
                            if failure.connection_must_close {
                                pipe::disconnect(connection);
                                return Err(failure.detail);
                            }
                            if let (Some(mutant), Some(observation)) =
                                (certification_mutant, failure.mutant_observation)
                            {
                                return pipe::write_frame(
                                    connection,
                                    &WindowsLauncherResponseV1::CertificationMutantObserved(
                                        memcordon_core::WindowsMutantNativeReceiptV1 {
                                            schema_version: 1,
                                            mutant,
                                            attempt_id,
                                            nonce,
                                            request_sha256,
                                            hook_observation:
                                                memcordon_core::WindowsMutantHookObservationV1::Native {
                                                    observation: *observation,
                                                },
                                            remote_observation_handle: None,
                                            terminal_candidate: failure.terminal_candidate,
                                        },
                                    ),
                                );
                            }
                            let primary_detail = failure.detail.clone();
                            let rejection = super::record::rejection_evidence(
                                &attempt_id,
                                failure.code,
                                failure.detail,
                                failure.phase,
                                failure.os_code,
                                failure.terminal_candidate,
                            )?;
                            let response = WindowsLauncherResponseV1::Reject {
                                schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                                attempt_id: attempt_id.clone(),
                                nonce: nonce.clone(),
                                request_sha256: request_sha256.clone(),
                                rejection,
                            };
                            let terminal_staged = super::record::stage_terminal_response(
                                &attempt_id,
                                &response,
                            )
                            .map_err(|secondary| {
                                format!(
                                    "{primary_detail}; secondary terminal staging failure: {secondary}"
                                )
                            })?;
                            let terminal_response_sha256 = super::record::digest(
                                serde_json::to_string(&response)
                                    .map_err(|error| error.to_string())?
                                    .as_bytes(),
                            );
                            pipe::write_frame(connection, &response).map_err(|secondary| {
                                format!(
                                    "{primary_detail}; secondary bound rejection delivery failure: {secondary}"
                                )
                            })?;
                            if terminal_staged {
                                wait_for_terminal_acknowledgment(
                                    connection,
                                    &attempt_id,
                                    &nonce,
                                    &request_sha256,
                                    &terminal_response_sha256,
                                )
                                .map_err(|secondary| {
                                    format!(
                                        "{primary_detail}; secondary terminal ACK failure: {secondary}"
                                    )
                                })?;
                                let retired = super::record::acknowledge_terminal_response(
                                    &attempt_id,
                                    &nonce,
                                    &request_sha256,
                                )
                                .map_err(|secondary| {
                                    format!(
                                        "{primary_detail}; secondary terminal retirement failure: {secondary}"
                                    )
                                })?;
                                pipe::write_frame(
                                    connection,
                                    &WindowsLauncherResponseV1::TerminalRetired(retired),
                                )
                                .map_err(|secondary| {
                                    format!(
                                        "{primary_detail}; secondary terminal retirement receipt failure: {secondary}"
                                    )
                                })?;
                            }
                            Ok(())
                        }
                    }
                }
                _ => Err("membership query was not followed by a launch request".to_owned()),
            }
        }
        _ => Err("unsupported Windows private launcher request".to_owned()),
    }
}

fn bound_launcher_replay_failure_response(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    error: String,
) -> WindowsLauncherResponseV1 {
    WindowsLauncherResponseV1::AttemptRetained(super::record::in_memory_retained_attempt_evidence(
        attempt_id,
        nonce,
        request_sha256,
        relay_phase,
        "authenticated launcher terminal replay did not complete".to_owned(),
        vec![format!("launcher replay record inspection failed: {error}")],
    ))
}

#[cfg(test)]
pub(crate) fn bound_launcher_replay_failure_response_for_test(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    error: String,
) -> WindowsLauncherResponseV1 {
    bound_launcher_replay_failure_response(attempt_id, nonce, request_sha256, relay_phase, error)
}

fn converge_package_cleanup(deadline_millis: u64) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(deadline_millis))
        .ok_or_else(|| "package cleanup deadline overflowed".to_owned())?;
    loop {
        let active_count = {
            let jobs = ACTIVE_JOBS
                .lock()
                .map_err(|_| "active Job registry is poisoned".to_owned())?;
            for active in jobs.iter() {
                active.job.terminate().map_err(|error| {
                    format!(
                        "phase=terminate-job attempt_id={} error={error}",
                        active.attempt_id
                    )
                })?;
            }
            jobs.len()
        };
        if active_count == 0 {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=wait-launcher-jobs active_jobs={active_count} deadline_millis={deadline_millis}"
            ));
        }
        std::thread::sleep(Duration::from_millis(50).min(deadline - now));
    }
    super::record::converge_package_cleanup(deadline)?;
    if super::record::attempts_empty()? {
        Ok(())
    } else {
        Err(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=durable-recovery attempts_empty=false"
                .to_owned(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlAuthenticationPhase {
    PeerPid,
    ProcessOpen,
    Image,
    TokenOpen,
    TokenUserQuery,
    AccountMismatch,
    OrdinarySid,
    RestrictingSid,
}

#[derive(Debug)]
struct ControlAuthenticationError {
    phase: ControlAuthenticationPhase,
    detail: String,
    os_code: Option<i32>,
}

impl ControlAuthenticationError {
    fn new(phase: ControlAuthenticationPhase, detail: impl ToString) -> Self {
        Self {
            phase,
            detail: detail.to_string(),
            os_code: None,
        }
    }

    fn native(
        phase: ControlAuthenticationPhase,
        detail: impl ToString,
        os_code: Option<i32>,
    ) -> Self {
        Self {
            phase,
            detail: detail.to_string(),
            os_code,
        }
    }

    const fn code(&self) -> &'static str {
        match self.phase {
            ControlAuthenticationPhase::PeerPid => "MCSEALED-WINDOWS-CONTROL-AUTH-PEER-PID",
            ControlAuthenticationPhase::ProcessOpen => "MCSEALED-WINDOWS-CONTROL-AUTH-PROCESS-OPEN",
            ControlAuthenticationPhase::Image => "MCSEALED-WINDOWS-CONTROL-AUTH-IMAGE",
            ControlAuthenticationPhase::TokenOpen => "MCSEALED-WINDOWS-CONTROL-AUTH-TOKEN-OPEN",
            ControlAuthenticationPhase::TokenUserQuery => {
                "MCSEALED-WINDOWS-CONTROL-AUTH-TOKEN-USER-QUERY"
            }
            ControlAuthenticationPhase::AccountMismatch => {
                "MCSEALED-WINDOWS-CONTROL-AUTH-ACCOUNT-MISMATCH"
            }
            ControlAuthenticationPhase::OrdinarySid => "MCSEALED-WINDOWS-CONTROL-AUTH-ORDINARY-SID",
            ControlAuthenticationPhase::RestrictingSid => {
                "MCSEALED-WINDOWS-CONTROL-AUTH-RESTRICTING-SID"
            }
        }
    }
}

impl std::fmt::Display for ControlAuthenticationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "code={} subphase={} error={}",
            self.code(),
            control_authentication_subphase(self.code()).unwrap_or("unknown"),
            self.detail
        )
    }
}

pub(crate) fn control_authentication_subphase(code: &str) -> Option<&'static str> {
    match code.as_bytes() {
        b"MCSEALED-WINDOWS-CONTROL-AUTH-PEER-PID" => Some("peer-pid"),
        b"MCSEALED-WINDOWS-CONTROL-AUTH-PROCESS-OPEN" => Some("process-open"),
        b"MCSEALED-WINDOWS-CONTROL-AUTH-IMAGE" => Some("image"),
        b"MCSEALED-WINDOWS-CONTROL-AUTH-TOKEN-OPEN" => Some("token-open"),
        b"MCSEALED-WINDOWS-CONTROL-AUTH-TOKEN-USER-QUERY" => Some("token-user-query"),
        b"MCSEALED-WINDOWS-CONTROL-AUTH-ACCOUNT-MISMATCH" => Some("account-mismatch"),
        b"MCSEALED-WINDOWS-CONTROL-AUTH-ORDINARY-SID" => Some("ordinary-service-sid"),
        b"MCSEALED-WINDOWS-CONTROL-AUTH-RESTRICTING-SID" => Some("restricting-service-sid"),
        _ => None,
    }
}

fn authenticate_control(connection: HANDLE) -> Result<(), ControlAuthenticationError> {
    let mut process_id = 0_u32;
    // SAFETY: connection is the connected server end of the private pipe.
    if unsafe { GetNamedPipeClientProcessId(connection, &raw mut process_id) } == 0 {
        let error = io::Error::last_os_error();
        return Err(ControlAuthenticationError::native(
            ControlAuthenticationPhase::PeerPid,
            &error,
            error.raw_os_error(),
        ));
    }
    // SAFETY: PID is supplied by the kernel for this pipe peer and only query
    // rights are requested.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        let error = io::Error::last_os_error();
        return Err(ControlAuthenticationError::native(
            ControlAuthenticationPhase::ProcessOpen,
            &error,
            error.raw_os_error(),
        ));
    }
    let process = OwnedHandle::new(process).map_err(|error| {
        ControlAuthenticationError::new(ControlAuthenticationPhase::ProcessOpen, error)
    })?;
    super::process::verify_image_path(process.raw(), &super::package::installed_binary()).map_err(
        |error| ControlAuthenticationError::new(ControlAuthenticationPhase::Image, error),
    )?;
    let token = super::token::process_token_detailed(process.raw()).map_err(|error| {
        ControlAuthenticationError::native(
            ControlAuthenticationPhase::TokenOpen,
            &error,
            error.os_code(),
        )
    })?;
    let account = super::token::token_user_sid(token.raw()).map_err(|error| {
        ControlAuthenticationError::new(ControlAuthenticationPhase::TokenUserQuery, error)
    })?;
    if account != "S-1-5-19" {
        return Err(ControlAuthenticationError::new(
            ControlAuthenticationPhase::AccountMismatch,
            "private launcher pipe peer is not LocalService",
        ));
    }
    let control_sid =
        super::security::service_sid(WINDOWS_CONTROL_SERVICE_NAME).map_err(|error| {
            ControlAuthenticationError::new(ControlAuthenticationPhase::OrdinarySid, error)
        })?;
    if !super::token::token_has_enabled_group(token.raw(), &control_sid).map_err(|error| {
        ControlAuthenticationError::new(ControlAuthenticationPhase::OrdinarySid, error)
    })? {
        return Err(ControlAuthenticationError::new(
            ControlAuthenticationPhase::OrdinarySid,
            "private launcher pipe peer lacks the enabled control-service SID",
        ));
    }
    if !super::token::token_has_restricting_sid(token.raw(), &control_sid).map_err(|error| {
        ControlAuthenticationError::new(ControlAuthenticationPhase::RestrictingSid, error)
    })? {
        return Err(ControlAuthenticationError::new(
            ControlAuthenticationPhase::RestrictingSid,
            "private launcher pipe peer lacks the control-service restricting SID".to_owned(),
        ));
    }
    Ok(())
}

fn guardian_process_exit_code(process: HANDLE) -> Result<u32, i32> {
    let mut exit_code = 0_u32;
    // SAFETY: process is the pinned guardian process handle and output is writable.
    if unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
        Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(exit_code)
    }
}

fn guardian_startup_diagnostic(
    outcome: GuardianStartupOutcome,
    guardian_identity: &memcordon_core::WindowsProcessIdentityV1,
    exit_code: Option<u32>,
    native_code: Option<i32>,
    started: Instant,
) -> GuardianStartupDiagnostic {
    let (subphase, role, child_native_code) = exit_code.map_or(
        (
            super::guardian::GuardianStartupSubphase::ReadyWait,
            None,
            None,
        ),
        super::guardian::startup_detail_for_exit_code,
    );
    GuardianStartupDiagnostic {
        outcome,
        subphase,
        role,
        guardian_identity: guardian_identity.clone(),
        exit_code,
        native_code: native_code.or(child_native_code),
        elapsed_millis: millis(started.elapsed()),
    }
}

fn observe_guardian_startup(
    ready: HANDLE,
    guardian: HANDLE,
    guardian_identity: &memcordon_core::WindowsProcessIdentityV1,
    timeout_millis: u32,
) -> Result<(), GuardianStartupDiagnostic> {
    let started = Instant::now();
    let watched = [ready, guardian];
    // SAFETY: both handles remain owned by the launch attempt for the bounded wait.
    let result = unsafe {
        WaitForMultipleObjects(watched.len() as u32, watched.as_ptr(), 0, timeout_millis)
    };
    match result {
        WAIT_OBJECT_0 => {
            // A signaled manual-reset event cannot be missed. Readiness is only
            // accepted while the pinned guardian process is still live.
            // SAFETY: guardian remains a live owned process handle.
            match unsafe { WaitForSingleObject(guardian, 0) } {
                WAIT_TIMEOUT => Ok(()),
                WAIT_OBJECT_0 => match guardian_process_exit_code(guardian) {
                    Ok(exit_code) => Err(guardian_startup_diagnostic(
                        GuardianStartupOutcome::ReadyThenExited,
                        guardian_identity,
                        Some(exit_code),
                        None,
                        started,
                    )),
                    Err(native_code) => Err(guardian_startup_diagnostic(
                        GuardianStartupOutcome::WaitFailed,
                        guardian_identity,
                        None,
                        Some(native_code),
                        started,
                    )),
                },
                WAIT_FAILED => {
                    // SAFETY: GetLastError is read immediately after the failed wait.
                    let native_code = unsafe { GetLastError() } as i32;
                    Err(guardian_startup_diagnostic(
                        GuardianStartupOutcome::WaitFailed,
                        guardian_identity,
                        None,
                        Some(native_code),
                        started,
                    ))
                }
                _ => Err(guardian_startup_diagnostic(
                    GuardianStartupOutcome::ImpossibleResult,
                    guardian_identity,
                    None,
                    None,
                    started,
                )),
            }
        }
        value if value == WAIT_OBJECT_0 + 1 => match guardian_process_exit_code(guardian) {
            Ok(exit_code) => Err(guardian_startup_diagnostic(
                GuardianStartupOutcome::GuardianExited,
                guardian_identity,
                Some(exit_code),
                None,
                started,
            )),
            Err(native_code) => Err(guardian_startup_diagnostic(
                GuardianStartupOutcome::WaitFailed,
                guardian_identity,
                None,
                Some(native_code),
                started,
            )),
        },
        WAIT_TIMEOUT => {
            // Recheck process liveness at the deadline so this outcome proves
            // the guardian, rather than a stale process handle, was still live.
            // SAFETY: guardian remains a live owned process handle.
            match unsafe { WaitForSingleObject(guardian, 0) } {
                WAIT_TIMEOUT => Err(guardian_startup_diagnostic(
                    GuardianStartupOutcome::GuardianLiveTimeout,
                    guardian_identity,
                    None,
                    None,
                    started,
                )),
                WAIT_OBJECT_0 => match guardian_process_exit_code(guardian) {
                    Ok(exit_code) => Err(guardian_startup_diagnostic(
                        GuardianStartupOutcome::GuardianExited,
                        guardian_identity,
                        Some(exit_code),
                        None,
                        started,
                    )),
                    Err(native_code) => Err(guardian_startup_diagnostic(
                        GuardianStartupOutcome::WaitFailed,
                        guardian_identity,
                        None,
                        Some(native_code),
                        started,
                    )),
                },
                WAIT_FAILED => {
                    // SAFETY: GetLastError is read immediately after the failed wait.
                    let native_code = unsafe { GetLastError() } as i32;
                    Err(guardian_startup_diagnostic(
                        GuardianStartupOutcome::WaitFailed,
                        guardian_identity,
                        None,
                        Some(native_code),
                        started,
                    ))
                }
                _ => Err(guardian_startup_diagnostic(
                    GuardianStartupOutcome::ImpossibleResult,
                    guardian_identity,
                    None,
                    None,
                    started,
                )),
            }
        }
        WAIT_FAILED => {
            // SAFETY: GetLastError is read immediately after WaitForMultipleObjects.
            let native_code = unsafe { GetLastError() } as i32;
            Err(guardian_startup_diagnostic(
                GuardianStartupOutcome::WaitFailed,
                guardian_identity,
                None,
                Some(native_code),
                started,
            ))
        }
        _ => Err(guardian_startup_diagnostic(
            GuardianStartupOutcome::ImpossibleResult,
            guardian_identity,
            None,
            None,
            started,
        )),
    }
}

#[cfg(test)]
pub(crate) fn guardian_startup_observation_for_test(
    ready: HANDLE,
    guardian: HANDLE,
    timeout_millis: u32,
) -> Result<(), (String, Option<i32>)> {
    let identity = super::process::process_identity(guardian)
        .map_err(|detail| (detail, io::Error::last_os_error().raw_os_error()))?;
    observe_guardian_startup(ready, guardian, &identity, timeout_millis).map_err(|diagnostic| {
        let failure = LaunchAttemptError::guardian_startup(diagnostic);
        (failure.detail, failure.os_code)
    })
}

#[cfg(test)]
pub(crate) fn guardian_state_after_observation_for_test(
    readiness_observed: bool,
) -> super::record::WindowsAttemptStateV1 {
    if readiness_observed {
        super::record::WindowsAttemptStateV1::GuardianReady
    } else {
        super::record::WindowsAttemptStateV1::BoundaryCreated
    }
}

fn launch_attempt(
    connection: HANDLE,
    request: WindowsLaunchBrokerRequestV1,
    expected_attempt_id: &str,
    expected_nonce: &str,
    expected_request_sha256: &str,
) -> Result<(), LaunchAttemptError> {
    // Adopt every transferred handle before any fallible validation so every
    // rejection path closes the launcher's copies.
    let primary_token = OwnedHandle::new(request.remote_primary_token_handle as usize as HANDLE)?;
    let frontend = OwnedHandle::new(request.remote_frontend_process_handle as usize as HANDLE)?;
    let frontend_canaries = request
        .remote_frontend_canary_handles
        .iter()
        .copied()
        .map(|raw| OwnedHandle::new(raw as usize as HANDLE))
        .collect::<Result<Vec<_>, _>>()?;
    let loader_restriction_canary_handles = request
        .loader_restriction_canary
        .as_ref()
        .map(|pair| {
            Ok::<_, String>((
                OwnedHandle::new(pair.remote_baseline_token_handle as usize as HANDLE)?,
                OwnedHandle::new(pair.remote_comparison_token_handle as usize as HANDLE)?,
                OwnedHandle::new(pair.remote_no_restricting_sid_token_handle as usize as HANDLE)?,
                OwnedHandle::new(pair.remote_profile_token_handle as usize as HANDLE)?,
                pair.source_binding_sha256.clone(),
                pair.pair_invariants_sha256.clone(),
                pair.restriction_presence_binding_sha256.clone(),
                pair.profile_binding_sha256.clone(),
            ))
        })
        .transpose()?;
    if request.attempt_id != expected_attempt_id
        || request.launch.nonce != expected_nonce
        || request.request_sha256 != expected_request_sha256
    {
        return Err("launch request does not match its membership binding"
            .to_owned()
            .into());
    }
    super::process::verify_not_inheritable(primary_token.raw())?;
    super::process::verify_not_inheritable(frontend.raw())?;
    for handle in &frontend_canaries {
        super::process::verify_not_inheritable(handle.raw())?;
    }
    let digest_length = super::record::digest(&[]).len();
    if request.schema_version != WINDOWS_PRIVATE_PROTOCOL_VERSION
        || request.attempt_id.len() != digest_length
        || request.request_sha256.len() != digest_length
    {
        return Err("invalid Windows launch broker request identity"
            .to_owned()
            .into());
    }
    let launch_bytes = serde_json::to_vec(&request.launch).map_err(|error| error.to_string())?;
    let request_sha256 = super::record::digest(&launch_bytes);
    let mut attempt_identity = request.launch.nonce.as_bytes().to_vec();
    attempt_identity.extend_from_slice(&request.caller_process_identity.process_id.to_le_bytes());
    attempt_identity.extend_from_slice(
        &request
            .caller_process_identity
            .creation_time_100ns
            .to_le_bytes(),
    );
    attempt_identity.extend_from_slice(request_sha256.as_bytes());
    if request.request_sha256 != request_sha256
        || request.attempt_id != super::record::digest(&attempt_identity)
    {
        return Err("Windows launch broker request digest or attempt id differs"
            .to_owned()
            .into());
    }
    if request.launch.nonce.is_empty()
        || request.launch.nonce.contains('\0')
        || request.launch.current_directory.is_empty()
        || request.launch.current_directory.contains(&0)
    {
        return Err(
            "Windows launch request nonce or current directory is invalid"
                .to_owned()
                .into(),
        );
    }
    if request.certification_fault == Some(WindowsSealedFault::LauncherPeerVerify) {
        authenticate_control(connection)
            .map_err(|error| LaunchAttemptError::from(error.to_string()))?;
        return Err(LaunchAttemptError::certification_fault(
            WindowsSealedFault::LauncherPeerVerify,
            memcordon_core::BoundarySetupPhase::LauncherServiceAuthentication,
        ));
    }
    if super::process::process_identity(frontend.raw())? != request.caller_process_identity {
        return Err(
            "frontend process handle does not match authenticated caller identity"
                .to_owned()
                .into(),
        );
    }
    let duplicated_primary_envelope = super::token::envelope(primary_token.raw())?;
    if duplicated_primary_envelope != request.caller_token_envelope {
        let mismatch_fields = super::token::envelope_mismatch_fields(
            &request.caller_token_envelope,
            &duplicated_primary_envelope,
        );
        return Err(format!(
            "duplicated primary token does not match authenticated caller envelope (fields: {})",
            mismatch_fields.join(", ")
        )
        .into());
    }
    let loader_restriction_canary = loader_restriction_canary_handles
        .map(
            |(
                baseline,
                comparison,
                no_restricting_sid,
                profile,
                source_binding_sha256,
                pair_invariants_sha256,
                restriction_presence_binding_sha256,
                profile_binding_sha256,
            )| {
                super::process::LoaderRestrictionCanaryTokens::from_transferred(
                    primary_token.raw(),
                    baseline,
                    comparison,
                    no_restricting_sid,
                    profile,
                    source_binding_sha256,
                    pair_invariants_sha256,
                    restriction_presence_binding_sha256,
                    profile_binding_sha256,
                )
            },
        )
        .transpose()?;
    super::record::reserve_attempt(&request.attempt_id, &request.request_sha256)?;
    // Keep the durable admission until the first authenticated attempt record
    // has been stored. Package mutation therefore sees either the admission or
    // the attempt across the complete authority handoff.
    super::record::validate_admission(&request.attempt_id, &request.request_sha256)?;

    let started = Instant::now();
    let job = Job::create(
        request.launch.policy.memory_limit_bytes,
        request.certification_fault,
        request.certification_mutant,
    )
    .map_err(|detail| {
        if let Some(fault) = request.certification_fault {
            LaunchAttemptError::certification_fault(
                fault,
                memcordon_core::BoundarySetupPhase::BoundaryCreation,
            )
        } else {
            LaunchAttemptError::from(detail)
        }
    })?;
    if request.certification_mutant == Some(memcordon_core::WindowsSealedMutant::PermitBreakaway)
        && job.breakaway_allowed()?
    {
        return Err(LaunchAttemptError::mutant_observed(
            memcordon_core::WindowsMutantNativeObservationV1::JobLimitReadback {
                breakaway_allowed: true,
            },
            memcordon_core::BoundarySetupPhase::BoundaryCreation,
        ));
    }
    let active_handle = super::process::duplicate_owned(job.handle())?;
    ACTIVE_JOBS
        .lock()
        .map_err(|_| "active Job registry is poisoned".to_owned())?
        .push(ActiveJob {
            attempt_id: request.attempt_id.clone(),
            job: JobView(active_handle),
        });
    let registration = ActiveRegistration(request.attempt_id.clone());

    // SAFETY: null security/name create private manual-reset events owned here.
    let disarm = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
    // SAFETY: same as disarm; this event is guardian readiness only.
    let ready = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
    let caller_token_sha256 = super::record::digest(
        &serde_json::to_vec(&request.caller_token_envelope).map_err(|error| error.to_string())?,
    );
    let mut job_identity = request.attempt_id.as_bytes().to_vec();
    job_identity.extend_from_slice(&unsafe { GetTickCount64() }.to_le_bytes());
    let record = super::record::WindowsAttemptRecordV1::new(
        request.attempt_id.clone(),
        request.request_sha256.clone(),
        request.caller_process_identity.clone(),
        caller_token_sha256.clone(),
        super::record::digest(&job_identity),
    )?;
    inject_fault(
        &request,
        &[WindowsSealedFault::GuardianCreate],
        memcordon_core::BoundarySetupPhase::GuardianStartup,
    )?;
    let guardian = if request.certification_mutant
        == Some(memcordon_core::WindowsSealedMutant::OmitGuardian)
    {
        None
    } else {
        Some(
            super::process::create_guardian(
                job.handle(),
                frontend.raw(),
                // SAFETY: this pseudo-handle identifies the per-attempt worker
                // thread; deferred transfer duplicates it with typed rights.
                unsafe { windows_sys::Win32::System::Threading::GetCurrentThread() },
                disarm.raw(),
                ready.raw(),
                &request.attempt_id,
                30_000,
                if request.certification_mutant
                    == Some(memcordon_core::WindowsSealedMutant::ResumeBeforeGuardian)
                {
                    2_000
                } else {
                    0
                },
            )
            .map_err(LaunchAttemptError::guardian_bootstrap)?,
        )
    };
    let Some((guardian, _guardian_pid)) = guardian else {
        return Err(LaunchAttemptError::mutant_observed(
            memcordon_core::WindowsMutantNativeObservationV1::GuardianMissing,
            memcordon_core::BoundarySetupPhase::GuardianStartup,
        ));
    };
    let guardian_identity = super::process::process_identity(guardian.raw())?;
    let mut record = record;
    record.guardian_identity = Some(guardian_identity.clone());
    // BoundaryCreated is the truthful durable claim while the guardian is
    // starting. Recovery must never infer readiness merely from process creation.
    record.store()?;
    let mut cleanup_guard = AttemptCleanup::new(&job, disarm.raw(), guardian.raw(), record);
    if request.certification_mutant
        != Some(memcordon_core::WindowsSealedMutant::ResumeBeforeGuardian)
    {
        observe_guardian_startup(
            ready.raw(),
            guardian.raw(),
            &guardian_identity,
            GUARDIAN_STARTUP_TIMEOUT_MILLIS,
        )
        .map_err(LaunchAttemptError::guardian_startup)?;
    }
    // The ResumeBeforeGuardian certification mutant deliberately retains its
    // old invalid ordering so the native suite can prove it is rejected. No
    // ordinary launch reaches this transition before observed readiness.
    cleanup_guard
        .record
        .transition(super::record::WindowsAttemptStateV1::GuardianReady)?;
    cleanup_guard.record.store()?;
    super::record::retire_admission(&request.attempt_id)?;

    let mut streams =
        StreamSet::create(frontend.raw(), request.certification_fault).map_err(|detail| {
            request.certification_fault.map_or_else(
                || LaunchAttemptError::from(detail),
                |fault| {
                    LaunchAttemptError::certification_fault(
                        fault,
                        memcordon_core::BoundarySetupPhase::ResourceVerification,
                    )
                },
            )
        })?;
    let relay_retired_event = super::process::duplicate_owned(streams.relay_retired_event())?;
    let remote_streams = streams.remote.clone();
    pipe::write_frame(
        connection,
        &WindowsLauncherResponseV1::StreamsPrepared {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            attempt_id: request.attempt_id.clone(),
            nonce: request.launch.nonce.clone(),
            request_sha256: request.request_sha256.clone(),
            streams: remote_streams,
            relay_retired_event_handle: streams.remote_relay_retired_event,
        },
    )?;
    // A complete successful frame transfers ownership of every frontend-side
    // handle. From this point the launcher must not revoke those values.
    streams.accept_remote_handles();
    macro_rules! retire_preauthorization_without_target {
        ($failure:expr) => {{
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::RelaysAbort {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    attempt_id: request.attempt_id.clone(),
                    nonce: request.launch.nonce.clone(),
                    request_sha256: request.request_sha256.clone(),
                },
            )?;
            let _ = wait_for_relays_retired(
                connection,
                &request.attempt_id,
                &request.launch.nonce,
                &request.request_sha256,
                frontend.raw(),
            )?;
            wait_for_relay_retirement_proof(
                relay_retired_event.raw(),
                frontend.raw(),
                Instant::now() + Duration::from_secs(30),
            )?;
            cleanup_guard.record.begin_preauthorization_abort()?;
            job.terminate(CANCEL_STATUS)?;
            if !job.wait_empty(Instant::now() + Duration::from_secs(30))? {
                return Err("Job did not empty after preauthorization failure"
                    .to_owned()
                    .into());
            }
            cleanup_guard.record.cleanup_state.active_processes_zero = true;
            if unsafe { SetEvent(disarm.raw()) } == 0
                || unsafe { WaitForSingleObject(guardian.raw(), 10_000) } != WAIT_OBJECT_0
            {
                return Err("guardian did not reap after preauthorization failure"
                    .to_owned()
                    .into());
            }
            cleanup_guard.record.cleanup_state.guardian_reaped = true;
            cleanup_guard.record.store()?;
            let mut record = cleanup_guard.finish();
            drop(streams);
            drop(relay_retired_event);
            drop(guardian);
            drop(ready);
            drop(disarm);
            drop(registration);
            drop(job);
            record.complete_preauthorization_abort()?;
            return Err($failure);
        }};
    }
    if request.certification_mutant != Some(memcordon_core::WindowsSealedMutant::ResumeBeforeRelays)
    {
        if let Err(detail) = wait_for_relays_ready(
            connection,
            &request.attempt_id,
            &request.launch.nonce,
            &request.request_sha256,
            frontend.raw(),
            request.certification_fault,
        ) {
            let failure = if request.certification_fault == Some(WindowsSealedFault::RelayReady) {
                LaunchAttemptError::certification_fault(
                    WindowsSealedFault::RelayReady,
                    memcordon_core::BoundarySetupPhase::ResourceVerification,
                )
            } else {
                LaunchAttemptError::from(detail)
            };
            retire_preauthorization_without_target!(failure);
        }
    }

    let certification_prelude_len = request
        .launch
        .command
        .arguments
        .first()
        .and_then(|argument| memcordon_core::windows_certification_argument_prelude_len(argument))
        .filter(|_| super::record::qualification_in_progress());
    let mut target_command = request.launch.command.clone();
    let excluded_handles = if let Some(retained_arguments) = certification_prelude_len {
        if frontend_canaries.len() != memcordon_core::WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT {
            retire_preauthorization_without_target!(LaunchAttemptError::from(
                "frontend handle-canary inventory is not exact".to_owned()
            ));
        }
        target_command.arguments.truncate(retained_arguments);
        for handle in &frontend_canaries {
            if let Err(detail) = super::process::mark_certification_handle_inheritable(handle.raw())
            {
                retire_preauthorization_without_target!(LaunchAttemptError::from(detail));
            }
        }
        target_command.arguments.extend(
            streams
                .certification_target_handle_values()
                .into_iter()
                .map(|handle| handle.to_string().encode_utf16().collect()),
        );
        Some(frontend_canaries)
    } else {
        if !frontend_canaries.is_empty() {
            retire_preauthorization_without_target!(LaunchAttemptError::from(
                "ordinary launch carried certification-only frontend handles".to_owned()
            ));
        }
        None
    };
    let target_result = SuspendedTarget::create(
        primary_token.raw(),
        loader_restriction_canary.as_ref(),
        &job,
        &target_command,
        &request.launch.environment,
        &request.launch.current_directory,
        &streams,
        connection,
        request.certification_fault,
        request.certification_mutant,
    );
    let target = match target_result {
        Ok(target) => target,
        Err(error) => {
            let failure = if let Some(fault) = request.certification_fault {
                LaunchAttemptError::certification_fault(
                    fault,
                    memcordon_core::BoundarySetupPhase::TargetCreation,
                )
            } else {
                LaunchAttemptError::target_create(error)
            };
            drop(excluded_handles);
            retire_preauthorization_without_target!(failure);
        }
    };
    let target_cleanup_barrier = TargetCleanupBarrier::new(&job, &target);
    macro_rules! retire_preauthorization_with_target {
        ($failure:expr) => {{
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::RelaysAbort {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    attempt_id: request.attempt_id.clone(),
                    nonce: request.launch.nonce.clone(),
                    request_sha256: request.request_sha256.clone(),
                },
            )?;
            let _ = wait_for_relays_retired(
                connection,
                &request.attempt_id,
                &request.launch.nonce,
                &request.request_sha256,
                frontend.raw(),
            )?;
            wait_for_relay_retirement_proof(
                relay_retired_event.raw(),
                frontend.raw(),
                Instant::now() + Duration::from_secs(30),
            )?;
            cleanup_guard.record.begin_preauthorization_abort()?;
            job.terminate(CANCEL_STATUS)?;
            if !job.wait_empty(Instant::now() + Duration::from_secs(30))? {
                return Err("Job did not empty after preauthorization failure"
                    .to_owned()
                    .into());
            }
            if !target.wait(Duration::from_secs(10))? {
                return Err(
                    "suspended target did not reap after preauthorization failure"
                        .to_owned()
                        .into(),
                );
            }
            cleanup_guard.record.cleanup_state.active_processes_zero = true;
            if unsafe { SetEvent(disarm.raw()) } == 0
                || unsafe { WaitForSingleObject(guardian.raw(), 10_000) } != WAIT_OBJECT_0
            {
                return Err("guardian did not reap after preauthorization failure"
                    .to_owned()
                    .into());
            }
            cleanup_guard.record.cleanup_state.guardian_reaped = true;
            cleanup_guard.record.store()?;
            let mut record = cleanup_guard.finish();
            target_cleanup_barrier.finish();
            drop(streams);
            drop(relay_retired_event);
            drop(target);
            drop(guardian);
            drop(ready);
            drop(disarm);
            drop(registration);
            drop(job);
            record.complete_preauthorization_abort()?;
            return Err($failure);
        }};
    }
    let creation = target.creation_observation;
    if request.certification_mutant
        == Some(memcordon_core::WindowsSealedMutant::AssignJobAfterCreate)
        && !creation.job_list_present
        && creation.post_create_job_assignment
    {
        retire_preauthorization_with_target!(LaunchAttemptError::mutant_observed(
            memcordon_core::WindowsMutantNativeObservationV1::CreationManifest {
                used_create_process_as_user: creation.used_create_process_as_user,
                job_list_present: creation.job_list_present,
                handle_list_present: creation.handle_list_present,
                post_create_job_assignment: creation.post_create_job_assignment,
                unexpected_handle_count: creation.unexpected_handle_count,
            },
            memcordon_core::BoundarySetupPhase::TargetCreation,
        ));
    }
    if request.certification_mutant == Some(memcordon_core::WindowsSealedMutant::OmitHandleList)
        && !creation.handle_list_present
    {
        retire_preauthorization_with_target!(LaunchAttemptError::mutant_observed(
            memcordon_core::WindowsMutantNativeObservationV1::CreationManifest {
                used_create_process_as_user: creation.used_create_process_as_user,
                job_list_present: creation.job_list_present,
                handle_list_present: creation.handle_list_present,
                post_create_job_assignment: creation.post_create_job_assignment,
                unexpected_handle_count: creation.unexpected_handle_count,
            },
            memcordon_core::BoundarySetupPhase::TargetCreation,
        ));
    }
    if let Some(handles) = excluded_handles.as_ref() {
        for (index, (role, handle)) in super::control_service::CERTIFICATION_FRONTEND_HANDLE_ROLES
            .iter()
            .zip(handles)
            .enumerate()
        {
            let raw = handle.raw();
            match super::process::compare_remote_handle_object(target.handle(), raw, raw) {
                Ok(super::process::RemoteHandleObjectIdentity::Absent)
                | Ok(super::process::RemoteHandleObjectIdentity::DifferentObject) => {}
                Ok(super::process::RemoteHandleObjectIdentity::SameObject) => {
                    retire_preauthorization_with_target!(LaunchAttemptError::from(format!(
                        "excluded frontend handle was inherited by the suspended target: role={role} inventory_index={index} launcher_value={}",
                        raw as usize as u64
                    )));
                }
                Err(error) => {
                    retire_preauthorization_with_target!(LaunchAttemptError::from(format!(
                        "excluded frontend handle identity attestation failed: role={role} inventory_index={index} launcher_value={} detail={error}",
                        raw as usize as u64
                    )));
                }
            }
        }
    }
    drop(excluded_handles);
    let verified_target = (|| -> Result<OwnedHandle, LaunchAttemptError> {
        cleanup_guard.record.target_identity =
            Some(super::process::process_identity(target.handle())?);
        cleanup_guard
            .record
            .transition(super::record::WindowsAttemptStateV1::TargetCreatedSuspended)?;
        cleanup_guard.record.store()?;
        inject_fault(
            &request,
            &[WindowsSealedFault::TargetTokenReadback],
            memcordon_core::BoundarySetupPhase::ResourceVerification,
        )?;
        let target_token = if request.certification_mutant
            == Some(memcordon_core::WindowsSealedMutant::SkipTargetTokenReadback)
        {
            super::process::duplicate_owned(primary_token.raw())?
        } else {
            super::token::process_token(target.handle())?
        };
        let target_envelope = if request.certification_mutant
            == Some(memcordon_core::WindowsSealedMutant::SkipTargetTokenReadback)
        {
            None
        } else {
            Some(super::token::envelope(target_token.raw())?)
        };
        if request.certification_mutant
            != Some(memcordon_core::WindowsSealedMutant::SkipTargetTokenReadback)
        {
            let observed_target_snapshot =
                super::token::token_query_attestation_snapshot(target_token.raw())?;
            target.attest_process_token_snapshot(&observed_target_snapshot)?;
        }
        if target_envelope
            .as_ref()
            .is_some_and(|target_envelope| target_envelope != &request.caller_token_envelope)
        {
            if matches!(
                request.certification_mutant,
                Some(
                    memcordon_core::WindowsSealedMutant::UseCreateProcessW
                        | memcordon_core::WindowsSealedMutant::CreateUnderServiceToken
                        | memcordon_core::WindowsSealedMutant::TrustClientToken
                )
            ) {
                let authenticated_envelope_sha256 = super::record::digest(
                    &serde_json::to_vec(&request.caller_token_envelope)
                        .map_err(|error| error.to_string())?,
                );
                let target_envelope_sha256 = super::record::digest(
                    &serde_json::to_vec(target_envelope.as_ref().expect("checked present"))
                        .map_err(|error| error.to_string())?,
                );
                return Err(LaunchAttemptError::mutant_observed(
                    memcordon_core::WindowsMutantNativeObservationV1::TargetTokenMismatch {
                        creation_api: if creation.used_create_process_as_user {
                            "create-process-as-user-w"
                        } else {
                            "create-process-w"
                        }
                        .to_owned(),
                        token_source: if request.certification_mutant
                            == Some(memcordon_core::WindowsSealedMutant::TrustClientToken)
                        {
                            "authenticated-handle-untrusted-envelope"
                        } else {
                            "launcher-service"
                        }
                        .to_owned(),
                        authenticated_envelope_sha256,
                        target_envelope_sha256,
                    },
                    memcordon_core::BoundarySetupPhase::ResourceVerification,
                ));
            }
            let mismatch_fields = super::token::envelope_mismatch_fields(
                &request.caller_token_envelope,
                target_envelope.as_ref().expect("checked present"),
            );
            return Err(format!(
                "initial target token readback differs from authenticated caller (fields: {})",
                mismatch_fields.join(", ")
            )
            .into());
        }
        inject_fault(
            &request,
            &[WindowsSealedFault::JobMembershipReadback],
            memcordon_core::BoundarySetupPhase::AssignmentVerification,
        )?;
        if request.certification_mutant
            != Some(memcordon_core::WindowsSealedMutant::SkipJobMembershipReadback)
            && !job.contains(target.handle())?
        {
            if request.certification_mutant
                == Some(memcordon_core::WindowsSealedMutant::OmitJobList)
            {
                return Err(LaunchAttemptError::mutant_observed(
                    memcordon_core::WindowsMutantNativeObservationV1::CreationManifest {
                        used_create_process_as_user: creation.used_create_process_as_user,
                        job_list_present: creation.job_list_present,
                        handle_list_present: creation.handle_list_present,
                        post_create_job_assignment: creation.post_create_job_assignment,
                        unexpected_handle_count: creation.unexpected_handle_count,
                    },
                    memcordon_core::BoundarySetupPhase::AssignmentVerification,
                ));
            }
            return Err(
                "target Job membership was not verified before authorization"
                    .to_owned()
                    .into(),
            );
        }
        Ok(target_token)
    })();
    let target_token = match verified_target {
        Ok(target_token) => target_token,
        Err(failure) => retire_preauthorization_with_target!(failure),
    };
    macro_rules! retire_postauthorization_before_resume {
        ($failure:expr) => {{
            let mut failure = $failure;
            let authorization_offset = started.elapsed();
            let mut job_process_identities = Vec::new();
            for process_id in job.process_ids()? {
                if let Some(identity) =
                    super::process::process_identity_for_pid_as_authenticated_caller(
                        process_id,
                        primary_token.raw(),
                        &job,
                    )
                    .map_err(LaunchAttemptError::process_inventory)?
                {
                    record_job_process_identity(&mut job_process_identities, identity)
                        .map_err(LaunchAttemptError::from)?;
                }
            }
            let job_total_processes = job.total_processes()?;
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::RelaysAbort {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    attempt_id: request.attempt_id.clone(),
                    nonce: request.launch.nonce.clone(),
                    request_sha256: request.request_sha256.clone(),
                },
            )?;
            let _ = wait_for_relays_retired(
                connection,
                &request.attempt_id,
                &request.launch.nonce,
                &request.request_sha256,
                frontend.raw(),
            )?;
            wait_for_relay_retirement_proof(
                relay_retired_event.raw(),
                frontend.raw(),
                Instant::now() + Duration::from_secs(30),
            )?;
            let relays_retired = RelaysRetired;
            cleanup_guard.record.begin_postauthorization_retirement()?;
            job.terminate(CANCEL_STATUS)?;
            let job_terminated = JobTerminated;
            if !target.wait(Duration::from_secs(30))? {
                return Err(
                    "suspended target did not reap after postauthorization failure"
                        .to_owned()
                        .into(),
                );
            }
            let direct_target_reaped = DirectTargetReaped;
            if !job.wait_empty(Instant::now() + Duration::from_secs(30))? {
                return Err("Job did not empty after postauthorization failure"
                    .to_owned()
                    .into());
            }
            let active_processes_zero = ActiveProcessesZero;
            target_cleanup_barrier.finish();
            cleanup_guard.record.cleanup_state.active_processes_zero = true;
            cleanup_guard.record.store()?;
            // SAFETY: disarm is a live private event and signals the guardian's normal path.
            if unsafe { SetEvent(disarm.raw()) } == 0
                || unsafe { WaitForSingleObject(guardian.raw(), 10_000) } != WAIT_OBJECT_0
            {
                return Err("guardian did not reap after postauthorization failure"
                    .to_owned()
                    .into());
            }
            let guardian_reaped = GuardianReaped;
            cleanup_guard.record.cleanup_state.guardian_reaped = true;
            cleanup_guard.record.store()?;
            let child_pid = target.process_id;
            let outcome = RunOutcome::MonitorFailed {
                error: failure.detail.clone(),
                child_after_termination: Some(child_termination(target.exit_status()?)),
                cleanup: CleanupSummary {
                    force_attempted: true,
                    direct_child_reaped: true,
                    workload_empty: Some(true),
                    ..CleanupSummary::default()
                },
            };
            let mut record = cleanup_guard.finish();
            drop(streams);
            drop(relay_retired_event);
            drop(target_token);
            drop(target);
            drop(guardian);
            drop(ready);
            drop(disarm);
            drop(registration);
            drop(job);
            let final_handles_closed = FinalHandlesClosed;
            record.complete_retirement()?;
            let record_retired = RecordRetired;
            let completed = CompletedRetirement {
                child_pid,
                job_total_processes,
                job_process_identities,
                cleanup_process_creation: None,
                outcome,
                target_release: TargetReleaseDisposition::CancelledWhileSuspended,
                job_terminated,
                direct_target_reaped,
                active_processes_zero,
                relays_retired,
                guardian_reaped,
                final_handles_closed,
                record_retired,
            };
            failure.terminal_candidate = Some(Box::new(build_terminal_receipt(
                &request,
                started,
                authorization_offset,
                completed,
            )));
            return Err(failure);
        }};
    }
    if let Some(
        mutant @ (memcordon_core::WindowsSealedMutant::ResumeBeforeGuardian
        | memcordon_core::WindowsSealedMutant::ResumeBeforeRelays),
    ) = request.certification_mutant
    {
        if let Err(detail) = cleanup_guard.record.begin_preauthorization_abort() {
            retire_preauthorization_with_target!(LaunchAttemptError::from(detail));
        }
        if let Err(detail) = target.resume(None) {
            retire_preauthorization_with_target!(LaunchAttemptError::from(detail));
        }
        if let Err(detail) = cleanup_guard.record.mark_released() {
            retire_preauthorization_with_target!(LaunchAttemptError::from(detail));
        }
        if let Err(detail) =
            wait_for_certification_release_marker(&request.launch.command.arguments)
        {
            retire_preauthorization_with_target!(LaunchAttemptError::from(detail));
        }
        let guardian_ready = unsafe { WaitForSingleObject(ready.raw(), 0) } == WAIT_OBJECT_0;
        retire_preauthorization_with_target!(LaunchAttemptError::mutant_observed(
            memcordon_core::WindowsMutantNativeObservationV1::PrematureAuthorization {
                guardian_ready,
                relays_ready: mutant != memcordon_core::WindowsSealedMutant::ResumeBeforeRelays,
                target_marker_observed: true,
            },
            memcordon_core::BoundarySetupPhase::Authorization,
        ));
    }
    if request.certification_fault == Some(WindowsSealedFault::GuardianKilledBeforeAuthorization) {
        // SAFETY: guardian is the live per-attempt process and this gated
        // certification scenario deliberately removes it before authorization.
        if unsafe { TerminateProcess(guardian.raw(), CANCEL_STATUS) } == 0
            || unsafe { WaitForSingleObject(guardian.raw(), 10_000) } != WAIT_OBJECT_0
        {
            retire_preauthorization_with_target!(LaunchAttemptError::from(
                "failed to inject preauthorization guardian loss".to_owned()
            ));
        }
    }
    if let Err(detail) = require_guardian_live(guardian.raw()) {
        let failure = if request.certification_fault
            == Some(WindowsSealedFault::GuardianKilledBeforeAuthorization)
        {
            LaunchAttemptError::certification_fault(
                WindowsSealedFault::GuardianKilledBeforeAuthorization,
                memcordon_core::BoundarySetupPhase::Authorization,
            )
        } else {
            LaunchAttemptError::from(detail)
        };
        retire_preauthorization_with_target!(failure);
    }
    if let Err(failure) = inject_fault(
        &request,
        &[WindowsSealedFault::BeforeResume],
        memcordon_core::BoundarySetupPhase::Authorization,
    ) {
        retire_preauthorization_with_target!(failure);
    }
    if let Err(detail) = cleanup_guard.record.authorize() {
        retire_preauthorization_with_target!(LaunchAttemptError::from(detail));
    }
    if let Err(detail) = require_guardian_live(guardian.raw()) {
        retire_preauthorization_with_target!(LaunchAttemptError::from(detail));
    }
    if request.certification_fault == Some(WindowsSealedFault::Resume) {
        retire_postauthorization_before_resume!(LaunchAttemptError::certification_fault(
            WindowsSealedFault::Resume,
            memcordon_core::BoundarySetupPhase::Authorization,
        ));
    }
    // This durable intent is the point of no return for failure evidence. A
    // ResumeThread failure after this store is conservatively post-release;
    // it can never be misreported as a preauthorization rejection.
    if let Err(detail) = cleanup_guard.record.mark_resume_attempted() {
        retire_preauthorization_with_target!(LaunchAttemptError::from(detail));
    }
    if let Err(detail) = target.resume(None) {
        retire_preauthorization_with_target!(LaunchAttemptError::from(detail));
    }
    drop(streams);
    let authorization_offset = started.elapsed();
    cleanup_guard.record.mark_released()?;
    if let Some(hook_observation) = match request.certification_mutant {
        Some(memcordon_core::WindowsSealedMutant::SkipTargetTokenReadback) => Some(
            memcordon_core::WindowsMutantHookObservationV1::TargetTokenReadbackSkipped {
                child_pid: target.process_id,
            },
        ),
        Some(memcordon_core::WindowsSealedMutant::SkipJobMembershipReadback) => Some(
            memcordon_core::WindowsMutantHookObservationV1::JobMembershipReadbackSkipped {
                child_pid: target.process_id,
            },
        ),
        _ => None,
    } {
        let remote_observation_handle =
            super::process::duplicate_remote_process_query(target.handle(), frontend.raw())?;
        let result = pipe::write_frame(
            connection,
            &WindowsLauncherResponseV1::CertificationMutantHookObserved(
                memcordon_core::WindowsMutantNativeReceiptV1 {
                    schema_version: 1,
                    mutant: request.certification_mutant.expect("matched mutant"),
                    attempt_id: request.attempt_id.clone(),
                    nonce: request.launch.nonce.clone(),
                    request_sha256: request.request_sha256.clone(),
                    hook_observation,
                    remote_observation_handle: Some(remote_observation_handle),
                    terminal_candidate: None,
                },
            ),
        );
        if let Err(error) = result {
            let _ = super::process::revoke_remote_handle(remote_observation_handle, frontend.raw());
            return Err(error.into());
        }
    }
    pipe::write_frame(
        connection,
        &WindowsLauncherResponseV1::TargetAuthorized {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            attempt_id: request.attempt_id.clone(),
            nonce: request.launch.nonce.clone(),
            request_sha256: request.request_sha256.clone(),
            child_pid: target.process_id,
        },
    )?;
    if request.certification_fault == Some(WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
    {
        cleanup_guard
            .record
            .transition(super::record::WindowsAttemptStateV1::Terminating)?;
        cleanup_guard.record.cleanup_state.termination_requested = true;
        cleanup_guard.record.store()?;
    }

    let monitored = monitor(
        connection,
        &request,
        &job,
        &target,
        primary_token.raw(),
        guardian.raw(),
    );
    let MonitorObservation {
        reason,
        mut control_connected,
        job_process_identities,
        peak_memory_bytes,
    } = match monitored {
        Ok(observation) => observation,
        Err(error)
            if request.certification_fault
                == Some(WindowsSealedFault::LauncherWorkerKilledAfterAuthorization) =>
        {
            cleanup_guard.abandon_to_guardian();
            target_cleanup_barrier.abandon_to_guardian();
            drop(relay_retired_event);
            drop(target_token);
            drop(target);
            drop(guardian);
            drop(ready);
            drop(disarm);
            drop(registration);
            drop(job);
            pipe::disconnect(connection);
            return Err(LaunchAttemptError::authority_loss(error.detail));
        }
        Err(error) => return Err(error),
    };
    let mut mutant_candidate = None;
    let mut mutant_observation = None;
    let mut success_before_zero_active_processes = None;
    let mut completion_accepted_without_accounting = false;
    let target_result = latch_certification_target_result(
        &request.launch.command.arguments,
        &request.launch.nonce,
    )?;
    let primary_target_failure = target_result.as_ref().and_then(|receipt| {
        (!receipt.success).then(|| {
            format!(
                "qualification target failed: phase={:?} detail={}",
                receipt.phase, receipt.detail
            )
        })
    });
    cleanup_guard
        .record
        .transition(super::record::WindowsAttemptStateV1::Terminating)?;
    cleanup_guard.record.cleanup_state.termination_requested = true;
    cleanup_guard.record.store()?;
    let (mut cleanup_process_creation, cleanup_probe_failure) = if target_result
        .as_ref()
        .is_none_or(|receipt| cleanup_process_creation_expected(receipt.phase))
    {
        match certify_cleanup_process_creation(
            &request.launch.command.arguments,
            &request.launch.nonce,
            &job,
        ) {
            Ok(evidence) => (evidence, None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };
    let job_total_processes = job.total_processes()?;
    if cleanup_process_creation
        .as_ref()
        .is_some_and(|evidence| job_total_processes < evidence.total_processes_after)
    {
        return Err(
            "pre-termination Job accounting contradicted cleanup evidence"
                .to_owned()
                .into(),
        );
    }
    inject_fault(
        &request,
        &[WindowsSealedFault::TerminateJob],
        memcordon_core::BoundarySetupPhase::Retirement,
    )?;
    if request.certification_mutant
        == Some(memcordon_core::WindowsSealedMutant::SuccessBeforeActiveZero)
    {
        let active_before_mutated_success = job.active_processes()?;
        if active_before_mutated_success == 0 {
            return Err(LaunchAttemptError::from(
                "success-before-zero mutant reached an already empty Job".to_owned(),
            ));
        }
        mutant_observation = Some(
            memcordon_core::WindowsMutantNativeObservationV1::SuccessBeforeActiveZero {
                active_processes: active_before_mutated_success,
            },
        );
        success_before_zero_active_processes = Some(active_before_mutated_success);
    }
    job.terminate(reason.termination_status())?;
    let job_terminated = JobTerminated;
    if !target.wait(Duration::from_secs(30))? {
        return Err("direct target did not become signaled during cleanup"
            .to_owned()
            .into());
    }
    let direct_target_reaped = DirectTargetReaped;
    if request.certification_mutant
        == Some(memcordon_core::WindowsSealedMutant::AcceptCompletionWithoutAccounting)
    {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if job.take_notification()? == Some(JobNotification::ActiveProcessesZero) {
                mutant_observation = Some(
                    memcordon_core::WindowsMutantNativeObservationV1::CompletionAcceptedWithoutAccounting {
                        completion_zero_observed: true,
                        active_process_query_performed: false,
                    },
                );
                completion_accepted_without_accounting = true;
                break;
            }
            if Instant::now() >= deadline {
                return Err(LaunchAttemptError::from(
                    "completion-port mutant did not receive active-process-zero".to_owned(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    inject_fault(
        &request,
        &[WindowsSealedFault::ActiveProcessQuery],
        memcordon_core::BoundarySetupPhase::Retirement,
    )?;
    let empty = job.wait_empty(Instant::now() + Duration::from_secs(30))?;
    if !empty {
        return Err(
            "Job did not reach zero active processes during terminal cleanup"
                .to_owned()
                .into(),
        );
    }
    let active_processes_zero = ActiveProcessesZero;
    target_cleanup_barrier.finish();
    cleanup_guard.record.cleanup_state.active_processes_zero = true;
    if let Some(observation) = cleanup_process_creation.as_mut() {
        observation.final_active_processes_zero = true;
    }
    cleanup_guard.record.store()?;
    let outcome = build_outcome(reason, &request, &target, started, peak_memory_bytes)?;
    if let Some(active_processes) = success_before_zero_active_processes {
        mutant_candidate = Some(build_terminal_candidate(
            &request,
            target.process_id,
            started,
            authorization_offset,
            active_processes,
            outcome.clone(),
            false,
            false,
            false,
            false,
        ));
    } else if completion_accepted_without_accounting {
        mutant_candidate = Some(build_terminal_candidate(
            &request,
            target.process_id,
            started,
            authorization_offset,
            0,
            outcome.clone(),
            true,
            false,
            false,
            false,
        ));
    }
    if control_connected {
        inject_fault(
            &request,
            &[WindowsSealedFault::RelayRetire],
            memcordon_core::BoundarySetupPhase::Retirement,
        )?;
        pipe::write_frame(
            connection,
            &WindowsLauncherResponseV1::TargetRetired {
                schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                attempt_id: request.attempt_id.clone(),
                nonce: request.launch.nonce.clone(),
                request_sha256: request.request_sha256.clone(),
            },
        )?;
        if request.certification_mutant == Some(memcordon_core::WindowsSealedMutant::SkipRelayAck) {
            mutant_observation = Some(
                memcordon_core::WindowsMutantNativeObservationV1::RelayAckSkipped {
                    target_retired_sent: true,
                    relays_retired_received: false,
                },
            );
        } else {
            control_connected = wait_for_relays_retired(
                connection,
                &request.attempt_id,
                &request.launch.nonce,
                &request.request_sha256,
                frontend.raw(),
            )?;
        }
    }
    wait_for_relay_retirement_proof(
        relay_retired_event.raw(),
        frontend.raw(),
        Instant::now() + Duration::from_secs(30),
    )?;
    let relays_retired = RelaysRetired;
    inject_fault(
        &request,
        &[WindowsSealedFault::GuardianReap],
        memcordon_core::BoundarySetupPhase::Retirement,
    )?;
    // SAFETY: disarm is a live private event and signals the guardian's normal path.
    if unsafe { SetEvent(disarm.raw()) } == 0 {
        return Err(io::Error::last_os_error().to_string().into());
    }
    // SAFETY: guardian handle is live and must retire before final Job closure.
    if unsafe { WaitForSingleObject(guardian.raw(), 10_000) } != WAIT_OBJECT_0 {
        return Err("guardian did not retire after disarm".to_owned().into());
    }
    let guardian_reaped = GuardianReaped;
    cleanup_guard.record.cleanup_state.guardian_reaped = true;
    cleanup_guard.record.store()?;
    let child_pid = target.process_id;
    inject_fault(
        &request,
        &[WindowsSealedFault::FinalHandleClose],
        memcordon_core::BoundarySetupPhase::Retirement,
    )?;
    let mut record = cleanup_guard.finish();
    drop(target_token);
    drop(target);
    drop(guardian);
    drop(ready);
    drop(disarm);
    drop(registration);
    drop(job);
    let final_handles_closed = FinalHandlesClosed;
    record.complete_retirement()?;
    let record_retired = RecordRetired;

    let completed = CompletedRetirement {
        child_pid,
        job_total_processes,
        job_process_identities,
        cleanup_process_creation,
        outcome,
        target_release: TargetReleaseDisposition::Released,
        job_terminated,
        direct_target_reaped,
        active_processes_zero,
        relays_retired,
        guardian_reaped,
        final_handles_closed,
        record_retired,
    };
    let receipt = build_terminal_receipt(&request, started, authorization_offset, completed);
    if let Some(
        fault @ (WindowsSealedFault::RecordRetire
        | WindowsSealedFault::GuardianKilledAfterAuthorization),
    ) = request.certification_fault
    {
        return Err(LaunchAttemptError::certification_fault(
            fault,
            memcordon_core::BoundarySetupPhase::Retirement,
        )
        .with_terminal_candidate(receipt));
    }
    if let Some(mut cleanup_failure) = cleanup_probe_failure {
        cleanup_failure.detail = primary_target_failure.map_or_else(
            || format!("cleanup certification failed: {}", cleanup_failure.detail),
            |primary| {
                format!(
                    "{primary}; secondary cleanup certification failure: {}",
                    cleanup_failure.detail
                )
            },
        );
        cleanup_failure.terminal_candidate = Some(Box::new(receipt));
        return Err(cleanup_failure);
    }
    if request.certification_mutant
        == Some(memcordon_core::WindowsSealedMutant::CloseJobBeforeEvidence)
    {
        return Err(LaunchAttemptError::mutant_candidate(
            memcordon_core::WindowsMutantNativeObservationV1::EvidenceAfterFinalHandleClose {
                final_handles_closed: true,
                evidence_constructed_after_close: true,
            },
            receipt,
        ));
    }
    if let Some(observation) = mutant_observation {
        return Err(LaunchAttemptError::mutant_candidate(
            observation,
            mutant_candidate.unwrap_or_else(|| receipt.clone()),
        ));
    }
    fn stage_completed_terminal_response(
        record: &mut super::record::WindowsAttemptRecordV1,
        receipt: WindowsTerminalReceiptV1,
    ) -> Result<(WindowsLauncherResponseV1, String), LaunchAttemptError> {
        let response = WindowsLauncherResponseV1::Terminal(receipt.clone());
        (|| -> Result<(), String> {
            record.stage_terminal_response(&response)?;
            Ok(())
        })()
        .map_err(|error| {
            LaunchAttemptError::from(format!(
                "durable terminal outbox staging failed after completed retirement: {error}"
            ))
            .with_terminal_candidate(receipt.clone())
        })?;
        let terminal_response_sha256 = super::record::digest(
            serde_json::to_string(&response)
                .map_err(|error| {
                    LaunchAttemptError::from(format!(
                        "durable terminal outbox digest serialization failed: {error}"
                    ))
                    .with_terminal_candidate(receipt)
                })?
                .as_bytes(),
        );
        Ok((response, terminal_response_sha256))
    }
    let (response, terminal_response_sha256) =
        stage_completed_terminal_response(&mut record, receipt)?;
    if control_connected {
        (|| -> Result<(), String> {
            pipe::write_frame(connection, &response)?;
            Ok(())
        })()
        .map_err(|error| LaunchAttemptError::terminal_transport("live-delivery", error))?;
        wait_for_terminal_acknowledgment(
            connection,
            &request.attempt_id,
            &request.launch.nonce,
            &request.request_sha256,
            &terminal_response_sha256,
        )
        .map_err(|error| LaunchAttemptError::terminal_transport("terminal-ack", error))?;
        let retired = record
            .terminal_retired_receipt(&request.launch.nonce)
            .map_err(|error| LaunchAttemptError::terminal_transport("retirement-receipt", error))?;
        (|| -> Result<(), String> {
            record.acknowledge_terminal_response()?;
            Ok(())
        })()
        .map_err(|error| LaunchAttemptError::terminal_transport("outbox-retirement", error))?;
        pipe::write_frame(
            connection,
            &WindowsLauncherResponseV1::TerminalRetired(retired),
        )
        .map_err(|error| LaunchAttemptError::terminal_transport("retirement-delivery", error))?;
    }
    Ok(())
}

struct DirectTargetReaped;
struct JobTerminated;
struct ActiveProcessesZero;
struct RelaysRetired;
struct GuardianReaped;
struct FinalHandlesClosed;
struct RecordRetired;

#[derive(Clone, Copy)]
enum TargetReleaseDisposition {
    Released,
    CancelledWhileSuspended,
}

impl TargetReleaseDisposition {
    const fn target_released(self) -> bool {
        matches!(self, Self::Released)
    }
}

trait VerifiedRetirementFact {
    fn verified(&self) -> bool {
        true
    }
}

impl VerifiedRetirementFact for DirectTargetReaped {}
impl VerifiedRetirementFact for JobTerminated {}
impl VerifiedRetirementFact for ActiveProcessesZero {}
impl VerifiedRetirementFact for RelaysRetired {}
impl VerifiedRetirementFact for GuardianReaped {}
impl VerifiedRetirementFact for FinalHandlesClosed {}
impl VerifiedRetirementFact for RecordRetired {}

struct CompletedRetirement {
    child_pid: u32,
    job_total_processes: u32,
    job_process_identities: Vec<memcordon_core::WindowsProcessIdentityV1>,
    cleanup_process_creation: Option<WindowsCleanupProcessCreationEvidenceV1>,
    outcome: RunOutcome,
    target_release: TargetReleaseDisposition,
    job_terminated: JobTerminated,
    direct_target_reaped: DirectTargetReaped,
    active_processes_zero: ActiveProcessesZero,
    relays_retired: RelaysRetired,
    guardian_reaped: GuardianReaped,
    final_handles_closed: FinalHandlesClosed,
    record_retired: RecordRetired,
}

fn build_terminal_receipt(
    request: &WindowsLaunchBrokerRequestV1,
    started: Instant,
    authorization_offset: Duration,
    completed: CompletedRetirement,
) -> WindowsTerminalReceiptV1 {
    let cleanup_errors = completed
        .outcome
        .cleanup()
        .errors
        .iter()
        .map(|error| error.message.clone())
        .collect();
    let boundary_detail = complete_windows_boundary_evidence(&completed);
    WindowsTerminalReceiptV1 {
        schema_version: 1,
        attempt_id: request.attempt_id.clone(),
        nonce: request.launch.nonce.clone(),
        request_sha256: request.request_sha256.clone(),
        child_pid: completed.child_pid,
        duration_millis: millis(started.elapsed()),
        authorization_offset_millis: millis(authorization_offset),
        job_total_processes: completed.job_total_processes,
        job_process_identities: completed.job_process_identities,
        cleanup_process_creation: completed.cleanup_process_creation,
        outcome: completed.outcome,
        restart_safety: RestartSafetyProof {
            direct_child_reaped: completed.direct_target_reaped.verified(),
            workload_empty: Some(completed.active_processes_zero.verified()),
            helpers_reaped: completed.guardian_reaped.verified(),
            containment_removed: completed.final_handles_closed.verified(),
            containment_incapable_of_live_members: completed.active_processes_zero.verified(),
            sealed_boundary_retired: completed.record_retired.verified(),
            errors: cleanup_errors,
        },
        boundary_detail,
    }
}

#[allow(clippy::too_many_arguments)] // Mutants vary individual terminal predicates explicitly.
fn build_terminal_candidate(
    request: &WindowsLaunchBrokerRequestV1,
    child_pid: u32,
    started: Instant,
    authorization_offset: Duration,
    job_total_processes: u32,
    outcome: RunOutcome,
    active_processes_zero: bool,
    relays_retired: bool,
    guardian_reaped: bool,
    final_job_handles_closed: bool,
) -> WindowsTerminalReceiptV1 {
    let mut evidence = match complete_windows_boundary_evidence_for_candidate() {
        BoundaryMechanismEvidence::WindowsJobObjectV2(evidence) => evidence,
        _ => unreachable!("Windows terminal evidence constructor changed variants"),
    };
    evidence.active_processes_zero = active_processes_zero;
    evidence.relays_retired = relays_retired;
    evidence.guardian_reaped = guardian_reaped;
    evidence.final_job_handles_closed = final_job_handles_closed;
    WindowsTerminalReceiptV1 {
        schema_version: 1,
        attempt_id: request.attempt_id.clone(),
        nonce: request.launch.nonce.clone(),
        request_sha256: request.request_sha256.clone(),
        child_pid,
        duration_millis: millis(started.elapsed()),
        authorization_offset_millis: millis(authorization_offset),
        job_total_processes,
        job_process_identities: Vec::new(),
        cleanup_process_creation: None,
        outcome,
        restart_safety: RestartSafetyProof::default(),
        boundary_detail: BoundaryMechanismEvidence::WindowsJobObjectV2(evidence),
    }
}

fn complete_windows_boundary_evidence(
    completed: &CompletedRetirement,
) -> BoundaryMechanismEvidence {
    BoundaryMechanismEvidence::WindowsJobObjectV2(WindowsSealedEvidenceV2 {
        schema_version: 2,
        service_identity: "MemCordonSealedControl+MemCordonSealedLauncher:v1".to_owned(),
        caller_token_authenticated: true,
        initial_target_token_matches_caller: true,
        credential_transition_disposition: CredentialTransitionDisposition::PreserveCallerEnvelope,
        job_membership_independent_of_token: true,
        job_created: true,
        job_limits_verified: true,
        kill_on_close_verified: true,
        breakaway_denied: true,
        completion_port_associated: true,
        guardian_ready: true,
        target_created_suspended: true,
        job_list_applied_at_creation: true,
        handle_list_applied_at_creation: true,
        target_job_membership_verified: true,
        target_still_suspended_during_verification: true,
        inherited_handles_verified: true,
        target_released: completed.target_release.target_released(),
        terminate_job_invoked: completed.job_terminated.verified(),
        active_processes_zero: completed.active_processes_zero.verified(),
        direct_target_reaped: completed.direct_target_reaped.verified(),
        relays_retired: completed.relays_retired.verified(),
        guardian_reaped: completed.guardian_reaped.verified(),
        final_job_handles_closed: completed.final_handles_closed.verified(),
    })
}

fn complete_windows_boundary_evidence_for_candidate() -> BoundaryMechanismEvidence {
    BoundaryMechanismEvidence::WindowsJobObjectV2(WindowsSealedEvidenceV2 {
        schema_version: 2,
        service_identity: "MemCordonSealedControl+MemCordonSealedLauncher:v1".to_owned(),
        caller_token_authenticated: true,
        initial_target_token_matches_caller: true,
        credential_transition_disposition: CredentialTransitionDisposition::PreserveCallerEnvelope,
        job_membership_independent_of_token: true,
        job_created: true,
        job_limits_verified: true,
        kill_on_close_verified: true,
        breakaway_denied: true,
        completion_port_associated: true,
        guardian_ready: true,
        target_created_suspended: true,
        job_list_applied_at_creation: true,
        handle_list_applied_at_creation: true,
        target_job_membership_verified: true,
        target_still_suspended_during_verification: true,
        inherited_handles_verified: true,
        target_released: true,
        terminate_job_invoked: true,
        active_processes_zero: true,
        direct_target_reaped: true,
        relays_retired: true,
        guardian_reaped: true,
        final_job_handles_closed: true,
    })
}

fn wait_for_relay_retirement_proof(
    relay_retired_event: HANDLE,
    frontend: HANDLE,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        // SAFETY: both synchronization handles remain owned by this attempt.
        if unsafe { WaitForSingleObject(relay_retired_event, 0) } == WAIT_OBJECT_0 {
            return Ok(());
        }
        if unsafe { WaitForSingleObject(frontend, 0) } == WAIT_OBJECT_0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("frontend did not prove relay-handle retirement".to_owned());
        }
        pipe::wait_poll_interval();
    }
}

fn wait_for_relays_ready(
    connection: HANDLE,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    frontend: HANDLE,
    certification_fault: Option<WindowsSealedFault>,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        // SAFETY: frontend remains a live synchronization handle.
        if unsafe { WaitForSingleObject(frontend, 0) } == WAIT_OBJECT_0 {
            return Err("frontend exited before relay readiness".to_owned());
        }
        if pipe::frame_available(connection)? {
            return match pipe::read_frame::<WindowsLauncherRequestV1>(connection)? {
                WindowsLauncherRequestV1::RelaysReady {
                    schema_version,
                    attempt_id: received,
                    nonce: received_nonce,
                    request_sha256: received_digest,
                } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
                    && received == attempt_id
                    && received_nonce == nonce
                    && received_digest == request_sha256 =>
                {
                    if certification_fault == Some(WindowsSealedFault::RelayReady) {
                        Err("MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected RelayReady".to_owned())
                    } else {
                        Ok(())
                    }
                }
                _ => Err("invalid relay-readiness message".to_owned()),
            };
        }
        pipe::wait_poll_interval();
    }
    Err("frontend did not acknowledge relay readiness".to_owned())
}

fn wait_for_relays_retired(
    connection: HANDLE,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    frontend: HANDLE,
) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        // SAFETY: frontend remains a live synchronization handle.
        if unsafe { WaitForSingleObject(frontend, 0) } == WAIT_OBJECT_0 {
            return Ok(false);
        }
        let available = match pipe::frame_available_detailed(connection) {
            Ok(available) => available,
            Err(pipe::FrameAvailabilityError::PeerClosed) => return Ok(false),
            Err(error) => {
                return Err(format!("relay-retirement availability failed: {error}"));
            }
        };
        if available {
            let frame = match pipe::read_frame_detailed::<WindowsLauncherRequestV1>(connection) {
                Ok(frame) => frame,
                Err(error) if error.peer_closed && error.transferred_bytes == 0 => {
                    return Ok(false);
                }
                Err(error) => {
                    return Err(format!("relay-retirement frame failed: {error}"));
                }
            };
            return match frame {
                WindowsLauncherRequestV1::RelaysRetired {
                    schema_version,
                    attempt_id: received,
                    nonce: received_nonce,
                    request_sha256: received_digest,
                } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
                    && received == attempt_id
                    && received_nonce == nonce
                    && received_digest == request_sha256 =>
                {
                    Ok(true)
                }
                _ => Err("invalid relay-retirement message".to_owned()),
            };
        }
        pipe::wait_poll_interval();
    }
    Err("frontend did not acknowledge relay retirement".to_owned())
}

fn wait_for_terminal_acknowledgment(
    connection: HANDLE,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    terminal_response_sha256: &str,
) -> Result<(), String> {
    match pipe::read_frame::<WindowsLauncherRequestV1>(connection)? {
        WindowsLauncherRequestV1::TerminalAcknowledged {
            schema_version,
            attempt_id: received_attempt_id,
            nonce: received_nonce,
            request_sha256: received_request_sha256,
            terminal_response_sha256: received_response_sha256,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
            && received_attempt_id == attempt_id
            && received_nonce == nonce
            && received_request_sha256 == request_sha256
            && received_response_sha256 == terminal_response_sha256 =>
        {
            Ok(())
        }
        _ => Err("control did not acknowledge the bound terminal response".to_owned()),
    }
}

fn certify_cleanup_process_creation(
    arguments: &[Vec<u16>],
    nonce: &str,
    job: &Job,
) -> Result<Option<WindowsCleanupProcessCreationEvidenceV1>, LaunchAttemptError> {
    use std::os::windows::ffi::OsStringExt;

    let Some(mode) = arguments.first() else {
        return Ok(None);
    };
    let mode = String::from_utf16(mode).map_err(|error| error.to_string())?;
    let marker_index = if mode == "windows-certification-target" {
        2
    } else if mode == "windows-certification-nested-target" {
        3
    } else {
        return Ok(None);
    };
    let marker = arguments
        .get(marker_index)
        .map(|value| std::path::PathBuf::from(std::ffi::OsString::from_wide(value)))
        .ok_or_else(|| "cleanup-creation marker is absent".to_owned())?;
    let attempt_binding = format!("attempt-{}", super::record::digest(nonce.as_bytes()));
    let expected = super::package::state_root()
        .join("package")
        .join("certification-markers")
        .join(&attempt_binding)
        .join("cleanup.marker");
    if marker != expected {
        return Err(LaunchAttemptError::from(format!(
            "cleanup-creation marker is not bound to the authenticated launch nonce: expected={} actual={}",
            expected.display(),
            marker.display()
        )));
    }

    let ready_path = super::qualification::cleanup_process_creation_phase_path(
        &marker,
        super::qualification::CleanupProcessCreationProducerPhaseV1::Ready,
    );
    let mut producer_state = read_cleanup_process_creation_state(&ready_path, &attempt_binding)?;
    if producer_state.phase != super::qualification::CleanupProcessCreationProducerPhaseV1::Ready
        || producer_state.sequence != 1
        || producer_state.completed_phases
            != [super::qualification::CleanupProcessCreationProducerPhaseV1::Ready]
        || producer_state.outcome.is_some()
        || producer_state.producer_pid == 0
        || producer_state.producer_identity.process_id != producer_state.producer_pid
    {
        return Err("cleanup producer ready state is inconsistent"
            .to_owned()
            .into());
    }
    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
    // SAFETY: the PID is bound to the typed attempt state. The retained handle
    // pins that exact process object across result/exit observation.
    let producer = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            producer_state.producer_pid,
        )
    })
    .map_err(|error| {
        LaunchAttemptError::from(format!(
            "cleanup producer could not be pinned: pid={} detail={error}",
            producer_state.producer_pid
        ))
    })?;
    let pinned_identity = super::process::process_identity(producer.raw())?;
    let producer_job_membership_verified =
        job.process_ids()?.contains(&producer_state.producer_pid);
    if pinned_identity != producer_state.producer_identity || !producer_job_membership_verified {
        return Err(format!(
            "cleanup producer identity or Job membership is inconsistent: pid={} identity_matches={} job_member={producer_job_membership_verified}",
            producer_state.producer_pid,
            pinned_identity == producer_state.producer_identity,
        )
        .into());
    }

    let total_processes_before = job.total_processes()?;
    let active_processes_before = job.active_processes()?;
    let start = marker.with_extension("start");
    std::fs::write(&start, b"terminating\n")
        .map_err(|error| LaunchAttemptError::cleanup_marker("start-write", &start, error))?;
    let result = marker.with_extension("result");
    let failure = marker.with_extension("failure");
    let staged_failure = super::qualification::staged_receipt_path(&failure);
    let fallback_stderr = marker.with_extension("stderr");
    let deadline = Instant::now() + Duration::from_secs(10);
    let terminal = loop {
        producer_state =
            read_cleanup_process_creation_progress(&marker, &attempt_binding, &pinned_identity)?;
        if producer_state.producer_identity != pinned_identity {
            return Err("cleanup producer state changed process identity"
                .to_owned()
                .into());
        }
        let success = read_cleanup_process_creation_terminal(&result)?;
        let failed = read_cleanup_process_creation_terminal(&failure)?;
        match (success, failed) {
            (_, Some(terminal)) => break terminal,
            (Some(terminal), None)
                if producer_state.phase
                    == super::qualification::CleanupProcessCreationProducerPhaseV1::ResultPublished =>
            {
                break terminal;
            }
            (Some(_), None) => {}
            (None, None) => {}
        }

        // SAFETY: producer is the pinned synchronization handle opened above.
        match unsafe { WaitForSingleObject(producer.raw(), 0) } {
            WAIT_OBJECT_0 => {
                if let Some(terminal) = read_cleanup_process_creation_terminal(&staged_failure)? {
                    break terminal;
                }
                let exit_code = cleanup_process_exit_code(producer.raw())?;
                let fallback =
                    super::qualification::cleanup_producer_fallback_diagnostic(&fallback_stderr);
                return Err(LaunchAttemptError::cleanup_producer_abrupt(format!(
                    "cleanup producer exited without a typed terminal receipt: phase={:?} pid={} creation_time_100ns={} exit_code={} fallback_stderr={} total_processes_before={} total_processes_now={} active_processes_before={} active_processes_now={}",
                    producer_state.phase,
                    producer_state.producer_pid,
                    producer_state.producer_identity.creation_time_100ns,
                    exit_code,
                    fallback,
                    total_processes_before,
                    job.total_processes()?,
                    active_processes_before,
                    job.active_processes()?,
                )));
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                return Err(io::Error::last_os_error().to_string().into());
            }
            status => {
                return Err(format!(
                    "cleanup producer wait returned unexpected status {status:#x}"
                )
                .into());
            }
        }
        if Instant::now() >= deadline {
            let exit_code = cleanup_process_exit_code(producer.raw())?;
            return Err(LaunchAttemptError::cleanup_producer_timeout(format!(
                "cleanup-time process creation result timed out: phase={:?} pid={} creation_time_100ns={} producer_alive=true job_member={} exit_code={} total_processes_before={} total_processes_now={} active_processes_before={} active_processes_now={}",
                producer_state.phase,
                producer_state.producer_pid,
                producer_state.producer_identity.creation_time_100ns,
                producer_job_membership_verified,
                exit_code,
                total_processes_before,
                job.total_processes()?,
                active_processes_before,
                job.active_processes()?,
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let receipt = match terminal {
        super::qualification::CleanupProcessCreationTerminalV1::Success(receipt) => receipt,
        super::qualification::CleanupProcessCreationTerminalV1::Failed {
            schema_version,
            attempt_binding: terminal_binding,
            producer_pid,
            producer_identity,
            completed_phases,
            failure,
        } => {
            if schema_version
                != super::qualification::CLEANUP_PROCESS_CREATION_RESULT_SCHEMA_VERSION
                || terminal_binding != attempt_binding
                || producer_pid != pinned_identity.process_id
                || producer_identity != pinned_identity
                || !cleanup_process_creation_phase_prefix_is_valid(&completed_phases)
                || failure.last_completed_phase != completed_phases.last().copied()
                || failure.attempted_phase != cleanup_process_creation_next_phase(&completed_phases)
            {
                return Err("cleanup producer failure receipt is inconsistent"
                    .to_owned()
                    .into());
            }
            return Err(LaunchAttemptError::cleanup_producer_failure(failure));
        }
    };
    if receipt.schema_version
        != super::qualification::CLEANUP_PROCESS_CREATION_RESULT_SCHEMA_VERSION
        || receipt.attempt_binding != attempt_binding
        || receipt.producer_pid != pinned_identity.process_id
        || receipt.producer_identity != pinned_identity
        || producer_state.outcome.as_ref() != Some(&receipt.outcome)
        || receipt.completed_phases
            != [
                super::qualification::CleanupProcessCreationProducerPhaseV1::Ready,
                super::qualification::CleanupProcessCreationProducerPhaseV1::StartObserved,
                super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnEntered,
                super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnReturned,
                super::qualification::CleanupProcessCreationProducerPhaseV1::ResultStaged,
                super::qualification::CleanupProcessCreationProducerPhaseV1::ResultSynced,
                super::qualification::CleanupProcessCreationProducerPhaseV1::ResultPublished,
            ]
    {
        return Err(format!(
            "cleanup-time process creation result is inconsistent: schema_version={} attempt_binding={} producer_pid={} producer_phase={:?}",
            receipt.schema_version,
            receipt.attempt_binding,
            receipt.producer_pid,
            producer_state.phase,
        )
        .into());
    }
    let child_pid = match receipt.outcome {
        super::qualification::CleanupProcessCreationOutcomeV1::Created { child_pid }
            if child_pid != 0 =>
        {
            child_pid
        }
        super::qualification::CleanupProcessCreationOutcomeV1::Created { .. } => {
            return Err(
                "cleanup-time process creation result reported a zero child PID"
                    .to_owned()
                    .into(),
            );
        }
        super::qualification::CleanupProcessCreationOutcomeV1::Failed {
            phase,
            code,
            os_code,
            detail,
        } => {
            return Err(LaunchAttemptError::cleanup_child_spawn(
                code, phase, os_code, detail,
            ));
        }
    };
    let child_job_membership_verified = job.process_ids()?.contains(&child_pid);
    let child_identity = super::process::process_identity_for_pid(child_pid)?
        .ok_or_else(|| "cleanup-time child retired before identity readback".to_owned())?;
    let total_processes_after = job.total_processes()?;
    let evidence = WindowsCleanupProcessCreationEvidenceV1 {
        schema_version: 1,
        attempt_binding,
        attempted_after_terminating_transition: true,
        child_created: true,
        child_job_membership_verified,
        child_identity,
        total_processes_before,
        total_processes_after,
        final_active_processes_zero: false,
    };
    if !child_job_membership_verified || total_processes_after <= total_processes_before {
        return Err("cleanup-time child was not accounted inside the sealed Job"
            .to_owned()
            .into());
    }
    Ok(Some(evidence))
}

fn read_cleanup_process_creation_state(
    path: &std::path::Path,
    expected_binding: &str,
) -> Result<super::qualification::CleanupProcessCreationStateV1, LaunchAttemptError> {
    read_cleanup_process_creation_state_if_present(path, expected_binding)?.ok_or_else(|| {
        LaunchAttemptError::cleanup_marker(
            "state-open",
            path,
            std::io::Error::new(std::io::ErrorKind::NotFound, "phase receipt is absent"),
        )
    })
}

fn read_cleanup_process_creation_state_if_present(
    path: &std::path::Path,
    expected_binding: &str,
) -> Result<Option<super::qualification::CleanupProcessCreationStateV1>, LaunchAttemptError> {
    use std::io::Read;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaunchAttemptError::cleanup_marker(
                "state-open",
                path,
                error,
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| LaunchAttemptError::cleanup_marker("state-metadata", path, error))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
        || metadata.len()
            > u64::try_from(memcordon_core::WINDOWS_MAX_FRAME_BYTES / 1024).unwrap_or(u64::MAX)
    {
        return Err("cleanup producer state is not a bounded regular file"
            .to_owned()
            .into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| LaunchAttemptError::cleanup_marker("state-read", path, error))?;
    let state: super::qualification::CleanupProcessCreationStateV1 = serde_json::from_slice(&bytes)
        .map_err(|error| {
            LaunchAttemptError::from(format!("cleanup producer state is malformed: {error}"))
        })?;
    if state.schema_version != super::qualification::CLEANUP_PROCESS_CREATION_STATE_SCHEMA_VERSION
        || state.attempt_binding != expected_binding
        || state.producer_pid == 0
        || state.producer_identity.process_id != state.producer_pid
    {
        return Err("cleanup producer state identity is inconsistent"
            .to_owned()
            .into());
    }
    Ok(Some(state))
}

fn cleanup_process_creation_phase_prefix_is_valid(
    phases: &[super::qualification::CleanupProcessCreationProducerPhaseV1],
) -> bool {
    let expected = [
        super::qualification::CleanupProcessCreationProducerPhaseV1::Ready,
        super::qualification::CleanupProcessCreationProducerPhaseV1::StartObserved,
        super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnEntered,
        super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnReturned,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultStaged,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultSynced,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultPublished,
    ];
    phases.len() <= expected.len() && phases == &expected[..phases.len()]
}

fn cleanup_process_creation_next_phase(
    phases: &[super::qualification::CleanupProcessCreationProducerPhaseV1],
) -> Option<super::qualification::CleanupProcessCreationProducerPhaseV1> {
    let expected = [
        super::qualification::CleanupProcessCreationProducerPhaseV1::Ready,
        super::qualification::CleanupProcessCreationProducerPhaseV1::StartObserved,
        super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnEntered,
        super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnReturned,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultStaged,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultSynced,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultPublished,
    ];
    expected.get(phases.len()).copied()
}

fn read_cleanup_process_creation_progress(
    marker: &std::path::Path,
    expected_binding: &str,
    expected_identity: &memcordon_core::WindowsProcessIdentityV1,
) -> Result<super::qualification::CleanupProcessCreationStateV1, LaunchAttemptError> {
    let phases = [
        super::qualification::CleanupProcessCreationProducerPhaseV1::Ready,
        super::qualification::CleanupProcessCreationProducerPhaseV1::StartObserved,
        super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnEntered,
        super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnReturned,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultStaged,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultSynced,
        super::qualification::CleanupProcessCreationProducerPhaseV1::ResultPublished,
    ];
    let mut observed = Vec::new();
    let mut last = None;
    let mut gap = false;
    let mut observed_outcome = None;
    for phase in phases {
        let path = super::qualification::cleanup_process_creation_phase_path(marker, phase);
        match read_cleanup_process_creation_state_if_present(&path, expected_binding)? {
            Some(state) => {
                if gap
                    || state.phase != phase
                    || state.producer_identity != *expected_identity
                    || state.sequence != u32::try_from(observed.len() + 1).unwrap_or(u32::MAX)
                {
                    return Err("cleanup producer phase sequence is inconsistent"
                        .to_owned()
                        .into());
                }
                observed.push(phase);
                let outcome_expected = matches!(
                    phase,
                    super::qualification::CleanupProcessCreationProducerPhaseV1::SpawnReturned
                        | super::qualification::CleanupProcessCreationProducerPhaseV1::ResultStaged
                        | super::qualification::CleanupProcessCreationProducerPhaseV1::ResultSynced
                        | super::qualification::CleanupProcessCreationProducerPhaseV1::ResultPublished
                );
                if state.completed_phases != observed
                    || (outcome_expected && state.outcome.is_none())
                    || (!outcome_expected && state.outcome.is_some())
                {
                    return Err("cleanup producer phase transcript is inconsistent"
                        .to_owned()
                        .into());
                }
                if outcome_expected {
                    if observed_outcome
                        .as_ref()
                        .is_some_and(|outcome| state.outcome.as_ref() != Some(outcome))
                    {
                        return Err("cleanup producer phase outcome changed after spawn return"
                            .to_owned()
                            .into());
                    }
                    observed_outcome = state.outcome.clone();
                }
                last = Some(state);
            }
            None => gap = true,
        }
    }
    last.ok_or_else(|| {
        "cleanup producer ready receipt disappeared"
            .to_owned()
            .into()
    })
}

fn read_cleanup_process_creation_terminal(
    path: &std::path::Path,
) -> Result<Option<super::qualification::CleanupProcessCreationTerminalV1>, LaunchAttemptError> {
    use std::io::Read;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaunchAttemptError::cleanup_marker(
                "terminal-open",
                path,
                error,
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| LaunchAttemptError::cleanup_marker("terminal-metadata", path, error))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
        || metadata.len()
            > u64::try_from(memcordon_core::WINDOWS_MAX_FRAME_BYTES / 1024).unwrap_or(u64::MAX)
    {
        return Err("cleanup producer terminal is not a bounded regular file"
            .to_owned()
            .into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| LaunchAttemptError::cleanup_marker("terminal-read", path, error))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("cleanup producer terminal is malformed: {error}").into())
}

fn cleanup_process_exit_code(process: HANDLE) -> Result<u32, LaunchAttemptError> {
    let mut exit_code = 0_u32;
    // SAFETY: process is the pinned cleanup producer and output is writable.
    if unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
        Err(io::Error::last_os_error().to_string().into())
    } else {
        Ok(exit_code)
    }
}

pub(crate) const fn cleanup_process_creation_expected(
    phase: super::qualification::TargetResultPhaseV1,
) -> bool {
    !matches!(
        phase,
        super::qualification::TargetResultPhaseV1::ArgumentBinding
            | super::qualification::TargetResultPhaseV1::HandleInheritance
            | super::qualification::TargetResultPhaseV1::StandardStreams
            | super::qualification::TargetResultPhaseV1::ProcessTree
    )
}

fn latch_certification_target_result(
    arguments: &[Vec<u16>],
    nonce: &str,
) -> Result<Option<super::qualification::TargetResultReceiptV1>, LaunchAttemptError> {
    use std::os::windows::ffi::OsStringExt;

    let Some(mode) = arguments.first() else {
        return Ok(None);
    };
    let mode = String::from_utf16(mode).map_err(|error| error.to_string())?;
    if mode != "windows-certification-target" && mode != "windows-certification-nested-target" {
        return Ok(None);
    }
    let path = arguments
        .get(1)
        .map(|value| std::path::PathBuf::from(std::ffi::OsString::from_wide(value)))
        .ok_or_else(|| "qualification target-result path is absent".to_owned())?;
    let receipt = super::qualification::read_bound_target_result(&path, nonce, &mode)?;
    Ok(Some(receipt))
}

#[derive(Clone, Copy)]
enum TerminalReason {
    Direct(u32),
    Deadline,
    Memory(u64),
    Interrupted(i32),
}

impl TerminalReason {
    const fn termination_status(self) -> u32 {
        match self {
            Self::Direct(_) | Self::Interrupted(_) => CANCEL_STATUS,
            Self::Deadline => DEADLINE_STATUS,
            Self::Memory(_) => LIMIT_STATUS,
        }
    }
}

struct MonitorObservation {
    reason: TerminalReason,
    control_connected: bool,
    job_process_identities: Vec<memcordon_core::WindowsProcessIdentityV1>,
    peak_memory_bytes: u64,
}

fn monitor(
    connection: HANDLE,
    request: &WindowsLaunchBrokerRequestV1,
    job: &Job,
    target: &SuspendedTarget,
    authenticated_primary: HANDLE,
    guardian: HANDLE,
) -> Result<MonitorObservation, LaunchAttemptError> {
    let mut direct_status = None;
    let mut command_exit = None;
    let mut memory_limit_notified = false;
    let mut control_connected = true;
    let mut job_process_identities = Vec::new();
    let mut guardian_loss_injected = false;
    let reason = loop {
        if matches!(
            request.certification_fault,
            Some(
                WindowsSealedFault::LauncherWorkerKilledAfterAuthorization
                    | WindowsSealedFault::LauncherServiceKilledAfterAuthorization
                    | WindowsSealedFault::AllJobOwnersClosedAfterAuthorization
            )
        ) {
            wait_for_certification_release_marker(&request.launch.command.arguments)?;
            match request.certification_fault {
                Some(WindowsSealedFault::LauncherWorkerKilledAfterAuthorization) => {
                    return Err("certification removed the per-attempt launcher worker"
                        .to_owned()
                        .into());
                }
                Some(WindowsSealedFault::LauncherServiceKilledAfterAuthorization) => {
                    // SAFETY: this gated native scenario deliberately crashes
                    // the launcher service after target authorization.
                    unsafe {
                        TerminateProcess(
                            windows_sys::Win32::System::Threading::GetCurrentProcess(),
                            CANCEL_STATUS,
                        )
                    };
                    return Err("launcher service termination unexpectedly returned"
                        .to_owned()
                        .into());
                }
                Some(WindowsSealedFault::AllJobOwnersClosedAfterAuthorization) => {
                    // SAFETY: removing guardian then launcher closes every Job
                    // owner; kill-on-close must retire the entire workload.
                    if unsafe { TerminateProcess(guardian, CANCEL_STATUS) } == 0 {
                        return Err("all-owner scenario could not terminate guardian"
                            .to_owned()
                            .into());
                    }
                    unsafe {
                        TerminateProcess(
                            windows_sys::Win32::System::Threading::GetCurrentProcess(),
                            CANCEL_STATUS,
                        )
                    };
                    return Err("all-owner launcher termination unexpectedly returned"
                        .to_owned()
                        .into());
                }
                _ => unreachable!("guarded authority-loss fault"),
            }
        }
        if !guardian_loss_injected
            && request.certification_fault
                == Some(WindowsSealedFault::GuardianKilledAfterAuthorization)
        {
            wait_for_certification_release_marker(&request.launch.command.arguments)?;
            // SAFETY: target was resumed and guardian is the live per-attempt
            // authority removed by this release-required native scenario.
            if unsafe { TerminateProcess(guardian, CANCEL_STATUS) } == 0
                || unsafe { WaitForSingleObject(guardian, 10_000) } != WAIT_OBJECT_0
            {
                return Err("failed to inject postauthorization guardian loss"
                    .to_owned()
                    .into());
            }
            guardian_loss_injected = true;
        }
        if !guardian_is_live(guardian)? {
            break TerminalReason::Interrupted(15);
        }
        if !target.desktop_authority_live()? {
            break TerminalReason::Interrupted(15);
        }
        for process_id in job.process_ids()? {
            if let Some(identity) =
                super::process::process_identity_for_pid_as_authenticated_caller(
                    process_id,
                    authenticated_primary,
                    job,
                )
                .map_err(LaunchAttemptError::process_inventory)?
            {
                record_job_process_identity(&mut job_process_identities, identity)
                    .map_err(LaunchAttemptError::from)?;
            }
        }
        while let Some(notification) = job.take_notification()? {
            if notification == JobNotification::MemoryLimit {
                memory_limit_notified = true;
            }
        }
        let peak = job.peak_memory()?;
        if memory_limit_notified
            || request
                .launch
                .policy
                .memory_limit_bytes
                .is_some_and(|limit| peak >= limit)
        {
            break TerminalReason::Memory(peak);
        }
        if direct_status.is_none() && target.wait(Duration::ZERO)? {
            let status = target.exit_status()?;
            direct_status = Some(status);
            command_exit = Some(Instant::now());
            if request.launch.policy.lifetime == memcordon_core::WindowsLifetimeV1::Command
                && request.launch.policy.command_exit_grace_millis == 0
            {
                break TerminalReason::Direct(status);
            }
        }
        if let (Some(exited), Some(status)) = (command_exit, direct_status) {
            if request.launch.policy.lifetime == memcordon_core::WindowsLifetimeV1::Command
                && exited.elapsed()
                    >= Duration::from_millis(request.launch.policy.command_exit_grace_millis)
            {
                break TerminalReason::Direct(status);
            }
        }
        if request.launch.policy.lifetime == memcordon_core::WindowsLifetimeV1::Workload {
            if let Some(status) = direct_status {
                if job.active_processes()? == 0 {
                    break TerminalReason::Direct(status);
                }
            }
        }
        let now = unsafe { GetTickCount64() };
        if request
            .launch
            .policy
            .absolute_deadline_millis
            .is_some_and(|deadline| now >= deadline)
        {
            break TerminalReason::Deadline;
        }
        if control_connected {
            let available = match pipe::frame_available(connection) {
                Ok(available) => available,
                Err(_) => {
                    control_connected = false;
                    false
                }
            };
            if available {
                match pipe::read_frame::<WindowsLauncherRequestV1>(connection) {
                    Err(_) => control_connected = false,
                    Ok(WindowsLauncherRequestV1::Cancel {
                        schema_version,
                        attempt_id,
                        nonce,
                        request_sha256,
                        signal,
                    }) if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
                        && attempt_id == request.attempt_id
                        && nonce == request.launch.nonce
                        && request_sha256 == request.request_sha256 =>
                    {
                        break TerminalReason::Interrupted(signal);
                    }
                    Ok(_) => {
                        return Err("invalid control message during target execution"
                            .to_owned()
                            .into());
                    }
                }
            }
        }
        // SAFETY: frontend is a live synchronization handle owned by this attempt.
        if unsafe {
            WaitForSingleObject(request.remote_frontend_process_handle as usize as HANDLE, 0)
        } == WAIT_OBJECT_0
        {
            break TerminalReason::Interrupted(15);
        }
        std::thread::sleep(Duration::from_millis(
            request.launch.policy.poll_interval_millis.clamp(1, 100),
        ));
    };
    Ok(MonitorObservation {
        reason,
        control_connected,
        job_process_identities,
        peak_memory_bytes: job.peak_memory()?,
    })
}

fn build_outcome(
    reason: TerminalReason,
    request: &WindowsLaunchBrokerRequestV1,
    target: &SuspendedTarget,
    started: Instant,
    peak_memory_bytes: u64,
) -> Result<RunOutcome, LaunchAttemptError> {
    let child_after_termination = if matches!(reason, TerminalReason::Direct(_)) {
        None
    } else {
        Some(child_termination(target.exit_status()?))
    };
    let cleanup = CleanupSummary {
        force_attempted: true,
        direct_child_reaped: true,
        workload_empty: Some(true),
        ..CleanupSummary::default()
    };
    let peak = Some(ByteSize::from_bytes(peak_memory_bytes));
    match reason {
        TerminalReason::Direct(status) => Ok(RunOutcome::Exited {
            child: child_termination(status),
            peak,
            cleanup,
        }),
        TerminalReason::Deadline => {
            let observed = millis(started.elapsed());
            let requested = request
                .launch
                .policy
                .absolute_deadline_millis
                .map(|deadline| {
                    deadline.saturating_sub(unsafe { GetTickCount64() }.saturating_sub(observed))
                })
                .unwrap_or(observed);
            let evidence = DeadlineEvidence::new(
                requested,
                DeadlineScope::Attempt,
                "suspended-thread-resume".to_owned(),
                requested,
                observed.max(requested),
                request.launch.policy.signal_grace_millis,
                0,
                None,
                Some("TerminateJobObject".to_owned()),
            )
            .map_err(|error| error.to_string())?;
            Ok(RunOutcome::DeadlineExceeded {
                deadline: evidence,
                child_after_termination,
                peak,
                cleanup,
            })
        }
        TerminalReason::Memory(observed) => Ok(RunOutcome::LimitExceeded {
            limit: ByteSize::from_bytes(
                request
                    .launch
                    .policy
                    .memory_limit_bytes
                    .expect("memory reason has a limit"),
            ),
            observed: Some(ByteSize::from_bytes(observed)),
            peak,
            evidence: LimitEvidence {
                backend: "windows-job-object".to_owned(),
                metric: "windows-job-commit".to_owned(),
                detail: "Job memory accounting reached the configured hard limit".to_owned(),
            },
            child_after_termination,
            cleanup,
        }),
        TerminalReason::Interrupted(signal) => Ok(RunOutcome::Interrupted {
            signal: Interruption { signal },
            child_after_termination,
            cleanup,
        }),
    }
}

pub(crate) fn record_job_process_identity(
    inventory: &mut Vec<memcordon_core::WindowsProcessIdentityV1>,
    identity: memcordon_core::WindowsProcessIdentityV1,
) -> Result<(), String> {
    if inventory.contains(&identity) {
        return Ok(());
    }
    if inventory.len() == memcordon_core::WINDOWS_MAX_JOB_PROCESS_IDENTITIES {
        return Err("Job process-identity observation limit was exceeded".to_owned());
    }
    inventory.push(identity);
    Ok(())
}

fn wait_for_certification_release_marker(arguments: &[Vec<u16>]) -> Result<(), String> {
    use std::os::windows::ffi::OsStringExt;

    let marker = arguments
        .get(1)
        .map(|value| std::ffi::OsString::from_wide(value))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "guardian-loss certification marker path is absent".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if marker.is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("postauthorization guardian-loss marker was not observed".to_owned())
}

fn require_guardian_live(guardian: HANDLE) -> Result<(), String> {
    if guardian_is_live(guardian)? {
        Ok(())
    } else {
        Err("guardian exited while the sealed attempt was active".to_owned())
    }
}

fn guardian_is_live(guardian: HANDLE) -> Result<bool, String> {
    // SAFETY: guardian is an owned synchronization handle for this attempt.
    match unsafe { WaitForSingleObject(guardian, 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error().to_string()),
        status => Err(format!("unexpected guardian wait status: {status}")),
    }
}

fn child_termination(status: u32) -> ChildTermination {
    i32::try_from(status)
        .ok()
        .filter(|code| (0..=255).contains(code))
        .map_or(ChildTermination::WindowsStatus { status }, |code| {
            ChildTermination::ExitCode { code }
        })
}

struct ActiveRegistration(String);

impl Drop for ActiveRegistration {
    fn drop(&mut self) {
        if let Ok(mut jobs) = ACTIVE_JOBS.lock() {
            jobs.retain(|active| active.attempt_id != self.0);
        }
    }
}

struct AttemptCleanup<'a> {
    job: &'a Job,
    disarm: HANDLE,
    guardian: HANDLE,
    record: super::record::WindowsAttemptRecordV1,
    armed: bool,
}

struct TargetCleanupBarrier<'a> {
    job: &'a Job,
    target: &'a SuspendedTarget,
    armed: bool,
}

impl<'a> TargetCleanupBarrier<'a> {
    fn new(job: &'a Job, target: &'a SuspendedTarget) -> Self {
        Self {
            job,
            target,
            armed: true,
        }
    }

    fn finish(mut self) {
        self.armed = false;
    }

    fn abandon_to_guardian(mut self) {
        self.armed = false;
    }
}

impl Drop for TargetCleanupBarrier<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.job.terminate(CANCEL_STATUS);
        let _ = self.target.wait(Duration::from_secs(30));
        let _ = self
            .job
            .wait_empty(Instant::now() + Duration::from_secs(30));
    }
}

impl<'a> AttemptCleanup<'a> {
    fn new(
        job: &'a Job,
        disarm: HANDLE,
        guardian: HANDLE,
        record: super::record::WindowsAttemptRecordV1,
    ) -> Self {
        if let Ok(mut failures) = FALLBACK_CLEANUP_FAILURES.lock() {
            failures.remove(&record.attempt_id);
        }
        Self {
            job,
            disarm,
            guardian,
            record,
            armed: true,
        }
    }

    fn finish(mut self) -> super::record::WindowsAttemptRecordV1 {
        self.armed = false;
        self.record.clone()
    }

    fn abandon_to_guardian(mut self) {
        self.armed = false;
    }
}

impl Drop for AttemptCleanup<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut failures = Vec::new();
        if self.record.authorization_unix_millis.is_none() && !self.record.resume_attempted {
            if let Err(error) = self.record.begin_preauthorization_abort() {
                failures.push(format!("record-preauthorization-abort: {error}"));
            }
        }
        if let Err(error) = self.job.terminate(CANCEL_STATUS) {
            failures.push(format!("terminate-job: {error}"));
        }
        let empty = match self
            .job
            .wait_empty(Instant::now() + Duration::from_secs(30))
        {
            Ok(empty) => empty,
            Err(error) => {
                failures.push(format!("wait-empty: {error}"));
                false
            }
        };
        // SAFETY: both handles remain owned by the enclosing attempt until this
        // guard has run, including every early-return path.
        let disarmed = unsafe { SetEvent(self.disarm) } != 0;
        if !disarmed {
            failures.push(format!("guardian-disarm: {}", io::Error::last_os_error()));
        }
        let guardian_reaped =
            disarmed && unsafe { WaitForSingleObject(self.guardian, 10_000) } == WAIT_OBJECT_0;
        if disarmed && !guardian_reaped {
            failures.push("guardian-reap: guardian did not become signaled".to_owned());
        }
        self.record.cleanup_state.termination_requested = true;
        self.record.cleanup_state.active_processes_zero = empty;
        self.record.cleanup_state.guardian_reaped = guardian_reaped;
        // Persist the observed cleanup before the enclosing scope closes its
        // final Job handles. The rejection builder runs only after this scope
        // has unwound; it may then prove those identities dead, record final
        // handle closure, and retire the record. A process crash in between
        // leaves this exact partial proof for startup recovery.
        if self.record.state != super::record::WindowsAttemptStateV1::Terminating
            && self.record.state != super::record::WindowsAttemptStateV1::Empty
        {
            if let Err(error) = self
                .record
                .transition(super::record::WindowsAttemptStateV1::Terminating)
            {
                failures.push(format!("record-transition: {error}"));
            }
        }
        if let Err(error) = self.record.store() {
            failures.push(format!("record-store: {error}"));
        }
        if !failures.is_empty() {
            if let Ok(mut stored) = FALLBACK_CLEANUP_FAILURES.lock() {
                stored.insert(self.record.attempt_id.clone(), failures);
            }
        }
    }
}

fn take_fallback_cleanup_failures(attempt_id: &str) -> Option<Vec<String>> {
    FALLBACK_CLEANUP_FAILURES
        .lock()
        .ok()
        .and_then(|mut failures| failures.remove(attempt_id))
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[allow(dead_code)]
fn cleanup_error(operation: &str, message: String) -> CleanupErrorRecord {
    CleanupErrorRecord {
        operation: operation.to_owned(),
        message,
    }
}
