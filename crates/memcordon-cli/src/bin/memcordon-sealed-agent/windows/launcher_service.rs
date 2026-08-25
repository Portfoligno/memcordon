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
use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, SetEvent, TerminateProcess,
    WaitForSingleObject,
};

use super::job::{Job, JobNotification};
use super::pipe::{self, OwnedHandle, PipeListener};
use super::process::{StreamSet, SuspendedTarget};
use super::security::{SecurityDescriptor, private_pipe_sddl};

const LIMIT_STATUS: u32 = 0xC000_0017;
const CANCEL_STATUS: u32 = 0xC000_013A;
const DEADLINE_STATUS: u32 = 0xC000_0102;

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
        let mut failure =
            Self::mutant_observed(observation, memcordon_core::BoundarySetupPhase::Retirement);
        failure.terminal_candidate = Some(Box::new(candidate));
        failure
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
}

static ACTIVE_JOBS: LazyLock<Mutex<Vec<ActiveJob>>> = LazyLock::new(|| Mutex::new(Vec::new()));

pub fn run() -> Result<(), String> {
    super::service::dispatch(WINDOWS_LAUNCHER_SERVICE_NAME, 2, service_main)
}

unsafe extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
    if let Err(error) = unsafe { super::service::announce_starting(WINDOWS_LAUNCHER_SERVICE_NAME) }
    {
        eprintln!("{error}");
        return;
    }
    let result = (|| {
        super::security::protect_current_service_process(WINDOWS_LAUNCHER_SERVICE_NAME)?;
        // Recovery is a capability gate: SCM must not observe RUNNING until
        // every durable attempt has been reconciled or quarantined.
        super::record::recover()?;
        let listener = PipeListener::new(
            WINDOWS_LAUNCHER_PIPE,
            SecurityDescriptor::from_sddl(&private_pipe_sddl()?)?,
        );
        let first = listener.prepare()?;
        super::service::announce_running()?;
        serve(listener, first)
    })();
    if let Err(error) = result {
        eprintln!("{error}");
        super::service::announce_stopped(1);
    } else {
        super::service::announce_stopped(0);
    }
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
            if let Err(error) = handle_control(connection.raw()) {
                let _ = pipe::write_frame(
                    connection.raw(),
                    &WindowsLauncherResponseV1::Reject {
                        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                        attempt_id: String::new(),
                        nonce: String::new(),
                        request_sha256: String::new(),
                        rejection: super::record::pretarget_rejection(
                            "MCSEALED-WINDOWS-LAUNCHER",
                            error,
                        ),
                    },
                );
            }
            pipe::disconnect(connection.raw());
        });
    }
    Ok(())
}

fn handle_control(connection: HANDLE) -> Result<(), String> {
    let first: WindowsLauncherRequestV1 = pipe::read_frame(connection)?;
    match first {
        WindowsLauncherRequestV1::Probe { schema_version }
            if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION =>
        {
            authenticate_control(connection)?;
            // SAFETY: pseudo-handle is live for the current process and queried only.
            let identity = super::process::process_identity(unsafe {
                windows_sys::Win32::System::Threading::GetCurrentProcess()
            })?;
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::Probe {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    process_identity: identity,
                },
            )
        }
        WindowsLauncherRequestV1::CertificationMachineRestart { schema_version }
            if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION =>
        {
            authenticate_control(connection)?;
            let recovered = super::record::certify_machine_restart_recovery()?;
            pipe::write_frame(
                connection,
                &WindowsLauncherResponseV1::CertificationMachineRestart {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                    recovered,
                },
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
            authenticate_control(connection)?;
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
                        Err(failure) => {
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
                            let rejection = super::record::rejection_evidence(
                                &attempt_id,
                                failure.code,
                                failure.detail,
                                failure.phase,
                                failure.os_code,
                            )?;
                            pipe::write_frame(
                                connection,
                                &WindowsLauncherResponseV1::Reject {
                                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                                    attempt_id,
                                    nonce,
                                    request_sha256,
                                    rejection,
                                },
                            )
                        }
                    }
                }
                _ => Err("membership query was not followed by a launch request".to_owned()),
            }
        }
        _ => Err("unsupported Windows private launcher request".to_owned()),
    }
}

fn authenticate_control(connection: HANDLE) -> Result<(), String> {
    let mut process_id = 0_u32;
    // SAFETY: connection is the connected server end of the private pipe.
    if unsafe { GetNamedPipeClientProcessId(connection, &raw mut process_id) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    // SAFETY: PID is supplied by the kernel for this pipe peer and only query
    // rights are requested.
    let process =
        OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) })?;
    super::process::verify_image_path(process.raw(), &super::package::installed_binary())?;
    if super::token::process_user_sid(process.raw())? != "S-1-5-19" {
        return Err("private launcher pipe peer is not LocalService".to_owned());
    }
    let control_sid = super::security::service_sid(WINDOWS_CONTROL_SERVICE_NAME)?;
    if !super::token::process_has_enabled_group(process.raw(), &control_sid, false)?
        || !super::token::process_has_enabled_group(process.raw(), &control_sid, true)?
    {
        return Err(
            "private launcher pipe peer lacks the enabled restricted control-service SID"
                .to_owned(),
        );
    }
    Ok(())
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
        authenticate_control(connection).map_err(LaunchAttemptError::from)?;
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
    if super::token::envelope(primary_token.raw())? != request.caller_token_envelope {
        return Err(
            "duplicated primary token does not match authenticated caller envelope"
                .to_owned()
                .into(),
        );
    }
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
        Some(super::process::create_guardian(
            job.handle(),
            frontend.raw(),
            // SAFETY: this pseudo-handle identifies the per-attempt worker thread;
            // create_guardian converts it to an independently owned real handle.
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
        )?)
    };
    let Some((guardian, _guardian_pid)) = guardian else {
        return Err(LaunchAttemptError::mutant_observed(
            memcordon_core::WindowsMutantNativeObservationV1::GuardianMissing,
            memcordon_core::BoundarySetupPhase::GuardianStartup,
        ));
    };
    let mut cleanup_guard = AttemptCleanup::new(&job, disarm.raw(), guardian.raw(), record);
    cleanup_guard.record.guardian_identity =
        Some(super::process::process_identity(guardian.raw())?);
    cleanup_guard
        .record
        .transition(super::record::WindowsAttemptStateV1::GuardianReady)?;
    cleanup_guard.record.store()?;
    super::record::retire_admission(&request.attempt_id)?;
    // SAFETY: ready remains live and guardian owns its inherited duplicate.
    if request.certification_mutant
        != Some(memcordon_core::WindowsSealedMutant::ResumeBeforeGuardian)
        && unsafe { WaitForSingleObject(ready.raw(), 10_000) } != WAIT_OBJECT_0
    {
        return Err("guardian did not become ready before target creation"
            .to_owned()
            .into());
    }

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
            cleanup_guard
                .record
                .transition(super::record::WindowsAttemptStateV1::Terminating)?;
            cleanup_guard.record.cleanup_state.termination_requested = true;
            cleanup_guard.record.store()?;
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
            record.retire()?;
            return Err($failure);
        }};
    }
    if request.certification_mutant != Some(memcordon_core::WindowsSealedMutant::ResumeBeforeRelays)
        && let Err(detail) = wait_for_relays_ready(
            connection,
            &request.attempt_id,
            &request.launch.nonce,
            &request.request_sha256,
            frontend.raw(),
            request.certification_fault,
        )
    {
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

    let certification_mode = request
        .launch
        .command
        .arguments
        .first()
        .is_some_and(|argument| {
            argument
                == &"windows-certification-target"
                    .encode_utf16()
                    .collect::<Vec<_>>()
                || argument
                    == &"windows-certification-nested-target"
                        .encode_utf16()
                        .collect::<Vec<_>>()
        })
        && super::record::qualification_in_progress();
    let mut target_command = request.launch.command.clone();
    let excluded_handles = if certification_mode {
        if frontend_canaries.len() != 6 {
            retire_preauthorization_without_target!(LaunchAttemptError::from(
                "frontend handle-canary inventory is not exact".to_owned()
            ));
        }
        let retained_arguments = if target_command.arguments.first().is_some_and(|argument| {
            argument
                == &"windows-certification-nested-target"
                    .encode_utf16()
                    .collect::<Vec<_>>()
        }) {
            3
        } else {
            2
        };
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
        target_command
            .arguments
            .extend(frontend_canaries.iter().map(|handle| {
                (handle.raw() as usize as u64)
                    .to_string()
                    .encode_utf16()
                    .collect()
            }));
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
    drop(excluded_handles);
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
            cleanup_guard
                .record
                .transition(super::record::WindowsAttemptStateV1::Terminating)?;
            cleanup_guard.record.cleanup_state.termination_requested = true;
            cleanup_guard.record.store()?;
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
            drop(streams);
            drop(relay_retired_event);
            drop(target);
            drop(guardian);
            drop(ready);
            drop(disarm);
            drop(registration);
            drop(job);
            record.retire()?;
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
            return Err(
                "initial target token readback differs from authenticated caller"
                    .to_owned()
                    .into(),
            );
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
    if let Some(
        mutant @ (memcordon_core::WindowsSealedMutant::ResumeBeforeGuardian
        | memcordon_core::WindowsSealedMutant::ResumeBeforeRelays),
    ) = request.certification_mutant
    {
        if let Err(detail) = cleanup_guard.record.mark_resume_attempted() {
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
        retire_preauthorization_with_target!(LaunchAttemptError::certification_fault(
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

    let monitored = monitor(connection, &request, &job, &target, guardian.raw(), started);
    let (outcome, mut control_connected, job_process_identities) = match monitored {
        Ok(observation) => observation,
        Err(detail)
            if request.certification_fault
                == Some(WindowsSealedFault::LauncherWorkerKilledAfterAuthorization) =>
        {
            cleanup_guard.abandon_to_guardian();
            drop(relay_retired_event);
            drop(target_token);
            drop(target);
            drop(guardian);
            drop(ready);
            drop(disarm);
            drop(registration);
            drop(job);
            pipe::disconnect(connection);
            return Err(LaunchAttemptError::authority_loss(detail));
        }
        Err(detail) => return Err(LaunchAttemptError::from(detail)),
    };
    let mut mutant_candidate = None;
    let mut mutant_observation = None;
    cleanup_guard
        .record
        .transition(super::record::WindowsAttemptStateV1::Terminating)?;
    cleanup_guard.record.cleanup_state.termination_requested = true;
    cleanup_guard.record.store()?;
    let mut cleanup_process_creation =
        certify_cleanup_process_creation(&request.launch.command.arguments, &job)?;
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
        mutant_candidate = Some(build_terminal_candidate(
            &request,
            target.process_id,
            started,
            authorization_offset,
            active_before_mutated_success,
            outcome.clone(),
            false,
            false,
            false,
            false,
        ));
    }
    let _ = job.terminate(CANCEL_STATUS);
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
    cleanup_guard.record.cleanup_state.active_processes_zero = true;
    if let Some(observation) = cleanup_process_creation.as_mut() {
        observation.final_active_processes_zero = true;
    }
    cleanup_guard.record.store()?;
    if !target.wait(Duration::from_secs(10))? {
        return Err("direct target did not become signaled during cleanup"
            .to_owned()
            .into());
    }
    let job_total_processes = job.total_processes()?;
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
    if request.certification_fault == Some(WindowsSealedFault::RecordRetire) {
        return Err(LaunchAttemptError::certification_fault(
            WindowsSealedFault::RecordRetire,
            memcordon_core::BoundarySetupPhase::Retirement,
        ));
    }
    record.retire()?;
    if request.certification_fault == Some(WindowsSealedFault::GuardianKilledAfterAuthorization) {
        return Err(LaunchAttemptError::certification_fault(
            WindowsSealedFault::GuardianKilledAfterAuthorization,
            memcordon_core::BoundarySetupPhase::Retirement,
        ));
    }

    let receipt = build_terminal_receipt(
        &request,
        child_pid,
        started,
        authorization_offset,
        job_total_processes,
        job_process_identities,
        cleanup_process_creation,
        outcome,
    );
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
    if control_connected {
        pipe::write_frame(connection, &WindowsLauncherResponseV1::Terminal(receipt))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Keep independently verified terminal facts explicit.
fn build_terminal_receipt(
    request: &WindowsLaunchBrokerRequestV1,
    child_pid: u32,
    started: Instant,
    authorization_offset: Duration,
    job_total_processes: u32,
    job_process_identities: Vec<memcordon_core::WindowsProcessIdentityV1>,
    cleanup_process_creation: Option<WindowsCleanupProcessCreationEvidenceV1>,
    outcome: RunOutcome,
) -> WindowsTerminalReceiptV1 {
    let cleanup_errors = outcome
        .cleanup()
        .errors
        .iter()
        .map(|error| error.message.clone())
        .collect();
    WindowsTerminalReceiptV1 {
        schema_version: 1,
        attempt_id: request.attempt_id.clone(),
        nonce: request.launch.nonce.clone(),
        request_sha256: request.request_sha256.clone(),
        child_pid,
        duration_millis: millis(started.elapsed()),
        authorization_offset_millis: millis(authorization_offset),
        job_total_processes,
        job_process_identities,
        cleanup_process_creation,
        outcome,
        restart_safety: RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: true,
            sealed_boundary_retired: true,
            errors: cleanup_errors,
        },
        boundary_detail: complete_windows_boundary_evidence(),
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
    let mut evidence = match complete_windows_boundary_evidence() {
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

fn complete_windows_boundary_evidence() -> BoundaryMechanismEvidence {
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
        let available = match pipe::frame_available(connection) {
            Ok(available) => available,
            Err(_) => return Ok(false),
        };
        if available {
            let frame = match pipe::read_frame::<WindowsLauncherRequestV1>(connection) {
                Ok(frame) => frame,
                Err(_) => return Ok(false),
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

fn certify_cleanup_process_creation(
    arguments: &[Vec<u16>],
    job: &Job,
) -> Result<Option<WindowsCleanupProcessCreationEvidenceV1>, LaunchAttemptError> {
    use std::os::windows::ffi::OsStringExt;

    let Some(mode) = arguments.first() else {
        return Ok(None);
    };
    let mode = String::from_utf16(mode).map_err(|error| error.to_string())?;
    let marker_index = if mode == "windows-certification-target" {
        1
    } else if mode == "windows-certification-nested-target" {
        2
    } else {
        return Ok(None);
    };
    let marker = arguments
        .get(marker_index)
        .map(|value| std::path::PathBuf::from(std::ffi::OsString::from_wide(value)))
        .ok_or_else(|| "cleanup-creation marker is absent".to_owned())?;
    let total_processes_before = job.total_processes()?;
    std::fs::write(marker.with_extension("start"), b"terminating\n")
        .map_err(|error| error.to_string())?;
    let result = marker.with_extension("result");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !result.is_file() {
        if Instant::now() >= deadline {
            return Err("cleanup-time process creation was not attempted"
                .to_owned()
                .into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let child_pid = std::fs::read_to_string(&result)
        .map_err(|error| error.to_string())?
        .trim()
        .parse::<u32>()
        .map_err(|error| error.to_string())?;
    let child_job_membership_verified = job.process_ids()?.contains(&child_pid);
    let total_processes_after = job.total_processes()?;
    let evidence = WindowsCleanupProcessCreationEvidenceV1 {
        schema_version: 1,
        attempted_after_terminating_transition: true,
        child_created: true,
        child_job_membership_verified,
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

enum TerminalReason {
    Direct(u32),
    Deadline,
    Memory(u64),
    Interrupted(i32),
}

fn monitor(
    connection: HANDLE,
    request: &WindowsLaunchBrokerRequestV1,
    job: &Job,
    target: &SuspendedTarget,
    guardian: HANDLE,
    started: Instant,
) -> Result<
    (
        RunOutcome,
        bool,
        Vec<memcordon_core::WindowsProcessIdentityV1>,
    ),
    String,
> {
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
                    return Err("certification removed the per-attempt launcher worker".to_owned());
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
                    return Err("launcher service termination unexpectedly returned".to_owned());
                }
                Some(WindowsSealedFault::AllJobOwnersClosedAfterAuthorization) => {
                    // SAFETY: removing guardian then launcher closes every Job
                    // owner; kill-on-close must retire the entire workload.
                    if unsafe { TerminateProcess(guardian, CANCEL_STATUS) } == 0 {
                        return Err("all-owner scenario could not terminate guardian".to_owned());
                    }
                    unsafe {
                        TerminateProcess(
                            windows_sys::Win32::System::Threading::GetCurrentProcess(),
                            CANCEL_STATUS,
                        )
                    };
                    return Err("all-owner launcher termination unexpectedly returned".to_owned());
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
                return Err("failed to inject postauthorization guardian loss".to_owned());
            }
            guardian_loss_injected = true;
        }
        if !guardian_is_live(guardian)? {
            break TerminalReason::Interrupted(15);
        }
        for process_id in job.process_ids()? {
            if job_process_identities.iter().any(
                |identity: &memcordon_core::WindowsProcessIdentityV1| {
                    identity.process_id == process_id
                },
            ) {
                continue;
            }
            if job_process_identities.len() == memcordon_core::WINDOWS_MAX_JOB_PROCESS_IDENTITIES {
                return Err("Job process-identity observation limit was exceeded".to_owned());
            }
            if let Some(identity) = super::process::process_identity_for_pid(process_id)? {
                job_process_identities.push(identity);
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
                        return Err("invalid control message during target execution".to_owned());
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
    let status = match reason {
        TerminalReason::Direct(_) => CANCEL_STATUS,
        TerminalReason::Deadline => DEADLINE_STATUS,
        TerminalReason::Memory(_) => LIMIT_STATUS,
        TerminalReason::Interrupted(_) => CANCEL_STATUS,
    };
    job.terminate(status)?;
    let child_after_termination = if matches!(reason, TerminalReason::Direct(_)) {
        None
    } else {
        if !target.wait(Duration::from_secs(30))? {
            return Err("direct target remained active after Job termination".to_owned());
        }
        Some(child_termination(target.exit_status()?))
    };
    let cleanup = CleanupSummary {
        force_attempted: true,
        direct_child_reaped: true,
        workload_empty: Some(true),
        ..CleanupSummary::default()
    };
    let peak = job.peak_memory().ok().map(ByteSize::from_bytes);
    let outcome = match reason {
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
    };
    outcome.map(|outcome| (outcome, control_connected, job_process_identities))
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

impl<'a> AttemptCleanup<'a> {
    fn new(
        job: &'a Job,
        disarm: HANDLE,
        guardian: HANDLE,
        record: super::record::WindowsAttemptRecordV1,
    ) -> Self {
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
        let _ = self.job.terminate(CANCEL_STATUS);
        let empty = self
            .job
            .wait_empty(Instant::now() + Duration::from_secs(30))
            .unwrap_or(false);
        // SAFETY: both handles remain owned by the enclosing attempt until this
        // guard has run, including every early-return path.
        let disarmed = unsafe { SetEvent(self.disarm) } != 0;
        let guardian_reaped =
            disarmed && unsafe { WaitForSingleObject(self.guardian, 10_000) } == WAIT_OBJECT_0;
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
            let _ = self
                .record
                .transition(super::record::WindowsAttemptStateV1::Terminating);
        }
        let _ = self.record.store();
    }
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
