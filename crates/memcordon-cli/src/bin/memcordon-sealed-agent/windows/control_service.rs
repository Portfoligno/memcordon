use std::io;
use std::ptr;

use memcordon_core::{
    WINDOWS_CONTROL_PIPE, WINDOWS_CONTROL_SERVICE_NAME, WINDOWS_LAUNCHER_PIPE,
    WINDOWS_LAUNCHER_SERVICE_NAME, WINDOWS_PRIVATE_PROTOCOL_VERSION,
    WINDOWS_PUBLIC_PROTOCOL_VERSION, WindowsLaunchBrokerRequestV1, WindowsLauncherRequestV1,
    WindowsLauncherResponseV1, WindowsProcessIdentityV1, WindowsProviderRequestV1,
    WindowsProviderResponseV1, WindowsRelayEventV1, WindowsRelayPhaseV1, WindowsSealedFault,
    WindowsSealedMutant, WindowsServiceSelfAttestationV1,
};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::pipe::{self, OwnedHandle, PipeListener, PipePreparationError};
use super::security::{NamedPipeSecurityError, SecurityDescriptor, public_pipe_sddl};

const STARTUP_PROCESS_PROTECTION: u32 = 0x4d43_0101;
const STARTUP_STATE_RECONCILIATION: u32 = 0x4d43_0102;
const STARTUP_PIPE_PREPARATION: u32 = 0x4d43_0103;
const STARTUP_LAUNCHER_AUTHENTICATION: u32 = 0x4d43_0104;
const STARTUP_RUNNING_ANNOUNCEMENT: u32 = 0x4d43_0105;
const STARTUP_SERVICE_LOOP: u32 = 0x4d43_0106;
const STARTUP_PIPE_SECURITY_READBACK: u32 = 0x4d43_0107;
const STARTUP_PIPE_SECURITY_MISMATCH: u32 = 0x4d43_0108;
const STARTUP_LAUNCHER_AUTHENTICATION_PIPE_CONNECT: u32 = 0x4d43_0301;
const STARTUP_LAUNCHER_AUTHENTICATION_PIPE_POLICY: u32 = 0x4d43_0302;
const STARTUP_LAUNCHER_AUTHENTICATION_PIPE_SECURITY_READBACK: u32 = 0x4d43_0303;
const STARTUP_LAUNCHER_AUTHENTICATION_PIPE_SECURITY_MISMATCH: u32 = 0x4d43_0304;
const STARTUP_LAUNCHER_AUTHENTICATION_PEER_PID: u32 = 0x4d43_0305;
const STARTUP_LAUNCHER_AUTHENTICATION_PROCESS_OPEN: u32 = 0x4d43_0306;
const STARTUP_LAUNCHER_AUTHENTICATION_IMAGE: u32 = 0x4d43_0307;
const STARTUP_LAUNCHER_AUTHENTICATION_TOKEN_OPEN: u32 = 0x4d43_0308;
const STARTUP_LAUNCHER_AUTHENTICATION_ORDINARY_SID: u32 = 0x4d43_0309;
const STARTUP_LAUNCHER_AUTHENTICATION_RESTRICTING_SID: u32 = 0x4d43_030a;
const STARTUP_LAUNCHER_AUTHENTICATION_PROCESS_IDENTITY: u32 = 0x4d43_030b;
const STARTUP_LAUNCHER_AUTHENTICATION_PROBE_WRITE: u32 = 0x4d43_030c;
const STARTUP_LAUNCHER_AUTHENTICATION_PROBE_READ: u32 = 0x4d43_030d;
const STARTUP_LAUNCHER_AUTHENTICATION_PROBE_SCHEMA: u32 = 0x4d43_030e;
const STARTUP_LAUNCHER_AUTHENTICATION_PROBE_IDENTITY: u32 = 0x4d43_030f;
const STARTUP_LAUNCHER_AUTHENTICATION_PEER_REJECTED: u32 = 0x4d43_0310;
const STARTUP_LAUNCHER_AUTHENTICATION_RESPONSE_KIND: u32 = 0x4d43_0311;
const STARTUP_LAUNCHER_AUTHENTICATION_TOKEN_USER_QUERY: u32 = 0x4d43_0312;
const STARTUP_LAUNCHER_AUTHENTICATION_ACCOUNT_MISMATCH: u32 = 0x4d43_0313;
const STARTUP_LAUNCHER_AUTHENTICATION_PROBE_ATTESTATION: u32 = 0x4d43_0314;
const STARTUP_LAUNCHER_AUTHENTICATION_PROBE_CHALLENGE: u32 = 0x4d43_0315;
const STARTUP_CONTROL_AUTHENTICATION_PEER_PID: u32 = 0x4d43_0320;
const STARTUP_CONTROL_AUTHENTICATION_PROCESS_OPEN: u32 = 0x4d43_0321;
const STARTUP_CONTROL_AUTHENTICATION_IMAGE: u32 = 0x4d43_0322;
const STARTUP_CONTROL_AUTHENTICATION_TOKEN_OPEN: u32 = 0x4d43_0323;
const STARTUP_CONTROL_AUTHENTICATION_TOKEN_USER_QUERY: u32 = 0x4d43_0324;
const STARTUP_CONTROL_AUTHENTICATION_ACCOUNT_MISMATCH: u32 = 0x4d43_0325;
const STARTUP_CONTROL_AUTHENTICATION_ORDINARY_SID: u32 = 0x4d43_0326;
const STARTUP_CONTROL_AUTHENTICATION_RESTRICTING_SID: u32 = 0x4d43_0327;

pub fn run() -> Result<(), String> {
    super::service::dispatch(WINDOWS_CONTROL_SERVICE_NAME, 1, service_main)
}

unsafe extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
    if let Err(error) = unsafe { super::service::announce_starting(WINDOWS_CONTROL_SERVICE_NAME) } {
        eprintln!("{error}");
        return;
    }
    let startup = (|| -> Result<(PipeListener, OwnedHandle), (u32, String)> {
        super::security::protect_current_service_process(WINDOWS_CONTROL_SERVICE_NAME)
            .map_err(|error| (STARTUP_PROCESS_PROTECTION, error))?;
        super::security::converge_current_service_token_peer_query(WINDOWS_CONTROL_SERVICE_NAME)
            .map_err(|error| {
                super::security::token_dacl_startup_error(WINDOWS_CONTROL_SERVICE_NAME, error)
            })?;
        super::record::reconcile_attempt_state()
            .map_err(|error| (STARTUP_STATE_RECONCILIATION, error))?;
        let listener = PipeListener::new(
            WINDOWS_CONTROL_PIPE,
            SecurityDescriptor::from_sddl(
                &public_pipe_sddl().map_err(|error| (STARTUP_PIPE_PREPARATION, error))?,
            )
            .map_err(|error| (STARTUP_PIPE_PREPARATION, error))?,
        );
        let first = listener.prepare().map_err(pipe_startup_error)?;
        probe_authenticated_launcher_detailed()
            .map_err(|error| (error.phase, error.to_string()))?;
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

#[derive(Debug)]
struct LauncherAuthenticationError {
    phase: u32,
    detail: String,
}

impl LauncherAuthenticationError {
    fn new(phase: u32, detail: impl ToString) -> Self {
        Self {
            phase,
            detail: detail.to_string(),
        }
    }
}

impl std::fmt::Display for LauncherAuthenticationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subphase =
            launcher_authentication_diagnostic_from_exit(self.phase).unwrap_or("authentication");
        write!(
            formatter,
            "MCSEALED-WINDOWS-LAUNCHER-AUTHENTICATION: subphase={subphase} error={}",
            self.detail
        )
    }
}

pub(crate) const fn launcher_authentication_diagnostic_from_exit(
    code: u32,
) -> Option<&'static str> {
    match code {
        STARTUP_LAUNCHER_AUTHENTICATION => Some("authentication"),
        STARTUP_LAUNCHER_AUTHENTICATION_PIPE_CONNECT => Some("pipe-connect"),
        STARTUP_LAUNCHER_AUTHENTICATION_PIPE_POLICY => Some("pipe-policy"),
        STARTUP_LAUNCHER_AUTHENTICATION_PIPE_SECURITY_READBACK => Some("pipe-security-readback"),
        STARTUP_LAUNCHER_AUTHENTICATION_PIPE_SECURITY_MISMATCH => Some("pipe-security-mismatch"),
        STARTUP_LAUNCHER_AUTHENTICATION_PEER_PID => Some("peer-pid"),
        STARTUP_LAUNCHER_AUTHENTICATION_PROCESS_OPEN => Some("process-open"),
        STARTUP_LAUNCHER_AUTHENTICATION_IMAGE => Some("image"),
        STARTUP_LAUNCHER_AUTHENTICATION_TOKEN_OPEN => Some("token-open"),
        STARTUP_LAUNCHER_AUTHENTICATION_ORDINARY_SID => Some("ordinary-service-sid"),
        STARTUP_LAUNCHER_AUTHENTICATION_RESTRICTING_SID => Some("restricting-service-sid"),
        STARTUP_LAUNCHER_AUTHENTICATION_PROCESS_IDENTITY => Some("process-identity"),
        STARTUP_LAUNCHER_AUTHENTICATION_PROBE_WRITE => Some("probe-write"),
        STARTUP_LAUNCHER_AUTHENTICATION_PROBE_READ => Some("probe-read"),
        STARTUP_LAUNCHER_AUTHENTICATION_PROBE_SCHEMA => Some("probe-schema"),
        STARTUP_LAUNCHER_AUTHENTICATION_PROBE_IDENTITY => Some("probe-identity"),
        STARTUP_LAUNCHER_AUTHENTICATION_PEER_REJECTED => Some("launcher-peer-rejected"),
        STARTUP_LAUNCHER_AUTHENTICATION_RESPONSE_KIND => Some("probe-response-kind"),
        STARTUP_LAUNCHER_AUTHENTICATION_TOKEN_USER_QUERY => Some("token-user-query"),
        STARTUP_LAUNCHER_AUTHENTICATION_ACCOUNT_MISMATCH => Some("account-mismatch"),
        _ => None,
    }
}

pub(crate) const fn control_authentication_diagnostic_from_exit(code: u32) -> Option<&'static str> {
    match code {
        STARTUP_CONTROL_AUTHENTICATION_PEER_PID => Some("peer-pid"),
        STARTUP_CONTROL_AUTHENTICATION_PROCESS_OPEN => Some("process-open"),
        STARTUP_CONTROL_AUTHENTICATION_IMAGE => Some("image"),
        STARTUP_CONTROL_AUTHENTICATION_TOKEN_OPEN => Some("token-open"),
        STARTUP_CONTROL_AUTHENTICATION_TOKEN_USER_QUERY => Some("token-user-query"),
        STARTUP_CONTROL_AUTHENTICATION_ACCOUNT_MISMATCH => Some("account-mismatch"),
        STARTUP_CONTROL_AUTHENTICATION_ORDINARY_SID => Some("ordinary-service-sid"),
        STARTUP_CONTROL_AUTHENTICATION_RESTRICTING_SID => Some("restricting-service-sid"),
        _ => None,
    }
}

fn control_authentication_phase_from_rejection_code(code: &str) -> Option<u32> {
    match code {
        "MCSEALED-WINDOWS-CONTROL-AUTH-PEER-PID" => Some(STARTUP_CONTROL_AUTHENTICATION_PEER_PID),
        "MCSEALED-WINDOWS-CONTROL-AUTH-PROCESS-OPEN" => {
            Some(STARTUP_CONTROL_AUTHENTICATION_PROCESS_OPEN)
        }
        "MCSEALED-WINDOWS-CONTROL-AUTH-IMAGE" => Some(STARTUP_CONTROL_AUTHENTICATION_IMAGE),
        "MCSEALED-WINDOWS-CONTROL-AUTH-TOKEN-OPEN" => {
            Some(STARTUP_CONTROL_AUTHENTICATION_TOKEN_OPEN)
        }
        "MCSEALED-WINDOWS-CONTROL-AUTH-TOKEN-USER-QUERY" => {
            Some(STARTUP_CONTROL_AUTHENTICATION_TOKEN_USER_QUERY)
        }
        "MCSEALED-WINDOWS-CONTROL-AUTH-ACCOUNT-MISMATCH" => {
            Some(STARTUP_CONTROL_AUTHENTICATION_ACCOUNT_MISMATCH)
        }
        "MCSEALED-WINDOWS-CONTROL-AUTH-ORDINARY-SID" => {
            Some(STARTUP_CONTROL_AUTHENTICATION_ORDINARY_SID)
        }
        "MCSEALED-WINDOWS-CONTROL-AUTH-RESTRICTING-SID" => {
            Some(STARTUP_CONTROL_AUTHENTICATION_RESTRICTING_SID)
        }
        _ => None,
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
            let response_written = handle_client(connection.raw())
                .map_err(|error| {
                    eprintln!("MCSEALED-WINDOWS-CONTROL-CONNECTION: {error}");
                    error
                })
                .is_ok();
            if response_written {
                if let Err(error) = pipe::finish_server_response(connection.raw()) {
                    eprintln!("MCSEALED-WINDOWS-CONTROL-RESPONSE-DRAIN: {error}");
                }
            } else {
                pipe::disconnect(connection.raw());
            }
        });
    }
    Ok(())
}

fn stable_error_code(error: &str) -> &str {
    error
        .split_once(':')
        .map_or("MCSEALED-WINDOWS-CONTROL", |(code, _)| {
            if code.starts_with("MCSEALED-WINDOWS-") {
                code
            } else {
                "MCSEALED-WINDOWS-CONTROL"
            }
        })
}

#[derive(Clone, Debug)]
struct LaunchBinding {
    attempt_id: String,
    nonce: String,
    request_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchResponseState {
    None,
    BoundAttemptActive,
    TerminalDelivered,
}

#[derive(Clone, Debug)]
struct LaunchProgress {
    binding: Option<LaunchBinding>,
    relay_phase: WindowsRelayPhaseV1,
    response_state: LaunchResponseState,
}

impl Default for LaunchProgress {
    fn default() -> Self {
        Self {
            binding: None,
            relay_phase: WindowsRelayPhaseV1::AwaitStreams,
            response_state: LaunchResponseState::None,
        }
    }
}

#[derive(Debug)]
struct LaunchClientFailure {
    progress: LaunchProgress,
    detail: String,
}

impl LaunchClientFailure {
    fn diagnostic(self) -> String {
        format!(
            "{}; relay_phase={:?} response_state={:?}",
            self.detail, self.progress.relay_phase, self.progress.response_state
        )
    }
}

fn handle_client(public: HANDLE) -> Result<(), String> {
    // A package-cleanup transaction temporarily grants the package principal
    // deletion rights to proven-empty leaf directories. A crashed caller can
    // never leave that transition usable by a later launch: startup and every
    // public admission restore and read back the exact runtime descriptors.
    super::record::reharden_attempt_state()?;
    let request: WindowsProviderRequestV1 = pipe::read_frame(public)?;
    match request {
        WindowsProviderRequestV1::Probe { schema_version }
            if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
        {
            if super::record::qualification_in_progress() {
                return Err(
                    "MCSEALED-WINDOWS-QUALIFICATION-IN-PROGRESS: capability is not committed"
                        .to_owned(),
                );
            }
            if !super::record::recovery_clear()? {
                return Err(
                    "MCSEALED-WINDOWS-RECOVERY-AMBIGUOUS: provider state is not clear".to_owned(),
                );
            }
            probe_authenticated_launcher()?;
            pipe::write_frame(
                public,
                &WindowsProviderResponseV1::Probe {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    qualification: super::qualification::local_receipt()?,
                },
            )
        }
        WindowsProviderRequestV1::RecoveryStatus {
            schema_version,
            challenge,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION && !challenge.is_empty() => {
            let (status, attempts_empty, detail) = match super::record::attempts_empty() {
                Ok(true) => (
                    memcordon_core::WindowsControlRequestStatusV1::Ready,
                    Some(true),
                    "recovery state is empty".to_owned(),
                ),
                Ok(false) => (
                    memcordon_core::WindowsControlRequestStatusV1::Active,
                    Some(false),
                    "MCSEALED-WINDOWS-PACKAGE-ACTIVE: recovery state is not empty".to_owned(),
                ),
                Err(error) => (
                    memcordon_core::WindowsControlRequestStatusV1::Failed,
                    None,
                    error,
                ),
            };
            pipe::write_frame(
                public,
                &WindowsProviderResponseV1::RecoveryStatus {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    challenge,
                    status,
                    attempts_empty,
                    detail,
                },
            )
        }
        WindowsProviderRequestV1::PackageCleanup {
            schema_version,
            challenge,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION && !challenge.is_empty() => {
            if !super::token::pipe_client_is_elevated(public)? {
                return Err(
                    "MCSEALED-WINDOWS-ELEVATION: package cleanup requires an elevated caller"
                        .to_owned(),
                );
            }
            let result = super::record::remove_empty_attempt_state();
            let (status, attempts_empty, detail) = match result {
                Ok(()) => (
                    memcordon_core::WindowsControlRequestStatusV1::Ready,
                    Some(true),
                    "package cleanup is ready".to_owned(),
                ),
                Err(error)
                    if error
                        .strip_prefix("MCSEALED-WINDOWS-PACKAGE-ACTIVE:")
                        .is_some() =>
                {
                    (
                        memcordon_core::WindowsControlRequestStatusV1::Active,
                        Some(false),
                        error,
                    )
                }
                Err(error) => (
                    memcordon_core::WindowsControlRequestStatusV1::Failed,
                    None,
                    error,
                ),
            };
            pipe::write_frame(
                public,
                &WindowsProviderResponseV1::PackageCleanupResult {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    challenge,
                    status,
                    attempts_empty,
                    terminal_outboxes: super::record::terminal_outbox_count().ok(),
                    detail,
                },
            )
        }
        WindowsProviderRequestV1::QualificationBegin {
            schema_version,
            scope,
            challenge,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION => {
            qualification_session(public, &scope, &challenge)
        }
        WindowsProviderRequestV1::ReplayTerminal {
            schema_version,
            attempt_id,
            nonce,
            request_sha256,
            relay_phase,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION => {
            let caller = authenticate_replay_binding(public, &attempt_id, &nonce, &request_sha256)?;
            replay_terminal_session(
                public,
                attempt_id,
                nonce,
                request_sha256,
                relay_phase,
                caller,
            )
        }
        WindowsProviderRequestV1::Launch(launch)
            if launch.schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
        {
            let nonce = launch.nonce.clone();
            let request_sha256 = hex(Sha256::digest(
                serde_json::to_vec(&launch).map_err(|error| error.to_string())?,
            ));
            match launch_client(public, launch, None, None) {
                Ok(()) => Ok(()),
                Err(failure) => {
                    let code = stable_error_code(&failure.detail).to_owned();
                    match (&failure.progress.binding, failure.progress.response_state) {
                        (Some(binding), LaunchResponseState::None) => pipe::write_frame(
                            public,
                            &WindowsProviderResponseV1::Reject {
                                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                                attempt_id: binding.attempt_id.clone(),
                                nonce: binding.nonce.clone(),
                                request_sha256: binding.request_sha256.clone(),
                                rejection: super::record::pretarget_rejection_at(
                                    &code,
                                    pretarget_phase(&code),
                                    failure.detail,
                                ),
                            },
                        ),
                        (None, LaunchResponseState::None) => {
                            let mut identity = Sha256::new();
                            identity.update(nonce.as_bytes());
                            identity.update(request_sha256.as_bytes());
                            identity.update(b"pretarget-rejection-v1");
                            pipe::write_frame(
                                public,
                                &WindowsProviderResponseV1::Reject {
                                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                                    attempt_id: hex(identity.finalize()),
                                    nonce,
                                    request_sha256,
                                    rejection: super::record::pretarget_rejection_at(
                                        &code,
                                        pretarget_phase(&code),
                                        failure.detail,
                                    ),
                                },
                            )
                        }
                        (Some(binding), response_state) => {
                            let primary = failure.detail.clone();
                            let replay_error = if response_state
                                == LaunchResponseState::BoundAttemptActive
                            {
                                match authenticate_replay_binding(
                                    public,
                                    &binding.attempt_id,
                                    &binding.nonce,
                                    &binding.request_sha256,
                                ) {
                                    Ok(caller) => match replay_terminal(
                                        public,
                                        &binding.attempt_id,
                                        &binding.nonce,
                                        &binding.request_sha256,
                                        failure.progress.relay_phase,
                                        &caller,
                                    ) {
                                        Ok(_) => return Ok(()),
                                        Err(error) => error,
                                    },
                                    Err(error) => error,
                                }
                            } else {
                                "terminal was delivered but durable retirement was not confirmed"
                                    .to_owned()
                            };
                            let retained = super::record::retained_attempt_evidence(
                                &binding.attempt_id,
                                &binding.nonce,
                                &binding.request_sha256,
                                failure.progress.relay_phase,
                                primary,
                                vec![replay_error],
                            )?;
                            pipe::write_frame(
                                public,
                                &WindowsProviderResponseV1::AttemptRetained(retained),
                            )
                        }
                        _ => Err(failure.diagnostic()),
                    }
                }
            }
        }
        WindowsProviderRequestV1::CertificationFault {
            schema_version,
            fault,
            attempt_id,
            request_sha256,
            caller_process_identity,
            launch,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && launch.schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
        {
            if !super::package::certification_faults_enabled()
                || !super::token::pipe_client_is_elevated(public)?
            {
                return Err(
                    "Windows fault injection is available only to elevated ephemeral certification"
                        .to_owned(),
                );
            }
            validate_certification_binding(
                &launch,
                &attempt_id,
                &request_sha256,
                &caller_process_identity,
            )?;
            if control_fault(fault) {
                exercise_control_fault(public, fault)?;
                pipe::write_frame(
                    public,
                    &WindowsProviderResponseV1::Reject {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id,
                        nonce: launch.nonce.clone(),
                        request_sha256,
                        rejection: super::record::pretarget_rejection(
                            "MCSEALED-WINDOWS-CERTIFICATION-FAULT",
                            format!("injected preauthorization fault: {fault:?}"),
                        ),
                    },
                )
            } else {
                launch_client(public, launch, Some(fault), None)
                    .map_err(LaunchClientFailure::diagnostic)
            }
        }
        WindowsProviderRequestV1::CertificationMutant {
            schema_version,
            mutant,
            attempt_id,
            request_sha256,
            caller_process_identity,
            launch,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && launch.schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
        {
            if !super::package::certification_faults_enabled()
                || !super::token::pipe_client_is_elevated(public)?
            {
                return Err(
                    "Windows mutant execution is available only to elevated ephemeral certification"
                        .to_owned(),
                );
            }
            validate_certification_binding(
                &launch,
                &attempt_id,
                &request_sha256,
                &caller_process_identity,
            )?;
            launch_client(public, launch, None, Some(mutant))
                .map_err(LaunchClientFailure::diagnostic)
        }
        WindowsProviderRequestV1::CertificationMachineRestart { schema_version }
            if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
        {
            if !super::package::certification_faults_enabled()
                || !super::token::pipe_client_is_elevated(public)?
            {
                return Err(
                    "machine-restart certification requires elevated ephemeral CI".to_owned(),
                );
            }
            let (launcher, _process, _identity) = authenticated_launcher()?;
            pipe::write_frame(
                launcher.raw(),
                &WindowsLauncherRequestV1::CertificationMachineRestart {
                    schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                },
            )?;
            match pipe::read_frame::<WindowsLauncherResponseV1>(launcher.raw())? {
                WindowsLauncherResponseV1::CertificationMachineRestart {
                    schema_version,
                    recovered,
                } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION => pipe::write_frame(
                    public,
                    &WindowsProviderResponseV1::CertificationMachineRestart {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        recovered,
                    },
                ),
                _ => Err("launcher returned invalid machine-restart evidence".to_owned()),
            }
        }
        _ => Err("unsupported Windows public provider request".to_owned()),
    }
}

fn pretarget_phase(code: &str) -> memcordon_core::BoundarySetupPhase {
    match code {
        "MCSEALED-WINDOWS-APPCONTAINER-UNSUPPORTED" => {
            memcordon_core::BoundarySetupPhase::CredentialTransitionPolicy
        }
        "MCSEALED-WINDOWS-QUALIFICATION-IN-PROGRESS" => {
            memcordon_core::BoundarySetupPhase::ProviderIdentity
        }
        "MCSEALED-WINDOWS-RECOVERY-AMBIGUOUS" => {
            memcordon_core::BoundarySetupPhase::ProviderConnection
        }
        _ => memcordon_core::BoundarySetupPhase::CallerEnvelopeCapture,
    }
}

fn qualification_session(public: HANDLE, scope: &str, challenge: &str) -> Result<(), String> {
    if !matches!(scope, "direct" | "package") {
        return Err("invalid Windows qualification admission scope".to_owned());
    }
    let mut client_pid = 0_u32;
    // SAFETY: public is a connected server pipe and output is writable.
    if unsafe { GetNamedPipeClientProcessId(public, &raw mut client_pid) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let (_token, envelope, _frontend, owner) =
        super::token::authenticate_pipe_client(public, client_pid, None)?;
    if !envelope.elevated {
        return Err("MCSEALED-WINDOWS-ELEVATION: qualification requires elevation".to_owned());
    }
    let control_attestation = super::token::current_service_self_attestation(
        "control-service",
        WINDOWS_CONTROL_SERVICE_NAME,
        super::package::CONTROL_PRIVILEGES,
        challenge,
    )
    .map_err(|error| error.to_string())?;
    let launcher_attestation =
        launcher_self_attestation_detailed(challenge).map_err(|error| error.to_string())?;
    // The authenticated caller still owns the package mutex here. Publish the
    // service-owned durable admission before acknowledging authentication, so
    // dropping the caller's mutex cannot expose an unrepresented handoff gap.
    if !super::record::attempts_empty()? {
        return Err(
            "MCSEALED-WINDOWS-QUALIFICATION-ACTIVE: attempt or recovery state is active".to_owned(),
        );
    }
    let admission = super::record::reserve_qualification_admission_for(scope, owner.clone())?;
    pipe::write_frame(
        public,
        &WindowsProviderResponseV1::QualificationAuthenticated {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            control_attestation,
            launcher_attestation,
        },
    )?;
    match pipe::read_frame::<WindowsProviderRequestV1>(public)? {
        WindowsProviderRequestV1::QualificationAcquire { schema_version }
            if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION => {}
        _ => return Err("qualification admission acquisition was not authorized".to_owned()),
    }
    pipe::write_frame(
        public,
        &WindowsProviderResponseV1::QualificationReady {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        },
    )?;
    loop {
        match pipe::read_frame::<WindowsProviderRequestV1>(public)? {
            WindowsProviderRequestV1::QualificationAuthorizeChild {
                schema_version,
                child_process_identity,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION => {
                super::record::authorize_qualification_child_for(
                    scope,
                    &owner,
                    child_process_identity,
                )?;
                pipe::write_frame(
                    public,
                    &WindowsProviderResponseV1::QualificationChildAuthorized {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    },
                )?;
            }
            WindowsProviderRequestV1::QualificationEnd { schema_version }
                if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
            {
                drop(admission);
                return pipe::write_frame(
                    public,
                    &WindowsProviderResponseV1::QualificationEnded {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    },
                );
            }
            _ => return Err("invalid request in Windows qualification session".to_owned()),
        }
    }
}

fn launch_client(
    public: HANDLE,
    launch: memcordon_core::WindowsLaunchRequestV1,
    certification_fault: Option<WindowsSealedFault>,
    certification_mutant: Option<WindowsSealedMutant>,
) -> Result<(), LaunchClientFailure> {
    let mut progress = LaunchProgress::default();
    launch_client_inner(
        public,
        launch,
        certification_fault,
        certification_mutant,
        &mut progress,
    )
    .map_err(|detail| LaunchClientFailure { progress, detail })
}

fn launch_client_inner(
    public: HANDLE,
    launch: memcordon_core::WindowsLaunchRequestV1,
    certification_fault: Option<WindowsSealedFault>,
    certification_mutant: Option<WindowsSealedMutant>,
    progress: &mut LaunchProgress,
) -> Result<(), String> {
    let mut client_pid = 0_u32;
    // SAFETY: public is a connected server pipe and output storage is writable.
    if unsafe { GetNamedPipeClientProcessId(public, &raw mut client_pid) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let (primary_token, mut caller_token_envelope, frontend, before) =
        super::token::authenticate_pipe_client(public, client_pid, None)?;
    if certification_mutant == Some(WindowsSealedMutant::TrustClientToken) {
        // The executable mutant replaces the authenticated envelope with the
        // certification client's untrusted claim. The launcher's independent
        // target-token readback must reject this changed trust boundary.
        caller_token_envelope.authentication_id =
            caller_token_envelope.authentication_id.wrapping_add(1);
    }
    let qualification_in_progress = super::record::qualification_in_progress();
    if !super::record::qualification_allows(&before)? {
        return Err(
            "MCSEALED-WINDOWS-QUALIFICATION-IN-PROGRESS: launch caller does not own qualification admission"
                .to_owned(),
        );
    }
    let request_bytes = serde_json::to_vec(&launch).map_err(|error| error.to_string())?;
    let request_sha256 = hex(Sha256::digest(request_bytes));
    let mut attempt_digest = Sha256::new();
    attempt_digest.update(launch.nonce.as_bytes());
    attempt_digest.update(before.process_id.to_le_bytes());
    attempt_digest.update(before.creation_time_100ns.to_le_bytes());
    attempt_digest.update(request_sha256.as_bytes());
    let attempt_id = hex(attempt_digest.finalize());
    progress.binding = Some(LaunchBinding {
        attempt_id: attempt_id.clone(),
        nonce: launch.nonce.clone(),
        request_sha256: request_sha256.clone(),
    });
    let _admission = if qualification_in_progress {
        // The authenticated qualification owner continuously retains the
        // package mutex. Its service-owned durable admission is the authority
        // for this certification launch, so no second mutex acquisition is
        // needed (or possible) here.
        if !super::record::recovery_clear()? {
            return Err(
                "MCSEALED-WINDOWS-RECOVERY-AMBIGUOUS: provider quarantine is not empty".to_owned(),
            );
        }
        super::record::reserve_admission(&attempt_id, &request_sha256)?
    } else {
        // Package mutation and launch admission share one cross-process
        // serialization point. The durable admission is established before
        // releasing it, closing the check-to-mutation race.
        let package_lease = super::package::PackageLease::acquire()?;
        if !super::record::recovery_clear()? {
            return Err(
                "MCSEALED-WINDOWS-RECOVERY-AMBIGUOUS: provider quarantine is not empty".to_owned(),
            );
        }
        let admission = super::record::reserve_admission(&attempt_id, &request_sha256)?;
        drop(package_lease);
        admission
    };
    let nonce = launch.nonce.clone();

    // SAFETY: the pseudo handle always denotes this live control process.
    let control_process = unsafe { GetCurrentProcess() };
    let control_identity = super::process::process_identity(control_process)?;
    let (launcher, launcher_process, launcher_identity) = authenticated_launcher()?;
    let control_namespace = HandleNamespace {
        process: control_process,
        identity: &control_identity,
        role: "control",
    };
    let frontend_namespace = HandleNamespace {
        process: frontend.raw(),
        identity: &before,
        role: "authenticated-frontend",
    };
    let launcher_namespace = HandleNamespace {
        process: launcher_process.raw(),
        identity: &launcher_identity,
        role: "launcher",
    };
    let remote_membership_process = duplicate_for_launcher(
        ProcessRelativeHandle {
            owner: control_namespace,
            raw: frontend.raw(),
            role: "membership-process",
            inventory_index: None,
        },
        launcher_namespace,
        None,
    )?;
    let mut membership_transfer = LauncherTransferRollback::new(launcher_namespace);
    membership_transfer.push(remote_membership_process);

    if let Err(error) = pipe::write_frame(
        launcher.raw(),
        &WindowsLauncherRequestV1::Membership {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            attempt_id: attempt_id.clone(),
            nonce: nonce.clone(),
            request_sha256: request_sha256.clone(),
            remote_process_handle: remote_membership_process,
        },
    ) {
        return Err(membership_transfer.abort(error));
    }
    membership_transfer.disarm();
    match pipe::read_frame::<WindowsLauncherResponseV1>(launcher.raw())? {
        WindowsLauncherResponseV1::Membership {
            schema_version,
            attempt_id: returned_attempt,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            inside_active_job: false,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
            && returned_attempt == attempt_id
            && returned_nonce == nonce
            && returned_digest == request_sha256 => {}
        WindowsLauncherResponseV1::Membership {
            schema_version,
            attempt_id: returned_attempt,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            inside_active_job: true,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
            && returned_attempt == attempt_id
            && returned_nonce == nonce
            && returned_digest == request_sha256
            && certification_mutant != Some(WindowsSealedMutant::AcceptRecursiveProvider) =>
        {
            let result = pipe::write_frame(
                public,
                &WindowsProviderResponseV1::Reject {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    attempt_id: attempt_id.clone(),
                    nonce: nonce.clone(),
                    request_sha256: request_sha256.clone(),
                    rejection: super::record::pretarget_rejection(
                        "MCSEALED-WINDOWS-RECURSIVE-PROVIDER",
                        "a process already inside an active MemCordon sealed Job cannot request another sealed launch".to_owned(),
                    ),
                },
            );
            if result.is_ok() {
                progress.response_state = LaunchResponseState::TerminalDelivered;
            }
            return result;
        }
        WindowsLauncherResponseV1::Membership {
            schema_version,
            attempt_id: returned_attempt,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            inside_active_job: true,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
            && returned_attempt == attempt_id
            && returned_nonce == nonce
            && returned_digest == request_sha256
            && certification_mutant == Some(WindowsSealedMutant::AcceptRecursiveProvider) => {}
        _ => return Err("launcher returned an invalid membership response".to_owned()),
    }

    let frontend_canaries =
        certification_frontend_handles(&launch, qualification_in_progress, frontend_namespace)?;
    let mut remote_transfers = LauncherTransferRollback::new(launcher_namespace);
    let mut remote_frontend_canaries = Vec::with_capacity(frontend_canaries.len());
    for handle in frontend_canaries {
        match duplicate_for_launcher(handle, launcher_namespace, None) {
            Ok(remote) => {
                remote_transfers.push(remote);
                remote_frontend_canaries.push(remote);
            }
            Err(error) => return Err(remote_transfers.abort(error)),
        }
    }
    let remote_frontend = match duplicate_for_launcher(
        ProcessRelativeHandle {
            owner: control_namespace,
            raw: frontend.raw(),
            role: "frontend-process",
            inventory_index: None,
        },
        launcher_namespace,
        None,
    ) {
        Ok(handle) => {
            remote_transfers.push(handle);
            handle
        }
        Err(error) => return Err(remote_transfers.abort(error)),
    };
    let remote_token = match duplicate_for_launcher(
        ProcessRelativeHandle {
            owner: control_namespace,
            raw: primary_token.raw(),
            role: "primary-token",
            inventory_index: None,
        },
        launcher_namespace,
        None,
    ) {
        Ok(handle) => {
            remote_transfers.push(handle);
            handle
        }
        Err(error) => return Err(remote_transfers.abort(error)),
    };

    let broker = WindowsLaunchBrokerRequestV1 {
        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        attempt_id: attempt_id.clone(),
        request_sha256: request_sha256.clone(),
        caller_process_identity: before,
        caller_token_envelope,
        remote_primary_token_handle: remote_token,
        remote_frontend_process_handle: remote_frontend,
        remote_frontend_canary_handles: remote_frontend_canaries.clone(),
        certification_fault,
        certification_mutant,
        launch,
    };
    if let Err(error) = pipe::write_frame(launcher.raw(), &WindowsLauncherRequestV1::Launch(broker))
    {
        return Err(remote_transfers.abort(error));
    }
    // A complete private frame transfers ownership of the exact launcher-local
    // inventory. Before this point, the rollback guard revokes every partial
    // duplicate on all error paths.
    remote_transfers.disarm();
    relay_protocol(
        public,
        launcher.raw(),
        frontend.raw(),
        &attempt_id,
        &nonce,
        &request_sha256,
        certification_fault,
        progress,
    )
}

struct ReplayCallerBinding {
    process_identity: WindowsProcessIdentityV1,
    token_sha256: String,
}

fn authenticate_replay_binding(
    public: HANDLE,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
) -> Result<ReplayCallerBinding, String> {
    if attempt_id.is_empty() || nonce.is_empty() || request_sha256.is_empty() {
        return Err("terminal replay binding is incomplete".to_owned());
    }
    let mut client_pid = 0_u32;
    // SAFETY: public is a connected server pipe and output storage is writable.
    if unsafe { GetNamedPipeClientProcessId(public, &raw mut client_pid) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let (_token, envelope, _frontend, identity) =
        super::token::authenticate_pipe_client(public, client_pid, None)?;
    let mut expected = Sha256::new();
    expected.update(nonce.as_bytes());
    expected.update(identity.process_id.to_le_bytes());
    expected.update(identity.creation_time_100ns.to_le_bytes());
    expected.update(request_sha256.as_bytes());
    if hex(expected.finalize()) != attempt_id {
        return Err("terminal replay caller does not own the exact attempt binding".to_owned());
    }
    let token_sha256 =
        super::record::digest(&serde_json::to_vec(&envelope).map_err(|error| error.to_string())?);
    Ok(ReplayCallerBinding {
        process_identity: identity,
        token_sha256,
    })
}

fn replay_terminal(
    public: HANDLE,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: WindowsRelayPhaseV1,
    caller: &ReplayCallerBinding,
) -> Result<ReplayTerminalProgress, String> {
    let (launcher, _process, _identity) = authenticated_launcher()?;
    pipe::write_frame(
        launcher.raw(),
        &WindowsLauncherRequestV1::ReplayTerminal {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            attempt_id: attempt_id.to_owned(),
            nonce: nonce.to_owned(),
            request_sha256: request_sha256.to_owned(),
            relay_phase,
            caller_process_identity: caller.process_identity.clone(),
            caller_token_sha256: caller.token_sha256.clone(),
        },
    )?;
    let response = pipe::read_frame::<WindowsLauncherResponseV1>(launcher.raw())?;
    let response_sha256 = super::record::digest(
        serde_json::to_string(&response)
            .map_err(|error| error.to_string())?
            .as_bytes(),
    );
    let public_response = match response {
        WindowsLauncherResponseV1::Terminal(receipt)
            if receipt.attempt_id == attempt_id
                && receipt.nonce == nonce
                && receipt.request_sha256 == request_sha256
                && receipt.process_identity_inventory_shape_is_bounded() =>
        {
            WindowsProviderResponseV1::Terminal(receipt)
        }
        WindowsLauncherResponseV1::Reject {
            schema_version,
            attempt_id: returned_attempt,
            nonce: returned_nonce,
            request_sha256: returned_request_sha256,
            rejection,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
            && returned_attempt == attempt_id
            && returned_nonce == nonce
            && returned_request_sha256 == request_sha256
            && rejection.terminal_ack_required
            && rejection.is_consistent() =>
        {
            WindowsProviderResponseV1::Reject {
                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                attempt_id: returned_attempt,
                nonce: returned_nonce,
                request_sha256: returned_request_sha256,
                rejection,
            }
        }
        WindowsLauncherResponseV1::ReplayPending(pending)
            if pending.is_consistent_for(attempt_id, nonce, request_sha256, relay_phase) =>
        {
            pipe::write_frame(public, &WindowsProviderResponseV1::ReplayPending(pending))?;
            return Ok(ReplayTerminalProgress::Pending);
        }
        WindowsLauncherResponseV1::AttemptRetained(retained)
            if retained.is_consistent_for(attempt_id, nonce, request_sha256, relay_phase) =>
        {
            pipe::write_frame(
                public,
                &WindowsProviderResponseV1::AttemptRetained(retained),
            )?;
            return Ok(ReplayTerminalProgress::Complete);
        }
        _ => return Err("launcher did not replay an exact durable terminal response".to_owned()),
    };
    pipe::write_frame(public, &public_response)?;
    match pipe::read_frame::<WindowsProviderRequestV1>(public)? {
        WindowsProviderRequestV1::TerminalAcknowledged {
            schema_version,
            attempt_id: acknowledged_attempt,
            nonce: acknowledged_nonce,
            request_sha256: acknowledged_request_sha256,
            terminal_response_sha256: acknowledged_response_sha256,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && acknowledged_attempt == attempt_id
            && acknowledged_nonce == nonce
            && acknowledged_request_sha256 == request_sha256
            && acknowledged_response_sha256 == response_sha256 => {}
        _ => return Err("frontend did not acknowledge the replayed terminal".to_owned()),
    }
    pipe::write_frame(
        launcher.raw(),
        &WindowsLauncherRequestV1::TerminalAcknowledged {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            attempt_id: attempt_id.to_owned(),
            nonce: nonce.to_owned(),
            request_sha256: request_sha256.to_owned(),
            terminal_response_sha256: response_sha256.clone(),
        },
    )?;
    let retired = match pipe::read_frame::<WindowsLauncherResponseV1>(launcher.raw())? {
        WindowsLauncherResponseV1::TerminalRetired(retired)
            if retired.is_consistent_for(attempt_id, nonce, request_sha256, &response_sha256) =>
        {
            retired
        }
        _ => return Err("launcher terminal replay retirement receipt is invalid".to_owned()),
    };
    pipe::write_frame(public, &WindowsProviderResponseV1::TerminalRetired(retired))?;
    Ok(ReplayTerminalProgress::Complete)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayTerminalProgress {
    Pending,
    Complete,
}

fn replay_terminal_session(
    public: HANDLE,
    attempt_id: String,
    nonce: String,
    request_sha256: String,
    relay_phase: WindowsRelayPhaseV1,
    mut caller: ReplayCallerBinding,
) -> Result<(), String> {
    loop {
        if replay_terminal(
            public,
            &attempt_id,
            &nonce,
            &request_sha256,
            relay_phase,
            &caller,
        )? == ReplayTerminalProgress::Complete
        {
            return Ok(());
        }
        match pipe::read_frame::<WindowsProviderRequestV1>(public)? {
            WindowsProviderRequestV1::ReplayTerminal {
                schema_version,
                attempt_id: repeated_attempt,
                nonce: repeated_nonce,
                request_sha256: repeated_digest,
                relay_phase: repeated_phase,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && repeated_attempt == attempt_id
                && repeated_nonce == nonce
                && repeated_digest == request_sha256
                && repeated_phase == relay_phase =>
            {
                caller = authenticate_replay_binding(public, &attempt_id, &nonce, &request_sha256)?;
            }
            _ => return Err("terminal replay retry changed the exact public binding".to_owned()),
        }
    }
}

pub(super) const CERTIFICATION_FRONTEND_HANDLE_ROLES: [&str;
    memcordon_core::WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT] = [
    "installed-binary-file-canary",
    "event-canary",
    "anonymous-pipe-canary",
    "frontend-process-canary",
    "section-canary",
    "registry-key-canary",
];

fn certification_frontend_handles<'a>(
    launch: &memcordon_core::WindowsLaunchRequestV1,
    qualification_in_progress: bool,
    owner: HandleNamespace<'a>,
) -> Result<Vec<ProcessRelativeHandle<'a>>, String> {
    if !qualification_in_progress {
        return Ok(Vec::new());
    }
    let Some(values) = memcordon_core::parse_windows_certification_frontend_handle_values(
        &launch.command.arguments,
    )?
    else {
        return Ok(Vec::new());
    };
    values
        .into_iter()
        .enumerate()
        .map(|(index, raw)| {
            Ok(ProcessRelativeHandle {
                owner,
                raw: raw as usize as HANDLE,
                role: CERTIFICATION_FRONTEND_HANDLE_ROLES[index],
                inventory_index: Some(index),
            })
        })
        .collect()
}

fn authenticated_launcher_detailed() -> Result<
    (
        OwnedHandle,
        OwnedHandle,
        memcordon_core::WindowsProcessIdentityV1,
    ),
    LauncherAuthenticationError,
> {
    let launcher = pipe::connect(WINDOWS_LAUNCHER_PIPE).map_err(|error| {
        LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_PIPE_CONNECT, error)
    })?;
    let pipe_policy = super::security::private_pipe_sddl().map_err(|error| {
        LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_PIPE_POLICY, error)
    })?;
    super::security::SecurityDescriptor::from_sddl(&pipe_policy)
        .map_err(|error| {
            LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_PIPE_POLICY, error)
        })?
        .verify_named_pipe(launcher.raw())
        .map_err(|error| match error {
            NamedPipeSecurityError::Readback(error) => LauncherAuthenticationError::new(
                STARTUP_LAUNCHER_AUTHENTICATION_PIPE_SECURITY_READBACK,
                error,
            ),
            NamedPipeSecurityError::Mismatch(error) => LauncherAuthenticationError::new(
                STARTUP_LAUNCHER_AUTHENTICATION_PIPE_SECURITY_MISMATCH,
                error,
            ),
        })?;
    let mut launcher_pid = 0_u32;
    // SAFETY: launcher is a connected client pipe and output storage is writable.
    if unsafe { GetNamedPipeServerProcessId(launcher.raw(), &raw mut launcher_pid) } == 0 {
        return Err(LauncherAuthenticationError::new(
            STARTUP_LAUNCHER_AUTHENTICATION_PEER_PID,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: PID is kernel-authenticated from the private pipe; rights are
    // limited to identity and handle transfer.
    let launcher_process = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE,
            0,
            launcher_pid,
        )
    })
    .map_err(|error| {
        LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_PROCESS_OPEN, error)
    })?;
    super::process::verify_image_path(launcher_process.raw(), &super::package::installed_binary())
        .map_err(|error| {
            LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_IMAGE, error)
        })?;
    let launcher_token =
        super::token::process_token_detailed(launcher_process.raw()).map_err(|error| {
            LauncherAuthenticationError::new(
                STARTUP_LAUNCHER_AUTHENTICATION_TOKEN_OPEN,
                format!("native_code={:?} {error}", error.os_code()),
            )
        })?;
    let launcher_account = super::token::token_user_sid(launcher_token.raw()).map_err(|error| {
        LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_TOKEN_USER_QUERY, error)
    })?;
    if launcher_account != "S-1-5-18" {
        return Err(LauncherAuthenticationError::new(
            STARTUP_LAUNCHER_AUTHENTICATION_ACCOUNT_MISMATCH,
            "private launcher is not running as LocalSystem",
        ));
    }
    let launcher_sid =
        super::security::service_sid(WINDOWS_LAUNCHER_SERVICE_NAME).map_err(|error| {
            LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_ORDINARY_SID, error)
        })?;
    if !super::token::token_has_enabled_group(launcher_token.raw(), &launcher_sid).map_err(
        |error| {
            LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_ORDINARY_SID, error)
        },
    )? {
        return Err(LauncherAuthenticationError::new(
            STARTUP_LAUNCHER_AUTHENTICATION_ORDINARY_SID,
            "private launcher lacks the enabled launcher-service SID",
        ));
    }
    if !super::token::token_has_restricting_sid(launcher_token.raw(), &launcher_sid).map_err(
        |error| {
            LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_RESTRICTING_SID, error)
        },
    )? {
        return Err(LauncherAuthenticationError::new(
            STARTUP_LAUNCHER_AUTHENTICATION_RESTRICTING_SID,
            "private launcher lacks the launcher-service restricting SID",
        ));
    }
    let identity = super::process::process_identity(launcher_process.raw()).map_err(|error| {
        LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_PROCESS_IDENTITY, error)
    })?;
    Ok((launcher, launcher_process, identity))
}

fn authenticated_launcher() -> Result<
    (
        OwnedHandle,
        OwnedHandle,
        memcordon_core::WindowsProcessIdentityV1,
    ),
    String,
> {
    authenticated_launcher_detailed().map_err(|error| error.to_string())
}

fn probe_authenticated_launcher_detailed() -> Result<(), LauncherAuthenticationError> {
    let challenge =
        super::token::service_attestation_challenge("control-service").map_err(|error| {
            LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_PROBE_CHALLENGE, error)
        })?;
    launcher_self_attestation_detailed(&challenge).map(|_| ())
}

fn launcher_self_attestation_detailed(
    challenge: &str,
) -> Result<WindowsServiceSelfAttestationV1, LauncherAuthenticationError> {
    let (launcher, _launcher_process, launcher_identity) = authenticated_launcher_detailed()?;
    pipe::write_frame(
        launcher.raw(),
        &WindowsLauncherRequestV1::Probe {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            challenge: challenge.to_owned(),
        },
    )
    .map_err(|error| {
        LauncherAuthenticationError::new(STARTUP_LAUNCHER_AUTHENTICATION_PROBE_WRITE, error)
    })?;
    let response = pipe::read_frame_detailed::<WindowsLauncherResponseV1>(launcher.raw()).map_err(
        |error| {
            LauncherAuthenticationError::new(
                STARTUP_LAUNCHER_AUTHENTICATION_PROBE_READ,
                format!(
                    "peer_process_id={} peer_creation_time_100ns={} {error}",
                    launcher_identity.process_id, launcher_identity.creation_time_100ns,
                ),
            )
        },
    )?;
    match response {
        WindowsLauncherResponseV1::Probe {
            schema_version,
            attestation,
        } => {
            if schema_version != WINDOWS_PRIVATE_PROTOCOL_VERSION {
                Err(LauncherAuthenticationError::new(
                    STARTUP_LAUNCHER_AUTHENTICATION_PROBE_SCHEMA,
                    "launcher probe response has the wrong schema version",
                ))
            } else {
                let launcher_sid = super::security::service_sid(WINDOWS_LAUNCHER_SERVICE_NAME)
                    .map_err(|error| {
                        LauncherAuthenticationError::new(
                            STARTUP_LAUNCHER_AUTHENTICATION_ORDINARY_SID,
                            error,
                        )
                    })?;
                attestation
                    .validate_for(
                        challenge,
                        WINDOWS_LAUNCHER_SERVICE_NAME,
                        &launcher_identity,
                        &launcher_sid,
                        super::package::LAUNCHER_PRIVILEGES,
                    )
                    .map_err(|error| {
                        LauncherAuthenticationError::new(
                            STARTUP_LAUNCHER_AUTHENTICATION_PROBE_ATTESTATION,
                            format!(
                                "stage=launcher-token-privileges api=service-self-attestation role=launcher-service detail={error}"
                            ),
                        )
                    })?;
                Ok(attestation)
            }
        }
        WindowsLauncherResponseV1::Reject { rejection, .. } => {
            let phase = control_authentication_phase_from_rejection_code(&rejection.code)
                .unwrap_or(STARTUP_LAUNCHER_AUTHENTICATION_PEER_REJECTED);
            Err(LauncherAuthenticationError::new(
                phase,
                format!(
                    "launcher rejected the control peer: code={} detail={}",
                    rejection.code, rejection.detail
                ),
            ))
        }
        _ => Err(LauncherAuthenticationError::new(
            STARTUP_LAUNCHER_AUTHENTICATION_RESPONSE_KIND,
            "launcher returned an unexpected probe response",
        )),
    }
}

fn probe_authenticated_launcher() -> Result<(), String> {
    probe_authenticated_launcher_detailed().map_err(|error| error.to_string())
}

fn control_fault(fault: WindowsSealedFault) -> bool {
    matches!(
        fault,
        WindowsSealedFault::PublicPipeCreate
            | WindowsSealedFault::CallerPidLookup
            | WindowsSealedFault::CallerTokenImpersonation
            | WindowsSealedFault::PrimaryTokenDuplicate
            | WindowsSealedFault::PrivatePipeConnect
            | WindowsSealedFault::TokenHandleDuplicate
    )
}

fn validate_certification_binding(
    launch: &memcordon_core::WindowsLaunchRequestV1,
    attempt_id: &str,
    request_sha256: &str,
    caller: &memcordon_core::WindowsProcessIdentityV1,
) -> Result<(), String> {
    let canonical_request = hex(Sha256::digest(
        serde_json::to_vec(launch).map_err(|error| error.to_string())?,
    ));
    let mut identity = Sha256::new();
    identity.update(launch.nonce.as_bytes());
    identity.update(caller.process_id.to_le_bytes());
    identity.update(caller.creation_time_100ns.to_le_bytes());
    identity.update(canonical_request.as_bytes());
    if request_sha256 == canonical_request && attempt_id == hex(identity.finalize()) {
        Ok(())
    } else {
        Err("Windows certification fault request has a noncanonical binding".to_owned())
    }
}

fn exercise_control_fault(public: HANDLE, fault: WindowsSealedFault) -> Result<(), String> {
    let result = match fault {
        WindowsSealedFault::PublicPipeCreate => {
            let listener = PipeListener::new(
                WINDOWS_CONTROL_PIPE,
                SecurityDescriptor::from_sddl(&public_pipe_sddl()?)?,
            );
            listener
                .prepare_with_fault(Some(fault))
                .map(drop)
                .map_err(|error| error.to_string())
        }
        WindowsSealedFault::CallerPidLookup => {
            Err("MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected CallerPidLookup".to_owned())
        }
        WindowsSealedFault::CallerTokenImpersonation
        | WindowsSealedFault::PrimaryTokenDuplicate => {
            let mut client_pid = 0_u32;
            // SAFETY: public is a connected server pipe and output storage is writable.
            if unsafe { GetNamedPipeClientProcessId(public, &raw mut client_pid) } == 0 {
                return Err(io::Error::last_os_error().to_string());
            }
            super::token::authenticate_pipe_client(public, client_pid, Some(fault)).map(drop)
        }
        WindowsSealedFault::PrivatePipeConnect => {
            pipe::connect_with_fault(WINDOWS_LAUNCHER_PIPE, Some(fault)).map(drop)
        }
        WindowsSealedFault::TokenHandleDuplicate => {
            let mut client_pid = 0_u32;
            // SAFETY: public is a connected server pipe and output storage is writable.
            if unsafe { GetNamedPipeClientProcessId(public, &raw mut client_pid) } == 0 {
                return Err(io::Error::last_os_error().to_string());
            }
            let (primary, _, _, _) =
                super::token::authenticate_pipe_client(public, client_pid, None)?;
            let launcher = pipe::connect(WINDOWS_LAUNCHER_PIPE)?;
            let mut launcher_pid = 0_u32;
            // SAFETY: launcher is a connected client pipe and output storage is writable.
            if unsafe { GetNamedPipeServerProcessId(launcher.raw(), &raw mut launcher_pid) } == 0 {
                return Err(io::Error::last_os_error().to_string());
            }
            let launcher_process = OwnedHandle::new(unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE,
                    0,
                    launcher_pid,
                )
            })?;
            // SAFETY: the pseudo handle always denotes this live control process.
            let control_process = unsafe { GetCurrentProcess() };
            let control_identity = super::process::process_identity(control_process)?;
            let launcher_identity = super::process::process_identity(launcher_process.raw())?;
            duplicate_for_launcher(
                ProcessRelativeHandle {
                    owner: HandleNamespace {
                        process: control_process,
                        identity: &control_identity,
                        role: "control",
                    },
                    raw: primary.raw(),
                    role: "primary-token",
                    inventory_index: None,
                },
                HandleNamespace {
                    process: launcher_process.raw(),
                    identity: &launcher_identity,
                    role: "launcher",
                },
                Some(fault),
            )
            .map(drop)
        }
        _ => return Err("requested fault is not a control-service operation".to_owned()),
    };
    match result {
        Err(error) if error.contains("MCSEALED-WINDOWS-CERTIFICATION-FAULT") => Ok(()),
        Err(error) => Err(error),
        Ok(()) => Err(format!(
            "fault {fault:?} did not fail at its named operation"
        )),
    }
}

fn relay_protocol(
    public: HANDLE,
    launcher: HANDLE,
    frontend_process: HANDLE,
    expected_attempt_id: &str,
    expected_nonce: &str,
    expected_request_sha256: &str,
    certification_fault: Option<WindowsSealedFault>,
    progress: &mut LaunchProgress,
) -> Result<(), String> {
    loop {
        if pipe::frame_available(launcher)? {
            let response: WindowsLauncherResponseV1 = pipe::read_frame(launcher)?;
            let response_sha256 = super::record::digest(
                serde_json::to_string(&response)
                    .map_err(|error| error.to_string())?
                    .as_bytes(),
            );
            let terminal_ack_required = match &response {
                WindowsLauncherResponseV1::Terminal(_) => true,
                WindowsLauncherResponseV1::Reject { rejection, .. } => {
                    rejection.terminal_ack_required
                }
                _ => false,
            };
            let terminal = matches!(
                response,
                WindowsLauncherResponseV1::Terminal(_)
                    | WindowsLauncherResponseV1::CertificationMutantObserved(_)
                    | WindowsLauncherResponseV1::Reject { .. }
            );
            let prepared_handles = match &response {
                WindowsLauncherResponseV1::StreamsPrepared {
                    streams,
                    relay_retired_event_handle,
                    ..
                } => streams
                    .iter()
                    .map(|stream| stream.remote_handle)
                    .chain(std::iter::once(*relay_retired_event_handle))
                    .collect::<Vec<_>>(),
                WindowsLauncherResponseV1::CertificationMutantHookObserved(receipt) => receipt
                    .remote_observation_handle
                    .into_iter()
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            };
            macro_rules! advance_relay {
                ($event:expr) => {
                    if let Err(detail) = advance_relay_phase(&mut progress.relay_phase, $event) {
                        revoke_frontend_streams(frontend_process, &prepared_handles);
                        cancel_launcher_attempt(
                            launcher,
                            expected_attempt_id,
                            expected_nonce,
                            expected_request_sha256,
                        );
                        return Err(detail);
                    }
                };
            }
            let public_response = match response {
                WindowsLauncherResponseV1::StreamsPrepared {
                    schema_version,
                    attempt_id,
                    nonce,
                    request_sha256,
                    streams,
                    relay_retired_event_handle,
                } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
                    && attempt_id == expected_attempt_id
                    && nonce == expected_nonce
                    && request_sha256 == expected_request_sha256 =>
                {
                    advance_relay!(WindowsRelayEventV1::StreamsPrepared);
                    WindowsProviderResponseV1::StreamsPrepared {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id,
                        nonce,
                        request_sha256,
                        streams,
                        relay_retired_event_handle,
                    }
                }
                WindowsLauncherResponseV1::TargetAuthorized {
                    schema_version,
                    attempt_id,
                    nonce,
                    request_sha256,
                    child_pid,
                } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
                    && attempt_id == expected_attempt_id
                    && nonce == expected_nonce
                    && request_sha256 == expected_request_sha256 =>
                {
                    advance_relay!(WindowsRelayEventV1::TargetAuthorized);
                    WindowsProviderResponseV1::TargetAuthorized {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id,
                        nonce,
                        request_sha256,
                        child_pid,
                    }
                }
                WindowsLauncherResponseV1::TargetRetired {
                    schema_version,
                    attempt_id,
                    nonce,
                    request_sha256,
                } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
                    && attempt_id == expected_attempt_id
                    && nonce == expected_nonce
                    && request_sha256 == expected_request_sha256 =>
                {
                    advance_relay!(WindowsRelayEventV1::TargetRetired);
                    WindowsProviderResponseV1::TargetRetired {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id,
                        nonce,
                        request_sha256,
                    }
                }
                WindowsLauncherResponseV1::RelaysAbort {
                    schema_version,
                    attempt_id,
                    nonce,
                    request_sha256,
                } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
                    && attempt_id == expected_attempt_id
                    && nonce == expected_nonce
                    && request_sha256 == expected_request_sha256 =>
                {
                    advance_relay!(WindowsRelayEventV1::RelaysAbort);
                    WindowsProviderResponseV1::RelaysAbort {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id,
                        nonce,
                        request_sha256,
                    }
                }
                WindowsLauncherResponseV1::Terminal(receipt)
                    if receipt.attempt_id == expected_attempt_id
                        && receipt.nonce == expected_nonce
                        && receipt.request_sha256 == expected_request_sha256
                        && receipt.process_identity_inventory_shape_is_bounded() =>
                {
                    advance_relay!(WindowsRelayEventV1::Terminal);
                    WindowsProviderResponseV1::Terminal(receipt)
                }
                WindowsLauncherResponseV1::CertificationMutantObserved(receipt)
                    if receipt.binding_matches(
                        expected_attempt_id,
                        expected_nonce,
                        expected_request_sha256,
                    ) =>
                {
                    advance_relay!(WindowsRelayEventV1::MutantTerminal);
                    WindowsProviderResponseV1::CertificationMutantObserved(receipt)
                }
                WindowsLauncherResponseV1::CertificationMutantHookObserved(receipt)
                    if receipt.binding_matches(
                        expected_attempt_id,
                        expected_nonce,
                        expected_request_sha256,
                    ) =>
                {
                    advance_relay!(WindowsRelayEventV1::MutantHook);
                    WindowsProviderResponseV1::CertificationMutantHookObserved(receipt)
                }
                WindowsLauncherResponseV1::Reject {
                    schema_version,
                    attempt_id,
                    nonce,
                    request_sha256,
                    rejection,
                } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
                    && attempt_id == expected_attempt_id
                    && nonce == expected_nonce
                    && request_sha256 == expected_request_sha256
                    && rejection.is_consistent()
                    && rejection.terminal_receipt.as_ref().is_none_or(|terminal| {
                        terminal.attempt_id == expected_attempt_id
                            && terminal.nonce == expected_nonce
                            && terminal.request_sha256 == expected_request_sha256
                    }) =>
                {
                    advance_relay!(WindowsRelayEventV1::Reject);
                    WindowsProviderResponseV1::Reject {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id,
                        nonce,
                        request_sha256,
                        rejection,
                    }
                }
                _ => {
                    revoke_frontend_streams(frontend_process, &prepared_handles);
                    cancel_launcher_attempt(
                        launcher,
                        expected_attempt_id,
                        expected_nonce,
                        expected_request_sha256,
                    );
                    return Err("launcher emitted an invalid launch response".to_owned());
                }
            };
            if let Err(error) = pipe::write_frame(public, &public_response) {
                revoke_frontend_streams(frontend_process, &prepared_handles);
                cancel_launcher_attempt(
                    launcher,
                    expected_attempt_id,
                    expected_nonce,
                    expected_request_sha256,
                );
                return Err(error);
            }
            progress.response_state = if terminal {
                LaunchResponseState::TerminalDelivered
            } else {
                LaunchResponseState::BoundAttemptActive
            };
            if certification_fault
                == Some(WindowsSealedFault::ControlServiceKilledAfterAuthorization)
                && matches!(
                    public_response,
                    WindowsProviderResponseV1::TargetAuthorized { .. }
                )
            {
                // SAFETY: this gated native scenario deliberately removes the
                // complete control-service process after authorization.
                unsafe {
                    windows_sys::Win32::System::Threading::TerminateProcess(
                        windows_sys::Win32::System::Threading::GetCurrentProcess(),
                        0xC000_013A,
                    )
                };
                return Err("control service termination unexpectedly returned".to_owned());
            }
            if certification_fault
                == Some(WindowsSealedFault::ControlWorkerKilledAfterAuthorization)
                && matches!(
                    public_response,
                    WindowsProviderResponseV1::TargetAuthorized { .. }
                )
            {
                // End only this authenticated relay worker. The frontend
                // process and its adopted stream handles remain live until
                // the external certification authority releases them.
                pipe::disconnect(launcher);
                pipe::disconnect(public);
                return Err("certification retired the control worker".to_owned());
            }
            if terminal {
                if terminal_ack_required {
                    match pipe::read_frame::<WindowsProviderRequestV1>(public)? {
                        WindowsProviderRequestV1::TerminalAcknowledged {
                            schema_version,
                            attempt_id,
                            nonce,
                            request_sha256,
                            terminal_response_sha256,
                        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                            && attempt_id == expected_attempt_id
                            && nonce == expected_nonce
                            && request_sha256 == expected_request_sha256
                            && terminal_response_sha256 == response_sha256 => {}
                        _ => {
                            return Err("frontend did not acknowledge the bound terminal response"
                                .to_owned());
                        }
                    }
                    pipe::write_frame(
                        launcher,
                        &WindowsLauncherRequestV1::TerminalAcknowledged {
                            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                            attempt_id: expected_attempt_id.to_owned(),
                            nonce: expected_nonce.to_owned(),
                            request_sha256: expected_request_sha256.to_owned(),
                            terminal_response_sha256: response_sha256.clone(),
                        },
                    )?;
                    let retired = match pipe::read_frame::<WindowsLauncherResponseV1>(launcher)? {
                        WindowsLauncherResponseV1::TerminalRetired(retired)
                            if retired.is_consistent_for(
                                expected_attempt_id,
                                expected_nonce,
                                expected_request_sha256,
                                &response_sha256,
                            ) =>
                        {
                            retired
                        }
                        _ => {
                            return Err(
                                "launcher did not confirm exact terminal retirement".to_owned()
                            );
                        }
                    };
                    pipe::write_frame(
                        public,
                        &WindowsProviderResponseV1::TerminalRetired(retired),
                    )?;
                }
                return Ok(());
            }
        }
        let public_available = match pipe::frame_available(public) {
            Ok(available) => available,
            Err(error) => {
                let _ = pipe::write_frame(
                    launcher,
                    &WindowsLauncherRequestV1::Cancel {
                        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                        attempt_id: expected_attempt_id.to_owned(),
                        nonce: expected_nonce.to_owned(),
                        request_sha256: expected_request_sha256.to_owned(),
                        signal: 15,
                    },
                );
                return Err(format!("frontend connection was lost: {error}"));
            }
        };
        if public_available {
            let request: WindowsProviderRequestV1 = match pipe::read_frame(public) {
                Ok(request) => request,
                Err(error) => {
                    let _ = pipe::write_frame(
                        launcher,
                        &WindowsLauncherRequestV1::Cancel {
                            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                            attempt_id: expected_attempt_id.to_owned(),
                            nonce: expected_nonce.to_owned(),
                            request_sha256: expected_request_sha256.to_owned(),
                            signal: 15,
                        },
                    );
                    return Err(format!("frontend request stream was lost: {error}"));
                }
            };
            let launcher_request = match request {
                WindowsProviderRequestV1::RelaysReady {
                    schema_version,
                    attempt_id,
                    nonce,
                    request_sha256,
                } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                    && attempt_id == expected_attempt_id
                    && nonce == expected_nonce
                    && request_sha256 == expected_request_sha256 =>
                {
                    if let Err(detail) = advance_relay_phase(
                        &mut progress.relay_phase,
                        WindowsRelayEventV1::RelaysReady,
                    ) {
                        cancel_launcher_attempt(
                            launcher,
                            expected_attempt_id,
                            expected_nonce,
                            expected_request_sha256,
                        );
                        return Err(detail);
                    }
                    WindowsLauncherRequestV1::RelaysReady {
                        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                        attempt_id,
                        nonce,
                        request_sha256,
                    }
                }
                WindowsProviderRequestV1::Cancel {
                    schema_version,
                    attempt_id,
                    nonce,
                    request_sha256,
                    signal,
                } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                    && attempt_id == expected_attempt_id
                    && nonce == expected_nonce
                    && request_sha256 == expected_request_sha256 =>
                {
                    WindowsLauncherRequestV1::Cancel {
                        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                        attempt_id,
                        nonce,
                        request_sha256,
                        signal,
                    }
                }
                WindowsProviderRequestV1::RelaysRetired {
                    schema_version,
                    attempt_id,
                    nonce,
                    request_sha256,
                } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                    && attempt_id == expected_attempt_id
                    && nonce == expected_nonce
                    && request_sha256 == expected_request_sha256 =>
                {
                    if let Err(detail) = advance_relay_phase(
                        &mut progress.relay_phase,
                        WindowsRelayEventV1::RelaysRetired,
                    ) {
                        cancel_launcher_attempt(
                            launcher,
                            expected_attempt_id,
                            expected_nonce,
                            expected_request_sha256,
                        );
                        return Err(detail);
                    }
                    WindowsLauncherRequestV1::RelaysRetired {
                        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
                        attempt_id,
                        nonce,
                        request_sha256,
                    }
                }
                _ => return Err("invalid request during a Windows sealed attempt".to_owned()),
            };
            pipe::write_frame(launcher, &launcher_request)?;
        }
        pipe::wait_poll_interval();
    }
}

fn advance_relay_phase(
    phase: &mut WindowsRelayPhaseV1,
    event: WindowsRelayEventV1,
) -> Result<(), String> {
    let before = *phase;
    phase
        .advance(event)
        .map_err(|detail| format!("{detail}: phase={before:?} event={event:?}"))
}

fn cancel_launcher_attempt(launcher: HANDLE, attempt_id: &str, nonce: &str, request_sha256: &str) {
    let _ = pipe::write_frame(
        launcher,
        &WindowsLauncherRequestV1::Cancel {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            attempt_id: attempt_id.to_owned(),
            nonce: nonce.to_owned(),
            request_sha256: request_sha256.to_owned(),
            signal: 15,
        },
    );
}

fn revoke_frontend_streams(frontend_process: HANDLE, handles: &[u64]) {
    let mut unique = std::collections::BTreeSet::new();
    for handle in handles
        .iter()
        .copied()
        .filter(|handle| unique.insert(*handle))
    {
        let _ = close_remote_handle(handle, frontend_process);
    }
}

#[derive(Debug)]
pub(crate) struct HandleDuplicationError {
    native_code: Option<u32>,
    detail: io::Error,
}

impl std::fmt::Display for HandleDuplicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.native_code {
            Some(native_code) => write!(
                formatter,
                "native_code={native_code} detail={}",
                self.detail
            ),
            None => write!(formatter, "native_code=none detail={}", self.detail),
        }
    }
}

pub(crate) fn duplicate_between(
    source_process: HANDLE,
    source_handle: HANDLE,
    target_process: HANDLE,
) -> Result<u64, HandleDuplicationError> {
    let mut remote = ptr::null_mut();
    // SAFETY: the caller names the process whose handle table contains
    // source_handle and a live target process. The output receives a
    // non-inheritable same-access duplicate in the target process.
    if unsafe {
        DuplicateHandle(
            source_process,
            source_handle,
            target_process,
            &raw mut remote,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        let detail = io::Error::last_os_error();
        Err(HandleDuplicationError {
            native_code: detail.raw_os_error().map(|code| code as u32),
            detail,
        })
    } else {
        Ok(remote as usize as u64)
    }
}

#[derive(Clone, Copy)]
struct HandleNamespace<'a> {
    process: HANDLE,
    identity: &'a WindowsProcessIdentityV1,
    role: &'static str,
}

#[derive(Clone, Copy)]
struct ProcessRelativeHandle<'a> {
    owner: HandleNamespace<'a>,
    raw: HANDLE,
    role: &'static str,
    inventory_index: Option<usize>,
}

fn duplicate_for_launcher(
    source: ProcessRelativeHandle<'_>,
    target: HandleNamespace<'_>,
    certification_fault: Option<WindowsSealedFault>,
) -> Result<u64, String> {
    if certification_fault == Some(WindowsSealedFault::TokenHandleDuplicate) {
        return Err(
            "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected TokenHandleDuplicate".to_owned(),
        );
    }
    duplicate_between(source.owner.process, source.raw, target.process).map_err(|error| {
        let inventory_index = source
            .inventory_index
            .map_or_else(|| "none".to_owned(), |index| index.to_string());
        format!(
            "MCSEALED-WINDOWS-HANDLE-DUPLICATE: phase={}-to-{} source_role={} source_pid={} source_creation_time_100ns={} destination_role={} destination_pid={} destination_creation_time_100ns={} handle_role={} inventory_index={} {error}",
            source.role,
            target.role,
            source.owner.role,
            source.owner.identity.process_id,
            source.owner.identity.creation_time_100ns,
            target.role,
            target.identity.process_id,
            target.identity.creation_time_100ns,
            source.role,
            inventory_index,
        )
    })
}

#[cfg(test)]
pub(crate) fn duplicate_authenticated_frontend_canary_for_test(
    frontend_process: HANDLE,
    frontend_identity: &WindowsProcessIdentityV1,
    source_handle: HANDLE,
    target_process: HANDLE,
    target_identity: &WindowsProcessIdentityV1,
    inventory_index: usize,
) -> Result<u64, String> {
    duplicate_for_launcher(
        ProcessRelativeHandle {
            owner: HandleNamespace {
                process: frontend_process,
                identity: frontend_identity,
                role: "authenticated-frontend",
            },
            raw: source_handle,
            role: "qualification-canary",
            inventory_index: Some(inventory_index),
        },
        HandleNamespace {
            process: target_process,
            identity: target_identity,
            role: "launcher",
        },
        None,
    )
}

struct LauncherTransferRollback<'a> {
    target: HandleNamespace<'a>,
    handles: Vec<u64>,
    armed: bool,
}

impl<'a> LauncherTransferRollback<'a> {
    fn new(target: HandleNamespace<'a>) -> Self {
        Self {
            target,
            handles: Vec::new(),
            armed: true,
        }
    }

    fn push(&mut self, handle: u64) {
        self.handles.push(handle);
    }

    fn abort(mut self, error: String) -> String {
        let created = self.handles.len();
        let failures = self.revoke_all();
        self.armed = false;
        if failures.is_empty() {
            format!("{error} target_duplicates_created={created} target_duplicates_revoked=true")
        } else {
            format!(
                "{error} target_duplicates_created={created} target_duplicates_revoked=false revoke_errors={}",
                failures.join(" | ")
            )
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }

    fn revoke_all(&mut self) -> Vec<String> {
        self.handles
            .drain(..)
            .rev()
            .filter_map(|handle| close_remote_handle(handle, self.target.process).err())
            .collect()
    }
}

impl Drop for LauncherTransferRollback<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.revoke_all();
        }
    }
}

fn close_remote_handle(remote: u64, source_process: HANDLE) -> Result<(), String> {
    let mut local = ptr::null_mut();
    // SAFETY: source_process is the authenticated launcher and remote denotes
    // a handle created there by duplicate_between. DUPLICATE_CLOSE_SOURCE revokes
    // it even when the local duplicate is not otherwise needed.
    if unsafe {
        DuplicateHandle(
            source_process,
            remote as usize as HANDLE,
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            &raw mut local,
            0,
            0,
            windows_sys::Win32::Foundation::DUPLICATE_CLOSE_SOURCE
                | windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        drop(OwnedHandle::new(local)?);
        Ok(())
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
