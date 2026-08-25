use std::io;
use std::ptr;

use memcordon_core::{
    WINDOWS_CONTROL_PIPE, WINDOWS_CONTROL_SERVICE_NAME, WINDOWS_LAUNCHER_PIPE,
    WINDOWS_LAUNCHER_SERVICE_NAME, WINDOWS_PRIVATE_PROTOCOL_VERSION,
    WINDOWS_PUBLIC_PROTOCOL_VERSION, WindowsLaunchBrokerRequestV1, WindowsLauncherRequestV1,
    WindowsLauncherResponseV1, WindowsProviderRequestV1, WindowsProviderResponseV1,
    WindowsSealedFault, WindowsSealedMutant,
};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::pipe::{self, OwnedHandle, PipeListener};
use super::security::{SecurityDescriptor, public_pipe_sddl};

pub fn run() -> Result<(), String> {
    super::service::dispatch(WINDOWS_CONTROL_SERVICE_NAME, 1, service_main)
}

unsafe extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
    if let Err(error) = unsafe { super::service::announce_starting(WINDOWS_CONTROL_SERVICE_NAME) } {
        eprintln!("{error}");
        return;
    }
    let result = (|| {
        super::security::protect_current_service_process(WINDOWS_CONTROL_SERVICE_NAME)?;
        super::record::reharden_attempt_state()?;
        let listener = PipeListener::new(
            WINDOWS_CONTROL_PIPE,
            SecurityDescriptor::from_sddl(&public_pipe_sddl()?)?,
        );
        let first = listener.prepare()?;
        probe_authenticated_launcher()?;
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
            if let Err(error) = handle_client(connection.raw()) {
                let code = stable_error_code(&error).to_owned();
                let _ = pipe::write_frame(
                    connection.raw(),
                    &WindowsProviderResponseV1::Reject {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: String::new(),
                        nonce: String::new(),
                        request_sha256: String::new(),
                        rejection: super::record::pretarget_rejection(&code, error),
                    },
                );
            }
            pipe::disconnect(connection.raw());
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
        WindowsProviderRequestV1::RecoveryStatus { schema_version }
            if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
        {
            pipe::write_frame(
                public,
                &WindowsProviderResponseV1::RecoveryStatus {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    attempts_empty: super::record::attempts_empty()?,
                },
            )
        }
        WindowsProviderRequestV1::PackageCleanup { schema_version }
            if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
        {
            if !super::token::pipe_client_is_elevated(public)? {
                return Err(
                    "MCSEALED-WINDOWS-ELEVATION: package cleanup requires an elevated caller"
                        .to_owned(),
                );
            }
            super::record::remove_empty_attempt_state()?;
            pipe::write_frame(
                public,
                &WindowsProviderResponseV1::PackageCleanupReady {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                },
            )
        }
        WindowsProviderRequestV1::QualificationBegin {
            schema_version,
            scope,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION => {
            qualification_session(public, &scope)
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
                Err(error) => {
                    let code = stable_error_code(&error).to_owned();
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
                                error,
                            ),
                        },
                    )
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

fn qualification_session(public: HANDLE, scope: &str) -> Result<(), String> {
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

    let (launcher, launcher_process, _launcher_identity) = authenticated_launcher()?;
    let remote_membership_process = duplicate_into(frontend.raw(), launcher_process.raw())?;

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
        let _ = close_remote_handle(remote_membership_process, launcher_process.raw());
        return Err(error);
    }
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
            return pipe::write_frame(
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

    let frontend_canaries = certification_frontend_handles(&launch, qualification_in_progress)?;
    let mut remote_frontend_canaries = Vec::with_capacity(frontend_canaries.len());
    for handle in frontend_canaries {
        match duplicate_into(handle, launcher_process.raw()) {
            Ok(remote) => remote_frontend_canaries.push(remote),
            Err(error) => {
                for remote in remote_frontend_canaries {
                    let _ = close_remote_handle(remote, launcher_process.raw());
                }
                return Err(error);
            }
        }
    }
    let remote_frontend = match duplicate_into(frontend.raw(), launcher_process.raw()) {
        Ok(handle) => handle,
        Err(error) => {
            for remote in remote_frontend_canaries {
                let _ = close_remote_handle(remote, launcher_process.raw());
            }
            return Err(error);
        }
    };
    let remote_token = match duplicate_into(primary_token.raw(), launcher_process.raw()) {
        Ok(handle) => handle,
        Err(error) => {
            for remote in remote_frontend_canaries {
                let _ = close_remote_handle(remote, launcher_process.raw());
            }
            let _ = close_remote_handle(remote_frontend, launcher_process.raw());
            return Err(error);
        }
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
        for remote in remote_frontend_canaries {
            let _ = close_remote_handle(remote, launcher_process.raw());
        }
        let _ = close_remote_handle(remote_token, launcher_process.raw());
        let _ = close_remote_handle(remote_frontend, launcher_process.raw());
        return Err(error);
    }
    relay_protocol(
        public,
        launcher.raw(),
        frontend.raw(),
        &attempt_id,
        &nonce,
        &request_sha256,
        certification_fault,
    )
}

fn certification_frontend_handles(
    launch: &memcordon_core::WindowsLaunchRequestV1,
    qualification_in_progress: bool,
) -> Result<Vec<HANDLE>, String> {
    if !qualification_in_progress {
        return Ok(Vec::new());
    }
    let Some(mode) = launch.command.arguments.first() else {
        return Ok(Vec::new());
    };
    let mode = String::from_utf16(mode).map_err(|error| error.to_string())?;
    let prefix = if mode == "windows-certification-target" {
        2
    } else if mode == "windows-certification-nested-target" {
        3
    } else {
        return Ok(Vec::new());
    };
    let expected_count = 6;
    let values = launch
        .command
        .arguments
        .get(prefix..)
        .ok_or_else(|| "frontend handle-canary arguments are absent".to_owned())?;
    if values.len() != expected_count {
        return Err("frontend handle-canary inventory is not exact".to_owned());
    }
    values
        .iter()
        .map(|value| {
            String::from_utf16(value)
                .map_err(|error| error.to_string())?
                .parse::<u64>()
                .map(|raw| raw as usize as HANDLE)
                .map_err(|error| format!("frontend handle-canary value is invalid: {error}"))
        })
        .collect()
}

fn authenticated_launcher() -> Result<
    (
        OwnedHandle,
        OwnedHandle,
        memcordon_core::WindowsProcessIdentityV1,
    ),
    String,
> {
    let launcher = pipe::connect(WINDOWS_LAUNCHER_PIPE)?;
    super::security::SecurityDescriptor::from_sddl(&super::security::private_pipe_sddl()?)?
        .verify_kernel_object(launcher.raw())?;
    let mut launcher_pid = 0_u32;
    // SAFETY: launcher is a connected client pipe and output storage is writable.
    if unsafe { GetNamedPipeServerProcessId(launcher.raw(), &raw mut launcher_pid) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    // SAFETY: PID is kernel-authenticated from the private pipe; rights are
    // limited to identity and handle transfer.
    let launcher_process = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE,
            0,
            launcher_pid,
        )
    })?;
    super::process::verify_image_path(launcher_process.raw(), &super::package::installed_binary())?;
    if super::token::process_user_sid(launcher_process.raw())? != "S-1-5-18" {
        return Err("private launcher is not running as LocalSystem".to_owned());
    }
    let launcher_sid = super::security::service_sid(WINDOWS_LAUNCHER_SERVICE_NAME)?;
    if !super::token::process_has_enabled_group(launcher_process.raw(), &launcher_sid, false)?
        || !super::token::process_has_enabled_group(launcher_process.raw(), &launcher_sid, true)?
    {
        return Err(
            "private launcher lacks the enabled restricted launcher-service SID".to_owned(),
        );
    }
    let identity = super::process::process_identity(launcher_process.raw())?;
    Ok((launcher, launcher_process, identity))
}

fn probe_authenticated_launcher() -> Result<(), String> {
    let (launcher, _launcher_process, launcher_identity) = authenticated_launcher()?;
    pipe::write_frame(
        launcher.raw(),
        &WindowsLauncherRequestV1::Probe {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        },
    )?;
    match pipe::read_frame::<WindowsLauncherResponseV1>(launcher.raw())? {
        WindowsLauncherResponseV1::Probe {
            schema_version,
            process_identity,
        } if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION
            && process_identity == launcher_identity =>
        {
            Ok(())
        }
        _ => Err("launcher returned an unauthenticated probe response".to_owned()),
    }
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
            listener.prepare_with_fault(Some(fault)).map(drop)
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
            duplicate_into_with_fault(primary.raw(), launcher_process.raw(), Some(fault)).map(drop)
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
) -> Result<(), String> {
    loop {
        if pipe::frame_available(launcher)? {
            let response: WindowsLauncherResponseV1 = pipe::read_frame(launcher)?;
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
                        && receipt.process_identity_inventory_is_bounded() =>
                {
                    WindowsProviderResponseV1::Terminal(receipt)
                }
                WindowsLauncherResponseV1::CertificationMutantObserved(receipt)
                    if receipt.binding_matches(
                        expected_attempt_id,
                        expected_nonce,
                        expected_request_sha256,
                    ) =>
                {
                    WindowsProviderResponseV1::CertificationMutantObserved(receipt)
                }
                WindowsLauncherResponseV1::CertificationMutantHookObserved(receipt)
                    if receipt.binding_matches(
                        expected_attempt_id,
                        expected_nonce,
                        expected_request_sha256,
                    ) =>
                {
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
                    && request_sha256 == expected_request_sha256 =>
                {
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

fn duplicate_into(handle: HANDLE, target_process: HANDLE) -> Result<u64, String> {
    duplicate_into_with_fault(handle, target_process, None)
}

fn duplicate_into_with_fault(
    handle: HANDLE,
    target_process: HANDLE,
    certification_fault: Option<WindowsSealedFault>,
) -> Result<u64, String> {
    if certification_fault == Some(WindowsSealedFault::TokenHandleDuplicate) {
        return Err(
            "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected TokenHandleDuplicate".to_owned(),
        );
    }
    let mut remote = ptr::null_mut();
    // SAFETY: current process owns source; target is the kernel-authenticated
    // launcher; remote receives a non-inheritable same-access duplicate.
    if unsafe {
        DuplicateHandle(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            handle,
            target_process,
            &raw mut remote,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(remote as usize as u64)
    }
}

fn close_remote_handle(remote: u64, source_process: HANDLE) -> Result<(), String> {
    let mut local = ptr::null_mut();
    // SAFETY: source_process is the authenticated launcher and remote denotes
    // a handle created there by duplicate_into. DUPLICATE_CLOSE_SOURCE revokes
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
