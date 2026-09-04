#[cfg(windows)]
use crate::{artifact, scenario::LoaderLabScenarioV1};
use std::path::Path;

pub fn lab_service_name(run_id: &str, scenario_id: &str) -> String {
    format!("MemCordonLoaderLab-{run_id}-{scenario_id}")
}

#[cfg(windows)]
pub fn run(scenario_path: &Path, result_path: &Path) -> Result<(), String> {
    let scenario: LoaderLabScenarioV1 = artifact::read_json(scenario_path)?;
    scenario.validate(&scenario.production_plan_sha256)?;
    let result = windows::run_scenario(&scenario)?;
    result.validate_against(&scenario)?;
    artifact::write_json(result_path, &result)?;
    Ok(())
}

#[cfg(not(windows))]
pub fn run(scenario_path: &Path, result_path: &Path) -> Result<(), String> {
    let _ = (scenario_path, result_path);
    Err(String::from(
        "the loader laboratory spawner is Windows-only",
    ))
}

pub fn run_as_service(
    service_name: &str,
    scenario_path: &Path,
    result_path: &Path,
    source_process_id: u32,
    source_creation_time: u64,
    source_token: u64,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::run_as_service(
            service_name,
            scenario_path,
            result_path,
            source_process_id,
            source_creation_time,
            source_token,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (
            service_name,
            scenario_path,
            result_path,
            source_process_id,
            source_creation_time,
            source_token,
        );
        Err(String::from(
            "the loader laboratory service spawner is Windows-only",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use crate::observer::ObserverLease;
    use crate::{
        artifact,
        scenario::{
            DiagnosticDesktopVariantV1, DiagnosticEnvironmentVariantV1,
            DiagnosticSecurityDescriptorVariantV1, DiagnosticTokenVariantV1,
            LoaderLabScenarioResultV1, LoaderLabScenarioV1, LoaderReadyTokenSnapshotEvidenceV1,
            LoaderReadyTokenSnapshotV1, ObserverEvidenceV1, PreparedInputEvidenceV1,
            SuspendedProcessEvidenceV1,
        },
    };
    use memcordon_windows_launch_core::{
        CleanupOutcomeV1, DesktopBindingV1, ExactHandleListV1, HandshakeOutcomeV1,
        LoaderReadyEndpointV1, NativeCallOutcomeV1, NativeSecurityDescriptorV1, NativeStatusV1,
        PreparedCurrentDirectoryV1, PreparedLoaderCommandV1, PreparedLoaderEnvironmentV1,
        ProductionJobV1, ProductionLoaderPlanInputV1, ProductionLoaderPlanV1,
        ProductionNativeCreateRequestV1, TargetTokenIdentityV1, WindowsLoaderQualificationStageV2,
        create_suspended_in_job,
    };
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::OsStr,
        os::windows::ffi::OsStrExt,
        path::{Path, PathBuf},
        ptr,
        sync::OnceLock,
        time::Duration,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_DATA,
            ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, FILETIME, HANDLE, HLOCAL,
            INVALID_HANDLE_VALUE, LocalFree,
        },
        Security::{
            Authorization::ConvertStringSidToSidW,
            CreateRestrictedToken,
            Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
            DISABLE_MAX_PRIVILEGE, GetUserObjectSecurity, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
            TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
            WRITE_RESTRICTED,
        },
        Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile,
            WriteFile,
        },
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_NOWAIT,
                PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            },
            Services::{
                RegisterServiceCtrlHandlerW, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STOPPED,
                SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
                StartServiceCtrlDispatcherW,
            },
            StationsAndDesktops::{
                CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
                DESKTOP_CREATEMENU, DESKTOP_CREATEWINDOW, DESKTOP_ENUMERATE, DESKTOP_HOOKCONTROL,
                DESKTOP_JOURNALPLAYBACK, DESKTOP_JOURNALRECORD, DESKTOP_READOBJECTS,
                DESKTOP_SWITCHDESKTOP, DESKTOP_WRITEOBJECTS, GetProcessWindowStation,
                GetThreadDesktop, GetUserObjectInformationW, SetProcessWindowStation, UOI_NAME,
            },
            Threading::{
                ExitProcess, GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess,
                OpenProcessToken, PROCESS_CREATE_PROCESS, PROCESS_DUP_HANDLE,
                PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, WaitForSingleObject,
            },
            WindowsProgramming::GetUserNameW,
        },
        UI::{
            Shell::{LoadUserProfileW, PROFILEINFOW, UnloadUserProfile},
            WindowsAndMessaging::WINSTA_ALL_ACCESS,
        },
    };

    const FRAME_LIMIT_BYTES: usize = 1024 * 1024;
    const BOOTSTRAP_SCHEMA_VERSION: u32 =
        memcordon_windows_launch_core::PRODUCTION_LOADER_READY_SCHEMA_VERSION;
    static SERVICE_ARGUMENTS: OnceLock<ServiceArguments> = OnceLock::new();

    struct ServiceArguments {
        name: Vec<u16>,
        scenario: PathBuf,
        result: PathBuf,
        source_token: usize,
    }

    pub fn run_as_service(
        service_name: &str,
        scenario: &Path,
        result: &Path,
        source_process_id: u32,
        source_creation_time: u64,
        source_token: u64,
    ) -> Result<(), String> {
        let mut name = service_name.encode_utf16().collect::<Vec<_>>();
        name.push(0);
        let source_token =
            duplicate_remote_token(source_process_id, source_creation_time, source_token)?;
        SERVICE_ARGUMENTS
            .set(ServiceArguments {
                name,
                scenario: scenario.to_path_buf(),
                result: result.to_path_buf(),
                source_token: source_token as usize,
            })
            .map_err(|_| String::from("loader lab service arguments were already installed"))?;
        let arguments = SERVICE_ARGUMENTS
            .get()
            .ok_or_else(|| String::from("loader lab service arguments are absent"))?;
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: arguments.name.as_ptr().cast_mut(),
                lpServiceProc: Some(loader_lab_service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            return Err(format!(
                "dispatch loader lab service: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    unsafe extern "system" fn loader_lab_service_main(_count: u32, _arguments: *mut *mut u16) {
        let Some(arguments) = SERVICE_ARGUMENTS.get() else {
            return;
        };
        let status_handle = unsafe {
            RegisterServiceCtrlHandlerW(arguments.name.as_ptr(), Some(ignore_service_control))
        };
        if status_handle.is_null() {
            return;
        }
        let running = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_RUNNING,
            ..SERVICE_STATUS::default()
        };
        if unsafe { SetServiceStatus(status_handle, &raw const running) } == 0 {
            return;
        }
        let exit_code = match super::run(&arguments.scenario, &arguments.result) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("memcordon-windows-loader-lab service spawner: {error}");
                1
            }
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_STOPPED,
            dwWin32ExitCode: exit_code,
            ..SERVICE_STATUS::default()
        };
        unsafe { SetServiceStatus(status_handle, &raw const status) };
    }

    unsafe extern "system" fn ignore_service_control(control: u32) {
        if control == windows_sys::Win32::System::Services::SERVICE_CONTROL_STOP {
            unsafe { ExitProcess(3) };
        }
    }

    fn duplicate_remote_token(
        source_process_id: u32,
        source_creation_time: u64,
        source_token_value: u64,
    ) -> Result<HANDLE, String> {
        let source = unsafe {
            OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                source_process_id,
            )
        };
        if source.is_null() {
            return Err(format!(
                "open loader lab token source process: {}",
                std::io::Error::last_os_error()
            ));
        }
        let source = TokenHandle(source);
        if process_identity(source.raw(), source_process_id)?.creation_time_100ns
            != source_creation_time
        {
            return Err(String::from(
                "loader lab token source process identity changed",
            ));
        }
        let source_token = usize::try_from(source_token_value)
            .map_err(|_| String::from("loader lab source token value overflow"))?
            as HANDLE;
        let mut local = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                source.raw(),
                source_token,
                GetCurrentProcess(),
                &raw mut local,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(format!(
                "duplicate loader lab source token: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(local)
    }

    pub fn run_scenario(
        scenario: &LoaderLabScenarioV1,
    ) -> Result<LoaderLabScenarioResultV1, String> {
        let token = match TokenHandle::for_variant(&scenario.token_variant) {
            Ok(token) => token,
            Err(_) => {
                return Ok(preparation_failure(
                    scenario,
                    None,
                    WindowsLoaderQualificationStageV2::DesktopPreflight,
                    "target-token-preflight",
                    CleanupOutcomeV1::complete(),
                ));
            }
        };
        let token_envelope = match memcordon_windows_launch_core::query_token_envelope(token.raw())
        {
            Ok(envelope) => envelope,
            Err(_) => {
                return Ok(preparation_failure(
                    scenario,
                    None,
                    WindowsLoaderQualificationStageV2::DesktopPreflight,
                    "target-token-envelope-readback",
                    CleanupOutcomeV1::complete(),
                ));
            }
        };
        let nonce = match random_nonce() {
            Ok(nonce) => nonce,
            Err(_) => {
                return Ok(preparation_failure(
                    scenario,
                    Some(token_envelope),
                    WindowsLoaderQualificationStageV2::PlanValidation,
                    "nonce-generation",
                    CleanupOutcomeV1::complete(),
                ));
            }
        };
        let endpoint = match LoaderReadyEndpointV1::new(nonce.clone()) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                return Ok(preparation_failure(
                    scenario,
                    Some(token_envelope),
                    WindowsLoaderQualificationStageV2::PlanValidation,
                    "loader-ready-endpoint",
                    CleanupOutcomeV1::complete(),
                ));
            }
        };
        let pipe_sddl = if scenario.production_equivalent {
            scenario
                .plan
                .loader_ready_pipe_security_descriptor_sddl()
                .to_owned()
        } else {
            target_aware_pipe_sddl(&token_envelope, &scenario.token_variant)
        };
        let pipe = match Pipe::create(endpoint.name(), &pipe_sddl) {
            Ok(pipe) => pipe,
            Err(_) => {
                return Ok(preparation_failure(
                    scenario,
                    Some(token_envelope),
                    WindowsLoaderQualificationStageV2::DesktopPreflight,
                    "loader-ready-pipe-create",
                    CleanupOutcomeV1::complete(),
                ));
            }
        };
        let executable = match executable_units(&scenario.target_path) {
            Ok(executable) => executable,
            Err(_) => {
                return Ok(preparation_failure(
                    scenario,
                    Some(token_envelope),
                    WindowsLoaderQualificationStageV2::PlanValidation,
                    "target-executable-identity",
                    CleanupOutcomeV1::complete(),
                ));
            }
        };
        let desktop_name = scenario_desktop_name(scenario);
        let desktop = desktop_name.encode_utf16().collect::<Vec<_>>();
        let mut command =
            match PreparedLoaderCommandV1::loader_control(&executable, &endpoint, &desktop) {
                Ok(command) => command,
                Err(_) => {
                    return Ok(preparation_failure(
                        scenario,
                        Some(token_envelope),
                        WindowsLoaderQualificationStageV2::PlanValidation,
                        "command-preparation",
                        CleanupOutcomeV1::complete(),
                    ));
                }
            };
        let mut profile_lease =
            match ProfileLease::for_variant(token.raw(), &scenario.profile_variant) {
                Ok(profile) => profile,
                Err(_) => {
                    return Ok(preparation_failure(
                        scenario,
                        Some(token_envelope),
                        WindowsLoaderQualificationStageV2::DesktopPreflight,
                        "profile-preparation",
                        CleanupOutcomeV1::complete(),
                    ));
                }
            };
        let parent = match ParentProcessLease::for_variant(
            &scenario.parent_variant,
            token_envelope.session_id,
        ) {
            Ok(parent) => parent,
            Err(_) => {
                let cleanup = merge_cleanup(
                    CleanupOutcomeV1::complete(),
                    Ok(()),
                    profile_lease.retire(),
                    Ok(()),
                );
                return Ok(preparation_failure(
                    scenario,
                    Some(token_envelope),
                    WindowsLoaderQualificationStageV2::DesktopPreflight,
                    "parent-context-preparation",
                    cleanup,
                ));
            }
        };
        let mut environment = match scenario_environment(&scenario.environment_variant, token.raw())
        {
            Ok(environment) => environment,
            Err(_) => {
                let cleanup = merge_cleanup(
                    CleanupOutcomeV1::complete(),
                    Ok(()),
                    profile_lease.retire(),
                    Ok(()),
                );
                return Ok(preparation_failure(
                    scenario,
                    Some(token_envelope),
                    WindowsLoaderQualificationStageV2::PlanValidation,
                    "environment-preparation",
                    cleanup,
                ));
            }
        };
        let current_directory =
            match PreparedCurrentDirectoryV1::new(os_units(scenario.current_directory.as_os_str()))
            {
                Ok(directory) => directory,
                Err(_) => {
                    let cleanup = merge_cleanup(
                        CleanupOutcomeV1::complete(),
                        Ok(()),
                        profile_lease.retire(),
                        Ok(()),
                    );
                    return Ok(preparation_failure(
                        scenario,
                        Some(token_envelope),
                        WindowsLoaderQualificationStageV2::PlanValidation,
                        "current-directory-preparation",
                        cleanup,
                    ));
                }
            };
        let plan = match scenario_plan(
            scenario,
            token.raw(),
            &executable,
            &command,
            &environment,
            &current_directory,
        ) {
            Ok(plan) => plan,
            Err(_) => {
                let cleanup = merge_cleanup(
                    CleanupOutcomeV1::complete(),
                    Ok(()),
                    profile_lease.retire(),
                    Ok(()),
                );
                return Ok(preparation_failure(
                    scenario,
                    Some(token_envelope),
                    WindowsLoaderQualificationStageV2::PlanValidation,
                    "scenario-plan-validation",
                    cleanup,
                ));
            }
        };
        let mut desktop_lease = match DesktopLease::create(
            &desktop_name,
            &plan.desktop().window_station_security_descriptor_sddl,
            &plan.desktop().desktop_security_descriptor_sddl,
        ) {
            Ok(desktop) => desktop,
            Err(_) => {
                let cleanup = merge_cleanup(
                    CleanupOutcomeV1::complete(),
                    Ok(()),
                    profile_lease.retire(),
                    Ok(()),
                );
                return Ok(preparation_failure_after_plan(
                    scenario,
                    token_envelope,
                    &plan,
                    WindowsLoaderQualificationStageV2::DesktopPreflight,
                    "desktop-preflight",
                    cleanup,
                ));
            }
        };
        let mut desktop_native = desktop;
        desktop_native.push(0);
        let default_security = scenario.security_descriptor_variant
            == DiagnosticSecurityDescriptorVariantV1::ProcessAndThreadDefaults;
        let process_security = match (!default_security)
            .then(|| NativeSecurityDescriptorV1::from_sddl(plan.process_security_descriptor_sddl()))
            .transpose()
        {
            Ok(security) => security,
            Err(_) => {
                let cleanup = merge_cleanup(
                    CleanupOutcomeV1::complete(),
                    desktop_lease.retire(),
                    profile_lease.retire(),
                    Ok(()),
                );
                return Ok(preparation_failure_after_plan(
                    scenario,
                    token_envelope,
                    &plan,
                    WindowsLoaderQualificationStageV2::PlanValidation,
                    "process-security-descriptor",
                    cleanup,
                ));
            }
        };
        let thread_security = match (!default_security)
            .then(|| NativeSecurityDescriptorV1::from_sddl(plan.thread_security_descriptor_sddl()))
            .transpose()
        {
            Ok(security) => security,
            Err(_) => {
                let cleanup = merge_cleanup(
                    CleanupOutcomeV1::complete(),
                    desktop_lease.retire(),
                    profile_lease.retire(),
                    Ok(()),
                );
                return Ok(preparation_failure_after_plan(
                    scenario,
                    token_envelope,
                    &plan,
                    WindowsLoaderQualificationStageV2::PlanValidation,
                    "thread-security-descriptor",
                    cleanup,
                ));
            }
        };
        let job = match ProductionJobV1::create(plan.job_security_descriptor_sddl()) {
            Ok(job) => job,
            Err(error) => {
                let status = native_status(&error);
                let cleanup = merge_cleanup(
                    CleanupOutcomeV1::complete(),
                    desktop_lease.retire(),
                    profile_lease.retire(),
                    Ok(()),
                );
                let mut result = preparation_failure_after_plan(
                    scenario,
                    token_envelope,
                    &plan,
                    WindowsLoaderQualificationStageV2::DesktopPreflight,
                    error.stable_code,
                    cleanup,
                );
                result.process_create.status = Some(status.clone());
                result.failure_status = Some(status);
                return Ok(result);
            }
        };
        let prepared_inputs = PreparedInputEvidenceV1 {
            command_line_sha256: sha256_utf16(command.units()),
            command_line_units: u64::try_from(command.units().len()).unwrap_or(u64::MAX),
            environment_sha256: sha256_utf16(environment.units()),
            environment_units: u64::try_from(environment.units().len()).unwrap_or(u64::MAX),
            current_directory_sha256: sha256_utf16(current_directory.units()),
            current_directory_units: u64::try_from(current_directory.units().len())
                .unwrap_or(u64::MAX),
        };
        let application = nul_terminated(&executable);
        let native_request = ProductionNativeCreateRequestV1 {
            plan: &plan,
            target_token: token.raw(),
            job: job.handle(),
            application: &application,
            command: &mut command,
            environment: &mut environment,
            current_directory: &current_directory,
            desktop: &mut desktop_native,
            process_security: process_security.as_ref(),
            thread_security: thread_security.as_ref(),
        };
        let creation = create_suspended_in_job(native_request);
        let process = match creation {
            Ok(process) => process,
            Err(error) => {
                let cleanup =
                    cleanup_after_create_failure(&job, &mut desktop_lease, &mut profile_lease);
                return Ok(result(
                    scenario,
                    &token_envelope,
                    &prepared_inputs,
                    None,
                    None,
                    None,
                    None,
                    None,
                    plan.launch_plan_sha256(),
                    NativeCallOutcomeV1 {
                        completed: false,
                        status: Some(native_status(&error)),
                    },
                    Some(WindowsLoaderQualificationStageV2::ProcessCreate),
                    Some(native_status(&error)),
                    None,
                    HandshakeOutcomeV1::NotStarted,
                    cleanup,
                ));
            }
        };
        let process_create = NativeCallOutcomeV1 {
            completed: true,
            status: None,
        };
        let suspended_process = match suspended_process_evidence(&process, &plan, &parent) {
            Ok(mut evidence) => {
                evidence.window_station_descriptor_sha256 =
                    desktop_lease.window_station_descriptor_sha256.clone();
                evidence.desktop_descriptor_sha256 =
                    desktop_lease.desktop_descriptor_sha256.clone();
                evidence
            }
            Err(stable_code) => {
                return Ok(failed_after_create(
                    scenario,
                    &token_envelope,
                    &prepared_inputs,
                    None,
                    None,
                    None,
                    None,
                    None,
                    &plan,
                    &job,
                    &mut desktop_lease,
                    &mut profile_lease,
                    process_create,
                    None,
                    WindowsLoaderQualificationStageV2::SuspendedAttestation,
                    stable_code,
                    None,
                ));
            }
        };
        let (observer, observer_start_evidence) = match ObserverLease::start(
            &scenario.observer,
            process.process_handle(),
            process.process_id(),
            &scenario.namespace,
        ) {
            Ok(observer) => (observer, None),
            Err(stable_code) => (
                None,
                Some(ObserverEvidenceV1 {
                    kind: scenario.observer.clone(),
                    completed: false,
                    stable_code: Some(String::from(stable_code)),
                    event_count: 0,
                    output_debug_string_count: 0,
                    module_event_count: 0,
                    exception_event_count: 0,
                    event_codes: Vec::new(),
                    session_started: false,
                    provider_enabled: false,
                    cleanup_complete: true,
                }),
            ),
        };
        if let Err(error) = process.resume_once() {
            return Ok(failed_after_create(
                scenario,
                &token_envelope,
                &prepared_inputs,
                observer_start_evidence,
                Some(suspended_process),
                None,
                None,
                None,
                &plan,
                &job,
                &mut desktop_lease,
                &mut profile_lease,
                process_create,
                observer,
                WindowsLoaderQualificationStageV2::Resume,
                "resume-thread",
                Some(native_status(&error)),
            ));
        }
        let ready = match pipe.authenticate(
            process.process_id(),
            process.process_handle(),
            &nonce,
            &plan.desktop().exact_name,
        ) {
            Ok(ready) => ready,
            Err(stable_code) => {
                return Ok(failed_after_create(
                    scenario,
                    &token_envelope,
                    &prepared_inputs,
                    observer_start_evidence,
                    Some(suspended_process),
                    None,
                    None,
                    None,
                    &plan,
                    &job,
                    &mut desktop_lease,
                    &mut profile_lease,
                    process_create,
                    observer,
                    WindowsLoaderQualificationStageV2::LoaderReadyHandshake,
                    stable_code,
                    None,
                ));
            }
        };
        if scenario.production_equivalent
            && (ready.bootstrap_identity.as_ref() != Some(&suspended_process.process_identity)
                || ready.process_envelope.as_ref() != Some(&token_envelope)
                || ready.process_snapshot.is_none())
        {
            return Ok(failed_after_create(
                scenario,
                &token_envelope,
                &prepared_inputs,
                observer_start_evidence,
                Some(suspended_process),
                ready.bootstrap_identity,
                ready.process_envelope,
                ready.process_snapshot,
                &plan,
                &job,
                &mut desktop_lease,
                &mut profile_lease,
                process_create,
                observer,
                WindowsLoaderQualificationStageV2::LoaderReadyHandshake,
                "loader-ready-live-evidence-mismatch",
                None,
            ));
        }
        if unsafe { WaitForSingleObject(process.process_handle(), 30_000) } != 0 {
            return Ok(failed_after_create(
                scenario,
                &token_envelope,
                &prepared_inputs,
                observer_start_evidence,
                Some(suspended_process),
                ready.bootstrap_identity.clone(),
                ready.process_envelope.clone(),
                ready.process_snapshot.clone(),
                &plan,
                &job,
                &mut desktop_lease,
                &mut profile_lease,
                process_create,
                observer,
                WindowsLoaderQualificationStageV2::ExitDrain,
                "target-exit-timeout",
                None,
            ));
        }
        let mut exit_code = 0_u32;
        if unsafe { GetExitCodeProcess(process.process_handle(), &raw mut exit_code) } == 0 {
            return Ok(failed_after_create(
                scenario,
                &token_envelope,
                &prepared_inputs,
                None,
                Some(suspended_process),
                ready.bootstrap_identity.clone(),
                ready.process_envelope.clone(),
                ready.process_snapshot.clone(),
                &plan,
                &job,
                &mut desktop_lease,
                &mut profile_lease,
                process_create,
                observer,
                WindowsLoaderQualificationStageV2::ExitDrain,
                "target-exit-readback",
                None,
            ));
        }
        let job_cleanup = match job.wait_empty(std::time::Instant::now() + Duration::from_secs(30))
        {
            Ok(true) => CleanupOutcomeV1::complete(),
            Ok(false) => CleanupOutcomeV1::failed(String::from("job-drain-incomplete")),
            Err(_) => CleanupOutcomeV1::failed(String::from("job-drain-failed")),
        };
        let (finished_observer_evidence, observer_cleanup) = finish_observer(observer);
        let observer_evidence = observer_start_evidence.or(finished_observer_evidence);
        let cleanup = merge_cleanup(
            job_cleanup,
            desktop_lease.retire(),
            profile_lease.retire(),
            observer_cleanup,
        );
        Ok(result(
            scenario,
            &token_envelope,
            &prepared_inputs,
            observer_evidence,
            Some(suspended_process),
            ready.bootstrap_identity,
            ready.process_envelope,
            ready.process_snapshot,
            plan.launch_plan_sha256(),
            process_create,
            None,
            None,
            Some(exit_code),
            HandshakeOutcomeV1::Authenticated {
                protocol_version: BOOTSTRAP_SCHEMA_VERSION,
            },
            cleanup,
        ))
    }

    // The failure constructor accepts each independently attested artifact
    // field so it cannot silently drop partial native evidence.
    #[allow(clippy::too_many_arguments)]
    fn failed_after_create(
        scenario: &LoaderLabScenarioV1,
        token_envelope: &memcordon_core::WindowsCallerTokenEnvelopeV1,
        prepared_inputs: &PreparedInputEvidenceV1,
        observer_evidence: Option<ObserverEvidenceV1>,
        suspended_process: Option<SuspendedProcessEvidenceV1>,
        loader_ready_process_identity: Option<memcordon_core::WindowsProcessIdentityV1>,
        loader_ready_token_envelope: Option<memcordon_core::WindowsCallerTokenEnvelopeV1>,
        loader_ready_process_snapshot: Option<LoaderReadyTokenSnapshotV1>,
        plan: &ProductionLoaderPlanV1,
        job: &ProductionJobV1,
        desktop: &mut DesktopLease,
        profile: &mut ProfileLease,
        process_create: NativeCallOutcomeV1,
        observer: Option<ObserverLease>,
        failure_stage: WindowsLoaderQualificationStageV2,
        stable_code: &str,
        status: Option<NativeStatusV1>,
    ) -> LoaderLabScenarioResultV1 {
        let termination = job.terminate(0xc000_0142);
        let drain = job.wait_empty(std::time::Instant::now() + Duration::from_secs(30));
        let job_cleanup = match (termination, drain) {
            (Ok(()), Ok(true)) => CleanupOutcomeV1::complete(),
            (Err(_), Ok(true)) => CleanupOutcomeV1::failed(String::from("job-terminate-failed")),
            (Ok(()), Ok(false)) => CleanupOutcomeV1::failed(String::from("job-drain-incomplete")),
            _ => CleanupOutcomeV1::failed(String::from("job-terminate-and-drain-failed")),
        };
        let (finished_observer_evidence, observer_cleanup) = finish_observer(observer);
        let observer_evidence = observer_evidence.or(finished_observer_evidence);
        let cleanup = merge_cleanup(
            job_cleanup,
            desktop.retire(),
            profile.retire(),
            observer_cleanup,
        );
        let handshake = match failure_stage {
            WindowsLoaderQualificationStageV2::LoaderReadyHandshake => HandshakeOutcomeV1::Failed {
                stable_code: stable_code.to_owned(),
            },
            WindowsLoaderQualificationStageV2::ExitDrain => HandshakeOutcomeV1::Authenticated {
                protocol_version: BOOTSTRAP_SCHEMA_VERSION,
            },
            _ => HandshakeOutcomeV1::NotStarted,
        };
        result(
            scenario,
            token_envelope,
            prepared_inputs,
            observer_evidence,
            suspended_process,
            loader_ready_process_identity,
            loader_ready_token_envelope,
            loader_ready_process_snapshot,
            plan.launch_plan_sha256(),
            process_create,
            Some(failure_stage),
            status,
            None,
            handshake,
            cleanup,
        )
    }

    fn cleanup_after_create_failure(
        job: &ProductionJobV1,
        desktop: &mut DesktopLease,
        profile: &mut ProfileLease,
    ) -> CleanupOutcomeV1 {
        let job_cleanup = match job.wait_empty(std::time::Instant::now() + Duration::from_secs(30))
        {
            Ok(true) => CleanupOutcomeV1::complete(),
            Ok(false) => CleanupOutcomeV1::failed(String::from("job-drain-incomplete")),
            Err(_) => CleanupOutcomeV1::failed(String::from("job-drain-failed")),
        };
        merge_cleanup(job_cleanup, desktop.retire(), profile.retire(), Ok(()))
    }

    fn finish_observer(
        observer: Option<ObserverLease>,
    ) -> (Option<ObserverEvidenceV1>, Result<(), &'static str>) {
        match observer {
            Some(observer) => match observer.finish() {
                Ok(evidence) => (Some(evidence), Ok(())),
                Err(code) => (None, Err(code)),
            },
            None => (None, Ok(())),
        }
    }

    fn merge_cleanup(
        job: CleanupOutcomeV1,
        desktop: Result<(), &'static str>,
        profile: Result<(), &'static str>,
        observer: Result<(), &'static str>,
    ) -> CleanupOutcomeV1 {
        match (job.status(), desktop, profile, observer) {
            (memcordon_windows_launch_core::CleanupStatusV1::Complete, Ok(()), Ok(()), Ok(())) => {
                CleanupOutcomeV1::complete()
            }
            (_, Err(code), _, _) | (_, _, Err(code), _) | (_, _, _, Err(code)) => {
                CleanupOutcomeV1::failed(String::from(code))
            }
            _ => job,
        }
    }

    // Keep the complete result schema visible at this single construction
    // boundary; grouping these fields would make omissions easier to hide.
    #[allow(clippy::too_many_arguments)]
    fn result(
        scenario: &LoaderLabScenarioV1,
        token_envelope: &memcordon_core::WindowsCallerTokenEnvelopeV1,
        prepared_inputs: &PreparedInputEvidenceV1,
        observer_evidence: Option<ObserverEvidenceV1>,
        suspended_process: Option<SuspendedProcessEvidenceV1>,
        loader_ready_process_identity: Option<memcordon_core::WindowsProcessIdentityV1>,
        loader_ready_token_envelope: Option<memcordon_core::WindowsCallerTokenEnvelopeV1>,
        loader_ready_process_snapshot: Option<LoaderReadyTokenSnapshotV1>,
        launch_plan_sha256: &str,
        process_create: NativeCallOutcomeV1,
        failure_stage: Option<WindowsLoaderQualificationStageV2>,
        failure_status: Option<NativeStatusV1>,
        target_exit_code: Option<u32>,
        handshake: HandshakeOutcomeV1,
        cleanup: CleanupOutcomeV1,
    ) -> LoaderLabScenarioResultV1 {
        LoaderLabScenarioResultV1 {
            scenario_id: scenario.scenario_id.clone(),
            production_equivalent: scenario.production_equivalent,
            perturbed: scenario.perturbed,
            launch_plan_sha256: Some(launch_plan_sha256.to_owned()),
            token_variant: scenario.token_variant.clone(),
            desktop_variant: scenario.desktop_variant.clone(),
            environment_variant: scenario.environment_variant.clone(),
            security_descriptor_variant: scenario.security_descriptor_variant.clone(),
            profile_variant: scenario.profile_variant.clone(),
            parent_variant: scenario.parent_variant.clone(),
            observer: scenario.observer.clone(),
            observer_evidence,
            target_token_envelope_sha256: Some(envelope_digest(token_envelope)),
            prepared_inputs: Some(prepared_inputs.clone()),
            suspended_process,
            loader_ready_process_identity,
            loader_ready_token_envelope_sha256: loader_ready_token_envelope
                .as_ref()
                .map(envelope_digest),
            loader_ready_process_snapshot: loader_ready_process_snapshot
                .as_ref()
                .map(redact_ready_snapshot),
            process_create,
            failure_stage,
            failure_status,
            target_exit_code,
            handshake,
            cleanup,
            attachments: Vec::new(),
        }
    }

    fn preparation_failure(
        scenario: &LoaderLabScenarioV1,
        token_envelope: Option<memcordon_core::WindowsCallerTokenEnvelopeV1>,
        stage: WindowsLoaderQualificationStageV2,
        stable_code: &str,
        cleanup: CleanupOutcomeV1,
    ) -> LoaderLabScenarioResultV1 {
        let status = NativeStatusV1::Stable {
            code: stable_code.to_owned(),
        };
        LoaderLabScenarioResultV1 {
            scenario_id: scenario.scenario_id.clone(),
            production_equivalent: scenario.production_equivalent,
            perturbed: scenario.perturbed,
            launch_plan_sha256: None,
            token_variant: scenario.token_variant.clone(),
            desktop_variant: scenario.desktop_variant.clone(),
            environment_variant: scenario.environment_variant.clone(),
            security_descriptor_variant: scenario.security_descriptor_variant.clone(),
            profile_variant: scenario.profile_variant.clone(),
            parent_variant: scenario.parent_variant.clone(),
            observer: scenario.observer.clone(),
            observer_evidence: None,
            target_token_envelope_sha256: token_envelope.as_ref().map(envelope_digest),
            prepared_inputs: None,
            suspended_process: None,
            loader_ready_process_identity: None,
            loader_ready_token_envelope_sha256: None,
            loader_ready_process_snapshot: None,
            process_create: NativeCallOutcomeV1 {
                completed: false,
                status: Some(status.clone()),
            },
            failure_stage: Some(stage),
            failure_status: Some(status),
            target_exit_code: None,
            handshake: HandshakeOutcomeV1::NotStarted,
            cleanup,
            attachments: Vec::new(),
        }
    }

    fn preparation_failure_after_plan(
        scenario: &LoaderLabScenarioV1,
        token_envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,
        plan: &ProductionLoaderPlanV1,
        stage: WindowsLoaderQualificationStageV2,
        stable_code: &str,
        cleanup: CleanupOutcomeV1,
    ) -> LoaderLabScenarioResultV1 {
        let mut result =
            preparation_failure(scenario, Some(token_envelope), stage, stable_code, cleanup);
        result.launch_plan_sha256 = Some(plan.launch_plan_sha256().to_owned());
        result
    }

    fn envelope_digest(envelope: &memcordon_core::WindowsCallerTokenEnvelopeV1) -> String {
        memcordon_windows_launch_core::token_envelope_sha256(envelope)
            .expect("a queried native token envelope must remain canonical")
    }

    fn redact_ready_snapshot(
        snapshot: &LoaderReadyTokenSnapshotV1,
    ) -> LoaderReadyTokenSnapshotEvidenceV1 {
        let serialized = serde_json::to_vec(snapshot)
            .expect("the typed loader-ready token snapshot must serialize");
        LoaderReadyTokenSnapshotEvidenceV1 {
            snapshot_sha256: hex::encode(Sha256::digest(serialized)),
            envelope_sha256: envelope_digest(&snapshot.behavior.envelope),
            token_id: snapshot.instance.token_id,
            modified_id: snapshot.instance.modified_id,
            authentication_id: snapshot.lineage.authentication_id,
            originating_logon_session: snapshot.lineage.originating_logon_session,
            session_id: snapshot.lineage.session_id,
            group_count: u64::try_from(snapshot.behavior.groups.len()).unwrap_or(u64::MAX),
            privilege_count: u64::try_from(snapshot.behavior.privileges.len()).unwrap_or(u64::MAX),
            restricting_sid_count: u64::try_from(snapshot.behavior.restricting_sids.len())
                .unwrap_or(u64::MAX),
            token_is_restricted: snapshot.behavior.token_is_restricted,
            enabled_sensitive_privilege_count: snapshot.behavior.enabled_sensitive_privilege_count,
            default_dacl_sha256: snapshot.behavior.default_dacl_sha256.clone(),
        }
    }

    fn scenario_plan(
        scenario: &LoaderLabScenarioV1,
        token: HANDLE,
        executable: &[u16],
        command: &PreparedLoaderCommandV1,
        environment: &PreparedLoaderEnvironmentV1,
        current_directory: &PreparedCurrentDirectoryV1,
    ) -> Result<ProductionLoaderPlanV1, String> {
        if scenario.production_equivalent {
            return Ok(scenario.plan.clone());
        }
        let (process_sddl, thread_sddl) = match scenario.security_descriptor_variant {
            DiagnosticSecurityDescriptorVariantV1::ProductionExact => (
                scenario.plan.process_security_descriptor_sddl(),
                scenario.plan.thread_security_descriptor_sddl(),
            ),
            DiagnosticSecurityDescriptorVariantV1::ProcessAndThreadDefaults => (
                memcordon_windows_launch_core::WINDOWS_DEFAULT_SECURITY_DESCRIPTOR_V1,
                memcordon_windows_launch_core::WINDOWS_DEFAULT_SECURITY_DESCRIPTOR_V1,
            ),
        };
        let desktop_name = scenario_desktop_name(scenario);
        let (window_station_sddl, desktop_sddl, desktop_descriptor_sha256) =
            match scenario.desktop_variant {
                DiagnosticDesktopVariantV1::ProductionPrivate => (
                    scenario
                        .plan
                        .desktop()
                        .window_station_security_descriptor_sddl
                        .clone(),
                    scenario
                        .plan
                        .desktop()
                        .desktop_security_descriptor_sddl
                        .clone(),
                    scenario.plan.desktop().security_descriptor_sha256.clone(),
                ),
                DiagnosticDesktopVariantV1::ControlledTest => {
                    let station = String::from("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)");
                    let desktop = station.clone();
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(station.as_bytes());
                    hasher.update([0]);
                    hasher.update(desktop.as_bytes());
                    (station, desktop, hex::encode(hasher.finalize()))
                }
            };
        ProductionLoaderPlanV1::new(ProductionLoaderPlanInputV1 {
            executable_path_utf16: executable.to_vec(),
            executable_sha256: artifact::file_sha256(&scenario.target_path)?,
            command_line_sha256: command.semantic_sha256().to_owned(),
            environment: environment.identity().clone(),
            current_directory_sha256: current_directory.sha256().to_owned(),
            desktop: DesktopBindingV1 {
                exact_name: desktop_name,
                security_descriptor_sha256: desktop_descriptor_sha256,
                window_station_security_descriptor_sddl: window_station_sddl,
                desktop_security_descriptor_sddl: desktop_sddl,
            },
            process_security_descriptor_sddl: process_sddl.to_owned(),
            thread_security_descriptor_sddl: thread_sddl.to_owned(),
            job_security_descriptor_sddl: scenario.plan.job_security_descriptor_sddl().to_owned(),
            loader_ready_pipe_security_descriptor_sddl: if scenario.production_equivalent {
                scenario
                    .plan
                    .loader_ready_pipe_security_descriptor_sddl()
                    .to_owned()
            } else {
                target_aware_pipe_sddl(
                    &memcordon_windows_launch_core::query_token_envelope(token)?,
                    &scenario.token_variant,
                )
            },
            target_token: if scenario.token_variant == DiagnosticTokenVariantV1::ProductionTarget {
                scenario.plan.target_token().clone()
            } else {
                token_identity_for_plan(token, &scenario.token_variant)?
            },
            inherited_handles: ExactHandleListV1::none(),
            job_at_creation: true,
        })
        .map_err(|error| format!("construct diagnostic plan: {error}"))
    }

    fn scenario_environment(
        variant: &DiagnosticEnvironmentVariantV1,
        token: HANDLE,
    ) -> Result<PreparedLoaderEnvironmentV1, String> {
        match variant {
            DiagnosticEnvironmentVariantV1::ProductionPrepared => canonical_environment(),
            DiagnosticEnvironmentVariantV1::QualificationCaller => caller_environment(),
            DiagnosticEnvironmentVariantV1::TargetDerived => target_environment(token),
        }
    }

    fn scenario_desktop_name(scenario: &LoaderLabScenarioV1) -> String {
        match scenario.desktop_variant {
            DiagnosticDesktopVariantV1::ProductionPrivate => {
                scenario.plan.desktop().exact_name.clone()
            }
            DiagnosticDesktopVariantV1::ControlledTest => {
                format!("{}-station\\controlled", scenario.namespace)
            }
        }
    }

    fn canonical_environment() -> Result<PreparedLoaderEnvironmentV1, String> {
        let value = |name: &str| {
            std::env::var_os(name)
                .ok_or_else(|| format!("required environment variable is absent: {name}"))
                .map(|value| os_units(&value))
        };
        PreparedLoaderEnvironmentV1::canonical_minimal_system([
            value("SystemDrive")?,
            value("SystemRoot")?,
            value("windir")?,
        ])
        .map_err(String::from)
    }

    fn caller_environment() -> Result<PreparedLoaderEnvironmentV1, String> {
        let entries = std::env::vars_os()
            .map(|(name, value)| memcordon_core::WindowsEnvironmentEntryV1 {
                name: os_units(&name),
                value: os_units(&value),
            })
            .collect::<Vec<_>>();
        let units = memcordon_core::encode_windows_environment_block(&entries)
            .map_err(|error| format!("prepare caller environment: {error}"))?;
        PreparedLoaderEnvironmentV1::new(units).map_err(String::from)
    }

    fn target_environment(token: HANDLE) -> Result<PreparedLoaderEnvironmentV1, String> {
        use std::ffi::c_void;
        #[link(name = "userenv")]
        unsafe extern "system" {
            fn CreateEnvironmentBlock(
                environment: *mut *mut c_void,
                token: HANDLE,
                inherit: i32,
            ) -> i32;
            fn DestroyEnvironmentBlock(environment: *mut c_void) -> i32;
        }
        let mut raw = ptr::null_mut();
        if unsafe { CreateEnvironmentBlock(&raw mut raw, token, 0) } == 0 {
            return Err(format!(
                "create target environment: {}",
                std::io::Error::last_os_error()
            ));
        }
        let raw = raw.cast::<u16>();
        let mut length = 0_usize;
        loop {
            let current = unsafe { *raw.add(length) };
            let next = unsafe { *raw.add(length + 1) };
            length = length
                .checked_add(1)
                .ok_or_else(|| String::from("target environment length overflow"))?;
            if current == 0 && next == 0 {
                length = length
                    .checked_add(1)
                    .ok_or_else(|| String::from("target environment length overflow"))?;
                break;
            }
            if length > 16 * 1024 * 1024 {
                unsafe { DestroyEnvironmentBlock(raw.cast()) };
                return Err(String::from("target environment exceeds laboratory bound"));
            }
        }
        let units = unsafe { std::slice::from_raw_parts(raw, length) }.to_vec();
        unsafe { DestroyEnvironmentBlock(raw.cast()) };
        PreparedLoaderEnvironmentV1::new(units).map_err(String::from)
    }

    fn executable_units(path: &std::path::Path) -> Result<Vec<u16>, String> {
        let units = os_units(path.as_os_str());
        if units.is_empty() || units.contains(&0) {
            Err(String::from(
                "scenario executable path is empty or contains NUL",
            ))
        } else {
            Ok(units)
        }
    }

    fn os_units(value: &OsStr) -> Vec<u16> {
        value.encode_wide().collect()
    }

    fn nul_terminated(value: &[u16]) -> Vec<u16> {
        value.iter().copied().chain(std::iter::once(0)).collect()
    }

    fn random_nonce() -> Result<String, String> {
        let mut nonce = vec![0_u8; sha2::Sha256::output_size()];
        let length =
            u32::try_from(nonce.len()).map_err(|_| String::from("nonce length overflow"))?;
        if unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                nonce.as_mut_ptr(),
                length,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } != 0
        {
            return Err(String::from("generate loader-ready nonce"));
        }
        Ok(hex::encode(nonce))
    }

    fn native_status(error: &memcordon_windows_launch_core::NativeCreateErrorV1) -> NativeStatusV1 {
        error.win32_error.map_or_else(
            || NativeStatusV1::Stable {
                code: error.stable_code.to_owned(),
            },
            |code| NativeStatusV1::Win32 { code },
        )
    }

    fn render_native_error(error: memcordon_windows_launch_core::NativeCreateErrorV1) -> String {
        format!("{}: {}", error.stable_code, error.detail)
    }

    fn suspended_process_evidence(
        process: &memcordon_windows_launch_core::SuspendedNativeProcessV1,
        plan: &ProductionLoaderPlanV1,
        parent: &ParentProcessLease,
    ) -> Result<SuspendedProcessEvidenceV1, &'static str> {
        let token = TokenHandle::process_query(process.process_handle())
            .map_err(|_| "suspended-token-open-failed")?;
        let token_envelope = memcordon_windows_launch_core::query_token_envelope(token.raw())
            .map_err(|_| "suspended-token-query-failed")?;
        if memcordon_windows_launch_core::token_envelope_sha256(&token_envelope)
            .map_err(|_| "suspended-token-digest-failed")?
            != plan.target_token().envelope_sha256
        {
            return Err("suspended-token-envelope-mismatch");
        }
        let image = process_image_path(process.process_handle())
            .map_err(|_| "suspended-image-readback-failed")?;
        let image_matches_plan = image == *plan.executable_path_utf16();
        if !image_matches_plan {
            return Err("suspended-image-mismatch");
        }
        let process_identity = process_identity(process.process_handle(), process.process_id())
            .map_err(|_| "suspended-identity-readback-failed")?;
        let desktop_name = thread_desktop_name(process.thread_id())
            .map_err(|_| "suspended-desktop-readback-failed")?;
        let expected_desktop = plan
            .desktop()
            .exact_name
            .rsplit_once('\\')
            .map_or(plan.desktop().exact_name.as_str(), |(_, desktop)| desktop);
        if desktop_name != expected_desktop {
            return Err("suspended-desktop-binding-mismatch");
        }
        Ok(SuspendedProcessEvidenceV1 {
            process_identity,
            parent_process_identity: parent.identity.clone(),
            parent_token_envelope_sha256: parent.token_envelope_sha256.clone(),
            token_envelope_sha256: envelope_digest(&token_envelope),
            image_path_sha256: sha256_utf16(&image),
            image_matches_plan,
            job_membership_at_creation: true,
            // The shared creator passes bInheritHandles=FALSE and its sole
            // process-thread attribute is the creation-time Job.
            empty_inherited_handle_list: true,
            desktop_binding_name_sha256: hex::encode(Sha256::digest(desktop_name.as_bytes())),
            window_station_descriptor_sha256: String::new(),
            desktop_descriptor_sha256: String::new(),
        })
    }

    fn thread_desktop_name(thread_id: u32) -> Result<String, String> {
        let desktop = unsafe { GetThreadDesktop(thread_id) };
        if desktop.is_null() {
            return Err(format!(
                "read suspended thread desktop: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut required = 0_u32;
        unsafe {
            GetUserObjectInformationW(desktop, UOI_NAME, ptr::null_mut(), 0, &raw mut required)
        };
        if required == 0 || required % 2 != 0 {
            return Err(String::from(
                "suspended thread desktop name size is invalid",
            ));
        }
        let mut units = vec![0_u16; required as usize / 2];
        if unsafe {
            GetUserObjectInformationW(
                desktop,
                UOI_NAME,
                units.as_mut_ptr().cast(),
                required,
                &raw mut required,
            )
        } == 0
        {
            return Err(format!(
                "read suspended thread desktop name: {}",
                std::io::Error::last_os_error()
            ));
        }
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units)
            .map_err(|_| String::from("suspended thread desktop name is invalid UTF-16"))
    }

    fn process_identity(
        process: HANDLE,
        process_id: u32,
    ) -> Result<memcordon_core::WindowsProcessIdentityV1, String> {
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe {
            GetProcessTimes(
                process,
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        } == 0
        {
            return Err(format!(
                "read process creation identity: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(memcordon_core::WindowsProcessIdentityV1 {
            process_id,
            creation_time_100ns: (u64::from(created.dwHighDateTime) << 32)
                | u64::from(created.dwLowDateTime),
        })
    }

    fn process_image_path(process: HANDLE) -> Result<Vec<u16>, String> {
        let mut units = vec![0_u16; 32 * 1024];
        let mut length = u32::try_from(units.len())
            .map_err(|_| String::from("process image buffer length overflow"))?;
        if unsafe { QueryFullProcessImageNameW(process, 0, units.as_mut_ptr(), &raw mut length) }
            == 0
        {
            return Err(format!(
                "read suspended process image: {}",
                std::io::Error::last_os_error()
            ));
        }
        units.truncate(
            usize::try_from(length).map_err(|_| String::from("process image length overflow"))?,
        );
        Ok(units)
    }

    fn sha256_utf16(units: &[u16]) -> String {
        let mut digest = Sha256::new();
        for unit in units {
            digest.update(unit.to_le_bytes());
        }
        hex::encode(digest.finalize())
    }

    struct TokenHandle(HANDLE);

    struct ProfileLease {
        token: HANDLE,
        profile: HANDLE,
        loaded: bool,
    }

    impl ProfileLease {
        fn for_variant(
            token: HANDLE,
            variant: &crate::scenario::DiagnosticProfileVariantV1,
        ) -> Result<Self, String> {
            if *variant == crate::scenario::DiagnosticProfileVariantV1::ProductionUnloaded {
                return Ok(Self {
                    token,
                    profile: ptr::null_mut(),
                    loaded: false,
                });
            }
            let mut username = current_username()?;
            let mut information = PROFILEINFOW {
                dwSize: u32::try_from(std::mem::size_of::<PROFILEINFOW>())
                    .map_err(|_| String::from("profile information size overflow"))?,
                lpUserName: username.as_mut_ptr(),
                ..PROFILEINFOW::default()
            };
            if unsafe { LoadUserProfileW(token, &raw mut information) } == 0 {
                return Err(format!(
                    "load target profile: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self {
                token,
                profile: information.hProfile,
                loaded: true,
            })
        }

        fn retire(&mut self) -> Result<(), &'static str> {
            if !self.loaded {
                return Ok(());
            }
            if unsafe { UnloadUserProfile(self.token, self.profile) } == 0 {
                return Err("profile-unload-failed");
            }
            self.loaded = false;
            Ok(())
        }
    }

    impl Drop for ProfileLease {
        fn drop(&mut self) {
            let _ = self.retire();
        }
    }

    struct ParentProcessLease {
        handle: HANDLE,
        identity: memcordon_core::WindowsProcessIdentityV1,
        token_envelope_sha256: String,
    }

    impl ParentProcessLease {
        fn for_variant(
            variant: &crate::scenario::DiagnosticParentVariantV1,
            _target_session_id: u32,
        ) -> Result<Self, String> {
            let expected_user = match variant {
                crate::scenario::DiagnosticParentVariantV1::ProductionLauncher => Some("S-1-5-18"),
                crate::scenario::DiagnosticParentVariantV1::InteractiveShell => None,
            };
            let process_id =
                unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
            let creator = Self::open_attested(process_id, expected_user, None)?;
            if *variant == crate::scenario::DiagnosticParentVariantV1::InteractiveShell {
                let token = TokenHandle::process_query(creator.raw())?;
                let envelope = memcordon_windows_launch_core::query_token_envelope(token.raw())?;
                if envelope.user_sid == "S-1-5-18" {
                    return Err(String::from(
                        "interactive creator context unexpectedly runs as LocalSystem",
                    ));
                }
            }
            Ok(creator)
        }

        fn open_attested(
            process_id: u32,
            required_user_sid: Option<&str>,
            required_session_id: Option<u32>,
        ) -> Result<Self, String> {
            let handle = unsafe {
                OpenProcess(
                    PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    process_id,
                )
            };
            if handle.is_null() {
                return Err(format!(
                    "open parent process {process_id}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let token = TokenHandle::process_query(handle).inspect_err(|_| unsafe {
                CloseHandle(handle);
            })?;
            let envelope = memcordon_windows_launch_core::query_token_envelope(token.raw())
                .inspect_err(|_| unsafe {
                    CloseHandle(handle);
                })?;
            if required_user_sid.is_some_and(|expected| envelope.user_sid != expected)
                || required_session_id.is_some_and(|expected| envelope.session_id != expected)
            {
                unsafe { CloseHandle(handle) };
                return Err(String::from(
                    "parent process identity does not match scenario",
                ));
            }
            let identity = process_identity(handle, process_id).inspect_err(|_| unsafe {
                CloseHandle(handle);
            })?;
            let token_envelope_sha256 = memcordon_windows_launch_core::token_envelope_sha256(
                &envelope,
            )
            .inspect_err(|_| unsafe {
                CloseHandle(handle);
            })?;
            Ok(Self {
                handle,
                identity,
                token_envelope_sha256,
            })
        }

        const fn raw(&self) -> HANDLE {
            self.handle
        }
    }

    impl Drop for ParentProcessLease {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.handle) };
        }
    }

    fn current_username() -> Result<Vec<u16>, String> {
        let mut length = 0_u32;
        unsafe { GetUserNameW(ptr::null_mut(), &raw mut length) };
        if length == 0 {
            return Err(format!(
                "measure current username: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut username = vec![
            0_u16;
            usize::try_from(length)
                .map_err(|_| String::from("username length overflow"))?
        ];
        if unsafe { GetUserNameW(username.as_mut_ptr(), &raw mut length) } == 0 {
            return Err(format!(
                "read current username: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(username)
    }

    struct DesktopLease {
        original_station: HANDLE,
        station: HANDLE,
        desktop: HANDLE,
        window_station_descriptor_sha256: String,
        desktop_descriptor_sha256: String,
        retired: bool,
    }

    impl DesktopLease {
        fn create(
            exact_name: &str,
            window_station_sddl: &str,
            desktop_sddl: &str,
        ) -> Result<Self, String> {
            let (station_name, desktop_name) = exact_name
                .split_once('\\')
                .ok_or_else(|| String::from("desktop binding is not station\\desktop"))?;
            if station_name.is_empty() || desktop_name.is_empty() || desktop_name.contains('\\') {
                return Err(String::from("desktop binding components are invalid"));
            }
            let station_security = NativeSecurityDescriptorV1::from_sddl(window_station_sddl)
                .map_err(render_native_error)?;
            let desktop_security =
                NativeSecurityDescriptorV1::from_sddl(desktop_sddl).map_err(render_native_error)?;
            let expected_window_station_descriptor_sha256 = station_security
                .binary_sha256()
                .map_err(render_native_error)?;
            let expected_desktop_descriptor_sha256 = desktop_security
                .binary_sha256()
                .map_err(render_native_error)?;
            let station_attributes = station_security
                .security_attributes()
                .map_err(render_native_error)?;
            let desktop_attributes = desktop_security
                .security_attributes()
                .map_err(render_native_error)?;
            let station_name = nul_terminated(&station_name.encode_utf16().collect::<Vec<_>>());
            let desktop_name = nul_terminated(&desktop_name.encode_utf16().collect::<Vec<_>>());
            let original_station = unsafe { GetProcessWindowStation() };
            if original_station.is_null() {
                return Err(format!(
                    "read source window station: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let station = unsafe {
                CreateWindowStationW(
                    station_name.as_ptr(),
                    0,
                    u32::try_from(WINSTA_ALL_ACCESS)
                        .map_err(|_| String::from("window-station access-mask overflow"))?,
                    &raw const station_attributes,
                )
            };
            if station.is_null() {
                return Err(format!(
                    "create laboratory window station: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if unsafe { SetProcessWindowStation(station) } == 0 {
                let error = std::io::Error::last_os_error();
                unsafe { CloseWindowStation(station) };
                return Err(format!("assign laboratory window station: {error}"));
            }
            let desktop = unsafe {
                CreateDesktopW(
                    desktop_name.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    DESKTOP_READOBJECTS
                        | DESKTOP_CREATEWINDOW
                        | DESKTOP_CREATEMENU
                        | DESKTOP_HOOKCONTROL
                        | DESKTOP_JOURNALRECORD
                        | DESKTOP_JOURNALPLAYBACK
                        | DESKTOP_ENUMERATE
                        | DESKTOP_WRITEOBJECTS
                        | DESKTOP_SWITCHDESKTOP,
                    &raw const desktop_attributes,
                )
            };
            if desktop.is_null() {
                let error = std::io::Error::last_os_error();
                unsafe {
                    SetProcessWindowStation(original_station);
                    CloseWindowStation(station);
                }
                return Err(format!("create laboratory desktop: {error}"));
            }
            let descriptors = (|| {
                Ok((
                    user_object_security_sha256(station)?,
                    user_object_security_sha256(desktop)?,
                ))
            })();
            let (window_station_descriptor_sha256, desktop_descriptor_sha256) = match descriptors {
                Ok(descriptors) => descriptors,
                Err(error) => {
                    unsafe {
                        CloseDesktop(desktop);
                        SetProcessWindowStation(original_station);
                        CloseWindowStation(station);
                    }
                    return Err(error);
                }
            };
            if window_station_descriptor_sha256 != expected_window_station_descriptor_sha256
                || desktop_descriptor_sha256 != expected_desktop_descriptor_sha256
            {
                unsafe {
                    CloseDesktop(desktop);
                    SetProcessWindowStation(original_station);
                    CloseWindowStation(station);
                }
                return Err(String::from(
                    "live user-object descriptor differs from the scenario plan",
                ));
            }
            Ok(Self {
                original_station,
                station,
                desktop,
                window_station_descriptor_sha256,
                desktop_descriptor_sha256,
                retired: false,
            })
        }

        fn retire(&mut self) -> Result<(), &'static str> {
            if self.retired {
                return Ok(());
            }
            let mut failure = None;
            if unsafe { CloseDesktop(self.desktop) } == 0 {
                failure = Some("desktop-close-failed");
            }
            if unsafe { SetProcessWindowStation(self.original_station) } == 0 && failure.is_none() {
                failure = Some("window-station-restore-failed");
            }
            if unsafe { CloseWindowStation(self.station) } == 0 && failure.is_none() {
                failure = Some("window-station-close-failed");
            }
            self.retired = true;
            failure.map_or(Ok(()), Err)
        }
    }

    fn user_object_security_sha256(handle: HANDLE) -> Result<String, String> {
        let mut information = windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION
            | windows_sys::Win32::Security::GROUP_SECURITY_INFORMATION
            | windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
        let mut required = 0_u32;
        unsafe {
            GetUserObjectSecurity(
                handle,
                &raw mut information,
                ptr::null_mut(),
                0,
                &raw mut required,
            )
        };
        if required == 0 {
            return Err(format!(
                "measure user-object security: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut descriptor = vec![
            0_u8;
            usize::try_from(required).map_err(|_| String::from(
                "user-object descriptor size overflow"
            ))?
        ];
        if unsafe {
            GetUserObjectSecurity(
                handle,
                &raw mut information,
                descriptor.as_mut_ptr().cast(),
                required,
                &raw mut required,
            )
        } == 0
        {
            return Err(format!(
                "read user-object security: {}",
                std::io::Error::last_os_error()
            ));
        }
        descriptor.truncate(
            usize::try_from(required)
                .map_err(|_| String::from("user-object descriptor size overflow"))?,
        );
        Ok(hex::encode(Sha256::digest(&descriptor)))
    }

    impl Drop for DesktopLease {
        fn drop(&mut self) {
            let _ = self.retire();
        }
    }

    impl TokenHandle {
        fn for_variant(variant: &DiagnosticTokenVariantV1) -> Result<Self, String> {
            let source = Self::current_query()?;
            let restricted = match variant {
                DiagnosticTokenVariantV1::ProductionTarget
                | DiagnosticTokenVariantV1::CallerPrimary => return Ok(source),
                DiagnosticTokenVariantV1::PrivilegeDisabled => {
                    return Self::restricted(source.raw(), DISABLE_MAX_PRIVILEGE, None);
                }
                DiagnosticTokenVariantV1::FullyRestrictedRestrictedCode => {
                    (DISABLE_MAX_PRIVILEGE, Some("S-1-5-12"))
                }
                DiagnosticTokenVariantV1::WriteRestrictedRestrictedCode => {
                    (DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED, Some("S-1-5-12"))
                }
                DiagnosticTokenVariantV1::WriteRestrictedWriteRestrictedCode => {
                    (DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED, Some("S-1-5-33"))
                }
            };
            Self::restricted(source.raw(), restricted.0, restricted.1)
        }

        fn current_query() -> Result<Self, String> {
            if let Some(arguments) = SERVICE_ARGUMENTS.get() {
                let mut handle = ptr::null_mut();
                if unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        arguments.source_token as HANDLE,
                        GetCurrentProcess(),
                        &raw mut handle,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                } == 0
                {
                    return Err(format!(
                        "duplicate transferred controller token: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                return Ok(Self(handle));
            }
            let mut handle = ptr::null_mut();
            let access = TOKEN_ASSIGN_PRIMARY
                | TOKEN_DUPLICATE
                | TOKEN_QUERY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID;
            if unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut handle) } == 0 {
                return Err(format!(
                    "open current process token: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self(handle))
        }

        fn process_query(process: HANDLE) -> Result<Self, String> {
            let mut handle = ptr::null_mut();
            if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut handle) } == 0 {
                return Err(format!(
                    "open suspended process token: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self(handle))
        }

        fn restricted(source: HANDLE, flags: u32, sid: Option<&str>) -> Result<Self, String> {
            let mut allocated_sid = ptr::null_mut();
            let mut sid_entry = SID_AND_ATTRIBUTES::default();
            let (count, entries) = if let Some(sid) = sid {
                let wide = nul_terminated(&sid.encode_utf16().collect::<Vec<_>>());
                if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut allocated_sid) } == 0 {
                    return Err(format!(
                        "parse restricting SID: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                sid_entry.Sid = allocated_sid;
                (1, &raw const sid_entry)
            } else {
                (0, ptr::null())
            };
            let mut token = ptr::null_mut();
            let created = unsafe {
                CreateRestrictedToken(
                    source,
                    flags,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    count,
                    entries,
                    &raw mut token,
                )
            };
            if !allocated_sid.is_null() {
                unsafe { LocalFree(allocated_sid as HLOCAL) };
            }
            if created == 0 {
                Err(format!(
                    "create diagnostic restricted token: {}",
                    std::io::Error::last_os_error()
                ))
            } else {
                Ok(Self(token))
            }
        }

        const fn raw(&self) -> HANDLE {
            self.0
        }
    }

    fn token_identity_for_plan(
        token: HANDLE,
        _variant: &DiagnosticTokenVariantV1,
    ) -> Result<TargetTokenIdentityV1, String> {
        let envelope = memcordon_windows_launch_core::query_token_envelope(token)?;
        Ok(TargetTokenIdentityV1 {
            envelope_sha256: memcordon_windows_launch_core::token_envelope_sha256(&envelope)?,
            authentication_id: envelope.authentication_id,
            session_id: envelope.session_id,
        })
    }

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    struct Pipe(HANDLE);

    fn target_aware_pipe_sddl(
        envelope: &memcordon_core::WindowsCallerTokenEnvelopeV1,
        variant: &DiagnosticTokenVariantV1,
    ) -> String {
        let mut trustees = vec![envelope.user_sid.as_str()];
        match variant {
            DiagnosticTokenVariantV1::FullyRestrictedRestrictedCode
            | DiagnosticTokenVariantV1::WriteRestrictedRestrictedCode => {
                trustees.push("S-1-5-12");
            }
            DiagnosticTokenVariantV1::WriteRestrictedWriteRestrictedCode => {
                trustees.push("S-1-5-33");
            }
            DiagnosticTokenVariantV1::ProductionTarget
            | DiagnosticTokenVariantV1::CallerPrimary
            | DiagnosticTokenVariantV1::PrivilegeDisabled => {}
        }
        trustees.sort_unstable();
        trustees.dedup();
        let mut sddl = String::from("O:SYG:SYD:P(A;;GA;;;SY)");
        for trustee in trustees {
            sddl.push_str(&format!("(A;;0x0012019b;;;{trustee})"));
        }
        sddl.push_str(&format!("S:(ML;;NW;;;{})", envelope.integrity_level));
        sddl
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LoaderReadyFrameV1 {
        kind: String,
        schema_version: u32,
        nonce: String,
        expected_desktop: String,
        #[serde(default)]
        bootstrap_identity: Option<memcordon_core::WindowsProcessIdentityV1>,
        #[serde(default)]
        process_envelope: Option<memcordon_core::WindowsCallerTokenEnvelopeV1>,
        #[serde(default)]
        process_snapshot: Option<LoaderReadyTokenSnapshotV1>,
    }

    struct LoaderReadyFrameEvidenceV1 {
        bootstrap_identity: Option<memcordon_core::WindowsProcessIdentityV1>,
        process_envelope: Option<memcordon_core::WindowsCallerTokenEnvelopeV1>,
        process_snapshot: Option<LoaderReadyTokenSnapshotV1>,
    }

    impl Pipe {
        fn create(name: &str, sddl: &str) -> Result<Self, String> {
            let name = OsStr::new(name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let security =
                NativeSecurityDescriptorV1::from_sddl(sddl).map_err(render_native_error)?;
            let attributes = security
                .security_attributes()
                .map_err(render_native_error)?;
            let handle = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    64 * 1024,
                    64 * 1024,
                    0,
                    &raw const attributes,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                Err(format!(
                    "create loader-ready pipe: {}",
                    std::io::Error::last_os_error()
                ))
            } else {
                Ok(Self(handle))
            }
        }

        fn authenticate(
            &self,
            expected_process_id: u32,
            process: HANDLE,
            nonce: &str,
            desktop: &str,
        ) -> Result<LoaderReadyFrameEvidenceV1, &'static str> {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                if unsafe { ConnectNamedPipe(self.0, ptr::null_mut()) } != 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(code) if code == ERROR_PIPE_CONNECTED as i32 => break,
                    Some(code) if code == ERROR_PIPE_LISTENING as i32 => {}
                    _ => return Err("pipe-connect-failed"),
                }
                if unsafe { WaitForSingleObject(process, 0) } == 0 {
                    return Err("pipe-peer-exited-before-connect");
                }
                if std::time::Instant::now() >= deadline {
                    return Err("pipe-connect-timeout");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut process_id = 0_u32;
            if unsafe { GetNamedPipeClientProcessId(self.0, &raw mut process_id) } == 0
                || process_id != expected_process_id
            {
                return Err("pipe-peer-mismatch");
            }
            let value =
                read_frame(self.0, process, deadline).map_err(|_| "loader-ready-read-failed")?;
            let frame: LoaderReadyFrameV1 =
                serde_json::from_value(value).map_err(|_| "loader-ready-schema-invalid")?;
            if frame.kind != "loader-ready"
                || frame.schema_version != BOOTSTRAP_SCHEMA_VERSION
                || frame.nonce != nonce
                || frame.expected_desktop != desktop
            {
                return Err("loader-ready-authentication-failed");
            }
            write_frame(
                self.0,
                &serde_json::json!({
                    "kind": "loader-control-release",
                    "schema_version": BOOTSTRAP_SCHEMA_VERSION,
                    "nonce": nonce,
                    "expected_desktop": desktop,
                }),
            )
            .map_err(|_| "loader-release-write-failed")?;
            if unsafe { FlushFileBuffers(self.0) } == 0 {
                return Err("loader-release-flush-failed");
            }
            Ok(LoaderReadyFrameEvidenceV1 {
                bootstrap_identity: frame.bootstrap_identity,
                process_envelope: frame.process_envelope,
                process_snapshot: frame.process_snapshot,
            })
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn read_frame(
        handle: HANDLE,
        process: HANDLE,
        deadline: std::time::Instant,
    ) -> Result<serde_json::Value, String> {
        let mut length = [0_u8; std::mem::size_of::<u32>()];
        read_exact(handle, process, deadline, &mut length)?;
        let length = usize::try_from(u32::from_le_bytes(length))
            .map_err(|_| String::from("loader-ready frame length overflow"))?;
        if length == 0 || length > FRAME_LIMIT_BYTES {
            return Err(String::from("loader-ready frame length is invalid"));
        }
        let mut payload = vec![0_u8; length];
        read_exact(handle, process, deadline, &mut payload)?;
        serde_json::from_slice(&payload)
            .map_err(|error| format!("decode loader-ready frame: {error}"))
    }

    fn write_frame(handle: HANDLE, value: &serde_json::Value) -> Result<(), String> {
        let payload = serde_json::to_vec(value)
            .map_err(|error| format!("encode loader-ready frame: {error}"))?;
        let length = u32::try_from(payload.len()).map_err(|_| String::from("frame too large"))?;
        write_all(handle, &length.to_le_bytes())?;
        write_all(handle, &payload)
    }

    fn read_exact(
        handle: HANDLE,
        process: HANDLE,
        deadline: std::time::Instant,
        mut target: &mut [u8],
    ) -> Result<(), String> {
        while !target.is_empty() {
            let mut transferred = 0_u32;
            if unsafe {
                ReadFile(
                    handle,
                    target.as_mut_ptr().cast(),
                    u32::try_from(target.len()).map_err(|_| String::from("read too large"))?,
                    &raw mut transferred,
                    ptr::null_mut(),
                )
            } == 0
            {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_DATA as i32) {
                    return Err(format!("read pipe: {error}"));
                }
                if unsafe { WaitForSingleObject(process, 0) } == 0 {
                    return Err(String::from("pipe peer exited before frame completed"));
                }
                if std::time::Instant::now() >= deadline {
                    return Err(String::from("loader-ready frame timed out"));
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let transferred = usize::try_from(transferred)
                .map_err(|_| String::from("pipe read length overflow"))?;
            if transferred == 0 {
                return Err(String::from("pipe closed before frame completed"));
            }
            target = &mut target[transferred..];
        }
        Ok(())
    }

    fn write_all(handle: HANDLE, mut source: &[u8]) -> Result<(), String> {
        while !source.is_empty() {
            let mut transferred = 0_u32;
            if unsafe {
                WriteFile(
                    handle,
                    source.as_ptr().cast(),
                    u32::try_from(source.len()).map_err(|_| String::from("write too large"))?,
                    &raw mut transferred,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(format!("write pipe: {}", std::io::Error::last_os_error()));
            }
            let transferred = usize::try_from(transferred)
                .map_err(|_| String::from("pipe write length overflow"))?;
            if transferred == 0 {
                return Err(String::from("pipe write made no progress"));
            }
            source = &source[transferred..];
        }
        Ok(())
    }
}
