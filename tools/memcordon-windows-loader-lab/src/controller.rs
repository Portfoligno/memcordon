use crate::{
    artifact,
    scenario::{
        DiagnosticDesktopVariantV1, DiagnosticEnvironmentVariantV1, DiagnosticObserverV1,
        DiagnosticParentVariantV1, DiagnosticProfileVariantV1,
        DiagnosticSecurityDescriptorVariantV1, DiagnosticTokenVariantV1, ExternalCaptureBindingV1,
        ExternalCaptureSummaryV1, ExternalCaptureToolV1, HarnessStatusV1, LoaderLabRunV1,
        LoaderLabScenarioResultV1, LoaderLabScenarioV1, LoaderLabStageV1, TargetVariantV1,
        WindowsBuildIdentityV1,
    },
};
use memcordon_windows_launch_core::{ProductionLoaderPlanV1, RedactionClassV1};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime},
};

pub fn run(output: &Path, production_plan: &Path, bootstrap: &Path) -> Result<(), String> {
    artifact::ensure_empty_directory(output)?;
    let plan: ProductionLoaderPlanV1 = artifact::read_json(production_plan)?;
    let package_sha256 = artifact::file_sha256(bootstrap)?;
    if package_sha256 != plan.executable_sha256() {
        return Err(String::from(
            "bootstrap digest does not match the supplied production plan",
        ));
    }
    let run_id = run_id()?;
    let run_directory = output.join(&run_id);
    std::fs::create_dir(&run_directory)
        .map_err(|error| format!("create unique loader-lab run directory: {error}"))?;
    let output = run_directory.as_path();
    let namespace = format!("memcordon-loader-lab-{run_id}");
    let scenarios = staged_scenarios(&plan, bootstrap, &namespace)?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve loader lab executable: {error}"))?;
    let mut results: Vec<LoaderLabScenarioResultV1> = Vec::with_capacity(scenarios.len());
    let mut artifacts = Vec::new();
    let mut discriminating_pair = None;
    for (left_id, right_id) in comparison_pairs() {
        for scenario_id in [left_id, right_id] {
            if results
                .iter()
                .any(|result| result.scenario_id == scenario_id)
            {
                continue;
            }
            let scenario = scenarios
                .iter()
                .find(|scenario| scenario.scenario_id == scenario_id)
                .ok_or_else(|| format!("missing staged scenario {scenario_id}"))?;
            results.push(execute_scenario(
                output,
                &executable,
                scenario,
                &run_id,
                &mut artifacts,
            )?);
        }
        let left = results
            .iter()
            .find(|result| result.scenario_id == left_id)
            .ok_or_else(|| format!("missing staged result {left_id}"))?;
        let right = results
            .iter()
            .find(|result| result.scenario_id == right_id)
            .ok_or_else(|| format!("missing staged result {right_id}"))?;
        if scenario_succeeded(left) != scenario_succeeded(right) {
            discriminating_pair = Some((left_id, right_id));
            break;
        }
    }
    if let Some((left_id, right_id)) = discriminating_pair {
        let left = scenarios
            .iter()
            .find(|scenario| scenario.scenario_id == left_id)
            .ok_or_else(|| format!("missing discriminating scenario {left_id}"))?;
        let right = scenarios
            .iter()
            .find(|scenario| scenario.scenario_id == right_id)
            .ok_or_else(|| format!("missing discriminating scenario {right_id}"))?;
        for scenario in observer_scenarios(left, right)? {
            results.push(execute_scenario(
                output,
                &executable,
                &scenario,
                &run_id,
                &mut artifacts,
            )?);
        }
    }
    let plan_artifact = artifact::write_json_in(
        output,
        &output.join("launch-plan.json"),
        &plan,
        RedactionClassV1::RestrictedTrace,
    )?;
    artifacts.push(plan_artifact);
    let production = results
        .iter()
        .find(|result| result.production_equivalent)
        .ok_or_else(|| String::from("production-equivalent scenario result is absent"))?;
    artifacts.push(artifact::write_json_in(
        output,
        &output.join("production-result.json"),
        production,
        RedactionClassV1::RestrictedTrace,
    )?);
    artifacts.push(artifact::write_json_in(
        output,
        &output.join("token-snapshots.json"),
        &results
            .iter()
            .filter_map(|result| {
                result
                    .target_token_envelope_sha256
                    .as_ref()
                    .map(|envelope_sha256| {
                        serde_json::json!({
                        "scenario_id": result.scenario_id,
                        "envelope_sha256": envelope_sha256,
                            })
                    })
            })
            .collect::<Vec<_>>(),
        RedactionClassV1::RedactedSummary,
    )?);
    artifacts.push(artifact::write_json_in(
        output,
        &output.join("user-object-descriptors.json"),
        &serde_json::json!({
            "desktop_exact_name_sha256": sha256_text(&plan.desktop().exact_name),
            "window_station_sddl_sha256": sha256_text(
                &plan.desktop().window_station_security_descriptor_sddl,
            ),
            "desktop_sddl_sha256": sha256_text(
                &plan.desktop().desktop_security_descriptor_sddl,
            ),
            "desktop_live_descriptor_sha256": plan.desktop().security_descriptor_sha256,
            "process_sddl_sha256": plan.process_security_descriptor_sha256(),
            "thread_sddl_sha256": plan.thread_security_descriptor_sha256(),
            "job_sddl_sha256": plan.job_security_descriptor_sha256(),
            "live": results.iter().filter_map(|result| {
                result.suspended_process.as_ref().map(|evidence| serde_json::json!({
                    "scenario_id": result.scenario_id,
                    "window_station_descriptor_sha256": evidence.window_station_descriptor_sha256,
                    "desktop_descriptor_sha256": evidence.desktop_descriptor_sha256,
                }))
            }).collect::<Vec<_>>(),
        }),
        RedactionClassV1::RedactedSummary,
    )?);
    artifacts.push(artifact::write_json_in(
        output,
        &output.join("prepared-inputs.json"),
        &results
            .iter()
            .map(|result| {
                serde_json::json!({
                    "scenario_id": result.scenario_id,
                    "inputs": result.prepared_inputs,
                })
            })
            .collect::<Vec<_>>(),
        RedactionClassV1::RedactedSummary,
    )?);
    let events = results
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("serialize lab events: {error}"))?
        .join("\n");
    artifacts.push(artifact::write_text_in(
        output,
        &output.join("events.jsonl"),
        &events,
        "application/x-ndjson",
        RedactionClassV1::RestrictedTrace,
    )?);
    artifacts.push(artifact::write_json_in(
        output,
        &output.join("cleanup.json"),
        &results
            .iter()
            .map(|result| &result.cleanup)
            .collect::<Vec<_>>(),
        RedactionClassV1::RedactedSummary,
    )?);
    artifacts.push(artifact::write_text_in(
        output,
        &output.join("README.txt"),
        "Scenario failures are observations. A complete manifest and cleanup proof determine the harness exit code.",
        "text/plain",
        RedactionClassV1::Public,
    )?);

    let run = LoaderLabRunV1 {
        schema_version: 1,
        run_id,
        os: windows_build_identity()?,
        package_sha256,
        harness_status: HarnessStatusV1::Complete,
        scenarios: results,
        artifacts,
    };
    run.validate()?;
    for reference in &run.artifacts {
        artifact::verify_reference(output, reference)?;
    }
    artifact::write_json_in(
        output,
        &output.join("manifest.json"),
        &run,
        RedactionClassV1::RestrictedTrace,
    )?;
    Ok(())
}

pub fn attach_external(
    run_directory: &Path,
    external_traces: &[std::path::PathBuf],
    external_summaries: &[std::path::PathBuf],
) -> Result<(), String> {
    if external_traces.len() != 2 || external_summaries.len() != 2 {
        return Err(String::from(
            "external observer evidence requires one trace and typed summary for each side",
        ));
    }
    let manifest_path = run_directory.join("manifest.json");
    let mut run: LoaderLabRunV1 = artifact::read_json(&manifest_path)?;
    run.validate()?;
    let (left_id, right_id) = comparison_pairs()
        .into_iter()
        .find(|(left, right)| {
            let left = run
                .scenarios
                .iter()
                .find(|result| result.scenario_id == *left);
            let right = run
                .scenarios
                .iter()
                .find(|result| result.scenario_id == *right);
            matches!((left, right), (Some(left), Some(right)) if scenario_succeeded(left) != scenario_succeeded(right))
        })
        .ok_or_else(|| String::from("external observer evidence has no native discriminating pair"))?;

    for (ordinal, (side, source_id)) in [("left", left_id), ("right", right_id)]
        .into_iter()
        .enumerate()
    {
        let summary: ExternalCaptureSummaryV1 = artifact::read_json(&external_summaries[ordinal])?;
        let source_result_path = run_directory.join(format!("result-{source_id}.json"));
        let source_result_sha256 = artifact::file_sha256(&source_result_path)?;
        let source_result = run
            .scenarios
            .iter()
            .find(|result| result.scenario_id == source_id)
            .cloned()
            .ok_or_else(|| format!("external observer source result is absent: {source_id}"))?;
        let target_process_id = source_result
            .suspended_process
            .as_ref()
            .map(|evidence| evidence.process_identity.process_id)
            .ok_or_else(|| {
                format!("external observer source has no target identity: {source_id}")
            })?;
        let trace_sha256 = artifact::file_sha256(&external_traces[ordinal])?;
        summary.validate(ExternalCaptureBindingV1 {
            run_id: &run.run_id,
            side,
            source_scenario_id: source_id,
            source_result_sha256: &source_result_sha256,
            production_plan_sha256: source_result
                .launch_plan_sha256
                .as_deref()
                .ok_or_else(|| String::from("external observer source has no plan digest"))?,
            package_sha256: &run.package_sha256,
            trace_sha256: &trace_sha256,
            target_process_id,
        })?;

        let mut scenario: LoaderLabScenarioV1 =
            artifact::read_json(&run_directory.join(format!("scenario-{source_id}.json")))?;
        let observer = match summary.tool {
            ExternalCaptureToolV1::Procmon => DiagnosticObserverV1::ExternalProcmon,
            ExternalCaptureToolV1::Wpr => DiagnosticObserverV1::ExternalWpr,
        };
        let observer_name = match observer {
            DiagnosticObserverV1::ExternalProcmon => "external-procmon",
            DiagnosticObserverV1::ExternalWpr => "external-wpr",
            _ => return Err(String::from("invalid external observer kind")),
        };
        scenario.scenario_id = format!("stage-d-{observer_name}-{side}");
        scenario.stage = LoaderLabStageV1::DObserver;
        scenario.production_equivalent = false;
        scenario.perturbed = true;
        scenario.observer = observer.clone();
        scenario.validate(&scenario.production_plan_sha256)?;

        let trace_extension = external_traces[ordinal].extension().unwrap_or_default();
        let mut trace_destination = run_directory
            .join("external")
            .join(format!("{observer_name}-{side}"));
        trace_destination.set_extension(trace_extension);
        let trace_artifact = artifact::copy_file_in(
            run_directory,
            &external_traces[ordinal],
            &trace_destination,
            "application/octet-stream",
            RedactionClassV1::RestrictedTrace,
        )?;
        let summary_destination = run_directory
            .join("external")
            .join(format!("{observer_name}-{side}.json"));
        let summary_artifact = artifact::copy_file_in(
            run_directory,
            &external_summaries[ordinal],
            &summary_destination,
            "application/json",
            RedactionClassV1::RedactedSummary,
        )?;
        let scenario_path = run_directory.join(format!("scenario-{}.json", scenario.scenario_id));
        let scenario_artifact = artifact::write_json_in(
            run_directory,
            &scenario_path,
            &scenario,
            RedactionClassV1::RestrictedTrace,
        )?;

        let mut observed = source_result;
        observed.scenario_id = scenario.scenario_id.clone();
        observed.production_equivalent = false;
        observed.perturbed = true;
        observed.observer = observer.clone();
        observed.observer_evidence =
            Some(memcordon_windows_loader_lab::scenario::ObserverEvidenceV1 {
                kind: observer,
                completed: true,
                stable_code: None,
                event_count: summary.event_count,
                output_debug_string_count: 0,
                module_event_count: 0,
                exception_event_count: 0,
                event_codes: Vec::new(),
                session_started: summary.collector_session_started,
                provider_enabled: summary.provider_enabled,
                cleanup_complete: summary.collector_cleanup_complete,
            });
        observed.attachments.extend([
            scenario_artifact.clone(),
            trace_artifact.clone(),
            summary_artifact.clone(),
        ]);
        observed.validate_against(&scenario)?;
        let result_artifact = artifact::write_json_in(
            run_directory,
            &run_directory.join(format!("result-{}.json", observed.scenario_id)),
            &observed,
            RedactionClassV1::RestrictedTrace,
        )?;
        run.artifacts.extend([
            trace_artifact,
            summary_artifact,
            scenario_artifact,
            result_artifact,
        ]);
        run.scenarios.push(observed);
    }
    run.validate()?;
    for reference in &run.artifacts {
        artifact::verify_reference(run_directory, reference)?;
    }
    artifact::write_json_in(
        run_directory,
        &manifest_path,
        &run,
        RedactionClassV1::RestrictedTrace,
    )?;
    Ok(())
}

#[cfg(windows)]
fn windows_build_identity() -> Result<WindowsBuildIdentityV1, String> {
    #[repr(C)]
    struct RtlOsVersionInfo {
        size: u32,
        major_version: u32,
        minor_version: u32,
        build_number: u32,
        platform_id: u32,
        service_pack: [u16; 128],
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(version: *mut RtlOsVersionInfo) -> i32;
    }
    let mut version = RtlOsVersionInfo {
        size: u32::try_from(std::mem::size_of::<RtlOsVersionInfo>())
            .map_err(|_| String::from("Windows version structure size overflow"))?,
        major_version: 0,
        minor_version: 0,
        build_number: 0,
        platform_id: 0,
        service_pack: [0; 128],
    };
    let status = unsafe { RtlGetVersion(&raw mut version) };
    if status < 0 {
        return Err(format!("RtlGetVersion failed with NTSTATUS {status:#010x}"));
    }
    Ok(WindowsBuildIdentityV1 {
        os: String::from("windows"),
        architecture: String::from(std::env::consts::ARCH),
        major_version: version.major_version,
        minor_version: version.minor_version,
        build_number: version.build_number,
    })
}

#[cfg(not(windows))]
fn windows_build_identity() -> Result<WindowsBuildIdentityV1, String> {
    Err(String::from(
        "Windows build identity is available only on Windows",
    ))
}

fn execute_scenario(
    output: &Path,
    executable: &Path,
    scenario: &LoaderLabScenarioV1,
    run_id: &str,
    artifacts: &mut Vec<memcordon_windows_launch_core::ArtifactRefV1>,
) -> Result<LoaderLabScenarioResultV1, String> {
    let scenario_path = output.join(format!("scenario-{}.json", scenario.scenario_id));
    let result_path = output.join(format!("result-{}.json", scenario.scenario_id));
    let scenario_artifact = artifact::write_json_in(
        output,
        &scenario_path,
        &scenario,
        RedactionClassV1::RestrictedTrace,
    )?;
    run_spawner(executable, scenario, &scenario_path, &result_path, run_id)?;
    let mut result: LoaderLabScenarioResultV1 = artifact::read_json(&result_path)?;
    result.attachments.push(scenario_artifact.clone());
    result.validate_against(scenario)?;
    let result_artifact = artifact::write_json_in(
        output,
        &result_path,
        &result,
        RedactionClassV1::RestrictedTrace,
    )?;
    artifacts.extend([scenario_artifact, result_artifact]);
    Ok(result)
}

fn scenario_succeeded(result: &LoaderLabScenarioResultV1) -> bool {
    matches!(
        result.handshake,
        memcordon_windows_launch_core::HandshakeOutcomeV1::Authenticated { .. }
    ) && result.target_exit_code == Some(0)
}

fn comparison_pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("stage-a-production-replica", "stage-b-minimal-target"),
        (
            "stage-a-production-replica",
            "stage-c-qualification-caller-environment",
        ),
        (
            "stage-a-production-replica",
            "stage-c-target-derived-environment",
        ),
        ("stage-a-production-replica", "stage-c-controlled-desktop"),
        (
            "stage-a-production-replica",
            "stage-c-default-process-thread-descriptors",
        ),
        ("stage-a-production-replica", "stage-c-profile-loaded"),
        ("stage-a-production-replica", "stage-c-interactive-parent"),
        (
            "stage-a-production-replica",
            "stage-c-privilege-disabled-token",
        ),
        (
            "stage-c-full-restricted-s-1-5-12",
            "stage-c-write-restricted-s-1-5-12",
        ),
        (
            "stage-c-write-restricted-s-1-5-12",
            "stage-c-write-restricted-s-1-5-33",
        ),
    ]
}

fn observer_scenarios(
    left: &LoaderLabScenarioV1,
    right: &LoaderLabScenarioV1,
) -> Result<Vec<LoaderLabScenarioV1>, String> {
    let mut scenarios = Vec::new();
    for observer in [
        DiagnosticObserverV1::DebugEventPump,
        DiagnosticObserverV1::FullDebugger,
        DiagnosticObserverV1::LoaderSnaps,
        DiagnosticObserverV1::PassiveEtw,
    ] {
        let observer_name = match observer {
            DiagnosticObserverV1::DebugEventPump => "debug-event-pump",
            DiagnosticObserverV1::FullDebugger => "full-debugger",
            DiagnosticObserverV1::LoaderSnaps => "loader-snaps",
            DiagnosticObserverV1::PassiveEtw => "passive-etw",
            DiagnosticObserverV1::None
            | DiagnosticObserverV1::ExternalProcmon
            | DiagnosticObserverV1::ExternalWpr => {
                return Err(String::from("invalid in-process stage-D observer"));
            }
        };
        for (side, source) in [("left", left), ("right", right)] {
            let mut scenario = source.clone();
            scenario.scenario_id = format!("stage-d-{observer_name}-{side}");
            scenario.stage = LoaderLabStageV1::DObserver;
            scenario.production_equivalent = false;
            scenario.perturbed = true;
            scenario.observer = observer.clone();
            scenario.validate(&scenario.production_plan_sha256)?;
            scenarios.push(scenario);
        }
    }
    Ok(scenarios)
}

fn run_spawner(
    executable: &Path,
    scenario: &LoaderLabScenarioV1,
    scenario_path: &Path,
    result_path: &Path,
    run_id: &str,
) -> Result<(), String> {
    if scenario.parent_variant == DiagnosticParentVariantV1::InteractiveShell {
        let mut child = Command::new(executable)
            .arg("spawner")
            .arg("--scenario")
            .arg(scenario_path)
            .arg("--result")
            .arg(result_path)
            .spawn()
            .map_err(|error| format!("start interactive lab spawner: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    let kill = child.kill();
                    let wait = child.wait();
                    return Err(format!(
                        "poll interactive lab spawner for scenario {}: {error}; kill={kill:?}; wait={wait:?}",
                        scenario.scenario_id
                    ));
                }
            };
            if let Some(status) = status {
                return status.success().then_some(()).ok_or_else(|| {
                    format!(
                        "interactive lab spawner did not complete scenario {}",
                        scenario.scenario_id
                    )
                });
            }
            if Instant::now() >= deadline {
                let kill = child.kill();
                let wait = child.wait();
                return match (kill, wait) {
                    (Ok(()), Ok(_)) => Err(format!(
                        "interactive lab spawner timed out for scenario {}",
                        scenario.scenario_id
                    )),
                    (kill, wait) => Err(format!(
                        "interactive lab spawner timed out for scenario {}; kill={kill:?}; wait={wait:?}",
                        scenario.scenario_id
                    )),
                };
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    #[cfg(windows)]
    {
        windows_service::run(
            executable,
            scenario_path,
            result_path,
            run_id,
            &scenario.scenario_id,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (executable, scenario_path, result_path, run_id);
        Err(String::from(
            "LocalSystem loader laboratory scenarios are Windows-only",
        ))
    }
}

#[cfg(windows)]
mod windows_service {
    use std::{
        ffi::OsStr,
        os::windows::ffi::OsStrExt,
        path::Path,
        ptr,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
        OpenServiceW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CREATE_SERVICE,
        SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
        SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, StartServiceW,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_SERVICE_DOES_NOT_EXIST, FILETIME, GetLastError, HANDLE},
        Security::{
            TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
            TOKEN_QUERY,
        },
        System::Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcessToken,
        },
    };

    pub fn run(
        executable: &Path,
        scenario: &Path,
        result: &Path,
        run_id: &str,
        scenario_id: &str,
    ) -> Result<(), String> {
        let source = SourceToken::current()?;
        let source_process_id = unsafe { GetCurrentProcessId() };
        let source_creation_time = current_process_creation_time()?;
        let service_name = crate::spawner::lab_service_name(run_id, scenario_id);
        let mut service_name_wide = service_name.encode_utf16().collect::<Vec<_>>();
        service_name_wide.push(0);
        let arguments = [
            executable.as_os_str().encode_wide().collect::<Vec<_>>(),
            OsStr::new("service-spawner").encode_wide().collect(),
            OsStr::new("--service-run-id").encode_wide().collect(),
            run_id.encode_utf16().collect(),
            OsStr::new("--service-scenario-id").encode_wide().collect(),
            scenario_id.encode_utf16().collect(),
            OsStr::new("--scenario").encode_wide().collect(),
            scenario.as_os_str().encode_wide().collect(),
            OsStr::new("--result").encode_wide().collect(),
            result.as_os_str().encode_wide().collect(),
            OsStr::new("--source-process-id").encode_wide().collect(),
            source_process_id.to_string().encode_utf16().collect(),
            OsStr::new("--source-creation-time").encode_wide().collect(),
            source_creation_time.to_string().encode_utf16().collect(),
            OsStr::new("--source-token").encode_wide().collect(),
            (source.0 as usize).to_string().encode_utf16().collect(),
        ];
        let mut command_line = memcordon_core::encode_windows_command_line(&arguments);
        command_line.push(0);
        let manager =
            unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CREATE_SERVICE) };
        if manager.is_null() {
            return Err(format!(
                "open service manager for lab: {}",
                std::io::Error::last_os_error()
            ));
        }
        let manager = ServiceHandle(manager);
        let service = unsafe {
            CreateServiceW(
                manager.0,
                service_name_wide.as_ptr(),
                service_name_wide.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                command_line.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
        if service.is_null() {
            return Err(format!(
                "create isolated lab service: {}",
                std::io::Error::last_os_error()
            ));
        }
        let service = OwnedService::new(service);
        if unsafe { StartServiceW(service.handle.0, 0, ptr::null()) } == 0 {
            let primary = format!(
                "start isolated lab service: {}",
                std::io::Error::last_os_error()
            );
            return match delete_and_verify(service, &manager, &service_name_wide, false) {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(format!("{primary}; cleanup: {cleanup}")),
            };
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let mut status = SERVICE_STATUS_PROCESS::default();
            let mut required = 0_u32;
            if unsafe {
                QueryServiceStatusEx(
                    service.handle.0,
                    SC_STATUS_PROCESS_INFO,
                    (&raw mut status).cast(),
                    u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>())
                        .map_err(|_| String::from("lab service status size overflow"))?,
                    &raw mut required,
                )
            } == 0
            {
                let primary = format!(
                    "query isolated lab service: {}",
                    std::io::Error::last_os_error()
                );
                return match delete_and_verify(service, &manager, &service_name_wide, true) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(format!("{primary}; cleanup: {cleanup}")),
                };
            }
            if status.dwCurrentState == SERVICE_STOPPED {
                delete_and_verify(service, &manager, &service_name_wide, false)?;
                return (status.dwWin32ExitCode == 0).then_some(()).ok_or_else(|| {
                    format!(
                        "isolated lab service failed scenario {scenario_id}: {}",
                        status.dwWin32ExitCode
                    )
                });
            }
            if Instant::now() >= deadline {
                delete_and_verify(service, &manager, &service_name_wide, true)?;
                return Err(format!(
                    "isolated lab service timed out for scenario {scenario_id}"
                ));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn delete_and_verify(
        mut service: OwnedService,
        manager: &ServiceHandle,
        service_name: &[u16],
        stop: bool,
    ) -> Result<(), String> {
        if stop {
            service.stop_and_delete()?;
        } else {
            service.delete()?;
        }
        drop(service);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let reopened =
                unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
            if reopened.is_null() {
                let error = unsafe { GetLastError() };
                if error == ERROR_SERVICE_DOES_NOT_EXIST {
                    return Ok(());
                }
                return Err(format!(
                    "verify isolated lab service absence: {}",
                    std::io::Error::from_raw_os_error(error as i32)
                ));
            }
            unsafe { CloseServiceHandle(reopened) };
            if Instant::now() >= deadline {
                return Err(String::from("isolated lab service remained registered"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn current_process_creation_time() -> Result<u64, String> {
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        } == 0
        {
            return Err(format!(
                "read loader lab controller identity: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    struct SourceToken(HANDLE);

    impl SourceToken {
        fn current() -> Result<Self, String> {
            let mut handle = std::ptr::null_mut();
            let access = TOKEN_ASSIGN_PRIMARY
                | TOKEN_DUPLICATE
                | TOKEN_QUERY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID;
            if unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut handle) } == 0 {
                return Err(format!(
                    "open loader lab controller token: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self(handle))
        }
    }

    impl Drop for SourceToken {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    struct ServiceHandle(SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    struct OwnedService {
        handle: ServiceHandle,
        deleted: bool,
    }

    impl OwnedService {
        fn new(handle: SC_HANDLE) -> Self {
            Self {
                handle: ServiceHandle(handle),
                deleted: false,
            }
        }

        fn delete(&mut self) -> Result<(), String> {
            if self.deleted {
                return Ok(());
            }
            if unsafe { DeleteService(self.handle.0) } == 0 {
                return Err(format!(
                    "delete isolated lab service: {}",
                    std::io::Error::last_os_error()
                ));
            }
            self.deleted = true;
            Ok(())
        }

        fn stop_and_delete(&mut self) -> Result<(), String> {
            let mut status = SERVICE_STATUS::default();
            if unsafe { ControlService(self.handle.0, SERVICE_CONTROL_STOP, &raw mut status) } == 0
                && status.dwCurrentState != SERVICE_STOPPED
            {
                return Err(format!(
                    "stop isolated lab service: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let mut observed = SERVICE_STATUS_PROCESS::default();
                let mut required = 0_u32;
                if unsafe {
                    QueryServiceStatusEx(
                        self.handle.0,
                        SC_STATUS_PROCESS_INFO,
                        (&raw mut observed).cast(),
                        u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>())
                            .map_err(|_| String::from("lab service status size overflow"))?,
                        &raw mut required,
                    )
                } == 0
                {
                    return Err(format!(
                        "query stopped lab service: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                if observed.dwCurrentState == SERVICE_STOPPED {
                    return self.delete();
                }
                if Instant::now() >= deadline {
                    return Err(String::from("isolated lab service did not stop"));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }

    impl Drop for OwnedService {
        fn drop(&mut self) {
            if !self.deleted {
                let _ = unsafe { DeleteService(self.handle.0) };
            }
        }
    }
}

fn sha256_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn staged_scenarios(
    plan: &ProductionLoaderPlanV1,
    bootstrap: &Path,
    namespace: &str,
) -> Result<Vec<LoaderLabScenarioV1>, String> {
    let baseline = LoaderLabScenarioV1 {
        schema_version: 1,
        scenario_id: String::from("stage-a-production-replica"),
        stage: LoaderLabStageV1::AProductionReplica,
        production_equivalent: true,
        perturbed: false,
        plan: plan.clone(),
        target: TargetVariantV1::PackagedBootstrap,
        target_path: bootstrap.to_path_buf(),
        current_directory: bootstrap
            .parent()
            .ok_or_else(|| String::from("production bootstrap has no parent directory"))?
            .to_path_buf(),
        token_variant: DiagnosticTokenVariantV1::ProductionTarget,
        desktop_variant: DiagnosticDesktopVariantV1::ProductionPrivate,
        environment_variant: DiagnosticEnvironmentVariantV1::ProductionPrepared,
        security_descriptor_variant: DiagnosticSecurityDescriptorVariantV1::ProductionExact,
        profile_variant: DiagnosticProfileVariantV1::ProductionUnloaded,
        parent_variant: DiagnosticParentVariantV1::ProductionLauncher,
        observer: DiagnosticObserverV1::None,
        namespace: String::from(namespace),
        production_plan_sha256: String::from(plan.launch_plan_sha256()),
    };
    baseline.validate(plan.launch_plan_sha256())?;
    let mut minimal = baseline.clone();
    minimal.scenario_id = String::from("stage-b-minimal-target");
    minimal.stage = LoaderLabStageV1::BTargetBoundary;
    minimal.production_equivalent = false;
    minimal.perturbed = true;
    minimal.target = TargetVariantV1::MinimalSmoke;
    minimal.target_path = smoke_target_path()?;
    minimal.validate(plan.launch_plan_sha256())?;
    let mut candidates = vec![baseline, minimal];
    for (id, variant) in [
        (
            "stage-c-qualification-caller-environment",
            DiagnosticEnvironmentVariantV1::QualificationCaller,
        ),
        (
            "stage-c-target-derived-environment",
            DiagnosticEnvironmentVariantV1::TargetDerived,
        ),
    ] {
        let mut scenario = candidates[0].clone();
        scenario.scenario_id = String::from(id);
        scenario.stage = LoaderLabStageV1::COneFactor;
        scenario.production_equivalent = false;
        scenario.perturbed = true;
        scenario.environment_variant = variant;
        scenario.validate(plan.launch_plan_sha256())?;
        candidates.push(scenario);
    }
    let mut desktop = candidates[0].clone();
    desktop.scenario_id = String::from("stage-c-controlled-desktop");
    desktop.stage = LoaderLabStageV1::COneFactor;
    desktop.production_equivalent = false;
    desktop.perturbed = true;
    desktop.desktop_variant = DiagnosticDesktopVariantV1::ControlledTest;
    desktop.validate(plan.launch_plan_sha256())?;
    candidates.push(desktop);

    let mut descriptors = candidates[0].clone();
    descriptors.scenario_id = String::from("stage-c-default-process-thread-descriptors");
    descriptors.stage = LoaderLabStageV1::COneFactor;
    descriptors.production_equivalent = false;
    descriptors.perturbed = true;
    descriptors.security_descriptor_variant =
        DiagnosticSecurityDescriptorVariantV1::ProcessAndThreadDefaults;
    descriptors.validate(plan.launch_plan_sha256())?;
    candidates.push(descriptors);

    let mut profile = candidates[0].clone();
    profile.scenario_id = String::from("stage-c-profile-loaded");
    profile.stage = LoaderLabStageV1::COneFactor;
    profile.production_equivalent = false;
    profile.perturbed = true;
    profile.profile_variant = DiagnosticProfileVariantV1::LoadedForTarget;
    profile.validate(plan.launch_plan_sha256())?;
    candidates.push(profile);

    let mut parent = candidates[0].clone();
    parent.scenario_id = String::from("stage-c-interactive-parent");
    parent.stage = LoaderLabStageV1::COneFactor;
    parent.production_equivalent = false;
    parent.perturbed = true;
    parent.parent_variant = DiagnosticParentVariantV1::InteractiveShell;
    parent.validate(plan.launch_plan_sha256())?;
    candidates.push(parent);

    for (id, variant) in [
        (
            "stage-c-privilege-disabled-token",
            DiagnosticTokenVariantV1::PrivilegeDisabled,
        ),
        (
            "stage-c-full-restricted-s-1-5-12",
            DiagnosticTokenVariantV1::FullyRestrictedRestrictedCode,
        ),
        (
            "stage-c-write-restricted-s-1-5-12",
            DiagnosticTokenVariantV1::WriteRestrictedRestrictedCode,
        ),
        (
            "stage-c-write-restricted-s-1-5-33",
            DiagnosticTokenVariantV1::WriteRestrictedWriteRestrictedCode,
        ),
    ] {
        let mut scenario = candidates[0].clone();
        scenario.scenario_id = String::from(id);
        scenario.stage = LoaderLabStageV1::COneFactor;
        scenario.production_equivalent = false;
        scenario.perturbed = true;
        scenario.token_variant = variant;
        scenario.validate(plan.launch_plan_sha256())?;
        candidates.push(scenario);
    }
    Ok(candidates)
}

fn smoke_target_path() -> Result<std::path::PathBuf, String> {
    let mut path = std::env::current_exe()
        .map_err(|error| format!("resolve loader lab executable: {error}"))?;
    path.set_file_name(if cfg!(windows) {
        "memcordon-loader-smoke-target.exe"
    } else {
        "memcordon-loader-smoke-target"
    });
    Ok(path)
}

fn run_id() -> Result<String, String> {
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(duration.as_nanos().to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    Ok(hex::encode(hasher.finalize()))
}
