//! External native loss probes. Original failures and recovered retirement are
//! separate observations; recovery never turns an interrupted workload into a
//! naturally completed workload.
use crate::windows_consumer_readiness::CaseKey;
#[cfg(windows)]
use crate::windows_consumer_readiness::{CaseInput, SuiteInput};
#[cfg(windows)]
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LossAssessment {
    pub key: CaseKey,
    pub behavior: std::result::Result<(), String>,
    pub collection: std::result::Result<(), String>,
    pub retirement: std::result::Result<(), String>,
    pub artifacts: Vec<crate::windows_installed_cases::SelectedArtifact>,
}

pub fn required_loss_keys() -> Vec<CaseKey> {
    [
        "frontend-loss",
        "control-service-loss",
        "attempt-worker-loss",
    ]
    .into_iter()
    .map(|scenario| CaseKey {
        family: "W-RETIREMENT".into(),
        scenario: scenario.into(),
    })
    .collect()
}

pub fn accepted(records: &[LossAssessment]) -> bool {
    records.len() == required_loss_keys().len()
        && required_loss_keys()
            .iter()
            .all(|key| records.iter().filter(|record| &record.key == key).count() == 1)
        && records.iter().all(|record| {
            record.behavior.is_ok()
                && record.collection.is_ok()
                && record.retirement.is_ok()
                && !record.artifacts.is_empty()
        })
}

#[cfg(windows)]
pub(crate) fn run(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &Path,
    records: &mut Vec<LossAssessment>,
) -> Result<()> {
    run_until(
        config,
        input_path,
        records,
        crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default(),
    )
}

#[cfg(windows)]
pub(crate) fn run_until(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &Path,
    records: &mut Vec<LossAssessment>,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<()> {
    native::run(config, input_path, records, deadlines)
}

/// Query-only SCM observation shared by the two owned native loss controllers.
#[cfg(windows)]
pub(crate) fn observe_running_control_service() -> std::io::Result<serde_json::Value> {
    serde_json::to_value(native::control_service()?).map_err(std::io::Error::other)
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::command::CommandSpec;
    use crate::windows_consumer_readiness::{
        descriptor,
        native::{event_create, read, signal},
        public_command,
    };
    use crate::windows_owned_guardian::GuardianBaseline;
    use memcordon_core::{
        WindowsGuardianAttemptObservation, WindowsProcessIdentityV1, WindowsWorkerThreadIdentityV1,
    };
    use std::ffi::OsString;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    fn retain(
        path: &Path,
        bytes: &[u8],
        artifacts: &mut Vec<crate::windows_installed_cases::SelectedArtifact>,
    ) -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if read(path, bytes.len())? != bytes {
            return Err(CiError::Message(
                "loss artifact named-file readback differs".into(),
            ));
        }
        artifacts.push(crate::windows_installed_cases::SelectedArtifact {
            path: path.to_owned(),
            sha256: crate::windows_causal_acceptance::sha256(bytes),
        });
        Ok(())
    }

    struct HeldProcess {
        handle: OwnedHandle,
        identity: WindowsProcessIdentityV1,
        _image: std::fs::File,
        image_sha256: String,
    }

    #[derive(Serialize)]
    struct NativeLossAction {
        format: String,
        revision: u32,
        subject_role: String,
        image_sha256: String,
        subject_held_before_action: bool,
        action_completed: bool,
        kind: String,
        process: WindowsProcessIdentityV1,
        thread: Option<WindowsWorkerThreadIdentityV1>,
        native_requested_status: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        control_service: Option<ControlServiceObservation>,
    }
    #[derive(Serialize)]
    pub(super) struct ControlServiceObservation {
        name: String,
        process_id: u32,
        current_state: u32,
    }

    #[allow(unsafe_code)] // Exact held native process identity and image are checked before termination.
    fn hold_process(
        pid: u32,
        expected: Option<&WindowsProcessIdentityV1>,
        image: &Path,
    ) -> io::Result<HeldProcess> {
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
            QueryFullProcessImageNameW,
        };
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | 0x00100000,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        let mut birth = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exit = birth;
        let mut kernel = birth;
        let mut user = birth;
        if unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let identity = WindowsProcessIdentityV1 {
            process_id: pid,
            creation_time_100ns: u64::from(birth.dwLowDateTime)
                | (u64::from(birth.dwHighDateTime) << 32),
        };
        if expected.is_some_and(|expected| expected != &identity) {
            return Err(io::Error::other("held native process birth differs"));
        }
        let mut name = vec![0u16; 32_768];
        let mut length = name.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(handle.as_raw_handle(), 0, name.as_mut_ptr(), &mut length)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let actual =
            PathBuf::from(String::from_utf16(&name[..length as usize]).map_err(io::Error::other)?);
        if fs::canonicalize(actual)? != fs::canonicalize(image)? {
            return Err(io::Error::other(
                "held native process image differs from measured selection",
            ));
        }
        use std::os::windows::fs::OpenOptionsExt;
        let held_image = OpenOptions::new()
            .read(true)
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(image)?;
        let image_sha256 = crate::windows_causal_acceptance::sha256(
            &read(image, 512 * 1024 * 1024).map_err(io::Error::other)?,
        );
        Ok(HeldProcess {
            handle,
            identity,
            _image: held_image,
            image_sha256,
        })
    }

    #[allow(unsafe_code)] // Birth comes directly from the original Child creation handle before independent handle custody.
    fn hold_recovery_child(child: &std::process::Child, image: &Path) -> io::Result<HeldProcess> {
        let mut birth = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exit = birth;
        let mut kernel = birth;
        let mut user = birth;
        if unsafe {
            windows_sys::Win32::System::Threading::GetProcessTimes(
                child.as_raw_handle(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let identity = WindowsProcessIdentityV1 {
            process_id: child.id(),
            creation_time_100ns: u64::from(birth.dwLowDateTime)
                | (u64::from(birth.dwHighDateTime) << 32),
        };
        hold_process(child.id(), Some(&identity), image)
    }

    #[allow(unsafe_code)] // The independently retained handle must be signaled; exit status comes from that same kernel object.
    fn recovery_wait(process: &HeldProcess) -> io::Result<u32> {
        let handle = process.handle.as_raw_handle();
        if unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 0) } != 0 {
            return Err(io::Error::other(
                "original recovery process still live after Child wait",
            ));
        }
        let mut status = 0;
        if unsafe { windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut status) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(status)
    }

    fn settle_failed_recovery_creation(
        child: &mut std::process::Child,
        cutoff: Instant,
    ) -> io::Result<()> {
        let kill_error = child.kill().err();
        loop {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= cutoff {
                return Err(io::Error::other(format!(
                    "original recovery Child could not settle before original cleanup cutoff; kill error: {kill_error:?}"
                )));
            }
            std::thread::sleep(
                Duration::from_millis(10).min(cutoff.saturating_duration_since(Instant::now())),
            );
        }
    }

    #[allow(unsafe_code)] // Owned process is the previously measured live subject; wait proves its retirement.
    fn terminate(process: &HeldProcess) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if unsafe { TerminateProcess(process.handle.as_raw_handle(), 126) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { WaitForSingleObject(process.handle.as_raw_handle(), 30_000) } != 0 {
            return Err(io::Error::other(
                "externally terminated exact native subject did not retire",
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Thread is joined to its measured owning process and native birth before the deliberate fault.
    fn terminate_worker(
        process: &HeldProcess,
        expected: &WindowsWorkerThreadIdentityV1,
    ) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::{
            GetProcessIdOfThread, GetThreadTimes, OpenThread, THREAD_QUERY_LIMITED_INFORMATION,
            THREAD_TERMINATE, TerminateThread, WaitForSingleObject,
        };
        let handle = unsafe {
            OpenThread(
                THREAD_QUERY_LIMITED_INFORMATION | THREAD_TERMINATE | 0x00100000,
                0,
                expected.thread_id,
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        let mut birth = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exit = birth;
        let mut kernel = birth;
        let mut user = birth;
        if unsafe { GetThreadTimes(handle, &mut birth, &mut exit, &mut kernel, &mut user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = u64::from(birth.dwLowDateTime) | (u64::from(birth.dwHighDateTime) << 32);
        if actual != expected.creation_time_100ns
            || unsafe { GetProcessIdOfThread(handle) } != process.identity.process_id
        {
            return Err(io::Error::other(
                "worker thread native identity/owning process differs",
            ));
        }
        if unsafe { TerminateThread(handle, 126) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { WaitForSingleObject(owned.as_raw_handle(), 30_000) } != 0 {
            return Err(io::Error::other(
                "exact native worker thread did not retire",
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Query-only SCM handle ownership; process image/birth are separately held and measured.
    pub(super) fn control_service() -> io::Result<ControlServiceObservation> {
        use windows_sys::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS,
            SERVICE_STATUS_PROCESS,
        };
        let name: Vec<_> = memcordon_core::WINDOWS_CONTROL_SERVICE_NAME
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let manager =
            unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(io::Error::last_os_error());
        }
        let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            let error = io::Error::last_os_error();
            unsafe { CloseServiceHandle(manager) };
            return Err(error);
        }
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        let ok = unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        };
        let error = io::Error::last_os_error();
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        if ok == 0 {
            return Err(error);
        }
        if status.dwProcessId == 0
            || status.dwCurrentState != windows_sys::Win32::System::Services::SERVICE_RUNNING
        {
            return Err(io::Error::other(
                "owned control service is not live/running before native fault",
            ));
        }
        Ok(ControlServiceObservation {
            name: memcordon_core::WINDOWS_CONTROL_SERVICE_NAME.into(),
            process_id: status.dwProcessId,
            current_state: status.dwCurrentState,
        })
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Recovery {
        schema_version: u32,
        provider_response: memcordon_core::WindowsProviderResponseV3,
        frontend_delivery: Option<memcordon_core::WindowsTerminalDeliveryEvidenceV1>,
    }

    pub fn run(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input_path: &Path,
        records: &mut Vec<LossAssessment>,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<()> {
        let suite: SuiteInput = serde_json::from_slice(&read(input_path, 4 * 1024 * 1024)?)?;
        crate::windows_consumer_readiness::validate_suite(&suite)?;
        let base = suite
            .cases
            .iter()
            .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
            .ok_or_else(|| {
                CiError::Message("loss driver lacks owned ordinary contract template".into())
            })?;
        for key in required_loss_keys() {
            records.push(LossAssessment {
                key: key.clone(),
                behavior: Err("not executed".into()),
                collection: Err("not collected".into()),
                retirement: Err("not observed".into()),
                artifacts: Vec::new(),
            });
            let index = records.len() - 1;
            let result = run_one(config, base, &mut records[index], deadlines);
            if let Err(error) = result {
                records[index].behavior = Err(error.to_string());
            }
            if records[index].retirement.is_err() {
                break;
            }
        }
        if !accepted(records) {
            return Err(CiError::Message(
                "external native Windows loss suite incomplete or failed".into(),
            ));
        }
        Ok(())
    }

    fn run_one(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        base: &CaseInput,
        record: &mut LossAssessment,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<()> {
        let baseline = GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )?;
        let directory = config
            .output_directory
            .join(&record.key.family)
            .join(&record.key.scenario);
        fs::create_dir_all(&directory)?;
        let lease_root = config
            .output_directory
            .parent()
            .ok_or_else(|| CiError::Message("original Windows lease root absent".into()))?;
        for (source, name) in [
            (
                "windows-lease-owner.json",
                "original-windows-lease-owner.json",
            ),
            (
                "windows-original-deadlines.json",
                "original-windows-deadlines.json",
            ),
        ] {
            let bytes = read(&lease_root.join(source), 16 * 1024 * 1024)?;
            let original: serde_json::Value = serde_json::from_slice(&bytes)?;
            if original["work_deadline_unix_millis"] != deadlines.work_deadline_unix_millis
                || original["cleanup_deadline_unix_millis"]
                    != deadlines.cleanup_deadline_unix_millis
            {
                return Err(CiError::Message(
                    "loss source cannot renew original installation cutoffs".into(),
                ));
            }
            if source == "windows-lease-owner.json"
                && original["current"] != serde_json::to_value(config)?
            {
                return Err(CiError::Message(
                    "loss source differs from original selected installation".into(),
                ));
            }
            retain(&directory.join(name), &bytes, &mut record.artifacts)?;
        }
        let mut input = base.clone();
        input.key = record.key.clone();
        input.descriptor.case = descriptor::Case::HeldDemand;
        input.descriptor.challenge =
            crate::windows_consumer_readiness::native::random_challenge()?.to_vec();
        retain(
            &directory.join("challenge.bin"),
            &input.descriptor.challenge,
            &mut record.artifacts,
        )?;
        input.workload_contract = config
            .output_directory
            .join("W-JOINT")
            .join("ordinary")
            .join("requested-contract.json");
        let contract = read(&input.workload_contract, 256 * 1024)?;
        memcordon_core::workload_contract::WorkloadContractV1::parse(&contract)
            .map_err(CiError::Message)?;
        retain(
            &directory.join("requested-contract.json"),
            &contract,
            &mut record.artifacts,
        )?;
        input.workload_contract = directory.join("requested-contract.json");
        input.descriptor.output_root = base
            .descriptor
            .output_root
            .parent()
            .ok_or_else(|| CiError::Message("candidate output parent absent".into()))?
            .join(&record.key.scenario);
        fs::create_dir(&input.descriptor.output_root)?;
        input.descriptor.transcript = input.descriptor.output_root.join("fixture-events.bin");
        input.descriptor.start_gate = Some(format!(
            "{}-{}",
            base.descriptor
                .start_gate
                .as_ref()
                .ok_or_else(|| CiError::Message("start gate absent".into()))?,
            record.key.scenario
        ));
        input.descriptor_path = directory.join("input.json");
        retain(
            &input.descriptor_path,
            &serde_json::to_vec(&input.descriptor)?,
            &mut record.artifacts,
        )?;
        let gate = event_create(
            input
                .descriptor
                .start_gate
                .as_ref()
                .expect("owned start gate"),
        )?;
        let report = input.descriptor.output_root.join("frontend-result.json");
        let mut command = public_command(
            &config.cli.path,
            &config.fixture.path,
            &config.output_directory,
            &report,
            &input,
        )?
        .materialize()?;
        command.env_clear();
        use std::os::windows::ffi::OsStrExt;
        retain(
            &directory.join("native-invocation.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-native-loss-invocation","revision":1,"target":config.target,
                "executable_sha256":config.cli.sha256,"public_executable_sha256":config.cli.sha256,
                "program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
                "public_program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
                "argv_utf16":command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                "cwd_utf16":command.get_current_dir().ok_or_else(||CiError::Message("loss frontend native cwd absent".into()))?.as_os_str().encode_wide().collect::<Vec<_>>(),
                "environment_cleared":true
            }))?,
            &mut record.artifacts,
        )?;
        let observation = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&observation);
        let action = Arc::new(Mutex::new(None));
        let captured_action = Arc::clone(&action);
        let family = Arc::new(Mutex::new(Vec::new()));
        let captured_family = Arc::clone(&family);
        let fixture = config.fixture.path.clone();
        let cli = config.cli.path.clone();
        let agent = config.installed_agent.path.clone();
        let cli_sha256 = config.cli.sha256.clone();
        let agent_sha256 = config.installed_agent.sha256.clone();
        let cwd = config.output_directory.clone();
        let transcript = input.descriptor.transcript.clone();
        let scenario = record.key.scenario.clone();
        let expected_provider = config.provider.clone();
        let budget = deadlines.work_budget(Duration::from_secs(120))?;
        let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
            command,
            budget,
            4 * 1024 * 1024,
            |mut command| command.spawn(),
            move |frontend_pid, _, _| {
                let deadline = deadlines.work.min(Instant::now() + Duration::from_secs(60));
                loop {
                    let held = memcordon_testkit::windows_processes_for_image(&fixture)?;
                    if transcript.is_file() && !held.is_empty() {
                        *captured_family
                            .lock()
                            .map_err(|_| io::Error::other("loss ownership poisoned"))? = held;
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(
                            "loss fixture did not enter held native start barrier",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let guardian = baseline.hold_new_guardian().map_err(io::Error::other)?;
                let query_budget = deadlines
                    .work_budget(Duration::from_secs(30))
                    .map_err(io::Error::other)?;
                let mut query = CommandSpec::new(&cli, &cwd, query_budget)
                    .args([
                        OsString::from("__observe-windows-guardian"),
                        guardian.identity.process_id.to_string().into(),
                        guardian.identity.creation_time_100ns.to_string().into(),
                    ])
                    .materialize()
                    .map_err(io::Error::other)?;
                let output = memcordon_testkit::run_with_deadline_output_limit(
                    &mut query,
                    query_budget,
                    WindowsGuardianAttemptObservation::MAX_FRAME_BYTES,
                )
                .map_err(io::Error::other)?;
                if !output.status.success() {
                    return Err(io::Error::other(
                        "loss attempt live association query failed",
                    ));
                }
                let observed: WindowsGuardianAttemptObservation =
                    serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
                if !observed.is_consistent()
                    || observed.guardian_identity.process_id != guardian.identity.process_id
                    || observed.guardian_identity.creation_time_100ns
                        != guardian.identity.creation_time_100ns
                    || observed.association.provider != expected_provider
                {
                    return Err(io::Error::other(
                        "loss attempt association differs from independently held guardian",
                    ));
                }
                let target = observed
                    .live_target_identity
                    .as_ref()
                    .ok_or_else(|| io::Error::other("live released target identity absent"))?;
                let family = captured_family
                    .lock()
                    .map_err(|_| io::Error::other("loss ownership poisoned"))?;
                if !family.iter().any(|held| {
                    held.identity.pid == target.process_id
                        && held.identity.birth == u128::from(target.creation_time_100ns)
                        && !held.has_exited().unwrap_or(true)
                }) {
                    return Err(io::Error::other(
                        "authenticated released target differs from independently held native fixture identity",
                    ));
                }
                drop(family);
                *captured
                    .lock()
                    .map_err(|_| io::Error::other("loss association poisoned"))? =
                    Some(observed.clone());
                signal(&gate)?;
                // The target now creates one descendant and holds its stdin
                // barrier. Retain both native identities before the external
                // action; a mere root-start event cannot certify this phase.
                let deadline = deadlines.work.min(Instant::now() + Duration::from_secs(30));
                loop {
                    let bytes = read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?;
                    if let Some(child) = crate::windows_consumer_readiness::live_demand_child(
                        &bytes,
                        target.process_id,
                    )
                    .map_err(io::Error::other)?
                    {
                        let held = memcordon_testkit::windows_processes_for_image(&fixture)?;
                        if held.len() == 2
                            && held
                                .iter()
                                .all(|process| !process.has_exited().unwrap_or(true))
                            && held.iter().any(|process| {
                                process.identity.pid == target.process_id
                                    && process.identity.birth
                                        == u128::from(target.creation_time_100ns)
                            })
                            && held.iter().any(|process| {
                                process.identity.pid == child.process_id
                                    && process.identity.birth
                                        == u128::from(child.creation_time_100ns)
                            })
                            && child.creation_time_100ns >= target.creation_time_100ns
                            && crate::windows_consumer_readiness::native::process_parents()?
                                .get(&child.process_id)
                                == Some(&target.process_id)
                        {
                            *captured_family
                                .lock()
                                .map_err(|_| io::Error::other("loss ownership poisoned"))? = held;
                            break;
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(
                            "loss target/descendant did not reach held native demand phase",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let native_action = match scenario.as_str() {
                    "frontend-loss" => {
                        let subject = hold_process(frontend_pid, None, &cli)?;
                        if subject.image_sha256 != cli_sha256 {
                            return Err(io::Error::other(
                                "held frontend image measurement changed",
                            ));
                        }
                        terminate(&subject)?;
                        NativeLossAction {
                            format: "memcordon.windows-native-loss-action".into(),
                            revision: 1,
                            subject_role: "frontend".into(),
                            image_sha256: subject.image_sha256,
                            subject_held_before_action: true,
                            action_completed: true,
                            kind: "terminate-process".into(),
                            process: subject.identity,
                            thread: None,
                            native_requested_status: 126,
                            control_service: None,
                        }
                    }
                    "control-service-loss" => {
                        let subject = hold_process(control_service()?.process_id, None, &agent)?;
                        if subject.image_sha256 != agent_sha256 {
                            return Err(io::Error::other(
                                "held control-service image measurement changed",
                            ));
                        }
                        let scm = control_service()?;
                        if scm.process_id != subject.identity.process_id {
                            return Err(io::Error::other(
                                "owned control service changed after native subject hold",
                            ));
                        }
                        terminate(&subject)?;
                        NativeLossAction {
                            format: "memcordon.windows-native-loss-action".into(),
                            revision: 1,
                            subject_role: "control-service".into(),
                            image_sha256: subject.image_sha256,
                            subject_held_before_action: true,
                            action_completed: true,
                            kind: "terminate-process".into(),
                            process: subject.identity,
                            thread: None,
                            native_requested_status: 126,
                            control_service: Some(scm),
                        }
                    }
                    "attempt-worker-loss" => {
                        let identity =
                            observed.worker_process_identity.as_ref().ok_or_else(|| {
                                io::Error::other("live worker process metadata absent")
                            })?;
                        let worker = hold_process(identity.process_id, Some(identity), &agent)?;
                        if worker.image_sha256 != agent_sha256 {
                            return Err(io::Error::other(
                                "held attempt-worker image measurement changed",
                            ));
                        }
                        let thread = observed.worker_thread_identity.as_ref().ok_or_else(|| {
                            io::Error::other("live worker thread metadata absent")
                        })?;
                        terminate_worker(&worker, thread)?;
                        NativeLossAction {
                            format: "memcordon.windows-native-loss-action".into(),
                            revision: 1,
                            subject_role: "attempt-worker".into(),
                            image_sha256: worker.image_sha256,
                            subject_held_before_action: true,
                            action_completed: true,
                            kind: "terminate-thread".into(),
                            process: worker.identity,
                            thread: Some(*thread),
                            native_requested_status: 126,
                            control_service: None,
                        }
                    }
                    _ => return Err(io::Error::other("unknown owned loss scenario")),
                };
                *captured_action
                    .lock()
                    .map_err(|_| io::Error::other("native loss action poisoned"))? =
                    Some(native_action);
                Ok(())
            },
        );
        match &output {
            Err(memcordon_testkit::ProcessTestError::Timeout { stdout, stderr, .. })
            | Err(memcordon_testkit::ProcessTestError::OutputLimit { stdout, stderr, .. }) => {
                retain(
                    &directory.join("partial.stdout.bin"),
                    stdout,
                    &mut record.artifacts,
                )?;
                retain(
                    &directory.join("partial.stderr.bin"),
                    stderr,
                    &mut record.artifacts,
                )?;
            }
            _ => {}
        }
        if let Err(error) = &output {
            retain(
                &directory.join("capture-failure.txt"),
                error.to_string().as_bytes(),
                &mut record.artifacts,
            )?;
        }
        let output = output.map_err(|error| CiError::Message(error.to_string()));
        let action = action
            .lock()
            .map_err(|_| CiError::Message("native loss action poisoned".into()))?;
        let action = action.as_ref().ok_or_else(|| {
            CiError::Message(
                "external native loss operation did not complete on the held subject".into(),
            )
        })?;
        retain(
            &directory.join("native-loss-action.json"),
            &serde_json::to_vec(action)?,
            &mut record.artifacts,
        )?;
        let observation = observation
            .lock()
            .map_err(|_| CiError::Message("loss association poisoned".into()))?
            .clone()
            .ok_or_else(|| CiError::Message("loss has no native-bound association".into()))?;
        let request_path = report
            .with_extension("terminal-observation.json")
            .with_extension("provider-request.bin");
        let request_bytes = read(&request_path, memcordon_core::WINDOWS_MAX_FRAME_BYTES)?;
        retain(
            &directory.join("provider-request.bin"),
            &request_bytes,
            &mut record.artifacts,
        )?;
        let request: memcordon_core::WindowsLaunchRequestV1 =
            serde_json::from_slice(&request_bytes)?;
        if crate::windows_causal_acceptance::sha256(&request_bytes)
            != String::from(observation.association.request_sha256.clone())
            || request.nonce != observation.live_nonce.as_deref().unwrap_or_default()
            || request.expected_provider_binding != observation.association.provider
            || !request.environment.is_empty()
        {
            return Err(CiError::Message("pre-Launch request custody differs from actual loss attempt/provider/native environment".into()));
        }
        if observation.association.provider != config.provider {
            return Err(CiError::Message(
                "loss provider differs from measured installation".into(),
            ));
        }
        retain(
            &directory.join("live-observation.json"),
            &serde_json::to_vec(&observation)?,
            &mut record.artifacts,
        )?;
        if let Ok(output) = &output {
            retain(
                &directory.join("native-exit.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-native-loss-exit","revision":1,"target":config.target,
                    "executable_sha256":config.cli.sha256,"native_status":output.status.code(),"capture_complete":true
                }))?,
                &mut record.artifacts,
            )?;
            retain(
                &directory.join("stdout.bin"),
                &output.stdout,
                &mut record.artifacts,
            )?;
            retain(
                &directory.join("stderr.bin"),
                &output.stderr,
                &mut record.artifacts,
            )?;
            if output.status.success() {
                return Err(CiError::Message(
                    "externally lost held workload returned successful application status".into(),
                ));
            }
        }
        if report.try_exists()? {
            let bytes = read(&report, crate::windows_causal_acceptance::MAX_REPORT_BYTES)?;
            retain(
                &directory.join("original-result.json"),
                &bytes,
                &mut record.artifacts,
            )?;
            let result =
                memcordon_core::result_v1::ResultV1::parse(&bytes).map_err(CiError::Message)?;
            if result.provider_association.as_ref() != Some(&observation.association)
                || result.outcome.kind == memcordon_core::result_v1::OutcomeKindV1::Completed
            {
                return Err(CiError::Message(
                    "loss original result substituted another attempt or application origin".into(),
                ));
            }
        }
        if input.descriptor.transcript.try_exists()? {
            let bytes = read(&input.descriptor.transcript, 16 * 1024 * 1024)?;
            retain(
                &directory.join("fixture-events.bin"),
                &bytes,
                &mut record.artifacts,
            )?;
        }
        let nonce = observation
            .live_nonce
            .as_ref()
            .ok_or_else(|| CiError::Message("live recovery nonce absent".into()))?;
        let attempt = String::from(observation.association.attempt_id.clone());
        let request = String::from(observation.association.request_sha256.clone());
        let recovery_deadline = deadlines
            .cleanup
            .min(Instant::now() + Duration::from_secs(90));
        let unix_millis = || -> Result<u64> {
            u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .as_millis(),
            )
            .map_err(|error| CiError::Message(error.to_string()))
        };
        let recovery_deadline_unix_millis = unix_millis()?
            .checked_add(90000)
            .ok_or_else(|| CiError::Message("loss recovery cutoff overflow".into()))?
            .min(deadlines.cleanup_deadline_unix_millis);
        let mut recovered_output = None;
        for ordinal in 0..16 {
            let started_unix_millis = unix_millis()?;
            let budget = recovery_deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(10))
                .min(Duration::from_millis(
                    recovery_deadline_unix_millis.saturating_sub(started_unix_millis),
                ));
            if budget.is_zero() {
                break;
            }
            let mut recovery = CommandSpec::new(&config.cli.path, &config.output_directory, budget)
                .args([
                    OsString::from("windows-recover"),
                    "attempt".into(),
                    attempt.clone().into(),
                    nonce.clone().into(),
                    request.clone().into(),
                ])
                .materialize()?;
            recovery.env_clear();
            use std::os::windows::ffi::OsStrExt;
            let invocation = serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.windows-loss-recovery-command","revision":1,
                "target":config.target,"source_commit":config.source_commit,"executable_sha256":config.cli.sha256,
                "program_utf16":recovery.get_program().encode_wide().collect::<Vec<_>>(),
                "argv_utf16":recovery.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                "cwd_utf16":config.output_directory.as_os_str().encode_wide().collect::<Vec<_>>(),"environment_cleared":true,
                "work_deadline_unix_millis":deadlines.work_deadline_unix_millis,"cleanup_deadline_unix_millis":deadlines.cleanup_deadline_unix_millis,
                "started_unix_millis":started_unix_millis,"budget_millis":u64::try_from(budget.as_millis()).map_err(|error|CiError::Message(error.to_string()))?,"recovery_deadline_unix_millis":recovery_deadline_unix_millis}),
            )?;
            retain(
                &directory.join(format!("recovery-{ordinal}.invocation.json")),
                &invocation,
                &mut record.artifacts,
            )?;
            let held = Arc::new(Mutex::new(None));
            let spawned = Arc::clone(&held);
            let image = config.cli.path.clone();
            let result = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
                recovery,
                budget,
                4 * 1024 * 1024,
                move |mut command| {
                    let mut child = command.spawn()?;
                    let owned = match hold_recovery_child(&child, &image) {
                        Ok(owned) => owned,
                        Err(error) => {
                            settle_failed_recovery_creation(&mut child, deadlines.cleanup)?;
                            return Err(error);
                        }
                    };
                    match spawned.lock() {
                        Ok(mut slot) => *slot = Some(owned),
                        Err(_) => {
                            settle_failed_recovery_creation(&mut child, deadlines.cleanup)?;
                            return Err(io::Error::other("recovery child custody poisoned"));
                        }
                    }
                    Ok(child)
                },
                |_, _, _| Ok(()),
            );
            match result {
                Ok(output) => {
                    retain(
                        &directory.join(format!("recovery-{ordinal}.stdout.bin")),
                        &output.stdout,
                        &mut record.artifacts,
                    )?;
                    retain(
                        &directory.join(format!("recovery-{ordinal}.stderr.bin")),
                        &output.stderr,
                        &mut record.artifacts,
                    )?;
                    let held = held
                        .lock()
                        .map_err(|_| CiError::Message("recovery child custody poisoned".into()))?;
                    let held = held.as_ref().ok_or_else(|| {
                        CiError::Message("original recovery Child custody absent".into())
                    })?;
                    let native_status = recovery_wait(held)?;
                    if output.status.code().map(|status| status as u32) != Some(native_status) {
                        return Err(CiError::Message(
                            "original recovery Child and kernel wait disagree".into(),
                        ));
                    }
                    let creation = serde_json::to_vec(
                        &serde_json::json!({"format":"memcordon.windows-loss-recovery-creation","revision":1,
                        "invocation_sha256":crate::windows_causal_acceptance::sha256(&invocation),"process":held.identity,
                        "image_sha256":held.image_sha256,"creation_handle_retained":true}),
                    )?;
                    let process = serde_json::to_vec(
                        &serde_json::json!({"format":"memcordon.windows-loss-recovery-process","revision":1,
                        "invocation_sha256":crate::windows_causal_acceptance::sha256(&invocation),"process":held.identity,
                        "image_sha256":held.image_sha256,"native_status":native_status,"native_wait_completed":true,"capture_complete":true,
                        "stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),"stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr)}),
                    )?;
                    retain(
                        &directory.join(format!("recovery-{ordinal}.creation.json")),
                        &creation,
                        &mut record.artifacts,
                    )?;
                    retain(
                        &directory.join(format!("recovery-{ordinal}.process.json")),
                        &process,
                        &mut record.artifacts,
                    )?;
                    if output.status.success() {
                        retain(
                            &directory.join("recovery-invocation.json"),
                            &invocation,
                            &mut record.artifacts,
                        )?;
                        retain(
                            &directory.join("recovery-creation.json"),
                            &creation,
                            &mut record.artifacts,
                        )?;
                        retain(
                            &directory.join("recovery-process.json"),
                            &process,
                            &mut record.artifacts,
                        )?;
                        recovered_output = Some(output);
                        break;
                    }
                }
                Err(error) => {
                    retain(
                        &directory.join(format!("recovery-{ordinal}.failure.txt")),
                        error.to_string().as_bytes(),
                        &mut record.artifacts,
                    )?;
                }
            }
            if Instant::now() >= recovery_deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let recovered = recovered_output.ok_or_else(|| {
            CiError::Message(
                "public recovery could not prove bound retirement within its owned deadline".into(),
            )
        })?;
        retain(
            &directory.join("recovery.stdout.json"),
            &recovered.stdout,
            &mut record.artifacts,
        )?;
        retain(
            &directory.join("recovery.stderr.bin"),
            &recovered.stderr,
            &mut record.artifacts,
        )?;
        if !recovered.status.success() {
            return Err(CiError::Message(
                "public recovery denied or failed; retirement remains unresolved".into(),
            ));
        }
        let recovered: Recovery = serde_json::from_slice(&recovered.stdout)?;
        let terminal = match &recovered.provider_response {
            memcordon_core::WindowsProviderResponseV3::Terminal(receipt) => Some(receipt),
            memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } => {
                rejection.terminal_receipt()
            }
            _ => None,
        };
        if let Some(terminal) = terminal {
            if recovered.schema_version != 1
                || terminal.attempt_id != attempt
                || terminal.nonce != *nonce
                || terminal.request_sha256 != request
                || terminal.retirement_proof.provider_generation
                    != config.provider.generation.as_str()
                || terminal.validate_for_attempt().is_err()
            {
                return Err(CiError::Message(
                    "loss replay authority differs from native-held association".into(),
                ));
            }
            let delivery = recovered.frontend_delivery.as_ref().ok_or_else(|| {
                CiError::Message("loss replay did not confirm acknowledgement retirement".into())
            })?;
            if !delivery.is_consistent()
                || delivery.attempt_id != attempt
                || delivery.nonce != *nonce
                || delivery.request_sha256 != request
            {
                return Err(CiError::Message(
                    "loss replay delivery differs from native-held authority".into(),
                ));
            }
            if matches!(
                &terminal.payload,
                memcordon_core::WindowsTerminalPayloadV2::Execution {
                    outcome: memcordon_core::RunOutcome::Exited { .. },
                    ..
                }
            ) {
                return Err(CiError::Message(
                    "loss replay substituted naturally completed application origin".into(),
                ));
            }
            let held = family
                .lock()
                .map_err(|_| CiError::Message("loss ownership poisoned".into()))?;
            let identities = held
                .iter()
                .map(|process| {
                    Ok(WindowsProcessIdentityV1 {
                        process_id: process.identity.pid,
                        creation_time_100ns: u64::try_from(process.identity.birth).map_err(
                            |_| {
                                CiError::Message(
                                    "held loss process birth exceeds FILETIME width".into(),
                                )
                            },
                        )?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let root = observation
                .live_target_identity
                .clone()
                .ok_or_else(|| CiError::Message("released target identity missing".into()))?;
            crate::windows_causal_acceptance::validate_process_observation(
                &terminal.process_observation,
                &identities,
                &crate::windows_causal_acceptance::ObservationExpectation {
                    root,
                    attempt_id: attempt.clone(),
                    nonce: nonce.clone(),
                    request_sha256: request.clone(),
                    worker_loss_before_freeze: record.key.scenario == "attempt-worker-loss",
                },
            )?;
            drop(held);
        } else if let memcordon_core::WindowsProviderResponseV3::TerminalRetiredV2(retired) =
            &recovered.provider_response
        {
            if recovered.schema_version != 1
                || retired.provider_generation != config.provider.generation.as_str()
                || !retired.is_consistent_for(
                    &attempt,
                    nonce,
                    &request,
                    &retired.terminal_response_sha256,
                )
                || !directory.join("original-result.json").try_exists()?
                || recovered.frontend_delivery.is_some()
            {
                return Err(CiError::Message("already retired replay lacks preserved original result or exact native authority binding".into()));
            }
        } else {
            return Err(CiError::Message(
                "loss replay did not retain authenticated terminal authority/first cause".into(),
            ));
        }
        record.behavior = Ok(());
        record.collection = Ok(());
        let held = family
            .lock()
            .map_err(|_| CiError::Message("loss ownership poisoned".into()))?;
        if held.is_empty()
            || held
                .iter()
                .any(|process| !process.has_exited().unwrap_or(false))
            || !memcordon_testkit::windows_processes_for_image(&config.fixture.path)?.is_empty()
        {
            return Err(CiError::Message(
                "loss fixture native held family did not retire".into(),
            ));
        }
        let root = observation
            .live_target_identity
            .as_ref()
            .ok_or_else(|| CiError::Message("loss native root association absent".into()))?;
        if held.len() != 2 {
            return Err(CiError::Message(
                "loss native held root/descendant set differs".into(),
            ));
        }
        let processes = held
            .iter()
            .map(|process| {
                let birth = u64::try_from(process.identity.birth).map_err(|_| {
                    CiError::Message("loss native birth exceeds FILETIME width".into())
                })?;
                let is_root =
                    process.identity.pid == root.process_id && birth == root.creation_time_100ns;
                Ok(serde_json::json!({"pid":process.identity.pid,"birth":birth,
                "parent_pid":if is_root { None } else { Some(root.process_id) },
                "parent_birth":if is_root { None } else { Some(root.creation_time_100ns) },
                "held_before_action":true,"retirement_observed":true}))
            })
            .collect::<Result<Vec<_>>>()?;
        retain(
            &directory.join("native-family-retirement.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-native-family-retirement","revision":1,
                "attempt_id":attempt,"nonce":nonce,"request_sha256":request,
                "root_pid":root.process_id,"root_birth":root.creation_time_100ns,
                "processes":processes
            }))?,
            &mut record.artifacts,
        )?;
        GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )?;
        record.retirement = Ok(());
        output?;
        Ok(())
    }
}
