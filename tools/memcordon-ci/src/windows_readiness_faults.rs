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
    .chain(
        ["frontend-loss", "service-loss", "worker-loss", "recovery"]
            .into_iter()
            .map(|scenario| CaseKey {
                family: "C-LIFETIME".into(),
                scenario: scenario.into(),
            }),
    )
    .chain([CaseKey {
        family: "W-REPLAY".into(),
        scenario: "public-recovery-after-loss".into(),
    }])
    .collect()
}

/// Publish the original installation lease handoff that the owned loss driver
/// consumes, anchored to the deadlines this installation was started with. The
/// loss driver refuses to renew cutoffs beyond these recorded values and
/// verifies the recorded owner against the selected installation.
#[cfg(windows)]
pub(crate) fn publish_original_lease(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<()> {
    let lease_root = config
        .output_directory
        .parent()
        .ok_or_else(|| CiError::Message("original Windows lease root absent".into()))?;
    std::fs::create_dir_all(lease_root)?;
    let owner = serde_json::json!({
        "format": "memcordon.consumer-readiness.windows-lease-owner",
        "revision": 2,
        "current": serde_json::to_value(config)?,
        "work_deadline_unix_millis": deadlines.work_deadline_unix_millis,
        "cleanup_deadline_unix_millis": deadlines.cleanup_deadline_unix_millis,
    });
    let original_deadlines = serde_json::json!({
        "format": "memcordon.consumer-readiness.windows-original-deadlines",
        "revision": 1,
        "work_deadline_unix_millis": deadlines.work_deadline_unix_millis,
        "cleanup_deadline_unix_millis": deadlines.cleanup_deadline_unix_millis,
    });
    for (name, value) in [
        ("windows-original-deadlines.json", &original_deadlines),
        ("windows-lease-owner.json", &owner),
    ] {
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        std::fs::write(lease_root.join(name), bytes)?;
    }
    Ok(())
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
pub(crate) fn observe_control_service_status() -> std::io::Result<serde_json::Value> {
    serde_json::to_value(native::control_service_status()?).map_err(std::io::Error::other)
}

#[cfg(windows)]
pub(crate) fn observe_launcher_service_status() -> std::io::Result<serde_json::Value> {
    serde_json::to_value(native::service_status(
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
    )?)
    .map_err(std::io::Error::other)
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessMember {
    pid: u32,
    birth: u64,
    parent_pid: Option<u32>,
    exited: bool,
}

#[cfg(any(windows, test))]
fn select_demand_workload_indices(
    census: &[ProcessMember],
    wrapped_wrapper: Option<(u32, u64)>,
    root: (u32, u64),
    child: (u32, u64),
    child_parent_pid: Option<u32>,
) -> std::result::Result<(usize, usize), &'static str> {
    if root.0 == 0 || root.1 == 0 || child.0 == 0 || child.1 == 0 || root.0 == child.0 {
        return Err("invalid loss workload root/descendant identity");
    }
    if child.1 < root.1 {
        return Err("loss descendant birth precedes root birth");
    }
    if child_parent_pid != Some(root.0) {
        return Err("loss descendant native parent differs from root");
    }
    let excluded_wrapper_index = if let Some((wrapper_pid, wrapper_birth)) = wrapped_wrapper {
        if wrapper_pid == 0 || wrapper_birth == 0 || wrapper_pid == root.0 || wrapper_pid == child.0
        {
            return Err("invalid wrapped loss fixture identity");
        }
        let mut matches = census.iter().enumerate().filter(|(_, member)| {
            member.pid == wrapper_pid && member.birth == wrapper_birth && !member.exited
        });
        let Some((index, _)) = matches.next() else {
            return Err("bound live loss fixture wrapper absent from image census");
        };
        if matches.next().is_some() {
            return Err("duplicate bound loss fixture wrapper in image census");
        }
        Some(index)
    } else {
        None
    };

    let mut remaining = Vec::new();
    for (index, member) in census.iter().enumerate() {
        if Some(index) == excluded_wrapper_index {
            continue;
        }
        remaining.push((index, *member));
    }
    if remaining.len() != 2 {
        return Err("loss workload image census does not contain exact root/descendant pair");
    }
    if remaining.iter().any(|(_, member)| member.exited) {
        return Err("loss workload member exited before external action");
    }
    let root_index = remaining
        .iter()
        .find(|(_, member)| member.pid == root.0 && member.birth == root.1)
        .map(|(index, _)| *index)
        .ok_or("loss workload census missing exact root identity")?;
    let child_index = remaining
        .iter()
        .find(|(_, member)| member.pid == child.0 && member.birth == child.1)
        .map(|(index, _)| *index)
        .ok_or("loss workload census missing exact descendant identity")?;
    if root_index == child_index {
        return Err("loss workload root and descendant collapsed to one member");
    }
    Ok((root_index, child_index))
}

#[cfg(any(windows, test))]
fn select_frontend_subject(
    candidates: &[ProcessMember],
    expected_parent_pid: Option<u32>,
    accepted_frontend: Option<(u32, u64)>,
) -> std::result::Result<usize, &'static str> {
    let mut matching = Vec::new();
    for (index, member) in candidates.iter().enumerate() {
        if member.exited || member.pid == 0 || member.birth == 0 {
            continue;
        }
        if expected_parent_pid.is_some() && member.parent_pid != expected_parent_pid {
            continue;
        }
        matching.push((index, *member));
    }
    if matching.len() != 1 {
        return Err("loss frontend subject selection is not uniquely bound");
    }
    let (index, selected) = matching[0];
    if let Some((accepted_pid, accepted_birth)) = accepted_frontend
        && (selected.pid != accepted_pid || selected.birth != accepted_birth)
    {
        return Err("loss frontend subject differs from accepted frontend identity");
    }
    Ok(index)
}

#[cfg(any(windows, test))]
fn verify_frontend_loss_exit(
    subject_status: u32,
    wrapper_status: Option<i32>,
) -> std::result::Result<(), &'static str> {
    if subject_status != 126 {
        return Err("held frontend subject did not exit with requested native status 126");
    }
    if wrapper_status != Some(126) {
        return Err("captured wrapper exit status disagrees with held frontend subject status 126");
    }
    Ok(())
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

    pub(super) fn control_service() -> io::Result<ControlServiceObservation> {
        let status = control_service_status()?;
        if status.process_id == 0
            || status.current_state != windows_sys::Win32::System::Services::SERVICE_RUNNING
        {
            return Err(io::Error::other(
                "owned control service is not live/running before native fault",
            ));
        }
        Ok(status)
    }

    pub(super) fn control_service_status() -> io::Result<ControlServiceObservation> {
        service_status(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)
    }

    #[allow(unsafe_code)] // Query-only SCM status; replacement process authority is separately held and measured.
    pub(super) fn service_status(service_name: &str) -> io::Result<ControlServiceObservation> {
        use windows_sys::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS,
            SERVICE_STATUS_PROCESS,
        };
        let name: Vec<_> = service_name.encode_utf16().chain(Some(0)).collect();
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
        Ok(ControlServiceObservation {
            name: service_name.into(),
            process_id: status.dwProcessId,
            current_state: status.dwCurrentState,
        })
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Recovery {
        schema_version: u32,
        provider_response: memcordon_core::WindowsProviderResponseV4,
        frontend_delivery: Option<memcordon_core::WindowsFrontendDeliveryV3>,
        terminal_authority_json: String,
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
            let lease_source = lease_root.join(source);
            let bytes = read(&lease_source, 16 * 1024 * 1024).map_err(|error| {
                CiError::Message(format!(
                    "original Windows lease source {source} is unreadable at {}: {error}",
                    lease_source.display()
                ))
            })?;
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
        input.workload_request = base.workload_request.clone();
        let contract = read(&input.workload_request, 256 * 1024)?;
        memcordon_core::workload_request::WorkloadRequestV1::parse(&contract)
            .map_err(|error| CiError::Message(error.to_string()))?;
        retain(
            &directory.join("workload-request.json"),
            &contract,
            &mut record.artifacts,
        )?;
        input.workload_request = directory.join("workload-request.json");
        input.descriptor.output_root = base
            .descriptor
            .output_root
            .parent()
            .ok_or_else(|| CiError::Message("candidate output parent absent".into()))?
            .join(&record.key.family)
            .join(&record.key.scenario);
        fs::create_dir_all(
            input
                .descriptor
                .output_root
                .parent()
                .ok_or_else(|| CiError::Message("owned loss output parent absent".into()))?,
        )?;
        fs::create_dir(&input.descriptor.output_root)?;
        input.descriptor.transcript = input.descriptor.output_root.join("fixture-events.bin");
        input.descriptor.start_gate = Some(format!(
            "{}-{}-{}",
            base.descriptor
                .start_gate
                .as_ref()
                .ok_or_else(|| CiError::Message("start gate absent".into()))?,
            record.key.family,
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
                "frontend_environment":crate::windows_consumer_readiness::fixture_environment::entries()?,
                "executable_sha256":if command.get_program() == config.fixture.path.as_os_str() { &config.fixture.sha256 } else { &config.cli.sha256 },"public_executable_sha256":config.cli.sha256,
                "program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
                "public_program_utf16":config.cli.path.as_os_str().encode_wide().collect::<Vec<_>>(),
                "argv_utf16":command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                "cwd_utf16":command.get_current_dir().ok_or_else(||CiError::Message("loss frontend native cwd absent".into()))?.as_os_str().encode_wide().collect::<Vec<_>>(),
                "environment_cleared":true
            }))?,
            &mut record.artifacts,
        )?;
        let wrapped_frontend = command.get_program() == config.fixture.path.as_os_str();
        let observation = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&observation);
        let action = Arc::new(Mutex::new(None));
        let captured_action = Arc::clone(&action);
        let family = Arc::new(Mutex::new(Vec::new()));
        let captured_family = Arc::clone(&family);
        let cli_subject_status = Arc::new(Mutex::new(None));
        let captured_subject_status = Arc::clone(&cli_subject_status);
        let fixture = config.fixture.path.clone();
        let cli = config.cli.path.clone();
        let agent = config.installed_agent.path.clone();
        let cli_sha256 = config.cli.sha256.clone();
        let agent_sha256 = config.installed_agent.sha256.clone();
        let cwd = config.output_directory.clone();
        let transcript = input.descriptor.transcript.clone();
        let report_for_callback = report.clone();
        let scenario = record.key.scenario.clone();
        let expected_provider = config.provider.clone();
        let budget = deadlines.work_budget(Duration::from_secs(120))?;
        let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
            command,
            budget,
            4 * 1024 * 1024,
            |mut command| command.spawn(),
            move |spawned_pid, _, _| {
                let deadline = deadlines.work.min(Instant::now() + Duration::from_secs(60));
                let wrapped_wrapper = if wrapped_frontend {
                    let wrapper =
                        match memcordon_testkit::windows_process_candidate_for_image_until(
                            &fixture,
                            spawned_pid,
                            deadline,
                        )? {
                            memcordon_testkit::WindowsProcessCandidate::Held(process) => process,
                            memcordon_testkit::WindowsProcessCandidate::CandidateUnavailable {
                                ..
                            } => {
                                return Err(io::Error::other(
                                    "spawned loss fixture wrapper unavailable for original custody",
                                ));
                            }
                        };
                    if wrapper.identity.birth == 0 || wrapper.has_exited()? {
                        return Err(io::Error::other(
                            "spawned loss fixture wrapper lacks live native identity",
                        ));
                    }
                    Some(wrapper)
                } else {
                    None
                };
                let wrapped_wrapper_id = wrapped_wrapper
                    .as_ref()
                    .map(|wrapper| {
                        let birth = u64::try_from(wrapper.identity.birth).map_err(|_| {
                            io::Error::other("loss fixture wrapper birth exceeds FILETIME width")
                        })?;
                        Ok::<(u32, u64), io::Error>((wrapper.identity.pid, birth))
                    })
                    .transpose()?;
                loop {
                    let held =
                        memcordon_testkit::windows_processes_for_image_until(&fixture, deadline)?;
                    let has_workload = held.iter().any(|process| {
                        wrapped_wrapper_id.is_none_or(|(wrapper_pid, wrapper_birth)| {
                            process.identity.pid != wrapper_pid
                                || process.identity.birth != u128::from(wrapper_birth)
                        })
                    });
                    if transcript.is_file() && has_workload {
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
                        if wrapped_wrapper
                            .as_ref()
                            .is_some_and(|wrapper| wrapper.has_exited().unwrap_or(true))
                        {
                            return Err(io::Error::other(
                                "wrapped loss fixture exited before demand phase",
                            ));
                        }
                        let held = memcordon_testkit::windows_processes_for_image_until(
                            &fixture, deadline,
                        )?;
                        let members = held
                            .iter()
                            .map(|process| {
                                let birth =
                                    u64::try_from(process.identity.birth).map_err(|_| {
                                        io::Error::other(
                                            "loss fixture process birth exceeds FILETIME width",
                                        )
                                    })?;
                                Ok::<ProcessMember, io::Error>(ProcessMember {
                                    pid: process.identity.pid,
                                    birth,
                                    parent_pid: None,
                                    exited: process.has_exited().unwrap_or(true),
                                })
                            })
                            .collect::<io::Result<Vec<_>>>()?;
                        let child_parent =
                            crate::windows_consumer_readiness::native::process_parents()?
                                .get(&child.process_id)
                                .copied();
                        if let Ok((root_idx, child_idx)) = select_demand_workload_indices(
                            &members,
                            wrapped_wrapper_id,
                            (target.process_id, target.creation_time_100ns),
                            (child.process_id, child.creation_time_100ns),
                            child_parent,
                        ) {
                            let workload_family: Vec<_> = held
                                .into_iter()
                                .enumerate()
                                .filter_map(|(index, process)| {
                                    (index == root_idx || index == child_idx).then_some(process)
                                })
                                .collect();
                            *captured_family
                                .lock()
                                .map_err(|_| io::Error::other("loss ownership poisoned"))? =
                                workload_family;
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
                        let accepted_terminal =
                            report_for_callback.with_extension("terminal-observation.json");
                        let accepted_path =
                            accepted_terminal.with_extension("accepted-observation.json");
                        let request_path = accepted_terminal.with_extension("provider-request.bin");
                        let accepted_frontend = if accepted_path.is_file() && request_path.is_file()
                        {
                            let accepted_bytes = read(
                                &accepted_path,
                                memcordon_core::MAX_WINDOWS_ACCEPTED_OBSERVATION_BYTES,
                            )
                            .map_err(io::Error::other)?;
                            let request_bytes =
                                read(&request_path, memcordon_core::WINDOWS_MAX_FRAME_BYTES)
                                    .map_err(io::Error::other)?;
                            memcordon_core::canonical_json::reject_duplicate_json_keys(
                                &accepted_bytes,
                            )
                            .map_err(io::Error::other)?;
                            let accepted: memcordon_core::WindowsWorkloadAcceptedV1 =
                                serde_json::from_slice(&accepted_bytes)
                                    .map_err(io::Error::other)?;
                            accepted.validate().map_err(io::Error::other)?;
                            if accepted.provider != observed.association.provider
                                || accepted.attempt_id
                                    != String::from(observed.association.attempt_id.clone())
                                || accepted.request_sha256
                                    != String::from(observed.association.request_sha256.clone())
                                || accepted.frontend.creation_time_100ns == 0
                            {
                                return Err(io::Error::other(
                                    "accepted frontend observation differs from live loss association",
                                ));
                            }
                            memcordon_core::validate_windows_accepted_observation(
                                &accepted,
                                &request_bytes,
                                &observed.association.provider,
                                &accepted.frontend,
                            )
                            .map_err(io::Error::other)?;
                            Some(accepted.frontend)
                        } else {
                            None
                        };
                        let subject = if let Some(wrapper) = wrapped_wrapper.as_ref() {
                            let action_deadline =
                                deadlines.work.min(Instant::now() + Duration::from_secs(30));
                            let direct_children =
                                wrapper.direct_children_for_image_until(&cli, action_deadline)?;
                            let candidates = direct_children
                                .iter()
                                .map(|process| {
                                    let birth =
                                        u64::try_from(process.identity.birth).map_err(|_| {
                                            io::Error::other(
                                                "loss frontend child birth exceeds FILETIME width",
                                            )
                                        })?;
                                    Ok::<ProcessMember, io::Error>(ProcessMember {
                                        pid: process.identity.pid,
                                        birth,
                                        parent_pid: Some(process.native_parent_process_id()?),
                                        exited: process.has_exited()?,
                                    })
                                })
                                .collect::<io::Result<Vec<_>>>()?;
                            let selected_index = select_frontend_subject(
                                &candidates,
                                Some(wrapper.identity.pid),
                                accepted_frontend
                                    .as_ref()
                                    .map(|id| (id.process_id, id.creation_time_100ns)),
                            )
                            .map_err(io::Error::other)?;
                            let selected = &candidates[selected_index];
                            let expected_frontend = WindowsProcessIdentityV1 {
                                process_id: selected.pid,
                                creation_time_100ns: selected.birth,
                            };
                            hold_process(
                                expected_frontend.process_id,
                                Some(&expected_frontend),
                                &cli,
                            )?
                        } else {
                            hold_process(spawned_pid, accepted_frontend.as_ref(), &cli)?
                        };
                        if subject.image_sha256 != cli_sha256 {
                            return Err(io::Error::other(
                                "held frontend image measurement changed",
                            ));
                        }
                        terminate(&subject)?;
                        let subject_status = recovery_wait(&subject)?;
                        if subject_status != 126 {
                            return Err(io::Error::other(
                                "held frontend subject did not exit with requested native status 126",
                            ));
                        }
                        *captured_subject_status
                            .lock()
                            .map_err(|_| io::Error::other("frontend subject status poisoned"))? =
                            Some(subject_status);
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
                    "control-service-loss"
                    | "service-loss"
                    | "recovery"
                    | "public-recovery-after-loss" => {
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
                    "attempt-worker-loss" | "worker-loss" => {
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
        let output = output.map_err(|error| {
            const CAPTURE_FAILURE_LIMIT: usize = 4096;
            let mut description = error.to_string();
            description.truncate(description.floor_char_boundary(CAPTURE_FAILURE_LIMIT));
            description
        });
        if let Err(description) = &output
            && let Err(retention_error) = retain(
                &directory.join("capture-failure.txt"),
                description.as_bytes(),
                &mut record.artifacts,
            )
        {
            return Err(CiError::Message(format!(
                "{description}; could not retain capture-failure.txt: {retention_error}"
            )));
        }
        let output = output.map_err(CiError::Message);
        let action = action
            .lock()
            .map_err(|_| CiError::Message("native loss action poisoned".into()))?;
        let action = action.as_ref().ok_or_else(|| {
            const MISSING_ACTION: &str =
                "external native loss operation did not complete on the held subject";
            match &output {
                Ok(_) => CiError::Message(MISSING_ACTION.into()),
                Err(error) => CiError::Message(format!("{MISSING_ACTION}: {error}")),
            }
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
        let original_terminal_path = report.with_extension("terminal-observation.json");
        if original_terminal_path.try_exists()? {
            let terminal = read(
                &original_terminal_path,
                3 * memcordon_core::WINDOWS_MAX_FRAME_BYTES,
            )?;
            if !terminal.is_empty() {
                memcordon_core::canonical_json::reject_duplicate_json_keys(&terminal)
                    .map_err(CiError::Message)?;
                retain(
                    &directory.join("original-terminal.json"),
                    &terminal,
                    &mut record.artifacts,
                )?;
            }
        }
        retain(
            &directory.join("provider-request.bin"),
            &request_bytes,
            &mut record.artifacts,
        )?;
        let request: memcordon_core::WindowsLaunchRequestV2 =
            serde_json::from_slice(&request_bytes)?;
        if crate::windows_causal_acceptance::sha256(&request_bytes)
            != String::from(observation.association.request_sha256.clone())
            || request.nonce != observation.live_nonce.as_deref().unwrap_or_default()
            || request.expected_provider_binding != observation.association.provider
            || request.environment
                != crate::windows_consumer_readiness::fixture_environment::entries()?
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
            let observed_native_status = if record.key.scenario == "frontend-loss" {
                let subject_status = cli_subject_status
                    .lock()
                    .map_err(|_| CiError::Message("frontend subject status poisoned".into()))?
                    .ok_or_else(|| {
                        CiError::Message(
                            "held frontend subject exit status was not observed".into(),
                        )
                    })?;
                verify_frontend_loss_exit(subject_status, output.status.code())
                    .map_err(|error| CiError::Message(error.into()))?;
                Some(i32::try_from(subject_status).map_err(|_| {
                    CiError::Message("held frontend subject exit status exceeds i32".into())
                })?)
            } else {
                output.status.code()
            };
            let exit_record = if wrapped_frontend {
                serde_json::json!({
                    "format": "memcordon.windows-native-loss-exit",
                    "revision": 1,
                    "target": config.target,
                    "executable_sha256": config.cli.sha256,
                    "native_status": observed_native_status,
                    "wrapper_executable_sha256": config.fixture.sha256,
                    "wrapper_native_status": output.status.code(),
                    "capture_complete": true
                })
            } else {
                serde_json::json!({
                    "format": "memcordon.windows-native-loss-exit",
                    "revision": 1,
                    "target": config.target,
                    "executable_sha256": config.cli.sha256,
                    "native_status": observed_native_status,
                    "capture_complete": true
                })
            };
            retain(
                &directory.join("native-exit.json"),
                &serde_json::to_vec(&exit_record)?,
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
                memcordon_core::result_v3::ResultV3::parse(&bytes).map_err(CiError::Message)?;
            if result.windows_attempt.as_ref() != Some(&observation.association)
                || result.outcome.kind == memcordon_core::execution_facts::OutcomeKindV1::Completed
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
            memcordon_core::WindowsProviderResponseV4::Terminal(receipt) => Some(receipt),
            memcordon_core::WindowsProviderResponseV4::Reject { rejection, .. } => {
                rejection.terminal_receipt()
            }
            _ => None,
        };
        if let Some(terminal) = terminal {
            if recovered.schema_version != 2
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
                memcordon_core::WindowsTerminalPayloadV3::Execution {
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
                    worker_loss_before_freeze: ["attempt-worker-loss", "worker-loss"]
                        .contains(&record.key.scenario.as_str()),
                },
            )?;
            drop(held);
        } else if let memcordon_core::WindowsProviderResponseV4::TerminalRetiredV2(retired) =
            &recovered.provider_response
        {
            if recovered.schema_version != 2
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
            || !memcordon_testkit::windows_processes_for_image_until(
                &config.fixture.path,
                deadlines.cleanup,
            )?
            .is_empty()
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

#[cfg(test)]
mod tests {
    use super::{
        ProcessMember, select_demand_workload_indices, select_frontend_subject,
        verify_frontend_loss_exit,
    };

    fn member(pid: u32, birth: u64, parent_pid: Option<u32>, exited: bool) -> ProcessMember {
        ProcessMember {
            pid,
            birth,
            parent_pid,
            exited,
        }
    }

    #[test]
    fn wrapped_four_role_census_excludes_only_bound_wrapper_and_keeps_strict_pair() {
        let census = [
            member(1000, 10, None, false),
            member(2000, 20, None, false),
            member(3000, 30, Some(2000), false),
        ];
        assert_eq!(
            select_demand_workload_indices(
                &census,
                Some((1000, 10)),
                (2000, 20),
                (3000, 30),
                Some(2000)
            ),
            Ok((1, 2))
        );

        let unwrapped = [
            member(2000, 20, None, false),
            member(3000, 30, Some(2000), false),
        ];
        assert_eq!(
            select_demand_workload_indices(&unwrapped, None, (2000, 20), (3000, 30), Some(2000)),
            Ok((0, 1))
        );
    }

    #[test]
    fn demand_census_rejects_wrong_wrapper_birth_extra_member_or_wrong_parent() {
        let census = [
            member(1000, 10, None, false),
            member(2000, 20, None, false),
            member(3000, 30, Some(2000), false),
        ];
        assert!(
            select_demand_workload_indices(
                &census,
                Some((1000, 99)),
                (2000, 20),
                (3000, 30),
                Some(2000)
            )
            .is_err()
        );
        assert!(
            select_demand_workload_indices(
                &census,
                Some((1000, 10)),
                (2000, 20),
                (3000, 30),
                Some(1000)
            )
            .is_err()
        );

        let extra_same_image = [
            member(1000, 10, None, false),
            member(2000, 20, None, false),
            member(3000, 30, Some(2000), false),
            member(4000, 40, None, false),
        ];
        assert!(
            select_demand_workload_indices(
                &extra_same_image,
                Some((1000, 10)),
                (2000, 20),
                (3000, 30),
                Some(2000)
            )
            .is_err()
        );

        let exited_wrapper = [
            member(1000, 10, None, true),
            member(2000, 20, None, false),
            member(3000, 30, Some(2000), false),
        ];
        assert!(
            select_demand_workload_indices(
                &exited_wrapper,
                Some((1000, 10)),
                (2000, 20),
                (3000, 30),
                Some(2000)
            )
            .is_err()
        );
    }

    #[test]
    fn frontend_subject_selection_requires_unique_live_direct_child_and_accepted_match() {
        let candidates = [member(1500, 15, Some(1000), false)];
        assert_eq!(
            select_frontend_subject(&candidates, Some(1000), Some((1500, 15))),
            Ok(0)
        );
        assert!(select_frontend_subject(&candidates, Some(9999), Some((1500, 15))).is_err());
        assert!(select_frontend_subject(&candidates, Some(1000), Some((1500, 99))).is_err());

        let ambiguous = [
            member(1500, 15, Some(1000), false),
            member(1501, 16, Some(1000), false),
        ];
        assert!(select_frontend_subject(&ambiguous, Some(1000), Some((1500, 15))).is_err());
        assert!(select_frontend_subject(&[], Some(1000), None).is_err());
    }

    #[test]
    fn frontend_loss_exit_requires_subject_126_and_wrapper_agreement() {
        assert_eq!(verify_frontend_loss_exit(126, Some(126)), Ok(()));
        assert!(verify_frontend_loss_exit(126, Some(1)).is_err());
        assert!(verify_frontend_loss_exit(126, Some(0)).is_err());
        assert!(verify_frontend_loss_exit(126, None).is_err());
        assert!(verify_frontend_loss_exit(1, Some(126)).is_err());
    }
}
