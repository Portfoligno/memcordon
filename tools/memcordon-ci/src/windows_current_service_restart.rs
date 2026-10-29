//! Actual current control-service restart followed by a fresh installed request.
use super::{HeldProcess, fixture_environment, write_new};
use crate::{
    CiError, Result,
    windows_installed_cases::{InstalledWindowsPayload, WindowsLeaseDeadlines},
};
use std::{
    fs, io,
    os::windows::ffi::{OsStrExt, OsStringExt},
    time::{Duration, Instant},
};
use windows_sys::Win32::System::Services::*;

struct Service {
    manager: SC_HANDLE,
    service: SC_HANDLE,
}
#[derive(serde::Serialize)]
struct Status {
    process_id: u32,
    current_state: u32,
}
impl Service {
    #[allow(unsafe_code)] // Native SCM references are retained until the exact restart completes.
    fn open() -> io::Result<Self> {
        let manager =
            unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(io::Error::last_os_error());
        }
        let name = memcordon_core::WINDOWS_CONTROL_SERVICE_NAME
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let service = unsafe {
            OpenServiceW(
                manager,
                name.as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START,
            )
        };
        if service.is_null() {
            let error = io::Error::last_os_error();
            unsafe { CloseServiceHandle(manager) };
            return Err(error);
        }
        Ok(Self { manager, service })
    }
    #[allow(unsafe_code)] // Query-only SCM state from this retained service reference.
    fn status(&self) -> io::Result<Status> {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        if unsafe {
            QueryServiceStatusEx(
                self.service,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Status {
            process_id: status.dwProcessId,
            current_state: status.dwCurrentState,
        })
    }
    #[allow(unsafe_code)] // Sends STOP only through the exact SCM service owner opened above.
    fn stop(&self) -> io::Result<()> {
        let mut status = SERVICE_STATUS::default();
        if unsafe { ControlService(self.service, SERVICE_CONTROL_STOP, &mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[allow(unsafe_code)] // Starts only the same existing selected control-service registration.
    fn start(&self) -> io::Result<()> {
        if unsafe { StartServiceW(self.service, 0, std::ptr::null()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for Service {
    #[allow(unsafe_code)] // Releases exactly the two SCM references owned by this object.
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.service);
            CloseServiceHandle(self.manager);
        }
    }
}
#[allow(unsafe_code)] // Query-only image path from an original held process, never a PID reopen.
pub(super) fn image(process: &HeldProcess) -> io::Result<Vec<u16>> {
    let mut buffer = vec![0u16; 32768];
    let mut count = buffer.len() as u32;
    if unsafe {
        windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
            process.0,
            0,
            buffer.as_mut_ptr(),
            &mut count,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(count as usize);
    Ok(buffer)
}

pub(super) fn run(
    config: &InstalledWindowsPayload,
    deadlines: WindowsLeaseDeadlines,
) -> Result<()> {
    let cutoff = deadlines.work;
    let directory = config
        .output_directory
        .join("current-controls/service-restart-fresh-request");
    fs::create_dir(&directory)?;
    let _selected = crate::windows_readiness_adapter::hold_artifact(
        &config.installed_agent.path,
        Some(&config.installed_agent.sha256),
        512 * 1024 * 1024,
    )?;
    let service = Service::open()?;
    let before = service.status()?;
    if before.current_state != SERVICE_RUNNING || before.process_id == 0 {
        return Err(CiError::Message(
            "current control service not running before owned restart".into(),
        ));
    }
    let original = HeldProcess::open(before.process_id)?;
    let original_identity = original.identity(before.process_id)?;
    let expected_image = config
        .installed_agent
        .path
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    if image(&original)? != expected_image
        || original.wait()? != windows_sys::Win32::Foundation::WAIT_TIMEOUT
    {
        return Err(CiError::Message(
            "original SCM process differs from selected native image".into(),
        ));
    }
    service.stop()?;
    loop {
        let status = service.status()?;
        if status.current_state == SERVICE_STOPPED
            && status.process_id == 0
            && original.wait()? == windows_sys::Win32::Foundation::WAIT_OBJECT_0
        {
            break;
        }
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original control service failed to retire under original cutoff".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    service.start()?;
    let (after, replacement, replacement_identity) = loop {
        let status = service.status()?;
        if status.current_state == SERVICE_RUNNING && status.process_id != 0 {
            let held = HeldProcess::open(status.process_id)?;
            let identity = held.identity(status.process_id)?;
            if identity == original_identity {
                return Err(CiError::Message(
                    "SCM restart reused original live native identity".into(),
                ));
            }
            if image(&held)? != expected_image
                || held.wait()? != windows_sys::Win32::Foundation::WAIT_TIMEOUT
            {
                return Err(CiError::Message(
                    "replacement SCM owner differs from current measured image".into(),
                ));
            }
            break (status, held, identity);
        }
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "current control service restart exhausted original cutoff".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let prior = config
        .output_directory
        .join("current-controls/after-release");
    write_new(
        &directory.join("service.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.windows-current-service-restart","revision":1,"service_name":memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,"api":"OpenSCManagerW/OpenServiceW/QueryServiceStatusEx/ControlService/StartServiceW","before":before,"after":after,"original":original_identity,"replacement":replacement_identity,"original_wait":original.wait()?,"replacement_wait":replacement.wait()?,"image_utf16":expected_image,"image_sha256":config.installed_agent.sha256,"prior_result_bytes":fs::read(prior.join("result.json"))?,"prior_terminal_bytes":fs::read(prior.join("terminal.json"))?,"work_deadline_unix_millis":deadlines.work_deadline_unix_millis,"cleanup_deadline_unix_millis":deadlines.cleanup_deadline_unix_millis}),
        )?,
    )?;
    let request = directory.join("request.json");
    let report = directory.join("result.json");
    let terminal = directory.join("terminal.json");
    write_new(&request,br#"{"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}"#)?;
    let environment = fixture_environment::entries()?
        .into_iter()
        .filter(|entry| entry.name.first() != Some(&u16::from(b'=')))
        .collect::<Vec<_>>();
    let mut command = std::process::Command::new(&config.cli.path);
    command.env_clear();
    for entry in &environment {
        command.env(
            std::ffi::OsString::from_wide(&entry.name),
            std::ffi::OsString::from_wide(&entry.value),
        );
    }
    command
        .current_dir(&directory)
        .args(["--boundary", "sealed", "--workload-request"])
        .arg(&request)
        .args(["--report-format", "result-v3", "--report"])
        .arg(&report)
        .arg("--windows-terminal-observation")
        .arg(&terminal)
        .arg("--")
        .arg(&config.fixture.path)
        .args(["exit", "--code", "0"])
        .stdin(std::process::Stdio::null());
    let budget = deadlines.work_budget(Duration::from_secs(90))?;
    write_new(
        &directory.join("invocation.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.windows-current-control-invocation","revision":1,"scenario":"service-restart-fresh-request","program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),"argv_utf16":command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),"cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"cli_sha256":config.cli.sha256,"fixture_sha256":config.fixture.sha256,"work_deadline_unix_millis":deadlines.work_deadline_unix_millis,"cleanup_deadline_unix_millis":deadlines.cleanup_deadline_unix_millis,"environment_cleared":true,"frontend_environment":environment}),
        )?,
    )?;
    let output =
        memcordon_testkit::run_with_deadline_output_limit(&mut command, budget, 4 * 1024 * 1024)
            .map_err(|error| CiError::Message(error.to_string()))?;
    write_new(&directory.join("stdout.bin"), &output.stdout)?;
    write_new(&directory.join("stderr.bin"), &output.stderr)?;
    write_new(
        &directory.join("wait.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.windows-current-control-wait","revision":1,"native_status":output.status.code(),"stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),"stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr)}),
        )?,
    )?;
    let result = memcordon_core::ResultV3::parse(&fs::read(&report)?)
        .map_err(|error| CiError::Message(error.to_string()))?;
    if !output.status.success()
        || !output.stdout.is_empty()
        || result.release != memcordon_core::result_v3::ReleaseKnowledgeV3::Released
        || result.outcome.wrapper_status != 0
        || result.cleanup.state != memcordon_core::execution_facts::CleanupStateV1::Complete
    {
        return Err(CiError::Message(
            "fresh current request failed after actual service restart".into(),
        ));
    }
    Ok(())
}
