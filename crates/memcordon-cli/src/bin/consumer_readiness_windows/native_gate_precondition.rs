//! Read-only comparison using the exact retained primary token, never authority.
use std::io::{self, Read, Write};
use std::os::windows::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt},
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::path::Path;
use std::time::{Duration, Instant};
use windows_sys::Win32::{Foundation::HANDLE, System::Threading::*};

fn remaining(
    input: &super::descriptor::gate_precondition::Input,
    watchdog: Instant,
) -> io::Result<Duration> {
    let mut now = 0i64;
    let mut frequency = 0i64;
    // SAFETY: scalar writable clock outputs have no external preconditions.
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut now) } == 0
        || unsafe {
            windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency)
        } == 0
        || frequency <= 0
        || frequency as u64 != input.qpc_frequency
        || now < 0
        || now as u64 >= input.work_cutoff_qpc
    {
        return Err(io::Error::other(
            "gate control original work cutoff expired or clock differs",
        ));
    }
    let nanos = u128::from(input.work_cutoff_qpc - now as u64) * 1_000_000_000
        / u128::from(input.qpc_frequency);
    let remaining = Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
        .min(watchdog.saturating_duration_since(Instant::now()));
    if remaining.is_zero() {
        return Err(io::Error::other("gate control original watchdog expired"));
    }
    Ok(remaining)
}

pub(super) fn run(
    source: HANDLE,
    token: HANDLE,
    startup: &STARTUPINFOEXW,
    environment: *const std::ffi::c_void,
    path: &Path,
    watchdog: Instant,
) -> io::Result<()> {
    let descriptor = super::read_descriptor(path)?;
    let input = descriptor
        .gate_precondition
        .as_ref()
        .ok_or_else(|| io::Error::other("gate control input missing"))?;
    input.validate().map_err(io::Error::other)?;
    remaining(input, watchdog)?;
    let source_before = super::native_fixture_default_dacl::snapshot(source)?;
    let selected_before = super::native_fixture_default_dacl::snapshot(token)?;
    let executable = std::env::current_exe()?;
    let argv = [
        executable.as_os_str().to_owned(),
        "consumer-readiness-windows".into(),
        "gate-precondition-child".into(),
        path.as_os_str().to_owned(),
        serde_json::to_string(selected_before.envelope())
            .map_err(io::Error::other)?
            .into(),
    ];
    let encoded: Vec<Vec<u16>> = argv.iter().map(|arg| arg.encode_wide().collect()).collect();
    let mut command = memcordon_core::encode_windows_command_line(&encoded);
    command.push(0);
    let image: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: same retained token, startup/three-handle list, environment and cwd
    // selection as the following real frontend. No gate capability is inherited.
    if unsafe {
        CreateProcessAsUserW(
            token,
            image.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            environment,
            std::ptr::null(),
            &startup.StartupInfo,
            &mut process,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both successful creation outputs transfer ownership exactly once.
    let held = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    let thread = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
    let observed = (|| -> io::Result<u32> {
        // SAFETY: sole held initial suspended thread.
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        let timeout = remaining(input, watchdog)?.min(Duration::from_secs(5));
        // SAFETY: original retained child only, bounded remaining work.
        if unsafe { WaitForSingleObject(held.as_raw_handle(), timeout.as_millis() as u32) } != 0 {
            return Err(io::Error::other(
                "gate control child did not settle within bounded original work",
            ));
        }
        let mut code = 0;
        // SAFETY: original held process has reached terminal state.
        if unsafe { GetExitCodeProcess(held.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(code)
    })();
    let code = match observed {
        Ok(code) => code,
        Err(original) => {
            // SAFETY: terminate only the retained original control child. Never
            // close an unsettled child and then proceed to the real frontend.
            unsafe { TerminateProcess(held.as_raw_handle(), 126) };
            let timeout = remaining(input, watchdog)
                .unwrap_or(Duration::ZERO)
                .min(Duration::from_secs(30));
            if unsafe { WaitForSingleObject(held.as_raw_handle(), timeout.as_millis() as u32) } != 0
            {
                std::process::abort();
            }
            return Err(original);
        }
    };
    let source_unchanged =
        super::native_fixture_default_dacl::snapshot(source)?.stable_eq(&source_before);
    let selected_unchanged =
        super::native_fixture_default_dacl::snapshot(token)?.stable_eq(&selected_before);
    let summary = serde_json::to_vec(&serde_json::json!({"format":"memcordon.fixture-gate-precondition-controller","revision":1,
        "diagnostic_only":true,"child_pid":process.dwProcessId,"child_exit_status":code,"child_settled":true,
        "same_retained_primary_token_input":true,"source_token_stable_identity_security_unchanged":source_unchanged,"selected_token_stable_identity_security_unchanged":selected_unchanged,
        "same_original_event_identity_proved":false,"acceptance_authority":false})).map_err(io::Error::other)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            descriptor
                .output_root
                .join("gate-precondition-control.json"),
        )?;
    output.write_all(&summary)?;
    output.sync_all()?;
    if code != 0 || !source_unchanged || !selected_unchanged {
        return Err(io::Error::other(
            "gate control infrastructure or original token stability failed",
        ));
    }
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(descriptor.output_root.join("gate-precondition-child.json"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > super::descriptor::gate_precondition::RECORD_BYTES as u64
    {
        return Err(io::Error::other(
            "gate control record is not a bounded ordinary file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((super::descriptor::gate_precondition::RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let observation = super::descriptor::gate_precondition::Observation::parse(&bytes)
        .map_err(io::Error::other)?;
    let name = descriptor
        .start_gate
        .as_ref()
        .ok_or_else(|| io::Error::other("gate control original name missing"))?;
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    observation
        .validate(
            input,
            &serde_json::to_value(descriptor.case).map_err(io::Error::other)?,
            &super::descriptor::gate_precondition::sha256(&descriptor.challenge),
            &super::descriptor::gate_precondition::sha256(&name_bytes),
            selected_before.envelope(),
        )
        .map_err(io::Error::other)?;
    remaining(input, watchdog)?;
    Ok(())
}
