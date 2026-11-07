//! Same-thread native input readback before either measurement START.
use super::{Descriptor, descriptor::controller_start::descriptor_digest};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
};

fn token_input() -> io::Result<(serde_json::Value, [u8; 32])> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::{
        Security::TOKEN_QUERY,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let held = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
    let process = super::native_fixture_default_dacl::snapshot(held.as_raw_handle())?;
    // SDK GetCurrentThreadEffectiveToken pseudo handle, queried on this thread.
    let effective = memcordon_windows_launch_core::query_token_envelope(
        -6isize as windows_sys::Win32::Foundation::HANDLE,
    )
    .map_err(io::Error::other)?;
    if process.envelope() != &effective {
        return Err(io::Error::other(
            "matched effective/process token inputs differ",
        ));
    }
    let bytes = serde_json::to_vec(process.envelope()).map_err(io::Error::other)?;
    Ok((process.measurement(), descriptor_digest(&bytes)))
}
pub(super) fn token_hash(clock: &super::descriptor::ControlClock) -> io::Result<[u8; 32]> {
    super::listener_trace::live(clock)?;
    let (_, hash) = token_input()?;
    super::listener_trace::live(clock)?;
    Ok(hash)
}

fn environment() -> io::Result<Vec<memcordon_core::WindowsEnvironmentEntryV1>> {
    use windows_sys::Win32::System::Environment::{
        FreeEnvironmentStringsW, GetEnvironmentStringsW,
    };
    let raw = unsafe { GetEnvironmentStringsW() };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let read = (|| {
        let mut entries = Vec::new();
        let mut current = Vec::new();
        let mut previous_zero = false;
        // The documented native allocation ends in two zero units. Its pointer
        // is owned until FreeEnvironmentStringsW, never a caller-supplied span.
        for index in 0..32768 {
            let unit = unsafe { *raw.add(index) };
            if unit == 0 {
                if previous_zero {
                    return Ok(entries);
                }
                let skip = usize::from(current.first() == Some(&u16::from(b'=')));
                let split = current
                    .iter()
                    .enumerate()
                    .skip(skip)
                    .find(|(_, unit)| **unit == u16::from(b'='))
                    .map(|(index, _)| index)
                    .ok_or_else(|| {
                        io::Error::other("native matched environment entry malformed")
                    })?;
                entries.push(memcordon_core::WindowsEnvironmentEntryV1 {
                    name: current[..split].to_vec(),
                    value: current[split + 1..].to_vec(),
                });
                current.clear();
                previous_zero = true;
                if entries.len() > 128 {
                    return Err(io::Error::other(
                        "native matched environment count exceeds128",
                    ));
                }
            } else {
                previous_zero = false;
                current.push(unit)
            }
        }
        Err(io::Error::other("native matched environment exceeds64KiB"))
    })();
    let freed = if unsafe { FreeEnvironmentStringsW(raw) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    match read {
        Err(primary) => Err(super::matched_control_process::combine(primary, freed)),
        Ok(entries) => {
            freed?;
            Ok(entries)
        }
    }
}

fn object_security(
    handle: windows_sys::Win32::Foundation::HANDLE,
    cutoff: std::time::Instant,
) -> io::Result<serde_json::Value> {
    use windows_sys::Win32::Security::GetKernelObjectSecurity;
    let mut required = 0;
    super::matched_control_process::live(cutoff)?;
    let first =
        unsafe { GetKernelObjectSecurity(handle, 23, std::ptr::null_mut(), 0, &mut required) };
    let error = if first == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    if error.as_ref().and_then(io::Error::raw_os_error) != Some(122)
        || required == 0
        || required > 8192
    {
        return Err(error.unwrap_or_else(|| {
            io::Error::other("matched stdio security sizing contract differs")
        }));
    }
    let mut bytes = vec![0u8; required as usize];
    let capacity = required;
    super::matched_control_process::live(cutoff)?;
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            23,
            bytes.as_mut_ptr().cast(),
            capacity,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if required == 0 || required > capacity {
        return Err(io::Error::other("matched stdio security extent differs"));
    }
    bytes.truncate(required as usize);
    super::matched_control_process::live(cutoff)?;
    Ok(
        serde_json::json!({"security_information":23,"bytes":required,"sha256":descriptor_digest(&bytes)}),
    )
}

pub(super) fn capture(
    descriptor: &Descriptor,
    descriptor_sha256: [u8; 32],
    token: &[u8],
    deadline: std::time::Instant,
) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileType,
        },
        System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
    };
    let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(deadline)
        .map_err(io::Error::other)?;
    let captured = (|| {
        super::matched_control_process::live(deadline)?;
        let (started_qpc, frequency) =
            memcordon_platform::test_support::windows_performance_counter()?;
        let identity = super::native::current_identity()?;
        let (full_token, full_token_hash) = token_input()?;
        let cwd = std::env::current_dir()?;
        super::matched_control_process::live(deadline)?;
        let cwd_file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&cwd)?;
        let cwd_identity = memcordon_platform::test_support::windows_held_file_metadata(&cwd_file)?;
        if cwd_identity.attributes & 0x400 != 0 || cwd_identity.attributes & 0x10 == 0 {
            return Err(io::Error::other(
                "matched actual cwd is not an ordinary directory",
            ));
        }
        super::matched_control_process::live(deadline)?;
        let mut environment = environment()?;
        environment.sort_by(|left, right| left.name.cmp(&right.name));
        let declared = super::fixture_environment::entries()?;
        if memcordon_core::encode_windows_environment_block(&environment)
            .map_err(io::Error::other)?
            != memcordon_core::encode_windows_environment_block(&declared)
                .map_err(io::Error::other)?
        {
            return Err(io::Error::other(
                "matched actual environment differs from the explicit fixture declaration",
            ));
        }
        let mut streams = Vec::new();
        for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            super::matched_control_process::live(deadline)?;
            let handle = unsafe { GetStdHandle(kind) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::other("matched original standard stream missing"));
            }
            let file_type = unsafe { GetFileType(handle) };
            super::matched_control_process::live(deadline)?;
            let security = object_security(handle, deadline)?;
            super::matched_control_process::live(deadline)?;
            streams
                .push(serde_json::json!({"role":kind,"file_type":file_type,"security":security}));
        }
        let (finished_qpc, after_frequency) =
            memcordon_platform::test_support::windows_performance_counter()?;
        let clock = descriptor.control_clock.as_ref().expect("matched clock");
        if frequency != after_frequency
            || frequency != clock.qpc_frequency
            || finished_qpc < started_qpc
            || finished_qpc >= clock.work_cutoff_qpc
        {
            return Err(io::Error::other(
                "matched input readback clock differs or expired",
            ));
        }
        let cwd_identity = serde_json::json!({"volume_serial":cwd_identity.volume_serial,"file_index":cwd_identity.file_index,"attributes":cwd_identity.attributes});
        let bytes=serde_json::to_vec(&serde_json::json!({"revision":1,"binding":descriptor.matched_control,"descriptor_sha256":descriptor_sha256,"pid":identity.process_id,"birth":identity.creation_time_100ns,"token_sha256":full_token_hash,"partial_token_sha256":descriptor_digest(token),"token":full_token,"cwd_utf16":cwd.as_os_str().encode_wide().collect::<Vec<_>>(),"cwd_identity":cwd_identity,"environment":environment,"streams":streams,"started_qpc":started_qpc,"finished_qpc":finished_qpc,"qpc_frequency":frequency,"cutoff_qpc":clock.work_cutoff_qpc})).map_err(io::Error::other)?;
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::other("matched input readback exceeds64KiB"));
        }
        super::matched_control_process::live(deadline)?;
        let pending = descriptor
            .output_root
            .join("matched-input-readback.pending");
        let target = descriptor.output_root.join("matched-input-readback.json");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&pending)?;
        file.write_all(&bytes)?;
        super::matched_control_process::live(deadline)?;
        file.sync_all()?;
        super::matched_control_process::live(deadline)?;
        // A completed file is published in one no-replace native rename. The
        // broker never interprets a partially written final JSON pathname.
        let pending: Vec<u16> = pending.as_os_str().encode_wide().chain(Some(0)).collect();
        let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                pending.as_ptr(),
                target.as_ptr(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        super::matched_control_process::live(deadline)
    })();
    let finished = timer.finish().map_err(io::Error::other);
    match captured {
        Err(primary) => Err(super::matched_control_process::combine(primary, finished)),
        Ok(()) => {
            finished?;
            super::matched_control_process::live(deadline)
        }
    }
}
