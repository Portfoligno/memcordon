use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsTokenRestricted, TOKEN_QUERY, TokenElevation, TokenIntegrityLevel,
    TokenUser,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, GetCurrentProcess, OpenProcessToken,
};

fn wide(value: &Path) -> Vec<u16> {
    value.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub struct NamedPipeProducts {
    pub server_received: Vec<u8>,
    pub client_received: Vec<u8>,
}

pub fn named_pipe_exchange(challenge: &[u8]) -> io::Result<NamedPipeProducts> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    let name = Path::new(r"\\.\pipe")
        .join(std::process::id().to_string())
        .with_extension("memcordon-readiness");
    let name = wide(&name);
    let sddl: Vec<u16> = "D:P(A;;GA;;;OW)(A;;GRGW;;;RC)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut security = std::ptr::null_mut();
    // SAFETY: terminated SDDL and output pointer remain live for the call.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut security,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security,
        bInheritHandle: 0,
    };
    // SAFETY: valid terminated name and initialized security descriptor; no inheritance.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            30_000,
            &attributes,
        )
    };
    let error = io::Error::last_os_error();
    // SAFETY: native conversion allocated this descriptor with LocalAlloc.
    unsafe { LocalFree(security) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(error);
    }
    // SAFETY: fresh handle ownership transfers to File exactly once.
    let mut server = unsafe { File::from_raw_handle(handle.cast()) };
    let path = Path::new(r"\\.\pipe")
        .join(std::process::id().to_string())
        .with_extension("memcordon-readiness");
    let payload = challenge.to_vec();
    let client = std::thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut client = OpenOptions::new().read(true).write(true).open(path)?;
        let mut received = Vec::new();
        for bytes in [Vec::new(), vec![0, 255, 128], payload] {
            super::frame_write(&mut client, &bytes)?;
            let actual = super::frame_read(&mut client)?;
            if actual != bytes {
                return Err(io::Error::other("named pipe frame differs"));
            }
            super::frame_write(&mut received, &actual)?;
        }
        Ok(received)
    });
    // SAFETY: handle is held by server and ConnectNamedPipe only associates its peer.
    if unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } == 0
        && io::Error::last_os_error().raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32)
    {
        return Err(io::Error::last_os_error());
    }
    let mut server_received = Vec::new();
    for bytes in [Vec::new(), vec![0, 255, 128], challenge.to_vec()] {
        let actual = super::frame_read(&mut server)?;
        if actual != bytes {
            return Err(io::Error::other("named pipe input differs"));
        }
        super::frame_write(&mut server_received, &actual)?;
        super::frame_write(&mut server, &bytes)?;
    }
    let client_received = client
        .join()
        .map_err(|_| io::Error::other("named pipe peer panicked"))??;
    Ok(NamedPipeProducts {
        server_received,
        client_received,
    })
}

pub fn assert_job_and_sentinels(sentinels: &[super::descriptor::Sentinel]) -> io::Result<()> {
    use windows_sys::Win32::Foundation::GetHandleInformation;
    let mut in_job = 0;
    // SAFETY: pseudo process handle and initialized writable scalar are valid.
    if unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if in_job == 0 {
        return Err(io::Error::other(
            "target is outside the native Job boundary",
        ));
    }
    for sentinel in sentinels {
        let mut flags = 0;
        // SAFETY: query only; invalid handle is the exact expected sentinel outcome.
        if unsafe { GetHandleInformation(sentinel.handle as HANDLE, &mut flags) } != 0 {
            use windows_sys::Win32::Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
            };
            let mut identity = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: observe the actual object, rejecting only the sentinel
            // identity; numeric handle slots may legitimately be reused.
            if unsafe { GetFileInformationByHandle(sentinel.handle as HANDLE, &mut identity) } != 0
                && identity.dwVolumeSerialNumber == sentinel.volume_serial_number
                && ((u64::from(identity.nFileIndexHigh) << 32) | u64::from(identity.nFileIndexLow))
                    == sentinel.file_index
            {
                return Err(io::Error::other(
                    "frontend sentinel file handle leaked into target",
                ));
            }
            continue;
        }
        if io::Error::last_os_error().raw_os_error() != Some(6) {
            return Err(io::Error::other(
                "sentinel query did not return ERROR_INVALID_HANDLE",
            ));
        }
    }
    Ok(())
}

fn token_bytes(token: HANDLE, class: i32) -> io::Result<Vec<usize>> {
    let mut length = 0;
    // SAFETY: sizing query does not read a buffer.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut length) };
    if length == 0 || length > 64 * 1024 {
        return Err(io::Error::other("token field exceeds bound"));
    }
    let slots = (length as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; slots];
    // SAFETY: aligned buffer spans the requested writable byte count.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

pub fn token_observation() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount};
    use windows_sys::Win32::Security::{
        TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenRestrictedSids,
    };
    let mut token = std::ptr::null_mut();
    // SAFETY: pseudo current process handle and output token pointer are valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: newly opened token handle transfers to OwnedHandle once.
    let owned = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    let user = token_bytes(token, TokenUser)?;
    let integrity = token_bytes(token, TokenIntegrityLevel)?;
    let elevation = token_bytes(token, TokenElevation)?;
    // SAFETY: token buffers have the layout returned for their queried classes.
    let (sid, level) = unsafe {
        let user = &*user.as_ptr().cast::<TOKEN_USER>();
        let label = &*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 {
            return Err(io::Error::other("integrity SID has no subauthority"));
        }
        let level = *GetSidSubAuthority(label.Label.Sid, u32::from(count - 1));
        let length = GetLengthSid(user.User.Sid) as usize;
        if length > 256 {
            return Err(io::Error::other("user SID exceeds bound"));
        }
        (
            std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length).to_vec(),
            level,
        )
    };
    // SAFETY: IsTokenRestricted only observes the live held token.
    let restricted = unsafe { IsTokenRestricted(token) } != 0;
    let groups = token_bytes(token, TokenRestrictedSids)?;
    // SAFETY: native TokenRestrictedSids result is an aligned TOKEN_GROUPS
    // allocation, whose fixed header is covered by token_bytes' native query.
    let group_count = unsafe { (*groups.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount } as usize;
    if group_count > 64 {
        return Err(io::Error::other("restricting SID count exceeds bound"));
    }
    let group_offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    if group_offset
        + group_count * std::mem::size_of::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>()
        > groups.len() * std::mem::size_of::<usize>()
    {
        return Err(io::Error::other(
            "restricting SID array exceeds returned token buffer",
        ));
    }
    let mut restricting_sids = Vec::new();
    for index in 0..group_count {
        // SAFETY: each entry lies within the checked native array and its SID is
        // retained by the live token query buffer until serialization completes.
        let group = unsafe {
            &*groups
                .as_ptr()
                .cast::<u8>()
                .add(group_offset)
                .cast::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>()
                .add(index)
        };
        let length = unsafe { GetLengthSid(group.Sid) } as usize;
        if length == 0 || length > 256 {
            return Err(io::Error::other("restricting SID length exceeds bound"));
        }
        restricting_sids
            .push(unsafe { std::slice::from_raw_parts(group.Sid.cast::<u8>(), length) }.to_vec());
    }
    restricting_sids.sort();
    let elevated = elevation.first().copied().unwrap_or(0) & u32::MAX as usize != 0;
    drop(owned);
    serde_json::to_vec(&serde_json::json!({"user_sid":sid,"restricted":restricted,
        "integrity_rid":level,"elevated":elevated,"restricting_sids":restricting_sids}))
    .map_err(io::Error::other)
}

pub fn nested_job() -> io::Result<()> {
    // SAFETY: creates an unnamed private Job with no inherited handle.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh Job ownership transfers exactly once.
    let owned = unsafe { OwnedHandle::from_raw_handle(job.cast()) };
    // SAFETY: current process is assigned to nested Job, without breakaway or limits.
    if unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    assert_job_and_sentinels(&[])?;
    drop(owned);
    Ok(())
}

pub fn breakaway_denied() -> io::Result<()> {
    let output = super::child_command()?
        .arg("generation")
        .arg("0")
        .arg("[]")
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .output();
    match output {
        Err(error) if error.raw_os_error() == Some(5) => Ok(()),
        Err(error) => Err(io::Error::other(format!(
            "breakaway returned wrong native error: {error}"
        ))),
        Ok(_) => Err(io::Error::other("forbidden Job breakaway was permitted")),
    }
}

pub fn create_controller_gate(name: &str) -> io::Result<OwnedHandle> {
    use windows_sys::Win32::System::Threading::CreateEventW;
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: terminated fresh name; manual-reset event starts nonsignaled.
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let reused = io::Error::last_os_error().raw_os_error() == Some(183);
    // SAFETY: newly returned event reference transfers ownership exactly once.
    let owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    if reused {
        return Err(io::Error::other("controller event name was reused"));
    }
    Ok(owned)
}

pub fn wait_controller_gate(
    name: &std::ffi::OsStr,
    ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    use windows_sys::Win32::System::Threading::{OpenEventW, WaitForSingleObject};
    let name: Vec<u16> = name.encode_wide().chain(Some(0)).collect();
    // SAFETY: opens only the explicitly named controller event for wait access.
    let handle = unsafe { OpenEventW(0x0010_0000, 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh owned event reference is closed once.
    let _owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    ready()?;
    // SAFETY: held event handle; bounded outer driver supervises this wait.
    if unsafe { WaitForSingleObject(handle, 120_000) } != 0 {
        return Err(io::Error::other(
            "controller descendant gate did not release",
        ));
    }
    Ok(())
}

pub fn wait_controller_gate_reset(name: &std::ffi::OsStr) -> io::Result<()> {
    use windows_sys::Win32::System::Threading::{OpenEventW, ResetEvent, WaitForSingleObject};
    let name: Vec<u16> = name.encode_wide().chain(Some(0)).collect();
    // SAFETY: opens exact explicit cohort event for wait and reset only.
    let handle = unsafe { OpenEventW(0x0010_0000 | 2, 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh owned native reference transfers exactly once.
    let _owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    // SAFETY: held event; watchdog expiry is a failed fixture, never cleanup proof.
    if unsafe { WaitForSingleObject(handle, 120_000) } != 0 {
        return Err(io::Error::other("cohort controller gate did not release"));
    }
    // SAFETY: reset occurs only after this cohort consumed its controller grant.
    if unsafe { ResetEvent(handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn child_identity(
    child: &std::process::Child,
) -> io::Result<memcordon_core::WindowsProcessIdentityV1> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let mut birth = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: Child holds the native process handle; all output scalars are valid.
    if unsafe {
        GetProcessTimes(
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
    Ok(memcordon_core::WindowsProcessIdentityV1 {
        process_id: child.id(),
        creation_time_100ns: (u64::from(birth.dwHighDateTime) << 32)
            | u64::from(birth.dwLowDateTime),
    })
}

pub fn verify_child_image(child: &std::process::Child, expected: &std::fs::File) -> io::Result<()> {
    use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, GetFileInformationByHandle,
    };
    use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;
    let mut name = vec![0u16; 32768];
    let mut length = name.len() as u32;
    // Both process and expected image handles are owned and held across this native query.
    if unsafe {
        QueryFullProcessImageNameW(
            child.as_raw_handle() as HANDLE,
            0,
            name.as_mut_ptr(),
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    name.truncate(length as usize);
    let observed = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(std::ffi::OsString::from_wide(&name))?;
    let mut identities = [unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() }; 2];
    for (file, identity) in [expected, &observed].into_iter().zip(identities.iter_mut()) {
        // The output buffer is initialized and the file handle remains owned by its File.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, identity) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if identity.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || identity.nNumberOfLinks != 1
        {
            return Err(io::Error::other(
                "owned compiler child image has reparse or alias custody",
            ));
        }
    }
    let left = &identities[0];
    let right = &identities[1];
    if (
        left.dwVolumeSerialNumber,
        left.nFileIndexHigh,
        left.nFileIndexLow,
    ) != (
        right.dwVolumeSerialNumber,
        right.nFileIndexHigh,
        right.nFileIndexLow,
    ) {
        return Err(io::Error::other(
            "actual owned child image differs from measured compiler input",
        ));
    }
    Ok(())
}

pub fn current_identity() -> io::Result<memcordon_core::WindowsProcessIdentityV1> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let mut birth = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the current-process pseudo handle is valid; all outputs are initialized.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut birth,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(memcordon_core::WindowsProcessIdentityV1 {
        process_id: std::process::id(),
        creation_time_100ns: (u64::from(birth.dwHighDateTime) << 32)
            | u64::from(birth.dwLowDateTime),
    })
}

pub fn child_parent_and_liveness(child: &std::process::Child) -> io::Result<(u32, bool)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    #[repr(C)]
    struct BasicProcessInformation {
        reserved1: usize,
        peb: usize,
        reserved2: [usize; 2],
        process_id: usize,
        parent_process_id: usize,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process: HANDLE,
            class: u32,
            information: *mut std::ffi::c_void,
            length: u32,
            returned_length: *mut u32,
        ) -> i32;
    }
    let mut basic = BasicProcessInformation {
        reserved1: 0,
        peb: 0,
        reserved2: [0; 2],
        process_id: 0,
        parent_process_id: 0,
    };
    let mut length = 0;
    // SAFETY: exact owned Child creation handle, native pointer-width basic
    // information layout, initialized bounded output; query changes no state.
    let status = unsafe {
        NtQueryInformationProcess(
            child.as_raw_handle(),
            0,
            (&mut basic as *mut BasicProcessInformation).cast(),
            std::mem::size_of::<BasicProcessInformation>() as u32,
            &mut length,
        )
    };
    if status < 0
        || length as usize != std::mem::size_of::<BasicProcessInformation>()
        || basic.process_id != child.id() as usize
    {
        return Err(io::Error::other(format!(
            "owned child native parent query failed with NTSTATUS {status}"
        )));
    }
    let parent = u32::try_from(basic.parent_process_id)
        .map_err(|_| io::Error::other("native parent PID exceeds width"))?;
    // SAFETY: zero-time wait observes only this still-held native process handle.
    let wait = unsafe { WaitForSingleObject(child.as_raw_handle(), 0) };
    match wait {
        0 => Ok((parent, false)),
        258 => Ok((parent, true)),
        _ => Err(io::Error::last_os_error()),
    }
}

fn frontend_os_error(operation: &'static str) -> io::Error {
    let cause = io::Error::last_os_error();
    io::Error::new(
        cause.kind(),
        format!(
            "native frontend {operation}: raw-os-error={:?}; {cause}",
            cause.raw_os_error()
        ),
    )
}

/// Trusted test launcher only: it changes the frontend caller envelope and waits
/// for that frontend. The installed provider remains the workload supervisor.
pub fn restricted_frontend(arguments: impl Iterator<Item = std::ffi::OsString>) -> io::Result<i32> {
    launch_frontend(arguments, true, None)
}

pub fn sentinel_frontend(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> io::Result<i32> {
    let descriptor = arguments
        .next()
        .ok_or_else(|| io::Error::other("sentinel descriptor missing"))?;
    launch_frontend(arguments, false, Some(Path::new(&descriptor)))
}

fn launch_frontend(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
    restrict: bool,
    sentinel_descriptor: Option<&Path>,
) -> io::Result<i32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{
        GetHandleInformation, HANDLE_FLAG_INHERIT, SetHandleInformation,
    };
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessAsUserW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    let executable = arguments
        .next()
        .ok_or_else(|| io::Error::other("restricted frontend executable missing"))?;
    if !Path::new(&executable).is_absolute() {
        return Err(io::Error::other(
            "restricted frontend requires a measured absolute executable",
        ));
    }
    let argv: Vec<_> = std::iter::once(executable.clone())
        .chain(arguments)
        .collect();
    if argv.len() > 128 || argv.iter().any(|arg| arg.encode_wide().any(|c| c == 0)) {
        return Err(io::Error::other(
            "restricted frontend argv exceeds its native bound",
        ));
    }
    let mut primary = std::ptr::null_mut();
    // SAFETY: current process pseudo-handle and writable output are valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut primary) } == 0 {
        return Err(frontend_os_error("OpenProcessToken"));
    }
    // SAFETY: successful OpenProcessToken transfers one token reference.
    let primary_owned = unsafe { OwnedHandle::from_raw_handle(primary.cast()) };
    use windows_sys::Win32::Security::{CreateWellKnownSid, WinRestrictedCodeSid};
    let mut restricting_sid = [0u32; 17];
    let mut restricting_length = std::mem::size_of_val(&restricting_sid) as u32;
    // SAFETY: aligned maximum native SID buffer; this distinct principal has
    // explicit read grants on inputs and write grants only on candidate outputs.
    if unsafe {
        CreateWellKnownSid(
            WinRestrictedCodeSid,
            std::ptr::null_mut(),
            restricting_sid.as_mut_ptr().cast(),
            &mut restricting_length,
        )
    } == 0
    {
        return Err(frontend_os_error("CreateWellKnownSid"));
    }
    let restricting = SID_AND_ATTRIBUTES {
        Sid: restricting_sid.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut restricted = std::ptr::null_mut();
    // SAFETY: live source token/SID; output acquires a new restricted primary
    // token. Privileges are removed, and access must also satisfy RestrictedCode
    // independently of the ordinary driver's owning user SID.
    if unsafe {
        CreateRestrictedToken(
            primary,
            DISABLE_MAX_PRIVILEGE,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            1,
            &restricting,
            &mut restricted,
        )
    } == 0
    {
        return Err(frontend_os_error("CreateRestrictedToken"));
    }
    // SAFETY: newly returned restricted token reference transfers once.
    let restricted_owned = unsafe { OwnedHandle::from_raw_handle(restricted.cast()) };
    // SAFETY: query only against held restricted token.
    if restrict && unsafe { IsTokenRestricted(restricted) } == 0 {
        return Err(io::Error::other(
            "native restricted token was not restricted",
        ));
    }
    // SAFETY: read only this launcher's three standard handles.
    let standard_handles = unsafe {
        [
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        ]
    };
    let mut handles = standard_handles.to_vec();
    let sentinel = if let Some(path) = sentinel_descriptor {
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut descriptor = super::read_descriptor(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(descriptor.output_root.join("frontend-sentinel.bin"))?;
        let handle = file.as_raw_handle();
        let mut identity = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: held ordinary file handle, initialized writable identity output.
        if unsafe { GetFileInformationByHandle(handle, &mut identity) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: permit only this specific file in the test frontend handle list.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
        descriptor.sentinel_handles = vec![super::descriptor::Sentinel {
            handle: handle as usize,
            volume_serial_number: identity.dwVolumeSerialNumber,
            file_index: (u64::from(identity.nFileIndexHigh) << 32)
                | u64::from(identity.nFileIndexLow),
        }];
        std::fs::write(
            path,
            serde_json::to_vec(&descriptor).map_err(io::Error::other)?,
        )?;
        handles.push(handle);
        Some(file)
    } else {
        None
    };
    let mut original = [0u32; 3];
    for (index, handle) in standard_handles.iter().enumerate() {
        if handle.is_null() || *handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(
                "restricted frontend standard stream missing",
            ));
        }
        // SAFETY: query and scoped flag change on the three owned frontend streams.
        if unsafe { GetHandleInformation(*handle, &mut original[index]) } == 0 {
            return Err(frontend_os_error("GetHandleInformation standard stream"));
        }
        // SAFETY: scoped flag change on the same borrowed frontend stream.
        if unsafe { SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(frontend_os_error("SetHandleInformation standard stream"));
        }
    }
    let mut size = 0usize;
    // SAFETY: sizing call only writes size.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let attributes = storage.as_mut_ptr().cast();
    // SAFETY: aligned storage covers the complete native attribute-list size.
    if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut size) } == 0 {
        return Err(frontend_os_error("InitializeProcThreadAttributeList"));
    }
    let operation = (|| -> io::Result<i32> {
        // SAFETY: explicit borrowed standard-handle list lives through creation.
        if unsafe {
            UpdateProcThreadAttribute(
                attributes,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast_mut().cast(),
                std::mem::size_of_val(handles.as_slice()),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(frontend_os_error("UpdateProcThreadAttribute handle list"));
        }
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes;
        let encoded: Vec<Vec<u16>> = argv.iter().map(|arg| arg.encode_wide().collect()).collect();
        let mut command_line = memcordon_core::encode_windows_command_line(&encoded);
        command_line.push(0);
        let name: Vec<u16> = executable.encode_wide().chain(Some(0)).collect();
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: measured absolute image, reviewed native argv encoder, held
        // token and exact three-handle list. This is never a shell invocation.
        let token = if restrict {
            restricted_owned.as_raw_handle()
        } else {
            primary_owned.as_raw_handle()
        };
        if unsafe {
            CreateProcessAsUserW(
                token,
                name.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                &startup.StartupInfo,
                &mut process,
            )
        } == 0
        {
            return Err(frontend_os_error("CreateProcessAsUserW measured frontend"));
        }
        // SAFETY: returned process/thread references transfer exactly once.
        let process_owned = unsafe { OwnedHandle::from_raw_handle(process.hProcess.cast()) };
        let thread_owned = unsafe { OwnedHandle::from_raw_handle(process.hThread.cast()) };
        // SAFETY: only this launcher owns the frontend's initial suspended thread.
        if unsafe { ResumeThread(thread_owned.as_raw_handle()) } == u32::MAX {
            let cause = frontend_os_error("ResumeThread");
            terminate_frontend(&process_owned)?;
            return Err(cause);
        }
        // SAFETY: held frontend process, bounded driver owns emergency termination.
        if unsafe { WaitForSingleObject(process_owned.as_raw_handle(), 660_000) } != 0 {
            terminate_frontend(&process_owned)?;
            return Err(io::Error::other(
                "restricted frontend exceeded its driver watchdog",
            ));
        }
        let mut code = 0;
        // SAFETY: process is held and has reached a terminal state.
        if unsafe { GetExitCodeProcess(process_owned.as_raw_handle(), &mut code) } == 0 {
            return Err(frontend_os_error("GetExitCodeProcess"));
        }
        Ok(code as i32)
    })();
    // SAFETY: attribute list was initialized and no creation still uses it.
    unsafe { DeleteProcThreadAttributeList(attributes) };
    for (index, handle) in standard_handles.iter().enumerate() {
        // SAFETY: restore original inheritance bits on the three borrowed streams.
        if unsafe {
            SetHandleInformation(
                *handle,
                HANDLE_FLAG_INHERIT,
                original[index] & HANDLE_FLAG_INHERIT,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    drop(primary_owned);
    drop(sentinel);
    operation
}

pub fn retain_child_handle(child: &std::process::Child) -> io::Result<OwnedHandle> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
    let mut duplicate = std::ptr::null_mut();
    // SAFETY: duplicate only the exact owned Child creation handle, noninheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            child.as_raw_handle(),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate.cast()) })
}

pub fn retire_failed_child(process: &OwnedHandle) -> io::Result<()> {
    terminate_frontend(process)
}

fn terminate_frontend(process: &OwnedHandle) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
    // SAFETY: launch_frontend retains the exact newly created process handle.
    // The error path owns termination and must observe retirement before close.
    if unsafe { TerminateProcess(process.as_raw_handle(), 126) } == 0 {
        let original = io::Error::last_os_error();
        if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != 0 {
            return Err(original);
        }
    }
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 30_000) } != 0 {
        return Err(io::Error::other(
            "failed frontend did not retire after owned native termination",
        ));
    }
    Ok(())
}
