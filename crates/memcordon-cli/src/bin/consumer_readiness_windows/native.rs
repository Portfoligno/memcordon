use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsTokenRestricted, TokenElevation, TokenIntegrityLevel, TokenUser,
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

/// Observe the catalog in the original failing child; never load or replace a provider.
pub fn tcp_bind_failure(original: io::Error) -> io::Error {
    use windows_sys::Win32::Networking::WinSock::{
        WSAPROTOCOL_INFOW, WSCEnumProtocols, WSCGetProviderPath,
    };
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    const ENTRIES: usize = 64;
    const PATH_UNITS: usize = 2048;
    let mut entries: Vec<WSAPROTOCOL_INFOW> = (0..ENTRIES)
        .map(|_| unsafe { std::mem::zeroed() })
        .collect();
    let mut bytes = (ENTRIES * std::mem::size_of::<WSAPROTOCOL_INFOW>()) as u32;
    let mut catalog_error = 0;
    // SAFETY: the aligned vector has the exact advertised writable capacity.
    let count = unsafe {
        WSCEnumProtocols(
            std::ptr::null(),
            entries.as_mut_ptr(),
            &raw mut bytes,
            &raw mut catalog_error,
        )
    };
    let mut observations = Vec::new();
    let mut matching_count = 0;
    if count >= 0 && (count as usize) <= ENTRIES {
        matching_count = entries
            .iter()
            .take(count as usize)
            .filter(|entry| {
                entry.iAddressFamily == 2 && entry.iSocketType == 1 && entry.iProtocol == 6
            })
            .count();
        for entry in entries
            .iter()
            .take(count as usize)
            .filter(|entry| {
                entry.iAddressFamily == 2 && entry.iSocketType == 1 && entry.iProtocol == 6
            })
            .take(8)
        {
            let mut path = [0u16; PATH_UNITS];
            let mut units = PATH_UNITS as i32;
            let mut path_error = 0;
            // SAFETY: provider identity comes from this actual catalog and output is bounded.
            let status = unsafe {
                WSCGetProviderPath(
                    &entry.ProviderId,
                    path.as_mut_ptr(),
                    &raw mut units,
                    &raw mut path_error,
                )
            };
            let end = path.iter().position(|unit| *unit == 0);
            let mut expanded = [0u16; PATH_UNITS];
            let expanded_units = if status == 0 && end.is_some() {
                // SAFETY: path is terminated and destination has the advertised capacity.
                unsafe {
                    ExpandEnvironmentStringsW(
                        path.as_ptr(),
                        expanded.as_mut_ptr(),
                        PATH_UNITS as u32,
                    )
                }
            } else {
                0
            };
            let expansion_error = (status == 0 && end.is_some() && expanded_units == 0)
                .then(io::Error::last_os_error);
            let expanded_end = expanded.iter().position(|unit| *unit == 0);
            let expanded_path = if expanded_units > 0 && expanded_units as usize <= PATH_UNITS {
                expanded_end.map(|end| String::from_utf16_lossy(&expanded[..end]))
            } else {
                None
            };
            observations.push(format!(
                "catalog-id={}; provider-id={:08x}-{:04x}-{:04x}-{:02x?}; chain-length={}; path-status={status}; path-error={path_error}; path-units={units}; path-cap={PATH_UNITS}; path-terminated={}; path={:?}; expanded={expanded_path:?}; expansion-units={expanded_units}; expansion-error={:?}",
                entry.dwCatalogEntryId, entry.ProviderId.data1, entry.ProviderId.data2,
                entry.ProviderId.data3, entry.ProviderId.data4,
                entry.ProtocolChain.ChainLen,
                end.is_some(),
                end.filter(|_| status == 0).map(|end| String::from_utf16_lossy(&path[..end])),
                expansion_error.and_then(|error| error.raw_os_error()),
            ));
        }
    }
    io::Error::new(
        original.kind(),
        format!(
            "native TCP listener bind failed: raw-os-error={:?}; {original}; SystemRoot-present={}; windir-present={}; catalog-count={count}; catalog-cap={ENTRIES}; catalog-error={catalog_error}; catalog-bytes={bytes}; matching-provider-count={matching_count}; providers-truncated={}; IPv4-TCP-provider-observations={observations:?}",
            original.raw_os_error(),
            std::env::var_os("SystemRoot").is_some(),
            std::env::var_os("windir").is_some(),
            matching_count > 8,
        ),
    )
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
        let cause = io::Error::last_os_error();
        return Err(io::Error::other(format!(
            "token-snapshot GetTokenInformation sizing; class={class}; length={length}; raw-os-error={:?}; cause={cause}; token field exceeds bound",
            cause.raw_os_error()
        )));
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
        let cause = frontend_os_error("token-snapshot GetTokenInformation read");
        return Err(io::Error::new(
            cause.kind(),
            format!("{cause}; class={class}"),
        ));
    }
    Ok(buffer)
}

pub fn token_observation() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount};
    use windows_sys::Win32::Security::{
        TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenRestrictedSids,
    };
    // GetCurrentProcessToken is an inline Windows SDK function returning -4.
    // Its pseudo-handle queries this process's actual token without reopening
    // the token object through its DACL. It grants only query access, cannot be
    // inherited or duplicated, and must not be treated as an owned handle.
    let token = -4isize as windows_sys::Win32::Foundation::HANDLE;
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
    // SAFETY: IsTokenRestricted only observes this process's token pseudo-handle.
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
    serde_json::to_vec(&serde_json::json!({"user_sid":sid,"restricted":restricted,
        "integrity_rid":level,"elevated":elevated,"restricting_sids":restricting_sids}))
    .map_err(|error| io::Error::other(format!("token-snapshot serialize observation: {error}")))
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
    wait_controller_gate_bound(name, ready, None)
}

pub fn wait_controller_gate_for_fixture(
    name: &std::ffi::OsStr,
    descriptor: &super::Descriptor,
    next_sequence: u32,
) -> io::Result<()> {
    wait_controller_gate_bound(name, || Ok(()), Some((descriptor, next_sequence)))
}

fn wait_controller_gate_bound(
    name: &std::ffi::OsStr,
    ready: impl FnOnce() -> io::Result<()>,
    binding: Option<(&super::Descriptor, u32)>,
) -> io::Result<()> {
    use windows_sys::Win32::System::Threading::{OpenEventW, WaitForSingleObject};
    let name: Vec<u16> = name.encode_wide().chain(Some(0)).collect();
    // SAFETY: opens only the explicitly named controller event for wait access.
    let handle = unsafe { OpenEventW(0x0010_0000, 0, name.as_ptr()) };
    if handle.is_null() {
        let original = io::Error::last_os_error();
        let original_name = name
            .strip_suffix(&[0])
            .expect("appended event name terminator");
        let access = binding.and_then(|(descriptor, _)| {
            descriptor.gate_access_diagnostic.as_ref().map(|input| {
                super::controller_gate_token::AccessRequest {
                    input,
                    name: original_name,
                    challenge: &descriptor.challenge,
                }
            })
        });
        let resolution = match access.as_ref() {
            Some(request) => super::controller_gate_resolution::query(&name, None, || {
                request.input.validate(request.name, request.challenge)?;
                super::controller_gate_access::check(request.input)
            }),
            None => super::controller_gate_resolution::Observation::unavailable(
                super::controller_gate_resolution::Context::FailedFixture,
                "bound-original-work-clock-unavailable",
            ),
        };
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        for unit in name
            .strip_suffix(&[0])
            .expect("appended event name terminator")
        {
            digest.update(unit.to_le_bytes());
        }
        let name_sha256 = super::controller_gate_diagnostic::hex(&digest.finalize());
        let challenge_sha256 = binding.map(|(descriptor, _)| {
            super::controller_gate_diagnostic::hex(&Sha256::digest(&descriptor.challenge))
        });
        let publication = (|| -> io::Result<super::controller_gate_control_publication::Permit> {
            let request = access
                .as_ref()
                .ok_or_else(|| io::Error::other("bound original gate input unavailable"))?;
            super::controller_gate_access::check(request.input)?;
            request.input.validate(request.name, request.challenge)?;
            let binding = serde_json::json!({"case":binding.map(|(descriptor,_)|descriptor.case),"gate_name_utf16_sha256":name_sha256,"challenge_sha256":challenge_sha256,"next_transcript_sequence":binding.map(|(_,sequence)|sequence)});
            let permit = super::controller_gate_control_publication::publish(
                &original,
                &binding,
                &mut std::io::stderr().lock(),
            )?;
            super::controller_gate_access::check(request.input)?;
            Ok(permit)
        })();
        let publication_observation = match &publication {
            Ok(_) => {
                serde_json::json!({"state":"offered-and-flushed","control":"pending","diagnostic_only":true})
            }
            Err(error) => {
                serde_json::json!({"state":"unavailable","kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),"control":"not-authorized-by-publication","diagnostic_only":true})
            }
        };
        let token = match publication {
            Ok(permit) => super::controller_gate_token::capture_with_control(access, Some(permit)),
            Err(_) => super::controller_gate_token::capture(access),
        };
        let context = serde_json::json!({
            "format":"memcordon.controller-gate-open-context","revision":1,"diagnostic_only":true,
            "access":0x0010_0000_u32,"gate_name_utf16_sha256":name_sha256,
            "case":binding.map(|(descriptor,_)|descriptor.case),
            "challenge_sha256":challenge_sha256,
            "next_transcript_sequence":binding.map(|(_,sequence)|sequence),
            "effective_token":token,
            "failed_fixture_zero_access_resolution":resolution,
            "original_failure_prepublication":publication_observation,
        });
        return Err(super::controller_gate_error::open_diagnostic(
            original,
            super::controller_gate_diagnostic::encode(&context),
        ));
    }
    // SAFETY: fresh owned event reference is closed once.
    let _owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    ready()?;
    // SAFETY: held event handle; bounded outer driver supervises this wait.
    let status = unsafe { WaitForSingleObject(handle, 120_000) };
    if status != 0 {
        let original = if status == windows_sys::Win32::Foundation::WAIT_FAILED {
            io::Error::last_os_error()
        } else {
            io::Error::other("controller descendant gate did not release")
        };
        return Err(super::controller_gate_error::context(
            super::controller_gate_error::Stage::Wait,
            Some(status),
            original,
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
    process_parent_and_liveness(child.as_raw_handle(), child.id())
}

pub(super) fn held_parent_and_liveness(owner: &OwnedHandle, pid: u32) -> io::Result<(u32, bool)> {
    use std::os::windows::io::AsRawHandle;
    process_parent_and_liveness(owner.as_raw_handle(), pid)
}

fn process_parent_and_liveness(handle: HANDLE, pid: u32) -> io::Result<(u32, bool)> {
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
            handle,
            0,
            (&mut basic as *mut BasicProcessInformation).cast(),
            std::mem::size_of::<BasicProcessInformation>() as u32,
            &mut length,
        )
    };
    if status < 0
        || length as usize != std::mem::size_of::<BasicProcessInformation>()
        || basic.process_id != pid as usize
    {
        return Err(io::Error::other(format!(
            "owned child native parent query failed with NTSTATUS {status}"
        )));
    }
    let parent = u32::try_from(basic.parent_process_id)
        .map_err(|_| io::Error::other("native parent PID exceeds width"))?;
    // SAFETY: zero-time wait observes only this still-held native process handle.
    let wait = unsafe { WaitForSingleObject(handle, 0) };
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
    launch_frontend(arguments, true, None, false)
}

pub fn system_frontend(arguments: impl Iterator<Item = std::ffi::OsString>) -> io::Result<i32> {
    launch_frontend(arguments, false, None, true)
}

pub fn system_restricted_frontend(
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> io::Result<i32> {
    launch_frontend(arguments, true, None, true)
}

pub fn system_sentinel_frontend(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> io::Result<i32> {
    let descriptor = arguments
        .next()
        .ok_or_else(|| io::Error::other("sentinel descriptor missing"))?;
    launch_frontend(arguments, false, Some(Path::new(&descriptor)), true)
}

pub fn sentinel_frontend(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> io::Result<i32> {
    let descriptor = arguments
        .next()
        .ok_or_else(|| io::Error::other("sentinel descriptor missing"))?;
    launch_frontend(arguments, false, Some(Path::new(&descriptor)), false)
}

fn launch_frontend(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
    restrict: bool,
    sentinel_descriptor: Option<&Path>,
    system_environment: bool,
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
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
        InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
        ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
        WaitForSingleObject,
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
    if restrict {
        // This launcher owns the newly derived fixture token. Its default
        // objects must satisfy both ordinary and RestrictedCode access checks.
        super::native_fixture_default_dacl::prepare(primary, restricted)?;
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
        let environment = if system_environment {
            Some(
                memcordon_core::encode_windows_environment_block(
                    &super::fixture_environment::entries()?,
                )
                .map_err(io::Error::other)?,
            )
        } else {
            None
        };
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
                CREATE_SUSPENDED
                    | EXTENDED_STARTUPINFO_PRESENT
                    | if system_environment {
                        CREATE_UNICODE_ENVIRONMENT
                    } else {
                        0
                    },
                environment
                    .as_ref()
                    .map_or(std::ptr::null(), |block| block.as_ptr().cast()),
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
        if code != 0 {
            use std::io::Write;
            // Fixed native scalar fields bound this diagnostic independently of
            // image paths or argv. A failed diagnostic write must not replace
            // the original held child's exit status.
            let _ = writeln!(
                io::stderr().lock(),
                "native-frontend phase=inner-child-exited child-pid={} exit-code={} exit-code-hex=0x{:08x} restricted={} system-environment={}",
                process.dwProcessId,
                code,
                code,
                restrict,
                system_environment,
            );
            if restrict && code == 0xc0000135 {
                diagnose_restricted_dependencies(&restricted_owned);
            }
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

// Query existing native sections without mapping them or asserting that the
// loader selected them. This uses the already duplicated original restricted
// token solely for a section-DACL check, without thread impersonation.
fn diagnose_known_dll_sections(token: &OwnedHandle) -> serde_json::Value {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree, UNICODE_STRING};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        AccessCheck, DACL_SECURITY_INFORMATION, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PRIVILEGE_SET,
    };

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: HANDLE,
        object_name: *mut UNICODE_STRING,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtOpenDirectoryObject(
            handle: *mut HANDLE,
            access: u32,
            attributes: *const ObjectAttributes,
        ) -> i32;
        fn NtOpenSection(
            handle: *mut HANDLE,
            access: u32,
            attributes: *const ObjectAttributes,
        ) -> i32;
    }
    fn attributes(
        storage: &mut [u16],
        name: &mut UNICODE_STRING,
        root: HANDLE,
    ) -> ObjectAttributes {
        *name = UNICODE_STRING {
            Length: (storage.len() * 2) as u16,
            MaximumLength: (storage.len() * 2) as u16,
            Buffer: storage.as_mut_ptr(),
        };
        ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: root,
            object_name: name,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        }
    }
    let mut storage: Vec<u16> = r"\KnownDlls".encode_utf16().collect();
    let mut name = UNICODE_STRING::default();
    let directory_attributes = attributes(&mut storage, &mut name, std::ptr::null_mut());
    let mut directory = std::ptr::null_mut();
    // SAFETY: fixed bounded native name and initialized output; query/traverse
    // rights only. The name storage remains held throughout this call.
    let directory_status =
        unsafe { NtOpenDirectoryObject(&mut directory, 3, &directory_attributes) };
    if directory_status < 0 || directory.is_null() {
        return serde_json::json!({"scope":"known-dll-section-dacl-only", "namespace":r"\KnownDlls",
            "stage":"NtOpenDirectoryObject", "ntstatus":directory_status,
            "successful_status_null_handle":directory_status >= 0 && directory.is_null()});
    }
    // SAFETY: successful native open transferred one owned kernel handle.
    let directory = unsafe { OwnedHandle::from_raw_handle(directory) };
    let mut entries = Vec::new();
    for leaf in [
        "bcrypt.dll",
        "bcryptprimitives.dll",
        "kernel32.dll",
        "advapi32.dll",
        "ntdll.dll",
    ] {
        let mut storage: Vec<u16> = leaf.encode_utf16().collect();
        let mut name = UNICODE_STRING::default();
        let section_attributes = attributes(&mut storage, &mut name, directory.as_raw_handle());
        let mut section = std::ptr::null_mut();
        // SAFETY: same held native directory and fixed leaf, no map rights.
        let status = unsafe { NtOpenSection(&mut section, 0x20001, &section_attributes) }; // READ_CONTROL | SECTION_QUERY
        if status < 0 || section.is_null() {
            entries.push(
                serde_json::json!({"leaf":leaf,"stage":"NtOpenSection","ntstatus":status,
                "absent":status == 0xc0000034u32 as i32,
                "successful_status_null_handle":status >= 0 && section.is_null()}),
            );
            continue;
        }
        // SAFETY: successful native open transferred one section reference.
        let section = unsafe { OwnedHandle::from_raw_handle(section) };
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: query security on this exact held section; descriptor allocation
        // is LocalFree-owned and never outlives the section/token.
        let security_status = unsafe {
            GetSecurityInfo(
                section.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if security_status != 0 || descriptor.is_null() {
            entries.push(serde_json::json!({"leaf":leaf,"ntstatus":status,"stage":"held-section-security-descriptor",
                "native_error":security_status,"successful_status_null_descriptor":security_status == 0 && descriptor.is_null()}));
            continue;
        }
        let mut checks = Vec::new();
        for desired in [12, 4, 8] {
            // SECTION_MAP_READ | SECTION_MAP_EXECUTE, each separately
            let mut mapping = GENERIC_MAPPING {
                GenericRead: 0x20005,
                GenericWrite: 0x20002,
                GenericExecute: 0x20008,
                GenericAll: 0xf001f,
            };
            let mut privileges = [0usize; 64];
            let mut size = std::mem::size_of_val(&privileges) as u32;
            let mut granted = 0;
            let mut allowed = 0;
            // SAFETY: original restricted query token, same held-section
            // descriptor and fresh bounded aligned outputs. No section mapping.
            let checked = unsafe {
                AccessCheck(
                    descriptor,
                    token.as_raw_handle(),
                    desired,
                    &mut mapping,
                    privileges.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                    &mut size,
                    &mut granted,
                    &mut allowed,
                )
            };
            let error = if checked == 0 || allowed == 0 {
                io::Error::last_os_error().raw_os_error()
            } else {
                None
            };
            checks.push(if checked == 0 {
                serde_json::json!({"desired":desired,"api_native_error":error})
            } else {
                serde_json::json!({"desired":desired,"allowed":allowed != 0,"granted":granted,"denial_native_error":error})
            });
        }
        // SAFETY: all descriptor users have finished; exact allocation returned
        // by successful GetSecurityInfo is released once.
        unsafe { LocalFree(descriptor) };
        entries.push(serde_json::json!({"leaf":leaf,"ntstatus":status,"checks":checks}));
    }
    serde_json::json!({"scope":"known-dll-section-dacl-only","namespace":r"\KnownDlls",
        "directory_ntstatus":directory_status,"entries":entries})
}

// Observe only a finite set of direct import candidates. These leaf-DACL
// checks do not identify the loader-selected module or model its full access.
fn diagnose_restricted_dependencies(token: &OwnedHandle) {
    use std::io::Write;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AccessCheck, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GENERIC_MAPPING,
        GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PRIVILEGE_SET,
        SecurityImpersonation, TOKEN_QUERY, TokenImpersonation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS, FILE_EXECUTE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, GetFileInformationByHandle, READ_CONTROL,
    };
    let mut setup_stage = "duplicate-original-restricted-token-for-query";
    let mut observe = || -> io::Result<serde_json::Value> {
        let mut impersonation = std::ptr::null_mut();
        // SAFETY: the original restricted primary token remains held; output
        // acquires a query-only impersonation token without changing any thread.
        if unsafe {
            DuplicateTokenEx(
                token.as_raw_handle(),
                TOKEN_QUERY,
                std::ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut impersonation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful duplication transfers exactly one token reference.
        let impersonation = unsafe { OwnedHandle::from_raw_handle(impersonation) };
        let sections = diagnose_known_dll_sections(&impersonation).to_string();
        if sections.len() + "native-frontend known-dll-access=".len() + 1 <= 8192 {
            let _ = writeln!(
                io::stderr().lock(),
                "native-frontend known-dll-access={sections}"
            );
        } else {
            let _ = writeln!(
                io::stderr().lock(),
                "native-frontend known-dll-access-unavailable=serialized-bound-exceeded"
            );
        }
        setup_stage = "native-system-directory";
        let mut directory = [0u16; 2048];
        // SAFETY: bounded writable buffer; successful length excludes the NUL.
        let units = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
                directory.as_mut_ptr(),
                directory.len() as u32,
            )
        };
        if units == 0 {
            return Err(io::Error::last_os_error());
        }
        if units as usize >= directory.len() {
            return Err(io::Error::other(
                "system directory exceeds diagnostic bound",
            ));
        }
        let directory =
            std::path::PathBuf::from(std::ffi::OsString::from_wide(&directory[..units as usize]));
        if !directory.is_absolute() {
            return Err(io::Error::other("system directory is not absolute"));
        }
        let mut entries = Vec::new();
        for leaf in [
            "bcrypt.dll",
            "bcryptprimitives.dll",
            "kernel32.dll",
            "advapi32.dll",
            "ntdll.dll",
        ] {
            let mut stage = "controller-open-read-control-attributes";
            let result = (|| -> io::Result<serde_json::Value> {
                let file = OpenOptions::new()
                    .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
                    .share_mode(1)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(directory.join(leaf))?;
                let mut identity = BY_HANDLE_FILE_INFORMATION::default();
                stage = "held-file-identity";
                // SAFETY: exact held file and initialized native output.
                if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut identity) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                if identity.dwFileAttributes & 0x410 != 0 {
                    return Err(io::Error::other("candidate is directory or reparse point"));
                }
                let mut descriptor = std::ptr::null_mut();
                stage = "held-file-security-descriptor";
                // SAFETY: query the same held file; native output is LocalFree-owned.
                let status = unsafe {
                    GetSecurityInfo(
                        file.as_raw_handle(),
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION
                            | GROUP_SECURITY_INFORMATION
                            | DACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut descriptor,
                    )
                };
                if status != 0 {
                    return Err(io::Error::from_raw_os_error(status as i32));
                }
                if descriptor.is_null() {
                    return Err(io::Error::other("native security descriptor is null"));
                }
                stage = "restricted-token-leaf-dacl-access-check";
                let mut checks = Vec::new();
                // A combined denial cannot identify which concrete permission
                // failed. Observe both constituent rights on this same token
                // and descriptor; none of these checks models loader policy.
                for desired in [FILE_READ_DATA | FILE_EXECUTE, FILE_READ_DATA, FILE_EXECUTE] {
                    let mut mapping = GENERIC_MAPPING {
                        GenericRead: FILE_GENERIC_READ,
                        GenericWrite: FILE_GENERIC_WRITE,
                        GenericExecute: FILE_GENERIC_EXECUTE,
                        GenericAll: FILE_ALL_ACCESS,
                    };
                    let mut privileges = [0usize; 64];
                    let mut size = std::mem::size_of_val(&privileges) as u32;
                    let mut granted = 0;
                    let mut allowed = 0;
                    // SAFETY: same descriptor/token and newly initialized,
                    // aligned bounded outputs remain live for each query.
                    let checked = unsafe {
                        AccessCheck(
                            descriptor,
                            impersonation.as_raw_handle(),
                            desired,
                            &mut mapping,
                            privileges.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                            &mut size,
                            &mut granted,
                            &mut allowed,
                        )
                    };
                    let native_error = if checked == 0 || allowed == 0 {
                        io::Error::last_os_error().raw_os_error()
                    } else {
                        None
                    };
                    checks.push(if checked == 0 {
                        serde_json::json!({"desired":desired,"api_native_error":native_error})
                    } else {
                        serde_json::json!({"desired":desired,"allowed":allowed != 0,
                            "granted":granted,"denial_native_error":native_error})
                    });
                }
                // SAFETY: GetSecurityInfo returned this allocation; no users remain.
                unsafe { LocalFree(descriptor) };
                Ok(serde_json::json!({"volume":identity.dwVolumeSerialNumber,
                    "file_index":(u64::from(identity.nFileIndexHigh)<<32)|u64::from(identity.nFileIndexLow),
                    "attributes":identity.dwFileAttributes,"checks":checks}))
            })();
            entries.push(match result { Ok(value) => serde_json::json!({"leaf":leaf,"observation":value}),
                Err(error) => serde_json::json!({"leaf":leaf,"stage":stage,"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind())}) });
        }
        let directory_text = directory.to_string_lossy();
        Ok(
            serde_json::json!({"scope":"system-directory-direct-import-candidates-leaf-dacl-only",
            "system_directory":directory_text.chars().take(256).collect::<String>(),
            "system_directory_truncated":directory_text.chars().count()>256,
            "entries":entries}),
        )
    };
    let observation = match observe() {
        Ok(value) => value,
        Err(error) => serde_json::json!({
        "setup_stage":setup_stage,"setup_native_error":error.raw_os_error(),"setup_kind":format!("{:?}",error.kind())}),
    };
    // Finite candidates and scalar fields bound this independent evidence;
    // failures to publish it never replace the original child's status.
    let encoded = observation.to_string();
    if encoded.len() <= 8192 {
        let _ = writeln!(
            io::stderr().lock(),
            "native-frontend dependency-access={encoded}"
        );
    } else {
        let _ = writeln!(
            io::stderr().lock(),
            "native-frontend dependency-access-unavailable=serialized-bound-exceeded"
        );
    }
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
