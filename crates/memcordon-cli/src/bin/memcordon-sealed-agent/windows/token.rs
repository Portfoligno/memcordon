use std::ffi::c_void;
use std::io;
use std::ptr;

use memcordon_core::{WindowsCallerTokenEnvelopeV1, WindowsSealedFault};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, GetLengthSid,
    GetTokenInformation, IsTokenRestricted, LUA_TOKEN, RevertToSelf, SID_AND_ATTRIBUTES,
    SecurityImpersonation, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_IMPERSONATE,
    TOKEN_MANDATORY_LABEL, TOKEN_MANDATORY_POLICY, TOKEN_OWNER, TOKEN_PRIMARY_GROUP,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS, TokenElevation, TokenElevationType,
    TokenGroups, TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel,
    TokenIsAppContainer, TokenMandatoryPolicy, TokenOwner, TokenPrimary, TokenPrimaryGroup,
    TokenPrivileges, TokenRestrictedSids, TokenSessionId, TokenStatistics, TokenUIAccess,
    TokenUser, TokenVirtualizationAllowed, TokenVirtualizationEnabled, WRITE_RESTRICTED,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, SetThreadToken,
};

use super::pipe::OwnedHandle;

struct RevertGuard;

impl Drop for RevertGuard {
    fn drop(&mut self) {
        // SAFETY: the guard is created only after successful named-pipe client
        // impersonation on this thread and reverts that exact impersonation.
        unsafe { RevertToSelf() };
    }
}

pub fn pipe_client_is_elevated(pipe: HANDLE) -> Result<bool, String> {
    // SAFETY: pipe is a connected server endpoint.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let _revert = RevertGuard;
    let mut token = ptr::null_mut();
    // SAFETY: the thread is impersonating the authenticated pipe client and
    // token receives an owned query handle.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = OwnedHandle::new(token)?;
    let caller = envelope(token.raw())?;
    Ok(caller.elevated && !caller.appcontainer)
}

pub fn process_has_privileges(process_id: u32, expected: &[&str]) -> Result<bool, String> {
    // SAFETY: process_id comes from an authenticated SCM status record.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    let process = OwnedHandle::new(process)?;
    let mut token = ptr::null_mut();
    // SAFETY: the process handle is live and token receives an owned query handle.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = OwnedHandle::new(token)?;
    let buffer = query(token.raw(), TokenPrivileges)?;
    // SAFETY: query returned native-aligned TOKEN_PRIVILEGES storage.
    let privileges = unsafe { ptr::read(buffer.as_ptr().cast::<TOKEN_PRIVILEGES>()) };
    let entries = privileges.PrivilegeCount as usize;
    let fixed = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let entry_bytes = entries
        .checked_mul(std::mem::size_of::<
            windows_sys::Win32::Security::LUID_AND_ATTRIBUTES,
        >())
        .and_then(|bytes| fixed.checked_add(bytes))
        .ok_or_else(|| "service privilege response size overflowed".to_owned())?;
    if entry_bytes > buffer.len() {
        return Err("service privilege response is truncated".to_owned());
    }
    // SAFETY: the byte-size check proves all declared entries are present.
    let entries = unsafe { std::slice::from_raw_parts(privileges.Privileges.as_ptr(), entries) };
    for name in expected {
        let name = super::pipe::wide_null(name);
        let mut expected_luid = windows_sys::Win32::Foundation::LUID::default();
        // SAFETY: the privilege name is NUL-terminated and the output is writable.
        if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &raw mut expected_luid) } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if !entries.iter().any(|entry| {
            entry.Luid.LowPart == expected_luid.LowPart
                && entry.Luid.HighPart == expected_luid.HighPart
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn process_envelope(process_id: u32) -> Result<WindowsCallerTokenEnvelopeV1, String> {
    // SAFETY: process_id comes from an authenticated SCM status record.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    let process = OwnedHandle::new(process)?;
    let mut token = ptr::null_mut();
    // SAFETY: process is live and token receives one owned query handle.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = OwnedHandle::new(token)?;
    envelope(token.raw())
}

pub struct RestrictedImpersonationGuard {
    _token: OwnedHandle,
}

impl Drop for RestrictedImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: construction succeeds only after setting this thread's token.
        unsafe { RevertToSelf() };
    }
}

pub fn impersonate_restricted_current_thread() -> Result<RestrictedImpersonationGuard, String> {
    let restricted = restricted_current_primary()?;
    impersonate_primary_token(restricted)
}

pub fn impersonate_write_restricted_current_thread() -> Result<RestrictedImpersonationGuard, String>
{
    let restricted =
        restricted_current_primary_with_flags(DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED)?;
    impersonate_primary_token(restricted)
}

pub fn impersonate_ordinary_current_thread() -> Result<RestrictedImpersonationGuard, String> {
    let restricted = restricted_current_primary_with_flags(DISABLE_MAX_PRIVILEGE | LUA_TOKEN)?;
    if envelope(restricted.raw())?.elevated {
        return Err("ordinary-token qualification fixture remained elevated".to_owned());
    }
    impersonate_primary_token(restricted)
}

pub fn impersonate_low_integrity_current_thread() -> Result<RestrictedImpersonationGuard, String> {
    let restricted = restricted_current_primary()?;
    let low = super::pipe::wide_null("S-1-16-4096");
    let mut sid = ptr::null_mut();
    // SAFETY: the SDDL SID is NUL-terminated and output receives LocalAlloc memory.
    if unsafe { ConvertStringSidToSidW(low.as_ptr(), &raw mut sid) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid,
            // SE_GROUP_INTEGRITY marks this SID as the token's mandatory label.
            Attributes: 0x20,
        },
    };
    // SAFETY: token has adjust-default access, label points to a live SID, and
    // the length covers the fixed label plus its variable SID payload.
    let changed = unsafe {
        SetTokenInformation(
            restricted.raw(),
            TokenIntegrityLevel,
            (&raw const label).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_MANDATORY_LABEL>())
                .map_err(|_| "mandatory label size is not representable".to_owned())?
                + GetLengthSid(sid),
        )
    };
    // SAFETY: sid is the exact LocalAlloc allocation returned above.
    unsafe { LocalFree(sid) };
    if changed == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    impersonate_primary_token(restricted)
}

pub fn impersonate_deny_only_admin_current_thread() -> Result<RestrictedImpersonationGuard, String>
{
    let process_token = current_process_token()?;
    let administrator = allocated_sid("S-1-5-32-544")?;
    let restricted_code = allocated_sid("S-1-5-12")?;
    let disabled = SID_AND_ATTRIBUTES {
        Sid: administrator,
        Attributes: 0,
    };
    let restricting = SID_AND_ATTRIBUTES {
        Sid: restricted_code,
        Attributes: 0,
    };
    let mut restricted = ptr::null_mut();
    // SAFETY: the input token and both one-entry SID arrays remain live for
    // the call; output ownership transfers to OwnedHandle.
    let created = unsafe {
        CreateRestrictedToken(
            process_token.raw(),
            DISABLE_MAX_PRIVILEGE,
            1,
            &raw const disabled,
            0,
            ptr::null(),
            1,
            &raw const restricting,
            &raw mut restricted,
        )
    };
    // SAFETY: both pointers are exact LocalAlloc results.
    unsafe {
        LocalFree(administrator);
        LocalFree(restricted_code);
    }
    if created == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    impersonate_primary_token(OwnedHandle::new(restricted)?)
}

fn impersonate_primary_token(primary: OwnedHandle) -> Result<RestrictedImpersonationGuard, String> {
    let mut impersonation = ptr::null_mut();
    // SAFETY: primary is a live primary token; output receives an independently
    // owned impersonation token.
    if unsafe {
        DuplicateTokenEx(
            primary.raw(),
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut impersonation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let impersonation = OwnedHandle::new(impersonation)?;
    // SAFETY: a null thread pointer selects the current thread and the token is
    // a live impersonation token retained by the returned guard.
    if unsafe { SetThreadToken(ptr::null(), impersonation.raw()) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(RestrictedImpersonationGuard {
        _token: impersonation,
    })
}

pub fn restricted_current_primary() -> Result<OwnedHandle, String> {
    restricted_current_primary_with_flags(DISABLE_MAX_PRIVILEGE)
}

fn restricted_current_primary_with_flags(flags: u32) -> Result<OwnedHandle, String> {
    let process_token = current_process_token()?;
    let sid = allocated_sid("S-1-5-12")?;
    let restricted_sid = SID_AND_ATTRIBUTES {
        Sid: sid,
        Attributes: 0,
    };
    let mut restricted = ptr::null_mut();
    // SAFETY: the input token and single restricting SID remain live for the call;
    // the returned token is transferred into OwnedHandle.
    let created = unsafe {
        CreateRestrictedToken(
            process_token.raw(),
            flags,
            0,
            ptr::null(),
            0,
            ptr::null(),
            1,
            &raw const restricted_sid,
            &raw mut restricted,
        )
    };
    // SAFETY: sid is the exact LocalAlloc allocation returned above.
    unsafe { LocalFree(sid) };
    if created == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    OwnedHandle::new(restricted)
}

fn current_process_token() -> Result<OwnedHandle, String> {
    let mut raw_process_token = ptr::null_mut();
    // SAFETY: the current process pseudo-handle is live and the returned token
    // is owned by the local handle wrapper.
    if unsafe {
        OpenProcessToken(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut raw_process_token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    OwnedHandle::new(raw_process_token)
}

fn allocated_sid(value: &str) -> Result<*mut c_void, String> {
    let value = super::pipe::wide_null(value);
    let mut sid = ptr::null_mut();
    // SAFETY: the SDDL SID is NUL-terminated and output receives LocalAlloc memory.
    if unsafe { ConvertStringSidToSidW(value.as_ptr(), &raw mut sid) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(sid)
    }
}

pub fn authenticate_pipe_client(
    pipe: HANDLE,
    client_process_id: u32,
    certification_fault: Option<WindowsSealedFault>,
) -> Result<
    (
        OwnedHandle,
        WindowsCallerTokenEnvelopeV1,
        OwnedHandle,
        memcordon_core::WindowsProcessIdentityV1,
    ),
    String,
> {
    reject_fault(
        certification_fault,
        WindowsSealedFault::CallerTokenImpersonation,
    )?;
    // SAFETY: pipe is the connected server end owned by the control service.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(format!(
            "MCSEALED-WINDOWS-CALLER-AUTH: {}",
            io::Error::last_os_error()
        ));
    }
    let _revert = RevertGuard;
    let mut impersonation = ptr::null_mut();
    // SAFETY: current thread is impersonating the authenticated pipe client;
    // output storage is live and ownership transfers to OwnedHandle.
    if unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            0,
            &raw mut impersonation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let impersonation = OwnedHandle::new(impersonation)?;
    if envelope(impersonation.raw())?.appcontainer {
        return Err("MCSEALED-WINDOWS-APPCONTAINER-UNSUPPORTED: AppContainer callers are not supported by Windows sealed v2".to_owned());
    }
    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
    // SAFETY: PID came from the same authenticated named-pipe connection and
    // this call executes while impersonating that client.
    let frontend = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE | SYNCHRONIZE_ACCESS,
            0,
            client_process_id,
        )
    })?;
    let identity_before = super::process::process_identity(frontend.raw())?;
    let mut primary = ptr::null_mut();
    reject_fault(
        certification_fault,
        WindowsSealedFault::PrimaryTokenDuplicate,
    )?;
    // SAFETY: the authenticated token remains live; the new primary token is
    // returned with independent ownership and no inheritable attributes.
    if unsafe {
        DuplicateTokenEx(
            impersonation.raw(),
            TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut primary,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let primary = OwnedHandle::new(primary)?;
    let primary_envelope = envelope(primary.raw())?;
    let mut client_process_id_after = 0_u32;
    // SAFETY: pipe is still the same connected server endpoint and the output
    // brackets token capture with a fresh kernel-authenticated client PID.
    if unsafe { GetNamedPipeClientProcessId(pipe, &raw mut client_process_id_after) } == 0 {
        return Err(format!(
            "MCSEALED-WINDOWS-CALLER-RACE: {}",
            io::Error::last_os_error()
        ));
    }
    if client_process_id_after != client_process_id {
        return Err(
            "MCSEALED-WINDOWS-CALLER-RACE: pipe client PID changed during token capture".to_owned(),
        );
    }
    // SAFETY: the re-queried PID is opened under the still-active authenticated
    // client impersonation, pinning the post-capture process object.
    let frontend_after = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE | SYNCHRONIZE_ACCESS,
            0,
            client_process_id_after,
        )
    })?;
    let identity_after = super::process::process_identity(frontend_after.raw())?;
    if identity_after != identity_before {
        return Err(
            "MCSEALED-WINDOWS-CALLER-RACE: pipe client process object changed during token capture"
                .to_owned(),
        );
    }
    drop(frontend_after);
    Ok((primary, primary_envelope, frontend, identity_before))
}

fn reject_fault(
    actual: Option<WindowsSealedFault>,
    expected: WindowsSealedFault,
) -> Result<(), String> {
    if actual == Some(expected) {
        Err(format!(
            "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected {expected:?}"
        ))
    } else {
        Ok(())
    }
}

pub fn process_token(process: HANDLE) -> Result<OwnedHandle, String> {
    let mut token = ptr::null_mut();
    // SAFETY: process is a live process handle with query rights and output
    // ownership transfers into OwnedHandle.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    OwnedHandle::new(token)
}

pub fn process_user_sid(process: HANDLE) -> Result<String, String> {
    let mut token = ptr::null_mut();
    // SAFETY: process is live with query rights and the returned query token is
    // transferred into OwnedHandle.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = OwnedHandle::new(token)?;
    let user = query(token.raw(), TokenUser)?;
    // SAFETY: the returned token-user buffer is large enough and remains live.
    let user = unsafe {
        ptr::read_unaligned(
            user.as_ptr()
                .cast::<windows_sys::Win32::Security::TOKEN_USER>(),
        )
    };
    sid_string(user.User.Sid)
}

pub fn process_has_enabled_group(
    process: HANDLE,
    expected_sid: &str,
    restricted: bool,
) -> Result<bool, String> {
    let token = process_token(process)?;
    let groups = query(
        token.raw(),
        if restricted {
            TokenRestrictedSids
        } else {
            TokenGroups
        },
    )?;
    let groups = unsafe { ptr::read_unaligned(groups.as_ptr().cast::<TOKEN_GROUPS>()) };
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    const ENABLED: u32 = 0x0000_0004;
    const DENY_ONLY: u32 = 0x0000_0010;
    for entry in entries {
        if entry.Attributes & ENABLED != 0
            && entry.Attributes & DENY_ONLY == 0
            && sid_string(entry.Sid)? == expected_sid
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn current_thread_envelope() -> Result<WindowsCallerTokenEnvelopeV1, String> {
    let token = current_thread_token()?;
    envelope(token.raw())
}

pub fn current_thread_restricted_sid_count() -> Result<u32, String> {
    let token = current_thread_token()?;
    let groups = query(token.raw(), TokenRestrictedSids)?;
    // SAFETY: the query buffer contains the TOKEN_GROUPS header.
    Ok(unsafe { ptr::read_unaligned(groups.as_ptr().cast::<TOKEN_GROUPS>()) }.GroupCount)
}

pub fn current_thread_is_restricted() -> Result<bool, String> {
    let token = current_thread_token()?;
    // SAFETY: token is a live query handle and IsTokenRestricted reads it only.
    Ok(unsafe { IsTokenRestricted(token.raw()) } != 0)
}

pub fn current_thread_enabled_sensitive_privilege_count() -> Result<u32, String> {
    const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
    let token = current_thread_token()?;
    let buffer = query(token.raw(), TokenPrivileges)?;
    // SAFETY: the native-aligned query buffer contains TOKEN_PRIVILEGES.
    let privileges = unsafe { ptr::read(buffer.as_ptr().cast::<TOKEN_PRIVILEGES>()) };
    let count = privileges.PrivilegeCount as usize;
    let fixed = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let bytes = count
        .checked_mul(std::mem::size_of::<
            windows_sys::Win32::Security::LUID_AND_ATTRIBUTES,
        >())
        .and_then(|bytes| fixed.checked_add(bytes))
        .ok_or_else(|| "token privilege inventory size overflowed".to_owned())?;
    if bytes > buffer.len() {
        return Err("token privilege inventory is truncated".to_owned());
    }
    // SAFETY: the independent length query proves the declared entry array.
    let entries = unsafe { std::slice::from_raw_parts(privileges.Privileges.as_ptr(), count) };
    let change_notify_name = super::pipe::wide_null("SeChangeNotifyPrivilege");
    let mut change_notify = windows_sys::Win32::Foundation::LUID::default();
    // SAFETY: name is NUL-terminated and the LUID output is writable.
    if unsafe {
        LookupPrivilegeValueW(
            ptr::null(),
            change_notify_name.as_ptr(),
            &raw mut change_notify,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(entries
        .iter()
        .filter(|entry| {
            entry.Attributes & SE_PRIVILEGE_ENABLED != 0
                && (entry.Luid.LowPart != change_notify.LowPart
                    || entry.Luid.HighPart != change_notify.HighPart)
        })
        .count() as u32)
}

pub fn current_thread_group_has_attributes(
    expected_sid: &str,
    required: u32,
) -> Result<bool, String> {
    let token = current_thread_token()?;
    let groups = query(token.raw(), TokenGroups)?;
    // SAFETY: Windows returned GroupCount entries in the variable-size buffer.
    let groups = unsafe { ptr::read_unaligned(groups.as_ptr().cast::<TOKEN_GROUPS>()) };
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    for entry in entries {
        if entry.Attributes & required == required && sid_string(entry.Sid)? == expected_sid {
            return Ok(true);
        }
    }
    Ok(false)
}

fn current_thread_token() -> Result<OwnedHandle, String> {
    let mut token = ptr::null_mut();
    // SAFETY: current thread is expected to carry the qualification fixture token.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &raw mut token) } == 0 {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            == Some(ERROR_NO_TOKEN)
        {
            current_process_token()
        } else {
            Err(error.to_string())
        }
    } else {
        OwnedHandle::new(token)
    }
}

pub fn envelope(token: HANDLE) -> Result<WindowsCallerTokenEnvelopeV1, String> {
    let user = query(token, TokenUser)?;
    let owner = query(token, TokenOwner)?;
    let primary_group = query(token, TokenPrimaryGroup)?;
    let groups = query(token, TokenGroups)?;
    let privileges = query(token, TokenPrivileges)?;
    let restricted = query(token, TokenRestrictedSids)?;
    let integrity = query(token, TokenIntegrityLevel)?;
    let mandatory = query(token, TokenMandatoryPolicy)?;
    let statistics = query(token, TokenStatistics)?;

    // SAFETY: each buffer was filled for the corresponding token information
    // class. Unaligned reads copy only the fixed header; embedded SID pointers
    // remain valid while their backing buffers are alive.
    let user = unsafe {
        ptr::read_unaligned(
            user.as_ptr()
                .cast::<windows_sys::Win32::Security::TOKEN_USER>(),
        )
    };
    let owner = unsafe { ptr::read_unaligned(owner.as_ptr().cast::<TOKEN_OWNER>()) };
    let primary_group =
        unsafe { ptr::read_unaligned(primary_group.as_ptr().cast::<TOKEN_PRIMARY_GROUP>()) };
    let integrity =
        unsafe { ptr::read_unaligned(integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    let mandatory =
        unsafe { ptr::read_unaligned(mandatory.as_ptr().cast::<TOKEN_MANDATORY_POLICY>()) };
    let statistics = unsafe { ptr::read_unaligned(statistics.as_ptr().cast::<TOKEN_STATISTICS>()) };

    let authentication_id = (u64::from(statistics.AuthenticationId.HighPart as u32) << 32)
        | u64::from(statistics.AuthenticationId.LowPart);
    Ok(WindowsCallerTokenEnvelopeV1 {
        user_sid: sid_string(user.User.Sid)?,
        owner_sid: sid_string(owner.Owner)?,
        primary_group_sid: sid_string(primary_group.PrimaryGroup)?,
        groups_sha256: groups_digest(groups.as_bytes())?,
        privileges_sha256: privileges_digest(privileges.as_bytes())?,
        restricted_sids_sha256: groups_digest(restricted.as_bytes())?,
        integrity_level: sid_string(integrity.Label.Sid)?,
        mandatory_policy: mandatory.Policy,
        session_id: scalar_u32(token, TokenSessionId)?,
        elevation_type: scalar_i32(token, TokenElevationType)? as u32,
        elevated: scalar_struct::<TOKEN_ELEVATION>(token, TokenElevation)?.TokenIsElevated != 0,
        virtualization_allowed: scalar_u32(token, TokenVirtualizationAllowed)? != 0,
        virtualization_enabled: scalar_u32(token, TokenVirtualizationEnabled)? != 0,
        ui_access: scalar_u32(token, TokenUIAccess)? != 0,
        appcontainer: scalar_u32(token, TokenIsAppContainer)? != 0,
        authentication_id,
        token_type: statistics.TokenType as u32,
        impersonation_level: scalar_i32(token, TokenImpersonationLevel)
            .unwrap_or(statistics.ImpersonationLevel) as u32,
    })
}

struct QueryBuffer {
    words: Vec<usize>,
    byte_length: usize,
}

impl QueryBuffer {
    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    fn len(&self) -> usize {
        self.byte_length
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: byte_length never exceeds the allocated word storage.
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.byte_length) }
    }
}

fn query(token: HANDLE, class: i32) -> Result<QueryBuffer, String> {
    let mut length = 0_u32;
    // SAFETY: the null-buffer query writes only the required length.
    unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &raw mut length) };
    if length == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let requested = length as usize;
    let word_count = requested.div_ceil(std::mem::size_of::<usize>());
    let mut words = vec![0_usize; word_count];
    // SAFETY: word storage is native-aligned and has at least the requested
    // writable byte capacity. It remains live for all embedded pointers.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            words.as_mut_ptr().cast::<c_void>(),
            length,
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(QueryBuffer {
        words,
        byte_length: length as usize,
    })
}

fn scalar_u32(token: HANDLE, class: i32) -> Result<u32, String> {
    let buffer = query(token, class)?;
    if buffer.len() < std::mem::size_of::<u32>() {
        return Err("token scalar response is truncated".to_owned());
    }
    // SAFETY: size was checked and read_unaligned copies the scalar.
    Ok(unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) })
}

fn scalar_i32(token: HANDLE, class: i32) -> Result<i32, String> {
    scalar_u32(token, class).map(|value| value as i32)
}

fn scalar_struct<T: Copy>(token: HANDLE, class: i32) -> Result<T, String> {
    let buffer = query(token, class)?;
    if buffer.len() < std::mem::size_of::<T>() {
        return Err("token structure response is truncated".to_owned());
    }
    // SAFETY: size was checked and read_unaligned copies the fixed structure.
    Ok(unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<T>()) })
}

fn groups_digest(buffer: &[u8]) -> Result<String, String> {
    if buffer.len() < std::mem::size_of::<TOKEN_GROUPS>() {
        return Err("token group response is truncated".to_owned());
    }
    // SAFETY: size was checked; read_unaligned copies the fixed header.
    let groups = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_GROUPS>()) };
    let first = groups.Groups.as_ptr();
    // SAFETY: Windows returned GroupCount entries in the variable-size buffer.
    let entries = unsafe { std::slice::from_raw_parts(first, groups.GroupCount as usize) };
    let mut canonical = entries
        .iter()
        .map(|entry| Ok((sid_string(entry.Sid)?, entry.Attributes)))
        .collect::<Result<Vec<_>, String>>()?;
    canonical.sort();
    digest_records(canonical.iter().map(|(sid, attributes)| {
        let mut record = sid.as_bytes().to_vec();
        record.extend_from_slice(&attributes.to_le_bytes());
        record
    }))
}

fn privileges_digest(buffer: &[u8]) -> Result<String, String> {
    if buffer.len() < std::mem::size_of::<TOKEN_PRIVILEGES>() {
        return Err("token privilege response is truncated".to_owned());
    }
    // SAFETY: size was checked; read_unaligned copies the fixed header.
    let privileges = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_PRIVILEGES>()) };
    let first = privileges.Privileges.as_ptr();
    // SAFETY: Windows returned PrivilegeCount entries in the variable-size buffer.
    let entries = unsafe { std::slice::from_raw_parts(first, privileges.PrivilegeCount as usize) };
    let mut canonical = entries
        .iter()
        .map(|entry| (entry.Luid.HighPart, entry.Luid.LowPart, entry.Attributes))
        .collect::<Vec<_>>();
    canonical.sort();
    digest_records(canonical.iter().map(|(high, low, attributes)| {
        let mut record = high.to_le_bytes().to_vec();
        record.extend_from_slice(&low.to_le_bytes());
        record.extend_from_slice(&attributes.to_le_bytes());
        record
    }))
}

fn digest_records(records: impl IntoIterator<Item = Vec<u8>>) -> Result<String, String> {
    let mut digest = Sha256::new();
    for record in records {
        let length =
            u32::try_from(record.len()).map_err(|_| "token record is too large".to_owned())?;
        digest.update(length.to_le_bytes());
        digest.update(record);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(super) fn sid_string(sid: *mut c_void) -> Result<String, String> {
    if sid.is_null() {
        return Err("token contains a null SID".to_owned());
    }
    let mut string = ptr::null_mut();
    // SAFETY: SID comes from a live token information buffer and output is a
    // LocalAlloc UTF-16 string freed below.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut string) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut length = 0;
    // SAFETY: the conversion API returns a NUL-terminated UTF-16 string.
    while unsafe { *string.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: length was determined within the returned NUL-terminated string.
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(string, length) })
        .map_err(|error| error.to_string());
    // SAFETY: string is the exact LocalAlloc result and is freed once.
    unsafe { LocalFree(string.cast()) };
    value
}
