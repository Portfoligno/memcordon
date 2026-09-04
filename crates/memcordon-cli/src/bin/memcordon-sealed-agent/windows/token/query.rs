use super::attestation::open_thread_token;
use super::derivation::*;
use super::service_attestation::RevertGuard;
use super::*;

pub(crate) fn thread_token_attestation(
    thread: HANDLE,
) -> Result<Option<TokenAttestationSnapshot>, String> {
    open_thread_token(thread)?
        .map(|token| token_attestation_snapshot(token.raw()))
        .transpose()
}

pub(crate) fn require_thread_token_absent(thread: HANDLE) -> Result<(), String> {
    if thread_token_attestation(thread)?.is_some() {
        Err("creator thread retained an impersonation token".to_owned())
    } else {
        Ok(())
    }
}

pub(crate) fn attach_creation_carrier_to_thread(
    thread: HANDLE,
    carrier: HANDLE,
) -> Result<TokenAttestationSnapshot, String> {
    require_thread_token_absent(thread)?;
    let requested = token_attestation_snapshot(carrier)?;
    if requested.behavior.enabled_sensitive_privilege_count != 1
        || !privilege_inventory_is_security_only_enabled(&requested.behavior.privileges)?
        || requested.behavior.envelope.token_type != TokenImpersonation as u32
        || requested.behavior.envelope.impersonation_level != SecurityImpersonation as u32
    {
        return Err("remote arm requested a noncanonical creation carrier".to_owned());
    }
    with_session_broker_impersonate_privilege(|| {
        let mut thread = thread;
        // SAFETY: thread is authenticated and opened with SET_THREAD_TOKEN;
        // carrier is the broker-retained, narrow impersonation token.
        if unsafe { SetThreadToken(&raw mut thread, carrier) } == 0 {
            Err(format!(
                "SetThreadToken failed for remote creator: {}",
                io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    })?;
    let observed = thread_token_attestation(thread)?
        .ok_or_else(|| "remote creator token is absent immediately after arming".to_owned())?;
    if observed != requested {
        return Err("remote creator thread token differs from the requested carrier".to_owned());
    }
    Ok(observed)
}

pub(crate) fn current_creation_carrier_attestation() -> Result<TokenAttestationSnapshot, String> {
    let current = thread_token_attestation(unsafe { GetCurrentThread() })?
        .ok_or_else(|| "creator thread was not armed".to_owned())?;
    if current.behavior.enabled_sensitive_privilege_count != 1
        || !privilege_inventory_is_security_only_enabled(&current.behavior.privileges)?
        || current.behavior.envelope.token_type != TokenImpersonation as u32
        || current.behavior.envelope.impersonation_level != SecurityImpersonation as u32
    {
        return Err("creator thread token is not the exact Security-only carrier".to_owned());
    }
    Ok(current)
}

pub(crate) struct AttachedCreationCarrierGuard {
    active: bool,
}

impl AttachedCreationCarrierGuard {
    pub(crate) fn adopt() -> Result<(Self, TokenAttestationSnapshot), String> {
        let evidence = current_creation_carrier_attestation()?;
        Ok((Self { active: true }, evidence))
    }

    pub(crate) fn revert(mut self) -> Result<(), String> {
        revert_creation_carrier_and_attest_absent()?;
        self.active = false;
        Ok(())
    }
}

impl Drop for AttachedCreationCarrierGuard {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            if revert_creation_carrier_and_attest_absent().is_err() {
                unsafe {
                    windows_sys::Win32::System::Threading::TerminateProcess(
                        GetCurrentProcess(),
                        0xED15_0004,
                    )
                };
                std::process::abort();
            }
        }
    }
}

pub(crate) fn revert_creation_carrier_and_attest_absent() -> Result<(), String> {
    // SAFETY: this function is called only after exact carrier attestation on
    // the current creator thread and must synchronously remove that carrier.
    if unsafe { RevertToSelf() } == 0 {
        return Err(format!(
            "creator RevertToSelf failed: {}",
            io::Error::last_os_error()
        ));
    }
    require_current_thread_token_absent()
}

pub(super) fn token_privileges_except_change_notify(
    token: HANDLE,
) -> Result<Vec<LUID_AND_ATTRIBUTES>, String> {
    let name = super::pipe::wide_null("SeChangeNotifyPrivilege");
    let mut keep = windows_sys::Win32::Foundation::LUID::default();
    // SAFETY: name is NUL-terminated and keep is writable.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &raw mut keep) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    token_privileges_except_keep(token, &[keep])
}

pub(super) fn token_privileges_except_keep(
    token: HANDLE,
    keep: &[windows_sys::Win32::Foundation::LUID],
) -> Result<Vec<LUID_AND_ATTRIBUTES>, String> {
    let privileges = query(token, TokenPrivileges)?;
    let entries = token_privilege_entries(privileges.as_bytes())?;
    Ok(entries
        .iter()
        .copied()
        .filter(|entry| {
            !keep.iter().any(|keep| {
                entry.Luid.LowPart == keep.LowPart && entry.Luid.HighPart == keep.HighPart
            })
        })
        .collect())
}

pub(super) fn privilege_inventory_is_change_notify_only(
    inventory: &[String],
) -> Result<bool, String> {
    let prefix = format!(
        "{:x}:{:x}@",
        SE_CHANGE_NOTIFY_PRIVILEGE_LUID.HighPart as u32, SE_CHANGE_NOTIFY_PRIVILEGE_LUID.LowPart
    );
    Ok(matches!(inventory, [entry] if entry.strip_prefix(&prefix).is_some()))
}

pub(super) fn current_process_token_with_access(access: u32) -> Result<OwnedHandle, String> {
    let mut raw_process_token = ptr::null_mut();
    // SAFETY: the current process pseudo-handle is live and the returned token
    // is owned by the local handle wrapper.
    if unsafe {
        OpenProcessToken(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            access,
            &raw mut raw_process_token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    OwnedHandle::new(raw_process_token)
}

pub(super) fn allocated_sid(value: &str) -> Result<*mut c_void, String> {
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
    let source_envelope = envelope(impersonation.raw())?;
    if source_envelope.token_type != TokenImpersonation as u32
        || source_envelope.impersonation_level < SecurityImpersonation as u32
        || source_envelope.impersonation_level > SecurityDelegation as u32
    {
        return Err(
            "MCSEALED-WINDOWS-CALLER-AUTH: caller impersonation level is unsupported".to_owned(),
        );
    }
    if source_envelope.appcontainer {
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
            CALLER_PRIMARY_LAUNCH_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS,
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
    if primary_envelope.token_type != TokenPrimary as u32
        || primary_envelope.impersonation_level != SecurityAnonymous as u32
    {
        return Err(
            "MCSEALED-WINDOWS-CALLER-AUTH: duplicated caller token is not canonical primary"
                .to_owned(),
        );
    }
    let mut expected_primary_envelope = source_envelope;
    expected_primary_envelope.token_type = TokenPrimary as u32;
    expected_primary_envelope.impersonation_level = SecurityAnonymous as u32;
    if primary_envelope != expected_primary_envelope {
        let mismatch_fields =
            envelope_mismatch_fields(&expected_primary_envelope, &primary_envelope);
        return Err(format!(
            "MCSEALED-WINDOWS-CALLER-AUTH: duplicated primary differs from effective caller (fields: {})",
            mismatch_fields.join(", ")
        ));
    }
    let launcher_sid = super::security::service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)
        .map_err(|error| format!("MCSEALED-WINDOWS-CALLER-TOKEN-DACL: peer SID: {error}"))?;
    super::security::converge_token_peer_query(primary.raw(), &launcher_sid)
        .map_err(|error| format!("MCSEALED-WINDOWS-CALLER-TOKEN-DACL: {error}"))?;
    let prepared_envelope = envelope(primary.raw())?;
    if prepared_envelope != primary_envelope {
        let mismatch_fields = envelope_mismatch_fields(&primary_envelope, &prepared_envelope);
        return Err(format!(
            "MCSEALED-WINDOWS-CALLER-TOKEN-DACL: token security preparation changed the caller envelope (fields: {})",
            mismatch_fields.join(", ")
        ));
    }
    let narrowed_primary = duplicate_handle_with_access(
        primary.raw(),
        CALLER_PRIMARY_LAUNCH_ACCESS,
        "MCSEALED-WINDOWS-CALLER-TOKEN-NARROW",
    )?;
    drop(primary);
    let primary = narrowed_primary;
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

pub(super) fn duplicate_handle_with_access(
    source: HANDLE,
    desired_access: u32,
    diagnostic_code: &str,
) -> Result<OwnedHandle, String> {
    duplicate_handle_with_access_result(source, desired_access)
        .map_err(|(error, _)| format!("{diagnostic_code}: {error}"))
}

pub(super) fn duplicate_handle_with_access_result(
    source: HANDLE,
    desired_access: u32,
) -> Result<OwnedHandle, (String, Option<i32>)> {
    let mut duplicate = ptr::null_mut();
    // SAFETY: source and both process pseudo-handles are live. The duplicate
    // is non-inheritable and receives exactly the requested subset of the
    // source handle's granted access.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &raw mut duplicate,
            desired_access,
            0,
            0,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        Err((error.to_string(), error.raw_os_error()))
    } else {
        OwnedHandle::new(duplicate).map_err(|error| (error, None))
    }
}

pub(super) fn reject_fault(
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
    process_token_detailed(process).map_err(|error| error.to_string())
}

#[derive(Debug)]
pub struct TokenOpenError {
    detail: String,
    os_code: Option<i32>,
}

impl TokenOpenError {
    pub const fn os_code(&self) -> Option<i32> {
        self.os_code
    }
}

impl std::fmt::Display for TokenOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

pub fn process_token_detailed(process: HANDLE) -> Result<OwnedHandle, TokenOpenError> {
    let mut token = ptr::null_mut();
    // SAFETY: process is a live process handle with query rights and output
    // ownership transfers into OwnedHandle.
    if unsafe { OpenProcessToken(process, PROCESS_TOKEN_QUERY_ACCESS, &raw mut token) } == 0 {
        let error = io::Error::last_os_error();
        return Err(TokenOpenError {
            detail: error.to_string(),
            os_code: error.raw_os_error(),
        });
    }
    let token = OwnedHandle::new(token).map_err(|detail| TokenOpenError {
        detail,
        os_code: None,
    })?;
    let mut flags = 0_u32;
    // SAFETY: token is live and flags is writable.
    if unsafe { GetHandleInformation(token.raw(), &raw mut flags) } == 0 {
        let error = io::Error::last_os_error();
        return Err(TokenOpenError {
            detail: format!("cannot attest process-token inheritability: {error}"),
            os_code: error.raw_os_error(),
        });
    }
    if flags & HANDLE_FLAG_INHERIT != 0 {
        return Err(TokenOpenError {
            detail: "process-token evidence handle is inheritable".to_owned(),
            os_code: None,
        });
    }
    let granted = handle_granted_access(token.raw()).map_err(|error| TokenOpenError {
        detail: format!(
            "cannot attest process-token granted access: api={} nt_status={:?} {}",
            error.api, error.nt_status, error.detail
        ),
        os_code: error.native_code,
    })?;
    if granted != PROCESS_TOKEN_QUERY_ACCESS {
        return Err(TokenOpenError {
            detail: format!(
                "process-token query handle has wrong granted access: expected={PROCESS_TOKEN_QUERY_ACCESS:#x} actual={granted:#x}"
            ),
            os_code: None,
        });
    }
    Ok(token)
}

pub(crate) fn process_token_query_attestation(
    process: HANDLE,
) -> Result<TokenQueryAttestationSnapshot, String> {
    let first = process_token_detailed(process).map_err(|error| error.to_string())?;
    let first_snapshot = token_query_attestation_snapshot(first.raw())?;
    let second = process_token_detailed(process).map_err(|error| error.to_string())?;
    let second_snapshot = token_query_attestation_snapshot(second.raw())?;
    require_same_process_token_query(
        "process-token-immediate-reopen",
        &first_snapshot,
        &second_snapshot,
    )
    .map_err(|error| error.to_string())?;
    Ok(first_snapshot)
}

pub fn process_user_sid(process: HANDLE) -> Result<String, String> {
    let token = process_token(process)?;
    token_user_sid(token.raw())
}

pub(crate) fn token_user_sid(token: HANDLE) -> Result<String, String> {
    let user = query(token, TokenUser)?;
    // SAFETY: the returned token-user buffer is large enough and remains live.
    let user = unsafe {
        ptr::read_unaligned(
            user.as_ptr()
                .cast::<windows_sys::Win32::Security::TOKEN_USER>(),
        )
    };
    sid_string(user.User.Sid)
}

pub(crate) fn token_logon_sid(token: HANDLE) -> Result<String, String> {
    let groups = query(token, TokenLogonSid)?;
    let entries = token_group_entries(groups.as_bytes())?;
    let [entry] = entries else {
        return Err(format!(
            "TokenLogonSid returned {} entries instead of exactly one",
            entries.len()
        ));
    };
    if entry.Attributes & (SE_GROUP_LOGON_ID as u32) != SE_GROUP_LOGON_ID as u32 {
        return Err("TokenLogonSid entry lacks SE_GROUP_LOGON_ID attributes".to_owned());
    }
    sid_string(entry.Sid)
}

pub(crate) fn token_has_enabled_group(token: HANDLE, expected_sid: &str) -> Result<bool, String> {
    let groups = query(token, TokenGroups)?;
    let entries = token_group_entries(groups.as_bytes())?;
    for entry in entries {
        if enabled_group_entry_matches(entry, expected_sid)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn token_has_restricting_sid(token: HANDLE, expected_sid: &str) -> Result<bool, String> {
    Ok(token_restricting_sid_attributes(token, expected_sid)?.is_some())
}

pub(crate) fn token_restricting_sid_attributes(
    token: HANDLE,
    expected_sid: &str,
) -> Result<Option<u32>, String> {
    let groups = query(token, TokenRestrictedSids)?;
    for entry in token_group_entries(groups.as_bytes())? {
        if restricting_sid_entry_matches(entry, expected_sid)? {
            return Ok(Some(entry.Attributes));
        }
    }
    Ok(None)
}

pub(super) fn token_has_exact_restricting_sid(
    token: HANDLE,
    expected_sid: &str,
    expected_attributes: u32,
) -> Result<bool, String> {
    let groups = query(token, TokenRestrictedSids)?;
    let entries = token_group_entries(groups.as_bytes())?;
    if entries.len() != 1 {
        return Ok(false);
    }
    let entry = &entries[0];
    Ok(entry.Attributes == expected_attributes
        && restricting_sid_entry_matches(entry, expected_sid)?)
}

pub(super) fn token_has_exact_restricting_sid_equal_sid(
    token: HANDLE,
    expected_sid: *mut c_void,
    expected_attributes: u32,
) -> Result<bool, String> {
    let groups = query(token, TokenRestrictedSids)?;
    let entries = token_group_entries(groups.as_bytes())?;
    if entries.len() != 1 || entries[0].Attributes != expected_attributes {
        return Ok(false);
    }
    // SAFETY: the token entry is backed by `groups` and expected_sid is backed
    // by the caller's live well-known-SID buffer for this immediate query.
    Ok(unsafe { EqualSid(entries[0].Sid, expected_sid) } != 0)
}

pub(crate) fn enabled_group_entry_matches(
    entry: &SID_AND_ATTRIBUTES,
    expected_sid: &str,
) -> Result<bool, String> {
    const ENABLED: u32 = 0x0000_0004;
    const DENY_ONLY: u32 = 0x0000_0010;
    Ok(entry.Attributes & ENABLED != 0
        && entry.Attributes & DENY_ONLY == 0
        && sid_string(entry.Sid)? == expected_sid)
}

pub(crate) fn restricting_sid_entry_matches(
    entry: &SID_AND_ATTRIBUTES,
    expected_sid: &str,
) -> Result<bool, String> {
    // TokenRestrictedSids entries do not use ordinary group-enable semantics.
    // CreateRestrictedToken requires their attributes to be zero, and their
    // presence makes them active in the token's second access check.
    Ok(sid_string(entry.Sid)? == expected_sid)
}

pub fn current_thread_envelope() -> Result<WindowsCallerTokenEnvelopeV1, String> {
    let token = current_thread_token()?;
    envelope(token.raw())
}

pub fn current_thread_fixture_snapshot() -> Result<TokenFixtureSnapshot, String> {
    let token = current_thread_token()?;
    token_fixture_snapshot(token.raw())
}

pub(super) fn token_fixture_snapshot(token: HANDLE) -> Result<TokenFixtureSnapshot, String> {
    Ok(TokenFixtureSnapshot {
        envelope: envelope(token)?,
        restricted_sid_count: restricted_sid_count(token)?,
        restricting_sids: token_restricting_sids(token)?,
        token_is_restricted: token_is_restricted(token),
        write_restricted: super::security::write_restricted_behavior_attested(token)?,
        enabled_sensitive_privilege_count: enabled_sensitive_privilege_count(token)?,
        administrator_deny_only: token_group_has_attributes(token, "S-1-5-32-544", 0x0000_0010)?,
    })
}

pub(super) fn token_group_has_attributes(
    token: HANDLE,
    expected_sid: &str,
    required: u32,
) -> Result<bool, String> {
    let groups = query(token, TokenGroups)?;
    let entries = token_group_entries(groups.as_bytes())?;
    for entry in entries {
        if entry.Attributes & required == required && sid_string(entry.Sid)? == expected_sid {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) struct TokenRestrictingSidInventory {
    pub entries: Vec<(String, u32)>,
    pub trustees: Vec<String>,
    pub evidence: Vec<String>,
}

pub(crate) fn token_restricting_sid_inventory(
    token: HANDLE,
) -> Result<TokenRestrictingSidInventory, String> {
    let groups = query(token, TokenRestrictedSids)?;
    let mut entries = token_group_entries(groups.as_bytes())?
        .iter()
        .map(|entry| Ok((sid_string(entry.Sid)?, entry.Attributes)))
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort();
    Ok(TokenRestrictingSidInventory {
        entries: entries.clone(),
        trustees: entries.iter().map(|(sid, _)| sid.clone()).collect(),
        evidence: entries
            .iter()
            .map(|(sid, attributes)| format!("{sid}@{attributes:x}"))
            .collect(),
    })
}

pub(crate) fn token_restricting_sids(token: HANDLE) -> Result<Vec<String>, String> {
    Ok(token_restricting_sid_inventory(token)?.trustees)
}

pub(crate) fn restricted_sid_count(token: HANDLE) -> Result<u32, String> {
    let groups = query(token, TokenRestrictedSids)?;
    u32::try_from(token_group_entries(groups.as_bytes())?.len())
        .map_err(|_| "token restricted SID count is not representable".to_owned())
}

pub(crate) fn token_is_restricted(token: HANDLE) -> bool {
    // SAFETY: caller supplies a live TOKEN_QUERY handle and the API reads it only.
    unsafe { IsTokenRestricted(token) != 0 }
}

pub(super) fn enabled_sensitive_privilege_count(token: HANDLE) -> Result<u32, String> {
    let buffer = query(token, TokenPrivileges)?;
    let entries = token_privilege_entries(buffer.as_bytes())?;
    Ok(entries
        .iter()
        .filter(|entry| privilege_is_enabled_sensitive(entry))
        .count() as u32)
}

pub(super) fn privilege_is_enabled_sensitive(entry: &LUID_AND_ATTRIBUTES) -> bool {
    entry.Attributes & SE_PRIVILEGE_ENABLED != 0
        && (entry.Luid.LowPart != SE_CHANGE_NOTIFY_PRIVILEGE_LUID.LowPart
            || entry.Luid.HighPart != SE_CHANGE_NOTIFY_PRIVILEGE_LUID.HighPart)
}

#[cfg(test)]
pub(crate) fn privilege_is_enabled_sensitive_for_test(
    low_part: u32,
    high_part: i32,
    attributes: u32,
) -> bool {
    privilege_is_enabled_sensitive(&LUID_AND_ATTRIBUTES {
        Luid: LUID {
            LowPart: low_part,
            HighPart: high_part,
        },
        Attributes: attributes,
    })
}

pub(super) fn current_thread_token() -> Result<OwnedHandle, String> {
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
    let statistics = token_statistics(token)?;
    envelope_with_statistics(token, &statistics)
}

pub(super) fn token_statistics(token: HANDLE) -> Result<TOKEN_STATISTICS, String> {
    let statistics = query(token, TokenStatistics)?;
    if statistics.len() < std::mem::size_of::<TOKEN_STATISTICS>() {
        return Err("token statistics response is truncated".to_owned());
    }
    // SAFETY: size was checked and read_unaligned copies the fixed structure.
    Ok(unsafe { ptr::read_unaligned(statistics.as_ptr().cast::<TOKEN_STATISTICS>()) })
}

pub(super) fn envelope_with_statistics(
    token: HANDLE,
    statistics: &TOKEN_STATISTICS,
) -> Result<WindowsCallerTokenEnvelopeV1, String> {
    let user = query(token, TokenUser)?;
    let owner = query(token, TokenOwner)?;
    let primary_group = query(token, TokenPrimaryGroup)?;
    let groups = query(token, TokenGroups)?;
    let privileges = query(token, TokenPrivileges)?;
    let restricted = query(token, TokenRestrictedSids)?;
    let integrity = query(token, TokenIntegrityLevel)?;
    let mandatory = query(token, TokenMandatoryPolicy)?;

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
    let authentication_id = luid_to_u64(&statistics.AuthenticationId);
    let token_type = statistics.TokenType;
    let impersonation_level = if token_type == TokenPrimary {
        // TokenImpersonationLevel is not applicable to a primary token. Zero is
        // the canonical wire representation and is disambiguated by token_type.
        SecurityAnonymous as u32
    } else if token_type == TokenImpersonation {
        let level = scalar_i32(token, TokenImpersonationLevel)?;
        if level < SecurityAnonymous || level > SecurityDelegation {
            return Err("token impersonation level is invalid".to_owned());
        }
        level as u32
    } else {
        return Err("token type is invalid".to_owned());
    };
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
        token_type: token_type as u32,
        impersonation_level,
    })
}

pub(super) fn luid_to_u64(luid: &windows_sys::Win32::Foundation::LUID) -> u64 {
    (u64::from(luid.HighPart as u32) << u32::BITS) | u64::from(luid.LowPart)
}

pub(super) fn group_inventory(token: HANDLE, class: i32) -> Result<Vec<String>, String> {
    let buffer = query(token, class)?;
    let mut inventory = token_group_entries(buffer.as_bytes())?
        .iter()
        .map(|entry| Ok(format!("{}@{:x}", sid_string(entry.Sid)?, entry.Attributes)))
        .collect::<Result<Vec<_>, String>>()?;
    inventory.sort();
    bounded_token_inventory(inventory)
}

pub(super) fn privilege_inventory(token: HANDLE) -> Result<Vec<String>, String> {
    let buffer = query(token, TokenPrivileges)?;
    let mut inventory = token_privilege_entries(buffer.as_bytes())?
        .iter()
        .map(|entry| {
            format!(
                "{:x}:{:x}@{:x}",
                entry.Luid.HighPart as u32, entry.Luid.LowPart, entry.Attributes
            )
        })
        .collect::<Vec<_>>();
    inventory.sort();
    bounded_token_inventory(inventory)
}

pub(super) fn bounded_token_inventory(inventory: Vec<String>) -> Result<Vec<String>, String> {
    let byte_length = inventory
        .iter()
        .try_fold(0_usize, |length, entry| length.checked_add(entry.len()));
    if byte_length.is_none_or(|length| {
        length > memcordon_core::WINDOWS_MAX_FRAME_BYTES / std::mem::size_of::<u32>()
    }) {
        return Err("token diagnostic inventory exceeds its evidence bound".to_owned());
    }
    Ok(inventory)
}

pub(crate) fn envelope_mismatch_fields(
    expected: &WindowsCallerTokenEnvelopeV1,
    actual: &WindowsCallerTokenEnvelopeV1,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if expected.user_sid != actual.user_sid {
        fields.push("user_sid");
    }
    if expected.owner_sid != actual.owner_sid {
        fields.push("owner_sid");
    }
    if expected.primary_group_sid != actual.primary_group_sid {
        fields.push("primary_group_sid");
    }
    if expected.groups_sha256 != actual.groups_sha256 {
        fields.push("groups_sha256");
    }
    if expected.privileges_sha256 != actual.privileges_sha256 {
        fields.push("privileges_sha256");
    }
    if expected.restricted_sids_sha256 != actual.restricted_sids_sha256 {
        fields.push("restricted_sids_sha256");
    }
    if expected.integrity_level != actual.integrity_level {
        fields.push("integrity_level");
    }
    if expected.mandatory_policy != actual.mandatory_policy {
        fields.push("mandatory_policy");
    }
    if expected.session_id != actual.session_id {
        fields.push("session_id");
    }
    if expected.elevation_type != actual.elevation_type {
        fields.push("elevation_type");
    }
    if expected.elevated != actual.elevated {
        fields.push("elevated");
    }
    if expected.virtualization_allowed != actual.virtualization_allowed {
        fields.push("virtualization_allowed");
    }
    if expected.virtualization_enabled != actual.virtualization_enabled {
        fields.push("virtualization_enabled");
    }
    if expected.ui_access != actual.ui_access {
        fields.push("ui_access");
    }
    if expected.appcontainer != actual.appcontainer {
        fields.push("appcontainer");
    }
    if expected.authentication_id != actual.authentication_id {
        fields.push("authentication_id");
    }
    if expected.token_type != actual.token_type {
        fields.push("token_type");
    }
    if expected.impersonation_level != actual.impersonation_level {
        fields.push("impersonation_level");
    }
    fields
}

pub(super) struct QueryBuffer {
    pub(super) words: Vec<usize>,
    pub(super) byte_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TokenQueryPhase {
    SizeProbe,
    Fill,
}

impl TokenQueryPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SizeProbe => "size-probe",
            Self::Fill => "fill",
        }
    }
}

#[derive(Debug)]
pub(super) struct TokenQueryError {
    information_class: i32,
    phase: TokenQueryPhase,
    native_code: Option<i32>,
    detail: String,
}

impl TokenQueryError {
    fn last(information_class: i32, phase: TokenQueryPhase) -> Self {
        let error = io::Error::last_os_error();
        Self {
            information_class,
            phase,
            native_code: error.raw_os_error(),
            detail: error.to_string(),
        }
    }

    #[cfg(test)]
    fn from_native_code(information_class: i32, phase: TokenQueryPhase, native_code: i32) -> Self {
        Self {
            information_class,
            phase,
            native_code: Some(native_code),
            detail: io::Error::from_raw_os_error(native_code).to_string(),
        }
    }
}

impl std::fmt::Display for TokenQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-TOKEN-QUERY: stage=token-information-query api=GetTokenInformation information_class={} phase={} native_code={} detail={}",
            self.information_class,
            self.phase.as_str(),
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail
        )
    }
}

#[cfg(test)]
pub(crate) fn token_query_error_for_test(
    information_class: i32,
    fill: bool,
    native_code: i32,
) -> String {
    TokenQueryError::from_native_code(
        information_class,
        if fill {
            TokenQueryPhase::Fill
        } else {
            TokenQueryPhase::SizeProbe
        },
        native_code,
    )
    .to_string()
}

impl QueryBuffer {
    pub(super) fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    pub(super) fn len(&self) -> usize {
        self.byte_length
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        // SAFETY: byte_length never exceeds the allocated word storage.
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.byte_length) }
    }
}

pub(super) fn query(token: HANDLE, class: i32) -> Result<QueryBuffer, String> {
    let mut length = 0_u32;
    // SAFETY: the null-buffer query writes only the required length.
    unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &raw mut length) };
    if length == 0 {
        return Err(TokenQueryError::last(class, TokenQueryPhase::SizeProbe).to_string());
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
        return Err(TokenQueryError::last(class, TokenQueryPhase::Fill).to_string());
    }
    Ok(QueryBuffer {
        words,
        byte_length: length as usize,
    })
}

pub(super) fn scalar_u32(token: HANDLE, class: i32) -> Result<u32, String> {
    let buffer = query(token, class)?;
    if buffer.len() < std::mem::size_of::<u32>() {
        return Err("token scalar response is truncated".to_owned());
    }
    // SAFETY: size was checked and read_unaligned copies the scalar.
    Ok(unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) })
}

pub(super) fn scalar_i32(token: HANDLE, class: i32) -> Result<i32, String> {
    scalar_u32(token, class).map(|value| value as i32)
}

pub(super) fn scalar_struct<T: Copy>(token: HANDLE, class: i32) -> Result<T, String> {
    let buffer = query(token, class)?;
    if buffer.len() < std::mem::size_of::<T>() {
        return Err("token structure response is truncated".to_owned());
    }
    // SAFETY: size was checked and read_unaligned copies the fixed structure.
    Ok(unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<T>()) })
}

pub(crate) fn groups_digest(buffer: &[u8]) -> Result<String, String> {
    let entries = token_group_entries(buffer)?;
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

pub(crate) fn privileges_digest(buffer: &[u8]) -> Result<String, String> {
    let entries = token_privilege_entries(buffer)?;
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

pub(crate) fn token_group_entries(buffer: &[u8]) -> Result<&[SID_AND_ATTRIBUTES], String> {
    variable_entries(
        buffer,
        std::mem::offset_of!(TOKEN_GROUPS, Groups),
        "token group response",
    )
}

pub(crate) fn token_privilege_entries(buffer: &[u8]) -> Result<&[LUID_AND_ATTRIBUTES], String> {
    variable_entries(
        buffer,
        std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges),
        "token privilege response",
    )
}

pub(super) fn variable_entries<'a, T>(
    buffer: &'a [u8],
    fixed: usize,
    label: &str,
) -> Result<&'a [T], String> {
    if buffer.len() < std::mem::size_of::<u32>() || buffer.len() < fixed {
        return Err(format!("{label} is truncated"));
    }
    // SAFETY: the count field is the first u32 in both TOKEN_GROUPS and
    // TOKEN_PRIVILEGES, and the preceding size check proves it is present.
    let count = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    let bytes = count
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| fixed.checked_add(bytes))
        .ok_or_else(|| format!("{label} size overflowed"))?;
    if bytes > buffer.len() {
        return Err(format!("{label} is truncated"));
    }
    // The native QueryBuffer is usize-aligned. Keep this explicit so callers
    // cannot turn an arbitrary byte slice into an unaligned typed slice.
    let first = unsafe { buffer.as_ptr().add(fixed) }.cast::<T>();
    if first.align_offset(std::mem::align_of::<T>()) != 0 {
        return Err(format!("{label} entries are misaligned"));
    }
    // SAFETY: checked arithmetic proves the live original buffer contains the
    // declared entries, and the alignment check makes the typed slice valid.
    Ok(unsafe { std::slice::from_raw_parts(first, count) })
}

pub(super) fn digest_records(records: impl IntoIterator<Item = Vec<u8>>) -> Result<String, String> {
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

pub(crate) fn sid_string(sid: *mut c_void) -> Result<String, String> {
    if sid.is_null() {
        return Err("token contains a null SID".to_owned());
    }
    let mut string = ptr::null_mut();
    // SAFETY: SID comes from a live token information buffer and output is a
    // LocalAlloc UTF-16 string freed below.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut string) } == 0 {
        let error = io::Error::last_os_error();
        let native_code = error
            .raw_os_error()
            .map_or_else(|| "none".to_owned(), |code| code.to_string());
        return Err(format!(
            "MCSEALED-WINDOWS-TOKEN-ATTESTATION: stage=sid-string-convert api=ConvertSidToStringSidW native_code={native_code} detail={error}"
        ));
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
