use std::ffi::c_void;
use std::io;
use std::ptr;

use memcordon_core::{
    WindowsCallerTokenEnvelopeV1, WindowsSealedFault, WindowsServiceSelfAttestationV1,
    windows_service_attestation_challenge_is_valid,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Wdk::Storage::FileSystem::NtSetInformationToken;
use windows_sys::Win32::Foundation::{
    DuplicateHandle, ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetHandleInformation,
    GetLastError, HANDLE, HANDLE_FLAG_INHERIT, LUID, LocalFree, RtlNtStatusToDosError,
    STATUS_ACCESS_DENIED, SetLastError,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::Security::{
    ACL, AdjustTokenPrivileges, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx,
    GetLengthSid, GetTokenInformation, IsTokenRestricted, LUA_TOKEN, LUID_AND_ATTRIBUTES,
    PRIVILEGE_SET, PrivilegeCheck, RevertToSelf, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES,
    SecurityAnonymous, SecurityDelegation, SecurityImpersonation, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_IMPERSONATE,
    TOKEN_MANDATORY_LABEL, TOKEN_MANDATORY_POLICY, TOKEN_ORIGIN, TOKEN_OWNER, TOKEN_PRIMARY_GROUP,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_QUERY_SOURCE, TOKEN_SOURCE, TOKEN_STATISTICS,
    TokenDefaultDacl, TokenElevation, TokenElevationType, TokenGroups, TokenImpersonation,
    TokenImpersonationLevel, TokenIntegrityLevel, TokenIsAppContainer, TokenLogonSid,
    TokenMandatoryPolicy, TokenOrigin, TokenOwner, TokenPrimary, TokenPrimaryGroup,
    TokenPrivileges, TokenRestrictedSids, TokenSessionId, TokenSource, TokenStatistics,
    TokenUIAccess, TokenUser, TokenVirtualizationAllowed, TokenVirtualizationEnabled,
    WRITE_RESTRICTED,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::SystemServices::{SE_GROUP_INTEGRITY, SE_GROUP_LOGON_ID};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION, SetThreadToken,
};
use windows_sys::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;

use super::pipe::OwnedHandle;

const CALLER_PRIMARY_LAUNCH_ACCESS: u32 = TOKEN_QUERY
    | TOKEN_QUERY_SOURCE
    | TOKEN_DUPLICATE
    | TOKEN_ASSIGN_PRIMARY
    | TOKEN_ADJUST_DEFAULT
    | TOKEN_ADJUST_SESSIONID;
const HOLDER_MUTABLE_TOKEN_ACCESS: u32 = TOKEN_QUERY
    | TOKEN_QUERY_SOURCE
    | TOKEN_DUPLICATE
    | TOKEN_ASSIGN_PRIMARY
    | TOKEN_ADJUST_DEFAULT
    | TOKEN_ADJUST_SESSIONID;
const HOLDER_LAUNCH_TOKEN_ACCESS: u32 =
    TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
pub(crate) const SESSION_CREATION_CARRIER_ACCESS: u32 =
    TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_IMPERSONATE | READ_CONTROL_ACCESS;
const PROCESS_TOKEN_QUERY_ACCESS: u32 = TOKEN_QUERY;
const TOKEN_ATTESTATION_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE;
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;
// MS-LSAD 3.1.1.2.1 defines SeChangeNotifyPrivilege as the stable LUID
// { HighPart: 0, LowPart: 23 }. Snapshot normalization must remain a pure
// function of the supplied token handle, including while the caller is
// impersonating a restricted token, so this value is not resolved through LSA.
const SE_CHANGE_NOTIFY_PRIVILEGE_LUID: LUID = LUID {
    LowPart: 23,
    HighPart: 0,
};
const SESSION_BROKER_RAW_SOURCE_PRIVILEGES: &[(&str, bool)] = &[
    ("SeAssignPrimaryTokenPrivilege", false),
    ("SeIncreaseQuotaPrivilege", false),
    ("SeImpersonatePrivilege", true),
    ("SeSecurityPrivilege", false),
    ("SeTcbPrivilege", true),
    ("SeChangeNotifyPrivilege", true),
];
const SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES: &[(&str, bool)] = &[
    ("SeAssignPrimaryTokenPrivilege", false),
    ("SeIncreaseQuotaPrivilege", false),
    ("SeImpersonatePrivilege", false),
    ("SeSecurityPrivilege", false),
    ("SeTcbPrivilege", false),
    ("SeChangeNotifyPrivilege", true),
];

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

#[derive(Debug)]
pub struct ServiceSelfAttestationError {
    component: &'static str,
    stage: &'static str,
    api: &'static str,
    object_role: &'static str,
    native_code: Option<i32>,
    detail: String,
}

impl ServiceSelfAttestationError {
    fn native(
        component: &'static str,
        stage: &'static str,
        api: &'static str,
        object_role: &'static str,
        error: io::Error,
    ) -> Self {
        Self {
            component,
            stage,
            api,
            object_role,
            native_code: error.raw_os_error(),
            detail: error.to_string(),
        }
    }

    fn semantic(
        component: &'static str,
        stage: &'static str,
        api: &'static str,
        object_role: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            component,
            stage,
            api,
            object_role,
            native_code: None,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ServiceSelfAttestationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-SERVICE-ATTESTATION: component={} stage={} api={} role={} native_code={} detail={}",
            self.component,
            self.stage,
            self.api,
            self.object_role,
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail
        )
    }
}

pub fn service_attestation_challenge(
    component: &'static str,
) -> Result<String, ServiceSelfAttestationError> {
    let mut bytes = [0_u8; 32];
    // SAFETY: system-preferred CNG fills the exact mutable byte array and uses
    // no caller-provided algorithm handle.
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(ServiceSelfAttestationError {
            component,
            stage: "challenge-create",
            api: "BCryptGenRandom",
            object_role: "service-attestation-challenge",
            native_code: Some(status),
            detail: "system-preferred random challenge generation failed".to_owned(),
        });
    }
    const HEX: &[u8] = b"0123456789abcdef";
    Ok(bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect())
}

pub fn current_service_self_attestation(
    component: &'static str,
    service_name: &'static str,
    expected_privileges: &[&str],
    challenge: &str,
) -> Result<WindowsServiceSelfAttestationV1, ServiceSelfAttestationError> {
    if !windows_service_attestation_challenge_is_valid(challenge) {
        return Err(ServiceSelfAttestationError::semantic(
            component,
            "challenge-validate",
            "protocol",
            "service-attestation-challenge",
            "challenge is not a canonical SHA-256 text value",
        ));
    }
    let mut token = ptr::null_mut();
    // SAFETY: the current-process pseudo-handle is live and token receives an
    // owned query handle in the same process.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(ServiceSelfAttestationError::native(
            component,
            "token-open",
            "OpenProcessToken",
            "current-service-token",
            io::Error::last_os_error(),
        ));
    }
    let token = OwnedHandle::new(token).map_err(|detail| {
        ServiceSelfAttestationError::semantic(
            component,
            "token-adopt",
            "OwnedHandle::new",
            "current-service-token",
            detail,
        )
    })?;
    let service_sid = super::security::service_sid(service_name).map_err(|detail| {
        ServiceSelfAttestationError::semantic(
            component,
            "service-sid-derive",
            "RtlCreateServiceSid",
            "current-service-sid",
            detail,
        )
    })?;
    let service_sid_enabled =
        token_has_enabled_group(token.raw(), &service_sid).map_err(|detail| {
            ServiceSelfAttestationError::semantic(
                component,
                "service-sid-enabled-query",
                "GetTokenInformation",
                "current-service-token-groups",
                detail,
            )
        })?;
    let service_sid_restricted =
        token_has_restricting_sid(token.raw(), &service_sid).map_err(|detail| {
            ServiceSelfAttestationError::semantic(
                component,
                "service-sid-restricted-query",
                "GetTokenInformation",
                "current-service-token-restricting-sids",
                detail,
            )
        })?;
    if !service_sid_enabled || !service_sid_restricted {
        return Err(ServiceSelfAttestationError::semantic(
            component,
            "service-sid-validate",
            "GetTokenInformation",
            "current-service-token",
            format!(
                "service_sid_enabled={service_sid_enabled} service_sid_restricted={service_sid_restricted}"
            ),
        ));
    }
    let buffer = query(token.raw(), TokenPrivileges).map_err(|detail| {
        ServiceSelfAttestationError::semantic(
            component,
            "privilege-query",
            "GetTokenInformation",
            "current-service-token-privileges",
            detail,
        )
    })?;
    let entries = token_privilege_entries(buffer.as_bytes()).map_err(|detail| {
        ServiceSelfAttestationError::semantic(
            component,
            "privilege-parse",
            "TOKEN_PRIVILEGES",
            "current-service-token-privileges",
            detail,
        )
    })?;
    let mut required_privileges = Vec::with_capacity(expected_privileges.len());
    for name in expected_privileges {
        let privilege_name = *name;
        let name = super::pipe::wide_null(privilege_name);
        let mut expected_luid = windows_sys::Win32::Foundation::LUID::default();
        // SAFETY: the privilege name is NUL-terminated and the output is writable.
        if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &raw mut expected_luid) } == 0
        {
            return Err(ServiceSelfAttestationError::native(
                component,
                "privilege-lookup",
                "LookupPrivilegeValueW",
                "required-service-privilege",
                io::Error::last_os_error(),
            ));
        }
        if !entries.iter().any(|entry| {
            entry.Luid.LowPart == expected_luid.LowPart
                && entry.Luid.HighPart == expected_luid.HighPart
        }) {
            return Err(ServiceSelfAttestationError::semantic(
                component,
                "privilege-validate",
                "GetTokenInformation",
                "required-service-privilege",
                "required privilege is absent from the current service token",
            ));
        }
        required_privileges.push(privilege_name.to_owned());
    }
    // SAFETY: the pseudo-handle is live for the current process and queried only.
    let process_identity = super::process::process_identity(unsafe { GetCurrentProcess() })
        .map_err(|detail| {
            ServiceSelfAttestationError::semantic(
                component,
                "process-identity",
                "GetProcessTimes",
                "current-service-process",
                detail,
            )
        })?;
    let token_session_id = scalar_u32(token.raw(), TokenSessionId).map_err(|detail| {
        ServiceSelfAttestationError::semantic(
            component,
            "token-session-query",
            "GetTokenInformation",
            "current-service-token-session",
            detail,
        )
    })?;
    Ok(WindowsServiceSelfAttestationV1 {
        schema_version: 1,
        challenge: challenge.to_owned(),
        service_name: service_name.to_owned(),
        process_identity,
        service_sid,
        service_sid_enabled,
        service_sid_restricted,
        token_session_id,
        required_privileges,
    })
}

#[cfg(test)]
pub fn process_envelope(process_id: u32) -> Result<WindowsCallerTokenEnvelopeV1, String> {
    // Test-only cross-process observation of the test process's own token.
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
    token: OwnedHandle,
    fixture_snapshot: TokenFixtureSnapshot,
    attestation_snapshot: TokenAttestationSnapshot,
    active: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectiveThreadTokenIdentity {
    token_id: u64,
    modified_id: u64,
    token_type: u32,
    impersonation_level: u32,
}

#[cfg(test)]
#[derive(Debug)]
struct RestrictedFixtureTokenError {
    stage: &'static str,
    api: &'static str,
    token_role: &'static str,
    requested_access: Option<u32>,
    open_as_self: Option<bool>,
    native_code: Option<i32>,
    detail: String,
}

#[cfg(test)]
impl RestrictedFixtureTokenError {
    fn native(
        stage: &'static str,
        api: &'static str,
        token_role: &'static str,
        requested_access: Option<u32>,
        open_as_self: Option<bool>,
        error: io::Error,
    ) -> Self {
        Self {
            stage,
            api,
            token_role,
            requested_access,
            open_as_self,
            native_code: error.raw_os_error(),
            detail: error.to_string(),
        }
    }

    fn semantic(
        stage: &'static str,
        api: &'static str,
        token_role: &'static str,
        requested_access: Option<u32>,
        open_as_self: Option<bool>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            api,
            token_role,
            requested_access,
            open_as_self,
            native_code: None,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
impl std::fmt::Display for RestrictedFixtureTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-RESTRICTED-FIXTURE: stage={} api={} role={} requested_access={} open_as_self={} native_code={} detail={}",
            self.stage,
            self.api,
            self.token_role,
            self.requested_access
                .map_or_else(|| "none".to_owned(), |access| format!("0x{access:08x}")),
            self.open_as_self
                .map_or_else(|| "none".to_owned(), |value| value.to_string()),
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail,
        )
    }
}

#[cfg(test)]
impl std::error::Error for RestrictedFixtureTokenError {}

#[cfg(test)]
fn restricted_fixture_open_error(error: io::Error) -> RestrictedFixtureTokenError {
    let stage = if error
        .raw_os_error()
        .and_then(|value| u32::try_from(value).ok())
        == Some(ERROR_NO_TOKEN)
    {
        "effective-thread-presence"
    } else {
        "effective-thread-open"
    };
    RestrictedFixtureTokenError::native(
        stage,
        "OpenThreadToken",
        "current-restricted-thread-token",
        Some(TOKEN_QUERY),
        Some(true),
        error,
    )
}

#[cfg(test)]
pub(crate) fn restricted_fixture_open_error_for_test(native_code: i32) -> String {
    restricted_fixture_open_error(io::Error::from_raw_os_error(native_code)).to_string()
}

#[cfg(test)]
fn effective_thread_token_identity() -> Result<EffectiveThreadTokenIdentity, String> {
    let mut observed = ptr::null_mut();
    // SAFETY: the current-thread pseudo-handle is valid, output receives one
    // owned TOKEN_QUERY handle, and OpenAsSelf authorizes the open through the
    // process context without changing which thread-token object is observed.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut observed) } == 0 {
        return Err(restricted_fixture_open_error(io::Error::last_os_error()).to_string());
    }
    let observed = OwnedHandle::new(observed).map_err(|detail| {
        RestrictedFixtureTokenError::semantic(
            "effective-thread-handle-adopt",
            "OwnedHandle::new",
            "current-restricted-thread-token",
            Some(TOKEN_QUERY),
            Some(true),
            detail,
        )
        .to_string()
    })?;
    let statistics = token_statistics(observed.raw()).map_err(|detail| {
        RestrictedFixtureTokenError::semantic(
            "effective-thread-identity-query",
            "GetTokenInformation",
            "current-restricted-thread-token",
            Some(TOKEN_QUERY),
            Some(true),
            detail,
        )
        .to_string()
    })?;
    let identity = EffectiveThreadTokenIdentity {
        token_id: luid_to_u64(&statistics.TokenId),
        modified_id: luid_to_u64(&statistics.ModifiedId),
        token_type: statistics.TokenType as u32,
        impersonation_level: statistics.ImpersonationLevel as u32,
    };
    drop(observed);
    Ok(identity)
}

#[cfg(test)]
fn require_effective_thread_token_identity(
    expected: EffectiveThreadTokenIdentity,
    observed: EffectiveThreadTokenIdentity,
) -> Result<(), String> {
    let mut differences = Vec::new();
    if expected.token_id == 0 {
        differences.push("expected_token_id_zero");
    }
    if observed.token_id == 0 {
        differences.push("observed_token_id_zero");
    }
    if expected.token_id != observed.token_id {
        differences.push("token_id");
    }
    if expected.modified_id != observed.modified_id {
        differences.push("modified_id");
    }
    if expected.token_type != TokenImpersonation as u32
        || observed.token_type != TokenImpersonation as u32
    {
        differences.push("token_type");
    }
    if expected.impersonation_level != SecurityImpersonation as u32
        || observed.impersonation_level != SecurityImpersonation as u32
    {
        differences.push("impersonation_level");
    }
    if differences.is_empty() {
        Ok(())
    } else {
        Err(RestrictedFixtureTokenError::semantic(
            "effective-thread-identity-compare",
            "CompareTokenStatistics",
            "current-restricted-thread-token",
            Some(TOKEN_QUERY),
            Some(true),
            format!("differences={differences:?} expected={expected:?} observed={observed:?}"),
        )
        .to_string())
    }
}

#[cfg(test)]
pub(crate) fn effective_thread_token_identity_validation_for_test(
    expected: (u64, u64, u32, u32),
    observed: (u64, u64, u32, u32),
) -> Result<(), String> {
    let identity = |value: (u64, u64, u32, u32)| EffectiveThreadTokenIdentity {
        token_id: value.0,
        modified_id: value.1,
        token_type: value.2,
        impersonation_level: value.3,
    };
    require_effective_thread_token_identity(identity(expected), identity(observed))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenFixtureSnapshot {
    pub envelope: WindowsCallerTokenEnvelopeV1,
    pub restricted_sid_count: u32,
    pub restricting_sids: Vec<String>,
    pub token_is_restricted: bool,
    pub write_restricted: bool,
    pub enabled_sensitive_privilege_count: u32,
    pub administrator_deny_only: bool,
}

impl RestrictedImpersonationGuard {
    pub fn fixture_snapshot(&self) -> TokenFixtureSnapshot {
        self.fixture_snapshot.clone()
    }

    #[cfg(test)]
    pub(crate) fn with_effective_token_for_test(
        &self,
        operation: impl FnOnce(HANDLE) -> Result<(), String>,
    ) -> Result<(), String> {
        if !self.active {
            return Err(RestrictedFixtureTokenError::semantic(
                "guard-state",
                "RestrictedImpersonationGuard::with_effective_token_for_test",
                "retained-restricted-token",
                None,
                None,
                "restricted impersonation guard is already reverted",
            )
            .to_string());
        }
        let expected = EffectiveThreadTokenIdentity {
            token_id: self.attestation_snapshot.instance.token_id,
            modified_id: self.attestation_snapshot.instance.modified_id,
            token_type: self.attestation_snapshot.behavior.envelope.token_type,
            impersonation_level: self
                .attestation_snapshot
                .behavior
                .envelope
                .impersonation_level,
        };
        // The observer is owned and closed inside this narrow query helper.
        // Only TokenStatistics is read while restricted; full qualification
        // remains the cached pre-install evidence for this exact token object.
        let observed = effective_thread_token_identity()?;
        require_effective_thread_token_identity(expected, observed)?;

        // The closure scopes the raw capability to this active guard. Lend the
        // guard-owned handle, not the independently opened identity observer.
        operation(self.token.raw())
    }

    pub fn revert(mut self) -> Result<(), String> {
        self.revert_checked()
    }

    fn revert_checked(&mut self) -> Result<(), String> {
        if !self.active {
            return Err("restricted impersonation guard is already reverted".to_owned());
        }
        // SAFETY: construction succeeds only after setting this thread's token.
        if unsafe { RevertToSelf() } == 0 {
            return Err(format!(
                "cannot explicitly revert restricted thread impersonation: {}",
                io::Error::last_os_error()
            ));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for RestrictedImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = self.revert_checked();
        }
    }
}

pub fn impersonate_restricted_current_thread() -> Result<RestrictedImpersonationGuard, String> {
    let restricted = restricted_current_primary()?;
    impersonate_primary_token(restricted)
}

pub fn impersonate_write_restricted_current_thread() -> Result<RestrictedImpersonationGuard, String>
{
    let restricted = write_restricted_current_primary()?;
    impersonate_primary_token(restricted)
}

pub fn impersonate_ordinary_current_thread() -> Result<RestrictedImpersonationGuard, String> {
    let restricted = current_primary_without_restricting_sid(DISABLE_MAX_PRIVILEGE | LUA_TOKEN)?;
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
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_IMPERSONATE,
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
    let fixture_snapshot = token_fixture_snapshot(impersonation.raw())?;
    let attestation_snapshot = token_attestation_snapshot(impersonation.raw())?;
    // SAFETY: a null thread pointer selects the current thread and the token is
    // a live impersonation token retained by the returned guard.
    if unsafe { SetThreadToken(ptr::null(), impersonation.raw()) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(RestrictedImpersonationGuard {
        token: impersonation,
        fixture_snapshot,
        attestation_snapshot,
        active: true,
    })
}

pub fn restricted_current_primary() -> Result<OwnedHandle, String> {
    restricted_current_primary_with_flags(DISABLE_MAX_PRIVILEGE)
}

pub fn write_restricted_current_primary() -> Result<OwnedHandle, String> {
    let source = current_process_token_with_access(CALLER_PRIMARY_LAUNCH_ACCESS)?;
    write_restricted_primary_from_source(source.raw())
}

fn write_restricted_primary_from_source(source: HANDLE) -> Result<OwnedHandle, String> {
    let source_envelope = envelope(source)?;
    let restricted = restricted_primary_for_source(
        source,
        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,
        "S-1-5-33",
    )?;
    let restricted_envelope = envelope(restricted.raw())?;
    if restricted_envelope.token_type != TokenPrimary as u32
        || !token_is_restricted(restricted.raw())
        || token_restricting_sid_attributes(restricted.raw(), "S-1-5-33")?.is_none()
        || token_restricting_sid_attributes(restricted.raw(), "S-1-5-12")?.is_some()
        || restricted_sid_count(restricted.raw())? != 1
        || !super::security::write_restricted_behavior_attested(restricted.raw())?
        || enabled_sensitive_privilege_count(restricted.raw())? != 0
        || restricted_envelope.user_sid != source_envelope.user_sid
        || restricted_envelope.authentication_id != source_envelope.authentication_id
        || restricted_envelope.session_id != source_envelope.session_id
    {
        return Err(
            "write-restricted alternate primary failed its token-envelope invariants".to_owned(),
        );
    }
    Ok(restricted)
}

fn nested_initial_thread_token_from_source(source: HANDLE) -> Result<OwnedHandle, String> {
    let source_envelope = envelope(source)?;
    let initial_primary =
        primary_without_restricting_sid_from_source(source, DISABLE_MAX_PRIVILEGE | LUA_TOKEN)?;
    let initial_primary_envelope = envelope(initial_primary.raw())?;
    if initial_primary_envelope.token_type != TokenPrimary as u32
        || initial_primary_envelope.elevated
        || restricted_sid_count(initial_primary.raw())? != 0
        || enabled_sensitive_privilege_count(initial_primary.raw())? != 0
        || initial_primary_envelope.user_sid != source_envelope.user_sid
        || initial_primary_envelope.authentication_id != source_envelope.authentication_id
        || initial_primary_envelope.session_id != source_envelope.session_id
    {
        return Err("nested initial primary failed its token-envelope invariants".to_owned());
    }

    let expected_restricting_sids = canonical_same_access_restricting_sids(initial_primary.raw())?;
    let same_access_primary = restricted_same_access_primary(initial_primary.raw())?;
    let same_access_envelope = envelope(same_access_primary.raw())?;
    let mut expected_same_access_envelope = initial_primary_envelope.clone();
    expected_same_access_envelope.restricted_sids_sha256 =
        same_access_envelope.restricted_sids_sha256.clone();
    let actual_restricting_sids = token_restricting_sids(same_access_primary.raw())?;
    if same_access_envelope != expected_same_access_envelope
        || !token_is_restricted(same_access_primary.raw())
        || actual_restricting_sids.is_empty()
        || actual_restricting_sids != expected_restricting_sids
        || enabled_sensitive_privilege_count(same_access_primary.raw())? != 0
    {
        return Err(
            "nested restricted-same-access primary failed its token-envelope invariants".to_owned(),
        );
    }

    let mut impersonation = ptr::null_mut();
    // SAFETY: same_access_primary is a live primary token and output receives an
    // independently owned, non-inheritable impersonation token.
    if unsafe {
        DuplicateTokenEx(
            same_access_primary.raw(),
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_IMPERSONATE,
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
    let impersonation_envelope = envelope(impersonation.raw())?;
    let mut expected_impersonation_envelope = same_access_envelope;
    expected_impersonation_envelope.token_type = TokenImpersonation as u32;
    expected_impersonation_envelope.impersonation_level = SecurityImpersonation as u32;
    if impersonation_envelope != expected_impersonation_envelope
        || !token_is_restricted(impersonation.raw())
        || token_restricting_sids(impersonation.raw())? != expected_restricting_sids
        || enabled_sensitive_privilege_count(impersonation.raw())? != 0
    {
        return Err("nested initial impersonation failed its token-envelope invariants".to_owned());
    }
    Ok(impersonation)
}

pub(super) struct NestedTargetTokens {
    pub permanent: OwnedHandle,
    pub initial: OwnedHandle,
}

pub(super) fn nested_target_tokens() -> Result<NestedTargetTokens, String> {
    let source = current_process_token_with_access(CALLER_PRIMARY_LAUNCH_ACCESS)?;
    let permanent = write_restricted_primary_from_source(source.raw())?;
    let initial = nested_initial_thread_token_from_source(source.raw())?;
    Ok(NestedTargetTokens { permanent, initial })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenInstanceEvidence {
    pub token_id: u64,
    pub modified_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenLineageEvidence {
    pub authentication_id: u64,
    pub originating_logon_session: u64,
    pub source_name: [u8; 8],
    pub source_identifier: u64,
    pub user_sid: String,
    pub session_id: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenBehaviorEvidence {
    pub envelope: WindowsCallerTokenEnvelopeV1,
    pub groups: Vec<String>,
    pub privileges: Vec<String>,
    pub restricting_sids: Vec<String>,
    pub token_is_restricted: bool,
    pub enabled_sensitive_privilege_count: u32,
    pub default_dacl_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenAttestationSnapshot {
    pub instance: TokenInstanceEvidence,
    pub lineage: TokenLineageEvidence,
    pub behavior: TokenBehaviorEvidence,
}

#[derive(Debug)]
pub(crate) struct SessionBrokerSourceError {
    phase: &'static str,
    field: &'static str,
    privilege: Option<&'static str>,
    requested_access: Option<u32>,
    native_code: Option<i32>,
    expected: String,
    actual: String,
    detail: String,
}

impl SessionBrokerSourceError {
    fn semantic(
        phase: &'static str,
        field: &'static str,
        privilege: Option<&'static str>,
        expected: impl Into<String>,
        actual: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            field,
            privilege,
            requested_access: None,
            native_code: None,
            expected: expected.into(),
            actual: actual.into(),
            detail: detail.into(),
        }
    }

    fn native(
        phase: &'static str,
        field: &'static str,
        privilege: Option<&'static str>,
        requested_access: Option<u32>,
        error: io::Error,
    ) -> Self {
        Self {
            phase,
            field,
            privilege,
            requested_access,
            native_code: error.raw_os_error(),
            expected: "success".to_owned(),
            actual: "native-error".to_owned(),
            detail: error.to_string(),
        }
    }

    fn wrapped(
        phase: &'static str,
        field: &'static str,
        privilege: Option<&'static str>,
        requested_access: Option<u32>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            field,
            privilege,
            requested_access,
            native_code: None,
            expected: "valid".to_owned(),
            actual: "error".to_owned(),
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for SessionBrokerSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-SESSION-BROKER-SOURCE: phase={} field={} privilege={} requested_access={} native_code={} expected={} actual={} detail={}",
            self.phase,
            self.field,
            self.privilege.unwrap_or("none"),
            self.requested_access
                .map_or_else(|| "none".to_owned(), |access| format!("0x{access:08x}")),
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.expected,
            self.actual,
            self.detail,
        )
    }
}

impl std::error::Error for SessionBrokerSourceError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenQueryLineageEvidence {
    pub authentication_id: u64,
    pub originating_logon_session: u64,
    pub user_sid: String,
    pub session_id: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenQueryAttestationSnapshot {
    pub instance: TokenInstanceEvidence,
    pub lineage: TokenQueryLineageEvidence,
    pub behavior: TokenBehaviorEvidence,
}

#[derive(Debug)]
pub(super) struct InstalledThreadTokenAttestation {
    pub requested_after_install: TokenAttestationSnapshot,
    pub observed_thread: TokenAttestationSnapshot,
}

pub(crate) fn token_attestation_snapshot(
    token: HANDLE,
) -> Result<TokenAttestationSnapshot, String> {
    let query = token_query_attestation_snapshot(token)?;
    let source = scalar_struct::<TOKEN_SOURCE>(token, TokenSource)?;
    Ok(TokenAttestationSnapshot {
        instance: query.instance,
        lineage: TokenLineageEvidence {
            authentication_id: query.lineage.authentication_id,
            originating_logon_session: query.lineage.originating_logon_session,
            source_name: source.SourceName.map(|byte| byte as u8),
            source_identifier: luid_to_u64(&source.SourceIdentifier),
            user_sid: query.lineage.user_sid,
            session_id: query.lineage.session_id,
        },
        behavior: query.behavior,
    })
}

pub(crate) fn token_query_attestation_snapshot(
    token: HANDLE,
) -> Result<TokenQueryAttestationSnapshot, String> {
    let statistics = token_statistics(token)?;
    let origin = scalar_struct::<TOKEN_ORIGIN>(token, TokenOrigin)?;
    let envelope = envelope_with_statistics(token, &statistics)?;
    Ok(TokenQueryAttestationSnapshot {
        instance: TokenInstanceEvidence {
            token_id: luid_to_u64(&statistics.TokenId),
            modified_id: luid_to_u64(&statistics.ModifiedId),
        },
        lineage: TokenQueryLineageEvidence {
            authentication_id: luid_to_u64(&statistics.AuthenticationId),
            originating_logon_session: luid_to_u64(&origin.OriginatingLogonSession),
            user_sid: envelope.user_sid.clone(),
            session_id: envelope.session_id,
        },
        behavior: TokenBehaviorEvidence {
            envelope,
            groups: group_inventory(token, TokenGroups)?,
            privileges: privilege_inventory(token)?,
            restricting_sids: group_inventory(token, TokenRestrictedSids)?,
            token_is_restricted: token_is_restricted(token),
            enabled_sensitive_privilege_count: enabled_sensitive_privilege_count(token)?,
            default_dacl_sha256: token_default_dacl_sha256(token)?,
        },
    })
}

fn token_default_dacl_sha256(token: HANDLE) -> Result<Option<String>, String> {
    let buffer = query(token, TokenDefaultDacl)?;
    if buffer.len() < std::mem::size_of::<TOKEN_DEFAULT_DACL>() {
        return Err("token default-DACL response is truncated".to_owned());
    }
    // SAFETY: the fixed-size header was checked and copied without retaining
    // the pointer-bearing structure beyond the live query buffer.
    let default_dacl = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()) };
    if default_dacl.DefaultDacl.is_null() {
        return Ok(None);
    }
    let base = buffer.as_ptr() as usize;
    let end = base
        .checked_add(buffer.len())
        .ok_or_else(|| "token default-DACL buffer range overflowed".to_owned())?;
    let acl_start = default_dacl.DefaultDacl as usize;
    let header_end = acl_start
        .checked_add(std::mem::size_of::<ACL>())
        .ok_or_else(|| "token default-DACL header range overflowed".to_owned())?;
    if acl_start < base || header_end > end {
        return Err("token default-DACL pointer escapes its query buffer".to_owned());
    }
    // SAFETY: the ACL header lies within the live query buffer.
    let acl = unsafe { ptr::read_unaligned(default_dacl.DefaultDacl) };
    let acl_length = usize::from(acl.AclSize);
    let acl_end = acl_start
        .checked_add(acl_length)
        .ok_or_else(|| "token default-DACL range overflowed".to_owned())?;
    if acl_length < std::mem::size_of::<ACL>() || acl_end > end {
        return Err("token default-DACL bytes escape their query buffer".to_owned());
    }
    // SAFETY: the complete ACL range was validated within the live buffer.
    let bytes = unsafe { std::slice::from_raw_parts(default_dacl.DefaultDacl.cast(), acl_length) };
    Ok(Some(super::record::digest(bytes)))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TokenAttestationDifferenceV1 {
    SourceTokenIdZero,
    ProcessTokenIdZero,
    TokenId,
    ModifiedId,
    AuthenticationId,
    OriginatingLogonSession,
    SourceName,
    SourceIdentifier,
    UserSid,
    SessionId,
    OwnerSid,
    PrimaryGroupSid,
    GroupsDigest,
    PrivilegesDigest,
    RestrictingSidsDigest,
    IntegrityLevel,
    MandatoryPolicy,
    ElevationType,
    Elevated,
    VirtualizationAllowed,
    VirtualizationEnabled,
    UiAccess,
    Appcontainer,
    TokenType,
    ImpersonationLevel,
    Groups,
    Privileges,
    RestrictingSids,
    IsTokenRestricted,
    EnabledSensitivePrivilegeCount,
    DefaultDacl,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssignedProcessTokenEvidenceV1 {
    pub source_token_id: u64,
    pub process_token_id: u64,
    pub modified_id: u64,
    pub same_token_id: bool,
}

#[derive(Debug)]
pub(crate) struct TokenAttestationRelationError {
    relation: &'static str,
    source_token_id: u64,
    process_token_id: u64,
    source_modified_id: u64,
    process_modified_id: u64,
    differences: Vec<TokenAttestationDifferenceV1>,
}

impl std::fmt::Display for TokenAttestationRelationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-TOKEN-RELATION: relation={} source_token_id={} process_token_id={} source_modified_id={} process_modified_id={} differences={:?}",
            self.relation,
            self.source_token_id,
            self.process_token_id,
            self.source_modified_id,
            self.process_modified_id,
            self.differences,
        )
    }
}

impl std::error::Error for TokenAttestationRelationError {}

fn token_attestation_difference_fields(
    source: &TokenAttestationSnapshot,
    process: &TokenAttestationSnapshot,
    compare_token_id: bool,
) -> Vec<TokenAttestationDifferenceV1> {
    use TokenAttestationDifferenceV1 as Field;

    let mut fields = Vec::new();
    if source.instance.token_id == 0 {
        fields.push(Field::SourceTokenIdZero);
    }
    if process.instance.token_id == 0 {
        fields.push(Field::ProcessTokenIdZero);
    }
    if compare_token_id && source.instance.token_id != process.instance.token_id {
        fields.push(Field::TokenId);
    }
    if source.instance.modified_id != process.instance.modified_id {
        fields.push(Field::ModifiedId);
    }
    if source.lineage.authentication_id != process.lineage.authentication_id {
        fields.push(Field::AuthenticationId);
    }
    if source.lineage.originating_logon_session != process.lineage.originating_logon_session {
        fields.push(Field::OriginatingLogonSession);
    }
    if source.lineage.source_name != process.lineage.source_name {
        fields.push(Field::SourceName);
    }
    if source.lineage.source_identifier != process.lineage.source_identifier {
        fields.push(Field::SourceIdentifier);
    }
    if source.lineage.user_sid != process.lineage.user_sid {
        fields.push(Field::UserSid);
    }
    if source.lineage.session_id != process.lineage.session_id {
        fields.push(Field::SessionId);
    }
    let expected = &source.behavior.envelope;
    let actual = &process.behavior.envelope;
    for field in envelope_mismatch_fields(expected, actual) {
        fields.push(match field {
            "user_sid" => Field::UserSid,
            "owner_sid" => Field::OwnerSid,
            "primary_group_sid" => Field::PrimaryGroupSid,
            "groups_sha256" => Field::GroupsDigest,
            "privileges_sha256" => Field::PrivilegesDigest,
            "restricted_sids_sha256" => Field::RestrictingSidsDigest,
            "integrity_level" => Field::IntegrityLevel,
            "mandatory_policy" => Field::MandatoryPolicy,
            "session_id" => Field::SessionId,
            "elevation_type" => Field::ElevationType,
            "elevated" => Field::Elevated,
            "virtualization_allowed" => Field::VirtualizationAllowed,
            "virtualization_enabled" => Field::VirtualizationEnabled,
            "ui_access" => Field::UiAccess,
            "appcontainer" => Field::Appcontainer,
            "authentication_id" => Field::AuthenticationId,
            "token_type" => Field::TokenType,
            "impersonation_level" => Field::ImpersonationLevel,
            _ => unreachable!("envelope mismatch field is exhaustive"),
        });
    }
    if source.behavior.groups != process.behavior.groups {
        fields.push(Field::Groups);
    }
    if source.behavior.privileges != process.behavior.privileges {
        fields.push(Field::Privileges);
    }
    if source.behavior.restricting_sids != process.behavior.restricting_sids {
        fields.push(Field::RestrictingSids);
    }
    if source.behavior.token_is_restricted != process.behavior.token_is_restricted {
        fields.push(Field::IsTokenRestricted);
    }
    if source.behavior.enabled_sensitive_privilege_count
        != process.behavior.enabled_sensitive_privilege_count
    {
        fields.push(Field::EnabledSensitivePrivilegeCount);
    }
    if source.behavior.default_dacl_sha256 != process.behavior.default_dacl_sha256 {
        fields.push(Field::DefaultDacl);
    }
    fields.sort_by_key(|field| *field as u8);
    fields.dedup();
    fields.truncate(32);
    fields
}

impl TokenAttestationSnapshot {
    pub(crate) fn query_evidence(&self) -> TokenQueryAttestationSnapshot {
        TokenQueryAttestationSnapshot {
            instance: self.instance.clone(),
            lineage: TokenQueryLineageEvidence {
                authentication_id: self.lineage.authentication_id,
                originating_logon_session: self.lineage.originating_logon_session,
                user_sid: self.lineage.user_sid.clone(),
                session_id: self.lineage.session_id,
            },
            behavior: self.behavior.clone(),
        }
    }
}

fn token_query_difference_fields(
    source: &TokenQueryAttestationSnapshot,
    process: &TokenQueryAttestationSnapshot,
    compare_token_id: bool,
) -> Vec<TokenAttestationDifferenceV1> {
    let source = TokenAttestationSnapshot {
        instance: source.instance.clone(),
        lineage: TokenLineageEvidence {
            authentication_id: source.lineage.authentication_id,
            originating_logon_session: source.lineage.originating_logon_session,
            source_name: [0; 8],
            source_identifier: 0,
            user_sid: source.lineage.user_sid.clone(),
            session_id: source.lineage.session_id,
        },
        behavior: source.behavior.clone(),
    };
    let process = TokenAttestationSnapshot {
        instance: process.instance.clone(),
        lineage: TokenLineageEvidence {
            authentication_id: process.lineage.authentication_id,
            originating_logon_session: process.lineage.originating_logon_session,
            source_name: [0; 8],
            source_identifier: 0,
            user_sid: process.lineage.user_sid.clone(),
            session_id: process.lineage.session_id,
        },
        behavior: process.behavior.clone(),
    };
    token_attestation_difference_fields(&source, &process, compare_token_id)
}

pub(crate) fn require_assigned_process_authority(
    relation: &'static str,
    source: &TokenAttestationSnapshot,
    process: &TokenQueryAttestationSnapshot,
) -> Result<AssignedProcessTokenEvidenceV1, TokenAttestationRelationError> {
    let differences = token_query_difference_fields(&source.query_evidence(), process, false);
    if !differences.is_empty() {
        return Err(TokenAttestationRelationError {
            relation,
            source_token_id: source.instance.token_id,
            process_token_id: process.instance.token_id,
            source_modified_id: source.instance.modified_id,
            process_modified_id: process.instance.modified_id,
            differences,
        });
    }
    Ok(AssignedProcessTokenEvidenceV1 {
        source_token_id: source.instance.token_id,
        process_token_id: process.instance.token_id,
        modified_id: source.instance.modified_id,
        same_token_id: source.instance.token_id == process.instance.token_id,
    })
}

pub(crate) fn require_assigned_token_authority(
    relation: &'static str,
    source: &TokenAttestationSnapshot,
    assigned: &TokenAttestationSnapshot,
) -> Result<AssignedProcessTokenEvidenceV1, TokenAttestationRelationError> {
    let differences = token_attestation_difference_fields(source, assigned, false);
    if !differences.is_empty() {
        return Err(TokenAttestationRelationError {
            relation,
            source_token_id: source.instance.token_id,
            process_token_id: assigned.instance.token_id,
            source_modified_id: source.instance.modified_id,
            process_modified_id: assigned.instance.modified_id,
            differences,
        });
    }
    Ok(AssignedProcessTokenEvidenceV1 {
        source_token_id: source.instance.token_id,
        process_token_id: assigned.instance.token_id,
        modified_id: source.instance.modified_id,
        same_token_id: source.instance.token_id == assigned.instance.token_id,
    })
}

pub(crate) fn require_same_process_token_query(
    relation: &'static str,
    expected: &TokenQueryAttestationSnapshot,
    observed: &TokenQueryAttestationSnapshot,
) -> Result<(), TokenAttestationRelationError> {
    let differences = token_query_difference_fields(expected, observed, true);
    if differences.is_empty() {
        Ok(())
    } else {
        Err(TokenAttestationRelationError {
            relation,
            source_token_id: expected.instance.token_id,
            process_token_id: observed.instance.token_id,
            source_modified_id: expected.instance.modified_id,
            process_modified_id: observed.instance.modified_id,
            differences,
        })
    }
}

pub(crate) fn require_same_token_instance(
    relation: &'static str,
    expected: &TokenAttestationSnapshot,
    observed: &TokenAttestationSnapshot,
) -> Result<(), TokenAttestationRelationError> {
    let differences = token_attestation_difference_fields(expected, observed, true);
    if differences.is_empty() {
        Ok(())
    } else {
        Err(TokenAttestationRelationError {
            relation,
            source_token_id: expected.instance.token_id,
            process_token_id: observed.instance.token_id,
            source_modified_id: expected.instance.modified_id,
            process_modified_id: observed.instance.modified_id,
            differences,
        })
    }
}

pub(crate) fn require_primary_to_impersonation_authority(
    relation: &'static str,
    primary: &TokenAttestationSnapshot,
    impersonation: &TokenAttestationSnapshot,
) -> Result<(), TokenAttestationRelationError> {
    let mut expected = primary.clone();
    // DuplicateTokenEx creates a new token object, but all authority-bearing
    // fields must remain identical.  Only the new token id, token type, and
    // requested SecurityImpersonation level are permitted to differ.
    expected.instance.token_id = impersonation.instance.token_id;
    expected.behavior.envelope.token_type = TokenImpersonation as u32;
    expected.behavior.envelope.impersonation_level = SecurityImpersonation as u32;
    require_same_token_instance(relation, &expected, impersonation)
}

pub(super) fn nested_loader_behavior_failures(
    behavior: &TokenBehaviorEvidence,
) -> Vec<&'static str> {
    let mut failures = Vec::new();
    if behavior.envelope.token_type != TokenImpersonation as u32 {
        failures.push("token_type");
    }
    if behavior.envelope.impersonation_level != SecurityImpersonation as u32 {
        failures.push("impersonation_level");
    }
    if behavior.envelope.elevated {
        failures.push("elevated");
    }
    if behavior.envelope.appcontainer {
        failures.push("appcontainer");
    }
    if behavior.envelope.ui_access {
        failures.push("ui_access");
    }
    if !behavior.token_is_restricted {
        failures.push("token_not_restricted");
    }
    if behavior.restricting_sids.is_empty() {
        failures.push("restricting_sids_empty");
    }
    if behavior.enabled_sensitive_privilege_count != 0 {
        failures.push("enabled_sensitive_privilege_count");
    }
    failures
}

pub(super) fn install_thread_token(
    thread: HANDLE,
    token: HANDLE,
) -> Result<InstalledThreadTokenAttestation, String> {
    let mut thread = thread;
    // SAFETY: thread is the suspended primary thread, token is a live
    // impersonation token, and the mutable local supplies the required handle pointer.
    if unsafe { SetThreadToken(&raw mut thread, token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let requested_after_install = token_attestation_snapshot(token)?;
    let observed = open_thread_token(thread)?.ok_or_else(|| {
        "nested initial thread token was absent immediately after installation".to_owned()
    })?;
    let observed_thread = token_attestation_snapshot(observed.raw())?;
    Ok(InstalledThreadTokenAttestation {
        requested_after_install,
        observed_thread,
    })
}

#[derive(Debug)]
pub struct EntryThreadTokenTransition {
    pub initial_token_id: Option<u64>,
    pub initial_token_envelope: Option<WindowsCallerTokenEnvelopeV1>,
    pub initial_token_behavior_attested: bool,
    pub initial_token_reverted: bool,
    pub thread_token_absent_after_revert: bool,
}

pub fn revert_entry_thread_token() -> Result<EntryThreadTokenTransition, String> {
    let Some(token) = open_thread_token(unsafe { GetCurrentThread() })? else {
        return Ok(EntryThreadTokenTransition {
            initial_token_id: None,
            initial_token_envelope: None,
            initial_token_behavior_attested: false,
            initial_token_reverted: false,
            thread_token_absent_after_revert: true,
        });
    };
    // SAFETY: the current thread has the token opened above. Reverting before
    // inspecting the retained token minimizes the controlled entry window.
    if unsafe { RevertToSelf() } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let initial_token = token_attestation_snapshot(token.raw())?;
    if thread_token_envelope(unsafe { GetCurrentThread() })?.is_some() {
        return Err("entry thread retained an impersonation token after revert".to_owned());
    }
    let initial_token_behavior_attested =
        nested_loader_behavior_failures(&initial_token.behavior).is_empty();
    Ok(EntryThreadTokenTransition {
        initial_token_id: Some(initial_token.instance.token_id),
        initial_token_envelope: Some(initial_token.behavior.envelope),
        initial_token_behavior_attested,
        initial_token_reverted: true,
        thread_token_absent_after_revert: true,
    })
}

fn open_thread_token(thread: HANDLE) -> Result<Option<OwnedHandle>, String> {
    let mut token = ptr::null_mut();
    // SAFETY: thread is a live thread handle or current-thread pseudo-handle;
    // output receives an owned query handle when a token is present. OpenAsSelf
    // makes the query authorization independent of caller-thread impersonation.
    if unsafe { OpenThreadToken(thread, TOKEN_QUERY | TOKEN_QUERY_SOURCE, 1, &raw mut token) } == 0
    {
        let error = io::Error::last_os_error();
        return if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            == Some(ERROR_NO_TOKEN)
        {
            Ok(None)
        } else {
            Err(error.to_string())
        };
    }
    OwnedHandle::new(token).map(Some)
}

fn thread_token_envelope(thread: HANDLE) -> Result<Option<WindowsCallerTokenEnvelopeV1>, String> {
    open_thread_token(thread)?
        .map(|token| envelope(token.raw()))
        .transpose()
}

fn restricted_current_primary_with_flags(flags: u32) -> Result<OwnedHandle, String> {
    restricted_current_primary_for_sid(flags, "S-1-5-12")
}

fn restricted_current_primary_for_sid(
    flags: u32,
    restricting_sid: &str,
) -> Result<OwnedHandle, String> {
    let process_token = current_process_token_with_access(
        CALLER_PRIMARY_LAUNCH_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS,
    )?;
    restricted_primary_for_source(process_token.raw(), flags, restricting_sid)
}

fn restricted_primary_for_source(
    process_token: HANDLE,
    flags: u32,
    restricting_sid: &str,
) -> Result<OwnedHandle, String> {
    let sid = allocated_sid(restricting_sid)?;
    let restricted_sid = SID_AND_ATTRIBUTES {
        Sid: sid,
        Attributes: 0,
    };
    let mut restricted = ptr::null_mut();
    // SAFETY: the input token and single restricting SID remain live for the call;
    // the returned token is transferred into OwnedHandle.
    let created = unsafe {
        CreateRestrictedToken(
            process_token,
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

fn restricted_same_access_primary(source: HANDLE) -> Result<OwnedHandle, String> {
    let user = query(source, TokenUser)?;
    if user.len() < std::mem::size_of::<windows_sys::Win32::Security::TOKEN_USER>() {
        return Err("token user response is truncated".to_owned());
    }
    // SAFETY: the fixed TOKEN_USER structure is present and its SID pointer
    // remains backed by `user` until CreateRestrictedToken returns.
    let user_entry = unsafe {
        ptr::read_unaligned(
            user.as_ptr()
                .cast::<windows_sys::Win32::Security::TOKEN_USER>(),
        )
        .User
    };
    let groups = query(source, TokenGroups)?;
    let group_entries = token_group_entries(groups.as_bytes())?;
    let mut restricting_sids = Vec::with_capacity(
        group_entries
            .len()
            .checked_add(1)
            .ok_or_else(|| "same-access restricting SID count overflowed".to_owned())?,
    );
    restricting_sids.push(SID_AND_ATTRIBUTES {
        Sid: user_entry.Sid,
        Attributes: 0,
    });
    restricting_sids.extend(
        group_entries
            .iter()
            .filter(|entry| entry.Attributes & SE_GROUP_INTEGRITY as u32 == 0)
            .map(|entry| SID_AND_ATTRIBUTES {
                Sid: entry.Sid,
                Attributes: 0,
            }),
    );
    let restricting_sid_count = u32::try_from(restricting_sids.len())
        .map_err(|_| "same-access restricting SID count is not representable".to_owned())?;
    let mut restricted = ptr::null_mut();
    // SAFETY: source is live; every restricting SID points into the live user
    // or group query buffer; CreateRestrictedToken requires zero attributes;
    // and output ownership transfers to OwnedHandle.
    if unsafe {
        CreateRestrictedToken(
            source,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            restricting_sid_count,
            restricting_sids.as_ptr(),
            &raw mut restricted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    OwnedHandle::new(restricted)
}

pub(crate) fn canonical_same_access_restricting_sids(token: HANDLE) -> Result<Vec<String>, String> {
    let mut sids = vec![token_user_sid(token)?];
    let groups = query(token, TokenGroups)?;
    sids.extend(
        token_group_entries(groups.as_bytes())?
            .iter()
            .filter(|entry| entry.Attributes & SE_GROUP_INTEGRITY as u32 == 0)
            .map(|entry| sid_string(entry.Sid))
            .collect::<Result<Vec<_>, _>>()?,
    );
    sids.sort();
    Ok(sids)
}

#[cfg(test)]
pub(crate) fn nested_initial_thread_token_for_test() -> Result<OwnedHandle, String> {
    let source = current_process_token_with_access(CALLER_PRIMARY_LAUNCH_ACCESS)?;
    nested_initial_thread_token_from_source(source.raw())
}

fn current_primary_without_restricting_sid(flags: u32) -> Result<OwnedHandle, String> {
    let process_token = current_process_token_with_access(
        CALLER_PRIMARY_LAUNCH_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS,
    )?;
    primary_without_restricting_sid_from_source(process_token.raw(), flags)
}

fn primary_without_restricting_sid_from_source(
    process_token: HANDLE,
    flags: u32,
) -> Result<OwnedHandle, String> {
    let mut restricted = ptr::null_mut();
    // SAFETY: the source token remains live and all optional SID/privilege
    // inventories are explicitly empty; output transfers to OwnedHandle.
    if unsafe {
        CreateRestrictedToken(
            process_token,
            flags,
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            &raw mut restricted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    OwnedHandle::new(restricted)
}

fn current_process_token() -> Result<OwnedHandle, String> {
    current_process_token_with_access(TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE)
}

/// Opens the local primary token with exactly the rights needed to inspect it
/// and derive the query-only impersonation token required by `AccessCheck`.
pub(crate) fn current_process_token_for_access_check() -> Result<OwnedHandle, String> {
    current_process_token_with_attested_access(TOKEN_QUERY | TOKEN_DUPLICATE, "access-check")
}

/// Opens the token owned by this process with the exact rights needed for a
/// complete query-plus-source attestation snapshot.
pub(crate) fn current_process_token_for_attestation() -> Result<OwnedHandle, String> {
    current_process_token_with_attested_access(TOKEN_ATTESTATION_ACCESS, "source-attestation")
}

/// Opens the owner token for a complete snapshot followed by an AccessCheck
/// that must derive a query-only impersonation token from the primary token.
pub(crate) fn current_process_token_for_attestation_and_access_check() -> Result<OwnedHandle, String>
{
    current_process_token_with_attested_access(
        TOKEN_ATTESTATION_ACCESS | TOKEN_DUPLICATE,
        "source-attestation-and-access-check",
    )
}

fn current_process_token_with_attested_access(
    access: u32,
    purpose: &'static str,
) -> Result<OwnedHandle, String> {
    let token = current_process_token_with_access(access)?;
    let mut flags = 0_u32;
    // SAFETY: token is live and flags is writable.
    if unsafe { GetHandleInformation(token.raw(), &raw mut flags) } == 0 {
        return Err(format!(
            "cannot attest {purpose} token inheritability: {}",
            io::Error::last_os_error()
        ));
    }
    if flags & HANDLE_FLAG_INHERIT != 0 {
        return Err(format!("{purpose} token capability is inheritable"));
    }
    let granted = handle_granted_access(token.raw()).map_err(|error| {
        format!(
            "cannot attest {purpose} token granted access: api={} nt_status={:?} {}",
            error.api, error.nt_status, error.detail
        )
    })?;
    if granted != access {
        return Err(format!(
            "{purpose} token capability has wrong granted access: expected={access:#x} actual={granted:#x}"
        ));
    }
    Ok(token)
}

pub(crate) struct LauncherHolderTokenDerivation {
    pub launch_token: OwnedHandle,
    pub launcher_original: TokenAttestationSnapshot,
    pub holder_effective: TokenAttestationSnapshot,
}

pub(crate) struct SessionBrokerHolderToken {
    pub launch_token: OwnedHandle,
    pub broker_source: TokenAttestationSnapshot,
    pub holder_effective: TokenAttestationSnapshot,
    pub station_creation_carrier: OwnedHandle,
    pub station_creation_evidence: TokenAttestationSnapshot,
    pub desktop_creation_carrier: OwnedHandle,
    pub desktop_creation_evidence: TokenAttestationSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LauncherHolderTokenDerivationStage {
    ThreadTokenPreflight,
    SourceOpen,
    SourceAttestation,
    CarrierDuplicate,
    TcbPrivilegeLookup,
    TcbPrivilegeEnable,
    AssignPrimaryPrivilegeLookup,
    AssignPrimaryPrivilegeEnable,
    CarrierInstall,
    EffectivePrivilegeAttestation,
    MutablePrimaryDuplicate,
    MutableAccessReadback,
    SessionSet,
    CarrierRevert,
    HolderAttestation,
    SourceInvariance,
    HandleNarrow,
    NarrowedAccessReadback,
    NarrowedAuthorityProof,
    NarrowedAttestation,
}

impl LauncherHolderTokenDerivationStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ThreadTokenPreflight => "thread-token-preflight",
            Self::SourceOpen => "source-open",
            Self::SourceAttestation => "source-attestation",
            Self::CarrierDuplicate => "carrier-duplicate",
            Self::TcbPrivilegeLookup => "tcb-privilege-lookup",
            Self::TcbPrivilegeEnable => "tcb-privilege-enable",
            Self::AssignPrimaryPrivilegeLookup => "assign-primary-privilege-lookup",
            Self::AssignPrimaryPrivilegeEnable => "assign-primary-privilege-enable",
            Self::CarrierInstall => "carrier-install",
            Self::EffectivePrivilegeAttestation => "effective-privilege-attestation",
            Self::MutablePrimaryDuplicate => "mutable-primary-duplicate",
            Self::MutableAccessReadback => "mutable-access-readback",
            Self::SessionSet => "session-set",
            Self::CarrierRevert => "carrier-revert",
            Self::HolderAttestation => "holder-attestation",
            Self::SourceInvariance => "source-invariance",
            Self::HandleNarrow => "handle-narrow",
            Self::NarrowedAccessReadback => "narrowed-access-readback",
            Self::NarrowedAuthorityProof => "narrowed-authority-proof",
            Self::NarrowedAttestation => "narrowed-attestation",
        }
    }
}

#[derive(Debug)]
pub(crate) struct LauncherHolderTokenDerivationError {
    pub stage: LauncherHolderTokenDerivationStage,
    pub api: &'static str,
    pub object_role: &'static str,
    pub token_type: &'static str,
    pub requested_access: u32,
    pub target_session_id: u32,
    pub native_code: Option<i32>,
    pub nt_status: Option<i32>,
    pub granted_access: Option<u32>,
    pub thread_token_present_before: bool,
    pub carrier_installed: bool,
    pub carrier_reverted: bool,
    pub detail: String,
}

impl LauncherHolderTokenDerivationError {
    fn new(
        stage: LauncherHolderTokenDerivationStage,
        api: &'static str,
        object_role: &'static str,
        token_type: &'static str,
        requested_access: u32,
        target_session_id: u32,
        native_code: Option<i32>,
        detail: impl ToString,
    ) -> Self {
        Self {
            stage,
            api,
            object_role,
            token_type,
            requested_access,
            target_session_id,
            native_code,
            nt_status: None,
            granted_access: None,
            thread_token_present_before: false,
            carrier_installed: false,
            carrier_reverted: false,
            detail: detail.to_string(),
        }
    }

    fn with_carrier_state(mut self, installed: bool, reverted: bool) -> Self {
        self.carrier_installed = installed;
        self.carrier_reverted = reverted;
        self
    }

    fn with_nt_status(mut self, nt_status: i32) -> Self {
        self.nt_status = Some(nt_status);
        self
    }

    fn with_granted_access(mut self, granted_access: u32) -> Self {
        self.granted_access = Some(granted_access);
        self
    }

    #[cfg(test)]
    pub(crate) fn session_set_for_test(target_session_id: u32, native_code: i32) -> Self {
        Self::new(
            LauncherHolderTokenDerivationStage::SessionSet,
            "NtSetInformationToken",
            "holder-mutable",
            "primary",
            TOKEN_QUERY
                | TOKEN_QUERY_SOURCE
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            target_session_id,
            Some(native_code),
            "injected session-set failure",
        )
        .with_nt_status(STATUS_ACCESS_DENIED)
        .with_granted_access(
            TOKEN_QUERY
                | TOKEN_QUERY_SOURCE
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
        )
        .with_carrier_state(true, true)
    }
}

impl std::fmt::Display for LauncherHolderTokenDerivationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-HOLDER-TOKEN: stage={} api={} object_role={} token_type={} requested_access=0x{:08x} granted_access={} target_session_id={} native_code={:?} nt_status={} thread_token_present_before={} carrier_installed={} carrier_reverted={} detail={}",
            self.stage.as_str(),
            self.api,
            self.object_role,
            self.token_type,
            self.requested_access,
            self.granted_access
                .map_or_else(|| "none".to_owned(), |access| format!("0x{access:08x}"),),
            self.target_session_id,
            self.native_code,
            self.nt_status.map_or_else(
                || "none".to_owned(),
                |status| format!("0x{:08x}", status as u32),
            ),
            self.thread_token_present_before,
            self.carrier_installed,
            self.carrier_reverted,
            self.detail,
        )
    }
}

impl std::error::Error for LauncherHolderTokenDerivationError {}

#[derive(Debug)]
struct ScopedPrivilegeThreadTokenError {
    api: &'static str,
    native_code: Option<i32>,
    detail: String,
}

impl std::fmt::Display for ScopedPrivilegeThreadTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "api={} native_code={} detail={}",
            self.api,
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail,
        )
    }
}

struct ScopedPrivilegeThreadToken {
    active: bool,
}

impl ScopedPrivilegeThreadToken {
    fn install(token: HANDLE) -> Result<Self, ScopedPrivilegeThreadTokenError> {
        require_current_thread_token_absent().map_err(|detail| {
            ScopedPrivilegeThreadTokenError {
                api: "OpenThreadToken",
                native_code: None,
                detail,
            }
        })?;
        if unsafe { SetThreadToken(ptr::null(), token) } == 0 {
            let error = io::Error::last_os_error();
            Err(ScopedPrivilegeThreadTokenError {
                api: "SetThreadToken",
                native_code: error.raw_os_error(),
                detail: error.to_string(),
            })
        } else {
            Ok(Self { active: true })
        }
    }

    fn revert(mut self) -> Result<(), ScopedPrivilegeThreadTokenError> {
        if unsafe { RevertToSelf() } == 0 {
            let error = io::Error::last_os_error();
            return Err(ScopedPrivilegeThreadTokenError {
                api: "RevertToSelf",
                native_code: error.raw_os_error(),
                detail: error.to_string(),
            });
        }
        self.active = false;
        require_current_thread_token_absent().map_err(|detail| {
            ScopedPrivilegeThreadTokenError {
                api: "OpenThreadToken",
                native_code: None,
                detail,
            }
        })?;
        Ok(())
    }
}

impl Drop for ScopedPrivilegeThreadToken {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            if unsafe { RevertToSelf() } == 0 || require_current_thread_token_absent().is_err() {
                unsafe {
                    windows_sys::Win32::System::Threading::TerminateProcess(
                        GetCurrentProcess(),
                        0xED15_0001,
                    )
                };
                std::process::abort();
            }
        }
    }
}

fn require_current_thread_token_absent() -> Result<(), String> {
    match open_thread_token(unsafe { GetCurrentThread() })? {
        None => Ok(()),
        Some(token) => {
            drop(token);
            Err("scoped privileged operation found an existing worker thread token".to_owned())
        }
    }
}

#[derive(Debug)]
struct PackageServiceOwnerPrivilegeError {
    stage: &'static str,
    api: &'static str,
    native_code: Option<i32>,
    detail: String,
}

impl PackageServiceOwnerPrivilegeError {
    fn native(stage: &'static str, api: &'static str, error: io::Error) -> Self {
        Self {
            stage,
            api,
            native_code: error.raw_os_error(),
            detail: error.to_string(),
        }
    }

    fn semantic(stage: &'static str, api: &'static str, detail: impl Into<String>) -> Self {
        Self {
            stage,
            api,
            native_code: None,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for PackageServiceOwnerPrivilegeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-PACKAGE-SERVICE-OWNER: stage={} api={} native_code={} detail={}",
            self.stage,
            self.api,
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail,
        )
    }
}

fn privilege_entries_snapshot(token: HANDLE) -> Result<Vec<LUID_AND_ATTRIBUTES>, String> {
    let privileges = query(token, TokenPrivileges)?;
    let mut entries = token_privilege_entries(privileges.as_bytes())?.to_vec();
    entries.sort_by_key(|entry| (entry.Luid.HighPart, entry.Luid.LowPart));
    Ok(entries)
}

fn exact_enabled_privilege_transition(
    before: &[LUID_AND_ATTRIBUTES],
    after: &[LUID_AND_ATTRIBUTES],
    enabled: &windows_sys::Win32::Foundation::LUID,
) -> bool {
    if before.len() != after.len() {
        return false;
    }
    let mut found = false;
    for (before, after) in before.iter().zip(after) {
        if before.Luid.LowPart != after.Luid.LowPart || before.Luid.HighPart != after.Luid.HighPart
        {
            return false;
        }
        if before.Luid.LowPart == enabled.LowPart && before.Luid.HighPart == enabled.HighPart {
            found = true;
            if before.Attributes & SE_PRIVILEGE_ENABLED != 0
                || after.Attributes != before.Attributes | SE_PRIVILEGE_ENABLED
            {
                return false;
            }
        } else if before.Attributes != after.Attributes {
            return false;
        }
    }
    found
}

fn privilege_snapshots_equal(left: &[LUID_AND_ATTRIBUTES], right: &[LUID_AND_ATTRIBUTES]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.Luid.LowPart == right.Luid.LowPart
                && left.Luid.HighPart == right.Luid.HighPart
                && left.Attributes == right.Attributes
        })
}

pub(crate) fn with_scoped_service_owner_restore_privilege<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    require_current_thread_token_absent().map_err(|detail| {
        PackageServiceOwnerPrivilegeError::semantic(
            "thread-token-preflight",
            "OpenThreadToken",
            detail,
        )
        .to_string()
    })?;
    let source_access = TOKEN_QUERY | TOKEN_DUPLICATE;
    let source =
        current_process_token_with_attested_access(source_access, "package-service-owner-source")
            .map_err(|detail| {
            PackageServiceOwnerPrivilegeError::semantic(
                "process-token-open",
                "OpenProcessToken",
                detail,
            )
            .to_string()
        })?;
    let source_privileges = privilege_entries_snapshot(source.raw()).map_err(|detail| {
        PackageServiceOwnerPrivilegeError::semantic(
            "process-token-baseline",
            "GetTokenInformation",
            detail,
        )
        .to_string()
    })?;

    let carrier_access = TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE;
    let mut carrier = ptr::null_mut();
    // SAFETY: source is a live process token with duplicate access and carrier
    // receives a new non-inheritable disposable impersonation token.
    if unsafe {
        DuplicateTokenEx(
            source.raw(),
            carrier_access,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut carrier,
        )
    } == 0
    {
        return Err(PackageServiceOwnerPrivilegeError::native(
            "carrier-duplicate",
            "DuplicateTokenEx",
            io::Error::last_os_error(),
        )
        .to_string());
    }
    let carrier = OwnedHandle::new(carrier).map_err(|detail| {
        PackageServiceOwnerPrivilegeError::semantic("carrier-duplicate", "OwnedHandle::new", detail)
            .to_string()
    })?;
    let carrier_before = privilege_entries_snapshot(carrier.raw()).map_err(|detail| {
        PackageServiceOwnerPrivilegeError::semantic(
            "carrier-baseline",
            "GetTokenInformation",
            detail,
        )
        .to_string()
    })?;

    let privilege_name = super::pipe::wide_null("SeRestorePrivilege");
    let mut restore = windows_sys::Win32::Foundation::LUID::default();
    // SAFETY: privilege_name is NUL-terminated and restore is writable.
    if unsafe { LookupPrivilegeValueW(ptr::null(), privilege_name.as_ptr(), &raw mut restore) } == 0
    {
        return Err(PackageServiceOwnerPrivilegeError::native(
            "restore-privilege-lookup",
            "LookupPrivilegeValueW",
            io::Error::last_os_error(),
        )
        .to_string());
    }
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: restore,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: carrier is a private disposable token with adjust-privilege
    // access and privileges describes exactly SeRestorePrivilege.
    unsafe { SetLastError(ERROR_SUCCESS) };
    let adjusted = unsafe {
        AdjustTokenPrivileges(
            carrier.raw(),
            0,
            &raw const privileges,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let adjust_error = unsafe { GetLastError() };
    if adjusted == 0 || !matches!(adjust_error, ERROR_SUCCESS) {
        return Err(PackageServiceOwnerPrivilegeError {
            stage: "restore-privilege-enable",
            api: "AdjustTokenPrivileges",
            native_code: Some(adjust_error as i32),
            detail: format!(
                "privilege=SeRestorePrivilege not_all_assigned={}",
                adjust_error == ERROR_NOT_ALL_ASSIGNED
            ),
        }
        .to_string());
    }
    let carrier_after = privilege_entries_snapshot(carrier.raw()).map_err(|detail| {
        PackageServiceOwnerPrivilegeError::semantic(
            "carrier-transition-readback",
            "GetTokenInformation",
            detail,
        )
        .to_string()
    })?;
    if !exact_enabled_privilege_transition(&carrier_before, &carrier_after, &restore) {
        return Err(PackageServiceOwnerPrivilegeError::semantic(
            "carrier-transition-readback",
            "GetTokenInformation",
            "carrier privilege transition was not exactly SeRestorePrivilege enablement",
        )
        .to_string());
    }

    let scoped = ScopedPrivilegeThreadToken::install(carrier.raw()).map_err(|error| {
        PackageServiceOwnerPrivilegeError {
            stage: "carrier-install",
            api: error.api,
            native_code: error.native_code,
            detail: error.detail,
        }
        .to_string()
    })?;
    let result = match effective_thread_privilege_enabled("SeRestorePrivilege") {
        Ok(true) => operation().map_err(|detail| {
            PackageServiceOwnerPrivilegeError::semantic(
                "service-security-apply",
                "SetServiceObjectSecurity",
                detail,
            )
            .to_string()
        }),
        Ok(false) => Err(PackageServiceOwnerPrivilegeError::semantic(
            "effective-privilege-readback",
            "PrivilegeCheck",
            "SeRestorePrivilege is not enabled on the effective thread token",
        )
        .to_string()),
        Err(error) => Err(PackageServiceOwnerPrivilegeError {
            stage: "effective-privilege-readback",
            api: error.api,
            native_code: error.native_code,
            detail: error.detail,
        }
        .to_string()),
    };
    if let Err(error) = scoped.revert() {
        eprintln!(
            "{}",
            PackageServiceOwnerPrivilegeError {
                stage: "carrier-revert",
                api: error.api,
                native_code: error.native_code,
                detail: error.detail,
            }
        );
        // A package worker must never continue after it cannot prove removal
        // of arbitrary-owner assignment authority from its effective token.
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(
                GetCurrentProcess(),
                0xED15_0002,
            )
        };
        std::process::abort();
    }
    drop(carrier);
    let source_after = privilege_entries_snapshot(source.raw()).map_err(|detail| {
        PackageServiceOwnerPrivilegeError::semantic(
            "process-token-invariance",
            "GetTokenInformation",
            detail,
        )
        .to_string()
    })?;
    if !privilege_snapshots_equal(&source_after, &source_privileges) {
        return Err(PackageServiceOwnerPrivilegeError::semantic(
            "process-token-invariance",
            "GetTokenInformation",
            "package process token privilege state changed",
        )
        .to_string());
    }
    drop(source);
    require_current_thread_token_absent().map_err(|detail| {
        PackageServiceOwnerPrivilegeError::semantic(
            "thread-token-residue",
            "OpenThreadToken",
            detail,
        )
        .to_string()
    })?;
    result
}

pub(crate) fn validate_holder_session_derivation(
    launcher: &TokenAttestationSnapshot,
    holder: &TokenAttestationSnapshot,
    target_session_id: u32,
) -> Result<(), String> {
    let mut expected_behavior = launcher.behavior.clone();
    expected_behavior.envelope.session_id = target_session_id;
    let mut expected_lineage = launcher.lineage.clone();
    expected_lineage.session_id = target_session_id;
    if holder.behavior != expected_behavior
        || holder.lineage != expected_lineage
        || holder.behavior.envelope.token_type != TokenPrimary as u32
        || !holder.behavior.token_is_restricted
        || holder.behavior.envelope.user_sid != "S-1-5-18"
    {
        return Err(
            "effective holder token is not a session-only launcher-token derivation".to_owned(),
        );
    }
    Ok(())
}

fn enable_holder_carrier_privilege(
    privilege_carrier: HANDLE,
    privilege_name: &str,
    lookup_stage: LauncherHolderTokenDerivationStage,
    enable_stage: LauncherHolderTokenDerivationStage,
    target_session_id: u32,
) -> Result<(), LauncherHolderTokenDerivationError> {
    let privilege_name_wide = super::pipe::wide_null(privilege_name);
    let mut luid = windows_sys::Win32::Foundation::LUID::default();
    if unsafe { LookupPrivilegeValueW(ptr::null(), privilege_name_wide.as_ptr(), &raw mut luid) }
        == 0
    {
        let error = io::Error::last_os_error();
        return Err(LauncherHolderTokenDerivationError::new(
            lookup_stage,
            "LookupPrivilegeValueW",
            "privilege-carrier",
            "impersonation",
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
            target_session_id,
            error.raw_os_error(),
            format!("privilege={privilege_name} error={error}"),
        ));
    }
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe { SetLastError(ERROR_SUCCESS) };
    let adjusted = unsafe {
        AdjustTokenPrivileges(
            privilege_carrier,
            0,
            &raw const privileges,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let adjust_error = unsafe { GetLastError() };
    if adjusted == 0 || adjust_error != ERROR_SUCCESS {
        return Err(LauncherHolderTokenDerivationError::new(
            enable_stage,
            "AdjustTokenPrivileges",
            "privilege-carrier",
            "impersonation",
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
            target_session_id,
            Some(adjust_error as i32),
            format!(
                "privilege={privilege_name} not_all_assigned={}",
                adjust_error == ERROR_NOT_ALL_ASSIGNED
            ),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct NativeEvidenceError {
    api: &'static str,
    native_code: Option<i32>,
    nt_status: Option<i32>,
    detail: String,
}

impl std::fmt::Display for NativeEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "api={} native_code={} nt_status={} detail={}",
            self.api,
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.nt_status.map_or_else(
                || "none".to_owned(),
                |status| format!("0x{:08x}", status as u32),
            ),
            self.detail,
        )
    }
}

fn nt_status_native_code(status: i32) -> Option<i32> {
    // SAFETY: status is returned directly by an NT native API and the mapper
    // has no pointer or lifetime preconditions.
    i32::try_from(unsafe { RtlNtStatusToDosError(status) }).ok()
}

fn handle_granted_access(handle: HANDLE) -> Result<u32, NativeEvidenceError> {
    let mut basic = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let mut returned = 0_u32;
    // SAFETY: handle remains live, basic is the documented writable buffer for
    // ObjectBasicInformation, and returned receives only the result length.
    let status = unsafe {
        NtQueryObject(
            handle,
            ObjectBasicInformation,
            (&raw mut basic).cast(),
            std::mem::size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32,
            &raw mut returned,
        )
    };
    if status < 0 {
        return Err(NativeEvidenceError {
            api: "NtQueryObject",
            native_code: nt_status_native_code(status),
            nt_status: Some(status),
            detail: format!("ObjectBasicInformation query failed; returned_length={returned}"),
        });
    }
    if returned < std::mem::size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32 {
        return Err(NativeEvidenceError {
            api: "NtQueryObject",
            native_code: None,
            nt_status: Some(status),
            detail: format!(
                "ObjectBasicInformation response was truncated; returned_length={returned}"
            ),
        });
    }
    Ok(basic.GrantedAccess)
}

pub(crate) fn granted_handle_access(handle: HANDLE) -> Result<u32, String> {
    handle_granted_access(handle).map_err(|error| {
        format!(
            "api={} native_code={:?} nt_status={:?} detail={}",
            error.api, error.native_code, error.nt_status, error.detail
        )
    })
}

#[cfg(test)]
pub(crate) fn holder_access_mask_readback_for_test(source: HANDLE) -> Result<(u32, u32), String> {
    let mutable = duplicate_handle_with_access_result(source, HOLDER_MUTABLE_TOKEN_ACCESS)
        .map_err(|(detail, _)| detail)?;
    let launch = duplicate_handle_with_access_result(source, HOLDER_LAUNCH_TOKEN_ACCESS)
        .map_err(|(detail, _)| detail)?;
    let mutable_granted = handle_granted_access(mutable.raw()).map_err(|error| error.detail)?;
    let launch_granted = handle_granted_access(launch.raw()).map_err(|error| error.detail)?;
    token_attestation_snapshot(mutable.raw())?;
    token_attestation_snapshot(launch.raw())?;
    Ok((mutable_granted, launch_granted))
}

fn effective_thread_privilege_enabled(privilege_name: &str) -> Result<bool, NativeEvidenceError> {
    let mut token = ptr::null_mut();
    // SAFETY: the scoped carrier is installed on the current thread and output
    // receives an owned query handle. OpenAsSelf avoids consulting that same
    // impersonation identity for the token-object open.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        let error = io::Error::last_os_error();
        return Err(NativeEvidenceError {
            api: "OpenThreadToken",
            native_code: error.raw_os_error(),
            nt_status: None,
            detail: error.to_string(),
        });
    }
    let token = OwnedHandle::new(token).map_err(|detail| NativeEvidenceError {
        api: "OwnedHandle::new",
        native_code: None,
        nt_status: None,
        detail,
    })?;
    let privilege_name_wide = super::pipe::wide_null(privilege_name);
    let mut luid = windows_sys::Win32::Foundation::LUID::default();
    // SAFETY: the privilege name is NUL-terminated and luid is writable.
    if unsafe { LookupPrivilegeValueW(ptr::null(), privilege_name_wide.as_ptr(), &raw mut luid) }
        == 0
    {
        let error = io::Error::last_os_error();
        return Err(NativeEvidenceError {
            api: "LookupPrivilegeValueW",
            native_code: error.raw_os_error(),
            nt_status: None,
            detail: format!("privilege={privilege_name} error={error}"),
        });
    }
    let mut required = PRIVILEGE_SET {
        PrivilegeCount: 1,
        Control: 1,
        Privilege: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let mut enabled = 0;
    // SAFETY: token has TOKEN_QUERY, required names one valid LUID, and enabled
    // is writable for the Boolean result.
    if unsafe { PrivilegeCheck(token.raw(), &raw mut required, &raw mut enabled) } == 0 {
        let error = io::Error::last_os_error();
        return Err(NativeEvidenceError {
            api: "PrivilegeCheck",
            native_code: error.raw_os_error(),
            nt_status: None,
            detail: format!("privilege={privilege_name} error={error}"),
        });
    }
    Ok(enabled != 0)
}

pub(crate) fn derive_launcher_holder_primary(
    target_session_id: u32,
) -> Result<LauncherHolderTokenDerivation, LauncherHolderTokenDerivationError> {
    if let Err(detail) = require_current_thread_token_absent() {
        let mut error = LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::ThreadTokenPreflight,
            "OpenThreadToken",
            "launcher-worker-thread",
            "impersonation",
            TOKEN_QUERY,
            target_session_id,
            None,
            detail,
        );
        error.thread_token_present_before = true;
        return Err(error);
    }

    let source_access = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE;
    let mut source = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), source_access, &raw mut source) } == 0 {
        let error = io::Error::last_os_error();
        return Err(LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::SourceOpen,
            "OpenProcessToken",
            "launcher-source",
            "primary",
            source_access,
            target_session_id,
            error.raw_os_error(),
            error,
        ));
    }
    let source = OwnedHandle::new(source).map_err(|detail| {
        LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::SourceOpen,
            "OwnedHandle::new",
            "launcher-source",
            "primary",
            source_access,
            target_session_id,
            None,
            detail,
        )
    })?;
    let launcher_original = token_attestation_snapshot(source.raw()).map_err(|detail| {
        LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::SourceAttestation,
            "GetTokenInformation",
            "launcher-source",
            "primary",
            source_access,
            target_session_id,
            None,
            detail,
        )
    })?;

    let carrier_access = TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE;
    let mut privilege_carrier = ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            source.raw(),
            carrier_access,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut privilege_carrier,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        return Err(LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::CarrierDuplicate,
            "DuplicateTokenEx",
            "privilege-carrier",
            "impersonation",
            carrier_access,
            target_session_id,
            error.raw_os_error(),
            error,
        ));
    }
    let privilege_carrier = OwnedHandle::new(privilege_carrier).map_err(|detail| {
        LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::CarrierDuplicate,
            "OwnedHandle::new",
            "privilege-carrier",
            "impersonation",
            carrier_access,
            target_session_id,
            None,
            detail,
        )
    })?;
    enable_holder_carrier_privilege(
        privilege_carrier.raw(),
        "SeTcbPrivilege",
        LauncherHolderTokenDerivationStage::TcbPrivilegeLookup,
        LauncherHolderTokenDerivationStage::TcbPrivilegeEnable,
        target_session_id,
    )?;
    enable_holder_carrier_privilege(
        privilege_carrier.raw(),
        "SeAssignPrimaryTokenPrivilege",
        LauncherHolderTokenDerivationStage::AssignPrimaryPrivilegeLookup,
        LauncherHolderTokenDerivationStage::AssignPrimaryPrivilegeEnable,
        target_session_id,
    )?;
    let scoped = ScopedPrivilegeThreadToken::install(privilege_carrier.raw()).map_err(|error| {
        LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::CarrierInstall,
            error.api,
            "privilege-carrier",
            "impersonation",
            carrier_access,
            target_session_id,
            error.native_code,
            error.detail,
        )
    })?;

    let mutable_access = HOLDER_MUTABLE_TOKEN_ACCESS;
    let launch_access = HOLDER_LAUNCH_TOKEN_ACCESS;
    let operation = (|| {
        for privilege_name in ["SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege"] {
            match effective_thread_privilege_enabled(privilege_name) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(LauncherHolderTokenDerivationError::new(
                        LauncherHolderTokenDerivationStage::EffectivePrivilegeAttestation,
                        "PrivilegeCheck",
                        "launcher-worker-thread",
                        "impersonation",
                        TOKEN_QUERY,
                        target_session_id,
                        None,
                        format!("privilege={privilege_name} is not enabled on the effective thread token"),
                    )
                    .with_carrier_state(true, false));
                }
                Err(error) => {
                    let mut mapped = LauncherHolderTokenDerivationError::new(
                        LauncherHolderTokenDerivationStage::EffectivePrivilegeAttestation,
                        error.api,
                        "launcher-worker-thread",
                        "impersonation",
                        TOKEN_QUERY,
                        target_session_id,
                        error.native_code,
                        format!("privilege={privilege_name} {}", error.detail),
                    )
                    .with_carrier_state(true, false);
                    mapped.nt_status = error.nt_status;
                    return Err(mapped);
                }
            }
        }
        let mut mutable_primary = ptr::null_mut();
        if unsafe {
            DuplicateTokenEx(
                source.raw(),
                mutable_access,
                ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &raw mut mutable_primary,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return Err(LauncherHolderTokenDerivationError::new(
                LauncherHolderTokenDerivationStage::MutablePrimaryDuplicate,
                "DuplicateTokenEx",
                "holder-mutable",
                "primary",
                mutable_access,
                target_session_id,
                error.raw_os_error(),
                error,
            )
            .with_carrier_state(true, false));
        }
        let mutable_primary = OwnedHandle::new(mutable_primary).map_err(|detail| {
            LauncherHolderTokenDerivationError::new(
                LauncherHolderTokenDerivationStage::MutablePrimaryDuplicate,
                "OwnedHandle::new",
                "holder-mutable",
                "primary",
                mutable_access,
                target_session_id,
                None,
                detail,
            )
            .with_carrier_state(true, false)
        })?;
        let mutable_granted_access =
            handle_granted_access(mutable_primary.raw()).map_err(|error| {
                let mut mapped = LauncherHolderTokenDerivationError::new(
                    LauncherHolderTokenDerivationStage::MutableAccessReadback,
                    error.api,
                    "holder-mutable",
                    "primary",
                    mutable_access,
                    target_session_id,
                    error.native_code,
                    error.detail,
                )
                .with_carrier_state(true, false);
                mapped.nt_status = error.nt_status;
                mapped
            })?;
        if mutable_granted_access != mutable_access {
            return Err(LauncherHolderTokenDerivationError::new(
                LauncherHolderTokenDerivationStage::MutableAccessReadback,
                "NtQueryObject",
                "holder-mutable",
                "primary",
                mutable_access,
                target_session_id,
                None,
                "mutable holder token handle was not granted the exact mutation capability",
            )
            .with_granted_access(mutable_granted_access)
            .with_carrier_state(true, false));
        }
        // SAFETY: mutable_primary is an unassigned primary token with the
        // exact read-back mutation rights, the session scalar has the native
        // ULONG representation, and the scoped thread carrier remains active.
        let session_set_status = unsafe {
            NtSetInformationToken(
                mutable_primary.raw(),
                TokenSessionId,
                (&raw const target_session_id).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if session_set_status < 0 {
            return Err(LauncherHolderTokenDerivationError::new(
                LauncherHolderTokenDerivationStage::SessionSet,
                "NtSetInformationToken",
                "holder-mutable",
                "primary",
                mutable_access,
                target_session_id,
                nt_status_native_code(session_set_status),
                "native token session mutation failed",
            )
            .with_nt_status(session_set_status)
            .with_granted_access(mutable_granted_access)
            .with_carrier_state(true, false));
        }
        let launch_token =
            duplicate_handle_with_access_result(mutable_primary.raw(), launch_access).map_err(
                |(detail, native_code)| {
                    LauncherHolderTokenDerivationError::new(
                        LauncherHolderTokenDerivationStage::HandleNarrow,
                        "DuplicateHandle",
                        "holder-launch",
                        "primary",
                        launch_access,
                        target_session_id,
                        native_code,
                        detail,
                    )
                    .with_carrier_state(true, false)
                },
            )?;
        let launch_granted_access = handle_granted_access(launch_token.raw()).map_err(|error| {
            let mut mapped = LauncherHolderTokenDerivationError::new(
                LauncherHolderTokenDerivationStage::NarrowedAccessReadback,
                error.api,
                "holder-launch",
                "primary",
                launch_access,
                target_session_id,
                error.native_code,
                error.detail,
            )
            .with_carrier_state(true, false);
            mapped.nt_status = error.nt_status;
            mapped
        })?;
        if launch_granted_access != launch_access {
            return Err(LauncherHolderTokenDerivationError::new(
                LauncherHolderTokenDerivationStage::NarrowedAccessReadback,
                "NtQueryObject",
                "holder-launch",
                "primary",
                launch_access,
                target_session_id,
                None,
                "narrowed holder token handle was not granted the exact launch capability",
            )
            .with_granted_access(launch_granted_access)
            .with_carrier_state(true, false));
        }
        // SAFETY: this deliberate negative proof uses the live narrowed handle
        // and the same correctly sized session scalar while the carrier is
        // still active, isolating the removed handle rights as the denial.
        let narrowed_session_status = unsafe {
            NtSetInformationToken(
                launch_token.raw(),
                TokenSessionId,
                (&raw const target_session_id).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if narrowed_session_status != STATUS_ACCESS_DENIED {
            return Err(LauncherHolderTokenDerivationError::new(
                LauncherHolderTokenDerivationStage::NarrowedAuthorityProof,
                "NtSetInformationToken",
                "holder-launch",
                "primary",
                launch_access,
                target_session_id,
                nt_status_native_code(narrowed_session_status),
                "narrowed holder launch handle retained session-adjust authority or failed with an unexpected status",
            )
            .with_nt_status(narrowed_session_status)
            .with_granted_access(launch_granted_access)
            .with_carrier_state(true, false));
        }
        Ok((mutable_primary, launch_token))
    })();
    if let Err(error) = scoped.revert() {
        let error = LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::CarrierRevert,
            error.api,
            "privilege-carrier",
            "impersonation",
            carrier_access,
            target_session_id,
            error.native_code,
            error.detail,
        )
        .with_carrier_state(true, false);
        eprintln!("{error}");
        std::process::abort();
    }
    let (mutable_primary, launch_token) =
        operation.map_err(|error| error.with_carrier_state(true, true))?;
    drop(privilege_carrier);

    let holder_effective = token_attestation_snapshot(mutable_primary.raw()).map_err(|detail| {
        LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::HolderAttestation,
            "GetTokenInformation",
            "holder-mutable",
            "primary",
            mutable_access,
            target_session_id,
            None,
            detail,
        )
        .with_carrier_state(true, true)
    })?;
    validate_holder_session_derivation(&launcher_original, &holder_effective, target_session_id)
        .map_err(|detail| {
            LauncherHolderTokenDerivationError::new(
                LauncherHolderTokenDerivationStage::HolderAttestation,
                "validate_holder_session_derivation",
                "holder-mutable",
                "primary",
                mutable_access,
                target_session_id,
                None,
                detail,
            )
            .with_carrier_state(true, true)
        })?;
    if token_attestation_snapshot(source.raw()).map_err(|detail| {
        LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::SourceInvariance,
            "GetTokenInformation",
            "launcher-source",
            "primary",
            source_access,
            target_session_id,
            None,
            detail,
        )
        .with_carrier_state(true, true)
    })? != launcher_original
    {
        return Err(LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::SourceInvariance,
            "token_attestation_snapshot",
            "launcher-source",
            "primary",
            source_access,
            target_session_id,
            None,
            "launcher process token changed during holder derivation",
        )
        .with_carrier_state(true, true));
    }
    drop(mutable_primary);
    if token_attestation_snapshot(launch_token.raw()).map_err(|detail| {
        LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::NarrowedAttestation,
            "GetTokenInformation",
            "holder-launch",
            "primary",
            launch_access,
            target_session_id,
            None,
            detail,
        )
        .with_carrier_state(true, true)
    })? != holder_effective
    {
        return Err(LauncherHolderTokenDerivationError::new(
            LauncherHolderTokenDerivationStage::NarrowedAttestation,
            "token_attestation_snapshot",
            "holder-launch",
            "primary",
            launch_access,
            target_session_id,
            None,
            "narrowed holder launch token changed identity",
        )
        .with_carrier_state(true, true));
    }
    Ok(LauncherHolderTokenDerivation {
        launch_token,
        launcher_original,
        holder_effective,
    })
}

fn privilege_luid(name: &str) -> Result<windows_sys::Win32::Foundation::LUID, String> {
    let name = super::pipe::wide_null(name);
    let mut luid = windows_sys::Win32::Foundation::LUID::default();
    // SAFETY: name is NUL-terminated and luid is writable.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &raw mut luid) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(luid)
    }
}

fn snapshot_has_enabled_group(snapshot: &TokenAttestationSnapshot, sid: &str) -> bool {
    snapshot.behavior.groups.iter().any(|entry| {
        entry
            .split_once('@')
            .is_some_and(|(observed_sid, attributes)| {
                observed_sid == sid
                    && u32::from_str_radix(attributes, 16)
                        .is_ok_and(|attributes| attributes & 0x0000_0004 != 0)
            })
    })
}

fn snapshot_privilege_attributes(
    snapshot: &TokenAttestationSnapshot,
    phase: &'static str,
    name: &'static str,
) -> Result<u32, SessionBrokerSourceError> {
    let luid = privilege_luid(name).map_err(|detail| {
        SessionBrokerSourceError::wrapped(phase, "SourcePrivilegeLookup", Some(name), None, detail)
    })?;
    let prefix = format!("{:x}:{:x}@", luid.HighPart as u32, luid.LowPart);
    let matches = snapshot
        .behavior
        .privileges
        .iter()
        .filter_map(|entry| entry.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(SessionBrokerSourceError::semantic(
            phase,
            "SourcePrivilegeMembership",
            Some(name),
            "exactly-one",
            matches.len().to_string(),
            "source privilege inventory is missing an entry or contains a duplicate",
        ));
    }
    u32::from_str_radix(matches[0], 16).map_err(|_| {
        SessionBrokerSourceError::semantic(
            phase,
            "SourcePrivilegeMembership",
            Some(name),
            "hex-attributes",
            matches[0],
            "source privilege attributes are malformed",
        )
    })
}

fn validate_session_broker_source_snapshot(
    snapshot: &TokenAttestationSnapshot,
    phase: &'static str,
    expected_privileges: &'static [(&'static str, bool)],
    expected_enabled_sensitive: u32,
) -> Result<(), SessionBrokerSourceError> {
    let mismatch = |field, expected: String, actual: String, detail| {
        SessionBrokerSourceError::semantic(phase, field, None, expected, actual, detail)
    };
    if snapshot.lineage.user_sid != "S-1-5-18" {
        return Err(mismatch(
            "SourceUserSid",
            "S-1-5-18".to_owned(),
            snapshot.lineage.user_sid.clone(),
            "session broker source user is not LocalSystem",
        ));
    }
    if snapshot.lineage.session_id != 0 {
        return Err(mismatch(
            "SourceSessionId",
            "0".to_owned(),
            snapshot.lineage.session_id.to_string(),
            "session broker source is not bound to session 0",
        ));
    }
    if snapshot.behavior.envelope.token_type != TokenPrimary as u32 {
        return Err(mismatch(
            "SourceTokenType",
            (TokenPrimary as u32).to_string(),
            snapshot.behavior.envelope.token_type.to_string(),
            "session broker source is not a primary token",
        ));
    }
    if snapshot.behavior.token_is_restricted {
        return Err(mismatch(
            "SourceRestrictedState",
            "false".to_owned(),
            "true".to_owned(),
            "session broker source is restricted",
        ));
    }
    if !snapshot.behavior.restricting_sids.is_empty() {
        return Err(mismatch(
            "SourceRestrictingSidInventory",
            "0".to_owned(),
            snapshot.behavior.restricting_sids.len().to_string(),
            "session broker source has restricting SIDs",
        ));
    }
    let broker_sid = super::security::service_sid(
        memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME,
    )
    .map_err(|detail| {
        SessionBrokerSourceError::wrapped(phase, "SourceBrokerSid", None, None, detail)
    })?;
    if !snapshot_has_enabled_group(snapshot, &broker_sid) {
        return Err(mismatch(
            "SourceBrokerSid",
            "present-enabled".to_owned(),
            "missing-or-disabled".to_owned(),
            "session broker service SID is not enabled",
        ));
    }
    if !snapshot_has_enabled_group(snapshot, "S-1-5-32-544") {
        return Err(mismatch(
            "SourceAdministratorsSid",
            "present-enabled".to_owned(),
            "missing-or-disabled".to_owned(),
            "BUILTIN\\Administrators is not enabled",
        ));
    }
    if snapshot.behavior.privileges.len() != expected_privileges.len() {
        return Err(mismatch(
            "SourcePrivilegeMembership",
            expected_privileges.len().to_string(),
            snapshot.behavior.privileges.len().to_string(),
            "session broker source privilege inventory has the wrong count",
        ));
    }
    if !snapshot
        .behavior
        .privileges
        .windows(2)
        .all(|entries| entries[0] < entries[1])
    {
        return Err(mismatch(
            "SourcePrivilegeMembership",
            "strictly-sorted-unique".to_owned(),
            "noncanonical-order-or-duplicate".to_owned(),
            "session broker source privilege inventory is not canonical",
        ));
    }
    for &(name, expected_enabled) in expected_privileges {
        let attributes = snapshot_privilege_attributes(snapshot, phase, name)?;
        if attributes & SE_PRIVILEGE_REMOVED != 0 {
            return Err(SessionBrokerSourceError::semantic(
                phase,
                "SourcePrivilegeMembership",
                Some(name),
                "present-not-removed",
                format!("attributes=0x{attributes:08x}"),
                "session broker source privilege is marked removed",
            ));
        }
        let actual_enabled = attributes & SE_PRIVILEGE_ENABLED != 0;
        if actual_enabled != expected_enabled {
            return Err(SessionBrokerSourceError::semantic(
                phase,
                "SourcePrivilegeState",
                Some(name),
                if expected_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                if actual_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                format!("observed_attributes=0x{attributes:08x}"),
            ));
        }
    }
    if snapshot.behavior.enabled_sensitive_privilege_count != expected_enabled_sensitive {
        return Err(mismatch(
            "SourceEnabledSensitivePrivilegeCount",
            expected_enabled_sensitive.to_string(),
            snapshot
                .behavior
                .enabled_sensitive_privilege_count
                .to_string(),
            "session broker source enabled-sensitive count is not exact",
        ));
    }
    Ok(())
}

pub(crate) fn validate_normalized_session_broker_source_snapshot(
    snapshot: &TokenAttestationSnapshot,
) -> Result<(), SessionBrokerSourceError> {
    validate_session_broker_source_snapshot(
        snapshot,
        "normalized-source-validation",
        SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES,
        0,
    )
}

fn exact_disabled_privilege_transition(
    before: &[LUID_AND_ATTRIBUTES],
    after: &[LUID_AND_ATTRIBUTES],
    disabled: &windows_sys::Win32::Foundation::LUID,
) -> bool {
    if before.len() != after.len() {
        return false;
    }
    let mut found = false;
    for (before, after) in before.iter().zip(after) {
        if before.Luid.LowPart != after.Luid.LowPart || before.Luid.HighPart != after.Luid.HighPart
        {
            return false;
        }
        if before.Luid.LowPart == disabled.LowPart && before.Luid.HighPart == disabled.HighPart {
            found = true;
            if before.Attributes & SE_PRIVILEGE_ENABLED == 0
                || after.Attributes != before.Attributes & !SE_PRIVILEGE_ENABLED
            {
                return false;
            }
        } else if before.Attributes != after.Attributes {
            return false;
        }
    }
    found
}

fn exact_disabled_privilege_set_transition(
    before: &[LUID_AND_ATTRIBUTES],
    after: &[LUID_AND_ATTRIBUTES],
    disabled: &[windows_sys::Win32::Foundation::LUID],
) -> bool {
    if before.len() != after.len() {
        return false;
    }
    let mut found = vec![false; disabled.len()];
    for (before, after) in before.iter().zip(after) {
        if before.Luid.LowPart != after.Luid.LowPart || before.Luid.HighPart != after.Luid.HighPart
        {
            return false;
        }
        if let Some((index, _)) = disabled.iter().enumerate().find(|(_, luid)| {
            before.Luid.LowPart == luid.LowPart && before.Luid.HighPart == luid.HighPart
        }) {
            found[index] = true;
            if before.Attributes & SE_PRIVILEGE_ENABLED == 0
                || after.Attributes != before.Attributes & !SE_PRIVILEGE_ENABLED
            {
                return false;
            }
        } else if before.Attributes != after.Attributes {
            return false;
        }
    }
    found.into_iter().all(|found| found)
}

pub(crate) fn exact_disabled_privilege_set_transition_for_test(
    before: &[LUID_AND_ATTRIBUTES],
    after: &[LUID_AND_ATTRIBUTES],
    disabled: &[windows_sys::Win32::Foundation::LUID],
) -> bool {
    exact_disabled_privilege_set_transition(before, after, disabled)
}

pub(crate) fn normalized_session_broker_privilege_entries_for_test(
    entries: &[LUID_AND_ATTRIBUTES],
) -> Result<bool, String> {
    if entries.len() != SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES.len() {
        return Ok(false);
    }
    if !entries.windows(2).all(|entries| {
        (entries[0].Luid.HighPart, entries[0].Luid.LowPart)
            < (entries[1].Luid.HighPart, entries[1].Luid.LowPart)
    }) {
        return Ok(false);
    }
    let expected = SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES
        .iter()
        .map(|(name, enabled)| privilege_luid(name).map(|luid| (luid, *enabled)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(expected.iter().all(|(luid, enabled)| {
        let matches = entries
            .iter()
            .filter(|entry| {
                entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart
            })
            .collect::<Vec<_>>();
        matches.len() == 1
            && matches[0].Attributes & SE_PRIVILEGE_REMOVED == 0
            && (matches[0].Attributes & SE_PRIVILEGE_ENABLED != 0) == *enabled
    }))
}

fn exact_session_broker_source_snapshot_transition(
    before: &TokenAttestationSnapshot,
    after: &TokenAttestationSnapshot,
) -> bool {
    if before.instance.token_id != after.instance.token_id
        || before.instance.modified_id == after.instance.modified_id
    {
        return false;
    }
    let mut expected = before.clone();
    expected.instance.modified_id = after.instance.modified_id;
    expected.behavior.privileges = after.behavior.privileges.clone();
    expected.behavior.enabled_sensitive_privilege_count =
        after.behavior.enabled_sensitive_privilege_count;
    expected.behavior.envelope.privileges_sha256 =
        after.behavior.envelope.privileges_sha256.clone();
    expected == *after
}

fn disable_session_broker_source_privilege(
    token: HANDLE,
    name: &'static str,
) -> Result<(), SessionBrokerSourceError> {
    let luid = privilege_luid(name).map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "privilege-disable",
            "SourcePrivilegeLookup",
            Some(name),
            None,
            detail,
        )
    })?;
    let before = privilege_entries_snapshot(token).map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "privilege-disable",
            "SourcePrivilegeReadback",
            Some(name),
            None,
            detail,
        )
    })?;
    let adjustment = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: 0,
        }],
    };
    unsafe { SetLastError(ERROR_SUCCESS) };
    if unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            &raw const adjustment,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(SessionBrokerSourceError::native(
            "privilege-disable",
            "SourcePrivilegeState",
            Some(name),
            Some(TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES),
            io::Error::last_os_error(),
        ));
    }
    if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        return Err(SessionBrokerSourceError::semantic(
            "privilege-disable",
            "SourcePrivilegeMembership",
            Some(name),
            "assigned",
            "not-assigned",
            "AdjustTokenPrivileges reported ERROR_NOT_ALL_ASSIGNED",
        ));
    }
    let after = privilege_entries_snapshot(token).map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "privilege-disable",
            "SourcePrivilegeReadback",
            Some(name),
            None,
            detail,
        )
    })?;
    if !exact_disabled_privilege_transition(&before, &after, &luid) {
        return Err(SessionBrokerSourceError::semantic(
            "transition-proof",
            "SourcePrivilegeTransition",
            Some(name),
            "only-SE_PRIVILEGE_ENABLED-cleared",
            "unexpected-inventory-or-attribute-change",
            "source privilege disable transition was not exact",
        ));
    }
    Ok(())
}

pub(crate) fn normalize_current_session_broker_source_privileges()
-> Result<TokenAttestationSnapshot, SessionBrokerSourceError> {
    require_current_thread_token_absent().map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "thread-token-preflight",
            "SourceThreadTokenAbsence",
            None,
            None,
            detail,
        )
    })?;
    let source_access = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES;
    let source =
        current_process_token_with_attested_access(source_access, "broker-source-normalization")
            .map_err(|detail| {
                SessionBrokerSourceError::wrapped(
                    "source-open",
                    "SourceHandleAccess",
                    None,
                    Some(source_access),
                    detail,
                )
            })?;
    let before = token_attestation_snapshot(source.raw()).map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "pre-attestation",
            "SourceSnapshot",
            None,
            Some(source_access),
            detail,
        )
    })?;
    validate_session_broker_source_snapshot(
        &before,
        "pre-attestation",
        SESSION_BROKER_RAW_SOURCE_PRIVILEGES,
        2,
    )?;
    let raw_before = privilege_entries_snapshot(source.raw()).map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "pre-attestation",
            "SourcePrivilegeReadback",
            None,
            Some(source_access),
            detail,
        )
    })?;
    disable_session_broker_source_privilege(source.raw(), "SeImpersonatePrivilege")?;
    disable_session_broker_source_privilege(source.raw(), "SeTcbPrivilege")?;
    let raw_after = privilege_entries_snapshot(source.raw()).map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "post-attestation",
            "SourcePrivilegeReadback",
            None,
            Some(source_access),
            detail,
        )
    })?;
    let disabled = [
        privilege_luid("SeImpersonatePrivilege").map_err(|detail| {
            SessionBrokerSourceError::wrapped(
                "transition-proof",
                "SourcePrivilegeLookup",
                Some("SeImpersonatePrivilege"),
                None,
                detail,
            )
        })?,
        privilege_luid("SeTcbPrivilege").map_err(|detail| {
            SessionBrokerSourceError::wrapped(
                "transition-proof",
                "SourcePrivilegeLookup",
                Some("SeTcbPrivilege"),
                None,
                detail,
            )
        })?,
    ];
    if !exact_disabled_privilege_set_transition(&raw_before, &raw_after, &disabled) {
        return Err(SessionBrokerSourceError::semantic(
            "transition-proof",
            "SourcePrivilegeTransition",
            None,
            "only-Impersonate-and-Tcb-enabled-bits-cleared",
            "unexpected-inventory-or-attribute-change",
            "aggregate source privilege transition was not exact",
        ));
    }
    let after = token_attestation_snapshot(source.raw()).map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "post-attestation",
            "SourceSnapshot",
            None,
            Some(source_access),
            detail,
        )
    })?;
    validate_session_broker_source_snapshot(
        &after,
        "post-attestation",
        SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES,
        0,
    )?;
    if !exact_session_broker_source_snapshot_transition(&before, &after) {
        return Err(SessionBrokerSourceError::semantic(
            "transition-proof",
            "SourceSnapshotTransition",
            None,
            "only-ModifiedId-privilege-digest-inventory-and-enabled-count-change",
            "unrelated-source-field-changed",
            "source normalization changed identity, lineage, groups, restrictions, envelope, or default DACL",
        ));
    }
    drop(source);
    require_current_thread_token_absent().map_err(|detail| {
        SessionBrokerSourceError::wrapped(
            "thread-token-postflight",
            "SourceThreadTokenAbsence",
            None,
            None,
            detail,
        )
    })?;
    Ok(after)
}

fn derive_exact_session_broker_carrier(
    source: HANDLE,
    purpose: &'static str,
    allowed_privileges: &[&str],
) -> Result<OwnedHandle, String> {
    let access = TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE;
    let mut carrier = ptr::null_mut();
    // SAFETY: source is the normalized process primary and output receives one
    // private, disposable impersonation token.
    if unsafe {
        DuplicateTokenEx(
            source,
            access,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut carrier,
        )
    } == 0
    {
        return Err(format!(
            "cannot duplicate exact {purpose} carrier: {}",
            io::Error::last_os_error()
        ));
    }
    let carrier = OwnedHandle::new(carrier)?;
    if handle_granted_access(carrier.raw()).map_err(|error| error.detail)? != access {
        return Err(format!("{purpose} carrier access is not exact"));
    }
    let allowed_luids = allowed_privileges
        .iter()
        .map(|name| privilege_luid(name))
        .collect::<Result<Vec<_>, _>>()?;
    for privilege in token_privileges_except_keep(carrier.raw(), &allowed_luids)? {
        let removal = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: privilege.Luid,
                Attributes: SE_PRIVILEGE_REMOVED,
            }],
        };
        unsafe { SetLastError(ERROR_SUCCESS) };
        if unsafe {
            AdjustTokenPrivileges(
                carrier.raw(),
                0,
                &raw const removal,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
            || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED
        {
            return Err(format!(
                "cannot remove forbidden privilege from {purpose} carrier: {}",
                io::Error::last_os_error()
            ));
        }
    }
    for (&name, luid) in allowed_privileges.iter().zip(&allowed_luids) {
        let enable = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: *luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe { SetLastError(ERROR_SUCCESS) };
        if unsafe {
            AdjustTokenPrivileges(
                carrier.raw(),
                0,
                &raw const enable,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
            || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED
        {
            return Err(format!(
                "cannot enable {name} on {purpose} carrier: {}",
                io::Error::last_os_error()
            ));
        }
    }
    let entries = privilege_entries_snapshot(carrier.raw())?;
    if entries.len() != allowed_luids.len()
        || !allowed_luids.iter().all(|luid| {
            entries.iter().any(|entry| {
                entry.Luid.LowPart == luid.LowPart
                    && entry.Luid.HighPart == luid.HighPart
                    && entry.Attributes & SE_PRIVILEGE_ENABLED != 0
                    && entry.Attributes & SE_PRIVILEGE_REMOVED == 0
            })
        })
    {
        return Err(format!(
            "{purpose} carrier failed exact enabled privilege-inventory attestation"
        ));
    }
    let evidence = token_query_attestation_snapshot(carrier.raw())?;
    if evidence.behavior.envelope.token_type != TokenImpersonation as u32
        || evidence.behavior.envelope.impersonation_level != SecurityImpersonation as u32
        || evidence.behavior.enabled_sensitive_privilege_count
            != u32::try_from(allowed_privileges.len())
                .map_err(|_| "carrier privilege count overflowed".to_owned())?
    {
        return Err(format!(
            "{purpose} carrier failed exact token-shape attestation"
        ));
    }
    Ok(carrier)
}

fn privilege_inventory_is_security_only_enabled(inventory: &[String]) -> Result<bool, String> {
    let security = privilege_luid("SeSecurityPrivilege")?;
    let prefix = format!("{:x}:{:x}@", security.HighPart as u32, security.LowPart);
    Ok(
        matches!(inventory, [entry] if entry.strip_prefix(&prefix).is_some_and(|attributes| {
            u32::from_str_radix(attributes, 16)
                .is_ok_and(|attributes| attributes & SE_PRIVILEGE_ENABLED != 0)
        })),
    )
}

fn derive_target_session_security_carrier(
    source: HANDLE,
    target_session_id: u32,
    mutable_access: u32,
    role: &str,
) -> Result<(OwnedHandle, TokenAttestationSnapshot), String> {
    let mut mutable = ptr::null_mut();
    // SAFETY: source is live and the broker's scoped TCB carrier is installed;
    // output receives a private unassigned primary seed.
    if unsafe {
        DuplicateTokenEx(
            source,
            mutable_access,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut mutable,
        )
    } == 0
    {
        return Err(format!(
            "cannot duplicate {role} creation-carrier seed: {}",
            io::Error::last_os_error()
        ));
    }
    let mutable = OwnedHandle::new(mutable)?;
    if handle_granted_access(mutable.raw()).map_err(|error| error.detail)? != mutable_access {
        return Err(format!("{role} creation-carrier seed access is not exact"));
    }
    // SAFETY: mutable is unassigned, storage is an exact ULONG, and TCB is
    // enabled only on the broker-local derivation carrier.
    let status = unsafe {
        NtSetInformationToken(
            mutable.raw(),
            TokenSessionId,
            (&raw const target_session_id).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if status < 0 {
        return Err(format!(
            "{role} creation-carrier TokenSessionId mutation failed: nt_status={status:#x}"
        ));
    }
    let security = privilege_luid("SeSecurityPrivilege")?;
    for privilege in token_privileges_except_keep(mutable.raw(), &[security])? {
        let removal = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: privilege.Luid,
                Attributes: 0x0000_0004,
            }],
        };
        unsafe { SetLastError(ERROR_SUCCESS) };
        if unsafe {
            AdjustTokenPrivileges(
                mutable.raw(),
                0,
                &raw const removal,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
            || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED
        {
            return Err(format!(
                "cannot remove non-Security privilege from {role} creation carrier: {}",
                io::Error::last_os_error()
            ));
        }
    }
    let enable = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: security,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe { SetLastError(ERROR_SUCCESS) };
    if unsafe {
        AdjustTokenPrivileges(
            mutable.raw(),
            0,
            &raw const enable,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
        || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED
    {
        return Err(format!(
            "cannot enable SeSecurityPrivilege on {role} creation carrier: {}",
            io::Error::last_os_error()
        ));
    }
    let carrier_security = super::security::SecurityDescriptor::from_sddl(
        &super::security::session_creation_carrier_token_sddl()?,
    )?;
    let carrier_attributes = carrier_security.attributes(false);
    let mut carrier = ptr::null_mut();
    // SAFETY: the seed is live and contains exactly enabled Security; output
    // receives a narrow, non-inheritable impersonation token with protected DACL.
    if unsafe {
        DuplicateTokenEx(
            mutable.raw(),
            SESSION_CREATION_CARRIER_ACCESS,
            &raw const carrier_attributes,
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut carrier,
        )
    } == 0
    {
        return Err(format!(
            "cannot narrow {role} creation carrier: {}",
            io::Error::last_os_error()
        ));
    }
    let carrier = OwnedHandle::new(carrier)?;
    if handle_granted_access(carrier.raw()).map_err(|error| error.detail)?
        != SESSION_CREATION_CARRIER_ACCESS
    {
        return Err(format!("{role} creation-carrier access is not exact"));
    }
    carrier_security
        .verify_kernel_object(carrier.raw(), super::security::SecurityObjectKind::Token)?;
    let evidence = token_attestation_snapshot(carrier.raw())?;
    if evidence.lineage.user_sid != "S-1-5-18"
        || evidence.lineage.session_id != target_session_id
        || evidence.behavior.token_is_restricted
        || !evidence.behavior.restricting_sids.is_empty()
        || evidence.behavior.enabled_sensitive_privilege_count != 1
        || !privilege_inventory_is_security_only_enabled(&evidence.behavior.privileges)?
        || evidence.behavior.envelope.token_type != TokenImpersonation as u32
        || evidence.behavior.envelope.impersonation_level != SecurityImpersonation as u32
        || !token_has_enabled_group(carrier.raw(), "S-1-5-32-544")?
    {
        return Err(format!(
            "{role} creation carrier failed exact target-session Security-only attestation"
        ));
    }
    Ok((carrier, evidence))
}

pub(crate) fn derive_session_broker_holder_primary(
    target_session_id: u32,
) -> Result<SessionBrokerHolderToken, String> {
    require_current_thread_token_absent()?;
    let source_access = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE;
    let source = current_process_token_with_attested_access(source_access, "broker-source")?;
    let broker_source = token_attestation_snapshot(source.raw())?;
    let broker_sid =
        super::security::service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    validate_normalized_session_broker_source_snapshot(&broker_source)
        .map_err(|error| error.to_string())?;

    let carrier = derive_exact_session_broker_carrier(
        source.raw(),
        "holder-derivation-tcb-only",
        &["SeTcbPrivilege"],
    )?;
    let scoped =
        ScopedPrivilegeThreadToken::install(carrier.raw()).map_err(|error| error.to_string())?;

    let mutable_access = TOKEN_QUERY
        | TOKEN_QUERY_SOURCE
        | TOKEN_DUPLICATE
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_PRIVILEGES
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | WRITE_DAC_ACCESS
        | READ_CONTROL_ACCESS;
    let operation = (|| -> Result<
        (
            OwnedHandle,
            OwnedHandle,
            TokenAttestationSnapshot,
            OwnedHandle,
            TokenAttestationSnapshot,
        ),
        String,
    > {
        if !effective_thread_privilege_enabled("SeTcbPrivilege")
            .map_err(|error| error.to_string())?
        {
            return Err(
                "session-broker holder-derivation carrier did not enable SeTcbPrivilege"
                    .to_owned(),
            );
        }
        let mut mutable = ptr::null_mut();
        // SAFETY: the source and effective carrier are live; output receives an
        // unassigned mutable primary used only inside this transaction.
        if unsafe {
            DuplicateTokenEx(
                source.raw(),
                mutable_access,
                ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &raw mut mutable,
            )
        } == 0
        {
            return Err(format!(
                "cannot duplicate session-broker mutable primary: {}",
                io::Error::last_os_error()
            ));
        }
        let mutable = OwnedHandle::new(mutable)?;
        let granted = handle_granted_access(mutable.raw()).map_err(|error| error.detail)?;
        if granted != mutable_access {
            return Err(format!(
                "session-broker mutable primary access mismatch: expected={mutable_access:#x} actual={granted:#x}"
            ));
        }
        // SAFETY: mutable is unassigned, session storage is exact ULONG, and
        // SeTcbPrivilege remains enabled on the disposable thread carrier.
        let status = unsafe {
            NtSetInformationToken(
                mutable.raw(),
                TokenSessionId,
                (&raw const target_session_id).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if status < 0 {
            return Err(format!(
                "session-broker TokenSessionId mutation failed: nt_status={status:#x}"
            ));
        }

        let delete_privileges = token_privileges_except_change_notify(mutable.raw())?;
        for privilege in delete_privileges {
            let removal = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: privilege.Luid,
                    Attributes: 0x0000_0004,
                }],
            };
            // SAFETY: mutable is private and has adjust-privilege access; the
            // one-entry removal structure remains live for the call.
            unsafe { SetLastError(ERROR_SUCCESS) };
            if unsafe {
                AdjustTokenPrivileges(
                    mutable.raw(),
                    0,
                    &raw const removal,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } == 0
                || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED
            {
                return Err(format!(
                    "cannot remove session-holder privilege: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        let default = super::security::SecurityDescriptor::from_sddl(
            &super::security::session_holder_default_dacl_sddl()?,
        )?;
        let default_dacl = TOKEN_DEFAULT_DACL {
            DefaultDacl: default.dacl()?,
        };
        // SAFETY: mutable is private; descriptor storage remains
        // live and owns the ACL through this synchronous token update.
        if unsafe {
            SetTokenInformation(
                mutable.raw(),
                TokenDefaultDacl,
                (&raw const default_dacl).cast(),
                std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        } == 0
        {
            return Err(format!(
                "cannot set session-holder default DACL: {}",
                io::Error::last_os_error()
            ));
        }
        let object_security = super::security::SecurityDescriptor::from_sddl(
            &super::security::session_holder_token_sddl()?,
        )?;
        object_security
            .apply_dacl_to_kernel_object_detailed(mutable.raw())
            .map_err(|error| error.to_string())?;
        object_security
            .verify_kernel_object(mutable.raw(), super::security::SecurityObjectKind::Token)?;
        let (station_creation_carrier, station_creation_evidence) =
            derive_target_session_security_carrier(
                source.raw(),
                target_session_id,
                mutable_access,
                "station",
            )?;
        let (desktop_creation_carrier, desktop_creation_evidence) =
            derive_target_session_security_carrier(
                source.raw(),
                target_session_id,
                mutable_access,
                "desktop",
            )?;
        if station_creation_evidence.instance.token_id
            == desktop_creation_evidence.instance.token_id
        {
            return Err("station and desktop creation carriers reused one token instance".to_owned());
        }
        Ok((
            mutable,
            station_creation_carrier,
            station_creation_evidence,
            desktop_creation_carrier,
            desktop_creation_evidence,
        ))
    })();
    if let Err(error) = scoped.revert() {
        eprintln!("session-broker carrier reversion failed: {error}");
        std::process::abort();
    }
    let (
        final_token,
        station_creation_carrier,
        station_creation_evidence,
        desktop_creation_carrier,
        desktop_creation_evidence,
    ) = operation?;
    drop(carrier);

    let holder_effective = token_attestation_snapshot(final_token.raw())?;
    if holder_effective.lineage.user_sid != "S-1-5-18"
        || holder_effective.lineage.session_id != target_session_id
        || holder_effective.behavior.token_is_restricted
        || !holder_effective.behavior.restricting_sids.is_empty()
        || holder_effective.behavior.enabled_sensitive_privilege_count != 0
        || !privilege_inventory_is_change_notify_only(&holder_effective.behavior.privileges)?
        || holder_effective.behavior.envelope.token_type != TokenPrimary as u32
        || !token_has_enabled_group(final_token.raw(), &broker_sid)?
        || station_creation_evidence.instance.token_id == broker_source.instance.token_id
        || station_creation_evidence.instance.token_id == holder_effective.instance.token_id
        || desktop_creation_evidence.instance.token_id == broker_source.instance.token_id
        || desktop_creation_evidence.instance.token_id == holder_effective.instance.token_id
    {
        return Err(
            "session-holder final token failed unrestricted least-privilege attestation".to_owned(),
        );
    }
    if token_attestation_snapshot(source.raw())? != broker_source {
        return Err("session-broker source token changed during holder derivation".to_owned());
    }

    let launch_access = HOLDER_LAUNCH_TOKEN_ACCESS;
    let launch_token = duplicate_handle_with_access(
        final_token.raw(),
        launch_access,
        "MCSEALED-WINDOWS-SESSION-BROKER-HOLDER-TOKEN-NARROW",
    )?;
    if handle_granted_access(launch_token.raw()).map_err(|error| error.detail)? != launch_access {
        return Err("session-holder launch handle was not narrowed exactly".to_owned());
    }
    drop(final_token);
    drop(source);
    require_current_thread_token_absent()?;
    Ok(SessionBrokerHolderToken {
        launch_token,
        broker_source,
        holder_effective,
        station_creation_carrier,
        station_creation_evidence,
        desktop_creation_carrier,
        desktop_creation_evidence,
    })
}

pub(crate) fn with_session_broker_launch_privileges<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    require_current_thread_token_absent()?;
    let source = current_process_token_with_attested_access(
        TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE,
        "broker-launch-source",
    )?;
    let source_before = token_attestation_snapshot(source.raw())?;
    validate_normalized_session_broker_source_snapshot(&source_before)
        .map_err(|error| error.to_string())?;
    let carrier = derive_exact_session_broker_carrier(
        source.raw(),
        "holder-launch-assign-primary-increase-quota",
        &["SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"],
    )?;
    let scoped =
        ScopedPrivilegeThreadToken::install(carrier.raw()).map_err(|error| error.to_string())?;
    let result = (|| {
        for name in ["SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"] {
            if !effective_thread_privilege_enabled(name).map_err(|error| error.to_string())? {
                return Err(format!(
                    "session-broker launch carrier privilege is not enabled: {name}"
                ));
            }
        }
        operation()
    })();
    if let Err(error) = scoped.revert() {
        eprintln!("session-broker launch-carrier reversion failed: {error}");
        std::process::abort();
    }
    drop(carrier);
    require_current_thread_token_absent()?;
    if token_attestation_snapshot(source.raw())? != source_before {
        return Err("session-broker source changed during holder launch".to_owned());
    }
    drop(source);
    result
}

fn with_session_broker_impersonate_privilege<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    require_current_thread_token_absent()?;
    let source = current_process_token_with_attested_access(
        TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE,
        "broker-remote-arm-source",
    )?;
    let source_before = token_attestation_snapshot(source.raw())?;
    validate_normalized_session_broker_source_snapshot(&source_before)
        .map_err(|error| error.to_string())?;
    let carrier = derive_exact_session_broker_carrier(
        source.raw(),
        "remote-arm-impersonate-only",
        &["SeImpersonatePrivilege"],
    )?;
    let scoped =
        ScopedPrivilegeThreadToken::install(carrier.raw()).map_err(|error| error.to_string())?;
    let result = (|| {
        if !effective_thread_privilege_enabled("SeImpersonatePrivilege")
            .map_err(|error| error.to_string())?
        {
            return Err(
                "broker remote-arm carrier did not enable SeImpersonatePrivilege".to_owned(),
            );
        }
        operation()
    })();
    if let Err(error) = scoped.revert() {
        eprintln!("session-broker impersonate-carrier reversion failed: {error}");
        std::process::abort();
    }
    drop(carrier);
    require_current_thread_token_absent()?;
    if token_attestation_snapshot(source.raw())? != source_before {
        return Err("broker source changed during remote thread-token arm".to_owned());
    }
    drop(source);
    result
}

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

fn token_privileges_except_change_notify(
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

fn token_privileges_except_keep(
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

fn privilege_inventory_is_change_notify_only(inventory: &[String]) -> Result<bool, String> {
    let prefix = format!(
        "{:x}:{:x}@",
        SE_CHANGE_NOTIFY_PRIVILEGE_LUID.HighPart as u32, SE_CHANGE_NOTIFY_PRIVILEGE_LUID.LowPart
    );
    Ok(matches!(inventory, [entry] if entry.strip_prefix(&prefix).is_some()))
}

fn current_process_token_with_access(access: u32) -> Result<OwnedHandle, String> {
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

fn duplicate_handle_with_access(
    source: HANDLE,
    desired_access: u32,
    diagnostic_code: &str,
) -> Result<OwnedHandle, String> {
    duplicate_handle_with_access_result(source, desired_access)
        .map_err(|(error, _)| format!("{diagnostic_code}: {error}"))
}

fn duplicate_handle_with_access_result(
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

fn token_fixture_snapshot(token: HANDLE) -> Result<TokenFixtureSnapshot, String> {
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

fn token_group_has_attributes(
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

fn enabled_sensitive_privilege_count(token: HANDLE) -> Result<u32, String> {
    let buffer = query(token, TokenPrivileges)?;
    let entries = token_privilege_entries(buffer.as_bytes())?;
    Ok(entries
        .iter()
        .filter(|entry| privilege_is_enabled_sensitive(entry))
        .count() as u32)
}

fn privilege_is_enabled_sensitive(entry: &LUID_AND_ATTRIBUTES) -> bool {
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
    let statistics = token_statistics(token)?;
    envelope_with_statistics(token, &statistics)
}

fn token_statistics(token: HANDLE) -> Result<TOKEN_STATISTICS, String> {
    let statistics = query(token, TokenStatistics)?;
    if statistics.len() < std::mem::size_of::<TOKEN_STATISTICS>() {
        return Err("token statistics response is truncated".to_owned());
    }
    // SAFETY: size was checked and read_unaligned copies the fixed structure.
    Ok(unsafe { ptr::read_unaligned(statistics.as_ptr().cast::<TOKEN_STATISTICS>()) })
}

fn envelope_with_statistics(
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

fn luid_to_u64(luid: &windows_sys::Win32::Foundation::LUID) -> u64 {
    (u64::from(luid.HighPart as u32) << u32::BITS) | u64::from(luid.LowPart)
}

fn group_inventory(token: HANDLE, class: i32) -> Result<Vec<String>, String> {
    let buffer = query(token, class)?;
    let mut inventory = token_group_entries(buffer.as_bytes())?
        .iter()
        .map(|entry| Ok(format!("{}@{:x}", sid_string(entry.Sid)?, entry.Attributes)))
        .collect::<Result<Vec<_>, String>>()?;
    inventory.sort();
    bounded_token_inventory(inventory)
}

fn privilege_inventory(token: HANDLE) -> Result<Vec<String>, String> {
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

fn bounded_token_inventory(inventory: Vec<String>) -> Result<Vec<String>, String> {
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

pub(super) fn envelope_mismatch_fields(
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

struct QueryBuffer {
    words: Vec<usize>,
    byte_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenQueryPhase {
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
struct TokenQueryError {
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

fn variable_entries<'a, T>(buffer: &'a [u8], fixed: usize, label: &str) -> Result<&'a [T], String> {
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
