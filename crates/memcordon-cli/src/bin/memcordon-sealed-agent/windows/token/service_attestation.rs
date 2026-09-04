use super::query::*;
use super::*;

pub(super) struct RevertGuard;

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
