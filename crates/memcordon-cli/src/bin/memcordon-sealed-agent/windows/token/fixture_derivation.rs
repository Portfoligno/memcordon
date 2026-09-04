use super::derivation::*;
use super::query::*;
use super::*;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, LUA_TOKEN, WRITE_RESTRICTED,
};

pub struct RestrictedImpersonationGuard {
    token: OwnedHandle,
    fixture_snapshot: TokenFixtureSnapshot,
    attestation_snapshot: TokenAttestationSnapshot,
    active: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EffectiveThreadTokenIdentity {
    token_id: u64,
    modified_id: u64,
    token_type: u32,
    impersonation_level: u32,
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct RestrictedFixtureTokenError {
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
pub(super) fn restricted_fixture_open_error(error: io::Error) -> RestrictedFixtureTokenError {
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
pub(super) fn effective_thread_token_identity() -> Result<EffectiveThreadTokenIdentity, String> {
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
pub(super) fn require_effective_thread_token_identity(
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
        let observed = effective_thread_token_identity()?;
        require_effective_thread_token_identity(expected, observed)?;
        operation(self.token.raw())
    }

    pub fn revert(mut self) -> Result<(), String> {
        self.revert_checked()
    }

    fn revert_checked(&mut self) -> Result<(), String> {
        if !self.active {
            return Err("restricted impersonation guard is already reverted".to_owned());
        }
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
    if unsafe { ConvertStringSidToSidW(low.as_ptr(), &raw mut sid) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0x20,
        },
    };
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
    unsafe {
        LocalFree(administrator);
        LocalFree(restricted_code);
    }
    if created == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    impersonate_primary_token(OwnedHandle::new(restricted)?)
}

pub(super) fn impersonate_primary_token(
    primary: OwnedHandle,
) -> Result<RestrictedImpersonationGuard, String> {
    let mut impersonation = ptr::null_mut();
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

pub(super) fn write_restricted_primary_from_source(source: HANDLE) -> Result<OwnedHandle, String> {
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

pub(super) fn nested_initial_thread_token_from_source(
    source: HANDLE,
) -> Result<OwnedHandle, String> {
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

pub(crate) struct NestedTargetTokens {
    pub permanent: OwnedHandle,
    pub initial: OwnedHandle,
}

pub(crate) fn nested_target_tokens() -> Result<NestedTargetTokens, String> {
    let source = current_process_token_with_access(CALLER_PRIMARY_LAUNCH_ACCESS)?;
    let permanent = write_restricted_primary_from_source(source.raw())?;
    let initial = nested_initial_thread_token_from_source(source.raw())?;
    Ok(NestedTargetTokens { permanent, initial })
}
