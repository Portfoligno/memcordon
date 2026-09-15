// Owner: windows::token::certification_derivation; compiled only with cfg(test).
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EffectiveThreadTokenIdentity {
    token_id: u64,
    modified_id: u64,
    token_type: u32,
    impersonation_level: u32,
}

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

impl std::error::Error for RestrictedFixtureTokenError {}

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

pub(crate) fn restricted_fixture_open_error_for_test(native_code: i32) -> String {
    restricted_fixture_open_error(io::Error::from_raw_os_error(native_code)).to_string()
}

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

impl RestrictedImpersonationGuard {
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
}
