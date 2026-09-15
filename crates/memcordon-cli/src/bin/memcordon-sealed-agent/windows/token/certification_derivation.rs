//! Shipped token derivation for installed-provider qualification canaries.
//! This runtime authority remains available in installed packages.

#[cfg(test)]
#[path = "../../../../../tests/sealed_agent/windows_certification_token_support.rs"]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::{
    effective_thread_token_identity_validation_for_test, restricted_fixture_open_error_for_test,
};

use super::derivation::*;
use super::query::*;
use super::*;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, LUA_TOKEN, WRITE_RESTRICTED,
};

pub struct RestrictedImpersonationGuard {
    token: OwnedHandle,
    certification_snapshot: TokenCertificationSnapshot,
    attestation_snapshot: TokenAttestationSnapshot,
    active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenCertificationSnapshot {
    pub envelope: WindowsCallerTokenEnvelopeV1,
    pub restricted_sid_count: u32,
    pub restricting_sids: Vec<String>,
    pub token_is_restricted: bool,
    pub write_restricted: bool,
    pub enabled_sensitive_privilege_count: u32,
    pub administrator_deny_only: bool,
}

impl RestrictedImpersonationGuard {
    pub fn certification_snapshot(&self) -> TokenCertificationSnapshot {
        self.certification_snapshot.clone()
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
    let certification_snapshot = token_certification_snapshot(impersonation.raw())?;
    let attestation_snapshot = token_attestation_snapshot(impersonation.raw())?;
    if unsafe { SetThreadToken(ptr::null(), impersonation.raw()) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(RestrictedImpersonationGuard {
        token: impersonation,
        certification_snapshot,
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
