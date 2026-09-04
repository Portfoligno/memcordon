use super::attestation::open_thread_token;
#[cfg(test)]
use super::fixture_derivation::nested_initial_thread_token_from_source;
use super::query::*;
use super::*;
use windows_sys::Win32::Security::CreateRestrictedToken;

pub(super) fn thread_token_envelope(
    thread: HANDLE,
) -> Result<Option<WindowsCallerTokenEnvelopeV1>, String> {
    open_thread_token(thread)?
        .map(|token| envelope(token.raw()))
        .transpose()
}

pub(super) fn restricted_current_primary_with_flags(flags: u32) -> Result<OwnedHandle, String> {
    restricted_current_primary_for_sid(flags, "S-1-5-12")
}

pub(super) fn restricted_current_primary_for_sid(
    flags: u32,
    restricting_sid: &str,
) -> Result<OwnedHandle, String> {
    let process_token = current_process_token_with_access(
        CALLER_PRIMARY_LAUNCH_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS,
    )?;
    restricted_primary_for_source(process_token.raw(), flags, restricting_sid)
}

pub(super) fn restricted_primary_for_source(
    process_token: HANDLE,
    flags: u32,
    restricting_sid: &str,
) -> Result<OwnedHandle, String> {
    let sid = allocated_sid(restricting_sid)?;
    let restricted_sid = SID_AND_ATTRIBUTES {
        Sid: sid,
        Attributes: CREATE_RESTRICTED_TOKEN_INPUT_ATTRIBUTES,
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

pub(super) fn restricted_same_access_primary(source: HANDLE) -> Result<OwnedHandle, String> {
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

pub(super) struct TokenLogonSidGroupEvidenceV1 {
    sid: String,
    attributes: u32,
}

pub(super) fn validate_logon_sid_group_inventory(
    groups: &[(String, u32)],
) -> Result<TokenLogonSidGroupEvidenceV1, String> {
    let candidates = groups
        .iter()
        .filter(|(_, attributes)| attributes & SE_GROUP_LOGON_ID as u32 == SE_GROUP_LOGON_ID as u32)
        .collect::<Vec<_>>();
    let [candidate] = candidates.as_slice() else {
        return Err(format!(
            "TokenGroups contains {} logon SID entries instead of exactly one",
            candidates.len()
        ));
    };
    if candidate.1 & SE_GROUP_ENABLED as u32 == 0
        || candidate.1 & SE_GROUP_USE_FOR_DENY_ONLY_ATTRIBUTES != 0
    {
        return Err("TokenGroups logon SID is disabled or deny-only".to_owned());
    }
    Ok(TokenLogonSidGroupEvidenceV1 {
        sid: candidate.0.clone(),
        attributes: candidate.1,
    })
}

pub(super) fn validate_token_logon_sid_attributes(attributes: u32) -> Result<(), String> {
    if attributes & SE_GROUP_LOGON_ID as u32 != SE_GROUP_LOGON_ID as u32 {
        return Err("TokenLogonSid entry lacks SE_GROUP_LOGON_ID attributes".to_owned());
    }
    Ok(())
}

pub(super) fn source_logon_sid_group_evidence(
    source: HANDLE,
) -> Result<TokenLogonSidGroupEvidenceV1, String> {
    let groups = query(source, TokenGroups)?;
    let group_entries = token_group_entries(groups.as_bytes())?;
    let candidates = group_entries
        .iter()
        .filter(|entry| entry.Attributes & SE_GROUP_LOGON_ID as u32 == SE_GROUP_LOGON_ID as u32)
        .collect::<Vec<_>>();
    let [source_entry] = candidates.as_slice() else {
        return Err(format!(
            "TokenGroups contains {} logon SID entries instead of exactly one",
            candidates.len()
        ));
    };
    if source_entry.Attributes & SE_GROUP_ENABLED as u32 == 0
        || source_entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY_ATTRIBUTES != 0
    {
        return Err("TokenGroups logon SID is disabled or deny-only".to_owned());
    }
    let logon_groups = query(source, TokenLogonSid)?;
    let logon_entries = token_group_entries(logon_groups.as_bytes())?;
    let [logon_entry] = logon_entries else {
        return Err(format!(
            "TokenLogonSid returned {} entries instead of exactly one",
            logon_entries.len()
        ));
    };
    validate_token_logon_sid_attributes(logon_entry.Attributes)?;
    // SAFETY: both PSIDs point into live token-information buffers and are
    // used only for this equality check.
    if unsafe { EqualSid(source_entry.Sid, logon_entry.Sid) } == 0 {
        return Err("TokenGroups logon SID differs from TokenLogonSid".to_owned());
    }
    Ok(TokenLogonSidGroupEvidenceV1 {
        sid: sid_string(source_entry.Sid)?,
        attributes: source_entry.Attributes,
    })
}

pub(super) fn restricted_logon_sid_primary(
    source: HANDLE,
) -> Result<(OwnedHandle, TokenLogonSidGroupEvidenceV1), String> {
    let groups = query(source, TokenGroups)?;
    let group_entries = token_group_entries(groups.as_bytes())?;
    let candidates = group_entries
        .iter()
        .filter(|entry| entry.Attributes & SE_GROUP_LOGON_ID as u32 == SE_GROUP_LOGON_ID as u32)
        .collect::<Vec<_>>();
    let [source_entry] = candidates.as_slice() else {
        return Err(format!(
            "TokenGroups contains {} logon SID entries instead of exactly one",
            candidates.len()
        ));
    };
    if source_entry.Attributes & SE_GROUP_ENABLED as u32 == 0
        || source_entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY_ATTRIBUTES != 0
    {
        return Err("TokenGroups logon SID is disabled or deny-only".to_owned());
    }
    let logon_groups = query(source, TokenLogonSid)?;
    let logon_entries = token_group_entries(logon_groups.as_bytes())?;
    let [logon_entry] = logon_entries else {
        return Err(format!(
            "TokenLogonSid returned {} entries instead of exactly one",
            logon_entries.len()
        ));
    };
    validate_token_logon_sid_attributes(logon_entry.Attributes)?;
    // SAFETY: both PSIDs point into live token-information buffers and are
    // used only for the duration of this equality check.
    if unsafe { EqualSid(source_entry.Sid, logon_entry.Sid) } == 0 {
        return Err("TokenGroups logon SID differs from TokenLogonSid".to_owned());
    }
    let evidence = TokenLogonSidGroupEvidenceV1 {
        sid: sid_string(source_entry.Sid)?,
        attributes: source_entry.Attributes,
    };
    let restricting_sid = SID_AND_ATTRIBUTES {
        Sid: source_entry.Sid,
        Attributes: CREATE_RESTRICTED_TOKEN_INPUT_ATTRIBUTES,
    };
    let mut restricted = ptr::null_mut();
    // SAFETY: source and the TokenGroups query buffer are live; the one SID
    // pointer comes from the uniquely attested enabled non-deny-only logon
    // group; CreateRestrictedToken requires zero input attributes; output
    // ownership transfers to OwnedHandle.
    if unsafe {
        CreateRestrictedToken(
            source,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            1,
            &raw const restricting_sid,
            &raw mut restricted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok((OwnedHandle::new(restricted)?, evidence))
}

pub(super) fn authenticated_users_sid() -> Result<QueryBuffer, String> {
    let requested = SECURITY_MAX_SID_SIZE as usize;
    let word_count = requested.div_ceil(std::mem::size_of::<usize>());
    let mut words = vec![0_usize; word_count];
    let mut byte_length = SECURITY_MAX_SID_SIZE;
    // SAFETY: the word vector is suitably aligned and has SECURITY_MAX_SID_SIZE
    // writable bytes; no domain SID is required for WinAuthenticatedUserSid.
    if unsafe {
        CreateWellKnownSid(
            WinAuthenticatedUserSid,
            ptr::null_mut(),
            words.as_mut_ptr().cast(),
            &raw mut byte_length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    if byte_length == 0 || byte_length as usize > requested {
        return Err("Authenticated Users well-known SID length is invalid".to_owned());
    }
    Ok(QueryBuffer {
        words,
        byte_length: byte_length as usize,
    })
}

pub(super) fn exact_equal_sid_entry<'a>(
    entries: &'a [SID_AND_ATTRIBUTES],
    expected_sid: *mut c_void,
    role: &str,
) -> Result<&'a SID_AND_ATTRIBUTES, String> {
    exact_equal_sid_entry_for_trustee(entries, expected_sid, role, "Authenticated Users")
}

pub(super) fn exact_equal_sid_entry_for_trustee<'a>(
    entries: &'a [SID_AND_ATTRIBUTES],
    expected_sid: *mut c_void,
    role: &str,
    trustee: &str,
) -> Result<&'a SID_AND_ATTRIBUTES, String> {
    let matches = entries
        .iter()
        .filter(|entry| {
            // SAFETY: the entry PSID is backed by its live token-information
            // buffer and expected_sid is backed by a live well-known-SID buffer.
            (unsafe { EqualSid(entry.Sid, expected_sid) }) != 0
        })
        .collect::<Vec<_>>();
    let [entry] = matches.as_slice() else {
        return Err(format!(
            "{role} contains {} {trustee} entries instead of exactly one",
            matches.len()
        ));
    };
    Ok(entry)
}

pub(super) fn token_user_entry(user: &QueryBuffer) -> Result<SID_AND_ATTRIBUTES, String> {
    if user.len() < std::mem::size_of::<windows_sys::Win32::Security::TOKEN_USER>() {
        return Err("token user response is truncated".to_owned());
    }
    // SAFETY: the fixed TOKEN_USER structure is present and the copied SID
    // pointer remains backed by `user` for the caller's use.
    let entry = unsafe {
        ptr::read_unaligned(
            user.as_ptr()
                .cast::<windows_sys::Win32::Security::TOKEN_USER>(),
        )
        .User
    };
    if entry.Sid.is_null() || unsafe { IsValidSid(entry.Sid) } == 0 {
        return Err("token user response contains an invalid SID".to_owned());
    }
    Ok(entry)
}

pub(super) fn validate_authenticated_users_attributes(
    attributes: u32,
    role: &str,
) -> Result<(), String> {
    if attributes != NORMALIZED_RESTRICTING_SID_ATTRIBUTES {
        return Err(format!(
            "{role} Authenticated Users attributes are not exact enabled non-deny-only 0x7"
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct AuthenticatedUsersGroupEvidenceV1 {
    sid: String,
    source_attributes: u32,
    canonical_attributes: u32,
}

pub(super) fn restricted_authenticated_users_primary(
    source: HANDLE,
    canonical_same_access: HANDLE,
) -> Result<(OwnedHandle, AuthenticatedUsersGroupEvidenceV1), String> {
    let expected_sid = authenticated_users_sid()?;
    let groups = query(source, TokenGroups)?;
    let group_entries = token_group_entries(groups.as_bytes())?;
    let source_entry = exact_equal_sid_entry(
        group_entries,
        expected_sid.as_ptr().cast_mut().cast(),
        "TokenGroups",
    )?;
    validate_authenticated_users_attributes(source_entry.Attributes, "TokenGroups")?;
    let canonical = query(canonical_same_access, TokenRestrictedSids)?;
    let canonical_entries = token_group_entries(canonical.as_bytes())?;
    let canonical_entry = exact_equal_sid_entry(
        canonical_entries,
        expected_sid.as_ptr().cast_mut().cast(),
        "canonical TokenRestrictedSids",
    )?;
    validate_authenticated_users_attributes(
        canonical_entry.Attributes,
        "canonical TokenRestrictedSids",
    )?;
    let sid = sid_string(expected_sid.as_ptr().cast_mut().cast())?;
    if sid != AUTHENTICATED_USERS_SID {
        return Err("well-known Authenticated Users SID rendered unexpectedly".to_owned());
    }
    let evidence = AuthenticatedUsersGroupEvidenceV1 {
        sid,
        source_attributes: source_entry.Attributes,
        canonical_attributes: canonical_entry.Attributes,
    };
    let restricting_sid = SID_AND_ATTRIBUTES {
        Sid: source_entry.Sid,
        Attributes: CREATE_RESTRICTED_TOKEN_INPUT_ATTRIBUTES,
    };
    let mut restricted = ptr::null_mut();
    // SAFETY: source, the raw TokenGroups entry, and both well-known/canonical
    // admission buffers remain live; exactly one zero-attribute restricting
    // SID is supplied and output ownership transfers to OwnedHandle.
    if unsafe {
        CreateRestrictedToken(
            source,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            1,
            &raw const restricting_sid,
            &raw mut restricted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok((OwnedHandle::new(restricted)?, evidence))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct TargetUserGroupEvidenceV1 {
    sid: String,
    source_attributes: u32,
    canonical_attributes: u32,
}

pub(super) fn target_user_group_evidence(
    source: HANDLE,
    canonical_same_access: HANDLE,
) -> Result<TargetUserGroupEvidenceV1, String> {
    let user = query(source, TokenUser)?;
    let source_entry = token_user_entry(&user)?;
    let canonical = query(canonical_same_access, TokenRestrictedSids)?;
    let canonical_entry = exact_equal_sid_entry_for_trustee(
        token_group_entries(canonical.as_bytes())?,
        source_entry.Sid,
        "canonical TokenRestrictedSids",
        "target user SID",
    )?;
    if canonical_entry.Attributes != NORMALIZED_RESTRICTING_SID_ATTRIBUTES {
        return Err(
            "canonical TokenRestrictedSids target user attributes are not exact 0x7".to_owned(),
        );
    }
    Ok(TargetUserGroupEvidenceV1 {
        sid: sid_string(source_entry.Sid)?,
        source_attributes: source_entry.Attributes,
        canonical_attributes: canonical_entry.Attributes,
    })
}

pub(super) fn restricted_target_user_primary(
    source: HANDLE,
    canonical_same_access: HANDLE,
) -> Result<(OwnedHandle, TargetUserGroupEvidenceV1), String> {
    let user = query(source, TokenUser)?;
    let source_entry = token_user_entry(&user)?;
    let canonical = query(canonical_same_access, TokenRestrictedSids)?;
    let canonical_entries = token_group_entries(canonical.as_bytes())?;
    let canonical_entry = exact_equal_sid_entry_for_trustee(
        canonical_entries,
        source_entry.Sid,
        "canonical TokenRestrictedSids",
        "target user SID",
    )?;
    if canonical_entry.Attributes != NORMALIZED_RESTRICTING_SID_ATTRIBUTES {
        return Err(
            "canonical TokenRestrictedSids target user attributes are not exact 0x7".to_owned(),
        );
    }
    let evidence = TargetUserGroupEvidenceV1 {
        sid: sid_string(source_entry.Sid)?,
        source_attributes: source_entry.Attributes,
        canonical_attributes: canonical_entry.Attributes,
    };
    let restricting_sid = SID_AND_ATTRIBUTES {
        Sid: source_entry.Sid,
        Attributes: CREATE_RESTRICTED_TOKEN_INPUT_ATTRIBUTES,
    };
    let mut restricted = ptr::null_mut();
    // SAFETY: source and the live TokenUser and canonical admission buffers
    // remain valid; exactly one zero-attribute raw target-user SID is supplied;
    // output ownership transfers to OwnedHandle.
    if unsafe {
        CreateRestrictedToken(
            source,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            1,
            &raw const restricting_sid,
            &raw mut restricted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let restricted = OwnedHandle::new(restricted)?;
    if !token_has_exact_restricting_sid_equal_sid(
        restricted.raw(),
        source_entry.Sid,
        NORMALIZED_RESTRICTING_SID_ATTRIBUTES,
    )? {
        return Err(
            "loader target-user sibling lacks its exact raw singleton restriction".to_owned(),
        );
    }
    Ok((restricted, evidence))
}

#[cfg(test)]
pub(crate) fn validate_authenticated_users_matches_for_test(
    matching_attributes: &[u32],
) -> Result<u32, String> {
    let [attributes] = matching_attributes else {
        return Err(format!(
            "TokenGroups contains {} Authenticated Users entries instead of exactly one",
            matching_attributes.len()
        ));
    };
    validate_authenticated_users_attributes(*attributes, "TokenGroups")?;
    Ok(*attributes)
}

#[cfg(test)]
pub(crate) fn validate_target_user_matches_for_test(
    source_user_valid: bool,
    canonical_entries: &[(bool, u32)],
    output_entries: &[(bool, u32)],
) -> Result<(u32, u32), String> {
    if !source_user_valid {
        return Err("token user response contains an invalid SID".to_owned());
    }
    let canonical_matches = canonical_entries
        .iter()
        .filter(|(equal_sid, _)| *equal_sid)
        .collect::<Vec<_>>();
    let [(_, canonical_attributes)] = canonical_matches.as_slice() else {
        return Err(format!(
            "canonical TokenRestrictedSids contains {} target user SID entries instead of exactly one",
            canonical_matches.len()
        ));
    };
    if *canonical_attributes != NORMALIZED_RESTRICTING_SID_ATTRIBUTES {
        return Err(
            "canonical TokenRestrictedSids target user attributes are not exact 0x7".to_owned(),
        );
    }
    let [(output_equal_sid, output_attributes)] = output_entries else {
        return Err(format!(
            "target-user output contains {} restricting entries instead of exactly one",
            output_entries.len()
        ));
    };
    if !output_equal_sid || *output_attributes != NORMALIZED_RESTRICTING_SID_ATTRIBUTES {
        return Err("target-user output is not the exact raw singleton at 0x7".to_owned());
    }
    Ok((*canonical_attributes, *output_attributes))
}

#[cfg(test)]
pub(crate) fn validate_logon_sid_group_inventory_for_test(
    groups: &[(&str, u32)],
) -> Result<(String, u32), String> {
    validate_logon_sid_group_inventory(
        &groups
            .iter()
            .map(|(sid, attributes)| ((*sid).to_owned(), *attributes))
            .collect::<Vec<_>>(),
    )
    .map(|evidence| (evidence.sid, evidence.attributes))
}

#[cfg(test)]
pub(crate) fn validate_token_logon_sid_attributes_for_test(attributes: u32) -> Result<(), String> {
    validate_token_logon_sid_attributes(attributes)
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
    sort_and_validate_canonical_same_access_restricting_sids(sids)
}

pub(super) fn sort_and_validate_canonical_same_access_restricting_sids(
    mut sids: Vec<String>,
) -> Result<Vec<String>, String> {
    sids.sort();
    if sids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(
            "canonical same-access restricting SID inventory contains duplicates".to_owned(),
        );
    }
    Ok(sids)
}

#[cfg(test)]
pub(crate) fn canonical_same_access_restricting_sids_for_test(
    sids: &[&str],
) -> Result<Vec<(String, u32)>, String> {
    sort_and_validate_canonical_same_access_restricting_sids(
        sids.iter().map(|sid| (*sid).to_owned()).collect(),
    )
    .map(|sids| {
        sids.into_iter()
            .map(|sid| (sid, NORMALIZED_RESTRICTING_SID_ATTRIBUTES))
            .collect()
    })
}

#[cfg(test)]
pub(crate) fn nested_initial_thread_token_for_test() -> Result<OwnedHandle, String> {
    let source = current_process_token_with_access(CALLER_PRIMARY_LAUNCH_ACCESS)?;
    nested_initial_thread_token_from_source(source.raw())
}

pub(super) fn current_primary_without_restricting_sid(flags: u32) -> Result<OwnedHandle, String> {
    let process_token = current_process_token_with_access(
        CALLER_PRIMARY_LAUNCH_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS,
    )?;
    primary_without_restricting_sid_from_source(process_token.raw(), flags)
}

pub(super) fn primary_without_restricting_sid_from_source(
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

pub(super) fn current_process_token() -> Result<OwnedHandle, String> {
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

pub(super) fn current_process_token_with_attested_access(
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
pub(super) struct ScopedPrivilegeThreadTokenError {
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

pub(super) struct ScopedPrivilegeThreadToken {
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

pub(super) fn require_current_thread_token_absent() -> Result<(), String> {
    match open_thread_token(unsafe { GetCurrentThread() })? {
        None => Ok(()),
        Some(token) => {
            drop(token);
            Err("scoped privileged operation found an existing worker thread token".to_owned())
        }
    }
}

#[derive(Debug)]
pub(super) struct PackageServiceOwnerPrivilegeError {
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

pub(super) fn privilege_entries_snapshot(
    token: HANDLE,
) -> Result<Vec<LUID_AND_ATTRIBUTES>, String> {
    let privileges = query(token, TokenPrivileges)?;
    let mut entries = token_privilege_entries(privileges.as_bytes())?.to_vec();
    entries.sort_by_key(|entry| (entry.Luid.HighPart, entry.Luid.LowPart));
    Ok(entries)
}

pub(super) fn exact_enabled_privilege_transition(
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

pub(super) fn privilege_snapshots_equal(
    left: &[LUID_AND_ATTRIBUTES],
    right: &[LUID_AND_ATTRIBUTES],
) -> bool {
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

pub(crate) fn with_scoped_loader_profile_privileges<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    const PRIVILEGES: [&str; 2] = ["SeBackupPrivilege", "SeRestorePrivilege"];
    require_current_thread_token_absent()?;
    let source = current_process_token_with_attested_access(
        TOKEN_QUERY | TOKEN_DUPLICATE,
        "loader-profile-privilege-source",
    )?;
    let source_before = privilege_entries_snapshot(source.raw())?;
    let carrier_access = TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE;
    let mut raw_carrier = ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            source.raw(),
            carrier_access,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut raw_carrier,
        )
    } == 0
    {
        return Err(format!(
            "loader profile privilege carrier duplication failed: {}",
            io::Error::last_os_error()
        ));
    }
    let carrier = OwnedHandle::new(raw_carrier)?;
    if handle_granted_access(carrier.raw()).map_err(|error| error.detail)? != carrier_access {
        return Err("loader profile privilege carrier has unexpected access".to_owned());
    }
    let carrier_before = privilege_entries_snapshot(carrier.raw())?;
    let mut luids = [windows_sys::Win32::Foundation::LUID::default(); 2];
    for (name, luid) in PRIVILEGES.iter().zip(luids.iter_mut()) {
        let wide = super::pipe::wide_null(name);
        if unsafe { LookupPrivilegeValueW(ptr::null(), wide.as_ptr(), luid) } == 0 {
            return Err(format!(
                "loader profile privilege lookup failed for {name}: {}",
                io::Error::last_os_error()
            ));
        }
    }
    #[repr(C)]
    struct TwoTokenPrivileges {
        privilege_count: u32,
        privileges: [LUID_AND_ATTRIBUTES; 2],
    }
    let requested = TwoTokenPrivileges {
        privilege_count: 2,
        privileges: luids.map(|luid| LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }),
    };
    unsafe { SetLastError(ERROR_SUCCESS) };
    let adjusted = unsafe {
        AdjustTokenPrivileges(
            carrier.raw(),
            0,
            (&raw const requested).cast(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let adjust_error = unsafe { GetLastError() };
    if adjusted == 0 || adjust_error != ERROR_SUCCESS {
        return Err(format!(
            "loader profile privilege enable failed: native_code={} not_all_assigned={}",
            adjust_error,
            adjust_error == ERROR_NOT_ALL_ASSIGNED
        ));
    }
    let carrier_after = privilege_entries_snapshot(carrier.raw())?;
    let luid_matches = |left: &windows_sys::Win32::Foundation::LUID,
                        right: &windows_sys::Win32::Foundation::LUID| {
        left.LowPart == right.LowPart && left.HighPart == right.HighPart
    };
    if carrier_before.len() != carrier_after.len()
        || carrier_before.iter().any(|before| {
            let Some(after) = carrier_after
                .iter()
                .find(|after| luid_matches(&before.Luid, &after.Luid))
            else {
                return true;
            };
            let selected = luids.iter().any(|luid| luid_matches(&before.Luid, luid));
            let expected = if selected {
                before.Attributes | SE_PRIVILEGE_ENABLED
            } else {
                before.Attributes
            };
            after.Attributes != expected
        })
        || luids.iter().any(|luid| {
            !carrier_after.iter().any(|entry| {
                luid_matches(&entry.Luid, luid) && entry.Attributes & SE_PRIVILEGE_ENABLED != 0
            })
        })
    {
        return Err(
            "loader profile privilege transition was not exactly backup/restore enablement"
                .to_owned(),
        );
    }
    let scoped =
        ScopedPrivilegeThreadToken::install(carrier.raw()).map_err(|error| error.to_string())?;
    let effective = PRIVILEGES.iter().try_fold(true, |all, name| {
        effective_thread_privilege_enabled(name).map(|enabled| all && enabled)
    });
    let result = match effective {
        Ok(true) => operation(),
        Ok(false) => Err(
            "loader profile backup/restore privileges are not effective on the disposable carrier"
                .to_owned(),
        ),
        Err(error) => Err(error.to_string()),
    };
    if let Err(error) = scoped.revert() {
        eprintln!("loader profile privilege carrier revert failed: {error}");
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(
                GetCurrentProcess(),
                0xED15_0003,
            )
        };
        std::process::abort();
    }
    drop(carrier);
    let source_after = privilege_entries_snapshot(source.raw())?;
    if !privilege_snapshots_equal(&source_before, &source_after) {
        return Err("launcher process privilege state changed during profile operation".to_owned());
    }
    drop(source);
    require_current_thread_token_absent()?;
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

pub(super) fn enable_holder_carrier_privilege(
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
pub(super) struct NativeEvidenceError {
    pub(super) api: &'static str,
    pub(super) native_code: Option<i32>,
    pub(super) nt_status: Option<i32>,
    pub(super) detail: String,
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

pub(super) fn nt_status_native_code(status: i32) -> Option<i32> {
    // SAFETY: status is returned directly by an NT native API and the mapper
    // has no pointer or lifetime preconditions.
    i32::try_from(unsafe { RtlNtStatusToDosError(status) }).ok()
}

pub(super) fn handle_granted_access(handle: HANDLE) -> Result<u32, NativeEvidenceError> {
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

pub(super) fn effective_thread_privilege_enabled(
    privilege_name: &str,
) -> Result<bool, NativeEvidenceError> {
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

pub(super) fn privilege_luid(name: &str) -> Result<windows_sys::Win32::Foundation::LUID, String> {
    let name = super::pipe::wide_null(name);
    let mut luid = windows_sys::Win32::Foundation::LUID::default();
    // SAFETY: name is NUL-terminated and luid is writable.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &raw mut luid) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(luid)
    }
}

pub(super) fn snapshot_has_enabled_group(snapshot: &TokenAttestationSnapshot, sid: &str) -> bool {
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

pub(super) fn snapshot_privilege_attributes(
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

pub(super) fn validate_session_broker_source_snapshot(
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

pub(super) fn exact_disabled_privilege_transition(
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

pub(super) fn exact_disabled_privilege_set_transition(
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

pub(super) fn exact_session_broker_source_snapshot_transition(
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

pub(super) fn disable_session_broker_source_privilege(
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

pub(super) fn derive_exact_session_broker_carrier(
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

pub(super) fn privilege_inventory_is_security_only_enabled(
    inventory: &[String],
) -> Result<bool, String> {
    let security = privilege_luid("SeSecurityPrivilege")?;
    let prefix = format!("{:x}:{:x}@", security.HighPart as u32, security.LowPart);
    Ok(
        matches!(inventory, [entry] if entry.strip_prefix(&prefix).is_some_and(|attributes| {
            u32::from_str_radix(attributes, 16)
                .is_ok_and(|attributes| attributes & SE_PRIVILEGE_ENABLED != 0)
        })),
    )
}

pub(super) fn derive_target_session_security_carrier(
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

pub(super) fn with_session_broker_impersonate_privilege<T>(
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
