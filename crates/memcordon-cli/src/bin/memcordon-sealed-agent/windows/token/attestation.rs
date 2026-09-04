use super::derivation::thread_token_envelope;
use super::query::*;
use super::*;

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
    pub(super) fn semantic(
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

    pub(super) fn native(
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

    pub(super) fn wrapped(
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
pub(crate) struct InstalledThreadTokenAttestation {
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

pub(super) fn token_default_dacl_sha256(token: HANDLE) -> Result<Option<String>, String> {
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

pub(super) fn token_attestation_difference_fields(
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

pub(super) fn token_query_difference_fields(
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

pub(crate) fn nested_loader_behavior_failures(
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

pub(crate) fn install_thread_token(
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

pub(super) fn open_thread_token(thread: HANDLE) -> Result<Option<OwnedHandle>, String> {
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
