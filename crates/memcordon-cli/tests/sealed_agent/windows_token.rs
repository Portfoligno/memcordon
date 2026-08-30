use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, LUID, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::Security::{
    LUID_AND_ATTRIBUTES, SID_AND_ATTRIBUTES, SecurityAnonymous, SecurityDelegation,
    SecurityIdentification, SecurityImpersonation, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_PRIVILEGES,
    TOKEN_QUERY, TOKEN_QUERY_SOURCE, TokenImpersonation, TokenPrimary, TokenStatistics,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::windows::qualification::prepare_frontend_canaries_for_test;
use crate::windows::token::{
    RestrictedImpersonationGuard, TokenFixtureSnapshot, canonical_same_access_restricting_sids,
    current_process_token_for_access_check, current_process_token_for_attestation,
    current_process_token_for_attestation_and_access_check,
    effective_thread_token_identity_validation_for_test, enabled_group_entry_matches, envelope,
    exact_disabled_privilege_set_transition_for_test, granted_handle_access, groups_digest,
    impersonate_deny_only_admin_current_thread, impersonate_low_integrity_current_thread,
    impersonate_ordinary_current_thread, impersonate_restricted_current_thread,
    impersonate_write_restricted_current_thread, nested_initial_thread_token_for_test,
    normalized_session_broker_privilege_entries_for_test, privilege_is_enabled_sensitive_for_test,
    privileges_digest, process_token, require_assigned_process_authority,
    require_assigned_token_authority, require_same_token_instance, restricted_current_primary,
    restricted_fixture_open_error_for_test, restricting_sid_entry_matches,
    token_attestation_snapshot, token_group_entries, token_has_enabled_group,
    token_has_restricting_sid, token_privilege_entries, token_query_attestation_snapshot,
    token_query_error_for_test, token_restricting_sid_attributes, token_restricting_sids,
    token_user_sid, write_restricted_current_primary,
};

fn privilege_luid(name: &str) -> LUID {
    let mut wide = name.encode_utf16().collect::<Vec<_>>();
    wide.push(0);
    let mut luid = LUID::default();
    // SAFETY: the privilege name is NUL-terminated and output storage is live.
    assert_ne!(
        unsafe { LookupPrivilegeValueW(ptr::null(), wide.as_ptr(), &raw mut luid) },
        0
    );
    luid
}

struct OwnedSid(*mut c_void);

impl OwnedSid {
    fn parse(value: &str) -> Self {
        let mut wide = value.encode_utf16().collect::<Vec<_>>();
        wide.push(0);
        let mut sid = ptr::null_mut();
        // SAFETY: the input is NUL-terminated and output receives LocalAlloc memory.
        assert_ne!(
            unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) },
            0
        );
        Self(sid)
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        // SAFETY: this is the exact LocalAlloc result and is released once.
        unsafe { LocalFree(self.0.cast()) };
    }
}

fn variable_buffer<T: Copy>(fixed: usize, entries: &[T]) -> (Vec<usize>, usize) {
    let byte_length = fixed + std::mem::size_of_val(entries);
    let mut words = vec![0_usize; byte_length.div_ceil(size_of::<usize>())];
    let count = u32::try_from(entries.len()).unwrap();
    // SAFETY: word storage is native-aligned and sized for the header/count and entries.
    unsafe {
        ptr::write_unaligned(words.as_mut_ptr().cast::<u32>(), count);
        ptr::copy_nonoverlapping(
            entries.as_ptr(),
            words.as_mut_ptr().cast::<u8>().add(fixed).cast::<T>(),
            entries.len(),
        );
    }
    (words, byte_length)
}

fn bytes(words: &[usize], byte_length: usize) -> &[u8] {
    // SAFETY: byte_length was used to size this word-aligned backing storage.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), byte_length) }
}

fn assert_cached_fixture_snapshot(
    scenario: &str,
    constructor: fn() -> Result<RestrictedImpersonationGuard, String>,
    validate: impl FnOnce(&TokenFixtureSnapshot),
) {
    let before = crate::windows::token::current_thread_envelope().unwrap();
    let installed_image = std::env::current_exe().unwrap();
    let frontend_canaries = prepare_frontend_canaries_for_test(&installed_image, scenario).unwrap();
    {
        let fixture = constructor().unwrap();
        let snapshot = fixture.fixture_snapshot();
        validate(&snapshot);
        frontend_canaries.validate_for_test().unwrap();
        let advertised = frontend_canaries.raw_values();
        assert_eq!(
            advertised.len(),
            memcordon_core::WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT
        );
        assert!(!advertised.contains(&frontend_canaries.retained_pipe_writer_for_test()));
    }
    assert_eq!(
        crate::windows::token::current_thread_envelope().unwrap(),
        before
    );
    frontend_canaries.validate_for_test().unwrap();
}

#[test]
fn qualification_fixture_snapshots_and_canaries_are_prepared_before_impersonation() {
    assert_cached_fixture_snapshot(
        "restricted",
        impersonate_restricted_current_thread,
        |snapshot| {
            assert!(snapshot.token_is_restricted);
            assert_ne!(snapshot.restricted_sid_count, 0);
            assert!(!snapshot.restricting_sids.is_empty());
        },
    );
    assert_cached_fixture_snapshot(
        "ordinary-user",
        impersonate_ordinary_current_thread,
        |snapshot| {
            assert!(!snapshot.envelope.elevated);
        },
    );
    assert_cached_fixture_snapshot(
        "write-restricted",
        impersonate_write_restricted_current_thread,
        |snapshot| {
            assert_ne!(snapshot.restricted_sid_count, 0);
            assert!(snapshot.write_restricted);
        },
    );
    assert_cached_fixture_snapshot(
        "low-integrity",
        impersonate_low_integrity_current_thread,
        |snapshot| {
            assert_eq!(snapshot.envelope.integrity_level, "S-1-16-4096");
        },
    );
    assert_cached_fixture_snapshot(
        "deny-only-admin",
        impersonate_deny_only_admin_current_thread,
        |snapshot| {
            assert!(snapshot.administrator_deny_only);
            assert_ne!(snapshot.restricted_sid_count, 0);
        },
    );

    let detail = std::io::Error::from_raw_os_error(5).to_string();
    assert_eq!(
        token_query_error_for_test(TokenStatistics, false, 5),
        format!(
            "MCSEALED-WINDOWS-TOKEN-QUERY: stage=token-information-query api=GetTokenInformation information_class={TokenStatistics} phase=size-probe native_code=5 detail={detail}"
        )
    );
    assert_eq!(
        token_query_error_for_test(TokenStatistics, true, 5),
        format!(
            "MCSEALED-WINDOWS-TOKEN-QUERY: stage=token-information-query api=GetTokenInformation information_class={TokenStatistics} phase=fill native_code=5 detail={detail}"
        )
    );
}

#[test]
fn effective_thread_identity_validation_rejects_every_provenance_drift() {
    let matching = (
        11,
        22,
        TokenImpersonation as u32,
        SecurityImpersonation as u32,
    );
    effective_thread_token_identity_validation_for_test(matching, matching).unwrap();

    for (label, expected, observed, difference) in [
        (
            "zero expected token id",
            (0, matching.1, matching.2, matching.3),
            matching,
            "expected_token_id_zero",
        ),
        (
            "zero observed token id",
            matching,
            (0, matching.1, matching.2, matching.3),
            "observed_token_id_zero",
        ),
        (
            "different token id",
            matching,
            (33, matching.1, matching.2, matching.3),
            "token_id",
        ),
        (
            "different modified id",
            matching,
            (matching.0, 44, matching.2, matching.3),
            "modified_id",
        ),
        (
            "primary token",
            matching,
            (matching.0, matching.1, TokenPrimary as u32, matching.3),
            "token_type",
        ),
        (
            "anonymous impersonation",
            matching,
            (matching.0, matching.1, matching.2, SecurityAnonymous as u32),
            "impersonation_level",
        ),
        (
            "identification impersonation",
            matching,
            (
                matching.0,
                matching.1,
                matching.2,
                SecurityIdentification as u32,
            ),
            "impersonation_level",
        ),
        (
            "delegation impersonation",
            matching,
            (
                matching.0,
                matching.1,
                matching.2,
                SecurityDelegation as u32,
            ),
            "impersonation_level",
        ),
    ] {
        let error = effective_thread_token_identity_validation_for_test(expected, observed)
            .expect_err(label);
        assert!(
            error.contains("stage=effective-thread-identity-compare"),
            "{label}: {error}"
        );
        assert!(error.contains(difference), "{label}: {error}");
    }
}

#[test]
fn restricted_fixture_open_errors_name_the_exact_operation() {
    let denied = restricted_fixture_open_error_for_test(5);
    assert!(denied.contains("stage=effective-thread-open"), "{denied}");
    assert!(denied.contains("api=OpenThreadToken"), "{denied}");
    assert!(denied.contains("requested_access=0x00000008"), "{denied}");
    assert!(denied.contains("open_as_self=true"), "{denied}");
    assert!(denied.contains("native_code=5"), "{denied}");

    let absent = restricted_fixture_open_error_for_test(ERROR_NO_TOKEN as i32);
    assert!(
        absent.contains("stage=effective-thread-presence"),
        "{absent}"
    );
    assert!(absent.contains("native_code=1008"), "{absent}");
}

#[test]
fn sensitive_privilege_normalization_uses_the_documented_change_notify_luid() {
    const ENABLED: u32 = 0x0000_0002;

    assert!(!privilege_is_enabled_sensitive_for_test(23, 0, ENABLED));
    assert!(!privilege_is_enabled_sensitive_for_test(24, 0, 0));
    assert!(privilege_is_enabled_sensitive_for_test(24, 0, ENABLED));
    assert!(privilege_is_enabled_sensitive_for_test(23, 1, ENABLED));
}

#[test]
fn group_parser_uses_all_entries_from_the_original_buffer_and_rejects_truncation() {
    let mut markers = [0_u8; 3];
    let entries = [
        SID_AND_ATTRIBUTES {
            Sid: ptr::from_mut(&mut markers[0]).cast(),
            Attributes: 1,
        },
        SID_AND_ATTRIBUTES {
            Sid: ptr::from_mut(&mut markers[1]).cast(),
            Attributes: 2,
        },
        SID_AND_ATTRIBUTES {
            Sid: ptr::from_mut(&mut markers[2]).cast(),
            Attributes: 4,
        },
    ];
    let fixed = offset_of!(TOKEN_GROUPS, Groups);
    let (mut words, byte_length) = variable_buffer(fixed, &entries);
    let parsed = token_group_entries(bytes(&words, byte_length)).unwrap();
    assert_eq!(parsed.len(), entries.len());
    assert_eq!(parsed[2].Sid, entries[2].Sid);
    assert_eq!(parsed[2].Attributes, 4);

    // SAFETY: the live buffer begins with the declared native u32 count.
    unsafe { ptr::write_unaligned(words.as_mut_ptr().cast::<u32>(), 4) };
    assert!(token_group_entries(bytes(&words, byte_length)).is_err());
}

#[test]
fn ordinary_and_restricting_sid_entries_use_distinct_semantics() {
    let expected = OwnedSid::parse("S-1-5-12");
    let other = OwnedSid::parse("S-1-5-11");
    let enabled = SID_AND_ATTRIBUTES {
        Sid: expected.0,
        Attributes: 0x0000_0004,
    };
    let disabled = SID_AND_ATTRIBUTES {
        Sid: expected.0,
        Attributes: 0,
    };
    let deny_only = SID_AND_ATTRIBUTES {
        Sid: expected.0,
        Attributes: 0x0000_0014,
    };
    let other_restricting = SID_AND_ATTRIBUTES {
        Sid: other.0,
        Attributes: 0,
    };

    assert!(enabled_group_entry_matches(&enabled, "S-1-5-12").unwrap());
    assert!(!enabled_group_entry_matches(&disabled, "S-1-5-12").unwrap());
    assert!(!enabled_group_entry_matches(&deny_only, "S-1-5-12").unwrap());
    assert!(restricting_sid_entry_matches(&disabled, "S-1-5-12").unwrap());
    assert!(!restricting_sid_entry_matches(&other_restricting, "S-1-5-12").unwrap());
}

#[test]
fn create_restricted_token_attests_the_native_restricting_sid_by_presence() {
    let token = restricted_current_primary().unwrap();

    assert!(token_has_restricting_sid(token.raw(), "S-1-5-12").unwrap());
    assert!(!token_has_restricting_sid(token.raw(), "S-1-5-33").unwrap());
    assert_eq!(token_restricting_sids(token.raw()).unwrap(), ["S-1-5-12"]);
    assert!(!crate::windows::security::write_restricted_behavior_attested(token.raw()).unwrap());
    // CreateRestrictedToken requires zero attributes on input. Windows marks
    // the resultant TokenRestrictedSids entry with provider-owned group flags;
    // its security effect is defined by membership in this separate list.
    assert!(
        token_restricting_sid_attributes(token.raw(), "S-1-5-12")
            .unwrap()
            .is_some()
    );
    assert!(!token_has_restricting_sid(token.raw(), "S-1-5-11").unwrap());
}

#[test]
fn one_token_handle_supplies_a_coherent_identity_snapshot() {
    let token = restricted_current_primary().unwrap();
    let snapshot = token_attestation_snapshot(token.raw()).unwrap();

    assert!(token_user_sid(token.raw()).unwrap().starts_with("S-1-5-"));
    assert!(token_has_enabled_group(token.raw(), "S-1-1-0").unwrap());
    assert!(token_has_restricting_sid(token.raw(), "S-1-5-12").unwrap());
    assert_ne!(snapshot.instance.token_id, 0);
    assert_eq!(
        snapshot.lineage.authentication_id,
        snapshot.behavior.envelope.authentication_id
    );
    assert_eq!(
        snapshot.lineage.user_sid,
        snapshot.behavior.envelope.user_sid
    );
    assert_eq!(
        snapshot.lineage.session_id,
        snapshot.behavior.envelope.session_id
    );
    assert!(snapshot.behavior.token_is_restricted);
    assert!(!snapshot.behavior.restricting_sids.is_empty());
    assert!(snapshot.behavior.default_dacl_sha256.is_some());
}

#[test]
fn process_query_and_owner_source_capabilities_are_not_interchangeable() {
    let query_only = process_token(unsafe { GetCurrentProcess() }).unwrap();
    let query = token_query_attestation_snapshot(query_only.raw()).unwrap();
    assert_ne!(query.instance.token_id, 0);
    assert!(token_attestation_snapshot(query_only.raw()).is_err());

    let access_check = current_process_token_for_access_check().unwrap();
    assert_eq!(
        granted_handle_access(access_check.raw()).unwrap(),
        TOKEN_QUERY | TOKEN_DUPLICATE
    );
    let access_check_query = token_query_attestation_snapshot(access_check.raw()).unwrap();
    assert_eq!(query, access_check_query);
    assert!(token_attestation_snapshot(access_check.raw()).is_err());

    let owner_source = current_process_token_for_attestation().unwrap();
    let complete = token_attestation_snapshot(owner_source.raw()).unwrap();
    assert_eq!(query.instance.token_id, complete.instance.token_id);
    assert_eq!(
        query.lineage.authentication_id,
        complete.lineage.authentication_id
    );
    assert_eq!(query.behavior, complete.behavior);

    let attestation_access_check =
        current_process_token_for_attestation_and_access_check().unwrap();
    assert_eq!(
        granted_handle_access(attestation_access_check.raw()).unwrap(),
        TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE
    );
    let attestation_access_check_query =
        token_query_attestation_snapshot(attestation_access_check.raw()).unwrap();
    assert_eq!(query, attestation_access_check_query);
    assert_eq!(
        complete,
        token_attestation_snapshot(attestation_access_check.raw()).unwrap()
    );
}

#[test]
fn assigned_process_authority_ignores_only_token_id_and_types_every_other_difference() {
    let token = restricted_current_primary().unwrap();
    let source = token_attestation_snapshot(token.raw()).unwrap();
    let mut assigned = source.query_evidence();
    assigned.instance.token_id = assigned.instance.token_id.wrapping_add(1).max(1);
    require_assigned_process_authority("unit-assignment", &source, &assigned).unwrap();
    assert!(
        require_same_token_instance(
            "unit-same-object",
            &source,
            &token_attestation_snapshot(token.raw()).unwrap()
        )
        .is_ok()
    );

    let mut source_provenance_mutation = source.clone();
    source_provenance_mutation.lineage.source_name[0] ^= 1;
    source_provenance_mutation.lineage.source_identifier ^= 1;
    require_assigned_process_authority(
        "unit-assignment-source-provenance-is-separate",
        &source_provenance_mutation,
        &assigned,
    )
    .unwrap();

    let mut mutations: Vec<(
        &str,
        Box<dyn Fn(&mut crate::windows::token::TokenQueryAttestationSnapshot)>,
    )> = vec![
        (
            "ModifiedId",
            Box::new(|value| value.instance.modified_id ^= 1),
        ),
        (
            "AuthenticationId",
            Box::new(|value| value.lineage.authentication_id ^= 1),
        ),
        (
            "OriginatingLogonSession",
            Box::new(|value| value.lineage.originating_logon_session ^= 1),
        ),
        (
            "UserSid",
            Box::new(|value| value.lineage.user_sid.push_str("-1")),
        ),
        ("SessionId", Box::new(|value| value.lineage.session_id ^= 1)),
        (
            "OwnerSid",
            Box::new(|value| value.behavior.envelope.owner_sid.push_str("-1")),
        ),
        (
            "Groups",
            Box::new(|value| value.behavior.groups.push("S-1-0-0@0".to_owned())),
        ),
        (
            "Privileges",
            Box::new(|value| value.behavior.privileges.push("0:0@0".to_owned())),
        ),
        (
            "RestrictingSids",
            Box::new(|value| value.behavior.restricting_sids.push("S-1-0-0@0".to_owned())),
        ),
        (
            "IsTokenRestricted",
            Box::new(|value| {
                value.behavior.token_is_restricted = !value.behavior.token_is_restricted
            }),
        ),
        (
            "EnabledSensitivePrivilegeCount",
            Box::new(|value| value.behavior.enabled_sensitive_privilege_count ^= 1),
        ),
        (
            "DefaultDacl",
            Box::new(|value| value.behavior.default_dacl_sha256 = None),
        ),
    ];
    for (expected, mutate) in mutations.drain(..) {
        let mut observed = assigned.clone();
        mutate(&mut observed);
        let error = require_assigned_process_authority("unit-assignment", &source, &observed)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "missing {expected} in {error}");
    }
}

#[test]
fn assigned_full_source_authority_ignores_only_token_id() {
    let token = restricted_current_primary().unwrap();
    let source = token_attestation_snapshot(token.raw()).unwrap();
    let mut assigned = source.clone();
    assigned.instance.token_id = assigned.instance.token_id.wrapping_add(1).max(1);
    let evidence =
        require_assigned_token_authority("unit-full-source-assignment", &source, &assigned)
            .unwrap();
    assert_eq!(evidence.source_token_id, source.instance.token_id);
    assert_eq!(evidence.process_token_id, assigned.instance.token_id);
    assert_eq!(evidence.modified_id, source.instance.modified_id);
    assert!(!evidence.same_token_id);

    type SnapshotMutation = Box<dyn Fn(&mut crate::windows::token::TokenAttestationSnapshot)>;
    let mutations: Vec<(&str, SnapshotMutation)> = vec![
        (
            "ModifiedId",
            Box::new(|value| value.instance.modified_id ^= 1),
        ),
        (
            "AuthenticationId",
            Box::new(|value| value.lineage.authentication_id ^= 1),
        ),
        (
            "OriginatingLogonSession",
            Box::new(|value| value.lineage.originating_logon_session ^= 1),
        ),
        (
            "SourceName",
            Box::new(|value| value.lineage.source_name[0] ^= 1),
        ),
        (
            "SourceIdentifier",
            Box::new(|value| value.lineage.source_identifier ^= 1),
        ),
        (
            "UserSid",
            Box::new(|value| value.lineage.user_sid.push_str("-1")),
        ),
        ("SessionId", Box::new(|value| value.lineage.session_id ^= 1)),
        (
            "OwnerSid",
            Box::new(|value| value.behavior.envelope.owner_sid.push_str("-1")),
        ),
        (
            "UserSid",
            Box::new(|value| value.behavior.envelope.user_sid.push_str("-1")),
        ),
        (
            "PrimaryGroupSid",
            Box::new(|value| value.behavior.envelope.primary_group_sid.push_str("-1")),
        ),
        (
            "GroupsDigest",
            Box::new(|value| value.behavior.envelope.groups_sha256.push('0')),
        ),
        (
            "PrivilegesDigest",
            Box::new(|value| value.behavior.envelope.privileges_sha256.push('0')),
        ),
        (
            "RestrictingSidsDigest",
            Box::new(|value| value.behavior.envelope.restricted_sids_sha256.push('0')),
        ),
        (
            "IntegrityLevel",
            Box::new(|value| value.behavior.envelope.integrity_level.push_str("-1")),
        ),
        (
            "MandatoryPolicy",
            Box::new(|value| value.behavior.envelope.mandatory_policy ^= 1),
        ),
        (
            "SessionId",
            Box::new(|value| value.behavior.envelope.session_id ^= 1),
        ),
        (
            "AuthenticationId",
            Box::new(|value| value.behavior.envelope.authentication_id ^= 1),
        ),
        (
            "ElevationType",
            Box::new(|value| value.behavior.envelope.elevation_type ^= 1),
        ),
        (
            "Elevated",
            Box::new(|value| value.behavior.envelope.elevated = !value.behavior.envelope.elevated),
        ),
        (
            "VirtualizationAllowed",
            Box::new(|value| {
                value.behavior.envelope.virtualization_allowed =
                    !value.behavior.envelope.virtualization_allowed
            }),
        ),
        (
            "VirtualizationEnabled",
            Box::new(|value| {
                value.behavior.envelope.virtualization_enabled =
                    !value.behavior.envelope.virtualization_enabled
            }),
        ),
        (
            "UiAccess",
            Box::new(|value| {
                value.behavior.envelope.ui_access = !value.behavior.envelope.ui_access
            }),
        ),
        (
            "Appcontainer",
            Box::new(|value| {
                value.behavior.envelope.appcontainer = !value.behavior.envelope.appcontainer
            }),
        ),
        (
            "TokenType",
            Box::new(|value| value.behavior.envelope.token_type ^= 1),
        ),
        (
            "ImpersonationLevel",
            Box::new(|value| value.behavior.envelope.impersonation_level ^= 1),
        ),
        (
            "Groups",
            Box::new(|value| value.behavior.groups.push("S-1-0-0@0".to_owned())),
        ),
        (
            "Privileges",
            Box::new(|value| value.behavior.privileges.push("0:0@0".to_owned())),
        ),
        (
            "RestrictingSids",
            Box::new(|value| value.behavior.restricting_sids.push("S-1-0-0@0".to_owned())),
        ),
        (
            "IsTokenRestricted",
            Box::new(|value| {
                value.behavior.token_is_restricted = !value.behavior.token_is_restricted
            }),
        ),
        (
            "EnabledSensitivePrivilegeCount",
            Box::new(|value| value.behavior.enabled_sensitive_privilege_count ^= 1),
        ),
        (
            "DefaultDacl",
            Box::new(|value| {
                value.behavior.default_dacl_sha256 = value
                    .behavior
                    .default_dacl_sha256
                    .take()
                    .map_or_else(|| Some("mutation".to_owned()), |_| None)
            }),
        ),
    ];
    for (expected, mutate) in mutations {
        let mut observed = assigned.clone();
        mutate(&mut observed);
        let error =
            require_assigned_token_authority("unit-full-source-assignment", &source, &observed)
                .unwrap_err()
                .to_string();
        assert!(error.contains(expected), "missing {expected} in {error}");
    }

    let mut zero_source = source.clone();
    zero_source.instance.token_id = 0;
    let error =
        require_assigned_token_authority("unit-full-source-assignment", &zero_source, &assigned)
            .unwrap_err()
            .to_string();
    assert!(error.contains("SourceTokenIdZero"), "{error}");

    let mut zero_assigned = assigned;
    zero_assigned.instance.token_id = 0;
    let error =
        require_assigned_token_authority("unit-full-source-assignment", &source, &zero_assigned)
            .unwrap_err()
            .to_string();
    assert!(error.contains("ProcessTokenIdZero"), "{error}");
}

#[test]
fn primary_token_envelope_uses_canonical_non_applicable_impersonation_level() {
    let token = restricted_current_primary().unwrap();
    let envelope = envelope(token.raw()).unwrap();

    assert_eq!(envelope.token_type, TokenPrimary as u32);
    assert_eq!(envelope.impersonation_level, SecurityAnonymous as u32);
}

#[test]
fn write_restricted_alternate_primary_preserves_identity_and_session() {
    let parent = crate::windows::token::current_thread_envelope().unwrap();
    let token = write_restricted_current_primary().unwrap();
    let alternate = envelope(token.raw()).unwrap();

    assert_eq!(alternate.token_type, TokenPrimary as u32);
    assert!(crate::windows::token::token_is_restricted(token.raw()));
    assert!(token_has_restricting_sid(token.raw(), "S-1-5-33").unwrap());
    assert!(!token_has_restricting_sid(token.raw(), "S-1-5-12").unwrap());
    assert_eq!(token_restricting_sids(token.raw()).unwrap(), ["S-1-5-33"]);
    assert!(crate::windows::security::write_restricted_behavior_attested(token.raw()).unwrap());
    assert_eq!(alternate.user_sid, parent.user_sid);
    assert_eq!(alternate.authentication_id, parent.authentication_id);
    assert_eq!(alternate.session_id, parent.session_id);
}

#[test]
fn nested_initial_token_is_restricted_same_access_impersonation() {
    let token = nested_initial_thread_token_for_test().unwrap();
    let snapshot = token_attestation_snapshot(token.raw()).unwrap();
    let restricting_sids = token_restricting_sids(token.raw()).unwrap();

    assert_eq!(
        snapshot.behavior.envelope.token_type,
        TokenImpersonation as u32
    );
    assert_eq!(
        snapshot.behavior.envelope.impersonation_level,
        SecurityImpersonation as u32
    );
    assert!(!snapshot.behavior.envelope.elevated);
    assert!(!snapshot.behavior.envelope.appcontainer);
    assert!(!snapshot.behavior.envelope.ui_access);
    assert!(snapshot.behavior.token_is_restricted);
    assert!(!restricting_sids.is_empty());
    assert_eq!(snapshot.behavior.enabled_sensitive_privilege_count, 0);
    assert_eq!(
        restricting_sids,
        canonical_same_access_restricting_sids(token.raw()).unwrap()
    );
}

#[test]
fn privilege_parser_uses_all_entries_from_the_original_buffer_and_rejects_truncation() {
    let entries = [
        LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 11,
                HighPart: 1,
            },
            Attributes: 0,
        },
        LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 22,
                HighPart: 2,
            },
            Attributes: 1,
        },
        LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 33,
                HighPart: 3,
            },
            Attributes: 2,
        },
    ];
    let fixed = offset_of!(TOKEN_PRIVILEGES, Privileges);
    let (mut words, byte_length) = variable_buffer(fixed, &entries);
    let parsed = token_privilege_entries(bytes(&words, byte_length)).unwrap();
    assert_eq!(parsed.len(), entries.len());
    assert_eq!(parsed[2].Luid.LowPart, 33);
    assert_eq!(parsed[2].Attributes, 2);

    // SAFETY: the live buffer begins with the declared native u32 count.
    unsafe { ptr::write_unaligned(words.as_mut_ptr().cast::<u32>(), 4) };
    assert!(token_privilege_entries(bytes(&words, byte_length)).is_err());
}

#[test]
fn multi_entry_group_and_privilege_digests_are_canonical() {
    let everyone = OwnedSid::parse("S-1-1-0");
    let authenticated = OwnedSid::parse("S-1-5-11");
    let groups = [
        SID_AND_ATTRIBUTES {
            Sid: everyone.0,
            Attributes: 4,
        },
        SID_AND_ATTRIBUTES {
            Sid: authenticated.0,
            Attributes: 7,
        },
    ];
    let reversed_groups = [groups[1], groups[0]];
    let group_fixed = offset_of!(TOKEN_GROUPS, Groups);
    let (group_words, group_bytes) = variable_buffer(group_fixed, &groups);
    let (reversed_group_words, reversed_group_bytes) =
        variable_buffer(group_fixed, &reversed_groups);
    assert_eq!(
        groups_digest(bytes(&group_words, group_bytes)).unwrap(),
        groups_digest(bytes(&reversed_group_words, reversed_group_bytes)).unwrap()
    );

    let privileges = [
        LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 41,
                HighPart: 4,
            },
            Attributes: 2,
        },
        LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 17,
                HighPart: 1,
            },
            Attributes: 0,
        },
    ];
    let reversed_privileges = [privileges[1], privileges[0]];
    let privilege_fixed = offset_of!(TOKEN_PRIVILEGES, Privileges);
    let (privilege_words, privilege_bytes) = variable_buffer(privilege_fixed, &privileges);
    let (reversed_privilege_words, reversed_privilege_bytes) =
        variable_buffer(privilege_fixed, &reversed_privileges);
    assert_eq!(
        privileges_digest(bytes(&privilege_words, privilege_bytes)).unwrap(),
        privileges_digest(bytes(&reversed_privilege_words, reversed_privilege_bytes)).unwrap()
    );
}

fn normalized_session_broker_privileges() -> Vec<LUID_AND_ATTRIBUTES> {
    let mut entries = [
        ("SeAssignPrimaryTokenPrivilege", 0),
        ("SeIncreaseQuotaPrivilege", 0),
        ("SeImpersonatePrivilege", 0x0000_0001),
        ("SeSecurityPrivilege", 0),
        ("SeTcbPrivilege", 0x0000_0001),
        ("SeChangeNotifyPrivilege", 0x0000_0003),
    ]
    .map(|(name, attributes)| LUID_AND_ATTRIBUTES {
        Luid: privilege_luid(name),
        Attributes: attributes,
    })
    .to_vec();
    entries.sort_by_key(|entry| (entry.Luid.HighPart, entry.Luid.LowPart));
    entries
}

#[test]
fn session_broker_source_disable_transition_clears_only_impersonate_and_tcb() {
    let after = normalized_session_broker_privileges();
    let impersonate = privilege_luid("SeImpersonatePrivilege");
    let tcb = privilege_luid("SeTcbPrivilege");
    let disabled = [impersonate, tcb];
    let mut before = after.clone();
    for entry in &mut before {
        if disabled
            .iter()
            .any(|luid| entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart)
        {
            entry.Attributes |= 0x0000_0002;
        }
    }
    assert!(exact_disabled_privilege_set_transition_for_test(
        &before, &after, &disabled
    ));
    assert!(normalized_session_broker_privilege_entries_for_test(&after).unwrap());
    assert!(!exact_disabled_privilege_set_transition_for_test(
        &after, &after, &disabled,
    ));
    let wrong_luid = [LUID {
        LowPart: u32::MAX,
        HighPart: i32::MAX,
    }];
    assert!(!exact_disabled_privilege_set_transition_for_test(
        &before,
        &after,
        &wrong_luid,
    ));

    let mut one_left_enabled = after.clone();
    one_left_enabled
        .iter_mut()
        .find(|entry| entry.Luid.LowPart == tcb.LowPart && entry.Luid.HighPart == tcb.HighPart)
        .unwrap()
        .Attributes |= 0x0000_0002;
    assert!(!exact_disabled_privilege_set_transition_for_test(
        &before,
        &one_left_enabled,
        &disabled,
    ));
    assert!(!normalized_session_broker_privilege_entries_for_test(&one_left_enabled).unwrap());

    let mut unrelated_changed = after.clone();
    unrelated_changed
        .iter_mut()
        .find(|entry| {
            entry.Luid.LowPart == privilege_luid("SeSecurityPrivilege").LowPart
                && entry.Luid.HighPart == privilege_luid("SeSecurityPrivilege").HighPart
        })
        .unwrap()
        .Attributes |= 0x0000_0002;
    assert!(!exact_disabled_privilege_set_transition_for_test(
        &before,
        &unrelated_changed,
        &disabled,
    ));
    assert!(!normalized_session_broker_privilege_entries_for_test(&unrelated_changed).unwrap());

    let mut removed = after.clone();
    removed
        .iter_mut()
        .find(|entry| {
            entry.Luid.LowPart == impersonate.LowPart && entry.Luid.HighPart == impersonate.HighPart
        })
        .unwrap()
        .Attributes |= 0x0000_0004;
    assert!(!exact_disabled_privilege_set_transition_for_test(
        &before, &removed, &disabled,
    ));
    assert!(!normalized_session_broker_privilege_entries_for_test(&removed).unwrap());

    let mut change_notify_disabled = after.clone();
    change_notify_disabled
        .iter_mut()
        .find(|entry| {
            let change_notify = privilege_luid("SeChangeNotifyPrivilege");
            entry.Luid.LowPart == change_notify.LowPart
                && entry.Luid.HighPart == change_notify.HighPart
        })
        .unwrap()
        .Attributes &= !0x0000_0002;
    assert!(!exact_disabled_privilege_set_transition_for_test(
        &before,
        &change_notify_disabled,
        &disabled,
    ));
    assert!(
        !normalized_session_broker_privilege_entries_for_test(&change_notify_disabled).unwrap()
    );

    let mut reordered = after.clone();
    reordered.swap(0, 1);
    assert!(!exact_disabled_privilege_set_transition_for_test(
        &before, &reordered, &disabled,
    ));
    assert!(!normalized_session_broker_privilege_entries_for_test(&reordered).unwrap());

    assert!(!exact_disabled_privilege_set_transition_for_test(
        &before,
        &after[..after.len() - 1],
        &disabled,
    ));
    assert!(
        !normalized_session_broker_privilege_entries_for_test(&after[..after.len() - 1]).unwrap()
    );
    let mut extra = after.clone();
    extra.push(LUID_AND_ATTRIBUTES {
        Luid: LUID {
            LowPart: u32::MAX,
            HighPart: i32::MAX,
        },
        Attributes: 0,
    });
    assert!(!normalized_session_broker_privilege_entries_for_test(&extra).unwrap());
    let mut duplicate = after.clone();
    duplicate[0] = duplicate[1];
    duplicate.sort_by_key(|entry| (entry.Luid.HighPart, entry.Luid.LowPart));
    assert!(!normalized_session_broker_privilege_entries_for_test(&duplicate).unwrap());
}
