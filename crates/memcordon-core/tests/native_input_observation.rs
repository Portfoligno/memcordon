use memcordon_core::*;

fn envelope() -> WindowsCallerTokenEnvelopeV1 {
    WindowsCallerTokenEnvelopeV1 {
        user_sid: "S-1-5-21-1".into(),
        owner_sid: "S-1-5-21-1".into(),
        primary_group_sid: "S-1-5-32-545".into(),
        groups_sha256: "a".repeat(64),
        privileges_sha256: "b".repeat(64),
        restricted_sids_sha256: "c".repeat(64),
        integrity_level: "S-1-16-8192".into(),
        mandatory_policy: 1,
        session_id: 1,
        elevation_type: 3,
        elevated: false,
        virtualization_allowed: false,
        virtualization_enabled: false,
        ui_access: false,
        appcontainer: false,
        authentication_id: 12,
        token_type: 2,
        impersonation_level: 2,
    }
}
fn observed() -> NativeInputStageV1 {
    NativeInputStageV1::Observed {
        summary: NativeTokenSummaryV1::from_envelope(&envelope()).unwrap(),
    }
}
fn observation() -> WindowsNativeInputObservationV1 {
    WindowsNativeInputObservationV1::new(
        [2; 32],
        [3; 32],
        WindowsProcessIdentityV1 {
            process_id: 4,
            creation_time_100ns: 5,
        },
        NativeInputCaptureV1 {
            authenticated: observed(),
            duplicated: observed(),
            prepared: observed(),
            frontend: observed(),
        },
    )
}
fn provider() -> PublicProviderBindingV1 {
    PublicProviderBindingV1 {
        generation: BoundedText::new("provider").unwrap(),
        source_commit: BoundedText::new(&"a".repeat(40)).unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
    }
}

#[test]
fn native_hash_is_full_and_derived_projection_changes_only_type_and_level() {
    use sha2::{Digest, Sha256};
    let source = envelope();
    let summary = NativeTokenSummaryV1::from_envelope(&source).unwrap();
    assert_eq!(
        summary.envelope_sha256,
        <[u8; 32]>::from(Sha256::digest(serde_json::to_vec(&source).unwrap()))
    );
    let mut primary = source.clone();
    primary.token_type = 1;
    primary.impersonation_level = 0;
    let expected = NativeTokenSummaryV1::from_envelope(&primary).unwrap();
    assert_eq!(
        summary.derived_primary_projection_sha256,
        expected.envelope_sha256
    );
    assert_ne!(summary.envelope_sha256, expected.envelope_sha256);
    assert_eq!(summary.groups_sha256, expected.groups_sha256);
    assert_eq!(summary.privileges_sha256, expected.privileges_sha256);
    assert_eq!(summary.group_count, None);
    assert_eq!(summary.privilege_count, None);
    assert_eq!(summary.clone().with_counts(0, 0).group_count, Some(0));
    let mut rights_changed = primary;
    rights_changed.privileges_sha256 = "d".repeat(64);
    let changed = NativeTokenSummaryV1::from_envelope(&rights_changed).unwrap();
    assert_ne!(
        summary.derived_primary_projection_sha256,
        changed.derived_primary_projection_sha256
    );
    let wire = serde_json::to_value(&summary).unwrap();
    assert_eq!(wire["digest_kind"], "native-envelope-json-v1");
    assert!(wire.get("user_sid").is_none());
    assert_eq!(source.token_type, 2);
}

#[test]
fn stages_are_immutable_and_binding_and_target_identity_cannot_be_replaced() {
    let original = observation();
    assert!(original.is_bound_to(
        &"02".repeat(32),
        &"03".repeat(32),
        &original.frontend_identity
    ));
    assert!(!original.is_bound_to(
        &"04".repeat(32),
        &"03".repeat(32),
        &original.frontend_identity
    ));
    let mut next = original.clone();
    next.launcher_primary = observed();
    next.target_identity = Some(WindowsProcessIdentityV1 {
        process_id: 6,
        creation_time_100ns: 7,
    });
    next.suspended_target = observed();
    let mut current = original.clone();
    current.monotonic_update(next.clone()).unwrap();
    assert!(current.monotonic_update(original).is_err());
    for field in ["attempt", "request", "frontend", "target", "stage"] {
        let mut replaced = next.clone();
        match field {
            "attempt" => replaced.attempt_sha256[0] ^= 1,
            "request" => replaced.request_sha256[0] ^= 1,
            "frontend" => replaced.frontend_identity.creation_time_100ns += 1,
            "target" => {
                replaced
                    .target_identity
                    .as_mut()
                    .unwrap()
                    .creation_time_100ns += 1
            }
            "stage" => {
                replaced.control.authenticated = NativeInputStageV1::Unavailable {
                    reason: NativeInputUnavailableV1::QueryFailed,
                    native_error: Some(5),
                }
            }
            _ => unreachable!(),
        }
        assert!(!replaced.is_monotonic_extension_of(&next), "{field}");
    }
    let mut missing_target = next;
    missing_target.target_identity = None;
    assert!(!missing_target.is_consistent());
}

#[test]
fn neutral_observation_roundtrips_without_becoming_a_failure_and_binds_projection() {
    let mut journal = WindowsCausalDiagnosticsV1::default();
    let old_wire = serde_json::to_vec(&journal).unwrap();
    assert!(
        !String::from_utf8(old_wire.clone())
            .unwrap()
            .contains("native_inputs")
    );
    let old_projection = ProviderFailureDiagnosticV1::from_journal(
        provider(),
        &"02".repeat(32),
        &"03".repeat(32),
        &journal,
    )
    .unwrap();
    let original = journal.original.clone();
    journal.set_native_inputs(observation()).unwrap();
    assert_eq!(journal.schema_version, 2);
    assert_eq!(journal.original, original);
    assert_eq!(journal.sequence, 0);
    assert!(journal.secondary.as_slice().is_empty());
    assert_eq!(journal.loss, DiagnosticLossV1::default());
    let bytes = serde_json::to_vec(&journal).unwrap();
    assert!(bytes.len() < MAX_DIAGNOSTIC_JOURNAL_BYTES);
    assert_eq!(WindowsCausalDiagnosticsV1::parse(&bytes).unwrap(), journal);
    let projection = ProviderFailureDiagnosticV1::from_journal(
        provider(),
        &"02".repeat(32),
        &"03".repeat(32),
        &journal,
    )
    .unwrap();
    assert!(projection.matches_journal(&"02".repeat(32), &"03".repeat(32), &journal));
    assert_ne!(
        projection.projection_sha256,
        old_projection.projection_sha256
    );
    assert_eq!(projection.safe_summary(), old_projection.safe_summary());
    let bytes = serde_json::to_vec(&projection).unwrap();
    ProviderFailureDiagnosticV1::parse_bound(
        &bytes,
        &provider(),
        &DiagnosticSha256::from_bytes([2; 32]),
        &DiagnosticSha256::from_bytes([3; 32]),
    )
    .unwrap();
    assert!(
        ProviderFailureDiagnosticV1::from_journal(
            provider(),
            &"04".repeat(32),
            &"03".repeat(32),
            &journal
        )
        .is_err()
    );
    let mut copied = WindowsCausalDiagnosticsV1::default();
    journal.copy_into_reserved(&mut copied);
    assert_eq!(copied, journal);
    let mut changed = projection;
    changed.native_inputs.as_mut().unwrap().control.frontend = NativeInputStageV1::Unavailable {
        reason: NativeInputUnavailableV1::FrontendTokenOpen,
        native_error: Some(5),
    };
    assert!(
        ProviderFailureDiagnosticV1::parse_bound(
            &serde_json::to_vec(&changed).unwrap(),
            &provider(),
            &DiagnosticSha256::from_bytes([2; 32]),
            &DiagnosticSha256::from_bytes([3; 32])
        )
        .is_err()
    );
    assert_eq!(
        serde_json::to_vec(&WindowsCausalDiagnosticsV1::parse(&old_wire).unwrap()).unwrap(),
        old_wire
    );
}

#[test]
fn closed_fixed_payload_fits_its_budget_and_absence_version_is_explicit() {
    let mut value = observation();
    value.attempt_sha256 = [255; 32];
    value.request_sha256 = [255; 32];
    value.frontend_identity = WindowsProcessIdentityV1 {
        process_id: u32::MAX,
        creation_time_100ns: u64::MAX,
    };
    let mut summary = NativeTokenSummaryV1::from_envelope(&envelope())
        .unwrap()
        .with_counts(u32::MAX, u32::MAX);
    summary.envelope_sha256 = [255; 32];
    summary.derived_primary_projection_sha256 = [255; 32];
    summary.groups_sha256 = [255; 32];
    summary.privileges_sha256 = [255; 32];
    summary.restricted_sids_sha256 = [255; 32];
    summary.token_type = u32::MAX;
    summary.impersonation_level = u32::MAX;
    let stage = NativeInputStageV1::Observed { summary };
    value.control = NativeInputCaptureV1 {
        authenticated: stage.clone(),
        duplicated: stage.clone(),
        prepared: stage.clone(),
        frontend: stage.clone(),
    };
    value.launcher_primary = stage.clone();
    value.suspended_target = stage;
    value.target_identity = Some(WindowsProcessIdentityV1 {
        process_id: u32::MAX,
        creation_time_100ns: u64::MAX,
    });
    assert!(value.is_consistent());
    assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_NATIVE_INPUT_OBSERVATION_BYTES);
    let mut wire = serde_json::to_value(&value).unwrap();
    wire["extra"] = true.into();
    assert!(serde_json::from_value::<WindowsNativeInputObservationV1>(wire).is_err());
    let mut journal = WindowsCausalDiagnosticsV1 {
        native_inputs: Some(value),
        ..WindowsCausalDiagnosticsV1::default()
    };
    assert!(
        !journal.is_consistent(),
        "schema1 must not silently claim new strict-reader compatibility"
    );
    journal.schema_version = 2;
    assert!(journal.is_consistent());
    journal.native_inputs = None;
    assert!(!journal.is_consistent());
    let mut malformed = envelope();
    malformed.groups_sha256 = "X".repeat(64);
    assert!(NativeTokenSummaryV1::from_envelope(&malformed).is_err());
    let unavailable = NativeInputStageV1::Unavailable {
        reason: NativeInputUnavailableV1::QueryFailed,
        native_error: None,
    };
    let zero = NativeInputStageV1::Unavailable {
        reason: NativeInputUnavailableV1::QueryFailed,
        native_error: Some(0),
    };
    assert_ne!(unavailable, zero);
    assert!(serde_json::to_value(unavailable).unwrap()["native_win32_error"].is_null());
    assert_eq!(serde_json::to_value(zero).unwrap()["native_win32_error"], 0);
}

#[test]
fn neutral_stages_preserve_real_original_secondary_and_loss_classification() {
    let event = CausalEventV1 {
        sequence: 0,
        origin: DiagnosticOriginV1::Launcher,
        category: FailureCategoryV1::Monitor,
        operation: FailureOperationV1::ObserveProcessIdentity,
        code: FailureCodeV1::ProcessInventoryObservation,
        native_code: Some(NativeFailureCodeV1::Win32(5)),
        observed_phase: AttemptObservationPhaseV1::Monitoring,
        safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    };
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(event.clone()).unwrap();
    journal.observe_secondary(event).unwrap();
    let before = journal.clone();
    journal.set_native_inputs(observation()).unwrap();
    assert_eq!(journal.original, before.original);
    assert_eq!(journal.secondary, before.secondary);
    assert_eq!(journal.sequence, before.sequence);
    assert_eq!(journal.loss, before.loss);
    assert!(journal.is_consistent());
}
