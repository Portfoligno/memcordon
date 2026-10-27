#[path = "private/fixture_namespace_primary_protocol.rs"]
mod protocol;
use protocol::*;
use serde_json::json;

fn request() -> Request {
    let user = "S-1-5-21-1-2-3-1001".to_owned();
    Request {
        revision: REVISION,
        nonce: "a".repeat(32),
        cell: Cell::Private,
        alias: "owned-alias".into(),
        boundary: "owned-boundary".into(),
        event: "original-event".into(),
        user_sid: user.clone(),
        deadline_qpc: u64::MAX,
        qpc_frequency: 10_000_000,
        expected_default_acl_sha256: "a".repeat(size_of::<[u8; 32]>() * 2),
        expected_token: memcordon_core::WindowsCallerTokenEnvelopeV1 {
            user_sid: user,
            owner_sid: "S-1-5-32-544".into(),
            primary_group_sid: "S-1-5-21-1-2-3-513".into(),
            groups_sha256: "1".repeat(64),
            privileges_sha256: "2".repeat(64),
            restricted_sids_sha256: "3".repeat(64),
            integrity_level: "S-1-16-12288".into(),
            mandatory_policy: 1,
            session_id: 2,
            elevation_type: 2,
            elevated: true,
            virtualization_allowed: false,
            virtualization_enabled: false,
            ui_access: false,
            appcontainer: false,
            authentication_id: u64::MAX,
            token_type: 1,
            impersonation_level: 0,
        },
    }
}
fn frame(value: serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn all_closed_cells_and_native_observations_roundtrip_without_narrowing() {
    for cell in [
        Cell::Local,
        Cell::Private,
        Cell::NamespaceDenied,
        Cell::EventDenied,
        Cell::WrongBoundary,
    ] {
        let mut value = request();
        value.cell = cell;
        let bytes = encode_request(&value).unwrap();
        assert!(bytes.len() <= FRAME_BOUND);
        assert_eq!(decode_request(&bytes).unwrap(), value);
    }
    for phase in [
        Phase::Primary,
        Phase::Namespace,
        Phase::Event,
        Phase::Held,
        Phase::Completed,
    ] {
        for success in [false, true] {
            if phase == Phase::Held && !success {
                continue;
            }
            let value = Response {
                revision: REVISION,
                nonce: request().nonce,
                phase,
                success,
                raw_error: (!success).then_some(5),
                event_handle: if success && phase == Phase::Held {
                    Some(u64::MAX)
                } else {
                    None
                },
                modify_denied: success.then_some(true),
                diagnostics: DiagnosticState::NotApplicable,
            };
            assert_eq!(
                decode_response(&encode_response(&value).unwrap()).unwrap(),
                value
            );
        }
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_ack(&request().nonce).unwrap())
            .unwrap(),
        json!({"revision":REVISION,"nonce":request().nonce})
    );
    assert!(encode_ack("foreign").is_err());
}

#[test]
fn request_admission_rejects_unbound_or_malformed_native_inputs() {
    let original = serde_json::to_value(request()).unwrap();
    for (field, bad) in [
        ("revision", json!(1)),
        ("nonce", json!("A".repeat(32))),
        ("nonce", json!("a".repeat(31))),
        ("cell", json!("Fallback")),
        ("deadline_qpc", json!(0)),
        ("qpc_frequency", json!(0)),
        ("unreviewed", json!(true)),
    ] {
        let mut value = original.clone();
        value[field] = bad;
        assert!(decode_request(&frame(value)).is_err(), "{field}");
    }
    for field in ["alias", "boundary", "event"] {
        for bad in [
            "".to_owned(),
            ".".into(),
            "..".into(),
            "Local\\name".into(),
            "a/b".into(),
            "a\0b".into(),
            "a\nb".into(),
            "x".repeat(NAME_UNITS_BOUND + 1),
            "😀".repeat(NAME_UNITS_BOUND),
        ] {
            let mut value = original.clone();
            value[field] = json!(bad);
            assert!(decode_request(&frame(value)).is_err(), "{field}");
        }
    }
    for bad in [
        "S-1-5",
        "s-1-5-18",
        "S-2-5-18",
        "S-1-05-18",
        "S-1-5-018",
        "S-1-281474976710656-1",
        "S-1-5-4294967296",
        "S-1-5-1\0",
        "S-1-5--1",
    ] {
        let mut value = original.clone();
        value["user_sid"] = json!(bad);
        assert!(decode_request(&frame(value)).is_err(), "{bad:?}");
    }
    let mut value = request();
    value.alias = "😀".repeat(NAME_UNITS_BOUND / 2);
    assert!(encode_request(&value).is_ok());
    value.alias.push('x');
    assert!(encode_request(&value).is_err());
    let mut mismatch = request();
    mismatch.expected_token.user_sid = "S-1-5-18".into();
    assert!(encode_request(&mismatch).is_err());
    for field in [
        "groups_sha256",
        "privileges_sha256",
        "restricted_sids_sha256",
        "owner_sid",
        "primary_group_sid",
        "integrity_level",
    ] {
        let mut value = original.clone();
        value["expected_token"][field] = json!("malformed");
        assert!(decode_request(&frame(value)).is_err());
    }
}

#[test]
fn frames_refuse_duplicate_unknown_multiple_truncated_and_oversized_data() {
    let encoded = encode_request(&request()).unwrap();
    assert!(decode_request(encoded.strip_suffix(b"\n").unwrap()).is_err());
    let mut multiple = encoded.clone();
    multiple.extend_from_slice(&encoded);
    assert!(decode_request(&multiple).is_err());
    let mut trailing = encoded.clone();
    trailing.push(b'\n');
    assert!(decode_request(&trailing).is_err());
    assert!(decode_request(&vec![b'x'; FRAME_BOUND + 1]).is_err());
    assert!(decode_request(b"{\"revision\":1,\"revision\":1}\n").is_err());
    assert!(decode_request(b"{\xff}\n").is_err());
    let response = Response {
        revision: REVISION,
        nonce: request().nonce,
        phase: Phase::Held,
        success: true,
        raw_error: None,
        event_handle: Some(9),
        modify_denied: Some(true),
        diagnostics: DiagnosticState::NotApplicable,
    };
    let original = serde_json::to_value(&response).unwrap();
    for (field, bad) in [
        ("event_handle", json!(0)),
        ("success", json!(false)),
        ("raw_error", json!(5)),
        ("phase", json!("Fallback")),
        ("extra", json!(true)),
        ("revision", json!(0)),
        ("nonce", json!("unbound")),
    ] {
        let mut value = original.clone();
        value[field] = bad;
        assert!(decode_response(&frame(value)).is_err(), "{field}");
    }
    assert!(decode_response(b"{\"success\":true,\"success\":false}\n").is_err());
    for field in [
        "revision",
        "nonce",
        "phase",
        "success",
        "raw_error",
        "event_handle",
        "modify_denied",
        "diagnostics",
    ] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(decode_response(&frame(value)).is_err(), "missing {field}");
    }
}

fn diagnostic_fixture(count: usize) -> (Request, DiagnosticState) {
    try_diagnostic_fixture(count).unwrap()
}
fn try_diagnostic_fixture(count: usize) -> Option<(Request, DiagnosticState)> {
    use memcordon_windows_launch_core::*;
    let mut request = request();
    let normal = vec![
        SidAttributesV1 {
            sid: "S-1-5-32-544".into(),
            attributes: 4
        };
        count
    ];
    let restricted = vec![SidAttributesV1 {
        sid: "S-1-5-12".into(),
        attributes: 4,
    }];
    let privileges = vec![PrivilegeAttributesV1 {
        luid_high: i32::MIN,
        luid_low: u32::MAX,
        attributes: u32::MAX,
    }];
    request.expected_token.groups_sha256 = sid_attributes_digest(&normal).unwrap();
    request.expected_token.restricted_sids_sha256 = sid_attributes_digest(&restricted).unwrap();
    request.expected_token.privileges_sha256 = privilege_attributes_digest(&privileges).unwrap();
    let stats = TokenStatisticsObservationV1 {
        token_id: u64::MAX,
        modified_id: u64::MAX - 1,
        expiration_time: i64::MIN,
        dynamic_charged: u32::MAX,
        dynamic_available: u32::MAX,
        group_count: count as u32,
        privilege_count: 1,
    };
    let token = TokenObservationV1::from_parts(
        request.expected_token.clone(),
        u32::MAX,
        stats,
        normal,
        restricted,
        privileges,
    )
    .ok()?;
    request.expected_default_acl_sha256 = acl_hash(&None);
    let before = SourceObservation {
        role: SourceRole::BeforeOpen,
        started_qpc: 10,
        finished_qpc: 20,
        token: token.clone(),
        default_acl_sha256: request.expected_default_acl_sha256.clone(),
        default_acl_bytes: None,
        no_thread_token_raw_error: 1008,
    };
    let after = SourceObservation {
        role: SourceRole::AfterFailedOpen,
        started_qpc: 30,
        finished_qpc: 40,
        token,
        default_acl_sha256: request.expected_default_acl_sha256.clone(),
        default_acl_bytes: None,
        no_thread_token_raw_error: 1008,
    };
    Some((request, DiagnosticState::Present { before, after }))
}
fn failed(diagnostics: DiagnosticState) -> Response {
    Response {
        revision: REVISION,
        nonce: request().nonce,
        phase: Phase::Event,
        success: false,
        raw_error: Some(5),
        event_handle: None,
        modify_denied: None,
        diagnostics,
    }
}
fn acl_hash(bytes: &Option<Vec<u8>>) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(serde_json::to_vec(bytes).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn complete_diagnostics_join_each_original_collection_to_expected_source_without_atomic_claim() {
    let (request, diagnostics) = diagnostic_fixture(2);
    diagnostics.validate_correspondence(&request).unwrap();
    let original = failed(diagnostics.clone());
    let wire = encode_response(&original).unwrap();
    let observed = decode_response(&wire).unwrap();
    assert_eq!(observed, original);
    observed
        .diagnostics
        .validate_correspondence(&request)
        .unwrap();
    for field in [
        "role",
        "started_qpc",
        "finished_qpc",
        "default_acl_sha256",
        "no_thread_token_raw_error",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["diagnostics"]["after"][field] = match field {
            "role" => json!("before-open"),
            "started_qpc" => json!(1),
            "finished_qpc" => json!(0),
            "default_acl_sha256" => json!("wrong"),
            _ => json!(5),
        };
        assert!(decode_response(&frame(value)).is_err(), "{field}");
    }
    let mut changed = request.clone();
    changed.deadline_qpc = 40;
    assert!(diagnostics.validate_correspondence(&changed).is_err());
    let mut changed = request.clone();
    changed.expected_token.session_id ^= 1;
    assert!(diagnostics.validate_correspondence(&changed).is_err());
    let mut changed = request.clone();
    changed.expected_default_acl_sha256 = "0".repeat(64);
    assert!(diagnostics.validate_correspondence(&changed).is_err());
    let mut malformed = serde_json::to_value(&original).unwrap();
    malformed["diagnostics"]["before"]["token"]["normal_groups"][0]["attributes"] = json!(16);
    let bytes = frame(malformed);
    assert!(decode_response(&bytes).is_err());
    let core = decode_failure_core(&bytes).unwrap();
    assert_eq!(core.raw_error, 5);
    assert_eq!(core.nonce, request.nonce);
    assert!(!core.success && !core.diagnostics_validated && !core.full_frame_canonical_validated);
    assert_eq!(core.frame_bytes, bytes.len());
}

#[test]
fn optional_diagnostic_refusal_preserves_failure_core_but_never_admits_success() {
    let (_, diagnostics) = diagnostic_fixture(1);
    let original = failed(diagnostics);
    let mut malformed = original.clone();
    if let DiagnosticState::Present { before, .. } = &mut malformed.diagnostics {
        before.token.user_attributes ^= 1;
        before.no_thread_token_raw_error = 5;
    }
    let fallback = decode_response(&encode_response(&malformed).unwrap()).unwrap();
    assert_eq!(fallback.raw_error, Some(5));
    assert_eq!(fallback.phase, Phase::Event);
    assert!(!fallback.success);
    assert!(matches!(
        fallback.diagnostics,
        DiagnosticState::Unavailable {
            reason: DiagnosticUnavailableReason::EncodingBoundOrRefused
        }
    ));
    for diagnostic in [
        None,
        Some(json!({"state":"present","before":"broken","after":null})),
        Some(json!({"state":"not-applicable","unexpected":true})),
        Some(
            json!({"state":"unavailable","reason":{"kind":"encoding-bound-or-refused","unexpected":true}}),
        ),
        Some(
            json!({"state":"unavailable","reason":{"kind":"observation","role":"before-open","reason":"count-bound","unexpected":true}}),
        ),
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        if let Some(diagnostic) = diagnostic {
            value["diagnostics"] = diagnostic;
        } else {
            value.as_object_mut().unwrap().remove("diagnostics");
        }
        let bytes = frame(value);
        assert!(decode_response(&bytes).is_err());
        assert_eq!(decode_failure_core(&bytes).unwrap().raw_error, 5);
    }
    let mut success = original.clone();
    success.phase = Phase::Held;
    success.success = true;
    success.raw_error = None;
    success.event_handle = Some(u64::MAX);
    success.diagnostics = DiagnosticState::NotApplicable;
    assert_eq!(
        decode_response(&encode_response(&success).unwrap()).unwrap(),
        success
    );
    let mut invalid = serde_json::to_value(&success).unwrap();
    invalid["diagnostics"] = json!({"state":"not-applicable","unexpected":true});
    let bytes = frame(invalid);
    assert!(decode_response(&bytes).is_err());
    assert!(decode_failure_core(&bytes).is_err());
    let mut invalid = serde_json::to_value(&success).unwrap();
    invalid["diagnostics"] = json!({"state":"present"});
    let bytes = frame(invalid);
    assert!(decode_response(&bytes).is_err());
    assert!(decode_failure_core(&bytes).is_err());
    success.diagnostics = original.diagnostics.clone();
    assert!(encode_response(&success).is_err());
    for (field, value) in [
        ("revision", json!(1)),
        ("nonce", json!("wrong")),
        ("success", json!(true)),
        ("raw_error", json!(null)),
        ("event_handle", json!(1)),
        ("modify_denied", json!(false)),
        ("phase", json!("Completed")),
        ("unknown", json!(true)),
    ] {
        let mut value_json = serde_json::to_value(&original).unwrap();
        value_json[field] = value;
        assert!(decode_failure_core(&frame(value_json)).is_err(), "{field}");
    }
}

#[test]
fn two_complete_observations_exceeding_original_frame_become_wholly_unavailable() {
    let (_, diagnostics) = (1..=memcordon_windows_launch_core::TOKEN_OBSERVATION_ENTRY_BOUND)
        .filter_map(try_diagnostic_fixture)
        .last()
        .unwrap();
    let original = failed(diagnostics);
    let oversized = serde_json::to_vec(&original).unwrap();
    assert!(oversized.len() + b"\n".len() > FRAME_BOUND);
    let bytes = encode_response(&original).unwrap();
    assert!(bytes.len() <= FRAME_BOUND);
    let projected = decode_response(&bytes).unwrap();
    assert_eq!(projected.raw_error, original.raw_error);
    assert_eq!(projected.nonce, original.nonce);
    assert_eq!(projected.phase, original.phase);
    assert_eq!(projected.success, original.success);
    assert!(matches!(
        projected.diagnostics,
        DiagnosticState::Unavailable {
            reason: DiagnosticUnavailableReason::EncodingBoundOrRefused
        }
    ));
    assert!(
        matches!(original.diagnostics, DiagnosticState::Present { .. }),
        "source complete vectors must not be trimmed or mutated"
    );
    let mut oversized = oversized;
    oversized.push(b'\n');
    assert!(decode_response(&oversized).is_err());
    assert!(decode_failure_core(&oversized).is_err());
}

#[test]
fn default_acl_raw_preimage_is_required_lossless_and_not_a_semantic_acl_verdict() {
    let empty_acl = vec![2, 0, 8, 0, 0, 0, 0, 0];
    let mut allow_rc = vec![2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0, 0, 0, 16, 0];
    allow_rc.extend([1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]);
    let mut digests = std::collections::BTreeSet::new();
    // Some(empty Vec) is a raw-preimage distinction, not an admitted native ACL.
    // Native collection supplies its own existing ACL extent admission.
    for bytes in [None, Some(vec![]), Some(empty_acl), Some(allow_rc)] {
        let (mut request, mut diagnostics) = diagnostic_fixture(1);
        let digest = acl_hash(&bytes);
        assert!(digests.insert(digest.clone()));
        request.expected_default_acl_sha256 = digest.clone();
        if let DiagnosticState::Present { before, after } = &mut diagnostics {
            for source in [before, after] {
                source.default_acl_bytes = bytes.clone();
                source.default_acl_sha256 = digest.clone();
            }
        }
        diagnostics.validate_correspondence(&request).unwrap();
        let original = failed(diagnostics);
        let encoded = encode_response(&original).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded, original);
        if let DiagnosticState::Present { before, after } = decoded.diagnostics {
            assert_eq!(before.default_acl_bytes, bytes);
            assert_eq!(after.default_acl_bytes, bytes);
        }
        for altered in [
            serde_json::json!("not-an-array"),
            serde_json::json!([256]),
            serde_json::json!([1, 2, 3]),
        ] {
            let mut wire = serde_json::to_value(&original).unwrap();
            wire["diagnostics"]["before"]["default_acl_bytes"] = altered;
            let bytes = frame(wire);
            assert!(decode_response(&bytes).is_err());
            assert_eq!(decode_failure_core(&bytes).unwrap().raw_error, 5);
        }
        let mut missing = serde_json::to_value(&original).unwrap();
        missing["diagnostics"]["before"]
            .as_object_mut()
            .unwrap()
            .remove("default_acl_bytes");
        let bytes = frame(missing);
        assert!(decode_response(&bytes).is_err());
        assert_eq!(decode_failure_core(&bytes).unwrap().raw_error, 5);
    }
    for length in [64 * 1024, 64 * 1024 + 1] {
        let (_, mut diagnostics) = diagnostic_fixture(1);
        if let DiagnosticState::Present { before, after } = &mut diagnostics {
            for source in [before, after] {
                source.default_acl_bytes = Some(vec![0; length]);
                source.default_acl_sha256 = acl_hash(&source.default_acl_bytes);
            }
        }
        let encoded = encode_response(&failed(diagnostics)).unwrap();
        assert!(encoded.len() <= FRAME_BOUND);
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded.raw_error, Some(5));
        assert!(matches!(
            decoded.diagnostics,
            DiagnosticState::Unavailable {
                reason: DiagnosticUnavailableReason::EncodingBoundOrRefused
            }
        ));
    }
}
