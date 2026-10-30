#[path = "private/fixture_namespace_security_evidence.rs"]
mod evidence;
#[path = "private/fixture_namespace_primary_protocol.rs"]
mod protocol;
use evidence::*;
use protocol::*;
use sha2::{Digest, Sha256};

fn request() -> Request {
    let user = "S-1-5-21-1-2-3-1001".to_owned();
    Request {
        revision: REVISION,
        nonce: "a".repeat(32),
        cell: Cell::Private,
        alias: "owned-alias".into(),
        boundary: "owned-boundary".into(),
        event: "self".into(),
        user_sid: user.clone(),
        deadline_qpc: u64::MAX,
        qpc_frequency: 10_000_000,
        expected_default_acl_sha256: acl_digest(&None),
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
fn response() -> Response {
    Response {
        revision: REVISION,
        nonce: request().nonce,
        phase: Phase::Event,
        success: false,
        raw_error: Some(5),
        event_handle: None,
        modify_denied: None,
        diagnostics: DiagnosticState::NotApplicable,
        native_open: None,
    }
}

fn acl_digest(bytes: &Option<Vec<u8>>) -> String {
    Sha256::digest(serde_json::to_vec(bytes).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn authz_calculation_never_substitutes_for_the_actual_open() {
    assert_ne!(
        encode_probe_ack(&request().nonce).unwrap(),
        encode_ack(&request().nonce).unwrap()
    );
    for (correlated, api, error, granted, expected) in [
        (true, true, 0, 0x0010_0000, "supplied-data-allow"),
        (true, true, 5, 0, "supplied-data-denial"),
        (true, false, 0, 0, "api-failure"),
        (false, true, 0, 0x0010_0000, "uncorrelated"),
        (true, true, 0, 0, "inconsistent"),
        (true, true, 5, 0x0010_0000, "inconsistent"),
    ] {
        assert_eq!(
            AuthzObservation::conclusion(correlated, api, error, granted),
            expected
        );
        let snapshot = Snapshot::new(vec![1, 0, 4, 128], 4).unwrap();
        let record = AuthzObservation::Evaluated {
            engine: "AuthzAccessCheck",
            scope: "controller-descriptor-and-token-derived-context",
            diagnostic_only: true,
            acceptance_authority: false,
            sampling: "sequential-non-atomic",
            descriptor_sha256: snapshot.sha256().into(),
            desired_access: 0x0010_0000,
            source_token_id: 7,
            source_modified_id: 9,
            context_matches: correlated,
            user_matches: correlated,
            groups_match: correlated,
            restricted_match: correlated,
            privileges_match: correlated,
            source_unchanged: correlated,
            api_success: api,
            native_error: (!api).then_some(5),
            reply_error: api.then_some(error),
            granted: api.then_some(granted),
            conclusion: expected,
        };
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(value["acceptance_authority"], false);
        assert_eq!(value["api_success"], api);
        assert_eq!(
            value["reply_error"].as_u64(),
            api.then_some(u64::from(error))
        );
        assert_eq!(value["conclusion"], expected);
    }
    for stage in [
        "descriptor",
        "source-token",
        "context-identities",
        "access-check",
    ] {
        let record = AuthzObservation::unavailable(stage, &std::io::Error::from_raw_os_error(5));
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(value["state"], "unavailable");
        assert_eq!(value["stage"], stage);
        assert_eq!(value["raw_error"], 5);
        assert!(value.get("conclusion").is_none());
        assert!(serde_json::to_vec(&value).unwrap().len() < RECORD_BOUND);
    }
}

#[test]
fn post_failure_readback_distinguishes_same_bytes_changes_and_unavailability_without_authority() {
    let request = request();
    let response = response();
    let name: Vec<u16> = "owned-alias\\self".encode_utf16().collect();
    let parent = Err(memcordon_windows_launch_core::ObservationUnavailable::NotRequested);
    let acl = None;
    let label = LabelObservation::Unavailable(LabelUnavailable::Native {
        stage: LabelStage::Size,
        raw_error: Some(5),
    });
    let original = Snapshot::new(vec![1, 0, 4, 128], 4).unwrap();
    for (post_failure, present, equal) in [
        (
            ReadbackObservation::Present(Snapshot::new(vec![1, 0, 4, 128], 4).unwrap()),
            true,
            Some(true),
        ),
        (
            ReadbackObservation::Present(Snapshot::new(vec![1, 0, 0, 128], 4).unwrap()),
            true,
            Some(false),
        ),
        (
            ReadbackObservation::Unavailable {
                raw_error: Some(5),
                deadline: false,
            },
            false,
            None,
        ),
        (
            ReadbackObservation::Unavailable {
                raw_error: None,
                deadline: true,
            },
            false,
            None,
        ),
    ] {
        let association = Association {
            request: &request,
            response: &response,
            original_name: &name,
            controller_handle: 7,
            child_pid: 9,
            child_birth: 11,
            parent_prelaunch_token: &parent,
            parent_default_acl_bytes: &acl,
            label: &label,
            post_failure: &post_failure,
        };
        let value = failure(&association, &original).unwrap();
        assert_eq!(value["post_failure_security_readback_observed"], present);
        assert_eq!(
            value["post_failure_security_readback"]["bytes_equal_prelaunch"].as_bool(),
            equal
        );
        assert_eq!(
            value["post_failure_security_readback"]["hash_equal_prelaunch"].as_bool(),
            equal
        );
        assert_eq!(value["original_response"]["raw_error"], 5);
        assert_eq!(value["acceptance_authority"], false);
        assert_eq!(value["cross_process_event_identity_observed"], false);
        assert_eq!(value["cleanup_observed"], false);
        assert!(serde_json::to_vec_pretty(&value).unwrap().len() <= RECORD_BOUND);
    }
}

#[test]
fn retained_native_bytes_are_lossless_and_explicitly_prelaunch_not_completed_proof() {
    let request = decode_request(&encode_request(&request()).unwrap()).unwrap();
    let response = decode_response(&encode_response(&response()).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_ack(&request.nonce).unwrap()).unwrap()
            ["nonce"],
        request.nonce
    );
    let name: Vec<u16> = "owned-alias\\self".encode_utf16().collect();
    let parent = Err(memcordon_windows_launch_core::ObservationUnavailable::NotRequested);
    let acl = None;
    let label = LabelObservation::Unavailable(LabelUnavailable::Native {
        stage: LabelStage::Size,
        raw_error: Some(5),
    });
    assert_eq!(
        decode_failure_core(&encode_response(&response).unwrap())
            .unwrap()
            .raw_error,
        5
    );
    let association = Association {
        request: &request,
        response: &response,
        original_name: &name,
        controller_handle: u64::MAX,
        child_pid: u32::MAX,
        child_birth: u64::MAX,
        parent_prelaunch_token: &parent,
        parent_default_acl_bytes: &acl,
        label: &label,
        post_failure: &ReadbackObservation::NotRequested,
    };
    for bytes in [
        vec![
            1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 44, 0, 0, 0,
        ],
        (0..=u8::MAX).cycle().take(NATIVE_BOUND).collect(),
    ] {
        let snapshot = Snapshot::new(bytes.clone(), u32::try_from(bytes.len()).unwrap()).unwrap();
        assert_eq!(snapshot.bytes(), bytes);
        assert_eq!(snapshot.native_length() as usize, bytes.len());
        let value = failure(&association, &snapshot).unwrap();
        let encoded = serde_json::to_vec(&value).unwrap();
        assert!(encoded.len() <= RECORD_BOUND);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
            value
        );
        assert_eq!(value["security_snapshot"]["native_length"], bytes.len());
        let chunks = value["security_snapshot"]["native_bytes_hex_chunks"]
            .as_array()
            .unwrap();
        assert_eq!(
            value["security_snapshot"]["chunk_hex_chars"],
            CHUNK_HEX_CHARS
        );
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.as_str().unwrap().len() <= CHUNK_HEX_CHARS)
        );
        let combined = chunks
            .iter()
            .map(|chunk| chunk.as_str().unwrap())
            .collect::<String>();
        let actual = combined
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(actual, bytes);
        let hash = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(value["security_snapshot"]["sha256"], hash);
        assert_eq!(value["security_snapshot"]["phase"], "prelaunch");
        assert_eq!(value["security_snapshot"]["security_information"], 7);
        for field in [
            "acceptance_authority",
            "post_failure_security_readback_observed",
            "cross_process_event_identity_observed",
            "cleanup_observed",
        ] {
            assert_eq!(value[field], false);
        }
        assert_eq!(value["original_response"]["raw_error"], 5);
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        assert!(pretty.len() <= RECORD_BOUND);
        assert!(
            pretty
                .split(|byte| *byte == b'\n')
                .all(|line| line.len() < 8 * 1024)
        );
    }
    assert!(Snapshot::new(vec![], 0).is_err());
    assert!(Snapshot::new(vec![1], 2).is_err());
    assert!(
        Snapshot::new(
            vec![0; NATIVE_BOUND + 1],
            u32::try_from(NATIVE_BOUND + 1).unwrap()
        )
        .is_err()
    );
}

#[test]
fn projection_refuses_cross_association_and_never_relabels_success_as_failure() {
    let mut request = request();
    let mut response = response();
    let mut name: Vec<u16> = "owned-alias\\self".encode_utf16().collect();
    let snapshot = Snapshot::new(vec![1], 1).unwrap();
    let parent = Err(memcordon_windows_launch_core::ObservationUnavailable::NotRequested);
    let acl = None;
    let label = LabelObservation::Unavailable(LabelUnavailable::Native {
        stage: LabelStage::Size,
        raw_error: Some(5),
    });
    let project = |request: &Request, response: &Response, name: &[u16], handle, pid, birth| {
        failure(
            &Association {
                request,
                response,
                original_name: name,
                controller_handle: handle,
                child_pid: pid,
                child_birth: birth,
                parent_prelaunch_token: &parent,
                parent_default_acl_bytes: &acl,
                label: &label,
                post_failure: &ReadbackObservation::NotRequested,
            },
            &snapshot,
        )
    };
    assert!(project(&request, &response, &name, 1, 1, 1).is_ok());
    for (handle, pid, birth) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert!(project(&request, &response, &name, handle, pid, birth).is_err());
    }
    response.nonce = "b".repeat(32);
    assert!(project(&request, &response, &name, 1, 1, 1).is_err());
    response.nonce = request.nonce.clone();
    response.success = true;
    response.raw_error = None;
    assert!(project(&request, &response, &name, 1, 1, 1).is_err());
    response.success = false;
    response.raw_error = Some(5);
    name.push(0);
    assert!(project(&request, &response, &name, 1, 1, 1).is_err());
    name.pop();
    request.cell = Cell::Local;
    assert!(project(&request, &response, &name, 1, 1, 1).is_err());
    name = "Local\\self".encode_utf16().collect();
    assert!(project(&request, &response, &name, 1, 1, 1).is_ok());
    request.alias = "unbound/alias".into();
    assert!(project(&request, &response, &name, 1, 1, 1).is_err());
}

#[test]
fn label_bytes_are_separate_from_info7_and_optional_bounds_never_replace_native_failure() {
    let mut request = request();
    let response = response();
    let name: Vec<u16> = "owned-alias\\self".encode_utf16().collect();
    let parent = Err(memcordon_windows_launch_core::ObservationUnavailable::NotRequested);
    let mut acl = None;
    let small = Snapshot::new(vec![1, 0, 4, 128], 4).unwrap();
    // These are lossless data projections, never a native ACL/label parser.
    let raw_label = vec![1, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let label = LabelObservation::Present(
        Snapshot::label(raw_label.clone(), raw_label.len() as u32).unwrap(),
    );
    let project = |request: &Request,
                   acl: &Option<Vec<u8>>,
                   label: &LabelObservation,
                   snapshot: &Snapshot| {
        failure(
            &Association {
                request,
                response: &response,
                original_name: &name,
                controller_handle: 7,
                child_pid: 9,
                child_birth: 11,
                parent_prelaunch_token: &parent,
                parent_default_acl_bytes: acl,
                label,
                post_failure: &ReadbackObservation::NotRequested,
            },
            snapshot,
        )
        .unwrap()
    };
    let value = project(&request, &acl, &label, &small);
    assert_eq!(value["security_snapshot"]["security_information"], 7);
    assert_eq!(
        value["label_snapshot"]["snapshot"]["security_information"],
        16
    );
    assert_eq!(
        value["label_snapshot"]["snapshot"]["native_length"],
        raw_label.len()
    );
    assert_eq!(
        value["label_snapshot"]["snapshot"]["sha256"],
        Sha256::digest(&raw_label)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let unavailable = LabelObservation::Unavailable(LabelUnavailable::Native {
        stage: LabelStage::Size,
        raw_error: Some(5),
    });
    let denied = project(&request, &acl, &unavailable, &small);
    assert_eq!(denied["label_snapshot"]["state"], "unavailable");
    assert_eq!(denied["label_snapshot"]["reason"]["raw_error"], 5);
    assert_eq!(denied["original_response"]["raw_error"], 5);
    for stage in [
        LabelStage::BeforeSize,
        LabelStage::Size,
        LabelStage::SizeBound,
        LabelStage::BeforeRead,
        LabelStage::Read,
        LabelStage::Extent,
        LabelStage::AfterRead,
        LabelStage::Projection,
    ] {
        for reason in [
            LabelUnavailable::Deadline { stage },
            LabelUnavailable::Native {
                stage,
                raw_error: Some(5),
            },
            LabelUnavailable::Bound { stage },
        ] {
            let unavailable = LabelObservation::Unavailable(reason);
            let value = project(&request, &acl, &unavailable, &small);
            assert_eq!(value["label_snapshot"]["state"], "unavailable");
            assert!(value["label_snapshot"].get("snapshot").is_none());
            assert_eq!(value["label_snapshot"]["requested_information"], 16);
            assert_eq!(value["original_response"]["raw_error"], 5);
        }
    }
    let maximum = Snapshot::new(vec![0x5a; NATIVE_BOUND], NATIVE_BOUND as u32).unwrap();
    let large_label = LabelObservation::Present(
        Snapshot::label(vec![0xa5; NATIVE_BOUND], NATIVE_BOUND as u32).unwrap(),
    );
    let combined = project(&request, &acl, &large_label, &maximum);
    assert_eq!(
        combined["label_snapshot"]["reason"],
        "combined-record-bound"
    );
    assert_eq!(combined["security_snapshot"]["native_length"], NATIVE_BOUND);
    assert_eq!(combined["original_response"]["raw_error"], 5);
    assert!(serde_json::to_vec_pretty(&combined).unwrap().len() <= RECORD_BOUND);
    acl = Some(vec![0; NATIVE_BOUND]);
    request.expected_default_acl_sha256 = acl_digest(&acl);
    let default_bound = project(&request, &acl, &unavailable, &maximum);
    assert_eq!(
        default_bound["parent_prelaunch_token"]["state"],
        "unavailable"
    );
    assert_eq!(
        default_bound["parent_prelaunch_token"]["reason"],
        "combined-record-bound"
    );
    assert_eq!(default_bound["label_snapshot"]["reason"]["raw_error"], 5);
    assert_eq!(default_bound["original_response"]["raw_error"], 5);
    assert!(serde_json::to_vec_pretty(&default_bound).unwrap().len() <= RECORD_BOUND);
    let wrong = LabelObservation::Present(
        Snapshot::new(raw_label.clone(), raw_label.len() as u32).unwrap(),
    );
    assert!(
        failure(
            &Association {
                request: &request,
                response: &response,
                original_name: &name,
                controller_handle: 7,
                child_pid: 9,
                child_birth: 11,
                parent_prelaunch_token: &parent,
                parent_default_acl_bytes: &acl,
                label: &wrong,
                post_failure: &ReadbackObservation::NotRequested,
            },
            &small
        )
        .is_err()
    );
}
