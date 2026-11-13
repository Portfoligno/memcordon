#[path = "../src/bin/consumer_readiness_windows/matched_control_record.rs"]
pub mod record;
mod descriptor {
    pub use super::record as matched;
}
#[path = "../src/bin/consumer_readiness_windows/matched_control_input_record.rs"]
mod input;
use input::*;

fn value() -> Readback {
    let envelope = memcordon_core::WindowsCallerTokenEnvelopeV1 {
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
        token_type: 1,
        impersonation_level: 0,
    };
    use sha2::{Digest, Sha256};
    let token_sha256 = Sha256::digest(serde_json::to_vec(&envelope).unwrap()).into();
    Readback {
        revision: 1,
        binding: record::Binding {
            pair_sha256: [1; 32],
            lane: record::Lane::Direct,
            scope: record::Scope::Envelope,
            input_sha256: [2; 32],
        },
        descriptor_sha256: [3; 32],
        pid: 4,
        birth: 5,
        token_sha256,
        partial_token_sha256: [6; 32],
        token: TokenDetails {
            envelope,
            token_id: 7,
            expiration: -1,
            group_count: 2,
            privilege_count: 3,
            modified_id: 8,
            default_acl_bytes: 40,
            default_acl_sha256: [9; 32],
        },
        cwd_utf16: "C:\\owned".encode_utf16().collect(),
        cwd_identity: CwdIdentity {
            volume_serial: 10,
            file_index: 11,
            attributes: 0x10,
        },
        environment: vec![memcordon_core::WindowsEnvironmentEntryV1 {
            name: "SystemRoot".encode_utf16().collect(),
            value: "C:\\Windows".encode_utf16().collect(),
        }],
        streams: [(-10i32) as u32, (-11i32) as u32, (-12i32) as u32]
            .into_iter()
            .map(|role| Stream {
                role,
                file_type: 3,
                security: Security {
                    security_information: 23,
                    bytes: 80,
                    sha256: [12; 32],
                },
            })
            .collect(),
        started_qpc: 1,
        finished_qpc: 10,
        qpc_frequency: 1000,
        cutoff_qpc: 100,
    }
}
fn expected(value: &Readback) -> Expected {
    Expected {
        binding: value.binding.clone(),
        descriptor_sha256: value.descriptor_sha256,
        token_sha256: value.token_sha256,
        default_acl_bytes: value.token.default_acl_bytes,
        default_acl_sha256: value.token.default_acl_sha256,
        qpc_frequency: value.qpc_frequency,
        cutoff_qpc: value.cutoff_qpc,
        identity: Some((value.pid, value.birth)),
    }
}

fn scoped_pair(scope: record::Scope) -> (Readback, Readback) {
    let mut direct = value();
    direct.binding.scope = scope;
    let mut installed = direct.clone();
    installed.binding.lane = record::Lane::Installed;
    installed.pid += 1;
    installed.birth += 1;
    installed.descriptor_sha256[0] ^= 1;
    (direct, installed)
}

#[test]
fn owned_file_scope_retains_unequal_physical_security_without_claiming_equal_inputs() {
    for scope in [
        record::Scope::BinaryFiles,
        record::Scope::Envelope,
        record::Scope::JointListenerPrefix,
        record::Scope::ProviderListenerSelection,
    ] {
        let (direct, mut installed) = scoped_pair(scope);
        assert!(
            assess_inputs(scope, &direct, &installed)
                .unwrap()
                .physical_stream_security_equal
        );
        for (index, stream) in installed.streams.iter_mut().enumerate() {
            stream.security.sha256[index] ^= 1;
            stream.security.bytes += 4;
        }
        let original = installed.clone();
        let assessment = assess_inputs(scope, &direct, &installed).unwrap();
        assert_eq!(assessment.scope, scope);
        assert!(!assessment.physical_stream_security_equal);
        assert_eq!(installed, original);
        assert!(compare_inputs(&direct, &installed).is_err());
    }
}

#[test]
fn scoped_assessment_keeps_binding_token_environment_clock_and_complete_shape_gates() {
    let (direct, installed) = scoped_pair(record::Scope::BinaryFiles);
    for field in [
        "scope",
        "pair",
        "input",
        "lane",
        "identity",
        "cwd",
        "cwd_identity",
        "environment",
        "token",
        "expiry",
        "groups",
        "privileges",
        "acl_bytes",
        "acl_hash",
        "frequency",
        "cutoff",
        "late",
        "role",
        "kind",
        "mask",
        "security_missing",
        "security_oversized",
    ] {
        let mut actual = installed.clone();
        actual.streams[0].security.sha256[0] ^= 1;
        match field {
            "scope" => actual.binding.scope = record::Scope::Envelope,
            "pair" => actual.binding.pair_sha256[0] ^= 1,
            "input" => actual.binding.input_sha256[0] ^= 1,
            "lane" => actual.binding.lane = record::Lane::Direct,
            "identity" => {
                actual.pid = direct.pid;
                actual.birth = direct.birth;
            }
            "cwd" => actual.cwd_utf16.push(b'x' as u16),
            "cwd_identity" => actual.cwd_identity.file_index += 1,
            "environment" => actual.environment[0].value.push(b'x' as u16),
            "token" => actual.token.envelope.session_id += 1,
            "expiry" => actual.token.expiration += 1,
            "groups" => actual.token.group_count += 1,
            "privileges" => actual.token.privilege_count += 1,
            "acl_bytes" => actual.token.default_acl_bytes += 1,
            "acl_hash" => actual.token.default_acl_sha256[0] ^= 1,
            "frequency" => actual.qpc_frequency += 1,
            "cutoff" => actual.cutoff_qpc += 1,
            "late" => actual.finished_qpc = actual.cutoff_qpc,
            "role" => actual.streams[1].role = actual.streams[0].role,
            "kind" => actual.streams[0].file_type = 0,
            "mask" => actual.streams[0].security.security_information = 7,
            "security_missing" => actual.streams[0].security.bytes = 0,
            "security_oversized" => actual.streams[0].security.bytes = 8193,
            _ => unreachable!(),
        }
        assert!(
            assess_inputs(record::Scope::BinaryFiles, &direct, &actual).is_err(),
            "{field}"
        );
    }
    assert!(assess_inputs(record::Scope::Envelope, &direct, &installed).is_err());
}
#[test]
fn complete_readbacks_validate_against_independent_caller_and_plan() {
    let source = value();
    let decoded = decode(&serde_json::to_vec(&source).unwrap()).unwrap();
    assert_eq!(decoded, source);
    validate(&decoded, &expected(&source)).unwrap();
    let mut installed = source.clone();
    installed.binding.lane = record::Lane::Installed;
    installed.descriptor_sha256 = [13; 32];
    installed.pid += 1;
    installed.token.token_id += 1;
    installed.token.modified_id += 1;
    compare_inputs(&source, &installed).unwrap();
    installed
        .environment
        .push(memcordon_core::WindowsEnvironmentEntryV1 {
            name: vec![b'A' as u16],
            value: vec![],
        });
    let mut direct = source;
    direct
        .environment
        .insert(0, installed.environment.last().unwrap().clone());
    compare_inputs(&direct, &installed).unwrap();
}
#[test]
fn missing_null_unknown_duplicate_and_oversized_capture_is_rejected() {
    let source = value();
    let wire = serde_json::to_value(&source).unwrap();
    for field in [
        "token",
        "cwd_identity",
        "environment",
        "streams",
        "partial_token_sha256",
    ] {
        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            decode(&serde_json::to_vec(&missing).unwrap()).is_err(),
            "{field}"
        );
        let mut null = wire.clone();
        null[field] = serde_json::Value::Null;
        assert!(
            decode(&serde_json::to_vec(&null).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut extra = wire.clone();
    extra["token"]["extra"] = true.into();
    assert!(decode(&serde_json::to_vec(&extra).unwrap()).is_err());
    let mut duplicate = serde_json::to_string(&source).unwrap();
    duplicate.insert_str(1, "\"revision\":1,");
    assert!(decode(duplicate.as_bytes()).is_err());
    assert!(decode(&vec![b' '; MAX_BYTES + 1]).is_err());
}
#[test]
fn actual_target_acl_token_and_all_expected_bindings_are_checked() {
    let original = value();
    for field in [
        "aclbytes",
        "aclhash",
        "token",
        "pair",
        "lane",
        "scope",
        "input",
        "descriptor",
        "pid",
        "birth",
        "frequency",
        "cutoff",
    ] {
        let mut actual = original.clone();
        match field {
            "aclbytes" => actual.token.default_acl_bytes += 1,
            "aclhash" => actual.token.default_acl_sha256[0] ^= 1,
            "token" => actual.token.envelope.session_id += 1,
            "pair" => actual.binding.pair_sha256[0] ^= 1,
            "lane" => actual.binding.lane = record::Lane::Installed,
            "scope" => actual.binding.scope = record::Scope::BinaryFiles,
            "input" => actual.binding.input_sha256[0] ^= 1,
            "descriptor" => actual.descriptor_sha256[0] ^= 1,
            "pid" => actual.pid += 1,
            "birth" => actual.birth += 1,
            "frequency" => actual.qpc_frequency += 1,
            "cutoff" => actual.cutoff_qpc += 1,
            _ => unreachable!(),
        }
        assert!(validate(&actual, &expected(&original)).is_err(), "{field}");
    }
    let mut actual = original.clone();
    actual.token.envelope.session_id += 1;
    use sha2::{Digest, Sha256};
    actual.token_sha256 =
        Sha256::digest(serde_json::to_vec(&actual.token.envelope).unwrap()).into();
    assert!(validate(&actual, &expected(&original)).is_err());
}
#[test]
fn exactly_three_pipe_streams_with_complete_requested_security_are_required() {
    let original = value();
    for field in ["missing", "duplicate", "kind", "mask", "empty", "oversized"] {
        let mut actual = original.clone();
        match field {
            "missing" => {
                actual.streams.pop();
            }
            "duplicate" => actual.streams[1].role = actual.streams[0].role,
            "kind" => actual.streams[0].file_type = 0,
            "mask" => actual.streams[0].security.security_information = 7,
            "empty" => actual.streams[0].security.bytes = 0,
            "oversized" => actual.streams[0].security.bytes = 8193,
            _ => unreachable!(),
        }
        assert!(validate(&actual, &expected(&original)).is_err(), "{field}");
    }
    let mut other = original.clone();
    other.streams[0].security.sha256[0] ^= 1;
    assert!(compare_inputs(&original, &other).is_err());
}
#[test]
fn environment_directory_and_clock_observations_cannot_be_partial_or_late() {
    let original = value();
    for field in [
        "emptyenv",
        "duplicateenv",
        "casealias",
        "envnul",
        "cwdnul",
        "cwdempty",
        "reparse",
        "device",
        "file",
        "frequency",
        "late",
        "backwards",
    ] {
        let mut actual = original.clone();
        match field {
            "emptyenv" => actual.environment.clear(),
            "duplicateenv" => actual.environment.push(actual.environment[0].clone()),
            "casealias" => {
                let mut alias = actual.environment[0].clone();
                alias.name = "SYSTEMROOT".encode_utf16().collect();
                actual.environment.push(alias)
            }
            "envnul" => actual.environment[0].value.push(0),
            "cwdnul" => actual.cwd_utf16.push(0),
            "cwdempty" => actual.cwd_utf16.clear(),
            "reparse" => actual.cwd_identity.attributes |= 0x400,
            "device" => actual.cwd_identity.attributes |= 0x40,
            "file" => actual.cwd_identity.attributes = 0,
            "frequency" => actual.qpc_frequency = 0,
            "late" => actual.finished_qpc = actual.cutoff_qpc,
            "backwards" => actual.finished_qpc = 0,
            _ => unreachable!(),
        }
        assert!(validate(&actual, &expected(&original)).is_err(), "{field}");
    }
}
#[test]
fn stable_input_differences_remain_differences_despite_equal_process_status() {
    let original = value();
    for field in [
        "cwd",
        "environment",
        "expiration",
        "groups",
        "privileges",
        "acl",
    ] {
        let mut actual = original.clone();
        match field {
            "cwd" => actual.cwd_identity.file_index += 1,
            "environment" => actual.environment[0].value.push(b'X' as u16),
            "expiration" => actual.token.expiration += 1,
            "groups" => actual.token.group_count += 1,
            "privileges" => actual.token.privilege_count += 1,
            "acl" => actual.token.default_acl_sha256[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(compare_inputs(&original, &actual).is_err(), "{field}");
    }
}

#[test]
fn diagnostic_identifies_each_original_expected_predicate_and_lane_without_accepting_it() {
    for lane in [record::Lane::Direct, record::Lane::Installed] {
        let mut actual = value();
        actual.binding.lane = lane;
        for predicate in [
            "binding",
            "descriptor_sha256",
            "selected_token_sha256",
            "default_acl_bytes",
            "default_acl_sha256",
            "qpc_frequency",
            "cutoff_qpc",
            "identity",
        ] {
            let mut held = expected(&actual);
            match predicate {
                "binding" => held.binding.input_sha256[0] ^= 1,
                "descriptor_sha256" => held.descriptor_sha256[0] ^= 1,
                "selected_token_sha256" => held.token_sha256[0] ^= 1,
                "default_acl_bytes" => held.default_acl_bytes += 1,
                "default_acl_sha256" => held.default_acl_sha256[0] ^= 1,
                "qpc_frequency" => held.qpc_frequency += 1,
                "cutoff_qpc" => held.cutoff_qpc += 1,
                "identity" => held.identity.as_mut().unwrap().1 += 1,
                _ => unreachable!(),
            }
            assert_eq!(
                validate(&actual, &held).unwrap_err(),
                "matched input differs from held caller, original identity or declared plan"
            );
            let facts = validation_diagnostic(&actual, &held);
            assert_eq!(facts["stage"], "validate");
            assert_eq!(facts["lane"], serde_json::to_value(lane).unwrap());
            assert_eq!(facts["first_failed_predicate"], predicate);
            assert_eq!(facts["expected"], serde_json::to_value(&held).unwrap());
            let failed: Vec<_> = facts["predicates"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["matches"] == false)
                .collect();
            assert_eq!(failed.len(), 1);
            assert_eq!(failed[0]["predicate"], predicate);
            assert!(facts["shape_error"].is_null());
            assert!(encode_diagnostic(&facts).unwrap().len() <= MAX_BYTES);
        }
    }
}

#[test]
fn diagnostic_preserves_comparison_order_and_never_duplicates_environment_or_security_bytes() {
    let (direct, mut installed) = scoped_pair(record::Scope::Envelope);
    installed.streams[0].security.sha256[0] ^= 1;
    installed.token.privilege_count += 1;
    assert_eq!(
        compare_inputs(&direct, &installed).unwrap_err(),
        "matched actual cwd, environment, streams or stable token inputs differ"
    );
    let facts = comparison_diagnostic(&direct, &installed);
    assert_eq!(facts["stage"], "compare");
    assert_eq!(facts["revision"], 2);
    assert_eq!(
        facts["comparison_scope"],
        "owned-file-operations-and-selected-token"
    );
    assert_eq!(facts["physical_stream_security_equal"], false);
    assert_eq!(facts["first_failed_predicate"], "privilege_count");
    for lane in ["direct", "installed"] {
        let actual = facts[lane].as_object().unwrap();
        assert!(!actual.contains_key("environment"));
        assert!(!actual.contains_key("cwd_utf16"));
        for stream in actual["streams"].as_array().unwrap() {
            let security = stream["security"].as_object().unwrap();
            assert_eq!(security.len(), 3);
            assert!(security.contains_key("security_information"));
            assert!(security.contains_key("bytes"));
            assert!(security.contains_key("sha256"));
        }
    }
    let rows = facts["predicates"].as_array().unwrap();
    assert_eq!(rows.iter().filter(|row| row["matches"] == false).count(), 1);
    assert!(rows.iter().all(|row| row["predicate"] != "streams"));
    assert!(encode_diagnostic(&facts).unwrap().len() <= MAX_BYTES);
    let mut earlier = installed.clone();
    earlier.cwd_identity.file_index += 1;
    assert_eq!(
        comparison_diagnostic(&direct, &earlier)["first_failed_predicate"],
        "cwd_identity"
    );
    assert!(compare_inputs(&direct, &earlier).is_err());
}

#[test]
fn malformed_input_and_oversized_diagnostics_remain_rejected() {
    let mut malformed = value();
    let held = expected(&malformed);
    malformed.streams.clear();
    assert!(validate(&malformed, &held).is_err());
    let facts = validation_diagnostic(&malformed, &held);
    assert!(facts["shape_error"].as_str().is_some());
    assert_eq!(facts["first_failed_predicate"], "shape");
    let valid = value();
    assert_eq!(
        comparison_diagnostic(&malformed, &valid)["first_failed_predicate"],
        "direct_shape"
    );
    assert_eq!(
        comparison_diagnostic(&valid, &malformed)["first_failed_predicate"],
        "installed_shape"
    );
    assert!(encode_diagnostic(&serde_json::json!({"extra":"x".repeat(MAX_BYTES)})).is_err());
}
