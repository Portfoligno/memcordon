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
