#![cfg(feature = "test-support")]

#[path = "../src/sealed/windows_client_input_observation.rs"]
mod observation;

use memcordon_core::{
    PublicProviderBindingV1, WindowsProcessIdentityV1, WindowsWorkloadAcceptedV1,
};
use observation::*;
use sha2::{Digest, Sha256};

fn record() -> Record {
    Record::new(
        serde_json::from_value::<PublicProviderBindingV1>(serde_json::json!({
            "generation":"provider", "source_commit":"ab".repeat(20),
            "runtime_manifest_sha256":"cd".repeat(32)
        }))
        .unwrap(),
    )
}

fn sample(token_type: u32, level: Option<u32>) -> Sample {
    Sample::Observed {
        process: WindowsProcessIdentityV1 {
            process_id: 4,
            creation_time_100ns: 5,
        },
        thread_id: 6,
        started_tick_ms: 7,
        finished_tick_ms: 8,
        token: Token::Observed {
            facts: Box::new(TokenFacts {
                source: Source::ThreadToken,
                token_id: 10,
                modified_id: 11,
                authentication_id: 12,
                token_type,
                impersonation_level: level,
                statistics_group_count: 3,
                statistics_privilege_count: 0,
                privileges: summarize(&[]).unwrap(),
            }),
        },
    }
}

#[test]
fn privilege_hashes_match_authenticated_token_encoding_and_keep_attributes() {
    let tuples = [
        PrivilegeTuple {
            high: 1,
            low: 4,
            attributes: 0x80000003,
        },
        PrivilegeTuple {
            high: -1,
            low: 8,
            attributes: 0,
        },
        PrivilegeTuple {
            high: 0,
            low: 2,
            attributes: 2,
        },
    ];
    let summary = summarize(&tuples).unwrap();
    // Fixed canonical bytes independently spell out signed-high sorting and LE framing.
    let mut bytes = Vec::new();
    for tuple in [tuples[1], tuples[2], tuples[0]] {
        bytes.extend_from_slice(&12_u32.to_le_bytes());
        bytes.extend_from_slice(&tuple.high.to_le_bytes());
        bytes.extend_from_slice(&tuple.low.to_le_bytes());
        bytes.extend_from_slice(&tuple.attributes.to_le_bytes());
    }
    assert_eq!(summary.all_sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
    assert_eq!(
        summary.enabled_sha256,
        <[u8; 32]>::from(Sha256::digest(&bytes[16..]))
    );
    #[cfg(windows)]
    {
        use memcordon_windows_launch_core::{PrivilegeAttributesV1, privilege_attributes_digest};
        let canonical: Vec<_> = tuples
            .iter()
            .map(|value| PrivilegeAttributesV1 {
                luid_high: value.high,
                luid_low: value.low,
                attributes: value.attributes,
            })
            .collect();
        assert_eq!(
            summary
                .all_sha256
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            privilege_attributes_digest(&canonical).unwrap()
        );
    }
    assert_eq!((summary.total_count, summary.enabled_count), (3, 2));
    let mut reversed = tuples;
    reversed.reverse();
    assert_eq!(summary, summarize(&reversed).unwrap());
    let mut changed = tuples;
    changed[0].attributes = 2;
    assert_ne!(
        summary.enabled_sha256,
        summarize(&changed).unwrap().enabled_sha256
    );
    assert_eq!(
        summarize(&[tuples[0]; MAX_PRIVILEGES + 1]),
        Err(Stage::CountBound)
    );
    assert_eq!(
        summarize(&[]).unwrap().all_sha256,
        <[u8; 32]>::from(Sha256::digest([]))
    );
}

#[test]
fn fallback_and_native_type_level_labels_are_explicit() {
    assert!(permits_process_fallback(Some(1008)));
    for error in [None, Some(0), Some(5), Some(1347)] {
        assert!(!permits_process_fallback(error));
    }
    for (kind, level, valid) in [
        (1, None, true),
        (1, Some(0), false),
        (2, Some(0), true),
        (2, Some(3), true),
        (2, None, false),
        (2, Some(4), false),
    ] {
        let mut value = record();
        value.before_launch_frame_call = sample(kind, level);
        assert_eq!(value.validate().is_ok(), valid);
    }
    let mut value = record();
    value.before_launch_frame_call = Sample::Unavailable {
        stage: Stage::ThreadTokenOpen,
        native_win32_error: None,
    };
    value.after_launch_frame_call = Sample::Unavailable {
        stage: Stage::ThreadTokenOpen,
        native_win32_error: Some(0),
    };
    let json = serde_json::to_value(&value).unwrap();
    assert!(json["before_launch_frame_call"]["native_win32_error"].is_null());
    assert_eq!(json["after_launch_frame_call"]["native_win32_error"], 0);
    value.encode().unwrap();
}

#[test]
fn fixed_samples_bind_only_to_the_exact_accepted_receipt() {
    let mut value = record();
    assert_eq!(value.binding, Binding::RequestMissing);
    value.encode().unwrap();
    value.request = Some(Request {
        nonce: "original".into(),
        request_sha256: "ef".repeat(32),
    });
    value.binding = Binding::AcceptedMissing;
    value.before_launch_frame_call = sample(1, None);
    value.after_launch_frame_call = sample(2, Some(2));
    value.connection = Some(Connection {
        attempt_ordinal: 2,
        desired_access: 3,
        share_mode: 0,
        creation_disposition: 3,
        flags_and_attributes: 0x80,
        before_create_file: sample(1, None),
    });
    value.encode().unwrap();
    value.accepted = Some(WindowsWorkloadAcceptedV1 {
        format: "memcordon.windows-workload-accepted".into(),
        revision: 1,
        provider: value.expected_provider.clone(),
        frontend: WindowsProcessIdentityV1 {
            process_id: 4,
            creation_time_100ns: 5,
        },
        attempt_id: "aa".repeat(32),
        nonce: "original".into(),
        request_sha256: "ef".repeat(32),
        setup_deadline_millis: 10,
    });
    value.binding = Binding::AcceptedReceipt;
    assert!(value.validate().is_err());
    value.frame_result = FrameResult::ReturnedOk;
    let bytes = value.encode().unwrap();
    assert!(bytes.len() <= MAX_BYTES);
    let json = String::from_utf8(bytes).unwrap();
    for private in ["environment", "raw_sid", "handle", "program", "luid_high"] {
        assert!(!json.contains(private));
    }
    let mut wrong = value.clone();
    wrong
        .accepted
        .as_mut()
        .unwrap()
        .frontend
        .creation_time_100ns += 1;
    assert!(wrong.validate().is_err());
    let mut wrong = value.clone();
    wrong.accepted.as_mut().unwrap().nonce.push('x');
    assert!(wrong.validate().is_err());
    let mut wrong = value.clone();
    wrong.connection.as_mut().unwrap().attempt_ordinal = 101;
    assert!(wrong.validate().is_err());
    let mut wrong = value.clone();
    wrong.request.as_mut().unwrap().nonce = "x".repeat(129);
    assert!(wrong.encode().is_err());
    let mut wrong = value.clone();
    wrong.request.as_mut().unwrap().request_sha256 = "x".repeat(64);
    assert!(wrong.encode().is_err());
    let mut wire = serde_json::to_value(value).unwrap();
    wire["retry_samples"] = serde_json::json!([]);
    assert!(serde_json::from_value::<Record>(wire).is_err());
}

#[test]
fn post_query_cannot_replace_the_original_io_error_or_success_value() {
    let original = Box::new(std::io::Error::from_raw_os_error(233));
    let pointer = std::ptr::from_ref(original.as_ref());
    let returned: Result<(), _> = after_io(Err(original), |result| {
        assert_eq!(result, FrameResult::ReturnedError);
        let _unavailable = Sample::Unavailable {
            stage: Stage::PrivilegesQuery,
            native_win32_error: Some(5),
        };
    });
    let error = returned.unwrap_err();
    assert_eq!(std::ptr::from_ref(error.as_ref()), pointer);
    assert_eq!(error.raw_os_error(), Some(233));
    let success: Result<_, ()> =
        after_io(Ok(17), |result| assert_eq!(result, FrameResult::ReturnedOk));
    assert_eq!(success, Ok(17));
}
