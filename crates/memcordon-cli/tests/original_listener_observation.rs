#[path = "../src/bin/consumer_readiness_windows/original_listener_observation.rs"]
mod observation;
use observation::*;

// Codec fixtures are deliberately wire data, not original-invocation witnesses.
fn fixture() -> (Observation, Expected) {
    let expected = Expected {
        pid: 10,
        birth: 20,
        descriptor_sha256: [1; 32],
        challenge_sha256: [2; 32],
        token_sha256: [3; 32],
        cutoff_qpc: 100,
        frequency: 1000,
    };
    let value = Observation {
        format: FORMAT.into(),
        revision: REVISION,
        operation: Operation::TcpListenerBind,
        domain: ErrorDomain::RustIoRawOsErrorOnWindows,
        raw_os_error: 10106,
        binding: Binding {
            pid: expected.pid,
            birth: expected.birth,
            descriptor_sha256: expected.descriptor_sha256,
            challenge_sha256: expected.challenge_sha256,
            token_sha256: expected.token_sha256,
            thread: 7,
            started_qpc: 10,
            finished_qpc: 20,
            cutoff_qpc: expected.cutoff_qpc,
            frequency: expected.frequency,
        },
        ipv4: [127, 0, 0, 1],
        port: 0,
    };
    (value, expected)
}

#[test]
fn exact_original_context_and_raw_application_result_round_trip_without_native_census() {
    let (mut value, expected) = fixture();
    assert_eq!(LEAF, "original-listener-observation.json");
    for raw in [0, -1, 5, 10106] {
        value.raw_os_error = raw;
        let bytes = encode(&value).unwrap();
        assert!(bytes.len() < MAX_BYTES);
        assert_eq!(decode(&bytes, &expected).unwrap(), value);
        let wire = String::from_utf8(bytes).unwrap();
        assert!(!wire.contains("calls") && !wire.contains("native_boundary"));
    }
}

#[test]
fn mismatched_original_identity_request_token_and_clock_never_decode() {
    let (value, expected) = fixture();
    let mutations: &[fn(&mut Expected)] = &[
        |v| v.pid += 1,
        |v| v.birth += 1,
        |v| v.descriptor_sha256[0] ^= 1,
        |v| v.challenge_sha256[0] ^= 1,
        |v| v.token_sha256[0] ^= 1,
        |v| v.cutoff_qpc += 1,
        |v| v.frequency += 1,
    ];
    let bytes = encode(&value).unwrap();
    for mutate in mutations {
        let mut wrong = expected.clone();
        mutate(&mut wrong);
        assert!(decode(&bytes, &wrong).is_err(), "{wrong:?}");
    }
    for mutate in [
        |v: &mut Observation| v.binding.pid = 0,
        |v: &mut Observation| v.binding.birth = 0,
        |v: &mut Observation| v.binding.thread = 0,
        |v: &mut Observation| v.binding.started_qpc = 0,
        |v: &mut Observation| v.binding.finished_qpc = 9,
        |v: &mut Observation| v.binding.finished_qpc = 100,
        |v: &mut Observation| v.binding.frequency = 0,
        |v: &mut Observation| v.ipv4 = [0, 0, 0, 0],
        |v: &mut Observation| v.port = 1234,
    ] {
        let mut wrong = value.clone();
        mutate(&mut wrong);
        assert!(encode(&wrong).is_err());
        assert!(decode(&serde_json::to_vec(&wrong).unwrap(), &expected).is_err());
    }
}

#[test]
fn closed_codec_rejects_forged_domains_counts_versions_duplicates_and_partial_records() {
    let (value, expected) = fixture();
    for field in [
        "operation",
        "domain",
        "calls",
        "revision",
        "format",
        "binding",
    ] {
        let mut wire = serde_json::to_value(&value).unwrap();
        match field {
            "operation" => wire[field] = "tcp-stream-connect".into(),
            "domain" => wire[field] = "winsock".into(),
            "calls" => wire[field] = 1.into(),
            "revision" => wire[field] = 0.into(),
            "format" => wire[field] = "stderr".into(),
            "binding" => wire[field]["extra"] = true.into(),
            _ => unreachable!(),
        }
        assert!(
            decode(&serde_json::to_vec(&wire).unwrap(), &expected).is_err(),
            "{field}"
        );
    }
    let bytes = encode(&value).unwrap();
    assert!(decode(&bytes[..bytes.len() - 1], &expected).is_err());
    assert!(decode(&[], &expected).is_err());
    assert!(decode(&vec![b' '; MAX_BYTES + 1], &expected).is_err());
    let mut duplicate = String::from_utf8(bytes).unwrap();
    duplicate.insert_str(1, "\"raw_os_error\":5,");
    assert!(decode(duplicate.as_bytes(), &expected).is_err());
}
