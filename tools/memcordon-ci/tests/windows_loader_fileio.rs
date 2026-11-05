use memcordon_ci::windows_loader_fileio::{decode_output, listener_windows};
use memcordon_platform::windows_fileio_record::{Binding, ConsumerSpec, Counters, Observation};
use serde_json::json;

fn spec() -> ConsumerSpec {
    ConsumerSpec {
        version: 1,
        session_name: "Memcordon-FileIo-test".into(),
        session_guid: [3; 16],
        pid: 42,
        birth: 99,
        binding: Binding {
            descriptor_sha256: [7; 32],
            challenge_sha256: [8; 32],
            cutoff_qpc: 1000,
            frequency: 10,
        },
    }
}
fn output(spec: &ConsumerSpec) -> Vec<u8> {
    let ready = json!({"format":"memcordon.fileio-consumer-ready","version":1,"ready":true,"error":null,"spec":spec});
    let observation = Observation {
        version: 2,
        spec: spec.clone(),
        rows: vec![],
        counters: Counters::default(),
        decode: Default::default(),
        process_trace_status: 0,
        close_trace_status: 0,
        consumer_completed: true,
        cutoff_reached: false,
    };
    let mut bytes = serde_json::to_vec(&ready).unwrap();
    bytes.push(b'\n');
    bytes.extend(serde_json::to_vec(&observation).unwrap());
    bytes.push(b'\n');
    bytes
}
#[test]
fn readiness_and_final_data_require_the_same_original_session_and_finite_frames() {
    let expected = spec();
    assert_eq!(
        decode_output(&output(&expected), &expected).unwrap().spec,
        expected
    );
    let mut foreign = expected.clone();
    foreign.session_guid[0] ^= 1;
    assert!(decode_output(&output(&foreign), &expected).is_err());
    let mut frames = output(&expected);
    frames.extend_from_slice(b"{}");
    assert!(decode_output(&frames, &expected).is_err());
    assert!(decode_output(&vec![b'x'; 8193], &expected).is_err());
    let mut lines = output(&expected)
        .split(|byte| *byte == b'\n')
        .map(|line| line.to_vec())
        .collect::<Vec<_>>();
    let mut malformed: serde_json::Value = serde_json::from_slice(&lines[1]).unwrap();
    malformed["version"] = json!(9);
    lines[1] = serde_json::to_vec(&malformed).unwrap();
    assert!(decode_output(&lines.join(&b'\n'), &expected).is_err());
}
fn packet(spec: &ConsumerSpec) -> serde_json::Value {
    let window = json!({"namespace":"loader_owner","operation":"LdrLoadDll","clock_domain":"original-QPC","thread_id":12,"invalid_window":false,"observation_incomplete":false,
        "dependency_sequence":1,"loader_dependency_sequence":2,"parent_listener_sequence":3,"started_qpc":100,"finished_qpc":200});
    json!({"format":"memcordon.original-rust-listener-trace","revision":1,"original_binding":{"pid":spec.pid,"creation_time_100ns":spec.birth,"descriptor_sha256":spec.binding.descriptor_sha256,"challenge_sha256":spec.binding.challenge_sha256,"cutoff_qpc":spec.binding.cutoff_qpc,"qpc_frequency":spec.binding.frequency},
        "trace":{"packet_version":4,"invalid_packet":false,"frequency":spec.binding.frequency,"cutoff_qpc":spec.binding.cutoff_qpc,"original_thread":12,"loader_owner":{"version":2,"invalid_scope":false,"first_failure_window":window,"windows":[window]}}})
}
#[test]
fn original_loader_windows_cannot_be_replaced_by_global_listener_time_or_foreign_binding() {
    let expected = spec();
    let original = packet(&expected);
    let encode = |value: &serde_json::Value| serde_json::to_vec(value).unwrap();
    let (thread, windows) = listener_windows(&encode(&original), &expected).unwrap();
    assert_eq!(thread, 12);
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].started_qpc, 100);
    for field in [
        "pid",
        "creation_time_100ns",
        "descriptor_sha256",
        "challenge_sha256",
        "cutoff_qpc",
        "qpc_frequency",
    ] {
        let mut bad = original.clone();
        bad["original_binding"][field] = json!(0);
        assert!(
            listener_windows(&encode(&bad), &expected).is_err(),
            "{field}"
        );
    }
    let mut historical = original.clone();
    historical["trace"]["packet_version"] = json!(3);
    assert!(listener_windows(&encode(&historical), &expected).is_err());
    for (field, replacement) in [
        ("invalid_window", json!(true)),
        ("thread_id", json!(13)),
        ("finished_qpc", json!(1001)),
        ("clock_domain", json!("wall-clock")),
    ] {
        let mut bad = original.clone();
        bad["trace"]["loader_owner"]["first_failure_window"] = serde_json::Value::Null;
        bad["trace"]["loader_owner"]["windows"][0][field] = replacement;
        assert!(
            listener_windows(&encode(&bad), &expected)
                .unwrap()
                .1
                .is_empty(),
            "{field}"
        );
    }
}
