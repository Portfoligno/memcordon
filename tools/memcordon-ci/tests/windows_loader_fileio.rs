use memcordon_ci::windows_loader_fileio::{decode_output, listener_windows};
use memcordon_platform::windows_fileio_record::{
    Binding, ConsumerSpec, Counters, Observation, RetentionMode,
};
use serde_json::json;

fn spec() -> ConsumerSpec {
    ConsumerSpec {
        version: 2,
        retention: RetentionMode::Prefix,
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
        version: 4,
        spec: spec.clone(),
        rows: vec![],
        counters: Counters::default(),
        history: Default::default(),
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

fn captured() -> memcordon_ci::windows_loader_fileio::Captured {
    use memcordon_platform::windows_fileio_record::{Collector, Completion, Create, StopRecord};
    let expected = spec();
    let mut collector = Collector::new(expected.clone()).unwrap();
    for index in 0..32 {
        let qpc = 100 + index * 2;
        collector.create(Create {
            irp: index + 1,
            qpc,
            header_pid: expected.pid,
            header_tid: 12,
            ttid: 12,
            file_object: 99,
            create_options: 0,
            file_attributes: 0,
            share_access: 0,
            path_prefix: vec![92, 120],
            path_units: 2,
            path_sha256: Some([7; 32]),
            path_truncated: false,
        });
        collector.completion(Completion {
            irp: index + 1,
            qpc: qpc + 1,
            extra_info: 0,
            ntstatus: 0xc0000022u32 as i32,
        });
    }
    memcordon_ci::windows_loader_fileio::Captured {
        spec: Some(expected),
        ready: true,
        stop: Some(StopRecord {
            attempted: true,
            status: 0,
            stopped: true,
            late: false,
            elapsed_ms: 1,
            events_lost: 0,
            log_buffers_lost: 0,
            realtime_buffers_lost: 0,
            buffers: 1,
            buffer_kib: 64,
        }),
        helper_settled: true,
        error: Some("original session diagnostic".into()),
        observation: Some(collector.finish(0, false)),
    }
}

#[test]
fn missing_invalid_or_incomplete_listener_keeps_bounded_candidates_without_association() {
    use memcordon_ci::windows_loader_fileio::render_record;
    for case in 0..3 {
        let mut state = captured();
        let listener = match case {
            0 => Err(std::io::Error::from_raw_os_error(2)),
            1 => Ok(b"not-json".to_vec()),
            _ => {
                state.stop.as_mut().unwrap().events_lost = 1;
                Ok(serde_json::to_vec(&packet(state.spec.as_ref().unwrap())).unwrap())
            }
        };
        let value = render_record(&state, listener);
        assert_eq!(value["error"], "original session diagnostic");
        assert_eq!(value["spec"]["pid"], state.spec.as_ref().unwrap().pid);
        assert_eq!(value["observation"]["state"], "incomplete-unassociated");
        assert_eq!(value["observation"]["counters"]["seen"], 64);
        assert_eq!(value["observation"]["history"]["decoded_events"], 64);
        assert_eq!(
            value["observation"]["candidate_records"]
                .as_array()
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            value["observation"]["absence_proves_no_file_activity"],
            false
        );
        assert_eq!(value["observation"]["denied_object_proved"], false);
        for row in value["observation"]["candidate_records"]
            .as_array()
            .unwrap()
        {
            assert_eq!(row["temporal_original_call_association"], false);
            assert!(row["window"].is_null());
        }
        if case < 2 {
            assert!(value["observation"]["error"].is_string());
        }
        assert!(
            serde_json::to_vec(&value).unwrap().len()
                <= memcordon_ci::windows_loader_fileio::RECORD_BYTES
        );
    }
    let mut state = captured();
    state.observation = None;
    assert_eq!(
        render_record(&state, Err(std::io::Error::from_raw_os_error(2)))["observation"]["state"],
        "unavailable"
    );
}

#[test]
fn valid_listener_uses_the_original_exact_correlation_path() {
    use memcordon_ci::windows_loader_fileio::render_record;
    let state = captured();
    let spec = state.spec.as_ref().unwrap();
    let bytes = serde_json::to_vec(&packet(spec)).unwrap();
    let (thread, windows) = listener_windows(&bytes, spec).unwrap();
    let expected = memcordon_platform::windows_fileio_record::correlate(
        state.observation.as_ref().unwrap(),
        spec,
        thread,
        &windows,
    );
    let value = render_record(&state, Ok(bytes));
    assert_eq!(value["observation"], expected);
    assert_eq!(
        value["observation"]["rows"][0]["temporal_original_call_association"],
        true
    );
}

#[test]
fn unassociated_envelope_omits_rows_but_keeps_loss_metadata_and_error_limits() {
    use memcordon_ci::windows_loader_fileio::render_record;
    let mut state = captured();
    let observation = state.observation.as_mut().unwrap();
    let base = u64::MAX - 1000;
    observation.spec.pid = u32::MAX;
    observation.spec.birth = u64::MAX;
    observation.spec.binding.cutoff_qpc = u64::MAX;
    observation.spec.binding.frequency = u64::MAX;
    observation.history.maximum_qpc += base;
    for row in &mut observation.rows {
        row.create.irp += base;
        row.create.qpc += base;
        row.create.header_pid = u32::MAX;
        row.create.header_tid = u32::MAX;
        row.create.ttid = u32::MAX;
        row.create.file_object = u64::MAX;
        row.create.create_options = u32::MAX;
        row.create.file_attributes = u32::MAX;
        row.create.share_access = u32::MAX;
        row.create.path_prefix = vec![65535; 128];
        row.create.path_units = 32767;
        row.create.path_truncated = true;
        row.create.path_sha256 = Some([255; 32]);
        let end = row.completion.as_mut().unwrap();
        end.irp = row.create.irp;
        end.qpc += base;
        end.extra_info = u64::MAX;
    }
    assert!(observation.validate().is_ok());
    state.spec = Some(observation.spec.clone());
    state.error = Some("\0".repeat(3000));
    let value = render_record(&state, Err(std::io::Error::other("\0".repeat(3000))));
    assert!(value["observation"]["rows_omitted"].as_u64().unwrap() > 0);
    assert_eq!(value["observation"]["history"]["decoded_events"], 64);
    assert_eq!(value["observation"]["counters"]["seen"], 64);
    assert!(value["observation"]["decode"].is_object());
    assert_eq!(value["error"].as_str().unwrap().chars().count(), 1024);
    assert_eq!(
        value["observation"]["error"]
            .as_str()
            .unwrap()
            .chars()
            .count(),
        1024
    );
    assert!(
        serde_json::to_vec(&value).unwrap().len()
            <= memcordon_ci::windows_loader_fileio::RECORD_BYTES
    );
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
    let mut foreign = expected.clone();
    foreign.retention = RetentionMode::RollingCompleted;
    assert!(decode_output(&output(&foreign), &expected).is_err());
    assert_eq!(
        decode_output(&output(&foreign), &foreign)
            .unwrap()
            .spec
            .retention,
        RetentionMode::RollingCompleted
    );
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
        "trace":{"packet_version":5,"invalid_packet":false,"frequency":spec.binding.frequency,"cutoff_qpc":spec.binding.cutoff_qpc,"original_thread":12,"loader_owner":{"version":2,"invalid_scope":false,"first_failure_window":window,"windows":[window]}}})
}
#[test]
fn original_loader_windows_cannot_be_replaced_by_global_listener_time_or_foreign_binding() {
    let expected = spec();
    let original = packet(&expected);
    assert_eq!(original["trace"]["packet_version"], 5);
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
    for version in [0, 3, 4, 6, u32::MAX] {
        let mut historical = original.clone();
        historical["trace"]["packet_version"] = json!(version);
        assert!(
            listener_windows(&encode(&historical), &expected).is_err(),
            "version {version}"
        );
    }
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

#[test]
fn successful_loader_window_remains_observable_without_a_failure_window() {
    let expected = spec();
    let mut success = packet(&expected);
    success["trace"]["loader_owner"]["first_failure_window"] = serde_json::Value::Null;
    let encode = |value: &serde_json::Value| serde_json::to_vec(value).unwrap();
    let (thread, windows) = listener_windows(&encode(&success), &expected).unwrap();
    assert_eq!(thread, 12);
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].dependency_sequence, 1);
    assert_eq!(windows[0].loader_dependency_sequence, 2);
    assert_eq!(
        (windows[0].started_qpc, windows[0].finished_qpc),
        (100, 200)
    );

    for (field, value) in [
        ("finished_qpc", expected.binding.cutoff_qpc),
        ("finished_qpc", 99),
        ("started_qpc", 0),
    ] {
        let mut invalid = success.clone();
        invalid["trace"]["loader_owner"]["windows"][0][field] = json!(value);
        assert!(
            listener_windows(&encode(&invalid), &expected)
                .unwrap()
                .1
                .is_empty(),
            "{field}={value}"
        );
    }
}
