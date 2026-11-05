use memcordon_ci::windows_access_failure_probe::{
    FRAME_BYTES, assessment, checked_attempt, consumer_output, finish_consumer, first_frame,
    preserve,
};
use memcordon_platform::windows_access_failure_preparation::{PreparationOperation, Record, State};
use memcordon_platform::windows_access_failure_record::{
    Binding, ConsumerSpec, Observation, Ready, StopRecord,
};
use serde_json::json;

fn spec() -> ConsumerSpec {
    ConsumerSpec {
        version: 1,
        session_name: "Memcordon-AccessFailure-01010101010101010101010101010101".into(),
        session_guid: [1; 16],
        pid: 123,
        birth: 456,
        object_name: "\\Device\\Owned\\calibration.bin".encode_utf16().collect(),
        binding: Binding {
            cutoff_qpc: 10000,
            frequency: 1000,
            attempt_sha256: [2; 32],
        },
    }
}
fn attempt() -> serde_json::Value {
    json!({"pid":123,"thread_id":7,"started_qpc":100,"finished_qpc":200,"frequency":1000,"requested_win32_access":1,"native_open_error":5,"denial_observed":true,"ordinary_rc_profile_verified":true,"thread_token_restored":true,"token_execution":"effective-thread-impersonation","fresh_primary_execution_coverage":false,"dacl_scope":"newly owned calibration file only","host_policy_modified":false})
}

#[test]
fn unsupported_emission_is_not_product_failure_or_coverage_success() {
    let spec = spec();
    let mut observation = Observation::new(spec.clone());
    observation.consumer_completed = true;
    let stop = StopRecord {
        status: 0,
        disable_status: 0,
        stopped: true,
        late: false,
        elapsed_ms: 1,
        events_lost: 0,
        log_buffers_lost: 0,
        realtime_buffers_lost: 0,
    };
    let value = assessment(
        &attempt(),
        true,
        true,
        true,
        Some(&spec),
        Some(&observation),
        Some(&stop),
    );
    assert_eq!(value["probe_execution_verified"], true);
    assert_eq!(value["coverage_validated"], false);
    assert_eq!(value["coverage_state"], "unsupported-or-inconclusive");
    for flag in [
        "acceptance_authority",
        "product_capability",
        "fresh_primary_execution_coverage",
        "installed_original_call_coverage",
        "full_semantic_token_sd_interpretation",
        "access_mask_is_original_syscall_desired_access",
        "raw_sensitive_bytes_exported",
        "absence_proves_access_succeeded",
    ] {
        assert_eq!(value[flag], false);
    }
    let mut failed = attempt();
    failed["thread_token_restored"] = json!(false);
    assert_eq!(
        assessment(
            &failed,
            true,
            true,
            true,
            Some(&spec),
            Some(&observation),
            Some(&stop)
        )["probe_execution_verified"],
        false
    );
    assert_eq!(
        assessment(
            &attempt(),
            false,
            true,
            true,
            Some(&spec),
            Some(&observation),
            Some(&stop)
        )["probe_execution_verified"],
        false
    );
    assert_eq!(
        assessment(
            &attempt(),
            true,
            false,
            true,
            Some(&spec),
            Some(&observation),
            Some(&stop)
        )["probe_execution_verified"],
        false
    );
}

#[test]
fn helper_frames_require_exact_owned_session_and_finite_complete_records() {
    assert!(first_frame(b"{\"partial\":").unwrap().is_none());
    assert!(first_frame(&vec![b'x'; FRAME_BYTES + 1]).is_err());
    assert!(first_frame(b"not-json\n").is_err());
    let spec = spec();
    let ready = Ready {
        spec: spec.clone(),
        open_trace_succeeded: true,
        native_error: None,
    };
    let mut observation = Observation::new(spec.clone());
    observation.consumer_completed = true;
    let mut bytes = serde_json::to_vec(&ready).unwrap();
    bytes.push(b'\n');
    bytes.extend(serde_json::to_vec(&observation).unwrap());
    assert!(consumer_output(&bytes, &spec).is_ok());
    let mut foreign = spec.clone();
    foreign.birth += 1;
    assert!(consumer_output(&bytes, &foreign).is_err());
    observation.version = 2;
    let mut invalid = serde_json::to_vec(&ready).unwrap();
    invalid.push(b'\n');
    invalid.extend(serde_json::to_vec(&observation).unwrap());
    assert!(consumer_output(&invalid, &spec).is_err());
}

#[test]
fn calibration_projection_refuses_unknown_private_fields_and_scope_relabeling() {
    assert!(checked_attempt(&attempt()).is_ok());
    let mut value = attempt();
    value["raw_sid"] = json!("must not be exported");
    assert!(checked_attempt(&value).is_err());
    assert!(
        !serde_json::to_string(&assessment(&value, true, true, false, None, None, None))
            .unwrap()
            .contains("must not be exported")
    );
    let mut value = attempt();
    value["token_execution"] = json!("fresh-primary");
    assert!(checked_attempt(&value).is_err());
    let mut value = attempt();
    value["native_open_error"] = json!("5");
    assert!(checked_attempt(&value).is_err());
}

#[test]
fn complete_assessment_preserves_maximum_sanitized_rows_under_report_cap() {
    use memcordon_platform::windows_access_failure_record::{Row, SanitizedField, SensitiveField};
    let mut expected = spec();
    expected.object_name = vec![0x4e00; 512];
    let mut observation = Observation::new(expected.clone());
    observation.consumer_completed = true;
    for qpc in 150..154 {
        observation
            .record(Row {
                qpc,
                pid: expected.pid,
                tid: 7,
                access_mask: 1,
                object_type: vec![0x4e00; 64],
                object_name: expected.object_name.clone(),
                token_type: 2,
                impersonation_level: 2,
                session_id: u32::MAX,
                security_descriptor_revision: 1,
                security_descriptor_control: u16::MAX,
                sensitive_fields: SensitiveField::ALL
                    .into_iter()
                    .map(|field| SanitizedField {
                        field,
                        in_type: u16::MAX,
                        out_type: u16::MAX,
                        count: 256,
                        bytes: 65536,
                        sha256: [255; 32],
                    })
                    .collect(),
            })
            .unwrap();
    }
    observation.validate().unwrap();
    let value = assessment(
        &attempt(),
        true,
        true,
        true,
        Some(&expected),
        Some(&observation),
        None,
    );
    assert_eq!(value["observation"]["rows"].as_array().unwrap().len(), 4);
    assert!(
        serde_json::to_vec(&value).unwrap().len() + 1
            < memcordon_ci::windows_access_failure_probe::STREAM_BYTES
    );
}

#[test]
fn optional_native_unavailability_is_distinct_from_mandatory_consumer_failures() {
    let expected = spec();
    let unavailable = Ready {
        spec: expected.clone(),
        open_trace_succeeded: false,
        native_error: Some(5),
    };
    let mut bytes = serde_json::to_vec(&unavailable).unwrap();
    bytes.push(b'\n');
    assert!(finish_consumer(&bytes, &expected, false).unwrap().is_none());
    assert!(finish_consumer(&bytes, &expected, true).is_err());
    for code in [None, Some(0)] {
        let unknown = Ready {
            native_error: code,
            ..unavailable.clone()
        };
        let mut invalid = serde_json::to_vec(&unknown).unwrap();
        invalid.push(b'\n');
        assert!(finish_consumer(&invalid, &expected, false).is_err());
    }
    let mut foreign = expected.clone();
    foreign.birth += 1;
    assert!(finish_consumer(&bytes, &foreign, false).is_err());
    let ready = Ready {
        spec: expected.clone(),
        open_trace_succeeded: true,
        native_error: None,
    };
    let mut observation = Observation::new(expected.clone());
    observation.consumer_completed = true;
    observation.matched_events = 1;
    observation.unsupported_events = 1;
    let framed = |value: &Observation| {
        let mut bytes = serde_json::to_vec(&ready).unwrap();
        bytes.push(b'\n');
        bytes.extend(serde_json::to_vec(value).unwrap());
        bytes
    };
    assert!(
        finish_consumer(&framed(&observation), &expected, true)
            .unwrap()
            .is_some()
    );
    assert!(finish_consumer(&framed(&observation), &expected, false).is_err());
    observation.close_trace_status = 6;
    assert!(finish_consumer(&framed(&observation), &expected, true).is_err());
    observation.close_trace_status = 0;
    observation.process_trace_status = 87;
    assert!(finish_consumer(&framed(&observation), &expected, true).is_err());
    observation.process_trace_status = 0;
    observation.matched_events = 2;
    assert!(finish_consumer(&framed(&observation), &expected, true).is_err());
}

#[test]
fn required_native_failure_survives_report_publication_failure() {
    let error = preserve(
        Err(std::io::Error::from_raw_os_error(5)),
        Err(std::io::Error::other("bounded report write failure")),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::Error::from_raw_os_error(5).kind());
    let secondary = error.get_ref().unwrap();
    let primary = std::error::Error::source(secondary)
        .unwrap()
        .downcast_ref::<std::io::Error>()
        .unwrap();
    assert_eq!(primary.raw_os_error(), Some(5));
    assert!(error.to_string().contains("bounded report write failure"));
    assert!(preserve(Ok(()), Err(std::io::Error::other("required report absent"))).is_err());
}

fn failed_preparation_ready() -> serde_json::Value {
    let state = State {
        operation: PreparationOperation::ApplyOwnedDacl,
        progress: memcordon_platform::windows_access_failure_preparation::Milestones {
            file_created: true,
            fixed_bytes_written: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let record = Record::from_error(&state, &std::io::Error::from_raw_os_error(5));
    json!({"format":"memcordon.access-calibration-ready","prepared":false,"pid":123,"native_error":5,"preparation_failure":record})
}

#[test]
fn preparation_operation_and_native_error_survive_helper_and_controller_custody() {
    use memcordon_ci::windows_access_failure_probe::{
        preparation_error, preparation_failure_ready,
    };
    let mut bytes = serde_json::to_vec(&failed_preparation_ready()).unwrap();
    bytes.push(b'\n');
    assert!(bytes.len() < FRAME_BYTES);
    let frame = first_frame(&bytes).unwrap().unwrap();
    let record = preparation_failure_ready(&frame, 123).unwrap().unwrap();
    assert_eq!(record.operation, PreparationOperation::ApplyOwnedDacl);
    assert_eq!(record.native_error, Some(5));
    assert!(!record.progress.dacl_applied);
    assert_eq!(record.request.owner_file_desired_access, 0x60003);
    let retained = serde_json::to_vec(&record).unwrap();
    assert_eq!(serde_json::from_slice::<Record>(&retained).unwrap(), record);
    let error = preserve(
        Err(preparation_error(record)),
        Err(std::io::Error::other("publication secondary")),
    )
    .unwrap_err();
    let mut source: &(dyn std::error::Error + 'static) = &error;
    let mut native = None;
    for _ in 0..8 {
        if let Some(code) = source
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            native = Some(code);
            break;
        }
        match source.source() {
            Some(next) => source = next,
            None => break,
        }
    }
    assert_eq!(native, Some(5));
    assert!(error.to_string().contains("ApplyOwnedDacl"));
}

#[test]
fn contradictory_or_unbound_preparation_frames_are_mandatory_protocol_failures() {
    use memcordon_ci::windows_access_failure_probe::preparation_failure_ready;
    let frame = failed_preparation_ready();
    assert!(preparation_failure_ready(&frame, 124).is_err());
    for (field, value) in [("prepared", json!(true)), ("native_error", json!(87))] {
        let mut bad = frame.clone();
        bad[field] = value;
        assert!(preparation_failure_ready(&bad, 123).is_err());
    }
    for (field, value) in [
        ("operation", json!("unknown-operation")),
        ("native_error", json!(0)),
    ] {
        let mut bad = frame.clone();
        bad["preparation_failure"][field] = value;
        assert!(preparation_failure_ready(&bad, 123).is_err());
    }
    let mut bad = frame.clone();
    bad["preparation_failure"]["progress"]["dacl_applied"] = json!(true);
    assert!(preparation_failure_ready(&bad, 123).is_err());
    let mut missing = frame.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("preparation_failure");
    assert!(preparation_failure_ready(&missing, 123).is_err());
    let mut foreign = frame;
    foreign["raw_sid"] = json!("not accepted");
    assert!(preparation_failure_ready(&foreign, 123).is_err());
}
