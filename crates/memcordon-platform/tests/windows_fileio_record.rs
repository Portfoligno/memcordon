#![cfg(feature = "test-support")]
use memcordon_platform::windows_fileio_record::*;

fn spec() -> ConsumerSpec {
    ConsumerSpec {
        version: 1,
        session_name: "Memcordon-FileIo-test".into(),
        session_guid: [1; 16],
        pid: 7,
        birth: 9,
        binding: Binding {
            descriptor_sha256: [2; 32],
            challenge_sha256: [3; 32],
            cutoff_qpc: 1000,
            frequency: 10,
        },
    }
}
fn create(irp: u64, qpc: u64) -> Create {
    Create {
        irp,
        qpc,
        header_pid: 7,
        header_tid: 8,
        ttid: 11,
        file_object: 99,
        create_options: 0,
        file_attributes: 0,
        share_access: 7,
        path_prefix: vec![0xd800, 92, 120],
        path_units: 3,
        path_sha256: Some([4; 32]),
        path_truncated: false,
    }
}
fn end(irp: u64, qpc: u64) -> Completion {
    Completion {
        irp,
        qpc,
        extra_info: 0,
        ntstatus: 0xc0000022u32 as i32,
    }
}
fn windows() -> Vec<Window> {
    vec![Window {
        dependency_sequence: 1,
        loader_dependency_sequence: 2,
        parent_listener_sequence: 3,
        started_qpc: 10,
        finished_qpc: 30,
    }]
}

fn rejection(opcode: u8, version: u8, stage: RejectStage) -> RejectSample {
    RejectSample {
        opcode,
        event_version: version,
        header_flags: 64,
        user_data_length: 4096,
        rejection: DecodeRejection::new(stage),
        metadata: None,
    }
}
fn preview() -> SchemaPreview {
    SchemaPreview {
        decoding_source: 1,
        provider_guid: [255; 16],
        event_guid: [254; 16],
        descriptor_id: u16::MAX,
        descriptor_version: 2,
        descriptor_opcode: 64,
        property_count: 8,
        top_level_property_count: 8,
        properties: (0..8)
            .map(|index| PropertyPreview {
                index,
                flags: 0,
                in_type: Some(u16::MAX),
                out_type: Some(u16::MAX),
                name_prefix: vec![65535; 32],
                name_units: Some(32),
                name_truncated: false,
                name_unavailable: false,
            })
            .collect(),
        properties_omitted: 0,
    }
}

#[test]
fn opcode_quotas_keep_create_reason_after_unbound_completion_flood() {
    let mut collector = Collector::new(spec()).unwrap();
    for version in 3..23 {
        collector.received(76);
        collector.rejected(rejection(76, version, RejectStage::EventVersion));
    }
    let mut sample = rejection(64, 2, RejectStage::SchemaRead);
    sample.rejection.native_status = Some(87);
    collector.received(64);
    collector.rejected(sample);
    assert!(!collector.wants_sample(64, 2, RejectStage::SchemaRead, None));
    let observed = collector.finish(0, false);
    assert!(observed.validate().is_ok());
    assert_eq!(observed.decode.completion_received, 20);
    assert_eq!(observed.decode.completion_rejected, 20);
    assert_eq!(observed.decode.create_header_matched, 1);
    assert_eq!(observed.decode.create_rejected, 1);
    assert_eq!(observed.counters.unsupported, 21);
    assert_eq!(observed.decode.sample_omitted, 16);
    assert_eq!(
        observed
            .decode
            .samples
            .iter()
            .filter(|sample| sample.opcode == 76)
            .count(),
        4
    );
    let eligible = observed
        .decode
        .samples
        .iter()
        .find(|sample| sample.opcode == 64)
        .unwrap();
    assert_eq!(eligible.rejection.native_status, Some(87));
    assert!(eligible.metadata.is_none());
    let value = decode_diagnostic(&observed.decode);
    assert_eq!(value["native_status_domain"], "Win32 TDH direct return");
    for sample in value["samples"].as_array().unwrap() {
        for forbidden in ["pid", "tid", "irp", "path", "payload", "file_object"] {
            assert!(sample.get(forbidden).is_none());
        }
    }
}

#[test]
fn raw_and_rendered_details_share_existing_carrier_bounds_and_fair_metadata() {
    let mut collector = Collector::new(spec()).unwrap();
    for opcode in [76, 64] {
        for version in 2..6 {
            collector.received(opcode);
            let mut sample = rejection(opcode, version, RejectStage::PropertyFlags);
            sample.metadata = Some(preview());
            collector.rejected(sample);
        }
    }
    for irp in 1..=32 {
        let mut row = create(irp, 12);
        row.path_prefix = vec![65535; 128];
        row.path_units = 32767;
        row.path_truncated = true;
        collector.create(row);
        collector.completion(end(irp, 20));
    }
    let observed = collector.finish(0, false);
    assert!(observed.validate().is_ok());
    assert_eq!(observed.decode.samples.len(), 8);
    assert!(observed.decode.detail_truncated);
    assert!(observed.decode.metadata_omitted > 0);
    for opcode in [64, 76] {
        assert!(
            observed
                .decode
                .samples
                .iter()
                .any(|sample| sample.opcode == opcode && sample.metadata.is_some())
        );
    }
    assert!(serde_json::to_vec(&observed.decode).unwrap().len() <= DECODE_BYTES);
    assert!(
        serde_json::to_vec(&decode_diagnostic(&observed.decode))
            .unwrap()
            .len()
            <= DECODE_BYTES
    );
    assert!(serde_json::to_vec(&observed).unwrap().len() <= RECORD_BYTES);
    let rendered = correlate(&observed, &spec(), 11, &windows());
    assert!(serde_json::to_vec(&rendered).unwrap().len() <= CORRELATION_BYTES);
    assert_eq!(rendered["unsupported_history_prevents_association"], true);
    assert!(!rendered["rows"].as_array().unwrap().is_empty());
    assert!(
        rendered["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["temporal_original_call_association"] == false)
    );
}

#[test]
fn malformed_schema_previews_and_stage_totals_are_rejected_without_interpreting_unions() {
    let mut collector = Collector::new(spec()).unwrap();
    collector.received(64);
    let mut sample = rejection(64, 2, RejectStage::SchemaInventory);
    sample.metadata = Some(preview());
    collector.rejected(sample);
    let observed = collector.finish(0, false);
    for mutation in 0..8 {
        let mut bad = observed.clone();
        let metadata = bad.decode.samples[0].metadata.as_mut().unwrap();
        match mutation {
            0 => metadata.properties[0].name_prefix.push(1),
            1 => metadata.properties[0].name_units = None,
            2 => metadata.properties[0].name_unavailable = true,
            3 => metadata.properties[0].flags = 1,
            4 => metadata.properties.push(metadata.properties[0].clone()),
            5 => metadata.properties_omitted = 1,
            6 => metadata.properties[1].index = 0,
            _ => bad.decode.stage_counts[0][RejectStage::SchemaInventory as usize] = 0,
        }
        assert!(bad.validate().is_err(), "mutation {mutation}");
    }
    let mut large = observed.clone();
    let metadata = large.decode.samples[0].metadata.as_mut().unwrap();
    metadata.property_count = u32::MAX;
    metadata.top_level_property_count = u32::MAX;
    metadata.properties_omitted = u32::MAX - 8;
    assert!(
        large.validate().is_ok(),
        "actual rejected inventory counts are raw facts, not allocation sizes"
    );
    let mut unknown = serde_json::to_value(&observed).unwrap();
    unknown["decode"]["samples"][0]["rejection"]["stage"] = serde_json::json!("not-a-stage");
    assert!(serde_json::from_value::<Observation>(unknown).is_err());
}

#[test]
fn version_three_requires_history_and_telemetry_without_reinterpreting_older_records() {
    let mut collector = Collector::new(spec()).unwrap();
    for _ in 0..2 {
        collector.received(64);
        collector.rejected(rejection(64, 7, RejectStage::EventVersion));
    }
    collector.received(76);
    collector.decoded(76);
    let observed = collector.finish(0, false);
    assert_eq!(observed.version, 3);
    assert_eq!(observed.spec.version, 1);
    assert!(observed.validate().is_ok());
    assert_eq!(observed.decode.samples.len(), 1);
    assert!(observed.decode.samples[0].metadata.is_none());
    assert_eq!(
        observed.decode.stage_counts[0][RejectStage::EventVersion as usize],
        2
    );
    assert_eq!(observed.counters.unsupported, 2);
    assert_eq!(observed.decode.sample_omitted, 0);
    let roundtrip: Observation =
        serde_json::from_slice(&serde_json::to_vec(&observed).unwrap()).unwrap();
    assert!(roundtrip.validate().is_ok());
    let mut old = roundtrip.clone();
    old.version = 2;
    assert!(old.validate().is_err());
    let mut missing_history = serde_json::to_value(&roundtrip).unwrap();
    missing_history.as_object_mut().unwrap().remove("history");
    assert!(serde_json::from_value::<Observation>(missing_history).is_err());
    let mut missing = serde_json::to_value(roundtrip).unwrap();
    missing.as_object_mut().unwrap().remove("decode");
    assert!(serde_json::from_value::<Observation>(missing).is_err());
}

fn prefix_collector() -> Collector {
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(1, 12));
    collector.completion(end(1, 20));
    for index in 1..MAX_ROWS {
        let qpc = 40 + index as u64 * 2;
        let irp = index as u64 + 1;
        collector.create(create(irp, qpc));
        collector.completion(end(irp, qpc + 1));
    }
    collector
}
fn row_associated(value: &serde_json::Value, irp: u64) -> bool {
    value["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["create"]["irp"] == irp)
        .unwrap()["temporal_original_call_association"]
        .as_bool()
        .unwrap()
}

#[test]
fn later_capacity_loss_preserves_only_a_whole_strictly_earlier_window() {
    let mut collector = prefix_collector();
    collector.create(create(100, 200));
    collector.completion(end(100, 201));
    let observed = collector.finish(0, false);
    assert!(observed.validate().is_ok());
    assert_eq!(observed.rows.len(), MAX_ROWS);
    assert_eq!(observed.counters.overflow, 1);
    assert_eq!(observed.history.dropped_creates, 1);
    assert_eq!(observed.history.earliest_dropped_create_qpc, Some(200));
    assert_eq!(observed.history.maximum_qpc, 201);
    assert_eq!(observed.history.decoded_events, 66);
    assert!(!observed.history.timestamp_regression);
    let rendered = correlate(&observed, &spec(), 11, &windows());
    assert!(row_associated(&rendered, 1));
    let row = rendered["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["create"]["irp"] == 1)
        .unwrap();
    assert_eq!(
        row["association_scope"],
        "retained-prefix-before-first-dropped-create"
    );
    assert_eq!(rendered["capacity_truncated"], true);
    assert_eq!(rendered["global_routes_complete"], false);
    assert_eq!(rendered["denied_object_proved"], false);
    for finish in [200, 201] {
        let mut window = windows();
        window[0].finished_qpc = finish;
        let rendered = correlate(&observed, &spec(), 11, &window);
        assert!(!row_associated(&rendered, 1));
        assert_eq!(
            rendered["rows"][0]["capacity_truncation_blocks_window"],
            true
        );
    }
    for mutation in 0..4 {
        let mut bad = observed.clone();
        match mutation {
            0 => bad.cutoff_reached = true,
            1 => bad.consumer_completed = false,
            2 => bad.close_trace_status = 5,
            _ => bad.counters.malformed = 1,
        };
        assert!(!row_associated(
            &correlate(&bad, &spec(), 11, &windows()),
            1
        ));
    }
    let mut collector = prefix_collector();
    collector.create(create(100, 200));
    collector.received(76);
    collector.rejected(rejection(76, 4, RejectStage::EventVersion));
    let unsupported = collector.finish(0, false);
    assert!(unsupported.validate().is_ok());
    assert!(!unsupported.history.timestamp_regression);
    assert!(!row_associated(
        &correlate(&unsupported, &spec(), 11, &windows()),
        1
    ));
    // Saturated scalar counts still fit the same carrier; no wrapping or count-
    // shaped allocation is needed to render them.
    let mut saturated = observed;
    saturated.history.decoded_events = u64::MAX;
    saturated.counters.seen = u64::MAX;
    saturated.history.dropped_creates = u64::MAX;
    saturated.counters.overflow = u64::MAX;
    assert!(saturated.validate().is_ok());
    assert!(serde_json::to_vec(&saturated).unwrap().len() <= RECORD_BYTES);
    assert!(
        serde_json::to_vec(&correlate(&saturated, &spec(), 11, &windows()))
            .unwrap()
            .len()
            <= CORRELATION_BYTES
    );
}

#[test]
fn every_dropped_create_and_orphan_completion_still_updates_stream_order() {
    let mut collector = prefix_collector();
    collector.create(create(100, 200));
    collector.create(create(101, 150));
    let observed = collector.finish(0, false);
    assert!(observed.validate().is_ok());
    assert_eq!(observed.history.earliest_dropped_create_qpc, Some(150));
    assert_eq!(observed.history.dropped_creates, 2);
    assert_eq!(observed.history.maximum_qpc, 200);
    assert!(observed.history.timestamp_regression);
    assert!(!row_associated(
        &correlate(&observed, &spec(), 11, &windows()),
        1
    ));
    let mut collector = prefix_collector();
    collector.create(create(100, 200));
    collector.completion(end(999, 199));
    let observed = collector.finish(0, false);
    assert!(observed.history.timestamp_regression);
    assert_eq!(observed.counters.orphan, 1);
    assert!(!row_associated(
        &correlate(&observed, &spec(), 11, &windows()),
        1
    ));
    let mut collector = prefix_collector();
    collector.completion(end(999, 0));
    let observed = collector.finish(0, false);
    assert!(observed.history.timestamp_regression);
    assert!(!row_associated(
        &correlate(&observed, &spec(), 11, &windows()),
        1
    ));
}

#[test]
fn same_irp_timestamp_ties_are_ambiguous_but_unrelated_ties_are_not() {
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(1, 12));
    collector.completion(end(1, 20));
    collector.create(create(1, 20));
    collector.completion(end(1, 25));
    let observed = collector.finish(0, false);
    assert!(!observed.history.timestamp_regression);
    assert!(observed.rows.iter().all(|row| row.ambiguous));
    assert!(!row_associated(
        &correlate(&observed, &spec(), 11, &windows()),
        1
    ));
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(1, 12));
    collector.completion(end(1, 20));
    collector.completion(end(1, 20));
    let observed = collector.finish(0, false);
    assert!(observed.rows[0].ambiguous);
    assert_eq!(observed.counters.orphan, 1);
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(1, 12));
    collector.completion(end(1, 12));
    let observed = collector.finish(0, false);
    assert!(!row_associated(
        &correlate(&observed, &spec(), 11, &windows()),
        1
    ));
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(1, 12));
    collector.create(create(2, 12));
    collector.completion(end(1, 20));
    collector.completion(end(2, 20));
    let observed = collector.finish(0, false);
    assert!(!observed.history.timestamp_regression);
    assert!(observed.rows.iter().all(|row| !row.ambiguous));
    let rendered = correlate(&observed, &spec(), 11, &windows());
    assert!(row_associated(&rendered, 1));
    assert!(row_associated(&rendered, 2));
}

#[test]
fn missing_or_contradictory_frontier_never_upgrades_a_record() {
    let mut collector = prefix_collector();
    collector.create(create(100, 200));
    let observed = collector.finish(0, false);
    for mutation in 0..8 {
        let mut bad = observed.clone();
        match mutation {
            0 => bad.history.decoded_events -= 1,
            1 => bad.history.dropped_creates = 0,
            2 => bad.history.earliest_dropped_create_qpc = None,
            3 => bad.history.earliest_dropped_create_qpc = Some(0),
            4 => bad.history.earliest_dropped_create_qpc = Some(201),
            5 => bad.history.maximum_qpc = 1001,
            6 => bad.history.maximum_qpc = 10,
            _ => bad.version = 2,
        }
        assert!(bad.validate().is_err(), "mutation {mutation}");
        assert_eq!(
            correlate(&bad, &spec(), 11, &windows())["valid_binding_and_record"],
            false
        );
    }
    let mut collector = Collector::new(spec()).unwrap();
    for index in 0..MAX_ROWS {
        collector.create(create(index as u64 + 1, 12 + index as u64));
    }
    collector.create(create(100, 50));
    collector.completion(end(1, 60));
    let pending = collector.finish(0, false);
    assert_eq!(pending.history.earliest_dropped_create_qpc, Some(50));
    assert_eq!(pending.counters.unmatched, 31);
    assert!(!row_associated(
        &correlate(
            &pending,
            &spec(),
            11,
            &[Window {
                finished_qpc: 70,
                ..windows()[0].clone()
            }]
        ),
        1
    ));
}

#[test]
fn exact_session_thread_and_unique_window_required() {
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(5, 12));
    collector.completion(end(5, 20));
    let observation = collector.finish(0, false);
    assert!(observation.validate().is_ok());
    let result = correlate(&observation, &spec(), 11, &windows());
    assert_eq!(result["rows"][0]["observed_failed_create"], true);
    assert_eq!(result["denied_object_proved"], false);
    let mut retained = windows();
    for sequence in 2..=17 {
        retained.push(Window {
            dependency_sequence: sequence,
            loader_dependency_sequence: sequence + 20,
            parent_listener_sequence: sequence + 40,
            started_qpc: 40 + sequence,
            finished_qpc: 41 + sequence,
        });
    }
    assert_eq!(
        correlate(&observation, &spec(), 11, &retained)["rows"][0]["observed_failed_create"],
        true
    );
    let mut foreign = spec();
    foreign.session_guid[0] = 2;
    assert_eq!(
        correlate(&observation, &foreign, 11, &windows())["valid_binding_and_record"],
        false
    );
    assert_eq!(
        correlate(&observation, &spec(), 12, &windows())["rows"][0]["temporal_original_call_association"],
        false
    );
    let mut overlap = windows();
    overlap.push(overlap[0].clone());
    assert_eq!(
        correlate(&observation, &spec(), 11, &overlap)["rows"][0]["temporal_original_call_association"],
        false
    );
}

#[test]
fn collisions_reordering_and_overflow_never_promote_pairs() {
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(5, 12));
    collector.create(create(5, 13));
    collector.completion(end(5, 20));
    collector.create(create(5, 21));
    collector.completion(end(5, 25));
    let observation = collector.finish(0, false);
    assert_eq!(observation.rows.len(), 1);
    assert!(observation.rows[0].ambiguous);
    assert!(observation.rows[0].completion.is_none());
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(5, 20));
    collector.completion(end(5, 12));
    assert_eq!(
        correlate(&collector.finish(0, false), &spec(), 11, &windows())["rows"][0]["observed_failed_create"],
        false
    );
    let mut collector = Collector::new(spec()).unwrap();
    for irp in 1..=33 {
        collector.create(create(irp, 12));
        collector.completion(end(irp, 20));
    }
    let observation = collector.finish(0, false);
    assert_eq!(observation.rows.len(), 32);
    assert_eq!(observation.counters.overflow, 1);
    assert!(
        correlate(&observation, &spec(), 11, &windows())["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["observed_failed_create"] == false)
    );
}

#[test]
fn native_width_and_utf16_validation_preserve_raw_units() {
    assert_eq!(pointer(&[255; 4], 4).unwrap(), u32::MAX as u64);
    assert_eq!(pointer(&[255; 8], 8).unwrap(), u64::MAX);
    assert!(pointer(&[0; 8], 4).is_err());
    assert!(pointer(&[0; 4], 8).is_err());
    assert_eq!(thread_id(pointer(&[255; 4], 4).unwrap()).unwrap(), u32::MAX);
    assert_eq!(
        thread_id(pointer(&[255, 255, 255, 255, 0, 0, 0, 0], 8).unwrap()).unwrap(),
        u32::MAX
    );
    assert!(thread_id(u32::MAX as u64 + 1).is_err());
    assert_eq!(path_units(&[0, 216, 0, 0, 0, 0]).unwrap(), vec![0xd800]);
    for malformed in [&[1u8][..], &[1, 0][..], &[0, 0, 1, 0][..]] {
        assert!(path_units(malformed).is_err());
    }
}

#[test]
fn finite_output_and_record_guards_cover_maximum_numeric_extents() {
    let mut collector = Collector::new(spec()).unwrap();
    for irp in 1..=32 {
        let mut value = create(irp, 12);
        value.path_prefix = vec![65535; 128];
        value.path_units = 32767;
        value.path_truncated = true;
        collector.create(value);
        collector.completion(end(irp, 20));
    }
    let observation = collector.finish(0, false);
    assert!(serde_json::to_vec(&observation).unwrap().len() <= RECORD_BYTES);
    assert!(
        serde_json::to_vec(&correlate(&observation, &spec(), 11, &windows()))
            .unwrap()
            .len()
            <= CORRELATION_BYTES
    );
    let mut invalid = observation.clone();
    invalid.rows[0].create.path_prefix.push(1);
    assert!(invalid.validate().is_err());
    let mut invalid = observation.clone();
    invalid.rows[0].create.header_pid = 8;
    assert!(invalid.validate().is_err());
    let mut invalid = observation.clone();
    invalid.rows[0].completion.as_mut().unwrap().qpc = 1001;
    assert!(invalid.validate().is_err());
    let mut invalid = observation.clone();
    invalid.rows[0].create.qpc = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = observation.clone();
    invalid.rows[0].create.path_truncated = false;
    assert!(invalid.validate().is_err());
    let mut invalid = observation;
    invalid.rows[0].completion.as_mut().unwrap().irp = 999;
    assert!(invalid.validate().is_err());
}

#[test]
fn cutoff_and_consumer_failure_remain_unassociated() {
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(5, 12));
    collector.completion(end(5, 20));
    let mut closed = collector.finish(0, false);
    closed.close_trace_status = 6;
    let result = correlate(&closed, &spec(), 11, &windows());
    assert_eq!(result["process_trace_status"], 0);
    assert_eq!(result["close_trace_status"], 6);
    assert_eq!(result["rows"][0]["observed_failed_create"], false);
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(5, 1001));
    let observed = collector.finish(0, true);
    assert!(observed.rows.is_empty());
    assert_eq!(observed.counters.filtered, 1);
    let mut collector = Collector::new(spec()).unwrap();
    collector.create(create(5, 12));
    collector.completion(end(5, 20));
    assert_eq!(
        correlate(&collector.finish(5, false), &spec(), 11, &windows())["rows"][0]["observed_failed_create"],
        false
    );
    let mut bad = spec();
    bad.session_name = "other".into();
    assert!(Collector::new(bad).is_err());
}
