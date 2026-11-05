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
