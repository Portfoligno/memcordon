#[path = "../src/bin/consumer_readiness_windows/provider_loader_context.rs"]
mod context;
use context::{Observation, bind, bounded, decode_details, diagnostic};
use serde_json::json;

fn word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn pointer(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn header() -> Vec<u8> {
    let mut bytes = vec![0; context::BUFFER_BYTES];
    word(&mut bytes, 4, 1);
    bytes
}
fn observation(details: serde_json::Value) -> Observation {
    Observation {
        attempted: true,
        started_qpc: Some(10),
        finished_qpc: Some(20),
        success: Some(true),
        required_bytes: Some(64),
        available_bytes: context::BUFFER_BYTES,
        cutoff_qpc: 100,
        qpc_frequency: 1000,
        details: Some(details),
        ..Default::default()
    }
}

#[test]
fn reported_paths_preserve_counted_units_and_known_empty_separately_from_absent() {
    let mut bytes = header();
    word(&mut bytes, 8, 0); // Zero assemblies is not an independently measured absent context.
    word(&mut bytes, 12, 2);
    word(&mut bytes, 16, 3);
    pointer(&mut bytes, 40, 0x1040);
    bytes[64..70].copy_from_slice(&[97, 0, 0, 0, 0, 216]);
    pointer(&mut bytes, 56, 0x1046); // Known zero-length application directory at the exact end.
    let value = decode_details(&bytes, 0x1000, 70);
    assert_eq!(value["state"], "complete");
    assert_eq!(
        value["paths"]["root_manifest"]["utf16_prefix"],
        json!([97, 0, 55296])
    );
    assert_eq!(
        value["paths"]["root_manifest"]["zero_unit_in_reported_span"],
        true
    );
    assert_eq!(value["paths"]["root_configuration"]["state"], "absent");
    assert!(value["paths"]["root_configuration"]["utf16_prefix"].is_null());
    assert_eq!(
        value["paths"]["application_directory"]["state"],
        "known-empty"
    );
    assert_eq!(
        value["paths"]["application_directory"]["utf16_prefix"],
        json!([])
    );
    assert_eq!(value["no_active_context_separately_measured"], false);
}

#[test]
fn invalid_native_extents_never_become_observed_strings() {
    for (address, characters) in [
        (0, 1),
        (0x1041, 1),
        (0x0ffe, 1),
        (0x1040, u32::MAX),
        (0x1048, 1),
    ] {
        let mut bytes = header();
        pointer(&mut bytes, 40, address);
        word(&mut bytes, 16, characters);
        let value = decode_details(&bytes, 0x1000, 72);
        assert_eq!(value["details_usable"], false);
        assert!(value["paths"]["root_manifest"]["utf16_prefix"].is_null());
    }
    let bytes = header();
    for returned in [0, 63, context::BUFFER_BYTES + 1] {
        let value = decode_details(&bytes, 0x1000, returned);
        assert_eq!(value["details_usable"], false);
        assert!(value["paths"].is_null());
    }
    let mut bytes = header();
    pointer(&mut bytes, 40, u64::MAX - 1);
    assert_eq!(
        decode_details(&bytes, usize::MAX - 7, 64)["details_usable"],
        false
    );
    word(&mut bytes, 4, 2);
    assert_eq!(
        decode_details(&bytes, 0x1000, 64)["state"],
        "unsupported-format"
    );
}

#[test]
fn failures_late_results_and_unmeasured_context_presence_keep_their_original_facts() {
    let details = decode_details(&header(), 0x1000, 64);
    let mut observed = observation(details);
    assert_eq!(
        diagnostic(&observed)["available_before_original_cutoff"],
        true
    );
    observed.available_bytes = 0;
    assert_eq!(
        diagnostic(&observed)["available_before_original_cutoff"],
        false
    );
    observed.available_bytes = context::BUFFER_BYTES;
    observed.success = Some(false);
    observed.details = None;
    observed.native_error = Some(5);
    assert_eq!(diagnostic(&observed)["state"], "query-error");
    assert_eq!(diagnostic(&observed)["native_error"], 5);
    assert_eq!(
        diagnostic(&observed)["active_context_presence"],
        "unmeasured"
    );
    observed.native_error = Some(120);
    assert_eq!(diagnostic(&observed)["state"], "unsupported");
    observed.required_bytes = Some(context::BUFFER_BYTES + 1);
    assert_eq!(diagnostic(&observed)["state"], "oversize");
    observed.finished_qpc = Some(9);
    assert_eq!(diagnostic(&observed)["clock_regressed"], true);
    assert!(diagnostic(&observed)["original_cutoff_reached"].is_null());
    observed.finished_qpc = Some(20);
    observed.qpc_frequency = 0;
    observed.attempted = false;
    assert_eq!(diagnostic(&observed)["state"], "clock-or-time-unavailable");
    assert!(diagnostic(&observed)["original_cutoff_reached"].is_null());
    observed.qpc_frequency = 1000;
    observed.attempted = true;
    observed.clock_error = Some(87);
    assert!(diagnostic(&observed)["original_cutoff_reached"].is_null());
    observed.clock_error = None;
    observed.finished_qpc = Some(observed.cutoff_qpc);
    assert_eq!(
        diagnostic(&observed)["available_before_original_cutoff"],
        false
    );
    assert_eq!(diagnostic(&observed)["state"], "clock-or-time-unavailable");
    observed.cutoff_reached = true;
    assert_eq!(diagnostic(&observed)["state"], "original-cutoff-reached");
    assert_eq!(
        diagnostic(&Observation {
            qpc_frequency: 1000,
            ..Default::default()
        })["state"],
        "not-attempted"
    );
}

#[test]
fn maximum_native_buffer_prefixes_and_bound_identity_fit_the_fixed_record_budget() {
    let mut bytes = header();
    for (type_offset, count_offset, pointer_offset, start) in
        [(12, 16, 40, 64), (20, 24, 48, 2664), (28, 32, 56, 5264)]
    {
        word(&mut bytes, type_offset, 2);
        word(&mut bytes, count_offset, 1300);
        pointer(&mut bytes, pointer_offset, 0x1000 + start as u64);
        bytes[start..start + 2600].fill(255);
    }
    let details = decode_details(&bytes, 0x1000, 7864);
    for path in [
        "root_manifest",
        "root_configuration",
        "application_directory",
    ] {
        assert_eq!(
            details["paths"][path]["captured_units"],
            context::PATH_UNITS
        );
        assert_eq!(details["paths"][path]["prefix_truncated"], true);
        assert_eq!(
            details["paths"][path]["reported_span_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }
    let mut measured = observation(details);
    measured.required_bytes = Some(7864);
    let mut snapshot = json!({"activation_context":diagnostic(&measured),
        "actual_self":{"available_before_original_cutoff":true,"pid":u32::MAX,"creation_time_100ns":u64::MAX,"thread_id":u32::MAX},
        "phase":"before-original-network-call","descriptor_sha256":([255u8;32]).as_slice(),"challenge_sha256":([255u8;32]).as_slice()});
    snapshot = bind(snapshot, u32::MAX, u64::MAX);
    assert_eq!(snapshot["matches_authenticated_original_identity"], true);
    assert!(bounded(snapshot.clone()).unwrap().len() <= context::RECORD_BYTES);
    assert_eq!(
        bind(snapshot, 1, u64::MAX)["matches_authenticated_original_identity"],
        false
    );
    assert!(bounded(json!({"oversize":"x".repeat(context::RECORD_BYTES)})).is_err());
}
