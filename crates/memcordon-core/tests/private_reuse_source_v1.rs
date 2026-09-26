use memcordon_core::DiagnosticSha256;
use memcordon_core::private_reuse_source_v1::*;
use memcordon_core::workload_codec::hash_bytes;
fn shapes() -> (ReuseSourceGateV1, ReuseSourceReportV1) {
    // The shape validator deliberately treats native journal bytes as opaque;
    // semantic replay separately checks their original full canonical wires.
    let before = br#"{"phase":"Retiring","release_knowledge":"ExecObserved"}"#.to_vec();
    let marker = br#"{"transition":"retiring-to-retired"}"#.to_vec();
    let object = |inode, bytes: &[u8]| ReuseSourceObjectV1 {
        device: 8,
        inode,
        uid: 0,
        mode: 0o100600,
        nlink: 1,
        size: bytes.len() as u64,
        bytes_sha256: hash_bytes(bytes),
    };
    let gate = ReuseSourceGateV1 {
        schema_version: 1,
        source_revision_sha256: reuse_source_revision_sha256(),
        phase: ReuseSourcePhaseV1::Blocked,
        selector: REUSE_SELECTOR_V1.into(),
        parent_result_key: DiagnosticSha256::from_bytes([1; 32]),
        challenge: [2; 32],
        admission_sha256: DiagnosticSha256::from_bytes([3; 32]),
        helper: ReuseSourceProcessV1 {
            pid: 42,
            start_time_ticks: 100,
        },
        directory_device: 8,
        directory_inode: 500,
        marker: object(501, &marker),
        record: object(502, &before),
        observed_monotonic_ns: 1000,
    };
    let report = ReuseSourceReportV1 {
        schema_version: 1,
        source_revision_sha256: reuse_source_revision_sha256(),
        phase: ReuseSourcePhaseV1::Blocked,
        parent_result_key: gate.parent_result_key.clone(),
        helper: gate.helper.clone(),
        admission_sha256: gate.admission_sha256.clone(),
        gate_sha256: hash_bytes(&serde_json::to_vec(&gate).unwrap()),
        before_bytes: before,
        marker_bytes: marker,
        original_observer_bytes: br#"{"schema_version":1}"#.to_vec(),
        retry_begin_monotonic_ns: 1100,
        retry_end_monotonic_ns: 1200,
        actual_reuse_error: "exclusive allocator returned File exists (os error 17)".into(),
        removed_monotonic_ns: None,
        recovered_monotonic_ns: None,
        after_bytes: None,
    };
    (gate, report)
}
#[test]
fn blocked_shape_is_not_recovery_or_a_qualification_capability() {
    let (gate, report) = shapes();
    validate_reuse_source_shape_v1(&gate, &report).unwrap();
    let mut changed = report.clone();
    changed.after_bytes = Some(br#"{"phase":"Retired"}"#.to_vec());
    assert!(validate_reuse_source_shape_v1(&gate, &changed).is_err());
}
#[test]
fn owned_objects_and_original_bytes_cannot_alias_or_be_substituted() {
    let (gate, report) = shapes();
    let mut changed = gate.clone();
    changed.marker.inode = changed.record.inode;
    assert!(validate_reuse_source_shape_v1(&changed, &report).is_err());
    let mut changed = report.clone();
    changed.marker_bytes.push(b' ');
    assert!(validate_reuse_source_shape_v1(&gate, &changed).is_err());
}
#[test]
fn recovery_shape_needs_later_removal_then_changed_durable_bytes() {
    let (mut gate, mut report) = shapes();
    gate.phase = ReuseSourcePhaseV1::Recover;
    report.phase = gate.phase;
    report.gate_sha256 = hash_bytes(&serde_json::to_vec(&gate).unwrap());
    report.removed_monotonic_ns = Some(1300);
    report.recovered_monotonic_ns = Some(1400);
    report.after_bytes =
        Some(br#"{"phase":"Retired","release_knowledge":"ExecObserved"}"#.to_vec());
    validate_reuse_source_shape_v1(&gate, &report).unwrap();
    report.removed_monotonic_ns = Some(report.retry_end_monotonic_ns);
    assert!(validate_reuse_source_shape_v1(&gate, &report).is_err());
}
