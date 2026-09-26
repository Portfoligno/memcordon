use memcordon_ci::private_candidate_replay::{
    ReplayTaskV1, UncertainCheckpointOperandsV1, validate_uncertain_checkpoint_capture,
};
use memcordon_ci::private_public_source_facts::validate_public_checkpoint_capture;
use memcordon_core::DiagnosticSha256;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn target() -> ReplayTaskV1 {
    ReplayTaskV1 {
        tid: 20,
        tgid: 20,
        start_boottime_ns: 100,
        cgroup_inode: 30,
        time_ns_inode: 40,
    }
}
fn operands() -> UncertainCheckpointOperandsV1 {
    UncertainCheckpointOperandsV1 {
        target: target(),
        file_sync_sequence: 3,
        transport_loss_sequence: 7,
        gate_failure_sequence: 8,
        file_dev: 1,
        file_inode: 2,
        directory_dev: 1,
        directory_inode: 4,
        reopened_monotonic_ns: 35,
    }
}
fn record(
    sequence: u64,
    kind: u32,
    pid: u32,
    nr: i64,
    occurrence: u64,
    result: i64,
    args: [u64; 6],
    time: u64,
    object: (u64, u64),
) -> Vec<u8> {
    let mut bytes = vec![0; 192];
    put64(&mut bytes, 0, sequence);
    put64(&mut bytes, 8, time);
    put64(&mut bytes, 16, 30);
    put64(&mut bytes, 24, if pid == 20 { 100 } else { 50 });
    put64(&mut bytes, 32, object.0);
    put64(&mut bytes, 40, object.1);
    put64(&mut bytes, 48, nr as u64);
    put64(&mut bytes, 56, result as u64);
    put32(&mut bytes, 64, pid);
    put32(&mut bytes, 72, 0xc000003e);
    put32(&mut bytes, 76, if kind == 4 { 0x7fff0000 } else { 0 });
    put32(&mut bytes, 80, kind);
    bytes[84..116].copy_from_slice(&[1; 32]);
    put64(&mut bytes, 120, 40);
    put64(&mut bytes, 128, occurrence);
    for (index, arg) in args.into_iter().enumerate() {
        put64(&mut bytes, 136 + index * 8, arg);
    }
    put32(&mut bytes, 184, pid);
    bytes
}
fn capture() -> Vec<u8> {
    let recv = [3, 0x2000, 2, 0, 0, 0];
    let file = [8, 0, 0, 0, 0, 0];
    let dir = [10, 0, 0, 0, 0, 0];
    let send = [9, 0x1000, 1, 0x4000, 0, 0];
    let records = [
        record(1, 4, 20, 45, 1, 0, recv, 1, (0, 0)),
        record(2, 11, 10, 74, 2, 0, file, 10, (1, 2)),
        record(3, 5, 10, 74, 2, 0, file, 11, (0, 0)),
        record(4, 11, 10, 74, 3, 0, dir, 20, (1, 4)),
        record(5, 5, 10, 74, 3, 0, dir, 21, (0, 0)),
        record(6, 11, 10, 44, 4, 0, send, 40, (0, 0)),
        record(7, 5, 10, 44, 4, -32, send, 41, (0, 0)),
        record(8, 5, 20, 45, 1, 0, recv, 43, (0, 0)),
    ];
    let mut bytes = vec![0; 40];
    put32(&mut bytes, 0, 0x4d434b31);
    put32(&mut bytes, 4, 2);
    put64(&mut bytes, 8, records.len() as u64);
    put32(&mut bytes, 24, 192);
    put32(&mut bytes, 28, 7);
    put32(&mut bytes, 32, 12);
    put32(&mut bytes, 36, 0x01020304);
    for record in records {
        bytes.extend(record);
    }
    bytes
}
#[test]
fn real_fsync_fstat_epipe_and_closed_gate_prove_noexec_checkpoint() {
    validate_uncertain_checkpoint_capture(
        &capture(),
        &DiagnosticSha256::from_bytes([1; 32]),
        &operands(),
    )
    .unwrap();
}
#[test]
fn missing_directory_fsync_wrong_object_or_fstat_order_reject() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    let mut missing = capture();
    put64(&mut missing, 40 + 3 * 192 + 48, 75);
    put64(&mut missing, 40 + 4 * 192 + 48, 75);
    assert!(validate_uncertain_checkpoint_capture(&missing, &key, &operands()).is_err());
    let mut substituted = capture();
    put64(&mut substituted, 40 + 3 * 192 + 40, 5);
    assert!(validate_uncertain_checkpoint_capture(&substituted, &key, &operands()).is_err());
    let mut late = operands();
    late.reopened_monotonic_ns = 41;
    assert!(validate_uncertain_checkpoint_capture(&capture(), &key, &late).is_err());
}
#[test]
fn successful_go_target_exec_and_legacy_capture_cannot_prove_uncertain_checkpoint() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    let mut go = capture();
    let args = [9, 0x1000, 1, 0, 0, 0];
    go.extend(record(9, 11, 10, 1, 5, 0, args, 44, (0, 0)));
    go.extend(record(10, 5, 10, 1, 5, 1, args, 45, (0, 0)));
    put64(&mut go, 8, 10);
    assert!(validate_uncertain_checkpoint_capture(&go, &key, &operands()).is_err());
    let mut exec = capture();
    exec.extend(record(9, 6, 20, 0, 0, 0, [0; 6], 44, (1, 9)));
    put64(&mut exec, 8, 9);
    assert!(validate_uncertain_checkpoint_capture(&exec, &key, &operands()).is_err());
    let mut legacy = capture();
    put32(&mut legacy, 28, 3);
    put32(&mut legacy, 32, 11);
    assert!(validate_uncertain_checkpoint_capture(&legacy, &key, &operands()).is_err());
}

fn reopened(observed: u64, inode: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version":1,"file_dev":1,"file_inode":inode,
        "directory_dev":1,"directory_inode":4,"observed_monotonic_ns":observed,
        "bytes_sha256":memcordon_core::workload_codec::hash_bytes(b"actual-release-intent")
    }))
    .unwrap()
}

#[test]
fn public_original_durable_checkpoint_requires_actual_noexec_or_go_branch() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    let metadata = reopened(35, 2);
    validate_public_checkpoint_capture(
        &capture(),
        &key,
        &target(),
        b"actual-release-intent",
        &metadata,
        true,
    )
    .unwrap();
    assert!(
        validate_public_checkpoint_capture(
            &capture(),
            &key,
            &target(),
            b"actual-release-intent",
            &metadata,
            false
        )
        .is_err()
    );
    let mut executed = capture();
    let args = [9, 0x1000, 1, 0, 0, 0];
    // A real successful release has a GO write and one-byte gate receive.
    let begin = 40 + 5 * 192;
    let end = 40 + 7 * 192;
    let go = [
        record(6, 11, 10, 1, 4, 0, args, 40, (0, 0)),
        record(7, 5, 10, 1, 4, 1, args, 41, (0, 0)),
    ]
    .concat();
    executed[begin..end].copy_from_slice(&go);
    put64(&mut executed, 40 + 7 * 192 + 56, 1);
    executed.extend(record(9, 6, 20, 0, 0, 0, [0; 6], 44, (1, 9)));
    put64(&mut executed, 8, 9);
    validate_public_checkpoint_capture(
        &executed,
        &key,
        &target(),
        b"actual-release-intent",
        &metadata,
        false,
    )
    .unwrap();
    assert!(
        validate_public_checkpoint_capture(
            &executed,
            &key,
            &target(),
            b"actual-release-intent",
            &metadata,
            true
        )
        .is_err()
    );
}

#[test]
fn public_checkpoint_copy_inode_digest_missing_dirsync_late_read_and_legacy_reject() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    for metadata in [reopened(35, 99), reopened(41, 2)] {
        assert!(
            validate_public_checkpoint_capture(
                &capture(),
                &key,
                &target(),
                b"actual-release-intent",
                &metadata,
                true
            )
            .is_err()
        );
    }
    assert!(
        validate_public_checkpoint_capture(
            &capture(),
            &key,
            &target(),
            b"copied-different-phase",
            &reopened(35, 2),
            true
        )
        .is_err()
    );
    let mut missing = capture();
    put64(&mut missing, 40 + 3 * 192 + 48, 75);
    put64(&mut missing, 40 + 4 * 192 + 48, 75);
    assert!(
        validate_public_checkpoint_capture(
            &missing,
            &key,
            &target(),
            b"actual-release-intent",
            &reopened(35, 2),
            true
        )
        .is_err()
    );
    let mut legacy = capture();
    put32(&mut legacy, 28, 3);
    put32(&mut legacy, 32, 11);
    assert!(
        validate_public_checkpoint_capture(
            &legacy,
            &key,
            &target(),
            b"actual-release-intent",
            &reopened(35, 2),
            true
        )
        .is_err()
    );
}
