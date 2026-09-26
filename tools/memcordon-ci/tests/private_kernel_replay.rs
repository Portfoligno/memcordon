pub use memcordon_ci::{CiError, Result};
#[path = "../src/private_kernel_replay.rs"]
mod private_kernel_replay;
use memcordon_core::DiagnosticSha256;
use private_kernel_replay::*;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn capture() -> Vec<u8> {
    let mut bytes = vec![0; CAPTURE_HEADER_BYTES_V2 + 2 * CAPTURE_RECORD_BYTES_V2];
    put32(&mut bytes, 0, 0x4d434b31);
    put32(&mut bytes, 4, 2);
    put64(&mut bytes, 8, 2);
    put32(&mut bytes, 24, 192);
    put32(&mut bytes, 28, 3);
    put32(&mut bytes, 32, 11);
    put32(&mut bytes, 36, 0x01020304);
    for (index, raw) in bytes[CAPTURE_HEADER_BYTES_V2..]
        .chunks_exact_mut(CAPTURE_RECORD_BYTES_V2)
        .enumerate()
    {
        put64(raw, 0, index as u64 + 1);
        put64(raw, 8, 1000 + index as u64);
        put64(raw, 16, 8);
        put64(raw, 24, 9);
        put32(raw, 64, 10);
        put32(raw, 184, 11);
        put64(raw, 120, 12);
        raw[84..116].copy_from_slice(&[1; 32]);
        put32(raw, 72, 0xc000003e);
        put64(raw, 48, 41);
        put64(raw, 128, 23);
        put64(raw, 136, 1);
        put32(raw, 80, if index == 0 { 4 } else { 5 });
        if index == 0 {
            put32(raw, 76, 0x00050000);
            put64(raw, 56, 97);
        } else {
            put64(raw, 56, (-97i64) as u64);
        }
    }
    bytes
}

fn filter_capture() -> Vec<u8> {
    let template = capture()
        [CAPTURE_HEADER_BYTES_V2..CAPTURE_HEADER_BYTES_V2 + CAPTURE_RECORD_BYTES_V2]
        .to_vec();
    let mut bytes = vec![0; CAPTURE_HEADER_BYTES_V2];
    put32(&mut bytes, 0, 0x4d434b31);
    put32(&mut bytes, 4, 2);
    put64(&mut bytes, 8, 10);
    put32(&mut bytes, 24, 192);
    put32(&mut bytes, 28, 31);
    put32(&mut bytes, 32, 12);
    put32(&mut bytes, 36, 0x01020304);
    for (index, kind) in [11, 14, 5, 12, 13, 6, 13, 13, 4, 5].into_iter().enumerate() {
        let mut raw = template.clone();
        put64(&mut raw, 0, index as u64 + 1);
        put64(&mut raw, 8, 1_000_000_000 + 100 * index as u64);
        put64(&mut raw, 24, 10_000_000);
        put32(&mut raw, 184, 10);
        put32(&mut raw, 80, kind);
        put32(&mut raw, 76, 0);
        put64(&mut raw, 56, 0);
        put64(&mut raw, 48, 317);
        put64(&mut raw, 136, 1);
        put64(&mut raw, 144, 0);
        put64(&mut raw, 152, 0x1000);
        match index {
            1 => {
                put64(&mut raw, 32, 1);
                put64(&mut raw, 40, 0x2000);
            }
            3 => {
                put32(&mut raw, 68, 1);
                put64(&mut raw, 32, 0x3000);
                put64(&mut raw, 40, 0x7fff000000000006);
            }
            4 => {
                put32(&mut raw, 68, 1);
                put64(&mut raw, 32, 0x3000);
                put32(&mut raw, 76, 1);
                put64(&mut raw, 56, 2);
            }
            5 | 6 => {
                put64(&mut raw, 128, 0);
                put32(&mut raw, 72, 0);
                put64(&mut raw, 48, 0);
                put64(&mut raw, 136, 0);
                put64(&mut raw, 152, 0);
                put64(&mut raw, 32, 0x3000);
                if index == 6 {
                    put32(&mut raw, 76, 3);
                    put64(&mut raw, 56, 2);
                }
            }
            7..=9 => {
                put64(&mut raw, 128, 24);
                put64(&mut raw, 48, 39);
                put64(&mut raw, 136, 0);
                put64(&mut raw, 152, 0);
                if index == 7 {
                    put64(&mut raw, 32, 0x3000);
                    put32(&mut raw, 76, 2);
                    put64(&mut raw, 56, 2);
                }
                if index == 8 {
                    put32(&mut raw, 76, 0x7fff0000);
                }
                if index == 9 {
                    put64(&mut raw, 56, 10);
                }
            }
            _ => {}
        }
        bytes.extend_from_slice(&raw);
    }
    bytes
}

#[test]
fn installed_filter_program_comes_from_paired_kernel_snapshot() {
    let bytes = filter_capture();
    let parsed = parse_capture_v2(&bytes, &DiagnosticSha256::from_bytes([1; 32])).unwrap();
    let filters = installed_kernel_filters(parsed.events()).unwrap();
    assert_eq!(filters.len(), 1);
    let filter = &filters[0];
    assert_eq!(filter.filter_identity, 0x3000);
    assert_eq!(filter.install_sequence, 1);
    assert_eq!(filter.installed_sequence, 5);
    assert_eq!(filter.instructions, 0x7fff000000000006u64.to_le_bytes());
    assert_eq!(
        filter.instructions_sha256,
        memcordon_core::workload_codec::hash_bytes(&filter.instructions)
    );
}

#[test]
fn filter_feature_loss_partial_substitution_and_failed_install_reject() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    for (offset, value, width) in [
        (28, 15, 4),
        (16, 1, 8),
        (CAPTURE_HEADER_BYTES_V2 + CAPTURE_RECORD_BYTES_V2 + 32, 2, 8),
        (
            CAPTURE_HEADER_BYTES_V2 + 2 * CAPTURE_RECORD_BYTES_V2 + 56,
            (-22i64) as u64,
            8,
        ),
        (
            CAPTURE_HEADER_BYTES_V2 + 3 * CAPTURE_RECORD_BYTES_V2 + 56,
            1,
            8,
        ),
        (
            CAPTURE_HEADER_BYTES_V2 + 3 * CAPTURE_RECORD_BYTES_V2 + 32,
            0x4000,
            8,
        ),
        (
            CAPTURE_HEADER_BYTES_V2 + 4 * CAPTURE_RECORD_BYTES_V2 + 128,
            25,
            8,
        ),
        (
            CAPTURE_HEADER_BYTES_V2 + 4 * CAPTURE_RECORD_BYTES_V2 + 76,
            5,
            4,
        ),
    ] {
        let mut bytes = filter_capture();
        if width == 4 {
            put32(&mut bytes, offset, value as u32);
        } else {
            put64(&mut bytes, offset, value);
        }
        assert!(
            parse_capture_v2(&bytes, &key).is_err(),
            "filter mutation at {offset}"
        );
    }
    let mut truncated = filter_capture();
    truncated.pop();
    assert!(parse_capture_v2(&truncated, &key).is_err());
}

#[test]
fn installed_filter_source_joins_actual_pre_exec_baseline_and_lineage() {
    use memcordon_ci::private_candidate_filter_facility_facts::validate_capture_filter_source;
    use memcordon_ci::private_candidate_replay::ReplayTaskV1;
    use memcordon_ci::private_public_live::{HeldPublicTargetSamplesV1, HeldPublicTaskSampleV1};
    use std::collections::BTreeMap;
    let task = ReplayTaskV1 {
        tid: 10,
        tgid: 10,
        start_boottime_ns: 10_000_000,
        cgroup_inode: 8,
        time_ns_inode: 12,
    };
    let stat = |pid| {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "1";
        format!("{pid} (filter worker) {}\n", fields.join(" "))
    };
    let clock=serde_json::to_vec(&serde_json::json!({"schema_version":1,"reader_pid":42,"reader_start_ticks":1,"stat_before":stat(42),"stat_after":stat(42),"time_namespace_before":"time:[12]","time_namespace_after":"time:[12]","timens_offsets":"monotonic 0 0\nboottime 0 0\n","clk_tck_stdout":b"100\n","clk_tck_exit_success":true})).unwrap();
    let sample = |begin, end| HeldPublicTargetSamplesV1 {
        schema_version: 1,
        pid: 10,
        start_time_ticks: 1,
        begin_monotonic_ns: begin,
        end_monotonic_ns: end,
        executable_sha256: DiagnosticSha256::from_bytes([2; 32]),
        executable_device: 3,
        executable_inode: 4,
        tasks: vec![HeldPublicTaskSampleV1 {
            tid: 10,
            tgid: 10,
            start_time_ticks: 1,
            namespace_inodes: BTreeMap::new(),
        }],
        leaves: BTreeMap::from([
            (
                "tasks/10/status.raw".into(),
                b"NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n".to_vec(),
            ),
            ("tasks/10/stat.raw".into(), stat(10).into_bytes()),
            ("tasks/10/stat-after.raw".into(), stat(10).into_bytes()),
        ]),
    };
    let pre = sample(1_000_000_410, 1_000_000_490);
    let baseline = sample(1_000_000_610, 1_000_000_690);
    let instructions = 0x7fff000000000006u64.to_le_bytes();
    let hash = memcordon_core::workload_codec::hash_bytes(&instructions);
    let key = DiagnosticSha256::from_bytes([1; 32]);
    let bytes = filter_capture();
    validate_capture_filter_source(
        &bytes,
        &key,
        &clock,
        &task,
        &pre,
        &baseline,
        &instructions,
        &hash,
    )
    .unwrap();
    for offset in [
        CAPTURE_HEADER_BYTES_V2 + 6 * CAPTURE_RECORD_BYTES_V2 + 32,
        CAPTURE_HEADER_BYTES_V2 + 7 * CAPTURE_RECORD_BYTES_V2 + 32,
    ] {
        let mut changed = bytes.clone();
        put64(&mut changed, offset, 0x4000);
        assert!(
            validate_capture_filter_source(
                &changed,
                &key,
                &clock,
                &task,
                &pre,
                &baseline,
                &instructions,
                &hash
            )
            .is_err()
        );
    }
    let mut changed = baseline.clone();
    changed.leaves.insert(
        "tasks/10/status.raw".into(),
        b"NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\n".to_vec(),
    );
    assert!(
        validate_capture_filter_source(
            &bytes,
            &key,
            &clock,
            &task,
            &pre,
            &changed,
            &instructions,
            &hash
        )
        .is_err()
    );
    let mut changed = pre.clone();
    changed.end_monotonic_ns = baseline.begin_monotonic_ns;
    assert!(
        validate_capture_filter_source(
            &bytes,
            &key,
            &clock,
            &task,
            &changed,
            &baseline,
            &instructions,
            &hash
        )
        .is_err()
    );
}
#[test]
fn portable_v2_retains_operands_clock_thread_and_errno() {
    let bytes = capture();
    let parsed = parse_capture_v2(&bytes, &DiagnosticSha256::from_bytes([1; 32])).unwrap();
    assert_eq!(parsed.events()[0].task.tid, 10);
    assert_eq!(parsed.events()[0].task.tgid, 11);
    assert_eq!(parsed.events()[0].args[0], 1);
    assert_eq!(parsed.events()[0].syscall_result, 97);
    assert_eq!(parsed.events()[1].syscall_result, -97);
    assert_eq!(parsed.events()[1].syscall_occurrence, 23);
    assert_eq!(parsed.events()[1].monotonic_ns, 1001);
}
#[test]
fn loss_detach_sequence_and_occurrence_substitutions_reject() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    for (offset, value) in [
        (16, 1),
        (28, 1),
        (32, 10),
        (40, 2),
        (40 + 192 + 128, 24),
        (40 + 192 + 136, 2),
    ] {
        let mut bytes = capture();
        if offset == 28 || offset == 32 {
            put32(&mut bytes, offset, value as u32);
        } else {
            put64(&mut bytes, offset, value);
        }
        assert!(
            parse_capture_v2(&bytes, &key).is_err(),
            "mutation at {offset}"
        );
    }
    let mut bytes = capture();
    bytes.push(0);
    assert!(parse_capture_v2(&bytes, &key).is_err());
}
#[test]
fn explicit_unfiltered_lifecycle_is_not_a_seccomp_allow() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    let mut bytes = capture();
    put32(&mut bytes, 28, 7);
    put32(&mut bytes, 32, 12);
    let first = CAPTURE_HEADER_BYTES_V2;
    put32(&mut bytes, first + 80, 11);
    put32(&mut bytes, first + 76, 0);
    put64(&mut bytes, first + 56, 0);
    put64(&mut bytes, first + 48, 74);
    put64(&mut bytes, first + CAPTURE_RECORD_BYTES_V2 + 48, 74);
    put64(&mut bytes, first + CAPTURE_RECORD_BYTES_V2 + 56, 0);
    let parsed = parse_capture_v2(&bytes, &key).unwrap();
    assert_eq!(parsed.events()[0].kind, 11);
    assert_eq!(parsed.events()[0].seccomp_action, 0);
    assert_eq!(parsed.events()[1].syscall_result, 0);
    let mut legacy = bytes.clone();
    put32(&mut legacy, 28, 3);
    put32(&mut legacy, 32, 11);
    assert!(parse_capture_v2(&legacy, &key).is_err());
    for (offset, value) in [
        (first + 76, 0x7fff0000_u64),
        (first + 48, 999),
        (first + CAPTURE_RECORD_BYTES_V2 + 128, 24),
        (first + CAPTURE_RECORD_BYTES_V2 + 136, 5),
    ] {
        let mut invalid = bytes.clone();
        if offset == first + 76 {
            put32(&mut invalid, offset, value as u32);
        } else {
            put64(&mut invalid, offset, value);
        }
        assert!(parse_capture_v2(&invalid, &key).is_err());
    }
}

#[test]
fn physical_intervals_separate_same_logical_request_across_phases() {
    let id = IntervalIdV1 {
        session_nonce: [2; 32],
        generation: 0,
        logical_case_key: DiagnosticSha256::from_bytes([3; 32]),
        purpose: IntervalPurposeV1::Ordinary,
        ordinal: 0,
    };
    for variant in [
        IntervalIdV1 {
            ordinal: 1,
            ..id.clone()
        },
        IntervalIdV1 {
            generation: 1,
            ..id.clone()
        },
        IntervalIdV1 {
            purpose: IntervalPurposeV1::Recovery,
            ..id.clone()
        },
        IntervalIdV1 {
            session_nonce: [4; 32],
            ..id.clone()
        },
    ] {
        assert_ne!(id.storage_sha256(), variant.storage_sha256());
        assert_eq!(id.logical_case_key, variant.logical_case_key);
    }
}

fn checked_bind_capture(arch: u32, nr: u64) -> Vec<u8> {
    let mut bytes = capture();
    put32(&mut bytes, 28, 15);
    put32(&mut bytes, 32, 12);
    let first = CAPTURE_HEADER_BYTES_V2;
    for offset in [first, first + CAPTURE_RECORD_BYTES_V2] {
        put32(&mut bytes, offset + 72, arch);
        put64(&mut bytes, offset + 48, nr);
        put64(&mut bytes, offset + 136, 7);
        put64(&mut bytes, offset + 144, 4096);
        put64(&mut bytes, offset + 152, 16);
        put64(&mut bytes, offset + 56, 0);
    }
    put32(&mut bytes, first + 76, 0x7fff0000);
    put64(&mut bytes, first + 32, 2u64 << 32 | 16);
    put64(
        &mut bytes,
        first + 40,
        (u32::from_le_bytes([127, 0, 0, 1]) as u64) << 32 | 24567,
    );
    bytes
}

#[test]
fn checked_socket_operands_are_explicit_and_architecture_independent() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    for (arch, nr) in [(0xc000003e, 49), (0xc00000b7, 200)] {
        let bytes = checked_bind_capture(arch, nr);
        let parsed = parse_capture_v2(&bytes, &key).unwrap();
        let address = parsed.events()[0].network_address.as_ref().unwrap();
        assert_eq!(address.family, 2);
        assert_eq!(address.length, 16);
        assert_eq!(address.address, [127, 0, 0, 1]);
        assert_eq!(address.port, 24567);
        assert!(parsed.events()[1].network_address.is_none());
        let mut legacy = bytes.clone();
        put32(&mut legacy, 28, 7);
        assert!(
            parse_capture_v2(&legacy, &key).unwrap().events()[0]
                .network_address
                .is_none()
        );
        for (offset, value) in [
            (first_offset(32), 1u64 << 32 | 16),
            (first_offset(32), 2u64 << 32 | 15),
            (first_offset(40), 1u64 << 16),
            (first_offset(144), 0),
            (first_offset(152), 15),
        ] {
            let mut invalid = bytes.clone();
            put64(&mut invalid, offset, value);
            assert!(parse_capture_v2(&invalid, &key).is_err());
        }
        let mut unsupported_feature = bytes;
        put32(&mut unsupported_feature, 28, 11);
        assert!(parse_capture_v2(&unsupported_feature, &key).is_err());
    }
}

fn first_offset(field: usize) -> usize {
    CAPTURE_HEADER_BYTES_V2 + field
}
