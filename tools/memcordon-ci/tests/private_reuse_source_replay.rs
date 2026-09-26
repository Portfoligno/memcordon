//! Real V2 wire shapes and independently measured object relationships only.
//! These diagnostics intentionally cannot construct an origin/Q capability.
use memcordon_ci::private_candidate_reuse_facts::*;
use memcordon_core::private_reuse_source_v1::*;
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
const HEADER: usize = 40;
const RECORD: usize = 192;
fn word(raw: &mut [u8], at: usize, value: u64) {
    raw[at..at + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
}
fn scalar(raw: &mut [u8], at: usize, value: u32) {
    raw[at..at + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}
struct Wire {
    records: Vec<Vec<u8>>,
    occurrence: u64,
}
impl Wire {
    fn push(
        &mut self,
        kind: u32,
        time: u64,
        nr: u64,
        role: u32,
        result: i64,
        args: [u64; 6],
        object: (u64, u64),
        occurrence: u64,
    ) {
        let mut raw = vec![0; RECORD];
        word(&mut raw, 0, self.records.len() as u64 + 1);
        word(&mut raw, 8, time);
        word(&mut raw, 16, 100);
        word(&mut raw, 24, 200);
        word(&mut raw, 32, object.0);
        word(&mut raw, 40, object.1);
        word(&mut raw, 48, nr);
        word(&mut raw, 56, result as u64);
        scalar(&mut raw, 64, 10);
        scalar(&mut raw, 68, role);
        scalar(&mut raw, 72, 0xc000003e);
        scalar(&mut raw, 80, kind);
        raw[84..116].copy_from_slice(&[1; 32]);
        word(&mut raw, 120, 300);
        word(&mut raw, 128, occurrence);
        scalar(&mut raw, 184, 10);
        for (index, value) in args.into_iter().enumerate() {
            word(&mut raw, 136 + index * size_of::<u64>(), value);
        }
        self.records.push(raw);
    }
    fn operation(
        &mut self,
        time: u64,
        role: u32,
        nr: u64,
        result: i64,
        args: [u64; 6],
        vfs: Option<[u64; 6]>,
    ) {
        self.occurrence += 1;
        let occurrence = self.occurrence;
        self.push(17, time, nr, role, 0, args, (8, 900), occurrence);
        let mut names = [0_u8; size_of::<[u64; 6]>()];
        let name = b"attempt.json.new";
        names[..name.len()].copy_from_slice(name);
        let second = b"attempt.json";
        if role == 3 {
            let at = names.len() / 2;
            names[at..at + second.len()].copy_from_slice(second);
        }
        let args_names = std::array::from_fn(|index| {
            u64::from_le_bytes(
                names[index * size_of::<u64>()..(index + 1) * size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            )
        });
        let lengths =
            (name.len() + 1) as i64 | ((if role == 3 { second.len() + 1 } else { 0 }) as i64) << 32;
        self.push(
            18,
            time + 1,
            nr,
            role,
            lengths,
            args_names,
            (8, 900),
            occurrence,
        );
        if let Some(vfs) = vfs {
            self.push(19, time + 2, nr, role, 0, vfs, (8, 900), occurrence);
        }
        self.push(5, time + 3, nr, role, result, args, (8, 900), occurrence);
    }
    fn sync(&mut self, time: u64, object: (u64, u64)) {
        self.occurrence += 1;
        let occurrence = self.occurrence;
        let args = [3, 0, 0, 0, 0, 0];
        self.push(11, time, 74, 0, 0, args, object, occurrence);
        self.push(5, time + 1, 74, 0, 0, args, object, occurrence);
    }
    fn bytes(self) -> Vec<u8> {
        let mut bytes = vec![0; HEADER];
        scalar(&mut bytes, 0, 0x4d434b31);
        scalar(&mut bytes, 4, 2);
        word(&mut bytes, 8, self.records.len() as u64);
        scalar(&mut bytes, 24, RECORD as u32);
        scalar(&mut bytes, 28, 79);
        scalar(&mut bytes, 32, 14);
        scalar(&mut bytes, 36, 0x01020304);
        for record in self.records {
            bytes.extend(record);
        }
        bytes
    }
}
fn object(inode: u64, bytes: &[u8]) -> ReuseSourceObjectV1 {
    ReuseSourceObjectV1 {
        device: 8,
        inode,
        uid: 0,
        mode: 0o100600,
        nlink: 1,
        size: bytes.len() as u64,
        bytes_sha256: hash_bytes(bytes),
    }
}
fn fixture(
    recover: bool,
) -> (
    Vec<u8>,
    ReuseSourceGateV1,
    ReuseSourceReportV1,
    ReuseHeldObjectsV1,
    ReuseAfterObjectsV1,
) {
    let phase = if recover {
        ReuseSourcePhaseV1::Recover
    } else {
        ReuseSourcePhaseV1::Blocked
    };
    let before = b"original canonical retiring wire".to_vec();
    let marker = b"owned marker wire".to_vec();
    let recovered = b"normal canonical retired wire".to_vec();
    let gate = ReuseSourceGateV1 {
        schema_version: 1,
        source_revision_sha256: reuse_source_revision_sha256(),
        phase,
        selector: REUSE_SELECTOR_V1.into(),
        parent_result_key: DiagnosticSha256::from_bytes([1; 32]),
        challenge: [2; 32],
        admission_sha256: hash_bytes(b"original admission"),
        helper: ReuseSourceProcessV1 {
            pid: 10,
            start_time_ticks: 1,
        },
        directory_device: 8,
        directory_inode: 900,
        marker: object(901, &marker),
        record: object(902, &before),
        observed_monotonic_ns: 10,
    };
    let report = ReuseSourceReportV1 {
        schema_version: 1,
        source_revision_sha256: reuse_source_revision_sha256(),
        phase,
        parent_result_key: gate.parent_result_key.clone(),
        helper: gate.helper.clone(),
        admission_sha256: gate.admission_sha256.clone(),
        gate_sha256: hash_bytes(&serde_json::to_vec(&gate).unwrap()),
        before_bytes: before.clone(),
        marker_bytes: marker.clone(),
        original_observer_bytes: b"original actual observer wire".to_vec(),
        retry_begin_monotonic_ns: 30,
        retry_end_monotonic_ns: 40,
        actual_reuse_error: "owned O_EXCL collision".into(),
        removed_monotonic_ns: recover.then_some(60),
        recovered_monotonic_ns: recover.then_some(100),
        after_bytes: recover.then(|| recovered.clone()),
    };
    let held = ReuseHeldObjectsV1 {
        schema_version: 1,
        directory_device: 8,
        directory_inode: 900,
        marker: gate.marker.clone(),
        record: gate.record.clone(),
        marker_bytes: marker,
        record_bytes: before.clone(),
        begin_monotonic_ns: 20,
        end_monotonic_ns: 25,
    };
    let after = ReuseAfterObjectsV1 {
        schema_version: 1,
        directory_device: 8,
        directory_inode: 900,
        old_marker_nlink: if recover { 0 } else { 1 },
        old_record_nlink: if recover { 0 } else { 1 },
        current_record: if recover {
            object(903, &recovered)
        } else {
            gate.record.clone()
        },
        current_bytes: if recover { recovered } else { before },
        observed_monotonic_ns: 110,
    };
    let mut wire = Wire {
        records: Vec::new(),
        occurrence: 0,
    };
    wire.push(1, 28, 0, 0, 0, [0; 6], (0, 0), 0);
    wire.operation(31, 1, 257, -17, [3, 0x1000, 0xc1, 0o600, 0, 0], None);
    if recover {
        wire.operation(
            45,
            2,
            263,
            0,
            [3, 0x1000, 0, 0, 0, 0],
            Some([8, 901, 0, 0, 0, 0]),
        );
        wire.sync(50, (8, 900));
        wire.sync(70, (8, 903));
        wire.operation(
            80,
            3,
            316,
            0,
            [3, 0x1000, 3, 0x2000, 0, 0],
            Some([8, 903, 8, 902, 8, 900]),
        );
        wire.sync(90, (8, 900));
    }
    wire.push(2, 105, 0, 0, 0, [0; 6], (0, 0), 0);
    (wire.bytes(), gate, report, held, after)
}
fn verify(
    input: &(
        Vec<u8>,
        ReuseSourceGateV1,
        ReuseSourceReportV1,
        ReuseHeldObjectsV1,
        ReuseAfterObjectsV1,
    ),
) -> bool {
    validate_reuse_capture_operands_v1(
        &input.0,
        &input.1.parent_result_key,
        &input.1,
        &input.2,
        &input.3,
        &input.4,
    )
    .is_ok()
}
#[test]
fn actual_blocked_and_recovered_operand_orders_are_distinct() {
    assert!(verify(&fixture(false)));
    assert!(verify(&fixture(true)));
}
#[test]
fn alias_substitution_or_claimed_removal_cannot_recover() {
    let mut wrong = fixture(true);
    wrong.4.current_record.inode = wrong.3.marker.inode;
    assert!(!verify(&wrong));
    let mut wrong = fixture(false);
    wrong.4.old_marker_nlink = 0;
    assert!(!verify(&wrong));
    let mut wrong = fixture(true);
    wrong.3.directory_inode += 1;
    assert!(!verify(&wrong));
}
#[test]
fn omitted_or_reordered_durability_never_passes() {
    let mut missing = fixture(true);
    let sync = missing.0[HEADER..]
        .chunks_exact(RECORD)
        .position(|raw| u32::from_le_bytes(raw[80..84].try_into().unwrap()) == 11)
        .unwrap();
    let at = HEADER + sync * RECORD;
    missing.0.drain(at..at + 2 * RECORD);
    let count = (missing.0.len() - HEADER) / RECORD;
    word(&mut missing.0, 8, count as u64);
    for (index, raw) in missing.0[HEADER..].chunks_exact_mut(RECORD).enumerate() {
        word(raw, 0, index as u64 + 1);
    }
    assert!(!verify(&missing));
    let mut wrong = fixture(true);
    wrong.2.removed_monotonic_ns = Some(49);
    assert!(!verify(&wrong));
    let mut wrong = fixture(true);
    wrong.2.recovered_monotonic_ns = Some(89);
    assert!(!verify(&wrong));
}
