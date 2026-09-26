use memcordon_ci::private_candidate_replay::diagnostic_candidate_no_allocation_v1;
use memcordon_core::DiagnosticSha256;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn wire(kinds: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0; 40 + 192 * kinds.len()];
    put32(&mut bytes, 0, 0x4d434b31);
    put32(&mut bytes, 4, 2);
    put64(&mut bytes, 8, kinds.len() as u64);
    put32(&mut bytes, 24, 192);
    put32(&mut bytes, 28, 3);
    put32(&mut bytes, 32, 11);
    put32(&mut bytes, 36, 0x01020304);
    for (index, kind) in kinds.iter().enumerate() {
        let raw = &mut bytes[40 + 192 * index..40 + 192 * (index + 1)];
        put64(raw, 0, index as u64 + 1);
        put64(raw, 8, 1000 + index as u64);
        put64(raw, 16, 8);
        put64(raw, 24, 9);
        put32(raw, 64, 10);
        put32(raw, 184, 10);
        put64(raw, 120, 12);
        raw[84..116].copy_from_slice(&[1; 32]);
        put32(raw, 80, *kind);
        if *kind == 7 {
            put32(raw, 68, 11);
        }
        if *kind == 6 {
            put64(raw, 32, 1);
            put64(raw, 40, 2);
        }
    }
    bytes
}
#[test]
fn genuine_driver_exec_and_auxiliary_fork_before_request_are_not_target_allocation() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    assert!(diagnostic_candidate_no_allocation_v1(&wire(&[7, 6, 1, 2]), &key).is_ok());
}
#[test]
fn allocate_anywhere_and_exec_or_fork_in_actual_request_reject() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    for kinds in [
        vec![3, 1, 2],
        vec![1, 3, 2],
        vec![1, 2, 3],
        vec![1, 6, 2],
        vec![1, 7, 2],
        vec![1],
        vec![1, 1, 2],
    ] {
        assert!(
            diagnostic_candidate_no_allocation_v1(&wire(&kinds), &key).is_err(),
            "{kinds:?}"
        );
    }
    let mut bytes = wire(&[1, 2]);
    put32(&mut bytes, 40 + 192 + 64, 13);
    put32(&mut bytes, 40 + 192 + 184, 13);
    assert!(diagnostic_candidate_no_allocation_v1(&bytes, &key).is_err());
}
