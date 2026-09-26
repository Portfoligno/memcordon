pub use memcordon_ci::{CiError, Result};
#[path = "../src/private_kernel_replay.rs"]
mod private_kernel_replay;
use memcordon_core::DiagnosticSha256;
use private_kernel_replay::{CAPTURE_HEADER_BYTES_V2, CAPTURE_RECORD_BYTES_V2, parse_capture_v2};

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
}
fn source(kind: u32, nr: u64, returned: i64) -> Vec<u8> {
    let kinds: &[u32] = if kind == 1 {
        &[17, 18, 5]
    } else {
        &[17, 18, 19, 5]
    };
    let mut bytes = vec![0; CAPTURE_HEADER_BYTES_V2];
    put32(&mut bytes, 0, 0x4d434b31);
    put32(&mut bytes, 4, 2);
    put64(&mut bytes, 8, kinds.len() as u64);
    put32(&mut bytes, 24, CAPTURE_RECORD_BYTES_V2 as u32);
    put32(&mut bytes, 28, 79);
    put32(&mut bytes, 32, 14);
    put32(&mut bytes, 36, 0x01020304);
    for (index, record_kind) in kinds.iter().enumerate() {
        let mut raw = vec![0; CAPTURE_RECORD_BYTES_V2];
        put64(&mut raw, 0, index as u64 + 1);
        put64(&mut raw, 8, 1_000 + index as u64);
        put64(&mut raw, 16, 100);
        put64(&mut raw, 24, 200);
        put64(&mut raw, 32, 8);
        put64(&mut raw, 40, 900);
        put64(&mut raw, 48, nr);
        put32(&mut raw, 64, 10);
        put32(&mut raw, 68, kind);
        put32(&mut raw, 72, 0xc000003e);
        put32(&mut raw, 80, *record_kind);
        raw[84..116].copy_from_slice(&[1; 32]);
        put64(&mut raw, 120, 300);
        put64(&mut raw, 128, 1);
        put64(&mut raw, 136, 3);
        put64(&mut raw, 144, 0x1000);
        put32(&mut raw, 184, 10);
        if *record_kind == 18 {
            raw[136..184].fill(0);
            let first = b"attempt.json.new";
            raw[136..136 + first.len()].copy_from_slice(first);
            let second = b"attempt.json";
            if kind == 3 {
                let second_offset = 136 + size_of::<[u64; 6]>() / 2;
                raw[second_offset..second_offset + second.len()].copy_from_slice(second);
            }
            let lengths = (first.len() + 1) as u64
                | ((if kind == 3 { second.len() + 1 } else { 0 }) as u64) << 32;
            put64(&mut raw, 56, lengths);
        } else if *record_kind == 19 {
            raw[136..184].fill(0);
            put64(&mut raw, 136, 8);
            put64(&mut raw, 144, 901);
            if kind == 3 {
                put64(&mut raw, 152, 8);
                put64(&mut raw, 160, 902);
                put64(&mut raw, 168, 8);
                put64(&mut raw, 176, 900);
            }
        } else if *record_kind == 5 {
            put64(&mut raw, 56, returned as u64);
        }
        bytes.extend_from_slice(&raw);
    }
    bytes
}
fn parse(bytes: &[u8]) -> Result<()> {
    parse_capture_v2(bytes, &DiagnosticSha256::from_bytes([1; 32])).map(|_| ())
}
#[test]
fn actual_native_open_conflict_unlink_and_rename_shapes_are_explicit() {
    for bytes in [source(1, 257, -17), source(2, 263, 0), source(3, 316, 0)] {
        parse(&bytes).unwrap();
    }
}
#[test]
fn owned_basename_and_kernel_parent_alias_cannot_be_remapped() {
    let mut wrong_name = source(2, 263, 0);
    wrong_name[CAPTURE_HEADER_BYTES_V2 + CAPTURE_RECORD_BYTES_V2 + 136] = b'x';
    assert!(parse(&wrong_name).is_err());
    let mut wrong_parent = source(3, 316, 0);
    put64(
        &mut wrong_parent,
        CAPTURE_HEADER_BYTES_V2 + 2 * CAPTURE_RECORD_BYTES_V2 + 176,
        901,
    );
    assert!(parse(&wrong_parent).is_err());
}
#[test]
fn successful_delete_requires_vfs_object_and_exact_return_pair() {
    let mut missing = source(2, 263, 0);
    let offset = CAPTURE_HEADER_BYTES_V2 + 2 * CAPTURE_RECORD_BYTES_V2;
    missing.drain(offset..offset + CAPTURE_RECORD_BYTES_V2);
    put64(&mut missing, 8, 3);
    put64(&mut missing, offset, 3);
    assert!(parse(&missing).is_err());
    let mut wrong_return = source(3, 316, 0);
    put64(
        &mut wrong_return,
        CAPTURE_HEADER_BYTES_V2 + 3 * CAPTURE_RECORD_BYTES_V2 + 144,
        0x2000,
    );
    assert!(parse(&wrong_return).is_err());
    let mut no_opt_in = source(1, 257, -17);
    put32(&mut no_opt_in, 28, 15);
    put32(&mut no_opt_in, 32, 12);
    assert!(parse(&no_opt_in).is_err());
}
