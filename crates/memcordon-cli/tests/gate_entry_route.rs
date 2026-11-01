#[path = "../src/bin/consumer_readiness_windows/gate_entry_route.rs"]
mod route;
use route::{DecodeError, decode};

#[test]
fn exact_x64_import_jump_uses_signed_next_instruction_displacement() {
    assert_eq!(
        decode(0x8664, 0x1000, &[0xff, 0x25, 0xfa, 0x0f, 0, 0]),
        Ok(0x2000)
    );
    assert_eq!(
        decode(0x8664, 0x2000, &[0xff, 0x25, 0xfa, 0xef, 0xff, 0xff]),
        Ok(0x1000)
    );
    for bytes in [
        &[0xe9, 0x25, 0, 0, 0, 0][..],
        &[0xff, 0x15, 0, 0, 0, 0],
        &[0xeb, 0, 0, 0, 0, 0],
    ] {
        assert_eq!(decode(0x8664, 0x1000, bytes), Err(DecodeError::Opcode));
    }
    assert_eq!(
        decode(0x8664, 0x1000, &[0xff, 0x25, 0, 0, 0]),
        Err(DecodeError::Truncated)
    );
    assert_eq!(
        decode(0x8664, u64::MAX - 5, &[0xff, 0x25, 0, 0, 0, 0]),
        Err(DecodeError::Overflow)
    );
    assert_eq!(
        decode(0x8664, 0, &[0xff, 0x25, 0, 0, 0, 0x80]),
        Err(DecodeError::Overflow)
    );
}

#[test]
fn exact_arm64_thunk_uses_architectural_page_and_scaled_load_offset() {
    // ADRP x16,+0x1000; LDR x16,[x16,#0x28]; BR x16.
    let forward = [
        0x10, 0, 0, 0xb0, 0x10, 0x16, 0x40, 0xf9, 0, 0x02, 0x1f, 0xd6,
    ];
    assert_eq!(decode(0xaa64, 0x1abc, &forward), Ok(0x2028));
    // ADRP x16,-0x1000 uses a sign-extended 21-bit page immediate.
    let backward = [
        0xf0, 0xff, 0xff, 0xf0, 0x10, 0x16, 0x40, 0xf9, 0, 0x02, 0x1f, 0xd6,
    ];
    assert_eq!(decode(0xaa64, 0x2abc, &backward), Ok(0x1028));
    assert_eq!(
        decode(0xaa64, 0x1abd, &forward),
        Err(DecodeError::Unaligned)
    );
    assert_eq!(
        decode(0xaa64, 0x1000, &forward[..11]),
        Err(DecodeError::Truncated)
    );
    assert_eq!(decode(0xaa64, 0, &backward), Err(DecodeError::Overflow));
    assert_eq!(
        decode(0xaa64, u64::MAX - 3, &forward),
        Err(DecodeError::Overflow)
    );
    for (index, mask) in [(0, 1), (4, 1), (8, 0x20), (3, 0x10), (7, 0x40)] {
        let mut wrong = forward;
        wrong[index] ^= mask;
        assert_eq!(decode(0xaa64, 0x1000, &wrong), Err(DecodeError::Opcode));
    }
    assert_eq!(decode(0x14c, 0x1000, &forward), Err(DecodeError::Machine));
}
