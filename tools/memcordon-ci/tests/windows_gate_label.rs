#[path = "../src/windows_gate_label.rs"]
mod label;
#[path = "../src/windows_gate_security.rs"]
mod security;

fn descriptor() -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&0x8010u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0]);
    bytes.extend_from_slice(&[
        0x11, 0, 20, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 16, 0, 32, 0, 0,
    ]);
    bytes
}

#[test]
fn explicit_label_preserves_native_mask_sid_and_separate_descriptor() {
    let bytes = descriptor();
    let parsed = label::parse(&bytes).unwrap();
    let ace = parsed.label.unwrap();
    assert_eq!(
        (
            parsed.information,
            ace.mask,
            ace.flags,
            ace.identifier_authority
        ),
        (16, 1, 0, 16)
    );
    assert_eq!(ace.subauthorities, [8192]);
    assert_eq!(parsed.descriptor_bytes_hex, hex::encode(&bytes));
    let mut dacl = vec![0; 20];
    dacl[0] = 1;
    dacl[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
    let original = security::parse(&dacl).unwrap().descriptor_sha256;
    label::parse(&bytes).unwrap();
    assert_eq!(security::parse(&dacl).unwrap().descriptor_sha256, original);
}

#[test]
fn absent_null_empty_are_explicitly_not_a_default_label_conclusion() {
    let mut bytes = descriptor();
    bytes.truncate(20);
    bytes[12..16].fill(0);
    let null = label::parse(&bytes).unwrap();
    assert!(null.sacl_null && null.label.is_none());
    bytes[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
    assert!(!label::parse(&bytes).unwrap().sacl_present);
    bytes = descriptor();
    bytes[24..26].fill(0);
    assert!(label::parse(&bytes).unwrap().label.is_none());
}

#[test]
fn malformed_label_extents_and_unsupported_aces_refuse() {
    let valid = descriptor();
    for length in 0..valid.len() {
        assert!(label::parse(&valid[..length]).is_err());
    }
    for (offset, value) in [
        (0, 2),
        (2, 0),
        (12, 21),
        (24, 2),
        (28, 0),
        (30, 16),
        (36, 2),
        (37, 15),
        (43, 5),
    ] {
        let mut bytes = valid.clone();
        bytes[offset] = value;
        assert!(label::parse(&bytes).is_err(), "offset {offset}");
    }
    let mut huge = valid;
    huge.resize(label::BYTE_BOUND + 1, 0);
    assert!(label::parse(&huge).is_err());
}
