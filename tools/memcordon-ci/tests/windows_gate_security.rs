#[path = "../src/windows_gate_security.rs"]
mod gate;

fn descriptor() -> Vec<u8> {
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut bytes = vec![0; 32];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&0x9004_u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&20_u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&20_u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&32_u32.to_le_bytes());
    bytes[20..].copy_from_slice(&sid);
    let mut acl = vec![2, 0, 0, 0, 3, 0, 0, 0];
    for mask in [0x1000_0000_u32, 0x1000_0000, 0x0010_0000] {
        let mut ace = vec![0, 0, 0, 0];
        ace.extend_from_slice(&mask.to_le_bytes());
        ace.extend_from_slice(&sid);
        let length = ace.len() as u16;
        ace[2..4].copy_from_slice(&length.to_le_bytes());
        acl.extend_from_slice(&ace);
    }
    // Native ACL capacity may exceed its used ACE prefix.
    acl.extend_from_slice(&[0; 4]);
    let length = acl.len() as u16;
    acl[2..4].copy_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&acl);
    bytes
}

#[test]
fn actual_descriptor_extent_owner_and_every_ace_are_preserved_without_claiming_access() {
    let bytes = descriptor();
    let snapshot = gate::parse(&bytes).unwrap();
    assert_eq!(snapshot.descriptor_bytes_hex, hex::encode(&bytes));
    assert_eq!(snapshot.owner_sid_hex, snapshot.group_sid_hex);
    assert_eq!(
        snapshot.owner_sid_hex.as_deref(),
        Some("010100000000000512000000")
    );
    assert_eq!(snapshot.declared_ace_count, Some(3));
    assert_eq!(snapshot.unused_acl_bytes, Some(4));
    assert!(snapshot.dacl_present && !snapshot.dacl_null);
    assert_eq!(
        snapshot
            .aces
            .iter()
            .map(|ace| ace.raw_u32_at_offset_four)
            .collect::<Vec<_>>(),
        [Some(0x1000_0000), Some(0x1000_0000), Some(0x0010_0000)]
    );
    assert!(
        snapshot
            .aces
            .iter()
            .all(|ace| ace.native_type == 0 && ace.flags == 0)
    );
    assert!(serde_json::to_vec(&snapshot).unwrap().len() < gate::BYTE_BOUND);
}

#[test]
fn absent_null_and_empty_dacl_remain_distinct_native_facts() {
    let mut bytes = descriptor();
    bytes[16..20].fill(0);
    let null = gate::parse(&bytes).unwrap();
    assert!(null.dacl_present && null.dacl_null && null.aces.is_empty());
    bytes[2..4].copy_from_slice(&0x9000_u16.to_le_bytes());
    let absent = gate::parse(&bytes).unwrap();
    assert!(!absent.dacl_present && !absent.dacl_null && absent.aces.is_empty());
    bytes[2..4].copy_from_slice(&0x9004_u16.to_le_bytes());
    bytes[16..20].copy_from_slice(&32_u32.to_le_bytes());
    bytes[36..38].fill(0);
    let empty = gate::parse(&bytes).unwrap();
    assert!(empty.dacl_present && !empty.dacl_null);
    assert_eq!(empty.declared_ace_count, Some(0));
}

#[test]
fn truncated_unbounded_or_inconsistent_native_extents_are_refused_explicitly() {
    let valid = descriptor();
    for end in 0..valid.len() {
        assert!(gate::parse(&valid[..end]).is_err());
    }
    for change in [
        |bytes: &mut Vec<u8>| bytes[0] = 2,
        |bytes: &mut Vec<u8>| bytes[2..4].fill(0),
        |bytes: &mut Vec<u8>| bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes()),
        |bytes: &mut Vec<u8>| bytes[21] = 16,
        |bytes: &mut Vec<u8>| bytes[34..36].copy_from_slice(&u16::MAX.to_le_bytes()),
        |bytes: &mut Vec<u8>| bytes[36..38].copy_from_slice(&65_u16.to_le_bytes()),
        |bytes: &mut Vec<u8>| bytes[42..44].copy_from_slice(&u16::MAX.to_le_bytes()),
        |bytes: &mut Vec<u8>| bytes.resize(gate::BYTE_BOUND + 1, 0),
    ] {
        let mut changed = valid.clone();
        change(&mut changed);
        assert!(gate::parse(&changed).is_err());
    }
}
