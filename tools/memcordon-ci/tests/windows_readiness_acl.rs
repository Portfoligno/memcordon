#[path = "../src/windows_readiness_acl.rs"]
mod windows_readiness_acl;

use windows_readiness_acl::verify_file_dacl;

fn acl(entries: &[(u8, u8, u32, u32)], padding: usize) -> Vec<u8> {
    let size = 8 + entries.len() * 20 + padding;
    let mut bytes = vec![2, 0];
    bytes.extend(u16::try_from(size).unwrap().to_le_bytes());
    bytes.extend(u16::try_from(entries.len()).unwrap().to_le_bytes());
    bytes.extend([0, 0]);
    for &(kind, flags, mask, rid) in entries {
        bytes.extend([kind, flags, 20, 0]);
        bytes.extend(mask.to_le_bytes());
        bytes.extend([1, 1, 0, 0, 0, 0, 0, 5]);
        bytes.extend(rid.to_le_bytes());
    }
    bytes.resize(size, 0xa5);
    bytes
}

fn policy() -> Vec<(u8, u8, u32, u32)> {
    vec![
        (1, 3, 0x4000_0000, 12),   // Restricted Code denied file writes.
        (0, 3, 0x1000_0000, 1001), // Original caller.
        (0, 3, 0xa000_0000, 12),   // Restricted Code read/execute only.
        (0, 3, 0x1000_0000, 18),   // Local System.
    ]
}

fn mapped(mask: u32) -> u32 {
    match mask {
        0x4000_0000 => 0x0012_0116,
        0x1000_0000 => 0x001f_01ff,
        0xa000_0000 => 0x0012_00a9,
        _ => unreachable!(),
    }
}

#[test]
fn file_generic_mapping_and_allocation_padding_preserve_exact_authority() {
    let expected = policy();
    let actual: Vec<_> = expected
        .iter()
        .map(|&(kind, flags, mask, rid)| (kind, flags, mapped(mask), rid))
        .collect();
    verify_file_dacl(&acl(&expected, 0), &acl(&actual, 28), true).unwrap();
}

#[test]
fn split_effective_and_inheritance_aces_preserve_both_ordered_sequences() {
    let expected = policy();
    let actual: Vec<_> = expected
        .iter()
        .flat_map(|&(kind, _, mask, rid)| [(kind, 0, mapped(mask), rid), (kind, 0x0b, mask, rid)])
        .collect();
    verify_file_dacl(&acl(&expected, 0), &acl(&actual, 0), true).unwrap();
}

#[test]
fn changed_principals_rights_order_inheritance_and_extra_entries_are_refused() {
    let expected = policy();
    let expected_bytes = acl(&expected, 0);
    for mutation in [
        "caller",
        "restricted",
        "system",
        "write",
        "deny",
        "order",
        "inheritance",
        "propagation",
        "extra",
        "missing",
    ] {
        let mut actual = expected.clone();
        match mutation {
            "caller" => actual[1].3 += 1,
            "restricted" => actual[2].3 += 1,
            "system" => actual[3].3 += 1,
            "write" => actual[2].2 |= 0x4000_0000,
            "deny" => actual[0].0 = 0,
            "order" => actual.swap(0, 2),
            "inheritance" => actual[1].1 = 0,
            "propagation" => actual[1].1 |= 4,
            "extra" => actual.push(actual[1]),
            "missing" => {
                actual.pop();
            }
            _ => unreachable!(),
        }
        assert!(
            verify_file_dacl(&expected_bytes, &acl(&actual, 0), true).is_err(),
            "accepted {mutation}"
        );
    }
    assert!(verify_file_dacl(&expected_bytes, &expected_bytes, false).is_err());
}

#[test]
fn malformed_or_unknown_aces_never_become_equivalent_authority() {
    let expected = acl(&policy(), 0);
    for mutation in [
        "truncated",
        "size",
        "count",
        "kind",
        "ace-size",
        "sid",
        "inert",
        "flags",
    ] {
        let mut actual = expected.clone();
        match mutation {
            "truncated" => actual.truncate(7),
            "size" => actual[2..4].copy_from_slice(&u16::MAX.to_le_bytes()),
            "count" => actual[4..6].copy_from_slice(&u16::MAX.to_le_bytes()),
            "kind" => actual[8] = 2,
            "ace-size" => actual[10..12].copy_from_slice(&u16::MAX.to_le_bytes()),
            "sid" => actual[17] = 15,
            "inert" => actual[9] = 8,
            "flags" => actual[9] |= 0x40,
            _ => unreachable!(),
        }
        assert!(
            verify_file_dacl(&expected, &actual, true).is_err(),
            "accepted {mutation}"
        );
    }
}
