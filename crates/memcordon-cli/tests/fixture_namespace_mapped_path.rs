#[path = "private/fixture_namespace_mapped_path.rs"]
mod mapped;
use mapped::*;
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

#[test]
fn query_requires_actual_terminator_and_complete_utf16_before_acceptance() {
    let path = wide("\\Device\\DiskOne\\Windows\\System32\\kernelbase.dll");
    let mut buffer = vec![0xffff; INITIAL_CAPACITY];
    buffer[..path.len()].copy_from_slice(&path);
    buffer[path.len()] = 0;
    assert_eq!(
        query(&buffer, path.len()).unwrap(),
        Query::Complete(path.clone())
    );
    assert!(query(&buffer, 0).is_err());
    buffer[path.len()] = 0xffff;
    assert!(query(&buffer, path.len()).is_err());
    buffer[path.len()] = 0;
    buffer[2] = 0;
    assert!(query(&buffer, path.len()).is_err());
    buffer[2] = 0xd800;
    assert!(query(&buffer, path.len()).is_err());
}

#[test]
fn truncation_grows_by_capacity_only_and_stops_at_existing_limit() {
    let mut capacity = INITIAL_CAPACITY;
    while capacity < PATH_LIMIT {
        let buffer = vec![0xffff; capacity];
        assert_eq!(query(&buffer, capacity).unwrap(), Query::Grow(capacity * 2));
        assert_eq!(
            query(&buffer, capacity + 1).unwrap(),
            Query::Grow(capacity * 2)
        );
        capacity *= 2;
    }
    assert!(query(&vec![0xffff; PATH_LIMIT], PATH_LIMIT).is_err());
    assert!(query(&vec![0; PATH_LIMIT + 1], 1).is_err());
    assert!(query(&[0; 8], 1).is_err());
    assert!(query(&vec![0; 257], 1).is_err());
}

#[test]
fn strict_device_components_do_not_normalize_untrusted_names() {
    let path = wide("\\Device\\DiskOne\\Windows\\System32\\kernelbase.dll");
    let (parent, leaf) = nt_parts(&path).unwrap();
    assert_eq!(parent, wide("\\Device\\DiskOne\\Windows\\System32"));
    assert_eq!(leaf, wide(PROFILE_LEAF));
    for invalid in [
        "",
        "C:\\Windows\\System32\\kernelbase.dll",
        "\\??\\C:\\Windows\\System32\\kernelbase.dll",
        "\\\\server\\share\\kernelbase.dll",
        "\\GLOBALROOT\\Device\\DiskOne\\kernelbase.dll",
        "\\Device\\",
        "\\Device\\DiskOne",
        "\\Device\\DiskOne\\",
        "\\Device\\DiskOne\\\\kernelbase.dll",
        "\\Device\\DiskOne\\.\\kernelbase.dll",
        "\\Device\\DiskOne\\..\\kernelbase.dll",
        "\\Device\\DiskOne\\root/leaf",
        "\\Device\\DiskOne\\leaf:stream",
        "\\Device\\DiskOne\\leaf\0suffix",
    ] {
        assert!(nt_parts(&wide(invalid)).is_err(), "{invalid:?}");
    }
    assert!(nt_parts(&[0xd800]).is_err());
}

#[test]
fn only_full_ordinal_parent_leaf_and_final_path_matches_bind() {
    let root = wide("\\Device\\DiskOne\\Windows\\System32");
    let observed = wide("\\Device\\DiskOne\\Windows\\System32\\KERNELBASE.DLL");
    // Case equivalence is supplied by Windows, not approximated in this helper.
    assert!(bind(&observed, &root, 2, 2).unwrap());
    for (parent, leaf) in [(1, 2), (3, 2), (2, 1), (2, 3)] {
        assert!(!bind(&observed, &root, parent, leaf).unwrap());
    }
    for (parent, leaf) in [(0, 2), (2, 0), (-1, 2), (2, 4)] {
        assert!(bind(&observed, &root, parent, leaf).is_err());
    }
    for different in [
        "\\Device\\DiskOne\\Windows\\System32-other\\kernelbase.dll",
        "\\Device\\DiskTwo\\Windows\\System32\\kernelbase.dll",
        "\\Device\\Mup\\server\\share\\kernelbase.dll",
    ] {
        assert!(!bind(&wide(different), &root, 1, 2).unwrap());
    }
    assert!(
        !bind(
            &wide("\\Device\\DiskOne\\Windows\\System32\\other.dll"),
            &root,
            2,
            1
        )
        .unwrap()
    );
    assert!(same_path(&observed, &observed, 2).unwrap());
    assert!(
        !same_path(
            &observed,
            &wide("\\Device\\DiskTwo\\Windows\\System32\\kernelbase.dll"),
            1
        )
        .unwrap()
    );
    assert!(same_path(&observed, &observed, 0).is_err());
    assert!(bind(&observed, &wide("C:\\Windows\\System32"), 2, 2).is_err());
}
