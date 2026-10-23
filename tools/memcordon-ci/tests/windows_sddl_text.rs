#![cfg(not(windows))]
#![deny(unsafe_code)]

#[path = "../src/windows_sddl_text.rs"]
mod text;

#[test]
fn first_terminator_excludes_all_allocation_padding() {
    let expected = "O:SYD:P(A;;GA;;;SY)";
    let prefix = expected.encode_utf16().collect::<Vec<_>>();
    for padding in [vec![], vec![0; 8], vec![0xffff, 0xd800, 42]] {
        let mut allocation = prefix.clone();
        allocation.push(0);
        allocation.extend(padding);
        let mut reads = 0;
        let decoded = text::decode(allocation.len(), |index| {
            assert!(index <= prefix.len(), "allocation padding must not be read");
            reads += 1;
            allocation[index]
        })
        .unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(reads, prefix.len() + 1);
        assert!(!decoded.contains('\0'));
    }
}

#[test]
fn malformed_logical_text_or_missing_termination_is_rejected() {
    for units in [vec![0], vec![0xd800, 0], vec![0xdc00, 0], vec![65, 66]] {
        assert!(text::decode(units.len(), |index| units[index]).is_err());
    }
    let units = "D:(A;;GA;;;😀)"
        .encode_utf16()
        .chain([0])
        .collect::<Vec<_>>();
    assert_eq!(
        text::decode(units.len(), |index| units[index]).unwrap(),
        "D:(A;;GA;;;😀)"
    );
}

#[test]
fn physical_extent_and_logical_scan_budget_are_independent() {
    assert!(text::decode(0, |_| panic!("zero extent must not be read")).is_err());
    for extent in [text::MAX_CAPACITY + 1, usize::MAX] {
        let mut reads = 0;
        assert_eq!(
            text::decode(extent, |index| {
                reads += 1;
                match index {
                    0 => 65,
                    1 => 0,
                    _ => panic!("allocation padding must not be read"),
                }
            })
            .unwrap(),
            "A"
        );
        assert_eq!(reads, 2);
    }
    let mut units = vec![65; text::MAX_CAPACITY];
    *units.last_mut().unwrap() = 0;
    assert_eq!(
        text::decode(units.len(), |index| units[index])
            .unwrap()
            .len(),
        units.len() - 1
    );
}

#[test]
fn missing_terminator_never_reads_past_either_bound() {
    for extent in [3, text::MAX_CAPACITY, text::MAX_CAPACITY + 1, usize::MAX] {
        let mut reads = 0;
        assert!(
            text::decode(extent, |index| {
                assert!(index < extent.min(text::MAX_CAPACITY));
                reads += 1;
                65
            })
            .is_err()
        );
        assert_eq!(reads, extent.min(text::MAX_CAPACITY));
    }
}
