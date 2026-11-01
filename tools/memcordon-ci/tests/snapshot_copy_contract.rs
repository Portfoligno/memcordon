use memcordon_ci::snapshot_copy_contract::{mutation_extent, mutation_gate, publication_event};

#[test]
fn publication_is_exact_and_overflow_or_removal_never_admits() {
    assert!(!publication_event(7, 7, 0x100, b"other", b"attempt").unwrap());
    assert!(publication_event(7, 7, 0x80, b"attempt", b"attempt").unwrap());
    for (watch, mask) in [
        (8, 0x100),
        (7, 0x4000),
        (7, 0x8000),
        (7, 0x200),
        (7, 0x40000100),
    ] {
        assert!(publication_event(7, watch, mask, b"attempt", b"attempt").is_err());
    }
    assert!(!publication_event(7, 7, 0, b"attempt", b"attempt").unwrap());
}

#[test]
fn abort_does_not_authorize_mutation_and_normal_phases_remain_exact() {
    assert!(!mutation_gate(*b"A\n", false).unwrap());
    assert!(!mutation_gate(*b"A\n", true).unwrap());
    assert!(mutation_gate(*b"W\n", false).unwrap());
    assert!(mutation_gate(*b"D\n", true).unwrap());
    assert!(mutation_gate(*b"D\n", false).is_err());
    assert!(mutation_gate(*b"W\n", true).is_err());
}

#[test]
fn entire_mutation_must_be_unread_and_within_original_extent() {
    assert!(mutation_extent(100, 100, 8, 108).is_ok());
    for tuple in [
        (101, 100, 8, 108),
        (100, 100, 9, 108),
        (0, u64::MAX, 1, u64::MAX),
    ] {
        assert!(mutation_extent(tuple.0, tuple.1, tuple.2, tuple.3).is_err());
    }
}
