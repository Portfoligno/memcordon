use memcordon_windows_loader_lab::holder_filtering_history::decode;

#[test]
fn history_boolean_ignores_poisoned_trailing_storage() {
    assert_eq!(decode(&[0, 0xff, 0xff, 0xff], 1).unwrap(), 0);
    assert_eq!(decode(&[1, 0xff, 0xff, 0xff], 1).unwrap(), 1);
    assert_eq!(decode(&[0xff, 0, 0, 0], 1).unwrap(), 0xff);
    assert_eq!(decode(&[0x80], 1).unwrap(), 0x80);
}

#[test]
fn history_boolean_rejects_other_extents_and_missing_payload() {
    for returned in [0, 2, 4, u32::MAX] {
        assert!(
            decode(&[0; 4], returned)
                .unwrap_err()
                .contains("invalid BOOLEAN extent")
        );
    }
    assert_eq!(decode(&[], 1).unwrap_err(), "BOOLEAN storage truncated");
}
