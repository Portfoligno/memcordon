mod library;

#[test]
fn all_bytes_and_empty() {
    let bytes = library::byte_vector();
    assert_eq!(bytes.len(), 256);
    for (position, value) in bytes.into_iter().enumerate() {
        assert_eq!(position, usize::from(value));
    }
    assert!(Vec::<u8>::new().is_empty());
}
