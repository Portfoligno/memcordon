use memcordon_core::product_fixture::dual_fixture_challenge;

#[test]
fn dual_fixture_challenge_is_distinct_bounded_and_byte_compatible() {
    assert!(dual_fixture_challenge(&[0; 32], 0).is_err());
    assert!(dual_fixture_challenge(&[1; 32], 2).is_err());
    let first = dual_fixture_challenge(&[1; 32], 0).unwrap();
    let second = dual_fixture_challenge(&[1; 32], 1).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        first,
        *memcordon_core::workload_codec::hash_bytes(&{
            let mut bytes = b"memcordon-final-public-dual-challenge-v1\0".to_vec();
            bytes.extend_from_slice(&[1; 32]);
            bytes.push(0);
            bytes
        })
        .bytes()
    );
}
