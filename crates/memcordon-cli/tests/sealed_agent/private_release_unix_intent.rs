#![cfg(target_os = "linux")]

use crate::linux::private_release_unix_intent::{SELECTOR, expected_observation_bytes};

#[test]
fn abstract_and_pathname_intents_record_socket_denial_before_bind() {
    assert_eq!(
        SELECTOR,
        "private_tcp::af_unix_abstract_and_pathname_denied"
    );
    let challenge = [0x5a; 32];
    let bytes = expected_observation_bytes(&challenge).unwrap();
    let mut cursor = b"memcordon-private-unix-intent-v1\0".len() + challenge.len();
    assert_eq!(
        &bytes[..cursor],
        b"memcordon-private-unix-intent-v1\0"
            .iter()
            .copied()
            .chain(challenge)
            .collect::<Vec<_>>()
    );
    for kind in [1_u8, 2_u8] {
        assert_eq!(bytes[cursor], kind);
        cursor += 1;
        let length = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        let address = &bytes[cursor..cursor + length];
        cursor += length;
        if kind == 1 {
            assert_eq!(address.last(), Some(&0));
            assert!(address.starts_with(b"/tmp/"));
            assert!(
                address
                    .windows(b"-path".len())
                    .any(|bytes| bytes == b"-path")
            );
        } else {
            assert_eq!(address.first(), Some(&0));
            assert!(
                address
                    .windows(b"-abstract".len())
                    .any(|bytes| bytes == b"-abstract")
            );
        }
        assert_eq!(
            i32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()),
            libc::EAFNOSUPPORT
        );
        cursor += 4;
        assert_eq!(&bytes[cursor..cursor + 2], &[0, 0]);
        cursor += 2;
    }
    assert_eq!(cursor, bytes.len());
    assert_ne!(bytes, expected_observation_bytes(&[0x5b; 32]).unwrap());
    assert!(expected_observation_bytes(&[0; 32]).is_err());
}

#[test]
fn unix_intent_remains_outside_generic_candidate_dispatch() {
    assert!(!crate::linux::private_release_case::candidate_fixture_supported(SELECTOR));
    assert!(!crate::linux::private_release_case::candidate_executable_fixture_supported(SELECTOR));
    assert!(!crate::linux::private_release_case::candidate_physical_selector_supported(SELECTOR));
}
