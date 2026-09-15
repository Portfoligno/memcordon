#![cfg(all(target_os = "macos", feature = "test-support"))]

use memcordon_platform::test_support::{
    macos_protocol_decode_fixture as decode, macos_protocol_encode_fixture as encode,
};

fn wire(frame: &[u8]) -> Vec<u8> {
    let mut bytes = u16::try_from(frame.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(frame);
    bytes
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../spec/vectors/macos-launch-v2.json")).unwrap()
}

#[test]
fn every_reviewed_message_preserves_exact_version_two_wire_bytes() {
    let vectors = vectors();
    assert_eq!(vectors["wire_version"], 2);
    let mut names = std::collections::BTreeSet::new();
    for category in ["production", "test_support"] {
        for case in vectors[category].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            assert!(names.insert(name));
            let message = case["message"].as_str().unwrap();
            let frame = case["frame"].as_str().unwrap();
            let expected = wire(frame.as_bytes());
            assert_eq!(
                encode(message.as_bytes(), 7, 0).unwrap(),
                expected,
                "{name}"
            );
            assert_eq!(decode(&expected, 7, 0).unwrap(), [message], "{name}");
            let mut extended: serde_json::Value = serde_json::from_str(frame).unwrap();
            extended["message"]["undeclared_authority"] = true.into();
            assert!(
                decode(&wire(&serde_json::to_vec(&extended).unwrap()), 7, 0).is_err(),
                "unknown field accepted by {name}"
            );
        }
    }
}

#[test]
fn transcript_sequence_binding_and_failure_shapes_are_preserved() {
    let first = br#"{"version":2,"run":7,"sequence":0,"message":{"kind":"Hello"}}"#;
    let second = br#"{"version":2,"run":7,"sequence":1,"message":{"kind":"Ready"}}"#;
    let mut transcript = wire(first);
    transcript.extend(wire(second));
    assert_eq!(
        decode(&transcript, 7, 0).unwrap(),
        [r#"{"kind":"Hello"}"#, r#"{"kind":"Ready"}"#]
    );
    assert!(
        decode(&transcript, 8, 0)
            .unwrap_err()
            .to_string()
            .contains("binding or sequence mismatch")
    );
    assert!(decode(&transcript, 7, 1).is_err());
    let mut replay = wire(first);
    replay.extend(wire(first));
    assert!(decode(&replay, 7, 0).is_err());
    for malformed in [
        br#"{"version":1,"run":7,"sequence":0,"message":{"kind":"Ready"}}"#.as_slice(),
        br#"{"version":2,"run":7,"sequence":0,"extra":true,"message":{"kind":"Ready"}}"#,
        br#"{"version":2,"run":7,"sequence":0,"message":{"kind":"Ready","extra":true}}"#,
        br#"{"version":2,"run":7,"sequence":0,"message":{"kind":"Unknown"}}"#,
        br#"{"version":2,"run":7,"sequence":0,"message":{"kind":"Status","raw":0}}"#,
    ] {
        assert!(
            decode(&wire(malformed), 7, 0).is_err(),
            "accepted malformed frame: {}",
            String::from_utf8_lossy(malformed)
        );
    }
    let valid = wire(first);
    for end in 1..valid.len() {
        assert_eq!(
            decode(&valid[..end], 7, 0).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof,
            "prefix {end}"
        );
    }
    assert!(decode(&[], 7, 0).unwrap().is_empty());
    assert!(decode(&0_u16.to_be_bytes(), 7, 0).is_err());
    assert!(decode(&u16::MAX.to_be_bytes(), 7, 0).is_err());
    assert!(encode(br#"{"kind":"Ready"}"#, 7, u64::MAX).is_err());
}

#[test]
fn strict_message_keys_preserve_optional_omission_and_reject_duplicate_typed_fields() {
    let omitted =
        br#"{"version":2,"run":7,"sequence":0,"message":{"kind":"Status","reaped":false}}"#;
    assert_eq!(
        decode(&wire(omitted), 7, 0).unwrap(),
        [r#"{"kind":"Status","raw":null,"reaped":false}"#]
    );
    let duplicate = br#"{"version":2,"run":7,"sequence":0,"message":{"kind":"Status","raw":0,"reaped":true,"reaped":false}}"#;
    assert!(decode(&wire(duplicate), 7, 0).is_err());
}
