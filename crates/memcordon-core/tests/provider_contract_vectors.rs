use memcordon_core::sealed_provider::protocol::{Frame, MessageKind, read_frame, write_frame};

#[test]
fn provider_pairing_requires_exact_versions_and_preserves_failure_context() {
    use memcordon_core::sealed_provider::inspection::validate_exact_provider_pairing;
    assert!(validate_exact_provider_pairing("1.2.3-dev", "1.2.3-dev", "cli", "provider").is_ok());
    let error =
        validate_exact_provider_pairing("1.2.3-dev", "1.2.3", "cli", "provider").unwrap_err();
    assert_eq!(
        error,
        "sealed provider version mismatch before target authorization: cli version 1.2.3-dev; provider version 1.2.3; install the matching memcordon package version and rerun package upgrade"
    );
}

#[test]
fn probe_v3_wire_bytes_match_the_reviewed_vector() {
    // V3, Probe, total length 72, zero nonce and attempt, SHA-256(empty).
    // This expected wire image does not call any production encoder to construct it.
    let mut expected = vec![0, 3, 0, 1, 0, 0, 0, 72];
    expected.extend_from_slice(&[0; 16]);
    expected.extend_from_slice(&[0; 16]);
    expected.extend_from_slice(&[
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ]);
    let frame = Frame {
        kind: MessageKind::Probe,
        nonce: [0; 16],
        attempt_id: [0; 16],
        payload: Vec::new(),
    };
    let mut encoded = Vec::new();
    write_frame(&mut encoded, &frame).unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(read_frame(&mut expected.as_slice()).unwrap(), frame);
}
