use memcordon_core::{
    MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES, WINDOWS_RESPONSE_PREFIX_BYTES, WindowsProviderResponseV1,
    WindowsQualificationRejectionV1, WindowsResponseFrame,
};

#[test]
fn qualification_refusal_is_bounded_and_bound_to_the_request() {
    let challenge = "12".repeat(32);
    let detail = "stage=caller-authentication: access denied";
    let refusal = WindowsQualificationRejectionV1::new(&challenge, detail).unwrap();
    assert!(refusal.matches_challenge(&challenge));
    assert!(!refusal.matches_challenge(&"34".repeat(32)));
    assert!(!refusal.matches_challenge("invalid"));
    assert_eq!(refusal.detail.as_str(), detail);
    assert!(!refusal.detail_truncated);
    let response = WindowsProviderResponseV1::QualificationRejected(refusal.clone());
    let bytes = serde_json::to_vec(&response).unwrap();
    assert_eq!(
        WindowsProviderResponseV1::frame_limit(
            &bytes[..bytes.len().min(WINDOWS_RESPONSE_PREFIX_BYTES)]
        )
        .unwrap(),
        MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES
    );
    let decoded: WindowsProviderResponseV1 = serde_json::from_slice(&bytes).unwrap();
    let WindowsProviderResponseV1::QualificationRejected(decoded) = decoded else {
        panic!("diagnostic refusal must not decode as admission authority");
    };
    assert_eq!(decoded, refusal);
    let mut wrong_schema = refusal;
    wrong_schema.schema_version += 1;
    assert!(!wrong_schema.matches_challenge(&challenge));
    assert!(WindowsQualificationRejectionV1::new("invalid", detail).is_err());
}

#[test]
fn qualification_refusal_caps_utf8_and_escape_expansion_and_rejects_invalid_wire() {
    let challenge = "12".repeat(32);
    for detail in [
        "é".repeat(WindowsQualificationRejectionV1::MAX_DETAIL_BYTES),
        "\u{1}".repeat(WindowsQualificationRejectionV1::MAX_DETAIL_BYTES + 1),
    ] {
        let refusal = WindowsQualificationRejectionV1::new(&challenge, &detail).unwrap();
        assert!(refusal.detail_truncated);
        assert!(refusal.detail.as_str().len() <= WindowsQualificationRejectionV1::MAX_DETAIL_BYTES);
        assert!(detail.starts_with(refusal.detail.as_str()));
        let response = WindowsProviderResponseV1::QualificationRejected(refusal);
        let bytes = serde_json::to_vec(&response).unwrap();
        assert!(bytes.len() < MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES);
        assert!(serde_json::from_slice::<WindowsProviderResponseV1>(&bytes).is_ok());
    }
    let refusal = WindowsQualificationRejectionV1::new(&challenge, "denied").unwrap();
    let mut invalid = serde_json::to_value(&refusal).unwrap();
    invalid["detail"] = "x"
        .repeat(WindowsQualificationRejectionV1::MAX_DETAIL_BYTES + 1)
        .into();
    assert!(serde_json::from_value::<WindowsQualificationRejectionV1>(invalid).is_err());
    let mut invalid = serde_json::to_value(&refusal).unwrap();
    invalid["challenge"] = "invalid".into();
    assert!(serde_json::from_value::<WindowsQualificationRejectionV1>(invalid).is_err());
    let mut invalid = serde_json::to_value(&refusal).unwrap();
    invalid["ready"] = true.into();
    assert!(serde_json::from_value::<WindowsQualificationRejectionV1>(invalid).is_err());
}
