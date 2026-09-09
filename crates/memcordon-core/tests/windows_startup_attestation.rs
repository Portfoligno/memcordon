use memcordon_core::{
    WINDOWS_MAX_FRAME_BYTES, WINDOWS_PRIVATE_PROTOCOL_VERSION, WINDOWS_RESPONSE_PREFIX_BYTES,
    WindowsLauncherRequestV1, WindowsLauncherResponseV1, WindowsProcessIdentityV1,
    WindowsProviderRequestV1, WindowsProviderResponseV1, WindowsResponseFrame,
    WindowsServiceSelfAttestationV1,
};

fn attestation() -> WindowsServiceSelfAttestationV1 {
    WindowsServiceSelfAttestationV1 {
        schema_version: 1,
        challenge: "12".repeat(32),
        service_name: "MemCordonSealedLauncher".into(),
        process_identity: WindowsProcessIdentityV1 {
            process_id: 41,
            creation_time_100ns: 73,
        },
        service_sid: "S-1-5-80-1-2-3-4-5".into(),
        service_sid_enabled: true,
        service_sid_restricted: true,
        token_session_id: 0,
        required_privileges: vec![
            "SeAssignPrimaryTokenPrivilege".into(),
            "SeIncreaseQuotaPrivilege".into(),
            "SeTcbPrivilege".into(),
        ],
    }
}

#[test]
fn startup_attestation_is_private_and_does_not_supply_public_binding() {
    let expected = attestation();
    let request = WindowsLauncherRequestV1::StartupAttestation {
        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        challenge: expected.challenge.clone(),
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let decoded: WindowsLauncherRequestV1 = serde_json::from_slice(&request_bytes).unwrap();
    assert!(
        matches!(decoded, WindowsLauncherRequestV1::StartupAttestation { schema_version, challenge }
        if schema_version == WINDOWS_PRIVATE_PROTOCOL_VERSION && challenge == expected.challenge)
    );
    assert!(serde_json::from_slice::<WindowsProviderRequestV1>(&request_bytes).is_err());
    let response = WindowsLauncherResponseV1::StartupAttestation {
        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        attestation: expected.clone(),
    };
    let bytes = serde_json::to_vec(&response).unwrap();
    assert!(bytes.len() > WINDOWS_RESPONSE_PREFIX_BYTES);
    assert_eq!(
        WindowsLauncherResponseV1::frame_limit(&bytes[..WINDOWS_RESPONSE_PREFIX_BYTES]).unwrap(),
        WINDOWS_MAX_FRAME_BYTES
    );
    assert!(serde_json::from_slice::<WindowsProviderResponseV1>(&bytes).is_err());
    let text = std::str::from_utf8(&bytes).unwrap();
    let duplicate = format!(
        "{{\"schema_version\":{},{}",
        WINDOWS_PRIVATE_PROTOCOL_VERSION,
        text.strip_prefix('{').unwrap()
    );
    assert!(serde_json::from_str::<WindowsLauncherResponseV1>(&duplicate).is_err());
    let original_identity = "\"process_id\":41";
    assert!(text.contains(original_identity));
    let duplicate_identity = text.replace(original_identity, "\"process_id\":41,\"process_id\":41");
    assert!(serde_json::from_str::<WindowsLauncherResponseV1>(&duplicate_identity).is_err());
    let decoded: WindowsLauncherResponseV1 = serde_json::from_slice(&bytes).unwrap();
    let WindowsLauncherResponseV1::StartupAttestation {
        schema_version,
        attestation: actual,
    } = decoded
    else {
        panic!("startup identity must not become a manifest-bound probe");
    };
    assert_eq!(schema_version, WINDOWS_PRIVATE_PROTOCOL_VERSION);
    assert_eq!(actual, expected);
    let mut unexpected = serde_json::to_value(&response).unwrap();
    unexpected["provider_binding"] = serde_json::json!({});
    assert!(serde_json::from_value::<WindowsLauncherResponseV1>(unexpected).is_err());
    let mut full_probe = serde_json::to_value(&response).unwrap();
    full_probe["kind"] = serde_json::json!("probe");
    assert!(
        serde_json::from_value::<WindowsLauncherResponseV1>(full_probe).is_err(),
        "full Probe still requires provider binding"
    );
}

#[test]
fn startup_attestation_retains_fresh_identity_and_token_requirements() {
    let expected = attestation();
    let privileges = [
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeTcbPrivilege",
    ];
    let validate = |actual: &WindowsServiceSelfAttestationV1| {
        actual.validate_for(
            &expected.challenge,
            &expected.service_name,
            &expected.process_identity,
            &expected.service_sid,
            &privileges,
        )
    };
    assert!(validate(&expected).is_ok());
    let mutations: &[fn(&mut WindowsServiceSelfAttestationV1)] = &[
        |value| value.schema_version += 1,
        |value| value.challenge = "34".repeat(32),
        |value| value.service_name.push_str("-other"),
        |value| value.process_identity.process_id += 1,
        |value| value.process_identity.creation_time_100ns += 1,
        |value| value.service_sid.push_str("-6"),
        |value| value.service_sid_enabled = false,
        |value| value.service_sid_restricted = false,
        |value| value.required_privileges.clear(),
    ];
    for mutate in mutations {
        let mut invalid = expected.clone();
        mutate(&mut invalid);
        assert!(
            validate(&invalid).is_err(),
            "invalid startup identity accepted: {invalid:?}"
        );
    }
}
