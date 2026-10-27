use memcordon_core::WindowsCallerTokenEnvelopeV1;
use memcordon_windows_loader_lab::startup_probe_contract::validate_token_pair;
use serde_json::json;

fn primary() -> WindowsCallerTokenEnvelopeV1 {
    let digest = String::from(memcordon_core::DiagnosticSha256::from_bytes([7; 32]));
    WindowsCallerTokenEnvelopeV1 {
        user_sid: "S-1-5-21-1-2-3-1001".into(),
        owner_sid: "S-1-5-21-1-2-3-1001".into(),
        primary_group_sid: "S-1-5-21-1-2-3-513".into(),
        groups_sha256: digest.clone(),
        privileges_sha256: digest.clone(),
        restricted_sids_sha256: digest,
        integrity_level: "S-1-16-12288".into(),
        mandatory_policy: 3,
        session_id: 2,
        elevation_type: 2,
        elevated: true,
        virtualization_allowed: false,
        virtualization_enabled: false,
        ui_access: false,
        appcontainer: false,
        authentication_id: 784146,
        token_type: 1,
        impersonation_level: 0,
    }
}

#[test]
fn probe_duplicate_changes_only_its_explicit_impersonation_role() {
    let primary = primary();
    let mut probe = primary.clone();
    probe.token_type = 2;
    probe.impersonation_level = 2;
    validate_token_pair(&primary, &probe).unwrap();
    for (field, replacement) in [
        ("user_sid", json!("S-1-5-18")),
        ("owner_sid", json!("S-1-5-18")),
        ("primary_group_sid", json!("S-1-5-32-544")),
        ("groups_sha256", json!("changed")),
        ("privileges_sha256", json!("changed")),
        ("restricted_sids_sha256", json!("changed")),
        ("integrity_level", json!("S-1-16-16384")),
        ("mandatory_policy", json!(0)),
        ("session_id", json!(0)),
        ("authentication_id", json!(0)),
        ("elevation_type", json!(1)),
        ("elevated", json!(false)),
        ("virtualization_allowed", json!(true)),
        ("virtualization_enabled", json!(true)),
        ("ui_access", json!(true)),
        ("appcontainer", json!(true)),
    ] {
        let mut changed = serde_json::to_value(&probe).unwrap();
        changed[field] = replacement;
        let changed = serde_json::from_value(changed).unwrap();
        assert!(
            validate_token_pair(&primary, &changed).is_err(),
            "accepted different {field}"
        );
    }
}

#[test]
fn primary_or_weaker_impersonation_handle_cannot_stand_in_for_probe_role() {
    let primary = primary();
    assert!(validate_token_pair(&primary, &primary).is_err());
    let mut probe = primary.clone();
    probe.token_type = 2;
    for level in [0, 1, 3] {
        probe.impersonation_level = level;
        assert!(validate_token_pair(&primary, &probe).is_err());
    }
    probe.impersonation_level = 2;
    let mut wrong_primary = primary.clone();
    wrong_primary.token_type = 2;
    assert!(validate_token_pair(&wrong_primary, &probe).is_err());
}

#[test]
fn default_dacl_capture_distinguishes_null_empty_and_exact_ace_bytes() {
    use memcordon_windows_loader_lab::startup_probe_contract::{
        default_dacl_equality, describe_default_dacl,
    };
    let null = json!({"captured":true,"facts":describe_default_dacl(None).unwrap()});
    let empty_bytes = [2, 0, 8, 0, 0, 0, 0, 0];
    let empty = json!({"captured":true,"facts":describe_default_dacl(Some(&empty_bytes)).unwrap()});
    assert_eq!(default_dacl_equality(&null, &null), Some(true));
    assert_eq!(default_dacl_equality(&null, &empty), Some(false));
    for malformed in [
        json!({"captured":true}),
        json!({"captured":true,"facts":{}}),
        json!({"captured":true,"facts":{"null":true}}),
        json!({"captured":true,"facts":{"null":"true","raw_hex":null,"sha256":null}}),
        json!({"captured":true,"facts":{"null":true,"raw_hex":"","sha256":null}}),
        json!({"captured":true,"facts":{"null":false,"raw_hex":null}}),
        json!({"captured":true,"facts":{"null":false,"raw_hex":"not-hex"}}),
    ] {
        assert_eq!(default_dacl_equality(&malformed, &malformed), None);
        assert_eq!(default_dacl_equality(&null, &malformed), None);
    }
    let mut contradictory = empty.clone();
    contradictory["facts"]["size"] = json!(0);
    assert_eq!(default_dacl_equality(&contradictory, &contradictory), None);
    let mut acl = vec![2, 0, 0, 0, 1, 0, 0, 0];
    let mut ace = vec![0, 0, 0, 0];
    ace.extend_from_slice(&1_u32.to_le_bytes());
    ace.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5]);
    ace.extend_from_slice(&18_u32.to_le_bytes());
    let ace_len = u16::try_from(ace.len()).unwrap();
    ace[2..4].copy_from_slice(&ace_len.to_le_bytes());
    acl.extend_from_slice(&ace);
    let acl_len = u16::try_from(acl.len()).unwrap();
    acl[2..4].copy_from_slice(&acl_len.to_le_bytes());
    let facts = describe_default_dacl(Some(&acl)).unwrap();
    assert_eq!(facts["aces"][0]["sid"], "S-1-5-18");
    assert_eq!(facts["aces"][0]["mask"], 1);
    let source = json!({"captured":true,"facts":facts});
    assert_eq!(default_dacl_equality(&source, &source), Some(true));
    let mut changed = acl.clone();
    let mask_offset = empty_bytes.len() + size_of::<u32>();
    changed[mask_offset] = 2;
    let actual = json!({"captured":true,"facts":describe_default_dacl(Some(&changed)).unwrap()});
    assert_eq!(default_dacl_equality(&source, &actual), Some(false));
    assert_eq!(
        default_dacl_equality(&source, &json!({"captured":false,"error":"query denied"})),
        None
    );
    let mut malformed = acl.clone();
    malformed[empty_bytes.len() + 2..empty_bytes.len() + 4]
        .copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(describe_default_dacl(Some(&malformed)).is_err());
    assert!(describe_default_dacl(Some(&acl[..acl.len() - 1])).is_err());
}

#[test]
fn default_dacl_bounds_and_unknown_ace_semantics_are_explicit() {
    use memcordon_windows_loader_lab::startup_probe_contract::{
        DEFAULT_DACL_BYTES, describe_default_dacl,
    };
    assert!(describe_default_dacl(Some(&vec![0; DEFAULT_DACL_BYTES + 1])).is_err());
    let excessive_count = [2, 0, 8, 0, 65, 0, 0, 0];
    assert!(describe_default_dacl(Some(&excessive_count)).is_err());
    let unknown = [2, 0, 12, 0, 1, 0, 0, 0, 255, 0, 4, 0];
    let facts = describe_default_dacl(Some(&unknown)).unwrap();
    assert_eq!(facts["aces"][0]["parsed"], false);
    assert!(facts["aces"][0]["semantic_omission"].is_string());
    assert_eq!(facts["aces"][0]["raw_hex"], hex::encode(&unknown[8..]));
}
