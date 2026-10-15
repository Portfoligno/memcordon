use memcordon_readiness_verifier::windows_control_site::validate;
use serde_json::{Value, json};

fn site() -> Value {
    json!({"format":"memcordon.windows-component-control-worker-site","revision":1,
        "attempt_id":"ab".repeat(32),"nonce":"original-launch","request_sha256":"cd".repeat(32),
        "fault":"control-worker-killed-after-authorization","target_pid":13,"target_authorization_observed":true,
        "process":{"process_id":7,"creation_time_100ns":134365042738576637_u64},
        "thread":{"thread_id":11,"creation_time_100ns":134365042738576639_u64}})
}

#[test]
fn independent_control_site_decoder_refuses_foreign_and_malformed_metadata() {
    let original = site();
    let check = |value: &Value| {
        validate(
            value,
            &"ab".repeat(32),
            "original-launch",
            &"cd".repeat(32),
            "control-worker-killed-after-authorization",
            13,
        )
    };
    check(&original).unwrap();
    let parsed: Value = serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(
        parsed["process"]["creation_time_100ns"].as_u64(),
        Some(134365042738576637)
    );
    for (field, value) in [
        ("attempt_id", json!("ef".repeat(32))),
        ("request_sha256", json!("ef".repeat(32))),
        ("nonce", json!("foreign")),
        ("fault", json!("frontend-killed-after-authorization")),
        ("target_pid", json!(17)),
        ("target_authorization_observed", json!(false)),
        ("revision", json!(2)),
        ("unknown", json!(true)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert_ne!(changed, original);
        assert!(check(&changed).is_err(), "accepted {field}");
    }
    for (role, field) in [
        ("process", "process_id"),
        ("process", "creation_time_100ns"),
        ("thread", "thread_id"),
        ("thread", "creation_time_100ns"),
    ] {
        let mut changed = original.clone();
        changed[role][field] = json!(0);
        assert!(check(&changed).is_err());
    }
    assert!(check(&Value::Null).is_err());
}
