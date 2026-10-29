use memcordon_readiness_verifier::current::linux::request_digest;
use sha2::{Digest, Sha256};

fn request() -> serde_json::Value {
    serde_json::json!({"format":"memcordon.workload-request","revision":1,
        "runtime":{"kind":"linux-private","profile":"linux-private-workload-v1",
            "inputs":{"runtime_digest":"11".repeat(32),"input_digest":"22".repeat(32),"entrypoint":"main"},
            "layout":{"writable_roots":[],"output_files":[]}},
        "requirements":[{"kind":"unix_stream_pair","id":"z"},{"kind":"unix_stream_pair","id":"a"}]})
}

#[test]
fn independent_current_encoder_uses_declared_field_order_and_requirement_identity() {
    let expected = format!(
        "{{\"format\":\"memcordon.workload-request\",\"revision\":1,\"runtime\":{{\"kind\":\"linux-private\",\"profile\":\"linux-private-workload-v1\",\"inputs\":{{\"runtime_digest\":\"{}\",\"input_digest\":\"{}\",\"entrypoint\":\"main\"}},\"layout\":{{\"writable_roots\":[],\"output_files\":[]}}}},\"requirements\":[{{\"kind\":\"unix_stream_pair\",\"id\":\"a\"}},{{\"kind\":\"unix_stream_pair\",\"id\":\"z\"}}]}}",
        "11".repeat(32),
        "22".repeat(32)
    );
    assert_eq!(
        request_digest(&serde_json::to_vec(&request()).unwrap()).unwrap(),
        hex::encode(Sha256::digest(expected.as_bytes()))
    );
    let mut changed = request();
    changed["requirements"][0]["id"] = "different".into();
    assert_ne!(
        request_digest(&serde_json::to_vec(&request()).unwrap()).unwrap(),
        request_digest(&serde_json::to_vec(&changed).unwrap()).unwrap()
    );
}

#[test]
fn independent_current_parser_does_not_accept_authorization_or_weaker_root_aliases() {
    for field in [
        "authorization",
        "expected_epoch",
        "execution_identity",
        "approved_plan_digest",
    ] {
        let mut changed = request();
        changed[field] = 1.into();
        assert!(request_digest(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut changed = request();
    changed["runtime"]["layout"]["writable_roots"] = serde_json::json!([{"id":"work","path":"../host","byte_limit":1,"generated_execution":false}]);
    assert!(request_digest(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = request();
    changed["requirements"] = serde_json::json!([{"kind":"generated_executable","id":"generated","writable_root":"missing"}]);
    assert!(request_digest(&serde_json::to_vec(&changed).unwrap()).is_err());
}
