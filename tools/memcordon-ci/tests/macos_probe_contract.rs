use serde_json::json;

#[test]
fn current_standard_probe_requires_every_native_fact_without_inventing_sealed_authority() {
    let probe = json!({"format":"memcordon.capabilities-probe","revision":2,
        "capabilities":{"format":"memcordon.capabilities","revision":3,"selected":{"sealed_unavailable":{"reason":"certified authority is not installed"}}},
        "execution":{"helper_ready":true,"target_exec_confirmed":true,"target_exit":0,"cleanup_complete":true,"supported":true,"failure":null}});
    memcordon_ci::macos_probe_contract::validate(&probe).unwrap();
    for (field, value) in [
        ("helper_ready", json!(false)),
        ("target_exec_confirmed", json!(false)),
        ("target_exit", json!(1)),
        ("cleanup_complete", json!(false)),
    ] {
        let mut invalid = probe.clone();
        invalid["execution"][field] = value;
        assert!(memcordon_ci::macos_probe_contract::validate(&invalid).is_err());
    }
    for (field, value) in [
        ("format", json!("doctor-execution-probe")),
        ("revision", json!(1)),
        ("format", json!(null)),
        ("revision", json!(null)),
    ] {
        let mut invalid = probe.clone();
        invalid[field] = value;
        assert!(memcordon_ci::macos_probe_contract::validate(&invalid).is_err());
    }
}
