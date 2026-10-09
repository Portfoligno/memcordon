//! Structural vectors only; no executed native listener claim.
use memcordon_readiness_verifier::validate_linux_endpoint_mismatch;
use serde_json::json;

#[test]
fn endpoint_refusal_requires_exact_native_root_namespace_and_two_held_listeners() {
    let challenge = [17u8; 32];
    let network = json!({"device":4,"inode":71});
    let observation = json!({"intended":"127.0.0.1:12345","observed":"127.0.0.1:12346","both_listeners_retained":true,"readiness_reached":false,"application_status":42});
    let receipt = json!({"format":"memcordon.linux-native-endpoint-mismatch","revision":1,"process_id":11,"birth":101,"network":network,
        "listeners":[{"endpoint":"127.0.0.1:12345","socket_inode":51},{"endpoint":"127.0.0.1:12346","socket_inode":52}],
        "root_held_live_before_and_after":true,"kernel_listen_and_root_descriptor_observed_twice":true,"challenge":hex::encode(challenge),"attempt_id":"owned-attempt"});
    validate_linux_endpoint_mismatch(
        &observation,
        &receipt,
        11,
        101,
        &network,
        "owned-attempt",
        &challenge,
    )
    .unwrap();
    for field in [
        "process_id",
        "birth",
        "attempt_id",
        "challenge",
        "root_held_live_before_and_after",
        "kernel_listen_and_root_descriptor_observed_twice",
    ] {
        let mut changed = receipt.clone();
        changed[field] = json!(null);
        assert!(
            validate_linux_endpoint_mismatch(
                &observation,
                &changed,
                11,
                101,
                &network,
                "owned-attempt",
                &challenge
            )
            .is_err(),
            "{field}"
        );
    }
    let mut changed = receipt.clone();
    changed["network"]["inode"] = json!(72);
    assert!(
        validate_linux_endpoint_mismatch(
            &observation,
            &changed,
            11,
            101,
            &network,
            "owned-attempt",
            &challenge
        )
        .is_err()
    );
    for field in ["endpoint", "socket_inode"] {
        let mut changed = receipt.clone();
        changed["listeners"][1][field] = changed["listeners"][0][field].clone();
        assert!(
            validate_linux_endpoint_mismatch(
                &observation,
                &changed,
                11,
                101,
                &network,
                "owned-attempt",
                &challenge
            )
            .is_err(),
            "aliased {field}"
        );
    }
    let mut changed = observation.clone();
    changed["readiness_reached"] = json!(true);
    assert!(
        validate_linux_endpoint_mismatch(
            &changed,
            &receipt,
            11,
            101,
            &network,
            "owned-attempt",
            &challenge
        )
        .is_err()
    );
    let mut changed = receipt.clone();
    changed["listeners"][0]["socket_inode"] = json!(0);
    assert!(
        validate_linux_endpoint_mismatch(
            &observation,
            &changed,
            11,
            101,
            &network,
            "owned-attempt",
            &challenge
        )
        .is_err()
    );
    let mut changed = receipt.clone();
    changed["selection"] = json!("endpoint-mismatch");
    assert!(
        validate_linux_endpoint_mismatch(
            &observation,
            &changed,
            11,
            101,
            &network,
            "owned-attempt",
            &challenge
        )
        .is_err()
    );
}
