#![cfg(feature = "test-fixtures")]
use memcordon::toolchain_creation_ack::{Expected, validate};
use memcordon_core::WindowsProcessIdentityV1;

fn acknowledgment() -> serde_json::Value {
    serde_json::json!({"format":"memcordon.windows-toolchain-creation-ack","revision":1,
        "challenge":[1,2,3],"descendant":{"format":"memcordon.windows-native-toolchain-descendant",
        "revision":1,"ordinal":2,"root_pid":1728,"pid":8520,"birth":134362698052903086u64,
        "parent_pid":6120,"parent_birth":134362698051955380u64,"image_sha256":"a".repeat(64),
        "native_parent_edge_observed":true,"parent_and_child_held_live":true}})
}

fn check(value: &serde_json::Value) -> Result<(), String> {
    validate(
        &serde_json::to_vec(value).unwrap(),
        Expected {
            challenge: &[1, 2, 3],
            root_pid: 1728,
            child: &WindowsProcessIdentityV1 {
                process_id: 8520,
                creation_time_100ns: 134362698052903086,
            },
            parent: &WindowsProcessIdentityV1 {
                process_id: 6120,
                creation_time_100ns: 134362698051955380,
            },
            image_sha256: &"a".repeat(64),
        },
    )
}

#[test]
fn original_child_ack_requires_exact_native_identity_and_authority_fields() {
    assert!(check(&acknowledgment()).is_ok());
    for field in [
        "root_pid",
        "pid",
        "birth",
        "parent_pid",
        "parent_birth",
        "ordinal",
    ] {
        let mut ack = acknowledgment();
        ack["descendant"][field] = serde_json::json!(0);
        assert!(check(&ack).is_err(), "{field}");
    }
    for field in ["native_parent_edge_observed", "parent_and_child_held_live"] {
        let mut ack = acknowledgment();
        ack["descendant"][field] = serde_json::json!(false);
        assert!(check(&ack).is_err(), "{field}");
    }
    let mut ack = acknowledgment();
    ack["challenge"] = serde_json::json!([1, 2, 4]);
    assert!(check(&ack).is_err());
    let mut ack = acknowledgment();
    ack["descendant"]["image_sha256"] = serde_json::json!("b".repeat(64));
    assert!(check(&ack).is_err());
    let mut ack = acknowledgment();
    ack["extra"] = serde_json::json!(true);
    assert!(check(&ack).is_err());
    let mut ack = acknowledgment();
    ack["descendant"]["extra"] = serde_json::json!(true);
    assert!(check(&ack).is_err());
}

#[test]
fn acknowledgment_bound_and_self_parent_cannot_be_bypassed() {
    let child = WindowsProcessIdentityV1 {
        process_id: 6120,
        creation_time_100ns: 134362698052903086,
    };
    let parent = WindowsProcessIdentityV1 {
        process_id: 6120,
        creation_time_100ns: 134362698051955380,
    };
    let hash = "a".repeat(64);
    let expected = || Expected {
        challenge: &[1, 2, 3],
        root_pid: 1728,
        child: &child,
        parent: &parent,
        image_sha256: &hash,
    };
    let mut ack = acknowledgment();
    ack["descendant"]["pid"] = serde_json::json!(child.process_id);
    assert!(validate(&serde_json::to_vec(&ack).unwrap(), expected()).is_err());
    let mut bytes = serde_json::to_vec(&acknowledgment()).unwrap();
    bytes.resize(16 * 1024 + 1, b' ');
    assert!(
        validate(&bytes, expected())
            .unwrap_err()
            .contains("exceeds bound")
    );
}
