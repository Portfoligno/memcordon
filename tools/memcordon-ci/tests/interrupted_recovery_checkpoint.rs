#[path = "../../../crates/memcordon-cli/src/bin/original_native_recovery_checkpoint.rs"]
mod checkpoint;

use memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry;
use serde_json::{Value, json};

fn records() -> (tempfile::TempDir, Value, Value) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let legacy: RuntimePrivatePolicyRegistry = serde_json::from_value(json!({
        "format":"memcordon.local-private-policy", "revision":1,
        "profiles":[], "execution_identities":[], "grants":[],
        "active_attempt_disposition":"drain-existing",
    }))
    .unwrap();
    legacy.validate().unwrap();
    let identity = json!({
        "run_id":"39146715998", "source_commit":"ab".repeat(20),
        "source_tree_sha256":"cd".repeat(32), "version":"0.5.8-dev",
    });
    let cell = json!({"target":"x86_64-unknown-linux-gnu", "channel":"candidate-cargo"});
    // This is the actual producer's association header, not a complete resource
    // checkpoint. Protected-byte custody precedes this helper; the existing
    // resource deserializer validates acquired images/accounts afterward.
    // Lease authority belongs to the separately validated owner/input/harness.
    let acquired = json!({
        "format":"memcordon.owned-readiness-resources", "revision":1,
        "identity":identity, "cell":cell, "admin_root":root,
        "device":2049, "inode":9700391,
        "legacy":legacy,
    });
    let owner = json!({
        "format":"memcordon.consumer-readiness.linux-lease-owner", "revision":1,
        "identity":acquired["identity"], "cell":acquired["cell"],
        "admin_root":acquired["admin_root"], "artifact_root":root.join("artifacts"),
        "device":acquired["device"], "inode":acquired["inode"],
        "cleanup_agent":root.join("cleanup-agent"), "cleanup_agent_sha256":"ef".repeat(32),
        "legacy":acquired["legacy"],
        "lease_id":"39146715998-x86_64-unknown-linux-gnu-candidate-cargo",
        "work_deadline_unix_millis":2000000, "cleanup_deadline_unix_millis":2900000,
    });
    (directory, owner, acquired)
}

#[test]
fn actual_checkpoint_association_header_joins_owner_without_a_lease_id() {
    let (_directory, mut owner, mut acquired) = records();
    assert!(acquired.get("lease_id").is_none());
    assert!(owner["lease_id"].is_string());
    checkpoint::validate_interrupted_checkpoint(&owner, &acquired).unwrap();
    // Device zero can be a legitimate filesystem identity. Exact equality to
    // the independently held owner, rather than a guessed minimum, is required.
    owner["device"] = 0.into();
    acquired["device"] = 0.into();
    checkpoint::validate_interrupted_checkpoint(&owner, &acquired).unwrap();
}

#[test]
fn partial_checkpoint_rejects_every_foreign_association_and_protocol_version() {
    let (directory, owner, acquired) = records();
    for mutation in [
        "format", "revision", "run", "commit", "tree", "version", "target", "channel", "root",
        "device", "inode", "legacy",
    ] {
        let mut changed = acquired.clone();
        match mutation {
            "format" => changed["format"] = "foreign".into(),
            "revision" => changed["revision"] = 2.into(),
            "run" => changed["identity"]["run_id"] = "39146715999".into(),
            "commit" => changed["identity"]["source_commit"] = "12".repeat(20).into(),
            "tree" => changed["identity"]["source_tree_sha256"] = "23".repeat(32).into(),
            "version" => changed["identity"]["version"] = "0.5.9-dev".into(),
            "target" => changed["cell"]["target"] = "aarch64-unknown-linux-gnu".into(),
            "channel" => changed["cell"]["channel"] = "candidate-native".into(),
            "root" => {
                changed["admin_root"] =
                    serde_json::to_value(directory.path().join("other-owner")).unwrap()
            }
            "device" => changed["device"] = 2050.into(),
            "inode" => changed["inode"] = 9700392.into(),
            "legacy" => changed["legacy"]["active_attempt_disposition"] = "revoke-active".into(),
            _ => unreachable!(),
        }
        assert!(
            checkpoint::validate_interrupted_checkpoint(&owner, &changed).is_err(),
            "accepted foreign {mutation}"
        );
    }
}

#[test]
fn partial_checkpoint_rejects_absent_or_wrongly_typed_native_association() {
    let (_directory, owner, acquired) = records();
    for field in [
        "format",
        "revision",
        "identity",
        "cell",
        "admin_root",
        "device",
        "inode",
        "legacy",
    ] {
        let mut absent = acquired.clone();
        absent.as_object_mut().unwrap().remove(field);
        assert!(
            checkpoint::validate_interrupted_checkpoint(&owner, &absent).is_err(),
            "accepted absent {field}"
        );
    }
    for (field, value) in [
        ("identity", json!([])),
        ("cell", json!([])),
        ("legacy", json!([])),
        ("admin_root", json!("relative/admin")),
        ("admin_root", json!(null)),
        ("device", json!(-1)),
        ("device", json!("2049")),
        ("inode", json!(-1)),
        ("inode", json!("9700391")),
    ] {
        let mut changed = acquired.clone();
        changed[field] = value;
        assert!(
            checkpoint::validate_interrupted_checkpoint(&owner, &changed).is_err(),
            "accepted invalid {field}"
        );
    }
    // A tuple missing on both sides must never pass as null == null.
    for field in [
        "identity",
        "cell",
        "admin_root",
        "device",
        "inode",
        "legacy",
    ] {
        let mut absent_owner = owner.clone();
        let mut absent_acquired = acquired.clone();
        absent_owner.as_object_mut().unwrap().remove(field);
        absent_acquired.as_object_mut().unwrap().remove(field);
        assert!(
            checkpoint::validate_interrupted_checkpoint(&absent_owner, &absent_acquired).is_err()
        );
    }
}
