use memcordon_ci::windows_channel_identity::package_contract;
use serde_json::{Value, json};

fn package(digest: &str) -> Value {
    json!({
        "executable_sha256": digest,
        "target_desktop_bootstrap_sha256": digest,
        "session_broker_sha256": digest,
        "source_commit": "accepted-source",
        "control_required_privileges": ["SeImpersonatePrivilege"],
        "control_pipe_security_sha256": "ab".repeat(32),
        "target_desktop_bootstrap_loader_contract_sha256": "cd".repeat(32),
        "target_desktop_bootstrap_normal_imports": ["KERNEL32.DLL"],
        "target_desktop_bootstrap_crt_static": true,
        "mechanism": "windows-job-object-v2"
    })
}

#[test]
fn independently_built_images_share_only_the_semantic_contract() {
    assert_eq!(
        package_contract(package(&"12".repeat(32))).unwrap(),
        package_contract(package(&"34".repeat(32))).unwrap(),
    );
}

#[test]
fn projection_retains_every_security_loader_and_source_contract() {
    let original = package(&"12".repeat(32));
    let expected = package_contract(original.clone()).unwrap();
    for (field, replacement) in [
        ("source_commit", json!("other-source")),
        ("control_required_privileges", json!([])),
        ("control_pipe_security_sha256", json!("ef".repeat(32))),
        (
            "target_desktop_bootstrap_loader_contract_sha256",
            json!("ef".repeat(32)),
        ),
        (
            "target_desktop_bootstrap_normal_imports",
            json!(["USER32.DLL"]),
        ),
        ("target_desktop_bootstrap_crt_static", json!(false)),
        ("mechanism", json!("other-mechanism")),
    ] {
        let mut changed = original.clone();
        changed[field] = replacement;
        assert_ne!(expected, package_contract(changed).unwrap(), "{field}");
    }
}

#[test]
fn projection_cannot_hide_missing_or_malformed_image_evidence() {
    for field in [
        "executable_sha256",
        "target_desktop_bootstrap_sha256",
        "session_broker_sha256",
    ] {
        let mut missing = package(&"12".repeat(32));
        missing.as_object_mut().unwrap().remove(field);
        assert!(package_contract(missing).is_err(), "{field}");
        for malformed in [
            Value::Null,
            json!(7),
            json!("not-a-digest"),
            json!("gg".repeat(32)),
        ] {
            let mut changed = package(&"12".repeat(32));
            changed[field] = malformed;
            assert!(package_contract(changed).is_err(), "{field}");
        }
    }
}
