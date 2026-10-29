use memcordon_core::{
    WindowsLaunchRequestV2, WindowsLoaderDiagnosticKindV1, WindowsLoaderDiagnosticSelectionV1,
};
use sha2::{Digest, Sha256};

fn ordinary_request() -> WindowsLaunchRequestV2 {
    serde_json::from_value(serde_json::json!({
        "restart_attempt": 0,
        "schema_version": 4,
        "expected_provider_binding": {
            "generation": "measured-support",
            "source_commit": "ab".repeat(20),
            "runtime_manifest_sha256": "cd".repeat(32)
        },
        "workload_request": null,
        "nonce": "own-diagnostic-request",
        "command": { "program": [120], "arguments": [] },
        "environment": [],
        "current_directory": [67, 58, 92],
        "policy": {
            "memory_limit_bytes": null,
            "absolute_deadline_millis": null,
            "lifetime": "command",
            "poll_interval_millis": 10,
            "signal_grace_millis": 10,
            "command_exit_grace_millis": 10,
            "limit_grace_millis": 10
        }
    }))
    .unwrap()
}

fn selection() -> WindowsLoaderDiagnosticSelectionV1 {
    WindowsLoaderDiagnosticSelectionV1 {
        kind: WindowsLoaderDiagnosticKindV1::OriginalRestrictedBootstrap,
        challenge: "ef".repeat(32),
        support_bootstrap_sha256: "12".repeat(32),
        producer_deadline_sha256: "56".repeat(32),
        work_deadline_unix_ms: 100,
        cleanup_deadline_unix_ms: 200,
    }
}

#[test]
fn ordinary_wire_omits_diagnostic_and_selection_is_inside_canonical_digest() {
    let ordinary = ordinary_request();
    let bytes = serde_json::to_vec(&ordinary).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("loader_diagnostic").is_none());
    assert!(ordinary.loader_diagnostic.is_none());

    let mut selected = ordinary.clone();
    selected.loader_diagnostic = Some(Box::new(selection()));
    let selected_bytes = serde_json::to_vec(&selected).unwrap();
    assert_ne!(Sha256::digest(&bytes), Sha256::digest(&selected_bytes));
    assert_eq!(
        serde_json::from_slice::<WindowsLaunchRequestV2>(&selected_bytes).unwrap(),
        selected
    );
    for changed_field in [
        "challenge",
        "support_bootstrap_sha256",
        "producer_deadline_sha256",
        "work_deadline_unix_ms",
        "cleanup_deadline_unix_ms",
    ] {
        let mut changed = serde_json::to_value(&selected).unwrap();
        let field = &mut changed["loader_diagnostic"][changed_field];
        *field = if field.is_string() {
            serde_json::json!("34".repeat(32))
        } else {
            serde_json::json!(300)
        };
        let changed: WindowsLaunchRequestV2 = serde_json::from_value(changed).unwrap();
        assert_ne!(changed, selected);
        assert_ne!(
            Sha256::digest(&selected_bytes),
            Sha256::digest(serde_json::to_vec(&changed).unwrap())
        );
    }
}

#[test]
fn selection_requires_original_nonexpired_ordered_bounds_and_exact_digests() {
    let selected = selection();
    assert!(selected.validate_at(99).is_ok());
    assert!(selected.validate_at(100).is_err());
    let mut invalid = selected.clone();
    invalid.cleanup_deadline_unix_ms = 99;
    assert!(invalid.validate_at(1).is_err());
    invalid = selected.clone();
    invalid.challenge.pop();
    assert!(invalid.validate_at(1).is_err());
    invalid = selected;
    invalid.support_bootstrap_sha256 = "z".repeat(64);
    assert!(invalid.validate_at(1).is_err());
}
