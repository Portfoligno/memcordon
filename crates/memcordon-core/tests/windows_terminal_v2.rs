use memcordon_core::{
    WindowsCapabilityOwnerEntryV1, WindowsCapabilityOwnerManifestV1, WindowsCapabilityOwnerRoleV1,
    WindowsTerminalPayloadV2,
};

#[test]
fn recovered_closure_cannot_smuggle_execution_fields() {
    let recovered = serde_json::json!({
        "kind": "recovered-closure",
        "primary_failure": {
            "unavailable": {"reason": "worker-lost-before-observation"}
        },
        "target_creation_observed": true,
        "resume_attempted": true,
    });
    let parsed: WindowsTerminalPayloadV2 =
        serde_json::from_value(recovered.clone()).expect("recovered closure is typed");
    assert!(matches!(
        parsed,
        WindowsTerminalPayloadV2::RecoveredClosure { .. }
    ));
    let mut smuggled = recovered;
    smuggled["child_pid"] = serde_json::json!(1234);
    assert!(serde_json::from_value::<WindowsTerminalPayloadV2>(smuggled).is_err());
}

#[test]
fn owner_manifest_requires_exact_order_and_all_required_roles() {
    let entries = std::array::from_fn(|index| {
        let role = WindowsCapabilityOwnerRoleV1::ALL[index];
        WindowsCapabilityOwnerEntryV1 {
            role,
            present: role.required(),
            process_identity: None,
            capability_binding_sha256: role.required().then(|| "a".repeat(64)),
        }
    });
    let manifest = WindowsCapabilityOwnerManifestV1 {
        schema_version: 1,
        attempt_id: "b".repeat(64),
        provider_generation: "generation".to_owned(),
        launch_incarnation: "incarnation".to_owned(),
        entries,
    };
    let digest = manifest
        .canonical_sha256()
        .expect("complete manifest validates");
    assert_eq!(digest.len(), 64);
    let mut omitted = manifest.clone();
    let index = WindowsCapabilityOwnerRoleV1::ALL
        .iter()
        .position(|role| *role == WindowsCapabilityOwnerRoleV1::GuardianProcess)
        .expect("guardian role exists");
    omitted.entries[index].present = false;
    omitted.entries[index].capability_binding_sha256 = None;
    assert!(omitted.validate().is_err());
    let mut reordered = manifest;
    reordered.entries.swap(0, 1);
    assert!(reordered.validate().is_err());
}
