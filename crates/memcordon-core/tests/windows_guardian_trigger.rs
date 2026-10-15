use memcordon_core::{
    WindowsGuardianCleanupTriggerV1, WindowsGuardianReceiptBinding, WindowsGuardianReceiptV2,
    WindowsProcessIdentityV1,
};

fn legacy_receipt() -> WindowsGuardianReceiptV2 {
    serde_json::from_value(serde_json::json!({
        "schema_version":2,"attempt_id":"ab".repeat(32),"nonce":"original-native-nonce",
        "request_sha256":"cd".repeat(32),"provider_generation":"original-provider",
        "launch_incarnation":"original-launch","original_boot_id":"original-boot",
        "job_identity":"ef".repeat(32),
        "guardian_identity":{"process_id":7,"creation_time_100ns":11},
        "worker_identity":{"process_id":13,"creation_time_100ns":17},
        "owner_manifest_sha256":"12".repeat(32),"termination_requested":true,
        "native_job_query_succeeded":true,"active_processes_zero_observed":true,
        "observed_unix_millis":1,"integrity_sha256":""
    }))
    .unwrap()
}

fn seal(receipt: &mut WindowsGuardianReceiptV2) {
    receipt.integrity_sha256 = receipt.canonical_sha256().unwrap();
}

fn bound(receipt: &WindowsGuardianReceiptV2, caller: &WindowsProcessIdentityV1) -> bool {
    receipt.binds(WindowsGuardianReceiptBinding {
        attempt_id: &receipt.attempt_id,
        nonce: &receipt.nonce,
        request_sha256: &receipt.request_sha256,
        provider_generation: &receipt.provider_generation,
        launch_incarnation: &receipt.launch_incarnation,
        boot_identity: &receipt.original_boot_id,
        job_identity: &receipt.job_identity,
        owner_manifest_sha256: &receipt.owner_manifest_sha256,
        caller_process_identity: caller,
    })
}

#[test]
fn legacy_absence_stays_absent_and_observed_trigger_changes_integrity() {
    let mut receipt = legacy_receipt();
    seal(&mut receipt);
    assert!(receipt.is_consistent());
    let legacy = serde_json::to_vec(&receipt).unwrap();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&legacy)
            .unwrap()
            .get("cleanup_trigger")
            .is_none()
    );
    assert_eq!(
        serde_json::from_slice::<WindowsGuardianReceiptV2>(&legacy).unwrap(),
        receipt
    );
    let legacy_digest = receipt.integrity_sha256.clone();
    let frontend = WindowsProcessIdentityV1 {
        process_id: 1372,
        creation_time_100ns: 134364958296860014,
    };
    receipt.cleanup_trigger = Some(WindowsGuardianCleanupTriggerV1::FrontendLost {
        frontend: frontend.clone(),
        native_exit_status: 0xc000013a,
    });
    assert!(!receipt.is_consistent());
    seal(&mut receipt);
    assert!(receipt.is_consistent());
    assert_ne!(receipt.integrity_sha256, legacy_digest);
    assert!(bound(&receipt, &frontend));
    let raw = serde_json::to_value(&receipt).unwrap();
    assert_eq!(
        raw["cleanup_trigger"]["frontend"]["creation_time_100ns"].as_u64(),
        Some(frontend.creation_time_100ns)
    );
    let mut foreign = frontend.clone();
    foreign.creation_time_100ns += 1;
    assert!(!bound(&receipt, &foreign));
    if let Some(WindowsGuardianCleanupTriggerV1::FrontendLost {
        native_exit_status, ..
    }) = &mut receipt.cleanup_trigger
    {
        *native_exit_status = 0;
    }
    assert!(!receipt.is_consistent());
}

#[test]
fn distinct_triggers_and_unavailable_identity_cannot_become_frontend_loss() {
    for trigger in [
        WindowsGuardianCleanupTriggerV1::WorkerLost,
        WindowsGuardianCleanupTriggerV1::ServiceStopped,
        WindowsGuardianCleanupTriggerV1::FrontendIdentityUnavailable,
        WindowsGuardianCleanupTriggerV1::FrontendExitStatusUnavailable {
            frontend: WindowsProcessIdentityV1 {
                process_id: 1372,
                creation_time_100ns: 134364958296860014,
            },
            native_code: 5,
        },
    ] {
        let mut receipt = legacy_receipt();
        receipt.cleanup_trigger = Some(trigger.clone());
        seal(&mut receipt);
        assert!(receipt.is_consistent());
        let decoded: WindowsGuardianReceiptV2 =
            serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert_eq!(decoded.cleanup_trigger, Some(trigger));
        assert!(!matches!(
            decoded.cleanup_trigger,
            Some(WindowsGuardianCleanupTriggerV1::FrontendLost { .. })
        ));
    }
}
