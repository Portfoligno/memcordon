use memcordon_core::*;

#[path = "support/windows_postauthorization.rs"]
mod postauthorization;

fn receipt() -> WindowsTerminalReceiptV2 {
    let rejection = postauthorization::rejection();
    let mut receipt = rejection.terminal_receipt().unwrap().clone();
    let manifest = WindowsCapabilityOwnerManifestV1 {
        schema_version: 1,
        attempt_id: receipt.attempt_id.clone(),
        provider_generation: receipt.retirement_proof.provider_generation.clone(),
        launch_incarnation: receipt.retirement_proof.launch_incarnation.clone(),
        entries: std::array::from_fn(|index| {
            let role = WindowsCapabilityOwnerRoleV1::ALL[index];
            WindowsCapabilityOwnerEntryV1 {
                role,
                present: role.required(),
                process_identity: role.required().then_some(WindowsProcessIdentityV1 {
                    process_id: 1234,
                    creation_time_100ns: 5678,
                }),
                capability_binding_sha256: role.required().then(|| "12".repeat(32)),
            }
        }),
    };
    let proof = &mut receipt.retirement_proof;
    proof.owner_manifest_sha256 = manifest.canonical_sha256().unwrap();
    proof.source = WindowsRetirementProofSourceV2::CapabilityExtinction;
    proof.target_completion_observed = false;
    proof.native_job_empty_observed = false;
    proof.relay_closure_observed = false;
    proof.guardian_completion_observed = false;
    proof.capability_extinction = Some(WindowsCapabilityExtinctionProofV1 {
        contract: WindowsJobClosureContractV1 {
            schema_version: 1,
            attempt_id: proof.attempt_id.clone(),
            nonce: proof.nonce.clone(),
            request_sha256: proof.request_sha256.clone(),
            provider_generation: proof.provider_generation.clone(),
            launch_incarnation: proof.launch_incarnation.clone(),
            original_boot_id: proof.original_boot_id.clone(),
            job_identity: proof.job_identity.clone(),
            owner_manifest_sha256: proof.owner_manifest_sha256.clone(),
            guardian_job_transfer_sha256: "78".repeat(32),
            kill_on_close_verified: true,
            breakaway_denied: true,
            job_handles_noninheritable: true,
            closed_job_owner_set: true,
            job_unnamed: true,
            target_handle_list_verified: true,
        },
        owner_manifest: manifest,
        current_boot_id: proof.original_boot_id.clone(),
        job_holder_processes_extinct: true,
        target_process_extinct: true,
        relay_capabilities_retired: true,
        launch_gate_closed: true,
    });
    receipt.payload = WindowsTerminalPayloadV2::RecoveredClosure {
        primary_failure: OriginalFailureV1::Unavailable {
            reason: OriginalUnavailableReasonV1::WorkerLostBeforeObservation,
        },
        target_creation_observed: true,
        resume_attempted: true,
    };
    receipt.restart_safety.direct_child_reaped = false;
    receipt.restart_safety.helpers_reaped = false;
    receipt.restart_safety.sealed_boundary_retired = false;
    receipt
}

#[test]
fn capability_extinction_is_bound_closure_without_native_completion_claims() {
    let receipt = receipt();
    receipt.validate_for_attempt().unwrap();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let restored: WindowsTerminalReceiptV2 = serde_json::from_slice(&bytes).unwrap();
    restored.validate_for_attempt().unwrap();
    assert_eq!(restored, receipt);
    assert!(restored.execution().is_none());
    assert!(!restored.retirement_proof.native_job_empty_observed);
    assert!(!restored.retirement_proof.guardian_completion_observed);
}

#[test]
fn private_desktop_owner_requires_its_own_bound_process_identity() {
    let mut receipt = receipt();
    let proof = &mut receipt.retirement_proof;
    let extinction = proof.capability_extinction.as_mut().unwrap();
    for entry in &mut extinction.owner_manifest.entries {
        if matches!(
            entry.role,
            WindowsCapabilityOwnerRoleV1::DesktopBootstrapJob
                | WindowsCapabilityOwnerRoleV1::DesktopBootstrapProcess
        ) {
            entry.present = true;
            entry.process_identity = Some(WindowsProcessIdentityV1 {
                process_id: 9999,
                creation_time_100ns: 8888,
            });
            entry.capability_binding_sha256 = Some("56".repeat(32));
        }
    }
    let manifest_digest = extinction.owner_manifest.canonical_sha256().unwrap();
    extinction.contract.owner_manifest_sha256 = manifest_digest.clone();
    proof.owner_manifest_sha256 = manifest_digest;
    receipt.validate_for_attempt().unwrap();
    let proof = &mut receipt.retirement_proof;
    let extinction = proof.capability_extinction.as_mut().unwrap();
    extinction
        .owner_manifest
        .entries
        .iter_mut()
        .find(|entry| entry.role == WindowsCapabilityOwnerRoleV1::DesktopBootstrapProcess)
        .unwrap()
        .process_identity = None;
    let manifest_digest = extinction.owner_manifest.canonical_sha256().unwrap();
    extinction.contract.owner_manifest_sha256 = manifest_digest.clone();
    proof.owner_manifest_sha256 = manifest_digest;
    assert!(
        receipt.validate_for_attempt().is_err(),
        "accepted present private desktop holder without exact native identity"
    );
}

#[test]
fn every_job_closure_and_owner_extinction_requirement_is_mandatory() {
    let original = serde_json::to_value(receipt()).unwrap();
    for field in [
        "kill_on_close_verified",
        "breakaway_denied",
        "job_handles_noninheritable",
        "closed_job_owner_set",
        "job_unnamed",
        "target_handle_list_verified",
    ] {
        let mut changed = original.clone();
        changed["retirement_proof"]["capability_extinction"]["contract"][field] = false.into();
        let parsed: WindowsTerminalReceiptV2 = serde_json::from_value(changed).unwrap();
        assert!(
            parsed.validate_for_attempt().is_err(),
            "accepted {field}=false"
        );
    }
    for field in [
        "job_holder_processes_extinct",
        "target_process_extinct",
        "relay_capabilities_retired",
        "launch_gate_closed",
    ] {
        let mut changed = original.clone();
        changed["retirement_proof"]["capability_extinction"][field] = false.into();
        let parsed: WindowsTerminalReceiptV2 = serde_json::from_value(changed).unwrap();
        assert!(
            parsed.validate_for_attempt().is_err(),
            "accepted {field}=false"
        );
    }
}

#[test]
fn capability_extinction_rejects_substitution_and_invented_native_proofs() {
    let original = receipt();
    for field in [
        "attempt_id",
        "nonce",
        "request_sha256",
        "provider_generation",
        "launch_incarnation",
        "original_boot_id",
        "job_identity",
        "owner_manifest_sha256",
    ] {
        let mut changed = serde_json::to_value(&original).unwrap();
        changed["retirement_proof"]["capability_extinction"]["contract"][field] =
            "99".repeat(32).into();
        let parsed: WindowsTerminalReceiptV2 = serde_json::from_value(changed).unwrap();
        assert!(
            parsed.validate_for_attempt().is_err(),
            "accepted substituted {field}"
        );
    }
    let mut changed = original.clone();
    changed
        .retirement_proof
        .capability_extinction
        .as_mut()
        .unwrap()
        .current_boot_id = "later-boot".into();
    assert!(changed.validate_for_attempt().is_err());
    let mut changed = original.clone();
    changed.retirement_proof.capability_extinction = None;
    assert!(changed.validate_for_attempt().is_err());
    let mut changed = original.clone();
    changed
        .retirement_proof
        .capability_extinction
        .as_mut()
        .unwrap()
        .owner_manifest
        .entries[0]
        .process_identity = None;
    assert!(changed.validate_for_attempt().is_err());
    let mut changed = original.clone();
    changed
        .retirement_proof
        .capability_extinction
        .as_mut()
        .unwrap()
        .owner_manifest
        .entries
        .swap(0, 1);
    assert!(changed.validate_for_attempt().is_err());
    for field in [
        "target_completion_observed",
        "native_job_empty_observed",
        "relay_closure_observed",
        "guardian_completion_observed",
    ] {
        let mut changed = serde_json::to_value(&original).unwrap();
        changed["retirement_proof"][field] = true.into();
        let parsed: WindowsTerminalReceiptV2 = serde_json::from_value(changed).unwrap();
        assert!(
            parsed.validate_for_attempt().is_err(),
            "accepted invented {field}"
        );
    }
    let mut changed = original.clone();
    changed.retirement_proof.guardian_receipt_sha256 = Some("cd".repeat(32));
    assert!(changed.validate_for_attempt().is_err());
    for field in [
        "direct_child_reaped",
        "helpers_reaped",
        "sealed_boundary_retired",
    ] {
        let mut changed = serde_json::to_value(&original).unwrap();
        changed["restart_safety"][field] = true.into();
        let parsed: WindowsTerminalReceiptV2 = serde_json::from_value(changed).unwrap();
        assert!(
            parsed.validate_for_attempt().is_err(),
            "accepted invented {field}"
        );
    }
    let mut changed = original;
    changed.retirement_proof.source = WindowsRetirementProofSourceV2::GuardianRecovery;
    assert!(changed.validate_for_attempt().is_err());
}
