use memcordon_core::*;
use serde_json::Value;

#[path = "../../../../crates/memcordon-core/tests/support/windows_postauthorization.rs"]
mod postauthorization;

pub fn response(
    attempt: &str,
    nonce: &str,
    request: &str,
    provider: &Value,
    held: &Value,
) -> WindowsProviderResponseV3 {
    let mut rejection = postauthorization::rejection();
    let mut receipt = rejection.terminal_receipt().unwrap().clone();
    receipt.attempt_id = attempt.into();
    receipt.nonce = nonce.into();
    receipt.request_sha256 = request.into();
    receipt.process_observation.root_identity =
        Some(serde_json::from_value(held["live_target_identity"].clone()).unwrap());
    let manifest = WindowsCapabilityOwnerManifestV1 {
        schema_version: 1,
        attempt_id: attempt.into(),
        provider_generation: provider["generation"].as_str().unwrap().into(),
        launch_incarnation: "original-launch".into(),
        entries: std::array::from_fn(|index| {
            let role = WindowsCapabilityOwnerRoleV1::ALL[index];
            let identity = match role {
                WindowsCapabilityOwnerRoleV1::DirectTargetProcess => &held["live_target_identity"],
                WindowsCapabilityOwnerRoleV1::GuardianProcess => &held["guardian_identity"],
                _ => &held["worker_process_identity"],
            };
            WindowsCapabilityOwnerEntryV1 {
                role,
                present: role.required(),
                process_identity: role
                    .required()
                    .then(|| serde_json::from_value(identity.clone()).unwrap()),
                capability_binding_sha256: role.required().then(|| "12".repeat(32)),
            }
        }),
    };
    let proof = &mut receipt.retirement_proof;
    proof.attempt_id = attempt.into();
    proof.nonce = nonce.into();
    proof.request_sha256 = request.into();
    proof.provider_generation = manifest.provider_generation.clone();
    proof.launch_incarnation = manifest.launch_incarnation.clone();
    proof.original_boot_id = "original-native-boot".into();
    proof.job_identity = "34".repeat(32);
    proof.owner_manifest_sha256 = manifest.canonical_sha256().unwrap();
    proof.source = WindowsRetirementProofSourceV2::CapabilityExtinction;
    proof.target_completion_observed = false;
    proof.native_job_empty_observed = false;
    proof.relay_closure_observed = false;
    proof.guardian_completion_observed = false;
    proof.capability_extinction = Some(WindowsCapabilityExtinctionProofV1 {
        contract: WindowsJobClosureContractV1 {
            schema_version: 1,
            attempt_id: attempt.into(),
            nonce: nonce.into(),
            request_sha256: request.into(),
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
    receipt.validate_for_attempt().unwrap();
    let mut journal = WindowsCausalDiagnosticsV1 {
        original: OriginalFailureV1::Unavailable {
            reason: OriginalUnavailableReasonV1::WorkerLostBeforeObservation,
        },
        ..WindowsCausalDiagnosticsV1::default()
    };
    journal
        .observe_secondary(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Monitor,
            operation: FailureOperationV1::CheckGuardian,
            code: FailureCodeV1::GuardianLoss,
            native_code: None,
            observed_phase: AttemptObservationPhaseV1::Monitoring,
            safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .unwrap();
    journal.durable_through_sequence = Some(journal.sequence);
    rejection.provider_failure = Some(
        ProviderFailureDiagnosticV1::from_journal(
            serde_json::from_value(provider.clone()).unwrap(),
            attempt,
            request,
            &journal,
        )
        .unwrap(),
    );
    rejection.code = "MCSEALED-WINDOWS-OWNER-LOST".into();
    rejection.phase = BoundarySetupPhase::Retirement;
    rejection.restart_safety = receipt.restart_safety.clone();
    rejection.disposition = WindowsProviderRejectionDispositionV2::PostauthorizationFailure {
        receipt: Box::new(receipt),
    };
    assert!(rejection.is_consistent());
    WindowsProviderResponseV3::Reject {
        schema_version: 3,
        attempt_id: attempt.into(),
        nonce: nonce.into(),
        request_sha256: request.into(),
        rejection,
    }
}
