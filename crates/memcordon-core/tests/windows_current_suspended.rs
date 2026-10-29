use memcordon_core::*;
#[path = "support/windows_current_postauthorization.rs"]
mod fixture;

#[test]
fn unreleased_windows_boundary_requires_exact_actual_ack_and_all_preparation_gates() {
    let rejection = fixture::rejection();
    let terminal = rejection.terminal_receipt().unwrap();
    let WindowsTerminalPayloadV3::Execution {
        boundary_detail, ..
    } = &terminal.payload
    else {
        panic!("current native execution carrier required")
    };
    let BoundaryMechanismEvidence::WindowsJobObjectV3(native) = boundary_detail.as_ref() else {
        panic!("current Windows native facts required")
    };
    let mut native = native.clone();
    native.target_released = false;
    native.retirement = Some(Box::new(terminal.retirement_proof.clone()));
    native.frontend_delivery = Some(WindowsFrontendDeliveryV3 {
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        terminal_sha256: "ab".repeat(32),
        retired_sha256: "cd".repeat(32),
        terminal_validated: true,
        acknowledgement_observed: true,
    });
    let mut provider = rejection
        .provider_failure
        .as_ref()
        .unwrap()
        .provider_binding
        .clone();
    provider.generation = BoundedText::new(&terminal.retirement_proof.provider_generation).unwrap();
    native.frontend_provider_association = Some(execution_facts::ProviderAttemptAssociationV1 {
        provider,
        attempt_id: DiagnosticSha256::try_from(BoundedText::new(&terminal.attempt_id).unwrap())
            .unwrap(),
        request_sha256: DiagnosticSha256::try_from(
            BoundedText::new(&terminal.request_sha256).unwrap(),
        )
        .unwrap(),
    });
    let launch = LaunchEvidence {
        mechanism: "windows-job-object-v2".into(),
        target_released: false,
        containment_verified_before_authorization: true,
        guardian_started_before_authorization: true,
        target_spawn_error_reported: true,
        boundary_requested: BoundaryRequirement::Sealed,
        boundary_effective: BoundaryClass::Sealed,
        boundary_assignment_verified: true,
        boundary_reconfiguration_denied: true,
        inherited_resources_restricted: true,
        frontend_loss_cleanup_authority_verified: true,
    };
    let valid = |native: Box<WindowsSealedEvidenceV3>| {
        boundary_evidence_is_consistent(
            &launch,
            &terminal.restart_safety,
            &BoundaryMechanismEvidence::WindowsJobObjectV3(native),
        )
    };
    assert!(valid(native.clone()));
    let mut no_ack = native.clone();
    no_ack.frontend_delivery = None;
    assert!(!valid(no_ack));
    let mut wrong_owner = native.clone();
    wrong_owner
        .frontend_provider_association
        .as_mut()
        .unwrap()
        .provider
        .generation = BoundedText::new("another provider").unwrap();
    assert!(!valid(wrong_owner));
    let mut skipped_token = native.clone();
    skipped_token.initial_target_token_matches_caller = false;
    assert!(!valid(skipped_token));
    let mut inherited_handle = native;
    inherited_handle.inherited_handles_verified = false;
    assert!(!valid(inherited_handle));
}
