//! Strict synthetic V3 terminal fixtures for live-record transport tests.

use memcordon_core::{
    AttemptObservationPhaseV1, BoundaryMechanismEvidence, BoundarySetupPhase, CausalEventV1,
    CleanupSummary, DiagnosticOriginV1, FailureCategoryV1, FailureCodeV1, FailureOperationV1,
    ProcessObservationUnavailableReasonV1, ProviderFailureDiagnosticV1, RestartSafetyProof,
    RunOutcome, SafeDiagnosticDetailV1, WindowsCapabilityOwnerEntryV1,
    WindowsCapabilityOwnerManifestV1, WindowsCapabilityOwnerRoleV1, WindowsProcessIdentityV1,
    WindowsProcessObservationV2, WindowsProviderRejectionDispositionV2, WindowsProviderRejectionV2,
    WindowsRetirementProofSourceV2, WindowsRetirementProofV2, WindowsSealedEvidenceV2,
    WindowsTerminalPayloadV2, WindowsTerminalReceiptV2, WindowsTerminalSeedV2,
};

pub fn bind_owner_manifest(
    record: &mut crate::windows::record::WindowsAttemptRecordV1,
    target: &WindowsProcessIdentityV1,
) {
    let entries = std::array::from_fn(|index| {
        let role = WindowsCapabilityOwnerRoleV1::ALL[index];
        WindowsCapabilityOwnerEntryV1 {
            role,
            present: role.required(),
            process_identity: match role {
                WindowsCapabilityOwnerRoleV1::DirectTargetProcess => Some(target.clone()),
                WindowsCapabilityOwnerRoleV1::GuardianProcess => record.guardian_identity.clone(),
                _ => None,
            },
            capability_binding_sha256: role.required().then(|| "ab".repeat(32)),
        }
    });
    record.owner_manifest = Some(WindowsCapabilityOwnerManifestV1 {
        schema_version: 1,
        attempt_id: record.attempt_id.clone(),
        provider_generation: record.provider_generation.clone(),
        launch_incarnation: record.launch_incarnation.clone(),
        entries,
    });
    record.recovery_authorization = Some(memcordon_core::WindowsRecoveryAuthorizationV1 {
        schema_version: 1,
        user_sid: "S-1-5-21-1".to_owned(),
        launch_logon_identity: 1,
        launch_token_binding_sha256: "ab".repeat(32),
        recovery_access_floor: memcordon_core::WindowsRecoveryAccessFloorV1 {
            integrity_level: "S-1-16-8192".to_owned(),
            elevated: false,
            restricted: false,
            restricted_sids_sha256: None,
            appcontainer: false,
            appcontainer_binding_sha256: None,
        },
        policy: memcordon_core::WindowsRecoveryPolicyV1::SameOwnerBootSensitive,
    });
    record.worker_identity = Some(target.clone());
    record.terminal_publication_reserved = true;
}

pub fn preauthorization_rejection(
    _record: &crate::windows::record::WindowsAttemptRecordV1,
    code: &str,
    phase: BoundarySetupPhase,
    target_created: bool,
) -> WindowsProviderRejectionV2 {
    WindowsProviderRejectionV2 {
        schema_version: 2,
        workload_admission: None,
        provider_failure: None,
        code: code.to_owned(),
        phase,
        detail: "synthetic preauthorization failure".to_owned(),
        os_code: Some(5),
        loader_qualification: None,
        target_created,
        target_released: false,
        cleanup_attempted: true,
        restart_safety: safe_restart(),
        disposition: WindowsProviderRejectionDispositionV2::Preauthorization {
            terminal_ack_required: true,
        },
    }
}

pub fn postauthorization_failure(
    record: &mut crate::windows::record::WindowsAttemptRecordV1,
    target: WindowsProcessIdentityV1,
    target_released: bool,
    code: &str,
    phase: BoundarySetupPhase,
) -> WindowsProviderRejectionV2 {
    bind_owner_manifest(record, &target);
    let mut journal = memcordon_core::WindowsCausalDiagnosticsV1::default();
    journal
        .observe(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Launch,
            operation: FailureOperationV1::ResumeTarget,
            code: FailureCodeV1::TargetResume,
            native_code: Some(memcordon_core::NativeFailureCodeV1::Win32(5)),
            observed_phase: AttemptObservationPhaseV1::AuthorizedBeforeResume,
            safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .expect("synthetic primary is valid");
    journal.durable_through_sequence = Some(journal.sequence);
    let binding: memcordon_core::PublicProviderBindingV1 =
        serde_json::from_value(serde_json::json!({
            "generation": "fixture-generation",
            "source_commit": "ab".repeat(20),
            "runtime_manifest_sha256": "cd".repeat(32),
        }))
        .expect("synthetic provider binding is valid");
    let failure = ProviderFailureDiagnosticV1::from_journal(
        binding,
        &record.attempt_id,
        &record.request_sha256,
        &journal,
    )
    .expect("synthetic original failure projects");
    let mut observation = WindowsProcessObservationV2::unavailable(
        ProcessObservationUnavailableReasonV1::WorkerLostBeforeFreeze,
    );
    observation.root_identity = Some(target.clone());
    let manifest_sha256 = record
        .owner_manifest
        .as_ref()
        .expect("manifest is bound")
        .canonical_sha256()
        .expect("manifest is canonical");
    let proof = WindowsRetirementProofV2 {
        schema_version: 2,
        source: WindowsRetirementProofSourceV2::LiveNative,
        attempt_id: record.attempt_id.clone(),
        nonce: record.nonce.clone(),
        request_sha256: record.request_sha256.clone(),
        provider_generation: record.provider_generation.clone(),
        launch_incarnation: record.launch_incarnation.clone(),
        original_boot_id: record.boot_identity.clone(),
        job_identity: record.job_identity_sha256.clone(),
        owner_manifest_sha256: manifest_sha256,
        guardian_receipt_sha256: None,
        current_boot_id: None,
        target_completion_observed: true,
        native_job_empty_observed: true,
        relay_closure_observed: true,
        guardian_completion_observed: true,
        owner_capabilities_closed: true,
        launch_gate_closed: true,
        policy_reference_bound: true,
    };
    let restart_safety = safe_restart();
    let receipt = WindowsTerminalReceiptV2 {
        policy_enforcement: None,
        schema_version: 2,
        attempt_id: record.attempt_id.clone(),
        nonce: record.nonce.clone(),
        request_sha256: record.request_sha256.clone(),
        payload: WindowsTerminalPayloadV2::Execution {
            child_pid: target.process_id,
            duration_millis: 2,
            authorization_offset_millis: 1,
            outcome: RunOutcome::MonitorFailed {
                error: code.to_owned(),
                child_after_termination: None,
                cleanup: CleanupSummary {
                    force_attempted: true,
                    direct_child_reaped: true,
                    workload_empty: Some(true),
                    ..CleanupSummary::default()
                },
            },
            boundary_detail: Box::new(BoundaryMechanismEvidence::WindowsJobObjectV2(Box::new(
                WindowsSealedEvidenceV2 {
                    target_released,
                    terminate_job_invoked: true,
                    active_processes_zero: true,
                    direct_target_reaped: true,
                    relays_retired: true,
                    guardian_reaped: true,
                    final_job_handles_closed: true,
                    ..WindowsSealedEvidenceV2::default()
                },
            ))),
        },
        process_observation: observation.clone(),
        cleanup_process_creation: None,
        restart_safety: restart_safety.clone(),
        retirement_proof: proof.clone(),
    };
    record.terminal_seed = Some(WindowsTerminalSeedV2 {
        schema_version: 2,
        attempt_id: record.attempt_id.clone(),
        nonce: record.nonce.clone(),
        request_sha256: record.request_sha256.clone(),
        process_observation: observation,
        primary_failure: Some(failure.clone()),
    });
    record.retirement_proof = Some(proof);
    record.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::ProofReady;
    let rejection = WindowsProviderRejectionV2 {
        schema_version: 2,
        workload_admission: None,
        provider_failure: Some(failure),
        code: code.to_owned(),
        phase,
        detail: "synthetic postauthorization failure".to_owned(),
        os_code: Some(5),
        loader_qualification: None,
        target_created: true,
        target_released,
        cleanup_attempted: true,
        restart_safety,
        disposition: WindowsProviderRejectionDispositionV2::PostauthorizationFailure {
            receipt: Box::new(receipt),
        },
    };
    assert!(rejection.is_consistent());
    rejection
}

fn safe_restart() -> RestartSafetyProof {
    RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: true,
        errors: Vec::new(),
    }
}
