use memcordon_ci::windows_component_failed_recovery::{
    RecoveryBinding, pending_original_frontend_relay, worker_loss_recovery_authority,
};
use memcordon_core::*;

#[path = "../../../crates/memcordon-core/tests/support/windows_postauthorization.rs"]
mod support;

fn held() -> WindowsGuardianAttemptObservation {
    WindowsGuardianAttemptObservation {
        format: "memcordon.windows-live-guardian-observation".into(),
        revision: 1,
        live_nonce: Some("b".repeat(32)),
        worker_process_identity: Some(WindowsProcessIdentityV1 {
            process_id: 43,
            creation_time_100ns: 1235,
        }),
        worker_thread_identity: Some(WindowsWorkerThreadIdentityV1 {
            thread_id: 44,
            creation_time_100ns: 1236,
        }),
        live_target_identity: Some(WindowsProcessIdentityV1 {
            process_id: 45,
            creation_time_100ns: 1237,
        }),
        challenge: BoundedText::new("original-native-query").unwrap(),
        guardian_identity: WindowsProcessIdentityV1 {
            process_id: 42,
            creation_time_100ns: 1234,
        },
        association: result_v1::ProviderAttemptAssociationV1 {
            provider: PublicProviderBindingV1 {
                generation: BoundedText::new("provider-generation").unwrap(),
                source_commit: BoundedText::new("c21430372b4c7b37982259f93aac757f605b7f35")
                    .unwrap(),
                runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
            },
            attempt_id: DiagnosticSha256::from_bytes([2; 32]),
            request_sha256: DiagnosticSha256::from_bytes([3; 32]),
        },
    }
}

fn retired(binding: &RecoveryBinding) -> WindowsTerminalRetiredV2 {
    WindowsTerminalRetiredV2 {
        schema_version: 2,
        attempt_id: binding.attempt.clone(),
        nonce: binding.nonce.clone(),
        request_sha256: binding.request.clone(),
        terminal_response_sha256: "d".repeat(64),
        disposition: WindowsAttemptTerminalDispositionV1::Posttarget,
        provider_generation: "provider-generation".into(),
        original_boot_id: "boot".into(),
        launch_incarnation: "launch".into(),
        job_identity: "e".repeat(64),
        owner_manifest_sha256: "f".repeat(64),
        retirement_proof_sha256: "0".repeat(64),
        preauthorization_retirement_proof: None,
        ledger_generation: "1".repeat(64),
        completion: WindowsRetirementLedgerCompletionV1::RetirementComplete,
    }
}

fn worker_recovery() -> (WindowsGuardianAttemptObservation, WindowsProviderResponseV3) {
    let mut rejection = support::rejection();
    let provider = rejection
        .provider_failure
        .as_ref()
        .unwrap()
        .provider_binding
        .clone();
    rejection.provider_failure = None; // Expirable diagnostics are not terminal authority.
    rejection.code = "MCSEALED-WINDOWS-OWNER-LOST".into();
    rejection.phase = BoundarySetupPhase::Retirement;
    let WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } =
        &mut rejection.disposition
    else {
        unreachable!()
    };
    receipt.payload = WindowsTerminalPayloadV2::RecoveredClosure {
        primary_failure: OriginalFailureV1::Unavailable {
            reason: OriginalUnavailableReasonV1::WorkerLostBeforeObservation,
        },
        target_creation_observed: true,
        resume_attempted: true,
    };
    receipt.retirement_proof.source = WindowsRetirementProofSourceV2::GuardianRecovery;
    receipt.retirement_proof.target_completion_observed = false;
    let mut original = held();
    original.association.provider = provider;
    original.association.attempt_id =
        DiagnosticSha256::try_from(BoundedText::new(&receipt.attempt_id).unwrap()).unwrap();
    original.association.request_sha256 =
        DiagnosticSha256::try_from(BoundedText::new(&receipt.request_sha256).unwrap()).unwrap();
    original.live_nonce = Some(receipt.nonce.clone());
    original.live_target_identity = receipt.process_observation.root_identity.clone();
    let proof = &receipt.retirement_proof;
    let mut guardian = WindowsGuardianReceiptV2 {
        schema_version: 2,
        attempt_id: receipt.attempt_id.clone(),
        nonce: receipt.nonce.clone(),
        request_sha256: receipt.request_sha256.clone(),
        provider_generation: proof.provider_generation.clone(),
        launch_incarnation: proof.launch_incarnation.clone(),
        original_boot_id: proof.original_boot_id.clone(),
        job_identity: proof.job_identity.clone(),
        owner_manifest_sha256: proof.owner_manifest_sha256.clone(),
        guardian_identity: original.guardian_identity.clone(),
        worker_identity: original.worker_process_identity.clone().unwrap(),
        termination_requested: true,
        native_job_query_succeeded: true,
        active_processes_zero_observed: true,
        cleanup_trigger: Some(WindowsGuardianCleanupTriggerV1::WorkerLost),
        observed_unix_millis: 1,
        integrity_sha256: String::new(),
    };
    guardian.integrity_sha256 = guardian.canonical_sha256().unwrap();
    receipt.retirement_proof.guardian_receipt_sha256 = Some(guardian.integrity_sha256.clone());
    rejection.guardian_causal_receipt = Some(Box::new(guardian));
    assert!(rejection.is_consistent());
    let response = WindowsProviderResponseV3::Reject {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        attempt_id: String::from(original.association.attempt_id.clone()),
        nonce: original.live_nonce.clone().unwrap(),
        request_sha256: String::from(original.association.request_sha256.clone()),
        rejection,
    };
    (original, response)
}

#[test]
fn selected_worker_loss_requires_original_native_cause_and_receipt_digest() {
    let (original, response) = worker_recovery();
    let provider = &original.association.provider;
    assert!(worker_loss_recovery_authority(&response, &original, provider).unwrap());
    for mutate in [
        |guardian: &mut WindowsGuardianReceiptV2| {
            guardian.cleanup_trigger = Some(WindowsGuardianCleanupTriggerV1::ServiceStopped)
        },
        |guardian: &mut WindowsGuardianReceiptV2| {
            guardian.guardian_identity.creation_time_100ns += 1
        },
        |guardian: &mut WindowsGuardianReceiptV2| guardian.worker_identity.creation_time_100ns += 1,
    ] {
        let mut changed = response.clone();
        let WindowsProviderResponseV3::Reject { rejection, .. } = &mut changed else {
            unreachable!()
        };
        let guardian = rejection.guardian_causal_receipt.as_mut().unwrap();
        mutate(guardian);
        guardian.integrity_sha256 = guardian.canonical_sha256().unwrap();
        let hash = guardian.integrity_sha256.clone();
        let WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } =
            &mut rejection.disposition
        else {
            unreachable!()
        };
        receipt.retirement_proof.guardian_receipt_sha256 = Some(hash);
        assert!(rejection.is_consistent());
        assert!(!worker_loss_recovery_authority(&changed, &original, provider).unwrap());
    }
    let mut changed = response.clone();
    let WindowsProviderResponseV3::Reject { rejection, .. } = &mut changed else {
        unreachable!()
    };
    let WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } =
        &mut rejection.disposition
    else {
        unreachable!()
    };
    receipt.retirement_proof.guardian_receipt_sha256 = Some("a".repeat(64));
    assert!(!worker_loss_recovery_authority(&changed, &original, provider).unwrap());
    let binding = RecoveryBinding::from_held(&original, provider).unwrap();
    assert!(
        !worker_loss_recovery_authority(
            &WindowsProviderResponseV3::TargetAuthorized {
                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                attempt_id: binding.attempt.clone(),
                nonce: binding.nonce.clone(),
                request_sha256: binding.request.clone(),
                child_pid: original.live_target_identity.as_ref().unwrap().process_id,
                control_site: None,
            },
            &original,
            provider,
        )
        .unwrap()
    );
    assert!(
        !worker_loss_recovery_authority(
            &WindowsProviderResponseV3::TerminalRetiredV2(retired(&binding)),
            &original,
            provider
        )
        .unwrap()
    );
}

#[test]
fn retry_requires_exact_original_frontend_relay_pending_response() {
    let original = held();
    let provider = &original.association.provider;
    let binding = RecoveryBinding::from_held(&original, provider).unwrap();
    let frontend = WindowsProcessIdentityV1 {
        process_id: 46,
        creation_time_100ns: 1238,
    };
    let request = WindowsProviderRequestV3::RecoverAttempt {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        attempt_id: binding.attempt.clone(),
        nonce: binding.nonce.clone(),
        request_sha256: binding.request.clone(),
        challenge: "actual-command-challenge".into(),
    };
    let response = WindowsProviderResponseV3::RecoveryAttemptUnavailable {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        attempt_id: binding.attempt.clone(), challenge: "actual-command-challenge".into(),
        detail: "exact recovery pending checked closure: frozen owner remains live without checked owner retirement; role=FrontendRelay; pid=46; birth=1238".into(),
    };
    let wrapper = serde_json::json!({"schema_version":1,"provider_request":request,"provider_response":response,"frontend_delivery":null});
    assert!(
        pending_original_frontend_relay(&wrapper, &original, provider, &frontend, Some(1)).unwrap()
    );
    for status in [Some(0), Some(2), None] {
        assert!(
            !pending_original_frontend_relay(&wrapper, &original, provider, &frontend, status)
                .unwrap()
        );
    }
    for (pointer, value) in [
        ("/schema_version", serde_json::json!(2)),
        ("/provider_request/schema_version", serde_json::json!(0)),
        ("/provider_response/schema_version", serde_json::json!(0)),
        (
            "/provider_request/attempt_id",
            serde_json::json!("a".repeat(64)),
        ),
        ("/provider_request/nonce", serde_json::json!("a".repeat(32))),
        (
            "/provider_request/request_sha256",
            serde_json::json!("a".repeat(64)),
        ),
        (
            "/provider_response/attempt_id",
            serde_json::json!("a".repeat(64)),
        ),
        (
            "/provider_response/challenge",
            serde_json::json!("another-command"),
        ),
        (
            "/provider_response/detail",
            serde_json::json!("exact recovery authority remains retained pending checked closure"),
        ),
        (
            "/provider_response/detail",
            serde_json::json!(
                "exact recovery pending checked closure: frozen owner remains live without checked owner retirement; role=LauncherJob; pid=46; birth=1238"
            ),
        ),
        (
            "/provider_response/detail",
            serde_json::json!(
                "exact recovery pending checked closure: frozen owner remains live without checked owner retirement; role=FrontendRelay; pid=47; birth=1238"
            ),
        ),
        (
            "/provider_response/detail",
            serde_json::json!(
                "exact recovery pending checked closure: frozen owner remains live without checked owner retirement; role=FrontendRelay; pid=46; birth=1239"
            ),
        ),
        (
            "/frontend_delivery",
            serde_json::json!({"retired_confirmed":true}),
        ),
    ] {
        let mut changed = wrapper.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            !pending_original_frontend_relay(&changed, &original, provider, &frontend, Some(1))
                .unwrap(),
            "accepted changed {pointer}"
        );
    }
    let mut missing = wrapper;
    missing.as_object_mut().unwrap().remove("frontend_delivery");
    assert!(
        !pending_original_frontend_relay(&missing, &original, provider, &frontend, Some(1))
            .unwrap()
    );
}

#[test]
fn settlement_requires_original_held_provider_and_nonce() {
    let original = held();
    let provider = original.association.provider.clone();
    RecoveryBinding::from_held(&original, &provider).unwrap();
    let mut wrong = provider.clone();
    wrong.generation = BoundedText::new("another-provider").unwrap();
    assert!(RecoveryBinding::from_held(&original, &wrong).is_err());
    let mut missing = original.clone();
    missing.live_nonce = None;
    assert!(RecoveryBinding::from_held(&missing, &provider).is_err());
    for mutate in [
        |value: &mut WindowsGuardianAttemptObservation| value.worker_process_identity = None,
        |value: &mut WindowsGuardianAttemptObservation| value.worker_thread_identity = None,
        |value: &mut WindowsGuardianAttemptObservation| value.live_target_identity = None,
        |value: &mut WindowsGuardianAttemptObservation| {
            value.worker_thread_identity.as_mut().unwrap().thread_id = 0
        },
        |value: &mut WindowsGuardianAttemptObservation| {
            value
                .live_target_identity
                .as_mut()
                .unwrap()
                .creation_time_100ns = 0
        },
    ] {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(RecoveryBinding::from_held(&changed, &provider).is_err());
    }
    let mut invalid = original;
    invalid.guardian_identity.creation_time_100ns = 0;
    assert!(RecoveryBinding::from_held(&invalid, &provider).is_err());
}

#[test]
fn acknowledged_retirement_is_settlement_only_and_cannot_cross_attempts() {
    let original = held();
    let binding = RecoveryBinding::from_held(&original, &original.association.provider).unwrap();
    let receipt = retired(&binding);
    let mut invalid_completion = serde_json::to_value(&receipt).unwrap();
    invalid_completion["completion"] = serde_json::json!("retirement-incomplete");
    assert!(serde_json::from_value::<WindowsTerminalRetiredV2>(invalid_completion).is_err());
    binding
        .validate_response(&WindowsProviderResponseV3::TerminalRetiredV2(
            receipt.clone(),
        ))
        .unwrap();
    for mutate in [
        |value: &mut WindowsTerminalRetiredV2| value.attempt_id = "a".repeat(64),
        |value: &mut WindowsTerminalRetiredV2| value.nonce = "a".repeat(32),
        |value: &mut WindowsTerminalRetiredV2| value.request_sha256 = "a".repeat(64),
        |value: &mut WindowsTerminalRetiredV2| value.provider_generation = "another".into(),
        |value: &mut WindowsTerminalRetiredV2| value.schema_version = 1,
        |value: &mut WindowsTerminalRetiredV2| value.retirement_proof_sha256.clear(),
    ] {
        let mut changed = receipt.clone();
        mutate(&mut changed);
        assert!(
            binding
                .validate_response(&WindowsProviderResponseV3::TerminalRetiredV2(changed))
                .is_err()
        );
    }
}

#[test]
fn terminal_receipt_requires_matching_outer_rejection_and_complete_proof() {
    let rejection = support::rejection();
    let receipt = rejection.terminal_receipt().unwrap().clone();
    let mut original = held();
    original.association.provider = rejection
        .provider_failure
        .as_ref()
        .unwrap()
        .provider_binding
        .clone();
    original.association.attempt_id =
        DiagnosticSha256::try_from(BoundedText::new(&receipt.attempt_id).unwrap()).unwrap();
    original.association.request_sha256 =
        DiagnosticSha256::try_from(BoundedText::new(&receipt.request_sha256).unwrap()).unwrap();
    original.live_nonce = Some(receipt.nonce.clone());
    let binding = RecoveryBinding::from_held(&original, &original.association.provider).unwrap();
    binding
        .validate_response(&WindowsProviderResponseV3::Terminal(receipt.clone()))
        .unwrap();
    let response = |attempt: String, nonce: String, request: String, schema_version: u32| {
        WindowsProviderResponseV3::Reject {
            schema_version,
            attempt_id: attempt,
            nonce,
            request_sha256: request,
            rejection: rejection.clone(),
        }
    };
    binding
        .validate_response(&response(
            binding.attempt.clone(),
            binding.nonce.clone(),
            binding.request.clone(),
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
        ))
        .unwrap();
    for changed in [
        response(
            "a".repeat(64),
            binding.nonce.clone(),
            binding.request.clone(),
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
        ),
        response(
            binding.attempt.clone(),
            "a".repeat(32),
            binding.request.clone(),
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
        ),
        response(
            binding.attempt.clone(),
            binding.nonce.clone(),
            "a".repeat(64),
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
        ),
        response(
            binding.attempt.clone(),
            binding.nonce.clone(),
            binding.request.clone(),
            0,
        ),
    ] {
        assert!(binding.validate_response(&changed).is_err());
    }
    let mut incomplete = receipt;
    incomplete.retirement_proof.provider_generation = "another".into();
    assert!(
        binding
            .validate_response(&WindowsProviderResponseV3::Terminal(incomplete))
            .is_err()
    );
    assert!(
        binding
            .validate_response(&WindowsProviderResponseV3::RecoveryAttemptUnavailable {
                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                challenge: "fresh".into(),
                attempt_id: binding.attempt.clone(),
                detail: "exact recovery authority remains retained pending checked closure".into(),
            })
            .is_err()
    );
}
