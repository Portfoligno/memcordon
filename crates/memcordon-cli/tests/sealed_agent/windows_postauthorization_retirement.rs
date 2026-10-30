use memcordon_core::{
    BoundaryMechanismEvidence, BoundarySetupPhase, ChildTermination, CleanupSummary,
    ProviderRejectionEvidence, RestartSafetyProof, RunOutcome,
    WINDOWS_CURRENT_PRIVATE_PROTOCOL_VERSION, WindowsLauncherResponseV4, WindowsProcessIdentityV1,
};

#[test]
fn terminal_seed_freezes_before_proof_and_rejects_replacement() {
    use memcordon_core::{ProcessObservationUnavailableReasonV1, WindowsProcessObservationV2};

    let digest = "c7".repeat(32);
    let target = WindowsProcessIdentityV1 {
        process_id: 417,
        creation_time_100ns: 991_342,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        target.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    record.nonce = "seed-before-final-close".to_owned();
    record.target_identity = Some(target.clone());
    record.guardian_identity = Some(target.clone());
    super::windows_v3_fixture::bind_owner_manifest(&mut record, &target);
    record.authorization_unix_millis = Some(1);
    record.state = crate::windows::record::WindowsAttemptStateV1::Terminating;
    let mut observation = WindowsProcessObservationV2::unavailable(
        ProcessObservationUnavailableReasonV1::WorkerLostBeforeFreeze,
    );
    observation.root_identity = Some(target);
    let mut stores = 0;
    record
        .freeze_terminal_seed_for_test(observation.clone(), None, |_| {
            stores += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(stores, 1);
    assert_eq!(
        record.terminal_seed.as_ref().unwrap().process_observation,
        observation
    );
    assert!(record.retirement_proof.is_none());
    let before = serde_json::to_vec(&record).unwrap();
    record
        .freeze_terminal_seed_for_test(observation, None, |_| panic!("duplicate seed store"))
        .unwrap_err();
    let after = serde_json::to_vec(&record).unwrap();
    assert_eq!(before, after);
}

#[test]
fn frozen_seed_accepts_only_matching_later_retirement_proof() {
    let digest = "c8".repeat(32);
    let target = WindowsProcessIdentityV1 {
        process_id: 418,
        creation_time_100ns: 991_343,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        target.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    record.nonce = "frozen-seed-proof".to_owned();
    record.target_identity = Some(target.clone());
    record.guardian_identity = Some(target.clone());
    record.authorization_unix_millis = Some(1);
    let rejection = super::windows_v3_fixture::postauthorization_failure(
        &mut record,
        target,
        false,
        "MCSEALED-WINDOWS-CERTIFICATION-FAULT",
        BoundarySetupPhase::Authorization,
    );
    let failure = rejection.provider_failure.unwrap();
    let memcordon_core::WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
        rejection.disposition
    else {
        panic!("fixture must contain a receipt")
    };
    record.state = crate::windows::record::WindowsAttemptStateV1::Empty;
    record.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::Retiring;
    record.retirement_proof = None;
    let mut mismatched = (*receipt).clone();
    mismatched
        .process_observation
        .root_identity
        .as_mut()
        .expect("fixture has a root identity")
        .creation_time_100ns += 1;
    let before = serde_json::to_vec(&record).unwrap();
    record
        .stage_terminal_proof_for_test(&mismatched, Some(failure.clone()), |_| {
            panic!("conflicting seed must not be stored")
        })
        .unwrap_err();
    let after_refusal = serde_json::to_vec(&record).unwrap();
    assert_eq!(before, after_refusal);
    record
        .stage_terminal_proof_for_test(&receipt, Some(failure), |_| Ok(()))
        .unwrap();
    assert_eq!(
        record.lifecycle,
        memcordon_core::WindowsTerminalLifecycleV1::ProofReady
    );
    assert_eq!(
        record.retirement_proof.as_ref(),
        Some(&receipt.retirement_proof)
    );
}

#[test]
fn suspended_postauthorization_rejection_stages_replays_and_retires_bound_outbox() {
    let digest = "9a".repeat(32);
    let nonce = "postauthorization-suspended-cancellation";
    let identity = WindowsProcessIdentityV1 {
        process_id: 412,
        creation_time_100ns: 991_337,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        identity.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    record.guardian_identity = Some(identity.clone());
    record.target_identity = Some(identity.clone());
    record.nonce = nonce.to_owned();
    super::windows_v3_fixture::bind_owner_manifest(&mut record, &identity);
    record.state = crate::windows::record::WindowsAttemptStateV1::Authorized;
    record.authorization_unix_millis = Some(1);
    record.validate_for_store_for_test().unwrap();

    record
        .begin_postauthorization_retirement_for_test()
        .unwrap();
    assert_eq!(
        record.state,
        crate::windows::record::WindowsAttemptStateV1::Terminating
    );
    assert_eq!(
        record.terminal_disposition,
        Some(crate::windows::record::WindowsAttemptTerminalDispositionV1::Posttarget)
    );
    assert!(!record.resume_attempted);
    assert!(!record.target_released);
    assert!(record.cleanup_state.termination_requested);

    record.cleanup_state.active_processes_zero = true;
    record.cleanup_state.guardian_reaped = true;
    record.complete_rejection_cleanup_for_test().unwrap();
    let rejection = super::windows_v3_fixture::postauthorization_failure(
        &mut record,
        identity,
        false,
        "MCSEALED-WINDOWS-CERTIFICATION-FAULT",
        BoundarySetupPhase::Authorization,
    );
    assert!(rejection.is_consistent());
    let mut diagnostic_expired = rejection.clone();
    diagnostic_expired.provider_failure = None;
    assert!(diagnostic_expired.is_consistent());
    let mut release_mismatch = rejection.clone();
    release_mismatch.target_released = true;
    assert!(!release_mismatch.is_consistent());

    let response = WindowsLauncherResponseV4::Reject {
        schema_version: WINDOWS_CURRENT_PRIVATE_PROTOCOL_VERSION,
        attempt_id: record.attempt_id.clone(),
        nonce: nonce.to_owned(),
        request_sha256: record.request_sha256.clone(),
        rejection,
    };
    record.stage_terminal_response_for_test(&response).unwrap();
    // Persist only this component fixture's own bytes. No installed receipt,
    // replay ledger, policy reference or acknowledgement store is accessed.
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("component-outbox.json");
    // Logical fixture validation above did not commit a previous durable image.
    record.record_revision = 0;
    crate::windows::record::publish_owned_component_record_for_test(&mut record, &path).unwrap();
    assert_eq!(record.record_revision, 1);
    let persisted = std::fs::read(&path).unwrap();
    let duplicate_refusal = record
        .stage_terminal_response_for_test(&response)
        .unwrap_err();
    assert_eq!(
        duplicate_refusal,
        "attempt is not ready for a create-once terminal outbox"
    );
    assert_eq!(std::fs::read(&path).unwrap(), persisted);
    let decode = |nonce: &str, request: &str| {
        crate::windows::record::pending_owned_component_response_for_test(
            &path,
            &record.attempt_id,
            nonce,
            request,
            &record.caller_process_identity,
            &record.caller_token_sha256,
        )
    };
    let first = decode(nonce, &record.request_sha256).unwrap().unwrap();
    let repeated = decode(nonce, &record.request_sha256).unwrap().unwrap();
    assert_eq!(
        first.terminal_authority_json().unwrap(),
        repeated.terminal_authority_json().unwrap()
    );
    decode("wrong-nonce", &record.request_sha256).unwrap_err();
    decode(nonce, &"c2".repeat(32)).unwrap_err();
    let after_refusals = std::fs::read(&path).unwrap();
    assert_eq!(after_refusals, persisted);
    let retention = record.diagnostic_retention.clone();
    let available_journal = crate::windows::record::owned_component_journal_at_for_test(
        &record,
        true,
        retention.expires_monotonic_millis - 1,
    );
    let expired_journal = crate::windows::record::owned_component_journal_at_for_test(
        &record,
        true,
        retention.expires_monotonic_millis,
    );
    assert_eq!(available_journal, record.causal_diagnostics);
    assert!(matches!(
        &expired_journal.original,
        memcordon_core::OriginalFailureV1::Unavailable {
            reason: memcordon_core::OriginalUnavailableReasonV1::RetentionExpired
        }
    ));
    assert!(expired_journal.secondary.as_slice().is_empty());
    // Projection loss at the exact fixed clock boundary cannot rewrite the
    // physically retained terminal authority or take over its ACK ownership.
    let after_expiry_projection = std::fs::read(&path).unwrap();
    assert_eq!(after_expiry_projection, persisted);
    assert_eq!(
        record.terminal_response_json.as_deref(),
        Some(response.terminal_authority_json().unwrap().as_str())
    );
    // Lose the acknowledgement response after the owned outbox and ACK ledger
    // were physically committed. Recovery must use those same named bytes.
    record.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::AckCommitted;
    crate::windows::record::publish_owned_component_record_for_test(&mut record, &path).unwrap();
    let ack_record = std::fs::read(&path).unwrap();
    let ack_path = root.path().join("component-ack.json");
    crate::windows::record::stage_owned_component_ack_for_test(&ack_path, &record).unwrap();
    let staged_ack = std::fs::read(&ack_path).unwrap();
    crate::windows::record::stage_owned_component_ack_for_test(&ack_path, &record).unwrap();
    assert_eq!(std::fs::read(&ack_path).unwrap(), staged_ack);
    let recover = |nonce: &str, caller: &WindowsProcessIdentityV1| {
        crate::windows::record::complete_owned_component_ack_for_test(
            &ack_path,
            &path,
            &record,
            nonce,
            caller,
            &record.caller_token_sha256,
        )
    };
    let active_refusal = recover(nonce, &record.caller_process_identity).unwrap_err();
    assert_eq!(
        active_refusal,
        "ACK tombstone still has a durable attempt record"
    );
    assert_eq!(std::fs::read(&ack_path).unwrap(), staged_ack);
    std::fs::remove_file(&path).unwrap();
    recover("wrong-nonce", &record.caller_process_identity).unwrap_err();
    let mut other_caller = record.caller_process_identity.clone();
    other_caller.creation_time_100ns += 1;
    recover(nonce, &other_caller).unwrap_err();
    assert_eq!(std::fs::read(&ack_path).unwrap(), staged_ack);
    let completed = recover(nonce, &record.caller_process_identity).unwrap();
    let completed_ack = std::fs::read(&ack_path).unwrap();
    let repeated_ack = recover(nonce, &record.caller_process_identity).unwrap();
    assert_eq!(completed, repeated_ack);
    assert_eq!(std::fs::read(&ack_path).unwrap(), completed_ack);

    let replayed: WindowsLauncherResponseV4 =
        serde_json::from_str(record.terminal_response_json.as_deref().unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(replayed).unwrap(),
        serde_json::from_str::<serde_json::Value>(&response.terminal_authority_json().unwrap())
            .unwrap()
    );
    let retired = record.terminal_retired_receipt(nonce).unwrap();
    assert!(record.terminal_retired_receipt("wrong-nonce").is_err());
    assert!(record.terminal_response_json.is_some());
    assert_eq!(retired.attempt_id, record.attempt_id);
    assert_eq!(retired.request_sha256, record.request_sha256);
    assert_eq!(
        retired.disposition,
        memcordon_core::WindowsAttemptTerminalDispositionV1::Posttarget
    );
}

#[test]
fn receiptless_posttarget_rejection_cannot_bypass_terminal_binding() {
    let digest = "8b".repeat(32);
    let nonce = "receiptless-posttarget-rejection";
    let identity = WindowsProcessIdentityV1 {
        process_id: 413,
        creation_time_100ns: 991_338,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        identity.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    let original = memcordon_core::CausalEventV1 {
        sequence: 0,
        origin: memcordon_core::DiagnosticOriginV1::Launcher,
        category: memcordon_core::FailureCategoryV1::Monitor,
        operation: memcordon_core::FailureOperationV1::ObserveProcessIdentity,
        code: memcordon_core::FailureCodeV1::ProcessInventoryObservation,
        native_code: Some(memcordon_core::NativeFailureCodeV1::Win32(1234)),
        observed_phase: memcordon_core::AttemptObservationPhaseV1::Monitoring,
        safe_detail: memcordon_core::SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    };
    record.causal_diagnostics.observe(original).unwrap();
    let retained_original = record.causal_diagnostics.original.clone();
    record.guardian_identity = Some(identity.clone());
    record.target_identity = Some(identity.clone());
    record.nonce = nonce.to_owned();
    super::windows_v3_fixture::bind_owner_manifest(&mut record, &identity);
    record.state = crate::windows::record::WindowsAttemptStateV1::Authorized;
    record.authorization_unix_millis = Some(1);
    record.validate_for_store_for_test().unwrap();
    record
        .begin_postauthorization_retirement_for_test()
        .unwrap();
    record.cleanup_state.active_processes_zero = true;
    record.cleanup_state.guardian_reaped = true;
    record.complete_rejection_cleanup_for_test().unwrap();

    let rejection = super::windows_v3_fixture::preauthorization_rejection(
        &record,
        "MCSEALED-WINDOWS-CERTIFICATION-FAULT",
        BoundarySetupPhase::Retirement,
        true,
    );
    assert!(rejection.is_consistent());
    let response = WindowsLauncherResponseV4::Reject {
        schema_version: WINDOWS_CURRENT_PRIVATE_PROTOCOL_VERSION,
        attempt_id: record.attempt_id.clone(),
        nonce: nonce.to_owned(),
        request_sha256: record.request_sha256.clone(),
        rejection,
    };

    let first_refusal = record
        .stage_terminal_response_for_test(&response)
        .unwrap_err();
    assert_eq!(
        first_refusal,
        "terminal outbox response is not bound and consistent for the attempt"
    );
    assert!(record.terminal_response_json.is_none());
    assert_eq!(record.causal_diagnostics.original, retained_original);
    assert!(
        record
            .stage_terminal_response_with_store_for_test(&response, |record| record
                .validate_for_store_for_test())
            .is_err()
    );
    assert_eq!(record.causal_diagnostics.original, retained_original);
    let secondary = record.causal_diagnostics.secondary.as_slice();
    assert_eq!(secondary.len(), 1);
    assert_eq!(
        secondary[0].operation,
        memcordon_core::FailureOperationV1::ValidateTerminalResponse
    );
    assert_eq!(
        secondary[0].terminalization_reference,
        Some(memcordon_core::TerminalizationReferenceV1::FirstError)
    );
    assert!(record.terminal_response_json.is_none());
}
