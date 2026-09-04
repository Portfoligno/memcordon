use memcordon_core::{
    WindowsLoaderCleanupOutcomeV1, WindowsLoaderCleanupStatusV1,
    WindowsLoaderQualificationFailureV2, WindowsLoaderQualificationOutcomeV2,
    WindowsLoaderQualificationStageV2, WindowsLoaderReadyEvidenceV1, WindowsQualificationReceiptV1,
};
use memcordon_windows_launch_core::{
    DesktopBindingV1, ExactHandleListV1, PreparedEnvironmentIdentityV1,
    ProductionLoaderPlanInputV1, ProductionLoaderPlanV1, TargetTokenIdentityV1,
    build_package_loader_plan,
};
use tempfile::TempDir;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn plan() -> ProductionLoaderPlanV1 {
    build_package_loader_plan(ProductionLoaderPlanInputV1 {
        executable_path_utf16: r"C:\Program Files\MemCordon\bootstrap.exe"
            .encode_utf16()
            .collect(),
        executable_sha256: DIGEST_A.to_owned(),
        command_line_sha256: DIGEST_B.to_owned(),
        environment: PreparedEnvironmentIdentityV1 {
            encoding: "utf-16le-double-nul".to_owned(),
            byte_len: 42,
            sha256: DIGEST_A.to_owned(),
        },
        current_directory_sha256: DIGEST_B.to_owned(),
        desktop: DesktopBindingV1 {
            exact_name: "MemCordon\\Qualification".to_owned(),
            security_descriptor_sha256: DIGEST_A.to_owned(),
            window_station_security_descriptor_sddl: "D:P(A;;GA;;;SY)".to_owned(),
            desktop_security_descriptor_sddl: "D:P(A;;GA;;;SY)".to_owned(),
        },
        process_security_descriptor_sddl: "D:P(A;;GA;;;SY)".to_owned(),
        thread_security_descriptor_sddl: "D:P(A;;GA;;;SY)".to_owned(),
        job_security_descriptor_sddl: "D:P(A;;GA;;;SY)".to_owned(),
        loader_ready_pipe_security_descriptor_sddl: "D:P(A;;GA;;;SY)".to_owned(),
        target_token: TargetTokenIdentityV1 {
            envelope_sha256: DIGEST_B.to_owned(),
            authentication_id: 7,
            session_id: 0,
        },
        inherited_handles: ExactHandleListV1::none(),
        job_at_creation: true,
    })
    .expect("fixture plan must be valid")
}

fn ready_outcome(plan: &ProductionLoaderPlanV1) -> WindowsLoaderQualificationOutcomeV2 {
    WindowsLoaderQualificationOutcomeV2::Ready(WindowsLoaderReadyEvidenceV1 {
        schema_version: 1,
        launch_plan_sha256: plan.launch_plan_sha256().to_owned(),
        launch_plan_json: Some(serde_json::to_string(plan).unwrap()),
        elapsed_millis: 1,
    })
}

fn failed_outcome(plan: &ProductionLoaderPlanV1) -> WindowsLoaderQualificationOutcomeV2 {
    WindowsLoaderQualificationOutcomeV2::Failed(WindowsLoaderQualificationFailureV2 {
        schema_version: 2,
        stable_code: "MCSEALED-WINDOWS-LOADER-PROCESS-CREATE".to_owned(),
        stage: WindowsLoaderQualificationStageV2::ProcessCreate,
        native_status: None,
        elapsed_millis: 1,
        launch_plan_sha256: Some(plan.launch_plan_sha256().to_owned()),
        launch_plan_json: Some(serde_json::to_string(plan).unwrap()),
        qualification_id: "qualification-export-fixture".to_owned(),
        cleanup: WindowsLoaderCleanupOutcomeV1 {
            status: WindowsLoaderCleanupStatusV1::Complete,
            stable_code: None,
        },
        diagnostic_id: None,
        detail: "production loader create failed".to_owned(),
    })
}

fn qualified_receipt(
    outcome: WindowsLoaderQualificationOutcomeV2,
) -> WindowsQualificationReceiptV1 {
    WindowsQualificationReceiptV1 {
        schema_version: memcordon_core::WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        provider_identity: format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        ),
        control_service_identity: "MemCordonSealedControl:LocalService:restricted".to_owned(),
        launcher_service_identity: "MemCordonSealedLauncher:LocalSystem:restricted".to_owned(),
        guardian_pool_identity: "MemCordonSealedGuardian-000..007:LocalSystem:restricted:demand"
            .to_owned(),
        package_verified: true,
        public_pipe_security_verified: true,
        private_pipe_security_verified: true,
        control_service_privileges_verified: true,
        launcher_service_privileges_verified: true,
        guardian_slot_tokens_verified: true,
        guardian_slot_loader_verified: true,
        guardian_capacity_verified: true,
        caller_token_authentication_verified: true,
        restricted_caller_token_verified: true,
        primary_token_duplication_verified: true,
        create_process_as_user_verified: true,
        job_list_supported: true,
        handle_list_supported: true,
        nested_host_job_supported: true,
        kill_on_close_verified: true,
        breakaway_denied: true,
        completion_port_verified: true,
        guardian_verified: true,
        frontend_loss_cleanup_verified: true,
        alternate_token_child_contained: true,
        nested_child_job_contained: true,
        recursive_provider_request_denied: true,
        exact_handle_inheritance_verified: true,
        active_processes_zero_verified: true,
        relays_retired_verified: true,
        recovery_complete: true,
        loader_qualification: outcome,
        qualified: true,
    }
}

fn qualification_draft(
    outcome: WindowsLoaderQualificationOutcomeV2,
) -> WindowsQualificationReceiptV1 {
    let mut receipt = qualified_receipt(outcome);
    receipt.recovery_complete = false;
    receipt.qualified = false;
    assert!(receipt.is_consistent());
    receipt
}

#[test]
fn admission_end_ack_precedes_recovery_proof_and_receipt_persistence() {
    let plan = plan();
    let outcome = ready_outcome(&plan);
    let events = std::cell::RefCell::new(Vec::new());
    let admission_live = std::cell::Cell::new(true);

    let receipt = crate::windows::qualification::finalize_qualification_after_admission_for_test(
        qualification_draft(outcome.clone()),
        || {
            assert!(admission_live.replace(false));
            events.borrow_mut().push("qualification-ended");
            Ok(())
        },
        || {
            assert!(!admission_live.get());
            assert_eq!(&*events.borrow(), &["qualification-ended"]);
            events.borrow_mut().push("recovery-empty");
            Ok(true)
        },
        |receipt| {
            assert!(receipt.recovery_complete);
            assert!(receipt.qualified);
            assert!(receipt.is_consistent());
            assert_eq!(receipt.loader_qualification, outcome);
            assert_eq!(
                &*events.borrow(),
                &["qualification-ended", "recovery-empty"]
            );
            events.borrow_mut().push("receipt-stored");
            Ok(())
        },
    )
    .unwrap();

    assert!(receipt.recovery_complete);
    assert!(receipt.qualified);
    assert!(receipt.is_consistent());
    assert_eq!(
        &*events.borrow(),
        &["qualification-ended", "recovery-empty", "receipt-stored"]
    );
}

#[test]
fn live_recovery_state_is_rejected_before_receipt_persistence() {
    let plan = plan();
    let outcome = ready_outcome(&plan);
    let persisted = std::cell::Cell::new(false);

    let (detail, retained_outcome) =
        crate::windows::qualification::finalize_qualification_after_admission_for_test(
            qualification_draft(outcome.clone()),
            || Ok(()),
            || Ok(false),
            |_| {
                persisted.set(true);
                Ok(())
            },
        )
        .unwrap_err();

    assert!(detail.contains("active attempt or admission state"));
    assert!(!persisted.get());
    assert_eq!(retained_outcome, Some(outcome));
}

#[test]
fn inconsistent_final_receipt_is_rejected_before_persistence() {
    let plan = plan();
    let outcome = ready_outcome(&plan);
    let mut draft = qualification_draft(outcome.clone());
    draft.package_verified = false;
    let persisted = std::cell::Cell::new(false);

    let (detail, retained_outcome) =
        crate::windows::qualification::finalize_qualification_after_admission_for_test(
            draft,
            || Ok(()),
            || Ok(true),
            |_| {
                persisted.set(true);
                Ok(())
            },
        )
        .unwrap_err();

    assert!(detail.contains("qualified consistent receipt"));
    assert!(!persisted.get());
    assert_eq!(retained_outcome, Some(outcome));
}

#[test]
fn ready_evidence_survives_admission_retirement_failure() {
    let plan = plan();
    let outcome = ready_outcome(&plan);
    let recovery_observed = std::cell::Cell::new(false);
    let persisted = std::cell::Cell::new(false);

    let (detail, retained_outcome) =
        crate::windows::qualification::finalize_qualification_after_admission_for_test(
            qualification_draft(outcome.clone()),
            || Err("QualificationEnded was not acknowledged".to_owned()),
            || {
                recovery_observed.set(true);
                Ok(true)
            },
            |_| {
                persisted.set(true);
                Ok(())
            },
        )
        .unwrap_err();

    assert!(detail.contains("QualificationEnded was not acknowledged"));
    assert!(!recovery_observed.get());
    assert!(!persisted.get());
    assert_eq!(retained_outcome, Some(outcome));
}

#[test]
fn ready_evidence_survives_receipt_persistence_failure() {
    let plan = plan();
    let outcome = ready_outcome(&plan);
    let persisted_qualified_receipt = std::cell::Cell::new(false);

    let (detail, retained_outcome) =
        crate::windows::qualification::finalize_qualification_after_admission_for_test(
            qualification_draft(outcome.clone()),
            || Ok(()),
            || Ok(true),
            |receipt| {
                persisted_qualified_receipt
                    .set(receipt.recovery_complete && receipt.qualified && receipt.is_consistent());
                Err("durable receipt write failed".to_owned())
            },
        )
        .unwrap_err();

    assert!(detail.contains("durable receipt write failed"));
    assert!(persisted_qualified_receipt.get());
    assert_eq!(retained_outcome, Some(outcome));
}

#[test]
fn failed_qualification_exports_in_memory_plan_and_outcome() {
    let directory = TempDir::new().unwrap();
    let plan = plan();
    let outcome = failed_outcome(&plan);

    crate::windows::package::export_typed_production_qualification_artifacts_for_test(
        directory.path(),
        &outcome,
        None,
    )
    .unwrap();
    let mut expected_outcome = outcome.clone();
    expected_outcome.clear_launch_plan_json();

    let exported_plan: ProductionLoaderPlanV1 = serde_json::from_slice(
        &std::fs::read(directory.path().join("production-loader-plan-v1.json")).unwrap(),
    )
    .unwrap();
    let exported_outcome: WindowsLoaderQualificationOutcomeV2 = serde_json::from_slice(
        &std::fs::read(directory.path().join("production-loader-result-v2.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(exported_plan, plan);
    assert_eq!(exported_outcome, expected_outcome);
    assert!(exported_outcome.launch_plan_json().is_none());
    assert!(!directory.path().join("qualification.json").exists());
}

#[test]
fn qualified_receipt_is_exported_unchanged_with_a_detached_outcome() {
    let directory = TempDir::new().unwrap();
    let plan = plan();
    let outcome = ready_outcome(&plan);
    let receipt = qualified_receipt(outcome.clone());
    assert!(receipt.is_consistent());

    crate::windows::package::export_typed_production_qualification_artifacts_for_test(
        directory.path(),
        &outcome,
        Some(&receipt),
    )
    .unwrap();
    let mut expected_outcome = outcome.clone();
    expected_outcome.clear_launch_plan_json();

    let exported_receipt: WindowsQualificationReceiptV1 = serde_json::from_slice(
        &std::fs::read(directory.path().join("qualification.json")).unwrap(),
    )
    .unwrap();
    let exported_outcome: WindowsLoaderQualificationOutcomeV2 = serde_json::from_slice(
        &std::fs::read(directory.path().join("production-loader-result-v2.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(exported_receipt, receipt);
    assert_eq!(
        serde_json::to_vec(&exported_receipt).unwrap(),
        serde_json::to_vec(&receipt).unwrap()
    );
    let mut detached_receipt = receipt.clone();
    detached_receipt
        .loader_qualification
        .clear_launch_plan_json();
    assert_ne!(
        serde_json::to_vec(&exported_receipt).unwrap(),
        serde_json::to_vec(&detached_receipt).unwrap()
    );
    assert_eq!(
        exported_receipt.loader_qualification.launch_plan_json(),
        outcome.launch_plan_json()
    );
    assert_eq!(exported_outcome, expected_outcome);
    assert!(exported_outcome.launch_plan_json().is_none());
}

#[test]
fn failed_qualification_reports_external_export_failure() {
    let directory = TempDir::new().unwrap();
    std::fs::create_dir(directory.path().join("production-loader-plan-v1.json")).unwrap();
    let plan = plan();
    let outcome = failed_outcome(&plan);

    let error = crate::windows::package::export_typed_production_qualification_artifacts_for_test(
        directory.path(),
        &outcome,
        None,
    )
    .unwrap_err();

    assert!(!error.is_empty());
    assert!(
        !directory
            .path()
            .join("production-loader-result-v2.json")
            .exists()
    );
}

#[test]
fn ready_qualification_reports_external_export_failure() {
    let directory = TempDir::new().unwrap();
    std::fs::create_dir(directory.path().join("production-loader-plan-v1.json")).unwrap();
    let plan = plan();
    let outcome = ready_outcome(&plan);
    let receipt = qualified_receipt(outcome.clone());

    let error = crate::windows::package::export_typed_production_qualification_artifacts_for_test(
        directory.path(),
        &outcome,
        Some(&receipt),
    )
    .unwrap_err();

    assert!(!error.is_empty());
    assert!(
        !directory
            .path()
            .join("production-loader-result-v2.json")
            .exists()
    );
}

#[test]
fn mismatched_typed_plan_is_rejected_before_outcome_publication() {
    let directory = TempDir::new().unwrap();
    let plan = plan();
    let mut outcome = failed_outcome(&plan);
    outcome.set_launch_plan_json(serde_json::json!({ "launch_plan_sha256": DIGEST_B }).to_string());

    let error = crate::windows::package::export_typed_production_qualification_artifacts_for_test(
        directory.path(),
        &outcome,
        None,
    )
    .unwrap_err();

    assert_eq!(
        error,
        "typed production loader qualification outcome is inconsistent"
    );
    assert!(
        !directory
            .path()
            .join("production-loader-result-v2.json")
            .exists()
    );
}

#[test]
fn artifact_export_failure_preserves_primary_and_bounds_secondary_detail() {
    let primary = "primary qualification failure";
    let retained = "é".repeat(memcordon_windows_launch_core::MAX_FAILURE_DETAIL_BYTES / 2);
    let discarded = "discarded-tail";
    let result = crate::windows::package::qualification_error_with_artifact_export_for_test(
        primary.to_owned(),
        format!("{retained}{discarded}"),
    );

    assert!(result.starts_with(primary));
    assert!(result.contains(&retained));
    assert!(!result.contains(discarded));
}
