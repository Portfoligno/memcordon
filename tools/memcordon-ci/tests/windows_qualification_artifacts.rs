use std::ffi::OsString;
use std::path::Path;

use memcordon_ci::windows_qualification_artifacts::{
    prepare_windows_qualification_artifact_directory, read_ready_windows_qualification_artifacts,
    windows_ephemeral_install_arguments,
};
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
use serde::Serialize;
use tempfile::TempDir;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn plan(command_line_sha256: &str) -> ProductionLoaderPlanV1 {
    build_package_loader_plan(ProductionLoaderPlanInputV1 {
        executable_path_utf16: r"C:\Program Files\MemCordon\bootstrap.exe"
            .encode_utf16()
            .collect(),
        executable_sha256: DIGEST_A.to_owned(),
        command_line_sha256: command_line_sha256.to_owned(),
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

fn detached_outcome(plan: &ProductionLoaderPlanV1) -> WindowsLoaderQualificationOutcomeV2 {
    WindowsLoaderQualificationOutcomeV2::Ready(WindowsLoaderReadyEvidenceV1 {
        schema_version: 1,
        launch_plan_sha256: plan.launch_plan_sha256().to_owned(),
        launch_plan_json: None,
        elapsed_millis: 1,
    })
}

fn receipt_outcome(plan: &ProductionLoaderPlanV1) -> WindowsLoaderQualificationOutcomeV2 {
    WindowsLoaderQualificationOutcomeV2::Ready(WindowsLoaderReadyEvidenceV1 {
        schema_version: 1,
        launch_plan_sha256: plan.launch_plan_sha256().to_owned(),
        launch_plan_json: Some(serde_json::to_string(plan).unwrap()),
        elapsed_millis: 1,
    })
}

fn receipt(outcome: WindowsLoaderQualificationOutcomeV2) -> WindowsQualificationReceiptV1 {
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

fn write_json(path: &Path, value: &impl Serialize) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    std::fs::write(path, bytes).unwrap();
}

fn write_artifacts(directory: &Path, plan: &ProductionLoaderPlanV1) {
    let outcome = detached_outcome(plan);
    write_json(
        &directory.join("qualification.json"),
        &receipt(receipt_outcome(plan)),
    );
    write_json(&directory.join("production-loader-plan-v1.json"), plan);
    write_json(
        &directory.join("production-loader-result-v2.json"),
        &outcome,
    );
}

#[test]
fn install_arguments_bind_the_durable_channel_as_a_discrete_value() {
    let directory = Path::new("channel").join("native");
    assert_eq!(
        windows_ephemeral_install_arguments(&directory),
        [
            OsString::from("package"),
            OsString::from("install"),
            OsString::from("--ephemeral-ci"),
            OsString::from("--qualification-artifact-directory"),
            directory.into_os_string(),
        ]
    );
}

#[test]
fn detached_channel_artifacts_are_mutually_digest_bound() {
    let directory = TempDir::new().unwrap();
    let plan = plan(DIGEST_B);
    let expected_receipt = receipt(receipt_outcome(&plan));
    write_artifacts(directory.path(), &plan);

    let artifacts = read_ready_windows_qualification_artifacts(directory.path()).unwrap();
    assert_eq!(artifacts.plan, plan);
    assert_eq!(artifacts.receipt, expected_receipt);
    assert_eq!(
        serde_json::to_vec(&artifacts.receipt).unwrap(),
        serde_json::to_vec(&expected_receipt).unwrap()
    );
    assert!(artifacts.receipt.qualified);
    assert!(artifacts.receipt.is_consistent());
    assert!(
        artifacts
            .receipt
            .loader_qualification
            .launch_plan_json()
            .is_some()
    );
}

#[test]
fn missing_detached_plan_has_a_phase_specific_error() {
    let directory = TempDir::new().unwrap();
    let plan = plan(DIGEST_B);
    write_artifacts(directory.path(), &plan);
    std::fs::remove_file(directory.path().join("production-loader-plan-v1.json")).unwrap();

    let error = read_ready_windows_qualification_artifacts(directory.path()).unwrap_err();
    let detail = error.to_string();
    assert!(detail.contains("package-channel qualification artifact is unavailable"));
    assert!(detail.contains("production-loader-plan-v1.json"));
}

#[test]
fn mismatched_detached_plan_digest_is_rejected() {
    let directory = TempDir::new().unwrap();
    let expected = plan(DIGEST_A);
    write_artifacts(directory.path(), &expected);
    let mismatched = plan(DIGEST_B);
    write_json(
        &directory.path().join("production-loader-plan-v1.json"),
        &mismatched,
    );

    let error = read_ready_windows_qualification_artifacts(directory.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("receipt and detached loader plans differ")
    );
}

#[test]
fn invalid_detached_outcome_names_the_artifact() {
    let directory = TempDir::new().unwrap();
    write_artifacts(directory.path(), &plan(DIGEST_B));
    std::fs::write(
        directory.path().join("production-loader-result-v2.json"),
        b"not-json\n",
    )
    .unwrap();

    let error = read_ready_windows_qualification_artifacts(directory.path()).unwrap_err();
    let detail = error.to_string();
    assert!(detail.contains("qualification artifact is invalid"));
    assert!(detail.contains("production-loader-result-v2.json"));
}

#[test]
fn failed_detached_outcome_is_rejected_before_public_verification() {
    let directory = TempDir::new().unwrap();
    let plan = plan(DIGEST_B);
    let failed = WindowsLoaderQualificationOutcomeV2::Failed(WindowsLoaderQualificationFailureV2 {
        schema_version: 2,
        stable_code: "MCSEALED-WINDOWS-LOADER-PROCESS-CREATE".to_owned(),
        stage: WindowsLoaderQualificationStageV2::ProcessCreate,
        native_status: None,
        elapsed_millis: 1,
        launch_plan_sha256: Some(plan.launch_plan_sha256().to_owned()),
        launch_plan_json: None,
        qualification_id: "package-channel-fixture".to_owned(),
        cleanup: WindowsLoaderCleanupOutcomeV1 {
            status: WindowsLoaderCleanupStatusV1::Complete,
            stable_code: None,
        },
        diagnostic_id: None,
        detail: "production loader create failed".to_owned(),
    });
    write_artifacts(directory.path(), &plan);
    write_json(
        &directory.path().join("production-loader-result-v2.json"),
        &failed,
    );

    let error = read_ready_windows_qualification_artifacts(directory.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("exported a failed loader outcome")
    );
}

#[test]
fn receipt_and_detached_plan_mismatch_is_rejected() {
    let directory = TempDir::new().unwrap();
    let receipt_plan = plan(DIGEST_A);
    let outcome_plan = plan(DIGEST_B);
    let receipt_outcome = receipt_outcome(&receipt_plan);
    let exported_outcome = detached_outcome(&outcome_plan);
    write_json(
        &directory.path().join("qualification.json"),
        &receipt(receipt_outcome),
    );
    write_json(
        &directory.path().join("production-loader-plan-v1.json"),
        &outcome_plan,
    );
    write_json(
        &directory.path().join("production-loader-result-v2.json"),
        &exported_outcome,
    );

    let error = read_ready_windows_qualification_artifacts(directory.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("receipt and detached loader plans differ")
    );
}

#[test]
fn normalized_receipt_and_detached_outcome_mismatch_is_rejected() {
    let directory = TempDir::new().unwrap();
    let plan = plan(DIGEST_B);
    write_artifacts(directory.path(), &plan);
    let mut mismatched = detached_outcome(&plan);
    let WindowsLoaderQualificationOutcomeV2::Ready(ready) = &mut mismatched else {
        unreachable!("fixture outcome is Ready");
    };
    ready.elapsed_millis += 1;
    write_json(
        &directory.path().join("production-loader-result-v2.json"),
        &mismatched,
    );

    let error = read_ready_windows_qualification_artifacts(directory.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("normalized receipt and detached loader outcome differ")
    );
}

#[test]
fn receipt_without_its_inline_plan_is_rejected() {
    let directory = TempDir::new().unwrap();
    let plan = plan(DIGEST_B);
    write_artifacts(directory.path(), &plan);
    write_json(
        &directory.path().join("qualification.json"),
        &receipt(detached_outcome(&plan)),
    );

    let error = read_ready_windows_qualification_artifacts(directory.path()).unwrap_err();
    assert!(error.to_string().contains("missing its inline loader plan"));
}

#[test]
fn preparation_removes_only_stale_typed_exports() {
    let directory = TempDir::new().unwrap();
    let retained = directory.path().join("rollback.json");
    std::fs::write(&retained, b"{}\n").unwrap();
    write_artifacts(directory.path(), &plan(DIGEST_B));

    prepare_windows_qualification_artifact_directory(directory.path()).unwrap();

    assert!(retained.is_file());
    for name in [
        "qualification.json",
        "production-loader-plan-v1.json",
        "production-loader-result-v2.json",
    ] {
        assert!(!directory.path().join(name).exists());
    }
}
