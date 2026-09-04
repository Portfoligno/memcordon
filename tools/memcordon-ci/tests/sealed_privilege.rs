use memcordon_core::{
    WindowsLoaderCleanupOutcomeV1, WindowsLoaderCleanupStatusV1, WindowsLoaderNativeStatusV1,
    WindowsLoaderQualificationFailureV2, WindowsLoaderQualificationOutcomeV2,
    WindowsLoaderQualificationStageV2,
};
use memcordon_windows_launch_core::{ArtifactRefV1, MAX_FAILURE_DETAIL_BYTES, RedactionClassV1};
use sha2::Digest;

fn digest(byte: char) -> String {
    byte.to_string().repeat(sha2::Sha256::output_size() * 2)
}

fn failed_loader_outcome() -> WindowsLoaderQualificationOutcomeV2 {
    WindowsLoaderQualificationOutcomeV2::Failed(WindowsLoaderQualificationFailureV2 {
        schema_version: 2,
        stable_code: String::from("process-create-failed"),
        stage: WindowsLoaderQualificationStageV2::ProcessCreate,
        native_status: Some(WindowsLoaderNativeStatusV1::Win32 { code: 5 }),
        elapsed_millis: 1,
        launch_plan_sha256: Some(digest('a')),
        qualification_id: String::from("qualification-1"),
        cleanup: WindowsLoaderCleanupOutcomeV1 {
            status: WindowsLoaderCleanupStatusV1::Complete,
            stable_code: None,
        },
        diagnostic_id: None,
        detail: String::from("CreateProcessAsUserW denied access"),
    })
}

#[test]
fn loader_failure_keeps_stage_native_status_plan_and_cleanup_independent() {
    let outcome = failed_loader_outcome();
    assert!(outcome.is_consistent());
    let WindowsLoaderQualificationOutcomeV2::Failed(failure) = outcome else {
        panic!("fixture must be a failure");
    };
    assert_eq!(
        failure.stage,
        WindowsLoaderQualificationStageV2::ProcessCreate
    );
    assert_eq!(
        failure.native_status,
        Some(WindowsLoaderNativeStatusV1::Win32 { code: 5 })
    );
    assert_eq!(
        failure.launch_plan_sha256.as_deref(),
        Some(digest('a').as_str())
    );
    assert_eq!(
        failure.cleanup.status,
        WindowsLoaderCleanupStatusV1::Complete
    );
}

#[test]
fn early_failure_may_omit_only_the_unconstructed_plan_digest() {
    let WindowsLoaderQualificationOutcomeV2::Failed(mut failure) = failed_loader_outcome() else {
        panic!("fixture must be a failure");
    };
    failure.stage = WindowsLoaderQualificationStageV2::DesktopPreflight;
    failure.launch_plan_sha256 = None;
    assert!(WindowsLoaderQualificationOutcomeV2::Failed(failure.clone()).is_consistent());
    failure.stage = WindowsLoaderQualificationStageV2::ProcessCreate;
    assert!(!WindowsLoaderQualificationOutcomeV2::Failed(failure).is_consistent());
}

#[test]
fn failure_detail_limit_is_schema_derived_and_enforced() {
    let WindowsLoaderQualificationOutcomeV2::Failed(mut failure) = failed_loader_outcome() else {
        panic!("fixture must be a failure");
    };
    failure.detail = "x".repeat(MAX_FAILURE_DETAIL_BYTES + 1);
    assert!(!WindowsLoaderQualificationOutcomeV2::Failed(failure).is_consistent());
}

#[test]
fn restricted_evidence_reference_is_digest_and_path_bound() {
    let reference = ArtifactRefV1::new(
        String::from("loader-production/production-result.json"),
        digest('b'),
        42,
        String::from("application/json"),
        RedactionClassV1::RestrictedTrace,
    )
    .expect("valid evidence reference");
    assert_eq!(reference.byte_length(), 42);
    assert!(
        ArtifactRefV1::new(
            String::from("../production-result.json"),
            digest('b'),
            42,
            String::from("application/json"),
            RedactionClassV1::RestrictedTrace,
        )
        .is_err()
    );
}
