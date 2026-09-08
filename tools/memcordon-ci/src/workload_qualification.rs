//! Exact native qualification obligations, separately published from runtime metadata.
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
pub const PROFILE_TESTS: [&str; 2] = [
    "native_workload_admission::native_exact_grant_epoch_and_terminal_checkpoint_are_enforced",
    "native_workload_admission::native_tcp_requirement_preserves_baseline_authority",
];
pub const WINDOWS_PACKAGE_POLICY_TESTS: [&str; 3] = [
    "windows::package::policy_rollback_tests::partial_uninstall_restores_captured_images_manifest_and_policy",
    "windows::package::policy_rollback_tests::mixed_runtime_component_is_rejected_before_execution",
    "windows::package::policy_rollback_tests::legacy_manifest_absence_survives_failed_upgrade_qualification",
];
pub const DIAGNOSTIC_TESTS: [&str; 14] = [
    "windows::record::record_fault_tests::native_publisher_process_exit_preserves_atomic_old_or_new_record",
    "windows::record::record_fault_tests::native_publication_fault_matrix_preserves_original_and_honest_commit_boundary",
    "windows::record::record_fault_tests::stale_revision_original_replacement_and_staging_collision_never_publish",
    "windows::record::record_fault_tests::native_rename_sharing_failure_retains_typed_code_and_original",
    "windows::record::record_fault_tests::both_native_disk_full_codes_are_captured_before_formatting",
    "windows::record::record_fault_tests::frozen_native_publication_does_not_own_workload_job_cleanup",
    "windows::attempt_store::writer_queue_tests::frozen_writer_bounds_queue_without_claiming_commit_or_waiting_on_io",
    "windows::attempt_store::writer_queue_tests::writer_unavailable_and_completion_contention_fail_without_pending_leaks",
    "windows::attempt_store::writer_queue_tests::cloned_lane_cannot_enqueue_after_retirement_proof",
    "windows::attempt_store::writer_queue_tests::retire_cannot_prove_completion_while_an_enqueue_is_in_flight",
    "windows::diagnostics::causal_capture_tests::source_capture_and_record_cleanup_share_one_ordered_journal",
    "windows::diagnostics::causal_capture_tests::unwinding_and_reentrant_capture_preserve_original_and_expose_loss",
    "windows::job::native_diagnostic_codes::job_wrappers_capture_native_codes_before_last_error_changes",
    "windows::control_service::retained_binding_tests::authenticated_retained_binding_rejects_other_attempt_request_process_creation_and_token",
];
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationKind {
    Profile,
    CausalDiagnostics,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationArtifactV1 {
    pub schema_version: u32,
    pub kind: QualificationKind,
    pub target: String,
    pub source_commit: String,
    pub profile_catalog_sha256: String,
    pub qualified: bool,
    pub tests: Vec<String>,
    pub tests_skipped: u32,
}
impl QualificationArtifactV1 {
    pub fn after_observed_tests(kind: QualificationKind, target: &str, source: &str) -> Self {
        let mut tests: Vec<String> = match kind {
            QualificationKind::Profile => PROFILE_TESTS.as_slice(),
            QualificationKind::CausalDiagnostics => DIAGNOSTIC_TESTS.as_slice(),
        }
        .iter()
        .map(|name| (*name).into())
        .collect();
        if kind == QualificationKind::Profile && target.contains("windows") {
            tests.extend(
                WINDOWS_PACKAGE_POLICY_TESTS
                    .iter()
                    .map(|name| (*name).to_owned()),
            );
        }
        Self {
            schema_version: 1,
            kind,
            target: target.into(),
            source_commit: source.into(),
            profile_catalog_sha256: memcordon_core::runtime_manifest::baseline_catalog_digest(
                target.contains("windows"),
            ),
            qualified: true,
            tests,
            tests_skipped: 0,
        }
    }
    pub fn validate(&self, kind: QualificationKind, target: &str, source: &str) -> Result<()> {
        if self != &Self::after_observed_tests(kind, target, source) {
            return Err(CiError::Message(
                "native workload/diagnostic qualification inventory or identity differs".into(),
            ));
        }
        Ok(())
    }
}

pub const ARTIFACTS: [(&str, &str, &str, QualificationKind); 5] = [
    (
        "release-certification-linux",
        "linux-profile-qualification.json",
        "x86_64-unknown-linux-gnu",
        QualificationKind::Profile,
    ),
    (
        "release-windows-package-channel-x64",
        "windows-x64-profile-qualification.json",
        "x86_64-pc-windows-msvc",
        QualificationKind::Profile,
    ),
    (
        "release-windows-package-channel-x64",
        "windows-x64-causal-diagnostics.json",
        "x86_64-pc-windows-msvc",
        QualificationKind::CausalDiagnostics,
    ),
    (
        "release-windows-package-channel-arm64",
        "windows-arm64-profile-qualification.json",
        "aarch64-pc-windows-msvc",
        QualificationKind::Profile,
    ),
    (
        "release-windows-package-channel-arm64",
        "windows-arm64-causal-diagnostics.json",
        "aarch64-pc-windows-msvc",
        QualificationKind::CausalDiagnostics,
    ),
];
