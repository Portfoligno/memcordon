//! Exact native qualification obligations, separately published from runtime metadata.
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::package_inspection_v6::LinuxUnitHashesV6;
use memcordon_core::runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole};
use memcordon_core::runtime_manifest_v3::QualificationArtifactReferenceV2;
use memcordon_core::workload_codec::{Encoder, hash_bytes};
use memcordon_core::workload_qualification_v2::{
    QualificationArtifactV2, TrustedQualificationExpectationV2,
};
use serde::{Deserialize, Serialize};

/// These are additional, independently required rows for a future Linux V2
/// release. The active V1 release inventory below does not promote them.
pub const PRIVATE_V2_ARTIFACTS: [(&str, &str); 2] = [
    (
        "aarch64-unknown-linux-gnu",
        "certification/workload/linux-arm64-private-v2.json",
    ),
    (
        "x86_64-unknown-linux-gnu",
        "certification/workload/linux-x64-private-v2.json",
    ),
];

/// Domain-separated identity of the immutable Linux executable build B.
/// It deliberately excludes runtime manifest, archive, installed receipt and
/// qualification-result bytes, so Q can refer to B before M1/A exist.
pub fn private_component_digest_v2(
    target: &str,
    source_commit: &str,
    version: &str,
    components: &[RuntimeComponentRecord],
) -> Result<DiagnosticSha256> {
    if !PRIVATE_V2_ARTIFACTS.iter().any(|(row, _)| *row == target)
        || !crate::certification_context::valid_commit(source_commit)
        || version.is_empty()
        || version.len() > 64
        || components.len() != 2
    {
        return Err(CiError::Message(
            "private component build identity differs".into(),
        ));
    }
    let mut sorted = components.to_vec();
    sorted.sort_by_key(|component| match component.role {
        RuntimeComponentRole::PublicCli => 1,
        RuntimeComponentRole::SealedAgent => 2,
        RuntimeComponentRole::DesktopBootstrap => 3,
        RuntimeComponentRole::SessionBroker => 4,
    });
    if sorted[0].role != RuntimeComponentRole::PublicCli
        || sorted[1].role != RuntimeComponentRole::SealedAgent
        || sorted[0].id != "public-cli"
        || sorted[1].id != "sealed-agent"
        || sorted[0].path != "memcordon"
        || sorted[1].path != "memcordon-sealed-agent"
        || sorted.iter().any(|component| {
            component.size == 0
                || component.mode != 0o755
                || component.sha256.len() != std::mem::size_of::<[u8; 32]>() * 2
        })
    {
        return Err(CiError::Message(
            "private component inventory differs".into(),
        ));
    }
    let mut encoder =
        Encoder::new(b"private-release-components-v2", 4096).map_err(CiError::Message)?;
    for text in [target, source_commit, version] {
        encoder.count(text.len()).map_err(CiError::Message)?;
        encoder.raw(text.as_bytes()).map_err(CiError::Message)?;
    }
    encoder.count(sorted.len()).map_err(CiError::Message)?;
    for (tag, component) in sorted.iter().enumerate() {
        let sha = hex::decode(&component.sha256)
            .map_err(|_| CiError::Message("private component digest is invalid".into()))?;
        if sha.len() != std::mem::size_of::<[u8; 32]>()
            || !component
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(CiError::Message(
                "private component digest is invalid".into(),
            ));
        }
        encoder
            .byte(u8::try_from(tag + 1).expect("two components fit u8"))
            .map_err(CiError::Message)?;
        encoder
            .count(component.id.len())
            .map_err(CiError::Message)?;
        encoder
            .raw(component.id.as_bytes())
            .map_err(CiError::Message)?;
        encoder
            .count(component.path.len())
            .map_err(CiError::Message)?;
        encoder
            .raw(component.path.as_bytes())
            .map_err(CiError::Message)?;
        encoder.u64(component.size).map_err(CiError::Message)?;
        encoder
            .u64(u64::from(component.mode))
            .map_err(CiError::Message)?;
        encoder.raw(&sha).map_err(CiError::Message)?;
    }
    Ok(hash_bytes(&encoder.finish()))
}

/// Canonical seven-unit identity used by Q, independent of manifest/archive
/// serialization and of a host's current service state.
pub fn private_unit_digest_v2(units: &LinuxUnitHashesV6) -> DiagnosticSha256 {
    let mut encoder =
        Encoder::new(b"private-release-units-v2", 512).expect("fixed unit identity fits bound");
    for (tag, digest) in [
        (1, &units.control_service),
        (2, &units.control_socket),
        (3, &units.launcher_service),
        (4, &units.launcher_socket),
        (5, &units.tmpfiles),
        (6, &units.network_launcher_service),
        (7, &units.network_launcher_socket),
    ] {
        encoder.byte(tag).expect("fixed unit identity fits bound");
        encoder
            .digest(digest)
            .expect("fixed unit identity fits bound");
    }
    hash_bytes(&encoder.finish())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateNativeInventoryV2 {
    schema_version: u32,
    profile: String,
    targets: Vec<String>,
    tests: Vec<String>,
}

/// Applies the checked-in test inventory before structural artifact parsing.
/// The caller must obtain completions from an independent native runner; this
/// validator cannot turn a self-reported artifact into release authority.
pub fn validate_private_v2_against_trusted_native_completions(
    artifact_bytes: &[u8],
    reference: &QualificationArtifactReferenceV2,
    expected: &TrustedQualificationExpectationV2<'_>,
) -> Result<QualificationArtifactV2> {
    let inventory: PrivateNativeInventoryV2 =
        toml::from_str(include_str!("../../../ci/private-native-v2.toml"))
            .map_err(|error| CiError::Message(error.to_string()))?;
    let target_rows = PRIVATE_V2_ARTIFACTS.map(|(target, _)| target.to_owned());
    if inventory.schema_version != 1
        || inventory.profile != "linux-tcp4-private-v1"
        || inventory.targets != target_rows
        || inventory.tests.is_empty()
        || inventory.tests.len() > memcordon_core::workload_qualification_v2::NATIVE_TESTS_MAX
        || inventory.tests.windows(2).any(|pair| pair[0] >= pair[1])
        || !PRIVATE_V2_ARTIFACTS.iter().any(|(target, artifact)| {
            *target == expected.target
                && reference.qualified_target == *target
                && reference.artifact == *artifact
        })
        || expected.profile
            != &memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1.reference()
        || expected.completions.len() != inventory.tests.len()
    {
        return Err(CiError::Message(
            "private V2 release inventory or target binding differs".into(),
        ));
    }
    for (observed, name) in expected.completions.iter().zip(&inventory.tests) {
        if observed.name != name || observed.target != expected.target || !observed.native_executed
        {
            return Err(CiError::Message(
                "private V2 native completion differs from required test inventory".into(),
            ));
        }
    }
    QualificationArtifactV2::parse_and_validate(artifact_bytes, reference, expected)
        .map_err(|error| CiError::Message(format!("private V2 artifact differs: {error}")))
}

/// Release readback additionally joins Q's component digest to the exact
/// immutable executable inventory B. The version, target and source are
/// supplied by the release identity, never copied from Q or its reference.
pub fn validate_private_v2_against_build(
    artifact_bytes: &[u8],
    reference: &QualificationArtifactReferenceV2,
    expected: &TrustedQualificationExpectationV2<'_>,
    version: &str,
    components: &[RuntimeComponentRecord],
) -> Result<QualificationArtifactV2> {
    let actual =
        private_component_digest_v2(expected.target, expected.source_commit, version, components)?;
    if &actual != expected.component_digest {
        return Err(CiError::Message(
            "private qualification component digest differs from build B".into(),
        ));
    }
    validate_private_v2_against_trusted_native_completions(artifact_bytes, reference, expected)
}

/// Audits a proposed private-profile artifact but never promotes it into this
/// release's required/accepted inventory. A trusted native completion source,
/// installed V4 qualification producer, and package binding are not wired yet.
pub fn reject_proposed_private_qualification_v2(
    artifact_bytes: &[u8],
    reference: &QualificationArtifactReferenceV2,
    expected: &TrustedQualificationExpectationV2<'_>,
) -> Result<()> {
    QualificationArtifactV2::parse_and_validate(artifact_bytes, reference, expected).map_err(
        |error| {
            CiError::Message(format!(
                "private V2 qualification artifact differs: {error}"
            ))
        },
    )?;
    Err(CiError::Message(
        "private V2 qualification is not accepted until installed native V4 evidence is wired"
            .into(),
    ))
}
pub const PROFILE_TESTS: [&str; 2] = [
    "native_workload_admission::native_exact_grant_epoch_and_terminal_checkpoint_are_enforced",
    "native_workload_admission::native_tcp_requirement_preserves_baseline_authority",
];
pub const WINDOWS_PACKAGE_POLICY_TESTS: [&str; 3] = [
    "windows::package::policy_rollback_tests::partial_uninstall_restores_captured_images_manifest_and_policy",
    "windows::package::policy_rollback_tests::mixed_runtime_component_is_rejected_before_execution",
    "windows::package::policy_rollback_tests::legacy_manifest_absence_survives_failed_upgrade_qualification",
];
pub const DIAGNOSTIC_TESTS: [&str; 20] = [
    "windows_postauthorization_retirement::receiptless_posttarget_rejection_cannot_bypass_terminal_binding",
    "windows_replay_retention::final_outbox_store_failure_preserves_primary_and_bounds_secondary_diagnostics",
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
    "windows::launcher_service::job_conversion_tests::job_accounting_conversion_preserves_monitor_classification",
    "windows::launcher_service::job_conversion_tests::job_observation_mapping_covers_emitted_operations",
    "windows::launcher_service::job_conversion_tests::job_string_conversion_preserves_semantics",
    "windows::launcher_service::job_conversion_tests::job_diagnostic_reconstruction_preserves_operation",
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

/// Installed public-path evidence is distinct from the source-native test inventory.
/// Each row is (target, channel, accepted artifact, raw-file prefix).
pub const INSTALLED_CAUSAL_ARTIFACTS: [(&str, &str, &str, &str); 4] = [
    (
        "x86_64-pc-windows-msvc",
        "native-bundle",
        "windows-x64-installed-causal-native.json",
        "windows-x64-installed-causal-native",
    ),
    (
        "x86_64-pc-windows-msvc",
        "cargo-package",
        "windows-x64-installed-causal-cargo.json",
        "windows-x64-installed-causal-cargo",
    ),
    (
        "aarch64-pc-windows-msvc",
        "native-bundle",
        "windows-arm64-installed-causal-native.json",
        "windows-arm64-installed-causal-native",
    ),
    (
        "aarch64-pc-windows-msvc",
        "cargo-package",
        "windows-arm64-installed-causal-cargo.json",
        "windows-arm64-installed-causal-cargo",
    ),
];
