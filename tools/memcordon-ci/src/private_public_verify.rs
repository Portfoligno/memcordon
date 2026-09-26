//! Final-public P requires the installed nonroot child, protected provider
//! readback, and independent complete-interval observation for every case.

use ed25519_dalek::{Signer, SigningKey};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_public_abi_composite_v1::PUBLIC_ABI_SELECTOR_V1;
use memcordon_core::private_public_case_v2::{
    FinalPublicCaseEvidenceV2, FinalPublicInstalledBindingV2,
};
use memcordon_core::private_public_policy_composite_v1::{
    PUBLIC_POLICY_SELECTOR_V1, PublicPolicyBranchOutcomeV1, PublicPolicyCompositeCaseV1,
};
use memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2;
use memcordon_core::private_public_reuse_composite_v1::{
    PUBLIC_REUSE_SELECTOR_V1, PublicReuseCompositeCaseV1,
};
use memcordon_core::private_release_build_v2::PrivateCandidateRecordV2;
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;
use memcordon_core::public_release_trust::{
    ExpectedPublicQualificationV1, PublicQualificationCertificateV1,
    SignedPublicQualificationCertificateV1,
};
use memcordon_core::release_trust::{
    ReleaseSigningRoleV1, ReleaseTrustAnchorV1, SignedNativeQualificationCertificateV1,
    SignedReleaseTrustPolicyV1, TrustHighWaterV1, VerifiedNativeQualificationV1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::private_completed_run::AuthenticatedCompletedProducerV2;
use crate::private_kernel_observer::{
    AllocationBoundaryKindV1, KernelEventV1, KernelTaskIdentityV1, KnownActionTupleV1,
    VerifiedKernelIntervalV1,
};
use crate::private_native::NativeRunStageV2;
use crate::private_native_verify::{RequiredDispositionV1, case_evidence_requirements_v1};
use crate::private_process_clock::VerifiedProcClockCalibrationV1;
use crate::private_public_case_readback::StructuralFinalPublicCaseReadbackV2;
#[cfg(target_os = "linux")]
use crate::private_public_dispatch::{
    ObservedInstalledPublicCaseV3, OwnedPublicRawAttachmentV2, StructuralProviderFrameReadbackV2,
};
#[cfg(target_os = "linux")]
use crate::private_public_kernel_join::VerifiedPublicCaseKernelJoinV1;
use crate::{CiError, Result};

/// This is not Deserialize. It can only be filled by an independent reviewed
/// host observer, which is still a prerequisite for release qualification.
pub(crate) struct IndependentPublicObservationV1 {
    selector: String,
    case_sha256: DiagnosticSha256,
    archive_sha256: DiagnosticSha256,
    host_receipt_sha256: DiagnosticSha256,
    kernel_interval: VerifiedKernelIntervalV1,
    clock_calibration: VerifiedProcClockCalibrationV1,
    public_task: KernelTaskIdentityV1,
    target_task: Option<(KernelTaskIdentityV1, u64)>,
    required_decisions: Vec<KnownActionTupleV1>,
    live_barrier_observed: bool,
    retirement_complete: bool,
}

pub(crate) struct VerifiedPublicSemanticsV2 {
    target: String,
    native_machine: String,
    source_commit: String,
    release_version: String,
    installed: FinalPublicInstalledBindingV2,
    boot_identity: String,
    historical_epoch_sha256: DiagnosticSha256,
    cases: Vec<PublicCaseDigestV2>,
}

/// Created only after an E0 positive public run, same-A qualified upgrade,
/// independently observed E1 no-allocation replay, and fresh E1 control.
pub(crate) struct VerifiedHistoricalPublicEpochV1 {
    e1_installation_epoch: DiagnosticSha256,
    e1_host_receipt_sha256: DiagnosticSha256,
    boot_identity: String,
    transcript_sha256: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
impl VerifiedHistoricalPublicEpochV1 {
    pub(crate) fn transcript_sha256(&self) -> &DiagnosticSha256 {
        &self.transcript_sha256
    }

    pub(crate) fn from_live_join(
        joined: &crate::private_public_epoch_join::VerifiedPublicEpochTransitionV1,
        boot_identity: &str,
    ) -> Result<Self> {
        if boot_identity.is_empty() || boot_identity.len() > 128 {
            return Err(CiError::Message(
                "public historical live join boot identity differs".into(),
            ));
        }
        Ok(Self {
            e1_installation_epoch: joined.e1_installation_epoch().clone(),
            e1_host_receipt_sha256: joined.e1_h1_receipt_sha256().clone(),
            boot_identity: boot_identity.into(),
            transcript_sha256: joined.transcript_sha256().clone(),
        })
    }
}

pub(crate) struct VerifiedPublicPolicyCompositeV1 {
    case_sha256: DiagnosticSha256,
    result_key: DiagnosticSha256,
    target: String,
    native_machine: String,
    source_commit: String,
    release_version: String,
    boot_identity: String,
    installation_epoch: DiagnosticSha256,
    archive_sha256: DiagnosticSha256,
    manifest_sha256: DiagnosticSha256,
    qualification_sha256: DiagnosticSha256,
    host_receipt_sha256: DiagnosticSha256,
}

/// A typed three-interval reuse decision; a first postallocation rejection is
/// never coerced into a Terminal observation.
pub(crate) struct VerifiedPublicReuseCompositeV1 {
    case_sha256: DiagnosticSha256,
    result_key: DiagnosticSha256,
    target: String,
    native_machine: String,
    source_commit: String,
    release_version: String,
    boot_identity: String,
    installation_epoch: DiagnosticSha256,
    archive_sha256: DiagnosticSha256,
    manifest_sha256: DiagnosticSha256,
    qualification_sha256: DiagnosticSha256,
    host_receipt_sha256: DiagnosticSha256,
}

/// The filtered target's alternate-ABI denial is joined separately from the
/// service's outer-only auxiliary. Only the live protected/BPF constructor
/// below can create this token; parsing the composite JSON cannot.
pub(crate) struct VerifiedPublicAbiCompositeV1 {
    case_sha256: DiagnosticSha256,
    result_key: DiagnosticSha256,
    target: String,
    native_machine: String,
    source_commit: String,
    release_version: String,
    boot_identity: String,
    installation_epoch: DiagnosticSha256,
    archive_sha256: DiagnosticSha256,
    manifest_sha256: DiagnosticSha256,
    qualification_sha256: DiagnosticSha256,
    host_receipt_sha256: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_public_reuse_composite(
    bytes: &[u8],
    joined: &crate::private_public_reuse_join::VerifiedPublicReuseV1,
    first: &VerifiedKernelIntervalV1,
    blocked: &VerifiedKernelIntervalV1,
    recovery: &VerifiedKernelIntervalV1,
) -> Result<VerifiedPublicReuseCompositeV1> {
    let case = PublicReuseCompositeCaseV1::parse(bytes).map_err(CiError::Message)?;
    if case.semantic_join_sha256 != *joined.transcript_sha256()
        || case.first_failure_sha256 != *joined.cleanup_failure_sha256()
        || case.blocked_rejection_sha256 != *joined.blocked_rejection_sha256()
        || case.recovered_cleanup_sha256 != *joined.recovered_cleanup_sha256()
        || case.first_kernel_capture_sha256 != *first.trace_sha256()
        || case.blocked_kernel_capture_sha256 != *blocked.trace_sha256()
        || case.recovery_kernel_capture_sha256 != *recovery.trace_sha256()
        || first.boot_id() != case.child.boot_identity.as_str()
        || blocked.boot_id() != case.child.boot_identity.as_str()
        || recovery.boot_id() != case.child.boot_identity.as_str()
    {
        return Err(CiError::Message(
            "public reuse composite differs from live three-interval join".into(),
        ));
    }
    Ok(VerifiedPublicReuseCompositeV1 {
        case_sha256: hash_bytes(bytes),
        result_key: case.result_key().map_err(CiError::Message)?,
        target: case.target,
        native_machine: case.native_machine,
        source_commit: case.source_commit,
        release_version: case.release_version.as_str().into(),
        boot_identity: case.child.boot_identity.as_str().into(),
        installation_epoch: case.installation_epoch,
        archive_sha256: case.archive_sha256,
        manifest_sha256: case.manifest_sha256,
        qualification_sha256: case.qualification_sha256,
        host_receipt_sha256: case.active_h1_receipt_sha256,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_public_abi_composite(
    bytes: &[u8],
    observed: &ObservedInstalledPublicCaseV3,
    provider: &StructuralProviderFrameReadbackV2,
    outer: &crate::private_public_abi_outer::StructuralPublicAbiOuterV1,
    outer_kernel: &crate::private_public_abi_outer::VerifiedPublicAbiOuterKernelV1,
    filtered: &crate::private_public_abi_filtered::StructuralPublicAbiFilteredV1,
    filtered_kernel: &crate::private_public_abi_filtered::VerifiedPublicAbiFilteredKernelV1,
    interval: &VerifiedKernelIntervalV1,
    joined_target: &VerifiedPublicCaseKernelJoinV1,
) -> Result<VerifiedPublicAbiCompositeV1> {
    let case =
        memcordon_core::private_public_abi_composite_v1::PublicAbiCompositeCaseV1::parse(bytes)
            .map_err(CiError::Message)?;
    let child = observed
        .process
        .linux_child
        .ok_or_else(|| CiError::Message("public ABI supervised child absent".into()))?;
    let [attempt] = provider.attempts.as_slice() else {
        return Err(CiError::Message(
            "public ABI provider attempt count differs".into(),
        ));
    };
    let target = attempt
        .target_identity
        .as_ref()
        .ok_or_else(|| CiError::Message("public ABI protected target identity absent".into()))?;
    let report = observed
        .report_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("public ABI public CLI report absent".into()))?;
    let terminal = attempt
        .terminal_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("public ABI protected Terminal absent".into()))?;
    let cleanup = attempt
        .cleanup_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("public ABI protected cleanup absent".into()))?;
    if case.result_key().map_err(CiError::Message)? != provider.result_key
        || case.result_key().map_err(CiError::Message)? != filtered.result_key
        || case.result_key().map_err(CiError::Message)? != outer.dispatch_key
        || case.filtered_child.pid != child.pid
        || case.filtered_child.start_time_ticks != child.start_time_ticks
        || case.filtered_child.executable_sha256 != observed.cli_sha256
        || case.filtered_child.argv_sha256 != observed.argv_sha256
        || case.filtered_child.working_directory_sha256 != observed.working_directory_sha256
        || case.filtered_provider_sha256 != hash_bytes(&provider.record_bytes)
        || case.filtered_report_sha256 != hash_bytes(report)
        || case.filtered_stdio_sha256 != hash_bytes(&observed.stdio_bytes)
        || case.filtered_terminal_sha256 != hash_bytes(terminal)
        || case.filtered_cleanup_sha256 != hash_bytes(cleanup)
        || case.filtered_target_report_sha256 != filtered.report_sha256
        || case.filtered_service_journal_sha256 != filtered.protected_sha256
        || case.filtered_checkpoint_file_sha256 != filtered.checkpoint_file_sha256
        || case.filtered_kernel_capture_sha256 != *filtered_kernel.capture_sha256()
        || case.filtered_kernel_capture_sha256 != *interval.trace_sha256()
        || case.outer_auxiliary_key != outer.auxiliary_key
        || case.outer_request_sha256 != outer.request_sha256
        || case.outer_raw_sha256 != outer.raw_sha256
        || case.outer_kernel_capture_sha256 != *outer_kernel.capture_sha256()
        || filtered.target_pid != target.target.pid
        || filtered.target_start_ticks != target.target.start_time
        || joined_target.target_count() != 1
        || joined_target.capture_sha256() != interval.trace_sha256()
        || filtered_kernel.child_count()
            != match case.target.as_str() {
                "x86_64-unknown-linux-gnu" => 2,
                "aarch64-unknown-linux-gnu" => 1,
                _ => return Err(CiError::Message("public ABI target differs".into())),
            }
        || interval.boot_id() != case.filtered_child.boot_identity.as_str()
    {
        return Err(CiError::Message(
            "public ABI composite differs from protected target and kernel joins".into(),
        ));
    }
    Ok(VerifiedPublicAbiCompositeV1 {
        case_sha256: hash_bytes(bytes),
        result_key: case.result_key().map_err(CiError::Message)?,
        target: case.target,
        native_machine: case.native_machine,
        source_commit: case.source_commit,
        release_version: case.release_version.as_str().into(),
        boot_identity: case.filtered_child.boot_identity.as_str().into(),
        installation_epoch: case.installation_epoch,
        archive_sha256: case.archive_sha256,
        manifest_sha256: case.manifest_sha256,
        qualification_sha256: case.qualification_sha256,
        host_receipt_sha256: case.active_h1_receipt_sha256,
    })
}

#[cfg(target_os = "linux")]
pub(crate) struct PublicPolicyBranchLiveV1 {
    pub(crate) observed: ObservedInstalledPublicCaseV3,
    pub(crate) provider: StructuralProviderFrameReadbackV2,
    pub(crate) interval: VerifiedKernelIntervalV1,
    pub(crate) joined: VerifiedPublicCaseKernelJoinV1,
    pub(crate) attachments: Vec<OwnedPublicRawAttachmentV2>,
}

/// This token is created only after the downloaded completed P ZIP is opened
/// and its exact P index and every protected case leaf are joined to the
/// authenticated producer. There is no current structural-to-token shortcut.
pub(crate) struct AuthenticatedCompletedPublicEvidenceV1 {
    completed: AuthenticatedCompletedProducerV2,
    public_index_bytes: Vec<u8>,
    raw_index_sha256: DiagnosticSha256,
}

pub struct PublicCertificateSigningIntentV1<'a> {
    pub trust_anchor: &'a ReleaseTrustAnchorV1,
    pub signed_policy: &'a SignedReleaseTrustPolicyV1,
    pub high_water: &'a TrustHighWaterV1,
    pub signing_key: &'a SigningKey,
    pub key_id: &'a str,
    pub release_sequence: u64,
    pub repository: &'a str,
    pub workflow_path: &'a str,
    pub workflow_revision: &'a str,
    pub verifier_sha256: &'a str,
    pub verifier_source_commit: &'a str,
    pub build_bytes: &'a [u8],
    pub qualification_bytes: &'a [u8],
    pub qualification_certificate_bytes: &'a [u8],
    pub archive_bytes: &'a [u8],
    pub manifest_bytes: &'a [u8],
    pub host_receipt_bytes: &'a [u8],
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCaseDigestV1 {
    pub selector: String,
    pub case_sha256: DiagnosticSha256,
    pub result_key: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEvidenceIndexV1 {
    pub schema_version: u8,
    pub target: String,
    pub native_machine: String,
    pub source_commit: String,
    pub release_version: String,
    pub archive_sha256: DiagnosticSha256,
    pub manifest_sha256: DiagnosticSha256,
    pub qualification_sha256: DiagnosticSha256,
    pub host_receipt_sha256: DiagnosticSha256,
    pub installation_epoch: DiagnosticSha256,
    pub boot_identity: String,
    pub historical_epoch_sha256: DiagnosticSha256,
    pub cases: Vec<PublicCaseDigestV1>,
}

impl PublicEvidenceIndexV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(CiError::Message("public P index byte bound differs".into()));
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
            .map_err(CiError::Message)?;
        let index: Self = serde_json::from_slice(bytes)?;
        if index.schema_version != 1
            || index.cases.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
            || index
                .cases
                .iter()
                .zip(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1)
                .any(|(case, selector)| {
                    case.selector != selector
                        || case.case_sha256 == hash_bytes(&[])
                        || case.result_key == hash_bytes(&[])
                })
            || index.boot_identity.is_empty()
            || index.historical_epoch_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || index.boot_identity.len() > 128
            || index.release_version.is_empty()
            || index.source_commit.len() != 40
            || !index
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !matches!(
                (index.target.as_str(), index.native_machine.as_str()),
                ("x86_64-unknown-linux-gnu", "x86_64") | ("aarch64-unknown-linux-gnu", "aarch64")
            )
        {
            return Err(CiError::Message("public P index identity differs".into()));
        }
        Ok(index)
    }
}

/// P V2 indexes 22 ordinary cases and three selector-specific composites.
/// None can be silently replaced by an ordinary one-child case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicCaseEvidenceFormatV2 {
    SingleCaseV2,
    PolicyCompositeV1,
    AbiCompositeV1,
    ReuseCompositeV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCaseDigestV2 {
    pub selector: String,
    pub evidence_format: PublicCaseEvidenceFormatV2,
    pub case_sha256: DiagnosticSha256,
    pub result_key: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEvidenceIndexV2 {
    pub schema_version: u8,
    pub target: String,
    pub native_machine: String,
    pub source_commit: String,
    pub release_version: String,
    pub archive_sha256: DiagnosticSha256,
    pub manifest_sha256: DiagnosticSha256,
    pub qualification_sha256: DiagnosticSha256,
    pub host_receipt_sha256: DiagnosticSha256,
    pub installation_epoch: DiagnosticSha256,
    pub boot_identity: String,
    pub historical_epoch_sha256: DiagnosticSha256,
    pub cases: Vec<PublicCaseDigestV2>,
}

impl PublicEvidenceIndexV2 {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(CiError::Message(
                "public P V2 index byte bound differs".into(),
            ));
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
            .map_err(CiError::Message)?;
        let index: Self = serde_json::from_slice(bytes)?;
        let zero = DiagnosticSha256::from_bytes([0; 32]);
        let mut keys = BTreeSet::new();
        let mut cases = BTreeSet::new();
        if index.schema_version != 2
            || index.cases.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
            || index.cases.iter().zip(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1).any(|(case, selector)| {
                let format = if selector == memcordon_core::private_public_policy_composite_v1::PUBLIC_POLICY_SELECTOR_V1 {
                    PublicCaseEvidenceFormatV2::PolicyCompositeV1
                } else if selector == memcordon_core::private_public_abi_composite_v1::PUBLIC_ABI_SELECTOR_V1 {
                    PublicCaseEvidenceFormatV2::AbiCompositeV1
                } else if selector == memcordon_core::private_public_reuse_composite_v1::PUBLIC_REUSE_SELECTOR_V1 {
                    PublicCaseEvidenceFormatV2::ReuseCompositeV1
                } else {
                    PublicCaseEvidenceFormatV2::SingleCaseV2
                };
                case.selector != selector
                    || case.evidence_format != format
                    || case.case_sha256 == zero
                    || case.result_key == zero
                    || !keys.insert(*case.result_key.bytes())
                    || !cases.insert(*case.case_sha256.bytes())
            })
            || index.boot_identity.is_empty()
            || index.boot_identity.len() > 128
            || index.release_version.is_empty()
            || index.source_commit.len() != 40
            || !index.source_commit.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !matches!((index.target.as_str(), index.native_machine.as_str()),
                ("x86_64-unknown-linux-gnu", "x86_64") | ("aarch64-unknown-linux-gnu", "aarch64"))
            || [
                &index.archive_sha256, &index.manifest_sha256, &index.qualification_sha256,
                &index.host_receipt_sha256, &index.installation_epoch,
                &index.historical_epoch_sha256,
            ].contains(&&zero)
        {
            return Err(CiError::Message("public P V2 index identity or case format differs".into()));
        }
        Ok(index)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_public_policy_composite(
    bytes: &[u8],
    live: &[PublicPolicyBranchLiveV1; 5],
) -> Result<VerifiedPublicPolicyCompositeV1> {
    let case = PublicPolicyCompositeCaseV1::parse(bytes).map_err(CiError::Message)?;
    let provider_inventory = serde_json::to_vec(
        &case
            .branches
            .iter()
            .map(|branch| &branch.provider_record_sha256)
            .collect::<Vec<_>>(),
    )?;
    let interval_inventory = serde_json::to_vec(
        &case
            .branches
            .iter()
            .map(|branch| &branch.kernel_capture_sha256)
            .collect::<Vec<_>>(),
    )?;
    if hash_bytes(&provider_inventory) != case.provider_inventory_sha256
        || hash_bytes(&interval_inventory) != case.interval_inventory_sha256
    {
        return Err(CiError::Message(
            "public policy composite inventory digests differ".into(),
        ));
    }
    for (record, observed) in case.branches.iter().zip(live) {
        let child = observed
            .observed
            .process
            .linux_child
            .ok_or_else(|| CiError::Message("public policy supervised child absent".into()))?;
        let report = observed
            .observed
            .report_bytes
            .as_ref()
            .ok_or_else(|| CiError::Message("public policy supervised report absent".into()))?;
        let raw_inventory = serde_json::to_vec(
            &observed
                .attachments
                .iter()
                .map(|item| (item.role, item.bytes.len() as u64, hash_bytes(&item.bytes)))
                .collect::<Vec<_>>(),
        )?;
        let accepted = matches!(
            record.outcome,
            PublicPolicyBranchOutcomeV1::AcceptedControl { .. }
        );
        if observed.provider.result_key != record.result_key
            || observed.provider.policy_branch != Some(record.branch)
            || observed.interval.result_key() != &record.result_key
            || observed.interval.trace_sha256() != &record.kernel_capture_sha256
            || observed.joined.capture_sha256() != observed.interval.trace_sha256()
            || hash_bytes(&observed.provider.record_bytes) != record.provider_record_sha256
            || hash_bytes(&observed.provider.plan_response_bytes) != record.plan_response_sha256
            || hash_bytes(&observed.provider.grant_decision_bytes) != record.grant_decision_sha256
            || hash_bytes(report) != record.report_sha256
            || hash_bytes(&observed.observed.stdio_bytes) != record.stdio_sha256
            || hash_bytes(&raw_inventory) != record.raw_inventory_sha256
            || child.pid != record.child.pid
            || child.start_time_ticks != record.child.start_time_ticks
            || observed.observed.cli_sha256 != record.child.executable_sha256
            || observed.observed.argv_sha256 != record.child.argv_sha256
            || observed.observed.working_directory_sha256 != record.child.working_directory_sha256
            || observed.interval.boot_id() != record.child.boot_identity.as_str()
            || accepted && observed.joined.target_count() != 1
            || !accepted
                && (observed.joined.target_count() != 0 || !observed.interval.no_allocation())
        {
            return Err(CiError::Message(
                "public policy branch lacks independently joined actor/provider/kernel bytes"
                    .into(),
            ));
        }
        match &record.outcome {
            PublicPolicyBranchOutcomeV1::AcceptedControl {
                attempt_id,
                target_identity_sha256,
                terminal_sha256,
                cleanup_sha256,
            } => {
                let Some(attempt) = observed.provider.attempts.first() else {
                    return Err(CiError::Message(
                        "public policy accepted attempt absent".into(),
                    ));
                };
                if observed.provider.attempts.len() != 1
                    || attempt.attempt_id != *attempt_id
                    || attempt
                        .target_identity_bytes
                        .as_ref()
                        .is_none_or(|bytes| hash_bytes(bytes) != *target_identity_sha256)
                    || attempt
                        .terminal_bytes
                        .as_ref()
                        .is_none_or(|bytes| hash_bytes(bytes) != *terminal_sha256)
                    || attempt
                        .cleanup_bytes
                        .as_ref()
                        .is_none_or(|bytes| hash_bytes(bytes) != *cleanup_sha256)
                {
                    return Err(CiError::Message(
                        "public policy accepted target/terminal/cleanup differs".into(),
                    ));
                }
            }
            PublicPolicyBranchOutcomeV1::PlanDenied {
                rejection_sha256, ..
            } => {
                if !observed.provider.attempts.is_empty()
                    || observed
                        .provider
                        .terminal_bytes
                        .as_ref()
                        .is_none_or(|bytes| hash_bytes(bytes) != *rejection_sha256)
                {
                    return Err(CiError::Message(
                        "public policy plan rejection differs".into(),
                    ));
                }
            }
            PublicPolicyBranchOutcomeV1::FrozenPlanDenied { rejection_sha256 } => {
                if observed.provider.attempts.len() != 1
                    || hash_bytes(&observed.provider.attempts[0].response_bytes)
                        != *rejection_sha256
                    || observed.provider.attempts[0]
                        .target_identity_bytes
                        .is_some()
                    || observed.provider.attempts[0].terminal_bytes.is_some()
                    || observed.provider.attempts[0].cleanup_bytes.is_some()
                {
                    return Err(CiError::Message(
                        "public policy frozen rejection differs".into(),
                    ));
                }
            }
        }
    }
    Ok(VerifiedPublicPolicyCompositeV1 {
        case_sha256: hash_bytes(bytes),
        result_key: case.result_key().map_err(CiError::Message)?,
        target: case.target,
        native_machine: case.native_machine,
        source_commit: case.source_commit,
        release_version: case.release_version.as_str().into(),
        boot_identity: case.branches[0].child.boot_identity.as_str().into(),
        installation_epoch: case.installation_epoch,
        archive_sha256: case.archive_sha256,
        manifest_sha256: case.manifest_sha256,
        qualification_sha256: case.qualification_sha256,
        host_receipt_sha256: case.active_h1_receipt_sha256,
    })
}

/// The input readbacks are structural and the independent records cannot be
/// created from the uploaded P ZIP. If any case lacks the observer, no token
/// exists and no P index is issued.
pub(crate) fn verify_public_semantics(
    cases: &[(Vec<u8>, StructuralFinalPublicCaseReadbackV2)],
    independent: &[IndependentPublicObservationV1],
    policy: &VerifiedPublicPolicyCompositeV1,
    abi: &VerifiedPublicAbiCompositeV1,
    reuse: &VerifiedPublicReuseCompositeV1,
    installed: &FinalPublicInstalledBindingV2,
    historical: &VerifiedHistoricalPublicEpochV1,
) -> Result<VerifiedPublicSemanticsV2> {
    if cases.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len() - 3
        || independent.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len() - 3
    {
        return Err(CiError::Message(
            "public 25-case evidence is incomplete".into(),
        ));
    }
    let mut digests = Vec::with_capacity(cases.len());
    let mut boots = BTreeSet::new();
    let mut subject = None;
    for ((bytes, readback), (selector, sample)) in cases.iter().zip(
        REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
            .iter()
            .filter(|selector| {
                **selector != PUBLIC_POLICY_SELECTOR_V1
                    && **selector != PUBLIC_ABI_SELECTOR_V1
                    && **selector != PUBLIC_REUSE_SELECTOR_V1
            })
            .zip(independent),
    ) {
        let case = FinalPublicCaseEvidenceV2::parse(bytes).map_err(CiError::Message)?;
        let requirements = case_evidence_requirements_v1(selector)
            .ok_or_else(|| CiError::Message("public selector has no semantics".into()))?;
        let required_disposition = requirements.disposition;
        let events = sample.kernel_interval.events();
        let case_key = case.result_key().map_err(CiError::Message)?;
        let allocated = events.iter().any(|event| {
            matches!(event,
            KernelEventV1::AllocationBoundary {
                request_key,
                kind: AllocationBoundaryKindV1::Allocate,
                ..
            } if *request_key == case_key)
        });
        let decisions_joined = !sample.required_decisions.is_empty()
            && sample.required_decisions.iter().all(|decision| {
                sample.kernel_interval.seccomp_decision(
                    decision.task,
                    decision.arch,
                    decision.syscall,
                    decision.action,
                )
            });
        let target_exec = sample.target_task.is_some_and(|(task, start)|
            sample.clock_calibration.matches(task, start)
                && events.iter().any(|event| matches!(event, KernelEventV1::Exec { task: observed, .. } if *observed == task)));
        let target_retired = sample.target_task.is_some_and(|(task, start)| {
            sample.clock_calibration.matches(task, start)
                && sample.kernel_interval.retired_task(task)
        });
        if case.selector != *selector
            || sample.selector != *selector
            || case.installed != *installed
            || hash_bytes(bytes) != readback.case_sha256
            || hash_bytes(bytes) != sample.case_sha256
            || case.result_key().map_err(CiError::Message)? != readback.result_key
            || sample.archive_sha256 != installed.archive_sha256
            || sample.host_receipt_sha256 != installed.active_host_receipt_sha256
            || sample.kernel_interval.boot_id() != case.child.boot_identity.as_str()
            || sample.public_task.pid != case.child.pid
            || !sample
                .clock_calibration
                .matches(sample.public_task, case.child.start_time_ticks)
            || readback.child_pid != case.child.pid
            || readback.child_start_time_ticks != case.child.start_time_ticks
            || sample.kernel_interval.trace_sha256() == &hash_bytes(&[])
            || sample.kernel_interval.result_key() != &case_key
            || !sample.kernel_interval.has_allocation_boundary()
            || !decisions_joined
            || !sample.live_barrier_observed
            || requirements.requires_exec_event && !target_exec
            || required_disposition == RequiredDispositionV1::PreallocationDenied
                && !sample.kernel_interval.no_allocation()
            || required_disposition != RequiredDispositionV1::PreallocationDenied && !allocated
            || required_disposition != RequiredDispositionV1::PreallocationDenied && !target_retired
            || !sample.retirement_complete
            || matches!(
                case.report,
                PublicCliReportEvidenceV2::AbsentFrontendLoss { .. }
            ) && *selector != "private_tcp::frontend_loss_retired"
        {
            return Err(CiError::Message(
                "public independent case semantics differ".into(),
            ));
        }
        let actual_disposition = match case.observation {
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::PolicyComposite { .. } => {
                return Err(CiError::Message("candidate policy composite is not public evidence".into()));
            }
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::PreallocationRejected { .. } => RequiredDispositionV1::PreallocationDenied,
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::AllocatedRetired { .. } => RequiredDispositionV1::AllocatedAndRetired,
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::DualAttemptsRetired { .. } => RequiredDispositionV1::DualAllocatedAndRetired,
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::RetirementFailureBlockedReuse { .. } => RequiredDispositionV1::ReuseBlockedThenRetired,
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::AbiComposite { .. } => {
                return Err(CiError::Message("candidate ABI composite is not public evidence".into()));
            }
        };
        if actual_disposition != required_disposition {
            return Err(CiError::Message("public case disposition differs".into()));
        }
        if matches!(
            requirements.family,
            crate::private_native_verify::CaseEvidenceFamilyV1::AlternateAbi
                | crate::private_native_verify::CaseEvidenceFamilyV1::HistoricalEpoch
        ) {
            return Err(CiError::Message(format!(
                "public {selector} lacks joined provider branch transcript and independent kernel decision sequence"
            )));
        }
        let current = (
            case.target.clone(),
            case.native_machine.clone(),
            case.source_commit.clone(),
            case.release_version.as_str().to_owned(),
        );
        if subject
            .as_ref()
            .is_some_and(|previous| *previous != current)
        {
            return Err(CiError::Message(
                "public case release subject differs".into(),
            ));
        }
        subject = Some(current);
        boots.insert(sample.kernel_interval.boot_id());
        digests.push(PublicCaseDigestV2 {
            selector: (*selector).into(),
            evidence_format: PublicCaseEvidenceFormatV2::SingleCaseV2,
            case_sha256: readback.case_sha256.clone(),
            result_key: readback.result_key.clone(),
        });
    }
    let policy_subject = (
        policy.target.clone(),
        policy.native_machine.clone(),
        policy.source_commit.clone(),
        policy.release_version.clone(),
    );
    if subject.as_ref() != Some(&policy_subject)
        || policy.installation_epoch != installed.installation_epoch
        || policy.archive_sha256 != installed.archive_sha256
        || policy.manifest_sha256 != installed.qualified_manifest_sha256
        || policy.qualification_sha256 != installed.release_qualification_sha256
        || policy.host_receipt_sha256 != installed.active_host_receipt_sha256
    {
        return Err(CiError::Message(
            "public five-branch policy composite differs from installed P subject".into(),
        ));
    }
    boots.insert(policy.boot_identity.as_str());
    digests.push(PublicCaseDigestV2 {
        selector: PUBLIC_POLICY_SELECTOR_V1.into(),
        evidence_format: PublicCaseEvidenceFormatV2::PolicyCompositeV1,
        case_sha256: policy.case_sha256.clone(),
        result_key: policy.result_key.clone(),
    });
    for (
        selector,
        format,
        case_sha256,
        result_key,
        current,
        boot,
        epoch,
        archive,
        manifest,
        q,
        h1,
    ) in [
        (
            PUBLIC_ABI_SELECTOR_V1,
            PublicCaseEvidenceFormatV2::AbiCompositeV1,
            &abi.case_sha256,
            &abi.result_key,
            (
                &abi.target,
                &abi.native_machine,
                &abi.source_commit,
                &abi.release_version,
            ),
            abi.boot_identity.as_str(),
            &abi.installation_epoch,
            &abi.archive_sha256,
            &abi.manifest_sha256,
            &abi.qualification_sha256,
            &abi.host_receipt_sha256,
        ),
        (
            PUBLIC_REUSE_SELECTOR_V1,
            PublicCaseEvidenceFormatV2::ReuseCompositeV1,
            &reuse.case_sha256,
            &reuse.result_key,
            (
                &reuse.target,
                &reuse.native_machine,
                &reuse.source_commit,
                &reuse.release_version,
            ),
            reuse.boot_identity.as_str(),
            &reuse.installation_epoch,
            &reuse.archive_sha256,
            &reuse.manifest_sha256,
            &reuse.qualification_sha256,
            &reuse.host_receipt_sha256,
        ),
    ] {
        if subject.as_ref()
            != Some(&(
                current.0.to_string(),
                current.1.to_string(),
                current.2.to_string(),
                current.3.to_string(),
            ))
            || *epoch != installed.installation_epoch
            || *archive != installed.archive_sha256
            || *manifest != installed.qualified_manifest_sha256
            || *q != installed.release_qualification_sha256
            || *h1 != installed.active_host_receipt_sha256
        {
            return Err(CiError::Message(format!(
                "public {selector} composite differs from installed P subject"
            )));
        }
        boots.insert(boot);
        digests.push(PublicCaseDigestV2 {
            selector: selector.into(),
            evidence_format: format,
            case_sha256: case_sha256.clone(),
            result_key: result_key.clone(),
        });
    }
    let mut indexed = digests
        .into_iter()
        .map(|case| (case.selector.clone(), case))
        .collect::<std::collections::BTreeMap<_, _>>();
    if indexed.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len() {
        return Err(CiError::Message(
            "public composite/ordinary selector inventory differs".into(),
        ));
    }
    let digests = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .iter()
        .map(|selector| {
            indexed
                .remove(*selector)
                .ok_or_else(|| CiError::Message("public ordered selector evidence absent".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    if boots.len() != 1 {
        return Err(CiError::Message(
            "public cases did not share one host boot".into(),
        ));
    }
    if historical.e1_installation_epoch != installed.installation_epoch
        || historical.e1_host_receipt_sha256 != installed.active_host_receipt_sha256
        || historical.boot_identity != *boots.iter().next().expect("25 cases have a boot")
        || historical.transcript_sha256 == DiagnosticSha256::from_bytes([0; 32])
    {
        return Err(CiError::Message(
            "public historical E0/E1 transcript differs from P cases".into(),
        ));
    }
    let first = FinalPublicCaseEvidenceV2::parse(&cases[0].0).map_err(CiError::Message)?;
    Ok(VerifiedPublicSemanticsV2 {
        target: first.target,
        native_machine: first.native_machine,
        source_commit: first.source_commit,
        release_version: first.release_version.as_str().into(),
        installed: installed.clone(),
        historical_epoch_sha256: historical.transcript_sha256.clone(),
        boot_identity: boots
            .into_iter()
            .next()
            .expect("25 cases have a boot")
            .into(),
        cases: digests,
    })
}

pub(crate) fn produce_public_evidence_index(
    verified: &VerifiedPublicSemanticsV2,
) -> Result<Vec<u8>> {
    let index = PublicEvidenceIndexV2 {
        schema_version: 2,
        target: verified.target.clone(),
        native_machine: verified.native_machine.clone(),
        source_commit: verified.source_commit.clone(),
        release_version: verified.release_version.clone(),
        archive_sha256: verified.installed.archive_sha256.clone(),
        manifest_sha256: verified.installed.qualified_manifest_sha256.clone(),
        qualification_sha256: verified.installed.release_qualification_sha256.clone(),
        host_receipt_sha256: verified.installed.active_host_receipt_sha256.clone(),
        installation_epoch: verified.installed.installation_epoch.clone(),
        boot_identity: verified.boot_identity.clone(),
        historical_epoch_sha256: verified.historical_epoch_sha256.clone(),
        cases: verified.cases.clone(),
    };
    let bytes = serde_json::to_vec(&index)?;
    PublicEvidenceIndexV2::parse(&bytes)?;
    Ok(bytes)
}

/// No arbitrary JSON/hash signing API: the P index is regenerated from the
/// private verified semantics token and matched to the completed ZIP token.
pub(crate) fn sign_public_qualification_certificate(
    verified: &VerifiedPublicSemanticsV2,
    completed: &AuthenticatedCompletedPublicEvidenceV1,
    verified_q: &VerifiedNativeQualificationV1,
    intent: &PublicCertificateSigningIntentV1<'_>,
) -> Result<Vec<u8>> {
    let p_bytes = produce_public_evidence_index(verified)?;
    PublicEvidenceIndexV2::parse(&completed.public_index_bytes)?;
    let policy = intent
        .signed_policy
        .verify(
            intent.trust_anchor,
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    let key = policy
        .policy()
        .delegated_keys
        .iter()
        .find(|key| key.key_id == intent.key_id)
        .ok_or_else(|| CiError::Message("public P signing key is not delegated".into()))?;
    let completed_run = &completed.completed;
    let signed_q =
        SignedNativeQualificationCertificateV1::parse(intent.qualification_certificate_bytes)
            .map_err(CiError::Message)?;
    let build = PrivateCandidateRecordV2::parse(intent.build_bytes).map_err(CiError::Message)?;
    let canonical_q_sha256 = hash_bytes(
        &signed_q
            .payload
            .canonical_bytes()
            .map_err(CiError::Message)?,
    );
    let final_binding = completed_run
        .artifact
        .envelope
        .final_installed
        .as_ref()
        .ok_or_else(|| CiError::Message("completed P producer lacks final H1".into()))?;
    if completed.public_index_bytes != p_bytes
        || completed.raw_index_sha256 != hash_bytes(&p_bytes)
        || completed_run.artifact.producer.stage != NativeRunStageV2::FinalPublic
        || completed_run.artifact.producer.target != verified.target
        || completed_run.artifact.envelope.target != verified.target
        || completed_run.artifact.envelope.native_machine != verified.native_machine
        || completed_run.artifact.envelope.source_commit != verified.source_commit
        || completed_run.artifact.envelope.version != verified.release_version
        || final_binding.archive_sha256 != verified.installed.archive_sha256
        || final_binding.runtime_manifest_sha256 != verified.installed.qualified_manifest_sha256
        || final_binding.installed_receipt_sha256 != verified.installed.active_host_receipt_sha256
        || completed_run.repository_id != policy.policy().repository_id
        || completed_run.run_id.to_string() != completed_run.artifact.envelope.workflow_run_id
        || completed_run.run_attempt != completed_run.artifact.envelope.workflow_attempt
        || hash_bytes(intent.archive_bytes) != verified.installed.archive_sha256
        || hash_bytes(intent.manifest_bytes) != verified.installed.qualified_manifest_sha256
        || hash_bytes(intent.qualification_bytes) != verified.installed.release_qualification_sha256
        || hash_bytes(intent.host_receipt_bytes) != verified.installed.active_host_receipt_sha256
        || String::from(canonical_q_sha256) != verified_q.certificate_sha256()
        || signed_q.payload.build_sha256 != String::from(hash_bytes(intent.build_bytes))
        || signed_q.payload.qualification_sha256
            != String::from(hash_bytes(intent.qualification_bytes))
        || signed_q.payload.target != verified.target
        || signed_q.payload.source_commit != verified.source_commit
        || signed_q.payload.release_version != verified.release_version
        || signed_q.payload.release_sequence != intent.release_sequence
        || build.target != verified.target
        || build.source_commit != verified.source_commit
        || build.version != verified.release_version
        || build.component_sha256 != verified.installed.component_sha256
        || build.unit_sha256 != verified.installed.unit_sha256
        || build.filter_sha256 != verified.installed.filter_sha256
        || verified_q.release_sequence() != intent.release_sequence
        || intent.repository != policy.policy().repository
        || intent.workflow_path != policy.policy().workflow_path
        || intent.workflow_revision != policy.policy().workflow_revision
        || intent.verifier_sha256 != policy.policy().verifier_sha256
        || String::from(
            completed_run
                .artifact
                .envelope
                .release_catalogue_sha256
                .clone(),
        ) != policy.policy().catalogue_sha256
        || !key.roles.contains(&ReleaseSigningRoleV1::PublicP)
        || key.public_key_hex != hex_bytes(intent.signing_key.verifying_key().as_bytes())
        || intent.issued_at_unix < key.not_before_unix
        || intent.expires_at_unix > key.expires_at_unix
        || intent.release_sequence < policy.policy().minimum_release_sequence
        || intent.release_sequence < intent.high_water.release_sequence
        || intent.issued_at_unix >= intent.expires_at_unix
    {
        return Err(CiError::Message(
            "public P signing authority differs".into(),
        ));
    }
    let mut accepted = b"memcordon/public-accepted-case-set/v1\0".to_vec();
    for case in &verified.cases {
        accepted.extend_from_slice(&(case.selector.len() as u32).to_be_bytes());
        accepted.extend_from_slice(case.selector.as_bytes());
        accepted.extend_from_slice(case.case_sha256.bytes());
        accepted.extend_from_slice(case.result_key.bytes());
    }
    let payload = PublicQualificationCertificateV1 {
        schema_version: 1,
        policy_version: policy.policy().policy_version,
        key_id: intent.key_id.into(),
        release_sequence: intent.release_sequence,
        build_sha256: String::from(hash_bytes(intent.build_bytes)),
        qualification_sha256: String::from(hash_bytes(intent.qualification_bytes)),
        qualification_certificate_sha256: verified_q.certificate_sha256().into(),
        archive_sha256: String::from(verified.installed.archive_sha256.clone()),
        manifest_sha256: String::from(verified.installed.qualified_manifest_sha256.clone()),
        host_receipt_sha256: String::from(verified.installed.active_host_receipt_sha256.clone()),
        public_evidence_sha256: String::from(hash_bytes(&p_bytes)),
        public_evidence_size: p_bytes.len() as u64,
        raw_index_sha256: String::from(completed.raw_index_sha256.clone()),
        completed_provenance_sha256: String::from(completed_run.provenance_sha256.clone()),
        target: verified.target.clone(),
        native_machine: verified.native_machine.clone(),
        source_commit: verified.source_commit.clone(),
        release_version: verified.release_version.clone(),
        repository_id: completed_run.repository_id,
        repository: intent.repository.into(),
        workflow_path: intent.workflow_path.into(),
        workflow_revision: intent.workflow_revision.into(),
        run_id: completed_run.run_id,
        run_attempt: completed_run.run_attempt,
        producer_job_id: completed_run.producer_job_id,
        artifact_id: completed_run.artifact_id,
        verifier_sha256: intent.verifier_sha256.into(),
        verifier_source_commit: intent.verifier_source_commit.into(),
        verifier_policy_sha256: policy.policy().verifier_policy_sha256.clone(),
        catalogue_sha256: policy.policy().catalogue_sha256.clone(),
        accepted_case_set_sha256: String::from(hash_bytes(&accepted)),
        issued_at_unix: intent.issued_at_unix,
        expires_at_unix: intent.expires_at_unix,
        decision: "Complete".into(),
    };
    let canonical = payload.canonical_bytes().map_err(CiError::Message)?;
    let signed = SignedPublicQualificationCertificateV1 {
        payload,
        signature_hex: hex_bytes(&intent.signing_key.sign(&canonical).to_bytes()),
    };
    signed
        .verify(
            &policy,
            &ExpectedPublicQualificationV1 {
                release_sequence: intent.release_sequence,
                repository_id: completed_run.repository_id,
                repository: intent.repository,
                workflow_path: intent.workflow_path,
                workflow_revision: intent.workflow_revision,
                run_id: completed_run.run_id,
                run_attempt: completed_run.run_attempt,
                producer_job_id: completed_run.producer_job_id,
                artifact_id: completed_run.artifact_id,
                target: &verified.target,
                native_machine: &verified.native_machine,
                source_commit: &verified.source_commit,
                release_version: &verified.release_version,
                verifier_sha256: intent.verifier_sha256,
                verifier_source_commit: intent.verifier_source_commit,
                build_sha256: &String::from(hash_bytes(intent.build_bytes)),
                qualification_sha256: &String::from(hash_bytes(intent.qualification_bytes)),
                qualification_certificate_sha256: verified_q.certificate_sha256(),
                archive_sha256: &String::from(verified.installed.archive_sha256.clone()),
                manifest_sha256: &String::from(
                    verified.installed.qualified_manifest_sha256.clone(),
                ),
                host_receipt_sha256: &String::from(
                    verified.installed.active_host_receipt_sha256.clone(),
                ),
                public_evidence_bytes: &p_bytes,
                raw_index_sha256: &String::from(completed.raw_index_sha256.clone()),
                completed_provenance_sha256: &String::from(completed_run.provenance_sha256.clone()),
                accepted_case_set_sha256: &String::from(hash_bytes(&accepted)),
            },
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    Ok(serde_json::to_vec(&signed)?)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
