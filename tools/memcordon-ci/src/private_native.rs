//! Strict structural readback of private native-run records.
//!
//! A matching JSON document is not native evidence by itself. The caller must
//! obtain expected workflow identity from the CI platform, independently read
//! every raw attachment, and authenticate the supervising runner before using
//! any resulting completion as release qualification authority.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Component, Path};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::certification_context::ExpectedCertificationOrigin;
use crate::{CiError, Result};

const MAX_ENVELOPE_BYTES: usize = 128 * 1024;
const MAX_ATTACHMENT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeRunStageV2 {
    CandidateCapability,
    FinalPublic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateNativeProducerSpec {
    pub stage: NativeRunStageV2,
    pub target: &'static str,
    pub native_machine: &'static str,
    pub job_id: &'static str,
    pub job_name: &'static str,
    pub runner_label: &'static str,
    pub artifact_name: &'static str,
}

pub const PRODUCERS: [PrivateNativeProducerSpec; 4] = [
    PrivateNativeProducerSpec {
        stage: NativeRunStageV2::CandidateCapability,
        target: "aarch64-unknown-linux-gnu",
        native_machine: "aarch64",
        job_id: "linux-private-candidate",
        job_name: "Release / Linux private candidate / arm64",
        runner_label: "ubuntu-24.04-arm",
        artifact_name: "release-private-candidate-arm64",
    },
    PrivateNativeProducerSpec {
        stage: NativeRunStageV2::CandidateCapability,
        target: "x86_64-unknown-linux-gnu",
        native_machine: "x86_64",
        job_id: "linux-private-candidate",
        job_name: "Release / Linux private candidate / x64",
        runner_label: "ubuntu-24.04",
        artifact_name: "release-private-candidate-x64",
    },
    PrivateNativeProducerSpec {
        stage: NativeRunStageV2::FinalPublic,
        target: "aarch64-unknown-linux-gnu",
        native_machine: "aarch64",
        job_id: "linux-private-final",
        job_name: "Release / Linux private final / arm64",
        runner_label: "ubuntu-24.04-arm",
        artifact_name: "release-private-final-arm64",
    },
    PrivateNativeProducerSpec {
        stage: NativeRunStageV2::FinalPublic,
        target: "x86_64-unknown-linux-gnu",
        native_machine: "x86_64",
        job_id: "linux-private-final",
        job_name: "Release / Linux private final / x64",
        runner_label: "ubuntu-24.04",
        artifact_name: "release-private-final-x64",
    },
];

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalInstalledBindingV2 {
    pub archive_sha256: DiagnosticSha256,
    pub runtime_manifest_sha256: DiagnosticSha256,
    pub installed_receipt_sha256: DiagnosticSha256,
}

/// Candidate M0 and installed unqualified H0, measured independently before
/// the native capability run. H0 is not qualification or public admission.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateInstalledBindingV2 {
    pub runtime_manifest_sha256: DiagnosticSha256,
    pub installed_inspection_sha256: DiagnosticSha256,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeAttachmentRoleV2 {
    Request,
    Report,
    Stdio,
    Observer,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCasePhaseV2 {
    PreallocationRejected,
    AllocatedRetired,
    RetirementFailureBlockedReuse,
}

/// The native result required for a named case. A passed test is not a
/// successful target invocation for denial and retirement-failure cases.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCaseOutcomeV2 {
    TargetCompleted,
    GrantRejected,
    PublicGrantRejected,
    AuthorizationUncertain,
    FrontendLost,
    GuardianLost,
    RetirementUnprovedReuseBlocked,
}

/// Reviewed shape for each required name. Listing a name here does not mean
/// its physical native selector exists or that a result is trusted evidence.
pub(crate) fn expected_case_result(
    name: &str,
    stage: NativeRunStageV2,
) -> Option<(NativeCasePhaseV2, NativeCaseOutcomeV2, bool)> {
    Some(match name {
        "private_tcp::wrong_grant_profile_and_port_rejected" => (
            NativeCasePhaseV2::PreallocationRejected,
            if stage == NativeRunStageV2::FinalPublic {
                NativeCaseOutcomeV2::PublicGrantRejected
            } else {
                NativeCaseOutcomeV2::GrantRejected
            },
            false,
        ),
        "private_tcp::retirement_failure_blocks_reuse" => (
            NativeCasePhaseV2::RetirementFailureBlockedReuse,
            NativeCaseOutcomeV2::RetirementUnprovedReuseBlocked,
            false,
        ),
        "private_tcp::authorization_uncertainty_retired" => (
            NativeCasePhaseV2::AllocatedRetired,
            NativeCaseOutcomeV2::AuthorizationUncertain,
            false,
        ),
        "private_tcp::frontend_loss_retired" => (
            NativeCasePhaseV2::AllocatedRetired,
            NativeCaseOutcomeV2::FrontendLost,
            false,
        ),
        "private_tcp::guardian_loss_retired" => (
            NativeCasePhaseV2::AllocatedRetired,
            NativeCaseOutcomeV2::GuardianLost,
            false,
        ),
        "private_tcp::abi_alternate_entry_denied"
        | "private_tcp::af_unix_abstract_and_pathname_denied"
        | "private_tcp::af_unix_socketpair_denied"
        | "private_tcp::caller_identity_and_epoch_bound"
        | "private_tcp::checkpoint_persisted_before_release"
        | "private_tcp::child_runtime_and_threads_retired"
        | "private_tcp::descriptor_table_and_stdio_bound"
        | "private_tcp::dual_attempt_namespace_isolation"
        | "private_tcp::elf_ancestor_and_identity_pinned"
        | "private_tcp::host_namespace_and_sysctl_unchanged"
        | "private_tcp::io_uring_and_pidfd_import_denied"
        | "private_tcp::namespace_reentry_denied"
        | "private_tcp::native_filter_digest_and_abi_bound"
        | "private_tcp::native_tcp_bind_listen_connect"
        | "private_tcp::port_collision_same_namespace"
        | "private_tcp::private_namespace_topology_exact"
        | "private_tcp::release_checkpoint_terminal_joined"
        | "private_tcp::scm_rights_and_precreated_socket_denied"
        | "private_tcp::target_credentials_and_capabilities_dropped"
        | "private_tcp::target_exec_and_fd_leak_observed" => (
            NativeCasePhaseV2::AllocatedRetired,
            NativeCaseOutcomeV2::TargetCompleted,
            true,
        ),
        _ => return None,
    })
}

const ATTACHMENT_ROLES: [NativeAttachmentRoleV2; 5] = [
    NativeAttachmentRoleV2::Request,
    NativeAttachmentRoleV2::Report,
    NativeAttachmentRoleV2::Stdio,
    NativeAttachmentRoleV2::Observer,
    NativeAttachmentRoleV2::Cleanup,
];

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAttachmentV2 {
    pub role: NativeAttachmentRoleV2,
    pub path: String,
    pub sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCaseCompletionV2 {
    pub name: String,
    pub attempt_id: Option<String>,
    pub passed: bool,
    pub phase: NativeCasePhaseV2,
    pub outcome: NativeCaseOutcomeV2,
    pub supervisor_observed_exec: bool,
    pub retirement_proved: bool,
    pub reuse_blocked: bool,
    pub attachments: Vec<NativeAttachmentV2>,
}

/// Raw observer attachment emitted by the supervising process, never by the
/// target. Parsing and joining this record is still not proof that the
/// supervisor was trusted or that a native target actually ran.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSupervisorObservationV2 {
    pub schema_version: u32,
    pub challenge: String,
    pub case_name: String,
    pub stage: NativeRunStageV2,
    pub target: String,
    pub phase: NativeCasePhaseV2,
    pub outcome: NativeCaseOutcomeV2,
    pub attempt_id: Option<String>,
    pub target_exec_observed: bool,
    pub retirement_proved: bool,
    pub reuse_blocked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRunEnvelopeV2 {
    pub schema_version: u32,
    pub stage: NativeRunStageV2,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub native_machine: String,
    pub workflow_run_id: String,
    pub workflow_job: String,
    pub workflow_attempt: u32,
    pub challenge: String,
    pub invocation_argv: Vec<String>,
    pub build_context_sha256: DiagnosticSha256,
    pub runner_sha256: DiagnosticSha256,
    pub host_prerequisites_sha256: DiagnosticSha256,
    pub release_catalogue_sha256: DiagnosticSha256,
    pub component_sha256: DiagnosticSha256,
    pub unit_sha256: DiagnosticSha256,
    pub filter_sha256: DiagnosticSha256,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub candidate_installed: Option<CandidateInstalledBindingV2>,
    pub final_installed: Option<FinalInstalledBindingV2>,
    pub cases: Vec<NativeCaseCompletionV2>,
}

/// These fields must originate outside the submitted run envelope and its
/// attachments. In particular, matching the workflow strings is not proof of
/// artifact ownership without a CI-platform provenance check.
pub struct ExpectedNativeRunV2<'a> {
    pub stage: NativeRunStageV2,
    pub version: &'a str,
    pub source_commit: &'a str,
    pub target: &'a str,
    pub native_machine: &'a str,
    pub workflow_run_id: &'a str,
    pub workflow_job: &'a str,
    pub workflow_attempt: u32,
    pub challenge: &'a str,
    pub invocation_argv: &'a [String],
    pub build_context_sha256: &'a DiagnosticSha256,
    pub runner_sha256: &'a DiagnosticSha256,
    pub host_prerequisites_sha256: &'a DiagnosticSha256,
    pub release_catalogue_sha256: &'a DiagnosticSha256,
    pub component_sha256: &'a DiagnosticSha256,
    pub unit_sha256: &'a DiagnosticSha256,
    pub filter_sha256: &'a DiagnosticSha256,
    pub candidate_installed: Option<&'a CandidateInstalledBindingV2>,
    pub final_installed: Option<&'a FinalInstalledBindingV2>,
}

/// Performs bounded, exact-inventory readback. This is a structural result;
/// it deliberately cannot be converted to `TrustedNativeCompletionV2` until
/// platform artifact provenance and native observer semantics are verified.
pub fn validate_native_run_envelope(
    bytes: &[u8],
    attachments: &BTreeMap<String, Vec<u8>>,
    expected: &ExpectedNativeRunV2<'_>,
) -> Result<NativeRunEnvelopeV2> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(error("private native envelope exceeds bound"));
    }
    reject_duplicate_json_keys(bytes).map_err(error)?;
    let envelope: NativeRunEnvelopeV2 = serde_json::from_slice(bytes)?;
    let inventory: PrivateNativeInventoryV2 =
        toml::from_str(include_str!("../../../ci/private-native-v2.toml"))?;
    if inventory.schema_version != 1
        || inventory.profile != "linux-tcp4-private-v1"
        || inventory.targets != ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
        || !inventory
            .targets
            .iter()
            .any(|target| target == expected.target)
        || inventory.tests.len() != 25
        || inventory.tests.windows(2).any(|pair| pair[0] >= pair[1])
        || envelope.schema_version != 2
        || envelope.stage != expected.stage
        || envelope.version != expected.version
        || envelope.source_commit != expected.source_commit
        || envelope.target != expected.target
        || envelope.native_machine != expected.native_machine
        || envelope.workflow_run_id != expected.workflow_run_id
        || envelope.workflow_job != expected.workflow_job
        || envelope.workflow_attempt == 0
        || envelope.workflow_attempt != expected.workflow_attempt
        || envelope.challenge != expected.challenge
        || envelope.invocation_argv != expected.invocation_argv
        || envelope.build_context_sha256 != *expected.build_context_sha256
        || envelope.runner_sha256 != *expected.runner_sha256
        || envelope.host_prerequisites_sha256 != *expected.host_prerequisites_sha256
        || envelope.release_catalogue_sha256 != *expected.release_catalogue_sha256
        || envelope.release_catalogue_sha256
            != hash_bytes(include_bytes!("../../../ci/private-native-v2.toml"))
        || envelope.component_sha256 != *expected.component_sha256
        || envelope.unit_sha256 != *expected.unit_sha256
        || envelope.filter_sha256 != *expected.filter_sha256
        || envelope.candidate_installed.as_ref() != expected.candidate_installed
        || envelope.final_installed.as_ref() != expected.final_installed
        || envelope.started_unix_ms == 0
        || envelope.completed_unix_ms < envelope.started_unix_ms
        || !valid_hex(&envelope.source_commit, std::mem::size_of::<[u8; 20]>())
        || !valid_hex(&envelope.challenge, std::mem::size_of::<[u8; 32]>())
        || envelope.version.is_empty()
        || envelope.version.len() > 64
        || envelope.invocation_argv.is_empty()
        || envelope.invocation_argv.len() > 64
        || envelope
            .invocation_argv
            .iter()
            .any(|arg| arg.is_empty() || arg.len() > 4096)
        || envelope.workflow_run_id.is_empty()
        || envelope.workflow_job.is_empty()
        || envelope.cases.len() != inventory.tests.len()
        || match envelope.target.as_str() {
            "x86_64-unknown-linux-gnu" => envelope.native_machine != "x86_64",
            "aarch64-unknown-linux-gnu" => envelope.native_machine != "aarch64",
            _ => true,
        }
        || matches!(envelope.stage, NativeRunStageV2::CandidateCapability)
            && (envelope.candidate_installed.is_none() || envelope.final_installed.is_some())
        || matches!(envelope.stage, NativeRunStageV2::FinalPublic)
            && (envelope.candidate_installed.is_some() || envelope.final_installed.is_none())
    {
        return Err(error("private native run identity or inventory differs"));
    }
    let mut seen_paths = BTreeSet::new();
    for (case, name) in envelope.cases.iter().zip(&inventory.tests) {
        let (required_phase, required_outcome, requires_exec) =
            expected_case_result(name, envelope.stage)
                .ok_or_else(|| error("private native selector has no fixed outcome contract"))?;
        if case.name != *name
            || match (&case.phase, &case.attempt_id) {
                (NativeCasePhaseV2::PreallocationRejected, None) => false,
                (NativeCasePhaseV2::AllocatedRetired, Some(id))
                | (NativeCasePhaseV2::RetirementFailureBlockedReuse, Some(id)) => {
                    !valid_hex(id, std::mem::size_of::<[u8; 16]>())
                }
                _ => true,
            }
            || !case.passed
            || case.phase != required_phase
            || case.outcome != required_outcome
            || requires_exec && !case.supervisor_observed_exec
            || match case.phase {
                NativeCasePhaseV2::PreallocationRejected => {
                    case.supervisor_observed_exec || case.retirement_proved || case.reuse_blocked
                }
                NativeCasePhaseV2::AllocatedRetired => {
                    !case.retirement_proved || case.reuse_blocked
                }
                NativeCasePhaseV2::RetirementFailureBlockedReuse => {
                    case.retirement_proved || !case.reuse_blocked
                }
            }
            || case.attachments.len() != ATTACHMENT_ROLES.len()
        {
            return Err(error("private native case completion differs"));
        }
        for (attachment, role) in case.attachments.iter().zip(ATTACHMENT_ROLES) {
            if attachment.role != role
                || !valid_relative_path(&attachment.path)
                || !seen_paths.insert(attachment.path.as_str())
            {
                return Err(error("private native attachment inventory differs"));
            }
            let raw = attachments
                .get(&attachment.path)
                .ok_or_else(|| error("private native attachment is missing"))?;
            if raw.len() > MAX_ATTACHMENT_BYTES || hash_bytes(raw) != attachment.sha256 {
                return Err(error("private native attachment bytes differ"));
            }
            if role == NativeAttachmentRoleV2::Observer {
                reject_duplicate_json_keys(raw).map_err(error)?;
                let observation: NativeSupervisorObservationV2 = serde_json::from_slice(raw)?;
                if observation.schema_version != 2
                    || observation.challenge != envelope.challenge
                    || observation.case_name != case.name
                    || observation.stage != envelope.stage
                    || observation.target != envelope.target
                    || observation.phase != case.phase
                    || observation.outcome != case.outcome
                    || observation.attempt_id != case.attempt_id
                    || observation.target_exec_observed != case.supervisor_observed_exec
                    || observation.retirement_proved != case.retirement_proved
                    || observation.reuse_blocked != case.reuse_blocked
                {
                    return Err(error("private native raw observer differs from completion"));
                }
            }
        }
    }
    if attachments.len() != seen_paths.len() {
        return Err(error("private native run has extra attachments"));
    }
    Ok(envelope)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateNativeInventoryV2 {
    schema_version: u32,
    profile: String,
    targets: Vec<String>,
    tests: Vec<String>,
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.contains('\\')
        && !path.contains(':')
        && path.split('/').all(|part| {
            !part.is_empty()
                && !matches!(part, "." | "..")
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        })
}

/// Joins independently fetched GitHub run, job, and artifact metadata to the
/// downloaded artifact ZIP. This authenticates workflow ownership of those
/// bytes; native observer semantics and installed qualification remain
/// separate checks.
pub fn validate_native_run_platform_provenance(
    envelope: &NativeRunEnvelopeV2,
    origin: &ExpectedCertificationOrigin,
    run: &Value,
    jobs: &Value,
    artifact: &Value,
    archive_bytes: &[u8],
) -> Result<PrivateNativeProducerSpec> {
    let fail = || error("private native producer provenance differs");
    let spec = PRODUCERS
        .into_iter()
        .find(|spec| spec.stage == envelope.stage && spec.target == envelope.target)
        .ok_or_else(fail)?;
    let (workflow_path, expected_ref) = origin
        .workflow_ref
        .split_once("/.github/workflows/")
        .and_then(|(_, tail)| tail.split_once('@'))
        .map(|(file, reference)| ([".github/workflows/", file].concat(), reference))
        .ok_or_else(fail)?;
    let run_path = run.get("path").and_then(Value::as_str).ok_or_else(fail)?;
    let (run_workflow_path, run_ref) = run_path.split_once('@').ok_or_else(fail)?;
    let short_ref = expected_ref
        .strip_prefix("refs/heads/")
        .or_else(|| expected_ref.strip_prefix("refs/tags/"));
    if workflow_path != ".github/workflows/release.yml"
        || run_workflow_path != workflow_path
        || run_ref.is_empty()
        || run_ref.contains("..")
        || (run_ref != expected_ref && short_ref != Some(run_ref))
        || matches!(envelope.stage, NativeRunStageV2::CandidateCapability)
            && (envelope.candidate_installed.is_none() || envelope.final_installed.is_some())
        || matches!(envelope.stage, NativeRunStageV2::FinalPublic)
            && (envelope.candidate_installed.is_some() || envelope.final_installed.is_none())
        || origin.workflow_commit != origin.source_commit
        || envelope.source_commit != origin.source_commit
        || envelope.native_machine != spec.native_machine
        || envelope.workflow_run_id != origin.run_id.to_string()
        || envelope.workflow_job != spec.job_id
        || run.get("id").and_then(Value::as_u64) != Some(origin.run_id.get())
        || run.get("run_attempt").and_then(Value::as_u64)
            != Some(u64::from(envelope.workflow_attempt))
        || run.get("head_sha").and_then(Value::as_str) != Some(origin.source_commit.as_str())
        || run.pointer("/repository/full_name").and_then(Value::as_str)
            != Some(origin.repository.as_str())
        || !matches!(
            run.get("event").and_then(Value::as_str),
            Some("push" | "workflow_dispatch")
        )
        || run.get("status").and_then(Value::as_str) != Some("completed")
        || run.get("conclusion").and_then(Value::as_str) != Some("success")
        || archive_bytes.is_empty()
        || archive_bytes.len() > 128 * 1024 * 1024
    {
        return Err(fail());
    }
    let matching_jobs: Vec<_> = jobs
        .get("jobs")
        .and_then(Value::as_array)
        .ok_or_else(fail)?
        .iter()
        .filter(|job| job.get("name").and_then(Value::as_str) == Some(spec.job_name))
        .collect();
    if matching_jobs.len() != 1 {
        return Err(fail());
    }
    let job = matching_jobs[0];
    if job.get("run_id").and_then(Value::as_u64) != Some(origin.run_id.get())
        || job.get("run_attempt").and_then(Value::as_u64)
            != Some(u64::from(envelope.workflow_attempt))
        || job.get("head_sha").and_then(Value::as_str) != Some(origin.source_commit.as_str())
        || job.get("status").and_then(Value::as_str) != Some("completed")
        || job.get("conclusion").and_then(Value::as_str) != Some("success")
        || job
            .get("runner_id")
            .and_then(Value::as_u64)
            .is_none_or(|id| id == 0)
        || !job
            .get("labels")
            .and_then(Value::as_array)
            .is_some_and(|labels| {
                labels
                    .iter()
                    .any(|label| label.as_str() == Some(spec.runner_label))
            })
    {
        return Err(fail());
    }
    let archive_digest = format!("sha256:{}", String::from(hash_bytes(archive_bytes)));
    let repository_id = run
        .pointer("/repository/id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or_else(fail)?;
    if artifact
        .get("id")
        .and_then(Value::as_u64)
        .is_none_or(|id| id == 0)
        || artifact.get("name").and_then(Value::as_str) != Some(spec.artifact_name)
        || artifact.get("expired").and_then(Value::as_bool) != Some(false)
        || artifact.get("size_in_bytes").and_then(Value::as_u64)
            != u64::try_from(archive_bytes.len()).ok()
        || artifact.get("digest").and_then(Value::as_str) != Some(archive_digest.as_str())
        || artifact.pointer("/workflow_run/id").and_then(Value::as_u64) != Some(origin.run_id.get())
        || artifact
            .pointer("/workflow_run/repository_id")
            .and_then(Value::as_u64)
            != Some(repository_id)
        || artifact
            .pointer("/workflow_run/head_repository_id")
            .and_then(Value::as_u64)
            != Some(repository_id)
        || artifact
            .pointer("/workflow_run/head_sha")
            .and_then(Value::as_str)
            != Some(origin.source_commit.as_str())
    {
        return Err(fail());
    }
    Ok(spec)
}

/// Opens the exact downloaded Actions ZIP before structural and platform
/// checks. The result still cannot become `TrustedNativeCompletionV2` without
/// independent native supervisor and terminal semantics.
pub struct StructuralNativeArtifactV2 {
    pub envelope: NativeRunEnvelopeV2,
    pub producer: PrivateNativeProducerSpec,
}

/// Independent values measured from B, sealed A/M1, and installed H1. They
/// must not be copied from the submitted final-public envelope.
pub struct ExpectedFinalPublicJoinV2<'a> {
    pub source_commit: &'a str,
    pub version: &'a str,
    pub target: &'a str,
    pub workflow_run_id: &'a str,
    pub workflow_attempt: u32,
    pub component_sha256: &'a DiagnosticSha256,
    pub unit_sha256: &'a DiagnosticSha256,
    pub filter_sha256: &'a DiagnosticSha256,
    pub candidate_manifest_sha256: &'a DiagnosticSha256,
    pub candidate_inspection_sha256: &'a DiagnosticSha256,
    pub archive_sha256: &'a DiagnosticSha256,
    pub runtime_manifest_sha256: &'a DiagnosticSha256,
    pub installed_receipt_sha256: &'a DiagnosticSha256,
}

/// Only a structural join: neither raw supervisor authority nor installed H1
/// provenance is established here, and this result is not a publication gate.
pub struct StructuralFinalPublicJoinV2 {
    _private: (),
}

fn structural_case_inventory_matches(envelope: &NativeRunEnvelopeV2) -> bool {
    envelope.cases.len() == crate::private_suite::REQUIRED_CASES.len()
        && envelope
            .cases
            .iter()
            .zip(crate::private_suite::REQUIRED_CASES)
            .all(|(case, name)| {
                let Some((phase, outcome, requires_exec)) =
                    expected_case_result(name, envelope.stage)
                else {
                    return false;
                };
                case.name == name
                    && case.passed
                    && case.phase == phase
                    && case.outcome == outcome
                    && (!requires_exec || case.supervisor_observed_exec)
                    && match case.phase {
                        NativeCasePhaseV2::PreallocationRejected => {
                            !case.supervisor_observed_exec
                                && !case.retirement_proved
                                && !case.reuse_blocked
                        }
                        NativeCasePhaseV2::AllocatedRetired => {
                            case.retirement_proved && !case.reuse_blocked
                        }
                        NativeCasePhaseV2::RetirementFailureBlockedReuse => {
                            !case.retirement_proved && case.reuse_blocked
                        }
                    }
            })
}

pub fn validate_final_public_structural_join(
    candidate: &NativeRunEnvelopeV2,
    final_public: &NativeRunEnvelopeV2,
    expected: &ExpectedFinalPublicJoinV2<'_>,
) -> Result<StructuralFinalPublicJoinV2> {
    let candidate_producer = PRODUCERS
        .iter()
        .find(|spec| spec.stage == candidate.stage && spec.target == candidate.target);
    let final_producer = PRODUCERS
        .iter()
        .find(|spec| spec.stage == final_public.stage && spec.target == final_public.target);
    let installed = final_public.final_installed.as_ref();
    let candidate_installed = candidate.candidate_installed.as_ref();
    if candidate.stage != NativeRunStageV2::CandidateCapability
        || final_public.stage != NativeRunStageV2::FinalPublic
        || !structural_case_inventory_matches(candidate)
        || !structural_case_inventory_matches(final_public)
        || candidate_producer.is_none_or(|spec| spec.job_id != candidate.workflow_job)
        || final_producer.is_none_or(|spec| spec.job_id != final_public.workflow_job)
        || candidate.final_installed.is_some()
        || final_public.candidate_installed.is_some()
        || candidate_installed.is_none_or(|binding| {
            binding.runtime_manifest_sha256 != *expected.candidate_manifest_sha256
                || binding.installed_inspection_sha256 != *expected.candidate_inspection_sha256
        })
        || candidate.source_commit != expected.source_commit
        || final_public.source_commit != expected.source_commit
        || candidate.version != expected.version
        || final_public.version != expected.version
        || candidate.target != expected.target
        || final_public.target != expected.target
        || candidate.workflow_run_id != expected.workflow_run_id
        || final_public.workflow_run_id != expected.workflow_run_id
        || candidate.workflow_attempt != expected.workflow_attempt
        || final_public.workflow_attempt != expected.workflow_attempt
        || candidate.native_machine != final_public.native_machine
        || candidate.build_context_sha256 != final_public.build_context_sha256
        || candidate.release_catalogue_sha256
            != hash_bytes(include_bytes!("../../../ci/private-native-v2.toml"))
        || final_public.release_catalogue_sha256 != candidate.release_catalogue_sha256
        || candidate.component_sha256 != *expected.component_sha256
        || final_public.component_sha256 != *expected.component_sha256
        || candidate.unit_sha256 != *expected.unit_sha256
        || final_public.unit_sha256 != *expected.unit_sha256
        || candidate.filter_sha256 != *expected.filter_sha256
        || final_public.filter_sha256 != *expected.filter_sha256
        || candidate.challenge == final_public.challenge
        || final_public.started_unix_ms < candidate.completed_unix_ms
        || installed.is_none_or(|binding| {
            binding.archive_sha256 != *expected.archive_sha256
                || binding.runtime_manifest_sha256 != *expected.runtime_manifest_sha256
                || binding.installed_receipt_sha256 != *expected.installed_receipt_sha256
        })
    {
        return Err(error("final public native run differs from B/A/M1/H1 join"));
    }
    Ok(StructuralFinalPublicJoinV2 { _private: () })
}

pub fn validate_native_artifact_zip(
    archive_bytes: &[u8],
    expected: &ExpectedNativeRunV2<'_>,
    origin: &ExpectedCertificationOrigin,
    run: &Value,
    jobs: &Value,
    artifact: &Value,
) -> Result<StructuralNativeArtifactV2> {
    const MAX_ZIP_BYTES: usize = 128 * 1024 * 1024;
    const MAX_ENTRY_BYTES: u64 = 1024 * 1024;
    if archive_bytes.is_empty() || archive_bytes.len() > MAX_ZIP_BYTES {
        return Err(error("private native artifact ZIP exceeds bound"));
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes))?;
    if archive.len() != 1 + 25 * ATTACHMENT_ROLES.len() {
        return Err(error("private native artifact ZIP member count differs"));
    }
    let mut envelope_bytes = None;
    let mut attachments = BTreeMap::new();
    let mut expanded = 0usize;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        let path = Path::new(&name);
        let mode = entry
            .unix_mode()
            .ok_or_else(|| error("private native ZIP member mode is absent"))?;
        if !entry.is_file()
            || mode & 0o170000 != 0o100000
            || entry.size() > MAX_ENTRY_BYTES
            || name.len() > 256
            || name.contains(['\\', ':'])
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(error("private native ZIP member is unsafe"));
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        expanded = expanded
            .checked_add(bytes.len())
            .ok_or_else(|| error("private native ZIP expands beyond bound"))?;
        if expanded > MAX_ZIP_BYTES {
            return Err(error("private native ZIP expands beyond bound"));
        }
        if name == "private-native-run-v2.json" {
            if envelope_bytes.replace(bytes).is_some() {
                return Err(error("private native ZIP repeats envelope"));
            }
        } else if attachments.insert(name, bytes).is_some() {
            return Err(error("private native ZIP repeats attachment"));
        }
    }
    let envelope_bytes =
        envelope_bytes.ok_or_else(|| error("private native ZIP lacks envelope"))?;
    let envelope = validate_native_run_envelope(&envelope_bytes, &attachments, expected)?;
    let producer = validate_native_run_platform_provenance(
        &envelope,
        origin,
        run,
        jobs,
        artifact,
        archive_bytes,
    )?;
    Ok(StructuralNativeArtifactV2 { envelope, producer })
}

fn error(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}
