//! Bounded, root-protected readback for native release-case raw files.
//!
//! Protected bytes are a necessary input, not proof of a native case. The
//! supervising process, typed schema and hosted job provenance are checked
//! separately before any trusted completion may exist.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PRIVATE_RELEASE_RESULT_ROOT_V1, PrivateReleaseAllocatedOutcomeV1,
    PrivateReleaseAttachmentRoleV1, PrivateReleaseCaseResultV1, PrivateReleaseDualRetiredBranchV1,
    PrivateReleaseExecV1, PrivateReleaseInstalledBindingV1, PrivateReleaseObservationV1,
    PrivateReleaseStageV1,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::private_native::{
    NativeCaseOutcomeV2, NativeCasePhaseV2, NativeRunStageV2, expected_case_result,
};
use crate::{CiError, Result};

const MAX_RAW_CASE_BYTES: u64 = 1024 * 1024;

/// This result authenticates filesystem custody only. It is not a trusted
/// native completion until raw supervisor semantics and hosted job ownership
/// are independently verified.
pub struct StructuralProtectedNativeCaseV1 {
    pub result: PrivateReleaseCaseResultV1,
    pub candidate_request: ProtectedCandidateReleaseRequestV1,
    pub candidate_request_bytes: Vec<u8>,
    /// Present only after native allocation. Its contents remain structural.
    pub attempt_record: Option<ProtectedCandidateAttemptV1>,
    pub attempt_record_bytes: Option<Vec<u8>>,
    /// Only the blocked-retirement selector has this protected O_EXCL marker.
    pub fault_marker_bytes: Option<Vec<u8>>,
    /// Only the pre-release checkpoint selector has this protected gate leaf.
    pub checkpoint_gate_bytes: Option<Vec<u8>>,
    pub attachments: Vec<Vec<u8>>,
}

const RETIREMENT_FAULT_SELECTOR: &str = "private_tcp::retirement_failure_blocks_reuse";
const CHECKPOINT_GATE_SELECTOR: &str = "private_tcp::checkpoint_persisted_before_release";
const CHILD_RUNTIME_SELECTOR: &str = "private_tcp::child_runtime_and_threads_retired";
const SOCKET_SELECTOR: &str = "private_tcp::scm_rights_and_precreated_socket_denied";
const TERMINAL_JOIN_SELECTOR: &str = "private_tcp::release_checkpoint_terminal_joined";
const DUAL_SELECTOR: &str = "private_tcp::dual_attempt_namespace_isolation";

pub fn expected_protected_candidate_leaves(
    observation: &PrivateReleaseObservationV1,
) -> std::collections::BTreeSet<String> {
    let mut leaves: std::collections::BTreeSet<_> = PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .map(|role| role.leaf().to_owned())
        .collect();
    leaves.insert("request.json".to_owned());
    if !matches!(
        observation,
        PrivateReleaseObservationV1::PreallocationRejected { .. }
            | PrivateReleaseObservationV1::DualAttemptsRetired { .. }
    ) {
        leaves.insert("attempt.json".to_owned());
    }
    leaves
}

pub fn expected_protected_candidate_leaves_for_selector(
    selector: &str,
    observation: &PrivateReleaseObservationV1,
) -> Result<std::collections::BTreeSet<String>> {
    let mut leaves = expected_protected_candidate_leaves(observation);
    if matches!(
        observation,
        PrivateReleaseObservationV1::RetirementFailureBlockedReuse { .. }
    ) {
        if selector != RETIREMENT_FAULT_SELECTOR {
            return Err(CiError::Message(
                "blocked retirement result has wrong fixed selector".into(),
            ));
        }
        leaves.insert("attempt.json.new".into());
    }
    if selector == CHECKPOINT_GATE_SELECTOR {
        if !matches!(
            observation,
            PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
                ..
            }
        ) {
            return Err(CiError::Message(
                "checkpoint gate result has wrong fixed outcome".into(),
            ));
        }
        leaves.insert("checkpoint-gate.json".into());
    }
    if selector == CHILD_RUNTIME_SELECTOR {
        if !matches!(
            observation,
            PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
                ..
            }
        ) {
            return Err(CiError::Message(
                "child live gate result has wrong fixed outcome".into(),
            ));
        }
        leaves.insert("live-gate.json".into());
        leaves.insert("live-ack.json".into());
    }
    if selector == SOCKET_SELECTOR {
        if !matches!(
            observation,
            PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
                ..
            }
        ) {
            return Err(CiError::Message(
                "SCM socket gate result has wrong fixed outcome".into(),
            ));
        }
        leaves.insert("socket-gate.json".into());
        leaves.insert("socket-ack.json".into());
    }
    if selector == TERMINAL_JOIN_SELECTOR {
        if !matches!(
            observation,
            PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
                ..
            }
        ) {
            return Err(CiError::Message(
                "terminal midpoint result has wrong fixed outcome".into(),
            ));
        }
        leaves.insert("terminal-join-midflight.json".into());
        leaves.insert("terminal-join-gate.json".into());
        leaves.insert("terminal-join-ack.json".into());
    }
    if selector == DUAL_SELECTOR {
        if !matches!(
            observation,
            PrivateReleaseObservationV1::DualAttemptsRetired { .. }
        ) {
            return Err(CiError::Message(
                "dual result has wrong fixed observation".into(),
            ));
        }
        for leaf in [
            "dual-first",
            "dual-second",
            "dual-first-midflight.json",
            "dual-second-midflight.json",
            "dual-live-gate.json",
            "dual-live-ack.json",
        ] {
            leaves.insert(leaf.into());
        }
    }
    Ok(leaves)
}

/// The native result may not choose its own successful branch. Exact denial
/// codes and physical raw observations are deliberately outside this check.
pub fn validate_fixed_case_observation(
    stage: NativeRunStageV2,
    selector: &str,
    observation: &PrivateReleaseObservationV1,
) -> Result<()> {
    if !crate::private_suite::REQUIRED_CASES.contains(&selector) {
        return Err(CiError::Message(
            "private result selector is not required".into(),
        ));
    }
    let (expected_phase, expected_outcome, requires_exec) = expected_case_result(selector, stage)
        .ok_or_else(|| {
        CiError::Message("private selector has no fixed outcome contract".into())
    })?;
    if selector == DUAL_SELECTOR {
        if stage != NativeRunStageV2::CandidateCapability
            || expected_phase != NativeCasePhaseV2::AllocatedRetired
            || expected_outcome != NativeCaseOutcomeV2::TargetCompleted
            || !requires_exec
            || !matches!(
                observation,
                PrivateReleaseObservationV1::DualAttemptsRetired { .. }
            )
        {
            return Err(CiError::Message("dual fixed outcome differs".into()));
        }
        return Ok(());
    }
    let matches = match (expected_phase, expected_outcome, observation) {
        (
            NativeCasePhaseV2::PreallocationRejected,
            NativeCaseOutcomeV2::GrantRejected | NativeCaseOutcomeV2::PublicGrantRejected,
            PrivateReleaseObservationV1::PreallocationRejected { .. },
        ) => true,
        (
            NativeCasePhaseV2::RetirementFailureBlockedReuse,
            NativeCaseOutcomeV2::RetirementUnprovedReuseBlocked,
            PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
                release_knowledge,
                exec,
                ..
            },
        ) => {
            *release_knowledge
                == memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
                && *exec == PrivateReleaseExecV1::Succeeded
        }
        (
            NativeCasePhaseV2::AllocatedRetired,
            expected,
            PrivateReleaseObservationV1::AllocatedRetired {
                outcome,
                exec,
                release_knowledge,
                ..
            },
        ) => {
            let outcome_matches = matches!(
                (expected, outcome),
                (
                    NativeCaseOutcomeV2::TargetCompleted,
                    PrivateReleaseAllocatedOutcomeV1::TargetCompleted
                ) | (
                    NativeCaseOutcomeV2::AuthorizationUncertain,
                    PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain
                ) | (
                    NativeCaseOutcomeV2::FrontendLost,
                    PrivateReleaseAllocatedOutcomeV1::FrontendLost
                ) | (
                    NativeCaseOutcomeV2::GuardianLost,
                    PrivateReleaseAllocatedOutcomeV1::GuardianLost
                )
            );
            outcome_matches
                && if expected == NativeCaseOutcomeV2::AuthorizationUncertain {
                    *exec == PrivateReleaseExecV1::NotObserved
                        && *release_knowledge
                            == memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::PossiblyReleased
                } else {
                    !requires_exec || *exec == PrivateReleaseExecV1::Succeeded
                }
        }
        _ => false,
    };
    if !matches {
        return Err(CiError::Message(
            "private result phase or outcome differs from fixed catalogue".into(),
        ));
    }
    Ok(())
}

/// Native's protected admission ledger, distinct from raw `request.bin`.
/// Parsing and cross-joining this record remains structural; the coordinator
/// identity and service generation still need independent supervisor proof.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedCandidateReleaseRequestV1 {
    pub schema_version: u8,
    pub stage: String,
    pub selector: String,
    pub challenge: String,
    pub result_key: DiagnosticSha256,
    pub installation_epoch: DiagnosticSha256,
    pub candidate_manifest_sha256: DiagnosticSha256,
    pub service_generation_sha256: DiagnosticSha256,
    pub coordinator: ProtectedCoordinatorIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedCoordinatorIdentityV1 {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectedAttemptPhaseV1 {
    Allocated,
    AuthorityFrozen,
    BoundaryCreated,
    GuardianReady,
    TargetGated,
    CheckpointCommitted,
    ReleaseIntent,
    ExecutionObserved,
    Retiring,
    Retired,
    CleanupIncomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectedReleaseKnowledgeV1 {
    NotReleased,
    PossiblyReleased,
    ExecObserved,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedCandidateCheckpointV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    selector: String,
    challenge_sha256: DiagnosticSha256,
    attempt_id: String,
    installation_epoch: DiagnosticSha256,
    candidate_manifest_sha256: DiagnosticSha256,
    service_generation_sha256: DiagnosticSha256,
    fixture_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    target_uid: u32,
    target_gid: u32,
    guardian: ProtectedCoordinatorIdentityV1,
    namespace_init: ProtectedCoordinatorIdentityV1,
    target: ProtectedCoordinatorIdentityV1,
    network_namespace_inode: u64,
    topology_sha256: DiagnosticSha256,
    native_readback_sha256: DiagnosticSha256,
}

impl ProtectedCandidateCheckpointV1 {
    pub fn canonical_digest(&self) -> Result<DiagnosticSha256> {
        let mut digest = Sha256::new();
        digest.update(b"memcordon-private-release-candidate-checkpoint-v1\0");
        digest.update(serde_json::to_vec(self)?);
        Ok(DiagnosticSha256::from_bytes(digest.finalize().into()))
    }
}

/// Candidate-only journal mirror. Digest/identity validation does not prove
/// the native checkpoint, exec, or retirement named by the result.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedCandidateAttemptV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    selector: String,
    challenge_sha256: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    candidate_manifest_sha256: DiagnosticSha256,
    service_generation_sha256: DiagnosticSha256,
    attempt_id: String,
    coordinator: ProtectedCoordinatorIdentityV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frontend_proxy: Option<ProtectedCoordinatorIdentityV1>,
    phase: ProtectedAttemptPhaseV1,
    guardian: Option<ProtectedCoordinatorIdentityV1>,
    namespace_init: Option<ProtectedCoordinatorIdentityV1>,
    target: Option<ProtectedCoordinatorIdentityV1>,
    network_namespace_inode: Option<u64>,
    checkpoint_digest: Option<DiagnosticSha256>,
    checkpoint_binding: Option<ProtectedCandidateCheckpointV1>,
    release_knowledge: ProtectedReleaseKnowledgeV1,
    cleanup_error: Option<String>,
    candidate_exit_code: Option<i32>,
    record_digest: DiagnosticSha256,
}

impl ProtectedCandidateAttemptV1 {
    pub fn canonical_digest(&self) -> Result<DiagnosticSha256> {
        let mut canonical = self.clone();
        canonical.record_digest = DiagnosticSha256::from_bytes([0; 32]);
        Ok(hash_bytes(&serde_json::to_vec(&canonical)?))
    }

    pub fn checkpoint_filter_sha256(&self) -> Option<&DiagnosticSha256> {
        self.checkpoint_binding
            .as_ref()
            .map(|binding| &binding.filter_sha256)
    }

    pub fn checkpoint_network_namespace_inode(&self) -> Option<u64> {
        self.checkpoint_binding
            .as_ref()
            .map(|binding| binding.network_namespace_inode)
    }

    pub fn terminal_record_digest(&self) -> &DiagnosticSha256 {
        &self.record_digest
    }

    pub fn terminal_processes(&self) -> Option<[ProtectedCoordinatorIdentityV1; 3]> {
        Some([
            self.guardian.clone()?,
            self.namespace_init.clone()?,
            self.target.clone()?,
        ])
    }
}

/// Parses one child of a dual retired result through the same strict V4
/// journal validator used for ordinary attempts, with its independently
/// derived child key substituted only for that child domain.
pub fn parse_protected_dual_retired_attempt(
    bytes: &[u8],
    parent_request: &ProtectedCandidateReleaseRequestV1,
    branch: &PrivateReleaseDualRetiredBranchV1,
    child_key: &DiagnosticSha256,
    challenge: [u8; 32],
    observer_sha256: &DiagnosticSha256,
) -> Result<ProtectedCandidateAttemptV1> {
    if parent_request.selector != DUAL_SELECTOR {
        return Err(CiError::Message("dual parent selector differs".into()));
    }
    let mut child_request = parent_request.clone();
    child_request.result_key = child_key.clone();
    let single = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
        attempt_id: branch.attempt_id.clone(),
        checkpoint_sha256: branch.checkpoint_sha256.clone(),
        terminal_sha256: branch.terminal_sha256.clone(),
        retirement_sha256: branch.retirement_sha256.clone(),
        release_knowledge: branch.release_knowledge,
        exec: branch.exec,
        native_observer_sha256: observer_sha256.clone(),
    };
    let attempt = parse_protected_candidate_attempt(bytes, &child_request, &single, challenge)?;
    if hash_bytes(bytes) != branch.terminal_sha256
        || attempt.record_digest != branch.retirement_sha256
        || attempt.candidate_exit_code != Some(0)
        || attempt.phase != ProtectedAttemptPhaseV1::Retired
        || attempt.release_knowledge != ProtectedReleaseKnowledgeV1::ExecObserved
        || branch.exec != PrivateReleaseExecV1::Succeeded
    {
        return Err(CiError::Message("dual retired branch differs".into()));
    }
    Ok(attempt)
}

fn candidate_attempt_id(key: &DiagnosticSha256) -> String {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-candidate-attempt-v1\0");
    digest.update(key.bytes());
    hex::encode(&digest.finalize()[..16])
}

pub struct StructuralTerminalMidflightV1 {
    pub attempt_id: String,
    pub target: ProtectedCoordinatorIdentityV1,
    pub checkpoint_sha256: DiagnosticSha256,
    pub execution_record_digest: DiagnosticSha256,
    pub filter_sha256: DiagnosticSha256,
    pub network_namespace_inode: u64,
}

/// Parses the protected ExecObserved state while the target is still held.
/// This is a midpoint custody join, not terminal or retirement evidence.
pub fn parse_protected_terminal_midflight(
    bytes: &[u8],
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: [u8; 32],
) -> Result<StructuralTerminalMidflightV1> {
    const SELECTOR: &str = "private_tcp::release_checkpoint_terminal_joined";
    parse_protected_candidate_midflight(bytes, request, challenge, &request.result_key, SELECTOR)
}

/// Validates one separately journaled dual-attempt midpoint against the
/// parent request and a fixed, independently derived subattempt key. It does
/// not establish simultaneous liveness or terminal retirement.
pub fn parse_protected_dual_midflight(
    bytes: &[u8],
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: [u8; 32],
    subattempt_key: &DiagnosticSha256,
) -> Result<StructuralTerminalMidflightV1> {
    const SELECTOR: &str = "private_tcp::dual_attempt_namespace_isolation";
    parse_protected_candidate_midflight(bytes, request, challenge, subattempt_key, SELECTOR)
}

fn parse_protected_candidate_midflight(
    bytes: &[u8],
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: [u8; 32],
    expected_key: &DiagnosticSha256,
    selector: &str,
) -> Result<StructuralTerminalMidflightV1> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(CiError::Message(
            "terminal midpoint byte bound differs".into(),
        ));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let attempt: ProtectedCandidateAttemptV1 = serde_json::from_slice(bytes)?;
    let (Some(checkpoint_sha256), Some(checkpoint)) =
        (&attempt.checkpoint_digest, &attempt.checkpoint_binding)
    else {
        return Err(CiError::Message(
            "terminal midpoint checkpoint absent".into(),
        ));
    };
    let target = attempt
        .target
        .as_ref()
        .ok_or_else(|| CiError::Message("terminal midpoint target absent".into()))?;
    if request.selector != selector
        || attempt.schema_version != 1
        || attempt.selector != selector
        || attempt.result_key != *expected_key
        || attempt.challenge_sha256 != hash_bytes(&challenge)
        || attempt.installation_epoch != request.installation_epoch
        || attempt.candidate_manifest_sha256 != request.candidate_manifest_sha256
        || attempt.service_generation_sha256 != request.service_generation_sha256
        || attempt.attempt_id != candidate_attempt_id(expected_key)
        || attempt.coordinator != request.coordinator
        || attempt.frontend_proxy.is_some()
        || attempt.phase != ProtectedAttemptPhaseV1::ExecutionObserved
        || attempt.release_knowledge != ProtectedReleaseKnowledgeV1::ExecObserved
        || attempt.cleanup_error.is_some()
        || attempt.candidate_exit_code.is_some()
        || attempt.record_digest != attempt.canonical_digest()?
        || serde_json::to_vec(&attempt)? != bytes
        || checkpoint.schema_version != 1
        || checkpoint.canonical_digest()? != *checkpoint_sha256
        || checkpoint.result_key != attempt.result_key
        || checkpoint.selector != selector
        || checkpoint.challenge_sha256 != attempt.challenge_sha256
        || checkpoint.attempt_id != attempt.attempt_id
        || checkpoint.installation_epoch != attempt.installation_epoch
        || checkpoint.candidate_manifest_sha256 != attempt.candidate_manifest_sha256
        || checkpoint.service_generation_sha256 != attempt.service_generation_sha256
        || attempt.guardian.as_ref() != Some(&checkpoint.guardian)
        || attempt.namespace_init.as_ref() != Some(&checkpoint.namespace_init)
        || target != &checkpoint.target
        || attempt.network_namespace_inode != Some(checkpoint.network_namespace_inode)
        || checkpoint.network_namespace_inode == 0
        || checkpoint.target_uid == 0
        || checkpoint.target_gid == 0
    {
        return Err(CiError::Message("terminal midpoint journal differs".into()));
    }
    Ok(StructuralTerminalMidflightV1 {
        attempt_id: attempt.attempt_id.clone(),
        target: target.clone(),
        checkpoint_sha256: checkpoint_sha256.clone(),
        execution_record_digest: attempt.record_digest,
        filter_sha256: checkpoint.filter_sha256.clone(),
        network_namespace_inode: checkpoint.network_namespace_inode,
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockedRetirementMarkerV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_digest: DiagnosticSha256,
    transition: String,
}

fn validate_blocked_retirement_marker(
    bytes: &[u8],
    result: &PrivateReleaseCaseResultV1,
    attempt: Option<&ProtectedCandidateAttemptV1>,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(CiError::Message(
            "blocked retirement marker size differs".into(),
        ));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let marker: BlockedRetirementMarkerV1 = serde_json::from_slice(bytes)?;
    let Some(attempt) = attempt else {
        return Err(CiError::Message("blocked retirement attempt absent".into()));
    };
    let PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
        attempt_id,
        checkpoint_sha256,
        cleanup_failure_sha256,
        ..
    } = &result.observation
    else {
        return Err(CiError::Message(
            "blocked retirement result branch differs".into(),
        ));
    };
    if result.selector != RETIREMENT_FAULT_SELECTOR
        || marker.schema_version != 1
        || marker.result_key != attempt.result_key
        || marker.attempt_id != *attempt_id
        || marker.checkpoint_digest != *checkpoint_sha256
        || marker.transition != "retired-transition-blocked"
        || serde_json::to_vec(&marker)? != bytes
        || hash_bytes(bytes) != *cleanup_failure_sha256
    {
        return Err(CiError::Message("blocked retirement marker differs".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedCheckpointGateWitnessV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    release_intent_record_digest: DiagnosticSha256,
    release_intent_bytes: Vec<u8>,
    target: ProtectedCoordinatorIdentityV1,
    target_pidfd_live: bool,
    control_event_absent: bool,
}

/// Parses a durable pre-release leaf and the embedded *prior* ReleaseIntent
/// journal. The recorded live/gated booleans are still owner-authored; this
/// exact readback is not independent proof that exec had not yet occurred.
pub fn parse_protected_checkpoint_gate_witness(
    bytes: &[u8],
    request: &ProtectedCandidateReleaseRequestV1,
    final_attempt: Option<&ProtectedCandidateAttemptV1>,
) -> Result<ProtectedCheckpointGateWitnessV1> {
    if bytes.is_empty() || bytes.len() > MAX_RAW_CASE_BYTES as usize {
        return Err(CiError::Message(
            "checkpoint gate witness size differs".into(),
        ));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let witness: ProtectedCheckpointGateWitnessV1 = serde_json::from_slice(bytes)?;
    let attempt = final_attempt
        .ok_or_else(|| CiError::Message("checkpoint gate final attempt absent".into()))?;
    let intent_bytes = &witness.release_intent_bytes;
    if intent_bytes.is_empty() || intent_bytes.len() > 16 * 1024 {
        return Err(CiError::Message(
            "checkpoint gate intent size differs".into(),
        ));
    }
    reject_duplicate_json_keys(intent_bytes).map_err(CiError::Message)?;
    let intent: ProtectedCandidateAttemptV1 = serde_json::from_slice(intent_bytes)?;
    if witness.schema_version != 1
        || witness.selector != CHECKPOINT_GATE_SELECTOR
        || request.selector != CHECKPOINT_GATE_SELECTOR
        || attempt.selector != CHECKPOINT_GATE_SELECTOR
        || witness.result_key != request.result_key
        || witness.attempt_id != attempt.attempt_id
        || Some(&witness.checkpoint_sha256) != attempt.checkpoint_digest.as_ref()
        || witness.release_intent_record_digest != intent.record_digest
        || !witness.target_pidfd_live
        || !witness.control_event_absent
        || serde_json::to_vec(&witness)? != bytes
        || intent.schema_version != 1
        || intent.selector != CHECKPOINT_GATE_SELECTOR
        || intent.result_key != request.result_key
        || intent.attempt_id != attempt.attempt_id
        || intent.challenge_sha256 != attempt.challenge_sha256
        || intent.installation_epoch != request.installation_epoch
        || intent.candidate_manifest_sha256 != request.candidate_manifest_sha256
        || intent.service_generation_sha256 != request.service_generation_sha256
        || intent.coordinator != request.coordinator
        || intent.frontend_proxy.is_some()
        || intent.phase != ProtectedAttemptPhaseV1::ReleaseIntent
        || intent.release_knowledge != ProtectedReleaseKnowledgeV1::PossiblyReleased
        || intent.cleanup_error.is_some()
        || intent.candidate_exit_code.is_some()
        || intent.checkpoint_digest != attempt.checkpoint_digest
        || intent.checkpoint_binding != attempt.checkpoint_binding
        || intent.guardian != attempt.guardian
        || intent.namespace_init != attempt.namespace_init
        || intent.target != attempt.target
        || intent.network_namespace_inode != attempt.network_namespace_inode
        || Some(&witness.target) != intent.target.as_ref()
        || intent.record_digest != intent.canonical_digest()?
        || serde_json::to_vec(&intent)? != *intent_bytes
        || attempt.phase != ProtectedAttemptPhaseV1::Retired
        || attempt.release_knowledge != ProtectedReleaseKnowledgeV1::ExecObserved
        || attempt.candidate_exit_code != Some(0)
    {
        return Err(CiError::Message("checkpoint gate witness differs".into()));
    }
    Ok(witness)
}

pub fn parse_protected_candidate_attempt(
    bytes: &[u8],
    request: &ProtectedCandidateReleaseRequestV1,
    observation: &PrivateReleaseObservationV1,
    challenge: [u8; 32],
) -> Result<ProtectedCandidateAttemptV1> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(CiError::Message(
            "private protected attempt size differs".into(),
        ));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let attempt: ProtectedCandidateAttemptV1 = serde_json::from_slice(bytes)?;
    let canonical_digest = attempt.canonical_digest()?;
    let checkpoint_matches = match (&attempt.checkpoint_digest, &attempt.checkpoint_binding) {
        (Some(digest), Some(binding)) => {
            binding.canonical_digest()? == *digest
                && binding.schema_version == 1
                && binding.result_key == attempt.result_key
                && binding.selector == attempt.selector
                && binding.challenge_sha256 == attempt.challenge_sha256
                && binding.attempt_id == attempt.attempt_id
                && binding.installation_epoch == attempt.installation_epoch
                && binding.candidate_manifest_sha256 == attempt.candidate_manifest_sha256
                && binding.service_generation_sha256 == attempt.service_generation_sha256
                && attempt.guardian.as_ref() == Some(&binding.guardian)
                && attempt.namespace_init.as_ref() == Some(&binding.namespace_init)
                && attempt.target.as_ref() == Some(&binding.target)
                && attempt.network_namespace_inode == Some(binding.network_namespace_inode)
                && binding.network_namespace_inode != 0
                && binding.target_uid != 0
                && binding.target_gid != 0
        }
        _ => false,
    };
    let terminal_matches = match observation {
        PrivateReleaseObservationV1::PreallocationRejected { .. } => false,
        PrivateReleaseObservationV1::DualAttemptsRetired { .. } => false,
        PrivateReleaseObservationV1::AllocatedRetired {
            attempt_id,
            checkpoint_sha256,
            release_knowledge,
            ..
        } => {
            attempt.phase == ProtectedAttemptPhaseV1::Retired
                && attempt.cleanup_error.is_none()
                && match observation {
                    PrivateReleaseObservationV1::AllocatedRetired {
                        outcome: PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain,
                        ..
                    } => {
                        attempt.candidate_exit_code != Some(0)
                            && attempt.release_knowledge
                                == ProtectedReleaseKnowledgeV1::PossiblyReleased
                    }
                    PrivateReleaseObservationV1::AllocatedRetired {
                        outcome:
                            PrivateReleaseAllocatedOutcomeV1::GuardianLost
                            | PrivateReleaseAllocatedOutcomeV1::FrontendLost,
                        ..
                    } => {
                        attempt.candidate_exit_code != Some(0)
                            && attempt.release_knowledge
                                == ProtectedReleaseKnowledgeV1::ExecObserved
                    }
                    _ => attempt.candidate_exit_code.is_some(),
                }
                && attempt.attempt_id == *attempt_id
                && attempt.checkpoint_digest.as_ref() == Some(checkpoint_sha256)
                && checkpoint_matches
                && release_knowledge_matches(attempt.release_knowledge, *release_knowledge)
        }
        PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
            attempt_id,
            checkpoint_sha256,
            release_knowledge,
            ..
        } => {
            attempt.phase == ProtectedAttemptPhaseV1::Retiring
                && attempt.cleanup_error.is_none()
                && attempt.candidate_exit_code.is_none()
                && attempt.attempt_id == *attempt_id
                && attempt.checkpoint_digest.as_ref() == Some(checkpoint_sha256)
                && checkpoint_matches
                && release_knowledge_matches(attempt.release_knowledge, *release_knowledge)
        }
    };
    if attempt.schema_version != 1
        || attempt.result_key != request.result_key
        || attempt.selector != request.selector
        || attempt.challenge_sha256 != hash_bytes(&challenge)
        || attempt.installation_epoch != request.installation_epoch
        || attempt.candidate_manifest_sha256 != request.candidate_manifest_sha256
        || attempt.service_generation_sha256 != request.service_generation_sha256
        || attempt.coordinator != request.coordinator
        || (attempt.selector == "private_tcp::frontend_loss_retired")
            != attempt.frontend_proxy.is_some()
        || attempt.frontend_proxy.as_ref() == Some(&attempt.coordinator)
        || attempt
            .frontend_proxy
            .as_ref()
            .is_some_and(|frontend| frontend.pid == 0 || frontend.start_time == 0)
        || attempt.attempt_id != candidate_attempt_id(&request.result_key)
        || attempt.record_digest != canonical_digest
        || !terminal_matches
    {
        return Err(CiError::Message(
            "private protected attempt custody or terminal phase differs".into(),
        ));
    }
    Ok(attempt)
}

fn release_knowledge_matches(
    attempt: ProtectedReleaseKnowledgeV1,
    result: memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1,
) -> bool {
    use memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1 as ResultKnowledge;
    matches!(
        (attempt, result),
        (
            ProtectedReleaseKnowledgeV1::NotReleased,
            ResultKnowledge::NotReleased
        ) | (
            ProtectedReleaseKnowledgeV1::PossiblyReleased,
            ResultKnowledge::PossiblyReleased
        ) | (
            ProtectedReleaseKnowledgeV1::ExecObserved,
            ResultKnowledge::ExecObserved
        )
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateTcpReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateTcpCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    candidate_exit_code: i32,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateCheckpointGateReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    checkpoint_gate_sha256: DiagnosticSha256,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateCheckpointGateObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    checkpoint_gate_sha256: DiagnosticSha256,
    settlement: CandidateKernelSettlementV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateCheckpointGateCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    checkpoint_gate_sha256: DiagnosticSha256,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateChildReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    child: ProtectedCoordinatorIdentityV1,
    thread_tid: u32,
    thread_start_time: u64,
    target_namespace_pid: u32,
    child_namespace_pid: u32,
    thread_namespace_tid: u32,
    target_pid_chain: Vec<u32>,
    child_pid_chain: Vec<u32>,
    thread_tid_chain: Vec<u32>,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateLiveDescendantWitnessV1 {
    schema_version: u8,
    target: ProtectedCoordinatorIdentityV1,
    child: ProtectedCoordinatorIdentityV1,
    thread_tid: u32,
    thread_start_time: u64,
    target_namespace_pid: u32,
    child_namespace_pid: u32,
    thread_namespace_tid: u32,
    target_pid_chain: Vec<u32>,
    child_pid_chain: Vec<u32>,
    thread_tid_chain: Vec<u32>,
    challenge_sha256: DiagnosticSha256,
    cgroup_procs_sha256: DiagnosticSha256,
    cgroup_threads_sha256: DiagnosticSha256,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateChildObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    live: CandidateLiveDescendantWitnessV1,
    settlement: CandidateKernelSettlementV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateChildCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    child: ProtectedCoordinatorIdentityV1,
    thread_tid: u32,
    target_namespace_pid: u32,
    child_namespace_pid: u32,
    thread_namespace_tid: u32,
    target_pid_chain: Vec<u32>,
    child_pid_chain: Vec<u32>,
    thread_tid_chain: Vec<u32>,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateSocketReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    socket_gate_sha256: DiagnosticSha256,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateSocketWitnessV1 {
    schema_version: u8,
    target: ProtectedCoordinatorIdentityV1,
    network_namespace_inode: u64,
    first_socket_device: u64,
    first_socket_inode: u64,
    second_socket_device: u64,
    second_socket_inode: u64,
    filter_sha256: DiagnosticSha256,
    sendmsg_errno: i32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateSocketObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    gated_witness: CandidateSocketWitnessV1,
    settlement: CandidateKernelSettlementV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateSocketCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    socket_gate_sha256: DiagnosticSha256,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateTerminalReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    midflight_record_digest: DiagnosticSha256,
    terminal_join_gate_sha256: DiagnosticSha256,
    target_namespace_pid: u32,
    target_pid_chain: Vec<u32>,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateTerminalObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    live_frame: Vec<u8>,
    settlement: CandidateKernelSettlementV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateTerminalCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    terminal_join_gate_sha256: DiagnosticSha256,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateKernelSettlementV1 {
    schema_version: u8,
    monitor_outcome: String,
    cgroup_empty_before_cleanup: bool,
    containment_removed: bool,
    target_pidfd_exited: bool,
    namespace_init_reaped: bool,
    guardian_terminal: [u8; 20],
    candidate_exit_code: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateKernelObservationV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    settlement: CandidateKernelSettlementV1,
    host_network_preservation: Option<serde_json::Value>,
    agent_path_preservation: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateUncertainReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    release_knowledge: String,
    transport_errno: i32,
    authorization_failure_phase: u8,
    authorization_failure_detail: String,
    candidate_exit_code: Option<i32>,
    installed_inspection_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateUncertainSettlementV1 {
    schema_version: u8,
    transport_errno: i32,
    containment_removed: bool,
    target_pidfd_exited: bool,
    namespace_init_reaped: bool,
    guardian_terminal: [u8; 20],
    candidate_exit_code: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateUncertainObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    authorization_failure_phase: u8,
    authorization_failure_detail: String,
    settlement: CandidateUncertainSettlementV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateUncertainCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    release_knowledge: String,
    transport_errno: i32,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateBlockedRetirementReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    fault_marker_sha256: DiagnosticSha256,
    transition_error: String,
    reuse_error: String,
    installed_inspection_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateBlockedRetirementObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    fault_marker_sha256: DiagnosticSha256,
    settlement: CandidateKernelSettlementV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateBlockedRetirementCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    fault_marker_sha256: DiagnosticSha256,
    reuse_rejection_sha256: DiagnosticSha256,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

/// Structural-only mirror of the native O_EXCL retirement collision. The
/// journal deliberately remains Retiring; this does not prove kernel cleanup
/// independently or create a trusted release completion.
pub fn validate_candidate_blocked_retirement_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    let selector = case.result.selector.as_str();
    let (Some(attempt), Some(attempt_bytes), Some(marker_bytes)) = (
        &case.attempt_record,
        &case.attempt_record_bytes,
        &case.fault_marker_bytes,
    ) else {
        return Err(CiError::Message(
            "blocked retirement protected evidence absent".into(),
        ));
    };
    let [request, report_bytes, stdio, observer_bytes, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message(
            "blocked retirement raw inventory differs".into(),
        ));
    };
    for bytes in [report_bytes, observer_bytes, cleanup_bytes] {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    }
    let report: CandidateBlockedRetirementReportV1 = serde_json::from_slice(report_bytes)?;
    let observer: CandidateBlockedRetirementObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateBlockedRetirementCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        cleanup_failure_sha256,
        reuse_rejection_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message(
            "blocked retirement result branch differs".into(),
        ));
    };
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &case.result.installed
    else {
        return Err(CiError::Message(
            "blocked retirement installed binding differs".into(),
        ));
    };
    validate_blocked_retirement_marker(marker_bytes, &case.result, Some(attempt))?;
    let expected_response = validate_candidate_target_stdio_with_agent_identity(
        selector,
        &case.result.target,
        challenge,
        stdio,
        attempt.checkpoint_network_namespace_inode(),
        None,
    )?;
    let attempt_bytes_id = hex::decode(&attempt.attempt_id)
        .map_err(|_| CiError::Message("blocked guardian attempt is not hex".into()))?;
    let error_prefix = "MCSEALED-PRIVATE-RELEASE: attempt transition blocked:";
    if selector != RETIREMENT_FAULT_SELECTOR
        || case.candidate_request.selector != RETIREMENT_FAULT_SELECTOR
        || request != &case.candidate_request_bytes
        || attempt_bytes_id.len() != 16
        || report.schema_version != 1
        || report.selector != selector
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || report.checkpoint_sha256 != *checkpoint_sha256
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.response_sha256 != expected_response
        || report.fault_marker_sha256 != hash_bytes(marker_bytes)
        || !report.transition_error.starts_with(error_prefix)
        || report.transition_error.len() <= error_prefix.len()
        || report.transition_error.len() > 512
        || !report.reuse_error.starts_with(error_prefix)
        || report.reuse_error.len() <= error_prefix.len()
        || report.reuse_error.len() > 512
        || hash_bytes(report.installed_inspection_json.as_bytes()) != *expected_inspection_sha256
        || *installed_inspection_sha256 != *expected_inspection_sha256
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || observer.fault_marker_sha256 != report.fault_marker_sha256
        || observer.settlement.schema_version != 1
        || observer.settlement.monitor_outcome != "Completed"
        || !observer.settlement.cgroup_empty_before_cleanup
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != Some(0)
        || observer.settlement.guardian_terminal[0] != 4
        || observer.settlement.guardian_terminal[1..17] != attempt_bytes_id
        || observer.settlement.guardian_terminal[17..] != [1, 0, 0]
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.fault_marker_sha256 != report.fault_marker_sha256
        || cleanup.reuse_rejection_sha256 != hash_bytes(report.reuse_error.as_bytes())
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || attempt_id != &report.attempt_id
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *cleanup_failure_sha256 != hash_bytes(marker_bytes)
        || *reuse_rejection_sha256 != hash_bytes(report.reuse_error.as_bytes())
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
        || *exec != PrivateReleaseExecV1::Succeeded
        || *native_observer_sha256 != hash_bytes(observer_bytes)
    {
        return Err(CiError::Message(
            "blocked retirement raw evidence differs".into(),
        ));
    }
    Ok(())
}

pub fn verify_blocked_candidate_worker_exited(
    case: &StructuralProtectedNativeCaseV1,
) -> Result<()> {
    let cleanup_bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("blocked retirement cleanup absent".into()))?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let cleanup: CandidateBlockedRetirementCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    if case.result.selector != RETIREMENT_FAULT_SELECTOR
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || !cleanup.worker_pidfd_exited
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err(CiError::Message(
            "blocked retirement worker identity differs".into(),
        ));
    }
    crate::private_supervisor::verify_recorded_process_exited(
        crate::private_supervisor::LinuxChildIdentityV1 {
            pid: cleanup.worker.pid,
            start_time_ticks: cleanup.worker.start_time,
        },
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateGuardianLossReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    armed_response_sha256: DiagnosticSha256,
    network_namespace_inode: u64,
    candidate_exit_code: Option<i32>,
    installed_inspection_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateGuardianLossSettlementV1 {
    schema_version: u8,
    guardian: ProtectedCoordinatorIdentityV1,
    guardian_signal: i32,
    containment_removed: bool,
    target_pidfd_exited: bool,
    namespace_init_reaped: bool,
    candidate_exit_code: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateGuardianLossObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    settlement: CandidateGuardianLossSettlementV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateGuardianLossCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    guardian_signal: i32,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

/// Structurally joins the distinct release-domain guardian-loss result. The
/// signal is still owner-authored; the OS exit checks below only corroborate
/// process absence and cannot establish trusted native qualification.
pub fn validate_candidate_guardian_loss_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    const SELECTOR: &str = "private_tcp::guardian_loss_retired";
    const SIGKILL: i32 = 9;
    let (Some(attempt), Some(attempt_bytes)) = (&case.attempt_record, &case.attempt_record_bytes)
    else {
        return Err(CiError::Message(
            "guardian-loss protected attempt absent".into(),
        ));
    };
    let [request, report_bytes, stdio, observer_bytes, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message(
            "guardian-loss raw inventory differs".into(),
        ));
    };
    for bytes in [report_bytes, observer_bytes, cleanup_bytes] {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    }
    let report: CandidateGuardianLossReportV1 = serde_json::from_slice(report_bytes)?;
    let observer: CandidateGuardianLossObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateGuardianLossCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let PrivateReleaseObservationV1::AllocatedRetired {
        outcome,
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message(
            "guardian-loss result branch differs".into(),
        ));
    };
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &case.result.installed
    else {
        return Err(CiError::Message(
            "guardian-loss installed binding differs".into(),
        ));
    };
    let armed_response = validate_candidate_target_stdio_with_agent_identity(
        SELECTOR,
        &case.result.target,
        challenge,
        stdio,
        attempt.checkpoint_network_namespace_inode(),
        None,
    )?;
    if case.result.selector != SELECTOR
        || case.candidate_request.selector != SELECTOR
        || request != &case.candidate_request_bytes
        || case.fault_marker_bytes.is_some()
        || attempt.phase != ProtectedAttemptPhaseV1::Retired
        || attempt.release_knowledge != ProtectedReleaseKnowledgeV1::ExecObserved
        || attempt.candidate_exit_code == Some(0)
        || report.schema_version != 1
        || report.selector != SELECTOR
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || report.checkpoint_sha256 != *checkpoint_sha256
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.armed_response_sha256 != armed_response
        || Some(report.network_namespace_inode) != attempt.network_namespace_inode
        || report.candidate_exit_code != attempt.candidate_exit_code
        || hash_bytes(report.installed_inspection_json.as_bytes()) != *expected_inspection_sha256
        || *installed_inspection_sha256 != *expected_inspection_sha256
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || observer.settlement.schema_version != 1
        || Some(&observer.settlement.guardian) != attempt.guardian.as_ref()
        || observer.settlement.guardian_signal != SIGKILL
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != report.candidate_exit_code
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.guardian_signal != SIGKILL
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || *outcome != PrivateReleaseAllocatedOutcomeV1::GuardianLost
        || attempt_id != &report.attempt_id
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *retirement_sha256 != hash_bytes(cleanup_bytes)
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
        || *exec != PrivateReleaseExecV1::Succeeded
        || *native_observer_sha256 != hash_bytes(observer_bytes)
    {
        return Err(CiError::Message(
            "guardian-loss raw evidence differs".into(),
        ));
    }
    Ok(())
}

pub fn verify_guardian_loss_processes_exited(case: &StructuralProtectedNativeCaseV1) -> Result<()> {
    const SELECTOR: &str = "private_tcp::guardian_loss_retired";
    if case.result.selector != SELECTOR {
        return Err(CiError::Message("guardian-loss selector differs".into()));
    }
    let attempt = case
        .attempt_record
        .as_ref()
        .ok_or_else(|| CiError::Message("guardian-loss attempt absent".into()))?;
    let cleanup_bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("guardian-loss cleanup absent".into()))?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let cleanup: CandidateGuardianLossCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    for identity in [
        Some(&cleanup.worker),
        attempt.guardian.as_ref(),
        attempt.namespace_init.as_ref(),
        attempt.target.as_ref(),
    ] {
        let identity = identity
            .ok_or_else(|| CiError::Message("guardian-loss native identity absent".into()))?;
        crate::private_supervisor::verify_recorded_process_exited(
            crate::private_supervisor::LinuxChildIdentityV1 {
                pid: identity.pid,
                start_time_ticks: identity.start_time,
            },
        )?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateFrontendLossReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    armed_response_sha256: DiagnosticSha256,
    network_namespace_inode: u64,
    frontend_proxy: ProtectedCoordinatorIdentityV1,
    candidate_exit_code: Option<i32>,
    installed_inspection_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateFrontendLossSettlementV1 {
    schema_version: u8,
    frontend: ProtectedCoordinatorIdentityV1,
    frontend_signal: i32,
    guardian_terminal: [u8; 20],
    containment_removed: bool,
    target_pidfd_exited: bool,
    namespace_init_reaped: bool,
    candidate_exit_code: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateFrontendLossObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    settlement: CandidateFrontendLossSettlementV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateFrontendLossCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    frontend_proxy: ProtectedCoordinatorIdentityV1,
    frontend_signal: i32,
    guardian_terminal: [u8; 20],
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProtectedCoordinatorIdentityV1,
    worker: ProtectedCoordinatorIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

/// Structural-only release-domain frontend-loss join. The separate proxy and
/// guardian frame are necessary, but owner-authored SIGKILL is not independent
/// native authority and this function cannot create Q.
pub fn validate_candidate_frontend_loss_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    const SELECTOR: &str = "private_tcp::frontend_loss_retired";
    const SIGKILL: i32 = 9;
    let (Some(attempt), Some(attempt_bytes)) = (&case.attempt_record, &case.attempt_record_bytes)
    else {
        return Err(CiError::Message(
            "frontend-loss protected attempt absent".into(),
        ));
    };
    let [request, report_bytes, stdio, observer_bytes, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message(
            "frontend-loss raw inventory differs".into(),
        ));
    };
    for bytes in [report_bytes, observer_bytes, cleanup_bytes] {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    }
    let report: CandidateFrontendLossReportV1 = serde_json::from_slice(report_bytes)?;
    let observer: CandidateFrontendLossObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateFrontendLossCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let PrivateReleaseObservationV1::AllocatedRetired {
        outcome,
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message(
            "frontend-loss result branch differs".into(),
        ));
    };
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &case.result.installed
    else {
        return Err(CiError::Message(
            "frontend-loss installed binding differs".into(),
        ));
    };
    let armed_response = validate_candidate_target_stdio_with_agent_identity(
        SELECTOR,
        &case.result.target,
        challenge,
        stdio,
        attempt.checkpoint_network_namespace_inode(),
        None,
    )?;
    let attempt_bytes_id = hex::decode(&attempt.attempt_id)
        .map_err(|_| CiError::Message("frontend-loss attempt is not hex".into()))?;
    if case.result.selector != SELECTOR
        || case.candidate_request.selector != SELECTOR
        || request != &case.candidate_request_bytes
        || case.fault_marker_bytes.is_some()
        || attempt.phase != ProtectedAttemptPhaseV1::Retired
        || attempt.release_knowledge != ProtectedReleaseKnowledgeV1::ExecObserved
        || attempt.candidate_exit_code == Some(0)
        || attempt_bytes_id.len() != 16
        || report.schema_version != 1
        || report.selector != SELECTOR
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || report.checkpoint_sha256 != *checkpoint_sha256
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.armed_response_sha256 != armed_response
        || Some(report.network_namespace_inode) != attempt.network_namespace_inode
        || Some(&report.frontend_proxy) != attempt.frontend_proxy.as_ref()
        || report.frontend_proxy == case.candidate_request.coordinator
        || report.candidate_exit_code != attempt.candidate_exit_code
        || hash_bytes(report.installed_inspection_json.as_bytes()) != *expected_inspection_sha256
        || *installed_inspection_sha256 != *expected_inspection_sha256
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || observer.settlement.schema_version != 1
        || observer.settlement.frontend != report.frontend_proxy
        || observer.settlement.frontend_signal != SIGKILL
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != report.candidate_exit_code
        || observer.settlement.guardian_terminal[0] != 4
        || observer.settlement.guardian_terminal[1..17] != attempt_bytes_id
        || observer.settlement.guardian_terminal[17..] != [2, 1, 0]
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.frontend_proxy != report.frontend_proxy
        || cleanup.frontend_signal != SIGKILL
        || cleanup.guardian_terminal != observer.settlement.guardian_terminal
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker == cleanup.frontend_proxy
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || *outcome != PrivateReleaseAllocatedOutcomeV1::FrontendLost
        || attempt_id != &report.attempt_id
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *retirement_sha256 != hash_bytes(cleanup_bytes)
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
        || *exec != PrivateReleaseExecV1::Succeeded
        || *native_observer_sha256 != hash_bytes(observer_bytes)
    {
        return Err(CiError::Message(
            "frontend-loss raw evidence differs".into(),
        ));
    }
    Ok(())
}

pub fn verify_frontend_loss_processes_exited(case: &StructuralProtectedNativeCaseV1) -> Result<()> {
    if case.result.selector != "private_tcp::frontend_loss_retired" {
        return Err(CiError::Message("frontend-loss selector differs".into()));
    }
    let attempt = case
        .attempt_record
        .as_ref()
        .ok_or_else(|| CiError::Message("frontend-loss attempt absent".into()))?;
    let cleanup_bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("frontend-loss cleanup absent".into()))?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let cleanup: CandidateFrontendLossCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    for identity in [
        Some(&cleanup.worker),
        attempt.frontend_proxy.as_ref(),
        attempt.guardian.as_ref(),
        attempt.namespace_init.as_ref(),
        attempt.target.as_ref(),
    ] {
        let identity = identity
            .ok_or_else(|| CiError::Message("frontend-loss native identity absent".into()))?;
        crate::private_supervisor::verify_recorded_process_exited(
            crate::private_supervisor::LinuxChildIdentityV1 {
                pid: identity.pid,
                start_time_ticks: identity.start_time,
            },
        )?;
    }
    Ok(())
}

/// Structural-only mirror of the physically lost authorization transport.
/// Exact phase-4 failure, EPIPE, non-exec retirement and coordinator cleanup
/// are required; this cannot construct a trusted native completion or Q.
pub fn validate_candidate_uncertain_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    const SELECTOR: &str = "private_tcp::authorization_uncertainty_retired";
    const EPIPE: i32 = 32;
    const DETAIL: &str = "authorization packet invalid";
    if case.result.selector != SELECTOR || case.candidate_request.selector != SELECTOR {
        return Err(CiError::Message(
            "uncertain candidate selector differs".into(),
        ));
    }
    let (Some(attempt), Some(attempt_bytes)) = (&case.attempt_record, &case.attempt_record_bytes)
    else {
        return Err(CiError::Message(
            "uncertain candidate retired attempt absent".into(),
        ));
    };
    let [request, report_bytes, stdio, observer_bytes, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message(
            "uncertain candidate raw inventory differs".into(),
        ));
    };
    for bytes in [report_bytes, observer_bytes, cleanup_bytes] {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    }
    let report: CandidateUncertainReportV1 = serde_json::from_slice(report_bytes)?;
    let observer: CandidateUncertainObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateUncertainCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let attempt_bytes_id = hex::decode(&attempt.attempt_id)
        .map_err(|_| CiError::Message("uncertain guardian attempt is not hex".into()))?;
    let PrivateReleaseObservationV1::AllocatedRetired {
        outcome,
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message(
            "uncertain candidate result branch differs".into(),
        ));
    };
    let installed = hash_bytes(report.installed_inspection_json.as_bytes());
    if request != &case.candidate_request_bytes
        || stdio != &challenge
        || attempt_bytes_id.len() != 16
        || report.schema_version != 1
        || report.selector != SELECTOR
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || attempt.checkpoint_digest.as_ref() != Some(&report.checkpoint_sha256)
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.release_knowledge != "possibly-released"
        || report.transport_errno != EPIPE
        || report.authorization_failure_phase != 4
        || report.authorization_failure_detail != DETAIL
        || report.candidate_exit_code == Some(0)
        || report.candidate_exit_code != attempt.candidate_exit_code
        || installed != *expected_inspection_sha256
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || observer.authorization_failure_phase != report.authorization_failure_phase
        || observer.authorization_failure_detail != report.authorization_failure_detail
        || observer.settlement.schema_version != 1
        || observer.settlement.transport_errno != EPIPE
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != report.candidate_exit_code
        || observer.settlement.guardian_terminal[0] != 4
        || observer.settlement.guardian_terminal[1..17] != attempt_bytes_id
        || observer.settlement.guardian_terminal[17..] != [1, 0, 0]
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.release_knowledge != "possibly-released"
        || cleanup.transport_errno != EPIPE
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || *outcome != PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain
        || attempt_id != &report.attempt_id
        || checkpoint_sha256 != &report.checkpoint_sha256
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *retirement_sha256 != hash_bytes(cleanup_bytes)
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::PossiblyReleased
        || *exec != PrivateReleaseExecV1::NotObserved
        || *native_observer_sha256 != hash_bytes(observer_bytes)
    {
        return Err(CiError::Message(
            "uncertain candidate raw evidence differs".into(),
        ));
    }
    Ok(())
}

pub fn verify_uncertain_candidate_worker_exited(
    case: &StructuralProtectedNativeCaseV1,
) -> Result<()> {
    let bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("uncertain cleanup absent".into()))?;
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let cleanup: CandidateUncertainCleanupV1 = serde_json::from_slice(bytes)?;
    if case.result.selector != "private_tcp::authorization_uncertainty_retired"
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
    {
        return Err(CiError::Message(
            "uncertain worker exit record differs".into(),
        ));
    }
    crate::private_supervisor::verify_recorded_process_exited(
        crate::private_supervisor::LinuxChildIdentityV1 {
            pid: cleanup.worker.pid,
            start_time_ticks: cleanup.worker.start_time,
        },
    )
}

/// Exact structural joins for the first physically implemented native TCP
/// selector. `expected_inspection_sha256` must be read from installed H0 by
/// an independent caller, never copied from result/report bytes. This still
/// does not prove an independent OS trace or construct Q.
/// Checks only the fixed target response byte semantics. The bytes remain
/// owner-produced and cannot by themselves prove a syscall or target identity.
pub fn validate_candidate_target_stdio(
    selector: &str,
    target: &str,
    challenge: [u8; 32],
    stdio: &[u8],
    checkpoint_network_namespace_inode: Option<u64>,
) -> Result<DiagnosticSha256> {
    validate_candidate_target_stdio_with_agent_identity(
        selector,
        target,
        challenge,
        stdio,
        checkpoint_network_namespace_inode,
        None,
    )
}

pub fn validate_candidate_target_stdio_with_agent_identity(
    selector: &str,
    target: &str,
    challenge: [u8; 32],
    stdio: &[u8],
    checkpoint_network_namespace_inode: Option<u64>,
    installed_agent_identity: Option<(u64, u64)>,
) -> Result<DiagnosticSha256> {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-candidate-fixture-v1\0");
    digest.update(selector.as_bytes());
    digest.update([0]);
    digest.update(challenge);
    let mut response: Vec<u8> = digest.finalize().to_vec();
    // These are Linux UAPI errno values, fixed independently of the native
    // fixture and of the CI host's libc constants.
    match selector {
        "private_tcp::native_tcp_bind_listen_connect"
        | CHECKPOINT_GATE_SELECTOR
        | "private_tcp::guardian_loss_retired"
        | "private_tcp::frontend_loss_retired"
        | RETIREMENT_FAULT_SELECTOR => {}
        "private_tcp::af_unix_socketpair_denied" => {
            response.extend_from_slice(&97_i32.to_le_bytes()); // EAFNOSUPPORT
            response.extend_from_slice(&1_i32.to_le_bytes()); // EPERM
        }
        "private_tcp::io_uring_and_pidfd_import_denied"
        | "private_tcp::namespace_reentry_denied" => {
            response.extend_from_slice(&1_i32.to_le_bytes()); // EPERM
            response.extend_from_slice(&1_i32.to_le_bytes()); // EPERM
        }
        "private_tcp::port_collision_same_namespace" => {
            response.extend_from_slice(&98_i32.to_le_bytes()); // EADDRINUSE
        }
        "private_tcp::target_credentials_and_capabilities_dropped" => {
            response.extend_from_slice(&[0_u8; 32]); // CapInh, CapPrm, CapEff, CapAmb
            response.push(1); // PR_GET_NO_NEW_PRIVS
        }
        "private_tcp::native_filter_digest_and_abi_bound" => {
            response.push(2); // PR_GET_SECCOMP filter mode
            response.push(match target {
                "x86_64-unknown-linux-gnu" => 1,
                "aarch64-unknown-linux-gnu" => 2,
                _ => {
                    return Err(CiError::Message(
                        "candidate target ABI is not supported".into(),
                    ));
                }
            });
        }
        "private_tcp::private_namespace_topology_exact" => {
            let inode = checkpoint_network_namespace_inode
                .filter(|inode| *inode != 0)
                .ok_or_else(|| {
                    CiError::Message("candidate topology checkpoint namespace absent".into())
                })?;
            response.extend_from_slice(&inode.to_le_bytes());
        }
        "private_tcp::host_namespace_and_sysctl_unchanged" => {
            response.extend_from_slice(&0_u16.to_le_bytes());
            response.extend_from_slice(&32768_u16.to_le_bytes());
            response.extend_from_slice(&60999_u16.to_le_bytes());
            response.push(0);
        }
        "private_tcp::descriptor_table_and_stdio_bound" | SOCKET_SELECTOR => {
            response.extend_from_slice(&[3, 1, 1, 1]);
        }
        "private_tcp::target_exec_and_fd_leak_observed"
        | "private_tcp::elf_ancestor_and_identity_pinned" => {
            let (device, inode) = installed_agent_identity
                .filter(|(device, inode)| *device != 0 && *inode != 0)
                .ok_or_else(|| {
                    CiError::Message("candidate installed agent identity absent".into())
                })?;
            response.extend_from_slice(&device.to_le_bytes());
            response.extend_from_slice(&inode.to_le_bytes());
            response.extend_from_slice(&[3, 1, 1, 1]);
        }
        _ => {
            return Err(CiError::Message(
                "candidate selector has no fixed target response contract".into(),
            ));
        }
    }
    if stdio.len() != challenge.len() + response.len()
        || stdio[..challenge.len()] != challenge
        || stdio[challenge.len()..] != response
    {
        return Err(CiError::Message(
            "candidate target response bytes differ".into(),
        ));
    }
    Ok(hash_bytes(&response))
}

/// Fixed post-release live frame followed by the selector-bound final echo.
/// A correctly shaped owner stream remains structural without CI live proof.
pub fn validate_terminal_target_stdio(
    challenge: [u8; 32],
    namespace_pid: u32,
    stdio: &[u8],
) -> Result<(Vec<u8>, DiagnosticSha256)> {
    if namespace_pid == 0 {
        return Err(CiError::Message("terminal namespace PID absent".into()));
    }
    let mut final_digest = Sha256::new();
    final_digest.update(b"memcordon-private-release-candidate-fixture-v1\0");
    final_digest.update(TERMINAL_JOIN_SELECTOR.as_bytes());
    final_digest.update([0]);
    final_digest.update(challenge);
    let mut live_frame = Vec::new();
    live_frame.extend_from_slice(b"MCRJOIN1");
    live_frame.extend_from_slice(&namespace_pid.to_le_bytes());
    live_frame.extend_from_slice(hash_bytes(&challenge).bytes());
    let mut response = live_frame.clone();
    response.extend_from_slice(&final_digest.finalize());
    let mut expected_stdio = challenge.to_vec();
    expected_stdio.extend_from_slice(&response);
    if stdio != expected_stdio {
        return Err(CiError::Message("terminal target I/O differs".into()));
    }
    Ok((live_frame, hash_bytes(&response)))
}

/// Structural-only join for the durable pre-release checkpoint gate. The
/// embedded ReleaseIntent journal proves byte custody, not independent timing
/// of the unsent authorization packet or a trusted native completion.
pub fn validate_candidate_checkpoint_gate_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    let (Some(attempt), Some(attempt_bytes), Some(gate_bytes)) = (
        &case.attempt_record,
        &case.attempt_record_bytes,
        &case.checkpoint_gate_bytes,
    ) else {
        return Err(CiError::Message(
            "checkpoint gate protected evidence absent".into(),
        ));
    };
    let [request, report_bytes, stdio, observer_bytes, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message(
            "checkpoint gate raw inventory differs".into(),
        ));
    };
    for bytes in [report_bytes, observer_bytes, cleanup_bytes] {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    }
    let report: CandidateCheckpointGateReportV1 = serde_json::from_slice(report_bytes)?;
    let observer: CandidateCheckpointGateObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateCheckpointGateCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let witness = parse_protected_checkpoint_gate_witness(
        gate_bytes,
        &case.candidate_request,
        Some(attempt),
    )?;
    let PrivateReleaseObservationV1::AllocatedRetired {
        outcome,
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message(
            "checkpoint gate result branch differs".into(),
        ));
    };
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &case.result.installed
    else {
        return Err(CiError::Message(
            "checkpoint gate installed binding differs".into(),
        ));
    };
    let expected_response = validate_candidate_target_stdio_with_agent_identity(
        CHECKPOINT_GATE_SELECTOR,
        &case.result.target,
        challenge,
        stdio,
        attempt.checkpoint_network_namespace_inode(),
        None,
    )?;
    let attempt_bytes_id = hex::decode(&attempt.attempt_id)
        .map_err(|_| CiError::Message("checkpoint gate attempt is not hex".into()))?;
    if case.result.selector != CHECKPOINT_GATE_SELECTOR
        || case.candidate_request.selector != CHECKPOINT_GATE_SELECTOR
        || case.fault_marker_bytes.is_some()
        || request != &case.candidate_request_bytes
        || attempt_bytes_id.len() != 16
        || report.schema_version != 1
        || report.selector != CHECKPOINT_GATE_SELECTOR
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || report.checkpoint_sha256 != *checkpoint_sha256
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.response_sha256 != expected_response
        || report.checkpoint_gate_sha256 != hash_bytes(gate_bytes)
        || report.candidate_exit_code != 0
        || hash_bytes(report.installed_inspection_json.as_bytes()) != *expected_inspection_sha256
        || *installed_inspection_sha256 != *expected_inspection_sha256
        || witness.target
            != attempt
                .target
                .clone()
                .ok_or_else(|| CiError::Message("checkpoint gate target absent".into()))?
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || observer.checkpoint_gate_sha256 != report.checkpoint_gate_sha256
        || observer.settlement.schema_version != 1
        || observer.settlement.monitor_outcome != "Completed"
        || !observer.settlement.cgroup_empty_before_cleanup
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != Some(0)
        || observer.settlement.guardian_terminal[0] != 4
        || observer.settlement.guardian_terminal[1..17] != attempt_bytes_id
        || observer.settlement.guardian_terminal[17..] != [1, 0, 0]
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.checkpoint_gate_sha256 != report.checkpoint_gate_sha256
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || *outcome != PrivateReleaseAllocatedOutcomeV1::TargetCompleted
        || attempt_id != &report.attempt_id
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *retirement_sha256 != hash_bytes(cleanup_bytes)
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
        || *exec != PrivateReleaseExecV1::Succeeded
        || *native_observer_sha256 != hash_bytes(observer_bytes)
    {
        return Err(CiError::Message(
            "checkpoint gate raw evidence differs".into(),
        ));
    }
    Ok(())
}

fn child_chain_matches(chain: &[u32], host: u32, namespace: u32) -> bool {
    !chain.is_empty()
        && chain.len() <= 8
        && chain.iter().all(|pid| *pid != 0)
        && chain.first() == Some(&host)
        && chain.last() == Some(&namespace)
}

/// Mirrors the release-domain child/thread raw projection without accepting
/// the owner-supplied live witness as an independent kernel observation.
pub fn validate_candidate_child_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    let (Some(attempt), Some(attempt_bytes)) = (&case.attempt_record, &case.attempt_record_bytes)
    else {
        return Err(CiError::Message(
            "child runtime protected attempt absent".into(),
        ));
    };
    let [request, report_bytes, stdio, observer_bytes, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message(
            "child runtime raw inventory differs".into(),
        ));
    };
    for bytes in [report_bytes, observer_bytes, cleanup_bytes] {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    }
    let report: CandidateChildReportV1 = serde_json::from_slice(report_bytes)?;
    let observer: CandidateChildObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateChildCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let PrivateReleaseObservationV1::AllocatedRetired {
        outcome,
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message(
            "child runtime result branch differs".into(),
        ));
    };
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &case.result.installed
    else {
        return Err(CiError::Message(
            "child runtime installed binding differs".into(),
        ));
    };
    let live = &observer.live;
    let mut final_digest = Sha256::new();
    final_digest.update(b"memcordon-private-release-candidate-fixture-v1\0");
    final_digest.update(CHILD_RUNTIME_SELECTOR.as_bytes());
    final_digest.update([0]);
    final_digest.update(challenge);
    let final_response: [u8; 32] = final_digest.finalize().into();
    let mut response = Vec::with_capacity(8 + 3 * 4 + 32 + final_response.len());
    response.extend_from_slice(b"MCRCHLD1");
    response.extend_from_slice(&live.target_namespace_pid.to_le_bytes());
    response.extend_from_slice(&live.child_namespace_pid.to_le_bytes());
    response.extend_from_slice(&live.thread_namespace_tid.to_le_bytes());
    response.extend_from_slice(hash_bytes(&challenge).bytes());
    response.extend_from_slice(&final_response);
    let mut expected_stdio = challenge.to_vec();
    expected_stdio.extend_from_slice(&response);
    let attempt_bytes_id = hex::decode(&attempt.attempt_id)
        .map_err(|_| CiError::Message("child runtime attempt is not hex".into()))?;
    if case.result.selector != CHILD_RUNTIME_SELECTOR
        || case.candidate_request.selector != CHILD_RUNTIME_SELECTOR
        || case.fault_marker_bytes.is_some()
        || case.checkpoint_gate_bytes.is_some()
        || request != &case.candidate_request_bytes
        || attempt_bytes_id.len() != 16
        || attempt.phase != ProtectedAttemptPhaseV1::Retired
        || attempt.candidate_exit_code != Some(0)
        || report.schema_version != 1
        || report.selector != CHILD_RUNTIME_SELECTOR
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || report.checkpoint_sha256 != *checkpoint_sha256
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.response_sha256 != hash_bytes(&response)
        || report.candidate_exit_code != 0
        || hash_bytes(report.installed_inspection_json.as_bytes()) != *expected_inspection_sha256
        || *installed_inspection_sha256 != *expected_inspection_sha256
        || stdio != &expected_stdio
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || live.schema_version != 1
        || Some(&live.target) != attempt.target.as_ref()
        || live.child != report.child
        || live.child.pid == live.target.pid
        || live.thread_tid != report.thread_tid
        || live.thread_tid == live.target.pid
        || live.thread_tid == live.child.pid
        || live.thread_start_time != report.thread_start_time
        || live.thread_start_time == 0
        || live.target_namespace_pid != report.target_namespace_pid
        || live.child_namespace_pid != report.child_namespace_pid
        || live.thread_namespace_tid != report.thread_namespace_tid
        || live.target_namespace_pid == 0
        || live.child_namespace_pid == 0
        || live.thread_namespace_tid == 0
        || live.target_namespace_pid == live.child_namespace_pid
        || live.target_namespace_pid == live.thread_namespace_tid
        || live.child_namespace_pid == live.thread_namespace_tid
        || live.target_pid_chain != report.target_pid_chain
        || live.child_pid_chain != report.child_pid_chain
        || live.thread_tid_chain != report.thread_tid_chain
        || !child_chain_matches(
            &live.target_pid_chain,
            live.target.pid,
            live.target_namespace_pid,
        )
        || !child_chain_matches(
            &live.child_pid_chain,
            live.child.pid,
            live.child_namespace_pid,
        )
        || !child_chain_matches(
            &live.thread_tid_chain,
            live.thread_tid,
            live.thread_namespace_tid,
        )
        || live.challenge_sha256 != hash_bytes(&challenge)
        || live.cgroup_procs_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || live.cgroup_threads_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || observer.settlement.schema_version != 1
        || observer.settlement.monitor_outcome != "Completed"
        || !observer.settlement.cgroup_empty_before_cleanup
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != Some(0)
        || observer.settlement.guardian_terminal[0] != 4
        || observer.settlement.guardian_terminal[1..17] != attempt_bytes_id
        || observer.settlement.guardian_terminal[17..] != [1, 0, 0]
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.child != live.child
        || cleanup.thread_tid != live.thread_tid
        || cleanup.target_namespace_pid != live.target_namespace_pid
        || cleanup.child_namespace_pid != live.child_namespace_pid
        || cleanup.thread_namespace_tid != live.thread_namespace_tid
        || cleanup.target_pid_chain != live.target_pid_chain
        || cleanup.child_pid_chain != live.child_pid_chain
        || cleanup.thread_tid_chain != live.thread_tid_chain
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || *outcome != PrivateReleaseAllocatedOutcomeV1::TargetCompleted
        || attempt_id != &report.attempt_id
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *retirement_sha256 != hash_bytes(cleanup_bytes)
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
        || *exec != PrivateReleaseExecV1::Succeeded
        || *native_observer_sha256 != hash_bytes(observer_bytes)
    {
        return Err(CiError::Message(
            "child runtime raw evidence differs".into(),
        ));
    }
    Ok(())
}

pub fn verify_child_runtime_processes_exited(case: &StructuralProtectedNativeCaseV1) -> Result<()> {
    if case.result.selector != CHILD_RUNTIME_SELECTOR {
        return Err(CiError::Message("child runtime selector differs".into()));
    }
    let attempt = case
        .attempt_record
        .as_ref()
        .ok_or_else(|| CiError::Message("child runtime attempt absent".into()))?;
    let observer_bytes = case
        .attachments
        .get(3)
        .ok_or_else(|| CiError::Message("child runtime observer absent".into()))?;
    let cleanup_bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("child runtime cleanup absent".into()))?;
    reject_duplicate_json_keys(observer_bytes).map_err(CiError::Message)?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let observer: CandidateChildObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateChildCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    for identity in [
        Some(&cleanup.worker),
        attempt.guardian.as_ref(),
        attempt.namespace_init.as_ref(),
        attempt.target.as_ref(),
        Some(&observer.live.child),
    ] {
        let identity = identity
            .ok_or_else(|| CiError::Message("child runtime native identity absent".into()))?;
        crate::private_supervisor::verify_recorded_process_exited(
            crate::private_supervisor::LinuxChildIdentityV1 {
                pid: identity.pid,
                start_time_ticks: identity.start_time,
            },
        )?;
    }
    let thread = Path::new("/proc")
        .join(observer.live.target.pid.to_string())
        .join("task")
        .join(observer.live.thread_tid.to_string());
    let cgroup = Path::new("/sys/fs/cgroup/memcordon-sealed").join(&attempt.attempt_id);
    for path in [thread, cgroup] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(CiError::Message(
                    "child runtime task or cgroup remains after retirement".into(),
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Exact protected SCM raw/result projection. The separate CI live sampler
/// must still join the gate and actual procfs socket identities; this parser
/// cannot turn native owner bytes into Q authority.
pub fn validate_candidate_socket_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    let (Some(attempt), Some(attempt_bytes)) = (&case.attempt_record, &case.attempt_record_bytes)
    else {
        return Err(CiError::Message("SCM retired attempt absent".into()));
    };
    let [request, report_bytes, stdio, observer_bytes, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message("SCM raw inventory differs".into()));
    };
    for bytes in [report_bytes, observer_bytes, cleanup_bytes] {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    }
    let report: CandidateSocketReportV1 = serde_json::from_slice(report_bytes)?;
    let observer: CandidateSocketObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateSocketCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let PrivateReleaseObservationV1::AllocatedRetired {
        outcome,
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message("SCM result branch differs".into()));
    };
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &case.result.installed
    else {
        return Err(CiError::Message("SCM installed binding differs".into()));
    };
    let response_sha256 = validate_candidate_target_stdio(
        SOCKET_SELECTOR,
        &case.result.target,
        challenge,
        stdio,
        attempt.checkpoint_network_namespace_inode(),
    )?;
    let witness = &observer.gated_witness;
    let attempt_bytes_id = hex::decode(&attempt.attempt_id)
        .map_err(|_| CiError::Message("SCM attempt ID is not hex".into()))?;
    if case.result.selector != SOCKET_SELECTOR
        || case.candidate_request.selector != SOCKET_SELECTOR
        || case.fault_marker_bytes.is_some()
        || case.checkpoint_gate_bytes.is_some()
        || request != &case.candidate_request_bytes
        || attempt_bytes_id.len() != 16
        || attempt.phase != ProtectedAttemptPhaseV1::Retired
        || attempt.candidate_exit_code != Some(0)
        || report.schema_version != 1
        || report.selector != SOCKET_SELECTOR
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || report.checkpoint_sha256 != *checkpoint_sha256
        || attempt.checkpoint_digest.as_ref() != Some(checkpoint_sha256)
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.response_sha256 != response_sha256
        || report.socket_gate_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || report.candidate_exit_code != 0
        || serde_json::to_vec(&report)? != *report_bytes
        || hash_bytes(report.installed_inspection_json.as_bytes()) != *expected_inspection_sha256
        || *installed_inspection_sha256 != *expected_inspection_sha256
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || witness.schema_version != 1
        || Some(&witness.target) != attempt.target.as_ref()
        || witness.network_namespace_inode == 0
        || Some(witness.network_namespace_inode) != attempt.checkpoint_network_namespace_inode()
        || witness.first_socket_inode == 0
        || witness.second_socket_inode == 0
        || (witness.first_socket_device, witness.first_socket_inode)
            == (witness.second_socket_device, witness.second_socket_inode)
        || witness.filter_sha256 != *attempt.checkpoint_filter_sha256().ok_or_else(|| {
            CiError::Message("SCM checkpoint filter absent".into())
        })?
        || witness.sendmsg_errno != 1 // Linux UAPI EPERM, fixed independently.
        || observer.settlement.schema_version != 1
        || observer.settlement.monitor_outcome != "Completed"
        || !observer.settlement.cgroup_empty_before_cleanup
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != Some(0)
        || observer.settlement.guardian_terminal[0] != 4
        || observer.settlement.guardian_terminal[1..17] != attempt_bytes_id
        || observer.settlement.guardian_terminal[17..] != [1, 0, 0]
        || serde_json::to_vec(&observer)? != *observer_bytes
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.socket_gate_sha256 != report.socket_gate_sha256
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || serde_json::to_vec(&cleanup)? != *cleanup_bytes
        || *outcome != PrivateReleaseAllocatedOutcomeV1::TargetCompleted
        || attempt_id != &report.attempt_id
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *retirement_sha256 != hash_bytes(cleanup_bytes)
        || *native_observer_sha256 != hash_bytes(observer_bytes)
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
        || *exec != PrivateReleaseExecV1::Succeeded
    {
        return Err(CiError::Message(
            "SCM protected raw/result join differs".into(),
        ));
    }
    Ok(())
}

pub fn verify_candidate_socket_processes_exited(
    case: &StructuralProtectedNativeCaseV1,
) -> Result<()> {
    if case.result.selector != SOCKET_SELECTOR {
        return Err(CiError::Message("SCM selector differs".into()));
    }
    let attempt = case
        .attempt_record
        .as_ref()
        .ok_or_else(|| CiError::Message("SCM attempt absent".into()))?;
    let cleanup_bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("SCM cleanup absent".into()))?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let cleanup: CandidateSocketCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    for identity in [
        Some(&cleanup.worker),
        attempt.guardian.as_ref(),
        attempt.namespace_init.as_ref(),
        attempt.target.as_ref(),
    ] {
        let identity =
            identity.ok_or_else(|| CiError::Message("SCM native identity absent".into()))?;
        crate::private_supervisor::verify_recorded_process_exited(
            crate::private_supervisor::LinuxChildIdentityV1 {
                pid: identity.pid,
                start_time_ticks: identity.start_time,
            },
        )?;
    }
    let cgroup = Path::new("/sys/fs/cgroup/memcordon-sealed").join(&attempt.attempt_id);
    match std::fs::symlink_metadata(cgroup) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(CiError::Message(
            "SCM cgroup remains after retirement".into(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// Structural midpoint/raw/result join. A separate CI sampler must have
/// observed the target and cgroup before ACK; owner bytes alone are not Q.
pub fn validate_candidate_terminal_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
    midpoint: &StructuralTerminalMidflightV1,
    gate_sha256: &DiagnosticSha256,
    sampled_pid_chain: &[u32],
) -> Result<()> {
    let (Some(attempt), Some(attempt_bytes)) = (&case.attempt_record, &case.attempt_record_bytes)
    else {
        return Err(CiError::Message("terminal retired attempt absent".into()));
    };
    let [request, report_bytes, stdio, observer_bytes, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message("terminal raw inventory differs".into()));
    };
    for bytes in [report_bytes, observer_bytes, cleanup_bytes] {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    }
    let report: CandidateTerminalReportV1 = serde_json::from_slice(report_bytes)?;
    let observer: CandidateTerminalObserverV1 = serde_json::from_slice(observer_bytes)?;
    let cleanup: CandidateTerminalCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let PrivateReleaseObservationV1::AllocatedRetired {
        outcome,
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message("terminal result branch differs".into()));
    };
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &case.result.installed
    else {
        return Err(CiError::Message(
            "terminal installed binding differs".into(),
        ));
    };
    let (live_frame, response_sha256) =
        validate_terminal_target_stdio(challenge, report.target_namespace_pid, stdio)?;
    let attempt_bytes_id = hex::decode(&attempt.attempt_id)
        .map_err(|_| CiError::Message("terminal attempt ID is not hex".into()))?;
    if case.result.selector != TERMINAL_JOIN_SELECTOR
        || case.candidate_request.selector != TERMINAL_JOIN_SELECTOR
        || case.fault_marker_bytes.is_some()
        || case.checkpoint_gate_bytes.is_some()
        || request != &case.candidate_request_bytes
        || attempt_bytes_id.len() != 16
        || attempt.phase != ProtectedAttemptPhaseV1::Retired
        || attempt.candidate_exit_code != Some(0)
        || attempt.release_knowledge != ProtectedReleaseKnowledgeV1::ExecObserved
        || attempt.target.as_ref() != Some(&midpoint.target)
        || attempt.checkpoint_digest.as_ref() != Some(&midpoint.checkpoint_sha256)
        || attempt.checkpoint_filter_sha256() != Some(&midpoint.filter_sha256)
        || attempt.checkpoint_network_namespace_inode() != Some(midpoint.network_namespace_inode)
        || report.schema_version != 1
        || report.selector != TERMINAL_JOIN_SELECTOR
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || report.checkpoint_sha256 != *checkpoint_sha256
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.response_sha256 != response_sha256
        || report.midflight_record_digest != midpoint.execution_record_digest
        || report.terminal_join_gate_sha256 != *gate_sha256
        || report.target_namespace_pid == 0
        || report.target_pid_chain != sampled_pid_chain
        || report.target_pid_chain.first() != Some(&midpoint.target.pid)
        || report.target_pid_chain.last() != Some(&report.target_namespace_pid)
        || report.target_pid_chain.len() > 8
        || report.target_pid_chain.contains(&0)
        || report.candidate_exit_code != 0
        || hash_bytes(report.installed_inspection_json.as_bytes()) != *expected_inspection_sha256
        || *installed_inspection_sha256 != *expected_inspection_sha256
        || serde_json::to_vec(&report)? != *report_bytes
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || observer.live_frame != live_frame
        || observer.settlement.schema_version != 1
        || observer.settlement.monitor_outcome != "Completed"
        || !observer.settlement.cgroup_empty_before_cleanup
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != Some(0)
        || observer.settlement.guardian_terminal[0] != 4
        || observer.settlement.guardian_terminal[1..17] != attempt_bytes_id
        || observer.settlement.guardian_terminal[17..] != [1, 0, 0]
        || serde_json::to_vec(&observer)? != *observer_bytes
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.terminal_join_gate_sha256 != *gate_sha256
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || serde_json::to_vec(&cleanup)? != *cleanup_bytes
        || *outcome != PrivateReleaseAllocatedOutcomeV1::TargetCompleted
        || attempt_id != &report.attempt_id
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *retirement_sha256 != hash_bytes(cleanup_bytes)
        || *native_observer_sha256 != hash_bytes(observer_bytes)
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
        || *exec != PrivateReleaseExecV1::Succeeded
    {
        return Err(CiError::Message(
            "terminal protected raw/result join differs".into(),
        ));
    }
    Ok(())
}

pub fn verify_candidate_terminal_processes_exited(
    case: &StructuralProtectedNativeCaseV1,
) -> Result<()> {
    if case.result.selector != TERMINAL_JOIN_SELECTOR {
        return Err(CiError::Message("terminal selector differs".into()));
    }
    let attempt = case
        .attempt_record
        .as_ref()
        .ok_or_else(|| CiError::Message("terminal attempt absent".into()))?;
    let cleanup_bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("terminal cleanup absent".into()))?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let cleanup: CandidateTerminalCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    for identity in [
        Some(&cleanup.worker),
        attempt.guardian.as_ref(),
        attempt.namespace_init.as_ref(),
        attempt.target.as_ref(),
    ] {
        let identity =
            identity.ok_or_else(|| CiError::Message("terminal native identity absent".into()))?;
        crate::private_supervisor::verify_recorded_process_exited(
            crate::private_supervisor::LinuxChildIdentityV1 {
                pid: identity.pid,
                start_time_ticks: identity.start_time,
            },
        )?;
    }
    let cgroup = Path::new("/sys/fs/cgroup/memcordon-sealed").join(&attempt.attempt_id);
    match std::fs::symlink_metadata(cgroup) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(CiError::Message(
            "terminal cgroup remains after retirement".into(),
        )),
        Err(error) => Err(error.into()),
    }
}

pub fn verify_checkpoint_gate_processes_exited(
    case: &StructuralProtectedNativeCaseV1,
) -> Result<()> {
    if case.result.selector != CHECKPOINT_GATE_SELECTOR {
        return Err(CiError::Message("checkpoint gate selector differs".into()));
    }
    let attempt = case
        .attempt_record
        .as_ref()
        .ok_or_else(|| CiError::Message("checkpoint gate attempt absent".into()))?;
    let cleanup_bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("checkpoint gate cleanup absent".into()))?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let cleanup: CandidateCheckpointGateCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    for identity in [
        Some(&cleanup.worker),
        attempt.guardian.as_ref(),
        attempt.namespace_init.as_ref(),
        attempt.target.as_ref(),
    ] {
        let identity = identity
            .ok_or_else(|| CiError::Message("checkpoint gate native identity absent".into()))?;
        crate::private_supervisor::verify_recorded_process_exited(
            crate::private_supervisor::LinuxChildIdentityV1 {
                pid: identity.pid,
                start_time_ticks: identity.start_time,
            },
        )?;
    }
    Ok(())
}

pub fn validate_candidate_allocated_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    validate_candidate_allocated_raw_attachments_with_agent_identity(
        case,
        challenge,
        expected_inspection_sha256,
        None,
    )
}

pub fn validate_candidate_allocated_raw_attachments_with_agent_identity(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
    installed_agent_identity: Option<(u64, u64)>,
) -> Result<()> {
    let selector = case.result.selector.as_str();
    let Some(attempt) = &case.attempt_record else {
        return Err(CiError::Message(
            "candidate TCP attempt journal absent".into(),
        ));
    };
    let Some(attempt_bytes) = &case.attempt_record_bytes else {
        return Err(CiError::Message(
            "candidate TCP attempt bytes absent".into(),
        ));
    };
    let [request, report_bytes, stdio, observer, cleanup_bytes] = case.attachments.as_slice()
    else {
        return Err(CiError::Message(
            "candidate TCP raw inventory differs".into(),
        ));
    };
    reject_duplicate_json_keys(report_bytes).map_err(CiError::Message)?;
    reject_duplicate_json_keys(observer).map_err(CiError::Message)?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let report: CandidateTcpReportV1 = serde_json::from_slice(report_bytes)?;
    let kernel: CandidateKernelObservationV1 = serde_json::from_slice(observer)?;
    if (selector == crate::private_host_state::HOST_PRESERVATION_SELECTOR)
        != kernel.host_network_preservation.is_some()
        || (selector == crate::private_agent_path::AGENT_PATH_SELECTOR)
            != kernel.agent_path_preservation.is_some()
    {
        return Err(CiError::Message(
            "candidate host-preservation observer inventory differs".into(),
        ));
    }
    let cleanup: CandidateTcpCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    let expected_guardian_attempt = hex::decode(&attempt.attempt_id)
        .map_err(|_| CiError::Message("candidate guardian attempt is not hex".into()))?;
    let expected_response_sha256 = validate_candidate_target_stdio_with_agent_identity(
        selector,
        &case.result.target,
        challenge,
        stdio,
        attempt.checkpoint_network_namespace_inode(),
        installed_agent_identity,
    )?;
    let installed_inspection_digest = hash_bytes(report.installed_inspection_json.as_bytes());
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &case.result.installed
    else {
        return Err(CiError::Message(
            "candidate TCP installed binding differs".into(),
        ));
    };
    let PrivateReleaseObservationV1::AllocatedRetired {
        outcome,
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        release_knowledge,
        exec,
        native_observer_sha256,
    } = &case.result.observation
    else {
        return Err(CiError::Message(
            "candidate TCP observation branch differs".into(),
        ));
    };
    if case.result.selector != selector
        || case.candidate_request.selector != selector
        || request != &case.candidate_request_bytes
        || expected_guardian_attempt.len() != 16
        || kernel.schema_version != 1
        || kernel.attempt_id != attempt.attempt_id
        || attempt.checkpoint_digest.as_ref() != Some(&kernel.checkpoint_sha256)
        || kernel.terminal_record_digest != attempt.record_digest
        || kernel.settlement.schema_version != 1
        || kernel.settlement.monitor_outcome != "Completed"
        || !kernel.settlement.cgroup_empty_before_cleanup
        || !kernel.settlement.containment_removed
        || !kernel.settlement.target_pidfd_exited
        || !kernel.settlement.namespace_init_reaped
        || kernel.settlement.candidate_exit_code != Some(0)
        || kernel.settlement.guardian_terminal[0] != 4
        || kernel.settlement.guardian_terminal[1..17] != expected_guardian_attempt
        || kernel.settlement.guardian_terminal[17..] != [1, 0, 0]
        || report.schema_version != 1
        || report.selector != selector
        || report.result_key != case.candidate_request.result_key
        || report.attempt_id != attempt.attempt_id
        || report.checkpoint_sha256 != *checkpoint_sha256
        || report.terminal_record_digest != attempt.record_digest
        || report.challenge_sha256 != hash_bytes(&challenge)
        || report.response_sha256 != expected_response_sha256
        || report.candidate_exit_code != 0
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.candidate_exit_code != 0
        || cleanup.kernel_trace_sha256 != hash_bytes(observer)
        || cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || installed_inspection_digest != *expected_inspection_sha256
        || installed_inspection_digest != *installed_inspection_sha256
        || *outcome != PrivateReleaseAllocatedOutcomeV1::TargetCompleted
        || attempt_id != &report.attempt_id
        || *terminal_sha256 != hash_bytes(attempt_bytes)
        || *retirement_sha256 != hash_bytes(cleanup_bytes)
        || *native_observer_sha256 != hash_bytes(observer)
        || *release_knowledge
            != memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::ExecObserved
        || *exec != PrivateReleaseExecV1::Succeeded
    {
        return Err(CiError::Message(
            "candidate TCP raw attachments differ from protected custody".into(),
        ));
    }
    Ok(())
}

/// Compatibility entrypoint retained for the existing TCP fixture tests.
pub fn validate_candidate_tcp_raw_attachments(
    case: &StructuralProtectedNativeCaseV1,
    challenge: [u8; 32],
    expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    if case.result.selector != "private_tcp::native_tcp_bind_listen_connect" {
        return Err(CiError::Message("candidate TCP selector differs".into()));
    }
    validate_candidate_allocated_raw_attachments(case, challenge, expected_inspection_sha256)
}

/// Rechecks the coordinator's recorded worker against the live host's process
/// table after native finalization. This only corroborates worker exit; the
/// owner trace and reported outcome still need independent native proof.
pub fn verify_candidate_worker_exited(case: &StructuralProtectedNativeCaseV1) -> Result<()> {
    let cleanup_bytes = case
        .attachments
        .get(4)
        .ok_or_else(|| CiError::Message("candidate cleanup attachment absent".into()))?;
    reject_duplicate_json_keys(cleanup_bytes).map_err(CiError::Message)?;
    let cleanup: CandidateTcpCleanupV1 = serde_json::from_slice(cleanup_bytes)?;
    if cleanup.coordinator != case.candidate_request.coordinator
        || cleanup.worker == cleanup.coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err(CiError::Message(
            "candidate worker exit record differs from protected admission".into(),
        ));
    }
    crate::private_supervisor::verify_recorded_process_exited(
        crate::private_supervisor::LinuxChildIdentityV1 {
            pid: cleanup.worker.pid,
            start_time_ticks: cleanup.worker.start_time,
        },
    )
}

pub fn parse_protected_candidate_request(
    bytes: &[u8],
    selector: &str,
    challenge: [u8; 32],
    key: &DiagnosticSha256,
) -> Result<ProtectedCandidateReleaseRequestV1> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(CiError::Message(
            "private protected request size differs".into(),
        ));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let request: ProtectedCandidateReleaseRequestV1 = serde_json::from_slice(bytes)?;
    if request.schema_version != 1
        || request.stage != "candidate-capability"
        || request.selector != selector
        || request.challenge != hex::encode(challenge)
        || request.result_key != *key
        || request.coordinator.pid == 0
        || request.coordinator.start_time == 0
    {
        return Err(CiError::Message(
            "private protected request identity differs".into(),
        ));
    }
    Ok(request)
}

pub fn read_structural_protected_native_case(
    stage: NativeRunStageV2,
    target: &str,
    selector: &str,
    challenge: [u8; 32],
) -> Result<StructuralProtectedNativeCaseV1> {
    use memcordon_core::private_release_case_v1::private_release_case_key_v1;

    let stage = match stage {
        NativeRunStageV2::CandidateCapability => PrivateReleaseStageV1::CandidateCapability,
        NativeRunStageV2::FinalPublic => {
            return Err(CiError::Message(
                "final-public protected admission contract is unavailable".into(),
            ));
        }
    };
    let key = private_release_case_key_v1(stage, selector, &challenge).map_err(CiError::Message)?;
    let key_text: String = key.clone().into();
    let root = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1);
    let result_path = root.join(format!("{key_text}.json"));
    let result_bytes = read_protected_raw_case_file(&result_path)?;
    let result = PrivateReleaseCaseResultV1::parse(&result_bytes).map_err(CiError::Message)?;
    if result.selector != selector
        || result.target != target
        || result.challenge != hex::encode(challenge)
        || result.installed.stage() != stage
        || result.result_key().map_err(CiError::Message)? != key
    {
        return Err(CiError::Message(
            "private protected case identity differs".into(),
        ));
    }
    validate_fixed_case_observation(
        match stage {
            PrivateReleaseStageV1::CandidateCapability => NativeRunStageV2::CandidateCapability,
            PrivateReleaseStageV1::FinalPublic => NativeRunStageV2::FinalPublic,
        },
        selector,
        &result.observation,
    )?;
    let attachment_directory = root.join(&key_text);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&attachment_directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(CiError::Message(
                "private raw attachment directory protection differs".into(),
            ));
        }
    }
    let mut observed_leaves = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&attachment_directory)? {
        let entry = entry?;
        let leaf = entry.file_name();
        let leaf = leaf
            .to_str()
            .ok_or_else(|| CiError::Message("private raw attachment leaf is not UTF-8".into()))?;
        if !observed_leaves.insert(leaf.to_owned()) {
            return Err(CiError::Message(
                "private raw attachment leaf repeats".into(),
            ));
        }
    }
    let expected_leaves =
        expected_protected_candidate_leaves_for_selector(selector, &result.observation)?;
    if observed_leaves != expected_leaves {
        return Err(CiError::Message(
            "private raw attachment inventory differs".into(),
        ));
    }
    if selector == DUAL_SELECTOR {
        for child in ["dual-first", "dual-second"] {
            let directory = attachment_directory.join(child);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let metadata = std::fs::symlink_metadata(&directory)?;
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
                    return Err(CiError::Message(
                        "dual child directory protection differs".into(),
                    ));
                }
            }
            let mut leaves = std::collections::BTreeSet::new();
            for entry in std::fs::read_dir(&directory)? {
                let entry = entry?;
                let leaf = entry.file_name();
                let leaf = leaf
                    .to_str()
                    .ok_or_else(|| CiError::Message("dual child leaf is not UTF-8".into()))?;
                leaves.insert(leaf.to_owned());
            }
            if leaves != std::collections::BTreeSet::from(["attempt.json".to_owned()]) {
                return Err(CiError::Message("dual child inventory differs".into()));
            }
        }
    }
    let candidate_request_bytes =
        read_protected_raw_case_file(&attachment_directory.join("request.json"))?;
    let candidate_request =
        parse_protected_candidate_request(&candidate_request_bytes, selector, challenge, &key)?;
    let (attempt_record, attempt_record_bytes) = if expected_leaves.contains("attempt.json") {
        let bytes = read_protected_raw_case_file(&attachment_directory.join("attempt.json"))?;
        let record = parse_protected_candidate_attempt(
            &bytes,
            &candidate_request,
            &result.observation,
            challenge,
        )?;
        (Some(record), Some(bytes))
    } else {
        (None, None)
    };
    let fault_marker_bytes = if expected_leaves.contains("attempt.json.new") {
        let bytes = read_protected_raw_case_file(&attachment_directory.join("attempt.json.new"))?;
        validate_blocked_retirement_marker(&bytes, &result, attempt_record.as_ref())?;
        Some(bytes)
    } else {
        None
    };
    let checkpoint_gate_bytes = if expected_leaves.contains("checkpoint-gate.json") {
        let bytes =
            read_protected_raw_case_file(&attachment_directory.join("checkpoint-gate.json"))?;
        parse_protected_checkpoint_gate_witness(
            &bytes,
            &candidate_request,
            attempt_record.as_ref(),
        )?;
        Some(bytes)
    } else {
        None
    };
    match &result.installed {
        PrivateReleaseInstalledBindingV1::CandidateCapability {
            installation_epoch,
            candidate_manifest_sha256,
            ..
        } if *installation_epoch == candidate_request.installation_epoch
            && *candidate_manifest_sha256 == candidate_request.candidate_manifest_sha256 => {}
        _ => {
            return Err(CiError::Message(
                "private result differs from protected M0 admission".into(),
            ));
        }
    }
    let mut attachments = Vec::with_capacity(PrivateReleaseAttachmentRoleV1::ALL.len());
    for (record, role) in result
        .attachments
        .iter()
        .zip(PrivateReleaseAttachmentRoleV1::ALL)
    {
        let bytes = read_protected_raw_case_file(&attachment_directory.join(role.leaf()))?;
        if bytes.len() as u64 != record.size || hash_bytes(&bytes) != record.sha256 {
            return Err(CiError::Message(
                "private raw attachment bytes differ".into(),
            ));
        }
        attachments.push(bytes);
    }
    Ok(StructuralProtectedNativeCaseV1 {
        result,
        candidate_request,
        candidate_request_bytes,
        attempt_record,
        attempt_record_bytes,
        fault_marker_bytes,
        checkpoint_gate_bytes,
        attachments,
    })
}

#[cfg(unix)]
pub fn read_protected_raw_case_file(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;

    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(CiError::Message(
            "private raw path is not exact absolute".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| CiError::Message("private raw parent absent".into()))?;
    let mut current = std::path::PathBuf::from("/");
    for part in parent.components() {
        if let Component::Normal(name) = part {
            current.push(name);
            let metadata = std::fs::symlink_metadata(&current)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(CiError::Message(
                    "private raw ancestor is not root-protected".into(),
                ));
            }
        }
    }
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.mode() & 0o7777 != 0o700 {
        return Err(CiError::Message("private raw parent mode differs".into()));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > MAX_RAW_CASE_BYTES
    {
        return Err(CiError::Message(
            "private raw file protection differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RAW_CASE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let path_after = std::fs::symlink_metadata(path)?;
    let parent_after = std::fs::symlink_metadata(parent)?;
    if bytes.len() as u64 != before.len()
        || bytes.len() as u64 > MAX_RAW_CASE_BYTES
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || (path_after.dev(), path_after.ino()) != (before.dev(), before.ino())
        || (parent_after.dev(), parent_after.ino())
            != (parent_metadata.dev(), parent_metadata.ino())
    {
        return Err(CiError::Message(
            "private raw file changed during readback".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
pub fn read_protected_raw_case_file(_path: &Path) -> Result<Vec<u8>> {
    Err(CiError::Message(
        "private raw readback requires Unix".into(),
    ))
}
