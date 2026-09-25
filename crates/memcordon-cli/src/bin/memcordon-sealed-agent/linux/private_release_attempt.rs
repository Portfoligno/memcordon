//! Durable V4 custody for one candidate release case. This is deliberately
//! disjoint from the installed eight-case H1 probe and production attempts.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::private_attempt::{PrivateAttemptPhase, ProcessIdentityV4, ReleaseKnowledge};
use super::private_lifecycle::PrivateNativeJournal;

const RECORD_LEAF: &str = "attempt.json";
const TEMP_LEAF: &str = "attempt.json.new";
const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_FAULT_MARKER_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetirementTransitionFaultMarkerV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_digest: DiagnosticSha256,
    transition: String,
}

impl RetirementTransitionFaultMarkerV1 {
    fn for_record(record: &ReleaseCandidateAttemptRecordV1) -> Result<Self, String> {
        Ok(Self {
            schema_version: 1,
            result_key: record.result_key.clone(),
            attempt_id: record.attempt_id.clone(),
            checkpoint_digest: record
                .checkpoint_digest
                .clone()
                .ok_or("MCSEALED-PRIVATE-RELEASE: retirement fault checkpoint absent")?,
            transition: "retired-transition-blocked".into(),
        })
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_FAULT_MARKER_BYTES {
            return Err("MCSEALED-PRIVATE-RELEASE: retirement fault marker too large".into());
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseCandidateCheckpointV1 {
    pub(super) schema_version: u8,
    pub(super) result_key: DiagnosticSha256,
    pub(super) selector: String,
    pub(super) challenge_sha256: DiagnosticSha256,
    pub(super) attempt_id: String,
    pub(super) installation_epoch: DiagnosticSha256,
    pub(super) candidate_manifest_sha256: DiagnosticSha256,
    pub(super) service_generation_sha256: DiagnosticSha256,
    pub(super) fixture_sha256: DiagnosticSha256,
    pub(super) filter_sha256: DiagnosticSha256,
    pub(super) target_uid: u32,
    pub(super) target_gid: u32,
    pub(super) guardian: ProcessIdentityV4,
    pub(super) namespace_init: ProcessIdentityV4,
    pub(super) target: ProcessIdentityV4,
    pub(super) network_namespace_inode: u64,
    pub(super) topology_sha256: DiagnosticSha256,
    pub(super) native_readback_sha256: DiagnosticSha256,
}

impl ReleaseCandidateCheckpointV1 {
    pub(crate) fn digest(&self) -> Result<DiagnosticSha256, String> {
        let mut digest = Sha256::new();
        digest.update(b"memcordon-private-release-candidate-checkpoint-v1\0");
        digest.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(DiagnosticSha256::from_bytes(digest.finalize().into()))
    }
}

pub(crate) struct ReleaseCandidatePermitV1 {
    attempt_id: String,
    checkpoint_digest: DiagnosticSha256,
}

pub(crate) struct ReleaseCandidateRetirementObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: Option<DiagnosticSha256>,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) candidate_exit_code: Option<i32>,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UncertainCandidateSettlementFactsV1 {
    pub(crate) schema_version: u8,
    pub(crate) transport_errno: i32,
    pub(crate) containment_removed: bool,
    pub(crate) target_pidfd_exited: bool,
    pub(crate) namespace_init_reaped: bool,
    pub(crate) guardian_terminal: [u8; 20],
    pub(crate) candidate_exit_code: Option<i32>,
}

pub(crate) struct UncertainCandidateRetirementObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) settlement: UncertainCandidateSettlementFactsV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardianLossCandidateSettlementFactsV1 {
    pub(crate) schema_version: u8,
    pub(crate) guardian: ProcessIdentityV4,
    pub(crate) guardian_signal: i32,
    pub(crate) containment_removed: bool,
    pub(crate) target_pidfd_exited: bool,
    pub(crate) namespace_init_reaped: bool,
    pub(crate) candidate_exit_code: Option<i32>,
}

pub(crate) struct GuardianLossCandidateRetirementObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) settlement: GuardianLossCandidateSettlementFactsV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrontendLossCandidateSettlementFactsV1 {
    pub(crate) schema_version: u8,
    pub(crate) frontend: ProcessIdentityV4,
    pub(crate) frontend_signal: i32,
    pub(crate) guardian_terminal: [u8; 20],
    pub(crate) containment_removed: bool,
    pub(crate) target_pidfd_exited: bool,
    pub(crate) namespace_init_reaped: bool,
    pub(crate) candidate_exit_code: Option<i32>,
}

pub(crate) struct FrontendLossCandidateRetirementObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) settlement: FrontendLossCandidateSettlementFactsV1,
}

pub(crate) struct BlockedCandidateRetirementObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) fault_marker_bytes: Vec<u8>,
    pub(crate) transition_error: String,
    pub(crate) reuse_error: String,
    pub(crate) settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
}

pub(crate) struct ReleaseCandidateReadbackExpectationV1<'a> {
    pub(crate) result_key: &'a DiagnosticSha256,
    pub(crate) selector: &'a str,
    pub(crate) challenge: &'a [u8; 32],
    pub(crate) installation_epoch: &'a DiagnosticSha256,
    pub(crate) candidate_manifest_sha256: &'a DiagnosticSha256,
    pub(crate) service_generation_sha256: &'a DiagnosticSha256,
    pub(crate) coordinator: &'a ProcessIdentityV4,
}

/// A protected journal readback, not an independent OS supervisor trace or a
/// release qualification. The containing finalizer must separately establish
/// that the coordinator has exited and that raw attachments agree.
pub(crate) struct ReadbackRetiredCandidateAttemptV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) terminal_bytes: Vec<u8>,
}

pub(crate) struct CheckpointGateCandidateReadbackV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) release_intent_record_digest: DiagnosticSha256,
    pub(crate) target: ProcessIdentityV4,
    pub(crate) release_intent_bytes: Vec<u8>,
}

/// Live post-release journal state, read while the fixed target remains
/// blocked on owner acknowledgment. It is not terminal/retirement evidence.
pub(crate) struct MidflightTerminalJoinReadbackV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) execution_record_digest: DiagnosticSha256,
    pub(crate) target: ProcessIdentityV4,
    pub(crate) network_namespace_inode: u64,
    pub(crate) filter_sha256: DiagnosticSha256,
    pub(crate) execution_record_bytes: Vec<u8>,
}

pub(crate) fn read_midflight_terminal_join_journal(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<MidflightTerminalJoinReadbackV1, String> {
    let (_, bytes) = read_record_in(directory, 0)?;
    parse_midflight_terminal_join_journal_bytes(&bytes, expected)
}

pub(crate) fn parse_midflight_terminal_join_journal_bytes(
    bytes: &[u8],
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<MidflightTerminalJoinReadbackV1, String> {
    if expected.selector != super::private_release_terminal_join::SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join selector differs".into());
    }
    parse_midflight_candidate_journal_bytes(bytes, expected)
}

pub(crate) fn read_midflight_dual_journal(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<MidflightTerminalJoinReadbackV1, String> {
    let (_, bytes) = read_record_in(directory, 0)?;
    parse_midflight_dual_journal_bytes(&bytes, expected)
}

pub(crate) fn parse_midflight_dual_journal_bytes(
    bytes: &[u8],
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<MidflightTerminalJoinReadbackV1, String> {
    if expected.selector != super::private_release_dual_attempt::SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: dual selector differs".into());
    }
    parse_midflight_candidate_journal_bytes(bytes, expected)
}

fn parse_midflight_candidate_journal_bytes(
    bytes: &[u8],
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<MidflightTerminalJoinReadbackV1, String> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join midflight bound differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let record: ReleaseCandidateAttemptRecordV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    record.validate()?;
    if record.selector != expected.selector
        || record.phase != PrivateAttemptPhase::ExecutionObserved
        || record.release_knowledge != ReleaseKnowledge::ExecObserved
        || record.cleanup_error.is_some()
        || record.candidate_exit_code.is_some()
        || &record.result_key != expected.result_key
        || record.challenge_sha256 != hash_bytes(expected.challenge)
        || &record.installation_epoch != expected.installation_epoch
        || &record.candidate_manifest_sha256 != expected.candidate_manifest_sha256
        || &record.service_generation_sha256 != expected.service_generation_sha256
        || &record.coordinator != expected.coordinator
        || record.frontend_proxy.is_some()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join midflight journal differs".into());
    }
    let checkpoint = record
        .checkpoint_binding
        .ok_or("MCSEALED-PRIVATE-RELEASE: terminal-join checkpoint absent")?;
    if Some(&checkpoint.target) != record.target.as_ref()
        || Some(&checkpoint.digest()?) != record.checkpoint_digest.as_ref()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join checkpoint binding differs".into());
    }
    Ok(MidflightTerminalJoinReadbackV1 {
        attempt_id: record.attempt_id,
        checkpoint_digest: record
            .checkpoint_digest
            .ok_or("MCSEALED-PRIVATE-RELEASE: terminal-join checkpoint digest absent")?,
        execution_record_digest: record.record_digest,
        target: checkpoint.target,
        network_namespace_inode: checkpoint.network_namespace_inode,
        filter_sha256: checkpoint.filter_sha256,
        execution_record_bytes: bytes.to_vec(),
    })
}

pub(crate) fn read_checkpoint_gate_candidate_journal(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<CheckpointGateCandidateReadbackV1, String> {
    let (_, bytes) = read_record_in(directory, 0)?;
    parse_checkpoint_gate_candidate_journal_bytes(&bytes, expected)
}

pub(crate) fn parse_checkpoint_gate_candidate_journal_bytes(
    bytes: &[u8],
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<CheckpointGateCandidateReadbackV1, String> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate journal bound differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let record: ReleaseCandidateAttemptRecordV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    record.validate()?;
    if expected.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR
        || record.selector != expected.selector
        || record.phase != PrivateAttemptPhase::ReleaseIntent
        || record.release_knowledge != ReleaseKnowledge::PossiblyReleased
        || record.cleanup_error.is_some()
        || record.candidate_exit_code.is_some()
        || &record.result_key != expected.result_key
        || record.challenge_sha256 != hash_bytes(expected.challenge)
        || &record.installation_epoch != expected.installation_epoch
        || &record.candidate_manifest_sha256 != expected.candidate_manifest_sha256
        || &record.service_generation_sha256 != expected.service_generation_sha256
        || &record.coordinator != expected.coordinator
        || record.frontend_proxy.is_some()
        || record.encode()? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate intent differs".into());
    }
    Ok(CheckpointGateCandidateReadbackV1 {
        attempt_id: record.attempt_id,
        checkpoint_digest: record
            .checkpoint_digest
            .expect("release intent retains checkpoint"),
        release_intent_record_digest: record.record_digest,
        target: record.target.expect("release intent retains gated target"),
        release_intent_bytes: bytes.to_vec(),
    })
}

pub(crate) struct ReadbackBlockedCandidateAttemptV1 {
    pub(crate) journal: ReadbackRetiredCandidateAttemptV1,
    pub(crate) fault_marker_bytes: Vec<u8>,
    pub(crate) detached_reuse_error: String,
}

#[allow(dead_code)] // Consumed by the detached retirement-fault verifier.
pub(crate) fn read_blocked_retirement_candidate_journal(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<ReadbackBlockedCandidateAttemptV1, String> {
    let (record, bytes) = read_record_in(directory, 0)?;
    if expected.selector != "private_tcp::retirement_failure_blocks_reuse"
        || record.selector != expected.selector
        || record.phase != PrivateAttemptPhase::Retiring
        || record.release_knowledge != ReleaseKnowledge::ExecObserved
        || record.cleanup_error.is_some()
        || record.candidate_exit_code.is_some()
        || &record.result_key != expected.result_key
        || record.challenge_sha256 != hash_bytes(expected.challenge)
        || &record.installation_epoch != expected.installation_epoch
        || &record.candidate_manifest_sha256 != expected.candidate_manifest_sha256
        || &record.service_generation_sha256 != expected.service_generation_sha256
        || &record.coordinator != expected.coordinator
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked retirement context differs".into());
    }
    let (marker, marker_bytes) = read_fault_marker_in(directory, 0)?;
    if marker != RetirementTransitionFaultMarkerV1::for_record(&record)? {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked retirement marker differs".into());
    }
    require_exclusive_temp_collision(directory)?;
    let detached_reuse_error = DurableReleaseCandidateAttemptV1::allocate(
        directory.try_clone().map_err(|error| error.to_string())?,
        record.result_key.clone(),
        &record.selector,
        expected.challenge,
        record.installation_epoch.clone(),
        record.candidate_manifest_sha256.clone(),
        record.service_generation_sha256.clone(),
        record.coordinator.clone(),
    )
    .err()
    .ok_or("MCSEALED-PRIVATE-RELEASE: detached same-key allocator succeeded")?;
    if read_record_in(directory, 0)?.1 != bytes
        || read_fault_marker_in(directory, 0)?.1 != marker_bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked retirement evidence changed".into());
    }
    Ok(ReadbackBlockedCandidateAttemptV1 {
        journal: ReadbackRetiredCandidateAttemptV1 {
            attempt_id: record.attempt_id,
            checkpoint_digest: record
                .checkpoint_digest
                .expect("retiring record retains checkpoint"),
            terminal_record_digest: record.record_digest,
            terminal_bytes: bytes,
        },
        fault_marker_bytes: marker_bytes,
        detached_reuse_error,
    })
}

pub(crate) struct RetiredCandidateNativeIdentitiesV1 {
    pub(crate) frontend_proxy: Option<ProcessIdentityV4>,
    pub(crate) guardian: ProcessIdentityV4,
    pub(crate) namespace_init: ProcessIdentityV4,
    pub(crate) target: ProcessIdentityV4,
    pub(crate) network_namespace_inode: u64,
    pub(crate) candidate_exit_code: Option<i32>,
}

impl ReadbackRetiredCandidateAttemptV1 {
    pub(crate) fn filter_digest(&self) -> Result<DiagnosticSha256, String> {
        memcordon_core::workload_contract::reject_duplicate_json_keys(&self.terminal_bytes)?;
        let record: ReleaseCandidateAttemptRecordV1 =
            serde_json::from_slice(&self.terminal_bytes).map_err(|error| error.to_string())?;
        record.validate()?;
        if record.phase != PrivateAttemptPhase::Retired
            || record.attempt_id != self.attempt_id
            || record.checkpoint_digest.as_ref() != Some(&self.checkpoint_digest)
            || record.record_digest != self.terminal_record_digest
            || record.encode()? != self.terminal_bytes
        {
            return Err("MCSEALED-PRIVATE-RELEASE: filter journal differs".into());
        }
        Ok(record
            .checkpoint_binding
            .ok_or("MCSEALED-PRIVATE-RELEASE: filter checkpoint absent")?
            .filter_sha256)
    }

    pub(crate) fn native_identities(&self) -> Result<RetiredCandidateNativeIdentitiesV1, String> {
        memcordon_core::workload_contract::reject_duplicate_json_keys(&self.terminal_bytes)?;
        let record: ReleaseCandidateAttemptRecordV1 =
            serde_json::from_slice(&self.terminal_bytes).map_err(|error| error.to_string())?;
        record.validate()?;
        if record.phase != PrivateAttemptPhase::Retired
            || record.attempt_id != self.attempt_id
            || record.checkpoint_digest.as_ref() != Some(&self.checkpoint_digest)
            || record.record_digest != self.terminal_record_digest
            || record.encode()? != self.terminal_bytes
        {
            return Err("MCSEALED-PRIVATE-RELEASE: native identity journal differs".into());
        }
        let checkpoint = record
            .checkpoint_binding
            .ok_or("MCSEALED-PRIVATE-RELEASE: native identity checkpoint absent")?;
        Ok(RetiredCandidateNativeIdentitiesV1 {
            frontend_proxy: record.frontend_proxy,
            guardian: checkpoint.guardian,
            namespace_init: checkpoint.namespace_init,
            target: checkpoint.target,
            network_namespace_inode: checkpoint.network_namespace_inode,
            candidate_exit_code: record.candidate_exit_code,
        })
    }
}

impl ReadbackBlockedCandidateAttemptV1 {
    #[allow(dead_code)] // Used by the detached retirement-fault reader.
    pub(crate) fn native_identities(&self) -> Result<RetiredCandidateNativeIdentitiesV1, String> {
        memcordon_core::workload_contract::reject_duplicate_json_keys(
            &self.journal.terminal_bytes,
        )?;
        let record: ReleaseCandidateAttemptRecordV1 =
            serde_json::from_slice(&self.journal.terminal_bytes)
                .map_err(|error| error.to_string())?;
        record.validate()?;
        if record.phase != PrivateAttemptPhase::Retiring
            || record.release_knowledge != ReleaseKnowledge::ExecObserved
            || record.attempt_id != self.journal.attempt_id
            || record.checkpoint_digest.as_ref() != Some(&self.journal.checkpoint_digest)
            || record.record_digest != self.journal.terminal_record_digest
            || record.encode()? != self.journal.terminal_bytes
        {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked native identity differs".into());
        }
        let checkpoint = record
            .checkpoint_binding
            .ok_or("MCSEALED-PRIVATE-RELEASE: blocked native checkpoint absent")?;
        Ok(RetiredCandidateNativeIdentitiesV1 {
            frontend_proxy: record.frontend_proxy,
            guardian: checkpoint.guardian,
            namespace_init: checkpoint.namespace_init,
            target: checkpoint.target,
            network_namespace_inode: checkpoint.network_namespace_inode,
            candidate_exit_code: record.candidate_exit_code,
        })
    }
}

pub(crate) fn read_retired_candidate_journal(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<ReadbackRetiredCandidateAttemptV1, String> {
    let (record, bytes) = read_record_in(directory, 0)?;
    if record.phase != PrivateAttemptPhase::Retired
        || record.release_knowledge != ReleaseKnowledge::ExecObserved
        || record.cleanup_error.is_some()
        || record.candidate_exit_code != Some(0)
        || &record.result_key != expected.result_key
        || record.selector != expected.selector
        || record.challenge_sha256 != hash_bytes(expected.challenge)
        || &record.installation_epoch != expected.installation_epoch
        || &record.candidate_manifest_sha256 != expected.candidate_manifest_sha256
        || &record.service_generation_sha256 != expected.service_generation_sha256
        || &record.coordinator != expected.coordinator
    {
        return Err("MCSEALED-PRIVATE-RELEASE: retired attempt context differs".into());
    }
    let checkpoint_digest = record
        .checkpoint_digest
        .ok_or("MCSEALED-PRIVATE-RELEASE: retired checkpoint absent")?;
    Ok(ReadbackRetiredCandidateAttemptV1 {
        attempt_id: record.attempt_id,
        checkpoint_digest,
        terminal_record_digest: record.record_digest,
        terminal_bytes: bytes,
    })
}

/// Reads only the fixed transport-loss branch. A retired journal here records
/// conservative release knowledge; it does not establish independent kernel
/// retirement or authorize a release qualification by itself.
pub(crate) fn read_retired_uncertain_candidate_journal(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<ReadbackRetiredCandidateAttemptV1, String> {
    let (record, bytes) = read_record_in(directory, 0)?;
    if expected.selector != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
        || record.selector != expected.selector
        || record.phase != PrivateAttemptPhase::Retired
        || record.release_knowledge != ReleaseKnowledge::PossiblyReleased
        || record.cleanup_error.is_some()
        || record.candidate_exit_code == Some(0)
        || &record.result_key != expected.result_key
        || record.challenge_sha256 != hash_bytes(expected.challenge)
        || &record.installation_epoch != expected.installation_epoch
        || &record.candidate_manifest_sha256 != expected.candidate_manifest_sha256
        || &record.service_generation_sha256 != expected.service_generation_sha256
        || &record.coordinator != expected.coordinator
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain retired attempt context differs".into());
    }
    let checkpoint_digest = record
        .checkpoint_digest
        .ok_or("MCSEALED-PRIVATE-RELEASE: uncertain retired checkpoint absent")?;
    Ok(ReadbackRetiredCandidateAttemptV1 {
        attempt_id: record.attempt_id,
        checkpoint_digest,
        terminal_record_digest: record.record_digest,
        terminal_bytes: bytes,
    })
}

/// Journal-only guardian-loss readback. The detached finalizer must separately
/// corroborate the exact guardian/target/init exits and absent cgroup, then
/// join the bounded physical settlement attachment before publication.
#[allow(dead_code)] // Detached guardian-loss finalizer is not connected yet.
pub(crate) fn read_retired_guardian_loss_candidate_journal(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<ReadbackRetiredCandidateAttemptV1, String> {
    let (record, bytes) = read_record_in(directory, 0)?;
    if expected.selector != super::private_release_guardian_loss::SELECTOR
        || record.selector != expected.selector
        || record.phase != PrivateAttemptPhase::Retired
        || record.release_knowledge != ReleaseKnowledge::ExecObserved
        || record.cleanup_error.is_some()
        || record.candidate_exit_code == Some(0)
        || &record.result_key != expected.result_key
        || record.challenge_sha256 != hash_bytes(expected.challenge)
        || &record.installation_epoch != expected.installation_epoch
        || &record.candidate_manifest_sha256 != expected.candidate_manifest_sha256
        || &record.service_generation_sha256 != expected.service_generation_sha256
        || &record.coordinator != expected.coordinator
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss retired attempt differs".into());
    }
    Ok(ReadbackRetiredCandidateAttemptV1 {
        attempt_id: record.attempt_id,
        checkpoint_digest: record
            .checkpoint_digest
            .expect("retired guardian loss retains checkpoint"),
        terminal_record_digest: record.record_digest,
        terminal_bytes: bytes,
    })
}

pub(crate) fn read_retired_frontend_loss_candidate_journal(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<ReadbackRetiredCandidateAttemptV1, String> {
    let (record, bytes) = read_record_in(directory, 0)?;
    if expected.selector != super::private_release_frontend_loss::SELECTOR
        || record.selector != expected.selector
        || record.phase != PrivateAttemptPhase::Retired
        || record.release_knowledge != ReleaseKnowledge::ExecObserved
        || record.cleanup_error.is_some()
        || record.candidate_exit_code == Some(0)
        || record.frontend_proxy.is_none()
        || &record.result_key != expected.result_key
        || record.challenge_sha256 != hash_bytes(expected.challenge)
        || &record.installation_epoch != expected.installation_epoch
        || &record.candidate_manifest_sha256 != expected.candidate_manifest_sha256
        || &record.service_generation_sha256 != expected.service_generation_sha256
        || &record.coordinator != expected.coordinator
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss retired attempt differs".into());
    }
    Ok(ReadbackRetiredCandidateAttemptV1 {
        attempt_id: record.attempt_id,
        checkpoint_digest: record
            .checkpoint_digest
            .expect("retired frontend loss retains checkpoint"),
        terminal_record_digest: record.record_digest,
        terminal_bytes: bytes,
    })
}

impl ReleaseCandidatePermitV1 {
    pub(crate) fn send(
        self,
        control: &mut File,
        attempt_id: &str,
        checkpoint_digest: &DiagnosticSha256,
    ) -> Result<(), String> {
        if self.attempt_id != attempt_id || &self.checkpoint_digest != checkpoint_digest {
            return Err("MCSEALED-PRIVATE-RELEASE: release permit binding differs".into());
        }
        super::private_attempt::send_private_release_byte(control)
    }

    pub(crate) fn force_transport_loss(
        self,
        control: &mut File,
        attempt_id: &str,
        checkpoint_digest: &DiagnosticSha256,
    ) -> Result<i32, String> {
        if self.attempt_id != attempt_id || &self.checkpoint_digest != checkpoint_digest {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertainty permit binding differs".into());
        }
        // SAFETY: control is the retained target SOCK_SEQPACKET descriptor.
        // SHUT_WR forces the subsequent one-byte release attempt to fail; the
        // durable record already says PossiblyReleased and is never reset.
        if unsafe { libc::shutdown(control.as_raw_fd(), libc::SHUT_WR) } != 0 {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE: fault shutdown: {}",
                std::io::Error::last_os_error()
            ));
        }
        let release = [1_u8];
        // SAFETY: release is one live byte, and MSG_NOSIGNAL prevents an
        // injected EPIPE from terminating the supervising service process.
        let sent = unsafe {
            libc::send(
                control.as_raw_fd(),
                release.as_ptr().cast(),
                release.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        if sent != -1 || errno != Some(libc::EPIPE) {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE: fault send result {sent} errno {errno:?} differs"
            ));
        }
        Ok(libc::EPIPE)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseCandidateAttemptRecordV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    selector: String,
    challenge_sha256: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    candidate_manifest_sha256: DiagnosticSha256,
    service_generation_sha256: DiagnosticSha256,
    attempt_id: String,
    coordinator: ProcessIdentityV4,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frontend_proxy: Option<ProcessIdentityV4>,
    phase: PrivateAttemptPhase,
    guardian: Option<ProcessIdentityV4>,
    namespace_init: Option<ProcessIdentityV4>,
    target: Option<ProcessIdentityV4>,
    network_namespace_inode: Option<u64>,
    checkpoint_digest: Option<DiagnosticSha256>,
    checkpoint_binding: Option<ReleaseCandidateCheckpointV1>,
    release_knowledge: ReleaseKnowledge,
    cleanup_error: Option<String>,
    candidate_exit_code: Option<i32>,
    record_digest: DiagnosticSha256,
}

impl ReleaseCandidateAttemptRecordV1 {
    fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        let mut canonical = self.clone();
        canonical.record_digest = DiagnosticSha256::from_bytes([0; 32]);
        Ok(hash_bytes(
            &serde_json::to_vec(&canonical).map_err(|error| error.to_string())?,
        ))
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
                .contains(&self.selector.as_str())
            || self.attempt_id != candidate_attempt_id(&self.result_key)
            || self.record_digest != self.canonical_digest()?
        {
            return Err("MCSEALED-PRIVATE-RELEASE: candidate attempt binding differs".into());
        }
        if (self.selector == super::private_release_frontend_loss::SELECTOR)
            != self.frontend_proxy.is_some()
            || self.frontend_proxy.as_ref() == Some(&self.coordinator)
            || self
                .frontend_proxy
                .as_ref()
                .is_some_and(|frontend| frontend.pid == 0 || frontend.start_time == 0)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend proxy binding differs".into());
        }
        let guardian = self.guardian.is_some();
        let target = self.namespace_init.is_some()
            && self.target.is_some()
            && self.network_namespace_inode.is_some_and(|inode| inode != 0);
        let no_target = self.namespace_init.is_none()
            && self.target.is_none()
            && self.network_namespace_inode.is_none();
        let checkpoint = self.checkpoint_binding.as_ref().is_some_and(|binding| {
            binding.digest().ok().as_ref() == self.checkpoint_digest.as_ref()
                && binding.schema_version == 1
                && binding.result_key == self.result_key
                && binding.selector == self.selector
                && binding.challenge_sha256 == self.challenge_sha256
                && binding.attempt_id == self.attempt_id
                && binding.installation_epoch == self.installation_epoch
                && binding.candidate_manifest_sha256 == self.candidate_manifest_sha256
                && binding.service_generation_sha256 == self.service_generation_sha256
                && self.guardian.as_ref() == Some(&binding.guardian)
                && self.namespace_init.as_ref() == Some(&binding.namespace_init)
                && self.target.as_ref() == Some(&binding.target)
                && self.network_namespace_inode == Some(binding.network_namespace_inode)
                && binding.network_namespace_inode != 0
                && binding.target_uid != 0
                && binding.target_gid != 0
        });
        let no_checkpoint = self.checkpoint_digest.is_none() && self.checkpoint_binding.is_none();
        let shape = match self.phase {
            PrivateAttemptPhase::Allocated | PrivateAttemptPhase::AuthorityFrozen => {
                !guardian
                    && no_target
                    && no_checkpoint
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            PrivateAttemptPhase::BoundaryCreated => {
                !guardian
                    && no_target
                    && no_checkpoint
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            PrivateAttemptPhase::GuardianReady => {
                guardian
                    && no_target
                    && no_checkpoint
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            PrivateAttemptPhase::TargetGated => {
                guardian
                    && target
                    && no_checkpoint
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            PrivateAttemptPhase::CheckpointCommitted => {
                guardian
                    && target
                    && checkpoint
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            PrivateAttemptPhase::ReleaseIntent => {
                guardian
                    && target
                    && checkpoint
                    && self.release_knowledge == ReleaseKnowledge::PossiblyReleased
            }
            PrivateAttemptPhase::ExecutionObserved => {
                guardian
                    && target
                    && checkpoint
                    && self.release_knowledge == ReleaseKnowledge::ExecObserved
            }
            // Retirement needs a later independent native settlement join.
            PrivateAttemptPhase::Retiring => {
                (self.release_knowledge == ReleaseKnowledge::NotReleased && no_checkpoint
                    || self.release_knowledge != ReleaseKnowledge::NotReleased && checkpoint)
                    && self.cleanup_error.is_none()
                    && self.candidate_exit_code.is_none()
            }
            PrivateAttemptPhase::Retired => {
                (self.release_knowledge == ReleaseKnowledge::ExecObserved
                    || self.selector
                        == super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
                        && self.release_knowledge == ReleaseKnowledge::PossiblyReleased
                        && self.candidate_exit_code != Some(0))
                    && checkpoint
                    && self.cleanup_error.is_none()
            }
            PrivateAttemptPhase::CleanupIncomplete => {
                self.cleanup_error.is_some()
                    && (self.release_knowledge == ReleaseKnowledge::NotReleased || checkpoint)
            }
        };
        if !shape
            || (self.phase != PrivateAttemptPhase::CleanupIncomplete
                && self.cleanup_error.is_some())
        {
            return Err("MCSEALED-PRIVATE-RELEASE: candidate attempt phase differs".into());
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("MCSEALED-PRIVATE-RELEASE: attempt record exceeds byte bound".into());
        }
        Ok(bytes)
    }
}

pub(crate) struct DurableReleaseCandidateAttemptV1 {
    directory: File,
    record: ReleaseCandidateAttemptRecordV1,
    owner_uid: u32,
}

impl DurableReleaseCandidateAttemptV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn allocate(
        directory: File,
        result_key: DiagnosticSha256,
        selector: &str,
        challenge: &[u8; 32],
        installation_epoch: DiagnosticSha256,
        candidate_manifest_sha256: DiagnosticSha256,
        service_generation_sha256: DiagnosticSha256,
        coordinator: ProcessIdentityV4,
    ) -> Result<Self, String> {
        Self::allocate_with_owner(
            directory,
            result_key,
            selector,
            challenge,
            installation_epoch,
            candidate_manifest_sha256,
            service_generation_sha256,
            coordinator,
            None,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn allocate_frontend_loss(
        directory: File,
        result_key: DiagnosticSha256,
        selector: &str,
        challenge: &[u8; 32],
        installation_epoch: DiagnosticSha256,
        candidate_manifest_sha256: DiagnosticSha256,
        service_generation_sha256: DiagnosticSha256,
        coordinator: ProcessIdentityV4,
        frontend_proxy: ProcessIdentityV4,
    ) -> Result<Self, String> {
        if selector != super::private_release_frontend_loss::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend allocator selector differs".into());
        }
        Self::allocate_with_owner(
            directory,
            result_key,
            selector,
            challenge,
            installation_epoch,
            candidate_manifest_sha256,
            service_generation_sha256,
            coordinator,
            Some(frontend_proxy),
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn allocate_with_owner(
        directory: File,
        result_key: DiagnosticSha256,
        selector: &str,
        challenge: &[u8; 32],
        installation_epoch: DiagnosticSha256,
        candidate_manifest_sha256: DiagnosticSha256,
        service_generation_sha256: DiagnosticSha256,
        coordinator: ProcessIdentityV4,
        frontend_proxy: Option<ProcessIdentityV4>,
        owner_uid: u32,
    ) -> Result<Self, String> {
        let metadata = directory.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.uid() != owner_uid || metadata.mode() & 0o777 != 0o700 {
            return Err("MCSEALED-PRIVATE-RELEASE: attempt directory protection differs".into());
        }
        let mut record = ReleaseCandidateAttemptRecordV1 {
            schema_version: 1,
            attempt_id: candidate_attempt_id(&result_key),
            result_key,
            selector: selector.to_owned(),
            challenge_sha256: hash_bytes(challenge),
            installation_epoch,
            candidate_manifest_sha256,
            service_generation_sha256,
            coordinator,
            frontend_proxy,
            phase: PrivateAttemptPhase::Allocated,
            guardian: None,
            namespace_init: None,
            target: None,
            network_namespace_inode: None,
            checkpoint_digest: None,
            checkpoint_binding: None,
            release_knowledge: ReleaseKnowledge::NotReleased,
            cleanup_error: None,
            candidate_exit_code: None,
            record_digest: DiagnosticSha256::from_bytes([0; 32]),
        };
        record.record_digest = record.canonical_digest()?;
        let owner = Self {
            directory,
            record,
            owner_uid,
        };
        owner.persist(&owner.record, true)?;
        Ok(owner)
    }

    pub(crate) fn freeze(&mut self) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::Allocated {
            return Err("MCSEALED-PRIVATE-RELEASE: attempt is not allocated".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::AuthorityFrozen;
        self.replace(next)
    }

    pub(crate) fn commit_checkpoint(
        &mut self,
        binding: ReleaseCandidateCheckpointV1,
    ) -> Result<DiagnosticSha256, String> {
        if self.record.phase != PrivateAttemptPhase::TargetGated {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint phase differs".into());
        }
        let digest = binding.digest()?;
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::CheckpointCommitted;
        next.checkpoint_digest = Some(digest.clone());
        next.checkpoint_binding = Some(binding);
        self.replace(next)?;
        Ok(digest)
    }

    pub(crate) fn release_intent(
        &mut self,
        digest: &DiagnosticSha256,
    ) -> Result<ReleaseCandidatePermitV1, String> {
        if self.record.phase != PrivateAttemptPhase::CheckpointCommitted
            || self.record.checkpoint_digest.as_ref() != Some(digest)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: release intent binding differs".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::ReleaseIntent;
        next.release_knowledge = ReleaseKnowledge::PossiblyReleased;
        self.replace(next)?;
        Ok(ReleaseCandidatePermitV1 {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest: digest.clone(),
        })
    }

    pub(crate) fn retired_after_native_cleanup(
        &mut self,
        settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
    ) -> Result<ReleaseCandidateRetirementObservationV1, String> {
        if self.record.phase != PrivateAttemptPhase::Retiring
            || self.record.release_knowledge != ReleaseKnowledge::ExecObserved
        {
            return Err("MCSEALED-PRIVATE-RELEASE: native retirement phase differs".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retired;
        next.candidate_exit_code = settlement.candidate_exit_code;
        self.replace(next)?;
        self.read_back()?;
        Ok(ReleaseCandidateRetirementObservationV1 {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest: self.record.checkpoint_digest.clone(),
            terminal_record_digest: self.record.record_digest.clone(),
            candidate_exit_code: settlement.candidate_exit_code,
            terminal_bytes: self.record.encode()?,
            settlement,
        })
    }

    /// Called only after the uncertainty owner has physically settled every
    /// resource. The durable state deliberately remains PossiblyReleased.
    #[allow(dead_code)] // The fault owner route is not connected yet.
    pub(crate) fn retired_after_uncertain_cleanup(
        &mut self,
        settlement: UncertainCandidateSettlementFactsV1,
    ) -> Result<UncertainCandidateRetirementObservationV1, String> {
        if self.record.selector != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
            || self.record.phase != PrivateAttemptPhase::Retiring
            || self.record.release_knowledge != ReleaseKnowledge::PossiblyReleased
            || settlement.schema_version != 1
            || settlement.transport_errno != libc::EPIPE
            || settlement.candidate_exit_code == Some(0)
            || !settlement.containment_removed
            || !settlement.target_pidfd_exited
            || !settlement.namespace_init_reaped
        {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain native retirement differs".into());
        }
        let terminal = super::private_guardian::GuardianTerminalV4::decode(
            settlement.guardian_terminal,
            candidate_attempt_bytes(&self.record.result_key),
        )?;
        if terminal.trigger != super::private_guardian::GuardianTriggerV4::Stopped
            || terminal.boundary_retired
        {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain guardian terminal differs".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retired;
        next.candidate_exit_code = settlement.candidate_exit_code;
        self.replace(next)?;
        self.read_back()?;
        Ok(UncertainCandidateRetirementObservationV1 {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest: self
                .record
                .checkpoint_digest
                .clone()
                .expect("retired uncertainty retains checkpoint"),
            terminal_record_digest: self.record.record_digest.clone(),
            terminal_bytes: self.record.encode()?,
            settlement,
        })
    }

    /// Only the fixed release-domain guardian-loss owner may turn an observed
    /// exec into this terminal. A zero target exit or a different guardian
    /// identity cannot be relabeled as guardian-loss settlement.
    #[allow(dead_code)] // Consumed by the distinct physical loss owner.
    pub(crate) fn retired_after_guardian_loss(
        &mut self,
        settlement: GuardianLossCandidateSettlementFactsV1,
    ) -> Result<GuardianLossCandidateRetirementObservationV1, String> {
        if self.record.selector != super::private_release_guardian_loss::SELECTOR
            || self.record.phase != PrivateAttemptPhase::Retiring
            || self.record.release_knowledge != ReleaseKnowledge::ExecObserved
            || settlement.schema_version != 1
            || self.record.guardian.as_ref() != Some(&settlement.guardian)
            || settlement.guardian_signal != libc::SIGKILL
            || !settlement.containment_removed
            || !settlement.target_pidfd_exited
            || !settlement.namespace_init_reaped
            || settlement.candidate_exit_code == Some(0)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss retirement differs".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retired;
        next.candidate_exit_code = settlement.candidate_exit_code;
        self.replace(next)?;
        self.read_back()?;
        Ok(GuardianLossCandidateRetirementObservationV1 {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest: self
                .record
                .checkpoint_digest
                .clone()
                .expect("retired guardian loss retains checkpoint"),
            terminal_record_digest: self.record.record_digest.clone(),
            terminal_bytes: self.record.encode()?,
            settlement,
        })
    }

    pub(crate) fn retired_after_frontend_loss(
        &mut self,
        settlement: FrontendLossCandidateSettlementFactsV1,
    ) -> Result<FrontendLossCandidateRetirementObservationV1, String> {
        let terminal = super::private_guardian::GuardianTerminalV4::decode(
            settlement.guardian_terminal,
            candidate_attempt_bytes(&self.record.result_key),
        )?;
        if self.record.selector != super::private_release_frontend_loss::SELECTOR
            || self.record.phase != PrivateAttemptPhase::Retiring
            || self.record.release_knowledge != ReleaseKnowledge::ExecObserved
            || settlement.schema_version != 1
            || self.record.frontend_proxy.as_ref() != Some(&settlement.frontend)
            || settlement.frontend_signal != libc::SIGKILL
            || terminal.trigger != super::private_guardian::GuardianTriggerV4::FrontendLost
            || !terminal.boundary_retired
            || !settlement.containment_removed
            || !settlement.target_pidfd_exited
            || !settlement.namespace_init_reaped
            || settlement.candidate_exit_code == Some(0)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss retirement differs".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retired;
        next.candidate_exit_code = settlement.candidate_exit_code;
        self.replace(next)?;
        self.read_back()?;
        Ok(FrontendLossCandidateRetirementObservationV1 {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest: self
                .record
                .checkpoint_digest
                .clone()
                .expect("retired frontend loss retains checkpoint"),
            terminal_record_digest: self.record.record_digest.clone(),
            terminal_bytes: self.record.encode()?,
            settlement,
        })
    }

    /// Injects a real O_EXCL collision at the canonical Retired transition.
    /// The canonical record remains Retiring/ExecObserved and is never
    /// promoted to a complete terminal. The same-key allocator must reject.
    #[allow(dead_code)] // Physical fault runner is not routed yet.
    pub(crate) fn force_retirement_transition_conflict(
        &mut self,
        challenge: &[u8; 32],
        settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
    ) -> Result<BlockedCandidateRetirementObservationV1, String> {
        if self.record.selector != "private_tcp::retirement_failure_blocks_reuse"
            || self.record.challenge_sha256 != hash_bytes(challenge)
            || self.record.phase != PrivateAttemptPhase::Retiring
            || self.record.release_knowledge != ReleaseKnowledge::ExecObserved
            || settlement.monitor_outcome
                != super::private_lifecycle::PrivateMonitorOutcome::Completed
            || !settlement.cgroup_empty_before_cleanup
            || !settlement.containment_removed
            || !settlement.target_pidfd_exited
            || !settlement.namespace_init_reaped
            || settlement.candidate_exit_code != Some(0)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: retirement fault prerequisites differ".into());
        }
        let guardian = super::private_guardian::GuardianTerminalV4::decode(
            settlement.guardian_terminal,
            candidate_attempt_bytes(&self.record.result_key),
        )?;
        if guardian.trigger != super::private_guardian::GuardianTriggerV4::Stopped
            || guardian.boundary_retired
        {
            return Err("MCSEALED-PRIVATE-RELEASE: retirement fault guardian differs".into());
        }
        self.read_back()?;
        let marker = RetirementTransitionFaultMarkerV1::for_record(&self.record)?;
        let marker_bytes = write_fault_marker_in(&self.directory, &marker, self.owner_uid)?;
        require_exclusive_temp_collision(&self.directory)?;
        let transition_error = self
            .retired_after_native_cleanup(settlement.clone())
            .err()
            .ok_or("MCSEALED-PRIVATE-RELEASE: injected retirement unexpectedly succeeded")?;
        if !transition_error.starts_with("MCSEALED-PRIVATE-RELEASE: attempt transition blocked:") {
            return Err("MCSEALED-PRIVATE-RELEASE: wrong retirement failure phase".into());
        }
        require_exclusive_temp_collision(&self.directory)?;
        self.read_back()?;
        if self.record.phase != PrivateAttemptPhase::Retiring
            || self.record.release_knowledge != ReleaseKnowledge::ExecObserved
            || read_fault_marker_in(&self.directory, self.owner_uid)?.1 != marker_bytes
        {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked retirement state changed".into());
        }
        let reuse_error = Self::allocate_with_owner(
            self.directory
                .try_clone()
                .map_err(|error| error.to_string())?,
            self.record.result_key.clone(),
            &self.record.selector,
            challenge,
            self.record.installation_epoch.clone(),
            self.record.candidate_manifest_sha256.clone(),
            self.record.service_generation_sha256.clone(),
            self.record.coordinator.clone(),
            None,
            self.owner_uid,
        )
        .err()
        .ok_or("MCSEALED-PRIVATE-RELEASE: same-key allocator unexpectedly reused attempt")?;
        if read_fault_marker_in(&self.directory, self.owner_uid)?.1 != marker_bytes {
            return Err("MCSEALED-PRIVATE-RELEASE: reuse changed retirement marker".into());
        }
        Ok(BlockedCandidateRetirementObservationV1 {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest: self
                .record
                .checkpoint_digest
                .clone()
                .expect("retiring record retains checkpoint"),
            terminal_record_digest: self.record.record_digest.clone(),
            terminal_bytes: self.record.encode()?,
            fault_marker_bytes: marker_bytes,
            transition_error,
            reuse_error,
            settlement,
        })
    }

    pub(crate) fn read_back(&self) -> Result<ReleaseCandidateAttemptRecordV1, String> {
        let observed = self.read_back_file()?;
        if observed != self.record {
            return Err("MCSEALED-PRIVATE-RELEASE: attempt readback changed".into());
        }
        Ok(observed)
    }

    fn read_back_file(&self) -> Result<ReleaseCandidateAttemptRecordV1, String> {
        let (record, _) = read_record_in(&self.directory, self.owner_uid)?;
        Ok(record)
    }

    fn replace(&mut self, mut next: ReleaseCandidateAttemptRecordV1) -> Result<(), String> {
        self.read_back()?;
        next.record_digest = next.canonical_digest()?;
        self.persist(&next, false)?;
        self.record = next;
        Ok(())
    }

    fn persist(
        &self,
        record: &ReleaseCandidateAttemptRecordV1,
        initial: bool,
    ) -> Result<(), String> {
        let bytes = record.encode()?;
        let temporary = CString::new(TEMP_LEAF).expect("fixed release attempt temp leaf");
        let canonical = CString::new(RECORD_LEAF).expect("fixed release attempt leaf");
        // SAFETY: O_EXCL and O_NOFOLLOW protect the fixed temporary leaf.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE: attempt transition blocked: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat returned one owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        let flags = if initial { libc::RENAME_NOREPLACE } else { 0 };
        // SAFETY: both fixed leaves are relative to one pinned protected dir.
        let status = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                self.directory.as_raw_fd(),
                canonical.as_ptr(),
                flags,
            )
        };
        if status == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE: attempt transition rename: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.directory
            .sync_all()
            .map_err(|error| error.to_string())?;
        if self.read_back_file()? != *record {
            return Err("MCSEALED-PRIVATE-RELEASE: attempt transition readback differs".into());
        }
        Ok(())
    }
}

fn read_record_in(
    directory: &File,
    owner_uid: u32,
) -> Result<(ReleaseCandidateAttemptRecordV1, Vec<u8>), String> {
    let leaf = CString::new(RECORD_LEAF).expect("fixed release attempt leaf");
    // SAFETY: the fixed leaf is resolved only below the retained directory.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: attempt readback open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_RECORD_BYTES as u64
    {
        return Err("MCSEALED-PRIVATE-RELEASE: attempt readback protection differs".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let observed: ReleaseCandidateAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    observed.validate()?;
    if observed.encode()? != bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: attempt canonical bytes differ".into());
    }
    Ok((observed, bytes))
}

fn require_exclusive_temp_collision(directory: &File) -> Result<(), String> {
    let temporary = CString::new(TEMP_LEAF).expect("fixed release attempt temp leaf");
    // SAFETY: the fixed leaf is resolved beneath the pinned protected case
    // directory. A successful open is never accepted as fault evidence.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd >= 0 {
        // SAFETY: the unexpected successful open returned one owned fd.
        unsafe { libc::close(fd) };
        return Err("MCSEALED-PRIVATE-RELEASE: retirement temp did not block O_EXCL".into());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EEXIST) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: retirement temp errno differs: {error}"
        ));
    }
    Ok(())
}

fn write_fault_marker_in(
    directory: &File,
    marker: &RetirementTransitionFaultMarkerV1,
    owner_uid: u32,
) -> Result<Vec<u8>, String> {
    let bytes = marker.encode()?;
    let leaf = CString::new(TEMP_LEAF).expect("fixed retirement fault leaf");
    // SAFETY: O_EXCL and O_NOFOLLOW target one fixed leaf under a pinned dir.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: retirement fault marker create: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat transferred one owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    directory.sync_all().map_err(|error| error.to_string())?;
    if read_fault_marker_in(directory, owner_uid)?.1 != bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: retirement marker readback changed".into());
    }
    Ok(bytes)
}

fn read_fault_marker_in(
    directory: &File,
    owner_uid: u32,
) -> Result<(RetirementTransitionFaultMarkerV1, Vec<u8>), String> {
    let leaf = CString::new(TEMP_LEAF).expect("fixed retirement fault leaf");
    // SAFETY: the fixed leaf is opened only beneath the pinned directory.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: retirement marker open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat transferred one owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_FAULT_MARKER_BYTES as u64
    {
        return Err("MCSEALED-PRIVATE-RELEASE: retirement marker protection differs".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FAULT_MARKER_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let marker: RetirementTransitionFaultMarkerV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if marker.schema_version != 1
        || marker.transition != "retired-transition-blocked"
        || marker.encode()? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: retirement marker content differs".into());
    }
    Ok((marker, bytes))
}

impl PrivateNativeJournal for DurableReleaseCandidateAttemptV1 {
    fn phase(&self) -> PrivateAttemptPhase {
        self.record.phase
    }
    fn read_back_native(&self) -> Result<(), String> {
        self.read_back().map(|_| ())
    }
    fn attempt_id(&self) -> &str {
        &self.record.attempt_id
    }
    fn frontend(&self) -> &ProcessIdentityV4 {
        self.record
            .frontend_proxy
            .as_ref()
            .unwrap_or(&self.record.coordinator)
    }
    fn target(&self) -> Option<&ProcessIdentityV4> {
        self.record.target.as_ref()
    }
    fn namespace_init(&self) -> Option<&ProcessIdentityV4> {
        self.record.namespace_init.as_ref()
    }
    fn network_namespace_inode(&self) -> Option<u64> {
        self.record.network_namespace_inode
    }
    fn possibly_released(&self) -> bool {
        self.record.release_knowledge != ReleaseKnowledge::NotReleased
    }

    fn boundary_created(&mut self) -> Result<(), String> {
        self.advance(
            PrivateAttemptPhase::AuthorityFrozen,
            PrivateAttemptPhase::BoundaryCreated,
        )
    }
    fn guardian_ready(&mut self, guardian: ProcessIdentityV4) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::BoundaryCreated {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian phase differs".into());
        }
        let mut next = self.record.clone();
        next.guardian = Some(guardian);
        next.phase = PrivateAttemptPhase::GuardianReady;
        self.replace(next)
    }
    fn target_gated(
        &mut self,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
    ) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::GuardianReady || network_namespace_inode == 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: target phase differs".into());
        }
        let mut next = self.record.clone();
        next.namespace_init = Some(namespace_init);
        next.target = Some(target);
        next.network_namespace_inode = Some(network_namespace_inode);
        next.phase = PrivateAttemptPhase::TargetGated;
        self.replace(next)
    }
    fn execution_observed(&mut self) -> Result<(), String> {
        if self.record.phase != PrivateAttemptPhase::ReleaseIntent {
            return Err("MCSEALED-PRIVATE-RELEASE: execution phase differs".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::ExecutionObserved;
        next.release_knowledge = ReleaseKnowledge::ExecObserved;
        self.replace(next)
    }
    fn retiring(&mut self) -> Result<(), String> {
        if matches!(
            self.record.phase,
            PrivateAttemptPhase::Retired
                | PrivateAttemptPhase::Retiring
                | PrivateAttemptPhase::CleanupIncomplete
        ) {
            return Err("MCSEALED-PRIVATE-RELEASE: attempt already terminal".into());
        }
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::Retiring;
        self.replace(next)
    }
    fn cleanup_incomplete(&mut self, detail: &str) -> Result<(), String> {
        let mut next = self.record.clone();
        next.phase = PrivateAttemptPhase::CleanupIncomplete;
        next.cleanup_error = Some(detail.to_owned());
        self.replace(next)
    }
}

impl DurableReleaseCandidateAttemptV1 {
    fn advance(
        &mut self,
        expected: PrivateAttemptPhase,
        next_phase: PrivateAttemptPhase,
    ) -> Result<(), String> {
        if self.record.phase != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: attempt transition differs".into());
        }
        let mut next = self.record.clone();
        next.phase = next_phase;
        self.replace(next)
    }
}

pub(super) fn candidate_attempt_id(result_key: &DiagnosticSha256) -> String {
    candidate_attempt_bytes(result_key)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn candidate_attempt_bytes(result_key: &DiagnosticSha256) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-candidate-attempt-v1\0");
    digest.update(result_key.bytes());
    let hash = digest.finalize();
    let mut attempt = [0_u8; 16];
    let length = attempt.len();
    attempt.copy_from_slice(&hash[..length]);
    attempt
}

#[cfg(feature = "test-support")]
pub(crate) fn permit_for_transport_fault_test(
    attempt_id: String,
    checkpoint_digest: DiagnosticSha256,
) -> ReleaseCandidatePermitV1 {
    ReleaseCandidatePermitV1 {
        attempt_id,
        checkpoint_digest,
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn commit_checkpoint_for_test(
    journal: &mut DurableReleaseCandidateAttemptV1,
) -> Result<DiagnosticSha256, String> {
    if journal.record.phase != PrivateAttemptPhase::TargetGated {
        return Err("MCSEALED-PRIVATE-RELEASE: test checkpoint phase differs".into());
    }
    let binding = ReleaseCandidateCheckpointV1 {
        schema_version: 1,
        result_key: journal.record.result_key.clone(),
        selector: journal.record.selector.clone(),
        challenge_sha256: journal.record.challenge_sha256.clone(),
        attempt_id: journal.record.attempt_id.clone(),
        installation_epoch: journal.record.installation_epoch.clone(),
        candidate_manifest_sha256: journal.record.candidate_manifest_sha256.clone(),
        service_generation_sha256: journal.record.service_generation_sha256.clone(),
        fixture_sha256: hash_bytes(b"unit fixture"),
        filter_sha256: hash_bytes(b"unit filter"),
        target_uid: 1000,
        target_gid: 1000,
        guardian: journal.record.guardian.clone().expect("test guardian"),
        namespace_init: journal.record.namespace_init.clone().expect("test init"),
        target: journal.record.target.clone().expect("test target"),
        network_namespace_inode: journal.record.network_namespace_inode.expect("test netns"),
        topology_sha256: hash_bytes(b"unit topology"),
        native_readback_sha256: hash_bytes(b"unit readback"),
    };
    let digest = journal.commit_checkpoint(binding)?;
    let _permit = journal.release_intent(&digest)?;
    Ok(digest)
}

#[cfg(feature = "test-support")]
pub(crate) fn allocate_for_test(
    directory: File,
    selector: &str,
) -> Result<DurableReleaseCandidateAttemptV1, String> {
    let owner_uid = directory
        .metadata()
        .map_err(|error| error.to_string())?
        .uid();
    DurableReleaseCandidateAttemptV1::allocate_with_owner(
        directory,
        hash_bytes(b"candidate release attempt test key"),
        selector,
        &[0x5a; 32],
        hash_bytes(b"candidate release attempt test epoch"),
        hash_bytes(b"candidate release attempt test M0"),
        hash_bytes(b"candidate release attempt test service"),
        ProcessIdentityV4 {
            pid: 123,
            start_time: 456,
        },
        None,
        owner_uid,
    )
}

#[cfg(feature = "test-support")]
pub(crate) fn allocate_frontend_loss_for_test(
    directory: File,
    frontend: ProcessIdentityV4,
) -> Result<DurableReleaseCandidateAttemptV1, String> {
    let owner_uid = directory
        .metadata()
        .map_err(|error| error.to_string())?
        .uid();
    DurableReleaseCandidateAttemptV1::allocate_with_owner(
        directory,
        hash_bytes(b"frontend loss candidate test key"),
        super::private_release_frontend_loss::SELECTOR,
        &[0x5a; 32],
        hash_bytes(b"frontend loss candidate test epoch"),
        hash_bytes(b"frontend loss candidate test M0"),
        hash_bytes(b"frontend loss candidate test service"),
        ProcessIdentityV4 {
            pid: 123,
            start_time: 456,
        },
        Some(frontend),
        owner_uid,
    )
}
