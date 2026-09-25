//! Durable pre-release gate witness for one fixed candidate selector. The
//! move-only release permit remains unsent until this protected leaf has been
//! fsynced, independently reopened, and joined to the live gated target.

use std::fs::File;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_lifecycle::{PrivateExecObservation, PrivateMonitorOutcome};
use super::private_release_attempt::{
    CheckpointGateCandidateReadbackV1, ReleaseCandidateReadbackExpectationV1,
};
use super::private_release_execution::CandidateNativeObservationV1;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointGateWitnessV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    release_intent_record_digest: DiagnosticSha256,
    release_intent_bytes: Vec<u8>,
    target: ProcessIdentityV4,
    target_pidfd_live: bool,
    control_event_absent: bool,
}

impl CheckpointGateWitnessV1 {
    pub(crate) fn persist(
        directory: &File,
        expected: &ReleaseCandidateReadbackExpectationV1<'_>,
        intent: CheckpointGateCandidateReadbackV1,
        observed_target: &ProcessIdentityV4,
    ) -> Result<Self, String> {
        if intent.target != *observed_target {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate target differs".into());
        }
        let witness = Self {
            schema_version: 1,
            selector: expected.selector.to_owned(),
            result_key: expected.result_key.clone(),
            attempt_id: intent.attempt_id,
            checkpoint_sha256: intent.checkpoint_digest,
            release_intent_record_digest: intent.release_intent_record_digest,
            release_intent_bytes: intent.release_intent_bytes,
            target: observed_target.clone(),
            target_pidfd_live: true,
            control_event_absent: true,
        };
        witness.validate(expected)?;
        let bytes = serde_json::to_vec(&witness).map_err(|error| error.to_string())?;
        if bytes.len()
            > memcordon_core::private_release_case_v1::MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1
                as usize
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate byte bound differs".into());
        }
        super::private_release_raw::persist_checkpoint_gate_leaf(directory, &bytes)?;
        if Self::readback(directory, expected)? != witness {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate readback differs".into());
        }
        Ok(witness)
    }

    pub(crate) fn readback(
        directory: &File,
        expected: &ReleaseCandidateReadbackExpectationV1<'_>,
    ) -> Result<Self, String> {
        let bytes = super::private_release_raw::read_checkpoint_gate_leaf(directory)?;
        if bytes.is_empty()
            || bytes.len()
                > memcordon_core::private_release_case_v1::MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1
                    as usize
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate byte bound differs".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
        let witness: Self = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        witness.validate(expected)?;
        if serde_json::to_vec(&witness).map_err(|error| error.to_string())? != bytes {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate encoding differs".into());
        }
        Ok(witness)
    }

    fn validate(&self, expected: &ReleaseCandidateReadbackExpectationV1<'_>) -> Result<(), String> {
        let intent = super::private_release_attempt::parse_checkpoint_gate_candidate_journal_bytes(
            &self.release_intent_bytes,
            expected,
        )?;
        if self.schema_version != 1
            || self.selector != expected.selector
            || &self.result_key != expected.result_key
            || self.attempt_id != intent.attempt_id
            || self.checkpoint_sha256 != intent.checkpoint_digest
            || self.release_intent_record_digest != intent.release_intent_record_digest
            || self.target != intent.target
            || !self.target_pidfd_live
            || !self.control_event_absent
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate witness differs".into());
        }
        Ok(())
    }

    pub(crate) fn checkpoint_digest(&self) -> &DiagnosticSha256 {
        &self.checkpoint_sha256
    }

    pub(crate) fn target(&self) -> &ProcessIdentityV4 {
        &self.target
    }

    pub(crate) fn digest(&self) -> Result<DiagnosticSha256, String> {
        Ok(memcordon_core::workload_codec::hash_bytes(
            &serde_json::to_vec(self).map_err(|error| error.to_string())?,
        ))
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn parse_witness_for_test(
    bytes: &[u8],
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<(), String> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let witness: CheckpointGateWitnessV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    witness.validate(expected)
}

pub(crate) struct CheckpointGateNativeObservationV1 {
    pub(crate) candidate: CandidateNativeObservationV1,
    pub(crate) gate_sha256: DiagnosticSha256,
}

/// Unlike an ordinary candidate TCP run, this owner holds the release permit
/// while another pinned-directory reader durably reopens ReleaseIntent and
/// observes the still-gated target/control endpoint. Only then may it send.
pub(crate) fn execute_checkpoint_gate_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<CheckpointGateNativeObservationV1, String> {
    if case.selector() != super::private_release_case::CHECKPOINT_GATE_SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate selector differs".into());
    }
    case.revalidate()?;
    let prelaunch = case.prepare_native_prelaunch()?;
    let (uid, gid) = case.target_ids()?;
    let identity = super::execution_identity::ResolvedTargetIdentity::for_probe_account(uid, gid)?;
    let abi = case.native_abi()?;
    let mount = File::open("/proc/self/ns/mnt")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: mount namespace: {error}"))?;
    let root = File::open("/")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: root descriptor: {error}"))?;
    let mount_metadata = mount.metadata().map_err(|error| error.to_string())?;
    let root_metadata = root.metadata().map_err(|error| error.to_string())?;
    let mount_context = super::namespace::CallerMountContext {
        mount_namespace: mount.into(),
        root: root.into(),
        mount_namespace_identity: NamespaceIdentity {
            device: mount_metadata.dev(),
            inode: mount_metadata.ino(),
        },
        root_identity: FileIdentity {
            device: root_metadata.dev(),
            inode: root_metadata.ino(),
        },
    };
    let work_directory = case.work_directory()?;
    let provider_namespace = super::network_profile::current_network_namespace()?;
    let worker_pidfd = super::private_execution::pidfd_for_self()?;
    let (stdin_read, stdin_write) = super::private_probe_execution::nonblocking_pipe()?;
    let (stdout_read, stdout_write) = super::private_probe_execution::nonblocking_pipe()?;
    let (stderr_read, stderr_write) = super::private_probe_execution::nonblocking_pipe()?;
    let challenge = case.challenge_bytes();
    File::from(stdin_write)
        .write_all(&challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: gate challenge pipe: {error}"))?;
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-RELEASE: gate startup deadline expired".into());
    }
    let run = (|| -> Result<_, String> {
        owner.create_boundary(None, SwapLimit::Host)?;
        owner.spawn_namespace(
            prelaunch,
            mount_context,
            work_directory.into(),
            provider_namespace,
            provider_namespace,
        )?;
        owner.start_guardian(
            case.attempt_bytes(),
            case.coordinator_pidfd(),
            worker_pidfd.as_fd(),
            startup_deadline,
        )?;
        let observed = owner.observe_gated_target(
            provider_namespace,
            provider_namespace,
            &identity,
            abi,
            *case.filter_digest().bytes(),
            startup_deadline,
        )?;
        let network_namespace_inode = observed.network_namespace_inode();
        owner.prepare_relay([stdin_read, stdout_write, stderr_write])?;
        let (checkpoint, permit) = owner.commit_checkpoint_gate_intent(observed, case)?;
        let gated_target = owner.observe_unsent_checkpoint_gate()?;
        let witness = case.persist_checkpoint_gate(&gated_target)?;
        if witness.checkpoint_digest() != &checkpoint {
            return Err("MCSEALED-PRIVATE-RELEASE: gate checkpoint changed".into());
        }
        let gate_sha256 = witness.digest()?;
        owner.send_checkpoint_gate_release(case, permit, &checkpoint, &gated_target)?;
        if !matches!(
            owner.observe_exec(startup_deadline)?,
            PrivateExecObservation::ArmedAndControlClosed
        ) {
            return Err("MCSEALED-PRIVATE-RELEASE: gate target failed native exec".into());
        }
        if owner.monitor_release_candidate(case)? != PrivateMonitorOutcome::Completed {
            return Err("MCSEALED-PRIVATE-RELEASE: gate monitor did not complete".into());
        }
        let expected = super::private_release_case::candidate_fixture_response(
            super::private_release_case::CHECKPOINT_GATE_SELECTOR,
            &challenge,
        );
        let response =
            super::private_probe_execution::read_bounded_pipe(stdout_read, expected.len() + 1)?;
        let stderr = super::private_probe_execution::read_bounded_pipe(stderr_read, 1025)?;
        if response != expected || !stderr.is_empty() {
            return Err("MCSEALED-PRIVATE-RELEASE: gate target response differs".into());
        }
        Ok((checkpoint, response, network_namespace_inode, gate_sha256))
    })();
    let retirement = owner.retire_release_candidate(Instant::now() + Duration::from_secs(30));
    let (checkpoint, response, network_namespace_inode, gate_sha256) = run?;
    let retirement = retirement?;
    if super::network_profile::current_network_namespace()? != provider_namespace
        || retirement.checkpoint_digest.as_ref() != Some(&checkpoint)
        || retirement.candidate_exit_code != Some(0)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: gate native retirement differs".into());
    }
    case.revalidate()?;
    Ok(CheckpointGateNativeObservationV1 {
        candidate: CandidateNativeObservationV1 {
            attempt_id: retirement.attempt_id,
            checkpoint_digest: checkpoint,
            terminal_record_digest: retirement.terminal_record_digest,
            challenge_sha256: memcordon_core::workload_codec::hash_bytes(&challenge),
            response_sha256: memcordon_core::workload_codec::hash_bytes(&response),
            candidate_exit_code: 0,
            response_bytes: response,
            network_namespace_inode,
            terminal_bytes: retirement.terminal_bytes,
            settlement: retirement.settlement,
            host_network_preservation: None,
            agent_path_preservation: None,
            unix_absence: None,
        },
        gate_sha256,
    })
}
