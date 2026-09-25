//! Separate candidate-only baseline UNIX probe through the baseline physical
//! owner. A pinned installed ELF, not the request pathname, reaches execveat.

use std::fs::File;
use std::io::{Read, Write};
use std::time::Instant;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::launch::{TargetExecStatus, TerminalFacts};
use super::private_probe_execution::nonblocking_pipe;
use super::private_qualification::{
    BaselineProbeObservationV1, ProbeCaseAuthority, ProbeFixtureKindV1,
};
use crate::request::{
    DeadlineScope, DescriptorPurpose, LaunchPolicyV2, LaunchRequestV2, Lifetime, SwapLimit,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BaselinePolicyObservationV1 {
    LegacyUnspecified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BaselineExecObservationV1 {
    Succeeded,
}

/// Typed protected producer observation. The independent reader checks this
/// exact projection and digest after reopening the root-owned completion; it
/// is still not a substitute for native producer provenance or an H1 receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BaselineTerminalProjectionV1 {
    pub(crate) attempt: [u8; 16],
    pub(crate) target_pid: u32,
    pub(crate) authorization_offset_millis: u64,
    pub(crate) child_status: Option<i32>,
    pub(crate) policy_enforcement: BaselinePolicyObservationV1,
    pub(crate) exec_status: BaselineExecObservationV1,
    pub(crate) policy_revoked: bool,
    pub(crate) spawn_error_reported: bool,
    pub(crate) cgroup_empty: bool,
    pub(crate) init_reaped: bool,
    pub(crate) guardian_reaped: bool,
    pub(crate) boundary_retired: bool,
    pub(crate) assignment_verified: bool,
    pub(crate) namespaces_verified: bool,
    pub(crate) target_initial_credentials_verified: bool,
    pub(crate) initial_provider_capabilities_absent: bool,
    pub(crate) caller_no_new_privs: bool,
    pub(crate) target_no_new_privs_matched: bool,
    pub(crate) target_capability_bounding_set_matched: bool,
    pub(crate) target_mount_context_derived_from_caller: bool,
    pub(crate) boundary_independent_of_credentials: bool,
    pub(crate) descriptors_verified: bool,
    pub(crate) writable_ancestor_cgroup_denied: bool,
    pub(crate) parent_namespace_handles_denied: bool,
    pub(crate) recursive_provider_request_denied: bool,
    pub(crate) guardian_ready_before_authorization: bool,
    pub(crate) frontend_loss_authority_verified: bool,
    pub(crate) cgroup_kill_invoked: bool,
    pub(crate) memory_limit_exceeded: bool,
    pub(crate) deadline_exceeded: bool,
    pub(crate) caller_envelope_digest: String,
    pub(crate) caller_capability_bounding_set_digest: String,
    pub(crate) caller_mount_namespace_digest: String,
}

impl BaselineTerminalProjectionV1 {
    pub(crate) fn from_verified_facts(
        attempt: [u8; 16],
        facts: &TerminalFacts,
    ) -> Result<Self, String> {
        verify_baseline_terminal(facts)?;
        Ok(Self {
            attempt,
            target_pid: facts.target_pid,
            authorization_offset_millis: facts.authorization_offset_millis,
            child_status: facts.child_status,
            policy_enforcement: BaselinePolicyObservationV1::LegacyUnspecified,
            exec_status: BaselineExecObservationV1::Succeeded,
            policy_revoked: facts.policy_revoked,
            spawn_error_reported: facts.spawn_error_reported,
            cgroup_empty: facts.cgroup_empty,
            init_reaped: facts.init_reaped,
            guardian_reaped: facts.guardian_reaped,
            boundary_retired: facts.boundary_retired,
            assignment_verified: facts.assignment_verified,
            namespaces_verified: facts.namespaces_verified,
            target_initial_credentials_verified: facts.target_initial_credentials_verified,
            initial_provider_capabilities_absent: facts.initial_provider_capabilities_absent,
            caller_no_new_privs: facts.caller_no_new_privs,
            target_no_new_privs_matched: facts.target_no_new_privs_matched,
            target_capability_bounding_set_matched: facts.target_capability_bounding_set_matched,
            target_mount_context_derived_from_caller: facts
                .target_mount_context_derived_from_caller,
            boundary_independent_of_credentials: facts.boundary_independent_of_credentials,
            descriptors_verified: facts.descriptors_verified,
            writable_ancestor_cgroup_denied: facts.writable_ancestor_cgroup_denied,
            parent_namespace_handles_denied: facts.parent_namespace_handles_denied,
            recursive_provider_request_denied: facts.recursive_provider_request_denied,
            guardian_ready_before_authorization: facts.guardian_ready_before_authorization,
            frontend_loss_authority_verified: facts.frontend_loss_authority_verified,
            cgroup_kill_invoked: facts.cgroup_kill_invoked,
            memory_limit_exceeded: facts.memory_limit_exceeded,
            deadline_exceeded: facts.deadline_exceeded,
            caller_envelope_digest: facts.caller_envelope_digest.clone(),
            caller_capability_bounding_set_digest: facts
                .caller_capability_bounding_set_digest
                .clone(),
            caller_mount_namespace_digest: facts.caller_mount_namespace_digest.clone(),
        })
    }

    pub(crate) fn validate_and_digest(&self) -> Result<DiagnosticSha256, String> {
        if self.target_pid == 0
            || self.child_status != Some(0)
            || self.policy_revoked
            || !self.spawn_error_reported
            || !self.cgroup_empty
            || !self.init_reaped
            || !self.guardian_reaped
            || !self.boundary_retired
            || !self.assignment_verified
            || !self.namespaces_verified
            || !self.target_initial_credentials_verified
            || !self.initial_provider_capabilities_absent
            || !self.target_no_new_privs_matched
            || !self.target_capability_bounding_set_matched
            || !self.target_mount_context_derived_from_caller
            || !self.boundary_independent_of_credentials
            || !self.descriptors_verified
            || !self.writable_ancestor_cgroup_denied
            || !self.parent_namespace_handles_denied
            || !self.recursive_provider_request_denied
            || !self.guardian_ready_before_authorization
            || !self.frontend_loss_authority_verified
            || !self.cgroup_kill_invoked
            || self.memory_limit_exceeded
            || self.deadline_exceeded
        {
            return Err(
                "MCSEALED-PROBE-BASELINE: terminal projection lacks native success or retirement"
                    .into(),
            );
        }
        for value in [
            &self.caller_envelope_digest,
            &self.caller_capability_bounding_set_digest,
            &self.caller_mount_namespace_digest,
        ] {
            let bounded = memcordon_core::BoundedText::<64>::new(value).map_err(str::to_owned)?;
            let _: DiagnosticSha256 = DiagnosticSha256::try_from(bounded).map_err(str::to_owned)?;
        }
        let mut digest = Sha256::new();
        digest.update(b"memcordon-baseline-probe-terminal-v1\0");
        digest.update(self.attempt);
        digest.update(self.target_pid.to_be_bytes());
        digest.update(self.authorization_offset_millis.to_be_bytes());
        digest.update(
            self.child_status
                .expect("validated baseline exit")
                .to_be_bytes(),
        );
        digest.update([1_u8, 1_u8]);
        for value in [
            self.policy_revoked,
            self.spawn_error_reported,
            self.cgroup_empty,
            self.init_reaped,
            self.guardian_reaped,
            self.boundary_retired,
            self.assignment_verified,
            self.namespaces_verified,
            self.target_initial_credentials_verified,
            self.initial_provider_capabilities_absent,
            self.caller_no_new_privs,
            self.target_no_new_privs_matched,
            self.target_capability_bounding_set_matched,
            self.target_mount_context_derived_from_caller,
            self.boundary_independent_of_credentials,
            self.descriptors_verified,
            self.writable_ancestor_cgroup_denied,
            self.parent_namespace_handles_denied,
            self.recursive_provider_request_denied,
            self.guardian_ready_before_authorization,
            self.frontend_loss_authority_verified,
            self.cgroup_kill_invoked,
            self.memory_limit_exceeded,
            self.deadline_exceeded,
        ] {
            digest.update([u8::from(value)]);
        }
        for value in [
            &self.caller_envelope_digest,
            &self.caller_capability_bounding_set_digest,
            &self.caller_mount_namespace_digest,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        Ok(DiagnosticSha256::from_bytes(digest.finalize().into()))
    }
}

/// The case's protected run lease must remain live throughout this call. A
/// successful return still depends on the independent completion readback;
/// raw TerminalFacts cannot themselves qualify or authorize an installed host.
pub(crate) fn execute_baseline_unix_fixture(
    case: &ProbeCaseAuthority<'_>,
) -> Result<BaselineProbeObservationV1, String> {
    if case.kind() != ProbeFixtureKindV1::BaselineUnixSuccessRetirement {
        return Err("MCSEALED-PROBE-BASELINE: wrong catalogue case".into());
    }
    case.revalidate()?;
    let remaining = case.deadline().saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("MCSEALED-PROBE-BASELINE: case deadline expired".into());
    }
    let budget_millis = u64::try_from(remaining.as_millis())
        .unwrap_or(u64::MAX)
        .min(30_000);
    let absolute_deadline_millis = super::clock::monotonic_millis()?
        .checked_add(budget_millis)
        .ok_or("MCSEALED-PROBE-BASELINE: deadline overflow")?;
    let entrypoint = case.pinned_fixture_entrypoint()?;
    let (uid, gid) = case.target_ids();
    let (stdin_read, stdin_write) = nonblocking_pipe()?;
    let (stdout_read, stdout_write) = nonblocking_pipe()?;
    let (stderr_read, stderr_write) = nonblocking_pipe()?;
    let challenge = case.challenge_bytes();
    let mut stdin_write = File::from(stdin_write);
    stdin_write
        .write_all(&challenge)
        .map_err(|error| format!("MCSEALED-PROBE-BASELINE: challenge write: {error}"))?;
    drop(stdin_write);
    let request = LaunchRequestV2 {
        restart_attempt: 0,
        workload_contract: None,
        // This is argv[0] only. The baseline owner executes the pinned image.
        program: b"memcordon-sealed-agent".to_vec(),
        arguments: vec![
            b"private-probe-fixture".to_vec(),
            case.name().as_bytes().to_vec(),
        ],
        environment: Vec::new(),
        policy: LaunchPolicyV2 {
            memory_limit_bytes: None,
            swap_limit: SwapLimit::Bytes(0),
            absolute_deadline_millis: Some(absolute_deadline_millis),
            deadline_scope: DeadlineScope::Attempt,
            lifetime: Lifetime::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 0,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
        descriptors: vec![
            DescriptorPurpose::CurrentDirectory,
            DescriptorPurpose::Stdin,
            DescriptorPurpose::Stdout,
            DescriptorPurpose::Stderr,
            DescriptorPurpose::FrontendLiveness,
        ],
    };
    let record = case.allocate_baseline_probe_record()?;
    let facts = super::launch::execute_pinned_probe_baseline(
        request,
        vec![
            case.work_directory()?.into(),
            stdin_read,
            stdout_write,
            stderr_write,
            case.duplicate_coordinator_pidfd()?,
        ],
        case.attempt_bytes(),
        case.coordinator_pid(),
        uid,
        gid,
        Vec::new(),
        record,
        entrypoint,
    )?;
    verify_baseline_terminal(&facts)?;
    let mut response = Vec::new();
    File::from(stdout_read)
        .take(challenge.len() as u64 + 1)
        .read_to_end(&mut response)
        .map_err(|error| format!("MCSEALED-PROBE-BASELINE: response read: {error}"))?;
    let mut stderr = Vec::new();
    File::from(stderr_read)
        .take(1025)
        .read_to_end(&mut stderr)
        .map_err(|error| format!("MCSEALED-PROBE-BASELINE: stderr read: {error}"))?;
    if response.as_slice() != case.expected_fixture_response() || !stderr.is_empty() {
        return Err("MCSEALED-PROBE-BASELINE: challenge response or stderr differs".into());
    }
    case.revalidate()?;
    let terminal_projection =
        BaselineTerminalProjectionV1::from_verified_facts(case.attempt_bytes(), &facts)?;
    let terminal_facts_sha256 = terminal_projection.validate_and_digest()?;
    if terminal_facts_sha256 != terminal_facts_digest(case.attempt_bytes(), &facts) {
        return Err(
            "MCSEALED-PROBE-BASELINE: typed terminal projection differs from native facts".into(),
        );
    }
    let observation = BaselineProbeObservationV1 {
        attempt_id: case
            .attempt_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        retired_record_digest: case.baseline_retired_record_digest()?,
        challenge_sha256: hash_bytes(&challenge),
        response_sha256: hash_bytes(&response),
        terminal_facts_sha256,
        terminal_projection,
    };
    case.persist_baseline_completion(&observation)?;
    Ok(observation)
}

pub(crate) fn verify_baseline_terminal(facts: &TerminalFacts) -> Result<(), String> {
    if facts.policy_enforcement
        != memcordon_core::workload_evidence::AttemptPolicyEnforcementV1::LegacyUnspecified
        || facts.child_status != Some(0)
        || facts.exec_status != TargetExecStatus::Succeeded
        || facts.policy_revoked
        || facts.memory_limit_exceeded
        || facts.deadline_exceeded
        || !facts.spawn_error_reported
        || !facts.cgroup_empty
        || !facts.init_reaped
        || !facts.guardian_reaped
        || !facts.boundary_retired
        || !facts.assignment_verified
        || !facts.namespaces_verified
        || !facts.target_initial_credentials_verified
        || !facts.initial_provider_capabilities_absent
        || !facts.target_no_new_privs_matched
        || !facts.target_capability_bounding_set_matched
        || !facts.target_mount_context_derived_from_caller
        || !facts.boundary_independent_of_credentials
        || !facts.descriptors_verified
        || !facts.writable_ancestor_cgroup_denied
        || !facts.parent_namespace_handles_denied
        || !facts.recursive_provider_request_denied
        || !facts.guardian_ready_before_authorization
        || !facts.frontend_loss_authority_verified
        || !facts.cgroup_kill_invoked
    {
        return Err("MCSEALED-PROBE-BASELINE: native terminal or retirement proof differs".into());
    }
    Ok(())
}

pub(crate) fn terminal_facts_digest(attempt: [u8; 16], facts: &TerminalFacts) -> DiagnosticSha256 {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-baseline-probe-terminal-v1\0");
    digest.update(attempt);
    digest.update(facts.target_pid.to_be_bytes());
    digest.update(facts.authorization_offset_millis.to_be_bytes());
    digest.update(
        facts
            .child_status
            .expect("verified baseline exit")
            .to_be_bytes(),
    );
    digest.update([u8::from(matches!(
        facts.policy_enforcement,
        memcordon_core::workload_evidence::AttemptPolicyEnforcementV1::LegacyUnspecified
    ))]);
    digest.update([u8::from(facts.exec_status == TargetExecStatus::Succeeded)]);
    for value in [
        facts.policy_revoked,
        facts.spawn_error_reported,
        facts.cgroup_empty,
        facts.init_reaped,
        facts.guardian_reaped,
        facts.boundary_retired,
        facts.assignment_verified,
        facts.namespaces_verified,
        facts.target_initial_credentials_verified,
        facts.initial_provider_capabilities_absent,
        facts.caller_no_new_privs,
        facts.target_no_new_privs_matched,
        facts.target_capability_bounding_set_matched,
        facts.target_mount_context_derived_from_caller,
        facts.boundary_independent_of_credentials,
        facts.descriptors_verified,
        facts.writable_ancestor_cgroup_denied,
        facts.parent_namespace_handles_denied,
        facts.recursive_provider_request_denied,
        facts.guardian_ready_before_authorization,
        facts.frontend_loss_authority_verified,
        facts.cgroup_kill_invoked,
        facts.memory_limit_exceeded,
        facts.deadline_exceeded,
    ] {
        digest.update([u8::from(value)]);
    }
    for value in [
        &facts.caller_envelope_digest,
        &facts.caller_capability_bounding_set_digest,
        &facts.caller_mount_namespace_digest,
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    DiagnosticSha256::from_bytes(digest.finalize().into())
}
