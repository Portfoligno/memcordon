//! Exact versioned fault transcript validation. Selector names choose expected
//! recipes, never outcomes: the durable phase, original response, trigger and
//! separate settlement determine actual knowledge and exec state.
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAllocatedOutcomeV1, PrivateReleaseExecV1, PrivateReleaseKnowledgeV1,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_evidence_v2::{PrivateTcpCheckpointV2, PrivateTcpRetiredV2};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultProcessV1 {
    pub pid: u32,
    pub start_time: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicFaultPlanV1 {
    DropAuthorizationAtDurableIntent,
    KillPinnedFrontendAtTargetLive,
    KillPinnedGuardianAtTargetLive,
}
impl PublicFaultPlanV1 {
    fn selector(self) -> &'static str {
        match self {
            Self::DropAuthorizationAtDurableIntent => {
                "private_tcp::authorization_uncertainty_retired"
            }
            Self::KillPinnedFrontendAtTargetLive => "private_tcp::frontend_loss_retired",
            Self::KillPinnedGuardianAtTargetLive => "private_tcp::guardian_loss_retired",
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultTriggerV1 {
    schema_version: u8,
    fault: PublicFaultPlanV1,
    attempt_id: String,
    result_key: DiagnosticSha256,
    request_sha256: DiagnosticSha256,
    checkpoint_sha256: DiagnosticSha256,
    victim: FaultProcessV1,
    target: FaultProcessV1,
    durable_attempt_bytes: Vec<u8>,
    target_tcp_bytes: Vec<u8>,
    target_socket_inodes: Vec<u64>,
    operation_errno: Option<i32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableFaultRecordV4 {
    attempt_id: String,
    boot_identity: String,
    frontend: FaultProcessV1,
    caller_envelope_digest: DiagnosticSha256,
    phase: String,
    release_knowledge: PrivateReleaseKnowledgeV1,
    admission: Option<serde_json::Value>,
    binding: Option<serde_json::Value>,
    guardian: Option<FaultProcessV1>,
    namespace_init: Option<FaultProcessV1>,
    target: Option<FaultProcessV1>,
    network_namespace_inode: Option<u64>,
    checkpoint: Option<PrivateTcpCheckpointV2>,
    checkpoint_digest: Option<DiagnosticSha256>,
    cleanup_error: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultFailureV1 {
    schema_version: u8,
    attempt_id: String,
    detail: String,
    possibly_released: bool,
    cleanup_complete: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultRetirementV1 {
    attempt_id: String,
    retired: Option<PrivateTcpRetiredV2>,
    candidate_exit_code: Option<i32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultRecoveryV1 {
    schema_version: u8,
    evidence_scope: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    original_incomplete_bytes: Vec<u8>,
    durable_attempt_record_absent: bool,
}

pub(crate) struct ValidatedPublicFaultV2 {
    pub(crate) outcome: PrivateReleaseAllocatedOutcomeV1,
    pub(crate) knowledge: PrivateReleaseKnowledgeV1,
    pub(crate) exec: PrivateReleaseExecV1,
    pub(crate) victim: FaultProcessV1,
    pub(crate) target: FaultProcessV1,
    pub(crate) trigger_sha256: DiagnosticSha256,
    pub(crate) failure_sha256: Option<DiagnosticSha256>,
    pub(crate) retirement_sha256: DiagnosticSha256,
    pub(crate) recovery_sha256: Option<DiagnosticSha256>,
    pub(crate) response_kind: u16,
    pub(crate) target_tcp_bytes: Vec<u8>,
    pub(crate) target_socket_inodes: Vec<u64>,
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    crate::private_observer_session::strict_json(bytes, 1024 * 1024)
}

pub(crate) fn validate_frontend_wait_checkpoint(
    bytes: &[u8],
    target: &FaultProcessV1,
    victim: &FaultProcessV1,
    boot: &str,
) -> Result<()> {
    let record: DurableFaultRecordV4 = parse(bytes)?;
    let checkpoint = record
        .checkpoint
        .as_ref()
        .ok_or_else(|| CiError::Message("frontend actual checkpoint absent".into()))?;
    checkpoint
        .validate()
        .map_err(|error| CiError::Message(error.into()))?;
    if record.phase != "execution-observed"
        || record.release_knowledge != PrivateReleaseKnowledgeV1::ExecObserved
        || record.frontend != *victim
        || record.target.as_ref() != Some(target)
        || record.boot_identity != boot
        || record.attempt_id.is_empty()
        || record.cleanup_error.is_some()
        || record.checkpoint_digest.as_ref()
            != Some(&checkpoint.canonical_digest().map_err(CiError::Message)?)
    {
        return fail("frontend actual execution checkpoint/victim/target/boot differs");
    }
    Ok(())
}

/// A derived raw carrier, never an authority token. The live observer must
/// retain the exact original provider record/leaves separately as well.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicRetirementRoleSourceV3 {
    pub(crate) schema_version: u8,
    pub(crate) provider_record: Vec<u8>,
    pub(crate) provider_leaves: BTreeMap<String, Vec<u8>>,
}

pub(crate) fn validate_public_terminal_states(
    checkpoint_bytes: &[u8],
    midpoint_bytes: &[u8],
    terminal_source_bytes: &[u8],
    key: &DiagnosticSha256,
    target: &FaultProcessV1,
    boot: &str,
) -> Result<()> {
    let checkpoint_record: DurableFaultRecordV4 = parse(checkpoint_bytes)?;
    let midpoint: DurableFaultRecordV4 = parse(midpoint_bytes)?;
    let source: PublicRetirementRoleSourceV3 =
        crate::private_observer_session::strict_json(terminal_source_bytes, 16 * 1024 * 1024)?;
    if source.schema_version != 3 {
        return fail("public terminal source schema differs");
    }
    let provider = crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
        &source.provider_record,
        &source.provider_leaves,
    )?;
    let provider_raw: serde_json::Value = parse(&source.provider_record)?;
    let [attempt] = provider.attempts.as_slice() else {
        return fail("public terminal exact attempt inventory differs");
    };
    let checkpoint = checkpoint_record
        .checkpoint
        .as_ref()
        .ok_or_else(|| CiError::Message("public terminal original checkpoint absent".into()))?;
    checkpoint
        .validate()
        .map_err(|message| CiError::Message(message.into()))?;
    let digest = checkpoint.canonical_digest().map_err(CiError::Message)?;
    let binding: memcordon_core::workload_admission_v2::AttemptBindingV2 = serde_json::from_value(
        checkpoint_record
            .binding
            .clone()
            .ok_or_else(|| CiError::Message("public terminal original binding absent".into()))?,
    )?;
    let terminal: memcordon_core::report_v11::PrivateExecutionReportV11 =
        parse(attempt.terminal_bytes.as_deref().ok_or_else(|| {
            CiError::Message("public terminal original authenticated response absent".into())
        })?)?;
    if provider.result_key != *key
        || provider_raw
            .get("selector")
            .and_then(serde_json::Value::as_str)
            != Some("private_tcp::release_checkpoint_terminal_joined")
        || provider.phase != "launch-exchanges-complete"
        || attempt.response_kind != 105
        || attempt.cleanup_bytes.is_none()
        || attempt.response_bytes
            != *attempt
                .terminal_bytes
                .as_ref()
                .expect("checked original terminal")
        || checkpoint_record.phase != "release-intent"
        || midpoint.phase != "execution-observed"
        || checkpoint_record.release_knowledge != PrivateReleaseKnowledgeV1::PossiblyReleased
        || midpoint.release_knowledge != PrivateReleaseKnowledgeV1::ExecObserved
        || [&checkpoint_record, &midpoint].iter().any(|record| {
            record.attempt_id != attempt.attempt_id
                || record.boot_identity != boot
                || record.target.as_ref() != Some(target)
                || record.checkpoint.as_ref() != Some(checkpoint)
                || record.checkpoint_digest.as_ref() != Some(&digest)
                || record.binding != checkpoint_record.binding
                || record.caller_envelope_digest != checkpoint_record.caller_envelope_digest
                || record.admission != checkpoint_record.admission
                || record.frontend != checkpoint_record.frontend
                || record.guardian != checkpoint_record.guardian
                || record.namespace_init != checkpoint_record.namespace_init
                || record.network_namespace_inode != checkpoint_record.network_namespace_inode
                || record.cleanup_error.is_some()
        })
        || checkpoint.attempt_binding != binding.canonical_digest().map_err(CiError::Message)?
        || binding.attempt_id.as_str() != attempt.attempt_id
        || terminal.schema_version != 11
        || terminal.attempt != binding
        || terminal.checkpoint != *checkpoint
        || !terminal.retirement.terminal_success(checkpoint)
        || terminal.outcome
            != (memcordon_core::report_v11::PrivateTerminalOutcomeV11::Exited { code: 0 })
        || attempt
            .phase_leaves
            .get("release-intent-v4.bin")
            .map(Vec::as_slice)
            != Some(checkpoint_bytes)
        || attempt
            .phase_leaves
            .get("execution-observed-v4.bin")
            .map(Vec::as_slice)
            != Some(midpoint_bytes)
    {
        return fail(
            "public checkpoint/held midpoint/authenticated terminal identity or knowledge differs",
        );
    }
    Ok(())
}

pub(crate) fn public_topology_checkpoint_init(
    provider: &crate::private_public_dispatch::StructuralProviderFrameReadbackV2,
    selector: &str,
    key: &DiagnosticSha256,
    boot: &str,
    filter: &DiagnosticSha256,
) -> Result<crate::private_candidate_network_facts::TopologyInitIdentityV1> {
    let raw: serde_json::Value = parse(&provider.record_bytes)?;
    let [attempt] = provider.attempts.as_slice() else {
        return fail("public topology requires one original allocated attempt");
    };
    let identity = attempt.target_identity.as_ref().ok_or_else(|| {
        CiError::Message("public topology original target identity absent".into())
    })?;
    let record: DurableFaultRecordV4 =
        parse(attempt.checkpoint_bytes.as_ref().ok_or_else(|| {
            CiError::Message("public topology committed checkpoint absent".into())
        })?)?;
    let checkpoint = record
        .checkpoint
        .as_ref()
        .ok_or_else(|| CiError::Message("public topology checkpoint body absent".into()))?;
    checkpoint
        .validate()
        .map_err(|error| CiError::Message(error.into()))?;
    let binding: memcordon_core::workload_admission_v2::AttemptBindingV2 =
        serde_json::from_value(record.binding.clone().ok_or_else(|| {
            CiError::Message("public topology original admission binding absent".into())
        })?)?;
    let init = record
        .namespace_init
        .as_ref()
        .ok_or_else(|| CiError::Message("public topology durable init role absent".into()))?;
    if provider.result_key != *key
        || raw.get("selector").and_then(serde_json::Value::as_str) != Some(selector)
        || record.phase != "checkpoint-committed"
        || record.attempt_id != attempt.attempt_id
        || record.boot_identity != boot
        || record.checkpoint_digest.as_ref()
            != Some(&checkpoint.canonical_digest().map_err(CiError::Message)?)
        || checkpoint.attempt_binding != binding.canonical_digest().map_err(CiError::Message)?
        || binding.attempt_id.as_str() != attempt.attempt_id
        || checkpoint.filter_digest != *filter
        || record.target.as_ref()
            != Some(&FaultProcessV1 {
                pid: identity.target.pid,
                start_time: identity.target.start_time,
            })
        || init.pid != identity.namespace_init.pid
        || init.start_time != identity.namespace_init.start_time
        || init.pid == 0
        || init.start_time == 0
        || record.network_namespace_inode != Some(identity.network_namespace_inode)
        || checkpoint
            .target_network_namespace
            .target_network_inode
            .get()
            != identity.network_namespace_inode
    {
        return fail("public topology original committed role/filter/binding/namespace differs");
    }
    Ok(
        crate::private_candidate_network_facts::TopologyInitIdentityV1 {
            pid: init.pid,
            start_time_ticks: init.start_time,
        },
    )
}

pub(crate) fn public_retirement_role_from_source(
    bytes: &[u8],
    key: &DiagnosticSha256,
    selector: &str,
    role: &str,
    pid: u32,
    boot: &str,
) -> Result<FaultProcessV1> {
    let source: PublicRetirementRoleSourceV3 =
        crate::private_observer_session::strict_json(bytes, 16 * 1024 * 1024)?;
    if source.schema_version != 3 || !matches!(role, "guardian" | "frontend") || pid == 0 {
        return fail("public retirement source role/schema differs");
    }
    let provider = crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
        &source.provider_record,
        &source.provider_leaves,
    )?;
    let raw: serde_json::Value = parse(&source.provider_record)?;
    if provider.result_key != *key
        || raw.get("selector").and_then(serde_json::Value::as_str) != Some(selector)
    {
        return fail("public retirement source belongs to another exact case");
    }
    let mut matched = Vec::new();
    for attempt in &provider.attempts {
        let bytes = attempt
            .phase_leaves
            .get("execution-observed-v4.bin")
            .or_else(|| attempt.phase_leaves.get("release-intent-v4.bin"))
            .or_else(|| attempt.phase_leaves.get("checkpoint-committed-v4.bin"))
            .ok_or_else(|| {
                CiError::Message("public retirement original durable checkpoint absent".into())
            })?;
        let record: DurableFaultRecordV4 = parse(bytes)?;
        let checkpoint = record
            .checkpoint
            .as_ref()
            .ok_or_else(|| CiError::Message("public retirement actual checkpoint absent".into()))?;
        checkpoint
            .validate()
            .map_err(|error| CiError::Message(error.into()))?;
        let binding: memcordon_core::workload_admission_v2::AttemptBindingV2 =
            serde_json::from_value(record.binding.clone().ok_or_else(|| {
                CiError::Message("public retirement actual binding absent".into())
            })?)?;
        if record.attempt_id != attempt.attempt_id
            || record.boot_identity != boot
            || !matches!(
                record.phase.as_str(),
                "checkpoint-committed" | "release-intent" | "execution-observed"
            )
            || record.checkpoint_digest.as_ref()
                != Some(&checkpoint.canonical_digest().map_err(CiError::Message)?)
            || checkpoint.attempt_binding != binding.canonical_digest().map_err(CiError::Message)?
            || binding.attempt_id.as_str() != record.attempt_id
        {
            return fail("public retirement durable checkpoint/binding/boot differs");
        }
        let identity = if role == "guardian" {
            record
                .guardian
                .ok_or_else(|| CiError::Message("public actual guardian identity absent".into()))?
        } else {
            record.frontend
        };
        if identity.pid == pid {
            if identity.start_time == 0
                || role == "frontend"
                    && (raw.get("peer_pid").and_then(serde_json::Value::as_u64)
                        != Some(u64::from(identity.pid))
                        || raw
                            .get("peer_start_time_ticks")
                            .and_then(serde_json::Value::as_u64)
                            != Some(identity.start_time))
            {
                return fail("public retirement held frontend/guardian identity differs");
            }
            matched.push(identity);
        }
    }
    if role == "frontend"
        && !matched.is_empty()
        && matched.iter().all(|identity| identity == &matched[0])
    {
        return Ok(matched.remove(0));
    }
    let [identity] = matched.as_slice() else {
        return fail("public retirement role identity is absent or ambiguous");
    };
    Ok(identity.clone())
}

/// Byte validation only; caller additionally proves target/victim lifecycle
/// from its own authenticated kernel interval and original-reader calibration.
pub(crate) fn validate_public_fault_attempt(
    selector: &str,
    key: &DiagnosticSha256,
    attempt_id: &str,
    phase: &str,
    request: &[u8],
    response: &[u8],
    response_kind: u16,
    checkpoint_bytes: &[u8],
    cleanup: &[u8],
    leaves: &BTreeMap<String, Vec<u8>>,
    expected_target: &FaultProcessV1,
    expected_boot: &str,
) -> Result<ValidatedPublicFaultV2> {
    let get = |name: &str| {
        leaves
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| CiError::Message("public fault exact phase leaf absent".into()))
    };
    let trigger_bytes = get("fault-trigger-v1.json")?;
    let trigger: FaultTriggerV1 = parse(trigger_bytes)?;
    let durable: DurableFaultRecordV4 = parse(&trigger.durable_attempt_bytes)?;
    let checkpoint_record: DurableFaultRecordV4 = parse(checkpoint_bytes)?;
    let checkpoint = checkpoint_record
        .checkpoint
        .as_ref()
        .ok_or_else(|| CiError::Message("fault durable checkpoint absent".into()))?;
    checkpoint
        .validate()
        .map_err(|error| CiError::Message(error.into()))?;
    let checkpoint_digest = checkpoint.canonical_digest().map_err(CiError::Message)?;
    if trigger.schema_version != 1
        || trigger.fault.selector() != selector
        || trigger.attempt_id != attempt_id
        || trigger.result_key != *key
        || trigger.request_sha256 != hash_bytes(request)
        || trigger.checkpoint_sha256 != checkpoint_digest
        || trigger.target != *expected_target
        || durable.attempt_id != attempt_id
        || durable.boot_identity != expected_boot
        || durable.target.as_ref() != Some(expected_target)
        || durable.checkpoint_digest.as_ref() != Some(&checkpoint_digest)
        || durable.checkpoint.as_ref() != Some(checkpoint)
        || checkpoint_record.attempt_id != attempt_id
        || checkpoint_record.boot_identity != expected_boot
        || checkpoint_record.target.as_ref() != Some(expected_target)
        || checkpoint_record.checkpoint_digest.as_ref() != Some(&checkpoint_digest)
    {
        return fail("public fault target/request/checkpoint/boot binding differs");
    }
    for (name, expected_phase) in [
        ("checkpoint-committed-v4.bin", "checkpoint-committed"),
        ("release-intent-v4.bin", "release-intent"),
    ] {
        let record: DurableFaultRecordV4 = parse(get(name)?)?;
        if record.attempt_id != attempt_id
            || record.boot_identity != expected_boot
            || record.phase != expected_phase
            || record.target.as_ref() != Some(expected_target)
            || record.checkpoint.as_ref() != Some(checkpoint)
            || record.checkpoint_digest.as_ref() != Some(&checkpoint_digest)
        {
            return fail("public fault committed phase snapshots differ");
        }
    }
    let authorization = trigger.fault == PublicFaultPlanV1::DropAuthorizationAtDurableIntent;
    let (outcome, knowledge, exec) = if authorization {
        if trigger.operation_errno != Some(libc::EPIPE)
            || trigger.victim != trigger.target
            || durable.phase != "release-intent"
            || durable.release_knowledge != PrivateReleaseKnowledgeV1::PossiblyReleased
            || leaves.contains_key("execution-observed-v4.bin")
            || response_kind != 106
        {
            return fail("authorization-loss transcript claims an unobserved release/exec outcome");
        }
        (
            PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain,
            PrivateReleaseKnowledgeV1::PossiblyReleased,
            PrivateReleaseExecV1::NotObserved,
        )
    } else {
        let executed: DurableFaultRecordV4 = parse(get("execution-observed-v4.bin")?)?;
        let victim = if trigger.fault == PublicFaultPlanV1::KillPinnedFrontendAtTargetLive {
            Some(&durable.frontend)
        } else {
            durable.guardian.as_ref()
        };
        if victim != Some(&trigger.victim)
            || trigger.operation_errno.is_some()
            || durable.phase != "execution-observed"
            || durable.release_knowledge != PrivateReleaseKnowledgeV1::ExecObserved
            || trigger.target_tcp_bytes.is_empty()
            || trigger.target_socket_inodes.len() < 2
            || trigger.target_socket_inodes.iter().any(|inode| *inode == 0)
            || executed.phase != "execution-observed"
            || executed.release_knowledge != PrivateReleaseKnowledgeV1::ExecObserved
            || executed.attempt_id != attempt_id
            || executed.target.as_ref() != Some(expected_target)
            || executed.checkpoint.as_ref() != Some(checkpoint)
            || executed.checkpoint_digest.as_ref() != Some(&checkpoint_digest)
        {
            return fail("frontend/guardian loss did not occur at the exact live TCP target phase");
        }
        (
            if trigger.fault == PublicFaultPlanV1::KillPinnedFrontendAtTargetLive {
                PrivateReleaseAllocatedOutcomeV1::FrontendLost
            } else {
                PrivateReleaseAllocatedOutcomeV1::GuardianLost
            },
            PrivateReleaseKnowledgeV1::ExecObserved,
            PrivateReleaseExecV1::Succeeded,
        )
    };
    let failure = leaves
        .get("fault-failure-v1.json")
        .map(|bytes| parse::<FaultFailureV1>(bytes))
        .transpose()?;
    if let Some(failure) = &failure {
        if failure.schema_version != 1
            || failure.attempt_id != attempt_id
            || failure.detail.is_empty()
            || !failure.possibly_released
        {
            return fail("public original fault failure differs");
        }
    }
    let (retirement_sha256, recovery_sha256) = match phase {
        "fault-retired-observed" => {
            let bytes = get("fault-retirement-v1.json")?;
            let retirement: FaultRetirementV1 = parse(bytes)?;
            if retirement.attempt_id != attempt_id
                || !retirement
                    .retired
                    .as_ref()
                    .is_some_and(|retired| retired.terminal_success(checkpoint))
                || leaves.contains_key("fault-recovery-v1.json")
            {
                return fail("public original fault retirement differs");
            }
            if response_kind == 106 && cleanup != bytes {
                return fail("public rejected fault cleanup lost its original retirement bytes");
            }
            (hash_bytes(bytes), None)
        }
        "fault-recovered-after-incomplete" => {
            let bytes = get("fault-recovery-v1.json")?;
            let recovery: FaultRecoveryV1 = parse(bytes)?;
            let original: DurableFaultRecordV4 = parse(&recovery.original_incomplete_bytes)?;
            if recovery.schema_version != 1
                || recovery.evidence_scope != "post-fault-exact-incomplete-recovery"
                || recovery.result_key != *key
                || recovery.attempt_id != attempt_id
                || !recovery.durable_attempt_record_absent
                || original.attempt_id != attempt_id
                || original.phase != "cleanup-incomplete"
                || original.target.as_ref() != Some(expected_target)
                || original.checkpoint_digest.as_ref() != Some(&checkpoint_digest)
                || original.release_knowledge != knowledge
                || !failure
                    .as_ref()
                    .is_some_and(|failure| !failure.cleanup_complete)
                || cleanup != bytes
                || response_kind != 106
            {
                return fail(
                    "public fault recovery overwrote or failed to bind the original incomplete rejection",
                );
            }
            (hash_bytes(bytes), Some(hash_bytes(bytes)))
        }
        _ => return fail("public fault is not actually retired or separately recovered"),
    };
    match response_kind {
        106 => {
            let rejection =
                memcordon_core::provider_rejection_wire::RejectionWireV1::parse(response)
                    .map_err(CiError::Message)?;
            if !rejection.target_created
                || !rejection.target_released
                || !rejection.cleanup.attempted
                || rejection.cleanup.sealed_boundary_retired != (phase == "fault-retired-observed")
            {
                return fail("public fault original rejection was coerced into a terminal");
            }
        }
        105 if !authorization => {}
        _ => return fail("public fault original response kind differs"),
    }
    Ok(ValidatedPublicFaultV2 {
        outcome,
        knowledge,
        exec,
        victim: trigger.victim,
        target: trigger.target,
        trigger_sha256: hash_bytes(trigger_bytes),
        failure_sha256: leaves
            .get("fault-failure-v1.json")
            .map(|bytes| hash_bytes(bytes)),
        retirement_sha256,
        recovery_sha256,
        response_kind,
        target_tcp_bytes: trigger.target_tcp_bytes,
        target_socket_inodes: trigger.target_socket_inodes,
    })
}
