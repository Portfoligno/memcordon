//! Detached five-branch policy proof. Runtime branches are reconstructed from
//! immutable enrolled leaves and compared with independently approved recipes.
use crate::private_observer_session::strict_json;
use crate::private_public_completion::AuthenticatedCompletedPublicEvidenceV2;
use crate::private_public_plan::{
    StaticPublicSuiteIntentV1, prepared_public_case_recipe_v1, public_contract_template_sha256,
    public_policy_fixture_template_sha256,
};
use crate::private_public_specialist_replay::{interval, observed, provider};
use crate::private_public_verify::{PublicPolicyBranchLiveV1, VerifiedPublicPolicyCompositeV1};
use crate::{CiError, Result};
use memcordon_core::private_public_policy_composite_v1::{
    PUBLIC_POLICY_SELECTOR_V1, PublicPolicyBranchOutcomeV1, PublicPolicyCompositeCaseV1,
};
use memcordon_core::private_release_branch_v1::{
    PolicyOperationBranchV1 as Branch, PrivatePolicyAgentFixtureV1, policy_branch_challenge_v1,
};
use memcordon_core::workload_codec::contract_digest_v2;
use memcordon_core::workload_contract::{PolicyEpoch, WorkloadContract, WorkloadContractV2};
use memcordon_core::workload_registry_v2::{
    AdmissionRejectionV2, PolicyGrantV2, PolicyRegistryV2, ProfileKindV2, resolve_v2,
};
use serde::Deserialize;
use std::path::Path;

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn path(prefix: &str, leaf: &str) -> String {
    Path::new(prefix).join(leaf).to_string_lossy().into_owned()
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum GrantOutcome {
    Granted { grant: PolicyGrantV2 },
    Rejected { rejection: AdmissionRejectionV2 },
}

/// Decode the exact contract and plan precondition from the argv-free native
/// launch envelope. Lengths are bounded before slicing; no text interpretation.
fn launch_contract(
    bytes: &[u8],
) -> Result<(
    WorkloadContractV2,
    memcordon_core::DiagnosticSha256,
    memcordon_core::DiagnosticSha256,
    memcordon_core::DiagnosticSha256,
    memcordon_core::DiagnosticSha256,
)> {
    struct Cursor<'a>(&'a [u8]);
    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            let value = self
                .0
                .get(..n)
                .ok_or_else(|| CiError::Message("policy launch envelope truncated".into()))?;
            self.0 = &self.0[n..];
            Ok(value)
        }
        fn blob(&mut self) -> Result<&'a [u8]> {
            let n = u32::from_be_bytes(self.take(4)?.try_into().expect("bounded u32")) as usize;
            if n > 1024 * 1024 {
                return fail("policy launch member exceeds bound");
            }
            self.take(n)
        }
        fn digest(&mut self) -> Result<memcordon_core::DiagnosticSha256> {
            Ok(memcordon_core::DiagnosticSha256::from_bytes(
                self.take(32)?.try_into().expect("bounded digest"),
            ))
        }
    }
    let mut cursor = Cursor(bytes);
    if u16::from_be_bytes(cursor.take(2)?.try_into().expect("bounded version")) != 5 {
        return fail("policy launch lacks exact plan precondition version");
    }
    let registry = cursor.digest()?;
    let qualification = cursor.digest()?;
    let digest = cursor.digest()?;
    let contract = WorkloadContractV2::parse(cursor.blob()?).map_err(CiError::Message)?;
    if contract_digest_v2(&contract).map_err(CiError::Message)? != digest {
        return fail("policy launch contract digest differs");
    }
    if cursor.blob()?.is_empty() {
        return fail("policy launch operation absent");
    }
    let expected_contract = cursor.digest()?;
    let expected_generation = cursor.digest()?;
    if !cursor.0.is_empty() {
        return fail("policy launch trailing bytes");
    }
    Ok((
        contract,
        expected_contract,
        expected_generation,
        registry,
        qualification,
    ))
}

#[cfg(unix)]
pub(crate) fn replay_completed_public_policy(
    intent: &StaticPublicSuiteIntentV1,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
) -> Result<VerifiedPublicPolicyCompositeV1> {
    replay_public_policy_origin(intent, completed.origin())
}

#[cfg(unix)]
pub(crate) fn replay_public_policy_origin(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
) -> Result<VerifiedPublicPolicyCompositeV1> {
    intent.validate()?;
    let bytes = origin.leaf("composites/policy/composite.json")?;
    let case = PublicPolicyCompositeCaseV1::parse(bytes).map_err(CiError::Message)?;
    let generation = origin
        .descriptor()
        .generations
        .iter()
        .find(|entry| entry.installation_epoch == case.installation_epoch)
        .ok_or_else(|| CiError::Message("policy observed generation absent".into()))?;
    let (base, _) = prepared_public_case_recipe_v1(
        intent,
        &origin.descriptor().session_nonce,
        generation.generation,
        PUBLIC_POLICY_SELECTOR_V1,
    )?;
    let fixture: PrivatePolicyAgentFixtureV1 =
        strict_json(origin.leaf("composites/policy/fixture.json")?, 512 * 1024)?;
    fixture.validate().map_err(CiError::Message)?;
    if case.base_challenge != base
        || case.target != intent.observer_subject.target
        || case.source_commit != intent.observer_subject.source_commit
        || case.release_version.as_str() != intent.observer_subject.release_version
        || case.archive_sha256 != intent.archive_sha256
        || case.manifest_sha256 != intent.manifest_sha256
        || case.qualification_sha256 != intent.qualification_sha256
        || case.active_h1_receipt_sha256 != generation.installed_receipt_sha256
        || case.release_catalogue_sha256 != intent.observer_subject.catalogue_sha256
        || fixture.base_challenge != base
        || fixture.authenticated_caller_uid != intent.public_uid
        || public_policy_fixture_template_sha256(&fixture)?
            != intent.policy_recipe.fixture_template_sha256
    {
        return fail(
            "policy composite differs from protected static recipe and observed generation",
        );
    }
    let names = [
        "accepted",
        "wrong-grant",
        "wrong-profile",
        "unapproved-port",
        "frozen-tamper",
    ];
    let mut live = Vec::with_capacity(5);
    let mut epoch: Option<PolicyEpoch> = None;
    for ((record, name), approved) in case
        .branches
        .iter()
        .zip(names)
        .zip(&intent.policy_recipe.branches)
    {
        let prefix = path("composites/policy", name);
        let provider = provider(origin, &path(&prefix, "provider"))?;
        let (capture, clock) = interval(origin, &path(&prefix, "interval.json"), "policy")?;
        let raw: serde_json::Value = strict_json(&provider.record_bytes, 128 * 1024)?;
        let expected_challenge = policy_branch_challenge_v1(&base, record.branch)
            .map_err(|error| CiError::Message(error.into()))?;
        let decision: serde_json::Value = strict_json(&provider.grant_decision_bytes, 128 * 1024)?;
        let decision_epoch: PolicyEpoch = serde_json::from_value(
            decision
                .get("policy_epoch")
                .cloned()
                .ok_or_else(|| CiError::Message("policy decision epoch absent".into()))?,
        )?;
        let WorkloadContract::V2(contract) =
            WorkloadContract::parse(&provider.request_bytes).map_err(CiError::Message)?
        else {
            return fail("policy request is not V2");
        };
        let registry = PolicyRegistryV2::parse(
            provider
                .registry_bytes
                .as_ref()
                .ok_or_else(|| CiError::Message("policy original registry absent".into()))?,
        )
        .map_err(CiError::Message)?;
        if approved.branch != record.branch
            || record.challenge != expected_challenge
            || provider.result_key != record.result_key
            || provider.policy_branch != Some(record.branch)
            || raw.get("challenge").and_then(serde_json::Value::as_str)
                != Some(hex::encode(expected_challenge).as_str())
            || raw.get("peer_pid").and_then(serde_json::Value::as_u64)
                != Some(u64::from(record.child.pid))
            || raw
                .get("peer_start_time_ticks")
                .and_then(serde_json::Value::as_u64)
                != Some(record.child.start_time_ticks)
            || raw.get("peer_uid").and_then(serde_json::Value::as_u64)
                != Some(u64::from(intent.public_uid))
            || raw.get("peer_gid").and_then(serde_json::Value::as_u64)
                != Some(u64::from(intent.public_gid))
            || raw.get("installation_epoch")
                != Some(&serde_json::to_value(&generation.installation_epoch)?)
            || raw.get("manifest_sha256") != Some(&serde_json::to_value(&intent.manifest_sha256)?)
            || raw.get("qualification_sha256")
                != Some(&serde_json::to_value(&intent.qualification_sha256)?)
            || raw.get("active_h1_receipt_sha256")
                != Some(&serde_json::to_value(&generation.installed_receipt_sha256)?)
            || contract.expected_epoch != decision_epoch
            || epoch.as_ref().is_some_and(|value| value != &decision_epoch)
            || public_contract_template_sha256(&contract)? != approved.contract_template_sha256
            || registry.canonical_digest().map_err(CiError::Message)?
                != intent.policy_recipe.registry_sha256
        {
            return fail(
                "policy original caller/contract/registry/epoch differs from approved branch",
            );
        }
        epoch = Some(decision_epoch.clone());
        let resolved = resolve_v2(
            &registry,
            &decision_epoch,
            &contract,
            &memcordon_core::workload_registry::CallerSelector::Linux {
                uid: intent.public_uid,
            },
            ProfileKindV2::LinuxTcp4PrivateV1,
            &intent.qualification_sha256,
        );
        let outcome: GrantOutcome = serde_json::from_value(
            decision
                .get("outcome")
                .cloned()
                .ok_or_else(|| CiError::Message("policy outcome absent".into()))?,
        )?;
        match (outcome, resolved) {
            (GrantOutcome::Granted { grant }, Ok(expected)) if &grant == expected => (),
            (GrantOutcome::Rejected { rejection }, Err(expected)) if rejection == expected => (),
            _ => return fail("policy decision differs from actual independent V2 resolution"),
        }
        let accepted = record.branch == Branch::AcceptedControl;
        if accepted || record.branch == Branch::CommittedPortTamper {
            let receipt =
                memcordon_core::workload_plan_v2::PrivatePlanReceiptV2::parse_for_contract(
                    &provider.plan_response_bytes,
                    &contract,
                )
                .map_err(CiError::Message)?;
            if receipt.registry_digest != intent.policy_recipe.registry_sha256
                || receipt.caller_uid != intent.public_uid
                || receipt.policy_epoch != decision_epoch
                || receipt.generation_digest != generation.installation_epoch
                || receipt.installed_qualification_sha256 != intent.qualification_sha256
                || receipt.runtime_manifest_sha256 != intent.manifest_sha256
                || receipt.source_commit != intent.observer_subject.source_commit
            {
                return fail(
                    "policy frozen receipt differs from authenticated installed generation",
                );
            }
            if record.branch == Branch::CommittedPortTamper {
                let [attempt] = provider.attempts.as_slice() else {
                    return fail("policy frozen launch count differs");
                };
                let (tampered, original, generation_pin, registry_pin, qualification_pin) =
                    launch_contract(&attempt.request_bytes)?;
                let rejection = memcordon_core::provider_rejection_wire::RejectionWireV1::parse(
                    &attempt.response_bytes,
                )
                .map_err(CiError::Message)?;
                if tampered != fixture.committed_tamper
                    || contract != fixture.accepted
                    || original != contract_digest_v2(&contract).map_err(CiError::Message)?
                    || generation_pin != generation.installation_epoch
                    || registry_pin != intent.policy_recipe.registry_sha256
                    || qualification_pin != intent.qualification_sha256
                    || tampered == contract
                    || rejection.code != "MCSEALED-PRIVATE-EXPECTED-PLAN"
                    || rejection.target_created
                    || rejection.target_released
                    || rejection.cleanup.attempted
                {
                    return fail("policy frozen actual tamper/preallocation rejection differs");
                }
            }
        } else {
            let rejection = memcordon_core::provider_rejection_wire::RejectionWireV1::parse(
                &provider.plan_response_bytes,
            )
            .map_err(CiError::Message)?;
            if rejection.code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
                || rejection.target_created
                || rejection.target_released
                || rejection.cleanup.attempted
            {
                return fail("policy denied request allocated or changed rejection");
            }
        }
        let targets = provider
            .attempts
            .iter()
            .filter_map(|attempt| {
                attempt.target_identity.as_ref().map(|target| {
                    crate::private_public_kernel_join::ProtectedPublicTargetExpectationV1 {
                        attempt_id: attempt.attempt_id.clone(),
                        pid: target.target.pid,
                        start_ticks: target.target.start_time,
                        network_namespace_inode: target.network_namespace_inode,
                        entrypoint_sha256: target.entrypoint_sha256.clone(),
                        entrypoint_device: target.entrypoint_device,
                        entrypoint_inode: target.entrypoint_inode,
                        entrypoint_path: target.entrypoint_path.clone(),
                    }
                })
            })
            .collect::<Vec<_>>();
        let joined = crate::private_public_kernel_join::join_public_case_kernel_targets(
            &capture,
            &clock,
            &record.result_key,
            &targets,
        )?;
        let observed = observed(
            origin,
            &path(&prefix, "cli"),
            intent,
            &generation.installed_receipt_sha256,
            &record.child,
            if accepted {
                crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0)
            } else {
                crate::private_public_v2::ExpectedPublicV2Outcome::PreallocationRejected
            },
        )?;
        let attachments = crate::private_public_dispatch::collect_public_raw_attachments(
            &case.selector,
            &observed,
            &provider,
            &capture,
        )?;
        if accepted
            != matches!(
                record.outcome,
                PublicPolicyBranchOutcomeV1::AcceptedControl { .. }
            )
        {
            return fail("policy branch closed outcome differs");
        }
        live.push(PublicPolicyBranchLiveV1 {
            observed,
            provider,
            interval: capture,
            joined,
            attachments,
        });
    }
    let live: [PublicPolicyBranchLiveV1; 5] = live
        .try_into()
        .map_err(|_| CiError::Message("policy exact five physical branches absent".into()))?;
    crate::private_public_verify::verify_public_policy_composite(bytes, &live)
}
