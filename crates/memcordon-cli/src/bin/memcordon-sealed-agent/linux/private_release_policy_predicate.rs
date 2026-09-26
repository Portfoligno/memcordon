//! Authenticated V2 policy predicate branches for the closed candidate
//! release selector. This module does not allocate an attempt or claim the
//! fourth frozen-port-tamper branch, which needs physical live observation.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_branch_v1::{
    PolicyOperationBranchV1, PrivatePolicyAgentFixtureV1, policy_branch_challenge_v1,
};
use memcordon_core::workload_admission_v2::ProviderAdmissionSnapshotV2;
use memcordon_core::workload_codec::{contract_digest_v2, hash_bytes};
use memcordon_core::workload_contract::Nonce128;
use memcordon_core::workload_contract::{
    LogicalId, RequirementV1, TcpEndpoint, TcpPeerRequirement, WorkloadContractV2,
};
use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
use memcordon_core::workload_registry::CallerSelector;
use memcordon_core::workload_registry_v2::{
    AdmissionCodeV2, CandidatePolicyDecisionV2, PolicyRegistryV2, ProfileKindV2,
    evaluate_candidate_policy_v2,
};

use crate::policy_registry::ActivationV2;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use serde::Serialize;

use super::private_release_case::ReleaseCaseRequestV1;
use super::private_release_run::PolicyDecisionRunAuthorityV1;

const POLICY_SELECTOR: &str = "private_tcp::wrong_grant_profile_and_port_rejected";
const POLICY_INPUT: &str = "/var/lib/memcordon/sealed/private-release-policy-v1.json";
const POLICY_RAW: &str = "policy-branches.raw.json";
const POLICY_RAW_NEW: &str = "policy-branches.raw.json.new";
const MAX_POLICY_INPUT: u64 = 256 * 1024;

type ProtectedPolicyInputV1 = PrivatePolicyAgentFixtureV1;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "kebab-case")]
enum PolicyOperationOutcomeV1 {
    AcceptedControl,
    Admission(AdmissionCodeV2),
    FrozenBindingMismatch,
}

#[derive(Serialize)]
struct PolicyPositiveNativeV1 {
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    network_namespace_inode: u64,
    candidate_exit_code: i32,
}

#[derive(Serialize)]
struct ProtectedPolicyBranchRawV1<'a> {
    schema_version: u8,
    selector: &'static str,
    branch: PolicyOperationBranchV1,
    base_challenge_sha256: DiagnosticSha256,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    fixture_sha256: DiagnosticSha256,
    reviewed_topology_sha256: DiagnosticSha256,
    installed_inspection_sha256: DiagnosticSha256,
    installation_epoch_sha256: DiagnosticSha256,
    registry_sha256: DiagnosticSha256,
    accepted_request_sha256: DiagnosticSha256,
    changed_request_sha256: DiagnosticSha256,
    committed_tamper_request_sha256: DiagnosticSha256,
    exact_branch_request_sha256: DiagnosticSha256,
    outcome: PolicyOperationOutcomeV1,
    frozen_snapshot_sha256: DiagnosticSha256,
    authenticated_caller_uid: u32,
    authenticated_caller_sha256: DiagnosticSha256,
    accepted: &'a WorkloadContractV2,
    changed_port: &'a WorkloadContractV2,
    committed_tamper: &'a WorkloadContractV2,
    exact_branch_request: &'a WorkloadContractV2,
    frozen: &'a ProviderAdmissionSnapshotV2,
    positive_native: Option<PolicyPositiveNativeV1>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PolicyPredicateBranchV1 {
    pub(crate) name: &'static str,
    pub(crate) request_sha256: DiagnosticSha256,
    pub(crate) rejection: AdmissionCodeV2,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AuthenticatedPolicyPredicateReadbackV1 {
    pub(crate) fixture_sha256: DiagnosticSha256,
    pub(crate) registry_sha256: DiagnosticSha256,
    pub(crate) accepted_request_sha256: DiagnosticSha256,
    pub(crate) branches: [PolicyPredicateBranchV1; 3],
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct CommittedPortTamperReadbackV1 {
    pub(crate) frozen_snapshot_sha256: DiagnosticSha256,
    pub(crate) tampered_request_sha256: DiagnosticSha256,
    pub(crate) rejection: &'static str,
}

fn require_decision(
    registry: &PolicyRegistryV2,
    activation: &ActivationV2,
    request: &WorkloadContractV2,
    caller: &CallerSelector,
    profile: ProfileKindV2,
    h0: &DiagnosticSha256,
    expected: AdmissionCodeV2,
) -> Result<(), String> {
    let CandidatePolicyDecisionV2::Rejected(rejection) =
        evaluate_candidate_policy_v2(registry, &activation.epoch, request, caller, profile, h0)
    else {
        return Err("MCSEALED-PRIVATE-RELEASE: policy branch unexpectedly accepted".into());
    };
    if rejection.code != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: policy branch rejection differs".into());
    }
    Ok(())
}

fn one_port_only_changed(original: &WorkloadContractV2, changed: &WorkloadContractV2) -> bool {
    if original.requirements.as_slice().len() != changed.requirements.as_slice().len()
        || original.workload_plan_digest == changed.workload_plan_digest
        || original.authorization.grant_id != changed.authorization.grant_id
        || original.authorization.grant_revision != changed.authorization.grant_revision
        || original.authorized_profile != changed.authorized_profile
        || original.expected_epoch != changed.expected_epoch
        || original.execution_identity != changed.execution_identity
        || original.ceiling != changed.ceiling
        || original.endpoints != changed.endpoints
    {
        return false;
    }
    let mut changed_ports = 0;
    for (left, right) in original
        .requirements
        .as_slice()
        .iter()
        .zip(changed.requirements.as_slice())
    {
        match (left, right) {
            (
                RequirementV1::Tcp {
                    id: left_id,
                    family: left_family,
                    operations: left_operations,
                    scope: left_scope,
                    local_ports: left_ports,
                    peer: left_peer,
                },
                RequirementV1::Tcp {
                    id: right_id,
                    family: right_family,
                    operations: right_operations,
                    scope: right_scope,
                    local_ports: right_ports,
                    peer: right_peer,
                },
            ) if left_id == right_id
                && left_family == right_family
                && left_operations == right_operations
                && left_scope == right_scope =>
            {
                if left_ports != right_ports {
                    changed_ports += 1;
                }
                if left_peer != right_peer {
                    match (left_peer, right_peer) {
                        (
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V4 {
                                        address: a,
                                        port: p,
                                    },
                            },
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V4 {
                                        address: b,
                                        port: q,
                                    },
                            },
                        ) if a == b && p != q => changed_ports += 1,
                        (
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V6 {
                                        address: a,
                                        port: p,
                                    },
                            },
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V6 {
                                        address: b,
                                        port: q,
                                    },
                            },
                        ) if a == b && p != q => changed_ports += 1,
                        _ => return false,
                    }
                }
            }
            _ if left == right => {}
            _ => return false,
        }
    }
    changed_ports == 1
}

/// The activation must have been read under the protected policy lease and
/// the accepted/changed contracts authenticated as exact fixture bytes. The
/// caller and H0 digest must come from the live provider, not these claims.
#[allow(dead_code)] // No fourth branch or independent allocation interval yet.
pub(crate) fn evaluate_authenticated_policy_predicates(
    activation: &ActivationV2,
    accepted: &WorkloadContractV2,
    changed_port: &WorkloadContractV2,
    caller: &CallerSelector,
    native_profile: ProfileKindV2,
    h0_qualification: &DiagnosticSha256,
    challenge: &[u8; 32],
) -> Result<AuthenticatedPolicyPredicateReadbackV1, String> {
    let fixture = super::private_release_policy_fixture::acquire_reviewed_policy_fixture()?;
    if fixture.branch_order()[..3]
        != [
            "wrong-grant",
            "wrong-profile",
            "unapproved-changed-port-plan",
        ]
    {
        return Err("MCSEALED-PRIVATE-RELEASE: policy fixture branch order differs".into());
    }
    activation.validate()?;
    accepted.validate()?;
    changed_port.validate()?;
    if accepted.expected_epoch != activation.epoch
        || !one_port_only_changed(accepted, changed_port)
        || activation.registry.grants.as_slice().iter().any(|grant| {
            grant
                .approved_plans
                .as_slice()
                .contains(&changed_port.workload_plan_digest)
        })
        || challenge == &[0; 32]
    {
        return Err("MCSEALED-PRIVATE-RELEASE: authenticated policy fixture differs".into());
    }
    if evaluate_candidate_policy_v2(
        &activation.registry,
        &activation.epoch,
        accepted,
        caller,
        native_profile,
        h0_qualification,
    ) != CandidatePolicyDecisionV2::Accepted
    {
        return Err("MCSEALED-PRIVATE-RELEASE: policy positive control rejected".into());
    }

    let mut wrong_grant = accepted.clone();
    wrong_grant.authorization.grant_id = LogicalId::new("private-release-wrong-grant".into())?;
    if activation
        .registry
        .grants
        .as_slice()
        .iter()
        .any(|grant| grant.id == wrong_grant.authorization.grant_id)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: wrong-grant fixture collides".into());
    }
    wrong_grant.validate()?;
    require_decision(
        &activation.registry,
        activation,
        &wrong_grant,
        caller,
        native_profile,
        h0_qualification,
        AdmissionCodeV2::ProfileNotAuthorized,
    )?;

    let mut wrong_profile = accepted.clone();
    let mut domain = b"memcordon/private-release/wrong-profile/v1\0".to_vec();
    domain.extend_from_slice(challenge);
    wrong_profile.authorized_profile.semantic_digest = hash_bytes(&domain);
    if wrong_profile.authorized_profile == accepted.authorized_profile {
        return Err("MCSEALED-PRIVATE-RELEASE: wrong-profile fixture collided".into());
    }
    wrong_profile.validate()?;
    require_decision(
        &activation.registry,
        activation,
        &wrong_profile,
        caller,
        native_profile,
        h0_qualification,
        AdmissionCodeV2::ProfileDigestMismatch,
    )?;

    require_decision(
        &activation.registry,
        activation,
        changed_port,
        caller,
        native_profile,
        h0_qualification,
        AdmissionCodeV2::ProfileNotAuthorized,
    )?;
    Ok(AuthenticatedPolicyPredicateReadbackV1 {
        fixture_sha256: fixture.digest(),
        registry_sha256: activation.registry_digest.clone(),
        accepted_request_sha256: contract_digest_v2(accepted)?,
        branches: [
            PolicyPredicateBranchV1 {
                name: "wrong-grant",
                request_sha256: contract_digest_v2(&wrong_grant)?,
                rejection: AdmissionCodeV2::ProfileNotAuthorized,
            },
            PolicyPredicateBranchV1 {
                name: "wrong-profile",
                request_sha256: contract_digest_v2(&wrong_profile)?,
                rejection: AdmissionCodeV2::ProfileDigestMismatch,
            },
            PolicyPredicateBranchV1 {
                name: "unapproved-changed-port-plan",
                request_sha256: contract_digest_v2(changed_port)?,
                rejection: AdmissionCodeV2::ProfileNotAuthorized,
            },
        ],
    })
}

/// Invoke the same frozen-authority check used before physical release after
/// changing exactly one port in an otherwise validated, previously accepted
/// snapshot. This is only the protected producer half: an independent BPF
/// interval must separately prove the tampered request allocated no target.
#[allow(dead_code)] // Awaiting routed physical branch and independent interval.
pub(crate) fn observe_committed_port_tamper(
    activation: &ActivationV2,
    accepted: &WorkloadContractV2,
    changed_port: &WorkloadContractV2,
    frozen: &ProviderAdmissionSnapshotV2,
) -> Result<CommittedPortTamperReadbackV1, String> {
    activation.validate()?;
    accepted.validate()?;
    changed_port.validate()?;
    frozen.validate_against(&activation.registry)?;
    if frozen.request != *accepted || !one_port_only_changed(accepted, changed_port) {
        return Err("MCSEALED-PRIVATE-RELEASE: frozen port fixture differs".into());
    }
    let frozen_snapshot_sha256 = frozen.canonical_digest()?;
    let mut tampered = frozen.clone();
    tampered.request = changed_port.clone();
    let rejection = tampered
        .validate_against(&activation.registry)
        .expect_err("changed port may not validate against frozen admission");
    if rejection != "V2 frozen admission binding differs" {
        return Err("MCSEALED-PRIVATE-RELEASE: frozen port rejection differs".into());
    }
    Ok(CommittedPortTamperReadbackV1 {
        frozen_snapshot_sha256,
        tampered_request_sha256: contract_digest_v2(changed_port)?,
        rejection: "V2 frozen admission binding differs",
    })
}

/// Acquire the currently protected policy activation under its lease for all
/// four predicate/frozen-binding branches. The caller/H0 and two exact plans
/// still require separate authentication by the release runner.
#[allow(dead_code)] // Closed until the live case route supplies authenticated plans.
pub(crate) fn observe_current_policy_branches(
    accepted: &WorkloadContractV2,
    changed_port: &WorkloadContractV2,
    frozen: &ProviderAdmissionSnapshotV2,
    caller: &CallerSelector,
    native_profile: ProfileKindV2,
    h0_qualification: &DiagnosticSha256,
    challenge: &[u8; 32],
) -> Result<
    (
        AuthenticatedPolicyPredicateReadbackV1,
        CommittedPortTamperReadbackV1,
    ),
    String,
> {
    let lease = crate::policy_registry::native::Lease::acquire()?;
    let activation = lease
        .read_v2()?
        .ok_or("MCSEALED-PRIVATE-RELEASE: V2 policy activation absent")?;
    let predicates = evaluate_authenticated_policy_predicates(
        &activation,
        accepted,
        changed_port,
        caller,
        native_profile,
        h0_qualification,
        challenge,
    )?;
    let committed = observe_committed_port_tamper(&activation, accepted, changed_port, frozen)?;
    Ok((predicates, committed))
}

fn read_protected_policy_input(
    challenge: &[u8; 32],
) -> Result<
    (
        ProtectedPolicyInputV1,
        PolicyOperationBranchV1,
        DiagnosticSha256,
    ),
    String,
> {
    let path = Path::new(POLICY_INPUT);
    let parent = path
        .parent()
        .ok_or("MCSEALED-PRIVATE-RELEASE: policy input parent absent")?;
    let parent_metadata = parent.metadata().map_err(|error| error.to_string())?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o777 != 0o700
    {
        return Err("MCSEALED-PRIVATE-RELEASE: policy input parent protection differs".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_POLICY_INPUT
    {
        return Err("MCSEALED-PRIVATE-RELEASE: policy input protection differs".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len()
        || bytes.is_empty()
        || bytes.len() as u64 > MAX_POLICY_INPUT
    {
        return Err("MCSEALED-PRIVATE-RELEASE: policy input length differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let input: ProtectedPolicyInputV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    input.validate()?;
    if input.schema_version != 1
        || input.selector != POLICY_SELECTOR
        || input.base_challenge == [0; 32]
        || serde_json::to_vec(&input).map_err(|error| error.to_string())? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: policy input binding differs".into());
    }
    input.accepted.validate()?;
    input.changed_port.validate()?;
    input.committed_tamper.validate()?;
    if !one_port_only_changed(&input.accepted, &input.changed_port)
        || !one_port_only_changed(&input.accepted, &input.committed_tamper)
        || contract_digest_v2(&input.changed_port)? == contract_digest_v2(&input.committed_tamper)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: policy fixture port branches differ".into());
    }
    let branch = PolicyOperationBranchV1::ALL
        .into_iter()
        .find(|branch| {
            policy_branch_challenge_v1(&input.base_challenge, *branch)
                .ok()
                .as_ref()
                == Some(challenge)
        })
        .ok_or("MCSEALED-PRIVATE-RELEASE: policy branch challenge differs")?;
    Ok((input, branch, hash_bytes(&bytes)))
}

/// Service-side admission of the distinct decision-only message uses the
/// exact protected branch challenge and kernel peer credentials. A caller
/// supplied UID is never part of the request body.
pub(crate) fn read_protected_policy_registration_fields(
    challenge: &[u8; 32],
) -> Result<(u32, DiagnosticSha256, DiagnosticSha256), String> {
    let (input, _, _) = read_protected_policy_input(challenge)?;
    Ok((
        input.authenticated_caller_uid,
        contract_digest_v2(&input.accepted)?,
        input.accepted.workload_plan_digest,
    ))
}

fn execute_one_policy_branch(
    activation: &ActivationV2,
    input: &ProtectedPolicyInputV1,
    branch: PolicyOperationBranchV1,
    caller: &CallerSelector,
    h0: &DiagnosticSha256,
) -> Result<(WorkloadContractV2, PolicyOperationOutcomeV1), String> {
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    match branch {
        PolicyOperationBranchV1::AcceptedControl => {
            if evaluate_candidate_policy_v2(
                &activation.registry,
                &activation.epoch,
                &input.accepted,
                caller,
                profile,
                h0,
            ) != CandidatePolicyDecisionV2::Accepted
            {
                return Err("MCSEALED-PRIVATE-RELEASE: policy accepted control rejected".into());
            }
            Ok((
                input.accepted.clone(),
                PolicyOperationOutcomeV1::AcceptedControl,
            ))
        }
        PolicyOperationBranchV1::WrongGrant => {
            let mut request = input.accepted.clone();
            request.authorization.grant_id = LogicalId::new("private-release-wrong-grant".into())?;
            if activation
                .registry
                .grants
                .as_slice()
                .iter()
                .any(|grant| grant.id == request.authorization.grant_id)
            {
                return Err("MCSEALED-PRIVATE-RELEASE: wrong-grant fixture collides".into());
            }
            request.validate()?;
            require_decision(
                &activation.registry,
                activation,
                &request,
                caller,
                profile,
                h0,
                AdmissionCodeV2::ProfileNotAuthorized,
            )?;
            Ok((
                request,
                PolicyOperationOutcomeV1::Admission(AdmissionCodeV2::ProfileNotAuthorized),
            ))
        }
        PolicyOperationBranchV1::WrongProfile => {
            let mut request = input.accepted.clone();
            let mut domain = b"memcordon/private-release/wrong-profile/v1\0".to_vec();
            domain.extend_from_slice(&input.base_challenge);
            request.authorized_profile.semantic_digest = hash_bytes(&domain);
            if request.authorized_profile == input.accepted.authorized_profile {
                return Err("MCSEALED-PRIVATE-RELEASE: wrong-profile fixture collided".into());
            }
            request.validate()?;
            require_decision(
                &activation.registry,
                activation,
                &request,
                caller,
                profile,
                h0,
                AdmissionCodeV2::ProfileDigestMismatch,
            )?;
            Ok((
                request,
                PolicyOperationOutcomeV1::Admission(AdmissionCodeV2::ProfileDigestMismatch),
            ))
        }
        PolicyOperationBranchV1::UnapprovedChangedPortPlan => {
            if activation.registry.grants.as_slice().iter().any(|grant| {
                grant
                    .approved_plans
                    .as_slice()
                    .contains(&input.changed_port.workload_plan_digest)
            }) {
                return Err("MCSEALED-PRIVATE-RELEASE: changed plan unexpectedly approved".into());
            }
            require_decision(
                &activation.registry,
                activation,
                &input.changed_port,
                caller,
                profile,
                h0,
                AdmissionCodeV2::PlanNotApproved,
            )?;
            Ok((
                input.changed_port.clone(),
                PolicyOperationOutcomeV1::Admission(AdmissionCodeV2::PlanNotApproved),
            ))
        }
        PolicyOperationBranchV1::CommittedPortTamper => {
            // The frozen snapshot is checked by the caller immediately before
            // this branch, then the exact distinct port change must fail.
            Ok((
                input.committed_tamper.clone(),
                PolicyOperationOutcomeV1::FrozenBindingMismatch,
            ))
        }
    }
}

/// The root-owned fixed input path is a candidate fixture, never authority by
/// itself. CI must independently pin its exact digest in protected intent and
/// bind the raw bytes to the package, live V2 activation and five BPF captures.
/// This function deliberately publishes no release-case result.
pub(crate) fn persist_authenticated_policy_decision_raw(
    request: &ReleaseCaseRequestV1,
    authenticated_peer_uid: u32,
) -> Result<DiagnosticSha256, String> {
    if request.selector != POLICY_SELECTOR || authenticated_peer_uid == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: policy case caller differs".into());
    }
    let case = PolicyDecisionRunAuthorityV1::prepare(request)?;
    case.revalidate()?;
    let challenge = *case.challenge();
    let (input, branch, fixture_sha256) = read_protected_policy_input(&challenge)?;
    if authenticated_peer_uid != input.authenticated_caller_uid {
        return Err(
            "MCSEALED-PRIVATE-RELEASE: policy authenticated peer differs from fixture".into(),
        );
    }
    let reviewed_topology =
        super::private_release_policy_fixture::acquire_reviewed_policy_fixture()?;
    let policy = crate::policy_registry::native::Lease::acquire()?;
    let activation = policy
        .read_v2()?
        .ok_or("MCSEALED-PRIVATE-RELEASE: V2 policy activation absent")?;
    activation.validate()?;
    let inspection = case.installed_inspection_bytes()?;
    let h0 = hash_bytes(&inspection);
    let caller = CallerSelector::Linux {
        uid: authenticated_peer_uid,
    };
    let native_abi = match case.target() {
        "x86_64-unknown-linux-gnu" => QualifiedNativeAbiV2::X86_64LinuxGnu,
        "aarch64-unknown-linux-gnu" => QualifiedNativeAbiV2::Aarch64LinuxGnu,
        _ => return Err("MCSEALED-PRIVATE-RELEASE: policy M0 target differs".into()),
    };
    let caller_bytes = serde_json::to_vec(&caller).map_err(|error| error.to_string())?;
    let caller_sha256 = hash_bytes(&caller_bytes);
    let frozen = ProviderAdmissionSnapshotV2::freeze(
        &activation.registry,
        &activation.epoch,
        &input.accepted,
        &caller,
        h0.clone(),
        case.installation_epoch().clone(),
        native_abi,
        Nonce128(challenge[..16].try_into().expect("fixed challenge half")),
        Nonce128(challenge[16..].try_into().expect("fixed challenge half")),
        caller_sha256.clone(),
        case.result_key().clone(),
    )?;
    let (exact_request, outcome) =
        execute_one_policy_branch(&activation, &input, branch, &caller, &h0)?;
    if branch == PolicyOperationBranchV1::CommittedPortTamper {
        let committed = observe_committed_port_tamper(
            &activation,
            &input.accepted,
            &input.committed_tamper,
            &frozen,
        )?;
        if committed.tampered_request_sha256 != contract_digest_v2(&exact_request)? {
            return Err("MCSEALED-PRIVATE-RELEASE: committed-port exact request differs".into());
        }
    }
    // This is a candidate-only decision control. It must stop before owner
    // construction; a generic TCP fixture would not execute the authenticated
    // accepted V2 contract and cannot be passed off as that plan's launch.
    let positive_native = None;
    let raw = ProtectedPolicyBranchRawV1 {
        schema_version: 1,
        selector: POLICY_SELECTOR,
        branch,
        base_challenge_sha256: hash_bytes(&input.base_challenge),
        result_key: case.result_key().clone(),
        challenge_sha256: hash_bytes(&challenge),
        fixture_sha256,
        reviewed_topology_sha256: reviewed_topology.digest(),
        installed_inspection_sha256: h0,
        installation_epoch_sha256: case.installation_epoch().clone(),
        registry_sha256: activation.registry_digest,
        accepted_request_sha256: contract_digest_v2(&input.accepted)?,
        changed_request_sha256: contract_digest_v2(&input.changed_port)?,
        committed_tamper_request_sha256: contract_digest_v2(&input.committed_tamper)?,
        exact_branch_request_sha256: contract_digest_v2(&exact_request)?,
        outcome,
        frozen_snapshot_sha256: frozen.canonical_digest()?,
        authenticated_caller_uid: authenticated_peer_uid,
        authenticated_caller_sha256: caller_sha256,
        accepted: &input.accepted,
        changed_port: &input.changed_port,
        committed_tamper: &input.committed_tamper,
        exact_branch_request: &exact_request,
        frozen: &frozen,
        positive_native,
    };
    let bytes = serde_json::to_vec(&raw).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_POLICY_INPUT as usize * 2 {
        return Err("MCSEALED-PRIVATE-RELEASE: policy raw exceeds bound".into());
    }
    let directory: &File = case.directory();
    super::private_release_alt_abi_raw::write_immutable(
        directory,
        POLICY_RAW,
        POLICY_RAW_NEW,
        &bytes,
    )?;
    case.revalidate()?;
    Ok(hash_bytes(&bytes))
}

pub(crate) fn readback_protected_policy_raw(
    directory: &File,
    request: &ReleaseCaseRequestV1,
) -> Result<DiagnosticSha256, String> {
    if request.selector != POLICY_SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: policy raw selector differs".into());
    }
    let bytes =
        super::private_release_alt_abi_raw::read_immutable(directory, POLICY_RAW, POLICY_RAW_NEW)?;
    if bytes.len() > MAX_POLICY_INPUT as usize * 2 {
        return Err("MCSEALED-PRIVATE-RELEASE: policy raw length differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let raw: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let object = raw
        .as_object()
        .ok_or("MCSEALED-PRIVATE-RELEASE: policy raw object absent")?;
    let (fixture, branch, fixture_digest) = read_protected_policy_input(&request.challenge)?;
    let typed = memcordon_core::private_release_branch_v1::ProtectedPolicyBranchRawV1::parse(
        &bytes,
        &fixture.base_challenge,
    )?;
    let reviewed_topology =
        super::private_release_policy_fixture::acquire_reviewed_policy_fixture()?;
    if typed.authenticated_caller_uid != fixture.authenticated_caller_uid
        || typed.branch != branch
        || typed.fixture_sha256 != fixture_digest
        || object
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        || object.get("selector").and_then(serde_json::Value::as_str) != Some(POLICY_SELECTOR)
        || object.get("result_key").and_then(serde_json::Value::as_str)
            != Some(String::from(request.result_key()).as_str())
        || object
            .get("challenge_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(String::from(hash_bytes(&request.challenge)).as_str())
        || object.get("branch").and_then(serde_json::Value::as_str) != Some(branch.as_str())
        || object
            .get("fixture_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(String::from(fixture_digest).as_str())
        || object
            .get("reviewed_topology_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(String::from(reviewed_topology.digest()).as_str())
        || object
            .get("base_challenge_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(String::from(hash_bytes(&fixture.base_challenge)).as_str())
    {
        return Err("MCSEALED-PRIVATE-RELEASE: policy raw request binding differs".into());
    }
    Ok(hash_bytes(&bytes))
}
