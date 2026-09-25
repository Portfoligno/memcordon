//! Version-two Linux policy schema and exact execution-identity grants.
//!
//! This module describes administrator authority. It does not install a native
//! profile or turn a registry declaration into package availability.

use crate::workload_codec::{Encoder, encode_ceiling, hash_bytes};
use crate::workload_contract::{
    ContractVersionTwo, CredentialGainCeiling, DeniedOperation, DirectSocketCeiling,
    ExecutionIdentityRefV2, ExecutionIdentityRequestV2, ExternalSocketCeiling, GrantId, IpFamily,
    LogicalId, MediatedCommunicationCeiling, NetworkCeilingV1, PolicyEpoch, ProfileId, ProfileRef,
    RequirementId, RequirementV1, TcpEndpoint, TcpPeerRequirement, TcpScope, UnixAuthorityCeiling,
    WorkloadContractV2,
};
use crate::workload_limits as limits;
use crate::workload_registry::{
    BaselineProfile, CallerSelector, GrantChangeDisposition, PolicyGrantV1, PolicyRegistryV1,
    ProfileDefinitionV1, ceiling_contains,
};
use crate::{BoundedText, BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU32, NonZeroU64};

pub type NonRootUid = NonZeroU32;
pub type NonRootGid = NonZeroU32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileKindV2 {
    LinuxUnixCreateV1,
    LinuxTcp4PrivateV1,
}

impl ProfileKindV2 {
    pub fn id(self) -> ProfileId {
        match self {
            Self::LinuxUnixCreateV1 => BaselineProfile::LinuxUnixCreate.id(),
            Self::LinuxTcp4PrivateV1 => {
                LogicalId::new("linux-tcp4-private-v1".into()).expect("fixed profile id")
            }
        }
    }

    pub fn ceiling(self) -> NetworkCeilingV1 {
        match self {
            Self::LinuxUnixCreateV1 => BaselineProfile::LinuxUnixCreate.ceiling(),
            Self::LinuxTcp4PrivateV1 => NetworkCeilingV1 {
                direct_socket_authority: DirectSocketCeiling::AttemptPrivateIpv4StackAllPorts,
                unix_authority: UnixAuthorityCeiling::NoNamedEndpointsSocketPairsOnly,
                external_socket_custody: ExternalSocketCeiling::NoSocketAtTargetEntry,
                credential_gains: CredentialGainCeiling::NoGain,
                mediated_communication:
                    MediatedCommunicationCeiling::ExternalFilesystemAndStdioPolicyAccepted,
            },
        }
    }

    pub fn reference(self) -> ProfileRef {
        match self {
            Self::LinuxUnixCreateV1 => BaselineProfile::LinuxUnixCreate.reference(),
            Self::LinuxTcp4PrivateV1 => {
                let mut encoder = Encoder::new(b"profile-definition-v2", limits::CONTRACT_BYTES)
                    .expect("fixed profile domain fits");
                encoder.id(&self.id()).expect("fixed profile id fits");
                encode_ceiling(&mut encoder, &self.ceiling()).expect("fixed ceiling fits");
                // Closed semantic tags: no Unix sockets or socketpairs, one
                // isolated IPv4 loopback stack, exact target identity, and a
                // reviewed native ABI filter; namespace-local port policy.
                for tag in [1_u8, 1, 1, 1] {
                    encoder.byte(tag).expect("fixed semantic tag fits");
                }
                for value in [0_u64, 32768, 60999] {
                    encoder.u64(value).expect("fixed port policy fits");
                }
                encoder.count(0).expect("empty reserved-port list fits");
                ProfileRef {
                    id: self.id(),
                    semantic_digest: hash_bytes(&encoder.finish()),
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedEntrypointV2 {
    pub id: LogicalId,
    pub absolute_path: BoundedText<{ limits::ENTRYPOINT_PATH_BYTES }>,
    pub sha256: DiagnosticSha256,
    pub size: NonZeroU64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxExecutionIdentityV2 {
    pub reference: ExecutionIdentityRefV2,
    pub enabled: bool,
    pub uid: NonRootUid,
    pub gid: NonRootGid,
    pub supplementary_groups: BoundedVec<NonRootGid, { limits::GROUPS_PER_IDENTITY }>,
    pub entrypoints: BoundedVec<ApprovedEntrypointV2, { limits::ENTRYPOINTS_PER_IDENTITY }>,
}

impl LinuxExecutionIdentityV2 {
    pub fn semantic_digest(&self) -> Result<DiagnosticSha256, String> {
        self.validate_fields()?;
        let mut encoder = Encoder::new(b"execution-identity-v2", limits::REGISTRY_BYTES)?;
        encoder.id(&self.reference.id)?;
        encoder.u64(u64::from(self.uid.get()))?;
        encoder.u64(u64::from(self.gid.get()))?;
        let mut groups: Vec<_> = self.supplementary_groups.as_slice().iter().collect();
        groups.sort();
        encoder.count(groups.len())?;
        for group in groups {
            encoder.u64(u64::from(group.get()))?;
        }
        let mut entrypoints: Vec<_> = self.entrypoints.as_slice().iter().collect();
        entrypoints.sort_by_key(|entrypoint| &entrypoint.id);
        encoder.count(entrypoints.len())?;
        for entrypoint in entrypoints {
            encoder.id(&entrypoint.id)?;
            encoder.count(entrypoint.absolute_path.as_str().len())?;
            encoder.raw(entrypoint.absolute_path.as_str().as_bytes())?;
            encoder.u64(entrypoint.size.get())?;
            encoder.digest(&entrypoint.sha256)?;
        }
        Ok(hash_bytes(&encoder.finish()))
    }

    fn validate_fields(&self) -> Result<(), String> {
        if self.entrypoints.as_slice().is_empty() {
            return Err("execution identity has no approved entrypoint".into());
        }
        for (index, group) in self.supplementary_groups.as_slice().iter().enumerate() {
            if self.supplementary_groups.as_slice()[..index].contains(group) {
                return Err("duplicate supplementary group".into());
            }
        }
        for (index, entrypoint) in self.entrypoints.as_slice().iter().enumerate() {
            let path = entrypoint.absolute_path.as_str();
            if !path.starts_with('/')
                || path == "/"
                || path.contains('\0')
                || path
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || self.entrypoints.as_slice()[..index]
                    .iter()
                    .any(|prior| prior.id == entrypoint.id)
            {
                return Err("invalid or duplicate approved entrypoint".into());
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.semantic_digest()? != self.reference.semantic_digest {
            return Err("execution identity semantic digest differs".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDefinitionV2 {
    pub profile: ProfileKindV2,
    pub reference: ProfileRef,
    pub enabled: bool,
    pub qualification_digest: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrantV2 {
    pub id: GrantId,
    pub revision: NonZeroU64,
    pub profile: ProfileRef,
    pub ceiling: NetworkCeilingV1,
    pub enabled: bool,
    pub callers: BoundedVec<CallerSelector, { limits::CALLERS_PER_GRANT }>,
    pub approved_plans: BoundedVec<DiagnosticSha256, { limits::PLANS_PER_GRANT }>,
    pub execution_identity: ExecutionIdentityRequestV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRegistryV2 {
    pub schema_version: ContractVersionTwo,
    pub profiles: BoundedVec<ProfileDefinitionV2, { limits::PROFILES }>,
    pub execution_identities:
        BoundedVec<LinuxExecutionIdentityV2, { limits::EXECUTION_IDENTITIES }>,
    pub grants: BoundedVec<PolicyGrantV2, { limits::GRANTS }>,
    pub active_attempt_disposition: GrantChangeDisposition,
}

impl PolicyRegistryV2 {
    /// A V2 activation retains the exact V1 Linux baseline authority. Only
    /// preserve-caller baseline grants are projected; private and delegated
    /// grants never become a V1 authorization.
    pub fn baseline_v1_projection(&self) -> Result<PolicyRegistryV1, String> {
        self.validate()?;
        let mut profiles = BoundedVec::default();
        for profile in self.profiles.as_slice() {
            if profile.profile == ProfileKindV2::LinuxUnixCreateV1 {
                profiles
                    .try_push(ProfileDefinitionV1 {
                        profile: BaselineProfile::LinuxUnixCreate,
                        reference: profile.reference.clone(),
                        enabled: profile.enabled,
                        qualification_digest: profile.qualification_digest.clone(),
                    })
                    .map_err(|_| "V1 baseline profile projection exceeds bound")?;
            }
        }
        let mut grants = BoundedVec::default();
        for grant in self.grants.as_slice() {
            if grant.profile == BaselineProfile::LinuxUnixCreate.reference()
                && grant.execution_identity == ExecutionIdentityRequestV2::PreserveCaller
            {
                grants
                    .try_push(PolicyGrantV1 {
                        id: grant.id.clone(),
                        revision: grant.revision,
                        profile: grant.profile.clone(),
                        ceiling: grant.ceiling.clone(),
                        enabled: grant.enabled,
                        callers: grant.callers.clone(),
                        approved_plans: grant.approved_plans.clone(),
                    })
                    .map_err(|_| "V1 baseline grant projection exceeds bound")?;
            }
        }
        let projected = PolicyRegistryV1 {
            schema_version: Default::default(),
            profiles,
            grants,
            active_attempt_disposition: self.active_attempt_disposition,
        };
        projected.validate()?;
        Ok(projected)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > limits::REGISTRY_BYTES {
            return Err("policy registry exceeds byte limit".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let registry: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        registry.validate()?;
        Ok(registry)
    }

    pub fn validate(&self) -> Result<(), String> {
        let profiles = self.profiles.as_slice();
        for (index, profile) in profiles.iter().enumerate() {
            if profile.reference != profile.profile.reference()
                || profiles[..index]
                    .iter()
                    .any(|prior| prior.reference.id == profile.reference.id)
            {
                return Err("invalid or duplicate V2 profile definition".into());
            }
        }
        let identities = self.execution_identities.as_slice();
        for (index, identity) in identities.iter().enumerate() {
            identity.validate()?;
            if identities[..index]
                .iter()
                .any(|prior| prior.reference.id == identity.reference.id)
            {
                return Err("duplicate execution identity".into());
            }
        }
        let grants = self.grants.as_slice();
        for (index, grant) in grants.iter().enumerate() {
            if grants[..index].iter().any(|prior| prior.id == grant.id)
                || grant.callers.as_slice().is_empty()
                || grant.approved_plans.as_slice().is_empty()
                || !profiles.iter().any(|profile| {
                    profile.reference == grant.profile
                        && ceiling_contains(&grant.ceiling, &profile.profile.ceiling())
                })
            {
                return Err("invalid V2 grant identity, profile or selectors".into());
            }
            for (caller_index, caller) in grant.callers.as_slice().iter().enumerate() {
                if !matches!(caller, CallerSelector::Linux { .. })
                    || grant.callers.as_slice()[..caller_index].contains(caller)
                {
                    return Err("V2 caller must be a unique Linux identity".into());
                }
            }
            for (plan_index, plan) in grant.approved_plans.as_slice().iter().enumerate() {
                if grant.approved_plans.as_slice()[..plan_index].contains(plan) {
                    return Err("duplicate V2 approved plan".into());
                }
            }
            if let ExecutionIdentityRequestV2::AdministratorProfile { reference } =
                &grant.execution_identity
            {
                if !identities.iter().any(|identity| {
                    identity.reference == *reference && (!grant.enabled || identity.enabled)
                }) {
                    return Err("V2 grant execution identity is absent or disabled".into());
                }
                if !profiles.iter().any(|profile| {
                    profile.reference == grant.profile
                        && profile.profile == ProfileKindV2::LinuxTcp4PrivateV1
                }) {
                    return Err("delegated identity requires private Linux profile".into());
                }
            }
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        self.validate()?;
        let mut encoder = Encoder::new(b"authorization-snapshot-v2", limits::REGISTRY_BYTES)?;
        let mut profiles: Vec<_> = self.profiles.as_slice().iter().collect();
        profiles.sort_by_key(|profile| &profile.reference.id);
        encoder.count(profiles.len())?;
        for profile in profiles {
            encoder.id(&profile.reference.id)?;
            encoder.digest(&profile.reference.semantic_digest)?;
            encoder.byte(u8::from(profile.enabled))?;
            encoder.digest(&profile.qualification_digest)?;
        }
        let mut identities: Vec<_> = self.execution_identities.as_slice().iter().collect();
        identities.sort_by_key(|identity| &identity.reference.id);
        encoder.count(identities.len())?;
        for identity in identities {
            encoder.id(&identity.reference.id)?;
            encoder.digest(&identity.reference.semantic_digest)?;
            encoder.byte(u8::from(identity.enabled))?;
            encoder.u64(u64::from(identity.uid.get()))?;
            encoder.u64(u64::from(identity.gid.get()))?;
            let mut groups: Vec<_> = identity.supplementary_groups.as_slice().iter().collect();
            groups.sort();
            encoder.count(groups.len())?;
            for group in groups {
                encoder.u64(u64::from(group.get()))?;
            }
            let mut entrypoints: Vec<_> = identity.entrypoints.as_slice().iter().collect();
            entrypoints.sort_by_key(|entrypoint| &entrypoint.id);
            encoder.count(entrypoints.len())?;
            for entrypoint in entrypoints {
                encoder.id(&entrypoint.id)?;
                encoder.count(entrypoint.absolute_path.as_str().len())?;
                encoder.raw(entrypoint.absolute_path.as_str().as_bytes())?;
                encoder.u64(entrypoint.size.get())?;
                encoder.digest(&entrypoint.sha256)?;
            }
        }
        let mut grants: Vec<_> = self.grants.as_slice().iter().collect();
        grants.sort_by_key(|grant| &grant.id);
        encoder.count(grants.len())?;
        for grant in grants {
            encoder.id(&grant.id)?;
            encoder.u64(grant.revision.get())?;
            encoder.id(&grant.profile.id)?;
            encoder.digest(&grant.profile.semantic_digest)?;
            encode_ceiling(&mut encoder, &grant.ceiling)?;
            encoder.byte(u8::from(grant.enabled))?;
            let mut callers: Vec<_> = grant.callers.as_slice().iter().collect();
            callers.sort_by_key(|caller| match caller {
                CallerSelector::Linux { uid } => *uid,
                CallerSelector::Windows { .. } => unreachable!("validated V2 caller"),
            });
            encoder.count(callers.len())?;
            for caller in callers {
                match caller {
                    CallerSelector::Linux { uid } => {
                        encoder.byte(1)?;
                        encoder.raw(&uid.to_be_bytes())?;
                    }
                    CallerSelector::Windows { .. } => unreachable!("validated V2 caller"),
                }
            }
            let mut plans: Vec<_> = grant.approved_plans.as_slice().iter().collect();
            plans.sort_by_key(|plan| plan.bytes());
            encoder.count(plans.len())?;
            for plan in plans {
                encoder.digest(plan)?;
            }
            encode_identity_request(&mut encoder, &grant.execution_identity)?;
        }
        encoder.byte(match self.active_attempt_disposition {
            GrantChangeDisposition::DrainExisting => 1,
            GrantChangeDisposition::RevokeActive => 2,
        })?;
        Ok(hash_bytes(&encoder.finish()))
    }
}

fn encode_identity_request(
    encoder: &mut Encoder,
    identity: &ExecutionIdentityRequestV2,
) -> Result<(), String> {
    match identity {
        ExecutionIdentityRequestV2::PreserveCaller => encoder.byte(1),
        ExecutionIdentityRequestV2::AdministratorProfile { reference } => {
            encoder.byte(2)?;
            encoder.id(&reference.id)?;
            encoder.digest(&reference.semantic_digest)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionCodeV2 {
    ProfileNotAuthorized,
    ProfileDigestMismatch,
    PolicyEpochStale,
    PolicyIncompatible,
    FeatureNotEnforceable,
    CallerEnvelopeIncompatible,
    DescriptorAuthorityIncompatible,
    HostPrerequisiteUnavailable,
    EnforcementInstallFailed,
    EnforcementReadbackFailed,
    PolicyDrift,
    ExecutionIdentityNotAuthorized,
    ExecutionIdentityUnavailable,
    EntrypointAuthorityMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConflictV2 {
    pub requirement: Option<RequirementId>,
    pub code: AdmissionCodeV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRejectionV2 {
    pub code: AdmissionCodeV2,
    pub conflicts: BoundedVec<AdmissionConflictV2, { limits::CONFLICTS }>,
    pub remaining_conflicts: u32,
}
impl AdmissionRejectionV2 {
    pub fn single(code: AdmissionCodeV2) -> Self {
        Self {
            code,
            conflicts: BoundedVec::default(),
            remaining_conflicts: 0,
        }
    }
}

/// A candidate run can test the production policy predicate without acquiring
/// launch authority. This value deliberately contains neither a grant nor an
/// admission snapshot and cannot be promoted into either one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidatePolicyDecisionV2 {
    Accepted,
    Rejected(AdmissionRejectionV2),
}

/// Evaluate the exact predicate used by ordinary V2 admission for a protected
/// candidate fixture. The caller must authenticate the candidate registry,
/// caller, and H0 qualification input independently. Even `Accepted` is only
/// a decision observation: this function does not verify installed Q/H1 or
/// allocate an attempt. The production path uses `resolve_v2` directly and
/// must still acquire its installed authority lease.
pub fn evaluate_candidate_policy_v2(
    registry: &PolicyRegistryV2,
    current_epoch: &PolicyEpoch,
    request: &WorkloadContractV2,
    authenticated_caller: &CallerSelector,
    native_profile: ProfileKindV2,
    candidate_qualification: &DiagnosticSha256,
) -> CandidatePolicyDecisionV2 {
    match resolve_v2(
        registry,
        current_epoch,
        request,
        authenticated_caller,
        native_profile,
        candidate_qualification,
    ) {
        Ok(_) => CandidatePolicyDecisionV2::Accepted,
        Err(rejection) => CandidatePolicyDecisionV2::Rejected(rejection),
    }
}

/// Resolves static administrator authority and functional compatibility.
/// Native caller/entrypoint/filter/namespace checks remain mandatory before
/// the provider may commit a checkpoint or release the target.
pub fn resolve_v2<'a>(
    registry: &'a PolicyRegistryV2,
    current_epoch: &PolicyEpoch,
    request: &WorkloadContractV2,
    authenticated_caller: &CallerSelector,
    native_profile: ProfileKindV2,
    qualification: &DiagnosticSha256,
) -> Result<&'a PolicyGrantV2, AdmissionRejectionV2> {
    use AdmissionCodeV2 as Code;
    let reject = AdmissionRejectionV2::single;
    if registry.validate().is_err() || request.validate().is_err() {
        return Err(reject(Code::PolicyIncompatible));
    }
    if !matches!(authenticated_caller, CallerSelector::Linux { .. }) {
        return Err(reject(Code::ProfileNotAuthorized));
    }
    let grant = registry
        .grants
        .as_slice()
        .iter()
        .find(|grant| {
            grant.id == request.authorization.grant_id
                && grant.revision == request.authorization.grant_revision
                && grant.enabled
                && grant.callers.as_slice().contains(authenticated_caller)
                && grant
                    .approved_plans
                    .as_slice()
                    .contains(&request.workload_plan_digest)
                && request.authorization.approved_plan_digest == request.workload_plan_digest
        })
        .ok_or_else(|| reject(Code::ProfileNotAuthorized))?;
    if current_epoch != &request.expected_epoch {
        return Err(reject(Code::PolicyEpochStale));
    }
    if grant.profile != request.authorized_profile {
        return Err(reject(Code::ProfileDigestMismatch));
    }
    let profile = registry
        .profiles
        .as_slice()
        .iter()
        .find(|profile| profile.reference == grant.profile && profile.enabled)
        .ok_or_else(|| reject(Code::ProfileNotAuthorized))?;
    if profile.profile != native_profile || &profile.qualification_digest != qualification {
        return Err(reject(Code::HostPrerequisiteUnavailable));
    }
    if grant.execution_identity != request.execution_identity {
        return Err(reject(Code::ExecutionIdentityNotAuthorized));
    }
    if let ExecutionIdentityRequestV2::AdministratorProfile { reference } =
        &request.execution_identity
    {
        if !registry
            .execution_identities
            .as_slice()
            .iter()
            .any(|identity| identity.enabled && identity.reference == *reference)
        {
            return Err(reject(Code::ExecutionIdentityUnavailable));
        }
    }
    if !ceiling_contains(&grant.ceiling, &request.ceiling)
        || !ceiling_contains(&request.ceiling, &profile.profile.ceiling())
    {
        return Err(reject(Code::PolicyIncompatible));
    }
    let mut requirements: Vec<_> = request.requirements.as_slice().iter().collect();
    requirements.sort_by_key(|requirement| requirement.id());
    let mut conflicts = BoundedVec::default();
    let mut remaining_conflicts = 0;
    for requirement in requirements {
        let code = match (native_profile, requirement) {
            (
                ProfileKindV2::LinuxUnixCreateV1,
                RequirementV1::UnixSocketCreation { .. } | RequirementV1::UnixSocketPair { .. },
            ) => None,
            (
                ProfileKindV2::LinuxUnixCreateV1,
                RequirementV1::DenialExercise {
                    operation: DeniedOperation::InetSocketCreation,
                    ..
                },
            ) => None,
            (
                ProfileKindV2::LinuxTcp4PrivateV1,
                RequirementV1::Tcp {
                    family: IpFamily::V4,
                    scope: TcpScope::AttemptPrivateStack,
                    peer,
                    ..
                },
            ) => match peer {
                TcpPeerRequirement::ExactAddress {
                    endpoint: TcpEndpoint::V4 { address, .. },
                } if !std::net::Ipv4Addr::from(*address).is_loopback() => {
                    Some(Code::PolicyIncompatible)
                }
                _ => None,
            },
            (
                ProfileKindV2::LinuxTcp4PrivateV1,
                RequirementV1::DenialExercise {
                    operation: DeniedOperation::NamedUnixSocketCreation,
                    ..
                },
            ) => None,
            (_, RequirementV1::Tcp { .. }) => Some(Code::PolicyIncompatible),
            (
                ProfileKindV2::LinuxTcp4PrivateV1,
                RequirementV1::DenialExercise {
                    operation: DeniedOperation::InetSocketCreation,
                    ..
                },
            ) => Some(Code::PolicyIncompatible),
            _ => Some(Code::FeatureNotEnforceable),
        };
        if let Some(code) = code {
            if conflicts
                .try_push(AdmissionConflictV2 {
                    requirement: Some(requirement.id().clone()),
                    code,
                })
                .is_err()
            {
                remaining_conflicts += 1;
            }
        }
    }
    if let Some(first) = conflicts.as_slice().first() {
        return Err(AdmissionRejectionV2 {
            code: first.code,
            conflicts,
            remaining_conflicts,
        });
    }
    Ok(grant)
}
