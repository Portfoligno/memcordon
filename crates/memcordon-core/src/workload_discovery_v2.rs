//! Advisory V2 Linux discovery; package state is not launch authorization.

use crate::workload_codec::{Encoder, hash_bytes};
use crate::workload_contract::{
    AuthorizationRef, ContractVersionTwo, ExecutionIdentityRefV2, ExecutionIdentityRequestV2,
    NetworkCeilingV1, PolicyEpoch, ProfileRef,
};
use crate::workload_evidence::False;
use crate::workload_limits as limits;
use crate::workload_registry::{CallerSelector, ceiling_contains};
use crate::workload_registry_v2::{PolicyRegistryV2, ProfileKindV2};
use crate::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiscoveryReportV2 {
    Authenticated { discovery: Box<WorkloadDiscoveryV2> },
    Unavailable { reason: BoundedText<256> },
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProfilePackageStateV2 {
    NotInstalled,
    InstalledDisabled,
    EnabledUnqualified,
    EnabledQualified {
        qualification_digest: DiagnosticSha256,
    },
    Unavailable,
}

impl ProfilePackageStateV2 {
    fn qualification_digest(&self) -> Option<&DiagnosticSha256> {
        match self {
            Self::EnabledQualified {
                qualification_digest,
            } => Some(qualification_digest),
            _ => None,
        }
    }
}

/// These facts must come from protected package/host inspection, not request
/// JSON. They remain advisory until the provider revalidates them at launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderProfileStateV2 {
    pub profile: ProfileKindV2,
    pub supported: bool,
    pub package_state: ProfilePackageStateV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverableGrantV2 {
    pub authorization: AuthorizationRef,
    pub ceiling: NetworkCeilingV1,
    pub execution_identity: ExecutionIdentityRequestV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverableProfileV2 {
    pub profile: ProfileRef,
    pub supported: bool,
    pub package_state: ProfilePackageStateV2,
    pub required_qualification_digest: Option<DiagnosticSha256>,
    pub available: bool,
    pub permitted_execution_identities:
        BoundedVec<ExecutionIdentityRefV2, { limits::EXECUTION_IDENTITIES }>,
    pub grants: BoundedVec<DiscoverableGrantV2, { limits::GRANTS * limits::PLANS_PER_GRANT }>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadDiscoveryV2 {
    pub schema_version: ContractVersionTwo,
    pub provider: PublicProviderBindingV1,
    pub boot_identity: BoundedText<128>,
    pub epoch: Option<PolicyEpoch>,
    pub registry_digest: Option<DiagnosticSha256>,
    pub catalog_digest: DiagnosticSha256,
    pub profiles: BoundedVec<DiscoverableProfileV2, { limits::PROFILES }>,
    pub complete: bool,
    pub cache_ttl_seconds: u32,
    pub target_authorized: False,
}

pub fn profile_catalog_digest_v2() -> DiagnosticSha256 {
    let mut profiles = [
        ProfileKindV2::LinuxUnixCreateV1.reference(),
        ProfileKindV2::LinuxTcp4PrivateV1.reference(),
    ];
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let mut encoder =
        Encoder::new(b"profile-catalog-v2", limits::CONTRACT_BYTES).expect("fixed catalog fits");
    encoder.count(profiles.len()).expect("fixed catalog fits");
    for profile in profiles {
        encoder.id(&profile.id).expect("fixed profile id fits");
        encoder
            .digest(&profile.semantic_digest)
            .expect("fixed profile digest fits");
    }
    hash_bytes(&encoder.finish())
}

impl WorkloadDiscoveryV2 {
    pub fn authenticated(
        registry: Option<(&PolicyRegistryV2, &PolicyEpoch)>,
        caller: &CallerSelector,
        states: &[ProviderProfileStateV2],
        provider: PublicProviderBindingV1,
        boot_identity: BoundedText<128>,
    ) -> Result<Self, String> {
        if !matches!(caller, CallerSelector::Linux { .. })
            || states.len() != 2
            || !states
                .iter()
                .any(|state| state.profile == ProfileKindV2::LinuxUnixCreateV1)
            || !states
                .iter()
                .any(|state| state.profile == ProfileKindV2::LinuxTcp4PrivateV1)
        {
            return Err("incomplete or non-Linux V2 discovery catalogue".into());
        }
        if states.iter().any(|state| {
            state.profile == ProfileKindV2::LinuxTcp4PrivateV1
                && (state.supported
                    || matches!(
                        state.package_state,
                        ProfilePackageStateV2::EnabledQualified { .. }
                            | ProfilePackageStateV2::EnabledUnqualified
                    ))
        }) {
            return Err("private TCP profile has no qualified native discovery source".into());
        }
        let (epoch, registry_digest) = if let Some((registry, epoch)) = registry {
            registry.validate()?;
            (Some(epoch.clone()), Some(registry.canonical_digest()?))
        } else {
            (None, None)
        };
        let mut ordered_states: Vec<_> = states.iter().collect();
        ordered_states.sort_by_key(|state| state.profile.id());
        let mut profiles = BoundedVec::default();
        for state in ordered_states {
            let reference = state.profile.reference();
            let registry_profile = registry.and_then(|(registry, _)| {
                registry
                    .profiles
                    .as_slice()
                    .iter()
                    .find(|profile| profile.reference == reference)
            });
            let available = state.supported
                && registry_profile.is_some_and(|profile| {
                    profile.enabled
                        && state.package_state.qualification_digest()
                            == Some(&profile.qualification_digest)
                });
            let mut visible_grants = Vec::new();
            let mut visible_identities = Vec::new();
            if let Some((registry, _)) = registry {
                for grant in registry.grants.as_slice().iter().filter(|grant| {
                    grant.enabled
                        && grant.profile == reference
                        && grant.callers.as_slice().contains(caller)
                }) {
                    if let ExecutionIdentityRequestV2::AdministratorProfile { reference } =
                        &grant.execution_identity
                    {
                        if !visible_identities.contains(reference) {
                            visible_identities.push(reference.clone());
                        }
                    }
                    for plan in grant.approved_plans.as_slice() {
                        visible_grants.push(DiscoverableGrantV2 {
                            authorization: AuthorizationRef {
                                grant_id: grant.id.clone(),
                                grant_revision: grant.revision,
                                approved_plan_digest: plan.clone(),
                            },
                            ceiling: grant.ceiling.clone(),
                            execution_identity: grant.execution_identity.clone(),
                        });
                    }
                }
            }
            visible_grants.sort_by(|left, right| {
                left.authorization
                    .grant_id
                    .cmp(&right.authorization.grant_id)
                    .then_with(|| {
                        left.authorization
                            .grant_revision
                            .cmp(&right.authorization.grant_revision)
                    })
                    .then_with(|| {
                        left.authorization
                            .approved_plan_digest
                            .bytes()
                            .cmp(right.authorization.approved_plan_digest.bytes())
                    })
            });
            visible_identities
                .sort_by(|left: &ExecutionIdentityRefV2, right| left.id.cmp(&right.id));
            let mut grants = BoundedVec::default();
            for grant in visible_grants {
                grants
                    .try_push(grant)
                    .map_err(|_| "V2 discovery grant capacity exceeded")?;
            }
            let mut permitted_execution_identities = BoundedVec::default();
            for identity in visible_identities {
                permitted_execution_identities
                    .try_push(identity)
                    .map_err(|_| "V2 discovery identity capacity exceeded")?;
            }
            profiles
                .try_push(DiscoverableProfileV2 {
                    profile: reference,
                    supported: state.supported,
                    package_state: state.package_state.clone(),
                    required_qualification_digest: registry_profile
                        .map(|profile| profile.qualification_digest.clone()),
                    available,
                    permitted_execution_identities,
                    grants,
                })
                .map_err(|_| "V2 discovery profile capacity exceeded")?;
        }
        let discovery = Self {
            schema_version: ContractVersionTwo::default(),
            provider,
            boot_identity,
            epoch,
            registry_digest,
            catalog_digest: profile_catalog_digest_v2(),
            profiles,
            complete: true,
            cache_ttl_seconds: u32::try_from(limits::DISCOVERY_TTL_SECONDS)
                .expect("fixed discovery TTL fits u32"),
            target_authorized: False::default(),
        };
        if !discovery.validate() {
            return Err("invalid or oversized V2 discovery projection".into());
        }
        Ok(discovery)
    }

    pub fn validate(&self) -> bool {
        if !self.provider.is_consistent()
            || self.boot_identity.as_str().is_empty()
            || self.catalog_digest != profile_catalog_digest_v2()
            || self.epoch.is_some() != self.registry_digest.is_some()
            || !self.complete
            || self.cache_ttl_seconds > limits::DISCOVERY_TTL_SECONDS as u32
            || self.profiles.as_slice().len() != 2
            || serde_json::to_vec(self)
                .map_or(true, |bytes| bytes.len() > limits::PUBLIC_OBJECT_BYTES)
        {
            return false;
        }
        let profiles = self.profiles.as_slice();
        if profiles[0].profile.id >= profiles[1].profile.id
            || !profiles
                .iter()
                .any(|entry| entry.profile == ProfileKindV2::LinuxUnixCreateV1.reference())
            || !profiles
                .iter()
                .any(|entry| entry.profile == ProfileKindV2::LinuxTcp4PrivateV1.reference())
        {
            return false;
        }
        for entry in profiles {
            if entry.profile == ProfileKindV2::LinuxTcp4PrivateV1.reference()
                && (entry.supported
                    || entry.available
                    || matches!(
                        entry.package_state,
                        ProfilePackageStateV2::EnabledQualified { .. }
                            | ProfilePackageStateV2::EnabledUnqualified
                    ))
            {
                return false;
            }
            if entry.available
                && (!entry.supported
                    || self.epoch.is_none()
                    || entry.package_state.qualification_digest()
                        != entry.required_qualification_digest.as_ref())
            {
                return false;
            }
            let identities = entry.permitted_execution_identities.as_slice();
            if identities.windows(2).any(|pair| pair[0].id >= pair[1].id) {
                return false;
            }
            for identity in identities {
                if !entry.grants.as_slice().iter().any(|grant| {
                    matches!(&grant.execution_identity,
                        ExecutionIdentityRequestV2::AdministratorProfile { reference }
                            if reference == identity)
                }) {
                    return false;
                }
            }
            for grant in entry.grants.as_slice() {
                let profile = if entry.profile == ProfileKindV2::LinuxUnixCreateV1.reference() {
                    ProfileKindV2::LinuxUnixCreateV1
                } else {
                    ProfileKindV2::LinuxTcp4PrivateV1
                };
                if !ceiling_contains(&grant.ceiling, &profile.ceiling()) {
                    return false;
                }
                if let ExecutionIdentityRequestV2::AdministratorProfile { reference } =
                    &grant.execution_identity
                {
                    if profile != ProfileKindV2::LinuxTcp4PrivateV1
                        || !identities.contains(reference)
                    {
                        return false;
                    }
                }
            }
            let grants = entry.grants.as_slice();
            if grants.windows(2).any(|pair| {
                pair[0].authorization.grant_id > pair[1].authorization.grant_id
                    || (pair[0].authorization.grant_id == pair[1].authorization.grant_id
                        && pair[0].authorization.approved_plan_digest.bytes()
                            >= pair[1].authorization.approved_plan_digest.bytes())
            }) {
                return false;
            }
        }
        if self.epoch.is_none()
            && profiles
                .iter()
                .any(|entry| entry.available || !entry.grants.as_slice().is_empty())
        {
            return false;
        }
        true
    }
}
