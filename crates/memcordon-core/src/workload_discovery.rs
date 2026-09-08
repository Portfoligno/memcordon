//! Authenticated, caller-filtered discovery. Discovery conveys no launch authority.
use crate::workload_contract::{
    AuthorizationRef, ContractVersionOne, NetworkCeilingV1, PolicyEpoch, ProfileRef,
};
use crate::workload_registry::{BaselineProfile, CallerSelector, PolicyRegistryV1};
use crate::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiscoveryReportV1 {
    Authenticated { discovery: WorkloadDiscoveryV1 },
    Unavailable { reason: BoundedText<256> },
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverableGrantV1 {
    pub authorization: AuthorizationRef,
    pub ceiling: NetworkCeilingV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadDiscoveryV1 {
    pub schema_version: ContractVersionOne,
    pub provider: PublicProviderBindingV1,
    pub boot_identity: BoundedText<128>,
    pub epoch: Option<PolicyEpoch>,
    pub registry_digest: Option<DiagnosticSha256>,
    pub catalog_digest: DiagnosticSha256,
    pub profile: ProfileRef,
    pub supported: bool,
    pub available: bool,
    pub qualification_digest: DiagnosticSha256,
    pub restriction: crate::workload_evidence::BaselineRestrictionObservationV1,
    pub ceiling: NetworkCeilingV1,
    pub grants: BoundedVec<DiscoverableGrantV1, 2048>,
    pub complete: bool,
    pub cache_ttl_seconds: u32,
    pub maximum_live_bindings: u32,
    pub maximum_snapshots: u32,
    pub target_authorized: crate::workload_evidence::False,
}

impl WorkloadDiscoveryV1 {
    pub fn authenticated(
        registry: Option<(&PolicyRegistryV1, &PolicyEpoch)>,
        caller: &CallerSelector,
        profile: BaselineProfile,
        qualification_digest: DiagnosticSha256,
        provider: PublicProviderBindingV1,
        boot_identity: BoundedText<128>,
    ) -> Result<Self, String> {
        let mut grants = BoundedVec::default();
        let mut available = false;
        let (epoch, registry_digest) = if let Some((registry, epoch)) = registry {
            registry.validate()?;
            available = registry.profiles.as_slice().iter().any(|entry| {
                entry.enabled
                    && entry.profile == profile
                    && entry.reference == profile.reference()
                    && entry.qualification_digest == qualification_digest
            });
            for grant in registry.grants.as_slice().iter().filter(|grant| {
                grant.enabled
                    && grant.profile == profile.reference()
                    && grant.callers.as_slice().contains(caller)
            }) {
                for plan in grant.approved_plans.as_slice() {
                    grants
                        .try_push(DiscoverableGrantV1 {
                            authorization: AuthorizationRef {
                                grant_id: grant.id.clone(),
                                grant_revision: grant.revision,
                                approved_plan_digest: plan.clone(),
                            },
                            ceiling: grant.ceiling.clone(),
                        })
                        .map_err(|_| "caller discovery grant capacity exceeded".to_owned())?;
                }
            }
            (Some(epoch.clone()), Some(registry.canonical_digest()?))
        } else {
            (None, None)
        };
        let catalog_digest = DiagnosticSha256::try_from(
            BoundedText::new(&crate::runtime_manifest::baseline_catalog_digest(
                profile == BaselineProfile::WindowsHostNetworkExternal,
            ))
            .map_err(str::to_owned)?,
        )
        .map_err(str::to_owned)?;
        let result = Self {
            schema_version: ContractVersionOne::default(),
            provider,
            boot_identity,
            epoch,
            registry_digest,
            catalog_digest,
            profile: profile.reference(),
            supported: true,
            available,
            qualification_digest,
            restriction: crate::workload_evidence::baseline_observation(profile),
            ceiling: profile.ceiling(),
            grants,
            complete: true,
            cache_ttl_seconds: 60,
            maximum_live_bindings: 256,
            maximum_snapshots: 16,
            target_authorized: crate::workload_evidence::False::default(),
        };
        if serde_json::to_vec(&result)
            .map_err(|error| error.to_string())?
            .len()
            > crate::workload_limits::PUBLIC_OBJECT_BYTES
        {
            return Err("caller discovery exceeds public object capacity".into());
        }
        Ok(result)
    }

    pub fn validate(&self, profile: BaselineProfile) -> bool {
        let grants = self.grants.as_slice();
        if grants.iter().enumerate().any(|(index, grant)| {
            !crate::workload_registry::ceiling_contains(&grant.ceiling, &profile.ceiling())
                || grants[..index]
                    .iter()
                    .any(|previous| previous.authorization == grant.authorization)
        }) || serde_json::to_vec(self).map_or(true, |bytes| {
            bytes.len() > crate::workload_limits::PUBLIC_OBJECT_BYTES
        }) {
            return false;
        }
        self.provider.is_consistent()
            && !self.boot_identity.as_str().is_empty()
            && self.profile == profile.reference()
            && self.ceiling == profile.ceiling()
            && self.restriction == crate::workload_evidence::baseline_observation(profile)
            && String::from(self.catalog_digest.clone())
                == crate::runtime_manifest::baseline_catalog_digest(
                    profile == BaselineProfile::WindowsHostNetworkExternal,
                )
            && self.epoch.is_some() == self.registry_digest.is_some()
            && self.supported
            && self.complete
            && self.cache_ttl_seconds <= 60
            && self.maximum_live_bindings == 256
            && self.maximum_snapshots == 16
            && (self.epoch.is_some() || (!self.available && self.grants.as_slice().is_empty()))
    }
}
