//! Test-owned frozen V1 registry vectors; no production reader or permission API.
use memcordon_core::workload_codec::{Encoder, encode_ceiling, hash_bytes};
use memcordon_core::workload_contract::*;
use memcordon_core::workload_limits as limits;
use memcordon_core::workload_registry::{
    BaselineProfile, CallerSelector, GrantChangeDisposition, PolicyGrantV1, ceiling_contains,
};
use memcordon_core::{BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDefinitionV1 {
    pub profile: BaselineProfile,
    pub reference: ProfileRef,
    pub enabled: bool,
    pub qualification_digest: DiagnosticSha256,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRegistryV1 {
    pub schema_version: ContractVersionOne,
    pub profiles: BoundedVec<ProfileDefinitionV1, { limits::PROFILES }>,
    pub grants: BoundedVec<PolicyGrantV1, { limits::GRANTS }>,
    pub active_attempt_disposition: GrantChangeDisposition,
}

impl HistoricalRegistryV1 {
    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        self.validate()?;
        let mut encoder = Encoder::new(b"authorization-snapshot-v1", limits::REGISTRY_BYTES)?;
        let mut profiles: Vec<_> = self.profiles.as_slice().iter().collect();
        profiles.sort_by_key(|profile| &profile.reference.id);
        encoder.count(profiles.len())?;
        for profile in profiles {
            encoder.id(&profile.reference.id)?;
            encoder.digest(&profile.reference.semantic_digest)?;
            encoder.byte(u8::from(profile.enabled))?;
            encoder.digest(&profile.qualification_digest)?;
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
            let mut callers: Vec<Vec<u8>> = Vec::new();
            for caller in grant.callers.as_slice() {
                let mut bytes = Vec::new();
                match caller {
                    CallerSelector::Linux { uid } => {
                        bytes.push(1);
                        bytes.extend_from_slice(&uid.to_be_bytes());
                    }
                    CallerSelector::Windows { sid } => {
                        bytes.push(2);
                        let text = sid.as_str().as_bytes();
                        bytes.extend_from_slice(
                            &u16::try_from(text.len())
                                .map_err(|_| "caller SID exceeds canonical length")?
                                .to_be_bytes(),
                        );
                        bytes.extend_from_slice(text);
                    }
                }
                callers.push(bytes);
            }
            callers.sort();
            encoder.count(callers.len())?;
            for caller in callers {
                encoder.raw(&caller)?;
            }
            let mut plans: Vec<_> = grant.approved_plans.as_slice().iter().collect();
            plans.sort_by_key(|plan| plan.bytes());
            encoder.count(plans.len())?;
            for plan in plans {
                encoder.digest(plan)?;
            }
        }
        encoder.byte(match self.active_attempt_disposition {
            GrantChangeDisposition::DrainExisting => 1,
            GrantChangeDisposition::RevokeActive => 2,
        })?;
        Ok(hash_bytes(&encoder.finish()))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > limits::REGISTRY_BYTES {
            return Err("policy registry exceeds byte limit".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
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
                return Err("registry profile definition differs or duplicates an identity".into());
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
                return Err("invalid grant identity, profile, ceiling or empty selectors".into());
            }
            for (index, caller) in grant.callers.as_slice().iter().enumerate() {
                if let CallerSelector::Windows { sid } = caller {
                    if !valid_windows_sid(sid.as_str()) {
                        return Err("noncanonical Windows caller SID".into());
                    }
                }
                if grant.callers.as_slice()[..index].contains(caller) {
                    return Err("duplicate caller selector".into());
                }
            }
            for (index, plan) in grant.approved_plans.as_slice().iter().enumerate() {
                if grant.approved_plans.as_slice()[..index].contains(plan) {
                    return Err("duplicate approved plan".into());
                }
            }
        }
        Ok(())
    }
}

fn valid_windows_sid(text: &str) -> bool {
    let mut fields = text.split('-');
    if fields.next() != Some("S") || fields.next() != Some("1") {
        return false;
    }
    let canonical = |value: &str| {
        !value.is_empty()
            && (value == "0" || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit())
    };
    let Some(authority) = fields.next() else {
        return false;
    };
    if !canonical(authority)
        || !authority
            .parse::<u64>()
            .is_ok_and(|value| value < (1_u64 << 48))
    {
        return false;
    }
    let mut count = 0;
    for field in fields {
        count += 1;
        if count > 15 || !canonical(field) || field.parse::<u32>().is_err() {
            return false;
        }
    }
    count > 0
}
