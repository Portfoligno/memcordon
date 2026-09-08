//! Immutable, explicitly granted baseline profiles and deterministic admission.
use crate::workload_codec::{Encoder, encode_ceiling, hash_bytes};
use crate::workload_contract::*;
use crate::workload_limits as limits;

/// Private provider snapshot. Caller identities are excluded from public projections.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdmissionSnapshotV1 {
    pub request: WorkloadContractV1,
    pub request_digest: DiagnosticSha256,
    pub registry_digest: DiagnosticSha256,
    pub qualification_digest: DiagnosticSha256,
    pub admission_nonce: Nonce128,
    pub caller_invocation_reference: Nonce128,
    pub private_invocation_digest: DiagnosticSha256,
    pub caller: CallerSelector,
    pub native_profile: BaselineProfile,
}
impl ProviderAdmissionSnapshotV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.request.validate()?;
        if crate::workload_codec::contract_digest(&self.request)? != self.request_digest
            || self.request.authorized_profile != self.native_profile.reference()
        {
            return Err("provider admission snapshot request binding differs".into());
        }
        Ok(())
    }
}

pub fn ceiling_contains(ceiling: &NetworkCeilingV1, authority: &NetworkCeilingV1) -> bool {
    (ceiling.direct_socket_authority == authority.direct_socket_authority
        || (ceiling.direct_socket_authority == DirectSocketCeiling::ExternalHostPolicyAccepted
            && authority.direct_socket_authority
                == DirectSocketCeiling::PinnedLegacySocketFilterAccepted))
        && ceiling.unix_authority == authority.unix_authority
        && ceiling.external_socket_custody == authority.external_socket_custody
        && ceiling.credential_gains == authority.credential_gains
        && ceiling.mediated_communication == authority.mediated_communication
}
use crate::{BoundedText, BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineProfile {
    LinuxUnixCreate,
    WindowsHostNetworkExternal,
}
impl BaselineProfile {
    pub fn id(self) -> ProfileId {
        LogicalId::new(
            match self {
                Self::LinuxUnixCreate => "linux-unix-create-v1",
                Self::WindowsHostNetworkExternal => "windows-host-network-external-v1",
            }
            .into(),
        )
        .expect("fixed profile identifiers are valid")
    }
    pub fn ceiling(self) -> NetworkCeilingV1 {
        NetworkCeilingV1 {
            direct_socket_authority: match self {
                Self::LinuxUnixCreate => DirectSocketCeiling::PinnedLegacySocketFilterAccepted,
                Self::WindowsHostNetworkExternal => DirectSocketCeiling::ExternalHostPolicyAccepted,
            },
            unix_authority: UnixAuthorityCeiling::ExistingHostUnixAuthorityAccepted,
            external_socket_custody: ExternalSocketCeiling::ExistingStdioAuthorityAccepted,
            credential_gains: CredentialGainCeiling::ExistingCallerEnvelopeAccepted,
            mediated_communication:
                MediatedCommunicationCeiling::ExternalFilesystemAndStdioPolicyAccepted,
        }
    }
    pub fn semantic_bytes(self) -> Vec<u8> {
        let mut encoder = Encoder::new(b"profile-definition-v1", limits::CONTRACT_BYTES)
            .expect("fixed domain fits");
        encoder.id(&self.id()).expect("fixed identifier fits");
        encode_ceiling(&mut encoder, &self.ceiling()).expect("fixed ceiling fits");
        // Explicit baseline restriction and alternate-path knowledge tags.
        encoder
            .byte(match self {
                Self::LinuxUnixCreate => 1,
                Self::WindowsHostNetworkExternal => 2,
            })
            .expect("tag fits");
        encoder
            .byte(1)
            .expect("unknown alternate-path coverage tag fits");
        encoder.finish()
    }
    pub fn reference(self) -> ProfileRef {
        ProfileRef {
            id: self.id(),
            semantic_digest: hash_bytes(&self.semantic_bytes()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CallerSelector {
    Linux { uid: u32 },
    Windows { sid: BoundedText<184> },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantChangeDisposition {
    DrainExisting,
    RevokeActive,
}
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
pub struct PolicyGrantV1 {
    pub id: GrantId,
    pub revision: NonZeroU64,
    pub profile: ProfileRef,
    pub ceiling: NetworkCeilingV1,
    pub enabled: bool,
    pub callers: BoundedVec<CallerSelector, { limits::CALLERS_PER_GRANT }>,
    pub approved_plans: BoundedVec<DiagnosticSha256, { limits::PLANS_PER_GRANT }>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRegistryV1 {
    pub schema_version: ContractVersionOne,
    pub profiles: BoundedVec<ProfileDefinitionV1, { limits::PROFILES }>,
    pub grants: BoundedVec<PolicyGrantV1, { limits::GRANTS }>,
    pub active_attempt_disposition: GrantChangeDisposition,
}

impl PolicyRegistryV1 {
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
        super::workload_contract::reject_duplicate_json_keys(bytes)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionCode {
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
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConflictV1 {
    pub requirement: Option<RequirementId>,
    pub code: AdmissionCode,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRejectionV1 {
    pub code: AdmissionCode,
    pub conflicts: BoundedVec<AdmissionConflictV1, { limits::CONFLICTS }>,
    pub remaining_conflicts: u32,
}
impl AdmissionRejectionV1 {
    pub fn single(code: AdmissionCode) -> Self {
        Self {
            code,
            conflicts: BoundedVec::default(),
            remaining_conflicts: 0,
        }
    }
}

/// Caller must originate from authenticated OS channel acquisition, never request JSON.
pub fn resolve<'a>(
    registry: &'a PolicyRegistryV1,
    current_epoch: &PolicyEpoch,
    request: &WorkloadContractV1,
    caller: &CallerSelector,
    native_profile: BaselineProfile,
    qualification: &DiagnosticSha256,
) -> Result<&'a PolicyGrantV1, AdmissionRejectionV1> {
    let reject = AdmissionRejectionV1::single;
    let grant = registry
        .grants
        .as_slice()
        .iter()
        .find(|grant| {
            grant.id == request.authorization.grant_id
                && grant.revision == request.authorization.grant_revision
                && grant.enabled
                && grant.callers.as_slice().contains(caller)
                && grant
                    .approved_plans
                    .as_slice()
                    .contains(&request.workload_plan_digest)
                && request.authorization.approved_plan_digest == request.workload_plan_digest
        })
        .ok_or_else(|| reject(AdmissionCode::ProfileNotAuthorized))?;
    if current_epoch != &request.expected_epoch {
        return Err(reject(AdmissionCode::PolicyEpochStale));
    }
    if grant.profile != request.authorized_profile {
        return Err(reject(AdmissionCode::ProfileDigestMismatch));
    }
    let profile = registry
        .profiles
        .as_slice()
        .iter()
        .find(|profile| profile.reference == grant.profile && profile.enabled)
        .ok_or_else(|| reject(AdmissionCode::ProfileNotAuthorized))?;
    if profile.profile != native_profile || &profile.qualification_digest != qualification {
        return Err(reject(AdmissionCode::HostPrerequisiteUnavailable));
    }
    if !ceiling_contains(&grant.ceiling, &request.ceiling)
        || !ceiling_contains(&request.ceiling, &profile.profile.ceiling())
    {
        return Err(reject(AdmissionCode::PolicyIncompatible));
    }
    let mut requirements: Vec<_> = request.requirements.as_slice().iter().collect();
    requirements.sort_by_key(|requirement| requirement.id());
    let mut conflicts = BoundedVec::default();
    let mut remainder = 0;
    for requirement in requirements {
        let code = match requirement {
            RequirementV1::UnixSocketCreation { .. } | RequirementV1::UnixSocketPair { .. }
                if native_profile == BaselineProfile::LinuxUnixCreate =>
            {
                None
            }
            RequirementV1::Tcp {
                scope: TcpScope::HostSharedLoopback,
                ..
            } if native_profile == BaselineProfile::WindowsHostNetworkExternal => None,
            RequirementV1::Tcp { .. } => Some(AdmissionCode::PolicyIncompatible),
            RequirementV1::DenialExercise {
                operation: DeniedOperation::InetSocketCreation,
                ..
            } if native_profile == BaselineProfile::LinuxUnixCreate => None,
            _ => Some(AdmissionCode::FeatureNotEnforceable),
        };
        if let Some(code) = code {
            if conflicts
                .try_push(AdmissionConflictV1 {
                    requirement: Some(requirement.id().clone()),
                    code,
                })
                .is_err()
            {
                remainder += 1;
            }
        }
    }
    if let Some(first) = conflicts.as_slice().first() {
        return Err(AdmissionRejectionV1 {
            code: first.code,
            conflicts,
            remaining_conflicts: remainder,
        });
    }
    Ok(grant)
}
