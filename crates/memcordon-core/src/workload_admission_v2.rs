//! Frozen V2 provider authority. This is a private admission record, not a
//! public claim that the optional native profile is installed or released.

use serde::{Deserialize, Serialize};

use crate::workload_codec::{Encoder, contract_digest_v2, hash_bytes};
use crate::workload_contract::{
    ExecutionIdentityRequestV2, Nonce128, PolicyEpoch, WorkloadContractV2,
};
use crate::workload_evidence_v2::QualifiedNativeAbiV2;
use crate::workload_limits as limits;
use crate::workload_registry::{CallerSelector, ceiling_contains};
use crate::workload_registry_v2::{
    LinuxExecutionIdentityV2, PolicyGrantV2, PolicyRegistryV2, ProfileDefinitionV2, ProfileKindV2,
    resolve_v2,
};
use crate::{BoundedText, DiagnosticSha256, workload_contract::reject_duplicate_json_keys};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBindingV2 {
    pub attempt_id: BoundedText<{ limits::IDENTIFIER_BYTES }>,
    pub admission_digest: DiagnosticSha256,
    pub caller_envelope_digest: DiagnosticSha256,
    pub native_invocation_digest: DiagnosticSha256,
}

impl AttemptBindingV2 {
    pub fn from_admission(
        attempt_id: BoundedText<{ limits::IDENTIFIER_BYTES }>,
        admission: &ProviderAdmissionSnapshotV2,
    ) -> Result<Self, String> {
        Ok(Self {
            attempt_id,
            admission_digest: admission.canonical_digest()?,
            caller_envelope_digest: admission.caller_envelope_digest.clone(),
            native_invocation_digest: admission.native_invocation_digest.clone(),
        })
    }

    pub fn matches_admission(&self, admission: &ProviderAdmissionSnapshotV2) -> bool {
        admission
            .canonical_digest()
            .is_ok_and(|digest| digest == self.admission_digest)
            && self.caller_envelope_digest == admission.caller_envelope_digest
            && self.native_invocation_digest == admission.native_invocation_digest
    }

    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        let mut encoder = Encoder::new(b"private-attempt-binding-v2", limits::CONTRACT_BYTES)?;
        encoder.count(self.attempt_id.as_str().len())?;
        encoder.raw(self.attempt_id.as_str().as_bytes())?;
        encoder.digest(&self.admission_digest)?;
        encoder.digest(&self.caller_envelope_digest)?;
        encoder.digest(&self.native_invocation_digest)?;
        Ok(hash_bytes(&encoder.finish()))
    }
}

/// All authorization objects needed after an activation changes are copied
/// here. The live activation is still rechecked before any release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdmissionSnapshotV2 {
    pub request: WorkloadContractV2,
    pub request_digest: DiagnosticSha256,
    pub registry_digest: DiagnosticSha256,
    pub epoch: PolicyEpoch,
    pub grant: PolicyGrantV2,
    pub profile: ProfileDefinitionV2,
    pub identity: LinuxExecutionIdentityV2,
    pub qualification_digest: DiagnosticSha256,
    pub package_generation_digest: DiagnosticSha256,
    pub native_abi: QualifiedNativeAbiV2,
    pub admission_nonce: Nonce128,
    pub caller_envelope_reference: Nonce128,
    pub caller_envelope_digest: DiagnosticSha256,
    pub native_invocation_digest: DiagnosticSha256,
    pub caller: CallerSelector,
}

impl ProviderAdmissionSnapshotV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn freeze(
        registry: &PolicyRegistryV2,
        epoch: &PolicyEpoch,
        request: &WorkloadContractV2,
        caller: &CallerSelector,
        qualification_digest: DiagnosticSha256,
        package_generation_digest: DiagnosticSha256,
        native_abi: QualifiedNativeAbiV2,
        admission_nonce: Nonce128,
        caller_envelope_reference: Nonce128,
        caller_envelope_digest: DiagnosticSha256,
        native_invocation_digest: DiagnosticSha256,
    ) -> Result<Self, String> {
        let grant = resolve_v2(
            registry,
            epoch,
            request,
            caller,
            ProfileKindV2::LinuxTcp4PrivateV1,
            &qualification_digest,
        )
        .map_err(|error| format!("V2 admission rejected: {:?}", error.code))?
        .clone();
        let profile = registry
            .profiles
            .as_slice()
            .iter()
            .find(|profile| profile.reference == grant.profile && profile.enabled)
            .ok_or("V2 selected profile absent")?
            .clone();
        let ExecutionIdentityRequestV2::AdministratorProfile { reference } =
            &request.execution_identity
        else {
            return Err("private V2 authority requires an administrator identity".into());
        };
        let identity = registry
            .execution_identities
            .as_slice()
            .iter()
            .find(|identity| identity.reference == *reference && identity.enabled)
            .ok_or("V2 selected identity absent")?
            .clone();
        let snapshot = Self {
            request: request.clone(),
            request_digest: contract_digest_v2(request)?,
            registry_digest: registry.canonical_digest()?,
            epoch: epoch.clone(),
            grant,
            profile,
            identity,
            qualification_digest,
            package_generation_digest,
            native_abi,
            admission_nonce,
            caller_envelope_reference,
            caller_envelope_digest,
            native_invocation_digest,
            caller: caller.clone(),
        };
        snapshot.validate_against(registry)?;
        Ok(snapshot)
    }

    /// Validates both frozen internal relationships and the retained immutable
    /// registry snapshot. A changed live activation must be checked separately.
    pub fn validate_against(&self, registry: &PolicyRegistryV2) -> Result<(), String> {
        registry.validate()?;
        self.validate()?;
        if registry.canonical_digest()? != self.registry_digest
            || !registry.grants.as_slice().contains(&self.grant)
            || !registry.profiles.as_slice().contains(&self.profile)
            || !registry
                .execution_identities
                .as_slice()
                .contains(&self.identity)
        {
            return Err("V2 frozen authority differs from registry snapshot".into());
        }
        resolve_v2(
            registry,
            &self.epoch,
            &self.request,
            &self.caller,
            ProfileKindV2::LinuxTcp4PrivateV1,
            &self.qualification_digest,
        )
        .map_err(|error| format!("V2 frozen authorization rejected: {:?}", error.code))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        self.request.validate()?;
        self.identity.validate()?;
        if self.request_digest != contract_digest_v2(&self.request)?
            || self.request.expected_epoch != self.epoch
            || self.request.authorization.grant_id != self.grant.id
            || self.request.authorization.grant_revision != self.grant.revision
            || self.request.authorization.approved_plan_digest != self.request.workload_plan_digest
            || !self
                .grant
                .approved_plans
                .as_slice()
                .contains(&self.request.workload_plan_digest)
            || !self.grant.callers.as_slice().contains(&self.caller)
            || !self.grant.enabled
            || self.grant.profile != self.profile.reference
            || self.profile.reference != self.profile.profile.reference()
            || self.request.authorized_profile != self.profile.reference
            || !self.profile.enabled
            || self.profile.profile != ProfileKindV2::LinuxTcp4PrivateV1
            || self.profile.qualification_digest != self.qualification_digest
            || self.grant.execution_identity != self.request.execution_identity
            || !ceiling_contains(&self.grant.ceiling, &self.request.ceiling)
            || !ceiling_contains(&self.request.ceiling, &self.profile.profile.ceiling())
            || self.request.execution_identity
                != (ExecutionIdentityRequestV2::AdministratorProfile {
                    reference: self.identity.reference.clone(),
                })
            || !self.identity.enabled
            || !matches!(self.caller, CallerSelector::Linux { .. })
        {
            return Err("V2 frozen admission binding differs".into());
        }
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > limits::REGISTRY_BYTES {
            return Err("V2 frozen admission exceeds bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let snapshot: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        self.validate()?;
        let mut encoder = Encoder::new(b"provider-admission-snapshot-v2", limits::REGISTRY_BYTES)?;
        let json = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        encoder.u64(u64::try_from(json.len()).map_err(|_| "V2 admission length exceeds u64")?)?;
        encoder.raw(&json)?;
        Ok(hash_bytes(&encoder.finish()))
    }
}
