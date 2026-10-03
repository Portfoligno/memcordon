//! Raw correlation facts retained by native checkpoint and retirement owners.
//! These serializable values do not grant permission to execute.

use crate::workload_codec::{Encoder, hash_bytes};
use crate::workload_contract::{Nonce128, PolicyEpoch, ProfileRef, WorkloadContractV2};
use crate::workload_limits as limits;
use crate::workload_registry::CallerSelector;
use crate::{BoundedText, DiagnosticSha256};
use serde::{Deserialize, Serialize};

/// Descriptive correlation retained for local revocation and native recovery.
/// Parsing or hashing this value cannot acquire a grant, lease, or native owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePrivateAdmissionSnapshot {
    pub format: String,
    pub revision: u32,
    pub request: WorkloadContractV2,
    pub request_sha256: DiagnosticSha256,
    pub invocation_sha256: DiagnosticSha256,
    pub caller: CallerSelector,
    pub registry_digest: DiagnosticSha256,
    pub epoch: PolicyEpoch,
    pub admission_nonce: Nonce128,
    pub profile_id: ProfileRef,
}
impl RuntimePrivateAdmissionSnapshot {
    pub fn validate(&self) -> Result<(), String> {
        self.request.validate()?;
        if self.format != "memcordon.private-admission-metadata"
            || self.revision != 1
            || crate::workload_codec::contract_digest_v2(&self.request)? != self.request_sha256
            || self.epoch != self.request.expected_epoch
            || self.profile_id != self.request.authorized_profile
            || !matches!(self.caller, CallerSelector::Linux { .. })
        {
            return Err("private admission metadata correlation differs".into());
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > limits::CONTRACT_ENVELOPE_BYTES {
            return Err("private admission metadata exceeds byte bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        self.validate()?;
        let mut encoder = Encoder::new(
            b"memcordon.private-admission-metadata/revision1",
            limits::PUBLIC_OBJECT_BYTES,
        )?;
        encoder.digest(&self.request_sha256)?;
        encoder.digest(&self.invocation_sha256)?;
        encoder.digest(&self.registry_digest)?;
        let CallerSelector::Linux { uid } = self.caller else {
            unreachable!("validated Linux correlation")
        };
        encoder.raw(&uid.to_be_bytes())?;
        encoder.raw(&self.epoch.service_instance.0)?;
        encoder.u64(self.epoch.revision.get())?;
        encoder.raw(&self.admission_nonce.0)?;
        encoder.id(&self.profile_id.id)?;
        encoder.digest(&self.profile_id.semantic_digest)?;
        Ok(hash_bytes(&encoder.finish()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBindingV2 {
    pub attempt_id: BoundedText<{ limits::IDENTIFIER_BYTES }>,
    pub admission_digest: DiagnosticSha256,
    pub caller_envelope_digest: DiagnosticSha256,
    pub native_invocation_digest: DiagnosticSha256,
}

impl AttemptBindingV2 {
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
