//! Strict descriptive V3 correlation. Decoding never acquires native authority.
use crate::workload_codec::{Encoder, hash_bytes};
use crate::workload_contract::{Nonce128, PolicyEpoch, ProfileRef, reject_duplicate_json_keys};
use crate::workload_contract_v3::WorkloadContractV3;
use crate::{BoundedText, DiagnosticSha256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMixedAdmissionSnapshot {
    pub format: String,
    pub revision: u32,
    pub attempt_id: BoundedText<64>,
    pub request: WorkloadContractV3,
    pub request_sha256: DiagnosticSha256,
    pub invocation_sha256: DiagnosticSha256,
    pub caller_uid: u32,
    pub registry_digest: DiagnosticSha256,
    pub epoch: PolicyEpoch,
    pub admission_nonce: Nonce128,
    pub profile_id: ProfileRef,
}
impl RuntimeMixedAdmissionSnapshot {
    pub fn validate(&self) -> Result<(), String> {
        self.request.validate()?;
        if self.format != "memcordon.private-admission-metadata"
            || self.revision != 2
            || self.attempt_id.as_str().len() != Nonce128([0; 16]).0.len() * 2
            || !self
                .attempt_id
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.request.digest()? != self.request_sha256
            || self.epoch != self.request.expected_epoch
            || self.profile_id != self.request.authorized_profile
            || self.profile_id != crate::workload_registry_v3::profile_reference()
            || self.admission_nonce.0 == [0; 16]
        {
            return Err("combined admission correlation differs".into());
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::workload_limits::CONTRACT_ENVELOPE_BYTES {
            return Err("combined admission metadata exceeds bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        self.validate()?;
        let mut e = Encoder::new(
            b"memcordon.private-admission-metadata/revision2",
            crate::workload_limits::PUBLIC_OBJECT_BYTES,
        )?;
        crate::workload_contract_v3::encode_text(&mut e, self.attempt_id.as_str())?;
        e.digest(&self.request_sha256)?;
        e.digest(&self.invocation_sha256)?;
        e.u64(u64::from(self.caller_uid))?;
        e.digest(&self.registry_digest)?;
        e.raw(&self.epoch.service_instance.0)?;
        e.u64(self.epoch.revision.get())?;
        e.raw(&self.admission_nonce.0)?;
        e.id(&self.profile_id.id)?;
        e.digest(&self.profile_id.semantic_digest)?;
        Ok(hash_bytes(&e.finish()))
    }
}
