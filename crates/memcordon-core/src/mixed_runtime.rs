//! Revision two requests select a logical installed image entrypoint. They
//! contain no caller credentials, host-root descriptors or release authority.
use crate::workload_contract_v3::WorkloadContractV3;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRuntimeRequest {
    pub format: String,
    pub revision: u32,
    pub contract: WorkloadContractV3,
    pub native_launch: Vec<u8>,
    pub attempt_deadline_millis: Option<u64>,
}
impl MixedRuntimeRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.mixed-runtime-request" || self.revision != 2 {
            return Err("unsupported mixed request revision".into());
        }
        self.contract.validate()?;
        if self.native_launch.is_empty()
            || self.native_launch.len() > crate::workload_limits::CONTRACT_ENVELOPE_BYTES
        {
            return Err("mixed native request exceeds finite bounds".into());
        }
        if serde_json::to_vec(&self.contract)
            .map_err(|error| error.to_string())?
            .len()
            > crate::workload_limits::CONTRACT_BYTES
        {
            return Err("mixed contract exceeds finite bounds".into());
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::workload_limits::CONTRACT_ENVELOPE_BYTES {
            return Err("mixed request envelope exceeds finite bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > crate::workload_limits::CONTRACT_ENVELOPE_BYTES {
            return Err("mixed request envelope exceeds finite bound".into());
        }
        Ok(bytes)
    }
}
