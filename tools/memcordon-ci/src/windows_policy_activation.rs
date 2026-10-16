use crate::{CiError, Result};
use memcordon_core::workload_contract::{Nonce128, PolicyEpoch, WorkloadContractV1};
use memcordon_core::workload_registry::RuntimePolicyRegistry;
use memcordon_core::{BoundedVec, DiagnosticSha256};

/// Bind a new execution to an actual activation of its exact configured policy.
/// This does not authorize rebinding any already launched attempt or receipt.
pub fn refresh_contract(
    requested: &WorkloadContractV1,
    configured: &RuntimePolicyRegistry,
    bytes: &[u8],
) -> Result<WorkloadContractV1> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Activation {
        format: String,
        revision: u32,
        registry: RuntimePolicyRegistry,
        registry_digest: DiagnosticSha256,
        epoch: PolicyEpoch,
        revoked_admissions: BoundedVec<Nonce128, 256>,
    }
    requested.validate().map_err(CiError::Message)?;
    let activated: Activation = serde_json::from_slice(bytes)?;
    if activated.format != "memcordon.local-activation"
        || activated.revision != 1
        || &activated.registry != configured
        || activated
            .registry
            .canonical_digest()
            .map_err(CiError::Message)?
            != activated.registry_digest
        || !activated.revoked_admissions.as_slice().is_empty()
    {
        return Err(CiError::Message(
            "activated policy differs from exact configured registry".into(),
        ));
    }
    let mut contract = requested.clone();
    contract.expected_epoch = activated.epoch;
    contract.validate().map_err(CiError::Message)?;
    Ok(contract)
}
