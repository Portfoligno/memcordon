//! Named operational private request envelopes. These carry a request, never
//! a caller identity, numeric target credentials, descriptors or permission.

use crate::workload_contract::{WorkloadContractV2, reject_duplicate_json_keys};
use crate::workload_limits::{CONTRACT_BYTES, CONTRACT_ENVELOPE_BYTES};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRuntimeRequest {
    pub format: String,
    pub revision: u32,
    pub contract: WorkloadContractV2,
    /// Existing bounded native launch grammar, decoded by the installed agent.
    pub native_launch: Vec<u8>,
    /// Attempt-scoped duration starts at the actual native release. Supervision
    /// deadlines remain absolute in the native launch grammar instead.
    pub attempt_deadline_millis: Option<u64>,
}

impl PrivateRuntimeRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.private-runtime-request" || self.revision != 1 {
            return Err("private runtime request format or revision unsupported".into());
        }
        self.contract.validate()?;
        if serde_json::to_vec(&self.contract)
            .map_err(|error| error.to_string())?
            .len()
            > CONTRACT_BYTES
            || self.native_launch.is_empty()
            || self.native_launch.len() > CONTRACT_ENVELOPE_BYTES
        {
            return Err("private runtime request exceeds finite input bounds".into());
        }
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > CONTRACT_ENVELOPE_BYTES {
            return Err("private runtime envelope exceeds 128 KiB".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > CONTRACT_ENVELOPE_BYTES {
            return Err("private runtime envelope exceeds 128 KiB".into());
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateNetworkNamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

/// Authenticated rejection observed before any native boundary allocation.
/// It describes that invocation only; it never grants permission to retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRuntimeRejection {
    pub format: String,
    pub revision: u32,
    pub provider: crate::PublicProviderBindingV1,
    pub attempt_id: [u8; 16],
    pub request_sha256: crate::DiagnosticSha256,
    pub invocation_sha256: crate::DiagnosticSha256,
    pub contract: WorkloadContractV2,
    pub boundary_allocated: bool,
    pub reservation_may_remain: bool,
    pub detail: crate::BoundedText<4096>,
}
impl PrivateRuntimeRejection {
    pub fn validate(&self) -> Result<(), String> {
        self.contract.validate()?;
        if self.format != "memcordon.private-runtime-rejection"
            || self.revision != 1
            || !self.provider.is_consistent()
            || self.attempt_id == [0; 16]
            || self.boundary_allocated
        {
            return Err("private preallocation rejection facts conflict".into());
        }
        Ok(())
    }
    pub fn parse_bound(
        bytes: &[u8],
        provider: &crate::PublicProviderBindingV1,
        attempt: [u8; 16],
        request: &crate::DiagnosticSha256,
        contract: &WorkloadContractV2,
        invocation: &crate::DiagnosticSha256,
    ) -> Result<Self, String> {
        if bytes.len() > CONTRACT_ENVELOPE_BYTES {
            return Err("private rejection exceeds bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        if value.provider != *provider
            || value.attempt_id != attempt
            || value.request_sha256 != *request
            || value.contract != *contract
            || value.invocation_sha256 != *invocation
        {
            return Err(
                "private rejection differs from independently authenticated invocation".into(),
            );
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRuntimeTerminal {
    pub format: String,
    pub revision: u32,
    pub provider: crate::PublicProviderBindingV1,
    pub native_abi: String,
    pub attempt_id: [u8; 16],
    pub request_sha256: crate::DiagnosticSha256,
    pub admission_metadata: crate::workload_admission_v2::RuntimePrivateAdmissionSnapshot,
    pub launch: crate::result_v1::LaunchStateV1,
    pub authorization_offset_millis: Option<u64>,
    pub authorization_monotonic_millis: Option<u64>,
    pub target_pid: Option<std::num::NonZeroU32>,
    pub network_namespace: Option<PrivateNetworkNamespaceIdentity>,
    pub exec_observed: bool,
    pub post_exec_descriptor_count: Option<u8>,
    pub outcome: crate::result_v1::OutcomeKindV1,
    pub native_termination: Option<crate::ChildTermination>,
    pub cleanup: crate::result_v1::CleanupStateV1,
    pub account_reservation_retired: bool,
    pub namespace_references_closed: bool,
    pub error: Option<crate::BoundedText<4096>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRuntimeExecution {
    pub terminal: PrivateRuntimeTerminal,
    pub frontend_relay_drained: bool,
    pub frontend_interruption: Option<i32>,
}

impl PrivateRuntimeExecution {
    pub fn cleanup_state(&self) -> crate::result_v1::CleanupStateV1 {
        if self.terminal.cleanup == crate::result_v1::CleanupStateV1::Complete
            && !self.frontend_relay_drained
        {
            crate::result_v1::CleanupStateV1::Incomplete
        } else {
            self.terminal.cleanup
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self
            .frontend_interruption
            .is_some_and(|signal| signal <= 0 || signal >= 128)
        {
            return Err("private frontend interruption is not a native signal".into());
        }
        self.terminal.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRuntimePlan {
    pub format: String,
    pub revision: u32,
    pub provider: crate::PublicProviderBindingV1,
    pub request_sha256: crate::DiagnosticSha256,
    pub request: WorkloadContractV2,
    pub available_for_preparation: bool,
    pub conflicts: Option<crate::workload_registry_v2::AdmissionRejectionV2>,
    pub pending: Vec<String>,
    pub authorizes_launch: bool,
}

impl PrivateRuntimePlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.private-runtime-plan"
            || self.revision != 1
            || !self.provider.is_consistent()
            || self.authorizes_launch
            || self.pending.len() > 16
            || self.available_for_preparation == self.conflicts.is_some()
            || self.request_sha256 != crate::workload_codec::contract_digest_v2(&self.request)?
        {
            return Err("private advisory plan format/request/availability differs".into());
        }
        self.request.validate()
    }
    pub fn parse_bound(
        bytes: &[u8],
        provider: &crate::PublicProviderBindingV1,
        request: &WorkloadContractV2,
    ) -> Result<Self, String> {
        if bytes.len() > CONTRACT_ENVELOPE_BYTES {
            return Err("private advisory plan exceeds bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        if value.provider != *provider || value.request != *request {
            return Err("private advisory plan differs from authenticated provider/request".into());
        }
        Ok(value)
    }
}

impl PrivateRuntimeTerminal {
    pub fn validate(&self) -> Result<(), String> {
        use crate::result_v1::{CleanupStateV1, LaunchStateV1, OutcomeKindV1};
        if self.format != "memcordon.private-runtime-terminal"
            || self.revision != 1
            || self.attempt_id == [0; 16]
            || !self.provider.is_consistent()
            || !matches!(
                self.native_abi.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
        {
            return Err("private terminal namespace/provider/attempt differs".into());
        }
        self.admission_metadata.validate()?;
        if self.exec_observed != (self.launch == LaunchStateV1::ExecObserved)
            || self.authorization_offset_millis.is_some()
                != self.authorization_monotonic_millis.is_some()
            || self.authorization_offset_millis.is_some()
                != matches!(
                    self.launch,
                    LaunchStateV1::ReleaseIssued
                        | LaunchStateV1::ExecObserved
                        | LaunchStateV1::ExecFailed
                )
            || self.post_exec_descriptor_count != self.exec_observed.then_some(3)
            || self.exec_observed && self.network_namespace.is_none()
            || self
                .network_namespace
                .as_ref()
                .is_some_and(|namespace| namespace.inode == 0)
            || self.target_pid.is_none()
                && !matches!(
                    self.launch,
                    LaunchStateV1::NotCreated | LaunchStateV1::Unknown
                )
            || self.cleanup == CleanupStateV1::Complete
                && (!self.account_reservation_retired || !self.namespace_references_closed)
            || self.outcome == OutcomeKindV1::Completed
                && (!self.exec_observed
                    || self.cleanup != CleanupStateV1::Complete
                    || self.native_termination.is_none())
        {
            return Err("private terminal actual launch/exec/retirement facts conflict".into());
        }
        Ok(())
    }

    pub fn parse_bound(
        bytes: &[u8],
        provider: &crate::PublicProviderBindingV1,
        attempt: [u8; 16],
        request_sha256: &crate::DiagnosticSha256,
        contract: &WorkloadContractV2,
        invocation_sha256: &crate::DiagnosticSha256,
    ) -> Result<Self, String> {
        if bytes.len() > CONTRACT_ENVELOPE_BYTES {
            return Err("private terminal exceeds bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        if value.provider != *provider
            || value.attempt_id != attempt
            || value.request_sha256 != *request_sha256
            || value.admission_metadata.request != *contract
            || value.admission_metadata.invocation_sha256 != *invocation_sha256
        {
            return Err(
                "private terminal differs from independently authenticated invocation".into(),
            );
        }
        Ok(value)
    }
}
