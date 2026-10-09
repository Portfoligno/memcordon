//! Explicit combined-runtime evidence. Parsed evidence is descriptive and never
//! acquires a namespace, account reservation, release gate or export capability.
use crate::workload_admission_v3::RuntimeMixedAdmissionSnapshot;
use crate::workload_contract::reject_duplicate_json_keys;
use crate::workload_contract_v3::{BoundObjectRef, ExclusiveAdministratorIdentityRef};
use crate::workload_evidence_v2::VerifiedTrue;
use crate::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeNamespaceV2 {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProcessV2 {
    pub pid: u32,
    pub birth: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedNativeExecutionV2 {
    pub host_target: BoundedText<64>,
    pub boot_id: BoundedText<64>,
    pub caller: NativeProcessV2,
    pub target: NativeProcessV2,
    pub namespace_init: NativeProcessV2,
    pub guardian: NativeProcessV2,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub caller_user_namespace: NativeNamespaceV2,
    pub caller_mount_namespace: NativeNamespaceV2,
    pub caller_pid_namespace: NativeNamespaceV2,
    pub caller_network_namespace: NativeNamespaceV2,
    pub caller_ipc_namespace: NativeNamespaceV2,
    pub user_namespace: NativeNamespaceV2,
    pub mount_namespace: NativeNamespaceV2,
    pub pid_namespace: NativeNamespaceV2,
    pub network_namespace: NativeNamespaceV2,
    pub ipc_namespace: NativeNamespaceV2,
    pub root_device: u64,
    pub root_inode: u64,
    pub runtime_image: BoundObjectRef,
    pub input_image: BoundObjectRef,
    pub root_layout: BoundObjectRef,
    pub execution_identity: ExclusiveAdministratorIdentityRef,
    pub target_uid: u32,
    pub target_gid: u32,
    pub supplementary_groups: BoundedVec<u32, 32>,
    pub init_uid: u32,
    pub init_nondumpable: VerifiedTrue,
    pub no_new_privileges: VerifiedTrue,
    pub capabilities_empty: VerifiedTrue,
    pub filter_abi: MixedFilterAbiV2,
    pub filter_instruction_sha256: DiagnosticSha256,
    pub target_authorized: VerifiedTrue,
    pub exec_observed: VerifiedTrue,
    pub authorization_monotonic_millis: u64,
    pub post_exec_descriptor_count: u8,
    pub native_wait_status: i32,
    pub outcome_origin: MixedOutcomeOriginV2,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedFilterAbiV2 {
    X86_64,
    Aarch64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedOutcomeOriginV2 {
    NativeExit,
    NativeSignal,
    Deadline,
    ControlledCancellation,
    FrontendLost,
    Revoked,
    MemoryOom,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementV2 {
    pub attempt_id: BoundedText<64>,
    pub workload_empty: VerifiedTrue,
    pub init_reaped: VerifiedTrue,
    pub guardian_reaped: VerifiedTrue,
    pub relays_drained_and_closed: VerifiedTrue,
    pub namespace_references_closed: VerifiedTrue,
    pub root_references_closed: VerifiedTrue,
    pub staging_removed: VerifiedTrue,
    pub account_quiescent: VerifiedTrue,
    pub reservation_retired: VerifiedTrue,
    pub export_receipt_sha256: DiagnosticSha256,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedAdmissionRejectionV2 {
    UnauthorizedCaller,
    UnauthorizedPlan,
    UnauthorizedRoot,
    DisabledGrant,
    WrongGrantRevision,
    StaleEpoch,
    UnauthorizedProfile,
    UnauthorizedImage,
    UnauthorizedIdentity,
    IncompatibleRequirement,
    ExclusiveAccountUnavailable,
    ImageCustodyMismatch,
    RootCustodyMismatch,
    HostPrerequisiteUnavailable,
    InstallReadbackFailure,
    PolicyDrift,
    NativeSetupFailed,
    ControlledCancellation,
    MalformedIngress,
    RecursiveProviderRequest,
    UnsupportedRequest,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedAuthorizationKnowledgeV2 {
    NeverAuthorized,
    Authorized,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutstandingMixedRetirementV2 {
    pub authorization: MixedAuthorizationKnowledgeV2,
    pub obligations: BoundedVec<BoundedText<256>, 32>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum MixedRuntimeOutcomeV2 {
    RejectedIngress {
        request_bytes_sha256: DiagnosticSha256,
        reason: MixedAdmissionRejectionV2,
        detail: BoundedText<4096>,
        allocation: OutstandingMixedRetirementV2,
    },
    Executed {
        admission: RuntimeMixedAdmissionSnapshot,
        request_bytes_sha256: DiagnosticSha256,
        provider: PublicProviderBindingV1,
        execution: MixedNativeExecutionV2,
        retirement: MixedRetirementV2,
    },
    RejectedBeforeAuthorization {
        request_sha256: DiagnosticSha256,
        request_bytes_sha256: DiagnosticSha256,
        detail: BoundedText<4096>,
        reason: MixedAdmissionRejectionV2,
        allocation: OutstandingMixedRetirementV2,
    },
    Indeterminate {
        attempt_id: BoundedText<64>,
        request_sha256: DiagnosticSha256,
        retained_obligations: OutstandingMixedRetirementV2,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRuntimeCarrierV2 {
    pub kind: String,
    pub carrier_revision: u32,
    pub provider_contract: u32,
    pub launch_wire: u32,
    pub outcome: MixedRuntimeOutcomeV2,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedFrontendEvidenceV2 {
    pub relay_drained: bool,
    pub interruption: Option<i32>,
    pub relay_error: Option<BoundedText<4096>>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRuntimeExecutionV2 {
    pub runtime: MixedRuntimeCarrierV2,
    pub frontend: MixedFrontendEvidenceV2,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultV2 {
    pub format: String,
    pub revision: u32,
    pub tool: crate::result_v1::OperationalToolV1,
    pub runtime: MixedRuntimeCarrierV2,
    pub delivery: crate::DeliveryEvidence,
    pub frontend: MixedFrontendEvidenceV2,
    pub wrapper_status: i32,
    pub invocation: crate::InvocationReport,
}
impl ResultV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.result" || self.revision != 2 {
            return Err("combined result format/revision differs".into());
        }
        self.invocation
            .validate()
            .map_err(|error| error.to_string())?;
        self.runtime.validate()
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("combined result exceeds bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }
}
impl MixedRuntimeCarrierV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.kind != "linux-mixed-private"
            || self.carrier_revision != 2
            || self.provider_contract != 4
            || self.launch_wire != 4
        {
            return Err("combined result revision/component association differs".into());
        }
        match &self.outcome {
            MixedRuntimeOutcomeV2::Executed {
                admission,
                provider,
                execution,
                retirement,
                ..
            } => {
                admission.validate()?;
                if !provider.is_consistent()
                    || retirement.attempt_id != admission.attempt_id
                    || execution.runtime_image != admission.request.runtime_image
                    || execution.input_image != admission.request.input_image
                    || execution.root_layout != admission.request.root_layout
                    || execution.execution_identity != admission.request.execution_identity
                    || execution.caller_uid != admission.caller_uid
                    || execution.caller_uid == execution.target_uid
                    || execution.user_namespace != execution.caller_user_namespace
                    || execution.mount_namespace == execution.caller_mount_namespace
                    || execution.pid_namespace == execution.caller_pid_namespace
                    || execution.network_namespace == execution.caller_network_namespace
                    || execution.ipc_namespace == execution.caller_ipc_namespace
                    || [
                        &execution.caller,
                        &execution.target,
                        &execution.namespace_init,
                        &execution.guardian,
                    ]
                    .iter()
                    .any(|process| process.pid == 0 || process.birth == 0)
                    || execution.target_uid == 0
                    || execution.target_gid == 0
                    || execution.init_uid == execution.target_uid
                    || execution.post_exec_descriptor_count != 3
                    || execution.root_inode == 0
                    || execution.authorization_monotonic_millis == 0
                    || execution.boot_id.as_str().is_empty()
                    || [
                        &execution.user_namespace,
                        &execution.mount_namespace,
                        &execution.pid_namespace,
                        &execution.network_namespace,
                        &execution.ipc_namespace,
                    ]
                    .iter()
                    .any(|namespace| namespace.inode == 0)
                {
                    return Err("combined executed native binding differs".into());
                }
                let target = execution.host_target.as_str();
                if !matches!(
                    (&execution.filter_abi, target),
                    (MixedFilterAbiV2::X86_64, "x86_64-unknown-linux-gnu")
                        | (MixedFilterAbiV2::Aarch64, "aarch64-unknown-linux-gnu")
                ) {
                    return Err("combined native ABI target differs".into());
                }
            }
            MixedRuntimeOutcomeV2::RejectedBeforeAuthorization { allocation, .. }
            | MixedRuntimeOutcomeV2::RejectedIngress { allocation, .. } => {
                if !matches!(
                    allocation.authorization,
                    MixedAuthorizationKnowledgeV2::NeverAuthorized
                ) {
                    return Err("rejection does not prove never authorized".into());
                }
            }
            MixedRuntimeOutcomeV2::Indeterminate {
                retained_obligations,
                ..
            } => {
                if retained_obligations.obligations.as_slice().is_empty() {
                    return Err("indeterminate result lacks retained obligations".into());
                }
            }
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("combined result exceeds bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }
}
