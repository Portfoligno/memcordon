//! Revision-three observations, independent of administrator grants and cleanup authorization.
use crate::execution_facts::{CleanupStateV1, OperationalToolV1, OutcomeKindV1, OutcomeV1};
use crate::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseKnowledgeV3 {
    NotReleased,
    Released,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputDeliveryStateV3 {
    Complete,
    Incomplete,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadOutputFileV1 {
    pub path: crate::workload_request::RootRelativePath,
    pub size: u64,
    pub sha256: DiagnosticSha256,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeWorkloadOutcomeV1 {
    Exited { code: i32 },
    Signaled { signal: i32 },
    Deadline,
    MemoryLimit,
    ControlledCancellation,
    FrontendLost,
    SetupFailure,
    NativeFailure,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxWorkloadTerminalV1 {
    pub format: String,
    pub revision: u32,
    pub association: crate::workload_request::WorkloadAttemptAssociationV1,
    pub request: WorkloadRequestAssociationV1,
    pub release: ReleaseKnowledgeV3,
    pub native: Option<LinuxNativeExecutionV3>,
    pub outcome: NativeWorkloadOutcomeV1,
    pub cleanup: CleanupV3,
    pub output_delivery: OutputDeliveryStateV3,
    pub failures: BoundedVec<BoundedText<4096>, 32>,
}
pub const LINUX_WORKLOAD_TERMINAL_FORMAT: &str = "memcordon.linux-workload-terminal";
pub const LINUX_WORKLOAD_TERMINAL_REVISION: u32 = 1;
impl LinuxWorkloadTerminalV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::execution_facts::RESULT_MAX_BYTES {
            return Err("workload terminal exceeds byte bound".into());
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.format != LINUX_WORKLOAD_TERMINAL_FORMAT
            || self.revision != LINUX_WORKLOAD_TERMINAL_REVISION
        {
            return Err("unsupported Linux workload terminal version".into());
        }
        self.association.validate().map_err(|e| e.to_string())?;
        if self.request.request_sha256 != self.association.request_sha256 {
            return Err("terminal request/attempt association differs".into());
        }
        let mut obligations = std::collections::BTreeSet::new();
        for obligation in self.cleanup.obligations.as_slice() {
            if !obligations.insert(obligation.resource)
                || (self.cleanup.state == CleanupStateV1::Complete && !obligation.settled)
            {
                return Err("inconsistent workload terminal cleanup".into());
            }
        }
        if let Some(native) = &self.native {
            native.validate_namespaces()?;
            if native.boot_id != self.association.boot_id
                || native.caller.pid == 0
                || native.target.pid == 0
                || native.target_namespace_pid == 0
                || native.namespace_init.pid == 0
                || native.guardian.pid == 0
                || native.target_uid == 0
                || native.target_gid == 0
                || native.target_uid == native.caller_uid
                || native.init_uid == native.target_uid
                || !native.init_nondumpable
                || !native.supplementary_groups.as_slice().is_empty()
                || !native.no_new_privileges
                || !native.capabilities_empty
                || native.cgroup_inode == 0
                || native.root_inode == 0
            {
                return Err(
                    "private terminal native identity or credential facts violate profile".into(),
                );
            }
            for required in [
                CleanupResourceV3::Target,
                CleanupResourceV3::Aggregate,
                CleanupResourceV3::Guardian,
                CleanupResourceV3::NamespaceInit,
                CleanupResourceV3::Relays,
                CleanupResourceV3::RootReferences,
                CleanupResourceV3::Staging,
                CleanupResourceV3::Footprint,
            ] {
                if !obligations.contains(&required) {
                    return Err("private terminal omits a native cleanup obligation".into());
                }
            }
            if native.exec_observed != native.exec_observed_monotonic_millis.is_some()
                || (native.exec_observed && native.release_monotonic_millis.is_none())
                || matches!((native.release_monotonic_millis,native.exec_observed_monotonic_millis),(Some(release),Some(exec)) if exec < release)
                || (self.release == ReleaseKnowledgeV3::Released
                    && native.release_monotonic_millis.is_none())
            {
                return Err(
                    "native execution timing conflicts with actual release observations".into(),
                );
            }
            if native.exec_observed && self.release != ReleaseKnowledgeV3::Released {
                return Err("native exec observation conflicts with release knowledge".into());
            }
            match self.outcome {
                NativeWorkloadOutcomeV1::MemoryLimit
                    if native.memory_max_bytes.is_none()
                        || native.memory_oom_event_count.is_none_or(|count| count == 0)
                        || native.memory_oom_kill_count.is_none_or(|count| count == 0) =>
                {
                    return Err(
                        "memory outcome lacks actual bounded cgroup oom/oom_kill observations"
                            .into(),
                    );
                }
                NativeWorkloadOutcomeV1::Exited { code } => {
                    let status = native
                        .native_wait_status
                        .ok_or("exit lacks direct target wait")?;
                    if !native.exec_observed || status & 0x7f != 0 || (status >> 8) & 0xff != code {
                        return Err("exit outcome differs from native wait".into());
                    }
                }
                NativeWorkloadOutcomeV1::Signaled { signal } => {
                    let status = native
                        .native_wait_status
                        .ok_or("signal lacks direct target wait")?;
                    if !native.exec_observed
                        || status & 0x7f != signal
                        || !(1..0x7f).contains(&signal)
                    {
                        return Err("signal outcome differs from native wait".into());
                    }
                }
                _ => {}
            }
        } else if self.release == ReleaseKnowledgeV3::Released
            || matches!(
                self.outcome,
                NativeWorkloadOutcomeV1::Exited { .. } | NativeWorkloadOutcomeV1::Signaled { .. }
            )
        {
            return Err("target outcome lacks native observations".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryStateV3 {
    Complete,
    Incomplete,
    Unknown,
    PreparedBy { writer_pid: std::num::NonZeroU32 },
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupResourceV3 {
    ControlHandles,
    Target,
    Aggregate,
    Guardian,
    NamespaceInit,
    Relays,
    RootReferences,
    Staging,
    Footprint,
    Record,
    Outputs,
    Job,
    TargetHandles,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupObligationV3 {
    pub resource: CleanupResourceV3,
    pub settled: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupV3 {
    pub state: CleanupStateV1,
    pub obligations: BoundedVec<CleanupObligationV3, 32>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRequestAssociationV1 {
    pub request_sha256: DiagnosticSha256,
    pub invocation_sha256: DiagnosticSha256,
    pub resource_policy_sha256: DiagnosticSha256,
    pub runtime_sha256: Option<DiagnosticSha256>,
    pub input_sha256: Option<DiagnosticSha256>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxNativeExecutionV3 {
    pub caller_namespaces: [crate::execution_facts::NativeNamespaceV2; 5],
    pub user_namespace: crate::execution_facts::NativeNamespaceV2,
    pub boot_id: BoundedText<64>,
    pub caller: crate::execution_facts::NativeProcessV2,
    pub target: crate::execution_facts::NativeProcessV2,
    pub target_namespace_pid: u32,
    pub namespace_init: crate::execution_facts::NativeProcessV2,
    pub guardian: crate::execution_facts::NativeProcessV2,
    pub caller_uid: u32,
    pub target_uid: u32,
    pub target_gid: u32,
    pub cgroup_device: u64,
    pub cgroup_inode: u64,
    pub init_uid: u32,
    pub init_nondumpable: bool,
    pub mount_namespace: crate::execution_facts::NativeNamespaceV2,
    pub pid_namespace: crate::execution_facts::NativeNamespaceV2,
    pub network_namespace: crate::execution_facts::NativeNamespaceV2,
    pub ipc_namespace: crate::execution_facts::NativeNamespaceV2,
    pub root_device: u64,
    pub root_inode: u64,
    pub filter_abi: crate::execution_facts::MixedFilterAbiV2,
    pub filter_instruction_sha256: DiagnosticSha256,
    pub entrypoint_sha256: DiagnosticSha256,
    pub supplementary_groups: BoundedVec<u32, 32>,
    pub no_new_privileges: bool,
    pub capabilities_empty: bool,
    pub exec_observed: bool,
    pub release_monotonic_millis: Option<u64>,
    pub exec_observed_monotonic_millis: Option<u64>,
    pub native_wait_status: Option<i32>,
    pub memory_oom_kill_count: Option<u64>,
    pub memory_oom_event_count: Option<u64>,
    pub memory_max_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxWorkloadPreparedV1 {
    pub format: String,
    pub revision: u32,
    pub association: crate::workload_request::WorkloadAttemptAssociationV1,
    pub request: WorkloadRequestAssociationV1,
    pub native: LinuxNativeExecutionV3,
}
impl LinuxWorkloadPreparedV1 {
    pub fn validate_ack(&self, raw: &[u8], ack: &WorkloadPreparedAckV1) -> Result<(), String> {
        if Self::parse(raw)? != *self
            || ack.association != self.association
            || ack.prepared_sha256 != crate::hash_bytes(raw)
        {
            return Err(
                "prepared acknowledgment does not bind exact original native observation bytes"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 65536 {
            return Err("native prepared observation exceeds bound".into());
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.association.validate().map_err(|e| e.to_string())?;
        let native = &self.native;
        if self.format != "memcordon.linux-workload-prepared"
            || self.revision != 1
            || self.request.request_sha256 != self.association.request_sha256
            || native.boot_id != self.association.boot_id
            || native.exec_observed
            || native.release_monotonic_millis.is_some()
            || native.exec_observed_monotonic_millis.is_some()
            || native.native_wait_status.is_some()
            || native.caller.pid == 0
            || native.target.pid == 0
            || native.namespace_init.pid == 0
            || native.guardian.pid == 0
            || native.target_namespace_pid == 0
            || native.target_uid == 0
            || native.target_gid == 0
            || native.target_uid == native.caller_uid
            || native.target_uid == native.init_uid
            || !native.supplementary_groups.as_slice().is_empty()
            || !native.no_new_privileges
            || !native.capabilities_empty
            || !native.init_nondumpable
            || native.root_inode == 0
            || native.cgroup_inode == 0
        {
            return Err("prepared native facts violate the original gated Linux profile".into());
        }
        native.validate_namespaces()
    }
}
impl LinuxNativeExecutionV3 {
    fn validate_namespaces(&self) -> Result<(), String> {
        if self.entrypoint_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || self.filter_instruction_sha256 == DiagnosticSha256::from_bytes([0; 32])
        {
            return Err("native held entrypoint digest is absent".into());
        }
        if self
            .caller_namespaces
            .iter()
            .any(|namespace| namespace.inode == 0)
            || self.user_namespace != self.caller_namespaces[0]
            || [
                &self.mount_namespace,
                &self.pid_namespace,
                &self.network_namespace,
                &self.ipc_namespace,
            ]
            .iter()
            .enumerate()
            .any(|(index, native)| {
                native.inode == 0 || **native == self.caller_namespaces[index + 1]
            })
        {
            return Err("native private namespace observations are not fresh relative to the original caller".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadPreparedAckV1 {
    pub format: String,
    pub revision: u32,
    pub association: crate::workload_request::WorkloadAttemptAssociationV1,
    pub prepared_sha256: DiagnosticSha256,
}
impl WorkloadPreparedAckV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 65536 {
            return Err("prepared acknowledgment exceeds bound".into());
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if value.format != "memcordon.workload-prepared-ack" || value.revision != 1 {
            return Err("unsupported prepared acknowledgment identity".into());
        }
        value.association.validate().map_err(|e| e.to_string())?;
        Ok(value)
    }
}
pub use crate::windows_sealed::WindowsSealedEvidenceV3 as WindowsNativeExecutionV3;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeExecutionV3 {
    LinuxSealed {
        native: Box<crate::LinuxSealedEvidenceV2>,
    },
    LinuxPrivate {
        profile: crate::workload_request::LinuxPrivateProfileV1,
        native: Box<LinuxNativeExecutionV3>,
    },
    WindowsSealed {
        profile: crate::workload_request::WindowsCurrentTokenProfileV1,
        native: Box<WindowsNativeExecutionV3>,
    },
    WindowsRecovered {
        profile: crate::workload_request::WindowsCurrentTokenProfileV1,
        terminal: Box<crate::WindowsTerminalReceiptV3>,
    },
    WindowsPreallocationCancelled {
        profile: crate::workload_request::WindowsCurrentTokenProfileV1,
        cancellation: Box<crate::WindowsPreallocationCancellationV1>,
    },
    WindowsPrematureRelease {
        profile: crate::workload_request::WindowsCurrentTokenProfileV1,
        terminal: Box<crate::WindowsTerminalReceiptV3>,
    },
    PreparationFailed {
        profile: BoundedText<64>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultV3 {
    pub format: String,
    pub revision: u32,
    pub tool: OperationalToolV1,
    pub invocation: crate::InvocationReport,
    pub request: Option<WorkloadRequestAssociationV1>,
    pub provider: Option<PublicProviderBindingV1>,
    pub workload_attempt: Option<crate::workload_request::WorkloadAttemptAssociationV1>,
    pub release: ReleaseKnowledgeV3,
    pub outcome: OutcomeV1,
    pub cleanup: CleanupV3,
    pub delivery: DeliveryStateV3,
    pub output_delivery: Option<OutputDeliveryStateV3>,
    pub diagnostics: BoundedVec<BoundedText<4096>, 32>,
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
    pub request_rejection: Option<crate::workload_request::WorkloadRejectionV1>,
    pub windows_rejection: Option<Box<crate::WindowsProviderRejectionV3>>,
    pub windows_attempt: Option<crate::execution_facts::ProviderAttemptAssociationV1>,
    pub runtime: RuntimeExecutionV3,
}
impl ResultV3 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::execution_facts::RESULT_MAX_BYTES {
            return Err("result exceeds byte bound".into());
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.result" || self.revision != 3 {
            return Err("unsupported result version".into());
        }
        self.invocation
            .validate()
            .map_err(|error| error.to_string())?;
        if let Some(failure) = &self.provider_failure {
            if !failure.is_consistent()
                || failure.canonical_digest() != failure.projection_sha256
                || self.provider.as_ref() != Some(&failure.provider_binding)
            {
                return Err("native causal diagnostic/provider association differs".into());
            }
        }
        if let Some(rejection) = &self.request_rejection {
            if rejection.format != "memcordon.workload-rejection"
                || rejection.revision != 1
                || self.release != ReleaseKnowledgeV3::NotReleased
                || !matches!(self.runtime, RuntimeExecutionV3::PreparationFailed { .. })
                || self.outcome.native_termination.is_some()
            {
                return Err(
                    "preallocation rejection conflicts with actual native execution".into(),
                );
            }
        }
        if let Some(attempt) = &self.workload_attempt {
            attempt.validate().map_err(|e| e.to_string())?;
            if self.provider.as_ref() != Some(&attempt.provider)
                || self
                    .request
                    .as_ref()
                    .is_some_and(|request| request.request_sha256 != attempt.request_sha256)
            {
                return Err("native workload attempt association differs".into());
            }
        }
        if let Some(rejection) = &self.windows_rejection {
            if !rejection.is_consistent()
                || rejection.provider_failure.as_ref() != self.provider_failure.as_ref()
                || (rejection.target_released && self.release == ReleaseKnowledgeV3::NotReleased)
            {
                return Err(
                    "current Windows rejection differs from actual causal/release observations"
                        .into(),
                );
            }
        }
        if let Some(attempt) = &self.windows_attempt {
            if self.provider.as_ref() != Some(&attempt.provider)
                || !attempt.provider.is_consistent()
            {
                return Err("Windows attempt provider association differs".into());
            }
            let terminal = self
                .windows_rejection
                .as_ref()
                .and_then(|rejection| rejection.terminal_receipt())
                .or_else(|| match &self.runtime {
                    RuntimeExecutionV3::WindowsRecovered { terminal, .. }
                    | RuntimeExecutionV3::WindowsPrematureRelease { terminal, .. } => {
                        Some(terminal.as_ref())
                    }
                    _ => None,
                });
            if let Some(terminal) = terminal {
                if terminal.attempt_id != String::from(attempt.attempt_id.clone())
                    || terminal.request_sha256 != String::from(attempt.request_sha256.clone())
                {
                    return Err("Windows terminal belongs to another original attempt".into());
                }
            }
        }
        if self.provider.is_none()
            && (!matches!(self.runtime, RuntimeExecutionV3::PreparationFailed { .. })
                || self.release == ReleaseKnowledgeV3::Released)
        {
            return Err("native execution lacks actual provider association".into());
        }
        let mut resources = std::collections::BTreeSet::new();
        for obligation in self.cleanup.obligations.as_slice() {
            if !resources.insert(obligation.resource) {
                return Err("duplicate cleanup obligation".into());
            }
            if self.cleanup.state == CleanupStateV1::Complete && !obligation.settled {
                return Err("complete cleanup has an outstanding obligation".into());
            }
        }
        if self.release == ReleaseKnowledgeV3::NotReleased
            && self.outcome.native_termination.is_some()
        {
            return Err("unreleased target has a native termination".into());
        }
        match &self.runtime {
            RuntimeExecutionV3::WindowsPreallocationCancelled { cancellation, .. } => {
                cancellation.validate().map_err(str::to_owned)?;
                let accepted = &cancellation.accepted;
                if self.provider.as_ref() != Some(&accepted.provider)
                    || self.release != ReleaseKnowledgeV3::NotReleased
                    || self.outcome.kind != OutcomeKindV1::Interrupted
                    || self.outcome.native_termination.is_some()
                    || self.outcome.wrapper_status != cancellation.exit_code()
                    || self.cleanup.state != CleanupStateV1::Complete
                    || !self.cleanup.obligations.as_slice().is_empty()
                    || self.windows_rejection.is_some()
                    || self.provider_failure.is_some()
                    || self.workload_attempt.is_some()
                    || self.output_delivery.is_some()
                    || self.request.as_ref().is_some_and(|request| {
                        request.runtime_sha256.is_some() || request.input_sha256.is_some()
                    })
                    || self.windows_attempt.as_ref().is_none_or(|attempt| {
                        attempt.provider != accepted.provider
                            || String::from(attempt.attempt_id.clone()) != accepted.attempt_id
                            || String::from(attempt.request_sha256.clone())
                                != accepted.request_sha256
                    })
                {
                    return Err("preallocation cancellation changes actual native no-allocation/owner observation".into());
                }
            }
            RuntimeExecutionV3::LinuxSealed { native } => {
                if self.request.is_some() || native.schema_version != 2 {
                    return Err("ordinary credential-preserving Linux evidence cannot satisfy a private request".into());
                }
                if native.target_released != (self.release == ReleaseKnowledgeV3::Released)
                    && self.release != ReleaseKnowledgeV3::Unknown
                {
                    return Err("Linux sealed release observations disagree".into());
                }
                if native.target_released
                    && !(native.cgroup_created
                        && native.cgroup_owned_by_provider
                        && native.memory_configuration_verified
                        && native.init_created_into_cgroup
                        && native.pid_namespace_created
                        && native.mount_namespace_created
                        && native.cgroup_namespace_created
                        && native.target_pidfd_verified
                        && native.target_cgroup_membership_verified
                        && native.target_pid_namespace_verified
                        && native.target_initial_credentials_verified
                        && native.initial_provider_capabilities_absent
                        && native.caller_no_new_privs_reproduced
                        && native.caller_capability_bounding_set_reproduced
                        && native.caller_mount_context_reproduced
                        && native.boundary_independent_of_credentials
                        && native.inherited_descriptors_verified
                        && native.writable_ancestor_cgroup_denied
                        && native.parent_namespace_handles_denied
                        && native.recursive_provider_request_denied
                        && native.guardian_ready)
                {
                    return Err("ordinary Linux sealed native gate observations incomplete".into());
                }
                if self.cleanup.state == CleanupStateV1::Complete
                    && !(native.cgroup_empty_verified
                        && native.namespace_init_reaped
                        && native.guardian_reaped
                        && native.cgroup_removed)
                {
                    return Err(
                        "ordinary Linux cleanup lacks native retirement observations".into(),
                    );
                }
            }
            RuntimeExecutionV3::LinuxPrivate { native, .. } => {
                if self.cleanup.state == CleanupStateV1::Complete
                    && !resources.contains(&CleanupResourceV3::ControlHandles)
                {
                    return Err("complete public Linux cleanup lacks original frontend control-handle observation".into());
                }
                let association = self
                    .workload_attempt
                    .as_ref()
                    .ok_or("private Linux result lacks original attempt association")?;
                let request = self
                    .request
                    .as_ref()
                    .ok_or("private Linux result lacks original request association")?;
                if request.runtime_sha256.is_none() || request.input_sha256.is_none() {
                    return Err("private Linux result lacks original snapshot associations".into());
                }
                if let Some(termination) = &self.outcome.native_termination {
                    let status = native
                        .native_wait_status
                        .ok_or("Linux termination lacks direct native wait")?;
                    let matches = match termination {
                        crate::ChildTermination::ExitCode { code } => {
                            native.exec_observed
                                && (0..=255).contains(code)
                                && status & 0x7f == 0
                                && (status >> 8) & 0xff == *code
                        }
                        crate::ChildTermination::UnixSignal { signal } => {
                            native.exec_observed
                                && (1..0x7f).contains(signal)
                                && status & 0x7f == *signal
                        }
                        _ => false,
                    };
                    if !matches {
                        return Err(
                            "Linux public termination differs from actual direct wait".into()
                        );
                    }
                }
                let outcome = match self.outcome.kind {
                    OutcomeKindV1::Completed => match self.outcome.native_termination.as_ref() {
                        Some(crate::ChildTermination::ExitCode { code }) => {
                            NativeWorkloadOutcomeV1::Exited { code: *code }
                        }
                        Some(crate::ChildTermination::UnixSignal { signal }) => {
                            NativeWorkloadOutcomeV1::Signaled { signal: *signal }
                        }
                        _ => {
                            return Err(
                                "completed Linux result lacks actual target termination".into()
                            );
                        }
                    },
                    OutcomeKindV1::Deadline => NativeWorkloadOutcomeV1::Deadline,
                    OutcomeKindV1::ConfirmedMemoryLimit => NativeWorkloadOutcomeV1::MemoryLimit,
                    OutcomeKindV1::Interrupted => NativeWorkloadOutcomeV1::ControlledCancellation,
                    OutcomeKindV1::LaunchFailure => NativeWorkloadOutcomeV1::SetupFailure,
                    OutcomeKindV1::ProviderFailure => NativeWorkloadOutcomeV1::NativeFailure,
                    OutcomeKindV1::Unknown => NativeWorkloadOutcomeV1::Unknown,
                };
                // Share the current native profile/session/timing validator;
                // this creates no new observation or native ownership.
                LinuxWorkloadTerminalV1 {
                    format: LINUX_WORKLOAD_TERMINAL_FORMAT.into(),
                    revision: LINUX_WORKLOAD_TERMINAL_REVISION,
                    association: association.clone(),
                    request: request.clone(),
                    release: self.release,
                    native: Some((**native).clone()),
                    outcome,
                    cleanup: self.cleanup.clone(),
                    output_delivery: self
                        .output_delivery
                        .unwrap_or(OutputDeliveryStateV3::Unknown),
                    failures: self.diagnostics.clone(),
                }
                .validate()?;
                native.validate_namespaces()?;
                if self.outcome.kind == crate::execution_facts::OutcomeKindV1::ConfirmedMemoryLimit
                    && (native.memory_max_bytes.is_none()
                        || native.memory_oom_event_count.is_none_or(|count| count == 0)
                        || native.memory_oom_kill_count.is_none_or(|count| count == 0))
                {
                    return Err("confirmed memory limit lacks actual bounded cgroup oom/oom_kill observations".into());
                }
                if self.workload_attempt.is_none() {
                    return Err("private Linux result lacks original attempt association".into());
                }
                if native.exec_observed && self.release != ReleaseKnowledgeV3::Released {
                    return Err("exec observation conflicts with release knowledge".into());
                }
                if native.target_uid == 0
                    || native.target_gid == 0
                    || !native.supplementary_groups.as_slice().is_empty()
                    || !native.no_new_privileges
                    || !native.capabilities_empty
                    || native.init_uid == native.target_uid
                    || !native.init_nondumpable
                {
                    return Err("private credential observations violate profile".into());
                }
            }
            RuntimeExecutionV3::WindowsSealed { native, .. } => {
                native.validate().map_err(str::to_owned)?;
                if native.target_released != (self.release == ReleaseKnowledgeV3::Released)
                    && self.release != ReleaseKnowledgeV3::Unknown
                {
                    return Err("Windows release observations disagree".into());
                }
                if self.outcome.native_termination.is_some() && !native.direct_target_reaped {
                    return Err("native termination lacks direct wait".into());
                }
                if self.cleanup.state == CleanupStateV1::Complete {
                    if !(native.direct_target_reaped
                        && native.active_processes_zero
                        && native.guardian_reaped
                        && native.relays_retired
                        && native.final_job_handles_closed)
                    {
                        return Err(
                            "complete Windows cleanup lacks actual native retirement observations"
                                .into(),
                        );
                    }
                    let proof = native
                        .retirement
                        .as_ref()
                        .ok_or("complete Windows cleanup lacks native retirement source")?;
                    proof.validate().map_err(str::to_owned)?;
                    let delivery = native
                        .frontend_delivery
                        .as_ref()
                        .ok_or("complete Windows cleanup lacks actual frontend acknowledgment")?;
                    if !delivery.terminal_validated
                        || !delivery.acknowledgement_observed
                        || delivery.attempt_id != proof.attempt_id
                        || delivery.nonce != proof.nonce
                        || delivery.request_sha256 != proof.request_sha256
                        || crate::BoundedText::new(&delivery.terminal_sha256)
                            .and_then(crate::DiagnosticSha256::try_from)
                            .is_err()
                        || crate::BoundedText::new(&delivery.retired_sha256)
                            .and_then(crate::DiagnosticSha256::try_from)
                            .is_err()
                    {
                        return Err(
                            "complete Windows cleanup has no matching native terminal ACK".into(),
                        );
                    }
                    let association = native
                        .frontend_provider_association
                        .as_ref()
                        .ok_or("complete Windows cleanup lacks actual provider association")?;
                    if self.windows_attempt.as_ref() != Some(association)
                        || self.provider.as_ref() != Some(&association.provider)
                        || association.provider.generation.as_str() != proof.provider_generation
                        || String::from(association.attempt_id.clone()) != proof.attempt_id
                        || String::from(association.request_sha256.clone()) != proof.request_sha256
                    {
                        return Err(
                            "complete Windows cleanup crosses native attempt/provider ownership"
                                .into(),
                        );
                    }
                }
            }
            RuntimeExecutionV3::WindowsRecovered { terminal, .. } => {
                terminal.validate_for_attempt().map_err(str::to_owned)?;
                let crate::WindowsTerminalPayloadV3::RecoveredClosure {
                    resume_attempted, ..
                } = &terminal.payload
                else {
                    return Err("recovered result lacks a recovered-closure observation".into());
                };
                if self.outcome.native_termination.is_some() {
                    return Err(
                        "recovered closure cannot synthesize native target termination".into(),
                    );
                }
                if *resume_attempted && self.release == ReleaseKnowledgeV3::NotReleased {
                    return Err("resume uncertainty conflicts with no-release result".into());
                }
                if self.release == ReleaseKnowledgeV3::Released {
                    return Err(
                        "recovered closure alone cannot establish released execution".into(),
                    );
                }
            }
            RuntimeExecutionV3::WindowsPrematureRelease { terminal, .. } => {
                terminal.validate_for_attempt().map_err(str::to_owned)?;
                if !matches!(
                    terminal.payload,
                    crate::WindowsTerminalPayloadV3::PrematureReleaseFailure { .. }
                ) || self.release != ReleaseKnowledgeV3::Unknown
                    || self.outcome.native_termination.is_some()
                {
                    return Err(
                        "premature release requires its actual uncertain native witness".into(),
                    );
                }
            }
            RuntimeExecutionV3::PreparationFailed { .. }
                if self.release == ReleaseKnowledgeV3::Released =>
            {
                return Err("preparation failure claims released execution".into());
            }
            _ => {}
        }
        Ok(())
    }
}
