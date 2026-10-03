//! Explicit operational output formats; legacy numeric reports keep their meaning.
use crate::{
    BoundaryRequirement, ChildTermination, DeliveryEvidence, MemcordonReport, RunOutcome,
    SupervisionTerminal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;

pub const RESULT_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReportFormat {
    #[default]
    Legacy,
    ResultV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationV1 {
    NotRequiredForStandard,
    RejectedBeforeRelease,
    Granted,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchStateV1 {
    NotCreated,
    GatedUnreleased,
    ReleaseIssued,
    ExecObserved,
    ExecFailed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeKindV1 {
    Completed,
    Deadline,
    ConfirmedMemoryLimit,
    Interrupted,
    LaunchFailure,
    ProviderFailure,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupStateV1 {
    Complete,
    Incomplete,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalToolV1 {
    pub name: String,
    pub version: String,
    pub os: String,
    pub architecture: String,
    pub runtime_features: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalBackendV1 {
    pub name: String,
    pub containment: crate::CapabilityStatusReport,
    pub boundary: crate::BoundaryClass,
    pub memory: Option<crate::MemoryCapabilityReport>,
    pub deadline: crate::CapabilityStatusReport,
    pub limitations: Vec<String>,
}

impl From<&crate::BackendCapabilityReport> for OperationalBackendV1 {
    fn from(value: &crate::BackendCapabilityReport) -> Self {
        Self {
            name: value.name.clone(),
            containment: value.containment.clone(),
            boundary: value.boundary.class,
            memory: value.memory.clone(),
            deadline: value.deadline.clone(),
            limitations: value.limitations.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationV1 {
    pub association_sha256: String,
    pub requested_memory: Option<crate::RequestedMemoryPolicyReport>,
    pub requested_deadline: Option<crate::DeadlinePolicyReport>,
    pub applied_memory: Option<crate::EffectiveMemoryPolicyReport>,
    pub applied_deadline: Option<crate::DeadlinePolicyReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchV1 {
    pub state: LaunchStateV1,
    pub target_pid: Option<NonZeroU32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeV1 {
    pub kind: OutcomeKindV1,
    pub native_termination: Option<ChildTermination>,
    pub wrapper_status: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupV1 {
    pub state: CleanupStateV1,
    pub direct_child_reaped: bool,
    pub workload_empty: Option<bool>,
    pub outstanding: Vec<crate::RetirementObligation>,
    pub failed_operations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeV1 {
    Standard {
        observation: Option<crate::RuntimeEvidenceV1>,
    },
    WindowsSealed {
        observation: Box<crate::WindowsSealedEvidenceV2>,
    },
    LinuxPrivateTcp4 {
        profile_reference: String,
        identity_reference: String,
        identity_kind: String,
        activation_epoch: u64,
        native_abi: String,
        invocation_sha256: String,
        private_namespace_observed: bool,
        no_socket_at_entry: bool,
        exec_observed: bool,
        port_range: [u16; 2],
        unprivileged_port_start: u16,
        resources_retired: bool,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultV1 {
    pub format: String,
    pub revision: u32,
    pub tool: OperationalToolV1,
    pub invocation: InvocationV1,
    pub policy: crate::PolicyEnvelopeReport,
    pub attempts: Vec<crate::AttemptRecord>,
    pub supervision: Option<crate::SupervisionReport>,
    pub error: Option<crate::ExecutionErrorReport>,
    pub backend: Option<OperationalBackendV1>,
    pub authorization: AuthorizationV1,
    pub launch: LaunchV1,
    pub outcome: OutcomeV1,
    pub cleanup: CleanupV1,
    pub restart: Option<crate::RestartSummary>,
    pub runtime: RuntimeV1,
    pub private_execution: Option<crate::private_runtime::PrivateRuntimeExecution>,
    pub private_rejection: Option<crate::private_runtime::PrivateRuntimeRejection>,
    pub diagnostics: Option<crate::ProviderFailureDiagnosticV1>,
    pub provider_association: Option<ProviderAttemptAssociationV1>,
    pub delivery: DeliveryEvidence,
}

/// Independent association retained from the authenticated public frontend exchange.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttemptAssociationV1 {
    pub provider: crate::PublicProviderBindingV1,
    pub attempt_id: crate::DiagnosticSha256,
    pub request_sha256: crate::DiagnosticSha256,
}

impl ResultV1 {
    pub fn from_legacy(
        report: &MemcordonReport,
        runtime_features: Vec<String>,
    ) -> Result<Self, String> {
        let attempt = report.attempts.last();
        let operational_failure = attempt.and_then(|attempt| attempt.operational_failure.as_ref());
        let private_execution = attempt.and_then(|attempt| attempt.private_execution.clone());
        let failed_windows_rejection = report
            .error
            .as_ref()
            .and_then(|error| error.windows_provider_rejection_v2.as_ref())
            .or_else(|| operational_failure.and_then(|failure| failure.windows_rejection.as_ref()));
        let failed_windows_terminal = failed_windows_rejection
            .filter(|rejection| rejection.is_consistent())
            .and_then(crate::WindowsProviderRejectionV2::terminal_receipt);
        let (failed_windows_outcome, failed_windows_boundary) =
            match failed_windows_terminal.map(|receipt| &receipt.payload) {
                Some(crate::WindowsTerminalPayloadV2::Execution {
                    outcome,
                    boundary_detail,
                    ..
                }) => (Some(outcome), Some(boundary_detail.as_ref())),
                _ => (None, None),
            };
        let runtime = attempt
            .and_then(|attempt| attempt.runtime.clone())
            .or_else(|| {
                report
                    .error
                    .as_ref()
                    .and_then(|error| error.runtime.clone())
            });
        let released = attempt.is_some_and(|attempt| attempt.launch.target_released)
            || report
                .error
                .as_ref()
                .is_some_and(|error| error.target_released);
        let unobserved_failure = (attempt
            .and_then(|attempt| attempt.error.as_ref())
            .is_some_and(|error| error.workload_may_be_alive)
            || report
                .error
                .as_ref()
                .is_some_and(|error| error.workload_may_be_alive))
            && !released
            && runtime.is_none()
            && failed_windows_rejection.is_none();
        let pid = attempt
            .and_then(|attempt| attempt.target_pid)
            .and_then(NonZeroU32::new)
            .or_else(|| runtime.as_ref().and_then(|runtime| runtime.target_pid))
            .or_else(|| {
                failed_windows_terminal.and_then(|receipt| match &receipt.payload {
                    crate::WindowsTerminalPayloadV2::Execution { child_pid, .. } => {
                        NonZeroU32::new(*child_pid)
                    }
                    _ => None,
                })
            });
        let launch_state = match runtime.as_ref().map(|runtime| &runtime.release) {
            Some(crate::ReleaseEvidence::Issued {
                exec_confirmed: true,
                ..
            }) => LaunchStateV1::ExecObserved,
            Some(crate::ReleaseEvidence::Issued { .. }) => LaunchStateV1::ReleaseIssued,
            Some(crate::ReleaseEvidence::Unknown) => LaunchStateV1::Unknown,
            _ if released => LaunchStateV1::ReleaseIssued,
            _ if runtime.as_ref().is_some_and(|runtime| {
                matches!(
                    runtime.retirement,
                    crate::RetirementEvidence::Pending { .. }
                        | crate::RetirementEvidence::Unconfirmed { .. }
                )
            }) =>
            {
                LaunchStateV1::Unknown
            }
            _ if unobserved_failure => LaunchStateV1::Unknown,
            _ if pid.is_some() => LaunchStateV1::GatedUnreleased,
            _ if failed_windows_rejection.is_some_and(|rejection| rejection.target_created) => {
                LaunchStateV1::GatedUnreleased
            }
            _ if report
                .error
                .as_ref()
                .is_some_and(|error| error.workload_may_be_alive) =>
            {
                LaunchStateV1::Unknown
            }
            _ => LaunchStateV1::NotCreated,
        };
        let outcome =
            report
                .supervision
                .as_ref()
                .and_then(|supervision| match &supervision.terminal {
                    SupervisionTerminal::AttemptOutcome { outcome, .. } => Some(outcome),
                    _ => None,
                });
        let (mut kind, mut native_termination) = match outcome {
            Some(RunOutcome::Exited {
                child: ChildTermination::Unavailable,
                ..
            }) => (OutcomeKindV1::Unknown, None),
            Some(RunOutcome::Exited { child, .. }) => {
                (OutcomeKindV1::Completed, Some(child.clone()))
            }
            Some(RunOutcome::LimitExceeded {
                child_after_termination,
                ..
            }) => (
                OutcomeKindV1::ConfirmedMemoryLimit,
                child_after_termination.clone(),
            ),
            Some(RunOutcome::DeadlineExceeded {
                child_after_termination,
                ..
            }) => (OutcomeKindV1::Deadline, child_after_termination.clone()),
            Some(RunOutcome::Interrupted {
                child_after_termination,
                ..
            }) => (OutcomeKindV1::Interrupted, child_after_termination.clone()),
            Some(RunOutcome::MonitorFailed {
                child_after_termination,
                ..
            }) => (
                OutcomeKindV1::ProviderFailure,
                child_after_termination.clone(),
            ),
            None if report.supervision.as_ref().is_some_and(|supervision| {
                matches!(
                    supervision.terminal,
                    SupervisionTerminal::DeadlineOutsideAttempt { .. }
                )
            }) =>
            {
                (OutcomeKindV1::Deadline, None)
            }
            None if report
                .error
                .as_ref()
                .is_some_and(|error| error.provider_failure.is_some())
                || operational_failure
                    .is_some_and(|failure| failure.provider_failure.is_some()) =>
            {
                (OutcomeKindV1::ProviderFailure, None)
            }
            None if unobserved_failure => (OutcomeKindV1::Unknown, None),
            None if report.error.is_some()
                || report.supervision.as_ref().is_some_and(|supervision| {
                    matches!(supervision.terminal, SupervisionTerminal::Error { .. })
                }) =>
            {
                (OutcomeKindV1::LaunchFailure, None)
            }
            None => (OutcomeKindV1::Unknown, None),
        };
        if outcome.is_none() {
            if let Some(observed) = failed_windows_outcome {
                // An authenticated target terminal is evidence, not a successful
                // production result after the frontend reported a failure.
                kind = OutcomeKindV1::ProviderFailure;
                native_termination = match observed {
                    RunOutcome::Exited {
                        child: ChildTermination::Unavailable,
                        ..
                    } => None,
                    RunOutcome::Exited { child, .. } => Some(child.clone()),
                    RunOutcome::LimitExceeded {
                        child_after_termination,
                        ..
                    }
                    | RunOutcome::DeadlineExceeded {
                        child_after_termination,
                        ..
                    }
                    | RunOutcome::Interrupted {
                        child_after_termination,
                        ..
                    }
                    | RunOutcome::MonitorFailed {
                        child_after_termination,
                        ..
                    } => child_after_termination.clone(),
                };
            }
        }
        let cleanup_summary = outcome.or(failed_windows_outcome).map(RunOutcome::cleanup);
        let restart_safety = attempt.map(|attempt| &attempt.restart_safety);
        let retirement = runtime.as_ref().map(|runtime| &runtime.retirement);
        let complete = retirement.is_some_and(crate::RetirementEvidence::is_complete)
            || restart_safety
                .is_some_and(|proof| proof.is_safe_for(report.policy.requested.boundary))
            || cleanup_summary.is_some_and(|cleanup| {
                cleanup.direct_child_reaped
                    && cleanup.workload_empty == Some(true)
                    && cleanup.errors.is_empty()
            });
        let no_target = launch_state == LaunchStateV1::NotCreated;
        let no_resources = no_target && report.backend.is_none();
        let cleanup = CleanupV1 {
            state: if complete || no_resources {
                CleanupStateV1::Complete
            } else if cleanup_summary.is_some_and(|cleanup| !cleanup.errors.is_empty())
                || restart_safety.is_some_and(|proof| !proof.errors.is_empty())
            {
                CleanupStateV1::Incomplete
            } else {
                CleanupStateV1::Unknown
            },
            direct_child_reaped: complete
                || cleanup_summary.is_some_and(|cleanup| cleanup.direct_child_reaped)
                || restart_safety.is_some_and(|proof| proof.direct_child_reaped),
            workload_empty: if complete || no_resources {
                Some(true)
            } else {
                cleanup_summary
                    .and_then(|cleanup| cleanup.workload_empty)
                    .or_else(|| restart_safety.and_then(|proof| proof.workload_empty))
            },
            outstanding: match retirement {
                Some(crate::RetirementEvidence::Pending { obligations, .. }) => obligations.clone(),
                _ => Vec::new(),
            },
            failed_operations: cleanup_summary
                .map(|cleanup| {
                    cleanup
                        .errors
                        .iter()
                        .map(|error| error.operation.clone())
                        .collect()
                })
                .unwrap_or_default(),
        };
        let authorization = if report.policy.requested.boundary == BoundaryRequirement::Standard {
            AuthorizationV1::NotRequiredForStandard
        } else if launch_state == LaunchStateV1::Unknown {
            AuthorizationV1::Uncertain
        } else if released {
            AuthorizationV1::Granted
        } else {
            AuthorizationV1::RejectedBeforeRelease
        };
        let selected_runtime = match attempt.map(|attempt| &attempt.boundary_detail) {
            Some(crate::BoundaryMechanismEvidence::LinuxPrivateTcp4(private)) => {
                let metadata = &private.terminal.admission_metadata;
                let (identity_reference, identity_kind) = match &metadata.request.execution_identity {
                    crate::workload_contract::ExecutionIdentityRequestV2::PreserveCaller =>
                        ("caller".to_owned(), "preserve-caller".to_owned()),
                    crate::workload_contract::ExecutionIdentityRequestV2::AdministratorProfile { reference } =>
                        (reference.id.as_str().to_owned(), "administrator-profile".to_owned()),
                };
                RuntimeV1::LinuxPrivateTcp4 {
                    profile_reference: metadata.profile_id.id.as_str().to_owned(),
                    identity_reference,
                    identity_kind,
                    activation_epoch: metadata.epoch.revision.get(),
                    native_abi: private.terminal.native_abi.clone(),
                    invocation_sha256: String::from(metadata.invocation_sha256.clone()),
                    private_namespace_observed: private.terminal.exec_observed,
                    no_socket_at_entry: private.terminal.exec_observed,
                    exec_observed: private.terminal.exec_observed,
                    port_range: [32768, 60999],
                    unprivileged_port_start: 0,
                    resources_retired: private.cleanup_state() == CleanupStateV1::Complete,
                }
            }
            Some(crate::BoundaryMechanismEvidence::WindowsJobObjectV2(observation)) => {
                RuntimeV1::WindowsSealed {
                    observation: observation.clone(),
                }
            }
            _ if matches!(
                failed_windows_boundary,
                Some(crate::BoundaryMechanismEvidence::WindowsJobObjectV2(_))
            ) =>
            {
                let Some(crate::BoundaryMechanismEvidence::WindowsJobObjectV2(observation)) =
                    failed_windows_boundary
                else {
                    unreachable!()
                };
                RuntimeV1::WindowsSealed {
                    observation: observation.clone(),
                }
            }
            _ if report.policy.requested.boundary == BoundaryRequirement::Standard => {
                RuntimeV1::Standard {
                    observation: runtime,
                }
            }
            _ => RuntimeV1::Unavailable {
                reason: "no operational runtime observation available".into(),
            },
        };
        let association = Sha256::digest(
            serde_json::to_vec(&report.invocation).map_err(|error| error.to_string())?,
        );
        let mut value = Self {
            format: "memcordon.result".into(),
            revision: 1,
            tool: OperationalToolV1 {
                name: report.tool.name.clone(),
                version: report.tool.version.clone(),
                os: std::env::consts::OS.into(),
                architecture: std::env::consts::ARCH.into(),
                runtime_features,
            },
            invocation: InvocationV1 {
                association_sha256: association
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                requested_memory: report.policy.requested.memory.clone(),
                requested_deadline: report.policy.requested.deadline.clone(),
                applied_memory: report.policy.effective.memory.clone(),
                applied_deadline: report.policy.effective.deadline.clone(),
            },
            policy: report.policy.clone(),
            attempts: report.attempts.clone(),
            supervision: report.supervision.clone(),
            error: report.error.clone(),
            backend: report.backend.as_ref().map(OperationalBackendV1::from),
            authorization,
            launch: LaunchV1 {
                state: launch_state,
                target_pid: pid,
            },
            outcome: OutcomeV1 {
                kind,
                native_termination,
                wrapper_status: report
                    .supervision
                    .as_ref()
                    .map(|supervision| supervision.wrapper_exit_code)
                    .unwrap_or(125),
            },
            cleanup,
            restart: report
                .supervision
                .as_ref()
                .map(|supervision| supervision.restart.clone()),
            runtime: selected_runtime,
            private_execution,
            private_rejection: report
                .error
                .as_ref()
                .and_then(|error| error.private_rejection.clone())
                .or_else(|| {
                    operational_failure.and_then(|failure| failure.private_rejection.clone())
                }),
            diagnostics: report
                .error
                .as_ref()
                .and_then(|error| error.provider_failure.clone())
                .or_else(|| {
                    operational_failure.and_then(|failure| failure.provider_failure.clone())
                }),
            provider_association: operational_failure
                .and_then(|failure| failure.provider_association.clone()),
            delivery: DeliveryEvidence::Prepared,
        };
        if let Some(private) = &value.private_execution {
            let terminal = &private.terminal;
            value.launch = LaunchV1 {
                state: terminal.launch,
                target_pid: terminal.target_pid,
            };
            value.authorization = if terminal.authorization_offset_millis.is_some() {
                AuthorizationV1::Granted
            } else if terminal.launch == LaunchStateV1::Unknown {
                AuthorizationV1::Uncertain
            } else {
                AuthorizationV1::RejectedBeforeRelease
            };
            value.outcome.kind = terminal.outcome;
            value.outcome.native_termination = terminal.native_termination.clone();
            value.cleanup.state = private.cleanup_state();
            value.cleanup.direct_child_reaped =
                terminal.target_pid.is_some() && terminal.cleanup == CleanupStateV1::Complete;
            value.cleanup.workload_empty =
                (terminal.cleanup == CleanupStateV1::Complete).then_some(true);
        }
        if let Some(rejection) = &value.private_rejection {
            value.launch = LaunchV1 {
                state: LaunchStateV1::NotCreated,
                target_pid: None,
            };
            value.authorization = AuthorizationV1::RejectedBeforeRelease;
            value.outcome.kind = OutcomeKindV1::LaunchFailure;
            value.outcome.native_termination = None;
            value.cleanup.state = if rejection.reservation_may_remain {
                CleanupStateV1::Unknown
            } else {
                CleanupStateV1::Complete
            };
            value.cleanup.direct_child_reaped = false;
            value.cleanup.workload_empty = Some(true);
            value.provider_association = None;
        }
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        let operational_failure = self
            .attempts
            .last()
            .and_then(|attempt| attempt.operational_failure.as_ref());
        if let Some(failure) = operational_failure {
            failure.validate()?;
            if self.diagnostics != failure.provider_failure
                || self.provider_association != failure.provider_association
                || self.private_rejection != failure.private_rejection
            {
                return Err(
                    "failed-attempt projection differs from retained operational observations"
                        .into(),
                );
            }
        }
        let failed_windows_receipt = self
            .error
            .as_ref()
            .and_then(|error| error.windows_provider_rejection_v2.as_ref())
            .or_else(|| operational_failure.and_then(|failure| failure.windows_rejection.as_ref()))
            .filter(|rejection| rejection.is_consistent())
            .and_then(crate::WindowsProviderRejectionV2::terminal_receipt);
        let last_attempt = self.attempts.last();
        let unobserved_failure = self.private_execution.is_none()
            && self.private_rejection.is_none()
            && self
                .error
                .as_ref()
                .is_none_or(|error| error.windows_provider_rejection_v2.is_none())
            && operational_failure.is_none_or(|failure| failure.windows_rejection.is_none())
            && (last_attempt.is_some_and(|attempt| {
                attempt
                    .error
                    .as_ref()
                    .is_some_and(|error| error.workload_may_be_alive)
                    && !attempt.launch.target_released
                    && attempt.runtime.is_none()
            }) || self.error.as_ref().is_some_and(|error| {
                error.workload_may_be_alive
                    && !error.target_released
                    && error.runtime.is_none()
                    && error.windows_provider_rejection_v2.is_none()
            }));
        if unobserved_failure
            && (self.launch.state != LaunchStateV1::Unknown
                || self.authorization
                    != if self.policy.requested.boundary == BoundaryRequirement::Standard {
                        AuthorizationV1::NotRequiredForStandard
                    } else {
                        AuthorizationV1::Uncertain
                    }
                || self.cleanup.state == CleanupStateV1::Complete
                || self.outcome.native_termination.is_some()
                || self.diagnostics.is_none() && self.outcome.kind != OutcomeKindV1::Unknown)
        {
            return Err(
                "unobserved failed transaction cannot claim launch or native retirement facts"
                    .into(),
            );
        }
        if failed_windows_receipt.is_some_and(|receipt| {
            matches!(
                receipt.payload,
                crate::WindowsTerminalPayloadV2::RecoveredClosure { .. }
            )
        }) && self.outcome.native_termination.is_some()
        {
            return Err(
                "recovered closure cannot supply an unobserved original native outcome".into(),
            );
        }
        if let Some(crate::WindowsTerminalPayloadV2::Execution {
            outcome, child_pid, ..
        }) = failed_windows_receipt.map(|receipt| &receipt.payload)
        {
            let native_termination = match outcome {
                RunOutcome::Exited {
                    child: ChildTermination::Unavailable,
                    ..
                } => None,
                RunOutcome::Exited { child, .. } => Some(child.clone()),
                RunOutcome::LimitExceeded {
                    child_after_termination,
                    ..
                }
                | RunOutcome::DeadlineExceeded {
                    child_after_termination,
                    ..
                }
                | RunOutcome::Interrupted {
                    child_after_termination,
                    ..
                }
                | RunOutcome::MonitorFailed {
                    child_after_termination,
                    ..
                } => child_after_termination.clone(),
            };
            if self.outcome.kind != OutcomeKindV1::ProviderFailure
                || self.outcome.native_termination != native_termination
                || self.launch.target_pid.map(NonZeroU32::get) != Some(*child_pid)
            {
                return Err(
                    "failed Windows result differs from authenticated native terminal".into(),
                );
            }
        }
        if let Some(rejection) = &self.private_rejection {
            rejection.validate()?;
            if self.private_execution.is_some()
                || self.launch.state != LaunchStateV1::NotCreated
                || self.launch.target_pid.is_some()
                || self.authorization != AuthorizationV1::RejectedBeforeRelease
                || self.outcome.kind != OutcomeKindV1::LaunchFailure
                || self.outcome.native_termination.is_some()
                || self.cleanup.state
                    != if rejection.reservation_may_remain {
                        CleanupStateV1::Unknown
                    } else {
                        CleanupStateV1::Complete
                    }
                || self
                    .error
                    .as_ref()
                    .and_then(|error| error.private_rejection.as_ref())
                    .or_else(|| {
                        operational_failure.and_then(|failure| failure.private_rejection.as_ref())
                    })
                    != Some(rejection)
            {
                return Err(
                    "private preallocation rejection projection differs from actual bound facts"
                        .into(),
                );
            }
            if self.provider_association.is_some() || self.cleanup.direct_child_reaped {
                return Err("private rejection must retain raw native attempt identity and no-child observation".into());
            }
        }
        if let Some(private) = &self.private_execution {
            private.validate()?;
            let terminal = &private.terminal;
            if self.launch.state != terminal.launch
                || self.launch.target_pid != terminal.target_pid
                || self.outcome.kind != terminal.outcome
                || self.outcome.native_termination != terminal.native_termination
                || self.cleanup.state != private.cleanup_state()
            {
                return Err(
                    "private operational projection differs from actual native terminal".into(),
                );
            }
            let RuntimeV1::LinuxPrivateTcp4 {
                profile_reference,
                identity_reference,
                identity_kind,
                activation_epoch,
                native_abi,
                invocation_sha256,
                private_namespace_observed,
                no_socket_at_entry,
                exec_observed,
                resources_retired,
                ..
            } = &self.runtime
            else {
                return Err("private terminal requires selected private runtime facts".into());
            };
            let (expected_identity, expected_kind) = match &terminal
                .admission_metadata
                .request
                .execution_identity
            {
                crate::workload_contract::ExecutionIdentityRequestV2::PreserveCaller => {
                    ("caller", "preserve-caller")
                }
                crate::workload_contract::ExecutionIdentityRequestV2::AdministratorProfile {
                    reference,
                } => (reference.id.as_str(), "administrator-profile"),
            };
            let expected_authorization = if terminal.authorization_offset_millis.is_some() {
                AuthorizationV1::Granted
            } else if terminal.launch == LaunchStateV1::Unknown {
                AuthorizationV1::Uncertain
            } else {
                AuthorizationV1::RejectedBeforeRelease
            };
            if profile_reference != terminal.admission_metadata.profile_id.id.as_str()
                || identity_reference != expected_identity
                || identity_kind != expected_kind
                || *activation_epoch != terminal.admission_metadata.epoch.revision.get()
                || native_abi != &terminal.native_abi
                || self.authorization != expected_authorization
                || self.cleanup.direct_child_reaped
                    != (terminal.target_pid.is_some()
                        && terminal.cleanup == CleanupStateV1::Complete)
                || self
                    .attempts
                    .last()
                    .and_then(|attempt| attempt.private_execution.as_ref())
                    != Some(private)
                || !matches!(
                    self.attempts.last().map(|attempt| &attempt.boundary_detail),
                    Some(crate::BoundaryMechanismEvidence::LinuxPrivateTcp4(observed))
                        if observed.as_ref() == private
                )
                || invocation_sha256
                    != &String::from(terminal.admission_metadata.invocation_sha256.clone())
                || *exec_observed != terminal.exec_observed
                || *private_namespace_observed != terminal.exec_observed
                || *no_socket_at_entry != terminal.exec_observed
                || *resources_retired != (private.cleanup_state() == CleanupStateV1::Complete)
            {
                return Err("private runtime/native invocation facts conflict".into());
            }
        } else if matches!(self.runtime, RuntimeV1::LinuxPrivateTcp4 { .. }) {
            return Err("private runtime facts lack actual bound native terminal".into());
        }
        self.policy
            .validate_budget_presence(
                self.invocation.requested_memory.is_some(),
                self.invocation.requested_deadline.is_some(),
            )
            .map_err(|error| error.to_string())?;
        crate::report::validate_operational_history(
            &self.policy,
            self.supervision.as_ref(),
            &self.attempts,
            self.error.as_ref(),
        )
        .map_err(|error| error.to_string())?;
        if serde_json::to_value(&self.policy.requested.memory).map_err(|error| error.to_string())?
            != serde_json::to_value(&self.invocation.requested_memory)
                .map_err(|error| error.to_string())?
            || serde_json::to_value(&self.policy.requested.deadline)
                .map_err(|error| error.to_string())?
                != serde_json::to_value(&self.invocation.requested_deadline)
                    .map_err(|error| error.to_string())?
            || serde_json::to_value(&self.policy.effective.memory)
                .map_err(|error| error.to_string())?
                != serde_json::to_value(&self.invocation.applied_memory)
                    .map_err(|error| error.to_string())?
            || serde_json::to_value(&self.policy.effective.deadline)
                .map_err(|error| error.to_string())?
                != serde_json::to_value(&self.invocation.applied_deadline)
                    .map_err(|error| error.to_string())?
            || self
                .supervision
                .as_ref()
                .is_some_and(|summary| summary.wrapper_exit_code != self.outcome.wrapper_status)
        {
            return Err(
                "operational policy or terminal projection differs from actual history".into(),
            );
        }
        if self.format != "memcordon.result"
            || self.revision != 1
            || self.tool.runtime_features.len() > 16
            || self.cleanup.outstanding.len() > crate::MAX_RETIREMENT_OBLIGATIONS
            || self.cleanup.failed_operations.len() > 64
            || self.invocation.association_sha256.len() != Sha256::output_size() * 2
            || !self
                .invocation
                .association_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("unsupported or oversized operational result".into());
        }
        if self.authorization == AuthorizationV1::RejectedBeforeRelease
            && matches!(
                self.launch.state,
                LaunchStateV1::ReleaseIssued | LaunchStateV1::ExecObserved
            )
            || self.authorization == AuthorizationV1::Uncertain
                && self.launch.state == LaunchStateV1::NotCreated
            || self.launch.state == LaunchStateV1::NotCreated
                && (self.launch.target_pid.is_some() || self.outcome.native_termination.is_some())
            || self.launch.state == LaunchStateV1::ExecObserved && self.launch.target_pid.is_none()
        {
            return Err("authorization/launch/native outcome combination is impossible".into());
        }
        if self.cleanup.state == CleanupStateV1::Complete
            && (self.cleanup.workload_empty != Some(true)
                || !self.cleanup.outstanding.is_empty()
                || !self.cleanup.failed_operations.is_empty())
        {
            return Err("inconsistent complete retirement".into());
        }
        if let Some(diagnostic) = &self.diagnostics {
            if !diagnostic.is_consistent()
                || diagnostic.projection_sha256 != diagnostic.canonical_digest()
                || serde_json::to_vec(diagnostic)
                    .map_err(|error| error.to_string())?
                    .len()
                    > crate::MAX_DIAGNOSTIC_PROJECTION_BYTES
                || self.outcome.kind != OutcomeKindV1::ProviderFailure
            {
                return Err("inconsistent original provider failure".into());
            }
        }
        if let Some(association) = &self.provider_association {
            if !association.provider.is_consistent()
                || self.diagnostics.as_ref().is_some_and(|diagnostic| {
                    diagnostic.provider_binding != association.provider
                        || diagnostic.attempt_id != association.attempt_id
                        || diagnostic.request_sha256 != association.request_sha256
                })
            {
                return Err("public provider association differs from causal projection".into());
            }
        }
        if let RuntimeV1::LinuxPrivateTcp4 {
            native_abi,
            private_namespace_observed,
            no_socket_at_entry,
            exec_observed,
            port_range,
            unprivileged_port_start,
            resources_retired,
            ..
        } = &self.runtime
        {
            if !matches!(
                native_abi.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            ) || *exec_observed
                && (!private_namespace_observed
                    || !no_socket_at_entry
                    || self.launch.state != LaunchStateV1::ExecObserved)
                || *port_range != [32768, 60999]
                || *unprivileged_port_start != 0
                || *resources_retired && self.cleanup.state != CleanupStateV1::Complete
            {
                return Err("inconsistent private TCP operational facts".into());
            }
        }
        if let RuntimeV1::WindowsSealed { observation } = &self.runtime {
            let attempt_observation =
                self.attempts
                    .last()
                    .and_then(|attempt| match &attempt.boundary_detail {
                        crate::BoundaryMechanismEvidence::WindowsJobObjectV2(native) => {
                            Some(native.as_ref())
                        }
                        _ => None,
                    });
            let receipt_observation = self
                .error
                .as_ref()
                .and_then(|error| error.windows_provider_rejection_v2.as_ref())
                .or_else(|| {
                    operational_failure.and_then(|failure| failure.windows_rejection.as_ref())
                })
                .filter(|rejection| rejection.is_consistent())
                .and_then(crate::WindowsProviderRejectionV2::terminal_receipt)
                .and_then(|receipt| match &receipt.payload {
                    crate::WindowsTerminalPayloadV2::Execution {
                        boundary_detail, ..
                    } => match boundary_detail.as_ref() {
                        crate::BoundaryMechanismEvidence::WindowsJobObjectV2(native) => {
                            Some(native.as_ref())
                        }
                        _ => None,
                    },
                    _ => None,
                });
            if attempt_observation.or(receipt_observation) != Some(observation.as_ref()) {
                return Err(
                    "Windows runtime observation differs from actual attempt or failed receipt"
                        .into(),
                );
            }
        }
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > RESULT_MAX_BYTES {
            return Err("operational result exceeds byte bound".into());
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub enum ResultReport {
    Legacy(Box<MemcordonReport>),
    Operational(Box<ResultV1>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OperationalDiscoveryV1 {
    Authenticated {
        profile: crate::workload_contract::ProfileRef,
        supported: bool,
        available: bool,
        activation_epoch: Option<crate::workload_contract::PolicyEpoch>,
        grants: Vec<crate::workload_discovery::DiscoverableGrantV1>,
        complete: bool,
        ttl_seconds: u32,
    },
    Unavailable {
        reason: String,
    },
    Unsupported,
}

impl From<&crate::workload_discovery::DiscoveryReportV1> for OperationalDiscoveryV1 {
    fn from(value: &crate::workload_discovery::DiscoveryReportV1) -> Self {
        match value {
            crate::workload_discovery::DiscoveryReportV1::Authenticated { discovery } => {
                Self::Authenticated {
                    profile: discovery.profile.clone(),
                    supported: discovery.supported,
                    available: discovery.available,
                    activation_epoch: discovery.epoch.clone(),
                    grants: discovery.grants.as_slice().to_vec(),
                    complete: discovery.complete,
                    ttl_seconds: discovery.cache_ttl_seconds.min(60),
                }
            }
            crate::workload_discovery::DiscoveryReportV1::Unavailable { reason } => {
                Self::Unavailable {
                    reason: reason.as_str().into(),
                }
            }
            crate::workload_discovery::DiscoveryReportV1::Unsupported => Self::Unsupported,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesV1 {
    pub format: String,
    pub revision: u32,
    pub tool: crate::ToolReport,
    pub host: crate::HostReport,
    pub selected: Option<OperationalBackendV1>,
    pub available: Vec<OperationalBackendV1>,
    pub unavailable: Vec<crate::UnavailableCapabilityReport>,
    pub request_versions: Vec<u32>,
    pub discovery: OperationalDiscoveryV1,
    pub private_discovery: Option<crate::workload_discovery_v2::PrivateWorkloadDiscovery>,
    pub requirement: crate::RequirementReport,
    pub private_plan: Option<crate::private_runtime::PrivateRuntimePlan>,
    pub authorizes_launch: bool,
}

impl From<&crate::DoctorReport> for CapabilitiesV1 {
    fn from(value: &crate::DoctorReport) -> Self {
        Self {
            format: "memcordon.capabilities".into(),
            revision: 1,
            tool: value.tool.clone(),
            host: value.host.clone(),
            selected: value.selected.as_ref().map(OperationalBackendV1::from),
            available: value
                .available
                .iter()
                .map(OperationalBackendV1::from)
                .collect(),
            unavailable: value.unavailable.clone(),
            request_versions: vec![1],
            discovery: OperationalDiscoveryV1::from(&value.workload_discovery),
            private_discovery: None,
            requirement: value.requirement.clone(),
            private_plan: None,
            authorizes_launch: false,
        }
    }
}

impl CapabilitiesV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.capabilities"
            || self.revision != 1
            || self.authorizes_launch
            || self.request_versions.is_empty()
            || self.request_versions[0] != 1
            || self
                .request_versions
                .iter()
                .any(|version| !matches!(version, 1 | 2))
            || self
                .request_versions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.available.len() > 64
            || self.unavailable.len() > 64
        {
            return Err(
                "capabilities namespace, advisory marker, or finite catalogue differs".into(),
            );
        }
        match &self.discovery {
            OperationalDiscoveryV1::Authenticated {
                profile,
                supported,
                available,
                activation_epoch,
                grants,
                complete,
                ttl_seconds,
            } => {
                let native =
                    baseline_profile(profile).ok_or("unknown baseline discovery profile")?;
                if !supported
                    || !complete
                    || *ttl_seconds > 60
                    || grants.len() > 2048
                    || activation_epoch.is_none() && (*available || !grants.is_empty())
                    || grants.iter().enumerate().any(|(index, grant)| {
                        !crate::workload_registry::ceiling_contains(
                            &grant.ceiling,
                            &native.ceiling(),
                        ) || grants[..index]
                            .iter()
                            .any(|previous| previous.authorization == grant.authorization)
                    })
                {
                    return Err("baseline advisory discovery facts conflict".into());
                }
            }
            OperationalDiscoveryV1::Unavailable { reason } if reason.is_empty() => {
                return Err("unavailable discovery has no reason".into());
            }
            _ => {}
        }
        if let Some(discovery) = &self.private_discovery {
            if !discovery.validate() || !self.request_versions.contains(&2) {
                return Err("private advisory discovery or request version differs".into());
            }
        }
        if let Some(plan) = &self.private_plan {
            plan.validate()?;
            if !self.request_versions.contains(&2)
                || self.requirement.kind.as_deref() != Some("sealed")
                || self.requirement.met && !plan.available_for_preparation
                || self
                    .private_discovery
                    .as_ref()
                    .is_some_and(|discovery| discovery.provider != plan.provider)
            {
                return Err("private capability plan differs from provider or requirement".into());
            }
        }
        if self.request_versions.contains(&2)
            && self.private_discovery.is_none()
            && self.private_plan.is_none()
        {
            return Err("private request support has no actual advisory observation".into());
        }
        if self.requirement.workload.as_ref().is_some_and(|workload| {
            matches!(
                workload,
                crate::workload_evidence::RuntimeWorkloadResolution::Admitted { .. }
            )
        }) {
            return Err("capability observation cannot contain an admitted target".into());
        }
        advisory_size(self)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = parse_advisory(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanV1 {
    pub format: String,
    pub revision: u32,
    pub tool: crate::ToolReport,
    pub requested: crate::RequestedPolicyReport,
    pub workload: crate::workload_evidence::RuntimeWorkloadResolution,
    pub private_plan: Option<crate::private_runtime::PrivateRuntimePlan>,
    pub backend: OperationalBackendV1,
    pub applied_memory: Option<crate::EffectiveMemoryPolicyReport>,
    pub applied_deadline: Option<crate::DeadlinePolicyReport>,
    pub limitations: Vec<String>,
    pub pending_steps: Vec<String>,
    pub authorizes_launch: bool,
}

impl From<&crate::PlanReport> for PlanV1 {
    fn from(value: &crate::PlanReport) -> Self {
        let steps: &[&str] = if value.request.boundary == BoundaryRequirement::Sealed {
            &[
                "authenticate-caller-and-invocation",
                "resolve-local-grant-and-epoch",
                "hold-approved-executable",
                "resolve-target-identity",
                "allocate-native-boundary",
                "establish-guardian",
                "verify-native-controls",
                "commit-local-release",
            ]
        } else {
            &[
                "allocate-native-boundary",
                "create-owned-target",
                "verify-native-controls",
            ]
        };
        Self {
            format: "memcordon.plan".into(),
            revision: 1,
            private_plan: None,
            tool: value.tool.clone(),
            requested: value.request.clone(),
            workload: value.resolution.effective.workload.clone(),
            backend: OperationalBackendV1::from(&value.resolution.backend),
            applied_memory: value.resolution.effective.memory.clone(),
            applied_deadline: value.resolution.effective.deadline.clone(),
            limitations: value.resolution.limitations.clone(),
            pending_steps: steps.iter().map(|step| (*step).to_owned()).collect(),
            authorizes_launch: false,
        }
    }
}

fn baseline_profile(
    reference: &crate::workload_contract::ProfileRef,
) -> Option<crate::workload_registry::BaselineProfile> {
    use crate::workload_registry::BaselineProfile;
    [
        BaselineProfile::LinuxUnixCreate,
        BaselineProfile::WindowsHostNetworkExternal,
    ]
    .into_iter()
    .find(|profile| profile.reference() == *reference)
}

fn advisory_size(value: &impl Serialize) -> Result<(), String> {
    if serde_json::to_vec(value)
        .map_err(|error| error.to_string())?
        .len()
        > RESULT_MAX_BYTES
    {
        return Err("advisory output exceeds byte bound".into());
    }
    Ok(())
}

fn parse_advisory<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > RESULT_MAX_BYTES {
        return Err("advisory output exceeds byte bound".into());
    }
    crate::canonical_json::reject_duplicate_json_keys(bytes)?;
    let value: T = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    // Existing shared policy DTOs predate strict nested unknown-field rejection.
    // Comparing the exact parsed JSON shape prevents discarded nested fields
    // from silently changing this new named format's meaning.
    if serde_json::from_slice::<serde_json::Value>(bytes).map_err(|error| error.to_string())?
        != serde_json::to_value(&value).map_err(|error| error.to_string())?
    {
        return Err("advisory output contains an unknown or omitted field".into());
    }
    Ok(value)
}

impl PlanV1 {
    pub fn validate(&self) -> Result<(), String> {
        use crate::workload_evidence::{RuntimeWorkloadResolution, WorkloadRequestReport};
        if self.format != "memcordon.plan"
            || self.revision != 1
            || self.authorizes_launch
            || self.pending_steps.len() > 32
            || self.pending_steps.iter().enumerate().any(|(index, step)| {
                step.is_empty() || step.len() > 256 || self.pending_steps[..index].contains(step)
            })
            || !self.workload.matches_request(&self.requested.workload)
            || matches!(self.workload, RuntimeWorkloadResolution::Admitted { .. })
        {
            return Err("plan namespace, advisory marker, or request facts differ".into());
        }
        if let WorkloadRequestReport::StrictV1 { contract } = &self.requested.workload {
            let profile = baseline_profile(&contract.authorized_profile)
                .ok_or("unknown local plan profile")?;
            if self.requested.boundary != BoundaryRequirement::Sealed
                || !self.workload.valid_plan_response(contract, profile)
            {
                return Err("local plan differs from exact request/profile".into());
            }
        }
        if let Some(plan) = &self.private_plan {
            plan.validate()?;
            if self.requested.boundary != BoundaryRequirement::Sealed
                || !matches!(
                    self.requested.workload,
                    WorkloadRequestReport::LegacyUnspecified
                )
                || self.backend.boundary != crate::BoundaryClass::Sealed
            {
                return Err(
                    "private advisory plan has incompatible baseline request/backend".into(),
                );
            }
        }
        advisory_size(self)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = parse_advisory(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

impl ResultReport {
    pub fn prepare_writer(&mut self, writer_pid: NonZeroU32) {
        match self {
            Self::Operational(report) => {
                report.delivery = DeliveryEvidence::PreparedBy { writer_pid }
            }
            Self::Legacy(report) => {
                for runtime in report
                    .attempts
                    .iter_mut()
                    .filter_map(|attempt| attempt.runtime.as_mut())
                    .chain(
                        report
                            .error
                            .iter_mut()
                            .filter_map(|error| error.runtime.as_mut()),
                    )
                {
                    runtime.delivery = DeliveryEvidence::PreparedBy { writer_pid };
                }
            }
        }
    }

    pub fn write_bytes(&self, writer: &mut impl std::io::Write) -> Result<(), String> {
        match self {
            Self::Legacy(report) => serde_json::to_writer_pretty(&mut *writer, report)
                .map_err(|error| error.to_string())?,
            Self::Operational(report) => {
                report.validate()?;
                serde_json::to_writer_pretty(&mut *writer, report)
                    .map_err(|error| error.to_string())?;
            }
        }
        writer.write_all(b"\n").map_err(|error| error.to_string())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        self.write_bytes(&mut bytes)?;
        if bytes.len() > RESULT_MAX_BYTES {
            return Err("result exceeds byte bound".into());
        }
        Ok(bytes)
    }
}
