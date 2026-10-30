//! Current sealed reports are built directly from current native observations.
//! Historical numeric reports are never an intermediate wire representation.
use super::*;
use memcordon_core::execution_facts::{
    CleanupStateV1, OperationalToolV1, OutcomeKindV1, OutcomeV1,
};
use memcordon_core::result_v3::*;
use memcordon_core::{BoundaryMechanismEvidence, RunOutcome};

fn diagnostic_text(value: &str) -> memcordon_core::BoundedText<4096> {
    const LIMIT: usize = 4096;
    let suffix = " [truncated]";
    if value.len() <= LIMIT {
        return memcordon_core::BoundedText::new(value).expect("checked diagnostic bound");
    }
    let mut end = LIMIT - suffix.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    memcordon_core::BoundedText::new(&format!("{}{suffix}", &value[..end]))
        .expect("bounded diagnostic projection")
}

fn invocation(args: &ExecutionArgs, command: &CommandSpec) -> InvocationReport {
    let mut argv = vec![memcordon_core::NativeArgument::from_os(command.program())];
    argv.extend(
        command
            .arguments()
            .iter()
            .map(|value| memcordon_core::NativeArgument::from_os(value)),
    );
    InvocationReport {
        syntax: "plus-budgets-v1".into(),
        budget_tokens: budget_tokens(&args.budgets),
        memory_token: args.budgets.memory_token().map(str::to_owned),
        deadline_token: deadline_token(&args.budgets).map(str::to_owned),
        argv,
    }
}

fn tool() -> OperationalToolV1 {
    OperationalToolV1 {
        name: "memcordon".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        runtime_features: [
            ("sealed-runtime", cfg!(feature = "sealed-runtime")),
            ("private-tcp", cfg!(feature = "private-tcp")),
            (
                "windows-sealed-runtime",
                cfg!(feature = "windows-sealed-runtime"),
            ),
        ]
        .into_iter()
        .filter(|(_, enabled)| *enabled)
        .map(|(name, _)| name.into())
        .collect(),
    }
}

fn outcome(observed: Option<&RunOutcome>, wrapper_status: i32) -> OutcomeV1 {
    let (kind, native_termination) = match observed {
        Some(RunOutcome::Exited {
            child: memcordon_core::ChildTermination::Unavailable,
            ..
        }) => (OutcomeKindV1::Unknown, None),
        Some(RunOutcome::Exited { child, .. }) => (OutcomeKindV1::Completed, Some(child.clone())),
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
        None => (OutcomeKindV1::Unknown, None),
    };
    OutcomeV1 {
        kind,
        native_termination,
        wrapper_status,
    }
}

fn cleanup(native: &memcordon_core::WindowsSealedEvidenceV3) -> CleanupV3 {
    let mut obligations = memcordon_core::BoundedVec::default();
    for (resource, settled) in [
        (CleanupResourceV3::Target, native.direct_target_reaped),
        (CleanupResourceV3::Aggregate, native.active_processes_zero),
        (CleanupResourceV3::Guardian, native.guardian_reaped),
        (CleanupResourceV3::Relays, native.relays_retired),
        (CleanupResourceV3::Job, native.final_job_handles_closed),
        (
            CleanupResourceV3::Record,
            native
                .frontend_delivery
                .as_ref()
                .is_some_and(|delivery| delivery.acknowledgement_observed),
        ),
    ] {
        obligations
            .try_push(CleanupObligationV3 { resource, settled })
            .expect("finite native obligations fit");
    }
    let state = if obligations
        .as_slice()
        .iter()
        .all(|obligation| obligation.settled)
    {
        CleanupStateV1::Complete
    } else {
        CleanupStateV1::Incomplete
    };
    CleanupV3 { state, obligations }
}

fn base(
    args: &ExecutionArgs,
    command: &CommandSpec,
    policy: &PolicyEnvelopeReport,
    provider: Option<memcordon_core::PublicProviderBindingV1>,
) -> Result<ResultV3, String> {
    let invocation = invocation(args, command);
    let request = args
        .policy
        .workload_request
        .as_ref()
        .map(|request| {
            use sha2::{Digest, Sha256};
            let digest = |bytes: Vec<u8>| {
                memcordon_core::DiagnosticSha256::from_bytes(Sha256::digest(bytes).into())
            };
            Ok::<_, String>(WorkloadRequestAssociationV1 {
                request_sha256: request.digest().map_err(|error| error.to_string())?,
                invocation_sha256: digest(
                    serde_json::to_vec(&invocation).map_err(|error| error.to_string())?,
                ),
                resource_policy_sha256: digest(
                    serde_json::to_vec(&policy.requested).map_err(|error| error.to_string())?,
                ),
                runtime_sha256: None,
                input_sha256: None,
            })
        })
        .transpose()?;
    Ok(ResultV3 {
        format: "memcordon.result".into(),
        revision: 3,
        tool: tool(),
        invocation,
        request,
        provider,
        release: ReleaseKnowledgeV3::NotReleased,
        outcome: outcome(None, 125),
        cleanup: CleanupV3 {
            state: CleanupStateV1::Unknown,
            obligations: Default::default(),
        },
        delivery: DeliveryStateV3::Unknown,
        output_delivery: None,
        diagnostics: Default::default(),
        provider_failure: None,
        windows_rejection: None,
        windows_attempt: None,
        workload_attempt: None,
        request_rejection: None,
        runtime: RuntimeExecutionV3::PreparationFailed {
            profile: memcordon_core::BoundedText::new(
                match args
                    .policy
                    .workload_request
                    .as_ref()
                    .map(|request| &request.runtime)
                {
                    Some(memcordon_core::workload_request::RuntimeRequestV1::LinuxPrivate {
                        ..
                    }) => "linux-private-workload-v1",
                    Some(memcordon_core::workload_request::RuntimeRequestV1::WindowsSealed {
                        ..
                    }) => "windows-sealed-current-token-v1",
                    None if cfg!(target_os = "linux") => "linux-pid-namespace-cgroup-v2",
                    // Sealed preparation failed before selecting a native backend.
                    None if cfg!(target_os = "macos") => "unsupported-sealed-platform",
                    None => "windows-sealed-current-token-v1",
                },
            )
            .expect("fixed profile fits"),
        },
    })
}

#[cfg(not(target_os = "macos"))]
pub(super) fn success(
    args: &ExecutionArgs,
    command: &CommandSpec,
    resolution: &Resolution,
    execution: &SupervisionExecution,
) -> Result<ResultV3, String> {
    let Some(attempt) = execution.attempts().records().last() else {
        let mut report = base(args, command, &resolution.report, None)?;
        report.outcome = OutcomeV1 {
            kind: match execution.terminal() {
                SupervisionTerminal::DeadlineOutsideAttempt { .. } => OutcomeKindV1::Deadline,
                _ => OutcomeKindV1::LaunchFailure,
            },
            native_termination: None,
            wrapper_status: execution.wrapper_exit_code(),
        };
        report
            .diagnostics
            .try_push(
                memcordon_core::BoundedText::new(
                    "supervision terminated outside any native target attempt",
                )
                .expect("fixed diagnostic fits"),
            )
            .expect("one diagnostic fits");
        report.validate()?;
        return Ok(report);
    };
    if let Some(cancellation) = attempt
        .operational_failure
        .as_ref()
        .and_then(|failure| failure.windows_preallocation_cancellation.as_deref())
    {
        return preallocation_cancelled(args, command, &resolution.report, cancellation);
    }
    #[allow(clippy::collapsible_if)] // Preserve Rust 1.85 compatibility.
    if let Some(failure) = &attempt.operational_failure {
        if failure.workload_attempt.is_some() || failure.workload_rejection.is_some() {
            let message = attempt
                .error
                .as_ref()
                .map_or("current workload transport failed".to_owned(), |error| {
                    format!("{}: {}", error.code, error.message)
                });
            return workload_failure(
                args,
                command,
                &resolution.report,
                WorkloadFailureContext {
                    association: failure.workload_attempt.clone(),
                    binding: failure.workload_binding.clone(),
                    rejection: failure.workload_rejection.clone(),
                    input_complete: failure.workload_input_complete,
                    message: &message,
                    exit_code: execution.wrapper_exit_code(),
                },
            );
        }
    }
    if let BoundaryMechanismEvidence::LinuxPrivateWorkloadV1 { terminal, frontend } =
        &attempt.boundary_detail
    {
        terminal.validate()?;
        let mut report = base(
            args,
            command,
            &resolution.report,
            Some(terminal.association.provider.clone()),
        )?;
        report.workload_attempt = Some(terminal.association.clone());
        report.request = Some(terminal.request.clone());
        report.release = terminal.release;
        let native_termination = terminal
            .native
            .as_ref()
            .and_then(|native| native.native_wait_status)
            .and_then(|status| {
                #[cfg(unix)]
                {
                    if libc::WIFEXITED(status) {
                        Some(memcordon_core::ChildTermination::ExitCode {
                            code: libc::WEXITSTATUS(status),
                        })
                    } else if libc::WIFSIGNALED(status) {
                        Some(memcordon_core::ChildTermination::UnixSignal {
                            signal: libc::WTERMSIG(status),
                        })
                    } else {
                        None
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = status;
                    None
                }
            });
        report.outcome = OutcomeV1 {
            kind: match terminal.outcome {
                NativeWorkloadOutcomeV1::Exited { .. }
                | NativeWorkloadOutcomeV1::Signaled { .. } => OutcomeKindV1::Completed,
                NativeWorkloadOutcomeV1::Deadline => OutcomeKindV1::Deadline,
                NativeWorkloadOutcomeV1::MemoryLimit => OutcomeKindV1::ConfirmedMemoryLimit,
                NativeWorkloadOutcomeV1::ControlledCancellation => OutcomeKindV1::Interrupted,
                NativeWorkloadOutcomeV1::SetupFailure => OutcomeKindV1::LaunchFailure,
                NativeWorkloadOutcomeV1::Unknown => OutcomeKindV1::Unknown,
                _ => OutcomeKindV1::ProviderFailure,
            },
            native_termination,
            wrapper_status: execution.wrapper_exit_code(),
        };
        report.cleanup = terminal.cleanup.clone();
        report
            .cleanup
            .obligations
            .try_push(CleanupObligationV3 {
                resource: CleanupResourceV3::ControlHandles,
                settled: frontend.control_handles_retired,
            })
            .map_err(|_| "frontend control cleanup inventory full".to_owned())?;
        if !frontend.control_handles_retired || !frontend.relay_drained {
            report.cleanup.state = CleanupStateV1::Incomplete;
        }
        report.output_delivery = Some(
            if frontend.output_delivery == OutputDeliveryStateV3::Incomplete
                || terminal.output_delivery == OutputDeliveryStateV3::Incomplete
            {
                OutputDeliveryStateV3::Incomplete
            } else if frontend.output_delivery == OutputDeliveryStateV3::Unknown
                || terminal.output_delivery == OutputDeliveryStateV3::Unknown
            {
                OutputDeliveryStateV3::Unknown
            } else {
                OutputDeliveryStateV3::Complete
            },
        );
        let all = terminal
            .failures
            .as_slice()
            .iter()
            .chain(frontend.failures.as_slice());
        let count = terminal.failures.as_slice().len() + frontend.failures.as_slice().len();
        for failure in all.take(if count > 32 { 31 } else { 32 }) {
            report
                .diagnostics
                .try_push(failure.clone())
                .expect("bounded diagnostic count");
        }
        if count > 32 {
            report
                .diagnostics
                .try_push(diagnostic_text(
                    "additional native/frontend diagnostics omitted by result inventory bound",
                ))
                .expect("reserved overflow diagnostic slot");
        }
        report.runtime = match &terminal.native {
            Some(native) => RuntimeExecutionV3::LinuxPrivate {
                profile:
                    memcordon_core::workload_request::LinuxPrivateProfileV1::LinuxPrivateWorkload,
                native: Box::new(native.clone()),
            },
            None => RuntimeExecutionV3::PreparationFailed {
                profile: memcordon_core::BoundedText::new("linux-private-workload-v1")
                    .expect("fixed profile fits"),
            },
        };
        report.validate()?;
        return Ok(report);
    }
    if let BoundaryMechanismEvidence::LinuxSealedCurrent { native, provider } =
        &attempt.boundary_detail
    {
        let mut report = base(args, command, &resolution.report, Some(provider.clone()))?;
        report.release = if native.target_released {
            ReleaseKnowledgeV3::Released
        } else {
            ReleaseKnowledgeV3::NotReleased
        };
        report.outcome = outcome(attempt.outcome.as_ref(), execution.wrapper_exit_code());
        for (resource, settled) in [
            (
                CleanupResourceV3::Target,
                attempt.restart_safety.direct_child_reaped,
            ),
            (
                CleanupResourceV3::Aggregate,
                native.cgroup_empty_verified && native.cgroup_removed,
            ),
            (
                CleanupResourceV3::NamespaceInit,
                native.namespace_init_reaped,
            ),
            (CleanupResourceV3::Guardian, native.guardian_reaped),
        ] {
            report
                .cleanup
                .obligations
                .try_push(CleanupObligationV3 { resource, settled })
                .expect("finite native obligations fit");
        }
        report.cleanup.state = if report
            .cleanup
            .obligations
            .as_slice()
            .iter()
            .all(|obligation| obligation.settled)
        {
            CleanupStateV1::Complete
        } else {
            CleanupStateV1::Incomplete
        };
        report.runtime = RuntimeExecutionV3::LinuxSealed {
            native: native.clone(),
        };
        report.validate()?;
        return Ok(report);
    }
    if args
        .policy
        .workload_request
        .as_ref()
        .is_some_and(|request| {
            matches!(
                request.runtime,
                memcordon_core::workload_request::RuntimeRequestV1::LinuxPrivate { .. }
            )
        })
    {
        let message = attempt.error.as_ref().map_or(
            "current private workload produced no native terminal".to_owned(),
            |error| format!("{}: {}", error.code, error.message),
        );
        return workload_failure(
            args,
            command,
            &resolution.report,
            WorkloadFailureContext {
                association: None,
                binding: None,
                rejection: None,
                input_complete: false,
                message: &message,
                exit_code: execution.wrapper_exit_code(),
            },
        );
    }
    #[allow(clippy::collapsible_if)] // Preserve Rust 1.85 compatibility.
    if let Some(failure) = &attempt.operational_failure {
        if let Some(rejection) = &failure.windows_current_rejection {
            return rejected(
                args,
                command,
                &resolution.report,
                rejection,
                failure.provider_association.clone(),
                execution.wrapper_exit_code(),
            );
        }
    }
    let BoundaryMechanismEvidence::WindowsJobObjectV3(native) = &attempt.boundary_detail else {
        return Err("sealed provider supplied no current native observation".into());
    };
    native.validate().map_err(str::to_owned)?;
    let association = native
        .frontend_provider_association
        .as_ref()
        .ok_or("current execution has no authenticated provider association")?;
    if native.retirement.is_none() {
        return Err("current execution has no native retirement source".into());
    }
    let mut report = base(
        args,
        command,
        &resolution.report,
        Some(association.provider.clone()),
    )?;
    report.windows_attempt = Some(association.clone());
    report.release = if native.target_released {
        ReleaseKnowledgeV3::Released
    } else {
        ReleaseKnowledgeV3::NotReleased
    };
    report.outcome = match execution.terminal() {
        SupervisionTerminal::AttemptOutcome {
            outcome: observed, ..
        } => outcome(Some(observed), execution.wrapper_exit_code()),
        _ => outcome(attempt.outcome.as_ref(), execution.wrapper_exit_code()),
    };
    if !native.target_released {
        // A wait after cancellation of a suspended target is cleanup evidence.
        // It cannot become a public termination of an executed workload.
        report.outcome.native_termination = None;
    }
    report.cleanup = cleanup(native);
    report.provider_failure = attempt
        .operational_failure
        .as_ref()
        .and_then(|failure| failure.provider_failure.clone());
    report.runtime = RuntimeExecutionV3::WindowsSealed {
        profile: memcordon_core::workload_request::WindowsCurrentTokenProfileV1::WindowsSealedCurrentToken,
        native: native.clone(),
    };
    report.validate()?;
    Ok(report)
}

fn preallocation_cancelled(
    args: &ExecutionArgs,
    command: &CommandSpec,
    policy: &PolicyEnvelopeReport,
    cancellation: &memcordon_core::WindowsPreallocationCancellationV1,
) -> Result<ResultV3, String> {
    cancellation.validate().map_err(str::to_owned)?;
    let accepted = &cancellation.accepted;
    let mut report = base(args, command, policy, Some(accepted.provider.clone()))?;
    report.windows_attempt = Some(
        memcordon_core::execution_facts::ProviderAttemptAssociationV1 {
            provider: accepted.provider.clone(),
            attempt_id: memcordon_core::DiagnosticSha256::try_from(
                memcordon_core::BoundedText::new(&accepted.attempt_id).map_err(str::to_owned)?,
            )
            .map_err(str::to_owned)?,
            request_sha256: memcordon_core::DiagnosticSha256::try_from(
                memcordon_core::BoundedText::new(&accepted.request_sha256)
                    .map_err(str::to_owned)?,
            )
            .map_err(str::to_owned)?,
        },
    );
    report.outcome = OutcomeV1 {
        kind: OutcomeKindV1::Interrupted,
        native_termination: None,
        wrapper_status: cancellation.exit_code(),
    };
    report.cleanup = CleanupV3 {
        state: CleanupStateV1::Complete,
        obligations: Default::default(),
    };
    report.runtime=RuntimeExecutionV3::WindowsPreallocationCancelled {
        profile:memcordon_core::workload_request::WindowsCurrentTokenProfileV1::WindowsSealedCurrentToken,
        cancellation:Box::new(cancellation.clone()),
    };
    report.validate()?;
    Ok(report)
}

fn rejected(
    args: &ExecutionArgs,
    command: &CommandSpec,
    policy: &PolicyEnvelopeReport,
    rejection: &memcordon_core::WindowsProviderRejectionV3,
    association: Option<memcordon_core::execution_facts::ProviderAttemptAssociationV1>,
    exit_code: i32,
) -> Result<ResultV3, String> {
    if !rejection.is_consistent() {
        return Err("current provider rejection is inconsistent".into());
    }
    let mut report = base(
        args,
        command,
        policy,
        association
            .as_ref()
            .map(|association| association.provider.clone()),
    )?;
    report.provider_failure = rejection.provider_failure.clone();
    report.windows_rejection = Some(Box::new(rejection.clone()));
    report.windows_attempt = association.clone();
    report.outcome = OutcomeV1 {
        kind: OutcomeKindV1::ProviderFailure,
        native_termination: None,
        wrapper_status: exit_code,
    };
    if let Some(terminal) = rejection.terminal_receipt() {
        terminal.validate_for_attempt().map_err(str::to_owned)?;
        match &terminal.payload {
            memcordon_core::WindowsTerminalPayloadV3::Execution {
                outcome: observed,
                boundary_detail,
                ..
            } => {
                let BoundaryMechanismEvidence::WindowsJobObjectV3(native) =
                    boundary_detail.as_ref()
                else {
                    return Err("current rejection has foreign native evidence".into());
                };
                let mut native = native.clone();
                native.retirement = Some(Box::new(terminal.retirement_proof.clone()));
                native.frontend_provider_association = association;
                report.release = if native.target_released {
                    ReleaseKnowledgeV3::Released
                } else {
                    ReleaseKnowledgeV3::NotReleased
                };
                report.outcome = outcome(Some(observed), exit_code);
                if !native.target_released {
                    report.outcome.native_termination = None;
                }
                report.outcome.kind = OutcomeKindV1::ProviderFailure;
                report.cleanup = cleanup(&native);
                report.runtime = RuntimeExecutionV3::WindowsSealed { profile: memcordon_core::workload_request::WindowsCurrentTokenProfileV1::WindowsSealedCurrentToken, native };
            }
            memcordon_core::WindowsTerminalPayloadV3::RecoveredClosure {
                resume_attempted, ..
            } => {
                report.release = if *resume_attempted {
                    ReleaseKnowledgeV3::Unknown
                } else {
                    ReleaseKnowledgeV3::NotReleased
                };
                report.runtime = RuntimeExecutionV3::WindowsRecovered { profile: memcordon_core::workload_request::WindowsCurrentTokenProfileV1::WindowsSealedCurrentToken, terminal: Box::new(terminal.clone()) };
                // Native containment closure does not manufacture a direct wait.
                report.cleanup.state = CleanupStateV1::Unknown;
                report
                    .cleanup
                    .obligations
                    .try_push(CleanupObligationV3 {
                        resource: CleanupResourceV3::Record,
                        settled: false,
                    })
                    .expect("one retained record fits");
            }
            memcordon_core::WindowsTerminalPayloadV3::PrematureReleaseFailure { .. } => {
                report.release = ReleaseKnowledgeV3::Unknown;
                report.runtime = RuntimeExecutionV3::WindowsPrematureRelease {
                    profile: memcordon_core::workload_request::WindowsCurrentTokenProfileV1::WindowsSealedCurrentToken,
                    terminal: Box::new(terminal.clone()),
                };
            }
        }
    } else {
        report.release = if rejection.target_created
            && !rejection
                .restart_safety
                .is_safe_for(BoundaryRequirement::Sealed)
        {
            ReleaseKnowledgeV3::Unknown
        } else {
            ReleaseKnowledgeV3::NotReleased
        };
        report.cleanup.state = if rejection
            .restart_safety
            .is_safe_for(BoundaryRequirement::Sealed)
        {
            CleanupStateV1::Complete
        } else {
            CleanupStateV1::Unknown
        };
    }
    report
        .diagnostics
        .try_push(diagnostic_text(&rejection.detail))
        .map_err(|_| "diagnostic inventory full")?;
    report.validate()?;
    Ok(report)
}

pub(super) fn failure(
    args: &ExecutionArgs,
    command: &CommandSpec,
    policy: &PolicyEnvelopeReport,
    error: &Error,
    exit_code: i32,
) -> Result<ResultV3, String> {
    if let Some(cancellation) = error.windows_preallocation_cancellation.as_deref() {
        if error.target_released
            || error.target_pid.is_some()
            || error.workload_may_be_alive
            || error.windows_provider_rejection_v3.is_some()
            || error.provider_failure.is_some()
        {
            return Err(
                "preallocation cancellation conflicts with observed native target/failure facts"
                    .into(),
            );
        }
        return preallocation_cancelled(args, command, policy, cancellation);
    }
    if error.workload_attempt.is_some() || error.workload_rejection.is_some() {
        return workload_failure(
            args,
            command,
            policy,
            WorkloadFailureContext {
                association: error.workload_attempt.clone(),
                binding: error.workload_binding.clone(),
                rejection: error.workload_rejection.clone(),
                input_complete: error.workload_input_complete,
                message: &error.message,
                exit_code,
            },
        );
    }
    if let Some(rejection) = &error.windows_provider_rejection_v3 {
        return rejected(
            args,
            command,
            policy,
            rejection,
            error.provider_association.as_deref().cloned(),
            exit_code,
        );
    }
    let mut report = base(
        args,
        command,
        policy,
        error
            .provider_association
            .as_ref()
            .map(|association| association.provider.clone()),
    )?;
    report.provider_failure = error.provider_failure.clone();
    #[cfg(windows)]
    {
        report.windows_attempt = error.provider_association.as_deref().cloned();
    }
    report.release = if error.target_released || error.workload_may_be_alive {
        ReleaseKnowledgeV3::Unknown
    } else {
        ReleaseKnowledgeV3::NotReleased
    };
    report.outcome = OutcomeV1 {
        kind: OutcomeKindV1::LaunchFailure,
        native_termination: None,
        wrapper_status: exit_code,
    };
    report
        .diagnostics
        .try_push(diagnostic_text(&format!(
            "{}: {}",
            error.code, error.message
        )))
        .map_err(|_| "diagnostic inventory full")?;
    report.validate()?;
    Ok(report)
}

struct WorkloadFailureContext<'a> {
    association: Option<memcordon_core::workload_request::WorkloadAttemptAssociationV1>,
    binding: Option<WorkloadRequestAssociationV1>,
    rejection: Option<memcordon_core::workload_request::WorkloadRejectionV1>,
    input_complete: bool,
    message: &'a str,
    exit_code: i32,
}

fn workload_failure(
    args: &ExecutionArgs,
    command: &CommandSpec,
    policy: &PolicyEnvelopeReport,
    context: WorkloadFailureContext<'_>,
) -> Result<ResultV3, String> {
    let WorkloadFailureContext {
        association,
        binding,
        rejection,
        input_complete,
        message,
        exit_code,
    } = context;
    let mut report = base(
        args,
        command,
        policy,
        association
            .as_ref()
            .map(|association| association.provider.clone()),
    )?;
    report.workload_attempt = association;
    report.request_rejection = rejection;
    if let Some(binding) = binding {
        report.request = Some(binding);
    }
    report.release = if input_complete && report.request_rejection.is_none() {
        ReleaseKnowledgeV3::Unknown
    } else {
        ReleaseKnowledgeV3::NotReleased
    };
    report.outcome = OutcomeV1 {
        kind: OutcomeKindV1::LaunchFailure,
        native_termination: None,
        wrapper_status: exit_code,
    };
    report
        .diagnostics
        .try_push(diagnostic_text(message))
        .map_err(|_| "diagnostic inventory full")?;
    report.validate()?;
    Ok(report)
}

#[cfg(not(target_os = "macos"))]
pub(super) fn write(path: &Path, report: ResultV3) -> Result<(), String> {
    let mut report = memcordon_core::ResultReport::Current(Box::new(report));
    report
        .prepare_writer(std::num::NonZeroU32::new(std::process::id()).expect("writer pid nonzero"));
    write_report_bytes_atomic(path, &report.to_bytes()?).map_err(|error| error.to_string())
}
