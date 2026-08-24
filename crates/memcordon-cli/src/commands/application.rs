use std::path::Path;

use memcordon::exit_mapping::error_exit_code;
use memcordon::invocation::{
    BudgetSet, BudgetToken, CleanArgs, DoctorArgs, ExecutionArgs, PlanArgs, PolicyArgs, Requirement,
};
use memcordon_core::{
    BackendCapabilityReport, BackoffPolicyReport, BoundaryCapability, BoundaryClass,
    BoundaryRequirement, BudgetKindReport, BudgetTokenReport, CLEAN_REPORT_SCHEMA_VERSION,
    CircuitBreakerPolicyReport, CleanReport, CommandSpec, DOCTOR_REPORT_SCHEMA_VERSION,
    DeadlinePolicyReport, DeadlineScope, DoctorReport, DormantRestartCondition,
    EffectiveMemoryPolicyReport, EffectivePolicyReport, EffectiveRestartPolicyReport, Enforcement,
    Error, ErrorCategory, ExecutionErrorReport, HALF_LIFE_LOGISTIC_MODEL,
    HalfLifeLogisticBackoffState, HostReport, InvocationReport, Lifetime, MemcordonReport, Metric,
    OptionEffectReport, PLAN_REPORT_SCHEMA_VERSION, PlanReport, PlanResolutionReport, Policy,
    PolicyEnvelopeReport, RequestedMemoryPolicyReport, RequestedPolicyReport,
    RequestedRestartPolicyReport, RequirementReport, RestartCondition, RestartConditions,
    RestartPolicy, RestartSettings, SupervisionExecution, SupervisionTerminal, SwapPolicy,
    SwapReport, ToolReport, UnavailableCapabilityReport, write_report_atomic,
};
use memcordon_platform::{SupervisorRequest, capabilities, cleanup_stale, probe, supervise};

use crate::presentation::{self, ExecutionSummary, Presentation, SummaryTone};

#[derive(Clone, Debug)]
struct Resolution {
    backend: BackendCapabilityReport,
    policy: Policy,
    restart: RestartPolicy,
    report: PolicyEnvelopeReport,
}

pub(crate) fn execute(args: ExecutionArgs, presentation: &Presentation) -> i32 {
    if let Some(path) = &args.output.report_path {
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !parent.is_dir() {
            let mut out = presentation.stderr();
            presentation::write_runtime_error(
                &mut out,
                format_args!(
                    "report parent directory does not exist: {}",
                    parent.display()
                ),
            )
            .expect("report diagnostic should be writable");
            return 125;
        }
    }
    let (program, arguments) = args.command.split_first().expect("router requires command");
    let command = CommandSpec::new(program.clone()).args(arguments.iter().cloned());
    let resolution = match resolve(&args.policy, &args.budgets) {
        Ok(value) => value,
        Err(error) => return finish_error(&args, &command, None, *error, presentation),
    };
    if !args.output.quiet {
        render_effect_warnings(
            &resolution.report.effects,
            args.policy.restart_on.is_some(),
            args.policy.explicit.swap,
            presentation,
        );
    }
    let helper = match helper_path() {
        Ok(value) => value,
        Err(error) => {
            return finish_error(&args, &command, Some(&resolution), *error, presentation);
        }
    };
    match supervise(SupervisorRequest {
        policy: resolution.policy.clone(),
        restart: resolution.restart.clone(),
        command: command.clone(),
        memcordon_executable: helper,
        resolved_backend: Some(resolution.backend.clone()),
    }) {
        Ok(execution) => finish_execution(&args, &command, &resolution, execution, presentation),
        Err(error) => finish_error(&args, &command, Some(&resolution), error, presentation),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn helper_path() -> Result<Option<std::path::PathBuf>, Box<Error>> {
    std::env::current_exe().map(Some).map_err(|error| {
        Box::new(
            Error::new(
                ErrorCategory::Setup,
                "MCSETUP-MEMCORDON-EXECUTABLE",
                format!("could not resolve the installed MemCordon executable: {error}"),
            )
            .with_os_error(&error),
        )
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn helper_path() -> Result<Option<std::path::PathBuf>, Box<Error>> {
    Ok(None)
}

fn finish_execution(
    args: &ExecutionArgs,
    command: &CommandSpec,
    resolution: &Resolution,
    execution: SupervisionExecution,
    presentation: &Presentation,
) -> i32 {
    let exit_code = execution.wrapper_exit_code();
    if args.output.summary || exit_code == 123 || exit_code == 124 || exit_code == 125 {
        let mut out = presentation.stderr();
        presentation::write_summary(&mut out, execution_summary(&execution))
            .expect("execution summary should be writable");
    }
    if let Some(path) = &args.output.report_path {
        let report = match report(
            args,
            command,
            &resolution.report,
            Some(resolution.backend.clone()),
            Some(execution),
            None,
        ) {
            Ok(value) => value,
            Err(error) => {
                let mut out = presentation.stderr();
                presentation::write_runtime_error(
                    &mut out,
                    format_args!("could not construct execution report: {error}"),
                )
                .expect("report diagnostic should be writable");
                return 125;
            }
        };
        if let Err(error) = write_report_atomic(path, &report) {
            let mut out = presentation.stderr();
            presentation::write_runtime_error(&mut out, error)
                .expect("report diagnostic should be writable");
            return 125;
        }
    }
    exit_code
}

fn finish_error(
    args: &ExecutionArgs,
    command: &CommandSpec,
    resolution: Option<&Resolution>,
    error: Error,
    presentation: &Presentation,
) -> i32 {
    let exit_code = error_exit_code(&error);
    let mut out = presentation.stderr();
    presentation::write_runtime_error(&mut out, &error)
        .expect("runtime diagnostic should be writable");
    if let Some(path) = &args.output.report_path {
        let policy = resolution
            .map(|value| value.report.clone())
            .unwrap_or_else(|| unresolved_report(&args.policy, &args.budgets));
        let error_report = ExecutionErrorReport {
            category: category_name(error.category).to_owned(),
            code: error.code.to_owned(),
            message: error.message.clone(),
            os_code: error.os_code,
            attempt_number: None,
            supervision_phase: Some("initial-setup".to_owned()),
            launch_phase: error.launch_phase.map(str::to_owned),
            target_released: error.target_released,
            workload_may_be_alive: error.workload_may_be_alive,
            boundary_setup_failure: error.boundary_setup_failure.clone(),
            provider_rejection: error.provider_rejection.clone(),
        };
        match report(
            args,
            command,
            &policy,
            resolution.map(|value| value.backend.clone()),
            None,
            Some(error_report),
        ) {
            Ok(report) => {
                if let Err(report_error) = write_report_atomic(path, &report) {
                    let mut out = presentation.stderr();
                    presentation::write_runtime_error(&mut out, report_error)
                        .expect("report diagnostic should be writable");
                    return 125;
                }
            }
            Err(report_error) => {
                let mut out = presentation.stderr();
                presentation::write_runtime_error(
                    &mut out,
                    format_args!("could not construct failure report: {report_error}"),
                )
                .expect("report diagnostic should be writable");
                return 125;
            }
        }
    }
    exit_code
}

fn report(
    args: &ExecutionArgs,
    command: &CommandSpec,
    policy: &PolicyEnvelopeReport,
    backend: Option<BackendCapabilityReport>,
    supervision: Option<SupervisionExecution>,
    error: Option<ExecutionErrorReport>,
) -> Result<MemcordonReport, memcordon_core::ReportModelError> {
    let mut argv = Vec::with_capacity(command.arguments().len() + 1);
    argv.push(memcordon_core::NativeArgument::from_os(command.program()));
    argv.extend(
        command
            .arguments()
            .iter()
            .map(|value| memcordon_core::NativeArgument::from_os(value)),
    );
    MemcordonReport::schema8(
        tool_report(),
        InvocationReport {
            syntax: "plus-budgets-v1".to_owned(),
            budget_tokens: budget_tokens(&args.budgets),
            memory_token: args.budgets.memory_token().map(str::to_owned),
            deadline_token: deadline_token(&args.budgets).map(str::to_owned),
            argv,
        },
        policy.clone(),
        backend,
        supervision,
        error,
    )
}

fn execution_summary(execution: &SupervisionExecution) -> ExecutionSummary<'_> {
    let (outcome, tone) = match execution.terminal() {
        SupervisionTerminal::AttemptOutcome { outcome, .. } => match outcome {
            memcordon_core::RunOutcome::Exited { cleanup, .. }
                if !cleanup.errors.is_empty()
                    || !cleanup.direct_child_reaped
                    || cleanup.workload_empty == Some(false) =>
            {
                ("child exited", SummaryTone::Error)
            }
            memcordon_core::RunOutcome::Exited {
                child: memcordon_core::ChildTermination::Unavailable,
                ..
            } => ("child exited", SummaryTone::Error),
            memcordon_core::RunOutcome::Exited {
                child: memcordon_core::ChildTermination::WindowsStatus { status },
                ..
            } if i32::try_from(*status).is_err() => ("child exited", SummaryTone::Error),
            memcordon_core::RunOutcome::Exited { .. } if execution.wrapper_exit_code() == 0 => {
                ("child exited", SummaryTone::Success)
            }
            memcordon_core::RunOutcome::Exited { .. } => ("child exited", SummaryTone::Warning),
            memcordon_core::RunOutcome::LimitExceeded { .. } => {
                ("memory limit exceeded", SummaryTone::Error)
            }
            memcordon_core::RunOutcome::DeadlineExceeded { .. } => {
                ("deadline exceeded", SummaryTone::Error)
            }
            memcordon_core::RunOutcome::Interrupted { .. } => ("interrupted", SummaryTone::Warning),
            memcordon_core::RunOutcome::MonitorFailed { .. } => {
                ("monitor failed", SummaryTone::Error)
            }
        },
        SupervisionTerminal::DeadlineOutsideAttempt { .. } => {
            ("supervision deadline exceeded", SummaryTone::Error)
        }
        SupervisionTerminal::Error { .. } => ("supervision failed", SummaryTone::Error),
    };
    let (failure_code, failure_phase, failure_detail) = match execution.terminal() {
        SupervisionTerminal::Error { error, .. } => error.provider_rejection.as_ref().map_or(
            (
                Some(error.code.as_str()),
                error.launch_phase.as_deref(),
                Some(error.message.as_str()),
            ),
            |rejection| {
                (
                    Some(rejection.code.as_str()),
                    error.launch_phase.as_deref(),
                    Some(rejection.detail.as_str()),
                )
            },
        ),
        _ => (None, None, None),
    };
    ExecutionSummary {
        outcome,
        tone,
        status: execution.wrapper_exit_code(),
        backend: &execution.backend().name,
        attempts: execution.attempts().total,
        restarts: execution.restart().restarts_launched(),
        failure_code,
        failure_phase,
        failure_detail,
    }
}

fn resolve(policy_args: &PolicyArgs, budgets: &BudgetSet) -> Result<Resolution, Box<Error>> {
    let policy = policy_args.policy(budgets);
    let probe = probe();
    let backend = probe
        .selected_for(policy.boundary())
        .cloned()
        .ok_or_else(|| {
            if policy.boundary() == BoundaryRequirement::Sealed {
                return sealed_boundary_unsupported();
            }
            Box::new(Error::new(
                ErrorCategory::Unsupported,
                "MCUNSUPPORTED-BACKEND",
                format!(
                    "no supported backend is available: {}",
                    probe
                        .unavailable
                        .iter()
                        .map(|value| format!("{}: {}", value.name, value.reason))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ))
        })?;
    let capability = memcordon_platform::capabilities_for(&backend, policy.boundary());
    if policy.boundary() == BoundaryRequirement::Sealed
        && capability.boundary.class != BoundaryClass::Sealed
    {
        return Err(sealed_boundary_unsupported());
    }
    if policy.enforcement == Enforcement::Hard && !backend.hard_limit {
        return Err(Box::new(Error::new(
            ErrorCategory::Unsupported,
            "MCUNSUPPORTED-HARD",
            "hard enforcement is unavailable on the selected backend",
        )));
    }
    if policy.enforcement == Enforcement::Watchdog && backend.class != "watchdog" {
        return Err(Box::new(Error::new(
            ErrorCategory::Unsupported,
            "MCUNSUPPORTED-WATCHDOG",
            "watchdog enforcement is unavailable on the selected backend",
        )));
    }
    let configured = if policy_args.restart || policy_args.restart_on.is_some() {
        policy_args.restart_on.unwrap_or(RestartConditions::BOTH)
    } else {
        RestartConditions::NONE
    };
    let mut effective = RestartConditions::NONE;
    let mut dormant = Vec::new();
    for condition in [RestartCondition::MemoryLimit, RestartCondition::Deadline] {
        if !configured.contains(condition) {
            continue;
        }
        let active = match condition {
            RestartCondition::MemoryLimit => {
                budgets.memory.is_some() && capability.restart_conditions.contains(condition)
            }
            RestartCondition::Deadline => {
                budgets.deadline.is_some()
                    && policy_args.deadline_scope == DeadlineScope::Attempt
                    && capability.restart_conditions.contains(condition)
            }
        };
        if active {
            effective = add_condition(effective, condition);
        } else {
            dormant.push(DormantRestartCondition {
                condition,
                reason: match condition {
                    RestartCondition::MemoryLimit => {
                        "no effective memory-limit condition".to_owned()
                    }
                    RestartCondition::Deadline => {
                        "deadline is absent, supervision-scoped, or unsupported".to_owned()
                    }
                },
            });
        }
    }
    let restart = if configured.is_empty() {
        RestartPolicy::Never
    } else {
        RestartPolicy::OnLimits(
            RestartSettings::new(
                configured,
                effective,
                dormant.clone(),
                policy_args.restart_limit,
                policy_args.backoff,
                policy_args.circuit_breaker,
            )
            .map_err(|error| {
                Box::new(Error::new(
                    ErrorCategory::Usage,
                    "MCUSAGE-RESTART",
                    error.to_string(),
                ))
            })?,
        )
    };
    let restart = memcordon::resolve_restart_policy(&policy, restart).map_err(Box::new)?;
    let report = policy_report(
        policy_args,
        budgets,
        &policy,
        &backend,
        configured,
        effective,
        dormant,
    );
    Ok(Resolution {
        backend: capability,
        policy,
        restart,
        report,
    })
}

fn sealed_boundary_unsupported() -> Box<Error> {
    Box::new(
        Error::new(
            ErrorCategory::Unsupported,
            "MCBOUNDARY-UNSUPPORTED",
            "certified sealed supervision is unavailable on this host; the target was not authorized",
        )
        .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
            requested: BoundaryRequirement::Sealed,
            mechanism: None,
            phase: memcordon_core::BoundarySetupPhase::ProviderConnection,
            target_created: false,
            target_released: false,
            cleanup_attempted: false,
            restart_safety: memcordon_core::RestartSafetyProof::default(),
        }),
    )
}

fn add_condition(value: RestartConditions, condition: RestartCondition) -> RestartConditions {
    match (value, condition) {
        (RestartConditions::NONE, RestartCondition::MemoryLimit) => RestartConditions::MEMORY_LIMIT,
        (RestartConditions::NONE, RestartCondition::Deadline) => RestartConditions::DEADLINE,
        (RestartConditions::MEMORY_LIMIT, RestartCondition::Deadline)
        | (RestartConditions::DEADLINE, RestartCondition::MemoryLimit) => RestartConditions::BOTH,
        _ => value,
    }
}

fn policy_report(
    args: &PolicyArgs,
    budgets: &BudgetSet,
    policy: &Policy,
    backend: &memcordon_platform::BackendInfo,
    configured: RestartConditions,
    effective_conditions: RestartConditions,
    dormant_conditions: Vec<DormantRestartCondition>,
) -> PolicyEnvelopeReport {
    let boundary_capability =
        memcordon_platform::capabilities_for(backend, policy.boundary()).boundary;
    let effective_enforcement = if backend.hard_limit {
        "hard"
    } else {
        "watchdog"
    };
    let effective_wait =
        if backend.name == "windows-job-object" && policy.lifetime == Lifetime::Workload {
            "command"
        } else {
            wait_name(policy.lifetime)
        };
    let effective_metric = if policy.metric == Metric::Native || backend.class != "watchdog" {
        backend.metric
    } else {
        metric_name(policy.metric)
    };
    let mut effects = Vec::new();
    if policy.enforcement == Enforcement::Auto {
        effects.push(OptionEffectReport::Adjusted {
            option: "enforcement".to_owned(),
            requested: "auto".to_owned(),
            effective: effective_enforcement.to_owned(),
            reason: format!("auto selected backend {}", backend.name),
        });
    } else {
        effects.push(OptionEffectReport::Applied {
            option: "enforcement".to_owned(),
        });
    }
    if backend.name == "windows-job-object" && policy.lifetime == Lifetime::Workload {
        effects.push(OptionEffectReport::Ignored {
            option: "wait-for".to_owned(),
            requested: "workload".to_owned(),
            reason: "the Windows backend uses command-style completion".to_owned(),
        });
    } else {
        effects.push(OptionEffectReport::Applied {
            option: "wait-for".to_owned(),
        });
    }
    if policy.metric != Metric::Native && backend.class != "watchdog" {
        effects.push(OptionEffectReport::Ignored {
            option: "metric".to_owned(),
            requested: metric_name(policy.metric).to_owned(),
            reason: format!("{} uses its native kernel metric", backend.name),
        });
    } else {
        effects.push(OptionEffectReport::Applied {
            option: "metric".to_owned(),
        });
    }
    effects.push(OptionEffectReport::Applied {
        option: "poll-interval".to_owned(),
    });
    if args.explicit.command_exit_grace {
        effects.push(OptionEffectReport::Applied {
            option: "command-exit-grace".to_owned(),
        });
    }
    if uses_linux_cgroup_memory(backend.name) {
        effects.push(OptionEffectReport::Applied {
            option: "swap".to_owned(),
        });
    } else if policy.memory.is_some() {
        effects.push(OptionEffectReport::Ignored {
            option: "swap".to_owned(),
            requested: swap_name(policy.swap),
            reason: format!(
                "{} has no separately configurable swap policy",
                backend.name
            ),
        });
    }
    if let Some(deadline) = policy.deadline {
        effects.push(OptionEffectReport::Applied {
            option: "deadline-scope".to_owned(),
        });
        effects.push(OptionEffectReport::Adjusted {
            option: "deadline-origin".to_owned(),
            requested: "platform-authorization".to_owned(),
            effective: deadline_origin(backend.name).to_owned(),
            reason: format!(
                "the {:?} deadline clock starts at the backend authorization boundary",
                deadline.scope()
            ),
        });
    }
    if policy.memory.is_some() || policy.deadline.is_some() {
        effects.push(OptionEffectReport::Applied {
            option: "limit-grace".to_owned(),
        });
    }
    for dormant in &dormant_conditions {
        effects.push(OptionEffectReport::Ignored {
            option: "restart-on".to_owned(),
            requested: restart_condition_name(dormant.condition).to_owned(),
            reason: dormant.reason.clone(),
        });
    }
    let requested = requested_report(args, budgets, configured);
    PolicyEnvelopeReport {
        requested,
        effective: EffectivePolicyReport {
            boundary: match policy.boundary() {
                memcordon_core::BoundaryRequirement::Sealed
                    if boundary_capability.class != memcordon_core::BoundaryClass::Sealed =>
                {
                    memcordon_core::BoundaryClass::Unavailable
                }
                _ => boundary_capability.class,
            },
            memory: policy.memory.map(|memory| EffectiveMemoryPolicyReport {
                limit_bytes: memory.bytes(),
                enforcement: effective_enforcement.to_owned(),
                metric: effective_metric.to_owned(),
                poll_interval_ms: Some(milliseconds(policy.poll_interval)),
                swap: uses_linux_cgroup_memory(backend.name).then(|| swap_report(policy.swap)),
            }),
            deadline: policy.deadline.map(|deadline| DeadlinePolicyReport {
                duration_ms: milliseconds(deadline.duration()),
                scope: deadline.scope(),
                origin: Some(deadline_origin(backend.name).to_owned()),
                clock: "rust-instant".to_owned(),
            }),
            wait_for: effective_wait.to_owned(),
            signal_grace_ms: milliseconds(policy.signal_grace),
            command_exit_grace_ms: milliseconds(policy.command_exit_grace),
            limit_grace_ms: milliseconds(policy.limit_grace),
            restart: EffectiveRestartPolicyReport {
                enabled: !configured.is_empty(),
                conditions: effective_conditions,
                dormant_conditions,
                cleanup_proof_required: !configured.is_empty(),
            },
        },
        effects,
    }
}

fn requested_report(
    args: &PolicyArgs,
    budgets: &BudgetSet,
    configured: RestartConditions,
) -> RequestedPolicyReport {
    RequestedPolicyReport {
        boundary: args.boundary,
        memory: budgets.memory.map(|memory| RequestedMemoryPolicyReport {
            limit_bytes: memory.bytes(),
            enforcement: enforcement_name(args.enforcement).to_owned(),
            metric: metric_name(args.metric).to_owned(),
            poll_interval_ms: milliseconds(args.poll_interval),
            swap: swap_report(args.swap),
        }),
        deadline: budgets.deadline.map(|duration| DeadlinePolicyReport {
            duration_ms: milliseconds(duration),
            scope: args.deadline_scope,
            origin: None,
            clock: "rust-instant".to_owned(),
        }),
        wait_for: wait_name(args.wait_for).to_owned(),
        signal_grace_ms: milliseconds(args.signal_grace),
        command_exit_grace_ms: milliseconds(args.command_exit_grace),
        limit_grace_ms: milliseconds(args.limit_grace),
        restart: RequestedRestartPolicyReport {
            enabled: !configured.is_empty(),
            enablement_source: if args.restart_on.is_some() {
                Some("restart-on".to_owned())
            } else if args.restart {
                Some("restart".to_owned())
            } else {
                None
            },
            configured_conditions: configured,
            limit: args.restart_limit,
            backoff: (!configured.is_empty()).then(|| BackoffPolicyReport {
                model: HALF_LIFE_LOGISTIC_MODEL.to_owned(),
                base_interval_ms: milliseconds(args.backoff.base_interval()),
                multiplier_numerator: args.backoff.multiplier().numerator(),
                multiplier_denominator: args.backoff.multiplier().denominator(),
                asymptote_interval_ms: milliseconds(args.backoff.asymptote_interval()),
                recovery_half_life_ms: milliseconds(args.backoff.recovery_half_life()),
                quantization: "ceil-whole-milliseconds".to_owned(),
            }),
            circuit_breaker: args
                .circuit_breaker
                .map(|value| CircuitBreakerPolicyReport {
                    threshold: value.threshold(),
                    half_life_ms: milliseconds(value.half_life()),
                    cooldown_ms: milliseconds(value.cooldown()),
                }),
        },
    }
}

fn unresolved_report(args: &PolicyArgs, budgets: &BudgetSet) -> PolicyEnvelopeReport {
    let configured = if args.restart || args.restart_on.is_some() {
        args.restart_on.unwrap_or(RestartConditions::BOTH)
    } else {
        RestartConditions::NONE
    };
    let dormant = [RestartCondition::MemoryLimit, RestartCondition::Deadline]
        .into_iter()
        .filter(|condition| configured.contains(*condition))
        .map(|condition| DormantRestartCondition {
            condition,
            reason: "backend resolution failed".to_owned(),
        })
        .collect();
    PolicyEnvelopeReport {
        requested: requested_report(args, budgets, configured),
        effective: EffectivePolicyReport {
            boundary: memcordon_core::BoundaryClass::Unavailable,
            memory: budgets.memory.map(|memory| EffectiveMemoryPolicyReport {
                limit_bytes: memory.bytes(),
                enforcement: "unresolved".to_owned(),
                metric: "unresolved".to_owned(),
                poll_interval_ms: None,
                swap: None,
            }),
            deadline: budgets.deadline.map(|duration| DeadlinePolicyReport {
                duration_ms: milliseconds(duration),
                scope: args.deadline_scope,
                origin: None,
                clock: "rust-instant".to_owned(),
            }),
            wait_for: wait_name(args.wait_for).to_owned(),
            signal_grace_ms: milliseconds(args.signal_grace),
            command_exit_grace_ms: milliseconds(args.command_exit_grace),
            limit_grace_ms: milliseconds(args.limit_grace),
            restart: EffectiveRestartPolicyReport {
                enabled: !configured.is_empty(),
                conditions: RestartConditions::NONE,
                dormant_conditions: dormant,
                cleanup_proof_required: !configured.is_empty(),
            },
        },
        effects: Vec::new(),
    }
}

pub(crate) fn plan(args: PlanArgs, presentation: &Presentation) -> i32 {
    let (backend, report) = match resolve(&args.policy, &args.budgets) {
        Ok(value) => (value.backend, value.report),
        Err(error) if error.code == "MCBOUNDARY-UNSUPPORTED" => (
            unavailable_backend_capability(),
            unresolved_report(&args.policy, &args.budgets),
        ),
        Err(error) => {
            let mut out = presentation.stderr();
            presentation::write_runtime_error(&mut out, error)
                .expect("plan diagnostic should be writable");
            return 125;
        }
    };
    let limitations = backend.limitations.clone();
    let plan = PlanReport {
        schema_version: PLAN_REPORT_SCHEMA_VERSION,
        tool: tool_report(),
        budget_tokens: budget_tokens(&args.budgets),
        request: report.requested,
        resolution: PlanResolutionReport {
            backend,
            effective: report.effective,
            effects: report.effects,
            limitations,
            launch_proof: false,
            backoff_sample_ms: if args.policy.restart || args.policy.restart_on.is_some() {
                let mut backoff = HalfLifeLogisticBackoffState::new(args.policy.backoff)
                    .unwrap_or_else(|error| panic!("validated backoff became invalid: {error}"));
                vec![milliseconds(
                    backoff
                        .on_backoff(std::time::Duration::ZERO)
                        .unwrap_or_else(|error| {
                            panic!("validated first backoff became invalid: {error}")
                        }),
                )]
            } else {
                Vec::new()
            },
        },
    };
    if args.json {
        print_json(&plan, "plan", presentation)
    } else {
        let mut out = presentation.stdout();
        presentation::write_selected_backend(&mut out, &plan.resolution.backend.name)
            .expect("plan output should be writable");
        presentation::write_label_value(&mut out, "launch proof", false)
            .expect("plan output should be writable");
        0
    }
}

fn unavailable_backend_capability() -> BackendCapabilityReport {
    BackendCapabilityReport {
        name: "unresolved".to_owned(),
        boundary: BoundaryCapability {
            class: BoundaryClass::Unavailable,
            mechanism: "unavailable".to_owned(),
            limitations: vec!["certified sealed supervision is unavailable".to_owned()],
            ..BoundaryCapability::default()
        },
        limitations: vec!["no backend satisfies the requested sealed boundary".to_owned()],
        sealed_unavailable: Some(memcordon_core::SealedUnavailableReport {
            reason: "no certified sealed backend was selected".to_owned(),
            prerequisites: Vec::new(),
        }),
        ..BackendCapabilityReport::default()
    }
}

pub(crate) fn doctor(args: DoctorArgs, presentation: &Presentation) -> i32 {
    let probe = probe();
    let capability = |backend: &memcordon_platform::BackendInfo| match args.requirement {
        Some(Requirement::Sealed) => {
            memcordon_platform::capabilities_for(backend, BoundaryRequirement::Sealed)
        }
        _ => capabilities(backend),
    };
    let selected_backend = match args.requirement {
        Some(Requirement::Sealed) => probe.selected_for(BoundaryRequirement::Sealed),
        _ => probe.selected.as_ref(),
    };
    let selected = selected_backend.map(capability);
    let available = probe.available.iter().map(capability).collect::<Vec<_>>();
    let met = args.requirement.is_none_or(|required| {
        selected.as_ref().is_some_and(|backend| match required {
            Requirement::Hard => backend
                .memory
                .as_ref()
                .is_some_and(|memory| memory.class == "hard"),
            Requirement::Watchdog => backend
                .memory
                .as_ref()
                .is_some_and(|memory| memory.class == "watchdog"),
            Requirement::Sealed => backend.boundary.class == memcordon_core::BoundaryClass::Sealed,
        })
    });
    let report = DoctorReport {
        schema_version: DOCTOR_REPORT_SCHEMA_VERSION,
        tool: tool_report(),
        host: HostReport {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
        },
        selected,
        available,
        unavailable: probe
            .unavailable
            .into_iter()
            .map(|value| UnavailableCapabilityReport {
                name: value.name.to_owned(),
                reason: value.reason,
            })
            .collect(),
        requirement: RequirementReport {
            kind: args.requirement.map(|value| match value {
                Requirement::Hard => "hard".to_owned(),
                Requirement::Watchdog => "watchdog".to_owned(),
                Requirement::Sealed => "sealed".to_owned(),
            }),
            met,
            reason: (!met)
                .then(|| "selected backend does not satisfy the requested enforcement".to_owned()),
        },
    };
    if args.json {
        let code = print_json(&report, "doctor", presentation);
        if code != 0 {
            return code;
        }
    } else {
        let mut out = presentation.stdout();
        presentation::write_version(&mut out, env!("CARGO_PKG_VERSION"))
            .expect("doctor output should be writable");
        presentation::write_selected_backend(
            &mut out,
            report
                .selected
                .as_ref()
                .map_or("none", |value| value.name.as_str()),
        )
        .expect("doctor output should be writable");
    }
    if met { 0 } else { 125 }
}

pub(crate) fn clean(args: CleanArgs, presentation: &Presentation) -> i32 {
    match cleanup_stale(args.dry_run) {
        Ok(cleaned) => {
            if args.json {
                print_json(
                    &CleanReport {
                        schema_version: CLEAN_REPORT_SCHEMA_VERSION,
                        dry_run: args.dry_run,
                        cleaned,
                    },
                    "clean",
                    presentation,
                )
            } else {
                let mut out = presentation.stdout();
                for value in cleaned {
                    presentation::write_clean_action(&mut out, args.dry_run, value)
                        .expect("clean output should be writable");
                }
                0
            }
        }
        Err(error) => {
            if args.json {
                let failure = clean_failure_report(args.dry_run, &error);
                let _ = print_json(&failure, "clean error", presentation);
            }
            let mut out = presentation.stderr();
            presentation::write_runtime_error(&mut out, error)
                .expect("clean diagnostic should be writable");
            125
        }
    }
}

fn clean_failure_report(dry_run: bool, error: &Error) -> serde_json::Value {
    serde_json::json!({
        "schema_version": CLEAN_REPORT_SCHEMA_VERSION,
        "platform": std::env::consts::OS,
        "dry_run": dry_run,
        "objects_examined": 0,
        "stale_objects_selected": [],
        "objects_removed": [],
        "skipped": [],
        "errors": [{
            "code": error.code,
            "message": error.message,
        }],
    })
}

fn budget_tokens(budgets: &BudgetSet) -> Vec<BudgetTokenReport> {
    budgets
        .source_order
        .iter()
        .map(|value| match value {
            BudgetToken::Memory { raw, .. } => BudgetTokenReport {
                kind: BudgetKindReport::Memory,
                token: raw.to_string_lossy().into_owned(),
            },
            BudgetToken::Time { raw, .. } => BudgetTokenReport {
                kind: BudgetKindReport::Time,
                token: raw.to_string_lossy().into_owned(),
            },
        })
        .collect()
}
fn deadline_token(budgets: &BudgetSet) -> Option<&str> {
    budgets.source_order.iter().find_map(|value| match value {
        BudgetToken::Time { raw, .. } => raw.to_str(),
        BudgetToken::Memory { .. } => None,
    })
}
fn tool_report() -> ToolReport {
    ToolReport {
        name: "memcordon".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}
fn print_json(value: &impl serde::Serialize, name: &str, presentation: &Presentation) -> i32 {
    let mut out = Presentation::machine_stdout();
    match presentation::write_json(&mut out, value) {
        Ok(()) => 0,
        Err(error) => {
            let mut out = presentation.stderr();
            presentation::write_runtime_error(
                &mut out,
                format_args!("could not serialize {name}: {error}"),
            )
            .expect("serialization diagnostic should be writable");
            125
        }
    }
}
fn milliseconds(value: std::time::Duration) -> u64 {
    value.as_millis().try_into().unwrap_or(u64::MAX)
}
fn enforcement_name(value: Enforcement) -> &'static str {
    match value {
        Enforcement::Auto => "auto",
        Enforcement::Hard => "hard",
        Enforcement::Watchdog => "watchdog",
    }
}
fn wait_name(value: Lifetime) -> &'static str {
    match value {
        Lifetime::Command => "command",
        Lifetime::Workload => "workload",
    }
}
fn metric_name(value: Metric) -> &'static str {
    match value {
        Metric::Native => "native",
        Metric::PhysicalFootprint => "physical-footprint",
        Metric::Rss => "rss",
        Metric::Virtual => "virtual",
    }
}
fn swap_report(value: SwapPolicy) -> SwapReport {
    match value {
        SwapPolicy::Bytes(bytes) => SwapReport::Bytes {
            bytes: bytes.bytes(),
        },
        SwapPolicy::Unlimited => SwapReport::Unlimited,
        SwapPolicy::Host => SwapReport::Host,
    }
}
fn swap_name(value: SwapPolicy) -> String {
    match value {
        SwapPolicy::Bytes(bytes) => format!("{}B", bytes.bytes()),
        SwapPolicy::Unlimited => "unlimited".to_owned(),
        SwapPolicy::Host => "host".to_owned(),
    }
}
fn restart_condition_name(value: RestartCondition) -> &'static str {
    match value {
        RestartCondition::MemoryLimit => "memory-limit",
        RestartCondition::Deadline => "deadline",
    }
}
fn deadline_origin(backend: &str) -> &'static str {
    match backend {
        "linux-cgroup-v2" => "installed-cli-release-byte",
        "windows-job-object" => "suspended-thread-resume",
        "macos-watchdog" => "pre-spawn",
        _ => "platform-authorization",
    }
}
fn uses_linux_cgroup_memory(backend: &str) -> bool {
    matches!(backend, "linux-cgroup-v2" | "linux-sealed-provider")
}
fn category_name(value: ErrorCategory) -> &'static str {
    match value {
        ErrorCategory::Usage => "usage",
        ErrorCategory::Unsupported => "unsupported",
        ErrorCategory::Setup => "setup",
        ErrorCategory::Spawn => "spawn",
        ErrorCategory::Monitor => "monitor",
        ErrorCategory::Wait => "wait",
        ErrorCategory::Termination => "termination",
        ErrorCategory::Cleanup => "cleanup",
        ErrorCategory::Report => "report",
    }
}
fn render_effect_warnings(
    effects: &[OptionEffectReport],
    restart_conditions_explicit: bool,
    swap_explicit: bool,
    presentation: &Presentation,
) {
    let mut out = presentation.stderr();
    for effect in effects {
        if let OptionEffectReport::Ignored {
            option,
            requested,
            reason,
        } = effect
        {
            if option == "restart-on" && !restart_conditions_explicit {
                continue;
            }
            if option == "swap" && !swap_explicit {
                continue;
            }
            presentation::write_warning(&mut out, option, requested, reason)
                .expect("warning output should be writable");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn clean_failure_json_uses_current_schema_and_is_machine_readable() {
        let error = memcordon_core::Error::new(
            memcordon_core::ErrorCategory::Cleanup,
            "MCCLEANUP-TEST",
            "fixture failure",
        );
        let value = super::clean_failure_report(true, &error);
        assert_eq!(
            value["schema_version"],
            memcordon_core::CLEAN_REPORT_SCHEMA_VERSION
        );
        assert_eq!(value["dry_run"], true);
        assert_eq!(value["errors"][0]["code"], "MCCLEANUP-TEST");
    }
}
