use std::io::Write as _;
#[cfg(not(target_os = "macos"))]
use std::path::Path;

use memcordon::exit_mapping::error_exit_code;
use memcordon::invocation::{
    BudgetSet, BudgetToken, CleanArgs, DoctorArgs, ExecutionArgs, PlanArgs, PolicyArgs, Requirement,
};
#[cfg(not(target_os = "macos"))]
use memcordon_core::write_report_atomic;
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
    SwapReport, ToolReport, UnavailableCapabilityReport,
};
#[cfg(not(target_os = "macos"))]
use memcordon_platform::supervise;
use memcordon_platform::{SupervisorRequest, capabilities, cleanup_stale, probe};

use crate::presentation::{self, ExecutionSummary, Presentation, SummaryTone};

#[derive(Clone, Debug)]
struct Resolution {
    backend: BackendCapabilityReport,
    policy: Policy,
    restart: RestartPolicy,
    report: PolicyEnvelopeReport,
}

pub(crate) fn execute(args: ExecutionArgs, presentation: &Presentation) -> i32 {
    #[cfg(not(target_os = "macos"))]
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
    if let Some(contract) = args.policy.private_workload_contract() {
        #[cfg(target_os = "linux")]
        return execute_private_v2(&args, &command, contract, presentation);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = contract;
            return unavailable_private_v2(presentation);
        }
    }
    #[cfg(target_os = "macos")]
    let run_origin = match memcordon_platform::macos_continuous_nanos() {
        Ok(origin) => origin,
        Err(error) => {
            return finish_error(
                &args,
                &command,
                None,
                Error::new(ErrorCategory::Setup, "MCSETUP-CLOCK", error.to_string()),
                presentation,
            );
        }
    };
    let resolution = match resolve(&args.policy, &args.budgets) {
        Ok(value) => value,
        Err(error) => return finish_error(&args, &command, None, *error, presentation),
    };
    #[cfg(target_os = "macos")]
    let context = match memcordon_platform::MacosExecutionContext::owned(run_origin) {
        Ok(context) => context,
        Err(error) => {
            return finish_error(&args, &command, Some(&resolution), error, presentation);
        }
    };
    #[cfg(not(target_os = "macos"))]
    if !args.output.quiet {
        render_effect_warnings(
            &resolution.report.effects,
            args.policy.restart_on.is_some(),
            args.policy.explicit.swap,
            presentation,
        );
    }
    #[cfg(target_os = "macos")]
    let helper_result = bounded_helper_path(
        run_origin,
        &context,
        resolution
            .policy
            .deadline
            .map(|deadline| deadline.duration()),
    );
    #[cfg(not(target_os = "macos"))]
    let helper_result = helper_path();
    let helper = match helper_result {
        Ok(value) => value,
        Err(error) => {
            #[cfg(target_os = "macos")]
            let error = Box::new(finish_context_error(context, *error));
            return finish_error(&args, &command, Some(&resolution), *error, presentation);
        }
    };
    let request = SupervisorRequest {
        policy: resolution.policy.clone(),
        restart: resolution.restart.clone(),
        command: command.clone(),
        memcordon_executable: helper,
        resolved_backend: Some(resolution.backend.clone()),
    };
    #[cfg(target_os = "macos")]
    let result = context.supervise(request);
    #[cfg(not(target_os = "macos"))]
    let result = supervise(request);
    match result {
        Ok(execution) => finish_execution(&args, &command, &resolution, execution, presentation),
        Err(error) => finish_error(&args, &command, Some(&resolution), error, presentation),
    }
}

#[cfg(target_os = "macos")]
fn finish_context_error(
    context: memcordon_platform::MacosExecutionContext,
    mut error: Error,
) -> Error {
    if let Err(restoration) = context.finish() {
        error.message.push_str("; signal restoration also failed: ");
        error.message.push_str(&restoration.to_string());
    }
    error
}

#[cfg(target_os = "macos")]
fn bounded_helper_path(
    origin: u64,
    context: &memcordon_platform::MacosExecutionContext,
    work: Option<std::time::Duration>,
) -> Result<Option<std::path::PathBuf>, Box<Error>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static RESERVED: AtomicBool = AtomicBool::new(false);
    if context.interruption().is_some() {
        return Ok(None);
    }
    // An expired work budget never permits target launch. Its finite retirement
    // reserve still permits resolving the image needed to construct the native
    // not-issued observation; supervision receives the original origin.
    let budget = work.map_or(std::time::Duration::from_secs(5), |work| {
        work.saturating_add(std::time::Duration::from_secs(3))
            .min(std::time::Duration::from_secs(5))
    });
    let expiry = u64::try_from(budget.as_nanos())
        .ok()
        .and_then(|budget| origin.checked_add(budget));
    let error = || {
        Box::new(Error::new(
            ErrorCategory::Setup,
            "MCSETUP-MEMCORDON-EXECUTABLE",
            "helper resolution did not complete within startup budget",
        ))
    };
    let Some(expiry) = expiry else {
        return Err(error());
    };
    if RESERVED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(error());
    }
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .name("helper-resolution".into())
        .spawn(move || {
            let _ = sender.send(helper_path());
            RESERVED.store(false, Ordering::Release);
        })
        .is_err()
    {
        RESERVED.store(false, Ordering::Release);
        return Err(error());
    }
    loop {
        // Cancellation leaves the existing worker responsible for its capture;
        // no replacement worker or target may be launched for this run.
        if context.interruption().is_some() {
            return Ok(None);
        }
        // Check completion first so an immediate deadline still enters native
        // supervision and records a truthful not-issued deadline attempt.
        match receiver.try_recv() {
            Ok(result) => return result,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Err(error()),
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if memcordon_platform::macos_continuous_nanos().map_err(|_| error())? >= expiry {
            return Err(error());
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
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

#[cfg(not(target_os = "macos"))]
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

#[cfg(not(target_os = "macos"))]
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
            runtime: error.runtime.clone(),
            native_startup: error.native_startup.clone(),
            policy_enforcement: error.policy_enforcement.clone(),
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
            provider_failure: error.provider_failure.clone(),
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

#[cfg(target_os = "macos")]
fn finish_execution(
    args: &ExecutionArgs,
    command: &CommandSpec,
    resolution: &Resolution,
    execution: SupervisionExecution,
    _presentation: &Presentation,
) -> i32 {
    let exit_code = execution.wrapper_exit_code();
    let mut diagnostics = Vec::new();
    let return_deadline = execution
        .attempts()
        .records()
        .last()
        .and_then(|attempt| attempt.runtime.as_ref())
        .and_then(|runtime| runtime.delivery_expires);
    deferred_warnings(args, resolution, &mut diagnostics);
    if args.output.summary || matches!(exit_code, 123..=125) {
        presentation::write_summary(&mut diagnostics, execution_summary(&execution))
            .expect("memory summary serialization");
    }
    let report = if args.output.report_path.is_some() {
        match report(
            args,
            command,
            &resolution.report,
            Some(resolution.backend.clone()),
            Some(execution),
            None,
        ) {
            Ok(report) => Some(report),
            Err(error) => {
                presentation::write_runtime_error(
                    &mut diagnostics,
                    format_args!("could not construct execution report: {error}"),
                )
                .expect("memory error serialization");
                super::result_delivery::deliver(diagnostics, None, None, return_deadline);
                return 125;
            }
        }
    } else {
        None
    };
    if super::result_delivery::deliver(
        diagnostics,
        args.output.report_path.as_deref(),
        report,
        return_deadline,
    ) {
        exit_code
    } else {
        125
    }
}

#[cfg(target_os = "macos")]
fn finish_error(
    args: &ExecutionArgs,
    command: &CommandSpec,
    resolution: Option<&Resolution>,
    error: Error,
    _presentation: &Presentation,
) -> i32 {
    let exit_code = error_exit_code(&error);
    let mut diagnostics = Vec::new();
    let return_deadline = error
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.delivery_expires);
    if let Some(resolution) = resolution {
        deferred_warnings(args, resolution, &mut diagnostics);
    }
    presentation::write_runtime_error(&mut diagnostics, &error)
        .expect("memory error serialization");
    let report = if args.output.report_path.is_some() {
        let policy = resolution
            .map(|value| value.report.clone())
            .unwrap_or_else(|| unresolved_report(&args.policy, &args.budgets));
        let error_report = ExecutionErrorReport {
            runtime: error.runtime.clone(),
            native_startup: error.native_startup.clone(),
            policy_enforcement: error.policy_enforcement.clone(),
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
            provider_failure: error.provider_failure.clone(),
        };
        match report(
            args,
            command,
            &policy,
            resolution.map(|value| value.backend.clone()),
            None,
            Some(error_report),
        ) {
            Ok(report) => Some(report),
            Err(report_error) => {
                presentation::write_runtime_error(
                    &mut diagnostics,
                    format_args!("could not construct failure report: {report_error}"),
                )
                .expect("memory error serialization");
                super::result_delivery::deliver(diagnostics, None, None, return_deadline);
                return 125;
            }
        }
    } else {
        None
    };
    if super::result_delivery::deliver(
        diagnostics,
        args.output.report_path.as_deref(),
        report,
        return_deadline,
    ) {
        exit_code
    } else {
        125
    }
}

#[cfg(target_os = "macos")]
fn deferred_warnings(args: &ExecutionArgs, resolution: &Resolution, out: &mut Vec<u8>) {
    if args.output.quiet {
        return;
    }
    for effect in &resolution.report.effects {
        if let OptionEffectReport::Ignored {
            option,
            requested,
            reason,
        } = effect
        {
            if (option == "restart-on" && args.policy.restart_on.is_none())
                || (option == "swap" && !args.policy.explicit.swap)
            {
                continue;
            }
            presentation::write_warning(out, option, requested, reason)
                .expect("memory warning serialization");
        }
    }
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
    let mut policy = policy.clone();
    let enforcement = error
        .as_ref()
        .and_then(|error| error.policy_enforcement.as_ref())
        .or_else(|| {
            supervision
                .as_ref()
                .and_then(|execution| execution.attempts().records().last())
                .map(|attempt| &attempt.policy_enforcement)
        });
    if let Some(resolution) = enforcement
        .and_then(memcordon_core::workload_evidence::AttemptPolicyEnforcementV1::resolution)
    {
        policy.effective.workload = resolution;
    }
    MemcordonReport::schema10(
        tool_report(),
        InvocationReport {
            syntax: "plus-budgets-v1".to_owned(),
            budget_tokens: budget_tokens(&args.budgets),
            memory_token: args.budgets.memory_token().map(str::to_owned),
            deadline_token: deadline_token(&args.budgets).map(str::to_owned),
            argv,
        },
        policy,
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
    if policy.workload_contract().is_some() && policy.boundary() != BoundaryRequirement::Sealed {
        return Err(Box::new(Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-WORKLOAD-BOUNDARY",
            "a strict workload contract requires --boundary sealed",
        )));
    }
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
    let mut report = policy_report(
        policy_args,
        budgets,
        &policy,
        &backend,
        configured,
        effective,
        dormant,
    );
    if let Some(contract) = policy.workload_contract() {
        report.effective.workload = memcordon_platform::workload_plan(contract).unwrap_or_else(|_| {
            memcordon_core::workload_evidence::WorkloadResolutionReportV1::Unavailable {
                request: Some(memcordon_core::workload_evidence::RequestBindingV1::from_contract(contract).expect("policy contains validated contract")),
                reason: memcordon_core::workload_evidence::AdmissionAvailabilityFailure::ProviderUnavailable,
                authorization: memcordon_core::workload_evidence::AuthorizationKnowledge::NotAuthorized,
            }
        });
    }
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
            reason: if backend.name == "macos-watchdog" {
                "the deadline clock starts before initial helper setup".to_owned()
            } else {
                format!(
                    "the {:?} deadline clock starts at the backend authorization boundary",
                    deadline.scope()
                )
            },
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
            workload: memcordon_core::workload_evidence::WorkloadResolutionReportV1::unresolved(
                policy.workload_contract(),
                workload_restriction(backend.name, policy.boundary()),
            ),
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
                clock: deadline_clock(backend.name).to_owned(),
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

fn workload_restriction(
    backend: &str,
    boundary: BoundaryRequirement,
) -> memcordon_core::workload_evidence::BaselineRestrictionObservationV1 {
    use memcordon_core::workload_evidence::BaselineRestrictionObservationV1 as Observation;
    match (boundary, backend) {
        (BoundaryRequirement::Sealed, "linux-sealed-provider") => {
            Observation::LinuxUnixOnlySocketSyscallFilterAlternatePathsUnknown
        }
        (BoundaryRequirement::Sealed, "windows-sealed-provider") => {
            Observation::WindowsNetworkExternallyGoverned
        }
        _ => Observation::UnmanagedStandardBackend,
    }
}

fn requested_report(
    args: &PolicyArgs,
    budgets: &BudgetSet,
    configured: RestartConditions,
) -> RequestedPolicyReport {
    RequestedPolicyReport {
        workload: memcordon_core::workload_evidence::WorkloadRequestReport::from_contract(
            args.baseline_workload_contract(),
        ),
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
            clock: requested_deadline_clock().to_owned(),
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
            workload: memcordon_core::workload_evidence::WorkloadResolutionReportV1::unresolved(
                args.baseline_workload_contract(), memcordon_core::workload_evidence::BaselineRestrictionObservationV1::UnmanagedStandardBackend,
            ),
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
                clock: requested_deadline_clock().to_owned(),
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
    if let Some(contract) = args.policy.private_workload_contract() {
        return plan_private_v2(contract, args.json, presentation);
    }
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
    if let Some(memcordon_core::workload_contract::WorkloadContract::V2(contract)) =
        args.workload_contract.as_ref()
    {
        return doctor_private_v2(contract, args.json, args.probe_execution, presentation);
    }
    let probe = probe();
    use memcordon_core::workload_discovery::DiscoveryReportV1;
    use memcordon_core::workload_evidence::{
        AdmissionAvailabilityFailure, AuthorizationKnowledge, RequestBindingV1,
        WorkloadResolutionReportV1,
    };
    let workload_discovery = if cfg!(any(target_os = "linux", target_os = "windows")) {
        memcordon_platform::workload_discovery()
            .map(|discovery| DiscoveryReportV1::Authenticated {
                discovery: Box::new(discovery),
            })
            .unwrap_or_else(|_| DiscoveryReportV1::Unavailable {
                reason: memcordon_core::BoundedText::new(
                    "authenticated provider discovery unavailable",
                )
                .expect("fixed reason fits"),
            })
    } else {
        DiscoveryReportV1::Unsupported
    };
    let workload = args.workload_contract.as_ref().and_then(|versioned| {
        let memcordon_core::workload_contract::WorkloadContract::V1(contract) = versioned else {
            return None;
        };
        Some(
            memcordon_platform::workload_plan(contract).unwrap_or_else(|_| {
                WorkloadResolutionReportV1::Unavailable {
                    request: Some(
                        RequestBindingV1::from_contract(contract).expect("CLI validated contract"),
                    ),
                    reason: AdmissionAvailabilityFailure::BindingUnavailable,
                    authorization: AuthorizationKnowledge::NotAuthorized,
                }
            }),
        )
    });
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
    let met = workload
        .as_ref()
        .is_none_or(|resolution| matches!(resolution, WorkloadResolutionReportV1::Planned { .. }))
        && args.requirement.is_none_or(|required| {
            selected.as_ref().is_some_and(|backend| match required {
                Requirement::Hard => backend
                    .memory
                    .as_ref()
                    .is_some_and(|memory| memory.class == "hard"),
                Requirement::Watchdog => backend
                    .memory
                    .as_ref()
                    .is_some_and(|memory| memory.class == "watchdog"),
                Requirement::Sealed => {
                    backend.boundary.class == memcordon_core::BoundaryClass::Sealed
                }
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
            workload,
            kind: args.requirement.map(|value| match value {
                Requirement::Hard => "hard".to_owned(),
                Requirement::Watchdog => "watchdog".to_owned(),
                Requirement::Sealed => "sealed".to_owned(),
            }),
            met,
            reason: (!met)
                .then(|| "selected backend does not satisfy the requested enforcement".to_owned()),
        },
        workload_discovery,
    };
    if args.probe_execution {
        return doctor_execution_probe(report, args.json, presentation);
    }
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
        if !met && args.requirement == Some(Requirement::Sealed) {
            for unavailable in &report.unavailable {
                if unavailable.name == "linux-sealed-provider" {
                    writeln!(out, "{}", unavailable.reason)
                        .expect("sealed provider diagnostic should be writable");
                }
            }
        }
    }
    if met { 0 } else { 125 }
}

#[cfg(not(target_os = "linux"))]
fn unavailable_private_v2(presentation: &Presentation) -> i32 {
    let mut out = presentation.stderr();
    presentation::write_runtime_error(
        &mut out,
        "MCWORKLOAD-V2-PLATFORM-UNSUPPORTED: Linux private V2 is unavailable on this platform",
    )
    .expect("private V2 diagnostic should be writable");
    125
}

#[cfg(target_os = "linux")]
fn execute_private_v2(
    args: &ExecutionArgs,
    command: &CommandSpec,
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
    presentation: &Presentation,
) -> i32 {
    use memcordon_core::report_v11::{
        PrivatePublicOutcomeV11, PrivatePublicResultV11, PrivateTerminalOutcomeV11,
    };
    use memcordon_platform::{PrivateLaunchErrorV2, PrivateServiceResultV2};

    let expected_plan = match args.expected_private_plan.as_ref() {
        Some(path) => {
            use std::io::Read;
            let read = || -> Result<_, String> {
                let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
                let limit = memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES;
                if !file
                    .metadata()
                    .map_err(|error| error.to_string())?
                    .is_file()
                {
                    return Err("expected private plan must be a regular file".into());
                }
                let mut bytes = Vec::new();
                file.take(limit as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                if bytes.len() > limit {
                    return Err("expected private plan exceeds byte bound".into());
                }
                memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
                let report: memcordon_core::workload_plan_v2::PrivatePlanReportV10 =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                let memcordon_core::workload_plan_v2::PrivatePlanAvailabilityV2::Available {
                    receipt,
                } = report.availability
                else {
                    return Err("expected private plan is unavailable".into());
                };
                if report.schema_version != 10
                    || report.launch_proof
                    || report.contract_digest != receipt.contract_digest
                    || receipt.schema_version != 3
                {
                    return Err("expected private plan report binding differs".into());
                }
                Ok(receipt)
            };
            match read() {
                Ok(receipt) => Some(receipt),
                Err(error) => {
                    let mut out = presentation.stderr();
                    presentation::write_runtime_error(
                        &mut out,
                        format!("MCUSAGE-EXPECTED-PRIVATE-PLAN: {error}"),
                    )
                    .expect("expected private plan diagnostic should be writable");
                    return 125;
                }
            }
        }
        None => None,
    };

    let frozen_contract = match args.frozen_private_contract.as_ref() {
        Some(path) => {
            use std::io::Read;
            let read = || -> Result<_, String> {
                let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
                let limit = memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES;
                let metadata = file.metadata().map_err(|error| error.to_string())?;
                if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
                    return Err("frozen private contract file bound differs".into());
                }
                let mut bytes = Vec::new();
                file.take(limit as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                if bytes.len() as u64 != metadata.len() {
                    return Err("frozen private contract file changed".into());
                }
                memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
                let memcordon_core::workload_contract::WorkloadContract::V2(frozen) =
                    memcordon_core::workload_contract::WorkloadContract::parse(&bytes)?
                else {
                    return Err("frozen private contract must be V2".into());
                };
                if !memcordon_core::private_release_branch_v1::one_policy_port_changed(
                    contract, &frozen,
                ) {
                    return Err("frozen private contract is not one port change".into());
                }
                Ok(frozen)
            };
            match read() {
                Ok(contract) => Some(contract),
                Err(error) => {
                    let mut out = presentation.stderr();
                    presentation::write_runtime_error(
                        &mut out,
                        format!("MCUSAGE-FROZEN-PRIVATE-CONTRACT: {error}"),
                    )
                    .expect("frozen private contract diagnostic should be writable");
                    return 125;
                }
            }
        }
        None => None,
    };

    let (result, exit_code, diagnostic) = if args.policy.restart || args.policy.restart_on.is_some()
    {
        (
            PrivatePublicOutcomeV11::BeforeSubmissionFailure {
                reason: "automatic V2 restart requires a typed limit cause and authenticated receipt query".into(),
            },
            125,
            Some("MCWORKLOAD-V2-RESTART-UNAVAILABLE: automatic restart was not attempted".to_owned()),
        )
    } else {
        let policy = args.policy.policy(&args.budgets);
        let result = if args.reuse_private_two_attempts {
            memcordon_platform::execute_private_v2_reuse_pair(
                &policy,
                command,
                contract,
                memcordon_platform::AttemptContext::default(),
                expected_plan.as_ref(),
                4,
            )
        } else {
            match frozen_contract.as_ref() {
                Some(tampered) => memcordon_platform::execute_private_v2_frozen_port_rejection(
                    &policy,
                    command,
                    contract,
                    tampered,
                    memcordon_platform::AttemptContext::default(),
                    expected_plan
                        .as_ref()
                        .expect("CLI parser required frozen expected plan"),
                ),
                None => memcordon_platform::execute_private_v2_with_expected_plan(
                    &policy,
                    command,
                    contract,
                    memcordon_platform::AttemptContext::default(),
                    expected_plan.as_ref(),
                ),
            }
        };
        match result {
            Ok(PrivateServiceResultV2::Complete(terminal)) => {
                let exit_code = match &terminal.report().outcome {
                    PrivateTerminalOutcomeV11::Exited { code } if (0..=255).contains(code) => *code,
                    _ => 125,
                };
                let diagnostic = match &terminal.report().outcome {
                    PrivateTerminalOutcomeV11::Exited { code } if (0..=255).contains(code) => None,
                    PrivateTerminalOutcomeV11::Exited { code } => Some(format!(
                        "private V2 target reported invalid exit code {code}"
                    )),
                    _ => Some("private V2 target did not exit ordinarily".to_owned()),
                };
                (
                    PrivatePublicOutcomeV11::Complete {
                        terminal: Box::new(terminal.report().clone()),
                        raw_response: terminal.raw_response().to_vec(),
                    },
                    exit_code,
                    diagnostic,
                )
            }
            Ok(PrivateServiceResultV2::Rejected {
                evidence,
                raw_response,
                release_knowledge: _,
            }) => {
                let diagnostic = format!(
                    "private V2 rejected [{}]: {}",
                    evidence.code, evidence.detail
                );
                let result = if evidence.target_created {
                    PrivatePublicOutcomeV11::AllocatedUnverified {
                        rejection: evidence,
                        raw_response,
                    }
                } else {
                    PrivatePublicOutcomeV11::PreallocationRejected {
                        rejection: evidence,
                        raw_response,
                    }
                };
                (result, 125, Some(diagnostic))
            }
            Ok(PrivateServiceResultV2::Indeterminate {
                attempt_id,
                raw_response,
                reason_code,
            }) => (
                PrivatePublicOutcomeV11::Indeterminate {
                    attempt_id: attempt_id
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    reason_code: reason_code.clone(),
                    raw_response,
                },
                125,
                Some(format!(
                    "private V2 release/retirement indeterminate [{reason_code}]; do not replay"
                )),
            ),
            Err(PrivateLaunchErrorV2::BeforeSubmission(reason)) => (
                PrivatePublicOutcomeV11::BeforeSubmissionFailure {
                    reason: reason.clone(),
                },
                125,
                Some(format!("private V2 not submitted: {reason}")),
            ),
            Err(PrivateLaunchErrorV2::AfterSubmission(failure)) => (
                PrivatePublicOutcomeV11::TransportUnverified {
                    reason: failure.detail.clone(),
                    raw_response: failure.raw_response,
                },
                125,
                Some(format!(
                    "private V2 response unverified: {}; do not replay",
                    failure.detail
                )),
            ),
        }
    };
    let report = PrivatePublicResultV11 {
        schema_version: 11,
        result,
    };
    if let Err(error) = report.validate_structure() {
        let mut out = presentation.stderr();
        presentation::write_runtime_error(
            &mut out,
            format_args!("private V11 report invalid: {error}"),
        )
        .expect("private report diagnostic should be writable");
        return 125;
    }
    if let Some(path) = &args.output.report_path {
        if let Err(error) = write_private_result_atomic(path, &report) {
            let mut out = presentation.stderr();
            presentation::write_runtime_error(
                &mut out,
                format_args!("private V11 report write failed: {error}"),
            )
            .expect("private report write diagnostic should be writable");
            return 125;
        }
    }
    if let Some(diagnostic) = diagnostic {
        let mut out = presentation.stderr();
        presentation::write_runtime_error(&mut out, diagnostic)
            .expect("private V2 diagnostic should be writable");
    } else if args.output.summary {
        let mut out = presentation.stderr();
        presentation::write_runtime_error(&mut out, format_args!("private V2 exit: {exit_code}"))
            .expect("private V2 summary should be writable");
    }
    exit_code
}

#[cfg(target_os = "linux")]
fn write_private_result_atomic(
    path: &Path,
    report: &memcordon_core::report_v11::PrivatePublicResultV11,
) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), report)
        .map_err(|error| error.to_string())?;
    temporary
        .write_all(b"\n")
        .map_err(|error| error.to_string())?;
    temporary.flush().map_err(|error| error.to_string())?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    temporary
        .persist(path)
        .map_err(|error| error.error.to_string())?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn private_plan_availability(
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
) -> memcordon_core::workload_plan_v2::PrivatePlanAvailabilityV2 {
    use memcordon_core::workload_plan_v2::PrivatePlanAvailabilityV2;
    #[cfg(target_os = "linux")]
    {
        match memcordon_platform::private_plan_v2(contract) {
            Ok(receipt) => PrivatePlanAvailabilityV2::Available { receipt },
            Err(reason) => PrivatePlanAvailabilityV2::Unavailable { reason },
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = contract;
        PrivatePlanAvailabilityV2::Unavailable {
            reason: "Linux private V2 is unsupported on this platform".into(),
        }
    }
}

fn plan_private_v2(
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
    json: bool,
    presentation: &Presentation,
) -> i32 {
    let digest = match memcordon_core::workload_codec::contract_digest_v2(contract) {
        Ok(value) => value,
        Err(error) => {
            let mut out = presentation.stderr();
            presentation::write_runtime_error(&mut out, error)
                .expect("V2 plan diagnostic should be writable");
            return 125;
        }
    };
    let report = memcordon_core::workload_plan_v2::PrivatePlanReportV10 {
        schema_version: 10,
        contract_digest: digest,
        availability: private_plan_availability(contract),
        launch_proof: false,
    };
    if let Err(error) = report.validate_for_contract(contract) {
        let mut out = presentation.stderr();
        presentation::write_runtime_error(&mut out, error)
            .expect("V2 plan validation diagnostic should be writable");
        return 125;
    }
    if json {
        return print_json(&report, "private V2 plan", presentation);
    }
    let mut out = presentation.stdout();
    match report.availability {
        memcordon_core::workload_plan_v2::PrivatePlanAvailabilityV2::Available { .. } => {
            writeln!(out, "private V2 plan: available (launch proof: false)")
                .expect("V2 plan output should be writable");
        }
        memcordon_core::workload_plan_v2::PrivatePlanAvailabilityV2::Unavailable { reason } => {
            writeln!(out, "private V2 plan: unavailable ({reason})")
                .expect("V2 plan output should be writable");
        }
    }
    0
}

fn doctor_private_v2(
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
    json: bool,
    probe_execution: bool,
    presentation: &Presentation,
) -> i32 {
    use memcordon_core::workload_plan_v2::{PrivateDoctorReportV7, PrivatePlanAvailabilityV2};
    let digest = match memcordon_core::workload_codec::contract_digest_v2(contract) {
        Ok(value) => value,
        Err(error) => {
            let mut out = presentation.stderr();
            presentation::write_runtime_error(&mut out, error)
                .expect("V2 doctor diagnostic should be writable");
            return 125;
        }
    };
    let availability = if probe_execution {
        PrivatePlanAvailabilityV2::Unavailable {
            reason: "public V2 doctor execution probe is not available".into(),
        }
    } else {
        private_plan_availability(contract)
    };
    let met = matches!(availability, PrivatePlanAvailabilityV2::Available { .. });
    let report = PrivateDoctorReportV7 {
        schema_version: 7,
        contract_digest: digest,
        host_os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        availability,
        execution_probe_performed: false,
    };
    if let Err(error) = report.validate_for_contract(contract) {
        let mut out = presentation.stderr();
        presentation::write_runtime_error(&mut out, error)
            .expect("V2 doctor validation diagnostic should be writable");
        return 125;
    }
    if json {
        let code = print_json(&report, "private V2 doctor", presentation);
        if code != 0 {
            return code;
        }
    } else {
        let mut out = presentation.stdout();
        writeln!(
            out,
            "private V2 doctor: {}",
            if met { "available" } else { "unavailable" }
        )
        .expect("V2 doctor output should be writable");
    }
    if met { 0 } else { 125 }
}

#[derive(serde::Serialize)]
struct ExecutionProbe {
    supported: bool,
    helper_ready: bool,
    target_exec_confirmed: bool,
    target_exit: Option<i32>,
    cleanup_complete: bool,
    failure: Option<String>,
}

fn doctor_execution_probe(doctor: DoctorReport, json: bool, presentation: &Presentation) -> i32 {
    #[cfg(target_os = "macos")]
    let execution = (|| -> Result<memcordon_platform::Execution, Box<Error>> {
        if !doctor.requirement.met || doctor.requirement.kind.as_deref() == Some("sealed") {
            return Err(Box::new(Error::new(
                ErrorCategory::Unsupported,
                "MCSETUP-PROBE-REQUIREMENT",
                "execution probe requires an available standard backend",
            )));
        }
        let origin = memcordon_platform::macos_continuous_nanos().map_err(|error| {
            Box::new(Error::new(
                ErrorCategory::Setup,
                "MCSETUP-CLOCK",
                error.to_string(),
            ))
        })?;
        let context = memcordon_platform::MacosExecutionContext::owned(origin).map_err(Box::new)?;
        let helper =
            match bounded_helper_path(origin, &context, Some(std::time::Duration::from_secs(5))) {
                Ok(Some(helper)) => helper,
                Ok(None) => {
                    context.finish().map_err(Box::new)?;
                    return Err(Box::new(Error::new(
                        ErrorCategory::Setup,
                        "MCSETUP-PROBE-INTERRUPTED",
                        "execution probe interrupted before helper resolution",
                    )));
                }
                Err(error) => {
                    return Err(Box::new(finish_context_error(context, *error)));
                }
            };
        let policy = Policy::unbounded()
            .with_deadline(std::time::Duration::from_secs(5))
            .expect("nonzero probe deadline");
        let command = CommandSpec::new(helper.as_os_str()).args(["__execution-probe"]);
        context.run(policy, &command, &helper).map_err(Box::new)
    })();
    #[cfg(not(target_os = "macos"))]
    let execution: Result<memcordon_platform::Execution, Box<Error>> = Err(Box::new(Error::new(
        ErrorCategory::Unsupported,
        "MCSETUP-PROBE-UNSUPPORTED",
        "the acknowledged helper execution probe is available on macOS",
    )));
    let execution = match execution {
        Ok(execution) => {
            let cleanup = execution.outcome.cleanup();
            let exit = match &execution.outcome {
                memcordon_core::RunOutcome::Exited {
                    child: memcordon_core::ChildTermination::ExitCode { code },
                    ..
                } => Some(*code),
                _ => None,
            };
            let cleanup_complete = cleanup.direct_child_reaped
                && cleanup.workload_empty == Some(true)
                && execution.restart_safety.helpers_reaped
                && cleanup.errors.is_empty();
            let target_exec_confirmed = execution.launch.target_released && exit.is_some();
            let helper_ready = execution.launch.guardian_started_before_authorization;
            ExecutionProbe {
                supported: true,
                helper_ready,
                target_exec_confirmed,
                target_exit: exit,
                cleanup_complete,
                failure: (!(helper_ready
                    && target_exec_confirmed
                    && exit == Some(0)
                    && cleanup_complete))
                    .then(|| format!("{:?}", execution.outcome)),
            }
        }
        Err(error) => ExecutionProbe {
            supported: cfg!(target_os = "macos"),
            helper_ready: error.guardian_ready_before_release,
            target_exec_confirmed: false,
            target_exit: None,
            cleanup_complete: false,
            failure: Some(error.to_string()),
        },
    };
    let passed = doctor.requirement.met
        && execution.helper_ready
        && execution.target_exec_confirmed
        && execution.target_exit == Some(0)
        && execution.cleanup_complete;
    if json {
        #[derive(serde::Serialize)]
        struct ProbeReport {
            kind: &'static str,
            schema_version: u32,
            doctor: DoctorReport,
            execution: ExecutionProbe,
        }
        let report = ProbeReport {
            kind: "doctor-execution-probe",
            schema_version: 1,
            doctor,
            execution,
        };
        if print_json(&report, "doctor execution probe", presentation) != 0 {
            return 125;
        }
    } else {
        let mut out = presentation.stdout();
        writeln!(out, "execution probe: helper-ready={} target-exec-confirmed={} target-exit={:?} cleanup-complete={}", execution.helper_ready, execution.target_exec_confirmed, execution.target_exit, execution.cleanup_complete).expect("probe output should be writable");
        if let Some(failure) = execution.failure {
            writeln!(out, "{failure}").expect("probe diagnostic should be writable");
        }
    }
    if passed { 0 } else { 125 }
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
        "macos-watchdog" => "before-helper-setup",
        _ => "platform-authorization",
    }
}
fn deadline_clock(backend: &str) -> &'static str {
    if backend == "macos-watchdog" {
        "darwin-continuous-nanoseconds-v1"
    } else {
        "rust-instant"
    }
}
fn requested_deadline_clock() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin-continuous-nanoseconds-v1"
    } else {
        "rust-instant"
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
#[cfg(not(target_os = "macos"))]
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
#[path = "../../tests/application/clean.rs"]
mod tests;
