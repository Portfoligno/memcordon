use std::ffi::OsString;

use memcordon_core::{
    BackendReport, ByteSize, CommandReport, CommandSpec, Enforcement, Lifetime, MemcordonReport,
    Metric, Policy, PolicyReport, ReportMode, ResultReport, RunOutcome, ToolReport,
    write_report_atomic,
};
use memcordon_platform::{Execution, probe, run};

use crate::args::{
    CompatArgs, EnforcementArg, ExplainArgs, LifetimeArg, MetricArg, ReportArg, RunArgs,
};
use crate::exit_mapping::outcome_exit_code;

pub fn run_command(args: RunArgs) -> i32 {
    if args.report == ReportArg::Json && args.report_file.is_none() {
        eprintln!("memcordon: --report json requires --report-file");
        return 2;
    }
    let (program, command_args) = match args.command.split_first() {
        Some(parts) => parts,
        None => {
            eprintln!("memcordon: no command supplied");
            return 2;
        }
    };
    let command = CommandSpec::new(program.clone()).args(command_args.iter().cloned());
    let mut policy = Policy::new(args.memory);
    policy.enforcement = args.enforcement.into();
    policy.lifetime = args.lifetime.into();
    policy.metric = args.metric.into();
    policy.poll_interval = args.poll_interval;
    policy.signal_grace = args.signal_grace;
    policy.limit_grace = args.limit_grace;
    policy.swap = args.swap.0;
    policy.report = args.report.into();
    policy.quiet = args.quiet;
    policy.backend_warning = !args.no_backend_warning;

    if policy.enforcement == Enforcement::Auto
        && cfg!(target_os = "macos")
        && policy.backend_warning
        && !policy.quiet
    {
        eprintln!(
            "memcordon: warning: auto selected sampled macOS watchdog enforcement; use `probe` for limitations"
        );
    }

    match run(policy.clone(), &command) {
        Ok(execution) => finish_run(&policy, &command, &args, &execution),
        Err(error) => {
            eprintln!("memcordon: {error}");
            crate::exit_mapping::error_exit_code(&error)
        }
    }
}

fn finish_run(
    policy: &Policy,
    command: &CommandSpec,
    args: &RunArgs,
    execution: &Execution,
) -> i32 {
    let exit_code = outcome_exit_code(&execution.outcome);
    if matches!(
        execution.outcome,
        RunOutcome::LimitExceeded { .. } | RunOutcome::MonitorFailed { .. }
    ) {
        eprintln!("{}", outcome_line(execution, exit_code));
    }
    if args.report == ReportArg::Text && !policy.quiet {
        eprintln!("{}", outcome_line(execution, exit_code));
    }
    if args.report == ReportArg::Json {
        let report = build_report(policy, command, execution, exit_code);
        if let Some(path) = &args.report_file {
            if let Err(error) = write_report_atomic(path, &report) {
                eprintln!("memcordon: {error}");
                return 125;
            }
        }
    }
    exit_code
}

fn outcome_line(execution: &Execution, exit_code: i32) -> String {
    let outcome = match execution.outcome {
        RunOutcome::Exited { .. } => "child exited",
        RunOutcome::LimitExceeded { .. } => "memory limit exceeded",
        RunOutcome::Interrupted { .. } => "interrupted",
        RunOutcome::MonitorFailed { .. } => "monitor failed; workload terminated",
    };
    format!(
        "memcordon: {outcome}; backend={} metric={} exit={exit_code}",
        execution.backend.name, execution.backend.metric
    )
}

fn build_report(
    policy: &Policy,
    command: &CommandSpec,
    execution: &Execution,
    exit_code: i32,
) -> MemcordonReport {
    let (outcome_name, child, evidence, peak) = match &execution.outcome {
        RunOutcome::Exited { child, peak, .. } => (
            "child-exited",
            Some(child.clone()),
            None,
            peak.map(ByteSize::bytes),
        ),
        RunOutcome::LimitExceeded {
            child_after_termination,
            evidence,
            peak,
            ..
        } => (
            "limit-exceeded",
            child_after_termination.clone(),
            Some(evidence.clone()),
            peak.map(ByteSize::bytes),
        ),
        RunOutcome::Interrupted {
            child_after_termination,
            ..
        } => ("interrupted", child_after_termination.clone(), None, None),
        RunOutcome::MonitorFailed {
            child_after_termination,
            ..
        } => (
            "monitor-failed",
            child_after_termination.clone(),
            None,
            None,
        ),
    };
    MemcordonReport {
        schema_version: 1,
        tool: ToolReport {
            name: "memcordon".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        command: CommandReport {
            program: command.program().to_string_lossy().into_owned(),
            args: command
                .arguments()
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect(),
            pid: Some(execution.child_pid),
        },
        policy: PolicyReport {
            requested_enforcement: format!("{:?}", policy.enforcement).to_lowercase(),
            effective_enforcement: execution.backend.class.to_owned(),
            memory_limit_bytes: policy.memory.bytes(),
            swap_limit_bytes: match policy.swap {
                memcordon_core::SwapPolicy::Bytes(bytes) => Some(bytes.bytes()),
                memcordon_core::SwapPolicy::Unlimited | memcordon_core::SwapPolicy::Host => None,
            },
            swap_policy: match policy.swap {
                memcordon_core::SwapPolicy::Bytes(_) => "bytes",
                memcordon_core::SwapPolicy::Unlimited => "unlimited",
                memcordon_core::SwapPolicy::Host => "host",
            }
            .to_owned(),
            lifetime: format!("{:?}", policy.lifetime).to_lowercase(),
            poll_interval_ms: policy.poll_interval.as_millis().min(u128::from(u64::MAX)) as u64,
        },
        backend: BackendReport {
            name: execution.backend.name.to_owned(),
            class: execution.backend.class.to_owned(),
            metric: execution.backend.metric.to_owned(),
            hard_limit: execution.backend.hard_limit,
            limitations: execution
                .backend
                .limitations
                .iter()
                .map(|item| (*item).to_owned())
                .collect(),
        },
        result: ResultReport {
            outcome: outcome_name.to_owned(),
            wrapper_exit_code: exit_code,
            child,
            limit_evidence: evidence,
            peak_bytes: peak,
            duration_ms: execution.duration.as_millis().min(u128::from(u64::MAX)) as u64,
        },
        cleanup: execution.outcome.cleanup().clone(),
    }
}

pub fn probe_command(json: bool) -> i32 {
    let report = probe();
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("memcordon: could not serialize probe result: {error}");
                return 125;
            }
        }
    } else if let Some(selected) = report.selected {
        println!("selected backend: {}", selected.name);
        println!("class: {}", selected.class);
        println!("metric: {}", selected.metric);
        println!(
            "whole-workload hard limit: {}",
            if selected.hard_limit {
                "available"
            } else {
                "unavailable"
            }
        );
        println!("startup containment: {}", selected.startup_containment);
        for limitation in selected.limitations {
            println!("known limitation: {limitation}");
        }
    } else {
        println!("selected backend: none");
        for unavailable in report.unavailable {
            println!("unavailable {}: {}", unavailable.name, unavailable.reason);
        }
    }
    0
}

pub fn explain_command(args: ExplainArgs) -> i32 {
    let report = probe();
    let enforcement: Enforcement = args.enforcement.into();
    if enforcement == Enforcement::Hard
        && report.available.iter().all(|backend| !backend.hard_limit)
    {
        eprintln!("memcordon: hard enforcement unavailable on this platform");
        return 125;
    }
    println!("requested enforcement: {enforcement:?}");
    if let Some(memory) = args.memory {
        println!("memory limit: {} bytes", memory.bytes());
    }
    if let Some(selected) = report.selected {
        println!("effective backend: {}", selected.name);
        println!("metric: {}", selected.metric);
        println!("class: {}", selected.class);
    }
    0
}

pub fn cleanup_command(dry_run: bool) -> i32 {
    match memcordon_platform::cleanup_stale(dry_run) {
        Ok(paths) if paths.is_empty() => {
            println!(
                "memcordon: no persistent backend state to clean{}",
                if dry_run { " (dry run)" } else { "" }
            );
            0
        }
        Ok(paths) => {
            for path in paths {
                println!(
                    "{} {path}",
                    if dry_run { "would remove" } else { "removed" }
                );
            }
            0
        }
        Err(error) => {
            eprintln!("memcordon: {error}");
            125
        }
    }
}

pub fn version_command(verbose: bool) -> i32 {
    println!("memcordon {}", env!("CARGO_PKG_VERSION"));
    if verbose {
        println!("target: {}", std::env::consts::OS);
        println!("report schema: 1");
        let backend = probe().selected.map_or("none", |backend| backend.name);
        println!("selected backend: {backend}");
    }
    0
}

pub fn compat_command(args: CompatArgs) -> i32 {
    if args.children {
        eprintln!(
            "memcordon: warning: --children is deprecated; workload scope is already the default"
        );
    }
    if args.virtual_memory {
        eprintln!(
            "memcordon: warning: --virtual selects a watchdog-only virtual metric, which is not physical memory"
        );
    }
    run_command(RunArgs {
        memory: args.amount,
        enforcement: EnforcementArg::Watchdog,
        lifetime: LifetimeArg::Command,
        metric: if args.virtual_memory {
            MetricArg::Virtual
        } else {
            MetricArg::Native
        },
        poll_interval: std::time::Duration::from_millis(50),
        signal_grace: std::time::Duration::from_secs(2),
        limit_grace: std::time::Duration::ZERO,
        swap: crate::args::SwapArg(memcordon_core::SwapPolicy::Bytes(ByteSize::from_bytes(0))),
        report: ReportArg::None,
        report_file: None,
        quiet: false,
        no_backend_warning: false,
        command: args.command,
    })
}

#[cfg(unix)]
pub fn launcher(control_fd: i32, command: Vec<OsString>) -> i32 {
    use std::os::unix::process::CommandExt;

    let (program, args) = match command.split_first() {
        Some(parts) => parts,
        None => return 126,
    };
    let mut release = 0_u8;
    // SAFETY: `release` is writable for one byte and `control_fd` is supplied by the trusted
    // parent launcher protocol. A failed/closed gate never executes the target.
    let read = unsafe { libc::read(control_fd, (&raw mut release).cast(), 1) };
    // SAFETY: the internal descriptor is no longer needed regardless of read result.
    unsafe {
        libc::close(control_fd);
    }
    if read != 1 || release != 1 {
        eprintln!("memcordon: launcher gate closed before release");
        return 126;
    }
    let error = std::process::Command::new(program).args(args).exec();
    eprintln!("memcordon: target exec failed: {error}");
    if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    }
}

#[cfg(unix)]
pub fn guardian(control_fd: i32, process_group: i32) -> i32 {
    let mut marker = 0_u8;
    // SAFETY: `marker` is writable for one byte and this hidden command receives the descriptor
    // only from its trusted parent.
    let read = unsafe { libc::read(control_fd, (&raw mut marker).cast(), 1) };
    // SAFETY: the descriptor is no longer needed after the protocol read.
    unsafe {
        libc::close(control_fd);
    }
    if read == 1 && marker == 1 {
        return 0;
    }
    // Unexpected EOF means the wrapper disappeared. The guardian is outside the workload group.
    // SAFETY: a negative PID addresses exactly the child-owned process group.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    0
}

#[cfg(not(unix))]
pub fn launcher(_control_fd: i32, _command: Vec<OsString>) -> i32 {
    eprintln!("memcordon: Unix launcher protocol is unavailable on this target");
    126
}

#[cfg(not(unix))]
pub fn guardian(_control_fd: i32, _process_group: i32) -> i32 {
    126
}

impl From<EnforcementArg> for Enforcement {
    fn from(value: EnforcementArg) -> Self {
        match value {
            EnforcementArg::Auto => Self::Auto,
            EnforcementArg::Hard => Self::Hard,
            EnforcementArg::Watchdog => Self::Watchdog,
        }
    }
}

impl From<LifetimeArg> for Lifetime {
    fn from(value: LifetimeArg) -> Self {
        match value {
            LifetimeArg::Command => Self::Command,
            LifetimeArg::Workload => Self::Workload,
        }
    }
}

impl From<MetricArg> for Metric {
    fn from(value: MetricArg) -> Self {
        match value {
            MetricArg::Native => Self::Native,
            MetricArg::PhysicalFootprint => Self::PhysicalFootprint,
            MetricArg::Rss => Self::Rss,
            MetricArg::Virtual => Self::Virtual,
        }
    }
}

impl From<ReportArg> for ReportMode {
    fn from(value: ReportArg) -> Self {
        match value {
            ReportArg::None => Self::None,
            ReportArg::Text => Self::Text,
            ReportArg::Json => Self::Json,
        }
    }
}
