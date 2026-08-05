use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use memcordon_core::{
    BackoffMultiplier, ByteSize, CircuitBreakerPolicy, DeadlinePolicy, DeadlineScope, Enforcement,
    Lifetime, LogisticBackoffPolicy, Metric, Policy, RestartConditions, RestartLimit, SwapPolicy,
};
use std::num::NonZeroU64;

use crate::parse_duration;

pub const REFERENCE_URL: &str =
    "https://github.com/Portfoligno/memcordon/blob/main/docs/reference.md";

pub const ROOT_USAGE: &str = "Run a command and its descendants with optional memory and elapsed-time limits.\n\nUsage:\n  memcordon [OPTIONS] [BUDGET]... [--] COMMAND [ARGUMENT]...\n  memcordon doctor [OPTIONS]\n  memcordon plan [OPTIONS] [BUDGET]...\n  memcordon clean [OPTIONS]\n\nExamples:\n  memcordon cargo check\n  memcordon +1GiB -- cargo check\n  memcordon +10m +1GiB -- cargo test --workspace\n\nIf no limit or wrapper failure occurs, MemCordon returns the command's exit status.\n\nBudgets:\n  +MEMORY    Workload memory ceiling; accepts bytes, KB..EB, or KiB..EiB\n  +TIME      Elapsed-time deadline; accepts decimal ms, s, or m\n\nPolicy options (value; default):\n  --enforcement auto|hard|watchdog       Backend requirement; auto\n  --wait-for command|workload            Return after the command or workload; command\n  --metric native|physical-footprint|rss|virtual\n                                         Memory metric; native\n  --poll-interval DURATION               Watchdog sampling interval, at least 10ms; 50ms\n  --signal-grace DURATION                Grace after external interruption; 2s\n  --limit-grace DURATION                 Grace after a configured limit; 0s\n  --swap SIZE|unlimited|host             Swap policy; 0B\n  --deadline-scope attempt|supervision   Deadline scope; attempt\n  --restart                              Restart on applicable configured limits; off\n  --restart-on both|memory-limit|deadline\n                                         Enable restart for selected conditions; unset\n  --restart-limit COUNT|unlimited        Additional launches; unlimited\n  --backoff-initial DURATION             Logistic backoff initial delay; 1s\n  --backoff-multiplier DECIMAL           Logistic multiplier, >1 and <=100; 2\n  --backoff-max DURATION                 Logistic backoff upper bound; 30s\n  --restart-burst COUNT                  Circuit-breaker burst count; unset\n  --restart-window DURATION              Circuit-breaker window; unset\n  --cooldown DURATION                    Circuit-breaker cooldown; unset\n\nOutput options:\n  --report PATH                          Write a schema-3 JSON report to PATH; unset\n  --summary                              Write one final summary line to stderr; off\n  --quiet                                Suppress optional wrapper output; off\n  -h, --help                             Print this help\n  -V, --version                          Print the version\n\nConstraints:\n  Options precede the optional contiguous, order-independent budget block.\n  At most one memory and one time budget are accepted. After the program, native\n  arguments are passed unchanged. Use -- before programs beginning with + or -.\n  Memory policy options require +MEMORY; deadline scope requires +TIME. Restart\n  tuning requires restart to be enabled. --restart-burst, --restart-window, and\n  --cooldown must be supplied together. --summary conflicts with --quiet.\n  A report path must have an existing parent; reports never use stdout.\n\nExit status:\n  Deadlines return 123, confirmed memory limits 124, wrapper failures 125, a\n  non-executable command 126, and a missing command 127.\n\nReference:\n  https://github.com/Portfoligno/memcordon/blob/main/docs/reference.md";

pub const DOCTOR_USAGE: &str = "Inspect backend availability without launching a workload.\n\nUsage:\n  memcordon doctor [--json] [--require hard|watchdog]\n\nThe default text report identifies the selected, available, and unavailable\nbackends and their capabilities, policies, and limitations.\n\nOptions (default):\n  --json                         Write the schema-2 report to stdout; off\n  --require hard|watchdog        Return 125 unless the backend satisfies it; unset\n  -h, --help                     Print this help\n\nReference:\n  https://github.com/Portfoligno/memcordon/blob/main/docs/reference.md";

pub const PLAN_USAGE: &str = "Resolve budgets and policy without launching a target.\n\nUsage:\n  memcordon plan [POLICY OPTIONS] [--json] [BUDGET]...\n\nExample:\n  memcordon plan +8GiB +10m\n\nThe default text report distinguishes requested, effective, dormant, ignored,\nand adjusted policy. No workload is launched.\n\nBudgets:\n  +MEMORY    Workload memory ceiling; accepts bytes, KB..EB, or KiB..EiB\n  +TIME      Elapsed-time deadline; accepts decimal ms, s, or m\n\nPolicy options (value; default):\n  --enforcement auto|hard|watchdog       Backend requirement; auto\n  --wait-for command|workload            Return after the command or workload; command\n  --metric native|physical-footprint|rss|virtual\n                                         Memory metric; native\n  --poll-interval DURATION               Sampling interval, at least 10ms; 50ms\n  --signal-grace DURATION                External-interruption grace; 2s\n  --limit-grace DURATION                 Configured-limit grace; 0s\n  --swap SIZE|unlimited|host             Swap policy; 0B\n  --deadline-scope attempt|supervision   Deadline scope; attempt\n  --restart                              Enable applicable limit restarts; off\n  --restart-on both|memory-limit|deadline\n                                         Enable selected restarts; unset\n  --restart-limit COUNT|unlimited        Additional launches; unlimited\n  --backoff-initial DURATION             Logistic backoff initial delay; 1s\n  --backoff-multiplier DECIMAL           Logistic multiplier, >1 and <=100; 2\n  --backoff-max DURATION                 Logistic backoff upper bound; 30s\n  --restart-burst COUNT                  Circuit-breaker burst count; unset\n  --restart-window DURATION              Circuit-breaker window; unset\n  --cooldown DURATION                    Circuit-breaker cooldown; unset\n  --json                                 Write the schema-2 report to stdout; off\n  -h, --help                             Print this help\n\nConstraints:\n  Options precede the optional budget block. At most one memory and one time budget\n  are accepted. A command and -- delimiter are not accepted. Memory policy options\n  require +MEMORY; deadline scope requires +TIME. Restart tuning requires restart\n  to be enabled. The three circuit-breaker options must be supplied together.\n\nReference:\n  https://github.com/Portfoligno/memcordon/blob/main/docs/reference.md";

pub const CLEAN_USAGE: &str = "Inspect or remove stale MemCordon-owned backend artifacts.\n\nUsage:\n  memcordon clean [--dry-run] [--json]\n\nExample:\n  memcordon clean --dry-run\n\nWithout --dry-run, this removes the reported stale artifacts. Incomplete cleanup\nreturns 125.\n\nOptions (default):\n  --dry-run                      Report candidates without changing the host; off\n  --json                         Write the schema-1 result to stdout; off\n  -h, --help                     Print this help\n\nReference:\n  https://github.com/Portfoligno/memcordon/blob/main/docs/reference.md";

pub const PUBLIC_POLICY_OPTIONS: &[&str] = &[
    "--enforcement",
    "--wait-for",
    "--metric",
    "--poll-interval",
    "--signal-grace",
    "--limit-grace",
    "--swap",
    "--deadline-scope",
    "--restart",
    "--restart-on",
    "--restart-limit",
    "--backoff-initial",
    "--backoff-multiplier",
    "--backoff-max",
    "--restart-burst",
    "--restart-window",
    "--cooldown",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimitToken {
    pub raw: OsString,
    pub bytes: ByteSize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BudgetToken {
    Memory { raw: OsString, bytes: ByteSize },
    Time { raw: OsString, duration: Duration },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BudgetSet {
    pub source_order: Vec<BudgetToken>,
    pub memory: Option<ByteSize>,
    pub deadline: Option<Duration>,
}

impl BudgetSet {
    pub fn memory_token(&self) -> Option<&str> {
        self.source_order.iter().find_map(|token| match token {
            BudgetToken::Memory { raw, .. } => raw.to_str(),
            BudgetToken::Time { .. } => None,
        })
    }
    fn push(&mut self, token: BudgetToken) -> Result<(), CliError> {
        if self.source_order.len() == 2 {
            return Err(CliError::new(
                "MCCLI-BUDGET-COUNT",
                "at most two budget candidates are accepted",
            ));
        }
        match &token {
            BudgetToken::Memory { .. } if self.memory.is_some() => {
                return Err(CliError::new(
                    "MCCLI-BUDGET-DUPLICATE-MEMORY",
                    "only one memory budget is accepted",
                ));
            }
            BudgetToken::Time { .. } if self.deadline.is_some() => {
                return Err(CliError::new(
                    "MCCLI-BUDGET-DUPLICATE-TIME",
                    "only one time budget is accepted",
                ));
            }
            BudgetToken::Memory { bytes, .. } => self.memory = Some(*bytes),
            BudgetToken::Time { duration, .. } => self.deadline = Some(*duration),
        }
        self.source_order.push(token);
        Ok(())
    }
}

pub fn parse_budget(raw: OsString) -> Result<BudgetToken, CliError> {
    let text = raw.to_str().filter(|text| text.is_ascii()).ok_or_else(|| {
        CliError::new(
            "MCCLI-BUDGET-ENCODING",
            "budget tokens must contain strict ASCII text",
        )
    })?;
    let value = text
        .strip_prefix('+')
        .ok_or_else(|| CliError::new("MCCLI-BUDGET", "budget tokens use one leading '+'"))?;
    if value.is_empty() || value.starts_with('+') {
        return Err(CliError::new(
            "MCCLI-BUDGET",
            "budget tokens use exactly one leading '+'",
        ));
    }
    let memory = value.parse::<ByteSize>();
    let time = parse_duration(value);
    match (memory, time) {
        (Ok(bytes), Err(_)) => Ok(BudgetToken::Memory { raw, bytes }),
        (Err(_), Ok(duration)) if !duration.is_zero() => Ok(BudgetToken::Time { raw, duration }),
        (Err(memory), Ok(_)) => Err(CliError::new(
            "MCCLI-BUDGET",
            format!("invalid memory budget ({memory}); time budget must be greater than zero"),
        )),
        (Ok(_), Ok(_)) => Err(CliError::new(
            "MCCLI-BUDGET-AMBIGUOUS",
            "budget matches both memory and time grammars",
        )),
        (Err(memory), Err(time)) => Err(CliError::new(
            "MCCLI-BUDGET",
            format!(
                "invalid memory budget ({memory}); invalid time budget ({})",
                time
            ),
        )),
    }
}

impl LimitToken {
    pub fn parse(raw: OsString) -> Result<Self, CliError> {
        let text = raw.to_str().ok_or_else(|| {
            CliError::new(
                "MCCLI-LIMIT-ENCODING",
                "+MEMORY must contain strict ASCII text",
            )
        })?;
        if !text.is_ascii() {
            return Err(CliError::new(
                "MCCLI-LIMIT-ENCODING",
                "+MEMORY must contain strict ASCII text",
            ));
        }
        let value = text.strip_prefix('+').ok_or_else(|| {
            CliError::new(
                "MCCLI-MISSING-LIMIT-MARKER",
                "memory limits use a leading '+'\nusage: memcordon [OPTIONS] +MEMORY [--] COMMAND [ARGUMENT...]\nexample: memcordon +8GiB cargo test --workspace",
            )
        })?;
        if value.starts_with('+') {
            return Err(CliError::new(
                "MCCLI-LIMIT",
                "+MEMORY must contain exactly one leading '+'",
            ));
        }
        let bytes = value
            .parse::<ByteSize>()
            .map_err(|error| CliError::new("MCCLI-LIMIT", error.to_string()))?;
        Ok(Self { raw, bytes })
    }

    pub fn display(&self) -> &str {
        self.raw
            .to_str()
            .expect("validated limit tokens are strict ASCII")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyArgs {
    pub enforcement: Enforcement,
    pub wait_for: Lifetime,
    pub metric: Metric,
    pub poll_interval: Duration,
    pub signal_grace: Duration,
    pub limit_grace: Duration,
    pub swap: SwapPolicy,
    pub deadline_scope: DeadlineScope,
    pub restart: bool,
    pub restart_on: Option<RestartConditions>,
    pub restart_limit: RestartLimit,
    pub backoff: LogisticBackoffPolicy,
    pub circuit_breaker: Option<CircuitBreakerPolicy>,
    backoff_initial: Option<Duration>,
    backoff_multiplier: Option<BackoffMultiplier>,
    backoff_maximum: Option<Duration>,
    restart_burst: Option<NonZeroU64>,
    restart_window: Option<Duration>,
    cooldown: Option<Duration>,
    pub explicit: ExplicitPolicyOptions,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExplicitPolicyOptions {
    pub enforcement: bool,
    pub metric: bool,
    pub poll_interval: bool,
    pub swap: bool,
    pub deadline_scope: bool,
    pub limit_grace: bool,
    pub restart_tuning: bool,
}

impl Default for PolicyArgs {
    fn default() -> Self {
        Self {
            enforcement: Enforcement::Auto,
            wait_for: Lifetime::Command,
            metric: Metric::Native,
            poll_interval: Duration::from_millis(50),
            signal_grace: Duration::from_secs(2),
            limit_grace: Duration::ZERO,
            swap: SwapPolicy::Bytes(ByteSize::from_bytes(0)),
            deadline_scope: DeadlineScope::Attempt,
            restart: false,
            restart_on: None,
            restart_limit: RestartLimit::Unlimited,
            backoff: LogisticBackoffPolicy::default(),
            circuit_breaker: None,
            backoff_initial: None,
            backoff_multiplier: None,
            backoff_maximum: None,
            restart_burst: None,
            restart_window: None,
            cooldown: None,
            explicit: ExplicitPolicyOptions::default(),
        }
    }
}

impl PolicyArgs {
    pub fn policy(&self, budgets: &BudgetSet) -> Policy {
        let mut policy = Policy::unbounded();
        policy.memory = budgets.memory;
        policy.deadline = budgets.deadline.map(|duration| {
            DeadlinePolicy::new(duration, self.deadline_scope)
                .unwrap_or_else(|error| panic!("validated CLI deadline became invalid: {error}"))
        });
        policy.enforcement = self.enforcement;
        policy.lifetime = self.wait_for;
        policy.metric = self.metric;
        policy.poll_interval = self.poll_interval;
        policy.signal_grace = self.signal_grace;
        policy.limit_grace = self.limit_grace;
        policy.swap = self.swap;
        policy
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputRequest {
    pub report_path: Option<PathBuf>,
    pub summary: bool,
    pub quiet: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionArgs {
    pub budgets: BudgetSet,
    pub policy: PolicyArgs,
    pub command: Vec<OsString>,
    pub output: OutputRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Requirement {
    Hard,
    Watchdog,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorArgs {
    pub json: bool,
    pub requirement: Option<Requirement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanArgs {
    pub json: bool,
    pub budgets: BudgetSet,
    pub policy: PolicyArgs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanArgs {
    pub dry_run: bool,
    pub json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelpKind {
    Root,
    Doctor,
    Plan,
    Clean,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Invocation {
    Execute(ExecutionArgs),
    Doctor(DoctorArgs),
    Plan(PlanArgs),
    Clean(CleanArgs),
    Help(HelpKind),
    Version,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliError {
    pub code: &'static str,
    pub message: String,
}

impl CliError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn route(argv: &[OsString]) -> Result<Invocation, CliError> {
    let first = argv.first().ok_or_else(|| {
        CliError::new(
            "MCCLI-MISSING-LIMIT",
            format!("no invocation supplied\n{ROOT_USAGE}"),
        )
    })?;
    if first == "-h" || first == "--help" {
        return exact_root_flag(argv, Invocation::Help(HelpKind::Root));
    }
    if first == "-V" || first == "--version" {
        return exact_root_flag(argv, Invocation::Version);
    }
    if first == "doctor" {
        return parse_doctor(&argv[1..]);
    }
    if first == "plan" {
        return parse_plan(&argv[1..]);
    }
    if first == "clean" {
        return parse_clean(&argv[1..]);
    }
    if let Some((code, replacement)) = legacy(first) {
        return Err(CliError::new(
            code,
            format!(
                "`memcordon {}` was removed in 0.2\nuse: {replacement}",
                first.to_string_lossy()
            ),
        ));
    }
    parse_execution(argv).map(Invocation::Execute)
}

fn exact_root_flag(argv: &[OsString], invocation: Invocation) -> Result<Invocation, CliError> {
    if argv.len() == 1 {
        Ok(invocation)
    } else {
        Err(CliError::new(
            "MCCLI-ROOT-FLAG-TRAILING",
            "root --help and --version do not accept trailing arguments",
        ))
    }
}

fn legacy(first: &OsStr) -> Option<(&'static str, &'static str)> {
    if first == "run" {
        Some((
            "MCCLI-LEGACY-RUN",
            "memcordon [OPTIONS] [BUDGET]... [--] COMMAND [ARGUMENT]...",
        ))
    } else if first == "probe" {
        Some(("MCCLI-LEGACY-PROBE", "memcordon doctor"))
    } else if first == "explain" {
        Some(("MCCLI-LEGACY-EXPLAIN", "memcordon plan +MEMORY"))
    } else if first == "cleanup" {
        Some(("MCCLI-LEGACY-CLEANUP", "memcordon clean"))
    } else if first == "version" {
        Some(("MCCLI-LEGACY-VERSION", "memcordon --version"))
    } else if first == "compat" {
        Some((
            "MCCLI-LEGACY-COMPAT",
            "memcordon --enforcement watchdog +MEMORY COMMAND [ARGUMENT...]",
        ))
    } else {
        None
    }
}

fn parse_execution(argv: &[OsString]) -> Result<ExecutionArgs, CliError> {
    let mut policy = PolicyArgs::default();
    let mut report_path = None;
    let mut summary = false;
    let mut quiet = false;
    let mut index = 0;
    let mut budgets = BudgetSet::default();
    while index < argv.len() {
        let token = &argv[index];
        if token == "--" {
            index += 1;
            break;
        }
        let text = token.to_str().ok_or_else(|| {
            CliError::new(
                "MCCLI-BUDGET-ENCODING",
                "pre-program budget and option tokens must contain strict ASCII text",
            )
        })?;
        if text == "-h" || text == "--help" {
            return Err(CliError::new("MCCLI-HELP", ROOT_USAGE));
        }
        if text.starts_with('+') {
            while index < argv.len()
                && argv[index]
                    .to_str()
                    .is_some_and(|value| value.starts_with('+'))
            {
                budgets.push(parse_budget(argv[index].clone())?)?;
                index += 1;
            }
            if argv.get(index).is_some_and(|value| value == "--") {
                index += 1;
            }
            break;
        }
        if !text.starts_with('-') {
            break;
        }
        let (name, inline_value) = split_option(text);
        match name {
            "--summary" if inline_value.is_none() => summary = true,
            "--quiet" if inline_value.is_none() => quiet = true,
            "--report" => {
                let value = option_value(argv, &mut index, inline_value, name)?;
                if value == OsStr::new("-") {
                    return Err(CliError::new(
                        "MCCLI-REPORT-STDOUT",
                        "--report - is invalid because stdout belongs to the child",
                    ));
                }
                report_path = Some(PathBuf::from(value));
            }
            _ => parse_policy_option(name, inline_value, argv, &mut index, &mut policy)?,
        }
        index += 1;
    }
    if index >= argv.len() {
        return Err(CliError::new(
            "MCCLI-MISSING-COMMAND",
            "a command must follow options, budgets, and the optional boundary",
        ));
    }
    if summary && quiet {
        return Err(CliError::new(
            "MCCLI-OUTPUT-CONFLICT",
            "--summary conflicts with --quiet",
        ));
    }
    validate_policy_dependencies(&mut policy, &budgets)?;
    Ok(ExecutionArgs {
        budgets,
        policy,
        command: argv[index..].to_vec(),
        output: OutputRequest {
            report_path,
            summary,
            quiet,
        },
    })
}

fn parse_doctor(argv: &[OsString]) -> Result<Invocation, CliError> {
    let mut json = false;
    let mut requirement = None;
    let mut index = 0;
    while index < argv.len() {
        let text = strict_text(&argv[index], "doctor option")?;
        if text == "-h" || text == "--help" {
            return exact_utility_help(argv, Invocation::Help(HelpKind::Doctor));
        }
        let (name, inline_value) = split_option(text);
        match name {
            "--json" if inline_value.is_none() => json = true,
            "--require" => {
                let value = option_value(argv, &mut index, inline_value, name)?;
                requirement = Some(match value.to_str() {
                    Some("hard") => Requirement::Hard,
                    Some("watchdog") => Requirement::Watchdog,
                    _ => {
                        return Err(CliError::new(
                            "MCCLI-DOCTOR-REQUIRE",
                            "--require accepts hard or watchdog",
                        ));
                    }
                });
            }
            _ => return Err(unknown_option(text)),
        }
        index += 1;
    }
    Ok(Invocation::Doctor(DoctorArgs { json, requirement }))
}

fn parse_plan(argv: &[OsString]) -> Result<Invocation, CliError> {
    let mut policy = PolicyArgs::default();
    let mut json = false;
    let mut index = 0;
    let mut budgets = BudgetSet::default();
    while index < argv.len() {
        let text = strict_text(&argv[index], "plan option or +MEMORY")?;
        if text == "-h" || text == "--help" {
            return exact_utility_help(argv, Invocation::Help(HelpKind::Plan));
        }
        if text == "--" {
            return Err(CliError::new(
                "MCCLI-DELIMITER-POSITION",
                "plan has no command delimiter",
            ));
        }
        if text.starts_with('+') {
            while index < argv.len() {
                budgets.push(parse_budget(argv[index].clone())?)?;
                index += 1;
            }
            break;
        }
        let (name, inline_value) = split_option(text);
        if name == "--json" && inline_value.is_none() {
            json = true;
        } else {
            parse_policy_option(name, inline_value, argv, &mut index, &mut policy)?;
        }
        index += 1;
    }
    validate_policy_dependencies(&mut policy, &budgets)?;
    Ok(Invocation::Plan(PlanArgs {
        json,
        budgets,
        policy,
    }))
}

fn validate_policy_dependencies(
    policy: &mut PolicyArgs,
    budgets: &BudgetSet,
) -> Result<(), CliError> {
    if budgets.memory.is_none()
        && (policy.explicit.enforcement
            || policy.explicit.metric
            || policy.explicit.poll_interval
            || policy.explicit.swap)
    {
        return Err(CliError::new(
            "MCUSAGE-MEMORY-OPTION-WITHOUT-MEMORY",
            "explicit memory policy options require a memory budget",
        ));
    }
    if policy.explicit.deadline_scope && budgets.deadline.is_none() {
        return Err(CliError::new(
            "MCUSAGE-DEADLINE-SCOPE",
            "--deadline-scope requires a time budget",
        ));
    }
    if policy.explicit.limit_grace && budgets.memory.is_none() && budgets.deadline.is_none() {
        return Err(CliError::new(
            "MCUSAGE-LIMIT-GRACE",
            "--limit-grace requires a memory or time budget",
        ));
    }
    if policy.explicit.restart_tuning && !policy.restart && policy.restart_on.is_none() {
        return Err(CliError::new(
            "MCUSAGE-RESTART-CONDITION",
            "restart tuning requires --restart or --restart-on",
        ));
    }
    if policy.restart || policy.restart_on.is_some() {
        let requested = policy.restart_on.unwrap_or(RestartConditions::BOTH);
        if policy.restart_on == Some(RestartConditions::MEMORY_LIMIT) && budgets.memory.is_none() {
            return Err(CliError::new(
                "MCUSAGE-RESTART-CONDITION",
                "memory-limit restart requires a memory budget",
            ));
        }
        if policy.restart_on == Some(RestartConditions::DEADLINE)
            && (budgets.deadline.is_none() || policy.deadline_scope != DeadlineScope::Attempt)
        {
            return Err(CliError::new(
                "MCUSAGE-RESTART-CONDITION",
                "deadline restart requires an attempt-scoped time budget",
            ));
        }
        let memory = budgets.memory.is_some()
            && requested.contains(memcordon_core::RestartCondition::MemoryLimit);
        let deadline = budgets.deadline.is_some()
            && policy.deadline_scope == DeadlineScope::Attempt
            && requested.contains(memcordon_core::RestartCondition::Deadline);
        if !memory && !deadline {
            return Err(CliError::new(
                "MCUSAGE-RESTART-NO-EFFECTIVE-CONDITION",
                "restart requires an effective memory-limit or attempt-deadline condition",
            ));
        }
    }
    let defaults = LogisticBackoffPolicy::default();
    policy.backoff = LogisticBackoffPolicy::new(
        policy.backoff_initial.unwrap_or(defaults.initial()),
        policy.backoff_multiplier.unwrap_or(defaults.multiplier()),
        policy.backoff_maximum.unwrap_or(defaults.maximum()),
    )
    .map_err(|error| CliError::new("MCUSAGE-BACKOFF", error.to_string()))?;
    policy.circuit_breaker = match (policy.restart_burst, policy.restart_window, policy.cooldown) {
        (None, None, None) => None,
        (Some(burst), Some(window), Some(cooldown))
            if window >= Duration::from_millis(10) && cooldown >= Duration::from_millis(10) =>
        {
            Some(
                CircuitBreakerPolicy::new(burst, window, cooldown).map_err(|error| {
                    CliError::new("MCUSAGE-CIRCUIT-INCOMPLETE", error.to_string())
                })?,
            )
        }
        _ => {
            return Err(CliError::new(
                "MCUSAGE-CIRCUIT-INCOMPLETE",
                "--restart-burst, --restart-window, and --cooldown must be supplied together and durations must be at least 10ms",
            ));
        }
    };
    Ok(())
}

fn parse_clean(argv: &[OsString]) -> Result<Invocation, CliError> {
    let mut dry_run = false;
    let mut json = false;
    for token in argv {
        let text = strict_text(token, "clean option")?;
        match text {
            "-h" | "--help" => {
                return exact_utility_help(argv, Invocation::Help(HelpKind::Clean));
            }
            "--dry-run" => dry_run = true,
            "--json" => json = true,
            _ => return Err(unknown_option(text)),
        }
    }
    Ok(Invocation::Clean(CleanArgs { dry_run, json }))
}

fn exact_utility_help(argv: &[OsString], invocation: Invocation) -> Result<Invocation, CliError> {
    if argv.len() == 1 {
        Ok(invocation)
    } else {
        Err(CliError::new(
            "MCCLI-HELP-TRAILING",
            "utility help does not accept other arguments",
        ))
    }
}

fn parse_policy_option(
    name: &str,
    inline_value: Option<&str>,
    argv: &[OsString],
    index: &mut usize,
    policy: &mut PolicyArgs,
) -> Result<(), CliError> {
    if name == "--restart" {
        if inline_value.is_some() {
            return Err(CliError::new(
                "MCUSAGE-RESTART-CONDITION",
                "--restart does not accept a value",
            ));
        }
        policy.restart = true;
        return Ok(());
    }
    if !matches!(
        name,
        "--enforcement"
            | "--wait-for"
            | "--metric"
            | "--poll-interval"
            | "--signal-grace"
            | "--limit-grace"
            | "--swap"
            | "--deadline-scope"
            | "--restart-on"
            | "--restart-limit"
            | "--backoff-initial"
            | "--backoff-multiplier"
            | "--backoff-max"
            | "--restart-burst"
            | "--restart-window"
            | "--cooldown"
    ) {
        return Err(unknown_option(name));
    }
    let value = option_value(argv, index, inline_value, name)?;
    let text = strict_text(&value, name)?;
    match name {
        "--enforcement" => {
            policy.explicit.enforcement = true;
            policy.enforcement = match text {
                "auto" => Enforcement::Auto,
                "hard" => Enforcement::Hard,
                "watchdog" => Enforcement::Watchdog,
                _ => return Err(invalid_value(name, text)),
            }
        }
        "--wait-for" => {
            policy.wait_for = match text {
                "command" => Lifetime::Command,
                "workload" => Lifetime::Workload,
                _ => return Err(invalid_value(name, text)),
            }
        }
        "--metric" => {
            policy.explicit.metric = true;
            policy.metric = match text {
                "native" => Metric::Native,
                "physical-footprint" => Metric::PhysicalFootprint,
                "rss" => Metric::Rss,
                "virtual" => Metric::Virtual,
                _ => return Err(invalid_value(name, text)),
            }
        }
        "--poll-interval" => {
            policy.explicit.poll_interval = true;
            policy.poll_interval =
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?;
            if policy.poll_interval < Duration::from_millis(10) {
                return Err(CliError::new(
                    "MCCLI-POLL-INTERVAL",
                    "--poll-interval must be at least 10ms",
                ));
            }
        }
        "--signal-grace" => {
            policy.signal_grace =
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?
        }
        "--limit-grace" => {
            policy.explicit.limit_grace = true;
            policy.limit_grace =
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?
        }
        "--swap" => {
            policy.explicit.swap = true;
            policy.swap = match text {
                "0" | "0B" => SwapPolicy::Bytes(ByteSize::from_bytes(0)),
                "unlimited" => SwapPolicy::Unlimited,
                "host" => SwapPolicy::Host,
                _ => SwapPolicy::Bytes(
                    text.parse::<ByteSize>()
                        .map_err(|error| CliError::new("MCCLI-SWAP", error.to_string()))?,
                ),
            }
        }
        "--deadline-scope" => {
            policy.explicit.deadline_scope = true;
            policy.deadline_scope = match text {
                "attempt" => DeadlineScope::Attempt,
                "supervision" => DeadlineScope::Supervision,
                _ => return Err(invalid_value(name, text)),
            }
        }
        "--restart-on" => {
            if policy.restart_on.is_some() {
                return Err(CliError::new(
                    "MCUSAGE-RESTART-CONDITION",
                    "--restart-on may be supplied once",
                ));
            }
            policy.restart_on = Some(match text {
                "both" => RestartConditions::BOTH,
                "memory-limit" => RestartConditions::MEMORY_LIMIT,
                "deadline" => RestartConditions::DEADLINE,
                _ => return Err(invalid_value(name, text)),
            });
        }
        "--restart-limit" => {
            policy.explicit.restart_tuning = true;
            policy.restart_limit = if text == "unlimited" {
                RestartLimit::Unlimited
            } else {
                RestartLimit::Count(text.parse::<NonZeroU64>().map_err(|_| {
                    CliError::new(
                        "MCUSAGE-RESTART-LIMIT",
                        "restart limit must be unlimited or a positive integer",
                    )
                })?)
            }
        }
        "--backoff-initial" => {
            policy.explicit.restart_tuning = true;
            policy.backoff_initial = Some(
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?,
            )
        }
        "--backoff-multiplier" => {
            policy.explicit.restart_tuning = true;
            policy.backoff_multiplier = Some(
                text.parse::<BackoffMultiplier>()
                    .map_err(|error| CliError::new("MCUSAGE-BACKOFF", error.to_string()))?,
            )
        }
        "--backoff-max" => {
            policy.explicit.restart_tuning = true;
            policy.backoff_maximum = Some(
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?,
            )
        }
        "--restart-burst" => {
            policy.explicit.restart_tuning = true;
            policy.restart_burst = Some(text.parse::<NonZeroU64>().map_err(|_| {
                CliError::new(
                    "MCUSAGE-CIRCUIT-INCOMPLETE",
                    "restart burst must be positive",
                )
            })?)
        }
        "--restart-window" => {
            policy.explicit.restart_tuning = true;
            policy.restart_window = Some(
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?,
            )
        }
        "--cooldown" => {
            policy.explicit.restart_tuning = true;
            policy.cooldown = Some(
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?,
            )
        }
        _ => return Err(unknown_option(name)),
    }
    Ok(())
}

fn option_value(
    argv: &[OsString],
    index: &mut usize,
    inline: Option<&str>,
    option: &str,
) -> Result<OsString, CliError> {
    if let Some(value) = inline {
        return Ok(OsString::from(value));
    }
    *index += 1;
    argv.get(*index).cloned().ok_or_else(|| {
        CliError::new(
            "MCCLI-MISSING-OPTION-VALUE",
            format!("{option} requires a value"),
        )
    })
}

fn split_option(text: &str) -> (&str, Option<&str>) {
    text.split_once('=')
        .map_or((text, None), |(name, value)| (name, Some(value)))
}

fn strict_text<'a>(value: &'a OsStr, context: &str) -> Result<&'a str, CliError> {
    value.to_str().ok_or_else(|| {
        CliError::new(
            "MCCLI-OPTION-ENCODING",
            format!("{context} must be valid UTF-8"),
        )
    })
}

fn unknown_option(option: &str) -> CliError {
    CliError::new(
        "MCCLI-UNKNOWN-OPTION",
        format!("unknown MemCordon option `{option}` before +MEMORY"),
    )
}

fn invalid_value(option: &str, value: &str) -> CliError {
    CliError::new(
        "MCCLI-OPTION-VALUE",
        format!("invalid value `{value}` for {option}"),
    )
}
