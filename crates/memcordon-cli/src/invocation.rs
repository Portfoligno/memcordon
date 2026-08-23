use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use memcordon_core::{
    BackoffMultiplier, BoundaryRequirement, ByteSize, CircuitBreakerPolicy, DeadlinePolicy,
    DeadlineScope, Enforcement, HalfLifeLogisticBackoffPolicy, Lifetime, Metric, Policy,
    RestartConditions, RestartLimit, SwapPolicy,
};
use std::num::NonZeroU64;

use crate::parse_duration;

macro_rules! reference_url {
    () => {
        concat!(
            env!("CARGO_PKG_REPOSITORY"),
            "/blob/",
            env!("CARGO_PKG_VERSION"),
            "/docs/reference.md"
        )
    };
}

macro_rules! with_reference {
    ($body:literal) => {
        concat!($body, "Reference:\n  ", reference_url!())
    };
}

pub const REFERENCE_URL: &str = reference_url!();

pub const ROOT_USAGE: &str = with_reference!(
    r#"Run a command and its descendants with optional memory and elapsed-time limits.

Usage:
  memcordon [OPTION|BUDGET]... [--] COMMAND [ARGUMENT]...
  memcordon help [TOPIC]
  memcordon doctor [OPTIONS]
  memcordon plan [OPTION|BUDGET]...
  memcordon clean [OPTIONS]

  Use -- before COMMAND if it is named help, doctor, plan, or clean,
  or begins with + or -. Arguments after COMMAND pass unchanged.

  Examples:
    memcordon ./workload
    memcordon +1GiB +10m ./workload

Budgets and common options:
  --sealed                       Require certified sealed supervision; off
  +MEMORY                        Memory ceiling; bytes, KB..EB, or KiB..EiB
  +TIME                          Elapsed-time deadline; decimal ms, s, m, or h
  --wait-for command|workload    Terminate remaining members after command exit
                                 or wait for workload empty; command
  --command-exit-grace DURATION  Natural-drain time before cleanup; 0s
  --restart                      Restart after memory or deadline limits; off
  --report PATH                  Write JSON to PATH; unset
  --summary                      Write one final summary line to stderr; off
  --quiet                        Suppress optional wrapper output; off
  -h, --help                     Print this help
  -V, --version                  Print the version

Utilities:
  help      List topics or show one topic
  doctor    Inspect backend availability
  plan      Resolve budgets and policy without launching
  clean     Inspect or remove stale owned artifacts

"#
);

pub const HELP_USAGE: &str = with_reference!(
    r#"Show focused offline reference by topic.

Usage:
  memcordon help [TOPIC]

Topics:
  usage        Invocation and argument boundaries
  budgets      Memory and time budget grammar
  memory       Memory policy
  containment  Sealed process-supervision boundary
  deadline     Deadline policy
  lifecycle    Completion, remaining-member cleanup, and termination grace
  restart      Restart conditions and limits
  backoff      Restart delay policy
  circuit      Circuit breaker policy
  output       Reports and optional output
  utilities    Help, doctor, plan, clean, and version
  exit-status  Exit statuses and precedence
  all          Complete option and rule reference

"#
);

pub const HELP_TOPIC_USAGE: &[(&str, &str)] = &[
    (
        "containment",
        with_reference!(
            r#"Require a certified process-supervision boundary.

Usage:
  memcordon --sealed [OPTION|BUDGET]... [--] COMMAND [ARGUMENT]...
  memcordon plan --sealed [OPTION|BUDGET]...
  memcordon doctor --require sealed

--sealed fails before target authorization when the host cannot establish and
verify a certified boundary with independent cleanup authority and terminal
workload-empty proof. It never falls back to standard supervision. It is not a
filesystem, network, syscall, or secret sandbox.

"#
        ),
    ),
    (
        "usage",
        with_reference!(
            r#"Invoke workloads, utilities, and topic help without a shell.

Usage:
  memcordon [OPTION|BUDGET]... [--] COMMAND [ARGUMENT]...
  memcordon help [TOPIC]
  memcordon doctor [OPTIONS]
  memcordon plan [OPTION|BUDGET]...
  memcordon clean [OPTIONS]

Examples:
  memcordon ./workload
  memcordon +1GiB --summary +10m ./workload --verbose
  memcordon -- help restart

Rules:
  Options and up to two budgets may be interleaved before COMMAND; budget source
  order is preserved. The first plain token starts COMMAND. One exact -- starts
  a command beginning with + or -. Built-in utilities are recognized only
  immediately after memcordon; elsewhere, the same names are workload commands.
  Every argument after COMMAND is preserved as native argv and is not parsed.

"#
        ),
    ),
    (
        "budgets",
        with_reference!(
            r#"Configure optional memory and elapsed-time limits.

Budgets:
  +MEMORY    Memory ceiling; bytes, B, KB..EB, or KiB..EiB
  +TIME      Elapsed-time deadline; decimal ms, s, m, or h

Rules:
  At most one budget of each kind is accepted, in either order. Budgets are
  interleavable with options and preserve their relative source order in reports.
  Decimal fractions round up; explicit zero remains distinct from omission.
  Memory accepts one leading +; ambiguous units such as G are invalid. Time
  accepts lowercase ms, s, m, or h and rejects signs and exponent notation.

"#
        ),
    ),
    (
        "memory",
        with_reference!(
            r#"Configure memory enforcement when +MEMORY is present.

Memory options (value; default):
  --enforcement auto|hard|watchdog       Backend requirement; auto
  --metric native|physical-footprint|rss|virtual
                                         Memory metric; native
  --poll-interval DURATION               Watchdog sampling interval; 50ms
  --swap SIZE|unlimited|host             Swap policy; 0B

Rules:
  Explicit memory options require +MEMORY. Polling must be at least 10ms.
  Native metrics and enforcement capabilities are platform-specific. A
  confirmed MemCordon memory-limit event returns 124.

"#
        ),
    ),
    (
        "deadline",
        with_reference!(
            r#"Configure elapsed-time enforcement when +TIME is present.

Deadline options (value; default):
  --deadline-scope attempt|supervision   Deadline scope; attempt

Rules:
  Explicit deadline scope requires +TIME. An attempt deadline restarts from
  each launch authorization and may trigger restart. A supervision deadline
  spans setup, cleanup, backoff, and cooldown and is terminal. A MemCordon
  deadline returns 123.

"#
        ),
    ),
    (
        "lifecycle",
        with_reference!(
            r#"Choose what happens after the direct command exits.

Lifecycle options (value; default):
  --wait-for command|workload            Clean on direct-command exit or wait for workload empty; command
  --command-exit-grace DURATION          Natural-drain grace after direct-command exit; 0s
  --signal-grace DURATION                Grace after external interruption; 2s
  --limit-grace DURATION                 Grace after a configured limit; 0s

Completion modes:
  command   Default. After the direct command exits, wait up to command-exit
            grace for the workload to empty naturally, then forcibly terminate
            and clean up remaining members. MemCordon returns only after cleanup,
            using the direct command's status when cleanup succeeds.
  workload  Keep supervising after the direct command exits. Remaining members
            are not terminated merely because the direct command exited; wait
            until the workload is empty. Without +TIME, this can wait indefinitely
            on Linux and macOS.

Rules:
  Descendants are workload members in both modes; --wait-for changes completion,
  not membership. Command-exit grace sends no signal and applies only to command
  mode. Signal grace applies only to external interruption. Limit grace requires
  +MEMORY or +TIME and applies after a configured limit before forced cleanup.
  On Windows, workload is currently adjusted to command and reported as an
  ignored option effect.

"#
        ),
    ),
    (
        "restart",
        with_reference!(
            r#"Restart workloads after selected MemCordon limits.

Restart options (value; default):
  --restart                              Restart on applicable configured limits; off
  --restart-on both|memory-limit|deadline
                                         Enable restart for selected conditions; unset
  --restart-limit COUNT|unlimited        Additional launches; unlimited

Rules:
  --restart enables both applicable conditions; --restart-on independently
  enables the selected conditions. A finite restart limit is a positive count
  of additional launches. memory-limit requires +MEMORY; deadline requires an
  attempt-scoped +TIME. At least one selected condition must be effective.

"#
        ),
    ),
    (
        "backoff",
        with_reference!(
            r#"Configure the half-life logistic delay between restarts.

Backoff options (value; default):
  --backoff-base DURATION                Recovery baseline; 250ms
  --backoff-multiplier DECIMAL           Delay growth control; 4
  --backoff-asymptote DURATION           Logistic asymptote; 15m
  --backoff-recovery-half-life DURATION  Quiet-time half-life of distance from base; 15m

Rules:
  Backoff options require --restart or --restart-on. Durations must be at least
  1ms. The multiplier is an exact decimal from 1 through 100. Quiet time moves
  the stored interval toward the base before the next logistic adjustment.

"#
        ),
    ),
    (
        "circuit",
        with_reference!(
            r#"Quarantine repeated limit failures using decayed pressure.

Circuit options (value; default):
  --circuit-threshold SCORE              Decayed failure pressure to open; unset
  --circuit-cooldown DURATION            Minimum circuit quarantine; unset
  --circuit-half-life DURATION           Failure-pressure half-life; backoff half-life

Rules:
  Circuit options require --restart or --restart-on. Threshold must be positive
  and finite; threshold and cooldown must be supplied together. Cooldown may be
  zero. The optional half-life must be at least 1ms and cannot stand alone.

"#
        ),
    ),
    (
        "output",
        with_reference!(
            r#"Configure execution reports and optional wrapper output.

Output options (value; default):
  --report PATH                          Write schema-7 JSON to PATH; unset
  --summary                              Write one final summary line to stderr; off
  --quiet                                Suppress optional wrapper output; off

Rules:
  A report is mandatory when requested, needs an existing parent directory,
  and cannot use - because stdout belongs to the child. --summary conflicts
  with --quiet; quiet never suppresses required diagnostics or child streams.

Utility JSON:
  doctor --json    schema-4
  plan --json      schema-6
  clean --json     schema-2

"#
        ),
    ),
    (
        "utilities",
        with_reference!(
            r#"Inspect MemCordon without launching a workload.

Usage:
  memcordon help [TOPIC]
  memcordon doctor [--json] [--require hard|watchdog|sealed]
  memcordon plan [OPTION|BUDGET]...
  memcordon clean [--dry-run] [--json]
  memcordon --version

Utilities:
  help      List topics or show one topic
  doctor    Print the version and selected backend; JSON uses schema-4
  plan      Resolve policy with launch proof false; JSON uses schema-6
  clean     Inspect or remove stale owned artifacts; JSON uses schema-2
  --version Print one version line

Doctor, plan, and clean have exact -h and --help output. Incomplete clean or
an unmet doctor requirement returns 125.

"#
        ),
    ),
    (
        "exit-status",
        with_reference!(
            r#"Map workload and wrapper outcomes to process status.

Exit status:
  child status    Direct-command exit after required workload cleanup succeeds
  123             MemCordon elapsed-time deadline
  124             Confirmed workload memory-limit event
  125             Backend, setup, monitoring, cleanup, report, or restart failure
  126             Command found but not executable
  127             Command not found
  2               Usage diagnostic
  128 + signal    Unix interruption or child signal when otherwise applicable

The direct command remains the ordinary status authority in both completion
modes. In command mode, remaining members are terminated before its status is
returned. In workload mode, its status is retained while MemCordon waits for the
workload to become empty. Cleanup failure replaces an ordinary result with 125.
Confirmed memory evidence precedes deadline, monitor failure, interruption, and
ordinary completion in one observation cycle. Reports establish provenance when
a child independently returns a reserved number.

"#
        ),
    ),
    (
        "all",
        with_reference!(
            r#"Complete command-line reference for running a command and its descendants with
optional memory and elapsed-time limits.

Usage:
  memcordon [OPTION|BUDGET]... [--] COMMAND [ARGUMENT]...
  memcordon help [TOPIC]
  memcordon doctor [--json] [--require hard|watchdog|sealed]
  memcordon plan [OPTION|BUDGET]...
  memcordon clean [--dry-run] [--json]

Examples:
  memcordon +10m --summary +1GiB cargo test --workspace
  memcordon +1GiB --restart --restart-limit 3 ./worker
  memcordon -- help restart

Invocation:
  Options and up to two budgets (one each) may be interleaved before COMMAND;
  budget source order is preserved. Built-in utilities are recognized only
  immediately after memcordon. Use -- to launch a first-position command with a
  utility name or beginning with + or -. Once COMMAND starts, its native
  arguments pass unchanged.

Budgets and values:
  +MEMORY    Memory ceiling; bare bytes, B, KB..EB, or KiB..EiB
  +TIME      Elapsed-time deadline; decimal ms, s, m, or h
  DURATION   Decimal ms, s, m, or h; rounded up to one millisecond
  SIZE       Memory size without the leading +

  At most one budget of each kind is accepted. Budget fractions round up to a
  byte or millisecond; explicit zero remains distinct from omission. Memory
  units must be unambiguous. Time and duration units are lowercase; their
  values reject additional signs and exponent notation.

Options:
  Accepted values follow each option; descriptions end with the default when
  applicable.

Containment:
  --sealed                              Require certified sealed supervision; off

  Sealed mode fails before target authorization when the complete contract is
  unavailable and never falls back to standard supervision.

Memory (requires +MEMORY):
  --enforcement auto|hard|watchdog       Enforcement requirement; auto
  --metric native|physical-footprint|rss|virtual
                                         Memory measurement; native
  --poll-interval DURATION               Monitoring poll interval; 50ms
  --swap SIZE|unlimited|host             Swap policy; 0B

  Polling must be at least 10ms. Available enforcement and native memory
  measurement vary by platform.

Deadline (requires +TIME):
  --deadline-scope attempt|supervision   Deadline scope; attempt

  attempt resets at each launch authorization and may restart. supervision
  starts at the first authorization, includes later cleanup, setup, backoff,
  and cooldown, and is terminal.

Completion and cleanup:
  --wait-for command|workload            Completion mode; command
  --command-exit-grace DURATION          Natural-drain grace; 0s
  --signal-grace DURATION                Grace after external interruption; 2s
  --limit-grace DURATION                 Grace after a configured limit; 0s

  command is the default: direct-command exit waits up to command-exit grace for
  natural drain, then forcibly cleans remaining members before returning the
  direct command's status. workload keeps those members running and waits for
  workload empty; without +TIME, this may wait indefinitely on Linux and macOS.
  Windows resolves workload to command and reports an ignored option effect.

  Command-exit grace sends no signal and applies only with --wait-for command.
  Signal grace applies only to external interruption. Limit grace requires
  +MEMORY or +TIME and applies before forced cleanup after that limit.

Restart:
  --restart                              Restart on applicable limits; off
  --restart-on both|memory-limit|deadline
                                         Selected limit conditions; unset
  --restart-limit COUNT|unlimited        Additional launches; unlimited

  --restart selects both applicable limits; --restart-on selects named limits.
  Restart limit, backoff, and circuit options require --restart or --restart-on.
  A finite restart limit is a positive number of additional launches.
  memory-limit requires +MEMORY; deadline requires attempt-scoped +TIME. At
  least one selected condition must be effective.

Backoff (requires --restart or --restart-on):
  --backoff-base DURATION                Restart-delay baseline; 250ms
  --backoff-multiplier DECIMAL           Logistic growth multiplier; 4
  --backoff-asymptote DURATION           Delay approached after failures; 15m
  --backoff-recovery-half-life DURATION  Time for excess delay to halve; 15m

  Durations must be at least 1ms. The multiplier is an exact decimal from 1
  through 100. Quiet time moves the stored delay toward the baseline.

Circuit breaker (requires --restart or --restart-on):
  --circuit-threshold SCORE              Pressure required to open; unset
  --circuit-cooldown DURATION            Minimum delay after opening; unset
  --circuit-half-life DURATION           Pressure half-life; backoff half-life

  Threshold must be positive and finite; threshold and cooldown must be set
  together. Cooldown may be zero. The optional half-life must be at least 1ms
  and cannot be set by itself.

Output:
  --report PATH                          Write a schema-7 JSON report; unset
  --summary                              Final summary line on stderr; off
  --quiet                                Suppress optional MemCordon output; off

  Reports need an existing parent directory and cannot use - because stdout
  belongs to the child. --summary conflicts with --quiet. Quiet does not
  suppress required diagnostics, child streams, or reports.

Root flags (must be used alone):
  -h, --help                             Print concise root help
  -V, --version                          Print the version

Utilities:
  help [TOPIC]                         Show focused offline help
  doctor [--json] [--require MODE]    Check available enforcement
  plan [OPTION|BUDGET]...             Resolve policy without launching
  clean [--dry-run] [--json]          Inspect or remove stale owned state

Utility options:
  doctor --json                       Write schema-4 JSON to stdout; off
  doctor --require hard|watchdog|sealed Require the selected backend class; unset
  plan --json                         Write schema-6 JSON to stdout; off
  clean --dry-run                     List without removing artifacts; off
  clean --json                        Write schema-2 JSON to stdout; off

  Plan accepts budgets and the Memory through Circuit breaker options above,
  plus --json, but not COMMAND or --. Doctor, plan, and clean accept -h or
  --help only by itself. An unmet doctor requirement or incomplete clean
  returns 125.

Exit status:
  child status  Direct-command status after required cleanup succeeds
  2             Usage error
  123           Elapsed-time deadline
  124           Confirmed memory limit
  125           Backend, setup, monitoring, cleanup, report, or restart failure
  126           Command found but not executable
  127           Command not found
  128 + signal  Unix interruption or child signal when applicable

  Confirmed memory evidence outranks deadline, monitor failure, interruption,
  and ordinary completion in the same observation cycle. Cleanup failure
  replaces an ordinary result with 125. Reports distinguish a child's
  reserved-number status.

Run memcordon help for topic-specific help.

"#
        ),
    ),
];

pub const DOCTOR_USAGE: &str = with_reference!(
    "Inspect backend availability without launching a workload.\n\nUsage:\n  memcordon doctor [--json] [--require hard|watchdog|sealed]\n\nText prints the version and selected backend; --json prints full capabilities\nand limitations.\n\nOptions (default):\n  --json                         Write schema-4 JSON to stdout; off\n  --require hard|watchdog|sealed Return 125 unless the backend matches; unset\n  -h, --help                     Print this help\n\n"
);

pub const PLAN_USAGE: &str = with_reference!(
    r#"Resolve budgets and policy without launching a target.

Usage:
  memcordon plan [OPTION|BUDGET]...

Example:
  memcordon plan +8GiB --wait-for workload +10m

Text prints the selected backend and "launch proof: false"; --json prints the
full policy resolution.

Budgets:
  +MEMORY    Memory ceiling; bytes, KB..EB, or KiB..EiB
  +TIME      Elapsed-time deadline; decimal ms, s, m, or h

Policy options (value; default):
  --sealed                              Require certified sealed supervision; off
  --enforcement auto|hard|watchdog       Backend requirement; auto
  --wait-for command|workload            Clean on direct-command exit or wait for workload empty; command
  --command-exit-grace DURATION          Natural-drain grace after direct-command exit; 0s
  --metric native|physical-footprint|rss|virtual
                                         Memory metric; native
  --poll-interval DURATION               Sampling interval; 50ms
  --signal-grace DURATION                External-interruption grace; 2s
  --limit-grace DURATION                 Configured-limit grace; 0s
  --swap SIZE|unlimited|host             Swap policy; 0B
  --deadline-scope attempt|supervision   Deadline scope; attempt
  --restart                              Enable applicable limit restarts; off
  --restart-on both|memory-limit|deadline
                                         Enable selected restarts; unset
  --restart-limit COUNT|unlimited        Additional launches; unlimited
  --backoff-base DURATION                Recovery baseline; 250ms
  --backoff-multiplier DECIMAL           Delay growth control; 4
  --backoff-asymptote DURATION           Logistic asymptote; 15m
  --backoff-recovery-half-life DURATION  Quiet-time half-life of distance from base; 15m
  --circuit-threshold SCORE              Decayed failure pressure to open; unset
  --circuit-cooldown DURATION            Minimum circuit quarantine; unset
  --circuit-half-life DURATION           Failure-pressure half-life; backoff half-life
  --json                                 Write schema-6 JSON to stdout; off
  -h, --help                             Print this help

Rules:
  Options and up to two budgets (one each) may be interleaved; budget source
  order is preserved. COMMAND and -- are invalid. --enforcement, --metric,
  --poll-interval, and --swap need +MEMORY;
  --deadline-scope needs +TIME; --command-exit-grace requires command completion;
  --limit-grace needs either budget. Restart tuning needs --restart or
  --restart-on. Set circuit threshold and cooldown together.
  On Windows, requested workload waiting resolves to command completion. Use
  --json to inspect requested/effective policy and option effects.

"#
);

pub const CLEAN_USAGE: &str = with_reference!(
    "Inspect or remove stale MemCordon-owned backend artifacts.\n\nUsage:\n  memcordon clean [--dry-run] [--json]\n\nExample:\n  memcordon clean --dry-run\n\nWithout --dry-run, removes listed artifacts; incomplete cleanup returns 125.\n\nOptions (default):\n  --dry-run                      List candidates without changing the host; off\n  --json                         Write schema-2 JSON to stdout; off\n  -h, --help                     Print this help\n\n"
);

pub const PUBLIC_POLICY_OPTIONS: &[&str] = &[
    "--sealed",
    "--enforcement",
    "--wait-for",
    "--command-exit-grace",
    "--metric",
    "--poll-interval",
    "--signal-grace",
    "--limit-grace",
    "--swap",
    "--deadline-scope",
    "--restart",
    "--restart-on",
    "--restart-limit",
    "--backoff-base",
    "--backoff-multiplier",
    "--backoff-asymptote",
    "--backoff-recovery-half-life",
    "--circuit-threshold",
    "--circuit-cooldown",
    "--circuit-half-life",
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
        (Err(_), Ok(duration)) => Ok(BudgetToken::Time { raw, duration }),
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
                "memory limits use a leading '+'\nusage: memcordon [OPTION|BUDGET]... [--] COMMAND [ARGUMENT...]\nexample: memcordon +8GiB cargo test --workspace",
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

#[derive(Clone, Debug, PartialEq)]
pub struct PolicyArgs {
    pub boundary: BoundaryRequirement,
    pub enforcement: Enforcement,
    pub wait_for: Lifetime,
    pub metric: Metric,
    pub poll_interval: Duration,
    pub signal_grace: Duration,
    pub command_exit_grace: Duration,
    pub limit_grace: Duration,
    pub swap: SwapPolicy,
    pub deadline_scope: DeadlineScope,
    pub restart: bool,
    pub restart_on: Option<RestartConditions>,
    pub restart_limit: RestartLimit,
    pub backoff: HalfLifeLogisticBackoffPolicy,
    pub circuit_breaker: Option<CircuitBreakerPolicy>,
    backoff_base_interval: Option<Duration>,
    backoff_multiplier: Option<BackoffMultiplier>,
    backoff_asymptote_interval: Option<Duration>,
    backoff_recovery_half_life: Option<Duration>,
    circuit_threshold: Option<f64>,
    circuit_cooldown: Option<Duration>,
    circuit_half_life: Option<Duration>,
    pub explicit: ExplicitPolicyOptions,
}

impl Eq for PolicyArgs {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExplicitPolicyOptions {
    pub boundary: bool,
    pub enforcement: bool,
    pub metric: bool,
    pub poll_interval: bool,
    pub swap: bool,
    pub deadline_scope: bool,
    pub command_exit_grace: bool,
    pub limit_grace: bool,
    pub restart_tuning: bool,
}

impl Default for PolicyArgs {
    fn default() -> Self {
        Self {
            boundary: BoundaryRequirement::Standard,
            enforcement: Enforcement::Auto,
            wait_for: Lifetime::Command,
            metric: Metric::Native,
            poll_interval: Duration::from_millis(50),
            signal_grace: Duration::from_secs(2),
            command_exit_grace: Duration::ZERO,
            limit_grace: Duration::ZERO,
            swap: SwapPolicy::Bytes(ByteSize::from_bytes(0)),
            deadline_scope: DeadlineScope::Attempt,
            restart: false,
            restart_on: None,
            restart_limit: RestartLimit::Unlimited,
            backoff: HalfLifeLogisticBackoffPolicy::default(),
            circuit_breaker: None,
            backoff_base_interval: None,
            backoff_multiplier: None,
            backoff_asymptote_interval: None,
            backoff_recovery_half_life: None,
            circuit_threshold: None,
            circuit_cooldown: None,
            circuit_half_life: None,
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
        policy = policy.with_boundary(self.boundary);
        policy.lifetime = self.wait_for;
        policy.metric = self.metric;
        policy.poll_interval = self.poll_interval;
        policy.signal_grace = self.signal_grace;
        policy.command_exit_grace = self.command_exit_grace;
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
    Sealed,
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
    pub help: Option<&'static str>,
}

impl CliError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            help: None,
        }
    }

    pub fn with_help(mut self, help: &'static str) -> Self {
        self.help = Some(help);
        self
    }
}

pub fn route(argv: &[OsString]) -> Result<Invocation, CliError> {
    let first = argv.first().ok_or_else(|| {
        CliError::new("MCCLI-MISSING-LIMIT", "no invocation supplied").with_help(ROOT_USAGE)
    })?;
    if first == "-h" || first == "--help" {
        return exact_root_flag(argv, Invocation::Help(HelpKind::Root));
    }
    if first == "-V" || first == "--version" {
        return exact_root_flag(argv, Invocation::Version);
    }
    if first == "help" {
        return parse_help(&argv[1..]);
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

fn parse_help(argv: &[OsString]) -> Result<Invocation, CliError> {
    if argv.is_empty() {
        return Err(CliError::new("MCCLI-HELP", HELP_USAGE));
    }
    if argv.len() > 1 {
        return Err(CliError::new(
            "MCCLI-HELP-TOPIC-COUNT",
            "help accepts at most one topic: usage, budgets, memory, containment, deadline, lifecycle, restart, backoff, circuit, output, utilities, exit-status, or all",
        ));
    }
    let topic = argv[0].to_str().ok_or_else(|| {
        CliError::new(
            "MCCLI-HELP-TOPIC-ENCODING",
            "help topic must be valid UTF-8",
        )
    })?;
    let usage = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(name, usage)| (*name == topic).then_some(*usage))
        .ok_or_else(|| {
            CliError::new(
                "MCCLI-HELP-TOPIC",
                format!(
                    "unknown help topic `{topic}`; expected usage, budgets, memory, containment, deadline, lifecycle, restart, backoff, circuit, output, utilities, exit-status, or all"
                ),
            )
        })?;
    Err(CliError::new("MCCLI-HELP", usage))
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
            "memcordon [OPTION|BUDGET]... [--] COMMAND [ARGUMENT]...",
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
        let prefix = token.as_encoded_bytes().first().copied();
        if prefix == Some(b'+') {
            budgets.push(parse_budget(token.clone())?)?;
            index += 1;
            continue;
        }
        if prefix != Some(b'-') {
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
                    Some("sealed") => Requirement::Sealed,
                    _ => {
                        return Err(CliError::new(
                            "MCCLI-DOCTOR-REQUIRE",
                            "--require accepts hard, watchdog, or sealed",
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
        let text = strict_text(&argv[index], "plan option or budget")?;
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
            budgets.push(parse_budget(argv[index].clone())?)?;
            index += 1;
            continue;
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
    if policy.explicit.command_exit_grace && policy.wait_for == Lifetime::Workload {
        return Err(CliError::new(
            "MCUSAGE-COMMAND-EXIT-GRACE",
            "--command-exit-grace applies only with --wait-for command",
        ));
    }
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
    let defaults = HalfLifeLogisticBackoffPolicy::default();
    policy.backoff = HalfLifeLogisticBackoffPolicy::new(
        policy
            .backoff_base_interval
            .unwrap_or(defaults.base_interval()),
        policy.backoff_multiplier.unwrap_or(defaults.multiplier()),
        policy
            .backoff_asymptote_interval
            .unwrap_or(defaults.asymptote_interval()),
        policy
            .backoff_recovery_half_life
            .unwrap_or(defaults.recovery_half_life()),
    )
    .map_err(|_| {
        CliError::new(
            "MCUSAGE-BACKOFF",
            "--backoff-base, --backoff-asymptote, and --backoff-recovery-half-life must be >=1ms",
        )
    })?;
    policy.circuit_breaker = match (policy.circuit_threshold, policy.circuit_cooldown) {
        (None, None) if policy.circuit_half_life.is_none() => None,
        (Some(threshold), Some(cooldown)) => Some(
            CircuitBreakerPolicy::new(
                threshold,
                policy
                    .circuit_half_life
                    .unwrap_or(policy.backoff.recovery_half_life()),
                cooldown,
            )
            .map_err(|_| {
                CliError::new(
                    "MCUSAGE-CIRCUIT-INCOMPLETE",
                    "circuit threshold must be a positive finite number, circuit cooldown may be zero, and circuit half-life must be at least 1ms",
                )
            })?,
        ),
        _ => {
            return Err(CliError::new(
                "MCUSAGE-CIRCUIT-INCOMPLETE",
                "--circuit-threshold and --circuit-cooldown must be supplied together; circuit cooldown may be zero and circuit half-life must be at least 1ms",
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
    if name == "--sealed" {
        if inline_value.is_some() || policy.explicit.boundary {
            return Err(CliError::new(
                "MCUSAGE-SEALED",
                "--sealed may be supplied once and does not accept a value",
            ));
        }
        policy.boundary = BoundaryRequirement::Sealed;
        policy.explicit.boundary = true;
        return Ok(());
    }
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
            | "--command-exit-grace"
            | "--signal-grace"
            | "--limit-grace"
            | "--swap"
            | "--deadline-scope"
            | "--restart-on"
            | "--restart-limit"
            | "--backoff-base"
            | "--backoff-multiplier"
            | "--backoff-asymptote"
            | "--backoff-recovery-half-life"
            | "--circuit-threshold"
            | "--circuit-cooldown"
            | "--circuit-half-life"
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
        "--command-exit-grace" => {
            policy.explicit.command_exit_grace = true;
            policy.command_exit_grace =
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
        "--backoff-base" => {
            policy.explicit.restart_tuning = true;
            policy.backoff_base_interval = Some(
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
        "--backoff-asymptote" => {
            policy.explicit.restart_tuning = true;
            policy.backoff_asymptote_interval = Some(
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?,
            )
        }
        "--backoff-recovery-half-life" => {
            policy.explicit.restart_tuning = true;
            policy.backoff_recovery_half_life = Some(
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?,
            )
        }
        "--circuit-threshold" => {
            policy.explicit.restart_tuning = true;
            let threshold = text.parse::<f64>().map_err(|_| {
                CliError::new(
                    "MCUSAGE-CIRCUIT-INCOMPLETE",
                    "circuit threshold must be a positive finite number",
                )
            })?;
            if !threshold.is_finite() || threshold <= 0.0 {
                return Err(CliError::new(
                    "MCUSAGE-CIRCUIT-INCOMPLETE",
                    "circuit threshold must be a positive finite number",
                ));
            }
            policy.circuit_threshold = Some(threshold)
        }
        "--circuit-cooldown" => {
            policy.explicit.restart_tuning = true;
            policy.circuit_cooldown = Some(
                parse_duration(text).map_err(|message| CliError::new("MCCLI-DURATION", message))?,
            )
        }
        "--circuit-half-life" => {
            policy.explicit.restart_tuning = true;
            policy.circuit_half_life = Some(
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
        format!("unknown MemCordon option `{option}`"),
    )
}

fn invalid_value(option: &str, value: &str) -> CliError {
    CliError::new(
        "MCCLI-OPTION-VALUE",
        format!("invalid value `{value}` for {option}"),
    )
}
