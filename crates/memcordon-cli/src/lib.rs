//! Run a typed native command under MemCordon's platform containment.
//!
//! The facade API and CLI use the same backend launch path. On Linux, target code cannot run
//! until its cgroup membership is verified and the crash guardian has been launched.
//!
//! ```no_run
//! use memcordon::{ByteSize, CommandSpec, Limiter, MemcordonExecutable, Policy};
//!
//! let command = CommandSpec::new("example-program").args(["--mode", "bounded"]);
//! let outcome = Limiter::new(Policy::new(ByteSize::gib(1)))
//!     .memcordon_executable(
//!         MemcordonExecutable::new("/usr/local/bin/memcordon")
//!             .expect("installed MemCordon path must be absolute"),
//!     )
//!     .command(command)
//!     .run()?;
//! # Ok::<(), memcordon::Error>(())
//! ```

#![forbid(unsafe_code)]

use std::time::Duration;
use std::{
    fmt,
    path::{Path, PathBuf},
};

pub mod exit_mapping;
pub mod invocation;

pub use memcordon_core::{
    BoundaryRequirement, ByteSize, ChildTermination, CircuitBreakerPolicy, CleanupSummary,
    CommandSpec, Enforcement, Error, HalfLifeLogisticBackoffPolicy, Lifetime, Metric, Policy,
    RestartConditions, RestartLimit, RestartPolicy, RestartSettings, RunOutcome,
    SupervisionExecution,
};
pub use memcordon_platform::{BackendInfo, ProbeReport, probe};

/// Parses a nonnegative decimal duration with an exact lowercase `ms`, `s`,
/// `m`, or `h` suffix.
///
/// Fractional values round upward to the next whole millisecond. Values whose
/// millisecond representation does not fit in `u64` are rejected.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let split = input
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(input.len());
    let (number, unit) = input.split_at(split);
    let multiplier = match unit {
        "ms" => 1_u128,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => return Err(format!("unsupported duration unit `{unit}`")),
    };
    let mut parts = number.split('.');
    let whole = parts
        .next()
        .ok_or_else(|| "missing duration number".to_owned())?;
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|digits| {
            digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("invalid duration decimal syntax".to_owned());
    }
    let whole = whole
        .parse::<u128>()
        .map_err(|_| "duration is too large".to_owned())?;
    let mut millis = whole
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_owned())?;
    if let Some(digits) = fraction {
        let numerator = digits
            .parse::<u128>()
            .map_err(|_| "duration is too large".to_owned())?
            .checked_mul(multiplier)
            .ok_or_else(|| "duration is too large".to_owned())?;
        let denominator = 10_u128
            .checked_pow(
                digits
                    .len()
                    .try_into()
                    .map_err(|_| "duration is too large".to_owned())?,
            )
            .ok_or_else(|| "duration is too large".to_owned())?;
        millis = millis
            .checked_add(
                numerator
                    .checked_add(denominator - 1)
                    .ok_or_else(|| "duration is too large".to_owned())?
                    / denominator,
            )
            .ok_or_else(|| "duration is too large".to_owned())?;
    }
    Ok(Duration::from_millis(
        millis
            .try_into()
            .map_err(|_| "duration is too large".to_owned())?,
    ))
}

/// An explicit absolute path to an installed `memcordon` CLI executable.
///
/// Linux and macOS library execution use this binary for private helper processes.
/// The path is passed directly to the operating system and is never interpreted by a shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemcordonExecutable(PathBuf);

impl MemcordonExecutable {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, ExecutablePathError> {
        let path = path.into();
        if path.is_absolute() {
            Ok(Self(path))
        } else {
            Err(ExecutablePathError { path })
        }
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutablePathError {
    path: PathBuf,
}

impl fmt::Display for ExecutablePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MemCordon executable path must be absolute: {}",
            self.path.display()
        )
    }
}

impl std::error::Error for ExecutablePathError {}

pub struct Limiter {
    policy: Policy,
    command: Option<CommandSpec>,
    memcordon_executable: Option<MemcordonExecutable>,
}

pub struct Supervisor {
    policy: Policy,
    restart: RestartPolicy,
    command: Option<CommandSpec>,
    memcordon_executable: Option<MemcordonExecutable>,
}

impl Supervisor {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            restart: RestartPolicy::Never,
            command: None,
            memcordon_executable: None,
        }
    }
    pub fn restart(mut self) -> Self {
        self.restart = RestartPolicy::OnLimits(default_restart_settings(RestartConditions::BOTH));
        self
    }
    pub fn restart_on(mut self, conditions: RestartConditions) -> Self {
        self.restart = RestartPolicy::OnLimits(default_restart_settings(conditions));
        self
    }
    pub fn restart_limit(mut self, limit: RestartLimit) -> Self {
        if let RestartPolicy::OnLimits(settings) = &mut self.restart {
            *settings = rebuild_settings(settings, Some(limit), None, None);
        } else {
            let mut settings = default_restart_settings(RestartConditions::BOTH);
            settings = rebuild_settings(&settings, Some(limit), None, None);
            self.restart = RestartPolicy::OnLimits(settings);
        }
        self
    }
    pub fn half_life_logistic_backoff(mut self, backoff: HalfLifeLogisticBackoffPolicy) -> Self {
        if let RestartPolicy::OnLimits(settings) = &mut self.restart {
            *settings = rebuild_settings(settings, None, Some(backoff), None);
        } else {
            let mut settings = default_restart_settings(RestartConditions::BOTH);
            settings = rebuild_settings(&settings, None, Some(backoff), None);
            self.restart = RestartPolicy::OnLimits(settings);
        }
        self
    }
    pub fn circuit_breaker(mut self, circuit: CircuitBreakerPolicy) -> Self {
        if let RestartPolicy::OnLimits(settings) = &mut self.restart {
            *settings = rebuild_settings(settings, None, None, Some(Some(circuit)));
        } else {
            let mut settings = default_restart_settings(RestartConditions::BOTH);
            settings = rebuild_settings(&settings, None, None, Some(Some(circuit)));
            self.restart = RestartPolicy::OnLimits(settings);
        }
        self
    }
    pub fn command(mut self, command: CommandSpec) -> Self {
        self.command = Some(command);
        self
    }
    pub fn memcordon_executable(mut self, executable: MemcordonExecutable) -> Self {
        self.memcordon_executable = Some(executable);
        self
    }

    #[allow(clippy::result_large_err)]
    pub fn run(self) -> Result<SupervisionExecution, Error> {
        let command = self.command.ok_or_else(|| {
            Error::new(
                memcordon_core::ErrorCategory::Usage,
                "MCUSAGE-COMMAND",
                "no command was configured",
            )
        })?;
        let helper = self.memcordon_executable.map(|value| value.0);
        let restart = resolve_restart_policy(&self.policy, self.restart)?;
        let boundary = self.policy.boundary();
        let probe = memcordon_platform::probe();
        let resolved_backend = probe
            .selected_for(boundary)
            .map(|backend| memcordon_platform::capabilities_for(backend, boundary));
        memcordon_platform::supervise(memcordon_platform::SupervisorRequest {
            policy: self.policy,
            restart,
            command,
            memcordon_executable: helper,
            resolved_backend,
        })
    }
}

#[doc(hidden)]
#[allow(clippy::result_large_err)]
pub fn resolve_restart_policy(
    policy: &Policy,
    restart: RestartPolicy,
) -> Result<RestartPolicy, Error> {
    let RestartPolicy::OnLimits(settings) = restart else {
        return Ok(RestartPolicy::Never);
    };
    let configured = settings.configured_conditions();
    let memory = policy.memory.is_some()
        && configured.contains(memcordon_core::RestartCondition::MemoryLimit);
    let deadline = policy
        .deadline
        .is_some_and(|value| value.scope() == memcordon_core::DeadlineScope::Attempt)
        && configured.contains(memcordon_core::RestartCondition::Deadline);
    let effective = match (memory, deadline) {
        (true, true) => RestartConditions::BOTH,
        (true, false) => RestartConditions::MEMORY_LIMIT,
        (false, true) => RestartConditions::DEADLINE,
        (false, false) => RestartConditions::NONE,
    };
    if effective.is_empty() {
        return Err(Error::new(
            memcordon_core::ErrorCategory::Usage,
            "MCUSAGE-RESTART-NO-EFFECTIVE-CONDITION",
            "restart requires an effective memory-limit or attempt-deadline condition",
        ));
    }
    let mut dormant = Vec::new();
    for condition in [
        memcordon_core::RestartCondition::MemoryLimit,
        memcordon_core::RestartCondition::Deadline,
    ] {
        if configured.contains(condition) && !effective.contains(condition) {
            dormant.push(memcordon_core::DormantRestartCondition {
                condition,
                reason: match condition {
                    memcordon_core::RestartCondition::MemoryLimit => {
                        "no memory budget was configured".to_owned()
                    }
                    memcordon_core::RestartCondition::Deadline => {
                        "no attempt-scoped deadline was configured".to_owned()
                    }
                },
            });
        }
    }
    RestartSettings::new(
        configured,
        effective,
        dormant,
        settings.limit(),
        settings.backoff(),
        settings.circuit_breaker(),
    )
    .map(RestartPolicy::OnLimits)
    .map_err(|error| {
        Error::new(
            memcordon_core::ErrorCategory::Usage,
            "MCUSAGE-RESTART",
            error.to_string(),
        )
    })
}

fn default_restart_settings(conditions: RestartConditions) -> RestartSettings {
    RestartSettings::new(
        conditions,
        conditions,
        Vec::new(),
        RestartLimit::Unlimited,
        HalfLifeLogisticBackoffPolicy::default(),
        None,
    )
    .unwrap_or_else(|error| panic!("invalid built-in restart defaults: {error}"))
}

fn rebuild_settings(
    settings: &RestartSettings,
    limit: Option<RestartLimit>,
    backoff: Option<HalfLifeLogisticBackoffPolicy>,
    circuit: Option<Option<CircuitBreakerPolicy>>,
) -> RestartSettings {
    RestartSettings::new(
        settings.configured_conditions(),
        settings.effective_conditions(),
        settings.dormant_conditions().to_vec(),
        limit.unwrap_or(settings.limit()),
        backoff.unwrap_or(settings.backoff()),
        circuit.unwrap_or(settings.circuit_breaker()),
    )
    .unwrap_or_else(|error| panic!("invalid supervisor policy: {error}"))
}

impl Limiter {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            command: None,
            memcordon_executable: None,
        }
    }

    pub fn memcordon_executable(mut self, executable: MemcordonExecutable) -> Self {
        self.memcordon_executable = Some(executable);
        self
    }

    pub fn command(mut self, command: CommandSpec) -> Self {
        self.command = Some(command);
        self
    }

    #[allow(
        clippy::result_large_err,
        reason = "the facade preserves the public categorized Error contract used by the CLI"
    )]
    pub fn run(self) -> Result<RunOutcome, Error> {
        let command = self.command.ok_or_else(|| {
            Error::new(
                memcordon_core::ErrorCategory::Usage,
                "MCUSAGE-COMMAND",
                "no command was configured",
            )
        })?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let executable = self.memcordon_executable.ok_or_else(|| {
                Error::new(
                    memcordon_core::ErrorCategory::Usage,
                    "MCUSAGE-MEMCORDON-EXECUTABLE",
                    "Unix helper execution requires an explicit absolute path to an installed memcordon CLI",
                )
            })?;
            memcordon_platform::run(self.policy, &command, executable.as_path())
                .map(|execution| execution.outcome)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = self.memcordon_executable;
            memcordon_platform::run(self.policy, &command).map(|execution| execution.outcome)
        }
    }
}
