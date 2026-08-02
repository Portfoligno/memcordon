#![forbid(unsafe_code)]

use std::time::Duration;

pub use memcordon_core::{
    ByteSize, ChildTermination, CleanupSummary, CommandSpec, Enforcement, Error, Lifetime, Metric,
    Policy, RunOutcome,
};
pub use memcordon_platform::{BackendInfo, ProbeReport, probe};

pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let split = input
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(input.len());
    let (number, unit) = input.split_at(split);
    let multiplier = match unit {
        "ms" => 1_u128,
        "s" => 1_000,
        "m" => 60_000,
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

pub struct Limiter {
    policy: Policy,
    command: Option<CommandSpec>,
}

impl Limiter {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            command: None,
        }
    }

    pub fn command(mut self, command: CommandSpec) -> Self {
        self.command = Some(command);
        self
    }

    pub fn run(self) -> Result<RunOutcome, Error> {
        let command = self.command.ok_or_else(|| {
            Error::new(
                memcordon_core::ErrorCategory::Usage,
                "MCUSAGE-COMMAND",
                "no command was configured",
            )
        })?;
        memcordon_platform::run(self.policy, &command).map(|execution| execution.outcome)
    }
}
