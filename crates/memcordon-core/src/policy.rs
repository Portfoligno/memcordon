use std::ffi::{OsStr, OsString};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ByteSize(u64);

impl ByteSize {
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    pub const fn bytes(self) -> u64 {
        self.0
    }

    pub const fn gib(value: u64) -> Self {
        Self(value.saturating_mul(1024 * 1024 * 1024))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}B", self.0)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ByteSizeParseError {
    #[error("memory size must include a number")]
    MissingNumber,
    #[error("memory size must be greater than zero")]
    Zero,
    #[error("ambiguous or unsupported memory unit `{0}`")]
    InvalidUnit(String),
    #[error("memory size has invalid decimal syntax")]
    InvalidDecimal,
    #[error("memory size exceeds the supported u64 byte range")]
    Overflow,
}

impl FromStr for ByteSize {
    type Err = ByteSizeParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let split = input
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(input.len());
        let (number, unit) = input.split_at(split);
        if number.is_empty() {
            return Err(ByteSizeParseError::MissingNumber);
        }
        let multiplier = match unit {
            "" | "B" => 1_u128,
            "KB" => 1_000,
            "MB" => 1_000_000,
            "GB" => 1_000_000_000,
            "TB" => 1_000_000_000_000,
            "PB" => 1_000_000_000_000_000,
            "EB" => 1_000_000_000_000_000_000,
            "KiB" => 1_u128 << 10,
            "MiB" => 1_u128 << 20,
            "GiB" => 1_u128 << 30,
            "TiB" => 1_u128 << 40,
            "PiB" => 1_u128 << 50,
            "EiB" => 1_u128 << 60,
            other => return Err(ByteSizeParseError::InvalidUnit(other.to_owned())),
        };

        let mut parts = number.split('.');
        let whole = parts.next().ok_or(ByteSizeParseError::InvalidDecimal)?;
        let fraction = parts.next();
        if parts.next().is_some()
            || whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.is_some_and(|digits| {
                digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(ByteSizeParseError::InvalidDecimal);
        }

        let whole = whole
            .parse::<u128>()
            .map_err(|_| ByteSizeParseError::Overflow)?;
        let scaled_whole = whole
            .checked_mul(multiplier)
            .ok_or(ByteSizeParseError::Overflow)?;
        let bytes = if let Some(digits) = fraction {
            let numerator = digits
                .parse::<u128>()
                .map_err(|_| ByteSizeParseError::Overflow)?
                .checked_mul(multiplier)
                .ok_or(ByteSizeParseError::Overflow)?;
            let denominator = 10_u128
                .checked_pow(
                    digits
                        .len()
                        .try_into()
                        .map_err(|_| ByteSizeParseError::Overflow)?,
                )
                .ok_or(ByteSizeParseError::Overflow)?;
            let rounded_fraction = numerator
                .checked_add(denominator - 1)
                .ok_or(ByteSizeParseError::Overflow)?
                / denominator;
            scaled_whole
                .checked_add(rounded_fraction)
                .ok_or(ByteSizeParseError::Overflow)?
        } else {
            scaled_whole
        };
        if bytes == 0 {
            return Err(ByteSizeParseError::Zero);
        }
        Ok(Self(
            bytes.try_into().map_err(|_| ByteSizeParseError::Overflow)?,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Enforcement {
    Auto,
    Hard,
    Watchdog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifetime {
    Command,
    Workload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Metric {
    Native,
    PhysicalFootprint,
    Rss,
    Virtual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportMode {
    None,
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SwapPolicy {
    Bytes(ByteSize),
    Unlimited,
    Host,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    program: OsString,
    args: Vec<OsString>,
}

impl CommandSpec {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn program(&self) -> &OsStr {
        &self.program
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub memory: ByteSize,
    pub enforcement: Enforcement,
    pub lifetime: Lifetime,
    pub metric: Metric,
    pub poll_interval: Duration,
    pub signal_grace: Duration,
    pub limit_grace: Duration,
    pub swap: SwapPolicy,
    pub report: ReportMode,
    pub quiet: bool,
    pub backend_warning: bool,
}

impl Policy {
    pub fn new(memory: ByteSize) -> Self {
        Self {
            memory,
            enforcement: Enforcement::Auto,
            lifetime: Lifetime::Command,
            metric: Metric::Native,
            poll_interval: Duration::from_millis(50),
            signal_grace: Duration::from_secs(2),
            limit_grace: Duration::ZERO,
            swap: SwapPolicy::Bytes(ByteSize::from_bytes(0)),
            report: ReportMode::None,
            quiet: false,
            backend_warning: true,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new(ByteSize::gib(1))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedPolicy {
    pub memory: ByteSize,
    pub requested_enforcement: Enforcement,
    pub effective_enforcement: Enforcement,
    pub lifetime: Lifetime,
    pub metric: Metric,
    #[serde(with = "duration_millis")]
    pub poll_interval: Duration,
    #[serde(with = "duration_millis")]
    pub signal_grace: Duration,
    #[serde(with = "duration_millis")]
    pub limit_grace: Duration,
    pub swap: SwapPolicy,
    pub report: ReportMode,
}

mod duration_millis {
    use std::time::Duration;

    use serde::Serializer;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis().try_into().unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteSize, ByteSizeParseError};

    #[test]
    fn parses_exact_binary_and_decimal_units() {
        assert_eq!(
            "1.5GiB".parse::<ByteSize>().map(ByteSize::bytes),
            Ok(1_610_612_736)
        );
        assert_eq!("1.1B".parse::<ByteSize>().map(ByteSize::bytes), Ok(2));
        assert_eq!(
            "8000MB".parse::<ByteSize>().map(ByteSize::bytes),
            Ok(8_000_000_000)
        );
    }

    #[test]
    fn rejects_ambiguous_zero_and_overflow() {
        assert!(matches!(
            "8G".parse::<ByteSize>(),
            Err(ByteSizeParseError::InvalidUnit(_))
        ));
        assert_eq!("0".parse::<ByteSize>(), Err(ByteSizeParseError::Zero));
        assert_eq!(
            "999999999999999999999999EB".parse::<ByteSize>(),
            Err(ByteSizeParseError::Overflow)
        );
    }
}
