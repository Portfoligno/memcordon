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
    pub memory: Option<ByteSize>,
    pub deadline: Option<DeadlinePolicy>,
    pub enforcement: Enforcement,
    pub lifetime: Lifetime,
    pub metric: Metric,
    pub poll_interval: Duration,
    pub signal_grace: Duration,
    pub limit_grace: Duration,
    pub swap: SwapPolicy,
}

impl Policy {
    pub fn new(memory: ByteSize) -> Self {
        Self {
            memory: Some(memory),
            deadline: None,
            enforcement: Enforcement::Auto,
            lifetime: Lifetime::Command,
            metric: Metric::Native,
            poll_interval: Duration::from_millis(50),
            signal_grace: Duration::from_secs(2),
            limit_grace: Duration::ZERO,
            swap: SwapPolicy::Bytes(ByteSize::from_bytes(0)),
        }
    }

    pub fn unbounded() -> Self {
        Self {
            memory: None,
            deadline: None,
            enforcement: Enforcement::Auto,
            lifetime: Lifetime::Command,
            metric: Metric::Native,
            poll_interval: Duration::from_millis(50),
            signal_grace: Duration::from_secs(2),
            limit_grace: Duration::ZERO,
            swap: SwapPolicy::Bytes(ByteSize::from_bytes(0)),
        }
    }

    pub fn with_deadline(mut self, duration: Duration) -> Result<Self, DeadlinePolicyError> {
        self.deadline = Some(DeadlinePolicy::new(duration, DeadlineScope::Attempt)?);
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlinePolicy {
    duration: Duration,
    scope: DeadlineScope,
}

impl DeadlinePolicy {
    pub fn new(duration: Duration, scope: DeadlineScope) -> Result<Self, DeadlinePolicyError> {
        let milliseconds = duration.as_millis();
        if milliseconds == 0 || u64::try_from(milliseconds).is_err() {
            return Err(DeadlinePolicyError);
        }
        Ok(Self { duration, scope })
    }

    pub const fn duration(self) -> Duration {
        self.duration
    }

    pub const fn scope(self) -> DeadlineScope {
        self.scope
    }
}

impl Serialize for DeadlinePolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DeadlinePolicy", 2)?;
        state.serialize_field(
            "duration_ms",
            &u64::try_from(self.duration.as_millis()).map_err(serde::ser::Error::custom)?,
        )?;
        state.serialize_field("scope", &self.scope)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DeadlinePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            duration_ms: u64,
            scope: DeadlineScope,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(Duration::from_millis(wire.duration_ms), wire.scope)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("deadline must be positive and representable as u64 milliseconds")]
pub struct DeadlinePolicyError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeadlineScope {
    Attempt,
    Supervision,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new(ByteSize::gib(1))
    }
}
