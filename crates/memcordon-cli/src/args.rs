use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use memcordon_core::{ByteSize, SwapPolicy};

#[derive(Debug, Parser)]
#[command(
    name = "memcordon",
    version,
    about = "Limit a workload using the strongest available platform backend"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Run(RunArgs),
    Probe {
        #[arg(long)]
        json: bool,
    },
    Explain(ExplainArgs),
    Cleanup {
        #[arg(long)]
        dry_run: bool,
    },
    Version {
        #[arg(long)]
        verbose: bool,
    },
    Compat(CompatArgs),
    #[command(name = "__launcher", hide = true)]
    Launcher {
        control_fd: i32,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    #[command(name = "__guardian", hide = true)]
    Guardian {
        control_fd: i32,
        process_group: i32,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum EnforcementArg {
    Auto,
    Hard,
    Watchdog,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LifetimeArg {
    Command,
    Workload,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum MetricArg {
    Native,
    PhysicalFootprint,
    Rss,
    Virtual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ReportArg {
    None,
    Text,
    Json,
}

#[derive(Clone, Copy, Debug)]
pub struct SwapArg(pub SwapPolicy);

impl std::str::FromStr for SwapArg {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "0" | "0B" => Ok(Self(SwapPolicy::Bytes(ByteSize::from_bytes(0)))),
            "unlimited" => Ok(Self(SwapPolicy::Unlimited)),
            "host" => Ok(Self(SwapPolicy::Host)),
            value => value
                .parse::<ByteSize>()
                .map(|bytes| Self(SwapPolicy::Bytes(bytes)))
                .map_err(|error| error.to_string()),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct RunArgs {
    #[arg(long)]
    pub memory: ByteSize,
    #[arg(long, value_enum, default_value = "auto")]
    pub enforcement: EnforcementArg,
    #[arg(long, value_enum, default_value = "command")]
    pub lifetime: LifetimeArg,
    #[arg(long, value_enum, default_value = "native")]
    pub metric: MetricArg,
    #[arg(long, value_parser = parse_duration, default_value = "50ms")]
    pub poll_interval: Duration,
    #[arg(long, value_parser = parse_duration, default_value = "2s")]
    pub signal_grace: Duration,
    #[arg(long, value_parser = parse_duration, default_value = "0s")]
    pub limit_grace: Duration,
    #[arg(long, default_value = "0B")]
    pub swap: SwapArg,
    #[arg(long, value_enum, default_value = "none")]
    pub report: ReportArg,
    #[arg(long, requires = "report")]
    pub report_file: Option<PathBuf>,
    #[arg(long)]
    pub quiet: bool,
    #[arg(long)]
    pub no_backend_warning: bool,
    #[arg(last = true, required = true)]
    pub command: Vec<OsString>,
}

#[derive(Clone, Debug, Args)]
pub struct ExplainArgs {
    #[arg(long, value_enum, default_value = "auto")]
    pub enforcement: EnforcementArg,
    #[arg(long)]
    pub memory: Option<ByteSize>,
}

#[derive(Clone, Debug, Args)]
pub struct CompatArgs {
    #[arg(long)]
    pub children: bool,
    #[arg(long = "virtual")]
    pub virtual_memory: bool,
    pub amount: ByteSize,
    #[arg(required = true)]
    pub command: Vec<OsString>,
}

fn parse_duration(input: &str) -> Result<Duration, String> {
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
