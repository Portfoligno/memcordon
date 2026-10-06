#![forbid(unsafe_code)]

mod suites;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use memcordon_ci::{CiError, Result, command, config, native_acceptance_catalogue, policy};
pub use memcordon_ci::{bootstrap_profile, performance_plan, preparation};

#[derive(Parser)]
#[command(name = "memcordon-ci", about = "Typed MemCordon product CI runner")]
struct Cli {
    #[command(subcommand)]
    command: Option<TopLevel>,
}

#[derive(Subcommand)]
enum TopLevel {
    Ci {
        #[command(subcommand)]
        command: CiCommand,
    },
    Release {
        #[command(subcommand)]
        command: memcordon_ci::release::ReleaseCommand,
    },
    ExternalConsumer {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    #[command(hide = true)]
    DelegatedLinuxBackend {
        #[arg(long)]
        rustup: PathBuf,
        #[arg(long)]
        uid: String,
    },
    Suite {
        #[arg(value_enum)]
        suite: Suite,
    },
}

#[derive(Subcommand)]
enum CiCommand {
    Prepare {
        #[arg(long, value_enum)]
        profile: memcordon_ci::bootstrap_profile::BootstrapProfile,
    },
    CacheContext {
        #[arg(long, default_value = "native")]
        purpose: String,
        #[arg(long, default_value = "complete")]
        shard: String,
        #[arg(long)]
        external: Vec<PathBuf>,
    },
    CheckWorkflows,
    PerformancePlan,
    WorkflowScope,
    AggregateStress {
        #[arg(long, default_value = "target/ci/stress-artifacts")]
        input: PathBuf,
        #[arg(long, default_value = "target/ci/reports/stress-assessment.json")]
        destination: PathBuf,
    },
    AggregateMacos {
        #[arg(long, default_value = "target/ci/macos-artifacts")]
        input: PathBuf,
        #[arg(long, default_value = "target/ci/reports/macos-assessment.json")]
        destination: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Suite {
    Policy,
    Quality,
    Msrv,
    Native,
    SupplyChain,
    Miri,
    MiriFirst,
    MiriSecond,
    Fuzz,
    FuzzFirst,
    FuzzSecond,
    FuzzQuarterOne,
    FuzzQuarterTwo,
    FuzzQuarterThree,
    FuzzQuarterFour,
    Stress,
    StressPackages,
    StressLifecycle,
    BackendLinuxCgroup,
    BackendLinuxPrivate,
    BackendWindowsJob,
    BackendWindowsSealed,
    BackendMacosWatchdog,
    ReleaseMacosNative,
    ReleaseMacosAcceptance,
    MacosDeadline,
}

fn workspace_root(start: &Path) -> Result<PathBuf> {
    let mut current = Some(start);
    while let Some(path) = current {
        if path.join("Cargo.toml").is_file() && path.join("ci").is_dir() {
            return Ok(path.to_path_buf());
        }
        current = path.parent();
    }
    Err(CiError::Message(
        "could not locate the MemCordon workspace".to_owned(),
    ))
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let current = std::env::current_dir()?;
    let root = match &cli.command {
        Some(TopLevel::ExternalConsumer { .. }) => current,
        Some(TopLevel::Release {
            command:
                memcordon_ci::release::ReleaseCommand::Publish { .. }
                | memcordon_ci::release::ReleaseCommand::Inspect { .. }
                | memcordon_ci::release::ReleaseCommand::PublicConsumer { .. }
                | memcordon_ci::release::ReleaseCommand::RehearsalTransaction { .. },
        }) => current,
        _ => workspace_root(&current)?,
    };
    let result = match cli.command {
        Some(TopLevel::Ci { command }) => match command {
            CiCommand::Prepare { profile } => memcordon_ci::preparation::prepare(&root, profile),
            CiCommand::CacheContext {
                purpose,
                shard,
                external,
            } => memcordon_ci::cache::emit(&root, &purpose, &shard, &external),
            CiCommand::CheckWorkflows => policy::run(&root),
            CiCommand::WorkflowScope => memcordon_ci::workflow_scope::emit_from_github(),
            CiCommand::PerformancePlan => {
                memcordon_ci::performance_plan::PerformancePlan::read(&root)?.emit()
            }
            CiCommand::AggregateStress { input, destination } => {
                memcordon_ci::performance_plan::aggregate_stress(&root, &input, &destination)
            }
            CiCommand::AggregateMacos { input, destination } => {
                memcordon_ci::macos_performance::aggregate(&root, &input, &destination)
            }
        },
        Some(TopLevel::Release { command }) => memcordon_ci::release::run(&root, command),
        Some(TopLevel::ExternalConsumer { input, destination }) => {
            let assessment = memcordon_ci::external_consumer::run_file(&input, &destination)?;
            if assessment.passed() {
                Ok(())
            } else {
                Err(CiError::Message(
                    "external consumer execution, collection or retirement assessment failed"
                        .into(),
                ))
            }
        }
        Some(TopLevel::DelegatedLinuxBackend { rustup, uid }) => {
            suites::delegated_linux_backend(&root, &rustup, &uid)
        }
        Some(TopLevel::Suite { suite }) => suites::run(&root, suite, suites::SuiteOptions),
        None => Err(CiError::Message(
            "exactly one CI command is required".to_owned(),
        )),
    };
    memcordon_ci::workflow_output::quiescent(result)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("memcordon-ci: {error}");
        let mut source = std::error::Error::source(&error);
        while let Some(error) = source {
            eprintln!("  caused by: {error}");
            source = error.source();
        }
        std::process::exit(1);
    }
}
