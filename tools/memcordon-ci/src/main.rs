#![forbid(unsafe_code)]

mod release;
mod sealed_linux;
mod suites;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use memcordon_ci::{CiError, Result, command, config, policy};

#[derive(Parser)]
#[command(
    name = "memcordon-ci",
    about = "Typed MemCordon CI and release orchestrator"
)]
struct Cli {
    #[arg(long, hide = true)]
    cargo_plugin: bool,
    #[command(subcommand)]
    command: Option<TopLevel>,
}

#[derive(Subcommand)]
enum TopLevel {
    Suite {
        #[arg(value_enum)]
        suite: Suite,
    },
    Release {
        #[arg(value_enum)]
        phase: ReleasePhase,
    },
    #[command(hide = true)]
    DelegatedLinuxCertification {
        #[arg(long)]
        rustup: PathBuf,
        #[arg(long)]
        uid: String,
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
    Fuzz,
    Stress,
    BackendLinuxCgroup,
    BackendLinuxSealedV2,
    BackendWindowsJob,
    BackendMacosWatchdog,
    ReleasePreflight,
    ReleaseNative,
    ReleaseMacos,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReleasePhase {
    Assemble,
    StageGithub,
    PublishNext,
    VerifyCrates,
    FinalizeGithub,
    VerifyPublic,
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
    let root = workspace_root(&std::env::current_dir()?)?;
    match (cli.cargo_plugin, cli.command) {
        (true, None) => release::cargo_credential_provider(&root),
        (false, Some(TopLevel::Suite { suite })) => suites::run(&root, suite),
        (false, Some(TopLevel::Release { phase })) => release::run(&root, phase),
        (false, Some(TopLevel::DelegatedLinuxCertification { rustup, uid })) => {
            suites::delegated_linux_certification(&root, &rustup, &uid)
        }
        _ => Err(CiError::Message(
            "exactly one CI command or --cargo-plugin is required".to_owned(),
        )),
    }
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
