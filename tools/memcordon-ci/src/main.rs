#![forbid(unsafe_code)]

mod release;
mod sealed_linux;
mod sealed_windows;
mod suites;

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use memcordon_ci::{CiError, Result, command, config, policy};

#[derive(Parser)]
#[command(
    name = "memcordon-ci",
    about = "Typed MemCordon CI and release orchestrator"
)]
struct Cli {
    /// Cargo's credential-provider protocol mode marker.
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
        #[command(subcommand)]
        command: ReleaseCommand,
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
    BackendWindowsSealedV2,
    WindowsLoaderProduction,
    WindowsProviderLifecycle,
    WindowsPackageChannel,
    WindowsLoaderLab,
    PackageWindowsSealed,
    ChannelParityWindowsSealed,
    BackendMacosWatchdog,
    ReleasePreflight,
    ReleaseNative,
    ReleaseMacos,
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    Assemble,
    StageGithub,
    AttemptOidc {
        #[arg(long)]
        publication_slot: NonZeroUsize,
    },
    AuthorizeNewCrateFallback {
        #[arg(long)]
        publication_slot: NonZeroUsize,
    },
    PublishTokenFallback {
        #[arg(long)]
        publication_slot: NonZeroUsize,
    },
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
        (false, Some(TopLevel::Release { command })) => release::run(&root, command),
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
