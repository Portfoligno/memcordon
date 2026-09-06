#![forbid(unsafe_code)]

mod release;
mod sealed_linux;
mod sealed_windows;
mod suites;

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use memcordon_ci::{CiError, Result, command, config, policy};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProviderOrigin {
    Oidc,
    NewCrateToken,
}

impl ProviderOrigin {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "oidc" => Some(Self::Oidc),
            "new-crate-token" => Some(Self::NewCrateToken),
            _ => None,
        }
    }

    fn release_origin(self) -> release::CredentialOrigin {
        match self {
            Self::Oidc => release::CredentialOrigin::Oidc,
            Self::NewCrateToken => release::CredentialOrigin::NewCrateToken,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "memcordon-ci",
    about = "Typed MemCordon CI and release orchestrator"
)]
struct Cli {
    #[arg(
        long,
        hide = true,
        num_args = 5,
        value_names = ["ORIGIN", "PUBLICATION_SLOT", "CRATE", "VERSION", "ARCHIVE_SHA256"]
    )]
    cargo_plugin: Option<Vec<String>>,
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
        (Some(binding), None) => {
            let [origin, publication_slot, name, version, archive_sha256] = binding.as_slice()
            else {
                return Err(CiError::Message(
                    "Cargo credential provider requires exactly five identity values".to_owned(),
                ));
            };
            let origin = ProviderOrigin::parse(origin).ok_or_else(|| {
                CiError::Message(format!("unknown credential-provider origin: {origin}"))
            })?;
            let publication_slot = publication_slot
                .parse::<NonZeroUsize>()
                .map_err(|error| CiError::Message(format!("invalid publication slot: {error}")))?;
            release::cargo_credential_provider(
                &root,
                origin.release_origin(),
                publication_slot,
                name,
                version,
                archive_sha256,
            )
        }
        (None, Some(TopLevel::Suite { suite })) => suites::run(&root, suite),
        (None, Some(TopLevel::Release { command })) => release::run(&root, command),
        (None, Some(TopLevel::DelegatedLinuxCertification { rustup, uid })) => {
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
