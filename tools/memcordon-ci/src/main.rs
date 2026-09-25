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
    /// Previously measured immutable compilation context; never supplied by env.
    #[arg(long)]
    build_context: Option<PathBuf>,
    /// Cargo's credential-provider protocol mode marker.
    #[arg(long, hide = true)]
    cargo_plugin: bool,
    #[command(subcommand)]
    command: Option<TopLevel>,
}

#[derive(Subcommand)]
enum TopLevel {
    InventoryProfile {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    InventoryScan {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        report_dir: PathBuf,
    },
    InventoryBenchmark {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    QualifyNativeProfile {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        selection: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    AuditNativeProfile {
        #[arg(long)]
        specification: PathBuf,
    },
    BuildContext {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        observation_dir: Option<PathBuf>,
    },
    AuditBuildContext {
        #[arg(long)]
        input: PathBuf,
    },
    Suite {
        #[arg(value_enum)]
        suite: Suite,
        #[arg(long, value_enum)]
        stage: Option<PrivateStage>,
        #[arg(long)]
        target: Option<String>,
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
        #[arg(long)]
        context_file: PathBuf,
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
    FuzzFirst,
    FuzzSecond,
    Stress,
    BackendLinuxCgroup,
    BackendLinuxSealedV2,
    BackendLinuxPrivateV4,
    BackendWindowsJob,
    BackendWindowsSealedV2,
    WindowsLoaderProduction,
    WindowsProviderLifecycle,
    WindowsPackageChannel,
    WindowsLoaderLab,
    PackageWindowsSealed,
    ChannelParityWindowsSealed,
    BackendMacosWatchdog,
    MacosDeadline,
    ReleasePreflight,
    ReleaseNative,
    ReleaseMacos,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PrivateStage {
    CandidateCapability,
    FinalPublic,
}

impl From<PrivateStage> for memcordon_ci::private_native::NativeRunStageV2 {
    fn from(stage: PrivateStage) -> Self {
        match stage {
            PrivateStage::CandidateCapability => Self::CandidateCapability,
            PrivateStage::FinalPublic => Self::FinalPublic,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    Assemble,
    VerifyPrivateCandidate,
    InstallPrivateCandidate,
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
    RehearsePublic {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        report: PathBuf,
    },
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
    if let Some(path) = cli.build_context {
        memcordon_ci::inventory_benchmark::require_admission(&path)?;
        memcordon_ci::build_context::activate(
            memcordon_ci::build_context::ValidatedBuildContext::read(&path)?,
        )?;
    }
    let result = match (cli.cargo_plugin, cli.command) {
        (false, Some(TopLevel::InventoryProfile { plan, output })) => {
            memcordon_ci::inventory_profile::profile(&plan, &output, &root)
        }
        (
            false,
            Some(TopLevel::InventoryScan {
                request,
                report_dir,
            }),
        ) => memcordon_ci::inventory_benchmark::scan(&request, &report_dir),
        (false, Some(TopLevel::InventoryBenchmark { plan, output })) => {
            memcordon_ci::inventory_benchmark::benchmark(&plan, &output)
        }
        (
            false,
            Some(TopLevel::QualifyNativeProfile {
                policy,
                selection,
                destination,
            }),
        ) => memcordon_ci::native_profile::qualify(&policy, &selection, &destination),
        (false, Some(TopLevel::AuditNativeProfile { specification })) => {
            memcordon_ci::native_profile::audit(&specification)
        }
        (
            false,
            Some(TopLevel::BuildContext {
                output,
                observation_dir,
            }),
        ) => {
            memcordon_ci::inventory_progress::set_report_directory(observation_dir)?;
            memcordon_ci::build_context::ValidatedBuildContext::prepare(&root)?.write(&output)
        }
        (false, Some(TopLevel::AuditBuildContext { input })) => {
            memcordon_ci::inventory_benchmark::require_admission(&input)?;
            memcordon_ci::build_context::ValidatedBuildContext::read(&input)?.audit()
        }
        (true, None) => release::cargo_credential_provider(&root),
        (
            false,
            Some(TopLevel::Suite {
                suite,
                stage,
                target,
            }),
        ) => suites::run(&root, suite, stage, target.as_deref()),
        (false, Some(TopLevel::Release { command })) => release::run(&root, command),
        (
            false,
            Some(TopLevel::DelegatedLinuxCertification {
                rustup,
                uid,
                context_file,
            }),
        ) => suites::delegated_linux_certification(&root, &rustup, &uid, &context_file),
        _ => Err(CiError::Message(
            "exactly one CI command or --cargo-plugin is required".to_owned(),
        )),
    };
    if let Some(context) = memcordon_ci::build_context::active() {
        context.audit()?;
    }
    result
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
