#![forbid(unsafe_code)]

mod suites;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use memcordon_ci::{CiError, Result, command, config, native_acceptance_catalogue, policy};
pub use memcordon_ci::{bootstrap_profile, failure_mode, performance_plan, preparation};

#[derive(Parser)]
#[command(name = "memcordon-ci", about = "Typed MemCordon product CI runner")]
struct Cli {
    #[command(subcommand)]
    command: Option<TopLevel>,
}

#[derive(Subcommand)]
enum TopLevel {
    #[cfg(target_os = "windows")]
    ConsumerReadinessLoaderDiagnostic(
        memcordon_ci::release::original_native_components::loader_diagnostic::Args,
    ),
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    ConsumerReadinessNativeComponents(memcordon_ci::release::original_native_components::Args),
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    ConsumerReadinessMalformedIngress(
        memcordon_ci::release::linux_malformed_ingress::MalformedIngressArguments,
    ),
    ConsumerReadinessCell(memcordon_ci::release::consumer_readiness_cell::CellArguments),
    ConsumerReadinessCleanup(memcordon_ci::release::consumer_readiness_cell::CellArguments),
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
        #[arg(long, value_enum, default_value = "stop-after-failure")]
        failure_mode: memcordon_ci::failure_mode::FailureMode,
    },
}

#[derive(Subcommand)]
enum CiCommand {
    DownloadCacheContext {
        #[arg(long, value_enum)]
        family: memcordon_ci::download_cache::DownloadFamily,
    },
    FetchDownloads {
        #[arg(long, value_enum)]
        family: memcordon_ci::download_cache::DownloadFamily,
    },
    Prepare {
        #[arg(long, value_enum)]
        profile: memcordon_ci::bootstrap_profile::BootstrapProfile,
        #[arg(long, value_enum, default_value_t = memcordon_ci::failure_mode::FailureMode::StopAfterFailure)]
        failure_mode: memcordon_ci::failure_mode::FailureMode,
    },
    PrepareMiriComponents,
    MiriCacheContext,
    PrepareMiriSysroot,
    SeedContext {
        #[arg(long, value_enum)]
        kind: memcordon_ci::cache_snapshot::SnapshotKind,
        #[arg(long, default_value = "native-debug")]
        purpose: String,
        #[arg(long, default_value = "complete")]
        shard: String,
        #[arg(long, value_enum)]
        partition: Option<memcordon_ci::cache_restore::CompiledPartition>,
    },
    CacheSnapshot {
        #[arg(long, value_enum)]
        kind: memcordon_ci::cache_snapshot::SnapshotKind,
        #[arg(long, default_value = "native-debug")]
        purpose: String,
        #[arg(long, default_value = "complete")]
        shard: String,
        #[arg(long, value_enum)]
        partition: Option<memcordon_ci::cache_restore::CompiledPartition>,
        #[arg(long, value_parser = ["build"], default_value = "build")]
        stage: String,
    },
    ImportCacheSnapshot {
        #[arg(long, value_enum)]
        kind: memcordon_ci::cache_snapshot::SnapshotKind,
        #[arg(long, default_value = "native-debug")]
        purpose: String,
        #[arg(long, default_value = "complete")]
        shard: String,
        #[arg(long, value_enum)]
        partition: Option<memcordon_ci::cache_restore::CompiledPartition>,
    },
    CleanupCacheSnapshot {
        #[arg(long, value_enum)]
        kind: memcordon_ci::cache_snapshot::SnapshotKind,
        #[arg(long, default_value = "native-debug")]
        purpose: String,
        #[arg(long, default_value = "complete")]
        shard: String,
        #[arg(long, value_enum)]
        partition: Option<memcordon_ci::cache_restore::CompiledPartition>,
    },
    CacheContext {
        #[arg(long, value_enum)]
        partition: Option<memcordon_ci::cache_restore::CompiledPartition>,
        #[arg(long)]
        for_save: bool,
        #[arg(long, default_value = "native")]
        purpose: String,
        #[arg(long, default_value = "complete")]
        shard: String,
        #[arg(long)]
        external: Vec<PathBuf>,
    },
    PrepareRestoredCache {
        #[arg(long, value_enum)]
        partition: Option<memcordon_ci::cache_restore::CompiledPartition>,
        #[arg(long)]
        purpose: String,
        #[arg(long, default_value = "complete")]
        shard: String,
        #[arg(long, value_enum)]
        mode: memcordon_ci::cache_restore::RestoreMode,
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
    QualityCompile,
    Msrv,
    Native,
    NativeCompile,
    NativeExecute,
    SupplyChain,
    Miri,
    MiriFirst,
    MiriSecond,
    MiriQuarterOne,
    MiriQuarterTwo,
    MiriQuarterThree,
    MiriQuarterFour,
    Fuzz,
    FuzzFirst,
    FuzzSecond,
    FuzzQuarterOne,
    FuzzQuarterTwo,
    FuzzQuarterThree,
    FuzzQuarterFour,
    FuzzCompileFirst,
    FuzzCompileSecond,
    FuzzCompileQuarterOne,
    FuzzCompileQuarterTwo,
    FuzzCompileQuarterThree,
    FuzzCompileQuarterFour,
    FuzzExecuteFirst,
    FuzzExecuteSecond,
    FuzzExecuteQuarterOne,
    FuzzExecuteQuarterTwo,
    FuzzExecuteQuarterThree,
    FuzzExecuteQuarterFour,
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
        #[cfg(target_os = "windows")]
        Some(TopLevel::ConsumerReadinessLoaderDiagnostic(arguments)) => {
            memcordon_ci::release::original_native_components::loader_diagnostic::run(
                &root, &arguments,
            )
        }
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        Some(TopLevel::ConsumerReadinessNativeComponents(arguments)) => {
            memcordon_ci::release::original_native_components::run(&root, &arguments)
        }
        Some(TopLevel::ConsumerReadinessCell(arguments)) => {
            memcordon_ci::release::consumer_readiness_cell::execute(&root, &arguments)
        }
        #[cfg(target_os = "linux")]
        Some(TopLevel::ConsumerReadinessMalformedIngress(arguments)) => {
            memcordon_ci::release::linux_malformed_ingress::execute(&arguments)
        }
        Some(TopLevel::ConsumerReadinessCleanup(arguments)) => {
            memcordon_ci::release::consumer_readiness_cell::cleanup(&root, &arguments)
        }
        Some(TopLevel::Ci { command }) => match command {
            CiCommand::DownloadCacheContext { family } => {
                memcordon_ci::download_cache::emit(&root, family)
            }
            CiCommand::FetchDownloads { family } => memcordon_ci::download_cache::fetch_until(
                &root,
                family,
                std::time::Instant::now() + std::time::Duration::from_secs(900),
                None,
            ),
            CiCommand::Prepare {
                profile,
                failure_mode,
            } => memcordon_ci::preparation::prepare_with_failure(&root, profile, failure_mode),
            CiCommand::PrepareMiriComponents => memcordon_ci::miri_cache::components(
                &root,
                std::time::Instant::now() + std::time::Duration::from_secs(2700),
            ),
            CiCommand::MiriCacheContext => memcordon_ci::miri_cache::context(&root),
            CiCommand::PrepareMiriSysroot => memcordon_ci::miri_cache::prepare(&root),
            CiCommand::SeedContext {
                kind,
                purpose,
                shard,
                partition,
            } => {
                memcordon_ci::cache_snapshot::seed_context(&root, kind, &purpose, &shard, partition)
            }
            CiCommand::CacheSnapshot {
                kind,
                purpose,
                shard,
                partition,
                stage: _,
            } => memcordon_ci::cache_snapshot::snapshot(&root, kind, &purpose, &shard, partition),
            CiCommand::ImportCacheSnapshot {
                kind,
                purpose,
                shard,
                partition,
            } => memcordon_ci::cache_snapshot::import(&root, kind, &purpose, &shard, partition),
            CiCommand::CleanupCacheSnapshot {
                kind,
                purpose,
                shard,
                partition,
            } => memcordon_ci::cache_snapshot::cleanup(&root, kind, &purpose, &shard, partition),
            CiCommand::CacheContext {
                partition,
                for_save,
                purpose,
                shard,
                external,
            } => memcordon_ci::cache::emit_partition(
                &root, &purpose, &shard, &external, for_save, partition,
            ),
            CiCommand::PrepareRestoredCache {
                partition,
                purpose,
                shard,
                mode,
            } => memcordon_ci::cache_restore::prepare_partition(
                &root, &purpose, &shard, partition, mode,
            ),
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
        Some(TopLevel::Suite {
            suite,
            failure_mode,
        }) => suites::run(&root, suite, suites::SuiteOptions { failure_mode }),
        None => Err(CiError::Message(
            "exactly one CI command is required".to_owned(),
        )),
    };
    memcordon_ci::workflow_output::quiescent(result)
}

fn main() {
    match memcordon_ci::public_install_capture::run_if_wrapper() {
        Ok(Some(status)) => memcordon_ci::public_install_capture::exit_wrapper(status),
        Ok(None) => {}
        Err(error) => {
            eprintln!("memcordon-ci compiler capture: {error}");
            std::process::exit(1);
        }
    }
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
