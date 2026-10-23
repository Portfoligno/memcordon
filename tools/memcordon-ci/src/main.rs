#![forbid(unsafe_code)]

mod ci_segments;
mod suites;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use memcordon_ci::suite::Suite;
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
    Workflows {
        #[arg(long, conflicts_with = "write", required_unless_present = "write")]
        check: bool,
        #[arg(long, conflicts_with = "check", required_unless_present = "check")]
        write: bool,
    },
    DriverBootstrap,
    DriverImageProbe,
    DriverCleanup,
    DriverContext,
    DriverSelect {
        #[arg(long, value_enum)]
        feedback: Option<memcordon_ci::driver_cache::DriverFeedback>,
    },
    DriverBuild {
        #[arg(long, value_enum)]
        feedback: Option<memcordon_ci::driver_cache::DriverFeedback>,
    },
    DriverAdoptCold {
        #[arg(long, value_enum)]
        feedback: Option<memcordon_ci::driver_cache::DriverFeedback>,
    },
    Feedback {
        #[arg(value_enum)]
        operation: memcordon_ci::driver_cache::DriverFeedback,
    },
    PreparationTools {
        #[arg(value_enum)]
        operation: memcordon_ci::preparation_tools::Operation,
        #[arg(long, value_enum)]
        kind: memcordon_ci::preparation_tools::Kind,
    },
    Segment {
        #[arg(value_enum)]
        recipe: Suite,
    },
    CacheRequests {
        #[arg(value_enum)]
        recipe: Suite,
    },
    CleanupTransfers {
        #[arg(value_enum)]
        recipe: Suite,
    },
    BootstrapCacheContext,
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
    let backend = |suite: &Suite| {
        matches!(
            suite,
            Suite::BackendLinuxCgroup
                | Suite::BackendLinuxPrivate
                | Suite::BackendLinuxPrivatePrepare
                | Suite::BackendLinuxPrivateRuntime
                | Suite::BackendWindowsJob
                | Suite::BackendWindowsSealed
                | Suite::BackendMacosWatchdog
                | Suite::ReleaseMacosNative
                | Suite::ReleaseMacosAcceptance
        )
    };
    let interruptible = match &cli.command {
        Some(TopLevel::Suite { suite, .. }) => backend(suite),
        Some(TopLevel::DelegatedLinuxBackend { .. }) => true,
        Some(TopLevel::Ci {
            command: CiCommand::Segment { recipe },
        }) => backend(recipe),
        Some(TopLevel::Release { command }) => matches!(
            command,
            memcordon_ci::release::ReleaseCommand::WorkingWindowsPrepare { .. }
                | memcordon_ci::release::ReleaseCommand::WorkingWindowsConsumer { .. }
                | memcordon_ci::release::ReleaseCommand::CleanupInstalledLoaderSupport { .. }
        ),
        _ => false,
    };
    let interrupt = interruptible
        .then(memcordon_ci::cancellation::Scope::install)
        .transpose()?;
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
    let result = (|| match cli.command {
        #[cfg(target_os = "windows")]
        Some(TopLevel::ConsumerReadinessLoaderDiagnostic(arguments)) => {
            let operation = memcordon_ci::work_outcome::WorkOutcome::from_result(
                memcordon_ci::release::original_native_components::loader_diagnostic::run(
                    &root, &arguments,
                ),
            );
            if arguments.cleanup {
                operation.into_result()
            } else {
                let mut cleanup = arguments;
                cleanup.cleanup = true;
                let cleanup = memcordon_ci::work_outcome::WorkOutcome::from_result(
                    memcordon_ci::release::original_native_components::loader_diagnostic::run(
                        &root, &cleanup,
                    ),
                );
                memcordon_ci::work_outcome::join_completed(operation, cleanup).into_result()
            }
        }
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        Some(TopLevel::ConsumerReadinessNativeComponents(arguments)) => {
            let operation = memcordon_ci::work_outcome::WorkOutcome::from_result(
                memcordon_ci::release::original_native_components::run(&root, &arguments),
            );
            if arguments.cleanup {
                operation.into_result()
            } else {
                let mut cleanup = arguments;
                cleanup.cleanup = true;
                let cleanup = memcordon_ci::work_outcome::WorkOutcome::from_result(
                    memcordon_ci::release::original_native_components::run(&root, &cleanup),
                );
                memcordon_ci::work_outcome::join_completed(operation, cleanup).into_result()
            }
        }
        Some(TopLevel::ConsumerReadinessCell(arguments)) => {
            let operation = memcordon_ci::work_outcome::WorkOutcome::from_result(
                memcordon_ci::release::consumer_readiness_cell::execute(&root, &arguments),
            );
            let cleanup = memcordon_ci::work_outcome::WorkOutcome::from_result(
                memcordon_ci::release::consumer_readiness_cell::cleanup(&root, &arguments),
            );
            memcordon_ci::work_outcome::join_completed(operation, cleanup).into_result()
        }
        #[cfg(target_os = "linux")]
        Some(TopLevel::ConsumerReadinessMalformedIngress(arguments)) => {
            memcordon_ci::release::linux_malformed_ingress::execute(&arguments)
        }
        Some(TopLevel::ConsumerReadinessCleanup(arguments)) => {
            memcordon_ci::release::consumer_readiness_cell::cleanup(&root, &arguments)
        }
        Some(TopLevel::Ci { command }) => match command {
            CiCommand::Workflows { check: _, write } => {
                memcordon_ci::workflow_definitions::run(&root, write)
            }
            CiCommand::DriverBootstrap => memcordon_ci::driver_cache::bootstrap(&root),
            CiCommand::DriverImageProbe => memcordon_ci::driver_cache::image_probe(&root),
            CiCommand::DriverCleanup => memcordon_ci::driver_cache::cleanup(&root),
            CiCommand::DriverContext => memcordon_ci::driver_cache::context(&root),
            CiCommand::DriverSelect { feedback } => {
                memcordon_ci::driver_cache::select(&root, feedback)
            }
            CiCommand::DriverBuild { feedback } => {
                memcordon_ci::driver_cache::build(&root, feedback)
            }
            CiCommand::DriverAdoptCold { feedback } => {
                memcordon_ci::driver_cache::adopt_cold(&root, feedback)
            }
            CiCommand::Feedback { operation } => operation.run(&root),
            CiCommand::PreparationTools { operation, kind } => {
                memcordon_ci::preparation_tools::run(&root, operation, kind)
            }
            CiCommand::Segment { recipe } => ci_segments::run(&root, recipe),
            CiCommand::CacheRequests { recipe } => ci_segments::requests(&root, recipe),
            CiCommand::CleanupTransfers { recipe } => ci_segments::cleanup(&root, recipe),
            CiCommand::BootstrapCacheContext => memcordon_ci::workflow_output::write(&[(
                "bootstrap-home-matches",
                memcordon_ci::download_cache::bootstrap_home_matches(&root).to_string(),
            )]),
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
        Some(TopLevel::Release { mut command }) => {
            if matches!(
                &command,
                memcordon_ci::release::ReleaseCommand::CompileTarget { .. }
                    | memcordon_ci::release::ReleaseCommand::ValidatePackage { .. }
                    | memcordon_ci::release::ReleaseCommand::NativeCoverageShard { .. }
            ) {
                ci_segments::native::run(&root, command)
            } else if let memcordon_ci::release::ReleaseCommand::BuildTarget {
                consumer_readiness,
                failure_mode,
                ..
            } = &mut command
            {
                let recipe = if *consumer_readiness {
                    Suite::ReleaseReadiness
                } else {
                    Suite::ReleaseBuild
                };
                if std::env::var_os("GITHUB_EVENT_PATH").is_some() {
                    *failure_mode = recipe.resolve_failure_mode(
                        memcordon_ci::suite::ModeRequest::Workflow(ci_segments::event_mode()?),
                    )?;
                }
                let session = memcordon_ci::segment_cache::Session::begin_selected(
                    &root,
                    ci_segments::scopes(recipe),
                    ci_segments::family(recipe),
                    false,
                )?;
                session.execute(&root, || memcordon_ci::release::run(&root, command))
            } else if matches!(
                &command,
                memcordon_ci::release::ReleaseCommand::WorkingWindowsPrepare { .. }
            ) {
                let recipe = Suite::WorkingWindowsPrepare;
                let session = memcordon_ci::segment_cache::Session::begin_selected(
                    &root,
                    ci_segments::scopes(recipe),
                    ci_segments::family(recipe),
                    false,
                )?;
                session.execute(&root, || memcordon_ci::release::run(&root, command))
            } else {
                memcordon_ci::release::run(&root, command)
            }
        }
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
    })();
    let result = memcordon_ci::workflow_output::finalize(
        memcordon_ci::work_outcome::WorkOutcome::from_result(result),
    );
    match interrupt.as_ref() {
        Some(scope) => scope.finish(result),
        None => result,
    }
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
