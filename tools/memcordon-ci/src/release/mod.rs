//! Direct release operations selected by the maintainer's existing tag.
pub mod artifacts;
pub mod bundle;
pub mod compatibility;
pub mod consumer_readiness_cell;
pub mod distribution;
pub mod git;
pub mod http;
pub mod installed_consumer;
#[cfg(target_os = "linux")]
pub mod linux_account_normalize;
#[cfg(target_os = "linux")]
pub mod linux_cross_attempt_cases;
#[cfg(target_os = "linux")]
pub mod linux_export_recovery;
#[cfg(target_os = "linux")]
pub mod linux_image_normalize;
#[cfg(target_os = "linux")]
pub mod linux_import_normalize;
pub mod linux_installed_consumer;
#[cfg(target_os = "linux")]
pub mod linux_isolation_cases;
#[cfg(target_os = "linux")]
pub mod linux_isolation_recovery;
#[cfg(target_os = "linux")]
pub mod linux_malformed_ingress;
#[cfg(target_os = "linux")]
pub mod linux_mixed_installed;
#[cfg(target_os = "linux")]
pub mod linux_native_component;
#[cfg(target_os = "linux")]
pub mod linux_native_package;
#[cfg(target_os = "linux")]
pub mod linux_readiness_image_cases;
#[cfg(target_os = "linux")]
pub mod linux_readiness_lease;
#[cfg(target_os = "linux")]
pub mod linux_readiness_legacy_cases;
#[cfg(target_os = "linux")]
pub mod linux_readiness_lifecycle_cases;
#[cfg(target_os = "linux")]
pub mod linux_readiness_limits_cases;
#[cfg(target_os = "linux")]
pub mod linux_readiness_policy_cases;
pub mod native_component_harness;
#[cfg(any(target_os = "linux", windows))]
pub mod original_native_components;
pub mod packages;
pub mod preparation;
pub mod public_consumer;
pub mod publish;
#[cfg(any(target_os = "linux", windows))]
pub mod readiness_product;
pub mod readiness_report;
pub mod readiness_transport;
pub mod recovery;
pub mod registry;
pub mod rehearsal;
pub mod rehearsal_input;
pub mod rehearsal_tool;
pub mod source;
pub mod tag;
pub mod target;
pub mod windows_installed_consumer;
#[cfg(windows)]
pub mod windows_readiness_lease;

use crate::{CiError, Result};
use clap::Subcommand;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum ConsumerChannel {
    Native,
    Cargo,
}

#[derive(Subcommand)]
pub enum ReleaseCommand {
    ConsumerReadinessReport(readiness_report::ReportArguments),
    SelectPreparation,
    WorkingWindowsPrepare {
        #[arg(long, default_value = "target/ci/windows-prepared")]
        destination: PathBuf,
    },
    WorkingWindowsConsumer {
        #[arg(long, default_value = "target/ci/windows-prepared")]
        prepared: PathBuf,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long, value_enum)]
        channel: ConsumerChannel,
    },
    ConsumerCache {
        #[arg(long, default_value = ".release/target")]
        target: PathBuf,
        #[arg(long, default_value = ".release/packages")]
        packages: PathBuf,
    },
    VerifySource {
        #[arg(long, conflicts_with = "build_source")]
        source: Option<PathBuf>,
        #[arg(long)]
        build_source: Option<PathBuf>,
    },
    PublicConsumer {
        #[arg(long, default_value = ".release/prepared")]
        prepared: PathBuf,
        #[arg(long, default_value = "1.97.1")]
        toolchain: String,
    },
    PublicationTool {
        #[arg(long, default_value = ".release/tool")]
        destination: PathBuf,
    },
    RecoveryInputs,
    RehearsalTool,
    #[command(hide = true)]
    RehearsalTransaction {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long)]
        result: PathBuf,
    },
    Publish {
        #[arg(long, default_value = ".release/prepared")]
        prepared: PathBuf,
    },
    Inspect {
        #[arg(long, default_value = ".release/prepared")]
        prepared: PathBuf,
    },
    BuildTarget {
        #[arg(long)]
        consumer_readiness: bool,
        #[arg(long, conflicts_with = "build_source")]
        source: Option<PathBuf>,
        #[arg(long)]
        build_source: Option<PathBuf>,
        #[arg(long, default_value = ".release/target")]
        destination: PathBuf,
    },
    Assemble {
        #[arg(long)]
        consumer_readiness: bool,
        #[arg(long, conflicts_with = "build_source")]
        source: Option<PathBuf>,
        #[arg(long)]
        build_source: Option<PathBuf>,
        #[arg(long, default_value = ".release/packages")]
        packages: PathBuf,
        #[arg(long)]
        targets: Vec<PathBuf>,
        #[arg(long)]
        destination: Option<PathBuf>,
    },
    Packages {
        #[arg(long, conflicts_with = "build_source")]
        source: Option<PathBuf>,
        #[arg(long)]
        build_source: Option<PathBuf>,
        #[arg(long, default_value = "target/ci-packages")]
        target: PathBuf,
        #[arg(long, default_value = ".release/packages")]
        destination: PathBuf,
    },
    InstalledConsumers {
        #[arg(long, requires = "channel")]
        external_input: Option<PathBuf>,
        #[arg(long, value_enum)]
        channel: Option<ConsumerChannel>,
        #[arg(long, default_value = ".release/target")]
        target: PathBuf,
        #[arg(long, default_value = ".release/packages")]
        packages: PathBuf,
        #[arg(long, default_value = ".release/installed-results")]
        destination: PathBuf,
    },
    Select {
        #[arg(long)]
        repository: Option<String>,
        #[arg(long)]
        tag_ref: Option<String>,
        #[arg(long, default_value = ".release/source.json")]
        record: PathBuf,
    },
    PrepareTag {
        #[arg(long)]
        version: String,
        #[arg(long)]
        repository: Option<String>,
        #[arg(long, default_value = ".release/tag-plan.json")]
        record: PathBuf,
    },
    CreateTag {
        #[arg(long, default_value = ".release/tag-plan.json")]
        record: PathBuf,
    },
    PushTag {
        #[arg(long, default_value = ".release/tag-plan.json")]
        record: PathBuf,
    },
    ReconcileTag {
        #[arg(long, default_value = ".release/tag-plan.json")]
        record: PathBuf,
        #[arg(long)]
        dispatch: bool,
        #[arg(long, value_enum, default_value = "reprepare")]
        mode: recovery::RecoveryMode,
        #[arg(long)]
        original_run_id: Option<u64>,
        #[arg(long)]
        prepared_artifact_id: Option<u64>,
        #[arg(long)]
        tool_artifact_id: Option<u64>,
    },
}

fn repository(root: &Path, supplied: Option<String>) -> Result<String> {
    supplied
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .map(Ok)
        .unwrap_or_else(|| Ok(crate::config::release(root)?.repository))
}

pub fn run(root: &Path, command: ReleaseCommand) -> Result<()> {
    match command {
        ReleaseCommand::SelectPreparation => {
            let selected = preparation::select_preparation(root)?;
            preparation::write_preparation_files(root, &selected)
        }
        ReleaseCommand::WorkingWindowsPrepare { destination } => {
            windows_installed_consumer::prepare_working(root, &destination)
        }
        ReleaseCommand::WorkingWindowsConsumer {
            prepared,
            destination,
            channel,
        } => windows_installed_consumer::run_working_channel(
            root,
            &prepared,
            &destination,
            match channel {
                ConsumerChannel::Native => {
                    crate::windows_causal_acceptance::InstalledChannel::NativeBundle
                }
                ConsumerChannel::Cargo => {
                    crate::windows_causal_acceptance::InstalledChannel::CargoPackage
                }
            },
        ),
        ReleaseCommand::ConsumerCache { target, packages } => {
            let (native, _) = target::TargetBundle::load(&target)?;
            let (crates, _) = packages::PackageBundle::load(&packages)?;
            if native.source != crates.source {
                return Err(CiError::Message(
                    "consumer cache source selections differ".into(),
                ));
            }
            let mut inputs = vec![target.join("target.json"), packages.join("packages.json")];
            inputs.push(target.join(&native.archive.name));
            inputs.push(target.join(&native.fixture.name));
            inputs.extend(crates.files.iter().map(|file| packages.join(&file.name)));
            crate::cache::emit(root, "installed", "complete", &inputs)
        }
        ReleaseCommand::VerifySource {
            source,
            build_source,
        } => preparation::read_build_source(source.as_deref(), build_source.as_deref())?
            .recheck(root),
        ReleaseCommand::PublicConsumer {
            prepared,
            toolchain,
        } => public_consumer::run(&prepared, &toolchain),
        ReleaseCommand::PublicationTool { destination } => {
            let image = artifacts::read_file(&std::env::current_exe()?)?;
            target::validate_executable(&image, "x86_64-unknown-linux-gnu")?;
            let archive = target::encode_archive(
                "x86_64-unknown-linux-gnu",
                &std::collections::BTreeMap::from([("memcordon-ci".into(), image)]),
                &std::collections::BTreeSet::from(["memcordon-ci".into()]),
            )?;
            if destination.exists() {
                return Err(CiError::Message(
                    "publication tool output must be fresh".into(),
                ));
            }
            std::fs::create_dir_all(&destination)?;
            std::fs::write(
                destination.join("memcordon-publication-tool.tar.gz"),
                archive,
            )?;
            Ok(())
        }
        ReleaseCommand::InstalledConsumers {
            external_input,
            channel,
            target,
            packages,
            destination,
        } => match channel {
            Some(channel) => installed_consumer::run_channel_with_external(
                root,
                &target,
                &packages,
                &destination,
                match channel {
                    ConsumerChannel::Native => {
                        crate::windows_causal_acceptance::InstalledChannel::NativeBundle
                    }
                    ConsumerChannel::Cargo => {
                        crate::windows_causal_acceptance::InstalledChannel::CargoPackage
                    }
                },
                external_input.as_deref(),
            ),
            None => {
                if external_input.is_some() {
                    return Err(CiError::Message(
                        "--external-input requires an explicitly selected --channel".into(),
                    ));
                }
                installed_consumer::run(root, &target, &packages, &destination)
            }
        },
        ReleaseCommand::ConsumerReadinessReport(arguments) => {
            readiness_report::run(root, &arguments)
        }
        ReleaseCommand::RecoveryInputs => recovery::recovery_inputs(root),
        ReleaseCommand::RehearsalTool => rehearsal_tool::package(root),
        ReleaseCommand::RehearsalTransaction {
            input,
            fixture,
            result,
        } => rehearsal::transaction(&input, &fixture, &result),
        ReleaseCommand::Publish { prepared } => publish::run(&prepared, true),
        ReleaseCommand::Inspect { prepared } => publish::run(&prepared, false),
        ReleaseCommand::BuildTarget {
            consumer_readiness,
            source,
            build_source,
            destination,
        } => {
            let selected =
                preparation::read_build_source(source.as_deref(), build_source.as_deref())?;
            let distribution = distribution::Distribution::read(root)?;
            let distribution = if consumer_readiness {
                distribution.consumer_readiness()?
            } else {
                distribution
            };
            let distribution = distribution.native()?.clone();
            target::build_selected_with_components(
                root,
                &selected,
                &distribution,
                &destination,
                consumer_readiness,
            )
        }
        ReleaseCommand::Assemble {
            consumer_readiness,
            source,
            build_source,
            packages,
            targets,
            destination,
        } => {
            let targets = if targets.is_empty() {
                let mut discovered = Vec::new();
                for entry in std::fs::read_dir(root.join(".release/targets"))? {
                    let entry = entry?;
                    if !entry.file_type()?.is_dir() {
                        return Err(CiError::Message(
                            "target routing entry is not a directory".into(),
                        ));
                    }
                    discovered.push(entry.path());
                }
                discovered
            } else {
                targets
            };
            let selected =
                preparation::read_build_source(source.as_deref(), build_source.as_deref())?;
            let destination = destination.unwrap_or_else(|| {
                root.join(
                    if matches!(selected, source::BuildSourceIdentity::Working { .. }) {
                        ".release/prepared-candidate"
                    } else {
                        ".release/prepared"
                    },
                )
            });
            bundle::assemble_build_profile(
                root,
                &selected,
                &packages,
                &targets,
                &destination,
                consumer_readiness,
            )
        }
        ReleaseCommand::Packages {
            source,
            build_source,
            target,
            destination,
        } => packages::prepare_build(
            root,
            &preparation::read_build_source(source.as_deref(), build_source.as_deref())?,
            &target,
            &destination,
        ),
        ReleaseCommand::Select {
            repository: supplied,
            tag_ref,
            record,
        } => {
            if let Ok(path) = std::env::var("GITHUB_EVENT_PATH") {
                let event: serde_json::Value = source::read_json(Path::new(&path))?;
                if event.get("deleted").and_then(serde_json::Value::as_bool) == Some(true) {
                    return Err(CiError::Message(
                        "deleted tag cannot select a release".into(),
                    ));
                }
            }
            let dispatched =
                if std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch") {
                    let path = std::env::var_os("GITHUB_EVENT_PATH")
                        .ok_or_else(|| CiError::Message("dispatch event path missing".into()))?;
                    Some(recovery::parse_event(&artifacts::read_file(Path::new(
                        &path,
                    ))?)?)
                } else {
                    None
                };
            let reference = tag_ref
                .or_else(|| {
                    dispatched
                        .as_ref()
                        .map(|input| format!("refs/tags/{}", input.tag))
                })
                .or_else(|| std::env::var("GITHUB_REF").ok())
                .ok_or_else(|| CiError::Message("supply the existing full tag ref".into()))?;
            let selected = source::select(root, &repository(root, supplied)?, &reference)?;
            source::write_json(&record, &selected)?;
            crate::workflow_output::write(&[
                ("selected-commit", selected.commit),
                ("selected-tag", selected.tag_ref),
                (
                    "public-consumer",
                    distribution::Distribution::read(root)?
                        .public_consumer
                        .to_string(),
                ),
                (
                    "recovery-mode",
                    if dispatched
                        .as_ref()
                        .is_some_and(|input| input.mode == recovery::RecoveryMode::PublicationOnly)
                    {
                        "publication-only".into()
                    } else {
                        "reprepare".into()
                    },
                ),
            ])
        }
        ReleaseCommand::PrepareTag {
            version,
            repository: supplied,
            record,
        } => tag::prepare(root, &repository(root, supplied)?, &version, &record),
        ReleaseCommand::CreateTag { record } => {
            println!("{:?}", tag::create(root, &record)?);
            Ok(())
        }
        ReleaseCommand::PushTag { record } => {
            println!("{:?}", tag::push(root, &record)?);
            Ok(())
        }
        ReleaseCommand::ReconcileTag {
            record,
            dispatch,
            mode,
            original_run_id,
            prepared_artifact_id,
            tool_artifact_id,
        } => {
            println!("{:?}", tag::inspect(root, &record)?);
            if dispatch {
                let original = match (original_run_id, prepared_artifact_id, tool_artifact_id) {
                    (None, None, None) => None,
                    (Some(run_id), Some(prepared_artifact_id), Some(tool_artifact_id)) => {
                        Some(recovery::PreparedArtifactLocator {
                            run_id,
                            prepared_artifact_id,
                            tool_artifact_id,
                        })
                    }
                    _ => {
                        return Err(CiError::Message(
                            "supply all original artifact IDs together".into(),
                        ));
                    }
                };
                let plan: tag::TagPlan = source::read_json(&record)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&recovery::dispatch(
                        &plan,
                        mode,
                        original.as_ref()
                    )?)?
                );
            } else if original_run_id.is_some()
                || prepared_artifact_id.is_some()
                || tool_artifact_id.is_some()
            {
                return Err(CiError::Message(
                    "artifact IDs require explicit --dispatch".into(),
                ));
            }
            Ok(())
        }
    }
}
