//! Fixed native compile/package adapters.
use crate::{CiError, Result, Suite};
use memcordon_ci::{
    cache_restore::CompiledPartition,
    cache_snapshot::TransferImport,
    release::{self, ReleaseCommand, distribution::Distribution, target},
    work_outcome::{WorkOutcome, WriterSettlement},
};
use std::{fs::OpenOptions, io::Write, path::Path};

fn import_category(outcome: Option<TransferImport>) -> &'static str {
    match outcome {
        None => "Import failed",
        Some(TransferImport::NoSeed) => "No staged seed",
        Some(TransferImport::Rejected) => "Seed rejected",
        Some(TransferImport::ImportedCompleteExact) => "Complete seed imported (exact)",
        Some(TransferImport::ImportedCompleteCompatible) => "Complete seed imported (compatible)",
        Some(TransferImport::ImportedPartial) => "Partial seed imported",
    }
}

fn compile_category(outcome: &WorkOutcome<()>) -> &'static str {
    if outcome.is_ok() {
        "Succeeded"
    } else if outcome.writers() == WriterSettlement::NotStarted {
        "Did not start"
    } else {
        "Did not succeed"
    }
}

pub fn run(root: &Path, mut command: ReleaseCommand) -> Result<()> {
    match &mut command {
        ReleaseCommand::CompileTarget {
            product_only,
            source,
            build_source,
            runtime_components,
            failure_mode,
            ..
        } => {
            if std::env::var_os("GITHUB_EVENT_PATH").is_some() {
                let recipe = if *runtime_components {
                    Suite::ReleaseRuntime
                } else {
                    Suite::ReleaseCompile
                };
                *failure_mode = recipe.resolve_failure_mode(
                    memcordon_ci::suite::ModeRequest::Workflow(super::event_mode()?),
                )?;
            }
            let selected = release::preparation::read_build_source(
                source.as_deref(),
                build_source.as_deref(),
            )?;
            let distribution = Distribution::read(root)?;
            let distribution = if *runtime_components {
                distribution.with_runtime_components()?
            } else {
                distribution
            };
            let native = distribution.native()?;
            let mode = *failure_mode;
            let product_only = *product_only;
            let recipe = if *runtime_components {
                Suite::ReleaseRuntime
            } else {
                Suite::ReleaseCompile
            };
            let summary = if cfg!(all(windows, target_arch = "x86_64"))
                && *runtime_components
                && !product_only
            {
                std::env::var_os("GITHUB_STEP_SUMMARY")
            } else {
                None
            };
            let mut product_import = "Not attempted";
            let mut native_import = "Not attempted";
            let session = memcordon_ci::segment_cache::Session::begin_observing_imports(
                root,
                super::scopes(recipe),
                super::family(recipe),
                false,
                true,
                |partition, outcome| {
                    if summary.is_some() {
                        match partition {
                            CompiledPartition::Product => product_import = import_category(outcome),
                            CompiledPartition::NativeTests => {
                                native_import = import_category(outcome)
                            }
                            _ => {}
                        }
                    }
                },
            );
            if product_only {
                return session?.execute(root, || release::run(root, command));
            }
            let mut product_compile = "Not observed";
            let mut native_compile = "Not observed";
            let compile = || {
                let outer = std::time::Instant::now() + std::time::Duration::from_secs(140 * 60);
                let pair = memcordon_ci::preparation::with_operation(mode, outer, || {
                    let prepared = target::prepare_native_compile(
                        root,
                        &selected,
                        native,
                        mode,
                        target::NativeCompileMode::Split,
                    )?;
                    memcordon_ci::preparation::with_operation(
                        mode,
                        prepared.operation_deadline,
                        || {
                            Ok(target::compile_native_pair(
                                root, &selected, native, prepared,
                            ))
                        },
                    )
                })?;
                if summary.is_some() {
                    product_compile = compile_category(&pair.first);
                    native_compile = compile_category(&pair.second);
                }
                Ok(pair)
            };
            let result =
                session.and_then(|session| session.execute_pair(root, &["product"], compile));
            if let Some(path) = summary {
                let _ = OpenOptions::new()
                    .append(true)
                    .open(path)
                    .and_then(|mut file| {
                        writeln!(
                            file,
                            "### Windows x64 compile and cache\n\n\
                             | Partition | Compiled cache import | Compile lane |\n\
                             | --- | --- | --- |\n\
                             | Product | {product_import} | {product_compile} |\n\
                             | Native tests | {native_import} | {native_compile} |\n"
                        )
                    });
            }
            result
        }
        ReleaseCommand::ValidatePackage { failure_mode, .. } => {
            if std::env::var_os("GITHUB_EVENT_PATH").is_some() {
                *failure_mode = Suite::ReleaseValidatePackage.resolve_failure_mode(
                    memcordon_ci::suite::ModeRequest::Workflow(super::event_mode()?),
                )?;
            }
            release::run(root, command)
        }
        _ => Err(CiError::Message(
            "native split adapter requires a fixed native phase".into(),
        )),
    }
}
