//! Fixed native compile/package adapters. Cache facts stay in memory.
use crate::{CiError, Result, Suite};
use memcordon_ci::release::{self, ReleaseCommand, distribution::Distribution, target};
use std::path::Path;

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
            let session = memcordon_ci::segment_cache::Session::begin_selected(
                root,
                super::scopes(recipe),
                super::family(recipe),
                false,
            )?;
            if product_only {
                return session.execute(root, || release::run(root, command));
            }
            session.execute_pair(root, &["product"], || {
                let outer = std::time::Instant::now() + std::time::Duration::from_secs(140 * 60);
                memcordon_ci::preparation::with_operation(mode, outer, || {
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
                })
            })
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
