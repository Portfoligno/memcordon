//! Closed binary adapters call the existing suite implementations directly.
pub mod native;
use crate::{CiError, Result, Suite};
use memcordon_ci::{
    cache_restore::CompiledPartition as P,
    cache_snapshot::{SnapshotKind, TransferSelection},
    download_cache::DownloadFamily as D,
    failure_mode::FailureMode,
    segment_cache::{CompiledScope, Session},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub fn event_mode() -> Result<FailureMode> {
    if std::env::var("GITHUB_EVENT_NAME").as_deref() != Ok("workflow_dispatch") {
        return Ok(FailureMode::StopAfterFailure);
    }
    let Some(path) = std::env::var_os("GITHUB_EVENT_PATH") else {
        return Ok(FailureMode::StopAfterFailure);
    };
    if std::fs::metadata(&path)?.len() > 1024 * 1024 {
        return Err(CiError::Message("event exceeds segment input bound".into()));
    }
    event_mode_bytes("workflow_dispatch", &std::fs::read(path)?)
}

fn event_mode_bytes(event_name: &str, bytes: &[u8]) -> Result<FailureMode> {
    if event_name != "workflow_dispatch" {
        return Ok(FailureMode::StopAfterFailure);
    }
    if bytes.len() > 1024 * 1024 {
        return Err(CiError::Message("event exceeds segment input bound".into()));
    }
    let event: serde_json::Value = serde_json::from_slice(bytes)?;
    match event
        .get("inputs")
        .and_then(|inputs| inputs.get("failure-mode"))
    {
        None => Ok(FailureMode::StopAfterFailure),
        Some(serde_json::Value::String(value)) if value == "stop-after-failure" => {
            Ok(FailureMode::StopAfterFailure)
        }
        Some(serde_json::Value::String(value)) if value == "collect-all" => {
            Ok(FailureMode::CollectAll)
        }
        _ => Err(CiError::Message("invalid workflow failure-mode".into())),
    }
}

fn scope(
    slot: &'static str,
    purpose: &'static str,
    shard: &'static str,
    partition: Option<P>,
    completion: &'static str,
) -> CompiledScope<'static> {
    CompiledScope {
        slot,
        selection: TransferSelection {
            kind: SnapshotKind::Compiled,
            purpose,
            shard,
            partition,
        },
        completion,
    }
}

pub fn scopes(suite: Suite) -> Vec<CompiledScope<'static>> {
    let ordinary = |purpose, shard| {
        vec![scope(
            "compiled",
            purpose,
            shard,
            None,
            "compiled-recipe-complete",
        )]
    };
    match suite {
        Suite::Policy
        | Suite::WorkspaceFetch
        | Suite::FuzzFetch
        | Suite::PrepareMiriComponents
        | Suite::MiriSetup => vec![],
        Suite::Quality | Suite::QualityCompile => vec![
            scope(
                "documentation",
                "quality-documentation-local-v1",
                "complete",
                None,
                "compiled-documentation-complete",
            ),
            scope(
                "compiler",
                "quality-compiler-local-v1",
                "complete",
                None,
                "compiled-compiler-complete",
            ),
        ],
        Suite::QualityCompiler | Suite::ReleaseQualityCompiler => {
            ordinary("quality-compiler-v1", "complete")
        }
        Suite::QualityDocumentation => ordinary("quality-documentation-v1", "complete"),
        Suite::SupplyAuditCheck | Suite::SupplyDenyCheck | Suite::ReleaseValidatePackage => vec![],
        Suite::Msrv => ordinary("msrv", "complete"),
        Suite::RehearsalToolBuild => ordinary("rehearsal-tool", "complete"),
        Suite::ReleaseBuild | Suite::ReleaseReadiness | Suite::ReleaseCompile => {
            let purpose = if matches!(suite, Suite::ReleaseReadiness) {
                "native-readiness"
            } else {
                "native-release"
            };
            vec![
                scope(
                    "native-tests",
                    purpose,
                    "complete",
                    Some(P::NativeTests),
                    "compiled-native-complete",
                ),
                scope(
                    "product",
                    purpose,
                    "complete",
                    Some(P::Product),
                    "compiled-product-complete",
                ),
            ]
        }
        Suite::WorkingWindowsPrepare => vec![
            scope(
                "native-tests",
                "windows-working",
                "complete",
                Some(P::NativeTests),
                "compiled-native-complete",
            ),
            scope(
                "product",
                "windows-working",
                "complete",
                Some(P::Product),
                "compiled-product-complete",
            ),
        ],
        Suite::Native | Suite::NativeCompile => vec![scope(
            "native-tests",
            "native-debug",
            "complete",
            Some(P::NativeTests),
            "compiled-native-complete",
        )],
        Suite::NativeExecute => vec![scope(
            "auxiliary-profiles",
            "native-auxiliary",
            "complete",
            Some(P::AuxiliaryProfiles),
            "compiled-recipe-complete",
        )],
        Suite::SupplyChain
        | Suite::PrepareTools
        | Suite::SupplyAuditPrepare
        | Suite::SupplyDenyPrepare => ["cargo-audit", "cargo-deny"]
            .into_iter()
            .filter(|purpose| match suite {
                Suite::SupplyAuditPrepare => *purpose == "cargo-audit",
                Suite::SupplyDenyPrepare => *purpose == "cargo-deny",
                _ => true,
            })
            .map(|purpose| CompiledScope {
                slot: purpose,
                selection: TransferSelection {
                    kind: SnapshotKind::ToolBuild,
                    purpose,
                    shard: match suite {
                        Suite::SupplyChain => "supply-pair-v1",
                        Suite::PrepareTools => "preparation-pair-v1",
                        _ => "complete",
                    },
                    partition: None,
                },
                completion: if purpose == "cargo-audit" {
                    "tool-cargo-audit-build-complete"
                } else {
                    "tool-cargo-deny-build-complete"
                },
            })
            .collect(),
        Suite::PrepareFuzz => vec![CompiledScope {
            slot: "cargo-fuzz",
            selection: TransferSelection {
                kind: SnapshotKind::ToolBuild,
                purpose: "cargo-fuzz",
                shard: "preparation-pair-v1",
                partition: None,
            },
            completion: "tool-cargo-fuzz-build-complete",
        }],
        Suite::Miri | Suite::MiriFirst => ordinary("miri", "first"),
        Suite::MiriSecond => ordinary("miri", "second"),
        Suite::MiriQuarterOne => ordinary("miri", "quarter-one"),
        Suite::MiriQuarterTwo => ordinary("miri", "quarter-two"),
        Suite::MiriQuarterThree => ordinary("miri", "quarter-three"),
        Suite::MiriQuarterFour => ordinary("miri", "quarter-four"),
        Suite::Fuzz | Suite::FuzzFirst | Suite::FuzzCompileFirst | Suite::FuzzExecuteFirst => {
            ordinary("fuzz", "first")
        }
        Suite::FuzzSecond | Suite::FuzzCompileSecond | Suite::FuzzExecuteSecond => {
            ordinary("fuzz", "second")
        }
        Suite::FuzzQuarterOne | Suite::FuzzCompileQuarterOne | Suite::FuzzExecuteQuarterOne => {
            ordinary("fuzz", "quarter-one")
        }
        Suite::FuzzQuarterTwo | Suite::FuzzCompileQuarterTwo | Suite::FuzzExecuteQuarterTwo => {
            ordinary("fuzz", "quarter-two")
        }
        Suite::FuzzQuarterThree
        | Suite::FuzzCompileQuarterThree
        | Suite::FuzzExecuteQuarterThree => ordinary("fuzz", "quarter-three"),
        Suite::FuzzQuarterFour | Suite::FuzzCompileQuarterFour | Suite::FuzzExecuteQuarterFour => {
            ordinary("fuzz", "quarter-four")
        }
        Suite::Stress => ordinary("stress", "complete"),
        Suite::StressPackages => ordinary("stress-packages", "complete"),
        Suite::StressLifecycle => ordinary("stress-lifecycle", "complete"),
        Suite::ReleaseMacosNative => ordinary("macos", "native"),
        Suite::BackendMacosWatchdog => ordinary("macos", "combined"),
        Suite::ReleaseMacosAcceptance => ordinary("macos", "acceptance"),
        Suite::MacosDeadline => ordinary("deadline", "complete"),
        Suite::BackendLinuxPrivate
        | Suite::BackendLinuxPrivatePrepare
        | Suite::BackendLinuxPrivateRuntime => {
            let mut scopes = vec![
                scope(
                    "native-tests",
                    "private",
                    "complete",
                    Some(P::NativeTests),
                    "compiled-native-complete",
                ),
                scope(
                    "product",
                    "private",
                    "complete",
                    Some(P::Product),
                    "compiled-product-complete",
                ),
                scope(
                    "private-native-tests",
                    "private",
                    "complete",
                    Some(P::PrivateNativeTests),
                    "compiled-recipe-complete",
                ),
            ];
            scopes.retain(|scope| match suite {
                Suite::BackendLinuxPrivatePrepare => scope.slot != "private-native-tests",
                Suite::BackendLinuxPrivateRuntime => scope.slot == "private-native-tests",
                _ => true,
            });
            scopes
        }
        Suite::BackendLinuxCgroup | Suite::BackendWindowsJob | Suite::BackendWindowsSealed => {
            ordinary("backend", "complete")
        }
    }
}

pub fn family(suite: Suite) -> D {
    if matches!(
        suite,
        Suite::Fuzz
            | Suite::FuzzFirst
            | Suite::FuzzSecond
            | Suite::FuzzQuarterOne
            | Suite::FuzzQuarterTwo
            | Suite::FuzzQuarterThree
            | Suite::FuzzQuarterFour
            | Suite::FuzzCompileFirst
            | Suite::FuzzCompileSecond
            | Suite::FuzzCompileQuarterOne
            | Suite::FuzzCompileQuarterTwo
            | Suite::FuzzCompileQuarterThree
            | Suite::FuzzCompileQuarterFour
            | Suite::FuzzExecuteFirst
            | Suite::FuzzExecuteSecond
            | Suite::FuzzExecuteQuarterOne
            | Suite::FuzzExecuteQuarterTwo
            | Suite::FuzzExecuteQuarterThree
            | Suite::FuzzExecuteQuarterFour
            | Suite::FuzzFetch
            | Suite::PrepareFuzz
    ) {
        D::Fuzz
    } else {
        D::Workspace
    }
}

pub fn operation(root: &Path, suite: Suite, mode: FailureMode) -> Result<()> {
    match suite {
        Suite::RehearsalToolBuild => {
            let pins = memcordon_ci::config::toolchains(root)?;
            let outcome = memcordon_ci::command::rustup_cargo(
                root,
                &pins.stable,
                [
                    "build",
                    "--locked",
                    "--release",
                    "--target-dir",
                    "target/ci/rehearsal-build",
                    "-p",
                    "memcordon-ci",
                    "--bin",
                    "memcordon-release-rehearsal",
                ],
                Duration::from_secs(30 * 60),
            )
            .run_owned()
            .map(|_| ());
            if outcome.is_ok() {
                outcome
                    .postcondition(memcordon_ci::workflow_output::compilation_complete(
                        "compiled-recipe-complete",
                    ))
                    .into_result()
            } else {
                outcome.into_result()
            }
        }
        Suite::ReleaseBuild
        | Suite::ReleaseReadiness
        | Suite::ReleaseCompile
        | Suite::ReleaseValidatePackage
        | Suite::WorkingWindowsPrepare => Err(CiError::Message(
            "release build recipes require the existing release build-target arguments".into(),
        )),
        Suite::WorkspaceFetch | Suite::FuzzFetch => memcordon_ci::download_cache::fetch_until(
            root,
            family(suite),
            Instant::now() + Duration::from_secs(900),
            None,
        ),
        Suite::PrepareTools | Suite::PrepareFuzz => {
            memcordon_ci::preparation::prepare_with_failure(
                root,
                if matches!(suite, Suite::PrepareTools) {
                    memcordon_ci::bootstrap_profile::BootstrapProfile::SupplyChain
                } else {
                    memcordon_ci::bootstrap_profile::BootstrapProfile::Fuzz
                },
                mode,
            )
        }
        Suite::PrepareMiriComponents => memcordon_ci::miri_cache::components_only(
            root,
            Instant::now() + Duration::from_secs(2700),
        ),
        Suite::MiriSetup => memcordon_ci::miri_cache::prepare(root),
        _ => crate::suites::run(
            root,
            suite,
            crate::suites::SuiteOptions { failure_mode: mode },
        ),
    }
}

pub fn run(root: &Path, suite: Suite) -> Result<()> {
    dispatch(suite, event_mode()?, |mode| run_resolved(root, suite, mode))
}

fn dispatch<T>(
    suite: Suite,
    requested: FailureMode,
    operation: impl FnOnce(FailureMode) -> Result<T>,
) -> Result<T> {
    let mode = suite.resolve_failure_mode(memcordon_ci::suite::ModeRequest::Workflow(requested))?;
    operation(mode)
}

fn run_resolved(root: &Path, suite: Suite, mode: FailureMode) -> Result<()> {
    let sources = matches!(
        suite,
        Suite::WorkspaceFetch
            | Suite::FuzzFetch
            | Suite::PrepareTools
            | Suite::PrepareFuzz
            | Suite::MiriSetup
            | Suite::SupplyChain
            | Suite::SupplyAuditPrepare
            | Suite::SupplyDenyPrepare
    );
    let restore_inputs = !matches!(
        suite,
        Suite::NativeExecute
            | Suite::FuzzExecuteFirst
            | Suite::FuzzExecuteSecond
            | Suite::FuzzExecuteQuarterOne
            | Suite::FuzzExecuteQuarterTwo
            | Suite::FuzzExecuteQuarterThree
            | Suite::FuzzExecuteQuarterFour
    );
    let session = Session::begin_selected_restoring(
        root,
        scopes(suite),
        family(suite),
        sources,
        restore_inputs,
    )?;
    if matches!(suite, Suite::Quality | Suite::QualityCompile) {
        return session.execute_pair(root, &["documentation"], || {
            crate::suites::quality_pair(root, mode, matches!(suite, Suite::Quality))
        });
    }
    if matches!(suite, Suite::SupplyChain) {
        return session.execute_pair(root, &["cargo-audit"], || {
            crate::suites::supply_pair(root, mode)
        });
    }
    session.execute_with(root, |cache| {
        let sysroot = matches!(suite, Suite::MiriSetup)
            .then(|| cache.optional(|| memcordon_ci::miri_cache::identity(root)));
        if sysroot.as_ref().is_some_and(|result| {
            result.as_ref().is_err_and(|error| {
                memcordon_ci::segment_cache::cache_safety_error(error)
                    || memcordon_ci::work_outcome::has_unresolved_owner(error)
            })
        }) {
            return sysroot.expect("observed sysroot context").map(|_| ());
        }
        let outcome =
            memcordon_ci::work_outcome::WorkOutcome::from_result(operation(root, suite, mode));
        let outcome = if let Some(before) = sysroot {
            let after = cache.optional(|| memcordon_ci::miri_cache::identity(root));
            let entry = before
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .zip(after.as_ref().ok().and_then(Option::as_ref))
                .filter(|(a, b)| a == b)
                .filter(|_| {
                    memcordon_ci::segment_cache::write_event()
                        && outcome.writers().permits_reading()
                        && memcordon_ci::miri_cache::ready_in_invocation()
                })
                .map(|(_, value)| value);
            let emission = memcordon_ci::workflow_output::write(&[
                (
                    "sysroot-key",
                    entry.map_or_else(String::new, |(key, _)| key.clone()),
                ),
                (
                    "sysroot-path",
                    entry.map_or_else(String::new, |(_, path)| path.display().to_string()),
                ),
                ("sysroot-save", entry.is_some().to_string()),
            ]);
            let mut outcome = outcome.postcondition(emission);
            for result in [before, after] {
                if let Err(error) = result
                    && (matches!(&error, CiError::CacheSafety(_))
                        || memcordon_ci::work_outcome::has_unresolved_owner(&error))
                {
                    outcome = outcome.post_finalization(Err(error));
                }
            }
            outcome
        } else {
            outcome
        };
        outcome.into_result()
    })
}

pub fn requests(root: &Path, suite: Suite) -> Result<()> {
    memcordon_ci::preparation::with_operation(
        FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(240),
        || requests_inner(root, suite),
    )
}

fn requests_inner(root: &Path, suite: Suite) -> Result<()> {
    let request = memcordon_ci::segment_cache::requests(root, &scopes(suite), family(suite));
    if matches!(suite, Suite::MiriSetup) {
        let context = memcordon_ci::miri_cache::identity(root);
        let entry = context.as_ref().ok().and_then(Option::as_ref);
        let emission = memcordon_ci::workflow_output::write(&[
            (
                "sysroot-key",
                entry.map_or_else(String::new, |(key, _)| key.clone()),
            ),
            (
                "sysroot-path",
                entry.map_or_else(String::new, |(_, path)| path.display().to_string()),
            ),
            ("sysroot-prefix", String::new()),
            ("sysroot-restore", entry.is_some().to_string()),
        ]);
        let emission = match context {
            Err(error)
                if memcordon_ci::segment_cache::cache_safety_error(&error)
                    || memcordon_ci::work_outcome::has_unresolved_owner(&error) =>
            {
                memcordon_ci::work_outcome::WorkOutcome::from_result(emission)
                    .post_finalization(Err(error))
                    .into_result()
            }
            _ => emission,
        };
        memcordon_ci::work_outcome::WorkOutcome::from_result(request)
            .post_finalization(emission)
            .into_result()
    } else {
        request
    }
}

pub fn cleanup(root: &Path, suite: Suite) -> Result<()> {
    memcordon_ci::segment_cache::cleanup(root, &scopes(suite))
}

#[cfg(test)]
#[path = "../tests/private/ci_segment_routing.rs"]
mod tests;
