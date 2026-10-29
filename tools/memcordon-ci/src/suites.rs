use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memcordon_ci::capability;
use memcordon_ci::standard_contract::{CargoTestTarget, HardBackendScenario};

use crate::command::{CommandSpec, git, rustup_cargo, supply_chain_commands};
use crate::config;
use crate::{CiError, Result, Suite, policy};

const CARGO_DEADLINE: Duration = Duration::from_secs(15 * 60);
const CERTIFICATION_DEADLINE: Duration = Duration::from_secs(60 * 60);

/// Only synchronous postconditions of already returned owners belong here.
fn settled_validation<T>(validation: impl FnOnce() -> Result<T>) -> Result<T> {
    memcordon_ci::work_outcome::WorkOutcome::from_result(Ok(()))
        .map_validated(|_| validation())
        .into_result()
}

#[cfg(test)]
#[path = "../tests/private/suite_failure_loops.rs"]
mod suite_failure_loops;

fn cargo(
    root: &Path,
    toolchain: &str,
    subcommand: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<Vec<u8>> {
    cargo_with_deadline(root, toolchain, subcommand, arguments, CARGO_DEADLINE)
}

fn cargo_with_deadline(
    root: &Path,
    toolchain: &str,
    subcommand: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    deadline: Duration,
) -> Result<Vec<u8>> {
    let mut cargo_arguments = vec![OsString::from(subcommand)];
    cargo_arguments.extend(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string()),
    );
    let command = rustup_cargo(root, toolchain, cargo_arguments, deadline);
    let command = if subcommand == "miri" {
        if let Some(path) = memcordon_ci::miri_cache::managed_root(root)? {
            command.miri_sysroot(&path)
        } else {
            command
        }
    } else {
        command
    };
    command.run()
}

fn quality(root: &Path, stable: &str, mode: crate::failure_mode::FailureMode) -> Result<()> {
    let parent = root.join("target/ci/reports/execution");
    fs::create_dir_all(&parent)?;
    let directory = tempfile::Builder::new()
        .prefix("quality-")
        .tempdir_in(parent)?
        .keep();
    let started = Instant::now();
    let record = |state: &str, error: Option<&CiError>| {
        let write = || -> Result<()> {
            fs::create_dir_all(&directory)?;
            let temporary = directory.join("source-check.tmp");
            let value = serde_json::json!({"phase":"source-check", "state":state, "expected-operation":"pinned format, metadata, check, Clippy and rustdoc", "toolchain":stable, "declared-budget-ms":Duration::from_secs(90*60).as_millis(), "elapsed-ms":started.elapsed().as_millis(), "error":error.map(|error| crate::command::bounded_excerpt(error.to_string().as_bytes()))});
            memcordon_ci::release::source::write_json(&temporary, &value)?;
            fs::rename(temporary, directory.join("source-check.json"))?;
            Ok(())
        };
        if let Err(error) = write() {
            eprintln!("diagnostic retention incomplete: {error}");
        }
    };
    record("in-progress", None);
    let result = quality_inner(root, stable, mode);
    record(
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
        result.as_ref().err(),
    );
    result
}

fn quality_inner(root: &Path, stable: &str, mode: crate::failure_mode::FailureMode) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90 * 60);
    rustup_cargo(
        root,
        stable,
        ["fmt", "--all", "--", "--check"],
        CARGO_DEADLINE,
    )
    .bounded_until(deadline)
    .run()?;
    rustup_cargo(
        root,
        stable,
        ["metadata", "--locked", "--format-version", "1"],
        CARGO_DEADLINE,
    )
    .bounded_until(deadline)
    .run()?;
    quality_compile_until(root, stable, mode, deadline)
}

fn quality_compile(
    root: &Path,
    stable: &str,
    mode: crate::failure_mode::FailureMode,
) -> Result<()> {
    quality_compile_until(
        root,
        stable,
        mode,
        Instant::now() + Duration::from_secs(90 * 60),
    )
}

fn quality_compile_until(
    root: &Path,
    stable: &str,
    mode: crate::failure_mode::FailureMode,
    deadline: Instant,
) -> Result<()> {
    quality_compile_selected(root, stable, mode, deadline, None)
}

fn quality_compile_selected(
    root: &Path,
    stable: &str,
    mode: crate::failure_mode::FailureMode,
    deadline: Instant,
    documentation: Option<bool>,
) -> Result<()> {
    quality_compile_owned(root, stable, mode, deadline, documentation)?.into_result()
}

fn quality_compile_owned(
    root: &Path,
    stable: &str,
    mode: crate::failure_mode::FailureMode,
    deadline: Instant,
    documentation: Option<bool>,
) -> Result<crate::preparation::PairOutcome<(), ()>> {
    let layout = crate::performance_plan::PerformancePlan::read(root)?
        .quality
        .selected;
    let workers = crate::preparation::compiler_budget();
    let layout = if workers == 1 || documentation.is_some() {
        crate::performance_plan::Layout::Serial
    } else {
        layout
    };
    let allocation = crate::preparation::allocate_pair(
        std::num::NonZeroUsize::new(workers).expect("positive budget"),
        layout == crate::performance_plan::Layout::Parallel,
        crate::preparation::active_group().is_some_and(|group| group.inside_parallel_lane()),
        crate::preparation::PairClass::Balanced,
    );
    let compiler_jobs = allocation.second.get().to_string();
    let doc_jobs = allocation.first.get().to_string();
    let reports = root.join("target/ci/reports/quality");
    fs::create_dir_all(&reports)?;
    let reports = tempfile::Builder::new()
        .prefix("operations-")
        .tempdir_in(&reports)?
        .keep();
    let first = reports.join("documentation");
    let second = reports.join("compile");
    fs::create_dir(&first)?;
    fs::create_dir(&second)?;
    let packages = config::policy(root)?.workspace.publish_packages;
    Ok(crate::preparation::complete_owned_pair(
        layout,
        [allocation.first.get(), allocation.second.get()],
        || {
            owned_compilation(
                "compiled-documentation-complete",
                documentation != Some(false),
                || {
                    let mut failures = None;
                    for package in packages {
                        let outcome = crate::preparation::observed(
                            rustup_cargo(
                                root,
                                stable,
                                [
                                    "rustdoc",
                                    "--jobs",
                                    &doc_jobs,
                                    "--target-dir",
                                    "target/ci/quality-doc",
                                    "--package",
                                    &package,
                                    "--lib",
                                    "--all-features",
                                    "--locked",
                                    "--",
                                    "-D",
                                    "warnings",
                                ],
                                crate::preparation::remaining(deadline, CARGO_DEADLINE)?,
                            )
                            .bounded_until(deadline),
                            &first,
                            &package,
                        );
                        retain_failure(&mut failures, outcome, mode)?;
                    }
                    failures.map_or(Ok(()), Err)
                },
            )
        },
        || {
            owned_compilation(
                "compiled-compiler-complete",
                documentation != Some(true),
                || {
                    crate::preparation::observed(
                        rustup_cargo(
                            root,
                            stable,
                            [
                                "check",
                                "--jobs",
                                &compiler_jobs,
                                "--target-dir",
                                "target/ci/quality",
                                "--workspace",
                                "--all-targets",
                                "--all-features",
                                "--locked",
                            ],
                            crate::preparation::remaining(deadline, CARGO_DEADLINE)?,
                        )
                        .bounded_until(deadline),
                        &second,
                        "check",
                    )?;
                    crate::preparation::observed(
                        rustup_cargo(
                            root,
                            stable,
                            [
                                "clippy",
                                "--jobs",
                                &compiler_jobs,
                                "--target-dir",
                                "target/ci/quality",
                                "--workspace",
                                "--all-targets",
                                "--all-features",
                                "--locked",
                                "--",
                                "-D",
                                "warnings",
                            ],
                            crate::preparation::remaining(deadline, CARGO_DEADLINE)?,
                        )
                        .bounded_until(deadline),
                        &second,
                        "clippy",
                    )?;
                    Ok(())
                },
            )
        },
    ))
}

fn owned_compilation(
    fact: &'static str,
    enabled: bool,
    operation: impl FnOnce() -> Result<()>,
) -> memcordon_ci::work_outcome::WorkOutcome<()> {
    if !enabled {
        return memcordon_ci::work_outcome::WorkOutcome::not_started(());
    }
    let outcome = memcordon_ci::work_outcome::WorkOutcome::not_started(())
        .postcondition(memcordon_ci::workflow_output::revoke_compilation(fact))
        .then_owned(|()| memcordon_ci::work_outcome::WorkOutcome::from_result(operation()));
    if outcome.is_ok() {
        outcome.postcondition(memcordon_ci::workflow_output::compilation_complete(fact))
    } else {
        outcome
    }
}

pub(crate) fn quality_pair(
    root: &Path,
    mode: crate::failure_mode::FailureMode,
    prechecks: bool,
) -> Result<crate::preparation::PairOutcome<(), ()>> {
    let stable = config::toolchains(root)?.stable;
    let deadline = Instant::now() + Duration::from_secs(90 * 60);
    crate::preparation::with_operation(mode, deadline, || {
        if prechecks {
            for args in [
                vec!["fmt", "--all", "--", "--check"],
                vec!["metadata", "--locked", "--format-version", "1"],
            ] {
                rustup_cargo(root, &stable, args, CARGO_DEADLINE)
                    .bounded_until(deadline)
                    .run()?;
            }
        }
        quality_compile_owned(root, &stable, mode, deadline, None)
    })
}

fn quality_leaf(
    root: &Path,
    stable: &str,
    mode: crate::failure_mode::FailureMode,
    suite: Suite,
) -> Result<()> {
    memcordon_ci::workflow_output::revoke_compilation("compiled-recipe-complete")?;
    let deadline = Instant::now() + Duration::from_secs(90 * 60);
    quality_compile_selected(
        root,
        stable,
        mode,
        deadline,
        Some(matches!(suite, Suite::QualityDocumentation)),
    )
}

fn msrv(root: &Path, version: &str, mode: crate::failure_mode::FailureMode) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90 * 60);
    let policy = config::policy(root)?;
    let mut failures = None;
    for package in policy.workspace.production_packages {
        let mut prerequisite = true;
        for phase in ["check", "test"] {
            if !prerequisite {
                break;
            }
            let mut arguments = vec![
                OsString::from(phase),
                OsString::from("--target-dir"),
                OsString::from("target/ci/msrv"),
                OsString::from("--package"),
                OsString::from(&package),
                OsString::from("--all-targets"),
                OsString::from("--all-features"),
                OsString::from("--locked"),
            ];
            if phase == "test" && mode == crate::failure_mode::FailureMode::CollectAll {
                arguments.push(OsString::from("--no-fail-fast"));
            }
            let outcome = rustup_cargo(root, version, arguments, CARGO_DEADLINE)
                .bounded_until(deadline)
                .run()
                .map(|_| ());
            prerequisite = outcome.is_ok();
            retain_failure(&mut failures, outcome, mode)?;
        }
    }
    failures.map_or(Ok(()), Err)
}

fn retain_failure(
    failures: &mut Option<CiError>,
    outcome: Result<()>,
    mode: crate::failure_mode::FailureMode,
) -> Result<()> {
    if let Err(error) = outcome {
        if mode == crate::failure_mode::FailureMode::StopAfterFailure
            || crate::preparation::active_group().is_some_and(|group| {
                group.requested.load(std::sync::atomic::Ordering::Acquire)
                    || Instant::now() >= group.deadline()
            })
        {
            return Err(match failures.take() {
                Some(primary) => CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(error),
                },
                None => error,
            });
        }
        let mut retained = 0;
        let mut current = failures.as_ref();
        while let Some(CiError::LaneFailures { primary, .. }) = current {
            retained += 1;
            current = Some(primary.as_ref());
        }
        if retained >= 8 {
            eprintln!(
                "additional suite failure omitted: {}",
                crate::command::bounded_excerpt(error.to_string().as_bytes())
            );
            return Ok(());
        }
        *failures = Some(match failures.take() {
            None => error,
            Some(primary) => CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(error),
            },
        });
    }
    Ok(())
}

fn native(
    root: &Path,
    stable: &str,
    release_mode: bool,
    mode: crate::failure_mode::FailureMode,
) -> Result<()> {
    for command in memcordon_ci::native_test_plan::commands_with_failure(release_mode, mode) {
        memcordon_ci::workflow_output::revoke_compilation("compiled-native-complete")?;
        cargo_with_deadline(root, stable, "test", command.arguments, command.deadline)?;
        memcordon_ci::workflow_output::compilation_complete("compiled-native-complete")?;
    }
    Ok(())
}

fn native_phase(
    root: &Path,
    stable: &str,
    mode: crate::failure_mode::FailureMode,
    compile: bool,
) -> Result<()> {
    let command = memcordon_ci::native_test_plan::commands_with_failure(false, mode)
        .into_iter()
        .nth(if compile { 0 } else { 1 })
        .expect("native compile/execute plan");
    memcordon_ci::workflow_output::revoke_compilation("compiled-native-complete")?;
    cargo_with_deadline(root, stable, "test", command.arguments, command.deadline)?;
    memcordon_ci::workflow_output::compilation_complete("compiled-native-complete")?;
    Ok(())
}

fn windows_fixture_native(root: &Path, stable: &str) -> Result<()> {
    if !cfg!(windows) {
        return Err(CiError::Message(
            "native fixture contract requires Windows".into(),
        ));
    }
    memcordon_ci::workflow_output::revoke_compilation("compiled-recipe-complete")?;
    let mut commands = memcordon_ci::native_test_plan::windows_fixture_commands().into_iter();
    let compile = commands.next().expect("fixture compile plan");
    cargo_with_deadline(root, stable, "test", compile.arguments, compile.deadline)?;
    // A settled test failure must not discard successfully compiled outputs.
    // This is compiler completion, never a cached test-success certificate.
    memcordon_ci::workflow_output::compilation_complete("compiled-recipe-complete")?;
    let execute = commands.next().expect("fixture execute plan");
    let output = cargo_with_deadline(root, stable, "test", execute.arguments, execute.deadline)?;
    settled_validation(|| {
        memcordon_ci::windows_fixture_native::verify_one_test(&output).map_err(Into::into)
    })?;
    eprintln!(
        "[ci windows-fixture-native] verified selected-test={}; executed=1; passed=1; failed=0; ignored=0",
        memcordon_ci::windows_fixture_native::TEST_SELECTOR
    );
    Ok(())
}

fn install_tool(root: &Path, stable: &str, name: &str, version: &str) -> Result<()> {
    install_tool_until(
        root,
        stable,
        name,
        version,
        Instant::now() + Duration::from_secs(45 * 60),
    )
}

fn install_tool_until(
    root: &Path,
    stable: &str,
    name: &str,
    version: &str,
    deadline: Instant,
) -> Result<()> {
    crate::preparation::ensure_one_auxiliary_until(
        root,
        name,
        version,
        stable,
        deadline,
        std::num::NonZeroUsize::new(crate::preparation::compiler_budget())
            .expect("positive budget"),
    )?;
    Ok(())
}

fn supply_chain(root: &Path, stable: &str, mode: crate::failure_mode::FailureMode) -> Result<()> {
    supply_pair_with_stable(root, stable, mode)?.into_result()
}

pub(crate) fn supply_pair(
    root: &Path,
    mode: crate::failure_mode::FailureMode,
) -> Result<crate::preparation::PairOutcome<(), ()>> {
    crate::preparation::with_operation(mode, Instant::now() + Duration::from_secs(60 * 60), || {
        supply_pair_with_stable(root, &config::toolchains(root)?.stable, mode)
    })
}

fn supply_pair_with_stable(
    root: &Path,
    stable: &str,
    mode: crate::failure_mode::FailureMode,
) -> Result<crate::preparation::PairOutcome<(), ()>> {
    let deadline = Instant::now() + Duration::from_secs(60 * 60);
    let lockfile = root.join("Cargo.lock");
    let lock_before = supply_input_bytes(&lockfile, 16 * 1024 * 1024)?;
    let tools = config::tools(root)?;
    // Toolchain mutation finishes before either Cargo/tool lane starts.
    CommandSpec::new("rustup", root, Duration::from_secs(900))
        .args(["toolchain", "install", stable, "--profile", "minimal"])
        .bounded_until(deadline)
        .run()?;
    let mut commands = supply_chain_commands(root, stable).into_iter();
    let audit = commands
        .next()
        .expect("audit command")
        .bounded_until(deadline);
    let deny = commands
        .next()
        .expect("deny command")
        .bounded_until(deadline);
    assert!(commands.next().is_none(), "exact supply command inventory");
    let workers = crate::preparation::compiler_budget();
    let layout = if workers == 1 {
        crate::performance_plan::Layout::Serial
    } else {
        crate::performance_plan::Layout::Parallel
    };
    let allocation = crate::preparation::allocate_pair(
        std::num::NonZeroUsize::new(workers).expect("positive budget"),
        layout == crate::performance_plan::Layout::Parallel,
        crate::preparation::active_group().is_some_and(|group| group.inside_parallel_lane()),
        crate::preparation::PairClass::Balanced,
    );
    let audit_jobs = allocation.first;
    let deny_jobs = allocation.second;
    let mut checks = crate::preparation::with_operation(mode, deadline, || {
        Ok(crate::preparation::complete_owned_pair(
            layout,
            [audit_jobs.get(), deny_jobs.get()],
            || {
                memcordon_ci::work_outcome::WorkOutcome::from_result((|| {
                    crate::preparation::ensure_one_auxiliary_until(
                        root,
                        "cargo-audit",
                        &tools.cargo_audit,
                        stable,
                        deadline,
                        audit_jobs,
                    )?;
                    audit.run().map(|_| ())
                })())
            },
            || {
                memcordon_ci::work_outcome::WorkOutcome::from_result((|| {
                    crate::preparation::ensure_one_auxiliary_until(
                        root,
                        "cargo-deny",
                        &tools.cargo_deny,
                        stable,
                        deadline,
                        deny_jobs,
                    )?;
                    deny.run().map(|_| ())
                })())
            },
        ))
    })?;
    let lock_check = supply_input_bytes(&lockfile, 16 * 1024 * 1024).and_then(|after| {
        if after == lock_before {
            Ok(())
        } else {
            Err(CiError::Message(
                "supply-chain operations changed Cargo.lock".into(),
            ))
        }
    });
    checks.first = checks.first.postcondition(lock_check);
    Ok(checks)
}

/// The handoff contains the original lock bytes only; it cannot attest work.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SupplyLockInput {
    checkout: PathBuf,
    commit: Vec<u8>,
    lock: Vec<u8>,
}

fn supply_input_bytes(path: &Path, bound: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > bound {
        return Err(CiError::Message(
            "supply input has unsafe kind or exceeds bound".into(),
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(bound + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > bound {
        return Err(CiError::Message("supply input grew beyond bound".into()));
    }
    Ok(bytes)
}

pub(crate) fn supply_owned_leaf(
    root: &Path,
    suite: Suite,
    mode: crate::failure_mode::FailureMode,
    session: &mut memcordon_ci::segment_cache::Session<'_>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120 * 60);
    crate::preparation::with_operation(mode, deadline, || {
        supply_owned_leaf_until(root, suite, mode, session, deadline)
    })
}

fn supply_owned_leaf_until(
    root: &Path,
    suite: Suite,
    mode: crate::failure_mode::FailureMode,
    session: &mut memcordon_ci::segment_cache::Session<'_>,
    deadline: Instant,
) -> Result<()> {
    use memcordon_ci::work_outcome::WorkOutcome;
    let audit = matches!(suite, Suite::SupplyAudit);
    let name = if audit { "cargo-audit" } else { "cargo-deny" };
    let checkout = root.canonicalize()?;
    let commit = git(root, ["rev-parse", "HEAD"])?;
    let lock = memcordon_ci::ci_operation_time::record_path(root, Path::new("Cargo.lock"))?;
    let before = supply_input_bytes(&lock, 16 * 1024 * 1024)?;
    let stable = config::toolchains(root)?.stable;
    let preparation_deadline = deadline.min(Instant::now() + Duration::from_secs(60 * 60));
    let prepare = WorkOutcome::from_result(crate::preparation::with_operation(
        mode,
        preparation_deadline,
        || {
            if root.canonicalize()? != checkout
                || git(root, ["rev-parse", "HEAD"])? != commit
                || supply_input_bytes(&lock, 16 * 1024 * 1024)? != before
            {
                return Err(CiError::Message("supply lock input changed".into()));
            }
            CommandSpec::new("rustup", root, Duration::from_secs(900))
                .args(["toolchain", "install", &stable, "--profile", "minimal"])
                .bounded_until(preparation_deadline)
                .run()?;
            let tools = config::tools(root)?;
            crate::preparation::ensure_one_auxiliary_until(
                root,
                name,
                if audit {
                    &tools.cargo_audit
                } else {
                    &tools.cargo_deny
                },
                &stable,
                preparation_deadline,
                std::num::NonZeroUsize::new(crate::preparation::compiler_budget())
                    .expect("positive budget"),
            )
            .map(|_| ())
        },
    ));
    session.record_scope_writers(name, prepare.writers())?;
    let outcome = prepare.then_owned(|()| {
        let check_deadline = deadline.min(Instant::now() + Duration::from_secs(60 * 60));
        supply_chain_commands(root, &stable)
            .into_iter()
            .nth(usize::from(!audit))
            .expect("fixed supply command")
            .bounded_until(check_deadline)
            .run_owned()
            .map(|_| ())
    });
    let invariant = (|| {
        if root.canonicalize()? != checkout
            || supply_input_bytes(&lock, 16 * 1024 * 1024)? != before
        {
            return Err(CiError::Message(
                "supply-chain operations changed source or Cargo.lock".into(),
            ));
        }
        Ok(())
    })();
    outcome.postcondition(invariant).into_result()
}

fn supply_leaf(root: &Path, stable: &str, suite: Suite) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60 * 60);
    let audit = matches!(suite, Suite::SupplyAuditPrepare | Suite::SupplyAuditCheck);
    let prepare = matches!(suite, Suite::SupplyAuditPrepare | Suite::SupplyDenyPrepare);
    let name = if audit { "cargo-audit" } else { "cargo-deny" };
    let relative = Path::new("target/ci-session/supply").join(name);
    let handoff = memcordon_ci::ci_operation_time::record_path(root, &relative)?;
    let lock = memcordon_ci::ci_operation_time::record_path(root, Path::new("Cargo.lock"))?;
    let checkout = root.canonicalize()?;
    let commit = git(root, ["rev-parse", "HEAD"])?;
    let before = if prepare {
        use std::io::Write;
        let bytes = supply_input_bytes(&lock, 16 * 1024 * 1024)?;
        let record = SupplyLockInput {
            checkout: checkout.clone(),
            commit: commit.clone(),
            lock: bytes.clone(),
        };
        fs::create_dir_all(handoff.parent().expect("fixed parent"))?;
        let path = memcordon_ci::ci_operation_time::record_path(root, &relative)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&serde_json::to_vec(&record)?)?;
        file.sync_all()?;
        bytes
    } else {
        let record: SupplyLockInput =
            serde_json::from_slice(&supply_input_bytes(&handoff, 64 * 1024 * 1024)?)?;
        if record.checkout != checkout
            || record.commit != commit
            || record.lock.len() > 16 * 1024 * 1024
        {
            return Err(CiError::Message(
                "supply lock input belongs to different source".into(),
            ));
        }
        record.lock
    };
    let operation = (|| {
        if supply_input_bytes(&lock, 16 * 1024 * 1024)? != before {
            return Err(CiError::Message("supply lock input changed".into()));
        }
        if prepare {
            CommandSpec::new("rustup", root, Duration::from_secs(900))
                .args(["toolchain", "install", stable, "--profile", "minimal"])
                .bounded_until(deadline)
                .run()?;
            let tools = config::tools(root)?;
            crate::preparation::ensure_one_auxiliary_until(
                root,
                name,
                if audit {
                    &tools.cargo_audit
                } else {
                    &tools.cargo_deny
                },
                stable,
                deadline,
                std::num::NonZeroUsize::new(crate::preparation::compiler_budget())
                    .expect("positive budget"),
            )?;
            Ok(())
        } else {
            supply_chain_commands(root, stable)
                .into_iter()
                .nth(usize::from(!audit))
                .expect("fixed supply command")
                .bounded_until(deadline)
                .run()
                .map(|_| ())
        }
    })();
    let invariant = supply_input_bytes(&lock, 16 * 1024 * 1024).and_then(|after| {
        if after == before {
            Ok(())
        } else {
            Err(CiError::Message(
                "supply-chain operations changed Cargo.lock".into(),
            ))
        }
    });
    memcordon_ci::work_outcome::WorkOutcome::from_result(operation)
        .postcondition(invariant)
        .into_result()
}

fn miri(
    root: &Path,
    nightly: &str,
    shard: Option<memcordon_ci::target_shard::ShardSpec>,
    target_directory: &Path,
    mode: crate::failure_mode::FailureMode,
) -> Result<()> {
    CommandSpec::new("rustup", root, Duration::from_secs(10 * 60))
        .args([
            "toolchain",
            "install",
            nightly,
            "--profile",
            "minimal",
            "--component",
            "miri",
        ])
        .run()?;
    memcordon_ci::miri_cache::ensure(root, nightly, Instant::now() + Duration::from_secs(900))?;
    let metadata = cargo(
        root,
        nightly,
        "metadata",
        ["--format-version", "1", "--no-deps", "--locked"],
    )?;
    let targets = memcordon_ci::work_outcome::WorkOutcome::from_result(Ok(metadata.as_slice()))
        .map_validated(|metadata| match shard {
            Some(shard) => {
                memcordon_ci::miri_targets::plan_partition(metadata, "memcordon-core", shard)
            }
            None => memcordon_ci::miri_targets::plan(metadata, "memcordon-core"),
        })
        .into_result()?;
    let name = match shard.map(|s| (s.index(), s.count())) {
        Some((0, 2)) => "first.json",
        Some((1, 2)) => "second.json",
        Some((0, 4)) => "quarter-one.json",
        Some((1, 4)) => "quarter-two.json",
        Some((2, 4)) => "quarter-three.json",
        Some((3, 4)) => "quarter-four.json",
        None => "all.json",
        _ => return Err(CiError::Message("unsupported Miri partition".into())),
    };
    write_plan(
        root,
        "miri",
        name,
        &serde_json::json!({"planner_version": 1, "package": "memcordon-core", "shard_index": shard.map(|s| s.index()), "shard_count": shard.map(|s| s.count()), "targets": targets}),
    )?;
    let mut failures = None;
    for target in targets {
        let outcome = (|| -> Result<()> {
            let mut arguments = vec![
                OsString::from("test"),
                OsString::from("--target-dir"),
                target_directory.as_os_str().to_owned(),
                OsString::from("--package"),
                OsString::from("memcordon-core"),
                OsString::from("--locked"),
            ];
            arguments.extend(target.arguments().into_iter().map(OsString::from));
            if target == memcordon_ci::miri_targets::MiriTarget::Integration("report".into()) {
                let mut list = arguments.clone();
                list.extend(["--", "--list", "--format", "terse"].map(OsString::from));
                let all = cargo(root, nightly, "miri", &list)?;
                list.push(OsString::from("--ignored"));
                let ignored = cargo(root, nightly, "miri", &list)?;
                let batches = settled_validation(|| {
                    memcordon_ci::miri_targets::report_batches(&all, &ignored)
                })?;
                write_plan(
                    root,
                    "miri",
                    "report-batches.json",
                    &serde_json::json!({
                        "planner_version": 1, "target": "report", "command_deadline_seconds": CARGO_DEADLINE.as_secs(), "batches": batches
                    }),
                )?;
                for batch in batches {
                    let mut command = arguments.clone();
                    command.push(OsString::from("--"));
                    command.extend(batch.arguments().into_iter().map(OsString::from));
                    retain_failure(
                        &mut failures,
                        cargo(root, nightly, "miri", command).map(|_| ()),
                        mode,
                    )?;
                }
            } else {
                // Concurrency-sensitive harnesses remain intact, including their
                // inter-test races. The original 900s command deadline applies.
                cargo(root, nightly, "miri", arguments)?;
            }
            Ok(())
        })();
        retain_failure(&mut failures, outcome, mode)?;
    }
    failures.map_or(Ok(()), Err)
}

fn fuzz(
    root: &Path,
    stable: &str,
    nightly: &str,
    shard: Option<memcordon_ci::target_shard::ShardSpec>,
    mode: crate::failure_mode::FailureMode,
) -> Result<()> {
    fuzz_phase(root, stable, nightly, shard, true, true, mode)
}

fn fuzz_phase(
    root: &Path,
    stable: &str,
    nightly: &str,
    shard: Option<memcordon_ci::target_shard::ShardSpec>,
    compile: bool,
    execute: bool,
    mode: crate::failure_mode::FailureMode,
) -> Result<()> {
    let target_plans = memcordon_ci::fuzz_targets::plans_sharded(
        &std::fs::read_to_string(root.join("fuzz").join("Cargo.toml"))?,
        shard,
    )?;
    let targets: Vec<_> = target_plans.iter().map(|target| &target.name).collect();
    let name = match shard.map(|s| (s.index(), s.count())) {
        None => "all.json",
        Some((0, 2)) => "first.json",
        Some((1, 2)) => "second.json",
        Some((0, 4)) => "quarter-one.json",
        Some((1, 4)) => "quarter-two.json",
        Some((2, 4)) => "quarter-three.json",
        Some((3, 4)) => "quarter-four.json",
        _ => return Err(CiError::Message("unsupported managed fuzz shard".into())),
    };
    write_plan(
        root,
        "fuzz",
        name,
        &serde_json::json!({"planner_version": 2, "shard_index": shard.map(|s| s.index()), "shard_count": shard.map(|s| s.count()), "targets": targets,"target_plans":target_plans}),
    )?;
    cargo(
        root,
        stable,
        "test",
        [
            "--locked",
            "--package",
            "memcordon-core",
            "--test",
            "workload_independent_vectors",
            "--",
            "--ignored",
            "--exact",
            "write_portable_fuzz_seed_corpora",
        ],
    )?;
    let tools = config::tools(root)?;
    install_tool(root, stable, "cargo-fuzz", &tools.cargo_fuzz)?;
    CommandSpec::new("rustup", root, Duration::from_secs(10 * 60))
        .args(["toolchain", "install", nightly, "--profile", "minimal"])
        .run()?;
    let cargo_fuzz = crate::preparation::auxiliary_tool(root, "cargo-fuzz")?;
    if targets.is_empty() {
        return Err(CiError::Message("fuzz selection is empty".into()));
    }
    let mut failures = None;
    if compile {
        for target in &target_plans {
            let arguments = target.build_arguments();
            announce_fuzz_command("compile", &target.name, nightly, &cargo_fuzz, &arguments);
            let outcome = CommandSpec::toolchain_program(
                "rustup",
                root,
                nightly,
                &cargo_fuzz,
                CARGO_DEADLINE,
            )
            .args(arguments)
            .run()
            .map(|_| ());
            retain_failure(&mut failures, outcome, mode)?;
        }
    }
    // A partially failed compile phase supplies no execution evidence.
    if let Some(error) = failures.take() {
        return Err(error);
    }
    if compile {
        memcordon_ci::workflow_output::compilation_complete("compiled-recipe-complete")?;
    }
    if execute {
        // `cargo fuzz run` may compile again. A failed later writer must not
        // retain a completion claim from the earlier build recipe.
        memcordon_ci::workflow_output::revoke_compilation("compiled-recipe-complete")?;
        for target in &target_plans {
            let arguments = target.run_arguments();
            announce_fuzz_command("execute", &target.name, nightly, &cargo_fuzz, &arguments);
            let outcome = CommandSpec::toolchain_program(
                "rustup",
                root,
                nightly,
                &cargo_fuzz,
                Duration::from_secs(5 * 60),
            )
            .args(arguments)
            .run()
            .map(|_| ());
            retain_failure(&mut failures, outcome, mode)?;
        }
    }
    failures.map_or(Ok(()), Err)
}

fn announce_fuzz_command(
    phase: &'static str,
    target: &str,
    toolchain: &str,
    program: &Path,
    arguments: &[OsString],
) {
    use std::io::Write;
    let observed = |value: &OsStr| {
        let bytes = value.as_encoded_bytes();
        let end = bytes.len().min(512);
        serde_json::json!({"prefix_hex":hex::encode(&bytes[..end]),"original_bytes":bytes.len(),"omitted_bytes":bytes.len()-end})
    };
    let record = serde_json::json!({"format":"memcordon.fuzz-command","revision":1,"phase":phase,
        "target":observed(OsStr::new(target)),"toolchain":observed(OsStr::new(toolchain)),
        "selected_program":observed(program.as_os_str()),
        "arguments":arguments.iter().take(16).map(|value|observed(value.as_os_str())).collect::<Vec<_>>(),
        "omitted_argument_count":arguments.len().saturating_sub(16)});
    // Release the diagnostic sink before the native command/progress workers run.
    let _ = writeln!(std::io::stderr().lock(), "fuzz-command {record}");
}

fn write_plan(root: &Path, family: &str, name: &str, value: &serde_json::Value) -> Result<()> {
    settled_validation(|| {
        let directory = root.join("target/ci/reports").join(family);
        fs::create_dir_all(&directory)?;
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        fs::write(directory.join(name), bytes)?;
        Ok(())
    })
}

fn shard(index: usize, count: usize) -> memcordon_ci::target_shard::ShardSpec {
    memcordon_ci::target_shard::ShardSpec::new(
        index,
        std::num::NonZeroUsize::new(count).expect("nonzero suite shard"),
    )
    .expect("valid suite shard")
}

fn certification_cargo(
    root: &Path,
    rustup: &Path,
    toolchain: &str,
    subcommand: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    deadline: Duration,
) -> Result<Vec<u8>> {
    let mut command_arguments = vec![OsString::from(subcommand)];
    command_arguments.extend(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string()),
    );
    CommandSpec::cargo(rustup, root, toolchain, deadline)
        .args(command_arguments)
        .run()
}

fn run_hard_scenario(
    root: &Path,
    rustup: &Path,
    stable: &str,
    scenario: HardBackendScenario,
    deadline: Duration,
) -> Result<()> {
    let mut arguments = match scenario.target {
        CargoTestTarget::BackendContract => vec![
            OsString::from("--target-dir"),
            OsString::from("target/ci/standard-backend"),
            OsString::from("--locked"),
            OsString::from("--package"),
            OsString::from("memcordon"),
            OsString::from("--features"),
            OsString::from("test-fixtures"),
            OsString::from("--test"),
            OsString::from("backend_contract"),
        ],
        CargoTestTarget::PlatformTest(test_binary) => vec![
            OsString::from("--target-dir"),
            OsString::from("target/ci/standard-backend"),
            OsString::from("--locked"),
            OsString::from("--package"),
            OsString::from("memcordon-platform"),
            OsString::from("--features"),
            OsString::from("test-support"),
            OsString::from("--test"),
            OsString::from(test_binary),
        ],
    };
    arguments.push(OsString::from("--"));
    arguments.push(OsString::from(scenario.exact_name));
    arguments.push(OsString::from("--exact"));
    if scenario.ignored {
        arguments.push(OsString::from("--ignored"));
    }
    arguments.extend([
        OsString::from("--format"),
        OsString::from("pretty"),
        OsString::from("--color"),
        OsString::from("never"),
        OsString::from("--test-threads"),
        OsString::from("1"),
    ]);
    let output = certification_cargo(root, rustup, stable, "test", arguments, deadline)?;
    settled_validation(|| {
        capability::require_exact_standard_test_success(&output, scenario.exact_name)
    })
}

fn backend_suite(root: &Path, rustup: &Path, stable: &str, backend: &str) -> Result<()> {
    let expected_os = match backend {
        "linux-cgroup-v2" => "linux",
        "windows-job-object" => "windows",
        _ => return Err(CiError::Message("unknown standard backend".into())),
    };
    if std::env::consts::OS != expected_os {
        return Err(CiError::Message("wrong native backend platform".into()));
    }
    let started = std::time::Instant::now();
    let remaining = || {
        settled_validation(|| {
            CERTIFICATION_DEADLINE
                .checked_sub(started.elapsed())
                .filter(|time| !time.is_zero())
                .ok_or_else(|| CiError::Message("native backend suite deadline exhausted".into()))
        })
    };
    let probe = certification_cargo(
        root,
        rustup,
        stable,
        "run",
        [
            "--target-dir",
            "target/ci/standard-backend",
            "--locked",
            "--package",
            "memcordon",
            "--bin",
            "memcordon",
            "--",
            "doctor",
            "--json",
        ],
        remaining()?.min(CARGO_DEADLINE),
    )?;
    settled_validation(|| {
        capability::require_certified_standard_backend(&serde_json::from_slice(&probe)?, backend)
    })?;
    let scenarios =
        settled_validation(|| memcordon_ci::standard_contract::hard_backend_scenarios(backend))?;
    if scenarios.is_empty() {
        return Err(CiError::Message(
            "native backend suite has no scenarios".into(),
        ));
    }
    for scenario in scenarios {
        run_hard_scenario(
            root,
            rustup,
            stable,
            scenario,
            remaining()?.min(CARGO_DEADLINE),
        )?;
    }
    Ok(())
}

fn current_uid(root: &Path) -> Result<String> {
    let output = CommandSpec::new("/usr/bin/id", root, Duration::from_secs(30))
        .arg("-u")
        .run()?;
    let uid = String::from_utf8(output)
        .map_err(|error| CiError::Message(format!("id returned non-UTF-8 output: {error}")))?
        .trim()
        .to_owned();
    if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CiError::Message(format!(
            "id returned an invalid numeric uid: {uid:?}"
        )));
    }
    Ok(uid)
}

fn resolve_rustup() -> Result<PathBuf> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| CiError::Message("PATH is unavailable while resolving rustup".to_owned()))?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("rustup"))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| CiError::Message("could not resolve rustup to an absolute path".to_owned()))
}

fn launch_delegated_linux_backend(root: &Path) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(CiError::Message(
            "Linux backend suite requires native Linux".into(),
        ));
    }
    let uid = current_uid(root)?;
    if uid == "0" {
        return Err(CiError::Message(
            "Linux backend suite must start unprivileged".into(),
        ));
    }
    let directory = tempfile::Builder::new()
        .prefix("memcordon-standard-")
        .suffix(".service")
        .tempdir()?;
    let unit = directory
        .path()
        .file_name()
        .ok_or_else(|| CiError::Message("missing owned unit basename".into()))?
        .to_os_string();
    let text = unit
        .to_str()
        .ok_or_else(|| CiError::Message("invalid owned unit encoding".into()))?;
    if !text.ends_with(".service")
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CiError::Message("invalid owned delegation unit".into()));
    }
    let rustup = resolve_rustup()?;
    let executable = std::env::current_exe()?;
    let mut arguments: Vec<OsString> = [
        "--non-interactive",
        "--",
        "/usr/bin/systemd-run",
        "--wait",
        "--pipe",
        "--collect",
        "--service-type",
        "exec",
        "--expand-environment=no",
        "--unit",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    arguments.push(unit.clone());
    arguments.push("--uid".into());
    arguments.push(uid.clone().into());
    arguments.extend(
        [
            "--property",
            "Delegate=memory",
            "--property",
            "DelegateSubgroup=memcordon-ci",
            "--property",
            "RuntimeMaxSec=60min",
            "--property",
            "TimeoutStartSec=2min",
            "--property",
            "TimeoutStopSec=30s",
            "--property",
            "KillMode=control-group",
            "--property",
            "Restart=no",
            "--working-directory",
        ]
        .map(OsString::from),
    );
    arguments.push(root.as_os_str().to_os_string());
    arguments.push("--".into());
    arguments.push(executable.into_os_string());
    arguments.extend(["delegated-linux-backend", "--rustup"].map(OsString::from));
    arguments.push(rustup.into_os_string());
    arguments.push("--uid".into());
    arguments.push(uid.into());
    let mut lease = memcordon_ci::standard_runner::DelegatedUnitLease::new(root, unit)?;
    let execution = CommandSpec::new("/usr/bin/sudo", root, Duration::from_secs(65 * 60))
        .args(arguments)
        .run();
    let retirement = lease.retire();
    memcordon_ci::standard_runner::finish_delegation(execution, retirement, directory.close())?;
    Ok(())
}

pub fn delegated_linux_backend(root: &Path, rustup: &Path, expected_uid: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(CiError::Message(
            "delegated Linux backend invoked on wrong platform".into(),
        ));
    }
    let uid = current_uid(root)?;
    if uid == "0" || uid != expected_uid {
        return Err(CiError::Message(
            "delegation did not preserve unprivileged uid".into(),
        ));
    }
    let toolchains = config::toolchains(root)?;
    backend_suite(root, rustup, &toolchains.stable, "linux-cgroup-v2")
}

fn macos_deadline(root: &Path, stable: &str) -> Result<()> {
    let mut exact = memcordon_ci::exact_harness::ExactHarnessRunner::default();
    if !cfg!(target_os = "macos") {
        return Err(CiError::Message(
            "macos-deadline requires native macOS".into(),
        ));
    }
    let evidence = root.join("target/ci/deadline-evidence");
    if evidence.exists() {
        fs::remove_dir_all(&evidence)?;
    }
    fs::create_dir_all(&evidence)?;
    fs::write(
        evidence.join("begin.json"),
        b"{\"schema_version\":1,\"status\":\"building\"}\n",
    )?;
    let result = (|| -> Result<()> {
        for scenario in [
            "pending_metric_query_is_answered_before_empty_inspector_retirement",
            "malformed_native_pid_listings_never_certify_absence",
            "unresolved_known_identity_is_retained_even_after_root_exit",
            "mutation_unknown_member_dropping_is_detected",
            "unrelated_inaccessible_process_does_not_poison_scoped_absence",
            "unresolved_new_group_member_prevents_false_empty_inventory",
            "positively_observed_pid_replacement_discharges_only_old_identity",
            "detached_child_survives_root_exit_and_group_change",
            "new_confirmed_members_survive_a_concurrent_metadata_failure",
        ] {
            exact.run(
                root,
                stable,
                "target/ci/deadline-build",
                "memcordon-platform",
                "test-support",
                "macos_inventory",
                scenario,
            )?;
        }
        exact.run_selected(
            root,
            stable,
            "target/ci/deadline-build",
            "memcordon",
            "test-fixtures",
            "macos_remediation",
            crate::native_acceptance_catalogue::MACOS_REMEDIATION_SCENARIOS,
        )?;
        exact.run(
            root,
            stable,
            "target/ci/deadline-build",
            "memcordon",
            "test-fixtures",
            "result_delivery",
            "result_writer_stalls_before_write_rename_and_ack_are_cancelled_and_reaped",
        )?;
        let mut admission = Vec::new();
        for (package, feature, scenario) in
            crate::native_acceptance_catalogue::MACOS_ADMISSION_SCENARIOS
        {
            exact.run(
                root,
                stable,
                "target/ci/deadline-build",
                package,
                feature,
                "macos_admission",
                scenario,
            )?;
            admission.push(serde_json::json!({"package": package, "target": "macos_admission", "scenario": scenario, "executed": 1, "passed": 1}));
        }
        settled_validation(|| {
            let mut admission_bytes = serde_json::to_vec_pretty(&admission)?;
            admission_bytes.push(b'\n');
            fs::write(evidence.join("admission-inventory.json"), admission_bytes)?;
            Ok(())
        })?;
        let mut mutations = Vec::new();
        for (package, target, scenario) in
            crate::native_acceptance_catalogue::MACOS_MUTATION_SCENARIOS
        {
            exact.run(
                root,
                stable,
                "target/ci/deadline-build",
                package,
                "test-support",
                target,
                scenario,
            )?;
            mutations.push(serde_json::json!({"package": package, "target": target, "scenario": scenario, "executed": 1, "passed": 1}));
        }
        settled_validation(|| {
            let mut inventory = serde_json::to_vec_pretty(
                &serde_json::json!({"schema_version": 1, "native_scenarios": crate::native_acceptance_catalogue::MACOS_REMEDIATION_SCENARIOS, "writer_barrier_scenarios": 3, "mutations": mutations}),
            )?;
            inventory.push(b'\n');
            fs::write(evidence.join("native-inventory.json"), inventory)?;
            Ok(())
        })?;
        cargo(
            root,
            stable,
            "build",
            [
                "--locked",
                "--target-dir",
                "target/ci/deadline-build",
                "--package",
                "memcordon",
                "--bin",
                "memcordon",
            ],
        )?;
        cargo(
            root,
            stable,
            "test",
            [
                "--locked",
                "--target-dir",
                "target/ci/deadline-oracle-build",
                "--package",
                "memcordon-deadline-oracle",
            ],
        )?;
        cargo(
            root,
            stable,
            "build",
            [
                "--locked",
                "--target-dir",
                "target/ci/deadline-oracle-build",
                "--package",
                "memcordon-deadline-oracle",
            ],
        )?;
        CommandSpec::new(
            root.join("target/ci/deadline-oracle-build/debug/memcordon-deadline-oracle"),
            root,
            Duration::from_secs(90),
        )
        .arg(root.join("target/ci/deadline-build/debug/memcordon"))
        .arg(&evidence)
        .run()?;
        Ok(())
    })();
    let diagnostic = (|| -> Result<()> {
        if let Err(error) = &result {
            let mut bytes = serde_json::to_vec_pretty(
                &serde_json::json!({"schema_version": 1, "passed": false, "error": error.to_string()}),
            )?;
            bytes.push(b'\n');
            fs::write(evidence.join("suite-final.json"), &bytes)?;
            if !evidence.join("final.json").exists() {
                let mut aggregate = serde_json::to_vec_pretty(
                    &serde_json::json!({"schema_version": 2, "passed": false, "error": error.to_string()}),
                )?;
                aggregate.push(b'\n');
                fs::write(evidence.join("final.json"), aggregate)?;
            }
        }
        Ok(())
    })();
    memcordon_ci::work_outcome::WorkOutcome::from_result(result)
        .postcondition(diagnostic)
        .into_result()
}

pub fn release_macos_native(root: &Path, stable: &str) -> Result<()> {
    let mut exact = memcordon_ci::exact_harness::ExactHarnessRunner::default();
    memcordon_ci::macos_performance::require_native_host(root, stable)?;
    if !cfg!(target_os = "macos") {
        return Err(CiError::Message(
            "macOS acceptance was invoked on the wrong platform".to_owned(),
        ));
    }
    for (target, scenarios) in [
        (
            "lifecycle",
            crate::native_acceptance_catalogue::MACOS_LIFECYCLE_SCENARIOS,
        ),
        (
            "macos_remediation",
            crate::native_acceptance_catalogue::MACOS_REMEDIATION_SCENARIOS,
        ),
    ] {
        exact.run_selected(
            root,
            stable,
            "target/ci/backend-macos",
            "memcordon",
            "test-support",
            target,
            scenarios,
        )?;
    }
    macos_deadline(root, stable)?;
    write_macos_report(
        root,
        "release-macos-native.json",
        crate::native_acceptance_catalogue::MACOS_LIFECYCLE_SCENARIOS
            .iter()
            .chain(crate::native_acceptance_catalogue::MACOS_REMEDIATION_SCENARIOS)
            .copied()
            .collect(),
    )
}

pub fn release_macos_acceptance(root: &Path, stable: &str) -> Result<()> {
    memcordon_ci::macos_performance::require_native_host(root, stable)?;
    if !cfg!(target_os = "macos") {
        return Err(CiError::Message(
            "macOS acceptance invoked on wrong platform".into(),
        ));
    }
    cargo(
        root,
        stable,
        "build",
        [
            "--locked",
            "--package",
            "memcordon",
            "--features",
            "test-fixtures",
            "--bin",
            "memcordon-test-fixture",
            "--target-dir",
            "target/ci/backend-macos",
        ],
    )?;
    // This isolated candidate-package installation never replaces the user's verifier.
    cargo(
        root,
        stable,
        "install",
        [
            "--path",
            "crates/memcordon-cli",
            "--root",
            "target/ci/macos-installed",
            "--target-dir",
            "target/ci/backend-macos",
            "--debug",
            "--locked",
            "--force",
        ],
    )?;
    let installed = root.join("target/ci/macos-installed/bin/memcordon");
    let bytes = CommandSpec::new(&installed, root, Duration::from_secs(10))
        .args(["doctor", "--probe-execution", "--json"])
        .run()?;
    let probe: serde_json::Value = serde_json::from_slice(&bytes)?;
    if probe["kind"] != "doctor-execution-probe"
        || probe["schema_version"] != 1
        || probe["execution"]["helper_ready"] != true
        || probe["execution"]["target_exec_confirmed"] != true
        || probe["execution"]["target_exit"] != 0
        || probe["execution"]["cleanup_complete"] != true
    {
        return Err(CiError::Message(
            "installed macOS execution probe lacks complete native lifecycle evidence".into(),
        ));
    }
    let deadline = CommandSpec::new(&installed, root, Duration::from_secs(5))
        .args(["+100ms", "--"])
        .arg(root.join("target/ci/backend-macos/debug/memcordon-test-fixture"))
        .args(["hold", "--duration", "5s"])
        .output()?;
    if deadline.status.code() != Some(123) {
        return Err(CiError::Message(
            "installed macOS package did not enforce its deadline".into(),
        ));
    }
    let fixture = root.join("target/ci/backend-macos/debug/memcordon-test-fixture");
    let measured = |path: &Path| -> Result<memcordon_ci::external_consumer::MeasuredExecutable> {
        let path = fs::canonicalize(path)?;
        Ok(memcordon_ci::external_consumer::MeasuredExecutable {
            sha256: memcordon_ci::release::artifacts::checksum(
                &memcordon_ci::release::artifacts::read_file(&path)?,
            ),
            path,
        })
    };
    let spec = memcordon_ci::external_consumer::ExternalConsumerSpec {
        format: "memcordon.external-consumer".into(),
        revision: 2,
        target: memcordon_ci::release::distribution::native_target()?.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        runtime_features: Vec::new(),
        selection: memcordon_ci::external_consumer::Selection::MeasuredCli,
        selected_inputs: Vec::new(),
        cli: measured(&installed)?,
        workload: measured(&fixture)?,
        working_directory: fs::canonicalize(root)?,
        arguments: ["exit", "--code", "0"]
            .into_iter()
            .map(|argument| memcordon_core::NativeArgument::from_os(std::ffi::OsStr::new(argument)))
            .collect(),
        report_format: "standard".into(),
        report_revision: 10,
        expected_outcome: memcordon_core::execution_facts::OutcomeKindV1::Completed,
        expected_native_termination: Some(memcordon_core::ChildTermination::ExitCode { code: 0 }),
        expected_wrapper_status: 0,
        coverage: memcordon_ci::external_consumer::ExpectedCoverage::Bytes {
            stdout_sha256: memcordon_ci::release::artifacts::checksum(b""),
            stderr_sha256: memcordon_ci::release::artifacts::checksum(b""),
        },
        outer_deadline_millis: 30_000,
    };
    let operation = tempfile::Builder::new()
        .prefix("memcordon-macos-acceptance-")
        .tempdir_in("/tmp")?
        .keep();
    let raw = operation.join("external");
    let assessment = memcordon_ci::external_consumer::run(&spec, &raw);
    let reports = root.join("target/ci/reports");
    fs::create_dir_all(&reports)?;
    let retained = reports.join(
        operation
            .file_name()
            .expect("native temporary operation has a basename"),
    );
    fs::create_dir(&retained)?;
    // Preserve every actual raw file, including partial observations on error.
    // The retained /tmp operation also survives an artifact collection error.
    if raw.try_exists()? {
        memcordon_ci::external_consumer::retain_diagnostics(&raw, &retained)?;
    }
    let assessment = assessment?;
    if !assessment.passed() {
        return Err(CiError::Message(
            "installed macOS typed consumer execution, collection or retirement failed".into(),
        ));
    }
    write_macos_report(
        root,
        "release-macos-acceptance.json",
        vec![
            "installed_package_execution_probe_and_deadline",
            "installed_package_typed_external_consumer",
        ],
    )
}

fn write_macos_report(root: &Path, filename: &str, scenarios: Vec<&str>) -> Result<()> {
    let commit =
        memcordon_ci::work_outcome::WorkOutcome::from_result(git(root, ["rev-parse", "HEAD"]))
            .map_validated(|bytes| {
                Ok(String::from_utf8(bytes)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .trim()
                    .to_owned())
            })
            .into_result()?;
    settled_validation(|| {
        let report = memcordon_ci::native_results::NativeTestReport {
            schema_version: 1,
            backend: "macos-watchdog".into(),
            tests_run: scenarios.len(),
            tests_skipped: 0,
            tests: scenarios
                .into_iter()
                .map(|name| memcordon_ci::native_results::NativeTestResult {
                    name: name.into(),
                    result: memcordon_ci::native_results::NativeTestOutcome::Passed,
                })
                .collect(),
            source_commit: commit,
        };
        let reports = root.join("target").join("ci").join("reports");
        fs::create_dir_all(&reports)?;
        let mut bytes = if let Some(phase) = match filename {
            "release-macos-native.json" => Some("native"),
            "release-macos-acceptance.json" => Some("acceptance"),
            _ => None,
        } {
            serde_json::to_vec_pretty(&memcordon_ci::macos_performance::MacosPhaseReport {
                format: "memcordon.macos-executed-phase".into(),
                revision: 1,
                host_os: std::env::consts::OS.into(),
                host_arch: std::env::consts::ARCH.into(),
                phase: phase.into(),
                native: report,
            })?
        } else {
            serde_json::to_vec_pretty(&report)?
        };
        bytes.push(b'\n');
        fs::write(reports.join(filename), bytes)?;
        Ok(())
    })
}

/// Complete sequential compatibility form. Optional job splitting changes
/// scheduling only; each selected phase remains required by the workflow.
pub fn release_macos(root: &Path, stable: &str) -> Result<()> {
    memcordon_ci::macos_performance::require_native_host(root, stable)?;
    let commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    memcordon_ci::macos_performance::clear_local_phases(root)?;
    release_macos_native(root, stable)?;
    release_macos_acceptance(root, stable)?;
    settled_validation(|| {
        memcordon_ci::macos_performance::validate_local_completed(
            root,
            &commit,
            std::env::consts::ARCH,
        )
    })?;
    write_macos_report(
        root,
        "backend-macos-watchdog.json",
        crate::native_acceptance_catalogue::macos_scenarios(),
    )
}

pub(crate) struct SuiteOptions {
    pub failure_mode: crate::failure_mode::FailureMode,
}

pub fn run(root: &Path, suite: Suite, options: SuiteOptions) -> Result<()> {
    run_with(suite, options, |options| run_result(root, suite, options))
}

pub(crate) fn run_with(
    suite: Suite,
    options: SuiteOptions,
    operation: impl FnOnce(SuiteOptions) -> Result<()>,
) -> Result<()> {
    let mode = suite.resolve_failure_mode(memcordon_ci::suite::ModeRequest::Explicit(
        options.failure_mode,
    ))?;
    let options = SuiteOptions { failure_mode: mode };
    let result = operation(options);
    if result.is_ok()
        && !matches!(
            suite,
            Suite::Policy
                | Suite::SupplyChain
                | Suite::SupplyAudit
                | Suite::SupplyDeny
                | Suite::SupplyAuditPrepare
                | Suite::SupplyAuditCheck
                | Suite::SupplyDenyPrepare
                | Suite::SupplyDenyCheck
                | Suite::NativeCompile
                | Suite::NativeExecute
                | Suite::WorkspaceFetch
                | Suite::FuzzFetch
                | Suite::PrepareTools
                | Suite::PrepareFuzz
                | Suite::PrepareMiriComponents
                | Suite::MiriSetup
        )
    {
        memcordon_ci::workflow_output::compilation_complete("compiled-recipe-complete")?;
    }
    result
}

fn run_result(root: &Path, suite: Suite, options: SuiteOptions) -> Result<()> {
    if matches!(
        suite,
        Suite::SupplyAudit
            | Suite::SupplyDeny
            | Suite::Policy
            | Suite::Stress
            | Suite::StressPackages
            | Suite::StressLifecycle
            | Suite::BackendLinuxCgroup
            | Suite::BackendLinuxPrivate
            | Suite::BackendLinuxPrivatePrepare
            | Suite::BackendLinuxPrivateRuntime
            | Suite::BackendWindowsJob
            | Suite::BackendWindowsSealed
            | Suite::BackendMacosWatchdog
            | Suite::ReleaseMacosNative
            | Suite::ReleaseMacosAcceptance
            | Suite::MacosDeadline
    ) {
        return run_inner(root, suite, options);
    }
    let deadline = Instant::now()
        + Duration::from_secs(
            if matches!(
                suite,
                Suite::Msrv
                    | Suite::Quality
                    | Suite::QualityCompile
                    | Suite::QualityCompiler
                    | Suite::ReleaseQualityCompiler
                    | Suite::QualityDocumentation
            ) {
                90 * 60
            } else {
                60 * 60
            },
        );
    crate::preparation::with_operation(options.failure_mode, deadline, || {
        run_inner(root, suite, options)
    })
}

fn run_inner(root: &Path, suite: Suite, options: SuiteOptions) -> Result<()> {
    let toolchains = config::toolchains(root)?;
    let phased_fuzz = match suite {
        Suite::FuzzCompileFirst => Some((0, 2, true)),
        Suite::FuzzCompileSecond => Some((1, 2, true)),
        Suite::FuzzCompileQuarterOne => Some((0, 4, true)),
        Suite::FuzzCompileQuarterTwo => Some((1, 4, true)),
        Suite::FuzzCompileQuarterThree => Some((2, 4, true)),
        Suite::FuzzCompileQuarterFour => Some((3, 4, true)),
        Suite::FuzzExecuteFirst => Some((0, 2, false)),
        Suite::FuzzExecuteSecond => Some((1, 2, false)),
        Suite::FuzzExecuteQuarterOne => Some((0, 4, false)),
        Suite::FuzzExecuteQuarterTwo => Some((1, 4, false)),
        Suite::FuzzExecuteQuarterThree => Some((2, 4, false)),
        Suite::FuzzExecuteQuarterFour => Some((3, 4, false)),
        _ => None,
    };
    if let Some((index, count, compile)) = phased_fuzz {
        return fuzz_phase(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(index, count)),
            compile,
            !compile,
            options.failure_mode,
        );
    }
    match suite {
        Suite::WorkspaceFetch
        | Suite::FuzzFetch
        | Suite::PrepareTools
        | Suite::PrepareFuzz
        | Suite::PrepareMiriComponents
        | Suite::MiriSetup
        | Suite::ReleaseBuild
        | Suite::ReleaseCompile
        | Suite::ReleaseValidatePackage
        | Suite::WorkingWindowsPrepare
        | Suite::RehearsalToolBuild
        | Suite::ReleaseReadiness => {
            crate::ci_segments::operation(root, suite, options.failure_mode)
        }
        Suite::Policy => policy::run(root),
        Suite::Quality => quality(root, &toolchains.stable, options.failure_mode),
        Suite::QualityCompile => quality_compile(root, &toolchains.stable, options.failure_mode),
        Suite::QualityCompiler | Suite::ReleaseQualityCompiler | Suite::QualityDocumentation => {
            quality_leaf(root, &toolchains.stable, options.failure_mode, suite)
        }
        Suite::Msrv => msrv(root, &toolchains.msrv, options.failure_mode),
        Suite::Native => native(root, &toolchains.stable, false, options.failure_mode),
        Suite::NativeCompile => native_phase(root, &toolchains.stable, options.failure_mode, true),
        Suite::NativeExecute => native_phase(root, &toolchains.stable, options.failure_mode, false),
        Suite::WindowsFixtureNative => windows_fixture_native(root, &toolchains.stable),
        Suite::FuzzCompileFirst
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
        | Suite::FuzzExecuteQuarterFour => unreachable!("phased fuzz handled above"),
        Suite::SupplyChain => supply_chain(root, &toolchains.stable, options.failure_mode),
        Suite::SupplyAudit | Suite::SupplyDeny => {
            memcordon_ci::segment_cache::Session::begin_selected_restoring(
                root,
                crate::ci_segments::scopes(suite),
                crate::ci_segments::family(suite),
                true,
                true,
            )?
            .execute_with(root, |session| {
                supply_owned_leaf(root, suite, options.failure_mode, session)
            })
        }
        Suite::SupplyAuditPrepare
        | Suite::SupplyAuditCheck
        | Suite::SupplyDenyPrepare
        | Suite::SupplyDenyCheck => supply_leaf(root, &toolchains.stable, suite),
        Suite::Miri => miri(
            root,
            &toolchains.miri,
            None,
            Path::new("target/ci/miri"),
            options.failure_mode,
        ),
        Suite::MiriFirst => miri(
            root,
            &toolchains.miri,
            Some(shard(0, 2)),
            Path::new("target/ci/miri-first"),
            options.failure_mode,
        ),
        Suite::MiriSecond => miri(
            root,
            &toolchains.miri,
            Some(shard(1, 2)),
            Path::new("target/ci/miri-second"),
            options.failure_mode,
        ),
        Suite::MiriQuarterOne => miri(
            root,
            &toolchains.miri,
            Some(shard(0, 4)),
            Path::new("target/ci/miri-quarter-one"),
            options.failure_mode,
        ),
        Suite::MiriQuarterTwo => miri(
            root,
            &toolchains.miri,
            Some(shard(1, 4)),
            Path::new("target/ci/miri-quarter-two"),
            options.failure_mode,
        ),
        Suite::MiriQuarterThree => miri(
            root,
            &toolchains.miri,
            Some(shard(2, 4)),
            Path::new("target/ci/miri-quarter-three"),
            options.failure_mode,
        ),
        Suite::MiriQuarterFour => miri(
            root,
            &toolchains.miri,
            Some(shard(3, 4)),
            Path::new("target/ci/miri-quarter-four"),
            options.failure_mode,
        ),
        Suite::Fuzz => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            None,
            options.failure_mode,
        ),
        Suite::FuzzFirst => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(0, 2)),
            options.failure_mode,
        ),
        Suite::FuzzSecond => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(1, 2)),
            options.failure_mode,
        ),
        Suite::FuzzQuarterOne => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(0, 4)),
            options.failure_mode,
        ),
        Suite::FuzzQuarterTwo => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(1, 4)),
            options.failure_mode,
        ),
        Suite::FuzzQuarterThree => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(2, 4)),
            options.failure_mode,
        ),
        Suite::FuzzQuarterFour => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(3, 4)),
            options.failure_mode,
        ),
        Suite::Stress => memcordon_ci::stress::combined(root, &toolchains.stable),
        Suite::StressPackages => memcordon_ci::stress::packages(
            root,
            &toolchains.stable,
            Path::new("target/ci/stress-packages"),
        ),
        Suite::StressLifecycle => memcordon_ci::stress::lifecycle(
            root,
            &toolchains.stable,
            Path::new("target/ci/stress-lifecycle"),
        )
        .map(|_| ()),
        Suite::BackendLinuxCgroup => launch_delegated_linux_backend(root),
        Suite::BackendLinuxPrivate => memcordon_ci::release::linux_current_consumer::run_working(
            root,
            &root.join("target/ci/private-installed"),
        ),
        Suite::BackendLinuxPrivatePrepare => {
            memcordon_ci::release::linux_current_consumer::prepare_working(
                root,
                &root.join("target/ci/private-prepared"),
            )
        }
        Suite::BackendLinuxPrivateRuntime => {
            memcordon_ci::release::linux_current_consumer::run_prepared(
                root,
                &root.join("target/ci/private-prepared"),
                &root.join("target/ci/private-installed"),
            )
        }
        Suite::BackendWindowsSealed => {
            memcordon_ci::release::windows_installed_consumer::run_working(
                root,
                &root.join("target/ci/windows-installed"),
            )
        }
        Suite::BackendWindowsJob => backend_suite(
            root,
            Path::new("rustup"),
            &toolchains.stable,
            "windows-job-object",
        ),
        Suite::BackendMacosWatchdog => release_macos(root, &toolchains.stable),
        Suite::ReleaseMacosNative => release_macos_native(root, &toolchains.stable),
        Suite::ReleaseMacosAcceptance => release_macos_acceptance(root, &toolchains.stable),
        Suite::MacosDeadline => macos_deadline(root, &toolchains.stable),
    }
}
