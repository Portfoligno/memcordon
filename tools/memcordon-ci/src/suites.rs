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
    let layout = crate::performance_plan::PerformancePlan::read(root)?
        .quality
        .selected;
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(4);
    let layout = if workers == 1 {
        crate::performance_plan::Layout::Serial
    } else {
        layout
    };
    let compiler_jobs = (workers / 2).max(1).to_string();
    let doc_jobs = (workers - workers / 2).max(1).to_string();
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
    crate::preparation::complete_lanes_with_allocation(
        layout,
        mode,
        [(workers - workers / 2).max(1), (workers / 2).max(1)],
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
        cargo_with_deadline(root, stable, "test", command.arguments, command.deadline)?;
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
    cargo_with_deadline(root, stable, "test", command.arguments, command.deadline).map(|_| ())
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
        std::num::NonZeroUsize::new(1).unwrap(),
    )?;
    Ok(())
}

fn supply_chain(root: &Path, stable: &str, mode: crate::failure_mode::FailureMode) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60 * 60);
    let lockfile = root.join("Cargo.lock");
    let lock_before = fs::read(&lockfile)?;
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
    let workers = std::thread::available_parallelism()
        .map_or(1, |count| count.get())
        .clamp(1, 4);
    let layout = if workers == 1 {
        crate::performance_plan::Layout::Serial
    } else {
        crate::performance_plan::Layout::Parallel
    };
    let audit_jobs = std::num::NonZeroUsize::new(workers.div_ceil(2)).unwrap();
    let deny_jobs = std::num::NonZeroUsize::new((workers / 2).max(1)).unwrap();
    let checks = crate::preparation::with_operation(mode, deadline, || {
        crate::preparation::complete_lanes_with_allocation(
            layout,
            mode,
            [audit_jobs.get(), deny_jobs.get()],
            || {
                crate::preparation::ensure_one_auxiliary_until(
                    root,
                    "cargo-audit",
                    &tools.cargo_audit,
                    stable,
                    deadline,
                    audit_jobs,
                )?;
                audit.run().map(|_| ())
            },
            || {
                crate::preparation::ensure_one_auxiliary_until(
                    root,
                    "cargo-deny",
                    &tools.cargo_deny,
                    stable,
                    deadline,
                    deny_jobs,
                )?;
                deny.run().map(|_| ())
            },
        )
    });
    let lock_check = fs::read(lockfile).map_err(CiError::from).and_then(|after| {
        if after == lock_before {
            Ok(())
        } else {
            Err(CiError::Message(
                "supply-chain operations changed Cargo.lock".into(),
            ))
        }
    });
    match (checks, lock_check) {
        (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
            primary: Box::new(primary),
            secondary: Box::new(secondary),
        }),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
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
    let targets = match shard {
        Some(shard) => {
            memcordon_ci::miri_targets::plan_partition(&metadata, "memcordon-core", shard)?
        }
        None => memcordon_ci::miri_targets::plan(&metadata, "memcordon-core")?,
    };
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
                let batches = memcordon_ci::miri_targets::report_batches(&all, &ignored)?;
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
    let targets = memcordon_ci::fuzz_targets::targets_sharded(
        &std::fs::read_to_string(root.join("fuzz").join("Cargo.toml"))?,
        shard,
    )?;
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
        &serde_json::json!({"planner_version": 1, "shard_index": shard.map(|s| s.index()), "shard_count": shard.map(|s| s.count()), "targets": targets}),
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
        for target in &targets {
            let outcome = CommandSpec::toolchain_program(
                "rustup",
                root,
                nightly,
                &cargo_fuzz,
                CARGO_DEADLINE,
            )
            .args([
                OsString::from("fuzz"),
                OsString::from("build"),
                OsString::from(target),
            ])
            .run()
            .map(|_| ());
            retain_failure(&mut failures, outcome, mode)?;
        }
    }
    // A partially failed compile phase supplies no execution evidence.
    if let Some(error) = failures.take() {
        return Err(error);
    }
    if execute {
        for target in &targets {
            let outcome = CommandSpec::toolchain_program(
                "rustup",
                root,
                nightly,
                &cargo_fuzz,
                Duration::from_secs(5 * 60),
            )
            .args([
                OsString::from("fuzz"),
                OsString::from("run"),
                OsString::from(target),
                OsString::from("--"),
                OsString::from("-max_total_time=30"),
                OsString::from(if target.starts_with("workload-") {
                    "-max_len=1048576"
                } else {
                    "-max_len=4096"
                }),
            ])
            .run()
            .map(|_| ());
            retain_failure(&mut failures, outcome, mode)?;
        }
    }
    failures.map_or(Ok(()), Err)
}

fn write_plan(root: &Path, family: &str, name: &str, value: &serde_json::Value) -> Result<()> {
    let directory = root.join("target/ci/reports").join(family);
    fs::create_dir_all(&directory)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(directory.join(name), bytes)?;
    Ok(())
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
    capability::require_exact_standard_test_success(&output, scenario.exact_name)
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
        CERTIFICATION_DEADLINE
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| CiError::Message("native backend suite deadline exhausted".into()))
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
    capability::require_certified_standard_backend(&serde_json::from_slice(&probe)?, backend)?;
    let scenarios = memcordon_ci::standard_contract::hard_backend_scenarios(backend)?;
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
        let mut admission_bytes = serde_json::to_vec_pretty(&admission)?;
        admission_bytes.push(b'\n');
        fs::write(evidence.join("admission-inventory.json"), admission_bytes)?;
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
        let mut inventory = serde_json::to_vec_pretty(
            &serde_json::json!({"schema_version": 1, "native_scenarios": crate::native_acceptance_catalogue::MACOS_REMEDIATION_SCENARIOS, "writer_barrier_scenarios": 3, "mutations": mutations}),
        )?;
        inventory.push(b'\n');
        fs::write(evidence.join("native-inventory.json"), inventory)?;
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
    result
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
        revision: 1,
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
        requested_contract: memcordon_ci::external_consumer::RequestedContract::Standard,
        report_format: "result-v1".into(),
        report_revision: 1,
        expected_outcome: memcordon_core::result_v1::OutcomeKindV1::Completed,
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
    let commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
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
    memcordon_ci::macos_performance::validate_local_completed(
        root,
        &commit,
        std::env::consts::ARCH,
    )?;
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
    if matches!(
        suite,
        Suite::Policy
            | Suite::Stress
            | Suite::StressPackages
            | Suite::StressLifecycle
            | Suite::BackendLinuxCgroup
            | Suite::BackendLinuxPrivate
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
            if matches!(suite, Suite::Msrv | Suite::Quality | Suite::QualityCompile) {
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
    if options.failure_mode == crate::failure_mode::FailureMode::CollectAll
        && !matches!(
            suite,
            Suite::Native
                | Suite::NativeCompile
                | Suite::NativeExecute
                | Suite::Quality
                | Suite::QualityCompile
                | Suite::SupplyChain
                | Suite::Msrv
                | Suite::Miri
                | Suite::MiriFirst
                | Suite::MiriSecond
                | Suite::MiriQuarterOne
                | Suite::MiriQuarterTwo
                | Suite::MiriQuarterThree
                | Suite::MiriQuarterFour
                | Suite::Fuzz
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
        )
    {
        return Err(CiError::Message(
            "collect-all is unsupported for this stateful suite".into(),
        ));
    }
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
        Suite::Policy => policy::run(root),
        Suite::Quality => quality(root, &toolchains.stable, options.failure_mode),
        Suite::QualityCompile => quality_compile(root, &toolchains.stable, options.failure_mode),
        Suite::Msrv => msrv(root, &toolchains.msrv, options.failure_mode),
        Suite::Native => native(root, &toolchains.stable, false, options.failure_mode),
        Suite::NativeCompile => native_phase(root, &toolchains.stable, options.failure_mode, true),
        Suite::NativeExecute => native_phase(root, &toolchains.stable, options.failure_mode, false),
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
        Suite::BackendLinuxPrivate => memcordon_ci::release::linux_installed_consumer::run_working(
            root,
            &root.join("target/ci/private-installed"),
        ),
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
