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
    rustup_cargo(root, toolchain, cargo_arguments, deadline).run()
}

fn quality(root: &Path, stable: &str) -> Result<()> {
    let directory = root.join("target/ci/reports/execution");
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
    let result = quality_inner(root, stable);
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

fn quality_inner(root: &Path, stable: &str) -> Result<()> {
    let layout = crate::performance_plan::PerformancePlan::read(root)?
        .quality
        .selected;
    let deadline = Instant::now() + Duration::from_secs(90 * 60);
    let reports = root.join("target/ci/reports/quality");
    fs::create_dir_all(&reports)?;
    let reports = tempfile::Builder::new()
        .prefix("operations-")
        .tempdir_in(&reports)?
        .keep();
    let first = reports.join("metadata");
    let second = reports.join("compile");
    fs::create_dir(&first)?;
    fs::create_dir(&second)?;
    let packages = config::policy(root)?.workspace.publish_packages;
    crate::preparation::complete_lanes(
        layout,
        || {
            crate::preparation::observed(
                rustup_cargo(
                    root,
                    stable,
                    ["fmt", "--all", "--", "--check"],
                    crate::preparation::remaining(deadline, CARGO_DEADLINE)?,
                ),
                &first,
                "format",
            )?;
            crate::preparation::observed(
                rustup_cargo(
                    root,
                    stable,
                    ["metadata", "--locked", "--format-version", "1"],
                    crate::preparation::remaining(deadline, CARGO_DEADLINE)?,
                ),
                &first,
                "metadata",
            )
        },
        || {
            crate::preparation::observed(
                rustup_cargo(
                    root,
                    stable,
                    [
                        "check",
                        "--target-dir",
                        "target/ci/quality",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                        "--locked",
                    ],
                    crate::preparation::remaining(deadline, CARGO_DEADLINE)?,
                ),
                &second,
                "check",
            )?;
            crate::preparation::observed(
                rustup_cargo(
                    root,
                    stable,
                    [
                        "clippy",
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
                ),
                &second,
                "clippy",
            )?;
            for package in packages {
                let arguments = vec![
                    OsString::from("rustdoc"),
                    OsString::from("--target-dir"),
                    OsString::from("target/ci/quality"),
                    OsString::from("--package"),
                    OsString::from(&package),
                    OsString::from("--lib"),
                    OsString::from("--all-features"),
                    OsString::from("--locked"),
                    OsString::from("--"),
                    OsString::from("-D"),
                    OsString::from("warnings"),
                ];
                crate::preparation::observed(
                    rustup_cargo(
                        root,
                        stable,
                        arguments,
                        crate::preparation::remaining(deadline, CARGO_DEADLINE)?,
                    ),
                    &second,
                    &package,
                )?;
            }
            Ok(())
        },
    )
}

fn msrv(root: &Path, version: &str) -> Result<()> {
    let policy = config::policy(root)?;
    for package in policy.workspace.production_packages {
        for phase in ["check", "test"] {
            let arguments = vec![
                OsString::from("--target-dir"),
                OsString::from("target/ci/msrv"),
                OsString::from("--package"),
                OsString::from(&package),
                OsString::from("--all-targets"),
                OsString::from("--all-features"),
                OsString::from("--locked"),
            ];
            cargo(root, version, phase, arguments)?;
        }
    }
    Ok(())
}

fn native(root: &Path, stable: &str, release_mode: bool) -> Result<()> {
    for command in memcordon_ci::native_test_plan::commands(release_mode) {
        cargo_with_deadline(root, stable, "test", command.arguments, command.deadline)?;
    }
    Ok(())
}

fn install_tool(root: &Path, stable: &str, name: &str, version: &str) -> Result<()> {
    let _ = stable;
    let profile = match name {
        "cargo-fuzz" => crate::bootstrap_profile::BootstrapProfile::Fuzz,
        "cargo-audit" | "cargo-deny" => crate::bootstrap_profile::BootstrapProfile::SupplyChain,
        _ => return Err(CiError::Message("unsupported auxiliary tool".into())),
    };
    crate::preparation::ensure_auxiliary_tool(root, profile, name, version)?;
    Ok(())
}

fn supply_chain(root: &Path, stable: &str) -> Result<()> {
    let lockfile = root.join("Cargo.lock");
    let lock_before = fs::read(&lockfile)?;
    let tools = config::tools(root)?;
    install_tool(root, stable, "cargo-audit", &tools.cargo_audit)?;
    install_tool(root, stable, "cargo-deny", &tools.cargo_deny)?;
    for command in supply_chain_commands(root, stable) {
        command.run()?;
    }
    if fs::read(lockfile)? != lock_before {
        return Err(CiError::Message(
            "supply-chain operations changed Cargo.lock".to_owned(),
        ));
    }
    Ok(())
}

fn miri(
    root: &Path,
    nightly: &str,
    shard: Option<memcordon_ci::miri_targets::MiriShard>,
    target_directory: &Path,
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
    cargo(root, nightly, "miri", ["setup"])?;
    let metadata = cargo(
        root,
        nightly,
        "metadata",
        ["--format-version", "1", "--no-deps", "--locked"],
    )?;
    let targets = match shard {
        Some(shard) => memcordon_ci::miri_targets::plan_shard(&metadata, "memcordon-core", shard)?,
        None => memcordon_ci::miri_targets::plan(&metadata, "memcordon-core")?,
    };
    let name = match shard {
        Some(memcordon_ci::miri_targets::MiriShard::First) => "first.json",
        Some(_) => "second.json",
        None => "all.json",
    };
    write_plan(
        root,
        "miri",
        name,
        &serde_json::json!({"planner_version": 1, "package": "memcordon-core", "shard_index": shard.map(|s| s.spec().index()), "shard_count": shard.map(|s| s.spec().count()), "targets": targets}),
    )?;
    for target in targets {
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
                cargo(root, nightly, "miri", command)?;
            }
        } else {
            // Concurrency-sensitive harnesses remain intact, including their
            // inter-test races. The original 900s command deadline applies.
            cargo(root, nightly, "miri", arguments)?;
        }
    }
    Ok(())
}

fn fuzz(
    root: &Path,
    stable: &str,
    nightly: &str,
    shard: Option<memcordon_ci::target_shard::ShardSpec>,
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
    for target in &targets {
        CommandSpec::toolchain_program("rustup", root, nightly, &cargo_fuzz, CARGO_DEADLINE)
            .args([
                OsString::from("fuzz"),
                OsString::from("build"),
                OsString::from(target),
            ])
            .run()?;
    }
    for target in &targets {
        CommandSpec::toolchain_program(
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
        .run()?;
    }
    Ok(())
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

pub(crate) struct SuiteOptions;

pub fn run(root: &Path, suite: Suite, _options: SuiteOptions) -> Result<()> {
    let toolchains = config::toolchains(root)?;
    match suite {
        Suite::Policy => policy::run(root),
        Suite::Quality => quality(root, &toolchains.stable),
        Suite::Msrv => msrv(root, &toolchains.msrv),
        Suite::Native => native(root, &toolchains.stable, false),
        Suite::SupplyChain => supply_chain(root, &toolchains.stable),
        Suite::Miri => miri(root, &toolchains.miri, None, Path::new("target/ci/miri")),
        Suite::MiriFirst => miri(
            root,
            &toolchains.miri,
            Some(memcordon_ci::miri_targets::MiriShard::First),
            Path::new("target/ci/miri-first"),
        ),
        Suite::MiriSecond => miri(
            root,
            &toolchains.miri,
            Some(memcordon_ci::miri_targets::MiriShard::Second),
            Path::new("target/ci/miri-second"),
        ),
        Suite::Fuzz => fuzz(root, &toolchains.stable, &toolchains.miri, None),
        Suite::FuzzFirst => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(0, 2)),
        ),
        Suite::FuzzSecond => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(1, 2)),
        ),
        Suite::FuzzQuarterOne => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(0, 4)),
        ),
        Suite::FuzzQuarterTwo => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(1, 4)),
        ),
        Suite::FuzzQuarterThree => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(2, 4)),
        ),
        Suite::FuzzQuarterFour => fuzz(
            root,
            &toolchains.stable,
            &toolchains.miri,
            Some(shard(3, 4)),
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
