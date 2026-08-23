use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use memcordon_ci::capability;

use crate::command::{CommandSpec, git, rustup_cargo};
use crate::config;
use crate::{CiError, Result, Suite, policy, release};

const CARGO_DEADLINE: Duration = Duration::from_secs(15 * 60);
const CERTIFICATION_DEADLINE: Duration = Duration::from_secs(60 * 60);
const HARD_CERTIFICATION_RUNNER_CLASS: &str = "ephemeral-certified";
const HARD_CERTIFICATION_RUNNER_PROVIDER: &str = "github-hosted";

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
    cargo(root, stable, "fmt", ["--all", "--", "--check"])?;
    cargo(
        root,
        stable,
        "check",
        [
            "--target-dir",
            "target/ci/quality",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
        ],
    )?;
    cargo(
        root,
        stable,
        "clippy",
        [
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
    )?;
    cargo(
        root,
        stable,
        "metadata",
        ["--locked", "--format-version", "1"],
    )?;
    let policy = config::policy(root)?;
    for package in policy.workspace.publish_packages {
        let arguments = vec![
            OsString::from("--target-dir"),
            OsString::from("target/ci/quality"),
            OsString::from("--package"),
            OsString::from(package),
            OsString::from("--lib"),
            OsString::from("--all-features"),
            OsString::from("--locked"),
            OsString::from("--"),
            OsString::from("-D"),
            OsString::from("warnings"),
        ];
        cargo(root, stable, "rustdoc", arguments)?;
    }
    Ok(())
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
    let mut arguments = vec![
        "--target-dir",
        "target/ci/native",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
    ];
    if release_mode {
        arguments.push("--release");
    }
    cargo(root, stable, "test", arguments)?;
    Ok(())
}

fn install_tool(root: &Path, stable: &str, name: &str, version: &str) -> Result<()> {
    let arguments = vec![
        OsString::from(name),
        OsString::from("--locked"),
        OsString::from("--version"),
        OsString::from(version),
        OsString::from("--root"),
        root.join("target").join("ci-tools").into_os_string(),
    ];
    cargo_with_deadline(
        root,
        stable,
        "install",
        arguments,
        Duration::from_secs(10 * 60),
    )?;
    Ok(())
}

fn supply_chain(root: &Path, stable: &str) -> Result<()> {
    let lockfile = root.join("Cargo.lock");
    let lock_before = fs::read(&lockfile)?;
    let tools = config::tools(root)?;
    install_tool(root, stable, "cargo-audit", &tools.cargo_audit)?;
    install_tool(root, stable, "cargo-deny", &tools.cargo_deny)?;
    let bin = root.join("target").join("ci-tools").join("bin");
    CommandSpec::new(bin.join("cargo-audit"), root, Duration::from_secs(10 * 60))
        .arg("audit")
        .arg("--deny")
        .arg("warnings")
        .run()?;
    CommandSpec::new(bin.join("cargo-deny"), root, Duration::from_secs(10 * 60))
        .args(["--config", "ci/deny.toml", "check"])
        .run()?;
    if fs::read(lockfile)? != lock_before {
        return Err(CiError::Message(
            "supply-chain operations changed Cargo.lock".to_owned(),
        ));
    }
    Ok(())
}

fn miri(root: &Path, nightly: &str) -> Result<()> {
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
    cargo(
        root,
        nightly,
        "miri",
        [
            "test",
            "--target-dir",
            "target/ci/miri",
            "--package",
            "memcordon-core",
            "--locked",
        ],
    )?;
    Ok(())
}

fn fuzz(root: &Path, stable: &str, nightly: &str) -> Result<()> {
    let tools = config::tools(root)?;
    install_tool(root, stable, "cargo-fuzz", &tools.cargo_fuzz)?;
    CommandSpec::new("rustup", root, Duration::from_secs(10 * 60))
        .args(["toolchain", "install", nightly, "--profile", "minimal"])
        .run()?;
    let cargo_fuzz = root
        .join("target")
        .join("ci-tools")
        .join("bin")
        .join("cargo-fuzz");
    let targets = [
        "backoff_multiplier",
        "bounded_history",
        "budget_classifier",
        "byte_size",
        "cleanup_json",
        "duration",
        "invocation_router",
        "half_life_logistic_recurrence",
        "limit_token",
        "native_argument",
        "outcome_json",
        "outcome_sequences",
        "policy_parser",
        "report_json",
        "restart_controller",
        "schema_four",
        "state_machine",
        "workflow_parser",
    ];
    for target in targets {
        CommandSpec::new("rustup", root, CARGO_DEADLINE)
            .args([
                OsString::from("run"),
                OsString::from(nightly),
                cargo_fuzz.clone().into_os_string(),
                OsString::from("fuzz"),
                OsString::from("build"),
                OsString::from(target),
            ])
            .run()?;
    }
    for target in targets {
        CommandSpec::new("rustup", root, Duration::from_secs(5 * 60))
            .args([
                OsString::from("run"),
                OsString::from(nightly),
                cargo_fuzz.clone().into_os_string(),
                OsString::from("fuzz"),
                OsString::from("run"),
                OsString::from(target),
                OsString::from("--"),
                OsString::from("-max_total_time=30"),
                OsString::from("-max_len=4096"),
            ])
            .run()?;
    }
    Ok(())
}

fn stress(root: &Path, stable: &str) -> Result<()> {
    let reports = root.join("target").join("ci").join("reports");
    fs::create_dir_all(&reports)?;
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ u64::from(std::process::id());
    fs::write(reports.join("stress-seed.txt"), format!("{seed}\n"))?;
    cargo(
        root,
        stable,
        "test",
        [
            "--target-dir",
            "target/ci/stress",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--release",
        ],
    )?;
    let probe = capability::probe(
        root,
        stable,
        &root.join("target").join("ci").join("stress"),
        CARGO_DEADLINE,
    )?;
    if cfg!(target_os = "linux") && capability::selected(&probe).is_none() {
        eprintln!(
            "deep backend-dependent stress is unavailable on this runner; mandatory protected backend certification remains authoritative: {probe}"
        );
        return Ok(());
    }
    capability::require_selected(&probe)?;
    cargo(
        root,
        stable,
        "test",
        [
            "--target-dir",
            "target/ci/stress",
            "--package",
            "memcordon",
            "--features",
            "test-fixtures",
            "--test",
            "stress",
            "--release",
            "--locked",
            "--",
            "deep_short_children_are_bounded_reaped_and_observed",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ],
    )?;
    let report: serde_json::Value = serde_json::from_slice(&fs::read(
        reports.join("stress-deep_short_child_iterations.json"),
    )?)?;
    if report.get("seed").and_then(serde_json::Value::as_u64) != Some(seed) {
        return Err(CiError::Message(
            "stress report did not preserve the selected seed".to_owned(),
        ));
    }
    println!("stress seed: {seed} (recorded in the stress report)");
    Ok(())
}

#[derive(Serialize)]
struct CertificationReport<'a> {
    schema: u32,
    backend: &'a str,
    certified: bool,
    tests_run: u32,
    tests_skipped: u32,
    scenarios: Vec<&'a str>,
    commit: String,
    runner_class: &'a str,
}

#[derive(Serialize)]
struct HardCertificationReport<'a> {
    schema: u32,
    backend: &'a str,
    certified: bool,
    tests_run: u32,
    tests_skipped: u32,
    commit: String,
    tests: Vec<CertificationTest>,
    runner_class: &'a str,
    runner_provider: &'a str,
    runner_label: &'a str,
    runtime: CertificationRuntime,
}

#[derive(Serialize)]
struct CertificationTest {
    name: &'static str,
    result: &'static str,
}

#[derive(Serialize)]
#[serde(untagged)]
enum CertificationRuntime {
    Linux {
        unified_cgroup_v2: bool,
        delegated_boundary: bool,
        memory_controller: bool,
        memory_max_round_trip: bool,
        memory_swap_max: bool,
        cgroup_kill: bool,
    },
    Windows {
        job_memory_limit: bool,
        kill_on_close: bool,
        suspended_assignment: bool,
        nested_job: bool,
        completion_port: bool,
    },
}

#[derive(Clone, Copy)]
enum CargoTestTarget {
    BackendContract,
    PlatformTest(&'static str),
}

#[derive(Clone, Copy)]
struct HardBackendScenario {
    public_name: &'static str,
    exact_name: &'static str,
    target: CargoTestTarget,
    ignored: bool,
}

impl HardBackendScenario {
    const fn integration(name: &'static str) -> Self {
        Self {
            public_name: name,
            exact_name: name,
            target: CargoTestTarget::BackendContract,
            ignored: true,
        }
    }

    const fn platform(
        test_binary: &'static str,
        public_name: &'static str,
        exact_name: &'static str,
    ) -> Self {
        Self {
            public_name,
            exact_name,
            target: CargoTestTarget::PlatformTest(test_binary),
            ignored: false,
        }
    }
}

const COMMON_HARD_SCENARIOS: [HardBackendScenario; 4] = [
    HardBackendScenario::integration("certified_backend_preserves_ordinary_status_and_reaps"),
    HardBackendScenario::integration("certified_backend_reports_limit_and_removes_workload"),
    HardBackendScenario::integration(
        "certified_backend_cleans_background_descendant_by_birth_identity",
    ),
    HardBackendScenario::integration("certified_backend_allows_bounded_transient_burst"),
];

const LINUX_HARD_SCENARIOS: [HardBackendScenario; 18] = [
    HardBackendScenario::integration("linux_cgroup_v2_contains_aggregate_tree"),
    HardBackendScenario::integration("linux_cgroup_v2_handles_rapid_process_churn"),
    HardBackendScenario::integration("linux_cgroup_controls_are_applied_before_target_observation"),
    HardBackendScenario::integration(
        "linux_embedding_limiter_blocks_target_until_containment_is_verified",
    ),
    HardBackendScenario::integration("linux_embedding_limiter_preserves_non_utf8_target_argv"),
    HardBackendScenario::integration("linux_target_spawn_failures_preserve_native_provenance"),
    HardBackendScenario::integration("linux_memory_events_produce_limit_evidence"),
    HardBackendScenario::integration("linux_cleanup_evidence_confirms_empty_reaped_cgroup"),
    HardBackendScenario::integration("linux_cgroup_identity_is_verified_before_exec"),
    HardBackendScenario::integration("linux_report_pid_is_the_actual_target_pid"),
    HardBackendScenario::integration(
        "linux_gate_failures_kill_the_blocked_target_before_fixture_code",
    ),
    HardBackendScenario::integration("linux_guardian_kills_process_group_after_wrapper_crash"),
    HardBackendScenario::integration("linux_cgroup_kill_reaps_continually_forking_workload"),
    HardBackendScenario::integration("linux_supervisor_monitor_error_fails_closed_end_to_end"),
    HardBackendScenario::platform(
        "linux_cgroup",
        "limit_evidence_requires_counter_delta",
        "limit_evidence_requires_counter_delta",
    ),
    HardBackendScenario::platform(
        "linux_cgroup",
        "cgroup_controls_are_written_exactly",
        "cgroup_controls_are_written_exactly",
    ),
    HardBackendScenario::platform(
        "linux_cgroup",
        "monitor_file_errors_are_reported_instead_of_treated_as_success",
        "monitor_file_errors_are_reported_instead_of_treated_as_success",
    ),
    HardBackendScenario::platform(
        "linux_cgroup",
        "cgroup_identity_verification_rejects_the_wrong_process",
        "cgroup_identity_verification_rejects_the_wrong_process",
    ),
];

const WINDOWS_HARD_SCENARIOS: [HardBackendScenario; 13] = [
    HardBackendScenario::integration("windows_job_object_contains_aggregate_tree"),
    HardBackendScenario::integration("windows_job_object_handles_rapid_process_churn"),
    HardBackendScenario::integration("windows_target_is_suspended_until_job_assignment"),
    HardBackendScenario::integration("windows_descendants_remain_in_job_and_are_cleaned"),
    HardBackendScenario::integration("windows_breakaway_descendant_is_not_left_alive"),
    HardBackendScenario::integration("windows_job_notification_produces_limit_evidence"),
    HardBackendScenario::integration("windows_kill_on_close_cleans_workload"),
    HardBackendScenario::integration("windows_wrapper_crash_closes_job_and_reaps_descendants"),
    HardBackendScenario::platform(
        "windows_job",
        "windows_quoting_preserves_spaces_and_quotes",
        "windows_native_encoder_quotes_without_shell_interpretation",
    ),
    HardBackendScenario::platform(
        "windows_job",
        "target_remains_suspended_until_successful_job_assignment",
        "target_remains_suspended_until_successful_job_assignment",
    ),
    HardBackendScenario::platform(
        "windows_job",
        "kill_on_job_close_terminates_a_running_member",
        "kill_on_job_close_terminates_a_running_member",
    ),
    HardBackendScenario::platform(
        "windows_job",
        "nested_assignment_is_accounted_by_the_memcordon_job",
        "nested_assignment_is_accounted_by_the_memcordon_job",
    ),
    HardBackendScenario::platform(
        "windows_job",
        "assignment_failure_terminates_suspended_target_before_execution",
        "assignment_failure_terminates_suspended_target_before_execution",
    ),
];

fn hard_backend_scenarios(backend: &str) -> Result<Vec<HardBackendScenario>> {
    let specific = match backend {
        "linux-cgroup-v2" => LINUX_HARD_SCENARIOS.as_slice(),
        "windows-job-object" => WINDOWS_HARD_SCENARIOS.as_slice(),
        _ => {
            return Err(CiError::Message(format!(
                "unknown hard backend certification: {backend}"
            )));
        }
    };
    Ok(COMMON_HARD_SCENARIOS
        .into_iter()
        .chain(specific.iter().copied())
        .collect())
}

fn certification_cargo(
    root: &Path,
    rustup: &Path,
    toolchain: &str,
    subcommand: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<Vec<u8>> {
    let mut command_arguments = vec![
        OsString::from("run"),
        OsString::from(toolchain),
        OsString::from("cargo"),
        OsString::from(subcommand),
    ];
    command_arguments.extend(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string()),
    );
    CommandSpec::new(rustup, root, CARGO_DEADLINE)
        .args(command_arguments)
        .run()
}

fn run_hard_scenario(
    root: &Path,
    rustup: &Path,
    stable: &str,
    scenario: HardBackendScenario,
) -> Result<()> {
    let mut arguments = match scenario.target {
        CargoTestTarget::BackendContract => vec![
            OsString::from("--target-dir"),
            OsString::from("target/ci/backend"),
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
            OsString::from("target/ci/backend"),
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
        OsString::from("--nocapture"),
        OsString::from("--test-threads=1"),
    ]);
    let output = certification_cargo(root, rustup, stable, "test", arguments)?;
    capability::require_single_test_success(&output, scenario.exact_name)
}

fn certification(
    root: &Path,
    rustup: &Path,
    stable: &str,
    backend: &str,
    platform_matches: bool,
) -> Result<()> {
    if !platform_matches {
        return Err(CiError::Message(format!(
            "{backend} certification was invoked on the wrong platform"
        )));
    }
    let output = certification_cargo(
        root,
        rustup,
        stable,
        "run",
        [
            "--target-dir",
            "target/ci/backend",
            "--locked",
            "--package",
            "memcordon",
            "--bin",
            "memcordon",
            "--",
            "doctor",
            "--json",
        ],
    )?;
    let probe: serde_json::Value = serde_json::from_slice(&output)?;
    capability::require_certified_hard_backend(&probe, backend)?;
    let scenarios = hard_backend_scenarios(backend)?;
    let mut tests = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        run_hard_scenario(root, rustup, stable, scenario)?;
        tests.push(CertificationTest {
            name: scenario.public_name,
            result: "passed",
        });
    }
    let commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let tests_run = u32::try_from(tests.len())
        .map_err(|_| CiError::Message("too many certification tests".to_owned()))?;
    let (runner_label, runtime) = match backend {
        "linux-cgroup-v2" => (
            "ubuntu-24.04",
            CertificationRuntime::Linux {
                unified_cgroup_v2: true,
                delegated_boundary: true,
                memory_controller: true,
                memory_max_round_trip: true,
                memory_swap_max: true,
                cgroup_kill: true,
            },
        ),
        "windows-job-object" => (
            "windows-2025",
            CertificationRuntime::Windows {
                job_memory_limit: true,
                kill_on_close: true,
                suspended_assignment: true,
                nested_job: true,
                completion_port: true,
            },
        ),
        _ => unreachable!("hard backend was validated before report construction"),
    };
    let report = HardCertificationReport {
        schema: 2,
        backend,
        certified: true,
        tests_run,
        tests_skipped: 0,
        commit,
        tests,
        runner_class: HARD_CERTIFICATION_RUNNER_CLASS,
        runner_provider: HARD_CERTIFICATION_RUNNER_PROVIDER,
        runner_label,
        runtime,
    };
    let reports = root.join("target").join("ci").join("reports");
    fs::create_dir_all(&reports)?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(reports.join(format!("backend-{backend}.json")), bytes)?;
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

fn launch_delegated_linux_certification(root: &Path) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(CiError::Message(
            "linux-cgroup-v2 certification was invoked on the wrong platform".to_owned(),
        ));
    }
    let uid = current_uid(root)?;
    if uid == "0" {
        return Err(CiError::Message(
            "linux certification must start as the unprivileged runner user".to_owned(),
        ));
    }
    let rustup = resolve_rustup()?;
    let executable = std::env::current_exe()?;
    let arguments = vec![
        OsString::from("--non-interactive"),
        OsString::from("--"),
        OsString::from("/usr/bin/systemd-run"),
        OsString::from("--wait"),
        OsString::from("--pipe"),
        OsString::from("--collect"),
        OsString::from("--service-type"),
        OsString::from("exec"),
        OsString::from("--uid"),
        OsString::from(&uid),
        OsString::from("--property"),
        OsString::from("Delegate=memory"),
        OsString::from("--property"),
        OsString::from("DelegateSubgroup=memcordon-ci"),
        OsString::from("--working-directory"),
        root.as_os_str().to_os_string(),
        OsString::from("--"),
        executable.into_os_string(),
        OsString::from("delegated-linux-certification"),
        OsString::from("--rustup"),
        rustup.into_os_string(),
        OsString::from("--uid"),
        OsString::from(uid),
    ];
    CommandSpec::new("/usr/bin/sudo", root, CERTIFICATION_DEADLINE)
        .args(arguments)
        .run()?;
    Ok(())
}

pub fn delegated_linux_certification(root: &Path, rustup: &Path, expected_uid: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(CiError::Message(
            "delegated Linux certification was invoked on the wrong platform".to_owned(),
        ));
    }
    let uid = current_uid(root)?;
    if uid == "0" || uid != expected_uid {
        return Err(CiError::Message(format!(
            "systemd delegation did not preserve the unprivileged runner uid: expected {expected_uid}, observed {uid}"
        )));
    }
    let toolchains = config::toolchains(root)?;
    certification(root, rustup, &toolchains.stable, "linux-cgroup-v2", true)
}

fn macos_acceptance(root: &Path, stable: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Err(CiError::Message(
            "macOS acceptance was invoked on the wrong platform".to_owned(),
        ));
    }
    cargo(
        root,
        stable,
        "test",
        [
            "--target-dir",
            "target/ci/backend-macos",
            "--locked",
            "--package",
            "memcordon",
            "--features",
            "test-fixtures",
            "--test",
            "lifecycle",
            "--",
            "--nocapture",
            "--test-threads=1",
        ],
    )?;
    let commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let report = CertificationReport {
        schema: 1,
        backend: "macos-watchdog",
        certified: true,
        tests_run: 8,
        tests_skipped: 0,
        scenarios: vec![
            "hard_unavailability_refuses_before_target_execution",
            "confirmed_limit_has_dedicated_status",
            "macos_system_success_and_failure_smoke_tests_are_bounded",
            "virtual_metric_is_explicitly_supported",
            "wrapper_interrupt_is_forwarded_cleaned_and_mapped",
            "guardian_kills_workload_after_wrapper_crash",
            "command_lifetime_kills_background_descendant_by_birth_identity",
            "immediate_success_failure_and_status_are_reaped_and_preserved",
        ],
        commit,
        runner_class: "hosted-release-acceptance",
    };
    let reports = root.join("target").join("ci").join("reports");
    fs::create_dir_all(&reports)?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(reports.join("backend-macos-watchdog.json"), bytes)?;
    Ok(())
}

pub fn run(root: &Path, suite: Suite) -> Result<()> {
    let toolchains = config::toolchains(root)?;
    match suite {
        Suite::Policy => policy::run(root),
        Suite::Quality => quality(root, &toolchains.stable),
        Suite::Msrv => msrv(root, &toolchains.msrv),
        Suite::Native => native(root, &toolchains.stable, false),
        Suite::SupplyChain => supply_chain(root, &toolchains.stable),
        Suite::Miri => miri(root, &toolchains.miri),
        Suite::Fuzz => fuzz(root, &toolchains.stable, &toolchains.miri),
        Suite::Stress => stress(root, &toolchains.stable),
        Suite::BackendLinuxCgroup => launch_delegated_linux_certification(root),
        Suite::BackendLinuxSealed => crate::sealed_linux::certify(root, &toolchains.stable),
        Suite::BackendWindowsJob => certification(
            root,
            Path::new("rustup"),
            &toolchains.stable,
            "windows-job-object",
            cfg!(target_os = "windows"),
        ),
        Suite::BackendMacosWatchdog => macos_acceptance(root, &toolchains.stable),
        Suite::ReleasePreflight => {
            release::preflight(root)?;
            policy::run(root)?;
            quality(root, &toolchains.stable)?;
            msrv(root, &toolchains.msrv)?;
            supply_chain(root, &toolchains.stable)?;
            release::validate_packages(root)
        }
        Suite::ReleaseNative => release::native_asset(root),
        Suite::ReleaseMacos => {
            if !cfg!(target_os = "macos") {
                return Err(CiError::Message("release-macos requires macOS".to_owned()));
            }
            native(root, &toolchains.stable, true)?;
            macos_acceptance(root, &toolchains.stable)
        }
    }
}
