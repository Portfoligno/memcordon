use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::command::{CommandSpec, git, rustup_cargo};
use crate::config;
use crate::{CiError, Result, Suite, policy, release};

const CARGO_DEADLINE: Duration = Duration::from_secs(15 * 60);

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
    for target in [
        "byte_size",
        "cleanup_json",
        "duration",
        "outcome_json",
        "outcome_sequences",
        "policy_parser",
        "report_json",
        "state_machine",
        "workflow_parser",
    ] {
        CommandSpec::new("rustup", root, Duration::from_secs(120))
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

fn hard_backend_scenarios(backend: &str) -> Result<Vec<&'static str>> {
    let common = [
        "certified_backend_preserves_ordinary_status_and_reaps",
        "certified_backend_reports_limit_and_removes_workload",
        "certified_backend_cleans_background_descendant_by_birth_identity",
        "certified_backend_allows_bounded_transient_burst",
    ];
    let specific: &[&str] = match backend {
        "linux-cgroup-v2" => &[
            "linux_cgroup_v2_contains_aggregate_tree",
            "linux_cgroup_v2_handles_rapid_process_churn",
            "linux_cgroup_controls_are_applied_before_target_observation",
            "linux_memory_events_produce_limit_evidence",
            "linux_cleanup_evidence_confirms_empty_reaped_cgroup",
            "linux_cgroup_identity_is_verified_before_exec",
            "linux_guardian_cleans_cgroup_after_wrapper_crash",
            "linux_cgroup_kill_reaps_continually_forking_workload",
            "linux_supervisor_monitor_error_fails_closed_end_to_end",
            "limit_evidence_requires_counter_delta",
            "cgroup_controls_are_written_exactly",
            "monitor_file_errors_are_reported_instead_of_treated_as_success",
            "cgroup_identity_verification_rejects_the_wrong_process",
        ],
        "windows-job-object" => &[
            "windows_job_object_contains_aggregate_tree",
            "windows_job_object_handles_rapid_process_churn",
            "windows_target_is_suspended_until_job_assignment",
            "windows_descendants_remain_in_job_and_are_cleaned",
            "windows_breakaway_descendant_is_not_left_alive",
            "windows_job_notification_produces_limit_evidence",
            "windows_kill_on_close_cleans_workload",
            "windows_wrapper_crash_closes_job_and_reaps_descendants",
            "windows_quoting_preserves_spaces_and_quotes",
            "target_remains_suspended_until_successful_job_assignment",
            "kill_on_job_close_terminates_a_running_member",
            "nested_assignment_is_accounted_by_the_memcordon_job",
            "assignment_failure_terminates_suspended_target_before_execution",
        ],
        _ => {
            return Err(CiError::Message(format!(
                "unknown hard backend certification: {backend}"
            )));
        }
    };
    Ok(common.into_iter().chain(specific.iter().copied()).collect())
}

fn certification(root: &Path, stable: &str, backend: &str, platform_matches: bool) -> Result<()> {
    if !platform_matches {
        return Err(CiError::Message(format!(
            "{backend} certification was invoked on the wrong platform"
        )));
    }
    let output = cargo(
        root,
        stable,
        "run",
        [
            "--target-dir",
            "target/ci/backend",
            "--locked",
            "--package",
            "memcordon",
            "--",
            "probe",
            "--json",
        ],
    )?;
    let probe: serde_json::Value = serde_json::from_slice(&output)?;
    let selected = probe
        .get("selected")
        .filter(|selected| !selected.is_null())
        .ok_or_else(|| {
            CiError::Message(format!(
                "required backend capability is unavailable: {probe}"
            ))
        })?;
    if selected.get("name").and_then(serde_json::Value::as_str) != Some(backend)
        || selected
            .get("hard_limit")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(CiError::Message(format!(
            "required certified hard backend is not selected: {probe}"
        )));
    }
    cargo(
        root,
        stable,
        "test",
        [
            "--target-dir",
            "target/ci/backend",
            "--locked",
            "--package",
            "memcordon",
            "--features",
            "test-fixtures",
            "--test",
            "backend_contract",
            "--",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ],
    )?;
    cargo(
        root,
        stable,
        "test",
        [
            "--target-dir",
            "target/ci/backend",
            "--locked",
            "--package",
            "memcordon-platform",
            "--lib",
            "--",
            "--nocapture",
            "--test-threads=1",
        ],
    )?;
    let commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let scenarios = hard_backend_scenarios(backend)?;
    let report = CertificationReport {
        schema: 1,
        backend,
        certified: true,
        tests_run: u32::try_from(scenarios.len())
            .map_err(|_| CiError::Message("too many certification scenarios".to_owned()))?,
        tests_skipped: 0,
        scenarios,
        commit,
        runner_class: "ephemeral-certified",
    };
    let reports = root.join("target").join("ci").join("reports");
    fs::create_dir_all(&reports)?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(reports.join(format!("backend-{backend}.json")), bytes)?;
    Ok(())
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
        Suite::BackendLinuxCgroup => certification(
            root,
            &toolchains.stable,
            "linux-cgroup-v2",
            cfg!(target_os = "linux"),
        ),
        Suite::BackendWindowsJob => certification(
            root,
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
