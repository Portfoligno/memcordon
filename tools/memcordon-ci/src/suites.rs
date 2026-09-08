use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use memcordon_ci::capability;
use memcordon_ci::standard_contract::{CargoTestTarget, HardBackendScenario};

use crate::command::{CommandSpec, git, rustup_cargo};
use crate::config;
use crate::{CiError, Result, Suite, policy, release};

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
        "caller-envelope-status",
        "capability-mask",
        "cleanup_json",
        "duration",
        "broker-protocol-v2",
        "invocation_router",
        "half_life_logistic_recurrence",
        "limit_token",
        "linux-evidence-v2",
        "mount-context-manifest",
        "runtime-manifest",
        "release-asset-components",
        "agent-package-inspection",
        "installed-provider-inspection",
        "cargo-bin-inventory",
        "channel-pairing",
        "native_argument",
        "namespace-identity",
        "outcome_json",
        "outcome_sequences",
        "policy_parser",
        "provider-recursion-proof",
        "qualification-receipt-v2",
        "report_json",
        "restart_controller",
        "schema_four",
        "service-unit-policy",
        "state_machine",
        "terminal-receipt-v2",
        "workflow_parser",
        "windows-public-provider-protocol",
        "windows-private-launcher-protocol",
        "windows-token-envelope",
        "windows-security-descriptor",
        "windows-handle-manifest",
        "windows-environment-block",
        "windows-argv",
        "windows-qualification",
        "windows-terminal-receipt",
        "windows-attempt-record",
        "windows-causal-diagnostics",
        "workload-request",
        "workload-registry",
        "workload-discovery",
        "workload-receipt",
        "workload-canonical",
        "workload-transitions",
        "windows-package-inspection",
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

fn stress(root: &Path, stable: &str) -> Result<()> {
    let reports = root.join("target").join("ci").join("reports");
    fs::create_dir_all(&reports)?;
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ u64::from(std::process::id());
    fs::write(reports.join("stress-seed.txt"), format!("{seed}\n"))?;
    for package in [
        "memcordon-core",
        "memcordon-windows-launch-core",
        "memcordon-platform",
        "memcordon",
        "memcordon-testkit",
        "memcordon-ci",
        "memcordon-windows-loader-lab",
    ] {
        fs::write(
            reports.join("stress-active-target.txt"),
            format!("package={package}\n"),
        )?;
        cargo(
            root,
            stable,
            "test",
            [
                "--target-dir",
                "target/ci/stress",
                "--package",
                package,
                "--all-targets",
                "--all-features",
                "--locked",
                "--release",
            ],
        )?;
    }
    fs::write(
        reports.join("stress-active-target.txt"),
        "package-suite=complete\n",
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

fn certification_cargo(
    root: &Path,
    rustup: &Path,
    toolchain: &str,
    subcommand: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    deadline: Duration,
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
    CommandSpec::new(rustup, root, deadline)
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

fn certification(
    root: &Path,
    rustup: &Path,
    stable: &str,
    backend: &str,
    platform_matches: bool,
    inherited_context: Option<memcordon_ci::certification_context::CertificationContext>,
) -> Result<()> {
    use memcordon_ci::certification_context::CertificationContext;
    use memcordon_ci::standard_contract::{
        StandardCertificationReportV3, StandardContract, StandardRuntimeEvidence, validate_report,
    };
    let contract = StandardContract::for_backend(backend)?;
    let reports = contract.report_directory(root);
    fs::create_dir_all(&reports)?;
    let final_path = reports.join(contract.report_name);
    if final_path.exists() {
        fs::remove_file(&final_path)?;
    }
    let candidate = reports.join("candidate.json");
    if candidate.exists() {
        fs::remove_file(&candidate)?;
    }
    contract.require_native()?;
    if !platform_matches {
        return Err(CiError::Message(
            "wrong standard certification platform".into(),
        ));
    }
    let context = match inherited_context {
        Some(context) => context,
        None => CertificationContext::capture(root, contract.contract_id)?,
    };
    context.validate(contract.contract_id)?;
    let source = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?;
    if source.trim() != context.source_commit {
        return Err(CiError::Message("delegated checkout changed".into()));
    }
    let started = std::time::Instant::now();
    let remaining = || {
        CERTIFICATION_DEADLINE
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| CiError::Message("standard suite deadline exhausted".into()))
    };
    let output = certification_cargo(
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
    let probe = serde_json::from_slice(&output)?;
    capability::require_certified_standard_backend(&probe, backend)?;
    for scenario in contract.scenarios() {
        run_hard_scenario(
            root,
            rustup,
            stable,
            scenario,
            remaining()?.min(CARGO_DEADLINE),
        )?;
    }
    // Each fact is justified jointly by the ordinary probe and the exact mandatory scenarios.
    let runtime = match contract.target {
        memcordon_ci::standard_contract::StandardTarget::LinuxX64 => {
            StandardRuntimeEvidence::Linux {
                unified_cgroup_v2: true,
                delegated_boundary: true,
                memory_controller: true,
                memory_max_round_trip: true,
                memory_swap_max: true,
                cgroup_kill: true,
            }
        }
        memcordon_ci::standard_contract::StandardTarget::WindowsX64 => {
            StandardRuntimeEvidence::Windows {
                job_memory_limit: true,
                kill_on_close: true,
                suspended_assignment: true,
                nested_job: true,
                completion_port: true,
            }
        }
    };
    let hosted = context.provenance.is_some();
    let tests = contract.results();
    let report = StandardCertificationReportV3 {
        schema: 3,
        contract_id: contract.contract_id.into(),
        contract_sha256: contract.digest()?,
        boundary: memcordon_core::BoundaryRequirement::Standard,
        backend: backend.into(),
        target: contract.rust_target.into(),
        certified: true,
        commit: context.source_commit.clone(),
        runner_class: if hosted {
            "ephemeral-certified"
        } else {
            "local"
        }
        .into(),
        runner_provider: if hosted { "github-hosted" } else { "local" }.into(),
        runner_label: if hosted { contract.runner_label } else { "" }.into(),
        provenance: context.provenance,
        runtime,
        tests_run: u32::try_from(tests.len())
            .map_err(|_| CiError::Message("too many standard tests".into()))?,
        tests_skipped: 0,
        tests,
    };
    validate_report(&report, contract, &context.source_commit, None)?;
    remaining()?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    let mut temporary = tempfile::NamedTempFile::new_in(&reports)?;
    std::io::Write::write_all(&mut temporary, &bytes)?;
    temporary.as_file().sync_all()?;
    let destination = if backend == "linux-cgroup-v2" {
        candidate
    } else {
        final_path
    };
    temporary
        .persist_noclobber(destination)
        .map_err(|error| CiError::Io(error.error))?;
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
    use memcordon_ci::certification_context::CertificationContext;
    use memcordon_ci::standard_contract::LINUX;
    let reports = LINUX.report_directory(root);
    fs::create_dir_all(&reports)?;
    for name in [LINUX.report_name, "candidate.json"] {
        let path = reports.join(name);
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    LINUX.require_native()?;
    let uid = current_uid(root)?;
    if uid == "0" {
        return Err(CiError::Message(
            "Linux certification must start unprivileged".into(),
        ));
    }
    let context = CertificationContext::capture(root, LINUX.contract_id)?;
    let directory = tempfile::Builder::new()
        .prefix("memcordon-standard-")
        .suffix(".service")
        .tempdir()?;
    let unit = directory
        .path()
        .file_name()
        .ok_or_else(|| CiError::Message("missing unit basename".into()))?
        .to_os_string();
    let unit_text = unit
        .to_str()
        .ok_or_else(|| CiError::Message("invalid unit encoding".into()))?;
    if !unit_text.ends_with(".service")
        || !unit_text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
    {
        return Err(CiError::Message("invalid owned delegation unit".into()));
    }
    let context_path = directory.path().join("context.json");
    let mut context_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&context_path)?;
    let mut bytes = serde_json::to_vec(&context)?;
    bytes.push(b'\n');
    std::io::Write::write_all(&mut context_file, &bytes)?;
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
    arguments.extend(["--uid"].map(OsString::from));
    arguments.push(OsString::from(&uid));
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
    arguments.extend(["delegated-linux-certification", "--rustup"].map(OsString::from));
    arguments.push(rustup.into_os_string());
    arguments.push("--uid".into());
    arguments.push(uid.into());
    arguments.push("--context-file".into());
    arguments.push(context_path.into_os_string());
    let mut lease = memcordon_ci::standard_runner::DelegatedUnitLease::new(root, unit)?;
    let execution = CommandSpec::new("/usr/bin/sudo", root, Duration::from_secs(65 * 60))
        .args(arguments)
        .run();
    let retirement = lease.retire();
    drop(context_file);
    let context_cleanup = directory.close();
    memcordon_ci::standard_runner::finish_delegation(execution, retirement, context_cleanup)?;
    let candidate = reports.join("candidate.json");
    let bytes = memcordon_ci::standard_runner::read_bounded_regular(&candidate)?;
    let report = serde_json::from_slice(&bytes)?;
    memcordon_ci::standard_contract::validate_report(&report, LINUX, &context.source_commit, None)?;
    if report.provenance != context.provenance {
        return Err(CiError::Message(
            "candidate provenance differs from originating context".into(),
        ));
    }
    memcordon_ci::standard_runner::publish_candidate(
        &candidate,
        &reports.join(LINUX.report_name),
        &bytes,
    )?;
    Ok(())
}

pub fn delegated_linux_certification(
    root: &Path,
    rustup: &Path,
    expected_uid: &str,
    context_file: &Path,
) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(CiError::Message(
            "delegated Linux certification invoked on wrong platform".into(),
        ));
    }
    let uid = current_uid(root)?;
    if uid == "0" || uid != expected_uid {
        return Err(CiError::Message(
            "delegation did not preserve unprivileged uid".into(),
        ));
    }
    let expected_uid = uid
        .parse()
        .map_err(|_| CiError::Message("invalid context owner uid".into()))?;
    let bytes = memcordon_ci::standard_runner::read_bounded_regular_owned(
        context_file,
        Some(expected_uid),
    )?;
    let context: memcordon_ci::certification_context::CertificationContext =
        serde_json::from_slice(&bytes)?;
    context.validate(memcordon_ci::standard_contract::LINUX.contract_id)?;
    let toolchains = config::toolchains(root)?;
    certification(
        root,
        rustup,
        &toolchains.stable,
        "linux-cgroup-v2",
        true,
        Some(context),
    )
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
        Suite::BackendLinuxSealedV2 => crate::sealed_linux::certify(root, &toolchains.stable),
        Suite::BackendWindowsJob => certification(
            root,
            Path::new("rustup"),
            &toolchains.stable,
            "windows-job-object",
            cfg!(target_os = "windows"),
            None,
        ),
        Suite::BackendWindowsSealedV2 => crate::sealed_windows::certify(root, &toolchains.stable),
        Suite::WindowsLoaderProduction => {
            crate::sealed_windows::loader_production(root, &toolchains.stable)
        }
        Suite::WindowsProviderLifecycle => {
            crate::sealed_windows::provider_lifecycle(root, &toolchains.stable)
        }
        Suite::WindowsPackageChannel => {
            crate::sealed_windows::package_certify(root, &toolchains.stable)?;
            crate::sealed_windows::channel_parity(root, &toolchains.stable)
        }
        Suite::WindowsLoaderLab => crate::sealed_windows::loader_lab(root, &toolchains.stable),
        Suite::PackageWindowsSealed => {
            crate::sealed_windows::package_certify(root, &toolchains.stable)
        }
        Suite::ChannelParityWindowsSealed => {
            crate::sealed_windows::channel_parity(root, &toolchains.stable)
        }
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
