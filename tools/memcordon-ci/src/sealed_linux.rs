use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use memcordon_ci::command::{CommandSpec, git};
use memcordon_ci::{CiError, Result};

const DEADLINE: Duration = Duration::from_secs(60 * 60);
const MECHANISM: &str = "linux-pid-namespace-cgroup-v1";
const PROVIDER_BINARY: &str = "target/ci/sealed-agent/debug/memcordon-sealed-agent";
const REPORT_DIRECTORY: &str = "target/ci/reports/linux-sealed";

#[derive(Clone, Copy)]
struct Scenario {
    test_binary: &'static str,
    name: &'static str,
    class: &'static str,
}

impl Scenario {
    fn privileged(self) -> bool {
        !matches!(
            self.name,
            "qualification_fails_closed_without_root_provider"
                | "qualification_receipt_requires_complete_retirement"
        )
    }
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        test_binary: "linux_provider",
        name: "qualification_fails_closed_without_root_provider",
        class: "qualification",
    },
    Scenario {
        test_binary: "linux_provider",
        name: "qualification_receipt_requires_complete_retirement",
        class: "qualification",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_direct_exit_retires_fresh_boundary",
        class: "lifecycle",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_child_outlives_direct_target_until_cleanup",
        class: "lifecycle",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_double_fork_remains_in_pid_namespace_and_cgroup",
        class: "escape",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_setsid_daemon_remains_contained",
        class: "escape",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_retained_streams_do_not_finish_before_retirement",
        class: "lifecycle",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_fork_storm_is_empty_before_result",
        class: "stress",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_fork_during_cleanup_cannot_survive",
        class: "stress",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_target_cannot_move_to_parent_or_sibling_cgroup",
        class: "escape",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_target_cannot_setns_into_host_namespace",
        class: "escape",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_target_cannot_mount_writable_cgroup_view",
        class: "escape",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_target_inherits_only_verified_descriptors",
        class: "inheritance",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_target_cannot_disable_namespace_init",
        class: "escape",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_frontend_loss_before_authorization_never_runs_target",
        class: "crash",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_frontend_loss_after_authorization_triggers_guardian",
        class: "crash",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_provider_worker_loss_triggers_guardian",
        class: "crash",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_guardian_loss_before_authorization_fails_closed",
        class: "crash",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_guardian_loss_after_authorization_cannot_report_success",
        class: "crash",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_exec_failure_preserves_native_provenance",
        class: "launch",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_restart_uses_fresh_retired_boundary",
        class: "restart",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_simultaneous_attempts_have_disjoint_boundaries",
        class: "concurrency",
    },
    Scenario {
        test_binary: "linux_recovery",
        name: "sealed_recovery_removes_authenticated_stale_record_without_cgroup",
        class: "recovery",
    },
    Scenario {
        test_binary: "linux_recovery",
        name: "sealed_recovery_quarantines_cgroup_without_authenticated_record",
        class: "recovery",
    },
    Scenario {
        test_binary: "linux_recovery",
        name: "sealed_recovery_blocks_capability_while_live_state_is_ambiguous",
        class: "recovery",
    },
    Scenario {
        test_binary: "linux_faults",
        name: "sealed_faults_before_authorization_never_create_marker",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_faults",
        name: "sealed_cgroup_kill_failure_never_reports_retirement",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_faults",
        name: "sealed_persistent_populated_state_blocks_restart",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_faults",
        name: "sealed_namespace_init_reap_delay_blocks_result",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_faults",
        name: "sealed_guardian_reap_failure_blocks_result",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_package",
        name: "sealed_package_identity_rejects_tampered_provider",
        class: "package",
    },
    Scenario {
        test_binary: "linux_package",
        name: "sealed_package_upgrade_recovers_before_advertising",
        class: "package",
    },
    Scenario {
        test_binary: "linux_package",
        name: "sealed_package_uninstall_refuses_live_authenticated_attempt",
        class: "package",
    },
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationReceipt {
    schema_version: u32,
    mechanism: String,
    provider_identity: String,
    receipt_digest: String,
    unified_cgroup_v2: bool,
    private_cgroup_subtree: bool,
    clone3_into_cgroup: bool,
    pid_namespace: bool,
    mount_namespace: bool,
    cgroup_namespace: bool,
    pidfd: bool,
    close_range: bool,
    guardian_outside_boundary: bool,
    target_gated: bool,
    assignment_verified: bool,
    inherited_descriptors_verified: bool,
    frontend_loss_authority_verified: bool,
    cgroup_kill: bool,
    workload_empty: bool,
    helpers_reaped: bool,
    boundary_retired: bool,
}

impl QualificationReceipt {
    fn validate(&self) -> Result<()> {
        let complete = self.schema_version == 1
            && self.mechanism == MECHANISM
            && !self.provider_identity.is_empty()
            && !self.receipt_digest.is_empty()
            && self.unified_cgroup_v2
            && self.private_cgroup_subtree
            && self.clone3_into_cgroup
            && self.pid_namespace
            && self.mount_namespace
            && self.cgroup_namespace
            && self.pidfd
            && self.close_range
            && self.guardian_outside_boundary
            && self.target_gated
            && self.assignment_verified
            && self.inherited_descriptors_verified
            && self.frontend_loss_authority_verified
            && self.cgroup_kill
            && self.workload_empty
            && self.helpers_reaped
            && self.boundary_retired;
        if complete {
            Ok(())
        } else {
            Err(CiError::Message(
                "Linux sealed qualification receipt is incomplete".to_owned(),
            ))
        }
    }
}

#[derive(Serialize)]
struct ScenarioResult {
    name: &'static str,
    class: &'static str,
    result: &'static str,
}

#[derive(Serialize)]
struct ScenarioReport {
    schema_version: u32,
    mechanism: &'static str,
    commit: String,
    tests_run: u32,
    tests_skipped: u32,
    scenarios: Vec<ScenarioResult>,
}

fn rustup_cargo(
    root: &Path,
    stable: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<Vec<u8>> {
    let mut args = vec![
        OsString::from("run"),
        OsString::from(stable),
        OsString::from("cargo"),
    ];
    args.extend(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string()),
    );
    CommandSpec::new("rustup", root, DEADLINE).args(args).run()
}

fn agent(root: &Path, arguments: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Result<Vec<u8>> {
    CommandSpec::new(root.join(PROVIDER_BINARY), root, DEADLINE)
        .args(
            arguments
                .into_iter()
                .map(|argument| argument.as_ref().to_os_string()),
        )
        .run()
}

fn privileged_agent(
    root: &Path,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<Vec<u8>> {
    let mut args = vec![
        OsString::from("--non-interactive"),
        OsString::from("--"),
        root.join(PROVIDER_BINARY).into_os_string(),
    ];
    args.extend(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string()),
    );
    CommandSpec::new("/usr/bin/sudo", root, DEADLINE)
        .args(args)
        .run()
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn run_exact(root: &Path, stable: &str, scenario: Scenario) -> Result<()> {
    let args = [
        "test",
        "--target-dir",
        "target/ci/sealed-agent",
        "--locked",
        "--package",
        "memcordon-sealed-agent",
        "--features",
        "test-support",
        "--test",
        scenario.test_binary,
        "--no-run",
        "--message-format=json",
    ];
    let output = rustup_cargo(root, stable, args)?;
    let executable = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .find(|value| {
            value.get("reason").and_then(Value::as_str) == Some("compiler-artifact")
                && value.pointer("/target/name").and_then(Value::as_str)
                    == Some(scenario.test_binary)
                && value.get("executable").is_some_and(Value::is_string)
        })
        .and_then(|value| {
            value
                .get("executable")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .ok_or_else(|| {
            CiError::Message(format!(
                "cargo omitted executable for {}",
                scenario.test_binary
            ))
        })?;
    let test_arguments = [scenario.name, "--exact", "--nocapture", "--test-threads=1"];
    let test_output = if scenario.privileged() {
        let mut arguments = vec![
            OsString::from("--non-interactive"),
            OsString::from("--"),
            executable.into_os_string(),
        ];
        arguments.extend(test_arguments.map(OsString::from));
        CommandSpec::new("/usr/bin/sudo", root, DEADLINE)
            .args(arguments)
            .run()?
    } else {
        CommandSpec::new(executable, root, DEADLINE)
            .args(test_arguments.map(OsString::from))
            .run()?
    };
    memcordon_ci::capability::require_single_test_success(&test_output, scenario.name)
}

fn validate_doctor(root: &Path, stable: &str, receipt: &QualificationReceipt) -> Result<Value> {
    let output = rustup_cargo(
        root,
        stable,
        [
            "run",
            "--target-dir",
            "target/ci/sealed-agent",
            "--locked",
            "--package",
            "memcordon",
            "--bin",
            "memcordon",
            "--",
            "doctor",
            "--json",
            "--require",
            "sealed",
        ],
    )?;
    let value: Value = serde_json::from_slice(&output)?;
    if value.get("schema_version").and_then(Value::as_u64)
        != Some(u64::from(memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION))
    {
        return Err(CiError::Message(
            "sealed doctor returned an unrecognized schema".to_owned(),
        ));
    }
    let selected = value
        .get("selected")
        .and_then(Value::as_object)
        .ok_or_else(|| CiError::Message("sealed doctor omitted selected backend".to_owned()))?;
    let boundary = selected
        .get("boundary")
        .and_then(Value::as_object)
        .ok_or_else(|| CiError::Message("sealed doctor omitted boundary evidence".to_owned()))?;
    if boundary.get("class").and_then(Value::as_str) != Some("sealed")
        || boundary.get("mechanism").and_then(Value::as_str) != Some(MECHANISM)
        || receipt.provider_identity.is_empty()
    {
        return Err(CiError::Message(
            "doctor did not select the qualified Linux sealed mechanism".to_owned(),
        ));
    }
    Ok(value)
}

fn certification_body(root: &Path, stable: &str, report_dir: &Path) -> Result<()> {
    if (
        memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
        memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
        memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
        memcordon_core::CLEAN_REPORT_SCHEMA_VERSION,
    ) != (7, 6, 4, 2)
    {
        return Err(CiError::Message(
            "Linux sealed certification has not been updated for the report schemas".to_owned(),
        ));
    }
    if SCENARIOS.len() != memcordon_ci::release_evidence::LINUX_SEALED_TESTS.len()
        || SCENARIOS
            .iter()
            .zip(memcordon_ci::release_evidence::LINUX_SEALED_TESTS)
            .any(|(scenario, expected)| scenario.name != *expected)
    {
        return Err(CiError::Message(
            "Linux sealed execution and release scenario inventories differ".to_owned(),
        ));
    }
    rustup_cargo(
        root,
        stable,
        [
            "build",
            "--target-dir",
            "target/ci/sealed-agent",
            "--locked",
            "--package",
            "memcordon-sealed-agent",
            "--bin",
            "memcordon-sealed-agent",
        ],
    )?;
    agent(root, ["package", "verify"])?;
    privileged_agent(root, ["package", "install", "--ephemeral-ci"])?;
    privileged_agent(root, ["package", "upgrade", "--ephemeral-ci"])?;

    let qualification_output = privileged_agent(root, ["qualify"])?;
    let receipt: QualificationReceipt = serde_json::from_slice(&qualification_output)?;
    receipt.validate()?;
    write_json(&report_dir.join("qualification-receipt.json"), &receipt)?;
    write_json(
        &report_dir.join("provider-identity.json"),
        &serde_json::json!({
            "schema_version": 1,
            "mechanism": MECHANISM,
            "provider_identity": receipt.provider_identity,
            "receipt_digest": receipt.receipt_digest,
        }),
    )?;
    let doctor = validate_doctor(root, stable, &receipt)?;
    write_json(&report_dir.join("platform-environment.json"), &doctor)?;

    let mut results = Vec::with_capacity(SCENARIOS.len());
    for scenario in SCENARIOS {
        run_exact(root, stable, *scenario)?;
        results.push(ScenarioResult {
            name: scenario.name,
            class: scenario.class,
            result: "passed",
        });
    }
    let commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let report = ScenarioReport {
        schema_version: 1,
        mechanism: MECHANISM,
        commit,
        tests_run: u32::try_from(results.len())
            .map_err(|_| CiError::Message("too many sealed scenarios".to_owned()))?,
        tests_skipped: 0,
        scenarios: results,
    };
    write_json(&report_dir.join("sealed-scenario-report.json"), &report)?;
    write_json(
        &report_dir.join("fault-injection-report.json"),
        &serde_json::json!({
            "schema_version": 1, "mechanism": MECHANISM, "result": "passed",
            "tests": SCENARIOS.iter().filter(|scenario| scenario.class == "fault").map(|scenario| scenario.name).collect::<Vec<_>>()
        }),
    )?;
    write_json(
        &report_dir.join("cleanup-recovery-report.json"),
        &serde_json::json!({
            "schema_version": 1, "mechanism": MECHANISM, "result": "passed",
            "tests": SCENARIOS.iter().filter(|scenario| scenario.class == "recovery").map(|scenario| scenario.name).collect::<Vec<_>>()
        }),
    )?;
    Ok(())
}

pub fn certify(root: &Path, stable: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(CiError::Message(
            "Linux sealed certification was invoked on the wrong platform".to_owned(),
        ));
    }
    let report_dir = root.join(REPORT_DIRECTORY);
    if report_dir.exists() {
        fs::remove_dir_all(&report_dir)?;
    }
    fs::create_dir_all(&report_dir)?;
    let result = certification_body(root, stable, &report_dir);
    let uninstall = privileged_agent(root, ["package", "uninstall", "--ephemeral-ci"]);
    match (result, uninstall) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(_)) => Ok(()),
    }
}
