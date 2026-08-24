use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use memcordon_ci::command::{CommandSpec, git};
use memcordon_ci::scenario_diagnostic::{
    BoundedStream, EvidenceDiagnosticError, EvidenceDiagnosticKind, ScenarioFailureDiagnostic,
    observe_scenario_process,
};
use memcordon_ci::sealed_identity::{
    FrontendIdentity, parse_credential_readback, parse_frontend_identity, setpriv_sudo_arguments,
};
use memcordon_ci::{
    CiError, Result,
    line_evidence::{FramedLineError, unique_prefixed_line},
};

const DEADLINE: Duration = Duration::from_secs(60 * 60);
const MECHANISM: &str = "linux-pid-namespace-cgroup-v1";
const PROVIDER_BINARY: &str = "target/ci/sealed-agent/debug/memcordon-sealed-agent";
const REPORT_DIRECTORY: &str = "target/ci/reports/linux-sealed";
const CONCURRENCY_EVIDENCE_PREFIX: &str = "MCSEALED-CONCURRENCY-EVIDENCE:";
const MAXIMUM_CONCURRENCY_EVIDENCE_BYTES: usize = 32 * 1024;
const FAULT_EVIDENCE_PREFIX: &str = "MCSEALED-FAULT-EVIDENCE:";
const MAXIMUM_FAULT_EVIDENCE_BYTES: usize = 32 * 1024;

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
        name: "sealed_staged_fixture_is_isolated_and_removed_after_retirement",
        class: "fixture",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_future_deadline_authorizes_and_retires",
        class: "deadline",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_expired_deadline_never_authorizes_and_retires",
        class: "deadline",
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
        name: "sealed_native_nonzero_exit_preserves_provenance",
        class: "launch",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_native_exit_126_and_127_are_not_exec_failures",
        class: "launch",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_missing_target_preserves_enoent_exec_provenance",
        class: "launch",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_non_executable_target_preserves_eacces_exec_provenance",
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
        test_binary: "linux_sealed",
        name: "sealed_faults_before_authorization_never_create_marker",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_namespace_init_failure_is_typed_prompt_and_retired",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_cgroup_kill_failure_never_reports_retirement",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_persistent_populated_state_blocks_restart",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_sealed",
        name: "sealed_namespace_init_reap_delay_blocks_result",
        class: "fault",
    },
    Scenario {
        test_binary: "linux_sealed",
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
    clone3: bool,
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
    spawn_error_reporting_verified: bool,
    frontend_loss_authority_verified: bool,
    cgroup_kill: bool,
    workload_empty: bool,
    helpers_reaped: bool,
    boundary_retired: bool,
    recovery_complete: bool,
}

impl QualificationReceipt {
    fn validate(&self) -> Result<()> {
        let complete = self.schema_version == 1
            && self.mechanism == MECHANISM
            && !self.provider_identity.is_empty()
            && !self.receipt_digest.is_empty()
            && self.unified_cgroup_v2
            && self.private_cgroup_subtree
            && self.clone3
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
            && self.spawn_error_reporting_verified
            && self.frontend_loss_authority_verified
            && self.cgroup_kill
            && self.workload_empty
            && self.helpers_reaped
            && self.boundary_retired
            && self.recovery_complete;
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConcurrencyAttemptEvidence {
    identity: String,
    target_pid: u32,
    live_cgroup_member_pids: Vec<u32>,
    started_monotonic_millis: u64,
    authorized_monotonic_millis: u64,
    terminal_monotonic_millis: u64,
    record_absent: bool,
    cgroup_absent: bool,
    fixture_absent: bool,
    boundary_retired: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConcurrencyHarnessEvidence {
    schema_version: u32,
    overlap: bool,
    attempts: Vec<ConcurrencyAttemptEvidence>,
}

#[derive(Serialize)]
struct ConcurrencyReport<'a> {
    schema_version: u32,
    mechanism: &'static str,
    commit: &'a str,
    overlap: bool,
    attempts: Vec<ConcurrencyAttemptEvidence>,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ScenarioProgressState {
    Pending,
    Running,
    Passed,
    Failed,
}

#[derive(Serialize)]
struct ScenarioProgressEntry {
    name: &'static str,
    class: &'static str,
    state: ScenarioProgressState,
    error: Option<String>,
    evidence: Option<FaultScenarioEvidence>,
    diagnostic: Option<ScenarioFailureDiagnostic>,
}

#[derive(Serialize)]
struct ScenarioProgressReport<'a> {
    schema_version: u32,
    mechanism: &'static str,
    commit: &'a str,
    tests_run: u32,
    tests_in_progress: u32,
    tests_remaining: u32,
    scenarios: &'a [ScenarioProgressEntry],
}

#[derive(Serialize)]
struct CertificationRunReport<'a> {
    schema_version: u32,
    mechanism: &'static str,
    commit: Option<&'a str>,
    status: &'static str,
}

struct ScenarioRunFailure {
    message: String,
    evidence: Option<FaultScenarioEvidence>,
    diagnostic: ScenarioFailureDiagnostic,
}

impl ScenarioRunFailure {
    fn setup(phase: &'static str, error: impl std::fmt::Display) -> Box<Self> {
        let diagnostic = ScenarioFailureDiagnostic::setup(phase, error.to_string());
        let ScenarioFailureDiagnostic::Setup { error, .. } = &diagnostic else {
            unreachable!("setup failure constructor requires setup diagnostics");
        };
        let message = error.data.clone();
        Box::new(Self {
            diagnostic,
            message,
            evidence: None,
        })
    }

    fn process(
        scenario: Scenario,
        evidence: Option<FaultScenarioEvidence>,
        diagnostic: ScenarioFailureDiagnostic,
    ) -> Box<Self> {
        let ScenarioFailureDiagnostic::Process {
            status,
            stdout,
            stderr,
            evidence_status,
            evidence_error,
        } = &diagnostic
        else {
            unreachable!("process failure constructor requires process diagnostics");
        };
        let message = format!(
            "sealed scenario {} did not satisfy certification: status={status}; evidence-status={evidence_status:?}; evidence-error={}\nstdout (encoding={}, bytes={}, truncated={}):\n{}\nstderr (encoding={}, bytes={}, truncated={}):\n{}",
            scenario.name,
            evidence_error.as_deref().unwrap_or("none"),
            stdout.encoding,
            stdout.original_bytes,
            stdout.truncated,
            stdout.data,
            stderr.encoding,
            stderr.original_bytes,
            stderr.truncated,
            stderr.data,
        );
        Box::new(Self {
            message,
            evidence,
            diagnostic,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FaultCleanupEvidence {
    attempted: bool,
    direct_child_reaped: bool,
    workload_empty: Option<bool>,
    helpers_reaped: bool,
    containment_removed: bool,
    sealed_boundary_retired: bool,
    errors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FaultRejectionEvidence {
    schema_version: u32,
    code: String,
    phase: String,
    detail: String,
    os_code: Option<i32>,
    target_created: bool,
    target_released: bool,
    cleanup: FaultCleanupEvidence,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FaultScenarioEvidence {
    schema_version: u32,
    selector: String,
    attempt_id: String,
    rejection: FaultRejectionEvidence,
    retirement_owner: String,
    marker_observed: bool,
    guardian_reaped: bool,
    final_record_absent: bool,
    final_cgroup_absent: bool,
}

#[derive(Clone, Copy)]
struct ExpectedFaultEvidence {
    code: &'static str,
    phase: &'static str,
    target_created: bool,
    target_released: bool,
    cleanup_retired: bool,
    retirement_owner: &'static str,
    guardian_reaped: bool,
}

fn expected_fault_evidence(selector: &str) -> Option<ExpectedFaultEvidence> {
    let expected = match selector {
        "sealed_frontend_loss_before_authorization_never_runs_target" => ExpectedFaultEvidence {
            code: "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION",
            phase: "authorization",
            target_created: true,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "guardian",
            guardian_reaped: true,
        },
        "sealed_frontend_loss_after_authorization_triggers_guardian" => ExpectedFaultEvidence {
            code: "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION",
            phase: "monitoring",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "guardian",
            guardian_reaped: true,
        },
        "sealed_provider_worker_loss_triggers_guardian" => ExpectedFaultEvidence {
            code: "MCSEALED-PROVIDER-WORKER-LOSS",
            phase: "guardian-startup",
            target_created: false,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "guardian",
            guardian_reaped: true,
        },
        "sealed_guardian_loss_before_authorization_fails_closed" => ExpectedFaultEvidence {
            code: "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION",
            phase: "authorization",
            target_created: true,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_guardian_loss_after_authorization_cannot_report_success" => ExpectedFaultEvidence {
            code: "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION",
            phase: "monitoring",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_faults_before_authorization_never_create_marker" => ExpectedFaultEvidence {
            code: "MCSEALED-LAUNCH-DESCRIPTOR-SET",
            phase: "request-validation",
            target_created: false,
            target_released: false,
            cleanup_retired: false,
            retirement_owner: "provider",
            guardian_reaped: false,
        },
        "sealed_namespace_init_failure_is_typed_prompt_and_retired" => ExpectedFaultEvidence {
            code: "MCSEALED-NAMESPACE-INIT-TARGET-FORK",
            phase: "target-creation",
            target_created: false,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_cgroup_kill_failure_never_reports_retirement" => ExpectedFaultEvidence {
            code: "MCSEALED-CGROUP-KILL-FAILURE",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_persistent_populated_state_blocks_restart" => ExpectedFaultEvidence {
            code: "MCSEALED-CGROUP-NOT-EMPTY",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_namespace_init_reap_delay_blocks_result" => ExpectedFaultEvidence {
            code: "MCSEALED-NAMESPACE-INIT-REAP-DELAY",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_guardian_reap_failure_blocks_result" => ExpectedFaultEvidence {
            code: "MCSEALED-GUARDIAN-REAP-FAILURE",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        _ => return None,
    };
    Some(expected)
}

impl FaultScenarioEvidence {
    fn validate(&self, scenario: Scenario) -> Result<()> {
        let expected = expected_fault_evidence(scenario.name).ok_or_else(|| {
            CiError::Message(format!(
                "sealed scenario {} has no typed fault evidence contract",
                scenario.name
            ))
        })?;
        let rejection = &self.rejection;
        let cleanup = &rejection.cleanup;
        let code_bound = rejection.code.starts_with("MCSEALED-")
            && (rejection.detail == rejection.code
                || rejection
                    .detail
                    .strip_prefix(&rejection.code)
                    .is_some_and(|detail| detail.starts_with(':')));
        let cleanup_exact = if expected.cleanup_retired {
            cleanup.attempted
                && cleanup.direct_child_reaped
                && cleanup.workload_empty == Some(true)
                && cleanup.helpers_reaped
                && cleanup.containment_removed
                && cleanup.sealed_boundary_retired
                && cleanup.errors.is_empty()
        } else {
            !cleanup.attempted
                && !cleanup.direct_child_reaped
                && cleanup.workload_empty.is_none()
                && !cleanup.helpers_reaped
                && !cleanup.containment_removed
                && !cleanup.sealed_boundary_retired
                && cleanup.errors.is_empty()
        };
        if self.schema_version != 1
            || self.selector != scenario.name
            || !valid_attempt_identity(&self.attempt_id)
            || rejection.schema_version != 1
            || rejection.code != expected.code
            || rejection.phase != expected.phase
            || !code_bound
            || rejection.os_code.is_some()
            || rejection.target_created != expected.target_created
            || rejection.target_released != expected.target_released
            || !cleanup_exact
            || self.retirement_owner != expected.retirement_owner
            || !self.final_record_absent
            || !self.final_cgroup_absent
            || self.marker_observed != expected.target_released
            || self.guardian_reaped != expected.guardian_reaped
        {
            return Err(CiError::Message(format!(
                "sealed scenario {} emitted incomplete or contradictory fault evidence",
                scenario.name
            )));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct FaultInjectionReport<'a> {
    schema_version: u32,
    mechanism: &'static str,
    commit: &'a str,
    result: &'static str,
    evidence: &'a [FaultScenarioEvidence],
}

#[derive(Serialize)]
struct CertificationFailureReport<'a> {
    schema_version: u32,
    mechanism: &'static str,
    commit: Option<&'a str>,
    primary_error: Option<&'a str>,
    cleanup_error: Option<&'a str>,
    provider_service: Option<&'a ProviderServiceDiagnostics>,
    public_execution_report: Option<&'a Value>,
    public_execution_report_error: Option<&'a str>,
}

#[derive(Serialize)]
struct ProviderServiceDiagnostics {
    properties: BTreeMap<String, String>,
    query_error: Option<String>,
    startup_failure: Option<StartupFailureEvidence>,
    startup_failure_error: Option<String>,
    journal: JournalEvidence,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StartupFailureEvidence {
    schema_version: u32,
    phase: String,
    code: String,
    detail: String,
    provider_pid: u32,
}

#[derive(Serialize)]
struct JournalEvidence {
    entries: Vec<Value>,
    query_error: Option<String>,
    truncated: bool,
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

fn frontend_identity(root: &Path) -> Result<FrontendIdentity> {
    let username = CommandSpec::new("/usr/bin/id", root, DEADLINE)
        .arg("-un")
        .run()?;
    let uid = CommandSpec::new("/usr/bin/id", root, DEADLINE)
        .arg("-u")
        .run()?;
    let provider_group = CommandSpec::new("/usr/bin/getent", root, DEADLINE)
        .args(["group", "memcordon"])
        .run()?;
    parse_frontend_identity(&username, &uid, &provider_group)
}

fn authorized_nonroot(
    root: &Path,
    identity: &FrontendIdentity,
    program: &Path,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<Vec<u8>> {
    let arguments = arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_os_string())
        .collect::<Vec<_>>();
    let args = setpriv_sudo_arguments(identity, program, &arguments)?;
    CommandSpec::new("/usr/bin/sudo", root, DEADLINE)
        .args(args)
        .run()
}

fn authorized_nonroot_memcordon(
    root: &Path,
    identity: &FrontendIdentity,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<Vec<u8>> {
    authorized_nonroot(
        root,
        identity,
        &root.join("target/ci/sealed-agent/debug/memcordon"),
        arguments,
    )
}

fn verify_frontend_credentials(root: &Path, identity: &FrontendIdentity) -> Result<()> {
    let status = authorized_nonroot(
        root,
        identity,
        Path::new("/usr/bin/cat"),
        ["/proc/self/status"],
    )?;
    let readback = parse_credential_readback(identity, &status)?;
    eprintln!(
        "ci sealed frontend credential readback: {}",
        serde_json::to_string(&readback)?
    );
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let temporary = path.with_extension("json.new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn write_scenario_progress(
    report_dir: &Path,
    commit: &str,
    scenarios: &[ScenarioProgressEntry],
) -> Result<()> {
    let count = |state| {
        u32::try_from(
            scenarios
                .iter()
                .filter(|scenario| scenario.state == state)
                .count(),
        )
        .expect("static Linux sealed scenario inventory fits u32")
    };
    let passed = count(ScenarioProgressState::Passed);
    let failed = count(ScenarioProgressState::Failed);
    let report = ScenarioProgressReport {
        schema_version: 2,
        mechanism: MECHANISM,
        commit,
        tests_run: passed + failed,
        tests_in_progress: count(ScenarioProgressState::Running),
        tests_remaining: count(ScenarioProgressState::Pending),
        scenarios,
    };
    write_json(&report_dir.join("sealed-scenario-progress.json"), &report)
}

fn parse_concurrency_evidence(output: &[u8]) -> Result<ConcurrencyHarnessEvidence> {
    let payload = unique_prefixed_line(
        output,
        CONCURRENCY_EVIDENCE_PREFIX,
        MAXIMUM_CONCURRENCY_EVIDENCE_BYTES,
    )
    .map_err(|error| match error {
        FramedLineError::InvalidUtf8(error) => {
            CiError::Message(format!("concurrency evidence was not UTF-8: {error}"))
        }
        FramedLineError::Missing => CiError::Message(
            "simultaneous certification omitted typed concurrency evidence".to_owned(),
        ),
        FramedLineError::Duplicate => CiError::Message(
            "simultaneous certification emitted duplicate concurrency evidence".to_owned(),
        ),
        FramedLineError::TooLarge => {
            CiError::Message("typed concurrency evidence exceeded its byte bound".to_owned())
        }
    })?;
    serde_json::from_str(payload).map_err(Into::into)
}

fn parse_fault_evidence(
    output: &[u8],
    scenario: Scenario,
) -> std::result::Result<FaultScenarioEvidence, EvidenceDiagnosticError> {
    let payload = unique_prefixed_line(output, FAULT_EVIDENCE_PREFIX, MAXIMUM_FAULT_EVIDENCE_BYTES)
        .map_err(|error| match error {
            FramedLineError::Missing => EvidenceDiagnosticError::new(
                EvidenceDiagnosticKind::Missing,
                format!(
                    "sealed scenario {} omitted typed fault evidence",
                    scenario.name
                ),
            ),
            FramedLineError::Duplicate => EvidenceDiagnosticError::new(
                EvidenceDiagnosticKind::Duplicate,
                format!(
                    "sealed scenario {} emitted duplicate typed fault evidence",
                    scenario.name
                ),
            ),
            FramedLineError::TooLarge => EvidenceDiagnosticError::new(
                EvidenceDiagnosticKind::Oversized,
                format!(
                    "sealed scenario {} emitted oversized typed fault evidence",
                    scenario.name
                ),
            ),
            FramedLineError::InvalidUtf8(error) => EvidenceDiagnosticError::new(
                EvidenceDiagnosticKind::InvalidUtf8,
                format!(
                    "sealed scenario {} emitted non-UTF-8 typed fault evidence: {error}",
                    scenario.name
                ),
            ),
        })?;
    let evidence: FaultScenarioEvidence = serde_json::from_str(payload).map_err(|error| {
        EvidenceDiagnosticError::new(
            EvidenceDiagnosticKind::InvalidPayload,
            format!(
                "sealed scenario {} emitted invalid typed fault evidence: {error}",
                scenario.name
            ),
        )
    })?;
    evidence.validate(scenario).map_err(|error| {
        EvidenceDiagnosticError::new(EvidenceDiagnosticKind::ContractMismatch, error.to_string())
    })?;
    Ok(evidence)
}

fn valid_attempt_identity(identity: &str) -> bool {
    identity.len().is_multiple_of(2)
        && identity.len() / 2 == std::mem::size_of::<[u8; 16]>()
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_concurrency_evidence(evidence: &ConcurrencyHarnessEvidence) -> Result<()> {
    if evidence.schema_version != 1 || !evidence.overlap || evidence.attempts.len() != 2 {
        return Err(CiError::Message(
            "typed concurrency evidence omitted exact two-attempt overlap".to_owned(),
        ));
    }
    let identities = evidence
        .attempts
        .iter()
        .map(|attempt| attempt.identity.as_str())
        .collect::<BTreeSet<_>>();
    let target_pids = evidence
        .attempts
        .iter()
        .map(|attempt| attempt.target_pid)
        .collect::<BTreeSet<_>>();
    if identities.len() != evidence.attempts.len()
        || target_pids.len() != evidence.attempts.len()
        || target_pids.contains(&0)
    {
        return Err(CiError::Message(
            "typed concurrency evidence reused an attempt identity or target pid".to_owned(),
        ));
    }
    for attempt in &evidence.attempts {
        let live_members = attempt
            .live_cgroup_member_pids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if !valid_attempt_identity(&attempt.identity)
            || live_members.len() != attempt.live_cgroup_member_pids.len()
            || live_members.contains(&0)
            || !live_members.contains(&attempt.target_pid)
            || attempt.started_monotonic_millis > attempt.authorized_monotonic_millis
            || attempt.authorized_monotonic_millis >= attempt.terminal_monotonic_millis
            || !(attempt.record_absent
                && attempt.cgroup_absent
                && attempt.fixture_absent
                && attempt.boundary_retired)
        {
            return Err(CiError::Message(
                "typed concurrency attempt evidence is incomplete or contradictory".to_owned(),
            ));
        }
    }
    let left_members = evidence.attempts[0]
        .live_cgroup_member_pids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let right_members = evidence.attempts[1]
        .live_cgroup_member_pids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let overlap_started = evidence
        .attempts
        .iter()
        .map(|attempt| attempt.authorized_monotonic_millis)
        .max()
        .expect("two attempts were already required");
    let overlap_ended = evidence
        .attempts
        .iter()
        .map(|attempt| attempt.terminal_monotonic_millis)
        .min()
        .expect("two attempts were already required");
    if !left_members.is_disjoint(&right_members) || overlap_started >= overlap_ended {
        return Err(CiError::Message(
            "typed concurrency evidence did not prove live disjoint overlap".to_owned(),
        ));
    }
    Ok(())
}

fn write_concurrency_evidence(output: &[u8], report_dir: &Path, commit: &str) -> Result<()> {
    let evidence = parse_concurrency_evidence(output)?;
    validate_concurrency_evidence(&evidence)?;
    write_json(
        &report_dir.join("sealed-concurrency-report.json"),
        &ConcurrencyReport {
            schema_version: evidence.schema_version,
            mechanism: MECHANISM,
            commit,
            overlap: evidence.overlap,
            attempts: evidence.attempts,
        },
    )
}

fn run_exact(
    root: &Path,
    stable: &str,
    scenario: Scenario,
    report_dir: &Path,
    commit: &str,
) -> std::result::Result<Option<FaultScenarioEvidence>, Box<ScenarioRunFailure>> {
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
    let output = rustup_cargo(root, stable, args)
        .map_err(|error| ScenarioRunFailure::setup("test-build", error))?;
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
            ScenarioRunFailure::setup(
                "test-executable",
                format!("cargo omitted executable for {}", scenario.test_binary),
            )
        })?;
    let mut test_arguments = vec![scenario.name, "--exact", "--nocapture", "--test-threads=1"];
    if scenario.privileged() {
        test_arguments.push("--ignored");
    }
    let test_output = if scenario.privileged() {
        let mut arguments = vec![
            OsString::from("--non-interactive"),
            OsString::from("--"),
            executable.into_os_string(),
        ];
        arguments.extend(test_arguments.iter().map(OsString::from));
        CommandSpec::new("/usr/bin/sudo", root, DEADLINE)
            .args(arguments)
            .output()
            .map_err(|error| ScenarioRunFailure::setup("test-process", error))?
    } else {
        CommandSpec::new(executable, root, DEADLINE)
            .args(test_arguments.iter().map(OsString::from))
            .output()
            .map_err(|error| ScenarioRunFailure::setup("test-process", error))?
    };
    if !test_output.stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&test_output.stdout));
    }
    if !test_output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&test_output.stderr));
    }

    let evidence_required = matches!(scenario.class, "crash" | "fault");
    let observation = observe_scenario_process(
        test_output.status.success(),
        test_output.status.to_string(),
        &test_output.stdout,
        &test_output.stderr,
        evidence_required,
        |output| parse_fault_evidence(output, scenario),
    );
    if let Some(diagnostic) = observation.failure {
        return Err(ScenarioRunFailure::process(
            scenario,
            observation.evidence,
            diagnostic,
        ));
    }
    let evidence = observation.evidence;
    memcordon_ci::capability::require_single_test_success(&test_output.stdout, scenario.name)
        .map_err(|error| {
            ScenarioRunFailure::process(
                scenario,
                evidence.clone(),
                ScenarioFailureDiagnostic::Process {
                    status: test_output.status.to_string(),
                    stdout: BoundedStream::capture(&test_output.stdout),
                    stderr: BoundedStream::capture(&test_output.stderr),
                    evidence_status: if evidence_required {
                        EvidenceDiagnosticKind::Valid
                    } else {
                        EvidenceDiagnosticKind::NotRequired
                    },
                    evidence_error: Some(format!("libtest acceptance failed: {error}")),
                },
            )
        })?;
    if scenario.name == "sealed_simultaneous_attempts_have_disjoint_boundaries" {
        write_concurrency_evidence(&test_output.stdout, report_dir, commit)
            .map_err(|error| ScenarioRunFailure::setup("concurrency-evidence", error))?;
    }
    Ok(evidence)
}

fn validate_doctor(
    root: &Path,
    stable: &str,
    receipt: &QualificationReceipt,
    report_dir: &Path,
) -> Result<Value> {
    rustup_cargo(
        root,
        stable,
        [
            "build",
            "--target-dir",
            "target/ci/sealed-agent",
            "--locked",
            "--package",
            "memcordon",
            "--bin",
            "memcordon",
        ],
    )?;
    let identity = frontend_identity(root)?;
    verify_frontend_credentials(root, &identity)?;
    let output =
        authorized_nonroot_memcordon(root, &identity, ["doctor", "--json", "--require", "sealed"])?;
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
    let qualification = selected
        .get("boundary_qualification")
        .and_then(Value::as_object)
        .ok_or_else(|| CiError::Message("sealed doctor omitted active qualification".to_owned()))?;
    let active_digest = qualification
        .get("receipt_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let available_selected =
        value
            .get("available")
            .and_then(Value::as_array)
            .and_then(|available| {
                available.iter().find(|backend| {
                    backend.get("name").and_then(Value::as_str) == Some("linux-sealed-provider")
                })
            });
    let memory = selected.get("memory").and_then(Value::as_object);
    let requirement = value.get("requirement").and_then(Value::as_object);
    if selected.get("name").and_then(Value::as_str) != Some("linux-sealed-provider")
        || boundary.get("class").and_then(Value::as_str) != Some("sealed")
        || boundary.get("mechanism").and_then(Value::as_str) != Some(MECHANISM)
        || boundary.get("target_gated").and_then(Value::as_bool) != Some(true)
        || boundary
            .get("boundary_verified_before_authorization")
            .and_then(Value::as_bool)
            != Some(true)
        || boundary
            .get("target_can_reconfigure_boundary")
            .and_then(Value::as_bool)
            != Some(false)
        || boundary
            .get("frontend_loss_cleanup_authority")
            .and_then(Value::as_bool)
            != Some(true)
        || boundary
            .get("workload_empty_proof")
            .and_then(Value::as_bool)
            != Some(true)
        || qualification
            .get("provider_identity")
            .and_then(Value::as_str)
            != Some(receipt.provider_identity.as_str())
        || qualification.get("mechanism").and_then(Value::as_str) != Some(MECHANISM)
        || active_digest.len() != 64
        || !active_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || selected.get("sealed_unavailable").is_some()
        || memory
            .and_then(|memory| memory.get("supported"))
            .and_then(Value::as_bool)
            != Some(true)
        || memory
            .and_then(|memory| memory.get("class"))
            .and_then(Value::as_str)
            != Some("hard")
        || available_selected.and_then(Value::as_object) != Some(selected)
        || requirement
            .and_then(|requirement| requirement.get("kind"))
            .and_then(Value::as_str)
            != Some("sealed")
        || requirement
            .and_then(|requirement| requirement.get("met"))
            .and_then(Value::as_bool)
            != Some(true)
        || requirement
            .and_then(|requirement| requirement.get("reason"))
            .is_none()
    {
        return Err(CiError::Message(
            "doctor did not select the qualified Linux sealed mechanism".to_owned(),
        ));
    }
    write_json(&report_dir.join("platform-environment.json"), &value)?;
    let public_report = report_dir.join("sealed-public-launch.json");
    let launch = authorized_nonroot_memcordon(
        root,
        &identity,
        [
            OsString::from("--sealed"),
            OsString::from("--report"),
            public_report.as_os_str().to_os_string(),
            OsString::from("--"),
            OsString::from("/usr/bin/true"),
        ],
    );
    if let Err(launch_error) = launch {
        return match validate_public_rejection_report(
            &public_report,
            &receipt.provider_identity,
            active_digest,
        ) {
            Ok(()) => Err(launch_error),
            Err(report_error) => Err(CiError::Message(format!(
                "{launch_error}; public sealed rejection report is inconsistent: {report_error}"
            ))),
        };
    }
    validate_public_execution_report(&public_report, &receipt.provider_identity, active_digest)?;
    Ok(value)
}

fn validate_public_execution_report(
    path: &Path,
    provider_identity: &str,
    receipt_digest: &str,
) -> Result<()> {
    let bytes = fs::read(path)?;
    let report: memcordon_core::MemcordonReport = serde_json::from_slice(&bytes)?;
    let backend = report
        .backend
        .as_ref()
        .ok_or_else(|| CiError::Message("public sealed report omitted backend".to_owned()))?;
    let qualification = backend.boundary_qualification.as_ref();
    let supervision = report
        .supervision
        .as_ref()
        .ok_or_else(|| CiError::Message("public sealed report omitted supervision".to_owned()))?;
    let attempt = report.attempts.first();
    let exited_zero = matches!(
        &supervision.terminal,
        memcordon_core::SupervisionTerminal::AttemptOutcome {
            attempt_number: 1,
            outcome: memcordon_core::RunOutcome::Exited {
                child: memcordon_core::ChildTermination::ExitCode { code: 0 },
                cleanup,
                ..
            },
        } if cleanup.direct_child_reaped
            && cleanup.workload_empty == Some(true)
            && cleanup.errors.is_empty()
    );
    let valid = report.schema_version == memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
        && report.error.is_none()
        && backend.name == "linux-sealed-provider"
        && backend.boundary.class == memcordon_core::BoundaryClass::Sealed
        && backend.boundary.mechanism == MECHANISM
        && qualification.is_some_and(|qualification| {
            qualification.provider_identity == provider_identity
                && qualification.receipt_digest == receipt_digest
                && qualification.mechanism == MECHANISM
        })
        && supervision.wrapper_exit_code == 0
        && supervision.attempt_records_created == 1
        && supervision.targets_authorized == 1
        && supervision.restart.restarts_launched() == 0
        && exited_zero
        && report.attempts.len() == 1
        && attempt.is_some_and(|attempt| {
            attempt.number == 1
                && attempt.launch.boundary_requested == memcordon_core::BoundaryRequirement::Sealed
                && attempt.launch.boundary_effective == memcordon_core::BoundaryClass::Sealed
                && attempt.launch.target_released
                && attempt.launch.boundary_assignment_verified
                && attempt.launch.inherited_resources_restricted
                && attempt
                    .restart_safety
                    .is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
                && matches!(
                    &attempt.boundary_detail,
                    memcordon_core::BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV1(native)
                        if native.provider_identity == provider_identity
                            && native.target_credentials_verified
                            && native.target_capabilities_empty
                            && native.inherited_descriptors_verified
                            && native.cgroup_empty_verified
                            && native.namespace_init_reaped
                            && native.guardian_reaped
                            && native.cgroup_removed
                )
        });
    if valid {
        Ok(())
    } else {
        Err(CiError::Message(
            "public sealed execution report is incomplete or contradictory".to_owned(),
        ))
    }
}

fn validate_public_rejection_report(
    path: &Path,
    provider_identity: &str,
    receipt_digest: &str,
) -> Result<()> {
    const MAX_CODE_BYTES: usize = 128;
    const MAX_DETAIL_BYTES: usize = 8 * 1024;
    let bytes = fs::read(path)?;
    let report: memcordon_core::MemcordonReport = serde_json::from_slice(&bytes)?;
    let backend = report
        .backend
        .as_ref()
        .ok_or_else(|| CiError::Message("public sealed rejection omitted backend".to_owned()))?;
    let qualification = backend.boundary_qualification.as_ref().ok_or_else(|| {
        CiError::Message("public sealed rejection omitted qualification".to_owned())
    })?;
    let supervision = report.supervision.as_ref().ok_or_else(|| {
        CiError::Message("public sealed rejection omitted supervision".to_owned())
    })?;
    let attempt = report.attempts.first().ok_or_else(|| {
        CiError::Message("public sealed rejection omitted its failed attempt".to_owned())
    })?;
    let terminal_error = match &supervision.terminal {
        memcordon_core::SupervisionTerminal::Error {
            attempt_number: Some(1),
            error,
        } => error,
        _ => {
            return Err(CiError::Message(
                "public sealed rejection has the wrong terminal envelope".to_owned(),
            ));
        }
    };
    let attempt_error = attempt.error.as_ref().ok_or_else(|| {
        CiError::Message("public sealed rejection attempt omitted its error".to_owned())
    })?;
    let rejection = attempt_error.provider_rejection.as_ref().ok_or_else(|| {
        CiError::Message("public sealed rejection omitted typed provider evidence".to_owned())
    })?;
    let expected_phase = boundary_phase_name(rejection.phase);
    let safe_code = !rejection.code.is_empty()
        && rejection.code.len() <= MAX_CODE_BYTES
        && rejection
            .code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-');
    let cleanup_is_consistent = if rejection.cleanup_attempted {
        true
    } else {
        rejection.restart_safety == memcordon_core::RestartSafetyProof::default()
    };
    let authorization_is_consistent = if rejection.target_released {
        supervision.targets_authorized == 1 && attempt.authorized_offset_ms.is_some()
    } else {
        supervision.targets_authorized == 0 && attempt.authorized_offset_ms.is_none()
    };
    let valid = report.schema_version == memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
        && report.error.is_none()
        && backend.name == "linux-sealed-provider"
        && backend.boundary.class == memcordon_core::BoundaryClass::Sealed
        && backend.boundary.mechanism == MECHANISM
        && qualification.provider_identity == provider_identity
        && qualification.receipt_digest == receipt_digest
        && qualification.mechanism == MECHANISM
        && supervision.wrapper_exit_code == 125
        && supervision.attempt_records_created == 1
        && supervision.restart.restarts_launched() == 0
        && report.attempts.len() == 1
        && attempt.number == 1
        && attempt.phase == memcordon_core::AttemptPhase::Failed
        && attempt.outcome.is_none()
        && attempt_error == terminal_error
        && attempt_error.code == "MCSEALED-PROVIDER-REJECTION"
        && attempt_error.launch_phase.as_deref() == Some(expected_phase)
        && attempt_error.target_released == rejection.target_released
        && attempt_error.workload_may_be_alive
            == (rejection.target_created && rejection.restart_safety.workload_empty != Some(true))
        && rejection.schema_version == 1
        && safe_code
        && !rejection.detail.is_empty()
        && rejection.detail.len() <= MAX_DETAIL_BYTES
        && !rejection.detail.contains('\0')
        && (!rejection.target_released || rejection.target_created)
        && cleanup_is_consistent
        && attempt.launch.mechanism == MECHANISM
        && attempt.launch.boundary_requested == memcordon_core::BoundaryRequirement::Sealed
        && attempt.launch.target_released == rejection.target_released
        && attempt.restart_safety == rejection.restart_safety
        && authorization_is_consistent
        && matches!(
            &attempt.boundary_detail,
            memcordon_core::BoundaryMechanismEvidence::SetupFailure {
                provider_mechanism,
                requested: memcordon_core::BoundaryRequirement::Sealed,
            } if provider_mechanism == MECHANISM
        );
    if valid {
        Ok(())
    } else {
        Err(CiError::Message(
            "public sealed provider rejection evidence is incomplete or contradictory".to_owned(),
        ))
    }
}

fn boundary_phase_name(phase: memcordon_core::BoundarySetupPhase) -> &'static str {
    match phase {
        memcordon_core::BoundarySetupPhase::ProviderConnection => "provider-connection",
        memcordon_core::BoundarySetupPhase::ProviderIdentity => "provider-identity",
        memcordon_core::BoundarySetupPhase::BoundaryCreation => "boundary-creation",
        memcordon_core::BoundarySetupPhase::GuardianStartup => "guardian-startup",
        memcordon_core::BoundarySetupPhase::TargetCreation => "target-creation",
        memcordon_core::BoundarySetupPhase::AssignmentVerification => "assignment-verification",
        memcordon_core::BoundarySetupPhase::ResourceVerification => "resource-verification",
        memcordon_core::BoundarySetupPhase::Authorization => "authorization",
        memcordon_core::BoundarySetupPhase::Monitoring => "monitoring",
        memcordon_core::BoundarySetupPhase::Retirement => "retirement",
    }
}

fn validate_service_privilege_readback(root: &Path, report_dir: &Path) -> Result<()> {
    const MAX_READBACK_BYTES: usize = 16 * 1024;
    let output = CommandSpec::new("/usr/bin/systemctl", root, Duration::from_secs(30))
        .args([
            "show",
            "--no-pager",
            "--property=User",
            "--property=Group",
            "--property=NoNewPrivileges",
            "--property=CapabilityBoundingSet",
            "--property=AmbientCapabilities",
            "memcordon-sealed-agent.service",
        ])
        .run()?;
    if output.len() > MAX_READBACK_BYTES {
        return Err(CiError::Message(
            "provider service privilege readback exceeded its evidence bound".to_owned(),
        ));
    }
    let text = String::from_utf8(output).map_err(|error| CiError::Message(error.to_string()))?;
    let properties = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect::<BTreeMap<_, _>>();
    write_json(
        &report_dir.join("provider-service-privileges.json"),
        &serde_json::json!({
            "schema_version": 1,
            "properties": properties,
        }),
    )?;
    let expected = [
        "cap_dac_override",
        "cap_kill",
        "cap_setgid",
        "cap_setuid",
        "cap_sys_admin",
        "cap_sys_chroot",
        "cap_sys_ptrace",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let observed = properties
        .get("CapabilityBoundingSet")
        .map(|value| {
            value
                .split_ascii_whitespace()
                .map(str::to_ascii_lowercase)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if properties.get("User").map(String::as_str) != Some("root")
        || properties.get("Group").map(String::as_str) != Some("memcordon")
        || properties.get("NoNewPrivileges").map(String::as_str) != Some("yes")
        || properties
            .get("AmbientCapabilities")
            .is_none_or(|value| !value.is_empty())
        || observed.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected
    {
        return Err(CiError::Message(
            "provider service privilege readback disagrees with the reviewed unit".to_owned(),
        ));
    }
    Ok(())
}

fn certification_body(root: &Path, stable: &str, report_dir: &Path, commit: &str) -> Result<()> {
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
    privileged_agent(root, ["package", "install", "--ephemeral-ci"])?;
    agent(root, ["package", "verify"])?;
    privileged_agent(root, ["package", "upgrade", "--ephemeral-ci"])?;
    validate_service_privilege_readback(root, report_dir)?;

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
    let _doctor = validate_doctor(root, stable, &receipt, report_dir)?;

    let mut progress = SCENARIOS
        .iter()
        .map(|scenario| ScenarioProgressEntry {
            name: scenario.name,
            class: scenario.class,
            state: ScenarioProgressState::Pending,
            error: None,
            evidence: None,
            diagnostic: None,
        })
        .collect::<Vec<_>>();
    write_scenario_progress(report_dir, commit, &progress)?;
    let mut results = Vec::with_capacity(SCENARIOS.len());
    let mut fault_evidence = Vec::new();
    for (index, scenario) in SCENARIOS.iter().enumerate() {
        progress[index].state = ScenarioProgressState::Running;
        write_scenario_progress(report_dir, commit, &progress)?;
        let scenario_result = run_exact(root, stable, *scenario, report_dir, commit);
        let scenario_evidence = match scenario_result {
            Ok(evidence) => evidence,
            Err(failure) => {
                let ScenarioRunFailure {
                    message,
                    evidence,
                    diagnostic,
                } = *failure;
                progress[index].evidence = evidence;
                progress[index].diagnostic = Some(diagnostic);
                progress[index].state = ScenarioProgressState::Failed;
                progress[index].error = Some(bounded_diagnostic_text(&message));
                write_scenario_progress(report_dir, commit, &progress).map_err(
                    |progress_error| {
                        CiError::Message(format!(
                            "{}; failed to persist typed scenario evidence: {progress_error}",
                            message
                        ))
                    },
                )?;
                return Err(CiError::Message(message));
            }
        };
        progress[index].evidence = scenario_evidence.clone();
        if let Some(evidence) = scenario_evidence {
            fault_evidence.push(evidence);
        }
        progress[index].state = ScenarioProgressState::Passed;
        write_scenario_progress(report_dir, commit, &progress)?;
        results.push(ScenarioResult {
            name: scenario.name,
            class: scenario.class,
            result: "passed",
        });
    }
    if !report_dir.join("sealed-concurrency-report.json").is_file() {
        return Err(CiError::Message(
            "Linux sealed certification omitted durable concurrency evidence".to_owned(),
        ));
    }
    let report = ScenarioReport {
        schema_version: 1,
        mechanism: MECHANISM,
        commit: commit.to_owned(),
        tests_run: u32::try_from(results.len())
            .map_err(|_| CiError::Message("too many sealed scenarios".to_owned()))?,
        tests_skipped: 0,
        scenarios: results,
    };
    write_json(&report_dir.join("sealed-scenario-report.json"), &report)?;
    write_json(
        &report_dir.join("fault-injection-report.json"),
        &FaultInjectionReport {
            schema_version: 2,
            mechanism: MECHANISM,
            commit,
            result: "passed",
            evidence: &fault_evidence,
        },
    )?;
    write_json(
        &report_dir.join("cleanup-recovery-report.json"),
        &serde_json::json!({
            "schema_version": 1, "mechanism": MECHANISM, "result": "passed",
            "tests": SCENARIOS.iter().filter(|scenario| scenario.class == "recovery").map(|scenario| scenario.name).collect::<Vec<_>>()
        }),
    )?;
    fs::remove_file(report_dir.join("sealed-scenario-progress.json"))?;
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
    let commit = git(root, ["rev-parse", "HEAD"])
        .and_then(|bytes| {
            String::from_utf8(bytes).map_err(|error| CiError::Message(error.to_string()))
        })
        .map(|value| value.trim().to_owned());
    let commit_ref = commit.as_ref().ok().map(String::as_str);
    write_json(
        &report_dir.join("certification-run.json"),
        &CertificationRunReport {
            schema_version: 1,
            mechanism: MECHANISM,
            commit: commit_ref,
            status: "running",
        },
    )?;
    let result = match &commit {
        Ok(commit) => certification_body(root, stable, &report_dir, commit),
        Err(error) => Err(CiError::Message(error.to_string())),
    };
    let provider_service = result
        .as_ref()
        .err()
        .map(|_| collect_provider_service_diagnostics(root));
    let (public_execution_report, public_execution_report_error) = if result.is_err() {
        collect_public_execution_report(&report_dir.join("sealed-public-launch.json"))
    } else {
        (None, None)
    };
    let uninstall = privileged_agent(root, ["package", "uninstall", "--ephemeral-ci"]);
    let primary_error = result.as_ref().err().map(ToString::to_string);
    let cleanup_error = uninstall.as_ref().err().map(ToString::to_string);
    if primary_error.is_some() || cleanup_error.is_some() {
        write_json(
            &report_dir.join("certification-failure.json"),
            &CertificationFailureReport {
                schema_version: 1,
                mechanism: MECHANISM,
                commit: commit_ref,
                primary_error: primary_error.as_deref(),
                cleanup_error: cleanup_error.as_deref(),
                provider_service: provider_service.as_ref(),
                public_execution_report: public_execution_report.as_ref(),
                public_execution_report_error: public_execution_report_error.as_deref(),
            },
        )?;
        write_json(
            &report_dir.join("certification-run.json"),
            &CertificationRunReport {
                schema_version: 1,
                mechanism: MECHANISM,
                commit: commit_ref,
                status: "failed",
            },
        )?;
        return Err(CiError::Message(format!(
            "Linux sealed certification failed: primary={}; cleanup={}",
            primary_error.as_deref().unwrap_or("none"),
            cleanup_error.as_deref().unwrap_or("none")
        )));
    }
    write_json(
        &report_dir.join("certification-run.json"),
        &CertificationRunReport {
            schema_version: 1,
            mechanism: MECHANISM,
            commit: commit_ref,
            status: "passed",
        },
    )?;
    fs::remove_file(report_dir.join("certification-run.json"))?;
    fs::File::open(&report_dir)?.sync_all()?;
    Ok(())
}

fn collect_public_execution_report(path: &Path) -> (Option<Value>, Option<String>) {
    const MAX_REPORT_BYTES: u64 = 1024 * 1024;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (None, Some("public execution report is absent".to_owned()));
        }
        Err(error) => return (None, Some(error.to_string())),
    };
    let mut bytes = Vec::new();
    if let Err(error) = file.take(MAX_REPORT_BYTES + 1).read_to_end(&mut bytes) {
        return (None, Some(error.to_string()));
    }
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return (
            None,
            Some("public execution report exceeds the evidence bound".to_owned()),
        );
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    }
}

fn collect_provider_service_diagnostics(root: &Path) -> ProviderServiceDiagnostics {
    const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
    let output = CommandSpec::new("/usr/bin/systemctl", root, Duration::from_secs(30))
        .args([
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainStatus",
            "memcordon-sealed-agent.service",
        ])
        .run();
    let (startup_failure, startup_failure_error) = collect_startup_failure();
    let journal = collect_provider_journal(root);
    match output {
        Ok(bytes) if bytes.len() <= MAX_DIAGNOSTIC_BYTES => match String::from_utf8(bytes) {
            Ok(text) => ProviderServiceDiagnostics {
                properties: text
                    .lines()
                    .filter_map(|line| line.split_once('='))
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .collect(),
                query_error: None,
                startup_failure,
                startup_failure_error,
                journal,
            },
            Err(error) => ProviderServiceDiagnostics {
                properties: BTreeMap::new(),
                query_error: Some(bounded_diagnostic_text(&format!(
                    "systemctl returned non-UTF-8 output: {error}"
                ))),
                startup_failure,
                startup_failure_error,
                journal,
            },
        },
        Ok(_) => ProviderServiceDiagnostics {
            properties: BTreeMap::new(),
            query_error: Some("systemctl diagnostic exceeded bounded payload".to_owned()),
            startup_failure,
            startup_failure_error,
            journal,
        },
        Err(error) => ProviderServiceDiagnostics {
            properties: BTreeMap::new(),
            query_error: Some(bounded_diagnostic_text(&error.to_string())),
            startup_failure,
            startup_failure_error,
            journal,
        },
    }
}

fn collect_startup_failure() -> (Option<StartupFailureEvidence>, Option<String>) {
    const PATH: &str = "/run/memcordon/sealed-startup-failure.json";
    const MAX_BYTES: u64 = 16 * 1024;
    let metadata = match fs::symlink_metadata(PATH) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => {
            return (
                None,
                Some("startup failure evidence is not a regular file".to_owned()),
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (None, None),
        Err(error) => return (None, Some(bounded_diagnostic_text(&error.to_string()))),
    };
    if metadata.len() > MAX_BYTES {
        return (
            None,
            Some("startup failure evidence exceeds size bound".to_owned()),
        );
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            return (
                None,
                Some("startup failure evidence has unsafe ownership or mode".to_owned()),
            );
        }
    }
    let bytes = match read_startup_failure_bytes(Path::new(PATH), MAX_BYTES) {
        Ok(bytes) if bytes.len() as u64 <= MAX_BYTES => bytes,
        Ok(_) => {
            return (
                None,
                Some("startup failure evidence exceeds size bound".to_owned()),
            );
        }
        Err(error) => return (None, Some(bounded_diagnostic_text(&error.to_string()))),
    };
    match serde_json::from_slice::<StartupFailureEvidence>(&bytes) {
        Ok(record)
            if record.schema_version == 1
                && matches!(record.phase.as_str(), "qualification" | "socket-activation")
                && !record.code.is_empty()
                && record.code.len() <= 128
                && record.detail.len() <= 8 * 1024
                && record.provider_pid != 0 =>
        {
            (Some(record), None)
        }
        Ok(_) => (None, Some("startup failure evidence is invalid".to_owned())),
        Err(error) => (None, Some(bounded_diagnostic_text(&error.to_string()))),
    }
}

fn read_startup_failure_bytes(path: &Path, maximum: u64) -> std::io::Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(target_os = "linux"))]
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn collect_provider_journal(root: &Path) -> JournalEvidence {
    const MAX_BYTES: usize = 32 * 1024;
    let output = CommandSpec::new("/usr/bin/journalctl", root, Duration::from_secs(30))
        .args([
            "--unit",
            "memcordon-sealed-agent.service",
            "--boot",
            "--no-pager",
            "--output=json",
            "--lines=50",
        ])
        .run();
    let bytes = match output {
        Ok(bytes) if bytes.len() <= MAX_BYTES => bytes,
        Ok(_) => {
            return JournalEvidence {
                entries: Vec::new(),
                query_error: None,
                truncated: true,
            };
        }
        Err(error) => {
            return JournalEvidence {
                entries: Vec::new(),
                query_error: Some(bounded_diagnostic_text(&error.to_string())),
                truncated: false,
            };
        }
    };
    let mut entries = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match serde_json::from_slice(line) {
            Ok(entry) => entries.push(entry),
            Err(error) => {
                return JournalEvidence {
                    entries: Vec::new(),
                    query_error: Some(format!("journal returned invalid JSON: {error}")),
                    truncated: false,
                };
            }
        }
    }
    JournalEvidence {
        entries,
        query_error: None,
        truncated: false,
    }
}

fn bounded_diagnostic_text(value: &str) -> String {
    const MAX_BYTES: usize = 8 * 1024;
    const SUFFIX: &str = "...[truncated]";
    if value.len() <= MAX_BYTES {
        return value.to_owned();
    }
    let mut boundary = MAX_BYTES - SUFFIX.len();
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}{SUFFIX}", &value[..boundary])
}
