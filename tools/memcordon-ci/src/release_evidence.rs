use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION;

use crate::{CiError, Result};

const MAXIMUM_CERTIFICATION_REPORT_BYTES: u64 = 64 * 1024;
const HARD_CERTIFICATION_RUNNER_CLASS: &str = "ephemeral-certified";
const HARD_CERTIFICATION_RUNNER_PROVIDER: &str = "github-hosted";

const LINUX_SEALED_FILES: &[&str] = &[
    "provider-identity.json",
    "qualification-receipt.json",
    "sealed-scenario-report.json",
    "fault-injection-report.json",
    "cleanup-recovery-report.json",
    "platform-environment.json",
];
pub const LINUX_SEALED_TESTS: &[&str] = &[
    "qualification_fails_closed_without_root_provider",
    "qualification_receipt_requires_complete_retirement",
    "sealed_direct_exit_retires_fresh_boundary",
    "sealed_child_outlives_direct_target_until_cleanup",
    "sealed_double_fork_remains_in_pid_namespace_and_cgroup",
    "sealed_setsid_daemon_remains_contained",
    "sealed_retained_streams_do_not_finish_before_retirement",
    "sealed_fork_storm_is_empty_before_result",
    "sealed_fork_during_cleanup_cannot_survive",
    "sealed_target_cannot_move_to_parent_or_sibling_cgroup",
    "sealed_target_cannot_setns_into_host_namespace",
    "sealed_target_cannot_mount_writable_cgroup_view",
    "sealed_target_inherits_only_verified_descriptors",
    "sealed_target_cannot_disable_namespace_init",
    "sealed_frontend_loss_before_authorization_never_runs_target",
    "sealed_frontend_loss_after_authorization_triggers_guardian",
    "sealed_provider_worker_loss_triggers_guardian",
    "sealed_guardian_loss_before_authorization_fails_closed",
    "sealed_guardian_loss_after_authorization_cannot_report_success",
    "sealed_exec_failure_preserves_native_provenance",
    "sealed_restart_uses_fresh_retired_boundary",
    "sealed_simultaneous_attempts_have_disjoint_boundaries",
    "sealed_recovery_removes_authenticated_stale_record_without_cgroup",
    "sealed_recovery_quarantines_cgroup_without_authenticated_record",
    "sealed_recovery_blocks_capability_while_live_state_is_ambiguous",
    "sealed_faults_before_authorization_never_create_marker",
    "sealed_cgroup_kill_failure_never_reports_retirement",
    "sealed_persistent_populated_state_blocks_restart",
    "sealed_namespace_init_reap_delay_blocks_result",
    "sealed_guardian_reap_failure_blocks_result",
    "sealed_package_identity_rejects_tampered_provider",
    "sealed_package_upgrade_recovers_before_advertising",
    "sealed_package_uninstall_refuses_live_authenticated_attempt",
];

const WINDOWS_TESTS: &[&str] = &[
    "certified_backend_preserves_ordinary_status_and_reaps",
    "certified_backend_reports_limit_and_removes_workload",
    "certified_backend_cleans_background_descendant_by_birth_identity",
    "certified_backend_allows_bounded_transient_burst",
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
];

const MACOS_SCENARIOS: &[&str] = &[
    "hard_unavailability_refuses_before_target_execution",
    "confirmed_limit_has_dedicated_status",
    "macos_system_success_and_failure_smoke_tests_are_bounded",
    "virtual_metric_is_explicitly_supported",
    "wrapper_interrupt_is_forwarded_cleaned_and_mapped",
    "guardian_kills_workload_after_wrapper_crash",
    "command_lifetime_kills_background_descendant_by_birth_identity",
    "immediate_success_failure_and_status_are_reaped_and_preserved",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationRecord {
    pub evidence_path: String,
    pub sha256: String,
}

#[derive(Clone, Copy)]
enum ReportKind {
    LinuxSealed,
    Windows,
    Macos,
}

#[derive(Clone, Copy)]
struct ReportSpec {
    backend: &'static str,
    artifact_directory: &'static str,
    report_name: &'static str,
    evidence_path: &'static str,
    kind: ReportKind,
}

const REPORTS: &[ReportSpec] = &[
    ReportSpec {
        backend: "linux-pid-namespace-cgroup-v1",
        artifact_directory: "release-certification-linux",
        report_name: "sealed-scenario-report.json",
        evidence_path: "certification/sealed-scenario-report.json",
        kind: ReportKind::LinuxSealed,
    },
    ReportSpec {
        backend: "windows-job-object",
        artifact_directory: "release-certification-windows",
        report_name: "backend-windows-job-object.json",
        evidence_path: "certification/backend-windows-job-object.json",
        kind: ReportKind::Windows,
    },
    ReportSpec {
        backend: "macos-watchdog",
        artifact_directory: "release-acceptance-macos-arm64",
        report_name: "backend-macos-watchdog.json",
        evidence_path: "certification/backend-macos-watchdog.json",
        kind: ReportKind::Macos,
    },
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificationTest {
    name: String,
    result: CertificationTestResult,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum CertificationTestResult {
    Passed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HardCertificationReport<R> {
    schema: u32,
    backend: String,
    certified: bool,
    commit: String,
    runner_class: String,
    runner_provider: String,
    runner_label: String,
    runtime: R,
    tests: Vec<CertificationTest>,
    tests_run: u32,
    tests_skipped: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxSealedScenario {
    name: String,
    class: String,
    result: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxSealedScenarioReport {
    schema_version: u32,
    mechanism: String,
    commit: String,
    tests_run: u32,
    tests_skipped: u32,
    scenarios: Vec<LinuxSealedScenario>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxProviderIdentity {
    schema_version: u32,
    mechanism: String,
    provider_identity: String,
    receipt_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxQualificationReceipt {
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxNamedEvidence {
    schema_version: u32,
    mechanism: String,
    result: String,
    tests: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsRuntimeEvidence {
    job_memory_limit: bool,
    kill_on_close: bool,
    suspended_assignment: bool,
    nested_job: bool,
    completion_port: bool,
}

impl WindowsRuntimeEvidence {
    fn complete(&self) -> bool {
        self.job_memory_limit
            && self.kill_on_close
            && self.suspended_assignment
            && self.nested_job
            && self.completion_port
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacosAcceptanceReport {
    schema: u32,
    backend: String,
    certified: bool,
    tests_run: u32,
    tests_skipped: u32,
    scenarios: Vec<String>,
    commit: String,
    runner_class: String,
}

struct ValidatedReport {
    spec: ReportSpec,
    bytes: Vec<u8>,
    sha256: String,
}

fn failure(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_report(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(failure(format!(
            "certification report is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAXIMUM_CERTIFICATION_REPORT_BYTES {
        return Err(failure(format!(
            "certification report exceeds size policy: {}",
            path.display()
        )));
    }
    let bytes = fs::read(path)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAXIMUM_CERTIFICATION_REPORT_BYTES)
    {
        return Err(failure(format!(
            "certification report exceeds size policy: {}",
            path.display()
        )));
    }
    if !bytes.ends_with(b"\n") {
        return Err(failure(format!(
            "certification report is not newline terminated: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn validate_hard_report<R: DeserializeOwned>(
    bytes: &[u8],
    spec: ReportSpec,
    expected_commit: &str,
    expected_label: &str,
    expected_tests: &[&str],
    runtime_complete: impl FnOnce(&R) -> bool,
) -> Result<()> {
    let report: HardCertificationReport<R> = serde_json::from_slice(bytes)?;
    let ordered_names_match = report.tests.len() == expected_tests.len()
        && report
            .tests
            .iter()
            .zip(expected_tests)
            .all(|(actual, expected)| actual.name == *expected);
    let all_passed = report
        .tests
        .iter()
        .all(|test| test.result == CertificationTestResult::Passed);
    let derived_count = u32::try_from(report.tests.len())
        .map_err(|_| failure("too many certification test results"))?;
    if report.schema != 2
        || report.backend != spec.backend
        || !report.certified
        || report.commit != expected_commit
        || report.runner_class != HARD_CERTIFICATION_RUNNER_CLASS
        || report.runner_provider != HARD_CERTIFICATION_RUNNER_PROVIDER
        || report.runner_label != expected_label
        || !runtime_complete(&report.runtime)
        || !ordered_names_match
        || !all_passed
        || report.tests_run != derived_count
        || report.tests_run != u32::try_from(expected_tests.len()).expect("static inventory fits")
        || report.tests_skipped != 0
    {
        return Err(failure(format!(
            "required certification failed: {}",
            spec.backend
        )));
    }
    Ok(())
}

fn validate_macos_report(bytes: &[u8], spec: ReportSpec, expected_commit: &str) -> Result<()> {
    let report: MacosAcceptanceReport = serde_json::from_slice(bytes)?;
    let expected_count = u32::try_from(MACOS_SCENARIOS.len()).expect("static inventory fits");
    let ordered_scenarios_match = report.scenarios.len() == MACOS_SCENARIOS.len()
        && report
            .scenarios
            .iter()
            .zip(MACOS_SCENARIOS)
            .all(|(actual, expected)| actual == expected);
    if report.schema != 1
        || report.backend != spec.backend
        || !report.certified
        || report.tests_run != expected_count
        || report.tests_skipped != 0
        || !ordered_scenarios_match
        || report.commit != expected_commit
        || report.runner_class != "hosted-release-acceptance"
    {
        return Err(failure(format!(
            "required certification failed: {}",
            spec.backend
        )));
    }
    Ok(())
}

fn validate_linux_sealed_report(bytes: &[u8], expected_commit: &str) -> Result<()> {
    let report: LinuxSealedScenarioReport = serde_json::from_slice(bytes)?;
    let count = u32::try_from(report.scenarios.len())
        .map_err(|_| failure("too many Linux sealed scenarios"))?;
    let exact_inventory = report.scenarios.len() == LINUX_SEALED_TESTS.len()
        && report
            .scenarios
            .iter()
            .zip(LINUX_SEALED_TESTS)
            .all(|(scenario, expected)| scenario.name == *expected);
    if report.schema_version != 1
        || report.mechanism != "linux-pid-namespace-cgroup-v1"
        || report.commit != expected_commit
        || report.tests_run != count
        || report.tests_skipped != 0
        || !exact_inventory
        || report.scenarios.iter().any(|scenario| {
            scenario.name.is_empty() || scenario.class.is_empty() || scenario.result != "passed"
        })
    {
        return Err(failure("required Linux sealed certification failed"));
    }
    Ok(())
}

fn validate_linux_auxiliary(name: &str, bytes: &[u8]) -> Result<()> {
    match name {
        "provider-identity.json" => {
            let report: LinuxProviderIdentity = serde_json::from_slice(bytes)?;
            if report.schema_version != 1
                || report.mechanism != "linux-pid-namespace-cgroup-v1"
                || report.provider_identity.is_empty()
                || report.receipt_digest.is_empty()
            {
                return Err(failure("Linux provider identity evidence is incomplete"));
            }
        }
        "qualification-receipt.json" => {
            let report: LinuxQualificationReceipt = serde_json::from_slice(bytes)?;
            let complete = report.schema_version == 1
                && report.mechanism == "linux-pid-namespace-cgroup-v1"
                && !report.provider_identity.is_empty()
                && !report.receipt_digest.is_empty()
                && report.unified_cgroup_v2
                && report.private_cgroup_subtree
                && report.clone3_into_cgroup
                && report.pid_namespace
                && report.mount_namespace
                && report.cgroup_namespace
                && report.pidfd
                && report.close_range
                && report.guardian_outside_boundary
                && report.target_gated
                && report.assignment_verified
                && report.inherited_descriptors_verified
                && report.frontend_loss_authority_verified
                && report.cgroup_kill
                && report.workload_empty
                && report.helpers_reaped
                && report.boundary_retired;
            if !complete {
                return Err(failure("Linux qualification evidence is incomplete"));
            }
        }
        "fault-injection-report.json" | "cleanup-recovery-report.json" => {
            let report: LinuxNamedEvidence = serde_json::from_slice(bytes)?;
            if report.schema_version != 1
                || report.mechanism != "linux-pid-namespace-cgroup-v1"
                || report.result != "passed"
                || report.tests.is_empty()
                || report.tests.iter().any(String::is_empty)
            {
                return Err(failure("Linux named certification evidence is incomplete"));
            }
        }
        "platform-environment.json" => {
            let report: serde_json::Value = serde_json::from_slice(bytes)?;
            if report
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                != Some(u64::from(DOCTOR_REPORT_SCHEMA_VERSION))
                || report
                    .pointer("/selected/boundary/class")
                    .and_then(serde_json::Value::as_str)
                    != Some("sealed")
                || report
                    .pointer("/selected/boundary/mechanism")
                    .and_then(serde_json::Value::as_str)
                    != Some("linux-pid-namespace-cgroup-v1")
            {
                return Err(failure("Linux platform evidence did not select sealed"));
            }
        }
        "sealed-scenario-report.json" => {}
        _ => return Err(failure("unexpected Linux sealed evidence file")),
    }
    Ok(())
}

fn validate_artifact_inventory(input: &Path) -> Result<()> {
    let allowed_directories: BTreeSet<&str> =
        REPORTS.iter().map(|spec| spec.artifact_directory).collect();
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| failure("release input artifact name is not UTF-8"))?;
        let certification_namespace =
            name.starts_with("release-certification-") || name.starts_with("release-acceptance-");
        if certification_namespace && !allowed_directories.contains(name.as_str()) {
            return Err(failure(format!(
                "unexpected certification artifact: {name}"
            )));
        }
    }

    for spec in REPORTS {
        let directory = input.join(spec.artifact_directory);
        if !fs::symlink_metadata(&directory)?.file_type().is_dir() {
            return Err(failure(format!(
                "certification artifact is not a directory: {}",
                directory.display()
            )));
        }
        let entries = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
        let expected: BTreeSet<&str> = if matches!(spec.kind, ReportKind::LinuxSealed) {
            LINUX_SEALED_FILES.iter().copied().collect()
        } else {
            [spec.report_name].into_iter().collect()
        };
        let actual: BTreeSet<String> = entries
            .iter()
            .map(|entry| {
                if !entry.file_type()?.is_file() {
                    return Err(failure("certification artifact entry is not a file"));
                }
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| failure("certification artifact name is not UTF-8"))
            })
            .collect::<Result<_>>()?;
        if actual.len() != expected.len()
            || !actual.iter().all(|name| expected.contains(name.as_str()))
        {
            return Err(failure(format!(
                "certification artifact has an unexpected inventory: {}",
                spec.artifact_directory
            )));
        }

        let expected_path = directory.join(spec.report_name);
        let matching_paths = WalkDir::new(input)
            .into_iter()
            .map(|entry| entry.map_err(|error| failure(error.to_string())))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| entry.file_type().is_file() && entry.file_name() == spec.report_name)
            .map(|entry| entry.into_path())
            .collect::<Vec<_>>();
        if matching_paths.as_slice() != [expected_path] {
            return Err(failure(format!(
                "expected exactly one certification report: {}",
                spec.backend
            )));
        }
    }
    Ok(())
}

fn validate_output_inventory(output: &Path) -> Result<()> {
    let evidence_directory = output.join("certification");
    if !evidence_directory.exists() {
        return Ok(());
    }
    if !fs::symlink_metadata(&evidence_directory)?
        .file_type()
        .is_dir()
    {
        return Err(failure(
            "release certification evidence path is not a directory",
        ));
    }
    let allowed_names: BTreeSet<&str> = REPORTS.iter().map(|spec| spec.report_name).collect();
    for entry in fs::read_dir(evidence_directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| failure("release certification evidence name is not UTF-8"))?;
        if name == "linux-sealed" && entry.file_type()?.is_dir() {
            let actual: BTreeSet<String> = fs::read_dir(entry.path())?
                .map(|item| {
                    let item = item?;
                    if !item.file_type()?.is_file() {
                        return Err(failure("Linux release evidence entry is not a file"));
                    }
                    item.file_name()
                        .into_string()
                        .map_err(|_| failure("Linux release evidence name is not UTF-8"))
                })
                .collect::<Result<_>>()?;
            let expected: BTreeSet<String> = LINUX_SEALED_FILES
                .iter()
                .filter(|name| **name != "sealed-scenario-report.json")
                .map(|name| (*name).to_owned())
                .collect();
            if actual != expected {
                return Err(failure("Linux release evidence inventory differs"));
            }
            continue;
        }
        if !allowed_names.contains(name.as_str()) || !entry.file_type()?.is_file() {
            return Err(failure(format!(
                "unexpected release certification evidence: {name}"
            )));
        }
    }
    Ok(())
}

pub fn collect_certification(
    input: &Path,
    output: &Path,
    expected_commit: &str,
) -> Result<BTreeMap<String, CertificationRecord>> {
    validate_artifact_inventory(input)?;
    validate_output_inventory(output)?;

    let mut validated = Vec::new();
    for spec in REPORTS {
        let path = input.join(spec.artifact_directory).join(spec.report_name);
        let bytes = read_report(&path)?;
        match spec.kind {
            ReportKind::LinuxSealed => {
                validate_linux_sealed_report(&bytes, expected_commit)?;
                for name in LINUX_SEALED_FILES {
                    let auxiliary = read_report(&input.join(spec.artifact_directory).join(name))?;
                    validate_linux_auxiliary(name, &auxiliary)?;
                }
            }
            ReportKind::Windows => validate_hard_report::<WindowsRuntimeEvidence>(
                &bytes,
                *spec,
                expected_commit,
                "windows-2025",
                WINDOWS_TESTS,
                WindowsRuntimeEvidence::complete,
            )?,
            ReportKind::Macos => validate_macos_report(&bytes, *spec, expected_commit)?,
        }
        validated.push(ValidatedReport {
            spec: *spec,
            sha256: sha256_bytes(&bytes),
            bytes,
        });
    }

    let evidence_directory = output.join("certification");
    fs::create_dir_all(&evidence_directory)?;
    let mut records = BTreeMap::new();
    for report in validated {
        let destination = output.join(report.spec.evidence_path);
        fs::write(&destination, report.bytes)?;
        records.insert(
            report.spec.backend.to_owned(),
            CertificationRecord {
                evidence_path: report.spec.evidence_path.to_owned(),
                sha256: report.sha256,
            },
        );
    }
    let linux_input = input.join("release-certification-linux");
    let linux_output = evidence_directory.join("linux-sealed");
    fs::create_dir_all(&linux_output)?;
    for name in LINUX_SEALED_FILES {
        if *name == "sealed-scenario-report.json" {
            continue;
        }
        let bytes = read_report(&linux_input.join(name))?;
        let relative = format!("certification/linux-sealed/{name}");
        fs::write(output.join(&relative), &bytes)?;
        records.insert(
            format!("linux-pid-namespace-cgroup-v1/{name}"),
            CertificationRecord {
                evidence_path: relative,
                sha256: sha256_bytes(&bytes),
            },
        );
    }
    Ok(records)
}
