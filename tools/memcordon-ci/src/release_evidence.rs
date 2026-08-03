use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{CiError, Result};

const MAXIMUM_CERTIFICATION_REPORT_BYTES: u64 = 64 * 1024;
const HARD_CERTIFICATION_RUNNER_CLASS: &str = "ephemeral-certified";
const HARD_CERTIFICATION_RUNNER_PROVIDER: &str = "github-hosted";

const LINUX_TESTS: &[&str] = &[
    "certified_backend_preserves_ordinary_status_and_reaps",
    "certified_backend_reports_limit_and_removes_workload",
    "certified_backend_cleans_background_descendant_by_birth_identity",
    "certified_backend_allows_bounded_transient_burst",
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
    Linux,
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
        backend: "linux-cgroup-v2",
        artifact_directory: "release-certification-linux",
        report_name: "backend-linux-cgroup-v2.json",
        evidence_path: "certification/backend-linux-cgroup-v2.json",
        kind: ReportKind::Linux,
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
struct LinuxRuntimeEvidence {
    unified_cgroup_v2: bool,
    delegated_boundary: bool,
    memory_controller: bool,
    memory_max_round_trip: bool,
    memory_swap_max: bool,
    cgroup_kill: bool,
}

impl LinuxRuntimeEvidence {
    fn complete(&self) -> bool {
        self.unified_cgroup_v2
            && self.delegated_boundary
            && self.memory_controller
            && self.memory_max_round_trip
            && self.memory_swap_max
            && self.cgroup_kill
    }
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
        if entries.len() != 1
            || entries[0].file_name().to_str() != Some(spec.report_name)
            || !entries[0].file_type()?.is_file()
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
            ReportKind::Linux => validate_hard_report::<LinuxRuntimeEvidence>(
                &bytes,
                *spec,
                expected_commit,
                "ubuntu-24.04",
                LINUX_TESTS,
                LinuxRuntimeEvidence::complete,
            )?,
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
    Ok(records)
}
