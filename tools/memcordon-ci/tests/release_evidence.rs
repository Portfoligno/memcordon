use std::fs;
use std::path::Path;

use memcordon_ci::release_evidence::{LINUX_SEALED_TESTS as LINUX_TESTS, collect_certification};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

type ReportMutation = fn(&mut Value);

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

fn tests(names: &[&str]) -> Vec<Value> {
    names
        .iter()
        .map(|name| json!({"name": name, "result": "passed"}))
        .collect()
}

fn linux_report() -> Value {
    json!({
        "schema_version": 1,
        "mechanism": "linux-pid-namespace-cgroup-v1",
        "commit": COMMIT,
        "scenarios": LINUX_TESTS.iter().map(|name| json!({"name": name, "class": "lifecycle", "result": "passed"})).collect::<Vec<_>>(),
        "tests_run": LINUX_TESTS.len(),
        "tests_skipped": 0
    })
}

fn windows_report() -> Value {
    json!({
        "schema": 2,
        "backend": "windows-job-object",
        "certified": true,
        "commit": COMMIT,
        "runner_class": "ephemeral-certified",
        "runner_provider": "github-hosted",
        "runner_label": "windows-2025",
        "runtime": {
            "job_memory_limit": true,
            "kill_on_close": true,
            "suspended_assignment": true,
            "nested_job": true,
            "completion_port": true
        },
        "tests": tests(WINDOWS_TESTS),
        "tests_run": WINDOWS_TESTS.len(),
        "tests_skipped": 0
    })
}

fn macos_report() -> Value {
    json!({
        "schema": 1,
        "backend": "macos-watchdog",
        "certified": true,
        "tests_run": MACOS_SCENARIOS.len(),
        "tests_skipped": 0,
        "scenarios": MACOS_SCENARIOS,
        "commit": COMMIT,
        "runner_class": "hosted-release-acceptance"
    })
}

fn write_report(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).expect("report should serialize");
    bytes.push(b'\n');
    fs::create_dir_all(path.parent().expect("report should have a parent"))
        .expect("artifact directory should exist");
    fs::write(path, bytes).expect("report should write");
}

fn fixture() -> (TempDir, Value, Value, Value) {
    let temporary = TempDir::new().expect("temporary directory should exist");
    let input = temporary.path().join("input");
    fs::create_dir_all(&input).expect("input directory should exist");
    let linux = linux_report();
    let windows = windows_report();
    let macos = macos_report();
    write_report(
        &input
            .join("release-certification-linux")
            .join("sealed-scenario-report.json"),
        &linux,
    );
    let identity = json!({"schema_version": 1, "mechanism": "linux-pid-namespace-cgroup-v1", "provider_identity": "fixture", "receipt_digest": "digest"});
    write_report(
        &input.join("release-certification-linux/provider-identity.json"),
        &identity,
    );
    let mut qualification = identity.clone();
    for field in [
        "unified_cgroup_v2",
        "private_cgroup_subtree",
        "clone3_into_cgroup",
        "pid_namespace",
        "mount_namespace",
        "cgroup_namespace",
        "pidfd",
        "close_range",
        "guardian_outside_boundary",
        "target_gated",
        "assignment_verified",
        "inherited_descriptors_verified",
        "frontend_loss_authority_verified",
        "cgroup_kill",
        "workload_empty",
        "helpers_reaped",
        "boundary_retired",
    ] {
        qualification[field] = json!(true);
    }
    write_report(
        &input.join("release-certification-linux/qualification-receipt.json"),
        &qualification,
    );
    let named = json!({"schema_version": 1, "mechanism": "linux-pid-namespace-cgroup-v1", "result": "passed", "tests": ["fixture"]});
    write_report(
        &input.join("release-certification-linux/fault-injection-report.json"),
        &named,
    );
    write_report(
        &input.join("release-certification-linux/cleanup-recovery-report.json"),
        &named,
    );
    write_report(
        &input.join("release-certification-linux/platform-environment.json"),
        &json!({"schema_version": memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION, "selected": {"boundary": {"class": "sealed", "mechanism": "linux-pid-namespace-cgroup-v1"}}}),
    );
    write_report(
        &input
            .join("release-certification-windows")
            .join("backend-windows-job-object.json"),
        &windows,
    );
    write_report(
        &input
            .join("release-acceptance-macos-arm64")
            .join("backend-macos-watchdog.json"),
        &macos,
    );
    (temporary, linux, windows, macos)
}

#[test]
fn valid_reports_are_copied_and_digest_bound() {
    let (temporary, _, _, _) = fixture();
    let input = temporary.path().join("input");
    let output = temporary.path().join("output");
    let records = collect_certification(&input, &output, COMMIT)
        .expect("valid certification reports should collect");

    assert_eq!(records.len(), 8);
    for (backend, report_name) in [
        (
            "linux-pid-namespace-cgroup-v1",
            "sealed-scenario-report.json",
        ),
        ("windows-job-object", "backend-windows-job-object.json"),
        ("macos-watchdog", "backend-macos-watchdog.json"),
    ] {
        let record = records.get(backend).expect("record should exist");
        assert_eq!(record.evidence_path, format!("certification/{report_name}"));
        let evidence = fs::read(output.join(&record.evidence_path))
            .expect("copied evidence should be readable");
        assert_eq!(record.sha256, hex::encode(Sha256::digest(evidence)));
    }
    for name in [
        "provider-identity.json",
        "qualification-receipt.json",
        "fault-injection-report.json",
        "cleanup-recovery-report.json",
        "platform-environment.json",
    ] {
        let key = format!("linux-pid-namespace-cgroup-v1/{name}");
        let record = records
            .get(&key)
            .expect("Linux evidence record should exist");
        assert_eq!(
            record.evidence_path,
            format!("certification/linux-sealed/{name}")
        );
    }
}

#[test]
fn hard_report_contract_mutations_fail_closed() {
    let cases: &[(&str, ReportMutation)] = &[
        ("schema", |report| report["schema_version"] = json!(2)),
        ("mechanism", |report| {
            report["mechanism"] = json!("standard")
        }),
        ("commit", |report| report["commit"] = json!("wrong")),
        ("count", |report| report["tests_run"] = json!(2)),
        ("skips", |report| report["tests_skipped"] = json!(1)),
        ("result", |report| {
            report["scenarios"][0]["result"] = json!("failed")
        }),
        ("unknown", |report| report["unexpected"] = json!(true)),
    ];

    for (name, mutate) in cases {
        let (temporary, mut linux, _, _) = fixture();
        mutate(&mut linux);
        write_report(
            &temporary
                .path()
                .join("input/release-certification-linux/sealed-scenario-report.json"),
            &linux,
        );
        let result = collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        );
        assert!(result.is_err(), "{name} mutation should fail closed");
    }
}

#[test]
fn artifact_path_cardinality_and_size_fail_closed() {
    let (temporary, linux, _, _) = fixture();
    let input = temporary.path().join("input");
    let output = temporary.path().join("output");

    fs::create_dir_all(input.join("release-certification-extra"))
        .expect("extra artifact directory should exist");
    assert!(collect_certification(&input, &output, COMMIT).is_err());
    fs::remove_dir(input.join("release-certification-extra"))
        .expect("extra artifact directory should be removable");

    write_report(&input.join("duplicate/sealed-scenario-report.json"), &linux);
    assert!(collect_certification(&input, &output, COMMIT).is_err());
    fs::remove_dir_all(input.join("duplicate")).expect("duplicate directory should be removable");

    fs::write(
        input.join("release-certification-linux/sealed-scenario-report.json"),
        vec![b' '; 64 * 1024 + 1],
    )
    .expect("oversize report should write");
    assert!(collect_certification(&input, &output, COMMIT).is_err());
}
