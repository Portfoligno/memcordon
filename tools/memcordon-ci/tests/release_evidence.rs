use std::fs;
use std::path::Path;

use memcordon_ci::release_evidence::collect_certification;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

type ReportMutation = fn(&mut Value);

const LINUX_TESTS: &[&str] = &[
    "certified_backend_preserves_ordinary_status_and_reaps",
    "certified_backend_reports_limit_and_removes_workload",
    "certified_backend_cleans_background_descendant_by_birth_identity",
    "certified_backend_allows_bounded_transient_burst",
    "linux_cgroup_v2_contains_aggregate_tree",
    "linux_cgroup_v2_handles_rapid_process_churn",
    "linux_cgroup_controls_are_applied_before_target_observation",
    "linux_embedding_limiter_blocks_target_until_containment_is_verified",
    "linux_embedding_limiter_preserves_non_utf8_target_argv",
    "linux_target_spawn_failures_preserve_native_provenance",
    "linux_memory_events_produce_limit_evidence",
    "linux_cleanup_evidence_confirms_empty_reaped_cgroup",
    "linux_cgroup_identity_is_verified_before_exec",
    "linux_report_pid_is_the_actual_target_pid",
    "linux_gate_failures_kill_the_blocked_target_before_fixture_code",
    "linux_guardian_kills_process_group_after_wrapper_crash",
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

fn tests(names: &[&str]) -> Vec<Value> {
    names
        .iter()
        .map(|name| json!({"name": name, "result": "passed"}))
        .collect()
}

fn linux_report() -> Value {
    json!({
        "schema": 2,
        "backend": "linux-cgroup-v2",
        "certified": true,
        "commit": COMMIT,
        "runner_class": "ephemeral-certified",
        "runner_provider": "github-hosted",
        "runner_label": "ubuntu-24.04",
        "runtime": {
            "unified_cgroup_v2": true,
            "delegated_boundary": true,
            "memory_controller": true,
            "memory_max_round_trip": true,
            "memory_swap_max": true,
            "cgroup_kill": true
        },
        "tests": tests(LINUX_TESTS),
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
            .join("backend-linux-cgroup-v2.json"),
        &linux,
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

    assert_eq!(records.len(), 3);
    for (backend, report_name) in [
        ("linux-cgroup-v2", "backend-linux-cgroup-v2.json"),
        ("windows-job-object", "backend-windows-job-object.json"),
        ("macos-watchdog", "backend-macos-watchdog.json"),
    ] {
        let record = records.get(backend).expect("record should exist");
        assert_eq!(record.evidence_path, format!("certification/{report_name}"));
        let evidence = fs::read(output.join(&record.evidence_path))
            .expect("copied evidence should be readable");
        assert_eq!(record.sha256, hex::encode(Sha256::digest(evidence)));
    }
}

#[test]
fn hard_report_contract_mutations_fail_closed() {
    let cases: &[(&str, ReportMutation)] = &[
        ("schema", |report| report["schema"] = json!(1)),
        ("provider", |report| {
            report["runner_provider"] = json!("self-hosted")
        }),
        ("label", |report| {
            report["runner_label"] = json!("ubuntu-latest")
        }),
        ("class", |report| {
            report["runner_class"] = json!("github-hosted-standard")
        }),
        ("commit", |report| report["commit"] = json!("wrong")),
        ("runtime", |report| {
            report["runtime"]["memory_swap_max"] = json!(false)
        }),
        ("count", |report| report["tests_run"] = json!(16)),
        ("skips", |report| report["tests_skipped"] = json!(1)),
        ("result", |report| {
            report["tests"][0]["result"] = json!("failed")
        }),
        ("order", |report| {
            report["tests"]
                .as_array_mut()
                .expect("tests should be an array")
                .swap(0, 1)
        }),
        ("unknown", |report| report["unexpected"] = json!(true)),
    ];

    for (name, mutate) in cases {
        let (temporary, mut linux, _, _) = fixture();
        mutate(&mut linux);
        write_report(
            &temporary
                .path()
                .join("input/release-certification-linux/backend-linux-cgroup-v2.json"),
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

    write_report(
        &input.join("duplicate/backend-linux-cgroup-v2.json"),
        &linux,
    );
    assert!(collect_certification(&input, &output, COMMIT).is_err());
    fs::remove_dir_all(input.join("duplicate")).expect("duplicate directory should be removable");

    fs::write(
        input.join("release-certification-linux/backend-linux-cgroup-v2.json"),
        vec![b' '; 64 * 1024 + 1],
    )
    .expect("oversize report should write");
    assert!(collect_certification(&input, &output, COMMIT).is_err());
}
