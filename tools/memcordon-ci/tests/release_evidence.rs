use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use memcordon_ci::release_evidence::{LINUX_SEALED_TESTS as LINUX_TESTS, collect_certification};
use memcordon_core::{
    AttemptHistory, AttemptKind, AttemptPhase, AttemptRecord, BackendCapabilityReport,
    BoundaryCapability, BoundaryClass, BoundaryMechanismEvidence, BoundaryQualificationReport,
    BoundaryRequirement, BudgetKindReport, BudgetTokenReport, ChildTermination, CleanupSummary,
    DeadlinePolicyReport, DeadlineScope, EffectivePolicyReport, EffectiveRestartPolicyReport,
    InvocationReport, LaunchEvidence, LinuxSealedEvidence, MemcordonReport, NativeArgument,
    PolicyEnvelopeReport, RequestedPolicyReport, RequestedRestartPolicyReport, RestartConditions,
    RestartDecisionRecord, RestartLimit, RestartSafetyProof, RestartSummary, RunOutcome,
    SupervisionAggregates, SupervisionExecution, SupervisionTerminal, ToolReport,
};
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

fn public_launch_report() -> Value {
    let provider_identity = "fixture-provider";
    let receipt_digest = "fixture-receipt";
    let mechanism = "linux-pid-namespace-cgroup-v1";
    let backend = BackendCapabilityReport {
        name: "linux-sealed-provider".to_owned(),
        boundary: BoundaryCapability {
            class: BoundaryClass::Sealed,
            mechanism: mechanism.to_owned(),
            target_gated: true,
            boundary_verified_before_authorization: true,
            target_can_reconfigure_boundary: false,
            frontend_loss_cleanup_authority: true,
            workload_empty_proof: true,
            limitations: Vec::new(),
        },
        boundary_qualification: Some(BoundaryQualificationReport {
            provider_identity: provider_identity.to_owned(),
            receipt_digest: receipt_digest.to_owned(),
            mechanism: mechanism.to_owned(),
        }),
        ..BackendCapabilityReport::default()
    };
    let cleanup = CleanupSummary {
        direct_child_reaped: true,
        workload_empty: Some(true),
        ..CleanupSummary::default()
    };
    let outcome = RunOutcome::Exited {
        child: ChildTermination::ExitCode { code: 0 },
        peak: None,
        cleanup,
    };
    let attempt = AttemptRecord {
        number: 1,
        kind: AttemptKind::Initial,
        phase: AttemptPhase::Completed,
        target_pid: Some(101),
        started_offset_ms: Some(1),
        authorized_offset_ms: Some(2),
        terminal_offset_ms: Some(3),
        finished_offset_ms: 4,
        outcome: Some(outcome.clone()),
        error: None,
        restart_decision: RestartDecisionRecord::default(),
        launch: LaunchEvidence {
            mechanism: mechanism.to_owned(),
            target_released: true,
            containment_verified_before_authorization: true,
            guardian_started_before_authorization: true,
            target_spawn_error_reported: true,
            boundary_requested: BoundaryRequirement::Sealed,
            boundary_effective: BoundaryClass::Sealed,
            boundary_assignment_verified: true,
            boundary_reconfiguration_denied: true,
            inherited_resources_restricted: true,
            frontend_loss_cleanup_authority_verified: true,
        },
        restart_safety: RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        },
        boundary_detail: BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV1(
            LinuxSealedEvidence {
                schema_version: 1,
                provider_identity: provider_identity.to_owned(),
                cgroup_identity_digest: "fixture-cgroup".to_owned(),
                cgroup_created: true,
                cgroup_owned_by_provider: true,
                memory_configuration_verified: true,
                init_created_into_cgroup: true,
                pid_namespace_created: true,
                mount_namespace_created: true,
                cgroup_namespace_created: true,
                target_pidfd_verified: true,
                target_cgroup_membership_verified: true,
                target_pid_namespace_verified: true,
                target_credentials_verified: true,
                target_capabilities_empty: true,
                no_new_privs_verified: true,
                inherited_descriptors_verified: true,
                writable_cgroup_view_denied: true,
                guardian_ready: true,
                target_released: true,
                cgroup_kill_invoked: true,
                cgroup_empty_verified: true,
                namespace_init_reaped: true,
                guardian_reaped: true,
                cgroup_removed: true,
            },
        ),
    };
    let mut attempts = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    attempts
        .append(attempt, &mut aggregates)
        .expect("public launch attempt should append");
    let execution = SupervisionExecution::new(
        backend.clone(),
        SupervisionTerminal::AttemptOutcome {
            attempt_number: 1,
            outcome,
        },
        attempts,
        aggregates,
        RestartSummary::default(),
        None,
        4,
        1,
    )
    .expect("public launch execution should be valid");
    let report = MemcordonReport::schema7(
        ToolReport {
            name: "memcordon".to_owned(),
            version: "test".to_owned(),
        },
        InvocationReport {
            syntax: "plus-budgets-v1".to_owned(),
            budget_tokens: vec![BudgetTokenReport {
                kind: BudgetKindReport::Time,
                token: "+1s".to_owned(),
            }],
            memory_token: None,
            deadline_token: Some("+1s".to_owned()),
            argv: vec![NativeArgument::from_os(OsStr::new("/usr/bin/true"))],
        },
        PolicyEnvelopeReport {
            requested: RequestedPolicyReport {
                boundary: BoundaryRequirement::Sealed,
                memory: None,
                deadline: Some(DeadlinePolicyReport {
                    duration_ms: 1_000,
                    scope: DeadlineScope::Attempt,
                    origin: None,
                    clock: "rust-instant".to_owned(),
                }),
                wait_for: "command".to_owned(),
                signal_grace_ms: 2_000,
                command_exit_grace_ms: 0,
                limit_grace_ms: 0,
                restart: RequestedRestartPolicyReport {
                    enabled: false,
                    enablement_source: None,
                    configured_conditions: RestartConditions::NONE,
                    limit: RestartLimit::Unlimited,
                    backoff: None,
                    circuit_breaker: None,
                },
            },
            effective: EffectivePolicyReport {
                boundary: BoundaryClass::Sealed,
                memory: None,
                deadline: Some(DeadlinePolicyReport {
                    duration_ms: 1_000,
                    scope: DeadlineScope::Attempt,
                    origin: Some("fixture".to_owned()),
                    clock: "rust-instant".to_owned(),
                }),
                wait_for: "command".to_owned(),
                signal_grace_ms: 2_000,
                command_exit_grace_ms: 0,
                limit_grace_ms: 0,
                restart: EffectiveRestartPolicyReport {
                    enabled: false,
                    conditions: RestartConditions::NONE,
                    dormant_conditions: Vec::new(),
                    cleanup_proof_required: true,
                },
            },
            effects: Vec::new(),
        },
        Some(backend),
        Some(execution),
        None,
    )
    .expect("public launch report should be valid");
    serde_json::to_value(report).expect("public launch report should serialize")
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
    let left_identity = "00".repeat(std::mem::size_of::<[u8; 16]>());
    let right_identity = "11".repeat(std::mem::size_of::<[u8; 16]>());
    write_report(
        &input.join("release-certification-linux/sealed-concurrency-report.json"),
        &json!({
            "schema_version": 1,
            "mechanism": "linux-pid-namespace-cgroup-v1",
            "commit": COMMIT,
            "overlap": true,
            "attempts": [
                {
                    "identity": left_identity,
                    "target_pid": 101,
                    "live_cgroup_member_pids": [100, 101],
                    "started_monotonic_millis": 1,
                    "authorized_monotonic_millis": 3,
                    "terminal_monotonic_millis": 8,
                    "record_absent": true,
                    "cgroup_absent": true,
                    "fixture_absent": true,
                    "boundary_retired": true
                },
                {
                    "identity": right_identity,
                    "target_pid": 201,
                    "live_cgroup_member_pids": [200, 201],
                    "started_monotonic_millis": 2,
                    "authorized_monotonic_millis": 4,
                    "terminal_monotonic_millis": 9,
                    "record_absent": true,
                    "cgroup_absent": true,
                    "fixture_absent": true,
                    "boundary_retired": true
                }
            ]
        }),
    );
    let identity = json!({"schema_version": 1, "mechanism": "linux-pid-namespace-cgroup-v1", "provider_identity": "fixture-provider", "receipt_digest": "fixture-receipt"});
    write_report(
        &input.join("release-certification-linux/provider-identity.json"),
        &identity,
    );
    let mut qualification = identity.clone();
    for field in [
        "unified_cgroup_v2",
        "private_cgroup_subtree",
        "clone3",
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
        "spawn_error_reporting_verified",
        "frontend_loss_authority_verified",
        "cgroup_kill",
        "workload_empty",
        "helpers_reaped",
        "boundary_retired",
        "recovery_complete",
    ] {
        qualification[field] = json!(true);
    }
    write_report(
        &input.join("release-certification-linux/qualification-receipt.json"),
        &qualification,
    );
    let fault_selectors = [
        (
            "sealed_frontend_loss_before_authorization_never_runs_target",
            "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION",
            "authorization",
            true,
            false,
            true,
            "guardian",
            true,
        ),
        (
            "sealed_frontend_loss_after_authorization_triggers_guardian",
            "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION",
            "monitoring",
            true,
            true,
            true,
            "guardian",
            true,
        ),
        (
            "sealed_provider_worker_loss_triggers_guardian",
            "MCSEALED-PROVIDER-WORKER-LOSS",
            "guardian-startup",
            false,
            false,
            true,
            "guardian",
            true,
        ),
        (
            "sealed_guardian_loss_before_authorization_fails_closed",
            "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION",
            "authorization",
            true,
            false,
            true,
            "provider",
            true,
        ),
        (
            "sealed_guardian_loss_after_authorization_cannot_report_success",
            "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION",
            "monitoring",
            true,
            true,
            true,
            "provider",
            true,
        ),
        (
            "sealed_faults_before_authorization_never_create_marker",
            "MCSEALED-LAUNCH-DESCRIPTOR-SET",
            "request-validation",
            false,
            false,
            false,
            "provider",
            false,
        ),
        (
            "sealed_namespace_init_failure_is_typed_prompt_and_retired",
            "MCSEALED-NAMESPACE-INIT-TARGET-FORK",
            "target-creation",
            false,
            false,
            true,
            "provider",
            true,
        ),
        (
            "sealed_cgroup_kill_failure_never_reports_retirement",
            "MCSEALED-CGROUP-KILL-FAILURE",
            "retirement",
            true,
            true,
            true,
            "provider",
            true,
        ),
        (
            "sealed_persistent_populated_state_blocks_restart",
            "MCSEALED-CGROUP-NOT-EMPTY",
            "retirement",
            true,
            true,
            true,
            "provider",
            true,
        ),
        (
            "sealed_namespace_init_reap_delay_blocks_result",
            "MCSEALED-NAMESPACE-INIT-REAP-DELAY",
            "retirement",
            true,
            true,
            true,
            "provider",
            true,
        ),
        (
            "sealed_guardian_reap_failure_blocks_result",
            "MCSEALED-GUARDIAN-REAP-FAILURE",
            "retirement",
            true,
            true,
            true,
            "provider",
            true,
        ),
    ];
    let fault_evidence = fault_selectors
        .iter()
        .enumerate()
        .map(
            |(
                index,
                (
                    selector,
                    code,
                    phase,
                    target_created,
                    target_released,
                    cleanup_retired,
                    retirement_owner,
                    guardian_reaped,
                ),
            )| {
            json!({
                "schema_version": 1,
                "selector": selector,
                "attempt_id": format!("{index:032x}"),
                "rejection": {
                    "schema_version": 1,
                    "code": code,
                    "phase": phase,
                    "detail": format!("{code}: release fixture"),
                    "os_code": null,
                    "target_created": target_created,
                    "target_released": target_released,
                    "cleanup": {
                        "attempted": cleanup_retired,
                        "direct_child_reaped": cleanup_retired,
                        "workload_empty": if *cleanup_retired { json!(true) } else { Value::Null },
                        "helpers_reaped": cleanup_retired,
                        "containment_removed": cleanup_retired,
                        "sealed_boundary_retired": cleanup_retired,
                        "errors": []
                    }
                },
                "retirement_owner": retirement_owner,
                "marker_observed": target_released,
                "guardian_reaped": guardian_reaped,
                "final_record_absent": true,
                "final_cgroup_absent": true
            })
        },
        )
        .collect::<Vec<_>>();
    write_report(
        &input.join("release-certification-linux/fault-injection-report.json"),
        &json!({
            "schema_version": 2,
            "mechanism": "linux-pid-namespace-cgroup-v1",
            "commit": COMMIT,
            "result": "passed",
            "evidence": fault_evidence
        }),
    );
    let named = json!({"schema_version": 1, "mechanism": "linux-pid-namespace-cgroup-v1", "result": "passed", "tests": ["fixture"]});
    write_report(
        &input.join("release-certification-linux/cleanup-recovery-report.json"),
        &named,
    );
    write_report(
        &input.join("release-certification-linux/platform-environment.json"),
        &json!({"schema_version": memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION, "selected": {"boundary": {"class": "sealed", "mechanism": "linux-pid-namespace-cgroup-v1"}}}),
    );
    write_report(
        &input.join("release-certification-linux/provider-service-privileges.json"),
        &json!({
            "schema_version": 1,
            "properties": {
                "User": "root",
                "Group": "memcordon",
                "NoNewPrivileges": "yes",
                "CapabilityBoundingSet": "cap_dac_override cap_kill cap_setgid cap_setuid cap_sys_admin cap_sys_chroot cap_sys_ptrace",
                "AmbientCapabilities": ""
            }
        }),
    );
    write_report(
        &input.join("release-certification-linux/sealed-public-launch.json"),
        &public_launch_report(),
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

    assert_eq!(records.len(), 11);
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
        "sealed-concurrency-report.json",
        "fault-injection-report.json",
        "cleanup-recovery-report.json",
        "platform-environment.json",
        "provider-service-privileges.json",
        "sealed-public-launch.json",
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
fn linux_concurrency_evidence_mutations_fail_closed() {
    let cases: &[(&str, ReportMutation)] = &[
        ("overlap", |report| report["overlap"] = json!(false)),
        ("identity", |report| {
            report["attempts"][1]["identity"] = report["attempts"][0]["identity"].clone()
        }),
        ("membership", |report| {
            report["attempts"][1]["live_cgroup_member_pids"] = json!([101, 201])
        }),
        ("target", |report| {
            report["attempts"][0]["target_pid"] = json!(999)
        }),
        ("retirement", |report| {
            report["attempts"][0]["record_absent"] = json!(false)
        }),
        ("interval", |report| {
            report["attempts"][0]["terminal_monotonic_millis"] =
                report["attempts"][1]["authorized_monotonic_millis"].clone()
        }),
        ("unknown", |report| report["unexpected"] = json!(true)),
    ];

    for (name, mutate) in cases {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-linux/sealed-concurrency-report.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut report);
        write_report(&path, &report);
        let result = collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        );
        assert!(result.is_err(), "{name} mutation should fail closed");
    }
}

#[test]
fn linux_fault_evidence_mutations_fail_closed() {
    let cases: &[(&str, ReportMutation)] = &[
        ("commit", |report| report["commit"] = json!("different")),
        ("missing-selector", |report| {
            report["evidence"].as_array_mut().unwrap().pop();
        }),
        ("duplicate-selector", |report| {
            report["evidence"][1]["selector"] = report["evidence"][0]["selector"].clone()
        }),
        ("wrong-code", |report| {
            report["evidence"][0]["rejection"]["code"] =
                json!("MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION");
            report["evidence"][0]["rejection"]["detail"] =
                json!("MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION: wrong selector binding");
        }),
        ("wrong-phase", |report| {
            report["evidence"][1]["rejection"]["phase"] = json!("retirement")
        }),
        ("wrong-owner", |report| {
            report["evidence"][3]["retirement_owner"] = json!("guardian")
        }),
        ("wrong-target-facts", |report| {
            report["evidence"][2]["rejection"]["target_created"] = json!(true)
        }),
        ("residual-record", |report| {
            report["evidence"][0]["final_record_absent"] = json!(false)
        }),
        ("released-without-target", |report| {
            report["evidence"][0]["rejection"]["target_created"] = json!(false);
            report["evidence"][0]["rejection"]["target_released"] = json!(true);
            report["evidence"][0]["marker_observed"] = json!(true);
        }),
        ("marker-contradiction", |report| {
            report["evidence"][1]["marker_observed"] = json!(false)
        }),
        ("retirement-contradiction", |report| {
            report["evidence"][0]["rejection"]["cleanup"]["sealed_boundary_retired"] = json!(true);
            report["evidence"][0]["rejection"]["cleanup"]["workload_empty"] = json!(false);
        }),
        ("unknown", |report| {
            report["evidence"][0]["unexpected"] = json!(true)
        }),
    ];

    for (name, mutate) in cases {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-linux/fault-injection-report.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut report);
        write_report(&path, &report);
        let result = collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        );
        assert!(result.is_err(), "{name} mutation should fail closed");
    }
}

#[test]
fn promoted_linux_evidence_mutations_fail_closed() {
    let cases: &[(&str, &str, ReportMutation)] = &[
        (
            "privilege-user",
            "provider-service-privileges.json",
            |report| report["properties"]["User"] = json!("memcordon"),
        ),
        (
            "privilege-capabilities",
            "provider-service-privileges.json",
            |report| report["properties"]["CapabilityBoundingSet"] = json!("cap_kill"),
        ),
        (
            "privilege-duplicate-capability",
            "provider-service-privileges.json",
            |report| {
                report["properties"]["CapabilityBoundingSet"] = json!(
                    "cap_dac_override cap_kill cap_setgid cap_setuid cap_sys_admin cap_sys_chroot cap_sys_ptrace cap_kill"
                )
            },
        ),
        (
            "privilege-extra-property",
            "provider-service-privileges.json",
            |report| report["properties"]["Unexpected"] = json!("value"),
        ),
        (
            "privilege-unknown-field",
            "provider-service-privileges.json",
            |report| report["unexpected"] = json!(true),
        ),
        ("public-schema", "sealed-public-launch.json", |report| {
            report["schema_version"] = json!(0)
        }),
        (
            "public-provider-identity",
            "sealed-public-launch.json",
            |report| {
                report["backend"]["boundary_qualification"]["provider_identity"] =
                    json!("other-provider")
            },
        ),
        (
            "public-receipt-digest",
            "sealed-public-launch.json",
            |report| {
                report["backend"]["boundary_qualification"]["receipt_digest"] =
                    json!("other-receipt")
            },
        ),
        (
            "public-boundary-mechanism",
            "sealed-public-launch.json",
            |report| report["backend"]["boundary"]["mechanism"] = json!("standard"),
        ),
        (
            "public-terminal-cleanup",
            "sealed-public-launch.json",
            |report| {
                report["supervision"]["terminal"]["outcome"]["cleanup"]["workload_empty"] =
                    json!(false)
            },
        ),
        (
            "public-boundary-assignment",
            "sealed-public-launch.json",
            |report| report["attempts"][0]["launch"]["boundary_assignment_verified"] = json!(false),
        ),
        (
            "public-native-provider",
            "sealed-public-launch.json",
            |report| {
                report["attempts"][0]["boundary_detail"]["provider_identity"] =
                    json!("other-provider")
            },
        ),
        (
            "public-native-namespace",
            "sealed-public-launch.json",
            |report| {
                report["attempts"][0]["boundary_detail"]["pid_namespace_created"] = json!(false)
            },
        ),
        (
            "public-native-target-release",
            "sealed-public-launch.json",
            |report| report["attempts"][0]["boundary_detail"]["target_released"] = json!(false),
        ),
        (
            "public-unknown-field",
            "sealed-public-launch.json",
            |report| report["unexpected"] = json!(true),
        ),
    ];

    for (name, report_name, mutate) in cases {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-linux")
            .join(report_name);
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut report);
        write_report(&path, &report);
        let result = collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        );
        assert!(result.is_err(), "{name} mutation should fail closed");
    }
}

#[test]
fn linux_provider_identity_binding_fails_closed() {
    for field in ["provider_identity", "receipt_digest"] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-linux/qualification-receipt.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        report[field] = json!(format!("mismatched-{field}"));
        write_report(&path, &report);
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "{field} mismatch should fail closed"
        );
    }
}

#[test]
fn promoted_linux_inventory_is_exact_and_failure_inventory_is_not_releasable() {
    let (successful, _, _, _) = fixture();
    let successful_linux = successful.path().join("input/release-certification-linux");
    assert_eq!(
        fs::read_dir(&successful_linux)
            .expect("successful Linux inventory should be readable")
            .count(),
        9,
        "successful Linux release inventory must contain exactly nine files"
    );

    for name in [
        "provider-service-privileges.json",
        "sealed-public-launch.json",
    ] {
        let (temporary, _, _, _) = fixture();
        fs::remove_file(
            temporary
                .path()
                .join("input/release-certification-linux")
                .join(name),
        )
        .expect("promoted evidence should be removable from the fixture");
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "missing {name} should fail closed"
        );
    }

    let (temporary, _, _, _) = fixture();
    let linux = temporary.path().join("input/release-certification-linux");
    write_report(
        &linux.join("unexpected.json"),
        &json!({"schema_version": 1}),
    );
    assert!(
        collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        )
        .is_err(),
        "extra Linux evidence should fail closed"
    );

    let (temporary, _, _, _) = fixture();
    let linux = temporary.path().join("input/release-certification-linux");
    for entry in fs::read_dir(&linux).expect("Linux fixture should be readable") {
        fs::remove_file(entry.expect("fixture entry should be readable").path())
            .expect("success evidence should be removable");
    }
    let failure_inventory = [
        "certification-run.json",
        "certification-failure.json",
        "sealed-scenario-progress.json",
        "provider-service-privileges.json",
        "sealed-public-launch.json",
        "provider-identity.json",
        "qualification-receipt.json",
        "platform-environment.json",
    ];
    assert_eq!(
        failure_inventory.len(),
        8,
        "failed Linux diagnostic inventory must contain exactly eight files"
    );
    for name in failure_inventory {
        write_report(&linux.join(name), &json!({"schema_version": 1}));
    }
    assert_eq!(
        fs::read_dir(&linux)
            .expect("failed Linux inventory should be readable")
            .count(),
        8,
    );
    assert!(
        collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        )
        .is_err(),
        "the eight-file failure diagnostic inventory must not be release input"
    );

    let (temporary, _, _, _) = fixture();
    let linux = temporary.path().join("input/release-certification-linux");
    for entry in fs::read_dir(&linux).expect("Linux fixture should be readable") {
        fs::remove_file(entry.expect("fixture entry should be readable").path())
            .expect("success evidence should be removable");
    }
    let late_package_failure_inventory = [
        "certification-run.json",
        "certification-failure.json",
        "sealed-scenario-progress.json",
        "provider-service-privileges.json",
        "sealed-public-launch.json",
        "provider-identity.json",
        "qualification-receipt.json",
        "platform-environment.json",
        "sealed-concurrency-report.json",
    ];
    assert_eq!(
        late_package_failure_inventory.len(),
        9,
        "late package failure diagnostics have the success inventory's count but not its names"
    );
    for name in late_package_failure_inventory {
        write_report(&linux.join(name), &json!({"schema_version": 1}));
    }
    assert_eq!(
        fs::read_dir(&linux)
            .expect("late failed Linux inventory should be readable")
            .count(),
        9,
    );
    assert!(
        collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        )
        .is_err(),
        "the nine-file late package failure inventory must not be mistaken for release input"
    );
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
