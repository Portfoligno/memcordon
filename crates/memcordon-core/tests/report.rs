use std::ffi::OsStr;
use std::fs;
use std::time::Duration;

use memcordon_core::{
    AttemptHistory, AttemptKind, AttemptPhase, AttemptRecord, BackendCapabilityReport, ByteSize,
    ChildTermination, CleanupSummary, DETAILED_ATTEMPT_CAPACITY, DeadlineEvidence,
    HalfLifeLogisticBackoffPolicy, InitialSpawnFailure, LaunchEvidence, RestartAction,
    RestartCoordinator, RestartDecisionRecord, RestartSafetyProof, RestartSettings, RestartSummary,
    RunOutcome, SupervisionAggregates, SupervisionDeadlineEvidence, SupervisionErrorRecord,
    SupervisionExecution, SupervisionPhase, SupervisionTerminal, WaitCompletion,
};
use memcordon_core::{
    BackoffPolicyReport, BudgetKindReport, BudgetTokenReport, CircuitBreakerPolicyReport,
    CircuitState, DeadlinePolicyReport, DeadlineScope, DormantRestartCondition,
    EXECUTION_REPORT_SCHEMA_VERSION, EffectiveMemoryPolicyReport, EffectivePolicyReport,
    EffectiveRestartPolicyReport, ErrorCategory, ExecutionErrorReport, InvocationReport,
    MemcordonReport, NativeArgument, PolicyEnvelopeReport, RequestedMemoryPolicyReport,
    RequestedPolicyReport, RequestedRestartPolicyReport, RestartCondition, RestartConditions,
    RestartLimit, SwapReport, ToolReport, write_report_atomic,
};

fn report() -> MemcordonReport {
    MemcordonReport::schema7(
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
            argv: vec![NativeArgument::from_os(OsStr::new("program"))],
        },
        PolicyEnvelopeReport {
            requested: RequestedPolicyReport {
                boundary: memcordon_core::BoundaryRequirement::Standard,
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
                boundary: memcordon_core::BoundaryClass::Standard,
                memory: None,
                deadline: Some(DeadlinePolicyReport {
                    duration_ms: 1_000,
                    scope: DeadlineScope::Attempt,
                    origin: Some("test-origin".to_owned()),
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
                    cleanup_proof_required: false,
                },
            },
            effects: Vec::new(),
        },
        None,
        None,
        Some(ExecutionErrorReport {
            category: "spawn".to_owned(),
            code: "MCSPAWN".to_owned(),
            message: "fixture".to_owned(),
            os_code: None,
            attempt_number: None,
            supervision_phase: Some("initial-setup".to_owned()),
            launch_phase: None,
            target_released: false,
            workload_may_be_alive: false,
            boundary_setup_failure: None,
        }),
    )
    .expect("valid report")
}

#[test]
#[cfg_attr(
    miri,
    ignore = "requires host filesystem operations unavailable under Miri isolation"
)]
fn atomic_report_replaces_existing_relative_destination_and_ends_in_newline() {
    let temporary = tempfile::tempdir().expect("temporary directory should exist");
    let path = temporary.path().join("report.json");
    fs::write(&path, b"old\n").expect("existing report should write");
    write_report_atomic(&path, &report()).expect("report should replace atomically");
    let bytes = fs::read(&path).expect("report should read");
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_ne!(bytes.get(bytes.len().saturating_sub(2)), Some(&b'\n'));
    let decoded: MemcordonReport =
        serde_json::from_slice(&bytes).expect("typed schema should read");
    assert_eq!(decoded.schema_version, EXECUTION_REPORT_SCHEMA_VERSION);
    assert!(decoded.policy.requested.memory.is_none());
    assert!(decoded.invocation.memory_token.is_none());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "requires host filesystem operations unavailable under Miri isolation"
)]
fn atomic_report_accepts_a_bare_relative_file_name() {
    let path = std::path::PathBuf::from(format!(
        "memcordon-relative-report-{}.json",
        std::process::id()
    ));
    write_report_atomic(&path, &report()).expect("bare relative report should write");
    let bytes = fs::read(&path).expect("bare relative report should read");
    assert_eq!(bytes.last(), Some(&b'\n'));
    fs::remove_file(path).expect("bare relative report should remove");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "requires host filesystem operations unavailable under Miri isolation"
)]
fn report_rejects_missing_parent_without_leaving_a_temporary_file() {
    let temporary = tempfile::tempdir().expect("temporary directory should exist");
    let missing = temporary.path().join("missing");
    let path = missing.join("report.json");
    let error = write_report_atomic(&path, &report()).expect_err("missing parent must fail");
    assert_eq!(error.category, ErrorCategory::Report);
    assert_eq!(error.code, "MCREPORT-WRITE");
    assert!(!missing.exists());
}

#[cfg(unix)]
#[test]
fn native_argument_preserves_non_utf8_unix_bytes() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use std::os::unix::ffi::OsStringExt;

    let bytes = vec![b'a', 0xff, b'b'];
    let value = std::ffi::OsString::from_vec(bytes.clone());
    let encoded = NativeArgument::from_os(&value);
    let raw = encoded.raw.expect("non-UTF-8 argument requires raw data");
    assert_eq!(raw.encoding, "unix-bytes-base64");
    assert_eq!(
        STANDARD.decode(raw.data).expect("base64 should decode"),
        bytes
    );
}

#[test]
fn circuit_state_is_typed_in_schema_models() {
    assert_eq!(
        serde_json::to_string(&CircuitState::HalfOpen).expect("serialize"),
        "\"half-open\""
    );
}

#[test]
fn schema_five_budget_orders_restart_numbers_and_nulls_round_trip_exactly() {
    let cases = [
        (Vec::new(), None, None),
        (
            vec![BudgetTokenReport {
                kind: BudgetKindReport::Memory,
                token: "+8GiB".to_owned(),
            }],
            Some("+8GiB".to_owned()),
            None,
        ),
        (
            vec![
                BudgetTokenReport {
                    kind: BudgetKindReport::Time,
                    token: "+10m".to_owned(),
                },
                BudgetTokenReport {
                    kind: BudgetKindReport::Memory,
                    token: "+8GiB".to_owned(),
                },
            ],
            Some("+8GiB".to_owned()),
            Some("+10m".to_owned()),
        ),
        (
            vec![
                BudgetTokenReport {
                    kind: BudgetKindReport::Memory,
                    token: "+8GiB".to_owned(),
                },
                BudgetTokenReport {
                    kind: BudgetKindReport::Time,
                    token: "+10m".to_owned(),
                },
            ],
            Some("+8GiB".to_owned()),
            Some("+10m".to_owned()),
        ),
    ];
    for (tokens, memory, deadline) in cases {
        let mut report = report();
        let expected_tokens = tokens.clone();
        report.invocation.budget_tokens = tokens;
        report.invocation.memory_token = memory;
        report.invocation.deadline_token = deadline;
        report.policy.requested.memory =
            report
                .invocation
                .memory_token
                .as_ref()
                .map(|_| RequestedMemoryPolicyReport {
                    limit_bytes: 8 * 1024 * 1024 * 1024,
                    enforcement: "auto".to_owned(),
                    metric: "native".to_owned(),
                    poll_interval_ms: 50,
                    swap: SwapReport::Bytes { bytes: 0 },
                });
        report.policy.effective.memory =
            report
                .invocation
                .memory_token
                .as_ref()
                .map(|_| EffectiveMemoryPolicyReport {
                    limit_bytes: 8 * 1024 * 1024 * 1024,
                    enforcement: "hard".to_owned(),
                    metric: "native".to_owned(),
                    poll_interval_ms: None,
                    swap: Some(SwapReport::Bytes { bytes: 0 }),
                });
        report.policy.requested.deadline =
            report
                .invocation
                .deadline_token
                .as_ref()
                .map(|_| DeadlinePolicyReport {
                    duration_ms: 600_000,
                    scope: DeadlineScope::Attempt,
                    origin: None,
                    clock: "rust-instant".to_owned(),
                });
        report.policy.effective.deadline =
            report
                .invocation
                .deadline_token
                .as_ref()
                .map(|_| DeadlinePolicyReport {
                    duration_ms: 600_000,
                    scope: DeadlineScope::Attempt,
                    origin: Some("test-origin".to_owned()),
                    clock: "rust-instant".to_owned(),
                });
        let restart_enabled =
            report.invocation.memory_token.is_some() || report.invocation.deadline_token.is_some();
        report.policy.requested.restart = RequestedRestartPolicyReport {
            enabled: restart_enabled,
            enablement_source: restart_enabled.then(|| "restart-on".to_owned()),
            configured_conditions: if restart_enabled {
                RestartConditions::BOTH
            } else {
                RestartConditions::NONE
            },
            limit: RestartLimit::Count(std::num::NonZeroU64::new(3).expect("nonzero")),
            backoff: restart_enabled.then_some(BackoffPolicyReport {
                model: "half-life-logistic-v1".to_owned(),
                base_interval_ms: 1000,
                multiplier_numerator: 3,
                multiplier_denominator: 2,
                asymptote_interval_ms: 30000,
                recovery_half_life_ms: 30000,
                quantization: "ceil-whole-milliseconds".to_owned(),
            }),
            circuit_breaker: restart_enabled.then_some(CircuitBreakerPolicyReport {
                threshold: 2.5,
                half_life_ms: 10000,
                cooldown_ms: 3000,
            }),
        };
        report.policy.effective.restart.enabled = restart_enabled;
        report.policy.effective.restart.conditions = match (
            report.invocation.memory_token.is_some(),
            report.invocation.deadline_token.is_some(),
        ) {
            (true, true) => RestartConditions::BOTH,
            (true, false) => RestartConditions::MEMORY_LIMIT,
            (false, true) => RestartConditions::DEADLINE,
            (false, false) => RestartConditions::NONE,
        };
        report.policy.effective.restart.dormant_conditions =
            if restart_enabled && report.invocation.deadline_token.is_none() {
                vec![DormantRestartCondition {
                    condition: RestartCondition::Deadline,
                    reason: "no attempt deadline".to_owned(),
                }]
            } else {
                Vec::new()
            };
        let value = serde_json::to_value(&report).expect("schema JSON");
        assert_eq!(
            value["invocation"]["budget_tokens"],
            serde_json::to_value(expected_tokens).expect("budget tokens")
        );
        if report.invocation.memory_token.is_some() {
            assert_eq!(
                value["policy"]["requested"]["memory"]["limit_bytes"],
                8 * 1024 * 1024 * 1024_u64
            );
        } else {
            assert!(value["policy"]["requested"]["memory"].is_null());
        }
        if report.invocation.deadline_token.is_some() {
            assert_eq!(
                value["policy"]["requested"]["deadline"]["duration_ms"],
                600_000
            );
        } else {
            assert!(value["policy"]["requested"]["deadline"].is_null());
        }
        assert_eq!(
            value["policy"]["requested"]["restart"]["enabled"],
            restart_enabled
        );
        if restart_enabled {
            assert_eq!(
                value["policy"]["requested"]["restart"]["backoff"]["base_interval_ms"],
                1000
            );
            assert_eq!(
                value["policy"]["requested"]["restart"]["circuit_breaker"]["threshold"],
                2.5
            );
            assert_eq!(
                value["policy"]["requested"]["restart"]["circuit_breaker"]["half_life_ms"],
                10000
            );
            assert!(
                value["policy"]["requested"]["restart"]["circuit_breaker"]
                    .get("burst")
                    .is_none()
            );
            assert!(
                value["policy"]["requested"]["restart"]["circuit_breaker"]
                    .get("window_ms")
                    .is_none()
            );
        } else {
            assert!(value["policy"]["requested"]["restart"]["backoff"].is_null());
            assert!(value["policy"]["requested"]["restart"]["circuit_breaker"].is_null());
        }
        assert!(value["supervision"].is_null());
        let decoded: MemcordonReport = serde_json::from_value(value).expect("validated round trip");
        assert_eq!(
            decoded.invocation.budget_tokens,
            report.invocation.budget_tokens
        );
    }
}

#[test]
fn schema_five_preserves_explicit_zero_budgets() {
    let mut report = report();
    report.invocation.budget_tokens = vec![
        BudgetTokenReport {
            kind: BudgetKindReport::Memory,
            token: "+0B".to_owned(),
        },
        BudgetTokenReport {
            kind: BudgetKindReport::Time,
            token: "+0ms".to_owned(),
        },
    ];
    report.invocation.memory_token = Some("+0B".to_owned());
    report.invocation.deadline_token = Some("+0ms".to_owned());
    report.policy.requested.memory = Some(RequestedMemoryPolicyReport {
        limit_bytes: 0,
        enforcement: "auto".to_owned(),
        metric: "native".to_owned(),
        poll_interval_ms: 50,
        swap: SwapReport::Bytes { bytes: 0 },
    });
    report.policy.effective.memory = Some(EffectiveMemoryPolicyReport {
        limit_bytes: 0,
        enforcement: "hard".to_owned(),
        metric: "native".to_owned(),
        poll_interval_ms: None,
        swap: Some(SwapReport::Bytes { bytes: 0 }),
    });
    report
        .policy
        .requested
        .deadline
        .as_mut()
        .expect("requested deadline")
        .duration_ms = 0;
    report
        .policy
        .effective
        .deadline
        .as_mut()
        .expect("effective deadline")
        .duration_ms = 0;

    let value = serde_json::to_value(&report).expect("schema JSON");
    let decoded: MemcordonReport =
        serde_json::from_value(value).expect("validated zero-budget round trip");
    assert_eq!(
        decoded
            .policy
            .requested
            .memory
            .expect("explicit memory")
            .limit_bytes,
        0
    );
    assert_eq!(
        decoded
            .policy
            .requested
            .deadline
            .expect("explicit deadline")
            .duration_ms,
        0
    );
}

#[test]
fn deadline_evidence_accepts_an_immediate_deadline() {
    let evidence = DeadlineEvidence::new(
        0,
        DeadlineScope::Attempt,
        "test-origin".to_owned(),
        0,
        0,
        0,
        0,
        None,
        None,
    )
    .expect("zero-duration evidence");
    assert_eq!(evidence.duration_ms(), 0);
    assert_eq!(evidence.overshoot_ms(), 0);
    let value = serde_json::to_value(&evidence).expect("deadline evidence JSON");
    let decoded: DeadlineEvidence =
        serde_json::from_value(value).expect("zero-duration evidence round trip");
    assert_eq!(decoded, evidence);
}

#[test]
fn schema_five_rejects_envelope_history_and_budget_contradictions() {
    let mut value = serde_json::to_value(report()).expect("schema JSON");
    value["schema_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<MemcordonReport>(value).is_err());
    let mut value = serde_json::to_value(report()).expect("schema JSON");
    value["invocation"]["memory_token"] = serde_json::json!("+1GiB");
    assert!(serde_json::from_value::<MemcordonReport>(value).is_err());
    let mut value = serde_json::to_value(report()).expect("schema JSON");
    value["attempts"] = serde_json::json!([{}]);
    assert!(serde_json::from_value::<MemcordonReport>(value).is_err());
}

fn safe_proof() -> RestartSafetyProof {
    RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: false,
        sealed_boundary_retired: false,
        errors: Vec::new(),
    }
}

fn cleanup() -> CleanupSummary {
    CleanupSummary {
        direct_child_reaped: true,
        workload_empty: Some(true),
        ..CleanupSummary::default()
    }
}

fn attempt_record(
    number: u64,
    outcome: Option<RunOutcome>,
    error: Option<SupervisionErrorRecord>,
) -> AttemptRecord {
    AttemptRecord {
        number,
        kind: if number == 1 {
            AttemptKind::Initial
        } else {
            AttemptKind::Restart
        },
        phase: if outcome.is_some() {
            AttemptPhase::Completed
        } else {
            AttemptPhase::Failed
        },
        target_pid: outcome
            .is_some()
            .then(|| u32::try_from(number).expect("fixture number") + 100),
        started_offset_ms: Some(number),
        authorized_offset_ms: outcome.is_some().then_some(number + 1),
        terminal_offset_ms: outcome.is_some().then_some(number + 2),
        finished_offset_ms: number + 3,
        outcome,
        error,
        restart_decision: RestartDecisionRecord::default(),
        launch: LaunchEvidence {
            mechanism: "fixture".to_owned(),
            target_released: true,
            containment_verified_before_authorization: true,
            guardian_started_before_authorization: true,
            target_spawn_error_reported: false,
            ..LaunchEvidence::default()
        },
        restart_safety: safe_proof(),
        boundary_detail: memcordon_core::BoundaryMechanismEvidence::Standard {
            backend: "fixture".to_owned(),
        },
    }
}

#[test]
fn attempt_deserialization_rejects_contradictory_boundary_evidence() {
    let record = attempt_record(
        1,
        Some(RunOutcome::Exited {
            child: ChildTermination::ExitCode { code: 0 },
            peak: None,
            cleanup: cleanup(),
        }),
        None,
    );

    let mut sealed_with_standard_detail = serde_json::to_value(&record).expect("attempt JSON");
    sealed_with_standard_detail["launch"]["boundary_requested"] = serde_json::json!("sealed");
    sealed_with_standard_detail["launch"]["boundary_effective"] = serde_json::json!("sealed");
    sealed_with_standard_detail["restart_safety"]["sealed_boundary_retired"] =
        serde_json::json!(true);
    assert!(
        serde_json::from_value::<AttemptRecord>(sealed_with_standard_detail).is_err(),
        "sealed generic facts must not deserialize with standard mechanism evidence"
    );

    let mut standard_with_sealed_retirement = serde_json::to_value(record).expect("attempt JSON");
    standard_with_sealed_retirement["restart_safety"]["sealed_boundary_retired"] =
        serde_json::json!(true);
    assert!(
        serde_json::from_value::<AttemptRecord>(standard_with_sealed_retirement).is_err(),
        "standard attempts must not claim sealed retirement authority"
    );
}

fn report_from_execution(execution: SupervisionExecution) -> MemcordonReport {
    let mut base = report();
    base.invocation.budget_tokens = vec![
        BudgetTokenReport {
            kind: BudgetKindReport::Memory,
            token: "+1B".to_owned(),
        },
        BudgetTokenReport {
            kind: BudgetKindReport::Time,
            token: "+1s".to_owned(),
        },
    ];
    base.invocation.memory_token = Some("+1B".to_owned());
    base.policy.requested.memory = Some(RequestedMemoryPolicyReport {
        limit_bytes: 1,
        enforcement: "auto".to_owned(),
        metric: "native".to_owned(),
        poll_interval_ms: 50,
        swap: SwapReport::Bytes { bytes: 0 },
    });
    base.policy.effective.memory = Some(EffectiveMemoryPolicyReport {
        limit_bytes: 1,
        enforcement: "hard".to_owned(),
        metric: "native".to_owned(),
        poll_interval_ms: None,
        swap: Some(SwapReport::Bytes { bytes: 0 }),
    });
    let restart_enabled = execution.restart().enabled();
    base.policy.requested.restart = RequestedRestartPolicyReport {
        enabled: restart_enabled,
        enablement_source: restart_enabled.then(|| "restart-flag".to_owned()),
        configured_conditions: if restart_enabled {
            RestartConditions::BOTH
        } else {
            RestartConditions::NONE
        },
        limit: RestartLimit::Unlimited,
        backoff: restart_enabled.then_some(BackoffPolicyReport {
            model: "half-life-logistic-v1".to_owned(),
            base_interval_ms: 250,
            multiplier_numerator: 4,
            multiplier_denominator: 1,
            asymptote_interval_ms: 900000,
            recovery_half_life_ms: 900000,
            quantization: "ceil-whole-milliseconds".to_owned(),
        }),
        circuit_breaker: None,
    };
    base.policy.effective.restart.enabled = restart_enabled;
    base.policy.effective.restart.conditions = if restart_enabled {
        RestartConditions::BOTH
    } else {
        RestartConditions::NONE
    };
    base.policy.effective.restart.dormant_conditions.clear();
    MemcordonReport::schema7(
        base.tool,
        base.invocation,
        base.policy,
        Some(BackendCapabilityReport::default()),
        Some(execution),
        None,
    )
    .expect("schema7")
}

fn coordinator() -> RestartCoordinator {
    RestartCoordinator::new(
        RestartSettings::new(
            RestartConditions::BOTH,
            RestartConditions::BOTH,
            Vec::new(),
            RestartLimit::Unlimited,
            HalfLifeLogisticBackoffPolicy::default(),
            None,
        )
        .expect("settings"),
    )
    .expect("coordinator")
}

fn schedule_launch(coordinator: &mut RestartCoordinator, record: &mut RestartDecisionRecord) {
    let RestartAction::Wait { duration, .. } = coordinator
        .on_limit(
            RestartCondition::Deadline,
            Duration::ZERO,
            &safe_proof(),
            record,
        )
        .expect("wait")
    else {
        panic!("eligible deadline should schedule a restart wait");
    };
    assert!(matches!(
        coordinator
            .complete_wait(WaitCompletion::Completed, duration, None, record)
            .expect("launch"),
        RestartAction::Launch { .. }
    ));
}

fn deadline_report_value(attempts: u64) -> serde_json::Value {
    assert!(attempts > 0, "deadline report fixture requires an attempt");
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    let mut coordinator = coordinator();
    for number in 1..=attempts {
        let outcome = RunOutcome::DeadlineExceeded {
            deadline: DeadlineEvidence::new(
                10,
                DeadlineScope::Attempt,
                "test-origin".to_owned(),
                number,
                number,
                0,
                0,
                None,
                None,
            )
            .expect("evidence"),
            child_after_termination: None,
            peak: None,
            cleanup: cleanup(),
        };
        history
            .append(
                attempt_record(number, Some(outcome.clone()), None),
                &mut aggregates,
            )
            .expect("append");
        if number < attempts {
            let mut decision = RestartDecisionRecord::default();
            schedule_launch(&mut coordinator, &mut decision);
        }
    }
    let terminal = history
        .recent
        .back()
        .and_then(|record| record.outcome.clone())
        .expect("terminal");
    let execution = SupervisionExecution::new(
        BackendCapabilityReport::default(),
        SupervisionTerminal::AttemptOutcome {
            attempt_number: attempts,
            outcome: terminal,
        },
        history,
        aggregates,
        coordinator.summary().clone(),
        None,
        10_000,
        attempts,
    )
    .expect("execution");
    serde_json::to_value(report_from_execution(execution)).expect("json")
}

#[test]
fn schema_five_active_attempt_success_is_exact_and_round_trips() {
    let evidence = DeadlineEvidence::new(
        1_000,
        DeadlineScope::Attempt,
        "test-origin".to_owned(),
        1_001,
        1_004,
        0,
        0,
        None,
        Some("kill".to_owned()),
    )
    .expect("evidence");
    let outcome = RunOutcome::DeadlineExceeded {
        deadline: evidence,
        child_after_termination: None,
        peak: None,
        cleanup: cleanup(),
    };
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    history
        .append(
            attempt_record(1, Some(outcome.clone()), None),
            &mut aggregates,
        )
        .expect("append");
    let execution = SupervisionExecution::new(
        BackendCapabilityReport::default(),
        SupervisionTerminal::AttemptOutcome {
            attempt_number: 1,
            outcome,
        },
        history,
        aggregates,
        RestartSummary::default(),
        None,
        1_010,
        1,
    )
    .expect("execution");
    let value = serde_json::to_value(report_from_execution(execution)).expect("json");
    assert_eq!(value["supervision"]["phase"], "completed");
    assert_eq!(value["supervision"]["wrapper_exit_code"], 123);
    assert_eq!(
        value["supervision"]["attempt_history"]["capacity"],
        DETAILED_ATTEMPT_CAPACITY
    );
    assert_eq!(value["attempts"][0]["number"], 1);
    assert!(value["attempts"][0]["outcome"]["peak"].is_null());
    let _: MemcordonReport = serde_json::from_value(value).expect("round trip");
}

#[test]
fn schema_five_outside_attempt_deadline_is_terminal_and_round_trips() {
    let outcome = RunOutcome::LimitExceeded {
        limit: ByteSize::from_bytes(1),
        observed: None,
        peak: Some(ByteSize::from_bytes(2)),
        evidence: memcordon_core::LimitEvidence {
            backend: "fixture".to_owned(),
            metric: "native".to_owned(),
            detail: "limit".to_owned(),
        },
        child_after_termination: None,
        cleanup: cleanup(),
    };
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    history
        .append(attempt_record(1, Some(outcome), None), &mut aggregates)
        .expect("append");
    let mut coordinator = coordinator();
    let mut decision = RestartDecisionRecord::default();
    assert!(matches!(
        coordinator
            .on_limit(
                RestartCondition::MemoryLimit,
                Duration::ZERO,
                &safe_proof(),
                &mut decision
            )
            .expect("wait"),
        RestartAction::Wait { .. }
    ));
    let _ = coordinator
        .complete_wait(
            WaitCompletion::SupervisionDeadline,
            Duration::from_millis(500),
            Some(Duration::ZERO),
            &mut decision,
        )
        .expect("deadline");
    let evidence = SupervisionDeadlineEvidence {
        evidence: DeadlineEvidence::new(
            1_500,
            DeadlineScope::Supervision,
            "test-origin".to_owned(),
            1_500,
            1_500,
            0,
            0,
            None,
            None,
        )
        .expect("evidence"),
        terminal_phase: SupervisionPhase::Backoff,
    };
    let execution = SupervisionExecution::new(
        BackendCapabilityReport::default(),
        SupervisionTerminal::DeadlineOutsideAttempt {
            evidence: evidence.clone(),
        },
        history,
        aggregates,
        coordinator.summary().clone(),
        Some(evidence),
        1_500,
        1,
    )
    .expect("execution");
    let value = serde_json::to_value(report_from_execution(execution)).expect("json");
    assert_eq!(
        value["supervision"]["terminal"]["kind"],
        "deadline-outside-attempt"
    );
    assert_eq!(value["supervision"]["wrapper_exit_code"], 123);
    let _: MemcordonReport = serde_json::from_value(value).expect("round trip");
}

#[test]
fn schema_five_later_helper_error_preserves_prior_attempt() {
    let first = RunOutcome::LimitExceeded {
        limit: ByteSize::from_bytes(1),
        observed: None,
        peak: None,
        evidence: memcordon_core::LimitEvidence {
            backend: "fixture".to_owned(),
            metric: "native".to_owned(),
            detail: "limit".to_owned(),
        },
        child_after_termination: None,
        cleanup: cleanup(),
    };
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    history
        .append(attempt_record(1, Some(first), None), &mut aggregates)
        .expect("first");
    let error = SupervisionErrorRecord {
        category: "helper".to_owned(),
        code: "MCHELPER".to_owned(),
        message: "missing helper".to_owned(),
        os_code: None,
        attempt_number: Some(2),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("guardian".to_owned()),
        target_released: false,
        workload_may_be_alive: false,
        initial_spawn_failure: None,
    };
    history
        .append(
            attempt_record(2, None, Some(error.clone())),
            &mut aggregates,
        )
        .expect("second");
    let mut coordinator = coordinator();
    let mut decision = RestartDecisionRecord::default();
    schedule_launch(&mut coordinator, &mut decision);
    let execution = SupervisionExecution::new(
        BackendCapabilityReport::default(),
        SupervisionTerminal::Error {
            attempt_number: Some(2),
            error,
        },
        history,
        aggregates,
        coordinator.summary().clone(),
        None,
        2_000,
        2,
    )
    .expect("execution");
    let value = serde_json::to_value(report_from_execution(execution)).expect("json");
    assert_eq!(value["attempts"].as_array().map(Vec::len), Some(2));
    assert_eq!(value["attempts"][0]["number"], 1);
    assert_eq!(value["attempts"][1]["error"]["code"], "MCHELPER");
    assert_eq!(value["supervision"]["wrapper_exit_code"], 125);
    let _: MemcordonReport = serde_json::from_value(value).expect("round trip");
}

#[test]
fn schema_five_initial_spawn_status_round_trips_typed_provenance() {
    for (failure, status) in [
        (InitialSpawnFailure::NotExecutable, 126),
        (InitialSpawnFailure::NotFound, 127),
    ] {
        let error = SupervisionErrorRecord {
            category: "spawn".to_owned(),
            code: "MCSPAWN-FIXTURE".to_owned(),
            message: "spawn failed".to_owned(),
            os_code: None,
            attempt_number: Some(1),
            supervision_phase: SupervisionPhase::AttemptSetup,
            launch_phase: Some("target-spawn-failed".to_owned()),
            target_released: true,
            workload_may_be_alive: false,
            initial_spawn_failure: Some(failure),
        };
        let mut history = AttemptHistory::default();
        let mut aggregates = SupervisionAggregates::default();
        history
            .append(
                attempt_record(1, None, Some(error.clone())),
                &mut aggregates,
            )
            .expect("append");
        let execution = SupervisionExecution::new(
            BackendCapabilityReport::default(),
            SupervisionTerminal::Error {
                attempt_number: Some(1),
                error,
            },
            history,
            aggregates,
            RestartSummary::default(),
            None,
            4,
            0,
        )
        .expect("typed spawn terminal");
        let value = serde_json::to_value(report_from_execution(execution)).expect("json");
        assert_eq!(value["supervision"]["wrapper_exit_code"], status);
        let _: MemcordonReport = serde_json::from_value(value).expect("round trip");
    }
}

#[test]
fn supervision_constructor_rejects_mismatched_or_misclassified_error_terminal() {
    let mut error = SupervisionErrorRecord {
        category: "spawn".to_owned(),
        code: "MCSPAWN-FIXTURE".to_owned(),
        message: "spawn failed".to_owned(),
        os_code: None,
        attempt_number: Some(1),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("target-spawn-failed".to_owned()),
        target_released: true,
        workload_may_be_alive: false,
        initial_spawn_failure: Some(InitialSpawnFailure::NotFound),
    };
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    history
        .append(
            attempt_record(1, None, Some(error.clone())),
            &mut aggregates,
        )
        .expect("append");
    error.message = "different terminal payload".to_owned();
    assert!(
        SupervisionExecution::new(
            BackendCapabilityReport::default(),
            SupervisionTerminal::Error {
                attempt_number: Some(1),
                error: error.clone(),
            },
            history.clone(),
            aggregates.clone(),
            RestartSummary::default(),
            None,
            4,
            0,
        )
        .is_err()
    );
    error.message = "spawn failed".to_owned();
    error.supervision_phase = SupervisionPhase::Backoff;
    assert!(
        SupervisionExecution::new(
            BackendCapabilityReport::default(),
            SupervisionTerminal::Error {
                attempt_number: Some(1),
                error,
            },
            history,
            aggregates,
            RestartSummary::default(),
            None,
            4,
            0,
        )
        .is_err()
    );
}

#[test]
fn supervision_constructor_rejects_stale_error_terminal() {
    let error = |number| SupervisionErrorRecord {
        category: "setup".to_owned(),
        code: "MCSETUP-FIXTURE".to_owned(),
        message: format!("setup failure {number}"),
        os_code: None,
        attempt_number: Some(number),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("guardian".to_owned()),
        target_released: false,
        workload_may_be_alive: false,
        initial_spawn_failure: None,
    };
    let first = error(1);
    let second = error(2);
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    history
        .append(
            attempt_record(1, None, Some(first.clone())),
            &mut aggregates,
        )
        .expect("first");
    history
        .append(attempt_record(2, None, Some(second)), &mut aggregates)
        .expect("second");
    assert!(
        SupervisionExecution::new(
            BackendCapabilityReport::default(),
            SupervisionTerminal::Error {
                attempt_number: Some(1),
                error: first,
            },
            history,
            aggregates,
            RestartSummary::default(),
            None,
            4,
            0,
        )
        .is_err()
    );
}

#[test]
fn supervision_constructor_rejects_embedded_error_attempt_mismatch() {
    let error = SupervisionErrorRecord {
        category: "setup".to_owned(),
        code: "MCSETUP-FIXTURE".to_owned(),
        message: "setup failure".to_owned(),
        os_code: None,
        attempt_number: Some(2),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("guardian".to_owned()),
        target_released: false,
        workload_may_be_alive: false,
        initial_spawn_failure: None,
    };
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    history
        .append(
            attempt_record(1, None, Some(error.clone())),
            &mut aggregates,
        )
        .expect("history append defers whole-model validation");
    assert!(
        SupervisionExecution::new(
            BackendCapabilityReport::default(),
            SupervisionTerminal::Error {
                attempt_number: Some(1),
                error,
            },
            history,
            aggregates,
            RestartSummary::default(),
            None,
            4,
            0,
        )
        .is_err()
    );
}

#[test]
fn schema_five_truncates_three_hundred_attempts_but_aggregates_all() {
    let value = deadline_report_value(300);
    assert_eq!(value["supervision"]["attempt_history"]["retained"], 256);
    assert_eq!(value["supervision"]["attempt_history"]["omitted"], 44);
    assert_eq!(value["supervision"]["aggregate"]["deadlines"], 300);
    assert_eq!(value["attempts"][0]["number"], 1);
    assert_eq!(value["attempts"][1]["number"], 46);
    assert_eq!(value["attempts"][255]["number"], 300);
    let _: MemcordonReport = serde_json::from_value(value.clone()).expect("round trip");

    let mut oversized = value.clone();
    let repeated = oversized["attempts"][255].clone();
    oversized["attempts"]
        .as_array_mut()
        .expect("attempt array")
        .push(repeated);
    oversized["supervision"]["attempt_history"]["retained"] = serde_json::json!(257);
    oversized["supervision"]["attempt_history"]["total"] = serde_json::json!(301);
    oversized["supervision"]["attempt_history"]["omitted"] = serde_json::json!(44);
    oversized["supervision"]["attempt_records_created"] = serde_json::json!(301);
    assert!(serde_json::from_value::<MemcordonReport>(oversized).is_err());

    let value = deadline_report_value(3);
    let _: MemcordonReport = serde_json::from_value(value.clone()).expect("compact valid report");

    let mut missing_first = value.clone();
    missing_first["attempts"][0]["number"] = serde_json::json!(45);
    assert!(serde_json::from_value::<MemcordonReport>(missing_first).is_err());

    let mut gapped_tail = value.clone();
    gapped_tail["attempts"][1]["number"] = serde_json::json!(999);
    assert!(serde_json::from_value::<MemcordonReport>(gapped_tail).is_err());

    let mut stale_tail = value.clone();
    stale_tail["attempts"][2]["number"] = serde_json::json!(2);
    assert!(serde_json::from_value::<MemcordonReport>(stale_tail).is_err());

    let mut terminal_mismatch = value.clone();
    terminal_mismatch["supervision"]["terminal"]["attempt_number"] = serde_json::json!(2);
    assert!(serde_json::from_value::<MemcordonReport>(terminal_mismatch).is_err());

    let mut aggregate_mismatch = value;
    aggregate_mismatch["supervision"]["aggregate"]["deadlines"] = serde_json::json!(4);
    assert!(serde_json::from_value::<MemcordonReport>(aggregate_mismatch).is_err());

    let valid = serde_json::to_value(report_from_execution({
        let mut history = AttemptHistory::default();
        let mut aggregates = SupervisionAggregates::default();
        let outcome = RunOutcome::Exited {
            child: ChildTermination::ExitCode { code: 0 },
            peak: None,
            cleanup: cleanup(),
        };
        history
            .append(
                attempt_record(1, Some(outcome.clone()), None),
                &mut aggregates,
            )
            .expect("append");
        SupervisionExecution::new(
            BackendCapabilityReport::default(),
            SupervisionTerminal::AttemptOutcome {
                attempt_number: 1,
                outcome,
            },
            history,
            aggregates,
            RestartSummary::default(),
            None,
            4,
            1,
        )
        .expect("execution")
    }))
    .expect("valid report");
    let mutations: [fn(&mut serde_json::Value); 3] = [
        |value: &mut serde_json::Value| {
            value["supervision"]["targets_authorized"] = serde_json::json!(2);
        },
        |value: &mut serde_json::Value| {
            value["supervision"]["phase"] = serde_json::json!("active-attempt");
        },
        |value: &mut serde_json::Value| {
            value["supervision"]["wrapper_exit_code"] = serde_json::json!(125);
        },
    ];
    for mutation in mutations {
        let mut contradictory = valid.clone();
        mutation(&mut contradictory);
        assert!(serde_json::from_value::<MemcordonReport>(contradictory).is_err());
    }
}
