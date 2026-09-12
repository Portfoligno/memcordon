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
    BackoffPolicyReport, BoundaryMechanismEvidence, BudgetKindReport, BudgetTokenReport,
    CircuitBreakerPolicyReport, CircuitState, DeadlinePolicyReport, DeadlineScope,
    DormantRestartCondition, EXECUTION_REPORT_SCHEMA_VERSION, EffectiveMemoryPolicyReport,
    EffectivePolicyReport, EffectiveRestartPolicyReport, ErrorCategory, ExecutionErrorReport,
    InvocationReport, MemcordonReport, NativeArgument, PolicyEnvelopeReport,
    RequestedMemoryPolicyReport, RequestedPolicyReport, RequestedRestartPolicyReport,
    RestartCondition, RestartConditions, RestartLimit, SwapReport, ToolReport, write_report_atomic,
};

#[test]
fn sealed_setup_failure_preserves_the_resolved_provider_mechanism() {
    let evidence = BoundaryMechanismEvidence::SetupFailure {
        provider_mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        requested: memcordon_core::BoundaryRequirement::Sealed,
    };

    let value = serde_json::to_value(&evidence).expect("evidence must serialize");
    assert_eq!(value["mechanism"], "setup-failure");
    assert_eq!(value["provider_mechanism"], "linux-pid-namespace-cgroup-v2");
    assert_eq!(value["requested"], "sealed");
    let decoded: BoundaryMechanismEvidence =
        serde_json::from_value(value).expect("evidence must round trip");
    assert_eq!(decoded, evidence);
}

#[test]
fn sealed_setup_failure_preserves_truthful_incomplete_retirement() {
    let launch = LaunchEvidence {
        mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        target_released: true,
        containment_verified_before_authorization: true,
        guardian_started_before_authorization: true,
        target_spawn_error_reported: false,
        boundary_requested: memcordon_core::BoundaryRequirement::Sealed,
        boundary_effective: memcordon_core::BoundaryClass::Sealed,
        boundary_assignment_verified: true,
        boundary_reconfiguration_denied: true,
        inherited_resources_restricted: true,
        frontend_loss_cleanup_authority_verified: true,
    };
    let incomplete = RestartSafetyProof {
        direct_child_reaped: false,
        workload_empty: Some(false),
        helpers_reaped: false,
        containment_removed: false,
        containment_incapable_of_live_members: false,
        sealed_boundary_retired: false,
        errors: vec!["authenticated residue remains".to_owned()],
    };
    let detail = BoundaryMechanismEvidence::SetupFailure {
        provider_mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        requested: memcordon_core::BoundaryRequirement::Sealed,
    };

    assert!(memcordon_core::boundary_evidence_is_consistent(
        &launch,
        &incomplete,
        &detail
    ));

    let mut false_retirement = incomplete;
    false_retirement.sealed_boundary_retired = true;
    assert!(!memcordon_core::boundary_evidence_is_consistent(
        &launch,
        &false_retirement,
        &detail
    ));
}

#[test]
fn typed_provider_rejection_round_trips_with_cleanup_proof() {
    let rejection = memcordon_core::ProviderRejectionEvidence {
        workload_admission: None,
        provider_failure: None,
        schema_version: 1,
        code: "MCSEALED-TARGET-DESCRIPTORS-READBACK".to_owned(),
        phase: memcordon_core::BoundarySetupPhase::ResourceVerification,
        detail: "permission denied".to_owned(),
        os_code: Some(13),
        loader_qualification: None,
        target_created: true,
        target_released: false,
        cleanup_attempted: true,
        restart_safety: RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        },
        terminal_ack_required: false,
        terminal_receipt: None,
    };
    let error = ExecutionErrorReport {
        native_startup: None,
        policy_enforcement: None,
        category: "setup".to_owned(),
        code: "MCSEALED-PROVIDER-REJECTION".to_owned(),
        message: "provider rejected launch".to_owned(),
        os_code: Some(13),
        attempt_number: Some(1),
        supervision_phase: Some("attempt-setup".to_owned()),
        launch_phase: Some("resource-verification".to_owned()),
        target_released: false,
        workload_may_be_alive: false,
        boundary_setup_failure: None,
        provider_rejection: Some(rejection.clone()),
        provider_failure: None,
    };

    let value = serde_json::to_value(&error).expect("error must serialize");
    assert_eq!(
        value["provider_rejection"]["code"],
        "MCSEALED-TARGET-DESCRIPTORS-READBACK"
    );
    assert_eq!(
        value["provider_rejection"]["restart_safety"]["sealed_boundary_retired"],
        true
    );
    let decoded: ExecutionErrorReport =
        serde_json::from_value(value).expect("error must round trip");
    assert_eq!(decoded.provider_rejection, Some(rejection));
}

fn report() -> MemcordonReport {
    MemcordonReport::schema9(
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
                workload: Default::default(),
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
                workload: memcordon_core::workload_evidence::WorkloadResolutionReportV1::unresolved(None, memcordon_core::workload_evidence::BaselineRestrictionObservationV1::UnmanagedStandardBackend),
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
            native_startup: None,
            policy_enforcement: None,
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
            provider_rejection: None,
            provider_failure: None,
        }),
    )
    .expect("valid report")
}

#[test]
fn execution_report_rejects_corrupt_or_future_provider_diagnostics() {
    let projection = memcordon_core::ProviderFailureDiagnosticV1::from_journal(
        memcordon_core::PublicProviderBindingV1 {
            generation: memcordon_core::BoundedText::new("1.0:test").unwrap(),
            source_commit: memcordon_core::BoundedText::new(
                "0123456789012345678901234567890123456789",
            )
            .unwrap(),
            runtime_manifest_sha256: memcordon_core::DiagnosticSha256::from_bytes([1; 32]),
        },
        &"02".repeat(32),
        &"03".repeat(32),
        &memcordon_core::WindowsCausalDiagnosticsV1::default(),
    )
    .unwrap();
    let mut value = serde_json::to_value(report()).unwrap();
    value["error"]["provider_failure"] = serde_json::to_value(projection).unwrap();
    assert!(serde_json::from_value::<MemcordonReport>(value.clone()).is_ok());
    for (field, invalid) in [
        ("schema_version", serde_json::json!(2)),
        ("diagnostic_sequence", serde_json::json!(20)),
        ("projection_sha256", serde_json::json!("00".repeat(32))),
    ] {
        let mut corrupt = value.clone();
        corrupt["error"]["provider_failure"][field] = invalid;
        assert!(
            serde_json::from_value::<MemcordonReport>(corrupt).is_err(),
            "accepted corrupt diagnostic field {field}"
        );
    }
}

fn native_startup_diagnostic() -> memcordon_core::NativeStartupDiagnosticV1 {
    use memcordon_core::{
        NativeHelperIdentityV1, NativeStartupCleanupErrorV1, NativeStartupCleanupStateV1,
        NativeStartupCleanupV1, NativeStartupDiagnosticV1, NativeStartupOperationV1,
        NativeStartupPhaseV1,
    };

    NativeStartupDiagnosticV1 {
        schema_version: 1,
        requested_helper: NativeArgument::from_os(OsStr::new("./memcordon-guardian")),
        canonical_helper: Some(NativeArgument::from_os(OsStr::new(
            "/opt/memcordon-guardian",
        ))),
        helper_identity: Some(NativeHelperIdentityV1 {
            device: 1,
            inode: 2,
            size_bytes: 4096,
            sha256: None,
        }),
        cwd: Some(NativeArgument::from_os(OsStr::new("/workload"))),
        phase: NativeStartupPhaseV1::TargetExec,
        operation: NativeStartupOperationV1::ConfirmTargetExec,
        native_errno: Some(13),
        guardian_pid: Some(100),
        guardian_ready: true,
        launcher_pid: Some(101),
        release_sent: true,
        exec_confirmed: false,
        cleanup: NativeStartupCleanupV1 {
            state: NativeStartupCleanupStateV1::Incomplete,
            errors: vec![NativeStartupCleanupErrorV1 {
                operation: NativeStartupOperationV1::ReapLauncher,
                native_errno: Some(4),
                detail: "launcher reap interrupted".to_owned(),
            }],
        },
    }
}

#[test]
fn native_startup_error_envelopes_preserve_primary_and_cleanup_causes() {
    let diagnostic = native_startup_diagnostic();
    let mut execution = report();
    let error = execution.error.as_mut().unwrap();
    error.target_released = true;
    error.workload_may_be_alive = true;
    error.os_code = Some(13);
    let primary = (error.code.clone(), error.message.clone(), error.os_code);
    error.native_startup = Some(diagnostic.clone());
    let valid_envelope = serde_json::to_value(&execution).unwrap();
    for (field, invalid) in [
        ("target_released", serde_json::json!(false)),
        ("os_code", serde_json::json!(5)),
    ] {
        let mut corrupt = valid_envelope.clone();
        corrupt["error"][field] = invalid;
        assert!(serde_json::from_value::<MemcordonReport>(corrupt).is_err());
    }
    let mut false_cleanup = valid_envelope.clone();
    false_cleanup["error"]["native_startup"]["cleanup"]["state"] = serde_json::json!("complete");
    assert!(serde_json::from_value::<MemcordonReport>(false_cleanup).is_err());
    let decoded: MemcordonReport =
        serde_json::from_slice(&serde_json::to_vec(&execution).unwrap()).unwrap();
    let error = decoded.error.unwrap();
    assert_eq!((error.code, error.message, error.os_code), primary);
    assert_eq!(error.native_startup, Some(diagnostic.clone()));

    let record = SupervisionErrorRecord {
        native_startup: Some(diagnostic.clone()),
        category: "helper".to_owned(),
        code: "MCHELPER-STARTUP".to_owned(),
        message: "original helper failure".to_owned(),
        os_code: Some(13),
        attempt_number: Some(1),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("native-startup".to_owned()),
        target_released: true,
        workload_may_be_alive: true,
        initial_spawn_failure: None,
        provider_rejection: None,
        backend_selection_drift: None,
    };
    assert!(record.is_consistent());
    let mut false_release = record.clone();
    false_release.target_released = false;
    assert!(!false_release.is_consistent());
    let mut false_cleanup = record.clone();
    false_cleanup.native_startup.as_mut().unwrap().cleanup.state =
        memcordon_core::NativeStartupCleanupStateV1::Complete;
    assert!(!false_cleanup.is_consistent());
    let decoded: SupervisionErrorRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.terminal_status(), 125);
    assert_eq!(
        decoded.native_startup.unwrap().cleanup.errors[0].native_errno,
        Some(4)
    );
}

#[test]
fn absent_native_startup_keeps_existing_error_wire_shape() {
    let execution = report();
    let before = serde_json::to_vec(&execution).unwrap();
    assert!(
        serde_json::to_value(&execution).unwrap()["error"]
            .get("native_startup")
            .is_none()
    );
    let decoded: MemcordonReport = serde_json::from_slice(&before).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), before);
    assert!(
        memcordon_core::Error::new(memcordon_core::ErrorCategory::Setup, "MCHELPER", "original")
            .native_startup
            .is_none()
    );

    let legacy = serde_json::json!({
        "category":"helper", "code":"MCHELPER", "message":"original", "os_code":null,
        "attempt_number":1, "supervision_phase":"attempt-setup", "launch_phase":null,
        "target_released":false, "workload_may_be_alive":false,
        "initial_spawn_failure":null, "provider_rejection":null
    });
    let decoded: SupervisionErrorRecord = serde_json::from_value(legacy.clone()).unwrap();
    assert!(decoded.native_startup.is_none());
    assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
}

#[test]
fn native_startup_rejects_unknown_or_contradictory_observations() {
    let valid = serde_json::to_value(native_startup_diagnostic()).unwrap();
    assert!(
        serde_json::from_value::<memcordon_core::NativeStartupDiagnosticV1>(valid.clone()).is_ok()
    );
    for (field, invalid) in [
        ("schema_version", serde_json::json!(2)),
        ("phase", serde_json::json!("invented-phase")),
        ("operation", serde_json::json!("invented-operation")),
        ("native_errno", serde_json::json!(0)),
        ("guardian_pid", serde_json::json!(0)),
        ("guardian_ready", serde_json::json!(false)),
        ("launcher_pid", serde_json::Value::Null),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut corrupt = valid.clone();
        corrupt[field] = invalid;
        assert!(
            serde_json::from_value::<memcordon_core::NativeStartupDiagnosticV1>(corrupt).is_err(),
            "accepted {field}"
        );
    }
    let mut impossible_exec = valid.clone();
    impossible_exec["exec_confirmed"] = serde_json::json!(true);
    impossible_exec["release_sent"] = serde_json::json!(false);
    assert!(
        serde_json::from_value::<memcordon_core::NativeStartupDiagnosticV1>(
            impossible_exec.clone()
        )
        .is_err()
    );
    let mut execution = serde_json::to_value(report()).unwrap();
    execution["error"]["native_startup"] = impossible_exec;
    assert!(serde_json::from_value::<MemcordonReport>(execution).is_err());
    for path in ["requested_helper", "helper_identity", "cleanup"] {
        let mut corrupt = valid.clone();
        corrupt[path]["unexpected"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<memcordon_core::NativeStartupDiagnosticV1>(corrupt).is_err()
        );
    }
}

#[test]
fn native_startup_preserves_native_path_bytes_and_rejects_false_display() {
    // Deliberately non-text native paths, interpreted independently of the host OS.
    for (encoding, data) in [
        ("unix-bytes-base64", "/w=="),
        ("windows-u16le-base64", "ANg="),
    ] {
        let mut diagnostic = native_startup_diagnostic();
        diagnostic.requested_helper = NativeArgument {
            display: "\u{fffd}".to_owned(),
            raw: Some(memcordon_core::NativeArgumentRaw {
                encoding: encoding.to_owned(),
                data: data.to_owned(),
            }),
        };
        let bytes = serde_json::to_vec(&diagnostic).unwrap();
        assert_eq!(
            serde_json::from_slice::<memcordon_core::NativeStartupDiagnosticV1>(&bytes).unwrap(),
            diagnostic
        );
        diagnostic.requested_helper.display = "not-the-native-path".to_owned();
        assert!(
            serde_json::from_slice::<memcordon_core::NativeStartupDiagnosticV1>(
                &serde_json::to_vec(&diagnostic).unwrap()
            )
            .is_err()
        );
    }
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

fn strict_retired_sealed_report() -> MemcordonReport {
    use memcordon_core::workload_contract::*;
    use memcordon_core::workload_evidence::*;
    use memcordon_core::workload_registry::*;
    use memcordon_core::{
        BoundaryCapability, BoundaryClass, BoundaryRequirement, BoundedText, BoundedVec,
        DiagnosticSha256, LinuxSealedEvidenceV2, PublicProviderBindingV1,
    };
    use std::num::NonZeroU64;

    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let profile = BaselineProfile::LinuxUnixCreate;
    let request = WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest: digest.clone(),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: LogicalId::new("reviewed-plan".into()).unwrap(),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest.clone(),
        },
        ceiling: profile.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
    };
    let snapshot = ProviderAdmissionSnapshotV1 {
        request_digest: memcordon_core::workload_codec::contract_digest(&request).unwrap(),
        request: request.clone(),
        registry_digest: digest.clone(),
        qualification_digest: digest.clone(),
        admission_nonce: Nonce128([4; 16]),
        caller_invocation_reference: Nonce128([5; 16]),
        private_invocation_digest: digest.clone(),
        caller: CallerSelector::Linux { uid: 1000 },
        native_profile: profile,
    };
    let binding = AttemptBindingV1::from_snapshot(
        &snapshot,
        PublicProviderBindingV1 {
            generation: BoundedText::new("test-provider").unwrap(),
            source_commit: BoundedText::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            runtime_manifest_sha256: digest,
        },
        BoundedText::new("boot-a").unwrap(),
        BoundedText::new("attempt-a").unwrap(),
        0,
    )
    .unwrap();
    let checkpoint = VerifiedCheckpointV1::observed(
        &binding,
        baseline_observation(profile),
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    let enforcement = AttemptPolicyEnforcementV1::retired(binding, checkpoint, true, true).unwrap();
    assert!(enforcement.valid_native_terminal(Some(&request), profile, "attempt-a", 0, "boot-a"));

    let outcome = RunOutcome::Exited {
        child: ChildTermination::ExitCode { code: 0 },
        peak: None,
        cleanup: cleanup(),
    };
    let mut attempt = attempt_record(1, Some(outcome.clone()), None);
    attempt.policy_enforcement = enforcement.clone();
    attempt.launch = LaunchEvidence {
        mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        boundary_requested: BoundaryRequirement::Sealed,
        boundary_effective: BoundaryClass::Sealed,
        target_released: true,
        containment_verified_before_authorization: true,
        guardian_started_before_authorization: true,
        target_spawn_error_reported: true,
        boundary_assignment_verified: true,
        boundary_reconfiguration_denied: true,
        inherited_resources_restricted: true,
        frontend_loss_cleanup_authority_verified: true,
    };
    attempt.restart_safety.sealed_boundary_retired = true;
    attempt.boundary_detail =
        BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2(LinuxSealedEvidenceV2 {
            schema_version: 2,
            provider_identity: "memcordon-sealed-agent-v2".to_owned(),
            control_service_identity: "memcordon-sealed-agent.service:v2".to_owned(),
            launcher_service_identity: "memcordon-sealed-launcher.service:v2".to_owned(),
            cgroup_identity_digest: "ab".repeat(32),
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
            target_initial_credentials_verified: true,
            initial_provider_capabilities_absent: true,
            caller_no_new_privs_reproduced: true,
            caller_capability_bounding_set_reproduced: true,
            caller_mount_context_reproduced: true,
            credential_transition_disposition:
                memcordon_core::CredentialTransitionDisposition::PreserveCallerEnvelope,
            boundary_independent_of_credentials: true,
            inherited_descriptors_verified: true,
            writable_ancestor_cgroup_denied: true,
            parent_namespace_handles_denied: true,
            recursive_provider_request_denied: true,
            guardian_ready: true,
            target_released: true,
            cgroup_kill_invoked: true,
            cgroup_empty_verified: true,
            namespace_init_reaped: true,
            guardian_reaped: true,
            cgroup_removed: true,
        });
    assert!(memcordon_core::boundary_evidence_is_consistent(
        &attempt.launch,
        &attempt.restart_safety,
        &attempt.boundary_detail
    ));
    let backend = BackendCapabilityReport {
        boundary: BoundaryCapability {
            class: BoundaryClass::Sealed,
            mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
            target_gated: true,
            boundary_verified_before_authorization: true,
            target_can_reconfigure_boundary: false,
            frontend_loss_cleanup_authority: true,
            workload_empty_proof: true,
            limitations: Vec::new(),
        },
        ..BackendCapabilityReport::default()
    };
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    history.append(attempt, &mut aggregates).unwrap();
    let execution = SupervisionExecution::new(
        backend.clone(),
        SupervisionTerminal::AttemptOutcome {
            attempt_number: 1,
            outcome,
        },
        history,
        aggregates,
        RestartSummary::default(),
        None,
        10,
        1,
    )
    .unwrap();
    let mut base = report();
    base.policy.requested.boundary = BoundaryRequirement::Sealed;
    base.policy.requested.workload = WorkloadRequestReport::StrictV1 {
        contract: Box::new(request),
    };
    base.policy.effective.boundary = BoundaryClass::Sealed;
    base.policy.effective.workload = enforcement.resolution().unwrap();
    MemcordonReport::schema9(
        base.tool,
        base.invocation,
        base.policy,
        Some(backend),
        Some(execution),
        None,
    )
    .unwrap()
}

#[test]
fn retired_strict_policy_cannot_replace_native_retirement() {
    let report = strict_retired_sealed_report();
    let valid = serde_json::to_value(&report).unwrap();
    assert!(serde_json::from_value::<MemcordonReport>(valid).is_ok());
    let mut invalid = report;
    let BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2(native) =
        &mut invalid.attempts[0].boundary_detail
    else {
        panic!("Linux fixture");
    };
    native.cgroup_empty_verified = false;
    assert!(invalid.attempts[0].policy_enforcement.is_consistent());
    assert!(
        serde_json::from_value::<MemcordonReport>(serde_json::to_value(invalid).unwrap()).is_err()
    );
}

#[test]
fn native_retirement_cannot_replace_strict_policy_terminal() {
    use memcordon_core::workload_evidence::{
        AdmissionAvailabilityFailure, AttemptPolicyEnforcementV1, PolicyTerminalEvidenceV1,
    };
    let report = strict_retired_sealed_report();
    assert_eq!(report.supervision.as_ref().unwrap().wrapper_exit_code, 0);
    for variant in ["missing", "invalid", "unavailable"] {
        let mut invalid = report.clone();
        let attempt = &mut invalid.attempts[0];
        assert!(memcordon_core::boundary_evidence_is_consistent(
            &attempt.launch,
            &attempt.restart_safety,
            &attempt.boundary_detail
        ));
        if variant == "missing" {
            attempt.policy_enforcement = AttemptPolicyEnforcementV1::LegacyUnspecified;
        } else {
            let AttemptPolicyEnforcementV1::Authorized { terminal, .. } =
                &mut attempt.policy_enforcement
            else {
                panic!("strict fixture");
            };
            if variant == "unavailable" {
                *terminal = PolicyTerminalEvidenceV1::Unavailable {
                    reason: AdmissionAvailabilityFailure::TerminalUnavailable,
                };
            } else {
                let PolicyTerminalEvidenceV1::Retired {
                    provider_resources_closed,
                    ..
                } = terminal
                else {
                    panic!("retired fixture");
                };
                *provider_resources_closed = false;
            }
        }
        assert!(
            serde_json::from_value::<MemcordonReport>(serde_json::to_value(invalid).unwrap())
                .is_err(),
            "accepted {variant} strict policy terminal"
        );
    }
}

#[test]
fn failed_strict_attempt_can_report_unavailable_policy_terminal_without_restart() {
    use memcordon_core::workload_evidence::{
        AdmissionAvailabilityFailure, AttemptPolicyEnforcementV1, PolicyTerminalEvidenceV1,
    };
    for (outcome, status) in [
        (
            RunOutcome::MonitorFailed {
                error: "policy retirement observation unavailable".to_owned(),
                child_after_termination: Some(ChildTermination::ExitCode { code: 0 }),
                cleanup: cleanup(),
            },
            125,
        ),
        (
            RunOutcome::Interrupted {
                signal: memcordon_core::Interruption { signal: 2 },
                child_after_termination: Some(ChildTermination::UnixSignal { signal: 2 }),
                cleanup: cleanup(),
            },
            130,
        ),
        (
            RunOutcome::Exited {
                child: ChildTermination::ExitCode { code: 17 },
                peak: None,
                cleanup: cleanup(),
            },
            17,
        ),
    ] {
        let mut base = strict_retired_sealed_report();
        let mut attempt = base.attempts.remove(0);
        let retired_enforcement = serde_json::to_value(&attempt.policy_enforcement).unwrap();
        let AttemptPolicyEnforcementV1::Authorized { terminal, .. } =
            &mut attempt.policy_enforcement
        else {
            panic!("strict fixture");
        };
        *terminal = PolicyTerminalEvidenceV1::Unavailable {
            reason: AdmissionAvailabilityFailure::TerminalUnavailable,
        };
        attempt.outcome = Some(outcome.clone());
        let original_outcome = outcome.clone();
        let mut history = AttemptHistory::default();
        let mut aggregates = SupervisionAggregates::default();
        history.append(attempt, &mut aggregates).unwrap();
        let backend = base.backend.clone().unwrap();
        let execution = SupervisionExecution::new(
            backend.clone(),
            SupervisionTerminal::AttemptOutcome {
                attempt_number: 1,
                outcome,
            },
            history,
            aggregates,
            RestartSummary::default(),
            None,
            10,
            1,
        )
        .unwrap();
        let failed = MemcordonReport::schema9(
            base.tool,
            base.invocation,
            base.policy,
            Some(backend),
            Some(execution),
            None,
        )
        .unwrap();
        assert_eq!(
            failed.supervision.as_ref().unwrap().wrapper_exit_code,
            status
        );
        assert_eq!(failed.attempts[0].outcome.as_ref(), Some(&original_outcome));
        let value = serde_json::to_value(failed).unwrap();
        assert!(serde_json::from_value::<MemcordonReport>(value.clone()).is_ok());

        for decision in [
            "half-life-logistic-backoff",
            "circuit-cooldown",
            "half-open-launch",
        ] {
            let mut restart_without_retirement = value.clone();
            restart_without_retirement["attempts"][0]["restart_decision"]["decision"] =
                serde_json::json!(decision);
            let mut with_retirement = restart_without_retirement.clone();
            with_retirement["attempts"][0]["policy_enforcement"] = retired_enforcement.clone();
            assert!(serde_json::from_value::<MemcordonReport>(with_retirement).is_ok());
            assert!(
                serde_json::from_value::<MemcordonReport>(restart_without_retirement).is_err(),
                "accepted restart {decision} without strict retirement"
            );
        }
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
        policy_enforcement: Default::default(),
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
    MemcordonReport::schema9(
        base.tool,
        base.invocation,
        base.policy,
        Some(BackendCapabilityReport::default()),
        Some(execution),
        None,
    )
    .expect("schema9")
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
        native_startup: None,
        code: "MCHELPER".to_owned(),
        message: "missing helper".to_owned(),
        os_code: None,
        attempt_number: Some(2),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("guardian".to_owned()),
        target_released: false,
        workload_may_be_alive: false,
        initial_spawn_failure: None,
        provider_rejection: None,
        backend_selection_drift: None,
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
            error: Box::new(error),
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
            native_startup: None,
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
            provider_rejection: None,
            backend_selection_drift: None,
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
                error: Box::new(error),
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
fn sealed_exec_failure_round_trips_authenticated_provider_provenance() {
    let restart_safety = RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: true,
        errors: Vec::new(),
    };
    let provider_rejection = memcordon_core::ProviderRejectionEvidence {
        workload_admission: None,
        provider_failure: None,
        schema_version: 1,
        code: "MCSPAWN-NOT-FOUND".to_owned(),
        phase: memcordon_core::BoundarySetupPhase::TargetCreation,
        detail: "authenticated target exec failed with ENOENT".to_owned(),
        os_code: Some(2),
        loader_qualification: None,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety,
        terminal_ack_required: false,
        terminal_receipt: None,
    };
    let error = SupervisionErrorRecord {
        category: "spawn".to_owned(),
        native_startup: None,
        code: "MCSPAWN-NOT-FOUND".to_owned(),
        message: "sealed target exec failed".to_owned(),
        os_code: Some(2),
        attempt_number: Some(1),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("target-spawn-failed".to_owned()),
        target_released: true,
        workload_may_be_alive: false,
        initial_spawn_failure: Some(InitialSpawnFailure::NotFound),
        provider_rejection: Some(provider_rejection),
        backend_selection_drift: None,
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
            error: Box::new(error),
        },
        history,
        aggregates,
        RestartSummary::default(),
        None,
        4,
        0,
    )
    .expect("authenticated sealed spawn provenance must remain reportable");
    let value = serde_json::to_value(report_from_execution(execution)).expect("json");
    assert_eq!(value["supervision"]["wrapper_exit_code"], 127);
    assert_eq!(
        value["attempts"][0]["error"]["provider_rejection"]["code"],
        "MCSPAWN-NOT-FOUND"
    );
    let _: MemcordonReport = serde_json::from_value(value).expect("round trip");
}

#[test]
fn request_validation_provider_rejection_round_trips_in_schema_eight() {
    let provider_rejection = memcordon_core::ProviderRejectionEvidence {
        workload_admission: None,
        provider_failure: None,
        schema_version: 1,
        code: "MCSEALED-PACKAGE-LEASE".to_owned(),
        phase: memcordon_core::BoundarySetupPhase::RequestValidation,
        detail: "stable package lease is unavailable".to_owned(),
        os_code: Some(30),
        loader_qualification: None,
        target_created: false,
        target_released: false,
        cleanup_attempted: false,
        restart_safety: RestartSafetyProof::default(),
        terminal_ack_required: false,
        terminal_receipt: None,
    };
    let error = SupervisionErrorRecord {
        category: "setup".to_owned(),
        code: "MCSEALED-PROVIDER-REJECTION".to_owned(),
        native_startup: None,
        message: "provider rejected launch".to_owned(),
        os_code: Some(30),
        attempt_number: Some(1),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("request-validation".to_owned()),
        target_released: false,
        workload_may_be_alive: false,
        initial_spawn_failure: None,
        provider_rejection: Some(provider_rejection),
        backend_selection_drift: None,
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
            error: Box::new(error),
        },
        history,
        aggregates,
        RestartSummary::default(),
        None,
        4,
        0,
    )
    .expect("pre-target provider rejection must remain reportable");
    let value = serde_json::to_value(report_from_execution(execution)).expect("json");
    assert_eq!(value["schema_version"], EXECUTION_REPORT_SCHEMA_VERSION);
    assert_eq!(
        value["attempts"][0]["error"]["provider_rejection"]["code"],
        "MCSEALED-PACKAGE-LEASE"
    );
    assert_eq!(
        value["attempts"][0]["error"]["provider_rejection"]["phase"],
        "request-validation"
    );
    assert_eq!(
        value["attempts"][0]["error"]["provider_rejection"]["detail"],
        "stable package lease is unavailable"
    );
    assert_eq!(
        value["attempts"][0]["error"]["launch_phase"],
        "request-validation"
    );
    assert_eq!(
        value["attempts"][0]["error"]["provider_rejection"]["target_created"],
        false
    );
    assert_eq!(
        value["attempts"][0]["error"]["provider_rejection"]["cleanup_attempted"],
        false
    );
    assert_eq!(
        value["attempts"][0]["error"]["provider_rejection"]["restart_safety"],
        serde_json::json!({
            "direct_child_reaped": false,
            "workload_empty": null,
            "helpers_reaped": false,
            "containment_removed": false,
            "containment_incapable_of_live_members": false,
            "sealed_boundary_retired": false,
            "errors": [],
        })
    );
    assert_eq!(
        value["attempts"][0]["error"]["workload_may_be_alive"],
        false
    );
    let decoded: MemcordonReport =
        serde_json::from_value(value.clone()).expect("request-validation round trip");
    assert_eq!(serde_json::to_value(decoded).expect("json"), value);

    let mut unknown = value;
    unknown["attempts"][0]["error"]["provider_rejection"]["phase"] =
        serde_json::json!("future-request-validation");
    assert!(serde_json::from_value::<MemcordonReport>(unknown).is_err());
}

#[test]
fn supervision_constructor_rejects_mismatched_or_misclassified_error_terminal() {
    let mut error = SupervisionErrorRecord {
        native_startup: None,
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
        provider_rejection: None,
        backend_selection_drift: None,
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
                error: Box::new(error.clone()),
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
                error: Box::new(error),
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
        native_startup: None,
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
        provider_rejection: None,
        backend_selection_drift: None,
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
                error: Box::new(first),
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
        native_startup: None,
        message: "setup failure".to_owned(),
        os_code: None,
        attempt_number: Some(2),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("guardian".to_owned()),
        target_released: false,
        workload_may_be_alive: false,
        initial_spawn_failure: None,
        provider_rejection: None,
        backend_selection_drift: None,
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
                error: Box::new(error),
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
