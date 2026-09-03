use windows_sys::Win32::Security::{DISABLE_MAX_PRIVILEGE, WRITE_RESTRICTED};
use windows_sys::Win32::System::SystemServices::{SE_GROUP_ENABLED, SE_GROUP_LOGON_ID};

use crate::windows::{
    access_trace::{
        MAX_FRONTIER_EVENTS_FOR_TEST, MAX_TRACE_EVENTS_FOR_TEST, PassiveAccessLocalizationCellV1,
        PassiveAccessLocalizationEventForTest, passive_access_consumer_open_failure_for_test,
        passive_access_localization_drain_barrier_for_test, passive_access_localization_for_test,
        passive_access_runtime_cleanup_for_test, passive_access_session_start_unavailable_for_test,
        passive_access_setup_cleanup_failure_for_test, passive_create_initiator_for_test,
        passive_file_object_name_digest_for_test,
    },
    process::{
        LoaderLaunchFailureBoundaryForTest, LoaderObjectSecurityOutcomeForTest,
        TraceSessionCapabilityTriggerMutationForTest, classify_loader_full_observer_for_test,
        classify_loader_restriction_authenticated_users_for_test,
        classify_loader_restriction_identity_for_test, classify_loader_restriction_logon_for_test,
        classify_loader_restriction_presence_for_test,
        classify_loader_restriction_target_user_for_test,
        loader_control_cell_job_empty_attested_for_test, loader_failure_phase_for_test,
        loader_full_observer_candidate_tail_digest_for_test,
        loader_full_observer_debug_f_gate_for_test,
        loader_full_observer_failed_invariants_for_test,
        loader_full_observer_fallback_gate_for_test, loader_full_observer_invariants_for_test,
        loader_full_observer_trace_admission_for_test,
        loader_full_observer_trace_admitted_for_test, loader_restriction_canary_required_for_test,
        loader_restriction_original_sext_reproduction_for_test,
        loader_restriction_presence_gate_for_test, loader_shared_environment_octet_valid_for_test,
        loader_shared_environment_pair_valid_for_test,
        loader_shared_environment_quad_valid_for_test,
        loader_shared_environment_quint_valid_for_test,
        loader_shared_environment_sext_valid_for_test,
        loader_shared_environment_triplet_valid_for_test,
        loader_trace_session_capability_gate_for_test,
        loader_trace_session_capability_trigger_binding_for_test,
        render_loader_full_observer_canary_for_test,
        render_loader_restriction_authenticated_users_canary_for_test,
        render_loader_restriction_canary_for_test, render_loader_restriction_logon_canary_for_test,
        render_loader_restriction_presence_canary_for_test,
        render_loader_restriction_target_user_canary_for_test,
        render_loader_shared_environment_observation_for_test,
    },
    session_broker::{
        TraceSessionCapabilityReceiptMutationForTest,
        trace_session_capability_dual_failure_diagnostic_for_test,
        trace_session_capability_receipt_for_test,
        trace_session_capability_schema_versions_for_test, trace_session_capability_state_for_test,
    },
    token::{
        canonical_same_access_restricting_sids_for_test,
        loader_restriction_pair_construction_for_test,
        loader_restriction_raw_sid_predicate_for_test,
        validate_authenticated_users_matches_for_test,
        validate_loader_restriction_pair_invariants_for_test,
        validate_logon_sid_group_inventory_for_test, validate_target_user_matches_for_test,
        validate_token_logon_sid_attributes_for_test,
    },
};

const RESTRICTED_CODE_SID: &str = "S-1-5-12";
const PRIMARY_FAILURE: &str = "authoritative full-restricted failure";
const TRACE_HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRACE_HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn admitted_full_observer_trace(module_path_hashes: &[&str]) -> String {
    let candidate_modules = module_path_hashes
        .iter()
        .enumerate()
        .map(|(index, path_sha256)| {
            let ordinal = index + 1;
            let base = ordinal * 0x1000;
            format!("{ordinal}@0x{base:x}:module-{index}.dll:file-handle:{path_sha256}:ok:file-ok")
        })
        .collect::<Vec<_>>()
        .join(",");
    let candidate_modules_sha256 =
        loader_full_observer_candidate_tail_digest_for_test(&candidate_modules);
    let module_count = module_path_hashes.len();
    let event_count = module_count + 1;
    format!(
        "loader_trace=v4 gate=ephemeral-ci trace_sha256={TRACE_HASH_A} drained=true debug_cleanup=exit-process-event-continued events={event_count} accounted_events={event_count} debug_strings=0 debug_string_bytes=0 debug_string_overflow=0 create_event=true exit_event=true candidate_modules_count={module_count} candidate_modules_retained={module_count} candidate_modules_overflow=0 candidate_modules_sha256={candidate_modules_sha256} candidate_modules=[{candidate_modules}] unload_tail_count=0 unload_tail_retained=0 unload_tail_overflow=0 unload_tail_sha256={EMPTY_SHA256} unload_tail=[] loader_snap_tail_count=0 loader_snap_tail_retained=0 loader_snap_tail_overflow=0 loader_snap_tail_sha256={EMPTY_SHA256} loader_snap_tail=[] unknown_event_tail_count=0 unknown_event_tail_retained=0 unknown_event_tail_overflow=0 unknown_event_tail_sha256={EMPTY_SHA256} unknown_event_tail=[] exception_tail_count=0 exception_tail_retained=0 exception_tail_overflow=0 exception_tail_sha256={EMPTY_SHA256} exception_tail=[] command_semantics_sha256={TRACE_HASH_A} command_dynamic_fields=authenticated-private-pipe,authenticated-nonce"
    )
}

fn candidate_modules_from_trace(trace: &str) -> &str {
    trace
        .split_ascii_whitespace()
        .find_map(|field| {
            field
                .strip_prefix("candidate_modules=[")
                .and_then(|value| value.strip_suffix(']'))
        })
        .expect("test trace has one candidate-module tail")
}

fn trace_with_candidate_modules(trace: &str, candidate_modules: &str) -> String {
    let previous_modules = candidate_modules_from_trace(trace);
    let previous_digest = loader_full_observer_candidate_tail_digest_for_test(previous_modules);
    let replacement_digest = loader_full_observer_candidate_tail_digest_for_test(candidate_modules);
    trace
        .replace(
            &format!("candidate_modules_sha256={previous_digest}"),
            &format!("candidate_modules_sha256={replacement_digest}"),
        )
        .replace(
            &format!("candidate_modules=[{previous_modules}]"),
            &format!("candidate_modules=[{candidate_modules}]"),
        )
}

#[test]
fn loader_peer_exit_phase_is_typed_and_never_selected_from_prose() {
    for detail in [
        "failure_phase=pre-create",
        "post-loader-ready-containment",
        "untrusted detail with post-resume-pre-loader-ready words",
    ] {
        assert_eq!(
            loader_failure_phase_for_test(
                LoaderLaunchFailureBoundaryForTest::PostResumePreLoaderReady,
                detail,
            ),
            "post-resume-pre-loader-ready",
        );
        assert_eq!(
            loader_failure_phase_for_test(LoaderLaunchFailureBoundaryForTest::Unknown, detail),
            "unclassified",
        );
    }
    assert_eq!(
        loader_failure_phase_for_test(
            LoaderLaunchFailureBoundaryForTest::PreCreate,
            "post-resume-pre-loader-ready",
        ),
        "pre-create",
    );
    assert_eq!(
        loader_failure_phase_for_test(
            LoaderLaunchFailureBoundaryForTest::PostLoaderReadyContainment,
            "pre-create",
        ),
        "post-loader-ready-containment",
    );
    assert_eq!(
        loader_failure_phase_for_test(LoaderLaunchFailureBoundaryForTest::ExitDrain, "pre-create",),
        "exit-drain",
    );
}

#[test]
fn passive_file_localization_requires_joined_scoped_events_and_exact_reproduction() {
    const CANONICAL_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TARGET_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let events = [
        PassiveAccessLocalizationEventForTest::Create {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            process_matches: true,
            initiator_matches: true,
            schema_matches: true,
            irp: 1,
            name_sha256: CANONICAL_HASH,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::OperationEnd {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            header_process_matches: true,
            schema_matches: true,
            irp: 1,
            native_status: 0,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::Create {
            cell: PassiveAccessLocalizationCellV1::TargetUser,
            process_matches: true,
            initiator_matches: true,
            schema_matches: true,
            irp: 2,
            name_sha256: CANONICAL_HASH,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::OperationEnd {
            cell: PassiveAccessLocalizationCellV1::TargetUser,
            header_process_matches: false,
            schema_matches: true,
            irp: 2,
            native_status: 0xc000_0022_u32 as i32,
            event_version: 0,
        },
    ];
    let evidence = passive_access_localization_for_test(&events, true, 1);
    assert_eq!(
        evidence.classification,
        "candidate-file-denial-differential"
    );
    assert!(evidence.admissible());
    let diagnostic = evidence.diagnostic();
    assert!(diagnostic.contains("coverage=kernel-file-create-operation-end/no-requested-access"));
    assert!(diagnostic.contains("requested_access_available=false"));
    assert!(diagnostic.contains("scope=child-pid-plus-creation-identity"));
    assert!(diagnostic.contains("cleanup_count=1"));
    assert!(diagnostic.contains("object_values_redacted=true"));
    assert!(diagnostic.contains(CANONICAL_HASH));
    assert!(!diagnostic.contains("DesiredAccess"));
    assert!(!diagnostic.contains("CreateOptions"));
    assert!(!diagnostic.contains("raw-object-name"));

    let common_events = [
        PassiveAccessLocalizationEventForTest::Create {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            process_matches: true,
            initiator_matches: true,
            schema_matches: true,
            irp: 10,
            name_sha256: CANONICAL_HASH,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::OperationEnd {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            header_process_matches: true,
            schema_matches: true,
            irp: 10,
            native_status: 0,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::Create {
            cell: PassiveAccessLocalizationCellV1::TargetUser,
            process_matches: true,
            initiator_matches: true,
            schema_matches: true,
            irp: 11,
            name_sha256: CANONICAL_HASH,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::OperationEnd {
            cell: PassiveAccessLocalizationCellV1::TargetUser,
            header_process_matches: false,
            schema_matches: true,
            irp: 11,
            native_status: 0,
            event_version: 0,
        },
    ];
    assert_eq!(
        passive_access_localization_for_test(&common_events, true, 1).classification,
        "file-domain-common",
    );

    let mut unmatched_events = events;
    unmatched_events[2] = PassiveAccessLocalizationEventForTest::Create {
        cell: PassiveAccessLocalizationCellV1::TargetUser,
        process_matches: true,
        initiator_matches: true,
        schema_matches: true,
        irp: 2,
        name_sha256: TARGET_HASH,
        event_version: 0,
    };
    assert_eq!(
        passive_access_localization_for_test(&unmatched_events, true, 1).classification,
        "coverage-insufficient",
    );

    let mut mismatched_schema_events = events;
    mismatched_schema_events[2] = PassiveAccessLocalizationEventForTest::Create {
        cell: PassiveAccessLocalizationCellV1::TargetUser,
        process_matches: true,
        initiator_matches: true,
        schema_matches: true,
        irp: 2,
        name_sha256: CANONICAL_HASH,
        event_version: 1,
    };
    assert_eq!(
        passive_access_localization_for_test(&mismatched_schema_events, true, 1).classification,
        "coverage-insufficient",
    );

    for (reproduction_valid, cleanup_count) in [(false, 1), (true, 0), (true, 2)] {
        let rejected =
            passive_access_localization_for_test(&events, reproduction_valid, cleanup_count);
        assert_eq!(rejected.classification, "invalid");
        assert!(!rejected.admissible());
        let rejected_diagnostic = rejected.diagnostic();
        assert!(!rejected_diagnostic.contains(CANONICAL_HASH));
        assert!(!rejected_diagnostic.contains(TARGET_HASH));
    }
}

#[test]
fn passive_file_localization_fails_closed_on_schema_loss_overflow_and_partial_joins() {
    const HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let create = PassiveAccessLocalizationEventForTest::Create {
        cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
        process_matches: true,
        initiator_matches: true,
        schema_matches: true,
        irp: 7,
        name_sha256: HASH,
        event_version: 0,
    };
    assert_eq!(
        passive_access_localization_for_test(
            &[PassiveAccessLocalizationEventForTest::Create {
                cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
                process_matches: true,
                initiator_matches: true,
                schema_matches: false,
                irp: 7,
                name_sha256: HASH,
                event_version: 0,
            }],
            true,
            1,
        )
        .classification,
        "unsupported-provider-schema",
    );
    for events in [
        vec![create],
        vec![PassiveAccessLocalizationEventForTest::Loss],
        vec![PassiveAccessLocalizationEventForTest::Overflow],
        vec![PassiveAccessLocalizationEventForTest::SubjectTimeout],
        vec![PassiveAccessLocalizationEventForTest::SessionTimeout],
        vec![PassiveAccessLocalizationEventForTest::Create {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            process_matches: true,
            initiator_matches: false,
            schema_matches: true,
            irp: 7,
            name_sha256: HASH,
            event_version: 0,
        }],
    ] {
        assert_eq!(
            passive_access_localization_for_test(&events, true, 1).classification,
            "invalid",
        );
    }

    let ignored = passive_access_localization_for_test(
        &[
            PassiveAccessLocalizationEventForTest::Create {
                cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
                process_matches: false,
                initiator_matches: true,
                schema_matches: true,
                irp: 7,
                name_sha256: HASH,
                event_version: 0,
            },
            PassiveAccessLocalizationEventForTest::OperationEnd {
                cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
                header_process_matches: false,
                schema_matches: true,
                irp: 7,
                native_status: 0,
                event_version: 0,
            },
        ],
        true,
        1,
    );
    assert_eq!(ignored.classification, "coverage-insufficient");
    assert!(ignored.admissible());
}

#[test]
fn passive_file_localization_bounds_drain_and_manifest_schema_fail_closed() {
    const HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let mut frontier_bound = Vec::new();
    for index in 0..=MAX_FRONTIER_EVENTS_FOR_TEST {
        let irp = u64::try_from(index).expect("frontier test ordinal fits u64");
        frontier_bound.push(PassiveAccessLocalizationEventForTest::Create {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            process_matches: true,
            initiator_matches: true,
            schema_matches: true,
            irp,
            name_sha256: HASH,
            event_version: 0,
        });
        frontier_bound.push(PassiveAccessLocalizationEventForTest::OperationEnd {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            header_process_matches: false,
            schema_matches: true,
            irp,
            native_status: 0,
            event_version: 0,
        });
    }
    let bounded = passive_access_localization_for_test(&frontier_bound, true, 1);
    assert_eq!(bounded.classification, "invalid");
    assert!(!bounded.admissible());
    let bounded_diagnostic = bounded.diagnostic();
    assert!(bounded_diagnostic.contains("overflow=true"));
    assert!(bounded_diagnostic.contains("incomplete=true"));
    assert!(bounded_diagnostic.contains("frontier=[]"));
    assert!(!bounded_diagnostic.contains(HASH));

    assert_eq!(
        passive_access_localization_drain_barrier_for_test(1, 2, false),
        (false, false),
        "the subject must not clear before the post-flush BufferCallback watermark",
    );
    assert_eq!(
        passive_access_localization_drain_barrier_for_test(1, 2, true),
        (false, true),
        "the callback after FlushTrace must acknowledge the drain epoch",
    );
    let setup_failure = passive_access_setup_cleanup_failure_for_test(Some(87), 5);
    assert!(setup_failure.contains("state=invalid-setup-cleanup"));
    assert!(setup_failure.contains("operation_status=87"));
    assert!(setup_failure.contains("cleanup_stop_status=5"));

    assert_eq!(
        passive_create_initiator_for_test(0, &42_u64.to_ne_bytes()).unwrap(),
        42,
    );
    assert_eq!(
        passive_create_initiator_for_test(1, &42_u32.to_ne_bytes()).unwrap(),
        42,
    );
    assert!(passive_create_initiator_for_test(1, &42_u64.to_ne_bytes()).is_err());

    let raw_name = b"raw-object-name-never-rendered";
    let domain_digest = passive_file_object_name_digest_for_test(raw_name);
    assert_eq!(domain_digest.len(), 64);
    assert!(!domain_digest.contains("raw-object-name"));

    let mut unrelated_then_valid = Vec::new();
    for index in 0..=MAX_TRACE_EVENTS_FOR_TEST {
        unrelated_then_valid.push(PassiveAccessLocalizationEventForTest::OperationEnd {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            header_process_matches: false,
            schema_matches: true,
            irp: u64::try_from(index).expect("event test ordinal fits u64") + 100,
            native_status: 0,
            event_version: 0,
        });
    }
    unrelated_then_valid.extend([
        PassiveAccessLocalizationEventForTest::Create {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            process_matches: true,
            initiator_matches: true,
            schema_matches: true,
            irp: 1,
            name_sha256: HASH,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::OperationEnd {
            cell: PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            header_process_matches: false,
            schema_matches: true,
            irp: 1,
            native_status: 0,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::Create {
            cell: PassiveAccessLocalizationCellV1::TargetUser,
            process_matches: true,
            initiator_matches: true,
            schema_matches: true,
            irp: 2,
            name_sha256: HASH,
            event_version: 0,
        },
        PassiveAccessLocalizationEventForTest::OperationEnd {
            cell: PassiveAccessLocalizationCellV1::TargetUser,
            header_process_matches: false,
            schema_matches: true,
            irp: 2,
            native_status: 0xc000_0022_u32 as i32,
            event_version: 0,
        },
    ]);
    let flooded = passive_access_localization_for_test(&unrelated_then_valid, true, 1);
    assert_eq!(flooded.classification, "candidate-file-denial-differential");
    assert!(flooded.admissible());
    let flooded_diagnostic = flooded.diagnostic();
    assert!(flooded_diagnostic.contains("canonical_events=1"));
    assert!(flooded_diagnostic.contains("target_user_events=1"));
}

#[test]
fn passive_session_start_denial_is_typed_and_only_exact_reproduction_enables_fallback() {
    let setup = passive_access_session_start_unavailable_for_test(5);
    assert_eq!(setup.classification, "observer-unavailable");
    assert!(!setup.admissible());
    assert!(setup.exact_session_start_access_denied());
    let diagnostic = setup.diagnostic();
    for field in [
        "passive_access_localization=v2",
        "state=observer-unavailable",
        "setup_stage=session-start",
        "win32_status=5",
        "operation_status=5",
        "session_created=false",
        "provider_enable_attempted=false",
        "consumer_opened=false",
        "consumer_ready=false",
        "schema_observed=false",
        "subject_binding_sha256=none",
        "frontier=[]",
        "events_lost=unavailable",
        "overflow=unavailable",
        "requested_access_available=false",
        "workload_executed=false",
        "qualification_promoted=false",
    ] {
        assert!(diagnostic.contains(field), "missing typed field {field}");
    }
    assert!(!diagnostic.contains("state=unsupported-provider-schema"));
    assert!(loader_full_observer_fallback_gate_for_test(true, &setup));
    assert!(!loader_full_observer_fallback_gate_for_test(false, &setup));

    let other_status = passive_access_session_start_unavailable_for_test(87);
    assert!(!other_status.exact_session_start_access_denied());
    assert!(!loader_full_observer_fallback_gate_for_test(
        true,
        &other_status
    ));

    let cleanup_failed = passive_access_consumer_open_failure_for_test(Some(87), 5);
    assert_eq!(cleanup_failed.classification, "invalid-setup-cleanup");
    assert!(!cleanup_failed.admissible());
    assert!(!loader_full_observer_fallback_gate_for_test(
        true,
        &cleanup_failed,
    ));
    let cleanup_diagnostic = cleanup_failed.diagnostic();
    assert!(cleanup_diagnostic.contains("operation_status=87"));
    assert!(cleanup_diagnostic.contains("cleanup_stop_status=5"));
    assert!(cleanup_diagnostic.contains("frontier=[]"));

    let absent = passive_access_consumer_open_failure_for_test(None, 0);
    let absent_diagnostic = absent.diagnostic();
    assert!(absent_diagnostic.contains("operation_status=none"));
    assert!(!absent_diagnostic.contains("operation_status=-1"));
    let actual_negative = passive_access_consumer_open_failure_for_test(Some(-7), 0).diagnostic();
    assert!(actual_negative.contains("operation_status=-7"));

    let cleaned = passive_access_runtime_cleanup_for_test(0, 0, 0, 0);
    let cleaned_diagnostic = cleaned.diagnostic();
    for field in [
        "cleanup_provider_disable_status=0",
        "cleanup_stop_status=0",
        "cleanup_process_trace_status=0",
        "cleanup_close_status=0",
    ] {
        assert!(cleaned_diagnostic.contains(field));
    }
    assert_eq!(cleaned.classification, "coverage-insufficient");
    for statuses in [(5, 0, 0, 0), (0, 5, 0, 0), (0, 0, 5, 0), (0, 0, 0, 5)] {
        let failed =
            passive_access_runtime_cleanup_for_test(statuses.0, statuses.1, statuses.2, statuses.3);
        assert_eq!(failed.classification, "invalid");
        assert!(!failed.admissible());
    }
}

#[test]
fn full_observer_pair_requires_exact_reproduction_and_bounds_its_claim() {
    use LoaderObjectSecurityOutcomeForTest::{Failed, Passed};
    const PHASE: &str = "post-resume-pre-loader-ready";
    const ACCESS_DENIED: i32 = 0xc000_0022_u32 as i32;

    assert_eq!(
        classify_loader_full_observer_for_test(
            Passed,
            Failed {
                native: ACCESS_DENIED,
                phase: PHASE,
            },
            true,
            Some(true),
        ),
        "observer-perturbed-differential",
    );
    assert_eq!(
        classify_loader_full_observer_for_test(
            Passed,
            Failed {
                native: ACCESS_DENIED,
                phase: PHASE,
            },
            true,
            Some(false),
        ),
        "observer-perturbed-nonlocalizing",
    );
    for (debug_c, debug_f, invariants, differential) in [
        (
            Failed {
                native: ACCESS_DENIED,
                phase: PHASE,
            },
            Failed {
                native: ACCESS_DENIED,
                phase: PHASE,
            },
            true,
            Some(true),
        ),
        (Passed, Passed, true, Some(true)),
        (
            Passed,
            Failed {
                native: 0xc000_0142_u32 as i32,
                phase: PHASE,
            },
            true,
            Some(true),
        ),
        (
            Passed,
            Failed {
                native: ACCESS_DENIED,
                phase: "exit-drain",
            },
            true,
            Some(true),
        ),
        (
            Passed,
            Failed {
                native: ACCESS_DENIED,
                phase: PHASE,
            },
            false,
            Some(true),
        ),
        (
            Passed,
            Failed {
                native: ACCESS_DENIED,
                phase: PHASE,
            },
            true,
            None,
        ),
    ] {
        assert_eq!(
            classify_loader_full_observer_for_test(debug_c, debug_f, invariants, differential,),
            "observer-perturbed-inconclusive",
        );
    }

    let original_a = Failed {
        native: 0xc000_0142_u32 as i32,
        phase: PHASE,
    };
    let singleton_failure = Failed {
        native: ACCESS_DENIED,
        phase: PHASE,
    };
    let original = |values: [LoaderObjectSecurityOutcomeForTest; 6], invariants| {
        loader_restriction_original_sext_reproduction_for_test(
            values[0], values[1], values[2], values[3], values[4], values[5], invariants,
        )
    };
    let pristine = [
        original_a,
        Passed,
        Passed,
        singleton_failure,
        singleton_failure,
        singleton_failure,
    ];
    assert!(original(pristine, true));
    for (index, mutation) in [
        Passed,
        Failed {
            native: ACCESS_DENIED,
            phase: PHASE,
        },
        Failed {
            native: 0xc000_0142_u32 as i32,
            phase: "exit-drain",
        },
        Passed,
        Passed,
        Passed,
    ]
    .into_iter()
    .enumerate()
    {
        let mut values = pristine;
        values[index] = mutation;
        assert!(
            !original(values, true),
            "A-F outcome predicate bypass at {index}"
        );
    }
    for baseline_mutation in [
        Failed {
            native: ACCESS_DENIED,
            phase: PHASE,
        },
        Failed {
            native: 0xc000_0142_u32 as i32,
            phase: "exit-drain",
        },
    ] {
        let mut values = pristine;
        values[0] = baseline_mutation;
        assert!(!original(values, true));
    }
    for index in 3..6 {
        let mut wrong_status = pristine;
        wrong_status[index] = Failed {
            native: 0xc000_0142_u32 as i32,
            phase: PHASE,
        };
        assert!(
            !original(wrong_status, true),
            "singleton status bypass at {index}"
        );
        let mut wrong_phase = pristine;
        wrong_phase[index] = Failed {
            native: ACCESS_DENIED,
            phase: "exit-drain",
        };
        assert!(
            !original(wrong_phase, true),
            "singleton phase bypass at {index}"
        );
    }
    assert!(!original(pristine, false));

    let valid = |values: [bool; 12]| {
        loader_full_observer_invariants_for_test(
            values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7],
            values[8], values[9], values[10], values[11],
        )
    };
    assert!(valid([true; 12]));
    for index in 0..12 {
        let mut values = [true; 12];
        values[index] = false;
        assert!(!valid(values), "invariant bypass at index {index}");
    }
    let invariant_names = [
        "fallback-authority",
        "original-reproduction",
        "original-invariants",
        "original-projection",
        "debug-pair-common",
        "debug-mode",
        "debug-c-trace-admission",
        "debug-f-trace-admission",
        "debug-containment",
        "post-debug-c-environment",
        "post-debug-f-environment",
        "profile-stability",
        "environment-destruction-once",
    ];
    assert_eq!(
        loader_full_observer_failed_invariants_for_test([true; 13]),
        (true, String::new()),
    );
    for (index, expected) in invariant_names.into_iter().enumerate() {
        let mut values = [true; 13];
        values[index] = false;
        let (valid, failed) = loader_full_observer_failed_invariants_for_test(values);
        assert!(!valid, "failed invariant {expected} was admitted");
        assert_eq!(failed, expected);
        assert_eq!(
            classify_loader_full_observer_for_test(
                Passed,
                Failed {
                    native: ACCESS_DENIED,
                    phase: PHASE,
                },
                valid,
                Some(true),
            ),
            "observer-perturbed-inconclusive",
        );
    }

    let debug_c_trace = admitted_full_observer_trace(&[TRACE_HASH_B, TRACE_HASH_A]);
    let debug_f_trace = admitted_full_observer_trace(&[TRACE_HASH_B]);
    assert!(loader_full_observer_trace_admitted_for_test(&debug_c_trace));
    assert_eq!(
        loader_full_observer_trace_admission_for_test(&format!(
            "loader_launch=v4 command_dynamic_fields=authenticated-private-pipe,authenticated-nonce command_semantics_sha256={TRACE_HASH_A} {debug_c_trace}"
        )),
        "admitted",
        "outer launch evidence must not collide with trace-local scalar uniqueness",
    );
    let candidate_modules = candidate_modules_from_trace(&debug_c_trace);
    let candidate_module_fields = candidate_modules.split(',').collect::<Vec<_>>();
    let first_candidate_identity = candidate_module_fields[0]
        .split_once(':')
        .expect("candidate module contains an ordinal/base prefix")
        .1;
    let duplicate_stable_identity = format!(
        "{},2@0x2000:{first_candidate_identity}",
        candidate_module_fields[0]
    );
    let extra_candidate =
        format!("{candidate_modules},3@0x3000:module-2.dll:file-handle:{TRACE_HASH_B}:ok:file-ok");
    let trace_rejections = [
        (
            "loader launch without a trace record".to_owned(),
            "rejected-missing-trace-record",
        ),
        (
            format!("{debug_c_trace} {debug_c_trace}"),
            "rejected-duplicate-trace-record",
        ),
        (
            debug_c_trace.replace("loader_trace=v4", "loader_trace=v3"),
            "rejected-version",
        ),
        (
            debug_c_trace.replace(" gate=ephemeral-ci", ""),
            "rejected-missing-scalar",
        ),
        (
            format!("{debug_c_trace} gate=ephemeral-ci"),
            "rejected-duplicate-scalar",
        ),
        (
            format!(
                "{debug_c_trace} command_dynamic_fields=authenticated-private-pipe,authenticated-nonce"
            ),
            "rejected-duplicate-scalar",
        ),
        (
            format!("{debug_c_trace} command_semantics_sha256={TRACE_HASH_A}"),
            "rejected-duplicate-scalar",
        ),
        (
            debug_c_trace.replace(
                &format!(" candidate_modules=[{candidate_modules}]"),
                "",
            ),
            "rejected-missing-scalar",
        ),
        (
            format!("{debug_c_trace} candidate_modules=[{candidate_modules}]"),
            "rejected-duplicate-scalar",
        ),
        (
            debug_c_trace.replace(
                &format!("candidate_modules=[{candidate_modules}]"),
                "candidate_modules=[malformed]",
            ),
            "rejected-candidate-module-tail-malformed",
        ),
        (
            trace_with_candidate_modules(&debug_c_trace, &duplicate_stable_identity),
            "rejected-candidate-module-tail-malformed",
        ),
        (
            trace_with_candidate_modules(&debug_c_trace, &extra_candidate),
            "rejected-candidate-module-tail-malformed",
        ),
        (
            trace_with_candidate_modules(
                &debug_c_trace,
                &candidate_modules.replacen(":ok:file-ok", ":ok", 1),
            ),
            "rejected-candidate-module-tail-malformed",
        ),
        (
            trace_with_candidate_modules(
                &debug_c_trace,
                &candidate_modules.replacen(":ok:file-ok", ":ok:unknown-provenance", 1),
            ),
            "rejected-candidate-module-tail-malformed",
        ),
        (
            trace_with_candidate_modules(
                &debug_c_trace,
                &candidate_modules.replacen(":ok:file-ok", ":os-5:file-ok", 1),
            ),
            "rejected-candidate-module-tail-malformed",
        ),
        (
            trace_with_candidate_modules(
                &debug_c_trace,
                &candidate_modules.replacen("1@0x1000", "0@0x1000", 1),
            ),
            "rejected-candidate-module-tail-malformed",
        ),
        (
            trace_with_candidate_modules(
                &debug_c_trace,
                &candidate_modules.replacen("1@0x1000", "1@0x0", 1),
            ),
            "rejected-candidate-module-tail-malformed",
        ),
        (
            debug_c_trace.replace(
                &format!(
                    "candidate_modules_sha256={}",
                    loader_full_observer_candidate_tail_digest_for_test(candidate_modules)
                ),
                &format!("candidate_modules_sha256={TRACE_HASH_A}"),
            ),
            "rejected-candidate-module-tail-digest",
        ),
        (
            debug_c_trace.replace(
                &format!(" unknown_event_tail_sha256={EMPTY_SHA256}"),
                "",
            ),
            "rejected-missing-scalar",
        ),
        (
            format!("{debug_c_trace} unknown_event_tail_sha256={EMPTY_SHA256}"),
            "rejected-duplicate-scalar",
        ),
        (
            debug_c_trace.replace(
                &format!("unknown_event_tail_sha256={EMPTY_SHA256}"),
                "unknown_event_tail_sha256=short",
            ),
            "rejected-digest-shape",
        ),
        (
            debug_c_trace.replace(
                &format!("unknown_event_tail_sha256={EMPTY_SHA256}"),
                &format!(
                    "unknown_event_tail_sha256={}",
                    TRACE_HASH_A.replacen('a', "g", 1)
                ),
            ),
            "rejected-digest-shape",
        ),
        (
            debug_c_trace.replace(
                " events=3 accounted_events=3",
                " events=invalid accounted_events=3",
            ),
            "rejected-invalid-unsigned",
        ),
        (
            debug_c_trace.replace("gate=ephemeral-ci", "gate=other"),
            "rejected-gate",
        ),
        (
            debug_c_trace.replace("drained=true", "drained=false"),
            "rejected-drain",
        ),
        (
            debug_c_trace.replace(
                "debug_cleanup=exit-process-event-continued",
                "debug_cleanup=pending",
            ),
            "rejected-debug-cleanup",
        ),
        (
            debug_c_trace.replace("create_event=true", "create_event=false"),
            "rejected-create-event",
        ),
        (
            debug_c_trace.replace("exit_event=true", "exit_event=false"),
            "rejected-exit-event",
        ),
        (
            debug_c_trace.replace(
                "command_dynamic_fields=authenticated-private-pipe,authenticated-nonce",
                "command_dynamic_fields=raw-command",
            ),
            "rejected-command-declaration",
        ),
        (
            debug_c_trace.replace("events=3 accounted_events=3", "events=4 accounted_events=3"),
            "rejected-event-accounting",
        ),
        (
            debug_c_trace.replace(
                "events=3 accounted_events=3",
                "events=65537 accounted_events=65537",
            ),
            "rejected-event-bound",
        ),
        (
            debug_c_trace.replace("debug_strings=0", "debug_strings=1"),
            "rejected-debug-string-count",
        ),
        (
            debug_c_trace.replace("debug_string_bytes=0", "debug_string_bytes=1"),
            "rejected-debug-string-bytes",
        ),
        (
            debug_c_trace.replace("debug_string_overflow=0", "debug_string_overflow=1"),
            "rejected-debug-string-overflow",
        ),
        (
            debug_c_trace.replace("candidate_modules_count=2", "candidate_modules_count=3"),
            "rejected-candidate-modules-tail-count-retained",
        ),
        (
            debug_c_trace.replace(
                "candidate_modules_overflow=0",
                "candidate_modules_overflow=1",
            ),
            "rejected-candidate-modules-tail-overflow",
        ),
        (
            debug_c_trace
                .replace("candidate_modules_count=2", "candidate_modules_count=9")
                .replace(
                    "candidate_modules_retained=2",
                    "candidate_modules_retained=9",
                ),
            "rejected-candidate-modules-tail-capacity",
        ),
        (
            debug_c_trace.replace("loader_snap_tail_count=0", "loader_snap_tail_count=1"),
            "rejected-loader-snap-count",
        ),
        (
            debug_c_trace.replace(
                "loader_snap_tail_retained=0",
                "loader_snap_tail_retained=1",
            ),
            "rejected-loader-snap-retained",
        ),
        (
            debug_c_trace.replace(
                "loader_snap_tail_overflow=0",
                "loader_snap_tail_overflow=1",
            ),
            "rejected-loader-snap-overflow",
        ),
        (
            debug_c_trace.replace("trace_sha256=aaaaaaaa", "trace_sha256=gggggggg"),
            "rejected-digest-shape",
        ),
        (
            debug_c_trace.replace(
                "loader_snap_tail_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "loader_snap_tail_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "rejected-empty-snap-digest",
        ),
    ];
    for (detail, expected) in trace_rejections {
        assert_eq!(
            loader_full_observer_trace_admission_for_test(&detail),
            expected,
            "wrong bounded trace rejection for {expected}",
        );
    }
    for malformed in [
        debug_c_trace.replace("drained=true", "drained=false"),
        debug_c_trace.replace(
            "debug_cleanup=exit-process-event-continued",
            "debug_cleanup=pending",
        ),
        debug_c_trace.replace(
            "events=3 accounted_events=3",
            "events=4 accounted_events=3",
        ),
        debug_c_trace.replace("candidate_modules_overflow=0", "candidate_modules_overflow=1"),
        debug_c_trace.replace("debug_strings=0", "debug_strings=1"),
        debug_c_trace.replace("trace_sha256=aaaaaaaa", "trace_sha256=gggggggg"),
        debug_c_trace.replace("loader_snap_tail_count=0", "loader_snap_tail_count=1"),
        debug_c_trace.replace(
            "loader_snap_tail_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "loader_snap_tail_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        debug_c_trace.replace(
            "command_dynamic_fields=authenticated-private-pipe,authenticated-nonce",
            "command_dynamic_fields=raw-command",
        ),
    ] {
        assert!(
            !loader_full_observer_trace_admitted_for_test(&malformed),
            "malformed FullObserver receipt was admitted: {malformed}",
        );
    }

    let debug_c_secret = "debug-c raw module C:\\secret\\c.dll";
    let debug_f_secret = "debug-f raw output secret";
    let debug_c_trace = format!("{debug_c_trace} raw_debug_secret={debug_c_secret}");
    let debug_f_trace = format!("{debug_f_trace} raw_debug_secret={debug_f_secret}");
    let diagnostic =
        render_loader_full_observer_canary_for_test(&debug_c_trace, &debug_f_trace, true, true);
    for field in [
        "state=observer-perturbed-differential",
        "observer_perturbed=true",
        "changed_fields=[debugger_relation,debug_creation_flag]",
        "debug_c_observer=full-observer-v4",
        "debug_f_observer=full-observer-v4",
        "debug_c_loader_snaps=false",
        "debug_f_loader_snaps=false",
        "loader_snap_evidence=expected-empty",
        "debug_c_trace_admission=admitted",
        "debug_f_trace_admission=admitted",
        "failed_invariants=[]",
        "ifeo_changed=false",
        "debug_f=[outcome=failed native=0xc0000022 phase=post-resume-pre-loader-ready",
        "shared_environment_owner=original-baseline",
        "shared_environment_destroyed_once=true",
        "stable_module_frontier=strict-f-prefix-c-extension",
        "stable_module_c_total=2",
        "stable_module_c_retained=2",
        "stable_module_c_sequence_sha256=",
        "stable_module_f_total=1",
        "stable_module_f_retained=1",
        "stable_module_f_sequence_sha256=",
        "stable_module_common_prefix=1",
        "stable_module_last_common_sha256=",
        "stable_module_first_c_only_sha256=",
        "candidate_frontier_only=true",
        "requested_access_available=false",
        "exact_resource_identified=false",
        "acl_fix_identified=false",
        "primary_failure=original-a",
        "job_empty=true",
        "release_sent=false",
        "workload_executed=false",
        "qualification_promoted=false",
    ] {
        assert!(diagnostic.contains(field), "missing bounded field {field}");
    }
    assert!(!diagnostic.contains(debug_c_secret));
    assert!(!diagnostic.contains(debug_f_secret));
    assert!(!diagnostic.contains("module-0.dll"));
    assert!(!diagnostic.contains("@0x"));

    let render = |debug_c_trace: &str, debug_f_trace: &str| {
        render_loader_full_observer_canary_for_test(debug_c_trace, debug_f_trace, true, true)
    };
    let assert_nonlocalizing = |diagnostic: &str| {
        assert!(diagnostic.contains("state=observer-perturbed-nonlocalizing"));
        assert!(diagnostic.contains("stable_module_frontier=nonlocalizing"));
        assert!(diagnostic.contains("stable_module_last_common_sha256=none"));
        assert!(diagnostic.contains("stable_module_first_c_only_sha256=none"));
        assert!(diagnostic.contains("requested_access_available=false"));
        assert!(diagnostic.contains("exact_resource_identified=false"));
        assert!(diagnostic.contains("acl_fix_identified=false"));
    };

    let equal_c = admitted_full_observer_trace(&[TRACE_HASH_B]);
    let equal_f = admitted_full_observer_trace(&[TRACE_HASH_B]);
    let address_only_modules =
        candidate_modules_from_trace(&equal_c).replacen("1@0x1000", "7@0x7000", 1);
    let address_only_c = trace_with_candidate_modules(&equal_c, &address_only_modules);
    let address_only_diagnostic = render(&address_only_c, &equal_f);
    assert_nonlocalizing(&address_only_diagnostic);
    assert!(address_only_diagnostic.contains("stable_module_common_prefix=1"));
    assert!(address_only_diagnostic.contains("stable_module_c_sequence_sha256="));

    let exception_only_c = equal_c.replace(
        &format!("exception_tail_sha256={EMPTY_SHA256}"),
        &format!("exception_tail_sha256={TRACE_HASH_A}"),
    );
    assert_nonlocalizing(&render(&exception_only_c, &equal_f));

    assert_nonlocalizing(&render(
        &admitted_full_observer_trace(&[TRACE_HASH_A, TRACE_HASH_B]),
        &admitted_full_observer_trace(&[TRACE_HASH_B, TRACE_HASH_A]),
    ));
    assert_nonlocalizing(&render(
        &admitted_full_observer_trace(&[TRACE_HASH_A]),
        &admitted_full_observer_trace(&[TRACE_HASH_B]),
    ));

    let unstable_modules = candidate_modules_from_trace(&equal_c)
        .replace(":file-handle:", ":event-image-name-untrusted:")
        .replace(
            ":ok:file-ok",
            ":ok:file-null>mapped-null-base>event-wide-ok",
        );
    let unstable_c = trace_with_candidate_modules(&equal_c, &unstable_modules);
    let unstable_f = trace_with_candidate_modules(&equal_f, &unstable_modules);
    assert_nonlocalizing(&render(&unstable_c, &unstable_f));

    let partial_unavailable_modules = format!(
        "1@0x1000:unavailable:unavailable:{TRACE_HASH_B}:os-5:file-null>mapped-null-base>event-wide-partial-12"
    );
    let partial_unavailable_c =
        trace_with_candidate_modules(&equal_c, &partial_unavailable_modules);
    let partial_unavailable_f =
        trace_with_candidate_modules(&equal_f, &partial_unavailable_modules);
    assert!(loader_full_observer_trace_admitted_for_test(
        &partial_unavailable_c
    ));
    assert_nonlocalizing(&render(&partial_unavailable_c, &partial_unavailable_f));

    let containment_failure =
        render_loader_full_observer_canary_for_test(&debug_c_trace, &debug_f_trace, false, true);
    assert!(containment_failure.contains("state=observer-perturbed-inconclusive"));
    assert!(containment_failure.contains("invariants_valid=false"));
    assert!(containment_failure.contains("failed_invariants=[debug-containment]"));
    assert!(containment_failure.contains("job_empty=true"));
    for field in [
        "debug_c_trace_sha256=none",
        "debug_f_trace_sha256=none",
        "debug_c_modules_sha256=none",
        "debug_f_modules_sha256=none",
    ] {
        assert!(containment_failure.contains(field));
    }

    let malformed_diagnostic = render_loader_full_observer_canary_for_test(
        &debug_c_trace.replace("drained=true", "drained=false"),
        &debug_f_trace,
        true,
        true,
    );
    assert!(malformed_diagnostic.contains("state=observer-perturbed-inconclusive"));
    assert!(malformed_diagnostic.contains("debug_c_trace_admission=rejected-drain"));
    assert!(malformed_diagnostic.contains("debug_f_trace_admission=admitted"));
    assert!(malformed_diagnostic.contains("failed_invariants=[debug-c-trace-admission]"));
    assert!(malformed_diagnostic.contains("debug_c_trace_sha256=none"));
    assert!(malformed_diagnostic.contains("debug_f_trace_sha256=none"));
    assert!(malformed_diagnostic.contains("stable_module_frontier=suppressed"));
    assert!(malformed_diagnostic.contains("stable_module_first_c_only_sha256=none"));
}

#[test]
fn trace_session_capability_gate_accepts_only_clean_zero_prefix_nonlocalizing_evidence() {
    let debug_c = admitted_full_observer_trace(&[TRACE_HASH_A, TRACE_HASH_B]);
    let debug_f = admitted_full_observer_trace(&[
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ]);
    let passed = LoaderObjectSecurityOutcomeForTest::Passed;
    let denied = LoaderObjectSecurityOutcomeForTest::Failed {
        native: 0xc000_0022_u32 as i32,
        phase: "post-resume-pre-loader-ready",
    };
    assert!(loader_trace_session_capability_gate_for_test(
        true, true, true, true, passed, denied, &debug_c, &debug_f, [true; 13], true, true,
    ));
    for rejected in [
        loader_trace_session_capability_gate_for_test(
            false, true, true, true, passed, denied, &debug_c, &debug_f, [true; 13], true, true,
        ),
        loader_trace_session_capability_gate_for_test(
            true, false, true, true, passed, denied, &debug_c, &debug_f, [true; 13], true, true,
        ),
        loader_trace_session_capability_gate_for_test(
            true, true, false, true, passed, denied, &debug_c, &debug_f, [true; 13], true, true,
        ),
        loader_trace_session_capability_gate_for_test(
            true, true, true, false, passed, denied, &debug_c, &debug_f, [true; 13], true, true,
        ),
        loader_trace_session_capability_gate_for_test(
            true,
            true,
            true,
            true,
            passed,
            denied,
            &debug_c,
            &debug_f,
            [
                true, true, true, true, true, true, true, true, true, true, true, true, false,
            ],
            true,
            true,
        ),
        loader_trace_session_capability_gate_for_test(
            true, true, true, true, passed, denied, &debug_c, &debug_f, [true; 13], false, true,
        ),
    ] {
        assert!(!rejected);
    }
    let strict_prefix_f = admitted_full_observer_trace(&[TRACE_HASH_A]);
    assert!(!loader_trace_session_capability_gate_for_test(
        true,
        true,
        true,
        true,
        passed,
        denied,
        &debug_c,
        &strict_prefix_f,
        [true; 13],
        true,
        true,
    ));
    let empty_modules = admitted_full_observer_trace(&[]);
    assert!(!loader_trace_session_capability_gate_for_test(
        true,
        true,
        true,
        true,
        passed,
        denied,
        &empty_modules,
        &debug_f,
        [true; 13],
        true,
        true,
    ));
    assert!(!loader_trace_session_capability_gate_for_test(
        true,
        true,
        true,
        true,
        passed,
        denied,
        &debug_c,
        &empty_modules,
        [true; 13],
        true,
        true,
    ));
}

#[test]
fn trace_session_capability_state_table_is_fail_closed() {
    assert_eq!(trace_session_capability_schema_versions_for_test(), (6, 1));
    assert_eq!(
        trace_session_capability_state_for_test(true, false, 0, true, true, Some(0), 1, true),
        "broker-session-available"
    );
    assert_eq!(
        trace_session_capability_state_for_test(true, false, 5, false, false, None, 0, true),
        "broker-session-unavailable"
    );
    for state in [
        trace_session_capability_state_for_test(true, false, 183, false, false, None, 0, false),
        trace_session_capability_state_for_test(true, false, 0, true, true, Some(5), 1, false),
        trace_session_capability_state_for_test(true, false, 0, true, true, Some(0), 2, true),
        trace_session_capability_state_for_test(false, false, 0, true, true, Some(0), 1, true),
        trace_session_capability_state_for_test(true, true, 0, true, true, Some(0), 1, true),
    ] {
        assert_eq!(state, "broker-session-invalid");
    }
}

#[test]
fn trace_session_capability_trigger_binds_every_a_f_evidence_layer() {
    let debug_c = admitted_full_observer_trace(&[TRACE_HASH_A, TRACE_HASH_B]);
    let debug_f = admitted_full_observer_trace(&[
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ]);
    let pristine = loader_trace_session_capability_trigger_binding_for_test(
        &debug_c,
        &debug_f,
        TraceSessionCapabilityTriggerMutationForTest::Pristine,
    )
    .expect("clean typed trigger must seal");
    for mutation in [
        TraceSessionCapabilityTriggerMutationForTest::RestrictionIdentity,
        TraceSessionCapabilityTriggerMutationForTest::LogonRestriction,
        TraceSessionCapabilityTriggerMutationForTest::AuthenticatedUsersRestriction,
        TraceSessionCapabilityTriggerMutationForTest::TargetUserRestriction,
        TraceSessionCapabilityTriggerMutationForTest::SharedEvidence,
        TraceSessionCapabilityTriggerMutationForTest::CellDetail,
    ] {
        let changed =
            loader_trace_session_capability_trigger_binding_for_test(&debug_c, &debug_f, mutation)
                .expect("mutated typed evidence remains structurally valid");
        assert_ne!(pristine, changed, "typed evidence mutation was not sealed");
    }
}

#[test]
fn trace_session_capability_receipt_admission_recomputes_every_relation() {
    for mutation in [
        TraceSessionCapabilityReceiptMutationForTest::Available,
        TraceSessionCapabilityReceiptMutationForTest::Unavailable,
        TraceSessionCapabilityReceiptMutationForTest::ClosedInvalidStopFailure,
    ] {
        let (admitted, seal_valid, _) = trace_session_capability_receipt_for_test(mutation);
        assert!(admitted, "closed production-shaped receipt was rejected");
        assert!(seal_valid, "closed production-shaped receipt lost its seal");
    }
    for mutation in [
        TraceSessionCapabilityReceiptMutationForTest::ContradictoryInvalid,
        TraceSessionCapabilityReceiptMutationForTest::WrongAfterAuthority,
        TraceSessionCapabilityReceiptMutationForTest::AuthorityEqualFalse,
        TraceSessionCapabilityReceiptMutationForTest::DeadlineExceeded,
        TraceSessionCapabilityReceiptMutationForTest::ElapsedPastDeadline,
        TraceSessionCapabilityReceiptMutationForTest::WrongTransaction,
        TraceSessionCapabilityReceiptMutationForTest::WrongTrigger,
        TraceSessionCapabilityReceiptMutationForTest::WrongRequestBinding,
        TraceSessionCapabilityReceiptMutationForTest::WrongBrokerSource,
        TraceSessionCapabilityReceiptMutationForTest::WrongBrokerIdentity,
        TraceSessionCapabilityReceiptMutationForTest::WrongSessionName,
        TraceSessionCapabilityReceiptMutationForTest::CorruptSeal,
    ] {
        let (admitted, _, _) = trace_session_capability_receipt_for_test(mutation);
        assert!(!admitted, "contradictory or misbound receipt was admitted");
    }
}

#[test]
fn trace_session_capability_renderer_preserves_sealed_and_retirement_provenance() {
    let (admitted, seal_valid, diagnostic) = trace_session_capability_receipt_for_test(
        TraceSessionCapabilityReceiptMutationForTest::RetirementFailure,
    );
    assert!(admitted);
    assert!(
        seal_valid,
        "retirement failure mutated the sealed native receipt"
    );
    for expected in [
        "state=broker-session-invalid",
        "broker_receipt_state=broker-session-available",
        "session_absence_proven=true",
        "retirement=retirement-failed",
        "failure_stage=broker-retire",
        "failure_sha256=none",
        "receipt_sha256=",
        "transaction_sha256=",
        "broker_source_sha256=",
        "retirement_failure_sha256=",
        "transaction_nonce_redacted=true",
        "broker_source_values_redacted=true",
        "primary_failure=original-a",
    ] {
        assert!(
            diagnostic.contains(expected),
            "missing renderer field {expected}"
        );
    }
    for secret in [
        "test-start-nonce-not-rendered",
        "test-challenge-not-rendered",
        "test-transaction-nonce-not-rendered",
        "test-normalized-broker-source",
    ] {
        assert!(!diagnostic.contains(secret), "renderer exposed {secret}");
    }
    assert!(
        diagnostic.len() < 4_096,
        "capability diagnostic is unbounded"
    );

    let dual_failure = trace_session_capability_dual_failure_diagnostic_for_test();
    assert!(dual_failure.contains("failure_stage=broker-protocol"));
    assert!(!dual_failure.contains("failure_sha256=none"));
    assert!(!dual_failure.contains("retirement_failure_sha256=none"));
    assert!(dual_failure.contains("primary_failure=original-a"));
}

#[test]
fn target_logon_sid_admission_requires_one_enabled_non_deny_raw_group() {
    const DENY_ONLY: u32 = 0x10;
    let logon_attributes = SE_GROUP_LOGON_ID as u32 | SE_GROUP_ENABLED as u32;
    assert_eq!(
        validate_logon_sid_group_inventory_for_test(&[
            ("S-1-5-32-545", SE_GROUP_ENABLED as u32),
            ("S-1-5-5-7-11", logon_attributes),
        ])
        .unwrap(),
        ("S-1-5-5-7-11".to_owned(), logon_attributes),
    );
    assert!(validate_token_logon_sid_attributes_for_test(logon_attributes).is_ok());
    assert!(
        validate_token_logon_sid_attributes_for_test(SE_GROUP_ENABLED as u32).is_err(),
        "TokenLogonSid without its raw logon marker was admitted",
    );
    for groups in [
        vec![("S-1-5-32-545", SE_GROUP_ENABLED as u32)],
        vec![("S-1-5-5-7-11", SE_GROUP_ENABLED as u32)],
        vec![("S-1-5-5-7-11", SE_GROUP_LOGON_ID as u32)],
        vec![("S-1-5-5-7-11", logon_attributes | DENY_ONLY)],
        vec![
            ("S-1-5-5-7-11", logon_attributes),
            ("S-1-5-5-13-17", logon_attributes),
        ],
        vec![
            ("S-1-5-5-7-11", logon_attributes),
            ("S-1-5-5-7-11", logon_attributes),
        ],
    ] {
        assert!(
            validate_logon_sid_group_inventory_for_test(&groups).is_err(),
            "a missing, malformed, or duplicate raw TokenGroups logon SID was admitted",
        );
    }
}

#[test]
fn authenticated_users_singleton_admission_requires_one_exact_raw_group() {
    assert_eq!(
        validate_authenticated_users_matches_for_test(&[0x7]).unwrap(),
        0x7
    );
    for attributes in [
        Vec::new(),
        vec![0],
        vec![SE_GROUP_ENABLED as u32],
        vec![0x7 | 0x10],
        vec![0x7, 0x7],
    ] {
        assert!(
            validate_authenticated_users_matches_for_test(&attributes).is_err(),
            "an absent, malformed, deny-only, or duplicate raw Authenticated Users entry was admitted",
        );
    }
}

#[test]
fn target_user_singleton_requires_raw_c_membership_and_exact_raw_output() {
    assert_eq!(
        validate_target_user_matches_for_test(
            true,
            &[(false, 0x7), (true, 0x7), (false, 0x7)],
            &[(true, 0x7)],
        )
        .unwrap(),
        (0x7, 0x7),
    );
    for (source_valid, canonical, output) in [
        (false, vec![(true, 0x7)], vec![(true, 0x7)]),
        (true, Vec::new(), vec![(true, 0x7)]),
        (true, vec![(false, 0x7)], vec![(true, 0x7)]),
        (true, vec![(true, 0x7), (true, 0x7)], vec![(true, 0x7)]),
        (true, vec![(true, 0)], vec![(true, 0x7)]),
        (true, vec![(true, 0x4)], vec![(true, 0x7)]),
        (true, vec![(true, 0x10)], vec![(true, 0x7)]),
        (true, vec![(true, 0x7 | 0x20)], vec![(true, 0x7)]),
        (true, vec![(true, 0x7)], Vec::new()),
        (true, vec![(true, 0x7)], vec![(false, 0x7)]),
        (true, vec![(true, 0x7)], vec![(true, 0)]),
        (true, vec![(true, 0x7)], vec![(true, 0x7), (false, 0x7)]),
    ] {
        assert!(
            validate_target_user_matches_for_test(source_valid, &canonical, &output).is_err(),
            "invalid raw target-user authority or output was admitted",
        );
    }
}

#[test]
fn canonical_same_access_inventory_sorts_but_rejects_duplicates() {
    assert_eq!(
        canonical_same_access_restricting_sids_for_test(&["S-1-5-32-545", "S-1-5-21-7"]).unwrap(),
        [
            ("S-1-5-21-7".to_owned(), 0x7),
            ("S-1-5-32-545".to_owned(), 0x7),
        ],
    );
    assert!(
        canonical_same_access_restricting_sids_for_test(&[
            "S-1-5-21-7",
            "S-1-5-32-545",
            "S-1-5-21-7",
        ])
        .is_err(),
        "duplicate canonical same-access SIDs must fail closed rather than be deduplicated",
    );
}

#[test]
fn loader_restriction_eligibility_uses_raw_sid_and_attributes() {
    let (display, decisions) = loader_restriction_raw_sid_predicate_for_test().unwrap();
    assert_eq!(display, ["S-1-5-12@7"]);
    assert_eq!(
        decisions,
        [true, false, false, false],
        "only one raw S-1-5-12 entry with normalized attributes 0x7 is eligible",
    );
}

#[test]
fn loader_restriction_pair_differs_only_by_write_restricted_semantics() {
    let (baseline_flags, comparison_flags, restricting_sid) =
        loader_restriction_pair_construction_for_test();
    assert_eq!(baseline_flags, DISABLE_MAX_PRIVILEGE);
    assert_eq!(comparison_flags, DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED);
    assert_eq!(restricting_sid, RESTRICTED_CODE_SID);

    let first = validate_loader_restriction_pair_invariants_for_test(None).unwrap();
    let second = validate_loader_restriction_pair_invariants_for_test(None).unwrap();
    assert_eq!(
        first, second,
        "the authenticated pair binding is deterministic"
    );
    assert_eq!(first.len(), 64);
    assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));

    for field in [
        "user",
        "logon",
        "authentication",
        "session",
        "type",
        "integrity",
        "mandatory",
        "groups",
        "privileges",
        "owner",
        "primary_group",
        "default_dacl",
        "appcontainer",
        "ui_access",
        "virtualization_allowed",
        "virtualization_enabled",
        "restricting_sids",
    ] {
        assert!(
            validate_loader_restriction_pair_invariants_for_test(Some(field)).is_err(),
            "loader restriction pair admitted a mutated {field} field",
        );
    }
}

#[test]
fn qualification_loader_restriction_lease_is_owner_bound_one_shot_and_private() {
    let token = include_str!("../../src/bin/memcordon-sealed-agent/windows/token.rs");
    let control = include_str!("../../src/bin/memcordon-sealed-agent/windows/control_service.rs");
    let launcher = include_str!("../../src/bin/memcordon-sealed-agent/windows/launcher_service.rs");
    let process = include_str!("../../src/bin/memcordon-sealed-agent/windows/process.rs");
    let core = include_str!("../../../memcordon-core/src/windows_sealed.rs");

    assert_qualification_loader_restriction_source_contract(
        token, control, launcher, process, core,
    );
    assert_qualification_loader_restriction_source_contract(
        &token.replace('\n', "\r\n"),
        &control.replace('\n', "\r\n"),
        &launcher.replace('\n', "\r\n"),
        &process.replace('\n', "\r\n"),
        &core.replace('\n', "\r\n"),
    );
}

#[test]
fn loader_restriction_canary_requires_every_pass_required_cell_to_fail() {
    for failed_cells in 0..6 {
        assert!(
            !loader_restriction_canary_required_for_test(failed_cells),
            "diagnostic canary ran after only {failed_cells} pass-required failures",
        );
    }
    assert!(loader_restriction_canary_required_for_test(6));
}

#[test]
fn bounded_loader_restriction_comparison_never_suppresses_primary_failure() {
    let unbounded = format!("comparison\0{}", "x".repeat(32_768));
    let (passing_comparison, primary, qualified) =
        render_loader_restriction_canary_for_test(true, &unbounded);
    assert_eq!(primary, PRIMARY_FAILURE);
    assert!(
        !qualified,
        "a diagnostic comparison cannot qualify the launch"
    );
    assert_canary_contract(&passing_comparison, "passed", "unavailable");
    assert!(passing_comparison.contains(&format!("selected_failure=[{PRIMARY_FAILURE}]")));
    assert!(!passing_comparison.contains('\0'));
    assert!(!passing_comparison.contains(&unbounded));
    assert!(passing_comparison.len() <= 2_048);

    let (failed_comparison, retained_primary, qualified) =
        render_loader_restriction_canary_for_test(false, &unbounded);
    assert_eq!(retained_primary, PRIMARY_FAILURE);
    assert!(
        !qualified,
        "a failed diagnostic comparison cannot qualify the launch"
    );
    assert_canary_contract(&failed_comparison, "failed", "0xc0000142");
    assert!(failed_comparison.contains(&format!("selected_failure=[{PRIMARY_FAILURE}]")));
    assert!(!failed_comparison.contains('\0'));
    assert!(!failed_comparison.contains(&unbounded));
    assert!(failed_comparison.len() <= 2_048);

    let repeated = render_loader_restriction_canary_for_test(false, &unbounded).0;
    assert_eq!(failed_comparison, repeated);
}

#[test]
fn restricting_sid_presence_gate_requires_valid_object_security_common_failure() {
    assert!(loader_restriction_presence_gate_for_test(
        "classified-common-failure",
        true,
        true,
        true,
    ));
    for (state, common_valid, descriptor_present, invariants_valid) in [
        ("classified-common-failure", false, true, true),
        ("classified-common-failure", true, false, true),
        ("classified-common-failure", true, true, false),
        ("process-access-causal", true, true, true),
        ("thread-access-causal", true, true, true),
        ("combined-access-causal", true, true, true),
        ("differing-inconclusive", true, true, true),
        ("invalid", true, true, true),
    ] {
        assert!(
            !loader_restriction_presence_gate_for_test(
                state,
                common_valid,
                descriptor_present,
                invariants_valid,
            ),
            "restriction-presence canary admitted state={state}, common_valid={common_valid}, descriptor_present={descriptor_present}, invariants_valid={invariants_valid}",
        );
    }
}

#[test]
fn restricting_sid_presence_accepts_only_verified_terminal_job_empty_shapes() {
    assert!(loader_control_cell_job_empty_attested_for_test(
        "phase=loader-ready-contained job_empty=true workload_executed=false",
    ));
    assert!(loader_control_cell_job_empty_attested_for_test(
        "phase=unclassified profile_child_cleanup=[job_empty_before_termination=false,job_empty_after_cleanup=true]",
    ));

    for detail in [
        "phase=loader-ready-contained job_empty=false",
        "phase=unclassified profile_child_cleanup=[job_empty_after_cleanup=false]",
        "phase=unclassified job_empty=true profile_child_cleanup=[job_empty_after_cleanup=false]",
        "phase=unclassified profile_child_cleanup=[job_empty_before_termination=true]",
        "phase=unclassified",
    ] {
        assert!(
            !loader_control_cell_job_empty_attested_for_test(detail),
            "unverified terminal Job state was admitted: {detail}",
        );
    }
}

#[test]
fn restricting_sid_presence_classification_is_fail_closed_and_exhaustive() {
    use LoaderObjectSecurityOutcomeForTest::{Failed, Passed};

    let dll_init = Failed {
        native: 0xc000_0142_u32 as i32,
        phase: "unclassified",
    };
    assert_eq!(
        classify_loader_restriction_presence_for_test(dll_init, Passed, true),
        "restricting-sid-presence-causal",
    );
    assert_eq!(
        classify_loader_restriction_presence_for_test(dll_init, dll_init, true),
        "classified-common-failure",
    );
    assert_eq!(
        classify_loader_restriction_presence_for_test(
            dll_init,
            Failed {
                native: 5,
                phase: "unclassified",
            },
            true,
        ),
        "differing-inconclusive",
    );
    assert_eq!(
        classify_loader_restriction_presence_for_test(
            dll_init,
            Failed {
                native: 0xc000_0142_u32 as i32,
                phase: "different-frontier",
            },
            true,
        ),
        "differing-inconclusive",
    );
    assert_eq!(
        classify_loader_restriction_presence_for_test(dll_init, Passed, false),
        "invalid",
    );
    assert_eq!(
        classify_loader_restriction_presence_for_test(Passed, dll_init, true),
        "invalid",
    );
    assert_eq!(
        classify_loader_restriction_presence_for_test(
            Failed {
                native: 5,
                phase: "unclassified",
            },
            Passed,
            true,
        ),
        "invalid",
    );
}

#[test]
fn restricting_sid_identity_classification_requires_the_decisive_third_sibling() {
    use LoaderObjectSecurityOutcomeForTest::{Failed, Passed};

    let dll_init = Failed {
        native: 0xc000_0142_u32 as i32,
        phase: "unclassified",
    };
    assert_eq!(
        classify_loader_restriction_identity_for_test(dll_init, Passed, Passed, true),
        "restricted-code-sid-narrowing-causal",
    );
    assert_eq!(
        classify_loader_restriction_identity_for_test(dll_init, Passed, dll_init, true),
        "restricted-token-or-canonical-inventory-causal",
    );
    for same_access in [
        Failed {
            native: 5,
            phase: "unclassified",
        },
        Failed {
            native: 0xc000_0142_u32 as i32,
            phase: "different-frontier",
        },
    ] {
        assert_eq!(
            classify_loader_restriction_identity_for_test(dll_init, Passed, same_access, true,),
            "differing-inconclusive",
        );
    }
    assert_eq!(
        classify_loader_restriction_identity_for_test(dll_init, dll_init, Passed, true),
        "classified-common-failure",
    );
    assert_eq!(
        classify_loader_restriction_identity_for_test(dll_init, Passed, Passed, false),
        "invalid",
    );
    assert_eq!(
        classify_loader_restriction_identity_for_test(Passed, Passed, Passed, true),
        "invalid",
    );
}

#[test]
fn target_logon_sid_classification_requires_a_passed_canonical_control() {
    use LoaderObjectSecurityOutcomeForTest::{Failed, Passed};

    let dll_init = Failed {
        native: 0xc000_0142_u32 as i32,
        phase: "unclassified",
    };
    assert_eq!(
        classify_loader_restriction_logon_for_test(dll_init, Passed, Passed, Passed, true),
        "restricted-code-sid-narrowing-logon-ceiling-compatible",
    );
    assert_eq!(
        classify_loader_restriction_logon_for_test(dll_init, Passed, Passed, dll_init, true),
        "canonical-broader-group-or-union-required",
    );
    for logon in [
        Failed {
            native: 5,
            phase: "unclassified",
        },
        Failed {
            native: 0xc000_0142_u32 as i32,
            phase: "different-frontier",
        },
    ] {
        assert_eq!(
            classify_loader_restriction_logon_for_test(dll_init, Passed, Passed, logon, true),
            "differing-inconclusive",
        );
    }
    assert_eq!(
        classify_loader_restriction_logon_for_test(dll_init, Passed, dll_init, Passed, true),
        "restricted-token-or-canonical-inventory-causal",
    );
    assert_eq!(
        classify_loader_restriction_logon_for_test(dll_init, dll_init, Passed, Passed, true),
        "classified-common-failure",
    );
    assert_eq!(
        classify_loader_restriction_logon_for_test(dll_init, Passed, Passed, Passed, false),
        "invalid",
    );
}

#[test]
fn authenticated_users_singleton_classification_preserves_the_distinct_logon_failure() {
    use LoaderObjectSecurityOutcomeForTest::{Failed, Passed};

    let dll_init = Failed {
        native: 0xc000_0142_u32 as i32,
        phase: "unclassified",
    };
    let access_denied = Failed {
        native: 0xc000_0022_u32 as i32,
        phase: "unclassified",
    };
    assert_eq!(
        classify_loader_restriction_authenticated_users_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            Passed,
            true,
        ),
        "authenticated-users-restriction-compatible-logon-too-narrow",
    );
    for authenticated_users in [dll_init, access_denied] {
        assert_eq!(
            classify_loader_restriction_authenticated_users_for_test(
                dll_init,
                Passed,
                Passed,
                access_denied,
                authenticated_users,
                true,
            ),
            "canonical-group-union-or-other-trustee-required",
        );
    }
    assert_eq!(
        classify_loader_restriction_authenticated_users_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            Failed {
                native: 5,
                phase: "unclassified",
            },
            true,
        ),
        "authenticated-users-inconclusive",
    );
    assert_eq!(
        classify_loader_restriction_authenticated_users_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            Failed {
                native: 0xc000_0022_u32 as i32,
                phase: "different-frontier",
            },
            true,
        ),
        "authenticated-users-inconclusive",
        "a different E phase must not be conflated with D's access-denied frontier",
    );
    assert_eq!(
        classify_loader_restriction_authenticated_users_for_test(
            dll_init, Passed, Passed, Passed, Passed, true,
        ),
        "authenticated-users-inconclusive",
        "E must not reinterpret a passing D as a logon-only ceiling failure",
    );
    assert_eq!(
        classify_loader_restriction_authenticated_users_for_test(
            dll_init,
            Passed,
            dll_init,
            access_denied,
            Passed,
            true,
        ),
        "authenticated-users-inconclusive",
    );
    assert_eq!(
        classify_loader_restriction_authenticated_users_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            Passed,
            false,
        ),
        "invalid",
    );
}

#[test]
fn target_user_singleton_classifier_requires_the_exact_admitted_frontier() {
    use LoaderObjectSecurityOutcomeForTest::{Failed, Passed};

    let dll_init = Failed {
        native: 0xc000_0142_u32 as i32,
        phase: "unclassified",
    };
    let access_denied = Failed {
        native: 0xc000_0022_u32 as i32,
        phase: "unclassified",
    };
    assert_eq!(
        classify_loader_restriction_target_user_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            access_denied,
            Passed,
            true,
        ),
        "target-user-restriction-bootstrap-compatible-group-singletons-too-narrow",
    );
    assert_eq!(
        classify_loader_restriction_target_user_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            access_denied,
            access_denied,
            true,
        ),
        "no-tested-singleton-sufficient-trace-required",
    );
    assert_eq!(
        classify_loader_restriction_target_user_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            access_denied,
            dll_init,
            true,
        ),
        "target-user-singleton-a-like-failure",
    );
    for state in [
        classify_loader_restriction_target_user_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            Failed {
                native: 0xc000_0022_u32 as i32,
                phase: "different",
            },
            Passed,
            true,
        ),
        classify_loader_restriction_target_user_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            access_denied,
            Failed {
                native: 5,
                phase: "unclassified",
            },
            true,
        ),
        classify_loader_restriction_target_user_for_test(
            dll_init,
            Passed,
            Failed {
                native: 0xc000_0142_u32 as i32,
                phase: "unclassified",
            },
            access_denied,
            access_denied,
            Passed,
            true,
        ),
    ] {
        assert_eq!(state, "target-user-singleton-inconclusive");
    }
    assert_eq!(
        classify_loader_restriction_target_user_for_test(
            dll_init,
            Passed,
            Passed,
            access_denied,
            access_denied,
            Passed,
            false,
        ),
        "invalid",
    );
}

#[test]
fn target_logon_sid_diagnostic_is_redacted_contained_and_nonpromoting() {
    let primary = "primary raw token=0x1234 SID=S-1-5-12 profile=C:\\private";
    let comparison = "comparison raw environment=SECRET handle=0x5678";
    let same_access = "same-access raw token=0x9abc PRIVATE=canonical-secret";
    let logon = "logon raw SID=S-1-5-5-7-11 LOGON_SECRET=credential";
    let diagnostic = render_loader_restriction_logon_canary_for_test(
        "restricted-code-sid-narrowing-logon-ceiling-compatible",
        primary,
        comparison,
        same_access,
        logon,
    );
    for required in [
        "loader_restriction_presence_prerequisite_canary=v2",
        "state=restricted-code-sid-narrowing-logon-ceiling-compatible",
        "identity_state=restricted-code-sid-narrowing-causal",
        "logon_semantics=privilege-disabled/target-logon-SID-restricted",
        "logon_restriction_binding_sha256=",
        "after_same_access_scan=ok",
        "after_same_access_metadata_match=true",
        "after_logon_scan=ok",
        "after_logon_metadata_match=true",
        "shared_environment_stable=true",
        "shared_environment_destroyed=true",
        "environment_values_redacted=true",
        "token_values_redacted=true",
        "job_empty=true",
        "workload_executed=false",
        "qualification_promoted=false",
    ] {
        assert!(diagnostic.contains(required), "missing {required}");
    }
    for forbidden in [
        primary,
        comparison,
        same_access,
        logon,
        "S-1-5-12",
        "S-1-5-5-7-11",
        "SECRET",
        "canonical-secret",
        "credential",
    ] {
        assert!(!diagnostic.contains(forbidden));
    }
}

#[test]
fn authenticated_users_singleton_diagnostic_is_redacted_bounded_and_nonpromoting() {
    let primary = "primary raw token=0x1234 SID=S-1-5-12 profile=C:\\private";
    let comparison = "comparison raw environment=SECRET handle=0x5678";
    let same_access = "same-access raw token=0x9abc PRIVATE=canonical-secret";
    let logon = "logon raw SID=S-1-5-5-7-11 LOGON_SECRET=credential";
    let authenticated_users = "E raw SID=S-1-5-11 AUTHENTICATED_USERS_SECRET=member";
    let diagnostic = render_loader_restriction_authenticated_users_canary_for_test(
        "authenticated-users-restriction-compatible-logon-too-narrow",
        primary,
        comparison,
        same_access,
        logon,
        authenticated_users,
    );
    for required in [
        "loader_restriction_presence_prerequisite_canary=v2",
        "state=authenticated-users-restriction-compatible-logon-too-narrow",
        "identity_state=restricted-code-sid-narrowing-causal",
        "logon_state=differing-inconclusive",
        "authenticated_users_semantics=privilege-disabled/authenticated-users-SID-restricted",
        "authenticated_users_restriction_binding_sha256=",
        "after_logon_scan=ok",
        "after_authenticated_users_scan=ok",
        "after_authenticated_users_metadata_match=true",
        "shared_environment_stable=true",
        "shared_environment_destroyed=true",
        "environment_values_redacted=true",
        "token_values_redacted=true",
        "job_empty=true",
        "workload_executed=false",
        "qualification_promoted=false",
    ] {
        assert!(diagnostic.contains(required), "missing {required}");
    }
    for forbidden in [
        primary,
        comparison,
        same_access,
        logon,
        authenticated_users,
        "S-1-5-12",
        "S-1-5-5-7-11",
        "S-1-5-11",
        "SECRET",
        "canonical-secret",
        "credential",
        "member",
        "exact_resource",
        "production_ready",
    ] {
        assert!(!diagnostic.contains(forbidden));
    }
}

#[test]
fn target_user_singleton_diagnostic_is_redacted_bounded_and_nonpromoting() {
    let primary = "A raw token=0x1234 SID=S-1-5-12 profile=C:\\private";
    let comparison = "B raw environment=SECRET handle=0x5678";
    let same_access = "C raw canonical=PRIVATE-CONTENT";
    let logon = "D raw SID=S-1-5-5-7-11 LOGON_SECRET=credential";
    let authenticated_users = "E raw SID=S-1-5-11 AU_SECRET=member";
    let target_user = "F raw SID=S-1-5-21-1-2-3-1001 USER_SECRET=identity";
    let diagnostic = render_loader_restriction_target_user_canary_for_test(
        "target-user-restriction-bootstrap-compatible-group-singletons-too-narrow",
        primary,
        comparison,
        same_access,
        logon,
        authenticated_users,
        target_user,
    );
    for required in [
        "loader_restriction_presence_prerequisite_canary=v2",
        "state=target-user-restriction-bootstrap-compatible-group-singletons-too-narrow",
        "authenticated_users_state=canonical-group-union-or-other-trustee-required",
        "target_user_semantics=privilege-disabled/target-user-SID-restricted",
        "target_user_restriction_binding_sha256=",
        "after_authenticated_users_scan=ok",
        "after_target_user_scan=ok",
        "after_target_user_metadata_match=true",
        "shared_environment_stable=true",
        "shared_environment_destroyed=true",
        "environment_values_redacted=true",
        "token_values_redacted=true",
        "job_empty=true",
        "workload_executed=false",
        "qualification_promoted=false",
    ] {
        assert!(diagnostic.contains(required), "missing {required}");
    }
    for forbidden in [
        primary,
        comparison,
        same_access,
        logon,
        authenticated_users,
        target_user,
        "S-1-5-12",
        "S-1-5-5-7-11",
        "S-1-5-11",
        "S-1-5-21-1-2-3-1001",
        "SECRET",
        "PRIVATE-CONTENT",
        "credential",
        "member",
        "USER_SECRET=identity",
        "exact_resource",
        "production_ready",
    ] {
        assert!(!diagnostic.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn restricting_sid_presence_diagnostic_is_redacted_contained_and_nonpromoting() {
    let primary = "primary raw token=0x1234 SID=S-1-5-12 profile=C:\\private";
    let comparison = "comparison raw environment=SECRET handle=0x5678";
    let same_access = "same-access raw token=0x9abc PRIVATE=canonical-secret";
    let diagnostic = render_loader_restriction_presence_canary_for_test(
        "restricted-code-sid-narrowing-causal",
        primary,
        comparison,
        same_access,
    );

    for required in [
        "loader_restriction_presence_prerequisite_canary=v2",
        "state=restricted-code-sid-narrowing-causal",
        "presence_state=restricting-sid-presence-causal",
        "baseline_semantics=full-restricted",
        "comparison_semantics=privilege-disabled/no-restricting-SID",
        "same_access_semantics=privilege-disabled/canonical-same-access-restricted",
        "differing_fields=[restricting_sid_inventory,token_is_restricted,token_instance_ids]",
        "failed_common_fields=[]",
        "restriction_identity_binding_sha256=",
        "shared_environment_profile_loaded=true",
        "after_baseline_scan=ok",
        "after_baseline_metadata_match=true",
        "after_baseline_observation_sha256=none",
        "after_comparison_scan=ok",
        "after_comparison_metadata_match=true",
        "after_comparison_observation_sha256=none",
        "shared_environment_scan=ok",
        "shared_environment_metadata_match=true",
        "shared_environment_observation_sha256=none",
        "shared_environment_stable=true",
        "shared_environment_destroyed=true",
        "environment_values_redacted=true",
        "token_values_redacted=true",
        "job_empty=true",
        "workload_executed=false",
        "qualification_promoted=false",
    ] {
        assert!(diagnostic.contains(required), "missing {required}");
    }
    assert!(!diagnostic.contains(primary));
    assert!(!diagnostic.contains(comparison));
    assert!(!diagnostic.contains(same_access));
    assert!(!diagnostic.contains("S-1-5-12"));
    assert!(!diagnostic.contains("SECRET"));
    assert!(!diagnostic.contains("canonical-secret"));
    assert!(!diagnostic.contains("unrestricted"));

    let digests = diagnostic
        .split("_sha256=")
        .skip(1)
        .map(|tail| tail.split_whitespace().next().unwrap())
        .filter(|digest| *digest != "none")
        .collect::<Vec<_>>();
    assert_eq!(digests.len(), 6);
    for digest in digests {
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn restricting_sid_pair_requires_one_byte_identical_attested_environment() {
    let environment = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=baseline",
        "windir=C:\\Windows",
    ]);
    assert!(
        loader_shared_environment_pair_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            true,
        )
        .unwrap()
    );

    let changed_value = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=comparison",
        "windir=C:\\Windows",
    ]);
    let changed_key = test_environment(&[
        "EXTRA=value",
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=baseline",
        "windir=C:\\Windows",
    ]);
    let missing_required = test_environment(&["SystemRoot=C:\\Windows", "TEMP=baseline"]);
    let malformed = [b'N' as u16, b'A' as u16, b'M' as u16, b'E' as u16, 0, 0];
    for (baseline, comparison, after_baseline, after_comparison, destroyed) in [
        (
            &environment[..],
            &changed_value[..],
            &environment[..],
            &environment[..],
            true,
        ),
        (
            &environment[..],
            &changed_key[..],
            &environment[..],
            &environment[..],
            true,
        ),
        (
            &environment[..],
            &environment[..],
            &changed_value[..],
            &environment[..],
            true,
        ),
        (
            &environment[..],
            &environment[..],
            &environment[..],
            &changed_value[..],
            true,
        ),
        (
            &environment[..],
            &environment[..],
            &environment[..],
            &environment[..],
            false,
        ),
        (
            &missing_required[..],
            &missing_required[..],
            &missing_required[..],
            &missing_required[..],
            true,
        ),
        (
            &environment[..],
            &environment[..],
            &malformed[..],
            &environment[..],
            true,
        ),
    ] {
        assert!(
            !loader_shared_environment_pair_valid_for_test(
                &environment,
                baseline,
                comparison,
                after_baseline,
                after_comparison,
                destroyed,
            )
            .unwrap(),
            "shared environment mutation or incomplete destruction was admitted",
        );
    }

    assert!(
        loader_shared_environment_pair_valid_for_test(
            &malformed,
            &environment,
            &environment,
            &environment,
            &environment,
            true,
        )
        .is_err(),
        "an invalid admitted inventory must fail closed",
    );
}

#[test]
fn restricting_sid_triplet_requires_every_borrow_and_rescan_to_match() {
    let environment = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=shared",
        "windir=C:\\Windows",
    ]);
    assert!(
        loader_shared_environment_triplet_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            true,
        )
        .unwrap(),
    );

    let changed = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=changed",
        "windir=C:\\Windows",
    ]);
    for changed_index in 0..6 {
        let mut observations = [
            &environment[..],
            &environment[..],
            &environment[..],
            &environment[..],
            &environment[..],
            &environment[..],
        ];
        observations[changed_index] = &changed;
        assert!(
            !loader_shared_environment_triplet_valid_for_test(
                &environment,
                observations[0],
                observations[1],
                observations[2],
                observations[3],
                observations[4],
                observations[5],
                true,
            )
            .unwrap(),
            "shared environment mutation at triplet checkpoint {changed_index} was admitted",
        );
    }
    assert!(
        !loader_shared_environment_triplet_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            false,
        )
        .unwrap(),
        "the triplet admitted an environment that was not explicitly destroyed",
    );
}

#[test]
fn target_logon_quad_requires_every_borrow_and_rescan_to_match() {
    let environment = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=shared",
        "windir=C:\\Windows",
    ]);
    assert!(
        loader_shared_environment_quad_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            true,
        )
        .unwrap(),
    );
    let changed = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=changed",
        "windir=C:\\Windows",
    ]);
    for changed_index in 0..8 {
        let mut observations = [&environment[..]; 8];
        observations[changed_index] = &changed;
        assert!(
            !loader_shared_environment_quad_valid_for_test(
                &environment,
                observations[0],
                observations[1],
                observations[2],
                observations[3],
                observations[4],
                observations[5],
                observations[6],
                observations[7],
                true,
            )
            .unwrap(),
            "shared environment mutation at four-way checkpoint {changed_index} was admitted",
        );
    }
    assert!(
        !loader_shared_environment_quad_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            false,
        )
        .unwrap(),
        "the four-way diagnostic admitted an owner that was not explicitly destroyed",
    );
}

#[test]
fn authenticated_users_quint_requires_every_borrow_and_rescan_to_match() {
    let environment = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=shared",
        "windir=C:\\Windows",
    ]);
    assert!(
        loader_shared_environment_quint_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            true,
        )
        .unwrap(),
    );
    let changed = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=changed",
        "windir=C:\\Windows",
    ]);
    for changed_index in 0..10 {
        let mut observations = [&environment[..]; 10];
        observations[changed_index] = &changed;
        assert!(
            !loader_shared_environment_quint_valid_for_test(
                &environment,
                observations[0],
                observations[1],
                observations[2],
                observations[3],
                observations[4],
                observations[5],
                observations[6],
                observations[7],
                observations[8],
                observations[9],
                true,
            )
            .unwrap(),
            "shared environment mutation at five-way checkpoint {changed_index} was admitted",
        );
    }
    assert!(
        !loader_shared_environment_quint_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            false,
        )
        .unwrap(),
        "the five-way diagnostic admitted an owner that was not explicitly destroyed",
    );
}

#[test]
fn target_user_sext_requires_every_borrow_and_rescan_to_match() {
    let environment = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=shared",
        "windir=C:\\Windows",
    ]);
    assert!(
        loader_shared_environment_sext_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            true,
        )
        .unwrap(),
    );
    let changed = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=changed",
        "windir=C:\\Windows",
    ]);
    for changed_index in 0..12 {
        let mut observations = [&environment[..]; 12];
        observations[changed_index] = &changed;
        assert!(
            !loader_shared_environment_sext_valid_for_test(
                &environment,
                observations[0],
                observations[1],
                observations[2],
                observations[3],
                observations[4],
                observations[5],
                observations[6],
                observations[7],
                observations[8],
                observations[9],
                observations[10],
                observations[11],
                true,
            )
            .unwrap(),
            "shared environment mutation at six-way checkpoint {changed_index} was admitted",
        );
    }
    assert!(
        !loader_shared_environment_sext_valid_for_test(
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            &environment,
            false,
        )
        .unwrap(),
        "the six-way diagnostic admitted an owner that was not explicitly destroyed",
    );
}

#[test]
fn full_observer_octet_keeps_one_environment_owner_through_debug_c_and_debug_f() {
    let environment = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=shared",
        "windir=C:\\Windows",
    ]);
    assert!(
        loader_shared_environment_octet_valid_for_test(&environment, [&environment; 16], true,)
            .unwrap(),
    );
    let changed = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "TEMP=debug-mutated",
        "windir=C:\\Windows",
    ]);
    for changed_index in 0..16 {
        let mut observations = [&environment[..]; 16];
        observations[changed_index] = &changed;
        assert!(
            !loader_shared_environment_octet_valid_for_test(&environment, observations, true)
                .unwrap(),
            "shared environment mutation at eight-way checkpoint {changed_index} was admitted",
        );
    }
    assert!(
        !loader_shared_environment_octet_valid_for_test(&environment, [&environment; 16], false,)
            .unwrap(),
        "the eight-cell diagnostic admitted an owner without its sole final destruction",
    );

    assert!(
        loader_full_observer_debug_f_gate_for_test(true, &environment, &environment).unwrap(),
        "a stable post-debug-C scan did not permit the already-authorized fallback",
    );
    assert!(
        !loader_full_observer_debug_f_gate_for_test(false, &environment, &environment).unwrap(),
        "the environment scan widened fallback authority",
    );
    assert!(
        !loader_full_observer_debug_f_gate_for_test(true, &environment, &changed).unwrap(),
        "debug F was permitted after debug C changed the shared environment",
    );
}

#[test]
fn restricting_sid_pair_distinguishes_redacted_mismatch_from_scan_error() {
    let admitted = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "PRIVATE=baseline-secret",
        "windir=C:\\Windows",
    ]);
    let changed = test_environment(&[
        "SystemDrive=C:",
        "SystemRoot=C:\\Windows",
        "PRIVATE=comparison-secret",
        "windir=C:\\Windows",
    ]);
    let mismatch = render_loader_shared_environment_observation_for_test(
        &admitted,
        &changed,
        "after-comparison",
    )
    .unwrap();
    assert!(mismatch.contains("shared_environment_scan=ok"));
    assert!(mismatch.contains("shared_environment_metadata_match=false"));
    assert_observation_digest_is_redacted(&mismatch);

    let malformed = [b'N' as u16, b'A' as u16, b'M' as u16, b'E' as u16, 0, 0];
    let scan_error = render_loader_shared_environment_observation_for_test(
        &admitted,
        &malformed,
        "after-baseline",
    )
    .unwrap();
    assert!(scan_error.contains("shared_environment_scan=error"));
    assert!(scan_error.contains("shared_environment_metadata_match=false"));
    assert_observation_digest_is_redacted(&scan_error);

    for forbidden in [
        "baseline-secret",
        "comparison-secret",
        "PRIVATE",
        "after-comparison",
        "after-baseline",
        "separator",
    ] {
        assert!(!mismatch.contains(forbidden));
        assert!(!scan_error.contains(forbidden));
    }
}

#[test]
fn full_observer_octet_borrows_one_owned_environment_sequentially() {
    let process = normalized_source(include_str!(
        "../../src/bin/memcordon-sealed-agent/windows/process.rs"
    ));
    let canary = source_region(
        &process,
        "fn loader_restriction_presence_prerequisite_canary_diagnostic(",
        "#[cfg(test)]",
    );
    assert_eq!(
        canary
            .matches("OwnedUserEnvironmentBlock::create(tokens.baseline.raw())")
            .count(),
        1,
    );
    assert_eq!(
        canary
            .matches("launch_target_desktop_loader_control_cell_with_shared_environment(")
            .count(),
        8,
    );
    assert_ordered(
        canary,
        &[
            "validate_transferred_loader_restriction_presence_pair(",
            "let comparison_snapshot = match super::token::token_attestation_snapshot(",
            "loader_restriction_identity_sibling_from_presence_comparison(",
            "loader_logon_restriction_sibling_from_identity_comparison(",
            "loader_authenticated_users_restriction_sibling_from_logon_comparison(",
            "loader_target_user_restriction_sibling_from_authenticated_users_comparison(",
            "let mut shared_environment =",
            "let admitted_environment =",
            "let baseline = launch_target_desktop_loader_control_cell_with_shared_environment(",
            "tokens.baseline.raw(),",
            "let after_baseline_environment = shared_environment.inventory();",
            "let after_baseline_observation = shared_environment_observation(",
            "if !after_baseline_observation.stable() {",
            "let comparison = launch_target_desktop_loader_control_cell_with_shared_environment(",
            "tokens.no_restricting_sid.raw(),",
            "let after_comparison_environment = shared_environment.inventory();",
            "let after_comparison_observation = shared_environment_observation(",
            "if !after_comparison_observation.stable() {",
            "let same_access = launch_target_desktop_loader_control_cell_with_shared_environment(",
            "same_access_restricted.raw(),",
            "let after_same_access_environment = shared_environment.inventory();",
            "let after_same_access_observation = shared_environment_observation(",
            "if !after_same_access_observation.stable() {",
            "let logon = launch_target_desktop_loader_control_cell_with_shared_environment(",
            "logon_restricted.raw(),",
            "let after_logon_environment = shared_environment.inventory();",
            "let after_logon_observation = shared_environment_observation(",
            "if !after_logon_observation.stable() {",
            "let authenticated_users = launch_target_desktop_loader_control_cell_with_shared_environment(",
            "authenticated_users_restricted.raw(),",
            "let after_authenticated_users_environment = shared_environment.inventory();",
            "let after_authenticated_users_observation = shared_environment_observation(",
            "if !after_authenticated_users_observation.stable() {",
            "let target_user = launch_target_desktop_loader_control_cell_with_shared_environment(",
            "target_user_restricted.raw(),",
            "let after_target_user_environment = shared_environment.inventory();",
            "let after_target_user_observation = shared_environment_observation(",
            "let original_environment_stable = after_baseline_observation.stable()",
            "let full_observer_fallback_allowed = original_reproduction_valid",
            "let debug_pair = if full_observer_fallback_allowed {",
            "let debug_c = launch_target_desktop_loader_control_cell_with_shared_environment(",
            "let after_debug_c_environment = shared_environment.inventory();",
            "let after_debug_c_observation = shared_environment_observation(",
            "if loader_full_observer_debug_f_allowed(",
            "let result = launch_target_desktop_loader_control_cell_with_shared_environment(",
            "let after_environment = shared_environment.inventory();",
            "let after_observation = shared_environment_observation(",
            "let debug_environment_stable = match debug_pair.as_ref() {",
            "let environment_stable = original_environment_stable && debug_environment_stable;",
            "let environment_destruction = shared_environment.destroy_after_create();",
            "\"environment_sha256\",",
            "\"environment_keys_sha256\",",
            "\"environment_units\",",
            "\"environment_entries\",",
            "environment_values_redacted=true",
            "token_values_redacted=true",
            "workload_executed=false",
            "qualification_promoted=false",
        ],
    );
    assert!(canary.contains(
        "let common_field_names = [\n\"matrix_cell\",\n\"debug_mode\",\n\"environment_classification\",\n\"environment_sha256\",\n\"environment_keys_sha256\",\n\"environment_units\",\n\"environment_entries\",\n\"environment_profile_loaded\",\n\"source_authentication_id\",\n\"source_session_id\",\n\"desktop_sha256\",\n\"binary_sha256\",\n\"current_directory_sha256\",\n\"command_semantics_sha256\",\n\"command_dynamic_fields\",\n\"creation_flags\",\n\"job_membership_attested\",\n\"object_security_authority\",\n\"process_policy_sha256\",\n\"thread_policy_sha256\",\n\"process_object_live_sha256\",\n\"thread_object_live_sha256\",\n\"descriptor_readback\",\n];"
    ));
    assert_eq!(
        canary
            .matches("original_reproduction_valid,\noriginal_invariants_valid,")
            .count(),
        2,
        "both FullObserver receipt paths must preserve pre-debug A-F invariant provenance",
    );
    assert_eq!(
        canary
            .matches("original_reproduction_valid,\ninvariants_valid,")
            .count(),
        0,
        "post-debug aggregate invariants must not relabel original A-F provenance",
    );
    for forbidden in [
        "CreateEnvironmentBlock(",
        "LoaderLaunchEnvironmentV5::create(",
        "restricted_same_access_primary(tokens.baseline.raw())",
        "restricted_logon_sid_primary(",
        "restricted_authenticated_users_primary(",
        "restricted_target_user_primary(",
        "primary_without_restricting_sid_from_source(",
        "ptr::null_mut()",
        "TargetAwareProcess",
        "TargetAwareThread",
        "TargetAwareBoth",
        "SetSecurityInfo(",
        "SetKernelObjectSecurity(",
        "WindowsProviderRequestV1",
        "LoaderControlReleaseWrite",
    ] {
        assert!(
            !canary.contains(forbidden),
            "shared-environment FullObserver octet admitted {forbidden}",
        );
    }

    let storage = source_region(
        &process,
        "enum LoaderLaunchEnvironmentStorageV5<'a> {",
        "fn loader_environment_keys_sha256(keys: &[String]) -> String {",
    );
    assert_ordered(
        storage,
        &[
            "BorrowedUserenv(&'a mut OwnedUserEnvironmentBlock),",
            "fn borrowed_userenv(",
            "LoaderLaunchEnvironmentStorageV5::BorrowedUserenv(block) => block.pointer(),",
            "LoaderLaunchEnvironmentStorageV5::BorrowedUserenv(_) => Ok(()),",
        ],
    );
}

fn assert_observation_digest_is_redacted(diagnostic: &str) {
    assert!(diagnostic.contains("environment_values_redacted=true"));
    let digest = diagnostic
        .split_once("shared_environment_observation_sha256=")
        .unwrap()
        .1
        .split_whitespace()
        .next()
        .unwrap();
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

fn test_environment(entries: &[&str]) -> Vec<u16> {
    let mut units = Vec::new();
    for entry in entries {
        units.extend(entry.encode_utf16());
        units.push(0);
    }
    units.push(0);
    units
}

fn assert_canary_contract(diagnostic: &str, comparison_outcome: &str, comparison_native: &str) {
    assert!(diagnostic.starts_with("loader_init_prerequisite_canary=v1 baseline=["));
    let baseline = "restriction=full-restricted:outcome=failed:native=0xc0000142";
    let comparison = format!(
        "restriction=write-restricted:outcome={comparison_outcome}:native={comparison_native}"
    );
    let selected = format!("selected_failure=[{PRIMARY_FAILURE}]");
    let baseline_offset = diagnostic.find(baseline).unwrap();
    let comparison_offset = diagnostic.find(&comparison).unwrap();
    let selected_offset = diagnostic.find(&selected).unwrap();
    assert!(baseline_offset < comparison_offset);
    assert!(comparison_offset < selected_offset);

    let digests = diagnostic
        .split("detail_sha256=")
        .skip(1)
        .map(|tail| tail.split(':').next().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(digests.len(), 2);
    for digest in digests {
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

fn assert_qualification_loader_restriction_source_contract(
    token: &str,
    control: &str,
    launcher: &str,
    process: &str,
    core: &str,
) {
    let token = normalized_source(token);
    let control = normalized_source(control);
    let launcher = normalized_source(launcher);
    let process = normalized_source(process);
    let core = normalized_source(core);

    let lease = source_region(
        &token,
        "struct QualificationLoaderRestrictionSourceLease {",
        "static QUALIFICATION_LOADER_RESTRICTION_SOURCE:",
    );
    assert_ordered(
        lease,
        &[
            "scope: String,",
            "generation_sha256: String,",
            "owner: WindowsProcessIdentityV1,",
            "frontend: OwnedHandle,",
            "baseline: Option<OwnedHandle>,",
            "comparison: Option<OwnedHandle>,",
            "no_restricting_sid: Option<OwnedHandle>,",
            "profile: Option<OwnedHandle>,",
            "source_binding_sha256: String,",
            "pair_invariants_sha256: String,",
            "restriction_presence_binding_sha256: String,",
            "profile_binding_sha256: String,",
        ],
    );
    assert!(!lease.contains("source: OwnedHandle"));
    assert!(!lease.contains("source_token"));

    let guard_drop = source_region(
        &token,
        "impl Drop for QualificationLoaderRestrictionSourceGuard {",
        "pub(crate) fn install_qualification_loader_restriction_source(",
    );
    assert_ordered(
        guard_drop,
        &[
            "lease.scope == self.scope",
            "lease.generation_sha256 == self.generation_sha256",
            "lease.owner == self.owner",
            "if !matches {",
            "std::process::abort();",
            "slot.take();",
        ],
    );

    let install = source_region(
        &token,
        "pub(crate) fn install_qualification_loader_restriction_source(",
        "struct LoaderRestrictionPairInvariantsV1 {",
    );
    assert_ordered(
        install,
        &[
            "if !matches!(scope, \"direct\" | \"package\") {",
            "if generation.is_empty() {",
            "let generation_sha256 = super::record::digest(generation.as_bytes());",
            "process_identity(frontend.raw())? != *owner",
            "let snapshot = token_attestation_snapshot(source.raw())?;",
            "!snapshot.behavior.envelope.elevated",
            "snapshot.behavior.token_is_restricted",
            "!snapshot.behavior.restricting_sids.is_empty()",
            "let pair = loader_restriction_diagnostic_pair_from_source(source.raw())?;",
            "if pair.source_binding_sha256 != source_binding_sha256 {",
            "if slot.is_some() {",
            "scope: scope.to_owned(),",
            "generation_sha256: generation_sha256.clone(),",
            "owner: owner.clone(),",
            "frontend,",
            "baseline: Some(pair.baseline),",
            "comparison: Some(pair.comparison),",
            "no_restricting_sid: Some(pair.no_restricting_sid),",
            "profile: Some(pair.profile),",
            "source_binding_sha256,",
            "pair_invariants_sha256: pair.pair_invariants_sha256,",
            "restriction_presence_binding_sha256: pair.restriction_presence_binding_sha256,",
            "profile_binding_sha256: pair.profile_binding_sha256,",
        ],
    );
    for forbidden in [
        "OpenProcessToken(",
        "SetSecurityInfo(",
        "SetKernelObjectSecurity(",
        "MAXIMUM_ALLOWED",
    ] {
        assert!(
            !install.contains(forbidden),
            "lease install admitted {forbidden}"
        );
    }

    let builder = source_region(
        &token,
        "fn loader_restriction_diagnostic_pair_from_source(",
        "pub(crate) fn loader_restriction_diagnostic_pair_for_qualification(",
    );
    assert_ordered(
        builder,
        &[
            "const RESTRICTING_SID: &str = \"S-1-5-12\";",
            "let source_snapshot = token_attestation_snapshot(source)?;",
            "source_snapshot.behavior.token_is_restricted",
            "!source_snapshot.behavior.restricting_sids.is_empty()",
            "restricted_primary_for_source(source, DISABLE_MAX_PRIVILEGE, RESTRICTING_SID)?;",
            "let comparison = restricted_primary_for_source(",
            "DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,",
            "let no_restricting_sid =",
            "primary_without_restricting_sid_from_source(source, DISABLE_MAX_PRIVILEGE)?;",
            "validate_loader_restriction_diagnostic_pair(",
            "validate_loader_restriction_presence_pair(baseline.raw(), no_restricting_sid.raw())?;",
            "source_snapshot.lineage.authentication_id",
            "source_snapshot.lineage.originating_logon_session",
            "source_snapshot.lineage.user_sid",
            "source_snapshot.lineage.session_id",
            "loader_restriction_presence_binding_sha256(",
            "&source_binding_sha256,",
            "&baseline_snapshot,",
            "&no_restricting_sid_snapshot,",
            "no_restricting_sid,",
            "restriction_presence_binding_sha256,",
        ],
    );
    for forbidden in [
        "OpenProcessToken(",
        "SetSecurityInfo(",
        "SetKernelObjectSecurity(",
        "MAXIMUM_ALLOWED",
    ] {
        assert!(
            !builder.contains(forbidden),
            "pair builder admitted {forbidden}"
        );
    }

    let consume = source_region(
        &token,
        "pub(crate) fn loader_restriction_diagnostic_pair_for_qualification(",
        "pub(crate) fn validate_transferred_loader_restriction_diagnostic_pair(",
    );
    assert_ordered(
        consume,
        &[
            "qualification loader restriction source is unavailable",
            "if &lease.owner != owner {",
            "qualification loader restriction source owner does not match launch",
            "process_identity(lease.frontend.raw())? != lease.owner",
            "qualification loader restriction source process identity changed",
            ".baseline",
            ".as_ref()",
            "qualification loader restriction pair was already consumed",
            ".comparison",
            ".as_ref()",
            ".no_restricting_sid",
            ".as_ref()",
            "qualification loader no-restricting-SID sibling was already consumed",
            "validate_loader_restriction_diagnostic_pair(effective, baseline.raw(), comparison.raw())?;",
            "if observed_pair_invariants_sha256 != lease.pair_invariants_sha256 {",
            "validate_loader_restriction_presence_pair(baseline.raw(), no_restricting_sid.raw())?;",
            "if observed_restriction_presence_binding_sha256 != lease.restriction_presence_binding_sha256 {",
            "baseline: lease",
            ".baseline",
            ".take()",
            "comparison: lease.comparison.take()",
            "no_restricting_sid: lease.no_restricting_sid.take()",
            "restriction_presence_binding_sha256: lease.restriction_presence_binding_sha256.clone(),",
        ],
    );

    let qualification = source_region(
        &control,
        "fn qualification_session(public: HANDLE, scope: &str, challenge: &str) -> Result<(), String> {",
        "fn launch_client(",
    );
    assert_ordered(
        qualification,
        &[
            "let (source_token, envelope, source_frontend, owner) =",
            "if !envelope.elevated {",
            "let admission = super::record::reserve_qualification_admission_for(scope, owner.clone())?;",
            "let loader_restriction_source = super::token::install_qualification_loader_restriction_source(",
            "scope,",
            "challenge,",
            "&owner,",
            "source_token,",
            "source_frontend,",
            "WindowsProviderResponseV1::QualificationReady {",
            "WindowsProviderRequestV1::QualificationEnd { schema_version }",
            "drop(loader_restriction_source);",
            "drop(admission);",
        ],
    );

    let launch_gate = source_region(
        &control,
        "fn launch_client_inner(",
        "let request_bytes = serde_json::to_vec(&launch).map_err(|error| error.to_string())?;",
    );
    assert_ordered(
        launch_gate,
        &[
            "let qualification_in_progress = super::record::qualification_in_progress();",
            "if !super::record::qualification_allows(&before)? {",
            "let loader_restriction_canary = if qualification_in_progress",
            "TargetDesktopBootstrapRoleV1::LoaderControl",
            "is_exact_full_restricted_loader_canary_source(primary_token.raw())?",
            "loader_restriction_diagnostic_pair_for_qualification(",
            "&before,",
            "primary_token.raw(),",
        ],
    );
    assert!(!launch_gate.contains("OpenProcessToken("));

    let canary_handles = source_region(
        &core,
        "pub struct WindowsLoaderRestrictionCanaryHandlesV1 {",
        "pub struct WindowsLaunchBrokerRequestV1 {",
    );
    assert_ordered(
        canary_handles,
        &[
            "pub remote_baseline_token_handle: u64,",
            "pub remote_comparison_token_handle: u64,",
            "pub remote_no_restricting_sid_token_handle: u64,",
            "pub remote_profile_token_handle: u64,",
            "pub source_binding_sha256: String,",
            "pub pair_invariants_sha256: String,",
            "pub restriction_presence_binding_sha256: String,",
            "pub profile_binding_sha256: String,",
        ],
    );
    assert_eq!(canary_handles.matches("token_handle: u64,").count(), 4);
    assert!(!canary_handles.contains("source_token"));

    let no_restricting_sid_constructor = source_region(
        &token,
        "fn primary_without_restricting_sid_from_source(",
        "fn current_process_token() -> Result<OwnedHandle, String> {",
    );
    assert_ordered(
        no_restricting_sid_constructor,
        &[
            "CreateRestrictedToken(",
            "process_token,",
            "flags,",
            "0,",
            "ptr::null(),",
            "0,",
            "ptr::null(),",
            "0,",
            "ptr::null(),",
            "&raw mut restricted,",
        ],
    );

    let presence_validation = source_region(
        &token,
        "fn validate_loader_restriction_presence_pair(",
        "fn validate_loader_restriction_pair_invariants(",
    );
    assert_ordered(
        presence_validation,
        &[
            "let baseline_snapshot = token_attestation_snapshot(baseline)?;",
            "let no_restricting_sid_snapshot = token_attestation_snapshot(no_restricting_sid)?;",
            ".without_restricting_sid_inventory();",
            ".without_restricting_sid_inventory();",
            "if baseline_invariants != no_restricting_sid_invariants",
            "!token_has_exact_restricting_sid(",
            "RESTRICTED_CODE_SID,",
            "NORMALIZED_RESTRICTING_SID_ATTRIBUTES,",
            "!no_restricting_sid_inventory.trustees.is_empty()",
            "!no_restricting_sid_inventory.evidence.is_empty()",
            "enabled_sensitive_privilege_count",
            "enabled_sensitive_privilege_count",
        ],
    );

    let control_transfer = source_region(
        &control,
        "let remote_loader_restriction_canary = if let Some(pair) = &loader_restriction_canary {",
        "let broker = WindowsLaunchBrokerRequestV1 {",
    );
    assert_ordered(
        control_transfer,
        &[
            "raw: pair.baseline.raw(),",
            "role: \"loader-restriction-baseline-token\",",
            "raw: pair.comparison.raw(),",
            "role: \"loader-restriction-comparison-token\",",
            "raw: pair.no_restricting_sid.raw(),",
            "role: \"loader-no-restricting-sid-token\",",
            "raw: pair.profile.raw(),",
            "role: \"loader-profile-token\",",
            "remote_no_restricting_sid_token_handle: no_restricting_sid,",
            "restriction_presence_binding_sha256: pair.restriction_presence_binding_sha256.clone(),",
        ],
    );

    let launcher_adoption = source_region(
        &launcher,
        "let loader_restriction_canary_handles = request",
        "if request.attempt_id != expected_attempt_id",
    );
    assert_ordered(
        launcher_adoption,
        &[
            "OwnedHandle::new(pair.remote_baseline_token_handle as usize as HANDLE)?",
            "OwnedHandle::new(pair.remote_comparison_token_handle as usize as HANDLE)?",
            "OwnedHandle::new(pair.remote_no_restricting_sid_token_handle as usize as HANDLE)?",
            "OwnedHandle::new(pair.remote_profile_token_handle as usize as HANDLE)?",
            "pair.restriction_presence_binding_sha256.clone(),",
        ],
    );

    let transferred_tokens = source_region(
        &process,
        "pub(crate) struct LoaderRestrictionCanaryTokens {",
        "struct LoaderRestrictionCanaryOutcomeV1 {",
    );
    assert_ordered(
        transferred_tokens,
        &[
            "baseline: OwnedHandle,",
            "comparison: OwnedHandle,",
            "no_restricting_sid: OwnedHandle,",
            "profile: OwnedHandle,",
            "restriction_presence_binding_sha256: String,",
            "pub(crate) fn from_transferred(",
            "no_restricting_sid: OwnedHandle,",
            "restriction_presence_binding_sha256: String,",
            "validate_transferred_loader_restriction_diagnostic_pair(",
            "validate_transferred_loader_restriction_presence_pair(",
            "no_restricting_sid.raw(),",
            "&restriction_presence_binding_sha256,",
            "validate_transferred_loader_profile_capability(",
        ],
    );

    let public_requests = source_region(
        &core,
        "pub enum WindowsProviderRequestV1 {",
        "pub enum WindowsProviderResponseV1 {",
    );
    for forbidden in [
        "source_token_handle",
        "loader_restriction_source",
        "source_token_access",
        "no_restricting_sid_token_handle",
        "restriction_presence_binding_sha256",
    ] {
        assert!(!public_requests.contains(forbidden));
    }
}

fn normalized_source(source: &str) -> String {
    source
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n")
}

fn source_region<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source
        .find(start)
        .unwrap_or_else(|| panic!("source omitted region start: {start}"));
    let relative_end = source[start..]
        .find(end)
        .unwrap_or_else(|| panic!("source omitted region end: {end}"));
    &source[start..start + relative_end]
}

fn assert_ordered(source: &str, fragments: &[&str]) {
    let mut cursor = 0_usize;
    for fragment in fragments {
        let relative = source[cursor..]
            .find(fragment)
            .unwrap_or_else(|| panic!("source omitted ordered fragment: {fragment}"));
        cursor += relative + fragment.len();
    }
}
