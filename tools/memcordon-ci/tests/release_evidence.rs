#![recursion_limit = "256"]

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use memcordon_ci::release_evidence::{LINUX_SEALED_TESTS as LINUX_TESTS, collect_certification};
use memcordon_core::{
    AttemptHistory, AttemptKind, AttemptPhase, AttemptRecord, BackendCapabilityReport,
    BoundaryCapability, BoundaryClass, BoundaryMechanismEvidence, BoundaryQualificationReport,
    BoundaryRequirement, BudgetKindReport, BudgetTokenReport, ChildTermination, CleanupSummary,
    CredentialTransitionDisposition, DeadlinePolicyReport, DeadlineScope, EffectivePolicyReport,
    EffectiveRestartPolicyReport, InvocationReport, LaunchEvidence, LinuxSealedEvidenceV2,
    MemcordonReport, NativeArgument, PolicyEnvelopeReport, RequestedPolicyReport,
    RequestedRestartPolicyReport, RestartConditions, RestartDecisionRecord, RestartLimit,
    RestartSafetyProof, RestartSummary, RunOutcome, SupervisionAggregates, SupervisionExecution,
    SupervisionTerminal, ToolReport, WINDOWS_QUALIFICATION_SCHEMA_VERSION,
    WindowsQualificationReceiptV1,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

type ReportMutation = fn(&mut Value);

const WINDOWS_TESTS: &[&str] = &[
    "fresh_qualification_failure_rollback_is_repeatable",
    "package_install_verify_probe_and_same_version_upgrade",
    "stale_low_integrity_workspace_upgrade_and_uninstall_cleanup",
    "active_attempt_upgrade_and_uninstall_are_refused",
    "public_sealed_launch_preserves_status_and_native_evidence",
    "frontend_loss_retires_the_job_and_durable_record",
    "package_uninstall_leaves_no_provider_state",
    "deadline_memory_and_raw_ntstatus_are_preserved",
    "production_package_lifecycle_without_ci_fault_gate",
    "windows_target_token_identity",
    "windows_creation_time_job_list",
    "windows_exact_handle_manifest",
    "windows_job_policy_readback",
    "windows_caller_token_authentication",
    "windows_job_membership_readback",
    "windows_preauthorization_gate",
    "windows_recursive_provider_rejection",
    "windows_guardian_authority",
    "windows_active_process_accounting",
    "windows_relay_retirement",
    "windows_final_handle_ordering",
    "windows_sealed_mechanism_selection",
    "windows_native_archive_inventory",
    "windows_qualification_advertisement",
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
    let left_identity = "00".repeat(std::mem::size_of::<[u8; 16]>());
    let right_identity = "11".repeat(std::mem::size_of::<[u8; 16]>());
    json!({
        "schema_version": 2,
        "mechanism": "linux-pid-namespace-cgroup-v2",
        "commit": COMMIT,
        "result": "passed",
        "scenarios": LINUX_TESTS.iter().map(|name| json!({"name": name, "class": "lifecycle", "result": "passed"})).collect::<Vec<_>>(),
        "tests_run": LINUX_TESTS.len(),
        "tests_skipped": 0,
        "recovery_tests": [
            "sealed_recovery_removes_authenticated_stale_record_without_cgroup",
            "sealed_recovery_quarantines_cgroup_without_authenticated_record",
            "sealed_recovery_blocks_capability_while_live_state_is_ambiguous"
        ],
        "concurrency": {
            "schema_version": 2,
            "mechanism": "linux-pid-namespace-cgroup-v2",
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
        },
        "public_launch": public_launch_report()
    })
}

fn public_launch_report() -> Value {
    let provider_identity = "memcordon-sealed-agent-v2";
    let receipt_digest = "ab".repeat(32);
    let mechanism = "linux-pid-namespace-cgroup-v2";
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
            receipt_digest: receipt_digest.clone(),
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
        boundary_detail: BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2(
            LinuxSealedEvidenceV2 {
                schema_version: 2,
                provider_identity: provider_identity.to_owned(),
                control_service_identity: "memcordon-sealed-agent.service:v2".to_owned(),
                launcher_service_identity: "memcordon-sealed-launcher.service:v2".to_owned(),
                cgroup_identity_digest:
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
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
                    CredentialTransitionDisposition::PreserveCallerEnvelope,
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
    let report = MemcordonReport::schema8(
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

fn windows_qualification() -> WindowsQualificationReceiptV1 {
    let receipt = WindowsQualificationReceiptV1 {
        schema_version: WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        provider_identity: format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        ),
        control_service_identity: "MemCordonSealedControl:LocalService:restricted".to_owned(),
        launcher_service_identity: "MemCordonSealedLauncher:LocalSystem:restricted".to_owned(),
        guardian_pool_identity: "MemCordonSealedGuardian-000..007:LocalSystem:restricted:demand"
            .to_owned(),
        package_verified: true,
        public_pipe_security_verified: true,
        private_pipe_security_verified: true,
        control_service_privileges_verified: true,
        launcher_service_privileges_verified: true,
        guardian_slot_tokens_verified: true,
        guardian_slot_loader_verified: true,
        guardian_capacity_verified: true,
        caller_token_authentication_verified: true,
        restricted_caller_token_verified: true,
        primary_token_duplication_verified: true,
        create_process_as_user_verified: true,
        job_list_supported: true,
        handle_list_supported: true,
        nested_host_job_supported: true,
        kill_on_close_verified: true,
        breakaway_denied: true,
        completion_port_verified: true,
        guardian_verified: true,
        frontend_loss_cleanup_verified: true,
        alternate_token_child_contained: true,
        nested_child_job_contained: true,
        recursive_provider_request_denied: true,
        exact_handle_inheritance_verified: true,
        active_processes_zero_verified: true,
        relays_retired_verified: true,
        recovery_complete: true,
        loader_qualification: memcordon_core::WindowsLoaderQualificationOutcomeV2::Ready(
            memcordon_core::WindowsLoaderReadyEvidenceV1 {
                schema_version: 1,
                launch_plan_sha256: hex::encode(Sha256::digest(b"production-plan")),
                elapsed_millis: 1,
            },
        ),
        qualified: true,
    };
    assert!(receipt.qualified && receipt.is_consistent());
    receipt
}

fn windows_authority_loss() -> Value {
    json!({
        "schema_version": 1,
        "frontend_killed": true,
        "frontend_disconnected": true,
        "control_worker_lost": true,
        "control_service_lost": true,
        "launcher_worker_lost": true,
        "launcher_service_lost": true,
        "guardian_killed_before_authorization": true,
        "guardian_killed_after_authorization": true,
        "all_job_owners_closed": true,
        "durable_service_restart_recovered": true,
        "machine_restart_recovery_exercised": true,
        "active_processes_zero_after_each": true,
        "relays_retired_after_each": true,
        "records_retired_after_each": true
    })
}

fn windows_mutant_kills() -> Value {
    use memcordon_core::{WindowsMutantNativeObservationV1 as Native, WindowsSealedMutant as M};

    let digest_a = hex::encode(Sha256::digest(b"mutant-caller"));
    let digest_b = hex::encode(Sha256::digest(b"mutant-target"));
    json!({
        "schema_version": 1,
        "observations": memcordon_core::WINDOWS_RELEASE_MUTANT_VARIANTS
            .iter()
            .zip(memcordon_core::WINDOWS_RELEASE_MUTANTS)
            .map(|(mutant, (_, mapped_test))| json!({
                "mutant": mutant,
                "mapped_test": mapped_test,
                "native_observation": match mutant {
                    M::UseCreateProcessW => Native::TargetTokenMismatch {
                        creation_api: "create-process-w".to_owned(),
                        token_source: "launcher-service".to_owned(),
                        authenticated_envelope_sha256: digest_a.clone(),
                        target_envelope_sha256: digest_b.clone(),
                    },
                    M::CreateUnderServiceToken => Native::TargetTokenMismatch {
                        creation_api: "create-process-as-user-w".to_owned(),
                        token_source: "launcher-service".to_owned(),
                        authenticated_envelope_sha256: digest_a.clone(),
                        target_envelope_sha256: digest_b.clone(),
                    },
                    M::TrustClientToken => Native::TargetTokenMismatch {
                        creation_api: "create-process-as-user-w".to_owned(),
                        token_source: "authenticated-handle-untrusted-envelope".to_owned(),
                        authenticated_envelope_sha256: digest_a.clone(),
                        target_envelope_sha256: digest_b.clone(),
                    },
                    M::AssignJobAfterCreate => Native::CreationManifest {
                        used_create_process_as_user: true,
                        job_list_present: false,
                        handle_list_present: true,
                        post_create_job_assignment: true,
                        unexpected_handle_count: 0,
                    },
                    M::OmitJobList => Native::CreationManifest {
                        used_create_process_as_user: true,
                        job_list_present: false,
                        handle_list_present: true,
                        post_create_job_assignment: false,
                        unexpected_handle_count: 0,
                    },
                    M::SkipJobMembershipReadback => Native::ExternalJobMembershipMissing {
                        process_in_any_job: false,
                    },
                    M::OmitHandleList => Native::CreationManifest {
                        used_create_process_as_user: true,
                        job_list_present: true,
                        handle_list_present: false,
                        post_create_job_assignment: false,
                        unexpected_handle_count: 0,
                    },
                    M::PermitBreakaway => Native::JobLimitReadback { breakaway_allowed: true },
                    M::SkipTargetTokenReadback => Native::ExternalTargetTokenMismatch {
                        authenticated_envelope_sha256: digest_a.clone(),
                        target_envelope_sha256: digest_b.clone(),
                    },
                    M::ResumeBeforeGuardian => Native::PrematureAuthorization {
                        guardian_ready: false,
                        relays_ready: true,
                        target_marker_observed: true,
                    },
                    M::ResumeBeforeRelays => Native::PrematureAuthorization {
                        guardian_ready: true,
                        relays_ready: false,
                        target_marker_observed: true,
                    },
                    M::LeakJobHandleToTarget => Native::LeakedHandleObserved { kind: "job".to_owned() },
                    M::LeakLauncherPipe => Native::LeakedHandleObserved { kind: "pipe".to_owned() },
                    M::AcceptRecursiveProvider => Native::RecursiveLaunchAccepted,
                    M::OmitGuardian => Native::GuardianMissing,
                    M::AcceptCompletionWithoutAccounting => Native::CompletionAcceptedWithoutAccounting {
                        completion_zero_observed: true,
                        active_process_query_performed: false,
                    },
                    M::SuccessBeforeActiveZero => Native::SuccessBeforeActiveZero { active_processes: 1 },
                    M::SkipRelayAck => Native::RelayAckSkipped {
                        target_retired_sent: true,
                        relays_retired_received: false,
                    },
                    M::CloseJobBeforeEvidence => Native::EvidenceAfterFinalHandleClose {
                        final_handles_closed: true,
                        evidence_constructed_after_close: true,
                    },
                    M::FallBackToStandard => Native::PlatformRouteFallback {
                        ordinary_route_sealed: true,
                        mutant_route_standard: true,
                    },
                    M::OmitAgentFromArchive => Native::ArchiveInventoryOmission {
                        sealed_agent_removed: true,
                        configuration_rejected: true,
                    },
                    M::AdvertiseWithoutCertificate => Native::UnqualifiedAdvertisement {
                        ordinary_advertised: false,
                        mutant_advertised: true,
                    },
                }
            }))
            .collect::<Vec<_>>()
    })
}

fn windows_public_launch_report(qualification: &WindowsQualificationReceiptV1) -> Value {
    let mut value = public_launch_report();
    value["backend"]["name"] = json!("windows-job-object");
    value["backend"]["boundary"]["mechanism"] = json!("windows-job-object-v2");
    value["backend"]["boundary_qualification"]["provider_identity"] =
        json!(qualification.provider_identity);
    value["backend"]["boundary_qualification"]["receipt_digest"] =
        json!(hex::encode(Sha256::digest(
            serde_json::to_vec(qualification).expect("Windows qualification should serialize")
        )));
    value["backend"]["boundary_qualification"]["mechanism"] = json!("windows-job-object-v2");
    value["attempts"][0]["launch"]["mechanism"] = json!("windows-job-object-v2");
    value["attempts"][0]["boundary_detail"] = json!({
        "mechanism": "windows-job-object-v2",
        "schema_version": 2,
        "service_identity": "MemCordonSealedControl+MemCordonSealedLauncher:v1",
        "caller_token_authenticated": true,
        "initial_target_token_matches_caller": true,
        "credential_transition_disposition": "preserve-caller-envelope",
        "job_membership_independent_of_token": true,
        "job_created": true,
        "job_limits_verified": true,
        "kill_on_close_verified": true,
        "breakaway_denied": true,
        "completion_port_associated": true,
        "guardian_ready": true,
        "target_created_suspended": true,
        "job_list_applied_at_creation": true,
        "handle_list_applied_at_creation": true,
        "target_job_membership_verified": true,
        "target_still_suspended_during_verification": true,
        "inherited_handles_verified": true,
        "target_released": true,
        "terminate_job_invoked": true,
        "active_processes_zero": true,
        "direct_target_reaped": true,
        "relays_retired": true,
        "guardian_reaped": true,
        "final_job_handles_closed": true
    });
    let _: MemcordonReport = serde_json::from_value(value.clone())
        .expect("Windows public launch fixture should be consistent");
    value
}

fn windows_token_matrix() -> Value {
    let envelope = json!({
        "user_sid": "S-1-5-21-1",
        "owner_sid": "S-1-5-21-1",
        "primary_group_sid": "S-1-5-32-545",
        "groups_sha256": "01".repeat(32),
        "privileges_sha256": "02".repeat(32),
        "restricted_sids_sha256": "03".repeat(32),
        "integrity_level": "S-1-16-8192",
        "mandatory_policy": 1,
        "session_id": 1,
        "elevation_type": 2,
        "elevated": true,
        "virtualization_allowed": false,
        "virtualization_enabled": false,
        "ui_access": false,
        "appcontainer": false,
        "authentication_id": 1,
        "token_type": 1,
        "impersonation_level": 0
    });
    let scenarios = [
        "elevated-admin",
        "ordinary-user",
        "restricted",
        "write-restricted",
        "disabled-privileges",
        "deny-only-admin",
        "low-integrity",
    ]
    .into_iter()
    .map(|name| {
        let mut scenario_envelope = envelope.clone();
        if name != "elevated-admin" {
            scenario_envelope["token_type"] = json!(2);
            scenario_envelope["impersonation_level"] = json!(2);
        }
        if name == "ordinary-user" {
            scenario_envelope["elevated"] = json!(false);
            scenario_envelope["elevation_type"] = json!(3);
        }
        if name == "low-integrity" {
            scenario_envelope["integrity_level"] = json!("S-1-16-4096");
        }
        let restricted = matches!(
            name,
            "restricted"
                | "write-restricted"
                | "disabled-privileges"
                | "deny-only-admin"
                | "low-integrity"
        );
        let write_restricted = matches!(name, "write-restricted" | "disabled-privileges");
        let restricting_sids = if write_restricted {
            vec!["S-1-5-33"]
        } else if restricted {
            vec!["S-1-5-12"]
        } else {
            Vec::new()
        };
        json!({
            "name": name,
            "caller_envelope": scenario_envelope,
            "restricted_sid_count": u32::from(restricted),
            "restricting_sids": restricting_sids,
            "token_is_restricted": restricted,
            "write_restricted": write_restricted,
            "enabled_sensitive_privilege_count": if name == "disabled-privileges" { 0 } else { 1 },
            "administrator_deny_only": name == "deny-only-admin",
            "initial_target_token_matches_caller": true
        })
    })
    .collect::<Vec<_>>();
    json!({
        "schema_version": 2,
        "scenarios": scenarios,
        "appcontainer_rejected_before_target": true,
        "different_session_supported": true,
        "different_session_verified": true
    })
}

fn windows_report(
    architecture: &str,
    runner_label: &str,
    qualification: &WindowsQualificationReceiptV1,
) -> Value {
    json!({
        "schema": 2,
        "backend": "windows-job-object-v2",
        "certified": true,
        "commit": COMMIT,
        "runner_class": "ephemeral-certified",
        "runner_provider": "github-hosted",
        "runner_label": runner_label,
        "architecture": architecture,
        "native_archive_sha256": "12".repeat(32),
        "runtime_manifest_sha256": "34".repeat(32),
        "native_target": match architecture {
            "x86_64" => "x86_64-pc-windows-msvc",
            "aarch64" => "aarch64-pc-windows-msvc",
            _ => "unsupported",
        },
        "runtime": {
            "qualification": qualification,
            "public_launch": windows_public_launch_report(qualification),
            "fresh_install_rollback_verified": true,
            "active_attempt_upgrade_refused": true,
            "active_attempt_uninstall_refused": true,
            "frontend_loss_record_retired": true,
            "provider_state_removed": true,
            "status_matrix": windows_status_matrix()
        },
        "tests": tests(WINDOWS_TESTS),
        "tests_run": WINDOWS_TESTS.len(),
        "tests_skipped": 0
    })
}

fn windows_status_matrix() -> Value {
    let cleanup = memcordon_core::CleanupSummary {
        graceful_attempted: false,
        force_attempted: true,
        direct_child_reaped: true,
        workload_empty: Some(true),
        errors: Vec::new(),
    };
    let deadline = memcordon_core::RunOutcome::DeadlineExceeded {
        deadline: memcordon_core::DeadlineEvidence::new(
            100,
            memcordon_core::DeadlineScope::Attempt,
            "windows-qualification".to_owned(),
            100,
            100,
            0,
            0,
            None,
            Some("TerminateJobObject".to_owned()),
        )
        .expect("deadline evidence should be valid"),
        child_after_termination: Some(memcordon_core::ChildTermination::WindowsStatus {
            status: 0xC000_013A,
        }),
        peak: None,
        cleanup: cleanup.clone(),
    };
    let memory = memcordon_core::RunOutcome::LimitExceeded {
        limit: memcordon_core::ByteSize::from_bytes(8 * 1024 * 1024),
        observed: Some(memcordon_core::ByteSize::from_bytes(8 * 1024 * 1024)),
        peak: Some(memcordon_core::ByteSize::from_bytes(8 * 1024 * 1024)),
        evidence: memcordon_core::LimitEvidence {
            backend: "windows-job-object-v2".to_owned(),
            metric: "job-memory".to_owned(),
            detail: "completion-port plus accounting readback".to_owned(),
        },
        child_after_termination: Some(memcordon_core::ChildTermination::WindowsStatus {
            status: 0xC000_0017,
        }),
        cleanup: cleanup.clone(),
    };
    let ntstatus = memcordon_core::RunOutcome::Exited {
        child: memcordon_core::ChildTermination::WindowsStatus {
            status: 0xC000_013A,
        },
        peak: None,
        cleanup: cleanup.clone(),
    };
    let orphan = memcordon_core::RunOutcome::Exited {
        child: memcordon_core::ChildTermination::ExitCode { code: 0 },
        peak: None,
        cleanup,
    };
    json!({
        "schema_version": 1,
        "ordinary_exit_codes": (u8::MIN..=u8::MAX).map(u32::from).collect::<Vec<_>>(),
        "deadline_outcome": deadline,
        "memory_limit_outcome": memory,
        "raw_ntstatus_outcome": ntstatus,
        "orphan_descendant_outcome": orphan,
        "command_not_found": windows_spawn_error("MCSPAWN-NOT-FOUND", 2, "not-found"),
        "command_not_executable": windows_spawn_error("MCSPAWN-NOT-EXECUTABLE", 193, "not-executable"),
        "provider_setup_failure": windows_fault_rejection("job-create", false),
        "relay_failure": windows_fault_rejection("relay-retire", true),
        "terminal_truncation_rejected": true,
        "report_consistency_verified": true
    })
}

fn windows_fault_rejection(fault: &str, released: bool) -> Value {
    json!({
        "schema_version": 1,
        "code": "MCSEALED-WINDOWS-CERTIFICATION-FAULT",
        "phase": if fault == "job-create" { "boundary-creation" } else if released { "retirement" } else { "provider-connection" },
        "detail": format!("injected certification fault: {fault}"),
        "os_code": null,
        "target_created": released,
        "target_released": released,
        "cleanup_attempted": released,
        "restart_safety": if released {
            json!({
                "direct_child_reaped": true,
                "workload_empty": true,
                "helpers_reaped": true,
                "containment_removed": true,
                "containment_incapable_of_live_members": true,
                "sealed_boundary_retired": true,
                "errors": []
            })
        } else {
            json!({
                "direct_child_reaped": false,
                "workload_empty": null,
                "helpers_reaped": false,
                "containment_removed": false,
                "containment_incapable_of_live_members": false,
                "sealed_boundary_retired": false,
                "errors": []
            })
        }
    })
}

fn windows_fault_observations(faults: &[&str], released: bool) -> Vec<Value> {
    faults
        .iter()
        .map(|fault| {
            json!({
                "fault": fault,
                "rejection": windows_fault_rejection(fault, released)
            })
        })
        .collect()
}

fn windows_spawn_error(code: &str, os_code: i32, failure: &str) -> Value {
    json!({
        "category": "spawn",
        "code": code,
        "message": "native Windows spawn failure",
        "os_code": os_code,
        "attempt_number": 1,
        "supervision_phase": "attempt-setup",
        "launch_phase": "target-spawn-failed",
        "target_released": false,
        "workload_may_be_alive": false,
        "initial_spawn_failure": failure,
        "provider_rejection": null
    })
}

fn windows_package_inspection() -> Value {
    json!({
        "schema_version": 3,
        "version": env!("CARGO_PKG_VERSION"),
        "source_commit": COMMIT,
        "executable_sha256": "56".repeat(32),
        "provider_protocol": memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
        "mechanism": "windows-job-object-v2",
        "execution_report_schema": memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
        "plan_report_schema": memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
        "doctor_report_schema": memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
        "platform": "windows-service",
        "control_service_name": memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,
        "launcher_service_name": memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
        "session_broker_service_name": memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME,
        "guardian_slot_count": memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT,
        "control_service_config_sha256": "10".repeat(32),
        "launcher_service_config_sha256": "20".repeat(32),
        "session_broker_service_config_sha256": "22".repeat(32),
        "guardian_slot_config_sha256": "25".repeat(32),
        "control_pipe": memcordon_core::WINDOWS_CONTROL_PIPE,
        "launcher_pipe": memcordon_core::WINDOWS_LAUNCHER_PIPE,
        "session_broker_pipe": memcordon_core::WINDOWS_SESSION_BROKER_PIPE,
        "guardian_pipe_prefix": memcordon_core::WINDOWS_GUARDIAN_PIPE_PREFIX,
        "binary_install_path": r"C:\Program Files\MemCordon\memcordon-sealed-agent.exe",
        "target_desktop_bootstrap_install_path": r"C:\Program Files\MemCordon\memcordon-target-desktop-bootstrap.exe",
        "target_desktop_bootstrap_sha256": "57".repeat(32),
        "session_broker_install_path": r"C:\Program Files\MemCordon\memcordon-session-broker.exe",
        "session_broker_sha256": "58".repeat(32),
        "state_root": r"C:\ProgramData\MemCordon\sealed",
        "control_service_sid_type": "restricted",
        "launcher_service_sid_type": "restricted",
        "session_broker_service_sid_type": "unrestricted",
        "guardian_slot_service_sid_type": "restricted",
        "control_required_privileges": ["SeImpersonatePrivilege"],
        "launcher_required_privileges": [
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeTcbPrivilege"
        ],
        "session_broker_required_privileges": [
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeTcbPrivilege"
        ],
        "guardian_slot_required_privileges": [],
        "control_pipe_security_sha256": "30".repeat(32),
        "launcher_pipe_security_sha256": "40".repeat(32),
        "session_broker_service_security_sha256": "42".repeat(32),
        "session_broker_pipe_security_sha256": "43".repeat(32),
        "guardian_pipe_security_contract_sha256": "45".repeat(32),
        "install_directory_security_sha256": "50".repeat(32),
        "state_directory_security_sha256": "60".repeat(32),
        "compiled_metadata_valid": true
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

fn write_windows_artifact(input: &Path, id: &str, architecture: &str, runner_label: &str) {
    let directory = input.join(format!("release-windows-package-channel-{id}"));
    let evidence = directory.join("release-evidence");
    fs::create_dir_all(&evidence).expect("split Windows evidence directory should exist");
    let names = [
        "production-result.json",
        "production-manifest.json",
        "lifecycle-outcomes.json",
        "package-lifecycle.json",
        "cargo-rollback.json",
        "native-rollback.json",
        "cargo-fingerprint.json",
        "native-fingerprint.json",
        "launch-plan.json",
    ];
    let mut bindings = serde_json::Map::new();
    for name in names {
        let path = evidence.join(name);
        write_report(&path, &json!({"schema_version": 1, "name": name}));
        let bytes = fs::read(&path).expect("split Windows evidence should read");
        bindings.insert(
            name.to_owned(),
            Value::String(hex::encode(Sha256::digest(bytes))),
        );
    }
    let native_target = match architecture {
        "x86_64" => "x86_64-pc-windows-msvc",
        "aarch64" => "aarch64-pc-windows-msvc",
        _ => panic!("unsupported Windows fixture architecture"),
    };
    write_report(
        &directory.join("windows-release-certification.json"),
        &json!({
            "schema_version": 1,
            "backend": "windows-job-object-v2",
            "certified": true,
            "commit": COMMIT,
            "runner_class": "ephemeral-certified",
            "runner_provider": "github-hosted",
            "runner_label": runner_label,
            "architecture": architecture,
            "native_archive_sha256": "91".repeat(32),
            "runtime_manifest_sha256": "92".repeat(32),
            "native_target": native_target,
            "evidence_bindings": bindings,
        }),
    );
    write_legacy_windows_artifact(input, id, architecture, runner_label);
}

#[allow(dead_code)]
fn write_legacy_windows_artifact(input: &Path, id: &str, architecture: &str, runner_label: &str) {
    let directory = input.join(format!("release-certification-windows-{id}"));
    let qualification = windows_qualification();
    let qualification_value =
        serde_json::to_value(&qualification).expect("Windows qualification should serialize");
    let package = windows_package_inspection();
    write_report(&directory.join("windows-package-inspection.json"), &package);
    write_report(
        &directory.join("windows-installed-provider.json"),
        &json!({
            "schema_version": 3,
            "agent": package,
            "installed_executable_sha256": "56".repeat(32),
            "installed_artifacts_valid": true,
            "provider_identity": format!("memcordon-sealed-agent-windows-v1:{}", env!("CARGO_PKG_VERSION")),
            "provider_reachable": true,
            "qualification_complete": true
        }),
    );
    write_report(
        &directory.join("windows-qualification.json"),
        &qualification_value,
    );
    for (name, evidence) in [
        (
            "windows-token-envelope.json",
            json!({
                "service_identity": "MemCordonSealedControl+MemCordonSealedLauncher:v1",
                "caller_token_authenticated": true,
                "initial_target_token_matches_caller": true,
                "credential_transition_disposition": "preserve-caller-envelope",
                "restricted_caller_token_verified": true,
                "primary_token_duplication_verified": true,
                "token_matrix": windows_token_matrix()
            }),
        ),
        (
            "windows-handle-inventory.json",
            json!({
                "job_list_applied_at_creation": true,
                "handle_list_applied_at_creation": true,
                "inherited_handles_verified": true,
                "exact_handle_inheritance_verified": true,
                "relays_retired": true
            }),
        ),
        (
            "windows-preauthorization.json",
            json!({
                "guardian_ready": true,
                "target_created_suspended": true,
                "target_job_membership_verified": true,
                "target_still_suspended_during_verification": true,
                "target_released": true,
                "fault_matrix": {
                    "schema_version": 1,
                    "preauthorization": {
                        "schema_version": 1,
                        "faults": [
                            "public-pipe-create", "caller-pid-lookup",
                            "caller-token-impersonation", "primary-token-duplicate",
                            "private-pipe-connect", "launcher-peer-verify",
                            "token-handle-duplicate", "job-create", "job-configure",
                            "completion-port", "guardian-create",
                            "guardian-killed-before-authorization", "stream-create",
                            "relay-handle-duplicate", "relay-ready", "attribute-list",
                            "job-list", "handle-list", "create-process-as-user",
                            "target-token-readback", "job-membership-readback",
                            "before-resume", "resume"
                        ],
                        "first_instruction_markers_absent": true,
                        "recovery_clear_after_each_fault": true,
                        "terminal_frame_truncation_rejected": true,
                        "rejections": windows_fault_observations(&[
                            "public-pipe-create", "caller-pid-lookup",
                            "caller-token-impersonation", "primary-token-duplicate",
                            "private-pipe-connect", "launcher-peer-verify",
                            "token-handle-duplicate", "job-create", "job-configure",
                            "completion-port", "guardian-create",
                            "guardian-killed-before-authorization", "stream-create",
                            "relay-handle-duplicate", "relay-ready", "attribute-list",
                            "job-list", "handle-list", "create-process-as-user",
                            "target-token-readback", "job-membership-readback",
                            "before-resume", "resume"
                        ], false)
                    },
                    "retirement": {
                        "schema_version": 1,
                        "faults": [
                            "guardian-killed-after-authorization", "terminate-job",
                            "active-process-query", "relay-retire", "guardian-reap",
                            "final-handle-close", "record-retire"
                        ],
                        "first_instruction_markers_observed": true,
                        "recovery_clear_after_each_fault": true,
                        "rejections": windows_fault_observations(&[
                            "guardian-killed-after-authorization", "terminate-job",
                            "active-process-query", "relay-retire", "guardian-reap",
                            "final-handle-close", "record-retire"
                        ], true)
                    }
                },
                "mutant_kills": windows_mutant_kills()
            }),
        ),
        (
            "windows-alternate-token.json",
            json!({
                "alternate_token_child_contained": true,
                "initial_target_token_matches_caller": true,
                "job_membership_independent_of_token": true
            }),
        ),
        (
            "windows-nested-job.json",
            json!({
                "nested_host_job_supported": true,
                "nested_child_job_contained": true,
                "target_job_membership_verified": true
            }),
        ),
        (
            "windows-front-end-loss.json",
            json!({
                "frontend_loss_cleanup_verified": true,
                "record_retired": true,
                "active_processes_zero_verified": true,
                "guardian_verified": true,
                "authority_loss": windows_authority_loss()
            }),
        ),
        (
            "windows-recovery.json",
            json!({
                "recovery_complete": true,
                "active_processes_zero_verified": true,
                "relays_retired_verified": true,
                "authority_loss": windows_authority_loss()
            }),
        ),
    ] {
        write_report(
            &directory.join(name),
            &json!({
                "schema_version": 1,
                "mechanism": "windows-job-object-v2",
                "architecture": architecture,
                "commit": COMMIT,
                "result": "passed",
                "evidence": evidence
            }),
        );
    }
    write_report(
        &directory.join("windows-cleanup.json"),
        &windows_report(architecture, runner_label, &qualification),
    );
}

fn fixture() -> (TempDir, Value, Value, Value) {
    let temporary = TempDir::new().expect("temporary directory should exist");
    let input = temporary.path().join("input");
    fs::create_dir_all(&input).expect("input directory should exist");
    let linux = linux_report();
    let windows = windows_report("x86_64", "windows-2025", &windows_qualification());
    let macos = macos_report();
    write_report(
        &input
            .join("release-certification-linux")
            .join("cleanup-leak-check.json"),
        &linux,
    );
    let receipt_digest = "ab".repeat(32);
    let setid_digest = "cd".repeat(32);
    let sudo_digest = "ef".repeat(32);
    let mut qualification = json!({
        "schema_version": 2,
        "version": env!("CARGO_PKG_VERSION"),
        "mechanism": "linux-pid-namespace-cgroup-v2",
        "provider_identity": "memcordon-sealed-agent-v2",
        "control_service_identity": "memcordon-sealed-agent.service:v2",
        "launcher_service_identity": "memcordon-sealed-launcher.service:v2",
        "receipt_digest": receipt_digest,
        "credential_transition_disposition": "preserve-caller-envelope",
        "setid_transition_certification_digest": setid_digest,
        "sudo_transition_certification_digest": sudo_digest
    });
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
        "split_control_and_launcher_services",
        "launcher_no_new_privs_disabled",
        "caller_mount_namespace_reproduction_verified",
        "caller_no_new_privs_reproduction_verified",
        "caller_capability_bounding_set_reproduction_verified",
        "initial_provider_capabilities_absent",
        "post_transition_cgroup_membership_verified",
        "post_transition_pid_namespace_verified",
        "post_transition_cleanup_verified",
        "recursive_provider_request_rejected",
    ] {
        qualification[field] = json!(true);
    }
    write_report(
        &input.join("release-certification-linux/provider-qualification-v2.json"),
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
        &input.join("release-certification-linux/fault-injection.json"),
        &json!({
            "schema_version": 2,
            "mechanism": "linux-pid-namespace-cgroup-v2",
            "commit": COMMIT,
            "result": "passed",
            "evidence": fault_evidence
        }),
    );
    write_report(
        &input.join("release-certification-linux/provider-package-verification.json"),
        &json!({
            "schema_version": 3,
            "mechanism": "linux-pid-namespace-cgroup-v2",
            "result": "passed",
            "package_verified": true,
            "artifacts": [
                "/usr/libexec/memcordon-sealed-agent",
                "/usr/lib/systemd/system/memcordon-sealed-agent.service",
                "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
                "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
                "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
                "/usr/lib/tmpfiles.d/memcordon.conf",
                "/run/memcordon-sealed-package.lock"
            ],
            "control": {
                "User": "root",
                "Group": "memcordon",
                "NoNewPrivileges": "yes",
                "CapabilityBoundingSet": "cap_dac_override cap_sys_ptrace",
                "AmbientCapabilities": "",
                "PrivateTmp": "yes",
                "ProtectSystem": "strict",
                "RestrictSUIDSGID": "no"
            },
            "launcher": {
                "User": "root",
                "Group": "root",
                "NoNewPrivileges": "no",
                "CapabilityBoundingSet": "cap_chown cap_dac_override cap_kill cap_setgid cap_setuid cap_sys_admin cap_sys_chroot cap_sys_ptrace",
                "AmbientCapabilities": "",
                "PrivateTmp": "no",
                "ProtectSystem": "no",
                "RestrictSUIDSGID": "no"
            }
        }),
    );
    let transition = |file: &str, scenario: &str, certification_digest: Option<&str>| {
        write_report(
            &input.join("release-certification-linux").join(file),
            &json!({
                "schema_version": 2,
                "mechanism": "linux-pid-namespace-cgroup-v2",
                "commit": COMMIT,
                "result": "passed",
                "scenario": scenario,
                "provider_identity": "memcordon-sealed-agent-v2",
                "qualification_digest": receipt_digest,
                "certification_digest": certification_digest,
                "fixture_digest": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
                "post_transition_cgroup_membership_verified": true,
                "post_transition_pid_namespace_verified": true,
                "post_transition_cleanup_verified": true
            }),
        );
    };
    transition(
        "setid-transition.json",
        "sealed_setid_transition_preserves_boundary",
        Some(&setid_digest),
    );
    transition(
        "sudo-transition.json",
        "sealed_sudo_transition_preserves_boundary",
        Some(&sudo_digest),
    );
    transition(
        "file-capability-transition.json",
        "sealed_file_capability_transition_preserves_boundary",
        None,
    );
    write_report(
        &input.join("release-certification-linux/caller-envelope.json"),
        &json!({
            "schema_version": 2,
            "mechanism": "linux-pid-namespace-cgroup-v2",
            "commit": COMMIT,
            "result": "passed",
            "credential_transition_disposition": "preserve-caller-envelope",
            "tests": [
                "sealed_caller_no_new_privs_is_reproduced",
                "sealed_caller_capability_bounding_set_is_reproduced",
                "sealed_recursive_provider_request_is_rejected"
            ],
            "doctor": {"schema_version": memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION, "selected": {"boundary": {"class": "sealed", "mechanism": "linux-pid-namespace-cgroup-v2"}}},
            "public_launch": public_launch_report()
        }),
    );
    write_report(
        &input.join("release-certification-linux/mount-context.json"),
        &json!({
            "schema_version": 2,
            "mechanism": "linux-pid-namespace-cgroup-v2",
            "commit": COMMIT,
            "result": "passed",
            "scenario": "sealed_caller_mount_context_is_reproduced",
            "caller_mount_namespace_reproduction_verified": true
        }),
    );
    write_windows_artifact(&input, "x64", "x86_64", "windows-2025");
    write_windows_artifact(&input, "arm64", "aarch64", "windows-11-arm");
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

    assert_eq!(records.len(), 12);
    for (backend, report_name) in [
        ("linux-pid-namespace-cgroup-v2", "cleanup-leak-check.json"),
        ("macos-watchdog", "backend-macos-watchdog.json"),
    ] {
        let record = records.get(backend).expect("record should exist");
        assert_eq!(record.evidence_path, format!("certification/{report_name}"));
        let evidence = fs::read(output.join(&record.evidence_path))
            .expect("copied evidence should be readable");
        assert_eq!(record.sha256, hex::encode(Sha256::digest(evidence)));
    }
    for (key, architecture) in [
        ("windows-job-object-v2/x86_64-pc-windows-msvc", "x64"),
        ("windows-job-object-v2/aarch64-pc-windows-msvc", "arm64"),
    ] {
        let record = records.get(key).expect("Windows record should exist");
        assert_eq!(
            record.evidence_path,
            format!(
                "certification/windows-sealed-v2/{architecture}-windows-release-certification.json"
            )
        );
    }
    for name in [
        "provider-package-verification.json",
        "provider-qualification-v2.json",
        "setid-transition.json",
        "sudo-transition.json",
        "file-capability-transition.json",
        "caller-envelope.json",
        "mount-context.json",
        "fault-injection.json",
    ] {
        let key = format!("linux-pid-namespace-cgroup-v2/{name}");
        let record = records
            .get(&key)
            .expect("Linux evidence record should exist");
        assert_eq!(
            record.evidence_path,
            format!("certification/linux-sealed-v2/{name}")
        );
    }
}

#[test]
fn windows_public_qualification_binding_mutations_fail_closed() {
    for (name, pointer, replacement) in [
        (
            "backend name",
            "/runtime/public_launch/backend/name",
            Some(json!("standard")),
        ),
        (
            "boundary class",
            "/runtime/public_launch/backend/boundary/class",
            Some(json!("standard")),
        ),
        (
            "boundary mechanism",
            "/runtime/public_launch/backend/boundary/mechanism",
            Some(json!("standard")),
        ),
        (
            "provider identity",
            "/runtime/public_launch/backend/boundary_qualification/provider_identity",
            Some(json!("memcordon-sealed-agent-windows-v1:other")),
        ),
        (
            "well-formed receipt digest",
            "/runtime/public_launch/backend/boundary_qualification/receipt_digest",
            Some(json!("cd".repeat(32))),
        ),
        (
            "qualification mechanism",
            "/runtime/public_launch/backend/boundary_qualification/mechanism",
            Some(json!("standard")),
        ),
        (
            "missing qualification binding",
            "/runtime/public_launch/backend/boundary_qualification",
            None,
        ),
    ] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-windows-x64/windows-cleanup.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        *report.pointer_mut(pointer).expect("binding pointer exists") =
            replacement.unwrap_or(Value::Null);
        write_report(&path, &report);
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "{name} mutation must fail closed"
        );
    }
}

#[test]
fn windows_cross_report_identity_mutations_fail_closed() {
    for (name, report_name, pointer, replacement) in [
        (
            "standalone package digest",
            "windows-package-inspection.json",
            "/guardian_slot_config_sha256",
            json!("26".repeat(32)),
        ),
        (
            "installed package digest",
            "windows-installed-provider.json",
            "/agent/guardian_slot_config_sha256",
            json!("27".repeat(32)),
        ),
        (
            "standalone qualification",
            "windows-qualification.json",
            "/guardian_capacity_verified",
            json!(false),
        ),
        (
            "installed provider identity",
            "windows-installed-provider.json",
            "/provider_identity",
            json!("memcordon-sealed-agent-windows-v1:other"),
        ),
    ] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-windows-x64")
            .join(report_name);
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        *report
            .pointer_mut(pointer)
            .expect("identity pointer exists") = replacement;
        write_report(&path, &report);
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "{name} mutation must fail closed"
        );
    }
}

#[test]
fn windows_token_matrix_rejects_incoherent_token_representations() {
    for (name, pointer, replacement) in [
        (
            "primary token with an impersonation level",
            "/evidence/token_matrix/scenarios/0/caller_envelope/impersonation_level",
            json!(2),
        ),
        (
            "impersonation scenario represented by a primary token",
            "/evidence/token_matrix/scenarios/1/caller_envelope/token_type",
            json!(1),
        ),
        (
            "identification-level scenario",
            "/evidence/token_matrix/scenarios/1/caller_envelope/impersonation_level",
            json!(1),
        ),
        (
            "unknown token type",
            "/evidence/token_matrix/scenarios/1/caller_envelope/token_type",
            json!(99),
        ),
    ] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-windows-x64/windows-token-envelope.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        *report
            .pointer_mut(pointer)
            .expect("token representation pointer exists") = replacement;
        write_report(&path, &report);
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "{name} mutation must fail closed"
        );
    }
}

#[test]
fn windows_token_matrix_rejects_incoherent_write_restricted_evidence() {
    for (name, pointer, replacement) in [
        (
            "write-restricted mode absent",
            "/evidence/token_matrix/scenarios/3/write_restricted",
            json!(false),
        ),
        (
            "Restricted Code substituted for Write Restricted Code",
            "/evidence/token_matrix/scenarios/3/restricting_sids",
            json!(["S-1-5-12"]),
        ),
        (
            "RC and WR union",
            "/evidence/token_matrix/scenarios/3/restricting_sids",
            json!(["S-1-5-12", "S-1-5-33"]),
        ),
        (
            "duplicated WR SID",
            "/evidence/token_matrix/scenarios/3/restricting_sids",
            json!(["S-1-5-33", "S-1-5-33"]),
        ),
    ] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-windows-x64/windows-token-envelope.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        *report
            .pointer_mut(pointer)
            .expect("WR evidence pointer exists") = replacement;
        write_report(&path, &report);
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "{name} mutation must fail closed"
        );
    }
}

#[test]
fn required_windows_mutants_are_mapped_and_killed_by_promoted_evidence() {
    for (mutant, mapped_test) in memcordon_core::WINDOWS_RELEASE_MUTANTS {
        assert!(
            WINDOWS_TESTS.contains(mapped_test),
            "{mutant} must map to a release-required native test"
        );
        let (temporary, _, _, _) = fixture();
        let directory = temporary
            .path()
            .join("input/release-certification-windows-x64");
        let (report_name, pointer) = match *mutant {
            "use-create-process-w"
            | "create-under-service-token"
            | "skip-target-token-readback" => (
                "windows-token-envelope.json",
                "/evidence/initial_target_token_matches_caller",
            ),
            "assign-job-after-create" | "omit-job-list" => (
                "windows-handle-inventory.json",
                "/evidence/job_list_applied_at_creation",
            ),
            "omit-handle-list" | "leak-job-handle-to-target" | "leak-launcher-pipe" => (
                "windows-handle-inventory.json",
                "/evidence/inherited_handles_verified",
            ),
            "permit-breakaway" => (
                "windows-cleanup.json",
                "/runtime/public_launch/attempts/0/boundary_detail/breakaway_denied",
            ),
            "trust-client-token" => (
                "windows-token-envelope.json",
                "/evidence/caller_token_authenticated",
            ),
            "skip-job-membership-readback" => (
                "windows-preauthorization.json",
                "/evidence/target_job_membership_verified",
            ),
            "resume-before-guardian" | "resume-before-relays" => {
                ("windows-preauthorization.json", "/evidence/guardian_ready")
            }
            "accept-recursive-provider" => (
                "windows-qualification.json",
                "/recursive_provider_request_denied",
            ),
            "omit-guardian" => ("windows-front-end-loss.json", "/evidence/guardian_verified"),
            "accept-completion-without-accounting" | "success-before-active-zero" => (
                "windows-cleanup.json",
                "/runtime/public_launch/attempts/0/boundary_detail/active_processes_zero",
            ),
            "skip-relay-ack" => ("windows-handle-inventory.json", "/evidence/relays_retired"),
            "close-job-before-evidence" => (
                "windows-cleanup.json",
                "/runtime/public_launch/attempts/0/boundary_detail/final_job_handles_closed",
            ),
            "fall-back-to-standard" => (
                "windows-cleanup.json",
                "/runtime/public_launch/attempts/0/launch/mechanism",
            ),
            "omit-agent-from-archive" => ("windows-cleanup.json", "/native_target"),
            "advertise-without-certificate" => ("windows-qualification.json", "/qualified"),
            other => panic!("unmapped Windows mutant: {other}"),
        };
        let path = directory.join(report_name);
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let replacement = if *mutant == "fall-back-to-standard" {
            json!("standard")
        } else if *mutant == "omit-agent-from-archive" {
            json!("x86_64-pc-windows-gnu")
        } else {
            json!(false)
        };
        *report
            .pointer_mut(pointer)
            .expect("mutant evidence pointer must exist") = replacement;
        write_report(&path, &report);
        let result = collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        );
        assert!(result.is_err(), "{mutant} must be killed by {mapped_test}");
    }
}

#[test]
fn windows_new_required_fields_cannot_be_omitted() {
    for (report_name, object_pointer, field) in [
        ("windows-qualification.json", "", "guardian_pool_identity"),
        (
            "windows-qualification.json",
            "",
            "guardian_slot_tokens_verified",
        ),
        (
            "windows-qualification.json",
            "",
            "guardian_slot_loader_verified",
        ),
        (
            "windows-qualification.json",
            "",
            "guardian_capacity_verified",
        ),
        ("windows-package-inspection.json", "", "guardian_slot_count"),
        (
            "windows-package-inspection.json",
            "",
            "session_broker_service_name",
        ),
        (
            "windows-package-inspection.json",
            "",
            "session_broker_service_config_sha256",
        ),
        ("windows-package-inspection.json", "", "session_broker_pipe"),
        (
            "windows-package-inspection.json",
            "",
            "session_broker_install_path",
        ),
        (
            "windows-package-inspection.json",
            "",
            "session_broker_sha256",
        ),
        (
            "windows-package-inspection.json",
            "",
            "session_broker_service_sid_type",
        ),
        (
            "windows-package-inspection.json",
            "",
            "session_broker_required_privileges",
        ),
        (
            "windows-package-inspection.json",
            "",
            "session_broker_service_security_sha256",
        ),
        (
            "windows-package-inspection.json",
            "",
            "session_broker_pipe_security_sha256",
        ),
        (
            "windows-package-inspection.json",
            "",
            "guardian_slot_config_sha256",
        ),
        (
            "windows-package-inspection.json",
            "",
            "guardian_pipe_prefix",
        ),
        (
            "windows-package-inspection.json",
            "",
            "guardian_slot_service_sid_type",
        ),
        (
            "windows-package-inspection.json",
            "",
            "guardian_slot_required_privileges",
        ),
        (
            "windows-package-inspection.json",
            "",
            "guardian_pipe_security_contract_sha256",
        ),
        (
            "windows-package-inspection.json",
            "",
            "target_desktop_bootstrap_install_path",
        ),
        (
            "windows-package-inspection.json",
            "",
            "target_desktop_bootstrap_sha256",
        ),
        (
            "windows-cleanup.json",
            "/runtime",
            "fresh_install_rollback_verified",
        ),
    ] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-windows-x64")
            .join(report_name);
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        report
            .pointer_mut(object_pointer)
            .expect("fixture object pointer exists")
            .as_object_mut()
            .expect("fixture pointer identifies an object")
            .remove(field)
            .expect("required fixture field exists");
        write_report(&path, &report);
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "omitting {field} must fail closed"
        );
    }
}

#[test]
fn windows_guardian_qualification_mutations_fail_closed() {
    for (field, replacement) in [
        (
            "guardian_pool_identity",
            json!("MemCordonSealedGuardian:wrong"),
        ),
        ("guardian_slot_tokens_verified", json!(false)),
        ("guardian_slot_loader_verified", json!(false)),
        ("guardian_capacity_verified", json!(false)),
    ] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-windows-x64/windows-qualification.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        report[field] = replacement;
        write_report(&path, &report);
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "mutating {field} must fail closed"
        );
    }
}

#[test]
fn windows_fresh_install_rollback_false_fails_closed() {
    let (temporary, _, _, _) = fixture();
    let path = temporary
        .path()
        .join("input/release-certification-windows-x64/windows-cleanup.json");
    let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    report["runtime"]["fresh_install_rollback_verified"] = json!(false);
    write_report(&path, &report);
    assert!(
        collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        )
        .is_err(),
        "false fresh-install rollback proof must fail closed"
    );
}

#[test]
fn windows_package_identity_mutations_fail_closed() {
    for (name, report_name, pointer, replacement) in [
        (
            "version",
            "windows-package-inspection.json",
            "/version",
            json!("0.0.0"),
        ),
        (
            "commit",
            "windows-package-inspection.json",
            "/source_commit",
            json!("wrong"),
        ),
        (
            "protocol",
            "windows-package-inspection.json",
            "/provider_protocol",
            json!(99),
        ),
        (
            "service name",
            "windows-package-inspection.json",
            "/control_service_name",
            json!("OtherService"),
        ),
        (
            "guardian slot count",
            "windows-package-inspection.json",
            "/guardian_slot_count",
            json!(7),
        ),
        (
            "guardian slot config digest",
            "windows-package-inspection.json",
            "/guardian_slot_config_sha256",
            json!("invalid"),
        ),
        (
            "guardian pipe prefix",
            "windows-package-inspection.json",
            "/guardian_pipe_prefix",
            json!(r"\\.\pipe\other-guardian-v1-"),
        ),
        (
            "guardian service SID type",
            "windows-package-inspection.json",
            "/guardian_slot_service_sid_type",
            json!("unrestricted"),
        ),
        (
            "guardian privilege inventory",
            "windows-package-inspection.json",
            "/guardian_slot_required_privileges",
            json!(["SeDebugPrivilege"]),
        ),
        (
            "guardian pipe security contract digest",
            "windows-package-inspection.json",
            "/guardian_pipe_security_contract_sha256",
            json!("invalid"),
        ),
        (
            "installed guardian slot count",
            "windows-installed-provider.json",
            "/agent/guardian_slot_count",
            json!(7),
        ),
        (
            "privilege inventory",
            "windows-package-inspection.json",
            "/launcher_required_privileges",
            json!([]),
        ),
        (
            "ACL digest",
            "windows-package-inspection.json",
            "/control_pipe_security_sha256",
            json!("invalid"),
        ),
        (
            "installed digest",
            "windows-installed-provider.json",
            "/installed_executable_sha256",
            json!("78".repeat(32)),
        ),
        (
            "installed provider identity",
            "windows-installed-provider.json",
            "/provider_identity",
            json!("other"),
        ),
        (
            "unknown package field",
            "windows-package-inspection.json",
            "/unexpected",
            json!(true),
        ),
    ] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-windows-x64")
            .join(report_name);
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if pointer == "/unexpected" {
            report["unexpected"] = replacement;
        } else {
            *report.pointer_mut(pointer).expect("fixture pointer exists") = replacement;
        }
        write_report(&path, &report);
        assert!(
            collect_certification(
                &temporary.path().join("input"),
                &temporary.path().join("output"),
                COMMIT,
            )
            .is_err(),
            "{name} mutation must fail closed"
        );
    }
}

#[test]
fn hard_report_contract_mutations_fail_closed() {
    let cases: &[(&str, ReportMutation)] = &[
        ("schema", |report| report["schema_version"] = json!(1)),
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
                .join("input/release-certification-linux/cleanup-leak-check.json"),
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
            .join("input/release-certification-linux/cleanup-leak-check.json");
        let mut report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut report["concurrency"]);
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
            .join("input/release-certification-linux/fault-injection.json");
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
            "package-schema",
            "provider-package-verification.json",
            |report| report["schema_version"] = json!(2),
        ),
        (
            "package-binary-inventory",
            "provider-package-verification.json",
            |report| {
                report["artifacts"].as_array_mut().unwrap().remove(0);
            },
        ),
        (
            "package-lease-inventory",
            "provider-package-verification.json",
            |report| {
                report["artifacts"].as_array_mut().unwrap().pop();
            },
        ),
        (
            "package-lease-identity",
            "provider-package-verification.json",
            |report| {
                report["artifacts"][6] = json!("/run/memcordon-sealed-package.lock.backup");
            },
        ),
        (
            "privilege-user",
            "provider-package-verification.json",
            |report| report["control"]["User"] = json!("memcordon"),
        ),
        (
            "privilege-capabilities",
            "provider-package-verification.json",
            |report| report["control"]["CapabilityBoundingSet"] = json!("cap_kill"),
        ),
        (
            "privilege-duplicate-capability",
            "provider-package-verification.json",
            |report| {
                report["control"]["CapabilityBoundingSet"] =
                    json!("cap_dac_override cap_sys_ptrace cap_sys_ptrace")
            },
        ),
        (
            "privilege-extra-property",
            "provider-package-verification.json",
            |report| report["control"]["Unexpected"] = json!("value"),
        ),
        (
            "privilege-unknown-field",
            "provider-package-verification.json",
            |report| report["unexpected"] = json!(true),
        ),
        ("public-schema", "caller-envelope.json", |report| {
            report["public_launch"]["schema_version"] = json!(0)
        }),
        (
            "public-provider-identity",
            "caller-envelope.json",
            |report| {
                report["public_launch"]["backend"]["boundary_qualification"]["provider_identity"] =
                    json!("other-provider")
            },
        ),
        ("public-receipt-digest", "caller-envelope.json", |report| {
            report["public_launch"]["backend"]["boundary_qualification"]["receipt_digest"] =
                json!("other-receipt")
        }),
        (
            "public-boundary-mechanism",
            "caller-envelope.json",
            |report| {
                report["public_launch"]["backend"]["boundary"]["mechanism"] = json!("standard")
            },
        ),
        (
            "public-terminal-cleanup",
            "caller-envelope.json",
            |report| {
                report["public_launch"]["supervision"]["terminal"]["outcome"]["cleanup"]["workload_empty"] =
                    json!(false)
            },
        ),
        (
            "public-boundary-assignment",
            "caller-envelope.json",
            |report| {
                report["public_launch"]["attempts"][0]["launch"]["boundary_assignment_verified"] =
                    json!(false)
            },
        ),
        ("public-native-provider", "caller-envelope.json", |report| {
            report["public_launch"]["attempts"][0]["boundary_detail"]["provider_identity"] =
                json!("other-provider")
        }),
        (
            "public-native-namespace",
            "caller-envelope.json",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["pid_namespace_created"] =
                    json!(false)
            },
        ),
        (
            "public-native-target-release",
            "caller-envelope.json",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["target_released"] =
                    json!(false)
            },
        ),
        ("public-unknown-field", "caller-envelope.json", |report| {
            report["public_launch"]["unexpected"] = json!(true)
        }),
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
fn required_credential_transition_mutants_fail_closed_and_map_to_named_tests() {
    let cases: &[(&str, &str, &str, ReportMutation)] = &[
        (
            "retain-service-nnp-on-target",
            "caller-envelope.json",
            "sealed_caller_no_new_privs_is_reproduced",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["caller_no_new_privs_reproduced"] =
                    json!(false)
            },
        ),
        (
            "force-target-nnp-regardless-of-caller",
            "caller-envelope.json",
            "sealed_caller_no_new_privs_is_reproduced",
            |report| report["tests"][0] = json!("mutant-forced-target-no-new-privileges"),
        ),
        (
            "ignore-caller-capability-bounding-set",
            "caller-envelope.json",
            "sealed_caller_capability_bounding_set_is_reproduced",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["caller_capability_bounding_set_reproduced"] =
                    json!(false)
            },
        ),
        (
            "preserve-provider-capability",
            "caller-envelope.json",
            "sealed_file_capability_transition_preserves_boundary",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["initial_provider_capabilities_absent"] =
                    json!(false)
            },
        ),
        (
            "inherit-control-service-mount-namespace",
            "mount-context.json",
            "sealed_caller_mount_context_is_reproduced",
            |report| report["caller_mount_namespace_reproduction_verified"] = json!(false),
        ),
        (
            "authorize-before-mount-context-verification",
            "caller-envelope.json",
            "sealed_caller_mount_context_is_reproduced",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["caller_mount_context_reproduced"] =
                    json!(false)
            },
        ),
        (
            "allow-recursive-provider-request",
            "caller-envelope.json",
            "sealed_recursive_provider_request_is_rejected",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["recursive_provider_request_denied"] =
                    json!(false)
            },
        ),
        (
            "accept-v1-provider",
            "provider-qualification-v2.json",
            "release_inventory_promotes_and_binds_public_provider_evidence",
            |report| report["schema_version"] = json!(1),
        ),
        (
            "hardcode-transition-compatibility",
            "setid-transition.json",
            "sealed_setid_transition_preserves_boundary",
            |report| report["post_transition_cgroup_membership_verified"] = json!(false),
        ),
        (
            "skip-setid-certification-digest",
            "provider-qualification-v2.json",
            "sealed_setid_transition_preserves_boundary",
            |report| report["setid_transition_certification_digest"] = json!(""),
        ),
        (
            "treat-credential-change-as-boundary-loss",
            "caller-envelope.json",
            "sealed_sudo_transition_preserves_boundary",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["credential_transition_disposition"] =
                    json!("reject")
            },
        ),
        (
            "omit-cgroup-kill-after-credential-change",
            "caller-envelope.json",
            "sealed_file_capability_transition_preserves_boundary",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["cgroup_kill_invoked"] =
                    json!(false)
            },
        ),
        (
            "restart-before-v2-retirement",
            "caller-envelope.json",
            "sealed_recovery_removes_authenticated_stale_record_without_cgroup",
            |report| {
                report["public_launch"]["attempts"][0]["boundary_detail"]["cgroup_removed"] =
                    json!(false)
            },
        ),
    ];

    for (mutant, report_name, mapped_test, mutate) in cases {
        assert!(
            !mapped_test.is_empty(),
            "{mutant} must map to an explicit named test"
        );
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
        assert!(result.is_err(), "{mutant} must be killed by {mapped_test}");
    }
}

#[test]
fn linux_provider_identity_binding_fails_closed() {
    for field in ["provider_identity", "receipt_digest"] {
        let (temporary, _, _, _) = fixture();
        let path = temporary
            .path()
            .join("input/release-certification-linux/provider-qualification-v2.json");
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

    for name in ["provider-package-verification.json", "caller-envelope.json"] {
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
        "provider-package-verification.json",
        ".sealed-public-launch.json",
        "provider-qualification-v2.json",
        ".platform-environment.json",
    ];
    assert_eq!(
        failure_inventory.len(),
        7,
        "failed Linux diagnostic inventory must contain exactly seven files"
    );
    for name in failure_inventory {
        write_report(&linux.join(name), &json!({"schema_version": 1}));
    }
    assert_eq!(
        fs::read_dir(&linux)
            .expect("failed Linux inventory should be readable")
            .count(),
        7,
    );
    assert!(
        collect_certification(
            &temporary.path().join("input"),
            &temporary.path().join("output"),
            COMMIT,
        )
        .is_err(),
        "the seven-file failure diagnostic inventory must not be release input"
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
        "provider-package-verification.json",
        ".sealed-public-launch.json",
        "provider-qualification-v2.json",
        ".platform-environment.json",
        ".sealed-concurrency-report.json",
        ".sealed-post-scenario-public-launch.json",
    ];
    assert_eq!(
        late_package_failure_inventory.len(),
        9,
        "late package failure diagnostics must not resemble the success inventory"
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
        "the late package failure inventory must not be mistaken for release input"
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

    write_report(&input.join("duplicate/cleanup-leak-check.json"), &linux);
    assert!(collect_certification(&input, &output, COMMIT).is_err());
    fs::remove_dir_all(input.join("duplicate")).expect("duplicate directory should be removable");

    fs::write(
        input.join("release-certification-linux/cleanup-leak-check.json"),
        vec![b' '; 64 * 1024 + 1],
    )
    .expect("oversize report should write");
    assert!(collect_certification(&input, &output, COMMIT).is_err());
}
