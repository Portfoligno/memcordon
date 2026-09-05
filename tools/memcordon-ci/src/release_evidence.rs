use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use memcordon_core::{
    BoundaryClass, BoundaryMechanismEvidence, BoundaryRequirement, ChildTermination,
    DOCTOR_REPORT_SCHEMA_VERSION, EXECUTION_REPORT_SCHEMA_VERSION, MemcordonReport, RunOutcome,
    SupervisionTerminal, WindowsAuthorityLossEvidenceV1, WindowsCertificationObservationsV1,
    WindowsMutantKillEvidenceV1, WindowsQualificationReceiptV1, WindowsTokenMatrixEvidenceV1,
};

use crate::{CiError, Result};

const MAXIMUM_CERTIFICATION_REPORT_BYTES: u64 = 64 * 1024;
const HARD_CERTIFICATION_RUNNER_CLASS: &str = "ephemeral-certified";
const HARD_CERTIFICATION_RUNNER_PROVIDER: &str = "github-hosted";

const LINUX_SEALED_FILES: &[&str] = &[
    "provider-package-verification.json",
    "provider-qualification-v2.json",
    "setid-transition.json",
    "sudo-transition.json",
    "file-capability-transition.json",
    "caller-envelope.json",
    "mount-context.json",
    "fault-injection.json",
    "cleanup-leak-check.json",
];
pub const LINUX_SEALED_TESTS: &[&str] = &[
    "qualification_fails_closed_without_root_provider",
    "qualification_receipt_requires_complete_retirement",
    "sealed_direct_exit_retires_fresh_boundary",
    "sealed_staged_fixture_is_isolated_and_removed_after_retirement",
    "sealed_future_deadline_authorizes_and_retires",
    "sealed_expired_deadline_never_authorizes_and_retires",
    "sealed_child_outlives_direct_target_until_cleanup",
    "sealed_double_fork_remains_in_pid_namespace_and_cgroup",
    "sealed_setsid_daemon_remains_contained",
    "sealed_setid_transition_preserves_boundary",
    "sealed_sudo_transition_preserves_boundary",
    "sealed_file_capability_transition_preserves_boundary",
    "sealed_caller_no_new_privs_is_reproduced",
    "sealed_caller_capability_bounding_set_is_reproduced",
    "sealed_caller_mount_context_is_reproduced",
    "sealed_recursive_provider_request_is_rejected",
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
    "sealed_native_nonzero_exit_preserves_provenance",
    "sealed_native_exit_126_and_127_are_not_exec_failures",
    "sealed_missing_target_preserves_enoent_exec_provenance",
    "sealed_non_executable_target_preserves_eacces_exec_provenance",
    "sealed_restart_uses_fresh_retired_boundary",
    "sealed_simultaneous_attempts_have_disjoint_boundaries",
    "sealed_recovery_removes_authenticated_stale_record_without_cgroup",
    "sealed_recovery_quarantines_cgroup_without_authenticated_record",
    "sealed_recovery_blocks_capability_while_live_state_is_ambiguous",
    "sealed_faults_before_authorization_never_create_marker",
    "sealed_namespace_init_failure_is_typed_prompt_and_retired",
    "sealed_cgroup_kill_failure_never_reports_retirement",
    "sealed_persistent_populated_state_blocks_restart",
    "sealed_namespace_init_reap_delay_blocks_result",
    "sealed_guardian_reap_failure_blocks_result",
    "sealed_package_identity_rejects_tampered_provider",
    "sealed_package_stable_lease_survives_legacy_inode_replacement",
    "sealed_package_upgrade_recovers_before_advertising",
    "sealed_package_uninstall_refuses_live_authenticated_attempt",
];

const WINDOWS_SEALED_FILES: &[&str] = &[
    "windows-package-inspection.json",
    "windows-installed-provider.json",
    "windows-qualification.json",
    "windows-token-envelope.json",
    "windows-handle-inventory.json",
    "windows-preauthorization.json",
    "windows-alternate-token.json",
    "windows-nested-job.json",
    "windows-front-end-loss.json",
    "windows-recovery.json",
    "windows-cleanup.json",
];
const WINDOWS_TESTS: &[&str] = &[
    "fresh_qualification_failure_rollback_is_repeatable",
    "package_install_verify_probe_and_same_version_upgrade",
    "stale_low_integrity_workspace_upgrade_and_uninstall_cleanup",
    "active_attempt_upgrade_and_uninstall_converge",
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationRecord {
    pub evidence_path: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReportKind {
    LinuxSealed,
    WindowsSplit,
    Macos,
}

#[derive(Clone, Copy)]
struct ReportSpec {
    record_key: &'static str,
    backend: &'static str,
    artifact_directory: &'static str,
    report_name: &'static str,
    evidence_path: &'static str,
    kind: ReportKind,
    architecture: Option<&'static str>,
    runner_label: Option<&'static str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SplitWindowsCertificationV1 {
    schema_version: u32,
    backend: String,
    certified: bool,
    commit: String,
    runner_class: String,
    runner_provider: String,
    runner_label: String,
    architecture: String,
    native_archive_sha256: Option<String>,
    runtime_manifest_sha256: Option<String>,
    native_target: Option<String>,
    evidence_bindings: BTreeMap<String, String>,
}

const REPORTS: &[ReportSpec] = &[
    ReportSpec {
        record_key: "linux-pid-namespace-cgroup-v2",
        backend: "linux-pid-namespace-cgroup-v2",
        artifact_directory: "release-certification-linux",
        report_name: "cleanup-leak-check.json",
        evidence_path: "certification/cleanup-leak-check.json",
        kind: ReportKind::LinuxSealed,
        architecture: None,
        runner_label: None,
    },
    ReportSpec {
        record_key: "windows-job-object-v2/x86_64-pc-windows-msvc",
        backend: "windows-job-object-v2",
        artifact_directory: "release-windows-package-channel-x64",
        report_name: "windows-release-certification.json",
        evidence_path: "certification/windows-sealed-v2/x64-windows-release-certification.json",
        kind: ReportKind::WindowsSplit,
        architecture: Some("x86_64"),
        runner_label: Some("windows-2025"),
    },
    ReportSpec {
        record_key: "windows-job-object-v2/aarch64-pc-windows-msvc",
        backend: "windows-job-object-v2",
        artifact_directory: "release-windows-package-channel-arm64",
        report_name: "windows-release-certification.json",
        evidence_path: "certification/windows-sealed-v2/arm64-windows-release-certification.json",
        kind: ReportKind::WindowsSplit,
        architecture: Some("aarch64"),
        runner_label: Some("windows-11-arm"),
    },
    ReportSpec {
        record_key: "macos-watchdog",
        backend: "macos-watchdog",
        artifact_directory: "release-acceptance-macos-arm64",
        report_name: "backend-macos-watchdog.json",
        evidence_path: "certification/backend-macos-watchdog.json",
        kind: ReportKind::Macos,
        architecture: None,
        runner_label: None,
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
    architecture: String,
    #[serde(default)]
    native_archive_sha256: Option<String>,
    #[serde(default)]
    runtime_manifest_sha256: Option<String>,
    #[serde(default)]
    native_target: Option<String>,
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
    result: String,
    tests_run: u32,
    tests_skipped: u32,
    scenarios: Vec<LinuxSealedScenario>,
    recovery_tests: Vec<String>,
    concurrency: LinuxConcurrencyReport,
    public_launch: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxQualificationReceipt {
    schema_version: u32,
    version: String,
    mechanism: String,
    provider_identity: String,
    control_service_identity: String,
    launcher_service_identity: String,
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
    split_control_and_launcher_services: bool,
    launcher_no_new_privs_disabled: bool,
    caller_mount_namespace_reproduction_verified: bool,
    caller_no_new_privs_reproduction_verified: bool,
    caller_capability_bounding_set_reproduction_verified: bool,
    initial_provider_capabilities_absent: bool,
    credential_transition_disposition: String,
    setid_transition_certification_digest: String,
    sudo_transition_certification_digest: String,
    post_transition_cgroup_membership_verified: bool,
    post_transition_pid_namespace_verified: bool,
    post_transition_cleanup_verified: bool,
    recursive_provider_request_rejected: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxTransitionEvidence {
    schema_version: u32,
    mechanism: String,
    commit: String,
    result: String,
    scenario: String,
    provider_identity: String,
    qualification_digest: String,
    certification_digest: Option<String>,
    fixture_digest: String,
    post_transition_cgroup_membership_verified: bool,
    post_transition_pid_namespace_verified: bool,
    post_transition_cleanup_verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxCallerEnvelopeEvidence {
    schema_version: u32,
    mechanism: String,
    commit: String,
    result: String,
    credential_transition_disposition: String,
    tests: Vec<String>,
    doctor: serde_json::Value,
    public_launch: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxMountContextEvidence {
    schema_version: u32,
    mechanism: String,
    commit: String,
    result: String,
    scenario: String,
    caller_mount_namespace_reproduction_verified: bool,
}

const LINUX_FAULT_EVIDENCE_TESTS: &[&str] = &[
    "sealed_frontend_loss_before_authorization_never_runs_target",
    "sealed_frontend_loss_after_authorization_triggers_guardian",
    "sealed_provider_worker_loss_triggers_guardian",
    "sealed_guardian_loss_before_authorization_fails_closed",
    "sealed_guardian_loss_after_authorization_cannot_report_success",
    "sealed_faults_before_authorization_never_create_marker",
    "sealed_namespace_init_failure_is_typed_prompt_and_retired",
    "sealed_cgroup_kill_failure_never_reports_retirement",
    "sealed_persistent_populated_state_blocks_restart",
    "sealed_namespace_init_reap_delay_blocks_result",
    "sealed_guardian_reap_failure_blocks_result",
];

#[derive(Clone, Copy)]
struct ExpectedLinuxFaultEvidence {
    code: &'static str,
    phase: &'static str,
    target_created: bool,
    target_released: bool,
    cleanup_retired: bool,
    retirement_owner: &'static str,
    guardian_reaped: bool,
}

fn expected_linux_fault_evidence(selector: &str) -> Option<ExpectedLinuxFaultEvidence> {
    let expected = match selector {
        "sealed_frontend_loss_before_authorization_never_runs_target" => {
            ExpectedLinuxFaultEvidence {
                code: "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION",
                phase: "authorization",
                target_created: true,
                target_released: false,
                cleanup_retired: true,
                retirement_owner: "guardian",
                guardian_reaped: true,
            }
        }
        "sealed_frontend_loss_after_authorization_triggers_guardian" => {
            ExpectedLinuxFaultEvidence {
                code: "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION",
                phase: "monitoring",
                target_created: true,
                target_released: true,
                cleanup_retired: true,
                retirement_owner: "guardian",
                guardian_reaped: true,
            }
        }
        "sealed_provider_worker_loss_triggers_guardian" => ExpectedLinuxFaultEvidence {
            code: "MCSEALED-PROVIDER-WORKER-LOSS",
            phase: "guardian-startup",
            target_created: false,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "guardian",
            guardian_reaped: true,
        },
        "sealed_guardian_loss_before_authorization_fails_closed" => ExpectedLinuxFaultEvidence {
            code: "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION",
            phase: "authorization",
            target_created: true,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_guardian_loss_after_authorization_cannot_report_success" => {
            ExpectedLinuxFaultEvidence {
                code: "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION",
                phase: "monitoring",
                target_created: true,
                target_released: true,
                cleanup_retired: true,
                retirement_owner: "provider",
                guardian_reaped: true,
            }
        }
        "sealed_faults_before_authorization_never_create_marker" => ExpectedLinuxFaultEvidence {
            code: "MCSEALED-LAUNCH-DESCRIPTOR-SET",
            phase: "request-validation",
            target_created: false,
            target_released: false,
            cleanup_retired: false,
            retirement_owner: "provider",
            guardian_reaped: false,
        },
        "sealed_namespace_init_failure_is_typed_prompt_and_retired" => ExpectedLinuxFaultEvidence {
            code: "MCSEALED-NAMESPACE-INIT-TARGET-FORK",
            phase: "target-creation",
            target_created: false,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_cgroup_kill_failure_never_reports_retirement" => ExpectedLinuxFaultEvidence {
            code: "MCSEALED-CGROUP-KILL-FAILURE",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_persistent_populated_state_blocks_restart" => ExpectedLinuxFaultEvidence {
            code: "MCSEALED-CGROUP-NOT-EMPTY",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_namespace_init_reap_delay_blocks_result" => ExpectedLinuxFaultEvidence {
            code: "MCSEALED-NAMESPACE-INIT-REAP-DELAY",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_guardian_reap_failure_blocks_result" => ExpectedLinuxFaultEvidence {
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxFaultCleanupEvidence {
    attempted: bool,
    direct_child_reaped: bool,
    workload_empty: Option<bool>,
    helpers_reaped: bool,
    containment_removed: bool,
    sealed_boundary_retired: bool,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxFaultRejectionEvidence {
    schema_version: u32,
    code: String,
    phase: String,
    detail: String,
    os_code: Option<i32>,
    target_created: bool,
    target_released: bool,
    cleanup: LinuxFaultCleanupEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxFaultScenarioEvidence {
    schema_version: u32,
    selector: String,
    attempt_id: String,
    rejection: LinuxFaultRejectionEvidence,
    retirement_owner: String,
    marker_observed: bool,
    guardian_reaped: bool,
    final_record_absent: bool,
    final_cgroup_absent: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxFaultInjectionReport {
    schema_version: u32,
    mechanism: String,
    commit: String,
    result: String,
    evidence: Vec<LinuxFaultScenarioEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxProviderPackageVerification {
    schema_version: u32,
    mechanism: String,
    result: String,
    package_verified: bool,
    artifacts: Vec<String>,
    control: BTreeMap<String, String>,
    launcher: BTreeMap<String, String>,
}

#[derive(Debug)]
struct LinuxProviderBinding {
    provider_identity: String,
    receipt_digest: String,
    setid_transition_certification_digest: String,
    sudo_transition_certification_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxConcurrencyAttempt {
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxConcurrencyReport {
    schema_version: u32,
    mechanism: String,
    commit: String,
    overlap: bool,
    attempts: Vec<LinuxConcurrencyAttempt>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsRuntimeEvidence {
    qualification: WindowsQualificationReceiptV1,
    public_launch: MemcordonReport,
    fresh_install_rollback_verified: bool,
    active_attempt_upgrade_converged: bool,
    active_attempt_uninstall_converged: bool,
    frontend_loss_record_retired: bool,
    provider_state_removed: bool,
    status_matrix: WindowsStatusMatrixEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsStatusMatrixEvidence {
    schema_version: u32,
    ordinary_exit_codes: Vec<u32>,
    deadline_outcome: memcordon_core::RunOutcome,
    memory_limit_outcome: memcordon_core::RunOutcome,
    raw_ntstatus_outcome: memcordon_core::RunOutcome,
    orphan_descendant_outcome: memcordon_core::RunOutcome,
    command_not_found: memcordon_core::SupervisionErrorRecord,
    command_not_executable: memcordon_core::SupervisionErrorRecord,
    provider_setup_failure: memcordon_core::ProviderRejectionEvidence,
    relay_failure: memcordon_core::ProviderRejectionEvidence,
    terminal_truncation_rejected: bool,
    report_consistency_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct WindowsPackageInspection {
    schema_version: u32,
    version: String,
    source_commit: String,
    executable_sha256: String,
    provider_protocol: u32,
    mechanism: String,
    execution_report_schema: u32,
    plan_report_schema: u32,
    doctor_report_schema: u32,
    platform: String,
    control_service_name: String,
    launcher_service_name: String,
    session_broker_service_name: String,
    guardian_slot_count: usize,
    control_service_config_sha256: String,
    launcher_service_config_sha256: String,
    session_broker_service_config_sha256: String,
    guardian_slot_config_sha256: String,
    control_pipe: String,
    launcher_pipe: String,
    session_broker_pipe: String,
    guardian_pipe_prefix: String,
    binary_install_path: String,
    target_desktop_bootstrap_install_path: String,
    target_desktop_bootstrap_sha256: String,
    session_broker_install_path: String,
    session_broker_sha256: String,
    state_root: String,
    control_service_sid_type: String,
    launcher_service_sid_type: String,
    session_broker_service_sid_type: String,
    guardian_slot_service_sid_type: String,
    control_required_privileges: Vec<String>,
    launcher_required_privileges: Vec<String>,
    session_broker_required_privileges: Vec<String>,
    guardian_slot_required_privileges: Vec<String>,
    control_pipe_security_sha256: String,
    launcher_pipe_security_sha256: String,
    session_broker_service_security_sha256: String,
    session_broker_pipe_security_sha256: String,
    guardian_pipe_security_contract_sha256: String,
    install_directory_security_sha256: String,
    state_directory_security_sha256: String,
    compiled_metadata_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsInstalledProviderInspection {
    schema_version: u32,
    agent: WindowsPackageInspection,
    installed_executable_sha256: String,
    installed_artifacts_valid: bool,
    provider_identity: Option<String>,
    provider_reachable: bool,
    qualification_complete: bool,
}

impl WindowsPackageInspection {
    fn valid(&self, expected_commit: &str) -> bool {
        self.schema_version == 3
            && self.version == env!("CARGO_PKG_VERSION")
            && self.source_commit == expected_commit
            && valid_sha256(&self.executable_sha256)
            && self.provider_protocol == memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
            && self.mechanism == "windows-job-object-v2"
            && self.execution_report_schema == memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
            && self.plan_report_schema == memcordon_core::PLAN_REPORT_SCHEMA_VERSION
            && self.doctor_report_schema == memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION
            && self.platform == "windows-service"
            && self.control_service_name == memcordon_core::WINDOWS_CONTROL_SERVICE_NAME
            && self.launcher_service_name == memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME
            && self.session_broker_service_name
                == memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME
            && self.guardian_slot_count == memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT
            && self.control_pipe == memcordon_core::WINDOWS_CONTROL_PIPE
            && self.launcher_pipe == memcordon_core::WINDOWS_LAUNCHER_PIPE
            && self.session_broker_pipe == memcordon_core::WINDOWS_SESSION_BROKER_PIPE
            && self.guardian_pipe_prefix == memcordon_core::WINDOWS_GUARDIAN_PIPE_PREFIX
            && self
                .binary_install_path
                .ends_with("MemCordon\\memcordon-sealed-agent.exe")
            && self
                .target_desktop_bootstrap_install_path
                .ends_with("MemCordon\\memcordon-target-desktop-bootstrap.exe")
            && valid_sha256(&self.target_desktop_bootstrap_sha256)
            && self
                .session_broker_install_path
                .ends_with("MemCordon\\memcordon-session-broker.exe")
            && valid_sha256(&self.session_broker_sha256)
            && self.state_root.ends_with("MemCordon\\sealed")
            && self.control_service_sid_type == "restricted"
            && self.launcher_service_sid_type == "restricted"
            && self.session_broker_service_sid_type == "unrestricted"
            && self.guardian_slot_service_sid_type == "restricted"
            && self.control_required_privileges
                == memcordon_core::WINDOWS_CONTROL_REQUIRED_PRIVILEGES
            && self.launcher_required_privileges
                == memcordon_core::WINDOWS_LAUNCHER_REQUIRED_PRIVILEGES
            && self.session_broker_required_privileges
                == memcordon_core::WINDOWS_SESSION_BROKER_REQUIRED_PRIVILEGES
            && self.guardian_slot_required_privileges.is_empty()
            && [
                &self.control_service_config_sha256,
                &self.launcher_service_config_sha256,
                &self.session_broker_service_config_sha256,
                &self.guardian_slot_config_sha256,
                &self.control_pipe_security_sha256,
                &self.launcher_pipe_security_sha256,
                &self.session_broker_service_security_sha256,
                &self.session_broker_pipe_security_sha256,
                &self.guardian_pipe_security_contract_sha256,
                &self.install_directory_security_sha256,
                &self.state_directory_security_sha256,
            ]
            .iter()
            .all(|value| valid_sha256(value))
            && self.compiled_metadata_valid
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsEvidenceEnvelope {
    schema_version: u32,
    mechanism: String,
    architecture: String,
    commit: String,
    result: String,
    evidence: serde_json::Value,
}

impl WindowsRuntimeEvidence {
    fn complete(&self) -> bool {
        self.qualification.qualified
            && self.qualification.is_consistent()
            && validate_windows_public_launch(&self.public_launch, &self.qualification)
            && self.fresh_install_rollback_verified
            && self.active_attempt_upgrade_converged
            && self.active_attempt_uninstall_converged
            && self.frontend_loss_record_retired
            && self.provider_state_removed
            && self.status_matrix.complete()
    }
}

impl WindowsStatusMatrixEvidence {
    fn complete(&self) -> bool {
        self.schema_version == 1
            && self.ordinary_exit_codes == (u8::MIN..=u8::MAX).map(u32::from).collect::<Vec<_>>()
            && matches!(
                self.deadline_outcome,
                memcordon_core::RunOutcome::DeadlineExceeded { .. }
            )
            && matches!(
                self.memory_limit_outcome,
                memcordon_core::RunOutcome::LimitExceeded { .. }
            )
            && matches!(
                self.raw_ntstatus_outcome,
                memcordon_core::RunOutcome::Exited {
                    child: memcordon_core::ChildTermination::WindowsStatus {
                        status: 0xC000_013A
                    },
                    ..
                }
            )
            && matches!(
                self.orphan_descendant_outcome,
                memcordon_core::RunOutcome::Exited {
                    child: memcordon_core::ChildTermination::ExitCode { code: 0 },
                    ..
                }
            )
            && self.command_not_found.initial_spawn_failure
                == Some(memcordon_core::InitialSpawnFailure::NotFound)
            && self.command_not_found.os_code == Some(2)
            && self.command_not_executable.initial_spawn_failure
                == Some(memcordon_core::InitialSpawnFailure::NotExecutable)
            && self.command_not_executable.os_code == Some(193)
            && self.provider_setup_failure.phase
                == memcordon_core::BoundarySetupPhase::BoundaryCreation
            && !self.provider_setup_failure.target_released
            && self.provider_setup_failure.is_consistent()
            && self.relay_failure.phase == memcordon_core::BoundarySetupPhase::Retirement
            && self.relay_failure.target_released
            && self.relay_failure.is_consistent()
            && self.terminal_truncation_rejected
            && self.report_consistency_verified
    }
}

fn validate_windows_public_launch(
    report: &MemcordonReport,
    qualification: &WindowsQualificationReceiptV1,
) -> bool {
    let Some(backend) = report.backend.as_ref() else {
        return false;
    };
    let Some(binding) = backend.boundary_qualification.as_ref() else {
        return false;
    };
    let Ok(receipt) = serde_json::to_vec(qualification) else {
        return false;
    };
    let Some(attempt) = report.attempts.last() else {
        return false;
    };
    let BoundaryMechanismEvidence::WindowsJobObjectV2(native) = &attempt.boundary_detail else {
        return false;
    };
    backend.name == "windows-job-object"
        && backend.boundary.class == BoundaryClass::Sealed
        && backend.boundary.mechanism == "windows-job-object-v2"
        && binding.provider_identity == qualification.provider_identity
        && binding.receipt_digest == sha256_bytes(&receipt)
        && binding.mechanism == "windows-job-object-v2"
        && attempt.launch.target_released
        && attempt.launch.containment_verified_before_authorization
        && attempt.launch.guardian_started_before_authorization
        && attempt.launch.boundary_assignment_verified
        && attempt.launch.boundary_reconfiguration_denied
        && attempt.launch.inherited_resources_restricted
        && attempt.launch.frontend_loss_cleanup_authority_verified
        && native.caller_token_authenticated
        && native.initial_target_token_matches_caller
        && native.job_created
        && native.job_limits_verified
        && native.kill_on_close_verified
        && native.breakaway_denied
        && native.completion_port_associated
        && native.guardian_ready
        && native.target_created_suspended
        && native.job_list_applied_at_creation
        && native.handle_list_applied_at_creation
        && native.target_job_membership_verified
        && native.target_still_suspended_during_verification
        && native.inherited_handles_verified
        && native.target_released
        && native.active_processes_zero
        && native.direct_target_reaped
        && native.relays_retired
        && native.guardian_reaped
        && native.final_job_handles_closed
}

fn validate_windows_auxiliary(
    name: &str,
    bytes: &[u8],
    expected_commit: &str,
    expected_architecture: &str,
) -> Result<()> {
    match name {
        "windows-package-inspection.json" => {
            let inspection: WindowsPackageInspection = serde_json::from_slice(bytes)?;
            if !inspection.valid(expected_commit) {
                return Err(failure("Windows package inspection is incomplete"));
            }
        }
        "windows-installed-provider.json" => {
            let inspection: WindowsInstalledProviderInspection = serde_json::from_slice(bytes)?;
            if inspection.schema_version != 3
                || !inspection.agent.valid(expected_commit)
                || inspection.installed_executable_sha256 != inspection.agent.executable_sha256
                || !inspection.installed_artifacts_valid
                || inspection.provider_identity.is_none()
                || !inspection.provider_reachable
                || !inspection.qualification_complete
            {
                return Err(failure(
                    "Windows installed-provider inspection is incomplete",
                ));
            }
        }
        "windows-qualification.json" => {
            let receipt: WindowsQualificationReceiptV1 = serde_json::from_slice(bytes)?;
            if !receipt.qualified || !receipt.is_consistent() {
                return Err(failure("Windows qualification evidence is incomplete"));
            }
        }
        "windows-cleanup.json" => {}
        _ => {
            let report: WindowsEvidenceEnvelope = serde_json::from_slice(bytes)?;
            if report.schema_version != 1
                || report.mechanism != "windows-job-object-v2"
                || report.architecture != expected_architecture
                || report.commit != expected_commit
                || report.result != "passed"
            {
                return Err(failure(format!(
                    "Windows auxiliary evidence is incomplete: {name}"
                )));
            }
            match name {
                "windows-token-envelope.json" => {
                    require_windows_evidence_fields(
                        name,
                        &report.evidence,
                        &[
                            "caller_token_authenticated",
                            "initial_target_token_matches_caller",
                            "restricted_caller_token_verified",
                            "primary_token_duplication_verified",
                        ],
                    )?;
                    let token_matrix: WindowsTokenMatrixEvidenceV1 = serde_json::from_value(
                        report
                            .evidence
                            .get("token_matrix")
                            .cloned()
                            .ok_or_else(|| failure("Windows token matrix is missing"))?,
                    )?;
                    if !token_matrix.is_complete() {
                        return Err(failure("Windows token matrix is incomplete"));
                    }
                }
                "windows-handle-inventory.json" => require_windows_evidence_fields(
                    name,
                    &report.evidence,
                    &[
                        "job_list_applied_at_creation",
                        "handle_list_applied_at_creation",
                        "inherited_handles_verified",
                        "exact_handle_inheritance_verified",
                        "relays_retired",
                    ],
                )?,
                "windows-preauthorization.json" => require_windows_evidence_fields(
                    name,
                    &report.evidence,
                    &[
                        "guardian_ready",
                        "target_created_suspended",
                        "target_job_membership_verified",
                        "target_still_suspended_during_verification",
                        "target_released",
                    ],
                )
                .and_then(|()| {
                    let fault_matrix: WindowsCertificationObservationsV1 = serde_json::from_value(
                        report
                            .evidence
                            .get("fault_matrix")
                            .cloned()
                            .ok_or_else(|| {
                                failure("Windows preauthorization evidence lacks a fault matrix")
                            })?,
                    )?;
                    if fault_matrix.is_complete() {
                        let mutant_kills: WindowsMutantKillEvidenceV1 = serde_json::from_value(
                            report
                                .evidence
                                .get("mutant_kills")
                                .cloned()
                                .ok_or_else(|| {
                                    failure(
                                        "Windows preauthorization evidence lacks executable mutant kills",
                                    )
                                })?,
                        )?;
                        if mutant_kills.is_complete() {
                            Ok(())
                        } else {
                            Err(failure(
                                "Windows executable mutant kill evidence is incomplete",
                            ))
                        }
                    } else {
                        Err(failure(
                            "Windows preauthorization fault matrix is incomplete",
                        ))
                    }
                })?,
                "windows-alternate-token.json" => require_windows_evidence_fields(
                    name,
                    &report.evidence,
                    &[
                        "alternate_token_child_contained",
                        "initial_target_token_matches_caller",
                        "job_membership_independent_of_token",
                    ],
                )?,
                "windows-nested-job.json" => require_windows_evidence_fields(
                    name,
                    &report.evidence,
                    &[
                        "nested_host_job_supported",
                        "nested_child_job_contained",
                        "target_job_membership_verified",
                    ],
                )?,
                "windows-front-end-loss.json" => {
                    require_windows_evidence_fields(
                        name,
                        &report.evidence,
                        &[
                            "frontend_loss_cleanup_verified",
                            "record_retired",
                            "active_processes_zero_verified",
                            "guardian_verified",
                        ],
                    )?;
                    require_windows_authority_loss(&report.evidence)?;
                }
                "windows-recovery.json" => {
                    require_windows_evidence_fields(
                        name,
                        &report.evidence,
                        &[
                            "recovery_complete",
                            "active_processes_zero_verified",
                            "relays_retired_verified",
                        ],
                    )?;
                    require_windows_authority_loss(&report.evidence)?;
                }
                _ => return Err(failure("unexpected Windows sealed v2 evidence file")),
            }
        }
    }
    Ok(())
}

fn validate_windows_cross_report_bindings(directory: &Path, cleanup: &[u8]) -> Result<()> {
    let cleanup: HardCertificationReport<WindowsRuntimeEvidence> = serde_json::from_slice(cleanup)?;
    let package: WindowsPackageInspection = serde_json::from_slice(&read_report(
        &directory.join("windows-package-inspection.json"),
    )?)?;
    let installed: WindowsInstalledProviderInspection = serde_json::from_slice(&read_report(
        &directory.join("windows-installed-provider.json"),
    )?)?;
    let qualification: WindowsQualificationReceiptV1 =
        serde_json::from_slice(&read_report(&directory.join("windows-qualification.json"))?)?;
    if package != installed.agent
        || qualification != cleanup.runtime.qualification
        || installed.provider_identity.as_deref()
            != Some(cleanup.runtime.qualification.provider_identity.as_str())
        || !validate_windows_public_launch(
            &cleanup.runtime.public_launch,
            &cleanup.runtime.qualification,
        )
    {
        return Err(failure(
            "Windows release evidence does not share one package and qualification identity",
        ));
    }
    Ok(())
}

fn require_windows_authority_loss(evidence: &serde_json::Value) -> Result<()> {
    let authority: WindowsAuthorityLossEvidenceV1 = serde_json::from_value(
        evidence
            .get("authority_loss")
            .cloned()
            .ok_or_else(|| failure("Windows authority-loss evidence is absent"))?,
    )?;
    if authority.is_complete() {
        Ok(())
    } else {
        Err(failure("Windows authority-loss evidence is incomplete"))
    }
}

fn require_windows_evidence_fields(
    name: &str,
    evidence: &serde_json::Value,
    fields: &[&str],
) -> Result<()> {
    if fields
        .iter()
        .all(|field| evidence.get(*field).and_then(serde_json::Value::as_bool) == Some(true))
    {
        Ok(())
    } else {
        Err(failure(format!(
            "Windows scenario evidence is contradictory: {name}"
        )))
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
    expected_architecture: &str,
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
    let native_identity_valid = spec.kind != ReportKind::WindowsSplit
        || (report.native_target.as_deref()
            == Some(match expected_architecture {
                "x86_64" => "x86_64-pc-windows-msvc",
                "aarch64" => "aarch64-pc-windows-msvc",
                _ => "",
            })
            && report
                .native_archive_sha256
                .as_deref()
                .is_some_and(valid_sha256)
            && report
                .runtime_manifest_sha256
                .as_deref()
                .is_some_and(valid_sha256));
    if report.schema != 2
        || report.backend != spec.backend
        || !report.certified
        || report.commit != expected_commit
        || report.runner_class != HARD_CERTIFICATION_RUNNER_CLASS
        || report.runner_provider != HARD_CERTIFICATION_RUNNER_PROVIDER
        || report.runner_label != expected_label
        || report.architecture != expected_architecture
        || !runtime_complete(&report.runtime)
        || !ordered_names_match
        || !all_passed
        || report.tests_run != derived_count
        || report.tests_run != u32::try_from(expected_tests.len()).expect("static inventory fits")
        || report.tests_skipped != 0
        || !native_identity_valid
    {
        return Err(failure(format!(
            "required certification failed: {}",
            spec.backend
        )));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == Sha256::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_split_windows_certification(
    bytes: &[u8],
    directory: &Path,
    spec: ReportSpec,
    expected_commit: &str,
) -> Result<()> {
    let report: SplitWindowsCertificationV1 = serde_json::from_slice(bytes)?;
    let expected_architecture = spec
        .architecture
        .expect("Windows split report has an architecture");
    let expected_target = match expected_architecture {
        "x86_64" => "x86_64-pc-windows-msvc",
        "aarch64" => "aarch64-pc-windows-msvc",
        _ => return Err(failure("unsupported Windows release architecture")),
    };
    let expected_names: BTreeSet<&str> = [
        "production-result.json",
        "production-manifest.json",
        "lifecycle-outcomes.json",
        "package-lifecycle.json",
        "cargo-rollback.json",
        "native-rollback.json",
        "cargo-fingerprint.json",
        "native-fingerprint.json",
        "launch-plan.json",
    ]
    .into_iter()
    .collect();
    if report.schema_version != 1
        || report.backend != spec.backend
        || !report.certified
        || report.commit != expected_commit
        || report.runner_class != HARD_CERTIFICATION_RUNNER_CLASS
        || report.runner_provider != HARD_CERTIFICATION_RUNNER_PROVIDER
        || report.runner_label
            != spec
                .runner_label
                .expect("Windows split report has a runner label")
        || report.architecture != expected_architecture
        || report.native_target.as_deref() != Some(expected_target)
        || !report
            .native_archive_sha256
            .as_deref()
            .is_some_and(valid_sha256)
        || !report
            .runtime_manifest_sha256
            .as_deref()
            .is_some_and(valid_sha256)
        || report
            .evidence_bindings
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != expected_names
    {
        return Err(failure("Windows split certification is incomplete"));
    }
    let evidence = directory.join("release-evidence");
    for (name, expected_sha256) in &report.evidence_bindings {
        if !valid_sha256(expected_sha256)
            || sha256_bytes(&read_report(&evidence.join(name))?) != *expected_sha256
        {
            return Err(failure(format!(
                "Windows split evidence binding differs: {name}"
            )));
        }
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

fn validate_linux_public_launch_value(
    value: &serde_json::Value,
    binding: &LinuxProviderBinding,
) -> bool {
    let Ok(report) = serde_json::from_value::<MemcordonReport>(value.clone()) else {
        return false;
    };
    if serde_json::to_value(&report).ok().as_ref() != Some(value) {
        return false;
    }
    validate_linux_public_launch(&report, binding)
}

fn validate_linux_sealed_report(
    bytes: &[u8],
    expected_commit: &str,
    binding: &LinuxProviderBinding,
) -> Result<()> {
    let report: LinuxSealedScenarioReport = serde_json::from_slice(bytes)?;
    let count = u32::try_from(report.scenarios.len())
        .map_err(|_| failure("too many Linux sealed scenarios"))?;
    let exact_inventory = report.scenarios.len() == LINUX_SEALED_TESTS.len()
        && report
            .scenarios
            .iter()
            .zip(LINUX_SEALED_TESTS)
            .all(|(scenario, expected)| scenario.name == *expected);
    let expected_recovery = [
        "sealed_recovery_removes_authenticated_stale_record_without_cgroup",
        "sealed_recovery_quarantines_cgroup_without_authenticated_record",
        "sealed_recovery_blocks_capability_while_live_state_is_ambiguous",
    ];
    if report.schema_version != 2
        || report.mechanism != "linux-pid-namespace-cgroup-v2"
        || report.commit != expected_commit
        || report.result != "passed"
        || report.tests_run != count
        || report.tests_skipped != 0
        || !exact_inventory
        || report.recovery_tests != expected_recovery
        || report.scenarios.iter().any(|scenario| {
            scenario.name.is_empty() || scenario.class.is_empty() || scenario.result != "passed"
        })
        || !validate_linux_concurrency(&report.concurrency, expected_commit)
        || !validate_linux_public_launch_value(&report.public_launch, binding)
    {
        return Err(failure("required Linux sealed v2 certification failed"));
    }
    Ok(())
}

fn valid_linux_attempt_identity(identity: &str) -> bool {
    identity.len().is_multiple_of(2)
        && identity.len() / 2 == std::mem::size_of::<[u8; 16]>()
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_linux_concurrency(report: &LinuxConcurrencyReport, expected_commit: &str) -> bool {
    if report.schema_version != 2
        || report.mechanism != "linux-pid-namespace-cgroup-v2"
        || report.commit != expected_commit
        || !report.overlap
        || report.attempts.len() != 2
    {
        return false;
    }
    let identities = report
        .attempts
        .iter()
        .map(|attempt| attempt.identity.as_str())
        .collect::<BTreeSet<_>>();
    let targets = report
        .attempts
        .iter()
        .map(|attempt| attempt.target_pid)
        .collect::<BTreeSet<_>>();
    if identities.len() != report.attempts.len()
        || targets.len() != report.attempts.len()
        || targets.contains(&0)
    {
        return false;
    }
    let complete = report.attempts.iter().all(|attempt| {
        let members = attempt
            .live_cgroup_member_pids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        valid_linux_attempt_identity(&attempt.identity)
            && members.len() == attempt.live_cgroup_member_pids.len()
            && !members.contains(&0)
            && members.contains(&attempt.target_pid)
            && attempt.started_monotonic_millis <= attempt.authorized_monotonic_millis
            && attempt.authorized_monotonic_millis < attempt.terminal_monotonic_millis
            && attempt.record_absent
            && attempt.cgroup_absent
            && attempt.fixture_absent
            && attempt.boundary_retired
    });
    let left = report.attempts[0]
        .live_cgroup_member_pids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let right = report.attempts[1]
        .live_cgroup_member_pids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let overlap_started = report
        .attempts
        .iter()
        .map(|attempt| attempt.authorized_monotonic_millis)
        .max()
        .expect("two concurrency attempts were already required");
    let overlap_ended = report
        .attempts
        .iter()
        .map(|attempt| attempt.terminal_monotonic_millis)
        .min()
        .expect("two concurrency attempts were already required");
    complete && left.is_disjoint(&right) && overlap_started < overlap_ended
}

fn linux_provider_binding(directory: &Path) -> Result<LinuxProviderBinding> {
    let qualification_bytes = read_report(&directory.join("provider-qualification-v2.json"))?;
    let qualification: LinuxQualificationReceipt = serde_json::from_slice(&qualification_bytes)?;
    if qualification.schema_version != 2
        || qualification.version != env!("CARGO_PKG_VERSION")
        || qualification.mechanism != "linux-pid-namespace-cgroup-v2"
        || qualification.provider_identity.is_empty()
        || qualification.receipt_digest.is_empty()
        || qualification
            .setid_transition_certification_digest
            .is_empty()
        || qualification
            .sudo_transition_certification_digest
            .is_empty()
    {
        return Err(failure(
            "Linux provider v2 qualification identity is incomplete",
        ));
    }
    Ok(LinuxProviderBinding {
        provider_identity: qualification.provider_identity,
        receipt_digest: qualification.receipt_digest,
        setid_transition_certification_digest: qualification.setid_transition_certification_digest,
        sudo_transition_certification_digest: qualification.sudo_transition_certification_digest,
    })
}

fn validate_linux_provider_package(report: &LinuxProviderPackageVerification) -> bool {
    let expected_keys = [
        "AmbientCapabilities",
        "CapabilityBoundingSet",
        "Group",
        "NoNewPrivileges",
        "PrivateTmp",
        "ProtectSystem",
        "RestrictSUIDSGID",
        "User",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let control_keys = report
        .control
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let launcher_keys = report
        .launcher
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_control_capabilities = ["cap_dac_override", "cap_sys_ptrace"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let capability_tokens = |properties: &BTreeMap<String, String>| {
        properties
            .get("CapabilityBoundingSet")
            .map(|value| {
                value
                    .split_ascii_whitespace()
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let control_tokens = capability_tokens(&report.control);
    let launcher_tokens = capability_tokens(&report.launcher);
    let control_capabilities = control_tokens.iter().cloned().collect::<BTreeSet<_>>();
    let launcher_capabilities = launcher_tokens.iter().cloned().collect::<BTreeSet<_>>();
    let expected_artifacts = [
        "/usr/libexec/memcordon-sealed-agent",
        "/usr/lib/systemd/system/memcordon-sealed-agent.service",
        "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
        "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
        "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
        "/usr/lib/tmpfiles.d/memcordon.conf",
        "/run/memcordon-sealed-package.lock",
    ];
    report.schema_version == 3
        && report.mechanism == "linux-pid-namespace-cgroup-v2"
        && report.result == "passed"
        && report.package_verified
        && report.artifacts == expected_artifacts
        && control_keys == expected_keys
        && launcher_keys == expected_keys
        && report.control.get("User").map(String::as_str) == Some("root")
        && report.control.get("Group").map(String::as_str) == Some("memcordon")
        && report.control.get("NoNewPrivileges").map(String::as_str) == Some("yes")
        && report.control.get("PrivateTmp").map(String::as_str) == Some("yes")
        && report.control.get("ProtectSystem").map(String::as_str) == Some("strict")
        && report
            .control
            .get("AmbientCapabilities")
            .map(String::as_str)
            == Some("")
        && control_capabilities
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected_control_capabilities
        && control_tokens.len() == control_capabilities.len()
        && report.launcher.get("User").map(String::as_str) == Some("root")
        && report.launcher.get("Group").map(String::as_str) == Some("root")
        && report.launcher.get("NoNewPrivileges").map(String::as_str) == Some("no")
        && report.launcher.get("PrivateTmp").map(String::as_str) == Some("no")
        && report.launcher.get("ProtectSystem").map(String::as_str) == Some("no")
        && report.launcher.get("RestrictSUIDSGID").map(String::as_str) == Some("no")
        && report
            .launcher
            .get("AmbientCapabilities")
            .map(String::as_str)
            == Some("")
        && !launcher_capabilities.is_empty()
        && launcher_tokens.len() == launcher_capabilities.len()
        && control_capabilities.is_subset(&launcher_capabilities)
}

fn validate_linux_public_launch(report: &MemcordonReport, binding: &LinuxProviderBinding) -> bool {
    let Some(backend) = report.backend.as_ref() else {
        return false;
    };
    let Some(supervision) = report.supervision.as_ref() else {
        return false;
    };
    let qualification = backend.boundary_qualification.as_ref();
    let attempt = report.attempts.first();
    let exited_zero = matches!(
        &supervision.terminal,
        SupervisionTerminal::AttemptOutcome {
            attempt_number: 1,
            outcome: RunOutcome::Exited {
                child: ChildTermination::ExitCode { code: 0 },
                cleanup,
                ..
            },
        } if cleanup.direct_child_reaped
            && cleanup.workload_empty == Some(true)
            && cleanup.errors.is_empty()
    );
    report.schema_version == EXECUTION_REPORT_SCHEMA_VERSION
        && report.error.is_none()
        && backend.name == "linux-sealed-provider"
        && backend.boundary.class == BoundaryClass::Sealed
        && backend.boundary.mechanism == "linux-pid-namespace-cgroup-v2"
        && qualification.is_some_and(|qualification| {
            qualification.provider_identity == binding.provider_identity
                && qualification.receipt_digest == binding.receipt_digest
                && qualification.mechanism == "linux-pid-namespace-cgroup-v2"
        })
        && supervision.wrapper_exit_code == 0
        && supervision.attempt_records_created == 1
        && supervision.targets_authorized == 1
        && supervision.restart.restarts_launched() == 0
        && exited_zero
        && report.attempts.len() == 1
        && attempt.is_some_and(|attempt| {
            attempt.number == 1
                && attempt.launch.boundary_requested == BoundaryRequirement::Sealed
                && attempt.launch.boundary_effective == BoundaryClass::Sealed
                && attempt.launch.target_released
                && attempt.launch.boundary_assignment_verified
                && attempt.launch.inherited_resources_restricted
                && attempt
                    .restart_safety
                    .is_safe_for(BoundaryRequirement::Sealed)
                && matches!(
                    &attempt.boundary_detail,
                    BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2(native)
                        if native.schema_version == 2
                            && native.provider_identity == binding.provider_identity
                            && native.control_service_identity
                                == "memcordon-sealed-agent.service:v2"
                            && native.launcher_service_identity
                                == "memcordon-sealed-launcher.service:v2"
                            && !native.cgroup_identity_digest.is_empty()
                            && native.cgroup_created
                            && native.cgroup_owned_by_provider
                            && native.memory_configuration_verified
                            && native.init_created_into_cgroup
                            && native.pid_namespace_created
                            && native.mount_namespace_created
                            && native.cgroup_namespace_created
                            && native.target_pidfd_verified
                            && native.target_cgroup_membership_verified
                            && native.target_pid_namespace_verified
                            && native.target_initial_credentials_verified
                            && native.initial_provider_capabilities_absent
                            && native.caller_no_new_privs_reproduced
                            && native.caller_capability_bounding_set_reproduced
                            && native.caller_mount_context_reproduced
                            && native.credential_transition_disposition
                                == memcordon_core::CredentialTransitionDisposition::PreserveCallerEnvelope
                            && native.boundary_independent_of_credentials
                            && native.inherited_descriptors_verified
                            && native.writable_ancestor_cgroup_denied
                            && native.parent_namespace_handles_denied
                            && native.recursive_provider_request_denied
                            && native.guardian_ready
                            && native.target_released
                            && native.cgroup_kill_invoked
                            && native.cgroup_empty_verified
                            && native.namespace_init_reaped
                            && native.guardian_reaped
                            && native.cgroup_removed
                )
        })
}

fn validate_linux_fault_evidence(
    report: &LinuxFaultInjectionReport,
    expected_commit: &str,
) -> bool {
    if report.schema_version != 2
        || report.mechanism != "linux-pid-namespace-cgroup-v2"
        || report.commit != expected_commit
        || report.result != "passed"
        || report.evidence.len() != LINUX_FAULT_EVIDENCE_TESTS.len()
    {
        return false;
    }
    report
        .evidence
        .iter()
        .zip(LINUX_FAULT_EVIDENCE_TESTS)
        .all(|(evidence, expected_selector)| {
            let Some(expected) = expected_linux_fault_evidence(expected_selector) else {
                return false;
            };
            let rejection = &evidence.rejection;
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
            evidence.schema_version == 1
                && evidence.selector == *expected_selector
                && valid_linux_attempt_identity(&evidence.attempt_id)
                && rejection.schema_version == 1
                && rejection.code == expected.code
                && rejection.phase == expected.phase
                && code_bound
                && rejection.os_code.is_none()
                && rejection.target_created == expected.target_created
                && rejection.target_released == expected.target_released
                && cleanup_exact
                && evidence.retirement_owner == expected.retirement_owner
                && evidence.final_record_absent
                && evidence.final_cgroup_absent
                && evidence.guardian_reaped == expected.guardian_reaped
                && evidence.marker_observed == expected.target_released
        })
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn linux_qualification_complete(
    report: &LinuxQualificationReceipt,
    binding: &LinuxProviderBinding,
) -> bool {
    report.schema_version == 2
        && report.mechanism == "linux-pid-namespace-cgroup-v2"
        && report.provider_identity == binding.provider_identity
        && report.control_service_identity == "memcordon-sealed-agent.service:v2"
        && report.launcher_service_identity == "memcordon-sealed-launcher.service:v2"
        && report.receipt_digest == binding.receipt_digest
        && is_sha256_digest(&report.receipt_digest)
        && report.unified_cgroup_v2
        && report.private_cgroup_subtree
        && report.clone3
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
        && report.spawn_error_reporting_verified
        && report.frontend_loss_authority_verified
        && report.cgroup_kill
        && report.workload_empty
        && report.helpers_reaped
        && report.boundary_retired
        && report.recovery_complete
        && report.split_control_and_launcher_services
        && report.launcher_no_new_privs_disabled
        && report.caller_mount_namespace_reproduction_verified
        && report.caller_no_new_privs_reproduction_verified
        && report.caller_capability_bounding_set_reproduction_verified
        && report.initial_provider_capabilities_absent
        && report.credential_transition_disposition == "preserve-caller-envelope"
        && report.setid_transition_certification_digest
            == binding.setid_transition_certification_digest
        && is_sha256_digest(&report.setid_transition_certification_digest)
        && report.sudo_transition_certification_digest
            == binding.sudo_transition_certification_digest
        && is_sha256_digest(&report.sudo_transition_certification_digest)
        && report.post_transition_cgroup_membership_verified
        && report.post_transition_pid_namespace_verified
        && report.post_transition_cleanup_verified
        && report.recursive_provider_request_rejected
}

#[doc(hidden)]
pub fn fuzz_linux_qualification_receipt(data: &[u8]) {
    if data.len() as u64 > MAXIMUM_CERTIFICATION_REPORT_BYTES {
        return;
    }
    if let Ok(report) = serde_json::from_slice::<LinuxQualificationReceipt>(data) {
        let binding = LinuxProviderBinding {
            provider_identity: report.provider_identity.clone(),
            receipt_digest: report.receipt_digest.clone(),
            setid_transition_certification_digest: report
                .setid_transition_certification_digest
                .clone(),
            sudo_transition_certification_digest: report
                .sudo_transition_certification_digest
                .clone(),
        };
        std::hint::black_box(linux_qualification_complete(&report, &binding));
    }
}

#[doc(hidden)]
pub fn fuzz_linux_service_unit_policy(data: &[u8]) {
    if data.len() as u64 > MAXIMUM_CERTIFICATION_REPORT_BYTES {
        return;
    }
    if let Ok(report) = serde_json::from_slice::<LinuxProviderPackageVerification>(data) {
        std::hint::black_box(validate_linux_provider_package(&report));
    }
}

#[doc(hidden)]
pub fn fuzz_linux_mount_context_manifest(data: &[u8]) {
    if data.len() as u64 > MAXIMUM_CERTIFICATION_REPORT_BYTES {
        return;
    }
    if let Ok(report) = serde_json::from_slice::<LinuxMountContextEvidence>(data) {
        std::hint::black_box(
            report.schema_version == 2
                && report.mechanism == "linux-pid-namespace-cgroup-v2"
                && !report.commit.is_empty()
                && report.result == "passed"
                && report.scenario == "sealed_caller_mount_context_is_reproduced"
                && report.caller_mount_namespace_reproduction_verified,
        );
    }
}

fn validate_linux_auxiliary(
    name: &str,
    bytes: &[u8],
    expected_commit: &str,
    binding: &LinuxProviderBinding,
) -> Result<()> {
    match name {
        "provider-package-verification.json" => {
            let report: LinuxProviderPackageVerification = serde_json::from_slice(bytes)?;
            if !validate_linux_provider_package(&report) {
                return Err(failure(
                    "Linux provider v2 package evidence is incomplete or contradictory",
                ));
            }
        }
        "provider-qualification-v2.json" => {
            let report: LinuxQualificationReceipt = serde_json::from_slice(bytes)?;
            if !linux_qualification_complete(&report, binding) {
                return Err(failure("Linux qualification v2 evidence is incomplete"));
            }
        }
        "setid-transition.json" | "sudo-transition.json" | "file-capability-transition.json" => {
            let report: LinuxTransitionEvidence = serde_json::from_slice(bytes)?;
            let (expected_scenario, expected_digest) = match name {
                "setid-transition.json" => (
                    "sealed_setid_transition_preserves_boundary",
                    Some(binding.setid_transition_certification_digest.as_str()),
                ),
                "sudo-transition.json" => (
                    "sealed_sudo_transition_preserves_boundary",
                    Some(binding.sudo_transition_certification_digest.as_str()),
                ),
                _ => ("sealed_file_capability_transition_preserves_boundary", None),
            };
            if report.schema_version != 2
                || report.mechanism != "linux-pid-namespace-cgroup-v2"
                || report.commit != expected_commit
                || report.result != "passed"
                || report.scenario != expected_scenario
                || report.provider_identity != binding.provider_identity
                || report.qualification_digest != binding.receipt_digest
                || report.certification_digest.as_deref() != expected_digest
                || !is_sha256_digest(&report.fixture_digest)
                || !report.post_transition_cgroup_membership_verified
                || !report.post_transition_pid_namespace_verified
                || !report.post_transition_cleanup_verified
            {
                return Err(failure(format!(
                    "Linux credential-transition evidence is incomplete: {name}"
                )));
            }
        }
        "caller-envelope.json" => {
            let report: LinuxCallerEnvelopeEvidence = serde_json::from_slice(bytes)?;
            let expected_tests = [
                "sealed_caller_no_new_privs_is_reproduced",
                "sealed_caller_capability_bounding_set_is_reproduced",
                "sealed_recursive_provider_request_is_rejected",
            ];
            let doctor_valid = report
                .doctor
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                == Some(u64::from(DOCTOR_REPORT_SCHEMA_VERSION))
                && report
                    .doctor
                    .pointer("/selected/boundary/class")
                    .and_then(serde_json::Value::as_str)
                    == Some("sealed")
                && report
                    .doctor
                    .pointer("/selected/boundary/mechanism")
                    .and_then(serde_json::Value::as_str)
                    == Some("linux-pid-namespace-cgroup-v2");
            if report.schema_version != 2
                || report.mechanism != "linux-pid-namespace-cgroup-v2"
                || report.commit != expected_commit
                || report.result != "passed"
                || report.credential_transition_disposition != "preserve-caller-envelope"
                || report.tests != expected_tests
                || !doctor_valid
                || !validate_linux_public_launch_value(&report.public_launch, binding)
            {
                return Err(failure(
                    "Linux caller-envelope evidence is incomplete or contradictory",
                ));
            }
        }
        "mount-context.json" => {
            let report: LinuxMountContextEvidence = serde_json::from_slice(bytes)?;
            if report.schema_version != 2
                || report.mechanism != "linux-pid-namespace-cgroup-v2"
                || report.commit != expected_commit
                || report.result != "passed"
                || report.scenario != "sealed_caller_mount_context_is_reproduced"
                || !report.caller_mount_namespace_reproduction_verified
            {
                return Err(failure("Linux caller mount-context evidence is incomplete"));
            }
        }
        "fault-injection.json" => {
            let report: LinuxFaultInjectionReport = serde_json::from_slice(bytes)?;
            if !validate_linux_fault_evidence(&report, expected_commit) {
                return Err(failure(
                    "Linux fault-injection evidence is incomplete or contradictory",
                ));
            }
        }
        "cleanup-leak-check.json" => {}
        _ => return Err(failure("unexpected Linux sealed v2 evidence file")),
    }
    Ok(())
}

fn validate_artifact_inventory(input: &Path) -> Result<()> {
    let allowed_directories: BTreeSet<&str> =
        REPORTS.iter().map(|spec| spec.artifact_directory).collect();
    let legacy_windows_directories = [
        "release-certification-windows-x64",
        "release-certification-windows-arm64",
    ];
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| failure("release input artifact name is not UTF-8"))?;
        let certification_namespace =
            name.starts_with("release-certification-") || name.starts_with("release-acceptance-");
        if certification_namespace
            && !allowed_directories.contains(name.as_str())
            && !legacy_windows_directories.contains(&name.as_str())
        {
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
        if !matches!(spec.kind, ReportKind::WindowsSplit) {
            let entries = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
            let expected: BTreeSet<&str> = match spec.kind {
                ReportKind::LinuxSealed => LINUX_SEALED_FILES.iter().copied().collect(),
                ReportKind::Macos => [spec.report_name].into_iter().collect(),
                ReportKind::WindowsSplit => unreachable!(),
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
        }

        let expected_path = directory.join(spec.report_name);
        let search_root = if matches!(spec.kind, ReportKind::WindowsSplit) {
            &directory
        } else {
            input
        };
        let matching_paths = WalkDir::new(search_root)
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
        if name == "linux-sealed-v2" && entry.file_type()?.is_dir() {
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
                .filter(|name| **name != "cleanup-leak-check.json")
                .map(|name| (*name).to_owned())
                .collect();
            if actual != expected {
                return Err(failure("Linux release evidence inventory differs"));
            }
            continue;
        }
        if name == "windows-sealed-v2" && entry.file_type()?.is_dir() {
            let expected: BTreeSet<String> = ["x64", "arm64"]
                .into_iter()
                .map(|architecture| format!("{architecture}-windows-release-certification.json"))
                .collect();
            let actual: BTreeSet<String> = fs::read_dir(entry.path())?
                .map(|file| {
                    let file = file?;
                    if !file.file_type()?.is_file() {
                        return Err(failure("Windows release evidence item is not a file"));
                    }
                    file.file_name()
                        .into_string()
                        .map_err(|_| failure("Windows release evidence name is not UTF-8"))
                })
                .collect::<Result<_>>()?;
            if actual != expected {
                return Err(failure("Windows release evidence inventory differs"));
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

    for (id, architecture, runner_label) in [
        ("x64", "x86_64", "windows-2025"),
        ("arm64", "aarch64", "windows-11-arm"),
    ] {
        let directory = input.join(format!("release-certification-windows-{id}"));
        if directory.is_dir() {
            let spec = ReportSpec {
                record_key: "legacy-windows-validation-only",
                backend: "windows-job-object-v2",
                artifact_directory: "legacy-windows-validation-only",
                report_name: "windows-cleanup.json",
                evidence_path: "legacy-windows-validation-only",
                kind: ReportKind::WindowsSplit,
                architecture: Some(architecture),
                runner_label: Some(runner_label),
            };
            let cleanup = read_report(&directory.join("windows-cleanup.json"))?;
            validate_hard_report::<WindowsRuntimeEvidence>(
                &cleanup,
                spec,
                expected_commit,
                runner_label,
                architecture,
                WINDOWS_TESTS,
                WindowsRuntimeEvidence::complete,
            )?;
            for name in WINDOWS_SEALED_FILES {
                let auxiliary = read_report(&directory.join(name))?;
                validate_windows_auxiliary(name, &auxiliary, expected_commit, architecture)?;
            }
            validate_windows_cross_report_bindings(&directory, &cleanup)?;
        }
    }

    let mut validated = Vec::new();
    for spec in REPORTS {
        let path = input.join(spec.artifact_directory).join(spec.report_name);
        let bytes = read_report(&path)?;
        match spec.kind {
            ReportKind::LinuxSealed => {
                let binding = linux_provider_binding(&input.join(spec.artifact_directory))?;
                validate_linux_sealed_report(&bytes, expected_commit, &binding)?;
                for name in LINUX_SEALED_FILES {
                    let auxiliary = read_report(&input.join(spec.artifact_directory).join(name))?;
                    validate_linux_auxiliary(name, &auxiliary, expected_commit, &binding)?;
                }
            }
            ReportKind::WindowsSplit => validate_split_windows_certification(
                &bytes,
                &input.join(spec.artifact_directory),
                *spec,
                expected_commit,
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
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| failure("certification evidence path has no parent"))?,
        )?;
        fs::write(&destination, report.bytes)?;
        records.insert(
            report.spec.record_key.to_owned(),
            CertificationRecord {
                evidence_path: report.spec.evidence_path.to_owned(),
                sha256: report.sha256,
            },
        );
    }
    let linux_input = input.join("release-certification-linux");
    let linux_output = evidence_directory.join("linux-sealed-v2");
    fs::create_dir_all(&linux_output)?;
    for name in LINUX_SEALED_FILES {
        if *name == "cleanup-leak-check.json" {
            continue;
        }
        let bytes = read_report(&linux_input.join(name))?;
        let relative = format!("certification/linux-sealed-v2/{name}");
        fs::write(output.join(&relative), &bytes)?;
        records.insert(
            format!("linux-pid-namespace-cgroup-v2/{name}"),
            CertificationRecord {
                evidence_path: relative,
                sha256: sha256_bytes(&bytes),
            },
        );
    }
    Ok(records)
}
