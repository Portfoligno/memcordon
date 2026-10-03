use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoTestTarget {
    BackendContract,
    PlatformTest(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardBackendScenario {
    pub public_name: &'static str,
    pub exact_name: &'static str,
    pub target: CargoTestTarget,
    pub ignored: bool,
}

impl HardBackendScenario {
    pub fn cargo_target(self) -> (&'static str, &'static str, &'static str) {
        match self.target {
            CargoTestTarget::BackendContract => ("memcordon", "test-fixtures", "backend_contract"),
            CargoTestTarget::PlatformTest(binary) => ("memcordon-platform", "test-support", binary),
        }
    }
    const fn integration(name: &'static str) -> Self {
        Self {
            public_name: name,
            exact_name: name,
            target: CargoTestTarget::BackendContract,
            ignored: true,
        }
    }

    const fn platform(
        test_binary: &'static str,
        public_name: &'static str,
        exact_name: &'static str,
    ) -> Self {
        Self {
            public_name,
            exact_name,
            target: CargoTestTarget::PlatformTest(test_binary),
            ignored: false,
        }
    }
}

const COMMON_HARD_SCENARIOS: [HardBackendScenario; 4] = [
    HardBackendScenario::integration("certified_backend_preserves_ordinary_status_and_reaps"),
    HardBackendScenario::integration("certified_backend_reports_limit_and_removes_workload"),
    HardBackendScenario::integration(
        "certified_backend_cleans_background_descendant_by_birth_identity",
    ),
    HardBackendScenario::integration("certified_backend_allows_bounded_transient_burst"),
];

const LINUX_HARD_SCENARIOS: [HardBackendScenario; 18] = [
    HardBackendScenario::integration("linux_cgroup_v2_contains_aggregate_tree"),
    HardBackendScenario::integration("linux_cgroup_v2_handles_rapid_process_churn"),
    HardBackendScenario::integration("linux_cgroup_controls_are_applied_before_target_observation"),
    HardBackendScenario::integration(
        "linux_embedding_limiter_blocks_target_until_containment_is_verified",
    ),
    HardBackendScenario::integration("linux_embedding_limiter_preserves_non_utf8_target_argv"),
    HardBackendScenario::integration("linux_target_spawn_failures_preserve_native_provenance"),
    HardBackendScenario::integration("linux_memory_events_produce_limit_evidence"),
    HardBackendScenario::integration("linux_cleanup_evidence_confirms_empty_reaped_cgroup"),
    HardBackendScenario::integration("linux_cgroup_identity_is_verified_before_exec"),
    HardBackendScenario::integration("linux_report_pid_is_the_actual_target_pid"),
    HardBackendScenario::integration(
        "linux_gate_failures_kill_the_blocked_target_before_fixture_code",
    ),
    HardBackendScenario::integration("linux_guardian_kills_process_group_after_wrapper_crash"),
    HardBackendScenario::integration("linux_cgroup_kill_reaps_continually_forking_workload"),
    HardBackendScenario::integration("linux_supervisor_monitor_error_fails_closed_end_to_end"),
    HardBackendScenario::platform(
        "linux_cgroup",
        "limit_evidence_requires_counter_delta",
        "limit_evidence_requires_counter_delta",
    ),
    HardBackendScenario::platform(
        "linux_cgroup",
        "cgroup_controls_are_written_exactly",
        "cgroup_controls_are_written_exactly",
    ),
    HardBackendScenario::platform(
        "linux_cgroup",
        "monitor_file_errors_are_reported_instead_of_treated_as_success",
        "monitor_file_errors_are_reported_instead_of_treated_as_success",
    ),
    HardBackendScenario::platform(
        "linux_cgroup",
        "cgroup_identity_verification_rejects_the_wrong_process",
        "cgroup_identity_verification_rejects_the_wrong_process",
    ),
];

const WINDOWS_HARD_SCENARIOS: [HardBackendScenario; 13] = [
    HardBackendScenario::integration("windows_job_object_contains_aggregate_tree"),
    HardBackendScenario::integration("windows_job_object_handles_rapid_process_churn"),
    HardBackendScenario::integration("windows_target_is_suspended_until_job_assignment"),
    HardBackendScenario::integration("windows_descendants_remain_in_job_and_are_cleaned"),
    HardBackendScenario::integration("windows_breakaway_descendant_is_not_left_alive"),
    HardBackendScenario::integration("windows_job_notification_produces_limit_evidence"),
    HardBackendScenario::integration("windows_kill_on_close_cleans_workload"),
    HardBackendScenario::integration("windows_wrapper_crash_closes_job_and_reaps_descendants"),
    HardBackendScenario::platform(
        "windows_job",
        "windows_quoting_preserves_spaces_and_quotes",
        "windows_native_encoder_quotes_without_shell_interpretation",
    ),
    HardBackendScenario::platform(
        "windows_job",
        "target_remains_suspended_until_successful_job_assignment",
        "target_remains_suspended_until_successful_job_assignment",
    ),
    HardBackendScenario::platform(
        "windows_job",
        "kill_on_job_close_terminates_a_running_member",
        "kill_on_job_close_terminates_a_running_member",
    ),
    HardBackendScenario::platform(
        "windows_job",
        "nested_assignment_is_accounted_by_the_memcordon_job",
        "nested_assignment_is_accounted_by_the_memcordon_job",
    ),
    HardBackendScenario::platform(
        "windows_job",
        "assignment_failure_terminates_suspended_target_before_execution",
        "assignment_failure_terminates_suspended_target_before_execution",
    ),
];

pub fn hard_backend_scenarios(backend: &str) -> Result<Vec<HardBackendScenario>> {
    let specific = match backend {
        "linux-cgroup-v2" => LINUX_HARD_SCENARIOS.as_slice(),
        "windows-job-object" => WINDOWS_HARD_SCENARIOS.as_slice(),
        _ => {
            return Err(CiError::Message(format!(
                "unknown hard backend certification: {backend}"
            )));
        }
    };
    Ok(COMMON_HARD_SCENARIOS
        .into_iter()
        .chain(specific.iter().copied())
        .chain(
            (backend == "linux-cgroup-v2").then_some(HardBackendScenario::integration(
                "linux_standard_success_reports_guardian_started_before_authorization",
            )),
        )
        .collect())
}
