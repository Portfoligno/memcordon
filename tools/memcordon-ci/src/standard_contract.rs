use crate::certification_context::{
    CertificationContext, CertificationProvenance, ExpectedCertificationOrigin,
};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardTarget {
    LinuxX64,
    WindowsX64,
}

#[derive(Clone, Copy, Debug)]
pub struct StandardContract {
    pub target: StandardTarget,
    pub contract_id: &'static str,
    pub suite_name: &'static str,
    pub backend_name: &'static str,
    pub rust_target: &'static str,
    pub runner_label: &'static str,
    pub report_name: &'static str,
    pub directory: &'static str,
    pub release_artifact: &'static str,
    pub manifest_key: &'static str,
    pub bundle_path: &'static str,
    pub release_job: &'static str,
}

pub const LINUX: StandardContract = StandardContract {
    target: StandardTarget::LinuxX64,
    contract_id: "standard-linux-cgroup-v2-x64-v1",
    suite_name: "backend-linux-cgroup",
    backend_name: "linux-cgroup-v2",
    rust_target: "x86_64-unknown-linux-gnu",
    runner_label: "ubuntu-24.04",
    report_name: "backend-linux-cgroup-v2.json",
    directory: "linux-x64",
    release_artifact: "release-certification-standard-linux-x64",
    manifest_key: "standard/linux-cgroup-v2/x86_64-unknown-linux-gnu",
    bundle_path: "certification/standard/backend-linux-cgroup-v2.json",
    release_job: "linux-standard-certification",
};
pub const WINDOWS: StandardContract = StandardContract {
    target: StandardTarget::WindowsX64,
    contract_id: "standard-windows-job-object-x64-v1",
    suite_name: "backend-windows-job",
    backend_name: "windows-job-object",
    rust_target: "x86_64-pc-windows-msvc",
    runner_label: "windows-2025",
    report_name: "backend-windows-job-object.json",
    directory: "windows-x64",
    release_artifact: "release-certification-standard-windows-x64",
    manifest_key: "standard/windows-job-object/x86_64-pc-windows-msvc",
    bundle_path: "certification/standard/backend-windows-job-object.json",
    release_job: "windows-standard-certification",
};

impl StandardContract {
    pub fn for_backend(backend: &str) -> Result<Self> {
        match backend {
            "linux-cgroup-v2" => Ok(LINUX),
            "windows-job-object" => Ok(WINDOWS),
            _ => Err(CiError::Message("unknown standard backend".into())),
        }
    }
    pub fn scenarios(self) -> Vec<HardBackendScenario> {
        hard_backend_scenarios(self.backend_name).expect("closed standard contract")
    }
    pub fn results(self) -> Vec<StandardTestResult> {
        self.scenarios()
            .into_iter()
            .map(|scenario| {
                let (package, feature, binary) = scenario.cargo_target();
                StandardTestResult {
                    name: scenario.public_name.into(),
                    package: package.into(),
                    required_features: vec![feature.into()],
                    test_binary: binary.into(),
                    exact_name: scenario.exact_name.into(),
                    ignored_selected: scenario.ignored,
                    result: StandardTestStatus::Passed,
                }
            })
            .collect()
    }
    pub fn digest(self) -> Result<String> {
        let tuples: Vec<_> = self
            .scenarios()
            .into_iter()
            .map(|scenario| {
                (
                    scenario.public_name,
                    scenario.cargo_target(),
                    scenario.exact_name,
                    scenario.ignored,
                )
            })
            .collect();
        let bytes = serde_json::to_vec(&(
            self.contract_id,
            "standard",
            self.rust_target,
            "1.97.1",
            "test",
            tuples,
        ))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
    pub fn report_directory(self, root: &std::path::Path) -> std::path::PathBuf {
        root.join("target")
            .join("ci")
            .join("reports")
            .join("standard")
            .join(self.directory)
    }
    pub fn require_native(self) -> Result<()> {
        if std::env::consts::ARCH != "x86_64"
            || std::env::consts::OS
                != match self.target {
                    StandardTarget::LinuxX64 => "linux",
                    StandardTarget::WindowsX64 => "windows",
                }
        {
            return Err(CiError::Message(
                "standard certificate requires its native x64 target".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardTestResult {
    pub name: String,
    pub package: String,
    pub required_features: Vec<String>,
    pub test_binary: String,
    pub exact_name: String,
    pub ignored_selected: bool,
    pub result: StandardTestStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StandardTestStatus {
    Passed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "facts",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum StandardRuntimeEvidence {
    Linux {
        unified_cgroup_v2: bool,
        delegated_boundary: bool,
        memory_controller: bool,
        memory_max_round_trip: bool,
        memory_swap_max: bool,
        cgroup_kill: bool,
    },
    Windows {
        job_memory_limit: bool,
        kill_on_close: bool,
        suspended_assignment: bool,
        nested_job: bool,
        completion_port: bool,
    },
}
impl StandardRuntimeEvidence {
    pub fn complete_for(&self, target: StandardTarget) -> bool {
        match (self, target) {
            (
                Self::Linux {
                    unified_cgroup_v2,
                    delegated_boundary,
                    memory_controller,
                    memory_max_round_trip,
                    memory_swap_max,
                    cgroup_kill,
                },
                StandardTarget::LinuxX64,
            ) => {
                *unified_cgroup_v2
                    && *delegated_boundary
                    && *memory_controller
                    && *memory_max_round_trip
                    && *memory_swap_max
                    && *cgroup_kill
            }
            (
                Self::Windows {
                    job_memory_limit,
                    kill_on_close,
                    suspended_assignment,
                    nested_job,
                    completion_port,
                },
                StandardTarget::WindowsX64,
            ) => {
                *job_memory_limit
                    && *kill_on_close
                    && *suspended_assignment
                    && *nested_job
                    && *completion_port
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardCertificationReportV3 {
    pub schema: u32,
    pub contract_id: String,
    pub contract_sha256: String,
    pub boundary: memcordon_core::BoundaryRequirement,
    pub backend: String,
    pub target: String,
    pub certified: bool,
    pub commit: String,
    pub runner_class: String,
    pub runner_provider: String,
    pub runner_label: String,
    pub provenance: Option<CertificationProvenance>,
    pub runtime: StandardRuntimeEvidence,
    pub tests: Vec<StandardTestResult>,
    pub tests_run: u32,
    pub tests_skipped: u32,
}

pub fn validate_report(
    report: &StandardCertificationReportV3,
    contract: StandardContract,
    source: &str,
    origin: Option<&ExpectedCertificationOrigin>,
) -> Result<()> {
    let context = CertificationContext {
        schema_version: 1,
        contract_id: report.contract_id.clone(),
        source_commit: report.commit.clone(),
        provenance: report.provenance.clone(),
    };
    context.validate(contract.contract_id)?;
    if report.schema != 3
        || report.contract_sha256 != contract.digest()?
        || report.boundary != memcordon_core::BoundaryRequirement::Standard
        || report.backend != contract.backend_name
        || report.target != contract.rust_target
        || !report.certified
        || report.commit != source
        || !report.runtime.complete_for(contract.target)
        || report.tests != contract.results()
        || usize::try_from(report.tests_run).ok() != Some(report.tests.len())
        || report.tests_skipped != 0
    {
        return Err(CiError::Message(
            "standard certificate does not satisfy its exact contract".into(),
        ));
    }
    match &report.provenance {
        Some(p) => {
            let os = match contract.target {
                StandardTarget::LinuxX64 => "Linux",
                StandardTarget::WindowsX64 => "Windows",
            };
            if report.runner_class != "ephemeral-certified"
                || report.runner_provider != "github-hosted"
                || report.runner_label != contract.runner_label
                || p.runner_os != os
            {
                return Err(CiError::Message(
                    "standard certificate runner mismatch".into(),
                ));
            }
            if let Some(o) = origin {
                if p.repository != o.repository
                    || p.run_id != o.run_id
                    || p.workflow_ref != o.workflow_ref
                    || p.workflow_commit != o.workflow_commit
                    || p.job != contract.release_job
                    || report.commit != o.source_commit
                {
                    return Err(CiError::Message(
                        "standard certificate producer origin mismatch".into(),
                    ));
                }
            }
        }
        None => {
            if origin.is_some()
                || report.runner_class != "local"
                || report.runner_provider != "local"
                || !report.runner_label.is_empty()
            {
                return Err(CiError::Message(
                    "local observation is not hosted certification".into(),
                ));
            }
        }
    }
    Ok(())
}

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
