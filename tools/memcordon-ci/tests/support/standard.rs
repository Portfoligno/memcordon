use memcordon_ci::certification_context::{CertificationProvenance, ExpectedCertificationOrigin};
use memcordon_ci::standard_contract::{
    StandardCertificationReportV3, StandardContract, StandardRuntimeEvidence, StandardTarget,
};

pub fn report(
    contract: StandardContract,
    origin: &ExpectedCertificationOrigin,
) -> StandardCertificationReportV3 {
    let linux = contract.target == StandardTarget::LinuxX64;
    StandardCertificationReportV3 {
        schema: 3,
        contract_id: contract.contract_id.into(),
        contract_sha256: contract.digest().unwrap(),
        boundary: memcordon_core::BoundaryRequirement::Standard,
        backend: contract.backend_name.into(),
        target: contract.rust_target.into(),
        certified: true,
        commit: origin.source_commit.clone(),
        runner_class: "ephemeral-certified".into(),
        runner_provider: "github-hosted".into(),
        runner_label: contract.runner_label.into(),
        provenance: Some(CertificationProvenance {
            repository: origin.repository.clone(),
            run_id: origin.run_id,
            run_attempt: 1.try_into().unwrap(),
            job: contract.release_job.into(),
            workflow_ref: origin.workflow_ref.clone(),
            workflow_commit: origin.workflow_commit.clone(),
            runner_environment: "github-hosted".into(),
            runner_os: if linux { "Linux" } else { "Windows" }.into(),
            runner_arch: "X64".into(),
        }),
        runtime: if linux {
            StandardRuntimeEvidence::Linux {
                unified_cgroup_v2: true,
                delegated_boundary: true,
                memory_controller: true,
                memory_max_round_trip: true,
                memory_swap_max: true,
                cgroup_kill: true,
            }
        } else {
            StandardRuntimeEvidence::Windows {
                job_memory_limit: true,
                kill_on_close: true,
                suspended_assignment: true,
                nested_job: true,
                completion_port: true,
            }
        },
        tests: contract.results(),
        tests_run: if linux { 23 } else { 17 },
        tests_skipped: 0,
    }
}
