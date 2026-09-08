use memcordon_ci::certification_context::ExpectedCertificationOrigin;
use memcordon_ci::standard_contract::{LINUX, StandardTarget, WINDOWS};
use serde_json::json;
#[path = "support/standard.rs"]
mod standard;

#[test]
fn actual_producer_job_and_attempt_are_independent_of_uploaded_claims() {
    let origin = ExpectedCertificationOrigin {
        source_commit: "a".repeat(40),
        repository: "Portfoligno/memcordon".into(),
        run_id: 123.try_into().unwrap(),
        workflow_ref: "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/0.5.3".into(),
        workflow_commit: "a".repeat(40),
    };
    for contract in [LINUX, WINDOWS] {
        let provenance = standard::report(contract, &origin).provenance.unwrap();
        let run = json!({"id":123,"run_attempt":1,"head_sha":origin.source_commit,"path":".github/workflows/release.yml",
            "repository":{"full_name":origin.repository},"event":"push"});
        let jobs = json!({"total_count":1,"jobs":[{"name":if contract.target==StandardTarget::LinuxX64 {"Release / Linux standard certification / x64"} else {"Release / Windows standard certification / x64"},
            "run_id":123,"run_attempt":1,"head_sha":origin.source_commit,"status":"completed","conclusion":"success","labels":[contract.runner_label],"runner_id":9}]});
        memcordon_ci::producer_metadata::validate(&origin, &provenance, contract, &run, &jobs)
            .unwrap();
        for pointer in [
            "/id",
            "/run_attempt",
            "/head_sha",
            "/path",
            "/repository/full_name",
            "/event",
        ] {
            let mut changed = run.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("different");
            assert!(
                memcordon_ci::producer_metadata::validate(
                    &origin,
                    &provenance,
                    contract,
                    &changed,
                    &jobs
                )
                .is_err(),
                "{pointer}"
            );
        }
        for pointer in [
            "/jobs/0/name",
            "/jobs/0/run_id",
            "/jobs/0/run_attempt",
            "/jobs/0/head_sha",
            "/jobs/0/status",
            "/jobs/0/conclusion",
            "/jobs/0/labels",
            "/jobs/0/runner_id",
        ] {
            let mut changed = jobs.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("different");
            assert!(
                memcordon_ci::producer_metadata::validate(
                    &origin,
                    &provenance,
                    contract,
                    &run,
                    &changed
                )
                .is_err(),
                "{pointer}"
            );
        }
        let mut duplicate = jobs.clone();
        duplicate["jobs"]
            .as_array_mut()
            .unwrap()
            .push(jobs["jobs"][0].clone());
        assert!(
            memcordon_ci::producer_metadata::validate(
                &origin,
                &provenance,
                contract,
                &run,
                &duplicate
            )
            .is_err()
        );
        let mut other_attempt = provenance.clone();
        other_attempt.run_attempt = 2.try_into().unwrap();
        assert!(
            memcordon_ci::producer_metadata::validate(
                &origin,
                &other_attempt,
                contract,
                &run,
                &jobs
            )
            .is_err()
        );
    }
}
