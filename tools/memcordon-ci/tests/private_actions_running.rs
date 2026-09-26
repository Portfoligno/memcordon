use std::num::{NonZeroU32, NonZeroU64};

use memcordon_ci::certification_context::{CertificationContext, CertificationProvenance};
use memcordon_ci::private_actions_readback::validate_running_candidate_actions_with;
use memcordon_ci::private_native::PRODUCERS;
use serde_json::{Value, json};

fn context() -> CertificationContext {
    CertificationContext {
        schema_version: 1,
        source_commit: "a".repeat(40),
        contract_id: "backend-linux-private-v4".into(),
        provenance: Some(CertificationProvenance {
            repository: "Portfoligno/memcordon".into(),
            run_id: NonZeroU64::new(42).unwrap(),
            run_attempt: NonZeroU32::new(3).unwrap(),
            job: "linux-private-candidate-x64".into(),
            workflow_ref: "Portfoligno/memcordon/.github/workflows/release.yml@refs/heads/main"
                .into(),
            workflow_commit: "a".repeat(40),
            runner_environment: "github-hosted".into(),
            runner_os: "Linux".into(),
            runner_arch: "X64".into(),
        }),
    }
}

fn responses() -> [Value; 2] {
    [
        json!({
            "id": 42,
            "run_attempt": 3,
            "head_sha": "a".repeat(40),
            "repository": {"full_name": "Portfoligno/memcordon"},
            "event": "workflow_dispatch",
            "status": "in_progress",
            "conclusion": null,
            "path": ".github/workflows/release.yml@main"
        }),
        json!({"total_count": 1, "jobs": [{
            "id": 71,
            "name": "Release / Linux private candidate / x64",
            "run_id": 42,
            "run_attempt": 3,
            "head_sha": "a".repeat(40),
            "status": "in_progress",
            "conclusion": null,
            "workflow_name": "Release",
            "runner_id": 19,
            "labels": ["ubuntu-24.04"]
        }]}),
    ]
}

fn verify(responses: [Value; 2]) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();
    let mut next = 0;
    let job =
        validate_running_candidate_actions_with(&context(), PRODUCERS[1], |url, max, accept| {
            assert_eq!(max, 1024 * 1024);
            assert_eq!(accept, "application/vnd.github+json");
            urls.push(url.to_owned());
            let value = responses.get(next).unwrap();
            next += 1;
            Ok(serde_json::to_vec(value).unwrap())
        })
        .map_err(|error| error.to_string())?;
    assert_eq!(job, 71);
    Ok(urls)
}

#[test]
fn running_candidate_reads_exact_attempt_and_unique_matrix_job() {
    assert_eq!(
        verify(responses()).unwrap(),
        [
            "https://api.github.com/repos/Portfoligno/memcordon/actions/runs/42/attempts/3",
            "https://api.github.com/repos/Portfoligno/memcordon/actions/runs/42/attempts/3/jobs?per_page=100"
        ]
    );
}

#[test]
fn running_candidate_rejects_foreign_or_ambiguous_actions_metadata() {
    let mut wrong_context = context();
    wrong_context.provenance.as_mut().unwrap().runner_arch = "ARM64".into();
    assert!(
        validate_running_candidate_actions_with(&wrong_context, PRODUCERS[1], |_, _, _| {
            panic!("wrong runner architecture must reject before fetching Actions metadata")
        })
        .is_err()
    );

    let mut wrong = responses();
    wrong[0]["head_sha"] = json!("b".repeat(40));
    assert!(verify(wrong).is_err());

    let mut wrong = responses();
    wrong[0]["event"] = json!("push");
    assert!(verify(wrong).is_err());

    let mut wrong = responses();
    wrong[1]["jobs"][0]["labels"] = json!(["ubuntu-24.04-arm"]);
    assert!(verify(wrong).is_err());

    let mut wrong = responses();
    wrong[1]["jobs"][0]["runner_id"] = json!(0);
    assert!(verify(wrong).is_err());

    let mut wrong = responses();
    let duplicate = wrong[1]["jobs"][0].clone();
    wrong[1]["jobs"].as_array_mut().unwrap().push(duplicate);
    wrong[1]["total_count"] = json!(2);
    assert!(verify(wrong).is_err());

    let mut wrong = responses();
    wrong[1]["total_count"] = json!(2);
    assert!(verify(wrong).is_err());

    let duplicate_run = br#"{"id":42,"id":43}"#;
    assert!(
        validate_running_candidate_actions_with(&context(), PRODUCERS[1], |_, _, _| {
            Ok(duplicate_run.to_vec())
        })
        .is_err()
    );
}
