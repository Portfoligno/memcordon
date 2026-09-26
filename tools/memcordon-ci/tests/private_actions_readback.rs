use std::num::{NonZeroU32, NonZeroU64};

use memcordon_ci::certification_context::ExpectedCertificationOrigin;
use memcordon_ci::private_actions_readback::read_actions_native_artifact_with;
use memcordon_ci::private_native::PRODUCERS;
use serde_json::{Value, json};

fn origin() -> ExpectedCertificationOrigin {
    ExpectedCertificationOrigin {
        source_commit: "a".repeat(40),
        repository: "Portfoligno/memcordon".into(),
        run_id: NonZeroU64::new(42).unwrap(),
        workflow_ref: "Portfoligno/memcordon/.github/workflows/release.yml@refs/heads/main".into(),
        workflow_commit: "a".repeat(40),
    }
}

fn responses() -> Vec<Value> {
    let spec = PRODUCERS[1];
    vec![
        json!({
            "id": 42,
            "run_attempt": 3,
            "head_sha": "a".repeat(40),
            "repository": {"full_name": "Portfoligno/memcordon"}
        }),
        json!({"total_count": 1, "jobs": [{"id": 61, "name": spec.job_name}]}),
        json!({"total_count": 1, "artifacts": [{
            "id": 71,
            "name": spec.artifact_name,
            "expired": false,
            "workflow_run": {"id": 42}
        }]}),
    ]
}

fn run_with(responses: Vec<Value>) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();
    let mut next = 0;
    read_actions_native_artifact_with(
        &origin(),
        PRODUCERS[1],
        NonZeroU32::new(3).unwrap(),
        |url, limit, accept| {
            urls.push(url.to_owned());
            if url.ends_with("/zip") {
                assert_eq!(accept, "application/zip");
                assert_eq!(limit, 128 * 1024 * 1024);
                return Ok(vec![1, 2, 3]);
            }
            assert_eq!(accept, "application/vnd.github+json");
            assert_eq!(limit, 1024 * 1024);
            let response = responses.get(next).unwrap();
            next += 1;
            Ok(serde_json::to_vec(response).unwrap())
        },
    )
    .map_err(|error| error.to_string())?;
    Ok(urls)
}

#[test]
fn fixed_run_jobs_artifact_and_zip_endpoints_are_fetched() {
    let urls = run_with(responses()).unwrap();
    assert_eq!(
        urls,
        [
            "https://api.github.com/repos/Portfoligno/memcordon/actions/runs/42/attempts/3",
            "https://api.github.com/repos/Portfoligno/memcordon/actions/runs/42/attempts/3/jobs?per_page=100",
            "https://api.github.com/repos/Portfoligno/memcordon/actions/runs/42/artifacts?per_page=100",
            "https://api.github.com/repos/Portfoligno/memcordon/actions/artifacts/71/zip",
        ]
    );
}

#[test]
fn incomplete_or_duplicated_artifact_inventory_is_rejected() {
    let mut incomplete = responses();
    incomplete[2]["total_count"] = json!(2);
    assert!(run_with(incomplete).unwrap_err().contains("incomplete"));

    let mut duplicated = responses();
    let artifact = duplicated[2]["artifacts"][0].clone();
    duplicated[2]["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(artifact);
    duplicated[2]["total_count"] = json!(2);
    assert!(run_with(duplicated).unwrap_err().contains("duplicated"));
}

#[test]
fn foreign_run_or_artifact_is_rejected_before_zip_fetch() {
    let mut foreign_run = responses();
    foreign_run[0]["head_sha"] = json!("b".repeat(40));
    assert!(run_with(foreign_run).unwrap_err().contains("origin"));

    let mut foreign_artifact = responses();
    foreign_artifact[2]["artifacts"][0]["workflow_run"]["id"] = json!(43);
    assert!(
        run_with(foreign_artifact)
            .unwrap_err()
            .contains("ownership")
    );
}

#[test]
fn repository_path_injection_and_zero_length_zip_are_rejected() {
    let mut invalid_origin = origin();
    invalid_origin.repository = "Portfoligno/memcordon/../other".into();
    let mut called = false;
    let error = read_actions_native_artifact_with(
        &invalid_origin,
        PRODUCERS[1],
        NonZeroU32::new(3).unwrap(),
        |_, _, _| {
            called = true;
            Ok(Vec::new())
        },
    )
    .err()
    .unwrap();
    assert!(!called);
    assert!(error.to_string().contains("repository/commit"));

    let metadata = responses();
    let mut index = 0;
    let error = read_actions_native_artifact_with(
        &origin(),
        PRODUCERS[1],
        NonZeroU32::new(3).unwrap(),
        |url, _, _| {
            if url.ends_with("/zip") {
                return Ok(Vec::new());
            }
            let bytes = serde_json::to_vec(&metadata[index]).unwrap();
            index += 1;
            Ok(bytes)
        },
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("empty or unbounded"));
}

#[test]
fn completed_reader_consumes_every_jobs_and_artifact_page() {
    let spec = PRODUCERS[1];
    let mut pages = Vec::new();
    let fetched = read_actions_native_artifact_with(
        &origin(),
        spec,
        NonZeroU32::new(3).unwrap(),
        |url, _, _| {
            pages.push(url.to_owned());
            if url.ends_with("/zip") {
                return Ok(vec![1, 2, 3]);
            }
            let response = if url.ends_with("/attempts/3") {
                responses()[0].clone()
            } else if url.contains("/jobs?") {
                let first = !url.contains("page=2");
                let jobs: Vec<_> = if first {
                    (1..=100)
                        .map(|id| json!({"id": id, "name": format!("other-{id}")}))
                        .collect()
                } else {
                    vec![json!({"id": 101, "name": spec.job_name})]
                };
                json!({"total_count": 101, "jobs": jobs})
            } else if url.contains("/artifacts?") {
                let first = !url.contains("page=2");
                let artifacts: Vec<_> = if first {
                    (1..=100)
                        .map(|id| json!({"id": id, "name": format!("other-{id}")}))
                        .collect()
                } else {
                    vec![json!({
                        "id": 171,
                        "name": spec.artifact_name,
                        "expired": false,
                        "workflow_run": {"id": 42}
                    })]
                };
                json!({"total_count": 101, "artifacts": artifacts})
            } else {
                panic!("unexpected Actions URL: {url}");
            };
            Ok(serde_json::to_vec(&response).unwrap())
        },
    )
    .unwrap();
    assert_eq!(fetched.artifact["id"], 171);
    assert_eq!(pages.len(), 6);
    assert!(
        pages
            .iter()
            .any(|url| url.ends_with("/jobs?per_page=100&page=2"))
    );
    assert!(
        pages
            .iter()
            .any(|url| url.ends_with("/artifacts?per_page=100&page=2"))
    );
}
