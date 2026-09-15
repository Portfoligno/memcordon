use memcordon_ci::source_registry::hosted::{
    Admission, Artifact, Job, WorkflowRun, validate_archive, validate_emitter, validate_run,
};
use memcordon_ci::source_registry::observation::Attestation;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};

const COMMIT: &str = "4ed12cd5b7c476797b7b324b13b116c113db56e6";

#[test]
fn collection_workflows_require_origin_jobs_and_fail_closed_execution() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let policy = memcordon_ci::config::policy(&root).unwrap();
    for workflow in ["ci.yml", "backend-certification.yml", "deep-ci.yml"] {
        let path = std::path::Path::new(".github/workflows").join(workflow);
        let bytes = std::fs::read(root.join(&path)).unwrap();
        memcordon_ci::policy::validate_workflow_bytes(&root, &path, &bytes, &policy).unwrap();
        let original: serde_yaml::Value = serde_yaml::from_slice(&bytes).unwrap();
        for mutation in ["dependency", "permissions", "skip", "continue"] {
            let mut document = original.clone();
            let job = &mut document["jobs"]["source-evidence"];
            match mutation {
                "dependency" => job["needs"] = "unrelated".into(),
                "permissions" => job["permissions"]["actions"] = "write".into(),
                "skip" | "continue" => {
                    let step = job["steps"]
                        .as_sequence_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|step| {
                            step["name"].as_str() == Some("Collect and verify source execution")
                        })
                        .unwrap();
                    if mutation == "skip" {
                        step["if"] = "false".into();
                    } else {
                        step["continue-on-error"] = true.into();
                    }
                }
                _ => unreachable!(),
            }
            assert!(
                memcordon_ci::policy::validate_workflow_bytes(
                    &root,
                    &path,
                    serde_yaml::to_string(&document).unwrap().as_bytes(),
                    &policy,
                )
                .is_err(),
                "{workflow} accepted collection mutation {mutation}"
            );
        }
        if workflow != "ci.yml" {
            let mut document = original;
            let job = if workflow == "deep-ci.yml" {
                "stress"
            } else {
                "windows-package-channel"
            };
            let upload = document["jobs"][job]["steps"]
                .as_sequence_mut()
                .unwrap()
                .iter_mut()
                .find(|step| step["name"].as_str() == Some("Upload source execution observations"))
                .unwrap();
            upload["with"]["path"] = "target/ci/unrelated".into();
            let error = memcordon_ci::policy::validate_workflow_bytes(
                &root,
                &path,
                serde_yaml::to_string(&document).unwrap().as_bytes(),
                &policy,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("source observation upload differs")
            );
        }
    }
}

fn run() -> WorkflowRun {
    serde_json::from_value(json!({
        "id": 123, "run_attempt": 2, "head_sha": COMMIT,
        "path": ".github/workflows/ci.yml", "name": "CI", "event": "push",
        "status": "completed", "conclusion": "success",
        "repository": {"id": 456, "full_name": "owner/repo"}
    }))
    .unwrap()
}

fn artifact(bytes: &[u8]) -> Artifact {
    let digest = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    serde_json::from_value(json!({
        "id": 789, "name": "source-observations-native-0", "size_in_bytes": bytes.len(),
        "digest": (["sha256:", &digest].concat()), "expired": false,
        "workflow_run": {"id": 123, "repository_id": 456, "head_sha": COMMIT}
    }))
    .unwrap()
}

fn job() -> Job {
    serde_json::from_value(json!({
        "id": 999, "run_id": 123, "run_attempt": 2, "head_sha": COMMIT,
        "name": "Native (windows-arm64)", "status": "completed", "conclusion": "success",
        "runner_name": "GitHub Actions 42", "runner_id": 42, "labels": ["windows-11-arm"]
    }))
    .unwrap()
}

fn attestation() -> Attestation {
    serde_json::from_value(json!({
        "schema": 1, "commit": COMMIT, "suite": "native", "workflow": "CI",
        "run_id": "123", "run_attempt": "2", "job": "native",
        "runner": "windows-arm64", "runner_name": "GitHub Actions 42",
        "journal_sha256": "opaque-for-emitter-test", "toolchains": ["stable"],
        "sources": [], "conclusion": "success"
    }))
    .unwrap()
}

#[test]
fn release_requires_successful_exact_repository_workflow_and_commit() {
    let check = |run: &WorkflowRun| {
        validate_run(
            run,
            "owner/repo",
            ".github/workflows/ci.yml",
            COMMIT,
            Admission::Completed,
        )
    };
    check(&run()).unwrap();
    for field in ["repository", "path", "head_sha", "status", "conclusion"] {
        let mut value = serde_json::to_value(run()).unwrap();
        if field == "repository" {
            value[field]["full_name"] = json!("fork/repo");
        } else {
            value[field] = json!("wrong");
        }
        assert!(
            check(&serde_json::from_value(value).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut current = run();
    current.status = "in_progress".into();
    current.conclusion = None;
    assert!(check(&current).is_err());
    validate_run(
        &current,
        "owner/repo",
        ".github/workflows/ci.yml",
        COMMIT,
        Admission::Current {
            run_id: 123,
            checkout: COMMIT,
        },
    )
    .unwrap();
    current.event = "pull_request".into();
    current.head_sha = "a3944bbfeb9c3768b4acf8de0e21efeabaf12ae8".into();
    validate_run(
        &current,
        "owner/repo",
        ".github/workflows/ci.yml",
        COMMIT,
        Admission::Current {
            run_id: 123,
            checkout: COMMIT,
        },
    )
    .unwrap();
    assert!(
        validate_run(
            &current,
            "owner/repo",
            ".github/workflows/ci.yml",
            COMMIT,
            Admission::Current {
                run_id: 124,
                checkout: COMMIT
            }
        )
        .is_err()
    );
    current.status = "completed".into();
    current.conclusion = Some("success".into());
    assert!(check(&current).is_err());
}

#[test]
fn artifacts_require_authenticated_digest_size_and_same_run_repository() {
    let bytes = b"opaque downloaded archive";
    validate_archive(&artifact(bytes), &run(), bytes).unwrap();
    assert!(validate_archive(&artifact(bytes), &run(), b"changed downloaded archive").is_err());
    for field in ["digest", "expired", "size_in_bytes", "workflow_run"] {
        let mut value = serde_json::to_value(artifact(bytes)).unwrap();
        match field {
            "digest" => value[field] = json!(null),
            "expired" => value[field] = json!(true),
            "size_in_bytes" => value[field] = json!(1),
            _ => value[field]["id"] = json!(124),
        }
        assert!(
            validate_archive(&serde_json::from_value(value).unwrap(), &run(), bytes).is_err(),
            "{field}"
        );
    }
}

#[test]
fn native_emitter_requires_unique_successful_job_from_current_attempt() {
    let artifact = artifact(b"archive");
    assert_eq!(
        validate_emitter(&run(), &[job()], &artifact, &attestation()).unwrap(),
        999
    );
    assert!(validate_emitter(&run(), &[job(), job()], &artifact, &attestation()).is_err());
    for field in [
        "run_attempt",
        "run_id",
        "head_sha",
        "runner_name",
        "conclusion",
    ] {
        let mut value = serde_json::to_value(job()).unwrap();
        value[field] = if field == "run_attempt" || field == "run_id" {
            json!(1)
        } else {
            json!("wrong")
        };
        assert!(
            validate_emitter(
                &run(),
                &[serde_json::from_value(value).unwrap()],
                &artifact,
                &attestation()
            )
            .is_err(),
            "{field}"
        );
    }
    let mut stale = attestation();
    stale.run_attempt = "1".into();
    assert!(validate_emitter(&run(), &[job()], &artifact, &stale).is_err());
    let mut other_artifact = artifact;
    other_artifact.name = "source-observations-other-0".into();
    assert!(validate_emitter(&run(), &[job()], &other_artifact, &attestation()).is_err());
}

fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[test]
fn zip_reader_rejects_traversal_size_limits_and_absent_journals() {
    use memcordon_ci::source_registry::hosted::read_journals;
    let valid = archive(&[(
        "native/run-unique/source-command-observations-v1.json",
        b"{}",
    )]);
    assert_eq!(
        read_journals(&valid, 4096, 10).unwrap(),
        vec![b"{}".to_vec()]
    );
    assert!(read_journals(&valid, 1, 10).is_err());
    assert!(read_journals(&valid, 4096, 0).is_err());
    for path in [
        "../source-command-observations-v1.json",
        "/source-command-observations-v1.json",
        "native\\source-command-observations-v1.json",
        "native/no-journal.json",
    ] {
        assert!(
            read_journals(&archive(&[(path, b"{}")]), 4096, 10).is_err(),
            "{path}"
        );
    }
}

#[test]
fn workflow_lane_identity_comes_from_exact_matrix_not_runner_claim() {
    use memcordon_ci::source_registry::hosted_client::{Lane, resolve_lane};
    let workflow = "jobs:\n  native:\n    name: native / ${{ matrix.id }}\n    runs-on: ${{ matrix.runner }}\n    steps:\n      - run: ./controller suite native\n    strategy:\n      matrix:\n        include:\n          - id: windows-x64\n            runner: windows-2025\n          - id: windows-arm64\n            runner: windows-11-arm\n";
    let lane = Lane {
        suite: "native".into(),
        workflow: ".github/workflows/ci.yml".into(),
        job: "native".into(),
        matrix: "windows-arm64".into(),
        runner: "windows-arm64".into(),
    };
    let resolved = resolve_lane(&lane, workflow).unwrap();
    assert_eq!(resolved.job_name, "native / windows-arm64");
    assert_eq!(resolved.runner_label, "windows-11-arm");
    assert_eq!(resolved.artifact_name, "source-observations-native-1");
    assert!(resolve_lane(&lane, &workflow.replace("windows-arm64", "windows-other")).is_err());
    assert!(
        resolve_lane(
            &lane,
            &workflow.replace("runs-on: ${{ matrix.runner }}", "runs-on: ubuntu-latest")
        )
        .is_err()
    );
}

#[test]
fn checked_in_lanes_cover_every_declared_suite_and_architecture() {
    use memcordon_ci::source_registry::hosted_client::{
        Lane, resolve_lane, validate_lane_coverage,
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let value: toml::Value =
        toml::from_str(&std::fs::read_to_string(root.join("ci/source-execution.toml")).unwrap())
            .unwrap();
    let lanes: Vec<Lane> = value["lane"].clone().try_into().unwrap();
    let sources = memcordon_ci::source_registry::read(&root).unwrap();
    validate_lane_coverage(&lanes, &sources).unwrap();
    for lane in &lanes {
        resolve_lane(
            lane,
            &std::fs::read_to_string(root.join(&lane.workflow)).unwrap(),
        )
        .unwrap();
    }
    assert!(validate_lane_coverage(&lanes[1..], &sources).is_err());
    let mut duplicates: Vec<Lane> = value["lane"].clone().try_into().unwrap();
    duplicates.push(value["lane"][0].clone().try_into().unwrap());
    assert!(validate_lane_coverage(&duplicates, &sources).is_err());
}

#[test]
fn archived_native_evidence_requires_actual_execution_and_authenticated_lane() {
    use memcordon_ci::source_registry::coverage::{
        Coverage, Evidence, Plan, PlannedSource, SkipPolicy,
    };
    use memcordon_ci::source_registry::hosted::{
        ExpectedLane, ExpectedRun, HostedArchive, attest_archive,
    };
    use memcordon_ci::source_registry::observation::{Invocation, digest};
    let plan = Plan {
        schema: 1,
        commit: COMMIT.into(),
        suite: "native".into(),
        sources: vec![PlannedSource {
            source_id: "reviewed-source".into(),
            route: Coverage {
                suite: "native".into(),
                cargo_package: "fixture".into(),
                cargo_target: "test:contract".into(),
                test_binary: "contract".into(),
                tests: vec!["reject".into()],
                runner: vec!["windows-arm64".into()],
                skip_policy: SkipPolicy::Forbidden,
                evidence: Evidence::Behavior,
            },
        }],
    };
    let invocation: Invocation = serde_json::from_value(json!({"program": {"display": "cargo", "raw": null}, "arguments": [], "current_directory": null})).unwrap();
    let execution = json!({"schema": 1, "binary": "contract.exe", "binary_sha256": "binary", "arguments": [], "listed_tests": ["reject"], "selected_tests": ["reject"], "ignored_tests": [], "executed_tests": ["reject"], "stdout_sha256": "stdout", "stderr_sha256": "stderr", "success": true});
    let bound = json!({"package_id": "fixture", "package_name": "fixture", "manifest_path": "Cargo.toml", "target_name": "contract", "target_kinds": ["test"], "features": [], "execution": execution});
    let observed = json!({"invocation": invocation, "command_sha256": digest(&serde_json::to_vec(&invocation).unwrap()), "toolchain": "stable", "stdout_sha256": "stdout", "stderr_sha256": "stderr", "exit_code": 0, "success": true, "error": null, "native_executions": [bound]});
    let mut journal = json!({
        "schema": 1, "commit": COMMIT, "checkout_clean": true, "suite": "native", "workflow": "CI", "run_id": "123", "run_attempt": "2", "job": "native", "runner": "GitHub Actions 42", "architecture": "aarch64", "platform": "windows", "execution_attested": false, "suite_success": true, "native_invocations": 1,
        "observations": [observed]
    });
    let origin = ExpectedRun {
        repository: "owner/repo",
        workflow_path: ".github/workflows/ci.yml",
        admission: Admission::Completed,
    };
    let lane = ExpectedLane {
        job: "native",
        job_name: "Native (windows-arm64)",
        runner: "windows-arm64",
        runner_label: "windows-11-arm",
    };
    let check = |journal: &serde_json::Value, jobs: &[Job]| {
        let bytes = archive(&[(
            "native/run/source-command-observations-v1.json",
            &serde_json::to_vec(journal).unwrap(),
        )]);
        attest_archive(
            &plan,
            &origin,
            &lane,
            &HostedArchive {
                run: &run(),
                jobs,
                artifact: &artifact(&bytes),
                bytes: &bytes,
            },
            65536,
        )
    };
    assert_eq!(check(&journal, &[job()]).unwrap().sources[0].tests.len(), 1);
    let mut wrong_runner = job();
    wrong_runner.labels = vec!["windows-2025".into()];
    assert!(check(&journal, &[wrong_runner]).is_err());
    journal["observations"][0]["native_executions"][0]["execution"]["executed_tests"] = json!([]);
    assert!(check(&journal, &[job()]).is_err());
}
