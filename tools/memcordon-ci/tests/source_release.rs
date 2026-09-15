use memcordon_ci::source_registry::hosted::WorkflowRun;
use memcordon_ci::source_registry::hosted_client::{
    Lane, RELEASE_WORKFLOWS, select_release_run, validate_release_checkout,
    validate_release_workflows, validate_selected_run,
};
use serde_json::json;

const COMMIT: &str = "8abcb264604c7b925cda1ce3fa0a436a4749b686";
const REPOSITORY: &str = "owner/repository";

fn git(root: &std::path::Path, arguments: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(root)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn release_checkout_rejects_dirty_configuration_and_changed_head() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "--quiet"]);
    git(root, &["config", "user.name", "Source admission fixture"]);
    git(
        root,
        &["config", "user.email", "source-fixture@example.invalid"],
    );
    git(root, &["config", "commit.gpgsign", "false"]);
    std::fs::create_dir(root.join("hooks")).unwrap();
    let configured = std::process::Command::new("git")
        .current_dir(root)
        .args(["config", "core.hooksPath"])
        .arg(root.join("hooks"))
        .status()
        .unwrap();
    assert!(configured.success());
    std::fs::write(root.join("source-execution.toml"), "schema = 1\n").unwrap();
    git(root, &["add", "source-execution.toml"]);
    git(
        root,
        &["commit", "--quiet", "--message", "Release evidence fixture"],
    );
    let original = git(root, &["rev-parse", "HEAD"]);
    validate_release_checkout(root, &original).unwrap();
    std::fs::write(root.join("source-execution.toml"), "schema = 2\n").unwrap();
    let error = validate_release_checkout(root, &original).unwrap_err();
    assert!(error.to_string().contains("unchanged clean checkout"));
    git(root, &["add", "source-execution.toml"]);
    git(
        root,
        &[
            "commit",
            "--quiet",
            "--message",
            "Changed source configuration",
        ],
    );
    let error = validate_release_checkout(root, &original).unwrap_err();
    assert!(error.to_string().contains("commit differs from checkout"));
    let current = git(root, &["rev-parse", "HEAD"]);
    validate_release_checkout(root, &current).unwrap();
}

fn run(number: u64, status: &str, conclusion: Option<&str>) -> WorkflowRun {
    serde_json::from_value(json!({
        "id": number, "run_number": number, "run_attempt": 1,
        "head_sha": COMMIT, "path": RELEASE_WORKFLOWS[0], "name": "CI",
        "event": "push", "status": status, "conclusion": conclusion,
        "repository": { "id": 1, "full_name": REPOSITORY }
    }))
    .unwrap()
}

#[test]
fn release_selects_newest_run_without_falling_back_to_green() {
    for (status, conclusion) in [
        ("queued", None),
        ("in_progress", None),
        ("completed", Some("failure")),
        ("completed", Some("cancelled")),
        ("completed", Some("skipped")),
    ] {
        let runs = [
            run(1, "completed", Some("success")),
            run(2, status, conclusion),
        ];
        assert!(select_release_run(&runs, REPOSITORY, RELEASE_WORKFLOWS[0], COMMIT).is_err());
    }
    let runs = [
        run(2, "completed", Some("success")),
        run(1, "completed", Some("failure")),
    ];
    assert_eq!(
        select_release_run(&runs, REPOSITORY, RELEASE_WORKFLOWS[0], COMMIT)
            .unwrap()
            .id,
        2
    );
    assert!(select_release_run(&[], REPOSITORY, RELEASE_WORKFLOWS[0], COMMIT).is_err());
}

#[test]
fn release_rejects_wrong_identity_and_ambiguous_inventory() {
    for field in ["commit", "workflow", "repository", "number", "attempt"] {
        let mut record = run(1, "completed", Some("success"));
        match field {
            "commit" => record.head_sha = "a".repeat(COMMIT.len()),
            "workflow" => record.path = RELEASE_WORKFLOWS[1].into(),
            "repository" => record.repository.full_name = "foreign/repository".into(),
            "number" => record.run_number = 0,
            "attempt" => record.run_attempt = 0,
            _ => unreachable!(),
        }
        assert!(
            select_release_run(&[record], REPOSITORY, RELEASE_WORKFLOWS[0], COMMIT).is_err(),
            "{field}"
        );
    }
    let duplicate = [
        run(1, "completed", Some("success")),
        run(1, "completed", Some("success")),
    ];
    assert!(select_release_run(&duplicate, REPOSITORY, RELEASE_WORKFLOWS[0], COMMIT).is_err());
}

#[test]
fn release_selection_cannot_change_during_archive_collection() {
    let before = run(1, "completed", Some("success"));
    validate_selected_run(&before, &run(1, "completed", Some("success"))).unwrap();
    for field in [
        "id",
        "number",
        "attempt",
        "commit",
        "workflow",
        "repository",
        "status",
        "conclusion",
    ] {
        let mut after = run(1, "completed", Some("success"));
        match field {
            "id" => after.id += 1,
            "number" => after.run_number += 1,
            "attempt" => after.run_attempt += 1,
            "commit" => after.head_sha = "a".repeat(COMMIT.len()),
            "workflow" => after.path = RELEASE_WORKFLOWS[1].into(),
            "repository" => after.repository.id += 1,
            "status" => after.status = "in_progress".into(),
            "conclusion" => after.conclusion = Some("failure".into()),
            _ => unreachable!(),
        }
        assert!(validate_selected_run(&before, &after).is_err(), "{field}");
    }
}

#[test]
fn release_requires_all_three_workflow_families() {
    let mut lanes = RELEASE_WORKFLOWS
        .iter()
        .map(|workflow| Lane {
            workflow: (*workflow).into(),
            suite: "native".into(),
            job: "native".into(),
            matrix: "windows-arm64".into(),
            runner: "windows/arm64".into(),
        })
        .collect::<Vec<_>>();
    validate_release_workflows(&lanes).unwrap();
    lanes.pop();
    assert!(validate_release_workflows(&lanes).is_err());
    lanes[0].workflow = ".github/workflows/release.yml".into();
    assert!(validate_release_workflows(&lanes).is_err());
}

#[test]
fn release_preflight_requires_read_only_authenticated_unconditional_admission() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = std::path::Path::new(".github/workflows/release.yml");
    let policy = memcordon_ci::config::policy(&root).unwrap();
    let bytes = std::fs::read(root.join(path)).unwrap();
    memcordon_ci::policy::validate_workflow_bytes(&root, path, &bytes, &policy).unwrap();
    let original: serde_yaml::Value = serde_yaml::from_slice(&bytes).unwrap();
    for mutation in ["permissions", "token", "skip", "continue", "command"] {
        let mut document = original.clone();
        let job = &mut document["jobs"]["preflight"];
        if mutation == "permissions" {
            job["permissions"]["actions"] = "write".into();
        } else {
            let step = job["steps"]
                .as_sequence_mut()
                .unwrap()
                .iter_mut()
                .find(|step| {
                    step["name"].as_str() == Some("Verify release source evidence and preflight")
                })
                .unwrap();
            match mutation {
                "token" => step["env"]["GITHUB_TOKEN"] = "untrusted".into(),
                "skip" => step["if"] = "false".into(),
                "continue" => step["continue-on-error"] = true.into(),
                "command" => step["run"] = "cargo --version".into(),
                _ => unreachable!(),
            }
        }
        assert!(
            memcordon_ci::policy::validate_workflow_bytes(
                &root,
                path,
                serde_yaml::to_string(&document).unwrap().as_bytes(),
                &policy
            )
            .is_err(),
            "{mutation}"
        );
    }
}
