use std::fs;
use std::path::Path;
use std::time::Duration;

use memcordon_ci::boundary_report::collect;
use memcordon_ci::command::CommandSpec;

fn git(root: &Path, arguments: &[&str]) {
    let output = CommandSpec::new("git", root, Duration::from_secs(30))
        .args(arguments.iter().copied())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn commit(root: &Path) {
    git(root, &["add", "."]);
    git(
        root,
        &[
            "-c",
            "user.name=Boundary Test",
            "-c",
            "user.email=boundary@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "fixture",
        ],
    );
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir_all(root.join("ci/source-presence")).unwrap();
    fs::create_dir_all(root.join("crates/sample/src")).unwrap();
    fs::write(
        root.join("crates/sample/src/alpha.rs"),
        "fn first() { second(); } fn second() {}\n",
    )
    .unwrap();
    fs::write(
        root.join("crates/sample/src/beta.rs"),
        "use crate::alpha::first;\n",
    )
    .unwrap();
    fs::write(
        root.join("ci/source-presence/core.toml"),
        r#"
schema = 1
[[source]]
id = "alpha"
path = "crates/sample/src/alpha.rs"
owner = "core"
kind = "production"
visibility = "binary-private"
disposition = "retain"
protected_invariants = ["sample"]
consumers = ["sample"]
routes = ["sample"]
cfg = []
item_visibility = []
platforms = ["portable"]
work_packages = ["GOV-06"]
decision = "review pending"
[[source]]
id = "beta"
path = "crates/sample/src/beta.rs"
owner = "core"
kind = "production"
visibility = "binary-private"
disposition = "retain"
protected_invariants = ["sample"]
consumers = ["sample"]
routes = ["sample"]
cfg = []
item_visibility = []
platforms = ["portable"]
work_packages = ["GOV-01"]
decision = "retained"
"#,
    )
    .unwrap();
    git(root, &["init", "--quiet"]);
    commit(root);
    directory
}

#[test]
fn report_binds_real_git_history_and_ignores_untracked_content() {
    let directory = fixture();
    let root = directory.path();
    fs::write(root.join("crates/sample/src/untracked.rs"), [0xff, 0xfe]).unwrap();
    fs::write(
        root.join("ci/source-presence/untracked.toml"),
        "not valid TOML {",
    )
    .unwrap();
    let first = collect(root, 8).unwrap();
    assert!(!first.tracked_dirty);
    assert_eq!(first.candidates.len(), 1);
    assert_eq!(first.source_sha256.len(), 2);
    assert_eq!(first.registry_sha256.len(), 1);
    assert_eq!(first.producer.algorithm, "memcordon-boundary-metrics-v1");
    assert_eq!(first.producer.collector_source_sha256.len(), 64);
    assert_eq!(first.producer.metrics_source_sha256.len(), 64);
    assert_eq!(first.history.len(), 1);
    assert!(!first.history_truncated);
    assert!(!first.shallow_repository);
    assert_eq!(
        first.candidates[0].metrics.cochanges["crates/sample/src/beta.rs"],
        1
    );
    let second = collect(root, 8).unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    fs::write(root.join("crates/sample/src/alpha.rs"), "fn changed() {}\n").unwrap();
    let dirty = collect(root, 8).unwrap();
    assert!(dirty.tracked_dirty);
    assert_eq!(first.head, dirty.head);
    assert_ne!(
        first.source_sha256["crates/sample/src/alpha.rs"],
        dirty.source_sha256["crates/sample/src/alpha.rs"]
    );
    assert_ne!(first.tracked_status_sha256, dirty.tracked_status_sha256);
}

#[test]
fn tracked_unregistered_content_is_reported_without_parsing_and_history_is_bounded() {
    let directory = fixture();
    let root = directory.path();
    fs::write(root.join("crates/sample/src/unregistered.rs"), [0xff]).unwrap();
    fs::write(root.join("crates/sample/src/alpha.rs"), "fn changed() {}\n").unwrap();
    commit(root);
    let report = collect(root, 1).unwrap();
    assert!(report.history_truncated);
    assert_eq!(report.history.len(), 1);
    assert!(report.candidates[0].metrics.cochanges.is_empty());
    assert!(
        report
            .unregistered_tracked_sources
            .contains("crates/sample/src/unregistered.rs")
    );
    assert_eq!(report.source_sha256.len(), 2);
    assert!(collect(root, 0).is_err());
    assert!(collect(root, 1001).is_err());
}

#[test]
fn shallow_history_is_disclosed() {
    let origin = fixture();
    fs::write(
        origin.path().join("crates/sample/src/alpha.rs"),
        "fn changed() {}\n",
    )
    .unwrap();
    commit(origin.path());
    let destination = tempfile::tempdir().unwrap();
    git(
        destination.path(),
        &[
            "clone",
            "--quiet",
            "--no-local",
            "--depth",
            "1",
            origin.path().to_str().unwrap(),
            "checkout",
        ],
    );
    let report = collect(&destination.path().join("checkout"), 8).unwrap();
    assert!(report.shallow_repository);
    assert_eq!(report.history.len(), 1);
    assert!(!report.history_truncated);
    assert!(
        report
            .shallow_boundary_commits
            .contains(&report.history[0].commit)
    );
    assert!(!report.history[0].parent_comparison_available);
    assert!(report.candidates[0].metrics.cochanges.is_empty());
}

#[test]
fn output_cannot_overwrite_tracked_inputs() {
    let directory = fixture();
    let root = directory.path();
    let source = root.join("crates/sample/src/alpha.rs");
    let before = fs::read(&source).unwrap();
    assert!(
        memcordon_ci::boundary_report::write(root, &source, 8)
            .unwrap_err()
            .to_string()
            .contains("overwrite")
    );
    assert_eq!(fs::read(&source).unwrap(), before);
    let registry = root.join("ci/source-presence/core.toml");
    assert!(memcordon_ci::boundary_report::write(root, &registry, 8).is_err());
}

#[test]
fn atomic_output_replaces_a_hardlink_without_changing_source_content() {
    let directory = fixture();
    let root = directory.path();
    let source = root.join("crates/sample/src/alpha.rs");
    let output = root.join("report.json");
    fs::hard_link(&source, &output).unwrap();
    let before = fs::read(&source).unwrap();
    memcordon_ci::boundary_report::write(root, &output, 8).unwrap();
    assert_eq!(fs::read(&source).unwrap(), before);
    let report: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(report["candidates"].as_array().unwrap().len(), 1);
}

#[test]
fn replacement_history_is_ignored_and_graft_metadata_is_rejected() {
    let directory = fixture();
    let root = directory.path();
    let original = collect(root, 8).unwrap();
    fs::write(root.join("crates/sample/src/alpha.rs"), "fn changed() {}\n").unwrap();
    commit(root);
    let second = collect(root, 8).unwrap();
    git(root, &["replace", &second.head, &original.head]);
    let replaced = collect(root, 8).unwrap();
    assert_eq!(
        serde_json::to_vec(&second.history).unwrap(),
        serde_json::to_vec(&replaced.history).unwrap()
    );
    fs::write(root.join(".git/info/grafts"), &second.head).unwrap();
    assert!(collect(root, 8).unwrap_err().to_string().contains("graft"));
}

#[test]
fn deleted_context_sources_are_disclosed_but_missing_candidates_fail() {
    let directory = fixture();
    let root = directory.path();
    fs::remove_file(root.join("crates/sample/src/beta.rs")).unwrap();
    let report = collect(root, 8).unwrap();
    assert!(
        report
            .excluded_deleted_registry_sources
            .contains("crates/sample/src/beta.rs")
    );
    assert_eq!(report.source_sha256.len(), 1);
    fs::remove_file(root.join("crates/sample/src/alpha.rs")).unwrap();
    assert!(
        collect(root, 8)
            .unwrap_err()
            .to_string()
            .contains("candidate is missing")
    );
}

#[cfg(unix)]
#[test]
fn tracked_symlink_sources_are_rejected() {
    let directory = fixture();
    let root = directory.path();
    let source = root.join("crates/sample/src/alpha.rs");
    fs::remove_file(&source).unwrap();
    std::os::unix::fs::symlink("beta.rs", source).unwrap();
    let error = collect(root, 8).unwrap_err().to_string();
    assert!(error.contains("symlink"), "{error}");
}
