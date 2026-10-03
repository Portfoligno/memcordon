use memcordon_ci::release::{
    git::Git,
    source,
    tag::{self, TagEffect, TagPlan},
};
use std::{fs, path::Path};

fn repository() -> tempfile::TempDir {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("memcordon-tag-fixture-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::Builder::new()
        .prefix("memcordon-tag-fixture-")
        .tempdir()
        .unwrap();
    let git = Git::new(root.path()).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text(["config", "user.name", "Temporary tag fixture"])
        .unwrap();
    git.text(["config", "user.email", "fixture@example.invalid"])
        .unwrap();
    git.text([
        "commit",
        "--allow-empty",
        "--no-gpg-sign",
        "-m",
        "Fixture commit",
    ])
    .unwrap();
    root
}

fn plan(root: &Path) -> TagPlan {
    TagPlan {
        format: "memcordon.tag-plan".into(),
        revision: 1,
        repository: "example/repository".into(),
        version: "1.2.3".parse().unwrap(),
        commit: Git::new(root).unwrap().text(["rev-parse", "HEAD"]).unwrap(),
        observed_ref: None,
        local_tag_object: None,
        local_checks: vec!["not-run".into()],
    }
}

#[test]
fn recorded_commit_creates_unsigned_annotation_and_idempotent_exact_readback() {
    let root = repository();
    let git = Git::new(root.path()).unwrap();
    git.text(["config", "tag.gpgSign", "true"]).unwrap();
    let record = root.path().join("plan.json");
    let original = plan(root.path());
    source::write_json(&record, &original).unwrap();
    assert_eq!(
        tag::create(root.path(), &record).unwrap(),
        TagEffect::Created
    );
    let observed: TagPlan = source::read_json(&record).unwrap();
    let reference = observed.observed_ref.as_ref().unwrap();
    let actual = git.tag(reference).unwrap();
    assert_eq!(actual.commit, original.commit);
    assert_eq!(observed.local_tag_object.as_ref(), Some(&actual.object));
    assert_eq!(
        git.text(["cat-file", "-t", actual.object.as_str()])
            .unwrap(),
        "tag"
    );
    assert!(
        !git.text(["cat-file", "-p", actual.object.as_str()])
            .unwrap()
            .contains("BEGIN PGP SIGNATURE")
    );
    assert_eq!(
        tag::create(root.path(), &record).unwrap(),
        TagEffect::AlreadyPresent
    );
}

#[test]
fn abbreviated_or_noncommit_record_cannot_create_a_tag() {
    let root = repository();
    let record = root.path().join("plan.json");
    let mut shortened = plan(root.path());
    shortened.commit = shortened.commit.chars().take(8).collect();
    source::write_json(&record, &shortened).unwrap();
    assert!(tag::create(root.path(), &record).is_err());
    let git = Git::new(root.path()).unwrap();
    fs::write(root.path().join("blob"), b"not a commit\n").unwrap();
    let mut blob = plan(root.path());
    blob.commit = git.text(["hash-object", "-w", "blob"]).unwrap();
    source::write_json(&record, &blob).unwrap();
    assert!(tag::create(root.path(), &record).is_err());
    assert!(git.tags().unwrap().is_empty());
}

#[test]
fn preexisting_or_replaced_tag_is_never_adopted_or_overwritten() {
    let root = repository();
    let git = Git::new(root.path()).unwrap();
    let record = root.path().join("plan.json");
    source::write_json(&record, &plan(root.path())).unwrap();
    git.text(["tag", "1.2.3"]).unwrap();
    let before = git.tag("refs/tags/1.2.3").unwrap().object;
    assert!(tag::create(root.path(), &record).is_err());
    assert_eq!(git.tag("refs/tags/1.2.3").unwrap().object, before);
    git.text(["tag", "--delete", "1.2.3"]).unwrap();
    assert_eq!(
        tag::create(root.path(), &record).unwrap(),
        TagEffect::Created
    );
    git.text(["tag", "--delete", "1.2.3"]).unwrap();
    assert!(tag::create(root.path(), &record).is_err());
    assert!(git.tags().unwrap().is_empty());
}

#[test]
fn native_git_status_disables_local_executable_helpers_and_detects_dirty_inputs() {
    let root = repository();
    let git = Git::new(root.path()).unwrap();
    git.text(["config", "core.fsmonitor", "forbidden-fsmonitor-helper"])
        .unwrap();
    git.require_clean().unwrap();
    fs::write(root.path().join("untracked-build-input"), b"changed\n").unwrap();
    git.text(["add", "--", "untracked-build-input"]).unwrap();
    assert!(git.require_clean().is_err());
}
