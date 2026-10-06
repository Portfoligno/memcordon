use memcordon_ci::release::{
    bundle::{NotesSelection, candidate_notes, changelog_notes},
    git::Git,
    preparation::{PreparationMode, read_build_source, select_event},
    source::{self, BuildSourceIdentity},
};
use serde_json::json;
use std::{fs, path::Path};

fn fixture() -> tempfile::TempDir {
    #[cfg(unix)]
    let directory = tempfile::Builder::new()
        .prefix("memcordon-preparation-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let directory = tempfile::Builder::new()
        .prefix("memcordon-preparation-")
        .tempdir()
        .unwrap();
    let root = directory.path();
    fs::create_dir(root.join("ci")).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/toolchains.toml"),
        root.join("ci/toolchains.toml"),
    )
    .unwrap();
    let names = [
        "memcordon-core",
        "memcordon-platform",
        "memcordon-windows-launch-core",
        "memcordon",
    ];
    fs::write(
        root.join("Cargo.toml"),
        format!("[workspace]\nresolver=\"3\"\nmembers={names:?}\n"),
    )
    .unwrap();
    for name in names {
        fs::create_dir_all(root.join(name).join("src")).unwrap();
        fs::write(root.join(name).join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        let dependency = if name == "memcordon-core" {
            String::new()
        } else {
            "[dependencies]\nmemcordon-core={path=\"../memcordon-core\",version=\"=1.2.3\"}\n"
                .into()
        };
        fs::write(
            root.join(name).join("Cargo.toml"),
            format!("[package]\nname={name:?}\nversion=\"1.2.3\"\nedition=\"2024\"\n{dependency}"),
        )
        .unwrap();
    }
    let git = Git::new(root).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text(["config", "user.name", "Preparation fixture"])
        .unwrap();
    git.text(["config", "user.email", "fixture@example.invalid"])
        .unwrap();
    git.text(["add", "."]).unwrap();
    git.text(["commit", "--no-gpg-sign", "-m", "Fixture source"])
        .unwrap();
    directory
}

#[test]
fn branch_and_tag_events_recheck_real_git_objects_and_conflicting_inputs() {
    let directory = fixture();
    let root = directory.path();
    let git = Git::new(root).unwrap();
    let sha = git.text(["rev-parse", "HEAD"]).unwrap();
    let branch = "refs/heads/1.2.3";
    let event = json!({"ref": branch, "after": sha, "deleted": false});
    let selected = select_event(root, "example/repository", "push", branch, &sha, &event).unwrap();
    assert_eq!(selected.mode, PreparationMode::Candidate);
    assert!(matches!(
        selected.build,
        BuildSourceIdentity::Working { .. }
    ));
    let mut wrong = event.clone();
    wrong["after"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(select_event(root, "example/repository", "push", branch, &sha, &wrong).is_err());
    wrong = event.clone();
    wrong["deleted"] = json!(true);
    assert!(select_event(root, "example/repository", "push", branch, &sha, &wrong).is_err());
    assert!(
        select_event(
            root,
            "example/repository",
            "push",
            branch,
            &sha[..8],
            &event
        )
        .is_err()
    );
    let dispatch = json!({"inputs":{"preparation-mode":"candidate", "recovery-mode":"reprepare"}});
    assert_eq!(
        select_event(
            root,
            "example/repository",
            "workflow_dispatch",
            branch,
            &sha,
            &dispatch
        )
        .unwrap()
        .mode,
        PreparationMode::Candidate
    );
    for field in [
        "tag",
        "original-run-id",
        "prepared-artifact-id",
        "tool-artifact-id",
    ] {
        let mut conflict = dispatch.clone();
        conflict["inputs"][field] = json!("1");
        assert!(
            select_event(
                root,
                "example/repository",
                "workflow_dispatch",
                branch,
                &sha,
                &conflict
            )
            .is_err()
        );
    }
    git.text(["tag", "1.2.3"]).unwrap();
    let tagged = json!({"ref":"refs/tags/1.2.3", "after":sha});
    assert_eq!(
        select_event(
            root,
            "example/repository",
            "push",
            "refs/tags/1.2.3",
            &sha,
            &tagged
        )
        .unwrap()
        .mode,
        PreparationMode::TaggedReprepare
    );
    let dispatch = json!({"inputs":{"preparation-mode":"release", "recovery-mode":"reprepare", "tag":"1.2.3"}});
    assert!(
        select_event(
            root,
            "example/repository",
            "workflow_dispatch",
            branch,
            &sha,
            &dispatch
        )
        .is_err()
    );
    assert!(
        select_event(
            root,
            "example/repository",
            "workflow_dispatch",
            "refs/tags/1.2.3",
            &sha,
            &dispatch
        )
        .is_ok()
    );
    git.text(["tag", "-d", "1.2.3"]).unwrap();
    git.text([
        "-c",
        "tag.gpgsign=false",
        "tag",
        "-a",
        "1.2.3",
        "-m",
        "Annotated fixture",
    ])
    .unwrap();
    let tagged =
        json!({"ref":"refs/tags/1.2.3", "after":git.tag("refs/tags/1.2.3").unwrap().object});
    assert!(
        select_event(
            root,
            "example/repository",
            "push",
            "refs/tags/1.2.3",
            &sha,
            &tagged
        )
        .is_ok()
    );
    fs::write(
        root.join("memcordon-core/src/lib.rs"),
        "pub fn changed() {}\n",
    )
    .unwrap();
    assert!(select_event(root, "example/repository", "push", branch, &sha, &event).is_err());
}

#[test]
fn annotated_tag_push_binds_payload_object_to_exact_ref_and_checkout_commit() {
    let directory = fixture();
    let root = directory.path();
    let git = Git::new(root).unwrap();
    let sha = git.text(["rev-parse", "HEAD"]).unwrap();
    git.text([
        "tag",
        "--annotate",
        "--no-sign",
        "--message",
        "Release",
        "--",
        "1.2.3",
        &sha,
    ])
    .unwrap();
    let reference = "refs/tags/1.2.3";
    let tag = git.tag(reference).unwrap();
    assert_ne!(tag.object, sha);
    let event = json!({
        "ref": reference,
        "before": "0000000000000000000000000000000000000000",
        "after": tag.object,
        "created": true,
        "deleted": false,
        "forced": false,
        "head_commit": {"id": sha},
    });
    let selected =
        select_event(root, "example/repository", "push", reference, &sha, &event).unwrap();
    assert_eq!(selected.mode, PreparationMode::TaggedReprepare);
    assert_eq!(selected.build.commit(), sha);

    git.text([
        "tag",
        "--annotate",
        "--no-sign",
        "--message",
        "Other tag",
        "--",
        "other",
        &sha,
    ])
    .unwrap();
    let other = git.tag("refs/tags/other").unwrap();
    let mut wrong = event.clone();
    wrong["after"] = json!(sha);
    assert!(select_event(root, "example/repository", "push", reference, &sha, &wrong).is_err());
    wrong["after"] = json!(other.object);
    assert!(select_event(root, "example/repository", "push", reference, &sha, &wrong).is_err());
    wrong["after"] = json!(git.text(["rev-parse", "HEAD^{tree}"]).unwrap());
    assert!(select_event(root, "example/repository", "push", reference, &sha, &wrong).is_err());
    wrong["after"] = json!("HEAD");
    assert!(select_event(root, "example/repository", "push", reference, &sha, &wrong).is_err());
    wrong["after"] = serde_json::Value::Null;
    assert!(select_event(root, "example/repository", "push", reference, &sha, &wrong).is_err());
    wrong = event.clone();
    wrong["ref"] = json!("refs/tags/other");
    assert!(select_event(root, "example/repository", "push", reference, &sha, &wrong).is_err());
    wrong = event.clone();
    wrong["deleted"] = json!(true);
    assert!(select_event(root, "example/repository", "push", reference, &sha, &wrong).is_err());
    let branch = "refs/heads/1.2.3";
    wrong = event.clone();
    wrong["ref"] = json!(branch);
    assert!(select_event(root, "example/repository", "push", branch, &sha, &wrong).is_err());
    assert!(
        select_event(
            root,
            "example/repository",
            "push",
            reference,
            &tag.object,
            &event
        )
        .is_err()
    );
}

#[test]
fn explicit_build_reader_rejects_ambiguity_and_malformed_input_without_fallback() {
    for command in ["verify-source", "packages", "build-target", "assemble"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
            .args([
                "release",
                command,
                "--source",
                "old.json",
                "--build-source",
                "new.json",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("build.json");
    fs::write(&path, b"{\"kind\":\"working\",\"kind\":\"tagged\"}\n").unwrap();
    assert!(read_build_source(Some(&path), Some(&path)).is_err());
    assert!(read_build_source(None, Some(&path)).is_err());
    let working = BuildSourceIdentity::Working {
        version: "1.2.3".parse().unwrap(),
        commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
    };
    source::write_json(&path, &working).unwrap();
    assert_eq!(read_build_source(None, Some(&path)).unwrap(), working);
}

#[test]
fn candidate_notes_dispositions_do_not_relax_tagged_exact_notes() {
    let directory = tempfile::tempdir().unwrap();
    let version = "1.2.3".parse().unwrap();
    let path = directory.path().join("CHANGELOG.md");
    for (text, expected) in [
        (
            "## [1.2.3]\nExact notes\n## Unreleased\nLater\n",
            NotesSelection::ExactVersion,
        ),
        (
            "## Unreleased\nDevelopment notes\n",
            NotesSelection::Unreleased,
        ),
        ("# Changelog\n", NotesSelection::Unavailable),
    ] {
        fs::write(&path, text).unwrap();
        let (selection, notes) = candidate_notes(directory.path(), &version).unwrap();
        assert_eq!(selection, expected);
        assert_eq!(notes.is_none(), expected == NotesSelection::Unavailable);
        assert_eq!(
            changelog_notes(directory.path(), &version).is_ok(),
            expected == NotesSelection::ExactVersion
        );
    }
    fs::write(path, "## [1.2.3]\n## Unreleased\nFallback forbidden\n").unwrap();
    assert!(candidate_notes(directory.path(), &version).is_err());
}
