#[path = "../build_support/mod.rs"]
mod build_support;

use std::path::Path;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER: &str = "abcdef0123456789abcdef0123456789abcdef01";

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn packaged_metadata_precedes_checkout_and_release() {
    use build_support::identity::select;
    let package = serde_json::to_vec(&serde_json::json!({"git":{"sha1":COMMIT,"dirty":true},"path_in_vcs":"crates/memcordon-cli"})).unwrap();
    let release =
        serde_json::to_vec(&serde_json::json!({"schema":1,"source_commit":OTHER})).unwrap();
    assert_eq!(
        select(Some(&package), Some(OTHER), Some(&release)).unwrap(),
        COMMIT
    );
    assert_eq!(select(None, Some(COMMIT), Some(&release)).unwrap(), COMMIT);
    assert_eq!(select(None, None, Some(&release)).unwrap(), OTHER);
    assert_eq!(select(None, None, None).unwrap(), "unknown");
    for bad in [
        b"{}".as_slice(),
        br#"{"git":{"sha1":"abc"}}"#,
        br#"{"git":{"sha1":"unknown"}}"#,
    ] {
        assert!(select(Some(bad), Some(COMMIT), Some(&release)).is_err());
    }
    let duplicate = format!(r#"{{"git":{{"sha1":"{COMMIT}","sha1":"{OTHER}"}}}}"#);
    assert!(select(Some(duplicate.as_bytes()), Some(COMMIT), None).is_err());
    assert!(
        select(
            None,
            None,
            Some(br#"{"schema":2,"source_commit":"unknown"}"#)
        )
        .is_err()
    );
}

#[test]
fn directory_checkout_detached_head_and_dirty_files_keep_exact_identity() {
    for detached in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let manifest = root.join("crates/application");
        std::fs::create_dir_all(&manifest).unwrap();
        write(
            &root.join(".git/HEAD"),
            if detached {
                COMMIT
            } else {
                "ref: refs/heads/main\n"
            },
        );
        write(&root.join(".git/refs/heads/main"), COMMIT);
        write(&manifest.join("tracked.rs"), "baseline source\n");
        assert_eq!(build_support::load(&manifest).unwrap().commit, COMMIT);
        write(&manifest.join("tracked.rs"), "dirty source\n");
        let identity = build_support::load(&manifest).unwrap();
        assert_eq!(
            identity.commit, COMMIT,
            "identity is not a clean-tree attestation"
        );
        assert!(identity.inputs.contains(&root.join(".git/HEAD")));
    }
}

#[test]
fn linked_worktree_resolves_common_loose_and_packed_refs() {
    for packed in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let manifest = root.join("worktree");
        write(
            &manifest.join(".git"),
            "gitdir: ../repository/.git/worktrees/linked\n",
        );
        let git = root.join("repository/.git/worktrees/linked");
        write(&git.join("HEAD"), "ref: refs/heads/work\n");
        write(&git.join("commondir"), "../..\n");
        if packed {
            write(
                &root.join("repository/.git/packed-refs"),
                format!("# pack-refs with: peeled\n{COMMIT} refs/heads/work\n"),
            );
        } else {
            write(&root.join("repository/.git/refs/heads/work"), COMMIT);
        }
        let identity = build_support::load(&manifest).unwrap();
        assert_eq!(identity.commit, COMMIT);
        let git = manifest.join("../repository/.git/worktrees/linked");
        assert!(identity.inputs.contains(&git.join("commondir")));
        assert!(identity.inputs.contains(&git.join("../../refs/heads/work")));
        assert!(identity.inputs.contains(&git.join("../../packed-refs")));
    }
}

#[test]
fn archives_use_explicit_release_metadata_and_reject_invalid_package_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    assert_eq!(build_support::load(root).unwrap().commit, "unknown");
    write(
        &root.join(".memcordon-source.json"),
        serde_json::to_vec(&serde_json::json!({"schema":1,"source_commit":COMMIT})).unwrap(),
    );
    assert_eq!(build_support::load(root).unwrap().commit, COMMIT);
    write(&root.join(".cargo_vcs_info.json"), [0xff]);
    assert!(build_support::load(root).is_err());
}

#[test]
fn exact_hashes_and_reference_paths_are_validated() {
    use build_support::identity::{reference, valid_commit};
    assert!(valid_commit(COMMIT));
    assert!(valid_commit(&"ab".repeat(32)));
    assert!(!valid_commit(&"00".repeat(20)));
    for value in [
        "",
        "unknown",
        "abc",
        "0123456789abcdef0123456789abcdef0123456g",
    ] {
        assert!(!valid_commit(value), "{value}");
    }
    for head in [
        "ref: ../HEAD",
        "ref: refs/../HEAD",
        "ref: refs//main",
        "ref: refs/heads\\main",
    ] {
        assert!(reference(head).is_none());
    }
    let packed = Some(format!("{COMMIT} refs/heads/main\n"));
    assert!(
        build_support::identity::resolve_head(
            "ref: refs/heads/main",
            &[Some("abcd".into())],
            &[packed],
        )
        .is_err(),
        "corrupt loose refs must not select an old packed identity"
    );
    for packed in [
        "abcd refs/heads/main\n".to_owned(),
        format!("{COMMIT} refs/heads/main\n{OTHER} refs/heads/main\n"),
    ] {
        assert!(
            build_support::identity::resolve_head("ref: refs/heads/main", &[], &[Some(packed)])
                .is_err()
        );
    }
    assert_eq!(
        build_support::identity::resolve_head("ref: refs/heads/unborn", &[], &[]).unwrap(),
        None
    );
}

#[test]
fn static_runtime_selection_follows_target_not_host() {
    for (os, environment, expected) in [
        ("windows", "msvc", true),
        ("windows", "gnu", false),
        ("linux", "gnu", false),
        ("linux", "musl", false),
        ("macos", "", false),
        ("linux", "msvc", false),
    ] {
        assert_eq!(
            build_support::runtime::static_msvc(os, environment),
            expected
        );
    }
}

#[test]
fn inherited_workflow_commit_cannot_override_checkout_files() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "directory_checkout_detached_head_and_dirty_files_keep_exact_identity",
        ])
        .env("GITHUB_SHA", "unrelated-workflow-metadata")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("1 passed")
    );
}
