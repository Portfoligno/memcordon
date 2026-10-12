#![cfg(unix)]
#[path = "../src/recovery_artifact_tree.rs"]
mod recovery_artifact_tree;
use sha2::Digest;
use std::fs;

#[test]
fn projection_preserves_exact_retained_parents_and_rejects_other_subtrees() {
    use std::path::Path;
    let case = Path::new("target/candidate-native/components/account-retirement");
    for leaf in [
        "native-input.json",
        "original-recovery-A1b2C3/stage.json",
        "original-recovery-A1b2C3/original-native-recovery-result.json",
    ] {
        let path = case.join(leaf);
        assert_eq!(
            recovery_artifact_tree::projected_parent(&path, case).unwrap(),
            path.parent().unwrap()
        );
    }
    for leaf in [
        "../escape",
        "original-recovery-/stage.json",
        "original-recovery-A_1/stage.json",
        "other/stage.json",
        "original-recovery-A1/unknown.json",
        "original-recovery-A1/nested/stage.json",
        ".hidden",
        "original-recovery-A1/../native-input.json",
    ] {
        assert!(
            recovery_artifact_tree::projected_parent(&case.join(leaf), case).is_err(),
            "{leaf}"
        );
    }
    assert!(
        recovery_artifact_tree::projected_parent(Path::new("elsewhere/native-input.json"), case)
            .is_err()
    );
}

fn original() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let attempt = "original-recovery-A1b2C3";
    let directory = root.path().join(attempt);
    fs::create_dir(&directory).unwrap();
    for leaf in [
        "origin.json",
        "input.json",
        "owner.json",
        "invocation.json",
        "process.json",
        "capture.json",
        "stdout.bin",
        "stderr.bin",
        "result.json",
    ] {
        fs::write(
            directory.join(format!("original-native-recovery-{leaf}")),
            b"original",
        )
        .unwrap();
    }
    let stage = "/owned/original-recovery-A1b2C3";
    let digest = hex::encode(sha2::Sha256::digest(b"original"));
    fs::write(
        directory.join("stage.json"),
        serde_json::to_vec(
            &serde_json::json!({"stage":stage,"input_sha256":digest,"origin_sha256":digest}),
        )
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.path().join("native-recovery-invocation.json"),
        serde_json::to_vec(&serde_json::json!({"working_directory":stage,"input_sha256":digest}))
            .unwrap(),
    )
    .unwrap();
    root
}

fn collect(root: &std::path::Path) -> Result<std::collections::BTreeMap<String, Vec<u8>>, String> {
    recovery_artifact_tree::collect(root, |path, _| {
        fs::read(path).map_err(|error| error.to_string())
    })
}

#[test]
fn retains_actual_attempt_records_and_refuses_unassociated_or_special_members() {
    let root = original();
    let records = collect(root.path()).unwrap();
    assert_eq!(records.len(), 11);
    assert_eq!(
        records["original-recovery-A1b2C3/original-native-recovery-result.json"],
        b"original"
    );
    fs::create_dir(root.path().join("unknown")).unwrap();
    assert!(collect(root.path()).is_err());
    let root = original();
    std::os::unix::fs::symlink(
        "original-native-recovery-result.json",
        root.path().join("original-recovery-A1b2C3/alias"),
    )
    .unwrap();
    assert!(collect(root.path()).is_err());
    let root = original();
    fs::write(
        root.path().join("native-recovery-invocation.json"),
        b"{\"working_directory\":\"/other/original-recovery-Wrong\",\"input_sha256\":\"input\"}",
    )
    .unwrap();
    assert!(collect(root.path()).is_err());
}

#[test]
fn refuses_missing_nested_records_extra_attempts_and_aggregate_count_overflow() {
    let root = original();
    fs::write(
        root.path()
            .join("original-recovery-A1b2C3/original-native-recovery-input.json"),
        b"substituted",
    )
    .unwrap();
    assert!(collect(root.path()).is_err());
    let root = original();
    fs::remove_file(
        root.path()
            .join("original-recovery-A1b2C3/original-native-recovery-result.json"),
    )
    .unwrap();
    assert!(collect(root.path()).is_err());
    let root = original();
    fs::create_dir(root.path().join("original-recovery-Other")).unwrap();
    assert!(collect(root.path()).is_err());
    let root = tempfile::tempdir().unwrap();
    for index in 0..129 {
        fs::write(root.path().join(index.to_string()), b"").unwrap();
    }
    assert!(collect(root.path()).is_err());
}
