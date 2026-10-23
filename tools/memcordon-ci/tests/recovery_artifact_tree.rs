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
        recovery_artifact_tree::LIFECYCLE_RECOVERY_OWNER_PRECONDITION,
        recovery_artifact_tree::LIFECYCLE_RECOVERY_DIAGNOSTIC_INVENTORY,
        "original-recovery-A1b2C3/stage.json",
        "original-recovery-A1b2C3/original-native-recovery-result.json",
        "original-recovery-A1b2C3/original-native-recovery-failure.json",
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

#[test]
fn failed_operation_is_exported_diagnostically_but_never_a_complete_success_attempt() {
    let root = original();
    let directory = root.path().join("original-recovery-A1b2C3");
    let leaf = "original-native-recovery-failure.json";
    fs::write(directory.join(leaf), b"retained failed-operation evidence").unwrap();
    fs::remove_file(directory.join("original-native-recovery-result.json")).unwrap();
    let (files, issues) =
        recovery_artifact_tree::collect_diagnostic_attempts(root.path(), |path, _| {
            fs::read(path).map_err(|error| error.to_string())
        })
        .unwrap();
    assert_eq!(
        files[&format!("original-recovery-A1b2C3/{leaf}")],
        b"retained failed-operation evidence"
    );
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("result.json: absent"))
    );
    assert!(
        collect(root.path()).is_err(),
        "diagnostic failure must not widen the strict success selector"
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
fn diagnostic_inventory_preserves_all_attempts_and_explicit_missing_receipts() {
    let root = original();
    fs::write(
        root.path()
            .join(recovery_artifact_tree::LIFECYCLE_RECOVERY_OWNER_PRECONDITION),
        b"selected held owners retired",
    )
    .unwrap();
    let (_, initial_issues) =
        recovery_artifact_tree::collect_diagnostic_attempts(root.path(), |path, _| {
            fs::read(path).map_err(|error| error.to_string())
        })
        .unwrap();
    assert!(
        !initial_issues
            .iter()
            .any(|issue| issue.contains("original-native-recovery-failure.json: absent")),
        "successful attempt has no failed-operation diagnostic"
    );
    let first = root.path().join("original-recovery-A1b2C3");
    let second = root.path().join("original-recovery-Second");
    fs::create_dir(&second).unwrap();
    for entry in fs::read_dir(&first).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), second.join(entry.file_name())).unwrap();
    }
    fs::remove_file(second.join("original-native-recovery-result.json")).unwrap();
    let digest = hex::encode(sha2::Sha256::digest(b"original"));
    for (directory, name) in [
        (&first, "original-recovery-A1b2C3"),
        (&second, "original-recovery-Second"),
    ] {
        let stage = format!("/owned/{name}");
        fs::write(
            directory.join("stage.json"),
            serde_json::to_vec(
                &serde_json::json!({"stage":stage,"input_sha256":digest,"origin_sha256":digest}),
            )
            .unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("original-native-recovery-invocation.json"),
            serde_json::to_vec(
                &serde_json::json!({"working_directory":stage,"input_sha256":digest}),
            )
            .unwrap(),
        )
        .unwrap();
    }
    let (files, issues) =
        recovery_artifact_tree::collect_diagnostic_attempts(root.path(), |path, _| {
            fs::read(path).map_err(|error| error.to_string())
        })
        .unwrap();
    assert_eq!(files.len(), 19);
    assert_eq!(
        files["original-recovery-A1b2C3/original-native-recovery-result.json"],
        b"original"
    );
    assert!(files.contains_key("original-recovery-Second/original-native-recovery-input.json"));
    assert!(issues.iter().any(|issue| {
        issue.contains("original-recovery-Second/original-native-recovery-result.json: absent")
    }));
    assert!(
        !issues
            .iter()
            .any(|issue| issue.contains("unbound diagnostic"))
    );
    fs::write(
        root.path()
            .join(recovery_artifact_tree::LIFECYCLE_RECOVERY_DIAGNOSTIC_INVENTORY),
        serde_json::to_vec(&serde_json::json!({"issues":issues})).unwrap(),
    )
    .unwrap();
    let (rescanned, repeated_issues) =
        recovery_artifact_tree::collect_diagnostic_attempts(root.path(), |path, _| {
            fs::read(path).map_err(|error| error.to_string())
        })
        .unwrap();
    assert_eq!(rescanned, files);
    assert_eq!(repeated_issues, issues);
    fs::write(second.join("original-native-recovery-invocation.json"), serde_json::to_vec(&serde_json::json!({"working_directory":"/owned/original-recovery-Unrelated","input_sha256":digest})).unwrap()).unwrap();
    let (retained, forged_issues) =
        recovery_artifact_tree::collect_diagnostic_attempts(root.path(), |path, _| {
            fs::read(path).map_err(|error| error.to_string())
        })
        .unwrap();
    assert_eq!(retained.len(), 19);
    assert!(
        forged_issues
            .iter()
            .any(|issue| issue.contains("original-recovery-Second: unbound diagnostic"))
    );
    // Broader diagnostic visibility never changes the complete/single authority selector.
    assert!(collect(root.path()).is_err());
}

#[test]
fn reserved_attempt_prefix_never_hides_malformed_metadata_or_file_aliases() {
    for leaf in [
        "original-recovery-owner-precondition.json",
        "original-recovery-diagnostic-inventory.json",
        "original-recovery-",
        "original-recovery-A_1",
    ] {
        let root = original();
        fs::write(
            root.path().join(leaf),
            b"metadata cannot occupy attempt namespace",
        )
        .unwrap();
        let error = recovery_artifact_tree::collect_diagnostic_attempts(root.path(), |path, _| {
            fs::read(path).map_err(|error| error.to_string())
        })
        .unwrap_err();
        assert_eq!(
            error, "recovery diagnostic attempt name/count differs",
            "{leaf}"
        );
    }
    let root = original();
    fs::write(
        root.path().join("original-recovery-Alias"),
        b"not a directory",
    )
    .unwrap();
    let error = recovery_artifact_tree::collect_diagnostic_attempts(root.path(), |path, _| {
        fs::read(path).map_err(|error| error.to_string())
    })
    .unwrap_err();
    assert!(error.contains("recovery diagnostic directory"), "{error}");
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
