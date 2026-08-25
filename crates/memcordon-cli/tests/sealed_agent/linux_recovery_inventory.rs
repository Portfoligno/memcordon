#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::os::unix::fs::symlink;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

const IDENTITY: &str = "abababababababababababababababab";

fn write_record(path: &std::path::Path, body: &str) {
    let digest: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(path, format!("{body}digest={digest}\n")).unwrap();
}

fn write_transaction(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn recovery_ignores_cgroup_v2_control_files_and_reports_only_attempt_directories() {
    let temporary = TempDir::new().unwrap();
    let state_root = temporary.path().join("state");
    let cgroup_root = temporary.path().join("cgroup");
    std::fs::create_dir(&state_root).unwrap();
    std::fs::create_dir(&cgroup_root).unwrap();
    for control in ["cgroup.controllers", "cgroup.events", "cgroup.procs"] {
        std::fs::write(cgroup_root.join(control), b"kernel control fixture\n").unwrap();
    }
    std::fs::create_dir(cgroup_root.join(IDENTITY)).unwrap();

    let ambiguous = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();

    assert_eq!(ambiguous, [IDENTITY]);
}

#[test]
fn recovery_scans_orphan_boundaries_when_state_root_is_missing() {
    let temporary = TempDir::new().unwrap();
    let state_root = temporary.path().join("missing-state");
    let cgroup_root = temporary.path().join("cgroup");
    std::fs::create_dir(&cgroup_root).unwrap();
    std::fs::create_dir(cgroup_root.join(IDENTITY)).unwrap();

    let ambiguous = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();

    assert_eq!(ambiguous, [IDENTITY]);
}

#[test]
fn recovery_never_accepts_noncanonical_attempt_identities() {
    for invalid in [
        "ABABABABABABABABABABABABABABABAB",
        "ababababababababababababababab",
        "abababababababababababababababab.new",
        "unrelated",
    ] {
        let temporary = TempDir::new().unwrap();
        let state_root = temporary.path().join("state");
        let cgroup_root = temporary.path().join("cgroup");
        std::fs::create_dir(&state_root).unwrap();
        std::fs::create_dir(&cgroup_root).unwrap();
        std::fs::create_dir(cgroup_root.join(invalid)).unwrap();

        let error =
            crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap_err();

        assert!(error.contains("invalid attempt directory"));
    }
}

#[test]
fn recovery_never_follows_state_or_cgroup_symlinks() {
    let temporary = TempDir::new().unwrap();
    let state_root = temporary.path().join("state");
    let cgroup_root = temporary.path().join("cgroup");
    let outside = temporary.path().join("outside");
    std::fs::create_dir(&state_root).unwrap();
    std::fs::create_dir(&cgroup_root).unwrap();
    std::fs::write(&outside, b"must remain untouched\n").unwrap();
    symlink(&outside, state_root.join(IDENTITY)).unwrap();

    let ambiguous = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();
    assert_eq!(ambiguous, [IDENTITY]);
    assert_eq!(std::fs::read(&outside).unwrap(), b"must remain untouched\n");

    symlink(temporary.path(), cgroup_root.join("unsafe-link")).unwrap();
    let error = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap_err();
    assert!(error.contains("unsafe cgroup entry"));
}

#[test]
fn recovery_preserves_a_live_allocated_record_and_retires_a_stale_record() {
    let temporary = TempDir::new().unwrap();
    let state_root = temporary.path().join("state");
    let cgroup_root = temporary.path().join("cgroup");
    std::fs::create_dir(&state_root).unwrap();
    std::fs::create_dir(&cgroup_root).unwrap();
    let live_body = format!(
        "version=1\ncgroup={IDENTITY}\nfrontend-pid={}\nstate=allocated\n",
        std::process::id()
    );
    write_record(&state_root.join(IDENTITY), &live_body);

    let ambiguous = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();
    assert_eq!(ambiguous, [IDENTITY]);
    assert!(state_root.join(IDENTITY).exists());

    std::fs::remove_file(state_root.join(IDENTITY)).unwrap();
    let stale_body = format!("version=1\ncgroup={IDENTITY}\nstate=boundary-created\n");
    write_record(&state_root.join(IDENTITY), &stale_body);
    let ambiguous = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();
    assert!(ambiguous.is_empty());
    assert!(!state_root.join(IDENTITY).exists());
}

#[test]
fn recovery_rolls_back_only_authenticated_stale_interrupted_transitions() {
    let temporary = TempDir::new().unwrap();
    let state_root = temporary.path().join("state");
    let cgroup_root = temporary.path().join("cgroup");
    std::fs::create_dir(&state_root).unwrap();
    std::fs::create_dir(&cgroup_root).unwrap();
    let canonical = state_root.join(IDENTITY);
    let transaction = canonical.with_extension("new");
    let stale_body = format!("version=1\ncgroup={IDENTITY}\nstate=boundary-created\n");
    write_record(&canonical, &stale_body);
    write_transaction(
        &transaction,
        &format!("version=1\ncgroup={IDENTITY}\nstate=guardian-ready\n"),
    );

    let ambiguous = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();
    assert!(ambiguous.is_empty());
    assert!(!canonical.exists());
    assert!(!transaction.exists());
}

#[test]
fn recovery_preserves_live_lone_and_conflicting_interrupted_transitions() {
    for case in ["live", "lone", "conflicting"] {
        let temporary = TempDir::new().unwrap();
        let state_root = temporary.path().join("state");
        let cgroup_root = temporary.path().join("cgroup");
        std::fs::create_dir(&state_root).unwrap();
        std::fs::create_dir(&cgroup_root).unwrap();
        let canonical = state_root.join(IDENTITY);
        let transaction = canonical.with_extension("new");
        if case != "lone" {
            let frontend = if case == "live" {
                format!("frontend-pid={}\n", std::process::id())
            } else {
                String::new()
            };
            let body = format!("version=1\ncgroup={IDENTITY}\n{frontend}state=boundary-created\n");
            write_record(&canonical, &body);
        }
        let binding = if case == "conflicting" {
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        } else {
            IDENTITY
        };
        write_transaction(
            &transaction,
            &format!("version=1\ncgroup={binding}\nstate=guardian-ready\n"),
        );

        let ambiguous =
            crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();
        assert!(
            ambiguous
                .iter()
                .any(|entry| entry == &format!("{IDENTITY}.new"))
        );
        assert!(transaction.exists());
        if case != "lone" {
            assert!(canonical.exists());
            assert!(ambiguous.iter().any(|entry| entry == IDENTITY));
        }
    }
}

#[test]
fn recovery_preserves_unsafe_interrupted_transition_metadata() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    for case in ["wrong-mode", "oversized", "symlink"] {
        let temporary = TempDir::new().unwrap();
        let state_root = temporary.path().join("state");
        let cgroup_root = temporary.path().join("cgroup");
        std::fs::create_dir(&state_root).unwrap();
        std::fs::create_dir(&cgroup_root).unwrap();
        let canonical = state_root.join(IDENTITY);
        let transaction = canonical.with_extension("new");
        let stale_body = format!("version=1\ncgroup={IDENTITY}\nstate=boundary-created\n");
        write_record(&canonical, &stale_body);
        match case {
            "wrong-mode" => {
                write_transaction(&transaction, "partial transaction\n");
                std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o640))
                    .unwrap();
            }
            "oversized" => {
                write_transaction(&transaction, &"x".repeat(16 * 1024 + 1));
            }
            "symlink" => {
                let target = temporary.path().join("outside");
                std::fs::write(&target, b"outside\n").unwrap();
                symlink(target, &transaction).unwrap();
            }
            _ => unreachable!("unsafe transition cases are exhaustive"),
        }

        let ambiguous =
            crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();
        assert!(ambiguous.iter().any(|entry| entry == IDENTITY));
        assert!(
            ambiguous
                .iter()
                .any(|entry| entry == &format!("{IDENTITY}.new"))
        );
        assert!(canonical.exists());
        assert!(std::fs::symlink_metadata(transaction).is_ok());
    }
}
