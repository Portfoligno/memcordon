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

fn account_reservation(state: &std::path::Path, live: bool) -> std::path::PathBuf {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "native recovery requires root"
    );
    let pid = unsafe { libc::getpid() };
    let birth = crate::linux::envelope::process_start_time(pid).unwrap();
    let namespace = std::fs::metadata("/proc/self/ns/user").unwrap();
    let path = state.join(format!(
        "account-{}-{}-1000.reservation",
        namespace.dev(),
        namespace.ino()
    ));
    let value = serde_json::json!({
        "format": "memcordon.account-reservation", "revision": 1,
        "user_namespace_device": namespace.dev(), "user_namespace_inode": namespace.ino(), "uid": 1000,
        "attempt": vec![0xab_u8; 16], "owner_pid": pid,
        "owner_birth": if live { birth } else { birth.checked_sub(1).filter(|birth| *birth != 0).unwrap() },
        "boot_identity": std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),
    });
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

#[test]
#[ignore = "requires native Linux root-owned reservation recovery"]
fn native_account_recovery_preserves_live_owner_and_reclaims_preallocation_orphan() {
    let state = TempDir::new().unwrap();
    let cgroup = TempDir::new().unwrap();
    let reservation = account_reservation(state.path(), true);
    let ambiguous =
        crate::linux::recovery::recover_test_roots(state.path(), cgroup.path()).unwrap();
    assert_eq!(
        ambiguous,
        [reservation.file_name().unwrap().to_str().unwrap()]
    );
    assert!(reservation.exists());
    account_reservation(state.path(), false);
    assert!(
        crate::linux::recovery::recover_test_roots(state.path(), cgroup.path())
            .unwrap()
            .is_empty()
    );
    assert!(!reservation.exists());
}

#[test]
#[ignore = "requires native Linux root-owned reservation recovery"]
fn native_account_recovery_refreshes_inventory_after_verified_allocated_journal_retirement() {
    use crate::linux::private_attempt::{
        DurablePrivateAttempt, PrivateAttemptRecordV4, ProcessIdentityV4,
    };
    use memcordon_core::{BoundedText, DiagnosticSha256};
    let state = TempDir::new().unwrap();
    let cgroup = TempDir::new().unwrap();
    let reservation = account_reservation(state.path(), false);
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let record = PrivateAttemptRecordV4::allocated(
        BoundedText::new(IDENTITY).unwrap(),
        BoundedText::new(boot.trim()).unwrap(),
        ProcessIdentityV4 {
            pid: std::process::id(),
            start_time: crate::linux::envelope::process_start_time(unsafe { libc::getpid() })
                .unwrap(),
        },
        DiagnosticSha256::from_bytes([7; 32]),
    )
    .unwrap();
    let _journal = DurablePrivateAttempt::create_for_test(state.path(), record).unwrap();
    assert!(
        crate::linux::recovery::recover_test_roots(state.path(), cgroup.path())
            .unwrap()
            .is_empty()
    );
    assert!(!reservation.exists());
    assert!(!state.path().join(IDENTITY).exists());
}

#[test]
#[ignore = "requires native Linux root-owned reservation recovery"]
fn native_account_recovery_keeps_capacity_charged_for_uncertain_or_native_allocated_state() {
    for case in [
        "boundary",
        "transaction",
        "malformed",
        "hardlink",
        "wrong-mode",
        "future-birth",
        "malformed-boot",
        "native-identity",
    ] {
        let state = TempDir::new().unwrap();
        let cgroup = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let reservation = account_reservation(state.path(), false);
        match case {
            "boundary" => std::fs::create_dir(cgroup.path().join(IDENTITY)).unwrap(),
            "transaction" => {
                std::fs::write(state.path().join(format!("{IDENTITY}.new")), b"uncertain").unwrap()
            }
            "malformed" => std::fs::write(&reservation, b"{\"format\":\"unknown\"}").unwrap(),
            "hardlink" => {
                std::fs::hard_link(&reservation, outside.path().join("retained-link")).unwrap()
            }
            "wrong-mode" => {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&reservation, std::fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
            "future-birth" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&reservation).unwrap()).unwrap();
                value["owner_birth"] = serde_json::Value::from(
                    crate::linux::envelope::process_start_time(unsafe { libc::getpid() })
                        .unwrap()
                        .checked_add(1)
                        .unwrap(),
                );
                std::fs::write(&reservation, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            "malformed-boot" | "native-identity" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&reservation).unwrap()).unwrap();
                if case == "malformed-boot" {
                    value["boot_identity"] =
                        serde_json::Value::String("not-a-native-boot-uuid".into());
                } else {
                    value["user_namespace_inode"] = serde_json::Value::from(0_u64);
                }
                std::fs::write(&reservation, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        let ambiguous =
            crate::linux::recovery::recover_test_roots(state.path(), cgroup.path()).unwrap();
        assert!(
            ambiguous
                .iter()
                .any(|name| name == reservation.file_name().unwrap().to_str().unwrap()),
            "case={case}"
        );
        assert!(
            reservation.exists(),
            "uncertain capacity must remain charged: {case}"
        );
    }
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
                let oversized =
                    usize::try_from(crate::linux::recovery::MAX_RECORD_BYTES).unwrap() + 1;
                write_transaction(&transaction, &"x".repeat(oversized));
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
        assert!(ambiguous.iter().any(|entry| entry == IDENTITY), "{case}");
        assert!(
            ambiguous
                .iter()
                .any(|entry| entry == &format!("{IDENTITY}.new"))
        );
        assert!(canonical.exists());
        assert!(std::fs::symlink_metadata(transaction).is_ok());
    }
}

#[test]
fn recovery_keeps_unknown_v4_private_attempt_and_boundary_ambiguous() {
    let temporary = TempDir::new().unwrap();
    let state_root = temporary.path().join("state");
    let cgroup_root = temporary.path().join("cgroup");
    std::fs::create_dir(&state_root).unwrap();
    std::fs::create_dir(&cgroup_root).unwrap();
    std::fs::create_dir(cgroup_root.join(IDENTITY)).unwrap();
    let record = state_root.join(IDENTITY);
    write_record(
        &record,
        &format!(
            "version=4\ncgroup={IDENTITY}\nprivate-profile=linux-tcp4-private-v1\nstate=checkpoint-committed\n"
        ),
    );

    // The digest and identity are well formed, but recovery has no V4 owner
    // ledger or terminal verifier. It must neither delete the record nor
    // quietly declare the cgroup retired.
    let ambiguous = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();
    assert_eq!(ambiguous, [IDENTITY]);
    assert!(record.exists());
    assert!(cgroup_root.join(IDENTITY).exists());
}

#[test]
fn recovery_does_not_roll_back_unknown_v4_interrupted_checkpoint() {
    let temporary = TempDir::new().unwrap();
    let state_root = temporary.path().join("state");
    let cgroup_root = temporary.path().join("cgroup");
    std::fs::create_dir(&state_root).unwrap();
    std::fs::create_dir(&cgroup_root).unwrap();
    let record = state_root.join(IDENTITY);
    let interrupted = record.with_extension("new");
    write_record(
        &record,
        &format!("version=4\ncgroup={IDENTITY}\nstate=network-prepared\n"),
    );
    write_transaction(
        &interrupted,
        &format!("version=4\ncgroup={IDENTITY}\nstate=checkpoint-committed\n"),
    );

    let ambiguous = crate::linux::recovery::recover_test_roots(&state_root, &cgroup_root).unwrap();
    assert!(ambiguous.iter().any(|entry| entry == IDENTITY));
    assert!(
        ambiguous
            .iter()
            .any(|entry| entry == &format!("{IDENTITY}.new"))
    );
    assert!(record.exists());
    assert!(interrupted.exists());
}
