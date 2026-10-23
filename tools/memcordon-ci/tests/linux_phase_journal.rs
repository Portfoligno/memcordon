#![cfg(unix)]
use memcordon_ci::release::linux_phase_journal::{self as journal, Capture};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    time::{Duration, Instant},
};

const ATTEMPT: &str = "1234567890abcdef1234567890abcdef";
fn record() -> Value {
    json!({"attempt_id":ATTEMPT,"boot_identity":"original-boot","frontend":{"pid":100,"start_time":1000},
        "mixed_worker":{"pid":101,"start_time":1001},"caller_envelope_digest":"1".repeat(64),
        "admission_metadata":null,"mixed_admission_metadata":{"attempt_id":ATTEMPT,"request":{"image":"original-image"}},
        "binding":{"attempt_id":ATTEMPT},"phase":"execution-observed","release_knowledge":"exec-observed"})
}
fn encode(record: &Value) -> Vec<u8> {
    let body = format!(
        "format=memcordon.private-native-journal\nrevision=1\ncgroup={ATTEMPT}\npayload={}\n",
        serde_json::to_string(record).unwrap()
    );
    format!(
        "{body}digest={}\n",
        memcordon_ci::release::artifacts::checksum(body.as_bytes())
    )
    .into_bytes()
}
fn create(path: &std::path::Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn replace(root: &std::path::Path, bytes: &[u8]) {
    let next = root.join("next.new");
    create(&next, bytes);
    fs::rename(next, root.join(ATTEMPT)).unwrap();
    File::open(root).unwrap().sync_all().unwrap();
}
fn fixture() -> (tempfile::TempDir, File, Value) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let expected = record();
    create(&root.path().join(ATTEMPT), &encode(&expected));
    let held = File::open(root.path()).unwrap();
    (root, held, expected)
}
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn selected_snapshot_is_held_but_authenticated_replacement_is_not_selected() {
    let (root, parent, expected) = fixture();
    let mut next = expected.clone();
    next["phase"] = json!("retiring");
    let advanced =
        journal::capture_checked(&parent, ATTEMPT, uid(), Some(&expected), deadline(), || {
            replace(root.path(), &encode(&next));
            Ok(())
        });
    assert!(
        matches!(advanced, Capture::GenerationAdvanced { .. }),
        "{}",
        advanced.diagnostic()
    );
    let stable = journal::capture(&parent, ATTEMPT, uid(), Some(&expected), deadline());
    let Capture::Stable(snapshot) = stable else {
        panic!("{}", stable.diagnostic())
    };
    assert_eq!(snapshot.record, next);
    assert_eq!(snapshot.bytes, encode(&next));
    fs::remove_file(root.path().join(ATTEMPT)).unwrap();
    assert_eq!(
        snapshot.held.metadata().unwrap().len(),
        snapshot.bytes.len() as u64
    );
}

#[test]
fn replacement_before_first_metadata_is_authenticated_but_never_selected() {
    let (root, parent, expected) = fixture();
    let mut next = expected.clone();
    next["phase"] = json!("retiring");
    let outcome = journal::capture_with_hooks(
        &parent,
        ATTEMPT,
        uid(),
        None,
        deadline(),
        || {
            replace(root.path(), &encode(&next));
            Ok(())
        },
        || Ok(()),
    );
    let Capture::GenerationAdvanced { association, .. } = outcome else {
        panic!("{}", outcome.diagnostic())
    };
    assert_eq!(association, next);
    let mut foreign = next.clone();
    foreign["mixed_worker"]["pid"] = json!(103);
    replace(root.path(), &encode(&foreign));
    assert!(
        matches!(
            journal::capture(&parent, ATTEMPT, uid(), Some(&association), deadline()),
            Capture::Fatal { .. }
        ),
        "cross-probe actor substitution must not reset the baseline"
    );
}

#[test]
fn in_place_corruption_foreign_actor_and_unsafe_replacement_are_fatal() {
    for kind in ["in-place", "digest", "actor", "attempt", "mode", "symlink"] {
        let (root, parent, expected) = fixture();
        let outcome =
            journal::capture_checked(&parent, ATTEMPT, uid(), Some(&expected), deadline(), || {
                let path = root.path().join(ATTEMPT);
                let mut next = expected.clone();
                next["phase"] = json!("retiring");
                match kind {
                    "in-place" => fs::write(path, encode(&next)).unwrap(),
                    "digest" => replace(root.path(), b"corrupt framed journal"),
                    "actor" => {
                        next["mixed_worker"]["pid"] = json!(102);
                        replace(root.path(), &encode(&next));
                    }
                    "attempt" => {
                        next["attempt_id"] = json!("f".repeat(32));
                        replace(root.path(), &encode(&next));
                    }
                    "mode" => {
                        replace(root.path(), &encode(&next));
                        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
                    }
                    "symlink" => {
                        fs::remove_file(&path).unwrap();
                        std::os::unix::fs::symlink("foreign", path).unwrap();
                    }
                    _ => unreachable!(),
                }
                Ok(())
            });
        assert!(
            matches!(outcome, Capture::Fatal { .. }),
            "{kind}: {}",
            outcome.diagnostic()
        );
    }
}

#[test]
fn original_cutoff_and_parent_custody_never_become_retry_permission() {
    let (root, parent, expected) = fixture();
    let expired = Instant::now();
    assert!(matches!(
        journal::capture_checked(
            &parent,
            ATTEMPT,
            uid(),
            Some(&expected),
            expired,
            || panic!("expired probe must not read")
        ),
        Capture::Deadline { .. }
    ));
    let outcome =
        journal::capture_checked(&parent, ATTEMPT, uid(), Some(&expected), deadline(), || {
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
            Ok(())
        });
    assert!(matches!(outcome, Capture::Fatal { .. }));
}

#[test]
fn valid_early_allocated_snapshot_does_not_require_later_optional_ownership() {
    let (root, parent, mut expected) = fixture();
    for field in ["binding", "mixed_worker", "mixed_admission_metadata"] {
        expected[field] = Value::Null;
    }
    expected["phase"] = json!("allocated");
    expected["release_knowledge"] = json!("not-released");
    replace(root.path(), &encode(&expected));
    assert!(matches!(
        journal::capture(&parent, ATTEMPT, uid(), Some(&expected), deadline()),
        Capture::Stable(_)
    ));
    let replacement = expected.clone();
    assert!(matches!(
        journal::capture_checked(&parent, ATTEMPT, uid(), Some(&expected), deadline(), || {
            replace(root.path(), &encode(&replacement));
            Ok(())
        }),
        Capture::GenerationAdvanced { .. }
    ));
}
