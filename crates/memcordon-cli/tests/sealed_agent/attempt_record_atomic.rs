#![cfg(target_os = "linux")]

use crate::linux::attempt::{AttemptRecord, TransitionFault};
use tempfile::TempDir;

const IDENTITY: &str = "abababababababababababababababab";

#[test]
fn transition_failure_before_rename_preserves_committed_record_and_removes_owned_temporary() {
    let temporary = TempDir::new().unwrap();
    let record = AttemptRecord::create_for_test(temporary.path(), IDENTITY.to_owned(), 1).unwrap();
    let canonical = temporary.path().join(IDENTITY);
    let transaction = canonical.with_extension("new");
    let allocated = std::fs::read(&canonical).unwrap();

    assert_eq!(
        record
            .transition_for_test("boundary-created", TransitionFault::BeforeRename)
            .unwrap_err(),
        "MCSEALED-RECORD-FAULT: before rename"
    );
    assert_eq!(std::fs::read(&canonical).unwrap(), allocated);
    assert!(!transaction.exists());
    record.retire().unwrap();
}

#[test]
fn committed_transition_survives_post_rename_failure_without_temporary_residue() {
    let temporary = TempDir::new().unwrap();
    let record = AttemptRecord::create_for_test(temporary.path(), IDENTITY.to_owned(), 1).unwrap();
    let canonical = temporary.path().join(IDENTITY);
    let transaction = canonical.with_extension("new");

    assert_eq!(
        record
            .transition_for_test("boundary-created", TransitionFault::AfterRename)
            .unwrap_err(),
        "MCSEALED-RECORD-FAULT: after rename"
    );
    let committed = std::fs::read_to_string(&canonical).unwrap();
    assert!(
        committed
            .lines()
            .any(|line| line == "state=boundary-created")
    );
    assert!(!transaction.exists());
    record.retire().unwrap();
}

#[test]
fn competing_transition_never_deletes_an_existing_writers_temporary() {
    let temporary = TempDir::new().unwrap();
    let record = AttemptRecord::create_for_test(temporary.path(), IDENTITY.to_owned(), 1).unwrap();
    let canonical = temporary.path().join(IDENTITY);
    let transaction = canonical.with_extension("new");
    let competing = b"competing-writer-owned-transaction\n";
    std::fs::write(&transaction, competing).unwrap();

    assert!(record.transition("boundary-created").is_err());
    assert_eq!(std::fs::read(&transaction).unwrap(), competing);

    std::fs::remove_file(transaction).unwrap();
    record.retire().unwrap();
}
