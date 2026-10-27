#[path = "../src/windows_rename_status.rs"]
mod status;

#[test]
fn only_exact_success_is_committed() {
    assert_eq!(status::classify(0), status::Completion::Success);
}

#[test]
fn negative_native_status_preserves_failure() {
    for native in [-1, i32::MIN] {
        assert_eq!(status::classify(native), status::Completion::Failure);
    }
}

#[test]
fn pending_and_other_positive_statuses_cannot_unwind_or_commit() {
    const STATUS_PENDING: i32 = 0x103;
    for native in [STATUS_PENDING, 1, i32::MAX] {
        assert_eq!(
            status::classify(native),
            status::Completion::InvariantViolation
        );
    }
}
