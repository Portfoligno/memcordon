//! Completion classification shared by the closed synchronous native owner.

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Completion {
    Success,
    Failure,
    InvariantViolation,
}

pub(super) fn classify(status: i32) -> Completion {
    if status == 0 {
        Completion::Success
    } else if status < 0 {
        Completion::Failure
    } else {
        Completion::InvariantViolation
    }
}
