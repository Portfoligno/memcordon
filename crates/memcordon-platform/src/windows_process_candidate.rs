//! Positive-admission acquisition facts, never census or retirement evidence.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acquisition {
    Held,
    CandidateUnavailable,
    Error,
}

/// Classify only the exact noninheritable query/synchronize acquisition context.
/// `query_only` excludes requests with capability-transfer or other extra rights.
pub fn classify(
    pid: u32,
    query_only: bool,
    inherit: bool,
    handle_acquired: bool,
    raw_error: Option<i32>,
) -> Acquisition {
    if handle_acquired {
        Acquisition::Held
    } else if pid != 0 && query_only && !inherit && raw_error == Some(87) {
        Acquisition::CandidateUnavailable
    } else {
        Acquisition::Error
    }
}
