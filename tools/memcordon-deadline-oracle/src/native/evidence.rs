use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct FailureReason {
    pub(super) kind: &'static str,
    pub(super) detail: String,
}

impl FailureReason {
    pub(super) fn new(kind: &'static str, detail: impl ToString) -> Self {
        Self {
            kind,
            detail: detail.to_string().chars().take(2048).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct SnapshotSummary {
    pub(super) elapsed_milliseconds: u64,
    pub(super) complete: bool,
    pub(super) member_count: usize,
    pub(super) raced_pids: usize,
}
