//! Diagnostic loss is explicit and does not certify operational success.
use serde::Serialize;

pub const MAX_ENTRIES: usize = 128;
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_DEPTH: usize = 8;

pub fn entry_limit(visited: usize) -> Option<Limit> {
    (visited >= MAX_ENTRIES).then_some(Limit::Entries)
}

pub fn extent_limit(depth: usize, copied: u64, length: u64) -> Option<Limit> {
    if depth > MAX_DEPTH {
        Some(Limit::Depth)
    } else if length > MAX_FILE_BYTES {
        Some(Limit::FileBytes)
    } else if copied.checked_add(length).is_none_or(|n| n > MAX_BYTES) {
        Some(Limit::AggregateBytes)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Limit {
    Entries,
    Depth,
    FileBytes,
    AggregateBytes,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Projection {
    Complete,
    Incomplete {
        limits: Vec<Limit>,
        remaining_entries: Option<usize>,
    },
}

impl Projection {
    pub fn record_limit(&mut self, limit: Limit) {
        if matches!(self, Self::Complete) {
            *self = Self::Incomplete {
                limits: Vec::new(),
                remaining_entries: None,
            };
        }
        if let Self::Incomplete { limits, .. } = self
            && !limits.contains(&limit)
        {
            limits.push(limit);
        }
    }
}
