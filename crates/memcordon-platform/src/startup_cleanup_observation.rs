//! Bounded supplementary startup facts; never a cleanup or ownership receipt.
use memcordon_core::{CleanupErrorRecord, ReleaseEvidence};
use serde::Serialize;
use std::{io, time::Instant};

pub const RECORD_BOUND: usize = 4096;

#[derive(Debug, Serialize)]
pub struct CreationSettlement<T> {
    pub before: T,
    pub after: T,
    pub observed_before: Option<u64>,
    pub observed_after: Option<u64>,
    pub original_cutoff: Option<u64>,
    pub settled: bool,
}

/// Convert the original cutoff using one supplementary clock pair, including
/// a past cutoff. This never creates or changes a native wait deadline.
pub fn cutoff_nanos(tick: u64, now: Instant, cutoff: Instant) -> Option<u64> {
    if let Some(remaining) = cutoff.checked_duration_since(now) {
        tick.checked_add(u64::try_from(remaining.as_nanos()).ok()?)
    } else {
        tick.checked_sub(u64::try_from(now.duration_since(cutoff).as_nanos()).ok()?)
    }
}

pub fn error_record<T: Serialize>(
    phase: &str,
    error: &io::Error,
    guardian_child_returned: bool,
    configured: bool,
    release: &ReleaseEvidence,
    settlement: Option<&CreationSettlement<T>>,
) -> CleanupErrorRecord {
    #[derive(Serialize)]
    struct Record<'a, T> {
        format: &'static str,
        revision: u32,
        diagnostic_only: bool,
        acceptance_authority: bool,
        sampling: &'static str,
        clock: &'static str,
        phase: &'a str,
        original_error_kind: String,
        original_raw_errno: Option<i32>,
        original_message: String,
        guardian_child_returned: bool,
        configured: bool,
        release: &'a ReleaseEvidence,
        exact_creation: Option<&'a CreationSettlement<T>>,
    }
    let record = Record {
        format: "memcordon.startup-cleanup-observation",
        revision: 1,
        diagnostic_only: true,
        acceptance_authority: false,
        sampling: "sequential-non-atomic",
        clock: "macos-continuous-nanos",
        phase,
        original_error_kind: format!("{:?}", error.kind()),
        original_raw_errno: error.raw_os_error(),
        original_message: error.to_string(),
        guardian_child_returned,
        configured,
        release,
        exact_creation: settlement,
    };
    let message = serde_json::to_vec(&record)
        .ok()
        .filter(|bytes| bytes.len() <= RECORD_BOUND)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| {
            // Fixed-size fallback does not replace the original native outcome.
            serde_json::json!({"format":"memcordon.startup-cleanup-observation","revision":1,
                "diagnostic_only":true,"acceptance_authority":false,"state":"unavailable",
                "reason":"serialization-or-record-bound","original_raw_errno":error.raw_os_error()})
            .to_string()
        });
    CleanupErrorRecord {
        operation: "startup-creation-observation".into(),
        message,
    }
}
