//! Duration selection for the existing absolute caller-command cutoff.
use crate::{CiError, Result};
use std::time::{Duration, Instant};

pub fn administrative() -> Duration {
    Duration::from_secs(60)
}

pub fn workload(now: Instant, original_work_cutoff: Instant) -> Result<Duration> {
    original_work_cutoff
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            CiError::Message("original workload command cutoff exhausted before spawn".into())
        })
}
