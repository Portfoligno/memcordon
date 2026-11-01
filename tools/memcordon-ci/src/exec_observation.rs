//! Ordered ownership boundaries for an original exec-stopped child.
use crate::{CiError, Result};
use std::time::{Duration, Instant};

pub fn cutoff(started: Instant, budget: Duration, outer: Instant) -> Result<Instant> {
    let selected = started
        .checked_add(budget)
        .ok_or_else(|| CiError::Message("exec observation budget overflow".into()))?
        .min(outer);
    if selected <= started {
        return Err(CiError::Message(
            "original exec observation cutoff exhausted".into(),
        ));
    }
    Ok(selected)
}

pub fn observe(
    cutoff: Instant,
    held: impl FnOnce() -> Result<()>,
    release: impl FnOnce() -> Result<()>,
    after_release: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let check = || {
        if Instant::now() >= cutoff {
            Err(CiError::Message(
                "original exec observation cutoff exhausted".into(),
            ))
        } else {
            Ok(())
        }
    };
    check()?;
    held()?;
    check()?;
    release()?;
    check()?;
    after_release()?;
    check()
}
