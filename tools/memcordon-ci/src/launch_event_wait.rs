//! Prerequisite-event waits bounded by the original work deadline.
use crate::{CiError, Result};
use std::time::{Duration, Instant};

pub fn wait_for_event(
    cutoff: Instant,
    label: &str,
    mut observed: impl FnMut() -> Result<bool>,
    mut terminal: impl FnMut() -> Result<bool>,
) -> Result<()> {
    let mut event_ready = || {
        if Instant::now() >= cutoff {
            return Err(CiError::Message(format!(
                "original frontend event cutoff exhausted: {label}"
            )));
        }
        let ready = observed()?;
        if Instant::now() >= cutoff {
            return Err(CiError::Message(format!(
                "original frontend event cutoff exhausted: {label}"
            )));
        }
        Ok(ready)
    };
    loop {
        if event_ready()? {
            return Ok(());
        }
        if terminal()? {
            // Publication can precede exit between the first check and poll.
            if event_ready()? {
                return Ok(());
            }
            return Err(CiError::Message(format!(
                "original frontend ended before {label}; original capture settlement remains due"
            )));
        }
        std::thread::sleep(
            cutoff
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(1)),
        );
    }
}
