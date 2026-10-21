//! Local signal observation and owner-selected retirement cutoffs.
use crate::{CiError, Result};
use memcordon_platform::test_support::{CiInterruptRegistration, CiInterruptToken};
use std::{sync::Mutex, time::Instant};

static TOKEN: Mutex<Option<CiInterruptToken>> = Mutex::new(None);
thread_local! {
    static RETIREMENT: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

pub struct Scope {
    registration: CiInterruptRegistration,
}
impl Scope {
    pub fn install() -> Result<Self> {
        let registration = CiInterruptRegistration::install()?;
        *TOKEN.lock().expect("CI interrupt token lock") = Some(registration.token());
        Ok(Self { registration })
    }
    pub fn finish<T>(&self, result: Result<T>) -> Result<T> {
        let stop = self.registration.token().observed();
        if let Some(stop) = stop {
            eprintln!(
                "[ci interruption] observed {stop:?}; only verified owner retirement is complete"
            );
        }
        match (result, stop) {
            (Ok(_), Some(stop)) => Err(CiError::SettledCancellation(format!(
                "external interruption: {stop:?}"
            ))),
            (result, _) => result,
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        *TOKEN.lock().expect("CI interrupt token lock") = None;
    }
}

pub(crate) fn observed() -> Option<memcordon_platform::test_support::CiInterrupt> {
    TOKEN
        .lock()
        .expect("CI interrupt token lock")
        .as_ref()
        .and_then(CiInterruptToken::observed)
}
pub(crate) fn check_admission() -> Result<()> {
    if retirement_deadline().is_none()
        && let Some(signal) = observed()
    {
        return Err(CiError::SettledCancellation(format!(
            "external interruption before work admission: {signal:?}"
        )));
    }
    Ok(())
}
pub(crate) fn retirement_deadline() -> Option<Instant> {
    RETIREMENT.get()
}

pub(crate) struct Retirement(Option<Instant>);
impl Drop for Retirement {
    fn drop(&mut self) {
        RETIREMENT.set(self.0);
    }
}
pub(crate) fn retirement_scope(deadline: Instant) -> Retirement {
    let previous = RETIREMENT.get();
    RETIREMENT.set(Some(previous.map_or(deadline, |old| old.min(deadline))));
    Retirement(previous)
}

#[cfg(test)]
#[path = "../tests/private/cancellation.rs"]
mod tests;
