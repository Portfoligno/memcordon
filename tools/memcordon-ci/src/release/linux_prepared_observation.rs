//! Failure surfacing on the original retained child; a native exit is never a receipt.
use std::{
    io,
    process::{Child, ExitStatus},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub enum Outcome<T> {
    Prepared(T),
    Retired(ExitStatus),
    Expired,
}

pub fn wait<T, E: From<io::Error>>(
    child: &mut Child,
    retained: &mut Option<ExitStatus>,
    deadline: Instant,
    mut scan: impl FnMut() -> Result<Option<T>, E>,
) -> Result<Outcome<T>, E> {
    loop {
        if Instant::now() >= deadline {
            return Ok(Outcome::Expired);
        }
        if let Some(prepared) = scan()? {
            return if Instant::now() < deadline {
                Ok(Outcome::Prepared(prepared))
            } else {
                Ok(Outcome::Expired)
            };
        }
        let status = match *retained {
            Some(status) => Some(status),
            None => child.try_wait()?,
        };
        if let Some(status) = status {
            *retained = Some(status);
            // Publication can race the first scan and original-child retirement.
            // The caller's exact authenticated scan remains the only authority.
            if Instant::now() < deadline
                && let Some(prepared) = scan()?
                && Instant::now() < deadline
            {
                return Ok(Outcome::Prepared(prepared));
            }
            return Ok(Outcome::Retired(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Outcome::Expired);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}
