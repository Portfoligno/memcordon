//! A kill request never substitutes for native exit proof or an owned process.
use std::{
    fmt, io,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Failure {
    primary: io::Error,
    secondary: io::Error,
}
impl fmt::Display for Failure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{}; peer cleanup: {}", self.primary, self.secondary)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn combine(primary: io::Error, secondary: Option<io::Error>) -> io::Error {
    match secondary {
        Some(secondary) => io::Error::new(primary.kind(), Failure { primary, secondary }),
        None => primary,
    }
}

pub enum Outcome<O> {
    Retired(io::Error),
    Unsettled { owner: O, error: io::Error },
}

/// Consumes the actual owner. Only the supplied native wait's exit result
/// releases it; errors and cutoff return that same owner, never a replacement.
pub fn settle<O>(
    mut owner: O,
    primary: io::Error,
    cutoff: Instant,
    mut kill: impl FnMut(&mut O) -> io::Result<()>,
    mut exited: impl FnMut(&mut O) -> io::Result<bool>,
) -> Outcome<O> {
    let mut cleanup = kill(&mut owner).err();
    loop {
        match exited(&mut owner) {
            Ok(true) => return Outcome::Retired(combine(primary, cleanup)),
            Err(error) => {
                cleanup = Some(match cleanup {
                    Some(previous) => combine(previous, Some(error)),
                    None => error,
                });
                return Outcome::Unsettled {
                    owner,
                    error: combine(primary, cleanup),
                };
            }
            Ok(false) if Instant::now() >= cutoff => {
                let error = io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original peer retirement unproved at original cutoff",
                );
                cleanup = Some(match cleanup {
                    Some(previous) => combine(previous, Some(error)),
                    None => error,
                });
                return Outcome::Unsettled {
                    owner,
                    error: combine(primary, cleanup),
                };
            }
            Ok(false) => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}
