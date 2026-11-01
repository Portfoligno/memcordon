//! Listener publication decisions from an already-held original process.
use std::{fmt, io, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub pid: u32,
    pub birth: u128,
}
pub struct Owner {
    pub identity: Identity,
    pub exit_status: Option<u32>,
}
pub struct Publication {
    pub pid: u32,
    pub value: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Failure {
    Retired { identity: Identity, status: u32 },
    IdentityMismatch,
    PublicationMismatch,
    Deadline,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retired { identity, status } => write!(
                f,
                "original held listener root retired before publication; pid={}; birth={}; native-exit-status={status}",
                identity.pid, identity.birth
            ),
            Self::IdentityMismatch => write!(
                f,
                "listener observation does not hold the original root identity"
            ),
            Self::PublicationMismatch => write!(
                f,
                "native listener publication differs from original held root or port extent"
            ),
            Self::Deadline => write!(f, "original native listener publication cutoff exhausted"),
        }
    }
}
impl std::error::Error for Failure {}
pub fn transcript_bytes(result: io::Result<Vec<u8>>) -> io::Result<Option<Vec<u8>>> {
    match result {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn live(expected: Identity, owner: Owner) -> io::Result<()> {
    if expected.pid == 0 || expected.birth == 0 || owner.identity != expected {
        return Err(io::Error::other(Failure::IdentityMismatch));
    }
    if let Some(status) = owner.exit_status {
        return Err(io::Error::other(Failure::Retired {
            identity: expected,
            status,
        }));
    }
    Ok(())
}
pub fn poll(
    expected: Identity,
    cutoff: Instant,
    mut now: impl FnMut() -> Instant,
    mut owner: impl FnMut() -> io::Result<Owner>,
    publication: impl FnOnce() -> io::Result<Option<Publication>>,
) -> io::Result<Option<u16>> {
    live(expected, owner()?)?;
    if now() >= cutoff {
        return Err(io::Error::new(io::ErrorKind::TimedOut, Failure::Deadline));
    }
    let published = publication()?;
    live(expected, owner()?)?;
    if now() >= cutoff {
        return Err(io::Error::new(io::ErrorKind::TimedOut, Failure::Deadline));
    }
    let Some(published) = published else {
        return Ok(None);
    };
    if published.pid != expected.pid || published.value.len() != 2 {
        return Err(io::Error::other(Failure::PublicationMismatch));
    }
    let port = u16::from_le_bytes(
        published
            .value
            .as_slice()
            .try_into()
            .expect("validated port width"),
    );
    if port == 0 {
        return Err(io::Error::other(Failure::PublicationMismatch));
    }
    Ok(Some(port))
}
