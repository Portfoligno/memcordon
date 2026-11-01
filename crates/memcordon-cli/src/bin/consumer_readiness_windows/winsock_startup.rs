//! Ownership of exactly one explicit successful WSAStartup reference.
use std::{fmt, io};

const VERSION: u16 = 0x0202;
#[derive(Debug)]
struct StartupFailure {
    returned: i32,
    negotiated: Option<u16>,
    original: Option<io::Error>,
}
impl fmt::Display for StartupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WSAStartup requested=0x{VERSION:04x}; direct-return={}; negotiated={:?}; native-error={:?}",
            self.returned, self.negotiated, self.original
        )
    }
}
impl std::error::Error for StartupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

pub struct Startup<C: FnOnce()> {
    cleanup: Option<C>,
}
impl<C: FnOnce()> Drop for Startup<C> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

pub fn acquire<C: FnOnce()>(returned: i32, negotiated: u16, cleanup: C) -> io::Result<Startup<C>> {
    if returned != 0 {
        let original = io::Error::from_raw_os_error(returned);
        return Err(io::Error::new(
            original.kind(),
            StartupFailure {
                returned,
                negotiated: None,
                original: Some(original),
            },
        ));
    }
    let owner = Startup {
        cleanup: Some(cleanup),
    };
    if negotiated != VERSION {
        let error = io::Error::new(
            io::ErrorKind::Unsupported,
            StartupFailure {
                returned,
                negotiated: Some(negotiated),
                original: None,
            },
        );
        drop(owner); // The native call succeeded, even when negotiation was unsuitable.
        return Err(error);
    }
    Ok(owner)
}
