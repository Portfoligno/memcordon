use std::io;
use std::time::Instant;
use std::{fmt, path::Path};

pub fn require_same_birth(original: u64, observed: u64) -> io::Result<()> {
    if original == observed {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native census process birth changed",
        ))
    }
}

pub struct DisappearanceFailure {
    original: io::Error,
    secondary: Option<(&'static str, io::Error)>,
}
impl fmt::Debug for DisappearanceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisappearanceFailure")
            .field("original_kind", &self.original.kind())
            .field("original_raw", &self.original.raw_os_error())
            .field(
                "secondary",
                &self
                    .secondary
                    .as_ref()
                    .map(|(operation, error)| (*operation, error.kind(), error.raw_os_error())),
            )
            .finish()
    }
}

struct ContextualFailure {
    original: io::Error,
    secondary: io::Error,
}
impl fmt::Display for ContextualFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; retirement-proof failure: {}",
            self.original, self.secondary
        )
    }
}
impl fmt::Debug for ContextualFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}
impl std::error::Error for ContextualFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
impl DisappearanceFailure {
    pub fn contextualize(
        self,
        operation: &'static str,
        path: &Path,
        process: &Path,
        context: impl Fn(&'static str, &Path, io::Error) -> io::Error,
    ) -> io::Error {
        let original = context(operation, path, self.original);
        match self.secondary {
            None => original,
            Some((operation, error)) => {
                let kind = error.kind();
                let secondary = context(operation, process, error);
                io::Error::new(
                    kind,
                    ContextualFailure {
                        original,
                        secondary,
                    },
                )
            }
        }
    }
}

/// A missing dynamic entry is not absence proof until its original owner retires.
pub fn disappeared(
    error: io::Error,
    deadline: Instant,
    retired: impl FnOnce() -> io::Result<bool>,
) -> Result<(), DisappearanceFailure> {
    let fail = |original, secondary| DisappearanceFailure {
        original,
        secondary,
    };
    if error.kind() != io::ErrorKind::NotFound {
        return Err(fail(error, None));
    }
    if Instant::now() >= deadline {
        return Err(fail(
            error,
            Some((
                "census-retirement-proof-cutoff",
                io::Error::new(io::ErrorKind::TimedOut, "census original cutoff elapsed"),
            )),
        ));
    }
    let retired = match retired() {
        Ok(retired) => retired,
        Err(proof) => return Err(fail(error, Some(("census-original-pidfd-poll", proof)))),
    };
    if retired {
        if Instant::now() >= deadline {
            return Err(fail(
                error,
                Some((
                    "census-retirement-proof-cutoff",
                    io::Error::new(io::ErrorKind::TimedOut, "census original cutoff elapsed"),
                )),
            ));
        }
        Ok(())
    } else {
        Err(fail(error, None))
    }
}
