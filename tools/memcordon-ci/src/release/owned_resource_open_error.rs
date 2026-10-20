use std::io;
use std::path::Path;

use crate::CiError;

/// Preserve optional absence only at the initial open, before custody is acquired.
/// A later read or named-file disappearance must never use this adapter.
pub fn open_error(path: &Path, error: io::Error) -> CiError {
    if error.kind() == io::ErrorKind::NotFound {
        CiError::Io(error)
    } else {
        CiError::Message(format!("open owned resource {path:?}: {error}"))
    }
}
