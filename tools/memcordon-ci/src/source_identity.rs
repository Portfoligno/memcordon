//! Release authority requires an exact source object id, never `unknown` or a
//! matching pair of unvalidated provenance strings.
use crate::{CiError, Result};

pub fn validate(commit: &str) -> Result<()> {
    const GIT_OBJECT_BYTES: [usize; 2] = [20, 32];
    if GIT_OBJECT_BYTES
        .into_iter()
        .any(|bytes| commit.len() == bytes * 2)
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        && commit.bytes().any(|byte| byte != b'0')
    {
        Ok(())
    } else {
        Err(CiError::Message(
            "release source identity must be an exact Git commit; unknown is forbidden".into(),
        ))
    }
}

pub fn validate_checkout(root: &std::path::Path) -> Result<()> {
    let bytes = crate::command::git(root, ["rev-parse", "HEAD"])?;
    let commit =
        std::str::from_utf8(&bytes).map_err(|error| CiError::Message(error.to_string()))?;
    validate(commit.trim())
}
