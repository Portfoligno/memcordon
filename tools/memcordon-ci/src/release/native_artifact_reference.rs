//! Join an exact original artifact reference to its already-owned native case.
use std::path::{Path, PathBuf};

pub(crate) fn resolve_case_reference(
    directory: &Path,
    prefix: &str,
    reference: &str,
    leaf: &str,
) -> Result<PathBuf, String> {
    let ordinary = |part: &str| {
        !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', ':', '\0'])
    };
    if !directory.is_absolute()
        || !ordinary(leaf)
        || leaf.contains('/')
        || !prefix.split('/').all(ordinary)
        || reference.rsplit_once('/') != Some((prefix, leaf))
    {
        return Err(
            "original component artifact reference differs from exact case prefix/leaf".into(),
        );
    }
    Ok(directory.join(leaf))
}
