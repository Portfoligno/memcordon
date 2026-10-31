use std::io::{self, Write};
use std::path::Path;

pub(crate) fn stage_snapshot(
    path: &Path,
    identities: &[(u32, u128)],
) -> io::Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staging = tempfile::NamedTempFile::new_in(parent)?;
    for (pid, birth) in identities {
        writeln!(staging, "{pid} {birth}")?;
    }
    staging.flush()?;
    // A delegated fixture reader must retain the original public file's
    // readability; the case owner protects the containing directory.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staging
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(staging)
}

pub(crate) fn publish_snapshot(path: &Path, identities: &[(u32, u128)]) -> io::Result<()> {
    stage_snapshot(path, identities)?
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
}
