//! Registry manifests must not inherit a surrounding Cargo workspace.
use std::path::Path;

pub(crate) fn require_independent(directory: &Path) -> Result<(), String> {
    let canonical = directory
        .canonicalize()
        .map_err(|error| error.to_string())?;
    for ancestor in canonical.ancestors() {
        match ancestor.join("Cargo.toml").symlink_metadata() {
            Ok(_) => {
                return Err("public registry acquisition has an ancestor Cargo manifest".into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "public registry ancestor inspection failed: {error}"
                ));
            }
        }
    }
    Ok(())
}
