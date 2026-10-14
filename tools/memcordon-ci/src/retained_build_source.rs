//! Fixed normalization-owned destinations, never recursive evidence-root repair.
use std::path::Path;

pub fn prepare_locked_source_tree(recipe_prefix: &Path) -> Result<(), String> {
    let prefix = std::fs::symlink_metadata(recipe_prefix).map_err(|error| {
        format!("inspect retained build recipe prefix {recipe_prefix:?}: {error}")
    })?;
    if !prefix.is_dir() || prefix.file_type().is_symlink() {
        return Err("retained build recipe prefix is not an existing directory".into());
    }
    for relative in ["locked-source", "locked-source/src", "locked-source/tests"] {
        let path = recipe_prefix.join(relative);
        std::fs::create_dir(&path).map_err(|error| {
            format!("create exclusive retained build directory {path:?}: {error}")
        })?;
    }
    Ok(())
}
