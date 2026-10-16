use std::fs;
use std::path::{Path, PathBuf};

const CACHE_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

/// Locate a conservatively bounded Cargo output tree without assuming OUT_DIR depth.
pub fn output_root(out_dir: &Path) -> Option<PathBuf> {
    let out_dir = out_dir.canonicalize().ok()?;
    let mut root = None;
    for ancestor in out_dir.ancestors() {
        let tag = ancestor.join("CACHEDIR.TAG");
        match fs::read_to_string(tag) {
            Ok(contents) if contents.lines().next() == Some(CACHE_SIGNATURE) => {
                root = Some(ancestor.to_path_buf());
            }
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    root
}

fn contains_symlink(directory: &Path) -> std::io::Result<bool> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() || (kind.is_dir() && contains_symlink(&entry.path())?) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Observe optional-file creation without making Cargo observe its own outputs.
/// Ambiguous or overlapping layouts retain the conservative missing-file watch.
pub fn watch_path(path: &Path, output_root: Option<&Path>) -> PathBuf {
    if path.exists() {
        return path.to_path_buf();
    }
    let Some(output_root) = output_root.and_then(|root| root.canonicalize().ok()) else {
        return path.to_path_buf();
    };
    let Some(parent) = path.ancestors().skip(1).find(|ancestor| ancestor.is_dir()) else {
        return path.to_path_buf();
    };
    let Ok(parent) = parent.canonicalize() else {
        return path.to_path_buf();
    };
    if parent.starts_with(&output_root)
        || output_root.starts_with(&parent)
        || contains_symlink(&parent).unwrap_or(true)
    {
        return path.to_path_buf();
    }
    parent
}
