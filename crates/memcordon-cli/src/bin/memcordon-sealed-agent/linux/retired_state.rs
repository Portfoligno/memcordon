//! Require reserved provider-registration paths to be absent before serving requests.
//! Records are never decoded or resumed. Any present inode, including a symlink
//! or malformed file, fails this guard; an absent path passes it.

use std::path::{Component, Path, PathBuf};

pub(crate) fn require_absent(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("retired release state path must be absolute".into());
    }
    let mut prefix = PathBuf::from("/");
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => prefix.push(name),
            _ => return Err("retired release state path is unsafe".into()),
        }
        match std::fs::symlink_metadata(&prefix) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("retired release state parent is a symlink".into());
            }
            Ok(metadata) if components.peek().is_some() && !metadata.is_dir() => {
                return Err("retired release state parent is not a directory".into());
            }
            Ok(_) if components.peek().is_none() => {
                return Err("retired release registration is unavailable under R3".into());
            }
            Ok(_) => {}
        }
    }
    Err("retired release state path has no file name".into())
}

/// Require both reserved provider-registration paths to be absent.
pub(crate) fn require_provider_registrations_absent() -> Result<(), String> {
    for path in [
        "/var/lib/memcordon/private-public-cases/pending.v2.json",
        "/var/lib/memcordon/hosted-public-cases/active.v1.json",
    ] {
        require_absent(Path::new(path))?;
    }
    Ok(())
}
