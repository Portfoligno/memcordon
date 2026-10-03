//! Cargo package creation and source extraction for Windows product tests.

use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;

use crate::{CiError, Result};

pub(crate) fn create_package_archives(
    root: &Path,
    stable: &str,
    packages: &[String],
    target: Option<&Path>,
) -> Result<PathBuf> {
    let output = memcordon_ci::command::PackageOutput::new(root, target)?;
    output.command(root, stable, packages).run()?;
    Ok(output.archive_directory())
}

pub(crate) fn extract_crate_source(archive_path: &Path, destination: &Path) -> Result<()> {
    let decoder = GzDecoder::new(File::open(archive_path)?);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let relative = normalized_member_path(&entry.path()?)?;
        let output = destination.join(relative);
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&output)?;
        } else if entry.header().entry_type().is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = File::create(output)?;
            std::io::copy(&mut entry, &mut file)?;
        } else {
            return Err(CiError::Message(
                "crate archive contains a non-file member".into(),
            ));
        }
    }
    Ok(())
}

fn normalized_member_path(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let package_root = components
        .next()
        .ok_or_else(|| CiError::Message("package archive contains an empty path".into()))?;
    if !matches!(package_root, Component::Normal(_)) {
        return Err(CiError::Message(
            "package archive root is not a normal relative path".into(),
        ));
    }
    let mut normalized = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(value) => normalized.push(value),
            _ => {
                return Err(CiError::Message(
                    "package archive contains a forbidden path component".into(),
                ));
            }
        }
    }
    Ok(normalized)
}
