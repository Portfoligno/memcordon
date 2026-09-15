pub mod identity;
pub mod runtime;

use std::fs;
use std::path::{Path, PathBuf};

pub struct BuildIdentity {
    pub commit: String,
    pub inputs: Vec<PathBuf>,
}

fn read(path: &Path, inputs: &mut Vec<PathBuf>) -> Result<Option<String>, String> {
    inputs.push(path.to_owned());
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// Collect filesystem inputs and delegate parsing to pure helpers. No Git
/// subprocess or inherited commit environment variable influences selection.
pub fn load(manifest: &Path) -> Result<BuildIdentity, String> {
    let mut inputs = Vec::new();
    let packaged = read(&manifest.join(".cargo_vcs_info.json"), &mut inputs)?;
    if let Some(packaged) = packaged {
        return Ok(BuildIdentity {
            commit: identity::select(Some(packaged.as_bytes()), None, None)?,
            inputs,
        });
    }
    let mut checkout = None;
    for ancestor in manifest.ancestors() {
        let pointer = ancestor.join(".git");
        inputs.push(pointer.clone());
        let git = if pointer.is_dir() {
            Some(pointer)
        } else if pointer.is_file() {
            let value = fs::read_to_string(&pointer).map_err(|error| error.to_string())?;
            let target = value
                .trim()
                .strip_prefix("gitdir: ")
                .ok_or("invalid Git directory pointer")?;
            Some(ancestor.join(target))
        } else {
            None
        };
        let Some(git) = git else { continue };
        let common = read(&git.join("commondir"), &mut inputs)?
            .map_or_else(|| git.clone(), |path| git.join(path.trim()));
        let head = read(&git.join("HEAD"), &mut inputs)?.ok_or("Git HEAD is unreadable")?;
        let mut loose = Vec::new();
        if let Some(reference) = identity::reference(&head) {
            loose.push(read(&git.join(reference), &mut inputs)?);
            if common != git {
                loose.push(read(&common.join(reference), &mut inputs)?);
            }
        }
        let packed = [
            read(&git.join("packed-refs"), &mut inputs)?,
            read(&common.join("packed-refs"), &mut inputs)?,
        ];
        checkout = identity::resolve_head(&head, &loose, &packed)?;
        break;
    }
    let release = read(&manifest.join(".memcordon-source.json"), &mut inputs)?;
    Ok(BuildIdentity {
        commit: identity::select(
            None,
            checkout.as_deref(),
            release.as_deref().map(str::as_bytes),
        )?,
        inputs,
    })
}
