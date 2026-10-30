//! Resolve current input/output paths without following substituted ancestors.
use crate::{CiError, Result};
use std::{fs, path::Path};

pub fn record_path(root: &Path, relative: &Path) -> Result<std::path::PathBuf> {
    let mut path = root.canonicalize()?;
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(CiError::Message(
                "native record path must be relative".into(),
            ));
        };
        path.push(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let final_part = index + 1 == components.len();
                if metadata.file_type().is_symlink()
                    || if final_part {
                        !metadata.is_file()
                    } else {
                        !metadata.is_dir()
                    }
                {
                    return Err(CiError::Message(
                        "native record path has unsafe file kind".into(),
                    ));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(CiError::Message(
                            "native record path traverses reparse point".into(),
                        ));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}
