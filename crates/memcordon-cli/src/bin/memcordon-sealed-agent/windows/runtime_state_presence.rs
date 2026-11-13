use std::path::Path;

/// Native path presence only; Present does not approve directory ACLs or children.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeStatePresence {
    Absent,
    Present,
}

pub(super) fn inspect(
    path: &Path,
    reject_components: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<RuntimeStatePresence, String> {
    reject_components(path)?;
    let mut components = path.ancestors().collect::<Vec<_>>();
    components.reverse();
    let mut presence = RuntimeStatePresence::Absent;
    for component in components {
        let metadata = match std::fs::symlink_metadata(component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "MCSEALED-WINDOWS-RUNTIME-STATE: path={} actual=unreadable error={error}",
                    component.display()
                ));
            }
        };
        let reparse = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let reparse = {
            use std::os::windows::fs::MetadataExt;
            reparse
                || metadata.file_attributes()
                    & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                    != 0
        };
        if reparse || !metadata.is_dir() {
            return Err(format!(
                "MCSEALED-WINDOWS-RUNTIME-STATE: path={} actual=non-directory-or-reparse",
                component.display()
            ));
        }
        if component == path {
            presence = RuntimeStatePresence::Present;
        }
    }
    Ok(presence)
}
