//! Native-tool path spelling remains separate from canonical input identity.
use std::io;
use std::path::{Path, PathBuf};

pub fn command_path(path: &Path) -> io::Result<PathBuf> {
    let identity = path.canonicalize()?;
    #[cfg(windows)]
    {
        let spelling = windows_command_spelling(&identity)?;
        if spelling.canonicalize()? != identity {
            return Err(io::Error::other(
                "native command path changes filesystem identity",
            ));
        }
        Ok(spelling)
    }
    #[cfg(not(windows))]
    Ok(identity)
}

/// Preserve the executable basename: multicall tools dispatch on argv[0].
pub fn command_program(path: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("tool parent missing"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("tool name missing"))?;
        Ok(command_path(parent)?.join(name))
    }
    #[cfg(not(windows))]
    Ok(path.to_path_buf())
}

/// Outputs may not exist yet; validate their nearest existing ancestor.
#[allow(dead_code)] // The dependency-free seed creates outputs beneath its verified root.
pub fn command_output_path(path: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        if path.try_exists()? {
            return command_path(path);
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("output parent missing"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("output name missing"))?;
        windows_command_spelling(&command_output_path(parent)?.join(name))
    }
    #[cfg(not(windows))]
    Ok(path.to_path_buf())
}

#[cfg(windows)]
pub fn windows_command_spelling(path: &Path) -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Prefix};
    let invalid = || io::Error::other("unsupported native command path namespace");
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid());
    };
    let mut root = OsString::new();
    match prefix.kind() {
        Prefix::VerbatimDisk(drive) | Prefix::Disk(drive) => {
            root.push(char::from(drive).to_string());
            root.push(":\\");
        }
        Prefix::VerbatimUNC(server, share) | Prefix::UNC(server, share) => {
            if server.is_empty() || share.is_empty() {
                return Err(invalid());
            }
            root.push("\\\\");
            root.push(server);
            root.push("\\");
            root.push(share);
            root.push("\\");
        }
        _ => return Err(invalid()),
    }
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid());
    }
    let mut result = PathBuf::from(root);
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid());
        };
        // Ordinary Win32 paths normalize these suffixes, unlike verbatim paths.
        if name
            .encode_wide()
            .last()
            .is_some_and(|unit| unit == u16::from(b'.') || unit == u16::from(b' '))
        {
            return Err(invalid());
        }
        result.push(name);
    }
    Ok(result)
}
