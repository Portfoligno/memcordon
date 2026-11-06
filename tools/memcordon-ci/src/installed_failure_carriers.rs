//! Finite original-call failure carriers shared by installed diagnostic delivery.
use std::{
    collections::BTreeSet,
    io,
    path::{Path, PathBuf},
};

pub const RELATIVE_PATHS: [&str; 10] = [
    "windows-installed/C-IO/empty-message/result.callback-failure.json",
    "windows-installed/C-IO/empty-message/result.stderr.bin",
    "windows-installed/C-IO/empty-message/result.winsock-startup-trace.json",
    "windows-installed/C-IO/empty-message/result.listener-call-trace.json",
    "windows-installed/W-JOINT/restricted/result.callback-failure.json",
    "windows-installed/W-JOINT/restricted/result.stderr.bin",
    "windows-installed/W-JOINT/restricted/result.winsock-startup-trace.json",
    "windows-installed/W-JOINT/restricted/result.listener-call-trace.json",
    "windows-installed/W-JOINT/restricted/result.loader-fileio.json",
    "windows-installed/fixture-manifest-inventory.json",
];

/// These exact leaves are already written by bounded package/recovery capture.
pub const PACKAGE_CLEANUP_PATHS: [&str; 6] = [
    "package-uninstall.stdout.bin",
    "package-uninstall.stderr.bin",
    "package-uninstall.capture.json",
    "package-uninstall.invocation.json",
    "recovery.stdout.bin",
    "recovery.stderr.bin",
];

pub fn package_cleanup_paths(prefix: &str) -> String {
    PACKAGE_CLEANUP_PATHS
        .iter()
        .map(|relative| format!("{prefix}/{relative}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn paths(prefix: &str) -> String {
    RELATIVE_PATHS
        .iter()
        .chain(PACKAGE_CLEANUP_PATHS.iter())
        .map(|relative| format!("{prefix}/{relative}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn unlinked(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    true
}

fn priority_file(source: &Path, relative: &str) -> io::Result<Option<PathBuf>> {
    let root = match std::fs::symlink_metadata(source) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !root.is_dir() || !unlinked(&root) {
        return Ok(None);
    }
    let mut path = source.to_path_buf();
    let mut components = Path::new(relative).components().peekable();
    while let Some(component) = components.next() {
        path.push(component);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !unlinked(&metadata)
            || if components.peek().is_some() {
                !metadata.is_dir()
            } else {
                !metadata.is_file()
            }
        {
            return Ok(None);
        }
    }
    Ok(Some(path))
}

/// Keep the established 4096-entry scan and 128-file selection bounds. Known
/// carriers are found directly first, then charged to that same selected set.
pub fn select(source: &Path) -> io::Result<Vec<PathBuf>> {
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for relative in RELATIVE_PATHS.into_iter().chain(PACKAGE_CLEANUP_PATHS) {
        if let Some(path) = priority_file(source, relative)? {
            seen.insert(path.clone());
            selected.push(path);
        }
    }
    let mut recent = Vec::new();
    for (index, entry) in walkdir::WalkDir::new(source)
        .follow_links(false)
        .follow_root_links(false)
        .into_iter()
        .enumerate()
    {
        if index >= 4096 {
            eprintln!("optional installed diagnostics truncated at entry bound");
            break;
        }
        let entry = entry.map_err(io::Error::other)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !path.extension().is_some_and(|extension| {
            extension == "json" || extension == "txt" || extension == "bin"
        }) {
            continue;
        }
        let metadata = entry.metadata().map_err(io::Error::other)?;
        recent.push((metadata.modified()?, path.to_owned()));
    }
    recent.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    for (_, path) in recent {
        if seen.insert(path.clone()) {
            selected.push(path);
        }
        if selected.len() == 128 {
            break;
        }
    }
    Ok(selected)
}
