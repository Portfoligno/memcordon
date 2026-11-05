//! Finite diagnostic projections; these files never supply component authority.
use crate::{CiError, Result};
#[cfg(not(windows))]
use std::io::Read;
use std::{
    fs,
    io::Write,
    path::{Component, Path},
    time::Instant,
};

fn live(cutoff: Instant) -> Result<()> {
    if Instant::now() >= cutoff {
        Err(CiError::Message(
            "component diagnostic original cleanup cutoff exhausted".into(),
        ))
    } else {
        Ok(())
    }
}

fn read(path: &Path, cutoff: Instant) -> Result<Vec<u8>> {
    live(cutoff)?;
    #[cfg(windows)]
    {
        let bytes = crate::windows_native_files::hold_artifact(
            path,
            None,
            crate::windows_component_diagnostics::INPUT_BYTES as u64,
        )?
        .bytes;
        live(cutoff)?;
        Ok(bytes)
    }
    #[cfg(not(windows))]
    {
        for parent in path.ancestors() {
            if parent.as_os_str().is_empty() {
                continue;
            }
            if fs::symlink_metadata(parent)?.file_type().is_symlink() {
                return Err(CiError::Message(
                    "component diagnostic path is a link".into(),
                ));
            }
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file()
            || file.metadata()?.len() > crate::windows_component_diagnostics::INPUT_BYTES as u64
        {
            return Err(CiError::Message(
                "component diagnostic source type/extent differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(crate::windows_component_diagnostics::INPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > crate::windows_component_diagnostics::INPUT_BYTES {
            return Err(CiError::Message("component diagnostic source grew".into()));
        }
        live(cutoff)?;
        Ok(bytes)
    }
}

fn write(path: &Path, bytes: &[u8], cutoff: Instant) -> Result<()> {
    live(cutoff)?;
    #[cfg(windows)]
    let _parents = crate::windows_native_files::hold_ancestors(
        path.parent()
            .ok_or_else(|| CiError::Message("diagnostic output parent absent".into()))?,
    )?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    live(cutoff)
}

fn directory(path: &Path, cutoff: Instant) -> Result<()> {
    live(cutoff)?;
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                #[cfg(windows)]
                let reparse = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes()
                        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                        != 0
                };
                #[cfg(not(windows))]
                let reparse = metadata.file_type().is_symlink();
                if reparse || !metadata.is_dir() {
                    return Err(CiError::Message(
                        "component diagnostic output ancestor differs".into(),
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::create_dir_all(path)?;
    live(cutoff)
}

/// Preserve the settled operation, including its exact panic payload, while
/// making a diagnostic failure secondary and observable.
pub fn after<T>(
    operation: impl FnOnce() -> Result<T>,
    retention: impl FnOnce() -> Result<()>,
) -> Result<T> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    let diagnostic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(retention))
        .unwrap_or_else(|_| {
            Err(CiError::Message(
                "component diagnostic exporter panicked".into(),
            ))
        });
    match (result, diagnostic) {
        (Ok(Err(primary)), Err(secondary)) => Err(CiError::LaneFailures {
            primary: Box::new(primary),
            secondary: Box::new(secondary),
        }),
        (Ok(result), Ok(())) => result,
        (Ok(Ok(value)), Err(error)) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "component diagnostic retention incomplete: {error}"
            );
            Ok(value)
        }
        (Err(payload), diagnostic) => {
            if let Err(error) = diagnostic {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "component panic diagnostic retention incomplete: {error}"
                );
            }
            std::panic::resume_unwind(payload)
        }
    }
}

/// Inspect only the caller's finite selector inventory and closed record list.
pub fn export(
    cases: &Path,
    destination: &Path,
    selectors: &[(String, serde_json::Value)],
    cutoff: Instant,
) -> Result<()> {
    live(cutoff)?;
    directory(destination, cutoff)?;
    #[cfg(windows)]
    let _destination_ancestors = crate::windows_native_files::hold_ancestors(destination)?;
    let mut entries = Vec::new();
    let mut files = 0usize;
    let mut retained_bytes = 0usize;
    // Reserve the bounded manifest before any output; failed/partial writes
    // still consume the same finite export allowance.
    let mut attempted_files = 1usize;
    let mut attempted_bytes = 128 * 1024usize;
    for (name, selection) in selectors {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(CiError::Message(
                "component diagnostic selector path differs".into(),
            ));
        }
        let directory = cases.join(name);
        let selected = match read(&directory.join("selection.json"), cutoff) {
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)?,
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if selected != *selection {
            return Err(CiError::Message(
                "component diagnostic selector differs".into(),
            ));
        }
        let marker = read(&directory.join("component-case-assessment.json"), cutoff)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        if marker
            .as_ref()
            .is_some_and(|value| value["collection_ok"] == true && value["retirement_ok"] == true)
        {
            continue;
        }
        let output = destination.join(name);
        live(cutoff)?;
        fs::create_dir(&output)?;
        for record in crate::windows_component_diagnostics::ALLOWED_RECORDS {
            if attempted_files >= 128 || attempted_bytes >= 4 * 1024 * 1024 {
                return Err(CiError::Message(
                    "component diagnostic existing file/byte bounds exhausted".into(),
                ));
            }
            let captured = (|| -> Result<usize> {
                let bytes = read(&directory.join(record), cutoff)?;
                let value = crate::windows_component_diagnostics::project(record, &bytes)
                    .map_err(CiError::Message)?;
                let projected = serde_json::to_vec(&value)?;
                if attempted_bytes.saturating_add(projected.len()) > 4 * 1024 * 1024 {
                    return Err(CiError::Message(
                        "component diagnostic existing byte bound exhausted".into(),
                    ));
                }
                attempted_files += 1;
                attempted_bytes += projected.len();
                write(
                    &output.join(record).with_extension("diagnostic.json"),
                    &projected,
                    cutoff,
                )?;
                Ok(projected.len())
            })();
            match captured {
                Ok(bytes) => {
                    files += 1;
                    retained_bytes += bytes;
                    entries.push(serde_json::json!({"case":name,"record":record,"state":"projected","projection_bytes":bytes}));
                }
                Err(error) => {
                    entries.push(serde_json::json!({"case":name,"record":record,"state":if matches!(&error,CiError::Io(error) if error.kind()==std::io::ErrorKind::NotFound){"missing"}else{"unavailable"}}));
                }
            }
        }
    }
    let manifest = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.windows-component-diagnostic-export","revision":1,"diagnostic_only":true,"acceptance_authority":false,"records":entries,"projection_files":files,"projection_bytes":retained_bytes,"attempted_files_including_manifest":attempted_files,"reserved_attempt_bytes_including_manifest_bound":attempted_bytes}),
    )?;
    if manifest.len() > 128 * 1024 {
        return Err(CiError::Message(
            "component diagnostic manifest bound exhausted".into(),
        ));
    }
    write(
        &destination.join("component-diagnostics.json"),
        &manifest,
        cutoff,
    )
}
