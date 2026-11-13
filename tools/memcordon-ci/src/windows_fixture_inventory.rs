//! Preparation-time file facts only; no loader eligibility or runtime authority.
use serde_json::{Value, json};

pub const REPORT_NAME: &str = "fixture-manifest-inventory.json";
pub const REPORT_BYTES: usize = 64 * 1024;
pub const DIRECTORY_ENTRIES: usize = 1024;
pub const SIBLING_RECORDS: usize = 64;

pub struct Input<'a> {
    pub source_commit: &'a str,
    pub target: &'a str,
    pub path: &'a std::path::Path,
    pub sha256: &'a str,
    pub embedded: &'a Value,
}

/// Closed documented sibling forms. Unrelated directory contents are never copied.
pub fn sibling_kind(executable: &str, name: &str) -> Option<&'static str> {
    if !executable.is_ascii() || !name.is_ascii() {
        return None;
    }
    let prefix = name.get(..executable.len())?;
    if !prefix.eq_ignore_ascii_case(executable) {
        return None;
    }
    let folded = name.get(executable.len()..)?.to_ascii_lowercase();
    let suffix = folded.as_str();
    if suffix == ".local" {
        return Some("dotlocal");
    }
    if suffix == ".manifest" {
        return Some("external_manifest");
    }
    let id = suffix.strip_prefix('.')?.strip_suffix(".manifest")?;
    if !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()) && id.parse::<u16>().is_ok() {
        Some("external_manifest_id")
    } else {
        None
    }
}

/// The record deliberately carries no permission to redirect or accept a workload.
pub fn record(
    commit: &str,
    target: &str,
    sha256: &str,
    byte_length: Option<u64>,
    embedded: Value,
    deployment: Value,
) -> crate::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&json!({
        "format":"memcordon.fixture-manifest-deployment","revision":1,
        "diagnostic_only":true,"acceptance_authority":false,
        "redirection_authorized":false,"loader_eligibility_proved":false,
        "source_commit":commit,"target":target,"fixture_sha256":sha256,
        "fixture_bytes":byte_length,"embedded":embedded,"deployment":deployment,
        "snapshot_scope":"preparation-time held deployed image and sibling observations",
        "continuous_sibling_absence_proved":false
    }))?;
    if bytes.len() > REPORT_BYTES {
        return Err(crate::CiError::Message(
            "fixture inventory report bound exceeded".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(windows)]
pub fn publish_to(
    input: &Input<'_>,
    output: &std::path::Path,
    cutoff: std::time::Instant,
) -> crate::Result<()> {
    use std::{fs, io::Write};
    live(cutoff)?;
    let (length, embedded, deployment) = snapshot(input, cutoff);
    let bytes = record(
        input.source_commit,
        input.target,
        input.sha256,
        length,
        embedded,
        deployment,
    )?;
    live(cutoff)?;
    let parent = output
        .parent()
        .ok_or_else(|| crate::CiError::Message("fixture report parent missing".into()))?;
    let _parents = directory(parent, cutoff)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    live(cutoff)
}

#[cfg(windows)]
fn directory(
    path: &std::path::Path,
    cutoff: std::time::Instant,
) -> crate::Result<Vec<std::fs::File>> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || path.ancestors().count() > 64
    {
        return Err(crate::CiError::Message(
            "fixture report directory is not bounded absolute ancestry".into(),
        ));
    }
    let mut held = Vec::new();
    for ancestor in path
        .ancestors()
        .filter(|part| !part.as_os_str().is_empty())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        live(cutoff)?;
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(ancestor)?
            }
            Err(error) => return Err(error.into()),
        }
        // Previously held no-delete parent handles span this creation and query.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(ancestor)?;
        crate::windows_native_files::native_file_identity(&file, true, ancestor)?;
        held.push(file);
    }
    Ok(held)
}

#[cfg(windows)]
fn live(cutoff: std::time::Instant) -> crate::Result<()> {
    if std::time::Instant::now() >= cutoff {
        Err(crate::CiError::Message(
            "fixture inventory original work cutoff exhausted".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn snapshot(input: &Input<'_>, cutoff: std::time::Instant) -> (Option<u64>, Value, Value) {
    let attempted = (|| -> crate::Result<(Option<u64>, Value, Value)> {
        live(cutoff)?;
        let held = crate::windows_native_files::hold_artifact(
            input.path,
            Some(input.sha256),
            512 * 1024 * 1024,
        )?;
        live(cutoff)?;
        let embedded = crate::windows_pe_manifest::inventory(&held.bytes);
        live(cutoff)?;
        if &embedded != input.embedded {
            return Err(crate::CiError::Message(
                "fixture parser snapshot differs from selected bytes".into(),
            ));
        }
        let identity = held.identity(input.path)?;
        let siblings = siblings(input.path, cutoff);
        live(cutoff)?;
        crate::windows_native_files::verify_named_artifact(&held, input.path)?;
        live(cutoff)?;
        Ok((
            Some(held.bytes.len() as u64),
            embedded,
            json!({
                "image_state":"held_exact_selected_image","volume_serial":identity.0,
                "file_index":identity.1,"siblings":siblings
            }),
        ))
    })();
    match attempted {
        Ok(value) => value,
        Err(error) => (
            None,
            input.embedded.clone(),
            json!({
                "image_state":"incomplete","phase":"held-image-or-sibling-snapshot",
                "native_error":match &error { crate::CiError::Io(error)=>error.raw_os_error(), _=>None },
                "error_sha256":crate::windows_causal_acceptance::sha256(error.to_string().as_bytes()),
                "absence_proved":false
            }),
        ),
    }
}

#[cfg(windows)]
fn siblings(image: &std::path::Path, cutoff: std::time::Instant) -> Value {
    use std::{
        fs,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut phase = "directory-ancestry";
    let mut rows = Vec::new();
    let mut visited = 0usize;
    let result = (|| -> crate::Result<()> {
        live(cutoff)?;
        let parent = image
            .parent()
            .ok_or_else(|| crate::CiError::Message("fixture parent missing".into()))?;
        let _parents = crate::windows_native_files::hold_ancestors(parent)?;
        let executable = image
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| crate::CiError::Message("fixture name is not Unicode".into()))?;
        phase = "directory-enumeration";
        let mut paths = std::collections::BTreeSet::new();
        // Exact default manifest and .local checks are required even if not listed.
        for suffix in [".manifest", ".1.manifest", ".local"] {
            let mut name = image.file_name().unwrap().to_os_string();
            name.push(suffix);
            paths.insert(parent.join(name));
        }
        live(cutoff)?;
        for entry in fs::read_dir(parent)? {
            live(cutoff)?;
            let entry = entry?;
            visited += 1;
            if visited > DIRECTORY_ENTRIES {
                return Err(crate::CiError::Message(
                    "fixture sibling directory bound exceeded".into(),
                ));
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                crate::CiError::Message("sibling directory contains non-Unicode name".into())
            })?;
            if !name.is_ascii() || !executable.is_ascii() {
                return Err(crate::CiError::Message(
                    "non-ASCII sibling case comparison unsupported".into(),
                ));
            }
            if sibling_kind(executable, name).is_some() {
                paths.insert(entry.path());
            }
        }
        if paths.len() > SIBLING_RECORDS {
            return Err(crate::CiError::Message(
                "fixture sibling record bound exceeded".into(),
            ));
        }
        let mut held = Vec::new();
        let mut manifests = Vec::new();
        let mut payload_bytes = 0usize;
        for path in paths {
            live(cutoff)?;
            phase = "exact-sibling-metadata";
            let name = path.file_name().and_then(|value| value.to_str()).unwrap();
            let kind = sibling_kind(executable, name).unwrap();
            let name_sha256 = crate::windows_causal_acceptance::sha256(name.as_bytes());
            let metadata = match fs::symlink_metadata(&path) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    rows.push(
                        json!({"kind":kind,"name_sha256":name_sha256,"state":"absent-at-query"}),
                    );
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if metadata.file_attributes() & 0x400 != 0 {
                rows.push(json!({"kind":kind,"name_sha256":name_sha256,"state":"reparse-unknown"}));
                return Err(crate::CiError::Message(
                    "fixture sibling is a reparse point".into(),
                ));
            }
            phase = "held-sibling-identity";
            let file = fs::OpenOptions::new()
                .access_mode(0)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(&path)?;
            let identity =
                crate::windows_native_files::native_file_identity(&file, metadata.is_dir(), &path)?;
            let mut row = json!({"kind":kind,"name_sha256":name_sha256,"state":if metadata.is_dir(){"directory"}else{"regular-file"},"volume_serial":identity.0,"file_index":identity.1});
            if kind != "dotlocal" && metadata.is_file() {
                phase = "held-manifest-bytes";
                live(cutoff)?;
                let manifest =
                    crate::windows_native_files::hold_artifact(&path, None, 1024 * 1024)?;
                if manifest.identity(&path)? != identity {
                    return Err(crate::CiError::Message(
                        "fixture sibling native identity changed".into(),
                    ));
                }
                payload_bytes = payload_bytes
                    .checked_add(manifest.bytes.len())
                    .ok_or_else(|| crate::CiError::Message("sibling extent overflow".into()))?;
                if payload_bytes > 1024 * 1024 {
                    return Err(crate::CiError::Message(
                        "sibling manifest byte bound exceeded".into(),
                    ));
                }
                row["bytes"] = json!(manifest.bytes.len());
                row["sha256"] = json!(manifest.sha256);
                manifests.push(manifest);
            }
            held.push(file);
            rows.push(row);
        }
        live(cutoff)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            json!({"complete":true,"entries_visited":visited,"rows":rows,"absence_scope":"exact names at preparation queries; not continuous"})
        }
        Err(error) => {
            json!({"complete":false,"phase":phase,"entries_visited":visited,"rows":rows,"native_error":match &error {crate::CiError::Io(error)=>error.raw_os_error(), _=>None},"error_sha256":crate::windows_causal_acceptance::sha256(error.to_string().as_bytes()),"absence_proved":false})
        }
    }
}
