use memcordon_windows_launch_core::{ArtifactRefV1, RedactionClassV1};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path};

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<ArtifactRefV1, String> {
    let root = path
        .parent()
        .ok_or_else(|| format!("artifact path has no parent: {}", path.display()))?;
    write_json_in(root, path, value, RedactionClassV1::RedactedSummary)
}

pub fn write_json_in<T: Serialize>(
    root: &Path,
    path: &Path,
    value: &T,
    redaction: RedactionClassV1,
) -> Result<ArtifactRefV1, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, &bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    reference(root, path, &bytes, "application/json", redaction)
}

pub fn write_text_in(
    root: &Path,
    path: &Path,
    value: &str,
    media_type: &str,
    redaction: RedactionClassV1,
) -> Result<ArtifactRefV1, String> {
    let mut bytes = value.as_bytes().to_vec();
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    fs::write(path, &bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    reference(root, path, &bytes, media_type, redaction)
}

pub fn copy_file_in(
    root: &Path,
    source: &Path,
    destination: &Path,
    media_type: &str,
    redaction: RedactionClassV1,
) -> Result<ArtifactRefV1, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("attachment path has no parent: {}", destination.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let bytes = fs::read(source)
        .map_err(|error| format!("read external attachment {}: {error}", source.display()))?;
    fs::write(destination, &bytes)
        .map_err(|error| format!("write {}: {error}", destination.display()))?;
    reference(root, destination, &bytes, media_type, redaction)
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("decode {}: {error}", path.display()))
}

pub fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn reference(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    media_type: &str,
    redaction: RedactionClassV1,
) -> Result<ArtifactRefV1, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| format!("artifact path escapes run root: {}", path.display()))?;
    ArtifactRefV1::new(
        relative.to_string_lossy().into_owned(),
        hex::encode(Sha256::digest(bytes)),
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        String::from(media_type),
        redaction,
    )
    .map_err(|error| error.to_string())
}

pub fn verify_reference(root: &Path, reference: &ArtifactRefV1) -> Result<(), String> {
    let path = root.join(reference.relative_path());
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("resolve {}: {error}", root.display()))?;
    let canonical_path = path
        .canonicalize()
        .map_err(|error| format!("resolve {}: {error}", path.display()))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(format!(
            "artifact path escapes run root: {}",
            path.display()
        ));
    }
    let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != reference.byte_length()
        || hex::encode(Sha256::digest(&bytes)) != reference.sha256()
    {
        return Err(format!("artifact identity mismatch: {}", path.display()));
    }
    Ok(())
}

pub fn ensure_empty_directory(path: &Path) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut entries = fs::read_dir(path)
                .map_err(|read_error| format!("inspect {}: {read_error}", path.display()))?;
            if entries.next().is_none() {
                Ok(())
            } else {
                Err(format!("output directory is not empty: {}", path.display()))
            }
        }
        Err(error) => Err(format!("create {}: {error}", path.display())),
    }
}
