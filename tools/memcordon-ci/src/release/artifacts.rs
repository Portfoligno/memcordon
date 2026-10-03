//! Finite archive and byte checks shared by preparation and publication.
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Component, Path, PathBuf},
};

pub const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_MEMBERS: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    pub name: String,
    pub kind: String,
    pub target: Option<String>,
    pub package: Option<String>,
    pub byte_len: u64,
    pub sha256: String,
}

pub fn safe_relative(path: &Path) -> Result<PathBuf> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || bytes
            .iter()
            .any(|byte| *byte < b' ' || matches!(*byte, b'\\' | b':' | 127))
        || bytes.split(|byte| *byte == b'/').any(|part| {
            part.is_empty()
                || part == b"."
                || part == b".."
                || part.last().is_some_and(|byte| matches!(*byte, b' ' | b'.'))
                || {
                    let stem = part
                        .split(|byte| *byte == b'.')
                        .next()
                        .expect("nonempty component");
                    let stem: Vec<_> = stem.iter().map(u8::to_ascii_uppercase).collect();
                    matches!(stem.as_slice(), b"CON" | b"PRN" | b"AUX" | b"NUL")
                        || (stem
                            .strip_prefix(b"COM")
                            .or_else(|| stem.strip_prefix(b"LPT"))
                            .is_some_and(|suffix| {
                                suffix.len() == 1 && matches!(suffix[0], b'1'..=b'9')
                            }))
                }
        })
    {
        return Err(CiError::Message(
            "archive path is not a safe relative member".into(),
        ));
    }
    Ok(path.into())
}

pub fn safe_basename(name: &str) -> Result<()> {
    if name.is_empty()
        || name.chars().any(char::is_control)
        || safe_relative(Path::new(name))?.components().count() != 1
    {
        return Err(CiError::Message(
            "artifact name is not a safe basename".into(),
        ));
    }
    Ok(())
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(CiError::Message("artifact may not be a symlink".into()));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_FILE_BYTES {
        return Err(CiError::Message("artifact type/length differs".into()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(CiError::Message("artifact exceeds byte bound".into()));
    }
    Ok(bytes)
}

pub fn checksum(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn check_bytes(record: &FileRecord, bytes: &[u8]) -> Result<()> {
    safe_basename(&record.name)?;
    if record.byte_len != bytes.len() as u64
        || record.byte_len > MAX_FILE_BYTES
        || record.sha256 != checksum(bytes)
    {
        return Err(CiError::Message(format!(
            "artifact length/checksum differs: {}",
            record.name
        )));
    }
    Ok(())
}

/// Read the exact compressed bytes and reject duplicate members/trailing streams.
pub fn crate_members(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(CiError::Message("crate archive byte bound exceeded".into()));
    }
    let mut archive = tar::Archive::new(flate2::bufread::GzDecoder::new(Cursor::new(bytes)));
    let mut members = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut expanded = 0_u64;
    let mut root: Option<String> = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = safe_relative(&entry.path()?)?;
        let text = path
            .to_str()
            .ok_or_else(|| CiError::Message("crate member is not UTF-8".into()))?;
        let (package_root, member) = text
            .split_once('/')
            .ok_or_else(|| CiError::Message("crate member lacks package root".into()))?;
        if root.as_deref().is_some_and(|root| root != package_root)
            || !entry.header().entry_type().is_file()
            || members.len() >= MAX_MEMBERS
            || !folded.insert(text.to_ascii_lowercase())
        {
            return Err(CiError::Message(
                "crate root/type/duplicate/member bound differs".into(),
            ));
        }
        root.get_or_insert_with(|| package_root.to_owned());
        expanded = expanded
            .checked_add(entry.size())
            .ok_or_else(|| CiError::Message("expanded archive overflow".into()))?;
        if expanded > MAX_FILE_BYTES {
            return Err(CiError::Message("expanded archive bound exceeded".into()));
        }
        let size = entry.size();
        let mut body = Vec::new();
        entry.by_ref().take(size + 1).read_to_end(&mut body)?;
        if body.len() as u64 != size {
            return Err(CiError::Message("truncated crate member".into()));
        }
        members.insert(member.to_owned(), body);
    }
    let mut decoder = archive.into_inner();
    let mut padding = Vec::new();
    decoder
        .by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut padding)?;
    if padding.len() > 1024 * 1024
        || padding.iter().any(|byte| *byte != 0)
        || decoder.into_inner().position() != bytes.len() as u64
    {
        return Err(CiError::Message(
            "crate has trailing compressed/expanded bytes".into(),
        ));
    }
    if members.is_empty() {
        return Err(CiError::Message("empty crate archive".into()));
    }
    let (name, version) = crate_identity(&members)?;
    if root.as_deref() != Some(format!("{name}-{version}").as_str()) {
        return Err(CiError::Message(
            "crate archive root differs from normalized manifest identity".into(),
        ));
    }
    Ok(members)
}

pub fn crate_identity(members: &BTreeMap<String, Vec<u8>>) -> Result<(String, semver::Version)> {
    let manifest = members
        .get("Cargo.toml")
        .ok_or_else(|| CiError::Message("crate lacks normalized Cargo.toml".into()))?;
    let manifest: toml::Value = toml::from_str(
        std::str::from_utf8(manifest)
            .map_err(|_| CiError::Message("crate manifest is not UTF-8".into()))?,
    )?;
    let package = manifest
        .get("package")
        .ok_or_else(|| CiError::Message("crate lacks package fields".into()))?;
    let name = package
        .get("name")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| CiError::Message("crate package name absent".into()))?;
    let version = package
        .get("version")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| CiError::Message("crate version absent".into()))?;
    Ok((name.into(), semver::Version::parse(version)?))
}

pub fn extract_members(members: &BTreeMap<String, Vec<u8>>, destination: &Path) -> Result<()> {
    if destination.exists() {
        return Err(CiError::Message(
            "archive extraction requires a fresh destination".into(),
        ));
    }
    fs::create_dir(destination)?;
    for (name, bytes) in members {
        let path = destination.join(safe_relative(Path::new(name))?);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
    }
    Ok(())
}
