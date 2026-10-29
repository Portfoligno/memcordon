//! Caller bundle framing and content validation; never opens a host pathname.
pub use crate::workload_files::{ImageEntryV1, ImageEntrypointV1};
use crate::{BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

pub const MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const MEMBER_BYTES: u64 = 1024 * 1024 * 1024;
pub const IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const STREAM_BYTES: usize = 64 * 1024;
pub const BUNDLE_MAGIC: &[u8] = b"memcordon.workload-bundle\0\x01";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifestV1 {
    pub format: String,
    pub revision: u32,
    pub target: String,
    pub entries: BoundedVec<ImageEntryV1, 16384>,
    pub entrypoints: BoundedVec<ImageEntrypointV1, 16>,
    pub library_directories: BoundedVec<crate::workload_request::RootRelativePath, 32>,
}
impl SnapshotManifestV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MANIFEST_BYTES {
            return Err("manifest exceeds byte ceiling".into());
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.workload-snapshot"
            || self.revision != 1
            || !matches!(
                self.target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
        {
            return Err("unsupported snapshot format or target".into());
        }
        let mut paths = BTreeMap::new();
        let mut total = 0_u64;
        let mut resolved_links = BTreeSet::new();
        for entry in self.entries.as_slice() {
            let path = entry.path();
            if path.as_str().split('/').count() > 64
                || paths.insert(path.as_str(), entry).is_some()
                || matches!(
                    path.as_str().split('/').next(),
                    Some("proc" | "dev" | "sys")
                )
            {
                return Err("unsafe or duplicate snapshot path".into());
            }
            if let ImageEntryV1::Regular { size, .. } = entry {
                if *size > MEMBER_BYTES {
                    return Err("member exceeds byte ceiling".into());
                }
                total = total.checked_add(*size).ok_or("snapshot size overflow")?;
                if total > IMAGE_BYTES {
                    return Err("snapshot exceeds byte ceiling".into());
                }
            }
        }
        for entry in self.entries.as_slice() {
            let mut path = entry.path().as_str();
            while let Some((parent, _)) = path.rsplit_once('/') {
                if paths.contains_key(parent) {
                    return Err("snapshot file is also a parent".into());
                }
                path = parent;
            }
            if let ImageEntryV1::Symlink { path, target } = entry {
                if resolved_links.contains(path.as_str()) {
                    continue;
                }
                let mut seen = BTreeSet::from([path.as_str()]);
                let mut current = target.as_str();
                loop {
                    if resolved_links.contains(current) {
                        break;
                    }
                    if !seen.insert(current) {
                        return Err("snapshot symlink cycle".into());
                    }
                    match paths.get(current) {
                        Some(ImageEntryV1::Symlink { target, .. }) => current = target.as_str(),
                        Some(ImageEntryV1::Regular { .. }) => break,
                        None => return Err("snapshot symlink target absent".into()),
                    }
                }
                resolved_links.extend(seen);
            }
        }
        let mut ids = BTreeSet::new();
        let mut libraries = BTreeSet::new();
        for directory in self.library_directories.as_slice() {
            if !libraries.insert(directory)
                || matches!(
                    directory.as_str().split('/').next(),
                    Some("proc" | "dev" | "sys" | "run")
                )
                || !self
                    .entries
                    .as_slice()
                    .iter()
                    .any(|entry| crate::workload_files::is_beneath(entry.path(), directory))
            {
                return Err("library directory lacks confined immutable snapshot members".into());
            }
        }
        for entrypoint in self.entrypoints.as_slice() {
            if !ids.insert(&entrypoint.id)
                || !matches!(
                    paths.get(entrypoint.path.as_str()),
                    Some(ImageEntryV1::Regular {
                        executable: true,
                        ..
                    })
                )
            {
                return Err("invalid snapshot entrypoint".into());
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut ordered = self.clone();
        let mut entries = self.entries.as_slice().to_vec();
        entries.sort_by(|a, b| a.path().cmp(b.path()));
        ordered.entries = BoundedVec::default();
        for entry in entries {
            ordered
                .entries
                .try_push(entry)
                .map_err(|_| "too many entries")?;
        }
        let mut entrypoints = self.entrypoints.as_slice().to_vec();
        entrypoints.sort_by(|a, b| a.id.cmp(&b.id));
        ordered.entrypoints = BoundedVec::default();
        for entrypoint in entrypoints {
            ordered
                .entrypoints
                .try_push(entrypoint)
                .map_err(|_| "too many entrypoints")?;
        }
        let bytes = serde_json::to_vec(&ordered).map_err(|e| e.to_string())?;
        if bytes.len() > MANIFEST_BYTES {
            return Err("manifest exceeds byte ceiling".into());
        }
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<DiagnosticSha256, String> {
        Ok(DiagnosticSha256::from_bytes(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }
    pub fn regular_members(&self) -> Vec<&ImageEntryV1> {
        let mut entries: Vec<_> = self
            .entries
            .as_slice()
            .iter()
            .filter(|entry| matches!(entry, ImageEntryV1::Regular { .. }))
            .collect();
        entries.sort_by(|a, b| a.path().cmp(b.path()));
        entries
    }
}

pub fn write_bundle_headers<W: Write>(
    writer: &mut W,
    runtime: &SnapshotManifestV1,
    input: &SnapshotManifestV1,
) -> Result<(), String> {
    validate_combined(runtime, input)?;
    writer.write_all(BUNDLE_MAGIC).map_err(|e| e.to_string())?;
    for manifest in [runtime, input] {
        let bytes = manifest.canonical_bytes()?;
        let length = u64::try_from(bytes.len()).map_err(|_| "manifest length overflow")?;
        writer
            .write_all(&length.to_be_bytes())
            .and_then(|_| writer.write_all(&bytes))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn read_bundle_headers<R: Read>(
    reader: &mut R,
) -> Result<(SnapshotManifestV1, SnapshotManifestV1), String> {
    let mut magic = vec![0; BUNDLE_MAGIC.len()];
    reader.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if magic != BUNDLE_MAGIC {
        return Err("unsupported bundle format".into());
    }
    let mut read_manifest = || -> Result<SnapshotManifestV1, String> {
        let mut length = [0; std::mem::size_of::<u64>()];
        reader.read_exact(&mut length).map_err(|e| e.to_string())?;
        let length =
            usize::try_from(u64::from_be_bytes(length)).map_err(|_| "manifest length overflow")?;
        if length > MANIFEST_BYTES {
            return Err("manifest exceeds byte ceiling".into());
        }
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).map_err(|e| e.to_string())?;
        SnapshotManifestV1::parse(&bytes)
    };
    let runtime = read_manifest()?;
    let input = read_manifest()?;
    validate_combined(&runtime, &input)?;
    Ok((runtime, input))
}
pub fn validate_combined(
    runtime: &SnapshotManifestV1,
    input: &SnapshotManifestV1,
) -> Result<(), String> {
    runtime.validate()?;
    input.validate()?;
    if runtime.target != input.target {
        return Err("snapshot targets differ".into());
    }
    let mut paths = BTreeSet::new();
    let mut total = 0_u64;
    for entry in runtime
        .entries
        .as_slice()
        .iter()
        .chain(input.entries.as_slice())
    {
        if !paths.insert(entry.path().as_str()) {
            return Err("runtime/input path collision".into());
        }
        if let ImageEntryV1::Regular { size, .. } = entry {
            total = total.checked_add(*size).ok_or("combined size overflow")?;
        }
    }
    for path in &paths {
        let mut current = *path;
        while let Some((parent, _)) = current.rsplit_once('/') {
            if paths.contains(parent) {
                return Err("combined snapshot parent collision".into());
            }
            current = parent;
        }
    }
    if total > IMAGE_BYTES {
        return Err("combined immutable root exceeds byte ceiling".into());
    }
    Ok(())
}

pub fn validate_layout(
    runtime: &SnapshotManifestV1,
    input: &SnapshotManifestV1,
    layout: &crate::workload_request::PrivateRootLayoutV1,
) -> Result<(), String> {
    use crate::workload_files::is_beneath;
    validate_combined(runtime, input)?;
    layout.validate().map_err(|error| error.to_string())?;
    for manifest in [runtime, input] {
        for root in layout.writable_roots.as_slice() {
            for path in manifest
                .entries
                .as_slice()
                .iter()
                .map(ImageEntryV1::path)
                .chain(manifest.library_directories.as_slice())
            {
                if &root.path == path
                    || is_beneath(&root.path, path)
                    || is_beneath(path, &root.path)
                {
                    return Err("immutable snapshot or loader search overlaps writable root".into());
                }
            }
        }
    }
    Ok(())
}

/// Copies exactly one declared member with bounded memory and verifies its digest.
/// The caller owns deadlines, native destination custody and partial-copy cleanup.
pub fn stream_member<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    member: &ImageEntryV1,
) -> Result<(), String> {
    let ImageEntryV1::Regular { size, sha256, .. } = member else {
        return Err("symlink has no member byte stream".into());
    };
    if *size > MEMBER_BYTES {
        return Err("member exceeds byte ceiling".into());
    }
    let mut remaining = *size;
    let mut buffer = [0; STREAM_BYTES];
    let mut digest = Sha256::new();
    while remaining != 0 {
        let amount = usize::try_from(
            remaining.min(u64::try_from(buffer.len()).expect("buffer length fits u64")),
        )
        .expect("bounded chunk fits usize");
        reader
            .read_exact(&mut buffer[..amount])
            .map_err(|e| e.to_string())?;
        digest.update(&buffer[..amount]);
        writer
            .write_all(&buffer[..amount])
            .map_err(|e| e.to_string())?;
        remaining -= u64::try_from(amount).expect("chunk fits u64");
    }
    if DiagnosticSha256::from_bytes(digest.finalize().into()) != *sha256 {
        return Err("member content digest differs".into());
    }
    Ok(())
}
