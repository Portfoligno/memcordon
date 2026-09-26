//! Versioned qualification probe bundle. All expected hashes and offsets
//! come from the independent protected collector intent; candidate artifacts
//! cannot select a loader, BPF object, build-id or probe offset.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};

use crate::{CiError, Result};

const BPF_SOURCE: &[u8] = include_bytes!("../probes/private_kernel_v1.bpf.c");
const LOADER_SOURCE: &[u8] = include_bytes!("../probes/private_kernel_v1_loader.c");
const OBJECT: &str = "/run/memcordon-private-observer/private_kernel_v1.bpf.o";
const LOADER: &str = "/run/memcordon-private-observer/private_kernel_v1_loader";
const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedProbeBundleV1 {
    pub(crate) bpf_source_sha256: DiagnosticSha256,
    pub(crate) loader_source_sha256: DiagnosticSha256,
    pub(crate) object_sha256: DiagnosticSha256,
    pub(crate) loader_sha256: DiagnosticSha256,
    pub(crate) agent_sha256: DiagnosticSha256,
    pub(crate) agent_build_id: Vec<u8>,
    pub(crate) request_entry_offset: u64,
    pub(crate) request_exit_offset: u64,
    pub(crate) allocation_entry_offset: u64,
}

pub(crate) struct VerifiedProbeBundleV1 {
    object: File,
    loader: File,
    agent: File,
    expected: ExpectedProbeBundleV1,
}

impl VerifiedProbeBundleV1 {
    pub(crate) fn attestation_digest(&self) -> DiagnosticSha256 {
        let mut bytes = b"memcordon/private-kernel-probe-bundle/v1\0".to_vec();
        for digest in [
            &self.expected.bpf_source_sha256,
            &self.expected.loader_source_sha256,
            &self.expected.object_sha256,
            &self.expected.loader_sha256,
            &self.expected.agent_sha256,
        ] {
            bytes.extend_from_slice(digest.bytes());
        }
        bytes.extend_from_slice(&self.expected.agent_build_id);
        bytes.extend_from_slice(&self.expected.request_entry_offset.to_le_bytes());
        bytes.extend_from_slice(&self.expected.request_exit_offset.to_le_bytes());
        bytes.extend_from_slice(&self.expected.allocation_entry_offset.to_le_bytes());
        hash_bytes(&bytes)
    }
    pub(crate) fn object_path(&self) -> &'static Path {
        Path::new(OBJECT)
    }
    pub(crate) fn loader_path(&self) -> &'static Path {
        Path::new(LOADER)
    }
    pub(crate) fn agent_path(&self) -> &'static Path {
        Path::new(AGENT)
    }
    pub(crate) fn request_entry_offset(&self) -> u64 {
        self.expected.request_entry_offset
    }
    pub(crate) fn request_exit_offset(&self) -> u64 {
        self.expected.request_exit_offset
    }
    pub(crate) fn allocation_entry_offset(&self) -> u64 {
        self.expected.allocation_entry_offset
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        for (file, path, digest, limit) in [
            (
                &self.object,
                OBJECT,
                &self.expected.object_sha256,
                16 * 1024 * 1024,
            ),
            (
                &self.loader,
                LOADER,
                &self.expected.loader_sha256,
                16 * 1024 * 1024,
            ),
            (
                &self.agent,
                AGENT,
                &self.expected.agent_sha256,
                128 * 1024 * 1024,
            ),
        ] {
            let reopened = open_root_regular(Path::new(path), limit)?;
            let first = file
                .metadata()
                .map_err(|error| CiError::Message(error.to_string()))?;
            let second = reopened
                .metadata()
                .map_err(|error| CiError::Message(error.to_string()))?;
            if first.len() != second.len() || hash_bytes(&read_file(&reopened, limit)?) != *digest {
                return Err(CiError::Message(
                    "qualification probe bundle changed".into(),
                ));
            }
        }
        Ok(())
    }
}

fn open_root_regular(path: &Path, maximum: u64) -> Result<File> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|error| CiError::Message(format!("probe bundle {}: {error}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|error| CiError::Message(error.to_string()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(CiError::Message(
            "probe bundle file identity differs".into(),
        ));
    }
    #[cfg(unix)]
    if metadata.uid() != 0 || metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "probe bundle file protection differs".into(),
        ));
    }
    Ok(file)
}

fn read_file(file: &File, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CiError::Message(error.to_string()))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(CiError::Message("probe bundle file exceeds bound".into()));
    }
    Ok(bytes)
}

pub(crate) fn verify_probe_bundle(
    expected: ExpectedProbeBundleV1,
) -> Result<VerifiedProbeBundleV1> {
    if expected.bpf_source_sha256 != hash_bytes(BPF_SOURCE)
        || expected.loader_source_sha256 != hash_bytes(LOADER_SOURCE)
        || expected.request_entry_offset == 0
        || expected.request_exit_offset == 0
        || expected.allocation_entry_offset == 0
        || expected.request_entry_offset == expected.allocation_entry_offset
        || expected.request_entry_offset == expected.request_exit_offset
        || expected.request_exit_offset == expected.allocation_entry_offset
        || !matches!(expected.agent_build_id.len(), 20 | 32)
    {
        return Err(CiError::Message(
            "reviewed probe source or offsets differ".into(),
        ));
    }
    let object = open_root_regular(Path::new(OBJECT), 16 * 1024 * 1024)?;
    let loader = open_root_regular(Path::new(LOADER), 16 * 1024 * 1024)?;
    let agent = open_root_regular(Path::new(AGENT), 128 * 1024 * 1024)?;
    let object_bytes = read_file(&object, 16 * 1024 * 1024)?;
    let loader_bytes = read_file(&loader, 16 * 1024 * 1024)?;
    let agent_bytes = read_file(&agent, 128 * 1024 * 1024)?;
    if hash_bytes(&object_bytes) != expected.object_sha256
        || hash_bytes(&loader_bytes) != expected.loader_sha256
        || hash_bytes(&agent_bytes) != expected.agent_sha256
        || elf_build_id(&agent_bytes)? != expected.agent_build_id
    {
        return Err(CiError::Message(
            "probe binary or target build-id differs".into(),
        ));
    }
    Ok(VerifiedProbeBundleV1 {
        object,
        loader,
        agent,
        expected,
    })
}

fn elf_build_id(bytes: &[u8]) -> Result<Vec<u8>> {
    let fail = || CiError::Message("probe target ELF build-id invalid".into());
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err(fail());
    }
    let u16_at = |offset: usize| -> Result<u16> {
        Ok(u16::from_le_bytes(
            bytes
                .get(offset..offset + 2)
                .ok_or_else(fail)?
                .try_into()
                .map_err(|_| fail())?,
        ))
    };
    let u32_at = |offset: usize| -> Result<u32> {
        Ok(u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or_else(fail)?
                .try_into()
                .map_err(|_| fail())?,
        ))
    };
    let u64_at = |offset: usize| -> Result<u64> {
        Ok(u64::from_le_bytes(
            bytes
                .get(offset..offset + 8)
                .ok_or_else(fail)?
                .try_into()
                .map_err(|_| fail())?,
        ))
    };
    let table = usize::try_from(u64_at(32)?).map_err(|_| fail())?;
    let entry_size = usize::from(u16_at(54)?);
    let count = usize::from(u16_at(56)?);
    if entry_size < 56 || count == 0 || count > 128 {
        return Err(fail());
    }
    let mut found = None;
    for index in 0..count {
        let entry = table
            .checked_add(index.checked_mul(entry_size).ok_or_else(fail)?)
            .ok_or_else(fail)?;
        if u32_at(entry)? != 4 {
            continue;
        } // PT_NOTE
        let start = usize::try_from(u64_at(entry + 8)?).map_err(|_| fail())?;
        let size = usize::try_from(u64_at(entry + 32)?).map_err(|_| fail())?;
        let end = start.checked_add(size).ok_or_else(fail)?;
        if end > bytes.len() {
            return Err(fail());
        }
        let mut offset = start;
        while offset + 12 <= end {
            let name_size = usize::try_from(u32_at(offset)?).map_err(|_| fail())?;
            let desc_size = usize::try_from(u32_at(offset + 4)?).map_err(|_| fail())?;
            let kind = u32_at(offset + 8)?;
            let name_start = offset + 12;
            let desc_start = name_start
                .checked_add((name_size + 3) & !3)
                .ok_or_else(fail)?;
            let next = desc_start
                .checked_add((desc_size + 3) & !3)
                .ok_or_else(fail)?;
            if next > end {
                return Err(fail());
            }
            if kind == 3
                && bytes.get(name_start..name_start + name_size) == Some(b"GNU\0".as_slice())
            {
                if found.is_some() || !matches!(desc_size, 20 | 32) {
                    return Err(fail());
                }
                found = Some(bytes[desc_start..desc_start + desc_size].to_vec());
            }
            offset = next;
        }
    }
    found.ok_or_else(fail)
}
