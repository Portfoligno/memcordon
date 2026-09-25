use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifestV2,
};
use memcordon_core::runtime_manifest_v3::{RuntimeManifestV3, VersionedRuntimeManifest};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub const INSTALLED: &str = "/usr/libexec/memcordon-runtime-manifest.json";
const V3_IMAGE_MAX_BYTES: u64 = 128 * 1024 * 1024;

/// Read an exact installed M0/M1 candidate without inferring that Q came from
/// an independently verified native run or that this host is qualified. The
/// installed caller must hold the shared package-generation lease throughout.
pub(crate) fn source_v3_candidate(
    source: &Path,
) -> Result<Option<super::installed_release_qualification::CandidateV3Readback>, String> {
    let installed = source == Path::new("/usr/libexec/memcordon-sealed-agent");
    let path = if installed {
        Path::new(INSTALLED).to_path_buf()
    } else {
        source
            .parent()
            .ok_or("provider source has no parent")?
            .join("runtime-manifest.json")
    };
    let bytes = if installed {
        super::installed_release_qualification::read_protected_absolute(
            &path,
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            None,
        )?
    } else {
        match manifest_bytes(&path, false) {
            Ok(bytes) => bytes,
            Err(error) => match std::fs::symlink_metadata(&path) {
                Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                _ => return Err(error),
            },
        }
    };
    match VersionedRuntimeManifest::parse(&bytes)? {
        VersionedRuntimeManifest::V2(_) => Ok(None),
        VersionedRuntimeManifest::V3(_) => {
            let public_path = if installed {
                Path::new("/usr/bin/memcordon").to_path_buf()
            } else {
                source
                    .parent()
                    .expect("V3 source already has a parent")
                    .join("memcordon")
            };
            let (agent_bytes, public_bytes) = if installed {
                (
                    super::installed_release_qualification::read_protected_absolute(
                        source,
                        V3_IMAGE_MAX_BYTES,
                        Some(0o755),
                    )?,
                    super::installed_release_qualification::read_protected_absolute(
                        &public_path,
                        V3_IMAGE_MAX_BYTES,
                        Some(0o755),
                    )?,
                )
            } else {
                (
                    read_v3_image(source, false)?,
                    read_v3_image(&public_path, false)?,
                )
            };
            super::installed_release_qualification::read_candidate(
                bytes,
                &agent_bytes,
                &public_bytes,
                installed,
            )
            .map(Some)
        }
    }
}

pub(crate) fn target() -> Result<&'static str, String> {
    match (std::env::consts::ARCH, cfg!(target_env = "musl")) {
        ("x86_64", false) => Ok("x86_64-unknown-linux-gnu"),
        ("aarch64", false) => Ok("aarch64-unknown-linux-gnu"),
        ("x86_64", true) => Ok("x86_64-unknown-linux-musl"),
        ("aarch64", true) => Ok("aarch64-unknown-linux-musl"),
        _ => Err("unsupported Linux runtime target".into()),
    }
}

fn digest(bytes: &[u8]) -> String {
    memcordon_core::workload_codec::hash_bytes(bytes).into()
}

pub(crate) fn manifest_bytes(path: &Path, protected: bool) -> Result<Vec<u8>, String> {
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || (protected && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0))
    {
        return Err("runtime manifest is not a protected regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
        return Err("runtime manifest exceeds limit".into());
    }
    Ok(bytes)
}

/// Reads an explicitly supplied V3 generation and independently verifies both
/// executable images. Absence preserves the historical V2 package path.
pub fn source_v3(source: &Path) -> Result<Option<(RuntimeManifestV3, Vec<u8>)>, String> {
    let installed = source == Path::new("/usr/libexec/memcordon-sealed-agent");
    let path = if installed {
        Path::new(INSTALLED).to_path_buf()
    } else {
        source
            .parent()
            .ok_or("provider source has no parent")?
            .join("runtime-manifest.json")
    };
    let bytes = match manifest_bytes(&path, installed) {
        Ok(bytes) => bytes,
        Err(error) => match std::fs::symlink_metadata(&path) {
            Err(missing) if missing.kind() == std::io::ErrorKind::NotFound && !installed => {
                return Ok(None);
            }
            _ => return Err(error),
        },
    };
    match VersionedRuntimeManifest::parse(&bytes)? {
        VersionedRuntimeManifest::V2(_) => Ok(None),
        VersionedRuntimeManifest::V3(_) => {
            let public_path = if installed {
                Path::new("/usr/bin/memcordon").to_path_buf()
            } else {
                source
                    .parent()
                    .expect("V3 source already has a parent")
                    .join("memcordon")
            };
            let agent_bytes = read_v3_image(source, installed)?;
            let public_bytes = read_v3_image(&public_path, installed)?;
            let manifest = validate_v3_source(&bytes, &agent_bytes, &public_bytes)?;
            Ok(Some((manifest, bytes)))
        }
    }
}

fn read_v3_image(path: &Path, protected: bool) -> Result<Vec<u8>, String> {
    let mut file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o755
        || (protected && metadata.uid() != 0)
        || metadata.len() > V3_IMAGE_MAX_BYTES
    {
        return Err("V3 executable image is not an exact protected regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(V3_IMAGE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len()
        || (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) != (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    {
        return Err("V3 executable image changed during readback".into());
    }
    Ok(bytes)
}

pub(crate) fn validate_v3_source(
    bytes: &[u8],
    agent_bytes: &[u8],
    public_bytes: &[u8],
) -> Result<RuntimeManifestV3, String> {
    let manifest = RuntimeManifestV3::parse(bytes)?;
    let expected = RuntimeManifestV3::linux_unqualified(
        env!("CARGO_PKG_VERSION").into(),
        crate::SOURCE_COMMIT.into(),
        target()?.into(),
        vec![
            RuntimeComponentRecord {
                id: "public-cli".into(),
                path: "memcordon".into(),
                role: RuntimeComponentRole::PublicCli,
                size: public_bytes.len() as u64,
                mode: 0o755,
                sha256: digest(public_bytes),
            },
            RuntimeComponentRecord {
                id: "sealed-agent".into(),
                path: "memcordon-sealed-agent".into(),
                role: RuntimeComponentRole::SealedAgent,
                size: agent_bytes.len() as u64,
                mode: 0o755,
                sha256: digest(agent_bytes),
            },
        ],
    )?;
    if manifest != expected {
        return Err("V3 runtime generation differs from exact executable images".into());
    }
    Ok(manifest)
}

pub fn source(source: &Path, agent_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if source == Path::new("/usr/libexec/memcordon-sealed-agent") {
        let mut image = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source)
            .map_err(|error| format!("installed source image unavailable: {error}"))?;
        let metadata = image.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != 0
            || metadata.len() != agent_bytes.len() as u64
            || metadata.mode() & 0o7777 != 0o755
        {
            return Err("installed source image is not protected".into());
        }
        let mut buffer = [0_u8; 64 * 1024];
        for expected in agent_bytes.chunks(buffer.len()) {
            let actual = &mut buffer[..expected.len()];
            image
                .read_exact(actual)
                .map_err(|error| format!("installed source image changed: {error}"))?;
            if actual != expected {
                return Err(
                    "installed source image differs from the snapshotted executable".into(),
                );
            }
        }
        if image
            .read(&mut buffer[..1])
            .map_err(|error| error.to_string())?
            != 0
        {
            return Err("installed source image grew after snapshot".into());
        }
        let bytes = manifest_bytes(Path::new(INSTALLED), true)?;
        validate_installed_source(&bytes, agent_bytes)?;
        return Ok(bytes);
    }
    let directory = source.parent().ok_or("provider source has no parent")?;
    let public = std::fs::read(directory.join("memcordon")).map_err(|error| error.to_string())?;
    let components = vec![
        RuntimeComponentRecord {
            id: "public-cli".into(),
            path: "memcordon".into(),
            role: RuntimeComponentRole::PublicCli,
            size: public.len() as u64,
            mode: 0o755,
            sha256: digest(&public),
        },
        RuntimeComponentRecord {
            id: "sealed-agent".into(),
            path: "memcordon-sealed-agent".into(),
            role: RuntimeComponentRole::SealedAgent,
            size: agent_bytes.len() as u64,
            mode: 0o755,
            sha256: digest(agent_bytes),
        },
    ];
    let expected = RuntimeManifestV2::linux(
        env!("CARGO_PKG_VERSION").into(),
        crate::SOURCE_COMMIT.into(),
        target()?.into(),
        components,
    );
    let path = directory.join("runtime-manifest.json");
    match manifest_bytes(&path, false) {
        Ok(bytes) => {
            if RuntimeManifestV2::parse(&bytes)? != expected {
                return Err(
                    "source runtime manifest differs from exact copied provider generation".into(),
                );
            }
            Ok(bytes)
        }
        Err(error) if !path.try_exists().map_err(|error| error.to_string())? => {
            let _ = error;
            let mut bytes = serde_json::to_vec(&expected).map_err(|error| error.to_string())?;
            bytes.push(b'\n');
            Ok(bytes)
        }
        Err(error) => Err(error),
    }
}

pub fn installed_binding() -> Result<memcordon_core::PublicProviderBindingV1, String> {
    crate::package::verify()?;
    let bytes = manifest_bytes(Path::new(INSTALLED), true)?;
    match VersionedRuntimeManifest::parse(&bytes)? {
        VersionedRuntimeManifest::V2(_) => {
            let manifest = installed_generation(&bytes)?;
            let agent = manifest
                .components
                .iter()
                .find(|entry| entry.role == RuntimeComponentRole::SealedAgent)
                .expect("installed generation validates the agent role");
            let installed_digest = crate::package::sha256_regular_no_follow(Path::new(
                "/usr/libexec/memcordon-sealed-agent",
            ))?;
            crate::package::verify_installed_executable_digest(&agent.sha256, &installed_digest)?;
            manifest.public_binding(&bytes)
        }
        VersionedRuntimeManifest::V3(_) => {
            let candidate = source_v3_candidate(Path::new("/usr/libexec/memcordon-sealed-agent"))?
                .ok_or("installed V3 candidate absent")?;
            if candidate.manifest_bytes != bytes {
                return Err("installed V3 generation changed during public binding".into());
            }
            candidate_public_binding(&candidate)
        }
    }
}

/// Candidate M1 may identify the public baseline generation, but this does
/// not qualify its private profile or construct a native host lease.
pub(crate) fn candidate_public_binding(
    candidate: &super::installed_release_qualification::CandidateV3Readback,
) -> Result<memcordon_core::PublicProviderBindingV1, String> {
    candidate.manifest.public_binding(&candidate.manifest_bytes)
}

/// The V3 public generation binding is candidate-only; it grants no private
/// admission and supplies no independent release or host qualification.
pub fn installed_binding_v3() -> Result<memcordon_core::PublicProviderBindingV1, String> {
    crate::package::verify()?;
    let candidate = source_v3_candidate(Path::new("/usr/libexec/memcordon-sealed-agent"))?
        .ok_or("installed runtime generation is not V3")?;
    candidate_public_binding(&candidate)
}

fn validate_installed_source(bytes: &[u8], agent_bytes: &[u8]) -> Result<(), String> {
    let manifest = installed_generation(bytes)?;
    let agent = manifest
        .components
        .iter()
        .find(|entry| entry.role == RuntimeComponentRole::SealedAgent)
        .expect("installed generation validates the agent role");
    if agent.size != agent_bytes.len() as u64 || agent.sha256 != digest(agent_bytes) {
        return Err("installed runtime manifest differs from exact source image".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_installed_source_for_test(
    bytes: &[u8],
    agent_bytes: &[u8],
) -> Result<(), String> {
    validate_installed_source(bytes, agent_bytes)
}

fn installed_generation(bytes: &[u8]) -> Result<RuntimeManifestV2, String> {
    let manifest = RuntimeManifestV2::parse(bytes)?;
    let expected = RuntimeManifestV2::linux(
        env!("CARGO_PKG_VERSION").into(),
        crate::SOURCE_COMMIT.into(),
        target()?.into(),
        manifest.components.clone(),
    );
    if manifest != expected || manifest.components.len() != 2 {
        return Err("installed runtime generation differs".into());
    }
    let agent = manifest
        .components
        .iter()
        .find(|entry| entry.role == RuntimeComponentRole::SealedAgent)
        .ok_or("runtime agent absent")?;
    if agent.id != "sealed-agent" || agent.path != "memcordon-sealed-agent" || agent.mode != 0o755 {
        return Err("runtime agent role differs".into());
    }
    let public = manifest
        .components
        .iter()
        .find(|entry| entry.role == RuntimeComponentRole::PublicCli)
        .ok_or("runtime CLI absent")?;
    if public.id != "public-cli" || public.path != "memcordon" || public.mode != 0o755 {
        return Err("runtime CLI role differs".into());
    }
    Ok(manifest)
}
