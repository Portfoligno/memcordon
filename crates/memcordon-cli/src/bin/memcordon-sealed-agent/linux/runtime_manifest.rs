use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifestV2,
};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub const INSTALLED: &str = "/usr/libexec/memcordon-runtime-manifest.json";

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

fn manifest_bytes(path: &Path, protected: bool) -> Result<Vec<u8>, String> {
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
    let manifest = installed_generation(&bytes)?;
    let agent = manifest
        .components
        .iter()
        .find(|entry| entry.role == RuntimeComponentRole::SealedAgent)
        .expect("installed generation validates the agent role");
    let installed_digest =
        crate::package::sha256_regular_no_follow(Path::new("/usr/libexec/memcordon-sealed-agent"))?;
    crate::package::verify_installed_executable_digest(&agent.sha256, &installed_digest)?;
    manifest.public_binding(&bytes)
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
