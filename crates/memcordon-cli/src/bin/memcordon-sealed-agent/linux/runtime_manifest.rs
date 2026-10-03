use std::path::Path;

use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifest,
};

pub const INSTALLED: &str = "/usr/libexec/memcordon-runtime-manifest.json";
pub const INSTALLED_ARM32_HELPER: &str = "/usr/libexec/memcordon-arm32-abi-helper";
const IMAGE_MAX_BYTES: u64 = 128 * 1024 * 1024;

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
    if protected {
        super::protected_read::read_protected_absolute(
            path,
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            None,
        )
    } else {
        read_source_file(
            path,
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            None,
        )
    }
}

fn read_source_file(path: &Path, maximum: u64, mode: Option<u32>) -> Result<Vec<u8>, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > maximum
        || mode.is_some_and(|expected| metadata.mode() & 0o7777 != expected)
    {
        return Err("runtime source member is not a bounded single-link regular file".into());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len()
        || bytes.len() as u64 > maximum
        || (
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mode(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("runtime source member changed during readback".into());
    }
    Ok(bytes)
}

fn verify_image(
    manifest: &RuntimeManifest,
    role: RuntimeComponentRole,
    bytes: &[u8],
) -> Result<(), String> {
    let component = manifest
        .components
        .iter()
        .find(|entry| entry.role == role)
        .ok_or("runtime manifest omits required image")?;
    if component.size != bytes.len() as u64 || component.sha256 != digest(bytes) {
        return Err("runtime manifest differs from exact image bytes".into());
    }
    Ok(())
}

pub fn source(source: &Path, agent_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let installed = source == Path::new("/usr/libexec/memcordon-sealed-agent");
    if installed {
        let actual =
            super::protected_read::read_protected_absolute(source, IMAGE_MAX_BYTES, Some(0o755))?;
        if actual != agent_bytes {
            return Err("installed source image differs from snapshotted executable".into());
        }
        let bytes = manifest_bytes(Path::new(INSTALLED), true)?;
        let manifest = RuntimeManifest::parse(&bytes)?;
        if manifest.target != target()?
            || manifest.version != env!("CARGO_PKG_VERSION")
            || manifest.source_commit != crate::SOURCE_COMMIT
        {
            return Err("installed runtime generation differs from provider".into());
        }
        verify_image(&manifest, RuntimeComponentRole::SealedAgent, agent_bytes)?;
        let public = super::protected_read::read_protected_absolute(
            Path::new("/usr/bin/memcordon"),
            IMAGE_MAX_BYTES,
            Some(0o755),
        )?;
        verify_image(&manifest, RuntimeComponentRole::PublicCli, &public)?;
        if manifest
            .components
            .iter()
            .any(|component| component.role == RuntimeComponentRole::Arm32AbiHelper)
        {
            let helper = super::protected_read::read_protected_absolute(
                Path::new(INSTALLED_ARM32_HELPER),
                IMAGE_MAX_BYTES,
                Some(0o755),
            )?;
            verify_image(&manifest, RuntimeComponentRole::Arm32AbiHelper, &helper)?;
        }
        return Ok(bytes);
    }
    let directory = source.parent().ok_or("provider source has no parent")?;
    let public = read_source_file(&directory.join("memcordon"), IMAGE_MAX_BYTES, Some(0o755))?;
    let mut components = vec![
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
    let helper_path = directory.join("memcordon-arm32-abi-helper");
    match std::fs::symlink_metadata(&helper_path) {
        Ok(_) => {
            let helper = read_source_file(&helper_path, 1024 * 1024, Some(0o755))?;
            components.push(RuntimeComponentRecord {
                id: "arm32-abi-helper".into(),
                path: "memcordon-arm32-abi-helper".into(),
                role: RuntimeComponentRole::Arm32AbiHelper,
                size: helper.len() as u64,
                mode: 0o755,
                sha256: digest(&helper),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let expected = RuntimeManifest::linux_selected(
        env!("CARGO_PKG_VERSION").into(),
        crate::SOURCE_COMMIT.into(),
        target()?.into(),
        components,
        cfg!(feature = "private-tcp"),
    )?;
    let path = directory.join("runtime-manifest.json");
    match manifest_bytes(&path, false) {
        Ok(bytes) => {
            if RuntimeManifest::parse(&bytes)? != expected {
                return Err("source runtime manifest differs from exact copied images".into());
            }
            Ok(bytes)
        }
        Err(error) => match std::fs::symlink_metadata(&path) {
            Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {
                let mut bytes = serde_json::to_vec(&expected).map_err(|error| error.to_string())?;
                bytes.push(b'\n');
                Ok(bytes)
            }
            _ => Err(error),
        },
    }
}

pub fn installed_binding() -> Result<memcordon_core::PublicProviderBindingV1, String> {
    crate::package::verify()?;
    let agent = super::protected_read::read_protected_absolute(
        Path::new("/usr/libexec/memcordon-sealed-agent"),
        IMAGE_MAX_BYTES,
        Some(0o755),
    )?;
    let bytes = source(Path::new("/usr/libexec/memcordon-sealed-agent"), &agent)?;
    RuntimeManifest::parse(&bytes)?.public_binding(&bytes)
}
