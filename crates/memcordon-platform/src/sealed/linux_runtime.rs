use memcordon_core::{PublicProviderBindingV1, runtime_components::RuntimeComponentRole};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

fn protected(path: &Path) -> Result<File, String> {
    for ancestor in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("provider runtime ancestor is not protected".into());
        }
    }
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err("provider runtime component is not protected".into());
    }
    Ok(file)
}

fn protected_digest(mut file: File) -> Result<memcordon_core::DiagnosticSha256, String> {
    let mut digest = Sha256::new();
    let mut chunk = [0; 64 * 1024];
    loop {
        let count = file.read(&mut chunk).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    Ok(memcordon_core::DiagnosticSha256::from_bytes(
        digest.finalize().into(),
    ))
}

pub fn verify(expected: &PublicProviderBindingV1) -> Result<(), String> {
    if installed_binding()? != *expected {
        return Err("authenticated provider runtime binding differs".into());
    }
    Ok(())
}

pub(super) fn installed_binding() -> Result<PublicProviderBindingV1, String> {
    let file = protected(Path::new("/usr/libexec/memcordon-runtime-manifest.json"))?;
    let mut bytes = Vec::new();
    file.take(memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    current_binding(&bytes, false)
}

pub(super) fn installed_current_binding() -> Result<PublicProviderBindingV1, String> {
    let file = protected(Path::new("/usr/libexec/memcordon-runtime-manifest.json"))?;
    let mut bytes = Vec::new();
    file.take(memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    current_binding(&bytes, true)
}

fn current_binding(bytes: &[u8], require_private: bool) -> Result<PublicProviderBindingV1, String> {
    use memcordon_core::runtime_manifest_v2::{RuntimeManifestV2, SealedRuntimeV2};
    let manifest = RuntimeManifestV2::parse(bytes)?;
    let target = match (std::env::consts::ARCH, cfg!(target_env = "musl")) {
        ("x86_64", false) => "x86_64-unknown-linux-gnu",
        ("aarch64", false) => "aarch64-unknown-linux-gnu",
        ("x86_64", true) => "x86_64-unknown-linux-musl",
        ("aarch64", true) => "aarch64-unknown-linux-musl",
        _ => return Err("unsupported current Linux provider target".into()),
    };
    if manifest.version != env!("CARGO_PKG_VERSION") || manifest.target != target {
        return Err("current installed Linux provider version or target differs".into());
    }
    if require_private
        && !matches!(&manifest.sealed, SealedRuntimeV2::Included { profile, .. } if profile == "linux-private-workload-v1")
    {
        return Err("current Linux private workload component is not installed".into());
    }
    let agent = manifest
        .components
        .iter()
        .find(|component| component.role == RuntimeComponentRole::SealedAgent)
        .ok_or("current Linux agent missing")?;
    let public = manifest
        .components
        .iter()
        .find(|component| component.role == RuntimeComponentRole::PublicCli)
        .ok_or("current Linux public frontend missing")?;
    if agent.id != "sealed-agent"
        || agent.path != "memcordon-sealed-agent"
        || agent.mode != 0o755
        || public.id != "public-cli"
        || public.path != "memcordon"
        || public.mode != 0o755
    {
        return Err("current Linux installed component roles differ".into());
    }
    for component in &manifest.components {
        if !matches!(
            component.role,
            RuntimeComponentRole::PublicCli
                | RuntimeComponentRole::SealedAgent
                | RuntimeComponentRole::Arm32AbiHelper
        ) {
            return Err("current Linux component role unsupported".into());
        }
        let file = protected(&Path::new("/usr/libexec").join(&component.path))?;
        let before = file.metadata().map_err(|error| error.to_string())?;
        if before.len() != component.size || before.mode() & 0o7777 != component.mode {
            return Err("current Linux component size or mode differs".into());
        }
        let actual: String =
            protected_digest(file.try_clone().map_err(|error| error.to_string())?)?.into();
        let after = file.metadata().map_err(|error| error.to_string())?;
        if actual != component.sha256
            || (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            )
        {
            return Err("current Linux component bytes or held native identity differ".into());
        }
    }
    manifest.public_binding(bytes)
}
