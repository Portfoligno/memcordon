use memcordon_core::{
    PublicProviderBindingV1,
    runtime_manifest::{RuntimeComponentRole, RuntimeManifestV2},
};
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

pub fn verify(expected: &PublicProviderBindingV1) -> Result<(), String> {
    let file = protected(Path::new("/usr/libexec/memcordon-runtime-manifest.json"))?;
    let mut bytes = Vec::new();
    file.take(memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let manifest = RuntimeManifestV2::parse(&bytes)?;
    if manifest.public_binding(&bytes)? != *expected
        || manifest.version != env!("CARGO_PKG_VERSION")
    {
        return Err("authenticated provider runtime binding differs".into());
    }
    let target = match (std::env::consts::ARCH, cfg!(target_env = "musl")) {
        ("x86_64", false) => "x86_64-unknown-linux-gnu",
        ("aarch64", false) => "aarch64-unknown-linux-gnu",
        ("x86_64", true) => "x86_64-unknown-linux-musl",
        ("aarch64", true) => "aarch64-unknown-linux-musl",
        _ => return Err("unsupported provider runtime target".into()),
    };
    if manifest
        != RuntimeManifestV2::linux(
            manifest.version.clone(),
            manifest.source_commit.clone(),
            target.into(),
            manifest.components.clone(),
        )
        || manifest.components.len() != 2
    {
        return Err("provider runtime support differs".into());
    }
    let agent = manifest
        .components
        .iter()
        .find(|value| value.role == RuntimeComponentRole::SealedAgent)
        .ok_or("provider runtime agent absent")?;
    let public = manifest
        .components
        .iter()
        .find(|value| value.role == RuntimeComponentRole::PublicCli)
        .ok_or("provider runtime CLI absent")?;
    if agent.id != "sealed-agent"
        || agent.path != "memcordon-sealed-agent"
        || agent.mode != 0o755
        || public.id != "public-cli"
        || public.path != "memcordon"
        || public.mode != 0o755
    {
        return Err("provider runtime roles differ".into());
    }
    let mut file = protected(Path::new("/usr/libexec/memcordon-sealed-agent"))?;
    if file.metadata().map_err(|error| error.to_string())?.len() != agent.size {
        return Err("installed provider size differs".into());
    }
    let mut digest = Sha256::new();
    let mut chunk = [0; 64 * 1024];
    loop {
        let count = file.read(&mut chunk).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    let actual: String =
        memcordon_core::DiagnosticSha256::from_bytes(digest.finalize().into()).into();
    if actual != agent.sha256 {
        return Err("installed provider hash differs".into());
    }
    Ok(())
}
