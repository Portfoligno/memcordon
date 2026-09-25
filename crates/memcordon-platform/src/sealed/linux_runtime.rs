use memcordon_core::{
    PublicProviderBindingV1,
    runtime_manifest::{RuntimeComponentRole, RuntimeManifestV2},
    runtime_manifest_v3::{RuntimeManifestV3, RuntimeProfileAvailabilityV3, SealedRuntimeV3},
    workload_evidence_v2::QualifiedNativeAbiV2,
    workload_plan_v2::PrivatePlanReceiptV2,
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
    let file = protected(Path::new("/usr/libexec/memcordon-sealed-agent"))?;
    if file.metadata().map_err(|error| error.to_string())?.len() != agent.size {
        return Err("installed provider size differs".into());
    }
    let actual: String = protected_digest(file)?.into();
    if actual != agent.sha256 {
        return Err("installed provider hash differs".into());
    }
    Ok(())
}

/// Independently pin the installed V3 manifest and agent bytes named by an
/// authenticated private plan. This does not replace current host receipt or
/// policy readback, which the provider must repeat at private launch.
pub fn verify_private(expected: &PrivatePlanReceiptV2) -> Result<(), String> {
    let file = protected(Path::new("/usr/libexec/memcordon-runtime-manifest.json"))?;
    let mut bytes = Vec::new();
    file.take(memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let manifest = RuntimeManifestV3::parse(&bytes)?;
    let manifest_digest = memcordon_core::workload_codec::hash_bytes(&bytes);
    let target = match expected.native_abi {
        QualifiedNativeAbiV2::X86_64LinuxGnu => "x86_64-unknown-linux-gnu",
        QualifiedNativeAbiV2::Aarch64LinuxGnu => "aarch64-unknown-linux-gnu",
    };
    if manifest_digest != expected.runtime_manifest_sha256
        || manifest.source_commit != expected.source_commit
        || manifest.version != env!("CARGO_PKG_VERSION")
        || manifest.target != target
        || (std::env::consts::ARCH, target)
            != (
                target
                    .split('-')
                    .next()
                    .expect("fixed target has architecture"),
                target,
            )
    {
        return Err("private plan differs from installed runtime identity".into());
    }
    let SealedRuntimeV3::WorkloadV2 {
        agent_component,
        profiles,
        ..
    } = &manifest.sealed
    else {
        return Err("installed runtime has no Linux V2 sealed provider".into());
    };
    if !matches!(
        profiles
            .as_slice()
            .first()
            .map(|profile| &profile.availability),
        Some(RuntimeProfileAvailabilityV3::Qualified { .. })
    ) {
        return Err("installed runtime has no qualified private profile".into());
    }
    let agent = manifest
        .components
        .iter()
        .find(|component| {
            component.id == *agent_component && component.role == RuntimeComponentRole::SealedAgent
        })
        .ok_or("installed runtime agent component missing")?;
    let file = protected(Path::new("/usr/libexec/memcordon-sealed-agent"))?;
    if file.metadata().map_err(|error| error.to_string())?.len() != agent.size
        || String::from(protected_digest(file)?) != agent.sha256
    {
        return Err("installed private provider bytes differ from runtime manifest".into());
    }
    Ok(())
}
