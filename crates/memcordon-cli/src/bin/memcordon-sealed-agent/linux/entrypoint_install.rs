//! Root-only local image installation. This does not activate a policy or grant.
use std::fs::{File, OpenOptions};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use memcordon_core::workload_registry_v2::ApprovedEntrypointV2;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalImageInstallation {
    format: String,
    revision: u32,
    entrypoint: ApprovedEntrypointV2,
}

pub(crate) fn install(definition: &Path, source: &Path) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getuid() } != 0 {
        return Err("MCSEALED-ENTRYPOINT-INSTALL: real and effective root required".into());
    }
    let bytes = super::protected_read::read_protected_absolute(definition, 8192, None)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let selected: LocalImageInstallation =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if selected.format != "memcordon.local-entrypoint-install" || selected.revision != 1 {
        return Err("MCSEALED-ENTRYPOINT-INSTALL: invalid local image installation format".into());
    }
    if !source.is_absolute() {
        return Err("MCSEALED-ENTRYPOINT-INSTALL: absolute source path required".into());
    }
    let installation_root: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| error.to_string())?;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(source)
        .map_err(|error| error.to_string())?;
    let metadata = source.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() != selected.entrypoint.size.get() {
        return Err("MCSEALED-ENTRYPOINT-INSTALL: regular source of selected size required".into());
    }
    let observed = super::entrypoint::install_protected_entrypoint(
        installation_root.as_fd(),
        &selected.entrypoint,
        &mut source,
    )?;
    println!(
        "{}",
        serde_json::json!({
            "format": "memcordon.local-entrypoint-observation", "revision": 1,
            "entrypoint": selected.entrypoint,
            "device": observed.device, "inode": observed.inode, "size": observed.size,
            "sha256": memcordon_core::DiagnosticSha256::from_bytes(observed.sha256),
            "policy_activated": false,
        })
    );
    Ok(())
}
