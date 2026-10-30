//! Explicit current installed lifetime; package and ordinary caller mutations
//! are journaled before they happen and finalized under the reserved cutoff.
use super::linux_current_installed::{CallerImages, CurrentLinuxInput, run_recipe};
use super::linux_request_fixture::CallerSession;
use super::{
    artifacts,
    installed_consumer::{MaterializedPayload, binary_path},
    source,
};
use crate::{
    CiError, Result,
    command::{CommandSpec, require_successful_output},
    readiness_identity::SourceIdentity,
};
use memcordon_readiness_verifier::current::{
    CaseEvidenceV2, InstalledLifecycleReceiptV2, NativeResourceObservationV2, NativeResourceV2,
};
use memcordon_readiness_verifier::{
    Artifact, CaseRecord, CaseState, InstalledLifecycleEvent, InstalledLifecycleJournal, ProductKey,
};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn relative(root: &Path, path: &Path) -> Result<String> {
    path.strip_prefix(root)
        .map_err(|_| CiError::Message("current artifact escaped original cell root".into()))?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| CiError::Message("current artifact path is not UTF8".into()))
}
fn persist(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    inventory: &mut Vec<Artifact>,
) -> Result<String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let path = relative(root, path)?;
    inventory.push(Artifact {
        path: path.clone(),
        length: bytes.len() as u64,
        sha256: artifacts::checksum(bytes),
    });
    Ok(path)
}

pub(super) fn retain_case_failure(
    caller_directory: &Path,
    controller_directory: &Path,
    artifact_root: &Path,
    caller_uid: u32,
    primary: &str,
    inventory: &mut Vec<Artifact>,
) -> Result<()> {
    let mut captures = Vec::new();
    for (origin, directory, names, uid) in [
        (
            "caller",
            caller_directory,
            &[
                "stdout.bin",
                "stderr.bin",
                "workload-request.json",
                "workload-result.json",
                "workload-observation.json",
                "launch-intent.json",
                "cleanup-settlement.json",
            ][..],
            caller_uid,
        ),
        (
            "controller",
            controller_directory,
            &["frontend-creation-intent.json", "original-frontend.json"][..],
            0,
        ),
    ] {
        for name in names {
            let path = directory.join(name);
            let mut file = match fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    captures.push(serde_json::json!({"origin":origin,"name":name,"absent":true}));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let before = file.metadata()?;
            if !before.is_file()
                || before.nlink() != 1
                || before.uid() != uid
                || before.len() > 16 * 1024 * 1024
            {
                return Err(CiError::Message(
                    "original failure capture custody/size differs".into(),
                ));
            }
            let mut bytes = Vec::new();
            (&mut file).take(before.len() + 1).read_to_end(&mut bytes)?;
            let after = file.metadata()?;
            if bytes.len() as u64 != before.len()
                || (
                    before.len(),
                    before.mtime(),
                    before.mtime_nsec(),
                    before.ctime(),
                    before.ctime_nsec(),
                ) != (
                    after.len(),
                    after.mtime(),
                    after.mtime_nsec(),
                    after.ctime(),
                    after.ctime_nsec(),
                )
            {
                return Err(CiError::Message(
                    "original failure capture changed during retention".into(),
                ));
            }
            let retained = persist(
                artifact_root,
                &controller_directory.join(format!("failure-{origin}-{name}")),
                &bytes,
                inventory,
            )?;
            captures.push(serde_json::json!({"origin":origin,"name":name,"artifact":retained}));
        }
    }
    persist(
        artifact_root,
        &controller_directory.join("failure-captures.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.current-case-failure","revision":1,"primary":primary,"captures":captures}),
        )?,
        inventory,
    )?;
    Ok(())
}
pub(super) fn observe_paths() -> Result<serde_json::Value> {
    let mut paths = Vec::new();
    for path in [
        "/sys/fs/cgroup/memcordon-sealed",
        "/run/memcordon",
        "/var/lib/memcordon/workload-attempts",
        "/var/lib/memcordon/workload-inputs",
        "/var/lib/memcordon/workload-resources",
    ] {
        let observed = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                serde_json::json!({"path":path,"absent":true})
            }
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
                    return Err(CiError::Message(
                        "native finalization root custody differs".into(),
                    ));
                }
                let held = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)?;
                let before = held.metadata()?;
                let children = fs::read_dir(path)?
                    .map(|entry| {
                        entry.map(|entry| entry.file_name().to_string_lossy().into_owned())
                    })
                    .collect::<std::io::Result<Vec<_>>>()?;
                let after = fs::symlink_metadata(path)?;
                if (before.dev(), before.ino()) != (after.dev(), after.ino())
                    || !children.is_empty()
                {
                    return Err(CiError::Message(
                        "native allocations remain after package finalization".into(),
                    ));
                }
                serde_json::json!({"path":path,"absent":false,"kind":"directory","device":before.dev(),"inode":before.ino(),"children":children})
            }
        };
        paths.push(observed);
    }
    Ok(serde_json::Value::Array(paths))
}
fn absent_package_images(names: &[String]) -> Result<serde_json::Value> {
    if names.is_empty() || names.len() > 16 {
        return Err(CiError::Message(
            "original installed binary inventory exceeds bound".into(),
        ));
    }
    let mut observations = Vec::new();
    let mut unique = std::collections::BTreeSet::new();
    let mut names = names.to_vec();
    names.push("memcordon-runtime-manifest.json".into());
    for name in &names {
        if Path::new(name).components().count() != 1
            || name.starts_with('.')
            || !name.starts_with("memcordon")
            || !unique.insert(name)
        {
            return Err(CiError::Message(
                "original installed binary role invalid".into(),
            ));
        }
        let path = Path::new("/usr/libexec").join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                observations.push(serde_json::json!({"path":path,"absent":true}))
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(CiError::Message(
                    "native package image remains after finalization".into(),
                ));
            }
        }
    }
    Ok(serde_json::to_value(observations)?)
}
pub(super) fn units(workspace: &Path, cutoff: Instant) -> Result<serde_json::Value> {
    let mut units = Vec::new();
    for unit in [
        "memcordon-sealed-agent.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-launcher.socket",
        "memcordon-sealed-network-launcher.service",
        "memcordon-sealed-network-launcher.socket",
    ] {
        let output = CommandSpec::new("/usr/bin/systemctl", workspace, Duration::from_secs(30))
            .bounded_until(cutoff)
            .args([
                "show",
                "--property=LoadState",
                "--property=ActiveState",
                unit,
            ])
            .output_quiet()?;
        let text =
            std::str::from_utf8(&output.stdout).map_err(|e| CiError::Message(e.to_string()))?;
        let value = |field: &str| -> Result<String> {
            let values = text
                .lines()
                .filter_map(|line| line.strip_prefix(field))
                .collect::<Vec<_>>();
            if values.len() != 1 {
                return Err(CiError::Message(
                    "native unit readback omitted/duplicated a field".into(),
                ));
            }
            Ok(values[0].into())
        };
        let load = value("LoadState=")?;
        let active = value("ActiveState=")?;
        if load != "not-found" || active != "inactive" {
            return Err(CiError::Message(
                "native provider unit remains installed or active".into(),
            ));
        }
        units.push(serde_json::json!({"unit":unit,"load_state":load,"active_state":active,"status":output.status.code(),"stderr":output.stderr}));
    }
    Ok(serde_json::Value::Array(units))
}
pub(super) fn retire_caller(root: &Path, owner: &serde_json::Value, cutoff: Instant) -> Result<()> {
    let name = owner["caller"]
        .as_str()
        .ok_or_else(|| CiError::Message("original caller name absent".into()))?;
    let observed = CommandSpec::new("/usr/bin/getent", root, Duration::from_secs(30))
        .bounded_until(cutoff)
        .args(["passwd", name])
        .output_quiet()?;
    if observed.status.code() == Some(2) && observed.stdout.is_empty() {
        let group = CommandSpec::new("/usr/bin/getent", root, Duration::from_secs(30))
            .bounded_until(cutoff)
            .args(["group", name])
            .output_quiet()?;
        if group.status.code() == Some(2) && group.stdout.is_empty() {
            return Ok(());
        }
        require_successful_output("interrupted caller group readback", &group)?;
        let text =
            std::str::from_utf8(&group.stdout).map_err(|e| CiError::Message(e.to_string()))?;
        let fields = text.trim_end_matches('\n').split(':').collect::<Vec<_>>();
        if fields.len() != 4
            || fields[0] != name
            || fields[2].parse::<u64>().ok() != owner["caller_gid"].as_u64()
            || owner["caller_gid"].as_u64().is_none()
            || !fields[3].is_empty()
        {
            return Err(CiError::Message(
                "interrupted caller allocation retains an unbound native group".into(),
            ));
        }
        let deleted = CommandSpec::new("/usr/sbin/groupdel", root, Duration::from_secs(30))
            .bounded_until(cutoff)
            .arg(name)
            .output_quiet()?;
        return require_successful_output("interrupted ordinary caller group retirement", &deleted);
    }
    require_successful_output("native original caller identity readback", &observed)?;
    let text =
        std::str::from_utf8(&observed.stdout).map_err(|e| CiError::Message(e.to_string()))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(CiError::Message(
            "native caller identity is ambiguous".into(),
        ));
    }
    let fields = lines[0].split(':').collect::<Vec<_>>();
    if fields.len() != 7 || fields[0] != name || Some(fields[4]) != owner["caller_marker"].as_str()
    {
        return Err(CiError::Message(
            "refusing to retire a replacement ordinary caller account".into(),
        ));
    }
    let uid = fields[2]
        .parse::<u32>()
        .map_err(|e| CiError::Message(e.to_string()))?;
    let gid = fields[3]
        .parse::<u32>()
        .map_err(|e| CiError::Message(e.to_string()))?;
    if uid == 0
        || gid == 0
        || owner["caller_uid"]
            .as_u64()
            .is_some_and(|expected| expected != u64::from(uid))
        || owner["caller_gid"]
            .as_u64()
            .is_some_and(|expected| expected != u64::from(gid))
    {
        return Err(CiError::Message(
            "ordinary caller native credential binding changed".into(),
        ));
    }
    let deleted = CommandSpec::new("/usr/sbin/userdel", root, Duration::from_secs(30))
        .bounded_until(cutoff)
        .arg(name)
        .output_quiet()?;
    require_successful_output("ordinary fixture caller retirement", &deleted)?;
    let group = CommandSpec::new("/usr/bin/getent", root, Duration::from_secs(30))
        .bounded_until(cutoff)
        .args(["group", name])
        .output_quiet()?;
    if group.status.code() == Some(2) && group.stdout.is_empty() {
        return Ok(());
    }
    require_successful_output("ordinary caller group readback", &group)?;
    let group_text =
        std::str::from_utf8(&group.stdout).map_err(|e| CiError::Message(e.to_string()))?;
    let fields = group_text
        .trim_end_matches('\n')
        .split(':')
        .collect::<Vec<_>>();
    if fields.len() != 4
        || fields[0] != name
        || fields[2].parse::<u32>().ok() != Some(gid)
        || !fields[3].is_empty()
    {
        return Err(CiError::Message(
            "original ordinary caller group ownership/membership differs".into(),
        ));
    }
    let deleted = CommandSpec::new("/usr/sbin/groupdel", root, Duration::from_secs(30))
        .bounded_until(cutoff)
        .arg(name)
        .output_quiet()?;
    require_successful_output("ordinary fixture caller group retirement", &deleted)
}
fn retire_held_tree(
    directory: &fs::File,
    depth: usize,
    remaining: &mut usize,
    cutoff: Instant,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    if depth > 64 {
        return Err(CiError::Message(
            "fixture retirement directory depth exceeds bound".into(),
        ));
    }
    for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original fixture retirement cutoff exhausted".into(),
            ));
        }
        let entry = entry?;
        *remaining = remaining.checked_sub(1).ok_or_else(|| {
            CiError::Message("fixture retirement entry count exceeds bound".into())
        })?;
        let name = entry.file_name();
        let before = rustix::fs::statat(directory, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        let is_directory = before.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if is_directory {
            let child = fs::File::from(
                rustix::fs::openat2(
                    directory,
                    &name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                    rustix::fs::ResolveFlags::BENEATH
                        | rustix::fs::ResolveFlags::NO_SYMLINKS
                        | rustix::fs::ResolveFlags::NO_XDEV,
                )
                .map_err(std::io::Error::from)?,
            );
            let held = child.metadata()?;
            if held.dev() != before.st_dev || held.ino() != before.st_ino {
                return Err(CiError::Message(
                    "fixture retirement child replaced before acquisition".into(),
                ));
            }
            retire_held_tree(&child, depth + 1, remaining, cutoff)?;
        }
        let after = rustix::fs::statat(directory, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        if (before.st_dev, before.st_ino, before.st_mode)
            != (after.st_dev, after.st_ino, after.st_mode)
        {
            return Err(CiError::Message(
                "fixture retirement entry replaced before unlink".into(),
            ));
        }
        rustix::fs::unlinkat(
            directory,
            &name,
            if is_directory {
                rustix::fs::AtFlags::REMOVEDIR
            } else {
                rustix::fs::AtFlags::empty()
            },
        )
        .map_err(std::io::Error::from)?;
    }
    Ok(())
}
pub(super) fn retire_fixture_tree(
    path: &Path,
    identity: &serde_json::Value,
    cutoff: Instant,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.uid() != 0
                || Some(metadata.dev()) != identity["device"].as_u64()
                || Some(metadata.ino()) != identity["inode"].as_u64()
            {
                return Err(CiError::Message(
                    "original fixture root identity is unknown or replaced".into(),
                ));
            }
        }
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let held = directory.metadata()?;
    if Some(held.dev()) != identity["device"].as_u64()
        || Some(held.ino()) != identity["inode"].as_u64()
    {
        return Err(CiError::Message(
            "fixture root replaced before held retirement".into(),
        ));
    }
    retire_held_tree(&directory, 0, &mut 1_000_000, cutoff)?;
    let named = fs::symlink_metadata(path)?;
    if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
        return Err(CiError::Message(
            "fixture root replaced before final retirement".into(),
        ));
    }
    fs::remove_dir(path)?;
    Ok(())
}
fn actual_readback(payload: &MaterializedPayload) -> Result<serde_json::Value> {
    let mut binaries = Vec::new();
    for binary in &payload.distribution.binaries {
        let selected = artifacts::read_file(&binary_path(
            &payload.directory,
            binary,
            &payload.distribution.target,
        ))?;
        let installed = crate::linux_consumer_readiness::measured(
            &Path::new("/usr/libexec").join(binary),
            512 * 1024 * 1024,
        )
        .map_err(CiError::Message)?;
        if installed != selected {
            return Err(CiError::Message(
                "actual installed image bytes differ from selected product".into(),
            ));
        }
        binaries
            .push(serde_json::json!({"binary":binary,"sha256":artifacts::checksum(&installed)}));
    }
    let manifest = crate::linux_consumer_readiness::measured(
        Path::new("/usr/libexec/memcordon-runtime-manifest.json"),
        4 * 1024 * 1024,
    )
    .map_err(CiError::Message)?;
    let current = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&manifest)
        .map_err(CiError::Message)?;
    if current.source_commit != payload.source.commit()
        || current.target != payload.distribution.target
    {
        return Err(CiError::Message(
            "installed current manifest source/target differs".into(),
        ));
    }
    Ok(
        serde_json::json!({"binaries":binaries,"manifest":current,"manifest_sha256":artifacts::checksum(&manifest)}),
    )
}

pub(super) fn protect_payload(
    payload: &MaterializedPayload,
    directory: &Path,
    cutoff: Instant,
) -> Result<Vec<fs::File>> {
    let manifest_bytes = artifacts::read_file(&payload.directory.join("runtime-manifest.json"))?;
    let manifest = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&manifest_bytes)
        .map_err(CiError::Message)?;
    if manifest.source_commit != payload.source.commit()
        || manifest.version != payload.source.version().to_string()
        || manifest.target != payload.distribution.target
    {
        return Err(CiError::Message(
            "selected source manifest identity differs before protected copy".into(),
        ));
    }
    protect_manifest_components(
        payload,
        directory,
        cutoff,
        &manifest_bytes,
        &manifest.components,
    )
}

fn protect_manifest_components(
    payload: &MaterializedPayload,
    directory: &Path,
    cutoff: Instant,
    manifest_bytes: &[u8],
    components: &[memcordon_core::runtime_components::RuntimeComponentRecord],
) -> Result<Vec<fs::File>> {
    let mut held = super::linux_native_component::protected_directory(directory)?;
    for component in components {
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original selected-image copy cutoff expired".into(),
            ));
        }
        if Path::new(&component.path).components().count() != 1
            || !matches!(
                component.path.as_str(),
                "memcordon" | "memcordon-sealed-agent" | "memcordon-arm32-abi-helper"
            )
            || component.mode != 0o755
        {
            return Err(CiError::Message(
                "selected native component inventory/path differs".into(),
            ));
        }
        let path = payload.directory.join(&component.path);
        let mut source = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let before = source.metadata()?;
        if !before.is_file()
            || before.nlink() != 1
            || before.len() != component.size
            || before.len() > 512 * 1024 * 1024
        {
            return Err(CiError::Message(
                "selected image native source custody differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        (&mut source)
            .take(before.len() + 1)
            .read_to_end(&mut bytes)?;
        let after = source.metadata()?;
        if (
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
        ) || bytes.len() as u64 != component.size
            || artifacts::checksum(&bytes) != component.sha256
        {
            return Err(CiError::Message(
                "selected source image bytes changed during protected copy".into(),
            ));
        }
        if let Some(selected) = payload
            .artifacts
            .iter()
            .find(|artifact| artifact.path == path)
            && selected.sha256 != artifacts::checksum(&bytes)
        {
            return Err(CiError::Message(
                "copied image differs from original selected artifact digest".into(),
            ));
        }
        let destination = directory.join(&component.path);
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&destination)?;
        output.write_all(&bytes)?;
        output.set_permissions(fs::Permissions::from_mode(0o755))?;
        output.sync_all()?;
        drop(output);
        held.push(
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(destination)?,
        );
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("runtime-manifest.json"))?;
    output.write_all(manifest_bytes)?;
    output.sync_all()?;
    drop(output);
    held.push(
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("runtime-manifest.json"))?,
    );
    fs::File::open(directory)?.sync_all()?;
    Ok(held)
}

fn protect_owner_probe(
    payload: &MaterializedPayload,
    directory: &Path,
    cutoff: Instant,
) -> Result<Vec<fs::File>> {
    let mut held = Vec::new();
    for name in [
        "current-linux-owner",
        "current-linux-owner.preparation.json",
    ] {
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original observer copy cutoff exhausted".into(),
            ));
        }
        let selected = payload
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.path.file_name().and_then(|leaf| leaf.to_str()) == Some(name)
            })
            .collect::<Vec<_>>();
        if selected.len() != 1 {
            return Err(CiError::Message(format!(
                "selected current observer artifact missing or duplicate: {name}"
            )));
        }
        let selected = selected[0];
        let mut input = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&selected.path)?;
        let before = input.metadata()?;
        if !before.is_file() || before.nlink() != 1 || before.len() > 512 * 1024 * 1024 {
            return Err(CiError::Message(
                "selected current observer source custody differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        (&mut input)
            .take(before.len() + 1)
            .read_to_end(&mut bytes)?;
        let after = input.metadata()?;
        if bytes.len() as u64 != before.len()
            || artifacts::checksum(&bytes) != selected.sha256
            || (
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            )
        {
            return Err(CiError::Message(
                "selected current observer source changed during copy".into(),
            ));
        }
        let destination = directory.join(name);
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&destination)?;
        output.write_all(&bytes)?;
        output.set_permissions(fs::Permissions::from_mode(
            if name == "current-linux-owner" {
                0o555
            } else {
                0o444
            },
        ))?;
        output.sync_all()?;
        drop(output);
        let pin = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&destination)?;
        let metadata = pin.metadata()?;
        if metadata.uid() != 0 || metadata.nlink() != 1 || metadata.len() != before.len() {
            return Err(CiError::Message(
                "protected current observer readback differs".into(),
            ));
        }
        held.push(pin);
    }
    Ok(held)
}

#[expect(
    clippy::too_many_arguments,
    reason = "One installed lease binds both selected products, actual native controller and original phase cutoffs"
)]
pub fn run_current_cell(
    root: &Path,
    payload: &MaterializedPayload,
    identity: &SourceIdentity,
    key: &ProductKey,
    lifetime: &Path,
    artifact_root: &Path,
    work: Instant,
    cleanup: Instant,
    deadline_unix_millis: u64,
    publication: std::sync::Arc<super::linux_lifecycle_diagnostics::HeldCellPublication>,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    publication.verify()?;
    if !rustix::process::geteuid().is_root() || work >= cleanup || Instant::now() >= work {
        return Err(CiError::Message(
            "current Linux installed controller/cutoff invalid".into(),
        ));
    }
    let host_network_before = super::linux_current_network::snapshot()?;
    fs::create_dir(lifetime)?;
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| CiError::Message(e.to_string()))?;
    let suffix = hex::encode(nonce);
    let lease_id = format!("{}-{}-{}", identity.run_id, key.target, key.channel);
    publication.verify_selection(identity, key, &lease_id)?;
    let caller_name = format!("mc-fixture-{suffix}");
    let working = Path::new("/tmp").join(format!("memcordon-current-{suffix}"));
    let admin_base = Path::new("/var/lib/memcordon-consumer-readiness");
    let admin = admin_base.join(format!("current-{suffix}"));
    let agent = admin.join("memcordon-sealed-agent");
    for binary in &payload.distribution.binaries {
        match fs::symlink_metadata(Path::new("/usr/libexec").join(binary)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(CiError::Message(
                    "current lease refuses an unmanaged existing selected installation".into(),
                ));
            }
        }
    }
    let mut journal = InstalledLifecycleJournal {
        format: "memcordon.consumer-readiness.installed-journal".into(),
        revision: 1,
        run_id: identity.run_id.clone(),
        lease_id: lease_id.clone(),
        key: key.clone(),
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        events: Vec::new(),
    };
    let journal_path = lifetime.join("installed-journal.json");
    source::write_json(&journal_path, &journal)?;
    let lifetime_metadata = fs::File::open(lifetime)?.metadata()?;
    let controller_birth = crate::linux_consumer_readiness::process_birth(std::process::id())
        .map_err(CiError::Message)?;
    let clock = crate::ci_operation_time::clock_reading()?;
    let cleanup_counter = clock
        .millis
        .checked_add(
            u64::try_from(
                cleanup
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .map_err(|e| CiError::Message(e.to_string()))?,
        )
        .ok_or_else(|| CiError::Message("original cleanup counter overflow".into()))?;
    let mut owner = serde_json::json!({"format":"memcordon.current-installed-owner","revision":1,"lease_id":lease_id,"source":identity,"cell":key,"caller":caller_name,"caller_marker":format!("memcordon-current-{suffix}"),"working":working,"working_identity":null,"admin":admin,"admin_identity":null,"selected_agent":agent,"selected_agent_sha256":null,"uninstall_required":true,"cleanup_deadline_unix_millis":deadline_unix_millis,"clock_domain":clock.domain,"cleanup_cutoff_millis":cleanup_counter,"controller":{"pid":std::process::id(),"birth":controller_birth,"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()},"lifetime":{"device":lifetime_metadata.dev(),"inode":lifetime_metadata.ino(),"uid":lifetime_metadata.uid(),"mode":lifetime_metadata.mode()}});
    source::write_json(&lifetime.join("current-owner.json"), &owner)?;
    owner["installed_binaries"] = serde_json::to_value(&payload.distribution.binaries)?;
    source::write_json(&lifetime.join("current-owner.json"), &owner)?;
    let mut inventory = Vec::new();
    let fixture_source_bytes = source::selected_archive(
        root,
        &identity.source_commit,
        &identity.source_tree_sha256,
        work,
    )?;
    let fixture_source = persist(
        artifact_root,
        &lifetime.join("fixture-source.tar"),
        &fixture_source_bytes,
        &mut inventory,
    )?;
    persist(
        artifact_root,
        &lifetime.join("host-network-before.json"),
        &serde_json::to_vec(&host_network_before)?,
        &mut inventory,
    )?;
    let mut records = Vec::new();
    let mut failures = Vec::new();
    let mut process_retirements = Vec::new();
    let mut install_issued = false;
    let mut caller_issued = false;
    let mut source_pins = Vec::new();
    let ownership_receipt = persist(
        artifact_root,
        &lifetime.join("original-owned-before-mutation.json"),
        &serde_json::to_vec(&owner)?,
        &mut inventory,
    )?;
    journal.events.push(InstalledLifecycleEvent {
        sequence: 1,
        phase: "owned-before-mutation".into(),
        operation: "actual-root-controller-and-original-cutoff".into(),
        succeeded: true,
        native_receipt: ownership_receipt,
    });
    source::write_json(&journal_path, &journal)?;
    let operation_sequence = std::sync::atomic::AtomicU64::new(0);
    let operation = |program: &Path, args: &[&str], cutoff: Instant| {
        let sequence = operation_sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if sequence >= 256 {
            return Err(CiError::Message(
                "original root operation inventory exceeds bound".into(),
            ));
        }
        let path = lifetime.join(format!("root-operation-{sequence}.json"));
        let executable_sha256 = artifacts::checksum(&artifacts::read_file(program)?);
        let intent = serde_json::json!({"format":"memcordon.current-root-operation","revision":1,"lease_id":lease_id,"program":program,"executable_sha256":executable_sha256,"arguments":args,"process":null,"completed":null});
        source::write_json(&path, &intent)?;
        let output = CommandSpec::new(program, root, Duration::from_secs(300))
            .bounded_until(cutoff)
            .args(args.iter().copied())
            .output_quiet_with_exec_observation(|child| {
                let birth = crate::linux_consumer_readiness::process_birth(child.id())
                    .map_err(CiError::Message)?;
                let mut observed = intent.clone();
                observed["process"] = serde_json::json!({"pid":child.id(),"birth":birth});
                source::write_json(&path, &observed)
            })?;
        let mut completed: serde_json::Value = source::read_json(&path)?;
        use std::os::unix::process::ExitStatusExt;
        completed["completed"] = serde_json::json!({
            "status":output.status.code(),"raw_wait_status":output.status.into_raw(),
            "stdout":output.stdout,"stderr":output.stderr,
        });
        source::write_json(&path, &completed)?;
        Ok(output)
    };
    let body = (|| -> Result<()> {
        match fs::create_dir(admin_base) {
            Ok(()) => fs::set_permissions(admin_base, fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let _base = super::linux_native_component::protected_directory(admin_base)?;
        fs::create_dir(&admin)?;
        fs::set_permissions(&admin, fs::Permissions::from_mode(0o700))?;
        let metadata = fs::File::open(&admin)?.metadata()?;
        owner["admin_identity"] =
            serde_json::json!({"device":metadata.dev(),"inode":metadata.ino()});
        source::write_json(&lifetime.join("current-owner.json"), &owner)?;
        source_pins = protect_payload(payload, &admin, work)?;
        owner["selected_agent_sha256"] = artifacts::checksum(&artifacts::read_file(&agent)?).into();
        source::write_json(&lifetime.join("current-owner.json"), &owner)?;
        let opaque_bytes =
            super::linux_current_package::publish_opaque(&mut owner, lifetime, &admin)?;
        let opaque_operation = operation_sequence.load(std::sync::atomic::Ordering::Relaxed);
        let opaque_output = operation(&agent, &["package", "install"], work);
        let opaque_native = super::linux_current_package::retire_opaque(&mut owner, lifetime)?;
        let opaque_output = opaque_output?;
        persist(
            artifact_root,
            &lifetime.join("opaque-install-native.json"),
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-current-opaque-install","revision":1,"run_id":identity.run_id,"lease_id":lease_id,"operation":relative(artifact_root,&lifetime.join(format!("root-operation-{opaque_operation}.json")))?,"bytes":opaque_bytes,"native":opaque_native}),
            )?,
            &mut inventory,
        )?;
        if opaque_output.status.code() != Some(125)
            || !String::from_utf8_lossy(&opaque_output.stderr)
                .contains("provider is already installed")
        {
            return Err(CiError::Message(
                "current installer did not refuse original opaque occupied bytes".into(),
            ));
        }
        install_issued = true;
        persist(
            artifact_root,
            &lifetime.join("current-fresh-install-before.json"),
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-current-fresh-install-before","revision":1,"lease_id":lease_id,"paths":observe_paths()?,"package_images":absent_package_images(&payload.distribution.binaries)?} ),
            )?,
            &mut inventory,
        )?;
        let installed = operation(&agent, &["package", "install"], work)?;
        require_successful_output("current selected package install", &installed)?;
        let verified = operation(
            Path::new("/usr/libexec/memcordon-sealed-agent"),
            &["package", "verify", "--json"],
            work,
        )?;
        require_successful_output("current installed provider verify", &verified)?;
        let verify_path = persist(
            artifact_root,
            &lifetime.join("installed-verify.json"),
            &verified.stdout,
            &mut inventory,
        )?;
        journal.events.push(InstalledLifecycleEvent {
            sequence: journal.events.len() as u64 + 1,
            phase: "verify".into(),
            operation: "package-install-and-verify".into(),
            succeeded: true,
            native_receipt: verify_path,
        });
        source::write_json(&journal_path, &journal)?;
        caller_issued = true;
        let added = operation(
            Path::new("/usr/sbin/useradd"),
            &[
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--password",
                "!",
                "--comment",
                owner["caller_marker"]
                    .as_str()
                    .expect("fixed native marker"),
                "--groups",
                "memcordon",
                &caller_name,
            ],
            work,
        )?;
        require_successful_output("ordinary fixture caller allocation", &added)?;
        let uid = operation(Path::new("/usr/bin/id"), &["-u", &caller_name], work)?;
        require_successful_output("ordinary caller UID", &uid)?;
        let gid = operation(Path::new("/usr/bin/id"), &["-g", &caller_name], work)?;
        require_successful_output("ordinary caller GID", &gid)?;
        let parse = |bytes: &[u8]| -> Result<u32> {
            std::str::from_utf8(bytes)
                .map_err(|e| CiError::Message(e.to_string()))?
                .trim()
                .parse::<u32>()
                .map_err(|e| CiError::Message(e.to_string()))
        };
        let caller = CallerSession {
            uid: parse(&uid.stdout)?,
            gid: parse(&gid.stdout)?,
            installed_cli: Path::new("/usr/libexec/memcordon").into(),
        };
        if caller.uid == 0 || caller.gid == 0 {
            return Err(CiError::Message(
                "ordinary fixture caller unexpectedly root".into(),
            ));
        }
        let foreign_name = format!("mc-foreign-{suffix}");
        owner["foreign_caller"] = serde_json::json!({
            "caller":foreign_name,"caller_marker":format!("memcordon-foreign-{suffix}")
        });
        source::write_json(&lifetime.join("current-owner.json"), &owner)?;
        let added = operation(
            Path::new("/usr/sbin/useradd"),
            &[
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--password",
                "!",
                "--comment",
                owner["foreign_caller"]["caller_marker"]
                    .as_str()
                    .expect("fixed foreign marker"),
                "--groups",
                "memcordon",
                &foreign_name,
            ],
            work,
        )?;
        require_successful_output("foreign ordinary fixture caller allocation", &added)?;
        let foreign_uid = operation(Path::new("/usr/bin/id"), &["-u", &foreign_name], work)?;
        let foreign_gid = operation(Path::new("/usr/bin/id"), &["-g", &foreign_name], work)?;
        require_successful_output("foreign ordinary caller UID", &foreign_uid)?;
        require_successful_output("foreign ordinary caller GID", &foreign_gid)?;
        let foreign = CallerSession {
            uid: parse(&foreign_uid.stdout)?,
            gid: parse(&foreign_gid.stdout)?,
            installed_cli: caller.installed_cli.clone(),
        };
        if foreign.uid == 0 || foreign.gid == 0 || foreign.uid == caller.uid {
            return Err(CiError::Message(
                "foreign caller native identity is not distinct".into(),
            ));
        }
        owner["foreign_caller"]["caller_uid"] = foreign.uid.into();
        owner["foreign_caller"]["caller_gid"] = foreign.gid.into();
        source::write_json(&lifetime.join("current-owner.json"), &owner)?;
        fs::create_dir(&working)?;
        fs::set_permissions(&working, fs::Permissions::from_mode(0o755))?;
        let metadata = fs::File::open(&working)?.metadata()?;
        owner["working_identity"] =
            serde_json::json!({"device":metadata.dev(),"inode":metadata.ino()});
        owner["caller_uid"] = caller.uid.into();
        owner["caller_gid"] = caller.gid.into();
        source::write_json(&lifetime.join("current-owner.json"), &owner)?;
        if payload.distribution.runtime_selection()?
            == super::distribution::RuntimeSelection::LinuxBaseline
        {
            let ordinary = working.join("ordinary");
            fs::create_dir(&ordinary)?;
            let directory = fs::File::open(&ordinary)?;
            rustix::fs::fchown(
                &directory,
                Some(rustix::process::Uid::from_raw(caller.uid)),
                Some(rustix::process::Gid::from_raw(caller.gid)),
            )
            .map_err(std::io::Error::from)?;
            for (name, program, arguments, status) in [
                ("zero", "/usr/bin/true", Vec::<&str>::new(), 0),
                ("nonzero", "/usr/bin/false", Vec::new(), 1),
                ("deadline", "/usr/bin/sleep", vec!["5"], 124),
            ] {
                let report = ordinary.join(format!("{name}.json"));
                let output = caller
                    .command(&ordinary, work)?
                    .args([
                        "+128MiB",
                        "+2s",
                        "--sealed",
                        "--report-format",
                        "result-v3",
                        "--report",
                    ])
                    .arg(&report)
                    .arg("--")
                    .arg(program)
                    .args(arguments)
                    .output()?;
                let bytes = fs::read(&report)?;
                let result =
                    memcordon_core::result_v3::ResultV3::parse(&bytes).map_err(CiError::Message)?;
                if output.status.code() != Some(status)
                    || result.request.is_some()
                    || result.workload_attempt.is_some()
                    || !matches!(
                        result.runtime,
                        memcordon_core::result_v3::RuntimeExecutionV3::LinuxSealed { .. }
                    )
                    || result.cleanup.state
                        != memcordon_core::execution_facts::CleanupStateV1::Complete
                    || result.delivery != memcordon_core::result_v3::DeliveryStateV3::Complete
                {
                    return Err(CiError::Message(
                        "ordinary credential-preserving installed sealed smoke facts differ".into(),
                    ));
                }
                persist(
                    artifact_root,
                    &lifetime.join(format!("ordinary-{name}.json")),
                    &bytes,
                    &mut inventory,
                )?;
                persist(
                    artifact_root,
                    &lifetime.join(format!("ordinary-{name}-capture.json")),
                    &serde_json::to_vec(
                        &serde_json::json!({"status":output.status.code(),"stdout":output.stdout,"stderr":output.stderr}),
                    )?,
                    &mut inventory,
                )?;
            }
        } else {
            source_pins.extend(protect_owner_probe(payload, &working, work)?);
            let owner_probe = working.join("current-linux-owner");
            let images = CallerImages::materialize(
                payload,
                root,
                &working.join("images"),
                identity,
                key,
                &caller,
                work,
            )?;
            let manifest_bytes = fs::read("/usr/libexec/memcordon-runtime-manifest.json")?;
            let provider =
                memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&manifest_bytes)
                    .and_then(|manifest| manifest.public_binding(&manifest_bytes))
                    .map_err(CiError::Message)?;
            let refusals = lifetime.join("request-refusals");
            fs::create_dir(&refusals)?;
            let refusals = super::linux_current_refusals::run(
                CurrentLinuxInput {
                    controller_directory: &refusals,
                    caller: &caller,
                    images: &images,
                    provider: &provider,
                    directory: &working.join("request-refusals"),
                    work_cutoff: work,
                    cleanup_cutoff: cleanup,
                },
                identity,
                key,
                &lease_id,
                artifact_root,
                &fixture_source,
                &mut owner,
                lifetime,
                &mut inventory,
            )?;
            records.extend(refusals);
            let owner_cases = super::linux_current_owner_cases::run_installed(
                root,
                identity,
                key,
                &caller,
                &foreign,
                &owner_probe,
                &images,
                &provider,
                lifetime,
                &working,
                artifact_root,
                &fixture_source,
                &lease_id,
                work,
                cleanup,
            );
            records.extend(owner_cases.records);
            inventory.extend(owner_cases.artifacts);
            if let Some(error) = owner_cases.primary_error {
                failures.push(error);
            }
            let isolation_cases = super::linux_current_isolation_cases::run_installed(
                root,
                identity,
                key,
                &caller,
                &foreign,
                &owner_probe,
                &images,
                &provider,
                lifetime,
                &working,
                artifact_root,
                &fixture_source,
                &lease_id,
                work,
                cleanup,
            );
            records.extend(isolation_cases.records);
            inventory.extend(isolation_cases.artifacts);
            if let Some(error) = isolation_cases.primary_error {
                failures.push(error);
            }
            let image_cases = super::linux_current_image_cases::run_installed(
                root,
                identity,
                key,
                &caller,
                &owner_probe,
                &images,
                &provider,
                lifetime,
                &working,
                artifact_root,
                &fixture_source,
                &lease_id,
                work,
                cleanup,
            );
            records.extend(image_cases.records);
            inventory.extend(image_cases.artifacts);
            if let Some(error) = image_cases.primary_error {
                failures.push(error);
            }
            let snapshot_cases = super::linux_current_snapshot_cases::run_installed(
                root,
                identity,
                key,
                &caller,
                &foreign,
                &owner_probe,
                &images,
                &provider,
                lifetime,
                &working,
                artifact_root,
                &fixture_source,
                &lease_id,
                work,
                cleanup,
            );
            records.extend(snapshot_cases.records);
            inventory.extend(snapshot_cases.artifacts);
            if let Some(error) = snapshot_cases.primary_error {
                failures.push(error);
            }
            for (ordinal, mut recipe) in super::linux_current_installed::current_recipes(key)?
                .into_iter()
                .enumerate()
            {
                if recipe.key.family == "L-LIFE-02"
                    || super::linux_current_installed::is_isolation_case(&recipe.key)
                {
                    continue;
                }
                if recipe.key.family == "C-IO" && recipe.key.scenario == "native-argv" {
                    use std::os::unix::ffi::OsStringExt;
                    recipe.arguments = vec![
                        "0".into(),
                        "".into(),
                        "white space".into(),
                        "tab\toperand".into(),
                        "embedded\"quote".into(),
                        "trailing\\".into(),
                        std::ffi::OsString::from_vec(vec![b'a', 0xff, b'b']),
                    ];
                }
                if recipe.key.family == "C-STATUS" && recipe.key.scenario == "memory" {
                    recipe.mode = "memory-pressure".into();
                    recipe.memory = "+128MiB".into();
                    recipe.product_deadline = "+30s".into();
                }
                if recipe.key.family == "C-STATUS" && recipe.key.scenario == "deadline" {
                    recipe.mode = "deadline-demand".into();
                    recipe.arguments.clear();
                    recipe.product_deadline = "+2s".into();
                }
                let directory = lifetime.join(format!("case-{ordinal}"));
                fs::create_dir(&directory)?;
                let outcome = run_recipe(
                    CurrentLinuxInput {
                        controller_directory: &directory,
                        caller: &caller,
                        images: &images,
                        provider: &provider,
                        directory: &working.join(format!("case-{ordinal}")),
                        work_cutoff: work,
                        cleanup_cutoff: cleanup,
                    },
                    recipe,
                );
                let case = match outcome {
                    Ok(case) => case,
                    Err(primary) => {
                        if let Err(retention) = retain_case_failure(
                            &working.join(format!("case-{ordinal}")),
                            &directory,
                            artifact_root,
                            caller.uid,
                            &primary.to_string(),
                            &mut inventory,
                        ) {
                            return Err(CiError::Message(format!(
                                "{primary}; failure capture retention: {retention}"
                            )));
                        }
                        return Err(primary);
                    }
                };
                let mut write = |name: &str, bytes: &[u8]| {
                    persist(artifact_root, &directory.join(name), bytes, &mut inventory)
                };
                let request = write("request.json", &serde_json::to_vec(&case.request)?)?;
                let result = case
                    .result
                    .as_ref()
                    .map(|result| write("result.json", &serde_json::to_vec(result)?))
                    .transpose()?;
                let recovery = case
                    .recovery
                    .as_deref()
                    .map(|bytes| write("recovery.json", bytes))
                    .transpose()?;
                let locator = write("attempt.json", &serde_json::to_vec(&case.locator)?)?;
                let stdout = write("stdout.bin", &case.stdout)?;
                let stderr = write("stderr.bin", &case.stderr)?;
                let native = write("native.json", &serde_json::to_vec(&case.controller)?)?;
                let retirement = write("retirement.json", &serde_json::to_vec(&case.retirement)?)?;
                let prepared = write("prepared.json", &case.prepared)?;
                let start = write("start.json", &case.start)?;
                let prepared_ack = case
                    .prepared_ack
                    .as_deref()
                    .map(|bytes| write("prepared-ack.json", bytes))
                    .transpose()?;
                if let Some(processes) = case.retirement["held_processes"].as_array() {
                    for process in processes {
                        if !process_retirements.contains(process) {
                            process_retirements.push(process.clone());
                        }
                    }
                }
                let binary: Vec<u8> = if case.key.scenario == "empty-input" {
                    Vec::new()
                } else {
                    (u8::MIN..=u8::MAX).collect()
                };
                let input = write(
                    "input.json",
                    &serde_json::to_vec(
                        &serde_json::json!({"format":"memcordon.consumer-readiness.input","revision":2,"run_id":identity.run_id,"challenge":case.challenge,"key":case.key,"request":request,"start":start,"prepared":prepared,"prepared_ack":prepared_ack,"binary":binary,"stderr_binary":binary,"deadline_millis":case.deadline_millis,"memory_bytes":case.memory_bytes,"lifetime":case.lifetime,"target_argv":memcordon_readiness_verifier::NativeArguments::UnixBytes(case.arguments.clone())}),
                    )?,
                )?;
                let invocation = if let Some(result) = &case.result {
                    write("invocation.json", &serde_json::to_vec(&result.invocation)?)?
                } else {
                    start.clone()
                };
                let fixture_bytes = fs::read(images.runtime_source.join("bin/owned-readiness"))?;
                let fixture = write("fixture.bin", &fixture_bytes)?;
                let semantic = write(
                    "semantic.json",
                    &serde_json::to_vec(
                        &serde_json::json!({"format":"memcordon.current-fixture-semantic-source","revision":1,"challenge":case.challenge,"stdout":stdout,"native":native}),
                    )?,
                )?;
                let mut outputs = Vec::new();
                for (path, bytes) in &case.outputs {
                    outputs.push(write(&format!("outputs/{}", path.as_str()), bytes)?);
                }
                let evidence = CaseEvidenceV2 {
                    format: "memcordon.consumer-readiness.case".into(),
                    revision: 2,
                    key: case.key.clone(),
                    run_id: identity.run_id.clone(),
                    source_commit: identity.source_commit.clone(),
                    source_tree_sha256: identity.source_tree_sha256.clone(),
                    lease_id: Some(lease_id.clone()),
                    fixture,
                    fixture_source: fixture_source.clone(),
                    fixture_sha256: artifacts::checksum(&fixture_bytes),
                    fixture_source_sha256: artifacts::checksum(&fixture_source_bytes),
                    input: input.clone(),
                    input_sha256: artifacts::checksum(&artifacts::read_file(
                        &artifact_root.join(&input),
                    )?),
                    invocation,
                    request: Some(request),
                    raw_result: result,
                    attempt_observation: Some(locator),
                    authenticated_terminal: None,
                    recovery,
                    stdout,
                    stderr,
                    outputs,
                    native_observation: native,
                    retirement,
                    semantic_observation: semantic,
                    component_recipe_id: None,
                };
                let evidence_path = write("case.json", &serde_json::to_vec(&evidence)?)?;
                let fixture_input =
                    source::read_json::<serde_json::Value>(&artifact_root.join(&evidence.input))?;
                memcordon_readiness_verifier::current::linux::verify_observed_case(
                    &evidence,
                    &fixture_input,
                    &identity.source_commit,
                    &|path| fs::read(artifact_root.join(path)).map_err(|error| error.to_string()),
                )
                .map_err(CiError::Message)?;
                records.push(CaseRecord {
                    key: case.key,
                    run_id: identity.run_id.clone(),
                    state: CaseState::Passed,
                    reason: None,
                    evidence: Some(evidence_path),
                });
                let acknowledged = caller
                    .command(&case.directory, cleanup)?
                    .args(["workload", "acknowledge", "--observation"])
                    .arg(case.directory.join("workload-observation.json"))
                    .output()?;
                require_successful_output(
                    "actual caller completed evidence acknowledgment",
                    &acknowledged,
                )?;
                let ack = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(
                    &acknowledged.stdout,
                )
                .map_err(|e| CiError::Message(e.to_string()))?;
                if ack.association != case.locator {
                    return Err(CiError::Message(
                        "native acknowledgment retired another original record".into(),
                    ));
                }
                write("acknowledgment.json", &acknowledged.stdout)?;
            }
        }
        let cases_receipt = persist(
            artifact_root,
            &lifetime.join("actual-current-cases.json"),
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.current-cases-observation","revision":1,"source":identity,"key":key,"records":records}),
            )?,
            &mut inventory,
        )?;
        journal.events.push(InstalledLifecycleEvent {
            sequence: journal.events.len() as u64 + 1,
            phase: "cases".into(),
            operation: "actual-original-case-drivers-settled".into(),
            succeeded: true,
            native_receipt: cases_receipt,
        });
        source::write_json(&journal_path, &journal)?;
        let fault_ordinal = operation_sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        super::linux_current_package_fault::interrupt(
            root,
            &agent,
            lifetime,
            artifact_root,
            &lease_id,
            fault_ordinal,
            work,
        )?;
        persist(
            artifact_root,
            &lifetime.join("current-install-interruption-retained.json"),
            &fs::read(lifetime.join("current-install-interruption.json"))?,
            &mut inventory,
        )?;
        let upgraded = operation(&agent, &["package", "upgrade"], work)?;
        require_successful_output("current selected package upgrade", &upgraded)?;
        let readback = actual_readback(payload)?;
        let journal_absent = match fs::symlink_metadata(
            "/usr/libexec/.memcordon-current-package-transaction.json",
        ) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
            Ok(_) => false,
        };
        persist(
            artifact_root,
            &lifetime.join("current-recovery-readback.json"),
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-current-package-recovery","revision":1,"lease_id":lease_id,"readback":readback,"journal_absent":journal_absent,"interruption":relative(artifact_root,&lifetime.join("current-install-interruption-retained.json"))?}),
            )?,
            &mut inventory,
        )?;
        let receipt = persist(
            artifact_root,
            &lifetime.join("installed-upgrade-readback.json"),
            &serde_json::to_vec(&readback)?,
            &mut inventory,
        )?;
        journal.events.push(InstalledLifecycleEvent {
            sequence: journal.events.len() as u64 + 1,
            phase: "upgrade".into(),
            operation: "actual-installed-package-readback".into(),
            succeeded: true,
            native_receipt: receipt,
        });
        source::write_json(&journal_path, &journal)?;
        Ok(())
    })();
    if let Err(error) = body {
        failures.push(error.to_string());
        let mut diagnostic_failure = None;
        if let Err(error) = super::linux_unit_diagnostics::capture_private_unit_diagnostics(
            root,
            lifetime,
            &mut diagnostic_failure,
            cleanup,
        ) {
            failures.push(format!("pre-cleanup unit diagnostics unavailable: {error}"));
        }
        if let Some(error) = diagnostic_failure {
            failures.push(error);
        }
        for kind in ["unit-status", "unit-journal"] {
            for extension in ["stdout.bin", "stderr.bin", "capture.json"] {
                let path = lifetime
                    .join("pre-cleanup-units")
                    .join(format!("{kind}.{extension}"));
                match artifacts::read_file(&path) {
                    Ok(bytes) => inventory.push(Artifact {
                        path: relative(artifact_root, &path)?,
                        length: bytes.len() as u64,
                        sha256: artifacts::checksum(&bytes),
                    }),
                    Err(error) => failures.push(format!(
                        "pre-cleanup diagnostic {kind}.{extension}: {error}"
                    )),
                }
            }
        }
    }
    if let Err(error) = super::linux_current_provider_state::restore(&mut owner, lifetime) {
        failures.push(error.to_string());
    }
    if let Err(error) = super::linux_current_package::retire_opaque(&mut owner, lifetime) {
        failures.push(format!("original opaque fixture retirement: {error}"));
    }
    if install_issued {
        match operation(&agent,&["package","uninstall"],cleanup).and_then(|output|{require_successful_output("explicit selected package uninstall",&output)?;persist(artifact_root,&lifetime.join("uninstall-native.json"),&serde_json::to_vec(&serde_json::json!({"status":output.status.code(),"stdout":output.stdout,"stderr":output.stderr}))?,&mut inventory).map(|_|())}){Ok(())=>{},Err(error)=>failures.push(error.to_string())}
    }
    let mut caller_retired = !caller_issued;
    if caller_issued {
        match retire_caller(root, &owner, cleanup) {
            Ok(()) => {
                caller_retired = true;
            }
            Err(error) => failures.push(error.to_string()),
        }
    }
    if !owner["foreign_caller"].is_null()
        && let Err(error) = retire_caller(root, &owner["foreign_caller"], cleanup)
    {
        caller_retired = false;
        failures.push(format!("foreign caller retirement: {error}"));
    }
    let absence = (|| -> Result<serde_json::Value> {
        Ok(
            serde_json::json!({"format":"memcordon.linux-installed-absence","revision":1,"lease_id":lease_id,"paths":observe_paths()?,"package_images":absent_package_images(&payload.distribution.binaries)?,"units":units(root,cleanup)?,"processes":process_retirements}),
        )
    })();
    let mut native = Vec::new();
    match absence {
        Ok(absence) => {
            if caller_retired {
                drop(source_pins);
                for (path, identity) in [
                    (&working, &owner["working_identity"]),
                    (&admin, &owner["admin_identity"]),
                ] {
                    if let Err(error) = retire_fixture_tree(path, identity, cleanup) {
                        failures.push(error.to_string());
                    }
                }
            }
            let evidence = persist(
                artifact_root,
                &lifetime.join("native-absence.json"),
                &serde_json::to_vec(&absence)?,
                &mut inventory,
            )?;
            for resource in [
                NativeResourceV2::LinuxAggregate,
                NativeResourceV2::LinuxTarget,
                NativeResourceV2::LinuxNamespaceInit,
                NativeResourceV2::LinuxGuardian,
                NativeResourceV2::LinuxRelays,
                NativeResourceV2::LinuxControlHandles,
                NativeResourceV2::LinuxRootReferences,
                NativeResourceV2::LinuxStaging,
                NativeResourceV2::LinuxFootprint,
            ] {
                native.push(NativeResourceObservationV2 {
                    resource,
                    settled: true,
                    evidence: evidence.clone(),
                });
            }
        }
        Err(error) => failures.push(error.to_string()),
    }
    let package_absent=payload.distribution.binaries.iter().all(|binary|matches!(fs::symlink_metadata(Path::new("/usr/libexec").join(binary)),Err(error)if error.kind()==std::io::ErrorKind::NotFound));
    match super::linux_current_network::snapshot().and_then(|after| {
        let comparison =
            super::linux_current_network::host_network_comparison(&host_network_before, &after)?;
        persist(
            artifact_root,
            &lifetime.join("host-network-after.json"),
            &serde_json::to_vec(&after)?,
            &mut inventory,
        )?;
        persist(
            artifact_root,
            &lifetime.join("host-network-comparison.json"),
            &serde_json::to_vec(&comparison)?,
            &mut inventory,
        )?;
        if comparison["unchanged"] != true {
            return Err(CiError::Message(
                "host network configuration changed during current installed lifetime".into(),
            ));
        }
        Ok(())
    }) {
        Ok(()) => {}
        Err(error) => failures.push(error.to_string()),
    }
    match super::linux_current_package::emit(
        root,
        payload,
        identity,
        key,
        &lease_id,
        lifetime,
        artifact_root,
        &fixture_source,
        operation_sequence.load(std::sync::atomic::Ordering::Relaxed),
        &mut inventory,
    ) {
        Ok(package_records) => records.extend(package_records),
        Err(error) => failures.push(format!("actual package evidence: {error}")),
    }
    journal.events.push(InstalledLifecycleEvent {
        sequence: journal.events.len() as u64 + 1,
        phase: "finalize".into(),
        operation: "explicit-current-finalization".into(),
        succeeded: failures.is_empty(),
        native_receipt: native
            .first()
            .map(|entry| entry.evidence.clone())
            .unwrap_or_default(),
    });
    source::write_json(&journal_path, &journal)?;
    let journal_bytes = fs::read(&journal_path)?;
    inventory.push(Artifact {
        path: relative(artifact_root, &journal_path)?,
        length: journal_bytes.len() as u64,
        sha256: artifacts::checksum(&journal_bytes),
    });
    let receipt = InstalledLifecycleReceiptV2 {
        format: "memcordon.installed-lifecycle.receipt".into(),
        revision: 2,
        run_id: identity.run_id.clone(),
        lease_id,
        key: key.clone(),
        journal_sha256: artifacts::checksum(&journal_bytes),
        final_sequence: journal.events.len() as u64,
        explicit_finalization_count: 1,
        package_absent,
        native,
        cache_quiescent: failures.is_empty(),
        cleanup_failures: failures.clone(),
        outstanding: if failures.is_empty() {
            Vec::new()
        } else {
            vec!["actual current installed lifetime retains failure evidence".into()]
        },
    };
    let receipt_path = lifetime.join("installed-retirement.json");
    source::write_json_new(&receipt_path, &receipt)?;
    let receipt_bytes = fs::read(&receipt_path)?;
    inventory.push(Artifact {
        path: relative(artifact_root, &receipt_path)?,
        length: receipt_bytes.len() as u64,
        sha256: artifacts::checksum(&receipt_bytes),
    });
    let observations = lifetime.join("current-cell-observations.json");
    source::write_json(
        &observations,
        &serde_json::json!({"format":"memcordon.current-cell-observations","revision":1,"source":identity,"key":key,"records":records,"artifacts":inventory,"failures":failures}),
    )?;
    let captured = fs::read(&observations)?;
    inventory.push(Artifact {
        path: relative(artifact_root, &observations)?,
        length: captured.len() as u64,
        sha256: artifacts::checksum(&captured),
    });
    if !failures.is_empty() {
        return Err(CiError::Message(failures.join("; ")));
    }
    Ok((records, inventory))
}

fn protected_json(path: &Path, limit: u64) -> Result<serde_json::Value> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err(CiError::Message(format!(
            "current original recovery record custody differs: path={:?}; uid={}; mode={:#o}; links={}; length={}; limit={limit}",
            path,
            metadata.uid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.len(),
        )));
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(CiError::Message(
            "current original recovery record changed length".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn process_extinct(pid: u32, birth: u64) -> Result<bool> {
    let path = Path::new("/proc").join(pid.to_string()).join("stat");
    match fs::read_to_string(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    if crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)? != birth {
        return Ok(true);
    }
    let native = rustix::process::Pid::from_raw(
        i32::try_from(pid).map_err(|e| CiError::Message(e.to_string()))?,
    )
    .ok_or_else(|| CiError::Message("original recovery process PID absent".into()))?;
    let fd = match rustix::process::pidfd_open(native, rustix::process::PidfdFlags::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::SRCH) => return Ok(true),
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    match fs::read_to_string(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    if crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)? != birth {
        return Ok(true);
    }
    let mut query = [rustix::event::PollFd::new(
        &fd,
        rustix::event::PollFlags::IN,
    )];
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    rustix::event::poll(&mut query, Some(&zero)).map_err(std::io::Error::from)?;
    let events = query[0].revents();
    if events.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL) {
        return Err(CiError::Message(
            "original native process query failed".into(),
        ));
    }
    Ok(events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP))
}

/// A fresh controller reacquires only actual protected files and query pidfds.
/// Descriptive records never recreate a Child, namespace owner or launch right.
pub fn recover_current_cell(
    root: &Path,
    lifetime: &Path,
    artifact_root: &Path,
    identity: &SourceIdentity,
    key: &ProductKey,
    cleanup: Instant,
) -> Result<Vec<Artifact>> {
    if !rustix::process::geteuid().is_root() || Instant::now() >= cleanup {
        return Err(CiError::Message(
            "current recovery requires actual root and original cleanup allowance".into(),
        ));
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lifetime)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "original current lifetime directory custody differs".into(),
        ));
    }
    let mut owner = protected_json(&lifetime.join("current-owner.json"), 65536)?;
    let clock = crate::ci_operation_time::clock_reading()?;
    let original = owner["cleanup_cutoff_millis"]
        .as_u64()
        .ok_or_else(|| CiError::Message("original native cleanup cutoff absent".into()))?;
    if owner["clock_domain"].as_str() != Some(clock.domain.as_str()) || original <= clock.millis {
        return Err(CiError::Message(
            "original native cleanup boot/domain or cutoff exhausted".into(),
        ));
    }
    let cleanup = cleanup.min(Instant::now() + Duration::from_millis(original - clock.millis));
    if owner["format"] != "memcordon.current-installed-owner"
        || owner["revision"] != 1
        || owner["source"] != serde_json::to_value(identity)?
        || owner["cell"] != serde_json::to_value(key)?
        || Some(metadata.dev()) != owner["lifetime"]["device"].as_u64()
        || Some(metadata.ino()) != owner["lifetime"]["inode"].as_u64()
        || Some(metadata.uid() as u64) != owner["lifetime"]["uid"].as_u64()
    {
        return Err(CiError::Message(
            "original native lifetime/source binding differs".into(),
        ));
    }
    let lock_path = lifetime.join("current-recovery.lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    let lock_metadata = lock.metadata()?;
    if !lock_metadata.is_file()
        || lock_metadata.uid() != 0
        || lock_metadata.mode() & 0o777 != 0o600
        || lock_metadata.nlink() != 1
        || lock_metadata.len() != 0
    {
        return Err(CiError::Message(
            "original current recovery serialization lock differs".into(),
        ));
    }
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(std::io::Error::from)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let same_boot = owner["controller"]["boot_id"].as_str() == Some(boot.trim());
    if !same_boot {
        return Err(CiError::Message(
            "original controller boot differs from current cleanup clock domain".into(),
        ));
    }
    if same_boot {
        let pid = u32::try_from(
            owner["controller"]["pid"]
                .as_u64()
                .ok_or_else(|| CiError::Message("original controller PID absent".into()))?,
        )
        .map_err(|e| CiError::Message(e.to_string()))?;
        let birth = owner["controller"]["birth"]
            .as_u64()
            .ok_or_else(|| CiError::Message("original controller birth absent".into()))?;
        if !process_extinct(pid, birth)? {
            return Err(CiError::Message(
                "original current controller still owns the native lifetime".into(),
            ));
        }
    }
    let mut operation_count = 0;
    for entry in fs::read_dir(lifetime)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(CiError::Message("nonUTF8 current lifetime entry".into()));
        };
        if let Some(index) = name
            .strip_prefix("root-operation-")
            .and_then(|value| value.strip_suffix(".json"))
        {
            if index.parse::<usize>().is_err() || operation_count >= 256 {
                return Err(CiError::Message(
                    "original root operation inventory invalid".into(),
                ));
            }
            operation_count += 1;
            let operation = protected_json(&entry.path(), 65536)?;
            if operation["format"] != "memcordon.current-root-operation"
                || operation["revision"] != 1
                || operation["lease_id"] != owner["lease_id"]
            {
                return Err(CiError::Message(
                    "original root operation source binding differs".into(),
                ));
            }
            if same_boot {
                let pid = u32::try_from(operation["process"]["pid"].as_u64().ok_or_else(|| {
                    CiError::Message("unpublished original root helper remains ambiguous".into())
                })?)
                .map_err(|e| CiError::Message(e.to_string()))?;
                let birth = operation["process"]["birth"]
                    .as_u64()
                    .ok_or_else(|| CiError::Message("original root helper birth absent".into()))?;
                while !process_extinct(pid, birth)? {
                    if Instant::now() >= cleanup {
                        return Err(CiError::Message(
                            "original native package helper remains live at cleanup cutoff".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
    let mut inventory = Vec::new();
    let recovery_directory=(0..32).map(|index|lifetime.join(format!("recovery-observation-{index}"))).find(|path|matches!(fs::symlink_metadata(path),Err(error)if error.kind()==std::io::ErrorKind::NotFound)).ok_or_else(||CiError::Message("original lifetime recovery capture inventory exhausted".into()))?;
    fs::create_dir(&recovery_directory)?;
    fs::set_permissions(&recovery_directory, fs::Permissions::from_mode(0o700))?;
    let mut recovered_frontends = Vec::new();
    let mut case_count = 0;
    for entry in fs::read_dir(lifetime)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name
            .strip_prefix("case-")
            .is_some_and(|index| index.parse::<usize>().is_ok())
        {
            continue;
        }
        case_count += 1;
        if case_count > 256 {
            return Err(CiError::Message(
                "original current case controller inventory exceeds bound".into(),
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "original case controller root custody differs".into(),
            ));
        }
        let frontend_path = entry.path().join("original-frontend.json");
        if !frontend_path.try_exists()? {
            if entry
                .path()
                .join("frontend-creation-intent.json")
                .try_exists()?
                && same_boot
            {
                return Err(CiError::Message(
                    "unpublished original frontend acquisition remains ambiguous".into(),
                ));
            }
            continue;
        }
        let frontend = protected_json(&frontend_path, 65536)?;
        if frontend["format"] != "memcordon.current-original-frontend"
            || frontend["revision"] != 1
            || frontend["provider"]["source_commit"] != identity.source_commit
            || frontend["caller_uid"] != owner["caller_uid"]
            || frontend["creator"]["pid"] != owner["controller"]["pid"]
            || frontend["creator"]["birth"] != owner["controller"]["birth"]
        {
            return Err(CiError::Message(
                "original frontend source/actor/native creator binding differs".into(),
            ));
        }
        let pid = u32::try_from(
            frontend["process"]["pid"]
                .as_u64()
                .ok_or_else(|| CiError::Message("original frontend PID absent".into()))?,
        )
        .map_err(|e| CiError::Message(e.to_string()))?;
        let birth = frontend["process"]["birth"]
            .as_u64()
            .ok_or_else(|| CiError::Message("original frontend birth absent".into()))?;
        let mut pidfd_readable = false;
        if same_boot && !process_extinct(pid, birth)? {
            let held = crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth)
                .map_err(CiError::Message)?;
            held.signal_interrupt()
                .map_err(CiError::Message)?
                .map_err(|code| {
                    CiError::Message(format!("original native frontend interrupt failed: {code}"))
                })?;
            let grace = cleanup.min(Instant::now() + Duration::from_secs(2));
            while !held.exited().map_err(CiError::Message)? && Instant::now() < grace {
                std::thread::sleep(Duration::from_millis(1));
            }
            if !held.exited().map_err(CiError::Message)? {
                held.signal_kill()
                    .map_err(CiError::Message)?
                    .map_err(|code| {
                        CiError::Message(format!(
                            "original native frontend containment failed: {code}"
                        ))
                    })?;
            }
            while !held.exited().map_err(CiError::Message)? {
                if Instant::now() >= cleanup {
                    return Err(CiError::Message(
                        "original native frontend remains at cleanup cutoff".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            pidfd_readable = true;
        }
        if pidfd_readable {
            recovered_frontends.push(serde_json::json!({"pid":pid,"birth":birth,"pidfd_readable":true,"original_boot":owner["controller"]["boot_id"],"current_boot":boot.trim()}));
        }
    }
    super::linux_current_provider_state::restore(&mut owner, lifetime)?;
    super::linux_current_package::retire_opaque(&mut owner, lifetime)?;
    let installed = Path::new("/usr/libexec/memcordon-sealed-agent");
    if fs::symlink_metadata(installed).is_ok() {
        let selected = PathBuf::from(
            owner["selected_agent"]
                .as_str()
                .ok_or_else(|| CiError::Message("original cleanup image name absent".into()))?,
        );
        let expected = owner["selected_agent_sha256"].as_str().ok_or_else(|| {
            CiError::Message("original cleanup image byte association absent".into())
        })?;
        let program = if selected.try_exists()? {
            selected
        } else {
            installed.into()
        };
        let _ancestry = super::linux_native_component::protected_directory(
            program
                .parent()
                .ok_or_else(|| CiError::Message("cleanup image parent absent".into()))?,
        )?;
        let image = super::native_executable::pin_install_image(&program)?;
        if artifacts::checksum(
            &crate::linux_consumer_readiness::measured(&program, 512 * 1024 * 1024)
                .map_err(CiError::Message)?,
        ) != expected
        {
            return Err(CiError::Message(
                "original native cleanup image was replaced".into(),
            ));
        }
        let output = CommandSpec::new(&program, root, Duration::from_secs(300))
            .bounded_until(cleanup)
            .args(["package", "uninstall"])
            .output_quiet()?;
        let captured = persist(
            artifact_root,
            &recovery_directory.join("uninstall.json"),
            &serde_json::to_vec(
                &serde_json::json!({"status":output.status.code(),"stdout":output.stdout,"stderr":output.stderr}),
            )?,
            &mut inventory,
        )?;
        let _ = (image, captured);
        require_successful_output("original selected package recovery uninstall", &output)?;
    }
    retire_caller(root, &owner, cleanup)?;
    if !owner["foreign_caller"].is_null() {
        retire_caller(root, &owner["foreign_caller"], cleanup)?;
    }
    let installed_binaries: Vec<String> =
        serde_json::from_value(owner["installed_binaries"].clone())?;
    let absence = serde_json::json!({"format":"memcordon.linux-installed-absence","revision":1,"lease_id":owner["lease_id"],"paths":observe_paths()?,"package_images":absent_package_images(&installed_binaries)?,"units":units(root,cleanup)?,"processes":recovered_frontends});
    for (field, identity_field) in [("working", "working_identity"), ("admin", "admin_identity")] {
        let path = PathBuf::from(
            owner[field]
                .as_str()
                .ok_or_else(|| CiError::Message("original fixture scope path absent".into()))?,
        );
        retire_fixture_tree(&path, &owner[identity_field], cleanup)?;
    }
    let absence_receipt = persist(
        artifact_root,
        &recovery_directory.join("native-absence.json"),
        &serde_json::to_vec(&absence)?,
        &mut inventory,
    )?;
    let journal_path = lifetime.join("installed-journal.json");
    let original_journal = protected_json(&journal_path, 16 * 1024 * 1024)?;
    let mut journal: InstalledLifecycleJournal = serde_json::from_value(original_journal.clone())?;
    if journal.format != "memcordon.consumer-readiness.installed-journal"
        || journal.revision != 1
        || journal.run_id != identity.run_id
        || journal.key != *key
        || journal.source_commit != identity.source_commit
        || journal.source_tree_sha256 != identity.source_tree_sha256
        || serde_json::to_value(&journal.lease_id)? != owner["lease_id"]
    {
        return Err(CiError::Message(
            "original installed journal differs during native recovery".into(),
        ));
    }
    persist(
        artifact_root,
        &recovery_directory.join("original-journal.json"),
        &serde_json::to_vec(&original_journal)?,
        &mut inventory,
    )?;
    let receipt_path = lifetime.join("installed-retirement.json");
    if receipt_path.try_exists()? {
        let original_receipt = protected_json(&receipt_path, 16 * 1024 * 1024)?;
        persist(
            artifact_root,
            &recovery_directory.join("original-retirement.json"),
            &serde_json::to_vec(&original_receipt)?,
            &mut inventory,
        )?;
    }
    journal.events.push(InstalledLifecycleEvent {
        sequence: journal.events.len() as u64 + 1,
        phase: "recovery".into(),
        operation: "actual-original-native-owners-settled".into(),
        succeeded: true,
        native_receipt: absence_receipt.clone(),
    });
    source::write_json(&journal_path, &journal)?;
    let journal_bytes = fs::read(&journal_path)?;
    inventory.push(Artifact {
        path: relative(artifact_root, &journal_path)?,
        length: journal_bytes.len() as u64,
        sha256: artifacts::checksum(&journal_bytes),
    });
    let binaries = owner["installed_binaries"]
        .as_array()
        .filter(|values| !values.is_empty() && values.len() <= 16)
        .ok_or_else(|| CiError::Message("original installed binary inventory absent".into()))?;
    for binary in binaries {
        let name = binary
            .as_str()
            .ok_or_else(|| CiError::Message("original installed binary name invalid".into()))?;
        if Path::new(name).components().count() != 1
            || name.starts_with('.')
            || !name.starts_with("memcordon")
        {
            return Err(CiError::Message(
                "original installed binary role invalid".into(),
            ));
        }
        match fs::symlink_metadata(Path::new("/usr/libexec").join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(CiError::Message(
                    "native installed package image remains after recovery uninstall".into(),
                ));
            }
        }
    }
    let native = [
        NativeResourceV2::LinuxTarget,
        NativeResourceV2::LinuxAggregate,
        NativeResourceV2::LinuxNamespaceInit,
        NativeResourceV2::LinuxGuardian,
        NativeResourceV2::LinuxRelays,
        NativeResourceV2::LinuxControlHandles,
        NativeResourceV2::LinuxRootReferences,
        NativeResourceV2::LinuxStaging,
        NativeResourceV2::LinuxFootprint,
    ]
    .into_iter()
    .map(|resource| NativeResourceObservationV2 {
        resource,
        settled: true,
        evidence: absence_receipt.clone(),
    })
    .collect();
    let receipt = InstalledLifecycleReceiptV2 {
        format: "memcordon.installed-lifecycle.receipt".into(),
        revision: 2,
        run_id: identity.run_id.clone(),
        lease_id: journal.lease_id.clone(),
        key: key.clone(),
        journal_sha256: artifacts::checksum(&journal_bytes),
        final_sequence: journal.events.len() as u64,
        explicit_finalization_count: 1,
        package_absent: true,
        native,
        cache_quiescent: true,
        cleanup_failures: Vec::new(),
        outstanding: Vec::new(),
    };
    source::write_json(&receipt_path, &receipt)?;
    let receipt_bytes = fs::read(&receipt_path)?;
    inventory.push(Artifact {
        path: relative(artifact_root, &receipt_path)?,
        length: receipt_bytes.len() as u64,
        sha256: artifacts::checksum(&receipt_bytes),
    });
    let after = fs::symlink_metadata(lifetime)?;
    if (metadata.dev(), metadata.ino()) != (after.dev(), after.ino()) {
        return Err(CiError::Message(
            "original current lifetime was replaced during recovery".into(),
        ));
    }
    Ok(inventory)
}
pub fn recover_current_smoke(
    root: &Path,
    lifetime: &Path,
    artifact_root: &Path,
    expected_commit: &str,
    expected_version: &str,
    key: &ProductKey,
    cleanup: Instant,
) -> Result<Vec<Artifact>> {
    let owner = protected_json(&lifetime.join("current-owner.json"), 65536)?;
    let identity: SourceIdentity = serde_json::from_value(owner["source"].clone())?;
    if identity.source_commit != expected_commit
        || identity.version != expected_version
        || owner["cell"] != serde_json::to_value(key)?
    {
        return Err(CiError::Message(
            "original smoke source/product association differs".into(),
        ));
    }
    recover_current_cell(root, lifetime, artifact_root, &identity, key, cleanup)
}
pub fn collect_current_cell_observations(
    lifetime: &Path,
    artifact_root: &Path,
    identity: &SourceIdentity,
    key: &ProductKey,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lifetime)?;
    let metadata = directory.metadata()?;
    let owner = protected_json(&lifetime.join("current-owner.json"), 65536)?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || Some(metadata.dev()) != owner["lifetime"]["device"].as_u64()
        || Some(metadata.ino()) != owner["lifetime"]["inode"].as_u64()
        || owner["source"] != serde_json::to_value(identity)?
        || owner["cell"] != serde_json::to_value(key)?
    {
        return Err(CiError::Message(
            "original current observation source/native directory binding differs".into(),
        ));
    }
    let path = lifetime.join("current-cell-observations.json");
    let value = protected_json(&path, 16 * 1024 * 1024)?;
    if value["format"] != "memcordon.current-cell-observations"
        || value["revision"] != 1
        || value["source"] != serde_json::to_value(identity)?
        || value["key"] != serde_json::to_value(key)?
    {
        return Err(CiError::Message(
            "original current observation payload association differs".into(),
        ));
    }
    let records: Vec<CaseRecord> = serde_json::from_value(value["records"].clone())?;
    let mut inventory: Vec<Artifact> = serde_json::from_value(value["artifacts"].clone())?;
    memcordon_readiness_verifier::validate_artifact_custody(artifact_root, &inventory)
        .map_err(CiError::Message)?;
    let bytes = fs::read(&path)?;
    inventory.push(Artifact {
        path: relative(artifact_root, &path)?,
        length: bytes.len() as u64,
        sha256: artifacts::checksum(&bytes),
    });
    Ok((records, inventory))
}
