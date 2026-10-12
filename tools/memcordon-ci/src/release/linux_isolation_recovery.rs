use super::linux_mixed_installed::{
    decode_owned_resource_json, owned_fixture_recipes, read_owned_resource, retain,
    retire_admin_children,
};
use crate::consumer_readiness_ledger::SourceIdentity;
use crate::{CiError, Result};
use memcordon_core::workload_registry_v3::RuntimeImageDefinitionV1;
use memcordon_readiness_verifier::ProductKey;
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::Instant,
};

fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn closed(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == fields.len() && object.keys().all(|key| fields.contains(&key.as_str()))
    })
}
fn remaining_deadline(deadline: Instant, cleanup_wall: u64) -> Result<Instant> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| fail(&error.to_string()))?
        .as_millis();
    let now = u64::try_from(now).map_err(|_| fail("isolation recovery wall clock overflow"))?;
    let remaining = cleanup_wall
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or_else(|| fail("isolation recovery original wall cleanup cutoff exhausted"))?;
    let wall_deadline = Instant::now()
        .checked_add(std::time::Duration::from_millis(remaining))
        .ok_or_else(|| fail("isolation recovery wall-to-monotonic cutoff overflow"))?;
    let bounded = deadline.min(wall_deadline);
    if Instant::now() >= bounded {
        return Err(fail(
            "isolation recovery original monotonic cleanup cutoff exhausted",
        ));
    }
    Ok(bounded)
}

/// Enroll only original finite import intents after native controller/attempt recovery.
#[expect(
    clippy::too_many_arguments,
    reason = "Recovery separately binds original lease, acquisition, import custody, account, and deadline"
)]
pub fn recover_imports(
    output: &Path,
    identity: &SourceIdentity,
    cell: &ProductKey,
    admin_root: &Path,
    lease_id: &str,
    work_wall: u64,
    cleanup_wall: u64,
    deadline: Instant,
) -> Result<Vec<(RuntimeImageDefinitionV1, PathBuf)>> {
    if !output.is_absolute()
        || !admin_root.is_absolute()
        || work_wall == 0
        || cleanup_wall <= work_wall
    {
        return Err(fail("isolation recovery original scope/cutoffs invalid"));
    }
    let deadline = remaining_deadline(deadline, cleanup_wall)?;
    let mut recovered = vec![];
    for (ordinal, recipe) in owned_fixture_recipes(cell)?.into_iter().enumerate() {
        let scenario = recipe.key.scenario.as_str();
        if recipe.key.family != "L-ISO-02"
            || !["input-socket", "imported-socket", "caller-writable-tree"].contains(&scenario)
        {
            continue;
        }
        if Instant::now() >= deadline {
            return Err(fail("isolation recovery crossed original cleanup deadline"));
        }
        let directory = output.join(format!("recipe-{ordinal}"));
        let intent_path = directory.join("isolation-import-intent.json");
        let intent_bytes = match read_owned_resource(&intent_path, 64 * 1024) {
            Ok(bytes) => bytes,
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let intent = decode_owned_resource_json(&intent_bytes)?;
        let definition_path = admin_root
            .join(format!("isolation-input-recipe-{ordinal}"))
            .join("definition.json");
        let source = directory.join("isolation-input-source");
        if !closed(
            &intent,
            &[
                "format",
                "revision",
                "identity",
                "cell",
                "lease_id",
                "scenario",
                "definition",
                "definition_sha256",
                "reference",
                "source_root",
                "work_deadline_unix_millis",
                "cleanup_deadline_unix_millis",
            ],
        ) || intent["format"] != "memcordon.linux-isolation-import-intent"
            || intent["revision"] != 1
            || intent["identity"] != json!(identity)
            || intent["cell"] != json!(cell)
            || intent["lease_id"] != lease_id
            || intent["scenario"] != scenario
            || intent["definition"] != json!(definition_path)
            || intent["source_root"] != json!(source)
            || intent["work_deadline_unix_millis"] != work_wall
            || intent["cleanup_deadline_unix_millis"] != cleanup_wall
        {
            return Err(fail(
                "isolation recovery substitutes original finite intent",
            ));
        }
        let definition_bytes = read_owned_resource(&definition_path, 16 * 1024 * 1024)?;
        let definition: RuntimeImageDefinitionV1 =
            serde_json::from_value(decode_owned_resource_json(&definition_bytes)?)?;
        if definition.target != cell.target
            || definition.image_id.as_str() != format!("isolation-{scenario}-recipe-{ordinal}")
            || intent["definition_sha256"] != super::artifacts::checksum(&definition_bytes)
            || intent["reference"] != json!(definition.reference().map_err(CiError::Message)?)
        {
            return Err(fail(
                "isolation recovery original definition hash/reference differs",
            ));
        }
        let source_present = match std::fs::symlink_metadata(&source) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
            Err(error) => return Err(error.into()),
        };
        let mut closed_files = 0usize;
        let mut socket_removed = false;
        let mut root_retired = false;
        if let Some(named) = source_present {
            let original = decode_owned_resource_json(&read_owned_resource(
                &directory.join("isolation-import-source.json"),
                64 * 1024,
            )?)?;
            let recovery_intent_path =
                directory.join("isolation-import-controller-death-intent.json");
            let recovery_intent = json!({"format":"memcordon.linux-isolation-import-controller-death-intent","revision":1,"identity":identity,"cell":cell,"lease_id":lease_id,"scenario":scenario,"original_source":original,"intent_sha256":super::artifacts::checksum(&intent_bytes),"cleanup_deadline_unix_millis":cleanup_wall});
            let resumed = match read_owned_resource(&recovery_intent_path, 128 * 1024) {
                Ok(bytes) => {
                    if decode_owned_resource_json(&bytes)? != recovery_intent {
                        return Err(fail(
                            "isolation recovery durable original stage intent differs",
                        ));
                    }
                    true
                }
                Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            };
            let original_mode = original["uid"] == named.uid()
                && original["gid"] == named.gid()
                && original["mode"] == named.mode();
            let revoked_mode = resumed
                && named.uid() == 0
                && named.gid() == 0
                && (named.mode() & 0o7777 == 0o700 || original["mode"] == named.mode());
            if !closed(
                &original,
                &[
                    "format", "revision", "scenario", "path", "device", "inode", "uid", "gid",
                    "mode", "mutation", "parent",
                ],
            ) || original["format"] != "memcordon.linux-isolation-import-source"
                || original["revision"] != 1
                || original["scenario"] != scenario
                || original["path"] != json!(source)
                || !named.is_dir()
                || original["device"] != named.dev()
                || original["inode"] != named.ino()
                || !(original_mode || revoked_mode)
            {
                return Err(fail(
                    "isolation recovery source original native root reassociated",
                ));
            }
            let parent = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&directory)?;
            let stamp = parent.metadata()?;
            if !closed(
                &original["parent"],
                &["path", "device", "inode", "uid", "mode"],
            ) || original["parent"]["path"] != json!(directory)
                || original["parent"]["device"] != stamp.dev()
                || original["parent"]["inode"] != stamp.ino()
                || original["parent"]["uid"] != 0
                || stamp.uid() != 0
                || original["parent"]["mode"] != stamp.mode()
                || stamp.mode() & 0o022 != 0
            {
                return Err(fail(
                    "isolation recovery original native parent reassociated",
                ));
            }
            let root = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&source)?;
            let held = root.metadata()?;
            if held.dev() != named.dev() || held.ino() != named.ino() {
                return Err(fail("isolation recovery named/held root differs"));
            }
            if scenario != "caller-writable-tree" {
                let mutation = &original["mutation"];
                let expected = if scenario == "input-socket" {
                    "owned-source/input-socket"
                } else {
                    definition
                        .entries
                        .as_slice()
                        .first()
                        .ok_or_else(|| fail("isolation original input member absent"))?
                        .path()
                        .as_str()
                };
                if mutation["kind"] != scenario || mutation["path"] != expected {
                    return Err(fail("isolation recovery socket source path differs"));
                }
                let socket_path = source.join(expected);
                let socket_parent_path = socket_path
                    .parent()
                    .ok_or_else(|| fail("isolation socket parent absent"))?;
                if resumed
                    && std::fs::symlink_metadata(socket_parent_path)
                        .err()
                        .is_some_and(|error| error.raw_os_error() == Some(libc::ENOENT))
                {
                    socket_removed = true;
                } else {
                    let socket_parent = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(socket_parent_path)?;
                    let socket_parent_stamp = socket_parent.metadata()?;
                    if socket_parent_stamp.dev() != held.dev()
                        || socket_parent_stamp.uid() != 0
                        || socket_parent_stamp.gid() != 0
                        || socket_parent_stamp.mode() & 0o022 != 0
                    {
                        return Err(fail(
                            "isolation recovery original socket parent is not protected",
                        ));
                    }
                    let leaf = socket_path
                        .file_name()
                        .ok_or_else(|| fail("isolation socket leaf absent"))?;
                    let socket = match rustix::fs::statat(
                        &socket_parent,
                        leaf,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    ) {
                        Ok(native) => Some(native),
                        Err(error) if error.raw_os_error() == libc::ENOENT && resumed => None,
                        Err(error) => return Err(fail(&error.to_string())),
                    };
                    if let Some(socket) = socket {
                        if socket.st_mode & libc::S_IFMT != libc::S_IFSOCK
                            || mutation["device"] != socket.st_dev
                            || mutation["inode"] != socket.st_ino
                            || socket.st_uid != 0
                            || socket.st_gid != 0
                        {
                            return Err(fail(
                                "isolation recovery original named socket reassociated",
                            ));
                        }
                        if !resumed {
                            retain(
                                &recovery_intent_path,
                                &serde_json::to_vec(&recovery_intent)?,
                            )?;
                        }
                        remaining_deadline(deadline, cleanup_wall)?;
                        rustix::fs::unlinkat(&socket_parent, leaf, rustix::fs::AtFlags::empty())
                            .map_err(|error| fail(&error.to_string()))?;
                    }
                    if rustix::fs::statat(
                        &socket_parent,
                        leaf,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .err()
                    .map(|error| error.raw_os_error())
                        != Some(libc::ENOENT)
                    {
                        return Err(fail("isolation recovery named socket remains"));
                    }
                    memcordon_platform::linux_checked_close(socket_parent.into())?;
                    closed_files += 1;
                    socket_removed = true;
                }
            } else {
                if original["mutation"]
                    != json!({"kind":"caller-writable-tree","caller_uid":65534,"caller_gid":65534})
                    || (!(held.uid() == 65534 && held.gid() == 65534) && !revoked_mode)
                {
                    return Err(fail(
                        "isolation recovery original caller-writable mutation differs",
                    ));
                }
                if !resumed {
                    retain(
                        &recovery_intent_path,
                        &serde_json::to_vec(&recovery_intent)?,
                    )?;
                }
            }
            remaining_deadline(deadline, cleanup_wall)?;
            rustix::fs::fchown(
                &root,
                Some(rustix::process::Uid::from_raw(0)),
                Some(rustix::process::Gid::from_raw(0)),
            )
            .map_err(|error| fail(&error.to_string()))?;
            root.set_permissions(std::fs::Permissions::from_mode(0o700))?;
            let mut count = 0;
            retire_admin_children(
                &root,
                held.dev(),
                remaining_deadline(deadline, cleanup_wall)?,
                0,
                &mut count,
            )?;
            remaining_deadline(deadline, cleanup_wall)?;
            rustix::fs::unlinkat(
                &parent,
                "isolation-input-source",
                rustix::fs::AtFlags::REMOVEDIR,
            )
            .map_err(|error| fail(&error.to_string()))?;
            if root.metadata()?.nlink() != 0
                || rustix::fs::statat(
                    &parent,
                    "isolation-input-source",
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .err()
                .map(|error| error.raw_os_error())
                    != Some(libc::ENOENT)
            {
                return Err(fail("isolation recovery original held root not retired"));
            }
            memcordon_platform::linux_checked_close(root.into())?;
            memcordon_platform::linux_checked_close(parent.into())?;
            closed_files += 2;
            root_retired = true;
        }
        let receipt = json!({"format":"memcordon.linux-isolation-import-controller-death-recovery","revision":1,"identity":identity,"cell":cell,"lease_id":lease_id,"scenario":scenario,"intent_sha256":super::artifacts::checksum(&intent_bytes),"definition_sha256":super::artifacts::checksum(&definition_bytes),"source_root":source,"source_absent":true,"named_socket_removed":socket_removed,"held_root_retired":root_retired,"native_file_closes":closed_files,"original_listener_descriptor_recovered":false,"work_deadline_unix_millis":work_wall,"cleanup_deadline_unix_millis":cleanup_wall});
        let mut saved = false;
        for ordinal in 0..128 {
            let path = directory.join(format!(
                "isolation-import-controller-death-recovery-{ordinal}.json"
            ));
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    retain(&path, &serde_json::to_vec(&receipt)?)?;
                    saved = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !saved {
            return Err(fail("isolation recovery receipt finite bound exhausted"));
        }
        recovered.push((definition, definition_path));
    }
    Ok(recovered)
}
