//! Independent immutable-image mutation and native import custody decoder.
use crate::{CaseKey, VerificationResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxImageImportEvidence {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: String,
    pub owner: String,
    pub original_lease_owner: String,
    pub observation: String,
    pub definition: String,
    pub cleanup_definition: String,
    pub import_intent: String,
    pub invocation: String,
    pub native_process: String,
    pub native_creation: String,
    pub stdout: String,
    pub stderr: String,
    pub exit: String,
    pub source_inventory: String,
    pub baseline_entrypoint: String,
    pub neighbor_definition: String,
    pub neighbor_stdout: String,
    pub neighbor_invocation: String,
    pub neighbor_native_process: String,
    pub neighbor_native_creation: String,
    pub neighbor_stderr: String,
    pub neighbor_exit: String,
    pub source_members: Vec<LinuxImageMemberCapture>,
    pub retirement: String,
    pub retirement_exit: String,
    pub retirement_stderr: String,
    pub preparation: Option<LinuxImagePreparationEvidence>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxImageMemberCapture {
    pub path: String,
    pub bytes: String,
    pub baseline_bytes: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxImagePreparationEvidence {
    pub receipt: String,
    pub activation: String,
    pub policy: String,
    pub contract: String,
    pub provider_request: String,
    pub result: String,
    pub native_census: String,
    pub stdout: String,
    pub stderr: String,
}
impl LinuxImageImportEvidence {
    pub fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.owner.as_str(),
            &self.original_lease_owner,
            &self.observation,
            &self.definition,
            &self.cleanup_definition,
            &self.import_intent,
            &self.invocation,
            &self.native_process,
            &self.native_creation,
            &self.stdout,
            &self.stderr,
            &self.exit,
            &self.source_inventory,
            &self.baseline_entrypoint,
            &self.neighbor_definition,
            &self.neighbor_stdout,
            &self.neighbor_invocation,
            &self.neighbor_native_process,
            &self.neighbor_stderr,
            &self.neighbor_exit,
            &self.neighbor_native_creation,
            &self.retirement,
            &self.retirement_exit,
            &self.retirement_stderr,
        ];
        for member in &self.source_members {
            paths.push(&member.bytes);
            if let Some(path) = &member.baseline_bytes {
                paths.push(path);
            }
        }
        if let Some(probe) = &self.preparation {
            paths.extend([
                probe.receipt.as_str(),
                &probe.activation,
                &probe.policy,
                &probe.contract,
                &probe.provider_request,
                &probe.result,
                &probe.native_census,
                &probe.stdout,
                &probe.stderr,
            ]);
        }
        paths
    }
}
fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    let object = value
        .as_object()
        .ok_or("image native receipt is not an object")?;
    if object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    {
        return Err("image native receipt missing/unknown field".into());
    }
    Ok(())
}
pub(crate) fn validate_entrypoint(
    raw: &Value,
    prepared: &Value,
    native: &crate::NativeObservation,
    fixture_sha256: &str,
    challenge: &[u8],
) -> VerificationResult<()> {
    closed(
        raw,
        &[
            "format",
            "revision",
            "source",
            "challenge",
            "attempt_id",
            "target",
            "executable",
        ],
    )?;
    let source = &raw["source"];
    closed(
        source,
        &[
            "host_path",
            "host_stat_errno",
            "observer",
            "host_mount",
            "runtime_definition",
            "fixture_sha256",
            "run_id",
            "lease_id",
        ],
    )?;
    closed(&source["observer"], &["pid", "birth"])?;
    closed(&source["host_mount"], &["device", "inode"])?;
    let target = &raw["target"];
    closed(
        target,
        &[
            "process_id",
            "birth",
            "namespace_pids",
            "user",
            "mount",
            "pid",
            "network",
            "ipc",
        ],
    )?;
    for namespace in ["user", "mount", "pid", "network", "ipc"] {
        closed(&target[namespace], &["device", "inode"])?;
    }
    closed(&raw["executable"], &["device", "inode", "length", "sha256"])?;
    if raw["format"] != "memcordon.linux-image-entrypoint"
        || raw["revision"] != 1
        || raw["attempt_id"].as_str() != native.attempt_id.as_deref()
        || raw["challenge"] != hex::encode(challenge)
        || source["run_id"] != native.run_id
        || source["lease_id"].as_str() != native.lease_id.as_deref()
        || source["observer"] != prepared["observer"]
        || source["host_mount"] != prepared["caller"]["mount"]
        || target != &prepared["target"]
        || target["mount"] == source["host_mount"]
        || source["host_stat_errno"] != 2
    {
        return Err("image entrypoint native host/target association differs".into());
    }
    let image = &source["runtime_definition"];
    let entries = image["entrypoints"]
        .as_array()
        .ok_or("image entrypoints absent")?;
    let selected = entries
        .iter()
        .filter(|entry| entry["id"] == "owned-readiness")
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err("image entrypoint selection differs".into());
    }
    let path = selected[0]["path"]
        .as_str()
        .ok_or("image entrypoint path absent")?;
    let member = regular_path(image, path)?;
    if source["host_path"] != format!("/{path}")
        || source["fixture_sha256"] != fixture_sha256
        || raw["executable"]["sha256"] != source["fixture_sha256"]
        || entry(image, &member)?["sha256"] != source["fixture_sha256"]
        || ["device", "inode", "length"].iter().any(|field| {
            raw["executable"][field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
    {
        return Err("image entrypoint actual kernel executable differs".into());
    }
    Ok(())
}
fn entry<'a>(image: &'a Value, path: &str) -> VerificationResult<&'a Value> {
    image["entries"]
        .as_array()
        .ok_or("image inventory absent")?
        .iter()
        .find(|entry| entry["path"] == path)
        .ok_or("image member absent".into())
}
fn regular_path(image: &Value, path: &str) -> VerificationResult<String> {
    let mut path = path.to_owned();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(path.clone()) || visited.len() > 64 {
            return Err("image dependency alias cycle/bound".into());
        }
        let value = entry(image, &path)?;
        match value["kind"].as_str() {
            Some("regular") => return Ok(path),
            Some("symlink") => {
                path = value["target"]
                    .as_str()
                    .ok_or("image alias target absent")?
                    .into()
            }
            _ => return Err("image dependency kind differs".into()),
        }
    }
}
fn owned_image_id(
    identity: &Value,
    cell: &Value,
    lease: &str,
    scenario: &str,
) -> VerificationResult<String> {
    #[derive(Serialize)]
    struct Source<'a> {
        run_id: &'a str,
        source_commit: &'a str,
        source_tree_sha256: &'a str,
        version: &'a str,
    }
    #[derive(Serialize)]
    struct Cell<'a> {
        target: &'a str,
        channel: &'a str,
    }
    fn text<'a>(value: &'a Value, field: &str) -> VerificationResult<&'a str> {
        value[field]
            .as_str()
            .ok_or_else(|| format!("image owner {field} absent"))
    }
    let source = Source {
        run_id: text(identity, "run_id")?,
        source_commit: text(identity, "source_commit")?,
        source_tree_sha256: text(identity, "source_tree_sha256")?,
        version: text(identity, "version")?,
    };
    let cell = Cell {
        target: text(cell, "target")?,
        channel: text(cell, "channel")?,
    };
    Ok(crate::sha256(
        &serde_json::to_vec(&(source, cell, lease, scenario)).map_err(|error| error.to_string())?,
    ))
}
struct ElfStartup {
    machine: u16,
    interpreter: Option<String>,
    needed: Vec<String>,
    first_needed: Option<(usize, usize)>,
    search: Vec<String>,
}
fn elf_startup(bytes: &[u8]) -> VerificationResult<ElfStartup> {
    let take = |offset: usize, size: usize| {
        bytes
            .get(offset..offset.checked_add(size).ok_or("ELF range overflow")?)
            .ok_or("ELF field exceeds captured image")
    };
    let u16_at = |offset| -> VerificationResult<u16> {
        Ok(u16::from_le_bytes(
            take(offset, 2)?.try_into().map_err(|_| "ELF16 width")?,
        ))
    };
    let u64_at = |offset| -> VerificationResult<u64> {
        Ok(u64::from_le_bytes(
            take(offset, 8)?.try_into().map_err(|_| "ELF64 width")?,
        ))
    };
    let number = |value: u64| -> VerificationResult<usize> {
        usize::try_from(value).map_err(|_| "ELF offset exceeds native capture".into())
    };
    let string = |offset: usize| -> VerificationResult<String> {
        let tail = bytes.get(offset..).ok_or("ELF string outside capture")?;
        let count = tail
            .iter()
            .take(4097)
            .position(|byte| *byte == 0)
            .ok_or("ELF string lacks bounded NUL")?;
        String::from_utf8(tail[..count].to_vec()).map_err(|error| error.to_string())
    };
    if take(0, 7)? != b"\x7fELF\x02\x01\x01" || u16_at(54)? != 56 {
        return Err("captured baseline startup is not native ELF64 little endian".into());
    }
    let machine = u16_at(18)?;
    let start = number(u64_at(32)?)?;
    let count = usize::from(u16_at(56)?);
    if count == 0 || count > 1024 {
        return Err("ELF program header count exceeds finite bound".into());
    }
    let mut loads = Vec::new();
    let mut dynamic = None;
    let mut interpreter = None;
    for index in 0..count {
        let header = start
            .checked_add(index.checked_mul(56).ok_or("ELF program index overflow")?)
            .ok_or("ELF program range overflow")?;
        let tag = u32::from_le_bytes(
            take(header, 4)?
                .try_into()
                .map_err(|_| "ELF program tag width")?,
        );
        let offset = u64_at(header + 8)?;
        let address = u64_at(header + 16)?;
        let size = u64_at(header + 32)?;
        take(number(offset)?, number(size)?)?;
        match tag {
            1 => loads.push((offset, address, size)),
            2 => {
                if dynamic.replace((number(offset)?, number(size)?)).is_some() {
                    return Err("ELF has duplicate dynamic segment".into());
                }
            }
            3 if interpreter.replace(string(number(offset)?)?).is_some() => {
                return Err("ELF has duplicate interpreter".into());
            }
            _ => {}
        }
    }
    let (start, size) = dynamic.ok_or("baseline dynamic ELF segment absent")?;
    if size % 16 != 0 || size > 1024 * 1024 {
        return Err("ELF dynamic segment width/bound differs".into());
    }
    let mut table = Vec::new();
    let mut strtab = None;
    let mut terminated = false;
    for index in 0..size / 16 {
        let position = start + index * 16;
        let tag = u64_at(position)?;
        if tag == 0 {
            terminated = true;
            break;
        }
        let value = u64_at(position + 8)?;
        if tag == 5 && strtab.replace(value).is_some() {
            return Err("ELF dynamic string table duplicated".into());
        }
        table.push((tag, value, position));
    }
    if !terminated {
        return Err("ELF dynamic table lacks terminal entry".into());
    }
    let address = strtab.ok_or("ELF dynamic string table absent")?;
    let bases = loads
        .iter()
        .filter_map(|(file, base, size)| {
            address
                .checked_sub(*base)
                .filter(|delta| delta < size)
                .and_then(|delta| file.checked_add(delta))
        })
        .collect::<Vec<_>>();
    if bases.len() != 1 {
        return Err("ELF dynamic strings map ambiguously".into());
    }
    let base = bases[0];
    let mut needed = Vec::new();
    let mut search = Vec::new();
    let mut first_needed = None;
    for (tag, value, position) in table {
        if matches!(tag, 1 | 15 | 29) {
            let offset = number(
                base.checked_add(value)
                    .ok_or("ELF string offset overflow")?,
            )?;
            let text = string(offset)?;
            if tag == 1 {
                if first_needed.is_none() {
                    first_needed = Some((position, offset));
                }
                needed.push(text);
            } else {
                search.push(text);
            }
        }
    }
    Ok(ElfStartup {
        machine,
        interpreter,
        needed,
        first_needed,
        search,
    })
}

/// Verify captured command bytes and native wait independently; exit alone is insufficient.
#[expect(
    clippy::too_many_arguments,
    reason = "Compare selected image bytes with independent command, creation, exit and custody evidence"
)]
pub fn validate_linux_image_command(
    command: &Value,
    native: &Value,
    creation_bytes: &[u8],
    exit: &Value,
    command_bytes: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    agent_sha: &str,
) -> VerificationResult<i32> {
    if command["format"] != "memcordon.linux-image-import-command" {
        return Err("original image import command format differs".into());
    }
    validate_linux_image_native_command(
        command,
        native,
        creation_bytes,
        exit,
        command_bytes,
        stdout,
        stderr,
        agent_sha,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Compare selected image bytes with independent command, creation, exit and custody evidence"
)]
pub(crate) fn validate_linux_image_native_command(
    command: &Value,
    native: &Value,
    creation_bytes: &[u8],
    exit: &Value,
    command_bytes: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    agent_sha: &str,
) -> VerificationResult<i32> {
    let creation: Value = crate::wire::decode(creation_bytes)?;
    closed(
        &creation,
        &[
            "format",
            "revision",
            "process_id",
            "birth",
            "pidfd_device",
            "pidfd_inode",
            "invocation_sha256",
            "kernel_image",
        ],
    )?;
    closed(
        &creation["kernel_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    closed(
        command,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "scenario",
            "program",
            "executable_sha256",
            "argv",
            "cwd",
            "environment_cleared",
            "definition_sha256",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    closed(
        native,
        &[
            "format",
            "revision",
            "process_id",
            "birth",
            "raw_wait_status",
            "native_exit",
            "signal",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
            "executable_device",
            "executable_inode",
            "creation_sha256",
            "pidfd_device",
            "pidfd_inode",
            "pidfd_revents",
        ],
    )?;
    if creation["format"] != "memcordon.linux-image-import-creation"
        || creation["revision"] != 1
        || [
            "process_id",
            "birth",
            "pidfd_device",
            "pidfd_inode",
            "invocation_sha256",
        ]
        .iter()
        .any(|field| creation[field] != native[field])
        || native["creation_sha256"] != crate::sha256(creation_bytes)
        || creation["pidfd_inode"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || creation["pidfd_device"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || creation["kernel_image"]["device"] != native["executable_device"]
        || creation["kernel_image"]["inode"] != native["executable_inode"]
        || creation["kernel_image"]["sha256"] != agent_sha
        || creation["kernel_image"]["length"]
            .as_u64()
            .is_none_or(|value| value == 0 || value > 512 * 1024 * 1024)
        || !matches!(native["pidfd_revents"].as_u64(), Some(1 | 16 | 17))
    {
        return Err("image importer original retained PIDFD creation/retirement differs".into());
    }
    closed(exit, &["native_exit", "success"])?;
    let status = native["native_exit"]
        .as_i64()
        .filter(|status| (0..=255).contains(status))
        .ok_or("native image importer did not exit normally")? as i32;
    if !matches!(
        command["format"].as_str(),
        Some(
            "memcordon.linux-image-import-command"
                | "memcordon.linux-isolation-image-retirement-command"
        )
    ) || command["revision"] != 1
        || command["program"] != "/usr/libexec/memcordon-sealed-agent"
        || command["executable_sha256"] != agent_sha
        || command["environment_cleared"] != true
        || native["format"] != "memcordon.linux-image-import-process"
        || native["revision"] != 1
        || native["process_id"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
            .is_none()
        || native["birth"]
            .as_u64()
            .filter(|birth| *birth > 0)
            .is_none()
        || native["executable_inode"]
            .as_u64()
            .filter(|inode| *inode > 0)
            .is_none()
        || native["executable_device"]
            .as_u64()
            .is_none_or(|device| device == 0)
        || native["raw_wait_status"] != status * 256
        || !native["signal"].is_null()
        || native["invocation_sha256"] != crate::sha256(command_bytes)
        || native["stdout_sha256"] != crate::sha256(stdout)
        || native["stderr_sha256"] != crate::sha256(stderr)
        || exit["native_exit"] != status
        || exit["success"] != (status == 0)
        || command["work_deadline_unix_millis"]
            .as_u64()
            .filter(|cutoff| *cutoff > 0)
            .is_none()
        || command["cleanup_deadline_unix_millis"].as_u64()
            <= command["work_deadline_unix_millis"].as_u64()
    {
        return Err("native image importer command/wait/capture association differs".into());
    }
    Ok(status)
}

/// Require the intended mutation in the measured source, with every other image member unchanged.
pub fn validate_linux_image_mutation(
    scenario: &str,
    target: &str,
    definition: &Value,
    inventory: &Value,
    baseline_entrypoint: &[u8],
    captures: &BTreeMap<String, (Vec<u8>, Option<Vec<u8>>)>,
) -> VerificationResult<()> {
    closed(
        inventory,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "scenario",
            "source_root",
            "baseline_definition",
            "members",
            "alias",
        ],
    )?;
    if inventory["format"] != "memcordon.linux-image-source-inventory"
        || inventory["revision"] != 1
        || inventory["scenario"] != scenario
    {
        return Err("image source inventory format/scenario differs".into());
    }
    let baseline = &inventory["baseline_definition"];
    crate::linux_build::linux_image_reference(baseline, target)?;
    let first = baseline["entrypoints"]
        .as_array()
        .ok_or("baseline entrypoint list absent")?
        .iter()
        .find(|entry| entry["id"] == "owned-readiness")
        .and_then(|entry| entry["path"].as_str())
        .ok_or("baseline owned image entrypoint absent")?;
    let first = regular_path(baseline, first)?;
    if entry(baseline, &first)?["sha256"] != crate::sha256(baseline_entrypoint) {
        return Err("baseline entrypoint bytes differ from actual image inventory".into());
    }
    let baseline_elf = elf_startup(baseline_entrypoint)?;
    if baseline_elf.machine
        != match target.split('-').next() {
            Some("x86_64") => 62,
            Some("aarch64") => 183,
            _ => return Err("image ELF native target unsupported".into()),
        }
    {
        return Err("baseline startup ELF machine differs from selected native target".into());
    }
    let members = inventory["members"]
        .as_array()
        .filter(|members| !members.is_empty() && members.len() <= 16384)
        .ok_or("native image source members empty/unbounded")?;
    let mut seen = BTreeSet::new();
    let mut changed = Vec::new();
    for member in members {
        closed(
            member,
            &[
                "path",
                "device",
                "inode",
                "uid",
                "mode",
                "nlink",
                "size",
                "ctime_seconds",
                "ctime_nanoseconds",
                "sha256",
                "bytes",
                "baseline_bytes",
            ],
        )?;
        let path = member["path"]
            .as_str()
            .ok_or("native source member path absent")?;
        if !seen.insert(path)
            || member["uid"] != 0
            || member["inode"]
                .as_u64()
                .filter(|inode| *inode > 0)
                .is_none()
            || member["device"].as_u64().is_none()
            || member["ctime_seconds"].as_i64().is_none()
            || member["ctime_nanoseconds"]
                .as_i64()
                .filter(|nanos| (0..1_000_000_000).contains(nanos))
                .is_none()
        {
            return Err("native source member identity/custody differs".into());
        }
        let declared = entry(definition, path)?;
        let mode = member["mode"].as_u64().ok_or("native source mode absent")?;
        if declared["kind"] != "regular"
            || member["size"] != declared["size"]
            || mode & 0o170000 != 0o100000
            || mode & 0o6000 != 0
            || (declared["executable"] == true && mode & 0o111 == 0)
        {
            return Err("source member type/size/mode differs from submitted definition".into());
        }
        if member["sha256"] != declared["sha256"] || member["nlink"] != 1 {
            changed.push(path);
        }
        if let Some((bytes, baseline_bytes)) = captures.get(path) {
            if member["sha256"] != crate::sha256(bytes)
                || member["size"].as_u64() != Some(bytes.len() as u64)
            {
                return Err("native source member captured bytes differ".into());
            }
            if let Some(before) = baseline_bytes
                && entry(baseline, path)?["sha256"] != crate::sha256(before)
            {
                return Err("captured baseline member differs from image".into());
            }
        } else if !member["bytes"].is_null() || !member["baseline_bytes"].is_null() {
            return Err("selected native source member bytes not retained".into());
        }
    }
    let declared = definition["entries"]
        .as_array()
        .ok_or("submitted image entries absent")?
        .iter()
        .filter(|entry| entry["kind"] == "regular")
        .map(|entry| entry["path"].as_str().ok_or("submitted member path absent"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if seen != declared {
        return Err(
            "native source inventory does not cover exact submitted regular members".into(),
        );
    }
    let mut expected = baseline.clone();
    match scenario {
        "first-image" | "interpreter" | "shared-library" => {
            if changed.len() != 1 || !inventory["alias"].is_null() {
                return Err("image byte mutation does not alter exactly one member".into());
            }
            let path = changed[0];
            let (after, before) = captures.get(path).ok_or("changed member bytes absent")?;
            let before = before
                .as_ref()
                .ok_or("changed member baseline bytes absent")?;
            if before.is_empty()
                || after.len() != before.len()
                || after[0] != (before[0] ^ 1)
                || after[1..] != before[1..]
            {
                return Err("source is not exact first-byte mutation".into());
            }
            if scenario == "first-image" && path != first {
                return Err("first-image mutation targets unrelated image member".into());
            }
            if scenario == "interpreter" {
                let interpreter = baseline_elf
                    .interpreter
                    .as_deref()
                    .and_then(|path| path.strip_prefix('/'))
                    .ok_or("native baseline interpreter absent")?;
                if path != regular_path(baseline, interpreter)? {
                    return Err("interpreter mutation selects unrelated image object".into());
                }
            }
            if scenario == "shared-library" {
                let needed = baseline_elf
                    .needed
                    .first()
                    .ok_or("native baseline shared-library dependency absent")?;
                let selected = baseline["library_directories"]
                    .as_array()
                    .ok_or("baseline loader directories absent")?
                    .iter()
                    .filter_map(|directory| directory.as_str())
                    .find_map(|directory| {
                        regular_path(baseline, &format!("{directory}/{needed}")).ok()
                    })
                    .ok_or("baseline dependency not in immutable catalogue")?;
                if path != selected {
                    return Err(
                        "shared-library mutation selects unrelated native dependency".into(),
                    );
                }
            }
        }
        "writable-alias" => {
            if changed != vec![first.as_str()] {
                return Err("writable alias does not select actual first image".into());
            }
            let member = members
                .iter()
                .find(|member| member["path"] == first)
                .ok_or("aliased first image metadata absent")?;
            let alias = &inventory["alias"];
            closed(alias, &["path", "device", "inode", "nlink", "mode"])?;
            if alias["device"] != member["device"]
                || alias["inode"] != member["inode"]
                || alias["nlink"] != 2
                || member["nlink"] != 2
                || alias["mode"] != member["mode"]
                || member["mode"].as_u64().is_none_or(|mode| mode & 0o200 == 0)
            {
                return Err(
                    "native writable alias does not share exact trusted-startup inode".into(),
                );
            }
        }
        "ld-injection" => {
            expected["startup_environment"]
                .as_array_mut()
                .ok_or("baseline startup environment absent")?
                .push(serde_json::json!({"name":"LD_PRELOAD","value":"/work/owned-injected.so"}));
            if !changed.is_empty() {
                return Err("environment injection changes unrelated member bytes".into());
            }
        }
        "loader-config" => {
            let bytes = b"/work/owned-injected.so\n";
            expected["entries"].as_array_mut().ok_or("baseline image entries absent")?.push(serde_json::json!({"kind":"regular","path":"etc/ld.so.preload","sha256":crate::sha256(bytes),"size":bytes.len(),"executable":false}));
            if !changed.is_empty()
                || captures
                    .get("etc/ld.so.preload")
                    .is_none_or(|(actual, _)| actual != bytes)
            {
                return Err("loader configuration injection native bytes differ".into());
            }
        }
        "rpath-injection" => {
            if !changed.is_empty() {
                return Err("RPATH candidate fails unrelated digest/alias check".into());
            }
            let (bytes, before) = captures
                .get(&first)
                .ok_or("RPATH mutated first image bytes absent")?;
            let before = before.as_ref().ok_or("RPATH baseline bytes absent")?;
            let (tag, string) = elf_startup(before)?
                .first_needed
                .ok_or("baseline first native dynamic dependency absent")?;
            let mut mutated = before.clone();
            mutated
                .get_mut(tag..tag + 8)
                .ok_or("RPATH native tag outside capture")?
                .copy_from_slice(&15u64.to_le_bytes());
            mutated
                .get_mut(string..string + 6)
                .ok_or("RPATH native string outside capture")?
                .copy_from_slice(b"/work\0");
            if mutated != *bytes
                || elf_startup(bytes)?
                    .search
                    .iter()
                    .filter(|search| search.as_str() == "/work")
                    .count()
                    != 1
            {
                return Err(
                    "native RPATH mutation differs from exact writable loader search injection"
                        .into(),
                );
            }
            let selected = expected["entries"]
                .as_array_mut()
                .ok_or("baseline entries absent")?
                .iter_mut()
                .find(|entry| entry["path"] == first)
                .ok_or("RPATH first member absent")?;
            selected["sha256"] = Value::String(crate::sha256(bytes));
        }
        _ => return Err("unknown finite image mutation".into()),
    }
    if expected != *definition {
        return Err("submitted image mutation changes unrelated authority".into());
    }
    Ok(())
}

pub(crate) fn verify_import(
    index: &crate::EvidenceIndex,
    record: &crate::CaseRecord,
    evidence: &LinuxImageImportEvidence,
    products: &BTreeMap<crate::ProductKey, &crate::ProductObservation>,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    crate::header(
        &evidence.format,
        evidence.revision,
        "memcordon.consumer-readiness.linux-image-import",
    )?;
    let origin = crate::producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    let family = if matches!(
        record.key.scenario.as_str(),
        "ld-injection" | "rpath-injection" | "loader-config"
    ) {
        "L-IMG-02"
    } else {
        "L-IMG-01"
    };
    if evidence.key != record.key
        || evidence.run_id != origin.run_id
        || evidence.source_commit != index.source_commit
        || evidence.source_tree_sha256 != index.source_tree_sha256
        || record.key.evidence_class != crate::EvidenceClass::InstalledProduct
        || !record.key.target.ends_with("linux-gnu")
        || record.key.family != family
        || !matches!(
            record.key.scenario.as_str(),
            "first-image"
                | "interpreter"
                | "shared-library"
                | "writable-alias"
                | "ld-injection"
                | "rpath-injection"
                | "loader-config"
        )
    {
        return Err("native image row crosses finite source/origin applicability".into());
    }
    for path in evidence.artifact_paths() {
        custody.bytes(path)?;
    }
    let product_key = crate::ProductKey {
        target: record.key.target.clone(),
        channel: record
            .key
            .channel
            .clone()
            .ok_or("image installed channel absent")?,
    };
    let product = products
        .get(&product_key)
        .copied()
        .ok_or("image selected installed product absent")?;
    if evidence.lease_id != product.lifecycle.lease_id {
        return Err("image case crosses original installed lifetime".into());
    }
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("image selected installed agent absent")?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("image selected installed frontend absent")?;
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let owner = decode(&evidence.owner)?;
    closed(
        &owner,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "provider",
            "account",
            "expected_agent_sha256",
            "output",
            "admin_root",
            "image_admin_root",
            "admin_root_device",
            "admin_root_inode",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    closed(
        &owner["identity"],
        &["run_id", "source_commit", "source_tree_sha256", "version"],
    )?;
    closed(
        &owner["account"],
        &[
            "name",
            "uid",
            "gid",
            "intent",
            "native_readback",
            "group_readback",
        ],
    )?;
    if owner["account"]["name"]
        .as_str()
        .is_none_or(|value| value.is_empty())
        || ["uid", "gid"].iter().any(|field| {
            owner["account"][field]
                .as_u64()
                .is_none_or(|value| value == 0 || value > u32::MAX as u64)
        })
    {
        return Err("image original exclusive account schema differs".into());
    }
    if owner["format"] != "memcordon.linux-image-case-owner"
        || owner["revision"] != 1
        || owner["identity"]["run_id"] != evidence.run_id
        || owner["identity"]["source_commit"] != evidence.source_commit
        || owner["identity"]["source_tree_sha256"] != evidence.source_tree_sha256
        || owner["identity"]["version"] != product.version
        || owner["cell"] != serde_json::to_value(&product_key).map_err(|error| error.to_string())?
        || owner["lease_id"] != evidence.lease_id
        || owner["expected_agent_sha256"] != agent.installed_sha256
    {
        return Err("native image original owner/source/product differs".into());
    }
    let admin = owner["admin_root"]
        .as_str()
        .ok_or("image original admin root absent")?;
    let image_admin = format!("{admin}/image-cases/{}", evidence.lease_id);
    if !admin.starts_with('/')
        || admin
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || owner["image_admin_root"] != image_admin
    {
        return Err("image protected original root scope differs".into());
    }
    let lifetime: crate::InstalledLifecycleJournal =
        serde_json::from_value(decode(&product.lifecycle.journal)?)
            .map_err(|error| error.to_string())?;
    let acquisitions = lifetime
        .events
        .iter()
        .filter(|event| {
            event.phase == "owned-before-mutation"
                && event.operation == "administrative-staging-created"
                && event.succeeded
        })
        .collect::<Vec<_>>();
    if acquisitions.len() != 1
        || lifetime.lease_id != evidence.lease_id
        || lifetime.run_id != evidence.run_id
        || lifetime.source_commit != evidence.source_commit
        || lifetime.source_tree_sha256 != evidence.source_tree_sha256
    {
        return Err("image staging lacks original native lifetime acquisition".into());
    }
    let acquisition = decode(&acquisitions[0].native_receipt)?;
    closed(&acquisition, &["path", "device", "inode"])?;
    if acquisition["path"] != admin
        || acquisition["device"] != owner["admin_root_device"]
        || acquisition["inode"] != owner["admin_root_inode"]
    {
        return Err("image original staging inode differs from native acquisition".into());
    }
    let checkpoints = index
        .artifacts
        .iter()
        .filter(|artifact| artifact.path.ends_with("/owned-resources-acquired.json"))
        .map(|artifact| decode(&artifact.path))
        .collect::<VerificationResult<Vec<_>>>()?;
    let checkpoints = checkpoints
        .iter()
        .filter(|checkpoint| {
            checkpoint["identity"] == owner["identity"]
                && checkpoint["cell"] == owner["cell"]
                && checkpoint["admin_root"] == owner["admin_root"]
        })
        .collect::<Vec<_>>();
    if checkpoints.len() != 1 {
        return Err(
            "image original native account/image acquisition checkpoint absent/ambiguous".into(),
        );
    }
    let checkpoint = checkpoints[0];
    closed(
        checkpoint,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "legacy",
            "images",
            "account",
        ],
    )?;
    let lease = decode(&evidence.original_lease_owner)?;
    closed(
        &lease,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "cleanup_agent",
            "cleanup_agent_sha256",
            "legacy",
            "lease_id",
            "artifact_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    if lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
        || lease["revision"] != 1
        || lease["identity"] != owner["identity"]
        || lease["cell"] != owner["cell"]
        || lease["lease_id"] != owner["lease_id"]
        || lease["admin_root"] != owner["admin_root"]
        || lease["device"] != owner["admin_root_device"]
        || lease["inode"] != owner["admin_root_inode"]
        || lease["cleanup_agent_sha256"] != agent.installed_sha256
        || lease["legacy"] != checkpoint["legacy"]
        || lease["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || lease["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || lease["work_deadline_unix_millis"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || lease["cleanup_deadline_unix_millis"].as_u64()
            <= lease["work_deadline_unix_millis"].as_u64()
    {
        return Err("image original lease scope/cutoff acquisition differs".into());
    }
    if checkpoint["format"] != "memcordon.owned-readiness-resources"
        || checkpoint["revision"] != 1
        || checkpoint["device"] != owner["admin_root_device"]
        || checkpoint["inode"] != owner["admin_root_inode"]
        || checkpoint["account"] != owner["account"]
    {
        return Err("image original native resource acquisition differs".into());
    }
    closed(
        &owner["provider"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    if owner["provider"]["source_commit"] != evidence.source_commit
        || owner["provider"]["runtime_manifest_sha256"]
            != custody.hash(&product.runtime_manifest)?
        || owner["provider"]["generation"]
            != format!("{}:{}", product.version, evidence.source_commit)
    {
        return Err("image provider differs from actual installed runtime".into());
    }
    let row = decode(&evidence.observation)?;
    closed(
        &row,
        &[
            "family",
            "scenario",
            "definition",
            "definition_capture",
            "cleanup_definition_capture",
            "source_root",
            "selected_member",
            "invocation",
            "native_process",
            "native_creation",
            "source_inventory",
            "baseline_entrypoint",
            "stdout",
            "stderr",
            "exit",
            "native_exit",
            "error",
            "preparation_probe",
        ],
    )?;
    let scenario = &record.key.scenario;
    let output = owner["output"]
        .as_str()
        .ok_or("image output scope absent")?;
    let prefix = evidence
        .owner
        .strip_suffix("/owner.json")
        .ok_or("image owner artifact basename differs")?;
    let acquisition_prefix = prefix
        .strip_suffix("/mixed-cases/image-cases")
        .ok_or("image owner not in original mixed acquisition scope")?;
    let artifact_root = lease["artifact_root"]
        .as_str()
        .ok_or("image original artifact root absent")?;
    if !artifact_root.starts_with('/')
        || artifact_root.contains('\0')
        || artifact_root
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || output != format!("{artifact_root}/{prefix}")
    {
        return Err("image native output crosses original acquisition artifact root".into());
    }
    if evidence.original_lease_owner != format!("{acquisition_prefix}/lease-owner.json") {
        return Err("image original lease artifact crosses acquisition scope".into());
    }
    let files = [
        (&evidence.observation, "observation.json", None),
        (
            &evidence.definition,
            "submitted-definition.json",
            Some("definition_capture"),
        ),
        (
            &evidence.cleanup_definition,
            "cleanup-definition.json",
            Some("cleanup_definition_capture"),
        ),
        (&evidence.import_intent, "import-intent.json", None),
        (&evidence.invocation, "invocation.json", Some("invocation")),
        (
            &evidence.native_process,
            "native-process.json",
            Some("native_process"),
        ),
        (
            &evidence.native_creation,
            "native-creation.json",
            Some("native_creation"),
        ),
        (&evidence.stdout, "stdout.json", Some("stdout")),
        (&evidence.stderr, "stderr.bin", Some("stderr")),
        (&evidence.exit, "exit.json", Some("exit")),
        (
            &evidence.source_inventory,
            "native-source-inventory.json",
            Some("source_inventory"),
        ),
        (
            &evidence.baseline_entrypoint,
            "baseline-entrypoint.bin",
            Some("baseline_entrypoint"),
        ),
    ];
    for (path, name, field) in files {
        if path != &format!("{prefix}/{scenario}/{name}")
            || field.is_some_and(|field| row[field] != format!("{output}/{scenario}/{name}"))
        {
            return Err("image native artifact path crosses exact scenario scope".into());
        }
    }
    let source_root = format!("{image_admin}/{scenario}/source");
    let submitted_path = format!("{image_admin}/{scenario}/definition.json");
    if row["family"] != family
        || row["scenario"] != *scenario
        || row["definition"] != submitted_path
        || row["source_root"] != source_root
        || !row["error"].is_null()
    {
        return Err("native image observation crosses selected mutation/source".into());
    }
    let definition = decode(&evidence.definition)?;
    let cleanup = decode(&evidence.cleanup_definition)?;
    let intent = decode(&evidence.import_intent)?;
    if definition["image_id"]
        != owned_image_id(
            &owner["identity"],
            &owner["cell"],
            &evidence.lease_id,
            scenario,
        )?
    {
        return Err("image mutation ID crosses original finite source/cell/scenario owner".into());
    }
    closed(
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
            "cleanup_definition",
            "cleanup_definition_sha256",
            "submitted_definition_valid",
            "reference",
            "source_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    let cleanup_reference =
        crate::linux_build::linux_image_reference(&cleanup, &record.key.target)?;
    if intent["format"] != "memcordon.linux-readiness-image-import-intent"
        || intent["revision"] != 1
        || intent["identity"] != owner["identity"]
        || intent["cell"] != owner["cell"]
        || intent["lease_id"] != evidence.lease_id
        || intent["scenario"] != *scenario
        || intent["definition"] != submitted_path
        || intent["source_root"] != source_root
        || intent["definition_sha256"] != custody.hash(&evidence.definition)?
        || intent["cleanup_definition"]
            != format!("{image_admin}/{scenario}/cleanup-definition.json")
        || intent["cleanup_definition_sha256"] != custody.hash(&evidence.cleanup_definition)?
        || intent["reference"] != cleanup_reference
        || intent["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || intent["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || cleanup["image_id"] != definition["image_id"]
        || intent["submitted_definition_valid"] != (scenario != "ld-injection")
        || (scenario != "ld-injection" && cleanup != definition)
    {
        return Err("image durable pre-import intent/cleanup/source differs".into());
    }
    let inventory = decode(&evidence.source_inventory)?;
    if inventory["identity"] != owner["identity"]
        || inventory["cell"] != owner["cell"]
        || inventory["lease_id"] != evidence.lease_id
        || inventory["source_root"] != source_root
    {
        return Err("image native source inventory crosses owner".into());
    }
    let mut original_baseline = inventory["baseline_definition"].clone();
    original_baseline["image_id"] = checkpoint["images"]["runtime"]["image_id"].clone();
    if original_baseline != checkpoint["images"]["runtime"]
        || definition["image_id"] != inventory["baseline_definition"]["image_id"]
    {
        return Err("image mutation baseline crosses original acquired runtime definition".into());
    }
    let mut captures = BTreeMap::new();
    for member in &evidence.source_members {
        let (ordinal, native) = inventory["members"]
            .as_array()
            .ok_or("native source members absent")?
            .iter()
            .enumerate()
            .find(|(_, native)| native["path"] == member.path)
            .ok_or("captured source member not in actual native inventory")?;
        if member.bytes != format!("{prefix}/{scenario}/source-member-{ordinal}.bin")
            || native["bytes"] != format!("{output}/{scenario}/source-member-{ordinal}.bin")
            || member.baseline_bytes.as_ref().is_some_and(|path| {
                path != &format!("{prefix}/{scenario}/baseline-member-{ordinal}.bin")
                    || native["baseline_bytes"]
                        != format!("{output}/{scenario}/baseline-member-{ordinal}.bin")
            })
            || (member.baseline_bytes.is_none() && !native["baseline_bytes"].is_null())
        {
            return Err("selected image source capture crosses native filename association".into());
        }
        if captures
            .insert(
                member.path.clone(),
                (
                    custody.bytes(&member.bytes)?.to_vec(),
                    member
                        .baseline_bytes
                        .as_deref()
                        .map(|path| custody.bytes(path).map(<[u8]>::to_vec))
                        .transpose()?,
                ),
            )
            .is_some()
        {
            return Err("image selected capture duplicate".into());
        }
    }
    validate_linux_image_mutation(
        scenario,
        &record.key.target,
        &definition,
        &inventory,
        custody.bytes(&evidence.baseline_entrypoint)?,
        &captures,
    )?;
    if scenario != "writable-alias" && !inventory["alias"].is_null() {
        return Err("image mutation invents unrelated alias authority".into());
    }
    let selected = captures
        .keys()
        .filter(|path| path.as_str() != "etc/ld.so.preload")
        .collect::<Vec<_>>();
    if matches!(scenario.as_str(), "ld-injection" | "loader-config") {
        if !row["selected_member"].is_null() || !selected.is_empty() {
            return Err("environment/config mutation substitutes selected object authority".into());
        }
    } else if selected.len() != 1 || row["selected_member"] != *selected[0] {
        return Err(
            "image selected-member projection differs from actual retained mutation bytes".into(),
        );
    }
    if scenario == "writable-alias"
        && inventory["alias"]["path"] != format!("{image_admin}/{scenario}/writable-startup-alias")
    {
        return Err("image writable alias crosses protected original case scope".into());
    }
    if scenario == "ld-injection" && cleanup != inventory["baseline_definition"] {
        return Err(
            "invalid startup definition does not retain exact baseline cleanup owner".into(),
        );
    }
    let command = decode(&evidence.invocation)?;
    let status = validate_linux_image_command(
        &command,
        &decode(&evidence.native_process)?,
        custody.bytes(&evidence.native_creation)?,
        &decode(&evidence.exit)?,
        custody.bytes(&evidence.invocation)?,
        custody.bytes(&evidence.stdout)?,
        custody.bytes(&evidence.stderr)?,
        &agent.installed_sha256,
    )?;
    let arguments = serde_json::json!([
        "package",
        "policy",
        "image",
        "install",
        "--definition",
        submitted_path,
        "--source-root",
        source_root,
        "--json"
    ]);
    if command["identity"] != owner["identity"]
        || command["cell"] != owner["cell"]
        || command["lease_id"] != evidence.lease_id
        || command["scenario"] != *scenario
        || command["cwd"] != format!("{output}/{scenario}")
        || command["argv"] != arguments
        || command["definition_sha256"] != custody.hash(&evidence.definition)?
        || command["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || command["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || row["native_exit"] != status
    {
        return Err("image importer native operands cross actual source/intent".into());
    }
    let installation = |bytes: &[u8], image: &Value| -> VerificationResult<()> {
        let value = crate::wire::json(bytes)?;
        closed(
            &value,
            &[
                "format",
                "revision",
                "image",
                "target",
                "policy_activated",
                "member_count",
            ],
        )?;
        if value["format"] != "memcordon.runtime-image-installation"
            || value["revision"] != 1
            || value["image"]
                != crate::linux_build::linux_image_reference(image, &record.key.target)?
            || value["target"] != record.key.target
            || value["policy_activated"] != false
            || value["member_count"].as_u64()
                != image["entries"]
                    .as_array()
                    .map(|entries| entries.len() as u64)
        {
            return Err(
                "native image installation readback differs from exact imported definition".into(),
            );
        }
        Ok(())
    };
    let neighbor = decode(&evidence.neighbor_definition)?;
    if neighbor["image_id"]
        != owned_image_id(
            &owner["identity"],
            &owner["cell"],
            &evidence.lease_id,
            "neighbor-import",
        )?
    {
        return Err("neighbor setup image ID crosses original finite owner".into());
    }
    let neighbor_command = decode(&evidence.neighbor_invocation)?;
    if validate_linux_image_command(
        &neighbor_command,
        &decode(&evidence.neighbor_native_process)?,
        custody.bytes(&evidence.neighbor_native_creation)?,
        &decode(&evidence.neighbor_exit)?,
        custody.bytes(&evidence.neighbor_invocation)?,
        custody.bytes(&evidence.neighbor_stdout)?,
        custody.bytes(&evidence.neighbor_stderr)?,
        &agent.installed_sha256,
    )? != 0
        || neighbor_command["identity"] != owner["identity"]
        || neighbor_command["cell"] != owner["cell"]
        || neighbor_command["lease_id"] != evidence.lease_id
        || neighbor_command["scenario"] != "neighbor-import"
        || neighbor_command["definition_sha256"] != custody.hash(&evidence.neighbor_definition)?
    {
        return Err("negative image setup lacks neighboring actual successful import".into());
    }
    if neighbor_command["argv"]
        != serde_json::json!([
            "package",
            "policy",
            "image",
            "install",
            "--definition",
            format!("{image_admin}/neighbor-import/definition.json"),
            "--source-root",
            format!("{image_admin}/neighbor-import/source"),
            "--json"
        ])
        || neighbor_command["cwd"] != format!("{output}/neighbor-import")
        || neighbor_command["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || neighbor_command["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || neighbor["image_id"] == definition["image_id"]
    {
        return Err(
            "neighbor import command/image crosses original independent setup scope".into(),
        );
    }
    installation(custody.bytes(&evidence.neighbor_stdout)?, &neighbor)?;
    let mut neighbor_baseline = inventory["baseline_definition"].clone();
    neighbor_baseline["image_id"] = neighbor["image_id"].clone();
    if neighbor_baseline != neighbor {
        return Err("neighbor import is not exact unmutated candidate image".into());
    }
    let loader = matches!(scenario.as_str(), "loader-config" | "rpath-injection");
    if loader {
        if status != 0 {
            return Err("loader probe did not reach actual imported closure".into());
        }
        installation(custody.bytes(&evidence.stdout)?, &definition)?;
    } else {
        let cause = match scenario.as_str() {
            "writable-alias" => "image member type/size/mode/alias differs",
            "ld-injection" => "unsafe or duplicate trusted-startup environment",
            _ => "image content digest differs",
        };
        let error = std::str::from_utf8(custody.bytes(&evidence.stderr)?)
            .map_err(|error| error.to_string())?;
        if status == 0
            || !custody.bytes(&evidence.stdout)?.is_empty()
            || error.lines().count() != 1
            || !error.trim_end().ends_with(cause)
        {
            return Err(
                "native import failed at unrelated setup or accepted intended image mutation"
                    .into(),
            );
        }
    }
    let retired = decode(&evidence.retirement)?;
    let fields = if retired["already_absent"] == true {
        vec![
            "format",
            "revision",
            "reference",
            "storage_absent",
            "already_absent",
        ]
    } else {
        vec![
            "format",
            "revision",
            "reference",
            "storage_absent",
            "device",
            "inode",
        ]
    };
    closed(&retired, &fields)?;
    if retired["format"] != "memcordon.runtime-image-retirement"
        || retired["revision"] != 1
        || retired["reference"] != cleanup_reference
        || retired["storage_absent"] != true
        || decode(&evidence.retirement_exit)? != serde_json::json!({"native_exit":0,"success":true})
        || !custody.bytes(&evidence.retirement_stderr)?.is_empty()
    {
        return Err("image actual retirement differs from exact retained cleanup owner".into());
    }
    if loader {
        verify_preparation(
            record,
            evidence,
            product,
            &owner,
            &definition,
            checkpoint,
            cli,
            custody,
        )?;
    } else if evidence.preparation.is_some() || !row["preparation_probe"].is_null() {
        return Err("import rejection invents unrelated preparation authority".into());
    }
    Ok(())
}

pub(crate) fn owned_empty_plan_digest(contract: &Value) -> VerificationResult<String> {
    if contract["requirements"] != serde_json::json!([]) {
        return Err("owned closure-only plan cannot digest undeclared socket requirements".into());
    }
    owned_plan_digest(contract)
}

pub(crate) fn owned_plan_digest(contract: &Value) -> VerificationResult<String> {
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        id: String,
        digest: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Execution {
        identity: Reference,
        exclusive_use_policy: Reference,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum Requirement {
        UnixPathStream { id: String, writable_root: String },
    }
    let reference = |field: &str| -> VerificationResult<Reference> {
        let value: Reference =
            serde_json::from_value(contract[field].clone()).map_err(|error| error.to_string())?;
        crate::identifier(&value.id)?;
        crate::digest(&value.digest)?;
        Ok(value)
    };
    let execution: Execution = serde_json::from_value(contract["execution_identity"].clone())
        .map_err(|error| error.to_string())?;
    for value in [&execution.identity, &execution.exclusive_use_policy] {
        crate::identifier(&value.id)?;
        crate::digest(&value.digest)?;
    }
    let requirements: Vec<Requirement> = serde_json::from_value(contract["requirements"].clone())
        .map_err(|error| error.to_string())?;
    if requirements.len() > 1 {
        return Err("owned export socket requirement count exceeds finite actual recipe".into());
    }
    for requirement in &requirements {
        match requirement {
            Requirement::UnixPathStream { id, writable_root } => {
                if id != "pathname" || writable_root != "work" {
                    return Err(
                        "owned export socket requirement differs from original finite recipe"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(crate::sha256(
        &serde_json::to_vec(&(
            reference("runtime_image")?,
            reference("input_image")?,
            reference("root_layout")?,
            execution,
            requirements,
        ))
        .map_err(|error| error.to_string())?,
    ))
}

pub(crate) fn owned_exclusive_declaration_reference(
    identity: &Value,
    cell: &Value,
    account: &Value,
) -> VerificationResult<Value> {
    let declaration = serde_json::json!({"format":"memcordon.owned-readiness-exclusive-use-declaration","revision":1,"run_id":identity["run_id"],"cell":cell,"account":account["name"],"uid":account["uid"],"gid":account["gid"],"purpose":"exclusive installed readiness attempt identity; no unrelated login or workload"});
    Ok(
        serde_json::json!({"id":"owned-exclusive-use","digest":crate::sha256(&serde_json::to_vec(&declaration).map_err(|error|error.to_string())?)}),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Compare selected image bytes with independent command, creation, exit and custody evidence"
)]
fn verify_preparation(
    record: &crate::CaseRecord,
    evidence: &LinuxImageImportEvidence,
    product: &crate::ProductObservation,
    owner: &Value,
    definition: &Value,
    checkpoint: &Value,
    cli: &crate::Component,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    let probe = evidence
        .preparation
        .as_ref()
        .ok_or("valid imported loader candidate lacks actual preparation attempt")?;
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let receipt = decode(&probe.receipt)?;
    closed(
        &receipt,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "scenario",
            "activation",
            "contract",
            "protected_contract",
            "contract_sha256",
            "provider_request",
            "result",
            "native_census",
            "frontend_invocation",
            "frontend_wait",
            "raw_result",
        ],
    )?;
    if receipt["format"] != "memcordon.linux-image-loader-preparation-probe"
        || receipt["revision"] != 1
        || receipt["identity"] != owner["identity"]
        || receipt["cell"] != owner["cell"]
        || receipt["lease_id"] != evidence.lease_id
        || receipt["scenario"] != record.key.scenario
        || receipt["contract_sha256"] != custody.hash(&probe.contract)?
        || receipt["raw_result"] != decode(&probe.result)?
    {
        return Err(
            "loader native preparation record crosses exact original owner/captured result".into(),
        );
    }
    let policy = decode(&probe.policy)?;
    let contract = decode(&probe.contract)?;
    let activation = decode(&probe.activation)?;
    if crate::linux_policy::activation_registry(&activation)? != &policy
        || activation["registry_digest"]
            != crate::linux_registry_digest(&policy, &record.key.target)?
        || contract["expected_epoch"] != activation["epoch"]
        || contract["runtime_image"]
            != crate::linux_build::linux_image_reference(definition, &record.key.target)?
    {
        return Err("loader preparation does not activate exact altered runtime image".into());
    }
    if policy["legacy"] != checkpoint["legacy"]
        || policy["execution_identities"]
            .as_array()
            .is_none_or(|rows| {
                rows.len() != 1
                    || rows[0]["uid"] != owner["account"]["uid"]
                    || rows[0]["gid"] != owner["account"]["gid"]
                    || rows[0]["enabled"] != true
            })
        || policy["root_layouts"].as_array().is_none_or(|rows| {
            rows.len() != 1 || rows[0]["runtime_image"] != contract["runtime_image"]
        })
        || contract["requirements"] != serde_json::json!([])
    {
        return Err("loader preparation crosses acquired identity or closure-only layout".into());
    }
    let input_reference = crate::linux_build::linux_image_reference(
        &checkpoint["images"]["input"],
        &record.key.target,
    )?;
    let execution = &policy["execution_identities"][0];
    let layout = &policy["root_layouts"][0];
    let identity_reference = crate::linux_registry::linux_identity_reference(execution)?;
    let layout_reference = crate::linux_registry::linux_root_layout_reference(layout)?;
    let exclusive = owned_exclusive_declaration_reference(
        &owner["identity"],
        &owner["cell"],
        &owner["account"],
    )?;
    let images = policy["images"]
        .as_array()
        .ok_or("loader original image catalogue absent")?;
    let grants = policy["grants"]
        .as_array()
        .ok_or("loader exact grant absent")?;
    if contract["input_image"] != input_reference
        || contract["execution_identity"]
            != serde_json::json!({"identity":identity_reference,"exclusive_use_policy":exclusive})
        || execution["identity_id"] != "owned-readiness-identity"
        || execution["supplementary_groups"] != serde_json::json!([])
        || execution["reservation_key"] != "owned-readiness-reservation"
        || execution["exclusive_use_policy"] != exclusive
        || contract["root_layout"] != layout_reference
        || layout["layout_id"] != "owned-readiness-root"
        || layout["runtime_image"] != contract["runtime_image"]
        || layout["input_image"] != input_reference
        || layout["writable_roots"]
            != serde_json::json!([{"id":"work","path":"work","byte_limit":16u64*1024*1024*1024,"generated_execution":true}])
        || layout["output_files"] != serde_json::json!([])
        || images.len() != 2
        || !images.contains(definition)
        || !images.contains(&checkpoint["images"]["input"])
        || grants.len() != 1
        || grants[0]["id"] != contract["authorization"]["grant_id"]
        || grants[0]["revision"] != contract["authorization"]["grant_revision"]
        || grants[0]["enabled"] != true
        || grants[0]["callers"] != serde_json::json!([{"platform":"linux","uid":65534}])
        || grants[0]["approved_plans"] != serde_json::json!([contract["workload_plan_digest"]])
        || grants[0]["profile"] != contract["authorized_profile"]
        || [
            "execution_identity",
            "runtime_image",
            "input_image",
            "root_layout",
        ]
        .iter()
        .any(|field| grants[0][*field] != contract[*field])
        || contract["launch"]
            != serde_json::json!({"entrypoint":"owned-readiness","working_directory":"work"})
        || policy["active_attempt_disposition"] != "drain-existing"
        || contract["authorized_profile"]
            != crate::linux_registry::linux_combined_profile_reference()
        || contract["workload_plan_digest"] != owned_empty_plan_digest(&contract)?
        || contract["authorization"]["approved_plan_digest"] != contract["workload_plan_digest"]
    {
        return Err("loader request/activated grant/catalogue/layout/exclusive identity crosses original acquired objects".into());
    }
    let command = &receipt["frontend_invocation"];
    closed(
        command,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "environment_cleared",
            "caller_uid",
            "caller_gid",
            "selected_cli_sha256",
        ],
    )?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    let program: Vec<u8> =
        serde_json::from_value(command["program"].clone()).map_err(|error| error.to_string())?;
    if command["format"] != "memcordon.linux-owned-frontend-invocation"
        || command["revision"] != 1
        || program != b"/usr/bin/setpriv"
        || command["environment_cleared"] != true
        || command["caller_uid"] != 65534
        || command["caller_gid"] != 65534
        || command["selected_cli_sha256"] != cli.installed_sha256
        || arguments.len() != 24
    {
        return Err("loader actual frontend native command differs".into());
    }
    for (index, text) in [
        (0, "--reuid"),
        (1, "65534"),
        (2, "--regid"),
        (3, "65534"),
        (4, "--clear-groups"),
        (5, "--"),
        (6, "/usr/libexec/memcordon"),
        (7, "+512M"),
        (9, "--sealed"),
        (10, "--workload-contract"),
        (12, "--report-format"),
        (13, "result-v2"),
        (14, "--report"),
        (16, "--mixed-observation-directory"),
        (18, "--image-entrypoint"),
        (19, "owned-readiness"),
        (20, "--"),
        (21, "bytes-argv-status"),
        (22, "0"),
        (23, "loader-closure-probe"),
    ] {
        if arguments[index] != text.as_bytes() {
            return Err("loader preparation invoked unrelated work".into());
        }
    }
    for (index, field) in [(11, "contract"), (15, "result")] {
        if arguments[index]
            != receipt[field]
                .as_str()
                .ok_or("loader actual frontend path absent")?
                .as_bytes()
        {
            return Err("loader actual native frontend file operands differ".into());
        }
    }
    let result_parent = crate::linux_path::parent(
        receipt["result"]
            .as_str()
            .ok_or("loader result path absent")?,
    )
    .ok_or("loader result parent absent")?;
    if arguments[17] != crate::linux_path::join(&result_parent, "observations").as_bytes() {
        return Err("loader actual frontend observation scope differs".into());
    }
    let deadline = std::str::from_utf8(&arguments[8]).map_err(|_| "loader deadline is not UTF8")?;
    let budget = deadline
        .strip_prefix('+')
        .and_then(|text| text.strip_suffix("ms"))
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|budget| *budget > 0 && *budget <= 60_000)
        .ok_or("loader original deadline token invalid")?;
    if deadline != format!("+{budget}ms") {
        return Err("loader native deadline not canonical".into());
    }
    let public_argv = [
        "owned-readiness",
        "bytes-argv-status",
        "0",
        "loader-closure-probe",
    ]
    .into_iter()
    .map(|text| serde_json::json!({"display":text,"raw":null}))
    .collect::<Vec<_>>();
    let public = serde_json::json!({"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+512M"},{"kind":"time","token":deadline}],
        "memory_token":"+512M","deadline_token":deadline,"argv":public_argv});
    let wait = &receipt["frontend_wait"];
    closed(
        wait,
        &[
            "format",
            "revision",
            "process_id",
            "process_birth",
            "raw_wait_status",
            "native_exit",
            "signal",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    let pid = wait["process_id"]
        .as_u64()
        .filter(|pid| *pid > 0 && *pid <= u64::from(u32::MAX))
        .ok_or("loader actual frontend PID absent")? as u32;
    let status = wait["native_exit"]
        .as_i64()
        .filter(|status| (1..=255).contains(status))
        .ok_or("loader frontend did not exit with native rejection")? as i32;
    if wait["format"] != "memcordon.linux-policy-frontend-exit"
        || wait["revision"] != 1
        || wait["process_birth"]
            .as_u64()
            .filter(|birth| *birth > 0)
            .is_none()
        || !wait["signal"].is_null()
        || wait["raw_wait_status"] != status * 256
        || wait["invocation_sha256"]
            != crate::sha256(&serde_json::to_vec(command).map_err(|error| error.to_string())?)
        || wait["stdout_sha256"] != custody.hash(&probe.stdout)?
        || wait["stderr_sha256"] != custody.hash(&probe.stderr)?
    {
        return Err(
            "loader actual frontend wait/capture differs from original native command".into(),
        );
    }
    let result = decode(&probe.result)?;
    crate::validate_linux_policy_refusal_result(
        &result,
        custody.bytes(&probe.provider_request)?,
        &contract,
        &public,
        &product.version,
        &record.key.target,
        status,
        pid,
        "image-custody-mismatch",
    )?;
    let detail = if record.key.scenario == "loader-config" {
        "ELF loader configuration is outside the approved immutable library catalogue"
    } else {
        "ELF loader search directory is outside approved immutable search catalogue"
    };
    if result["runtime"]["outcome"]["detail"] != detail {
        return Err(
            "loader native rejection did not reach intended protected closure point".into(),
        );
    }
    let census = decode(&probe.native_census)?;
    let attempt = probe
        .provider_request
        .rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".provider-request.bin"))
        .ok_or("loader original request native attempt basename absent")?;
    crate::validate_linux_refusal_census(
        &census,
        &owner["identity"],
        &owner["cell"],
        &evidence.lease_id,
        &record.key.scenario,
        &owner["account"],
        &owner["provider"],
        custody.hash(&probe.provider_request)?,
        custody.hash(&probe.result)?,
        attempt,
    )?;
    Ok(())
}
