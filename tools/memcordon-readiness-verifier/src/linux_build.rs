use crate::{HeldProcessIdentity, VerificationResult};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn linux_image_reference(image: &Value, target: &str) -> VerificationResult<Value> {
    fields(
        image,
        &[
            "format",
            "revision",
            "image_id",
            "target",
            "entries",
            "entrypoints",
            "library_directories",
            "startup_environment",
        ],
    )?;
    if image["format"] != "memcordon.runtime-image"
        || image["revision"] != 1
        || image["target"] != target
    {
        return Err("measured Linux build image format/native target differs".into());
    }
    fn count(output: &mut Vec<u8>, value: usize) -> VerificationResult<()> {
        output.extend(
            u16::try_from(value)
                .map_err(|_| "image count exceeds canonical bound")?
                .to_be_bytes(),
        );
        Ok(())
    }
    fn text(output: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
        let value = value.as_str().ok_or("image canonical text absent")?;
        if value.contains('\0') {
            return Err("image canonical text contains NUL".into());
        }
        count(output, value.len())?;
        output.extend(value.as_bytes());
        Ok(())
    }
    fn relative(value: &Value) -> VerificationResult<()> {
        let path = value.as_str().ok_or("image relative path absent")?;
        if path.is_empty()
            || path.starts_with('/')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("image path is not confined".into());
        }
        Ok(())
    }
    let mut bytes = b"memcordon.runtime-image/version1\0\0\x01".to_vec();
    text(&mut bytes, &image["image_id"])?;
    text(&mut bytes, &image["target"])?;
    let mut entries = image["entries"]
        .as_array()
        .filter(|entries| !entries.is_empty() && entries.len() <= 16384)
        .ok_or("image entries empty/unbounded")?
        .iter()
        .collect::<Vec<_>>();
    for entry in &entries {
        relative(&entry["path"])?;
    }
    entries.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let by_path = entries
        .iter()
        .map(|entry| (entry["path"].as_str().expect("validated path"), *entry))
        .collect::<BTreeMap<_, _>>();
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    count(&mut bytes, entries.len())?;
    for entry in entries {
        if !paths.insert(entry["path"].as_str().expect("validated path")) {
            return Err("image path duplicated".into());
        }
        text(&mut bytes, &entry["path"])?;
        let path = entry["path"].as_str().expect("validated path");
        let mut parent = std::path::Path::new(path).parent();
        while let Some(path) = parent {
            if path.to_str().is_some_and(|path| by_path.contains_key(path)) {
                return Err("image member aliases ancestor directory".into());
            }
            parent = path.parent();
        }
        match entry["kind"].as_str() {
            Some("regular") => {
                fields(entry, &["kind", "path", "sha256", "size", "executable"])?;
                bytes.push(1);
                let digest = entry["sha256"]
                    .as_str()
                    .ok_or("image file measurement absent")?;
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err("image file digest malformed".into());
                }
                bytes.extend(hex::decode(digest).map_err(|error| error.to_string())?);
                let size = entry["size"]
                    .as_u64()
                    .filter(|size| *size <= 1024 * 1024 * 1024)
                    .ok_or("image file size exceeds bound")?;
                total = total
                    .checked_add(size)
                    .filter(|total| *total <= 16 * 1024 * 1024 * 1024)
                    .ok_or("image total bytes exceed bound")?;
                bytes.extend(size.to_be_bytes());
                bytes.push(u8::from(
                    entry["executable"]
                        .as_bool()
                        .ok_or("image executable mode absent")?,
                ));
            }
            Some("symlink") => {
                fields(entry, &["kind", "path", "target"])?;
                relative(&entry["target"])?;
                let mut next = entry["target"].as_str().expect("validated target");
                let mut visited = BTreeSet::from([path]);
                loop {
                    if !visited.insert(next) {
                        return Err("image symbolic link cycle".into());
                    }
                    let item = by_path
                        .get(next)
                        .ok_or("image symbolic link target absent")?;
                    match item["kind"].as_str() {
                        Some("regular") => break,
                        Some("symlink") => {
                            next = item["target"]
                                .as_str()
                                .ok_or("image symbolic link target malformed")?
                        }
                        _ => return Err("image symbolic target kind unsupported".into()),
                    }
                }
                bytes.push(2);
                text(&mut bytes, &entry["target"])?;
            }
            _ => return Err("image member kind unsupported".into()),
        }
    }
    let mut entrypoints = image["entrypoints"]
        .as_array()
        .filter(|items| items.len() <= 16)
        .ok_or("image entrypoint bound differs")?
        .iter()
        .collect::<Vec<_>>();
    entrypoints.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    count(&mut bytes, entrypoints.len())?;
    let mut ids = BTreeSet::new();
    for item in entrypoints {
        fields(item, &["id", "path"])?;
        relative(&item["path"])?;
        if !ids.insert(item["id"].as_str().ok_or("image entrypoint ID absent")?) {
            return Err("image entrypoint duplicated".into());
        }
        let selected = by_path
            .get(item["path"].as_str().expect("validated path"))
            .ok_or("image entrypoint absent")?;
        if selected["kind"] != "regular" || selected["executable"] != true {
            return Err("image entrypoint is not a native executable regular member".into());
        }
        text(&mut bytes, &item["id"])?;
        text(&mut bytes, &item["path"])?;
    }
    let directories = image["library_directories"]
        .as_array()
        .filter(|items| items.len() <= 32)
        .ok_or("image library path bound differs")?;
    count(&mut bytes, directories.len())?;
    for path in directories {
        relative(path)?;
        text(&mut bytes, path)?;
    }
    let mut variables = image["startup_environment"]
        .as_array()
        .filter(|items| items.len() <= 32)
        .ok_or("image startup environment bound differs")?
        .iter()
        .collect::<Vec<_>>();
    variables.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    count(&mut bytes, variables.len())?;
    let mut names = BTreeSet::new();
    for variable in variables {
        fields(variable, &["name", "value"])?;
        let name = variable["name"]
            .as_str()
            .ok_or("image startup name absent")?;
        let value = variable["value"]
            .as_str()
            .ok_or("image startup value absent")?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || value.len() > 4096
            || name.starts_with("LD_")
            || name.starts_with("DYLD_")
            || [
                "GLIBC_TUNABLES",
                "GCONV_PATH",
                "LOCPATH",
                "LIBRARY_PATH",
                "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER",
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
            ]
            .contains(&name)
            || !names.insert(name)
        {
            return Err("image startup variable unsafe/duplicated".into());
        }
        text(&mut bytes, &variable["name"])?;
        text(&mut bytes, &variable["value"])?;
    }
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("image canonical bytes exceed bound".into());
    }
    Ok(serde_json::json!({"id":image["image_id"],"digest":hex::encode(Sha256::digest(&bytes))}))
}

fn fields(value: &Value, names: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != names.len() || object.keys().any(|name| !names.contains(&name.as_str()))
    }) {
        return Err("Linux build native receipt fields differ".into());
    }
    Ok(())
}
fn number(value: &Value, name: &str) -> VerificationResult<u64> {
    value[name]
        .as_u64()
        .filter(|number| *number != 0)
        .ok_or_else(|| format!("Linux build {name} absent/zero"))
}

/// Validates fixture-owned creation/wait facts only when the separate
/// controller held the complete native ancestry before releasing the child.
pub fn validate_linux_generated_lifecycle(
    created: &Value,
    retired: &Value,
    compiler: &Value,
    generated: &Value,
    target: &Value,
    held: &[HeldProcessIdentity],
    root: (u32, u64),
    attempt: &str,
    challenge: &[u8],
    target_name: &str,
    executable: &[u8],
) -> VerificationResult<()> {
    fields(
        created,
        &[
            "format",
            "revision",
            "challenge",
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "compiler_pid",
            "compiler_birth",
            "image_device",
            "image_inode",
            "program",
            "output",
            "creation_owner_retained",
            "ready_before_release",
        ],
    )?;
    fields(
        retired,
        &[
            "format",
            "revision",
            "challenge",
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "native_wait_status",
            "same_creation_owner_waited",
        ],
    )?;
    let token = hex::encode(challenge);
    if challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || created["format"] != "memcordon.linux-generated-child-created"
        || created["revision"] != 1
        || retired["format"] != "memcordon.linux-generated-child-retired"
        || retired["revision"] != 1
        || created["challenge"] != token
        || retired["challenge"] != token
        || created["program"] != "/work/generated-child-executable.bin"
        || created["output"] != "/work/generated-readiness-artifact.bin"
        || created["creation_owner_retained"] != true
        || created["ready_before_release"] != true
        || retired["same_creation_owner_waited"] != true
        || retired["native_wait_status"] != 0
    {
        return Err(
            "Linux generated effect lacks exact creation/gated native wait association".into(),
        );
    }
    for field in ["pid", "birth", "parent_pid", "parent_birth"] {
        if created[field] != retired[field] {
            return Err("Linux generated native creation/wait identity changed".into());
        }
        number(created, field)?;
    }
    validate_linux_generated_build(
        created,
        compiler,
        generated,
        target,
        held,
        root,
        attempt,
        challenge,
        target_name,
        executable,
    )
}

/// Physical held compiler/child proof is also required when an actual limit
/// terminates the child before it can emit its natural-exit receipt.
pub(crate) fn validate_linux_generated_build(
    created: &Value,
    compiler: &Value,
    generated: &Value,
    target: &Value,
    held: &[HeldProcessIdentity],
    root: (u32, u64),
    attempt: &str,
    challenge: &[u8],
    target_name: &str,
    executable: &[u8],
) -> VerificationResult<()> {
    fields(
        created,
        &[
            "format",
            "revision",
            "challenge",
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "compiler_pid",
            "compiler_birth",
            "image_device",
            "image_inode",
            "program",
            "output",
            "creation_owner_retained",
            "ready_before_release",
        ],
    )?;
    let token = hex::encode(challenge);
    if challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || created["format"] != "memcordon.linux-generated-child-created"
        || created["revision"] != 1
        || created["challenge"] != token
        || created["program"] != "/work/generated-child-executable.bin"
        || created["output"] != "/work/generated-readiness-artifact.bin"
        || created["creation_owner_retained"] != true
        || created["ready_before_release"] != true
    {
        return Err("Linux generated build lacks original held creation receipt".into());
    }
    number(created, "image_device")?;
    number(created, "image_inode")?;
    let machine = match target_name {
        "x86_64-unknown-linux-gnu" => 62,
        "aarch64-unknown-linux-gnu" => 183,
        _ => return Err("Linux generated native target unsupported".into()),
    };
    if executable.len() < 20
        || &executable[..4] != b"\x7fELF"
        || executable[4] != 2
        || executable[5] != 1
        || u16::from_le_bytes([executable[18], executable[19]]) != machine
    {
        return Err("generated executable is not selected native ELF".into());
    }
    let expected = [
        (
            number(created, "compiler_pid")?,
            number(created, "compiler_birth")?,
        ),
        (
            number(created, "parent_pid")?,
            number(created, "parent_birth")?,
        ),
        (number(created, "pid")?, number(created, "birth")?),
    ];
    if expected.iter().copied().collect::<BTreeSet<_>>().len() != 3
        || expected[0].1 > expected[1].1
        || expected[1].1 > expected[2].1
    {
        return Err("generated compiler/test/child identities alias or birth order differs".into());
    }
    let final_held = held
        .iter()
        .map(|process| ((u64::from(process.pid), process.birth), process))
        .collect::<BTreeMap<_, _>>();
    if final_held.len() != held.len() {
        return Err("Linux final native family duplicated".into());
    }
    let mut previous = root;
    let mut actual_chain = Vec::new();
    for (barrier, stage, count) in [
        (compiler, "offline-compiler-held", 1),
        (generated, "joint-generated-child-held", 3),
    ] {
        fields(
            barrier,
            &[
                "format",
                "revision",
                "stage",
                "challenge",
                "attempt_id",
                "root_pid",
                "root_birth",
                "members",
            ],
        )?;
        if barrier["format"] != "memcordon.linux-native-build-barrier"
            || barrier["revision"] != 1
            || barrier["stage"] != stage
            || barrier["challenge"] != token
            || barrier["attempt_id"] != attempt
            || barrier["root_pid"] != root.0
            || barrier["root_birth"] != root.1
        {
            return Err("Linux independent build barrier binding changed".into());
        }
        let members = barrier["members"]
            .as_array()
            .filter(|members| members.len() == count)
            .ok_or("Linux independent build barrier cardinality differs")?;
        let mut observed = BTreeMap::new();
        for member in members {
            fields(member, &["native", "identity", "executable"])?;
            fields(
                &member["executable"],
                &["device", "inode", "length", "sha256"],
            )?;
            number(&member["executable"], "inode")?;
            let snapshot = &member["native"];
            fields(
                snapshot,
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
            let identity: HeldProcessIdentity = serde_json::from_value(member["identity"].clone())
                .map_err(|error| error.to_string())?;
            let native_pair = (u64::from(identity.pid), identity.birth);
            if identity.retirement_observed
                || snapshot["process_id"] != identity.pid
                || snapshot["birth"] != identity.birth
            {
                return Err("build barrier substituted an exited or different native owner".into());
            }
            let pids = snapshot["namespace_pids"]
                .as_array()
                .filter(|pids| !pids.is_empty() && pids.len() <= 32)
                .ok_or("build namespace mapping absent/unbounded")?;
            if pids.first().and_then(Value::as_u64) != Some(native_pair.0)
                || pids.iter().any(|pid| {
                    pid.as_u64()
                        .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
                })
            {
                return Err("build namespace mapping is not actual held host identity".into());
            }
            let local = (
                pids.last().and_then(Value::as_u64).expect("validated PID"),
                identity.birth,
            );
            if stage == "joint-generated-child-held"
                && local == expected[2]
                && (member["executable"]["device"] != created["image_device"]
                    || member["executable"]["inode"] != created["image_inode"]
                    || member["executable"]["length"] != executable.len() as u64
                    || member["executable"]["sha256"] != hex::encode(Sha256::digest(executable)))
            {
                return Err("generated executable fixture inode/bytes differ from independently held kernel image".into());
            }
            if observed.insert(local, identity).is_some() {
                return Err("build barrier duplicates local native member".into());
            }
            for namespace in ["user", "mount", "pid", "network", "ipc"] {
                fields(&snapshot[namespace], &["device", "inode"])?;
                number(&snapshot[namespace], "inode")?;
                if snapshot[namespace] != target[namespace] {
                    return Err("generated native member escaped prepared namespace".into());
                }
            }
            let final_identity = final_held
                .get(&native_pair)
                .ok_or("held live build member missing from final native family")?;
            let live = observed.get(&local).expect("inserted member");
            if !final_identity.retirement_observed
                || final_identity.parent_pid != live.parent_pid
                || final_identity.parent_birth != live.parent_birth
            {
                return Err("build native retirement/ancestry changed after held barrier".into());
            }
        }
        for (ordinal, local) in expected.iter().take(count).enumerate() {
            let member = observed
                .get(local)
                .ok_or("created compiler/test/child missing from actual native controller hold")?;
            if member.parent_pid != Some(previous.0) || member.parent_birth != Some(previous.1) {
                return Err(
                    "generated native parent edge is not the held compiler/test ancestry".into(),
                );
            }
            if stage == "joint-generated-child-held" {
                actual_chain.push((member.pid, member.birth));
            }
            previous = (member.pid, member.birth);
            if stage == "offline-compiler-held" && ordinal == 0 {
                previous = root;
            }
        }
    }
    if actual_chain.len() != 3 {
        return Err("complete generated native ancestry absent".into());
    }
    Ok(())
}
