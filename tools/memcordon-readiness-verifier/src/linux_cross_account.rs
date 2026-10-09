//! Independent custody of the finite secondary account used by the live peer.
use crate::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) {
        return Err("cross account original schema differs".into());
    }
    Ok(())
}
fn path<'a>(canary: &'a Value, field: &str) -> VerificationResult<&'a str> {
    canary[field]
        .as_str()
        .ok_or_else(|| format!("cross original account artifact absent: {field}"))
}
#[derive(Serialize)]
struct Identity<'a> {
    run_id: &'a str,
    source_commit: &'a str,
    source_tree_sha256: &'a str,
    version: &'a str,
}

pub(crate) fn validate_creation(
    canary: &Value,
    index: &EvidenceIndex,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let run_id = canary["run_id"]
        .as_str()
        .ok_or("cross original run absent")?;
    let identity = Identity {
        run_id,
        source_commit: &index.source_commit,
        source_tree_sha256: &index.source_tree_sha256,
        version: &index.version,
    };
    let cell = ProductKey {
        target: key.target.clone(),
        channel: key.channel.clone().ok_or("cross original channel absent")?,
    };
    let discriminator = Sha256::digest(
        serde_json::to_vec(&(&identity, &cell, "other-attempt-abstract-peer"))
            .map_err(|error| error.to_string())?,
    );
    let number = u64::from_le_bytes(
        discriminator[..8]
            .try_into()
            .map_err(|_| "cross discriminator width")?,
    );
    let name = format!("mc-ready-{number:x}");
    let account = &canary["peer_account"];
    closed(
        account,
        &[
            "name",
            "uid",
            "gid",
            "intent",
            "native_readback",
            "group_readback",
        ],
    )?;
    let uid = account["uid"]
        .as_u64()
        .filter(|uid| *uid > 0 && *uid <= u32::MAX as u64 && ![65533, 65534].contains(uid))
        .ok_or("cross original secondary UID absent/aliases frozen owner or frontend")?;
    let gid = account["gid"]
        .as_u64()
        .filter(|gid| *gid > 0 && *gid <= u32::MAX as u64 && ![65533, 65534].contains(gid))
        .ok_or("cross original secondary GID absent/aliases frozen owner or frontend")?;
    if account["name"] != name {
        return Err("cross secondary account discriminator differs".into());
    }
    let intent_path = path(canary, "peer_account_intent")?;
    let intent = crate::wire::json(custody.bytes(intent_path)?)?;
    closed(
        &intent,
        &[
            "format",
            "revision",
            "run_id",
            "cell",
            "account_name",
            "native_absence_verified",
            "creation_attempted",
            "purpose",
        ],
    )?;
    if intent["format"] != "memcordon.owned-readiness-account-intent"
        || intent["revision"] != 2
        || intent["run_id"] != run_id
        || intent["cell"] != serde_json::to_value(&cell).map_err(|error| error.to_string())?
        || intent["account_name"] != name
        || intent["purpose"] != "other-attempt-abstract-peer"
        || intent["native_absence_verified"] != true
        || intent["creation_attempted"] != true
    {
        return Err("cross secondary original purpose intent differs".into());
    }
    let original_parent = crate::linux_path::parent(
        account["intent"]
            .as_str()
            .ok_or("cross original account intent path absent")?,
    )
    .ok_or("cross original account directory absent")?;
    for (field, leaf) in [
        ("intent", "exclusive-account-intent.json"),
        ("native_readback", "exclusive-account-getent.bin"),
        ("group_readback", "exclusive-group-getent.bin"),
    ] {
        if !crate::linux_path::equivalent(
            account[field]
                .as_str()
                .ok_or("cross original account source path absent")?,
            &crate::linux_path::join(&original_parent, leaf),
        ) {
            return Err("cross original secondary source paths differ".into());
        }
    }
    for (field, database) in [
        ("peer_account_passwd", "passwd"),
        ("peer_account_group", "group"),
    ] {
        let raw = custody.bytes(path(canary, field)?)?;
        if raw.len() > 4096 {
            return Err("cross original secondary native lookup unbounded".into());
        }
        let text = std::str::from_utf8(raw).map_err(|error| error.to_string())?;
        let rows = text.lines().collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err("cross original secondary lookup population differs".into());
        }
        let values = rows[0].split(':').collect::<Vec<_>>();
        if database == "passwd" {
            if values.len() != 7
                || values[0] != name
                || values[2] != uid.to_string()
                || values[3] != gid.to_string()
                || values[6] != "/usr/sbin/nologin"
            {
                return Err("cross original secondary passwd identity differs".into());
            }
        } else if values.len() != 4
            || values[0] != name
            || values[2] != gid.to_string()
            || !values[3].is_empty()
        {
            return Err("cross original secondary group identity differs".into());
        }
    }
    let creation_path = path(canary, "peer_account_creation")?;
    let parent = creation_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .ok_or("cross account creation archive parent absent")?;
    let artifact = |leaf: &str| format!("{parent}/exclusive-account-useradd-{leaf}");
    if creation_path != artifact("creation.json")
        || intent_path != format!("{parent}/exclusive-account-intent.json")
        || path(canary, "peer_account_passwd")? != format!("{parent}/exclusive-account-getent.bin")
        || path(canary, "peer_account_group")? != format!("{parent}/exclusive-group-getent.bin")
    {
        return Err("cross native creation crosses original secondary acquisition".into());
    }
    let invocation_path = artifact("invocation.json");
    let invocation = crate::wire::json(custody.bytes(&invocation_path)?)?;
    let creation = crate::wire::json(custody.bytes(creation_path)?)?;
    let exit = crate::wire::json(custody.bytes(&artifact("exit.json"))?)?;
    closed(
        &invocation,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "purpose",
            "program",
            "program_sha256",
            "arguments",
            "cwd",
            "intent_sha256",
        ],
    )?;
    closed(
        &creation,
        &[
            "format",
            "revision",
            "process_id",
            "birth",
            "invocation_sha256",
            "kernel_image",
        ],
    )?;
    closed(
        &creation["kernel_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    closed(
        &exit,
        &[
            "format",
            "revision",
            "held",
            "raw_wait_status",
            "native_exit",
            "signal",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    let held: HeldProcessIdentity =
        serde_json::from_value(exit["held"].clone()).map_err(|error| error.to_string())?;
    let original_image = artifact("image.bin");
    if custody.bytes(&original_image)?.is_empty()
        || invocation["program_sha256"] != custody.hash(&original_image)?
        || creation["kernel_image"]["length"] != custody.bytes(&original_image)?.len()
    {
        return Err("cross original useradd native image bytes differ".into());
    }
    // This is retained Linux-native custody, independent of the verifier host.
    if !original_parent.starts_with('/')
        || original_parent
            .split('/')
            .any(|component| component == "..")
        || original_parent.contains('\0')
        || canary["held_peer"]["birth"]
            .as_u64()
            .is_none_or(|birth| birth < held.birth)
    {
        return Err("cross original native creation chronology/path differs".into());
    }
    if invocation["format"] != "memcordon.owned-readiness-account-creation-invocation"
        || invocation["revision"] != 1
        || invocation["identity"]
            != serde_json::to_value(&identity).map_err(|error| error.to_string())?
        || invocation["cell"] != serde_json::to_value(&cell).map_err(|error| error.to_string())?
        || invocation["purpose"] != "other-attempt-abstract-peer"
        || invocation["program"] != "/usr/sbin/useradd"
        || invocation["arguments"]
            != json!([
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "--user-group",
                "--",
                name
            ])
        || invocation["cwd"] != original_parent
        || invocation["intent_sha256"] != custody.hash(intent_path)?
        || creation["format"] != "memcordon.owned-readiness-account-creation"
        || creation["revision"] != 1
        || creation["process_id"].as_u64() != Some(held.pid as u64)
        || creation["birth"].as_u64() != Some(held.birth)
        || held.pid == 0
        || held.birth == 0
        || !held.retirement_observed
        || creation["invocation_sha256"] != custody.hash(&invocation_path)?
        || creation["kernel_image"]["sha256"] != invocation["program_sha256"]
        || ["device", "inode", "length"].iter().any(|field| {
            creation["kernel_image"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
        || exit["format"] != "memcordon.owned-readiness-account-creation-exit"
        || exit["revision"] != 1
        || exit["raw_wait_status"] != 0
        || exit["native_exit"] != 0
        || !exit["signal"].is_null()
        || exit["invocation_sha256"] != custody.hash(&invocation_path)?
        || exit["stdout_sha256"] != custody.hash(&artifact("stdout.bin"))?
        || exit["stderr_sha256"] != custody.hash(&artifact("stderr.bin"))?
    {
        return Err("cross original useradd Child/PIDFD/kernel image/wait/capture differs".into());
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Bind command custody to the independent account identity, cell, argv and native lifetime"
)]
fn command(
    bundle: &Value,
    parent: &str,
    original_cwd: &str,
    identity: &Value,
    cell: &Value,
    program: &str,
    args: &[String],
    peer_birth: u64,
    cleanup: u64,
    custody: &custody::Custody,
) -> VerificationResult<(u64, Vec<u8>)> {
    closed(
        bundle,
        &[
            "invocation",
            "image",
            "creation",
            "stdout",
            "stderr",
            "exit",
        ],
    )?;
    let reference = |field: &str| -> VerificationResult<String> {
        let leaf = bundle[field]
            .as_str()
            .ok_or("cross account native bundle leaf absent")?;
        if leaf.is_empty() || leaf.contains(['/', '\\', ':', '\0']) || leaf == "." || leaf == ".." {
            return Err("cross account bundle escapes original source directory".into());
        }
        Ok(format!("{parent}/{leaf}"))
    };
    let invocation_path = reference("invocation")?;
    let image_path = reference("image")?;
    let invocation = crate::wire::json(custody.bytes(&invocation_path)?)?;
    let stem = bundle["invocation"]
        .as_str()
        .and_then(|leaf| leaf.strip_suffix(".invocation.json"))
        .ok_or("cross original native command stem absent")?;
    for (field, suffix) in [
        ("image", "image.bin"),
        ("creation", "creation.json"),
        ("stdout", "stdout.bin"),
        ("stderr", "stderr.bin"),
        ("exit", "exit.json"),
    ] {
        if bundle[field] != format!("{stem}.{suffix}") {
            return Err("cross native command bundle substitutes another original capture".into());
        }
    }
    let creation = crate::wire::json(custody.bytes(&reference("creation")?)?)?;
    let exit = crate::wire::json(custody.bytes(&reference("exit")?)?)?;
    closed(
        &invocation,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "program",
            "program_sha256",
            "arguments",
            "cwd",
            "started_unix_millis",
            "budget_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    let started = invocation["started_unix_millis"]
        .as_u64()
        .filter(|started| *started > 0 && *started < cleanup)
        .ok_or("cross original account command starts outside original cleanup cutoff")?;
    let budget = invocation["budget_millis"]
        .as_u64()
        .filter(|budget| *budget > 0 && *budget <= 30000 && *budget <= cleanup - started)
        .ok_or("cross original account native command budget refreshes cleanup cutoff")?;
    if budget == 0 || invocation["cleanup_deadline_unix_millis"] != cleanup {
        return Err("cross account command original cutoff differs".into());
    }
    closed(
        &creation,
        &[
            "format",
            "revision",
            "process_id",
            "birth",
            "invocation_sha256",
            "kernel_image",
        ],
    )?;
    closed(
        &creation["kernel_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    closed(
        &exit,
        &[
            "format",
            "revision",
            "held",
            "raw_wait_status",
            "native_exit",
            "signal",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    let held: HeldProcessIdentity =
        serde_json::from_value(exit["held"].clone()).map_err(|error| error.to_string())?;
    let status = exit["native_exit"]
        .as_u64()
        .filter(|status| *status <= 255)
        .ok_or("cross account native command exit absent")?;
    if invocation["format"] != "memcordon.linux-cross-account-command"
        || invocation["revision"] != 1
        || invocation["identity"] != *identity
        || invocation["cell"] != *cell
        || invocation["program"] != program
        || invocation["arguments"] != json!(args)
        || invocation["cwd"] != original_cwd
        || invocation["program_sha256"] != custody.hash(&image_path)?
        || custody.bytes(&image_path)?.is_empty()
        || creation["format"] != "memcordon.linux-cross-account-command-creation"
        || creation["revision"] != 1
        || creation["process_id"].as_u64() != Some(held.pid as u64)
        || creation["birth"].as_u64() != Some(held.birth)
        || held.pid == 0
        || held.birth < peer_birth
        || !held.retirement_observed
        || creation["invocation_sha256"] != custody.hash(&invocation_path)?
        || creation["kernel_image"]["sha256"] != custody.hash(&image_path)?
        || creation["kernel_image"]["length"] != custody.bytes(&image_path)?.len()
        || ["device", "inode"].iter().any(|field| {
            creation["kernel_image"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
        || exit["format"] != "memcordon.linux-cross-account-command-exit"
        || exit["revision"] != 1
        || exit["raw_wait_status"] != status * 256
        || !exit["signal"].is_null()
        || exit["invocation_sha256"] != custody.hash(&invocation_path)?
        || exit["stdout_sha256"] != custody.hash(&reference("stdout")?)?
        || exit["stderr_sha256"] != custody.hash(&reference("stderr")?)?
    {
        return Err(
            "cross secondary retirement original native command/Child/kernel/wait differs".into(),
        );
    }
    Ok((status, custody.bytes(&reference("stdout")?)?.to_vec()))
}

pub(crate) fn validate(
    canary: &Value,
    index: &EvidenceIndex,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    validate_creation(canary, index, key, custody)?;
    let retired_path = path(canary, "peer_account_retirement")?;
    let parent = retired_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .ok_or("cross secondary native retirement parent absent")?;
    let retired = crate::wire::json(custody.bytes(retired_path)?)?;
    closed(
        &retired,
        &[
            "format",
            "revision",
            "account",
            "task_census",
            "identity_checks",
            "removals",
            "absence_checks",
        ],
    )?;
    let lease = crate::wire::json(custody.bytes(path(canary, "original_lease")?)?)?;
    let cleanup = lease["cleanup_deadline_unix_millis"]
        .as_u64()
        .filter(|cutoff| *cutoff > 0)
        .ok_or("cross original cleanup cutoff absent")?;
    let account = &canary["peer_account"];
    if retired["format"] != "memcordon.linux-cross-account-retired"
        || retired["revision"] != 2
        || retired["account"] != *account
    {
        return Err("cross original secondary native retirement account differs".into());
    }
    let original_cwd = crate::linux_path::parent(
        account["intent"]
            .as_str()
            .ok_or("cross original account source absent")?,
    )
    .and_then(|parent| crate::linux_path::parent(&parent))
    .ok_or("cross original retirement source directory absent")?;
    let census_leaf = retired["task_census"]
        .as_str()
        .filter(|leaf| {
            !leaf.is_empty()
                && !leaf.contains(['/', '\\', ':', '\0'])
                && *leaf != "."
                && *leaf != ".."
        })
        .ok_or("cross original native census source leaf unsafe")?;
    let census = crate::wire::json(custody.bytes(&format!("{parent}/{census_leaf}"))?)?;
    closed(&census, &["format", "revision", "uid", "gid", "tasks"])?;
    let uid = account["uid"].as_u64().ok_or("cross original UID absent")?;
    let gid = account["gid"].as_u64().ok_or("cross original GID absent")?;
    if census["format"] != "memcordon.linux-cross-account-task-census"
        || census["revision"] != 1
        || census["uid"] != uid
        || census["gid"] != gid
    {
        return Err("cross native task census crosses owned secondary credentials".into());
    }
    let tasks = census["tasks"]
        .as_array()
        .filter(|tasks| !tasks.is_empty() && tasks.len() <= 1_048_576)
        .ok_or("cross native task census empty/unbounded")?;
    let mut previous = None;
    for task in tasks {
        closed(task, &["process_id", "task_id", "status", "credentials"])?;
        let pid = task["process_id"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
            .ok_or("cross native census hostPID absent")?;
        let tid = task["task_id"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
            .ok_or("cross native census taskPID absent")?;
        if previous.is_some_and(|previous| previous >= (pid, tid)) {
            return Err("cross native census original task ordering/uniqueness differs".into());
        }
        previous = Some((pid, tid));
        let raw: Vec<u8> =
            serde_json::from_value(task["status"].clone()).map_err(|error| error.to_string())?;
        if raw.len() > 131072 {
            return Err("cross native census raw status unbounded".into());
        }
        let text = std::str::from_utf8(&raw).map_err(|error| error.to_string())?;
        let values = |prefix: &str| -> VerificationResult<Vec<u64>> {
            let rows = text
                .lines()
                .filter_map(|line| line.strip_prefix(prefix))
                .collect::<Vec<_>>();
            if rows.len() != 1 {
                return Err("cross native census exact credential field absent/duplicate".into());
            }
            rows[0]
                .split_whitespace()
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())
        };
        if values("Tgid:")? != [pid] || values("Pid:")? != [tid] {
            return Err("cross native census original /proc directory identity differs".into());
        }
        let credentials = [values("Uid:")?, values("Gid:")?, values("Groups:")?];
        if credentials[0].len() != 4
            || credentials[1].len() != 4
            || credentials[0].contains(&uid)
            || credentials[1].contains(&gid)
            || credentials[2].contains(&gid)
            || task["credentials"] != json!(credentials)
        {
            return Err("cross original secondary remains in native task credentials".into());
        }
    }
    let identity = json!({"run_id":canary["run_id"],"source_commit":index.source_commit,"source_tree_sha256":index.source_tree_sha256,"version":index.version});
    let cell = &canary["cell"];
    let peer_birth = canary["held_peer"]["birth"]
        .as_u64()
        .ok_or("cross original peer birth absent")?
        .max(
            canary["target_native"]["birth"]
                .as_u64()
                .ok_or("cross original target birth absent")?,
        );
    let name = account["name"]
        .as_str()
        .ok_or("cross original secondary name absent")?;
    let checks = retired["identity_checks"]
        .as_array()
        .filter(|checks| checks.len() == 2)
        .ok_or("cross secondary original native identity checks incomplete")?;
    let removals = retired["removals"]
        .as_array()
        .filter(|removals| removals.len() <= 2)
        .ok_or("cross secondary removal population differs")?;
    let mut removal = 0;
    for (ordinal, (database, original_field, program)) in [
        ("passwd", "peer_account_passwd", "/usr/sbin/userdel"),
        ("group", "peer_account_group", "/usr/sbin/groupdel"),
    ]
    .into_iter()
    .enumerate()
    {
        let (status, stdout) = command(
            &checks[ordinal],
            parent,
            &original_cwd,
            &identity,
            cell,
            "/usr/bin/getent",
            &[database.into(), name.into()],
            peer_birth,
            cleanup,
            custody,
        )?;
        if status == 2 && stdout.is_empty() {
            continue;
        }
        if status != 0 || stdout != custody.bytes(path(canary, original_field)?)? {
            return Err("cross secondary original identity changed before actual removal".into());
        }
        let proof = removals
            .get(removal)
            .ok_or("cross original native removal missing")?;
        removal += 1;
        if command(
            proof,
            parent,
            &original_cwd,
            &identity,
            cell,
            program,
            &["--".into(), name.into()],
            peer_birth,
            cleanup,
            custody,
        )?
        .0 != 0
        {
            return Err("cross original secondary native removal failed".into());
        }
    }
    if removal != removals.len() {
        return Err("cross original secondary removal includes unrelated native command".into());
    }
    let absence = retired["absence_checks"]
        .as_array()
        .filter(|checks| checks.len() == 4)
        .ok_or("cross original secondary final name/numeric absence incomplete")?;
    let mut commands = std::collections::BTreeSet::new();
    let mut identities = std::collections::BTreeSet::new();
    for bundle in checks.iter().chain(removals).chain(absence) {
        let invocation = bundle["invocation"]
            .as_str()
            .ok_or("cross original native command reference absent")?;
        let creation = bundle["creation"]
            .as_str()
            .ok_or("cross original native creation reference absent")?;
        let row = crate::wire::json(custody.bytes(&format!("{parent}/{creation}"))?)?;
        let id = (
            row["process_id"]
                .as_u64()
                .ok_or("cross native creatorPID absent")?,
            row["birth"]
                .as_u64()
                .ok_or("cross native creatorbirth absent")?,
        );
        if !commands.insert(invocation)
            || !identities.insert(id)
            || [&canary["held_peer"], &canary["target_native"]]
                .iter()
                .any(|original| {
                    original["process_id"].as_u64() == Some(id.0)
                        && original["birth"].as_u64() == Some(id.1)
                })
        {
            return Err("cross retirement reuses original native command/family identity".into());
        }
    }
    for (ordinal, (database, key)) in [
        ("passwd", name.to_owned()),
        ("passwd", uid.to_string()),
        ("group", name.to_owned()),
        ("group", gid.to_string()),
    ]
    .into_iter()
    .enumerate()
    {
        let (status, stdout) = command(
            &absence[ordinal],
            parent,
            &original_cwd,
            &identity,
            cell,
            "/usr/bin/getent",
            &[database.into(), key],
            peer_birth,
            cleanup,
            custody,
        )?;
        if status != 2 || !stdout.is_empty() {
            return Err("cross original secondary native name/numeric identity remains".into());
        }
    }
    Ok(())
}
