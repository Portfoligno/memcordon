//! Independently decodes actual host canaries and private-root denial effects.
use crate::{
    FixtureBehavior, FixtureInput, NativeArguments, NativeObservation, OutcomeOrigin,
    SemanticObservation,
};
use serde_json::Value;
fn closed(value: &Value, fields: &[&str]) -> Result<(), String> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) {
        return Err("outside file native fields differ".into());
    }
    Ok(())
}
fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

pub fn validate_linux_outside_file(
    kind: &str,
    canary: &Value,
    denied: &Value,
    positive: &Value,
    arguments: &[Vec<u8>],
    challenge: &[u8],
) -> Result<(), String> {
    if ![
        "symlink",
        "dotdot",
        "proc-root",
        "proc-cwd",
        "proc-fd",
        "hardlink",
        "opath",
        "mount-alias",
    ]
    .contains(&kind)
        || challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
    {
        return Err("outside file finite selector/challenge differs".into());
    }
    closed(
        canary,
        &[
            "format",
            "revision",
            "kind",
            "before",
            "after",
            "parents",
            "mount",
            "leaked_descriptor",
            "resolved_close_errno",
            "owner_close_errno",
        ],
    )?;
    closed(
        &canary["before"],
        &[
            "path",
            "probe",
            "kind",
            "device",
            "inode",
            "uid",
            "mode",
            "nlink",
            "length",
            "sha256",
            "controller_pid",
            "controller_birth",
            "source_descriptor",
            "resolved_device",
            "resolved_inode",
            "positive_bytes",
            "alias_native",
            "original_cwd",
        ],
    )?;
    closed(
        &canary["after"],
        &["device", "inode", "uid", "mode", "nlink", "length", "bytes"],
    )?;
    closed(
        &canary["before"]["alias_native"],
        &["device", "inode", "mode", "nlink", "symlink_target"],
    )?;
    closed(
        denied,
        &[
            "kind",
            "path",
            if kind == "opath" {
                "native_descriptor"
            } else {
                "native_open_flags"
            },
            "native_result",
            "native_errno",
        ],
    )?;
    closed(positive, &["path", "bytes"])?;
    let before = &canary["before"];
    let after = &canary["after"];
    let alias = &before["alias_native"];
    let token = hex::encode(challenge).into_bytes();
    let path = bytes(&before["path"])?;
    let probe = bytes(&before["probe"])?;
    if canary["format"] != "memcordon.linux-outside-file-canary"
        || canary["revision"] != 1
        || canary["kind"] != kind
        || before["kind"] != kind
        || !canary["resolved_close_errno"].is_null()
        || !canary["owner_close_errno"].is_null()
        || path.first() != Some(&b'/')
        || probe.first() != Some(&b'/')
        || path.contains(&0)
        || probe.contains(&0)
        || path.len() > 131072
        || probe.len() > 131072
        || bytes(&before["positive_bytes"])? != token
        || bytes(&after["bytes"])? != token
        || before["sha256"] != crate::sha256(&token)
        || before["uid"] != 0
        || before["mode"]
            .as_u64()
            .is_none_or(|mode| mode & 0o170000 != 0o100000 || mode & 0o7777 != 0o444)
        || before["length"] != token.len() as u64
        || before["controller_pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
        || before["controller_birth"]
            .as_u64()
            .is_none_or(|birth| birth == 0)
        || before["source_descriptor"]
            .as_i64()
            .is_none_or(|fd| fd < 3 || fd > i32::MAX as i64)
    {
        return Err("outside original host canary/source differs".into());
    }
    for field in ["device", "inode", "uid", "mode", "nlink", "length"] {
        if before[field] != after[field] {
            return Err("outside native host canary changed across attempt".into());
        }
    }
    for field in ["device", "inode"] {
        if before[field].as_u64().is_none_or(|value| value == 0)
            || before[format!("resolved_{field}")] != before[field]
        {
            return Err("outside native alias substituted a different original inode".into());
        }
    }
    if before["nlink"] != if kind == "hardlink" { 2 } else { 1 } {
        return Err("outside original hardlink count differs".into());
    }
    let pid = before["controller_pid"].as_u64().expect("validated PID");
    let cwd = bytes(&before["original_cwd"])?;
    if cwd.first() != Some(&b'/') || cwd.contains(&0) {
        return Err("outside original controller cwd differs".into());
    }
    let parents = canary["parents"]
        .as_array()
        .filter(|parents| parents.len() == 2)
        .ok_or("outside original parents absent")?;
    let root = path
        .strip_suffix(b"/original.bin")
        .ok_or("outside original canary canonical path differs")?;
    let output = root
        .strip_suffix(b"/host-outside-canary")
        .ok_or("outside original canary parent path differs")?;
    for (parent, expected) in parents.iter().zip([output, root]) {
        closed(
            parent,
            &[
                "path",
                "device",
                "inode",
                "named_device",
                "named_inode",
                "uid",
                "mode",
                "nlink",
                "closed",
                "close_native_errno",
            ],
        )?;
        if bytes(&parent["path"])? != expected
            || parent["device"].as_u64().is_none_or(|id| id == 0)
            || parent["inode"].as_u64().is_none_or(|id| id == 0)
            || parent["named_device"] != parent["device"]
            || parent["named_inode"] != parent["inode"]
            || parent["uid"] != 0
            || parent["mode"]
                .as_u64()
                .is_none_or(|mode| mode & 0o170000 != 0o040000 || mode & 0o022 != 0)
            || parent["nlink"].as_u64().is_none_or(|count| count == 0)
            || parent["closed"] != true
            || !parent["close_native_errno"].is_null()
        {
            return Err("outside original held parent custody differs".into());
        }
    }
    if alias["device"].as_u64().is_none_or(|id| id == 0)
        || alias["inode"].as_u64().is_none_or(|id| id == 0)
    {
        return Err("outside native alias identity absent".into());
    }
    let regular = alias["mode"]
        .as_u64()
        .is_some_and(|mode| mode & 0o170000 == 0o100000);
    match kind {
        "mount-alias" => {
            closed(
                &canary["mount"],
                &[
                    "source",
                    "destination",
                    "mount_flags",
                    "mount_result",
                    "unmount_flags",
                    "unmount_result",
                    "unmount_native_errno",
                ],
            )?;
            if probe != [root, b"/outside-mount"].concat()
                || !regular
                || alias["device"] != before["device"]
                || alias["inode"] != before["inode"]
                || bytes(&canary["mount"]["source"])? != path
                || bytes(&canary["mount"]["destination"])? != probe
                || canary["mount"]["mount_flags"] != 4096
                || canary["mount"]["mount_result"] != 0
                || canary["mount"]["unmount_flags"] != 0
                || canary["mount"]["unmount_result"] != 0
                || !canary["mount"]["unmount_native_errno"].is_null()
            {
                return Err("outside native bind mount/retirement differs".into());
            }
        }
        "opath" => {
            if probe != path || !regular {
                return Err("outside O_PATH original native source differs".into());
            }
            let receipt = &canary["leaked_descriptor"];
            closed(receipt, &["original", "closed", "close_native_errno"])?;
            let original = &receipt["original"];
            closed(
                original,
                &[
                    "frontend_pid",
                    "frontend_birth",
                    "descriptor",
                    "parent_source_descriptor",
                    "path",
                    "device",
                    "inode",
                    "fdinfo",
                ],
            )?;
            if original["frontend_pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
                || original["frontend_birth"]
                    .as_u64()
                    .is_none_or(|birth| birth == 0)
                || original["descriptor"] != 128
                || original["parent_source_descriptor"]
                    .as_i64()
                    .is_none_or(|fd| fd < 3 || fd > i32::MAX as i64)
                || original["device"] != before["device"]
                || original["inode"] != before["inode"]
                || bytes(&original["path"])? != path
                || receipt["closed"] != true
                || !receipt["close_native_errno"].is_null()
            {
                return Err("original frontend hostile O_PATH custody differs".into());
            }
            let fdinfo = bytes(&original["fdinfo"])?;
            if fdinfo.len() > 4096 {
                return Err("original O_PATH fdinfo exceeds bound".into());
            }
            let text = std::str::from_utf8(&fdinfo).map_err(|error| error.to_string())?;
            let mut fields = std::collections::BTreeMap::new();
            for line in text.lines() {
                let (name, value) = line
                    .split_once(':')
                    .ok_or("original O_PATH fdinfo malformed")?;
                if fields.insert(name, value.trim()).is_some() {
                    return Err("original O_PATH fdinfo duplicated".into());
                }
            }
            if fields.len() != 4
                || fields
                    .keys()
                    .any(|field| !["pos", "flags", "mnt_id", "ino"].contains(field))
            {
                return Err("original O_PATH fdinfo fields differ".into());
            }
            let flags = u64::from_str_radix(fields["flags"], 8)
                .map_err(|_| "original O_PATH flags malformed")?;
            if flags & 0x200000 == 0
                || flags & 0x80000 != 0
                || flags & 3 != 0
                || fields["ino"].parse::<u64>().ok() != before["inode"].as_u64()
                || fields["mnt_id"]
                    .parse::<u64>()
                    .ok()
                    .is_none_or(|id| id == 0)
                || fields["pos"] != "0"
            {
                return Err(
                    "original inherited descriptor was not a live hostile O_PATH loan".into(),
                );
            }
        }
        "symlink" => {
            if !probe.ends_with(b"/outside-symlink")
                || alias["mode"]
                    .as_u64()
                    .is_none_or(|mode| mode & 0o170000 != 0o120000)
                || bytes(&alias["symlink_target"])? != path
            {
                return Err("outside symlink native source differs".into());
            }
        }
        "hardlink" => {
            if !probe.ends_with(b"/outside-hardlink")
                || !regular
                || alias["device"] != before["device"]
                || alias["inode"] != before["inode"]
                || alias["nlink"] != 2
            {
                return Err("outside hardlink native source differs".into());
            }
        }
        "dotdot" => {
            if !probe.ends_with(b"/child/../original.bin") || !regular {
                return Err("outside dotdot native source differs".into());
            }
        }
        "proc-root" => {
            if probe != [format!("/proc/{pid}/root").as_bytes(), &path].concat() || !regular {
                return Err("outside proc root source differs".into());
            }
        }
        "proc-cwd" => {
            let count = cwd
                .split(|byte| *byte == b'/')
                .filter(|part| !part.is_empty())
                .count();
            let expected = [
                format!("/proc/{pid}/cwd/").into_bytes(),
                b"../".repeat(count),
                path[1..].to_vec(),
            ]
            .concat();
            if probe != expected || !regular {
                return Err("outside proc cwd source differs".into());
            }
        }
        "proc-fd" => {
            if probe
                != format!(
                    "/proc/{pid}/fd/{}",
                    before["source_descriptor"].as_i64().expect("validated FD")
                )
                .as_bytes()
                || alias["mode"]
                    .as_u64()
                    .is_none_or(|mode| mode & 0o170000 != 0o120000)
                || bytes(&alias["symlink_target"])? != path
            {
                return Err("outside proc FD source differs".into());
            }
        }
        _ => return Err("unknown outside source applicability".into()),
    }
    if kind != "mount-alias" && !canary["mount"].is_null() {
        return Err("outside unrelated mount authority present".into());
    }
    if kind != "opath" && !canary["leaked_descriptor"].is_null() {
        return Err("outside unrelated descriptor authority present".into());
    }
    let mut expected = vec![
        b"outside-file".to_vec(),
        hex::encode(challenge).into_bytes(),
        kind.as_bytes().to_vec(),
        probe.clone(),
    ];
    if kind == "opath" {
        expected.push(b"128".to_vec());
    }
    if arguments != expected
        || denied["kind"] != kind
        || bytes(&denied["path"])? != probe
        || denied["native_result"] != -1
        || (if kind == "opath" {
            denied["native_descriptor"] != 128 || denied["native_errno"] != 9
        } else {
            denied["native_open_flags"] != 0x80000
                || !matches!(denied["native_errno"].as_i64(), Some(1 | 2 | 13 | 40))
        })
        || bytes(&positive["path"])? != b"/work/private-path-positive.bin"
        || bytes(&positive["bytes"])? != b"private-read-write-positive"
    {
        return Err("actual outside syscall/neighboring private effects differ".into());
    }
    Ok(())
}

pub(crate) fn validate_behavior(
    behavior: &FixtureBehavior,
    semantic: &SemanticObservation,
    native: &NativeObservation,
    input: &FixtureInput,
    custody: &crate::custody::Custody,
) -> Result<Option<crate::behavior::Facts>, String> {
    let key = &semantic.key;
    if key.family != "L-ISO-04"
        || ![
            "symlink",
            "dotdot",
            "proc-root",
            "proc-cwd",
            "proc-fd",
            "hardlink",
            "opath",
            "mount-alias",
        ]
        .contains(&key.scenario.as_str())
    {
        return Ok(None);
    }
    if native.origin != OutcomeOrigin::Target || native.target_status != Some(0) {
        return Err("outside path effect substituted wrapper/native failure".into());
    }
    let binding: Value = crate::wire::decode(
        custody.bytes(
            behavior
                .native_binding
                .as_deref()
                .ok_or("outside path native preparation absent")?,
        )?,
    )?;
    let local = binding["target"]["namespace_pids"]
        .as_array()
        .and_then(|values| values.last())
        .and_then(Value::as_u64)
        .ok_or("outside original namespace target absent")?;
    if binding["target"]["process_id"].as_u64() != native.root_pid.map(u64::from)
        || binding["target"]["birth"].as_u64() != native.root_birth
        || binding["run_id"] != native.run_id
    {
        return Err("outside original held target birth differs".into());
    }
    let transcript = custody.bytes(&behavior.transcript)?;
    if transcript.is_empty() || !transcript.ends_with(b"\n") {
        return Err("outside transcript truncated".into());
    }
    let rows = transcript
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
        .map(crate::wire::decode::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != 2 {
        return Err("outside exact native operation sequence differs".into());
    }
    let challenge = custody.bytes(&semantic.challenge)?;
    for (index, row) in rows.iter().enumerate() {
        closed(
            row,
            &[
                "format",
                "revision",
                "sequence",
                "challenge",
                "root_pid",
                "root_birth",
                "operation",
                "observation",
            ],
        )?;
        if row["format"] != "memcordon.linux-readiness-transcript"
            || row["revision"] != 1
            || row["sequence"] != index as u64 + 1
            || row["challenge"] != hex::encode(challenge)
            || row["root_pid"] != local
            || row["root_birth"].as_u64() != native.root_birth
        {
            return Err("outside original transcript association differs".into());
        }
    }
    if rows[0]["operation"] != "neighboring-private-file"
        || rows[1]["operation"] != "native-outside-file-denied"
    {
        return Err("outside positive/negative operation order differs".into());
    }
    let peers = behavior
        .peer_artifacts
        .iter()
        .filter(|peer| peer.role == "outside-file-canary")
        .collect::<Vec<_>>();
    if peers.len() != 1 {
        return Err("outside original host canary custody absent".into());
    }
    let canary: Value = crate::wire::decode(custody.bytes(&peers[0].path)?)?;
    if key.scenario == "opath"
        && (canary["leaked_descriptor"]["original"]["frontend_pid"]
            != binding["caller"]["process_id"]
            || canary["leaked_descriptor"]["original"]["frontend_birth"]
                != binding["caller"]["birth"])
    {
        return Err("hostile O_PATH descriptor substitutes original frontend birth".into());
    }
    let NativeArguments::UnixBytes(arguments) = &input.target_argv else {
        return Err("outside native Unix argv absent".into());
    };
    validate_linux_outside_file(
        &key.scenario,
        &canary,
        &rows[1]["observation"],
        &rows[0]["observation"],
        arguments,
        challenge,
    )?;
    let probe = semantic
        .negative_probe
        .as_ref()
        .ok_or("outside original native syscall projection absent")?;
    if probe.stage != key.scenario
        || probe.domain != "linux"
        || Some(probe.native_code) != rows[1]["observation"]["native_errno"].as_i64()
        || probe.receipt != behavior.transcript
    {
        return Err("outside native denial projection differs".into());
    }
    Ok(Some(crate::behavior::Facts {
        operations: ["native-authority-probe".into()].into_iter().collect(),
        counters: Default::default(),
    }))
}
