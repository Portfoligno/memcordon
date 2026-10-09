//! Independent raw Linux limit observations. These predicates do not establish
//! installed authority, native family retirement, or profile readiness.
use crate::HeldProcessIdentity;
use crate::{FixtureBehavior, FixtureInput, NativeObservation, OutcomeOrigin, SemanticObservation};
use serde_json::Value;
use std::collections::BTreeMap;

fn closed(value: &Value, fields: &[&str]) -> Result<(), String> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    }) {
        return Err("limit raw native observation shape differs".into());
    }
    Ok(())
}
fn held(value: &Value) -> Result<(u64, u64), String> {
    closed(
        value,
        &[
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "retirement_observed",
        ],
    )?;
    let pid = value["pid"]
        .as_u64()
        .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
        .ok_or("limit held PID absent")?;
    let birth = value["birth"]
        .as_u64()
        .filter(|birth| *birth > 0)
        .ok_or("limit held birth absent")?;
    if value["retirement_observed"] != false
        || !value["parent_pid"].is_null()
        || !value["parent_birth"].is_null()
    {
        return Err("limit selected worker was retired or substituted ancestry".into());
    }
    Ok((pid, birth))
}

fn validate_memory_source(
    source: &Value,
    worker: &Value,
    stopped: &Value,
    request: &Value,
    native: &NativeObservation,
    agent_hash: &str,
) -> Result<(), String> {
    closed(
        source,
        &[
            "format",
            "revision",
            "attempt_id",
            "provider",
            "admission",
            "journal_path",
            "journal_device",
            "journal_inode",
            "journal_sha256",
            "journal_bytes",
            "worker",
            "native_image",
        ],
    )?;
    closed(&source["worker"], &["pid", "birth", "image_sha256"])?;
    closed(
        &source["native_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    let (pid, birth) = held(worker)?;
    let attempt = native
        .attempt_id
        .as_deref()
        .ok_or("limit actual attempt absent")?;
    if source["format"] != "memcordon.linux-prepared-worker-observation"
        || source["revision"] != 1
        || source["attempt_id"] != attempt
        || source["worker"]["pid"] != pid
        || source["worker"]["birth"] != birth
        || source["worker"]["image_sha256"] != agent_hash
        || source["native_image"]["sha256"] != agent_hash
        || ["device", "inode", "length"].iter().any(|field| {
            source["native_image"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
        || source["journal_path"] != format!("/var/lib/memcordon/sealed/{attempt}")
        || ["journal_device", "journal_inode"]
            .iter()
            .any(|field| source[*field].as_u64().is_none_or(|value| value == 0))
        || source["admission"]["attempt_id"] != attempt
        || source["admission"]["request"] != request["contract"]
        || source["admission"]["request_sha256"]
            != crate::wire::v3_request_digest(&request["contract"])?
        || source["provider"]["generation"].as_str() != native.provider_generation.as_deref()
        || source["provider"]["runtime_manifest_sha256"].as_str()
            != native.runtime_manifest_sha256.as_deref()
    {
        return Err("memory interval substitutes selected original worker/provider/image".into());
    }
    let bytes: Vec<u8> = serde_json::from_value(source["journal_bytes"].clone())
        .map_err(|error| error.to_string())?;
    if bytes.is_empty()
        || bytes.len() > 4 * 1024 * 1024
        || source["journal_sha256"] != crate::sha256(&bytes)
    {
        return Err("memory worker journal measurement differs".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "memory worker journal is not UTF8")?;
    let (body, checksum) = text
        .rsplit_once("digest=")
        .ok_or("memory worker journal checksum absent")?;
    if checksum != format!("{}\n", crate::sha256(body.as_bytes())) {
        return Err("memory worker native journal checksum differs".into());
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
        || lines.next() != Some(format!("cgroup={attempt}").as_str())
    {
        return Err("memory worker native journal envelope differs".into());
    }
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or("memory worker journal payload absent")?;
    if lines.next().is_some() {
        return Err("memory worker journal envelope extra fields".into());
    }
    let journal: Value = crate::wire::decode(payload.as_bytes())?;
    if journal["attempt_id"] != attempt
        || journal["mixed_admission_metadata"] != source["admission"]
        || journal["mixed_worker"]["pid"] != pid
        || journal["mixed_worker"]["start_time"] != birth
        || journal["target"]["pid"].as_u64() != native.root_pid.map(u64::from)
        || journal["target"]["start_time"].as_u64() != native.root_birth
        || journal["phase"] != "target-gated"
        || journal["release_knowledge"] != "not-released"
    {
        return Err("memory worker journal is not selected pre-release family".into());
    }
    closed(
        stopped,
        &[
            "format",
            "revision",
            "process_id",
            "birth",
            "state",
            "native_stat_bytes",
        ],
    )?;
    let stat: Vec<u8> = serde_json::from_value(stopped["native_stat_bytes"].clone())
        .map_err(|error| error.to_string())?;
    if stat.is_empty()
        || stat.len() > 4096
        || stopped["format"] != "memcordon.linux-limit-worker-stopped"
        || stopped["revision"] != 1
        || stopped["process_id"] != pid
        || stopped["birth"] != birth
    {
        return Err("memory native stopped worker association differs".into());
    }
    let stat = std::str::from_utf8(&stat).map_err(|_| "native stopped stat is not UTF8")?;
    let (head, tail) = stat
        .rsplit_once(')')
        .ok_or("native stopped stat command absent")?;
    let fields = tail.split_ascii_whitespace().collect::<Vec<_>>();
    if head
        .split_once(" (")
        .and_then(|(value, _)| value.parse::<u64>().ok())
        != Some(pid)
        || fields
            .first()
            .is_none_or(|state| !matches!(*state, "T" | "t"))
        || stopped["state"].as_str() != fields.first().copied()
        || fields.get(19).and_then(|value| value.parse::<u64>().ok()) != Some(birth)
    {
        return Err(
            "memory worker actual native stat does not establish stopped original birth".into(),
        );
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
    let backpressure = key.family == "L-LIFE-05" && key.scenario == "relay-backpressure";
    let stream = backpressure
        || (["C-IO", "L-MIX-05"].contains(&key.family.as_str())
            && key.scenario == "bounded-large-output");
    if !stream
        && !(["C-STATUS", "L-LIFE-03"].contains(&key.family.as_str())
            && ["deadline", "memory", "cancellation", "reserved-target-exit"]
                .contains(&key.scenario.as_str()))
    {
        return Ok(None);
    }
    let mut facts = crate::behavior::Facts {
        operations: Default::default(),
        counters: Default::default(),
    };
    let peers = behavior
        .peer_artifacts
        .iter()
        .map(|peer| (peer.role.as_str(), peer.path.as_str()))
        .collect::<BTreeMap<_, _>>();
    if peers.len() != behavior.peer_artifacts.len() {
        return Err("limit peer role duplicated".into());
    }
    let request_bytes = custody.bytes(
        peers
            .get("limit-provider-request")
            .copied()
            .ok_or("limit actual native provider request absent")?,
    )?;
    let request: Value = crate::wire::decode(request_bytes)?;
    if native.request_sha256.as_deref() != Some(crate::sha256(request_bytes).as_str())
        || request["attempt_deadline_millis"].as_u64() != input.deadline_millis
    {
        return Err("limit selected budget/actual provider request association differs".into());
    }
    let actions: Vec<Value> = crate::wire::decode(
        custody.bytes(
            peers
                .get("limit-controller")
                .copied()
                .ok_or("limit controller raw observations absent")?,
        )?,
    )?;
    if actions.len() > 32 {
        return Err("limit controller vector exceeds finite bound".into());
    }
    if stream {
        if native.origin != OutcomeOrigin::Target
            || native.target_status != Some(0)
            || (!backpressure && !actions.is_empty())
        {
            return Err("bounded stream substituted a limit/controller failure".into());
        }
        validate_bounded_large_streams(
            custody.bytes(
                peers
                    .get("stdout")
                    .copied()
                    .ok_or("bounded stdout absent")?,
            )?,
            custody.bytes(
                peers
                    .get("stderr")
                    .copied()
                    .ok_or("bounded stderr absent")?,
            )?,
        )?;
        if backpressure {
            if actions.len() != 2 {
                return Err("relay backpressure lacks exact hold/resume native sequence".into());
            }
            let held = &actions[0];
            let resumed = &actions[1];
            closed(
                held,
                &[
                    "format",
                    "revision",
                    "frontend_pid",
                    "frontend_birth",
                    "native_frontend_live",
                    "capture_held",
                    "pipes",
                ],
            )?;
            closed(resumed, &["format", "revision", "key", "capture_resumed"])?;
            let binding: Value = crate::wire::decode(
                custody.bytes(
                    behavior
                        .native_binding
                        .as_deref()
                        .ok_or("relay backpressure original native caller absent")?,
                )?,
            )?;
            let live: HeldProcessIdentity =
                serde_json::from_value(held["native_frontend_live"].clone())
                    .map_err(|error| error.to_string())?;
            if held["format"] != "memcordon.linux-native-output-backpressure"
                || held["revision"] != 1
                || held["capture_held"] != true
                || live.retirement_observed
                || live.pid == 0
                || live.pid > i32::MAX as u32
                || live.birth == 0
                || held["frontend_pid"] != live.pid
                || held["frontend_birth"] != live.birth
                || held["frontend_pid"] != binding["caller"]["process_id"]
                || held["frontend_birth"] != binding["caller"]["birth"]
                || resumed["format"] != "memcordon.linux-output-capture-resumed"
                || resumed["revision"] != 1
                || resumed["key"] != serde_json::to_value(key).map_err(|error| error.to_string())?
                || resumed["capture_resumed"] != true
            {
                return Err(
                    "relay backpressure substitutes another original held caller/capture sequence"
                        .into(),
                );
            }
            let pipes = held["pipes"]
                .as_array()
                .filter(|pipes| pipes.len() == 2)
                .ok_or("relay backpressure actual stdout/stderr pipe census differs")?;
            let mut identities = std::collections::BTreeSet::new();
            let mut full = false;
            for (ordinal, pipe) in pipes.iter().enumerate() {
                closed(
                    pipe,
                    &[
                        "device",
                        "inode",
                        "mode",
                        "capacity_bytes",
                        "queued_bytes",
                        "native_descriptor",
                        "source_link",
                    ],
                )?;
                let device = pipe["device"]
                    .as_u64()
                    .filter(|value| *value > 0)
                    .ok_or("relay pipe native device absent")?;
                let inode = pipe["inode"]
                    .as_u64()
                    .filter(|value| *value > 0)
                    .ok_or("relay pipe native inode absent")?;
                let link: Vec<u8> = serde_json::from_value(pipe["source_link"].clone())
                    .map_err(|error| error.to_string())?;
                if pipe["native_descriptor"] != ordinal + 1
                    || link != format!("pipe:[{inode}]").as_bytes()
                {
                    return Err("relay held pipe differs from original live frontend native stdout/stderr descriptor".into());
                }
                let mode = pipe["mode"]
                    .as_u64()
                    .ok_or("relay pipe native mode absent")?;
                let capacity = pipe["capacity_bytes"]
                    .as_u64()
                    .filter(|value| *value > 0 && *value <= i32::MAX as u64)
                    .ok_or("relay pipe native capacity invalid")?;
                let queued = pipe["queued_bytes"]
                    .as_u64()
                    .filter(|value| *value <= capacity)
                    .ok_or("relay pipe queued native byte count invalid")?;
                if mode & 0o170000 != 0o010000 || !identities.insert((device, inode)) {
                    return Err("relay native stdout/stderr pipe type/identity differs".into());
                }
                full |= queued == capacity;
            }
            if !full {
                return Err("relay backpressure never measured a full native held pipe".into());
            }
            facts.operations.extend(
                [
                    "backpressure-observed",
                    "relay-drained",
                    "fault-relay-backpressure",
                    "original-cause-retained",
                    "independent-retirement",
                ]
                .map(String::from),
            );
        }
        facts
            .operations
            .extend(["stdout-bytes", "stderr-bytes"].map(String::from));
        facts.counters.extend([
            ("stdout-bytes".into(), 256 * 8192),
            ("stderr-bytes".into(), 256 * 8192),
        ]);
        return Ok(Some(facts));
    }
    let binding: Value = crate::wire::decode(
        custody.bytes(
            behavior
                .native_binding
                .as_deref()
                .ok_or("limit independently held target binding absent")?,
        )?,
    )?;
    let local = binding["target"]["namespace_pids"]
        .as_array()
        .and_then(|values| values.last())
        .and_then(Value::as_u64)
        .ok_or("limit namespace PID absent")?;
    if binding["run_id"] != native.run_id
        || binding["attempt_id"].as_str() != native.attempt_id.as_deref()
        || binding["target"]["process_id"].as_u64() != native.root_pid.map(u64::from)
        || binding["target"]["birth"].as_u64() != native.root_birth
    {
        return Err("limit native target/attempt/run binding differs".into());
    }
    let transcript = custody.bytes(&behavior.transcript)?;
    if transcript.is_empty() || !transcript.ends_with(b"\n") {
        return Err("limit fixture transcript truncated".into());
    }
    let mut rows = BTreeMap::<String, Value>::new();
    let mut sequences = BTreeMap::<String, u64>::new();
    for (ordinal, line) in transcript
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let row: Value = crate::wire::decode(line)?;
        let fields = [
            "format",
            "revision",
            "sequence",
            "challenge",
            "root_pid",
            "root_birth",
            "operation",
            "observation",
        ];
        if row.as_object().is_none_or(|object| {
            object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        }) || row["format"] != "memcordon.linux-readiness-transcript"
            || row["revision"] != 1
            || row["sequence"] != ordinal as u64 + 1
            || row["root_pid"] != local
            || row["root_birth"].as_u64() != native.root_birth
            || row["challenge"] != hex::encode(custody.bytes(&semantic.challenge)?)
        {
            return Err("limit fixture actual row association differs".into());
        }
        let operation = row["operation"]
            .as_str()
            .ok_or("limit operation encoding differs")?
            .to_owned();
        sequences.insert(operation.clone(), ordinal as u64 + 1);
        if rows.insert(operation, row["observation"].clone()).is_some() {
            return Err("limit fixture stage repeated".into());
        }
    }
    if key.family == "L-LIFE-03" {
        for stage in [
            "bind-zero-and-competing-bind",
            "unix-path-round-trip",
            "unix-abstract-round-trip",
            "unix-stream-pair-round-trip",
            "joint-unix-rights-held-through-build",
            "offline-compiler-held",
            "joint-generated-child-held",
        ] {
            if !rows.contains_key(stage) {
                return Err(
                    "mixed limit omits actual same-attempt TCP/Unix/compiler/generated-child stage"
                        .into(),
                );
            }
        }
        if rows["bind-zero-and-competing-bind"]["native_errno"] != 98
            || rows["bind-zero-and-competing-bind"]["listener_retained"] != true
            || rows["joint-unix-rights-held-through-build"]["owned_native_descriptors"] != 14
        {
            return Err("mixed limit loses actual held TCP/Unix resources".into());
        }
        let raw =
            |role: &str| -> Result<Value, String> {
                crate::wire::decode(custody.bytes(peers.get(role).copied().ok_or_else(
                    || format!("joint limit original physical peer absent: {role}"),
                )?)?)
            };
        let created = raw("generated-created")?;
        let compiler = raw("native-compiler-live")?;
        let generated = raw("native-generated-live")?;
        let manifest = raw("toolchain-inputs")?;
        closed(&manifest, &["runtime", "input"])?;
        if crate::linux_build::linux_image_reference(&manifest["runtime"], &native.target)?
            != request["contract"]["runtime_image"]
            || crate::linux_build::linux_image_reference(&manifest["input"], &native.target)?
                != request["contract"]["input_image"]
        {
            return Err(
                "joint limit compiler/source image definitions differ from original admission"
                    .into(),
            );
        }
        for relative in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "src/main.rs",
            "tests/generated_child.rs",
        ] {
            let role = format!("source-{relative}");
            let bytes = custody.bytes(
                peers
                    .get(role.as_str())
                    .copied()
                    .ok_or("joint limit original locked source bytes absent")?,
            )?;
            let entries = manifest["input"]["entries"]
                .as_array()
                .ok_or("joint limit source image entries absent")?;
            let path = format!("owned-source/{relative}");
            let selected = entries
                .iter()
                .filter(|entry| entry["path"] == path)
                .collect::<Vec<_>>();
            if selected.len() != 1
                || selected[0]["kind"] != "regular"
                || selected[0]["sha256"] != crate::sha256(bytes)
                || selected[0]["size"] != bytes.len() as u64
            {
                return Err("joint limit compiled source/lock bytes differ from original immutable input image".into());
            }
        }
        for path in ["toolchain/bin/cargo", "toolchain/bin/rustc", "usr/bin/cc"] {
            let entries = manifest["runtime"]["entries"]
                .as_array()
                .ok_or("joint limit compiler image entries absent")?;
            if entries
                .iter()
                .filter(|entry| {
                    entry["path"] == path
                        && entry["kind"] == "regular"
                        && entry["executable"] == true
                })
                .count()
                != 1
            {
                return Err("joint limit original native compiler/linker authority absent".into());
            }
        }
        for (barrier, path) in [
            (&compiler, "bin/owned-readiness"),
            (&generated, "toolchain/bin/cargo"),
        ] {
            let members = barrier["members"]
                .as_array()
                .ok_or("joint limit original native compiler image absent")?;
            let selected = members
                .iter()
                .filter(|member| {
                    member["native"]["namespace_pids"]
                        .as_array()
                        .and_then(|pids| pids.last())
                        == Some(&created["compiler_pid"])
                        && member["native"]["birth"] == created["compiler_birth"]
                })
                .collect::<Vec<_>>();
            let entries = manifest["runtime"]["entries"]
                .as_array()
                .ok_or("joint limit original runtime image entries absent")?;
            let images = entries
                .iter()
                .filter(|entry| {
                    entry["path"] == path
                        && entry["kind"] == "regular"
                        && entry["executable"] == true
                })
                .collect::<Vec<_>>();
            if selected.len() != 1
                || images.len() != 1
                || selected[0]["executable"]["sha256"] != images[0]["sha256"]
                || selected[0]["executable"]["length"] != images[0]["size"]
            {
                return Err("joint limit held compiler kernel image differs from admitted immutable executable".into());
            }
        }
        if rows["joint-generated-child-held"]["created"] != created {
            return Err(
                "joint limit generated fixture readiness crosses original creation receipt".into(),
            );
        }
        crate::linux_build::validate_linux_generated_build(
            &created,
            &compiler,
            &generated,
            &binding["target"],
            &native.held_processes,
            (
                native.root_pid.ok_or("joint limit held root absent")?,
                native
                    .root_birth
                    .ok_or("joint limit original root birth absent")?,
            ),
            native
                .attempt_id
                .as_deref()
                .ok_or("joint limit original attempt absent")?,
            custody.bytes(&semantic.challenge)?,
            &native.target,
            custody.bytes(
                peers
                    .get("generated-executable")
                    .copied()
                    .ok_or("joint limit original generated native executable absent")?,
            )?,
        )?;
        let closures = raw("native-build-observer-close")?;
        let closures = closures
            .as_array()
            .filter(|values| values.len() == 4)
            .ok_or("joint limit original four read observation closures absent")?;
        let mut identities = std::collections::BTreeSet::new();
        for closure in closures {
            closed(closure, &["device", "inode", "closed", "native_errno"])?;
            let device = closure["device"]
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or("joint build observer native device absent")?;
            let inode = closure["inode"]
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or("joint build observer native inode absent")?;
            if !identities.insert((device, inode))
                || closure["closed"] != true
                || !closure["native_errno"].is_null()
            {
                return Err(
                    "joint build original read observation handle did not settle uniquely".into(),
                );
            }
        }
        for (device, inode) in [
            (&binding["root_device"], &binding["root_inode"]),
            (&created["image_device"], &created["image_inode"]),
        ] {
            let identity = (
                device
                    .as_u64()
                    .ok_or("joint original observed device absent")?,
                inode
                    .as_u64()
                    .ok_or("joint original observed inode absent")?,
            );
            if !identities.contains(&identity) {
                return Err(
                    "joint read observer closures adopt another original root/generated executable"
                        .into(),
                );
            }
        }
    }
    match key.scenario.as_str() {
        "deadline" => {
            if native.origin != OutcomeOrigin::Deadline
                || input.deadline_millis.is_none_or(|value| value == 0)
            {
                return Err("deadline actual origin/budget/controller differs".into());
            }
            if key.family == "C-STATUS" {
                let population = rows
                    .get("population-held-until-native-deadline")
                    .ok_or("deadline original population absent")?;
                closed(population, &["population", "children"])?;
                if population["population"] != 257 {
                    return Err("deadline original population count differs".into());
                }
                let children = population["children"]
                    .as_array()
                    .filter(|children| children.len() == 256)
                    .ok_or("deadline actual root-plus-256 population absent")?;
                if actions.len() != 1 {
                    return Err("deadline original held population receipt absent".into());
                }
                let receipt = &actions[0];
                closed(
                    receipt,
                    &[
                        "format",
                        "revision",
                        "attempt_id",
                        "challenge",
                        "root",
                        "members",
                    ],
                )?;
                if receipt["format"] != "memcordon.linux-native-deadline-population"
                    || receipt["revision"] != 1
                    || receipt["attempt_id"] != native.attempt_id.clone().unwrap_or_default()
                    || receipt["challenge"] != hex::encode(custody.bytes(&semantic.challenge)?)
                {
                    return Err("deadline native population association differs".into());
                }
                let root = &receipt["root"];
                closed(
                    root,
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
                if root != &binding["target"]
                    || root["process_id"].as_u64() != native.root_pid.map(u64::from)
                    || root["birth"].as_u64() != native.root_birth
                {
                    return Err("deadline native population root differs".into());
                }
                let local_root = root["namespace_pids"]
                    .as_array()
                    .and_then(|pids| pids.last())
                    .and_then(Value::as_u64)
                    .ok_or("deadline root namespace PID absent")?;
                let members = receipt["members"]
                    .as_array()
                    .filter(|members| members.len() == 256)
                    .ok_or("deadline independent held population absent")?;
                if native
                    .held_processes
                    .iter()
                    .filter(|held| {
                        Some(held.pid) == native.root_pid
                            && Some(held.birth) == native.root_birth
                            && held.parent_pid.is_none()
                            && held.parent_birth.is_none()
                            && held.retirement_observed
                    })
                    .count()
                    != 1
                {
                    return Err("deadline original root native retirement absent".into());
                }
                let mut locals = BTreeMap::new();
                let mut hosts = std::collections::BTreeSet::new();
                for member in members {
                    closed(member, &["native", "identity"])?;
                    let snapshot = &member["native"];
                    closed(
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
                    let identity: crate::HeldProcessIdentity = crate::wire::decode(
                        &serde_json::to_vec(&member["identity"])
                            .map_err(|error| error.to_string())?,
                    )?;
                    if Some(identity.pid) == native.root_pid
                        || native.root_birth.is_none_or(|birth| identity.birth < birth)
                    {
                        return Err("deadline child substitutes original root identity".into());
                    }
                    let pids = snapshot["namespace_pids"]
                        .as_array()
                        .filter(|pids| !pids.is_empty() && pids.len() <= 32)
                        .ok_or("deadline member namespace mapping absent")?;
                    let local = pids
                        .last()
                        .and_then(Value::as_u64)
                        .filter(|pid| *pid > 0 && *pid != local_root)
                        .ok_or("deadline child namespace PID invalid")?;
                    if identity.pid == 0
                        || identity.birth == 0
                        || identity.retirement_observed
                        || identity.parent_pid != native.root_pid
                        || identity.parent_birth != native.root_birth
                        || snapshot["process_id"] != identity.pid
                        || snapshot["birth"] != identity.birth
                        || pids.first().and_then(Value::as_u64) != Some(u64::from(identity.pid))
                        || pids.iter().any(|pid| {
                            pid.as_u64()
                                .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
                        })
                        || !hosts.insert((identity.pid, identity.birth))
                        || locals.insert(local, identity.birth).is_some()
                    {
                        return Err("deadline child original custody/ancestry differs".into());
                    }
                    for ns in ["user", "mount", "pid", "network", "ipc"] {
                        if snapshot[ns] != root[ns] {
                            return Err("deadline child left original target namespace".into());
                        }
                    }
                    if native
                        .held_processes
                        .iter()
                        .filter(|held| {
                            held.pid == identity.pid
                                && held.birth == identity.birth
                                && held.parent_pid == identity.parent_pid
                                && held.parent_birth == identity.parent_birth
                                && held.retirement_observed
                        })
                        .count()
                        != 1
                    {
                        return Err("deadline child original native retirement absent".into());
                    }
                }
                for child in children {
                    closed(child, &["pid", "birth", "parent_pid", "members"])?;
                    let pid = child["pid"]
                        .as_u64()
                        .ok_or("deadline reported child PID absent")?;
                    if child["parent_pid"] != local_root
                        || child["members"]
                            .as_array()
                            .is_none_or(|members| !members.is_empty())
                        || locals.remove(&pid) != child["birth"].as_u64()
                    {
                        return Err(
                            "deadline reported child does not match original held native process"
                                .into(),
                        );
                    }
                }
                if !locals.is_empty() || native.held_processes.len() != 257 {
                    return Err("deadline population native closure differs".into());
                }
            } else if !actions.is_empty() {
                return Err("joint deadline unexpected controller action".into());
            }
            facts.operations.insert("deadline-expired".into());
        }
        "reserved-target-exit" => {
            if native.origin != OutcomeOrigin::Target
                || native.target_status != Some(125)
                || rows
                    .get("joint-reserved-application-exit")
                    .is_none_or(|row| row["requested_exit_code"] != 125)
                || !actions.is_empty()
            {
                return Err(
                    "mixed reserved application exit substituted wrapper/limit failure".into(),
                );
            }
            facts
                .operations
                .insert("reserved-native-target-exit".into());
        }
        "cancellation" => {
            if native.origin != OutcomeOrigin::Interrupted || actions.len() != 1 {
                return Err(
                    "controlled cancellation actual cause/controller vector differs".into(),
                );
            }
            let action = &actions[0];
            closed(
                action,
                &[
                    "format",
                    "revision",
                    "run_id",
                    "lease_id",
                    "key",
                    "challenge",
                    "held_frontend",
                    "image",
                    "barrier_sequence",
                    "barrier_operation",
                    "signal",
                    "syscall_succeeded",
                    "native_errno",
                ],
            )?;
            let frontend = held(&action["held_frontend"])?;
            closed(&action["image"], &["device", "inode", "length", "sha256"])?;
            if binding["caller"]["process_id"] != frontend.0
                || binding["caller"]["birth"] != frontend.1
                || action["image"]["sha256"] != native.executable_sha256
                || ["device", "inode", "length"].iter().any(|field| {
                    action["image"][*field]
                        .as_u64()
                        .is_none_or(|value| value == 0)
                })
                || action["barrier_sequence"].as_u64()
                    != sequences.get("joint-generated-child-held").copied()
            {
                return Err(
                    "controlled cancellation substitutes native frontend image/birth/barrier"
                        .into(),
                );
            }
            if action["format"] != "memcordon.linux-limit-controller-interrupt"
                || action["revision"] != 1
                || action["run_id"] != native.run_id
                || action["lease_id"].as_str() != native.lease_id.as_deref()
                || action["key"] != serde_json::to_value(key).map_err(|error| error.to_string())?
                || action["challenge"] != hex::encode(custody.bytes(&semantic.challenge)?)
                || action["signal"] != 2
                || action["syscall_succeeded"] != true
                || !action["native_errno"].is_null()
                || action["barrier_operation"] != "joint-generated-child-held"
            {
                return Err("controlled cancellation original native action differs".into());
            }
            facts.operations.insert("controlled-cancellation".into());
        }
        "memory" => {
            if native.origin != OutcomeOrigin::Memory
                || !rows.contains_key("memory-pressure-descendant-held")
                || actions.len() != 5
            {
                return Err(
                    "actual memory allocation/native cause/controller vector differs".into(),
                );
            }
            let stop = &actions[0];
            let stopped = &actions[1];
            let armed = &actions[2];
            let transition = &actions[3];
            let resume = &actions[4];
            closed(
                stop,
                &[
                    "format",
                    "revision",
                    "worker",
                    "signal",
                    "syscall_succeeded",
                    "native_errno",
                ],
            )?;
            closed(
                resume,
                &[
                    "format",
                    "revision",
                    "worker",
                    "signal",
                    "syscall_succeeded",
                    "native_errno",
                ],
            )?;
            closed(
                stopped,
                &[
                    "format",
                    "revision",
                    "key",
                    "attempt_id",
                    "worker",
                    "selected_worker_source",
                    "actual_stop",
                    "stopped",
                ],
            )?;
            closed(
                armed,
                &[
                    "format",
                    "revision",
                    "key",
                    "attempt_id",
                    "worker_index",
                    "group_device",
                    "group_inode",
                    "events_device",
                    "events_inode",
                    "maximum_device",
                    "maximum_inode",
                    "target",
                    "target_membership",
                    "before",
                    "memory_max",
                ],
            )?;
            closed(
                transition,
                &[
                    "format",
                    "revision",
                    "key",
                    "attempt_id",
                    "worker_index",
                    "group_device",
                    "group_inode",
                    "events_device",
                    "events_inode",
                    "maximum_device",
                    "maximum_inode",
                    "before",
                    "after",
                ],
            )?;
            let image = peers
                .get("limit-agent-image")
                .copied()
                .ok_or("memory selected native agent image absent")?;
            validate_memory_source(
                &stopped["selected_worker_source"],
                &stop["worker"],
                &stopped["stopped"],
                &request,
                native,
                custody.hash(image)?,
            )?;
            closed(&armed["target"], &["pid", "birth"])?;
            let membership: Vec<u8> = serde_json::from_value(armed["target_membership"].clone())
                .map_err(|error| error.to_string())?;
            if membership
                != format!(
                    "0::/memcordon-sealed/{}\n",
                    native
                        .attempt_id
                        .as_deref()
                        .ok_or("memory native attempt absent")?
                )
                .as_bytes()
                || [stop, resume].iter().any(|action| action["revision"] != 1)
                || ["group_device", "events_device", "maximum_device"]
                    .iter()
                    .any(|field| armed[*field].as_u64().is_none_or(|value| value == 0))
            {
                return Err("memory interval raw cgroup membership/native source differs".into());
            }
            if stop["format"] != "memcordon.linux-memory-worker-stop"
                || stop["signal"] != 19
                || stop["syscall_succeeded"] != true
                || !stop["native_errno"].is_null()
                || stopped["format"] != "memcordon.linux-memory-worker-stopped"
                || stopped["actual_stop"] != *stop
                || stopped["worker"] != stop["worker"]
                || resume["worker"] != stop["worker"]
                || resume["format"] != "memcordon.linux-memory-worker-resume"
                || resume["signal"] != 18
                || resume["syscall_succeeded"] != true
                || !resume["native_errno"].is_null()
                || armed["format"] != "memcordon.linux-memory-events-armed"
                || transition["format"] != "memcordon.linux-memory-events-transition"
            {
                return Err("memory native worker stop/resume/interval shapes differ".into());
            }
            for action in [stopped, armed, transition] {
                if action["revision"] != 1
                    || action["key"]
                        != serde_json::to_value(key).map_err(|error| error.to_string())?
                    || action["attempt_id"].as_str() != native.attempt_id.as_deref()
                {
                    return Err("memory native interval crosses original attempt/key".into());
                }
            }
            for field in [
                "group_device",
                "group_inode",
                "events_device",
                "events_inode",
                "maximum_device",
                "maximum_inode",
                "worker_index",
                "before",
            ] {
                if armed[field] != transition[field] || armed.get(field).is_none() {
                    return Err("memory interval native descriptor/counter source changed".into());
                }
            }
            if armed["target"]["pid"].as_u64() != native.root_pid.map(u64::from)
                || armed["target"]["birth"].as_u64() != native.root_birth
                || ["group_inode", "events_inode", "maximum_inode"]
                    .iter()
                    .any(|field| armed[*field].as_u64().is_none_or(|value| value == 0))
                || !matches!(stopped["stopped"]["state"].as_str(), Some("T" | "t"))
            {
                return Err("memory actual stopped worker/held descriptors differ".into());
            }
            let maximum: Vec<u8> = serde_json::from_value(armed["memory_max"].clone())
                .map_err(|error| error.to_string())?;
            if std::str::from_utf8(&maximum)
                .map_err(|_| "native memory.max not UTF8")?
                .trim()
                .parse::<u64>()
                .map_err(|_| "native memory.max not finite")?
                != input
                    .memory_bytes
                    .ok_or("independent selected memory budget absent")?
            {
                return Err("actual memory.max differs from selected public budget".into());
            }
            let before: Vec<u8> = serde_json::from_value(armed["before"].clone())
                .map_err(|error| error.to_string())?;
            let after: Vec<u8> = serde_json::from_value(transition["after"].clone())
                .map_err(|error| error.to_string())?;
            validate_memory_event_transition(&before, &after)?;
            facts.operations.insert("memory-limit-confirmed".into());
        }
        _ => return Err("unknown exact Linux limit scenario".into()),
    }
    Ok(Some(facts))
}

/// Independent byte effects of the selected fixture's two native streams.
/// Native capture ownership and terminal/retirement association are checked
/// separately by the installed-case route.
pub fn validate_bounded_large_streams(stdout: &[u8], stderr: &[u8]) -> Result<(), String> {
    for stream in [stdout, stderr] {
        if stream.len() != 256 * 8192
            || stream
                .iter()
                .enumerate()
                .any(|(index, byte)| *byte != (index % 256) as u8)
        {
            return Err("bounded native stream differs from complete all-byte vector".into());
        }
    }
    Ok(())
}

/// Decodes the actual cgroup-v2 memory.events byte stream without accepting a
/// supplied OOM boolean or deriving memory pressure from an exit status.
fn memory_events(bytes: &[u8]) -> Result<BTreeMap<&str, u64>, String> {
    if bytes.is_empty() || bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return Err("native memory events length/termination differs".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "native memory events are not UTF-8")?;
    let mut counters = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once(' ')
            .ok_or("native memory counter shape differs")?;
        if !matches!(
            name,
            "low" | "high" | "max" | "oom" | "oom_kill" | "oom_group_kill"
        ) || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err("native memory counter name/value differs".into());
        }
        let value = value
            .parse::<u64>()
            .map_err(|_| "native memory counter exceeds u64")?;
        if counters.insert(name, value).is_some() {
            return Err("native memory counter repeated".into());
        }
    }
    if counters.len() != 6 {
        return Err("native memory counter inventory differs".into());
    }
    Ok(counters)
}

/// The caller must independently bind both streams to the same genuinely held
/// attempt cgroup and the original controller observation interval.
pub fn validate_memory_event_transition(before: &[u8], after: &[u8]) -> Result<(), String> {
    let before = memory_events(before)?;
    let after = memory_events(after)?;
    if before["oom_kill"] != 0 || after["oom_kill"] == 0 {
        return Err("actual fresh cgroup OOM-kill transition absent".into());
    }
    if before.iter().any(|(name, value)| after[name] < *value) {
        return Err("native cumulative memory counter moved backwards".into());
    }
    if after["oom"] == 0 {
        return Err("native OOM-kill lacks actual OOM event".into());
    }
    Ok(())
}
