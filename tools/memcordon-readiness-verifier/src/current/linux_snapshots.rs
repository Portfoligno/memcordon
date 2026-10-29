//! Independent current caller-source/private snapshot byte joins.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::{ComponentBuild, VerificationResult};
use serde_json::Value;

fn bytes(value: &Value) -> VerificationResult<Vec<u8>> {
    value
        .as_array()
        .ok_or("snapshot bytes absent")?
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(|| "snapshot byte outside native range".into())
        })
        .collect()
}
fn same_file(left: &Value, right: &Value) -> bool {
    [
        "device", "inode", "uid", "gid", "mode", "links", "length", "sha256",
    ]
    .iter()
    .all(|field| left[*field] == right[*field])
}
fn same_native(left: &Value, right: &Value) -> bool {
    [
        "boot_id",
        "caller",
        "caller_uid",
        "guardian",
        "namespace_init",
        "target",
        "target_uid",
        "target_gid",
        "cgroup_device",
        "cgroup_inode",
        "mount_namespace",
        "pid_namespace",
        "network_namespace",
        "ipc_namespace",
        "root_device",
        "root_inode",
        "entrypoint_sha256",
    ]
    .iter()
    .all(|field| !left[*field].is_null() && left[*field] == right[*field])
}
fn helper_child(
    path: &str,
    helper: &Value,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    super::linux::closed(
        helper,
        &[
            "format", "revision", "request", "uid", "gid", "pid", "birth", "opened", "changed",
            "named", "restored",
        ],
    )?;
    for field in ["opened", "changed", "named"] {
        super::linux::closed(
            &helper[field],
            &[
                "device", "inode", "uid", "gid", "mode", "links", "length", "sha256", "flags",
            ],
        )?;
    }
    if helper["pid"].as_u64().is_none_or(|pid| pid == 0)
        || helper["birth"].as_u64().is_none()
        || helper["uid"].as_u64().is_none_or(|uid| uid == 0)
        || helper["gid"].as_u64().is_none_or(|gid| gid == 0)
    {
        return Err("source helper actual ordinary identity absent".into());
    }
    let prefix = path
        .strip_suffix("probe-receipt.json")
        .ok_or("source helper receipt role differs")?;
    let wait = crate::validate_json_document(&resolver(&format!("{prefix}probe-wait.json"))?)?;
    super::linux::closed(
        &wait,
        &[
            "pid",
            "birth",
            "held_before_input",
            "retired",
            "raw_wait_status",
        ],
    )?;
    if wait["pid"] != helper["pid"]
        || wait["birth"] != helper["birth"]
        || wait["held_before_input"] != true
        || wait["retired"] != true
        || wait["raw_wait_status"] != 0
    {
        return Err("source helper original Child did not settle".into());
    }
    Ok(())
}
pub fn verify_observed_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if evidence.key.family == "L-SNAPSHOT"
        && ["content-mismatch", "source-mutation-during-copy"]
            .contains(&evidence.key.scenario.as_str())
    {
        return verify_negative(evidence, input, source_commit, resolver);
    }
    if evidence.key.family == "L-SNAPSHOT" && evidence.key.scenario == "source-fd-substitution" {
        let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
        let extra = &semantic["extra"];
        let original = bytes(&extra["original_bytes"])?;
        let helper = crate::validate_json_document(&resolver(
            extra["helper_receipt"]
                .as_str()
                .ok_or("substitution source helper absent")?,
        )?)?;
        helper_child(
            extra["helper_receipt"]
                .as_str()
                .ok_or("source helper absent")?,
            &helper,
            resolver,
        )?;
        let proof = &extra["proof"];
        let permission = &proof["permission"];
        if extra["format"] != "memcordon.current-snapshot-substitution"
            || extra["revision"] != 1
            || proof["format"] != extra["format"]
            || proof["revision"] != 1
            || helper["format"] != "memcordon.current-snapshot-probe-receipt"
            || helper["revision"] != 1
            || helper["request"]["operation"] != "hold-substitute"
            || helper["uid"].as_u64().is_none_or(|uid| uid == 0)
            || permission["mechanism"] != "fanotify-open-permission"
            || permission["scope_kind"] != "file"
            || permission["record_read"] != false
            || permission["allow_written"] != true
            || !permission["allow_errno"].is_null()
            || permission["pid"] != proof["frontend"]["pid"]
            || permission["device"] != helper["opened"]["device"]
            || permission["inode"] != helper["opened"]["inode"]
            || permission["file_uid"] != helper["uid"]
            || helper["opened"] != helper["changed"]
            || !same_file(&helper["opened"], &helper["restored"])
            || helper["named"]["inode"] == helper["opened"]["inode"]
            || helper["named"]["device"] != helper["opened"]["device"]
            || helper["named"]["sha256"] == helper["opened"]["sha256"]
            || helper["named"]["length"] != helper["opened"]["length"]
            || helper["named"]["uid"] != helper["uid"]
            || proof["changed"]["file"] != helper["changed"]
            || proof["changed"]["named"] != helper["named"]
        {
            return Err(
                "native opened-FD substitution custody or distinct named replacement differs"
                    .into(),
            );
        }
        return super::linux::verify_execution(
            evidence,
            input,
            source_commit,
            resolver,
            &|rows, result, native| {
                let observed = super::linux::operation(rows, "snapshot-input-observed")?;
                if original.len() != 32
                    || bytes(&observed["bytes"])? != original
                    || result["outcome"]["kind"] != "completed"
                    || result["outcome"]["native_termination"]["code"] != 0
                    || native["caller"] != proof["frontend"]
                    || native["caller_uid"] != helper["uid"]
                    || bytes(&observed["private_bytes"])?
                        != input["challenge"]
                            .as_str()
                            .ok_or("snapshot private challenge absent")?
                            .as_bytes()
                    || ![Some(1), Some(13), Some(30)]
                        .contains(&observed["native_write_errno"].as_u64())
                {
                    return Err(
                        "native source substitution changed copied bytes or original frontend join"
                            .into(),
                    );
                }
                Ok(())
            },
        );
    }
    if evidence.key.family == "L-SNAPSHOT" && evidence.key.scenario == "concurrent-same-digest" {
        let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
        let extra = &semantic["extra"];
        if extra["format"] != "memcordon.current-snapshot-concurrent" || extra["revision"] != 1 {
            return Err("concurrent snapshot proof format differs".into());
        }
        let original = bytes(&extra["original_bytes"])?;
        if original.len() != 32 {
            return Err("concurrent snapshot input bytes absent".into());
        }
        let peer: CaseEvidenceV2 = serde_json::from_slice(&resolver(
            extra["peer_evidence"]
                .as_str()
                .ok_or("concurrent peer evidence absent")?,
        )?)
        .map_err(|error| error.to_string())?;
        if peer.key != evidence.key
            || peer.run_id != evidence.run_id
            || peer.source_commit != evidence.source_commit
            || peer.source_tree_sha256 != evidence.source_tree_sha256
            || peer.lease_id != evidence.lease_id
        {
            return Err("concurrent peer belongs to another current cell".into());
        }
        let peer_input = &extra["peer_input"];
        let mut peer_native = None;
        let mut peer_result = None;
        // The callback retains only parsed factual values, never native owners.
        let native_cell = std::cell::RefCell::new(&mut peer_native);
        let result_cell = std::cell::RefCell::new(&mut peer_result);
        super::linux::verify_execution(
            &peer,
            peer_input,
            source_commit,
            resolver,
            &|rows, result, native| {
                snapshot_rows(rows, result, peer_input, &original)?;
                **native_cell.borrow_mut() = Some(native.clone());
                **result_cell.borrow_mut() = Some(result.clone());
                Ok(())
            },
        )?;
        let peer_native = peer_native.ok_or("actual concurrent peer native facts absent")?;
        let peer_result = peer_result.ok_or("actual concurrent peer result absent")?;
        return super::linux::verify_execution(
            evidence,
            input,
            source_commit,
            resolver,
            &|rows, result, native| {
                snapshot_rows(rows, result, input, &original)?;
                if result["provider"] != peer_result["provider"]
                    || result["request"]["request_sha256"]
                        != peer_result["request"]["request_sha256"]
                    || result["workload_attempt"] == peer_result["workload_attempt"]
                    || native["target"] == peer_native["target"]
                    || (native["root_device"] == peer_native["root_device"]
                        && native["root_inode"] == peer_native["root_inode"])
                    || (native["cgroup_device"] == peer_native["cgroup_device"]
                        && native["cgroup_inode"] == peer_native["cgroup_inode"])
                {
                    return Err("same-digest attempts reused actual native identities".into());
                }
                for namespace in [
                    "mount_namespace",
                    "pid_namespace",
                    "network_namespace",
                    "ipc_namespace",
                ] {
                    if native[namespace] == peer_native[namespace] {
                        return Err("same-digest attempts shared private namespace".into());
                    }
                }
                let controller =
                    crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
                let peer_controller =
                    crate::validate_json_document(&resolver(&peer.native_observation)?)?;
                let held = &controller["intervention"];
                let peer_intervention = &peer_controller["intervention"];
                if held["format"] != "memcordon.current-snapshot-concurrent"
                    || held["revision"] != 1
                    || !same_native(&held["before"]["native"], native)
                    || !same_native(&held["peer_before"]["native"], &peer_native)
                    || peer_controller["intervention"]["other_association"]
                        != result["workload_attempt"]
                    || peer_controller["intervention"]["other_before"] != held["before"]
                {
                    return Err(
                        "same-digest concurrent native holds differ from original attempts".into(),
                    );
                }
                validate_concurrent_holds(
                    &held["before"],
                    &held["peer_before"],
                    &result["workload_attempt"],
                    &peer_result["workload_attempt"],
                    native,
                    &peer_native,
                    &peer_intervention["other_liveness"],
                    &peer_intervention["this_liveness"],
                    &held["holder_after_peer"],
                )?;
                Ok(())
            },
        );
    }
    if evidence.key.family != "L-SNAPSHOT"
        || !["caller-writable-source", "retained-writable-alias"]
            .contains(&evidence.key.scenario.as_str())
    {
        return Err("snapshot experiment has no implemented independent oracle".into());
    }
    let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
    let extra = &semantic["extra"];
    let original = bytes(&extra["original_bytes"])?;
    let changed = bytes(&extra["changed_bytes"])?;
    if extra["format"] != "memcordon.current-snapshot-source"
        || extra["revision"] != 1
        || extra["scenario"] != evidence.key.scenario
        || original.len() != 32
        || changed.len() != original.len()
        || original
            .iter()
            .zip(&changed)
            .any(|(left, right)| left ^ right != 0xff)
    {
        return Err("actual snapshot source mutation bytes differ".into());
    }
    let helper_path = extra["helper_receipt"]
        .as_str()
        .ok_or("actual source helper receipt absent")?;
    let helper = crate::validate_json_document(&resolver(helper_path)?)?;
    helper_child(helper_path, &helper, resolver)?;
    if helper["format"] != "memcordon.current-snapshot-probe-receipt"
        || helper["revision"] != 1
        || helper["uid"] != extra["source_uid"]
        || helper["gid"] != extra["source_gid"]
        || helper["uid"].as_u64().is_none_or(|uid| uid == 0)
        || helper["pid"].as_u64().is_none_or(|pid| pid == 0)
        || helper["birth"].as_u64().is_none()
        || helper["request"]["operation"] != "hold-write"
        || bytes(&helper["request"]["bytes"])? != changed
        || helper["request"]["offset"] != 0
    {
        return Err("source mutation not performed by retained ordinary caller".into());
    }
    for field in ["opened", "changed", "named"] {
        let file = &helper[field];
        if file["device"] != extra["source_device"]
            || file["inode"] != extra["source_inode"]
            || file["uid"] != extra["source_uid"]
            || file["gid"] != extra["source_gid"]
            || file["links"] != 1
            || file["mode"] != 0o100600
            || file["length"] != original.len()
            || file["flags"]
                .as_u64()
                .is_none_or(|flags| flags & 3 != if field == "named" { 0 } else { 2 })
        {
            return Err("source mutation lost original writable file identity".into());
        }
        if file["sha256"]
            != crate::sha256(if field == "opened" {
                &original
            } else {
                &changed
            })
        {
            return Err("source actual file hash differs from retained bytes".into());
        }
    }
    let wait_path = helper_path
        .strip_suffix("probe-receipt.json")
        .ok_or("source helper receipt role differs")?
        .to_owned()
        + "probe-wait.json";
    let wait = crate::validate_json_document(&resolver(&wait_path)?)?;
    if wait["pid"] != helper["pid"]
        || wait["birth"] != helper["birth"]
        || wait["held_before_input"] != true
        || wait["retired"] != true
        || wait["raw_wait_status"] != 0
    {
        return Err("original source alias Child did not settle".into());
    }
    super::linux::verify_execution(
        evidence,
        input,
        source_commit,
        resolver,
        &|rows, result, _native| {
            let before = super::linux::operation(rows, "snapshot-input-observed")?;
            let ready = super::linux::operation(rows, "snapshot-input-ready")?;
            let after = super::linux::operation(rows, "snapshot-input-after")?;
            if result["outcome"]["kind"] != "completed"
                || result["outcome"]["native_termination"]["code"] != 0
                || bytes(&before["bytes"])? != original
                || bytes(&after["bytes"])? != original
                || bytes(&ready["bytes"])? != original
                || before["device"] != after["device"]
                || before["inode"] != after["inode"]
                || before["inode"].as_u64().is_none_or(|inode| inode == 0)
                || before["path"] != "/input/snapshot.bin"
                || ![Some(1), Some(13), Some(30)].contains(&before["native_write_errno"].as_u64())
                || bytes(&before["private_bytes"])?
                    != input["challenge"]
                        .as_str()
                        .ok_or("snapshot private challenge absent")?
                        .as_bytes()
            {
                return Err("target private snapshot changed with writable caller source or private IO failed".into());
            }
            Ok(())
        },
    )
}

/// Decode only the sole current framing and independently verify every retained
/// regular member, then require one exact final input-payload mutation.
pub fn validate_bundle_mutation(
    original: &[u8],
    changed: &[u8],
    expected: &[u8],
    replacement: &[u8],
) -> VerificationResult<(Value, Value)> {
    let magic = b"memcordon.workload-bundle\0\x01";
    if !original.starts_with(magic)
        || expected.len() != 32
        || replacement.len() != expected.len()
        || original.len() != changed.len()
        || original.len() <= expected.len()
        || original[..original.len() - expected.len()] != changed[..changed.len() - expected.len()]
        || &original[original.len() - expected.len()..] != expected
        || &changed[changed.len() - replacement.len()..] != replacement
    {
        return Err("bundle mutation is not the exact original final input extent".into());
    }
    let mut position = magic.len();
    let mut manifests = Vec::new();
    for _ in 0..2 {
        let end = position.checked_add(8).ok_or("bundle header overflow")?;
        let length = u64::from_be_bytes(
            original
                .get(position..end)
                .ok_or("bundle length truncated")?
                .try_into()
                .map_err(|_| "bundle length width")?,
        );
        let length = usize::try_from(length).map_err(|_| "bundle manifest length overflow")?;
        if length > 8 * 1024 * 1024 {
            return Err("bundle manifest exceeds bound".into());
        }
        position = end;
        let end = position
            .checked_add(length)
            .ok_or("bundle manifest overflow")?;
        let raw = original
            .get(position..end)
            .ok_or("bundle manifest truncated")?;
        let manifest = crate::validate_json_document(raw)?;
        super::linux::closed(
            &manifest,
            &[
                "format",
                "revision",
                "target",
                "entries",
                "entrypoints",
                "library_directories",
            ],
        )?;
        if manifest["format"] != "memcordon.workload-snapshot" || manifest["revision"] != 1 {
            return Err("bundle snapshot format differs".into());
        }
        manifests.push(manifest);
        position = end;
    }
    if manifests[0]["target"] != manifests[1]["target"] {
        return Err("bundle snapshot targets differ".into());
    }
    for manifest in &manifests {
        let mut members = manifest["entries"]
            .as_array()
            .ok_or("bundle entry inventory absent")?
            .iter()
            .filter(|entry| entry["kind"] == "regular")
            .collect::<Vec<_>>();
        members.sort_by_key(|entry| entry["path"].as_str().unwrap_or(""));
        let mut previous = None;
        for member in members {
            let path = member["path"].as_str().ok_or("bundle member path absent")?;
            if previous == Some(path) {
                return Err("bundle member path duplicated".into());
            }
            previous = Some(path);
            let size = usize::try_from(member["size"].as_u64().ok_or("bundle member size absent")?)
                .map_err(|_| "bundle member size overflow")?;
            let end = position.checked_add(size).ok_or("bundle member overflow")?;
            let raw = original
                .get(position..end)
                .ok_or("bundle member truncated")?;
            if member["sha256"] != crate::sha256(raw) {
                return Err(
                    "original bundle regular member differs from actual manifest digest".into(),
                );
            }
            position = end;
        }
    }
    if position != original.len()
        || manifests[1]["entries"]
            != serde_json::json!([{"kind":"regular","path":"input/snapshot.bin","sha256":crate::sha256(expected),"size":expected.len(),"executable":false}])
    {
        return Err("bundle contains trailing bytes or another input member".into());
    }
    Ok((manifests.remove(0), manifests.remove(0)))
}

fn verify_negative(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let proof = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
    let read = |field: &str| {
        resolver(
            proof[field]
                .as_str()
                .ok_or_else(|| format!("snapshot {field} source absent"))?,
        )
    };
    if proof["format"] != "memcordon.current-snapshot-negative"
        || proof["revision"] != 1
        || proof["scenario"] != evidence.key.scenario
        || proof["prepared_observed"] != false
        || evidence.source_commit != source_commit
        || input["format"] != "memcordon.current-snapshot-negative-input"
        || input["revision"] != 1
        || input["run_id"] != evidence.run_id
        || input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || evidence.request.as_deref() != proof["request"].as_str()
        || Some(evidence.invocation.as_str()) != proof["start"].as_str()
    {
        return Err("corrupt snapshot source references differ".into());
    }
    let original = read("original_bundle")?;
    let changed = read("changed_bundle")?;
    let expected = bytes(&proof["original_bytes"])?;
    let replacement = bytes(&proof["changed_bytes"])?;
    if expected
        .iter()
        .zip(&replacement)
        .any(|(left, right)| left ^ right != 0xff)
    {
        return Err("snapshot corruption operand differs".into());
    }
    let (runtime, snapshot) =
        validate_bundle_mutation(&original, &changed, &expected, &replacement)?;
    if runtime != proof["runtime_snapshot"]
        || snapshot != proof["input_snapshot"]
        || runtime["target"] != evidence.key.target
        || proof["bundle_length"] != original.len()
    {
        return Err("retained bundle manifests differ from declared snapshot inputs".into());
    }
    let request_bytes = read("request")?;
    let request = crate::validate_json_document(&request_bytes)?;
    if request["runtime"]["inputs"]["runtime_digest"]
        != crate::sha256(&serde_json::to_vec(&runtime).map_err(|error| error.to_string())?)
        || request["runtime"]["inputs"]["input_digest"]
            != crate::sha256(&serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?)
    {
        return Err("corrupted stream manifests differ from authenticated request digests".into());
    }
    let digest = super::linux::request_digest(&request_bytes)?;
    let result = crate::validate_json_document(&resolver(
        evidence
            .raw_result
            .as_deref()
            .ok_or("corrupt snapshot actual result absent")?,
    )?)?;
    super::linux::closed(
        &result,
        &[
            "format",
            "revision",
            "tool",
            "invocation",
            "request",
            "provider",
            "workload_attempt",
            "release",
            "outcome",
            "cleanup",
            "delivery",
            "output_delivery",
            "diagnostics",
            "provider_failure",
            "request_rejection",
            "windows_rejection",
            "windows_attempt",
            "runtime",
        ],
    )?;
    super::linux::closed(&result["runtime"], &["kind", "profile"])?;
    super::linux::closed(
        &result["outcome"],
        &["kind", "native_termination", "wrapper_status"],
    )?;
    super::linux::closed(
        &result["request"],
        &[
            "request_sha256",
            "invocation_sha256",
            "resource_policy_sha256",
            "runtime_sha256",
            "input_sha256",
        ],
    )?;
    let association = crate::validate_json_document(&resolver(
        evidence
            .attempt_observation
            .as_deref()
            .ok_or("corrupt input original locator absent")?,
    )?)?;
    super::linux::closed(
        &association,
        &[
            "format",
            "revision",
            "attempt",
            "challenge",
            "request_sha256",
            "boot_id",
            "provider",
            "control",
        ],
    )?;
    super::linux::closed(&association["control"], &["pid", "birth"])?;
    let recovery = crate::validate_json_document(&resolver(
        evidence
            .recovery
            .as_deref()
            .ok_or("corrupt snapshot exact cleanup absent")?,
    )?)?;
    super::linux::closed(
        &recovery,
        &[
            "format",
            "revision",
            "association",
            "request",
            "release",
            "native",
            "outcome",
            "cleanup",
            "output_delivery",
            "failures",
        ],
    )?;
    let frontend = crate::validate_json_document(&read("frontend")?)?;
    if result["format"] != "memcordon.result"
        || result["revision"] != 3
        || result["release"] != "not-released"
        || result["runtime"]["kind"] != "preparation-failed"
        || result["outcome"]["kind"] != "launch-failure"
        || result["outcome"]["wrapper_status"] != 125
        || !result["outcome"]["native_termination"].is_null()
        || result["delivery"] != "complete"
        || result["request"]["request_sha256"] != digest
        || result["provider"] != input["provider"]
        || result["workload_attempt"] != association
        || association["request_sha256"] != digest
        || association["provider"] != result["provider"]
        || association["format"] != "memcordon.workload-attempt"
        || association["revision"] != 1
        || result["request"]["runtime_sha256"] != request["runtime"]["inputs"]["runtime_digest"]
        || result["request"]["input_sha256"] != request["runtime"]["inputs"]["input_digest"]
        || !resolver(&evidence.stdout)?.is_empty()
        || proof["wait"]["status"] != 125
        || proof["wait"]["raw_wait_status"] != 125 * 256
        || proof["wait"]["held_before_input"] != true
        || proof["wait"]["retired"] != true
        || frontend["format"] != "memcordon.current-original-frontend"
        || frontend["revision"] != 1
        || frontend["process"] != proof["wait"]["process"]
        || frontend["provider"] != result["provider"]
        || frontend["request_sha256"] != digest
        || frontend["caller_uid"].as_u64().is_none_or(|uid| uid == 0)
        || recovery["format"] != "memcordon.linux-workload-terminal"
        || recovery["revision"] != 1
        || recovery["association"] != association
        || recovery["request"] != result["request"]
        || recovery["release"] != "not-released"
        || !recovery["native"].is_null()
        || recovery["outcome"]["kind"] != "setup-failure"
    {
        return Err(
            "corrupted input reached execution or lost original native cleanup/binding".into(),
        );
    }
    super::linux_wire::verify_start(&read("start")?, &request, &result["request"], input)?;
    super::linux_component_lifecycle::cleanup(&result["cleanup"])?;
    super::linux_component_lifecycle::cleanup(&recovery["cleanup"])?;
    if !recovery["failures"].as_array().is_some_and(|failures| {
        failures.iter().any(|failure| {
            failure
                .as_str()
                .is_some_and(|text| text.contains("member content digest differs"))
        })
    }) {
        return Err("corrupted stream did not retain actual member-digest failure".into());
    }
    let helper = crate::validate_json_document(&read("helper_receipt")?)?;
    helper_child(
        proof["helper_receipt"]
            .as_str()
            .ok_or("source helper absent")?,
        &helper,
        resolver,
    )?;
    if helper["format"] != "memcordon.current-snapshot-probe-receipt"
        || helper["revision"] != 1
        || helper["uid"] != frontend["caller_uid"]
        || helper["gid"] != frontend["caller_gid"]
        || helper["request"]["operation"] != "hold-write"
        || helper["request"]["offset"] != original.len() - expected.len()
        || bytes(&helper["request"]["bytes"])? != replacement
        || helper["opened"]["sha256"] != crate::sha256(&original)
        || helper["changed"]["sha256"] != crate::sha256(&changed)
        || !same_file(&helper["named"], &helper["changed"])
        || helper["opened"]["device"] != helper["changed"]["device"]
        || helper["opened"]["inode"] != helper["changed"]["inode"]
        || helper["opened"]["length"] != original.len()
        || helper["opened"]["uid"] != helper["uid"]
        || helper["opened"]["mode"] != 0o100600
        || helper["opened"]["links"] != 1
    {
        return Err("corruption was not an exact ordinary retained source-file write".into());
    }
    if evidence.key.scenario == "source-mutation-during-copy" {
        let phase = &proof["phase"];
        let read = &phase["read"];
        let permission = &phase["permission"];
        let journal = &phase["journal"];
        if phase["format"] != "memcordon.current-snapshot-copy-boundary"
            || phase["revision"] != 1
            || read["format"] != "memcordon.current-source-read-stop"
            || read["revision"] != 1
            || read["process"] != frontend["process"]
            || read["source"]["device"] != helper["opened"]["device"]
            || read["source"]["inode"] != helper["opened"]["inode"]
            || read["source"]["uid"] != helper["uid"]
            || read["source"]["length"] != original.len()
            || read["read_bytes"].as_u64().is_none_or(|count| count == 0)
            || read["position"]
                .as_u64()
                .is_none_or(|position| position <= 65536 || position >= original.len() as u64)
            || read["stopped_after_native_read"] != true
            || permission["mechanism"] != "fanotify-open-permission"
            || permission["pid"] != frontend["process"]["pid"]
            || permission["device"] != helper["opened"]["device"]
            || permission["inode"] != helper["opened"]["inode"]
            || permission["allow_written"] != true
            || journal["format"] != "memcordon.private-workload-journal"
            || journal["revision"] != 1
            || journal["association"] != association
            || !journal["native"].is_null()
            || phase["journal_custody"]["uid"] != 0
            || phase["journal_custody"]["mode"] != 0o100600
            || phase["journal_custody"]["links"] != 1
            || phase["changed"]["file"] != helper["changed"]
        {
            return Err(
                "source mutation did not occur at actual original native copy read boundary".into(),
            );
        }
    } else if !proof["phase"].is_null() {
        return Err("pre-start corrupt input invented a copy phase".into());
    }
    Ok(())
}

/// Validate retained data only. This function never opens a process or native
/// resource; all observations were captured by the original case controller.
#[allow(clippy::too_many_arguments)]
pub fn validate_concurrent_holds(
    holder: &Value,
    peer: &Value,
    association: &Value,
    peer_association: &Value,
    native: &Value,
    peer_native: &Value,
    holder_live: &Value,
    peer_live: &Value,
    holder_after: &Value,
) -> VerificationResult<()> {
    let identity = |value: &Value| -> VerificationResult<(u64, u64)> {
        Ok((
            value["device"]
                .as_u64()
                .ok_or("native object device absent")?,
            value["inode"]
                .as_u64()
                .filter(|inode| *inode != 0)
                .ok_or("native object inode absent")?,
        ))
    };
    for (left, right) in [
        (
            serde_json::json!({"device":native["root_device"],"inode":native["root_inode"]}),
            serde_json::json!({"device":peer_native["root_device"],"inode":peer_native["root_inode"]}),
        ),
        (
            serde_json::json!({"device":native["cgroup_device"],"inode":native["cgroup_inode"]}),
            serde_json::json!({"device":peer_native["cgroup_device"],"inode":peer_native["cgroup_inode"]}),
        ),
    ] {
        if identity(&left)? == identity(&right)? {
            return Err("same-digest attempts share an actual native resource identity".into());
        }
    }
    if association["attempt"] == peer_association["attempt"]
        || association["challenge"] == peer_association["challenge"]
        || association["request_sha256"] != peer_association["request_sha256"]
        || association["provider"] != peer_association["provider"]
    {
        return Err(
            "concurrent observations do not name distinct original same-request attempts".into(),
        );
    }
    let mut all_processes = std::collections::BTreeSet::new();
    for (held, expected, reported, live) in [
        (holder, association, native, holder_live),
        (peer, peer_association, peer_native, peer_live),
    ] {
        super::linux::closed(
            held,
            &[
                "format",
                "revision",
                "association",
                "journal_sha256",
                "native",
                "processes",
                "root",
            ],
        )?;
        if held["format"] != "memcordon.linux-current-held"
            || held["revision"] != 1
            || held["association"] != *expected
            || !same_native(&held["native"], reported)
            || held["journal_sha256"].as_str().is_none_or(|hash| {
                hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err("concurrent held observation lost original journal/native binding".into());
        }
        super::linux::closed(&held["root"], &["device", "inode"])?;
        if identity(&held["root"])?
            != (
                reported["root_device"]
                    .as_u64()
                    .ok_or("reported root device absent")?,
                reported["root_inode"]
                    .as_u64()
                    .ok_or("reported root inode absent")?,
            )
        {
            return Err("concurrent held root differs from actual original native root".into());
        }
        let processes = held["processes"]
            .as_array()
            .filter(|rows| rows.len() == 5)
            .ok_or("all five original concurrent native process snapshots are required")?;
        let live = live
            .as_array()
            .filter(|rows| rows.len() == processes.len())
            .ok_or("all original concurrent liveness results are required")?;
        for ((process, live), role) in processes.iter().zip(live).zip([
            "worker",
            "control",
            "guardian",
            "namespace_init",
            "target",
        ]) {
            super::linux::closed(process, &["role", "snapshot", "credentials"])?;
            let snapshot = &process["snapshot"];
            super::linux::closed(
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
            let pid = snapshot["process_id"]
                .as_u64()
                .filter(|pid| *pid > 0 && *pid <= u64::from(u32::MAX))
                .ok_or("original snapshot PID absent")?;
            let birth = snapshot["birth"]
                .as_u64()
                .ok_or("original snapshot birth absent")?;
            if process["role"] != role || !all_processes.insert(pid) {
                return Err("original concurrent process role or unique PID differs".into());
            }
            let expected_process = if role == "control" {
                &expected["control"]
            } else {
                &reported[role]
            };
            if role != "worker"
                && (expected_process["pid"] != pid || expected_process["birth"] != birth)
            {
                return Err(
                    "held concurrent process differs from actual original native identity".into(),
                );
            }
            let namespace_pids = snapshot["namespace_pids"]
                .as_array()
                .filter(|rows| !rows.is_empty() && rows.len() <= 32)
                .ok_or("original namespace PID tuple absent")?;
            if namespace_pids.first().and_then(Value::as_u64) != Some(pid)
                || namespace_pids.iter().any(|pid| {
                    pid.as_u64()
                        .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
                })
            {
                return Err("original namespace PID tuple differs".into());
            }
            for (observed, field) in [
                ("user", "user_namespace"),
                ("mount", "mount_namespace"),
                ("pid", "pid_namespace"),
                ("network", "network_namespace"),
                ("ipc", "ipc_namespace"),
            ] {
                super::linux::closed(&snapshot[observed], &["device", "inode"])?;
                identity(&snapshot[observed])?;
                if ["target", "namespace_init"].contains(&role)
                    && snapshot[observed] != reported[field]
                {
                    return Err(
                        "held concurrent sandbox process escaped original namespaces".into(),
                    );
                }
            }
            if role == "target" && namespace_pids.last() != Some(&reported["target_namespace_pid"])
                || role == "namespace_init" && namespace_pids.last() != Some(&serde_json::json!(1))
            {
                return Err("held target/init namespace PID differs".into());
            }
            let credentials = &process["credentials"];
            super::linux::closed(
                credentials,
                &[
                    "uid",
                    "gid",
                    "groups",
                    "cap_effective",
                    "cap_permitted",
                    "cap_ambient",
                    "no_new_privileges",
                ],
            )?;
            for field in ["uid", "gid"] {
                let columns = credentials[field]
                    .as_array()
                    .filter(|rows| rows.len() == 4)
                    .ok_or("actual original credential columns absent")?;
                if columns.iter().any(|value| {
                    value
                        .as_u64()
                        .is_none_or(|value| value > u64::from(u32::MAX))
                }) {
                    return Err("actual native credential column outside range".into());
                }
                if role == "target"
                    && columns.iter().any(|value| {
                        value
                            != &reported[if field == "uid" {
                                "target_uid"
                            } else {
                                "target_gid"
                            }]
                    })
                {
                    return Err(
                        "actual concurrent target credentials differ from native execution".into(),
                    );
                }
            }
            let groups = credentials["groups"]
                .as_array()
                .filter(|rows| rows.len() <= 65536)
                .ok_or("actual native supplementary group inventory absent")?;
            if groups.iter().any(|value| {
                value
                    .as_u64()
                    .is_none_or(|value| value > u64::from(u32::MAX))
            }) {
                return Err("actual native group outside range".into());
            }
            for field in [
                "cap_effective",
                "cap_permitted",
                "cap_ambient",
                "no_new_privileges",
            ] {
                if credentials[field].as_u64().is_none() {
                    return Err("actual native credential state absent".into());
                }
            }
            if role == "target"
                && (!groups.is_empty()
                    || credentials["cap_effective"] != 0
                    || credentials["cap_permitted"] != 0
                    || credentials["cap_ambient"] != 0
                    || credentials["no_new_privileges"] != 1)
            {
                return Err("actual concurrent target retained privileges".into());
            }
            super::linux::closed(live, &["pid", "birth", "pidfd_readable", "native_error"])?;
            if live["pid"] != pid
                || live["birth"] != birth
                || live["pidfd_readable"] != false
                || !live["native_error"].is_null()
            {
                return Err("original concurrent process was not held live".into());
            }
        }
    }
    let holder_live = holder_live.as_array().ok_or("holder liveness absent")?;
    let after = holder_after
        .as_array()
        .filter(|rows| rows.len() == holder_live.len())
        .ok_or("original holder post-peer liveness results absent")?;
    for (before, after) in holder_live.iter().zip(after) {
        super::linux::closed(after, &["pid", "birth", "pidfd_readable", "native_error"])?;
        if before != after {
            return Err("original holder did not remain live through peer settlement".into());
        }
    }
    Ok(())
}

fn snapshot_rows(
    rows: &[Value],
    result: &Value,
    input: &Value,
    original: &[u8],
) -> VerificationResult<()> {
    let before = super::linux::operation(rows, "snapshot-input-observed")?;
    let ready = super::linux::operation(rows, "snapshot-input-ready")?;
    let after = super::linux::operation(rows, "snapshot-input-after")?;
    if result["outcome"]["kind"] != "completed"
        || result["outcome"]["native_termination"]["code"] != 0
        || bytes(&before["bytes"])? != original
        || bytes(&after["bytes"])? != original
        || bytes(&ready["bytes"])? != original
        || before["device"] != after["device"]
        || before["inode"] != after["inode"]
        || before["inode"].as_u64().is_none_or(|inode| inode == 0)
        || before["path"] != "/input/snapshot.bin"
        || ![Some(1), Some(13), Some(30)].contains(&before["native_write_errno"].as_u64())
        || bytes(&before["private_bytes"])?
            != input["challenge"]
                .as_str()
                .ok_or("snapshot private challenge absent")?
                .as_bytes()
    {
        return Err("target private snapshot changed or private IO failed".into());
    }
    Ok(())
}
pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: Option<&ProductObservationV2>,
    build: Option<&ComponentBuild>,
    version: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let product = product
        .filter(|_| build.is_none())
        .ok_or("snapshot experiment requires selected installed product")?;
    if product.key.target != evidence.key.target
        || Some(&product.key.channel) != evidence.key.channel.as_ref()
        || product.source_commit != evidence.source_commit
        || product.source_tree_sha256 != evidence.source_tree_sha256
        || product.version != version
        || evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
    {
        return Err("snapshot experiment belongs to another selected product".into());
    }
    let result = crate::validate_json_document(&resolver(
        evidence
            .raw_result
            .as_deref()
            .ok_or("snapshot actual result absent")?,
    )?)?;
    if result["provider"]["runtime_manifest_sha256"]
        != crate::sha256(&resolver(&product.runtime_manifest)?)
        || result["provider"]["generation"] != format!("{version}:{}", product.source_commit)
    {
        return Err("snapshot provider differs from selected installed bytes".into());
    }
    verify_observed_case(evidence, input, &evidence.source_commit, resolver)
}
