//! Independent verification of a private, original measured recovery operation.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[path = "../../../crates/memcordon-cli/src/bin/original_native_recovery_contract.rs"]
pub mod contract;

pub struct OriginalFixtureRecovery<'a> {
    pub invocation: &'a Value,
    pub process: &'a Value,
    pub capture: &'a Value,
    pub invocation_bytes: &'a [u8],
    pub input_bytes: &'a [u8],
    pub result_bytes: &'a [u8],
    pub owner_bytes: &'a [u8],
    pub origin_bytes: &'a [u8],
    pub stdout_bytes: &'a [u8],
    pub stderr_bytes: &'a [u8],
    pub acquisition_projection: &'a Value,
    pub acquisition_records: &'a BTreeMap<String, Vec<u8>>,
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn closed(value: &Value, fields: &[&str]) -> Result<(), String> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) {
        return Err("original fixture recovery object shape differs".into());
    }
    Ok(())
}
/// The compiler is resolved by the family from its original acquisition artifact.
pub fn validate_embedded_original_fixture_recovery(
    invocation: &Value,
    process: &Value,
    capture: &Value,
    acquisition_records: &BTreeMap<String, Vec<u8>>,
) -> Result<contract::Input, String> {
    let embedded = &invocation["original_fixture"];
    let mut fields = vec![
        "format",
        "revision",
        "capture",
        "invocation_bytes",
        "input_bytes",
        "result_bytes",
        "owner_bytes",
        "origin_bytes",
        "acquisition_projection",
    ];
    if embedded.get("acquisition_artifacts").is_some() {
        fields.push("acquisition_artifacts");
    }
    closed(embedded, &fields)?;
    if embedded["format"] != "memcordon.original-native-recovery-proof" || embedded["revision"] != 1
    {
        return Err("original fixture embedded proof format differs".into());
    }
    if embedded["capture"] != *capture {
        return Err("original fixture capture substitutes embedded actual observation".into());
    }
    let bytes = |field: &str| -> Result<Vec<u8>, String> {
        serde_json::from_value(embedded[field].clone()).map_err(|e| e.to_string())
    };
    let invocation_bytes = bytes("invocation_bytes")?;
    let inner: Value = crate::wire::decode(&invocation_bytes)?;
    let mut actual = invocation.clone();
    actual
        .as_object_mut()
        .ok_or("original fixture invocation is not an object")?
        .remove("original_fixture");
    if actual != inner {
        return Err("original fixture outer invocation substitutes original command".into());
    }
    let input_bytes = bytes("input_bytes")?;
    let result_bytes = bytes("result_bytes")?;
    let owner_bytes = bytes("owner_bytes")?;
    let origin_bytes = bytes("origin_bytes")?;
    let stdout_bytes: Vec<u8> =
        serde_json::from_value(capture["stdout"].clone()).map_err(|e| e.to_string())?;
    let stderr_bytes: Vec<u8> =
        serde_json::from_value(capture["stderr"].clone()).map_err(|e| e.to_string())?;
    validate_original_fixture_recovery(&OriginalFixtureRecovery {
        invocation: &inner,
        process,
        capture,
        invocation_bytes: &invocation_bytes,
        input_bytes: &input_bytes,
        result_bytes: &result_bytes,
        owner_bytes: &owner_bytes,
        origin_bytes: &origin_bytes,
        stdout_bytes: &stdout_bytes,
        stderr_bytes: &stderr_bytes,
        acquisition_projection: &embedded["acquisition_projection"],
        acquisition_records,
    })?;
    contract::Input::decode(&input_bytes)
}
pub fn validate_original_fixture_recovery(
    proof: &OriginalFixtureRecovery<'_>,
) -> Result<(), String> {
    let input = contract::Input::decode(proof.input_bytes)?;
    let result: contract::RecoveryResult = crate::wire::decode(proof.result_bytes)?;
    let owner: Value = crate::wire::decode(proof.owner_bytes)?;
    let origin: Value = crate::wire::decode(proof.origin_bytes)?;
    closed(
        &owner,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "scope_id",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
            "owner_path",
            "executable",
            "sha256",
            "device",
            "inode",
            "length",
            "mode",
            "compiler_output",
            "compiler_output_sha256",
            "compiler_errors",
            "compiler_errors_sha256",
            "acquisition_records",
        ],
    )?;
    closed(
        &origin,
        &["format", "revision", "original_artifact_root", "records"],
    )?;
    if proof.owner_bytes.is_empty()
        || proof.owner_bytes.len() > 1024 * 1024
        || proof.origin_bytes.is_empty()
        || proof.origin_bytes.len() > 16 * 1024 * 1024
        || proof.result_bytes.is_empty()
        || proof.result_bytes.len() > 4 * 1024 * 1024
        || proof.stdout_bytes.len() > 4 * 1024 * 1024
        || proof.stderr_bytes.len() > 4 * 1024 * 1024
    {
        return Err("original fixture recovery byte bounds differ".into());
    }
    input.validate(&input.artifact_root, result.completed_unix_millis)?;
    let invocation = proof.invocation;
    let process = proof.process;
    let capture = proof.capture;
    closed(
        invocation,
        &[
            "format",
            "revision",
            "identity",
            "native_target",
            "scope_id",
            "program",
            "arguments",
            "working_directory",
            "input_sha256",
            "harness_owner_sha256",
            "executable_sha256",
            "cleared_environment",
            "timeout_millis",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    closed(
        process,
        &[
            "format",
            "revision",
            "invocation_sha256",
            "creation",
            "native_wait_status",
            "status",
            "retirement",
            "pidfd_retirement_observed",
        ],
    )?;
    closed(
        capture,
        &[
            "format",
            "revision",
            "invocation_sha256",
            "input_sha256",
            "status",
            "native_wait_status",
            "stdout_sha256",
            "stderr_sha256",
            "stdout",
            "stderr",
        ],
    )?;
    let invocation_hash = hash(proof.invocation_bytes);
    let identity = serde_json::to_value(&input.identity).map_err(|e| e.to_string())?;
    let argv = serde_json::json!([
        "--exact",
        contract::TEST_NAME,
        "--ignored",
        "--nocapture",
        "--test-threads=1"
    ]);
    if crate::wire::decode::<Value>(proof.invocation_bytes)? != *invocation
        || invocation["format"] != "memcordon.original-native-recovery-invocation"
        || invocation["revision"] != 1
        || invocation["identity"] != identity
        || owner["identity"] != identity
        || invocation["native_target"] != input.native_target
        || owner["cell"]["target"] != input.native_target
        || invocation["scope_id"] != input.scope_id
        || owner["scope_id"] != input.scope_id
        || invocation["program"] != owner["executable"]
        || invocation["executable_sha256"] != owner["sha256"]
        || invocation["arguments"] != argv
        || invocation["working_directory"]
            != serde_json::to_value(&input.artifact_root).map_err(|e| e.to_string())?
        || invocation["input_sha256"] != hash(proof.input_bytes)
        || invocation["harness_owner_sha256"] != hash(proof.owner_bytes)
        || input.recovery_harness_owner_sha256 != hash(proof.owner_bytes)
        || invocation["cleared_environment"] != true
        || invocation["timeout_millis"] != 300000
        || owner["format"] != "memcordon.original-native-recovery-harness-owner"
        || owner["revision"] != 1
        || owner["mode"].as_u64().map(|m| m & 0o7777) != Some(0o555)
        || owner["length"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > 512 * 1024 * 1024)
    {
        return Err(
            "original fixture recovery adopts a different measured owner/invocation".into(),
        );
    }
    for field in ["work_deadline_unix_millis", "cleanup_deadline_unix_millis"] {
        let expected = if field.starts_with("work") {
            input.work_deadline_unix_millis
        } else {
            input.cleanup_deadline_unix_millis
        };
        if invocation[field] != expected || owner[field] != expected {
            return Err("original fixture recovery original cutoff differs".into());
        }
    }
    if process["format"] != "memcordon.original-native-recovery-process"
        || process["revision"] != 1
        || capture["format"] != "memcordon.original-native-recovery-capture"
        || capture["revision"] != 1
        || process["invocation_sha256"] != invocation_hash
        || capture["invocation_sha256"] != invocation_hash
        || capture["input_sha256"] != hash(proof.input_bytes)
        || process["status"] != 0
        || capture["status"] != 0
        || process["native_wait_status"] != 0
        || capture["native_wait_status"] != 0
        || process["pidfd_retirement_observed"] != true
        || process["creation"]["identity"]["pid"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > i32::MAX as u64)
        || process["creation"]["identity"]["birth"]
            .as_u64()
            .is_none_or(|n| n == 0)
        || process["creation"]["identity"]["pid"] != process["retirement"]["pid"]
        || process["creation"]["identity"]["birth"] != process["retirement"]["birth"]
        || process["retirement"]["retirement_observed"] != true
        || process["creation"]["image"]["device"] != owner["device"]
        || process["creation"]["image"]["inode"] != owner["inode"]
        || process["creation"]["image"]["sha256"] != owner["sha256"]
        || capture["stdout_sha256"] != hash(proof.stdout_bytes)
        || capture["stderr_sha256"] != hash(proof.stderr_bytes)
    {
        return Err("original fixture recovery actual process/capture differs".into());
    }
    if origin["format"] != "memcordon.original-native-recovery-origin"
        || origin["revision"] != 1
        || hash(proof.origin_bytes) != input.origin_sha256
        || origin["original_artifact_root"]
            != serde_json::to_value(&input.original_artifact_root).map_err(|e| e.to_string())?
        || origin["records"].as_object().map(|v| v.len()) != Some(input.context.records().len())
    {
        return Err("original fixture recovery staging origin differs".into());
    }
    for (role, record) in input.context.records() {
        let original = &origin["records"][role];
        closed(
            original,
            &[
                "original_path",
                "staged_path",
                "length",
                "sha256",
                "native_identity",
            ],
        )?;
        let original_path = original["original_path"]
            .as_str()
            .ok_or("original fixture source path absent")?;
        let root = input
            .original_artifact_root
            .to_str()
            .ok_or("original fixture source root is not UTF-8")?;
        let ordinary = original_path.starts_with('/')
            && original_path
                .split('/')
                .skip(1)
                .all(|p| !p.is_empty() && p != "." && p != ".." && !p.contains('\0'));
        let in_original_case = original_path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'));
        let native = original["native_identity"]
            .as_array()
            .ok_or("original fixture source native identity absent")?;
        if original["staged_path"]
            != serde_json::to_value(&record.path).map_err(|e| e.to_string())?
            || original["length"] != record.length
            || original["sha256"] != record.sha256
            || !ordinary
            || (role != "lease_owner" && !in_original_case)
            || (role == "lease_owner" && !original_path.ends_with("/lease-owner.json"))
            || native.len() != 10
            || native[3] != 0
            || native[5] != 1
            || native[2] != record.length
            || native[4]
                .as_u64()
                .is_none_or(|mode| mode & 0o170000 != 0o100000 || mode & 0o022 != 0)
        {
            return Err("original fixture recovery original record custody differs".into());
        }
    }
    if result.format != "memcordon.original-native-recovery-result"
        || result.revision != 1
        || result.input_sha256 != hash(proof.input_bytes)
        || result.identity != input.identity
        || result.context != input.context.kind()
        || result.native_target != input.native_target
        || result.scope_id != input.scope_id
        || result.recovery_harness_owner_sha256 != input.recovery_harness_owner_sha256
        || result.original_records
            != input
                .context
                .records()
                .iter()
                .map(|(role, r)| ((*role).to_string(), r.sha256.clone()))
                .collect::<Vec<_>>()
        || !result.within_original_cleanup
        || !result.outstanding.is_empty()
    {
        return Err(
            "original fixture recovery result retains obligations or substitutes originals".into(),
        );
    }
    let projection = proof.acquisition_projection;
    if projection["format"] != "memcordon.original-native-recovery-acquisition-projection"
        || projection["revision"] != 1
        || projection["owner_sha256"] != hash(proof.owner_bytes)
    {
        return Err("original fixture recovery acquisition projection differs".into());
    }
    let entries = projection["records"]
        .as_array()
        .ok_or("original fixture acquisition entries absent")?;
    let acquisitions = owner["acquisition_records"]
        .as_array()
        .ok_or("original fixture owner acquisitions absent")?;
    let owner_path = owner["owner_path"]
        .as_str()
        .ok_or("original fixture owner path absent")?;
    let parent =
        crate::linux_path::parent(owner_path).ok_or("original fixture owner parent absent")?;
    if owner_path != crate::linux_path::join(&parent, "recovery-harness-owner.json")
        || owner["compiler_output"]
            != crate::linux_path::join(&parent, "recovery-cargo-output.jsonl")
        || owner["compiler_errors"] != crate::linux_path::join(&parent, "recovery-cargo-stderr.bin")
    {
        return Err("original fixture owner acquisition paths differ".into());
    }
    if acquisitions.len() != 5
        || entries.len() != 8
        || proof.acquisition_records.len() != entries.len()
    {
        return Err("original fixture recovery acquisition inventory differs".into());
    }
    for (record, (leaf, bound)) in acquisitions.iter().zip([
        ("recovery-cargo-status.json", 1024 * 1024u64),
        ("recovery-native-host.json", 1024 * 1024u64),
        ("recovery-native-compiler.bin", 512 * 1024 * 1024u64),
        ("recovery-compiler-identity.stdout", 1024 * 1024u64),
        ("recovery-compiler-identity.stderr", 1024 * 1024u64),
    ]) {
        if record.as_array().is_none_or(|fields| fields.len() != 3)
            || record[0] != crate::linux_path::join(&parent, leaf)
            || record[2] != bound
        {
            return Err("original fixture owner fixed acquisition inventory differs".into());
        }
    }
    for (index, entry) in entries.iter().enumerate() {
        let leaf = entry["artifact"]
            .as_str()
            .ok_or("original fixture acquisition leaf absent")?;
        if leaf.contains(['/', '\\', ':', '\0']) || leaf.is_empty() {
            return Err("original fixture acquisition leaf malformed".into());
        }
        let bytes = proof
            .acquisition_records
            .get(leaf)
            .ok_or("original fixture acquisition bytes absent")?;
        let bound = if index == 5 {
            512 * 1024 * 1024
        } else {
            16 * 1024 * 1024
        };
        if bytes.len() > bound || entry["length"] != bytes.len() || entry["sha256"] != hash(bytes) {
            return Err("original fixture acquisition bytes differ".into());
        }
        let (original, digest) = match index {
            0 => (&owner["owner_path"], hash(proof.owner_bytes)),
            1 => (
                &owner["compiler_output"],
                owner["compiler_output_sha256"]
                    .as_str()
                    .ok_or("compiler output digest absent")?
                    .to_string(),
            ),
            2 => (
                &owner["compiler_errors"],
                owner["compiler_errors_sha256"]
                    .as_str()
                    .ok_or("compiler errors digest absent")?
                    .to_string(),
            ),
            n => (
                &acquisitions[n - 3][0],
                acquisitions[n - 3][1]
                    .as_str()
                    .ok_or("acquisition digest absent")?
                    .to_string(),
            ),
        };
        if entry["original"] != *original || hash(bytes) != digest {
            return Err("original fixture acquisition owner association differs".into());
        }
    }
    let status: Value = crate::wire::decode(
        proof
            .acquisition_records
            .get("acquisition-0.bin")
            .ok_or("original compiler status absent")?,
    )?;
    let host: Value = crate::wire::decode(
        proof
            .acquisition_records
            .get("acquisition-1.bin")
            .ok_or("original compiler host absent")?,
    )?;
    let source = &host["source"];
    let (commit, version) = match source["kind"].as_str() {
        Some("working") => (&source["commit"], &source["version"]),
        Some("tagged") => (&source["source"]["commit"], &source["source"]["version"]),
        _ => return Err("original recovery compiler source kind differs".into()),
    };
    if status["status"] != 0
        || status["package"] != "memcordon"
        || status["test"] != "sealed_agent"
        || status["target"] != input.native_target
        || status["features"] != "private-tcp,test-support"
        || host["format"] != "memcordon.consumer-readiness.original-native-host"
        || host["revision"] != 1
        || host["target"] != input.native_target
        || *commit != input.identity.source_commit
        || *version != input.identity.version
        || host["compiler_sha256"]
            != hash(
                proof
                    .acquisition_records
                    .get("acquisition-2.bin")
                    .ok_or("original compiler image absent")?,
            )
    {
        return Err("original fixture recovery compiler/source selection differs".into());
    }
    Ok(())
}
