//! Independent current Windows retirement source and capability inventory validation.
use crate::wire::validate_original_failure;
use crate::{VerificationResult, digest};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> VerificationResult<&'a Map<String, Value>> {
    let map = value.as_object().ok_or("expected JSON object")?;
    if required.iter().any(|field| !map.contains_key(*field))
        || map
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err("missing/unknown authority-bearing wire field".into());
    }
    Ok(map)
}
fn text<'a>(value: &'a Value, field: &str) -> VerificationResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {field}"))
}
fn number(value: &Value, field: &str) -> VerificationResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing unsigned field {field}"))
}
fn yes(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if fields
        .iter()
        .any(|field| value.get(*field) != Some(&Value::Bool(true)))
    {
        return Err("native wire obligation is not true".into());
    }
    Ok(())
}
fn empty_array(value: &Value, field: &str) -> VerificationResult<()> {
    if !value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err("wire outstanding/failure collection is not empty".into());
    }
    Ok(())
}

pub(super) fn validate_job_closure_contract(contract: &Value) -> VerificationResult<()> {
    object(
        contract,
        &[
            "schema_version",
            "attempt_id",
            "nonce",
            "request_sha256",
            "provider_generation",
            "launch_incarnation",
            "original_boot_id",
            "job_identity",
            "owner_manifest_sha256",
            "guardian_job_transfer_sha256",
            "kill_on_close_verified",
            "breakaway_denied",
            "job_handles_noninheritable",
            "closed_job_owner_set",
            "job_unnamed",
            "target_handle_list_verified",
        ],
        &[],
    )?;
    if number(contract, "schema_version")? != 2 {
        return Err("unknown Job closure contract revision".into());
    }
    for field in [
        "attempt_id",
        "request_sha256",
        "job_identity",
        "owner_manifest_sha256",
        "guardian_job_transfer_sha256",
    ] {
        digest(text(contract, field)?)?;
    }
    for field in [
        "nonce",
        "provider_generation",
        "launch_incarnation",
        "original_boot_id",
    ] {
        if text(contract, field)?.is_empty() {
            return Err("Job closure contract identity absent".into());
        }
    }
    yes(
        contract,
        &[
            "kill_on_close_verified",
            "breakaway_denied",
            "job_handles_noninheritable",
            "closed_job_owner_set",
            "job_unnamed",
            "target_handle_list_verified",
        ],
    )
}

pub(super) fn manifest_wire_sha256(manifest: &Value) -> VerificationResult<String> {
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        process_id: u32,
        creation_time_100ns: u64,
    }
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        role: String,
        present: bool,
        process_identity: Option<Identity>,
        capability_binding_sha256: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        schema_version: u32,
        attempt_id: String,
        provider_generation: String,
        launch_incarnation: String,
        entries: Vec<Entry>,
    }
    let canonical: Manifest =
        serde_json::from_value(manifest.clone()).map_err(|error| error.to_string())?;
    Ok(crate::sha256(
        &serde_json::to_vec(&canonical).map_err(|error| error.to_string())?,
    ))
}

fn validate_capability_extinction(terminal: &Value) -> VerificationResult<()> {
    let proof = &terminal["retirement_proof"];
    let witness = &proof["capability_extinction"];
    object(
        witness,
        &[
            "contract",
            "owner_manifest",
            "current_boot_id",
            "job_holder_processes_extinct",
            "target_process_extinct",
            "relay_capabilities_retired",
            "launch_gate_closed",
        ],
        &[],
    )?;
    yes(
        witness,
        &[
            "job_holder_processes_extinct",
            "target_process_extinct",
            "relay_capabilities_retired",
            "launch_gate_closed",
        ],
    )?;
    let contract = &witness["contract"];
    validate_job_closure_contract(contract)?;
    for field in [
        "attempt_id",
        "nonce",
        "request_sha256",
        "provider_generation",
        "launch_incarnation",
        "original_boot_id",
        "job_identity",
        "owner_manifest_sha256",
    ] {
        if contract[field] != proof[field] {
            return Err("extinction contract crosses original proof binding".into());
        }
    }
    if witness["current_boot_id"] != contract["original_boot_id"] {
        return Err("extinction proof crosses boot".into());
    }
    let manifest = &witness["owner_manifest"];
    object(
        manifest,
        &[
            "schema_version",
            "attempt_id",
            "provider_generation",
            "launch_incarnation",
            "entries",
        ],
        &[],
    )?;
    if manifest["schema_version"] != 2 {
        return Err("unknown extinction owner manifest".into());
    }
    for field in ["attempt_id", "provider_generation", "launch_incarnation"] {
        if manifest[field] != contract[field] {
            return Err("extinction owner manifest crosses contract".into());
        }
    }
    let roles = [
        "launcher-job",
        "active-registry-duplicate",
        "direct-target-process",
        "desktop-bootstrap-job",
        "desktop-bootstrap-process",
        "guardian-process",
        "control-relay",
        "frontend-relay",
        "broker-holder",
        "session-broker-transfer",
        "launch-gate",
    ];
    let entries = manifest["entries"]
        .as_array()
        .ok_or("extinction owner entries absent")?;
    if entries.len() != roles.len() {
        return Err("extinction owner inventory differs".into());
    }
    for (entry, role) in entries.iter().zip(roles) {
        object(
            entry,
            &[
                "role",
                "present",
                "process_identity",
                "capability_binding_sha256",
            ],
            &[],
        )?;
        let present = entry["present"]
            .as_bool()
            .ok_or("extinction owner presence malformed")?;
        let required = matches!(
            role,
            "launcher-job"
                | "active-registry-duplicate"
                | "direct-target-process"
                | "guardian-process"
                | "control-relay"
                | "frontend-relay"
                | "launch-gate"
        );
        if entry["role"] != role
            || (required && !present)
            || present == entry["capability_binding_sha256"].is_null()
            || (!present && !entry["process_identity"].is_null())
        {
            return Err("extinction owner role or presence differs".into());
        }
        if present {
            digest(text(entry, "capability_binding_sha256")?)?;
            {
                let identity = &entry["process_identity"];
                object(identity, &["process_id", "creation_time_100ns"], &[])?;
                if number(identity, "process_id")? == 0
                    || number(identity, "process_id")? > u64::from(u32::MAX)
                    || number(identity, "creation_time_100ns")? == 0
                {
                    return Err("extinction native owner identity absent".into());
                }
            }
        }
        if role == "direct-target-process"
            && entry["process_identity"] != terminal["process_observation"]["root_identity"]
        {
            return Err("extinction target root differs".into());
        }
    }
    // Wire canonicalization is independent of provider Rust types. The finite
    // schema preserves its documented declaration order for the digest.
    if manifest_wire_sha256(manifest)? != text(contract, "owner_manifest_sha256")? {
        return Err("extinction frozen manifest digest differs".into());
    }
    let safety = &terminal["restart_safety"];
    for field in [
        "direct_child_reaped",
        "helpers_reaped",
        "sealed_boundary_retired",
    ] {
        if safety[field] != false {
            return Err("extinction proof invents historical native observation".into());
        }
    }
    yes(
        safety,
        &[
            "workload_empty",
            "containment_removed",
            "containment_incapable_of_live_members",
        ],
    )?;
    empty_array(safety, "errors")?;
    Ok(())
}

pub fn validate_windows_proof_matrix(terminal: &Value) -> VerificationResult<()> {
    let proof = terminal
        .get("retirement_proof")
        .ok_or("retirement proof absent")?;
    let payload = terminal.get("payload").ok_or("terminal payload absent")?;
    object(
        proof,
        &[
            "schema_version",
            "source",
            "attempt_id",
            "nonce",
            "request_sha256",
            "provider_generation",
            "launch_incarnation",
            "original_boot_id",
            "job_identity",
            "owner_manifest_sha256",
            "target_completion_observed",
            "native_job_empty_observed",
            "relay_closure_observed",
            "guardian_completion_observed",
            "owner_capabilities_closed",
            "launch_gate_closed",
        ],
        &[
            "guardian_receipt_sha256",
            "current_boot_id",
            "capability_extinction",
        ],
    )?;
    if number(terminal, "schema_version")? != 3 || number(proof, "schema_version")? != 3 {
        return Err("current Windows terminal/proof named revision differs".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if proof[field] != terminal[field] {
            return Err("current native proof crosses terminal transaction".into());
        }
    }
    for field in ["request_sha256", "owner_manifest_sha256"] {
        digest(text(proof, field)?)?;
    }
    for field in [
        "attempt_id",
        "nonce",
        "provider_generation",
        "launch_incarnation",
        "original_boot_id",
        "job_identity",
    ] {
        if text(proof, field)?.is_empty() {
            return Err("current native proof identity absent".into());
        }
    }
    yes(proof, &["owner_capabilities_closed", "launch_gate_closed"])?;
    let absent = |field: &str| proof.get(field).is_none_or(Value::is_null);
    let facts = [
        "target_completion_observed",
        "native_job_empty_observed",
        "relay_closure_observed",
        "guardian_completion_observed",
    ];
    for field in facts {
        if !proof.get(field).is_some_and(Value::is_boolean) {
            return Err("retirement native fact is not boolean".into());
        }
    }
    if text(proof, "source")? != "capability-extinction" && !absent("capability_extinction") {
        return Err("unrelated retirement source carries extinction witness".into());
    }
    match (text(payload, "kind")?, text(proof, "source")?) {
        ("execution" | "premature-release-failure", "live-native") => {
            yes(proof, &facts)?;
            if !absent("guardian_receipt_sha256")
                || !absent("current_boot_id")
                || number(payload, "child_pid")? == 0
                || terminal.pointer("/process_observation/root_identity/process_id")
                    != payload.get("child_pid")
            {
                return Err("live-native proof contains recovery fields or wrong root".into());
            }
        }
        (
            "recovered-closure",
            source @ ("guardian-recovery" | "prior-boot" | "capability-extinction"),
        ) => {
            let original = payload
                .get("primary_failure")
                .ok_or("recovery original failure absent")?;
            validate_original_failure(original)?;
            if original
                .pointer("/unavailable/reason")
                .and_then(Value::as_str)
                == Some("no-earlier-error-observed")
                || !terminal
                    .get("cleanup_process_creation")
                    .is_none_or(Value::is_null)
            {
                return Err("recovery proof invents creation or lacks original cause".into());
            }
            if source == "capability-extinction" {
                if facts
                    .iter()
                    .any(|field| proof.get(*field) != Some(&Value::Bool(false)))
                    || !absent("guardian_receipt_sha256")
                    || !absent("current_boot_id")
                {
                    return Err("extinction proof invents native completion".into());
                }
                validate_capability_extinction(terminal)?;
            } else if source == "guardian-recovery" {
                yes(
                    proof,
                    &["native_job_empty_observed", "guardian_completion_observed"],
                )?;
                digest(text(proof, "guardian_receipt_sha256")?)?;
                if !absent("current_boot_id") {
                    return Err("guardian recovery contains prior-boot evidence".into());
                }
            } else {
                if facts
                    .iter()
                    .any(|field| proof.get(*field) != Some(&Value::Bool(false)))
                    || !absent("guardian_receipt_sha256")
                    || text(proof, "current_boot_id")?.is_empty()
                    || text(proof, "current_boot_id")? == text(proof, "original_boot_id")?
                {
                    return Err("prior-boot proof substitutes live native observations".into());
                }
            }
        }
        _ => return Err("retirement proof source/payload authority differs".into()),
    }
    Ok(())
}
