//! Independent diagnostic receipt decoder. Its digest detects corruption; the
//! authenticated provider response/protected producer remains its provenance.
use crate::VerificationResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    process_id: u32,
    creation_time_100ns: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "trigger", rename_all = "kebab-case", deny_unknown_fields)]
enum Trigger {
    FrontendLost {
        frontend: Identity,
        native_exit_status: u32,
    },
    WorkerLost,
    ServiceStopped,
    FrontendIdentityUnavailable,
    FrontendExitStatusUnavailable {
        frontend: Identity,
        native_code: u32,
    },
}

// Field order is the explicitly versioned native receipt canonical encoding.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    attempt_id: String,
    nonce: String,
    request_sha256: String,
    provider_generation: String,
    launch_incarnation: String,
    original_boot_id: String,
    job_identity: String,
    guardian_identity: Identity,
    worker_identity: Identity,
    owner_manifest_sha256: String,
    termination_requested: bool,
    native_job_query_succeeded: bool,
    active_processes_zero_observed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleanup_trigger: Option<Trigger>,
    observed_unix_millis: u64,
    integrity_sha256: String,
}

pub fn validate(receipt: &Value, terminal: &Value) -> VerificationResult<()> {
    let decoded: Receipt =
        serde_json::from_value(receipt.clone()).map_err(|error| error.to_string())?;
    let identity_valid =
        |identity: &Identity| identity.process_id != 0 && identity.creation_time_100ns != 0;
    if decoded.schema_version != 2
        || decoded.nonce.is_empty()
        || decoded.provider_generation.is_empty()
        || decoded.launch_incarnation.is_empty()
        || decoded.original_boot_id.is_empty()
        || !decoded.termination_requested
        || !decoded.native_job_query_succeeded
        || !decoded.active_processes_zero_observed
        || decoded.observed_unix_millis == 0
        || !identity_valid(&decoded.guardian_identity)
        || !identity_valid(&decoded.worker_identity)
        || decoded
            .cleanup_trigger
            .as_ref()
            .is_some_and(|trigger| match trigger {
                Trigger::FrontendLost { frontend, .. }
                | Trigger::FrontendExitStatusUnavailable { frontend, .. } => {
                    !identity_valid(frontend)
                }
                _ => false,
            })
    {
        return Err("guardian causal receipt native observation is inconsistent".into());
    }
    for digest in [
        &decoded.attempt_id,
        &decoded.request_sha256,
        &decoded.job_identity,
        &decoded.owner_manifest_sha256,
        &decoded.integrity_sha256,
    ] {
        crate::digest(digest)?;
    }
    let mut canonical = decoded.clone();
    canonical.integrity_sha256.clear();
    if crate::sha256(&serde_json::to_vec(&canonical).map_err(|error| error.to_string())?)
        != decoded.integrity_sha256
    {
        return Err("guardian causal receipt integrity differs".into());
    }
    let proof = &terminal["retirement_proof"];
    if receipt["attempt_id"] != terminal["attempt_id"]
        || receipt["nonce"] != terminal["nonce"]
        || receipt["request_sha256"] != terminal["request_sha256"]
        || receipt["provider_generation"] != proof["provider_generation"]
        || receipt["launch_incarnation"] != proof["launch_incarnation"]
        || receipt["original_boot_id"] != proof["original_boot_id"]
        || receipt["job_identity"] != proof["job_identity"]
        || receipt["owner_manifest_sha256"] != proof["owner_manifest_sha256"]
    {
        return Err("guardian causal receipt crosses terminal attempt".into());
    }
    Ok(())
}

// This causal alternative admits exactly the two observed effects. Other
// diagnostic histories retain their existing refusal, rather than gaining a
// generic GuardianLoss exception.
fn validate_frontend_diagnostic(failure: &Value) -> VerificationResult<()> {
    fn fields(value: &Value, expected: &[&str]) -> VerificationResult<()> {
        let object = value.as_object().ok_or("causal diagnostic object absent")?;
        if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
            return Err("causal diagnostic fields differ".into());
        }
        Ok(())
    }
    fields(
        failure,
        &[
            "schema_version",
            "provider_binding",
            "attempt_id",
            "request_sha256",
            "diagnostic_sequence",
            "durable_through_sequence",
            "original",
            "secondary",
            "loss",
            "projection_sha256",
        ],
    )?;
    let provider = &failure["provider_binding"];
    fields(
        provider,
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    fields(&failure["original"], &["observed"])?;
    fields(&failure["original"]["observed"], &["event"])?;
    let original = &failure["original"]["observed"]["event"];
    let secondary = failure["secondary"]
        .as_array()
        .ok_or("causal secondary absent")?;
    if failure["schema_version"] != 1
        || failure["diagnostic_sequence"] != 2
        || secondary.len() != 1
        || original["sequence"] != 1
        || secondary[0]["sequence"] != 2
        || failure["loss"]
            != serde_json::json!({"secondary_events_omitted":0,"secondary_count_saturated":false,"persistence_failure_observed":false,"writer_unavailable":false})
    {
        return Err("frontend causal history is incomplete or unordered".into());
    }
    let mut bytes = b"memcordon:causal-diagnostic:v1\0".to_vec();
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    for key in ["generation", "source_commit"] {
        let text = provider[key]
            .as_str()
            .filter(|text| !text.is_empty())
            .ok_or("diagnostic provider text absent")?;
        bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
    }
    for value in [
        &provider["runtime_manifest_sha256"],
        &failure["attempt_id"],
        &failure["request_sha256"],
    ] {
        let text = value.as_str().ok_or("diagnostic digest absent")?;
        crate::digest(text)?;
        bytes.extend_from_slice(&hex::decode(text).map_err(|error| error.to_string())?);
    }
    bytes.extend_from_slice(&2_u64.to_be_bytes());
    if failure["durable_through_sequence"].is_null() {
        bytes.push(0);
    } else {
        let durable = failure["durable_through_sequence"]
            .as_u64()
            .filter(|value| *value > 0 && *value <= 2)
            .ok_or("diagnostic durable sequence differs")?;
        bytes.push(1);
        bytes.extend_from_slice(&durable.to_be_bytes());
    }
    bytes.push(0); // observed original
    for (index, event) in [original, &secondary[0]].into_iter().enumerate() {
        fields(
            event,
            &[
                "sequence",
                "origin",
                "category",
                "operation",
                "code",
                "native_code",
                "observed_phase",
                "safe_detail",
                "detail_redacted",
                "detail_truncated",
                "terminalization_reference",
            ],
        )?;
        let first = index == 0;
        if event["origin"] != "launcher"
            || event["category"] != if first { "monitor" } else { "transport" }
            || event["operation"]
                != if first {
                    "check-guardian"
                } else {
                    "deliver-response"
                }
            || event["code"]
                != if first {
                    "guardian-loss"
                } else {
                    "control-transport"
                }
            || event["observed_phase"] != if first { "monitoring" } else { "cleaning" }
            || !event["terminalization_reference"].is_null()
        {
            return Err("frontend causal event vocabulary differs".into());
        }
        bytes.extend_from_slice(&((index + 1) as u64).to_be_bytes());
        for tag in if first {
            [0_u16, 2, 16, 3]
        } else {
            [0_u16, 5, 27, 7]
        } {
            bytes.extend_from_slice(&tag.to_be_bytes());
        }
        if first {
            if !event["native_code"].is_null() || event["safe_detail"] != "no-additional-detail" {
                return Err("guardian original differs".into());
            }
            bytes.push(0);
        } else {
            fields(&event["native_code"], &["win32"])?;
            let code = event["native_code"]["win32"]
                .as_u64()
                .filter(|code| matches!(code, 109 | 232 | 233))
                .ok_or("transport native code differs")?;
            bytes.push(1);
            bytes.extend_from_slice(&(code as u32).to_be_bytes());
        }
        bytes.extend_from_slice(&(if first { 3_u16 } else { 5_u16 }).to_be_bytes());
        if first {
            bytes.push(0);
        } else {
            if event["safe_detail"]
                != serde_json::json!({"injected-windows-fault":{"fault":"frontend-killed-after-authorization"}})
            {
                return Err("transport injected detail differs".into());
            }
            let fault = serde_json::to_vec("frontend-killed-after-authorization")
                .map_err(|error| error.to_string())?;
            bytes.push(3);
            bytes.extend_from_slice(&(fault.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&fault);
        }
        for key in ["detail_redacted", "detail_truncated"] {
            bytes.push(u8::from(
                event[key]
                    .as_bool()
                    .ok_or("diagnostic detail flag absent")?,
            ));
        }
        bytes.push(0);
        if first {
            bytes.extend_from_slice(&1_u64.to_be_bytes());
        }
    }
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0]);
    if failure["projection_sha256"] != crate::sha256(&bytes) {
        return Err("frontend diagnostic canonical digest differs".into());
    }
    Ok(())
}

pub fn frontend_path(
    rejection: &Value,
    terminal: &Value,
    observation: &Value,
    held_before: &Value,
    frontend_exit: &Value,
) -> VerificationResult<bool> {
    let receipt = &rejection["guardian_causal_receipt"];
    if receipt.is_null() {
        return Ok(false);
    }
    validate(receipt, terminal)?;
    crate::wire::validate_windows_proof_matrix(terminal)?;
    let cause = &receipt["cleanup_trigger"];
    let action = &observation["frontend_action"];
    let failure = &rejection["provider_failure"];
    validate_frontend_diagnostic(failure)?;
    let original = &failure["original"]["observed"]["event"];
    if terminal["payload"]["kind"] != "execution"
        || terminal["payload"]["outcome"]["outcome"] != "monitor-failed"
        || failure["provider_binding"] != observation["launch"]["expected_provider_binding"]
        || failure["attempt_id"] != terminal["attempt_id"]
        || failure["request_sha256"] != terminal["request_sha256"]
        || held_before["live_nonce"] != terminal["nonce"]
        || cause["trigger"] != "frontend-lost"
        || cause["native_exit_status"] != 0xC000013A_u32
        || cause["frontend"] != action["process"]
        || cause["frontend"]["process_id"] != frontend_exit["process_id"]
        || cause["frontend"]["creation_time_100ns"] != frontend_exit["creation_time_100ns"]
        || frontend_exit["held_before_fault"] != true
        || frontend_exit["retirement_observed"] != true
        || frontend_exit["native_status"] != cause["native_exit_status"]
        || action["kind"] != "exit-process"
        || action["requested_exit_status"] != cause["native_exit_status"]
        || action["target_authorization_observed"] != true
        || action["controller_release_observed"] != true
        || receipt["guardian_identity"] != held_before["guardian_identity"]
        || receipt["worker_identity"] != held_before["worker_process_identity"]
        || held_before["association"]["attempt_id"] != terminal["attempt_id"]
        || held_before["association"]["request_sha256"] != terminal["request_sha256"]
        || held_before["association"]["provider"]
            != observation["launch"]["expected_provider_binding"]
        || original["sequence"]
            .as_u64()
            .is_none_or(|sequence| sequence == 0)
        || original["origin"] != "launcher"
        || original["category"] != "monitor"
        || original["operation"] != "check-guardian"
        || original["code"] != "guardian-loss"
        || original["observed_phase"] != "monitoring"
        || !original["native_code"].is_null()
        || original["safe_detail"] != "no-additional-detail"
    {
        return Ok(false);
    }
    let sequence = original["sequence"]
        .as_u64()
        .expect("checked original sequence");
    Ok(failure["secondary"].as_array().is_some_and(|events|events.iter().any(|event| {
        event["sequence"].as_u64().is_some_and(|later|later>sequence)
            &&event["origin"]=="launcher"&&event["category"]=="transport"
            &&event["operation"]=="deliver-response"&&event["code"]=="control-transport"
            &&event["observed_phase"]=="cleaning"
            &&event["native_code"]["win32"].as_u64().is_some_and(|code|matches!(code,109|232|233))
            &&event["safe_detail"]==serde_json::json!({"injected-windows-fault":{"fault":"frontend-killed-after-authorization"}})
    })))
}
