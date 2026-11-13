//! Closed public projections of temporary component diagnostics. These outputs
//! are never provider receipts, command inputs, or acceptance evidence.
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const INPUT_BYTES: usize = 32 * 1024 * 1024;
pub const PROJECTION_BYTES: usize = 32 * 1024;
pub const ALLOWED_RECORDS: &[&str] = &[
    "selection.json",
    "component-case-assessment.json",
    "control-service-assessment.json",
    "control-worker-native.json",
    "held-control-worker-before.json",
    "held-before-fault.json",
    "held-frontend-before.json",
    "native-actor-retirement.json",
    "actor-exit.json",
    "native-observation.json",
    "terminal-recovery.json",
    "terminal-recovery-exit.json",
    "terminal-recovery.stderr.bin",
    "held-control-worker-exit.json",
    "held-owner-status-after-collection.txt",
    "held-after-fault.json",
    "recovery.json",
    "recovery-exit.json",
    "recovery.stderr.bin",
    "failed-collection-recovery.json",
    "failed-collection-recovery-exit.json",
    "failed-collection-recovery.stderr.bin",
    "extinction-terminal-recovery.json",
    "extinction-terminal-recovery-exit.json",
    "extinction-terminal-recovery.stderr.bin",
];

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn reference(value: &Value) -> Value {
    let bytes = serde_json::to_vec(value).expect("JSON values serialize");
    json!({"serialized_value_sha256":sha(&bytes),"serialized_value_bytes":bytes.len(),"content_omitted":true})
}
#[derive(Clone, Copy)]
enum Field {
    Boolean,
    Number,
    Digest,
    Identity,
    State,
    Fault,
    Mutant,
    RecoveryCheck,
    RecoveryChecks,
}
fn selected(value: &Value, kind: Field) -> Option<Value> {
    if value.is_null() {
        return Some(Value::Null);
    }
    match kind {
        Field::RecoveryCheck => value
            .as_str()
            .filter(|name| {
                crate::windows_readiness_components::CONTROL_RECOVERY_CHECKS.contains(name)
            })
            .map(|name| json!(name)),
        Field::RecoveryChecks => {
            let mut checks = Map::new();
            for name in crate::windows_readiness_components::CONTROL_RECOVERY_CHECKS {
                if let Some(passed) = value.get(*name).and_then(Value::as_bool) {
                    checks.insert((*name).to_owned(), json!(passed));
                }
            }
            Some(Value::Object(checks))
        }
        Field::Boolean => value.as_bool().map(Value::Bool),
        Field::Number => value
            .as_i64()
            .map(Value::from)
            .or_else(|| value.as_u64().map(Value::from)),
        Field::Digest => value
            .as_str()
            .filter(|text| text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .map(|text| json!(text)),
        Field::Identity => {
            let mut fields = Map::new();
            for key in [
                "process_id",
                "thread_id",
                "creation_time_100ns",
                "pid",
                "birth",
            ] {
                if let Some(value) = value.get(key).and_then(Value::as_u64) {
                    fields.insert(key.into(), json!(value));
                }
            }
            (!fields.is_empty()).then_some(Value::Object(fields))
        }
        Field::State => value
            .as_str()
            .filter(|text| {
                matches!(
                    *text,
                    "not-observed"
                        | "missing-prerequisite"
                        | "evaluated-false"
                        | "assessment-started"
                        | "assessed"
                        | "command-returned"
                        | "command-started"
                        | "process-not-retired"
                        | "frontend-not-retired"
                        | "process-retired"
                        | "frontend-retired"
                        | "process-status"
                        | "thread-status"
                        | "frontend-status"
                        | "loss-observation-unavailable"
                        | "Io"
                        | "Syntax"
                        | "Data"
                        | "Eof"
                        | "terminal"
                        | "reject"
                        | "other"
                        | "execution"
                        | "monitor-failed"
                        | "guardian-loss"
                        | "control-transport"
                        | "postauthorization-failure"
                        | "preauthorization"
                        | "recovery-attempt-unavailable"
                        | "frontend-lost"
                        | "worker-lost"
                        | "service-stopped"
                        | "frontend-identity-unavailable"
                        | "frontend-exit-status-unavailable"
                )
            })
            .map(|text| json!(text)),
        Field::Fault => serde_json::from_value::<memcordon_core::WindowsSealedFault>(value.clone())
            .ok()
            .and_then(|fault| serde_json::to_value(fault).ok()),
        Field::Mutant => {
            serde_json::from_value::<memcordon_core::WindowsSealedMutant>(value.clone())
                .ok()
                .and_then(|mutant| serde_json::to_value(mutant).ok())
        }
    }
}
fn fields(value: &Value, paths: &[(&str, Field)]) -> Value {
    let mut projected = Map::new();
    for (path, kind) in paths {
        let item = match value.pointer(path) {
            None => json!({"state":"missing"}),
            Some(value) => match selected(value, *kind) {
                Some(value) => json!({"state":"observed","value":value}),
                None => json!({"state":"not-public-shape","reference":reference(value)}),
            },
        };
        projected.insert((*path).into(), item);
    }
    Value::Object(projected)
}

pub fn project(name: &str, bytes: &[u8]) -> Result<Value, String> {
    if !ALLOWED_RECORDS.contains(&name) {
        return Err("component diagnostic filename is not allowlisted".into());
    }
    if bytes.len() > INPUT_BYTES {
        return Err("component diagnostic source exceeds bound".into());
    }
    let mut result = json!({"format":"memcordon.windows-component-public-diagnostic","revision":1,"diagnostic_only":true,"acceptance_authority":false,"receipt_authority":false,"record":name,"source_sha256":sha(bytes),"source_bytes":bytes.len(),"private_fields_omitted":true});
    if name.ends_with(".stderr.bin") || name.ends_with(".txt") {
        result["content_state"] = json!("opaque-content-not-exported");
    } else {
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
            .map_err(|_| "component diagnostic JSON has duplicate fields")?;
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|_| "component diagnostic JSON cannot be parsed")?;
        result["content_state"] = json!("projected");
        result["fields"] = record_fields(name, &value);
        let mut private = Map::new();
        for path in [
            "/nonce",
            "/challenge",
            "/live_nonce",
            "/provider_response/nonce",
            "/provider_response/rejection/disposition/receipt/nonce",
            "/frontend_delivery/nonce",
        ] {
            if let Some(value) = value.pointer(path) {
                private.insert(path.into(), reference(value));
            }
        }
        result["omitted_private_field_references"] = Value::Object(private);
    }
    if serde_json::to_vec(&result).map_or(true, |bytes| bytes.len() > PROJECTION_BYTES) {
        return Err("component public projection exceeds bound".into());
    }
    Ok(result)
}

fn record_fields(name: &str, value: &Value) -> Value {
    use Field::*;
    let common = &[("/revision", Number), ("/schema_version", Number)];
    let mut result = fields(value, common);
    let extra = match name {
        "control-service-assessment.json" => assessment_fields(value),
        "component-case-assessment.json" => fields(
            value,
            &[
                ("/selected_fault", Fault),
                ("/selected_mutant", Mutant),
                ("/collection_ok", Boolean),
                ("/retirement_ok", Boolean),
                ("/error_sha256", Digest),
            ],
        ),
        "control-worker-native.json" => fields(
            value,
            &[
                ("/attempt_id", Digest),
                ("/request_sha256", Digest),
                ("/fault", Fault),
                ("/process", Identity),
                ("/thread", Identity),
                ("/target_pid", Number),
                ("/target_authorization_observed", Boolean),
            ],
        ),
        "held-control-worker-before.json" => fields(
            value,
            &[
                ("/process", Identity),
                ("/thread", Identity),
                ("/target_pid", Number),
                ("/held_before_fault", Boolean),
                ("/control_service/process_id", Number),
            ],
        ),
        "held-frontend-before.json"
        | "native-actor-retirement.json"
        | "actor-exit.json"
        | "held-control-worker-exit.json"
        | "held-after-fault.json" => fields(
            value,
            &[
                ("/process_id", Number),
                ("/creation_time_100ns", Number),
                ("/process_creation_time_100ns", Number),
                ("/thread", Identity),
                ("/guardian", Identity),
                ("/target_process_id", Number),
                ("/target_creation_time_100ns", Number),
                ("/wrapper_process_id", Number),
                ("/wrapper_creation_time_100ns", Number),
                ("/native_parent_process_id", Number),
                ("/native_status", Number),
                ("/native_exit_status", Number),
                ("/process_native_exit_status", Number),
                ("/guardian_native_exit_status", Number),
                ("/target_native_exit_status", Number),
                ("/wrapper_native_status", Number),
                ("/image_sha256", Digest),
                ("/wrapper_image_sha256", Digest),
                ("/executable_sha256", Digest),
                ("/held_before_execution", Boolean),
                ("/native_live_before_release", Boolean),
                ("/held_before_fault", Boolean),
                ("/exit_observed", Boolean),
                ("/retirement_observed", Boolean),
                ("/process_retirement_observed", Boolean),
                ("/target_retired", Boolean),
                ("/guardian_retired", Boolean),
                ("/wrapper_retirement_observed", Boolean),
                ("/capture_complete", Boolean),
            ],
        ),
        "held-before-fault.json" => fields(
            value,
            &[
                ("/association/attempt_id", Digest),
                ("/association/request_sha256", Digest),
                ("/live_target_identity", Identity),
                ("/guardian_identity", Identity),
                ("/worker_process_identity", Identity),
                ("/worker_thread_identity", Identity),
            ],
        ),
        name if name.ends_with("-exit.json") => fields(
            value,
            &[
                ("/invocation_sha256", Digest),
                ("/stdout_sha256", Digest),
                ("/stderr_sha256", Digest),
                ("/native_status", Number),
            ],
        ),
        "selection.json" => fields(value, &[("/fault", Fault), ("/mutant", Mutant)]),
        _ => response_fields(value),
    };
    result
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    result
}

fn assessment_fields(value: &Value) -> Value {
    use Field::*;
    fields(
        value,
        &[
            ("/selected_fault", Fault),
            ("/attempt_id", Digest),
            ("/request_sha256", Digest),
            ("/final_rejected", Boolean),
            ("/collection_succeeded", Boolean),
            ("/settlement_succeeded", Boolean),
            ("/loss/state", State),
            ("/loss/site_sha256", Digest),
            ("/loss/association_sha256", Digest),
            ("/loss/process", Identity),
            ("/loss/thread", Identity),
            ("/loss/frontend", Identity),
            ("/loss/process_retired", Boolean),
            ("/loss/frontend_retired", Boolean),
            ("/loss/process_status", Number),
            ("/loss/thread_status", Number),
            ("/loss/frontend_status", Number),
            ("/loss/query_error_code", Number),
            ("/loss/query_phase", State),
            ("/loss/query_failed", Boolean),
            ("/loss/loss_observation_present", Boolean),
            ("/loss/skipped_reason", State),
            ("/recovery/state", State),
            ("/recovery/command_attempted", Boolean),
            ("/recovery/native_status", Number),
            ("/recovery/command_success", Boolean),
            ("/recovery/stdout_sha256", Digest),
            ("/recovery/stdout_bytes", Number),
            ("/recovery/stderr_sha256", Digest),
            ("/recovery/stderr_bytes", Number),
            ("/recovery/loss_observation_present", Boolean),
            ("/recovery/delivery_present", Boolean),
            ("/recovery/delivery_parsed", Boolean),
            ("/recovery/delivery_parse_error", State),
            ("/recovery/response_variant", State),
            ("/recovery/receipt_present", Boolean),
            ("/recovery/selected_control_guardian_original", Boolean),
            ("/recovery/authority_assessment/accepted", Boolean),
            (
                "/recovery/authority_assessment/first_failed_check",
                RecoveryCheck,
            ),
            (
                "/recovery/authority_assessment/first_failed_check_state",
                State,
            ),
            ("/recovery/authority_assessment/evaluated_checks", Number),
            (
                "/recovery/authority_assessment/remaining_checks_not_evaluated",
                Boolean,
            ),
            ("/recovery/authority_assessment/checks", RecoveryChecks),
            ("/recovery/authority_assessment/authority_bytes", Number),
            ("/recovery/authority_assessment/authority_sha256", Digest),
            (
                "/recovery/authority_assessment/delivery_terminal_bytes",
                Number,
            ),
            (
                "/recovery/authority_assessment/delivery_terminal_sha256",
                Digest,
            ),
            ("/recovery/skipped_reason", State),
        ],
    )
}

fn response_fields(value: &Value) -> Value {
    use Field::*;
    let mut result = fields(
        value,
        &[
            ("/attempt_id", Digest),
            ("/request_sha256", Digest),
            ("/provider_response/kind", State),
            ("/provider_response/attempt_id", Digest),
            ("/provider_response/request_sha256", Digest),
            ("/provider_response/rejection/schema_version", Number),
            ("/provider_response/rejection/os_code", Number),
            ("/provider_response/rejection/target_created", Boolean),
            ("/provider_response/rejection/target_released", Boolean),
            ("/provider_response/rejection/cleanup_attempted", Boolean),
            ("/provider_response/rejection/disposition/kind", State),
            ("/provider_response/payload/kind", State),
            ("/provider_response/payload/child_pid", Number),
            ("/provider_response/payload/outcome/kind", State),
            ("/frontend_delivery/attempt_id", Digest),
            ("/frontend_delivery/request_sha256", Digest),
            ("/frontend_delivery/terminal_sha256", Digest),
            ("/frontend_delivery/retired_sha256", Digest),
            ("/frontend_delivery/terminal_validated", Boolean),
            ("/frontend_delivery/acknowledgement_observed", Boolean),
        ],
    );
    let mut references = Map::new();
    for path in [
        "/provider_response",
        "/frontend_delivery",
        "/launch",
        "/capture_failure",
        "/provider_response/rejection/provider_failure",
        "/provider_response/rejection/guardian_causal_receipt",
        "/provider_response/rejection/disposition/receipt",
        "/selection",
    ] {
        references.insert(
            path.into(),
            value
                .pointer(path)
                .map_or_else(|| json!({"state":"missing"}), reference),
        );
    }
    result["content_references"] = Value::Object(references);
    if let Some(response) = value.get("provider_response") {
        result["response_facts"] = fields(
            response,
            &[
                ("/schema_version", Number),
                ("/attempt_id", Digest),
                ("/request_sha256", Digest),
                ("/rejection/disposition/disposition", State),
            ],
        );
        let guardian = response.pointer("/rejection/guardian_causal_receipt");
        result["guardian_receipt"] = guardian.map_or_else(
            || json!({"state":"missing"}),
            |guardian| {
                fields(
                    guardian,
                    &[
                        ("/schema_version", Number),
                        ("/attempt_id", Digest),
                        ("/request_sha256", Digest),
                        ("/job_identity", Digest),
                        ("/owner_manifest_sha256", Digest),
                        ("/integrity_sha256", Digest),
                        ("/guardian_identity", Identity),
                        ("/worker_identity", Identity),
                        ("/termination_requested", Boolean),
                        ("/native_job_query_succeeded", Boolean),
                        ("/active_processes_zero_observed", Boolean),
                        ("/cleanup_trigger/trigger", State),
                        ("/cleanup_trigger/frontend", Identity),
                        ("/cleanup_trigger/native_exit_status", Number),
                    ],
                )
            },
        );
        let receipt = if response.get("kind").and_then(Value::as_str) == Some("terminal") {
            Some(response)
        } else {
            response.pointer("/rejection/disposition/receipt")
        };
        result["terminal_receipt_present"] = json!(receipt.is_some_and(|value| !value.is_null()));
        result["terminal_receipt"] = receipt.map_or_else(
            || json!({"state":"missing"}),
            |receipt| {
                fields(
                    receipt,
                    &[
                        ("/schema_version", Number),
                        ("/attempt_id", Digest),
                        ("/request_sha256", Digest),
                        ("/payload/kind", State),
                        ("/payload/child_pid", Number),
                        ("/payload/outcome/outcome", State),
                        ("/process_observation/root_identity", Identity),
                    ],
                )
            },
        );
        result["provider_failure"]=response.pointer("/rejection/provider_failure").map_or_else(||json!({"state":"missing"}),|failure| {
            match serde_json::from_value::<memcordon_core::ProviderFailureDiagnosticV1>(failure.clone()) {
                Ok(failure)=>json!({"state":"observed-closed-diagnostic","schema_version":failure.schema_version,"attempt_id":failure.attempt_id,"request_sha256":failure.request_sha256,"diagnostic_sequence":failure.diagnostic_sequence,"durable_through_sequence":failure.durable_through_sequence,"original":failure.original,"secondary":failure.secondary,"loss":failure.loss,"projection_sha256":failure.projection_sha256,"provider_binding_reference":reference(&serde_json::to_value(failure.provider_binding).expect("public binding serializes"))}),
                Err(_)=>json!({"state":"not-public-shape","reference":reference(failure)}),
            }
        });
    }
    result
}
