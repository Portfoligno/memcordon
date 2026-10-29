//! Current native component vectors with independently decoded native records.
use super::windows_component_facts::*;
use super::windows_proof::{manifest_wire_sha256, validate_job_closure_contract};
use crate::wire::{json, validate_original_failure};
use crate::*;
use serde_json::{Map, Value};
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNativeComponentReceiptV2 {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub test_name: String,
    pub native_target: String,
    pub executable_sha256: String,
    pub payload: Value,
}
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
fn validate_retained_binding(
    receipt: &WindowsNativeComponentReceiptV2,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let p = &receipt.payload;
    object(
        p,
        &[
            "kind",
            "record",
            "caller_envelope",
            "caller_identity",
            "caller_held_live",
            "baseline",
            "variants",
            "record_revision_after",
            "terminal_published",
        ],
        &[],
    )?;
    if key.family != "W-BINDING"
        || ![
            "caller-substitution",
            "attempt-substitution",
            "request-substitution",
        ]
        .contains(&key.scenario.as_str())
        || receipt.test_name
            != "windows::control_service::retained_binding_tests::authenticated_retained_binding_rejects_other_attempt_request_process_creation_and_token"
        || p["caller_held_live"] != true
        || p["terminal_published"] != false
        || p["record_revision_after"] != 0
    {
        return Err("retained binding source/live caller/side effects differ".into());
    }
    let record = json(custody.bytes(text(p, "record")?)?)?;
    let envelope = custody.bytes(text(p, "caller_envelope")?)?;
    verify_retained_binding_values(p, &record, envelope)
}

/// Checks a retained binding vector against its actual native record and token bytes.
/// Source/test provenance and held caller process joins belong to the enclosing case.
pub fn verify_retained_binding_values(
    p: &Value,
    record: &Value,
    envelope: &[u8],
) -> VerificationResult<()> {
    if p["kind"] != "binding"
        || p["caller_held_live"] != true
        || p["terminal_published"] != false
        || p["record_revision_after"] != 0
    {
        return Err("binding vector invents mutation/publication authority".into());
    }
    let baseline = &p["baseline"];
    let fields = [
        "attempt_id",
        "nonce",
        "request_sha256",
        "process_identity",
        "token_sha256",
        "accepted",
    ];
    object(baseline, &fields, &[])?;
    if record["schema_version"] != 5
        || record["record_revision"] != 0
        || !record["terminal_response_json"].is_null()
        || baseline["accepted"] != true
        || baseline["attempt_id"] != record["attempt_id"]
        || baseline["request_sha256"] != record["request_sha256"]
        || baseline["process_identity"] != record["caller_process_identity"]
        || baseline["process_identity"] != p["caller_identity"]
        || baseline["token_sha256"] != record["caller_token_sha256"]
        || baseline["token_sha256"] != sha256(envelope)
        || baseline["nonce"] != "authenticated-request-nonce"
    {
        return Err(
            "retained binding baseline differs from actual held caller and native token bytes"
                .into(),
        );
    }
    let variants = p["variants"]
        .as_array()
        .filter(|rows| rows.len() == 5)
        .ok_or("retained binding requires all five actual substitutions")?;
    let mut seen = std::collections::BTreeSet::new();
    for row in variants {
        object(row, &fields, &["changed_field"])?;
        let changed = text(row, "changed_field")?;
        if !seen.insert(changed) || row["accepted"] != false {
            return Err("binding substitution repeated or accepted".into());
        }
        let mut expected = baseline.clone();
        expected["accepted"] = Value::Bool(false);
        expected["changed_field"] = Value::String(changed.into());
        match changed {
            "attempt-id" => expected["attempt_id"] = Value::String("05".repeat(32)),
            "request-sha256" => expected["request_sha256"] = Value::String("06".repeat(32)),
            "token-sha256" => expected["token_sha256"] = Value::String("07".repeat(32)),
            "process-id" => {
                expected["process_identity"]["process_id"] = Value::from(
                    number(&baseline["process_identity"], "process_id")?
                        .checked_add(1)
                        .ok_or("PID overflow")?,
                )
            }
            "process-birth" => {
                expected["process_identity"]["creation_time_100ns"] = Value::from(
                    number(&baseline["process_identity"], "creation_time_100ns")?
                        .checked_add(1)
                        .ok_or("birth overflow")?,
                )
            }
            _ => return Err("unknown retained binding substitution".into()),
        }
        if *row != expected {
            return Err(
                "retained binding substitution changes an undeclared native binding field".into(),
            );
        }
    }
    Ok(())
}
fn validate_projection_receipt(
    receipt: &WindowsNativeComponentReceiptV2,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let payload = &receipt.payload;
    object(
        payload,
        &[
            "kind",
            "record",
            "projection",
            "original",
            "secondary_attempts",
            "availability",
        ],
        &[],
    )?;
    if key.family != "W-BINDING"
        || key.scenario != "projection-bounds"
        || receipt.test_name
            != "windows::record::record_fault_tests::native_provider_projection_preserves_original_and_reports_bounded_loss"
        || payload["secondary_attempts"] != 25
        || payload["availability"] != "available"
    {
        return Err("current projection test/scenario/observation differs".into());
    }
    let record = json(custody.bytes(text(payload, "record")?)?)?;
    let projection = json(custody.bytes(text(payload, "projection")?)?)?;
    let original = json(custody.bytes(text(payload, "original")?)?)?;
    super::windows_diagnostics::validate_projection(&projection)?;
    let journal = &record["causal_diagnostics"];
    if record["schema_version"] != 5
        || projection["provider_binding"]["generation"] != record["provider_generation"]
        || projection["attempt_id"] != record["attempt_id"]
        || projection["request_sha256"] != record["request_sha256"]
        || projection["original"] != original
        || journal["original"] != original
        || projection["secondary"] != journal["secondary"]
        || projection["loss"] != journal["loss"]
        || projection["diagnostic_sequence"] != journal["sequence"]
        || projection["durable_through_sequence"] != journal["durable_through_sequence"]
        || projection["diagnostic_sequence"] != 26
        || projection["loss"]["secondary_events_omitted"] != 17
        || projection["secondary"].as_array().map(Vec::len) != Some(8)
    {
        return Err("current diagnostic projection changed native journal binding, first cause, or bounded loss".into());
    }
    if original["observed"]["event"]["sequence"] != 1 {
        return Err("projection original is not actual first observed event".into());
    }
    for (index, event) in projection["secondary"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        if event["sequence"].as_u64()
            != Some(u64::try_from(index).map_err(|error| error.to_string())? + 2)
        {
            return Err("projection retained secondary sequence differs".into());
        }
    }
    Ok(())
}

fn validate_outbox_crash(
    receipt: &WindowsNativeComponentReceiptV2,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let p = &receipt.payload;
    object(
        p,
        &[
            "kind",
            "observations",
            "fixture_resource_claims",
            "installed_attempt_store_accessed",
        ],
        &[],
    )?;
    if key.family != "W-REPLAY"
        || !["crash-before-durable", "crash-after-durable"].contains(&key.scenario.as_str())
        || receipt.test_name
            != "windows::record::record_fault_tests::native_terminal_outbox_crash_preserves_exact_replay_boundary"
        || p["fixture_resource_claims"] != false
        || p["installed_attempt_store_accessed"] != false
    {
        return Err("native outbox crash source/scope differs".into());
    }
    let rows = p["observations"]
        .as_array()
        .filter(|rows| rows.len() == 2)
        .ok_or("outbox crash requires both actual rename boundaries")?;
    let mut phases = BTreeSet::new();
    let mut publishers = BTreeSet::new();
    for row in rows {
        object(
            row,
            &[
                "after_rename",
                "before_record",
                "after_record",
                "authority",
                "replayed_response",
                "publisher_identity",
                "publisher_held_before_input",
                "publisher_exit_status",
                "publisher_retired",
            ],
            &[],
        )?;
        let renamed = row["after_rename"]
            .as_bool()
            .ok_or("outbox crash phase absent")?;
        if !phases.insert(renamed)
            || row["publisher_held_before_input"] != true
            || row["publisher_exit_status"] != 73
            || row["publisher_retired"] != true
            || number(&row["publisher_identity"], "process_id")? == 0
            || !publishers.insert((
                number(&row["publisher_identity"], "process_id")?,
                number(&row["publisher_identity"], "creation_time_100ns")?,
            ))
        {
            return Err(
                "outbox crash lacks distinct actually held/exited native publishers".into(),
            );
        }
        let before = json(custody.bytes(text(row, "before_record")?)?)?;
        let after = json(custody.bytes(text(row, "after_record")?)?)?;
        validate_windows_record_v5(&before)?;
        validate_windows_record_v5(&after)?;
        let authority = custody.bytes(text(row, "authority")?)?;
        let authority_text = std::str::from_utf8(authority).map_err(|error| error.to_string())?;
        let wire = json(authority)?;
        if before["record_revision"] != 1
            || after["record_revision"] != if renamed { 3 } else { 2 }
            || !before["terminal_response_json"].is_null()
            || before["causal_diagnostics"] != after["causal_diagnostics"]
            || wire["schema_version"] != 4
            || wire["attempt_id"] != before["attempt_id"]
            || wire["nonce"] != before["nonce"]
            || wire["request_sha256"] != before["request_sha256"]
        {
            return Err("outbox crash changes original binding/journal or durable revision".into());
        }
        for field in [
            "attempt_id",
            "nonce",
            "request_sha256",
            "provider_generation",
            "caller_process_identity",
            "caller_token_sha256",
            "job_identity_sha256",
            "boot_identity",
            "launch_incarnation",
            "owner_manifest",
            "job_closure_contract",
        ] {
            if before[field] != after[field] {
                return Err("outbox crash changes immutable original owner association".into());
            }
        }
        if renamed {
            if after["terminal_response_json"] != authority_text
                || after["lifecycle"] != "outbox-staged"
            {
                return Err(
                    "durable terminal outbox differs from exact original authority bytes".into(),
                );
            }
            let mut replay = json(custody.bytes(text(row, "replayed_response")?)?)?;
            if let Some(rejection) = replay["rejection"].as_object_mut() {
                rejection.remove("provider_failure");
                rejection.remove("guardian_causal_receipt");
            }
            if replay != wire {
                return Err("post-crash replay differs from original terminal authority".into());
            }
        } else if !after["terminal_response_json"].is_null() || !row["replayed_response"].is_null()
        {
            return Err("pre-durable crash fabricated a terminal replay".into());
        }
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

pub(crate) fn validate_windows_component(
    receipt: &WindowsNativeComponentReceiptV2,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    if receipt.payload["kind"] == "binding-projection" {
        return validate_projection_receipt(receipt, key, custody);
    }
    if receipt.payload["kind"] == "binding" {
        return validate_retained_binding(receipt, key, custody);
    }
    if receipt.payload["kind"] == "replay-crash" {
        return validate_outbox_crash(receipt, key, custody);
    }
    let payload: CurrentNativeComponentPayload = serde_json::from_value(receipt.payload.clone())
        .map_err(|error| format!("unknown current native component payload: {error}"))?;
    match &payload {
        CurrentNativeComponentPayload::CausalCapture {
            before_journal,
            after_journal,
            first_api,
            first_return,
            first_win32_code,
            second_api,
            second_return,
            second_win32_code,
            invalid_handle_was_null,
        } => {
            if key.family != "W-CAUSAL"
                || key.scenario != "native-code-capture"
                || receipt.test_name
                    != "windows::diagnostics::causal_capture_tests::native_invalid_handle_capture_preserves_first_cause_across_phase_change"
                || first_api != "GetProcessTimes"
                || second_api != "GetExitCodeProcess"
                || *first_return != 0
                || *second_return != 0
                || *first_win32_code != 6
                || *second_win32_code != 6
                || !*invalid_handle_was_null
            {
                return Err("native causal capture exact test/API/code differs".into());
            }
            let before = json(custody.bytes(before_journal)?)?;
            let after = json(custody.bytes(after_journal)?)?;
            for journal in [&before, &after] {
                object(
                    journal,
                    &[
                        "schema_version",
                        "original",
                        "secondary",
                        "sequence",
                        "durable_through_sequence",
                        "loss",
                    ],
                    &[],
                )?;
                if number(journal, "schema_version")? != 1
                    || number(journal, "durable_through_sequence")? != 0
                    || journal.get("loss")
                        != Some(
                            &serde_json::json!({"secondary_events_omitted":0,"secondary_count_saturated":false,"persistence_failure_observed":false,"writer_unavailable":false}),
                        )
                {
                    return Err("native causal capture journal revision/loss differs".into());
                }
                validate_original_failure(
                    journal.get("original").ok_or("captured original absent")?,
                )?;
            }
            if number(&before, "sequence")? != 1
                || number(&after, "sequence")? != 2
                || before["original"] != after["original"]
            {
                return Err("second native failure replaced immutable original or sequence".into());
            }
            empty_array(&before, "secondary")?;
            let secondary = after
                .get("secondary")
                .and_then(Value::as_array)
                .ok_or("captured secondary absent")?;
            if secondary.len() != 1 {
                return Err("captured secondary cardinality differs".into());
            }
            for (event, sequence, operation, phase) in [
                (
                    &before["original"]["observed"]["event"],
                    1,
                    "read-target-exit",
                    "authorized-before-resume",
                ),
                (&secondary[0], 2, "poll-target", "monitoring"),
            ] {
                validate_original_failure(&serde_json::json!({"observed":{"event":event}}))?;
                if event["sequence"] != sequence
                    || event["origin"] != "launcher"
                    || event["category"] != "monitor"
                    || event["operation"] != operation
                    || event["code"] != "target-query"
                    || event["native_code"] != serde_json::json!({"win32":6})
                    || event["observed_phase"] != phase
                    || event["safe_detail"] != "no-additional-detail"
                    || event["detail_redacted"] != true
                    || event["detail_truncated"] != false
                    || !event["terminalization_reference"].is_null()
                {
                    return Err("actual native causal event domain/order/phase differs".into());
                }
            }
            Ok(())
        }
        CurrentNativeComponentPayload::ReplayOwnedOutbox {
            record,
            after_record,
            first_response,
            repeated_response,
            duplicate_refusal,
            nonce_refusal,
            request_refusal,
            attempt_id,
            nonce,
            request_sha256,
            fixture_resource_claims,
            installed_state_accessed,
            ack_record,
            staged_ack,
            completed_ack,
            retired_response,
            repeated_retired_response,
            active_record_refusal,
            ack_nonce_refusal,
            ack_caller_refusal,
            outbox_absent_after_ack,
            available_journal,
            expired_journal,
            expiry_record,
            retention,
            pre_expiry_clock,
            expired_clock,
            same_boot,
        } => {
            if key.family != "W-REPLAY"
                || ![
                    "durable-replay",
                    "lost-publication-response",
                    "lost-acknowledgement",
                    "expiry-authority",
                ]
                .contains(&key.scenario.as_str())
                || receipt.test_name
                    != "windows_postauthorization_retirement::suspended_postauthorization_rejection_stages_replays_and_retires_bound_outbox"
                || !*fixture_resource_claims
                || *installed_state_accessed
                || !*outbox_absent_after_ack
                || !*same_boot
                || duplicate_refusal != "attempt is not ready for a create-once terminal outbox"
                || nonce_refusal != "pending terminal response is not bound to the replay request"
                || request_refusal
                    != "pending terminal replay credentials are not bound to the exact attempt"
                || active_record_refusal != "ACK tombstone still has a durable attempt record"
                || [ack_nonce_refusal, ack_caller_refusal].iter().any(|value| {
                    value.as_str()
                        != "terminal ACK tombstone does not match authenticated replay caller"
                })
            {
                return Err("owned component replay source/refusal/ownership differs".into());
            }
            digest(attempt_id)?;
            digest(request_sha256)?;
            let bytes = custody.bytes(record)?;
            if record == after_record
                || bytes != custody.bytes(after_record)?
                || bytes != custody.bytes(expiry_record)?
                || custody.bytes(first_response)? != custody.bytes(repeated_response)?
                || custody.bytes(retired_response)? != custody.bytes(repeated_retired_response)?
            {
                return Err(
                    "owned replay/refusal/expiry or repeated ACK mutated actual committed bytes"
                        .into(),
                );
            }
            let initial = json(bytes)?;
            let response = json(custody.bytes(first_response)?)?;
            if response["kind"] != "reject"
                || response["schema_version"] != 4
                || response["rejection"]["schema_version"] != 3
                || response["rejection"]["disposition"]["disposition"]
                    != "postauthorization-failure"
            {
                return Err(
                    "current replay outbox substituted historical or receiptless native authority"
                        .into(),
                );
            }
            let terminal = &response["rejection"]["disposition"]["receipt"];
            super::windows_actors::validate_terminal_shapes(terminal)?;
            super::windows_proof::validate_windows_proof_matrix(terminal)?;
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if response[field] != initial[field] || terminal[field] != initial[field] {
                    return Err("current replay nested receipt crosses durable attempt".into());
                }
            }
            validate_windows_record_v5(&initial)?;
            if text(&initial, "attempt_id")? != attempt_id
                || text(&initial, "nonce")? != nonce
                || text(&initial, "request_sha256")? != request_sha256
                || text(&initial, "lifecycle")? != "outbox-staged"
                || text(&initial, "terminal_response_json")?.as_bytes()
                    != custody.bytes(first_response)?
            {
                return Err("owned replay durable outbox/response association differs".into());
            }
            let mut ack = json(custody.bytes(ack_record)?)?;
            validate_windows_record_v5(&ack)?;
            if text(&ack, "lifecycle")? != "ack-committed"
                || number(&ack, "record_revision")? != number(&initial, "record_revision")? + 1
            {
                return Err("owned ACK did not advance exact committed outbox".into());
            }
            for field in ["lifecycle", "record_revision", "integrity_sha256"] {
                ack[field] = initial[field].clone();
            }
            if ack != initial {
                return Err("ACK changed immutable outbox association/original".into());
            }
            let staged = json(custody.bytes(staged_ack)?)?;
            let mut completed = json(custody.bytes(completed_ack)?)?;
            object(
                &staged,
                &["attempt_id", "request_sha256", "acknowledged"],
                &[],
            )?;
            object(
                &completed,
                &["attempt_id", "request_sha256", "acknowledged"],
                &[],
            )?;
            if text(&staged, "attempt_id")? != attempt_id
                || text(&staged, "request_sha256")? != request_sha256
                || staged["acknowledged"]["retirement_complete"] != false
                || completed["acknowledged"]["retirement_complete"] != true
            {
                return Err(
                    "owned staged/completed ACK association or actual retirement differs".into(),
                );
            }
            completed["acknowledged"]["retirement_complete"] = serde_json::json!(false);
            if completed != staged {
                return Err("ACK completion rewrote its original authority".into());
            }
            let tombstone = &staged["acknowledged"];
            if tombstone["caller_process_identity"] != initial["caller_process_identity"]
                || tombstone["caller_token_sha256"] != initial["caller_token_sha256"]
                || tombstone["provider_generation"] != initial["provider_generation"]
                || tombstone["launch_incarnation"] != initial["launch_incarnation"]
                || tombstone["retired"]["nonce"] != serde_json::json!(nonce)
                || tombstone["retired"]["request_sha256"] != serde_json::json!(request_sha256)
            {
                return Err(
                    "owned ACK caller/provider/request differs from physical outbox".into(),
                );
            }
            if retention != &initial["diagnostic_retention"]
                || number(retention, "expires_monotonic_millis")? != *expired_clock
                || pre_expiry_clock.checked_add(1) != Some(*expired_clock)
                || *pre_expiry_clock < number(retention, "admitted_monotonic_millis")?
            {
                return Err("component expiry clock differs from exact declared boundary".into());
            }
            let available = json(custody.bytes(available_journal)?)?;
            let expired = json(custody.bytes(expired_journal)?)?;
            if available != initial["causal_diagnostics"]
                || expired["original"]
                    != serde_json::json!({"unavailable":{"reason":"retention-expired"}})
                || !expired["secondary"].as_array().is_some_and(Vec::is_empty)
            {
                return Err(
                    "component expiry projection differs or rewrites retained authority".into(),
                );
            }
            Ok(())
        }
        CurrentNativeComponentPayload::BindingSeed {
            before_record,
            after_record,
            replacement_observation,
            refusal,
            stores_before_refusal,
            stores_after_refusal,
        } => {
            if key.family != "W-BINDING"
                || key.scenario != "seed-replacement"
                || receipt.test_name
                    != "windows_postauthorization_retirement::terminal_seed_freezes_before_proof_and_rejects_replacement"
                || refusal != "terminal seed cannot be frozen outside retiring authority"
                || *stores_before_refusal != 1
                || *stores_after_refusal != 1
                || before_record == after_record
                || custody.bytes(before_record)? != custody.bytes(after_record)?
            {
                return Err("seed replacement mutated frozen authority or differs from exact component refusal".into());
            }
            let record = json(custody.bytes(before_record)?)?;
            validate_windows_fixture_record(&record)?;
            let seed = record
                .get("terminal_seed")
                .filter(|value| value.is_object())
                .ok_or("component frozen seed absent")?;
            object(
                seed,
                &[
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "process_observation",
                    "primary_failure",
                ],
                &[],
            )?;
            if number(seed, "schema_version")? != 2
                || text(&record, "state")? != "terminating"
                || !record.get("retirement_proof").is_some_and(Value::is_null)
                || seed.get("process_observation")
                    != Some(&json(custody.bytes(replacement_observation)?)?)
            {
                return Err("component seed replacement/proof authority differs".into());
            }
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if seed.get(field) != record.get(field) {
                    return Err("component frozen seed association differs".into());
                }
            }
            Ok(())
        }
        CurrentNativeComponentPayload::BindingProof {
            before_record,
            after_refusal_record,
            after_matching_record,
            mismatched_receipt,
            matching_receipt,
            refusal,
        } => {
            if key.family != "W-BINDING"
                || key.scenario != "proof-mismatch"
                || receipt.test_name
                    != "windows_postauthorization_retirement::frozen_seed_accepts_only_matching_later_retirement_proof"
                || refusal != "terminal proof differs from the frozen seed"
                || before_record == after_refusal_record
                || custody.bytes(before_record)? != custody.bytes(after_refusal_record)?
            {
                return Err("mismatched proof mutated frozen component authority".into());
            }
            let before = json(custody.bytes(before_record)?)?;
            let after = json(custody.bytes(after_matching_record)?)?;
            validate_windows_fixture_record(&before)?;
            validate_windows_fixture_record(&after)?;
            let matching = json(custody.bytes(matching_receipt)?)?;
            super::windows_actors::validate_terminal_shapes(&matching)?;
            super::windows_proof::validate_windows_proof_matrix(&matching)?;
            let mismatched = json(custody.bytes(mismatched_receipt)?)?;
            let mut expected_mismatch = matching.clone();
            let birth = matching
                .pointer("/process_observation/root_identity/creation_time_100ns")
                .and_then(Value::as_u64)
                .ok_or("component matching root birth absent")?;
            *expected_mismatch
                .pointer_mut("/process_observation/root_identity/creation_time_100ns")
                .ok_or("component matching root absent")? = Value::from(
                birth
                    .checked_add(1)
                    .ok_or("component root birth overflow")?,
            );
            if expected_mismatch != mismatched
                || text(&before, "lifecycle")? != "retiring"
                || text(&after, "lifecycle")? != "proof-ready"
                || !before.get("retirement_proof").is_some_and(Value::is_null)
                || after.get("retirement_proof") != matching.get("retirement_proof")
                || !before.get("terminal_seed").is_some_and(Value::is_object)
                || before.get("terminal_seed") != after.get("terminal_seed")
                || after.pointer("/terminal_seed/process_observation")
                    != matching.get("process_observation")
            {
                return Err("component matching/mismatched proof transition differs".into());
            }
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if matching.get(field) != before.get(field) {
                    return Err("component proof attempt association differs".into());
                }
            }
            let mut expected_after = before.clone();
            for field in ["lifecycle", "terminal_seed", "retirement_proof"] {
                *expected_after
                    .get_mut(field)
                    .ok_or("component staged field absent")? = after
                    .get(field)
                    .cloned()
                    .ok_or("component staged field absent")?;
            }
            if expected_after != after {
                return Err(
                    "component proof staging replaced unrelated state or original cause".into(),
                );
            }
            Ok(())
        }
        CurrentNativeComponentPayload::BindingReceiptless {
            before_record,
            after_record,
            response,
            original,
            refusal,
        } => {
            if !((key.family == "W-BINDING" && key.scenario == "receiptless-posttarget")
                || (key.family == "W-CAUSAL" && key.scenario == "receiptless-first-cause"))
                || receipt.test_name
                    != "windows_postauthorization_retirement::receiptless_posttarget_rejection_cannot_bypass_terminal_binding"
                || refusal != "terminal outbox response is not bound and consistent for the attempt"
                || before_record == after_record
            {
                return Err(
                    "receiptless response differs from exact component binding refusal".into(),
                );
            }
            let before = json(custody.bytes(before_record)?)?;
            let after = json(custody.bytes(after_record)?)?;
            validate_windows_fixture_record(&before)?;
            validate_windows_fixture_record(&after)?;
            let retained = json(custody.bytes(original)?)?;
            validate_original_failure(&retained)?;
            // 1234 is the frozen protocol vector's declared native value. This
            // component test does not establish an observed Win32 API error.
            let expected_original = serde_json::json!({"observed":{"event":{"sequence":1,"origin":"launcher",
                "category":"monitor","operation":"observe-process-identity","code":"process-inventory-observation",
                "native_code":{"win32":1234},"observed_phase":"monitoring","safe_detail":"no-additional-detail",
                "detail_redacted":true,"detail_truncated":false,"terminalization_reference":null}}});
            if retained != expected_original {
                return Err(
                    "receiptless component original differs from frozen protocol vector".into(),
                );
            }
            let rejected = json(custody.bytes(response)?)?;
            let expected_response = serde_json::json!({"kind":"reject","schema_version":4,
                "attempt_id":before["attempt_id"],"nonce":before["nonce"],"request_sha256":before["request_sha256"],
                "rejection":{"schema_version":3,"code":"MCSEALED-WINDOWS-CERTIFICATION-FAULT","phase":"retirement",
                    "detail":"synthetic preauthorization failure","os_code":5,"target_created":true,"target_released":false,
                    "cleanup_attempted":true,"restart_safety":{"direct_child_reaped":true,"workload_empty":true,
                        "helpers_reaped":true,"containment_removed":true,"containment_incapable_of_live_members":true,
                        "sealed_boundary_retired":true,"errors":[]},
                    "disposition":{"disposition":"preauthorization","terminal_ack_required":true}}});
            if rejected != expected_response {
                return Err("receiptless response differs from frozen preauthorization-shaped protocol vector".into());
            }
            if rejected.get("kind").and_then(Value::as_str) != Some("reject")
                || before.pointer("/causal_diagnostics/original") != Some(&retained)
                || after.pointer("/causal_diagnostics/original") != Some(&retained)
                || before
                    .get("terminal_response_json")
                    .is_some_and(|value| !value.is_null())
                || after
                    .get("terminal_response_json")
                    .is_some_and(|value| !value.is_null())
            {
                return Err(
                    "receiptless response replaced original or published terminal authority".into(),
                );
            }
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if rejected.get(field) != before.get(field) {
                    return Err("receiptless response component association differs".into());
                }
            }
            let secondary = after
                .pointer("/causal_diagnostics/secondary")
                .and_then(Value::as_array)
                .ok_or("receiptless secondary absent")?;
            if secondary.len() != 1 {
                return Err("receiptless component secondary cardinality differs".into());
            }
            validate_receiptless_cause(&retained, &secondary[0])?;
            if secondary.len() != 1
                || secondary[0]["operation"] != "validate-terminal-response"
                || secondary[0]["terminalization_reference"] != "first-error"
                || secondary[0]["sequence"] != 2
                || secondary[0]["category"] != "terminalization"
                || secondary[0]["code"] != "terminal-binding"
                || secondary[0]["observed_phase"] != "terminalizing"
                || secondary[0]["native_code"] != Value::Null
                || secondary[0]["origin"] != "launcher"
                || secondary[0]["safe_detail"] != "no-additional-detail"
                || secondary[0]["detail_redacted"] != true
                || secondary[0]["detail_truncated"] != false
            {
                return Err(
                    "receiptless response lacks exact first-error terminalization observation"
                        .into(),
                );
            }
            let mut expected_diagnostics = before["causal_diagnostics"].clone();
            if expected_diagnostics["sequence"] != 1
                || expected_diagnostics["secondary"] != serde_json::json!([])
            {
                return Err("receiptless component baseline has unrelated diagnostics".into());
            }
            expected_diagnostics["sequence"] = Value::from(2);
            expected_diagnostics["secondary"] = Value::from(secondary.clone());
            if expected_diagnostics != after["causal_diagnostics"] {
                return Err("receiptless refusal changed diagnostic loss or durability".into());
            }
            let terminalization = &after["terminalization"];
            if terminalization["owner"] != "launcher-worker"
                || terminalization["checkpoint"] != "retained-failure"
                || terminalization["sequence"].as_u64()
                    != before["terminalization"]["sequence"]
                        .as_u64()
                        .and_then(|n| n.checked_add(1))
                || terminalization
                    .pointer("/last_error/stage")
                    .and_then(Value::as_str)
                    != Some("response-validate")
                || terminalization
                    .pointer("/last_error/error_code")
                    .and_then(Value::as_str)
                    != Some("MCSEALED-WINDOWS-TERMINAL-RESPONSE")
            {
                return Err(
                    "receiptless refusal lacks exact retained terminalization failure".into(),
                );
            }
            let failure = &terminalization["last_error"];
            object(
                failure,
                &[
                    "stage",
                    "error_code",
                    "detail",
                    "native_code",
                    "observed_unix_millis",
                ],
                &[],
            )?;
            if failure["detail"].as_str() != Some(refusal.as_str())
                || failure["native_code"] != Value::Null
                || terminalization
                    .get("secondary_errors")
                    .is_some_and(|value| value != &serde_json::json!([]))
            {
                return Err(
                    "receiptless component terminalization invented secondary/native failure"
                        .into(),
                );
            }
            let mut expected = before.clone();
            *expected
                .get_mut("causal_diagnostics")
                .ok_or("receiptless diagnostics absent")? = after["causal_diagnostics"].clone();
            *expected
                .get_mut("terminalization")
                .ok_or("receiptless terminalization absent")? = terminalization.clone();
            if expected != after {
                return Err("receiptless refusal mutated unrelated component state".into());
            }
            Ok(())
        }
        CurrentNativeComponentPayload::BindingGeneration {
            record,
            attempt_id,
            provider_generation,
            substituted_generation,
            refusal,
        } => {
            if key.family != "W-BINDING"
                || key.scenario != "generation-substitution"
                || receipt.test_name
                    != "windows::record::record_fault_tests::native_durable_record_rejects_provider_generation_substitution"
                || refusal != "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=v5-binding"
            {
                return Err("generation substitution exact native test/refusal differs".into());
            }
            digest(attempt_id)?;
            digest(provider_generation)?;
            digest(substituted_generation)?;
            if substituted_generation != &sha256(provider_generation.as_bytes())
                || substituted_generation == provider_generation
            {
                return Err("generation substitution does not change the measured exact original generation".into());
            }
            let record = json(custody.bytes(record)?)?;
            validate_windows_record_v5(&record)?;
            if number(&record, "record_revision")? != 1
                || text(&record, "attempt_id")? != attempt_id
                || text(&record, "provider_generation")? != provider_generation
            {
                return Err(
                    "generation substitution record/attempt/source generation differs".into(),
                );
            }
            Ok(())
        }
        CurrentNativeComponentPayload::WriterFrozen { observations } => {
            if key.family != "W-WRITER"
                || key.scenario != "frozen-live"
                || receipt.test_name
                    != "windows::record::record_fault_tests::frozen_native_publication_does_not_own_workload_job_cleanup"
                || observations.len() != 2
            {
                return Err("frozen writer exact native test/rows differ".into());
            }
            let owners: BTreeSet<_> = observations
                .iter()
                .map(|row| row.cleanup_owner.as_str())
                .collect();
            if owners != BTreeSet::from(["guardian", "worker"]) {
                return Err("frozen writer omits/duplicates cleanup owner".into());
            }
            for row in observations {
                if row.job_active_before != 2
                    || row.job_active_after != 0
                    || row.job_members.len() != 2
                    || !row.writer_frozen_during_cleanup
                    || row.cleanup_publication_confirmed
                    || !row.guardian_retired_during_cleanup
                    || row.worker_retired_during_cleanup != (row.cleanup_owner == "guardian")
                {
                    return Err(
                        "frozen writer conflates cleanup publication with native Job retirement"
                            .into(),
                    );
                }
                let mut identities = BTreeSet::new();
                for member in &row.job_members {
                    if member.identity.process_id == 0
                        || member.identity.creation_time_100ns == 0
                        || !member.held_before_cleanup
                        || !member.retirement_observed
                        || !identities.insert((
                            member.identity.process_id,
                            member.identity.creation_time_100ns,
                        ))
                    {
                        return Err(
                            "frozen writer actual held Job members missing/duplicated".into()
                        );
                    }
                }
                for identity in [&row.worker_identity, &row.guardian_identity] {
                    if identity.process_id == 0
                        || identity.creation_time_100ns == 0
                        || !identities.insert((identity.process_id, identity.creation_time_100ns))
                    {
                        return Err("frozen writer owner native identity absent/aliased".into());
                    }
                }
                let record = json(custody.bytes(&row.after_record)?)?;
                validate_windows_record_v5(&record)?;
                let original = json(custody.bytes(&row.original)?)?;
                validate_original_failure(&original)?;
                if number(&record, "record_revision")? != 1
                    || record.pointer("/cleanup_state/termination_requested")
                        != Some(&Value::Bool(false))
                    || record.pointer("/causal_diagnostics/original") != Some(&original)
                {
                    return Err(
                        "frozen writer changed original or invented confirmed cleanup publication"
                            .into(),
                    );
                }
            }
            Ok(())
        }
        CurrentNativeComponentPayload::WriterReservation {
            attempt_id,
            request_sha256,
            owner_identity,
            owner_held_live_during_refusal,
            before_reservation,
            after_refusal_reservation,
            retirement_without_local_proof,
            writer_frozen_during_refusal,
            writer_joined_before_retirement,
            published_record,
            local_writer_retirement_proved,
            reservation_absent_after_retirement,
        } => {
            if key.family != "W-WRITER"
                || key.scenario != "settlement-reservation"
                || receipt.test_name
                    != "windows::record::record_fault_tests::native_settlement_reservation_requires_local_writer_retirement"
                || !owner_held_live_during_refusal
                || !writer_frozen_during_refusal
                || !writer_joined_before_retirement
                || !local_writer_retirement_proved
                || !reservation_absent_after_retirement
                || owner_identity.process_id == 0
                || owner_identity.creation_time_100ns == 0
                || retirement_without_local_proof
                    != "cannot release a live writer reservation without local retirement proof"
            {
                return Err(
                    "writer settlement lacks actual local retirement/held refusal sequence".into(),
                );
            }
            digest(attempt_id)?;
            digest(request_sha256)?;
            let before = custody.bytes(before_reservation)?;
            let after = custody.bytes(after_refusal_reservation)?;
            if before_reservation == after_refusal_reservation || before != after {
                return Err("live writer refusal mutated reservation".into());
            }
            let reservation = json(before)?;
            object(
                &reservation,
                &[
                    "format",
                    "revision",
                    "attempt_id",
                    "request_sha256",
                    "owner_process_identities",
                    "workload_reservation",
                ],
                &[],
            )?;
            if text(&reservation, "format")? != "memcordon.windows-admission-record"
                || number(&reservation, "revision")? != 1
                || text(&reservation, "attempt_id")? != attempt_id
                || text(&reservation, "request_sha256")? != request_sha256
                || reservation.get("workload_reservation") != Some(&Value::Bool(true))
                || reservation.get("owner_process_identities")
                    != Some(&serde_json::json!([owner_identity]))
            {
                return Err("writer admission reservation native owner/binding differs".into());
            }
            let published = json(custody.bytes(published_record)?)?;
            validate_windows_record_v5(&published)?;
            if number(&published, "record_revision")? != 1
                || text(&published, "attempt_id")? != attempt_id
                || text(&published, "request_sha256")? != request_sha256
            {
                return Err("joined writer publication reservation association differs".into());
            }
            Ok(())
        }
        CurrentNativeComponentPayload::Writer { observations } => {
            if key.family != "W-WRITER" {
                return Err(
                    "publication matrix substituted another native component obligation".into(),
                );
            }
            let (native_test, expected_phases): (&str, &[&str]) = match key.scenario.as_str() {
                "serialization-error" | "write-error" | "readback-error" => (
                    "native_publication_fault_matrix_preserves_original_and_honest_commit_boundary",
                    &[
                        "read-previous",
                        "serialize",
                        "create-staging",
                        "write-prefix",
                        "write-remainder",
                        "flush",
                        "rename",
                        "after-rename",
                        "readback",
                    ],
                ),
                "rename-error" => (
                    "native_rename_sharing_failure_retains_typed_code_and_original",
                    &["native-sharing-rename"],
                ),
                "crash-before-durable" | "crash-after-durable" => (
                    "native_publisher_process_exit_preserves_atomic_old_or_new_record",
                    &["crash-before-rename", "crash-after-rename"],
                ),
                _ => {
                    return Err(
                        "writer payload cannot substitute frozen-live/settlement evidence".into(),
                    );
                }
            };
            if receipt.test_name != format!("windows::record::record_fault_tests::{native_test}") {
                return Err("native writer actual exact test name differs".into());
            }
            let phases: BTreeSet<_> = observations
                .iter()
                .map(|observation| observation.phase.as_str())
                .collect();
            let expected: BTreeSet<_> = expected_phases.iter().copied().collect();
            if observations.len() != expected.len() || phases != expected {
                return Err(
                    "native publication matrix omits/duplicates an actual required phase".into(),
                );
            }
            for observation in observations {
                if observation.before_record == observation.after_record {
                    return Err("publication observation compares one artifact to itself".into());
                }
                let crash = observation.phase.starts_with("crash-");
                if observation.publication_rejected == crash || observation.caller_ack_revision != 1
                {
                    return Err("native publication return/crash was conflated or caller object substituted".into());
                }
                if crash {
                    let publisher = observation
                        .publisher_process
                        .as_ref()
                        .ok_or("crash publisher held identity missing")?;
                    if publisher.process_id == 0
                        || publisher.creation_time_100ns == 0
                        || !publisher.held_before_input_delivery
                        || !publisher.retirement_observed
                        || publisher.exit_status != 73
                        || observation.native_code.is_some()
                    {
                        return Err(
                            "publisher crash lacks actual held identity/native wait73".into()
                        );
                    }
                } else if observation.publisher_process.is_some() {
                    return Err("returned-error publication invents crashed publisher".into());
                }
                if observation.phase == "native-sharing-rename"
                    && !matches!(observation.native_code.as_ref(), Some(WindowsNativeComponentCode::Win32(value)) if *value != 0)
                {
                    return Err("real native rename-sharing error code absent".into());
                }
                if observation.native_code.as_ref().is_some_and(
                    |code| !matches!(code, WindowsNativeComponentCode::Win32(value) if *value != 0),
                ) {
                    return Err("writer invents success/unknown native error code".into());
                }
                let before_bytes = custody.bytes(&observation.before_record)?;
                let after_bytes = custody.bytes(&observation.after_record)?;
                let mut before = json(before_bytes)?;
                let mut after = json(after_bytes)?;
                validate_windows_record_v5(&before)?;
                validate_windows_record_v5(&after)?;
                let original = json(custody.bytes(&observation.original)?)?;
                validate_original_failure(&original)?;
                if before.pointer("/causal_diagnostics/original") != Some(&original)
                    || after.pointer("/causal_diagnostics/original") != Some(&original)
                    || number(&before, "record_revision")? != 1
                    || number(&after, "record_revision")? != observation.persisted_revision
                {
                    return Err(
                        "publication lost actual immutable original/revision observation".into(),
                    );
                }
                if ["after-rename", "readback", "crash-after-rename"]
                    .contains(&observation.phase.as_str())
                {
                    if observation.persisted_revision != 2 {
                        return Err("post-publication failure hid committed native revision".into());
                    }
                    for record in [&mut before, &mut after] {
                        let object = record.as_object_mut().ok_or("native record not object")?;
                        object.remove("record_revision");
                        object.remove("integrity_sha256");
                    }
                    if before != after {
                        return Err(
                            "native publication changed frozen authority/first-cause payload"
                                .into(),
                        );
                    }
                } else if observation.persisted_revision != 1 || before_bytes != after_bytes {
                    return Err("prepublication failure mutated native authority".into());
                }
            }
            Ok(())
        }
    }
}

fn validate_windows_record_v5(record: &Value) -> VerificationResult<()> {
    validate_windows_record_fields(record, true)
}

fn validate_windows_fixture_record(record: &Value) -> VerificationResult<()> {
    if number(record, "record_revision")? != 0 || !text(record, "integrity_sha256")?.is_empty() {
        return Err("component fixture was promoted to durable native authority".into());
    }
    validate_windows_record_fields(record, false)
}

fn validate_windows_record_fields(record: &Value, durable: bool) -> VerificationResult<()> {
    object(
        record,
        &[
            "schema_version",
            "attempt_id",
            "provider_generation",
            "boot_identity",
            "launch_incarnation",
            "nonce",
            "request_sha256",
            "caller_process_identity",
            "caller_token_sha256",
            "job_identity_sha256",
            "guardian_identity",
            "worker_identity",
            "target_identity",
            "state",
            "lifecycle",
            "authorization_unix_millis",
            "resume_attempted",
            "target_released",
            "cleanup_state",
            "owner_manifest",
            "recovery_authorization",
            "terminal_publication_reserved",
            "terminal_seed",
            "retirement_proof",
            "terminalization",
            "causal_diagnostics",
            "diagnostic_retention",
            "record_revision",
            "provider_incarnation",
            "integrity_sha256",
        ],
        &[
            "worker_thread_identity",
            "terminal_response_json",
            "terminal_disposition",
            "job_closure_contract",
        ],
    )?;
    if number(record, "schema_version")? != 5 {
        return Err("unknown protected native record revision".into());
    }
    if record["retirement_proof"]["source"] == "capability-extinction"
        && (record["job_closure_contract"].is_null()
            || record["retirement_proof"]["capability_extinction"]["owner_manifest"]
                != record["owner_manifest"])
    {
        return Err("protected extinction proof lacks original frozen contract or owners".into());
    }
    if let Some(contract) = record
        .get("job_closure_contract")
        .filter(|value| !value.is_null())
    {
        validate_job_closure_contract(contract)?;
        for (contract_field, record_field) in [
            ("attempt_id", "attempt_id"),
            ("nonce", "nonce"),
            ("request_sha256", "request_sha256"),
            ("provider_generation", "provider_generation"),
            ("launch_incarnation", "launch_incarnation"),
            ("original_boot_id", "boot_identity"),
            ("job_identity", "job_identity_sha256"),
        ] {
            if contract[contract_field] != record[record_field] {
                return Err("protected Job closure contract crosses original record".into());
            }
        }
        if contract["owner_manifest_sha256"] != manifest_wire_sha256(&record["owner_manifest"])? {
            return Err("protected Job contract frozen manifest differs".into());
        }
        if record["retirement_proof"]["source"] == "capability-extinction"
            && record["retirement_proof"]["capability_extinction"]["contract"] != *contract
        {
            return Err("protected extinction proof substitutes closure contract".into());
        }
    }
    if ![
        "boundary-created",
        "guardian-ready",
        "target-created-suspended",
        "authorized",
        "terminating",
        "empty",
    ]
    .contains(&text(record, "state")?)
        || ![
            "executing",
            "retiring",
            "proof-ready",
            "outbox-staged",
            "ack-committed",
            "retirement-complete",
            "retained",
            "quarantined",
        ]
        .contains(&text(record, "lifecycle")?)
    {
        return Err("unknown native record authority state".into());
    }
    let cleanup = record.get("cleanup_state").ok_or("record cleanup absent")?;
    object(
        cleanup,
        &[
            "termination_requested",
            "active_processes_zero",
            "guardian_reaped",
            "final_handles_closed",
        ],
        &[],
    )?;
    for field in [
        "termination_requested",
        "active_processes_zero",
        "guardian_reaped",
        "final_handles_closed",
    ] {
        if !cleanup.get(field).is_some_and(Value::is_boolean) {
            return Err("record cleanup flag not boolean".into());
        }
    }
    let terminalization = record
        .get("terminalization")
        .ok_or("record terminalization absent")?;
    object(
        terminalization,
        &["schema_version", "owner", "sequence", "checkpoint"],
        &["last_error", "secondary_errors"],
    )?;
    if number(terminalization, "schema_version")? != 1
        || ![
            "launcher-worker",
            "control-service",
            "startup-recovery",
            "guardian-recovery",
        ]
        .contains(&text(terminalization, "owner")?)
        || ![
            "executing",
            "cleanup-requested",
            "cleanup-proof-ready",
            "rejection-building",
            "outbox-staging",
            "outbox-staged",
            "ack-retiring",
            "retained-failure",
        ]
        .contains(&text(terminalization, "checkpoint")?)
    {
        return Err("unknown native terminalization authority".into());
    }
    for field in [
        "attempt_id",
        "request_sha256",
        "caller_token_sha256",
        "job_identity_sha256",
    ] {
        digest(text(record, field)?)?;
    }
    if durable {
        digest(text(record, "integrity_sha256")?)?;
    }
    let causal = record
        .get("causal_diagnostics")
        .ok_or("native causal diagnostics missing")?;
    object(
        causal,
        &[
            "schema_version",
            "original",
            "secondary",
            "sequence",
            "durable_through_sequence",
            "loss",
        ],
        &[],
    )?;
    if number(causal, "schema_version")? != 1 {
        return Err("unknown native causal diagnostic revision".into());
    }
    validate_original_failure(
        causal
            .get("original")
            .ok_or("native original failure missing")?,
    )
}
