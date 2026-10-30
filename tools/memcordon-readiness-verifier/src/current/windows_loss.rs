//! Current loss evidence joins retain the original OS subject, first cause and cleanup cutoff.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::wire::{decode, json, validate_arguments, validate_original_failure};
use crate::{
    CaseKey, NativeArguments, NativeEnvironment, NativeInvocation, NativeObservation,
    OutcomeOrigin, SemanticObservation, VerificationResult, WindowsLossEvidence, custody, digest,
    sha256,
};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
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

pub(crate) fn validate_windows_loss(
    evidence: &CaseEvidenceV2,
    loss: &WindowsLossEvidence,
    provider_request_path: &str,
    native: &NativeObservation,
    key: &CaseKey,
    product: &ProductObservationV2,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let allowed = key.target.ends_with("windows-msvc")
        && ((key.family == "W-RETIREMENT"
            && [
                "frontend-loss",
                "control-service-loss",
                "attempt-worker-loss",
            ]
            .contains(&key.scenario.as_str()))
            || (key.family == "C-LIFETIME"
                && ["frontend-loss", "service-loss", "worker-loss", "recovery"]
                    .contains(&key.scenario.as_str()))
            || (key.family == "W-REPLAY" && key.scenario == "public-recovery-after-loss"));
    if !allowed || native.origin != OutcomeOrigin::ProviderFailure {
        return Err("external loss substituted into another row/origin".into());
    }
    custody.bytes(&loss.stdout)?;
    custody.bytes(&loss.stderr)?;
    if let Some(path) = &loss.capture_failure
        && custody.bytes(path)?.is_empty()
    {
        return Err("empty loss capture failure".into());
    }
    let action = json(custody.bytes(&loss.action)?)?;
    object(
        &action,
        &[
            "format",
            "revision",
            "kind",
            "process",
            "thread",
            "native_requested_status",
            "subject_role",
            "image_sha256",
            "subject_held_before_action",
            "action_completed",
        ],
        &["control_service"],
    )?;
    if text(&action, "format")? != "memcordon.windows-native-loss-action"
        || number(&action, "revision")? != 1
        || number(&action, "native_requested_status")? != 126
    {
        return Err("native loss action format/status differs".into());
    }
    yes(&action, &["subject_held_before_action", "action_completed"])?;
    let worker = ["attempt-worker-loss", "worker-loss"].contains(&key.scenario.as_str());
    let frontend = key.scenario == "frontend-loss";
    let role = if worker {
        "attempt-worker"
    } else if frontend {
        "frontend"
    } else {
        "control-service"
    };
    if text(&action, "subject_role")? != role
        || text(&action, "kind")?
            != if worker {
                "terminate-thread"
            } else {
                "terminate-process"
            }
    {
        return Err("native loss subject/action differs".into());
    }
    let selected = product
        .components
        .iter()
        .find(|c| {
            c.role
                == if frontend {
                    "public-cli"
                } else {
                    "sealed-agent"
                }
        })
        .ok_or("loss subject selected image missing")?;
    if text(&action, "image_sha256")? != selected.installed_sha256 {
        return Err("fault subject image differs from installed selection".into());
    }
    let process = action
        .get("process")
        .ok_or("fault subject identity absent")?;
    object(process, &["process_id", "creation_time_100ns"], &[])?;
    if number(process, "process_id")? == 0
        || number(process, "creation_time_100ns")? == 0
        || process.get("process_id").and_then(Value::as_u64) == native.root_pid.map(u64::from)
    {
        return Err("fault subject identity absent or target substituted".into());
    }
    if !worker && !frontend {
        let scm = action
            .get("control_service")
            .ok_or("control service native SCM observation absent")?;
        object(scm, &["name", "process_id", "current_state"], &[])?;
        if text(scm, "name")? != "MemCordonSealedControl"
            || scm.get("process_id") != process.get("process_id")
            || number(scm, "current_state")? != 4
        {
            return Err("control service fault acted on another/nonrunning SCM process".into());
        }
    } else if action.get("control_service").is_some() {
        return Err("nonservice loss invented SCM authority".into());
    }
    let family = json(custody.bytes(&loss.native_family_retirement)?)?;
    object(
        &family,
        &[
            "format",
            "revision",
            "attempt_id",
            "nonce",
            "request_sha256",
            "root_pid",
            "root_birth",
            "processes",
        ],
        &[],
    )?;
    if text(&family, "format")? != "memcordon.windows-native-family-retirement"
        || number(&family, "revision")? != 1
        || family.get("attempt_id").and_then(Value::as_str) != native.attempt_id.as_deref()
        || family.get("nonce").and_then(Value::as_str) != native.attempt_nonce.as_deref()
        || family.get("request_sha256").and_then(Value::as_str) != native.request_sha256.as_deref()
        || family.get("root_pid").and_then(Value::as_u64) != native.root_pid.map(u64::from)
        || family.get("root_birth").and_then(Value::as_u64) != native.root_birth
    {
        return Err("native loss held-family raw association differs".into());
    }
    let processes = family
        .get("processes")
        .and_then(Value::as_array)
        .ok_or("native loss family members absent")?;
    if processes.len() != 2 || native.held_processes.len() != 2 {
        return Err("native loss requires independently held root and descendant".into());
    }
    let mut members = BTreeSet::new();
    for member in processes {
        object(
            member,
            &[
                "pid",
                "birth",
                "parent_pid",
                "parent_birth",
                "held_before_action",
                "retirement_observed",
            ],
            &[],
        )?;
        yes(member, &["held_before_action", "retirement_observed"])?;
        let pid =
            u32::try_from(number(member, "pid")?).map_err(|_| "native loss PID outside bound")?;
        let birth = number(member, "birth")?;
        if pid == 0 || birth == 0 || !members.insert((pid, birth)) {
            return Err("native loss family identity missing/duplicated".into());
        }
        let expected = native
            .held_processes
            .iter()
            .find(|held| (held.pid, held.birth) == (pid, birth))
            .ok_or("native loss raw member not independently held")?;
        if !expected.retirement_observed
            || member.get("parent_pid")
                != Some(&serde_json::to_value(expected.parent_pid).map_err(|e| e.to_string())?)
            || member.get("parent_birth")
                != Some(&serde_json::to_value(expected.parent_birth).map_err(|e| e.to_string())?)
        {
            return Err("native loss member parent/retirement differs".into());
        }
        if Some(pid) == native.root_pid {
            if expected.parent_pid.is_some() || expected.parent_birth.is_some() {
                return Err("native loss root invents parent authority".into());
            }
        } else if expected.parent_pid != native.root_pid
            || expected.parent_birth != native.root_birth
            || native.root_birth.is_none_or(|root| root > birth)
        {
            return Err("native loss descendant ancestry/birth differs".into());
        }
    }
    let live = json(custody.bytes(&loss.live_observation)?)?;
    object(
        &live,
        &[
            "format",
            "revision",
            "challenge",
            "guardian_identity",
            "association",
        ],
        &[
            "live_nonce",
            "live_target_identity",
            "worker_process_identity",
            "worker_thread_identity",
        ],
    )?;
    let semantic: SemanticObservation = decode(custody.bytes(&evidence.semantic_observation)?)?;
    if text(&live, "format")? != "memcordon.windows-live-guardian-observation"
        || number(&live, "revision")? != 1
        || text(&live, "challenge")? != hex::encode(custody.bytes(&semantic.challenge)?)
    {
        return Err("live loss observation revision/challenge differs".into());
    }
    for field in [
        "guardian_identity",
        "live_target_identity",
        "worker_process_identity",
    ] {
        if let Some(identity) = live.get(field).filter(|value| !value.is_null()) {
            object(identity, &["process_id", "creation_time_100ns"], &[])?;
            if number(identity, "process_id")? == 0 || number(identity, "creation_time_100ns")? == 0
            {
                return Err("live fault native process identity absent".into());
            }
        }
    }
    let association = live
        .get("association")
        .ok_or("live loss association absent")?;
    object(
        association,
        &["provider", "attempt_id", "request_sha256"],
        &[],
    )?;
    let provider = association.get("provider").ok_or("live provider absent")?;
    object(
        provider,
        &["generation", "source_commit", "runtime_manifest_sha256"],
        &[],
    )?;
    if provider.get("generation").and_then(Value::as_str) != native.provider_generation.as_deref()
        || provider.get("source_commit").and_then(Value::as_str)
            != Some(product.source_commit.as_str())
        || provider
            .get("runtime_manifest_sha256")
            .and_then(Value::as_str)
            != native.runtime_manifest_sha256.as_deref()
    {
        return Err("live loss provider differs from installed selection".into());
    }
    if association.get("attempt_id").and_then(Value::as_str) != native.attempt_id.as_deref()
        || association.get("request_sha256").and_then(Value::as_str)
            != native.request_sha256.as_deref()
        || live.get("live_nonce").and_then(Value::as_str) != native.attempt_nonce.as_deref()
        || live
            .pointer("/live_target_identity/process_id")
            .and_then(Value::as_u64)
            != native.root_pid.map(u64::from)
        || live
            .pointer("/live_target_identity/creation_time_100ns")
            .and_then(Value::as_u64)
            != native.root_birth
    {
        return Err("live fault root/transaction differs from held native identity".into());
    }
    if worker {
        if live.get("worker_process_identity") != Some(process)
            || live.get("worker_thread_identity") != action.get("thread")
            || action.get("thread").is_none_or(Value::is_null)
        {
            return Err("native worker fault did not act on exact live worker".into());
        }
        let thread = action.get("thread").ok_or("native worker thread absent")?;
        object(thread, &["thread_id", "creation_time_100ns"], &[])?;
        if number(thread, "thread_id")? == 0 || number(thread, "creation_time_100ns")? == 0 {
            return Err("native fault worker thread identity absent".into());
        }
    } else if !action.get("thread").is_none_or(Value::is_null) {
        return Err("process loss invented worker thread".into());
    }
    let provider_request = custody.bytes(provider_request_path)?;
    if native.request_sha256.as_deref() != Some(sha256(provider_request).as_str()) {
        return Err("loss actual request bytes differ from authenticated association".into());
    }
    let invocation: NativeInvocation = decode(custody.bytes(&evidence.invocation)?)?;
    validate_windows_request(
        provider_request,
        custody.bytes(
            evidence
                .request
                .as_deref()
                .ok_or("loss requested contract absent")?,
        )?,
        &invocation,
        custody.bytes(&invocation.environment)?,
    )?;
    let actual_request = json(provider_request)?;
    if actual_request.get("expected_provider_binding") != Some(provider)
        || actual_request.get("nonce") != live.get("live_nonce")
    {
        return Err("loss actual request differs from live provider/nonce".into());
    }
    if let Some(path) = &loss.original_result {
        let original = json(custody.bytes(path)?)?;
        super::windows::result(&original)?;
        if original["windows_attempt"] != *association
            || original["provider"] != *provider
            || original["outcome"]["kind"] != "provider-failure"
            || original["release"] == "not-released"
        {
            return Err(
                "current loss original result changes actual released attempt/provider/cause"
                    .into(),
            );
        }
        if let Some(diagnostic) = original
            .get("provider_failure")
            .filter(|value| !value.is_null())
        {
            if diagnostic["provider_binding"] != *provider
                || diagnostic["attempt_id"] != association["attempt_id"]
                || diagnostic["request_sha256"] != association["request_sha256"]
            {
                return Err("current original causal projection crosses native attempt".into());
            }
            validate_original_failure(&diagnostic["original"])?;
        }
    }
    let recovery = json(custody.bytes(&loss.recovery)?)?;
    let owner = json(custody.bytes(&loss.original_lease_owner)?)?;
    let deadlines = json(custody.bytes(&loss.original_deadlines)?)?;
    object(
        &owner,
        &[
            "format",
            "revision",
            "identity",
            "key",
            "current",
            "binary_root",
            "state_root",
            "diagnostics_root",
            "artifact_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
        &[],
    )?;
    object(
        &deadlines,
        &[
            "format",
            "revision",
            "identity",
            "key",
            "artifact_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
        &[],
    )?;
    object(
        &owner["identity"],
        &["run_id", "source_commit", "source_tree_sha256", "version"],
        &[],
    )?;
    object(&owner["key"], &["target", "channel"], &[])?;
    if owner["format"] != "memcordon.consumer-readiness.windows-lease-owner"
        || owner["revision"] != 2
        || deadlines["format"] != "memcordon.consumer-readiness.windows-original-deadlines"
        || deadlines["revision"] != 1
        || owner["identity"] != deadlines["identity"]
        || owner["key"] != serde_json::to_value(&product.key).map_err(|e| e.to_string())?
        || owner["key"] != deadlines["key"]
        || owner["artifact_root"] != deadlines["artifact_root"]
        || owner["identity"]["run_id"] != evidence.run_id
        || owner["identity"]["source_commit"] != evidence.source_commit
        || owner["identity"]["source_tree_sha256"] != evidence.source_tree_sha256
        || owner["identity"]["version"] != product.version
    {
        return Err("loss recovery original installation owner/deadline source differs".into());
    }
    let work = number(&deadlines, "work_deadline_unix_millis")?;
    let cleanup = number(&deadlines, "cleanup_deadline_unix_millis")?;
    if work == 0
        || cleanup.checked_sub(work) != Some(15 * 60 * 1000)
        || owner["work_deadline_unix_millis"] != work
        || owner["cleanup_deadline_unix_millis"] != cleanup
    {
        return Err("loss recovery renewed original work/cleanup cutoffs".into());
    }
    let current = &owner["current"];
    object(
        current,
        &[
            "channel",
            "source_commit",
            "version",
            "target",
            "artifacts",
            "cli",
            "agent",
            "components",
            "installed_components",
            "fixture",
            "installed_agent",
            "installed_manifest",
            "provider",
            "output_directory",
        ],
        &[],
    )?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("loss recovery original CLI selection absent")?;
    object(&current["cli"], &["path", "sha256"], &[])?;
    let native_path = |value: &Value| -> VerificationResult<String> {
        let path = value.as_str().ok_or("loss original native path absent")?;
        if path.len() < 3
            || !path.as_bytes()[0].is_ascii_alphabetic()
            || path.as_bytes()[1] != b':'
            || path[2..].contains(':')
            || !matches!(path.as_bytes()[2], b'\\' | b'/')
            || path.contains('\0')
            || path
                .split(['\\', '/'])
                .any(|component| matches!(component, "." | ".."))
        {
            return Err("loss original native path malformed/escaping".into());
        }
        Ok(path.to_owned())
    };
    let artifact_root = native_path(&owner["artifact_root"])?;
    for path in [&current["output_directory"], &current["cli"]["path"]] {
        let path = native_path(path)?;
        if path
            .strip_prefix(artifact_root.trim_end_matches(['\\', '/']))
            .is_none_or(|suffix| !suffix.starts_with(['\\', '/']))
        {
            return Err(
                "loss original selected recovery command escapes original artifact lifetime".into(),
            );
        }
    }
    let installed_channel = match key.channel.as_deref() {
        Some("candidate-native" | "public-native") => "native-bundle",
        Some("candidate-cargo" | "public-cargo") => "cargo-package",
        _ => return Err("loss original installed channel absent/unknown".into()),
    };
    if current["source_commit"] != evidence.source_commit
        || current["version"] != product.version
        || current["target"] != key.target
        || current["channel"] != installed_channel
        || current["provider"] != *provider
        || current["cli"]["sha256"] != cli.installed_sha256
    {
        return Err("loss recovery selected original CLI/provider differs".into());
    }
    let command_bytes = custody.bytes(&loss.recovery_invocation)?;
    let command = json(command_bytes)?;
    object(
        &command,
        &[
            "format",
            "revision",
            "target",
            "source_commit",
            "executable_sha256",
            "program_utf16",
            "argv_utf16",
            "cwd_utf16",
            "environment_cleared",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
            "started_unix_millis",
            "budget_millis",
            "recovery_deadline_unix_millis",
        ],
        &[],
    )?;
    let started = number(&command, "started_unix_millis")?;
    let budget = number(&command, "budget_millis")?;
    let recovery_cutoff = number(&command, "recovery_deadline_unix_millis")?;
    if started == 0
        || budget == 0
        || budget > 10000
        || recovery_cutoff > cleanup
        || recovery_cutoff
            .checked_sub(started)
            .is_none_or(|remaining| remaining > 90000 || budget > remaining)
    {
        return Err("loss recovery original command starts after cleanup or extends bounded original cutoff".into());
    }
    let utf16 = |value: &Value| -> VerificationResult<Vec<u16>> {
        serde_json::from_value(value.clone())
            .map_err(|_| "loss recovery native UTF16 operands malformed".into())
    };
    let expected_argv = [
        "windows-recover",
        "attempt",
        native
            .attempt_id
            .as_deref()
            .ok_or("loss original attempt absent")?,
        native
            .attempt_nonce
            .as_deref()
            .ok_or("loss original nonce absent")?,
        native
            .request_sha256
            .as_deref()
            .ok_or("loss original request absent")?,
    ]
    .map(|arg| arg.encode_utf16().collect::<Vec<_>>());
    let argv: Vec<Vec<u16>> = serde_json::from_value(command["argv_utf16"].clone())
        .map_err(|_| "loss recovery argv malformed")?;
    if command["format"] != "memcordon.windows-loss-recovery-command"
        || command["revision"] != 1
        || command["target"] != key.target
        || command["source_commit"] != evidence.source_commit
        || command["executable_sha256"] != cli.installed_sha256
        || command["environment_cleared"] != true
        || command["work_deadline_unix_millis"] != work
        || command["cleanup_deadline_unix_millis"] != cleanup
        || argv != expected_argv
        || utf16(&command["program_utf16"])?
            != text(&current["cli"], "path")?
                .encode_utf16()
                .collect::<Vec<_>>()
        || utf16(&command["cwd_utf16"])?
            != text(current, "output_directory")?
                .encode_utf16()
                .collect::<Vec<_>>()
    {
        return Err(
            "loss recovery command reassociated operands/image/native cwd or renewed cutoffs"
                .into(),
        );
    }
    let creation = json(custody.bytes(&loss.recovery_creation)?)?;
    let process = json(custody.bytes(&loss.recovery_process)?)?;
    object(
        &creation,
        &[
            "format",
            "revision",
            "invocation_sha256",
            "process",
            "image_sha256",
            "creation_handle_retained",
        ],
        &[],
    )?;
    object(
        &process,
        &[
            "format",
            "revision",
            "invocation_sha256",
            "process",
            "image_sha256",
            "native_status",
            "native_wait_completed",
            "capture_complete",
            "stdout_sha256",
            "stderr_sha256",
        ],
        &[],
    )?;
    object(
        &creation["process"],
        &["process_id", "creation_time_100ns"],
        &[],
    )?;
    if creation["format"] != "memcordon.windows-loss-recovery-creation"
        || process["format"] != "memcordon.windows-loss-recovery-process"
        || creation["revision"] != 1
        || process["revision"] != 1
        || creation["process"] != process["process"]
        || number(&creation["process"], "process_id")? == 0
        || number(&creation["process"], "process_id")? > u32::MAX as u64
        || number(&creation["process"], "creation_time_100ns")? == 0
        || creation["creation_handle_retained"] != true
        || creation["invocation_sha256"] != sha256(command_bytes)
        || process["invocation_sha256"] != sha256(command_bytes)
        || creation["image_sha256"] != cli.installed_sha256
        || process["image_sha256"] != cli.installed_sha256
        || process["native_status"] != 0
        || process["native_wait_completed"] != true
        || process["capture_complete"] != true
        || process["stdout_sha256"] != sha256(custody.bytes(&loss.recovery)?)
        || process["stderr_sha256"] != sha256(custody.bytes(&loss.recovery_stderr)?)
    {
        return Err(
            "loss recovery original creation handle/kernel wait/capture custody differs".into(),
        );
    }
    object(
        &recovery,
        &[
            "schema_version",
            "provider_response",
            "frontend_delivery",
            "terminal_authority_json",
        ],
        &[],
    )?;
    if number(&recovery, "schema_version")? != 2 {
        return Err("unknown public recovery wrapper".into());
    }
    let response = recovery
        .get("provider_response")
        .ok_or("recovery authority absent")?;
    match text(response, "kind")? {
        "terminal" => {
            let mut terminal = response.clone();
            terminal
                .as_object_mut()
                .ok_or("terminal not object")?
                .remove("kind");
            validate_loss_terminal(
                &terminal,
                &recovery,
                association,
                LossTerminalContext {
                    evidence,
                    loss,
                    provider_request_path,
                    native,
                    custody,
                },
            )
        }
        "reject" => {
            object(
                response,
                &[
                    "kind",
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "rejection",
                ],
                &[],
            )?;
            let disposition = response
                .pointer("/rejection/disposition")
                .ok_or("recovered rejection disposition absent")?;
            if text(disposition, "disposition")? != "postauthorization-failure" {
                return Err("loss recovery lacks postauthorization authority".into());
            }
            validate_loss_terminal(
                disposition
                    .get("receipt")
                    .ok_or("loss recovered receipt absent")?,
                &recovery,
                association,
                LossTerminalContext {
                    evidence,
                    loss,
                    provider_request_path,
                    native,
                    custody,
                },
            )
        }
        "terminal-retired-v2" => {
            if !recovery["frontend_delivery"].is_null() {
                return Err("already-retired recovery fabricated a new frontend ACK".into());
            }
            let original_terminal = json(
                custody.bytes(
                    evidence
                        .authenticated_terminal
                        .as_deref()
                        .ok_or("retired recovery requires original actual terminal/ACK bytes")?,
                )?,
            )?;
            if original_terminal["format"] != "memcordon.windows-terminal-observation"
                || original_terminal["revision"] != 2
                || original_terminal["provider"] != *provider
            {
                return Err("original retired terminal provider/revision differs".into());
            }
            let terminal = &original_terminal["terminal"];
            let authority = original_terminal["terminal_authority_json"]
                .as_str()
                .ok_or("original immutable terminal authority bytes absent")?;
            let delivery = &original_terminal["frontend_delivery"];
            super::windows::validate_terminal_authority(terminal, authority, delivery)?;
            super::windows_proof::validate_windows_proof_matrix(terminal)?;
            if delivery["terminal_sha256"] != response["terminal_response_sha256"]
                || delivery["retired_sha256"] != super::windows::terminal_retired_digest(response)?
                || response["retirement_proof_sha256"]
                    != super::windows::terminal_proof_digest(authority)?
            {
                return Err("already-retired response differs from original actual terminal/ACK/proof bytes".into());
            }
            object(
                delivery,
                &[
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "terminal_sha256",
                    "retired_sha256",
                    "terminal_validated",
                    "acknowledgement_observed",
                ],
                &[],
            )?;
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if delivery.get(field) != response.get(field) {
                    return Err("retired recovery delivery association differs".into());
                }
            }
            for field in [
                "attempt_id",
                "request_sha256",
                "terminal_sha256",
                "retired_sha256",
            ] {
                digest(text(delivery, field)?)?;
            }
            yes(
                delivery,
                &["terminal_validated", "acknowledgement_observed"],
            )?;
            object(
                response,
                &[
                    "kind",
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "terminal_response_sha256",
                    "disposition",
                    "provider_generation",
                    "original_boot_id",
                    "launch_incarnation",
                    "job_identity",
                    "owner_manifest_sha256",
                    "retirement_proof_sha256",
                    "ledger_generation",
                    "completion",
                ],
                &[],
            )?;
            if loss.original_result.is_none()
                || number(response, "schema_version")? != 2
                || text(response, "completion")? != "retirement-complete"
                || text(response, "disposition")? != "posttarget"
                || response.get("attempt_id") != association.get("attempt_id")
                || response.get("request_sha256") != association.get("request_sha256")
                || response.get("nonce").and_then(Value::as_str) != native.attempt_nonce.as_deref()
                || response.get("provider_generation").and_then(Value::as_str)
                    != native.provider_generation.as_deref()
            {
                return Err(
                    "retired tombstone lacks actual original bound failure/retirement".into(),
                );
            }
            for field in [
                "terminal_response_sha256",
                "job_identity",
                "owner_manifest_sha256",
                "retirement_proof_sha256",
                "ledger_generation",
            ] {
                digest(text(response, field)?)?;
            }
            for field in ["original_boot_id", "launch_incarnation"] {
                if text(response, field)?.is_empty() {
                    return Err("retired tombstone identity absent".into());
                }
            }
            Ok(())
        }
        _ => Err("loss recovery authority variant is unavailable/retained/unknown".into()),
    }
}

pub(crate) fn validate_windows_request(
    bytes: &[u8],
    workload: &[u8],
    invocation: &NativeInvocation,
    environment_bytes: &[u8],
) -> VerificationResult<()> {
    let _ = super::windows::request(workload)?;
    let request = json(bytes)?;
    object(
        &request,
        &[
            "restart_attempt",
            "schema_version",
            "expected_provider_binding",
            "workload_request",
            "nonce",
            "command",
            "environment",
            "current_directory",
            "policy",
        ],
        &[],
    )?;
    if number(&request, "schema_version")? != 4
        || request.get("workload_request") != Some(&json(workload)?)
    {
        return Err("actual Windows provider request contract/revision differs".into());
    }
    let command = request
        .get("command")
        .ok_or("native Windows command missing")?;
    object(command, &["program", "arguments"], &[])?;
    let program: Vec<u16> =
        serde_json::from_value(command.get("program").ok_or("program missing")?.clone())
            .map_err(|e| e.to_string())?;
    let args: Vec<Vec<u16>> =
        serde_json::from_value(command.get("arguments").ok_or("arguments missing")?.clone())
            .map_err(|e| e.to_string())?;
    let combined = NativeArguments::WindowsUtf16(std::iter::once(program).chain(args).collect());
    validate_arguments(&combined, "x86_64-pc-windows-msvc")?;
    if serde_json::to_value(&combined).map_err(|e| e.to_string())?
        != serde_json::to_value(&invocation.arguments).map_err(|e| e.to_string())?
    {
        return Err("actual Windows request native argv differs from invocation receipt".into());
    }
    let NativeEnvironment::WindowsUtf16(environment) = decode(environment_bytes)? else {
        return Err("Windows environment has wrong native encoding".into());
    };
    if request.get("environment")
        != Some(&serde_json::to_value(&environment).map_err(|e| e.to_string())?)
    {
        return Err("actual Windows request environment differs from protected receipt".into());
    }
    let mut names = BTreeSet::new();
    if environment.len() > 4096 {
        return Err("Windows environment exceeds bound".into());
    }
    for variable in &environment {
        let key: Vec<_> = variable
            .name
            .iter()
            .map(|unit| {
                if (u16::from(b'a')..=u16::from(b'z')).contains(unit) {
                    *unit - 32
                } else {
                    *unit
                }
            })
            .collect();
        if variable.name.is_empty()
            || variable.name.contains(&0)
            || variable.value.contains(&0)
            || !names.insert(key)
        {
            return Err("actual Windows environment is malformed/ambiguous".into());
        }
    }
    let directory: Vec<u16> = serde_json::from_value(
        request
            .get("current_directory")
            .ok_or("native cwd missing")?
            .clone(),
    )
    .map_err(|e| e.to_string())?;
    if directory.is_empty() || directory.contains(&0) || directory.len() > 32_768 {
        return Err("actual native Windows cwd is malformed".into());
    }
    let policy = request
        .get("policy")
        .ok_or("native Windows launch policy missing")?;
    object(
        policy,
        &[
            "memory_limit_bytes",
            "absolute_deadline_millis",
            "lifetime",
            "poll_interval_millis",
            "signal_grace_millis",
            "command_exit_grace_millis",
            "limit_grace_millis",
        ],
        &[],
    )?;
    if !["command", "workload"].contains(&text(policy, "lifetime")?)
        || number(policy, "poll_interval_millis")? == 0
    {
        return Err("unknown/invalid actual Windows launch policy".into());
    }
    Ok(())
}

struct LossTerminalContext<'a> {
    evidence: &'a CaseEvidenceV2,
    loss: &'a WindowsLossEvidence,
    provider_request_path: &'a str,
    native: &'a NativeObservation,
    custody: &'a custody::Custody,
}

fn validate_loss_terminal(
    terminal: &Value,
    recovery: &Value,
    association: &Value,
    context: LossTerminalContext<'_>,
) -> VerificationResult<()> {
    let LossTerminalContext {
        evidence,
        loss,
        provider_request_path,
        native,
        custody,
    } = context;
    super::windows_actors::validate_terminal_shapes(terminal)?;
    super::windows_proof::validate_windows_proof_matrix(terminal)?;
    super::windows::validate_terminal_authority(
        terminal,
        text(recovery, "terminal_authority_json")?,
        &recovery["frontend_delivery"],
    )?;
    for field in ["attempt_id", "request_sha256"] {
        if terminal[field] != association[field] {
            return Err("current loss terminal crosses original held attempt".into());
        }
    }
    if terminal["nonce"].as_str() != native.attempt_nonce.as_deref()
        || terminal["retirement_proof"]["provider_generation"]
            != association["provider"]["generation"]
        || terminal["process_observation"]["root_identity"]["process_id"].as_u64()
            != native.root_pid.map(u64::from)
        || terminal["process_observation"]["root_identity"]["creation_time_100ns"].as_u64()
            != native.root_birth
    {
        return Err("current loss terminal changes actual provider/target identity".into());
    }
    if terminal["payload"]["kind"] == "execution"
        && terminal["payload"]["outcome"]["outcome"] != "monitor-failed"
    {
        return Err("current loss substituted ordinary target completion".into());
    }
    if let Some(path) = &loss.original_result {
        let original = json(custody.bytes(path)?)?;
        if let Some(cause) = original.pointer("/provider_failure/original")
            && let Some(recovered) = terminal.pointer("/payload/primary_failure")
            && cause != recovered
        {
            return Err("current recovery replaced immutable original first cause".into());
        }
    }
    let invocation: NativeInvocation = decode(custody.bytes(&evidence.invocation)?)?;
    validate_windows_request(
        custody.bytes(provider_request_path)?,
        custody.bytes(
            evidence
                .request
                .as_deref()
                .ok_or("original current workload request absent")?,
        )?,
        &invocation,
        custody.bytes(&invocation.environment)?,
    )
}
