//! Independent native actor acceptance. Actor lifetime is distinct from the
//! target Job and never manufactures guardian or aggregate retirement facts.
use crate::{VerificationResult, windows_acceptance::WindowsAcceptanceContext};
use serde_json::Value;
use std::collections::BTreeSet;

fn shape(value: &Value, required: &[&str], optional: &[&str]) -> VerificationResult<()> {
    let object = value.as_object().ok_or("actor receipt is not an object")?;
    if required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err("actor receipt has missing/unknown fields".into());
    }
    Ok(())
}

pub(crate) fn validate(context: &WindowsAcceptanceContext<'_>) -> VerificationResult<bool> {
    let key = &context.record.key;
    if !key.target.ends_with("windows-msvc")
        || key.evidence_class != crate::EvidenceClass::NativeComponentRegression
        || context.semantic.component_actors.is_none()
    {
        return Ok(false);
    }
    if key.family != "W-CAUSAL" || key.channel.is_some() {
        return Err("actor substituted into unrelated native row".into());
    }
    let expected = selectors(&key.scenario)?;
    let actors = context
        .semantic
        .component_actors
        .as_ref()
        .expect("checked actors");
    let recipe = context
        .evidence
        .component_recipe_id
        .as_deref()
        .ok_or("actor native component recipe absent")?;
    let build = context
        .builds
        .get(&key.target)
        .filter(|build| build.recipe_id == recipe)
        .ok_or("actor native component build absent")?;
    let executable = build
        .actor_executable
        .as_deref()
        .ok_or("measured native actor executable absent")?;
    let executable_sha = context.custody.hash(executable)?;
    if !build.instrumented
        || build.source_commit != context.index.source_commit
        || build.source_tree_sha256 != context.index.source_tree_sha256
        || context.evidence.component_recipe_id.as_deref() != Some(build.recipe_id.as_str())
        || context.evidence.lease_id.is_some()
        || context.native.executable_sha256 != executable_sha
        || context.native.origin != crate::OutcomeOrigin::ComponentRegression
        || context.semantic.component_test.is_some()
        || context.semantic.windows_refusal.is_some()
        || context.semantic.windows_capacity.is_some()
        || context.semantic.fixture_behavior.is_some()
        || context.semantic.negative_probe.is_some()
        || !context.semantic.operations.is_empty()
        || !context.semantic.comparisons.is_empty()
        || context.semantic.counters
            != std::collections::BTreeMap::from([("actors_executed".into(), expected.len() as u64)])
    {
        return Err("actor source/executable/recipe/semantic shape differs".into());
    }
    crate::header(
        &context.semantic.format,
        context.semantic.revision,
        "memcordon.consumer-readiness.semantic",
    )?;
    crate::header(
        &context.retirement.format,
        context.retirement.revision,
        "memcordon.consumer-readiness.retirement",
    )?;
    let challenge = context.custody.bytes(&context.semantic.challenge)?;
    if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
        return Err("actor original challenge absent".into());
    }
    let input: crate::FixtureInput =
        crate::wire::decode(context.custody.bytes(&context.evidence.input)?)?;
    crate::header(
        &input.format,
        input.revision,
        "memcordon.consumer-readiness.input",
    )?;
    if input.key != *key
        || input.run_id != context.evidence.run_id
        || input.challenge_sha256 != crate::sha256(challenge)
        || !input.binary.is_empty()
        || input.deadline_millis.is_some()
        || input.memory_bytes.is_some()
        || input.toolchain_identity.is_some()
        || serde_json::to_value(&input.target_argv).map_err(|error| error.to_string())?
            != serde_json::to_value(&context.invocation.arguments)
                .map_err(|error| error.to_string())?
    {
        return Err("actor normalized input differs from actual first invocation".into());
    }
    let retired = context.retirement;
    if retired.run_id != context.native.run_id
        || retired.attempt_id != context.native.attempt_id
        || retired.root_pid != context.native.root_pid
        || retired.root_birth != context.native.root_birth
        || !retired.target_reaped_or_absent
        || !retired.independently_observed
        || retired.aggregate_empty
        || retired.relays_retired
        || retired.guardian_retired
        || retired.native_handles_closed
        || retired.namespace_init_reaped.is_some()
        || retired.private_root_closed.is_some()
        || retired.exports_finalized.is_some()
        || retired.account_reservation_retired.is_some()
        || retired.final_job_handles_closed.is_some()
        || retired.active_processes_zero.is_some()
        || !retired.outstanding.is_empty()
        || !retired.failed_operations.is_empty()
    {
        return Err("actor retirement invents target aggregate authority".into());
    }
    let json = |path: &str| crate::wire::json(context.custody.bytes(path)?);
    let mut observed = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut attempts = BTreeSet::new();
    for (ordinal, actor) in actors.iter().enumerate() {
        if actor.recipe_id != build.recipe_id {
            return Err("actor recipe crosses native build".into());
        }
        let selection = json(&actor.selection)?;
        shape(&selection, &["kind"], &["fault", "mutant"])?;
        let kind = selection["kind"]
            .as_str()
            .ok_or("actor selector kind absent")?;
        let selector = selection[kind].as_str().ok_or("actor selector absent")?;
        if !["fault", "mutant"].contains(&kind)
            || actor.selection_kind != kind
            || selection.as_object().expect("checked object").len() != 2
            || !observed.insert((kind.to_owned(), selector.to_owned()))
        {
            return Err("actor selectors duplicate or differ from frozen schema".into());
        }
        let command = json(&actor.invocation)?;
        shape(
            &command,
            &[
                "format",
                "revision",
                "run_id",
                "recipe_id",
                "native_target",
                "executable_sha256",
                "program_utf16",
                "argv_utf16",
                "cwd_utf16",
                "environment_cleared",
            ],
            &[],
        )?;
        if command["format"] != "memcordon.windows-native-component-invocation"
            || command["revision"] != 1
            || command["run_id"] != context.evidence.run_id
            || command["recipe_id"] != build.recipe_id
            || command["native_target"] != key.target
            || command["executable_sha256"] != executable_sha
            || command["environment_cleared"] != true
        {
            return Err("actor invocation differs from actual native build/source".into());
        }
        let program: Vec<u16> = serde_json::from_value(command["program_utf16"].clone())
            .map_err(|error| error.to_string())?;
        let args: Vec<Vec<u16>> = serde_json::from_value(command["argv_utf16"].clone())
            .map_err(|error| error.to_string())?;
        let cwd: Vec<u16> = serde_json::from_value(command["cwd_utf16"].clone())
            .map_err(|error| error.to_string())?;
        if program.is_empty()
            || cwd.is_empty()
            || program.contains(&0)
            || cwd.contains(&0)
            || args.len() < 6
            || args.iter().any(|arg| arg.contains(&0))
            || args[0] != "__windows-certification".encode_utf16().collect::<Vec<_>>()
            || args[3] != "--controller-start-gate".encode_utf16().collect::<Vec<_>>()
        {
            return Err("actor native certification argv malformed".into());
        }
        let observation = json(&actor.observation)?;
        shape(
            &observation,
            &[
                "selection",
                "launch",
                "caller",
                "attempt_id",
                "request_sha256",
                "authenticated_provider_frames",
                "capture_failure",
            ],
            &["frontend_action"],
        )?;
        if observation["selection"] != selection || !observation["capture_failure"].is_null() {
            return Err("actor actual capture/selection differs".into());
        }
        let attempt = observation["attempt_id"]
            .as_str()
            .ok_or("actor actual attempt absent")?;
        let request = observation["request_sha256"]
            .as_str()
            .ok_or("actor actual request absent")?;
        let nonce = observation["launch"]["nonce"]
            .as_str()
            .filter(|nonce| !nonce.is_empty())
            .ok_or("actor actual nonce absent")?;
        validate_launch_request(&observation["launch"])?;
        crate::digest(attempt)?;
        crate::digest(request)?;
        let request_bytes = context.custody.bytes(&actor.provider_request)?;
        if !attempts.insert(attempt.to_owned())
            || crate::sha256(request_bytes) != request
            || crate::wire::json(request_bytes)? != observation["launch"]
            || observation["launch"]["expected_provider_binding"]["source_commit"]
                != context.index.source_commit
            || observation["launch"]["expected_provider_binding"]["generation"].as_str()
                != context.native.provider_generation.as_deref()
            || observation["launch"]["expected_provider_binding"]["runtime_manifest_sha256"]
                .as_str()
                != context.native.runtime_manifest_sha256.as_deref()
        {
            return Err("actor actual request/source/provider binding differs".into());
        }
        let held = json(&actor.actor_held)?;
        shape(
            &held,
            &[
                "format",
                "revision",
                "process_id",
                "creation_time_100ns",
                "held_before_execution",
                "native_live_before_release",
            ],
            &[],
        )?;
        let pid = held["process_id"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= u64::from(u32::MAX))
            .ok_or("held actor PID absent")?;
        let birth = held["creation_time_100ns"]
            .as_u64()
            .filter(|birth| *birth > 0)
            .ok_or("held actor birth absent")?;
        if held["format"] != "memcordon.windows-component-frontend-held"
            || held["revision"] != 1
            || held["held_before_execution"] != true
            || held["native_live_before_release"] != true
            || !identities.insert((pid, birth))
            || observation["caller"]["process_id"] != pid
            || observation["caller"]["creation_time_100ns"] != birth
        {
            return Err("actor lacks independently held original caller birth".into());
        }
        let exit = json(&actor.exit)?;
        shape(
            &exit,
            &[
                "format",
                "revision",
                "run_id",
                "recipe_id",
                "native_target",
                "executable_sha256",
                "native_status",
                "capture_complete",
            ],
            &[],
        )?;
        let exit_status = i32::try_from(
            exit["native_status"]
                .as_i64()
                .ok_or("actor std native status absent")?,
        )
        .map_err(|_| "actor std native status exceeds i32")?;
        let native_status = u32::from_ne_bytes(exit_status.to_ne_bytes());
        let wait = json(&actor.native_retirement)?;
        shape(
            &wait,
            &[
                "format",
                "revision",
                "process_id",
                "creation_time_100ns",
                "image_sha256",
                "held_before_execution",
                "retirement_observed",
                "native_status",
            ],
            &[],
        )?;
        if exit["format"] != "memcordon.windows-native-component-exit"
            || exit["revision"] != 1
            || exit["run_id"] != context.evidence.run_id
            || exit["recipe_id"] != build.recipe_id
            || exit["native_target"] != key.target
            || exit["executable_sha256"] != executable_sha
            || exit["capture_complete"] != true
            || wait["format"] != "memcordon.windows-component-actor-retirement"
            || wait["revision"] != 1
            || wait["process_id"] != pid
            || wait["creation_time_100ns"] != birth
            || wait["image_sha256"] != executable_sha
            || wait["held_before_execution"] != true
            || wait["retirement_observed"] != true
            || wait["native_status"] != native_status
        {
            return Err("actor actual native wait/capture differs from held process".into());
        }
        context.custody.bytes(&actor.stdout)?;
        context.custody.bytes(&actor.stderr)?;
        let settlement_command = json(&actor.settlement_invocation)?;
        let deadline = json(&actor.settlement_deadline)?;
        shape(
            &deadline,
            &[
                "format",
                "revision",
                "source",
                "native_target",
                "started_unix_millis",
                "work_deadline_unix_millis",
                "cleanup_deadline_unix_millis",
            ],
            &[],
        )?;
        let source = &deadline["source"];
        let selected = match source["kind"].as_str() {
            Some("working") => {
                shape(source, &["kind", "version", "commit"], &[])?;
                source
            }
            Some("tagged") => {
                shape(source, &["kind", "source"], &[])?;
                let selected = &source["source"];
                shape(
                    selected,
                    &[
                        "format",
                        "revision",
                        "repository",
                        "tag_ref",
                        "commit",
                        "version",
                    ],
                    &[],
                )?;
                let repository = selected["repository"]
                    .as_str()
                    .ok_or("actor tagged source repository absent")?;
                let parts = repository.split('/').collect::<Vec<_>>();
                if selected["format"] != "memcordon.selected-source"
                    || selected["revision"] != 1
                    || selected["tag_ref"] != format!("refs/tags/{}", context.index.version)
                    || parts.len() != 2
                    || parts.iter().any(|part| {
                        part.is_empty()
                            || *part == "."
                            || *part == ".."
                            || !part.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                            })
                    })
                    || context
                        .index
                        .repository
                        .as_deref()
                        .is_some_and(|actual| actual != repository)
                {
                    return Err(
                        "actor tagged source crosses actual selected repository/tag authority"
                            .into(),
                    );
                }
                selected
            }
            _ => return Err("actor original native source selection absent".into()),
        };
        let started = deadline["started_unix_millis"]
            .as_u64()
            .ok_or("original native start absent")?;
        let work = deadline["work_deadline_unix_millis"]
            .as_u64()
            .ok_or("original native work cutoff absent")?;
        let cleanup = deadline["cleanup_deadline_unix_millis"]
            .as_u64()
            .ok_or("original native cleanup cutoff absent")?;
        let origin = actor
            .invocation
            .split_once("actors/")
            .ok_or("actor original producer scope absent")?
            .0;
        if actor.settlement_deadline
            != format!("{origin}roles/compiler/native-operation-deadline.json")
            || deadline["format"] != "memcordon.consumer-readiness.original-native-deadline"
            || deadline["revision"] != 1
            || deadline["native_target"] != key.target
            || selected["commit"] != context.index.source_commit
            || selected["version"] != context.index.version
            || work.checked_sub(started) != Some(140 * 60 * 1000)
            || cleanup.checked_sub(started) != Some(155 * 60 * 1000)
            || settlement_command["work_deadline_unix_millis"] != work
            || settlement_command["cleanup_deadline_unix_millis"] != cleanup
        {
            return Err(
                "actor later convergence minted or reassociated original native cutoff authority"
                    .into(),
            );
        }
        shape(
            &settlement_command,
            &[
                "format",
                "revision",
                "run_id",
                "recipe_id",
                "native_target",
                "source_commit",
                "executable_sha256",
                "program_utf16",
                "argv_utf16",
                "cwd_utf16",
                "environment_cleared",
                "work_deadline_unix_millis",
                "cleanup_deadline_unix_millis",
            ],
            &[],
        )?;
        let settlement_args = settlement_command["argv_utf16"]
            .as_array()
            .ok_or("settlement native argv absent")?;
        let units = |text: &str| serde_json::json!(text.encode_utf16().collect::<Vec<_>>());
        if settlement_command["format"] != "memcordon.windows-component-settlement-command"
            || settlement_command["revision"] != 1
            || settlement_command["run_id"] != command["run_id"]
            || settlement_command["recipe_id"] != command["recipe_id"]
            || settlement_command["native_target"] != command["native_target"]
            || settlement_command["source_commit"] != context.index.source_commit
            || settlement_command["executable_sha256"] != executable_sha
            || settlement_command["program_utf16"] != command["program_utf16"]
            || settlement_command["cwd_utf16"] != command["cwd_utf16"]
            || settlement_command["environment_cleared"] != true
            || settlement_args.len() != 3
            || settlement_args[0] != units("windows-recover")
            || settlement_args[1] != units("converge")
        {
            return Err("actor later native settlement command reassociated".into());
        }
        let budget_units: Vec<u16> = serde_json::from_value(settlement_args[2].clone())
            .map_err(|_| "settlement budget is not native UTF16")?;
        let budget = String::from_utf16(&budget_units)
            .map_err(|_| "settlement budget malformed UTF16")?
            .parse::<u64>()
            .map_err(|_| "settlement budget malformed integer")?;
        if budget == 0 || budget > 90000 {
            return Err("settlement budget exceeds finite cleanup bound".into());
        }
        let settlement_exit = json(&actor.settlement_exit)?;
        shape(
            &settlement_exit,
            &[
                "format",
                "revision",
                "invocation_sha256",
                "stdout_sha256",
                "stderr_sha256",
                "native_status",
            ],
            &[],
        )?;
        if settlement_exit["format"] != "memcordon.windows-component-settlement-exit"
            || settlement_exit["revision"] != 1
            || settlement_exit["native_status"] != 0
            || settlement_exit["invocation_sha256"]
                != crate::sha256(context.custody.bytes(&actor.settlement_invocation)?)
            || settlement_exit["stdout_sha256"]
                != crate::sha256(context.custody.bytes(&actor.settlement_inventory)?)
            || settlement_exit["stderr_sha256"]
                != crate::sha256(context.custody.bytes(&actor.settlement_stderr)?)
        {
            return Err("actor later native settlement wait/capture reassociated".into());
        }
        let inventory = json(&actor.settlement_inventory)?;
        shape(
            &inventory,
            &[
                "schema_version",
                "challenge",
                "provider_generation",
                "current_boot_identity",
                "executing",
                "incomplete_proof",
                "unacknowledged_outboxes",
                "ack_retirement_in_progress",
                "completed_tombstones",
                "active_admissions",
                "quarantined",
            ],
            &[],
        )?;
        if inventory["schema_version"] != 1
            || inventory["provider_generation"].as_str()
                != context.native.provider_generation.as_deref()
            || inventory["challenge"].as_str().is_none_or(str::is_empty)
            || inventory["current_boot_identity"]
                .as_str()
                .is_none_or(str::is_empty)
            || [
                "executing",
                "incomplete_proof",
                "unacknowledged_outboxes",
                "ack_retirement_in_progress",
                "active_admissions",
                "quarantined",
            ]
            .iter()
            .any(|field| inventory[*field] != 0)
            || inventory["completed_tombstones"]
                .as_u64()
                .is_none_or(|count| count > u64::from(u32::MAX))
        {
            return Err("actor exact native recovery has unsettled authority".into());
        }
        validate_effect(
            kind,
            selector,
            &observation,
            actor.recovery.as_deref().map(json).transpose()?.as_ref(),
            attempt,
            nonce,
            request,
        )?;
        if let Some(path) = &actor.recovery {
            let invocation_path = actor
                .recovery_invocation
                .as_deref()
                .ok_or("actual actor recovery command absent")?;
            let recovery_command = json(invocation_path)?;
            shape(
                &recovery_command,
                &[
                    "format",
                    "revision",
                    "run_id",
                    "recipe_id",
                    "native_target",
                    "executable_sha256",
                    "program_utf16",
                    "argv_utf16",
                    "cwd_utf16",
                    "environment_cleared",
                ],
                &[],
            )?;
            let expected_args = ["windows-recover", "attempt", attempt, nonce, request]
                .iter()
                .map(|arg| arg.encode_utf16().collect::<Vec<_>>())
                .collect::<Vec<_>>();
            if recovery_command["format"] != "memcordon.windows-component-recovery-command"
                || recovery_command["revision"] != 1
                || recovery_command["run_id"] != command["run_id"]
                || recovery_command["recipe_id"] != command["recipe_id"]
                || recovery_command["native_target"] != command["native_target"]
                || recovery_command["program_utf16"] != command["program_utf16"]
                || recovery_command["executable_sha256"] != executable_sha
                || recovery_command["argv_utf16"] != serde_json::json!(expected_args)
                || recovery_command["cwd_utf16"] != command["cwd_utf16"]
                || recovery_command["environment_cleared"] != true
            {
                return Err(
                    "actual actor recovery request operands differ from held original attempt"
                        .into(),
                );
            }
            let exit = json(
                actor
                    .recovery_exit
                    .as_deref()
                    .ok_or("actual recovery native wait absent")?,
            )?;
            shape(
                &exit,
                &[
                    "format",
                    "revision",
                    "invocation_sha256",
                    "stdout_sha256",
                    "stderr_sha256",
                    "native_status",
                ],
                &[],
            )?;
            if exit["format"] != "memcordon.windows-component-recovery-exit"
                || exit["revision"] != 1
                || exit["invocation_sha256"] != context.custody.hash(invocation_path)?
                || exit["stdout_sha256"] != context.custody.hash(path)?
                || exit["stderr_sha256"]
                    != context.custody.hash(
                        actor
                            .recovery_stderr
                            .as_deref()
                            .ok_or("actual recovery stderr absent")?,
                    )?
                || (exit["native_status"] != 0
                    && !(selector == "all-job-owners-closed-after-authorization"
                        && exit["native_status"] == 1))
            {
                return Err(
                    "actual actor recovery wait/captures differ from bound public request".into(),
                );
            }
        } else if actor.recovery_invocation.is_some()
            || actor.recovery_exit.is_some()
            || actor.recovery_stderr.is_some()
        {
            return Err("actor invented recovery without native response".into());
        }
        if let Some(before_path) = &actor.held_before {
            let before = json(before_path)?;
            let after = json(
                actor
                    .held_after
                    .as_deref()
                    .ok_or("held actor target lacks native retirement")?,
            )?;
            shape(
                &before,
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
            shape(
                &after,
                &[
                    "format",
                    "revision",
                    "target_process_id",
                    "target_creation_time_100ns",
                    "guardian",
                    "held_before_fault",
                    "target_retired",
                    "guardian_retired",
                    "guardian_native_exit_status",
                    "target_native_exit_status",
                ],
                &[],
            )?;
            shape(
                &before["association"],
                &["provider", "attempt_id", "request_sha256"],
                &[],
            )?;
            for field in [
                "guardian_identity",
                "live_target_identity",
                "worker_process_identity",
            ] {
                if !before[field].is_null() {
                    shape(&before[field], &["process_id", "creation_time_100ns"], &[])?;
                }
            }
            if !before["worker_thread_identity"].is_null() {
                shape(
                    &before["worker_thread_identity"],
                    &["thread_id", "creation_time_100ns"],
                    &[],
                )?;
            }
            if before["association"]["attempt_id"] != attempt
                || before["association"]["request_sha256"] != request
                || before["live_nonce"] != nonce
                || before["format"] != "memcordon.windows-live-guardian-observation"
                || before["revision"] != 1
                || before["challenge"].as_str().is_none_or(str::is_empty)
                || before["association"]["provider"]
                    != observation["launch"]["expected_provider_binding"]
                || after["format"] != "memcordon.windows-component-held-retirement"
                || after["revision"] != 1
                || after["held_before_fault"] != true
                || after["target_retired"] != true
                || after["guardian_retired"] != true
                || after["target_process_id"] != before["live_target_identity"]["process_id"]
                || after["target_creation_time_100ns"]
                    != before["live_target_identity"]["creation_time_100ns"]
                || after["guardian"] != before["guardian_identity"]
            {
                return Err(
                    "actor held target/guardian retirement crosses original authority".into(),
                );
            }
            let mut terminal_frames = observation["authenticated_provider_frames"]
                .as_array()
                .ok_or("actor original raw frames absent")?
                .iter()
                .map(|frame| {
                    let bytes: Vec<u8> = serde_json::from_value(frame.clone())
                        .map_err(|_| "actor original frame bytes malformed".to_owned())?;
                    crate::wire::json(&bytes)
                })
                .collect::<VerificationResult<Vec<_>>>()?;
            if let Some(path) = &actor.recovery {
                terminal_frames.push(json(path)?["provider_response"].clone());
            }
            for frame in terminal_frames {
                let terminal = if frame["kind"] == "terminal" {
                    &frame
                } else {
                    &frame["rejection"]["disposition"]["receipt"]
                };
                if terminal["payload"]["kind"] == "execution"
                    && (terminal["payload"]["child_pid"]
                        != before["live_target_identity"]["process_id"]
                        || terminal["process_observation"]["root_identity"]
                            != before["live_target_identity"])
                {
                    return Err(
                        "actor execution terminal reassociated original held native target birth"
                            .into(),
                    );
                }
                if terminal["payload"]["kind"] == "execution"
                    && terminal["payload"]["outcome"]["outcome"] == "exited"
                {
                    let child = &terminal["payload"]["outcome"]["child"];
                    let status = match child["kind"].as_str() {
                        Some("windows-status") => child["status"].as_u64(),
                        Some("exit-code") => child["code"]
                            .as_i64()
                            .and_then(|value| i32::try_from(value).ok())
                            .map(|value| u32::from_ne_bytes(value.to_ne_bytes()) as u64),
                        _ => None,
                    };
                    if status != after["target_native_exit_status"].as_u64() {
                        return Err(
                            "actor execution outcome differs from original held target native wait"
                                .into(),
                        );
                    }
                }
            }
            if [
                "guardian-killed-after-authorization",
                "all-job-owners-closed-after-authorization",
            ]
            .contains(&selector)
                && after["guardian_native_exit_status"] != 0xC000_013A_u32
            {
                return Err("selected guardian native loss status differs".into());
            }
            if [
                "launcher-worker-killed-after-authorization",
                "launcher-service-killed-after-authorization",
                "all-job-owners-closed-after-authorization",
                "control-worker-killed-after-authorization",
                "control-service-killed-after-authorization",
            ]
            .contains(&selector)
            {
                let worker = json(
                    actor
                        .worker_exit
                        .as_deref()
                        .ok_or("selected native worker lacks retained exit")?,
                )?;
                let control = selector.starts_with("control-");
                let process_loss = selector == "control-service-killed-after-authorization"
                    || selector == "launcher-service-killed-after-authorization"
                    || selector == "all-job-owners-closed-after-authorization";
                shape(
                    &worker,
                    &[
                        "format",
                        "revision",
                        "process_id",
                        "process_creation_time_100ns",
                        "thread",
                        "held_before_fault",
                        "exit_observed",
                        "native_exit_status",
                        "process_retirement_observed",
                        "process_native_exit_status",
                    ],
                    &[],
                )?;
                if worker["format"]
                    != if control {
                        "memcordon.windows-component-control-worker-exit"
                    } else {
                        "memcordon.windows-component-worker-exit"
                    }
                    || worker["revision"] != 1
                    || worker["held_before_fault"] != true
                    || worker["exit_observed"] != true
                    || worker["process_retirement_observed"] != process_loss
                    || worker["native_exit_status"]
                        != if control && !process_loss {
                            0
                        } else {
                            0xC000_013A_u32
                        }
                    || (process_loss && worker["process_native_exit_status"] != 0xC000_013A_u32)
                {
                    return Err("selected worker thread/process native effect differs".into());
                }
                let (process, thread) = if control {
                    let site = json(
                        actor
                            .control_worker_site
                            .as_deref()
                            .ok_or("actual control fault site absent")?,
                    )?;
                    let held_worker = json(
                        actor
                            .control_worker_held
                            .as_deref()
                            .ok_or("actual held control worker absent")?,
                    )?;
                    shape(
                        &site,
                        &[
                            "format",
                            "revision",
                            "fault",
                            "process",
                            "thread",
                            "target_pid",
                            "target_authorization_observed",
                        ],
                        &[],
                    )?;
                    shape(
                        &held_worker,
                        &[
                            "format",
                            "revision",
                            "process",
                            "thread",
                            "target_pid",
                            "held_before_fault",
                            "control_service",
                        ],
                        &[],
                    )?;
                    shape(
                        &held_worker["control_service"],
                        &["name", "process_id", "current_state"],
                        &[],
                    )?;
                    if site["format"] != "memcordon.windows-component-control-worker-site"
                        || site["revision"] != 1
                        || site["fault"] != selector
                        || site["target_authorization_observed"] != true
                        || site["target_pid"] != before["live_target_identity"]["process_id"]
                        || held_worker["format"]
                            != "memcordon.windows-component-control-worker-held"
                        || held_worker["revision"] != 1
                        || held_worker["held_before_fault"] != true
                        || held_worker["process"] != site["process"]
                        || held_worker["thread"] != site["thread"]
                        || held_worker["target_pid"] != site["target_pid"]
                        || held_worker["control_service"]["process_id"]
                            != site["process"]["process_id"]
                    {
                        return Err(
                            "native control site/SCM/held worker association differs".into()
                        );
                    }
                    (
                        held_worker["process"].clone(),
                        held_worker["thread"].clone(),
                    )
                } else {
                    (
                        before["worker_process_identity"].clone(),
                        before["worker_thread_identity"].clone(),
                    )
                };
                if worker["process_id"] != process["process_id"]
                    || worker["process_creation_time_100ns"] != process["creation_time_100ns"]
                    || worker["thread"] != thread
                    || thread["thread_id"].as_u64().is_none_or(|id| id == 0)
                    || thread["creation_time_100ns"]
                        .as_u64()
                        .is_none_or(|birth| birth == 0)
                {
                    return Err(
                        "native worker effect substituted another process/thread birth".into(),
                    );
                }
            } else if actor.worker_exit.is_some()
                || actor.control_worker_site.is_some()
                || actor.control_worker_held.is_some()
            {
                return Err("actor invented unrelated worker effect".into());
            }
        } else if actor.held_after.is_some() || key.scenario == "postresume" {
            return Err("postresume actor lacks independently held live family".into());
        }
        if [
            "frontend-killed-after-authorization",
            "frontend-disconnected-after-authorization",
        ]
        .contains(&selector)
        {
            let action = &observation["frontend_action"];
            let frontend = json(
                actor
                    .frontend_exit
                    .as_deref()
                    .ok_or("selected frontend lacks held exit")?,
            )?;
            let killed = selector == "frontend-killed-after-authorization";
            shape(
                action,
                &[
                    "format",
                    "revision",
                    "kind",
                    "process",
                    "target_pid",
                    "target_authorization_observed",
                    "controller_release_observed",
                    "requested_exit_status",
                ],
                &[],
            )?;
            shape(
                &frontend,
                &[
                    "format",
                    "revision",
                    "process_id",
                    "creation_time_100ns",
                    "held_before_fault",
                    "retirement_observed",
                    "native_status",
                ],
                &[],
            )?;
            if action["format"] != "memcordon.windows-component-frontend-action"
                || action["revision"] != 1
                || action["kind"]
                    != if killed {
                        "exit-process"
                    } else {
                        "disconnect-public-channel"
                    }
                || action["process"]["process_id"] != pid
                || action["process"]["creation_time_100ns"] != birth
                || action["target_authorization_observed"] != true
                || action["controller_release_observed"] != true
                || action["target_pid"]
                    != json(
                        actor
                            .held_before
                            .as_deref()
                            .ok_or("frontend live association absent")?,
                    )?["live_target_identity"]["process_id"]
                || frontend["format"] != "memcordon.windows-component-frontend-exit"
                || frontend["revision"] != 1
                || frontend["process_id"] != pid
                || frontend["creation_time_100ns"] != birth
                || frontend["held_before_fault"] != true
                || frontend["retirement_observed"] != true
                || frontend["native_status"] != native_status
                || native_status == 0
                || (killed && native_status != 0xC000_013A_u32)
            {
                return Err("selected frontend action differs from actual native exit".into());
            }
        } else if actor.frontend_exit.is_some() || !observation["frontend_action"].is_null() {
            return Err("actor invents unrelated frontend action".into());
        }
        if ordinal == 0 {
            let actual = crate::NativeArguments::WindowsUtf16(
                std::iter::once(program).chain(args).collect(),
            );
            if serde_json::to_value(actual).map_err(|error| error.to_string())?
                != serde_json::to_value(&context.invocation.arguments)
                    .map_err(|error| error.to_string())?
                || context.native.root_pid.map(u64::from) != Some(pid)
                || context.native.root_birth != Some(birth)
                || context.native.attempt_id.as_deref() != Some(attempt)
                || context.native.request_sha256.as_deref() != Some(request)
                || context.native.attempt_nonce.as_deref() != Some(nonce)
                || context.native.frontend_status != exit_status
            {
                return Err("normalized first actor differs from native raw execution".into());
            }
        }
    }
    if observed != expected {
        return Err("actual actor selectors differ from finite required effects".into());
    }
    Ok(true)
}

fn selectors(scenario: &str) -> VerificationResult<BTreeSet<(String, String)>> {
    let faults: &[&str] = match scenario {
        "preauthorization" => &[
            "public-pipe-create",
            "caller-pid-lookup",
            "caller-token-impersonation",
            "primary-token-duplicate",
            "private-pipe-connect",
            "launcher-peer-verify",
            "token-handle-duplicate",
            "job-create",
            "job-configure",
            "completion-port",
            "guardian-create",
            "guardian-killed-before-authorization",
            "stream-create",
            "relay-handle-duplicate",
            "relay-ready",
            "attribute-list",
            "job-list",
            "handle-list",
            "create-process-as-user",
            "target-token-readback",
            "job-membership-readback",
            "before-resume",
        ],
        "postresume" => &[
            "guardian-killed-after-authorization",
            "frontend-disconnected-after-authorization",
            "frontend-killed-after-authorization",
            "control-worker-killed-after-authorization",
            "control-service-killed-after-authorization",
            "launcher-worker-killed-after-authorization",
            "launcher-service-killed-after-authorization",
            "all-job-owners-closed-after-authorization",
        ],
        "cleanup" => &[
            "resume",
            "terminate-job",
            "active-process-query",
            "relay-retire",
            "guardian-reap",
            "final-handle-close",
        ],
        "after-exit" => &["record-retire"],
        _ => return Err("unrecognized actor causal facet".into()),
    };
    let mut set = faults
        .iter()
        .map(|value| ("fault".into(), (*value).into()))
        .collect::<BTreeSet<_>>();
    if scenario == "preauthorization" {
        set.extend(
            [
                "omit-job-list",
                "resume-before-guardian",
                "create-under-service-token",
                "omit-handle-list",
            ]
            .iter()
            .map(|value| ("mutant".into(), (*value).into())),
        );
    }
    Ok(set)
}

fn validate_launch_request(value: &Value) -> VerificationResult<()> {
    shape(
        value,
        &[
            "restart_attempt",
            "schema_version",
            "expected_provider_binding",
            "workload_contract",
            "nonce",
            "command",
            "environment",
            "current_directory",
            "policy",
        ],
        &[],
    )?;
    shape(
        &value["expected_provider_binding"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
        &[],
    )?;
    shape(&value["command"], &["program", "arguments"], &[])?;
    shape(
        &value["policy"],
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
    let units = |v: &Value| -> VerificationResult<Vec<u16>> {
        serde_json::from_value(v.clone()).map_err(|error| error.to_string())
    };
    let program = units(&value["command"]["program"])?;
    let cwd = units(&value["current_directory"])?;
    if program.is_empty()
        || program.contains(&0)
        || cwd.is_empty()
        || cwd.contains(&0)
        || value["restart_attempt"].as_u64().is_none()
        || value["schema_version"] != 3
        || !value["workload_contract"].is_null()
    {
        return Err("actor request primitive or exclusive native contract differs".into());
    }
    for argument in value["command"]["arguments"]
        .as_array()
        .ok_or("actor argv array absent")?
    {
        if units(argument)?.contains(&0) {
            return Err("actor argv contains native NUL".into());
        }
    }
    for entry in value["environment"]
        .as_array()
        .ok_or("actor environment array absent")?
    {
        shape(entry, &["name", "value"], &[])?;
        let name = units(&entry["name"])?;
        if name.is_empty() || name.contains(&0) || units(&entry["value"])?.contains(&0) {
            return Err("actor environment primitive differs".into());
        }
    }
    for field in [
        "poll_interval_millis",
        "signal_grace_millis",
        "command_exit_grace_millis",
        "limit_grace_millis",
    ] {
        if value["policy"][field].as_u64().is_none() {
            return Err("actor policy integer absent".into());
        }
    }
    for field in ["memory_limit_bytes", "absolute_deadline_millis"] {
        if !value["policy"][field].is_null() && value["policy"][field].as_u64().is_none() {
            return Err("actor policy optional integer differs".into());
        }
    }
    if !matches!(
        value["policy"]["lifetime"].as_str(),
        Some("command" | "workload")
    ) {
        return Err("actor lifetime vocabulary differs".into());
    }
    Ok(())
}

fn validate_effect(
    kind: &str,
    selector: &str,
    observation: &Value,
    recovery: Option<&Value>,
    attempt: &str,
    nonce: &str,
    request: &str,
) -> VerificationResult<()> {
    let frames = observation["authenticated_provider_frames"]
        .as_array()
        .ok_or("actual authenticated actor frames absent")?;
    if frames.len() > 256 {
        return Err("actor native frame count exceeds bound".into());
    }
    let mut decoded = Vec::new();
    for frame in frames {
        let bytes: Vec<u8> =
            serde_json::from_value(frame.clone()).map_err(|error| error.to_string())?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("actor frame exceeds native bound".into());
        }
        decoded.push(crate::wire::json(&bytes)?);
    }
    if let Some(recovery) = recovery {
        shape(
            recovery,
            &[
                "schema_version",
                "provider_response",
                "frontend_delivery",
                "provider_request",
            ],
            &[],
        )?;
        if recovery["schema_version"] != 1 {
            return Err("actor recovery public envelope revision differs".into());
        }
        let recovery_request = &recovery["provider_request"];
        shape(
            recovery_request,
            &[
                "kind",
                "schema_version",
                "attempt_id",
                "nonce",
                "request_sha256",
                "challenge",
            ],
            &[],
        )?;
        if recovery_request["kind"] != "recover-attempt"
            || recovery_request["schema_version"] != 3
            || recovery_request["attempt_id"] != attempt
            || recovery_request["nonce"] != nonce
            || recovery_request["request_sha256"] != request
        {
            return Err("actual retained recovery request crosses original attempt".into());
        }
        crate::digest(
            recovery_request["challenge"]
                .as_str()
                .ok_or("actual recovery request challenge absent")?,
        )?;
        if recovery["provider_response"]["kind"] == "recovery-attempt-unavailable"
            && recovery["provider_response"]["challenge"] != recovery_request["challenge"]
        {
            return Err(
                "actual recovery unavailable response challenge differs from original sent request"
                    .into(),
            );
        }
        decoded.push(recovery["provider_response"].clone());
    }
    for frame in &decoded {
        validate_frame(frame, attempt, nonce, request)?;
    }
    for frame in decoded {
        let receipt = frame.get("receipt").unwrap_or(&frame);
        if kind == "mutant" && frame["kind"] == "certification-mutant-observed" {
            if receipt["schema_version"] != 1
                || receipt["mutant"] != selector
                || receipt["attempt_id"] != attempt
                || receipt["nonce"] != nonce
                || receipt["request_sha256"] != request
                || receipt["hook_observation"]["hook"] != "native"
            {
                continue;
            }
            let native = &receipt["hook_observation"]["observation"];
            let rejects = match selector {
                "omit-job-list" => {
                    native["detector"] == "creation-manifest"
                        && native["used_create_process_as_user"] == true
                        && native["job_list_present"] == false
                        && native["handle_list_present"] == true
                        && native["post_create_job_assignment"] == false
                        && native["unexpected_handle_count"] == 0
                }
                "omit-handle-list" => {
                    native["detector"] == "creation-manifest"
                        && native["used_create_process_as_user"] == true
                        && native["job_list_present"] == true
                        && native["handle_list_present"] == false
                        && native["post_create_job_assignment"] == false
                        && native["unexpected_handle_count"] == 0
                }
                "resume-before-guardian" => {
                    native["detector"] == "premature-authorization"
                        && native["guardian_ready"] == false
                        && native["target_marker_observed"] == true
                }
                "create-under-service-token" => {
                    native["detector"] == "target-token-mismatch"
                        && native["creation_api"] == "create-process-as-user-w"
                        && native["token_source"] == "launcher-service"
                        && native["authenticated_envelope_sha256"]
                            != native["target_envelope_sha256"]
                        && native["authenticated_envelope_sha256"]
                            .as_str()
                            .is_some_and(|value| crate::digest(value).is_ok())
                        && native["target_envelope_sha256"]
                            .as_str()
                            .is_some_and(|value| crate::digest(value).is_ok())
                }
                _ => false,
            };
            if rejects {
                return Ok(());
            }
        }
        if kind != "fault" {
            continue;
        }
        if selector == "all-job-owners-closed-after-authorization"
            && frame["kind"] == "recovery-attempt-unavailable"
            && frame["schema_version"] == 3
            && frame["attempt_id"] == attempt
            && frame["challenge"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && frame["detail"]
                == "exact recovery authority remains retained pending checked closure"
            && recovery.is_some()
        {
            return Ok(());
        }
        let rejection = &frame["rejection"];
        let terminal = if frame["kind"] == "terminal" {
            receipt
        } else {
            &rejection["disposition"]["receipt"]
        };
        if [
            "guardian-killed-after-authorization",
            "frontend-disconnected-after-authorization",
            "frontend-killed-after-authorization",
            "control-worker-killed-after-authorization",
            "control-service-killed-after-authorization",
            "launcher-worker-killed-after-authorization",
            "launcher-service-killed-after-authorization",
        ]
        .contains(&selector)
            && terminal.is_null()
        {
            continue;
        }
        let original = if terminal["payload"]["kind"] == "recovered-closure" {
            &terminal["payload"]["primary_failure"]
        } else {
            &rejection["provider_failure"]["original"]
        };
        if frame["kind"] == "reject"
            && (frame["attempt_id"] != attempt
                || frame["nonce"] != nonce
                || frame["request_sha256"] != request)
        {
            continue;
        }
        if frame["kind"] == "reject" && !rejection["provider_failure"].is_null() {
            let failure = &rejection["provider_failure"];
            if failure["provider_binding"] != observation["launch"]["expected_provider_binding"]
                || failure["attempt_id"] != attempt
                || failure["request_sha256"] != request
            {
                continue;
            }
        }
        if !terminal.is_null() {
            shape(
                terminal,
                &[
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "payload",
                    "process_observation",
                    "restart_safety",
                    "retirement_proof",
                ],
                &["kind", "policy_enforcement", "cleanup_process_creation"],
            )?;
            validate_terminal_shapes(terminal)?;
            if terminal["attempt_id"] != attempt
                || terminal["nonce"] != nonce
                || terminal["request_sha256"] != request
                || terminal["retirement_proof"]["provider_generation"]
                    != observation["launch"]["expected_provider_binding"]["generation"]
            {
                continue;
            }
            let mut proof_vocabulary = terminal.clone();
            if proof_vocabulary["payload"]["primary_failure"]["observed"]["event"]["safe_detail"]
                == serde_json::json!({"injected-windows-fault":{"fault":selector}})
            {
                proof_vocabulary["payload"]["primary_failure"]["observed"]["event"]["safe_detail"] =
                    Value::String("no-additional-detail".into());
            }
            crate::wire::validate_windows_proof_matrix(&proof_vocabulary)?;
        }
        let event = &original["observed"]["event"];
        if event["safe_detail"] == serde_json::json!({"injected-windows-fault":{"fault":selector}})
        {
            let mut vocabulary = original.clone();
            vocabulary["observed"]["event"]["safe_detail"] =
                Value::String("no-additional-detail".into());
            crate::wire::validate_original_failure(&vocabulary)?;
            let transport = [
                "frontend-disconnected-after-authorization",
                "frontend-killed-after-authorization",
                "control-worker-killed-after-authorization",
                "control-service-killed-after-authorization",
            ]
            .contains(&selector);
            let cleaning = [
                "terminate-job",
                "active-process-query",
                "relay-retire",
                "guardian-reap",
                "final-handle-close",
            ]
            .contains(&selector);
            if (selector == "resume" || cleaning || selector == "record-retire")
                && terminal.is_null()
            {
                continue;
            }
            if transport {
                if event["category"] != "transport"
                    || event["operation"] != "read-control-frame"
                    || event["code"] != "control-transport"
                    || event["observed_phase"] != "monitoring"
                {
                    continue;
                }
            } else if selector == "resume" || cleaning {
                if event["operation"] != "unclassified-provider-operation"
                    || event["code"] != "unexpected-provider-failure"
                    || event["category"] != "launch"
                    || !event["native_code"].is_null()
                    || event["observed_phase"]
                        != if cleaning {
                            "cleaning"
                        } else {
                            "authorized-before-resume"
                        }
                {
                    continue;
                }
            } else if selector == "record-retire" {
                if event["observed_phase"] != "target-exit-observed"
                    || event["category"] != "launch"
                    || event["operation"] != "unclassified-provider-operation"
                    || event["code"] != "unexpected-provider-failure"
                    || !event["native_code"].is_null()
                {
                    continue;
                }
            } else if event["observed_phase"] != "before-authorization" {
                continue;
            }
            return Ok(());
        }
        if selector == "guardian-killed-after-authorization"
            && event["operation"] == "check-guardian"
            && event["code"] == "guardian-loss"
            && event["observed_phase"] == "monitoring"
            && event["sequence"]
                .as_u64()
                .is_some_and(|sequence| sequence > 0)
            && event["native_code"].is_null()
        {
            return Ok(());
        }
        if [
            "launcher-worker-killed-after-authorization",
            "launcher-service-killed-after-authorization",
        ]
        .contains(&selector)
            && original["unavailable"]["reason"] == "worker-lost-before-observation"
        {
            crate::wire::validate_original_failure(original)?;
            return Ok(());
        }
    }
    Err("actor selected native effect lacks independently bound original cause".into())
}

fn validate_frame(
    frame: &Value,
    attempt: &str,
    nonce: &str,
    request: &str,
) -> VerificationResult<()> {
    let kind = frame["kind"]
        .as_str()
        .ok_or("actual actor provider variant absent")?;
    let core = [
        "kind",
        "schema_version",
        "attempt_id",
        "nonce",
        "request_sha256",
    ];
    match kind {
        "certification-mutant-observed" | "certification-mutant-hook-observed" => {
            shape(
                frame,
                &[
                    "kind",
                    "schema_version",
                    "mutant",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "hook_observation",
                ],
                &["remote_observation_handle", "terminal_candidate"],
            )?;
            shape(
                &frame["hook_observation"],
                &["hook"],
                &["observation", "child_pid"],
            )?;
            if frame["hook_observation"]["hook"] == "native" {
                let native = &frame["hook_observation"]["observation"];
                match native["detector"]
                    .as_str()
                    .ok_or("native mutant detector absent")?
                {
                    "creation-manifest" => shape(
                        native,
                        &[
                            "detector",
                            "used_create_process_as_user",
                            "job_list_present",
                            "handle_list_present",
                            "post_create_job_assignment",
                            "unexpected_handle_count",
                        ],
                        &[],
                    )?,
                    "premature-authorization" => shape(
                        native,
                        &[
                            "detector",
                            "guardian_ready",
                            "relays_ready",
                            "target_marker_observed",
                        ],
                        &[],
                    )?,
                    "target-token-mismatch" => shape(
                        native,
                        &[
                            "detector",
                            "creation_api",
                            "token_source",
                            "authenticated_envelope_sha256",
                            "target_envelope_sha256",
                        ],
                        &[],
                    )?,
                    _ => return Err("unrequested native mutant detector".into()),
                }
            }
            if frame["schema_version"] != 1 {
                return Err("native mutant receipt revision differs".into());
            }
        }
        "recovery-attempt-unavailable" => {
            shape(
                frame,
                &[
                    "kind",
                    "schema_version",
                    "challenge",
                    "attempt_id",
                    "detail",
                ],
                &[],
            )?;
            if frame["schema_version"] != 3 || frame["attempt_id"] != attempt {
                return Err("actual recovery unavailability response crosses request".into());
            }
            return Ok(());
        }
        "reject" => {
            shape(
                frame,
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
            let rejection = &frame["rejection"];
            shape(
                rejection,
                &[
                    "schema_version",
                    "code",
                    "phase",
                    "detail",
                    "os_code",
                    "target_created",
                    "target_released",
                    "cleanup_attempted",
                    "restart_safety",
                    "disposition",
                ],
                &[
                    "workload_admission",
                    "provider_failure",
                    "loader_qualification",
                ],
            )?;
            if rejection["schema_version"] != 2
                || !rejection["workload_admission"].is_null()
                || !rejection["loader_qualification"].is_null()
            {
                return Err("actor fault substituted an admission/loader refusal".into());
            }
            match rejection["disposition"]["disposition"]
                .as_str()
                .ok_or("actual rejection disposition absent")?
            {
                "preauthorization" => {
                    shape(
                        &rejection["disposition"],
                        &["disposition", "terminal_ack_required"],
                        &[],
                    )?;
                    if rejection["disposition"]["terminal_ack_required"] != false
                        || rejection["target_released"] != false
                    {
                        return Err(
                            "preauthorization actor rejection invents released target".into()
                        );
                    }
                }
                "postauthorization-failure" => {
                    shape(&rejection["disposition"], &["disposition", "receipt"], &[])?
                }
                "retained" => shape(&rejection["disposition"], &["disposition", "evidence"], &[])?,
                _ => return Err("unknown actor rejection disposition".into()),
            }
            if !rejection["provider_failure"].is_null() {
                shape(
                    &rejection["provider_failure"],
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
                    &[],
                )?;
                let diagnostic = &rejection["provider_failure"];
                shape(
                    &diagnostic["loss"],
                    &[
                        "secondary_events_omitted",
                        "secondary_count_saturated",
                        "persistence_failure_observed",
                        "writer_unavailable",
                    ],
                    &[],
                )?;
                let sequence = diagnostic["diagnostic_sequence"]
                    .as_u64()
                    .filter(|value| *value > 0)
                    .ok_or("actual actor diagnostic sequence absent")?;
                if (!diagnostic["durable_through_sequence"].is_null()
                    && diagnostic["durable_through_sequence"]
                        .as_u64()
                        .is_none_or(|value| value > sequence))
                    || diagnostic["secondary"]
                        .as_array()
                        .is_none_or(|events| events.len() > 8)
                    || diagnostic["loss"]["secondary_events_omitted"]
                        .as_u64()
                        .is_none_or(|value| value > u32::MAX as u64)
                    || [
                        "secondary_count_saturated",
                        "persistence_failure_observed",
                        "writer_unavailable",
                    ]
                    .iter()
                    .any(|field| diagnostic["loss"][*field].as_bool().is_none())
                {
                    return Err("actor original diagnostic loss/durability shape differs".into());
                }
                crate::digest(
                    diagnostic["projection_sha256"]
                        .as_str()
                        .ok_or("actor diagnostic projection absent")?,
                )?;
                if rejection["provider_failure"]["schema_version"] != 1
                    || rejection["provider_failure"]["attempt_id"] != attempt
                    || rejection["provider_failure"]["request_sha256"] != request
                {
                    return Err("actor original cause diagnostic crosses request".into());
                }
            }
        }
        "terminal" => {
            shape(
                frame,
                &[
                    "kind",
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "payload",
                    "process_observation",
                    "restart_safety",
                    "retirement_proof",
                ],
                &["policy_enforcement", "cleanup_process_creation"],
            )?;
            if frame["schema_version"] != 2 {
                return Err("actor terminal named revision differs".into());
            }
            validate_terminal_shapes(frame)?;
        }
        "streams-prepared" => {
            shape(
                frame,
                &[
                    "kind",
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "streams",
                    "relay_retired_event_handle",
                ],
                &[],
            )?;
            let streams = frame["streams"]
                .as_array()
                .filter(|streams| streams.len() == 3)
                .ok_or("actor actual stream manifest differs")?;
            let mut roles = BTreeSet::new();
            let mut handles = BTreeSet::new();
            for stream in streams {
                shape(stream, &["role", "remote_handle"], &[])?;
                let role = stream["role"].as_str().ok_or("actor stream role absent")?;
                let handle = stream["remote_handle"]
                    .as_u64()
                    .filter(|handle| *handle > 0)
                    .ok_or("actor stream handle absent")?;
                if !["stdin", "stdout", "stderr"].contains(&role)
                    || !roles.insert(role)
                    || !handles.insert(handle)
                {
                    return Err("actor stream manifest duplicated/null".into());
                }
            }
            if frame["relay_retired_event_handle"]
                .as_u64()
                .is_none_or(|handle| handle == 0)
            {
                return Err("actor relay retirement event absent".into());
            }
        }
        "target-authorized" => {
            shape(
                frame,
                &[
                    "kind",
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "child_pid",
                ],
                &[],
            )?;
            if frame["child_pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
            {
                return Err("actor authorization PID absent".into());
            }
        }
        "target-retired" | "relays-abort" => shape(frame, &core, &[])?,
        "attempt-retained-v2" => shape(
            frame,
            &[
                "kind",
                "schema_version",
                "attempt_id",
                "nonce",
                "request_sha256",
                "record_binding",
                "relay_phase",
                "durable_state",
                "terminal_disposition",
                "checkpoint",
                "missing_proofs",
                "cleanup_complete",
                "terminal_replay_available",
                "authority_retained",
                "primary_detail",
                "secondary_failures",
                "causal_diagnostics",
                "provider_failure",
                "diagnostic_availability",
            ],
            &[],
        )?,
        "terminal-retired-v2" => {
            shape(
                frame,
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
            for field in [
                "terminal_response_sha256",
                "owner_manifest_sha256",
                "retirement_proof_sha256",
            ] {
                crate::digest(
                    frame[field]
                        .as_str()
                        .ok_or("actor retired native hash absent")?,
                )?;
            }
        }
        _ => return Err("actor captured unrelated/unknown native provider frame".into()),
    }
    if frame["attempt_id"] != attempt
        || frame["nonce"] != nonce
        || frame["request_sha256"] != request
    {
        return Err("actual actor provider frame crosses native request".into());
    }
    if ["attempt-retained-v2", "terminal-retired-v2"].contains(&kind)
        && frame["schema_version"] != 2
    {
        return Err("native actor retained named revision differs".into());
    }
    if ![
        "terminal",
        "certification-mutant-observed",
        "certification-mutant-hook-observed",
        "attempt-retained-v2",
        "terminal-retired-v2",
    ]
    .contains(&kind)
        && frame["schema_version"] != 3
    {
        return Err("actor provider public protocol revision differs".into());
    }
    Ok(())
}

fn validate_actor_execution_outcome(outcome: &Value) -> VerificationResult<()> {
    let fields: &[&str] = match outcome["outcome"].as_str() {
        Some("exited") => &["outcome", "child", "peak", "cleanup"],
        Some("limit-exceeded") => &[
            "outcome",
            "limit",
            "observed",
            "peak",
            "evidence",
            "child_after_termination",
            "cleanup",
        ],
        Some("deadline-exceeded") => &[
            "outcome",
            "deadline",
            "child_after_termination",
            "peak",
            "cleanup",
        ],
        Some("interrupted") => &["outcome", "signal", "child_after_termination", "cleanup"],
        Some("monitor-failed") => &["outcome", "error", "child_after_termination", "cleanup"],
        _ => return Err("actor execution outcome variant unknown".into()),
    };
    shape(outcome, fields, &[])?;
    let cleanup = &outcome["cleanup"];
    shape(
        cleanup,
        &[
            "graceful_attempted",
            "force_attempted",
            "direct_child_reaped",
            "workload_empty",
            "errors",
        ],
        &[],
    )?;
    if ["graceful_attempted", "force_attempted"]
        .iter()
        .any(|field| cleanup[*field].as_bool().is_none())
        || cleanup["direct_child_reaped"] != true
        || cleanup["workload_empty"] != true
        || cleanup["errors"] != serde_json::json!([])
    {
        return Err("actor execution cleanup is not original settled effect".into());
    }
    for field in ["limit", "observed", "peak"] {
        if fields.contains(&field) && !outcome[field].is_null() && outcome[field].as_u64().is_none()
        {
            return Err("actor execution native memory integer malformed".into());
        }
    }
    let child = if outcome["outcome"] == "exited" {
        &outcome["child"]
    } else {
        &outcome["child_after_termination"]
    };
    if outcome["outcome"] == "exited" && child.is_null() {
        return Err("actor exited execution omitted original child termination".into());
    }
    if !child.is_null() {
        match child["kind"].as_str() {
            Some("windows-status") => {
                shape(child, &["kind", "status"], &[])?;
                if child["status"]
                    .as_u64()
                    .is_none_or(|value| value > u32::MAX as u64)
                {
                    return Err("actor execution native Windows status malformed".into());
                }
            }
            Some("exit-code") => {
                shape(child, &["kind", "code"], &[])?;
                if child["code"]
                    .as_i64()
                    .is_none_or(|value| i32::try_from(value).is_err())
                {
                    return Err("actor execution native exit integer malformed".into());
                }
            }
            Some("unavailable") => shape(child, &["kind"], &[])?,
            _ => return Err("actor execution child variant not Windows native".into()),
        }
    }
    if outcome["outcome"] == "deadline-exceeded"
        && outcome["deadline"]["grace_elapsed_ms"]
            .as_u64()
            .is_some_and(|elapsed| elapsed > 0)
        && outcome["deadline"]["graceful_action"].is_null()
    {
        return Err("actor deadline grace elapsed without original graceful action".into());
    }
    match outcome["outcome"].as_str() {
        Some("limit-exceeded") => {
            shape(&outcome["evidence"], &["backend", "metric", "detail"], &[])?;
            if ["backend", "metric", "detail"]
                .iter()
                .any(|field| outcome["evidence"][*field].as_str().is_none())
                || outcome["limit"].as_u64().is_none()
            {
                return Err("actor execution native memory cause malformed".into());
            }
        }
        Some("deadline-exceeded") => {
            let deadline = &outcome["deadline"];
            shape(
                deadline,
                &[
                    "duration_ms",
                    "scope",
                    "origin",
                    "overshoot_ms",
                    "expires_offset_ms",
                    "observed_offset_ms",
                    "grace_requested_ms",
                    "grace_elapsed_ms",
                    "graceful_action",
                    "force_action",
                ],
                &[],
            )?;
            for field in [
                "duration_ms",
                "overshoot_ms",
                "expires_offset_ms",
                "observed_offset_ms",
                "grace_requested_ms",
                "grace_elapsed_ms",
            ] {
                if deadline[field].as_u64().is_none() {
                    return Err("actor native deadline integer malformed".into());
                }
            }
            if deadline["origin"].as_str().is_none_or(str::is_empty)
                || !matches!(deadline["scope"].as_str(), Some("attempt" | "supervision"))
                || deadline["observed_offset_ms"]
                    .as_u64()
                    .and_then(|observed| {
                        observed.checked_sub(deadline["expires_offset_ms"].as_u64().unwrap())
                    })
                    != deadline["overshoot_ms"].as_u64()
                || deadline["grace_elapsed_ms"].as_u64() > deadline["grace_requested_ms"].as_u64()
                || ["graceful_action", "force_action"]
                    .iter()
                    .any(|field| !deadline[*field].is_null() && deadline[*field].as_str().is_none())
            {
                return Err("actor native deadline cause inconsistent".into());
            }
        }
        Some("interrupted") => {
            shape(&outcome["signal"], &["signal"], &[])?;
            if outcome["signal"]["signal"]
                .as_i64()
                .is_none_or(|value| i32::try_from(value).is_err())
            {
                return Err("actor native interruption malformed".into());
            }
        }
        Some("monitor-failed") if outcome["error"].as_str().is_none_or(str::is_empty) => {
            return Err("actor native monitor cause absent".into());
        }
        _ => {}
    }
    Ok(())
}

fn validate_terminal_shapes(terminal: &Value) -> VerificationResult<()> {
    if !terminal["policy_enforcement"].is_null() {
        return Err("contract-free native actor terminal adds unrelated workload authority".into());
    }
    let proof = &terminal["retirement_proof"];
    shape(
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
            "policy_reference_bound",
        ],
        &["guardian_receipt_sha256", "current_boot_id"],
    )?;
    if proof["schema_version"] != 2
        || [
            "provider_generation",
            "launch_incarnation",
            "original_boot_id",
            "job_identity",
        ]
        .iter()
        .any(|field| proof[*field].as_str().is_none_or(str::is_empty))
    {
        return Err("actor terminal native proof custody identity absent".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if proof[field] != terminal[field] {
            return Err("actor terminal nested original transaction differs".into());
        }
    }
    crate::digest(
        proof["owner_manifest_sha256"]
            .as_str()
            .ok_or("actor owner manifest commitment absent")?,
    )?;
    let payload = &terminal["payload"];
    match payload["kind"].as_str() {
        Some("recovered-closure") => {
            shape(
                payload,
                &[
                    "kind",
                    "primary_failure",
                    "target_creation_observed",
                    "resume_attempted",
                ],
                &[],
            )?;
            if ["target_creation_observed", "resume_attempted"]
                .iter()
                .any(|field| payload[*field].as_bool().is_none())
            {
                return Err("actor recovery original target/resume facts malformed".into());
            }
        }
        Some("execution") => {
            shape(
                payload,
                &[
                    "kind",
                    "child_pid",
                    "duration_millis",
                    "authorization_offset_millis",
                    "outcome",
                    "boundary_detail",
                ],
                &[],
            )?;
            let duration = payload["duration_millis"]
                .as_u64()
                .ok_or("actor original execution duration malformed")?;
            let offset = payload["authorization_offset_millis"]
                .as_u64()
                .ok_or("actor original authorization offset malformed")?;
            if payload["child_pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > u32::MAX as u64)
                || duration.checked_add(offset).is_none()
            {
                return Err("actor original execution PID/time overflows native protocol".into());
            }
            validate_actor_execution_outcome(&payload["outcome"])?;
            let boundary = &payload["boundary_detail"];
            let boundary_fields = [
                "mechanism",
                "schema_version",
                "service_identity",
                "caller_token_authenticated",
                "initial_target_token_matches_caller",
                "credential_transition_disposition",
                "job_membership_independent_of_token",
                "job_created",
                "job_limits_verified",
                "kill_on_close_verified",
                "breakaway_denied",
                "completion_port_associated",
                "guardian_ready",
                "target_created_suspended",
                "job_list_applied_at_creation",
                "handle_list_applied_at_creation",
                "target_job_membership_verified",
                "target_still_suspended_during_verification",
                "inherited_handles_verified",
                "target_released",
                "terminate_job_invoked",
                "active_processes_zero",
                "direct_target_reaped",
                "relays_retired",
                "guardian_reaped",
                "final_job_handles_closed",
            ];
            shape(boundary, &boundary_fields, &[])?;
            if boundary["mechanism"] != "windows-job-object-v2"
                || boundary["schema_version"] != 2
                || boundary["service_identity"]
                    != "MemCordonSealedControl+MemCordonSealedLauncher:v1"
                || boundary["credential_transition_disposition"] != "preserve-caller-envelope"
                || boundary_fields
                    .iter()
                    .skip(4)
                    .filter(|field| **field != "credential_transition_disposition")
                    .any(|field| boundary[*field].as_bool().is_none())
            {
                return Err("actor execution native Windows boundary schema differs".into());
            }
            let cleanup = &payload["outcome"]["cleanup"];
            if cleanup["direct_child_reaped"] != true
                || cleanup["workload_empty"] != true
                || cleanup["errors"] != serde_json::json!([])
            {
                return Err(
                    "actor execution original cleanup contradicts authoritative retirement".into(),
                );
            }
            if [
                "caller_token_authenticated",
                "initial_target_token_matches_caller",
                "job_created",
                "job_limits_verified",
                "kill_on_close_verified",
                "breakaway_denied",
                "completion_port_associated",
                "target_job_membership_verified",
                "active_processes_zero",
                "direct_target_reaped",
                "relays_retired",
                "guardian_reaped",
                "final_job_handles_closed",
            ]
            .iter()
            .any(|field| boundary[*field] != true)
            {
                return Err(
                    "actor execution native Job boundary contradicts authoritative retirement"
                        .into(),
                );
            }
        }
        _ => return Err("actor terminal payload variant unknown".into()),
    }
    let safety = &terminal["restart_safety"];
    shape(
        safety,
        &[
            "direct_child_reaped",
            "workload_empty",
            "helpers_reaped",
            "containment_removed",
            "containment_incapable_of_live_members",
            "sealed_boundary_retired",
            "errors",
        ],
        &[],
    )?;
    if [
        "direct_child_reaped",
        "workload_empty",
        "helpers_reaped",
        "containment_removed",
        "containment_incapable_of_live_members",
        "sealed_boundary_retired",
    ]
    .iter()
    .any(|field| safety[*field] != true)
        || safety["errors"] != serde_json::json!([])
    {
        return Err("actor terminal original native restart safety incomplete".into());
    }
    let processes = &terminal["process_observation"];
    shape(
        processes,
        &[
            "schema_version",
            "coverage",
            "root_identity",
            "final_accounting",
            "required_witness",
        ],
        &[],
    )?;
    if processes["schema_version"] != 2 || !processes["required_witness"].is_null() {
        return Err("actor terminal invents unrelated qualification authority".into());
    }
    if !processes["root_identity"].is_null() {
        shape(
            &processes["root_identity"],
            &["process_id", "creation_time_100ns"],
            &[],
        )?;
        if processes["root_identity"]["process_id"]
            .as_u64()
            .is_none_or(|value| value == 0 || value > u32::MAX as u64)
            || processes["root_identity"]["creation_time_100ns"]
                .as_u64()
                .is_none_or(|value| value == 0)
        {
            return Err("actor terminal native root identity malformed".into());
        }
    }
    if !processes["final_accounting"].is_null() {
        let accounting = &processes["final_accounting"];
        shape(
            accounting,
            &[
                "total_processes_native_u32",
                "active_processes_native_u32",
                "observed_after_target_retirement",
                "counter_regression_observed",
            ],
            &[],
        )?;
        if accounting["total_processes_native_u32"]
            .as_u64()
            .is_none_or(|value| value > u32::MAX as u64)
            || accounting["active_processes_native_u32"] != 0
            || accounting["observed_after_target_retirement"] != true
            || accounting["counter_regression_observed"] != false
        {
            return Err("actor terminal actual native accounting remains live/regressed".into());
        }
    }
    let coverage = &processes["coverage"];
    match coverage["coverage"].as_str() {
        Some("unavailable") => {
            shape(coverage, &["coverage", "reason"], &[])?;
            if !matches!(
                coverage["reason"].as_str(),
                Some(
                    "worker-lost-before-freeze"
                        | "legacy-observation-unavailable"
                        | "target-not-created"
                )
            ) || !processes["root_identity"].is_null()
                || !processes["final_accounting"].is_null()
            {
                return Err("actor unavailable process observation reason/facts differ".into());
            }
        }
        Some("sampled") => {
            shape(
                coverage,
                &["coverage", "policy", "counters", "omissions", "sample"],
                &[],
            )?;
            shape(
                &coverage["policy"],
                &[
                    "snapshot_storage_bytes",
                    "sample_storage_bytes",
                    "serialized_field_bytes",
                    "snapshot_queries_per_tick",
                    "identity_queries_per_tick",
                    "sample_interval_millis",
                ],
                &[],
            )?;
            shape(
                &coverage["counters"],
                &[
                    "polls_attempted",
                    "snapshots_obtained",
                    "identity_queries_attempted",
                    "identity_observations_verified",
                    "vanished_or_not_member",
                    "sample_evictions",
                    "counter_saturated",
                ],
                &[],
            )?;
            shape(
                &coverage["omissions"],
                &[
                    "snapshot_byte_budget",
                    "snapshot_race_or_retry_budget",
                    "per_tick_query_budget",
                    "allocation_unavailable",
                    "sample_eviction",
                ],
                &[],
            )?;
            if coverage["policy"]
                != serde_json::json!({"snapshot_storage_bytes":262144,"sample_storage_bytes":24576,"serialized_field_bytes":131072,"snapshot_queries_per_tick":2,"identity_queries_per_tick":64,"sample_interval_millis":100})
                || processes["root_identity"].is_null()
            {
                return Err("actor sampled process policy/root differs".into());
            }
            for (field, value) in coverage["counters"].as_object().expect("closed counters") {
                if field == "counter_saturated" {
                    if value.as_bool().is_none() {
                        return Err("actor sampled counter saturation malformed".into());
                    }
                } else if value.as_u64().is_none() {
                    return Err("actor sampled native counter malformed".into());
                }
            }
            if coverage["omissions"]
                .as_object()
                .expect("closed omissions")
                .values()
                .any(|value| value.as_u64().is_none())
                || coverage["counters"]["snapshots_obtained"].as_u64()
                    > coverage["counters"]["polls_attempted"].as_u64()
                || coverage["counters"]["identity_observations_verified"].as_u64()
                    > coverage["counters"]["identity_queries_attempted"].as_u64()
                || coverage["counters"]["vanished_or_not_member"].as_u64()
                    > coverage["counters"]["identity_queries_attempted"].as_u64()
                || coverage["omissions"]["sample_eviction"]
                    != coverage["counters"]["sample_evictions"]
            {
                return Err("actor actual sample counters/omissions contradictory".into());
            }
            let sample = coverage["sample"]
                .as_array()
                .filter(|sample| sample.len() <= 1024)
                .ok_or("actor actual bounded process sample absent")?;
            if sample.len() as u64
                > coverage["counters"]["identity_observations_verified"]
                    .as_u64()
                    .expect("validated count")
            {
                return Err("actor sample exceeds actually verified observations".into());
            }
            let mut identities = BTreeSet::new();
            for row in sample {
                shape(row, &["identity", "last_observation_sequence"], &[])?;
                shape(
                    &row["identity"],
                    &["process_id", "creation_time_100ns"],
                    &[],
                )?;
                let pid = row["identity"]["process_id"]
                    .as_u64()
                    .filter(|value| *value > 0 && *value <= u32::MAX as u64)
                    .ok_or("actor sampled native PID malformed")?;
                let birth = row["identity"]["creation_time_100ns"]
                    .as_u64()
                    .filter(|value| *value > 0)
                    .ok_or("actor sampled native birth malformed")?;
                if !identities.insert((pid, birth))
                    || row["last_observation_sequence"]
                        .as_u64()
                        .is_none_or(|value| value == 0)
                {
                    return Err("actor process sample duplicates identity or loses sequence".into());
                }
            }
        }
        _ => return Err("actor process observation coverage unknown".into()),
    }
    Ok(())
}
