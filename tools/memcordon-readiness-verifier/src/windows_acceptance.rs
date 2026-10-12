//! Independent Windows raw-evidence rules. Producer assessment code is never
//! imported here; native execution and custody joins remain separate inputs.
use serde_json::Value;

use crate::VerificationResult;

/// All inputs have already passed bounded artifact custody and common header
/// checks. Windows-specific branches must still independently join every raw
/// authority, effect and lifetime record before returning acceptance.
pub(crate) struct WindowsAcceptanceContext<'a> {
    pub index: &'a crate::EvidenceIndex,
    pub record: &'a crate::CaseRecord,
    pub evidence: &'a crate::CaseEvidence,
    pub invocation: &'a crate::NativeInvocation,
    pub native: &'a crate::NativeObservation,
    pub retirement: &'a crate::RetirementObservation,
    pub semantic: &'a crate::SemanticObservation,
    pub products: &'a std::collections::BTreeMap<crate::ProductKey, &'a crate::ProductObservation>,
    pub builds: &'a std::collections::BTreeMap<String, &'a crate::ComponentBuild>,
    pub custody: &'a crate::custody::Custody,
}

/// The four policy refusals have no native target or Job. Validate their actual
/// command, request, provider cause, registry restoration and SCM census before
/// permitting this precisely scoped absence of retirement authority.
pub(crate) fn validate_authenticated_refusal_case(
    context: &WindowsAcceptanceContext<'_>,
) -> VerificationResult<bool> {
    use crate::{EvidenceClass, OutcomeOrigin, WindowsRefusalEvidence};
    let key = &context.record.key;
    if !key.target.ends_with("windows-msvc")
        || key.evidence_class != EvidenceClass::InstalledProduct
        || !((key.family == "W-STATUS" && key.scenario == "admission-refusal")
            || (key.family == "W-BINDING"
                && [
                    "stale-policy-epoch",
                    "revoked-grant",
                    "wrong-authorized-caller",
                ]
                .contains(&key.scenario.as_str())))
    {
        return Ok(false);
    }
    let WindowsRefusalEvidence::AuthenticatedAdmission {
        provider_request,
        requested_contract,
        quiescence,
        guardian_quiescence,
        frontend,
        baseline_policy,
        baseline_contract,
        prior_contract,
        prior_activation,
        prior_invocation,
        prior_exit,
        prior_stderr,
        baseline_activation,
        policy_apply,
        policy_restore,
    } = context
        .semantic
        .windows_refusal
        .as_ref()
        .ok_or("Windows authenticated refusal observations absent")?
    else {
        return Err("Windows policy refusal substitutes another execution shape".into());
    };
    let product_key = crate::ProductKey {
        target: key.target.clone(),
        channel: key
            .channel
            .clone()
            .ok_or("Windows product channel absent")?,
    };
    let product = context
        .products
        .get(&product_key)
        .ok_or("Windows selected product absent")?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("Windows selected CLI absent")?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("Windows selected agent absent")?;
    let manifest_sha = context.custody.hash(&product.runtime_manifest)?;
    let provider = serde_json::json!({"generation":format!("{}:{}",context.index.version,context.index.source_commit),
        "source_commit":context.index.source_commit,"runtime_manifest_sha256":manifest_sha});
    let native = context.native;
    let retired = context.retirement;
    let evidence = context.evidence;
    // This scoped branch establishes its own headers and original association;
    // an early router return must not rely on later generic semantic checks.
    crate::header(
        &evidence.format,
        evidence.revision,
        "memcordon.consumer-readiness.case",
    )?;
    crate::header(
        &native.format,
        native.revision,
        "memcordon.consumer-readiness.native",
    )?;
    if evidence.key != *key
        || evidence.run_id != context.record.run_id
        || evidence.source_commit != context.index.source_commit
        || evidence.source_tree_sha256 != context.index.source_tree_sha256
        || native.run_id != evidence.run_id
        || native.target != key.target
        || native.lease_id != evidence.lease_id
        || native.invocation_sha256 != context.invocation.association_sha256
        || native.executable_sha256 != context.invocation.executable_sha256
        || context.custody.hash(&evidence.input)? != evidence.input_sha256
    {
        return Err(
            "authenticated Windows refusal crosses original case/native/input association".into(),
        );
    }
    if evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
        || evidence.component_recipe_id.is_some()
        || native.origin != OutcomeOrigin::AdmissionRefusal
        || native.executable_sha256 != cli.installed_sha256
        || !native.authenticated_provider_exchange
        || native.root_pid.is_some()
        || native.root_birth.is_some()
        || native.target_status.is_some()
        || !native.held_processes.is_empty()
        || native.application_stage.is_some()
        || native.provider_sha256.as_deref() != Some(agent.installed_sha256.as_str())
        || native.runtime_manifest_sha256.as_deref() != Some(manifest_sha)
        || native.provider_generation.as_deref() != provider["generation"].as_str()
        || native.attempt_id.as_deref().is_none_or(str::is_empty)
        || native.attempt_nonce.is_none()
        || evidence.authenticated_terminal.is_some()
        || evidence.windows_loss.is_some()
        || evidence.execution_invocation.is_some()
        || evidence.execution_environment.is_some()
        || evidence.provider_request.as_deref() != Some(provider_request.as_str())
        || evidence.request.as_deref() != Some(requested_contract.as_str())
    {
        return Err(
            "Windows refusal invents native authority or differs from selected installed lease"
                .into(),
        );
    }
    crate::header(
        &retired.format,
        retired.revision,
        "memcordon.consumer-readiness.retirement",
    )?;
    if retired.run_id != native.run_id
        || retired.attempt_id != native.attempt_id
        || retired.root_pid.is_some()
        || retired.root_birth.is_some()
        || !retired.target_reaped_or_absent
        || !retired.aggregate_empty
        || !retired.independently_observed
        || retired.relays_retired
        || retired.guardian_retired
        || retired.native_handles_closed
        || retired.final_job_handles_closed.is_some()
        || retired.active_processes_zero.is_some()
        || retired.namespace_init_reaped.is_some()
        || retired.private_root_closed.is_some()
        || retired.exports_finalized.is_some()
        || retired.account_reservation_retired.is_some()
        || !retired.outstanding.is_empty()
        || !retired.failed_operations.is_empty()
    {
        return Err("preallocation Windows refusal manufactures target/Job retirement".into());
    }
    let json = |path: &str| crate::wire::json(context.custody.bytes(path)?);
    let policy = json(baseline_policy)?;
    let baseline = json(baseline_contract)?;
    let prior = json(prior_contract)?;
    let prior_active = json(prior_activation)?;
    let active = json(baseline_activation)?;
    let requested = json(requested_contract)?;
    let apply = policy_apply.as_deref().map(json).transpose()?;
    let restore = policy_restore.as_deref().map(json).transpose()?;
    validate_policy_refusal_mutation(
        &key.scenario,
        &policy,
        &baseline,
        &prior,
        &prior_active,
        &active,
        &requested,
        apply.as_ref(),
        restore.as_ref(),
    )?;
    // The actual outer lease's measured installed readback supplies native
    // paths; the command observation cannot select its own expected executable.
    let journal: crate::InstalledLifecycleJournal =
        crate::wire::decode(context.custody.bytes(&product.lifecycle.journal)?)?;
    let readback = journal
        .events
        .iter()
        .rfind(|event| {
            event.phase == "upgrade"
                && event.operation == "actual-installed-package-readback"
                && event.succeeded
        })
        .ok_or("Windows installed upgrade readback absent")?;
    let actual = json(&readback.native_receipt)?;
    let binaries = actual["binaries"]
        .as_array()
        .ok_or("Windows installed readback binaries absent")?;
    let selected_agent = binaries
        .iter()
        .filter(|binary| binary["binary"] == "memcordon-sealed-agent")
        .collect::<Vec<_>>();
    if selected_agent.len() != 1 || selected_agent[0]["sha256"] != agent.installed_sha256 {
        return Err(
            "Windows prior activation executable differs from actual native installed readback"
                .into(),
        );
    }
    let agent_path = selected_agent[0]["path"]
        .as_str()
        .ok_or("Windows installed agent native path absent")?;
    let lifetime_parent = product
        .lifecycle
        .journal
        .rsplit_once('/')
        .ok_or("Windows lifecycle path absent")?
        .0;
    let selected = json(&format!("{lifetime_parent}/selected-current.json"))?;
    crate::validate_acquisition_payload_shape(&selected)?;
    if selected["installed_agent"]["path"] != agent_path
        || selected["installed_agent"]["sha256"] != agent.installed_sha256
        || selected["provider"] != provider
        || selected["target"] != key.target
        || selected["source_commit"] != context.index.source_commit
        || selected["version"] != context.index.version
    {
        return Err("Windows selected acquisition crosses original product/layout/provider".into());
    }
    let output = selected["output_directory"]
        .as_str()
        .ok_or("Windows owned output native path absent")?;
    let separator = if output.ends_with('\\') || output.ends_with('/') {
        ""
    } else {
        "\\"
    };
    let policy_path = format!("{output}{separator}windows-local-policy.json");
    validate_prior_activation_command(
        context.custody.bytes(prior_invocation)?,
        &json(prior_exit)?,
        context.custody.bytes(prior_activation)?,
        context.custody.bytes(prior_stderr)?,
        &agent.installed_sha256,
        &agent_path.encode_utf16().collect::<Vec<_>>(),
        &policy_path.encode_utf16().collect::<Vec<_>>(),
        &output.encode_utf16().collect::<Vec<_>>(),
        context.custody.bytes(baseline_policy)?,
    )?;
    validate_guardian_quiescence(
        &json(guardian_quiescence)?,
        &agent.installed_sha256,
        manifest_sha,
        &agent_path.encode_utf16().collect::<Vec<_>>(),
    )?;
    let quiet = json(quiescence)?;
    fields(
        &quiet,
        &[
            "format",
            "revision",
            "provider",
            "installed_agent_sha256",
            "runtime_manifest_sha256",
            "guardian_native_quiescence",
            "fixture_processes_absent",
            "owned_policy_restoration_required",
            "owned_policy_restoration_completed",
        ],
    )?;
    let changed = matches!(
        key.scenario.as_str(),
        "revoked-grant" | "wrong-authorized-caller"
    );
    if quiet["format"] != "memcordon.windows-native-refusal-quiescence"
        || quiet["revision"] != 1
        || quiet["provider"] != provider
        || quiet["installed_agent_sha256"] != agent.installed_sha256
        || quiet["runtime_manifest_sha256"] != manifest_sha
        || quiet["guardian_native_quiescence"] != true
        || quiet["fixture_processes_absent"] != true
        || quiet["owned_policy_restoration_required"] != changed
        || quiet["owned_policy_restoration_completed"] != changed
    {
        return Err(
            "Windows actual refusal quiescence/restoration crosses selected authority".into(),
        );
    }
    let provider_bytes = context.custody.bytes(provider_request)?;
    if native.request_sha256.as_deref() != Some(context.custody.hash(provider_request)?) {
        return Err("Windows rejected provider request SHA differs".into());
    }
    let wire_request = crate::wire::json(provider_bytes)?;
    if wire_request["expected_provider_binding"] != provider
        || wire_request["nonce"] != serde_json::json!(native.attempt_nonce)
        || wire_request["restart_attempt"] != 0
    {
        return Err("Windows rejected request provider/nonce/restart binding differs".into());
    }
    crate::wire::validate_windows_request(
        provider_bytes,
        context.custody.bytes(requested_contract)?,
        context.invocation,
        context.custody.bytes(&context.invocation.environment)?,
    )?;
    let result_path = evidence
        .raw_result
        .as_deref()
        .ok_or("Windows actual refusal result absent")?;
    let frontend_observation = json(frontend)?;
    fields(
        &frontend_observation,
        &[
            "format",
            "revision",
            "process_id",
            "creation_time_100ns",
            "image_sha256",
            "held_before_wait",
            "native_wait_completed",
            "native_status",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    if frontend_observation["format"] != "memcordon.windows-native-refusal-frontend"
        || frontend_observation["revision"] != 1
        || frontend_observation["process_id"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= u64::from(u32::MAX))
            .is_none()
        || frontend_observation["creation_time_100ns"]
            .as_u64()
            .filter(|birth| *birth > 0)
            .is_none()
        || frontend_observation["image_sha256"] != cli.installed_sha256
        || frontend_observation["held_before_wait"] != true
        || frontend_observation["native_wait_completed"] != true
        || frontend_observation["native_status"] != native.frontend_status
    {
        return Err("Windows refusal frontend native ownership differs".into());
    }
    let result_parent = result_path
        .rsplit_once('/')
        .ok_or("Windows refusal result lacks owned parent")?
        .0;
    for (field, basename) in [
        ("stdout_sha256", "stdout.bin"),
        ("stderr_sha256", "stderr.bin"),
    ] {
        let path = format!("{result_parent}/{basename}");
        if frontend_observation[field] != context.custody.hash(&path)? {
            return Err("Windows refusal frontend captured bytes differ".into());
        }
    }
    let actual_result = json(result_path)?;
    let rejection_diagnostic =
        &actual_result["error"]["windows_provider_rejection_v2"]["provider_failure"];
    if actual_result["error"]["provider_failure"] != *rejection_diagnostic
        || actual_result["diagnostics"] != *rejection_diagnostic
    {
        return Err(
            "Windows refusal diagnostic projection differs from actual provider rejection".into(),
        );
    }
    if !rejection_diagnostic.is_null() {
        fields(
            rejection_diagnostic,
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
        if rejection_diagnostic["schema_version"] != 1
            || rejection_diagnostic["provider_binding"] != provider
            || rejection_diagnostic["attempt_id"] != serde_json::json!(native.attempt_id)
            || rejection_diagnostic["request_sha256"] != serde_json::json!(native.request_sha256)
        {
            return Err("Windows refusal diagnostic belongs to another request/provider".into());
        }
        crate::wire::validate_original_failure(&rejection_diagnostic["original"])?;
        let original = &rejection_diagnostic["original"];
        fields(original, &["observed"])?;
        fields(&original["observed"], &["event"])?;
        let event = &original["observed"]["event"];
        // The native admission path captures LaunchAttemptError::from before
        // assigning its outward admission code. Preserve that actual first
        // observation instead of manufacturing a later admission event.
        if event
            != &serde_json::json!({
                "sequence":1,"origin":"launcher","category":"launch",
                "operation":"unclassified-provider-operation","code":"unexpected-provider-failure",
                "native_code":null,"observed_phase":"before-authorization",
                "safe_detail":"no-additional-detail","detail_redacted":true,
                "detail_truncated":false,"terminalization_reference":null
            })
        {
            return Err(
                "Windows admission original observation differs from native capture site".into(),
            );
        }
        let sequence = rejection_diagnostic["diagnostic_sequence"]
            .as_u64()
            .ok_or("Windows refusal diagnostic sequence invalid")?;
        if sequence == 0
            || rejection_diagnostic["durable_through_sequence"]
                .as_u64()
                .is_some_and(|durable| durable > sequence)
        {
            return Err("Windows refusal diagnostic persistence sequence differs".into());
        }
        if sequence != 1
            || !rejection_diagnostic["durable_through_sequence"].is_null()
            || rejection_diagnostic["secondary"] != serde_json::json!([])
            || rejection_diagnostic["loss"]
                != serde_json::json!({"secondary_events_omitted":0,"secondary_count_saturated":false,"persistence_failure_observed":false,"writer_unavailable":false})
        {
            return Err("Windows ordinary admission diagnostics include unrelated effects or unavailable publication".into());
        }
        let mut projection = b"memcordon:causal-diagnostic:v1\0".to_vec();
        projection.extend_from_slice(&1_u32.to_be_bytes());
        for field in ["generation", "source_commit"] {
            let text = provider[field]
                .as_str()
                .ok_or("Windows diagnostic provider text absent")?;
            projection.extend_from_slice(&(text.len() as u64).to_be_bytes());
            projection.extend_from_slice(text.as_bytes());
        }
        for text in [
            provider["runtime_manifest_sha256"].as_str(),
            native.attempt_id.as_deref(),
            native.request_sha256.as_deref(),
        ] {
            let bytes = hex::decode(text.ok_or("Windows diagnostic digest absent")?)
                .map_err(|_| "Windows diagnostic digest malformed")?;
            if bytes.len() != 32 {
                return Err("Windows diagnostic digest length differs".into());
            }
            projection.extend_from_slice(&bytes);
        }
        projection.extend_from_slice(&1_u64.to_be_bytes());
        projection.extend_from_slice(&[0, 0]); // no durable sequence; observed original
        projection.extend_from_slice(&1_u64.to_be_bytes());
        for tag in [0_u16, 1, 32, 13] {
            projection.extend_from_slice(&tag.to_be_bytes());
        }
        projection.push(0); // no native code
        projection.extend_from_slice(&0_u16.to_be_bytes());
        projection.extend_from_slice(&[0, 1, 0, 0]); // detail, redacted, truncated, no terminal reference
        projection.extend_from_slice(&0_u64.to_be_bytes());
        projection.extend_from_slice(&0_u32.to_be_bytes());
        projection.extend_from_slice(&[0, 0, 0]);
        if rejection_diagnostic["projection_sha256"] != crate::sha256(&projection) {
            return Err("Windows admission diagnostic canonical projection differs".into());
        }
    }
    fields(&actual_result["delivery"], &["prepared-by"])?;
    fields(&actual_result["delivery"]["prepared-by"], &["writer_pid"])?;
    if actual_result["delivery"]["prepared-by"]["writer_pid"] != frontend_observation["process_id"]
    {
        return Err("Windows refusal delivery writer differs from retained frontend".into());
    }
    crate::wire::validate_result(
        context.custody.bytes(result_path)?,
        None,
        context.custody.bytes(requested_contract)?,
        native,
        key,
        &context.index.version,
        &context.index.source_commit,
        evidence,
        context.custody,
    )?;
    validate_admission_refusal_cause(
        &key.scenario,
        &json(result_path)?,
        &requested,
        &provider,
        native.attempt_id.as_deref().expect("validated attempt"),
        native.request_sha256.as_deref().expect("validated request"),
    )?;
    crate::header(
        &context.semantic.format,
        context.semantic.revision,
        "memcordon.consumer-readiness.semantic",
    )?;
    let input: crate::FixtureInput = crate::wire::decode(context.custody.bytes(&evidence.input)?)?;
    crate::header(
        &input.format,
        input.revision,
        "memcordon.consumer-readiness.input",
    )?;
    let challenge = context.custody.bytes(&context.semantic.challenge)?;
    if challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || input.challenge_sha256 != crate::sha256(challenge)
        || input.key != *key
        || input.run_id != evidence.run_id
        || serde_json::to_value(&input.target_argv).map_err(|error| error.to_string())?
            != serde_json::to_value(&context.invocation.arguments)
                .map_err(|error| error.to_string())?
        || input.deadline_millis != Some(600000)
        || input.memory_bytes != Some(4 * 1024 * 1024 * 1024)
        || !input.binary.is_empty()
        || input.toolchain_identity.is_some()
        || context.semantic.key != *key
        || context.semantic.run_id != evidence.run_id
        || context.semantic.operations.len() != 1
        || !context.semantic.comparisons.is_empty()
        || !context.semantic.counters.is_empty()
        || context.semantic.negative_probe.is_some()
        || context.semantic.component_test.is_some()
        || context.semantic.component_actors.is_some()
        || context.semantic.windows_capacity.is_some()
        || context.semantic.fixture_behavior.is_some()
    {
        return Err("Windows refusal semantic source/challenge/execution shape differs".into());
    }
    let operation = &context.semantic.operations[0];
    if operation.operation != "admission-refused"
        || operation.attempt_id != native.attempt_id
        || operation.root_pid.is_some()
        || operation.observer != "owned-native-preauthorization"
        || operation.native_receipt != result_path
    {
        return Err("Windows refusal semantic operation substitutes another native result".into());
    }
    Ok(true)
}

/// Precisely scoped refusals made before any provider launch serialization.
/// The NUL row executes the measured facade; the unsupported row executes the
/// selected public CLI on its actual standard backend.
pub(crate) fn validate_preprovider_refusal_case(
    context: &WindowsAcceptanceContext<'_>,
) -> VerificationResult<bool> {
    use crate::{EvidenceClass, OutcomeOrigin, WindowsRefusalEvidence};
    let key = &context.record.key;
    let nul = key.family == "W-IO" && key.scenario == "argv-nul-rejection";
    let unsupported = key.family == "W-BINDING" && key.scenario == "unsupported-public-request";
    if !key.target.ends_with("windows-msvc")
        || key.evidence_class != EvidenceClass::InstalledProduct
        || (!nul && !unsupported)
    {
        return Ok(false);
    }
    let (quiescence, guardian, frontend, receipt) = match context
        .semantic
        .windows_refusal
        .as_ref()
        .ok_or("preprovider refusal source absent")?
    {
        WindowsRefusalEvidence::NativeArgument {
            receipt,
            quiescence,
            guardian_quiescence,
            frontend,
        } if nul => (quiescence, guardian_quiescence, frontend, Some(receipt)),
        WindowsRefusalEvidence::UnsupportedPublicRequest {
            quiescence,
            guardian_quiescence,
            frontend,
        } if unsupported => (quiescence, guardian_quiescence, frontend, None),
        _ => return Err("preprovider refusal substitutes another execution shape".into()),
    };
    let product = context
        .products
        .get(&crate::ProductKey {
            target: key.target.clone(),
            channel: key
                .channel
                .clone()
                .ok_or("preprovider installed channel absent")?,
        })
        .ok_or("preprovider selected product absent")?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("preprovider selected agent absent")?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("preprovider selected CLI absent")?;
    let executable = if nul {
        &context.evidence.fixture_sha256
    } else {
        &cli.installed_sha256
    };
    let native = context.native;
    let retired = context.retirement;
    let evidence = context.evidence;
    crate::header(
        &evidence.format,
        evidence.revision,
        "memcordon.consumer-readiness.case",
    )?;
    crate::header(
        &native.format,
        native.revision,
        "memcordon.consumer-readiness.native",
    )?;
    crate::header(
        &retired.format,
        retired.revision,
        "memcordon.consumer-readiness.retirement",
    )?;
    crate::header(
        &context.semantic.format,
        context.semantic.revision,
        "memcordon.consumer-readiness.semantic",
    )?;
    let input: crate::FixtureInput = crate::wire::decode(context.custody.bytes(&evidence.input)?)?;
    crate::header(
        &input.format,
        input.revision,
        "memcordon.consumer-readiness.input",
    )?;
    if evidence.key != *key
        || evidence.run_id != context.record.run_id
        || native.run_id != evidence.run_id
        || evidence.source_commit != context.index.source_commit
        || evidence.source_tree_sha256 != context.index.source_tree_sha256
        || input.key != *key
        || input.run_id != evidence.run_id
        || input.challenge_sha256 != context.custody.hash(&context.semantic.challenge)?
        || evidence.input_sha256 != context.custody.hash(&evidence.input)?
        || serde_json::to_value(&input.target_argv).map_err(|error| error.to_string())?
            != serde_json::to_value(&context.invocation.arguments)
                .map_err(|error| error.to_string())?
        || input.deadline_millis != if nul { None } else { Some(600000) }
        || input.memory_bytes
            != if nul {
                None
            } else {
                Some(4 * 1024 * 1024 * 1024)
            }
        || !input.binary.is_empty()
        || input.toolchain_identity.is_some()
    {
        return Err("preprovider fixture input/source/header/challenge association differs".into());
    }
    let environment: crate::NativeEnvironment =
        crate::wire::decode(context.custody.bytes(&context.invocation.environment)?)?;
    if !matches!(environment, crate::NativeEnvironment::WindowsUtf16(values) if values.is_empty()) {
        return Err(
            "preprovider owned frontend environment is not the actual cleared native block".into(),
        );
    }
    if evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
        || evidence.component_recipe_id.is_some()
        || evidence.provider_request.is_some()
        || evidence.authenticated_terminal.is_some()
        || evidence.windows_loss.is_some()
        || evidence.execution_invocation.is_some()
        || evidence.execution_environment.is_some()
        || native.origin != OutcomeOrigin::AdmissionRefusal
        || native.executable_sha256 != *executable
        || native.authenticated_provider_exchange
        || native.provider_sha256.is_some()
        || native.provider_generation.is_some()
        || native.runtime_manifest_sha256.is_some()
        || native.request_sha256.is_some()
        || native.attempt_id.is_some()
        || native.attempt_nonce.is_some()
        || native.root_pid.is_some()
        || native.root_birth.is_some()
        || native.target_status.is_some()
        || native.application_stage.is_some()
        || !native.held_processes.is_empty()
    {
        return Err("preprovider refusal invents provider/target authority".into());
    }
    if retired.run_id != native.run_id
        || retired.attempt_id.is_some()
        || retired.root_pid.is_some()
        || retired.root_birth.is_some()
        || !retired.target_reaped_or_absent
        || !retired.aggregate_empty
        || !retired.independently_observed
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
        return Err("preprovider refusal invents native family retirement".into());
    }
    let json = |path: &str| crate::wire::json(context.custody.bytes(path)?);
    let lifecycle: crate::InstalledLifecycleJournal =
        crate::wire::decode(context.custody.bytes(&product.lifecycle.journal)?)?;
    let readback = lifecycle
        .events
        .iter()
        .rfind(|event| {
            event.phase == "upgrade"
                && event.operation == "actual-installed-package-readback"
                && event.succeeded
        })
        .ok_or("preprovider installed readback absent")?;
    let actual = json(&readback.native_receipt)?;
    let agents = actual["binaries"]
        .as_array()
        .ok_or("preprovider installed binaries absent")?
        .iter()
        .filter(|binary| binary["binary"] == "memcordon-sealed-agent")
        .collect::<Vec<_>>();
    if agents.len() != 1 || agents[0]["sha256"] != agent.installed_sha256 {
        return Err("preprovider installed agent differs".into());
    }
    let agent_path = agents[0]["path"]
        .as_str()
        .ok_or("preprovider installed agent path absent")?;
    let manifest = context.custody.hash(&product.runtime_manifest)?;
    validate_guardian_quiescence(
        &json(guardian)?,
        &agent.installed_sha256,
        manifest,
        &agent_path.encode_utf16().collect::<Vec<_>>(),
    )?;
    let quiet = json(quiescence)?;
    fields(
        &quiet,
        &[
            "format",
            "revision",
            "provider",
            "installed_agent_sha256",
            "runtime_manifest_sha256",
            "guardian_native_quiescence",
            "fixture_processes_absent",
            "owned_policy_restoration_required",
            "owned_policy_restoration_completed",
        ],
    )?;
    let provider = serde_json::json!({"generation":format!("{}:{}",context.index.version,context.index.source_commit),"source_commit":context.index.source_commit,"runtime_manifest_sha256":manifest});
    if quiet["format"] != "memcordon.windows-native-refusal-quiescence"
        || quiet["revision"] != 1
        || quiet["provider"] != provider
        || quiet["installed_agent_sha256"] != agent.installed_sha256
        || quiet["runtime_manifest_sha256"] != manifest
        || quiet["guardian_native_quiescence"] != true
        || quiet["fixture_processes_absent"] != true
        || quiet["owned_policy_restoration_required"] != false
        || quiet["owned_policy_restoration_completed"] != false
    {
        return Err("preprovider actual quiescence crosses selected generation".into());
    }
    let result_path = evidence
        .raw_result
        .as_deref()
        .ok_or("preprovider actual result absent")?;
    let frontend = json(frontend)?;
    fields(
        &frontend,
        &[
            "format",
            "revision",
            "process_id",
            "creation_time_100ns",
            "image_sha256",
            "held_before_wait",
            "native_wait_completed",
            "native_status",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    if frontend["format"] != "memcordon.windows-native-refusal-frontend"
        || frontend["revision"] != 1
        || frontend["process_id"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= u64::from(u32::MAX))
            .is_none()
        || frontend["creation_time_100ns"]
            .as_u64()
            .filter(|birth| *birth > 0)
            .is_none()
        || frontend["image_sha256"] != *executable
        || frontend["held_before_wait"] != true
        || frontend["native_wait_completed"] != true
        || frontend["native_status"] != native.frontend_status
    {
        return Err("preprovider frontend native identity/wait differs".into());
    }
    let parent = result_path
        .rsplit_once('/')
        .ok_or("preprovider result parent absent")?
        .0;
    for (field, leaf) in [
        ("stdout_sha256", "stdout.bin"),
        ("stderr_sha256", "stderr.bin"),
    ] {
        if frontend[field] != context.custody.hash(&format!("{parent}/{leaf}"))? {
            return Err("preprovider captured bytes differ".into());
        }
    }
    let request = evidence
        .request
        .as_deref()
        .ok_or("preprovider actual contract absent")?;
    if nul {
        if receipt.map(String::as_str) != Some(result_path) {
            return Err("NUL facade receipt differs from actual result".into());
        }
        crate::wire::validate_result(
            context.custody.bytes(result_path)?,
            None,
            context.custody.bytes(request)?,
            native,
            key,
            &context.index.version,
            &context.index.source_commit,
            evidence,
            context.custody,
        )?;
        let crate::NativeArguments::WindowsUtf16(arguments) = &context.invocation.arguments else {
            return Err("NUL facade native argv codec differs".into());
        };
        if arguments.len() != 5
            || arguments[0]
                != "consumer-readiness-windows"
                    .encode_utf16()
                    .collect::<Vec<_>>()
            || arguments[1] != "argv-nul-refusal".encode_utf16().collect::<Vec<_>>()
            || native.frontend_status != 0
        {
            return Err("NUL row did not execute actual bounded facade".into());
        }
    } else {
        let result = json(result_path)?;
        fields(
            &result,
            &[
                "format",
                "revision",
                "tool",
                "invocation",
                "policy",
                "attempts",
                "supervision",
                "error",
                "backend",
                "authorization",
                "launch",
                "outcome",
                "cleanup",
                "restart",
                "runtime",
                "private_execution",
                "private_rejection",
                "diagnostics",
                "provider_association",
                "delivery",
            ],
        )?;
        if result["format"] != "memcordon.result"
            || result["revision"] != 1
            || result["tool"]["name"] != "memcordon"
            || result["tool"]["version"] != context.index.version
            || result["tool"]["os"] != "windows"
            || result["tool"]["architecture"]
                != key
                    .target
                    .split('-')
                    .next()
                    .ok_or("preprovider native target absent")?
            || result["invocation"]["association_sha256"] != native.invocation_sha256
            || result["authorization"] != "not-required-for-standard"
            || result["launch"] != serde_json::json!({"state":"not-created","target_pid":null})
            || result["runtime"] != serde_json::json!({"kind":"standard","observation":null})
            || !result["provider_association"].is_null()
            || !result["diagnostics"].is_null()
            || !result["private_execution"].is_null()
            || !result["private_rejection"].is_null()
            || result["outcome"]["kind"] != "launch-failure"
            || native.frontend_status != 125
            || result["outcome"]["wrapper_status"] != native.frontend_status
            || !result["outcome"]["native_termination"].is_null()
            || result["error"]["code"] != "MCUNSUPPORTED-WORKLOAD-CONTRACT"
            || result["error"]["category"] != "unsupported"
            || !result["error"]["provider_failure"].is_null()
            || !result["error"]["windows_provider_rejection_v2"].is_null()
            || result["cleanup"]["state"] != "complete"
            || result["cleanup"]["outstanding"] != serde_json::json!([])
            || result["cleanup"]["failed_operations"] != serde_json::json!([])
            || result["delivery"]
                != serde_json::json!({"prepared-by":{"writer_pid":frontend["process_id"]}})
        {
            return Err(
                "standard unsupported request substitutes execution/provider authority".into(),
            );
        }
        let contract = json(request)?;
        let contract_sha = windows_contract_digest(&contract)?;
        if result["attempts"] != serde_json::json!([])
            || !result["supervision"].is_null()
            || !result["restart"].is_null()
            || result["error"]["message"] != "strict workload admission requires a sealed provider"
            || result["error"]["target_released"] != false
            || result["error"]["workload_may_be_alive"] != false
            || !result["error"]["os_code"].is_null()
            || !result["error"]["attempt_number"].is_null()
            || !result["error"]["boundary_setup_failure"].is_null()
            || !result["error"]["provider_rejection"].is_null()
            || result["policy"]["requested"]["boundary"] != "standard"
            || result["policy"]["effective"]["boundary"] != "standard"
            || result["policy"]["requested"]["workload"]
                != serde_json::json!({"state":"strict-v1","contract":contract})
            || result["policy"]["effective"]["workload"]
                != serde_json::json!({"state":"unavailable",
                "request":{"request_digest":contract_sha,"workload_plan_digest":contract["workload_plan_digest"],"profile":contract["authorized_profile"],"authorization":contract["authorization"],"epoch":contract["expected_epoch"]},
                "reason":"binding-unavailable","authorization":"not-authorized"})
        {
            return Err("standard refusal changes actual prelaunch cause/request knowledge".into());
        }
        let crate::NativeArguments::WindowsUtf16(arguments) = &context.invocation.arguments else {
            return Err("unsupported native argv codec differs".into());
        };
        if arguments
            .iter()
            .any(|argument| argument == &"--sealed".encode_utf16().collect::<Vec<_>>())
            || !arguments.iter().any(|argument| {
                argument == &"--workload-contract".encode_utf16().collect::<Vec<_>>()
            })
        {
            return Err(
                "unsupported row did not select actual standard strict-contract request".into(),
            );
        }
    }
    let semantic = context.semantic;
    let challenge = context.custody.bytes(&semantic.challenge)?;
    if semantic.key != *key
        || semantic.run_id != native.run_id
        || challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || semantic.operations.len() != 1
        || !semantic.comparisons.is_empty()
        || !semantic.counters.is_empty()
        || semantic.negative_probe.is_some()
        || semantic.component_test.is_some()
        || semantic.component_actors.is_some()
        || semantic.windows_capacity.is_some()
        || semantic.fixture_behavior.is_some()
    {
        return Err("preprovider semantic source/challenge/execution shape differs".into());
    }
    let operation = &semantic.operations[0];
    if operation.operation
        != if nul {
            "argv-nul-rejected"
        } else {
            "admission-refused"
        }
        || operation.attempt_id.is_some()
        || operation.root_pid.is_some()
        || operation.observer != "owned-native-preauthorization"
        || operation.native_receipt != result_path
    {
        return Err("preprovider semantic operation differs from actual receipt".into());
    }
    Ok(true)
}

/// Validate the complete persisted preprovider branch with native artifact
/// custody. This does not replace index, product lineage or lifecycle gates.
pub fn validate_preprovider_case(
    index: &crate::EvidenceIndex,
    record: &crate::CaseRecord,
    root: &std::path::Path,
) -> VerificationResult<()> {
    validate_persisted_refusal_case(index, record, root, PersistedBranch::Preprovider)
}

/// Exercises the complete authenticated refusal predicate with persisted native
/// artifact custody. Index/product lifecycle verification remains separate.
pub fn validate_authenticated_case(
    index: &crate::EvidenceIndex,
    record: &crate::CaseRecord,
    root: &std::path::Path,
) -> VerificationResult<()> {
    validate_persisted_refusal_case(index, record, root, PersistedBranch::Authenticated)
}

/// Decoder vectors for the complete native actor branch. This cannot establish
/// native execution or substitute for the index's component build gates.
pub fn validate_actor_case(
    index: &crate::EvidenceIndex,
    record: &crate::CaseRecord,
    root: &std::path::Path,
) -> VerificationResult<()> {
    validate_persisted_refusal_case(index, record, root, PersistedBranch::Actors)
}

enum PersistedBranch {
    Preprovider,
    Authenticated,
    Actors,
}

fn validate_persisted_refusal_case(
    index: &crate::EvidenceIndex,
    record: &crate::CaseRecord,
    root: &std::path::Path,
    branch: PersistedBranch,
) -> VerificationResult<()> {
    let custody = crate::custody::Custody::new(root, &index.artifacts)?;
    let evidence: crate::CaseEvidence = crate::wire::decode(
        custody.bytes(
            record
                .evidence
                .as_deref()
                .ok_or("preprovider case path absent")?,
        )?,
    )?;
    let invocation: crate::NativeInvocation =
        crate::wire::decode(custody.bytes(&evidence.invocation)?)?;
    let native: crate::NativeObservation =
        crate::wire::decode(custody.bytes(&evidence.native_observation)?)?;
    let retirement: crate::RetirementObservation =
        crate::wire::decode(custody.bytes(&evidence.retirement)?)?;
    let semantic: crate::SemanticObservation =
        crate::wire::decode(custody.bytes(&evidence.semantic_observation)?)?;
    let products = index
        .products
        .iter()
        .map(|product| (product.key.clone(), product))
        .collect();
    let builds = index
        .component_builds
        .iter()
        .map(|build| (build.target.clone(), build))
        .collect();
    if evidence.key != record.key
        || evidence.run_id != record.run_id
        || evidence.source_commit != index.source_commit
        || evidence.source_tree_sha256 != index.source_tree_sha256
        || native.run_id != evidence.run_id
        || native.target != record.key.target
        || native.invocation_sha256 != invocation.association_sha256
        || native.executable_sha256 != invocation.executable_sha256
        || crate::reconstruct_invocation_sha256(&invocation)? != invocation.association_sha256
        || custody.hash(&invocation.environment)? != invocation.environment_sha256
        || custody.hash(&evidence.fixture)? != evidence.fixture_sha256
        || custody.hash(&evidence.fixture_source)? != evidence.fixture_source_sha256
        || custody.hash(&evidence.input)? != evidence.input_sha256
    {
        return Err("preprovider persisted case/common association differs".into());
    }
    let context = WindowsAcceptanceContext {
        index,
        record,
        evidence: &evidence,
        invocation: &invocation,
        native: &native,
        retirement: &retirement,
        semantic: &semantic,
        products: &products,
        builds: &builds,
        custody: &custody,
    };
    let applicable = match branch {
        PersistedBranch::Authenticated => validate_authenticated_refusal_case(&context)?,
        PersistedBranch::Preprovider => validate_preprovider_refusal_case(&context)?,
        PersistedBranch::Actors => crate::windows_actors::validate(&context)?,
    };
    if !applicable {
        return Err("case is outside the selected exact refusal branch".into());
    }
    Ok(())
}

fn fields(value: &Value, required: &[&str]) -> VerificationResult<()> {
    let object = value.as_object().ok_or("Windows evidence object absent")?;
    if object.len() != required.len()
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()))
    {
        return Err("Windows evidence object has missing or unknown fields".into());
    }
    Ok(())
}

/// Validates actual administrative command observations without interpreting
/// them as a provider launch or a terminal retirement authority.
#[expect(
    clippy::too_many_arguments,
    reason = "Compare independent policy, process and captured invocation observations"
)]
pub fn validate_prior_activation_command(
    invocation_bytes: &[u8],
    exit: &Value,
    stdout: &[u8],
    stderr: &[u8],
    agent_sha256: &str,
    program_utf16: &[u16],
    policy_utf16: &[u16],
    cwd_utf16: &[u16],
    policy_bytes: &[u8],
) -> VerificationResult<()> {
    let invocation = crate::wire::json(invocation_bytes)?;
    fields(
        &invocation,
        &[
            "format",
            "revision",
            "agent_sha256",
            "program_utf16",
            "argv_utf16",
            "cwd_utf16",
            "environment_cleared",
            "budget_millis",
            "policy_sha256",
        ],
    )?;
    let argv = ["package", "policy", "apply", "--file"]
        .into_iter()
        .map(|argument| argument.encode_utf16().collect::<Vec<_>>())
        .chain(std::iter::once(policy_utf16.to_vec()))
        .collect::<Vec<_>>();
    if invocation["format"] != "memcordon.windows-policy-activation-command"
        || invocation["revision"] != 1
        || invocation["agent_sha256"] != agent_sha256
        || invocation["program_utf16"] != serde_json::json!(program_utf16)
        || invocation["argv_utf16"] != serde_json::json!(argv)
        || invocation["cwd_utf16"] != serde_json::json!(cwd_utf16)
        || invocation["environment_cleared"] != true
        || invocation["policy_sha256"] != crate::sha256(policy_bytes)
        || invocation["budget_millis"]
            .as_u64()
            .is_none_or(|budget| budget == 0 || budget > 30_000)
    {
        return Err(
            "Windows prior activation command differs from exact selected native input".into(),
        );
    }
    fields(
        exit,
        &[
            "format",
            "revision",
            "invocation_sha256",
            "status",
            "success",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    if exit["format"] != "memcordon.windows-policy-activation-exit"
        || exit["revision"] != 1
        || exit["invocation_sha256"] != crate::sha256(invocation_bytes)
        || exit["status"] != 0
        || exit["success"] != true
        || exit["stdout_sha256"] != crate::sha256(stdout)
        || exit["stderr_sha256"] != crate::sha256(stderr)
    {
        return Err("Windows prior activation native exit or capture association differs".into());
    }
    Ok(())
}

/// Independent V1 preimage for the frozen Windows readiness workload. This
/// pins the complete TCP requirement instead of accepting a narrowed plan.
pub fn windows_contract_digest(contract: &Value) -> VerificationResult<String> {
    fields(
        contract,
        &[
            "schema_version",
            "workload_plan_digest",
            "authorized_profile",
            "authorization",
            "ceiling",
            "requirements",
            "endpoints",
            "expected_epoch",
        ],
    )?;
    fields(&contract["authorized_profile"], &["id", "semantic_digest"])?;
    fields(
        &contract["authorization"],
        &["grant_id", "grant_revision", "approved_plan_digest"],
    )?;
    if contract["schema_version"] != 1
        || contract["authorized_profile"]["id"] != "windows-host-network-external-v1"
        || contract["authorized_profile"]["semantic_digest"] != windows_profile_digest()
        || contract["authorization"]["grant_id"] != "windows-readiness-owned"
        || contract["authorization"]["grant_revision"] != 1
        || contract["authorization"]["approved_plan_digest"] != contract["workload_plan_digest"]
        || contract["ceiling"]
            != serde_json::json!({
            "direct_socket_authority":"external-host-policy-accepted",
            "unix_authority":"existing-host-unix-authority-accepted",
            "external_socket_custody":"existing-stdio-authority-accepted",
            "credential_gains":"existing-caller-envelope-accepted",
            "mediated_communication":"external-filesystem-and-stdio-policy-accepted"})
        || contract["requirements"]
            != serde_json::json!([{
            "kind":"tcp","id":"owned-tcp","family":"v4",
            "operations":["create","bind","listen","accept","stream-read","stream-write"],
            "scope":"host-shared-loopback","local_ports":{"kind":"kernel-assigned"},
            "peer":{"kind":"exact-address","endpoint":{"family":"v4","address":[127,0,0,1],"port":1}}},
            {"kind":"tcp","id":"owned-tcp-client","family":"v4",
            "operations":["create","connect","stream-read","stream-write"],
            "scope":"host-shared-loopback","local_ports":{"kind":"kernel-assigned"},
            "peer":{"kind":"same-attempt-endpoint","endpoint":"owned-listener"}}])
        || contract["endpoints"]
            != serde_json::json!([{"id":"owned-listener","requirement":"owned-tcp"}])
    {
        return Err("Windows workload differs from the complete frozen readiness contract".into());
    }
    epoch(&contract["expected_epoch"])?;
    fn id(bytes: &mut Vec<u8>, value: &str) -> VerificationResult<()> {
        let length = u16::try_from(value.len()).map_err(|_| "Windows canonical id too long")?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }
    fn hash(bytes: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
        let value = value.as_str().ok_or("Windows canonical digest absent")?;
        crate::digest(value)?;
        bytes.extend_from_slice(&hex::decode(value).map_err(|error| error.to_string())?);
        Ok(())
    }
    let mut bytes = b"memcordon-workload-contract-v1\0\0\x01".to_vec();
    hash(&mut bytes, &contract["workload_plan_digest"])?;
    id(&mut bytes, "windows-host-network-external-v1")?;
    hash(
        &mut bytes,
        &contract["authorized_profile"]["semantic_digest"],
    )?;
    id(&mut bytes, "windows-readiness-owned")?;
    bytes.extend_from_slice(&1u64.to_be_bytes());
    hash(
        &mut bytes,
        &contract["authorization"]["approved_plan_digest"],
    )?;
    bytes.extend_from_slice(&[4, 2, 2, 2, 1]);
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.push(3);
    id(&mut bytes, "owned-tcp")?;
    bytes.push(1);
    bytes.extend_from_slice(&6u16.to_be_bytes());
    bytes.extend_from_slice(&[1, 2, 3, 4, 6, 7, 2, 1, 2, 1, 127, 0, 0, 1]);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(3);
    id(&mut bytes, "owned-tcp-client")?;
    bytes.push(1);
    bytes.extend_from_slice(&4u16.to_be_bytes());
    bytes.extend_from_slice(&[1, 5, 6, 7, 2, 1, 1]);
    id(&mut bytes, "owned-listener")?;
    bytes.extend_from_slice(&1u16.to_be_bytes());
    id(&mut bytes, "owned-listener")?;
    id(&mut bytes, "owned-tcp")?;
    for byte in contract["expected_epoch"]["service_instance"]
        .as_array()
        .expect("validated nonce")
    {
        bytes.push(u8::try_from(byte.as_u64().expect("validated byte")).expect("validated byte"));
    }
    bytes.extend_from_slice(
        &contract["expected_epoch"]["revision"]
            .as_u64()
            .expect("validated revision")
            .to_be_bytes(),
    );
    Ok(crate::sha256(&bytes))
}

/// Check the actual typed refusal and complete request binding. This does not
/// replace the separate selected-provider exchange and native census joins.
pub fn validate_admission_refusal_cause(
    scenario: &str,
    result: &Value,
    contract: &Value,
    provider: &Value,
    attempt_id: &str,
    provider_request_sha256: &str,
) -> VerificationResult<()> {
    let expected = match scenario {
        "admission-refusal" | "stale-policy-epoch" => "policy-epoch-stale",
        "revoked-grant" | "wrong-authorized-caller" => "profile-not-authorized",
        _ => return Err("unfrozen Windows authenticated admission refusal".into()),
    };
    fields(
        provider,
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    crate::digest(
        provider["runtime_manifest_sha256"]
            .as_str()
            .ok_or("Windows selected manifest digest absent")?,
    )?;
    if provider["generation"].as_str().is_none_or(str::is_empty)
        || provider["source_commit"].as_str().is_none_or(str::is_empty)
    {
        return Err("Windows selected provider identity absent".into());
    }
    let association = &result["provider_association"];
    fields(association, &["provider", "attempt_id", "request_sha256"])?;
    if association["provider"] != *provider
        || association["attempt_id"] != attempt_id
        || association["request_sha256"] != provider_request_sha256
        || result["authorization"] != "rejected-before-release"
        || result["launch"] != serde_json::json!({"state":"not-created","target_pid":null})
        || result["outcome"]["kind"] != "provider-failure"
        || result["runtime"]
            != serde_json::json!({"kind":"unavailable","reason":"no operational runtime observation available"})
        || !result["outcome"]["native_termination"].is_null()
        || result["error"]["category"] != "setup"
        || result["error"]["code"] != "MCSEALED-PROVIDER-REJECTION"
        || result["error"]["target_released"] != false
        || result["error"]["workload_may_be_alive"] != false
    {
        return Err("Windows refusal substitutes target authority, provider or first cause".into());
    }
    let rejection = &result["error"]["windows_provider_rejection_v2"];
    let object = rejection
        .as_object()
        .ok_or("typed native Windows refusal absent")?;
    let required = [
        "schema_version",
        "workload_admission",
        "code",
        "phase",
        "detail",
        "os_code",
        "target_created",
        "target_released",
        "cleanup_attempted",
        "restart_safety",
        "disposition",
    ];
    if required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()) && field != "provider_failure")
        || rejection["schema_version"] != 2
        || rejection["code"] != "MCSEALED-POLICY-ADMISSION"
        || rejection["phase"] != "provider-connection"
        || rejection["detail"]
            != "exact caller workload admission was rejected before target allocation"
        || !rejection["os_code"].is_null()
        || rejection["target_created"] != false
        || rejection["target_released"] != false
        || rejection["cleanup_attempted"] != false
        || rejection["restart_safety"]
            != serde_json::json!({
            "direct_child_reaped":false,"workload_empty":null,"helpers_reaped":false,
            "containment_removed":false,"containment_incapable_of_live_members":false,
            "sealed_boundary_retired":false,"errors":[]})
        || rejection["disposition"]
            != serde_json::json!({"disposition":"preauthorization","terminal_ack_required":false})
    {
        return Err(
            "Windows typed rejection differs from actual preallocation admission cause".into(),
        );
    }
    let admission = &rejection["workload_admission"];
    fields(admission, &["request", "rejection"])?;
    let expected_binding = serde_json::json!({
        "request_digest":windows_contract_digest(contract)?,
        "workload_plan_digest":contract["workload_plan_digest"],
        "profile":contract["authorized_profile"],
        "authorization":contract["authorization"],
        "epoch":contract["expected_epoch"],
    });
    if admission["request"] != expected_binding
        || admission["rejection"]
            != serde_json::json!({"code":expected,"conflicts":[],"remaining_conflicts":0})
    {
        return Err(
            "Windows admission rejection is not bound to the exact requested contract".into(),
        );
    }
    Ok(())
}

/// Decode the complete native SCM census, including independently encoded
/// service configuration. Stopped services are not fabricated Job receipts.
pub fn validate_guardian_quiescence(
    receipt: &Value,
    agent_sha256: &str,
    manifest_sha256: &str,
    installed_agent_utf16: &[u16],
) -> VerificationResult<()> {
    fields(
        receipt,
        &[
            "format",
            "revision",
            "image_sha256",
            "runtime_manifest_sha256",
            "slots",
        ],
    )?;
    if receipt["format"] != "memcordon.windows-native-guardian-quiescence"
        || receipt["revision"] != 1
        || receipt["image_sha256"] != agent_sha256
        || receipt["runtime_manifest_sha256"] != manifest_sha256
        || installed_agent_utf16.is_empty()
        || installed_agent_utf16.contains(&0)
    {
        return Err("native guardian census selected generation differs".into());
    }
    fn command_line(arguments: &[Vec<u16>]) -> Vec<u16> {
        let mut output = Vec::new();
        for (index, argument) in arguments.iter().enumerate() {
            if index != 0 {
                output.push(32);
            }
            if !argument.is_empty() && !argument.iter().any(|unit| [9, 32, 34].contains(unit)) {
                output.extend_from_slice(argument);
                continue;
            }
            output.push(34);
            let mut slashes = 0;
            for unit in argument {
                if *unit == 92 {
                    slashes += 1;
                    continue;
                }
                output.extend(std::iter::repeat_n(
                    92,
                    if *unit == 34 {
                        slashes * 2 + 1
                    } else {
                        slashes
                    },
                ));
                output.push(*unit);
                slashes = 0;
            }
            output.extend(std::iter::repeat_n(92, slashes * 2));
            output.push(34);
        }
        output
    }
    let slots = receipt["slots"]
        .as_array()
        .ok_or("native guardian slot census absent")?;
    if slots.len() != 8 {
        return Err("native guardian census omits or adds installed slot".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for slot in slots {
        fields(
            slot,
            &[
                "service_name",
                "configuration_sha256",
                "configuration",
                "service_type",
                "current_state",
                "process_id",
                "controls_accepted",
                "win32_exit_code",
                "service_specific_exit_code",
                "checkpoint",
                "wait_hint",
                "service_flags",
            ],
        )?;
        let name = slot["service_name"]
            .as_str()
            .ok_or("native guardian slot name absent")?;
        if !(0..8).any(|ordinal| name == format!("MemCordonSealedGuardian-{ordinal:03}"))
            || !names.insert(name)
        {
            return Err("native guardian slot identity differs or duplicates".into());
        }
        if slot["current_state"] != 1 || slot["process_id"] != 0 || slot["service_type"] != 16 {
            return Err("actual native guardian slot remains live or changes service type".into());
        }
        for key in [
            "controls_accepted",
            "win32_exit_code",
            "service_specific_exit_code",
            "checkpoint",
            "wait_hint",
            "service_flags",
        ] {
            if slot[key]
                .as_u64()
                .is_none_or(|number| number > u64::from(u32::MAX))
            {
                return Err("native SCM observation is outside DWORD bounds".into());
            }
        }
        let config = &slot["configuration"];
        fields(
            config,
            &[
                "service_type",
                "start_type",
                "error_control",
                "binary_path_utf16",
                "service_start_name_utf16",
            ],
        )?;
        let command = command_line(&[
            installed_agent_utf16.to_vec(),
            "windows-guardian-service".encode_utf16().collect(),
            name.encode_utf16().collect(),
        ]);
        if config["service_type"] != 16
            || config["start_type"] != 3
            || config["error_control"] != 1
            || config["binary_path_utf16"] != serde_json::json!(command)
            || config["service_start_name_utf16"]
                != serde_json::json!("LocalSystem".encode_utf16().collect::<Vec<_>>())
        {
            return Err(
                "native guardian service configuration differs from selected agent/slot/account"
                    .into(),
            );
        }
        let mut bytes = Vec::new();
        for value in [16u32, 3, 1] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for key in ["binary_path_utf16", "service_start_name_utf16"] {
            let units: Vec<u16> =
                serde_json::from_value(config[key].clone()).map_err(|error| error.to_string())?;
            bytes.extend_from_slice(&(units.len() as u64).to_le_bytes());
            for unit in units {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
        }
        if slot["configuration_sha256"] != crate::sha256(&bytes) {
            return Err(
                "native guardian configuration SHA differs from actual semantic values".into(),
            );
        }
    }
    Ok(())
}

fn epoch(value: &Value) -> VerificationResult<()> {
    fields(value, &["service_instance", "revision"])?;
    let instance = value["service_instance"]
        .as_array()
        .ok_or("Windows policy service instance absent")?;
    if instance.len() != 16
        || instance
            .iter()
            .any(|byte| byte.as_u64().is_none_or(|byte| byte > 255))
        || value["revision"]
            .as_u64()
            .is_none_or(|revision| revision == 0)
    {
        return Err("Windows policy epoch shape differs".into());
    }
    Ok(())
}

fn canonical_id(bytes: &mut Vec<u8>, text: &str) -> VerificationResult<()> {
    let length = u16::try_from(text.len()).map_err(|_| "Windows canonical identifier too long")?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(text.as_bytes());
    Ok(())
}

fn windows_profile_digest() -> String {
    let mut bytes = b"profile-definition-v1\0\0\x01".to_vec();
    canonical_id(&mut bytes, "windows-host-network-external-v1").expect("fixed bounded identifier");
    bytes.extend_from_slice(&[4, 2, 2, 2, 1, 2, 1]);
    crate::sha256(&bytes)
}

/// Independent canonical registry bytes for the single owned Windows grant.
pub fn windows_registry_digest(registry: &Value) -> VerificationResult<String> {
    fields(
        registry,
        &[
            "format",
            "revision",
            "profiles",
            "grants",
            "active_attempt_disposition",
        ],
    )?;
    let profiles = registry["profiles"]
        .as_array()
        .ok_or("Windows registry profiles absent")?;
    let grants = registry["grants"]
        .as_array()
        .ok_or("Windows registry grants absent")?;
    if registry["format"] != "memcordon.local-policy"
        || registry["revision"] != 1
        || registry["active_attempt_disposition"] != "drain-existing"
        || profiles.len() != 1
        || grants.len() != 1
    {
        return Err("Windows registry differs from frozen single owned grant".into());
    }
    let profile = &profiles[0];
    let grant = &grants[0];
    fields(profile, &["profile", "reference", "enabled"])?;
    fields(
        grant,
        &[
            "id",
            "revision",
            "profile",
            "ceiling",
            "enabled",
            "callers",
            "approved_plans",
        ],
    )?;
    let reference = serde_json::json!({"id":"windows-host-network-external-v1","semantic_digest":windows_profile_digest()});
    if profile["profile"] != "windows-host-network-external"
        || profile["reference"] != reference
        || profile["enabled"] != true
        || grant["id"] != "windows-readiness-owned"
        || grant["revision"] != 1
        || grant["profile"] != reference
        || !grant["enabled"].is_boolean()
        || grant["ceiling"]
            != serde_json::json!({
            "direct_socket_authority":"external-host-policy-accepted","unix_authority":"existing-host-unix-authority-accepted",
            "external_socket_custody":"existing-stdio-authority-accepted","credential_gains":"existing-caller-envelope-accepted",
            "mediated_communication":"external-filesystem-and-stdio-policy-accepted"})
    {
        return Err("Windows registry profile/grant authority differs".into());
    }
    let callers = grant["callers"]
        .as_array()
        .ok_or("Windows caller selectors absent")?;
    let plans = grant["approved_plans"]
        .as_array()
        .ok_or("Windows approved plans absent")?;
    if callers.is_empty() || callers.len() > 64 || plans.len() != 1 {
        return Err("Windows caller/plan bounds differ".into());
    }
    let mut encoded_callers = std::collections::BTreeSet::new();
    for caller in callers {
        fields(caller, &["platform", "sid"])?;
        let sid = caller["sid"].as_str().ok_or("Windows caller SID absent")?;
        if caller["platform"] != "windows"
            || !sid.starts_with("S-1-")
            || sid.len() > 184
            || sid.contains('\0')
        {
            return Err("Windows native caller selector differs".into());
        }
        let mut bytes = vec![2];
        canonical_id(&mut bytes, sid)?;
        if !encoded_callers.insert(bytes) {
            return Err("duplicate Windows native caller".into());
        }
    }
    let plan = plans[0]
        .as_str()
        .ok_or("Windows approved plan digest absent")?;
    crate::digest(plan)?;
    let mut bytes = b"memcordon.local-policy/revision1\0\0\x01".to_vec();
    bytes.extend_from_slice(&1u16.to_be_bytes());
    canonical_id(&mut bytes, "windows-host-network-external-v1")?;
    bytes.extend_from_slice(&hex::decode(windows_profile_digest()).expect("encoded SHA"));
    bytes.push(1);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    canonical_id(&mut bytes, "windows-readiness-owned")?;
    bytes.extend_from_slice(&1u64.to_be_bytes());
    canonical_id(&mut bytes, "windows-host-network-external-v1")?;
    bytes.extend_from_slice(&hex::decode(windows_profile_digest()).expect("encoded SHA"));
    bytes.extend_from_slice(&[4, 2, 2, 2, 1]);
    bytes.push(u8::from(
        grant["enabled"].as_bool().expect("validated boolean"),
    ));
    bytes.extend_from_slice(&(encoded_callers.len() as u16).to_be_bytes());
    for caller in encoded_callers {
        bytes.extend_from_slice(&caller);
    }
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&hex::decode(plan).map_err(|error| error.to_string())?);
    bytes.push(1);
    Ok(crate::sha256(&bytes))
}

fn activation(value: &Value, registry: &Value) -> VerificationResult<()> {
    fields(
        value,
        &[
            "format",
            "revision",
            "registry",
            "registry_digest",
            "epoch",
            "revoked_admissions",
        ],
    )?;
    if value["format"] != "memcordon.local-activation"
        || value["revision"] != 1
        || value["registry"] != *registry
        || value["revoked_admissions"] != serde_json::json!([])
    {
        return Err(
            "Windows actual policy activation differs from exact registry or retains admissions"
                .into(),
        );
    }
    crate::digest(
        value["registry_digest"]
            .as_str()
            .ok_or("Windows activated registry digest absent")?,
    )?;
    if value["registry_digest"] != windows_registry_digest(registry)? {
        return Err(
            "Windows native activation registry digest differs from independent canonical bytes"
                .into(),
        );
    }
    epoch(&value["epoch"])
}

/// Pins only the four actual policy-refusal transformations. The caller must
/// also validate the selected native provider rejection/request association,
/// actual native quiescence and protected artifact custody.
#[expect(
    clippy::too_many_arguments,
    reason = "Compare independent policy, process and captured invocation observations"
)]
pub fn validate_policy_refusal_mutation(
    scenario: &str,
    baseline_policy: &Value,
    baseline_contract: &Value,
    prior_contract: &Value,
    prior_activation: &Value,
    baseline_activation: &Value,
    requested_contract: &Value,
    policy_apply: Option<&Value>,
    policy_restore: Option<&Value>,
) -> VerificationResult<()> {
    if ![
        "admission-refusal",
        "stale-policy-epoch",
        "revoked-grant",
        "wrong-authorized-caller",
    ]
    .contains(&scenario)
    {
        return Err("Windows policy mutation is outside the finite refusal set".into());
    }
    fields(
        baseline_policy,
        &[
            "format",
            "revision",
            "profiles",
            "grants",
            "active_attempt_disposition",
        ],
    )?;
    for contract in [baseline_contract, prior_contract, requested_contract] {
        fields(
            contract,
            &[
                "schema_version",
                "workload_plan_digest",
                "authorized_profile",
                "authorization",
                "ceiling",
                "requirements",
                "endpoints",
                "expected_epoch",
            ],
        )?;
        if contract["schema_version"] != 1 {
            return Err("Windows refusal contract is not V1".into());
        }
    }
    if baseline_policy["format"] != "memcordon.local-policy" || baseline_policy["revision"] != 1 {
        return Err("Windows baseline policy format differs".into());
    }
    let grants = baseline_policy["grants"]
        .as_array()
        .filter(|grants| grants.len() == 1)
        .ok_or("Windows owned baseline requires its single original grant")?;
    let profiles = baseline_policy["profiles"]
        .as_array()
        .filter(|profiles| profiles.len() == 1)
        .ok_or("Windows original profile absent or widened")?;
    fields(&profiles[0], &["profile", "reference", "enabled"])?;
    if profiles[0]["profile"] != "windows-host-network-external"
        || profiles[0]["enabled"] != true
        || profiles[0]["reference"] != grants[0]["profile"]
        || baseline_policy["active_attempt_disposition"] != "drain-existing"
    {
        return Err("Windows original native profile or disposition differs".into());
    }
    fields(
        &grants[0],
        &[
            "id",
            "revision",
            "profile",
            "ceiling",
            "enabled",
            "callers",
            "approved_plans",
        ],
    )?;
    if grants[0]["enabled"] != true
        || grants[0]["revision"] != 1
        || grants[0]["id"] != "windows-readiness-owned"
        || grants[0]["profile"]["id"] != "windows-host-network-external-v1"
        || baseline_contract["authorization"]["grant_id"] != grants[0]["id"]
        || baseline_contract["authorization"]["grant_revision"] != grants[0]["revision"]
        || baseline_contract["authorized_profile"] != grants[0]["profile"]
    {
        return Err("Windows baseline request differs from the original enabled grant".into());
    }
    let ceiling = serde_json::json!({"direct_socket_authority":"external-host-policy-accepted","unix_authority":"existing-host-unix-authority-accepted",
        "external_socket_custody":"existing-stdio-authority-accepted","credential_gains":"existing-caller-envelope-accepted",
        "mediated_communication":"external-filesystem-and-stdio-policy-accepted"});
    if grants[0]["ceiling"] != ceiling || baseline_contract["ceiling"] != ceiling {
        return Err("Windows original caller ceiling differs".into());
    }
    let plans = grants[0]["approved_plans"]
        .as_array()
        .filter(|plans| plans.len() == 1)
        .ok_or("Windows original approved plan absent or widened")?;
    if plans[0] != baseline_contract["workload_plan_digest"]
        || plans[0] != baseline_contract["authorization"]["approved_plan_digest"]
    {
        return Err("Windows baseline approved plan differs".into());
    }
    activation(baseline_activation, baseline_policy)?;
    activation(prior_activation, baseline_policy)?;
    if prior_activation["registry_digest"] != baseline_activation["registry_digest"] {
        return Err("Windows earlier activation changed the original registry digest".into());
    }
    if baseline_contract["expected_epoch"] != baseline_activation["epoch"] {
        return Err("Windows baseline request does not retain its actual activation epoch".into());
    }
    epoch(&prior_contract["expected_epoch"])?;
    if prior_contract["expected_epoch"] != prior_activation["epoch"]
        || prior_activation["epoch"]["service_instance"]
            != baseline_activation["epoch"]["service_instance"]
        || prior_activation["epoch"]["revision"].as_u64()
            >= baseline_activation["epoch"]["revision"].as_u64()
    {
        return Err("Windows prior epoch is not an earlier actual same-instance activation".into());
    }
    let mut earlier = prior_contract.clone();
    earlier["expected_epoch"] = baseline_contract["expected_epoch"].clone();
    if earlier != *baseline_contract
        || prior_contract["expected_epoch"] == baseline_contract["expected_epoch"]
    {
        return Err("Windows prior contract is not the exact earlier measured baseline".into());
    }
    let changes_policy = ["revoked-grant", "wrong-authorized-caller"].contains(&scenario);
    if !changes_policy {
        if policy_apply.is_some()
            || policy_restore.is_some()
            || requested_contract != prior_contract
        {
            return Err(
                "Windows stale refusal substituted a registry mutation or arbitrary epoch".into(),
            );
        }
        return Ok(());
    }
    let apply = policy_apply.ok_or("Windows changed policy activation absent")?;
    let restore = policy_restore.ok_or("Windows original policy restoration absent")?;
    let mut changed = baseline_policy.clone();
    if scenario == "revoked-grant" {
        changed["grants"][0]["enabled"] = false.into();
    } else {
        let callers = grants[0]["callers"]
            .as_array()
            .filter(|callers| !callers.is_empty() && callers.len() <= 64)
            .ok_or("Windows original native callers absent or unbounded")?;
        for caller in callers {
            fields(caller, &["platform", "sid"])?;
            if caller["platform"] != "windows" || caller["sid"].as_str().is_none_or(str::is_empty) {
                return Err("Windows native caller selector differs".into());
            }
        }
        let substitute = if callers.iter().any(|caller| caller["sid"] == "S-1-5-19") {
            "S-1-5-20"
        } else {
            "S-1-5-19"
        };
        changed["grants"][0]["callers"] =
            serde_json::json!([{"platform":"windows","sid":substitute}]);
    }
    activation(apply, &changed)?;
    activation(restore, baseline_policy)?;
    if apply["epoch"] == baseline_activation["epoch"]
        || restore["epoch"] == apply["epoch"]
        || restore["epoch"]["service_instance"] != apply["epoch"]["service_instance"]
        || restore["epoch"]["revision"].as_u64() <= apply["epoch"]["revision"].as_u64()
        || restore["registry_digest"] != baseline_activation["registry_digest"]
    {
        return Err("Windows actual mutation/restoration epochs or original digest differ".into());
    }
    let mut expected = baseline_contract.clone();
    expected["expected_epoch"] = apply["epoch"].clone();
    if requested_contract != &expected {
        return Err("Windows changed policy request altered unrelated original contract".into());
    }
    Ok(())
}
