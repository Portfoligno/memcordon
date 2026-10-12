use memcordon_readiness_verifier::windows_acceptance::validate_policy_refusal_mutation;
use serde_json::{Value, json};
#[path = "support/persisted_case.rs"]
mod persisted_actor_support;

#[expect(
    clippy::type_complexity,
    reason = "the fixture returns actor evidence together with its independent native command bindings"
)]
fn persist_actor_effect(
    case: &mut persisted_actor_support::PersistedCase,
    ordinal: usize,
    kind: &str,
    selector: &str,
    provider: &Value,
    image: &str,
    recipe: &str,
) -> (
    memcordon_readiness_verifier::ComponentActor,
    (u32, u64, String, String, String, Vec<Vec<u16>>),
) {
    use memcordon_readiness_verifier::*;
    let units = |text: &str| text.encode_utf16().collect::<Vec<_>>();
    let prefix = format!("actors/{ordinal}");
    let pid = 1000 + ordinal as u32;
    let birth = 10000 + ordinal as u64;
    let attempt = format!("{ordinal:064x}");
    let nonce = hex::encode([ordinal as u8 + 1; 16]);
    let args = vec![
        units("__windows-certification"),
        units(&format!("C:\\owned\\{ordinal}\\selection.json")),
        units(&format!("C:\\owned\\{ordinal}\\observation.json")),
        units("--controller-start-gate"),
        units(&format!("Local\\original-{ordinal}")),
        units("+60000ms"),
        units("--"),
        units("C:\\owned\\fixture.exe"),
    ];
    let request = json!({"restart_attempt":0,"schema_version":3,"expected_provider_binding":provider,"workload_contract":null,"nonce":nonce,"command":{"program":units("C:\\owned\\fixture.exe"),"arguments":[]},"environment":[],"current_directory":units("C:\\owned"),"policy":{"memory_limit_bytes":null,"absolute_deadline_millis":123456,"lifetime":"workload","poll_interval_millis":100,"signal_grace_millis":0,"command_exit_grace_millis":0,"limit_grace_millis":0}});
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let digest = sha256(&request_bytes);
    let mut selection = json!({"kind":kind});
    selection[kind] = json!(selector);
    let frame = if kind == "fault" {
        json!({"kind":"reject","schema_version":2,"attempt_id":attempt,"nonce":nonce,"request_sha256":digest,"rejection":{"schema_version":2,"code":"MCSEALED-PROVIDER-REJECTION","phase":"before-authorization","detail":"native injected fault","os_code":null,"target_created":false,"target_released":false,"cleanup_attempted":true,"restart_safety":{"direct_child_reaped":true,"workload_empty":true,"helpers_reaped":true,"containment_removed":true,"containment_incapable_of_live_members":true,"sealed_boundary_retired":true,"errors":[]},"disposition":{"disposition":"preauthorization","terminal_ack_required":false},"provider_failure":{"schema_version":1,"provider_binding":provider,"attempt_id":attempt,"request_sha256":digest,"diagnostic_sequence":1,"durable_through_sequence":1,"original":{"observed":{"event":{"sequence":1,"origin":"launcher","category":"launch","operation":"unclassified-provider-operation","code":"unexpected-provider-failure","native_code":null,"observed_phase":"before-authorization","safe_detail":{"injected-windows-fault":{"fault":selector}},"detail_redacted":false,"detail_truncated":false,"terminalization_reference":null}}},"secondary":[],"loss":[],"projection_sha256":sha256(b"native diagnostic projection")}}})
    } else {
        let native = match selector {
            "omit-job-list" | "omit-handle-list" => {
                json!({"detector":"creation-manifest","used_create_process_as_user":true,"job_list_present":selector!="omit-job-list","handle_list_present":selector!="omit-handle-list","post_create_job_assignment":false,"unexpected_handle_count":0})
            }
            "resume-before-guardian" => {
                json!({"detector":"premature-authorization","guardian_ready":false,"relays_ready":true,"target_marker_observed":true})
            }
            _ => {
                json!({"detector":"target-token-mismatch","creation_api":"create-process-as-user-w","token_source":"launcher-service","authenticated_envelope_sha256":"1".repeat(64),"target_envelope_sha256":"2".repeat(64)})
            }
        };
        json!({"kind":"certification-mutant-observed","schema_version":1,"mutant":selector,"attempt_id":attempt,"nonce":nonce,"request_sha256":digest,"hook_observation":{"hook":"native","observation":native}})
    };
    let mut frame = frame;
    if kind == "fault" {
        frame["schema_version"] = json!(3);
        frame["rejection"]["phase"] = json!("provider-connection");
        frame["rejection"]["provider_failure"]["loss"] = json!({"secondary_events_omitted":0,"secondary_count_saturated":false,"persistence_failure_observed":false,"writer_unavailable":false});
        let mut diagnostic: memcordon_core::ProviderFailureDiagnosticV1 =
            serde_json::from_value(frame["rejection"]["provider_failure"].clone()).unwrap();
        diagnostic.projection_sha256 = diagnostic.canonical_digest();
        frame["rejection"]["provider_failure"] = serde_json::to_value(diagnostic).unwrap();
        let _: memcordon_core::WindowsProviderRejectionV2 =
            serde_json::from_value(frame["rejection"].clone()).unwrap();
    }
    let target = case.record.key.target.clone();
    let source_commit = case.index.source_commit.clone();
    let version = case.index.version.clone();
    let put = |case: &mut persisted_actor_support::PersistedCase, leaf: &str, value: &Value| {
        let path = format!("{prefix}/{leaf}");
        case.json(&path, value);
        path
    };
    let selection_path = put(case, "selection.json", &selection);
    let invocation = put(
        case,
        "invocation.json",
        &json!({"format":"memcordon.windows-native-component-invocation","revision":1,"run_id":"vector-run","recipe_id":recipe,"native_target":target,"executable_sha256":image,"program_utf16":units("C:\\owned\\actor.exe"),"argv_utf16":args,"cwd_utf16":units("C:\\owned"),"environment_cleared":true}),
    );
    let observation = put(
        case,
        "observation.json",
        &json!({"selection":selection,"launch":request,"caller":{"process_id":pid,"creation_time_100ns":birth},"attempt_id":attempt,"request_sha256":digest,"authenticated_provider_frames":[serde_json::to_vec(&frame).unwrap()],"capture_failure":null}),
    );
    let actor_held = put(
        case,
        "held.json",
        &json!({"format":"memcordon.windows-component-frontend-held","revision":1,"process_id":pid,"creation_time_100ns":birth,"held_before_execution":true,"native_live_before_release":true}),
    );
    let exit = put(
        case,
        "exit.json",
        &json!({"format":"memcordon.windows-native-component-exit","revision":1,"run_id":"vector-run","recipe_id":recipe,"native_target":target,"executable_sha256":image,"native_status":125,"capture_complete":true}),
    );
    let native_retirement = put(
        case,
        "retirement.json",
        &json!({"format":"memcordon.windows-component-actor-retirement","revision":1,"process_id":pid,"creation_time_100ns":birth,"image_sha256":image,"held_before_execution":true,"retirement_observed":true,"native_status":125}),
    );
    let settlement_inventory = put(
        case,
        "inventory.json",
        &json!({"schema_version":1,"challenge":"a".repeat(64),"provider_generation":provider["generation"],"current_boot_identity":"b".repeat(64),"executing":0,"incomplete_proof":0,"unacknowledged_outboxes":0,"ack_retirement_in_progress":0,"completed_tombstones":0,"active_admissions":0,"quarantined":0}),
    );
    let settlement_invocation = put(
        case,
        "settlement-invocation.json",
        &json!({"format":"memcordon.windows-component-settlement-command","revision":1,"run_id":"vector-run","recipe_id":recipe,"native_target":target,"source_commit":source_commit,"executable_sha256":image,"program_utf16":units("C:\\owned\\actor.exe"),"argv_utf16":[units("windows-recover"),units("converge"),units("90000")],"cwd_utf16":units("C:\\owned"),"environment_cleared":true,"work_deadline_unix_millis":8400000,"cleanup_deadline_unix_millis":9300000}),
    );
    let settlement_stderr = format!("{prefix}/recovery.stderr.bin");
    case.write(&settlement_stderr, b"");
    let settlement_deadline = "roles/compiler/native-operation-deadline.json".to_owned();
    if !case.root.path().join(&settlement_deadline).exists() {
        case.json(&settlement_deadline,&json!({"format":"memcordon.consumer-readiness.original-native-deadline","revision":1,"source":{"kind":"working","commit":source_commit,"version":version},"native_target":target,"started_unix_millis":0,"work_deadline_unix_millis":8400000,"cleanup_deadline_unix_millis":9300000}));
    }
    let settlement_command_sha =
        sha256(&std::fs::read(case.root.path().join(&settlement_invocation)).unwrap());
    let settlement_stdout_sha =
        sha256(&std::fs::read(case.root.path().join(&settlement_inventory)).unwrap());
    let settlement_exit = put(
        case,
        "settlement-exit.json",
        &json!({"format":"memcordon.windows-component-settlement-exit","revision":1,"invocation_sha256":settlement_command_sha,"stdout_sha256":settlement_stdout_sha,"stderr_sha256":sha256(b""),"native_status":0}),
    );
    let provider_request = format!("{prefix}/request.bin");
    case.write(&provider_request, &request_bytes);
    let stdout = format!("{prefix}/stdout.bin");
    let stderr = format!("{prefix}/stderr.bin");
    case.write(&stdout, b"");
    case.write(&stderr, b"");
    let mut actor = ComponentActor {
        provider_request,
        recipe_id: recipe.into(),
        selection_kind: kind.into(),
        selection: selection_path,
        invocation,
        exit,
        observation,
        stdout,
        stderr,
        actor_held,
        native_retirement,
        settlement_inventory,
        settlement_invocation,
        settlement_exit,
        settlement_stderr,
        settlement_deadline,
        held_before: None,
        held_after: None,
        worker_exit: None,
        frontend_exit: None,
        recovery: None,
        recovery_invocation: None,
        recovery_exit: None,
        recovery_stderr: None,
        control_worker_site: None,
        control_worker_held: None,
    };
    if case.record.key.scenario != "preauthorization" {
        persist_actor_late_effect(
            case, &mut actor, ordinal, selector, &attempt, &nonce, &digest, provider,
        );
    }
    (
        actor,
        (
            pid,
            birth,
            attempt,
            nonce,
            digest,
            std::iter::once(units("C:\\owned\\actor.exe"))
                .chain(args)
                .collect(),
        ),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "late actor evidence independently binds selector, attempt, nonce, digest and provider"
)]
fn persist_actor_late_effect(
    case: &mut persisted_actor_support::PersistedCase,
    actor: &mut memcordon_readiness_verifier::ComponentActor,
    ordinal: usize,
    selector: &str,
    attempt: &str,
    nonce: &str,
    digest: &str,
    provider: &Value,
) {
    let read = |case: &persisted_actor_support::PersistedCase, path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap()).unwrap()
    };
    let prefix = format!("actors/{ordinal}");
    let put = |case: &mut persisted_actor_support::PersistedCase, leaf: &str, value: &Value| {
        let path = format!("{prefix}/{leaf}");
        case.json(&path, value);
        path
    };
    let mut observation = read(case, &actor.observation);
    let transport = [
        "frontend-disconnected-after-authorization",
        "frontend-killed-after-authorization",
        "control-worker-killed-after-authorization",
        "control-service-killed-after-authorization",
    ]
    .contains(&selector);
    let launcher_loss = [
        "launcher-worker-killed-after-authorization",
        "launcher-service-killed-after-authorization",
    ]
    .contains(&selector);
    let original = if launcher_loss {
        json!({"unavailable":{"reason":"worker-lost-before-observation"}})
    } else {
        json!({"observed":{"event":{"sequence":1,"origin":"launcher","category":if transport{"transport"}else{"launch"},"operation":if transport{"read-control-frame"}else if selector=="guardian-killed-after-authorization"{"check-guardian"}else{"unclassified-provider-operation"},"code":if transport{"control-transport"}else if selector=="guardian-killed-after-authorization"{"guardian-loss"}else{"unexpected-provider-failure"},"native_code":null,"observed_phase":if selector=="resume"{"authorized-before-resume"}else if selector=="record-retire"{"target-exit-observed"}else if case.record.key.scenario=="cleanup"{"cleaning"}else{"monitoring"},"safe_detail":if selector=="guardian-killed-after-authorization"{json!("no-additional-detail")}else{json!({"injected-windows-fault":{"fault":selector}})},"detail_redacted":false,"detail_truncated":false,"terminalization_reference":null}}})
    };
    let terminal = json!({"kind":"terminal","schema_version":2,"attempt_id":attempt,"nonce":nonce,"request_sha256":digest,
        "payload":{"kind":"recovered-closure","primary_failure":original,"target_creation_observed":true,"resume_attempted":selector!="resume"},
        "process_observation":{"schema_version":2,"coverage":{"coverage":"unavailable","reason":"worker-lost-before-freeze"},"root_identity":null,"final_accounting":null,"required_witness":null},
        "restart_safety":{"direct_child_reaped":true,"workload_empty":true,"helpers_reaped":true,"containment_removed":true,"containment_incapable_of_live_members":true,"sealed_boundary_retired":true,"errors":[]},
        "retirement_proof":{"schema_version":2,"source":"guardian-recovery","attempt_id":attempt,"nonce":nonce,"request_sha256":digest,"provider_generation":provider["generation"],"launch_incarnation":format!("launch-{ordinal}"),"original_boot_id":"original-native-boot","job_identity":format!("original-job-{ordinal}"),"owner_manifest_sha256":"7".repeat(64),"guardian_receipt_sha256":"8".repeat(64),"target_completion_observed":false,"native_job_empty_observed":true,"relay_closure_observed":false,"guardian_completion_observed":true,"owner_capabilities_closed":true,"launch_gate_closed":true,"policy_reference_bound":true}});
    let mut typed = terminal.clone();
    typed.as_object_mut().unwrap().remove("kind");
    let _: memcordon_core::WindowsTerminalReceiptV2 = serde_json::from_value(typed).unwrap();
    observation["authenticated_provider_frames"] = json!([serde_json::to_vec(&terminal).unwrap()]);
    if case.record.key.scenario == "postresume" {
        let target =
            json!({"process_id":2000+ordinal as u32,"creation_time_100ns":20000+ordinal as u64});
        let guardian =
            json!({"process_id":3000+ordinal as u32,"creation_time_100ns":30000+ordinal as u64});
        let worker =
            json!({"process_id":4000+ordinal as u32,"creation_time_100ns":40000+ordinal as u64});
        let thread =
            json!({"thread_id":5000+ordinal as u32,"creation_time_100ns":50000+ordinal as u64});
        actor.held_before = Some(put(
            case,
            "held-before.json",
            &json!({"format":"memcordon.windows-live-guardian-observation","revision":1,"challenge":"9".repeat(64),"guardian_identity":guardian,"association":{"provider":provider,"attempt_id":attempt,"request_sha256":digest},"live_nonce":nonce,"live_target_identity":target,"worker_process_identity":worker,"worker_thread_identity":thread}),
        ));
        actor.held_after = Some(put(
            case,
            "held-after.json",
            &json!({"format":"memcordon.windows-component-held-retirement","revision":1,"target_process_id":target["process_id"],"target_creation_time_100ns":target["creation_time_100ns"],"guardian":guardian,"held_before_fault":true,"target_retired":true,"guardian_retired":true,"guardian_native_exit_status":if ["guardian-killed-after-authorization","all-job-owners-closed-after-authorization"].contains(&selector){0xC000_013A_u32}else{0},"target_native_exit_status":0}),
        ));
        if launcher_loss
            || selector.starts_with("control-")
            || selector == "all-job-owners-closed-after-authorization"
        {
            let control = selector.starts_with("control-");
            let process_loss = selector == "control-service-killed-after-authorization"
                || selector == "launcher-service-killed-after-authorization"
                || selector == "all-job-owners-closed-after-authorization";
            actor.worker_exit = Some(put(
                case,
                "worker-exit.json",
                &json!({"format":if control{"memcordon.windows-component-control-worker-exit"}else{"memcordon.windows-component-worker-exit"},"revision":1,"process_id":worker["process_id"],"process_creation_time_100ns":worker["creation_time_100ns"],"thread":thread,"held_before_fault":true,"exit_observed":true,"native_exit_status":if control&&!process_loss{0}else{0xC000_013A_u32},"process_retirement_observed":process_loss,"process_native_exit_status":if process_loss{json!(0xC000_013A_u32)}else{Value::Null}}),
            ));
            if control {
                actor.control_worker_site = Some(put(
                    case,
                    "control-site.json",
                    &json!({"format":"memcordon.windows-component-control-worker-site","revision":1,"fault":selector,"process":worker,"thread":thread,"target_pid":target["process_id"],"target_authorization_observed":true}),
                ));
                actor.control_worker_held = Some(put(
                    case,
                    "control-held.json",
                    &json!({"format":"memcordon.windows-component-control-worker-held","revision":1,"process":worker,"thread":thread,"target_pid":target["process_id"],"held_before_fault":true,"control_service":{"name":"MemCordonControl","process_id":worker["process_id"],"current_state":4}}),
                ));
            }
        }
        if selector.starts_with("frontend-") {
            let killed = selector == "frontend-killed-after-authorization";
            let status = if killed { 0xC000_013A_u32 } else { 126 };
            let caller = observation["caller"].clone();
            observation["frontend_action"] = json!({"format":"memcordon.windows-component-frontend-action","revision":1,"kind":if killed{"exit-process"}else{"disconnect-public-channel"},"process":caller,"target_pid":target["process_id"],"target_authorization_observed":true,"controller_release_observed":true,"requested_exit_status":status});
            actor.frontend_exit = Some(put(
                case,
                "frontend-exit.json",
                &json!({"format":"memcordon.windows-component-frontend-exit","revision":1,"process_id":caller["process_id"],"creation_time_100ns":caller["creation_time_100ns"],"held_before_fault":true,"retirement_observed":true,"native_status":status}),
            ));
            let mut exit = read(case, &actor.exit);
            exit["native_status"] = json!(i32::from_ne_bytes(status.to_ne_bytes()));
            case.json(&actor.exit, &exit);
            let mut wait = read(case, &actor.native_retirement);
            wait["native_status"] = json!(status);
            case.json(&actor.native_retirement, &wait);
        }
    }
    if selector == "all-job-owners-closed-after-authorization" {
        let recovery = json!({"schema_version":1,"provider_response":{"kind":"recovery-attempt-unavailable","schema_version":3,"challenge":"a".repeat(64),"attempt_id":attempt,"detail":"exact recovery authority remains retained pending checked closure"},"frontend_delivery":null,"provider_request":{"kind":"recover-attempt","schema_version":3,"attempt_id":attempt,"nonce":nonce,"request_sha256":digest,"challenge":"a".repeat(64)}});
        actor.recovery = Some(put(case, "recovery.json", &recovery));
        let mut command = read(case, &actor.invocation);
        command["format"] = json!("memcordon.windows-component-recovery-command");
        command["argv_utf16"] = json!(
            ["windows-recover", "attempt", attempt, nonce, digest]
                .iter()
                .map(|text| text.encode_utf16().collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );
        actor.recovery_invocation = Some(put(case, "recovery-invocation.json", &command));
        let stderr = format!("{prefix}/recovery-stderr.bin");
        case.write(&stderr, b"");
        actor.recovery_stderr = Some(stderr);
        actor.recovery_exit = Some(put(
            case,
            "recovery-exit.json",
            &json!({"format":"memcordon.windows-component-recovery-exit","revision":1,"invocation_sha256":memcordon_readiness_verifier::sha256(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":memcordon_readiness_verifier::sha256(&serde_json::to_vec(&recovery).unwrap()),"stderr_sha256":memcordon_readiness_verifier::sha256(b""),"native_status":1}),
        ));
    }
    case.json(&actor.observation, &observation);
}

fn persisted_actor_facet(facet: &str) -> persisted_actor_support::PersistedCase {
    use memcordon_readiness_verifier::*;
    let (root, index, mut record) = preprovider_refusal_case(false, None);
    record.key.channel = None;
    record.key.evidence_class = EvidenceClass::NativeComponentRegression;
    record.key.family = "W-CAUSAL".into();
    record.key.scenario = facet.into();
    let mut case = persisted_actor_support::PersistedCase {
        root,
        index,
        record,
    };
    case.write(
        "native-producer-bundle.bin",
        b"original immutable native decoder vector bundle",
    );
    case.index.producer_origins.push(ProducerOrigin {
        job: "native-windows-x64".into(),
        run_id: "vector-run".into(),
        run_attempt: 1,
        artifact_id: "original-native-vector".into(),
        artifact_sha256: sha256(b"original immutable native decoder vector bundle"),
        bundle_artifact: "native-producer-bundle.bin".into(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        version: case.index.version.clone(),
        manifest_sha256: case.index.manifest_sha256.clone(),
        repository: None,
    });
    let read = |case: &persisted_actor_support::PersistedCase, path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap()).unwrap()
    };
    let provider = read(&case, "quiescence.json")["provider"].clone();
    let actor_sha = sha256(b"measured actor decoder vector image");
    case.write("actor.exe", b"measured actor decoder vector image");
    let recipe = "original-native-components-v1";
    case.index.component_builds.push(ComponentBuild {
        target: case.record.key.target.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        host: case.index.products[0].host.clone(),
        recipe_id: recipe.into(),
        recipe_sha256: sha256(b"original finite actor recipe"),
        executable: "actor.exe".into(),
        instrumented: true,
        actor_executable: Some("actor.exe".into()),
        parser_executable: None,
    });
    let faults = [
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
    ];
    let late: &[&str] = match facet {
        "preauthorization" => &faults,
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
        _ => panic!("unknown actor decoder facet"),
    };
    let mutants: &[&str] = if facet == "preauthorization" {
        &[
            "omit-job-list",
            "resume-before-guardian",
            "create-under-service-token",
            "omit-handle-list",
        ]
    } else {
        &[]
    };
    let mut actors = Vec::new();
    let mut first = None;
    for (ordinal, (kind, selector)) in late
        .iter()
        .map(|value| ("fault", *value))
        .chain(mutants.iter().map(|value| ("mutant", *value)))
        .enumerate()
    {
        let (actor, projection) = persist_actor_effect(
            &mut case, ordinal, kind, selector, &provider, &actor_sha, recipe,
        );
        actors.push(actor);
        if ordinal == 0 {
            first = Some(projection);
        }
    }
    let (pid, birth, attempt, nonce, digest, arguments) = first.unwrap();
    let mut invocation: NativeInvocation =
        serde_json::from_value(read(&case, "invocation.json")).unwrap();
    invocation.arguments = NativeArguments::WindowsUtf16(arguments);
    invocation.executable_sha256 = actor_sha.clone();
    invocation.association_sha256 = reconstruct_invocation_sha256(&invocation).unwrap();
    case.json(
        "invocation.json",
        &serde_json::to_value(&invocation).unwrap(),
    );
    let mut native: NativeObservation = serde_json::from_value(read(&case, "native.json")).unwrap();
    native.lease_id = None;
    native.origin = OutcomeOrigin::ComponentRegression;
    native.root_pid = Some(pid);
    native.root_birth = Some(birth);
    native.attempt_id = Some(attempt.clone());
    native.attempt_nonce = Some(nonce);
    native.request_sha256 = Some(digest);
    native.provider_generation = provider["generation"].as_str().map(str::to_owned);
    native.runtime_manifest_sha256 = provider["runtime_manifest_sha256"]
        .as_str()
        .map(str::to_owned);
    native.executable_sha256 = actor_sha.clone();
    native.invocation_sha256 = invocation.association_sha256;
    case.json("native.json", &serde_json::to_value(native).unwrap());
    let mut retirement: RetirementObservation =
        serde_json::from_value(read(&case, "retirement.json")).unwrap();
    retirement.aggregate_empty = false;
    retirement.attempt_id = Some(attempt);
    retirement.root_pid = Some(pid);
    retirement.root_birth = Some(birth);
    case.json(
        "retirement.json",
        &serde_json::to_value(retirement).unwrap(),
    );
    let actor_count = actors.len() as u64;
    let mut semantic: SemanticObservation =
        serde_json::from_value(read(&case, "semantic.json")).unwrap();
    semantic.key = case.record.key.clone();
    semantic.windows_refusal = None;
    semantic.operations.clear();
    semantic.component_actors = Some(actors);
    semantic.counters = std::collections::BTreeMap::from([("actors_executed".into(), actor_count)]);
    case.json("semantic.json", &serde_json::to_value(semantic).unwrap());
    let mut input: FixtureInput = serde_json::from_value(read(&case, "input.json")).unwrap();
    input.key = case.record.key.clone();
    input.deadline_millis = None;
    input.memory_bytes = None;
    input.target_argv = invocation.arguments;
    case.json("input.json", &serde_json::to_value(input).unwrap());
    let mut evidence: CaseEvidence = serde_json::from_value(read(&case, "case.json")).unwrap();
    evidence.key = case.record.key.clone();
    evidence.lease_id = None;
    evidence.component_recipe_id = Some(recipe.into());
    evidence.raw_result = None;
    evidence.request = None;
    evidence.fixture = "actor.exe".into();
    evidence.fixture_sha256 = actor_sha;
    evidence.input_sha256 = sha256(&std::fs::read(case.root.path().join("input.json")).unwrap());
    case.json("case.json", &serde_json::to_value(evidence).unwrap());
    case
}

#[test]
fn persisted_all_26_preauthorization_actor_effects_reject_rehashed_raw_reassociation() {
    let mut case = persisted_actor_facet("preauthorization");
    case.validate().unwrap();
    for ordinal in 0..26 {
        let path = format!("actors/{ordinal}/retirement.json");
        let original = std::fs::read(case.root.path().join(&path)).unwrap();
        case.mutate(&path, |raw| raw["retirement_observed"] = json!(false));
        assert!(
            case.validate().is_err(),
            "preauthorization/{ordinal} accepted unretired native actor"
        );
        case.write(&path, &original);
        let path = format!("actors/{ordinal}/settlement-exit.json");
        let original = std::fs::read(case.root.path().join(&path)).unwrap();
        case.mutate(&path, |raw| raw["native_status"] = json!(1));
        assert!(
            case.validate().is_err(),
            "preauthorization/{ordinal} accepted failed later convergence"
        );
        case.write(&path, &original);
    }
    for (path, field, value) in [
        ("actors/0/held.json", "creation_time_100ns", json!(999)),
        (
            "actors/0/retirement.json",
            "retirement_observed",
            json!(false),
        ),
        ("actors/0/inventory.json", "active_admissions", json!(1)),
        ("actors/25/selection.json", "mutant", json!("omit-job-list")),
    ] {
        let original = std::fs::read(case.root.path().join(path)).unwrap();
        case.mutate(path, |raw| raw[field] = value);
        assert!(case.validate().is_err(), "accepted {path}/{field}");
        case.write(path, &original);
    }
}

#[test]
fn persisted_remaining_15_authorized_actor_effects_require_original_terminal_and_native_owner_settlement()
 {
    for facet in ["postresume", "cleanup", "after-exit"] {
        let mut case = persisted_actor_facet(facet);
        case.validate().unwrap();
        let count = match facet {
            "postresume" => 8,
            "cleanup" => 6,
            "after-exit" => 1,
            _ => unreachable!(),
        };
        for ordinal in 0..count {
            let path = format!("actors/{ordinal}/retirement.json");
            let original = std::fs::read(case.root.path().join(&path)).unwrap();
            case.mutate(&path, |raw| raw["retirement_observed"] = json!(false));
            assert!(
                case.validate().is_err(),
                "{facet}/{ordinal} accepted unretired native actor"
            );
            case.write(&path, &original);
            let path = format!("actors/{ordinal}/settlement-exit.json");
            let original = std::fs::read(case.root.path().join(&path)).unwrap();
            case.mutate(&path, |raw| raw["native_status"] = json!(1));
            assert!(
                case.validate().is_err(),
                "{facet}/{ordinal} accepted failed actual later convergence"
            );
            case.write(&path, &original);
        }
        let path = "actors/0/observation.json";
        let original = std::fs::read(case.root.path().join(path)).unwrap();
        case.mutate(path, |raw| {
            let bytes: Vec<u8> =
                serde_json::from_value(raw["authenticated_provider_frames"][0].clone()).unwrap();
            let mut terminal: Value = serde_json::from_slice(&bytes).unwrap();
            terminal["retirement_proof"]["owner_capabilities_closed"] = json!(false);
            raw["authenticated_provider_frames"][0] = json!(serde_json::to_vec(&terminal).unwrap());
        });
        assert!(
            case.validate().is_err(),
            "{facet} accepted unclosedoriginalJobowner"
        );
        case.write(path, &original);
        case.mutate(path, |raw| {
            let bytes: Vec<u8> =
                serde_json::from_value(raw["authenticated_provider_frames"][0].clone()).unwrap();
            let mut terminal: Value = serde_json::from_slice(&bytes).unwrap();
            terminal["process_observation"]["fake_native_authority"] = json!(true);
            raw["authenticated_provider_frames"][0] = json!(serde_json::to_vec(&terminal).unwrap());
        });
        assert!(
            case.validate().is_err(),
            "{facet} accepted unknownnativeauthority"
        );
        case.write(path, &original);
        case.mutate(path, |raw| {
            let bytes: Vec<u8> =
                serde_json::from_value(raw["authenticated_provider_frames"][0].clone()).unwrap();
            let mut terminal: Value = serde_json::from_slice(&bytes).unwrap();
            terminal["policy_enforcement"] =
                json!({"state":"authorized","provider_resources_closed":true});
            raw["authenticated_provider_frames"][0] = json!(serde_json::to_vec(&terminal).unwrap());
        });
        assert!(
            case.validate().is_err(),
            "{facet} accepted unrelated workload authority for contract-free actor"
        );
    }
}

/// Entire retained native Windows completion graphs, never execution evidence.
fn persisted_windows_completion(status: i32) -> persisted_actor_support::PersistedCase {
    use memcordon_readiness_verifier::*;
    let (root, index, mut record) = preprovider_refusal_case(false, None);
    record.key.family = "W-STATUS".into();
    record.key.scenario = if status == 0 {
        "zero".into()
    } else {
        format!("exit-{status}")
    };
    let mut case = persisted_actor_support::PersistedCase {
        root,
        index,
        record,
    };
    case.write(
        "installed-producer-bundle.bin",
        b"original immutable installed Windows decoder vector bundle",
    );
    case.index.producer_origins.push(ProducerOrigin {
        job: "candidate-windows-x64-native".into(),
        run_id: "vector-run".into(),
        run_attempt: 1,
        artifact_id: "original-installed-vector".into(),
        artifact_sha256: sha256(b"original immutable installed Windows decoder vector bundle"),
        bundle_artifact: "installed-producer-bundle.bin".into(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        version: case.index.version.clone(),
        manifest_sha256: case.index.manifest_sha256.clone(),
        repository: None,
    });
    let read = |case: &persisted_actor_support::PersistedCase, path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap()).unwrap()
    };
    let mut evidence: CaseEvidence = serde_json::from_value(read(&case, "case.json")).unwrap();
    evidence.key = case.record.key.clone();
    evidence.authenticated_terminal = Some("terminal.json".into());
    evidence.provider_request = Some("provider-request.bin".into());
    let mut input: FixtureInput = serde_json::from_value(read(&case, "input.json")).unwrap();
    input.key = case.record.key.clone();
    input.target_argv = NativeArguments::WindowsUtf16(Vec::new());
    case.json("input.json", &serde_json::to_value(&input).unwrap());
    evidence.input_sha256 = sha256(&serde_json::to_vec(&input).unwrap());
    let mut invocation: NativeInvocation =
        serde_json::from_value(read(&case, "invocation.json")).unwrap();
    invocation.arguments =
        NativeArguments::WindowsUtf16(vec!["C:\\owned\\fixture.exe".encode_utf16().collect()]);
    invocation.association_sha256 = reconstruct_invocation_sha256(&invocation).unwrap();
    case.json(
        "invocation.json",
        &serde_json::to_value(&invocation).unwrap(),
    );
    evidence.input_sha256 = sha256(&std::fs::read(case.root.path().join("input.json")).unwrap());
    let provider = read(&case, "quiescence.json")["provider"].clone();
    let contract = read(&case, "contract.json");
    let nonce = hex::encode([1u8; 16]);
    let attempt = "6".repeat(64);
    let request = json!({"restart_attempt":0,"schema_version":3,"expected_provider_binding":provider,"workload_contract":contract,"nonce":nonce,"command":{"program":"C:\\owned\\fixture.exe".encode_utf16().collect::<Vec<_>>(),"arguments":[]},"environment":[],"current_directory":"C:\\owned".encode_utf16().collect::<Vec<_>>(),"policy":{"memory_limit_bytes":4294967296u64,"absolute_deadline_millis":123456,"lifetime":"workload","poll_interval_millis":100,"signal_grace_millis":0,"command_exit_grace_millis":0,"limit_grace_millis":0}});
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let digest = sha256(&request_bytes);
    case.write("provider-request.bin", &request_bytes);
    let mut native: NativeObservation = serde_json::from_value(read(&case, "native.json")).unwrap();
    native.invocation_sha256 = invocation.association_sha256.clone();
    native.origin = OutcomeOrigin::Target;
    native.frontend_status = status;
    native.target_status = Some(status);
    native.root_pid = Some(10);
    native.root_birth = Some(100);
    native.attempt_id = Some(attempt.clone());
    native.attempt_nonce = Some(nonce.clone());
    native.request_sha256 = Some(digest.clone());
    native.provider_sha256 = Some(
        case.index.products[0]
            .components
            .iter()
            .find(|component| component.role == "sealed-agent")
            .unwrap()
            .installed_sha256
            .clone(),
    );
    native.provider_generation = Some(provider["generation"].as_str().unwrap().into());
    native.runtime_manifest_sha256 =
        Some(provider["runtime_manifest_sha256"].as_str().unwrap().into());
    native.authenticated_provider_exchange = true;
    native.held_processes = vec![HeldProcessIdentity {
        pid: 10,
        birth: 100,
        parent_pid: None,
        parent_birth: None,
        retirement_observed: true,
    }];
    case.json("native.json", &serde_json::to_value(&native).unwrap());
    let mut boundary = json!({"schema_version":2,"service_identity":"MemCordonSealedControl+MemCordonSealedLauncher:v1","credential_transition_disposition":"preserve-caller-envelope"});
    for field in [
        "caller_token_authenticated",
        "initial_target_token_matches_caller",
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
    ] {
        boundary[field] = json!(true);
    }
    let safety = json!({"direct_child_reaped":true,"workload_empty":true,"helpers_reaped":true,"containment_removed":true,"containment_incapable_of_live_members":true,"sealed_boundary_retired":true,"errors":[]});
    let native_outcome = json!({"outcome":"exited","child":{"kind":"exit-code","code":status},"peak":null,"cleanup":{"graceful_attempted":false,"force_attempted":false,"direct_child_reaped":true,"workload_empty":true,"errors":[]}});
    let delivery = json!({"schema_version":1,"attempt_id":attempt,"nonce":nonce,"request_sha256":digest,"authority_sha256":"8".repeat(64),"retired_sha256":"9".repeat(64),"retired_confirmed":true});
    let mut terminal_boundary = boundary.clone();
    terminal_boundary["mechanism"] = json!("windows-job-object-v2");
    let terminal = json!({"schema_version":2,"attempt_id":attempt,"nonce":nonce,"request_sha256":digest,"payload":{"kind":"execution","child_pid":10,"duration_millis":20,"authorization_offset_millis":1,"outcome":native_outcome,"boundary_detail":terminal_boundary},"restart_safety":safety,"retirement_proof":{"schema_version":2,"source":"live-native","attempt_id":attempt,"nonce":nonce,"request_sha256":digest,"provider_generation":provider["generation"],"launch_incarnation":"original-launch","original_boot_id":"original-boot","job_identity":"original-job","owner_manifest_sha256":"7".repeat(64),"target_completion_observed":true,"native_job_empty_observed":true,"relay_closure_observed":true,"guardian_completion_observed":true,"owner_capabilities_closed":true,"launch_gate_closed":true,"policy_reference_bound":true},"process_observation":{"schema_version":2,"root_identity":{"process_id":10,"creation_time_100ns":100},"required_witness":null,"final_accounting":{"total_processes_native_u32":1,"active_processes_native_u32":0,"observed_after_target_retirement":true,"counter_regression_observed":false},"coverage":{"coverage":"sampled","policy":{"snapshot_storage_bytes":262144,"sample_storage_bytes":24576,"serialized_field_bytes":131072,"snapshot_queries_per_tick":2,"identity_queries_per_tick":64,"sample_interval_millis":100},"counters":{"polls_attempted":1,"snapshots_obtained":1,"identity_queries_attempted":1,"identity_observations_verified":1,"vanished_or_not_member":0,"sample_evictions":0,"counter_saturated":false},"omissions":{"snapshot_byte_budget":0,"snapshot_race_or_retry_budget":0,"per_tick_query_budget":0,"allocation_unavailable":0,"sample_eviction":0},"sample":[{"identity":{"process_id":10,"creation_time_100ns":100},"last_observation_sequence":1}]}}});
    let mut typed_boundary: memcordon_core::WindowsSealedEvidenceV2 =
        serde_json::from_value(boundary.clone()).unwrap();
    typed_boundary.frontend_delivery = Some(serde_json::from_value(delivery.clone()).unwrap());
    let typed_outcome: memcordon_core::RunOutcome = serde_json::from_value(native_outcome).unwrap();
    let typed_safety: memcordon_core::RestartSafetyProof = serde_json::from_value(safety).unwrap();
    let attempt_record = memcordon_core::AttemptRecord {
        operational_failure: None,
        runtime: None,
        private_execution: None,
        policy_enforcement: Default::default(),
        number: 1,
        kind: memcordon_core::AttemptKind::Initial,
        phase: memcordon_core::AttemptPhase::Completed,
        target_pid: Some(10),
        started_offset_ms: Some(0),
        authorized_offset_ms: Some(1),
        terminal_offset_ms: Some(20),
        finished_offset_ms: 21,
        outcome: Some(typed_outcome),
        error: None,
        restart_decision: Default::default(),
        launch: memcordon_core::LaunchEvidence {
            mechanism: "windows-job-object-v2".into(),
            target_released: true,
            containment_verified_before_authorization: true,
            guardian_started_before_authorization: true,
            target_spawn_error_reported: false,
            boundary_requested: memcordon_core::BoundaryRequirement::Sealed,
            boundary_effective: memcordon_core::BoundaryClass::Sealed,
            boundary_assignment_verified: true,
            boundary_reconfiguration_denied: true,
            inherited_resources_restricted: true,
            frontend_loss_cleanup_authority_verified: true,
        },
        restart_safety: typed_safety,
        boundary_detail: memcordon_core::BoundaryMechanismEvidence::WindowsJobObjectV2(Box::new(
            typed_boundary,
        )),
    };
    let mut attempt_record = attempt_record;
    attempt_record.launch.target_spawn_error_reported = true;
    use memcordon_core::workload_evidence::{
        EffectiveWorkloadPolicyV1, RuntimeAttemptBinding, RuntimePlanBinding,
        RuntimePolicyEnforcement, RuntimeWorkloadResolution, VerifiedCheckpointV1,
        baseline_observation,
    };
    let profile_kind =
        memcordon_core::workload_registry::BaselineProfile::WindowsHostNetworkExternal;
    let typed_contract: memcordon_core::workload_contract::WorkloadContractV1 =
        serde_json::from_value(contract.clone()).unwrap();
    let plan_binding = RuntimePlanBinding::from_local_grant(
        &typed_contract,
        memcordon_core::DiagnosticSha256::from_bytes([7u8; 32]),
        serde_json::from_value(provider.clone()).unwrap(),
        memcordon_core::BoundedText::new("original-boot").unwrap(),
    )
    .unwrap();
    let attempt_binding = RuntimeAttemptBinding {
        format: "memcordon.local-attempt-binding".into(),
        revision: 1,
        plan: plan_binding,
        attempt_id: memcordon_core::BoundedText::new(&attempt).unwrap(),
        restart_attempt: 0,
        admission_nonce: serde_json::from_value(json!(vec![1u8; 16])).unwrap(),
        caller_invocation_reference: serde_json::from_value(json!(vec![2u8; 16])).unwrap(),
    };
    let checkpoint = VerifiedCheckpointV1::observed(
        &attempt_binding,
        baseline_observation(profile_kind),
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    let resolution = RuntimeWorkloadResolution::Admitted {
        binding: attempt_binding.clone(),
        effective: EffectiveWorkloadPolicyV1 {
            profile: profile_kind,
            ceiling: profile_kind.ceiling(),
            restriction: baseline_observation(profile_kind),
        },
        preauthorization: checkpoint.digest().clone(),
    };
    attempt_record.policy_enforcement =
        RuntimePolicyEnforcement::retired(attempt_binding, checkpoint, true, true).unwrap();
    let mut terminal = terminal;
    terminal["policy_enforcement"] =
        serde_json::to_value(&attempt_record.policy_enforcement).unwrap();
    let mut public_boundary = boundary;
    public_boundary["frontend_delivery"] = delivery.clone();
    let mut result = read(&case, "case/result.json");
    result["invocation"]["association_sha256"] = json!(invocation.association_sha256);
    result["attempts"] = json!([attempt_record]);
    result["error"] = Value::Null;
    result["authorization"] = json!("granted");
    result["launch"] = json!({"state":"authorized","target_pid":10});
    result["outcome"] = json!({"kind":"completed","native_termination":{"kind":"exit-code","code":status},"wrapper_status":status});
    result["cleanup"]["direct_child_reaped"] = json!(true);
    result["runtime"] = json!({"kind":"windows-sealed","observation":public_boundary});
    result["provider_association"] =
        json!({"provider":provider,"attempt_id":attempt,"request_sha256":digest});
    result["policy"]["requested"]["boundary"] = json!("sealed");
    result["policy"]["effective"]["boundary"] = json!("sealed");
    result["launch"]["state"] = json!("release-issued");
    result["policy"]["effective"]["workload"] = serde_json::to_value(resolution).unwrap();
    result["supervision"] = json!({"phase":"completed","duration_ms":21,"attempt_records_created":1,"targets_authorized":1,"wrapper_exit_code":status,"terminal":{"kind":"attempt-outcome","attempt_number":1,"outcome":result["attempts"][0]["outcome"]},"attempt_history":{"capacity":memcordon_core::DETAILED_ATTEMPT_CAPACITY,"retained":1,"total":1,"omitted":0,"truncated":false},"aggregate":{"confirmed_authorizations":1,"unknown_authorization_attempts":0,"retry_attempts_started":0,"confirmed_retry_authorizations":0,"child_exits":1,"memory_limits":0,"deadlines":0,"interruptions":0,"monitor_failures":0,"setup_failures":0,"max_peak":null},"restart":{"enabled":false,"restarts_launched":0,"restart_limit_exhausted":false,"half_life_logistic_waits":0,"cooldowns":0,"circuit_open_count":0,"final_circuit_state":"closed"}});
    memcordon_core::ResultV1::parse(&serde_json::to_vec(&result).unwrap())
        .expect("completion factory must preserve a genuine frozen public ResultV1");
    case.json("case/result.json", &result);
    case.json("terminal.json",&json!({"format":"memcordon.windows-terminal-observation","revision":1,"provider":provider,"terminal":terminal,"provider_request":request_bytes,"frontend_delivery":delivery}));
    case.mutate("retirement.json", |raw| {
        raw["attempt_id"] = json!(attempt);
        raw["root_pid"] = json!(10);
        raw["root_birth"] = json!(100);
        raw["relays_retired"] = json!(true);
        raw["guardian_retired"] = json!(true);
        raw["native_handles_closed"] = json!(true);
        raw["final_job_handles_closed"] = json!(true);
        raw["active_processes_zero"] = json!(true);
    });
    let semantic_key = serde_json::to_value(&case.record.key).unwrap();
    case.mutate("semantic.json", |raw| {
        raw["key"] = semantic_key;
        raw["operations"] = json!([]);
        raw["counters"] = json!({});
        raw["windows_refusal"] = Value::Null;
    });
    case.json("case.json", &serde_json::to_value(&evidence).unwrap());
    case
}

#[test]
fn persisted_windows_zero_and_reserved_completion_statuses_preserve_original_native_authority() {
    for status in [0, 123, 124, 125, 126, 127] {
        let mut case = persisted_windows_completion(status);
        case.validate().unwrap();
        case.mutate("terminal.json", |raw| {
            raw["terminal"]["retirement_proof"]["native_job_empty_observed"] = json!(false)
        });
        assert!(
            case.validate().is_err(),
            "exit{status} accepted absent original native Job empty proof"
        );
    }
}

fn positive_toolchain(
    case: &mut persisted_actor_support::PersistedCase,
    native: &mut memcordon_readiness_verifier::NativeObservation,
    challenge: &[u8],
) -> (
    Value,
    Vec<memcordon_readiness_verifier::BehaviorArtifact>,
    String,
) {
    use memcordon_readiness_verifier::*;
    let tc = json!({"rustc":"C:\\owned\\toolchain\\rustc.exe","native_linker":"C:\\owned\\toolchain\\link.exe","native_library_directories":["C:\\owned\\toolchain\\vcrt","C:\\owned\\toolchain\\ucrt","C:\\owned\\toolchain\\um"],"library_source":"C:\\owned\\sources\\library.rs","test_source":"C:\\owned\\sources\\tests.rs","child_source":"C:\\owned\\sources\\child.rs","dll_source":"C:\\owned\\sources\\dll.rs","loader_source":"C:\\owned\\sources\\loader.rs","target":native.target});
    let mut peers = Vec::new();
    let mut selected = Vec::new();
    for field in [
        "rustc",
        "native_linker",
        "library_source",
        "test_source",
        "child_source",
        "dll_source",
        "loader_source",
    ] {
        let bytes = format!("original immutable selected {field}").into_bytes();
        let path = format!("positive-selected-{field}.bin");
        case.write(&path, &bytes);
        peers.push(BehaviorArtifact {
            role: format!("selected-{field}"),
            path,
        });
        selected.push(json!({"path":tc[field],"sha256":sha256(&bytes)}));
    }
    let mut images = std::collections::BTreeMap::new();
    for artifact in [
        "readiness.rlib",
        "child.exe",
        "tests.exe",
        "readiness.dll",
        "loader.exe",
    ] {
        let bytes = format!("original generated compiler output {artifact}").into_bytes();
        let path = format!("positive-generated-{artifact}.bin");
        case.write(&path, &bytes);
        peers.push(BehaviorArtifact {
            role: format!("generated-{artifact}"),
            path,
        });
        images.insert(artifact, sha256(&bytes));
    }
    for (field, file) in [
        ("library_source", "library.rs"),
        ("test_source", "tests.rs"),
        ("child_source", "child.rs"),
        ("dll_source", "dll.rs"),
        ("loader_source", "loader.rs"),
    ] {
        let path = format!("positive-compiler-source-{file}.bin");
        case.write(
            &path,
            format!("original immutable selected {field}").as_bytes(),
        );
        peers.push(BehaviorArtifact {
            role: format!("compiler-source-{file}"),
            path,
        });
    }
    let mut libraries = Vec::new();
    for (ordinal, directory) in ["vcrt", "ucrt", "um"].into_iter().enumerate() {
        let path = format!("selected-native-library-{ordinal}.bin");
        let original = format!("C:\\owned\\toolchain\\{directory}\\native.lib");
        let bytes = format!("original native {directory} library");
        case.write(&path, bytes.as_bytes());
        selected.push(json!({"path":original,"sha256":sha256(bytes.as_bytes())}));
        libraries.push(json!({"original_path":original,"artifact":path}));
    }
    case.json("positive-native-library-inputs.json", &json!(libraries));
    peers.push(BehaviorArtifact {
        role: "selected-native-library-inputs".into(),
        path: "positive-native-library-inputs.json".into(),
    });
    case.json("positive-toolchain-inputs.json", &json!(selected));
    let manifest_sha =
        sha256(&std::fs::read(case.root.path().join("positive-toolchain-inputs.json")).unwrap());
    peers.push(BehaviorArtifact {
        role: "toolchain-inputs".into(),
        path: "positive-toolchain-inputs.json".into(),
    });
    let parent = json!({"process_id":10,"creation_time_100ns":100});
    let root = "C:\\owned\\products\\compiled";
    let utf16 = |value: &str| value.encode_utf16().collect::<Vec<_>>();
    for (ordinal, (role, source, flags)) in [
        ("readiness.rlib", "library.rs", vec!["--crate-type=rlib"]),
        ("child.exe", "child.rs", vec![]),
        ("tests.exe", "tests.rs", vec!["--test"]),
        ("readiness.dll", "dll.rs", vec!["--crate-type=cdylib"]),
        ("loader.exe", "loader.rs", vec![]),
        ("run-tests", "", vec![]),
        ("run-child", "", vec![]),
        ("run-loader", "", vec![]),
    ]
    .into_iter()
    .enumerate()
    {
        let pid = 12 + ordinal as u32;
        let birth = 102 + ordinal as u64;
        if ordinal > 0 {
            native.held_processes.push(HeldProcessIdentity {
                pid,
                birth,
                parent_pid: Some(10),
                parent_birth: Some(100),
                retirement_observed: true,
            });
        }
        let child = json!({"process_id":pid,"creation_time_100ns":birth});
        let (program, args, image) = if !source.is_empty() {
            let mut args = vec![format!("{root}\\{source}")];
            args.extend(flags.into_iter().map(String::from));
            args.extend([
                "--edition=2021".into(),
                "--target".into(),
                native.target.clone(),
                "-C".into(),
                "linker=C:\\owned\\toolchain\\link.exe".into(),
                "-o".into(),
                format!("{root}\\{role}"),
            ]);
            for directory in ["vcrt", "ucrt", "um"] {
                args.extend([
                    "-L".into(),
                    format!("native=C:\\owned\\toolchain\\{directory}"),
                ]);
            }
            (
                "C:\\owned\\toolchain\\rustc.exe".into(),
                args,
                sha256(b"original immutable selected rustc"),
            )
        } else {
            let artifact = match role {
                "run-tests" => "tests.exe",
                "run-child" => "child.exe",
                _ => "loader.exe",
            };
            let args = match role {
                "run-tests" => vec!["--test-threads=1".into()],
                "run-child" => vec![
                    format!("{root}\\challenge-input.bin"),
                    format!("{root}\\child-output.bin"),
                ],
                _ => vec![format!("{root}\\readiness.dll"), root.into()],
            };
            (
                format!("{root}\\{artifact}"),
                args,
                images[artifact].clone(),
            )
        };
        let created = json!({"format":"memcordon.windows-fixture-owned-child-created","revision":1,"role":role,"challenge":challenge,"parent":parent,"child":child,"program_utf16":utf16(&program),"argv_utf16":args.iter().map(|arg|utf16(arg)).collect::<Vec<_>>(),"image_sha256":image,"held_from_process_creation":true,"held_live_before_wait":true,"native_parent_edge_observed":true});
        let retired = json!({"format":"memcordon.windows-fixture-owned-child-retired","revision":1,"role":role,"challenge":challenge,"parent":parent,"child":child,"image_sha256":image,"held_from_process_creation":true,"held_live_before_wait":true,"native_parent_edge_observed":true,"native_wait_completed":true,"native_status":0});
        for (phase, value) in [("created", created), ("retired", retired)] {
            let path = format!("positive-native-child-{role}-{phase}.json");
            case.json(&path, &value);
            peers.push(BehaviorArtifact {
                role: format!("native-child-{role}-{phase}"),
                path,
            });
        }
    }
    native.held_processes.push(HeldProcessIdentity {
        pid: 30,
        birth: 130,
        parent_pid: Some(12),
        parent_birth: Some(102),
        retirement_observed: true,
    });
    for (ordinal, pid, birth, parent_pid, parent_birth, field) in [
        (0, 12, 102, 10, 100, "rustc"),
        (1, 30, 130, 12, 102, "native_linker"),
    ] {
        let role = format!("native-toolchain-descendant-{ordinal}");
        let path = format!("positive-{role}.json");
        case.json(&path,&json!({"format":"memcordon.windows-native-toolchain-descendant","revision":1,"ordinal":ordinal,"root_pid":10,"pid":pid,"birth":birth,"parent_pid":parent_pid,"parent_birth":parent_birth,"image_sha256":sha256(format!("original immutable selected {field}").as_bytes()),"native_parent_edge_observed":true,"parent_and_child_held_live":true}));
        peers.push(BehaviorArtifact { role, path });
    }
    (tc, peers, manifest_sha)
}

fn persisted_windows_positive(
    family: &str,
    scenario: &str,
) -> persisted_actor_support::PersistedCase {
    use memcordon_readiness_verifier::*;
    let mut case = persisted_windows_completion(0);
    case.record.key.family = family.into();
    case.record.key.scenario = scenario.into();
    let read = |case: &persisted_actor_support::PersistedCase, path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap()).unwrap()
    };
    let mut e: CaseEvidence = serde_json::from_value(read(&case, "case.json")).unwrap();
    e.key = case.record.key.clone();
    let mut input: FixtureInput = serde_json::from_value(read(&case, "input.json")).unwrap();
    input.key = case.record.key.clone();
    case.json("input.json", &serde_json::to_value(&input).unwrap());
    e.input_sha256 = sha256(&std::fs::read(case.root.path().join("input.json")).unwrap());
    let mut native: NativeObservation = serde_json::from_value(read(&case, "native.json")).unwrap();
    native.held_processes.push(HeldProcessIdentity {
        pid: 11,
        birth: 101,
        parent_pid: Some(10),
        parent_birth: Some(100),
        retirement_observed: true,
    });
    native.held_processes.push(HeldProcessIdentity {
        pid: 12,
        birth: 102,
        parent_pid: Some(10),
        parent_birth: Some(100),
        retirement_observed: true,
    });
    case.json("native.json", &serde_json::to_value(&native).unwrap());
    let challenge = std::fs::read(case.root.path().join("challenge.bin")).unwrap();
    let restricted = scenario == "restricted";
    let (toolchain, mut toolchain_peers, toolchain_identity) =
        positive_toolchain(&mut case, &mut native, &challenge);
    input.toolchain_identity = Some(toolchain_identity);
    case.json("input.json", &serde_json::to_value(&input).unwrap());
    e.input_sha256 = sha256(&std::fs::read(case.root.path().join("input.json")).unwrap());
    case.json("native.json", &serde_json::to_value(&native).unwrap());
    case.mutate("terminal.json", |raw| {
        raw["terminal"]["process_observation"]["final_accounting"]["total_processes_native_u32"] =
            json!(native.held_processes.len())
    });
    let user_sid = vec![1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let token = json!({"user_sid":user_sid,"restricted":restricted,"integrity_rid":8192,"elevated":false,"restricting_sids":if restricted{json!([user_sid])}else{json!([])}});
    case.json("positive-token.json", &token);
    let descriptor = json!({"format":"memcordon.fixture-workload","revision":1,"case":if family=="W-TOOLCHAIN"{"toolchain"}else{"joint"},"output_root":"C:\\owned\\products","transcript":"C:\\owned\\transcript.bin","challenge":challenge,"stdout":[],"stderr":[],"arguments":[],"application_status":0,"churn_creations":0,"churn_live":0,"denied_write_paths":if restricted{json!(["C:\\owned\\protected\\forbidden"])}else{json!([])},"sentinel_handles":[128],"descendant_gate":null,"start_gate":"owned-native-observer-gate","completion_gate":null,"cohort_gate":null,"generation_gate":null,"toolchain":toolchain});
    case.json("positive-descriptor.json", &descriptor);
    let argv = serde_json::to_value(NativeArguments::WindowsUtf16(Vec::new())).unwrap();
    case.json("positive-native-argv.json", &argv);
    let association = json!({"attempt_id":native.attempt_id,"request_sha256":native.request_sha256,"provider":read(&case,"quiescence.json")["provider"]});
    let guardian = json!({"process_id":20,"creation_time_100ns":120});
    case.json("positive-live.json",&json!({"format":"memcordon.windows-live-guardian-observation","revision":1,"challenge":hex::encode(&challenge),"guardian_identity":guardian,"association":association,"live_nonce":native.attempt_nonce,"live_target_identity":{"process_id":10,"creation_time_100ns":100}}));
    case.json("positive-retired.json",&json!({"format":"memcordon.windows-native-positive-retirement","revision":1,"association":association,"held_processes":native.held_processes,"guardian_identity":guardian,"guardian_retirement_observed":true,"same_image_processes_absent":true,"global_quiescence_required":true}));
    case.json("positive-peer.json",&json!({"format":"memcordon.windows-native-tcp-peer","revision":1,"pid":11,"birth":101,"parent_pid":10,"parent_birth":100,"native_parent_edge_observed":true,"parent_and_child_held_live":true}));
    case.json("positive-listener.json",&json!({"format":"memcordon.windows-native-listener","revision":1,"root_pid":10,"root_creation_time_100ns":100,"address":"127.0.0.1","port":32123,"held_owner_live":true,"native_table_owner_observed_before_and_after":true,"conflicting_bind_win32_code":10048}));
    let frames = |values: &[Vec<u8>]| {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend((value.len() as u32).to_le_bytes());
            bytes.extend(value);
        }
        bytes
    };
    let request = frames(&[
        b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        vec![],
        vec![0, 255, 128, 10],
        challenge.clone(),
    ]);
    let response = frames(&[
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        vec![],
        vec![0, 255, 128, 10],
        challenge.clone(),
    ]);
    let pipe = frames(&[vec![], vec![0, 255, 128], challenge.clone()]);
    let mut peers = Vec::new();
    for (role, path) in [
        ("native-argv", "positive-native-argv.json"),
        ("native-retirement", "positive-retired.json"),
        ("native-live-association", "positive-live.json"),
        ("native-tcp-peer", "positive-peer.json"),
        ("native-listener", "positive-listener.json"),
    ] {
        peers.push(BehaviorArtifact {
            role: role.into(),
            path: path.into(),
        });
    }
    for (role, bytes) in [
        ("tcp-server-received", request),
        ("tcp-peer-received", response),
        ("named-pipe-server", pipe.clone()),
        ("named-pipe-client", pipe),
        ("empty-file", vec![]),
        ("binary-file", (0..=255).collect()),
        ("challenge-file", challenge.clone()),
        ("compiled-child", challenge.clone()),
        ("dll-empty", vec![]),
        ("dll-binary", (0..=255).collect()),
        (
            "compiled-test-stdout",
            b"test result: ok. 1 passed; 0 failed; 0 ignored;\n".to_vec(),
        ),
    ] {
        let path = format!("positive-{role}.bin");
        case.write(&path, &bytes);
        peers.push(BehaviorArtifact {
            role: role.into(),
            path,
        });
    }
    peers.append(&mut toolchain_peers);
    let mut transcript = Vec::new();
    let mut events = vec![
        ("started", challenge.clone()),
        ("native-argv-observed", serde_json::to_vec(&argv).unwrap()),
        ("sentinel-handles-excluded", 1u32.to_le_bytes().to_vec()),
        ("token-envelope", serde_json::to_vec(&token).unwrap()),
        ("toolchain-ready-for-native-observer", challenge.clone()),
    ];
    if restricted {
        events.push(("protected-write-denied",serde_json::to_vec(&json!({"path_utf16":"C:\\owned\\protected\\forbidden".encode_utf16().collect::<Vec<_>>(),"win32_code":5})).unwrap()));
    }
    if family != "W-TOOLCHAIN" {
        events.extend([
            ("tcp-listener-owned", 32123u16.to_le_bytes().to_vec()),
            ("tcp-conflicting-bind", 10048i32.to_le_bytes().to_vec()),
            ("named-pipe-while-tcp-owned", challenge.clone()),
            ("binary-files", challenge.clone()),
        ]);
    }
    events.extend([
        ("toolchain-compiled", challenge.clone()),
        ("toolchain-test-child-dll-complete", challenge.clone()),
    ]);
    if family != "W-TOOLCHAIN" {
        events.push(("tcp-peer-complete", challenge.clone()));
    }
    events.push(("finished", challenge.clone()));
    for (ordinal, (stage, value)) in events.into_iter().enumerate() {
        let bytes = serde_json::to_vec(
            &json!({"sequence":ordinal+1,"stage":stage,"pid":10,"ordinal":null,"value":value}),
        )
        .unwrap();
        transcript.extend((bytes.len() as u32).to_le_bytes());
        transcript.extend(bytes);
    }
    case.write("positive-transcript.bin", &transcript);
    let mut semantic: SemanticObservation =
        serde_json::from_value(read(&case, "semantic.json")).unwrap();
    semantic.key = case.record.key.clone();
    semantic.fixture_behavior = Some(FixtureBehavior {
        descriptor: "positive-descriptor.json".into(),
        transcript: "positive-transcript.bin".into(),
        expected_token: Some("positive-token.json".into()),
        peer_artifacts: peers,
        native_binding: None,
    });
    let mut operations = vec![
        "caller-token-attested",
        "locked-rust-compile",
        "compiled-tests",
        "generated-executable",
        "compiled-dll-loaded",
        "generated-descendant",
        "frontend-sentinel-held",
        "sentinel-not-inherited",
    ];
    if restricted {
        operations.extend(["restricted-token", "protected-write-denied"]);
    }
    if family != "W-TOOLCHAIN" {
        operations.extend([
            "tcp-conflicting-bind",
            "tcp-owned-listener",
            "named-pipe-exchange",
            "allowed-file-write",
            "http-exchange",
        ]);
    }
    semantic.operations = operations
        .into_iter()
        .map(|operation| OperationObservation {
            operation: operation.into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            observer: "owned-fixture-behavior".into(),
            native_receipt: "positive-transcript.bin".into(),
        })
        .collect();
    semantic.comparisons = vec![];
    for (role, actual, expected) in if family == "W-TOOLCHAIN" {
        vec![
            (
                "compiled-child",
                "positive-compiled-child.bin",
                challenge.clone(),
            ),
            ("dll-empty", "positive-dll-empty.bin", vec![]),
            ("dll-binary", "positive-dll-binary.bin", (0..=255).collect()),
        ]
    } else {
        vec![
            (
                "tcp",
                "positive-tcp-server-received.bin",
                frames(&[
                    b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
                    vec![],
                    vec![0, 255, 128, 10],
                    challenge.clone(),
                ]),
            ),
            (
                "http",
                "positive-tcp-peer-received.bin",
                frames(&[
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                    vec![],
                    vec![0, 255, 128, 10],
                    challenge.clone(),
                ]),
            ),
            (
                "named-pipe",
                "positive-named-pipe-client.bin",
                frames(&[vec![], vec![0, 255, 128], challenge.clone()]),
            ),
            ("file", "positive-binary-file.bin", (0..=255).collect()),
            (
                "descendant",
                "positive-compiled-child.bin",
                challenge.clone(),
            ),
        ]
    } {
        let path = format!("positive-expected-{role}.bin");
        case.write(&path, &expected);
        semantic.comparisons.push(ByteComparison {
            role: role.into(),
            actual: actual.into(),
            expected: path,
        });
    }
    semantic.counters = Default::default();
    case.json("semantic.json", &serde_json::to_value(semantic).unwrap());
    case.json("case.json", &serde_json::to_value(e).unwrap());
    case
}

#[test]
fn persisted_windows_joint_and_toolchain_original_native_positive_graphs() {
    for (family, scenario) in [
        ("W-JOINT", "ordinary"),
        ("W-JOINT", "restricted"),
        ("W-TOOLCHAIN", "ordinary"),
        ("W-TOOLCHAIN", "restricted"),
    ] {
        let factory = || persisted_windows_positive(family, scenario);
        let mut case = factory();
        case.validate().unwrap();
        case.mutate("positive-retired.json", |raw| {
            raw["held_processes"][1]["birth"] = json!(999)
        });
        assert!(
            case.validate().is_err(),
            "{family}/{scenario} reassociated held original descendant"
        );
        let mut case = factory();
        case.mutate("positive-native-child-run-child-retired.json", |raw| {
            raw["native_wait_completed"] = json!(false)
        });
        assert!(
            case.validate().is_err(),
            "{family}/{scenario} omitted genuine generated child wait"
        );
        let mut case = factory();
        case.write(
            "positive-generated-child.exe.bin",
            b"another generated image",
        );
        assert!(
            case.validate().is_err(),
            "{family}/{scenario} reassociated original kernel generated child image"
        );
        let mut case = factory();
        case.mutate("positive-native-toolchain-descendant-1.json", |raw| {
            raw["parent_birth"] = json!(999)
        });
        assert!(
            case.validate().is_err(),
            "{family}/{scenario} reassociated real native linker ancestry"
        );
        let mut case = factory();
        case.write(
            "positive-compiler-source-child.rs.bin",
            b"another source file",
        );
        assert!(
            case.validate().is_err(),
            "{family}/{scenario} changed original measured source supplied to compiler"
        );
    }
}

fn persisted_windows_loss(scenario: &str) -> persisted_actor_support::PersistedCase {
    use memcordon_readiness_verifier::*;
    let mut case = persisted_windows_completion(0);
    case.record.key.family = "W-RETIREMENT".into();
    case.record.key.scenario = scenario.into();
    let read = |case: &persisted_actor_support::PersistedCase, path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap()).unwrap()
    };
    let mut evidence: CaseEvidence = serde_json::from_value(read(&case, "case.json")).unwrap();
    evidence.key = case.record.key.clone();
    let mut native: NativeObservation = serde_json::from_value(read(&case, "native.json")).unwrap();
    native.origin = OutcomeOrigin::ProviderFailure;
    native.target_status = None;
    native.frontend_status = 126;
    native.held_processes.push(HeldProcessIdentity {
        pid: 11,
        birth: 101,
        parent_pid: Some(10),
        parent_birth: Some(100),
        retirement_observed: true,
    });
    case.json("native.json", &serde_json::to_value(&native).unwrap());
    let mut input: FixtureInput = serde_json::from_value(read(&case, "input.json")).unwrap();
    input.key = case.record.key.clone();
    case.json("input.json", &serde_json::to_value(&input).unwrap());
    evidence.input_sha256 = sha256(&std::fs::read(case.root.path().join("input.json")).unwrap());
    let challenge = std::fs::read(case.root.path().join("challenge.bin")).unwrap();
    let provider = read(&case, "quiescence.json")["provider"].clone();
    let association = json!({"provider":provider,"attempt_id":native.attempt_id,"request_sha256":native.request_sha256});
    let worker = scenario == "attempt-worker-loss";
    let frontend = scenario == "frontend-loss";
    let process = json!({"process_id":90,"creation_time_100ns":90});
    let thread = json!({"thread_id":91,"creation_time_100ns":91});
    let mut action = json!({"format":"memcordon.windows-native-loss-action","revision":1,"kind":if worker{"terminate-thread"}else{"terminate-process"},"process":process,"thread":if worker{thread.clone()}else{Value::Null},"native_requested_status":126,"subject_role":if worker{"attempt-worker"}else if frontend{"frontend"}else{"control-service"},"image_sha256":sha256(if frontend{b"original CLI image".as_slice()}else{b"original agent image".as_slice()}),"subject_held_before_action":true,"action_completed":true});
    // The installed Windows factory selects these exact component bytes.
    let product = &case.index.products[0];
    let selected = product
        .components
        .iter()
        .find(|component| {
            component.role
                == if frontend {
                    "public-cli"
                } else {
                    "sealed-agent"
                }
        })
        .unwrap();
    action["image_sha256"] = json!(selected.installed_sha256);
    if !worker && !frontend {
        action["control_service"] =
            json!({"name":"MemCordonSealedControl","process_id":90,"current_state":4});
    }
    case.json("loss-action.json", &action);
    let mut live = json!({"format":"memcordon.windows-live-guardian-observation","revision":1,"challenge":hex::encode(&challenge),"guardian_identity":{"process_id":20,"creation_time_100ns":120},"association":association,"live_nonce":native.attempt_nonce,"live_target_identity":{"process_id":10,"creation_time_100ns":100}});
    if worker {
        live["worker_process_identity"] = process;
        live["worker_thread_identity"] = thread;
    }
    case.json("loss-live.json", &live);
    let members=native.held_processes.iter().map(|member|json!({"pid":member.pid,"birth":member.birth,"parent_pid":member.parent_pid,"parent_birth":member.parent_birth,"held_before_action":true,"retirement_observed":true})).collect::<Vec<_>>();
    case.json("loss-family.json",&json!({"format":"memcordon.windows-native-family-retirement","revision":1,"attempt_id":native.attempt_id,"nonce":native.attempt_nonce,"request_sha256":native.request_sha256,"root_pid":10,"root_birth":100,"processes":members}));
    let sidecar = read(&case, "terminal.json");
    let mut terminal = sidecar["terminal"].clone();
    terminal["payload"] = json!({"kind":"recovered-closure","primary_failure":{"unavailable":{"reason":"worker-lost-before-observation"}},"target_creation_observed":true,"resume_attempted":true});
    terminal["process_observation"] = json!({"schema_version":2,"coverage":{"coverage":"unavailable","reason":"worker-lost-before-freeze"},"root_identity":null,"final_accounting":null,"required_witness":null});
    terminal["retirement_proof"]["source"] = json!("guardian-recovery");
    terminal["retirement_proof"]["guardian_receipt_sha256"] = json!("8".repeat(64));
    terminal["retirement_proof"]["target_completion_observed"] = json!(false);
    terminal["retirement_proof"]["relay_closure_observed"] = json!(false);
    terminal["kind"] = json!("terminal");
    if !worker {
        terminal["process_observation"] = sidecar["terminal"]["process_observation"].clone();
        terminal["process_observation"]["final_accounting"]["total_processes_native_u32"] =
            json!(2);
    }
    case.json("loss-recovery.json",&json!({"schema_version":1,"provider_response":terminal,"frontend_delivery":sidecar["frontend_delivery"]}));
    case.write("loss-stdout.bin", b"");
    case.write("loss-stderr.bin", b"");
    let cli = case.index.products[0]
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .unwrap()
        .installed_sha256
        .clone();
    let current = json!({"channel":"native-bundle","source_commit":case.index.source_commit,"version":case.index.version,"target":case.record.key.target,
        "artifacts":[],"cli":{"path":"C:\\original\\memcordon.exe","sha256":cli},"agent":{},"components":[],"installed_components":[],"fixture":{},"installed_agent":{},"installed_manifest":{},"provider":provider,"output_directory":"C:\\original\\current"});
    let identity = json!({"run_id":case.index.run_id,"source_commit":case.index.source_commit,"source_tree_sha256":case.index.source_tree_sha256,"version":case.index.version});
    let product_key = json!({"target":case.record.key.target,"channel":case.record.key.channel});
    case.json("loss-owner.json",&json!({"format":"memcordon.consumer-readiness.windows-lease-owner","revision":1,"identity":identity,"key":product_key,"current":current,"predecessor":{},"binary_root":"C:\\installed","state_root":"C:\\state","policy_root":"C:\\policy","artifact_root":"C:\\original","work_deadline_unix_millis":1000,"cleanup_deadline_unix_millis":901000}));
    case.json("loss-deadlines.json",&json!({"format":"memcordon.consumer-readiness.windows-original-deadlines","revision":1,"identity":identity,"key":product_key,"artifact_root":"C:\\original","work_deadline_unix_millis":1000,"cleanup_deadline_unix_millis":901000}));
    let command = json!({"format":"memcordon.windows-loss-recovery-command","revision":1,"target":case.record.key.target,"source_commit":case.index.source_commit,"executable_sha256":cli,
        "program_utf16":"C:\\original\\memcordon.exe".encode_utf16().collect::<Vec<_>>(),"cwd_utf16":"C:\\original\\current".encode_utf16().collect::<Vec<_>>(),
        "argv_utf16":(["windows-recover","attempt",native.attempt_id.as_deref().unwrap(),native.attempt_nonce.as_deref().unwrap(),native.request_sha256.as_deref().unwrap()].map(|arg|arg.encode_utf16().collect::<Vec<_>>())),
        "environment_cleared":true,"work_deadline_unix_millis":1000,"cleanup_deadline_unix_millis":901000,"started_unix_millis":811000,"budget_millis":10000,"recovery_deadline_unix_millis":901000});
    case.json("loss-command.json", &command);
    let command_sha = sha256(&std::fs::read(case.root.path().join("loss-command.json")).unwrap());
    case.json("loss-creation.json",&json!({"format":"memcordon.windows-loss-recovery-creation","revision":1,"invocation_sha256":command_sha,"process":{"process_id":95,"creation_time_100ns":195},"image_sha256":cli,"creation_handle_retained":true}));
    case.json("loss-process.json",&json!({"format":"memcordon.windows-loss-recovery-process","revision":1,"invocation_sha256":command_sha,"process":{"process_id":95,"creation_time_100ns":195},"image_sha256":cli,"native_status":0,"native_wait_completed":true,"capture_complete":true,"stdout_sha256":sha256(&std::fs::read(case.root.path().join("loss-recovery.json")).unwrap()),"stderr_sha256":sha256(b"")}));
    evidence.windows_loss = Some(WindowsLossEvidence {
        action: "loss-action.json".into(),
        live_observation: "loss-live.json".into(),
        original_result: None,
        native_family_retirement: "loss-family.json".into(),
        recovery: "loss-recovery.json".into(),
        stdout: "loss-stdout.bin".into(),
        stderr: "loss-stderr.bin".into(),
        capture_failure: None,
        recovery_invocation: "loss-command.json".into(),
        recovery_process: "loss-process.json".into(),
        recovery_creation: "loss-creation.json".into(),
        recovery_stderr: "loss-stderr.bin".into(),
        original_lease_owner: "loss-owner.json".into(),
        original_deadlines: "loss-deadlines.json".into(),
    });
    let mut semantic: SemanticObservation =
        serde_json::from_value(read(&case, "semantic.json")).unwrap();
    semantic.key = case.record.key.clone();
    semantic.operations = [
        format!("fault-{scenario}"),
        "original-cause-retained".into(),
        "independent-retirement".into(),
    ]
    .into_iter()
    .map(|operation| OperationObservation {
        operation,
        attempt_id: native.attempt_id.clone(),
        root_pid: native.root_pid,
        observer: "owned-native-loss".into(),
        native_receipt: "loss-action.json".into(),
    })
    .collect();
    case.json("semantic.json", &serde_json::to_value(&semantic).unwrap());
    case.json("case.json", &serde_json::to_value(&evidence).unwrap());
    case
}

#[test]
fn persisted_windows_three_native_loss_subjects_require_original_family_and_recovered_closure() {
    for scenario in [
        "frontend-loss",
        "control-service-loss",
        "attempt-worker-loss",
    ] {
        let factory = || persisted_windows_loss(scenario);
        let mut case = factory();
        case.validate().unwrap();
        case.mutate("loss-action.json", |raw| {
            raw["process"]["process_id"] = json!(10)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} substituted target as fault subject"
        );
        let mut case = factory();
        case.mutate("loss-family.json", |raw| {
            raw["processes"][1]["birth"] = json!(999)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} substituted unrelated descendant"
        );
    }
}

#[test]
fn persisted_windows_loss_recovery_rehashed_cutoff_and_native_creation_hostiles() {
    use memcordon_readiness_verifier::sha256;
    for scenario in [
        "frontend-loss",
        "control-service-loss",
        "attempt-worker-loss",
    ] {
        let mut case = persisted_windows_loss(scenario);
        case.validate().unwrap();
        case.mutate("loss-command.json", |raw| {
            raw["started_unix_millis"] = json!(901001)
        });
        let digest = sha256(&std::fs::read(case.root.path().join("loss-command.json")).unwrap());
        for path in ["loss-creation.json", "loss-process.json"] {
            case.mutate(path, |raw| raw["invocation_sha256"] = json!(digest));
        }
        assert!(
            case.validate().is_err(),
            "{scenario} recovery minted time after original cleanup"
        );
        let mut case = persisted_windows_loss(scenario);
        case.validate().unwrap();
        case.mutate("loss-process.json", |raw| {
            raw["process"]["creation_time_100ns"] = json!(196)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} recovery substituted kernel process birth"
        );
        let mut case = persisted_windows_loss(scenario);
        case.validate().unwrap();
        case.mutate("loss-process.json", |raw| {
            raw["native_wait_completed"] = json!(false)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} recovery omitted original kernel wait"
        );
        for malformed in ["1:\\original", "C:\\original:stream"] {
            let mut case = persisted_windows_loss(scenario);
            case.validate().unwrap();
            case.mutate("loss-owner.json", |raw| {
                raw["artifact_root"] = json!(malformed)
            });
            assert!(
                case.validate().is_err(),
                "{scenario} recovery accepted malformed native drive or alternate stream root"
            );
        }
    }
}

/// Retain distinct original invocations rather than relabel one invocation as a
/// multi-attempt vector. Each fixture's hashes are recomputed after encoding.
fn capacity_constituent(
    case: &mut persisted_actor_support::PersistedCase,
    scenario: &str,
    ordinal: usize,
) -> String {
    use memcordon_readiness_verifier::*;
    let source = persisted_windows_positive("W-JOINT", "ordinary");
    let prefix = format!("capacity/{ordinal}");
    let read = |path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(source.root.path().join(path)).unwrap()).unwrap()
    };
    let old_challenge = std::fs::read(source.root.path().join("challenge.bin")).unwrap();
    let challenge = vec![40 + ordinal as u8; 32];
    let native = read("native.json");
    let old_nonce = native["attempt_nonce"].as_str().unwrap().to_owned();
    let nonce = hex::encode([40 + ordinal as u8; 16]);
    let old_attempt = native["attempt_id"].as_str().unwrap().to_owned();
    let attempt = hex::encode([60 + ordinal as u8; 32]);
    let paths = source
        .index
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.clone(), format!("{prefix}/{}", artifact.path)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut replacements = std::collections::BTreeMap::from([
        (old_nonce, nonce),
        (old_attempt, attempt),
        (hex::encode(&old_challenge), hex::encode(&challenge)),
        (sha256(&old_challenge), sha256(&challenge)),
    ]);
    fn transform(
        value: &mut Value,
        field: &str,
        paths: &std::collections::BTreeMap<String, String>,
        replacements: &std::collections::BTreeMap<String, String>,
        old: &[u8],
        new: &[u8],
        offset: u64,
    ) {
        match value {
            Value::String(text) => {
                if let Some(next) = replacements.get(text).or_else(|| paths.get(text)) {
                    *text = next.clone();
                }
            }
            Value::Number(number) => {
                if ([
                    "pid",
                    "process_id",
                    "root_pid",
                    "target_pid",
                    "child_pid",
                    "parent_pid",
                    "target_process_id",
                ]
                .contains(&field)
                    || [
                        "birth",
                        "creation_time_100ns",
                        "root_creation_time_100ns",
                        "root_birth",
                        "parent_birth",
                        "target_creation_time_100ns",
                    ]
                    .contains(&field))
                    && let Some(original) = number.as_u64()
                {
                    *value = json!(original + offset);
                }
            }
            Value::Object(object) => {
                for (name, value) in object {
                    transform(value, name, paths, replacements, old, new, offset);
                }
            }
            Value::Array(array) => {
                if let Ok(bytes) = serde_json::from_value::<Vec<u8>>(json!(array)) {
                    if bytes == old {
                        *value = json!(new);
                        return;
                    }
                    if let Ok(mut inner) = serde_json::from_slice::<Value>(&bytes) {
                        transform(&mut inner, "", paths, replacements, old, new, offset);
                        *value = json!(serde_json::to_vec(&inner).unwrap());
                        return;
                    }
                }
                for item in array {
                    transform(item, field, paths, replacements, old, new, offset);
                }
            }
            _ => {}
        }
    }
    let offset = (ordinal as u64 + 1) * 1000;
    let mut request = read("provider-request.bin");
    transform(
        &mut request,
        "",
        &paths,
        &replacements,
        &old_challenge,
        &challenge,
        offset,
    );
    replacements.insert(
        native["request_sha256"].as_str().unwrap().into(),
        sha256(&serde_json::to_vec(&request).unwrap()),
    );
    let mut invocation = read("invocation.json");
    transform(
        &mut invocation,
        "",
        &paths,
        &replacements,
        &old_challenge,
        &challenge,
        offset,
    );
    let typed: NativeInvocation = serde_json::from_value(invocation).unwrap();
    replacements.insert(
        typed.association_sha256.clone(),
        reconstruct_invocation_sha256(&typed).unwrap(),
    );
    let mut input = read("input.json");
    transform(
        &mut input,
        "",
        &paths,
        &replacements,
        &old_challenge,
        &challenge,
        offset,
    );
    input["key"] = serde_json::to_value(&case.record.key).unwrap();
    let input_sha = sha256(&serde_json::to_vec(&input).unwrap());
    replacements.insert(
        read("case.json")["input_sha256"].as_str().unwrap().into(),
        input_sha,
    );
    for artifact in &source.index.artifacts {
        let bytes = std::fs::read(source.root.path().join(&artifact.path)).unwrap();
        let target = &paths[&artifact.path];
        if artifact.path == "positive-transcript.bin" {
            let mut tail = bytes.as_slice();
            let mut transcript = Vec::new();
            while !tail.is_empty() {
                let length = u32::from_le_bytes(tail[..4].try_into().unwrap()) as usize;
                let mut event: Value = serde_json::from_slice(&tail[4..4 + length]).unwrap();
                transform(
                    &mut event,
                    "",
                    &paths,
                    &replacements,
                    &old_challenge,
                    &challenge,
                    offset,
                );
                let encoded = serde_json::to_vec(&event).unwrap();
                transcript.extend((encoded.len() as u32).to_le_bytes());
                transcript.extend(encoded);
                tail = &tail[4 + length..];
            }
            case.write(target, &transcript);
        } else if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) {
            transform(
                &mut value,
                "",
                &paths,
                &replacements,
                &old_challenge,
                &challenge,
                offset,
            );
            if value.get("key").is_some() {
                value["key"] = serde_json::to_value(&case.record.key).unwrap();
            }
            case.json(target, &value);
        } else {
            let mut output = Vec::new();
            let mut remaining = bytes.as_slice();
            while let Some(at) = remaining
                .windows(old_challenge.len())
                .position(|window| window == old_challenge)
            {
                output.extend(&remaining[..at]);
                output.extend(&challenge);
                remaining = &remaining[at + old_challenge.len()..];
            }
            output.extend(remaining);
            case.write(target, &output);
        }
    }
    let evidence_path = paths["case.json"].clone();
    let key = serde_json::to_value(&case.record.key).unwrap();
    case.mutate(&evidence_path, |evidence| {
        evidence["key"] = key;
    });
    assert_eq!(scenario, case.record.key.scenario);
    evidence_path
}

fn persisted_windows_capacity(scenario: &str) -> persisted_actor_support::PersistedCase {
    use memcordon_readiness_verifier::*;
    let mut case = persisted_windows_positive("W-JOINT", "ordinary");
    case.record.key.family = "W-CAPACITY".into();
    case.record.key.scenario = scenario.into();
    let (count, inventories) = match scenario {
        "serial-retirement" => (3, 4),
        "bounded-concurrency" => (2, 2),
        "fresh-positive-after-recovery" => (1, 2),
        _ => panic!("unknown finite native capacity fixture"),
    };
    let attempts = (0..count)
        .map(|ordinal| capacity_constituent(&mut case, scenario, ordinal))
        .collect::<Vec<_>>();
    let read = |case: &persisted_actor_support::PersistedCase, path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap()).unwrap()
    };
    let mut evidence: CaseEvidence = serde_json::from_value(read(&case, &attempts[0])).unwrap();
    let native: NativeObservation =
        serde_json::from_value(read(&case, &evidence.native_observation)).unwrap();
    let first: SemanticObservation =
        serde_json::from_value(read(&case, &evidence.semantic_observation)).unwrap();
    let mut inventory_paths = Vec::new();
    for ordinal in 0..inventories {
        let path = format!("capacity/inventory-{ordinal}.json");
        case.json(&path,&json!({"schema_version":1,"challenge":hex::encode([80+ordinal as u8;32]),"provider_generation":native.provider_generation,"current_boot_identity":"original-native-boot","executing":0,"incomplete_proof":0,"unacknowledged_outboxes":0,"ack_retirement_in_progress":0,"completed_tombstones":ordinal,"active_admissions":0,"quarantined":0}));
        inventory_paths.push(path);
    }
    let overlap = scenario == "bounded-concurrency";
    if overlap {
        let behavior = first.fixture_behavior.as_ref().unwrap();
        let peer = |role: &str| {
            behavior
                .peer_artifacts
                .iter()
                .find(|peer| peer.role == role)
                .unwrap()
                .path
                .clone()
        };
        let live = read(&case, &peer("native-live-association"));
        let tcp = read(&case, &peer("native-tcp-peer"));
        case.json("capacity/overlap-live.json", &live);
        case.json("capacity/overlap-guardian.json", &live["guardian_identity"]);
        let second: CaseEvidence = serde_json::from_value(read(&case, &attempts[1])).unwrap();
        let mut retired = read(&case, "capacity/1/positive-retired.json");
        retired["format"] = json!("memcordon.windows-native-overlap-retirement");
        retired["same_image_processes_absent"] = json!(false);
        retired["global_quiescence_required"] = json!(false);
        retired["excluded_live_association"] = live;
        retired["excluded_held_processes"] = json!([{"pid":native.root_pid,"birth":native.root_birth,"held_live_before_overlap":true,"still_live_at_own_retirement":true},{"pid":tcp["pid"],"birth":tcp["birth"],"held_live_before_overlap":true,"still_live_at_own_retirement":true}]);
        case.json("capacity/1/positive-retired.json", &retired);
        assert_eq!(second.native_observation, "capacity/1/native.json");
        case.mutate(&second.retirement, |retired| {
            retired["independently_observed"] = json!(false)
        });
    }
    let mut semantic = first;
    semantic.windows_capacity = Some(WindowsCapacityEvidence {
        attempts,
        inventories: inventory_paths.clone(),
        overlap_live_association: overlap.then(|| "capacity/overlap-live.json".into()),
        overlap_held_guardian: overlap.then(|| "capacity/overlap-guardian.json".into()),
    });
    semantic
        .counters
        .insert("capacity-attempts".into(), count as u64);
    for operation in [
        format!("capacity-{scenario}"),
        "fresh-admission".into(),
        "capacity-attempts".into(),
    ] {
        semantic.operations.push(OperationObservation {
            operation,
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            observer: "owned-native-capacity".into(),
            native_receipt: inventory_paths.last().unwrap().clone(),
        });
    }
    case.json(
        "capacity/semantic.json",
        &serde_json::to_value(&semantic).unwrap(),
    );
    evidence.semantic_observation = "capacity/semantic.json".into();
    case.json("case.json", &serde_json::to_value(&evidence).unwrap());
    case
}

#[test]
fn persisted_windows_all_three_capacity_vectors_require_distinct_original_constituents() {
    for scenario in [
        "serial-retirement",
        "bounded-concurrency",
        "fresh-positive-after-recovery",
    ] {
        let factory = || persisted_windows_capacity(scenario);
        let mut case = factory();
        case.validate().unwrap();
        case.mutate("capacity/inventory-0.json", |raw| {
            raw["active_admissions"] = json!(1)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} accepted retained native admission authority"
        );
        let mut case = factory();
        case.mutate(
            "capacity/0/positive-native-child-run-loader-retired.json",
            |raw| raw["native_status"] = json!(1),
        );
        assert!(
            case.validate().is_err(),
            "{scenario} skipped constituent real loader native wait failure"
        );
        if scenario == "bounded-concurrency" {
            let mut case = factory();
            case.mutate("capacity/1/positive-retired.json", |raw| {
                raw["excluded_held_processes"][1]["birth"] = json!(999)
            });
            assert!(
                case.validate().is_err(),
                "overlap accepted foreign held peer exclusion"
            );
        }
    }
}

/// Full persisted decoder vectors; these are not native execution evidence.
#[test]
fn persisted_standard_refusal_rejects_native_and_authority_reassociation() {
    for mutation in [
        None,
        Some("frontend-birth"),
        Some("frontend-writer"),
        Some("live-guardian"),
        Some("invented-handle-closure"),
        Some("sealed-authorization"),
        Some("completed-target"),
        Some("provider-authority"),
        Some("capture-bytes"),
        Some("ambient-environment"),
        Some("input-challenge"),
        Some("semantic-header"),
        Some("retirement-header"),
    ] {
        let (root, index, record) = preprovider_refusal_case(false, mutation);
        let result = memcordon_readiness_verifier::windows_acceptance::validate_preprovider_case(
            &index,
            &record,
            root.path(),
        );
        if mutation.is_none() {
            result.unwrap();
        } else {
            assert!(
                result.is_err(),
                "accepted hostile whole-case mutation {mutation:?}"
            );
        }
    }
}

#[test]
fn persisted_nul_facade_rejects_native_capture_and_argument_reassociation() {
    for mutation in [
        None,
        Some("frontend-birth"),
        Some("live-guardian"),
        Some("invented-handle-closure"),
        Some("provider-authority"),
        Some("capture-bytes"),
        Some("ambient-environment"),
        Some("nul-argument"),
        Some("nul-release"),
        Some("input-challenge"),
        Some("semantic-header"),
        Some("retirement-header"),
    ] {
        let (root, index, record) = preprovider_refusal_case(true, mutation);
        let result = memcordon_readiness_verifier::windows_acceptance::validate_preprovider_case(
            &index,
            &record,
            root.path(),
        );
        if mutation.is_none() {
            result.unwrap();
        } else {
            assert!(
                result.is_err(),
                "accepted hostile persisted NUL case {mutation:?}"
            );
        }
    }
}

fn preprovider_refusal_case(
    nul: bool,
    mutation: Option<&str>,
) -> (
    tempfile::TempDir,
    memcordon_readiness_verifier::EvidenceIndex,
    memcordon_readiness_verifier::CaseRecord,
) {
    use memcordon_readiness_verifier::*;
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let mut artifacts = Vec::new();
    let mut write = |path: &str, bytes: &[u8]| {
        std::fs::create_dir_all(root.path().join(path).parent().unwrap()).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.path().join(path))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        artifacts.push(Artifact {
            path: path.into(),
            length: bytes.len() as u64,
            sha256: sha256(bytes),
        });
        path.to_owned()
    };
    let source = "c".repeat(40);
    let tree = "d".repeat(64);
    let target = "x86_64-pc-windows-msvc";
    let version = "0.1.0-vector";
    let key = CaseKey {
        target: target.into(),
        channel: Some("candidate-native".into()),
        evidence_class: EvidenceClass::InstalledProduct,
        family: if nul { "W-IO" } else { "W-BINDING" }.into(),
        scenario: if nul {
            "argv-nul-rejection"
        } else {
            "unsupported-public-request"
        }
        .into(),
    };
    let cell = ProductKey {
        target: target.into(),
        channel: "candidate-native".into(),
    };
    let cli_sha = sha256(b"selected-vector-cli");
    let agent_sha = sha256(b"selected-vector-agent");
    let fixture_sha = sha256(b"selected-vector-fixture");
    let executable = if nul {
        fixture_sha.clone()
    } else {
        cli_sha.clone()
    };
    let status = if nul { 0 } else { 125 };
    write("cli.bin", b"selected-vector-cli");
    write("agent.bin", b"selected-vector-agent");
    write("fixture.bin", b"selected-vector-fixture");
    write("source.tar", b"selected source vector");
    write("manifest.json", b"selected runtime manifest vector");
    let manifest = sha256(b"selected runtime manifest vector");
    let provider = json!({"generation":format!("{version}:{source}"),"source_commit":source,"runtime_manifest_sha256":manifest});
    write("case/stdout.bin", b"");
    write("case/stderr.bin", b"unsupported contract\n");
    write("challenge.bin", &[7; 32]);
    let environment = serde_json::to_vec(&NativeEnvironment::WindowsUtf16(
        if mutation == Some("ambient-environment") {
            vec![WindowsEnvironmentVariable {
                name: "OWNED_VECTOR".encode_utf16().collect(),
                value: "unexpected".encode_utf16().collect(),
            }]
        } else {
            Vec::new()
        },
    ))
    .unwrap();
    write("environment.json", &environment);
    let arguments = if nul {
        [
            "consumer-readiness-windows",
            "argv-nul-refusal",
            "C:\\owned\\fixture.exe",
            "C:\\owned\\contract.json",
            "C:\\owned\\result.json",
        ]
        .iter()
        .map(|argument| argument.encode_utf16().collect())
        .collect::<Vec<_>>()
    } else {
        [
            "+4GiB",
            "+600s",
            "--workload-contract",
            "C:\\owned\\contract.json",
            "--report-format",
            "result-v1",
            "--report",
            "C:\\owned\\result.json",
            "--",
            "C:\\owned\\fixture.exe",
            "consumer-readiness-windows",
            "C:\\owned\\input.json",
        ]
        .iter()
        .map(|argument| argument.encode_utf16().collect())
        .collect::<Vec<_>>()
    };
    let mut invocation = NativeInvocation {
        format: "memcordon.consumer-readiness.invocation".into(),
        revision: 1,
        arguments: NativeArguments::WindowsUtf16(arguments.clone()),
        executable_sha256: executable.clone(),
        environment: "environment.json".into(),
        environment_sha256: sha256(&environment),
        association_sha256: String::new(),
        budget_tokens: if nul {
            Vec::new()
        } else {
            vec![
                BudgetToken {
                    kind: "memory".into(),
                    token: "+4GiB".into(),
                },
                BudgetToken {
                    kind: "time".into(),
                    token: "+600s".into(),
                },
            ]
        },
        memory_token: if nul { None } else { Some("+4GiB".into()) },
        deadline_token: if nul { None } else { Some("+600s".into()) },
    };
    invocation.association_sha256 = reconstruct_invocation_sha256(&invocation).unwrap();
    write("invocation.json", &serde_json::to_vec(&invocation).unwrap());
    let (_, mut contract, _, _, _) = vectors();
    contract["requirements"] = json!([{"kind":"tcp","id":"owned-tcp","family":"v4","operations":["create","bind","listen","accept","stream-read","stream-write"],
        "scope":"host-shared-loopback","local_ports":{"kind":"kernel-assigned"},"peer":{"kind":"exact-address","endpoint":{"family":"v4","address":[127,0,0,1],"port":1}}},
        {"kind":"tcp","id":"owned-tcp-client","family":"v4","operations":["create","connect","stream-read","stream-write"],"scope":"host-shared-loopback",
        "local_ports":{"kind":"kernel-assigned"},"peer":{"kind":"same-attempt-endpoint","endpoint":"owned-listener"}}]);
    contract["endpoints"] = json!([{"id":"owned-listener","requirement":"owned-tcp"}]);
    write("contract.json", &serde_json::to_vec(&contract).unwrap());
    let native_contract: memcordon_core::workload_contract::WorkloadContractV1 =
        serde_json::from_value(contract.clone()).unwrap();
    let memory = memcordon_core::RequestedMemoryPolicyReport {
        limit_bytes: 4 * 1024 * 1024 * 1024,
        enforcement: "aggregate".into(),
        metric: "private-bytes".into(),
        poll_interval_ms: 100,
        swap: memcordon_core::SwapReport::Host,
    };
    let deadline = memcordon_core::DeadlinePolicyReport {
        duration_ms: 600000,
        scope: memcordon_core::DeadlineScope::Attempt,
        origin: None,
        clock: "monotonic".into(),
    };
    let policy=memcordon_core::PolicyEnvelopeReport {requested:memcordon_core::RequestedPolicyReport {
        workload:memcordon_core::workload_evidence::WorkloadRequestReport::from_contract(Some(&native_contract)),boundary:memcordon_core::BoundaryRequirement::Standard,
        memory:Some(memory.clone()),deadline:Some(deadline.clone()),wait_for:"workload".into(),signal_grace_ms:0,command_exit_grace_ms:0,limit_grace_ms:0,
        restart:memcordon_core::RequestedRestartPolicyReport {enabled:false,enablement_source:None,configured_conditions:memcordon_core::RestartConditions::default(),limit:memcordon_core::RestartLimit::Unlimited,backoff:None,circuit_breaker:None}},
        effective:memcordon_core::EffectivePolicyReport {workload:memcordon_core::workload_evidence::RuntimeWorkloadResolution::unresolved(Some(&native_contract),memcordon_core::workload_evidence::BaselineRestrictionObservationV1::UnmanagedStandardBackend),
            boundary:memcordon_core::BoundaryClass::Standard,memory:None,deadline:None,wait_for:"workload".into(),signal_grace_ms:0,command_exit_grace_ms:0,limit_grace_ms:0,
            restart:memcordon_core::EffectiveRestartPolicyReport {enabled:false,conditions:memcordon_core::RestartConditions::default(),dormant_conditions:Vec::new(),cleanup_proof_required:false}},effects:Vec::new()};
    let mut result = json!({"format":"memcordon.result","revision":1,"tool":{"name":"memcordon","version":version,"os":"windows","architecture":"x86_64","runtime_features":["sealed-runtime"]},
        "invocation":{"association_sha256":invocation.association_sha256,"requested_memory":memory,"requested_deadline":deadline,"applied_memory":null,"applied_deadline":null},"policy":policy,"attempts":[],"supervision":null,
        "error":{"code":"MCUNSUPPORTED-WORKLOAD-CONTRACT","category":"unsupported","message":"strict workload admission requires a sealed provider","os_code":null,"attempt_number":null,"supervision_phase":null,"launch_phase":null,
            "target_released":false,"workload_may_be_alive":false,"boundary_setup_failure":null,"provider_rejection":null,"provider_failure":null},
        "backend":null,"authorization":"not-required-for-standard","launch":{"state":"not-created","target_pid":null},
        "outcome":{"kind":"launch-failure","wrapper_status":125,"native_termination":null},"cleanup":{"state":"complete","direct_child_reaped":false,"workload_empty":true,"outstanding":[],"failed_operations":[]},
        "restart":null,"runtime":{"kind":"standard","observation":null},"private_execution":null,"private_rejection":null,"diagnostics":null,"provider_association":null,
        "delivery":{"prepared-by":{"writer_pid":123}}});
    memcordon_core::ResultV1::parse(&serde_json::to_vec(&result).unwrap())
        .expect("baseline is an actual valid native V1 standard refusal");
    if nul {
        result = json!({"format":"memcordon.windows-native-argv-refusal","revision":1,"argument_utf16":[97,0,98],"code":"MCSEALED-WINDOWS-REQUEST","category":"Usage",
        "target_pid":null,"target_released":false,"provider_association":null,"detail":"argument contains NUL"});
    }
    let mut frontend = json!({"format":"memcordon.windows-native-refusal-frontend","revision":1,"process_id":123,"creation_time_100ns":500,
        "image_sha256":executable,"held_before_wait":true,"native_wait_completed":true,"native_status":status,"stdout_sha256":sha256(b""),"stderr_sha256":sha256(b"unsupported contract\n")});
    match mutation {
        Some("frontend-birth") => frontend["creation_time_100ns"] = json!(0),
        Some("frontend-writer") => frontend["process_id"] = json!(124),
        Some("sealed-authorization") => result["authorization"] = json!("rejected-before-release"),
        Some("completed-target") => result["outcome"]["kind"] = json!("completed"),
        Some("capture-bytes") => frontend["stderr_sha256"] = json!(sha256(b"unrelated failure")),
        Some("nul-argument") => result["argument_utf16"] = json!([97, 98]),
        Some("nul-release") => result["target_released"] = json!(true),
        _ => {}
    }
    write("case/result.json", &serde_json::to_vec(&result).unwrap());
    write("frontend.json", &serde_json::to_vec(&frontend).unwrap());
    let program = "C:\\Program Files\\MemCordon\\agent.exe"
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut slots = Vec::new();
    for ordinal in 0..8 {
        let name = format!("MemCordonSealedGuardian-{ordinal:03}");
        let command = memcordon_core::encode_windows_command_line(&[
            program.clone(),
            "windows-guardian-service".encode_utf16().collect(),
            name.encode_utf16().collect(),
        ]);
        let account = "LocalSystem".encode_utf16().collect::<Vec<_>>();
        let mut encoded = Vec::new();
        for value in [16u32, 3, 1] {
            encoded.extend_from_slice(&value.to_le_bytes());
        }
        for value in [&command, &account] {
            encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
            for unit in value {
                encoded.extend_from_slice(&unit.to_le_bytes());
            }
        }
        slots.push(json!({"service_name":name,"configuration_sha256":sha256(&encoded),"configuration":{"service_type":16,"start_type":3,"error_control":1,"binary_path_utf16":command,"service_start_name_utf16":account},
            "service_type":16,"current_state":1,"process_id":0,"controls_accepted":0,"win32_exit_code":0,"service_specific_exit_code":0,"checkpoint":0,"wait_hint":0,"service_flags":0}));
    }
    if mutation == Some("live-guardian") {
        slots[0]["current_state"] = json!(4);
    }
    write("guardian.json",&serde_json::to_vec(&json!({"format":"memcordon.windows-native-guardian-quiescence","revision":1,"image_sha256":agent_sha,"runtime_manifest_sha256":manifest,"slots":slots})).unwrap());
    write("quiescence.json",&serde_json::to_vec(&json!({"format":"memcordon.windows-native-refusal-quiescence","revision":1,"provider":provider,"installed_agent_sha256":agent_sha,"runtime_manifest_sha256":manifest,
        "guardian_native_quiescence":true,"fixture_processes_absent":true,"owned_policy_restoration_required":false,"owned_policy_restoration_completed":false})).unwrap());
    write("readback.json",&serde_json::to_vec(&json!({"binaries":[{"binary":"memcordon-sealed-agent","sha256":agent_sha,"path":String::from_utf16(&program).unwrap()}]})).unwrap());
    let journal = InstalledLifecycleJournal {
        format: "memcordon.consumer-readiness.lifecycle-journal".into(),
        revision: 1,
        run_id: "vector-run".into(),
        lease_id: "vector-lease".into(),
        key: cell.clone(),
        source_commit: source.clone(),
        source_tree_sha256: tree.clone(),
        events: vec![InstalledLifecycleEvent {
            sequence: 1,
            phase: "upgrade".into(),
            operation: "actual-installed-package-readback".into(),
            succeeded: true,
            native_receipt: "readback.json".into(),
        }],
    };
    write("journal.json", &serde_json::to_vec(&journal).unwrap());
    let mut native:NativeObservation=serde_json::from_value(json!({"format":"memcordon.consumer-readiness.native","revision":1,"run_id":"vector-run","lease_id":"vector-lease","target":target,
        "executable_sha256":executable,"invocation_sha256":invocation.association_sha256,"held_processes":[],"frontend_status":status,"origin":"admission_refusal",
        "authenticated_provider_exchange":false,"relay_complete":true,"result_named_identity_verified":true,"result_readback_verified":true})).unwrap();
    if mutation == Some("provider-authority") {
        native.provider_sha256 = Some(agent_sha.clone());
    }
    write("native.json", &serde_json::to_vec(&native).unwrap());
    let mut retired:RetirementObservation=serde_json::from_value(json!({"format":"memcordon.consumer-readiness.retirement","revision":1,"run_id":"vector-run","target_reaped_or_absent":true,"aggregate_empty":true,
        "relays_retired":false,"guardian_retired":false,"native_handles_closed":false,"independently_observed":true,"outstanding":[],"failed_operations":[]})).unwrap();
    if mutation == Some("invented-handle-closure") {
        retired.native_handles_closed = true;
    }
    if mutation == Some("retirement-header") {
        retired.revision = 2;
    }
    write("retirement.json", &serde_json::to_vec(&retired).unwrap());
    let refusal = if nul {
        json!({"kind":"native-argument","receipt":"case/result.json","quiescence":"quiescence.json","guardian_quiescence":"guardian.json","frontend":"frontend.json"})
    } else {
        json!({"kind":"unsupported-public-request","quiescence":"quiescence.json","guardian_quiescence":"guardian.json","frontend":"frontend.json"})
    };
    let mut semantic:SemanticObservation=serde_json::from_value(json!({"format":"memcordon.consumer-readiness.semantic","revision":1,"run_id":"vector-run","key":key,"challenge":"challenge.bin",
        "operations":[{"operation":if nul {"argv-nul-rejected"}else{"admission-refused"},"attempt_id":null,"root_pid":null,"observer":"owned-native-preauthorization","native_receipt":"case/result.json"}],"comparisons":[],"counters":{},
        "windows_refusal":refusal})).unwrap();
    if mutation == Some("semantic-header") {
        semantic.format = "unknown-semantic".into();
    }
    write("semantic.json", &serde_json::to_vec(&semantic).unwrap());
    let mut input = FixtureInput {
        format: "memcordon.consumer-readiness.input".into(),
        revision: 1,
        run_id: "vector-run".into(),
        key: key.clone(),
        challenge_sha256: sha256(&[7; 32]),
        binary: Vec::new(),
        target_argv: NativeArguments::WindowsUtf16(arguments),
        deadline_millis: if nul { None } else { Some(600000) },
        memory_bytes: if nul {
            None
        } else {
            Some(4 * 1024 * 1024 * 1024)
        },
        toolchain_identity: None,
    };
    if mutation == Some("input-challenge") {
        input.challenge_sha256 = sha256(&[8; 32]);
    }
    let input = serde_json::to_vec(&input).unwrap();
    write("input.json", &input);
    let evidence:CaseEvidence=serde_json::from_value(json!({"format":"memcordon.consumer-readiness.case","revision":1,"key":key,"run_id":"vector-run","source_commit":source,"source_tree_sha256":tree,
        "lease_id":"vector-lease","fixture":"fixture.bin","fixture_source":"source.tar","fixture_sha256":fixture_sha,"fixture_source_sha256":sha256(b"selected source vector"),"input":"input.json","input_sha256":sha256(&input),
        "invocation":"invocation.json","request":"contract.json","raw_result":"case/result.json","native_observation":"native.json","retirement":"retirement.json","semantic_observation":"semantic.json"})).unwrap();
    write("case.json", &serde_json::to_vec(&evidence).unwrap());
    let product:ProductObservation=serde_json::from_value(json!({"key":cell,"source_commit":source,"source_tree_sha256":tree,"version":version,"host":{"kernel":"windows","native_target":target,"executable_target":target,
        "emulated":false,"toolchain_identity":"vector","toolchain_sha256":"1".repeat(64),"lockfile_sha256":"2".repeat(64)},"features":["windows-sealed-runtime"],"components":[{"role":"public-cli","artifact":"cli.bin","installed_sha256":cli_sha},{"role":"sealed-agent","artifact":"agent.bin","installed_sha256":agent_sha}],
        "materialization":"vector","runtime_manifest":"manifest.json","package_sha256":"3".repeat(64),"request_revision":1,"result_revision":1,"runtime_profile":"windows-host-network-external",
        "lifecycle":{"lease_id":"vector-lease","journal":"journal.json","receipt":"journal.json","journal_before_mutation":true,"installed_verified":true,"all_cases_inside_lease":true,"explicit_finalization":true,"finalization_records":1,
            "package_absent":true,"policy_retired":true,"native_resources_retired":true,"cleanup_failures":[],"outstanding":[],"predecessor_version":"vector-old","predecessor_package_sha256":"4".repeat(64)}})).unwrap();
    let record = CaseRecord {
        key,
        run_id: "vector-run".into(),
        state: CaseState::Passed,
        reason: None,
        evidence: Some("case.json".into()),
    };
    let index = EvidenceIndex {
        format: "memcordon.consumer-readiness.index".into(),
        revision: 1,
        profile: "decoder-vector".into(),
        run_id: "vector-run".into(),
        repository: None,
        source_commit: source,
        source_tree_sha256: tree,
        version: version.into(),
        manifest_sha256: "5".repeat(64),
        products: vec![product],
        component_builds: Vec::new(),
        workflow_cells: Vec::new(),
        fixture_cases: Vec::new(),
        artifacts,
        records: vec![record.clone()],
        producer_origins: Vec::new(),
        job_outcomes: Vec::new(),
        assessment_failures: Vec::new(),
    };
    (root, index, record)
}

// These persisted declared vectors exercise the production context branch;
// they do not represent native Windows execution or installed qualification.
#[test]
fn persisted_authenticated_four_refusals_reject_input_and_native_reassociation() {
    use memcordon_readiness_verifier::windows_acceptance::validate_authenticated_case;
    for scenario in [
        "admission-refusal",
        "stale-policy-epoch",
        "revoked-grant",
        "wrong-authorized-caller",
    ] {
        let (root, index, record) = authenticated_refusal_case(scenario, None);
        validate_authenticated_case(&index, &record, root.path()).unwrap();
        for mutation in [
            "input-argv",
            "input-budget",
            "request-nonce",
            "frontend-writer",
            "source-provider",
            "unknown-semantic",
        ] {
            let (root, index, record) = authenticated_refusal_case(scenario, Some(mutation));
            assert!(
                validate_authenticated_case(&index, &record, root.path()).is_err(),
                "{scenario}/{mutation}"
            );
        }
    }
}

fn authenticated_refusal_case(
    scenario: &str,
    mutation: Option<&str>,
) -> (
    tempfile::TempDir,
    memcordon_readiness_verifier::EvidenceIndex,
    memcordon_readiness_verifier::CaseRecord,
) {
    use memcordon_readiness_verifier::*;
    let (root, mut index, mut record) = preprovider_refusal_case(false, None);
    record.key.family = if scenario == "admission-refusal" {
        "W-STATUS"
    } else {
        "W-BINDING"
    }
    .into();
    record.key.scenario = scenario.into();
    let read = |path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(root.path().join(path)).unwrap()).unwrap()
    };
    let mut replacements = std::collections::BTreeMap::<String, Value>::new();
    let (policy, mut baseline, mut prior, prior_activation, activation) = vectors();
    let original_contract = read("contract.json");
    for field in ["requirements", "endpoints"] {
        baseline[field] = original_contract[field].clone();
        prior[field] = original_contract[field].clone();
    }
    let changes_policy = ["revoked-grant", "wrong-authorized-caller"].contains(&scenario);
    let mut changed = policy.clone();
    if scenario == "revoked-grant" {
        changed["grants"][0]["enabled"] = json!(false);
    }
    if scenario == "wrong-authorized-caller" {
        changed["grants"][0]["callers"] = json!([{"platform":"windows","sid":"S-1-5-19"}]);
    }
    let mut applied = activation.clone();
    applied["registry"] = changed.clone();
    applied["registry_digest"] =
        json!(windows_acceptance::windows_registry_digest(&changed).unwrap());
    applied["epoch"]["revision"] = json!(3);
    let mut restored = activation.clone();
    restored["epoch"]["revision"] = json!(4);
    let mut requested = if changes_policy {
        baseline.clone()
    } else {
        prior.clone()
    };
    if changes_policy {
        requested["expected_epoch"] = applied["epoch"].clone();
    }
    let provider = read("quiescence.json")["provider"].clone();
    let agent = index.products[0]
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .unwrap()
        .installed_sha256
        .clone();
    let cli = index.products[0]
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .unwrap()
        .installed_sha256
        .clone();
    let agent_path = "C:\\Program Files\\MemCordon\\agent.exe";
    let output = "C:\\owned";
    let selected_artifact = |path: &str, hash: &str| json!({"path":path,"sha256":hash});
    let selected_cli = selected_artifact("C:\\owned\\memcordon.exe", &cli);
    let selected_agent = selected_artifact(agent_path, &agent);
    let selected_fixture = selected_artifact(
        "C:\\owned\\fixture.exe",
        &sha256(b"selected-vector-fixture"),
    );
    let installed_components = json!([
        selected_agent,
        selected_artifact("C:\\owned\\bootstrap.exe", &"8".repeat(64)),
        selected_artifact("C:\\owned\\broker.exe", &"9".repeat(64))
    ]);
    let mut components = installed_components.clone();
    components
        .as_array_mut()
        .unwrap()
        .push(selected_cli.clone());
    replacements.insert("lifetime/selected-current.json".into(),json!({"channel":"candidate-native","source_commit":index.source_commit,"version":index.version,"target":record.key.target,
        "artifacts":[selected_cli.clone(),selected_agent.clone(),selected_fixture.clone()],"cli":selected_cli,"agent":selected_agent,"components":components,"installed_components":installed_components,
        "fixture":selected_fixture,"installed_agent":selected_agent,"installed_manifest":selected_artifact("C:\\owned\\runtime-manifest.json",provider["runtime_manifest_sha256"].as_str().unwrap()),"provider":provider,"output_directory":output}));
    replacements.insert("lifetime/journal.json".into(), read("journal.json"));
    index.products[0].lifecycle.journal = "lifetime/journal.json".into();
    index.products[0].lifecycle.receipt = "lifetime/journal.json".into();
    let mut invocation: NativeInvocation = serde_json::from_value(read("invocation.json")).unwrap();
    let argv = [
        "C:\\owned\\fixture.exe",
        "consumer-readiness-windows",
        "C:\\owned\\input.json",
    ];
    let units = argv
        .iter()
        .map(|value| value.encode_utf16().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    invocation.arguments = NativeArguments::WindowsUtf16(units.clone());
    invocation.association_sha256 = reconstruct_invocation_sha256(&invocation).unwrap();
    let nonce = hex::encode([3u8; 16]);
    let attempt = "e".repeat(64);
    let request = json!({"schema_version":3,"restart_attempt":0,"expected_provider_binding":provider,"workload_contract":requested,
        "nonce":nonce,"command":{"program":units[0],"arguments":units[1..]},"environment":[],"current_directory":output.encode_utf16().collect::<Vec<_>>(),
        "policy":{"memory_limit_bytes":4u64*1024*1024*1024,"absolute_deadline_millis":123456,"lifetime":"workload","poll_interval_millis":100,"signal_grace_millis":0,"command_exit_grace_millis":0,"limit_grace_millis":0}});
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let request_sha = sha256(&request_bytes);
    let mut result = read("case/result.json");
    result["invocation"]["association_sha256"] = json!(invocation.association_sha256);
    result["authorization"] = json!("rejected-before-release");
    result["outcome"]["kind"] = json!("provider-failure");
    result["runtime"] =
        json!({"kind":"unavailable","reason":"no operational runtime observation available"});
    let typed_prior: memcordon_core::workload_contract::WorkloadContractV1 =
        serde_json::from_value(requested.clone()).unwrap();
    result["policy"]["requested"]["workload"] = serde_json::to_value(
        memcordon_core::workload_evidence::WorkloadRequestReport::from_contract(Some(&typed_prior)),
    )
    .unwrap();
    result["policy"]["requested"]["boundary"] = json!("sealed");
    result["policy"]["effective"]["boundary"] = json!("unavailable");
    result["policy"]["effective"]["workload"]=serde_json::to_value(memcordon_core::workload_evidence::RuntimeWorkloadResolution::unresolved(Some(&typed_prior),
        memcordon_core::workload_evidence::BaselineRestrictionObservationV1::WindowsNetworkExternallyGoverned)).unwrap();
    result["provider_association"] =
        json!({"provider":provider,"attempt_id":attempt,"request_sha256":request_sha});
    result["error"] = json!({"category":"setup","code":"MCSEALED-PROVIDER-REJECTION","message":"provider refused admission","os_code":null,"attempt_number":null,"supervision_phase":null,"launch_phase":null,
        "target_released":false,"workload_may_be_alive":false,"boundary_setup_failure":null,"provider_rejection":null,"provider_failure":null,
        "windows_provider_rejection_v2":{"schema_version":2,"code":"MCSEALED-POLICY-ADMISSION","phase":"provider-connection","detail":"exact caller workload admission was rejected before target allocation","os_code":null,
            "target_created":false,"target_released":false,"cleanup_attempted":false,"restart_safety":{"direct_child_reaped":false,"workload_empty":null,"helpers_reaped":false,"containment_removed":false,"containment_incapable_of_live_members":false,"sealed_boundary_retired":false,"errors":[]},
            "disposition":{"disposition":"preauthorization","terminal_ack_required":false},"workload_admission":{"request":{"request_digest":windows_acceptance::windows_contract_digest(&requested).unwrap(),
                "workload_plan_digest":requested["workload_plan_digest"],"profile":requested["authorized_profile"],"authorization":requested["authorization"],"epoch":requested["expected_epoch"]},
                "rejection":{"code":if changes_policy{"profile-not-authorized"}else{"policy-epoch-stale"},"conflicts":[],"remaining_conflicts":0}}}});
    memcordon_core::ResultV1::parse(&serde_json::to_vec(&result).unwrap())
        .expect("authenticated baseline must be an actual valid native V1 refusal before mutation");
    let mut native = read("native.json");
    native["authenticated_provider_exchange"] = json!(true);
    native["provider_sha256"] = json!(agent);
    native["runtime_manifest_sha256"] = provider["runtime_manifest_sha256"].clone();
    native["provider_generation"] = provider["generation"].clone();
    native["attempt_id"] = json!(attempt);
    native["attempt_nonce"] = json!(nonce);
    native["request_sha256"] = json!(request_sha);
    native["invocation_sha256"] = json!(invocation.association_sha256);
    let mut retired = read("retirement.json");
    retired["attempt_id"] = json!(attempt);
    let mut input = read("input.json");
    input["key"] = serde_json::to_value(&record.key).unwrap();
    input["target_argv"] = serde_json::to_value(&invocation.arguments).unwrap();
    let mut semantic = read("semantic.json");
    semantic["key"] = serde_json::to_value(&record.key).unwrap();
    semantic["operations"][0]["attempt_id"] = json!(attempt);
    semantic["windows_refusal"] = json!({"kind":"authenticated-admission","provider_request":"provider-request.json","requested_contract":"contract.json","quiescence":"quiescence.json","guardian_quiescence":"guardian.json","frontend":"frontend.json",
        "baseline_policy":"baseline-policy.json","baseline_contract":"baseline-contract.json","prior_contract":"prior-contract.json","prior_activation":"prior-activation.json","prior_invocation":"prior-invocation.json","prior_exit":"prior-exit.json","prior_stderr":"case/stderr.bin","baseline_activation":"baseline-activation.json",
        "policy_apply":if changes_policy{Some("policy-apply.json")}else{None},"policy_restore":if changes_policy{Some("policy-restore.json")}else{None}});
    if changes_policy {
        replacements.insert("policy-apply.json".into(), applied);
        replacements.insert("policy-restore.json".into(), restored);
        let mut quiet = read("quiescence.json");
        quiet["owned_policy_restoration_required"] = json!(true);
        quiet["owned_policy_restoration_completed"] = json!(true);
        replacements.insert("quiescence.json".into(), quiet);
    }
    let prior_command = json!({"format":"memcordon.windows-policy-activation-command","revision":1,"agent_sha256":agent,"program_utf16":agent_path.encode_utf16().collect::<Vec<_>>(),
        "argv_utf16":(["package","policy","apply","--file","C:\\owned\\windows-local-policy.json"].iter().map(|value|value.encode_utf16().collect::<Vec<_>>()).collect::<Vec<_>>()),
        "cwd_utf16":output.encode_utf16().collect::<Vec<_>>(),"environment_cleared":true,"budget_millis":30000,"policy_sha256":sha256(&serde_json::to_vec(&policy).unwrap())});
    let prior_exit = json!({"format":"memcordon.windows-policy-activation-exit","revision":1,"invocation_sha256":sha256(&serde_json::to_vec(&prior_command).unwrap()),"status":0,"success":true,
        "stdout_sha256":sha256(&serde_json::to_vec(&prior_activation).unwrap()),"stderr_sha256":sha256(b"unsupported contract\n")});
    match mutation {
        Some("input-argv") => {
            input["target_argv"] =
                serde_json::to_value(NativeArguments::WindowsUtf16(vec![vec![97]])).unwrap()
        }
        Some("input-budget") => input["memory_bytes"] = json!(1),
        Some("request-nonce") => native["attempt_nonce"] = json!(hex::encode([4u8; 16])),
        Some("frontend-writer") => result["delivery"]["prepared-by"]["writer_pid"] = json!(999),
        Some("source-provider") => native["provider_generation"] = json!("unrelated"),
        Some("unknown-semantic") => semantic["format"] = json!("unrelated"),
        _ => {}
    }
    for (path, value) in [
        ("invocation.json", serde_json::to_value(invocation).unwrap()),
        ("contract.json", requested),
        ("case/result.json", result),
        ("native.json", native),
        ("retirement.json", retired),
        ("semantic.json", semantic),
        ("input.json", input.clone()),
        ("provider-request.json", request),
        ("baseline-policy.json", policy),
        ("baseline-contract.json", baseline),
        ("prior-contract.json", prior),
        ("prior-activation.json", prior_activation),
        ("prior-invocation.json", prior_command),
        ("prior-exit.json", prior_exit),
        ("baseline-activation.json", activation),
    ] {
        replacements.insert(path.into(), value);
    }
    let mut evidence = read("case.json");
    evidence["key"] = serde_json::to_value(&record.key).unwrap();
    evidence["provider_request"] = json!("provider-request.json");
    evidence["input_sha256"] = json!(sha256(&serde_json::to_vec(&input).unwrap()));
    replacements.insert("case.json".into(), evidence);
    for (path, value) in replacements {
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::create_dir_all(root.path().join(&path).parent().unwrap()).unwrap();
        std::fs::write(root.path().join(&path), &bytes).unwrap();
        let artifact = Artifact {
            path: path.clone(),
            length: bytes.len() as u64,
            sha256: sha256(&bytes),
        };
        if let Some(existing) = index.artifacts.iter_mut().find(|entry| entry.path == path) {
            *existing = artifact;
        } else {
            index.artifacts.push(artifact);
        }
    }
    index.records = vec![record.clone()];
    (root, index, record)
}

#[test]
fn independent_registry_codec_matches_actual_owned_mutations() {
    use memcordon_readiness_verifier::windows_acceptance::windows_registry_digest;
    let (baseline, _, _, _, _) = vectors();
    let mut disabled = baseline.clone();
    disabled["grants"][0]["enabled"] = json!(false);
    let mut wrong = baseline.clone();
    wrong["grants"][0]["callers"] = json!([{"platform":"windows","sid":"S-1-5-19"}]);
    for registry in [&baseline, &disabled, &wrong] {
        let native: memcordon_core::workload_registry::RuntimePolicyRegistry =
            serde_json::from_value(registry.clone()).unwrap();
        assert_eq!(
            windows_registry_digest(registry).unwrap(),
            String::from(native.canonical_digest().unwrap())
        );
    }
    assert_ne!(
        windows_registry_digest(&baseline).unwrap(),
        windows_registry_digest(&disabled).unwrap()
    );
    let mut widened = baseline;
    widened["grants"][0]["approved_plans"]
        .as_array_mut()
        .unwrap()
        .push(json!("c".repeat(64)));
    assert!(windows_registry_digest(&widened).is_err());
}

#[test]
fn native_guardian_census_rejects_live_slot_and_configuration_reassociation() {
    use memcordon_readiness_verifier::{sha256, windows_acceptance::validate_guardian_quiescence};
    let program = "C:\\Program Files\\MemCordon\\agent.exe"
        .encode_utf16()
        .collect::<Vec<_>>();
    let image = "a".repeat(64);
    let manifest = "b".repeat(64);
    let mut slots = Vec::new();
    for ordinal in 0..8 {
        let name = format!("MemCordonSealedGuardian-{ordinal:03}");
        let command = memcordon_core::encode_windows_command_line(&[
            program.clone(),
            "windows-guardian-service".encode_utf16().collect(),
            name.encode_utf16().collect(),
        ]);
        let account = "LocalSystem".encode_utf16().collect::<Vec<_>>();
        let mut encoded = Vec::new();
        for value in [16u32, 3, 1] {
            encoded.extend_from_slice(&value.to_le_bytes());
        }
        for value in [&command, &account] {
            encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
            for unit in value {
                encoded.extend_from_slice(&unit.to_le_bytes());
            }
        }
        slots.push(json!({"service_name":name,"configuration_sha256":sha256(&encoded),
            "configuration":{"service_type":16,"start_type":3,"error_control":1,
                "binary_path_utf16":command,"service_start_name_utf16":account},
            "service_type":16,"current_state":1,"process_id":0,"controls_accepted":0,
            "win32_exit_code":0,"service_specific_exit_code":0,"checkpoint":0,"wait_hint":0,"service_flags":0}));
    }
    let receipt = json!({"format":"memcordon.windows-native-guardian-quiescence","revision":1,
        "image_sha256":image,"runtime_manifest_sha256":manifest,"slots":slots});
    validate_guardian_quiescence(&receipt, &image, &manifest, &program).unwrap();
    for (field, value) in [
        ("current_state", json!(4)),
        ("process_id", json!(42)),
        ("configuration_sha256", json!("c".repeat(64))),
        ("service_name", json!("MemCordonSealedGuardian-001")),
    ] {
        let mut changed = receipt.clone();
        changed["slots"][0][field] = value;
        assert!(validate_guardian_quiescence(&changed, &image, &manifest, &program).is_err());
    }
    let mut absent = receipt.clone();
    absent["slots"].as_array_mut().unwrap().pop();
    assert!(validate_guardian_quiescence(&absent, &image, &manifest, &program).is_err());
    let mut account = receipt.clone();
    account["slots"][0]["configuration"]["service_start_name_utf16"] =
        json!("Other".encode_utf16().collect::<Vec<_>>());
    assert!(validate_guardian_quiescence(&account, &image, &manifest, &program).is_err());
}

#[test]
fn admission_refusal_retains_exact_cause_and_actual_request_binding() {
    use memcordon_readiness_verifier::windows_acceptance::{
        validate_admission_refusal_cause, windows_contract_digest,
    };
    let (_, mut contract, _, _, _) = vectors();
    contract["requirements"] = json!([{"kind":"tcp","id":"owned-tcp","family":"v4",
        "operations":["create","bind","listen","accept","stream-read","stream-write"],
        "scope":"host-shared-loopback","local_ports":{"kind":"kernel-assigned"},
        "peer":{"kind":"exact-address","endpoint":{"family":"v4","address":[127,0,0,1],"port":1}}},
        {"kind":"tcp","id":"owned-tcp-client","family":"v4","operations":["create","connect","stream-read","stream-write"],
        "scope":"host-shared-loopback","local_ports":{"kind":"kernel-assigned"},
        "peer":{"kind":"same-attempt-endpoint","endpoint":"owned-listener"}}]);
    contract["endpoints"] = json!([{"id":"owned-listener","requirement":"owned-tcp"}]);
    let provider = json!({"source_commit":"c".repeat(40),"generation":"declared-generation","runtime_manifest_sha256":"d".repeat(64)});
    let attempt = "e".repeat(64);
    let request = "f".repeat(64);
    let result = json!({"authorization":"rejected-before-release",
        "runtime":{"kind":"unavailable","reason":"no operational runtime observation available"},
        "launch":{"state":"not-created","target_pid":null},
        "outcome":{"kind":"provider-failure","native_termination":null},
        "provider_association":{"provider":provider,"attempt_id":attempt,"request_sha256":request},
        "error":{"category":"setup","code":"MCSEALED-PROVIDER-REJECTION","target_released":false,
            "workload_may_be_alive":false,"windows_provider_rejection_v2":{
                "schema_version":2,"code":"MCSEALED-POLICY-ADMISSION","phase":"provider-connection",
                "detail":"exact caller workload admission was rejected before target allocation","os_code":null,
                "target_created":false,"target_released":false,"cleanup_attempted":false,
                "restart_safety":{"direct_child_reaped":false,"workload_empty":null,"helpers_reaped":false,
                    "containment_removed":false,"containment_incapable_of_live_members":false,"sealed_boundary_retired":false,"errors":[]},
                "disposition":{"disposition":"preauthorization","terminal_ack_required":false},
                "workload_admission":{"request":{"request_digest":windows_contract_digest(&contract).unwrap(),
                    "workload_plan_digest":contract["workload_plan_digest"],"profile":contract["authorized_profile"],
                    "authorization":contract["authorization"],"epoch":contract["expected_epoch"]},
                    "rejection":{"code":"policy-epoch-stale","conflicts":[],"remaining_conflicts":0}}}}});
    validate_admission_refusal_cause(
        "stale-policy-epoch",
        &result,
        &contract,
        &provider,
        &attempt,
        &request,
    )
    .unwrap();
    for pointer in [
        "/error/windows_provider_rejection_v2/target_created",
        "/error/windows_provider_rejection_v2/restart_safety/direct_child_reaped",
    ] {
        let mut mutated = result.clone();
        *mutated.pointer_mut(pointer).unwrap() = json!(true);
        assert!(
            validate_admission_refusal_cause(
                "stale-policy-epoch",
                &mutated,
                &contract,
                &provider,
                &attempt,
                &request
            )
            .is_err()
        );
    }
    let mut unrelated = result.clone();
    unrelated["error"]["windows_provider_rejection_v2"]["workload_admission"]["rejection"]["code"] =
        json!("host-prerequisite-unavailable");
    assert!(
        validate_admission_refusal_cause(
            "stale-policy-epoch",
            &unrelated,
            &contract,
            &provider,
            &attempt,
            &request
        )
        .is_err()
    );
    let mut changed = contract;
    changed["expected_epoch"]["revision"] = json!(99);
    assert!(
        validate_admission_refusal_cause(
            "stale-policy-epoch",
            &result,
            &changed,
            &provider,
            &attempt,
            &request
        )
        .is_err()
    );
}

#[test]
fn independent_windows_v1_codec_matches_native_contract_and_rejects_narrowing() {
    use memcordon_readiness_verifier::windows_acceptance::windows_contract_digest;
    let (_, mut contract, _, _, _) = vectors();
    contract["requirements"] = json!([{"kind":"tcp","id":"owned-tcp","family":"v4",
        "operations":["create","bind","listen","accept","stream-read","stream-write"],
        "scope":"host-shared-loopback","local_ports":{"kind":"kernel-assigned"},
        "peer":{"kind":"exact-address","endpoint":{"family":"v4","address":[127,0,0,1],"port":1}}},
        {"kind":"tcp","id":"owned-tcp-client","family":"v4","operations":["create","connect","stream-read","stream-write"],
        "scope":"host-shared-loopback","local_ports":{"kind":"kernel-assigned"},
        "peer":{"kind":"same-attempt-endpoint","endpoint":"owned-listener"}}]);
    contract["endpoints"] = json!([{"id":"owned-listener","requirement":"owned-tcp"}]);
    let native: memcordon_core::workload_contract::WorkloadContractV1 =
        serde_json::from_value(contract.clone()).unwrap();
    let expected = String::from(memcordon_core::workload_codec::contract_digest(&native).unwrap());
    assert_eq!(windows_contract_digest(&contract).unwrap(), expected);
    let mut cyclic = contract.clone();
    cyclic["requirements"][0]["peer"] =
        json!({"kind":"same-attempt-endpoint","endpoint":"owned-listener"});
    let cyclic_native: memcordon_core::workload_contract::WorkloadContractV1 =
        serde_json::from_value(cyclic.clone()).unwrap();
    assert!(cyclic_native.validate().is_err());
    assert!(windows_contract_digest(&cyclic).is_err());
    for field in ["requirements", "endpoints"] {
        let mut narrowed = contract.clone();
        narrowed[field] = json!([]);
        assert!(windows_contract_digest(&narrowed).is_err());
    }
    let mut changed = contract.clone();
    changed["requirements"][0]["scope"] = json!("attempt-private-stack");
    assert!(windows_contract_digest(&changed).is_err());
    let mut epoch = contract;
    epoch["expected_epoch"]["revision"] = json!(3);
    assert_ne!(windows_contract_digest(&epoch).unwrap(), expected);
}

#[test]
fn prior_native_activation_capture_reassociation_is_rejected() {
    use memcordon_readiness_verifier::{
        sha256, windows_acceptance::validate_prior_activation_command,
    };
    let program = "C:\\owned\\agent.exe".encode_utf16().collect::<Vec<_>>();
    let policy = "C:\\owned\\policy.json".encode_utf16().collect::<Vec<_>>();
    let cwd = "C:\\owned".encode_utf16().collect::<Vec<_>>();
    let policy_bytes = b"declared-policy-vector";
    let stdout = b"declared-native-stdout-vector";
    let stderr = b"declared-native-stderr-vector";
    let agent = "a".repeat(64);
    let argv = ["package", "policy", "apply", "--file"]
        .into_iter()
        .map(|argument| argument.encode_utf16().collect::<Vec<_>>())
        .chain(std::iter::once(policy.clone()))
        .collect::<Vec<_>>();
    let command = json!({"format":"memcordon.windows-policy-activation-command","revision":1,
        "agent_sha256":agent,"program_utf16":program,"argv_utf16":argv,"cwd_utf16":cwd,
        "environment_cleared":true,"budget_millis":30000,"policy_sha256":sha256(policy_bytes)});
    let bytes = serde_json::to_vec(&command).unwrap();
    let exit = json!({"format":"memcordon.windows-policy-activation-exit","revision":1,
        "invocation_sha256":sha256(&bytes),"status":0,"success":true,
        "stdout_sha256":sha256(stdout),"stderr_sha256":sha256(stderr)});
    validate_prior_activation_command(
        &bytes,
        &exit,
        stdout,
        stderr,
        &agent,
        &program,
        &policy,
        &cwd,
        policy_bytes,
    )
    .unwrap();
    assert!(
        validate_prior_activation_command(
            &bytes,
            &exit,
            stdout,
            b"changed",
            &agent,
            &program,
            &policy,
            &cwd,
            policy_bytes
        )
        .is_err()
    );
    for field in ["status", "invocation_sha256", "stdout_sha256"] {
        let mut changed = exit.clone();
        changed[field] = if field == "status" {
            json!(7)
        } else {
            json!("b".repeat(64))
        };
        assert!(
            validate_prior_activation_command(
                &bytes,
                &changed,
                stdout,
                stderr,
                &agent,
                &program,
                &policy,
                &cwd,
                policy_bytes
            )
            .is_err()
        );
    }
    let mut inherited = command.clone();
    inherited["environment_cleared"] = json!(false);
    let bytes = serde_json::to_vec(&inherited).unwrap();
    assert!(
        validate_prior_activation_command(
            &bytes,
            &exit,
            stdout,
            stderr,
            &agent,
            &program,
            &policy,
            &cwd,
            policy_bytes
        )
        .is_err()
    );
}

// Declared policy vectors exercise the independent structural rule. They do
// not represent native activation, execution, receipt custody or acceptance.
fn vectors() -> (Value, Value, Value, Value, Value) {
    let profile = serde_json::to_value(
        memcordon_core::workload_registry::BaselineProfile::WindowsHostNetworkExternal.reference(),
    )
    .unwrap();
    let ceiling = json!({"direct_socket_authority":"external-host-policy-accepted","unix_authority":"existing-host-unix-authority-accepted",
        "external_socket_custody":"existing-stdio-authority-accepted","credential_gains":"existing-caller-envelope-accepted",
        "mediated_communication":"external-filesystem-and-stdio-policy-accepted"});
    let policy = json!({"format":"memcordon.local-policy","revision":1,
        "profiles":[{"profile":"windows-host-network-external","reference":profile,"enabled":true}],
        "grants":[{"id":"windows-readiness-owned","revision":1,"profile":profile,"ceiling":ceiling,"enabled":true,
            "callers":[{"platform":"windows","sid":"S-1-5-21-1000"}],"approved_plans":["b".repeat(64)]}],
        "active_attempt_disposition":"drain-existing"});
    let contract = json!({"schema_version":1,"workload_plan_digest":"b".repeat(64),"authorized_profile":profile,
        "authorization":{"grant_id":"windows-readiness-owned","grant_revision":1,"approved_plan_digest":"b".repeat(64)},
        "ceiling":ceiling,"requirements":[],"endpoints":[],"expected_epoch":{"service_instance":vec![1u8;16],"revision":2}});
    let mut prior = contract.clone();
    prior["expected_epoch"]["revision"] = 1.into();
    let activation = json!({"format":"memcordon.local-activation","revision":1,"registry":policy,
        "registry_digest":memcordon_readiness_verifier::windows_acceptance::windows_registry_digest(&policy).unwrap(),"epoch":contract["expected_epoch"],"revoked_admissions":[]});
    let mut prior_activation = activation.clone();
    prior_activation["epoch"]["revision"] = 1.into();
    (policy, contract, prior, prior_activation, activation)
}

#[test]
fn stale_refusal_requires_exact_earlier_contract() {
    let (policy, contract, prior, prior_activation, activation) = vectors();
    validate_policy_refusal_mutation(
        "stale-policy-epoch",
        &policy,
        &contract,
        &prior,
        &prior_activation,
        &activation,
        &prior,
        None,
        None,
    )
    .unwrap();
    let mut arbitrary = prior.clone();
    arbitrary["expected_epoch"]["revision"] = 99.into();
    assert!(
        validate_policy_refusal_mutation(
            "stale-policy-epoch",
            &policy,
            &contract,
            &prior,
            &prior_activation,
            &activation,
            &arbitrary,
            None,
            None
        )
        .is_err()
    );
    let mut unrelated = prior.clone();
    unrelated["authorization"]["grant_id"] = "unrelated".into();
    assert!(
        validate_policy_refusal_mutation(
            "stale-policy-epoch",
            &policy,
            &contract,
            &unrelated,
            &prior_activation,
            &activation,
            &unrelated,
            None,
            None
        )
        .is_err()
    );
}

#[test]
fn revoked_grant_requires_exact_mutation_and_original_restoration() {
    let (policy, contract, prior, prior_activation, activation) = vectors();
    let mut changed = policy.clone();
    changed["grants"][0]["enabled"] = false.into();
    let mut apply = activation.clone();
    apply["registry"] = changed;
    apply["epoch"]["revision"] = 3.into();
    apply["registry_digest"] =
        memcordon_readiness_verifier::windows_acceptance::windows_registry_digest(
            &apply["registry"],
        )
        .unwrap()
        .into();
    let mut restore = activation.clone();
    restore["epoch"]["revision"] = 4.into();
    let mut requested = contract.clone();
    requested["expected_epoch"] = apply["epoch"].clone();
    validate_policy_refusal_mutation(
        "revoked-grant",
        &policy,
        &contract,
        &prior,
        &prior_activation,
        &activation,
        &requested,
        Some(&apply),
        Some(&restore),
    )
    .unwrap();
    let mut widened = apply.clone();
    widened["registry"]["grants"][0]["approved_plans"] = json!(["e".repeat(64)]);
    assert!(
        validate_policy_refusal_mutation(
            "revoked-grant",
            &policy,
            &contract,
            &prior,
            &prior_activation,
            &activation,
            &requested,
            Some(&widened),
            Some(&restore)
        )
        .is_err()
    );
    restore["registry"]["grants"][0]["enabled"] = false.into();
    assert!(
        validate_policy_refusal_mutation(
            "revoked-grant",
            &policy,
            &contract,
            &prior,
            &prior_activation,
            &activation,
            &requested,
            Some(&apply),
            Some(&restore)
        )
        .is_err()
    );
}

#[test]
fn wrong_caller_rejects_widened_or_reassociated_selectors() {
    let (policy, contract, prior, prior_activation, activation) = vectors();
    let mut apply = activation.clone();
    apply["registry"]["grants"][0]["callers"] = json!([{"platform":"windows","sid":"S-1-5-19"}]);
    apply["epoch"]["revision"] = 3.into();
    apply["registry_digest"] =
        memcordon_readiness_verifier::windows_acceptance::windows_registry_digest(
            &apply["registry"],
        )
        .unwrap()
        .into();
    let mut restore = activation.clone();
    restore["epoch"]["revision"] = 4.into();
    let mut requested = contract.clone();
    requested["expected_epoch"] = apply["epoch"].clone();
    validate_policy_refusal_mutation(
        "wrong-authorized-caller",
        &policy,
        &contract,
        &prior,
        &prior_activation,
        &activation,
        &requested,
        Some(&apply),
        Some(&restore),
    )
    .unwrap();
    apply["registry"]["grants"][0]["callers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"platform":"windows","sid":"S-1-5-21-1000"}));
    assert!(
        validate_policy_refusal_mutation(
            "wrong-authorized-caller",
            &policy,
            &contract,
            &prior,
            &prior_activation,
            &activation,
            &requested,
            Some(&apply),
            Some(&restore)
        )
        .is_err()
    );
}
