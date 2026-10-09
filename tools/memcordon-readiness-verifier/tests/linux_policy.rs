use memcordon_readiness_verifier::validate_linux_policy_mutation;
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn discovery_cannot_become_launch_authority_or_hide_revocation() {
    use memcordon_readiness_verifier::validate_linux_policy_discovery;
    let reference = |id: &str, byte: u8| json!({"id":id,"digest":hex::encode([byte;32])});
    let contract = json!({"schema_version":3,"workload_plan_digest":"01".repeat(32),
        "authorized_profile":{"id":"linux-tcp4-unix-private-v1","semantic_digest":"02".repeat(32)},
        "authorization":{"grant_id":"combined-grant","grant_revision":1,"approved_plan_digest":"01".repeat(32)},
        "ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain","requirements":[],
        "execution_identity":{"identity":reference("account",3),"exclusive_use_policy":reference("exclusive",4)},
        "runtime_image":reference("toolchain",5),"input_image":reference("fixture",6),"root_layout":reference("build-root",7),
        "launch":{"entrypoint":"build-driver","working_directory":"work"},"expected_epoch":{"service_instance":vec![8u8;16],"revision":1}});
    let actual: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(contract.clone()).unwrap();
    actual.validate().unwrap();
    let provider = json!({"generation":"fixture:source","source_commit":"a".repeat(40),"runtime_manifest_sha256":"b".repeat(64)});
    let pending = memcordon_core::mixed_advisory::pending_obligations();
    let plan = json!({"format":"memcordon.plan","revision":2,"provider_contract":4,"launch_wire":4,"provider":provider,
        "request":contract,"request_sha256":hex::encode(Sha256::digest(actual.canonical_bytes().unwrap())),
        "available_for_preparation":true,"conflict":null,"prerequisite_error":null,"pending":pending,"authorizes_launch":false});
    let capabilities = json!({"format":"memcordon.capabilities","revision":2,"provider_contract":4,"launch_wire":4,"provider":provider,
        "boot_identity":"native-boot","profile":contract["authorized_profile"],"request_versions":[3],"carrier_versions":[2],
        "supported":true,"installed_enabled":true,"exclusive_identity_eligible":true,"image_support":true,"plan":plan,"authorizes_launch":false});
    let values = [
        "--reuid",
        "65534",
        "--regid",
        "65534",
        "--clear-groups",
        "--",
        "/usr/libexec/memcordon",
        "doctor",
        "--json",
        "--capability-format",
        "capabilities-v2",
        "--require",
        "sealed",
        "--workload-contract",
        "/owned/discovery-contract.json",
    ];
    let command = json!({"format":"memcordon.linux-policy-discovery-invocation","revision":1,"program":b"/usr/bin/setpriv",
        "arguments":values.iter().map(|value|value.as_bytes()).collect::<Vec<_>>(),"caller_uid":65534,"caller_gid":65534,
        "environment_cleared":true,"cli_sha256":"c".repeat(64)});
    let baseline = json!({"grants":[{"enabled":true,"revision":1}]});
    let mut revoked = baseline.clone();
    revoked["grants"][0]["enabled"] = false.into();
    let activation = |revision, registry: &serde_json::Value| {
        json!({"format":"memcordon.local-private-activation","revision":2,
        "registry":registry,"registry_digest":"d".repeat(64),"epoch":{"service_instance":vec![8u8;16],"revision":revision},"revoked_admissions":[]})
    };
    let check = |caps: &serde_json::Value, revoked: &serde_json::Value, revoke_revision| {
        let stdout = serde_json::to_vec(caps).unwrap();
        let stderr = b"";
        let exit = json!({"native_exit":0,"stdout_sha256":hex::encode(Sha256::digest(&stdout)),"stderr_sha256":hex::encode(Sha256::digest(stderr))});
        validate_linux_policy_discovery(
            &command,
            &exit,
            &stdout,
            stderr,
            &contract,
            &baseline,
            &activation(1, &baseline),
            revoked,
            &activation(revoke_revision, revoked),
            &activation(3, &baseline),
            &"c".repeat(64),
            &provider,
        )
    };
    assert!(check(&capabilities, &revoked, 2).is_ok());
    assert!(check(&capabilities, &baseline, 2).is_err());
    assert!(check(&capabilities, &revoked, 1).is_err());
    for field in [
        "authorizes_launch",
        "plan.authorizes_launch",
        "plan.available_for_preparation",
        "plan.request",
        "provider",
    ] {
        let mut changed = capabilities.clone();
        match field {
            "authorizes_launch" => changed["authorizes_launch"] = true.into(),
            "plan.authorizes_launch" => changed["plan"]["authorizes_launch"] = true.into(),
            "plan.available_for_preparation" => {
                changed["plan"]["available_for_preparation"] = false.into()
            }
            "plan.request" => changed["plan"]["request"]["expected_epoch"]["revision"] = 2.into(),
            "provider" => changed["provider"]["generation"] = "other".into(),
            _ => unreachable!(),
        }
        assert!(check(&changed, &revoked, 2).is_err(), "{field}");
    }
}

#[test]
fn frontend_public_projection_preserves_actual_budget_syntax_and_argv() {
    let challenge = [7u8; 32];
    let token = hex::encode(challenge);
    let values = [
        "--reuid",
        "65534",
        "--regid",
        "65534",
        "--clear-groups",
        "--",
        "/usr/libexec/memcordon",
        "+256M",
        "+1234ms",
        "--sealed",
        "--workload-contract",
        "/owned/contract.json",
        "--report-format",
        "result-v2",
        "--report",
        "/owned/result.json",
        "--mixed-observation-directory",
        "/owned/observations",
        "--image-entrypoint",
        "owned-readiness",
        "--",
        "tcp-http",
        token.as_str(),
    ];
    let command = json!({"format":"memcordon.linux-owned-frontend-invocation","revision":1,"program":b"/usr/bin/setpriv",
        "arguments":values.iter().map(|value|value.as_bytes()).collect::<Vec<_>>(),"environment_cleared":true,
        "caller_uid":65534,"caller_gid":65534,"selected_cli_sha256":"a".repeat(64)});
    // Dev-only actual public representation comparison, not CLI execution.
    let public = memcordon_core::InvocationReport {
        syntax: "plus-budgets-v1".into(),
        budget_tokens: vec![
            memcordon_core::BudgetTokenReport {
                kind: memcordon_core::BudgetKindReport::Memory,
                token: "+256M".into(),
            },
            memcordon_core::BudgetTokenReport {
                kind: memcordon_core::BudgetKindReport::Time,
                token: "+1234ms".into(),
            },
        ],
        memory_token: Some("+256M".into()),
        deadline_token: Some("+1234ms".into()),
        argv: ["owned-readiness", "tcp-http", token.as_str()]
            .iter()
            .map(|value| memcordon_core::NativeArgument::from_os(std::ffi::OsStr::new(value)))
            .collect(),
    };
    let public = serde_json::to_value(public).unwrap();
    let check = |command: &serde_json::Value, public: &serde_json::Value| {
        memcordon_readiness_verifier::validate_linux_policy_frontend(
            command,
            public,
            &challenge,
            65534,
            &"a".repeat(64),
        )
    };
    assert!(check(&command, &public).is_ok());
    let mut changed = command.clone();
    changed["arguments"][7] = serde_json::to_value(b"256M".to_vec()).unwrap();
    assert!(check(&changed, &public).is_err());
    changed = command.clone();
    changed["environment_cleared"] = false.into();
    assert!(check(&changed, &public).is_err());
    changed = command.clone();
    changed["caller_uid"] = 65533.into();
    assert!(check(&changed, &public).is_err());
    let mut other = public.clone();
    other["budget_tokens"][1]["kind"] = "deadline".into();
    assert!(check(&command, &other).is_err());
    other = public.clone();
    other["argv"][0]["display"] = "tcp-http".into();
    assert!(check(&command, &other).is_err());
}

#[test]
fn native_activation_capture_rejects_policy_command_and_output_reassociation() {
    use memcordon_readiness_verifier::validate_linux_policy_command_capture;
    let policy = b"actual retained policy bytes";
    let stdout = b"actual native activation bytes";
    let stderr = b"actual stderr bytes";
    let hash = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let command = json!({"format":"memcordon.linux-policy-activation-command","revision":1,"agent_sha256":"a".repeat(64),
        "program":b"/usr/libexec/memcordon-sealed-agent".to_vec(),"arguments":[b"package".to_vec(),b"policy".to_vec(),b"apply".to_vec(),b"--file".to_vec(),
            b"/var/lib/memcordon-consumer-readiness/owned/policy-cases-lease/wrong-caller/activation.policy.json".to_vec()],
        "cwd":b"/owned/artifacts/wrong-caller","environment_cleared":true,"budget_millis":1000,"policy_sha256":hash(policy)});
    let bytes = serde_json::to_vec(&command).unwrap();
    let exit = json!({"format":"memcordon.linux-policy-activation-exit","revision":1,"native_exit":0,"success":true,
        "invocation_sha256":hash(&bytes),"stdout_sha256":hash(stdout),"stderr_sha256":hash(stderr)});
    let check = |command: &serde_json::Value, exit: &serde_json::Value, policy: &[u8]| {
        validate_linux_policy_command_capture(
            command,
            exit,
            &serde_json::to_vec(command).unwrap(),
            stdout,
            stderr,
            policy,
            &"a".repeat(64),
        )
    };
    assert!(check(&command, &exit, policy).is_ok());
    assert!(check(&command, &exit, b"replacement policy").is_err());
    let mut changed = exit.clone();
    changed["stderr_sha256"] = hash(b"").into();
    assert!(check(&command, &changed, policy).is_err());
    changed = exit.clone();
    changed["native_exit"] = 1.into();
    assert!(check(&command, &changed, policy).is_err());
    let mut other = command.clone();
    other["arguments"][2] = serde_json::to_value(b"recover".to_vec()).unwrap();
    changed = exit.clone();
    changed["invocation_sha256"] = hash(&serde_json::to_vec(&other).unwrap()).into();
    assert!(check(&other, &changed, policy).is_err());
    other = command.clone();
    other["arguments"][4] = serde_json::to_value(b"/tmp/foreign-policy.json".to_vec()).unwrap();
    changed = exit.clone();
    changed["invocation_sha256"] = hash(&serde_json::to_vec(&other).unwrap()).into();
    assert!(check(&other, &changed, policy).is_err());
}

#[test]
fn actual_result_shape_refuses_request_and_native_status_reassociation() {
    use memcordon_readiness_verifier::validate_linux_policy_refusal_result;
    let reference = |id: &str, byte: u8| json!({"id":id,"digest":hex::encode([byte;32])});
    let contract = json!({"schema_version":3,"workload_plan_digest":"01".repeat(32),
        "authorized_profile":{"id":"linux-tcp4-unix-private-v1","semantic_digest":"02".repeat(32)},
        "authorization":{"grant_id":"combined-grant","grant_revision":1,"approved_plan_digest":"01".repeat(32)},
        "ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain","requirements":[],
        "execution_identity":{"identity":reference("account",3),"exclusive_use_policy":reference("exclusive",4)},
        "runtime_image":reference("toolchain",5),"input_image":reference("fixture",6),"root_layout":reference("build-root",7),
        "launch":{"entrypoint":"build-driver","working_directory":"work"},"expected_epoch":{"service_instance":vec![8u8;16],"revision":1}});
    let actual: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(contract.clone()).unwrap();
    actual.validate().unwrap();
    let request = serde_json::to_vec(
        &json!({"format":"memcordon.mixed-runtime-request","revision":2,"contract":contract,
        "native_launch":[1],"attempt_deadline_millis":1}),
    )
    .unwrap();
    // Native launch interpretation and command custody are additional outer
    // obligations. This vector tests actual result and canonical request joins.
    let invocation = json!({"syntax":"plus-budgets-v1","budget_tokens":[],"memory_token":null,"deadline_token":null,"argv":[]});
    let result = json!({"format":"memcordon.result","revision":2,
        "tool":{"name":"memcordon","version":"fixture","os":"linux","architecture":"x86_64","runtime_features":["sealed-runtime","private-tcp"]},"invocation":invocation,
        "runtime":{"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,
            "outcome":{"kind":"rejected-before-authorization","request_sha256":hex::encode(Sha256::digest(actual.canonical_bytes().unwrap())),
                "request_bytes_sha256":hex::encode(Sha256::digest(&request)),"reason":"unauthorized-caller","detail":"native refusal vector",
                "allocation":{"authorization":"never-authorized","obligations":[]}}},
        "delivery":{"prepared-by":{"writer_pid":1}},"frontend":{"relay_drained":true,"interruption":null,"relay_error":null},"wrapper_status":125});
    let check = |value: &serde_json::Value, bytes: &[u8], status| {
        validate_linux_policy_refusal_result(
            value,
            bytes,
            &contract,
            &invocation,
            "fixture",
            "x86_64-unknown-linux-gnu",
            status,
            1,
            "unauthorized-caller",
        )
    };
    assert!(check(&result, &request, 125).is_ok());
    assert!(check(&result, &request, 124).is_err());
    let mut changed = result.clone();
    changed["runtime"]["outcome"]["request_sha256"] = "f".repeat(64).into();
    assert!(check(&changed, &request, 125).is_err());
    changed = result.clone();
    changed["runtime"]["outcome"]["allocation"]["obligations"] = json!(["retained-root"]);
    assert!(check(&changed, &request, 125).is_err());
    changed = result.clone();
    changed["delivery"] = "prepared".into();
    assert!(check(&changed, &request, 125).is_err());
    changed = result.clone();
    changed["delivery"]["prepared-by"]["writer_pid"] = 2.into();
    assert!(check(&changed, &request, 125).is_err());
    changed = result.clone();
    changed["tool"]["runtime_features"] = json!(["sealed-runtime"]);
    assert!(check(&changed, &request, 125).is_err());
    let mut bytes = request.clone();
    bytes.push(b' ');
    assert!(check(&result, &bytes, 125).is_err());
}

#[test]
fn stale_epoch_requires_original_activation_and_exact_restoration() {
    use memcordon_readiness_verifier::validate_linux_policy_activation_sequence;
    // Structural native-format vectors; command execution and digest custody
    // are separate required observations, not asserted by this test.
    let registry = json!({"grants":[{"enabled":true}]});
    let receipt = |revision| {
        json!({"format":"memcordon.local-private-activation","revision":2,
        "registry":registry,"registry_digest":"a".repeat(64),"epoch":{"service_instance":vec![1u8;16],"revision":revision},"revoked_admissions":[]})
    };
    let earlier = receipt(1);
    let active = receipt(2);
    let restored = receipt(3);
    let request = json!({"expected_epoch":earlier["epoch"]});
    let check = |request: &serde_json::Value,
                 restored: &serde_json::Value,
                 earlier: &[serde_json::Value]| {
        validate_linux_policy_activation_sequence(
            "wrong-epoch",
            &registry,
            &registry,
            request,
            &active,
            restored,
            earlier,
        )
    };
    assert!(check(&request, &restored, std::slice::from_ref(&earlier)).is_ok());
    let mut invented = request.clone();
    invented["expected_epoch"]["revision"] = 0.into();
    assert!(check(&invented, &restored, std::slice::from_ref(&earlier)).is_err());
    invented["expected_epoch"]["revision"] = 4.into();
    assert!(check(&invented, &restored, std::slice::from_ref(&earlier)).is_err());
    assert!(check(&request, &restored, &[]).is_err());
    let mut other_boot = earlier.clone();
    other_boot["epoch"]["service_instance"][0] = 2.into();
    assert!(check(&request, &restored, &[other_boot]).is_err());
    let mut wrong_registry = restored.clone();
    wrong_registry["registry"]["grants"][0]["enabled"] = false.into();
    assert!(check(&request, &wrong_registry, std::slice::from_ref(&earlier)).is_err());
    let mut backwards = restored.clone();
    backwards["epoch"]["revision"] = 1.into();
    assert!(check(&request, &backwards, std::slice::from_ref(&earlier)).is_err());
    let mut extra = earlier.clone();
    extra["epoch"]["generation"] = 1.into();
    assert!(check(&request, &restored, &[extra]).is_err());
}

#[test]
fn exact_policy_mutation_rejects_unrelated_data_and_refusal_reassociation() {
    // Structural fixture only: actual native activation and refusal are still
    // required by installed-case verification.
    let baseline = json!({"grants":[{"enabled":true,"revision":1,"id":"original"}],"legacy":{"keep":"unchanged"}});
    let epoch = json!({"service_instance":"current","generation":2});
    let contract = json!({"authorization":{"approved_plan_digest":"original"},"runtime_image":{"id":"original","digest":"original"},
        "authorized_profile":{"semantic_digest":"original"},"execution_identity":{"identity":{"digest":"original"}},
        "expected_epoch":{"service_instance":"original","generation":1},"preserved":"unchanged"});
    let mut request = contract.clone();
    request["expected_epoch"] = epoch.clone();
    assert!(
        validate_linux_policy_mutation(
            "wrong-caller",
            &baseline,
            &baseline,
            &contract,
            &request,
            &epoch,
            65533,
            "unauthorized-caller"
        )
        .is_ok()
    );
    assert!(
        validate_linux_policy_mutation(
            "wrong-caller",
            &baseline,
            &baseline,
            &contract,
            &request,
            &epoch,
            65534,
            "unauthorized-caller"
        )
        .is_err()
    );
    assert!(
        validate_linux_policy_mutation(
            "wrong-caller",
            &baseline,
            &baseline,
            &contract,
            &request,
            &epoch,
            65533,
            "unauthorized-image"
        )
        .is_err()
    );
    let mut changed = baseline.clone();
    changed["legacy"]["keep"] = "substituted".into();
    assert!(
        validate_linux_policy_mutation(
            "wrong-caller",
            &baseline,
            &changed,
            &contract,
            &request,
            &epoch,
            65533,
            "unauthorized-caller"
        )
        .is_err()
    );
    let mut redirected = request.clone();
    redirected["runtime_image"]["id"] = "other".into();
    assert!(
        validate_linux_policy_mutation(
            "wrong-caller",
            &baseline,
            &baseline,
            &contract,
            &redirected,
            &epoch,
            65533,
            "unauthorized-caller"
        )
        .is_err()
    );
    let mut disabled = baseline.clone();
    disabled["grants"][0]["enabled"] = false.into();
    assert!(
        validate_linux_policy_mutation(
            "disabled-grant",
            &baseline,
            &disabled,
            &contract,
            &request,
            &epoch,
            65534,
            "disabled-grant"
        )
        .is_ok()
    );
    disabled["grants"][0]["revision"] = 2.into();
    assert!(
        validate_linux_policy_mutation(
            "disabled-grant",
            &baseline,
            &disabled,
            &contract,
            &request,
            &epoch,
            65534,
            "disabled-grant"
        )
        .is_err()
    );
    assert!(
        validate_linux_policy_mutation(
            "wrong-epoch",
            &baseline,
            &baseline,
            &contract,
            &request,
            &epoch,
            65534,
            "stale-epoch"
        )
        .is_err()
    );
    assert!(
        validate_linux_policy_mutation(
            "wrong-epoch",
            &baseline,
            &baseline,
            &contract,
            &contract,
            &epoch,
            65534,
            "stale-epoch"
        )
        .is_ok()
    );
    for (scenario, reason) in [
        ("wrong-plan", "unauthorized-plan"),
        ("wrong-image", "unauthorized-image"),
        ("wrong-profile", "unauthorized-profile"),
        ("wrong-identity", "unauthorized-identity"),
        ("wrong-digest", "unauthorized-image"),
        ("changed-grant", "wrong-grant-revision"),
    ] {
        let mut requested = request.clone();
        let mut applied = baseline.clone();
        let digest = hex::encode(Sha256::digest(scenario.as_bytes()));
        match scenario {
            "wrong-plan" => {
                requested["workload_plan_digest"] = digest.clone().into();
                requested["authorization"]["approved_plan_digest"] = digest.into();
            }
            "wrong-image" => {
                requested["runtime_image"]["id"] = "owned-readiness-wrong-image".into()
            }
            "wrong-profile" => requested["authorized_profile"]["semantic_digest"] = digest.into(),
            "wrong-identity" => {
                requested["execution_identity"]["identity"]["digest"] = digest.into()
            }
            "wrong-digest" => requested["runtime_image"]["digest"] = digest.into(),
            "changed-grant" => applied["grants"][0]["revision"] = 2.into(),
            _ => unreachable!(),
        }
        assert!(
            validate_linux_policy_mutation(
                scenario, &baseline, &applied, &contract, &requested, &epoch, 65534, reason
            )
            .is_ok(),
            "{scenario}"
        );
        requested["preserved"] = "unrelated-change".into();
        assert!(
            validate_linux_policy_mutation(
                scenario, &baseline, &applied, &contract, &requested, &epoch, 65534, reason
            )
            .is_err(),
            "{scenario}"
        );
    }
    let mut malformed = contract.clone();
    malformed["authorization"] = json!([]);
    assert!(
        validate_linux_policy_mutation(
            "wrong-plan",
            &baseline,
            &baseline,
            &malformed,
            &request,
            &epoch,
            65534,
            "unauthorized-plan"
        )
        .is_err()
    );
}
