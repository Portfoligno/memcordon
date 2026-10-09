//! Complete original admitted cohort and separately retained fresh refusal.
use super::{
    linux_installed_case as installed, linux_limits_case as limits, linux_policy_case as policy,
    linux_positive_case as positive, linux_prepared_case as prepared,
    persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

pub fn baseline(scenario: &str) -> PersistedCase {
    if scenario == "restart-fresh-admission" {
        return restart();
    }
    assert!(["drain-running", "revoke-running"].contains(&scenario));
    let mut case = policy::baseline("disabled-grant");
    case.record = case.index.records[0].clone();
    let original = positive::freeze(&mut case);
    case.index.records = vec![original];
    case.record.key.family = "L-ID-03".into();
    case.record.key.scenario = scenario.into();
    case.record.evidence = Some("case-evidence.json".into());
    case.index.fixture_cases = vec![case.index.records[0].key.clone(), case.record.key.clone()];
    let token = hex::encode([7u8; 32]);
    let args = vec![b"cooperation".to_vec(), token.as_bytes().to_vec()];
    let (graph, mut native) = limits::rebind(
        &mut case,
        &args,
        256 * 1024 * 1024,
        30000,
        "+256M",
        "+30000ms",
    );
    native.held_processes.truncate(2);
    case.json("native.json", &json!(native));
    let mut evidence: CaseEvidence =
        serde_json::from_value(installed::read(&case, "case-evidence.json")).unwrap();
    evidence.key = case.record.key.clone();
    evidence.input_sha256 = sha256(&std::fs::read(case.root.path().join("input.json")).unwrap());
    case.json("case-evidence.json", &json!(evidence));
    let owner = installed::read(&case, "policy/disabled-grant/owner.json");
    let registry = owner["baseline_registry"].clone();
    let mut disabled = registry.clone();
    disabled["grants"][0]["enabled"] = json!(false);
    disabled["active_attempt_disposition"] = json!(if scenario == "drain-running" {
        "drain-existing"
    } else {
        "revoke-active"
    });
    let baseline = installed::read(&case, "policy/disabled-grant/baseline-activation.json");
    let mut peers = vec![];
    let mut put = |case: &mut PersistedCase, role: &str, value: &Value| {
        let path = format!("running/{role}");
        case.json(&path, value);
        peers.push(BehaviorArtifact {
            role: role.into(),
            path,
        });
    };
    put(&mut case, "policy-owner", &owner);
    case.write("running/agent.bin", b"original agent image");
    for (stem, policy, revision) in [
        ("activation", &registry, 1),
        ("revocation", &disabled, 2),
        ("restoration", &registry, 3),
    ] {
        let mut receipt = baseline.clone();
        receipt["registry"] = policy.clone();
        receipt["registry_digest"] =
            json!(linux_registry_digest(policy, &case.record.key.target).unwrap());
        receipt["epoch"]["revision"] = json!(revision);
        receipt["revoked_admissions"] = if stem == "revocation" && scenario == "revoke-running" {
            json!([graph.prepared["admission"]["admission_nonce"]])
        } else {
            json!([])
        };
        let command = json!({"format":"memcordon.linux-policy-activation-command","revision":1,"agent_sha256":sha256(b"original agent image"),"program":b"/usr/libexec/memcordon-sealed-agent".as_slice(),"arguments":[b"package".as_slice(),b"policy",b"apply",b"--file",format!("{}/{scenario}/{stem}.policy.json",owner["privileged_policy_root"].as_str().unwrap()).as_bytes()],"cwd":b"/owned/policy/running","environment_cleared":true,"budget_millis":1000,"policy_sha256":sha256(&serde_json::to_vec(policy).unwrap())});
        let exit = json!({"format":"memcordon.linux-policy-activation-exit","revision":1,"native_exit":0,"success":true,"invocation_sha256":sha256(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":sha256(&serde_json::to_vec(&receipt).unwrap()),"stderr_sha256":sha256(b"")});
        put(&mut case, &format!("policy-{stem}-json"), &receipt);
        put(&mut case, &format!("policy-{stem}-policy.json"), policy);
        put(
            &mut case,
            &format!("policy-{stem}-invocation.json"),
            &command,
        );
        put(&mut case, &format!("policy-{stem}-exit.json"), &exit);
    }
    let child = json!({"pid":200,"birth":310,"parent_pid":103,"parent_birth":302,"retirement_observed":false});
    let ready = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":1,"challenge":token,"root_pid":3,"root_birth":310,"operation":"cooperation-peer-ready","observation":{"endpoint":"127.0.0.1:42000"}});
    let mut ready = serde_json::to_vec(&ready).unwrap();
    ready.push(b'\n');
    let held_row = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":1,"challenge":token,"root_pid":2,"root_birth":302,"operation":"same-attempt-cooperation-held","observation":{"pid":3,"birth":310,"members":[],"endpoint":"127.0.0.1:42000","transcript":ready}});
    let mut snapshot = graph.native["target"].clone();
    snapshot["process_id"] = json!(200);
    snapshot["birth"] = json!(310);
    snapshot["namespace_pids"] = json!([200, 3]);
    put(
        &mut case,
        "policy-running-native-held.json",
        &json!({"format":"memcordon.linux-policy-running-native-held","revision":1,"attempt_id":native.attempt_id,"target":{"pid":103,"birth":302},"challenge":token,"fixture_row":held_row,"held_descendants":[child],"native_descendants":[snapshot]}),
    );
    let mut transcript = serde_json::to_vec(&held_row).unwrap();
    transcript.push(b'\n');
    if scenario == "drain-running" {
        let peer = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":2,"challenge":token,"root_pid":3,"root_birth":310,"operation":"cooperation-peer-received","observation":{"endpoint":"127.0.0.1:42000","bytes":token.as_bytes()}});
        let mut peer = serde_json::to_vec(&peer).unwrap();
        peer.push(b'\n');
        let completed = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":2,"challenge":token,"root_pid":2,"root_birth":302,"operation":"same-attempt-cooperation-complete","observation":{"pid":3,"birth":310,"endpoint":"127.0.0.1:42000","server_received":token.as_bytes(),"peer_transcript":peer,"native_status":0}});
        transcript.extend(serde_json::to_vec(&completed).unwrap());
        transcript.push(b'\n');
    }
    case.write("transcript.bin", &transcript);
    let mut settled = child.clone();
    settled["retirement_observed"] = json!(true);
    put(
        &mut case,
        "policy-prepared-family-retirement.json",
        &json!({"format":"memcordon.linux-policy-prepared-family-retirement","revision":1,"attempt_id":native.attempt_id,"admission_nonce":graph.prepared["admission"]["admission_nonce"],"target":graph.prepared["target"],"namespace_init":graph.prepared["namespace_init"],"guardian":graph.prepared["guardian"],"target_retirement":prepared::held(103,302,true),"namespace_init_retirement":prepared::held(104,303,true),"guardian_retirement":prepared::held(105,304,true),"held_before_revocation":true,"native_family_retired":true,"held_descendants":[settled]}),
    );
    if scenario == "drain-running" {
        put(
            &mut case,
            "policy-running-after-revocation.json",
            &json!({"format":"memcordon.linux-policy-running-after-revocation","revision":1,"attempt_id":native.attempt_id,"target":prepared::held(103,302,false),"descendants":[child]}),
        );
    } else {
        native.origin = OutcomeOrigin::ProviderFailure;
        native.frontend_status = 125;
        native.target_status = None;
        case.json("native.json", &json!(native));
        case.mutate("result.json", |result| {
            result["wrapper_status"] = json!(125);
            result["runtime"]["outcome"]["execution"]["outcome_origin"] = json!("revoked");
            result["runtime"]["outcome"]["execution"]["native_wait_status"] = json!(9);
        });
    }
    let fresh_token = hex::encode([8u8; 32]);
    let fresh_contract = installed::read(&case, "policy/disabled-grant/requested-contract.json");
    let fresh_activation = installed::read(&case, "policy/disabled-grant/activation.json");
    let fresh_graph = prepared::prepared_graph(
        &fresh_contract,
        &fresh_activation,
        &owner["provider"],
        &case.record.run_id,
        &[b"tcp-http".to_vec(), fresh_token.as_bytes().to_vec()],
        256 * 1024 * 1024,
        30000,
        b"original agent image",
    );
    let mut fresh_result = installed::read(&case, "policy/disabled-grant/result.json");
    fresh_result["invocation"]["argv"][2]["display"] = json!(fresh_token);
    fresh_result["runtime"]["outcome"]["request_bytes_sha256"] =
        json!(sha256(&serde_json::to_vec(&fresh_graph.request).unwrap()));
    fresh_result["delivery"]["prepared-by"]["writer_pid"] = json!(108);
    let mut command = installed::read(&case, "policy/disabled-grant/frontend-invocation.json");
    let last = command["arguments"].as_array().unwrap().len() - 1;
    command["arguments"][last] = json!(fresh_token.as_bytes());
    let mut exit = installed::read(&case, "policy/disabled-grant/frontend-exit.json");
    exit["invocation_sha256"] = json!(sha256(&serde_json::to_vec(&command).unwrap()));
    exit["process_id"] = json!(108);
    exit["process_birth"] = json!(306);
    let mut census = installed::read(&case, "policy/disabled-grant/census.json");
    census["scenario"] = json!(scenario);
    census["request_sha256"] = json!(sha256(&serde_json::to_vec(&fresh_graph.request).unwrap()));
    census["result_sha256"] = json!(sha256(&serde_json::to_vec(&fresh_result).unwrap()));
    census["attempt_id"] = json!("08080808080808080808080808080808");
    for (role, value) in [
        ("policy-fresh-contract.json", fresh_contract),
        ("policy-fresh-result.json", fresh_result),
        ("policy-fresh-frontend-invocation.json", command),
        ("policy-fresh-exit.json", exit),
        ("policy-fresh-native-census.json", census),
    ] {
        put(&mut case, role, &value);
    }
    drop(put);
    let request_path = "running/policy-fresh-08080808080808080808080808080808.provider-request.bin";
    case.json(request_path, &fresh_graph.request);
    peers.push(BehaviorArtifact {
        role: "policy-fresh-provider-request.json".into(),
        path: request_path.into(),
    });
    for role in [
        "policy-agent-image",
        "policy-activation-stderr.bin",
        "policy-revocation-stderr.bin",
        "policy-restoration-stderr.bin",
        "policy-fresh-stdout.bin",
        "policy-fresh-stderr.bin",
        "policy-fresh-challenge.bin",
    ] {
        let path = format!("running/{role}");
        case.write(
            &path,
            if role == "policy-agent-image" {
                b"original agent image"
            } else if role == "policy-fresh-challenge.bin" {
                &[8u8; 32]
            } else {
                b""
            },
        );
        peers.push(BehaviorArtifact {
            role: role.into(),
            path,
        });
    }
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: case.record.run_id.clone(),
        key: case.record.key.clone(),
        challenge: "challenge.bin".into(),
        operations: vec![OperationObservation {
            operation: format!("policy-{scenario}"),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            observer: "owned-fixture-behavior".into(),
            native_receipt: "transcript.bin".into(),
        }],
        comparisons: vec![],
        counters: Default::default(),
        negative_probe: None,
        component_test: None,
        component_actors: None,
        windows_capacity: None,
        windows_refusal: None,
        fixture_behavior: Some(FixtureBehavior {
            descriptor: "input.json".into(),
            transcript: "transcript.bin".into(),
            peer_artifacts: peers,
            expected_token: None,
            native_binding: Some("prepared-native.json".into()),
        }),
    };
    case.json("semantic.json", &json!(semantic));
    case
}

fn restart() -> PersistedCase {
    let mut case = baseline("drain-running");
    case.record.key.scenario = "restart-fresh-admission".into();
    case.index.fixture_cases = vec![case.index.records[0].key.clone(), case.record.key.clone()];
    let mut activation = installed::read(&case, "running/policy-activation-json");
    activation["epoch"]["service_instance"] = json!(vec![10u8; 16]);
    activation["epoch"]["revision"] = json!(1);
    case.mutate("request.json", |request| {
        request["expected_epoch"] = activation["epoch"].clone()
    });
    let token = hex::encode([7u8; 32]);
    let args = vec![b"tcp-http".to_vec(), token.as_bytes().to_vec()];
    let (mut graph, mut native) = limits::rebind_activation(
        &mut case,
        &args,
        256 * 1024 * 1024,
        30000,
        "+256M",
        "+30000ms",
        Some(activation.clone()),
    );
    let attempt = "09090909090909090909090909090909";
    graph.prepared["admission"]["attempt_id"] = json!(attempt);
    graph.native["attempt_id"] = json!(attempt);
    for (role, pid, birth) in [
        ("caller", 402, 901),
        ("target", 403, 902),
        ("namespace_init", 404, 903),
        ("guardian", 405, 904),
    ] {
        graph.prepared[role] = json!({"pid":pid,"birth":birth});
        graph.native[role]["process_id"] = json!(pid);
        graph.native[role]["birth"] = json!(birth);
        graph.native[role]["namespace_pids"][0] = json!(pid);
    }
    graph.native["observer"] = json!({"pid":406,"birth":905});
    graph.native["prepared_sha256"] = json!(sha256(&serde_json::to_vec(&graph.prepared).unwrap()));
    case.json("prepared.json", &graph.prepared);
    case.json("prepared-native.json", &graph.native);
    native.attempt_id = Some(attempt.into());
    native.root_pid = Some(403);
    native.root_birth = Some(902);
    native.held_processes = vec![HeldProcessIdentity {
        pid: 403,
        birth: 902,
        parent_pid: None,
        parent_birth: None,
        retirement_observed: true,
    }];
    case.json("native.json", &json!(native));
    case.mutate("retirement.json", |retirement| {
        retirement["attempt_id"] = json!(attempt);
        retirement["root_pid"] = json!(403);
        retirement["root_birth"] = json!(902);
    });
    case.mutate("result.json", |result| {
        result["runtime"]["outcome"]["admission"] = graph.prepared["admission"].clone();
        for role in ["caller", "target", "namespace_init", "guardian"] {
            result["runtime"]["outcome"]["execution"][role] = graph.prepared[role].clone();
        }
        result["runtime"]["outcome"]["retirement"]["attempt_id"] = json!(attempt);
        result["delivery"]["prepared-by"]["writer_pid"] = json!(402);
    });
    let mut evidence: CaseEvidence =
        serde_json::from_value(installed::read(&case, "case-evidence.json")).unwrap();
    evidence.key = case.record.key.clone();
    evidence.input_sha256 = sha256(&std::fs::read(case.root.path().join("input.json")).unwrap());
    case.json("case-evidence.json", &json!(evidence));
    let mut semantic: SemanticObservation =
        serde_json::from_value(installed::read(&case, "semantic.json")).unwrap();
    semantic.key = case.record.key.clone();
    semantic.operations[0].operation = "policy-restart-fresh-admission".into();
    let peers = &mut semantic.fixture_behavior.as_mut().unwrap().peer_artifacts;
    for stem in ["activation", "restoration"] {
        let mut receipt = activation.clone();
        if stem == "restoration" {
            receipt["epoch"]["revision"] = json!(2);
        }
        case.json(&format!("running/policy-{stem}-json"), &receipt);
        let mut command = installed::read(&case, &format!("running/policy-{stem}-invocation.json"));
        let owner = installed::read(&case, "running/policy-owner");
        command["arguments"][4] = json!(
            format!(
                "{}/restart-fresh-admission/{stem}.policy.json",
                owner["privileged_policy_root"].as_str().unwrap()
            )
            .as_bytes()
        );
        case.json(&format!("running/policy-{stem}-invocation.json"), &command);
        case.mutate(&format!("running/policy-{stem}-exit.json"), |exit| {
            exit["invocation_sha256"] = json!(sha256(&serde_json::to_vec(&command).unwrap()));
            exit["stdout_sha256"] = json!(sha256(&serde_json::to_vec(&receipt).unwrap()));
        });
    }
    let mut put = |role: &str, value: &Value| {
        let path = format!("running/{role}");
        case.json(&path, value);
        peers.push(BehaviorArtifact {
            role: role.into(),
            path,
        });
    };
    for (stage, pid, birth) in [("before", 500, 600), ("after", 501, 601)] {
        put(
            &format!("policy-{stage}.service-native.json"),
            &json!({"format":"memcordon.linux-policy-control-service-native","revision":1,"stage":stage,"unit":"memcordon-sealed-agent.service","process_id":pid,"birth":birth,"image":"/usr/libexec/memcordon-sealed-agent","image_sha256":sha256(b"original agent image"),"held_live":true,"native_unit_exit":0}),
        );
    }
    put(
        "policy-control-generation-settlement.json",
        &json!({"format":"memcordon.linux-policy-control-generation-settlement","revision":1,"old":prepared::held(500,600,true),"current":prepared::held(501,601,false)}),
    );
    put(
        "policy-fresh-family-retirement.json",
        &json!({"format":"memcordon.linux-policy-restarted-family-retirement","revision":1,"prepared":graph.prepared,"native_family_retired":true,"target_retirement":prepared::held(403,902,true),"namespace_init_retirement":prepared::held(404,903,true),"guardian_retirement":prepared::held(405,904,true),"old_control_retired":true,"new_control_live":true}),
    );
    drop(put);
    let tool = b"original systemctl image";
    let toolpath = "running/systemctl.bin";
    case.write(toolpath, tool);
    peers.push(BehaviorArtifact {
        role: "policy-control-tool-image".into(),
        path: toolpath.into(),
    });
    for (ordinal, stem) in ["before-show", "restart", "after-show"]
        .into_iter()
        .enumerate()
    {
        let arguments = if stem == "restart" {
            vec![
                b"restart".to_vec(),
                b"memcordon-sealed-agent.service".to_vec(),
            ]
        } else {
            vec![
                b"show".to_vec(),
                b"--property=MainPID".to_vec(),
                b"--value".to_vec(),
                b"memcordon-sealed-agent.service".to_vec(),
            ]
        };
        let command = json!({"format":"memcordon.linux-policy-control-command","revision":1,"program":b"/usr/bin/systemctl","arguments":arguments,"cwd":b"/owned/policy/restart","environment":[],"program_sha256":sha256(tool),"program_device":1,"program_inode":999,"budget_millis":1000});
        let stdout: &[u8] = if stem == "before-show" {
            b"500\n"
        } else if stem == "after-show" {
            b"501\n"
        } else {
            b""
        };
        let pid = 700 + ordinal as u32;
        let birth = 800 + ordinal as u64;
        let exit = json!({"format":"memcordon.linux-policy-control-command-exit","revision":1,"creation":{"pid":pid,"birth":birth,"image":{"device":1,"inode":999,"length":tool.len(),"sha256":sha256(tool)}},"retirement":prepared::held(pid,birth,true),"raw_wait_status":0,"native_exit":0,"signal":null,"invocation_sha256":sha256(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":sha256(stdout),"stderr_sha256":sha256(b"")});
        for (role, value) in [
            (format!("policy-{stem}-command.json"), command),
            (format!("policy-{stem}-command-exit.json"), exit),
        ] {
            let path = format!("running/{role}");
            case.json(&path, &value);
            peers.push(BehaviorArtifact { role, path });
        }
        for (role, bytes) in [
            (format!("policy-{stem}-command.stdout.bin"), stdout),
            (format!("policy-{stem}-command.stderr.bin"), b"".as_slice()),
        ] {
            let path = format!("running/{role}");
            case.write(&path, bytes);
            peers.push(BehaviorArtifact { role, path });
        }
    }
    semantic.operations[0].attempt_id = native.attempt_id.clone();
    semantic.operations[0].root_pid = native.root_pid;
    let http = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":1,"challenge":token,"root_pid":2,"root_birth":902,"operation":"http-round-trip","observation":{"endpoint":"127.0.0.1:42000","peer":"127.0.0.1:42001","request":b"GET /readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),"response":b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreadiness".as_slice()}});
    let mut transcript = serde_json::to_vec(&http).unwrap();
    transcript.push(b'\n');
    case.write("transcript.bin", &transcript);
    case.json("semantic.json", &json!(semantic));
    case
}
