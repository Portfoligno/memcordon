use super::{
    linux_cross_account_case as accounts, linux_image_entrypoint_case as image,
    linux_installed_case as installed, linux_isolation_case as isolation,
    linux_limits_case as limits, persisted_case::PersistedCase,
};
use memcordon_core::workload_contract::LogicalId;
use memcordon_core::workload_contract_v3::{DeniedOperationV3, RequirementV3, WorkloadContractV3};
use memcordon_core::workload_registry_v3::{
    ExclusiveIdentityDefinitionV3, RuntimePrivatePolicyRegistryV3,
};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

fn source_plan(contract: &mut WorkloadContractV3) {
    let raw = serde_json::to_vec(&(
        &contract.runtime_image,
        &contract.input_image,
        &contract.root_layout,
        &contract.execution_identity,
        &contract.requirements,
    ))
    .unwrap();
    contract.workload_plan_digest = serde_json::from_value(json!(sha256(&raw))).unwrap();
    contract.authorization.approved_plan_digest = contract.workload_plan_digest.clone();
}
fn rows(case: &mut PersistedCase, operations: &[(&str, Value)], birth: u64) {
    let mut raw = vec![];
    for (ordinal, (operation, observation)) in operations.iter().enumerate() {
        raw.extend(serde_json::to_vec(&json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":ordinal+1,"challenge":hex::encode([7;32]),"root_pid":2,"root_birth":birth,"operation":operation,"observation":observation})).unwrap());
        raw.push(b'\n');
    }
    case.write("transcript.bin", &raw);
}
fn move_peer_identity(value: &mut Value, key: &str) {
    match value {
        Value::Object(object) => {
            for (field, value) in object {
                move_peer_identity(value, field)
            }
        }
        Value::Array(values) => {
            for (ordinal, value) in values.iter_mut().enumerate() {
                if key == "namespace_pids" && ordinal == 0 {
                    move_peer_identity(value, "process_id")
                } else {
                    move_peer_identity(value, key)
                }
            }
        }
        Value::Number(number) => {
            if let Some(n) = number.as_u64() {
                if [
                    "pid",
                    "process_id",
                    "writer_pid",
                    "root_pid",
                    "parent_pid",
                    "observer_pid",
                ]
                .contains(&key)
                    && n >= 100
                {
                    *value = json!(n + 100);
                } else if ["birth", "root_birth", "process_birth", "parent_birth"].contains(&key)
                    && n >= 300
                {
                    *value = json!(n - 100);
                } else if key == "inode" && (100..=104).contains(&n)
                    || (key == "inode" && (1100..=1104).contains(&n))
                {
                    *value = json!(n + 5000);
                } else if key == "root_inode" {
                    *value = json!(n + 5000);
                }
            }
        }
        Value::String(text) => {
            if key == "attempt_id" && text == "07070707070707070707070707070707" {
                *text = "08080808080808080808080808080808".into();
            }
        }
        _ => {}
    }
}
fn copy_peer(case: &mut PersistedCase, peer: &PersistedCase) {
    let names = [
        "case-evidence.json",
        "fixture.bin",
        "fixture-source.bin",
        "input.json",
        "invocation.json",
        "request.json",
        "provider-request.json",
        "result.json",
        "execution.bin",
        "environment.json",
        "export.json",
        "prepared.json",
        "prepared-native.json",
        "native.json",
        "retirement.json",
        "semantic.json",
        "challenge.bin",
        "transcript.bin",
        "abstract.bin",
        "abstract-expected.bin",
    ];
    fn rekey(value: &mut Value, names: &[&str]) {
        match value {
            Value::Object(object) => {
                for value in object.values_mut() {
                    rekey(value, names)
                }
            }
            Value::Array(array) => {
                for value in array {
                    rekey(value, names)
                }
            }
            Value::String(text) => {
                if names.contains(&text.as_str()) {
                    *text = format!("peer/{text}");
                }
            }
            _ => {}
        }
    }
    for name in names {
        let bytes = std::fs::read(peer.root.path().join(name)).unwrap();
        let path = format!("peer/{name}");
        if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) {
            rekey(&mut value, &names);
            case.json(&path, &value);
        } else {
            case.write(&path, &bytes);
        }
    }
    let input_hash = sha256(&std::fs::read(case.root.path().join("peer/input.json")).unwrap());
    case.mutate("peer/case-evidence.json", |evidence| {
        evidence["input_sha256"] = json!(input_hash)
    });
}
fn policy_command(
    case: &mut PersistedCase,
    stem: &str,
    policy: &Value,
    receipt: &Value,
    pid: u32,
    birth: u64,
    protected: &str,
) {
    let command = json!({"format":"memcordon.linux-cross-policy-command","revision":1,"program":b"/usr/libexec/memcordon-sealed-agent".as_slice(),"arguments":[b"package".as_slice(),b"policy",b"apply",b"--file",format!("{protected}/{stem}.policy.json").as_bytes()],"cwd":format!("{}/cross",installed::EVIDENCE_ROOT).as_bytes(),"environment_cleared":true,"budget_millis":60,"program_sha256":sha256(b"original agent image"),"program_device":7,"program_inode":300,"policy_sha256":sha256(&serde_json::to_vec(policy).unwrap())});
    let mut command = command;
    command["started_unix_millis"] = json!(if stem == "activation" { 25 } else { 125 });
    command["deadline_unix_millis"] = json!(if stem == "activation" { 100 } else { 200 });
    case.json(&format!("cross/{stem}.policy.json"), policy);
    case.json(&format!("cross/{stem}.json"), receipt);
    case.json(&format!("cross/{stem}.invocation.json"), &command);
    case.write(&format!("cross/{stem}.stderr.bin"), b"");
    case.json(&format!("cross/{stem}.exit.json"),&json!({"format":"memcordon.linux-cross-policy-exit","revision":1,"creation":{"pid":pid,"birth":birth,"image":{"device":7,"inode":300,"length":b"original agent image".len(),"sha256":sha256(b"original agent image")}},"retirement":{"pid":pid,"birth":birth,"parent_pid":null,"parent_birth":null,"retirement_observed":true},"raw_wait_status":0,"native_exit":0,"signal":null,"invocation_sha256":sha256(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":sha256(&serde_json::to_vec(receipt).unwrap()),"stderr_sha256":sha256(b"")}));
}

pub fn baseline() -> PersistedCase {
    let mut case = image::baseline();
    case.record.key.family = "L-ISO-03".into();
    case.record.key.scenario = "other-attempt-abstract".into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let acquired = installed::read(&case, "installed/owned-resources-acquired.json");
    let owner = installed::read(&case, "installed/mixed-cases/image-cases/owner.json");
    let original = installed::read(&case, "request.json");
    let (_, prior, initial) = installed::activation(
        &mut case,
        acquired["images"]["runtime"].clone(),
        acquired["images"]["input"].clone(),
        vec![],
        original["requirements"].clone(),
    );
    let root = installed::EVIDENCE_ROOT;
    let mut account_fields = accounts::populate(&mut case, root, "cross/account", 202);
    account_fields["original_lease"] = json!("installed/lease-owner.json");
    account_fields["original_acquisition"] = json!("installed/owned-resources-acquired.json");
    let account = account_fields["peer_account"].clone();
    let mut registry: RuntimePrivatePolicyRegistryV3 =
        serde_json::from_value(prior.clone()).unwrap();
    let mut target: WorkloadContractV3 = serde_json::from_value(original.clone()).unwrap();
    let mut peer = target.clone();
    let id = |text: &str| LogicalId::new(text.into()).unwrap();
    let mut secondary = registry.execution_identities.as_slice()[0].clone();
    secondary.identity_id = id("owned-cross-attempt-identity");
    secondary.uid = std::num::NonZeroU32::new(61002).unwrap();
    secondary.gid = std::num::NonZeroU32::new(61002).unwrap();
    secondary.reservation_key = id("owned-cross-attempt-reservation");
    let declaration = json!({"format":"memcordon.owned-readiness-exclusive-use-declaration","revision":1,"run_id":case.record.run_id,"cell":case.index.products[0].key,"account":account["name"],"uid":61002,"gid":61002,"purpose":"exclusive original other-attempt abstract peer identity"});
    secondary.exclusive_use_policy=serde_json::from_value(json!({"id":"owned-cross-attempt-use","digest":sha256(&serde_json::to_vec(&declaration).unwrap())})).unwrap();
    peer.execution_identity = secondary.reference().unwrap();
    peer.requirements = serde_json::from_value(json!([RequirementV3::UnixAbstractStream {
        id: id("peer-abstract")
    }]))
    .unwrap();
    target.requirements = serde_json::from_value(json!([
        RequirementV3::UnixAbstractStream {
            id: id("own-abstract")
        },
        RequirementV3::ExpectedDenial {
            id: id("other-attempt-denial"),
            operation: DeniedOperationV3::OtherAttempt
        }
    ]))
    .unwrap();
    source_plan(&mut peer);
    source_plan(&mut target);
    let mut grants = registry.grants.as_slice().to_vec();
    let mut plans = grants[0].approved_plans.as_slice().to_vec();
    plans.push(target.workload_plan_digest.clone());
    grants[0].approved_plans = serde_json::from_value(json!(plans)).unwrap();
    let mut grant = grants[0].clone();
    grant.id = id("owned-cross-attempt-grant");
    grant.execution_identity = peer.execution_identity.clone();
    grant.approved_plans = serde_json::from_value(json!([peer.workload_plan_digest])).unwrap();
    peer.authorization.grant_id = grant.id.clone();
    grants.push(grant);
    registry.grants = serde_json::from_value(json!(grants)).unwrap();
    let mut identities = registry.execution_identities.as_slice().to_vec();
    identities.push(secondary);
    registry.execution_identities = serde_json::from_value(json!(identities)).unwrap();
    registry.validate().unwrap();
    let registry = json!(registry);
    let mut activation = initial.clone();
    activation["registry"] = registry.clone();
    activation["registry_digest"] =
        json!(linux_registry_digest(&registry, &case.record.key.target).unwrap());
    activation["epoch"]["revision"] = json!(2);
    target.expected_epoch = serde_json::from_value(activation["epoch"].clone()).unwrap();
    peer.expected_epoch = target.expected_epoch.clone();
    case.json("request.json", &json!(target));
    let token = hex::encode([7; 32]);
    let name = format!("memcordon-readiness-{token}");
    let args = vec![
        b"forbidden-abstract".to_vec(),
        token.as_bytes().to_vec(),
        name.as_bytes().to_vec(),
    ];
    let (_, mut native) = limits::rebind_activation(
        &mut case,
        &args,
        256 * 1024 * 1024,
        30000,
        "+256M",
        "+30000ms",
        Some(activation.clone()),
    );
    native.held_processes.truncate(1);
    case.json("native.json", &json!(native));
    rows(
        &mut case,
        &[
            (
                "neighboring-private-unix",
                json!({"bytes":b"private-positive".as_slice()}),
            ),
            (
                "forbidden-abstract-denied",
                json!({"name":name.as_bytes(),"native_errno":111,"denied":true}),
            ),
        ],
        302,
    );
    let mut semantic: SemanticObservation =
        serde_json::from_value(installed::read(&case, "semantic.json")).unwrap();
    semantic.key = case.record.key.clone();
    semantic.operations = vec![OperationObservation {
        operation: "native-authority-probe".into(),
        observer: "owned-fixture-behavior".into(),
        attempt_id: native.attempt_id.clone(),
        root_pid: native.root_pid,
        native_receipt: "transcript.bin".into(),
    }];
    semantic.comparisons.clear();
    semantic.negative_probe = Some(NegativeProbe {
        stage: "other-attempt-abstract".into(),
        domain: "linux".into(),
        native_code: 111,
        receipt: "transcript.bin".into(),
    });
    semantic.fixture_behavior = Some(FixtureBehavior {
        descriptor: "input.json".into(),
        transcript: "transcript.bin".into(),
        expected_token: None,
        native_binding: Some("prepared-native.json".into()),
        peer_artifacts: vec![BehaviorArtifact {
            role: "other-attempt-abstract-canary".into(),
            path: "cross/canary.json".into(),
        }],
    });
    case.json("semantic.json", &json!(semantic));
    let key = case.record.key.clone();
    case.mutate("case-evidence.json", |evidence| {
        evidence["key"] = json!(key)
    });
    let mut peer_case = isolation::own_abstract();
    peer_case.json("request.json", &json!(peer));
    let peer_args = vec![b"own-abstract-held".to_vec(), token.as_bytes().to_vec()];
    let (_, mut peer_native) = limits::rebind_activation(
        &mut peer_case,
        &peer_args,
        256 * 1024 * 1024,
        30000,
        "+256M",
        "+30000ms",
        Some(activation.clone()),
    );
    peer_native.held_processes.truncate(1);
    peer_case.json("native.json", &json!(peer_native));
    for leaf in [
        "prepared.json",
        "prepared-native.json",
        "result.json",
        "native.json",
        "retirement.json",
        "semantic.json",
    ] {
        peer_case.mutate(leaf, |value| move_peer_identity(value, ""));
    }
    let peer_contract = json!(peer);
    peer_case.mutate("result.json", |value| {
        for field in [
            "runtime_image",
            "input_image",
            "root_layout",
            "execution_identity",
        ] {
            value["runtime"]["outcome"]["execution"][field] = peer_contract[field].clone();
        }
        value["runtime"]["outcome"]["execution"]["target_uid"] = json!(61002);
        value["runtime"]["outcome"]["execution"]["target_gid"] = json!(61002);
    });
    peer_case.mutate("prepared.json", |value| {
        value["admission"]["admission_nonce"] = json!(vec![10; 16])
    });
    let peer_prepared = installed::read(&peer_case, "prepared.json");
    peer_case.mutate("prepared-native.json", |value| {
        value["prepared_sha256"] = json!(sha256(&serde_json::to_vec(&peer_prepared).unwrap()))
    });
    peer_case.mutate("result.json", |value| {
        value["runtime"]["outcome"]["admission"] = peer_prepared["admission"].clone()
    });
    let peer_binding = installed::read(&peer_case, "prepared-native.json");
    let observation = json!({"name":name.as_bytes(),"socket_inode":800,"network_namespace_inode":peer_binding["target"]["network"]["inode"],"baseline_client_connected":true,"baseline_server_accepted":true,"bytes":b"abstract-unix-readiness".as_slice()});
    rows(
        &mut peer_case,
        &[
            ("other-attempt-abstract-held", observation.clone()),
            ("other-attempt-abstract-released", observation.clone()),
        ],
        202,
    );
    copy_peer(&mut case, &peer_case);
    let peer_binding = installed::read(&case, "peer/prepared-native.json");
    case.write(
        "peer/stdout.bin",
        &std::fs::read(case.root.path().join("peer/transcript.bin")).unwrap(),
    );
    case.write("peer/stderr.bin", b"");
    let peer_dir = format!("{}/peer", installed::EVIDENCE_ROOT);
    let command = json!({"format":"memcordon.linux-owned-frontend-invocation","revision":1,"program":b"/usr/bin/setpriv".as_slice(),"arguments":[b"--reuid".as_slice(),b"65534",b"--regid",b"65534",b"--clear-groups",b"--",b"/usr/libexec/memcordon",b"+256M",b"+30000ms",b"--sealed",b"--workload-contract",format!("{peer_dir}/contract.json").as_bytes(),b"--report-format",b"result-v2",b"--report",format!("{peer_dir}/result.json").as_bytes(),b"--mixed-observation-directory",format!("{peer_dir}/observations").as_bytes(),b"--image-entrypoint",b"owned-readiness",b"--",b"own-abstract-held",token.as_bytes()],"environment_cleared":true,"caller_uid":65534,"caller_gid":65534,"selected_cli_sha256":sha256(b"original CLI image")});
    case.json("peer/original-frontend-invocation.json", &command);
    case.json("peer/original-frontend-exit.json",&json!({"format":"memcordon.linux-policy-frontend-exit","revision":1,"process_id":202,"process_birth":201,"raw_wait_status":0,"native_exit":0,"signal":null,"invocation_sha256":sha256(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":sha256(&std::fs::read(case.root.path().join("peer/stdout.bin")).unwrap()),"stderr_sha256":sha256(b"")}));
    let retired = |role: &str| json!({"pid":peer_prepared[role]["pid"],"birth":peer_prepared[role]["birth"],"parent_pid":null,"parent_birth":null,"retirement_observed":true});
    case.json("peer/native-family-retirement.json",&json!({"format":"memcordon.linux-held-family-retirement","revision":1,"run_id":case.record.run_id,"lease_id":"original-lease","attempt_id":peer_binding["attempt_id"],"target":retired("target"),"namespace_init":retired("namespace_init"),"guardian":retired("guardian"),"descendants":[],"namespace_members":[],"aggregate_empty":true}));
    case.json("cross/prior-registry.json", &prior);
    case.json("cross/prior-activation.json", &initial);
    case.json("cross/original-contract.json", &original);
    let protected = format!(
        "{}/cross-attempt-abstract",
        owner["admin_root"].as_str().unwrap()
    );
    let mut restoration = initial.clone();
    restoration["epoch"]["revision"] = json!(3);
    policy_command(
        &mut case,
        "activation",
        &registry,
        &activation,
        120,
        190,
        &protected,
    );
    policy_command(
        &mut case,
        "restoration",
        &prior,
        &restoration,
        121,
        350,
        &protected,
    );
    let lease = installed::read(&case, "installed/lease-owner.json");
    case.json("cross/owner.json",&json!({"format":"memcordon.linux-cross-attempt-owner","revision":1,"identity":lease["identity"],"cell":lease["cell"],"lease_id":"original-lease","acquisition_output":format!("{}/cross/account",installed::EVIDENCE_ROOT),"protected_output":protected,"original_registry_sha256":sha256(&serde_json::to_vec(&prior).unwrap()),"primary_account":acquired["account"]}));
    let original_lease = format!("{}/installed/lease-owner.json", installed::EVIDENCE_ROOT);
    let original_acquisition = format!(
        "{}/installed/owned-resources-acquired.json",
        installed::EVIDENCE_ROOT
    );
    case.mutate("cross/owner.json", |owner| {
        owner["original_lease"] = json!(original_lease);
        owner["original_acquisition"] = json!(original_acquisition);
        owner["work_deadline_unix_millis"] = json!(100);
        owner["cleanup_deadline_unix_millis"] = json!(200);
    });
    let mut canary = json!({"format":"memcordon.linux-other-attempt-abstract-canary","revision":1,"run_id":case.record.run_id,"lease_id":"original-lease","cell":case.index.products[0].key,"challenge":token,"name":name.as_bytes(),"prior_registry":"cross/prior-registry.json","cross_owner":"cross/owner.json","prior_activation":"cross/prior-activation.json","original_contract":"cross/original-contract.json","activation":"cross/activation.json","activation_policy":"cross/activation.policy.json","activation_invocation":"cross/activation.invocation.json","activation_exit":"cross/activation.exit.json","activation_stderr":"cross/activation.stderr.bin","restoration":"cross/restoration.json","restoration_policy":"cross/restoration.policy.json","restoration_invocation":"cross/restoration.invocation.json","restoration_exit":"cross/restoration.exit.json","restoration_stderr":"cross/restoration.stderr.bin","peer_frontend_invocation":"peer/original-frontend-invocation.json","peer_frontend_exit":"peer/original-frontend-exit.json","peer_case":"peer/case-evidence.json","peer_request":"peer/provider-request.json","peer_prepared":"peer/prepared.json","peer_native":"peer/prepared-native.json","peer_result":"peer/result.json","peer_retirement":"peer/native-family-retirement.json","held_peer":peer_binding["target"],"held_peer_after":peer_binding["target"],"target_native":installed::read(&case,"prepared-native.json")["target"],"listener":{"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":1,"challenge":hex::encode([7;32]),"root_pid":2,"root_birth":202,"operation":"other-attempt-abstract-held","observation":observation},"peer_collection_root":"peer","target_collection_root":"target"});
    for (field, value) in account_fields.as_object_mut().unwrap() {
        canary[field] = value.clone();
    }
    case.json("cross/canary.json", &canary);
    let input_hash = sha256(&std::fs::read(case.root.path().join("input.json")).unwrap());
    case.mutate("case-evidence.json", |evidence| {
        evidence["input_sha256"] = json!(input_hash)
    });
    case
}
