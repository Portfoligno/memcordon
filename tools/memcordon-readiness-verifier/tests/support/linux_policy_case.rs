//! Full persisted policy records with a separately verified original admission.
use super::{
    linux_installed_case as installed, linux_positive_case as positive,
    linux_prepared_case as prepared, persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

pub fn baseline(scenario: &str) -> PersistedCase {
    let mut case = positive::baseline();
    let positive_record = case.record.clone();
    let evidence = installed::read(&case, "case-evidence.json");
    case.json("positive-case-evidence.json", &evidence);
    let mut positive_record = positive_record;
    positive_record.evidence = Some("positive-case-evidence.json".into());
    case.index.records.push(positive_record);
    let admin = "/var/lib/memcordon-consumer-readiness/original-admin";
    case.mutate("installed/root-acquisition.json", |root| {
        root["path"] = json!(admin)
    });
    case.mutate("installed/owned-resources-acquired.json", |root| {
        root["admin_root"] = json!(admin)
    });
    let acquired = installed::read(&case, "installed/owned-resources-acquired.json");
    let req = installed::read(&case, "request.json");
    let (contract, registry, activation) = installed::activation(
        &mut case,
        acquired["images"]["runtime"].clone(),
        acquired["images"]["input"].clone(),
        vec![],
        req["requirements"].clone(),
    );
    let earlier = if scenario == "wrong-epoch" {
        let record = add_case(
            &mut case,
            "disabled-grant",
            &contract,
            &registry,
            &activation,
            2,
            vec![],
        );
        case.index.records.push(record);
        vec!["policy/disabled-grant/restoration.json".into()]
    } else {
        vec![]
    };
    let record = add_case(
        &mut case,
        scenario,
        &contract,
        &registry,
        &activation,
        if scenario == "wrong-epoch" { 4 } else { 2 },
        earlier,
    );
    case.record = record;
    case.index.fixture_cases.push(case.record.key.clone());
    case
}

fn add_case(
    case: &mut PersistedCase,
    scenario: &str,
    contract: &Value,
    registry: &Value,
    baseline_activation: &Value,
    epoch_revision: u64,
    earlier: Vec<String>,
) -> CaseRecord {
    let gated = ["revoke-discovery", "revoke-preparation", "revoke-release"].contains(&scenario);
    let mut key = case.record.key.clone();
    key.family = if gated { "L-ID-03" } else { "L-ID-02" }.into();
    key.scenario = scenario.into();
    let path = |leaf: &str| format!("policy/{scenario}/{leaf}");
    let mut applied = registry.clone();
    let mut requested = contract.clone();
    match scenario {
        "disabled-grant" => applied["grants"][0]["enabled"] = json!(false),
        "changed-grant" => applied["grants"][0]["revision"] = json!(2),
        _ => {}
    }
    let mut activation = baseline_activation.clone();
    activation["epoch"]["revision"] = json!(epoch_revision);
    activation["registry"] = applied.clone();
    activation["registry_digest"] = json!(linux_registry_digest(&applied, &key.target).unwrap());
    requested["expected_epoch"] = activation["epoch"].clone();
    let changed = sha256(scenario.as_bytes());
    let reason = match scenario {
        "wrong-caller" => "unauthorized-caller",
        "wrong-plan" => {
            requested["workload_plan_digest"] = json!(changed);
            requested["authorization"]["approved_plan_digest"] = json!(changed);
            "unauthorized-plan"
        }
        "wrong-image" => {
            requested["runtime_image"]["id"] = json!("owned-readiness-wrong-image");
            "unauthorized-image"
        }
        "wrong-digest" => {
            requested["runtime_image"]["digest"] = json!(changed);
            "unauthorized-image"
        }
        "wrong-profile" => {
            requested["authorized_profile"]["semantic_digest"] = json!(changed);
            "unauthorized-profile"
        }
        "wrong-identity" => {
            requested["execution_identity"]["identity"]["digest"] = json!(changed);
            "unauthorized-identity"
        }
        "wrong-epoch" => {
            requested["expected_epoch"]["revision"] = json!(epoch_revision - 1);
            "stale-epoch"
        }
        "disabled-grant" => "disabled-grant",
        "changed-grant" => "wrong-grant-revision",
        "revoke-discovery" | "revoke-preparation" | "revoke-release" => "stale-epoch",
        _ => panic!("unsupported full policy fixture {scenario}"),
    };
    let mut restoration = baseline_activation.clone();
    restoration["epoch"]["revision"] = json!(epoch_revision + if gated { 2 } else { 1 });
    let acquired = installed::read(case, "installed/owned-resources-acquired.json");
    let image_owner = installed::read(case, "installed/mixed-cases/image-cases/owner.json");
    let provider = image_owner["provider"].clone();
    let admin = "/var/lib/memcordon-consumer-readiness/original-admin";
    let privileged = format!("{admin}/policy-cases-original-lease");
    let owner = json!({"format":"memcordon.linux-policy-case-owner","revision":1,"run_id":case.record.run_id,"source_commit":case.index.source_commit,"source_tree_sha256":case.index.source_tree_sha256,"cell":case.index.products[0].key,"lease_id":"original-lease","provider":provider,"baseline_registry":registry,"baseline_epoch":baseline_activation["epoch"],"admin_root":admin,"admin_root_device":7,"admin_root_inode":8,"privileged_policy_root":privileged});
    case.json(&path("owner.json"), &owner);
    case.json(&path("baseline-registry.json"), registry);
    case.json(&path("baseline-contract.json"), contract);
    case.json(&path("baseline-activation.json"), baseline_activation);
    case.json(&path("requested-contract.json"), &requested);
    for (stem, policy, receipt) in [
        ("activation", &applied, &activation),
        ("restoration", registry, &restoration),
    ] {
        let policy_bytes = serde_json::to_vec(policy).unwrap();
        let receipt_bytes = serde_json::to_vec(receipt).unwrap();
        let command = json!({"format":"memcordon.linux-policy-activation-command","revision":1,"agent_sha256":sha256(b"original agent image"),"program":b"/usr/libexec/memcordon-sealed-agent".as_slice(),"arguments":[b"package".as_slice(),b"policy",b"apply",b"--file",format!("{privileged}/{scenario}/{stem}.policy.json").as_bytes()],"cwd":format!("/owned/policy/{scenario}").as_bytes(),"environment_cleared":true,"budget_millis":1000,"policy_sha256":sha256(&policy_bytes)});
        case.json(&path(&format!("{stem}.policy.json")), policy);
        case.json(&path(&format!("{stem}.json")), receipt);
        case.json(&path(&format!("{stem}.invocation.json")), &command);
        case.write(&path(&format!("{stem}.stderr.bin")), b"");
        case.json(&path(&format!("{stem}.exit.json")),&json!({"format":"memcordon.linux-policy-activation-exit","revision":1,"native_exit":0,"success":true,"invocation_sha256":sha256(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":sha256(&receipt_bytes),"stderr_sha256":sha256(b"")}));
    }
    let challenge = [7u8; 32];
    let token = hex::encode(challenge);
    let args = vec![b"tcp-http".to_vec(), token.as_bytes().to_vec()];
    let graph = prepared::prepared_graph(
        &requested,
        &activation,
        &provider,
        &case.record.run_id,
        &args,
        256 * 1024 * 1024,
        30000,
        b"original agent image",
    );
    let request_path = path("07070707070707070707070707070707.provider-request.bin");
    case.json(&request_path, &graph.request);
    case.write(&path("challenge.bin"), &challenge);
    let caller = if scenario == "wrong-caller" {
        65533
    } else {
        65534
    };
    let caller_text = caller.to_string();
    let argv = vec![
        b"--reuid".to_vec(),
        caller_text.as_bytes().to_vec(),
        b"--regid".to_vec(),
        caller_text.as_bytes().to_vec(),
        b"--clear-groups".to_vec(),
        b"--".to_vec(),
        b"/usr/libexec/memcordon".to_vec(),
        b"+256M".to_vec(),
        b"+30000ms".to_vec(),
        b"--sealed".to_vec(),
        b"--workload-contract".to_vec(),
        format!("/owned/policy/{scenario}/request.json").into_bytes(),
        b"--report-format".to_vec(),
        b"result-v2".to_vec(),
        b"--report".to_vec(),
        format!("/owned/policy/{scenario}/result.json").into_bytes(),
        b"--mixed-observation-directory".to_vec(),
        format!("/owned/policy/{scenario}/observations").into_bytes(),
        b"--image-entrypoint".to_vec(),
        b"owned-readiness".to_vec(),
        b"--".to_vec(),
        b"tcp-http".to_vec(),
        token.as_bytes().to_vec(),
    ];
    let command = json!({"format":"memcordon.linux-owned-frontend-invocation","revision":1,"program":b"/usr/bin/setpriv","arguments":argv,"environment_cleared":true,"caller_uid":caller,"caller_gid":caller,"selected_cli_sha256":sha256(b"original CLI image")});
    let invocation = json!({"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+256M"},{"kind":"time","token":"+30000ms"}],"memory_token":"+256M","deadline_token":"+30000ms","argv":[{"display":"owned-readiness","raw":null},{"display":"tcp-http","raw":null},{"display":token,"raw":null}]});
    case.json(&path("frontend-invocation.json"), &command);
    case.json(&path("public-invocation.json"), &invocation);
    case.write(&path("stdout.bin"), b"");
    case.write(&path("stderr.bin"), b"");
    let result = json!({"format":"memcordon.result","revision":2,"tool":{"name":"memcordon","version":case.index.version,"os":"linux","architecture":"x86_64","runtime_features":["sealed-runtime","private-tcp"]},"invocation":invocation,"runtime":{"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,"outcome":{"kind":"rejected-before-authorization","request_sha256":sha256(&serde_json::from_value::<memcordon_core::workload_contract_v3::WorkloadContractV3>(requested.clone()).unwrap().canonical_bytes().unwrap()),"request_bytes_sha256":sha256(&serde_json::to_vec(&graph.request).unwrap()),"reason":reason,"detail":"actual original policy refusal","allocation":{"authorization":"never-authorized","obligations":[]}}},"delivery":{"prepared-by":{"writer_pid":102}},"frontend":{"relay_drained":true,"interruption":null,"relay_error":null},"wrapper_status":125});
    case.json(&path("result.json"), &result);
    case.json(&path("frontend-exit.json"),&json!({"format":"memcordon.linux-policy-frontend-exit","revision":1,"process_id":102,"process_birth":301,"raw_wait_status":125*256,"native_exit":125,"signal":null,"invocation_sha256":sha256(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":sha256(b""),"stderr_sha256":sha256(b"")}));
    let root = |path: &str| json!({"path":path,"device":7,"inode":8,"uid":0,"mode":0o040700,"attempt_absence_errno":2});
    let mut cgroup = root("/sys/fs/cgroup/memcordon-sealed");
    cgroup["filesystem_type"] = json!(0x63677270u64);
    cgroup["attempt_directories"] = json!([]);
    case.json(&path("census.json"),&json!({"format":"memcordon.linux-policy-native-census","revision":1,"identity":acquired["identity"],"cell":acquired["cell"],"lease_id":"original-lease","scenario":scenario,"attempt_id":"07070707070707070707070707070707","provider":provider,"account":acquired["account"],"result_sha256":sha256(&serde_json::to_vec(&result).unwrap()),"request_sha256":sha256(&serde_json::to_vec(&graph.request).unwrap()),"tasks":[{"pid":1,"tid":1,"birth":1,"uids":[0,0,0,0],"gids":[0,0,0,0],"groups":[]}],"cgroup_root":cgroup,"journal_root":root("/var/lib/memcordon/sealed")}));
    let (discovery, gate) = if gated {
        gate_records(
            case,
            scenario,
            &key,
            &requested,
            registry,
            &activation,
            &graph,
            &provider,
            &privileged,
        )
    } else {
        (None, None)
    };
    let evidence = LinuxPolicyRefusalEvidence {
        format: "memcordon.consumer-readiness.linux-policy-refusal".into(),
        revision: 1,
        key: key.clone(),
        run_id: case.record.run_id.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        baseline_registry: path("baseline-registry.json"),
        baseline_contract: path("baseline-contract.json"),
        baseline_activation: path("baseline-activation.json"),
        earlier_activations: earlier,
        discovery,
        gate,
        activation: path("activation.json"),
        activation_policy: path("activation.policy.json"),
        activation_invocation: path("activation.invocation.json"),
        activation_exit: path("activation.exit.json"),
        activation_stderr: path("activation.stderr.bin"),
        restoration: path("restoration.json"),
        restoration_policy: path("restoration.policy.json"),
        restoration_invocation: path("restoration.invocation.json"),
        restoration_exit: path("restoration.exit.json"),
        restoration_stderr: path("restoration.stderr.bin"),
        requested_contract: path("requested-contract.json"),
        provider_request: request_path,
        raw_result: path("result.json"),
        invocation: path("public-invocation.json"),
        frontend_invocation: path("frontend-invocation.json"),
        frontend_exit: path("frontend-exit.json"),
        stdout: path("stdout.bin"),
        stderr: path("stderr.bin"),
        challenge: path("challenge.bin"),
        native_census: path("census.json"),
        owner: path("owner.json"),
    };
    let evidence_path = path("case-evidence.json");
    case.json(&evidence_path, &json!(evidence));
    CaseRecord {
        key,
        run_id: case.record.run_id.clone(),
        state: CaseState::Passed,
        reason: None,
        evidence: Some(evidence_path),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Preserve independent case, request, registry, activation, prepared native, provider and privileged scope inputs"
)]
fn gate_records(
    case: &mut PersistedCase,
    scenario: &str,
    key: &CaseKey,
    requested: &Value,
    registry: &Value,
    activation: &Value,
    graph: &prepared::PreparedGraph,
    provider: &Value,
    privileged: &str,
) -> (
    Option<LinuxPolicyDiscoveryEvidence>,
    Option<LinuxPolicyGateEvidence>,
) {
    let path = |leaf: &str| format!("policy/{scenario}/{leaf}");
    let stem = if scenario == "revoke-discovery" {
        "discovery-revocation"
    } else {
        "revocation"
    };
    let mut revoked = registry.clone();
    revoked["grants"][0]["enabled"] = json!(false);
    if scenario != "revoke-discovery" {
        revoked["active_attempt_disposition"] = json!("revoke-active");
    }
    let mut revocation = activation.clone();
    revocation["epoch"]["revision"] = json!(activation["epoch"]["revision"].as_u64().unwrap() + 1);
    revocation["registry"] = revoked.clone();
    revocation["registry_digest"] = json!(linux_registry_digest(&revoked, &key.target).unwrap());
    let command = json!({"format":"memcordon.linux-policy-activation-command","revision":1,"agent_sha256":sha256(b"original agent image"),"program":b"/usr/libexec/memcordon-sealed-agent".as_slice(),"arguments":[b"package".as_slice(),b"policy",b"apply",b"--file",format!("{privileged}/{scenario}/{stem}.policy.json").as_bytes()],"cwd":format!("/owned/policy/{scenario}").as_bytes(),"environment_cleared":true,"budget_millis":1000,"policy_sha256":sha256(&serde_json::to_vec(&revoked).unwrap())});
    for (leaf, value) in [
        (format!("{stem}.policy.json"), revoked),
        (format!("{stem}.json"), revocation.clone()),
        (format!("{stem}.invocation.json"), command.clone()),
    ] {
        case.json(&path(&leaf), &value);
    }
    case.write(&path(&format!("{stem}.stderr.bin")), b"");
    case.json(&path(&format!("{stem}.exit.json")),&json!({"format":"memcordon.linux-policy-activation-exit","revision":1,"native_exit":0,"success":true,"invocation_sha256":sha256(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":sha256(&serde_json::to_vec(&revocation).unwrap()),"stderr_sha256":sha256(b"")}));
    if scenario == "revoke-discovery" {
        let pending = memcordon_core::mixed_advisory::pending_obligations();
        let plan = json!({"format":"memcordon.plan","revision":2,"provider_contract":4,"launch_wire":4,"provider":provider,"request":requested,"request_sha256":graph.prepared["admission"]["request_sha256"],"available_for_preparation":true,"conflict":null,"prerequisite_error":null,"pending":pending,"authorizes_launch":false});
        let capabilities = json!({"format":"memcordon.capabilities","revision":2,"provider_contract":4,"launch_wire":4,"provider":provider,"boot_identity":"original-native-boot","profile":requested["authorized_profile"],"request_versions":[3],"carrier_versions":[2],"supported":true,"installed_enabled":true,"exclusive_identity_eligible":true,"image_support":true,"plan":plan,"authorizes_launch":false});
        let command = json!({"format":"memcordon.linux-policy-discovery-invocation","revision":1,"program":b"/usr/bin/setpriv","arguments":(["--reuid","65534","--regid","65534","--clear-groups","--","/usr/libexec/memcordon","doctor","--json","--capability-format","capabilities-v2","--require","sealed","--workload-contract",&format!("/owned/policy/{scenario}/discovery-contract.json")].iter().map(|arg|arg.as_bytes()).collect::<Vec<_>>()),"caller_uid":65534,"caller_gid":65534,"environment_cleared":true,"cli_sha256":sha256(b"original CLI image")});
        case.json(&path("discovery-contract.json"), requested);
        case.json(&path("discovery-invocation.json"), &command);
        case.json(&path("discovery-stdout.json"), &capabilities);
        case.write(&path("discovery-stderr.bin"), b"");
        case.json(&path("discovery-exit.json"),&json!({"native_exit":0,"stdout_sha256":sha256(&serde_json::to_vec(&capabilities).unwrap()),"stderr_sha256":sha256(b"")}));
        return (
            Some(LinuxPolicyDiscoveryEvidence {
                contract: path("discovery-contract.json"),
                invocation: path("discovery-invocation.json"),
                stdout: path("discovery-stdout.json"),
                stderr: path("discovery-stderr.bin"),
                exit: path("discovery-exit.json"),
                revocation: path(&format!("{stem}.json")),
                revocation_policy: path(&format!("{stem}.policy.json")),
                revocation_invocation: path(&format!("{stem}.invocation.json")),
                revocation_exit: path(&format!("{stem}.exit.json")),
                revocation_stderr: path(&format!("{stem}.stderr.bin")),
            }),
            None,
        );
    }
    case.json(&path("prepared.json"), &graph.prepared);
    case.json(&path("prepared-native.json"), &graph.native);
    let p = &graph.prepared;
    let retired = json!({"format":"memcordon.linux-policy-prepared-family-retirement","revision":1,"attempt_id":p["admission"]["attempt_id"],"admission_nonce":p["admission"]["admission_nonce"],"target":p["target"],"namespace_init":p["namespace_init"],"guardian":p["guardian"],"target_retirement":prepared::held(103,302,true),"namespace_init_retirement":prepared::held(104,303,true),"guardian_retirement":prepared::held(105,304,true),"held_before_revocation":true,"native_family_retired":true,"held_descendants":[]});
    case.json(&path("family-retirement.json"), &retired);
    case.json(&path("acknowledgment.json"),&json!({"format":"memcordon.linux-policy-observer-ack-operation","revision":1,"after_revocation":true,"acknowledgment_published":true,"error":null}));
    let (release, release_ack) = if scenario == "revoke-release" {
        case.json(&path("release.json"),&json!({"format":"memcordon.mixed-release-observation","revision":2,"prepared":p,"authorizes_launch":false}));
        case.json(&path("release-ack.json"),&json!({"format":"memcordon.mixed-release-observer-acknowledgment","revision":2,"attempt_id":p["admission"]["attempt_id"],"admission_nonce":p["admission"]["admission_nonce"],"target":p["target"],"observer":graph.native["observer"]}));
        (Some(path("release.json")), Some(path("release-ack.json")))
    } else {
        (None, None)
    };
    (
        None,
        Some(LinuxPolicyGateEvidence {
            prepared: path("prepared.json"),
            prepared_native: path("prepared-native.json"),
            retirement: path("family-retirement.json"),
            acknowledgment: path("acknowledgment.json"),
            revocation: path(&format!("{stem}.json")),
            revocation_policy: path(&format!("{stem}.policy.json")),
            revocation_invocation: path(&format!("{stem}.invocation.json")),
            revocation_exit: path(&format!("{stem}.exit.json")),
            revocation_stderr: path(&format!("{stem}.stderr.bin")),
            release,
            release_ack,
        }),
    )
}
