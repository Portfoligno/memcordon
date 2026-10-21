//! Complete original no-target account vectors; parser fixtures only.
use super::{
    linux_ingress_case as ingress, linux_installed_case as installed,
    linux_prepared_case as prepared, persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

fn external_graph(
    case: &mut PersistedCase,
    contract: &Value,
    activation: &Value,
    owner: &Value,
    stale: bool,
) {
    let image = b"original sleep executable";
    case.write("external-image.bin", image);
    let intent = json!({"format":"memcordon.linux-external-account-task-intent","revision":1,"program":b"/usr/bin/setpriv","arguments":[b"--reuid".as_slice(),b"61001",b"--regid",b"61001",b"--clear-groups",b"--",b"/usr/bin/sleep",b"300"],"environment_cleared":true,"uid":61001,"gid":61001,"selected_executable_sha256":sha256(image)});
    case.json("external-intent.json", &intent);
    let graph = prepared::prepared_graph(
        contract,
        activation,
        &owner["provider"],
        &case.record.run_id,
        &[b"tcp-http".to_vec(), hex::encode([7; 32]).into_bytes()],
        256 * 1024 * 1024,
        30000,
        b"original agent image",
    );
    let mut held = graph.native["caller"].clone();
    held["process_id"] = json!(800);
    held["birth"] = json!(900);
    held["namespace_pids"] = json!([800]);
    let live = json!({"format":"memcordon.linux-external-account-task","revision":1,"intent_sha256":sha256(&std::fs::read(case.root.path().join("external-intent.json")).unwrap()),"held":held,"kernel_image":{"device":1,"inode":850,"length":image.len(),"sha256":sha256(image)},"native_status":b"Uid:\t61001\t61001\t61001\t61001\nGid:\t61001\t61001\t61001\t61001\nGroups:\n".as_slice(),"uid":61001,"gid":61001,"creator":{"pid":106,"birth":305}});
    case.json("external-live.json", &live);
    case.json("external-at-refusal.json", &held);
    case.json("external-retired.json",&json!({"format":"memcordon.linux-external-account-retired","revision":1,"original_sha256":sha256(&std::fs::read(case.root.path().join("external-live.json")).unwrap()),"held":{"pid":800,"birth":900,"parent_pid":null,"parent_birth":null,"retirement_observed":true},"signal_sent":true,"raw_wait_status":9,"native_exit":null,"signal":9}));
    if stale {
        let dev = held["user"]["device"].as_u64().unwrap();
        let ino = held["user"]["inode"].as_u64().unwrap();
        let path = format!("/var/lib/memcordon/sealed/account-{dev}-{ino}-61001.reservation");
        let payload = json!({"format":"memcordon.account-reservation","revision":1,"user_namespace_device":dev,"user_namespace_inode":ino,"uid":61001,"attempt":vec![7;16],"owner_pid":800,"owner_birth":900,"boot_identity":"11111111-2222-3333-4444-555555555555"});
        let parents=["/","/var","/var/lib","/var/lib/memcordon","/var/lib/memcordon/sealed"].into_iter().enumerate().map(|(n,path)|json!({"path":path,"device":1,"inode":700+n,"uid":0,"mode":0o040700,"nlink":2})).collect::<Vec<_>>();
        let parent = json!({"device":1,"inode":704,"uid":0,"mode":0o040700});
        let digest = sha256(&serde_json::to_vec(&payload).unwrap());
        case.json("reservation-intent.json",&json!({"format":"memcordon.linux-stale-reservation-intent","revision":1,"path":path,"payload":payload,"payload_sha256":digest,"parent":parent}));
        let live = json!({"format":"memcordon.linux-stale-reservation-live","revision":1,"path":path,"payload":payload,"device":1,"inode":750,"uid":0,"gid":0,"mode":0o100600,"nlink":1,"payload_sha256":digest,"parent":parent,"parents":parents});
        case.json("reservation-live.json", &live);
        let closure=parents.iter().enumerate().map(|(n,parent)|json!({"index":n,"path":parent["path"],"device":parent["device"],"inode":parent["inode"],"named_device":parent["device"],"named_inode":parent["inode"],"uid":0,"mode":parent["mode"],"closed":true,"native_errno":null})).collect::<Vec<_>>();
        case.json("reservation-retired.json",&json!({"format":"memcordon.linux-stale-reservation-retired","revision":1,"original":live,"path":path,"native_errno":2,"held_nlink":0,"closed":true,"parents":closure}));
    }
}

fn alias_graph(
    case: &mut PersistedCase,
    contract: &Value,
    activation: &Value,
    owner: &Value,
    original: &LinuxMalformedIngressEvidence,
) {
    use sha2::{Digest, Sha256};
    let baseline: memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3 =
        serde_json::from_value(owner["baseline_registry"].clone()).unwrap();
    baseline.validate().unwrap();
    let mut policy = owner["baseline_registry"].clone();
    policy["execution_identities"][0]["uid"] = 65534.into();
    policy["execution_identities"][0]["gid"] = 65534.into();
    let definition: memcordon_core::workload_registry_v3::ExclusiveIdentityDefinitionV3 =
        serde_json::from_value(policy["execution_identities"][0].clone()).unwrap();
    let reference = definition.reference().unwrap();
    let mut typed: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(contract.clone()).unwrap();
    typed.execution_identity = reference.clone();
    let digest = memcordon_core::DiagnosticSha256::from_bytes(
        Sha256::digest(
            serde_json::to_vec(&(
                &typed.runtime_image,
                &typed.input_image,
                &typed.root_layout,
                &typed.execution_identity,
                &typed.requirements,
            ))
            .unwrap(),
        )
        .into(),
    );
    policy["grants"][0]["execution_identity"] = json!(reference);
    policy["grants"][0]["approved_plans"] = json!([digest]);
    let candidate: memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3 =
        serde_json::from_value(policy.clone()).unwrap();
    assert_eq!(
        candidate.validate().unwrap_err(),
        "exclusive account id/uid/reservation alias across current or legacy policy"
    );
    case.json("alias-candidate.json", &policy);
    case.json("alias-baseline-contract.json", contract);
    let rejection = b"exclusive account id/uid/reservation alias across current or legacy policy\n";
    let mut commands = Vec::new();
    for (stem, apply) in [
        ("alias-before", false),
        ("alias-rejection", true),
        ("alias-after", false),
    ] {
        let mut command = json!({"format":if apply {"memcordon.linux-policy-activation-command"}else{"memcordon.linux-policy-inspection-command"},"revision":1,"agent_sha256":sha256(b"original agent image"),"program":b"/usr/libexec/memcordon-sealed-agent".as_slice(),"arguments":[],"cwd":b"/owned/account","environment_cleared":true,"budget_millis":1000});
        command["arguments"] = if apply {
            let source = [
                owner["admin_root"].as_str().unwrap(),
                "isolation-alias-account",
                "alias-rejection.policy.json",
            ]
            .join("/");
            command["policy_sha256"] = json!(sha256(
                &std::fs::read(case.root.path().join("alias-candidate.json")).unwrap()
            ));
            json!([
                b"package".as_slice(),
                b"policy",
                b"apply",
                b"--file",
                source.as_bytes()
            ])
        } else {
            json!([b"package".as_slice(), b"policy", b"inspect", b"--json"])
        };
        let invocation = format!("{stem}.invocation.json");
        let exit = format!("{stem}.exit.json");
        let stdout = format!("{stem}.json");
        let stderr = format!("{stem}.stderr.bin");
        case.json(&invocation, &command);
        if apply {
            case.write(&stdout, b"");
            case.write(&stderr, rejection);
        } else {
            case.json(&stdout, activation);
            case.write(&stderr, b"");
        }
        case.json(&exit,&json!({"format":if apply {"memcordon.linux-policy-activation-exit"}else{"memcordon.linux-policy-inspection-exit"},"revision":1,"native_exit":if apply {125}else{0},"success":!apply,"invocation_sha256":sha256(&std::fs::read(case.root.path().join(&invocation)).unwrap()),"stdout_sha256":sha256(&std::fs::read(case.root.path().join(&stdout)).unwrap()),"stderr_sha256":sha256(&std::fs::read(case.root.path().join(&stderr)).unwrap())}));
        commands.push(NativeAliasPolicyCommand {
            invocation,
            exit,
            stdout,
            stderr,
        });
    }
    let evidence = LinuxAccountAliasPolicyEvidence {
        format: "memcordon.consumer-readiness.linux-account-alias-policy-refusal".into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: case.record.run_id.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        owner: original.owner.clone(),
        original_lease: original.original_lease.clone(),
        acquisition: original.acquisition.clone(),
        baseline_contract: "alias-baseline-contract.json".into(),
        baseline_activation: original.activation.clone(),
        account_intent: original.account_intent.clone(),
        account_readback: original.account_readback.clone(),
        group_readback: original.group_readback.clone(),
        candidate_policy: "alias-candidate.json".into(),
        before: commands.remove(0),
        rejected: commands.remove(0),
        after: commands.remove(0),
    };
    case.json("case-evidence.json", &json!(evidence));
}

pub fn baseline(scenario: &str) -> PersistedCase {
    let mut case = ingress::baseline();
    let original: LinuxMalformedIngressEvidence =
        serde_json::from_value(installed::read(&case, "case-evidence.json")).unwrap();
    case.record.key.family = "L-ISO-06".into();
    case.record.key.scenario = scenario.into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let owner = installed::read(&case, &original.owner);
    let activation = installed::read(&case, &original.activation);
    let request = installed::read(&case, &original.original_request);
    let baseline_contract = request["contract"].clone();
    let contract = baseline_contract.clone();
    let active = activation.clone();
    let alias = scenario == "account-alias";
    let stale = scenario == "stale-reservation";
    if alias {
        // Production retains legacy caller grants; the hostile fixture must
        // reach the same cross-generation caller separation guard.
        let profile = memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1;
        let legacy = json!({"format":"memcordon.local-private-policy","revision":1,
            "profiles":[{"profile":profile,"reference":profile.reference(),"enabled":true}],"execution_identities":[],
            "grants":[{"id":"installed-preserved","revision":1,"profile":profile.reference(),"ceiling":profile.ceiling(),"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":[sha256(b"original installed fixture")],"execution_identity":{"kind":"preserve-caller"}}],"active_attempt_disposition":"drain-existing"});
        let mut owner = owner;
        owner["baseline_registry"]["legacy"] = legacy.clone();
        let mut activation = activation;
        activation["registry"] = owner["baseline_registry"].clone();
        activation["registry_digest"] =
            json!(linux_registry_digest(&activation["registry"], &case.record.key.target).unwrap());
        case.json(&original.owner, &owner);
        case.json(&original.activation, &activation);
        for path in [&original.original_lease, &original.acquisition] {
            case.mutate(path, |raw| raw["legacy"] = legacy.clone());
        }
        alias_graph(
            &mut case,
            &baseline_contract,
            &activation,
            &owner,
            &original,
        );
        return case;
    }
    case.json("account-baseline.json", &baseline_contract);
    case.json("account-contract.json", &contract);
    case.json("account-activation.json", &active);
    case.write("challenge.bin", &[7; 32]);
    let mut request = request;
    request["contract"] = contract.clone();
    request["attempt_deadline_millis"] = json!(30000);
    let request_path = "07070707070707070707070707070707.provider-request.bin";
    case.json(request_path, &request);
    let mut command = installed::read(&case, &original.original_frontend);
    command["arguments"][8] = json!(b"+30000ms".to_vec());
    case.json("account-frontend.json", &command);
    let public = json!({"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+256M"},{"kind":"time","token":"+30000ms"}],"memory_token":"+256M","deadline_token":"+30000ms","argv":[{"display":"owned-readiness","raw":null},{"display":"tcp-http","raw":null},{"display":hex::encode([7;32]),"raw":null}]});
    case.json("account-public.json", &public);
    let reason = if alias {
        "host-prerequisite-unavailable"
    } else {
        "exclusive-account-unavailable"
    };
    let typed: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(contract.clone()).unwrap();
    let result = json!({"format":"memcordon.result","revision":2,"tool":{"name":"memcordon","version":case.index.version,"os":"linux","architecture":case.record.key.target.split('-').next().unwrap(),"runtime_features":["sealed-runtime","private-tcp"]},"invocation":public,
        "runtime":{"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,"outcome":{"kind":"rejected-before-authorization","request_sha256":typed.digest().unwrap(),"request_bytes_sha256":sha256(&std::fs::read(case.root.path().join(request_path)).unwrap()),"reason":reason,"detail":if alias{"exclusive target must be enabled and distinct from frontend"}else{"original exclusive account unavailable"},"allocation":{"authorization":"never-authorized","obligations":[]}}},
        "delivery":{"prepared-by":{"writer_pid":108}},"frontend":{"relay_drained":true,"interruption":null,"relay_error":null},"wrapper_status":125});
    case.json("account-result.json", &result);
    case.write("account-stdout.bin", b"");
    case.write("account-stderr.bin", b"original account refusal\n");
    case.json("account-exit.json",&json!({"format":"memcordon.linux-policy-frontend-exit","revision":1,"process_id":108,"process_birth":306,"raw_wait_status":125*256,"native_exit":125,"signal":null,"invocation_sha256":sha256(&std::fs::read(case.root.path().join("account-frontend.json")).unwrap()),"stdout_sha256":sha256(b""),"stderr_sha256":sha256(b"original account refusal\n")}));
    let mut census = installed::read(&case, &original.census);
    census["scenario"] = json!(scenario);
    census["result_sha256"] = json!(sha256(
        &std::fs::read(case.root.path().join("account-result.json")).unwrap()
    ));
    census["request_sha256"] = json!(sha256(
        &std::fs::read(case.root.path().join(request_path)).unwrap()
    ));
    case.json("account-census.json", &census);
    if !alias {
        external_graph(&mut case, &baseline_contract, &activation, &owner, stale);
    }
    let optional = |name: &str, enabled: bool| enabled.then(|| name.to_owned());
    let evidence = LinuxAccountRefusalEvidence {
        format: "memcordon.consumer-readiness.linux-account-refusal".into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: case.record.run_id.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        owner: original.owner,
        original_lease: original.original_lease,
        acquisition: original.acquisition,
        baseline_contract: "account-baseline.json".into(),
        baseline_activation: original.activation,
        contract: "account-contract.json".into(),
        activation: "account-activation.json".into(),
        challenge: "challenge.bin".into(),
        public_invocation: "account-public.json".into(),
        frontend_invocation: "account-frontend.json".into(),
        frontend_exit: "account-exit.json".into(),
        result: "account-result.json".into(),
        provider_request: request_path.into(),
        stdout: "account-stdout.bin".into(),
        stderr: "account-stderr.bin".into(),
        census: "account-census.json".into(),
        account_intent: original.account_intent,
        account_readback: original.account_readback,
        group_readback: original.group_readback,
        external_intent: optional("external-intent.json", !alias),
        external_image: optional("external-image.bin", !alias),
        external_live: optional("external-live.json", !alias),
        external_at_refusal: optional("external-at-refusal.json", !alias && !stale),
        external_retired: optional("external-retired.json", !alias),
        reservation_intent: optional("reservation-intent.json", stale),
        reservation_live: optional("reservation-live.json", stale),
        reservation_retired: optional("reservation-retired.json", stale),
        alias_policy: optional("alias-policy.json", alias),
        alias_invocation: optional("alias-command.json", alias),
        alias_exit: optional("alias-exit.json", alias),
        alias_stderr: optional("alias-stderr.bin", alias),
        restoration: optional("restoration.json", alias),
        restoration_policy: optional("restoration-policy.json", alias),
        restoration_invocation: optional("restoration-command.json", alias),
        restoration_exit: optional("restoration-exit.json", alias),
        restoration_stderr: optional("restoration-stderr.bin", alias),
    };
    case.json("case-evidence.json", &json!(evidence));
    case
}
