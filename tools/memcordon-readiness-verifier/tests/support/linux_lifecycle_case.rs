//! Complete persisted parser graphs; these do not assert native execution.
use super::{
    linux_installed_case as installed, linux_prepared_case as prepared,
    persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

pub fn allocation_case(actor: &str) -> PersistedCase {
    loss_case(actor, "allocation")
}

pub fn loss_case(actor: &str, phase: &str) -> PersistedCase {
    case_graph(actor, phase, false)
}

pub fn delivery_case() -> PersistedCase {
    case_graph("frontend", "allocation", true)
}

fn case_graph(actor: &str, phase: &str, delivery: bool) -> PersistedCase {
    assert!(["frontend", "worker", "guardian", "control"].contains(&actor));
    assert!(["allocation", "release", "drain"].contains(&phase));
    let scenario = if delivery {
        "report-persistence-failure".into()
    } else {
        format!("{actor}-{phase}")
    };
    let mut case =
        installed::installed(if delivery { "L-LIFE-05" } else { "L-LIFE-02" }, &scenario);
    let original = installed::read(&case, "installed/mixed-cases/image-cases/owner.json");
    let fixture = b"original owned fixture";
    let agent = b"original agent image";
    let cli = b"original CLI image";
    let image = |id: &str, path: &str| {
        json!({"format":"memcordon.runtime-image","revision":1,"image_id":id,"target":case.record.key.target,
        "entries":[{"kind":"regular","path":path,"sha256":sha256(fixture),"size":fixture.len(),"executable":true}],
        "entrypoints":[{"id":"owned-readiness","path":path}],"library_directories":[],"startup_environment":[]})
    };
    let runtime = image("original-runtime", "bin/owned-readiness");
    let input = image("original-input", "inputs/owned-readiness");
    let outputs = if phase == "drain" {
        vec![
            "work/orphan-descendant.bin".into(),
            "work/orphan-completion.json".into(),
        ]
    } else {
        vec![]
    };
    let (contract, _, activation) =
        installed::activation(&mut case, runtime, input, outputs, json!([]));
    let prefix = format!(
        "{}/{}/linux-mixed/recipe-0",
        case.record.key.target,
        case.record.key.channel.as_deref().unwrap()
    );
    let directory = format!("{}/{prefix}", installed::EVIDENCE_ROOT);
    let path = |name: &str| format!("{prefix}/{name}");
    let frontend_directory = format!(
        "{}/installed/mixed-cases/recipe-0",
        installed::EVIDENCE_ROOT
    );
    let challenge = vec![7u8; 32];
    let mut argv = vec![
        if delivery {
            b"bytes-argv-status".to_vec()
        } else if phase == "drain" {
            b"root-first".to_vec()
        } else {
            b"held-tree".to_vec()
        },
        hex::encode(&challenge).into_bytes(),
    ];
    if delivery {
        argv.push(b"0".to_vec());
    }
    let graph = prepared::prepared_graph(
        &contract,
        &activation,
        &original["provider"],
        &case.record.run_id,
        &argv,
        512 * 1024 * 1024,
        300000,
        agent,
    );
    let attempt = graph.prepared["admission"]["attempt_id"].as_str().unwrap();
    let identity = original["identity"].clone();
    let cell = original["cell"].clone();
    let key = serde_json::to_value(&case.record.key).unwrap();
    let mut peers = Vec::<BehaviorArtifact>::new();
    let mut persist = |case: &mut PersistedCase, name: &str, bytes: &[u8]| {
        let relative = path(name);
        case.write(&relative, bytes);
        peers.push(BehaviorArtifact {
            role: name.into(),
            path: relative,
        });
    };
    persist(&mut case, "challenge.bin", &challenge);
    for (name, bytes) in [
        ("selected-cli-image.bin", cli.as_slice()),
        ("selected-agent-image.bin", agent.as_slice()),
    ] {
        persist(&mut case, name, bytes);
    }
    let manifest = std::fs::read(case.root.path().join("runtime-manifest.json")).unwrap();
    persist(&mut case, "selected-runtime-manifest.json", &manifest);
    for (name, value) in [
        (
            "original-lease-owner.json",
            installed::read(&case, "installed/lease-owner.json"),
        ),
        (
            "original-acquisition.json",
            installed::read(&case, "installed/owned-resources-acquired.json"),
        ),
        ("original-activation.json", activation.clone()),
        ("original-contract.json", contract.clone()),
        ("prepared.json", graph.prepared.clone()),
        ("prepared-native-before-ack.json", graph.native.clone()),
        ("provider-request.bin", graph.request.clone()),
    ] {
        persist(&mut case, name, &serde_json::to_vec(&value).unwrap());
    }
    persist(
        &mut case,
        "allocation-phase-journal.bin",
        &graph.journal_bytes,
    );
    let mut phase_journal = graph.journal.clone();
    if phase == "drain" {
        phase_journal["phase"] = json!("retiring");
        phase_journal["release_knowledge"] = json!("exec-observed");
    }
    let phase_bytes = prepared::durable_journal(&phase_journal);
    if !delivery {
        persist(&mut case, "phase-journal.bin", &phase_bytes);
    }
    let mut arguments = vec![
        "--reuid",
        "65534",
        "--regid",
        "65534",
        "--clear-groups",
        "--",
        "/usr/libexec/memcordon",
        "+512M",
        "+300s",
        "--sealed",
        "--workload-contract",
    ]
    .into_iter()
    .map(|text| text.as_bytes().to_vec())
    .collect::<Vec<_>>();
    arguments.push(format!("{frontend_directory}/mixed.contract.json").into_bytes());
    arguments.extend([
        b"--report-format".to_vec(),
        b"result-v2".to_vec(),
        b"--report".to_vec(),
        format!("{frontend_directory}/frontend/result.json").into_bytes(),
        b"--mixed-observation-directory".to_vec(),
        format!("{frontend_directory}/frontend/observations").into_bytes(),
        b"--image-entrypoint".to_vec(),
        b"owned-readiness".to_vec(),
        b"--".to_vec(),
    ]);
    arguments.extend(argv.clone());
    let command = json!({"format":"memcordon.linux-owned-frontend-invocation","revision":1,"program":b"/usr/bin/setpriv","arguments":arguments,
        "environment_cleared":true,"caller_uid":65534,"caller_gid":65534,"selected_cli_sha256":sha256(cli)});
    let command_bytes = serde_json::to_vec(&command).unwrap();
    persist(&mut case, "frontend-invocation.json", &command_bytes);
    let preinput = json!({"format":"memcordon.linux-lifecycle-frontend-preinput","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","key":key,
        "process":prepared::held(102,301,false),"held_at_prepared_barrier":true,"invocation_sha256":sha256(&command_bytes),"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    persist(
        &mut case,
        "frontend-preinput.json",
        &serde_json::to_vec(&preinput).unwrap(),
    );
    let (pid, birth, selected) = match actor {
        "frontend" => (102, 301, cli.as_slice()),
        "guardian" => (105, 304, agent.as_slice()),
        _ => (101, 300, agent.as_slice()),
    };
    let release = if phase == "release" {
        json!({"format":"memcordon.mixed-release-observation","revision":2,"prepared":graph.prepared,"authorizes_launch":false})
    } else {
        Value::Null
    };
    if phase == "release" {
        persist(
            &mut case,
            "release-prepared.json",
            &serde_json::to_vec(&release).unwrap(),
        );
    }
    let intent = json!({"format":"memcordon.linux-lifecycle-controller-intent","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","key":key,"attempt_id":attempt,
        "actor":prepared::held(pid,birth,false),"phase":phase_journal["phase"],"release_knowledge":phase_journal["release_knowledge"],"journal_sha256":sha256(&phase_bytes),"release_barrier":release,
        "native_image":{"device":1,"inode":500,"length":selected.len(),"sha256":sha256(selected)},"selected_image_sha256":sha256(selected),"native_operation":if actor=="control"{"socket-shutdown"}else{"pidfd-sigkill"}});
    let action = if actor == "control" {
        json!({"format":"memcordon.linux-lifecycle-control-shutdown","revision":1,"worker":{"pid":101,"birth":300},"caller":{"pid":102,"birth":301},
        "source_descriptor":13,"device":1,"inode":700,"peer_uid":65534,"peer_gid":65534,"socket_type":1,"socket_domain":1,
        "caller_status_bytes":b"Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n".as_slice(),"native_how":2,"native_status":0,"native_errno":null})
    } else {
        json!({"format":"memcordon.linux-lifecycle-pidfd-kill","revision":1,"actor":intent["actor"],"signal":9,"native_status":0,"native_errno":null})
    };
    if !delivery {
        persist(
            &mut case,
            "controller-intent.json",
            &serde_json::to_vec(&intent).unwrap(),
        );
        persist(
            &mut case,
            "controller-action.json",
            &serde_json::to_vec(&action).unwrap(),
        );
    }
    let (raw_wait, native_exit, signal) = if actor == "frontend" && !delivery {
        (9, None, Some(9))
    } else {
        (125 * 256, Some(125), None)
    };
    let transcript = if phase == "drain" {
        vec![
            json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":1,"challenge":hex::encode(&challenge),"root_pid":2,"root_birth":302,
        "operation":"root-exiting-before-held-descendant","observation":{"pid":3,"birth":307,"parent_pid":2,"members":[]}}),
        ]
    } else {
        vec![]
    };
    let stdout = if phase == "drain" {
        let mut bytes = serde_json::to_vec(&transcript[0]).unwrap();
        bytes.push(b'\n');
        bytes
    } else {
        vec![]
    };
    let wait = json!({"format":"memcordon.linux-policy-frontend-exit","revision":1,"process_id":102,"process_birth":301,"raw_wait_status":raw_wait,"native_exit":native_exit,"signal":signal,
        "invocation_sha256":sha256(&command_bytes),"stdout_sha256":sha256(&stdout),"stderr_sha256":sha256(b"")});
    persist(
        &mut case,
        "frontend-wait.json",
        &serde_json::to_vec(&wait).unwrap(),
    );
    persist(&mut case, "stdout.bin", &stdout);
    persist(&mut case, "stderr.bin", b"");
    let descendants = if phase == "drain" {
        let mut held = prepared::held(108, 307, true);
        held["parent_pid"] = json!(103);
        held["parent_birth"] = json!(302);
        vec![json!({"identity":held,"namespace_pid":3})]
    } else {
        vec![]
    };
    let family = json!({"format":"memcordon.linux-lifecycle-native-family-retirement","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","key":key,"attempt_id":attempt,
        "frontend":prepared::held(102,301,true),"target":prepared::held(103,302,true),"namespace_init":prepared::held(104,303,true),"guardian":prepared::held(105,304,true),
        "worker":prepared::held(101,300,true),"actor":prepared::held(pid,birth,true),"descendants":descendants,"transcript":transcript});
    persist(
        &mut case,
        "native-family-retirement.json",
        &serde_json::to_vec(&family).unwrap(),
    );
    let recovery = json!({"format":"memcordon.linux-lifecycle-native-recovery-invocation","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","key":key,
        "program":"/usr/libexec/memcordon-sealed-agent","arguments":["package","policy","recover","--json"],"cwd_native_bytes":directory.as_bytes(),"timeout_millis":60000,
        "work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200,"cleanup_deadline_scope":"original-installed-lease","cleared_environment":true,"selected_agent_sha256":sha256(agent)});
    let recovery_bytes = serde_json::to_vec(&recovery).unwrap();
    let recovered = serde_json::to_vec(
        &json!({"format":"memcordon.native-recovery","revision":1,"outstanding":[]}),
    )
    .unwrap();
    let recovery_process = json!({"format":"memcordon.linux-lifecycle-native-recovery-process","revision":1,"preinput":prepared::held(107,306,false),"process":prepared::held(107,306,true),
        "native_image":{"device":1,"inode":501,"length":agent.len(),"sha256":sha256(agent)},"invocation_sha256":sha256(&recovery_bytes),"raw_wait_status":0,"native_exit":0,"signal":null,"stdout_sha256":sha256(&recovered),"stderr_sha256":sha256(b"")});
    persist(
        &mut case,
        "native-recovery-invocation.json",
        &recovery_bytes,
    );
    persist(
        &mut case,
        "native-recovery-process.json",
        &serde_json::to_vec(&recovery_process).unwrap(),
    );
    persist(&mut case, "native-recovery-stdout.bin", &recovered);
    persist(&mut case, "native-recovery-stderr.bin", b"");
    let census = json!({"format":"memcordon.linux-policy-native-census","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","scenario":scenario,"attempt_id":attempt,"provider":original["provider"],"account":original["account"],
        "result_sha256":sha256(b""),"request_sha256":sha256(&serde_json::to_vec(&graph.request).unwrap()),"tasks":[{"pid":1,"tid":1,"birth":1,"uids":[0,0,0,0],"gids":[0,0,0,0],"groups":[]}],
        "cgroup_root":{"path":"/sys/fs/cgroup/memcordon-sealed","device":7,"inode":10,"uid":0,"mode":0o40700,"filesystem_type":0x63677270u64,"attempt_directories":[],"attempt_absence_errno":2},
        "journal_root":{"path":"/var/lib/memcordon/sealed","device":7,"inode":11,"uid":0,"mode":0o40700,"attempt_absence_errno":2}});
    persist(
        &mut case,
        "recovered-ownership.json",
        &serde_json::to_vec(&census).unwrap(),
    );
    if delivery {
        let export = json!({"format":"memcordon.private-export","revision":1,"attempt_id":attempt,"root_layout":contract["root_layout"],"identity":contract["execution_identity"]["identity"],"files":[]});
        let export_bytes = serde_json::to_vec(&export).unwrap();
        persist(&mut case, "export-receipt.json", &export_bytes);
        let result = executed_result(
            &case,
            &graph,
            &original,
            &contract,
            &argv,
            sha256(&export_bytes),
        );
        let result_bytes = serde_json::to_vec(&result).unwrap();
        persist(
            &mut case,
            "provider-terminal.json",
            &serde_json::to_vec(&result["runtime"]).unwrap(),
        );
        let destination = json!({"device":1,"inode":800,"uid":65534,"gid":65534,"mode":0o040700,"is_directory":true});
        let before = json!({"format":"memcordon.linux-report-destination","revision":1,"path":format!("{frontend_directory}/frontend/result.json").as_bytes(),
            "device":1,"inode":800,"uid":65534,"gid":65534,"mode":0o040700,"is_directory":true});
        let failure = json!({"format":"memcordon.linux-native-report-delivery-failure","revision":1,"report_path":before["path"],"submitted_report":result_bytes,
            "native_errno":21,"native_error_code":"MCREPORT-WRITE","destination":destination,"frontend_pid":102});
        persist(
            &mut case,
            "report-destination.json",
            &serde_json::to_vec(&before).unwrap(),
        );
        persist(
            &mut case,
            "report-delivery-failure.json",
            &serde_json::to_vec(&failure).unwrap(),
        );
    }
    let allocation = json!({"format":"memcordon.linux-lifecycle-allocation","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","key":key,"attempt_id":attempt,"worker_index":0,
        "worker_source":graph.worker,"phase":"checkpoint-committed","release_knowledge":"not-released","journal_sha256":sha256(&graph.journal_bytes),"prepared":graph.prepared,"frontend_invocation":command});
    let observations = if delivery {
        vec![allocation]
    } else {
        vec![
            allocation,
            json!({"format":"memcordon.linux-lifecycle-intervention","revision":1,"key":key,"intent":intent,"action":action}),
        ]
    };
    let raw = json!({"format":"memcordon.linux-lifecycle-loss-raw","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","key":key,
        "observations":observations,"frontend_wait":wait,"result_present":false,"result_absence_errno":if delivery{Value::Null}else{json!(2)},"report_destination_directory":delivery});
    case.json(&path("lifecycle-loss-raw.json"), &raw);
    let owner = json!({"format":"memcordon.linux-lifecycle-owner","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","provider":original["provider"],
        "lease_owner":path("original-lease-owner.json"),"acquisition":path("original-acquisition.json"),"activation":path("original-activation.json"),"contract":path("original-contract.json"),
        "runtime_manifest":path("selected-runtime-manifest.json"),"selected_cli":path("selected-cli-image.bin"),"selected_agent":path("selected-agent-image.bin"),"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    case.json(&path("lifecycle-owner.json"), &owner);
    case.write(&path("fixture.bin"), fixture);
    case.json(&path("fixture-source.json"),&json!({
        "module":include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../crates/memcordon-cli/src/bin/consumer_readiness_linux/mod.rs")).as_slice(),
        "entrypoint":include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../crates/memcordon-cli/src/bin/memcordon-linux-readiness-fixture.rs")).as_slice()}));
    let input = FixtureInput {
        format: "memcordon.consumer-readiness.input".into(),
        revision: 1,
        run_id: case.record.run_id.clone(),
        key: case.record.key.clone(),
        challenge_sha256: sha256(&challenge),
        binary: vec![],
        target_argv: NativeArguments::UnixBytes(argv),
        deadline_millis: Some(300000),
        memory_bytes: Some(512 * 1024 * 1024),
        toolchain_identity: None,
    };
    case.json(
        &path("fixture-input.json"),
        &serde_json::to_value(input).unwrap(),
    );
    let source = std::fs::read(case.root.path().join(path("fixture-source.json"))).unwrap();
    let evidence = LinuxLifecycleLossEvidence {
        format: if delivery {
            "memcordon.consumer-readiness.linux-delivery"
        } else {
            "memcordon.consumer-readiness.linux-lifecycle-loss"
        }
        .into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: case.record.run_id.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        fixture: path("fixture.bin"),
        fixture_sha256: sha256(fixture),
        fixture_source: path("fixture-source.json"),
        fixture_source_sha256: sha256(&source),
        input: path("fixture-input.json"),
        owner: path("lifecycle-owner.json"),
        raw: path("lifecycle-loss-raw.json"),
        artifacts: peers,
    };
    case.json(
        "case-evidence.json",
        &serde_json::to_value(evidence).unwrap(),
    );
    case
}

pub(crate) fn executed_result(
    case: &PersistedCase,
    graph: &prepared::PreparedGraph,
    owner: &Value,
    contract: &Value,
    argv: &[Vec<u8>],
    export_hash: String,
) -> Value {
    let mut filter = Vec::new();
    for instruction in frozen_linux_filter_program("x86_64").unwrap() {
        filter.extend(instruction.code.to_le_bytes());
        filter.extend([instruction.jt, instruction.jf]);
        filter.extend(instruction.k.to_le_bytes());
    }
    let mut execution = json!({"host_target":case.record.key.target,"boot_id":graph.journal["boot_identity"],
        "caller_uid":65534,"caller_gid":65534,"target_uid":owner["account"]["uid"],"target_gid":owner["account"]["gid"],
        "supplementary_groups":[],"init_uid":0,"init_nondumpable":true,"no_new_privileges":true,"capabilities_empty":true,
        "filter_abi":"x86_64","filter_instruction_sha256":sha256(&filter),"target_authorized":true,"exec_observed":true,"post_exec_descriptor_count":3,
        "native_wait_status":0,"outcome_origin":"native-exit","authorization_monotonic_millis":10,"root_device":1,"root_inode":900});
    for field in [
        "caller",
        "target",
        "namespace_init",
        "guardian",
        "user_namespace",
        "mount_namespace",
        "pid_namespace",
        "network_namespace",
        "ipc_namespace",
    ] {
        execution[field] = graph.prepared[field].clone();
    }
    for (field, native) in [
        ("caller_user_namespace", "user"),
        ("caller_mount_namespace", "mount"),
        ("caller_pid_namespace", "pid"),
        ("caller_network_namespace", "network"),
        ("caller_ipc_namespace", "ipc"),
    ] {
        execution[field] = graph.native["caller"][native].clone();
    }
    for field in [
        "runtime_image",
        "input_image",
        "root_layout",
        "execution_identity",
    ] {
        execution[field] = contract[field].clone();
    }
    let retirement = json!({"attempt_id":graph.prepared["admission"]["attempt_id"],"workload_empty":true,"init_reaped":true,"guardian_reaped":true,
        "relays_drained_and_closed":true,"namespace_references_closed":true,"root_references_closed":true,"staging_removed":true,
        "account_quiescent":true,"reservation_retired":true,"export_receipt_sha256":export_hash});
    let mut public = vec![json!({"display":"owned-readiness","raw":null})];
    for argument in argv {
        public.push(json!({"display":std::str::from_utf8(argument).unwrap(),"raw":null}));
    }
    json!({"format":"memcordon.result","revision":2,"tool":{"name":"memcordon","version":case.index.version,"os":"linux","architecture":"x86_64","runtime_features":["sealed-runtime","private-tcp"]},
        "invocation":{"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+512M"},{"kind":"time","token":"+300s"}],"memory_token":"+512M","deadline_token":"+300s","argv":public},
        "runtime":{"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,"outcome":{"kind":"executed","admission":graph.prepared["admission"],
            "request_bytes_sha256":sha256(&serde_json::to_vec(&graph.request).unwrap()),"provider":owner["provider"],"execution":execution,"retirement":retirement}},
        "delivery":{"prepared-by":{"writer_pid":102}},"frontend":{"relay_drained":true,"interruption":null,"relay_error":null},"wrapper_status":0})
}
