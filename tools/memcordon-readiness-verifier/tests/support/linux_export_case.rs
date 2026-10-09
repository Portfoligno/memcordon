//! Full persisted decoder vectors; these are never native execution evidence.
use super::{linux_installed_case, linux_prepared_case, persisted_case::PersistedCase};
use memcordon_readiness_verifier::{LinuxImageExportEvidence, sha256};
use serde_json::{Value, json};

pub struct ExportGraph {
    pub case: PersistedCase,
    pub evidence: LinuxImageExportEvidence,
    pub owner: Value,
    pub prepared: linux_prepared_case::PreparedGraph,
    pub prefix: String,
    pub directory: String,
}

pub fn original_graph(scenario: &str) -> ExportGraph {
    let key_scenario = format!("export-{scenario}");
    let mut case = linux_installed_case::installed("L-IMG-04", &key_scenario);
    let owner = linux_installed_case::read(&case, "installed/mixed-cases/image-cases/owner.json");
    let prefix = format!("installed/mixed-cases/image-cases/{key_scenario}");
    let directory = format!("{}/{key_scenario}", owner["output"].as_str().unwrap());
    let path = |leaf: &str| format!("{prefix}/{leaf}");
    let runtime = json!({"format":"memcordon.runtime-image","revision":1,"image_id":"original-runtime-image","target":case.record.key.target,
        "entries":[{"kind":"regular","path":"bin/owned-readiness","sha256":sha256(b"original immutable executable"),"size":29,"executable":true}],"entrypoints":[{"id":"owned-readiness","path":"bin/owned-readiness"}],"library_directories":[],"startup_environment":[]});
    let mut input = runtime.clone();
    input["image_id"] = json!("original-input-image");
    let requirements = if scenario == "socket" {
        json!([{"kind":"unix_path_stream","id":"pathname","writable_root":"work"}])
    } else {
        json!([])
    };
    let (contract, policy, activation) = linux_installed_case::activation(
        &mut case,
        runtime,
        input,
        vec![if scenario == "traversal" {
            "work/parent/exported.bin".into()
        } else {
            "work/exported.bin".into()
        }],
        requirements,
    );
    let challenge = vec![7u8; 32];
    let challenge_hex = hex::encode(&challenge);
    let arguments = vec![
        b"export-object".to_vec(),
        challenge_hex.as_bytes().to_vec(),
        scenario.as_bytes().to_vec(),
    ];
    let mut graph = linux_prepared_case::prepared_graph(
        &contract,
        &activation,
        &owner["provider"],
        "decoder-run",
        &arguments,
        512 * 1024 * 1024,
        60000,
        b"original agent image",
    );
    graph.journal["phase"] = json!("retiring");
    graph.journal["release_knowledge"] = json!("exec-observed");
    let attempt = graph.prepared["admission"]["attempt_id"]
        .as_str()
        .unwrap()
        .to_owned();
    graph.journal["mixed_root_staging_intent"] =
        json!(format!("/run/memcordon/private-root-{attempt}"));
    graph.journal["mixed_staging_identity"] = json!({"device":1,"inode":500});
    graph.journal["mixed_export_intent"] =
        json!(format!("/run/memcordon/private-export-{attempt}"));
    graph.journal["mixed_export_identity"] = json!({"device":1,"inode":501});
    graph.journal_bytes = linux_prepared_case::durable_journal(&graph.journal);
    // Preserve the original pre-release worker receipt. Recovery reads the
    // later retiring journal from the same original admission and owners.
    let request_bytes = serde_json::to_vec(&graph.request).unwrap();
    let request_path = path(&format!(
        "launch/observations/{attempt}.provider-request.bin"
    ));
    case.write(&request_path, &request_bytes);
    let cause = match scenario {
        "symlink" | "traversal" => "Too many levels of symbolic links (os error 40)",
        "fifo" | "device" => "selected output lacks exclusive regular-file custody",
        "socket" => "No such device or address (os error 6)",
        "concurrent-writer" => "selected output native identity/content changed",
        _ => panic!("unknown finite export vector"),
    };
    let public_argv = [
        "owned-readiness",
        "export-object",
        challenge_hex.as_str(),
        scenario,
    ]
    .map(|value| json!({"display":value,"raw":null}));
    let result = json!({"format":"memcordon.result","revision":2,"tool":{"name":"memcordon","version":case.index.version,"os":"linux","architecture":"x86_64","runtime_features":["sealed-runtime","private-tcp"]},
        "invocation":{"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+512M"},{"kind":"time","token":"+60000ms"}],"memory_token":"+512M","deadline_token":"+60000ms","argv":public_argv},
        "runtime":{"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,"outcome":{"kind":"indeterminate","attempt_id":attempt,"request_sha256":graph.prepared["admission"]["request_sha256"],"retained_obligations":{"authorization":"authorized","obligations":[cause]}}},"delivery":{"prepared-by":{"writer_pid":102}},"frontend":{"relay_drained":true,"interruption":null,"relay_error":null},"wrapper_status":125});
    let ready = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":1,"challenge":challenge_hex,"root_pid":2,"root_birth":302,"operation":"export-object-ready",
        "observation":{"scenario":scenario,"path":if scenario=="traversal"{"/work/parent/exported.bin"}else{"/work/exported.bin"},"kind":match scenario{"symlink"=>"symlink","fifo"=>"fifo","device"=>"admin-device-required","socket"=>"socket","traversal"=>"parent-symlink",_=>"regular-with-held-writer"},"source_path":if scenario=="traversal"{json!("/work/other/exported.bin")}else{Value::Null}}});
    let mut stdout = serde_json::to_vec(&ready).unwrap();
    stdout.push(b'\n');
    case.write(&path("launch/stdout.bin"), &stdout);
    case.write(&path("launch/stderr.bin"), b"");
    let values = vec![
        "--reuid".into(),
        "65534".into(),
        "--regid".into(),
        "65534".into(),
        "--clear-groups".into(),
        "--".into(),
        "/usr/libexec/memcordon".into(),
        "+512M".into(),
        "+60000ms".into(),
        "--sealed".into(),
        "--workload-contract".into(),
        format!("{directory}/request.json"),
        "--report-format".into(),
        "result-v2".into(),
        "--report".into(),
        format!("{directory}/launch/result.json"),
        "--mixed-observation-directory".into(),
        format!("{directory}/launch/observations"),
        "--image-entrypoint".into(),
        "owned-readiness".into(),
        "--".into(),
        "export-object".into(),
        challenge_hex.clone(),
        scenario.into(),
    ];
    let command = json!({"format":"memcordon.linux-owned-frontend-invocation","revision":1,"program":b"/usr/bin/setpriv","arguments":values.iter().map(|value:&String|value.as_bytes()).collect::<Vec<_>>(),"environment_cleared":true,"caller_uid":65534,"caller_gid":65534,"selected_cli_sha256":sha256(b"original CLI image")});
    case.json(&path("frontend-invocation.json"), &command);
    let wait = json!({"format":"memcordon.linux-policy-frontend-exit","revision":1,"process_id":102,"process_birth":301,"raw_wait_status":125*256,"native_exit":125,"signal":null,"invocation_sha256":sha256(&std::fs::read(case.root.path().join(path("frontend-invocation.json"))).unwrap()),"stdout_sha256":sha256(&stdout),"stderr_sha256":sha256(b"")});
    let mut family = json!({"format":"memcordon.linux-export-held-retirement","revision":1,"attempt_id":attempt,"workers":[linux_prepared_case::held(101,300,true)]});
    for (role, pid, birth) in [
        ("caller", 102, 301),
        ("target", 103, 302),
        ("namespace_init", 104, 303),
        ("guardian", 105, 304),
    ] {
        family[role] = linux_prepared_case::held(pid, birth, true);
    }
    let kind = match scenario {
        "symlink" | "traversal" => 0o120000,
        "fifo" => 0o010000,
        "device" => 0o020000,
        "socket" => 0o140000,
        _ => 0o100000,
    };
    let source = json!({"format":"memcordon.linux-export-native-source","revision":1,"scenario":scenario,"attempt_id":attempt,"target":graph.native["target"],"root_device":1,"root_inode":900,"member":if scenario=="traversal"{"parent"}else{"exported.bin"},"device":1,"inode":700,"mode":kind|0o600,"uid":if scenario=="device"{0}else{61001},"gid":if scenario=="device"{0}else{61001},"nlink":1,"length":32,"ctime_seconds":100,"ctime_nanoseconds":1,"symlink_target":match scenario{"symlink"=>json!("/owned-source/Cargo.toml"),"traversal"=>json!("/work/other"),_=>Value::Null},"exclusive_uid":61001,"exclusive_gid":61001});
    for (leaf, value) in [
        ("request.json", contract),
        ("mixed.policy.json", policy),
        ("mixed.activation.json", activation),
        ("prepared.json", graph.prepared.clone()),
        ("prepared-native.json", graph.native.clone()),
        ("export-worker.json", graph.worker.clone()),
        ("ready.json", ready),
        ("native-export-source.json", source),
        ("native-family-retirement.json", family),
        ("frontend-native-wait.json", wait),
        ("launch/result.json", result),
    ] {
        case.json(&path(leaf), &value);
    }
    case.write(&path("challenge.bin"), &challenge);
    let evidence = LinuxImageExportEvidence {
        format: "memcordon.consumer-readiness.linux-image-export".into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: "decoder-run".into(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        owner: "installed/mixed-cases/image-cases/owner.json".into(),
        original_lease_owner: "installed/lease-owner.json".into(),
        observation: path("observation.json"),
        challenge: path("challenge.bin"),
        activation: path("mixed.activation.json"),
        policy: path("mixed.policy.json"),
        contract: path("request.json"),
        provider_request: request_path,
        result: path("launch/result.json"),
        prepared: path("prepared.json"),
        prepared_native: path("prepared-native.json"),
        ready: path("ready.json"),
        native_source: path("native-export-source.json"),
        native_worker: path("export-worker.json"),
        invocation: path("frontend-invocation.json"),
        native_wait: path("frontend-native-wait.json"),
        native_family: path("native-family-retirement.json"),
        stdout: path("launch/stdout.bin"),
        stderr: path("launch/stderr.bin"),
        controller_setup: None,
        external: Default::default(),
        recovery: path("export-recovery.json"),
        recovery_artifacts: Default::default(),
    };
    ExportGraph {
        case,
        evidence,
        owner,
        prepared: graph,
        prefix,
        directory,
    }
}

pub fn recovery(graph: &mut ExportGraph) {
    let owner = &graph.owner;
    let attempt = graph.prepared.prepared["admission"]["attempt_id"]
        .as_str()
        .unwrap();
    let scenario = graph.case.record.key.scenario.clone();
    let path = |leaf: &str| format!("{}/{leaf}", graph.prefix);
    let command = json!({"format":"memcordon.linux-export-recovery-invocation","revision":1,"identity":owner["identity"],"cell":owner["cell"],"lease_id":"original-lease","attempt_id":attempt,"program":"/usr/libexec/memcordon-sealed-agent","arguments":["package","policy","recover","--json"],"cwd_native_bytes":graph.directory.as_bytes(),"timeout_millis":60000,"cleared_environment":true,"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200,"selected_agent_sha256":sha256(b"original agent image")});
    graph.case.json(&path("recovery-invocation.json"), &command);
    graph.case.json(
        &path("recovery-stdout.bin"),
        &json!({"format":"memcordon.native-recovery","revision":1,"outstanding":[]}),
    );
    graph.case.write(&path("recovery-stderr.bin"), b"");
    let measured = |case: &PersistedCase, leaf: &str| {
        sha256(&std::fs::read(case.root.path().join(path(leaf))).unwrap())
    };
    let process = json!({"format":"memcordon.linux-export-recovery-process","revision":1,"preinput":linux_prepared_case::held(201,400,false),"process":linux_prepared_case::held(201,400,true),"native_image":{"device":1,"inode":402,"length":20,"sha256":sha256(b"original agent image")},"invocation_sha256":measured(&graph.case,"recovery-invocation.json"),"raw_wait_status":0,"native_exit":0,"signal":null,"stdout_sha256":measured(&graph.case,"recovery-stdout.bin"),"stderr_sha256":sha256(b"")});
    graph.case.json(&path("recovery-process.json"), &process);
    let provider_request_sha = sha256(
        &std::fs::read(
            graph
                .case
                .root
                .path()
                .join(&graph.evidence.provider_request),
        )
        .unwrap(),
    );
    let result_sha = measured(&graph.case, "launch/result.json");
    let census = json!({"format":"memcordon.linux-policy-native-census","revision":1,"identity":owner["identity"],"cell":owner["cell"],"lease_id":"original-lease","scenario":scenario,"attempt_id":attempt,"provider":owner["provider"],"account":owner["account"],"result_sha256":result_sha,"request_sha256":provider_request_sha,"tasks":[{"pid":1,"tid":1,"birth":1,"uids":[0,0,0,0],"gids":[0,0,0,0],"groups":[]}],"cgroup_root":{"path":"/sys/fs/cgroup/memcordon-sealed","device":1,"inode":400,"uid":0,"mode":0o040700,"filesystem_type":0x63677270u64,"attempt_directories":[],"attempt_absence_errno":2},"journal_root":{"path":"/var/lib/memcordon/sealed","device":1,"inode":399,"uid":0,"mode":0o040700,"attempt_absence_errno":2}});
    graph.case.json(&path("recovery-census.json"), &census);
    graph.case.write(
        &path("recovery-original-journal.bin"),
        &graph.prepared.journal_bytes,
    );
    let body = json!({"format":"memcordon.account-reservation","revision":1,"user_namespace_device":1,"user_namespace_inode":100,"uid":61001,"attempt":hex::decode(attempt).unwrap(),"owner_pid":101,"owner_birth":300,"boot_identity":graph.prepared.journal["boot_identity"]});
    let reservation_path = "/var/lib/memcordon/sealed/account-1-100-61001.reservation";
    let before_reservation = json!({"path":reservation_path,"device":1,"inode":600,"uid":0,"mode":0o100600,"nlink":1,"bytes":serde_json::to_vec(&body).unwrap()});
    let after_reservation = json!({"path":reservation_path,"device":1,"inode":600,"nlink":0,"native_errno":2,"closed":true,"close_native_errno":null});
    let parents=["/","/var","/var/lib","/var/lib/memcordon","/var/lib/memcordon/sealed"].iter().enumerate().map(|(ordinal,path)|json!({"path":path,"device":1,"inode":1000+ordinal,"uid":0,"mode":0o040700,"nlink":2,"named_device":1,"named_inode":1000+ordinal,"closed":true,"close_native_errno":null})).collect::<Vec<_>>();
    let mut parents = parents;
    parents[4]["inode"] = json!(399);
    parents[4]["named_inode"] = json!(399);
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut retired = Vec::new();
    for (field, identity) in [
        ("mixed_root_staging_intent", "mixed_staging_identity"),
        ("mixed_export_intent", "mixed_export_identity"),
    ] {
        let named = &graph.prepared.journal[field];
        let held = &graph.prepared.journal[identity];
        before.push(json!({"field":field,"path":named,"device":held["device"],"inode":held["inode"],"uid":0,"mode":0o040700}));
        after.push(json!({"path":named,"native_errno":2}));
        retired.push(json!({"path":named,"device":held["device"],"inode":held["inode"],"nlink":0,"closed":true,"close_native_errno":null}));
    }
    let recovery = json!({"format":"memcordon.linux-export-recovery","revision":1,"identity":owner["identity"],"cell":owner["cell"],"lease_id":"original-lease","scenario":scenario,"attempt_id":attempt,"original_journal_present":true,"original_journal_sha256":sha256(&graph.prepared.journal_bytes),"before_paths":before,"after_absence":after,"held_retirement":retired,"reservation_before":before_reservation,"reservation_after":after_reservation,"reservation_parents":parents,"invocation":"recovery-invocation.json","process":"recovery-process.json","stdout":"recovery-stdout.bin","stderr":"recovery-stderr.bin","census":"recovery-census.json","request_sha256":provider_request_sha,"result_sha256":result_sha,"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    graph.case.json(&graph.evidence.recovery, &recovery);
    for field in ["invocation", "process", "stdout", "stderr", "census"] {
        graph.evidence.recovery_artifacts.insert(
            field.into(),
            path(&format!(
                "recovery-{field}.{}",
                if ["stdout", "stderr"].contains(&field) {
                    "bin"
                } else {
                    "json"
                }
            )),
        );
    }
    graph.evidence.recovery_artifacts.insert(
        "original_journal".into(),
        path("recovery-original-journal.bin"),
    );
}

pub fn device_graph() -> ExportGraph {
    let mut graph = original_graph("device");
    let path = format!("{}/device-created.json", graph.prefix);
    graph.case.json(&path,&json!({"format":"memcordon.linux-native-export-device","revision":1,"target_pid":103,"target_birth":302,"root_device":1,"root_inode":900,"work_device":1,"work_inode":901,"path":"/work/exported.bin","device":1,"inode":700,"rdev":259,"mode":0o020600,"links":1,"held_live_before_and_after":true}));
    graph.evidence.controller_setup = Some(path);
    let path = format!("{}/device-admin-handles-retired.json", graph.prefix);
    graph.case.json(&path,&json!({"format":"memcordon.linux-export-administrative-handle-retirement","revision":1,"attempt_id":graph.prepared.prepared["admission"]["attempt_id"],"before_root_release":true,"closures":[{"completed":true,"errno":null},{"completed":true,"errno":null},{"completed":true,"errno":null}]}));
    graph
        .evidence
        .external
        .insert("device-admin-handles-retired.json".into(), path);
    graph
}

pub fn concurrent_graph() -> ExportGraph {
    let mut graph = original_graph("concurrent-writer");
    let challenge = hex::encode([7u8; 32]);
    let event_id = "d".repeat(64);
    let attempt = graph.prepared.prepared["admission"]["attempt_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = |leaf: &str| format!("{}/{leaf}", graph.prefix);
    let held = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":1,"challenge":challenge,"root_pid":2,"root_birth":302,"operation":"export-writer-held","observation":{"pid":3,"birth":401,"parent_pid":2,"members":[]}});
    let stopped = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":2,"challenge":challenge,"root_pid":2,"root_birth":302,"operation":"export-writer-retired","observation":{"pid":3,"native_wait_completed":true,"raw_wait_status":0,"native_exit_code":0,"native_signal":null,"before_root_release":true}});
    let mut native = graph.prepared.native["target"].clone();
    native["process_id"] = json!(107);
    native["birth"] = json!(401);
    native["namespace_pids"] = json!([107, 3]);
    let retired = json!({"format":"memcordon.linux-export-preempty-writer-retirement","revision":1,"fixture":stopped,"held_retirement":[{"pid":107,"birth":401,"parent_pid":103,"parent_birth":302,"retirement_observed":true}]});
    let mut ready = linux_installed_case::read(&graph.case, &graph.evidence.ready);
    ready["sequence"] = json!(3);
    graph.case.json(&graph.evidence.ready, &ready);
    let mut stdout = Vec::new();
    for row in [&held, &stopped, &ready] {
        stdout.extend(serde_json::to_vec(row).unwrap());
        stdout.push(b'\n');
    }
    graph.case.write(&graph.evidence.stdout, &stdout);
    graph.case.mutate(&graph.evidence.native_wait, |raw| {
        raw["stdout_sha256"] = json!(sha256(&stdout))
    });
    graph.evidence.controller_setup = Some(path("writer-held.json"));
    let source = json!({"device":1,"inode":700,"uid":61001,"gid":61001,"length":32,"ctime_seconds":100,"ctime_nanoseconds":1});
    let worker = graph.prepared.worker["worker"].clone();
    let group = json!({"device":1,"inode":400,"native_links":0,"filesystem":"cgroup2","kind":"removed-held-inode"});
    let setup = json!({"format":"memcordon.native-export-permission-setup","revision":1,"challenge_hex":challenge,"work_unix_ms":100,"cleanup_unix_ms":200,"source":source,"cgroup":{"device":1,"inode":400},"worker":worker});
    let event = json!({"format":"memcordon.native-export-permission-event","revision":1,"event_id":event_id,"challenge_hex":challenge,"source":source,"worker":worker,"cgroup_retirement":group});
    let mut family = json!({"format":"memcordon.linux-export-native-family-retirement","revision":1,"prepared":graph.prepared.prepared,"challenge_hex":challenge});
    for (role, pid, birth) in [
        ("target", 103, 302),
        ("namespace_init", 104, 303),
        ("guardian", 105, 304),
    ] {
        family[role] = linux_prepared_case::held(pid, birth, true);
    }
    let cgroup = json!({"format":"memcordon.linux-export-native-cgroup-retirement","revision":1,"attempt_id":attempt,"prepared":graph.prepared.prepared,"held":group,"parent":{"path":"/sys/fs/cgroup/memcordon-sealed","device":1,"inode":399,"uid":0,"mode":0o040700},"named_attempt_errno":2});
    let family_bytes = serde_json::to_vec(&family).unwrap();
    let cgroup_bytes = serde_json::to_vec(&cgroup).unwrap();
    let ack = json!({"format":"memcordon.native-export-permission-ack","revision":1,"event_id":event_id,"challenge_hex":challenge,"source_device":1,"source_inode":700,"worker_pid":101,"worker_birth":300,"family_retirement_sha256":sha256(&family_bytes),"cgroup_retirement_sha256":sha256(&cgroup_bytes),"retirement_kind":"removed-held-inode"});
    let closures = [
        "event",
        "event-pidfd",
        "worker-pidfd",
        "group",
        "source",
        "cgroup",
    ]
    .iter()
    .map(|role| json!({"role":role,"attempted":true,"completed":true,"errno":null}))
    .collect::<Vec<_>>();
    let settled = json!({"format":"memcordon.native-export-permission-settled","revision":1,"challenge_hex":challenge,"work_unix_ms":100,"cleanup_unix_ms":200,"permission_answer":{"attempted":true,"fan_allow_written":true},"mark_installed":true,"unmark":{"attempted":true,"completed":true,"errno":null},"closures":closures,"operation":{"event_id":event_id,"before_length":32,"after_length":64,"before_ctime_seconds":100,"before_ctime_nanoseconds":1,"after_ctime_seconds":101,"after_ctime_nanoseconds":2,"family_retirement_sha256":sha256(&family_bytes),"cgroup_retirement_sha256":sha256(&cgroup_bytes),"cgroup_retirement":group},"operation_error":null,"settlement_errors":[]});
    let executable = sha256(b"original immutable executable");
    let runtime_source = format!(
        "{}/images/runtime-source",
        graph.owner["admin_root"].as_str().unwrap()
    );
    graph
        .case
        .mutate("installed/owned-resources-acquired.json", |raw| {
            raw["images"]["runtime_source"] = json!(runtime_source);
            raw["images"]["fixture_sha256"] = json!(executable);
        });
    let setup_sha = sha256(&serde_json::to_vec(&setup).unwrap());
    let arguments = [
        "native-export-permission",
        "--work-unix-ms",
        "100",
        "--cleanup-unix-ms",
        "200",
    ]
    .iter()
    .map(|text| text.as_bytes())
    .collect::<Vec<_>>();
    let invocation = json!({"format":"memcordon.linux-external-export-helper-invocation","revision":1,"program":format!("{runtime_source}/bin/owned-readiness").as_bytes(),"arguments":arguments,"cwd":graph.directory.as_bytes(),"env_clear":true,"executable_sha256":executable,"setup_sha256":setup_sha});
    let helper_held = json!({"format":"memcordon.linux-external-export-helper-held","revision":1,"process_id":202,"birth":402,"native_image":{"device":1,"inode":800,"length":29,"sha256":executable},"held_before_setup_delivery":true,"setup_sha256":setup_sha,"challenge_hex":challenge});
    let armed = json!({"format":"memcordon.native-export-permission-armed","revision":1,"challenge_hex":challenge,"source":source,"worker":worker});
    // Actual helper sends its three frames over the measured Unix control
    // socket; successful native execution leaves its stdio captures empty.
    let helper_stdout = Vec::<u8>::new();
    let ancestry = std::path::Path::new(&graph.directory)
        .ancestors()
        .collect::<Vec<_>>();
    let ancestry=ancestry.iter().rev().enumerate().map(|(ordinal,_)|json!({"ordinal":ordinal,"device":1,"inode":2000+ordinal,"uid":0,"gid":0,"mode":0o040700})).collect::<Vec<_>>();
    let helper_retired = json!({"format":"memcordon.linux-external-export-helper-retirement","revision":1,"challenge_hex":challenge,"process":linux_prepared_case::held(202,402,true),"native_exit":0,"native_success":true,"captures":[{"role":"stdout","device":1,"inode":801,"length":helper_stdout.len(),"sha256":sha256(&helper_stdout)},{"role":"stderr","device":1,"inode":802,"length":0,"sha256":sha256(b"")}],"capture_directory":graph.directory,"capture_directory_ancestry":ancestry});
    let admin_closures = (0..5)
        .map(|_| json!({"completed":true,"errno":null}))
        .collect::<Vec<_>>();
    for (leaf, value) in [
        ("writer-held.json", held),
        ("writer-native-held.json", native),
        ("writer-retired.json", retired),
        ("external-helper-setup.json", setup),
        ("external-helper-invocation.json", invocation),
        ("external-helper-held.json", helper_held),
        ("external-helper-armed.json", armed),
        ("external-helper-event.json", event),
        ("external-family-retirement.json", family),
        ("external-cgroup-retirement.json", cgroup),
        ("external-helper-ack.json", ack),
        (
            "external-administrative-closure.json",
            json!(admin_closures),
        ),
        ("external-helper-settled.json", settled),
        ("external-helper-retirement.json", helper_retired),
    ] {
        let file = path(leaf);
        graph.case.json(&file, &value);
        graph.evidence.external.insert(leaf.into(), file);
    }
    for (leaf, bytes) in [
        ("external-helper-stdout.bin", helper_stdout.as_slice()),
        ("external-helper-stderr.bin", b"".as_slice()),
    ] {
        let file = path(leaf);
        graph.case.write(&file, bytes);
        graph.evidence.external.insert(leaf.into(), file);
    }
    graph
}

pub fn finish(mut graph: ExportGraph) -> PersistedCase {
    recovery(&mut graph);
    let e = &graph.evidence;
    let mut row = json!({"family":"L-IMG-04","scenario":graph.case.record.key.scenario,"fixture_mode":graph.case.record.key.scenario.strip_prefix("export-").unwrap(),"controller_setup":null,"native_exit":125,"error":null});
    for (field, leaf) in [
        ("challenge", "challenge.bin"),
        ("contract", "request.json"),
        ("activation", "mixed.activation.json"),
        ("prepared", "prepared.json"),
        ("prepared_native", "prepared-native.json"),
        ("ready", "ready.json"),
        ("native_source", "native-export-source.json"),
        ("native_invocation", "frontend-invocation.json"),
        ("native_wait", "frontend-native-wait.json"),
        ("native_family", "native-family-retirement.json"),
        ("recovery", "export-recovery.json"),
        ("stdout", "launch/stdout.bin"),
        ("stderr", "launch/stderr.bin"),
        ("result", "launch/result.json"),
    ] {
        row[field] = json!(format!("{}/{leaf}", graph.directory));
    }
    row["provider_request"] = json!(format!(
        "{}/launch/observations/{}.provider-request.bin",
        graph.directory,
        graph.prepared.prepared["admission"]["attempt_id"]
            .as_str()
            .unwrap()
    ));
    if let Some(controller) = &e.controller_setup {
        row["controller_setup"] = json!(format!(
            "{}/{}",
            graph.directory,
            controller.rsplit('/').next().unwrap()
        ));
    }
    graph.case.json(&e.observation, &row);
    graph
        .case
        .json("case-evidence.json", &serde_json::to_value(e).unwrap());
    graph.case
}
