//! Full encoded original records exercise the central decoder, never native execution.
use super::{
    linux_installed_case as installed, linux_prepared_case as prepared,
    persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

pub fn baseline() -> PersistedCase {
    use memcordon_core::workload_contract_v3::{LocalPortV3, PrivatePeerV3, RequirementV3 as R};
    let id = |value: &str| memcordon_core::workload_contract::LogicalId::new(value.into()).unwrap();
    baseline_with_requirements(json!([
        R::TcpListener {
            id: id("tcp"),
            local_port: LocalPortV3::KernelAssigned,
            peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt
        },
        R::UnixStreamPair { id: id("pair") },
        R::UnixPathStream {
            id: id("pathname"),
            writable_root: id("work")
        },
        R::UnixAbstractStream { id: id("abstract") },
        R::IntraAttemptDescriptorTransfer { id: id("rights") },
        R::GeneratedExecutable {
            id: id("generated"),
            writable_root: id("work")
        }
    ]))
}

pub fn baseline_with_requirements(requirements: Value) -> PersistedCase {
    let mut case = installed::installed("L-IMG-03", "image-only-entrypoint");
    let owner = installed::read(&case, "installed/mixed-cases/image-cases/owner.json");
    let fixture = b"original immutable executable";
    let challenge = [7u8; 32];
    let token = hex::encode(challenge);
    let mut runtime = json!({"format":"memcordon.runtime-image","revision":1,"image_id":"original-runtime-image","target":case.record.key.target,
        "entries":[],"entrypoints":[{"id":"owned-readiness","path":"bin/owned-readiness"}],"library_directories":[],"startup_environment":[]});
    let mut runtime_entries = vec![];
    for (path, bytes) in [
        ("bin/owned-readiness", fixture.as_slice()),
        ("toolchain/bin/cargo", b"original cargo"),
        ("toolchain/bin/rustc", b"original rustc"),
        ("usr/bin/cc", b"original linker"),
    ] {
        runtime_entries.push(json!({"kind":"regular","path":path,"sha256":sha256(bytes),"size":bytes.len(),"executable":true}));
    }
    runtime["entries"] = json!(runtime_entries);
    let mut input_image = runtime.clone();
    input_image["image_id"] = json!("original-input-image");
    input_image["entries"] = json!([]);
    input_image["entrypoints"] = json!([]);
    let mut source_entries = vec![];
    let mut peers = vec![];
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "src/main.rs",
        "tests/generated_child.rs",
    ] {
        let bytes = relative.as_bytes();
        let artifact = format!("source/{relative}");
        case.write(&artifact, bytes);
        source_entries.push(json!({"kind":"regular","path":format!("owned-source/{relative}"),"sha256":sha256(bytes),"size":bytes.len(),"executable":false}));
        peers.push(BehaviorArtifact {
            role: format!("locked-source-{relative}"),
            path: artifact,
        });
    }
    input_image["entries"] = json!(source_entries);
    let (contract, _, activation) = installed::activation(
        &mut case,
        runtime.clone(),
        input_image.clone(),
        vec![],
        requirements,
    );
    let toolchain = json!({"runtime":runtime,"input":input_image});
    case.json("toolchain.json", &toolchain);
    let toolchain_sha = sha256(&std::fs::read(case.root.path().join("toolchain.json")).unwrap());
    let args = vec![b"joint".to_vec(), token.as_bytes().to_vec()];
    let mut graph = prepared::prepared_graph(
        &contract,
        &activation,
        &owner["provider"],
        "decoder-run",
        &args,
        512 * 1024 * 1024,
        300000,
        b"original agent image",
    );
    // Public ingress selects the authorized id; the original admitted launch
    // resolves that id to the absolute private image member before execution.
    let launch: Vec<u8> = serde_json::from_value(graph.request["native_launch"].clone()).unwrap();
    let header = 3u16.to_be_bytes().len() + 0u64.to_be_bytes().len();
    let width = 0u32.to_be_bytes().len();
    let selected_length =
        u32::from_be_bytes(launch[header..header + width].try_into().unwrap()) as usize;
    let program = b"/bin/owned-readiness";
    let mut execution_bytes = launch[..header].to_vec();
    execution_bytes.extend((program.len() as u32).to_be_bytes());
    execution_bytes.extend(program);
    execution_bytes.extend(&launch[header + width + selected_length..]);
    execution_bytes.extend(
        hex::decode(
            graph.prepared["admission"]["request_sha256"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    );
    graph.prepared["admission"]["invocation_sha256"] = json!(sha256(&execution_bytes));
    graph.native["prepared_sha256"] = json!(sha256(&serde_json::to_vec(&graph.prepared).unwrap()));
    case.json("request.json", &contract);
    case.json("provider-request.json", &graph.request);
    case.json("prepared.json", &graph.prepared);
    case.json("prepared-native.json", &graph.native);
    case.write("execution.bin", &execution_bytes);
    case.json(
        "environment.json",
        &json!(NativeEnvironment::UnixBytes(vec![])),
    );
    case.write("challenge.bin", &challenge);
    case.write("fixture.bin", fixture);
    case.write("fixture-source.bin", b"original fixture source");
    case.json("export.json", &json!([]));
    let mut values = vec![b"owned-readiness".to_vec()];
    values.extend(args.clone());
    let mut invocation = NativeInvocation {
        format: "memcordon.consumer-readiness.invocation".into(),
        revision: 1,
        arguments: NativeArguments::UnixBytes(values.clone()),
        executable_sha256: sha256(b"original CLI image"),
        environment: "environment.json".into(),
        environment_sha256: sha256(
            &std::fs::read(case.root.path().join("environment.json")).unwrap(),
        ),
        association_sha256: String::new(),
        budget_tokens: vec![
            BudgetToken {
                kind: "memory".into(),
                token: "+512M".into(),
            },
            BudgetToken {
                kind: "time".into(),
                token: "+300s".into(),
            },
        ],
        memory_token: Some("+512M".into()),
        deadline_token: Some("+300s".into()),
    };
    #[derive(serde::Serialize)]
    struct Public<'a> {
        syntax: &'static str,
        budget_tokens: &'a [BudgetToken],
        memory_token: &'a Option<String>,
        deadline_token: &'a Option<String>,
        argv: Vec<Value>,
    }
    let public = Public {
        syntax: "plus-budgets-v1",
        budget_tokens: &invocation.budget_tokens,
        memory_token: &invocation.memory_token,
        deadline_token: &invocation.deadline_token,
        argv: values
            .iter()
            .map(|arg| json!({"display":std::str::from_utf8(arg).unwrap(),"raw":null}))
            .collect(),
    };
    invocation.association_sha256 = sha256(&serde_json::to_vec(&public).unwrap());
    case.json("invocation.json", &json!(invocation));
    let input = FixtureInput {
        format: "memcordon.consumer-readiness.input".into(),
        revision: 1,
        run_id: "decoder-run".into(),
        key: case.record.key.clone(),
        challenge_sha256: sha256(&challenge),
        binary: vec![],
        target_argv: NativeArguments::UnixBytes(args.clone()),
        deadline_millis: Some(300000),
        memory_bytes: Some(512 * 1024 * 1024),
        toolchain_identity: Some(toolchain_sha),
    };
    case.json("input.json", &json!(input));
    let attempt = graph.prepared["admission"]["attempt_id"].as_str().unwrap();
    let mut native = NativeObservation {
        format: "memcordon.consumer-readiness.native".into(),
        revision: 1,
        run_id: "decoder-run".into(),
        lease_id: Some("original-lease".into()),
        target: case.record.key.target.clone(),
        executable_sha256: invocation.executable_sha256.clone(),
        invocation_sha256: invocation.association_sha256.clone(),
        execution_invocation_sha256: Some(sha256(&execution_bytes)),
        request_sha256: Some(sha256(
            &std::fs::read(case.root.path().join("provider-request.json")).unwrap(),
        )),
        provider_sha256: Some(sha256(b"original agent image")),
        provider_generation: Some(owner["provider"]["generation"].as_str().unwrap().into()),
        runtime_manifest_sha256: Some(
            owner["provider"]["runtime_manifest_sha256"]
                .as_str()
                .unwrap()
                .into(),
        ),
        attempt_id: Some(attempt.into()),
        root_pid: Some(103),
        root_birth: Some(302),
        attempt_nonce: None,
        held_processes: vec![],
        frontend_status: 0,
        origin: OutcomeOrigin::Target,
        target_status: Some(0),
        authenticated_provider_exchange: true,
        relay_complete: true,
        result_named_identity_verified: true,
        result_readback_verified: true,
        application_stage: None,
    };
    for (pid, birth, parent, parent_birth) in [
        (103, 302, None, None),
        (200, 310, Some(103), Some(302)),
        (201, 311, Some(200), Some(310)),
        (202, 312, Some(201), Some(311)),
    ] {
        native.held_processes.push(HeldProcessIdentity {
            pid,
            birth,
            parent_pid: parent,
            parent_birth,
            retirement_observed: true,
        });
    }
    case.json("native.json", &json!(native));
    let retired = RetirementObservation {
        format: "memcordon.consumer-readiness.retirement".into(),
        revision: 1,
        run_id: "decoder-run".into(),
        attempt_id: Some(attempt.into()),
        root_pid: Some(103),
        root_birth: Some(302),
        target_reaped_or_absent: true,
        aggregate_empty: true,
        relays_retired: true,
        guardian_retired: true,
        native_handles_closed: true,
        independently_observed: true,
        namespace_init_reaped: Some(true),
        private_root_closed: Some(true),
        exports_finalized: Some(true),
        account_reservation_retired: Some(true),
        final_job_handles_closed: None,
        active_processes_zero: None,
        outstanding: vec![],
        failed_operations: vec![],
    };
    case.json("retirement.json", &json!(retired));
    let mut result = super::linux_lifecycle_case::executed_result(
        &case,
        &graph,
        &owner,
        &contract,
        &args,
        sha256(&std::fs::read(case.root.path().join("export.json")).unwrap()),
    );
    result["invocation"] = serde_json::to_value(&public).unwrap();
    case.json("result.json", &result);
    let raw = json!({"format":"memcordon.linux-image-entrypoint","revision":1,"source":{"host_path":"/bin/owned-readiness","host_stat_errno":2,"observer":graph.native["observer"],"host_mount":graph.native["caller"]["mount"],"runtime_definition":toolchain["runtime"],"fixture_sha256":sha256(fixture),"run_id":"decoder-run","lease_id":"original-lease"},"challenge":token,"attempt_id":attempt,"target":graph.native["target"],"executable":{"device":1,"inode":600,"length":fixture.len(),"sha256":sha256(fixture)}});
    case.json("entrypoint.json", &raw);
    build_graph(&mut case, &graph, &native, &mut peers, &toolchain, &token);
    let mut operations = [
        "locked-rust-compile",
        "compiled-tests",
        "generated-executable",
    ]
    .map(|operation| OperationObservation {
        operation: operation.into(),
        attempt_id: Some(attempt.into()),
        root_pid: Some(103),
        observer: "owned-fixture-behavior".into(),
        native_receipt: "transcript.bin".into(),
    })
    .to_vec();
    operations.extend(
        ["host-entrypoint-absent", "image-entrypoint-executed"].map(|operation| {
            OperationObservation {
                operation: operation.into(),
                attempt_id: Some(attempt.into()),
                root_pid: Some(103),
                observer: "owned-image-entrypoint".into(),
                native_receipt: "entrypoint.json".into(),
            }
        }),
    );
    let mut expected = Vec::new();
    for byte in u8::MIN..=u8::MAX {
        expected.push(byte);
    }
    case.write("compiled-output.bin", &expected);
    case.write("compiled-expected.bin", &expected);
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: "decoder-run".into(),
        key: case.record.key.clone(),
        challenge: "challenge.bin".into(),
        operations,
        comparisons: vec![ByteComparison {
            role: "compiled-child".into(),
            expected: "compiled-expected.bin".into(),
            actual: "compiled-output.bin".into(),
        }],
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
    let evidence = CaseEvidence {
        format: "memcordon.consumer-readiness.case".into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: "decoder-run".into(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: Some("original-lease".into()),
        fixture: "fixture.bin".into(),
        fixture_source: "fixture-source.bin".into(),
        fixture_sha256: sha256(fixture),
        fixture_source_sha256: sha256(b"original fixture source"),
        input: "input.json".into(),
        input_sha256: sha256(&std::fs::read(case.root.path().join("input.json")).unwrap()),
        invocation: "invocation.json".into(),
        request: Some("request.json".into()),
        raw_result: Some("result.json".into()),
        provider_request: Some("provider-request.json".into()),
        authenticated_terminal: None,
        windows_loss: None,
        execution_invocation: Some("execution.bin".into()),
        execution_environment: Some("environment.json".into()),
        transcript: Some("transcript.bin".into()),
        inventory: None,
        qualification: None,
        export_receipt: Some("export.json".into()),
        prepared_observation: Some("prepared.json".into()),
        prepared_native_receipt: Some("prepared-native.json".into()),
        native_observation: "native.json".into(),
        retirement: "retirement.json".into(),
        semantic_observation: "semantic.json".into(),
        component_recipe_id: None,
    };
    case.json("case-evidence.json", &json!(evidence));
    case
}

fn build_graph(
    case: &mut PersistedCase,
    graph: &prepared::PreparedGraph,
    native: &NativeObservation,
    peers: &mut Vec<BehaviorArtifact>,
    toolchain: &Value,
    token: &str,
) {
    let created = json!({"format":"memcordon.linux-generated-child-created","revision":1,"challenge":token,"pid":5,"birth":312,"parent_pid":4,"parent_birth":311,"compiler_pid":3,"compiler_birth":310,"image_device":8,"image_inode":9,"program":"/work/generated-child-executable.bin","output":"/work/generated-readiness-artifact.bin","creation_owner_retained":true,"ready_before_release":true});
    let retired = json!({"format":"memcordon.linux-generated-child-retired","revision":1,"challenge":token,"pid":5,"birth":312,"parent_pid":4,"parent_birth":311,"native_wait_status":0,"same_creation_owner_waited":true});
    let mut elf = vec![0; 20];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[18] = 62;
    case.write("generated.bin", &elf);
    let target = &graph.native["target"];
    let member = |host, local, birth, parent, parent_birth, bytes: &[u8]| json!({"native":{"process_id":host,"birth":birth,"namespace_pids":[host,local],"user":target["user"],"mount":target["mount"],"pid":target["pid"],"network":target["network"],"ipc":target["ipc"]},"identity":{"pid":host,"birth":birth,"parent_pid":parent,"parent_birth":parent_birth,"retirement_observed":false},"executable":{"device":8,"inode":9,"length":bytes.len(),"sha256":sha256(bytes)}});
    let barrier = |stage, members: Vec<Value>| json!({"format":"memcordon.linux-native-build-barrier","revision":1,"stage":stage,"challenge":token,"attempt_id":native.attempt_id,"root_pid":103,"root_birth":302,"members":members});
    let compiler = barrier(
        "offline-compiler-held",
        vec![member(
            200,
            3,
            310,
            103,
            302,
            b"original immutable executable",
        )],
    );
    let generated = barrier(
        "joint-generated-child-held",
        vec![
            member(200, 3, 310, 103, 302, b"original cargo"),
            member(201, 4, 311, 200, 310, b"generated parent"),
            member(202, 5, 312, 201, 311, &elf),
        ],
    );
    for (role, path, value) in [
        ("generated-created", "created.json", created.clone()),
        ("generated-retired", "retired.json", retired),
        ("native-compiler-live", "compiler.json", compiler),
        ("native-generated-live", "generated.json", generated),
        (
            "build-request",
            "request.json",
            graph.request["contract"].clone(),
        ),
        ("toolchain-inputs", "toolchain.json", toolchain.clone()),
    ] {
        case.json(path, &value);
        peers.push(BehaviorArtifact {
            role: role.into(),
            path: path.into(),
        });
    }
    peers.push(BehaviorArtifact {
        role: "generated-executable".into(),
        path: "generated.bin".into(),
    });
    for (role, path, bytes) in [
        (
            "http",
            "http.bin",
            b"GET /readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
        ),
        (
            "http-response",
            "response.bin",
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreadiness",
        ),
        ("unix-path", "unix-path.bin", b"path-unix-readiness"),
        (
            "unix-abstract",
            "unix-abstract.bin",
            b"abstract-unix-readiness",
        ),
        ("unix-pair", "unix-pair.bin", b"R"),
    ] {
        case.write(path, bytes);
        peers.push(BehaviorArtifact {
            role: role.into(),
            path: path.into(),
        });
    }
    let observations = [
        (
            "bind-zero-and-competing-bind",
            json!({"endpoint":"127.0.0.1:32768","native_errno":98,"listener_retained":true}),
        ),
        (
            "http-round-trip",
            json!({"endpoint":"127.0.0.1:32768","request":b"GET /readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),"response":b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreadiness".as_slice()}),
        ),
        (
            "unix-path-round-trip",
            json!({"path":"/work/readiness.sock","bytes":b"path-unix-readiness"}),
        ),
        (
            "unix-abstract-round-trip",
            json!({"name":token.as_bytes(),"bytes":b"abstract-unix-readiness"}),
        ),
        ("unix-stream-pair-round-trip", json!({"bytes":b"R"})),
        (
            "offline-rust-compile-and-test",
            json!({"native_status":0,"tcp_listener_still_bound":true,"output":"/work/offline-target"}),
        ),
        (
            "joint-unix-rights-held-through-build",
            json!({"owned_native_descriptors":14,"path":"/work/readiness.sock","transferred_file":"/work/rights-input.bin"}),
        ),
        (
            "joint-descendant-tree-naturally-retired",
            json!({"tcp_listener_still_bound":true}),
        ),
        ("joint-generated-child-held", json!({"created":created})),
        (
            "generated-executable-binary-product",
            json!({"path":"/work/generated-readiness-artifact.bin","inode":700,"bytes":(u8::MIN..=u8::MAX).collect::<Vec<_>>()}),
        ),
    ];
    let mut transcript = vec![];
    for (ordinal, (operation, observation)) in observations.into_iter().enumerate() {
        transcript.extend(serde_json::to_vec(&json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":ordinal+1,"challenge":token,"root_pid":2,"root_birth":302,"operation":operation,"observation":observation})).unwrap());
        transcript.push(b'\n');
    }
    case.write("transcript.bin", &transcript);
}
