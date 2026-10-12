//! Complete encoded native limit graphs, never an executed readiness claim.
use super::{
    linux_image_entrypoint_case as image, linux_installed_case as installed,
    linux_prepared_case as prepared, persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::*;
use serde::Serialize;
use serde_json::{Value, json};

#[allow(
    dead_code,
    reason = "Some integration targets reuse limit graph helpers without the standalone baseline"
)]
pub fn baseline(family: &str, scenario: &str) -> PersistedCase {
    let mut case = if family == "L-LIFE-03" {
        image::baseline()
    } else {
        image::baseline_with_requirements(json!([]))
    };
    case.record.key.family = family.into();
    case.record.key.scenario = scenario.into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let raw = matches!(family, "C-IO" | "L-MIX-05")
        || (family == "L-LIFE-05" && scenario == "relay-backpressure");
    let (mode, memory, deadline, memory_token, deadline_token) = match (family, scenario) {
        ("C-STATUS", "deadline") => (
            "population-deadline",
            2 * 1024 * 1024 * 1024,
            30000,
            "+2GiB",
            "+30s",
        ),
        ("C-STATUS", "memory") => (
            "memory-pressure-descendant",
            128 * 1024 * 1024,
            300000,
            "+128M",
            "+300s",
        ),
        ("L-LIFE-03", "memory") => ("joint-memory", 512 * 1024 * 1024, 300000, "+512M", "+300s"),
        ("L-LIFE-03", "reserved-target-exit") => (
            "joint-reserved-exit",
            2 * 1024 * 1024 * 1024,
            300000,
            "+2GiB",
            "+300s",
        ),
        ("L-LIFE-03", _) => ("joint", 2 * 1024 * 1024 * 1024, 300000, "+2GiB", "+300s"),
        _ if raw => (
            "bounded-large-output",
            256 * 1024 * 1024,
            30000,
            "+256M",
            "+30s",
        ),
        _ => panic!("unfrozen limit fixture"),
    };
    let challenge = [7u8; 32];
    let token = hex::encode(challenge);
    let args = vec![mode.as_bytes().to_vec(), token.as_bytes().to_vec()];
    let (graph, mut native) = rebind(
        &mut case,
        &args,
        memory,
        deadline,
        memory_token,
        deadline_token,
    );
    let mut peers =
        serde_json::from_value::<SemanticObservation>(installed::read(&case, "semantic.json"))
            .unwrap()
            .fixture_behavior
            .unwrap()
            .peer_artifacts;
    peers.retain(|peer| {
        ![
            "stdout",
            "stderr",
            "limit-provider-request",
            "limit-controller",
            "limit-agent-image",
        ]
        .contains(&peer.role.as_str())
    });
    for peer in &mut peers {
        if let Some(relative) = peer.role.strip_prefix("locked-source-") {
            peer.role = format!("source-{relative}");
        }
    }
    peers.push(BehaviorArtifact {
        role: "limit-provider-request".into(),
        path: "provider-request.json".into(),
    });
    peers.push(BehaviorArtifact {
        role: "limit-controller".into(),
        path: "controller.json".into(),
    });
    case.write("limit-agent.bin", b"original agent image");
    peers.push(BehaviorArtifact {
        role: "limit-agent-image".into(),
        path: "limit-agent.bin".into(),
    });
    let mut rows = if raw { vec![] } else { read_transcript(&case) };
    if family == "L-LIFE-03" {
        let compiler = installed::read(&case, "compiler.json");
        rows.push(row(
            rows.len() + 1,
            &token,
            "offline-compiler-held",
            compiler,
        ));
        case.json("observer-close.json",&json!([{ "device":1,"inode":900,"closed":true,"native_errno":null},{"device":8,"inode":9,"closed":true,"native_errno":null},{"device":8,"inode":10,"closed":true,"native_errno":null},{"device":8,"inode":11,"closed":true,"native_errno":null}]));
        peers.push(BehaviorArtifact {
            role: "native-build-observer-close".into(),
            path: "observer-close.json".into(),
        });
    }
    let mut actions = vec![];
    let (operation, origin, status, wait) = if raw {
        (
            if scenario == "relay-backpressure" {
                "backpressure-observed"
            } else {
                "stdout-bytes"
            },
            OutcomeOrigin::Target,
            0,
            0,
        )
    } else {
        match scenario {
            "deadline" => {
                if family == "C-STATUS" {
                    let children = (0..256)
                        .map(|n| json!({"pid":n+3,"birth":n+400,"parent_pid":2,"members":[]}))
                        .collect::<Vec<_>>();
                    rows = vec![row(
                        1,
                        &token,
                        "population-held-until-native-deadline",
                        json!({"population":257,"children":children}),
                    )];
                    native.held_processes.truncate(1);
                    let members=(0..256u32).map(|n|{
      native.held_processes.push(HeldProcessIdentity{pid:n+200,birth:u64::from(n)+400,parent_pid:Some(103),parent_birth:Some(302),retirement_observed:true});
      let mut snapshot=graph.native["target"].clone();snapshot["process_id"]=json!(n+200);snapshot["birth"]=json!(n+400);snapshot["namespace_pids"]=json!([n+200,n+3]);
      json!({"native":snapshot,"identity":{"pid":n+200,"birth":n+400,"parent_pid":103,"parent_birth":302,"retirement_observed":false}})
    }).collect::<Vec<_>>();
                    actions.push(json!({"format":"memcordon.linux-native-deadline-population","revision":1,"attempt_id":native.attempt_id,"challenge":token,"root":graph.native["target"],"members":members}));
                }
                ("deadline-expired", OutcomeOrigin::Deadline, 124, 9)
            }
            "memory" => {
                rows.push(row(
                    rows.len() + 1,
                    &token,
                    "memory-pressure-descendant-held",
                    json!({"pid":5,"birth":312}),
                ));
                actions = memory_actions(&case, &graph, memory);
                ("memory-limit-confirmed", OutcomeOrigin::Memory, 137, 9)
            }
            "cancellation" => {
                let sequence = rows
                    .iter()
                    .position(|value| value["operation"] == "joint-generated-child-held")
                    .unwrap()
                    + 1;
                actions.push(json!({"format":"memcordon.linux-limit-controller-interrupt","revision":1,"run_id":case.record.run_id,"lease_id":"original-lease","key":case.record.key,"challenge":token,"held_frontend":prepared::held(102,301,false),"image":{"device":1,"inode":20,"length":b"original CLI image".len(),"sha256":sha256(b"original CLI image")},"barrier_sequence":sequence,"barrier_operation":"joint-generated-child-held","signal":2,"syscall_succeeded":true,"native_errno":null}));
                (
                    "controlled-cancellation",
                    OutcomeOrigin::Interrupted,
                    130,
                    9,
                )
            }
            "reserved-target-exit" => {
                rows.push(row(
                    rows.len() + 1,
                    &token,
                    "joint-reserved-application-exit",
                    json!({"requested_exit_code":125}),
                ));
                (
                    "reserved-native-target-exit",
                    OutcomeOrigin::Target,
                    125,
                    125 * 256,
                )
            }
            _ => panic!("unfrozen limit scenario"),
        }
    };
    native.origin = origin;
    native.frontend_status = status;
    native.target_status = if origin == OutcomeOrigin::Target {
        Some(status)
    } else {
        None
    };
    case.json("native.json", &json!(native));
    let mut result = installed::read(&case, "result.json");
    result["wrapper_status"] = json!(status);
    result["runtime"]["outcome"]["execution"]["native_wait_status"] = json!(wait);
    result["runtime"]["outcome"]["execution"]["outcome_origin"] = json!(match origin {
        OutcomeOrigin::Deadline => "deadline",
        OutcomeOrigin::Memory => "memory-oom",
        OutcomeOrigin::Interrupted => "controlled-cancellation",
        _ => "native-exit",
    });
    case.json("result.json", &result);
    let mut comparisons = vec![];
    let mut counters = std::collections::BTreeMap::new();
    if raw {
        let bytes = (0..256 * 8192).map(|n| (n % 256) as u8).collect::<Vec<_>>();
        for leaf in ["stdout.bin", "stderr.bin", "expected-stream.bin"] {
            case.write(leaf, &bytes);
        }
        for role in ["stdout", "stderr"] {
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: format!("{role}.bin"),
            });
            comparisons.push(ByteComparison {
                role: role.into(),
                expected: "expected-stream.bin".into(),
                actual: format!("{role}.bin"),
            });
            counters.insert(format!("{role}-bytes"), bytes.len() as u64);
        }
        if scenario == "relay-backpressure" {
            let pipe = |n| json!({"device":1,"inode":n,"mode":0o010600,"capacity_bytes":8192,"queued_bytes":8192,"native_descriptor":n-20,"source_link":format!("pipe:[{n}]").as_bytes()});
            actions = vec![
                json!({"format":"memcordon.linux-native-output-backpressure","revision":1,"frontend_pid":102,"frontend_birth":301,"native_frontend_live":prepared::held(102,301,false),"capture_held":true,"pipes":[pipe(21),pipe(22)]}),
                json!({"format":"memcordon.linux-output-capture-resumed","revision":1,"key":case.record.key,"capture_resumed":true}),
            ];
        }
    } else {
        let mut transcript = vec![];
        for (ordinal, value) in rows.iter_mut().enumerate() {
            value["sequence"] = json!(ordinal + 1);
            transcript.extend(serde_json::to_vec(value).unwrap());
            transcript.push(b'\n');
        }
        case.write("transcript.bin", &transcript);
    }
    case.json("controller.json", &json!(actions));
    let transcript = if raw { "stdout.bin" } else { "transcript.bin" };
    let mut operations = vec![OperationObservation {
        operation: operation.into(),
        attempt_id: native.attempt_id.clone(),
        root_pid: native.root_pid,
        observer: "owned-fixture-behavior".into(),
        native_receipt: transcript.into(),
    }];
    if raw {
        for op in ["stdout-bytes", "stderr-bytes"] {
            if op == operation {
                continue;
            }
            let mut additional = operations[0].clone();
            additional.operation = op.into();
            operations.push(additional);
        }
    }
    if family == "L-LIFE-05" && scenario == "relay-backpressure" {
        for op in [
            "fault-relay-backpressure",
            "original-cause-retained",
            "independent-retirement",
        ] {
            let mut additional = operations[0].clone();
            additional.operation = op.into();
            operations.push(additional);
        }
    }
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: case.record.run_id.clone(),
        key: case.record.key.clone(),
        challenge: "challenge.bin".into(),
        operations,
        comparisons,
        counters,
        negative_probe: None,
        component_test: None,
        component_actors: None,
        windows_capacity: None,
        windows_refusal: None,
        fixture_behavior: Some(FixtureBehavior {
            descriptor: "input.json".into(),
            transcript: transcript.into(),
            peer_artifacts: peers,
            expected_token: None,
            native_binding: Some("prepared-native.json".into()),
        }),
    };
    case.json("semantic.json", &json!(semantic));
    let mut evidence: CaseEvidence =
        serde_json::from_value(installed::read(&case, "case-evidence.json")).unwrap();
    evidence.key = case.record.key.clone();
    evidence.input_sha256 = case
        .index
        .artifacts
        .iter()
        .find(|a| a.path == "input.json")
        .unwrap()
        .sha256
        .clone();
    evidence.transcript = Some(transcript.into());
    case.json("case-evidence.json", &json!(evidence));
    case
}

#[allow(
    dead_code,
    reason = "Transcript rows are needed only by the standalone limit baseline"
)]
fn row(sequence: usize, token: &str, operation: &str, observation: Value) -> Value {
    json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":sequence,"challenge":token,"root_pid":2,"root_birth":302,"operation":operation,"observation":observation})
}
#[allow(
    dead_code,
    reason = "Transcript decoding is needed only by the standalone limit baseline"
)]
fn read_transcript(case: &PersistedCase) -> Vec<Value> {
    std::fs::read(case.root.path().join("transcript.bin"))
        .unwrap()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

pub fn rebind(
    case: &mut PersistedCase,
    args: &[Vec<u8>],
    memory: u64,
    deadline: u64,
    memory_token: &str,
    deadline_token: &str,
) -> (prepared::PreparedGraph, NativeObservation) {
    rebind_activation(
        case,
        args,
        memory,
        deadline,
        memory_token,
        deadline_token,
        None,
    )
}

pub fn rebind_activation(
    case: &mut PersistedCase,
    args: &[Vec<u8>],
    memory: u64,
    deadline: u64,
    memory_token: &str,
    deadline_token: &str,
    selected_activation: Option<Value>,
) -> (prepared::PreparedGraph, NativeObservation) {
    let contract = installed::read(case, "request.json");
    let owner = installed::read(case, "installed/mixed-cases/image-cases/owner.json");
    let acquired = installed::read(case, "installed/owned-resources-acquired.json");
    let (_, _, activation) = installed::activation(
        case,
        acquired["images"]["runtime"].clone(),
        acquired["images"]["input"].clone(),
        vec![],
        contract["requirements"].clone(),
    );
    let activation = selected_activation.unwrap_or(activation);
    let mut graph = prepared::prepared_graph(
        &contract,
        &activation,
        &owner["provider"],
        &case.record.run_id,
        args,
        memory,
        deadline,
        b"original agent image",
    );
    let launch: Vec<u8> = serde_json::from_value(graph.request["native_launch"].clone()).unwrap();
    let header = 3u16.to_be_bytes().len() + 0u64.to_be_bytes().len();
    let width = 0u32.to_be_bytes().len();
    let old = u32::from_be_bytes(launch[header..header + width].try_into().unwrap()) as usize;
    let program = b"/bin/owned-readiness";
    let mut execution = launch[..header].to_vec();
    execution.extend((program.len() as u32).to_be_bytes());
    execution.extend(program);
    execution.extend(&launch[header + width + old..]);
    execution.extend(
        hex::decode(
            graph.prepared["admission"]["request_sha256"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    );
    graph.prepared["admission"]["invocation_sha256"] = json!(sha256(&execution));
    graph.native["prepared_sha256"] = json!(sha256(&serde_json::to_vec(&graph.prepared).unwrap()));
    case.json("provider-request.json", &graph.request);
    case.json("prepared.json", &graph.prepared);
    case.json("prepared-native.json", &graph.native);
    case.write("execution.bin", &execution);
    let mut invocation: NativeInvocation =
        serde_json::from_value(installed::read(case, "invocation.json")).unwrap();
    let mut argv = vec![b"owned-readiness".to_vec()];
    argv.extend_from_slice(args);
    invocation.arguments = NativeArguments::UnixBytes(argv.clone());
    invocation.budget_tokens = vec![
        BudgetToken {
            kind: "memory".into(),
            token: memory_token.into(),
        },
        BudgetToken {
            kind: "time".into(),
            token: deadline_token.into(),
        },
    ];
    invocation.memory_token = Some(memory_token.into());
    invocation.deadline_token = Some(deadline_token.into());
    #[derive(Serialize)]
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
        argv: argv
            .iter()
            .map(|arg| json!({"display":std::str::from_utf8(arg).unwrap(),"raw":null}))
            .collect(),
    };
    let public_value = json!(public);
    invocation.association_sha256 = sha256(&serde_json::to_vec(&public).unwrap());
    case.json("invocation.json", &json!(invocation));
    let mut input: FixtureInput =
        serde_json::from_value(installed::read(case, "input.json")).unwrap();
    input.key = case.record.key.clone();
    input.target_argv = NativeArguments::UnixBytes(args.to_vec());
    input.memory_bytes = Some(memory);
    input.deadline_millis = Some(deadline);
    case.json("input.json", &json!(input));
    let mut native: NativeObservation =
        serde_json::from_value(installed::read(case, "native.json")).unwrap();
    native.invocation_sha256 = invocation.association_sha256;
    native.execution_invocation_sha256 = Some(sha256(&execution));
    native.request_sha256 = Some(sha256(&serde_json::to_vec(&graph.request).unwrap()));
    let mut result = installed::read(case, "result.json");
    result["invocation"] = public_value;
    result["runtime"]["outcome"]["admission"] = graph.prepared["admission"].clone();
    result["runtime"]["outcome"]["request_bytes_sha256"] = json!(native.request_sha256);
    case.json("result.json", &result);
    (graph, native)
}

#[allow(
    dead_code,
    reason = "Memory action graphs are needed only by the standalone limit baseline"
)]
fn memory_actions(
    case: &PersistedCase,
    graph: &prepared::PreparedGraph,
    memory: u64,
) -> Vec<Value> {
    let attempt = graph.prepared["admission"]["attempt_id"].clone();
    let key = json!(case.record.key);
    let worker = prepared::held(101, 300, false);
    let stop = json!({"format":"memcordon.linux-memory-worker-stop","revision":1,"worker":worker,"signal":19,"syscall_succeeded":true,"native_errno":null});
    let mut resume = stop.clone();
    resume["format"] = json!("memcordon.linux-memory-worker-resume");
    resume["signal"] = json!(18);
    let mut journal = graph.journal.clone();
    journal["phase"] = json!("target-gated");
    journal["mixed_admission_metadata"] = graph.prepared["admission"].clone();
    let journal_bytes = prepared::durable_journal(&journal);
    let mut source = graph.worker.clone();
    source["admission"] = graph.prepared["admission"].clone();
    source["journal_bytes"] = json!(journal_bytes);
    source["journal_sha256"] = json!(sha256(&journal_bytes));
    let mut fields = vec!["T".to_owned(); 20];
    fields[19] = "300".into();
    let stat = format!("101 (original worker) {}", fields.join(" "));
    let stopped = json!({"format":"memcordon.linux-memory-worker-stopped","revision":1,"key":key,"attempt_id":attempt,"worker":worker,"selected_worker_source":source,"actual_stop":stop,"stopped":{"format":"memcordon.linux-limit-worker-stopped","revision":1,"process_id":101,"birth":300,"state":"T","native_stat_bytes":stat.as_bytes()}});
    let before = b"low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n";
    let after = b"low 0\nhigh 0\nmax 1\noom 1\noom_kill 1\noom_group_kill 0\n";
    let armed = json!({"format":"memcordon.linux-memory-events-armed","revision":1,"key":key,"attempt_id":attempt,"worker_index":0,"group_device":1,"group_inode":400,"events_device":1,"events_inode":401,"maximum_device":1,"maximum_inode":402,"target":{"pid":103,"birth":302},"target_membership":format!("0::/memcordon-sealed/{}\n",attempt.as_str().unwrap()).as_bytes(),"before":before.as_slice(),"memory_max":format!("{memory}\n").as_bytes()});
    let transition = json!({"format":"memcordon.linux-memory-events-transition","revision":1,"key":key,"attempt_id":attempt,"worker_index":0,"group_device":1,"group_inode":400,"events_device":1,"events_inode":401,"maximum_device":1,"maximum_inode":402,"before":before.as_slice(),"after":after.as_slice()});
    vec![stop, stopped, armed, transition, resume]
}
