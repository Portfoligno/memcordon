//! Full original command/private root/native retirement graphs for isolation rows.
use super::{
    linux_image_entrypoint_case as image, linux_installed_case as installed,
    linux_limits_case as limits, persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

pub fn authority(family: &str, scenario: &str) -> PersistedCase {
    use memcordon_core::workload_contract::LogicalId;
    use memcordon_core::workload_contract_v3::{
        DeniedOperationV3 as D, LocalPortV3, PrivatePeerV3, RequirementV3 as R,
    };
    let id = |text: &str| LogicalId::new(text.into()).unwrap();
    let denial = match scenario {
        "ipv6" => D::Inet6,
        "udp" => D::Udp,
        "raw" => D::Raw,
        "packet" => D::Packet,
        "netlink" => D::Netlink,
        "pidfd-getfd" | "ptrace" => D::ProcessImport,
        "namespace-entry" => D::NamespaceEntry,
        _ => panic!("unfrozen authority fixture"),
    };
    let requirements = json!([
        R::TcpListener {
            id: id("tcp"),
            local_port: LocalPortV3::KernelAssigned,
            peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt
        },
        R::ExpectedDenial {
            id: id("denial"),
            operation: denial
        }
    ]);
    let mut case = image::baseline_with_requirements(requirements);
    case.record.key.family = family.into();
    case.record.key.scenario = scenario.into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let args = vec![
        b"authority-denial".to_vec(),
        hex::encode([7; 32]).into_bytes(),
        scenario.as_bytes().to_vec(),
    ];
    let (_, mut native) = limits::rebind(
        &mut case,
        &args,
        2 * 1024 * 1024 * 1024,
        30000,
        "+2GiB",
        "+30s",
    );
    native.held_processes.truncate(1);
    case.json("native.json", &json!(native));
    let errno = match scenario {
        "ipv6" | "packet" | "netlink" => 97,
        "udp" | "raw" => 93,
        _ => 1,
    };
    let rows = vec![
        (
            "neighboring-permitted-sockets",
            json!({"tcp_endpoint":"127.0.0.1:42000","unix_bytes":b"positive".to_vec()}),
        ),
        (
            "native-authority-denied",
            json!({"probe":scenario,"native_errno":errno,"result":-1}),
        ),
    ];
    finish(&mut case, &native, rows, vec![], scenario, errno);
    case
}

fn finish(
    case: &mut PersistedCase,
    native: &NativeObservation,
    rows: Vec<(&str, Value)>,
    peers: Vec<BehaviorArtifact>,
    stage: &str,
    errno: i64,
) {
    let mut transcript = vec![];
    for (ordinal, (operation, observation)) in rows.into_iter().enumerate() {
        let row = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":ordinal+1,"challenge":hex::encode([7;32]),"root_pid":2,"root_birth":302,"operation":operation,"observation":observation});
        transcript.extend(serde_json::to_vec(&row).unwrap());
        transcript.push(b'\n');
    }
    case.write("transcript.bin", &transcript);
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: case.record.run_id.clone(),
        key: case.record.key.clone(),
        challenge: "challenge.bin".into(),
        operations: vec![OperationObservation {
            operation: "native-authority-probe".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            observer: "owned-fixture-behavior".into(),
            native_receipt: "transcript.bin".into(),
        }],
        comparisons: vec![],
        counters: Default::default(),
        negative_probe: Some(NegativeProbe {
            stage: stage.into(),
            domain: "linux".into(),
            native_code: errno,
            receipt: "transcript.bin".into(),
        }),
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
    let mut evidence: CaseEvidence =
        serde_json::from_value(installed::read(case, "case-evidence.json")).unwrap();
    evidence.key = case.record.key.clone();
    evidence.input_sha256 = case
        .index
        .artifacts
        .iter()
        .find(|artifact| artifact.path == "input.json")
        .unwrap()
        .sha256
        .clone();
    case.json("case-evidence.json", &json!(evidence));
}

pub fn host(scenario: &str) -> PersistedCase {
    use memcordon_core::workload_contract::LogicalId;
    use memcordon_core::workload_contract_v3::{
        DeniedOperationV3 as D, LocalPortV3, PrivatePeerV3, RequirementV3 as R,
    };
    let id = |text: &str| LogicalId::new(text.into()).unwrap();
    let tcp = scenario != "host-abstract";
    let family = if tcp { "L-ISO-01" } else { "L-ISO-03" };
    let requirements = json!([
        R::TcpListener {
            id: id("tcp"),
            local_port: LocalPortV3::KernelAssigned,
            peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt
        },
        R::ExpectedDenial {
            id: id(if tcp {
                if scenario == "nonloopback" {
                    "nonloopback-denial"
                } else {
                    "host-tcp-denial"
                }
            } else {
                "host-abstract-denial"
            }),
            operation: if tcp { D::HostTcp } else { D::HostUnixAbstract }
        }
    ]);
    let mut case = image::baseline_with_requirements(requirements);
    case.record.key.family = family.into();
    case.record.key.scenario = scenario.into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let endpoint = if scenario == "nonloopback" {
        "192.0.2.20:42000"
    } else {
        "127.0.0.1:42000"
    };
    let name = format!("memcordon-readiness-{}", hex::encode([7; 32])).into_bytes();
    let mut args = vec![
        if tcp {
            b"forbidden-tcp".to_vec()
        } else {
            b"forbidden-abstract".to_vec()
        },
        hex::encode([7; 32]).into_bytes(),
    ];
    args.push(if tcp {
        endpoint.as_bytes().to_vec()
    } else {
        name.clone()
    });
    let (graph, mut native) = limits::rebind(
        &mut case,
        &args,
        2 * 1024 * 1024 * 1024,
        30000,
        "+2GiB",
        "+30s",
    );
    native.held_processes.truncate(1);
    case.json("native.json", &json!(native));
    let mut canary = json!({"format":if tcp{"memcordon.linux-host-tcp-canary"}else{"memcordon.linux-host-abstract-canary"},"revision":1,"challenge":hex::encode([7;32]),"socket_inode":900,"network_namespace_inode":graph.native["caller"]["network"]["inode"],"baseline_client_connected":true,"baseline_server_accepted":true});
    let mut denied = json!({"native_errno":111});
    let field = if tcp { "endpoint" } else { "name" };
    canary[field] = if tcp { json!(endpoint) } else { json!(name) };
    denied[field] = canary[field].clone();
    case.json("host-canary.json", &canary);
    finish(
        &mut case,
        &native,
        vec![(
            if tcp {
                "forbidden-tcp-denied"
            } else {
                "forbidden-abstract-denied"
            },
            denied,
        )],
        vec![BehaviorArtifact {
            role: if tcp {
                "host-tcp-canary".into()
            } else {
                "host-abstract-canary".into()
            },
            path: "host-canary.json".into(),
        }],
        scenario,
        111,
    );
    case
}

pub fn host_path(scenario: &str) -> PersistedCase {
    use memcordon_core::workload_contract::LogicalId;
    use memcordon_core::workload_contract_v3::{DeniedOperationV3 as D, RequirementV3 as R};
    let id = |text: &str| LogicalId::new(text.into()).unwrap();
    let token = hex::encode([7; 32]);
    let parent_path = if scenario == "host-run-socket" {
        "/run"
    } else {
        "/tmp"
    };
    let path = format!("{parent_path}/memcordon-readiness-{token}.sock");
    let mut case = image::baseline_with_requirements(json!([
        R::UnixStreamPair { id: id("pair") },
        R::ExpectedDenial {
            id: id("host-path-denial"),
            operation: D::HostUnixPath
        }
    ]));
    case.record.key.family = "L-ISO-02".into();
    case.record.key.scenario = scenario.into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let args = vec![
        b"forbidden-unix-path".to_vec(),
        token.as_bytes().to_vec(),
        path.as_bytes().to_vec(),
    ];
    let (graph, mut native) = limits::rebind(
        &mut case,
        &args,
        2 * 1024 * 1024 * 1024,
        30000,
        "+2GiB",
        "+30s",
    );
    native.held_processes.truncate(1);
    case.json("native.json", &json!(native));
    let parent = json!({"path":parent_path,"device":1,"inode":600,"uid":0,"mode":if parent_path=="/tmp"{0o041777}else{0o040755}});
    let intent = json!({"format":"memcordon.linux-host-path-socket-intent","revision":1,"kind":scenario,"path":path,"challenge":token,"parent":parent});
    case.json("host-path-intent.json", &intent);
    let original = json!({"path":path,"device":1,"inode":610,"uid":0,"gid":0,"mode":0o140666,"nlink":1,"listener_device":8,"listener_inode":620,"bytes":token.as_bytes(),"kind":scenario,"peer":{"pid":graph.native["observer"]["pid"],"birth":graph.native["observer"]["birth"],"uid":0,"gid":0},"network_namespace_inode":graph.native["caller"]["network"]["inode"]});
    case.json("host-path-allocation.json",&json!({"format":"memcordon.linux-host-path-socket-allocation","revision":1,"path":path,"device":1,"inode":610,"uid":0,"gid":0,"nlink":1,"intent_sha256":sha256(&std::fs::read(case.root.path().join("host-path-intent.json")).unwrap())}));
    case.json("host-path-canary.json",&json!({"format":"memcordon.linux-host-path-socket-canary","revision":1,"original":original,"parent":parent,"named_absence_errno":2,"listener_closed":true,"parent_closed":true}));
    let peers = [
        ("host-path-socket-intent", "host-path-intent.json"),
        ("host-path-socket-allocation", "host-path-allocation.json"),
        ("host-path-socket-canary", "host-path-canary.json"),
    ]
    .into_iter()
    .map(|(role, path)| BehaviorArtifact {
        role: role.into(),
        path: path.into(),
    })
    .collect();
    finish(
        &mut case,
        &native,
        vec![
            (
                "private-unix-pair-positive",
                json!({"bytes":token.as_bytes()}),
            ),
            (
                "forbidden-unix-path-denied",
                json!({"path":path,"native_errno":2}),
            ),
        ],
        peers,
        scenario,
        2,
    );
    case
}

pub fn descriptor(scenario: &str) -> PersistedCase {
    use memcordon_core::workload_contract::LogicalId;
    use memcordon_core::workload_contract_v3::RequirementV3 as R;
    let mut case = image::baseline_with_requirements(json!([R::UnixStreamPair {
        id: LogicalId::new("pair".into()).unwrap()
    }]));
    case.record.key.family = "L-ISO-05".into();
    case.record.key.scenario = scenario.into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let token = hex::encode([7; 32]);
    let args = vec![b"descriptor-isolation".to_vec(), token.as_bytes().to_vec()];
    let (graph, mut native) = limits::rebind(
        &mut case,
        &args,
        2 * 1024 * 1024 * 1024,
        30000,
        "+2GiB",
        "+30s",
    );
    native.held_processes.truncate(1);
    case.json("native.json", &json!(native));
    let original = json!({"format":"memcordon.linux-host-socket-descriptor","revision":1,"descriptor":if scenario=="stdio-host-socket"{0}else{128},"frontend":graph.native["caller"],"source":{"device":8,"inode":700,"mode":0o140777},"peer":{"device":8,"inode":701,"mode":0o140777},"source_link":b"socket:[700]","fdinfo":b"pos:\t0\nflags:\t02\nmnt_id:\t1\nino:\t700\nscm_fds:\t0\n".as_slice(),"observer":graph.native["observer"],"host_network":graph.native["caller"]["network"]});
    case.json("descriptor-closure.json",&json!({"format":"memcordon.linux-host-socket-descriptor-retired","revision":1,"original":original,"source_closed":true,"peer_closed":true,"native_errno":null}));
    let stdio = (0..3)
        .map(|n| json!({"descriptor":n,"device":8,"inode":710+n,"mode":0o010600}))
        .collect::<Vec<_>>();
    finish(
        &mut case,
        &native,
        vec![
            (
                "private-unix-pair-positive",
                json!({"bytes":token.as_bytes()}),
            ),
            (
                "native-descriptor-isolation",
                json!({"stdio":stdio,"extra_descriptor":128,"native_errno":9}),
            ),
        ],
        vec![BehaviorArtifact {
            role: "host-socket-descriptor".into(),
            path: "descriptor-closure.json".into(),
        }],
        scenario,
        9,
    );
    case
}

pub fn own_abstract() -> PersistedCase {
    use memcordon_core::workload_contract::LogicalId;
    use memcordon_core::workload_contract_v3::RequirementV3 as R;
    let mut case = image::baseline_with_requirements(json!([R::UnixAbstractStream {
        id: LogicalId::new("own-abstract".into()).unwrap()
    }]));
    case.record.key.family = "L-ISO-03".into();
    case.record.key.scenario = "own-abstract-positive".into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let token = hex::encode([7; 32]);
    let args = vec![b"own-abstract".to_vec(), token.as_bytes().to_vec()];
    let (_, mut native) = limits::rebind(
        &mut case,
        &args,
        2 * 1024 * 1024 * 1024,
        30000,
        "+2GiB",
        "+30s",
    );
    native.held_processes.truncate(1);
    case.json("native.json", &json!(native));
    case.write("abstract.bin", b"abstract-unix-readiness");
    finish(
        &mut case,
        &native,
        vec![(
            "unix-abstract-round-trip",
            json!({"name":token.as_bytes(),"bytes":b"abstract-unix-readiness"}),
        )],
        vec![BehaviorArtifact {
            role: "unix-abstract".into(),
            path: "abstract.bin".into(),
        }],
        "own-abstract-positive",
        0,
    );
    case.write("abstract-expected.bin", b"abstract-unix-readiness");
    case.mutate("semantic.json",|semantic|{semantic["operations"][0]["operation"]=json!("unix-abstract-exchange");semantic["negative_probe"]=Value::Null;semantic["comparisons"]=json!([{"role":"unix-abstract","expected":"abstract-expected.bin","actual":"abstract.bin"}]);});
    case
}

pub fn outside(scenario: &str) -> PersistedCase {
    let (mut canary, denial, positive, args, challenge) = super::original_vectors::vector(scenario);
    let mut case = image::baseline_with_requirements(json!([]));
    case.record.key.family = "L-ISO-04".into();
    case.record.key.scenario = scenario.into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let (_, mut native) = limits::rebind(
        &mut case,
        &args,
        2 * 1024 * 1024 * 1024,
        30000,
        "+2GiB",
        "+30s",
    );
    native.held_processes.truncate(1);
    case.json("native.json", &json!(native));
    if scenario == "opath" {
        canary["leaked_descriptor"]["original"]["frontend_pid"] = json!(102);
        canary["leaked_descriptor"]["original"]["frontend_birth"] = json!(301);
    }
    case.json("outside-canary.json", &canary);
    let mut transcript = vec![];
    for (ordinal, (operation, observation)) in [
        ("neighboring-private-file", positive),
        ("native-outside-file-denied", denial.clone()),
    ]
    .into_iter()
    .enumerate()
    {
        let row = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":ordinal+1,"challenge":hex::encode(&challenge),"root_pid":2,"root_birth":302,"operation":operation,"observation":observation});
        transcript.extend(serde_json::to_vec(&row).unwrap());
        transcript.push(b'\n');
    }
    case.write("transcript.bin", &transcript);
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: case.record.run_id.clone(),
        key: case.record.key.clone(),
        challenge: "challenge.bin".into(),
        operations: vec![OperationObservation {
            operation: "native-authority-probe".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            observer: "owned-fixture-behavior".into(),
            native_receipt: "transcript.bin".into(),
        }],
        comparisons: vec![],
        counters: Default::default(),
        negative_probe: Some(NegativeProbe {
            stage: scenario.into(),
            domain: "linux".into(),
            native_code: denial["native_errno"].as_i64().unwrap(),
            receipt: "transcript.bin".into(),
        }),
        component_test: None,
        component_actors: None,
        windows_capacity: None,
        windows_refusal: None,
        fixture_behavior: Some(FixtureBehavior {
            descriptor: "input.json".into(),
            transcript: "transcript.bin".into(),
            peer_artifacts: vec![BehaviorArtifact {
                role: "outside-file-canary".into(),
                path: "outside-canary.json".into(),
            }],
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
        .find(|artifact| artifact.path == "input.json")
        .unwrap()
        .sha256
        .clone();
    case.json("case-evidence.json", &json!(evidence));
    case
}
