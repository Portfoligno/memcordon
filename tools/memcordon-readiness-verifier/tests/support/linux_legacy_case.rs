//! Original encoded frozen Unix records; no native execution claim.
use super::{linux_installed_case, persisted_case::PersistedCase};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};
pub fn baseline() -> PersistedCase {
    let mut case = linux_installed_case::installed("L-ID-01", "v1-preserve-caller");
    let prefix = "installed/installed/frozen-legacy";
    let root = linux_installed_case::EVIDENCE_ROOT;
    let fixture = b"original installed fixture";
    let fixture_hash = sha256(fixture);
    let old = linux_installed_case::read(&case, "installed/lease-owner.json");
    case.json("installed/lifetime/lease-owner.json", &old);
    let profile = memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate;
    let registry = json!({"format":"memcordon.local-policy","revision":1,"profiles":[{"profile":profile,"reference":profile.reference(),"enabled":true}],"grants":[{"id":"installed-preserved","revision":1,"profile":profile.reference(),"ceiling":profile.ceiling(),"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":[fixture_hash]}],"active_attempt_disposition":"drain-existing"});
    let epoch = json!({"service_instance":vec![7u8;16],"revision":9});
    let request = json!({"schema_version":1,"workload_plan_digest":fixture_hash,"authorized_profile":profile.reference(),"authorization":{"grant_id":"installed-preserved","grant_revision":1,"approved_plan_digest":fixture_hash},"ceiling":profile.ceiling(),"requirements":[],"endpoints":[],"expected_epoch":epoch});
    let image = |path: &str, data: &[u8], inode: u64| json!({"path":path.as_bytes(),"device":7,"inode":inode,"length":data.len(),"sha256":sha256(data),"uid":0,"mode":0o100755});
    let cli = image("/usr/libexec/memcordon", b"original CLI image", 20);
    let installed_fixture = image(
        "/usr/libexec/memcordon-installed-private-fixture",
        fixture,
        21,
    );
    let launcher = image("/usr/bin/setpriv", b"original setpriv image", 22);
    let agent = image(
        "/usr/libexec/memcordon-sealed-agent",
        b"original agent image",
        23,
    );
    let output = format!("{root}/installed/installed");
    let work = format!("{root}/native-work");
    let owner = json!({"format":"memcordon.linux-frozen-legacy-owner","revision":1,"registry":registry,"contract":request,"caller_uid":65534,"caller_gid":65534,"caller_group":65534,"work":work,"output":output,"cli":cli,"fixture":installed_fixture,"launcher":launcher,"host_network_namespace":{"device":7,"inode":24},"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    case.json(&format!("{prefix}/v1/owner.json"), &owner);
    case.json(&format!("{prefix}/v1/request.json"), &request);
    case.write(&format!("{prefix}/cli.bin"), b"original CLI image");
    case.write(&format!("{prefix}/fixture.bin"), fixture);
    case.write(&format!("{prefix}/launcher.bin"), b"original setpriv image");
    let held = |retired: bool| json!({"pid":50,"birth":60,"parent_pid":1,"parent_birth":1,"retirement_observed":retired});
    let stat = {
        let mut fields = vec!["S".to_owned(); 20];
        fields[19] = "60".into();
        format!("50 (original) {}", fields.join(" "))
    };
    let kernel = |image: &Value| json!({"device":image["device"],"inode":image["inode"],"length":image["length"],"sha256":image["sha256"]});
    let mut activation = std::collections::BTreeMap::new();
    for leaf in [
        "policy.json",
        "invocation.json",
        "creation.json",
        "stdout.json",
        "stderr.bin",
        "exit.json",
    ] {
        activation.insert(leaf.to_owned(), format!("{prefix}/v1-activation.{leaf}"));
    }
    let apply = json!({"program":b"/usr/libexec/memcordon-sealed-agent".as_slice(),"arguments":[b"package".as_slice(),b"policy",b"apply",b"--registry",format!("{output}/frozen-legacy/v1-activation.policy.json").as_bytes()],"cwd":work.as_bytes(),"environment":[],"started_unix_millis":1,"work_deadline_unix_millis":100,"budget_millis":60,"selected_image":agent});
    let typed: memcordon_core::workload_registry::RuntimePolicyRegistry =
        serde_json::from_value(registry.clone()).unwrap();
    let registry_digest = hex::encode(typed.canonical_digest().unwrap().bytes());
    let readback = json!({"format":"memcordon.local-activation","revision":1,"registry":registry,"epoch":epoch,"registry_digest":registry_digest,"revoked_admissions":[]});
    case.json(&activation["policy.json"], &registry);
    case.json(&activation["invocation.json"], &apply);
    case.json(
        &activation["creation.json"],
        &json!({"identity":held(false),"kernel_image":kernel(&agent),"stat":stat.as_bytes()}),
    );
    case.json(&activation["stdout.json"], &readback);
    case.write(&activation["stderr.bin"], b"");
    case.json(&activation["exit.json"],&json!({"identity":held(true),"native_status":0,"invocation_sha256":sha256(&serde_json::to_vec(&apply).unwrap()),"stdout_sha256":sha256(&serde_json::to_vec(&readback).unwrap()),"stderr_sha256":sha256(b"")}));
    let provider = json!({"generation":format!("{}:{}",case.index.version,case.index.source_commit),"source_commit":case.index.source_commit,"runtime_manifest_sha256":case.index.artifacts.iter().find(|a|a.path=="runtime-manifest.json").unwrap().sha256});
    let contract: memcordon_core::workload_contract::WorkloadContractV1 =
        serde_json::from_value(request.clone()).unwrap();
    let provider_typed = serde_json::from_value(provider).unwrap();
    let plan = memcordon_core::workload_evidence::RuntimePlanBinding::from_local_grant(
        &contract,
        typed.canonical_digest().unwrap(),
        provider_typed,
        serde_json::from_value(json!("original-boot")).unwrap(),
    )
    .unwrap();
    let plan = json!(plan);
    let effective = json!({"profile":profile,"ceiling":profile.ceiling(),"restriction":"linux-unix-only-socket-syscall-filter-alternate-paths-unknown"});
    let admission = json!({"format":"memcordon.local-attempt-binding","revision":1,"plan":plan,"attempt_id":"07070707070707070707070707070707","restart_attempt":0,"admission_nonce":vec![8u8;16],"caller_invocation_reference":vec![9u8;16]});
    let typed_admission: memcordon_core::workload_evidence::RuntimeAttemptBinding =
        serde_json::from_value(admission.clone()).unwrap();
    let attempt_digest = hex::encode(typed_admission.canonical_digest().unwrap().bytes());
    let mut checkpoint_bytes = b"attempt-policy-enforcement-v1\0\0\x01".to_vec();
    checkpoint_bytes.extend(hex::decode(&attempt_digest).unwrap());
    checkpoint_bytes.extend([1, 1, 1, 1, 1, 1, 1]);
    let checkpoint_hash = sha256(&checkpoint_bytes);
    let checkpoint = json!({"attempt_binding":attempt_digest,"digest":checkpoint_hash,"controls":"linux-unix-only-socket-syscall-filter-alternate-paths-unknown","target_gated":true,"caller_verified":true,"resources_verified":true,"guardian_verified":true,"epoch_verified":true,"durable":true});
    let pending = json!([
        "caller-identity",
        "invocation-identity",
        "descriptor-custody",
        "native-controls",
        "guardian",
        "current-epoch",
        "durable-checkpoint"
    ]);
    let planned = json!({"state":"planned","binding":plan,"effective":effective,"pending":pending});
    let admitted = json!({"state":"admitted","binding":admission,"effective":effective,"preauthorization":checkpoint_hash});
    let mut commands = Vec::new();
    for action in ["result", "plan", "capabilities"] {
        let row = format!("{prefix}/v1/{action}");
        let native_request = format!("{output}/frozen-legacy/v1/request.json");
        let native_report = format!("{work}/frozen-v1-{action}.json");
        let mut args = vec![
            "--reuid=65534".to_owned(),
            "--regid=65534".into(),
            "--groups=65534".into(),
            "--bounding-set=-all".into(),
            "--inh-caps=-all".into(),
            "--ambient-caps=-all".into(),
            "--no-new-privs".into(),
            "--".into(),
            "/usr/libexec/memcordon".into(),
        ];
        match action {
            "result" => args.extend([
                "--sealed".into(),
                "--workload-contract".into(),
                native_request,
                "--report-format".into(),
                "result-v1".into(),
                "--report".into(),
                native_report,
                "--".into(),
                "/usr/libexec/memcordon-installed-private-fixture".into(),
                "assert-frozen-baseline".into(),
            ]),
            "plan" => args.extend([
                "plan".into(),
                "--sealed".into(),
                "--plan-format".into(),
                "plan-v1".into(),
                "--workload-contract".into(),
                native_request,
            ]),
            _ => args.extend([
                "doctor".into(),
                "--require".into(),
                "sealed".into(),
                "--capability-format".into(),
                "capabilities-v1".into(),
                "--workload-contract".into(),
                native_request,
            ]),
        };
        if action == "result" {
            args.splice(
                9..9,
                [
                    "--mixed-observation-directory".into(),
                    format!("{output}/frozen-legacy/v1/result/observations"),
                ],
            );
        }
        let invocation = json!({"format":"memcordon.linux-frozen-legacy-invocation","revision":1,"program":b"/usr/bin/setpriv","arguments":args.iter().map(|a|a.as_bytes()).collect::<Vec<_>>(),"cwd":work.as_bytes(),"environment":[],"started_unix_millis":1,"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200,"budget_millis":60});
        let tool = json!({"version":case.index.version,"os":"linux"});
        let public = match action {
            "plan" => {
                json!({"format":"memcordon.plan","revision":1,"tool":tool,"private_plan":null,"authorizes_launch":false,"workload":planned})
            }
            "capabilities" => {
                json!({"format":"memcordon.capabilities","revision":1,"tool":tool,"private_plan":null,"authorizes_launch":false,"requirement":{"met":true,"workload":planned}})
            }
            _ => {
                json!({"format":"memcordon.result","revision":1,"tool":tool,"invocation":null,"policy":{"effective":{"workload":admitted}},"attempts":[{"policy_enforcement":{"state":"authorized","admission":admission,"before_authorization":checkpoint,"terminal":{"state":"retired","attempt_binding":attempt_digest,"checkpoint":checkpoint_hash,"controls_preserved":true,"provider_resources_closed":true}}}],"supervision":null,"error":null,"backend":null,"authorization":"granted","launch":{"state":"exec-observed","target_pid":70},"outcome":{"kind":"completed","native_termination":{"kind":"exit-code","code":0},"wrapper_status":0},"cleanup":{"state":"complete","direct_child_reaped":true,"workload_empty":true,"outstanding":[],"failed_operations":[]},"restart":null,"runtime":null,"private_execution":null,"private_rejection":null,"diagnostics":null,"provider_association":null,"delivery":null})
            }
        };
        let mut public = public;
        public["tool"] = json!({"name":"memcordon","version":case.index.version,"os":"linux","architecture":"x86_64","runtime_features":["sealed-runtime","private-tcp"]});
        if action != "result" {
            public["tool"] = json!({"name":"memcordon","version":case.index.version});
        }
        if action == "result" {
            let original_invocation = memcordon_core::InvocationReport {
                syntax: "plus-budgets-v1".into(),
                budget_tokens: vec![],
                memory_token: None,
                deadline_token: None,
                argv: [
                    "/usr/libexec/memcordon-installed-private-fixture",
                    "assert-frozen-baseline",
                ]
                .into_iter()
                .map(|s| memcordon_core::NativeArgument::from_os(std::ffi::OsStr::new(s)))
                .collect(),
            };
            public["invocation"] = json!({"association_sha256":sha256(&serde_json::to_vec(&original_invocation).unwrap()),"requested_memory":null,"requested_deadline":null,"applied_memory":null,"applied_deadline":null});
            public["runtime"] = json!({"kind":"unavailable","reason":"no operational runtime observation available"});
            public["delivery"] = json!("prepared");
            public["backend"] = json!({"name":"linux-sealed-provider","containment":{"supported":true,"reason":null},"boundary":"sealed","memory":null,"deadline":{"supported":true,"reason":null},"limitations":[]});
        }
        let stdout = if action == "result" {
            json!({"format":"memcordon.frozen-linux-unix-baseline","revision":1,"pid":70,"birth":80,"uid":[65534,65534,65534,65534],"gid":[65534,65534,65534,65534],"groups":[65534],"unix_bytes":b"frozen-unix-baseline".as_slice(),"denials":[{"family":2,"native_errno":97},{"family":10,"native_errno":97}]})
        } else {
            public.clone()
        };
        case.json(&format!("{row}/invocation.json"), &invocation);
        case.json(&format!("{row}/creation.json"),&json!({"identity":held(false),"kernel_image":kernel(&launcher),"stat":stat.as_bytes()}));
        case.json(&format!("{row}/stdout.bin"), &stdout);
        case.write(&format!("{row}/stderr.bin"), b"");
        case.json(&format!("{row}/exit.json"),&json!({"identity":held(true),"native_status":0,"invocation_sha256":sha256(&serde_json::to_vec(&invocation).unwrap()),"stdout_sha256":sha256(&serde_json::to_vec(&stdout).unwrap()),"stderr_sha256":sha256(b""),"cli":cli,"fixture":installed_fixture,"launcher":launcher}));
        if action == "result" {
            case.json(&format!("{row}/result.json"), &public);
        }
        let (provider_request, provider_terminal) = if action == "result" {
            let (raw_request, raw_terminal) = baseline_exchange(&request, &public);
            let request_path = format!(
                "{row}/observations/07070707070707070707070707070707.legacy-provider-request.bin"
            );
            let terminal_path = format!(
                "{row}/observations/07070707070707070707070707070707.legacy-provider-terminal.bin"
            );
            case.write(&request_path, &raw_request);
            case.write(&terminal_path, &raw_terminal);
            (Some(request_path), Some(terminal_path))
        } else {
            (None, None)
        };
        commands.push(LinuxFrozenLegacyCommand {
            action: action.into(),
            invocation: format!("{row}/invocation.json"),
            creation: format!("{row}/creation.json"),
            exit: format!("{row}/exit.json"),
            stdout: format!("{row}/stdout.bin"),
            stderr: format!("{row}/stderr.bin"),
            result: if action == "result" {
                Some(format!("{row}/result.json"))
            } else {
                None
            },
            provider_request,
            provider_terminal,
        });
    }
    let evidence = LinuxFrozenLegacyEvidence {
        format: "memcordon.consumer-readiness.linux-frozen-legacy".into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: case.record.run_id.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        owner: format!("{prefix}/v1/owner.json"),
        original_lease: "installed/lifetime/lease-owner.json".into(),
        request: format!("{prefix}/v1/request.json"),
        cli: format!("{prefix}/cli.bin"),
        fixture: format!("{prefix}/fixture.bin"),
        launcher: format!("{prefix}/launcher.bin"),
        activation,
        commands,
    };
    case.json("case-evidence.json", &json!(evidence));
    case
}

/// A separate historical private TCP record, restored under its own epoch.
pub fn baseline_v2() -> PersistedCase {
    let mut case = baseline();
    let prefix = "installed/installed/frozen-legacy";
    case.record.key.scenario = "v2-preserve-caller".into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let profile = memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1;
    let plan_hash = sha256(b"original installed fixture");
    let mut delegated = json!({"reference":{"id":"installed-delegated","semantic_digest":"0".repeat(64)},"enabled":true,"uid":65533,"gid":65533,"supplementary_groups":[],"entrypoints":[{"id":"installed-fixture","absolute_path":"/usr/libexec/memcordon-installed-private-fixture","sha256":plan_hash,"size":b"original installed fixture".len()}]});
    delegated["reference"]["semantic_digest"] = json!(
        serde_json::from_value::<memcordon_core::workload_registry_v2::LinuxExecutionIdentityV2>(
            delegated.clone()
        )
        .unwrap()
        .semantic_digest()
        .unwrap()
    );
    let registry = json!({"format":"memcordon.local-private-policy","revision":1,"profiles":[{"profile":profile,"reference":profile.reference(),"enabled":true}],"execution_identities":[delegated],"grants":[{"id":"installed-preserved","revision":1,"profile":profile.reference(),"ceiling":profile.ceiling(),"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":[plan_hash],"execution_identity":{"kind":"preserve-caller"}},{"id":"installed-delegated","revision":1,"profile":profile.reference(),"ceiling":profile.ceiling(),"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":[plan_hash],"execution_identity":{"kind":"administrator-profile","reference":delegated["reference"]}}],"active_attempt_disposition":"drain-existing"});
    let epoch = json!({"service_instance":vec![7u8;16],"revision":10});
    let request = json!({"schema_version":2,"workload_plan_digest":plan_hash,"authorized_profile":profile.reference(),"authorization":{"grant_id":"installed-preserved","grant_revision":1,"approved_plan_digest":plan_hash},"ceiling":profile.ceiling(),"requirements":[],"endpoints":[],"expected_epoch":epoch,"execution_identity":{"kind":"preserve-caller"}});
    let mut owner = linux_installed_case::read(&case, &format!("{prefix}/v1/owner.json"));
    owner["registry"] = registry.clone();
    owner["contract"] = request.clone();
    case.json(&format!("{prefix}/v2/owner.json"), &owner);
    case.json(&format!("{prefix}/v2/request.json"), &request);
    let typed: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry =
        serde_json::from_value(registry.clone()).unwrap();
    let registry_digest = hex::encode(typed.canonical_digest().unwrap().bytes());
    let mut activation = std::collections::BTreeMap::new();
    for leaf in [
        "policy.json",
        "invocation.json",
        "creation.json",
        "stdout.json",
        "stderr.bin",
        "exit.json",
    ] {
        activation.insert(leaf.to_owned(), format!("{prefix}/v2-restoration.{leaf}"));
    }
    let mut apply =
        linux_installed_case::read(&case, &format!("{prefix}/v1-activation.invocation.json"));
    apply["arguments"][4] = json!(
        format!(
            "{}/frozen-legacy/v2-restoration.policy.json",
            owner["output"].as_str().unwrap()
        )
        .as_bytes()
    );
    let readback = json!({"format":"memcordon.local-private-activation","revision":1,"registry":registry,"epoch":epoch,"registry_digest":registry_digest,"revoked_admissions":[]});
    case.json(&activation["policy.json"], &registry);
    case.json(&activation["invocation.json"], &apply);
    let creation =
        linux_installed_case::read(&case, &format!("{prefix}/v1-activation.creation.json"));
    case.json(&activation["creation.json"], &creation);
    case.json(&activation["stdout.json"], &readback);
    case.write(&activation["stderr.bin"], b"");
    let mut exit = linux_installed_case::read(&case, &format!("{prefix}/v1-activation.exit.json"));
    exit["invocation_sha256"] = json!(sha256(&serde_json::to_vec(&apply).unwrap()));
    exit["stdout_sha256"] = json!(sha256(&serde_json::to_vec(&readback).unwrap()));
    case.json(&activation["exit.json"], &exit);
    // Encode the historical argv grammar independently of the verifier helper.
    fn put(out: &mut Vec<u8>, value: &[u8]) {
        out.extend((value.len() as u32).to_be_bytes());
        out.extend(value);
    }
    let mut launch = Vec::new();
    launch.extend(3u16.to_be_bytes());
    launch.extend(0u64.to_be_bytes());
    put(
        &mut launch,
        b"/usr/libexec/memcordon-installed-private-fixture",
    );
    let args = [b"assert-private-runtime".as_slice(), b"65534", b"65534"];
    launch.extend((args.len() as u32).to_be_bytes());
    for arg in args {
        put(&mut launch, arg);
    }
    launch.extend(0u32.to_be_bytes());
    launch.extend([0, 1]);
    launch.extend(0u64.to_be_bytes());
    launch.extend([0, 1, 1]);
    for n in [50u64, 2000, 0, 0] {
        launch.extend(n.to_be_bytes());
    }
    launch.extend(5u32.to_be_bytes());
    launch.extend([1, 2, 3, 4, 5, 0]);
    let contract: memcordon_core::workload_contract::WorkloadContractV2 =
        serde_json::from_value(request.clone()).unwrap();
    let semantic = hex::encode(
        memcordon_core::workload_codec::contract_digest_v2(&contract)
            .unwrap()
            .bytes(),
    );
    let envelope = memcordon_core::private_runtime::PrivateRuntimeRequest {
        format: "memcordon.private-runtime-request".into(),
        revision: 1,
        contract,
        native_launch: launch.clone(),
        attempt_deadline_millis: None,
    };
    let native_hash = sha256(&serde_json::to_vec(&envelope).unwrap());
    let invocation_hash = sha256(&launch);
    let row = format!("{prefix}/v2/result");
    let mut invocation =
        linux_installed_case::read(&case, &format!("{prefix}/v1/result/invocation.json"));
    let mut arguments: Vec<Vec<u8>> =
        serde_json::from_value(invocation["arguments"].clone()).unwrap();
    arguments.drain(9..11);
    arguments[11] = format!(
        "{}/frozen-legacy/v2/request.json",
        owner["output"].as_str().unwrap()
    )
    .into_bytes();
    arguments[15] =
        format!("{}/frozen-v2-result.json", owner["work"].as_str().unwrap()).into_bytes();
    arguments.pop();
    arguments.extend(args.iter().map(|a| a.to_vec()));
    invocation["arguments"] = json!(arguments);
    let fixture = json!({"format":"memcordon.private-native-fixture","revision":1,"uid":[65534,65534,65534,65534],"gid":[65534,65534,65534,65534],"groups":[65534],"no_new_privileges":true,"capabilities":{"CapInh":"0000000000000000","CapPrm":"0000000000000000","CapEff":"0000000000000000","CapBnd":"0000000000000000","CapAmb":"0000000000000000"},"entry_fds":[0,1,2],"network_namespace":"net:[25]","ipv6_addresses":0,"tcp_port":32768,"tcp_bytes":"private","denied":["unix","ipv6","udp","raw","netlink","packet","socketpair","recvmsg","sendmsg","unshare","setns","ptrace","pidfd_getfd","io_uring_setup","setresuid","setresgid","fcntl-async","clone-newnet","clone-detached"]});
    let admission = json!({"format":"memcordon.private-admission-metadata","revision":1,"request":request,"request_sha256":semantic,"invocation_sha256":invocation_hash,"caller":{"platform":"linux","uid":65534},"registry_digest":registry_digest,"epoch":epoch,"admission_nonce":vec![8u8;16],"profile_id":profile.reference()});
    let mut public = linux_installed_case::read(&case, &format!("{prefix}/v1/result/result.json"));
    public["policy"] = json!({"effective":{"workload":null}});
    public["attempts"] = json!([]);
    public["private_execution"] = json!({"terminal":{"format":"memcordon.private-runtime-terminal","revision":1,"provider":"original-provider","native_abi":"linux-x86_64","attempt_id":"original-private-attempt","request_sha256":native_hash,"admission_metadata":admission,"launch":"exec-observed","authorization_offset_millis":1,"authorization_monotonic_millis":1,"target_pid":70,"network_namespace":{"device":7,"inode":25},"exec_observed":true,"post_exec_descriptor_count":3,"outcome":"completed","native_termination":{"kind":"exit-code","code":0},"cleanup":"complete","account_reservation_retired":true,"namespace_references_closed":true,"error":null},"frontend_relay_drained":true,"frontend_interruption":null});
    public["runtime"] = json!({"kind":"linux-private-tcp4","profile_reference":"linux-tcp4-private-v1","identity_reference":"caller","identity_kind":"preserve-caller","activation_epoch":10,"native_abi":"linux-x86_64","invocation_sha256":invocation_hash,"private_namespace_observed":true,"no_socket_at_entry":true,"exec_observed":true,"port_range":[32768,60999],"unprivileged_port_start":0,"resources_retired":true});
    case.json(&format!("{row}/invocation.json"), &invocation);
    let creation = linux_installed_case::read(&case, &format!("{prefix}/v1/result/creation.json"));
    case.json(&format!("{row}/creation.json"), &creation);
    case.json(&format!("{row}/stdout.bin"), &fixture);
    case.write(&format!("{row}/stderr.bin"), b"");
    case.json(&format!("{row}/result.json"), &public);
    let mut exit = linux_installed_case::read(&case, &format!("{prefix}/v1/result/exit.json"));
    exit["invocation_sha256"] = json!(sha256(&serde_json::to_vec(&invocation).unwrap()));
    exit["stdout_sha256"] = json!(sha256(&serde_json::to_vec(&fixture).unwrap()));
    case.json(&format!("{row}/exit.json"), &exit);
    let mut evidence: LinuxFrozenLegacyEvidence =
        serde_json::from_value(linux_installed_case::read(&case, "case-evidence.json")).unwrap();
    evidence.key = case.record.key.clone();
    evidence.owner = format!("{prefix}/v2/owner.json");
    evidence.request = format!("{prefix}/v2/request.json");
    evidence.activation = activation;
    evidence.commands = vec![LinuxFrozenLegacyCommand {
        action: "result".into(),
        invocation: format!("{row}/invocation.json"),
        creation: format!("{row}/creation.json"),
        exit: format!("{row}/exit.json"),
        stdout: format!("{row}/stdout.bin"),
        stderr: format!("{row}/stderr.bin"),
        result: Some(format!("{row}/result.json")),
        provider_request: None,
        provider_terminal: None,
    }];
    case.json("case-evidence.json", &json!(evidence));
    case
}

fn baseline_exchange(request: &Value, public: &Value) -> (Vec<u8>, Vec<u8>) {
    fn put(out: &mut Vec<u8>, value: &[u8]) {
        out.extend((value.len() as u32).to_be_bytes());
        out.extend(value);
    }
    let mut launch = 3u16.to_be_bytes().to_vec();
    launch.extend(0u64.to_be_bytes());
    put(
        &mut launch,
        b"/usr/libexec/memcordon-installed-private-fixture",
    );
    launch.extend(1u32.to_be_bytes());
    put(&mut launch, b"assert-frozen-baseline");
    launch.extend(0u32.to_be_bytes());
    launch.extend([0, 1]);
    launch.extend(0u64.to_be_bytes());
    launch.extend([0, 1, 1]);
    for n in [50u64, 2000, 0, 0] {
        launch.extend(n.to_be_bytes());
    }
    launch.extend(5u32.to_be_bytes());
    launch.extend([1, 2, 3, 4, 5, 1]);
    let typed: memcordon_core::workload_contract::WorkloadContractV1 =
        serde_json::from_value(request.clone()).unwrap();
    put(&mut launch, &serde_json::to_vec(&typed).unwrap());
    let mut terminal = String::new();
    for (name, value) in [
        ("schema-version", "2"),
        ("mechanism", "linux-pid-namespace-cgroup-v2"),
        ("status", "0"),
        ("exec-status", "success"),
        ("exec-os-code", "none"),
        (
            "credential-transition-disposition",
            "preserve-caller-envelope",
        ),
        ("memory-limit-exceeded", "false"),
        ("deadline-exceeded", "false"),
        ("target-pid", "70"),
        ("authorization-offset-millis", "1"),
    ] {
        terminal.push_str(&format!("{name}={value}\n"));
    }
    terminal.push_str(&format!(
        "policy-enforcement={}\n",
        public["attempts"][0]["policy_enforcement"]
    ));
    for name in [
        "caller-envelope-digest",
        "caller-capability-bounding-set-digest",
        "caller-mount-namespace-digest",
    ] {
        terminal.push_str(&format!("{name}={}\n", sha256(b"original caller context")));
    }
    for name in [
        "spawn-error-reported",
        "assignment-verified",
        "namespaces-verified",
        "target-initial-credentials-verified",
        "initial-provider-capabilities-absent",
        "caller-no-new-privs",
        "target-no-new-privs-matched",
        "target-capability-bounding-set-matched",
        "target-mount-context-derived-from-caller",
        "boundary-independent-of-credentials",
        "descriptors-verified",
        "writable-ancestor-cgroup-denied",
        "parent-namespace-handles-denied",
        "recursive-provider-request-denied",
        "guardian-ready-before-authorization",
        "frontend-loss-authority-verified",
        "cgroup-kill-invoked",
        "cgroup-empty",
        "init-reaped",
        "guardian-reaped",
        "boundary-retired",
    ] {
        terminal.push_str(&format!("{name}=true\n"));
    }
    let frame = |kind: u16, payload: &[u8]| {
        let mut raw = 3u16.to_be_bytes().to_vec();
        raw.extend(kind.to_be_bytes());
        raw.extend(((72 + payload.len()) as u32).to_be_bytes());
        raw.extend([9u8; 16]);
        raw.extend([7u8; 16]);
        raw.extend(hex::decode(sha256(payload)).unwrap());
        raw.extend(payload);
        raw
    };
    (frame(2, &launch), frame(105, terminal.as_bytes()))
}
