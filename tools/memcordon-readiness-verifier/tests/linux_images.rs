use memcordon_readiness_verifier::validate_linux_image_mutation;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn importer_wait_requires_same_original_pidfd_creation_and_native_retirement() {
    use memcordon_readiness_verifier::validate_linux_image_command;
    let agent = "a".repeat(64);
    let command = json!({"format":"memcordon.linux-image-import-command","revision":1,"identity":{},"cell":{},"lease_id":"lease","scenario":"first-image","program":"/usr/libexec/memcordon-sealed-agent","executable_sha256":agent,"argv":[],"cwd":"/owned/first-image","environment_cleared":true,"definition_sha256":"b".repeat(64),"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    let command_bytes = serde_json::to_vec(&command).unwrap();
    let creation = json!({"format":"memcordon.linux-image-import-creation","revision":1,"process_id":101,"birth":123,"pidfd_device":5,"pidfd_inode":456,"invocation_sha256":hash(&command_bytes),"kernel_image":{"device":7,"inode":8,"length":1024,"sha256":agent}});
    let creation_bytes = serde_json::to_vec(&creation).unwrap();
    let native = json!({"format":"memcordon.linux-image-import-process","revision":1,"process_id":101,"birth":123,"raw_wait_status":256,"native_exit":1,"signal":null,"invocation_sha256":hash(&command_bytes),"stdout_sha256":hash(b""),"stderr_sha256":hash(b"denied"),"executable_device":7,"executable_inode":8,"creation_sha256":hash(&creation_bytes),"pidfd_device":5,"pidfd_inode":456,"pidfd_revents":1});
    let exit = json!({"native_exit":1,"success":false});
    let validate = |native: &Value, creation: &[u8]| {
        validate_linux_image_command(
            &command,
            native,
            creation,
            &exit,
            &command_bytes,
            b"",
            b"denied",
            &agent,
        )
    };
    assert_eq!(validate(&native, &creation_bytes).unwrap(), 1);
    for (field, value) in [
        ("birth", json!(124)),
        ("pidfd_inode", json!(457)),
        ("pidfd_revents", json!(0)),
        ("pidfd_revents", json!(8)),
        ("process_id", json!(2147483648u64)),
        ("executable_device", json!(0)),
    ] {
        let mut hostile = native.clone();
        hostile[field] = value;
        assert!(
            validate(&hostile, &creation_bytes).is_err(),
            "accepted {field}"
        );
    }
    let mut hostile_image = creation.clone();
    hostile_image["kernel_image"]["sha256"] = json!("f".repeat(64));
    let bytes = serde_json::to_vec(&hostile_image).unwrap();
    let mut rebound = native.clone();
    rebound["creation_sha256"] = json!(hash(&bytes));
    assert!(validate(&rebound, &bytes).is_err());
    let mut hostile = creation.clone();
    hostile["extra_authority"] = json!(true);
    let bytes = serde_json::to_vec(&hostile).unwrap();
    let mut rebound = native;
    rebound["creation_sha256"] = json!(hash(&bytes));
    assert!(validate(&rebound, &bytes).is_err());
}

// Independent ELF64 vector with bounded PT_LOAD/PT_DYNAMIC/PT_INTERP and an
// actual DT_NEEDED string. These parser vectors do not claim native execution.
fn elf() -> Vec<u8> {
    let mut bytes = vec![0u8; 1024];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
    for (index, tag, offset, address, size) in [
        (0, 1u32, 0u64, 0x400000u64, 1024u64),
        (1, 2, 256, 0x400100, 64),
        (2, 3, 400, 0x400190, 16),
    ] {
        let base = 64 + index * 56;
        bytes[base..base + 4].copy_from_slice(&tag.to_le_bytes());
        bytes[base + 8..base + 16].copy_from_slice(&offset.to_le_bytes());
        bytes[base + 16..base + 24].copy_from_slice(&address.to_le_bytes());
        bytes[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
    }
    bytes[256..264].copy_from_slice(&5u64.to_le_bytes());
    bytes[264..272].copy_from_slice(&0x400200u64.to_le_bytes());
    bytes[272..280].copy_from_slice(&1u64.to_le_bytes());
    bytes[280..288].copy_from_slice(&1u64.to_le_bytes());
    bytes[400..411].copy_from_slice(b"/lib/ld.so\0");
    bytes[513..521].copy_from_slice(b"libc.so\0");
    bytes
}
fn vector(
    scenario: &str,
) -> (
    Value,
    Value,
    Vec<u8>,
    BTreeMap<String, (Vec<u8>, Option<Vec<u8>>)>,
) {
    let first = elf();
    let mut files = BTreeMap::from([
        ("bin/owned".to_owned(), first.clone()),
        ("lib/ld.so".into(), b"native-interpreter".to_vec()),
        ("lib/libc.so".into(), b"native-library".to_vec()),
    ]);
    let entries=files.iter().map(|(path,bytes)|json!({"kind":"regular","path":path,"sha256":hash(bytes),"size":bytes.len(),"executable":true})).collect::<Vec<_>>();
    let baseline = json!({"format":"memcordon.runtime-image","revision":1,"image_id":"owned-image","target":"x86_64-unknown-linux-gnu","entries":entries,
        "entrypoints":[{"id":"owned-readiness","path":"bin/owned"}],"library_directories":["lib"],"startup_environment":[]});
    let mut definition = baseline.clone();
    let selected = match scenario {
        "interpreter" => Some("lib/ld.so"),
        "shared-library" => Some("lib/libc.so"),
        "ld-injection" | "loader-config" => None,
        _ => Some("bin/owned"),
    };
    let mut captures = BTreeMap::new();
    if let Some(path) = selected {
        let before = files[path].clone();
        let after = files.get_mut(path).unwrap();
        if matches!(scenario, "first-image" | "interpreter" | "shared-library") {
            after[0] ^= 1;
        }
        if scenario == "rpath-injection" {
            after[272..280].copy_from_slice(&15u64.to_le_bytes());
            after[513..519].copy_from_slice(b"/work\0");
            definition["entries"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|entry| entry["path"] == path)
                .unwrap()["sha256"] = hash(after).into();
        }
        captures.insert(path.to_owned(), (after.clone(), Some(before)));
    }
    if scenario == "ld-injection" {
        definition["startup_environment"] =
            json!([{"name":"LD_PRELOAD","value":"/work/owned-injected.so"}]);
    }
    if scenario == "loader-config" {
        let bytes = b"/work/owned-injected.so\n".to_vec();
        definition["entries"].as_array_mut().unwrap().push(json!({"kind":"regular","path":"etc/ld.so.preload","sha256":hash(&bytes),"size":bytes.len(),"executable":false}));
        files.insert("etc/ld.so.preload".into(), bytes.clone());
        captures.insert("etc/ld.so.preload".into(), (bytes, None));
    }
    let members=files.iter().enumerate().map(|(index,(path,bytes))|json!({"path":path,"device":8,"inode":100+index,"uid":0,"mode":if scenario=="writable-alias"&&path=="bin/owned"{0o100700}else{0o100555},
        "nlink":if scenario=="writable-alias"&&path=="bin/owned"{2}else{1},"size":bytes.len(),"ctime_seconds":1,"ctime_nanoseconds":0,"sha256":hash(bytes),
        "bytes":if captures.contains_key(path){json!("captured-native-member")}else{Value::Null},"baseline_bytes":if captures.get(path).is_some_and(|(_,before)|before.is_some()){json!("captured-baseline-member")}else{Value::Null}})).collect::<Vec<_>>();
    let alias = if scenario == "writable-alias" {
        json!({"path":"/protected/writable-startup-alias","device":8,"inode":100,"nlink":2,"mode":0o100700})
    } else {
        Value::Null
    };
    (
        definition,
        json!({"format":"memcordon.linux-image-source-inventory","revision":1,"identity":{},"cell":{},"lease_id":"owned-lease","scenario":scenario,"source_root":"/protected/source","baseline_definition":baseline,"members":members,"alias":alias}),
        first,
        captures,
    )
}

fn image_id(owner: &Value, scenario: &str) -> String {
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        run_id: &'a str,
        source_commit: &'a str,
        source_tree_sha256: &'a str,
        version: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Cell<'a> {
        target: &'a str,
        channel: &'a str,
    }
    let source = &owner["identity"];
    let cell = &owner["cell"];
    hash(
        &serde_json::to_vec(&(
            Identity {
                run_id: source["run_id"].as_str().unwrap(),
                source_commit: source["source_commit"].as_str().unwrap(),
                source_tree_sha256: source["source_tree_sha256"].as_str().unwrap(),
                version: source["version"].as_str().unwrap(),
            },
            Cell {
                target: cell["target"].as_str().unwrap(),
                channel: cell["channel"].as_str().unwrap(),
            },
            "original-lease",
            scenario,
        ))
        .unwrap(),
    )
}

fn command_graph(
    case: &mut persisted_case::PersistedCase,
    prefix: &str,
    owner: &Value,
    scenario: &str,
    definition: &Value,
    status: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> (String, String, String, String, String, String) {
    let path = |leaf: &str| format!("{prefix}/{leaf}");
    let image_admin = owner["image_admin_root"].as_str().unwrap();
    let output = owner["output"].as_str().unwrap();
    let command = serde_json::json!({"format":"memcordon.linux-image-import-command","revision":1,"identity":owner["identity"],"cell":owner["cell"],"lease_id":"original-lease","scenario":scenario,"program":"/usr/libexec/memcordon-sealed-agent","executable_sha256":owner["expected_agent_sha256"],"argv":["package","policy","image","install","--definition",format!("{image_admin}/{scenario}/definition.json"),"--source-root",format!("{image_admin}/{scenario}/source"),"--json"],"cwd":format!("{output}/{scenario}"),"environment_cleared":true,"definition_sha256":hash(&serde_json::to_vec(definition).unwrap()),"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    let command_bytes = serde_json::to_vec(&command).unwrap();
    let command_path = path("invocation.json");
    case.write(&command_path, &command_bytes);
    let creation = serde_json::json!({"format":"memcordon.linux-image-import-creation","revision":1,"process_id":101,"birth":123,"pidfd_device":5,"pidfd_inode":456,"invocation_sha256":hash(&command_bytes),"kernel_image":{"device":7,"inode":8,"length":20,"sha256":owner["expected_agent_sha256"]}});
    let creation_bytes = serde_json::to_vec(&creation).unwrap();
    let creation_path = path("native-creation.json");
    case.write(&creation_path, &creation_bytes);
    let native_path = path("native-process.json");
    case.json(&native_path,&json!({"format":"memcordon.linux-image-import-process","revision":1,"process_id":101,"birth":123,"raw_wait_status":status*256,"native_exit":status,"signal":null,"invocation_sha256":hash(&command_bytes),"stdout_sha256":hash(stdout),"stderr_sha256":hash(stderr),"executable_device":7,"executable_inode":8,"creation_sha256":hash(&creation_bytes),"pidfd_device":5,"pidfd_inode":456,"pidfd_revents":1}));
    let exit_path = path("exit.json");
    case.json(
        &exit_path,
        &json!({"native_exit":status,"success":status==0}),
    );
    let stdout_path = path("stdout.json");
    case.write(&stdout_path, stdout);
    let stderr_path = path("stderr.bin");
    case.write(&stderr_path, stderr);
    (
        command_path,
        native_path,
        creation_path,
        exit_path,
        stdout_path,
        stderr_path,
    )
}

fn persisted_import(scenario: &str) -> persisted_case::PersistedCase {
    use memcordon_readiness_verifier::*;
    let loader = matches!(scenario, "loader-config" | "rpath-injection");
    let family = if scenario == "ld-injection" || loader {
        "L-IMG-02"
    } else {
        "L-IMG-01"
    };
    let mut case = linux_installed_case::installed(family, scenario);
    let owner_path = "installed/mixed-cases/image-cases/owner.json";
    let owner = linux_installed_case::read(&case, owner_path);
    let prefix = format!("installed/mixed-cases/image-cases/{scenario}");
    let output = owner["output"].as_str().unwrap();
    let image_admin = owner["image_admin_root"].as_str().unwrap();
    let (mut definition, mut inventory, first, captures) = vector(scenario);
    let id = image_id(&owner, scenario);
    definition["image_id"] = json!(id);
    inventory["baseline_definition"]["image_id"] = json!(id);
    inventory["identity"] = owner["identity"].clone();
    inventory["cell"] = owner["cell"].clone();
    inventory["lease_id"] = json!("original-lease");
    inventory["source_root"] = json!(format!("{image_admin}/{scenario}/source"));
    if scenario == "writable-alias" {
        inventory["alias"]["path"] =
            json!(format!("{image_admin}/{scenario}/writable-startup-alias"));
    }
    let cleanup = if scenario == "ld-injection" {
        inventory["baseline_definition"].clone()
    } else {
        definition.clone()
    };
    let cleanup_reference = linux_image_reference(&cleanup, &case.record.key.target).unwrap();
    let mut acquired = inventory["baseline_definition"].clone();
    acquired["image_id"] = json!("original-acquired-image");
    case.mutate("installed/owned-resources-acquired.json", |raw| {
        raw["images"]["runtime"] = acquired
    });
    let mut source_members = Vec::new();
    for (ordinal, native) in inventory["members"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        let path = native["path"].as_str().unwrap().to_owned();
        if let Some((bytes, baseline)) = captures.get(&path) {
            let captured = format!("{prefix}/source-member-{ordinal}.bin");
            case.write(&captured, bytes);
            native["bytes"] = json!(format!("{output}/{scenario}/source-member-{ordinal}.bin"));
            let baseline_path = baseline.as_ref().map(|bytes| {
                let path = format!("{prefix}/baseline-member-{ordinal}.bin");
                case.write(&path, bytes);
                native["baseline_bytes"] =
                    json!(format!("{output}/{scenario}/baseline-member-{ordinal}.bin"));
                path
            });
            source_members.push(LinuxImageMemberCapture {
                path,
                bytes: captured,
                baseline_bytes: baseline_path,
            });
        }
    }
    let definition_path = format!("{prefix}/submitted-definition.json");
    case.json(&definition_path, &definition);
    let cleanup_path = format!("{prefix}/cleanup-definition.json");
    case.json(&cleanup_path, &cleanup);
    let inventory_path = format!("{prefix}/native-source-inventory.json");
    case.json(&inventory_path, &inventory);
    let baseline_path = format!("{prefix}/baseline-entrypoint.bin");
    case.write(&baseline_path, &first);
    let intent_path = format!("{prefix}/import-intent.json");
    case.json(&intent_path,&json!({"format":"memcordon.linux-readiness-image-import-intent","revision":1,"identity":owner["identity"],"cell":owner["cell"],"lease_id":"original-lease","scenario":scenario,"definition":format!("{image_admin}/{scenario}/definition.json"),"definition_sha256":hash(&serde_json::to_vec(&definition).unwrap()),"cleanup_definition":format!("{image_admin}/{scenario}/cleanup-definition.json"),"cleanup_definition_sha256":hash(&serde_json::to_vec(&cleanup).unwrap()),"submitted_definition_valid":scenario!="ld-injection","reference":cleanup_reference,"source_root":format!("{image_admin}/{scenario}/source"),"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200}));
    let cause = match scenario {
        "writable-alias" => "image member type/size/mode/alias differs",
        "ld-injection" => "unsafe or duplicate trusted-startup environment",
        _ => "image content digest differs",
    };
    let import_stdout = if loader {
        serde_json::to_vec(&json!({"format":"memcordon.runtime-image-installation","revision":1,"image":linux_image_reference(&definition,&case.record.key.target).unwrap(),"target":case.record.key.target,"policy_activated":false,"member_count":definition["entries"].as_array().unwrap().len()})).unwrap()
    } else {
        Vec::new()
    };
    let import_stderr = if loader {
        Vec::new()
    } else {
        format!("{cause}\n").into_bytes()
    };
    let import_status = if loader { 0 } else { 1 };
    let (invocation, native_process, native_creation, exit, stdout, stderr) = command_graph(
        &mut case,
        &prefix,
        &owner,
        scenario,
        &definition,
        import_status,
        &import_stdout,
        &import_stderr,
    );
    let mut neighbor = inventory["baseline_definition"].clone();
    neighbor["image_id"] = json!(image_id(&owner, "neighbor-import"));
    let neighbor_prefix = "installed/mixed-cases/image-cases/neighbor-import";
    let neighbor_definition = format!("{neighbor_prefix}/submitted-definition.json");
    case.json(&neighbor_definition, &neighbor);
    let installation = json!({"format":"memcordon.runtime-image-installation","revision":1,"image":linux_image_reference(&neighbor,&case.record.key.target).unwrap(),"target":case.record.key.target,"policy_activated":false,"member_count":neighbor["entries"].as_array().unwrap().len()});
    let (
        neighbor_invocation,
        neighbor_native_process,
        neighbor_native_creation,
        neighbor_exit,
        neighbor_stdout,
        neighbor_stderr,
    ) = command_graph(
        &mut case,
        neighbor_prefix,
        &owner,
        "neighbor-import",
        &neighbor,
        0,
        &serde_json::to_vec(&installation).unwrap(),
        b"",
    );
    let retirement = format!("{prefix}/retirement.json");
    case.json(&retirement,&if loader{json!({"format":"memcordon.runtime-image-retirement","revision":1,"reference":cleanup_reference,"storage_absent":true,"device":7,"inode":9})}else{json!({"format":"memcordon.runtime-image-retirement","revision":1,"reference":cleanup_reference,"storage_absent":true,"already_absent":true})});
    let retirement_exit = format!("{prefix}/retirement-exit.json");
    case.json(&retirement_exit, &json!({"native_exit":0,"success":true}));
    let retirement_stderr = format!("{prefix}/retirement-stderr.bin");
    case.write(&retirement_stderr, b"");
    let observation = format!("{prefix}/observation.json");
    case.json(&observation,&json!({"family":family,"scenario":scenario,"definition":format!("{image_admin}/{scenario}/definition.json"),"definition_capture":format!("{output}/{scenario}/submitted-definition.json"),"cleanup_definition_capture":format!("{output}/{scenario}/cleanup-definition.json"),"source_root":format!("{image_admin}/{scenario}/source"),"selected_member":captures.keys().next(),"invocation":format!("{output}/{scenario}/invocation.json"),"native_process":format!("{output}/{scenario}/native-process.json"),"native_creation":format!("{output}/{scenario}/native-creation.json"),"source_inventory":format!("{output}/{scenario}/native-source-inventory.json"),"baseline_entrypoint":format!("{output}/{scenario}/baseline-entrypoint.bin"),"stdout":format!("{output}/{scenario}/stdout.json"),"stderr":format!("{output}/{scenario}/stderr.bin"),"exit":format!("{output}/{scenario}/exit.json"),"native_exit":1,"error":null,"preparation_probe":null}));
    case.mutate(&observation, |raw| {
        raw["native_exit"] = json!(import_status)
    });
    if matches!(scenario, "ld-injection" | "loader-config") {
        case.mutate(&observation, |raw| raw["selected_member"] = Value::Null);
    }
    let mut evidence = LinuxImageImportEvidence {
        format: "memcordon.consumer-readiness.linux-image-import".into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: case.record.run_id.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        owner: owner_path.into(),
        original_lease_owner: "installed/lease-owner.json".into(),
        observation,
        definition: definition_path,
        cleanup_definition: cleanup_path,
        import_intent: intent_path,
        invocation,
        native_process,
        native_creation,
        stdout,
        stderr,
        exit,
        source_inventory: inventory_path,
        baseline_entrypoint: baseline_path,
        neighbor_definition,
        neighbor_stdout,
        neighbor_invocation,
        neighbor_native_process,
        neighbor_native_creation,
        neighbor_stderr,
        neighbor_exit,
        source_members,
        retirement,
        retirement_exit,
        retirement_stderr,
        preparation: None,
    };
    if loader {
        evidence.preparation = Some(loader_preparation(
            &mut case,
            &owner,
            &definition,
            &evidence,
        ));
    }
    case.json(
        "case-evidence.json",
        &serde_json::to_value(evidence).unwrap(),
    );
    case
}

fn loader_preparation(
    case: &mut persisted_case::PersistedCase,
    owner: &Value,
    definition: &Value,
    evidence: &memcordon_readiness_verifier::LinuxImageImportEvidence,
) -> memcordon_readiness_verifier::LinuxImagePreparationEvidence {
    use memcordon_core::workload_registry_v3::{
        ExclusiveIdentityDefinitionV3, IMAGE_TOTAL_BYTES, RootLayoutDefinitionV1, profile_reference,
    };
    use memcordon_readiness_verifier::*;
    let scenario = &evidence.key.scenario;
    let prefix = format!("installed/mixed-cases/image-cases/{scenario}/preparation-probe");
    let directory = format!(
        "{}/{scenario}/preparation-probe",
        owner["output"].as_str().unwrap()
    );
    let path = |leaf: &str| format!("{prefix}/{leaf}");
    let runtime = linux_image_reference(definition, &evidence.key.target).unwrap();
    let mut input = linux_installed_case::read(case, &evidence.neighbor_definition);
    input["image_id"] = json!("original-input-image");
    let input_ref = linux_image_reference(&input, &evidence.key.target).unwrap();
    case.mutate("installed/owned-resources-acquired.json", |raw| {
        raw["images"]["input"] = input.clone()
    });
    let declaration = json!({"format":"memcordon.owned-readiness-exclusive-use-declaration","revision":1,"run_id":evidence.run_id,"cell":owner["cell"],"account":owner["account"]["name"],"uid":61001,"gid":61001,"purpose":"exclusive installed readiness attempt identity; no unrelated login or workload"});
    let exclusive = json!({"id":"owned-exclusive-use","digest":hash(&serde_json::to_vec(&declaration).unwrap())});
    let identity = json!({"identity_id":"owned-readiness-identity","enabled":true,"uid":61001,"gid":61001,"supplementary_groups":[],"exclusive_use_policy":exclusive,"reservation_key":"owned-readiness-reservation"});
    let typed_identity: ExclusiveIdentityDefinitionV3 =
        serde_json::from_value(identity.clone()).unwrap();
    let execution = serde_json::to_value(typed_identity.reference().unwrap()).unwrap();
    let layout = json!({"format":"memcordon.root-layout","revision":1,"layout_id":"owned-readiness-root","runtime_image":runtime,"input_image":input_ref,"writable_roots":[{"id":"work","path":"work","byte_limit":IMAGE_TOTAL_BYTES,"generated_execution":true}],"output_files":[]});
    let typed_layout: RootLayoutDefinitionV1 = serde_json::from_value(layout.clone()).unwrap();
    let layout_ref = serde_json::to_value(typed_layout.reference().unwrap()).unwrap();
    // Preserve the producer's typed tuple order when measuring the original approved plan.
    let approved = serde_json::to_vec(&(
        typed_layout.runtime_image.clone(),
        typed_layout.input_image.clone(),
        typed_layout.reference().unwrap(),
        typed_identity.reference().unwrap(),
        Vec::<Value>::new(),
    ))
    .unwrap();
    let plan = hash(&approved);
    let profile = serde_json::to_value(profile_reference()).unwrap();
    let epoch = json!({"service_instance":vec![8u8;16],"revision":1});
    let contract = json!({"schema_version":3,"workload_plan_digest":plan,"authorized_profile":profile,"authorization":{"grant_id":"owned-readiness-grant","grant_revision":1,"approved_plan_digest":plan},"ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain","requirements":[],"execution_identity":execution,"runtime_image":runtime,"input_image":input_ref,"root_layout":layout_ref,"launch":{"entrypoint":"owned-readiness","working_directory":"work"},"expected_epoch":epoch});
    let legacy = linux_installed_case::read(case, "installed/lease-owner.json")["legacy"].clone();
    let policy = json!({"format":"memcordon.local-private-policy","revision":2,"legacy":legacy,"execution_identities":[identity],"images":[definition,input],"root_layouts":[layout],"grants":[{"id":"owned-readiness-grant","revision":1,"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":[plan],"profile":profile,"execution_identity":execution,"runtime_image":runtime,"input_image":input_ref,"root_layout":layout_ref}],"active_attempt_disposition":"drain-existing"});
    let activation = json!({"format":"memcordon.local-private-activation","revision":2,"registry":policy,"registry_digest":linux_registry_digest(&policy,&evidence.key.target).unwrap(),"epoch":epoch,"revoked_admissions":[]});
    let activation_path = path("mixed.activation.json");
    case.json(&activation_path, &activation);
    let policy_path = path("mixed.policy.json");
    case.json(&policy_path, &policy);
    let contract_path = path("mixed.contract.json");
    case.json(&contract_path, &contract);
    let typed_contract: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(contract.clone()).unwrap();
    typed_contract.validate().unwrap();
    let digest = typed_contract.digest().unwrap();
    fn item(bytes: &mut Vec<u8>, value: &[u8]) {
        bytes.extend((value.len() as u32).to_be_bytes());
        bytes.extend(value);
    }
    let mut native = Vec::new();
    native.extend(3u16.to_be_bytes());
    native.extend(0u64.to_be_bytes());
    item(&mut native, b"owned-readiness");
    native.extend(3u32.to_be_bytes());
    for arg in [
        b"bytes-argv-status".as_slice(),
        b"0",
        b"loader-closure-probe",
    ] {
        item(&mut native, arg);
    }
    native.extend(0u32.to_be_bytes());
    native.push(1);
    native.extend((512u64 * 1024 * 1024).to_be_bytes());
    native.extend([2, 0, 1, 1]);
    native.extend([9u8; 32]);
    native.extend(0u32.to_be_bytes());
    native.push(0);
    native.extend(digest.bytes());
    let request=serde_json::to_vec(&json!({"format":"memcordon.mixed-runtime-request","revision":2,"contract":contract,"native_launch":native,"attempt_deadline_millis":100})).unwrap();
    let attempt = "12".repeat(16);
    let provider_request = path(&format!("observations/{attempt}.provider-request.bin"));
    case.write(&provider_request, &request);
    let contract_native = format!("{directory}/mixed.contract.json");
    let result_native = format!("{directory}/result.json");
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
        contract_native.clone(),
        "--report-format".into(),
        "result-v2".into(),
        "--report".into(),
        result_native.clone(),
        "--mixed-observation-directory".into(),
        format!("{directory}/observations"),
        "--image-entrypoint".into(),
        "owned-readiness".into(),
        "--".into(),
        "bytes-argv-status".into(),
        "0".into(),
        "loader-closure-probe".into(),
    ];
    let command = json!({"format":"memcordon.linux-owned-frontend-invocation","revision":1,"program":b"/usr/bin/setpriv","arguments":values.iter().map(|value:&String|value.as_bytes()).collect::<Vec<_>>(),"environment_cleared":true,"caller_uid":65534,"caller_gid":65534,"selected_cli_sha256":sha256(b"original CLI image")});
    let public_argv = [
        "owned-readiness",
        "bytes-argv-status",
        "0",
        "loader-closure-probe",
    ]
    .map(|value| json!({"display":value,"raw":null}));
    let public = json!({"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+512M"},{"kind":"time","token":"+60000ms"}],"memory_token":"+512M","deadline_token":"+60000ms","argv":public_argv});
    let detail = if scenario == "loader-config" {
        "ELF loader configuration is outside the approved immutable library catalogue"
    } else {
        "ELF loader search directory is outside approved immutable search catalogue"
    };
    let result = json!({"format":"memcordon.result","revision":2,"tool":{"name":"memcordon","version":case.index.version,"os":"linux","architecture":"x86_64","runtime_features":["sealed-runtime","private-tcp"]},"invocation":public,"runtime":{"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,"outcome":{"kind":"rejected-before-authorization","request_sha256":digest,"request_bytes_sha256":hash(&request),"reason":"image-custody-mismatch","detail":detail,"allocation":{"authorization":"never-authorized","obligations":[]}}},"delivery":{"prepared-by":{"writer_pid":201}},"frontend":{"relay_drained":true,"interruption":null,"relay_error":null},"wrapper_status":125});
    let result_path = path("result.json");
    case.json(&result_path, &result);
    let stdout = path("stdout.bin");
    let stderr = path("stderr.bin");
    case.write(&stdout, b"");
    case.write(&stderr, b"");
    let wait = json!({"format":"memcordon.linux-policy-frontend-exit","revision":1,"process_id":201,"process_birth":222,"raw_wait_status":125*256,"native_exit":125,"signal":null,"invocation_sha256":hash(&serde_json::to_vec(&command).unwrap()),"stdout_sha256":hash(b""),"stderr_sha256":hash(b"")});
    let census_path = path("native-census.json");
    case.json(&census_path,&json!({"format":"memcordon.linux-policy-native-census","revision":1,"identity":owner["identity"],"cell":owner["cell"],"lease_id":"original-lease","scenario":scenario,"attempt_id":attempt,"provider":owner["provider"],"account":owner["account"],"result_sha256":hash(&serde_json::to_vec(&result).unwrap()),"request_sha256":hash(&request),"tasks":[{"pid":1,"tid":1,"birth":1,"uids":[0,0,0,0],"gids":[0,0,0,0],"groups":[]}],"cgroup_root":{"path":"/sys/fs/cgroup/memcordon-sealed","device":7,"inode":10,"uid":0,"mode":0o40700,"filesystem_type":0x63677270u64,"attempt_directories":[],"attempt_absence_errno":2},"journal_root":{"path":"/var/lib/memcordon/sealed","device":7,"inode":11,"uid":0,"mode":0o40700,"attempt_absence_errno":2}}));
    let receipt = path("preparation-probe.json");
    case.json(&receipt,&json!({"format":"memcordon.linux-image-loader-preparation-probe","revision":1,"identity":owner["identity"],"cell":owner["cell"],"lease_id":"original-lease","scenario":scenario,"activation":format!("{directory}/mixed.activation.json"),"contract":contract_native,"protected_contract":format!("{}/{scenario}/preparation-probe/mixed.contract.json",owner["image_admin_root"].as_str().unwrap()),"contract_sha256":hash(&serde_json::to_vec(&contract).unwrap()),"provider_request":format!("{directory}/observations/{attempt}.provider-request.bin"),"result":result_native,"native_census":format!("{directory}/native-census.json"),"frontend_invocation":command,"frontend_wait":wait,"raw_result":result}));
    case.mutate(&evidence.observation, |raw| {
        raw["preparation_probe"] = json!(format!("{directory}/preparation-probe.json"))
    });
    LinuxImagePreparationEvidence {
        receipt,
        activation: activation_path,
        policy: policy_path,
        contract: contract_path,
        provider_request,
        result: result_path,
        native_census: census_path,
        stdout,
        stderr,
    }
}

#[test]
fn persisted_import_rejections_require_original_acquisition_and_native_command_closure() {
    for scenario in [
        "first-image",
        "interpreter",
        "shared-library",
        "writable-alias",
        "ld-injection",
        "loader-config",
        "rpath-injection",
    ] {
        let mut case = persisted_import(scenario);
        case.validate().unwrap();
        let path = format!("installed/mixed-cases/image-cases/{scenario}/native-process.json");
        case.mutate(&path, |raw| raw["pidfd_revents"] = json!(0));
        assert!(
            case.validate().is_err(),
            "{scenario} accepted unretired original native owner"
        );
        let mut case = persisted_import(scenario);
        case.mutate("installed/lease-owner.json", |raw| {
            raw["work_deadline_unix_millis"] = json!(101)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} accepted substituted original acquisition cutoff"
        );
        let mut case = persisted_import(scenario);
        let path = format!("installed/mixed-cases/image-cases/{scenario}/native-creation.json");
        case.mutate(&path, |raw| {
            raw["kernel_image"]["sha256"] = json!("f".repeat(64))
        });
        let creation_sha = hash(&std::fs::read(case.root.path().join(&path)).unwrap());
        case.mutate(
            &format!("installed/mixed-cases/image-cases/{scenario}/native-process.json"),
            |raw| raw["creation_sha256"] = json!(creation_sha),
        );
        assert!(
            case.validate().is_err(),
            "{scenario} accepted substituted original kernel executable"
        );
        let mut case = persisted_import(scenario);
        case.mutate("installed/owned-resources-acquired.json", |raw| {
            raw["inode"] = json!(999)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} accepted substituted original administrative inode"
        );
    }
}

#[test]
fn original_registry_factory_preserves_frozen_empty_and_pathname_plan_codecs() {
    for requirements in [
        json!([]),
        json!([{"kind":"unix_path_stream","id":"pathname","writable_root":"work"}]),
    ] {
        let mut case = linux_installed_case::installed("L-IMG-04", "export-socket");
        let (mut runtime, _, _, _) = vector("first-image");
        runtime["image_id"] = json!("original-runtime-image");
        let mut input = runtime.clone();
        input["image_id"] = json!("original-input-image");
        let (contract, policy, activation) = linux_installed_case::activation(
            &mut case,
            runtime,
            input,
            vec!["work/exported.bin".into()],
            requirements,
        );
        let typed: memcordon_core::workload_contract_v3::WorkloadContractV3 =
            serde_json::from_value(contract.clone()).unwrap();
        typed.validate().unwrap();
        assert_eq!(
            activation["registry_digest"],
            memcordon_readiness_verifier::linux_registry_digest(&policy, &case.record.key.target)
                .unwrap()
        );
        assert_eq!(
            contract["authorization"]["approved_plan_digest"],
            contract["workload_plan_digest"]
        );
        if !contract["requirements"].as_array().unwrap().is_empty() {
            let mut hostile = contract;
            hostile["requirements"][0]["kind"] = json!("unix-path-stream");
            assert!(
                serde_json::from_value::<memcordon_core::workload_contract_v3::WorkloadContractV3>(
                    hostile
                )
                .is_err()
            );
        }
    }
}

#[test]
fn seven_image_mutations_require_actual_selected_bytes_and_closure() {
    for scenario in [
        "first-image",
        "interpreter",
        "shared-library",
        "writable-alias",
        "ld-injection",
        "loader-config",
        "rpath-injection",
    ] {
        let (definition, inventory, first, captures) = vector(scenario);
        validate_linux_image_mutation(
            scenario,
            "x86_64-unknown-linux-gnu",
            &definition,
            &inventory,
            &first,
            &captures,
        )
        .unwrap();
        let mut extra = definition.clone();
        extra["image_id"] = "unrelated-authority".into();
        assert!(
            validate_linux_image_mutation(
                scenario,
                "x86_64-unknown-linux-gnu",
                &extra,
                &inventory,
                &first,
                &captures
            )
            .is_err(),
            "{scenario} extra authority"
        );
        let mut missing = inventory.clone();
        missing["members"].as_array_mut().unwrap().pop();
        assert!(
            validate_linux_image_mutation(
                scenario,
                "x86_64-unknown-linux-gnu",
                &definition,
                &missing,
                &first,
                &captures
            )
            .is_err(),
            "{scenario} missing source member"
        );
        let mut first_mutant = first.clone();
        first_mutant[18] ^= 1;
        assert!(
            validate_linux_image_mutation(
                scenario,
                "x86_64-unknown-linux-gnu",
                &definition,
                &inventory,
                &first_mutant,
                &captures
            )
            .is_err(),
            "{scenario} different real first image"
        );
    }
}
