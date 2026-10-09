use crate::{
    linux_ingress_case as ingress, linux_installed_case as installed, persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::{
    LinuxIsolationImportEvidence, LinuxMalformedIngressEvidence, linux_image_reference, sha256,
};
use serde_json::{Value, json};

fn command_graph(
    case: &mut PersistedCase,
    prefix: &str,
    command: Value,
    pid: u32,
    birth: u64,
    status: i32,
    stdout: Value,
) {
    let path = |leaf: &str| {
        std::path::Path::new(prefix)
            .join(leaf)
            .to_str()
            .unwrap()
            .to_owned()
    };
    case.json(&path("invocation.json"), &command);
    case.json(&path("stdout.json"), &stdout);
    case.write(&path("stderr.bin"), b"");
    case.json(
        &path("exit.json"),
        &json!({"native_exit":status,"success":status==0}),
    );
    let creation = json!({"format":"memcordon.linux-image-import-creation","revision":1,"process_id":pid,"birth":birth,"pidfd_device":7,"pidfd_inode":u64::from(pid)+1000,"invocation_sha256":sha256(&std::fs::read(case.root.path().join(path("invocation.json"))).unwrap()),"kernel_image":{"device":7,"inode":300,"length":b"original agent image".len(),"sha256":sha256(b"original agent image")}});
    case.json(&path("native-creation.json"), &creation);
    case.json(&path("native-process.json"),&json!({"format":"memcordon.linux-image-import-process","revision":1,"process_id":pid,"birth":birth,"raw_wait_status":status*256,"native_exit":status,"signal":null,"invocation_sha256":creation["invocation_sha256"],"stdout_sha256":sha256(&std::fs::read(case.root.path().join(path("stdout.json"))).unwrap()),"stderr_sha256":sha256(b""),"executable_device":7,"executable_inode":300,"creation_sha256":sha256(&std::fs::read(case.root.path().join(path("native-creation.json"))).unwrap()),"pidfd_device":7,"pidfd_inode":u64::from(pid)+1000,"pidfd_revents":1}));
}

pub fn baseline(scenario: &str) -> PersistedCase {
    let mut case = ingress::baseline();
    let original: LinuxMalformedIngressEvidence =
        serde_json::from_value(installed::read(&case, "case-evidence.json")).unwrap();
    case.record.key.family = "L-ISO-02".into();
    case.record.key.scenario = scenario.into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let lease = installed::read(&case, &original.original_lease);
    let mut owner = installed::read(&case, &original.owner);
    let mut acquired = installed::read(&case, &original.acquisition);
    let files: [(&str, &[u8]); 5] = [
        (
            "Cargo.toml",
            include_bytes!("../../../../tests/fixtures/linux_readiness/Cargo.toml"),
        ),
        (
            "Cargo.lock",
            include_bytes!("../../../../tests/fixtures/linux_readiness/Cargo.lock"),
        ),
        (
            "rust-toolchain.toml",
            include_bytes!("../../../../tests/fixtures/linux_readiness/rust-toolchain.toml"),
        ),
        (
            "src/main.rs",
            include_bytes!("../../../../tests/fixtures/linux_readiness/src/main.rs"),
        ),
        (
            "tests/generated_child.rs",
            include_bytes!("../../../../tests/fixtures/linux_readiness/tests/generated_child.rs"),
        ),
    ];
    let entries=files.iter().map(|(path,bytes)|json!({"kind":"regular","path":std::path::Path::new("owned-source").join(path),"sha256":sha256(bytes),"size":bytes.len(),"executable":false})).collect::<Vec<_>>();
    let input = json!({"format":"memcordon.runtime-image","revision":1,"image_id":"input","target":case.record.key.target,"entries":entries,"entrypoints":[],"library_directories":[],"startup_environment":[]});
    let (contract, registry, activation) = installed::activation(
        &mut case,
        acquired["images"]["runtime"].clone(),
        input.clone(),
        vec![],
        json!([]),
    );
    acquired["images"]["input"] = input.clone();
    case.json(&original.acquisition, &acquired);
    owner["baseline_registry"] = registry;
    owner["baseline_epoch"] = activation["epoch"].clone();
    case.json(&original.owner, &owner);
    case.json(&original.activation, &activation);
    case.json("import-contract.json", &contract);
    let directory = case.root.path().join("installed/mixed-cases/import-recipe");
    let source_path = directory.join("isolation-input-source");
    let definition_path = std::path::Path::new(lease["admin_root"].as_str().unwrap())
        .join("isolation-input-recipe")
        .join("definition.json");
    let mut definition = input;
    definition["image_id"] = json!(format!("isolation-{scenario}-recipe"));
    case.json("import-definition.json", &definition);
    let definition_hash =
        sha256(&std::fs::read(case.root.path().join("import-definition.json")).unwrap());
    let intent = json!({"format":"memcordon.linux-isolation-import-intent","revision":1,"identity":lease["identity"],"cell":lease["cell"],"lease_id":"original-lease","scenario":scenario,"definition":definition_path,"definition_sha256":definition_hash,"reference":linux_image_reference(&definition,&case.record.key.target).unwrap(),"source_root":source_path,"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    case.json("import-intent.json", &intent);
    let writable = scenario == "caller-writable-tree";
    let extra = scenario == "input-socket";
    let socket_path = if extra {
        "owned-source/input-socket"
    } else {
        "owned-source/Cargo.toml"
    };
    let mutation = if writable {
        json!({"kind":scenario,"caller_uid":65534,"caller_gid":65534})
    } else {
        json!({"kind":scenario,"path":socket_path,"device":7,"inode":401,"uid":0,"gid":0,"mode":0o140755,"nlink":1,"baseline_sha256":if extra{Value::Null}else{json!(sha256(files[0].1))},"listener":{"device":9,"inode":402,"mode":0o140777}})
    };
    let source = json!({"format":"memcordon.linux-isolation-import-source","revision":1,"scenario":scenario,"path":source_path,"device":7,"inode":400,"uid":if writable{65534}else{0},"gid":if writable{65534}else{0},"mode":if writable{0o040755}else{0o040700},"mutation":mutation,"parent":{"path":directory,"device":7,"inode":399,"uid":0,"mode":0o040711}});
    case.json("import-source.json", &source);
    let members=entries.iter().enumerate().map(|(ordinal,entry)|json!({"path":entry["path"],"device":7,"inode":500+ordinal,"uid":0,"gid":0,"mode":0o100444,"nlink":1,"length":entry["size"],"sha256":entry["sha256"]})).collect::<Vec<_>>();
    let before = json!({"format":"memcordon.linux-isolation-import-inventory","revision":1,"source_root":source_path,"root":{"device":7,"inode":400,"uid":0,"gid":0,"mode":0o040700},"members":members});
    case.json("import-original-inventory.json", &before);
    let mut after = before;
    for field in ["device", "inode", "uid", "gid", "mode"] {
        after["root"][field] = source[field].clone();
    }
    if !writable {
        let socket = json!({"path":socket_path,"device":7,"inode":401,"uid":0,"gid":0,"mode":0o140755,"nlink":1,"length":0,"sha256":null});
        if extra {
            after["members"].as_array_mut().unwrap().push(socket);
        } else {
            after["members"][0] = socket;
            case.write("import-replaced-original.bin", files[0].1);
        }
    }
    case.json("import-inventory.json", &after);
    case.json("import-source-retired.json",&json!({"format":"memcordon.linux-isolation-import-source-retired","revision":1,"original":source,"held_nlink":0,"native_errno":2,"caller_write_revoked_before_cleanup":writable}));
    case.json("import-source-closed.json",&json!({"format":"memcordon.linux-isolation-import-source-closed","revision":1,"original":source,"parent":{"device":7,"inode":399,"uid":0,"mode":0o040711},"root_closed":true,"parent_closed":true,"socket_parent_closed":!writable,"listener_closed":!writable,"native_file_closes":24+usize::from(extra)-usize::from(scenario=="imported-socket"),"native_errno":null}));
    let command = json!({"format":"memcordon.linux-image-import-command","revision":1,"identity":lease["identity"],"cell":lease["cell"],"lease_id":"original-lease","scenario":scenario,"program":"/usr/libexec/memcordon-sealed-agent","executable_sha256":sha256(b"original agent image"),"argv":["package","policy","image","install","--definition",intent["definition"],"--source-root",source_path,"--json"],"cwd":directory,"environment_cleared":true,"definition_sha256":definition_hash,"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    command_graph(
        &mut case,
        "import",
        command.clone(),
        800,
        900,
        1,
        json!({"error":"original native hostile source refused"}),
    );
    let mut retirement = command;
    retirement["format"] = json!("memcordon.linux-isolation-image-retirement-command");
    retirement["argv"] = json!([
        "package",
        "policy",
        "image",
        "retire",
        "--definition",
        intent["definition"],
        "--json"
    ]);
    retirement["cwd"] = json!(directory.join("definition-retirement"));
    command_graph(
        &mut case,
        "import-retirement",
        retirement,
        801,
        901,
        0,
        json!({"format":"memcordon.runtime-image-retirement","revision":1,"reference":intent["reference"],"storage_absent":true,"already_absent":true}),
    );
    case.write("import-challenge.bin", &[7; 32]);
    let mut census = installed::read(&case, &original.census);
    census["scenario"] = json!(scenario);
    census["request_sha256"] = json!(definition_hash);
    census["result_sha256"] = json!(sha256(
        &std::fs::read(case.root.path().join("import/stdout.json")).unwrap()
    ));
    case.json("import-census.json",&json!({"format":"memcordon.linux-isolation-import-census","revision":1,"original_probe_nonce":hex::encode([7;16]),"definition_sha256":definition_hash,"stdout_sha256":census["result_sha256"],"native_census":census}));
    let evidence = LinuxIsolationImportEvidence {
        format: "memcordon.consumer-readiness.linux-isolation-import-refusal".into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: case.record.run_id.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        owner: original.owner,
        original_lease: original.original_lease,
        acquisition: original.acquisition,
        activation: original.activation,
        contract: "import-contract.json".into(),
        definition: "import-definition.json".into(),
        intent: "import-intent.json".into(),
        source: "import-source.json".into(),
        original_inventory: "import-original-inventory.json".into(),
        inventory: "import-inventory.json".into(),
        source_retirement: "import-source-retired.json".into(),
        source_closure: "import-source-closed.json".into(),
        invocation: "import/invocation.json".into(),
        native_creation: "import/native-creation.json".into(),
        native_process: "import/native-process.json".into(),
        exit: "import/exit.json".into(),
        stdout: "import/stdout.json".into(),
        stderr: "import/stderr.bin".into(),
        account_intent: original.account_intent,
        account_readback: original.account_readback,
        group_readback: original.group_readback,
        census: "import-census.json".into(),
        challenge: "import-challenge.bin".into(),
        definition_retirement: "import-retirement/invocation.json".into(),
        retirement_creation: "import-retirement/native-creation.json".into(),
        retirement_process: "import-retirement/native-process.json".into(),
        retirement_exit: "import-retirement/exit.json".into(),
        retirement_stdout: "import-retirement/stdout.json".into(),
        retirement_stderr: "import-retirement/stderr.bin".into(),
        replaced_original: (scenario == "imported-socket")
            .then(|| "import-replaced-original.bin".into()),
    };
    case.json("case-evidence.json", &json!(evidence));
    case
}
