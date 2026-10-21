use crate::{
    linux_import_case::{baseline, command_graph},
    linux_installed_case as installed,
    persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::sha256;
use serde_json::json;

/// Persisted decoder graph, not a native installation or custody claim.
pub fn excluded() -> PersistedCase {
    installed_projection("input-socket", "excluded")
}

pub fn projected() -> PersistedCase {
    installed_projection("caller-writable-tree", "projected")
}

fn installed_projection(scenario: &str, outcome: &str) -> PersistedCase {
    let mut case = baseline(scenario);
    let definition = installed::read(&case, "import-definition.json");
    let intent = installed::read(&case, "import-intent.json");
    let command = installed::read(&case, "import/invocation.json");
    let receipt = json!({"format":"memcordon.runtime-image-installation","revision":1,
        "image":intent["reference"],"target":case.record.key.target,"policy_activated":false,
        "member_count":definition["entries"].as_array().unwrap().len()});
    command_graph(&mut case, "import", command.clone(), 800, 900, 0, receipt);
    let mut probe = installed::read(&case, "import-census.json");
    let result_hash = sha256(&std::fs::read(case.root.path().join("import/stdout.json")).unwrap());
    probe["stdout_sha256"] = json!(result_hash);
    probe["native_census"]["result_sha256"] = json!(result_hash);
    case.json("import-census.json", &probe);
    let id = |inode: u64, mode: u32, length: u64| {
        json!({"device":7,"inode":inode,
        "uid":0,"gid":0,"mode":mode,"nlink":if mode & 0o170000 == 0o040000 {2}else{1},"length":length})
    };
    let mut objects = std::collections::BTreeMap::new();
    objects.insert(".memcordon-image.json".to_owned(), json!({"path":".memcordon-image.json",
        "identity":id(10000,0o100444,512),"object":{"kind":"regular","sha256":intent["definition_sha256"],"capability_absent":true}}));
    for (ordinal, entry) in definition["entries"].as_array().unwrap().iter().enumerate() {
        let path = entry["path"].as_str().unwrap();
        let components: Vec<_> = path.split('/').collect();
        for count in 1..components.len() {
            let parent = components[..count].join("/");
            if !objects.contains_key(&parent) {
                let inode = 11000 + objects.len() as u64;
                objects.insert(parent.clone(), json!({"path":parent,"identity":id(inode,0o040555,0),"object":{"kind":"directory"}}));
            }
        }
        objects.insert(path.into(),json!({"path":path,"identity":id(12000+ordinal as u64,0o100444,entry["size"].as_u64().unwrap()),
            "object":{"kind":"regular","sha256":entry["sha256"],"capability_absent":true}}));
    }
    let census = json!({"format":"memcordon.runtime-image-census","revision":1,
        "reference":intent["reference"],"target":case.record.key.target,
        "definition_sha256":intent["definition_sha256"],"cutoff_unix_millis":100,
        "store":id(9000,0o040700,0),"root":id(9001,0o040555,0),
        "members":objects.into_values().collect::<Vec<_>>()});
    let mut inspection = command;
    inspection["format"] = json!("memcordon.linux-isolation-image-inspection-command");
    inspection["cwd"] = json!(format!(
        "{}/installed-image-inspection",
        inspection["cwd"].as_str().unwrap()
    ));
    inspection["argv"] = json!([
        "package",
        "policy",
        "image",
        "inspect",
        "--definition",
        intent["definition"],
        "--cutoff-unix-millis",
        "100",
        "--json"
    ]);
    command_graph(
        &mut case,
        "exclusion-inspection",
        inspection,
        802,
        902,
        0,
        census,
    );
    let source = installed::read(&case, "import-source.json");
    let inventory = installed::read(&case, "import-inventory.json");
    case.json("exclusion-source-after.json",&json!({"format":"memcordon.linux-isolation-import-source-after","revision":1,"inventory":inventory,"listener":source["mutation"]["listener"]}));
    case.mutate("case-evidence.json", |e| {
        e["format"] = json!("memcordon.consumer-readiness.linux-isolation-import");
        e["revision"] = json!(2);
        e["outcome"] = json!({"outcome":outcome,"invocation":"exclusion-inspection/invocation.json",
            "native_creation":"exclusion-inspection/native-creation.json","native_process":"exclusion-inspection/native-process.json",
            "exit":"exclusion-inspection/exit.json","stdout":"exclusion-inspection/stdout.json",
            "stderr":"exclusion-inspection/stderr.bin","source_after":"exclusion-source-after.json"});
    });
    case
}
