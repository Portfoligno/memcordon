use memcordon_readiness_verifier::original_fixture_recovery_contract as contract;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
const ACQUISITION_NAMES: [&str; 5] = [
    "recovery-cargo-status.json",
    "recovery-native-host.json",
    "recovery-native-compiler.bin",
    "recovery-compiler-identity.stdout",
    "recovery-compiler-identity.stderr",
];

#[derive(Clone)]
#[allow(
    dead_code,
    reason = "Only complete family integration targets rebind the shared measured proof"
)]
pub struct Family {
    pub identity: Value,
    pub cell: Value,
    pub scope: String,
    pub work: u64,
    pub cleanup: u64,
    pub admin: String,
    pub original_root: String,
    pub context: contract::Context,
    pub originals: BTreeMap<String, String>,
}

#[allow(
    dead_code,
    reason = "Only complete family integration targets rebind the shared measured proof"
)]
pub fn family(family: Family) -> (Value, Value, Value, BTreeMap<String, Vec<u8>>) {
    let (mut invocation, mut process, mut capture, mut records) = fixture();
    let mut owner: Value = serde_json::from_slice(&records["owner.json"]).unwrap();
    owner["identity"] = family.identity.clone();
    owner["cell"] = family.cell.clone();
    owner["scope_id"] = json!(family.scope);
    owner["work_deadline_unix_millis"] = json!(family.work);
    owner["cleanup_deadline_unix_millis"] = json!(family.cleanup);
    owner["owner_path"] = json!(format!("{}/recovery-harness-owner.json", family.admin));
    owner["compiler_output"] = json!(format!("{}/recovery-cargo-output.jsonl", family.admin));
    owner["compiler_errors"] = json!(format!("{}/recovery-cargo-stderr.bin", family.admin));
    for (index, name) in ACQUISITION_NAMES.iter().enumerate() {
        owner["acquisition_records"][index][0] = json!(format!("{}/{name}", family.admin));
    }
    owner["executable"] = json!(format!(
        "{}/recovery-harness/operational/native-test-harness",
        family.admin
    ));
    let mut host: Value = serde_json::from_slice(&records["acquisition-1.bin"]).unwrap();
    host["source"]["commit"] = family.identity["source_commit"].clone();
    host["source"]["version"] = family.identity["version"].clone();
    records.insert(
        "acquisition-1.bin".into(),
        serde_json::to_vec(&host).unwrap(),
    );
    owner["acquisition_records"][1][1] = json!(hash(&records["acquisition-1.bin"]));
    let owner_bytes = serde_json::to_vec(&owner).unwrap();
    records.insert("owner.json".into(), owner_bytes.clone());
    let stage = format!("{}/recovery-stage", family.admin);
    let mut origin_records = serde_json::Map::new();
    for (role, record) in family.context.records() {
        origin_records.insert(role.into(), json!({"original_path":family.originals[role],"staged_path":record.path,"length":record.length,"sha256":record.sha256,"native_identity":[1,2,record.length,0,0o100600,1,10,0,10,0]}));
    }
    let origin = json!({"format":"memcordon.original-native-recovery-origin","revision":1,"original_artifact_root":family.original_root,"records":origin_records});
    let origin_bytes = serde_json::to_vec(&origin).unwrap();
    let input = contract::Input {
        format: "memcordon.original-native-recovery-input".into(),
        revision: 1,
        identity: serde_json::from_value(family.identity.clone()).unwrap(),
        native_target: family.cell["target"].as_str().unwrap().into(),
        scope_id: family.scope.clone(),
        artifact_root: stage.into(),
        original_artifact_root: family.original_root.into(),
        origin_sha256: hash(&origin_bytes),
        work_deadline_unix_millis: family.work,
        cleanup_deadline_unix_millis: family.cleanup,
        recovery_harness_owner_sha256: hash(&owner_bytes),
        context: family.context,
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let result = contract::RecoveryResult {
        format: "memcordon.original-native-recovery-result".into(),
        revision: 1,
        input_sha256: hash(&input_bytes),
        context: input.context.kind().into(),
        identity: input.identity.clone(),
        native_target: input.native_target.clone(),
        scope_id: input.scope_id.clone(),
        recovery_harness_owner_sha256: hash(&owner_bytes),
        original_records: input
            .context
            .records()
            .iter()
            .map(|(role, record)| ((*role).into(), record.sha256.clone()))
            .collect(),
        completed_unix_millis: family.work,
        within_original_cleanup: true,
        outstanding: vec![],
    };
    let mut proof = invocation
        .as_object_mut()
        .unwrap()
        .remove("original_fixture")
        .unwrap();
    invocation["identity"] = family.identity;
    invocation["scope_id"] = json!(input.scope_id);
    invocation["program"] = owner["executable"].clone();
    invocation["working_directory"] = json!(input.artifact_root);
    invocation["input_sha256"] = json!(hash(&input_bytes));
    invocation["harness_owner_sha256"] = json!(hash(&owner_bytes));
    invocation["work_deadline_unix_millis"] = json!(family.work);
    invocation["cleanup_deadline_unix_millis"] = json!(family.cleanup);
    let invocation_bytes = serde_json::to_vec(&invocation).unwrap();
    process["invocation_sha256"] = json!(hash(&invocation_bytes));
    capture["invocation_sha256"] = json!(hash(&invocation_bytes));
    capture["input_sha256"] = json!(hash(&input_bytes));
    proof["capture"] = capture.clone();
    proof["invocation_bytes"] = json!(invocation_bytes);
    proof["owner_bytes"] = json!(owner_bytes);
    proof["input_bytes"] = json!(input_bytes);
    proof["origin_bytes"] = json!(origin_bytes);
    proof["result_bytes"] = json!(serde_json::to_vec(&result).unwrap());
    proof["acquisition_projection"]["owner_sha256"] = json!(hash(&records["owner.json"]));
    for entry in proof["acquisition_projection"]["records"]
        .as_array_mut()
        .unwrap()
    {
        let leaf = entry["artifact"].as_str().unwrap().to_owned();
        entry["length"] = json!(records[&leaf].len());
        entry["sha256"] = json!(hash(&records[&leaf]));
        if leaf == "owner.json" {
            entry["original"] = owner["owner_path"].clone();
        } else if leaf == "cargo-output.jsonl" {
            entry["original"] = owner["compiler_output"].clone();
        } else if leaf == "cargo-stderr.bin" {
            entry["original"] = owner["compiler_errors"].clone();
        } else {
            let index: usize = leaf
                .strip_prefix("acquisition-")
                .unwrap()
                .strip_suffix(".bin")
                .unwrap()
                .parse()
                .unwrap();
            entry["original"] = owner["acquisition_records"][index][0].clone();
        }
    }
    invocation["original_fixture"] = proof;
    (invocation, process, capture, records)
}
pub fn fixture() -> (Value, Value, Value, BTreeMap<String, Vec<u8>>) {
    let compiler = b"actual retained compiler fixture bytes".to_vec();
    let identity = json!({"run_id":"42","source_commit":"a".repeat(40),"source_tree_sha256":"b".repeat(64),"version":"0.5.8-dev"});
    let status = serde_json::to_vec(&json!({"status":0,"package":"memcordon","test":"sealed_agent","target":"x86_64-unknown-linux-gnu","features":"private-tcp,test-support"})).unwrap();
    let host = serde_json::to_vec(&json!({"format":"memcordon.consumer-readiness.original-native-host","revision":1,
        "target":"x86_64-unknown-linux-gnu","source":{"kind":"working","commit":"a".repeat(40),"version":"0.5.8-dev"},"compiler_sha256":hash(&compiler)})).unwrap();
    let small = [
        status,
        host,
        compiler.clone(),
        b"rustc fixture identity".to_vec(),
        Vec::new(),
    ];
    let acquisitions: Vec<Value> = small
        .iter()
        .enumerate()
        .map(|(i, b)| {
            json!([
                format!("/var/lib/original/{}", ACQUISITION_NAMES[i]),
                hash(b),
                if i == 2 {
                    512 * 1024 * 1024u64
                } else {
                    1024 * 1024u64
                }
            ])
        })
        .collect();
    let owner = json!({"format":"memcordon.original-native-recovery-harness-owner","revision":1,"identity":identity,
        "cell":{"target":"x86_64-unknown-linux-gnu"},"scope_id":"original-lease","work_deadline_unix_millis":100,
        "cleanup_deadline_unix_millis":200,"owner_path":"/var/lib/original/recovery-harness-owner.json","executable":"/var/lib/original/recovery-harness/operational/native-test-harness",
        "sha256":hash(b"harness"),"device":7,"inode":8,"length":7,"mode":0o100555,
        "compiler_output":"/var/lib/original/recovery-cargo-output.jsonl","compiler_output_sha256":hash(b"cargo"),
        "compiler_errors":"/var/lib/original/recovery-cargo-stderr.bin","compiler_errors_sha256":hash(b""),"acquisition_records":acquisitions});
    let owner_bytes = serde_json::to_vec(&owner).unwrap();
    let record_hash = hash(b"original lease owner bytes");
    let origin = json!({"format":"memcordon.original-native-recovery-origin","revision":1,"original_artifact_root":"/var/lib/case",
        "records":{"lease_owner":{"original_path":"/var/lib/case/lease-owner.json","staged_path":"/var/lib/original/stage/input-lease_owner.bin",
        "length":26,"sha256":record_hash,"native_identity":[1,2,26,0,0o100600,1,10,0,10,0]}}});
    let origin_bytes = serde_json::to_vec(&origin).unwrap();
    let input = contract::Input {
        format: "memcordon.original-native-recovery-input".into(),
        revision: 1,
        identity: serde_json::from_value(identity.clone()).unwrap(),
        native_target: "x86_64-unknown-linux-gnu".into(),
        scope_id: "original-lease".into(),
        artifact_root: "/var/lib/original/stage".into(),
        original_artifact_root: "/var/lib/case".into(),
        origin_sha256: hash(&origin_bytes),
        work_deadline_unix_millis: 100,
        cleanup_deadline_unix_millis: 200,
        recovery_harness_owner_sha256: hash(&owner_bytes),
        context: contract::Context::InterruptedLease {
            lease_owner: contract::Record {
                path: "/var/lib/original/stage/input-lease_owner.bin".into(),
                length: 26,
                sha256: record_hash.clone(),
            },
            resources_acquired: None,
        },
    };
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let result = contract::RecoveryResult {
        format: "memcordon.original-native-recovery-result".into(),
        revision: 1,
        input_sha256: hash(&input_bytes),
        context: "InterruptedLease".into(),
        identity: input.identity.clone(),
        native_target: input.native_target.clone(),
        scope_id: input.scope_id.clone(),
        recovery_harness_owner_sha256: hash(&owner_bytes),
        original_records: vec![("lease_owner".into(), record_hash)],
        completed_unix_millis: 150,
        within_original_cleanup: true,
        outstanding: vec![],
    };
    let mut invocation = json!({"format":"memcordon.original-native-recovery-invocation","revision":1,"identity":identity,
        "native_target":input.native_target,"scope_id":input.scope_id,"program":owner["executable"],"arguments":["--exact",contract::TEST_NAME,"--ignored","--nocapture","--test-threads=1"],
        "working_directory":input.artifact_root,"input_sha256":hash(&input_bytes),"harness_owner_sha256":hash(&owner_bytes),"executable_sha256":owner["sha256"],
        "cleared_environment":true,"timeout_millis":300000,"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    let invocation_bytes = serde_json::to_vec(&invocation).unwrap();
    let process = json!({"format":"memcordon.original-native-recovery-process","revision":1,"invocation_sha256":hash(&invocation_bytes),
        "creation":{"identity":{"pid":123,"birth":456},"image":{"device":7,"inode":8,"sha256":owner["sha256"]}},
        "native_wait_status":0,"status":0,"retirement":{"pid":123,"birth":456,"retirement_observed":true},"pidfd_retirement_observed":true});
    let capture = json!({"format":"memcordon.original-native-recovery-capture","revision":1,"invocation_sha256":hash(&invocation_bytes),
        "input_sha256":hash(&input_bytes),"status":0,"native_wait_status":0,"stdout":[],"stderr":[],"stdout_sha256":hash(b""),"stderr_sha256":hash(b"")});
    let mut records = serde_json::Map::new();
    records.insert("owner.json".into(), json!(owner_bytes));
    records.insert("cargo-output.jsonl".into(), json!(b"cargo".to_vec()));
    records.insert("cargo-stderr.bin".into(), json!([]));
    let mut projections = vec![
        json!({"original":owner["owner_path"],"artifact":"owner.json","length":owner_bytes.len(),"sha256":hash(&owner_bytes)}),
        json!({"original":owner["compiler_output"],"artifact":"cargo-output.jsonl","length":5,"sha256":hash(b"cargo")}),
        json!({"original":owner["compiler_errors"],"artifact":"cargo-stderr.bin","length":0,"sha256":hash(b"")}),
    ];
    for (i, bytes) in small.iter().enumerate() {
        let leaf = format!("acquisition-{i}.bin");
        projections.push(json!({"original":owner["acquisition_records"][i][0],"artifact":leaf,"length":bytes.len(),"sha256":hash(bytes)}));
        records.insert(leaf, json!(bytes));
    }
    invocation["original_fixture"] = json!({"format":"memcordon.original-native-recovery-proof","revision":1,"capture":capture,
        "invocation_bytes":invocation_bytes,"input_bytes":input_bytes,"result_bytes":serde_json::to_vec(&result).unwrap(),"owner_bytes":owner_bytes,"origin_bytes":origin_bytes,
        "acquisition_projection":{"format":"memcordon.original-native-recovery-acquisition-projection","revision":1,"owner_sha256":hash(&owner_bytes),"records":projections}});
    (
        invocation,
        process,
        capture,
        serde_json::from_value(Value::Object(records)).unwrap(),
    )
}
