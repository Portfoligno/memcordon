//! Encoded decoder fixtures, never native execution or installation evidence.
use memcordon_readiness_verifier::sha256;
use serde_json::{Value, json};

pub struct PreparedGraph {
    pub request: Value,
    pub prepared: Value,
    pub native: Value,
    #[allow(
        dead_code,
        reason = "Worker custody is consumed by lifecycle and image targets, not every prepared graph consumer"
    )]
    pub worker: Value,
    pub journal: Value,
    #[allow(
        dead_code,
        reason = "Only lifecycle and export integration targets consume the retained journal bytes directly"
    )]
    pub journal_bytes: Vec<u8>,
}

pub fn durable_journal(record: &Value) -> Vec<u8> {
    let attempt = record["attempt_id"].as_str().unwrap();
    let body = format!(
        "format=memcordon.private-native-journal\nrevision=1\ncgroup={attempt}\npayload={record}\n"
    );
    format!("{body}digest={}\n", sha256(body.as_bytes())).into_bytes()
}

#[allow(
    dead_code,
    reason = "Held process identities are needed only by some prepared graph integration targets"
)]
pub fn held(pid: u32, birth: u64, retired: bool) -> Value {
    json!({"pid":pid,"birth":birth,"parent_pid":null,"parent_birth":null,"retirement_observed":retired})
}

/// Match the public Attempt codec: the original frontend carries the total
/// attempt duration separately, so the native absolute deadline is absent.
#[expect(
    clippy::too_many_arguments,
    reason = "Bind independent contract, activation, provider, run, argv, memory, deadline and executable evidence"
)]
pub fn prepared_graph(
    contract: &Value,
    activation: &Value,
    provider: &Value,
    run_id: &str,
    arguments: &[Vec<u8>],
    memory: u64,
    attempt_deadline: u64,
    agent: &[u8],
) -> PreparedGraph {
    let typed: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(contract.clone()).unwrap();
    let digest = sha256(&typed.canonical_bytes().unwrap());
    let put = |out: &mut Vec<u8>, value: &[u8]| {
        out.extend((value.len() as u32).to_be_bytes());
        out.extend(value);
    };
    let mut launch = 3u16.to_be_bytes().to_vec();
    launch.extend(0u64.to_be_bytes());
    put(&mut launch, b"owned-readiness");
    launch.extend((arguments.len() as u32).to_be_bytes());
    for argument in arguments {
        put(&mut launch, argument);
    }
    launch.extend(0u32.to_be_bytes());
    launch.push(1);
    launch.extend(memory.to_be_bytes());
    launch.push(1);
    launch.extend(0u64.to_be_bytes());
    launch.extend([0, 1, 2]);
    for interval in [10u64, 100, 100, 100] {
        launch.extend(interval.to_be_bytes());
    }
    launch.extend(5u32.to_be_bytes());
    launch.extend([1, 2, 3, 4, 5, 0]);
    let mut bound = launch.clone();
    bound.extend(hex::decode(&digest).unwrap());
    let request = json!({"format":"memcordon.mixed-runtime-request","revision":2,"contract":contract,"native_launch":launch,"attempt_deadline_millis":attempt_deadline});
    let attempt = "07070707070707070707070707070707";
    let process = |pid, birth| json!({"pid":pid,"birth":birth});
    let namespace = |inode| json!({"device":1,"inode":inode});
    let admission = json!({"format":"memcordon.private-admission-metadata","revision":2,"attempt_id":attempt,
        "request":contract,"request_sha256":digest,"invocation_sha256":sha256(&bound),"caller_uid":65534,
        "registry_digest":activation["registry_digest"],"epoch":activation["epoch"],"admission_nonce":vec![9u8;16],"profile_id":contract["authorized_profile"]});
    let prepared = json!({"format":"memcordon.mixed-prepared-observation","revision":2,"provider":provider,"admission":admission,
        "caller":process(102,301),"target":process(103,302),"namespace_init":process(104,303),"guardian":process(105,304),
        "user_namespace":namespace(100),"mount_namespace":namespace(101),"pid_namespace":namespace(102),
        "network_namespace":namespace(103),"ipc_namespace":namespace(104),"root_device":1,"root_inode":900,"authorizes_launch":false});
    let snapshot = |pid, birth, pids: Vec<u32>, fresh: bool| {
        let mut value = json!({"process_id":pid,"birth":birth,"namespace_pids":pids});
        for (field, inode) in [
            ("user", 100),
            ("mount", 101),
            ("pid", 102),
            ("network", 103),
            ("ipc", 104),
        ] {
            value[field] = namespace(if fresh || field == "user" {
                inode
            } else {
                inode + 1000
            });
        }
        value
    };
    let native = json!({"format":"memcordon.linux-prepared-native-observation","revision":1,"run_id":run_id,
        "attempt_id":attempt,"prepared_sha256":sha256(&serde_json::to_vec(&prepared).unwrap()),"observer":process(106,305),
        "held_before_authorization":true,"caller":snapshot(102,301,vec![102],false),
        "target":snapshot(103,302,vec![103,2],true),"namespace_init":snapshot(104,303,vec![104,1],true),
        "guardian":snapshot(105,304,vec![105],false),"root_device":1,"root_inode":900});
    let journal_process = |pid, birth| json!({"pid":pid,"start_time":birth});
    let journal = json!({"attempt_id":attempt,"boot_identity":"12345678-1234-1234-1234-123456789abc",
        "frontend":journal_process(102,301),"caller_envelope_digest":sha256(b"original caller envelope"),
        "admission_metadata":null,"phase":"checkpoint-committed","release_knowledge":"not-released","binding":null,
        "guardian":journal_process(105,304),"namespace_init":journal_process(104,303),"target":journal_process(103,302),
        "network_namespace_inode":103,"checkpoint":null,"checkpoint_digest":null,"gated_facts":null,"cleanup_error":null,
        "mixed_admission_metadata":admission,"mixed_worker":journal_process(101,300),
        "mixed_export_intent":null,"mixed_cgroup_identity":{"inode":400}});
    let journal_bytes = durable_journal(&journal);
    let worker = json!({"format":"memcordon.linux-prepared-worker-observation","revision":1,"attempt_id":attempt,
        "provider":provider,"admission":admission,"journal_path":format!("/var/lib/memcordon/sealed/{attempt}"),
        "journal_device":1,"journal_inode":401,"journal_sha256":sha256(&journal_bytes),"journal_bytes":journal_bytes,
        "worker":{"pid":101,"birth":300,"image_sha256":sha256(agent)},
        "native_image":{"device":1,"inode":402,"length":agent.len(),"sha256":sha256(agent)}});
    PreparedGraph {
        request,
        prepared,
        native,
        worker,
        journal,
        journal_bytes,
    }
}
