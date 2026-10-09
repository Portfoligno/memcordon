//! Persisted original-wire decoder records; no native execution claim.
use super::{linux_installed_case as installed, persisted_case::PersistedCase};
use memcordon_readiness_verifier::*;
use serde::Serialize;
use serde_json::{Value, json};

pub fn baseline() -> PersistedCase {
    let mut case = installed::installed("L-ID-01", "v3-preserve-caller");
    let cell = case.index.products[0].key.clone();
    let root = case.root.path().display().to_string();
    let lease = installed::read(&case, "installed/lease-owner.json");
    let identity = lease["identity"].clone();
    #[derive(Serialize)]
    struct Identity<'a> {
        run_id: &'a str,
        source_commit: &'a str,
        source_tree_sha256: &'a str,
        version: &'a str,
    }
    let discriminator = hex::decode(sha256(
        &serde_json::to_vec(&(
            Identity {
                run_id: &case.record.run_id,
                source_commit: &case.index.source_commit,
                source_tree_sha256: &case.index.source_tree_sha256,
                version: &case.index.version,
            },
            &cell,
        ))
        .unwrap(),
    ))
    .unwrap();
    let name = format!(
        "mc-ready-{:x}",
        u64::from_le_bytes(discriminator[..8].try_into().unwrap())
    );
    let account = json!({"name":name,"uid":61001,"gid":61001,"intent":format!("{root}/installed/mixed-cases/exclusive-account-intent.json"),"native_readback":format!("{root}/installed/mixed-cases/exclusive-account-getent.bin"),"group_readback":format!("{root}/installed/mixed-cases/exclusive-group-getent.bin")});
    case.mutate("installed/mixed-cases/image-cases/owner.json", |owner| {
        owner["account"] = account.clone()
    });
    case.mutate("installed/owned-resources-acquired.json", |acquired| {
        acquired["account"] = account.clone()
    });
    let fixture = b"original fixture";
    let target = case.record.key.target.clone();
    let image = |id: &str, path: &str| json!({"format":"memcordon.runtime-image","revision":1,"image_id":id,"target":target,"entries":[{"kind":"regular","path":path,"sha256":sha256(fixture),"size":fixture.len(),"executable":true}],"entrypoints":[{"id":"owned-readiness","path":path}],"library_directories":[],"startup_environment":[]});
    let requirements = json!([{"kind":"tcp_listener","id":"tcp","local_port":{"kind":"kernel_assigned"},"peer":{"kind":"dynamic_loopback_within_this_attempt"}}]);
    let (contract, registry, activation) = installed::activation(
        &mut case,
        image("runtime", "bin/owned-readiness"),
        image("input", "inputs/owned-readiness"),
        vec![],
        requirements,
    );
    let acquired = installed::read(&case, "installed/owned-resources-acquired.json");
    case.json(
        "installed/mixed-cases/owned-resources-acquired.json",
        &acquired,
    );
    let old = installed::read(&case, "installed/mixed-cases/image-cases/owner.json");
    let provider = old["provider"].clone();
    let scope = "installed/mixed-cases/policy-cases/v3-preserve-caller";
    let path = |leaf: &str| format!("{scope}/{leaf}");
    let cwd = format!("{root}/{scope}");
    let owner = json!({"format":"memcordon.linux-policy-case-owner","revision":1,"run_id":case.record.run_id,"source_commit":case.index.source_commit,"source_tree_sha256":case.index.source_tree_sha256,"cell":cell,"lease_id":"original-lease","provider":provider,"baseline_registry":registry,"baseline_epoch":activation["epoch"],"admin_root":lease["admin_root"],"admin_root_device":lease["device"],"admin_root_inode":lease["inode"],"privileged_policy_root":"/var/lib/memcordon-consumer-readiness/policies"});
    case.json(&path("owner.json"), &owner);
    case.json(&path("activation.json"), &activation);
    // The rejected identity is the only mutation to the retained original envelope.
    fn put(out: &mut Vec<u8>, value: &[u8]) {
        out.extend((value.len() as u32).to_be_bytes());
        out.extend(value);
    }
    let mut launch = 3u16.to_be_bytes().to_vec();
    launch.extend(0u64.to_be_bytes());
    put(&mut launch, b"owned-readiness");
    let argv = [
        b"tcp-http".as_slice(),
        b"0707070707070707070707070707070707070707070707070707070707070707",
    ];
    launch.extend((argv.len() as u32).to_be_bytes());
    for arg in argv {
        put(&mut launch, arg);
    }
    launch.extend(0u32.to_be_bytes());
    launch.push(1);
    launch.extend((256u64 * 1024 * 1024).to_be_bytes());
    launch.push(1);
    launch.extend(0u64.to_be_bytes());
    launch.extend([0, 1, 2]);
    for n in [10u64, 100, 100, 100] {
        launch.extend(n.to_be_bytes());
    }
    launch.extend(5u32.to_be_bytes());
    launch.extend([1, 2, 3, 4, 5, 0]);
    let original = json!({"format":"memcordon.mixed-runtime-request","revision":2,"contract":contract,"native_launch":launch,"attempt_deadline_millis":300000});
    let mut malformed = original.clone();
    malformed["contract"]["execution_identity"] = json!({"kind":"preserve-caller"});
    let original_source="installed/mixed-cases/policy-cases/restart-fresh-admission/frontend/observations/07070707070707070707070707070707.provider-request.bin".to_owned();
    let original_frontend="installed/mixed-cases/policy-cases/restart-fresh-admission/frontend/frontend-invocation.json".to_owned();
    let original_directory =
        format!("{root}/installed/mixed-cases/policy-cases/restart-fresh-admission/frontend");
    let command = json!({"format":"memcordon.linux-owned-frontend-invocation","revision":1,"program":b"/usr/bin/setpriv","arguments":[b"--reuid".as_slice(),b"65534",b"--regid",b"65534",b"--clear-groups",b"--",b"/usr/libexec/memcordon",b"+256M",b"+300000ms",b"--sealed",b"--workload-contract",format!("{original_directory}/request.json").as_bytes(),b"--report-format",b"result-v2",b"--report",format!("{original_directory}/result.json").as_bytes(),b"--mixed-observation-directory",format!("{original_directory}/observations").as_bytes(),b"--image-entrypoint",b"owned-readiness",b"--",b"tcp-http",argv[1]],"environment_cleared":true,"caller_uid":65534,"caller_gid":65534,"selected_cli_sha256":sha256(b"original CLI image")});
    case.json(&original_frontend, &command);
    case.json(&original_source, &original);
    case.json(&path("original-request.bin"), &original);
    case.json(&path("malformed-provider-request.bin"), &malformed);
    let malformed_bytes = serde_json::to_vec(&malformed).unwrap();
    let response=serde_json::to_vec(&json!({"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,"outcome":{"kind":"rejected-ingress","request_bytes_sha256":sha256(&malformed_bytes),"reason":"malformed-ingress","detail":"preserve-caller is invalid in V3","allocation":{"authorization":"never-authorized","obligations":[]}}})).unwrap();
    let nonce = vec![9u8; 16];
    let attempt = vec![7u8; 16];
    let frame = |kind: u16, payload: &[u8]| {
        let mut raw = 4u16.to_be_bytes().to_vec();
        raw.extend(kind.to_be_bytes());
        raw.extend(((72 + payload.len()) as u32).to_be_bytes());
        raw.extend(&nonce);
        raw.extend(&attempt);
        raw.extend(hex::decode(sha256(payload)).unwrap());
        raw.extend(payload);
        raw
    };
    let mut fields = vec!["S".to_owned(); 20];
    fields[19] = "60".into();
    let stat = format!("50 (original peer) {}", fields.join(" "));
    let helper = b"original retained helper";
    case.write(&path("helper.bin"), helper);
    let transport = json!({"response":response,"provider":provider,"nonce":nonce,"attempt":attempt,"request_frame":frame(14,&malformed_bytes),"response_frame":frame(115,&response),"peer_pid":50,"peer_uid":0,"peer_gid":0,"peer_stat":stat.as_bytes(),"peer_pidfd_device":7,"peer_pidfd_inode":8,"peer_pidfd_before_revents":0,"peer_pidfd_after_revents":0});
    let receipt = json!({"format":"memcordon.linux-malformed-ingress-observation","revision":2,"caller_pid":70,"caller_uid":65534,"caller_gid":65534,"caller_birth":80,"native_image":{"device":7,"inode":9,"length":helper.len(),"sha256":sha256(helper)},"provider":provider,"wire_nonce":nonce,"attempt":attempt,"request":malformed_bytes,"response":response,"transport":transport});
    case.json(&path("receipt.json"), &receipt);
    let helper_path = "/usr/libexec/memcordon-readiness-helper";
    let arguments = [
        b"--reuid".as_slice(),
        b"65534",
        b"--regid",
        b"65534",
        b"--clear-groups",
        b"--",
        helper_path.as_bytes(),
        b"consumer-readiness-malformed-ingress",
        b"--request",
        format!("{cwd}/malformed-provider-request.bin").as_bytes(),
        b"--output",
        format!("{cwd}/caller-observation/native-ingress.json").as_bytes(),
    ]
    .into_iter()
    .map(|value| value.to_vec())
    .collect::<Vec<_>>();
    let invocation = json!({"format":"memcordon.linux-malformed-ingress-invocation","revision":2,"program":b"/usr/bin/setpriv","arguments":arguments,"environment_cleared":true,"helper":helper_path,"helper_sha256":sha256(helper),"caller_uid":65534,"caller_gid":65534,"cwd":cwd.as_bytes(),"budget_millis":60,"started_unix_millis":1,"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    case.json(&path("invocation.json"), &invocation);
    case.write(&path("stdout.bin"), b"");
    case.write(&path("stderr.bin"), b"");
    let held = |retired: bool| json!({"pid":70,"birth":80,"parent_pid":null,"parent_birth":null,"retirement_observed":retired});
    case.json(&path("exit.json"),&json!({"format":"memcordon.linux-malformed-ingress-exit","revision":1,"creation":held(false),"retirement":held(true),"raw_wait_status":0,"native_exit":0,"signal":null,"invocation_sha256":sha256(&serde_json::to_vec(&invocation).unwrap()),"stdout_sha256":sha256(b""),"stderr_sha256":sha256(b"")}));
    case.json("installed/mixed-cases/exclusive-account-intent.json",&json!({"format":"memcordon.owned-readiness-account-intent","revision":1,"run_id":case.record.run_id,"cell":cell,"account_name":name,"native_absence_verified":true,"creation_attempted":true}));
    case.write(
        "installed/mixed-cases/exclusive-account-getent.bin",
        format!("{name}:x:61001:61001::/nonexistent:/usr/sbin/nologin\n").as_bytes(),
    );
    case.write(
        "installed/mixed-cases/exclusive-group-getent.bin",
        format!("{name}:x:61001:\n").as_bytes(),
    );
    let root_entry = |path: &str| json!({"path":path,"device":7,"inode":8,"uid":0,"mode":0o040700,"attempt_absence_errno":2});
    let mut cgroup = root_entry("/sys/fs/cgroup/memcordon-sealed");
    cgroup["filesystem_type"] = json!(0x63677270u64);
    cgroup["attempt_directories"] = json!([]);
    case.json(&path("census.json"),&json!({"format":"memcordon.linux-policy-native-census","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","scenario":"v3-preserve-caller","attempt_id":hex::encode(&attempt),"provider":provider,"account":account,"result_sha256":sha256(&serde_json::to_vec(&receipt).unwrap()),"request_sha256":sha256(&malformed_bytes),"tasks":[{"pid":1,"tid":1,"birth":1,"uids":[0,0,0,0],"gids":[0,0,0,0],"groups":[]}],"cgroup_root":cgroup,"journal_root":root_entry("/var/lib/memcordon/sealed")}));
    let evidence = LinuxMalformedIngressEvidence {
        format: "memcordon.consumer-readiness.linux-malformed-ingress".into(),
        revision: 1,
        key: case.record.key.clone(),
        run_id: case.record.run_id.clone(),
        source_commit: case.index.source_commit.clone(),
        source_tree_sha256: case.index.source_tree_sha256.clone(),
        lease_id: "original-lease".into(),
        owner: path("owner.json"),
        original_lease: "installed/lease-owner.json".into(),
        acquisition: "installed/mixed-cases/owned-resources-acquired.json".into(),
        activation: path("activation.json"),
        original_request: path("original-request.bin"),
        original_source_request: original_source,
        original_frontend,
        malformed_request: path("malformed-provider-request.bin"),
        helper_image: path("helper.bin"),
        invocation: path("invocation.json"),
        exit: path("exit.json"),
        receipt: path("receipt.json"),
        stdout: path("stdout.bin"),
        stderr: path("stderr.bin"),
        census: path("census.json"),
        account_intent: "installed/mixed-cases/exclusive-account-intent.json".into(),
        account_readback: "installed/mixed-cases/exclusive-account-getent.bin".into(),
        group_readback: "installed/mixed-cases/exclusive-group-getent.bin".into(),
    };
    case.json("case-evidence.json", &json!(evidence));
    case
}
