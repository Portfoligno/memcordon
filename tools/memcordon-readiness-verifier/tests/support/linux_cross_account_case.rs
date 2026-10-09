//! Complete original secondary account custody for the central cross-attempt vector.
use super::persisted_case::PersistedCase;
use memcordon_readiness_verifier::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Identity<'a> {
    run_id: &'a str,
    source_commit: &'a str,
    source_tree_sha256: &'a str,
    version: &'a str,
}
pub fn populate(
    case: &mut PersistedCase,
    artifact_root: &str,
    prefix: &str,
    peer_birth: u64,
) -> Value {
    let identity = Identity {
        run_id: &case.record.run_id,
        source_commit: &case.index.source_commit,
        source_tree_sha256: &case.index.source_tree_sha256,
        version: &case.index.version,
    };
    let cell = ProductKey {
        target: case.record.key.target.clone(),
        channel: case.record.key.channel.clone().unwrap(),
    };
    let discriminator = Sha256::digest(
        serde_json::to_vec(&(&identity, &cell, "other-attempt-abstract-peer")).unwrap(),
    );
    let number = u64::from_le_bytes(discriminator[..8].try_into().unwrap());
    let name = format!("mc-ready-{number:x}");
    let identity = serde_json::to_value(identity).unwrap();
    let cell = serde_json::to_value(cell).unwrap();
    let directory = format!("{artifact_root}/{prefix}");
    let leaf = |name: &str| format!("{prefix}/{name}");
    let account = json!({"name":name,"uid":61002,"gid":61002,"intent":format!("{directory}/exclusive-account-intent.json"),"native_readback":format!("{directory}/exclusive-account-getent.bin"),"group_readback":format!("{directory}/exclusive-group-getent.bin")});
    let intent = json!({"format":"memcordon.owned-readiness-account-intent","revision":2,"run_id":case.record.run_id,"cell":cell,"account_name":name,"native_absence_verified":true,"creation_attempted":true,"purpose":"other-attempt-abstract-peer"});
    let intent_bytes = serde_json::to_vec(&intent).unwrap();
    case.write(&leaf("exclusive-account-intent.json"), &intent_bytes);
    case.write(
        &leaf("exclusive-account-getent.bin"),
        format!("{name}:x:61002:61002::/nonexistent:/usr/sbin/nologin\n").as_bytes(),
    );
    case.write(
        &leaf("exclusive-group-getent.bin"),
        format!("{name}:x:61002:\n").as_bytes(),
    );
    let image = b"original owned native useradd image";
    case.write(&leaf("exclusive-account-useradd-image.bin"), image);
    let invocation = json!({"format":"memcordon.owned-readiness-account-creation-invocation","revision":1,"identity":identity,"cell":cell,"purpose":"other-attempt-abstract-peer","program":"/usr/sbin/useradd","program_sha256":sha256(image),"arguments":["--system","--no-create-home","--shell","/usr/sbin/nologin","--user-group","--",name],"cwd":directory,"intent_sha256":sha256(&intent_bytes)});
    let bytes = serde_json::to_vec(&invocation).unwrap();
    case.write(&leaf("exclusive-account-useradd-invocation.json"), &bytes);
    let birth = peer_birth.checked_sub(1).unwrap();
    let kernel = json!({"device":1,"inode":880,"length":image.len(),"sha256":sha256(image)});
    case.json(&leaf("exclusive-account-useradd-creation.json"),&json!({"format":"memcordon.owned-readiness-account-creation","revision":1,"process_id":880,"birth":birth,"invocation_sha256":sha256(&bytes),"kernel_image":kernel}));
    case.write(&leaf("exclusive-account-useradd-stdout.bin"), b"");
    case.write(&leaf("exclusive-account-useradd-stderr.bin"), b"");
    case.json(&leaf("exclusive-account-useradd-exit.json"),&json!({"format":"memcordon.owned-readiness-account-creation-exit","revision":1,"held":{"pid":880,"birth":birth,"parent_pid":null,"parent_birth":null,"retirement_observed":true},"raw_wait_status":0,"native_exit":0,"signal":null,"invocation_sha256":sha256(&bytes),"stdout_sha256":sha256(b""),"stderr_sha256":sha256(b"")}));
    let retirement_parent = prefix.rsplit_once('/').unwrap().0;
    let cwd = format!("{artifact_root}/{retirement_parent}");
    let census_leaf = "account-task-census-1.json";
    let status = b"Tgid:\t106\nPid:\t106\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0\n";
    case.json(&format!("{retirement_parent}/{census_leaf}"),&json!({"format":"memcordon.linux-cross-account-task-census","revision":1,"uid":61002,"gid":61002,"tasks":[{"process_id":106,"task_id":106,"status":status.as_slice(),"credentials":[vec![0;4],vec![0;4],vec![0]]}]}));
    let passwd = format!("{name}:x:61002:61002::/nonexistent:/usr/sbin/nologin\n").into_bytes();
    let first = command(
        case,
        retirement_parent,
        &cwd,
        &identity,
        &cell,
        "/usr/bin/getent",
        &["passwd".into(), name.clone()],
        0,
        &passwd,
        0,
        peer_birth + 1000 + 1,
    );
    let removal = command(
        case,
        retirement_parent,
        &cwd,
        &identity,
        &cell,
        "/usr/sbin/userdel",
        &["--".into(), name.clone()],
        0,
        b"",
        1,
        peer_birth + 1000 + 2,
    );
    let second = command(
        case,
        retirement_parent,
        &cwd,
        &identity,
        &cell,
        "/usr/bin/getent",
        &["group".into(), name.clone()],
        2,
        b"",
        2,
        peer_birth + 1000 + 3,
    );
    let absence = [
        ("passwd", name.clone()),
        ("passwd", "61002".into()),
        ("group", name.clone()),
        ("group", "61002".into()),
    ]
    .into_iter()
    .enumerate()
    .map(|(ordinal, (database, key))| {
        command(
            case,
            retirement_parent,
            &cwd,
            &identity,
            &cell,
            "/usr/bin/getent",
            &[database.into(), key],
            2,
            b"",
            ordinal + 3,
            peer_birth + 1000 + 4 + ordinal as u64,
        )
    })
    .collect::<Vec<_>>();
    let retired_path = format!("{retirement_parent}/account-retired.json");
    case.json(&retired_path,&json!({"format":"memcordon.linux-cross-account-retired","revision":2,"account":account,"task_census":census_leaf,"identity_checks":[first,second],"removals":[removal],"absence_checks":absence}));
    json!({"peer_account":account,"peer_account_intent":leaf("exclusive-account-intent.json"),"peer_account_passwd":leaf("exclusive-account-getent.bin"),"peer_account_group":leaf("exclusive-group-getent.bin"),"peer_account_creation":leaf("exclusive-account-useradd-creation.json"),"peer_account_retirement":retired_path})
}

#[expect(
    clippy::too_many_arguments,
    reason = "Bind original account identity, cell, executable, argv, cwd, exit, output, ordinal and process birth independently"
)]
fn command(
    case: &mut PersistedCase,
    parent: &str,
    cwd: &str,
    identity: &Value,
    cell: &Value,
    program: &str,
    args: &[String],
    status: u64,
    stdout: &[u8],
    ordinal: usize,
    birth: u64,
) -> Value {
    let stem = format!("account-original-command-{ordinal}");
    let leaf = |suffix: &str| format!("{stem}.{suffix}");
    let path = |suffix: &str| format!("{parent}/{}", leaf(suffix));
    let image = format!("original native executable {program}").into_bytes();
    case.write(&path("image.bin"), &image);
    let invocation = json!({"format":"memcordon.linux-cross-account-command","revision":1,"identity":identity,"cell":cell,"program":program,"program_sha256":sha256(&image),"arguments":args,"cwd":cwd,"started_unix_millis":125,"budget_millis":25,"cleanup_deadline_unix_millis":200});
    let bytes = serde_json::to_vec(&invocation).unwrap();
    case.write(&path("invocation.json"), &bytes);
    let pid = 900 + ordinal as u32;
    case.json(&path("creation.json"),&json!({"format":"memcordon.linux-cross-account-command-creation","revision":1,"process_id":pid,"birth":birth,"invocation_sha256":sha256(&bytes),"kernel_image":{"device":1,"inode":1000+ordinal,"length":image.len(),"sha256":sha256(&image)}}));
    case.write(&path("stdout.bin"), stdout);
    case.write(&path("stderr.bin"), b"");
    case.json(&path("exit.json"),&json!({"format":"memcordon.linux-cross-account-command-exit","revision":1,"held":{"pid":pid,"birth":birth,"parent_pid":null,"parent_birth":null,"retirement_observed":true},"raw_wait_status":status*256,"native_exit":status,"signal":null,"invocation_sha256":sha256(&bytes),"stdout_sha256":sha256(stdout),"stderr_sha256":sha256(b"")}));
    json!({"invocation":leaf("invocation.json"),"image":leaf("image.bin"),"creation":leaf("creation.json"),"stdout":leaf("stdout.bin"),"stderr":leaf("stderr.bin"),"exit":leaf("exit.json")})
}
