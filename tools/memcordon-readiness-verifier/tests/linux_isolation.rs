use memcordon_readiness_verifier::validate_linux_outside_file;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) fn vector(kind: &str) -> (Value, Value, Value, Vec<Vec<u8>>, Vec<u8>) {
    let challenge = vec![7; 32];
    let token = hex::encode(&challenge).into_bytes();
    let path = b"/owned/host-outside-canary/original.bin".to_vec();
    let probe = match kind {
        "mount-alias" => b"/owned/host-outside-canary/outside-mount".to_vec(),
        "opath" => path.clone(),
        "symlink" => b"/owned/host-outside-canary/outside-symlink".to_vec(),
        "hardlink" => b"/owned/host-outside-canary/outside-hardlink".to_vec(),
        "dotdot" => b"/owned/host-outside-canary/child/../original.bin".to_vec(),
        "proc-root" => b"/proc/100/root/owned/host-outside-canary/original.bin".to_vec(),
        "proc-cwd" => b"/proc/100/cwd/../../owned/host-outside-canary/original.bin".to_vec(),
        "proc-fd" => b"/proc/100/fd/9".to_vec(),
        _ => panic!("unknown test selector"),
    };
    let link = matches!(kind, "symlink" | "proc-fd");
    let nlink = if kind == "hardlink" { 2 } else { 1 };
    let canary = json!({"format":"memcordon.linux-outside-file-canary","revision":1,"kind":kind,
        "before":{"path":path,"probe":probe,"kind":kind,"device":5,"inode":80,"uid":0,
            "mode":0o100444,"nlink":nlink,"length":token.len(),"sha256":hex::encode(Sha256::digest(&token)),
            "controller_pid":100,"controller_birth":200,"source_descriptor":9,"original_cwd":b"/original/cwd".to_vec(),
            "resolved_device":5,"resolved_inode":80,"positive_bytes":token,
            "alias_native":{"device":5,"inode":if link {81}else{80},"mode":if link {0o120777}else{0o100444},
                "nlink":nlink,"symlink_target":if link {Some(path.clone())}else{None}}},
        "after":{"device":5,"inode":80,"uid":0,"mode":0o100444,"nlink":nlink,"length":64,"bytes":token},
        "parents":[
            {"path":b"/owned".to_vec(),"device":5,"inode":60,"named_device":5,"named_inode":60,"uid":0,"mode":0o040711,"nlink":2,"closed":true,"close_native_errno":null},
            {"path":b"/owned/host-outside-canary".to_vec(),"device":5,"inode":70,"named_device":5,"named_inode":70,"uid":0,"mode":0o040711,"nlink":2,"closed":true,"close_native_errno":null}],
        "mount":if kind=="mount-alias" {Some(json!({"source":path,"destination":probe,"mount_flags":4096,"mount_result":0,"unmount_flags":0,"unmount_result":0,"unmount_native_errno":null}))}else{None},
        "leaked_descriptor":if kind=="opath"{Some(json!({"original":{"frontend_pid":300,"frontend_birth":400,"descriptor":128,"parent_source_descriptor":12,"path":path,"device":5,"inode":80,"fdinfo":b"pos:\t0\nflags:\t010400000\nmnt_id:\t20\nino:\t80\n".to_vec()},"closed":true,"close_native_errno":null}))}else{None},
        "resolved_close_errno":null,"owner_close_errno":null});
    let denied = if kind == "opath" {
        json!({"kind":kind,"path":probe,"native_descriptor":128,"native_result":-1,"native_errno":9})
    } else {
        json!({"kind":kind,"path":probe,"native_open_flags":0x80000,"native_result":-1,"native_errno":2})
    };
    let positive = json!({"path":b"/work/private-path-positive.bin".to_vec(),"bytes":b"private-read-write-positive".to_vec()});
    let mut argv = vec![
        b"outside-file".to_vec(),
        hex::encode(&challenge).into_bytes(),
        kind.as_bytes().to_vec(),
        probe,
    ];
    if kind == "opath" {
        argv.push(b"128".to_vec());
    }
    (canary, denied, positive, argv, challenge)
}

#[test]
fn eight_original_native_alias_vectors_and_reassociated_inode_rejection() {
    for kind in [
        "symlink",
        "dotdot",
        "proc-root",
        "proc-cwd",
        "proc-fd",
        "hardlink",
        "opath",
        "mount-alias",
    ] {
        let (canary, denied, positive, argv, challenge) = vector(kind);
        validate_linux_outside_file(kind, &canary, &denied, &positive, &argv, &challenge).unwrap();
        let mut changed = canary.clone();
        changed["before"]["resolved_inode"] = json!(900);
        assert!(
            validate_linux_outside_file(kind, &changed, &denied, &positive, &argv, &challenge)
                .unwrap_err()
                .contains("different original inode")
        );
        let mut changed = canary.clone();
        changed["after"]["inode"] = json!(900);
        assert!(
            validate_linux_outside_file(kind, &changed, &denied, &positive, &argv, &challenge)
                .unwrap_err()
                .contains("changed across attempt")
        );
    }
}

#[test]
fn host_read_success_and_missing_private_control_cannot_prove_isolation() {
    let (canary, mut denied, mut positive, argv, challenge) = vector("proc-fd");
    validate_linux_outside_file("proc-fd", &canary, &denied, &positive, &argv, &challenge).unwrap();
    denied["native_result"] = json!(10);
    assert!(
        validate_linux_outside_file("proc-fd", &canary, &denied, &positive, &argv, &challenge)
            .is_err()
    );
    denied["native_result"] = json!(-1);
    positive["bytes"] = json!([]);
    assert!(
        validate_linux_outside_file("proc-fd", &canary, &denied, &positive, &argv, &challenge)
            .is_err()
    );
    let mut changed = canary.clone();
    changed["authority"] = json!(true);
    assert!(
        validate_linux_outside_file("proc-fd", &changed, &denied, &positive, &argv, &challenge)
            .unwrap_err()
            .contains("native fields")
    );
}
