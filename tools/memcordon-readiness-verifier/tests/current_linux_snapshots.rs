use memcordon_readiness_verifier::{current::linux_snapshots::validate_bundle_mutation, sha256};
use serde_json::json;

fn concurrent_data() -> [serde_json::Value; 9] {
    use serde_json::Value;
    let make = |base: u64, device: u64| {
        let ns = |index: u64| json!({"device":7,"inode":base+100+index});
        let native = json!({"boot_id":"same-boot","caller":{"pid":base+10,"birth":0},"caller_uid":1000,"guardian":{"pid":base+2,"birth":0},"namespace_init":{"pid":base+3,"birth":0},"target":{"pid":base+4,"birth":0},"target_namespace_pid":2,"target_uid":1000,"target_gid":1000,"cgroup_device":8,"cgroup_inode":base+200,"mount_namespace":ns(1),"pid_namespace":ns(2),"network_namespace":ns(3),"ipc_namespace":ns(4),"user_namespace":ns(5),"root_device":device,"root_inode":2,"entrypoint_sha256":"01".repeat(32)});
        let association = json!({"format":"memcordon.workload-attempt","revision":1,"attempt":vec![u8::try_from(base).unwrap();16],"challenge":vec![u8::try_from(base+1).unwrap();16],"boot_id":"00112233-4455-6677-8899-aabbccddeeff","request_sha256":"02".repeat(32),"provider":{"generation":"current","source_commit":"01".repeat(20),"runtime_manifest_sha256":"04".repeat(32)},"control":{"pid":base+1,"birth":0}});
        let mut processes = Vec::new();
        let mut live = Vec::new();
        for (index, role) in ["worker", "control", "guardian", "namespace_init", "target"]
            .into_iter()
            .enumerate()
        {
            let pid = base + index as u64;
            let target = role == "target";
            let mut snapshot = json!({"process_id":pid,"birth":0,"namespace_pids":[pid],"user":ns(5),"mount":ns(1),"pid":ns(2),"network":ns(3),"ipc":ns(4)});
            if target {
                snapshot["namespace_pids"] = json!([pid, 2]);
            }
            if role == "namespace_init" {
                snapshot["namespace_pids"] = json!([pid, 1]);
            }
            let uid = if target { 1000 } else { 0 };
            processes.push(json!({"role":role,"snapshot":snapshot,"credentials":{"uid":vec![uid;4],"gid":vec![uid;4],"groups":[],"cap_effective":0,"cap_permitted":0,"cap_ambient":0,"no_new_privileges":1}}));
            live.push(json!({"pid":pid,"birth":0,"pidfd_readable":false,"native_error":null}));
        }
        (
            json!({"format":"memcordon.linux-current-held","revision":1,"association":association,"journal_sha256":"03".repeat(32),"native":native,"processes":processes,"root":{"device":device,"inode":2}}),
            association,
            native,
            Value::Array(live),
        )
    };
    let (holder, association, native, live) = make(100, 11);
    let (peer, peer_association, peer_native, peer_live) = make(200, 12);
    [
        holder,
        peer,
        association,
        peer_association,
        native,
        peer_native,
        live.clone(),
        peer_live,
        live,
    ]
}
fn validate_concurrency(data: &[serde_json::Value; 9]) -> Result<(), String> {
    memcordon_readiness_verifier::current::linux_snapshots::validate_concurrent_holds(
        &data[0], &data[1], &data[2], &data[3], &data[4], &data[5], &data[6], &data[7], &data[8],
    )
}

#[test]
fn concurrent_native_identity_uses_device_inode_and_original_live_processes() {
    let data = concurrent_data();
    assert!(
        validate_concurrency(&data).is_ok(),
        "equal inode numbers on distinct tmpfs devices are valid"
    );
    let mut rebound = data.clone();
    rebound[5]["root_device"] = data[4]["root_device"].clone();
    rebound[1]["native"]["root_device"] = data[4]["root_device"].clone();
    rebound[1]["root"]["device"] = data[4]["root_device"].clone();
    assert!(validate_concurrency(&rebound).is_err());
    let mut rebound = data.clone();
    rebound[5]["cgroup_inode"] = data[4]["cgroup_inode"].clone();
    rebound[1]["native"]["cgroup_inode"] = data[4]["cgroup_inode"].clone();
    assert!(validate_concurrency(&rebound).is_err());
}

#[test]
fn concurrent_proof_rejects_missing_rebound_credentials_namespaces_and_liveness() {
    let original = concurrent_data();
    for (index, path, value) in [
        (0, vec!["processes"], json!([])),
        (0, vec!["root", "inode"], json!(99)),
        (0, vec!["association", "attempt"], json!([999])),
        (6, vec![], json!([])),
        (8, vec![], json!([])),
    ] {
        let mut data = original.clone();
        if path.is_empty() {
            data[index] = value;
        } else if path.len() == 1 {
            data[index][path[0]] = value;
        } else {
            data[index][path[0]][path[1]] = value;
        }
        assert!(validate_concurrency(&data).is_err());
    }
    let mut data = original.clone();
    data[0]["processes"][4]["credentials"]["uid"] = json!(vec![2000; 4]);
    assert!(validate_concurrency(&data).is_err());
    let mut data = original.clone();
    data[1]["processes"][4]["snapshot"]["network"]["inode"] = json!(999);
    assert!(validate_concurrency(&data).is_err());
    let mut data = original.clone();
    data[7][4]["birth"] = json!(1);
    assert!(validate_concurrency(&data).is_err());
    let mut data = original.clone();
    data[8][0]["pidfd_readable"] = json!(true);
    assert!(validate_concurrency(&data).is_err());
}

fn bundle() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let source = vec![0x31; 32];
    let replacement = vec![0xce; 32];
    let fixture = b"actual-current-fixture-bytes";
    let runtime = json!({"format":"memcordon.workload-snapshot","revision":1,"target":"aarch64-unknown-linux-gnu","entries":[{"kind":"regular","path":"bin/fixture","size":fixture.len(),"sha256":sha256(fixture),"executable":true}],"entrypoints":[{"id":"fixture","path":"bin/fixture"}],"library_directories":[]});
    let input = json!({"format":"memcordon.workload-snapshot","revision":1,"target":"aarch64-unknown-linux-gnu","entries":[{"kind":"regular","path":"input/snapshot.bin","size":source.len(),"sha256":sha256(&source),"executable":false}],"entrypoints":[],"library_directories":[]});
    let mut original = b"memcordon.workload-bundle\0\x01".to_vec();
    for manifest in [runtime, input] {
        let bytes = serde_json::to_vec(&manifest).unwrap();
        original.extend((bytes.len() as u64).to_be_bytes());
        original.extend(bytes);
    }
    original.extend(fixture);
    original.extend(&source);
    let mut changed = original.clone();
    let at = changed.len() - replacement.len();
    changed[at..].copy_from_slice(&replacement);
    (original, changed, source, replacement)
}

#[test]
fn exact_corruption_requires_original_valid_members_and_only_input_delta() {
    let (original, changed, source, replacement) = bundle();
    assert!(validate_bundle_mutation(&original, &changed, &source, &replacement).is_ok());
    let mut other = changed.clone();
    other[0] ^= 1;
    assert!(validate_bundle_mutation(&original, &other, &source, &replacement).is_err());
    let mut original_bad = original.clone();
    let at = original_bad.len() - source.len() - 1;
    original_bad[at] ^= 1;
    let mut changed_bad = changed.clone();
    changed_bad[at] ^= 1;
    assert!(validate_bundle_mutation(&original_bad, &changed_bad, &source, &replacement).is_err());
    let mut trailing = original.clone();
    trailing.push(0);
    let mut changed_trailing = changed.clone();
    changed_trailing.push(0);
    assert!(validate_bundle_mutation(&trailing, &changed_trailing, &source, &replacement).is_err());
}

#[test]
fn malformed_headers_never_authorize_source_mutation() {
    let (original, changed, source, replacement) = bundle();
    for length in [0, 1, 8, 24, original.len() - 1] {
        assert!(
            validate_bundle_mutation(
                &original[..length],
                &changed[..length],
                &source,
                &replacement
            )
            .is_err()
        );
    }
    let mut oversized = original.clone();
    let at = b"memcordon.workload-bundle\0\x01".len();
    oversized[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(validate_bundle_mutation(&oversized, &changed, &source, &replacement).is_err());
}
