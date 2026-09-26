use memcordon_ci::private_public_abi_outer::{
    ExpectedPublicAbiOuterV1, readback_public_abi_outer_v1,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;

fn fixture() -> (
    Vec<u8>,
    Vec<u8>,
    [u8; 32],
    DiagnosticSha256,
    DiagnosticSha256,
) {
    let challenge = [0x41; 32];
    let h1 = hash_bytes(b"protected H1");
    let epoch = hash_bytes(b"installed epoch");
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::FinalPublic,
        "private_tcp::abi_alternate_entry_denied",
        &challenge,
    )
    .unwrap();
    let mut material = b"memcordon-public-abi-outer-v1\0".to_vec();
    for digest in [&h1, &epoch, &key, &DiagnosticSha256::from_bytes(challenge)] {
        material.extend_from_slice(digest.bytes());
    }
    let aux = hash_bytes(&material);
    let request = format!(
        "{{\"schema\":1,\"selector\":\"private_tcp::abi_alternate_entry_denied\",\"challenge\":\"{}\",\"dispatch_key\":\"{}\"}}",
        String::from(DiagnosticSha256::from_bytes(challenge)),
        String::from(key.clone()),
    );
    let branch = |name: &str, pid: u32, arch: u32, nr: u32, returned: i64| {
        format!(
            "{{\"branch\":\"{name}\",\"child\":{{\"pid\":{pid},\"start_time\":{pid}0}},\"audit_arch\":{arch},\"syscall_nr\":{nr},\"return_value\":{returned},\"errno\":null,\"return_marker\":null,\"exec_device\":null,\"exec_inode\":null,\"exit_code\":0,\"reaped\":true,\"inherited_outer_filters\":2}}"
        )
    };
    let branches = [
        branch("native", 13, 0xc000_003e, 39, 13),
        branch("x32", 14, 0xc000_003e, 0x4000_0027, 14),
        branch("i386", 15, 0x4000_0003, 20, 15),
    ]
    .join(",");
    let raw = format!(
        "{{\"schema\":1,\"selector\":\"private_tcp::abi_alternate_entry_denied\",\"auxiliary_only\":true,\"challenge_sha256\":\"{}\",\"dispatch_key\":\"{}\",\"auxiliary_key\":\"{}\",\"h1_sha256\":\"{}\",\"installation_epoch\":\"{}\",\"outer\":{{\"service\":{{\"pid\":11,\"start_time\":110}},\"service_worker\":{{\"pid\":12,\"start_time\":120}},\"cgroup\":\"/system.slice/memcordon-sealed-agent.service\",\"cgroup_inode\":55,\"seccomp_mode\":2,\"seccomp_filters\":2,\"no_new_privs\":1}},\"branches\":[{branches}]}}",
        String::from(hash_bytes(&challenge)),
        String::from(key),
        String::from(aux),
        String::from(h1.clone()),
        String::from(epoch.clone()),
    );
    (request.into_bytes(), raw.into_bytes(), challenge, h1, epoch)
}

#[test]
fn exact_outer_controls_are_structural_only() {
    let (request, raw, challenge, h1, epoch) = fixture();
    let expected = ExpectedPublicAbiOuterV1 {
        target: "x86_64-unknown-linux-gnu",
        challenge: &challenge,
        h1_sha256: &h1,
        installation_epoch: &epoch,
        service_pid: 11,
        service_start_ticks: 110,
        service_cgroup_inode: 55,
    };
    let readback = readback_public_abi_outer_v1(&request, &raw, &expected).unwrap();
    assert_eq!(readback.children.len(), 3);
    assert_eq!(readback.request_sha256, hash_bytes(&request));
    assert_eq!(readback.raw_sha256, hash_bytes(&raw));
    assert_eq!(readback.service_worker_pid, 12);
    assert_eq!(readback.service_worker_start_ticks, 120);
    assert_ne!(readback.auxiliary_key, readback.dispatch_key);
}

#[test]
fn substituted_branch_and_outer_provenance_fail() {
    let (request, raw, challenge, h1, epoch) = fixture();
    let expected = ExpectedPublicAbiOuterV1 {
        target: "x86_64-unknown-linux-gnu",
        challenge: &challenge,
        h1_sha256: &h1,
        installation_epoch: &epoch,
        service_pid: 11,
        service_start_ticks: 110,
        service_cgroup_inode: 55,
    };
    for swapped in [
        String::from_utf8(raw.clone())
            .unwrap()
            .replace("\"branch\":\"i386\"", "\"branch\":\"x32\""),
        String::from_utf8(raw.clone())
            .unwrap()
            .replace("\"no_new_privs\":1", "\"no_new_privs\":0"),
        String::from_utf8(raw.clone()).unwrap().replace(
            "\"inherited_outer_filters\":2",
            "\"inherited_outer_filters\":3",
        ),
        String::from_utf8(raw.clone())
            .unwrap()
            .replace("\"return_value\":15", "\"return_value\":-1"),
    ] {
        assert!(readback_public_abi_outer_v1(&request, swapped.as_bytes(), &expected).is_err());
    }
    let wrong = ExpectedPublicAbiOuterV1 {
        service_cgroup_inode: 56,
        ..expected
    };
    assert!(readback_public_abi_outer_v1(&request, &raw, &wrong).is_err());
}
