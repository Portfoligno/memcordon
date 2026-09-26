use memcordon_ci::private_public_source_facts::{
    decode_public_exec_response_frame, decode_public_held_payload, extract_public_fixture_response,
};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};

#[test]
fn descendant_mapping_requires_original_parent_and_private_namespaces() {
    use memcordon_ci::private_public_live::{HeldPublicTargetSamplesV1, HeldPublicTaskSampleV1};
    use memcordon_ci::private_public_source_facts::validate_public_descendant_samples;
    use std::collections::BTreeMap;
    let task = |tid, tgid| HeldPublicTaskSampleV1 {
        tid,
        tgid,
        start_time_ticks: 100,
        namespace_inodes: BTreeMap::from([
            ("pid".into(), 901),
            ("net".into(), 902),
            ("mnt".into(), 903),
        ]),
    };
    let mut parent = HeldPublicTargetSamplesV1 {
        schema_version: 1,
        pid: 500,
        start_time_ticks: 100,
        begin_monotonic_ns: 1000,
        end_monotonic_ns: 2000,
        executable_sha256: hash_bytes(b"diagnostic ELF"),
        executable_device: 1,
        executable_inode: 2,
        tasks: vec![task(500, 500), task(502, 500)],
        leaves: BTreeMap::from([
            ("status.raw".into(), b"NSpid:\t500\t1\n".to_vec()),
            ("tasks/502/status.raw".into(), b"NSpid:\t502\t3\n".to_vec()),
        ]),
    };
    let mut child = parent.clone();
    child.pid = 501;
    child.tasks = vec![task(501, 501)];
    child.leaves = BTreeMap::from([
        (
            "status.raw".into(),
            b"PPid:\t500\nTgid:\t501\nNSpid:\t501\t2\n".to_vec(),
        ),
        ("parent-children.raw".into(), b"501 ".to_vec()),
    ]);
    let challenge = [21; 32];
    let mut operations = b"MCRCHLD1".to_vec();
    for id in [1_u32, 2, 3] {
        operations.extend_from_slice(&id.to_le_bytes());
    }
    operations.extend_from_slice(hash_bytes(&challenge).bytes());
    assert_eq!(
        validate_public_descendant_samples(&parent, &child, &operations, &challenge).unwrap(),
        502
    );
    child.leaves.insert(
        "status.raw".into(),
        b"PPid:\t900\nTgid:\t501\nNSpid:\t501\t2\n".to_vec(),
    );
    assert!(validate_public_descendant_samples(&parent, &child, &operations, &challenge).is_err());
    child.leaves.insert(
        "status.raw".into(),
        b"PPid:\t500\nTgid:\t501\nNSpid:\t501\t2\n".to_vec(),
    );
    child.tasks[0].namespace_inodes.insert("net".into(), 904);
    assert!(validate_public_descendant_samples(&parent, &child, &operations, &challenge).is_err());
    child.tasks[0].namespace_inodes.insert("net".into(), 902);
    child
        .leaves
        .insert("parent-children.raw".into(), b"501 501 ".to_vec());
    assert!(validate_public_descendant_samples(&parent, &child, &operations, &challenge).is_err());
    parent
        .leaves
        .insert("tasks/502/status.raw".into(), b"NSpid:\t502\t4\n".to_vec());
    assert!(validate_public_descendant_samples(&parent, &child, &operations, &challenge).is_err());
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = b"MCPH\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn topology_version_three_retains_actual_nested_tcp_bytes_and_exact_role() {
    let selector = "private_tcp::private_namespace_topology_exact";
    let challenge = [31; 32];
    let port = 24011;
    let response = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, &challenge, port,
    )
    .unwrap();
    let tcp = serde_json::json!({"schema_version":2,"network_namespace_inode":900,"listener_port":port,"client_port":40011,
        "challenge_sha256":hash_bytes(&challenge),"response_sha256":DiagnosticSha256::from_bytes(response),"observed_response_bytes":response});
    let source = serde_json::json!({"schema_version":3,"tcp":tcp,"namespace_reentry_errno":null,"namespace_creation_errno":null,
        "namespace_operand":null});
    assert_eq!(
        extract_public_fixture_response(
            selector,
            &challenge,
            port,
            &frame(&serde_json::to_vec(&source).unwrap())
        )
        .unwrap(),
        response
    );
    let mut changed = source.clone();
    changed["tcp"]["observed_response_bytes"][0] = serde_json::json!(response[0] ^ 1);
    assert!(
        extract_public_fixture_response(
            selector,
            &challenge,
            port,
            &frame(&serde_json::to_vec(&changed).unwrap())
        )
        .is_err()
    );
    changed = source.clone();
    changed["namespace_reentry_errno"] = serde_json::json!(1);
    assert!(
        extract_public_fixture_response(
            selector,
            &challenge,
            port,
            &frame(&serde_json::to_vec(&changed).unwrap())
        )
        .is_err()
    );
    assert!(
        extract_public_fixture_response(
            selector,
            &challenge,
            port,
            &frame(&serde_json::to_vec(&source["tcp"]).unwrap())
        )
        .is_err()
    );
}

#[test]
fn reentry_response_requires_explicit_retained_valid_operand_source() {
    let selector = "private_tcp::namespace_reentry_denied";
    let challenge = [32; 32];
    let port = 24012;
    let response = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, &challenge, port,
    )
    .unwrap();
    let mut source = serde_json::json!({"schema_version":3,"tcp":{"schema_version":2,"network_namespace_inode":901,"listener_port":port,"client_port":40012,
        "challenge_sha256":hash_bytes(&challenge),"response_sha256":DiagnosticSha256::from_bytes(response),"observed_response_bytes":response},
        "namespace_reentry_errno":1,"namespace_creation_errno":1,"namespace_operand":{"descriptor":3,"device":4,"inode":901}});
    assert_eq!(
        extract_public_fixture_response(
            selector,
            &challenge,
            port,
            &frame(&serde_json::to_vec(&source).unwrap())
        )
        .unwrap(),
        response
    );
    source["namespace_operand"] = serde_json::Value::Null;
    assert!(
        extract_public_fixture_response(
            selector,
            &challenge,
            port,
            &frame(&serde_json::to_vec(&source).unwrap())
        )
        .is_err()
    );
}

#[test]
fn facility_status_keeps_originals_but_compares_stable_predicates() {
    use memcordon_ci::private_public_source_facts::validate_public_facility_status_join;
    let gate=b"Pid:\t500\nTgid:\t500\nUid:\t0 0 0 0\nGid:\t0 0 0 0\nGroups:\t\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\tffffffff\nCapAmb:\t0\nvoluntary_ctxt_switches:\t3\n";
    let mut held = gate.to_vec();
    held.extend_from_slice(b"VmRSS:\t2400 kB\n");
    assert!(validate_public_facility_status_join(gate, &held).is_ok());
    let changed = std::str::from_utf8(gate)
        .unwrap()
        .replace("Seccomp_filters:\t2", "Seccomp_filters:\t3");
    assert!(validate_public_facility_status_join(gate, changed.as_bytes()).is_err());
    held.extend_from_slice(b"Pid:\t500\n");
    assert!(validate_public_facility_status_join(gate, &held).is_err());
}

#[test]
fn terminal_midpoint_decodes_only_the_original_emitted_frame() {
    use memcordon_ci::private_public_source_facts::decode_public_terminal_midpoint_frame;
    let challenge = [24; 32];
    let mut source = b"MCEX\x01\0\0\0".to_vec();
    source.extend_from_slice(
        &memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
            "private_tcp::release_checkpoint_terminal_joined",
            &challenge,
            0,
        )
        .unwrap(),
    );
    source.extend_from_slice(b"MCRJOIN1");
    source.extend_from_slice(&1_u32.to_le_bytes());
    source.extend_from_slice(hash_bytes(&challenge).bytes());
    assert_eq!(
        decode_public_terminal_midpoint_frame(&source, &challenge).unwrap(),
        1
    );
    assert!(
        decode_public_terminal_midpoint_frame(&source[..source.len() - 1], &challenge).is_err()
    );
    assert!(decode_public_terminal_midpoint_frame(&source, &[25; 32]).is_err());
    source.push(0);
    assert!(decode_public_terminal_midpoint_frame(&source, &challenge).is_err());
}

#[test]
fn exact_held_frame_rejects_truncated_or_concatenated_streams() {
    let valid = frame(b"actual bytes");
    assert_eq!(decode_public_held_payload(&valid).unwrap(), b"actual bytes");
    assert!(decode_public_held_payload(&valid[..valid.len() - 1]).is_err());
    let mut doubled = valid.clone();
    doubled.extend_from_slice(&valid);
    assert!(decode_public_held_payload(&doubled).is_err());
    assert!(decode_public_held_payload(&frame(&[])).is_err());
}

#[test]
fn generic_response_is_extracted_from_actual_payload_not_synthesized() {
    let selector = "private_tcp::descriptor_table_and_stdio_bound";
    let challenge = [7; 32];
    let expected = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, &challenge, 0,
    )
    .unwrap();
    let mut payload = expected.to_vec();
    payload.extend_from_slice(b"original native operation observations");
    assert_eq!(
        extract_public_fixture_response(selector, &challenge, 0, &frame(&payload)).unwrap(),
        expected
    );
    payload[0] ^= 1;
    assert!(extract_public_fixture_response(selector, &challenge, 0, &frame(&payload)).is_err());
}

#[test]
fn tcp_actual_read_schema_cannot_upgrade_digest_only_or_changed_bytes() {
    let selector = "private_tcp::native_tcp_bind_listen_connect";
    let challenge = [9; 32];
    let port = 31025;
    let response = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, &challenge, port,
    )
    .unwrap();
    let mut source = serde_json::json!({
        "schema_version":2,"network_namespace_inode":573,"listener_port":port,
        "client_port":48001,"challenge_sha256":hash_bytes(&challenge),
        "response_sha256":DiagnosticSha256::from_bytes(response),
        "observed_response_bytes":response,
    });
    let encoded = |source: &serde_json::Value| frame(&serde_json::to_vec(source).unwrap());
    assert_eq!(
        extract_public_fixture_response(selector, &challenge, port, &encoded(&source)).unwrap(),
        response
    );
    source["schema_version"] = 1.into();
    source
        .as_object_mut()
        .unwrap()
        .remove("observed_response_bytes");
    assert!(
        extract_public_fixture_response(selector, &challenge, port, &encoded(&source)).is_err()
    );
    source["schema_version"] = 2.into();
    source["observed_response_bytes"] = serde_json::to_value([8_u8; 32]).unwrap();
    assert!(
        extract_public_fixture_response(selector, &challenge, port, &encoded(&source)).is_err()
    );
}

#[test]
fn collision_requires_observed_read_recipe_and_linux_errno() {
    let selector = "private_tcp::port_collision_same_namespace";
    let challenge = [11; 32];
    let port = 31026;
    let mut source = serde_json::json!({
        "schema_version":2,"network_namespace_inode":574,"bound_port":port,
        "challenge_sha256":hash_bytes(&challenge),"collision_os_code":98,
        "observed_response_bytes":challenge,
    });
    let encoded = |source: &serde_json::Value| frame(&serde_json::to_vec(source).unwrap());
    assert_eq!(
        extract_public_fixture_response(selector, &challenge, port, &encoded(&source)).unwrap(),
        challenge
    );
    source["collision_os_code"] = 1.into();
    assert!(
        extract_public_fixture_response(selector, &challenge, port, &encoded(&source)).is_err()
    );
}

#[test]
fn dual_exec_response_uses_the_actual_branch_not_the_parent_recipe() {
    let selector = "private_tcp::dual_attempt_namespace_isolation";
    let parent = [17; 32];
    let port = 31027;
    let challenge =
        memcordon_core::private_release_case_v1::public_dual_challenge_v1(&parent, 0).unwrap();
    let response = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, &challenge, port,
    )
    .unwrap();
    let source = serde_json::json!({"schema_version":2,"network_namespace_inode":575,"listener_port":port,
        "client_port":48002,"challenge_sha256":hash_bytes(&challenge),"response_sha256":DiagnosticSha256::from_bytes(response),
        "observed_response_bytes":response});
    let raw = frame(&serde_json::to_vec(&source).unwrap());
    assert_eq!(
        extract_public_fixture_response(selector, &challenge, port, &raw).unwrap(),
        response
    );
    assert!(extract_public_fixture_response(selector, &parent, port, &raw).is_err());
    let second =
        memcordon_core::private_release_case_v1::public_dual_challenge_v1(&parent, 1).unwrap();
    assert!(extract_public_fixture_response(selector, &second, port, &raw).is_err());
}

#[test]
fn special_exec_frame_retains_real_prefix_and_original_operation_bytes() {
    let selector = "private_tcp::af_unix_abstract_and_pathname_denied";
    let challenge = [13; 32];
    let response = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, &challenge, 0,
    )
    .unwrap();
    let mut emitted = b"MCEX\x01\0\0\0".to_vec();
    emitted.extend_from_slice(&response);
    assert!(
        decode_public_exec_response_frame(selector, &challenge, &emitted[..emitted.len() - 1])
            .unwrap()
            .is_none()
    );
    assert!(extract_public_fixture_response(selector, &challenge, 0, &emitted).is_err());
    let operations = frame(b"actual unchanged Unix intent operation bytes");
    emitted.extend_from_slice(&operations);
    let (actual, retained_operations) =
        decode_public_exec_response_frame(selector, &challenge, &emitted)
            .unwrap()
            .unwrap();
    assert_eq!(actual, response);
    assert_eq!(retained_operations, operations);
    assert_eq!(
        extract_public_fixture_response(selector, &challenge, 0, &emitted).unwrap(),
        response
    );
    emitted[8] ^= 1;
    assert!(decode_public_exec_response_frame(selector, &challenge, &emitted).is_err());
}
