use memcordon_ci::private_candidate_unix_facts::{
    diagnostic_unix_creation_denials_v1, parse_unix_proc_table_v1, unix_intent_names_v1,
    validate_planted_unix_sources_v1,
};
use std::collections::BTreeMap;

const HEADER: &str = "Num RefCount Protocol Flags Type St Inode Path\n";
fn stat() -> Vec<u8> {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "123";
    format!("101 (unix detector) {}\n", fields.join(" ")).into_bytes()
}

fn denial_capture(key: &memcordon_core::DiagnosticSha256, errno: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [0x4d434b31u32, 2] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&4u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    for value in [192u32, 15, 12, 0x01020304] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for sequence in 1..=4u64 {
        let mut record = vec![0u8; 192];
        for (offset, value) in [
            (0, sequence),
            (8, 10 + sequence),
            (16, 3),
            (24, 1000),
            (120, 4),
            (128, sequence.div_ceil(2)),
        ] {
            record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        record[48..56].copy_from_slice(&41i64.to_le_bytes());
        let decision = sequence % 2 == 1;
        record[56..64].copy_from_slice(&(if decision { errno } else { -errno }).to_le_bytes());
        for (offset, value) in [
            (64, 7u32),
            (72, 0xc000003e),
            (76, if decision { 0x50000 } else { 0 }),
            (80, if decision { 4 } else { 5 }),
            (184, 7),
        ] {
            record[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        record[84..116].copy_from_slice(key.bytes());
        record[136..144].copy_from_slice(&1u64.to_le_bytes());
        record[144..152].copy_from_slice(&0x80001u64.to_le_bytes());
        bytes.extend(record);
    }
    bytes
}

#[test]
fn unix_denials_use_real_v2_action_and_separate_errno_data() {
    let key = memcordon_core::DiagnosticSha256::from_bytes([9; 32]);
    let bytes = denial_capture(&key, 97);
    diagnostic_unix_creation_denials_v1(&bytes, &key, 7, "x86_64-unknown-linux-gnu", 20).unwrap();
    assert!(
        diagnostic_unix_creation_denials_v1(
            &denial_capture(&key, 1),
            &key,
            7,
            "x86_64-unknown-linux-gnu",
            20
        )
        .is_err()
    );
    assert!(
        diagnostic_unix_creation_denials_v1(&bytes, &key, 7, "x86_64-unknown-linux-gnu", 13)
            .is_err()
    );
}
fn fixture(challenge: [u8; 32]) -> BTreeMap<String, Vec<u8>> {
    let (path, abstract_name) = unix_intent_names_v1(&challenge);
    let identity = serde_json::json!({"schema_version":1,"protocol":"private-unix-planted-detector-v1","pathname":path,"abstract_name":abstract_name.strip_prefix('@').unwrap(),"reader_netns_inode":10,"reader_mountns_inode":20,"control_netns_inode":30,"control_mountns_inode":40,"pathname_fd":5,"pathname_socket_inode":1001,"abstract_fd":6,"abstract_socket_inode":1002,"pathname_device":50,"pathname_inode":1003,"pathname_mode":0o140700,"pathname_uid":0,"begin_monotonic_ns":100,"held_monotonic_ns":110});
    BTreeMap::from([
        ("identity.json".into(),serde_json::to_vec(&identity).unwrap()),
        ("stat-before.raw".into(),stat()),("stat-after.raw".into(),stat()),
        ("status.raw".into(),b"Name:\tunix detector\nUid:\t0\t0\t0\t0\n".to_vec()),
        ("unix-before.raw".into(),HEADER.as_bytes().to_vec()),
        ("unix-after.raw".into(),HEADER.as_bytes().to_vec()),
        ("unix-held.raw".into(),format!("{HEADER}00000000: 00000002 00000000 00010000 0001 01 1001 {path}\n00000001: 00000002 00000000 00010000 0001 01 1002 {abstract_name}\n").into_bytes()),
        ("pathname-fdinfo.raw".into(),b"pos:\t0\nflags:\t02000002\nino:\t1001\n".to_vec()),
        ("abstract-fdinfo.raw".into(),b"pos:\t0\nflags:\t02000002\nino:\t1002\n".to_vec()),
        ("end-monotonic.raw".into(),120u64.to_le_bytes().to_vec()),
    ])
}

#[test]
fn exact_unix_inventory_keeps_path_remainder_and_rejects_invalid_rows() {
    let rows = parse_unix_proc_table_v1(
        format!("{HEADER}0: 2 0 10000 1 01 42 /tmp/path with spaces\n").as_bytes(),
    )
    .unwrap();
    assert_eq!(rows[0].path, "/tmp/path with spaces");
    for row in [
        "0: 2 0 10000 1 01 +42 /tmp/path\n",
        "0: +2 0 10000 1 01 42 /tmp/path\n",
        "0: 2 0 10000 1 01 42 /tmp/path",
        "0: 2 0 10000 1 01 42 /tmp/a\n1: 2 0 10000 1 01 42 /tmp/b\n",
    ] {
        assert!(
            parse_unix_proc_table_v1(format!("{HEADER}{row}").as_bytes()).is_err(),
            "accepted malformed row {row}"
        );
    }
    let orphan =
        parse_unix_proc_table_v1(format!("{HEADER}0: 2 0 0 1 03 0 /tmp/orphan\n").as_bytes())
            .unwrap();
    assert_eq!(orphan[0].inode, 0);
    assert_eq!(orphan[0].path, "/tmp/orphan");
}

#[test]
fn actual_planted_control_requires_both_objects_and_cleanup() {
    let challenge = [0xab; 32];
    let sources = fixture(challenge);
    assert_eq!(
        validate_planted_unix_sources_v1(&sources, &challenge).unwrap(),
        (100, 120)
    );
    assert!(validate_planted_unix_sources_v1(&sources, &[0xac; 32]).is_err());
    for name in sources.keys() {
        let mut missing = sources.clone();
        missing.remove(name);
        assert!(
            validate_planted_unix_sources_v1(&missing, &challenge).is_err(),
            "accepted missing {name}"
        );
    }
    let mut changed = sources.clone();
    changed.insert("unix-after.raw".into(), sources["unix-held.raw"].clone());
    assert!(validate_planted_unix_sources_v1(&changed, &challenge).is_err());
    let mut changed = sources.clone();
    changed.insert("abstract-fdinfo.raw".into(), b"ino:\t1001\n".to_vec());
    assert!(validate_planted_unix_sources_v1(&changed, &challenge).is_err());
    let mut changed = sources.clone();
    changed.insert("verdict.json".into(), b"true".to_vec());
    assert!(validate_planted_unix_sources_v1(&changed, &challenge).is_err());
    let mut changed = sources.clone();
    let mut identity: serde_json::Value =
        serde_json::from_slice(&changed["identity.json"]).unwrap();
    identity["control_netns_inode"] = serde_json::json!(10);
    changed.insert(
        "identity.json".into(),
        serde_json::to_vec(&identity).unwrap(),
    );
    assert!(validate_planted_unix_sources_v1(&changed, &challenge).is_err());
}
