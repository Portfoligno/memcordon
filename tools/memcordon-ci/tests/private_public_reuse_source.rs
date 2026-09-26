use memcordon_ci::private_public_reuse_join::validate_holder_fd_source;
use memcordon_core::workload_codec::hash_bytes;

fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let transcript=serde_json::to_vec(&serde_json::json!({"holder_pid":44,"holder_start_time":500,"held_fd":7,"namespace_inode":71})).unwrap();
    let open=serde_json::to_vec(&serde_json::json!({"schema_version":1,"holder":{"pid":44,"start_time":500},"held_fd":7,"namespace_inode":71})).unwrap();
    let source=serde_json::to_vec(&serde_json::json!({"pid":44,"start_time_ticks":500,"descriptor":7,"device":4,"inode":71,"link":"net:[71]","fdinfo":b"pos:\t0\nflags:\t02100000\nmnt_id:\t4\nino:\t71\n".to_vec(),"holder_open_sha256":hash_bytes(&open),"observed_monotonic_ns":2000})).unwrap();
    (transcript, source, open)
}
#[test]
fn independent_original_fdinfo_matches_exact_holder_snapshot() {
    let (transcript, source, open) = fixture();
    validate_holder_fd_source(&transcript, &source, &open, 44, 500).unwrap();
}
#[test]
fn rejects_wrong_fd_inode_pid_time_or_missing_observation() {
    let (transcript, source, open) = fixture();
    for (field, value) in [
        ("descriptor", serde_json::json!(8)),
        ("inode", serde_json::json!(72)),
        ("pid", serde_json::json!(45)),
        ("start_time_ticks", serde_json::json!(501)),
        ("observed_monotonic_ns", serde_json::json!(0)),
        ("link", serde_json::json!("net:[72]")),
    ] {
        let mut changed: serde_json::Value = serde_json::from_slice(&source).unwrap();
        changed[field] = value;
        assert!(
            validate_holder_fd_source(
                &transcript,
                &serde_json::to_vec(&changed).unwrap(),
                &open,
                44,
                500
            )
            .is_err(),
            "accepted substituted {field}"
        );
    }
    assert!(validate_holder_fd_source(&transcript, &source, b"{}", 44, 500).is_err());
}
#[test]
fn rejects_duplicate_or_unmeasured_fdinfo_inode() {
    let (transcript, source, open) = fixture();
    for raw in [
        b"ino:\t71\nino:\t71\n".as_slice(),
        b"ino:\t72\n",
        b"pos:\t0\n",
    ] {
        let mut changed: serde_json::Value = serde_json::from_slice(&source).unwrap();
        changed["fdinfo"] = serde_json::json!(raw.to_vec());
        assert!(
            validate_holder_fd_source(
                &transcript,
                &serde_json::to_vec(&changed).unwrap(),
                &open,
                44,
                500
            )
            .is_err()
        );
    }
}
