use super::*;

#[test]
fn public_recovery_never_adopts_supplied_descriptors() {
    let (mut server, _client) = UnixStream::pair().unwrap();
    let descriptor: OwnedFd = File::open("/dev/null").unwrap().into();
    let frame = Frame {
        kind: MessageKind::WorkloadRecover,
        nonce: [1; 16],
        attempt_id: [2; 16],
        payload: Vec::new(),
    };
    let response = recover_public(&mut server, &frame, vec![descriptor], 0, 0, 0).unwrap();
    assert_eq!(response.kind, MessageKind::WorkloadRejected);
    let refusal: WorkloadRejectionV1 = serde_json::from_slice(&response.payload).unwrap();
    assert_eq!(refusal.code, WorkloadRejectionCodeV1::MalformedRequest);
}

#[test]
fn acknowledgment_never_adopts_public_or_private_descriptors() {
    for brokered in [false, true] {
        let (mut server, _client) = UnixStream::pair().unwrap();
        let descriptor: OwnedFd = File::open("/dev/null").unwrap().into();
        let frame = Frame {
            kind: if brokered {
                MessageKind::WorkloadBrokerAcknowledge
            } else {
                MessageKind::WorkloadAcknowledge
            },
            nonce: [1; 16],
            attempt_id: [2; 16],
            payload: Vec::new(),
        };
        let response = if brokered {
            acknowledge_brokered(&mut server, &frame, vec![descriptor], 0, 0)
        } else {
            acknowledge_public(&mut server, &frame, vec![descriptor], 0, 0, 0)
        }
        .unwrap();
        assert_eq!(response.kind, MessageKind::WorkloadRejected);
        let refusal: WorkloadRejectionV1 = serde_json::from_slice(&response.payload).unwrap();
        assert_eq!(refusal.code, WorkloadRejectionCodeV1::MalformedRequest);
    }
}

#[test]
fn malformed_recovery_cannot_create_native_ownership() {
    for payload in [
        b"{}".to_vec(),
        b"{\"format\":\"a\",\"format\":\"b\"}".to_vec(),
        vec![0; 64 * 1024 + 1],
    ] {
        let frame = Frame {
            kind: MessageKind::WorkloadRecover,
            nonce: [1; 16],
            attempt_id: [2; 16],
            payload,
        };
        assert!(parse_association(&frame).is_err());
    }
}

#[test]
#[ignore = "requires root ownership for a real provider staging fixture"]
fn input_cleanup_unlinks_symlinks_without_opening_their_destination() {
    let staging = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let sentinel = outside.path().join("outside-data");
    std::fs::write(&sentinel, b"preserve unrelated host bytes").unwrap();
    std::fs::create_dir(staging.path().join("nested")).unwrap();
    std::fs::write(staging.path().join("nested/input"), b"owned copied bytes").unwrap();
    std::os::unix::fs::symlink(&sentinel, staging.path().join("foreign-link")).unwrap();
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(staging.path())
        .unwrap();
    assert_eq!(
        root.metadata().unwrap().uid(),
        0,
        "real root-owned fixture required"
    );
    clear_input_tree(&root, Instant::now() + Duration::from_secs(2)).unwrap();
    assert!(std::fs::read_dir(staging.path()).unwrap().next().is_none());
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"preserve unrelated host bytes"
    );
}

#[test]
#[ignore = "requires an installed protected provider and root ownership"]
fn substituted_staging_inode_is_preserved() {
    let _package = super::super::service::acquire_shared_package_lease().unwrap();
    let parent = tempfile::Builder::new()
        .prefix("recovery-inode-test-")
        .tempdir_in(super::super::STATE_ROOT)
        .unwrap();
    let selected = parent.path().join("selected");
    std::fs::create_dir(&selected).unwrap();
    let original = File::open(&selected).unwrap();
    let metadata = original.metadata().unwrap();
    assert_eq!(metadata.uid(), 0, "real root-owned fixture required");
    let identity = DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    std::fs::rename(&selected, parent.path().join("retained-original")).unwrap();
    std::fs::create_dir(&selected).unwrap();
    let sentinel = selected.join("unrelated");
    std::fs::write(&sentinel, b"do not adopt replacement inode").unwrap();
    let error = retire_staging(
        &selected,
        Some(&identity),
        true,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap_err();
    assert!(
        error.contains("native directory identity substitution"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"do not adopt replacement inode"
    );
    assert_eq!(original.metadata().unwrap().ino(), identity.inode);
}
