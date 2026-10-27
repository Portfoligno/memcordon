use super::*;
use std::os::unix::fs::MetadataExt;

const ISOLATED_SOFT_LIMIT: u64 = 1024;

#[test]
fn child_image_observation_preserves_strict_original_capability_admission() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original");
    std::fs::write(&path, b"held identity").unwrap();
    let readonly = File::open(&path).unwrap();
    let expected = Identity::of(&readonly).unwrap();
    assert_eq!(
        Identity::of_observed(&readonly, Some(diagnostic::ImageOperand::Child)).unwrap(),
        expected
    );
    let writable = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let path_only = File::from(
        rustix::fs::open(
            &path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap(),
    );
    for (operand, label) in [
        (diagnostic::ImageOperand::Child, "Child"),
        (diagnostic::ImageOperand::HeldDriver, "HeldDriver"),
    ] {
        for file in [&writable, &path_only] {
            let before = rustix::fs::fcntl_getfl(file).unwrap().bits();
            assert!(Identity::of(file).is_err());
            let error = Identity::of_observed(file, Some(operand)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let text = error.to_string();
            assert!(text.contains(label) && text.contains("is-file=true; is-directory=false"));
            assert!(text.contains(&format!("flags={before}")));
            assert_eq!(rustix::fs::fcntl_getfl(file).unwrap().bits(), before);
        }
    }
}

fn original_clock(deadline: Instant) {
    assert!(
        Instant::now() < deadline,
        "original native fixture cutoff elapsed"
    );
}

fn pool(regular: usize, deadline: Instant) -> Custodians {
    let driver = match option_env!("CARGO_BIN_EXE_memcordon-ci") {
        Some(driver) => driver,
        None => panic!("native integration worker requires its actual qualified Cargo binary"),
    };
    let mut result = Custodians::default();
    result
        .pin_driver(PathBuf::from(driver), File::open(driver).unwrap(), deadline)
        .unwrap();
    let budget = image_custody_fd_budget().unwrap();
    result
        .configure(
            capacity::Plan::new(budget.open_descriptors, regular, 4, 0, budget.soft_limit).unwrap(),
        )
        .unwrap();
    result
}

fn source(root: &Path, ordinal: usize) -> PathBuf {
    root.join(ordinal.to_string())
}

fn create(root: &Path, ordinal: usize, bytes: &[u8]) -> (PathBuf, File) {
    let path = source(root, ordinal);
    std::fs::write(&path, bytes).unwrap();
    let file = File::open(&path).unwrap();
    assert_eq!(file.metadata().unwrap().nlink(), 1);
    (path, file)
}

fn over_frontier_and_original_continuity(work: Instant, cleanup: Instant) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let sources = root.path().join("sources");
    let copies = root.path().join("copies");
    std::fs::create_dir(&sources).unwrap();
    std::fs::create_dir(&copies).unwrap();
    let regular = usize::try_from(ISOLATED_SOFT_LIMIT / 2).unwrap() + 1;
    let mut owners = pool(regular, work);
    let baseline = image_custody_fd_budget().unwrap().open_descriptors;
    let mut witnesses = Vec::new();
    let started = Instant::now();
    for ordinal in 0..regular {
        original_clock(work);
        let (path, original) = create(&sources, ordinal, b"actual source bytes");
        let (witness, lease) = owners
            .admit(Role::AdministrativeFile, &path, original, work, cleanup)
            .unwrap_or_else(|error| panic!("{error}; native-admission ordinal={ordinal}; member=source-original; elapsed-micros={}", started.elapsed().as_micros()));
        drop(lease);
        let copy_path = source(&copies, ordinal);
        std::fs::copy(&path, &copy_path).unwrap();
        let copy = File::open(&copy_path).unwrap();
        assert_ne!(copy.metadata().unwrap().ino(), witness.identity.inode);
        let (copied, lease) = owners
            .admit(Role::AdministrativeFile, &copy_path, copy, work, cleanup)
            .unwrap_or_else(|error| panic!("{error}; native-admission ordinal={ordinal}; member=copied-inode; elapsed-micros={}", started.elapsed().as_micros()));
        drop(lease);
        witnesses.push((witness, copied));
        let completed = witnesses.len() * 2;
        if completed.is_multiple_of(SLOTS) || witnesses.len() == regular {
            eprintln!(
                "native-custody-progress completed={completed}; shards={}; last-shard-slots={:?}; elapsed-micros={}",
                owners.shards.len(),
                owners.shards.last().map(|shard| shard.count),
                started.elapsed().as_micros()
            );
        }
        // Only channels, not per-file descriptors, grow in the coordinator.
        assert!(
            image_custody_fd_budget().unwrap().open_descriptors
                <= baseline + owners.shards.len() * 2 + 8
        );
    }
    assert!(owners.owner_count() > ISOLATED_SOFT_LIMIT as usize);
    assert_eq!(owners.shards.len(), (regular * 2).div_ceil(SLOTS));
    for shard in &owners.shards {
        assert!(shard.count <= SLOTS);
        let directory = Path::new("/proc")
            .join(shard.child.id().to_string())
            .join("fd");
        let count = std::fs::read_dir(directory).unwrap().count();
        assert!(
            count <= SLOTS + 16,
            "native shard exceeded its fixed slot/stdio/channel allowance"
        );
    }
    let first = &witnesses[0].0;
    let mut lease = owners.borrow(first, work).unwrap();
    let metadata = lease.metadata().unwrap();
    assert_eq!(
        (metadata.dev(), metadata.ino()),
        (first.identity.device, first.identity.inode)
    );
    use std::io::Seek;
    lease.seek(std::io::SeekFrom::Start(3)).unwrap();
    let second = owners.borrow(first, work).unwrap();
    let mut bytes = [0; 6];
    second.read_at(&mut bytes, 0).unwrap();
    assert_eq!(&bytes, b"actual");
    assert_eq!(lease.stream_position().unwrap(), 3);
    drop(second);
    drop(lease);
    // Observe a same-inode edit freshly, with no cached content/length proof.
    std::fs::write(&first.path, b"changed original bytes").unwrap();
    let edited = owners.borrow(first, work).unwrap();
    // Shared-description offsets are intentionally not used for real hashing.
    let mut positional = vec![0; edited.metadata().unwrap().len() as usize];
    assert_eq!(
        edited.read_at(&mut positional, 0).unwrap(),
        positional.len()
    );
    assert_eq!(positional, b"changed original bytes");
    drop(edited);
    let replacement = first.path.with_extension("replacement");
    std::fs::write(&replacement, b"changed original bytes").unwrap();
    std::fs::rename(replacement, &first.path).unwrap();
    let original = owners.borrow(first, work).unwrap();
    assert_eq!(original.metadata().unwrap().ino(), first.identity.inode);
    assert_eq!(original.metadata().unwrap().nlink(), 0);
    drop(original);
    let (source_witness, _) = &witnesses[0];
    assert!(
        owners
            .admit(
                Role::AdministrativeFile,
                &source_witness.path,
                File::open(&source_witness.path).unwrap(),
                work,
                cleanup
            )
            .is_err()
    );
    assert_eq!(owners.failed_originals.len(), 1);
    assert!(
        owners.finish(cleanup).is_ok(),
        "failed qualification does not waive native settlement"
    );
    assert!(owners.shards.iter().all(|shard| shard.retired));
}

fn acknowledged_binding_loss_keeps_sender(work: Instant, cleanup: Instant) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut owners = pool(2, work);
    let (path, file) = create(root.path(), 0, b"first");
    let (_, lease) = owners
        .admit(Role::AdministrativeFile, &path, file, work, cleanup)
        .unwrap();
    drop(lease);
    let (pending_path, pending) = create(root.path(), 1, b"unacknowledged original");
    let pending_identity = Identity::of(&pending).unwrap();
    let shard = &mut owners.shards[0];
    let binding = shard
        .next(
            shard.count,
            Role::AdministrativeFile,
            &pending_path,
            pending_identity,
        )
        .unwrap();
    // The real child owns this original, but its ACK is deliberately not
    // consumed/committed by the coordinator. No local sender owner is dropped.
    shard
        .socket
        .send(
            &encode(&Frame::Admit { binding }).unwrap(),
            Some(&pending),
            work,
        )
        .unwrap();
    assert!(
        owners
            .admit(
                Role::AdministrativeFile,
                &pending_path,
                pending,
                work,
                cleanup
            )
            .is_err()
    );
    assert_eq!(owners.failed_originals.len(), 1);
    assert_eq!(
        Identity::of(&owners.failed_originals[0]).unwrap(),
        pending_identity
    );
    assert!(owners.finish(cleanup).is_err());
    assert!(owners.shards.iter().all(|shard| shard.retired));
    let first_error = owners.finish(cleanup).unwrap_err().to_string();
    assert_eq!(owners.finish(cleanup).unwrap_err().to_string(), first_error);
}

fn first_child_failure_does_not_skip_later_retirement(work: Instant, cleanup: Instant) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut owners = pool(SLOTS + 1, work);
    for ordinal in 0..=SLOTS {
        let (path, file) = create(root.path(), ordinal, b"owned");
        let (_, lease) = owners
            .admit(Role::AdministrativeFile, &path, file, work, cleanup)
            .unwrap();
        drop(lease);
    }
    assert_eq!(owners.shards.len(), 2);
    owners.shards[0].child.kill().unwrap();
    assert!(owners.finish(cleanup).is_err());
    assert!(owners.shards.iter().all(|shard| shard.retired));
    assert!(
        owners.shards[1]
            .child
            .try_wait()
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(owners.finish(cleanup).is_err());
}

fn role_and_directory_originals_are_not_refreshed(work: Instant, cleanup: Instant) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let directory = root.path().join("directory");
    std::fs::create_dir(&directory).unwrap();
    let mut owners = pool(1, work);
    let (original, lease) = owners
        .admit(
            Role::AdministrativeDirectory,
            &directory,
            File::open(&directory).unwrap(),
            work,
            cleanup,
        )
        .unwrap();
    drop(lease);
    let (evidence, lease) = owners
        .admit(
            Role::EvidenceDirectory,
            &directory,
            File::open(&directory).unwrap(),
            work,
            cleanup,
        )
        .unwrap();
    drop(lease);
    assert_ne!(original.slot, evidence.slot);
    let moved = directory.with_extension("retained");
    std::fs::rename(&directory, &moved).unwrap();
    std::fs::create_dir(&directory).unwrap();
    let held = owners.borrow(&original, work).unwrap();
    assert_eq!(held.metadata().unwrap().ino(), original.identity.inode);
    assert_ne!(
        held.metadata().unwrap().ino(),
        std::fs::metadata(&directory).unwrap().ino()
    );
    drop(held);
    let (path, file) = create(root.path(), 0, b"not a directory");
    let before = owners.owner_count();
    assert!(
        owners
            .admit(Role::EvidenceDirectory, &path, file, work, cleanup)
            .is_err()
    );
    assert_eq!(owners.owner_count(), before);
    assert_eq!(owners.failed_originals.len(), 1);
    assert!(owners.finish(cleanup).is_ok());
}

fn expired_finish_stays_failed_with_test_owned_retirement(work: Instant, cleanup: Instant) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut owners = pool(1, work);
    let (path, file) = create(root.path(), 0, b"owned");
    let (_, lease) = owners
        .admit(Role::AdministrativeFile, &path, file, work, cleanup)
        .unwrap();
    drop(lease);
    assert!(owners.finish(Instant::now()).is_err());
    // The fixture, not a renewed production allowance, retains every actual
    // Child until its forced native retirement is observed. Never poison the
    // parent test runner with a detached process or fabricate a successful ACK.
    for shard in &mut owners.shards {
        while !shard.retired {
            original_clock(cleanup);
            if shard.child.try_wait().unwrap().is_some() {
                shard.retired = true;
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    assert!(owners.finish(cleanup).is_err());
}

fn expired_admission_retains_sender_without_starting_child(work: Instant, cleanup: Instant) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut owners = pool(1, work);
    let (path, file) = create(root.path(), 0, b"unreleased sender");
    let identity = Identity::of(&file).unwrap();
    assert!(
        owners
            .admit(
                Role::AdministrativeFile,
                &path,
                file,
                Instant::now(),
                cleanup
            )
            .is_err()
    );
    assert!(owners.shards.is_empty());
    assert_eq!(owners.failed_originals.len(), 1);
    assert_eq!(Identity::of(&owners.failed_originals[0]).unwrap(), identity);
    assert!(owners.finish(cleanup).is_ok());
}

#[test]
#[ignore = "executed by the owned external integration parent with a qualified driver"]
fn isolated_contract_worker() {
    let socket = ImageCustodySocket::take_stdin().unwrap();
    let peer = ImageCustodyPeer {
        pid: memcordon_platform::test_support::image_custody_parent_pid().unwrap(),
        ..image_custody_current_peer().unwrap()
    };
    let startup = Instant::now() + Duration::from_secs(10);
    let packet = socket.receive(peer, startup).unwrap();
    assert!(packet.descriptor.is_none());
    let encoded: [u8; std::mem::size_of::<u64>()] = packet.bytes.try_into().unwrap();
    let cleanup = image_custody_deadline(u64::from_le_bytes(encoded)).unwrap();
    let work = cleanup.checked_sub(Duration::from_secs(5)).unwrap();
    let original = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    assert!(
        original
            .current
            .is_none_or(|limit| limit >= ISOLATED_SOFT_LIMIT)
    );
    // Verified safe rustix API; ONLY this isolated test worker is narrowed.
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(ISOLATED_SOFT_LIMIT),
            maximum: original.maximum,
        },
    )
    .unwrap();
    assert_eq!(
        image_custody_fd_budget().unwrap().soft_limit,
        ISOLATED_SOFT_LIMIT
    );
    over_frontier_and_original_continuity(work, cleanup);
    acknowledged_binding_loss_keeps_sender(work, cleanup);
    first_child_failure_does_not_skip_later_retirement(work, cleanup);
    role_and_directory_originals_are_not_refreshed(work, cleanup);
    expired_finish_stays_failed_with_test_owned_retirement(work, cleanup);
    expired_admission_retains_sender_without_starting_child(work, cleanup);
    socket
        .send(b"all-native-custody-checks-retired", None, cleanup)
        .unwrap();
}
