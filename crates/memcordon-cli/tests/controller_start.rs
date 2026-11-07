#[path = "../src/bin/consumer_readiness_windows/controller_start.rs"]
mod start;
use start::{Binding, Receiver};
use std::io::{self, Cursor, Read, Write};

fn binding() -> Binding {
    Binding {
        challenge: vec![0, 0xff, b'R', 17],
        descriptor_sha256: start::descriptor_digest(b"{\"case\":\"envelope\"}\n"),
        pid: 9001,
        birth: 134_379_920_909_214_884,
    }
}
fn frame(binding: &Binding) -> Vec<u8> {
    let mut bytes = Vec::new();
    start::send(&mut bytes, binding, || Ok(())).unwrap();
    bytes
}

fn registry() -> start::Capability {
    start::Capability {
        version: 1,
        handle: 0x320,
        manifest_sha256: start::descriptor_digest(b"captured native registry input"),
    }
}

fn directories(
    input_count: u32,
    output_count: u32,
) -> (start::DirectoryExpectation, start::DirectoryTransfer) {
    let expected = start::DirectoryExpectation {
        local_role: start::DirectoryRole::LocalDirectory,
        manifest_sha256: [17; 32],
        input_count,
        output_count,
    };
    let transfer = start::DirectoryTransfer {
        version: 1,
        manifest_sha256: expected.manifest_sha256,
        references: expected
            .roles()
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(slot, (role, index))| start::DirectoryReference {
                role,
                index,
                handle: 0x1000 + slot as u64 * 4,
                access_mask: 128,
            })
            .collect(),
    };
    (expected, transfer)
}

#[test]
fn private_start_binds_all129_metadata_references_and_requires_peer_owner_ack_before_release() {
    let mut binding = binding();
    binding.challenge = vec![0xff; start::MAX_CHALLENGE];
    let (expected, directories) = directories(64, 64);
    let registry = registry();
    let peer = start::PeerRecipient {
        handle: 0x400,
        pid: 9002,
        birth: binding.birth + 1,
    };
    let mut sender = start::Sender::with_registry(registry, true)
        .with_directories(directories.clone(), expected.clone())
        .unwrap();
    let mut bytes = Vec::new();
    sender
        .send(&mut bytes, &binding, start::Phase::Start, || Ok(()))
        .unwrap();
    assert_eq!(bytes.len(), start::MAX_FRAME_BYTES);
    assert_eq!(bytes.len(), 6824);
    let first = bytes.len();
    sender
        .send_peer_held(&mut bytes, &binding, &peer, || Ok(()))
        .unwrap();
    let ack = bytes.len();
    sender
        .send(
            &mut bytes,
            &binding,
            start::Phase::ToolchainObserverRelease,
            || Ok(()),
        )
        .unwrap();
    // Later phases carry no directory scalars that the recipient may have closed.
    assert_eq!(bytes.len() - ack, 64 + 44 + binding.challenge.len());
    let frame_extent = bytes.len();
    bytes.extend([0, 255, 17]);
    let mut reader = Cursor::new(bytes);
    let mut receiver =
        start::Receiver::with_directories(registry.manifest_sha256, expected.clone(), true)
            .unwrap();
    assert!(receiver.directory_transfer().is_none());
    receiver.receive(&mut reader, &binding, || Ok(())).unwrap();
    assert_eq!(reader.position(), first as u64);
    assert_eq!(receiver.directory_transfer(), Some(&directories));
    receiver
        .receive_peer_held(&mut reader, &binding, &peer, || Ok(()))
        .unwrap();
    assert_eq!(reader.position(), ack as u64);
    receiver
        .receive_phase(
            &mut reader,
            &binding,
            start::Phase::ToolchainObserverRelease,
            || Ok(()),
        )
        .unwrap();
    assert_eq!(reader.position(), frame_extent as u64);
    let mut application = Vec::new();
    reader.read_to_end(&mut application).unwrap();
    assert_eq!(application, [0, 255, 17]);

    let mut premature = start::Sender::with_registry(registry, true)
        .with_directories(directories, expected)
        .unwrap();
    premature
        .send(&mut Vec::new(), &binding, start::Phase::Start, || Ok(()))
        .unwrap();
    assert!(
        premature
            .send(
                &mut Vec::new(),
                &binding,
                start::Phase::ToolchainObserverRelease,
                || Ok(())
            )
            .is_err()
    );
}

#[test]
fn marker_start5_authenticates_role4_without_directory_downgrade_or_new_frame_capacity() {
    let mut binding = binding();
    binding.challenge = vec![0xff; start::MAX_CHALLENGE];
    let (mut expected, mut metadata) = directories(64, 64);
    let directory_expected = expected.clone();
    expected.local_role = start::DirectoryRole::LocalMarkerFile;
    metadata.version = expected.transfer_version();
    metadata.references[64].role = start::DirectoryRole::LocalMarkerFile;
    let registry = registry();
    assert!(
        start::Sender::with_registry(registry, true)
            .with_directories(metadata.clone(), directory_expected.clone())
            .is_err()
    );
    let mut sender = start::Sender::with_registry(registry, true)
        .with_directories(metadata.clone(), expected.clone())
        .unwrap();
    let mut bytes = Vec::new();
    sender
        .send(&mut bytes, &binding, start::Phase::Start, || Ok(()))
        .unwrap();
    assert_eq!(bytes.len(), start::MAX_FRAME_BYTES);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 5);
    assert_eq!(u32::from_le_bytes(bytes[108..112].try_into().unwrap()), 2);
    let mut receiver =
        Receiver::with_directories(registry.manifest_sha256, expected.clone(), true).unwrap();
    receiver
        .receive(&mut Cursor::new(&bytes), &binding, || Ok(()))
        .unwrap();
    assert_eq!(receiver.directory_transfer(), Some(&metadata));
    let peer = start::PeerRecipient {
        handle: 0x400,
        pid: 9002,
        birth: binding.birth + 1,
    };
    let mut ack = Vec::new();
    sender
        .send_peer_held(&mut ack, &binding, &peer, || Ok(()))
        .unwrap();
    assert_eq!(ack.len(), 64 + 44 + 20 + binding.challenge.len());
    assert_eq!(u32::from_le_bytes(ack[8..12].try_into().unwrap()), 5);
    receiver
        .receive_peer_held(&mut Cursor::new(ack), &binding, &peer, || Ok(()))
        .unwrap();
    let marker = 108 + 40 + 64 * 20;
    for case in 0..6 {
        let mut changed = bytes.clone();
        match case {
            0 => changed[8..12].copy_from_slice(&4u32.to_le_bytes()),
            1 => changed[108..112].copy_from_slice(&1u32.to_le_bytes()),
            2 => changed[marker..marker + 4].copy_from_slice(&2u32.to_le_bytes()),
            3 => changed[116] ^= 1,
            4 => changed[marker + 16..marker + 20].copy_from_slice(&0x100080u32.to_le_bytes()),
            _ => changed[16] ^= 1,
        }
        let mut receiver =
            Receiver::with_directories(registry.manifest_sha256, expected.clone(), true).unwrap();
        assert!(
            receiver
                .receive(&mut Cursor::new(changed), &binding, || Ok(()))
                .is_err(),
            "{case}"
        );
        assert!(receiver.directory_transfer().is_none());
        assert!(receiver.registry_capability().is_none());
    }
    let mut directory_receiver =
        Receiver::with_directories(registry.manifest_sha256, directory_expected, true).unwrap();
    assert!(
        directory_receiver
            .receive(&mut Cursor::new(&bytes), &binding, || Ok(()))
            .is_err()
    );
    for length in [64, 108, marker + 12, bytes.len() - 1] {
        let mut receiver =
            Receiver::with_directories(registry.manifest_sha256, expected.clone(), true).unwrap();
        assert!(
            receiver
                .receive(&mut Cursor::new(&bytes[..length]), &binding, || Ok(()))
                .is_err()
        );
        assert!(receiver.directory_transfer().is_none());
    }
}

#[test]
fn private_frames_never_admit_partial_wrong_rights_roles_manifests_or_cross_owner_scalars() {
    let binding = binding();
    let registry = registry();
    let (expected, directories) = directories(2, 2);
    let mut sender = start::Sender::with_registry(registry, false)
        .with_directories(directories.clone(), expected.clone())
        .unwrap();
    let mut bytes = Vec::new();
    sender
        .send(&mut bytes, &binding, start::Phase::Start, || Ok(()))
        .unwrap();
    for end in 0..bytes.len() {
        let mut receiver =
            start::Receiver::with_directories(registry.manifest_sha256, expected.clone(), false)
                .unwrap();
        assert!(
            receiver
                .receive(&mut Cursor::new(&bytes[..end]), &binding, || Ok(()))
                .is_err()
        );
        assert!(receiver.directory_transfer().is_none());
        assert!(receiver.registry_capability().is_none());
    }
    for case in 0..8 {
        let mut changed = bytes.clone();
        let start = 64 + 44;
        match case {
            0 => changed[8..12].copy_from_slice(&3u32.to_le_bytes()),
            1 => changed[start + 4..start + 8].copy_from_slice(&130u32.to_le_bytes()),
            2 => changed[start + 8] ^= 1,
            3 => changed[start + 40..start + 44].copy_from_slice(&3u32.to_le_bytes()),
            4 => changed[start + 40 + 16..start + 40 + 20]
                .copy_from_slice(&0x100080u32.to_le_bytes()),
            5 => changed[start + 40 + 8..start + 40 + 16]
                .copy_from_slice(&registry.handle.to_le_bytes()),
            6 => changed[start + 40 + 8..start + 40 + 16].copy_from_slice(&u64::MAX.to_le_bytes()),
            _ => {
                *changed.last_mut().unwrap() ^= 1;
            }
        }
        let mut receiver =
            start::Receiver::with_directories(registry.manifest_sha256, expected.clone(), false)
                .unwrap();
        assert!(
            receiver
                .receive(&mut Cursor::new(changed), &binding, || Ok(()))
                .is_err(),
            "case {case}"
        );
        assert!(receiver.directory_transfer().is_none());
    }
}

#[test]
fn held_peer_ack_and_pending_admission_require_exact_original_context_and_child() {
    let binding = binding();
    let registry = registry();
    let (expected, directories) = directories(1, 1);
    let peer = start::PeerRecipient {
        handle: 0x400,
        pid: 9002,
        birth: binding.birth + 1,
    };
    let pending = start::PeerPendingAdmission {
        version: 1,
        binding: start::PeerAdmissionBinding::from_start(&binding),
        recipient: peer,
    };
    pending.validate(&binding).unwrap();
    let mut forged = pending.clone();
    forged.binding.descriptor_sha256[0] ^= 1;
    assert!(forged.validate(&binding).is_err());
    for case in 0..5 {
        let mut sender = start::Sender::with_registry(registry, true)
            .with_directories(directories.clone(), expected.clone())
            .unwrap();
        let mut initial = Vec::new();
        sender
            .send(&mut initial, &binding, start::Phase::Start, || Ok(()))
            .unwrap();
        let mut ack = Vec::new();
        sender
            .send_peer_held(&mut ack, &binding, &peer, || Ok(()))
            .unwrap();
        let mut receiver =
            start::Receiver::with_directories(registry.manifest_sha256, expected.clone(), true)
                .unwrap();
        receiver
            .receive(&mut Cursor::new(initial), &binding, || Ok(()))
            .unwrap();
        let mut wanted = peer;
        match case {
            0 => wanted.handle += 4,
            1 => wanted.pid += 1,
            2 => wanted.birth += 1,
            3 => {
                ack.pop();
            }
            _ => {
                ack[16] ^= 1;
            }
        }
        assert!(
            receiver
                .receive_peer_held(&mut Cursor::new(ack), &binding, &wanted, || Ok(()))
                .is_err()
        );
        assert!(receiver.directory_transfer().is_none());
    }
}

#[test]
fn registry_two_phase_session_binds_one_target_local_key_without_application_read_ahead() {
    let binding = binding();
    let capability = registry();
    let mut sender = start::Sender::with_registry(capability, true);
    let mut bytes = Vec::new();
    sender
        .send(&mut bytes, &binding, start::Phase::Start, || Ok(()))
        .unwrap();
    let first_extent = bytes.len();
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 3);
    sender
        .send(
            &mut bytes,
            &binding,
            start::Phase::ToolchainObserverRelease,
            || Ok(()),
        )
        .unwrap();
    assert!(sender.completed());
    let frame_extent = bytes.len();
    bytes.extend([0, 255, b'R', 128]);
    let mut reader = Split {
        inner: Cursor::new(bytes),
        maximum: 3,
    };
    let mut receiver = Receiver::with_registry(capability.manifest_sha256, true);
    assert!(receiver.registry_capability().is_none());
    receiver.receive(&mut reader, &binding, || Ok(())).unwrap();
    assert_eq!(reader.inner.position(), first_extent as u64);
    assert_eq!(receiver.registry_capability(), Some(&capability));
    receiver
        .receive_phase(
            &mut reader,
            &binding,
            start::Phase::ToolchainObserverRelease,
            || Ok(()),
        )
        .unwrap();
    assert_eq!(reader.inner.position(), frame_extent as u64);
    let mut application = Vec::new();
    reader.read_to_end(&mut application).unwrap();
    assert_eq!(application, [0, 255, b'R', 128]);
    assert!(receiver.receive(&mut reader, &binding, || Ok(())).is_err());
}

#[test]
fn registry_frames_reject_legacy_version_wrong_identity_digest_and_unowned_handle_scalars() {
    let binding = binding();
    let capability = registry();
    let mut bytes = Vec::new();
    start::Sender::with_registry(capability, false)
        .send(&mut bytes, &binding, start::Phase::Start, || Ok(()))
        .unwrap();
    for offset in [8, 32, 48, 52, 64, 76, 108] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        let mut receiver = Receiver::with_registry(capability.manifest_sha256, false);
        assert!(
            receiver
                .receive(&mut Cursor::new(bad), &binding, || Ok(()))
                .is_err(),
            "offset {offset}"
        );
        assert!(receiver.registry_capability().is_none());
        assert!(
            receiver
                .receive(&mut Cursor::new(&bytes), &binding, || Ok(()))
                .is_err()
        );
    }
    // A valid but different scalar is acceptable only in the first bound
    // capability; native handle readback, not its number, checks key contents.
    for handle in [0, u64::MAX, u64::MAX - 1] {
        let mut bad = bytes.clone();
        bad[68..76].copy_from_slice(&handle.to_le_bytes());
        assert!(
            Receiver::with_registry(capability.manifest_sha256, false)
                .receive(&mut Cursor::new(bad), &binding, || Ok(()))
                .is_err()
        );
    }
    assert!(
        Receiver::default()
            .receive(&mut Cursor::new(bytes), &binding, || Ok(()))
            .is_err()
    );
    assert!(
        Receiver::with_registry(capability.manifest_sha256, false)
            .receive(&mut Cursor::new(frame(&binding)), &binding, || Ok(()))
            .is_err()
    );
}

#[test]
fn registry_replay_or_second_phase_capability_substitution_poison_the_original_session() {
    let binding = binding();
    let capability = registry();
    let mut initial = Vec::new();
    let mut original = start::Sender::with_registry(capability, true);
    original
        .send(&mut initial, &binding, start::Phase::Start, || Ok(()))
        .unwrap();
    for changed in [
        start::Capability {
            handle: capability.handle + 4,
            ..capability
        },
        start::Capability {
            manifest_sha256: [9; 32],
            ..capability
        },
    ] {
        let mut receiver = Receiver::with_registry(capability.manifest_sha256, true);
        receiver
            .receive(&mut Cursor::new(&initial), &binding, || Ok(()))
            .unwrap();
        let mut other = start::Sender::with_registry(changed, true);
        let mut discard = Vec::new();
        other
            .send(&mut discard, &binding, start::Phase::Start, || Ok(()))
            .unwrap();
        let mut second = Vec::new();
        other
            .send(
                &mut second,
                &binding,
                start::Phase::ToolchainObserverRelease,
                || Ok(()),
            )
            .unwrap();
        assert!(
            receiver
                .receive_phase(
                    &mut Cursor::new(second),
                    &binding,
                    start::Phase::ToolchainObserverRelease,
                    || Ok(())
                )
                .is_err()
        );
        assert!(receiver.registry_capability().is_none());
    }
    let mut receiver = Receiver::with_registry(capability.manifest_sha256, true);
    receiver
        .receive(&mut Cursor::new(&initial), &binding, || Ok(()))
        .unwrap();
    assert!(
        receiver
            .receive_phase(
                &mut Cursor::new(&initial),
                &binding,
                start::Phase::ToolchainObserverRelease,
                || Ok(())
            )
            .is_err()
    );
}

#[test]
fn partial_registry_capabilities_and_original_cutoff_never_admit_a_key() {
    let binding = binding();
    let capability = registry();
    let mut bytes = Vec::new();
    start::Sender::with_registry(capability, false)
        .send(&mut bytes, &binding, start::Phase::Start, || Ok(()))
        .unwrap();
    for extent in [0, 63, 64, 68, 75, 107, bytes.len() - 1] {
        let mut receiver = Receiver::with_registry(capability.manifest_sha256, false);
        assert_eq!(
            receiver
                .receive(&mut Cursor::new(&bytes[..extent]), &binding, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(receiver.registry_capability().is_none());
    }
    let mut reads = 0;
    let mut reader = Split {
        inner: Cursor::new(bytes),
        maximum: 1,
    };
    let mut receiver = Receiver::with_registry(capability.manifest_sha256, false);
    let error = receiver
        .receive(&mut reader, &binding, || {
            reads += 1;
            if reads > 140 {
                Err(io::Error::new(io::ErrorKind::TimedOut, "original cutoff"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(reader.inner.position() < 108);
    assert!(receiver.registry_capability().is_none());
}
struct Split<R> {
    inner: R,
    maximum: usize,
}
impl<R: Read> Read for Split<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let size = out.len().min(self.maximum);
        self.inner.read(&mut out[..size])
    }
}

#[test]
fn exact_wire_and_split_reads_leave_following_binary_application_bytes_untouched() {
    let binding = binding();
    let bytes = frame(&binding);
    let mut expected = b"MCSTART\0".to_vec();
    expected.extend(2_u32.to_le_bytes());
    expected.extend(4_u32.to_le_bytes());
    expected.extend(binding.descriptor_sha256);
    expected.extend(9001_u32.to_le_bytes());
    expected.extend(134_379_920_909_214_884_u64.to_le_bytes());
    expected.extend(1_u32.to_le_bytes());
    expected.extend([0, 255, b'R', 17]);
    assert_eq!(bytes, expected);
    let application = [0, 255, b'R', b'\n', 128];
    let mut stream = bytes;
    stream.extend(application);
    let mut reader = Split {
        inner: Cursor::new(stream),
        maximum: 3,
    };
    let mut receiver = Receiver::default();
    receiver.receive(&mut reader, &binding, || Ok(())).unwrap();
    assert_eq!(reader.inner.position(), expected.len() as u64);
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, application);
    let position = reader.inner.position();
    assert_eq!(
        receiver
            .receive(&mut reader, &binding, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(reader.inner.position(), position);
    assert_eq!(
        start::descriptor_digest(b""),
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ]
    );
    assert_ne!(
        start::descriptor_digest(b"{\"case\":\"envelope\"}"),
        binding.descriptor_sha256
    );
}

#[test]
fn cross_case_wrong_identity_unknown_version_and_invalid_extents_never_release() {
    let binding = binding();
    let bytes = frame(&binding);
    for offset in [0, 8, 12, 16, 48, 52, 60, 64] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let mut receiver = Receiver::default();
        assert_eq!(
            receiver
                .receive(&mut Cursor::new(changed), &binding, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
            "offset={offset}"
        );
        assert!(
            receiver
                .receive(&mut Cursor::new(&bytes), &binding, || Ok(()))
                .is_err()
        );
    }
    let mut oversized = bytes.clone();
    oversized[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut reader = Cursor::new(oversized);
    assert!(
        Receiver::default()
            .receive(&mut reader, &binding, || Ok(()))
            .is_err()
    );
    assert_eq!(reader.position(), 64);
    for length in 0..bytes.len() {
        assert_eq!(
            Receiver::default()
                .receive(&mut Cursor::new(&bytes[..length]), &binding, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof,
            "length={length}"
        );
    }
    for invalid in [
        Binding {
            pid: 0,
            ..self::binding()
        },
        Binding {
            birth: 0,
            ..self::binding()
        },
        Binding {
            challenge: Vec::new(),
            ..self::binding()
        },
        Binding {
            challenge: vec![0; start::MAX_CHALLENGE + 1],
            ..self::binding()
        },
    ] {
        let mut destination = Vec::new();
        assert_eq!(
            start::send(&mut destination, &invalid, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(destination.is_empty());
    }
}

#[test]
fn exact_io_admission_deadlines_and_original_native_failures_are_retained() {
    let binding = binding();
    let bytes = frame(&binding);
    let mut reader = Cursor::new(&bytes);
    assert_eq!(
        Receiver::default()
            .receive(&mut reader, &binding, || Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original cutoff"
            )))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(reader.position(), 0);
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(109))
        }
    }
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(232))
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("failed writer must not flush")
        }
    }
    assert_eq!(
        Receiver::default()
            .receive(&mut Broken, &binding, || Ok(()))
            .unwrap_err()
            .raw_os_error(),
        Some(109)
    );
    assert_eq!(
        start::send(&mut Broken, &binding, || Ok(()))
            .unwrap_err()
            .raw_os_error(),
        Some(232)
    );
    let mut calls = 0;
    let mut partial = Split {
        inner: Cursor::new(&bytes),
        maximum: 1,
    };
    let result = Receiver::default().receive(&mut partial, &binding, || {
        calls += 1;
        if calls >= 2 {
            Err(io::Error::new(io::ErrorKind::TimedOut, "same cutoff"))
        } else {
            Ok(())
        }
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(partial.inner.position(), 1);
    struct Partial(Vec<u8>);
    impl Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend(&bytes[..bytes.len().min(2)]);
            Ok(bytes.len().min(2))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Partial(Vec::new());
    start::send(&mut output, &binding, || Ok(())).unwrap();
    assert_eq!(output.0, bytes);
}

#[test]
fn interrupted_native_io_retains_its_cause_at_cutoff_and_retries_only_while_live() {
    struct Interrupted<R> {
        inner: R,
        once: bool,
    }
    impl<R: Read> Read for Interrupted<R> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if !std::mem::replace(&mut self.once, true) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    io::Error::from_raw_os_error(995),
                ));
            }
            self.inner.read(bytes)
        }
    }
    let binding = binding();
    let bytes = frame(&binding);
    let mut reader = Interrupted {
        inner: Cursor::new(&bytes),
        once: false,
    };
    let mut checks = 0;
    let error = Receiver::default()
        .receive(&mut reader, &binding, || {
            checks += 1;
            if checks == 1 {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "retained cutoff observation",
                ))
            }
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(reader.inner.position(), 0);
    let primary = error
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(primary.kind(), io::ErrorKind::Interrupted);
    assert_eq!(
        primary
            .get_ref()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(995)
    );
    assert!(error.to_string().contains("retained cutoff observation"));
    let mut reader = Interrupted {
        inner: Cursor::new(&bytes),
        once: false,
    };
    Receiver::default()
        .receive(&mut reader, &binding, || Ok(()))
        .unwrap();
    assert_eq!(reader.inner.position(), bytes.len() as u64);
}

#[test]
fn joint_session_releases_two_distinct_phases_without_reading_following_application_bytes() {
    use start::Phase::{Start, ToolchainObserverRelease};
    let binding = binding();
    let mut sender = start::Sender::joint();
    let mut bytes = Vec::new();
    sender.send(&mut bytes, &binding, Start, || Ok(())).unwrap();
    assert!(!sender.completed());
    let boundary = bytes.len();
    sender
        .send(&mut bytes, &binding, ToolchainObserverRelease, || Ok(()))
        .unwrap();
    assert!(sender.completed());
    let complete = bytes.len();
    assert!(
        sender
            .send(&mut bytes, &binding, ToolchainObserverRelease, || Ok(()))
            .is_err()
    );
    assert_eq!(bytes.len(), complete);
    bytes.extend([0, 255, 128, b'R']);
    let mut reader = Split {
        inner: Cursor::new(bytes),
        maximum: 2,
    };
    let mut session = Receiver::joint();
    session
        .receive_phase(&mut reader, &binding, Start, || Ok(()))
        .unwrap();
    assert_eq!(reader.inner.position(), boundary as u64);
    session
        .receive_phase(&mut reader, &binding, ToolchainObserverRelease, || Ok(()))
        .unwrap();
    assert_eq!(reader.inner.position(), complete as u64);
    assert!(
        session
            .receive_phase(&mut reader, &binding, ToolchainObserverRelease, || Ok(()))
            .is_err()
    );
    assert_eq!(reader.inner.position(), complete as u64);
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, [0, 255, 128, b'R']);
}

#[test]
fn joint_phase_replay_premature_release_binding_changes_and_second_phase_eof_fail_closed() {
    use start::Phase::{Start, ToolchainObserverRelease};
    let binding = binding();
    let first = frame(&binding);
    let mut second = Vec::new();
    start::send_phase(&mut second, &binding, ToolchainObserverRelease, || Ok(())).unwrap();
    let mut premature = Receiver::joint();
    assert!(
        premature
            .receive_phase(&mut Cursor::new(&second), &binding, Start, || Ok(()))
            .is_err()
    );
    assert!(
        premature
            .receive_phase(&mut Cursor::new(&first), &binding, Start, || Ok(()))
            .is_err()
    );
    let mut declared_wrong = Receiver::joint();
    let mut unread = Cursor::new(&first);
    assert!(
        declared_wrong
            .receive_phase(&mut unread, &binding, ToolchainObserverRelease, || Ok(()))
            .is_err()
    );
    assert_eq!(unread.position(), 0);
    for offset in [8, 12, 16, 48, 52, 60, 64] {
        let mut changed = second.clone();
        changed[offset] ^= 1;
        let mut session = Receiver::joint();
        session
            .receive(&mut Cursor::new(&first), &binding, || Ok(()))
            .unwrap();
        assert!(
            session
                .receive_phase(
                    &mut Cursor::new(changed),
                    &binding,
                    ToolchainObserverRelease,
                    || Ok(())
                )
                .is_err(),
            "offset={offset}"
        );
    }
    let mut replay = Receiver::joint();
    replay
        .receive(&mut Cursor::new(&first), &binding, || Ok(()))
        .unwrap();
    assert!(
        replay
            .receive_phase(
                &mut Cursor::new(&first),
                &binding,
                ToolchainObserverRelease,
                || Ok(())
            )
            .is_err()
    );
    for extent in 0..second.len() {
        let mut session = Receiver::joint();
        session
            .receive(&mut Cursor::new(&first), &binding, || Ok(()))
            .unwrap();
        assert_eq!(
            session
                .receive_phase(
                    &mut Cursor::new(&second[..extent]),
                    &binding,
                    ToolchainObserverRelease,
                    || Ok(())
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    let mut session = Receiver::joint();
    session
        .receive(&mut Cursor::new(&first), &binding, || Ok(()))
        .unwrap();
    let mut unread = Cursor::new(&second);
    assert_eq!(
        session
            .receive_phase(&mut unread, &binding, ToolchainObserverRelease, || Err(
                io::Error::new(io::ErrorKind::TimedOut, "same original deadline")
            ))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(unread.position(), 0);
    assert!(
        session
            .receive_phase(&mut unread, &binding, ToolchainObserverRelease, || Ok(()))
            .is_err()
    );
}
