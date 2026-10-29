use crate::protocol::{
    Frame, MessageKind, PROTOCOL_VERSION, ProtocolError, read_frame, write_frame,
};
use crate::state::{AttemptState, AttemptStateMachine};

fn unsupported_vectors() -> Vec<serde_json::Value> {
    let frame = Frame {
        kind: MessageKind::WorkloadStart,
        nonce: [7; 16],
        attempt_id: [9; 16],
        payload: vec![],
    };
    let mut current = Vec::new();
    write_frame(&mut current, &frame).unwrap();
    assert_eq!(
        crate::protocol::read_frame_version(
            &mut current.as_slice(),
            crate::protocol::WORKLOAD_PROTOCOL_VERSION
        )
        .unwrap(),
        frame
    );
    [0_u16, 1, 255]
        .into_iter()
        .map(|version| {
            let mut bytes = current.clone();
            bytes[..size_of::<u16>()].copy_from_slice(&version.to_be_bytes());
            let error = crate::protocol::read_frame_version(
                &mut bytes.as_slice(),
                crate::protocol::WORKLOAD_PROTOCOL_VERSION,
            )
            .unwrap_err();
            assert_eq!(error, ProtocolError::UnsupportedVersion(version));
            serde_json::json!({"version":version,"frame_bytes":bytes,"error":error.to_string()})
        })
        .collect()
}

#[test]
fn current_unsupported_versions_reject_before_payload_allocation() {
    assert_eq!(unsupported_vectors().len(), 3);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires original native controller stdin, held executable, and owned artifact directory"]
fn unsupported_current_wire_versions_emit_actual_receipt() {
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::PathBuf,
    };
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        run_id: String,
        recipe_id: String,
        native_target: String,
        artifact_root: PathBuf,
        artifact_prefix: String,
        challenge: Vec<u8>,
        work_deadline_unix_millis: u64,
        cleanup_deadline_unix_millis: u64,
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 65536);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).unwrap();
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    let now = || {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    };
    assert!(
        !input.run_id.is_empty()
            && !input.recipe_id.is_empty()
            && !input.artifact_prefix.is_empty()
    );
    assert_eq!(input.challenge.len(), 32);
    assert!(input.artifact_root.is_absolute());
    assert!(
        std::path::Path::new(&input.artifact_prefix)
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    );
    assert!(
        now() < input.work_deadline_unix_millis
            && input.work_deadline_unix_millis < input.cleanup_deadline_unix_millis
    );
    let target = if cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-gnu"
    } else {
        panic!("unsupported native target")
    };
    assert_eq!(input.native_target, target);
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&input.artifact_root)
        .unwrap();
    let metadata = directory.metadata().unwrap();
    assert!(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0);
    let executable = File::open(std::env::current_exe().unwrap()).unwrap();
    let before = executable.metadata().unwrap();
    assert!(
        before.is_file()
            && before.len() <= 512 * 1024 * 1024
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
    );
    let mut image = Vec::new();
    (&executable)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut image)
        .unwrap();
    assert_eq!(image.len() as u64, before.len());
    let after = executable.metadata().unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec()
        )
    );
    let sha = |value: &[u8]| {
        String::from(memcordon_core::DiagnosticSha256::from_bytes(
            Sha256::digest(value).into(),
        ))
    };
    let observations = unsupported_vectors();
    assert!(now() < input.work_deadline_unix_millis);
    let receipt = serde_json::json!({"format":"memcordon.linux-current-wire-version","revision":1,"run_id":input.run_id,"recipe_id":input.recipe_id,"test_name":"protocol_tests::unsupported_current_wire_versions_emit_actual_receipt","native_target":target,"artifact_prefix":input.artifact_prefix,"challenge_sha256":sha(&input.challenge),"executable_sha256":sha(&image),"rejected_versions":[0,1,255],"observations":observations});
    // SAFETY: held protected directory and fixed no-follow exclusive relative filename.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"current-wire-version.receipt.json".as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_WRONLY,
            0o600,
        )
    };
    assert!(raw >= 0, "{}", std::io::Error::last_os_error());
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(&serde_json::to_vec_pretty(&receipt).unwrap())
        .unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
    directory.sync_all().unwrap();
}

#[test]
fn frame_round_trips_native_counted_payload() {
    let expected = Frame {
        kind: MessageKind::Launch,
        nonce: [7; 16],
        attempt_id: [9; 16],
        payload: vec![0, 1, 2, 255],
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &expected).unwrap();
    assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), expected);
}

#[test]
fn unknown_version_is_rejected_before_payload_allocation() {
    let mut bytes = vec![0, PROTOCOL_VERSION as u8 + 1];
    bytes.extend_from_slice(&[0; 70]);
    assert!(matches!(
        read_frame(&mut bytes.as_slice()),
        Err(ProtocolError::UnsupportedVersion(_))
    ));
}

#[test]
fn payload_corruption_is_rejected() {
    let frame = Frame {
        kind: MessageKind::Probe,
        nonce: [1; 16],
        attempt_id: [0; 16],
        payload: vec![1, 2, 3],
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &frame).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(
        read_frame(&mut bytes.as_slice()),
        Err(ProtocolError::PayloadDigestMismatch)
    );
}

#[test]
fn retirement_cannot_skip_empty_proof() {
    let mut machine = AttemptStateMachine::default();
    assert!(machine.transition(AttemptState::Retired).is_err());
}

#[test]
fn every_resource_owning_preauthorization_state_can_enter_cleanup() {
    let setup_path = [
        AttemptState::BoundaryCreated,
        AttemptState::GuardianReady,
        AttemptState::TargetCreatedGated,
        AttemptState::AssignmentVerified,
        AttemptState::ResourceInheritanceVerified,
        AttemptState::Authorized,
    ];
    for failure_state in setup_path {
        let mut machine = AttemptStateMachine::default();
        for state in setup_path {
            machine.transition(state).unwrap();
            if state == failure_state {
                break;
            }
        }
        machine.transition(AttemptState::Terminating).unwrap();
        machine.transition(AttemptState::Empty).unwrap();
        machine.transition(AttemptState::Retired).unwrap();
    }
}
