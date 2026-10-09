#![cfg(target_os = "linux")]

use crate::linux::private_attempt::{
    DurablePrivateAttempt, PrivateAttemptPhase, PrivateAttemptRecordV4, ProcessIdentityV4,
    ReleaseKnowledge,
};
use memcordon_core::{BoundedText, DiagnosticSha256};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use tempfile::TempDir;

const IDENTITY: &str = "abababababababababababababababab";

/// Exercise the real durable journal transition barriers in an owned native
/// component directory. No target, account reservation or launch is allocated.
#[test]
#[ignore = "requires an explicitly owned native component receipt directory"]
fn durable_journal_barriers_emit_actual_component_receipts() {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        run_id: String,
        recipe_id: String,
        native_target: String,
        artifact_root: std::path::PathBuf,
        artifact_prefix: String,
        challenge: Vec<u8>,
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 65536);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).unwrap();
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    assert!(!input.run_id.is_empty() && !input.recipe_id.is_empty());
    assert_eq!(input.challenge.len(), 32);
    let native_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        _ => panic!("unsupported native journal target"),
    };
    assert_eq!(input.native_target, native_target);
    assert!(input.artifact_root.is_absolute());
    assert!(
        !input.artifact_prefix.is_empty()
            && input
                .artifact_prefix
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && !input.artifact_prefix.contains(['\\', ':'])
    );
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&input.artifact_root)
        .unwrap();
    let metadata = directory.metadata().unwrap();
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.mode() & 0o022, 0);
    let state = input.artifact_root.join("journal-state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory.sync_all().unwrap();
    let state_directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&state)
        .unwrap();
    let state_identity = state_directory.metadata().unwrap();
    let self_pid = libc::pid_t::try_from(std::process::id()).unwrap();
    // SAFETY: this process's live PID and zero flags are valid pidfd_open arguments.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, self_pid, 0) };
    assert!(raw >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    // SAFETY: successful pidfd_open returns a fresh owned descriptor.
    let self_pidfd = unsafe { OwnedFd::from_raw_fd(i32::try_from(raw).unwrap()) };
    let self_identity = ProcessIdentityV4::observe(self_pid, self_pidfd.as_fd()).unwrap();
    let mut boot = String::new();
    std::fs::File::open("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .take(1025)
        .read_to_string(&mut boot)
        .unwrap();
    assert!(boot.len() <= 1024);
    let attempt = hex(&input.challenge[..16]);
    let record = PrivateAttemptRecordV4::allocated(
        BoundedText::new(attempt.as_str()).unwrap(),
        BoundedText::new(boot.trim()).unwrap(),
        self_identity,
        DiagnosticSha256::from_bytes(Sha256::digest(&bytes).into()),
    )
    .unwrap();
    let mut durable = DurablePrivateAttempt::create_for_test(&state, record.clone()).unwrap();
    let canonical = state.join(&attempt);
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&canonical)
        .unwrap();
    let original_identity = held.metadata().unwrap();
    let before = std::fs::read(&canonical).unwrap();
    assert_eq!(PrivateAttemptRecordV4::parse(&before).unwrap(), record);
    let release_refusal = durable.release_intent_for_component_test().unwrap_err();
    assert_eq!(
        release_refusal,
        "private release requires durable gated observations"
    );
    assert_eq!(std::fs::read(&canonical).unwrap(), before);
    let transaction = canonical.with_extension("new");
    let mut competing = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&transaction)
        .unwrap();
    competing
        .write_all(b"owned competing publication\n")
        .unwrap();
    competing.sync_all().unwrap();
    std::fs::File::open(&state).unwrap().sync_all().unwrap();
    let competing_identity = competing.metadata().unwrap();
    let journal_refusal = durable.boundary_created().unwrap_err();
    assert_eq!(
        journal_refusal,
        std::io::Error::from_raw_os_error(libc::EEXIST).to_string()
    );
    let after = std::fs::read(&canonical).unwrap();
    assert_eq!(after, before);
    assert_eq!(durable.read_back().unwrap(), record);
    let named = std::fs::symlink_metadata(&canonical).unwrap();
    assert_eq!(
        (named.dev(), named.ino()),
        (original_identity.dev(), original_identity.ino())
    );
    let named_competing = std::fs::symlink_metadata(&transaction).unwrap();
    assert_eq!(
        (named_competing.dev(), named_competing.ino()),
        (competing_identity.dev(), competing_identity.ino())
    );
    std::fs::remove_file(&transaction).unwrap();
    assert_eq!(competing.metadata().unwrap().nlink(), 0);
    std::fs::File::open(&state).unwrap().sync_all().unwrap();
    durable.retire_unallocated().unwrap();
    assert!(!canonical.exists());
    std::fs::File::open(&state).unwrap().sync_all().unwrap();
    assert!(std::fs::read_dir(&state).unwrap().next().is_none());
    let named_state = std::fs::symlink_metadata(&state).unwrap();
    assert_eq!(
        (named_state.dev(), named_state.ino()),
        (state_identity.dev(), state_identity.ino())
    );
    std::fs::remove_dir(&state).unwrap();
    assert_eq!(state_directory.metadata().unwrap().nlink(), 0);
    directory.sync_all().unwrap();
    let mut executable = Vec::new();
    std::fs::File::open(std::env::current_exe().unwrap())
        .unwrap()
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut executable)
        .unwrap();
    assert!(executable.len() <= 512 * 1024 * 1024);
    for (name, data) in [
        ("journal-before.bin", before.as_slice()),
        ("journal-after-refusal.bin", after.as_slice()),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(input.artifact_root.join(name))
            .unwrap();
        file.write_all(data).unwrap();
        file.sync_all().unwrap();
    }
    let receipt = serde_json::json!({"format":"memcordon.linux-journal-component","revision":1,"run_id":input.run_id,"recipe_id":input.recipe_id,"test_name":"private_attempt::durable_journal_barriers_emit_actual_component_receipts","native_target":native_target,"executable_sha256":hex(&Sha256::digest(executable)),"challenge_sha256":hex(&Sha256::digest(&input.challenge)),"operation":"durable-preboundary-journal-barriers","attempt_id":attempt,"frontend":record.frontend,"boot_id":record.boot_identity,"record_before":format!("{}/journal-before.bin",input.artifact_prefix),"record_after_refusal":format!("{}/journal-after-refusal.bin",input.artifact_prefix),"canonical_device":original_identity.dev(),"canonical_inode":original_identity.ino(),"canonical_unchanged":true,"release_refusal":release_refusal,"journal_refusal":journal_refusal,"native_publication_errno":libc::EEXIST,"owned_competing_device":competing_identity.dev(),"owned_competing_inode":competing_identity.ino(),"owned_competing_unlinked":competing.metadata().unwrap().nlink()==0,"unallocated_record_retired":!canonical.exists()});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(input.artifact_root.join("journal-native-receipt.json"))
        .unwrap();
    file.write_all(&serde_json::to_vec(&receipt).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    directory.sync_all().unwrap();
}

fn allocated() -> PrivateAttemptRecordV4 {
    PrivateAttemptRecordV4::allocated(
        BoundedText::new(IDENTITY).unwrap(),
        BoundedText::new("boot-1").unwrap(),
        ProcessIdentityV4 {
            pid: 123,
            start_time: 456,
        },
        DiagnosticSha256::from_bytes([7; 32]),
    )
    .unwrap()
}

#[test]
fn native_journal_allocated_record_roundtrips_and_recovery_preserves_it() {
    let state = TempDir::new().unwrap();
    let cgroup = TempDir::new().unwrap();
    let durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    assert_eq!(durable.read_back().unwrap(), allocated());
    let bytes = std::fs::read(state.path().join(IDENTITY)).unwrap();
    assert!(crate::linux::recovery::integrity_valid(
        std::str::from_utf8(&bytes).unwrap()
    ));
    assert!(
        crate::linux::attempt::parse_durable_policy(std::str::from_utf8(&bytes).unwrap()).is_err()
    );
    let ambiguous =
        crate::linux::recovery::recover_test_roots(state.path(), cgroup.path()).unwrap();
    assert_eq!(ambiguous, vec![IDENTITY.to_owned()]);
    assert!(state.path().join(IDENTITY).exists());
}

#[test]
fn v4_parser_rejects_corruption_and_unearned_release_claims() {
    let state = TempDir::new().unwrap();
    let durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    let mut bytes = std::fs::read(state.path().join(IDENTITY)).unwrap();
    let midpoint = bytes.len() / 2;
    bytes[midpoint] ^= 1;
    assert!(PrivateAttemptRecordV4::parse(&bytes).is_err());
    assert!(durable.read_back().is_ok());

    let record = std::fs::read_to_string(state.path().join(IDENTITY)).unwrap();
    let (body, _) = record.rsplit_once("digest=").unwrap();
    let changed = body.replace("\"phase\":\"allocated\"", "\"phase\":\"release-intent\"");
    assert_ne!(changed, body);
    let digest: String = memcordon_core::workload_codec::hash_bytes(changed.as_bytes()).into();
    assert!(
        PrivateAttemptRecordV4::parse(format!("{changed}digest={digest}\n").as_bytes()).is_err()
    );

    let changed = body.replace("\"phase\":\"allocated\"", "\"phase\":\"future-phase\"");
    assert_ne!(changed, body);
    let digest: String = memcordon_core::workload_codec::hash_bytes(changed.as_bytes()).into();
    assert!(
        PrivateAttemptRecordV4::parse(format!("{changed}digest={digest}\n").as_bytes()).is_err()
    );

    let mut forged = allocated();
    forged.phase = PrivateAttemptPhase::ReleaseIntent;
    forged.release_knowledge = ReleaseKnowledge::PossiblyReleased;
    assert!(forged.validate().is_err());
    let mut forged = allocated();
    forged.phase = PrivateAttemptPhase::CleanupIncomplete;
    assert!(forged.validate().is_err());
    let mut forged = allocated();
    forged.frontend.start_time = 0;
    assert!(forged.validate().is_err());
}

#[test]
fn v4_interrupted_transition_remains_ambiguous_and_is_not_deleted() {
    let state = TempDir::new().unwrap();
    let cgroup = TempDir::new().unwrap();
    let _durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    let canonical = state.path().join(IDENTITY);
    let temporary = canonical.with_extension("new");
    std::fs::copy(&canonical, &temporary).unwrap();
    let ambiguous =
        crate::linux::recovery::recover_test_roots(state.path(), cgroup.path()).unwrap();
    assert!(ambiguous.contains(&IDENTITY.to_owned()));
    assert!(ambiguous.contains(&format!("{IDENTITY}.new")));
    assert!(canonical.exists());
    assert!(temporary.exists());
}

#[test]
fn v4_process_identity_requires_the_exact_live_pidfd() {
    let pid = std::process::id() as libc::pid_t;
    // SAFETY: pidfd_open receives this process's live PID and zero flags.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    assert!(raw >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    // SAFETY: a successful pidfd_open returns a fresh owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let identity = ProcessIdentityV4::observe(pid, pidfd.as_fd()).unwrap();
    assert_eq!(identity.pid, pid as u32);
    assert!(ProcessIdentityV4::observe(pid + 1, pidfd.as_fd()).is_err());
}

#[test]
fn v4_early_retirement_is_only_available_before_native_boundary() {
    let state = TempDir::new().unwrap();
    let durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    durable.retire_unallocated().unwrap();
    assert!(!state.path().join(IDENTITY).exists());
    let mut durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    durable.boundary_created().unwrap();
    assert!(durable.retire_unallocated().is_err());
    assert!(state.path().join(IDENTITY).exists());
}

#[test]
fn v4_cleanup_failure_stays_durable_and_blocks_release() {
    let state = TempDir::new().unwrap();
    let mut durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    durable.cleanup_incomplete("native cleanup failed").unwrap();
    let persisted = durable.read_back().unwrap();
    assert_eq!(persisted.phase, PrivateAttemptPhase::CleanupIncomplete);
    assert_eq!(persisted.release_knowledge, ReleaseKnowledge::NotReleased);
    assert!(durable.boundary_created().is_err());
    assert!(state.path().join(IDENTITY).exists());
}
