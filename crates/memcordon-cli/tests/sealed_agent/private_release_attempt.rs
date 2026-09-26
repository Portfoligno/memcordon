#![cfg(target_os = "linux")]

use crate::linux::private_attempt::{PrivateAttemptPhase, ProcessIdentityV4};
use crate::linux::private_lifecycle::PrivateNativeJournal;
use crate::linux::private_release_attempt::ReadbackRetiredCandidateAttemptV1;
use crate::linux::private_release_attempt::{allocate_for_test, commit_checkpoint_for_test};
use memcordon_core::DiagnosticSha256;
use std::fs::File;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;

#[test]
fn candidate_release_attempt_has_own_durable_phase_domain() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let mut journal =
        allocate_for_test(directory, "private_tcp::native_tcp_bind_listen_connect").unwrap();
    assert_eq!(journal.phase(), PrivateAttemptPhase::Allocated);
    assert!(journal.execution_observed().is_err());
    journal.freeze().unwrap();
    journal.boundary_created().unwrap();
    journal
        .guardian_ready(ProcessIdentityV4 {
            pid: 124,
            start_time: 457,
        })
        .unwrap();
    journal
        .target_gated(
            ProcessIdentityV4 {
                pid: 125,
                start_time: 458,
            },
            ProcessIdentityV4 {
                pid: 126,
                start_time: 459,
            },
            12,
        )
        .unwrap();
    journal.read_back_native().unwrap();
    assert_eq!(journal.phase(), PrivateAttemptPhase::TargetGated);
    assert!(!journal.possibly_released());
    assert!(journal.execution_observed().is_err());
    assert!(
        allocate_for_test(
            File::open(root.path()).unwrap(),
            "private_tcp::native_tcp_bind_listen_connect"
        )
        .is_err()
    );
}

#[test]
fn checkpoint_gate_reader_requires_the_durable_unsent_release_intent() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = allocate_for_test(
        File::open(root.path()).unwrap(),
        crate::linux::private_release_case::CHECKPOINT_GATE_SELECTOR,
    )
    .unwrap();
    let key = memcordon_core::workload_codec::hash_bytes(b"candidate release attempt test key");
    let challenge = [0x5a; 32];
    let epoch = memcordon_core::workload_codec::hash_bytes(b"candidate release attempt test epoch");
    let manifest = memcordon_core::workload_codec::hash_bytes(b"candidate release attempt test M0");
    let service =
        memcordon_core::workload_codec::hash_bytes(b"candidate release attempt test service");
    let coordinator = ProcessIdentityV4 {
        pid: 123,
        start_time: 456,
    };
    let expected = crate::linux::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
        result_key: &key,
        selector: crate::linux::private_release_case::CHECKPOINT_GATE_SELECTOR,
        challenge: &challenge,
        installation_epoch: &epoch,
        candidate_manifest_sha256: &manifest,
        service_generation_sha256: &service,
        coordinator: &coordinator,
    };
    assert!(
        crate::linux::private_release_attempt::read_checkpoint_gate_candidate_journal(
            &File::open(root.path()).unwrap(),
            &expected,
        )
        .is_err()
    );
    journal.freeze().unwrap();
    journal.boundary_created().unwrap();
    journal
        .guardian_ready(ProcessIdentityV4 {
            pid: 124,
            start_time: 457,
        })
        .unwrap();
    journal
        .target_gated(
            ProcessIdentityV4 {
                pid: 125,
                start_time: 458,
            },
            ProcessIdentityV4 {
                pid: 126,
                start_time: 459,
            },
            12,
        )
        .unwrap();
    let digest = commit_checkpoint_for_test(&mut journal).unwrap();
    let gate = crate::linux::private_release_attempt::read_checkpoint_gate_candidate_journal(
        &File::open(root.path()).unwrap(),
        &expected,
    )
    .unwrap();
    assert_eq!(gate.checkpoint_digest, digest);
    assert_eq!(gate.target.pid, 126);
    assert!(
        crate::linux::private_release_attempt::parse_checkpoint_gate_candidate_journal_bytes(
            b"{}", &expected,
        )
        .is_err()
    );
}

#[test]
fn frontend_loss_candidate_journal_binds_a_distinct_proxy_before_release() {
    let root = tempfile::tempdir().unwrap();
    let frontend = ProcessIdentityV4 {
        pid: 321,
        start_time: 654,
    };
    let journal = crate::linux::private_release_attempt::allocate_frontend_loss_for_test(
        File::open(root.path()).unwrap(),
        frontend.clone(),
    )
    .unwrap();
    assert_eq!(journal.frontend(), &frontend);
    journal.read_back_native().unwrap();
    assert!(
        crate::linux::private_release_attempt::allocate_for_test(
            File::open(root.path()).unwrap(),
            crate::linux::private_release_frontend_loss::SELECTOR,
        )
        .is_err()
    );

    let other = tempfile::tempdir().unwrap();
    assert!(
        crate::linux::private_release_attempt::allocate_frontend_loss_for_test(
            File::open(other.path()).unwrap(),
            ProcessIdentityV4 {
                pid: 123,
                start_time: 456,
            },
        )
        .is_err()
    );
}

#[test]
fn candidate_release_attempt_rejects_tampered_readback() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let journal =
        allocate_for_test(directory, "private_tcp::native_tcp_bind_listen_connect").unwrap();
    std::fs::write(root.path().join("attempt.json"), b"{}").unwrap();
    assert!(journal.read_back_native().is_err());
}

#[test]
fn candidate_release_attempt_cannot_claim_release_without_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let journal =
        allocate_for_test(directory, "private_tcp::native_tcp_bind_listen_connect").unwrap();
    let path = root.path().join("attempt.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["phase"] = serde_json::Value::String("release-intent".into());
    record["release_knowledge"] = serde_json::Value::String("possibly-released".into());
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(journal.read_back_native().is_err());
}

#[test]
fn detached_native_identity_projection_rejects_unverified_terminal_bytes() {
    let purported = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: "ab".repeat(16),
        checkpoint_digest: DiagnosticSha256::from_bytes([1; 32]),
        terminal_record_digest: DiagnosticSha256::from_bytes([2; 32]),
        terminal_bytes: b"{}".to_vec(),
    };
    assert!(purported.native_identities().is_err());
}

#[test]
fn release_intent_fault_attempt_returns_epipe_without_releasing_target() {
    let (control, mut target) = UnixStream::pair().unwrap();
    // SAFETY: into_raw_fd transfers the unique socket ownership to File.
    let mut control = unsafe { File::from_raw_fd(control.into_raw_fd()) };
    let digest = memcordon_core::workload_codec::hash_bytes(b"durable fault checkpoint");
    let permit = crate::linux::private_release_attempt::permit_for_transport_fault_test(
        "fixed-attempt".into(),
        digest.clone(),
    );
    assert_eq!(
        permit
            .force_transport_loss(&mut control, "fixed-attempt", &digest)
            .unwrap(),
        libc::EPIPE
    );
    let mut byte = [0_u8; 1];
    use std::io::Read;
    assert_eq!(target.read(&mut byte).unwrap(), 0);
}

#[test]
fn uncertain_retirement_rejects_missing_physical_settlement_without_reverting_release_intent() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = allocate_for_test(
        File::open(root.path()).unwrap(),
        "private_tcp::authorization_uncertainty_retired",
    )
    .unwrap();
    journal.freeze().unwrap();
    journal.boundary_created().unwrap();
    journal
        .guardian_ready(ProcessIdentityV4 {
            pid: 124,
            start_time: 457,
        })
        .unwrap();
    journal
        .target_gated(
            ProcessIdentityV4 {
                pid: 125,
                start_time: 458,
            },
            ProcessIdentityV4 {
                pid: 126,
                start_time: 459,
            },
            12,
        )
        .unwrap();
    commit_checkpoint_for_test(&mut journal).unwrap();
    assert!(journal.possibly_released());
    assert_eq!(journal.phase(), PrivateAttemptPhase::ReleaseIntent);
    journal.retiring().unwrap();
    let result = journal.retired_after_uncertain_cleanup(
        crate::linux::private_release_attempt::UncertainCandidateSettlementFactsV1 {
            schema_version: 1,
            transport_errno: libc::EPIPE,
            containment_removed: false,
            target_pidfd_exited: false,
            namespace_init_reaped: false,
            guardian_terminal: [0; 20],
            candidate_exit_code: None,
            cgroup_retirement_raw: None,
        },
    );
    assert!(result.is_err());
    assert!(journal.possibly_released());
    assert_eq!(journal.phase(), PrivateAttemptPhase::Retiring);
    journal.read_back_native().unwrap();
}

#[test]
fn injected_retired_transition_collision_blocks_actual_same_key_allocator() {
    let root = tempfile::tempdir().unwrap();
    let selector = "private_tcp::retirement_failure_blocks_reuse";
    let mut journal = allocate_for_test(File::open(root.path()).unwrap(), selector).unwrap();
    journal.freeze().unwrap();
    journal.boundary_created().unwrap();
    journal
        .guardian_ready(ProcessIdentityV4 {
            pid: 124,
            start_time: 457,
        })
        .unwrap();
    journal
        .target_gated(
            ProcessIdentityV4 {
                pid: 125,
                start_time: 458,
            },
            ProcessIdentityV4 {
                pid: 126,
                start_time: 459,
            },
            12,
        )
        .unwrap();
    commit_checkpoint_for_test(&mut journal).unwrap();
    journal.execution_observed().unwrap();
    journal.retiring().unwrap();
    let challenge = [0x5a; 32];
    let key = memcordon_core::workload_codec::hash_bytes(b"candidate release attempt test key");
    let guardian_terminal = crate::linux::private_guardian::GuardianTerminalV4 {
        attempt_id: crate::linux::private_release_attempt::candidate_attempt_bytes(&key),
        trigger: crate::linux::private_guardian::GuardianTriggerV4::Stopped,
        boundary_retired: false,
    }
    .encode();
    let blocked = journal
        .force_retirement_transition_conflict(
            &challenge,
            crate::linux::private_lifecycle::ReleaseCandidateSettlementFactsV1 {
                cgroup_retirement_raw: None,
                schema_version: 1,
                monitor_outcome: crate::linux::private_lifecycle::PrivateMonitorOutcome::Completed,
                cgroup_empty_before_cleanup: true,
                containment_removed: true,
                target_pidfd_exited: true,
                namespace_init_reaped: true,
                guardian_terminal,
                candidate_exit_code: Some(0),
            },
        )
        .unwrap();
    assert_eq!(journal.phase(), PrivateAttemptPhase::Retiring);
    assert!(journal.possibly_released());
    journal.read_back_native().unwrap();
    assert!(
        blocked
            .transition_error
            .starts_with("MCSEALED-PRIVATE-RELEASE: attempt transition blocked:")
    );
    assert!(!blocked.reuse_error.is_empty());
    assert_eq!(blocked.attempt_id.len(), [0_u8; 16].len() * 2);
    assert_eq!(
        std::fs::read(root.path().join("attempt.json.new")).unwrap(),
        blocked.fault_marker_bytes
    );
    assert!(allocate_for_test(File::open(root.path()).unwrap(), selector).is_err());
}

#[test]
fn guardian_loss_journal_rejects_wrong_signal_and_zero_exit() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = allocate_for_test(
        File::open(root.path()).unwrap(),
        crate::linux::private_release_guardian_loss::SELECTOR,
    )
    .unwrap();
    journal.freeze().unwrap();
    journal.boundary_created().unwrap();
    let guardian = ProcessIdentityV4 {
        pid: 124,
        start_time: 457,
    };
    journal.guardian_ready(guardian.clone()).unwrap();
    journal
        .target_gated(
            ProcessIdentityV4 {
                pid: 125,
                start_time: 458,
            },
            ProcessIdentityV4 {
                pid: 126,
                start_time: 459,
            },
            12,
        )
        .unwrap();
    commit_checkpoint_for_test(&mut journal).unwrap();
    journal.execution_observed().unwrap();
    journal.retiring().unwrap();
    let mut facts = crate::linux::private_release_attempt::GuardianLossCandidateSettlementFactsV1 {
        schema_version: 1,
        guardian,
        guardian_signal: libc::SIGTERM,
        containment_removed: true,
        target_pidfd_exited: true,
        namespace_init_reaped: true,
        candidate_exit_code: None,
        cgroup_retirement_raw: None,
    };
    assert!(journal.retired_after_guardian_loss(facts.clone()).is_err());
    facts.guardian_signal = libc::SIGKILL;
    facts.candidate_exit_code = Some(0);
    assert!(journal.retired_after_guardian_loss(facts).is_err());
    assert_eq!(journal.phase(), PrivateAttemptPhase::Retiring);
}
