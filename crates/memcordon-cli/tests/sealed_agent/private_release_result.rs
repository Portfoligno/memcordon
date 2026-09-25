#![cfg(target_os = "linux")]

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAllocatedOutcomeV1, PrivateReleaseAttachmentRoleV1, PrivateReleaseAttachmentV1,
    PrivateReleaseCaseResultV1, PrivateReleaseExecV1, PrivateReleaseInstalledBindingV1,
    PrivateReleaseKnowledgeV1, PrivateReleaseObservationV1,
};

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn diagnostic_result(epoch: u8) -> PrivateReleaseCaseResultV1 {
    PrivateReleaseCaseResultV1 {
        schema_version: 1,
        selector: "private_tcp::native_tcp_bind_listen_connect".into(),
        challenge: "cd".repeat(32),
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
            installation_epoch: digest(epoch),
            candidate_manifest_sha256: digest(2),
            installed_inspection_sha256: digest(3),
        },
        observation: PrivateReleaseObservationV1::AllocatedRetired {
            outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
            attempt_id: "ab".repeat(16),
            checkpoint_sha256: digest(4),
            terminal_sha256: digest(5),
            retirement_sha256: digest(6),
            release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
            exec: PrivateReleaseExecV1::Succeeded,
            native_observer_sha256: digest(7),
        },
        attachments: PrivateReleaseAttachmentRoleV1::ALL
            .into_iter()
            .map(|role| PrivateReleaseAttachmentV1 {
                role,
                size: 1,
                sha256: digest(7),
            })
            .collect(),
    }
}

fn blocked_retirement_result() -> PrivateReleaseCaseResultV1 {
    let mut result = diagnostic_result(1);
    result.selector = "private_tcp::retirement_failure_blocks_reuse".into();
    result.observation = PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
        attempt_id: "ab".repeat(16),
        checkpoint_sha256: digest(4),
        terminal_sha256: digest(5),
        cleanup_failure_sha256: digest(6),
        reuse_rejection_sha256: digest(8),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: digest(7),
    };
    result
}

fn guardian_loss_result() -> PrivateReleaseCaseResultV1 {
    let mut result = diagnostic_result(1);
    result.selector = "private_tcp::guardian_loss_retired".into();
    result.observation = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::GuardianLost,
        attempt_id: "ab".repeat(16),
        checkpoint_sha256: digest(4),
        terminal_sha256: digest(5),
        retirement_sha256: digest(6),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: digest(7),
    };
    result
}

fn frontend_loss_result() -> PrivateReleaseCaseResultV1 {
    let mut result = diagnostic_result(1);
    result.selector = "private_tcp::frontend_loss_retired".into();
    result.observation = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::FrontendLost,
        attempt_id: "ab".repeat(16),
        checkpoint_sha256: digest(4),
        terminal_sha256: digest(5),
        retirement_sha256: digest(6),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: digest(7),
    };
    result
}

#[test]
fn closed_result_storage_is_atomic_idempotent_and_refuses_changed_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::File::open(directory.path()).unwrap();
    let result = diagnostic_result(1);
    let key = result.result_key().unwrap();
    let bytes = serde_json::to_vec(&result).unwrap();
    crate::linux::private_release_result::publish_storage_for_test(&root, &key, &bytes).unwrap();
    let leaf = format!("{}.json", String::from(key.clone()));
    assert_eq!(std::fs::read(directory.path().join(&leaf)).unwrap(), bytes);
    assert!(!directory.path().join(format!("{leaf}.new")).exists());
    crate::linux::private_release_result::publish_storage_for_test(&root, &key, &bytes).unwrap();

    let changed = serde_json::to_vec(&diagnostic_result(9)).unwrap();
    assert!(
        crate::linux::private_release_result::publish_storage_for_test(&root, &key, &changed)
            .is_err()
    );
    assert_eq!(std::fs::read(directory.path().join(&leaf)).unwrap(), bytes);
}

#[test]
fn closed_result_storage_rejects_unparsed_or_wrong_key_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::File::open(directory.path()).unwrap();
    let result = diagnostic_result(1);
    let key = result.result_key().unwrap();
    assert!(
        crate::linux::private_release_result::publish_storage_for_test(&root, &key, b"{}").is_err()
    );
    assert!(
        crate::linux::private_release_result::publish_storage_for_test(
            &root,
            &digest(8),
            &serde_json::to_vec(&result).unwrap(),
        )
        .is_err()
    );
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn blocked_retirement_result_is_distinct_from_retired_success() {
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::File::open(directory.path()).unwrap();
    let blocked = blocked_retirement_result();
    blocked.validate().unwrap();
    let key = blocked.result_key().unwrap();
    let bytes = serde_json::to_vec(&blocked).unwrap();
    crate::linux::private_release_result::publish_storage_for_test(&root, &key, &bytes).unwrap();

    let mut misclassified = blocked;
    misclassified.observation = diagnostic_result(1).observation;
    assert!(misclassified.validate().is_err());
}

#[test]
fn guardian_loss_result_cannot_be_relabelled_as_target_completion() {
    let result = guardian_loss_result();
    result.validate().unwrap();
    let mut misclassified = result;
    misclassified.observation = diagnostic_result(1).observation;
    assert!(misclassified.validate().is_err());
}

#[test]
fn frontend_loss_result_cannot_be_relabelled_as_target_completion() {
    let result = frontend_loss_result();
    result.validate().unwrap();
    let mut misclassified = result;
    misclassified.observation = diagnostic_result(1).observation;
    assert!(misclassified.validate().is_err());
}
