use memcordon_ci::{readiness_identity::SourceIdentity, support_loader_producer::*};

fn source() -> SourceIdentity {
    SourceIdentity {
        run_id: "measured-diagnostic-run".into(),
        source_commit: "ab".repeat(20),
        source_tree_sha256: "cd".repeat(32),
        version: "0.5.8-dev".into(),
    }
}

#[test]
fn installed_selection_clamps_original_lease_and_rejects_expiration_or_bad_identity() {
    let challenge = [7; 32];
    let image = "ab".repeat(32);
    let binding = "cd".repeat(32);
    let selected =
        installed_selection(&challenge, &image, &binding, 1_000, 100_000, 200_000).unwrap();
    assert_eq!(selected.work_deadline_unix_ms, 31_000);
    assert_eq!(selected.cleanup_deadline_unix_ms, 61_000);
    assert_eq!(selected.challenge, hex::encode(challenge));
    assert_eq!(selected.support_bootstrap_sha256, image);
    assert_eq!(selected.producer_deadline_sha256, binding);
    let short = installed_selection(&challenge, &image, &binding, 1_000, 2_000, 3_000).unwrap();
    assert_eq!(
        (short.work_deadline_unix_ms, short.cleanup_deadline_unix_ms),
        (2_000, 3_000)
    );
    for (now, work, cleanup) in [
        (2_000, 2_000, 3_000),
        (3_000, 2_000, 3_000),
        (1_000, 3_000, 2_000),
        (u64::MAX - 1, u64::MAX - 1, u64::MAX),
    ] {
        assert!(installed_selection(&challenge, &image, &binding, now, work, cleanup).is_err());
    }
    for (challenge, image, binding) in [
        (&[0; 32][..], image.as_str(), binding.as_str()),
        (&[7; 31][..], image.as_str(), binding.as_str()),
        (&challenge[..], "invalid", binding.as_str()),
        (&challenge[..], image.as_str(), "invalid"),
    ] {
        assert!(installed_selection(challenge, image, binding, 1_000, 2_000, 3_000).is_err());
    }
}

#[test]
fn separate_operation_cutoffs_never_renew_expired_work_or_cleanup() {
    let deadline = DiagnosticDeadline::at(
        source(),
        "aarch64-pc-windows-msvc".into(),
        "ef".repeat(32),
        1000,
    )
    .unwrap();
    let origin = std::time::Instant::now();
    let (work, cleanup) = deadline.remaining_at(origin, 1000).unwrap();
    assert_eq!(work.duration_since(origin), PREPARATION + BOOTSTRAP_WORK);
    assert_eq!(cleanup.duration_since(work), BOOTSTRAP_CLEANUP);
    assert!(
        deadline
            .remaining_at(origin, deadline.work_deadline_unix_millis)
            .is_err()
    );
    let (expired, remaining) = deadline
        .remaining_cleanup_at(origin, deadline.work_deadline_unix_millis)
        .unwrap();
    assert_eq!(expired, origin);
    assert_eq!(remaining.duration_since(origin), BOOTSTRAP_CLEANUP);
    assert!(
        deadline
            .remaining_cleanup_at(origin, deadline.cleanup_deadline_unix_millis)
            .is_err()
    );
    let mut forged = deadline.clone();
    forged.work_deadline_unix_millis += 1;
    assert!(forged.remaining_at(origin, 1000).is_err());
    assert!(deadline.remaining_at(origin, 999).is_err());
}
