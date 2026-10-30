use memcordon_ci::release::{
    consumer_success::exited_zero, installed_consumer::public_success_retired,
    public_consumer::completed_success_retired,
};
use memcordon_core::{
    ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary, DeadlineEvidence,
    DeadlineScope, Interruption, LimitEvidence, RunOutcome,
};

fn exited(child: ChildTermination) -> RunOutcome {
    RunOutcome::Exited {
        child,
        peak: None,
        cleanup: CleanupSummary {
            direct_child_reaped: true,
            workload_empty: Some(true),
            ..Default::default()
        },
    }
}

#[test]
fn both_native_zero_variants_pass_actual_retirement_guards_without_rewriting_reports() {
    for child in [
        ChildTermination::ExitCode { code: 0 },
        ChildTermination::WindowsStatus { status: 0 },
    ] {
        let outcome = exited(child);
        let original = serde_json::to_value(&outcome).unwrap();
        assert!(exited_zero(Some(&outcome)));
        assert!(public_success_retired(Some(&outcome), Some(0)));
        assert!(completed_success_retired(Some(&outcome), Some(0)));
        assert_eq!(serde_json::to_value(&outcome).unwrap(), original);
    }
    let native =
        serde_json::to_value(exited(ChildTermination::WindowsStatus { status: 0 })).unwrap();
    assert_eq!(native["child"]["kind"], "windows-status");
    assert_eq!(native["child"]["status"], 0);
}

#[test]
fn nonzero_high_bit_signal_and_unavailable_results_cannot_be_child_success() {
    let mut children = vec![
        ChildTermination::ExitCode { code: 1 },
        ChildTermination::ExitCode { code: -1 },
        ChildTermination::UnixSignal { signal: 0 },
        ChildTermination::UnixSignal { signal: 9 },
        ChildTermination::Unavailable,
    ];
    children.extend(
        [1, 259, 0x80000000, 0xc0000022, u32::MAX]
            .map(|status| ChildTermination::WindowsStatus { status }),
    );
    for child in children {
        let outcome = exited(child);
        assert!(!exited_zero(Some(&outcome)));
        assert!(!public_success_retired(Some(&outcome), Some(0)));
        assert!(!completed_success_retired(Some(&outcome), Some(0)));
    }
}

#[test]
fn zero_child_never_bypasses_supervision_wrapper_or_cleanup_requirements() {
    assert!(!exited_zero(None));
    assert!(!public_success_retired(None, Some(0)));
    assert!(!completed_success_retired(None, Some(0)));
    for child in [
        ChildTermination::ExitCode { code: 0 },
        ChildTermination::WindowsStatus { status: 0 },
    ] {
        let outcome = exited(child.clone());
        for wrapper in [None, Some(1), Some(-1), Some(123)] {
            assert!(!public_success_retired(Some(&outcome), wrapper));
            assert!(!completed_success_retired(Some(&outcome), wrapper));
        }
        for failure in 0..3 {
            let mut outcome = exited(child.clone());
            match failure {
                0 => outcome.cleanup_mut().direct_child_reaped = false,
                1 => outcome.cleanup_mut().errors.push(CleanupErrorRecord {
                    operation: "wait".into(),
                    message: "owned child retirement failed".into(),
                }),
                _ => outcome.cleanup_mut().workload_empty = Some(false),
            }
            assert!(exited_zero(Some(&outcome))); // Child status alone is insufficient.
            assert!(!public_success_retired(Some(&outcome), Some(0)));
            assert!(!completed_success_retired(Some(&outcome), Some(0)));
        }
        let mut unknown = exited(child);
        unknown.cleanup_mut().workload_empty = None;
        assert!(public_success_retired(Some(&unknown), Some(0)));
        assert!(!completed_success_retired(Some(&unknown), Some(0)));
    }
}

#[test]
fn every_non_exited_outcome_rejects_even_with_zero_post_termination_status() {
    let cleanup = exited(ChildTermination::ExitCode { code: 0 })
        .cleanup()
        .clone();
    let child = Some(ChildTermination::WindowsStatus { status: 0 });
    let outcomes = [
        RunOutcome::DeadlineExceeded {
            deadline: DeadlineEvidence::new(
                1000,
                DeadlineScope::Attempt,
                "ordinary consumer deadline".into(),
                1000,
                1001,
                0,
                0,
                None,
                Some("terminate".into()),
            )
            .unwrap(),
            child_after_termination: child.clone(),
            peak: None,
            cleanup: cleanup.clone(),
        },
        RunOutcome::LimitExceeded {
            limit: ByteSize::from_bytes(1024),
            observed: Some(ByteSize::from_bytes(2048)),
            peak: None,
            evidence: LimitEvidence {
                backend: "standard".into(),
                metric: "memory".into(),
                detail: "observed limit exceeded".into(),
            },
            child_after_termination: child.clone(),
            cleanup: cleanup.clone(),
        },
        RunOutcome::Interrupted {
            signal: Interruption { signal: 9 },
            child_after_termination: child.clone(),
            cleanup: cleanup.clone(),
        },
        RunOutcome::MonitorFailed {
            error: "monitor observation failed".into(),
            child_after_termination: child,
            cleanup,
        },
    ];
    for outcome in outcomes {
        assert!(!exited_zero(Some(&outcome)));
        assert!(!public_success_retired(Some(&outcome), Some(0)));
        assert!(!completed_success_retired(Some(&outcome), Some(0)));
    }
}
