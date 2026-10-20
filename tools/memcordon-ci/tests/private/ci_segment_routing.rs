use super::*;

#[test]
fn manual_collection_reaches_fixed_and_adaptive_work_and_keeps_failures() {
    let requested = event_mode_bytes(
        "workflow_dispatch",
        br#"{"inputs":{"failure-mode":"collect-all"}}"#,
    )
    .unwrap();
    for suite in [
        Suite::StressPackages,
        Suite::StressLifecycle,
        Suite::Stress,
        Suite::Policy,
        Suite::MacosDeadline,
        Suite::MiriFirst,
        Suite::FuzzFirst,
        Suite::QualityCompiler,
        Suite::Native,
    ] {
        let reached = std::cell::Cell::new(0);
        let result = dispatch(suite, requested, |mode| {
            crate::suites::run_with(
                suite,
                crate::suites::SuiteOptions { failure_mode: mode },
                |options| {
                    reached.set(reached.get() + 1);
                    let expected = if matches!(
                        suite,
                        Suite::StressPackages
                            | Suite::StressLifecycle
                            | Suite::Stress
                            | Suite::Policy
                            | Suite::MacosDeadline
                    ) {
                        FailureMode::StopAfterFailure
                    } else {
                        FailureMode::CollectAll
                    };
                    assert_eq!(options.failure_mode, expected);
                    Err(CiError::Message("actual selected work failed".into()))
                },
            )
        });
        assert_eq!(reached.get(), 1, "{suite:?}");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("actual selected work failed")
        );
    }
}

#[test]
fn event_decoder_preserves_non_dispatch_defaults_and_rejects_bad_requests() {
    assert_eq!(
        event_mode_bytes("push", b"invalid JSON").unwrap(),
        FailureMode::StopAfterFailure
    );
    assert_eq!(
        event_mode_bytes("workflow_dispatch", b"{}").unwrap(),
        FailureMode::StopAfterFailure
    );
    assert!(
        event_mode_bytes(
            "workflow_dispatch",
            br#"{"inputs":{"failure-mode":"skip"}}"#
        )
        .is_err()
    );
    assert!(event_mode_bytes("workflow_dispatch", &vec![b' '; 1024 * 1024 + 1]).is_err());
}
