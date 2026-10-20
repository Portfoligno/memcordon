use clap::ValueEnum;
use memcordon_ci::{
    failure_mode::FailureMode,
    suite::{ModeRequest, Suite, SuiteFailurePolicy},
};

#[test]
fn workflow_collection_executes_fixed_suites_with_supported_mode() {
    let mut fixed = 0;
    let mut adaptive = 0;
    let expected_fixed = [
        Suite::WorkspaceFetch,
        Suite::FuzzFetch,
        Suite::PrepareMiriComponents,
        Suite::MiriSetup,
        Suite::WorkingWindowsPrepare,
        Suite::RehearsalToolBuild,
        Suite::Policy,
        Suite::Stress,
        Suite::StressPackages,
        Suite::StressLifecycle,
        Suite::BackendLinuxCgroup,
        Suite::BackendLinuxPrivate,
        Suite::BackendLinuxPrivatePrepare,
        Suite::BackendLinuxPrivateRuntime,
        Suite::BackendWindowsJob,
        Suite::BackendWindowsSealed,
        Suite::BackendMacosWatchdog,
        Suite::ReleaseMacosNative,
        Suite::ReleaseMacosAcceptance,
        Suite::MacosDeadline,
    ];
    for &suite in Suite::value_variants() {
        assert_eq!(
            suite.failure_policy() == SuiteFailurePolicy::FixedStop,
            expected_fixed.contains(&suite),
            "{suite:?}"
        );
        assert_eq!(
            suite
                .resolve_failure_mode(ModeRequest::Workflow(FailureMode::StopAfterFailure))
                .unwrap(),
            FailureMode::StopAfterFailure
        );
        match suite.failure_policy() {
            SuiteFailurePolicy::FixedStop => {
                fixed += 1;
                assert_eq!(
                    suite
                        .resolve_failure_mode(ModeRequest::Workflow(FailureMode::CollectAll))
                        .unwrap(),
                    FailureMode::StopAfterFailure
                );
                assert!(
                    suite
                        .resolve_failure_mode(ModeRequest::Explicit(FailureMode::CollectAll))
                        .unwrap_err()
                        .to_string()
                        .contains("requires stop-after-failure")
                );
            }
            SuiteFailurePolicy::Adaptive => {
                adaptive += 1;
                assert_eq!(
                    suite
                        .resolve_failure_mode(ModeRequest::Workflow(FailureMode::CollectAll))
                        .unwrap(),
                    FailureMode::CollectAll
                );
                assert_eq!(
                    suite
                        .resolve_failure_mode(ModeRequest::Explicit(FailureMode::CollectAll))
                        .unwrap(),
                    FailureMode::CollectAll
                );
            }
        }
    }
    assert_eq!((fixed, adaptive), (20, 46));
}

#[test]
fn cache_writes_include_real_push_tags_but_not_manual_tags_or_empty_refs() {
    for reference in ["refs/heads/main", "refs/tags/0.5.8"] {
        assert!(memcordon_ci::segment_cache::write_event_for(
            Some("push"),
            Some(reference)
        ));
    }
    for reference in ["refs/heads/", "refs/tags/", "refs/pull/1/merge", ""] {
        assert!(!memcordon_ci::segment_cache::write_event_for(
            Some("push"),
            Some(reference)
        ));
    }
    assert!(!memcordon_ci::segment_cache::write_event_for(
        Some("workflow_dispatch"),
        Some("refs/tags/0.5.8")
    ));
    assert!(!memcordon_ci::segment_cache::write_event_for(
        Some("pull_request"),
        Some("refs/heads/main")
    ));
}
