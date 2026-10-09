use memcordon_ci::windows_causal_acceptance::{
    ObservationExpectation, validate_process_observation,
};
use memcordon_core::{
    ProcessObservationUnavailableReasonV1, WindowsProcessIdentityV1, WindowsProcessObservationV2,
};

#[test]
fn worker_loss_keeps_unavailable_coverage_without_inventing_final_diagnostics() {
    let root = WindowsProcessIdentityV1 {
        process_id: 41,
        creation_time_100ns: 100,
    };
    let mut expected = ObservationExpectation {
        root: root.clone(),
        attempt_id: "a".repeat(64),
        nonce: "held-live-nonce".into(),
        request_sha256: "b".repeat(64),
        worker_loss_before_freeze: true,
    };
    let observation = WindowsProcessObservationV2::unavailable(
        ProcessObservationUnavailableReasonV1::WorkerLostBeforeFreeze,
    );
    let sampled =
        validate_process_observation(&observation, std::slice::from_ref(&root), &expected).unwrap();
    assert_eq!(sampled.capacity, None);
    assert_eq!(sampled.sampled, 0);
    assert!(observation.final_accounting.is_none());
    expected.worker_loss_before_freeze = false;
    assert!(
        validate_process_observation(&observation, std::slice::from_ref(&root), &expected).is_err()
    );
    expected.worker_loss_before_freeze = true;
    assert!(validate_process_observation(&observation, &[], &expected).is_err());
    assert!(validate_process_observation(&observation, &[root.clone(), root], &expected).is_err());
}
