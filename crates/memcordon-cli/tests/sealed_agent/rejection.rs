use crate::rejection::{RejectionPhaseV1, RejectionV1};

#[test]
fn native_readback_failure_is_bounded_and_classified_before_authorization() {
    let rejection = RejectionV1::from_launch_error(
        "MCSEALED-TARGET-DESCRIPTORS-READBACK: permission denied",
        [0x5a; 16],
    );

    assert_eq!(rejection.schema_version, 1);
    assert_eq!(rejection.code, "MCSEALED-TARGET-DESCRIPTORS-READBACK");
    assert_eq!(rejection.phase, RejectionPhaseV1::ResourceVerification);
    assert!(rejection.target_created);
    assert!(!rejection.target_released);
    rejection
        .validate()
        .expect("rejection must be self-consistent");

    let encoded = rejection.encode().expect("rejection must encode");
    assert_eq!(encoded.last(), Some(&b'\n'));
    let decoded: RejectionV1 =
        serde_json::from_slice(&encoded).expect("receipt must be strict JSON");
    assert_eq!(decoded, rejection);
}

#[test]
fn rejection_validation_fails_closed_on_contradictory_cleanup() {
    let mut rejection =
        RejectionV1::request_error("MCSEALED-LAUNCH-DECODE", "invalid bounded launch request");
    rejection.cleanup.sealed_boundary_retired = true;

    assert!(rejection.validate().is_err());
}

#[test]
fn rejection_detail_is_truncated_without_splitting_utf8() {
    let detail = format!("MCSEALED-MONITOR-POLL: {}", "界".repeat(4_000));
    let rejection = RejectionV1::from_launch_error(&detail, [0x39; 16]);

    assert_eq!(rejection.phase, RejectionPhaseV1::Monitoring);
    assert!(rejection.detail.len() <= 8 * 1024);
    assert!(rejection.detail.ends_with("...[truncated]"));
    rejection
        .validate()
        .expect("bounded UTF-8 detail must validate");
}

#[test]
fn pretarget_failures_do_not_claim_that_a_target_was_created() {
    for (detail, expected_phase, cleanup_attempted) in [
        (
            "MCSEALED-LAUNCH-DESCRIPTOR-SET: exact descriptor inventory required",
            RejectionPhaseV1::RequestValidation,
            false,
        ),
        (
            "MCSEALED-TARGET-CONTROL: too many open files",
            RejectionPhaseV1::BoundaryCreation,
            true,
        ),
        (
            "MCSEALED-TARGET-WAIT: gated target not observed",
            RejectionPhaseV1::TargetCreation,
            true,
        ),
        (
            "MCSEALED-NAMESPACE-INIT-TARGET-FORK: Resource temporarily unavailable",
            RejectionPhaseV1::TargetCreation,
            true,
        ),
    ] {
        let rejection = RejectionV1::from_launch_error(detail, [0xa7; 16]);
        assert_eq!(rejection.phase, expected_phase);
        assert!(!rejection.target_created);
        assert!(!rejection.target_released);
        assert_eq!(rejection.cleanup.attempted, cleanup_attempted);
        rejection.validate().expect("rejection must validate");
    }
}

#[test]
fn clock_failures_preserve_their_exact_launch_phase() {
    let authorization = RejectionV1::from_launch_error(
        "MCSEALED-AUTHORIZATION-CLOCK: MCSEALED-CLOCK-MONOTONIC: unavailable",
        [0x2c; 16],
    );
    assert_eq!(authorization.phase, RejectionPhaseV1::Authorization);
    assert!(authorization.target_created);
    assert!(!authorization.target_released);
    assert!(authorization.cleanup.attempted);

    let monitoring = RejectionV1::from_launch_error(
        "MCSEALED-MONITOR-CLOCK: MCSEALED-CLOCK-MONOTONIC: unavailable",
        [0x2d; 16],
    );
    assert_eq!(monitoring.phase, RejectionPhaseV1::Monitoring);
    assert!(monitoring.target_created);
    assert!(monitoring.target_released);
    assert!(monitoring.cleanup.attempted);
}

#[test]
fn malformed_postauthorization_exec_status_preserves_release_and_retirement_truth() {
    let rejection = RejectionV1::from_launch_error(
        "MCSEALED-TARGET-EXEC-STATUS: errno classification mismatch",
        [0xe3; 16],
    );
    assert_eq!(rejection.phase, RejectionPhaseV1::TargetCreation);
    assert!(rejection.target_created);
    assert!(rejection.target_released);
    assert!(rejection.cleanup.attempted);
    #[cfg(target_os = "linux")]
    assert!(rejection.cleanup.sealed_boundary_retired);
    #[cfg(not(target_os = "linux"))]
    assert!(!rejection.cleanup.sealed_boundary_retired);
    rejection.validate().expect("rejection must validate");
}

#[test]
fn injected_native_retirement_faults_preserve_terminal_phase_and_release_truth() {
    for code in [
        "MCSEALED-CGROUP-KILL-FAILURE",
        "MCSEALED-CGROUP-NOT-EMPTY",
        "MCSEALED-NAMESPACE-INIT-REAP-DELAY",
        "MCSEALED-GUARDIAN-REAP-FAILURE",
    ] {
        let rejection = RejectionV1::from_launch_error(
            &format!("{code}: injected certification fault"),
            [0xe4; 16],
        );
        assert_eq!(rejection.code, code);
        assert_eq!(rejection.phase, RejectionPhaseV1::Retirement);
        assert!(rejection.target_created);
        assert!(rejection.target_released);
        assert!(rejection.cleanup.attempted);
        rejection.validate().expect("rejection must validate");
    }
}
