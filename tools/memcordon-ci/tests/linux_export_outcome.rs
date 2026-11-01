use memcordon_ci::linux_export_outcome::validate;
use memcordon_core::{
    BoundedText, ChildTermination,
    execution_facts::{OutcomeKindV1, OutcomeV1},
    result_v3::OutputDeliveryStateV3,
};

fn refused() -> OutcomeV1 {
    OutcomeV1 {
        kind: OutcomeKindV1::Completed,
        native_termination: Some(ChildTermination::ExitCode { code: 0 }),
        wrapper_status: 125,
    }
}
fn diagnostic() -> Vec<BoundedText<4096>> {
    vec![BoundedText::new("output delivery is incomplete").unwrap()]
}

#[test]
fn each_explicit_unsafe_export_requires_target_success_and_captured_wrapper_refusal() {
    for scenario in [
        "export-symlink",
        "export-fifo",
        "export-device",
        "export-socket",
        "export-traversal",
    ] {
        validate(
            scenario,
            &refused(),
            Some(OutputDeliveryStateV3::Incomplete),
            &diagnostic(),
            Some(125),
        )
        .unwrap();
    }
    for scenario in ["export-unknown", "export-symlink-extra", ""] {
        assert!(
            validate(
                scenario,
                &refused(),
                Some(OutputDeliveryStateV3::Incomplete),
                &diagnostic(),
                Some(125)
            )
            .is_err()
        );
    }
}

#[test]
fn other_failures_and_missing_native_target_completion_cannot_stand_in_for_export_refusal() {
    for kind in [
        OutcomeKindV1::Deadline,
        OutcomeKindV1::Interrupted,
        OutcomeKindV1::LaunchFailure,
        OutcomeKindV1::ProviderFailure,
        OutcomeKindV1::ConfirmedMemoryLimit,
        OutcomeKindV1::Unknown,
    ] {
        let mut outcome = refused();
        outcome.kind = kind;
        assert!(
            validate(
                "export-symlink",
                &outcome,
                Some(OutputDeliveryStateV3::Incomplete),
                &diagnostic(),
                Some(125)
            )
            .is_err()
        );
    }
    for termination in [
        None,
        Some(ChildTermination::ExitCode { code: 1 }),
        Some(ChildTermination::UnixSignal { signal: 9 }),
        Some(ChildTermination::WindowsStatus { status: 0 }),
        Some(ChildTermination::Unavailable),
    ] {
        let mut outcome = refused();
        outcome.native_termination = termination;
        assert!(
            validate(
                "export-symlink",
                &outcome,
                Some(OutputDeliveryStateV3::Incomplete),
                &diagnostic(),
                Some(125)
            )
            .is_err()
        );
    }
    for status in [0, 123, 126, 130] {
        let mut outcome = refused();
        outcome.wrapper_status = status;
        assert!(
            validate(
                "export-symlink",
                &outcome,
                Some(OutputDeliveryStateV3::Incomplete),
                &diagnostic(),
                Some(status)
            )
            .is_err()
        );
    }
    for captured in [None, Some(0), Some(130)] {
        assert!(
            validate(
                "export-symlink",
                &refused(),
                Some(OutputDeliveryStateV3::Incomplete),
                &diagnostic(),
                captured
            )
            .is_err()
        );
    }
}

#[test]
fn incomplete_delivery_and_exact_structured_diagnostic_are_both_required() {
    for delivery in [
        None,
        Some(OutputDeliveryStateV3::Unknown),
        Some(OutputDeliveryStateV3::Complete),
    ] {
        assert!(
            validate(
                "export-symlink",
                &refused(),
                delivery,
                &diagnostic(),
                Some(125)
            )
            .is_err()
        );
    }
    assert!(
        validate(
            "export-symlink",
            &refused(),
            Some(OutputDeliveryStateV3::Incomplete),
            &[],
            Some(125)
        )
        .is_err()
    );
    for text in [
        "output delivery is incomplete: another failure",
        "prefix output delivery is incomplete",
        "Output delivery is incomplete",
    ] {
        let diagnostics = [BoundedText::new(text).unwrap()];
        assert!(
            validate(
                "export-symlink",
                &refused(),
                Some(OutputDeliveryStateV3::Incomplete),
                &diagnostics,
                Some(125)
            )
            .is_err()
        );
    }
}

#[test]
fn concurrent_writer_keeps_its_separate_complete_zero_status_contract() {
    let mut outcome = refused();
    outcome.wrapper_status = 0;
    validate(
        "export-concurrent-writer",
        &outcome,
        Some(OutputDeliveryStateV3::Complete),
        &[],
        Some(0),
    )
    .unwrap();
    assert!(
        validate(
            "export-concurrent-writer",
            &refused(),
            Some(OutputDeliveryStateV3::Incomplete),
            &diagnostic(),
            Some(125)
        )
        .is_err()
    );
    assert!(
        validate(
            "export-concurrent-writer",
            &outcome,
            Some(OutputDeliveryStateV3::Incomplete),
            &[],
            Some(0)
        )
        .is_err()
    );
    assert!(
        validate(
            "export-symlink",
            &outcome,
            Some(OutputDeliveryStateV3::Complete),
            &[],
            Some(0)
        )
        .is_err()
    );
}
