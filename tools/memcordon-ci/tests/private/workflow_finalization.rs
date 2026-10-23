use crate::{CiError, work_outcome::WorkOutcome};

#[test]
fn optional_projection_preserves_only_actual_unresolved_owner_evidence() {
    use crate::work_outcome::{WriterSettlement, has_unresolved_owner};
    let unknown = WorkOutcome::<()>::observed(
        Err(CiError::Message("native reader did not settle".into())),
        WriterSettlement::Unknown,
    )
    .into_result()
    .unwrap_err();
    assert!(has_unresolved_owner(&unknown));
    let nested = CiError::LaneFailures {
        primary: Box::new(CiError::Message("unavailable input".into())),
        secondary: Box::new(unknown),
    };
    assert!(has_unresolved_owner(&nested));
    assert!(!has_unresolved_owner(&CiError::Message(
        "unavailable optional input".into()
    )));
    assert!(!has_unresolved_owner(&CiError::SettledCommandFailure(
        "probe exited".into()
    )));
}
