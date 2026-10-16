use super::retain_failure;
use memcordon_ci::{CiError, failure_mode::FailureMode, preparation};
use std::time::{Duration, Instant};

#[test]
fn collect_all_keeps_the_original_failure_when_ownership_closes_admission() {
    preparation::with_operation(
        FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(10),
        || {
            let mut retained = None;
            retain_failure(
                &mut retained,
                Err(CiError::Message("original compiler defect".into())),
                FailureMode::CollectAll,
            )?;
            preparation::active_group().unwrap().close_admission();
            let error = retain_failure(
                &mut retained,
                Err(CiError::Message("later ownership failure".into())),
                FailureMode::CollectAll,
            )
            .unwrap_err();
            match error {
                CiError::LaneFailures { primary, secondary } => {
                    assert_eq!(primary.to_string(), "original compiler defect");
                    assert_eq!(secondary.to_string(), "later ownership failure");
                }
                _ => panic!("terminal failure replaced the original cause"),
            }
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn independent_failures_are_retained_and_stop_mode_is_immediate() {
    let mut retained = None;
    for name in ["one", "two"] {
        retain_failure(
            &mut retained,
            Err(CiError::Message(name.into())),
            FailureMode::CollectAll,
        )
        .unwrap();
    }
    let text = retained.unwrap().to_string();
    assert!(text.contains("one") && text.contains("two"));
    assert!(
        retain_failure(
            &mut None,
            Err(CiError::Message("stop".into())),
            FailureMode::StopAfterFailure
        )
        .is_err()
    );
}
