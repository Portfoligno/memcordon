use memcordon_ci::{
    CiError,
    failure_mode::FailureMode,
    performance_plan::Layout,
    preparation::{LaneId, PairClass, allocate_pair, complete_owned_pair},
    work_outcome::{WorkOutcome, WriterSettlement},
};
use std::{num::NonZeroUsize, time::Duration};

#[test]
fn allocation_preserves_each_inherited_budget() {
    for workers in [1, 2, 3, 4, 16] {
        for requested in [false, true] {
            for nested in [false, true] {
                for class in [PairClass::Balanced, PairClass::ProductAndNative] {
                    let result = allocate_pair(
                        NonZeroUsize::new(workers).unwrap(),
                        requested,
                        nested,
                        class,
                    );
                    if result.parallel {
                        assert!(result.first.get() + result.second.get() <= workers.min(4));
                    } else {
                        assert_eq!(result.first.get(), workers.min(4));
                        assert_eq!(result.second.get(), workers.min(4));
                    }
                    assert_eq!(result.parallel, requested && !nested && workers >= 2);
                }
            }
        }
    }
}

#[test]
fn second_failure_keeps_product_outcome_in_first_slot_on_serial_hosts() {
    let pair = memcordon_ci::preparation::with_operation(
        FailureMode::CollectAll,
        std::time::Instant::now() + Duration::from_secs(20),
        || {
            Ok(complete_owned_pair(
                Layout::Serial,
                [1, 1],
                || WorkOutcome::from_result(Ok("product")),
                move || {
                    memcordon_ci::preparation::active_group()
                        .unwrap()
                        .request_after_failure();
                    WorkOutcome::<()>::from_result(Err(CiError::SettledCommandFailure(
                        "native failed".into(),
                    )))
                },
            ))
        },
    )
    .unwrap();
    assert_eq!(pair.first_cause, Some(LaneId::Second));
    assert_eq!(pair.first.into_result().unwrap(), "product");
    assert_eq!(pair.second.writers(), WriterSettlement::Settled);
    assert!(
        pair.second
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("native failed")
    );
}

#[test]
fn panic_keeps_unknown_ownership_and_closes_collect_all_admission() {
    let pair = memcordon_ci::preparation::with_operation(
        FailureMode::CollectAll,
        std::time::Instant::now() + Duration::from_secs(20),
        || {
            Ok(complete_owned_pair(
                Layout::Serial,
                [1, 1],
                || -> WorkOutcome<()> { panic!("owned callback panic") },
                || WorkOutcome::from_result(Ok(17)),
            ))
        },
    )
    .unwrap();
    assert_eq!(pair.first.writers(), WriterSettlement::Unknown);
    assert_eq!(pair.second.writers(), WriterSettlement::NotStarted);
    assert!(matches!(
        pair.second.into_result(),
        Err(CiError::NotStartedAfterFailure)
    ));
}
