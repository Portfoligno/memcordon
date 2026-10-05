use memcordon_testkit::harness_budget::{
    BudgetError, natural_root_guard, running_deadline_guard, startup_deadline_guard, sum,
};
use std::time::Duration;

#[test]
fn independent_fixed_scenario_vectors_preserve_original_work_cutoffs() {
    let seconds = Duration::from_secs;
    assert_eq!(
        startup_deadline_guard(
            seconds(5),
            Duration::from_millis(100),
            seconds(3),
            seconds(1),
            seconds(1)
        ),
        Ok(Duration::from_millis(5100))
    );
    assert_eq!(
        startup_deadline_guard(seconds(5), seconds(5), seconds(3), seconds(1), seconds(1)),
        Ok(seconds(10))
    );
    assert_eq!(
        running_deadline_guard(seconds(8), seconds(3), seconds(1), seconds(1)),
        Ok(seconds(13))
    );
    assert_eq!(
        natural_root_guard(
            seconds(5),
            seconds(2),
            seconds(3),
            seconds(1),
            seconds(1),
            seconds(30)
        ),
        Ok(seconds(12))
    );
    assert_eq!(
        natural_root_guard(
            seconds(5),
            seconds(2),
            seconds(3),
            seconds(1),
            seconds(1),
            seconds(12)
        ),
        Err(BudgetError::InconsistentScenario)
    );
    assert_eq!(
        sum(&[Duration::MAX, seconds(1)]),
        Err(BudgetError::Overflow)
    );
}

#[test]
fn historical_measured_prefix_fits_repaired_combined_stress_envelope() {
    let prefix = Duration::from_secs(71 * 60 + 36);
    let lifecycle = Duration::from_secs(35 * 60);
    let finalization = Duration::from_secs(5 * 60);
    let measured_envelope = sum(&[prefix, lifecycle]).unwrap();
    assert_eq!(measured_envelope, Duration::from_secs(106 * 60 + 36));
    assert_eq!(
        Duration::from_secs(120 * 60) - measured_envelope,
        Duration::from_secs(13 * 60 + 24)
    );
    let admitted = sum(&[prefix, lifecycle, finalization]).unwrap();
    assert!(admitted > Duration::from_secs(90 * 60));
    assert_eq!(
        Duration::from_secs(120 * 60) - admitted,
        Duration::from_secs(8 * 60 + 24)
    );
}

#[test]
fn enumerated_native_operations_fit_initial_job_allowance() {
    let minutes = |value: u64| Duration::from_secs(value * 60);
    assert_eq!(
        sum(&[minutes(30), minutes(25), minutes(15), minutes(60)]),
        Ok(minutes(130))
    );
    assert_eq!(
        sum(&[minutes(30), minutes(130), minutes(10), minutes(10)]),
        Ok(minutes(180))
    );
}
