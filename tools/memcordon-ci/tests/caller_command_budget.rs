use memcordon_ci::{
    caller_command_budget::{administrative, workload},
    command::remaining_budget,
};
use std::time::{Duration, Instant};

#[test]
fn administrative_ceiling_and_original_workload_cutoff_remain_distinct() {
    let start = Instant::now();
    let cutoff = start + Duration::from_secs(600);
    assert_eq!(administrative(), Duration::from_secs(60));
    assert_eq!(workload(start, cutoff).unwrap(), Duration::from_secs(600));
    assert_eq!(
        workload(start + Duration::from_secs(90), cutoff).unwrap(),
        Duration::from_secs(510)
    );
    assert_eq!(
        workload(start + Duration::from_secs(599), cutoff).unwrap(),
        Duration::from_secs(1)
    );
    assert_eq!(administrative(), Duration::from_secs(60));
    assert!(workload(cutoff, cutoff).is_err());
    assert!(workload(cutoff + Duration::from_secs(1), cutoff).is_err());
}

#[test]
fn parent_remaining_and_original_cleanup_reservation_still_limit_selected_work() {
    let start = Instant::now();
    let selected = workload(start, start + Duration::from_secs(600)).unwrap();
    assert_eq!(
        remaining_budget(selected, Duration::from_secs(550), Duration::from_secs(30)).unwrap(),
        Duration::from_secs(520)
    );
    assert_eq!(
        remaining_budget(selected, Duration::from_secs(100), Duration::from_secs(20)).unwrap(),
        Duration::from_secs(80)
    );
    assert_eq!(
        remaining_budget(
            administrative(),
            Duration::from_secs(550),
            Duration::from_secs(30)
        )
        .unwrap(),
        Duration::from_secs(60)
    );
    assert!(remaining_budget(selected, Duration::from_secs(30), Duration::from_secs(30)).is_err());
    assert!(remaining_budget(selected, Duration::from_secs(29), Duration::from_secs(30)).is_err());
}
