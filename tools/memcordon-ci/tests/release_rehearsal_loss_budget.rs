#[path = "support/release_loss_budget.rs"]
mod release_loss_budget;

use release_loss_budget::{
    PHASE_ALLOWANCE, PHASES, RETIREMENT_ALLOWANCE, ScenarioClock, work_allowance,
};
use std::time::{Duration, Instant};

#[test]
fn required_loss_phases_compose_one_finite_original_cutoff() {
    assert_eq!(
        PHASES,
        [
            "readiness",
            "initial-publication",
            "independent-readback",
            "idempotent-publication",
        ]
    );
    assert_eq!(PHASE_ALLOWANCE, Duration::from_secs(15));
    assert_eq!(work_allowance(), Duration::from_secs(60));
    let started = Instant::now();
    let clock = ScenarioClock::from_start(started, 1000);
    assert_eq!(clock.started, started);
    assert_eq!(clock.readiness.duration_since(started), PHASE_ALLOWANCE);
    assert_eq!(clock.work.duration_since(started), work_allowance());
    assert_eq!(clock.work_unix_ms, 61_000);
    assert!(clock.admits_readiness(started));
    assert!(!clock.admits_readiness(clock.readiness));
    assert!(!clock.admits_readiness(started + Duration::from_secs(16)));
    // A later phase consumes the original remainder rather than renewing work.
    let retry_start = started + Duration::from_secs(47);
    assert_eq!(
        clock.work.duration_since(retry_start),
        Duration::from_secs(13)
    );
}

#[test]
fn complete_small_inventory_and_retirement_fit_the_unchanged_command_guard() {
    // Six native archives, four crates, and three metadata files. This is the
    // focused target's envelope, not a claim about all other native tests/builds.
    let managed_positions = 6 + 4 + 3;
    assert_eq!(RETIREMENT_ALLOWANCE, Duration::from_secs(5));
    let target = work_allowance()
        .checked_add(RETIREMENT_ALLOWANCE)
        .unwrap()
        .checked_mul(managed_positions)
        .unwrap();
    assert_eq!(target, Duration::from_secs(845));
    assert!(target < Duration::from_secs(900));
    assert!(work_allowance() < Duration::from_secs(20 * 60));
}
