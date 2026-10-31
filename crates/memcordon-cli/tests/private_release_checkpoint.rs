#[path = "../src/bin/memcordon-sealed-agent/linux/private_attempt_phase.rs"]
mod private_attempt_phase;

use private_attempt_phase::{PrivateAttemptPhase as Phase, ReleaseCheckpoint as Checkpoint};

#[test]
fn durable_release_transition_is_admitted_only_at_its_exact_checkpoint() {
    let phases = [
        Phase::Allocated,
        Phase::BoundaryCreated,
        Phase::GuardianReady,
        Phase::TargetGated,
        Phase::ReleaseIntent,
        Phase::ExecutionObserved,
        Phase::Retiring,
        Phase::Retired,
        Phase::CleanupIncomplete,
    ];
    for phase in phases {
        assert_eq!(
            Checkpoint::BeforeIntent.validate(phase).is_ok(),
            phase == Phase::TargetGated
        );
        assert_eq!(
            Checkpoint::AfterIntent.validate(phase).is_ok(),
            phase == Phase::ReleaseIntent
        );
    }
    let repeated = Checkpoint::BeforeIntent
        .validate(Phase::ReleaseIntent)
        .unwrap_err();
    assert!(repeated.contains("BeforeIntent") && repeated.contains("actual ReleaseIntent"));
    let uncommitted = Checkpoint::AfterIntent
        .validate(Phase::TargetGated)
        .unwrap_err();
    assert!(uncommitted.contains("AfterIntent") && uncommitted.contains("actual TargetGated"));
}
