#[path = "../src/bin/memcordon-sealed-agent/linux/private_attempt_phase.rs"]
mod private_attempt_phase;

use private_attempt_phase::PrivateAttemptPhase;
#[path = "../src/bin/memcordon-sealed-agent/linux/private_acquisition.rs"]
mod private_acquisition;

use memcordon_core::{execution_facts::NativeProcessV2, result_v3::ReleaseKnowledgeV3};
use private_acquisition::{
    AcquisitionContext, AcquisitionRole, record_identity, require_gated_pair,
};
use private_attempt_phase::{PrivateAttemptPhase as Phase, ReleaseCheckpoint as Checkpoint};

fn acquisition(phase: Phase) -> AcquisitionContext {
    AcquisitionContext {
        phase,
        release: ReleaseKnowledgeV3::NotReleased,
        native_published: false,
    }
}

#[test]
fn factual_acquisition_is_exact_single_assignment_without_release_authority() {
    let observed = NativeProcessV2 {
        pid: 321,
        birth: 111,
    };
    for (role, phase) in [
        (AcquisitionRole::NamespaceInit, Phase::BoundaryCreated),
        (AcquisitionRole::Target, Phase::GuardianReady),
    ] {
        let context = acquisition(phase);
        assert!(record_identity(role, &context, true, None, &observed).unwrap());
        assert!(!record_identity(role, &context, true, Some(&observed), &observed).unwrap());
        for foreign in [
            NativeProcessV2 {
                pid: 322,
                birth: 111,
            },
            NativeProcessV2 {
                pid: 321,
                birth: 112,
            },
        ] {
            assert!(record_identity(role, &context, true, Some(&observed), &foreign).is_err());
        }
        assert!(record_identity(role, &context, false, None, &observed).is_err());
        assert!(record_identity(role, &context, false, Some(&observed), &observed).is_err());
        assert_eq!(context.phase, phase);
        assert_eq!(context.release, ReleaseKnowledgeV3::NotReleased);
        assert!(!context.native_published);
    }
}

#[test]
fn factual_acquisition_rejects_wrong_phase_release_and_native_publication() {
    let observed = NativeProcessV2 {
        pid: 321,
        birth: 111,
    };
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
    for (role, expected) in [
        (AcquisitionRole::NamespaceInit, Phase::BoundaryCreated),
        (AcquisitionRole::Target, Phase::GuardianReady),
    ] {
        for phase in phases {
            assert_eq!(
                record_identity(role, &acquisition(phase), true, None, &observed).is_ok(),
                phase == expected
            );
        }
        for release in [ReleaseKnowledgeV3::Released, ReleaseKnowledgeV3::Unknown] {
            let context = AcquisitionContext {
                phase: expected,
                release,
                native_published: false,
            };
            assert!(record_identity(role, &context, true, None, &observed).is_err());
        }
        let context = AcquisitionContext {
            phase: expected,
            release: ReleaseKnowledgeV3::NotReleased,
            native_published: true,
        };
        assert!(record_identity(role, &context, true, None, &observed).is_err());
    }
}

#[test]
fn authorization_requires_both_exact_previously_acquired_identities() {
    let init = NativeProcessV2 {
        pid: 321,
        birth: 111,
    };
    let target = NativeProcessV2 {
        pid: 322,
        birth: 112,
    };
    let context = acquisition(Phase::GuardianReady);
    require_gated_pair(&context, Some(&init), Some(&target), &init, &target).unwrap();
    for (published_init, published_target) in
        [(None, Some(&target)), (Some(&init), None), (None, None)]
    {
        assert!(
            require_gated_pair(&context, published_init, published_target, &init, &target).is_err()
        );
    }
    let foreign_init = NativeProcessV2 {
        pid: init.pid,
        birth: init.birth + 1,
    };
    let foreign_target = NativeProcessV2 {
        pid: target.pid + 1,
        birth: target.birth,
    };
    assert!(
        require_gated_pair(&context, Some(&init), Some(&target), &foreign_init, &target).is_err()
    );
    assert!(
        require_gated_pair(&context, Some(&init), Some(&target), &init, &foreign_target).is_err()
    );
    assert!(
        require_gated_pair(
            &acquisition(Phase::TargetGated),
            Some(&init),
            Some(&target),
            &init,
            &target
        )
        .is_err()
    );
    for release in [ReleaseKnowledgeV3::Released, ReleaseKnowledgeV3::Unknown] {
        let context = AcquisitionContext {
            phase: Phase::GuardianReady,
            release,
            native_published: false,
        };
        assert!(require_gated_pair(&context, Some(&init), Some(&target), &init, &target).is_err());
    }
    let published = AcquisitionContext {
        phase: Phase::GuardianReady,
        release: ReleaseKnowledgeV3::NotReleased,
        native_published: true,
    };
    assert!(require_gated_pair(&published, Some(&init), Some(&target), &init, &target).is_err());
}

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
