#![cfg(all(target_os = "linux", feature = "test-support"))]

use crate::linux::launch::{
    GuardianTerminalClaim, GuardianTrigger, decode_guardian_terminal_for_test,
    encode_guardian_terminal_for_test, verified_guardian_observed_provider_retirement_for_test,
};

fn complete_claim(trigger: GuardianTrigger) -> GuardianTerminalClaim {
    GuardianTerminalClaim {
        trigger,
        attempt_id: [0x5a; 16],
        cgroup_kill_invoked: true,
        populated_zero_observed: true,
        containment_removed: true,
        record_retired: trigger == GuardianTrigger::ProviderLoss,
    }
}

#[test]
fn guardian_terminal_claim_round_trips_each_trigger() {
    for trigger in [GuardianTrigger::FrontendLoss, GuardianTrigger::ProviderLoss] {
        let claim = complete_claim(trigger);
        let encoded = encode_guardian_terminal_for_test(claim);
        assert_eq!(decode_guardian_terminal_for_test(&encoded), Ok(claim));
    }
}

#[test]
fn guardian_terminal_claim_rejects_framing_and_reserved_bytes() {
    let encoded = encode_guardian_terminal_for_test(complete_claim(GuardianTrigger::FrontendLoss));

    let mut truncated = encoded.to_vec();
    truncated.pop();
    assert!(decode_guardian_terminal_for_test(&truncated).is_err());

    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(decode_guardian_terminal_for_test(&trailing).is_err());

    let mut wrong_version = encoded;
    wrong_version[0] = wrong_version[0].wrapping_add(1);
    assert!(decode_guardian_terminal_for_test(&wrong_version).is_err());

    let mut wrong_trigger = encoded;
    wrong_trigger[1] = 0;
    assert!(decode_guardian_terminal_for_test(&wrong_trigger).is_err());

    let mut unknown_flag = encoded;
    unknown_flag[2] |= 1 << (u8::BITS - 1);
    assert!(decode_guardian_terminal_for_test(&unknown_flag).is_err());

    let mut reserved_header = encoded;
    reserved_header[3] = 1;
    assert!(decode_guardian_terminal_for_test(&reserved_header).is_err());

    let mut reserved_tail = encoded;
    let last = reserved_tail.len() - 1;
    reserved_tail[last] = 1;
    assert!(decode_guardian_terminal_for_test(&reserved_tail).is_err());
}

#[test]
fn guardian_terminal_claim_rejects_contradictory_facts() {
    let cases = [
        GuardianTerminalClaim {
            cgroup_kill_invoked: false,
            ..complete_claim(GuardianTrigger::FrontendLoss)
        },
        GuardianTerminalClaim {
            populated_zero_observed: false,
            ..complete_claim(GuardianTrigger::FrontendLoss)
        },
        GuardianTerminalClaim {
            record_retired: true,
            ..complete_claim(GuardianTrigger::FrontendLoss)
        },
        GuardianTerminalClaim {
            containment_removed: false,
            ..complete_claim(GuardianTrigger::ProviderLoss)
        },
    ];

    for claim in cases {
        let encoded = encode_guardian_terminal_for_test(claim);
        assert!(decode_guardian_terminal_for_test(&encoded).is_err());
    }
}

#[test]
fn provider_loss_absence_is_truthful_and_requires_the_matching_provider_fact() {
    let attempt_id = [0x6b; 16];
    let observed_absence = GuardianTerminalClaim {
        trigger: GuardianTrigger::ProviderLoss,
        attempt_id,
        cgroup_kill_invoked: false,
        populated_zero_observed: false,
        containment_removed: true,
        record_retired: false,
    };
    let encoded = encode_guardian_terminal_for_test(observed_absence);
    assert_eq!(
        decode_guardian_terminal_for_test(&encoded).unwrap(),
        observed_absence
    );
    assert!(verified_guardian_observed_provider_retirement_for_test(
        observed_absence,
        attempt_id
    ));
    assert!(!verified_guardian_observed_provider_retirement_for_test(
        observed_absence,
        [0x6c; 16]
    ));

    let frontend_absence = GuardianTerminalClaim {
        trigger: GuardianTrigger::FrontendLoss,
        ..observed_absence
    };
    assert!(
        decode_guardian_terminal_for_test(&encode_guardian_terminal_for_test(frontend_absence))
            .is_err()
    );
    assert!(!verified_guardian_observed_provider_retirement_for_test(
        frontend_absence,
        attempt_id
    ));
}
