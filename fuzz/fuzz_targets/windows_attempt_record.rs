#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{
    WindowsCertificationPhaseV1, parse_and_authenticate_windows_attempt_record,
    windows_certification_transition_allowed,
};

fuzz_target!(|data: (
    Vec<u8>,
    String,
    String,
    Vec<u8>,
)| {
    let (bytes, expected_attempt_id, expected_generation, states) = data;
    if let Ok(record) = parse_and_authenticate_windows_attempt_record(
        &bytes,
        &expected_attempt_id,
        &expected_generation,
    ) {
        assert_eq!(record.attempt_id, expected_attempt_id);
        assert_eq!(record.provider_generation, expected_generation);
        let canonical = serde_json::to_vec(&record).expect("authenticated record must serialize");
        assert!(parse_and_authenticate_windows_attempt_record(
            &canonical,
            &record.attempt_id,
            &record.provider_generation,
        )
        .is_ok());
    }

    use WindowsCertificationPhaseV1 as Phase;
    let phases = [
        Phase::Connected,
        Phase::CallerAuthenticated,
        Phase::LauncherAuthenticated,
        Phase::GuardianReady,
        Phase::RelaysReady,
        Phase::TargetCreatedSuspended,
        Phase::AssignmentVerified,
        Phase::Authorized,
        Phase::Running,
        Phase::Terminating,
        Phase::Empty,
        Phase::RelaysRetired,
        Phase::GuardianReaped,
        Phase::HandlesClosed,
        Phase::Retired,
    ];
    let mut current = Phase::Connected;
    let mut authorized = false;
    let mut ordinary_result_accepted = false;
    let mut restart_accepted = false;
    for selector in states {
        let action = selector % 17;
        if action < phases.len() as u8 {
            let candidate = phases[action as usize];
            if windows_certification_transition_allowed(current, candidate) {
                if candidate == Phase::Authorized {
                    assert_eq!(current, Phase::AssignmentVerified);
                    authorized = true;
                }
                current = candidate;
            }
        } else if action == phases.len() as u8 {
            ordinary_result_accepted = current == Phase::Retired;
        } else {
            restart_accepted = current == Phase::Retired;
        }
        if current == Phase::Running {
            assert!(authorized);
        }
        if ordinary_result_accepted {
            assert_eq!(current, Phase::Retired);
        }
        if restart_accepted {
            assert_eq!(current, Phase::Retired);
        }
        if current == Phase::Retired {
            let candidate = phases[(selector as usize) % phases.len()];
            assert!(!windows_certification_transition_allowed(current, candidate));
        }
    }
});
