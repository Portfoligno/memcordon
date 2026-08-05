#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use std::time::Duration;

    use memcordon_core::{
        LogisticBackoffPolicy, RestartAction, RestartCondition, RestartConditions,
        RestartCoordinator, RestartDecisionRecord, RestartLimit, RestartSafetyProof,
        RestartSettings, WaitCompletion,
    };

    for (index, byte) in data.iter().copied().take(64).enumerate() {
        let settings = RestartSettings::new(
            RestartConditions::BOTH,
            RestartConditions::BOTH,
            Vec::new(),
            RestartLimit::Unlimited,
            LogisticBackoffPolicy::default(),
            None,
        )
        .expect("fixed settings are valid");
        let mut coordinator = RestartCoordinator::new(settings).expect("coordinator");
        let safe = RestartSafetyProof {
            direct_child_reaped: byte & 0x10 == 0,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: false,
            errors: Vec::new(),
        };
        let condition = if byte & 1 == 0 {
            RestartCondition::MemoryLimit
        } else {
            RestartCondition::Deadline
        };
        let mut record = RestartDecisionRecord::default();
        let action = coordinator
            .on_limit(
                condition,
                Duration::from_millis(u64::try_from(index).expect("bounded index")),
                &safe,
                &mut record,
            )
            .expect("valid transition");
        if !safe.is_safe() {
            assert!(matches!(action, RestartAction::Stop(_)));
            continue;
        }
        let RestartAction::Wait { duration, .. } = action else {
            continue;
        };
        let completion = match byte & 0x0c {
            0x04 => WaitCompletion::Interrupted,
            0x08 => WaitCompletion::SupervisionDeadline,
            _ => WaitCompletion::Completed,
        };
        let after = coordinator
            .complete_wait(
                completion,
                duration,
                (completion == WaitCompletion::SupervisionDeadline).then_some(Duration::ZERO),
                &mut record,
            )
            .expect("valid wait completion");
        if completion != WaitCompletion::Completed {
            assert!(matches!(after, RestartAction::Stop(_)));
            assert_eq!(coordinator.summary().restarts_launched(), 0);
        }
    }
});
