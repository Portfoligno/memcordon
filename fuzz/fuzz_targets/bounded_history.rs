#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|count: u16| {
    let mut history = memcordon_core::AttemptHistory::default();
    let mut aggregates = memcordon_core::SupervisionAggregates::default();
    for number in 1..=u64::from(count) {
        history
            .append(
                memcordon_core::AttemptRecord {
                    number,
                    kind: if number == 1 {
                        memcordon_core::AttemptKind::Initial
                    } else {
                        memcordon_core::AttemptKind::Restart
                    },
                    phase: memcordon_core::AttemptPhase::Failed,
                    target_pid: None,
                    started_offset_ms: Some(number),
                    authorized_offset_ms: None,
                    terminal_offset_ms: None,
                    finished_offset_ms: number,
                    outcome: None,
                    error: Some(memcordon_core::SupervisionErrorRecord {
                        category: "setup".to_owned(),
                        code: "MCFUZZ".to_owned(),
                        message: "fixture".to_owned(),
                        os_code: None,
                        attempt_number: Some(number),
                        supervision_phase: memcordon_core::SupervisionPhase::AttemptSetup,
                        launch_phase: None,
                        target_released: false,
                        workload_may_be_alive: false,
                        initial_spawn_failure: None,
                        provider_rejection: None,
                    }),
                    restart_decision: memcordon_core::RestartDecisionRecord::default(),
                    launch: memcordon_core::LaunchEvidence::default(),
                    restart_safety: memcordon_core::RestartSafetyProof::default(),
                    boundary_detail: memcordon_core::BoundaryMechanismEvidence::Standard {
                        backend: "fuzz-fixture".to_owned(),
                    },
                },
                &mut aggregates,
            )
            .expect("bounded fuzz count cannot exhaust counters");
    }
    assert!(history.retained() <= memcordon_core::DETAILED_ATTEMPT_CAPACITY);
    assert_eq!(history.total, u64::from(count));
    assert_eq!(history.omitted, history.total.saturating_sub(history.retained() as u64));
    if count > 0 {
        assert_eq!(history.records().next().map(|record| record.number), Some(1));
        assert_eq!(history.records().last().map(|record| record.number), Some(u64::from(count)));
    }
});
