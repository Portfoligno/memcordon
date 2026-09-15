#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{RunState, StateMachine};

fuzz_target!(|data: &[u8]| {
    let mut machine = StateMachine::default();
    for byte in data.iter().take(1_024) {
        let state = match byte % 9 {
            0 => RunState::Resolving,
            1 => RunState::Prepared,
            2 => RunState::SpawnedGated,
            3 => RunState::Running,
            4 => RunState::ChildExited,
            5 => RunState::Terminating,
            6 => RunState::Reaping,
            7 => RunState::Cleaning,
            _ => RunState::Finished,
        };
        let previous = machine.state();
        match machine.transition(state) {
            Ok(()) => assert_eq!(machine.state(), state),
            Err(error) => {
                assert_eq!(machine.state(), previous);
                assert_eq!(error.from, previous);
                assert_eq!(error.to, state);
            }
        }
    }
});
