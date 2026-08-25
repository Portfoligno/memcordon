#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/protocol.rs"]
mod protocol;
#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/request.rs"]
mod request;
#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/state.rs"]
mod state;

use state::{AttemptState, AttemptStateMachine};

fuzz_target!(|data: &[u8]| {
    let _ = protocol::read_frame(&mut Cursor::new(data));
    let _ = request::decode_launch_broker_request(data);

    let mut state = AttemptStateMachine::default();
    let mut boundary_created = false;
    let mut broker_prepared = false;
    let mut target_gated = false;
    let mut assignment_verified = false;
    let mut resources_verified = false;
    for event in data.iter().copied().map(|byte| byte % 8) {
        match event {
            0 => {
                let _ = protocol::read_frame(&mut Cursor::new(data));
            }
            1 => {
                if state.transition(AttemptState::BoundaryCreated).is_ok() {
                    boundary_created = true;
                }
            }
            2 => {
                if state.transition(AttemptState::GuardianReady).is_ok() {
                    broker_prepared = true;
                }
            }
            3 => {
                if state.transition(AttemptState::TargetCreatedGated).is_ok() {
                    target_gated = true;
                }
                if state.transition(AttemptState::AssignmentVerified).is_ok() {
                    assignment_verified = true;
                }
                if state
                    .transition(AttemptState::ResourceInheritanceVerified)
                    .is_ok()
                {
                    resources_verified = true;
                }
            }
            4 => {
                let _ = state.transition(AttemptState::Authorized);
            }
            5..=7 => {
                if state.state() == AttemptState::Authorized {
                    let _ = state.transition(AttemptState::Running);
                }
                let _ = state.transition(AttemptState::Terminating);
                let _ = state.transition(AttemptState::Empty);
                let _ = state.transition(AttemptState::Retired);
            }
            _ => unreachable!("event is reduced modulo eight"),
        }
        if matches!(
            state.state(),
            AttemptState::Authorized | AttemptState::Running
        ) {
            assert!(
                boundary_created
                    && broker_prepared
                    && target_gated
                    && assignment_verified
                    && resources_verified,
                "v2 target authorization bypassed a required predicate"
            );
        }
    }
});
