use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunState {
    Resolving,
    Prepared,
    SpawnedGated,
    Running,
    ChildExited,
    Terminating,
    Reaping,
    Cleaning,
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid run-state transition from {from:?} to {to:?}")]
pub struct StateTransitionError {
    pub from: RunState,
    pub to: RunState,
}

#[derive(Debug)]
pub struct StateMachine {
    state: RunState,
}

impl Default for StateMachine {
    fn default() -> Self {
        Self {
            state: RunState::Resolving,
        }
    }
}

impl StateMachine {
    pub const fn state(&self) -> RunState {
        self.state
    }

    pub fn transition(&mut self, to: RunState) -> Result<(), StateTransitionError> {
        let valid = matches!(
            (self.state, to),
            (RunState::Resolving, RunState::Prepared)
                | (RunState::Prepared, RunState::SpawnedGated)
                | (RunState::SpawnedGated, RunState::Running)
                | (
                    RunState::SpawnedGated | RunState::Running,
                    RunState::ChildExited
                )
                | (
                    RunState::SpawnedGated | RunState::Running | RunState::ChildExited,
                    RunState::Terminating
                )
                | (
                    RunState::SpawnedGated
                        | RunState::Running
                        | RunState::ChildExited
                        | RunState::Terminating,
                    RunState::Reaping
                )
                | (
                    RunState::SpawnedGated
                        | RunState::Running
                        | RunState::ChildExited
                        | RunState::Terminating
                        | RunState::Reaping,
                    RunState::Cleaning
                )
                | (RunState::Cleaning, RunState::Finished)
        );
        if !valid {
            return Err(StateTransitionError {
                from: self.state,
                to,
            });
        }
        self.state = to;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{RunState, StateMachine};

    #[test]
    fn rejects_skipping_from_resolving_to_running() {
        let mut machine = StateMachine::default();
        assert!(machine.transition(RunState::Running).is_err());
        assert_eq!(machine.state(), RunState::Resolving);
    }

    #[test]
    fn accepts_complete_supervisor_lifecycle() {
        let mut machine = StateMachine::default();
        for state in [
            RunState::Prepared,
            RunState::SpawnedGated,
            RunState::Running,
            RunState::Terminating,
            RunState::Reaping,
            RunState::Cleaning,
            RunState::Finished,
        ] {
            machine
                .transition(state)
                .expect("normative lifecycle transition should be valid");
        }
        assert_eq!(machine.state(), RunState::Finished);
    }
}
