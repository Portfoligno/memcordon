#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum AttemptState {
    Allocated,
    BoundaryCreated,
    GuardianReady,
    TargetCreatedGated,
    AssignmentVerified,
    ResourceInheritanceVerified,
    Authorized,
    Running,
    Terminating,
    Empty,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTransition {
    pub from: AttemptState,
    pub to: AttemptState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptStateMachine {
    state: AttemptState,
}

impl Default for AttemptStateMachine {
    fn default() -> Self {
        Self {
            state: AttemptState::Allocated,
        }
    }
}

impl AttemptStateMachine {
    pub const fn state(self) -> AttemptState {
        self.state
    }

    pub fn transition(&mut self, next: AttemptState) -> Result<(), InvalidTransition> {
        let valid = matches!(
            (self.state, next),
            (AttemptState::Allocated, AttemptState::BoundaryCreated)
                | (AttemptState::BoundaryCreated, AttemptState::GuardianReady)
                | (
                    AttemptState::GuardianReady,
                    AttemptState::TargetCreatedGated
                )
                | (
                    AttemptState::TargetCreatedGated,
                    AttemptState::AssignmentVerified
                )
                | (
                    AttemptState::AssignmentVerified,
                    AttemptState::ResourceInheritanceVerified
                )
                | (
                    AttemptState::ResourceInheritanceVerified,
                    AttemptState::Authorized
                )
                | (AttemptState::Authorized, AttemptState::Running)
                | (AttemptState::Running, AttemptState::Terminating)
                | (
                    AttemptState::BoundaryCreated
                        | AttemptState::GuardianReady
                        | AttemptState::TargetCreatedGated
                        | AttemptState::AssignmentVerified
                        | AttemptState::ResourceInheritanceVerified
                        | AttemptState::Authorized,
                    AttemptState::Terminating
                )
                | (AttemptState::Terminating, AttemptState::Empty)
                | (AttemptState::Empty, AttemptState::Retired)
        );
        if !valid {
            return Err(InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }
}
