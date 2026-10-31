//! Durable native attempt phases and the two one-use release checkpoints.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateAttemptPhase {
    Allocated,
    BoundaryCreated,
    GuardianReady,
    TargetGated,
    ReleaseIntent,
    ExecutionObserved,
    Retiring,
    Retired,
    CleanupIncomplete,
}

#[derive(Clone, Copy, Debug)]
pub enum ReleaseCheckpoint {
    BeforeIntent,
    AfterIntent,
}

impl ReleaseCheckpoint {
    pub fn validate(self, actual: PrivateAttemptPhase) -> Result<(), String> {
        let expected = match self {
            Self::BeforeIntent => PrivateAttemptPhase::TargetGated,
            Self::AfterIntent => PrivateAttemptPhase::ReleaseIntent,
        };
        if actual != expected {
            return Err(format!(
                "MCSEALED-PRIVATE-CHECKPOINT: {self:?} expected phase {expected:?}, actual {actual:?}"
            ));
        }
        Ok(())
    }
}
