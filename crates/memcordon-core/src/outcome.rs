use serde::{Deserialize, Serialize};

use crate::ByteSize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ChildTermination {
    ExitCode { code: i32 },
    UnixSignal { signal: i32 },
    WindowsStatus { status: u32 },
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Interruption {
    pub signal: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LimitEvidence {
    pub backend: String,
    pub metric: String,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CleanupErrorRecord {
    pub operation: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CleanupSummary {
    pub graceful_attempted: bool,
    pub force_attempted: bool,
    pub direct_child_reaped: bool,
    pub workload_empty: Option<bool>,
    pub errors: Vec<CleanupErrorRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum RunOutcome {
    Exited {
        child: ChildTermination,
        peak: Option<ByteSize>,
        cleanup: CleanupSummary,
    },
    LimitExceeded {
        limit: ByteSize,
        observed: Option<ByteSize>,
        peak: Option<ByteSize>,
        evidence: LimitEvidence,
        child_after_termination: Option<ChildTermination>,
        cleanup: CleanupSummary,
    },
    Interrupted {
        signal: Interruption,
        child_after_termination: Option<ChildTermination>,
        cleanup: CleanupSummary,
    },
    MonitorFailed {
        error: String,
        child_after_termination: Option<ChildTermination>,
        cleanup: CleanupSummary,
    },
}

impl RunOutcome {
    pub const fn cleanup(&self) -> &CleanupSummary {
        match self {
            Self::Exited { cleanup, .. }
            | Self::LimitExceeded { cleanup, .. }
            | Self::Interrupted { cleanup, .. }
            | Self::MonitorFailed { cleanup, .. } => cleanup,
        }
    }

    pub fn cleanup_mut(&mut self) -> &mut CleanupSummary {
        match self {
            Self::Exited { cleanup, .. }
            | Self::LimitExceeded { cleanup, .. }
            | Self::Interrupted { cleanup, .. }
            | Self::MonitorFailed { cleanup, .. } => cleanup,
        }
    }
}
