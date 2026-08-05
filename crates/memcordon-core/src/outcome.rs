use serde::{Deserialize, Serialize};

use crate::ByteSize;
use crate::DeadlineScope;

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeadlineEvidence {
    duration_ms: u64,
    scope: DeadlineScope,
    origin: String,
    overshoot_ms: u64,
    expires_offset_ms: u64,
    observed_offset_ms: u64,
    grace_requested_ms: u64,
    grace_elapsed_ms: u64,
    graceful_action: Option<String>,
    force_action: Option<String>,
}

impl DeadlineEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        duration_ms: u64,
        scope: DeadlineScope,
        origin: String,
        expires_offset_ms: u64,
        observed_offset_ms: u64,
        grace_requested_ms: u64,
        grace_elapsed_ms: u64,
        graceful_action: Option<String>,
        force_action: Option<String>,
    ) -> Result<Self, DeadlineEvidenceError> {
        if duration_ms == 0
            || origin.is_empty()
            || observed_offset_ms < expires_offset_ms
            || grace_elapsed_ms > grace_requested_ms
            || (grace_elapsed_ms > 0 && graceful_action.is_none())
        {
            return Err(DeadlineEvidenceError);
        }
        Ok(Self {
            duration_ms,
            scope,
            origin,
            overshoot_ms: observed_offset_ms - expires_offset_ms,
            expires_offset_ms,
            observed_offset_ms,
            grace_requested_ms,
            grace_elapsed_ms,
            graceful_action,
            force_action,
        })
    }

    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }
    pub const fn scope(&self) -> DeadlineScope {
        self.scope
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub const fn overshoot_ms(&self) -> u64 {
        self.overshoot_ms
    }
    pub const fn expires_offset_ms(&self) -> u64 {
        self.expires_offset_ms
    }
    pub const fn observed_offset_ms(&self) -> u64 {
        self.observed_offset_ms
    }
    pub const fn grace_requested_ms(&self) -> u64 {
        self.grace_requested_ms
    }
    pub const fn grace_elapsed_ms(&self) -> u64 {
        self.grace_elapsed_ms
    }
    pub fn graceful_action(&self) -> Option<&str> {
        self.graceful_action.as_deref()
    }
    pub fn force_action(&self) -> Option<&str> {
        self.force_action.as_deref()
    }
}

impl<'de> Deserialize<'de> for DeadlineEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            duration_ms: u64,
            scope: DeadlineScope,
            origin: String,
            overshoot_ms: u64,
            expires_offset_ms: u64,
            observed_offset_ms: u64,
            grace_requested_ms: u64,
            grace_elapsed_ms: u64,
            graceful_action: Option<String>,
            force_action: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let evidence = Self::new(
            wire.duration_ms,
            wire.scope,
            wire.origin,
            wire.expires_offset_ms,
            wire.observed_offset_ms,
            wire.grace_requested_ms,
            wire.grace_elapsed_ms,
            wire.graceful_action,
            wire.force_action,
        )
        .map_err(serde::de::Error::custom)?;
        if evidence.overshoot_ms != wire.overshoot_ms {
            return Err(serde::de::Error::custom(
                "deadline overshoot does not match offsets",
            ));
        }
        Ok(evidence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineEvidenceError;

impl std::fmt::Display for DeadlineEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("deadline evidence offsets or grace fields are inconsistent")
    }
}

impl std::error::Error for DeadlineEvidenceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptEventKind {
    MemoryLimit,
    Deadline,
    MonitorFailure,
    Interruption,
    Completion,
}

impl AttemptEventKind {
    pub const fn precedence(self) -> u8 {
        match self {
            Self::MemoryLimit => 0,
            Self::Deadline => 1,
            Self::MonitorFailure => 2,
            Self::Interruption => 3,
            Self::Completion => 4,
        }
    }

    pub fn select(events: impl IntoIterator<Item = Self>) -> Option<Self> {
        events.into_iter().min_by_key(|event| event.precedence())
    }
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
    DeadlineExceeded {
        deadline: DeadlineEvidence,
        child_after_termination: Option<ChildTermination>,
        peak: Option<ByteSize>,
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
            | Self::DeadlineExceeded { cleanup, .. }
            | Self::Interrupted { cleanup, .. }
            | Self::MonitorFailed { cleanup, .. } => cleanup,
        }
    }

    pub fn cleanup_mut(&mut self) -> &mut CleanupSummary {
        match self {
            Self::Exited { cleanup, .. }
            | Self::LimitExceeded { cleanup, .. }
            | Self::DeadlineExceeded { cleanup, .. }
            | Self::Interrupted { cleanup, .. }
            | Self::MonitorFailed { cleanup, .. } => cleanup,
        }
    }
}
