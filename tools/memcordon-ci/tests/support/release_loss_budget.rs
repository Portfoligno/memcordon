use std::time::{Duration, Instant};

// Preserve the original finite harness scheduling allowance for each required
// phase. This is a scenario envelope, not a per-request latency guarantee:
// readiness; publication (draft/assets/registry/visibility and body readback);
// independent exposed-body verification; and a full no-write publication retry.
pub const PHASE_ALLOWANCE: Duration = Duration::from_secs(15);
pub const RETIREMENT_ALLOWANCE: Duration = Duration::from_secs(5);
pub const PHASES: [&str; 4] = [
    "readiness",
    "initial-publication",
    "independent-readback",
    "idempotent-publication",
];

pub fn work_allowance() -> Duration {
    PHASES.iter().fold(Duration::ZERO, |total, _| {
        total
            .checked_add(PHASE_ALLOWANCE)
            .expect("finite loss scenario phase sum")
    })
}

pub struct ScenarioClock {
    pub started: Instant,
    pub readiness: Instant,
    pub work: Instant,
    pub work_unix_ms: u64,
}

impl ScenarioClock {
    pub fn admits_readiness(&self, observed: Instant) -> bool {
        observed < self.readiness
    }

    pub fn from_start(started: Instant, started_unix_ms: u64) -> Self {
        let work = work_allowance();
        Self {
            started,
            readiness: started
                .checked_add(PHASE_ALLOWANCE)
                .expect("finite readiness cutoff"),
            work: started.checked_add(work).expect("finite work cutoff"),
            work_unix_ms: started_unix_ms
                .checked_add(u64::try_from(work.as_millis()).expect("finite work milliseconds"))
                .expect("finite wall-clock work cutoff"),
        }
    }
}
