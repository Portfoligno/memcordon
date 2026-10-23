//! The two original recovery owners must retire before orphan recovery starts.
use memcordon_readiness_verifier::HeldProcessIdentity;
use serde::Serialize;
use std::time::Instant;

#[derive(Clone, Debug, Serialize)]
pub struct Owners {
    pub frontend: HeldProcessIdentity,
    pub worker: HeldProcessIdentity,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub before: Owners,
    pub after: Owners,
    pub retired: bool,
    pub reason: String,
}

fn same(original: &HeldProcessIdentity, current: &HeldProcessIdentity) -> bool {
    (
        original.pid,
        original.birth,
        original.parent_pid,
        original.parent_birth,
    ) == (
        current.pid,
        current.birth,
        current.parent_pid,
        current.parent_birth,
    )
}

/// `observe` samples the already-held original pidfds; it must never reopen PIDs.
/// Target/init/guardian are intentionally absent: recovery may own their cleanup.
pub fn await_retirement(
    before: Owners,
    cutoff: Instant,
    mut observe: impl FnMut() -> Result<Owners, String>,
) -> Observation {
    let mut after = before.clone();
    if before.frontend.pid == 0
        || before.frontend.birth == 0
        || before.worker.pid == 0
        || before.worker.birth == 0
        || (before.frontend.pid, before.frontend.birth) == (before.worker.pid, before.worker.birth)
    {
        return Observation {
            before,
            after,
            retired: false,
            reason: "original recovery owner identities are invalid or aliased".into(),
        };
    }
    let reason = loop {
        if Instant::now() >= cutoff {
            break "original cleanup cutoff expired before recovery owner retirement".into();
        }
        after = match observe() {
            Ok(value) => value,
            Err(error) => break format!("held recovery owner observation failed: {error}"),
        };
        if !same(&before.frontend, &after.frontend) || !same(&before.worker, &after.worker) {
            break "original recovery owner identity changed".into();
        }
        if after.frontend.retirement_observed && after.worker.retirement_observed {
            if Instant::now() >= cutoff {
                break "original cleanup cutoff expired at recovery owner retirement".into();
            }
            return Observation {
                before,
                after,
                retired: true,
                reason: "both original held owners retired".into(),
            };
        }
        std::thread::sleep(
            cutoff
                .saturating_duration_since(Instant::now())
                .min(std::time::Duration::from_millis(1)),
        );
    };
    Observation {
        before,
        after,
        retired: false,
        reason,
    }
}
