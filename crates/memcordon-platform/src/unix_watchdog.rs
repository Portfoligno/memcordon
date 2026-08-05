use memcordon_core::{CommandSpec, Error, ErrorCategory, Policy};

use crate::backend::{Execution, ProbeReport, UnavailableBackend};

pub fn probe() -> ProbeReport {
    ProbeReport {
        selected: None,
        available: Vec::new(),
        unavailable: vec![UnavailableBackend {
            name: "generic-unix",
            reason: "no truthful platform-specific metric collector is implemented".to_owned(),
        }],
    }
}

#[allow(
    clippy::result_large_err,
    reason = "execution preserves the public categorized Error contract on unsupported Unix targets"
)]
pub fn run(_policy: Policy, _command: &CommandSpec) -> Result<Execution, Error> {
    Err(Error::new(
        ErrorCategory::Unsupported,
        "MCUNSUPPORTED-UNIX",
        "this Unix target has no implemented metric collector; no target was launched",
    ))
}
