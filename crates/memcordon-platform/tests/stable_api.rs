//! Downstream consumer crate: compile public backend signatures without launching work.
use memcordon_core::{BackendCapabilityReport, BoundaryRequirement, Error, SupervisionExecution};
use memcordon_platform::{BackendInfo, ProbeReport, SupervisorRequest};

#[test]
fn stable_backend_entrypoints_keep_their_public_types() {
    let _: fn() -> ProbeReport = memcordon_platform::probe;
    let _: fn(&BackendInfo) -> BackendCapabilityReport = memcordon_platform::capabilities;
    let _: fn(&BackendInfo, BoundaryRequirement) -> BackendCapabilityReport =
        memcordon_platform::capabilities_for;
    let _: fn(SupervisorRequest) -> Result<SupervisionExecution, Error> =
        memcordon_platform::supervise;
    let _: fn(bool) -> Result<Vec<String>, Error> = memcordon_platform::cleanup_stale;
    assert!(std::mem::size_of::<SupervisorRequest>() > 0);
}
