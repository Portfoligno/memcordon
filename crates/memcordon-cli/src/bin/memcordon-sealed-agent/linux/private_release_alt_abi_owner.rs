//! Closed protected worker for the x86 alternate-ABI subwitness. This owns
//! only two filtered child probes, not a V4 candidate target or case result.

use std::os::fd::AsFd;

use memcordon_core::DiagnosticSha256;

use super::private_attempt::ProcessIdentityV4;
use super::private_release_alt_abi::{SELECTOR, observe_x32_subwitness};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClosedX32OwnerObservationV1 {
    pub(crate) worker: ProcessIdentityV4,
    pub(crate) witness_sha256: DiagnosticSha256,
    pub(crate) raw_sha256: DiagnosticSha256,
}

/// The fixed protected M0 request and two pidfd children are revalidated
/// before immutable raw persistence. Nothing here enters the 25-case result
/// constructor; ARM64 AArch32 proof is still absent.
#[allow(dead_code)] // Closed until a separately reviewed aggregate route exists.
pub(crate) fn execute_closed_x32_owner(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<ClosedX32OwnerObservationV1, String> {
    if case.selector() != SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 owner selector differs".into());
    }
    case.revalidate()?;
    let worker_pidfd = super::private_execution::pidfd_for_self()?;
    // SAFETY: getpid returns only this protected worker's process ID.
    let worker_pid = unsafe { libc::getpid() };
    let worker = ProcessIdentityV4::observe(worker_pid, worker_pidfd.as_fd())?;
    let witness = observe_x32_subwitness(case)?;
    if worker == witness.native || worker == witness.alternate {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child aliases protected worker".into());
    }
    case.revalidate()?;
    let raw_sha256 =
        super::private_release_alt_abi_raw::persist_closed_x32_raw(case, &worker, &witness)?;
    Ok(ClosedX32OwnerObservationV1 {
        worker,
        witness_sha256: witness.digest()?,
        raw_sha256,
    })
}
