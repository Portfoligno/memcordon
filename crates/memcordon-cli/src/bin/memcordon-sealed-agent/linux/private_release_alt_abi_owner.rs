//! Closed protected worker for x86 alternate-ABI subwitnesses. This owns
//! five distinct child probes, not a V4 candidate target or case result.

use std::os::fd::AsFd;

use memcordon_core::DiagnosticSha256;

use super::private_attempt::ProcessIdentityV4;
use super::private_release_alt_abi::{
    SELECTOR, observe_i386_entry_subwitness, observe_x32_subwitness,
};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClosedX32OwnerObservationV1 {
    pub(crate) worker: ProcessIdentityV4,
    pub(crate) witness_sha256: DiagnosticSha256,
    pub(crate) raw_sha256: DiagnosticSha256,
    pub(crate) i386_raw_sha256: DiagnosticSha256,
}

/// The fixed protected M0 request and five pidfd children are revalidated
/// before immutable raw persistence. Nothing here enters the 25-case result
/// constructor; the aggregate independent kernel join remains closed.
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
    if worker == witness.native || worker == witness.outer_control || worker == witness.alternate {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child aliases protected worker".into());
    }
    case.revalidate()?;
    let raw_sha256 =
        super::private_release_alt_abi_raw::persist_closed_x32_raw(case, &worker, &witness)?;
    let i386 = observe_i386_entry_subwitness(case)?;
    if [
        &worker,
        &witness.native,
        &witness.outer_control,
        &witness.alternate,
    ]
    .iter()
    .any(|identity| **identity == i386.outer_control || **identity == i386.filtered)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 child aliases x32 branch".into());
    }
    case.revalidate()?;
    let i386_raw_sha256 = super::private_release_i386_raw::persist_i386_raw(case, &worker, &i386)?;
    Ok(ClosedX32OwnerObservationV1 {
        worker,
        witness_sha256: witness.digest()?,
        raw_sha256,
        i386_raw_sha256,
    })
}
