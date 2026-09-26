//! Closed ARM32 alternate-ABI worker. It writes a protected raw attachment,
//! not a successful V4 case result or publishable qualification.

use std::os::fd::AsFd;

use memcordon_core::DiagnosticSha256;

use super::private_attempt::ProcessIdentityV4;
use super::private_release_alt_abi::SELECTOR;
use super::private_release_arm32_abi::observe_arm32_subwitness;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClosedArm32OwnerObservationV1 {
    pub(crate) worker: ProcessIdentityV4,
    pub(crate) witness_sha256: DiagnosticSha256,
    pub(crate) raw_sha256: DiagnosticSha256,
}

#[allow(dead_code)] // Independent kernel-event observer and aggregate are required.
pub(crate) fn execute_closed_arm32_owner(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<ClosedArm32OwnerObservationV1, String> {
    if case.selector() != SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 owner selector differs".into());
    }
    case.revalidate()?;
    let worker_pidfd = super::private_execution::pidfd_for_self()?;
    // SAFETY: getpid returns this protected worker's process ID only.
    let worker_pid = unsafe { libc::getpid() };
    let worker = ProcessIdentityV4::observe(worker_pid, worker_pidfd.as_fd())?;
    let witness = observe_arm32_subwitness(case)?;
    if worker == witness.native || worker == witness.outer_control || worker == witness.filtered {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 child aliases protected worker".into());
    }
    case.revalidate()?;
    let raw_sha256 =
        super::private_release_arm32_abi_raw::persist_closed_arm32_raw(case, &worker, &witness)?;
    Ok(ClosedArm32OwnerObservationV1 {
        worker,
        witness_sha256: witness.digest()?,
        raw_sha256,
    })
}
