//! Closed i386 alternate-entry probe. The outer-policy-only control and the
//! private-filtered child use the same fixed `int 0x80` getpid instruction.
//! This subwitness is not a release-case result or qualification authority.

use super::private_release_alt_abi::{I386AlternateAbiSubwitnessV1, observe_i386_entry_subwitness};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

#[allow(dead_code)]
pub(crate) fn observe_i386_subwitness(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<I386AlternateAbiSubwitnessV1, String> {
    observe_i386_entry_subwitness(case)
}
