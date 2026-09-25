//! Closed AF_UNIX candidate owner. Its typed entrypoint deliberately has no
//! service or selector dispatch until native and independent CI joins exist.

use memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1;

use super::private_release_execution::CandidateNativeObservationV1;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

pub(crate) struct ClosedUnixIntentOwnerObservationV1 {
    pub(crate) native: CandidateNativeObservationV1,
    pub(crate) worker_inventory: Vec<PrivateReleaseAttachmentV1>,
}

pub(crate) fn execute_and_persist(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<ClosedUnixIntentOwnerObservationV1, String> {
    if case.selector() != super::private_release_unix_intent::SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix intent owner selector differs".into());
    }
    let native = super::private_release_execution::execute_closed_unix_intent_case(case)?;
    let worker_inventory = case.persist_closed_unix_intent_raw_observation(&native)?;
    Ok(ClosedUnixIntentOwnerObservationV1 {
        native,
        worker_inventory,
    })
}
