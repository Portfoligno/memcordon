//! Protected raw custody for the ARM32 half of the alternate-ABI case.
//! This record is deliberately not a case completion: an independent kernel
//! observer must still join the exec and seccomp decision events.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_alt_abi::SELECTOR;
use super::private_release_alt_abi_raw::{read_immutable, write_immutable};
use super::private_release_arm32_abi::Arm32AlternateAbiSubwitnessV1;
use super::private_release_case::{ReleaseCaseRequestV1, ReleaseStageV1};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

const RAW_LEAF: &str = "arm32-alternate.raw.json";
const TEMP_LEAF: &str = "arm32-alternate.raw.json.new";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedArm32RawV1 {
    schema: u32,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    installed_inspection_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    helper_sha256: DiagnosticSha256,
    worker: ProcessIdentityV4,
    witness: Arm32AlternateAbiSubwitnessV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DetachedArm32RawReadbackV1 {
    pub(crate) raw_sha256: DiagnosticSha256,
    pub(crate) worker: ProcessIdentityV4,
    pub(crate) witness: Arm32AlternateAbiSubwitnessV1,
}

/// The retained candidate authority supplies all expected hashes. A writable
/// request or a caller-provided JSON record cannot mint this raw attachment.
#[allow(dead_code)] // Composite ABI routing awaits independent event coverage.
pub(crate) fn persist_closed_arm32_raw(
    case: &ReleaseCandidateRunAuthorityV1,
    worker: &ProcessIdentityV4,
    witness: &Arm32AlternateAbiSubwitnessV1,
) -> Result<DiagnosticSha256, String> {
    if case.selector() != SELECTOR || worker.pid == 0 || worker.start_time == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 raw authority differs".into());
    }
    case.revalidate()?;
    let helper_sha256 = DiagnosticSha256::try_from(
        memcordon_core::BoundedText::new(&case.installed_arm32_helper_digest()?)
            .map_err(str::to_owned)?,
    )
    .map_err(str::to_owned)?;
    witness.verify_binding(
        &case.challenge_bytes(),
        &helper_sha256,
        case.filter_digest(),
    )?;
    let record = ProtectedArm32RawV1 {
        schema: 1,
        selector: SELECTOR.into(),
        result_key: case.protected_result_key()?.clone(),
        challenge_sha256: hash_bytes(&case.challenge_bytes()),
        installed_inspection_sha256: hash_bytes(&case.installed_inspection_bytes()?),
        filter_sha256: case.filter_digest().clone(),
        helper_sha256,
        worker: worker.clone(),
        witness: witness.clone(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
    if bytes.len() > 4096 {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 raw exceeds bound".into());
    }
    write_immutable(
        case.protected_case_directory()?,
        RAW_LEAF,
        TEMP_LEAF,
        &bytes,
    )?;
    case.revalidate()?;
    Ok(hash_bytes(&bytes))
}

/// Expected worker/coordinator identities and installed bytes arrive from
/// detached custody, not from the raw record being checked.
#[allow(dead_code)] // Composite ABI routing awaits independent event coverage.
pub(crate) fn readback_closed_arm32_raw(
    directory: &File,
    request: &ReleaseCaseRequestV1,
    expected_filter: &DiagnosticSha256,
    expected_helper: &DiagnosticSha256,
    expected_installed_inspection: &DiagnosticSha256,
    expected_worker: &ProcessIdentityV4,
    expected_coordinator: &ProcessIdentityV4,
) -> Result<DetachedArm32RawReadbackV1, String> {
    if !cfg!(target_arch = "aarch64")
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != SELECTOR
    {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 detached selector differs".into());
    }
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 detached directory differs".into());
    }
    let bytes = read_immutable(directory, RAW_LEAF, TEMP_LEAF)?;
    let record: ProtectedArm32RawV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if serde_json::to_vec(&record).map_err(|error| error.to_string())? != bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 raw is not canonical".into());
    }
    record
        .witness
        .verify_binding(&request.challenge, expected_helper, expected_filter)?;
    if record.schema != 1
        || record.selector != SELECTOR
        || record.result_key != request.result_key()
        || record.challenge_sha256 != hash_bytes(&request.challenge)
        || record.installed_inspection_sha256 != *expected_installed_inspection
        || record.filter_sha256 != *expected_filter
        || record.helper_sha256 != *expected_helper
        || record.worker != *expected_worker
        || expected_worker == expected_coordinator
        || expected_worker == &record.witness.native
        || expected_worker == &record.witness.outer_control
        || expected_worker == &record.witness.filtered
        || expected_coordinator == &record.witness.native
        || expected_coordinator == &record.witness.outer_control
        || expected_coordinator == &record.witness.filtered
    {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 detached raw binding differs".into());
    }
    super::private_release_run::require_recorded_process_exited(expected_worker)?;
    super::private_release_run::require_recorded_process_exited(expected_coordinator)?;
    Ok(DetachedArm32RawReadbackV1 {
        raw_sha256: hash_bytes(&bytes),
        worker: record.worker,
        witness: record.witness,
    })
}
