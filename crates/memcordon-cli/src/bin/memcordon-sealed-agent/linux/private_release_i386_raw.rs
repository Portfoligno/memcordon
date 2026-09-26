//! Immutable i386 int-0x80 control/filtered branch beside the x32 raw leaf.
//! This is a subwitness, not a completed ABI release-case result.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_alt_abi::{I386AlternateAbiSubwitnessV1, SELECTOR};
use super::private_release_case::{ReleaseCaseRequestV1, ReleaseStageV1};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

pub(crate) const RAW_LEAF: &str = "i386-entry.raw.json";
const TEMP_LEAF: &str = "i386-entry.raw.json.new";
const MAX_RAW_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedI386RawV1 {
    schema: u32,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    installed_inspection_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    worker: ProcessIdentityV4,
    witness: I386AlternateAbiSubwitnessV1,
}

pub(crate) struct DetachedI386RawReadbackV1 {
    pub(crate) raw_sha256: DiagnosticSha256,
    pub(crate) witness: I386AlternateAbiSubwitnessV1,
}

pub(crate) fn persist_i386_raw(
    case: &ReleaseCandidateRunAuthorityV1,
    worker: &ProcessIdentityV4,
    witness: &I386AlternateAbiSubwitnessV1,
) -> Result<DiagnosticSha256, String> {
    if case.selector() != SELECTOR || worker.pid == 0 || worker.start_time == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 raw authority differs".into());
    }
    case.revalidate()?;
    witness.verify_binding(&case.challenge_bytes(), case.filter_digest())?;
    if *worker == witness.outer_control || *worker == witness.filtered {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 child aliases worker".into());
    }
    let record = ProtectedI386RawV1 {
        schema: 1,
        selector: SELECTOR.into(),
        result_key: case.protected_result_key()?.clone(),
        challenge_sha256: hash_bytes(&case.challenge_bytes()),
        installed_inspection_sha256: hash_bytes(&case.installed_inspection_bytes()?),
        filter_sha256: case.filter_digest().clone(),
        worker: worker.clone(),
        witness: witness.clone(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_RAW_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 raw exceeds bound".into());
    }
    super::private_release_alt_abi_raw::write_immutable(
        case.protected_case_directory()?,
        RAW_LEAF,
        TEMP_LEAF,
        &bytes,
    )?;
    case.revalidate()?;
    Ok(hash_bytes(&bytes))
}

pub(crate) fn readback_i386_raw(
    directory: &File,
    request: &ReleaseCaseRequestV1,
    expected_filter: &DiagnosticSha256,
    expected_inspection: &DiagnosticSha256,
    expected_worker: &ProcessIdentityV4,
    expected_coordinator: &ProcessIdentityV4,
) -> Result<DetachedI386RawReadbackV1, String> {
    if !cfg!(target_arch = "x86_64")
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != SELECTOR
    {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 detached selector differs".into());
    }
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 directory differs".into());
    }
    let bytes = super::private_release_alt_abi_raw::read_immutable(directory, RAW_LEAF, TEMP_LEAF)?;
    if bytes.len() > MAX_RAW_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 raw length differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let record: ProtectedI386RawV1 = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if serde_json::to_vec(&record).map_err(|e| e.to_string())? != bytes
        || record.schema != 1
        || record.selector != SELECTOR
        || record.result_key != request.result_key()
        || record.challenge_sha256 != hash_bytes(&request.challenge)
        || record.installed_inspection_sha256 != *expected_inspection
        || record.filter_sha256 != *expected_filter
        || record.worker != *expected_worker
        || expected_worker == expected_coordinator
        || record.witness.outer_control == *expected_worker
        || record.witness.filtered == *expected_worker
        || record.witness.outer_control == *expected_coordinator
        || record.witness.filtered == *expected_coordinator
    {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 detached raw differs".into());
    }
    record
        .witness
        .verify_binding(&request.challenge, expected_filter)?;
    super::private_release_run::require_recorded_process_exited(expected_worker)?;
    super::private_release_run::require_recorded_process_exited(expected_coordinator)?;
    Ok(DetachedI386RawReadbackV1 {
        raw_sha256: hash_bytes(&bytes),
        witness: record.witness,
    })
}
