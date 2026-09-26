//! Portable readback of the original nonroot caller exchange. This is a
//! diagnostic value, not a family capability: completed replay must additionally
//! join independently held caller credentials and a distinct no-allocation
//! physical interval. Neither a rejection label nor this parser grants authority.

use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::provider_rejection_wire::{RejectionPhaseV1, RejectionWireV1};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

const SELECTOR: &str = "private_tcp::caller_identity_and_epoch_bound";
const MAX_CALLER_BYTES: usize = 128 * 1024;
const MAX_FRAME_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallerIdentityV1 {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentCallerAdmissionV2 {
    pub schema_version: u8,
    pub protocol: String,
    pub parent_result_key: DiagnosticSha256,
    pub challenge: [u8; 32],
    pub spoof_result_key: DiagnosticSha256,
    pub spoof_challenge: [u8; 32],
    pub installation_epoch: DiagnosticSha256,
    pub candidate_manifest_sha256: DiagnosticSha256,
    pub installed_inspection_sha256: DiagnosticSha256,
    pub service_generation_sha256: DiagnosticSha256,
    pub coordinator: CallerIdentityV1,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub admission_monotonic_ns: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentCallerReadyV1 {
    pub schema_version: u8,
    pub protocol: String,
    pub parent_result_key: DiagnosticSha256,
    pub admission_sha256: DiagnosticSha256,
    pub caller: CallerIdentityV1,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub control_group_gid: u32,
    pub request_frame_sha256: DiagnosticSha256,
    pub ready_monotonic_ns: u64,
}

pub fn caller_spoof_challenge_v1(parent: &[u8; 32]) -> [u8; 32] {
    let mut bytes = b"memcordon-private-caller-spoof-v1\0".to_vec();
    bytes.extend_from_slice(parent);
    *hash_bytes(&bytes).bytes()
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCallerFrameReadbackV1 {
    pub caller: CallerIdentityV1,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub control_group_gid: u32,
    pub spoof_result_key: DiagnosticSha256,
    pub rejection_sha256: DiagnosticSha256,
    pub request_frame_bytes: Vec<u8>,
    pub response_frame_bytes: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CallerRequestV1 {
    schema_version: u8,
    stage: String,
    selector: String,
    challenge: [u8; 32],
    result_key: DiagnosticSha256,
}

struct FrameV4 {
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: Vec<u8>,
}

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn word<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    cursor.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn frame(bytes: &[u8]) -> Result<FrameV4> {
    const HEADER_BYTES: usize = 2 + 2 + 4 + 16 + 16 + 32;
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_FRAME_BYTES {
        return fail("caller original network frame size differs");
    }
    let mut cursor = Cursor::new(bytes);
    let version = u16::from_be_bytes(word(&mut cursor)?);
    let kind = u16::from_be_bytes(word(&mut cursor)?);
    let size = u32::from_be_bytes(word(&mut cursor)?) as usize;
    let nonce = word(&mut cursor)?;
    let attempt = word(&mut cursor)?;
    let digest: [u8; 32] = word(&mut cursor)?;
    let mut payload = Vec::new();
    cursor.read_to_end(&mut payload)?;
    if version != 4
        || size != bytes.len()
        || nonce == [0; 16]
        || attempt == [0; 16]
        || hash_bytes(&payload).bytes() != &digest
    {
        return fail("caller exact version/context/length/payload digest differs");
    }
    Ok(FrameV4 {
        kind,
        nonce,
        attempt,
        payload,
    })
}

pub fn parse_candidate_caller_frames_v1(
    bytes: &[u8],
    parent_challenge: &[u8; 32],
    expected_uid: u32,
    expected_gid: u32,
) -> Result<CandidateCallerFrameReadbackV1> {
    let parsed: CandidateCallerFrameReadbackV1 =
        crate::private_observer_session::strict_json(bytes, MAX_CALLER_BYTES)?;
    let challenge = caller_spoof_challenge_v1(parent_challenge);
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        SELECTOR,
        &challenge,
    )
    .map_err(CiError::Message)?;
    if expected_uid == 0
        || expected_gid == 0
        || parent_challenge == &[0; 32]
        || parsed.caller.pid == 0
        || parsed.caller.start_time == 0
        || parsed.caller_uid != expected_uid
        || parsed.caller_gid != expected_gid
        || parsed.control_group_gid == 0
        || parsed.spoof_result_key != key
        || serde_json::to_vec(&parsed)? != bytes
    {
        return fail("caller original pinned source identity/key/encoding differs");
    }
    let request = frame(&parsed.request_frame_bytes)?;
    let response = frame(&parsed.response_frame_bytes)?;
    let raw_request: CallerRequestV1 =
        crate::private_observer_session::strict_json(&request.payload, 4096)?;
    if request.kind != 15
        || response.kind != 106
        || request.nonce != response.nonce
        || request.attempt != response.attempt
        || raw_request.schema_version != 1
        || raw_request.stage != "candidate-capability"
        || raw_request.selector != SELECTOR
        || raw_request.challenge != challenge
        || raw_request.result_key != key
        || serde_json::to_vec(&raw_request)? != request.payload
        || hash_bytes(&response.payload) != parsed.rejection_sha256
    {
        return fail("caller exact original request/rejection frame linkage differs");
    }
    let rejection = RejectionWireV1::parse(&response.payload).map_err(CiError::Message)?;
    if rejection.code != "MCSEALED-PRIVATE-RELEASE-AUTHORIZATION"
        || rejection.phase != RejectionPhaseV1::RequestValidation
        || rejection.target_created
        || rejection.target_released
        || rejection.cleanup.attempted
        || rejection.workload_admission.is_some()
        || rejection.os_code.is_some()
    {
        return fail("caller actual typed pre-allocation authorization rejection differs");
    }
    Ok(parsed)
}
