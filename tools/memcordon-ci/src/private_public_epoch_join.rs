//! Typed final-public E0→E1 join. Structural provider JSON alone cannot
//! establish either a live target or a rejected spoofed peer.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::provider_rejection_wire::RejectionWireV1;
use memcordon_core::workload_codec::hash_bytes;
use serde::Deserialize;

use crate::{CiError, Result};

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

pub struct ExpectedSameArchiveEpochV1<'a> {
    pub e0_installation_epoch: &'a DiagnosticSha256,
    pub e1_installation_epoch: &'a DiagnosticSha256,
    pub e0_h1_receipt_sha256: &'a DiagnosticSha256,
    pub e1_h1_receipt_sha256: &'a DiagnosticSha256,
    pub e0_challenge: &'a str,
    pub e1_challenge: &'a str,
    pub protected_archive_sha256: &'a DiagnosticSha256,
    pub upgrade_archive_sha256: &'a DiagnosticSha256,
}

/// This is a necessary structural join, not a completed historical P proof.
pub fn validate_same_archive_epoch_transition_v1(
    input: &ExpectedSameArchiveEpochV1<'_>,
) -> Result<()> {
    let zero = DiagnosticSha256::from_bytes([0; 32]);
    if input.e0_installation_epoch == &zero
        || input.e1_installation_epoch == &zero
        || input.e0_h1_receipt_sha256 == &zero
        || input.e1_h1_receipt_sha256 == &zero
        || input.e0_installation_epoch == input.e1_installation_epoch
        || input.e0_h1_receipt_sha256 == input.e1_h1_receipt_sha256
        || input.e0_challenge == input.e1_challenge
        || input.protected_archive_sha256 == &zero
        || input.protected_archive_sha256 != input.upgrade_archive_sha256
    {
        return Err(fail("public historical same-A epoch/H1 transition differs"));
    }
    for challenge in [input.e0_challenge, input.e1_challenge] {
        if challenge.len() != 64
            || !challenge
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || challenge.bytes().all(|byte| byte == b'0')
        {
            return Err(fail("public historical challenge syntax differs"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedPublicSpoofV1 {
    schema_version: u8,
    selector: String,
    challenge: String,
    result_key: DiagnosticSha256,
    authenticated_peer_uid: u32,
    authenticated_peer_gid: u32,
    authenticated_peer_pid: u32,
    authenticated_peer_start_ticks: u64,
    authorized_uid: u32,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    contract_file_sha256: DiagnosticSha256,
    grant_decision_sha256: DiagnosticSha256,
    request_sha256: DiagnosticSha256,
    rejection_sha256: DiagnosticSha256,
    rejection_code: String,
    durable_attempt_record_absent: bool,
}

/// Expected values are supplied by the protected dispatch intent and E1 H1,
/// never by the presented spoof record. The producer must write this record
/// under root-only custody from SO_PEERCRED and exact response bytes.
pub struct ExpectedPublicSpoofV1<'a> {
    pub selector: &'a str,
    pub challenge: &'a str,
    pub result_key: &'a DiagnosticSha256,
    pub authorized_uid: u32,
    pub unauthorized_uid: u32,
    pub unauthorized_gid: u32,
    pub registered_peer_pid: u32,
    pub registered_peer_start_ticks: u64,
    pub installation_epoch: &'a DiagnosticSha256,
    pub active_h1_receipt_sha256: &'a DiagnosticSha256,
    pub request_bytes: &'a [u8],
    pub grant_decision_bytes: &'a [u8],
    pub rejection_code: &'a str,
}

pub fn validate_protected_public_spoof_v1(
    record_bytes: &[u8],
    rejection_bytes: &[u8],
    expected: &ExpectedPublicSpoofV1<'_>,
) -> Result<()> {
    if record_bytes.is_empty() || record_bytes.len() > 16 * 1024 {
        return Err(fail("public spoof protected record byte bound differs"));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(record_bytes)
        .map_err(CiError::Message)?;
    let record: ProtectedPublicSpoofV1 = serde_json::from_slice(record_bytes)?;
    let rejection = RejectionWireV1::parse(rejection_bytes).map_err(CiError::Message)?;
    if expected.request_bytes.is_empty()
        || expected.request_bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
        || expected.grant_decision_bytes.is_empty()
        || expected.grant_decision_bytes.len() > 128 * 1024
    {
        return Err(fail("public spoof protected input byte bound differs"));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(expected.grant_decision_bytes)
        .map_err(CiError::Message)?;
    let _: serde_json::Value = serde_json::from_slice(expected.grant_decision_bytes)?;
    let challenge: [u8; 32] = hex::decode(expected.challenge)
        .map_err(|_| fail("public spoof challenge syntax differs"))?
        .try_into()
        .map_err(|_| fail("public spoof challenge length differs"))?;
    let derived = private_release_case_key_v1(
        PrivateReleaseStageV1::FinalPublic,
        expected.selector,
        &challenge,
    )
    .map_err(CiError::Message)?;
    if expected.selector != "private_tcp::caller_identity_and_epoch_bound"
        || expected.authorized_uid == 0
        || expected.unauthorized_uid == 0
        || expected.unauthorized_uid == expected.authorized_uid
        || expected.unauthorized_gid == 0
        || expected.registered_peer_pid == 0
        || expected.registered_peer_start_ticks == 0
        || expected.rejection_code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
        || record.schema_version != 1
        || record.selector != expected.selector
        || record.challenge != expected.challenge
        || record.result_key != derived
        || record.result_key != *expected.result_key
        || record.authenticated_peer_uid != expected.unauthorized_uid
        || record.authenticated_peer_gid != expected.unauthorized_gid
        || record.authenticated_peer_pid != expected.registered_peer_pid
        || record.authenticated_peer_start_ticks != expected.registered_peer_start_ticks
        || record.authorized_uid != expected.authorized_uid
        || record.installation_epoch != *expected.installation_epoch
        || record.active_h1_receipt_sha256 != *expected.active_h1_receipt_sha256
        || record.contract_file_sha256 != hash_bytes(expected.request_bytes)
        || record.grant_decision_sha256 != hash_bytes(expected.grant_decision_bytes)
        || record.request_sha256 != hash_bytes(expected.request_bytes)
        || record.rejection_sha256 != hash_bytes(rejection_bytes)
        || record.rejection_code != expected.rejection_code
        || rejection.code != record.rejection_code
        || rejection.phase
            != memcordon_core::provider_rejection_wire::RejectionPhaseV1::RequestValidation
        || rejection.target_created
        || rejection.target_released
        || rejection.cleanup.attempted
        || !rejection.cleanup.errors.is_empty()
        || !record.durable_attempt_record_absent
    {
        return Err(fail(
            "public spoof peer, H1, request or no-allocation denial differs",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub struct PublicEpochPositiveV1<'a> {
    pub selector: &'a str,
    pub challenge: &'a str,
    pub host: &'a crate::private_final_install::FinalHostReadbackV1,
    pub provider: &'a crate::private_public_dispatch::StructuralProviderFrameReadbackV2,
    pub kernel_join: &'a crate::private_public_kernel_join::VerifiedPublicCaseKernelJoinV1,
    pub interval: &'a crate::private_kernel_observer::VerifiedKernelIntervalV1,
}

#[cfg(target_os = "linux")]
pub struct ExpectedPublicEpochTransitionV1<'a> {
    pub e0: PublicEpochPositiveV1<'a>,
    pub e1: PublicEpochPositiveV1<'a>,
    pub protected_archive_sha256: &'a DiagnosticSha256,
    pub upgrade_archive_sha256: &'a DiagnosticSha256,
    pub replay_record_bytes: &'a [u8],
    pub replay_rejection_bytes: &'a [u8],
    pub replay_stdout: &'a [u8],
    pub replay_interval: &'a crate::private_kernel_observer::VerifiedKernelIntervalV1,
    pub spoof_record_bytes: &'a [u8],
    pub spoof_stdout: &'a [u8],
    pub spoof_request_bytes: &'a [u8],
    pub spoof_rejection_bytes: &'a [u8],
    pub spoof_expected: ExpectedPublicSpoofV1<'a>,
    pub spoof_interval: &'a crate::private_kernel_observer::VerifiedKernelIntervalV1,
}

#[cfg(target_os = "linux")]
pub(crate) struct VerifiedPublicEpochTransitionV1 {
    transcript_sha256: DiagnosticSha256,
    e1_installation_epoch: DiagnosticSha256,
    e1_h1_receipt_sha256: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
impl VerifiedPublicEpochTransitionV1 {
    pub(crate) fn transcript_sha256(&self) -> &DiagnosticSha256 {
        &self.transcript_sha256
    }
    pub(crate) fn e1_installation_epoch(&self) -> &DiagnosticSha256 {
        &self.e1_installation_epoch
    }
    pub(crate) fn e1_h1_receipt_sha256(&self) -> &DiagnosticSha256 {
        &self.e1_h1_receipt_sha256
    }
}

#[cfg(target_os = "linux")]
fn positive(input: &PublicEpochPositiveV1<'_>) -> Result<DiagnosticSha256> {
    let challenge: [u8; 32] = hex::decode(input.challenge)
        .map_err(|_| fail("public epoch control challenge differs"))?
        .try_into()
        .map_err(|_| fail("public epoch control challenge length differs"))?;
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::FinalPublic,
        input.selector,
        &challenge,
    )
    .map_err(CiError::Message)?;
    if input.provider.result_key != key
        || input.interval.result_key() != &key
        || input.interval.boot_id() != input.host.boot_id()
        || input.kernel_join.target_count() != 1
        || input.kernel_join.capture_sha256() != input.interval.trace_sha256()
        || input.provider.phase != "launch-exchanges-complete"
        || input.provider.attempts.len() != 1
        || input.provider.attempts[0].terminal_bytes.is_none()
        || input.provider.attempts[0].cleanup_bytes.is_none()
        || input.provider.attempts[0].target_identity_bytes.is_none()
    {
        return Err(fail(
            "public epoch positive provider/kernel control differs",
        ));
    }
    input.interval.verify_allocation(&key)?;
    let raw: serde_json::Value = serde_json::from_slice(&input.provider.record_bytes)?;
    if raw.get("selector").and_then(serde_json::Value::as_str) != Some(input.selector)
        || raw.get("challenge").and_then(serde_json::Value::as_str) != Some(input.challenge)
        || raw.get("installation_epoch")
            != Some(&serde_json::to_value(input.host.installation_epoch())?)
        || raw.get("active_h1_receipt_sha256")
            != Some(&serde_json::to_value(
                input.host.active_h1_receipt_sha256(),
            )?)
    {
        return Err(fail("public epoch positive H1/actor transcript differs"));
    }
    Ok(hash_bytes(&input.provider.record_bytes))
}

#[cfg(target_os = "linux")]
pub(crate) fn join_public_epoch_transition_v1(
    input: &ExpectedPublicEpochTransitionV1<'_>,
) -> Result<VerifiedPublicEpochTransitionV1> {
    let e0_digest = positive(&input.e0)?;
    let e1_digest = positive(&input.e1)?;
    validate_same_archive_epoch_transition_v1(&ExpectedSameArchiveEpochV1 {
        e0_installation_epoch: input.e0.host.installation_epoch(),
        e1_installation_epoch: input.e1.host.installation_epoch(),
        e0_h1_receipt_sha256: input.e0.host.active_h1_receipt_sha256(),
        e1_h1_receipt_sha256: input.e1.host.active_h1_receipt_sha256(),
        e0_challenge: input.e0.challenge,
        e1_challenge: input.e1.challenge,
        protected_archive_sha256: input.protected_archive_sha256,
        upgrade_archive_sha256: input.upgrade_archive_sha256,
    })?;
    if input.e0.selector != "private_tcp::caller_identity_and_epoch_bound"
        || input.e1.selector != "private_tcp::native_tcp_bind_listen_connect"
        || input.e0.host.boot_id() != input.e1.host.boot_id()
        || input.e0.interval.boot_id() != input.e1.interval.boot_id()
        || input.e0.interval.boot_id() != input.replay_interval.boot_id()
        || input.e0.interval.boot_id() != input.spoof_interval.boot_id()
        || input.e0.interval.kernel_release() != input.e1.interval.kernel_release()
        || input.e0.interval.kernel_release() != input.replay_interval.kernel_release()
        || input.e0.interval.kernel_release() != input.spoof_interval.kernel_release()
        || input.e0.interval.btf_sha256() != input.e1.interval.btf_sha256()
        || input.e0.interval.btf_sha256() != input.replay_interval.btf_sha256()
        || input.e0.interval.btf_sha256() != input.spoof_interval.btf_sha256()
        || input.e0.interval.probe_map_sha256() != input.e1.interval.probe_map_sha256()
        || input.e0.interval.probe_map_sha256() != input.replay_interval.probe_map_sha256()
        || input.e0.interval.probe_map_sha256() != input.spoof_interval.probe_map_sha256()
        || input.e0.host.source_commit() != input.e1.host.source_commit()
        || input.e0.host.target() != input.e1.host.target()
        || input.e0.host.manifest_sha256() != input.e1.host.manifest_sha256()
        || input.e0.host.qualification_sha256() != input.e1.host.qualification_sha256()
        || input.replay_stdout.strip_suffix(b"\n") != Some(input.replay_record_bytes)
        || input.replay_interval.result_key() != &input.e0.provider.result_key
    {
        return Err(fail("public historical same-A E0/E1 transition differs"));
    }
    let original = input.e0.provider.attempts[0].request_bytes.as_slice();
    crate::private_public_dispatch::validate_historical_public_epoch_replay_v1(
        input.replay_record_bytes,
        input.replay_rejection_bytes,
        &crate::private_public_dispatch::ExpectedHistoricalPublicEpochReplayV1 {
            selector: input.e0.selector,
            result_key: &input.e0.provider.result_key,
            original_request_bytes: original,
            e0_installation_epoch_sha256: input.e0.host.installation_epoch(),
            e0_h1_receipt_sha256: input.e0.host.active_h1_receipt_sha256(),
            e1_installation_epoch_sha256: input.e1.host.installation_epoch(),
            e1_h1_receipt_sha256: input.e1.host.active_h1_receipt_sha256(),
        },
    )?;
    input
        .replay_interval
        .verify_no_allocation(&input.e0.provider.result_key)?;
    if input.spoof_request_bytes != input.spoof_expected.request_bytes
        || input.spoof_stdout.strip_suffix(b"\n") != Some(input.spoof_record_bytes)
        || input.spoof_expected.installation_epoch != input.e1.host.installation_epoch()
        || input.spoof_expected.active_h1_receipt_sha256 != input.e1.host.active_h1_receipt_sha256()
        || input.spoof_expected.result_key == &input.e0.provider.result_key
        || input.spoof_expected.result_key == &input.e1.provider.result_key
    {
        return Err(fail(
            "public historical spoof branch aliases a positive control",
        ));
    }
    validate_protected_public_spoof_v1(
        input.spoof_record_bytes,
        input.spoof_rejection_bytes,
        &input.spoof_expected,
    )?;
    input
        .spoof_interval
        .verify_no_allocation(input.spoof_expected.result_key)?;
    let joined = serde_json::to_vec(&(
        "memcordon/public-epoch-join/v1",
        input.protected_archive_sha256,
        input.e0.host.installation_epoch(),
        input.e0.host.active_h1_receipt_sha256(),
        &e0_digest,
        input.e0.interval.trace_sha256(),
        input.e1.host.installation_epoch(),
        input.e1.host.active_h1_receipt_sha256(),
        &e1_digest,
        input.e1.interval.trace_sha256(),
        hash_bytes(input.replay_record_bytes),
        hash_bytes(input.replay_rejection_bytes),
        input.replay_interval.trace_sha256(),
        hash_bytes(input.spoof_record_bytes),
        hash_bytes(input.spoof_rejection_bytes),
        input.spoof_interval.trace_sha256(),
    ))?;
    Ok(VerifiedPublicEpochTransitionV1 {
        transcript_sha256: hash_bytes(&joined),
        e1_installation_epoch: input.e1.host.installation_epoch().clone(),
        e1_h1_receipt_sha256: input.e1.host.active_h1_receipt_sha256().clone(),
    })
}
