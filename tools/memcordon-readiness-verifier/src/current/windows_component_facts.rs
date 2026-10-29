//! Factual native component captures consumed only by the current verifier.
use serde::{Deserialize, Serialize};

pub(super) fn validate_receiptless_cause(
    original: &serde_json::Value,
    secondary: &serde_json::Value,
) -> crate::VerificationResult<()> {
    let expected = serde_json::json!({"observed":{"event":{"sequence":1,"origin":"launcher","category":"monitor",
        "operation":"observe-process-identity","code":"process-inventory-observation","native_code":{"win32":1234},
        "observed_phase":"monitoring","safe_detail":"no-additional-detail","detail_redacted":true,
        "detail_truncated":false,"terminalization_reference":null}}});
    let expected_secondary = serde_json::json!({"sequence":2,"origin":"launcher","category":"terminalization",
        "operation":"validate-terminal-response","code":"terminal-binding","native_code":null,
        "observed_phase":"terminalizing","safe_detail":"no-additional-detail","detail_redacted":true,
        "detail_truncated":false,"terminalization_reference":"first-error"});
    if original != &expected || secondary != &expected_secondary {
        return Err(
            "receiptless cause differs from exact declared current component vector".into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
#[expect(
    clippy::large_enum_variant,
    reason = "Preserve direct typed component wire payloads and their public constructors"
)]
pub enum CurrentNativeComponentPayload {
    CausalCapture {
        before_journal: String,
        after_journal: String,
        first_api: String,
        first_return: i32,
        first_win32_code: u32,
        second_api: String,
        second_return: i32,
        second_win32_code: u32,
        invalid_handle_was_null: bool,
    },
    ReplayOwnedOutbox {
        record: String,
        after_record: String,
        first_response: String,
        repeated_response: String,
        duplicate_refusal: String,
        nonce_refusal: String,
        request_refusal: String,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        fixture_resource_claims: bool,
        installed_state_accessed: bool,
        ack_record: String,
        staged_ack: String,
        completed_ack: String,
        retired_response: String,
        repeated_retired_response: String,
        active_record_refusal: String,
        ack_nonce_refusal: String,
        ack_caller_refusal: String,
        outbox_absent_after_ack: bool,
        available_journal: String,
        expired_journal: String,
        expiry_record: String,
        retention: serde_json::Value,
        pre_expiry_clock: u64,
        expired_clock: u64,
        same_boot: bool,
    },
    BindingSeed {
        before_record: String,
        after_record: String,
        replacement_observation: String,
        refusal: String,
        stores_before_refusal: u64,
        stores_after_refusal: u64,
    },
    BindingProof {
        before_record: String,
        after_refusal_record: String,
        after_matching_record: String,
        mismatched_receipt: String,
        matching_receipt: String,
        refusal: String,
    },
    BindingReceiptless {
        before_record: String,
        after_record: String,
        response: String,
        original: String,
        refusal: String,
    },
    BindingGeneration {
        record: String,
        attempt_id: String,
        provider_generation: String,
        substituted_generation: String,
        refusal: String,
    },
    Writer {
        observations: Vec<WindowsWriterObservation>,
    },
    WriterFrozen {
        observations: Vec<WindowsFrozenWriterObservation>,
    },
    WriterReservation {
        attempt_id: String,
        request_sha256: String,
        owner_identity: WindowsComponentIdentity,
        owner_held_live_during_refusal: bool,
        before_reservation: String,
        after_refusal_reservation: String,
        retirement_without_local_proof: String,
        writer_frozen_during_refusal: bool,
        writer_joined_before_retirement: bool,
        published_record: String,
        local_writer_retirement_proved: bool,
        reservation_absent_after_retirement: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WindowsComponentIdentity {
    pub process_id: u32,
    pub creation_time_100ns: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsFrozenWriterMember {
    pub identity: WindowsComponentIdentity,
    pub held_before_cleanup: bool,
    pub retirement_observed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsFrozenWriterObservation {
    pub cleanup_owner: String,
    pub job_active_before: u64,
    pub job_active_after: u64,
    pub job_members: Vec<WindowsFrozenWriterMember>,
    pub worker_identity: WindowsComponentIdentity,
    pub worker_retired_during_cleanup: bool,
    pub guardian_identity: WindowsComponentIdentity,
    pub guardian_retired_during_cleanup: bool,
    pub writer_frozen_during_cleanup: bool,
    pub cleanup_publication_confirmed: bool,
    pub after_record: String,
    pub original: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWriterObservation {
    pub phase: String,
    pub before_record: String,
    pub after_record: String,
    pub original: String,
    pub caller_ack_revision: u64,
    pub persisted_revision: u64,
    pub publication_rejected: bool,
    pub native_code: Option<WindowsNativeComponentCode>,
    pub publisher_process: Option<WindowsPublisherProcess>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPublisherProcess {
    pub process_id: u32,
    pub creation_time_100ns: u64,
    pub held_before_input_delivery: bool,
    pub exit_status: i32,
    pub retirement_observed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsNativeComponentCode {
    Win32(u32),
    NtStatus(u32),
    HResult(u32),
    Winsock(i32),
}
