//! The same bound rejection delivery applies before and after stream setup.
use memcordon_core::{
    Error, ErrorCategory, PublicProviderBindingV1, WindowsProviderResponseV3,
    WindowsTerminalDeliveryEvidenceV1,
};
use sha2::{Digest, Sha256};

pub(crate) struct RejectionContext<'a> {
    pub attempt_id: &'a str,
    pub nonce: &'a str,
    pub request_sha256: &'a str,
    pub provider: &'a PublicProviderBindingV1,
}

fn transport_error(detail: impl Into<String>) -> Error {
    Error::new(ErrorCategory::Setup, "MCSEALED-WINDOWS-TRANSPORT", detail)
}

fn digest_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn observed_terminal_delivery(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    authority: &[u8],
    retired: &[u8],
) -> Result<WindowsTerminalDeliveryEvidenceV1, Box<Error>> {
    if authority.is_empty()
        || authority.len() > memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES
        || retired.is_empty()
        || retired.len() > memcordon_core::MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES
    {
        return Err(Box::new(transport_error(
            "terminal response exceeds its native frame bound",
        )));
    }
    let delivery = WindowsTerminalDeliveryEvidenceV1 {
        schema_version: 1,
        attempt_id: attempt_id.to_owned(),
        nonce: nonce.to_owned(),
        request_sha256: request_sha256.to_owned(),
        authority_sha256: digest_bytes(authority),
        retired_sha256: digest_bytes(retired),
        retired_confirmed: true,
    };
    if !delivery.is_consistent() {
        return Err(Box::new(transport_error(
            "terminal delivery binding is invalid",
        )));
    }
    Ok(delivery)
}

pub(crate) fn complete_rejection_ack(
    mut primary: Error,
    response: &WindowsProviderResponseV3,
    response_raw: &[u8],
    context: &RejectionContext<'_>,
    acknowledge: impl FnOnce(&str) -> Result<Vec<u8>, Box<Error>>,
) -> Error {
    let completion = (|| -> Result<Option<WindowsTerminalDeliveryEvidenceV1>, Box<Error>> {
        let WindowsProviderResponseV3::Reject {
            schema_version,
            attempt_id,
            nonce,
            request_sha256,
            rejection,
        } = response
        else {
            return Err(Box::new(transport_error(
                "terminal acknowledgment requires an exact rejection",
            )));
        };
        if *schema_version != memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
            || attempt_id != context.attempt_id
            || nonce != context.nonce
            || request_sha256 != context.request_sha256
            || !rejection.is_consistent()
            || primary
                .provider_association
                .as_ref()
                .is_none_or(|association| {
                    association.provider != *context.provider
                        || String::from(association.attempt_id.clone()) != context.attempt_id
                        || String::from(association.request_sha256.clone())
                            != context.request_sha256
                })
            || rejection.terminal_receipt().is_some_and(|receipt| {
                receipt.attempt_id != context.attempt_id
                    || receipt.nonce != context.nonce
                    || receipt.request_sha256 != context.request_sha256
                    || receipt.retirement_proof.provider_generation
                        != context.provider.generation.as_str()
            })
        {
            return Err(Box::new(transport_error(
                "terminal rejection acknowledgment binding differs",
            )));
        }
        if !rejection.terminal_ack_required() {
            return Ok(None);
        }
        let authority = response
            .terminal_authority_json()
            .map_err(|error| Box::new(transport_error(error.to_string())))?;
        let digest = digest_bytes(authority.as_bytes());
        let retired_raw = acknowledge(&digest)?;
        let retired: WindowsProviderResponseV3 = serde_json::from_slice(&retired_raw)
            .map_err(|error| Box::new(transport_error(error.to_string())))?;
        if !matches!(&retired, WindowsProviderResponseV3::TerminalRetiredV2(retired)
            if retired.provider_generation == context.provider.generation.as_str()
                && retired.is_consistent_for(context.attempt_id, context.nonce,
                    context.request_sha256, &digest))
        {
            return Err(Box::new(transport_error(
                "provider did not confirm exact terminal retirement",
            )));
        }
        observed_terminal_delivery(
            context.attempt_id,
            context.nonce,
            context.request_sha256,
            response_raw,
            &retired_raw,
        )
        .map(Some)
    })();
    match completion {
        Ok(Some(delivery)) => primary.windows_terminal_delivery = Some(delivery),
        Ok(None) => {}
        Err(acknowledgment) => {
            if primary.provider_failure.is_none() {
                primary.provider_failure = acknowledgment.provider_failure.clone();
            }
            primary.message = format!(
                "{}; secondary terminal acknowledgment failure: {}",
                primary.message, acknowledgment
            );
        }
    }
    primary
}
