//! Closed, read-only diagnostic transport; never terminal or acknowledgement authority.
use super::super::windows_sha256_text_is_valid;
use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsAttemptDiagnosticsStatusV1 {
    Observed,
    Unavailable,
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAttemptDiagnosticsV1 {
    pub schema_version: u32,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 128>")]
    pub challenge: String,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 64>")]
    pub attempt_id: String,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 64>")]
    pub request_sha256: String,
    pub provider_binding: PublicProviderBindingV1,
    pub status: WindowsAttemptDiagnosticsStatusV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_availability: Option<DiagnosticProjectionAvailabilityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_failure: Option<Box<ProviderFailureDiagnosticV1>>,
}

fn bounded_nonempty(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}

pub fn validate_windows_attempt_diagnostics_request(
    schema_version: u32,
    attempt: &str,
    nonce: &str,
    request: &str,
    challenge: &str,
) -> Result<(), String> {
    if schema_version != WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
        || !windows_sha256_text_is_valid(attempt)
        || !windows_sha256_text_is_valid(request)
        || !bounded_nonempty(nonce)
        || !bounded_nonempty(challenge)
    {
        return Err("invalid read-only attempt diagnostic request binding".into());
    }
    Ok(())
}

impl WindowsAttemptDiagnosticsV1 {
    pub fn validate_bound(
        &self,
        schema_version: u32,
        challenge: &str,
        attempt: &str,
        request: &str,
        provider: &PublicProviderBindingV1,
    ) -> Result<(), String> {
        if self.schema_version != schema_version
            || schema_version != WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
            || self.challenge != challenge
            || !bounded_nonempty(challenge)
            || self.attempt_id != attempt
            || !windows_sha256_text_is_valid(attempt)
            || self.request_sha256 != request
            || !windows_sha256_text_is_valid(request)
            || &self.provider_binding != provider
            || !provider.is_consistent()
        {
            return Err("read-only attempt diagnostic reply binding differs".into());
        }
        match (
            self.status,
            self.diagnostic_availability,
            self.provider_failure.as_deref(),
        ) {
            (
                WindowsAttemptDiagnosticsStatusV1::Observed,
                Some(DiagnosticProjectionAvailabilityV1::Available),
                Some(projection),
            ) => {
                let attempt =
                    DiagnosticSha256::try_from(BoundedText::new(attempt).map_err(str::to_owned)?)
                        .map_err(str::to_owned)?;
                let request =
                    DiagnosticSha256::try_from(BoundedText::new(request).map_err(str::to_owned)?)
                        .map_err(str::to_owned)?;
                let bytes = bounded_json_bytes(projection, MAX_DIAGNOSTIC_PROJECTION_BYTES, false)
                    .map_err(|error| error.to_string())?;
                ProviderFailureDiagnosticV1::parse_bound(&bytes, provider, &attempt, &request)
                    .map_err(str::to_owned)?;
            }
            (WindowsAttemptDiagnosticsStatusV1::Unavailable, Some(availability), None)
                if availability != DiagnosticProjectionAvailabilityV1::Available => {}
            (WindowsAttemptDiagnosticsStatusV1::Denied, None, None) => {}
            _ => return Err("read-only attempt diagnostic status or projection differs".into()),
        }
        bounded_json_bytes(self, MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES, false)
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}
