//! Neutral native snapshots. These never confer launch or retirement authority.
use crate::{WindowsCallerTokenEnvelopeV1, WindowsProcessIdentityV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_NATIVE_INPUT_OBSERVATION_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeEnvelopeDigestKindV1 {
    NativeEnvelopeJsonV1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativePrimaryProjectionKindV1 {
    PrimaryTypeAnonymousLevelV1,
}

fn digest(text: &str) -> Option<[u8; 32]> {
    let mut result = [0; 32];
    if text.len() != result.len() * 2 {
        return None;
    }
    for (output, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *output = digit(pair[0])?
            .checked_mul(16)?
            .checked_add(digit(pair[1])?)?;
    }
    Some(result)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTokenSummaryV1 {
    pub digest_kind: NativeEnvelopeDigestKindV1,
    pub envelope_sha256: [u8; 32],
    pub derived_primary_projection_kind: NativePrimaryProjectionKindV1,
    pub derived_primary_projection_sha256: [u8; 32],
    pub groups_sha256: [u8; 32],
    pub privileges_sha256: [u8; 32],
    pub restricted_sids_sha256: [u8; 32],
    pub token_type: u32,
    pub impersonation_level: u32,
    pub group_count: Option<u32>,
    pub privilege_count: Option<u32>,
}
impl NativeTokenSummaryV1 {
    pub fn from_envelope(value: &WindowsCallerTokenEnvelopeV1) -> Result<Self, &'static str> {
        let mut primary = value.clone();
        primary.token_type = 1;
        primary.impersonation_level = 0;
        Ok(Self {
            digest_kind: NativeEnvelopeDigestKindV1::NativeEnvelopeJsonV1,
            envelope_sha256: Sha256::digest(
                serde_json::to_vec(value).map_err(|_| "native envelope encoding failed")?,
            )
            .into(),
            derived_primary_projection_kind:
                NativePrimaryProjectionKindV1::PrimaryTypeAnonymousLevelV1,
            derived_primary_projection_sha256: Sha256::digest(
                serde_json::to_vec(&primary)
                    .map_err(|_| "native primary projection encoding failed")?,
            )
            .into(),
            groups_sha256: digest(&value.groups_sha256).ok_or("invalid native groups digest")?,
            privileges_sha256: digest(&value.privileges_sha256)
                .ok_or("invalid native privileges digest")?,
            restricted_sids_sha256: digest(&value.restricted_sids_sha256)
                .ok_or("invalid native restricted SID digest")?,
            token_type: value.token_type,
            impersonation_level: value.impersonation_level,
            group_count: None,
            privilege_count: None,
        })
    }
    pub fn with_counts(mut self, groups: u32, privileges: u32) -> Self {
        self.group_count = Some(groups);
        self.privilege_count = Some(privileges);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeInputUnavailableV1 {
    QueryFailed,
    EncodingFailed,
    ClockExpired,
    FrontendTokenOpen,
    FrontendEnvelopeQuery,
    SummaryEncoding,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeInputStageV1 {
    #[default]
    NotReached,
    Observed {
        summary: NativeTokenSummaryV1,
    },
    Unavailable {
        reason: NativeInputUnavailableV1,
        /// A captured Win32 code only; textual helper errors leave it absent.
        #[serde(rename = "native_win32_error")]
        native_error: Option<u32>,
    },
}
impl NativeInputStageV1 {
    fn extends(&self, previous: &Self) -> bool {
        matches!(previous, Self::NotReached) || self == previous
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInputCaptureV1 {
    pub authenticated: NativeInputStageV1,
    pub duplicated: NativeInputStageV1,
    pub prepared: NativeInputStageV1,
    pub frontend: NativeInputStageV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNativeInputObservationV1 {
    pub attempt_sha256: [u8; 32],
    pub request_sha256: [u8; 32],
    pub frontend_identity: WindowsProcessIdentityV1,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub control: NativeInputCaptureV1,
    pub launcher_primary: NativeInputStageV1,
    pub suspended_target: NativeInputStageV1,
}
impl WindowsNativeInputObservationV1 {
    pub fn new(
        attempt_sha256: [u8; 32],
        request_sha256: [u8; 32],
        frontend_identity: WindowsProcessIdentityV1,
        control: NativeInputCaptureV1,
    ) -> Self {
        Self {
            attempt_sha256,
            request_sha256,
            frontend_identity,
            target_identity: None,
            control,
            launcher_primary: NativeInputStageV1::NotReached,
            suspended_target: NativeInputStageV1::NotReached,
        }
    }
    pub fn is_bound_to(
        &self,
        attempt: &str,
        request: &str,
        frontend: &WindowsProcessIdentityV1,
    ) -> bool {
        digest(attempt) == Some(self.attempt_sha256)
            && digest(request) == Some(self.request_sha256)
            && &self.frontend_identity == frontend
            && self.is_consistent()
    }
    pub fn is_consistent(&self) -> bool {
        let valid_identity = |value: &WindowsProcessIdentityV1| {
            value.process_id != 0 && value.creation_time_100ns != 0
        };
        valid_identity(&self.frontend_identity)
            && self.target_identity.as_ref().is_none_or(valid_identity)
            && (matches!(self.suspended_target, NativeInputStageV1::NotReached)
                || self.target_identity.is_some())
            && serde_json::to_vec(self)
                .is_ok_and(|bytes| bytes.len() <= MAX_NATIVE_INPUT_OBSERVATION_BYTES)
    }
    pub fn is_monotonic_extension_of(&self, previous: &Self) -> bool {
        self.is_consistent()
            && previous.is_consistent()
            && self.attempt_sha256 == previous.attempt_sha256
            && self.request_sha256 == previous.request_sha256
            && self.frontend_identity == previous.frontend_identity
            && previous
                .target_identity
                .as_ref()
                .is_none_or(|identity| self.target_identity.as_ref() == Some(identity))
            && self
                .control
                .authenticated
                .extends(&previous.control.authenticated)
            && self
                .control
                .duplicated
                .extends(&previous.control.duplicated)
            && self.control.prepared.extends(&previous.control.prepared)
            && self.control.frontend.extends(&previous.control.frontend)
            && self.launcher_primary.extends(&previous.launcher_primary)
            && self.suspended_target.extends(&previous.suspended_target)
    }
    pub fn monotonic_update(&mut self, next: Self) -> Result<(), &'static str> {
        if !next.is_monotonic_extension_of(self) {
            return Err("native input observation replacement refused");
        }
        *self = next;
        Ok(())
    }
}
