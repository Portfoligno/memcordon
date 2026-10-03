//! Admitted-token access floor for same-owner, boot-sensitive Windows recovery.

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::WindowsProcessIdentityV1;

fn digest(value: &str) -> bool {
    value.len() == sha2::Sha256::output_size() * 2
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn integrity_rid(value: &str) -> Option<u32> {
    value.strip_prefix("S-1-16-")?.parse().ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsRecoveryPolicyV1 {
    SameOwnerBootSensitive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRecoveryAccessFloorV1 {
    pub integrity_level: String,
    pub elevated: bool,
    pub restricted: bool,
    pub restricted_sids_sha256: Option<String>,
    pub appcontainer: bool,
    pub appcontainer_binding_sha256: Option<String>,
}

impl WindowsRecoveryAccessFloorV1 {
    pub fn is_consistent(&self) -> bool {
        integrity_rid(&self.integrity_level).is_some()
            && (self.restricted == self.restricted_sids_sha256.is_some())
            && self.restricted_sids_sha256.as_deref().is_none_or(digest)
            && (self.appcontainer == self.appcontainer_binding_sha256.is_some())
            && self
                .appcontainer_binding_sha256
                .as_deref()
                .is_none_or(digest)
    }

    pub fn admits(&self, observed: &Self) -> bool {
        self.is_consistent()
            && observed.is_consistent()
            && integrity_rid(&observed.integrity_level)
                .zip(integrity_rid(&self.integrity_level))
                .is_some_and(|(current, admitted)| current >= admitted)
            && (!self.elevated || observed.elevated)
            && self.restricted == observed.restricted
            && self.restricted_sids_sha256 == observed.restricted_sids_sha256
            && self.appcontainer == observed.appcontainer
            && self.appcontainer_binding_sha256 == observed.appcontainer_binding_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRecoveryAuthorizationV1 {
    pub schema_version: u32,
    pub user_sid: String,
    pub launch_logon_identity: u64,
    pub launch_token_binding_sha256: String,
    pub recovery_access_floor: WindowsRecoveryAccessFloorV1,
    pub policy: WindowsRecoveryPolicyV1,
}

impl WindowsRecoveryAuthorizationV1 {
    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && self.user_sid.starts_with("S-1-")
            && self.user_sid.len() <= 256
            && self.launch_logon_identity != 0
            && digest(&self.launch_token_binding_sha256)
            && self.recovery_access_floor.is_consistent()
            && self.policy == WindowsRecoveryPolicyV1::SameOwnerBootSensitive
    }

    pub fn admits_recovery(
        &self,
        observed_user_sid: &str,
        observed_logon_identity: u64,
        observed_floor: &WindowsRecoveryAccessFloorV1,
        same_trusted_boot: bool,
    ) -> bool {
        self.is_consistent()
            && self.user_sid == observed_user_sid
            && observed_logon_identity != 0
            && (!same_trusted_boot || self.launch_logon_identity == observed_logon_identity)
            && self.recovery_access_floor.admits(observed_floor)
    }
}

/// Native observations made by the authenticated control service for one
/// recovery requester. Public callers cannot supply this object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRecoveryCallerEvidenceV1 {
    pub schema_version: u32,
    pub current_boot_identity: String,
    pub process_identity: WindowsProcessIdentityV1,
    pub user_sid: String,
    pub logon_identity: u64,
    pub token_binding_sha256: String,
    pub access_floor: WindowsRecoveryAccessFloorV1,
}

impl WindowsRecoveryCallerEvidenceV1 {
    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && !self.current_boot_identity.is_empty()
            && self.process_identity.process_id != 0
            && self.process_identity.creation_time_100ns != 0
            && self.user_sid.starts_with("S-1-")
            && self.user_sid.len() <= 256
            && self.logon_identity != 0
            && digest(&self.token_binding_sha256)
            && self.access_floor.is_consistent()
    }
}
