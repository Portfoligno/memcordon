//! Immutable inventory of authority-bearing Windows attempt capabilities.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::WindowsProcessIdentityV1;

pub const WINDOWS_CAPABILITY_OWNER_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_CAPABILITY_OWNER_ROLE_COUNT: usize = 12;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsCapabilityOwnerRoleV1 {
    LauncherJob,
    ActiveRegistryDuplicate,
    DirectTargetProcess,
    DesktopBootstrapJob,
    DesktopBootstrapProcess,
    GuardianProcess,
    ControlRelay,
    FrontendRelay,
    BrokerHolder,
    SessionBrokerTransfer,
    LaunchGate,
    PolicyReference,
}

impl WindowsCapabilityOwnerRoleV1 {
    pub const ALL: [Self; WINDOWS_CAPABILITY_OWNER_ROLE_COUNT] = [
        Self::LauncherJob,
        Self::ActiveRegistryDuplicate,
        Self::DirectTargetProcess,
        Self::DesktopBootstrapJob,
        Self::DesktopBootstrapProcess,
        Self::GuardianProcess,
        Self::ControlRelay,
        Self::FrontendRelay,
        Self::BrokerHolder,
        Self::SessionBrokerTransfer,
        Self::LaunchGate,
        Self::PolicyReference,
    ];

    pub const fn required(self) -> bool {
        matches!(
            self,
            Self::LauncherJob
                | Self::ActiveRegistryDuplicate
                | Self::DirectTargetProcess
                | Self::GuardianProcess
                | Self::ControlRelay
                | Self::FrontendRelay
                | Self::LaunchGate
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCapabilityOwnerEntryV1 {
    pub role: WindowsCapabilityOwnerRoleV1,
    pub present: bool,
    pub process_identity: Option<WindowsProcessIdentityV1>,
    pub capability_binding_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCapabilityOwnerManifestV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub provider_generation: String,
    pub launch_incarnation: String,
    pub entries: [WindowsCapabilityOwnerEntryV1; WINDOWS_CAPABILITY_OWNER_ROLE_COUNT],
}

fn valid_sha256(value: &str) -> bool {
    value.len() == Sha256::output_size() * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl WindowsCapabilityOwnerManifestV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != WINDOWS_CAPABILITY_OWNER_MANIFEST_SCHEMA_VERSION
            || !valid_sha256(&self.attempt_id)
            || self.provider_generation.is_empty()
            || self.launch_incarnation.is_empty()
        {
            return Err("owner_manifest.binding_or_shape");
        }
        let mut roles = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.role != WindowsCapabilityOwnerRoleV1::ALL[index]
                || !roles.insert(entry.role)
                || (entry.role.required() && !entry.present)
                || (entry.present != entry.capability_binding_sha256.is_some())
                || entry
                    .capability_binding_sha256
                    .as_deref()
                    .is_some_and(|digest| !valid_sha256(digest))
                || entry.process_identity.as_ref().is_some_and(|identity| {
                    !entry.present || identity.process_id == 0 || identity.creation_time_100ns == 0
                })
            {
                return Err("owner_manifest.entries");
            }
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> Result<String, &'static str> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "owner_manifest.serialization")?;
        let digest = Sha256::digest(bytes);
        let mut text = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(&mut text, "{byte:02x}").expect("writing a String cannot fail");
        }
        Ok(text)
    }
}
