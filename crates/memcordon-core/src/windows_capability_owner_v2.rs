//! Immutable inventory of authority-bearing Windows attempt capabilities.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::WindowsProcessIdentityV1;

pub const WINDOWS_CURRENT_CAPABILITY_OWNER_MANIFEST_SCHEMA_VERSION: u32 = 2;
pub const WINDOWS_CURRENT_CAPABILITY_OWNER_ROLE_COUNT: usize = 11;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsCapabilityOwnerRoleV2 {
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
}

impl WindowsCapabilityOwnerRoleV2 {
    pub const ALL: [Self; WINDOWS_CURRENT_CAPABILITY_OWNER_ROLE_COUNT] = [
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
pub struct WindowsCapabilityOwnerEntryV2 {
    pub role: WindowsCapabilityOwnerRoleV2,
    pub present: bool,
    pub process_identity: Option<WindowsProcessIdentityV1>,
    pub capability_binding_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCapabilityOwnerManifestV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub provider_generation: String,
    pub launch_incarnation: String,
    pub entries: [WindowsCapabilityOwnerEntryV2; WINDOWS_CURRENT_CAPABILITY_OWNER_ROLE_COUNT],
}

/// Immutable preauthorization readback of the finite Job ownership contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsJobClosureContractV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub provider_generation: String,
    pub launch_incarnation: String,
    pub original_boot_id: String,
    pub job_identity: String,
    pub owner_manifest_sha256: String,
    pub guardian_job_transfer_sha256: String,
    pub kill_on_close_verified: bool,
    pub breakaway_denied: bool,
    pub job_handles_noninheritable: bool,
    pub closed_job_owner_set: bool,
    pub job_unnamed: bool,
    pub target_handle_list_verified: bool,
}

impl WindowsJobClosureContractV2 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 2
            || !valid_sha256(&self.attempt_id)
            || self.nonce.is_empty()
            || !valid_sha256(&self.request_sha256)
            || self.provider_generation.is_empty()
            || self.launch_incarnation.is_empty()
            || self.original_boot_id.is_empty()
            || !valid_sha256(&self.job_identity)
            || !valid_sha256(&self.owner_manifest_sha256)
            || !valid_sha256(&self.guardian_job_transfer_sha256)
            || !self.kill_on_close_verified
            || !self.breakaway_denied
            || !self.job_handles_noninheritable
            || !self.closed_job_owner_set
            || !self.job_unnamed
            || !self.target_handle_list_verified
        {
            return Err("job_closure_contract.binding_or_readback");
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> Result<String, &'static str> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "job_closure_contract.serialization")?;
        let mut text = String::with_capacity(Sha256::output_size() * 2);
        for byte in Sha256::digest(bytes) {
            write!(text, "{byte:02x}").expect("String formatting cannot fail");
        }
        Ok(text)
    }
}

/// Same-boot closure derived from checked capability extinction, without a
/// native Job-zero observation or a guardian completion receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCapabilityExtinctionProofV2 {
    pub contract: WindowsJobClosureContractV2,
    pub owner_manifest: WindowsCapabilityOwnerManifestV2,
    pub current_boot_id: String,
    pub job_holder_processes_extinct: bool,
    pub target_process_extinct: bool,
    pub relay_capabilities_retired: bool,
    pub launch_gate_closed: bool,
}

impl WindowsCapabilityExtinctionProofV2 {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.contract.validate()?;
        self.owner_manifest.validate()?;
        if self.current_boot_id != self.contract.original_boot_id
            || self.owner_manifest.attempt_id != self.contract.attempt_id
            || self.owner_manifest.provider_generation != self.contract.provider_generation
            || self.owner_manifest.launch_incarnation != self.contract.launch_incarnation
            || self.owner_manifest.canonical_sha256()? != self.contract.owner_manifest_sha256
            || !self.job_holder_processes_extinct
            || !self.target_process_extinct
            || !self.relay_capabilities_retired
            || !self.launch_gate_closed
            || self
                .owner_manifest
                .entries
                .iter()
                .any(|entry| entry.present && entry.process_identity.is_none())
        {
            return Err("capability_extinction.binding_or_owner_closure");
        }
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == Sha256::output_size() * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl WindowsCapabilityOwnerManifestV2 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != WINDOWS_CURRENT_CAPABILITY_OWNER_MANIFEST_SCHEMA_VERSION
            || !valid_sha256(&self.attempt_id)
            || self.provider_generation.is_empty()
            || self.launch_incarnation.is_empty()
        {
            return Err("owner_manifest.binding_or_shape");
        }
        let mut roles = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.role != WindowsCapabilityOwnerRoleV2::ALL[index]
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
