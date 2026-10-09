//! Authenticated pre-release observations for an independent native observer.
//! The observer acknowledgment is a barrier and never grants target authority.
use crate::result_v2::{NativeNamespaceV2, NativeProcessV2};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedPreparedObservationV2 {
    pub format: String,
    pub revision: u32,
    pub provider: crate::PublicProviderBindingV1,
    pub admission: crate::workload_admission_v3::RuntimeMixedAdmissionSnapshot,
    pub caller: NativeProcessV2,
    pub target: NativeProcessV2,
    pub namespace_init: NativeProcessV2,
    pub guardian: NativeProcessV2,
    pub user_namespace: NativeNamespaceV2,
    pub mount_namespace: NativeNamespaceV2,
    pub pid_namespace: NativeNamespaceV2,
    pub network_namespace: NativeNamespaceV2,
    pub ipc_namespace: NativeNamespaceV2,
    pub root_device: u64,
    pub root_inode: u64,
    pub authorizes_launch: bool,
}
impl MixedPreparedObservationV2 {
    pub fn validate(&self) -> Result<(), String> {
        self.admission.validate()?;
        if self.format != "memcordon.mixed-prepared-observation"
            || self.revision != 2
            || self.authorizes_launch
            || [
                &self.caller,
                &self.target,
                &self.namespace_init,
                &self.guardian,
            ]
            .iter()
            .any(|process| process.pid == 0 || process.birth == 0)
            || [
                &self.user_namespace,
                &self.mount_namespace,
                &self.pid_namespace,
                &self.network_namespace,
                &self.ipc_namespace,
            ]
            .iter()
            .any(|namespace| namespace.inode == 0)
            || self.root_inode == 0
        {
            return Err("mixed prepared observation identity/authority differs".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedObserverAcknowledgmentV2 {
    pub format: String,
    pub revision: u32,
    pub attempt_id: crate::BoundedText<64>,
    pub admission_nonce: crate::workload_contract::Nonce128,
    pub target: NativeProcessV2,
    pub observer: NativeProcessV2,
}

/// A native observation immediately before the final policy lease is acquired.
/// Acknowledging it permits the fresh policy check, never target authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedReleaseObservationV2 {
    pub format: String,
    pub revision: u32,
    pub prepared: MixedPreparedObservationV2,
    pub authorizes_launch: bool,
}
impl MixedReleaseObservationV2 {
    pub fn validate(&self) -> Result<(), String> {
        self.prepared.validate()?;
        if self.format != "memcordon.mixed-release-observation"
            || self.revision != 2
            || self.authorizes_launch
        {
            return Err("mixed release observation authority differs".into());
        }
        Ok(())
    }
}
