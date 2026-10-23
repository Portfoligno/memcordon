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

/// Closed optional retirement exchange. Digests associate authenticated frames;
/// none of these messages grant launch, signal, or cleanup authority.
pub const RETIREMENT_OBSERVATION_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedRetirementPhaseV1 {
    Retiring,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedRetirementKnowledgeV1 {
    ExecObserved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementBindingV1 {
    pub attempt_id: crate::BoundedText<64>,
    pub admission_nonce: crate::workload_contract::Nonce128,
    pub prepared_sha256: crate::DiagnosticSha256,
}
impl MixedRetirementBindingV1 {
    pub fn matches(&self, prepared: &MixedPreparedObservationV2, bytes: &[u8]) -> bool {
        self.attempt_id == prepared.admission.attempt_id
            && self.admission_nonce == prepared.admission.admission_nonce
            && self.prepared_sha256 == retirement_digest(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementObserverV1 {
    pub format: String,
    pub revision: u32,
    pub observer: NativeProcessV2,
    pub boot_identity: crate::BoundedText<128>,
    pub observer_work_deadline_monotonic_millis: u64,
    pub observer_cleanup_deadline_monotonic_millis: u64,
    pub phase: MixedRetirementPhaseV1,
}
impl MixedRetirementObserverV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.mixed-retirement-observer"
            || self.revision != 1
            || self.observer.pid == 0
            || self.observer.birth == 0
            || self.boot_identity.as_str().is_empty()
            || self.observer_work_deadline_monotonic_millis == 0
            || self.observer_work_deadline_monotonic_millis
                >= self.observer_cleanup_deadline_monotonic_millis
        {
            return Err("mixed retirement observer configuration differs".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementEnrollmentV1 {
    pub format: String,
    pub revision: u32,
    pub binding: MixedRetirementBindingV1,
    pub observer: MixedRetirementObserverV1,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementEnrolledV1 {
    pub format: String,
    pub revision: u32,
    pub binding: MixedRetirementBindingV1,
    pub enrollment_sha256: crate::DiagnosticSha256,
    pub phase: MixedRetirementPhaseV1,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementJournalV1 {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub sha256: crate::DiagnosticSha256,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementObservationV1 {
    pub format: String,
    pub revision: u32,
    pub binding: MixedRetirementBindingV1,
    pub enrollment_sha256: crate::DiagnosticSha256,
    pub boot_identity: crate::BoundedText<128>,
    pub caller: NativeProcessV2,
    pub target: NativeProcessV2,
    pub namespace_init: NativeProcessV2,
    pub guardian: NativeProcessV2,
    pub worker: NativeProcessV2,
    pub phase: MixedRetirementPhaseV1,
    pub release_knowledge: MixedRetirementKnowledgeV1,
    pub journal: MixedRetirementJournalV1,
    pub cleanup_deadline_monotonic_millis: u64,
    pub observation_deadline_monotonic_millis: u64,
    pub authorizes_launch: bool,
    pub retirement_completed: bool,
}
impl MixedRetirementObservationV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.mixed-retirement-observation"
            || self.revision != 1
            || self.authorizes_launch
            || self.retirement_completed
            || self.journal.inode == 0
            || self.journal.length == 0
            || self.journal.length
                > (crate::workload_limits::REGISTRY_BYTES
                    + 2 * crate::workload_limits::PUBLIC_OBJECT_BYTES) as u64
            || self.observation_deadline_monotonic_millis == 0
            || self.observation_deadline_monotonic_millis >= self.cleanup_deadline_monotonic_millis
            || [
                &self.caller,
                &self.target,
                &self.namespace_init,
                &self.guardian,
                &self.worker,
            ]
            .iter()
            .any(|process| process.pid == 0 || process.birth == 0)
        {
            return Err("mixed retirement witness identity/authority differs".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "kebab-case", deny_unknown_fields)]
pub enum MixedRetirementDispositionV1 {
    Completed,
    Aborted { detail: crate::BoundedText<1024> },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementAcknowledgmentV1 {
    pub format: String,
    pub revision: u32,
    pub binding: MixedRetirementBindingV1,
    pub enrollment_sha256: crate::DiagnosticSha256,
    pub witness_sha256: crate::DiagnosticSha256,
    pub disposition: MixedRetirementDispositionV1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedRetirementFailureStageV1 {
    IneligiblePhase,
    JournalSnapshot,
    WitnessWrite,
    AcknowledgementRead,
    AcknowledgementAssociation,
    ObserverAborted,
    ObservationDeadline,
    PeerLost,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
pub enum MixedRetirementOutcomeV1 {
    Acknowledged,
    Failed {
        stage: MixedRetirementFailureStageV1,
        detail: crate::BoundedText<1024>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedRetirementObserverResultV1 {
    pub format: String,
    pub revision: u32,
    pub binding: MixedRetirementBindingV1,
    pub enrollment_sha256: crate::DiagnosticSha256,
    pub witness_sha256: Option<crate::DiagnosticSha256>,
    pub outcome: MixedRetirementOutcomeV1,
}
impl MixedRetirementObserverResultV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.mixed-retirement-observer-result" || self.revision != 1 {
            return Err("retirement observer result format differs".into());
        }
        if self.witness_sha256.is_none()
            && !matches!(
                self.outcome,
                MixedRetirementOutcomeV1::Failed {
                    stage: MixedRetirementFailureStageV1::IneligiblePhase
                        | MixedRetirementFailureStageV1::JournalSnapshot
                        | MixedRetirementFailureStageV1::WitnessWrite
                        | MixedRetirementFailureStageV1::ObservationDeadline,
                    ..
                }
            )
        {
            return Err("retirement result without witness uses a post-witness outcome".into());
        }
        Ok(())
    }
}

pub fn retirement_digest(bytes: &[u8]) -> crate::DiagnosticSha256 {
    use sha2::{Digest, Sha256};
    crate::DiagnosticSha256::from_bytes(Sha256::digest(bytes).into())
}
pub fn encode_retirement<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > RETIREMENT_OBSERVATION_BYTES {
        return Err("mixed retirement payload exceeds bound".into());
    }
    Ok(bytes)
}
pub fn parse_retirement<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > RETIREMENT_OBSERVATION_BYTES {
        return Err("mixed retirement payload exceeds bound".into());
    }
    crate::workload_contract::reject_duplicate_json_keys(bytes)?;
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}
