//! Observer custody is a separately provisioned verifier service, not a
//! producer assertion. Wire records are structural. Only an authenticated
//! controller readback can construct live/completed origin capabilities.
//!
//! This implementation uses an administrator enrolled, persistent Unix host
//! lease. Its root, kernel and pinned supervisor/controller are in the TCB.
//! It does not protect against a hostile unrestricted host root. Deploying
//! that trust boundary and provisioning transport credentials is a separate
//! operator action; no release signing role is introduced here.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

pub const PAYLOAD_INDEX_LEAF: &str = "observer-payload-index.v1.json";
pub const ORIGIN_COMMITMENT_LEAF: &str = "origin-commitment.v1.json";
pub const ORIGIN_RECEIPT_LEAF: &str = "origin-receipt.v1.json";
pub const MAX_ORIGIN_BYTES: usize = 64 * 1024;
pub const MAX_PAYLOAD_INDEX_BYTES: usize = 128 * 1024;
const MAX_CONTROLLER_FRAME: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObserverStageV1 {
    Candidate,
    Public,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverSubjectV1 {
    pub stage: ObserverStageV1,
    pub repository_id: u64,
    pub run_id: u64,
    pub run_attempt: u32,
    pub job_id: u64,
    pub runner_id: u64,
    pub target: String,
    pub source_commit: String,
    pub release_version: String,
    pub build_sha256: DiagnosticSha256,
    pub intent_sha256: DiagnosticSha256,
    pub catalogue_sha256: DiagnosticSha256,
    pub host_profile_sha256: DiagnosticSha256,
}

impl ObserverSubjectV1 {
    pub fn validate(&self) -> Result<()> {
        if self.repository_id == 0
            || self.run_id == 0
            || self.run_attempt == 0
            || self.job_id == 0
            || self.runner_id == 0
            || !matches!(
                self.target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
            || self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.release_version.is_empty()
            || self.release_version.len() > 128
            || [
                &self.build_sha256,
                &self.intent_sha256,
                &self.catalogue_sha256,
                &self.host_profile_sha256,
            ]
            .iter()
            .any(|digest| !nonzero(digest))
        {
            return fail("observer static subject differs");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedGenerationV1 {
    pub generation: u32,
    pub installation_epoch: DiagnosticSha256,
    pub installed_manifest_sha256: DiagnosticSha256,
    pub installed_receipt_sha256: DiagnosticSha256,
    pub service_identity_sha256: DiagnosticSha256,
    pub broker_identity_sha256: DiagnosticSha256,
    pub transaction_sha256: DiagnosticSha256,
    pub observer_bundle_sha256: DiagnosticSha256,
    pub begin_monotonic_ns: u64,
    pub end_monotonic_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverIntervalRecordV1 {
    /// Digest of native IntervalIdV1, never the logical request key alone.
    pub interval_id: DiagnosticSha256,
    pub logical_case_key: DiagnosticSha256,
    pub generation: u32,
    pub purpose: String,
    pub ordinal: u32,
    pub capture_path: String,
    pub capture_sha256: DiagnosticSha256,
    pub controls_paths: Vec<String>,
    pub sample_paths: Vec<String>,
    pub arm_monotonic_ns: u64,
    pub begin_monotonic_ns: u64,
    pub end_monotonic_ns: u64,
    pub detach_monotonic_ns: u64,
    pub loss_count: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverSessionDescriptorV1 {
    pub schema_version: u8,
    pub session_nonce: String,
    pub subject: ObserverSubjectV1,
    pub enrolled_host: String,
    pub boot_id: String,
    pub kernel_btf_sha256: DiagnosticSha256,
    pub observer_executable_sha256: DiagnosticSha256,
    pub generations: Vec<ObservedGenerationV1>,
    pub intervals: Vec<ObserverIntervalRecordV1>,
}

impl ObserverSessionDescriptorV1 {
    pub fn validate(&self) -> Result<()> {
        self.subject.validate()?;
        let nonce = hex::decode(&self.session_nonce)
            .map_err(|_| CiError::Message("observer nonce is not hex".into()))?;
        if self.schema_version != 1
            || nonce.len() != 32
            || nonce.iter().all(|byte| *byte == 0)
            || hex::encode(&nonce) != self.session_nonce
            || self.enrolled_host.is_empty()
            || self.enrolled_host.len() > 128
            || self.boot_id.is_empty()
            || self.boot_id.len() > 128
            || !nonzero(&self.kernel_btf_sha256)
            || !nonzero(&self.observer_executable_sha256)
            || self.generations.is_empty()
            || self.generations.len() > 64
            || self.intervals.len() > 1024
        {
            return fail("observer descriptor identity or bounds differ");
        }
        let mut epochs = BTreeSet::new();
        for (ordinal, generation) in self.generations.iter().enumerate() {
            if generation.generation as usize != ordinal
                || generation.begin_monotonic_ns == 0
                || generation.end_monotonic_ns < generation.begin_monotonic_ns
                || [
                    &generation.installation_epoch,
                    &generation.installed_manifest_sha256,
                    &generation.installed_receipt_sha256,
                    &generation.service_identity_sha256,
                    &generation.broker_identity_sha256,
                    &generation.transaction_sha256,
                    &generation.observer_bundle_sha256,
                ]
                .iter()
                .any(|digest| !nonzero(digest))
                || !epochs.insert(*generation.installation_epoch.bytes())
                || ordinal > 0
                    && self.generations[ordinal - 1].end_monotonic_ns
                        > generation.begin_monotonic_ns
            {
                return fail("observer installed generation timeline differs");
            }
        }
        let mut identities = BTreeSet::new();
        for interval in &self.intervals {
            let generation = self
                .generations
                .get(interval.generation as usize)
                .ok_or_else(|| CiError::Message("observer interval generation absent".into()))?;
            if !nonzero(&interval.interval_id)
                || !identities.insert(*interval.interval_id.bytes())
                || !nonzero(&interval.logical_case_key)
                || !nonzero(&interval.capture_sha256)
                || interval.loss_count != 0
                || interval.arm_monotonic_ns == 0
                || interval.arm_monotonic_ns > interval.begin_monotonic_ns
                || interval.begin_monotonic_ns >= interval.end_monotonic_ns
                || interval.end_monotonic_ns > interval.detach_monotonic_ns
                || interval.arm_monotonic_ns < generation.begin_monotonic_ns
                || interval.detach_monotonic_ns > generation.end_monotonic_ns
                || interval.first_sequence == 0
                || interval.first_sequence > interval.last_sequence
                || interval.controls_paths.is_empty()
                || interval.controls_paths.len() > 32
                || interval.sample_paths.len() > 256
                || !valid_relative_path(&interval.capture_path)
                || interval
                    .controls_paths
                    .iter()
                    .chain(&interval.sample_paths)
                    .any(|path| !valid_relative_path(path))
                || !matches!(
                    interval.purpose.as_str(),
                    "controls"
                        | "ordinary"
                        | "policy"
                        | "abi-outer"
                        | "abi-filtered"
                        | "historical-e0"
                        | "historical-replay"
                        | "historical-e1"
                        | "caller-spoof"
                        | "reuse-first"
                        | "reuse-blocked"
                        | "reuse-recovery"
                        | "dual"
                        | "facility-controls"
                        | "dual-continuous"
                        | "fault-recovery"
                )
            {
                return fail("observer interval continuity/closure differs");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverPayloadLeafV1 {
    pub path: String,
    pub size: u64,
    pub sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverPayloadIndexV1 {
    pub schema_version: u8,
    pub subject: ObserverSubjectV1,
    pub leaves: Vec<ObserverPayloadLeafV1>,
}

pub fn canonical_payload_index(
    subject: &ObserverSubjectV1,
    payload: &BTreeMap<String, Vec<u8>>,
) -> Result<ObserverPayloadIndexV1> {
    subject.validate()?;
    if payload.is_empty() || payload.len() > 16384 {
        return fail("observer payload count differs");
    }
    let mut total = 0_u64;
    let mut leaves = Vec::with_capacity(payload.len());
    for (path, bytes) in payload {
        if !valid_relative_path(path)
            || is_origin_carrier(path)
            || bytes.is_empty() && !is_exact_stream_leaf(path)
        {
            return fail("observer payload path is recursive or empty");
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| CiError::Message("observer payload size overflow".into()))?;
        if total > 4 * 1024 * 1024 * 1024 {
            return fail("observer payload aggregate bound differs");
        }
        leaves.push(ObserverPayloadLeafV1 {
            path: path.clone(),
            size: bytes.len() as u64,
            sha256: hash_bytes(bytes),
        });
    }
    Ok(ObserverPayloadIndexV1 {
        schema_version: 1,
        subject: subject.clone(),
        leaves,
    })
}

// Exact empty stdout/stderr is a measured stream, not a missing evidence
// object. All non-stream leaves still require nonempty bytes.
fn is_exact_stream_leaf(path: &str) -> bool {
    matches!(path.rsplit('/').next(), Some("stdout.raw" | "stderr.raw"))
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn strict_json<T: serde::de::DeserializeOwned>(bytes: &[u8], bound: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > bound {
        return fail("observer JSON bound differs");
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
        .map_err(CiError::Message)?;
    Ok(serde_json::from_slice(bytes)?)
}

pub fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.starts_with('/')
        && !path.contains('\\')
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        })
}

fn is_origin_carrier(path: &str) -> bool {
    let leaf = path.rsplit('/').next().unwrap_or(path);
    matches!(
        path,
        "qualification.json" | "qualification.certificate.json" | "candidate-c-v3/index.json"
    ) || matches!(
        leaf,
        PAYLOAD_INDEX_LEAF
            | ORIGIN_COMMITMENT_LEAF
            | ORIGIN_RECEIPT_LEAF
            | "raw-public-index-v1.json"
            | "transport-public-index-v1.json"
            | "candidate-index-v3.json"
            | "commitment-v1.json"
            | "receipt-v1.json"
            | "public-index-v3.json"
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginCommitmentV1 {
    pub schema_version: u8,
    pub session_nonce: String,
    pub subject: ObserverSubjectV1,
    pub descriptor_sha256: DiagnosticSha256,
    pub payload_index_sha256: DiagnosticSha256,
    pub generation_timeline_sha256: DiagnosticSha256,
    pub interval_inventory_sha256: DiagnosticSha256,
    pub last_chunk_sha256: DiagnosticSha256,
    pub chunks: u64,
    pub sealed_monotonic_ns: u64,
    pub cleanup_inventory_sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginReceiptV1 {
    pub schema_version: u8,
    pub custodian_id: String,
    pub storage_revision: u64,
    pub origin_commitment_sha256: DiagnosticSha256,
    /// Enrollment transport authentication; never a release role signature.
    pub signature: String,
}

pub fn origin_receipt_message(receipt: &OriginReceiptV1) -> Result<Vec<u8>> {
    if receipt.schema_version != 1
        || receipt.storage_revision == 0
        || receipt.custodian_id.is_empty()
        || receipt.custodian_id.len() > 128
        || !nonzero(&receipt.origin_commitment_sha256)
    {
        return fail("custodian receipt identity differs");
    }
    let mut bytes = b"memcordon/observer-custody-receipt/v1\0".to_vec();
    let length = u32::try_from(receipt.custodian_id.len())
        .map_err(|_| CiError::Message("custodian id exceeds bound".into()))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(receipt.custodian_id.as_bytes());
    bytes.extend_from_slice(&receipt.storage_revision.to_be_bytes());
    bytes.extend_from_slice(receipt.origin_commitment_sha256.bytes());
    Ok(bytes)
}

/// Checks the acyclic L -> I -> K -> R byte joins. This structural function
/// deliberately returns no origin capability.
pub fn verify_origin_layers(
    descriptor: &ObserverSessionDescriptorV1,
    payload: &BTreeMap<String, Vec<u8>>,
    index_bytes: &[u8],
    commitment_bytes: &[u8],
    receipt_bytes: &[u8],
    public_key: &[u8; 32],
) -> Result<(ObserverPayloadIndexV1, OriginCommitmentV1, OriginReceiptV1)> {
    descriptor.validate()?;
    let index_bound = match descriptor.subject.stage {
        ObserverStageV1::Candidate => MAX_PAYLOAD_INDEX_BYTES,
        ObserverStageV1::Public => 16 * 1024 * 1024,
    };
    let index: ObserverPayloadIndexV1 = strict_json(index_bytes, index_bound)?;
    let commitment: OriginCommitmentV1 = strict_json(commitment_bytes, MAX_ORIGIN_BYTES)?;
    let receipt: OriginReceiptV1 = strict_json(receipt_bytes, MAX_ORIGIN_BYTES)?;
    if index != canonical_payload_index(&descriptor.subject, payload)?
        || canonical_bytes(&index)? != index_bytes
        || canonical_bytes(&commitment)? != commitment_bytes
        || canonical_bytes(&receipt)? != receipt_bytes
        || commitment.schema_version != 1
        || commitment.subject != descriptor.subject
        || commitment.session_nonce != descriptor.session_nonce
        || commitment.descriptor_sha256 != hash_bytes(&canonical_bytes(descriptor)?)
        || commitment.payload_index_sha256 != hash_bytes(index_bytes)
        || commitment.generation_timeline_sha256
            != hash_bytes(&canonical_bytes(&descriptor.generations)?)
        || commitment.interval_inventory_sha256
            != hash_bytes(&canonical_bytes(&descriptor.intervals)?)
        || commitment.sealed_monotonic_ns == 0
        || commitment.chunks == 0
        || !nonzero(&commitment.last_chunk_sha256)
        || !nonzero(&commitment.cleanup_inventory_sha256)
        || descriptor.intervals.is_empty()
        || descriptor
            .intervals
            .iter()
            .any(|interval| interval.detach_monotonic_ns > commitment.sealed_monotonic_ns)
        || receipt.origin_commitment_sha256 != hash_bytes(commitment_bytes)
    {
        return fail("observer L/I/K/R commitment differs");
    }
    let views = crate::private_candidate_replay::expand_replay_payload(payload)?;
    for interval in &descriptor.intervals {
        if views
            .get(&interval.capture_path)
            .map(|bytes| hash_bytes(bytes))
            != Some(interval.capture_sha256.clone())
            || interval
                .controls_paths
                .iter()
                .chain(&interval.sample_paths)
                .any(|path| !views.contains_key(path))
        {
            return fail("observer interval exact raw inventory absent");
        }
    }
    let signature = hex::decode(&receipt.signature)
        .map_err(|_| CiError::Message("custody receipt signature is not hex".into()))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| CiError::Message("custody signature length differs".into()))?;
    VerifyingKey::from_bytes(public_key)
        .map_err(|_| CiError::Message("custody key is invalid".into()))?
        .verify(&origin_receipt_message(&receipt)?, &signature)
        .map_err(|_| CiError::Message("custody receipt authentication differs".into()))?;
    Ok((index, commitment, receipt))
}

/// Server-side append state. It cannot construct an authenticated client
/// token. Deployments retain its exact canonical state durably after each ack.
pub struct CustodyJournalV1 {
    descriptor: ObserverSessionDescriptorV1,
    next_chunk: u64,
    chain: DiagnosticSha256,
    leaves: BTreeMap<String, Vec<u8>>,
    open_interval: Option<DiagnosticSha256>,
    intervals: BTreeSet<[u8; 32]>,
    sealed: bool,
    incomplete: bool,
    partial_leaf: Option<PartialCustodyLeafV1>,
}

struct PartialCustodyLeafV1 {
    path: String,
    total_size: u64,
    sha256: DiagnosticSha256,
    bytes: Vec<u8>,
}

impl CustodyJournalV1 {
    /// Admission is the controller's protected scheduled job/host policy.
    /// The journal itself does not claim to authenticate that policy.
    pub fn begin(descriptor: ObserverSessionDescriptorV1) -> Result<Self> {
        descriptor.validate()?;
        if !descriptor.intervals.is_empty() {
            return fail("new observer session already has intervals");
        }
        let chain = hash_bytes(&canonical_bytes(&descriptor)?);
        Ok(Self {
            descriptor,
            next_chunk: 0,
            chain,
            leaves: BTreeMap::new(),
            open_interval: None,
            intervals: BTreeSet::new(),
            sealed: false,
            incomplete: false,
            partial_leaf: None,
        })
    }
    pub fn begin_interval(&mut self, interval_id: DiagnosticSha256) -> Result<()> {
        self.active()?;
        if self.open_interval.is_some()
            || !nonzero(&interval_id)
            || !self.intervals.insert(*interval_id.bytes())
        {
            self.incomplete = true;
            return fail("observer interval reused or overlapped");
        }
        self.open_interval = Some(interval_id);
        Ok(())
    }
    pub fn append(
        &mut self,
        sequence: u64,
        previous: &DiagnosticSha256,
        path: &str,
        bytes: &[u8],
    ) -> Result<DiagnosticSha256> {
        self.append_inner(sequence, previous, path, bytes, false)
    }
    /// Representation assembly happens after genuine captures close. This
    /// operation cannot add an interval or turn a serialized fact into a
    /// capability; it retains only bounded, closed transport representations.
    pub fn append_representation(
        &mut self,
        sequence: u64,
        previous: &DiagnosticSha256,
        path: &str,
        bytes: &[u8],
    ) -> Result<DiagnosticSha256> {
        let closed_path = path
            .strip_prefix("candidate-c-v3/cases/")
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(key, leaf)| {
                key.len() == 2 * std::mem::size_of::<[u8; 32]>()
                    && key
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    && (matches!(
                        leaf,
                        "result.json"
                            | "request.bin"
                            | "report.bin"
                            | "stdio.bin"
                            | "observer.bin"
                            | "cleanup.bin"
                    ) || leaf.starts_with("kernel-") && leaf.ends_with(".capture.bin")
                        || leaf.starts_with("family/")
                            && !crate::private_source_carrier::is_source_carrier(path))
            });
        let public_path = path == "historical/epoch-transition.json"
            || matches!(
                path,
                "composites/abi/composite.json"
                    | "composites/reuse/composite.json"
                    | "composites/policy/composite.json"
            )
            || path
                .strip_prefix("cases/")
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(ordinal, leaf)| {
                    ordinal
                        .parse::<u8>()
                        .ok()
                        .is_some_and(|value| value < 25 && value.to_string() == ordinal)
                        && matches!(leaf, "facts.json" | "result.json")
                });
        let admitted_path = match self.descriptor.subject.stage {
            ObserverStageV1::Candidate => closed_path,
            ObserverStageV1::Public => public_path,
        };
        if !admitted_path
            || self.open_interval.is_some()
            || self.descriptor.intervals.is_empty()
            || bytes.len() > 8 * 1024 * 1024
        {
            self.incomplete = true;
            return fail("observer representation phase/path differs");
        }
        self.append_inner(sequence, previous, path, bytes, true)
    }
    fn append_inner(
        &mut self,
        sequence: u64,
        previous: &DiagnosticSha256,
        path: &str,
        bytes: &[u8],
        representation: bool,
    ) -> Result<DiagnosticSha256> {
        self.active()?;
        if self.open_interval.is_none() && !representation
            || sequence != self.next_chunk
            || previous != &self.chain
            || !valid_relative_path(path)
            || is_origin_carrier(path)
            || bytes.is_empty() && !is_exact_stream_leaf(path)
            || bytes.len() > MAX_CONTROLLER_FRAME
            || self.leaves.contains_key(path)
            || self.partial_leaf.is_some()
            || self.leaves.len() >= 16384
            || self
                .leaves
                .values()
                .map(|leaf| leaf.len() as u64)
                .sum::<u64>()
                .checked_add(bytes.len() as u64)
                .is_none_or(|total| total > 4 * 1024 * 1024 * 1024)
        {
            self.incomplete = true;
            return fail("observer append continuity/path differs");
        }
        let mut record = b"memcordon/observer-append/v1\0".to_vec();
        record.extend_from_slice(previous.bytes());
        record.extend_from_slice(&sequence.to_be_bytes());
        record.extend_from_slice(&(path.len() as u64).to_be_bytes());
        record.extend_from_slice(path.as_bytes());
        record.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        record.extend_from_slice(hash_bytes(bytes).bytes());
        self.chain = hash_bytes(&record);
        self.next_chunk = self
            .next_chunk
            .checked_add(1)
            .ok_or_else(|| CiError::Message("custodian chunk overflow".into()))?;
        self.leaves.insert(path.into(), bytes.to_vec());
        Ok(self.chain.clone())
    }
    /// Partial bytes are durable operation-log data, never a complete I leaf.
    /// Only the exact final digest advances the logical append chain.
    pub fn append_leaf_part(
        &mut self,
        sequence: u64,
        previous: &DiagnosticSha256,
        path: &str,
        total_size: u64,
        sha256: &DiagnosticSha256,
        offset: u64,
        bytes: &[u8],
    ) -> Result<DiagnosticSha256> {
        self.active()?;
        let maximum = match self.descriptor.subject.stage {
            ObserverStageV1::Candidate => 8 * 1024 * 1024,
            ObserverStageV1::Public => 64 * 1024 * 1024,
        };
        if self.open_interval.is_none()
            || sequence != self.next_chunk
            || previous != &self.chain
            || !valid_relative_path(path)
            || is_origin_carrier(path)
            || self.leaves.contains_key(path)
            || total_size == 0
            || total_size > maximum
            || !nonzero(sha256)
            || bytes.is_empty()
            || bytes.len() > 1024 * 1024
            || offset
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > total_size)
        {
            self.incomplete = true;
            return fail("custody partial leaf bound/continuity differs");
        }
        if self.partial_leaf.is_none() {
            if offset != 0 {
                self.incomplete = true;
                return fail("custody partial leaf did not begin at zero");
            }
            self.partial_leaf = Some(PartialCustodyLeafV1 {
                path: path.into(),
                total_size,
                sha256: sha256.clone(),
                bytes: Vec::new(),
            });
        }
        let part = self
            .partial_leaf
            .as_mut()
            .expect("partial leaf initialized");
        if part.path != path
            || part.total_size != total_size
            || &part.sha256 != sha256
            || part.bytes.len() as u64 != offset
        {
            self.incomplete = true;
            return fail("custody partial leaf identity/offset differs");
        }
        part.bytes.extend_from_slice(bytes);
        if part.bytes.len() as u64 == total_size {
            let part = self
                .partial_leaf
                .take()
                .expect("completed partial leaf present");
            if hash_bytes(&part.bytes) != part.sha256 {
                self.incomplete = true;
                return fail("custody completed leaf digest differs");
            }
            self.append(sequence, previous, path, &part.bytes)
        } else {
            Ok(self.chain.clone())
        }
    }
    /// Representation-only transition. Every source must already have a
    /// durable append acknowledgement; the controller encodes the carrier
    /// itself and preserves the exact mapping in its signed append chain.
    pub fn repack_sources(
        &mut self,
        sequence: u64,
        previous: &DiagnosticSha256,
        path: &str,
        sources: &[String],
    ) -> Result<DiagnosticSha256> {
        self.active()?;
        if self.descriptor.subject.stage != ObserverStageV1::Candidate
            || self.open_interval.is_some()
            || self.partial_leaf.is_some()
            || self.descriptor.intervals.is_empty()
            || sequence != self.next_chunk
            || previous != &self.chain
            || !crate::private_source_carrier::is_source_carrier(path)
            || !valid_relative_path(path)
            || self.leaves.contains_key(path)
            || sources.is_empty()
            || sources.len() > 256
            || sources.windows(2).any(|pair| pair[0] >= pair[1])
        {
            self.incomplete = true;
            return fail("custody repack continuity/closed source mapping differs");
        }
        let mut originals = BTreeMap::new();
        for source in sources {
            let Some(raw) = self.leaves.get(source) else {
                self.incomplete = true;
                return fail("custody repack omitted original source");
            };
            originals.insert(source.clone(), raw.clone());
        }
        let packed = match crate::private_source_carrier::encode_source_carrier(&originals) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.incomplete = true;
                return Err(error);
            }
        };
        let mut event = b"memcordon/observer-repack/v1\0".to_vec();
        event.extend_from_slice(previous.bytes());
        event.extend_from_slice(&sequence.to_be_bytes());
        event.extend_from_slice(&(path.len() as u64).to_be_bytes());
        event.extend_from_slice(path.as_bytes());
        event.extend_from_slice(hash_bytes(&packed).bytes());
        self.chain = hash_bytes(&event);
        self.next_chunk = self
            .next_chunk
            .checked_add(1)
            .ok_or_else(|| CiError::Message("custody repack sequence overflow".into()))?;
        for source in sources {
            self.leaves.remove(source);
        }
        self.leaves.insert(path.into(), packed);
        Ok(self.chain.clone())
    }
    pub fn close_interval(&mut self, record: ObserverIntervalRecordV1) -> Result<()> {
        self.active()?;
        let views = crate::private_candidate_replay::expand_replay_payload(&self.leaves)?;
        if self.partial_leaf.is_some()
            || self.open_interval.as_ref() != Some(&record.interval_id)
            || views
                .get(&record.capture_path)
                .map(|bytes| hash_bytes(bytes))
                != Some(record.capture_sha256.clone())
            || record
                .controls_paths
                .iter()
                .chain(&record.sample_paths)
                .any(|path| !views.contains_key(path))
        {
            self.incomplete = true;
            return fail("observer interval close inventory differs");
        }
        let generation = self
            .descriptor
            .generations
            .get_mut(record.generation as usize)
            .ok_or_else(|| CiError::Message("interval generation not observed".into()))?;
        generation.end_monotonic_ns = generation.end_monotonic_ns.max(record.detach_monotonic_ns);
        self.descriptor.intervals.push(record);
        if let Err(error) = self.descriptor.validate() {
            self.incomplete = true;
            return Err(error);
        }
        self.open_interval = None;
        Ok(())
    }
    pub fn observe_generation(&mut self, generation: ObservedGenerationV1) -> Result<()> {
        self.active()?;
        if self.open_interval.is_some()
            || generation.generation as usize != self.descriptor.generations.len()
        {
            self.incomplete = true;
            return fail("generation transition crosses active interval or is not consecutive");
        }
        self.descriptor.generations.push(generation);
        if let Err(error) = self.descriptor.validate() {
            self.incomplete = true;
            return Err(error);
        }
        Ok(())
    }
    pub fn disconnect(&mut self) {
        self.incomplete = true;
    }
    pub fn seal(
        &mut self,
        cleanup_inventory_sha256: DiagnosticSha256,
        sealed_monotonic_ns: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.active()?;
        if self.partial_leaf.is_some()
            || self.open_interval.is_some()
            || self.next_chunk == 0
            || self.descriptor.intervals.is_empty()
            || !nonzero(&cleanup_inventory_sha256)
            || self
                .descriptor
                .intervals
                .iter()
                .any(|interval| interval.detach_monotonic_ns > sealed_monotonic_ns)
        {
            self.incomplete = true;
            return fail("observer seal precedes complete cleanup");
        }
        let index = canonical_bytes(&canonical_payload_index(
            &self.descriptor.subject,
            &self.leaves,
        )?)?;
        let index_bound = match self.descriptor.subject.stage {
            ObserverStageV1::Candidate => MAX_PAYLOAD_INDEX_BYTES,
            ObserverStageV1::Public => 16 * 1024 * 1024,
        };
        if index.len() > index_bound {
            return fail("observer payload index exceeds bound");
        }
        let commitment = OriginCommitmentV1 {
            schema_version: 1,
            session_nonce: self.descriptor.session_nonce.clone(),
            subject: self.descriptor.subject.clone(),
            descriptor_sha256: hash_bytes(&canonical_bytes(&self.descriptor)?),
            payload_index_sha256: hash_bytes(&index),
            generation_timeline_sha256: hash_bytes(&canonical_bytes(&self.descriptor.generations)?),
            interval_inventory_sha256: hash_bytes(&canonical_bytes(&self.descriptor.intervals)?),
            last_chunk_sha256: self.chain.clone(),
            chunks: self.next_chunk,
            sealed_monotonic_ns,
            cleanup_inventory_sha256,
        };
        self.sealed = true;
        Ok((index, canonical_bytes(&commitment)?))
    }
    pub fn descriptor(&self) -> &ObserverSessionDescriptorV1 {
        &self.descriptor
    }
    pub fn leaves(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.leaves
    }
    pub fn chain(&self) -> &DiagnosticSha256 {
        &self.chain
    }
    fn active(&self) -> Result<()> {
        if self.sealed || self.incomplete {
            return fail("observer session sealed or incomplete");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedObserverArtifactV1 {
    pub artifact_id: u64,
    pub archive_sha256: DiagnosticSha256,
    pub archive_size: u64,
    pub uploaded_job_id: u64,
    pub uploaded_run_attempt: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodianReadbackV1 {
    pub descriptor: ObserverSessionDescriptorV1,
    pub payload_index: Vec<u8>,
    pub origin_commitment: Vec<u8>,
    pub origin_receipt: Vec<u8>,
    /// Recorded by the protected upload/controller handoff, not by C/P JSON.
    pub upload: Option<CompletedObserverArtifactV1>,
    pub next_chunk: u64,
    pub last_chunk_sha256: DiagnosticSha256,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedCustodianPolicyV1 {
    schema_version: u8,
    custodian_id: String,
    socket: PathBuf,
    controller_executable: PathBuf,
    controller_sha256: DiagnosticSha256,
    transport_public_key: String,
    approved_root_tcb_sha256: DiagnosticSha256,
    enrolled_hosts: Vec<String>,
    approved_host_profiles: Vec<DiagnosticSha256>,
}

/// Private origin capabilities have no Deserialize/Default/unchecked ctor.
pub struct AuthenticatedObserverSessionV1 {
    descriptor: ObserverSessionDescriptorV1,
    payload: BTreeMap<String, Vec<u8>>,
    views: BTreeMap<String, Vec<u8>>,
    payload_index_sha256: DiagnosticSha256,
    origin_commitment_sha256: DiagnosticSha256,
    receipt_sha256: DiagnosticSha256,
    generation_timeline_sha256: DiagnosticSha256,
    upload: Option<CompletedObserverArtifactV1>,
}

impl AuthenticatedObserverSessionV1 {
    pub fn descriptor(&self) -> &ObserverSessionDescriptorV1 {
        &self.descriptor
    }
    pub fn payload_index_sha256(&self) -> &DiagnosticSha256 {
        &self.payload_index_sha256
    }
    pub fn origin_commitment_sha256(&self) -> &DiagnosticSha256 {
        &self.origin_commitment_sha256
    }
    pub fn receipt_sha256(&self) -> &DiagnosticSha256 {
        &self.receipt_sha256
    }
    pub fn generation_timeline_sha256(&self) -> &DiagnosticSha256 {
        &self.generation_timeline_sha256
    }
    pub fn upload(&self) -> Option<&CompletedObserverArtifactV1> {
        self.upload.as_ref()
    }
    pub fn leaf(&self, path: &str) -> Result<&[u8]> {
        self.views
            .get(path)
            .map(Vec::as_slice)
            .ok_or_else(|| CiError::Message("origin-bound raw leaf absent".into()))
    }
    pub(crate) fn payload(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.payload
    }
    pub fn require_exact_leaf(&self, path: &str, bytes: &[u8]) -> Result<()> {
        if self.leaf(path)? != bytes {
            return fail("origin-bound raw leaf substituted");
        }
        Ok(())
    }
}

pub struct AuthenticatedLiveObserverLeaseV1 {
    descriptor: ObserverSessionDescriptorV1,
    policy_sha256: DiagnosticSha256,
}

impl AuthenticatedLiveObserverLeaseV1 {
    pub fn descriptor(&self) -> &ObserverSessionDescriptorV1 {
        &self.descriptor
    }
    pub fn policy_sha256(&self) -> &DiagnosticSha256 {
        &self.policy_sha256
    }
}

/// This endpoint comes exclusively from protected administrator policy.
/// A producer/artifact cannot supply a URL, executable pin or transport key.
pub struct AuthenticatedCustodianTransportV1 {
    policy: ProtectedCustodianPolicyV1,
    policy_sha256: DiagnosticSha256,
    #[cfg(target_os = "linux")]
    stream: std::os::unix::net::UnixStream,
}

impl AuthenticatedCustodianTransportV1 {
    pub fn connect(policy_path: &Path) -> Result<Self> {
        let bytes = crate::private_protected_readback::read_protected_raw_case_file(policy_path)?;
        let policy: ProtectedCustodianPolicyV1 = strict_json(&bytes, MAX_ORIGIN_BYTES)?;
        if policy.schema_version != 1
            || policy.custodian_id.is_empty()
            || !policy.socket.is_absolute()
            || !policy.controller_executable.is_absolute()
            || !nonzero(&policy.controller_sha256)
            || !nonzero(&policy.approved_root_tcb_sha256)
            || policy.enrolled_hosts.is_empty()
            || policy.approved_host_profiles.is_empty()
            || policy.enrolled_hosts.len() > 256
            || policy.approved_host_profiles.len() > 64
            || hex::decode(&policy.transport_public_key).map_or(true, |key| key.len() != 32)
        {
            return fail("custodian enrollment policy absent or invalid");
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
            for ancestor in policy.socket.ancestors().skip(1) {
                let metadata = std::fs::symlink_metadata(ancestor)?;
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return fail("custodian endpoint ancestor is not protected");
                }
            }
            let metadata = std::fs::symlink_metadata(&policy.socket)?;
            if !metadata.file_type().is_socket()
                || metadata.uid() != 0
                || metadata.mode() & 0o077 != 0
            {
                return fail("custodian endpoint is not root private");
            }
            let stream = std::os::unix::net::UnixStream::connect(&policy.socket)?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
            let peer =
                rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
            if peer.uid.as_raw() != 0 || peer.pid.as_raw_nonzero().get() <= 0 {
                return fail("custodian peer credentials differ");
            }
            let process = Path::new("/proc").join(peer.pid.as_raw_nonzero().get().to_string());
            let executable_path = process.join("exe");
            if std::fs::read_link(&executable_path)? != policy.controller_executable {
                return fail("custodian peer executable path differs");
            }
            // /proc/PID/exe is intentionally followed as a kernel-held image.
            let mut image = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC)
                .open(executable_path)?;
            let held = image.metadata()?;
            if !held.is_file()
                || held.len() == 0
                || held.len() > 256 * 1024 * 1024
                || held.uid() != 0
                || held.mode() & 0o022 != 0
            {
                return fail("custodian held executable protection differs");
            }
            let mut image_bytes = Vec::new();
            (&mut image)
                .take(held.len() + 1)
                .read_to_end(&mut image_bytes)?;
            if image_bytes.len() as u64 != held.len()
                || hash_bytes(&image_bytes) != policy.controller_sha256
            {
                return fail("custodian independently pinned executable differs");
            }
            Ok(Self {
                policy,
                policy_sha256: hash_bytes(&bytes),
                stream,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = policy;
            fail("custodian persistent host transport requires Linux")
        }
    }

    fn request(&mut self, request: &CustodianRequestV1) -> Result<CustodianReadbackV1> {
        #[cfg(target_os = "linux")]
        {
            let bytes = canonical_bytes(request)?;
            write_controller_frame(&mut self.stream, &bytes)?;
            let reply = read_controller_frame(&mut self.stream)?;
            strict_json(&reply, MAX_CONTROLLER_FRAME)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            fail("custodian persistent host transport requires Linux")
        }
    }

    pub fn begin_live(
        &mut self,
        expected: &ObserverSubjectV1,
    ) -> Result<AuthenticatedLiveObserverLeaseV1> {
        expected.validate()?;
        let readback = self.request(&CustodianRequestV1::Begin {
            expected: expected.clone(),
        })?;
        self.validate_descriptor(&readback.descriptor, expected)?;
        if !readback.origin_commitment.is_empty() || readback.upload.is_some() {
            return fail("live lease is already sealed/completed");
        }
        Ok(AuthenticatedLiveObserverLeaseV1 {
            descriptor: readback.descriptor,
            policy_sha256: self.policy_sha256.clone(),
        })
    }

    pub fn authenticate_completed_session(
        &mut self,
        expected: &ObserverSubjectV1,
        expected_upload: &CompletedObserverArtifactV1,
        payload: BTreeMap<String, Vec<u8>>,
        index_bytes: &[u8],
        commitment_bytes: &[u8],
        receipt_bytes: &[u8],
    ) -> Result<AuthenticatedObserverSessionV1> {
        let commitment: OriginCommitmentV1 = strict_json(commitment_bytes, MAX_ORIGIN_BYTES)?;
        let readback = self.request(&CustodianRequestV1::ReadCompleted {
            expected: expected.clone(),
            session_nonce: commitment.session_nonce.clone(),
        })?;
        self.validate_descriptor(&readback.descriptor, expected)?;
        if readback.payload_index != index_bytes
            || readback.origin_commitment != commitment_bytes
            || readback.origin_receipt != receipt_bytes
            || readback.upload.as_ref() != Some(expected_upload)
            || expected_upload.artifact_id == 0
            || expected_upload.archive_size == 0
            || expected_upload.uploaded_job_id != expected.job_id
            || expected_upload.uploaded_run_attempt != expected.run_attempt
        {
            return fail("immutable custodian readback/upload differs from completed Actions");
        }
        let key: [u8; 32] = hex::decode(&self.policy.transport_public_key)
            .map_err(|_| CiError::Message("custodian transport key is invalid".into()))?
            .try_into()
            .map_err(|_| CiError::Message("custodian transport key length differs".into()))?;
        let (_, verified_commitment, receipt) = verify_origin_layers(
            &readback.descriptor,
            &payload,
            index_bytes,
            commitment_bytes,
            receipt_bytes,
            &key,
        )?;
        if receipt.custodian_id != self.policy.custodian_id {
            return fail("custodian receipt id differs from enrollment");
        }
        let views = crate::private_candidate_replay::expand_replay_payload(&payload)?;
        Ok(AuthenticatedObserverSessionV1 {
            descriptor: readback.descriptor,
            payload,
            views,
            payload_index_sha256: hash_bytes(index_bytes),
            origin_commitment_sha256: hash_bytes(commitment_bytes),
            receipt_sha256: hash_bytes(receipt_bytes),
            generation_timeline_sha256: verified_commitment.generation_timeline_sha256,
            upload: Some(expected_upload.clone()),
        })
    }
    fn validate_descriptor(
        &self,
        descriptor: &ObserverSessionDescriptorV1,
        expected: &ObserverSubjectV1,
    ) -> Result<()> {
        descriptor.validate()?;
        if &descriptor.subject != expected
            || !self
                .policy
                .enrolled_hosts
                .contains(&descriptor.enrolled_host)
            || !self
                .policy
                .approved_host_profiles
                .contains(&expected.host_profile_sha256)
        {
            return fail("observer host/subject is not enrolled for this release");
        }
        Ok(())
    }
}

/// Local producer proof context is sealed live custody, not completed Actions
/// authority. It can export payload but cannot enter the Q/CP signer boundary.
pub struct AuthenticatedSealedLiveObserverSessionV1 {
    inner: AuthenticatedObserverSessionV1,
}

pub(crate) trait ObserverEvidenceV1 {
    fn descriptor(&self) -> &ObserverSessionDescriptorV1;
    fn payload_index_sha256(&self) -> &DiagnosticSha256;
    fn origin_commitment_sha256(&self) -> &DiagnosticSha256;
    fn generation_timeline_sha256(&self) -> &DiagnosticSha256;
    fn leaf(&self, path: &str) -> Result<&[u8]>;
    fn completed(&self) -> bool;
}
impl ObserverEvidenceV1 for AuthenticatedObserverSessionV1 {
    fn descriptor(&self) -> &ObserverSessionDescriptorV1 {
        self.descriptor()
    }
    fn payload_index_sha256(&self) -> &DiagnosticSha256 {
        self.payload_index_sha256()
    }
    fn origin_commitment_sha256(&self) -> &DiagnosticSha256 {
        self.origin_commitment_sha256()
    }
    fn generation_timeline_sha256(&self) -> &DiagnosticSha256 {
        self.generation_timeline_sha256()
    }
    fn leaf(&self, path: &str) -> Result<&[u8]> {
        self.leaf(path)
    }
    fn completed(&self) -> bool {
        self.upload.is_some()
    }
}
impl ObserverEvidenceV1 for AuthenticatedSealedLiveObserverSessionV1 {
    fn descriptor(&self) -> &ObserverSessionDescriptorV1 {
        self.inner.descriptor()
    }
    fn payload_index_sha256(&self) -> &DiagnosticSha256 {
        self.inner.payload_index_sha256()
    }
    fn origin_commitment_sha256(&self) -> &DiagnosticSha256 {
        self.inner.origin_commitment_sha256()
    }
    fn generation_timeline_sha256(&self) -> &DiagnosticSha256 {
        self.inner.generation_timeline_sha256()
    }
    fn leaf(&self, path: &str) -> Result<&[u8]> {
        self.inner.leaf(path)
    }
    fn completed(&self) -> bool {
        false
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CustodianRequestV1 {
    Begin {
        expected: ObserverSubjectV1,
    },
    BeginObserved {
        descriptor: ObserverSessionDescriptorV1,
    },
    BeginInterval {
        session_nonce: String,
        interval_id: DiagnosticSha256,
    },
    ObserveGeneration {
        session_nonce: String,
        generation: ObservedGenerationV1,
    },
    Append {
        session_nonce: String,
        sequence: u64,
        previous: DiagnosticSha256,
        path: String,
        bytes_hex: String,
    },
    AppendLeafPart {
        session_nonce: String,
        sequence: u64,
        previous: DiagnosticSha256,
        path: String,
        total_size: u64,
        sha256: DiagnosticSha256,
        offset: u64,
        bytes_hex: String,
    },
    AppendRepresentation {
        session_nonce: String,
        sequence: u64,
        previous: DiagnosticSha256,
        path: String,
        bytes_hex: String,
    },
    RepackSources {
        session_nonce: String,
        sequence: u64,
        previous: DiagnosticSha256,
        path: String,
        sources: Vec<String>,
    },
    CloseInterval {
        session_nonce: String,
        record: ObserverIntervalRecordV1,
    },
    Seal {
        session_nonce: String,
        cleanup_inventory_sha256: DiagnosticSha256,
        sealed_monotonic_ns: u64,
    },
    RecordUpload {
        session_nonce: String,
        upload: CompletedObserverArtifactV1,
    },
    Disconnect {
        session_nonce: String,
    },
    ReadCompleted {
        expected: ObserverSubjectV1,
        session_nonce: String,
    },
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerPeerV1 {
    executable: PathBuf,
    sha256: DiagnosticSha256,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedControllerConfigV1 {
    schema_version: u8,
    custodian_id: String,
    socket: PathBuf,
    storage: PathBuf,
    supervisor: ControllerPeerV1,
    verifier: ControllerPeerV1,
    uploader: ControllerPeerV1,
    enrolled_hosts: Vec<String>,
    approved_subjects: Vec<ObserverSubjectV1>,
    transport_public_key: String,
}

/// A real bounded controller operation engine. It produces transport records,
/// never native qualification or public pass tokens. Admission and keys must
/// be provisioned independently of the tested release checkout.
pub struct CustodianControllerV1 {
    custodian_id: String,
    approved_subjects: Vec<ObserverSubjectV1>,
    enrolled_hosts: Vec<String>,
    sessions: BTreeMap<String, CustodyJournalV1>,
    sealed: BTreeMap<String, CustodianReadbackV1>,
    next_revision: u64,
    transport_key: SigningKey,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CustodianPeerRoleV1 {
    Supervisor,
    Uploader,
    Verifier,
}

impl CustodianControllerV1 {
    pub fn new(
        custodian_id: String,
        approved_subjects: Vec<ObserverSubjectV1>,
        enrolled_hosts: Vec<String>,
        transport_key: SigningKey,
    ) -> Result<Self> {
        if custodian_id.is_empty()
            || approved_subjects.is_empty()
            || approved_subjects.len() > 1024
            || enrolled_hosts.is_empty()
        {
            return fail("custodian scheduled admission/enrollment is absent");
        }
        for subject in &approved_subjects {
            subject.validate()?;
        }
        Ok(Self {
            custodian_id,
            approved_subjects,
            enrolled_hosts,
            sessions: BTreeMap::new(),
            sealed: BTreeMap::new(),
            next_revision: 1,
            transport_key,
        })
    }

    pub fn handle(
        &mut self,
        role: CustodianPeerRoleV1,
        request: CustodianRequestV1,
    ) -> Result<CustodianReadbackV1> {
        match request {
            CustodianRequestV1::BeginObserved { mut descriptor } => {
                if role != CustodianPeerRoleV1::Supervisor
                    || !self.approved_subjects.contains(&descriptor.subject)
                    || !self.enrolled_hosts.contains(&descriptor.enrolled_host)
                    || !descriptor.intervals.is_empty()
                    || self
                        .sessions
                        .values()
                        .any(|session| session.descriptor.subject == descriptor.subject)
                {
                    return fail("custodian job/host is not admitted or already consumed");
                }
                let mut nonce = [0; 32];
                std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
                descriptor.session_nonce = hex::encode(nonce);
                let journal = CustodyJournalV1::begin(descriptor.clone())?;
                let readback = active_readback(&journal);
                self.sessions.insert(descriptor.session_nonce, journal);
                Ok(readback)
            }
            CustodianRequestV1::Begin { expected } => {
                if role != CustodianPeerRoleV1::Supervisor {
                    return fail("verifier cannot acquire producer lease");
                }
                let sessions: Vec<_> = self
                    .sessions
                    .values()
                    .filter(|journal| journal.descriptor.subject == expected && !journal.sealed)
                    .collect();
                let [journal] = sessions.as_slice() else {
                    return fail("custodian observed live lease absent/ambiguous");
                };
                journal.active()?;
                Ok(active_readback(journal))
            }
            CustodianRequestV1::ReadCompleted {
                expected,
                session_nonce,
            } => {
                if role != CustodianPeerRoleV1::Verifier {
                    return fail("producer cannot acquire completed origin readback");
                }
                let readback = self
                    .sealed
                    .get(&session_nonce)
                    .ok_or_else(|| CiError::Message("custodian immutable session absent".into()))?;
                if readback.descriptor.subject != expected || readback.upload.is_none() {
                    return fail("custodian completed subject/upload absent");
                }
                Ok(readback.clone())
            }
            CustodianRequestV1::RecordUpload {
                session_nonce,
                upload,
            } => {
                if role != CustodianPeerRoleV1::Uploader {
                    return fail("producer cannot self-assign uploaded artifact authority");
                }
                let readback = self
                    .sealed
                    .get_mut(&session_nonce)
                    .ok_or_else(|| CiError::Message("custodian upload precedes seal".into()))?;
                if readback.upload.is_some()
                    || upload.artifact_id == 0
                    || upload.archive_size == 0
                    || !nonzero(&upload.archive_sha256)
                    || upload.uploaded_job_id != readback.descriptor.subject.job_id
                    || upload.uploaded_run_attempt != readback.descriptor.subject.run_attempt
                {
                    return fail("custodian immutable uploader handoff differs");
                }
                readback.upload = Some(upload);
                Ok(readback.clone())
            }
            CustodianRequestV1::Disconnect { session_nonce } => {
                if role != CustodianPeerRoleV1::Supervisor {
                    return fail("only enrolled supervisor may close its disconnected session");
                }
                self.disconnect(&session_nonce);
                let journal = self
                    .sessions
                    .get(&session_nonce)
                    .ok_or_else(|| CiError::Message("disconnected session absent".into()))?;
                Ok(active_readback(journal))
            }
            request => {
                if role != CustodianPeerRoleV1::Supervisor {
                    return fail("only enrolled supervisor may append/close/seal");
                }
                let nonce = match &request {
                    CustodianRequestV1::BeginInterval { session_nonce, .. }
                    | CustodianRequestV1::ObserveGeneration { session_nonce, .. }
                    | CustodianRequestV1::Append { session_nonce, .. }
                    | CustodianRequestV1::AppendLeafPart { session_nonce, .. }
                    | CustodianRequestV1::AppendRepresentation { session_nonce, .. }
                    | CustodianRequestV1::RepackSources { session_nonce, .. }
                    | CustodianRequestV1::CloseInterval { session_nonce, .. }
                    | CustodianRequestV1::Seal { session_nonce, .. } => session_nonce.clone(),
                    _ => unreachable!(),
                };
                let journal = self
                    .sessions
                    .get_mut(&nonce)
                    .ok_or_else(|| CiError::Message("custodian session absent".into()))?;
                match request {
                    CustodianRequestV1::BeginInterval { interval_id, .. } => {
                        journal.begin_interval(interval_id)?
                    }
                    CustodianRequestV1::ObserveGeneration { generation, .. } => {
                        journal.observe_generation(generation)?
                    }
                    CustodianRequestV1::Append {
                        sequence,
                        previous,
                        path,
                        bytes_hex,
                        ..
                    } => {
                        if bytes_hex.len() > MAX_CONTROLLER_FRAME / 2 {
                            return fail("custodian hex payload exceeds bound");
                        }
                        let bytes = hex::decode(bytes_hex).map_err(|_| {
                            CiError::Message("custodian append payload encoding differs".into())
                        })?;
                        journal.append(sequence, &previous, &path, &bytes)?;
                    }
                    CustodianRequestV1::AppendLeafPart {
                        sequence,
                        previous,
                        path,
                        total_size,
                        sha256,
                        offset,
                        bytes_hex,
                        ..
                    } => {
                        if bytes_hex.len() > 2 * 1024 * 1024 {
                            return fail("custody leaf part exceeds bounded frame");
                        }
                        let bytes = hex::decode(bytes_hex).map_err(|_| {
                            CiError::Message("custody leaf part encoding differs".into())
                        })?;
                        journal.append_leaf_part(
                            sequence, &previous, &path, total_size, &sha256, offset, &bytes,
                        )?;
                    }
                    CustodianRequestV1::AppendRepresentation {
                        sequence,
                        previous,
                        path,
                        bytes_hex,
                        ..
                    } => {
                        if bytes_hex.len() > 2 * 8 * 1024 * 1024 {
                            return fail("candidate representation exceeds reviewed member bound");
                        }
                        let bytes = hex::decode(bytes_hex).map_err(|_| {
                            CiError::Message("candidate representation encoding differs".into())
                        })?;
                        journal.append_representation(sequence, &previous, &path, &bytes)?;
                    }
                    CustodianRequestV1::CloseInterval { record, .. } => {
                        journal.close_interval(record)?
                    }
                    CustodianRequestV1::RepackSources {
                        sequence,
                        previous,
                        path,
                        sources,
                        ..
                    } => {
                        journal.repack_sources(sequence, &previous, &path, &sources)?;
                    }
                    CustodianRequestV1::Seal {
                        cleanup_inventory_sha256,
                        sealed_monotonic_ns,
                        ..
                    } => {
                        let (payload_index, origin_commitment) =
                            journal.seal(cleanup_inventory_sha256, sealed_monotonic_ns)?;
                        let mut receipt = OriginReceiptV1 {
                            schema_version: 1,
                            custodian_id: self.custodian_id.clone(),
                            storage_revision: self.next_revision,
                            origin_commitment_sha256: hash_bytes(&origin_commitment),
                            signature: String::new(),
                        };
                        receipt.signature = hex::encode(
                            self.transport_key
                                .sign(&origin_receipt_message(&receipt)?)
                                .to_bytes(),
                        );
                        self.next_revision =
                            self.next_revision.checked_add(1).ok_or_else(|| {
                                CiError::Message("custodian storage revision overflow".into())
                            })?;
                        let readback = CustodianReadbackV1 {
                            descriptor: journal.descriptor.clone(),
                            payload_index,
                            origin_commitment,
                            origin_receipt: canonical_bytes(&receipt)?,
                            upload: None,
                            next_chunk: journal.next_chunk,
                            last_chunk_sha256: journal.chain.clone(),
                        };
                        self.sealed.insert(nonce, readback.clone());
                        return Ok(readback);
                    }
                    _ => unreachable!(),
                }
                Ok(active_readback(journal))
            }
        }
    }
    pub fn disconnect(&mut self, nonce: &str) {
        if let Some(journal) = self.sessions.get_mut(nonce) {
            if !journal.sealed {
                journal.disconnect();
            }
        }
    }
}
fn active_readback(journal: &CustodyJournalV1) -> CustodianReadbackV1 {
    CustodianReadbackV1 {
        descriptor: journal.descriptor.clone(),
        payload_index: Vec::new(),
        origin_commitment: Vec::new(),
        origin_receipt: Vec::new(),
        upload: None,
        next_chunk: journal.next_chunk,
        last_chunk_sha256: journal.chain.clone(),
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistentCustodianOperationV1 {
    schema_version: u8,
    sequence: u64,
    previous_sha256: DiagnosticSha256,
    role: CustodianPeerRoleV1,
    request: CustodianRequestV1,
    reply: CustodianReadbackV1,
}

fn recover_controller(
    controller: &mut CustodianControllerV1,
    storage: &Path,
) -> Result<(u64, DiagnosticSha256)> {
    let mut operations = BTreeMap::new();
    for entry in std::fs::read_dir(storage)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| CiError::Message("custodian log path is not UTF-8".into()))?;
        let sequence = name
            .strip_suffix(".json")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                CiError::Message("custodian storage contains an undeclared log member".into())
            })?;
        if operations.insert(sequence, entry.path()).is_some() {
            return fail("custodian durable operation repeats");
        }
    }
    let mut next = 0_u64;
    let mut chain = hash_bytes(b"memcordon/custodian-durable-log/v1\0");
    for (sequence, path) in operations {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
            {
                return fail("custodian durable operation protection differs");
            }
        }
        let bytes = read_bounded_file(&path, (MAX_CONTROLLER_FRAME * 2) as u64)?;
        let operation: PersistentCustodianOperationV1 =
            strict_json(&bytes, MAX_CONTROLLER_FRAME * 2)?;
        if sequence != next
            || operation.sequence != sequence
            || operation.schema_version != 1
            || operation.previous_sha256 != chain
            || canonical_bytes(&operation)? != bytes
        {
            return fail("custodian durable log continuity differs");
        }
        let reply = if let CustodianRequestV1::BeginObserved { descriptor } = &operation.request {
            // The original controller nonce is immutable. Recovery does not
            // reopen admission or allocate a replacement challenge.
            if operation.role != CustodianPeerRoleV1::Supervisor
                || !controller.approved_subjects.contains(&descriptor.subject)
                || !controller
                    .enrolled_hosts
                    .contains(&descriptor.enrolled_host)
                || operation.reply.descriptor.subject != descriptor.subject
                || controller
                    .sessions
                    .values()
                    .any(|journal| journal.descriptor.subject == descriptor.subject)
            {
                return fail("custodian recovered admission differs");
            }
            let journal = CustodyJournalV1::begin(operation.reply.descriptor.clone())?;
            let reply = active_readback(&journal);
            controller
                .sessions
                .insert(operation.reply.descriptor.session_nonce.clone(), journal);
            reply
        } else {
            controller.handle(operation.role, operation.request)?
        };
        if canonical_bytes(&reply)? != canonical_bytes(&operation.reply)? {
            return fail("custodian recovered state differs from durable ack");
        }
        chain = hash_bytes(&bytes);
        next = next
            .checked_add(1)
            .ok_or_else(|| CiError::Message("custodian log sequence overflow".into()))?;
    }
    Ok((next, chain))
}

fn persist_controller_operation(
    storage: &Path,
    sequence: &mut u64,
    chain: &mut DiagnosticSha256,
    role: CustodianPeerRoleV1,
    request: CustodianRequestV1,
    reply: CustodianReadbackV1,
) -> Result<()> {
    let record = PersistentCustodianOperationV1 {
        schema_version: 1,
        sequence: *sequence,
        previous_sha256: chain.clone(),
        role,
        request,
        reply,
    };
    let bytes = canonical_bytes(&record)?;
    if bytes.len() > MAX_CONTROLLER_FRAME * 2 {
        return fail("custodian durable operation bound differs");
    }
    let destination = storage.join(sequence.to_string()).with_extension("json");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::File::open(storage)?.sync_all()?;
    *chain = hash_bytes(&bytes);
    *sequence = sequence
        .checked_add(1)
        .ok_or_else(|| CiError::Message("custodian durable log sequence overflow".into()))?;
    Ok(())
}

impl AuthenticatedCustodianTransportV1 {
    pub fn append_representation(
        &mut self,
        lease: &AuthenticatedLiveObserverLeaseV1,
        sequence: u64,
        previous: DiagnosticSha256,
        path: String,
        bytes: Vec<u8>,
    ) -> Result<CustodianReadbackV1> {
        self.require_lease(lease)?;
        self.request(&CustodianRequestV1::AppendRepresentation {
            session_nonce: lease.descriptor.session_nonce.clone(),
            sequence,
            previous,
            path,
            bytes_hex: hex::encode(bytes),
        })
    }
    pub fn repack_sources(
        &mut self,
        lease: &AuthenticatedLiveObserverLeaseV1,
        sequence: u64,
        previous: DiagnosticSha256,
        path: String,
        sources: Vec<String>,
    ) -> Result<CustodianReadbackV1> {
        self.require_lease(lease)?;
        self.request(&CustodianRequestV1::RepackSources {
            session_nonce: lease.descriptor.session_nonce.clone(),
            sequence,
            previous,
            path,
            sources,
        })
    }
    pub fn begin_live_observed(
        &mut self,
        descriptor: ObserverSessionDescriptorV1,
    ) -> Result<AuthenticatedLiveObserverLeaseV1> {
        let subject = descriptor.subject.clone();
        let readback = self.request(&CustodianRequestV1::BeginObserved { descriptor })?;
        self.validate_descriptor(&readback.descriptor, &subject)?;
        Ok(AuthenticatedLiveObserverLeaseV1 {
            descriptor: readback.descriptor,
            policy_sha256: self.policy_sha256.clone(),
        })
    }
    pub fn begin_interval(
        &mut self,
        lease: &AuthenticatedLiveObserverLeaseV1,
        interval_id: DiagnosticSha256,
    ) -> Result<CustodianReadbackV1> {
        self.require_lease(lease)?;
        self.request(&CustodianRequestV1::BeginInterval {
            session_nonce: lease.descriptor.session_nonce.clone(),
            interval_id,
        })
    }
    pub fn observe_generation(
        &mut self,
        lease: &AuthenticatedLiveObserverLeaseV1,
        generation: ObservedGenerationV1,
    ) -> Result<CustodianReadbackV1> {
        self.require_lease(lease)?;
        self.request(&CustodianRequestV1::ObserveGeneration {
            session_nonce: lease.descriptor.session_nonce.clone(),
            generation,
        })
    }
    pub fn append(
        &mut self,
        lease: &AuthenticatedLiveObserverLeaseV1,
        sequence: u64,
        previous: DiagnosticSha256,
        path: String,
        bytes: Vec<u8>,
    ) -> Result<CustodianReadbackV1> {
        self.require_lease(lease)?;
        if bytes.is_empty() {
            if !is_exact_stream_leaf(&path) {
                return fail("custody complete leaf is empty outside an exact stream role");
            }
            let reply = self.request(&CustodianRequestV1::Append {
                session_nonce: lease.descriptor.session_nonce.clone(),
                sequence,
                previous,
                path,
                bytes_hex: String::new(),
            })?;
            if reply.next_chunk
                != sequence
                    .checked_add(1)
                    .ok_or_else(|| CiError::Message("custody append sequence overflow".into()))?
            {
                return fail("empty observed stream acknowledgment differs");
            }
            return Ok(reply);
        }
        let sha256 = hash_bytes(&bytes);
        let total_size = bytes.len() as u64;
        let mut offset = 0_u64;
        let mut readback = None;
        for part in bytes.chunks(1024 * 1024) {
            let reply = self.request(&CustodianRequestV1::AppendLeafPart {
                session_nonce: lease.descriptor.session_nonce.clone(),
                sequence,
                previous: previous.clone(),
                path: path.clone(),
                total_size,
                sha256: sha256.clone(),
                offset,
                bytes_hex: hex::encode(part),
            })?;
            offset += part.len() as u64;
            if offset < total_size
                && (reply.next_chunk != sequence || reply.last_chunk_sha256 != previous)
                || offset == total_size
                    && reply.next_chunk
                        != sequence.checked_add(1).ok_or_else(|| {
                            CiError::Message("custody append sequence overflow".into())
                        })?
            {
                return fail("custody leaf part acknowledgement differs");
            }
            readback = Some(reply);
        }
        readback
            .ok_or_else(|| CiError::Message("custody complete leaf was not acknowledged".into()))
    }
    pub fn close_interval(
        &mut self,
        lease: &AuthenticatedLiveObserverLeaseV1,
        record: ObserverIntervalRecordV1,
    ) -> Result<CustodianReadbackV1> {
        self.require_lease(lease)?;
        self.request(&CustodianRequestV1::CloseInterval {
            session_nonce: lease.descriptor.session_nonce.clone(),
            record,
        })
    }
    pub fn seal(
        &mut self,
        lease: AuthenticatedLiveObserverLeaseV1,
        cleanup_inventory_sha256: DiagnosticSha256,
        sealed_monotonic_ns: u64,
    ) -> Result<CustodianReadbackV1> {
        self.require_lease(&lease)?;
        self.request(&CustodianRequestV1::Seal {
            session_nonce: lease.descriptor.session_nonce,
            cleanup_inventory_sha256,
            sealed_monotonic_ns,
        })
    }
    /// Sealing authenticates the live controller's immutable I/K/R, but does
    /// not assert that a future Actions upload exists or completed.
    pub fn seal_and_authenticate(
        &mut self,
        lease: AuthenticatedLiveObserverLeaseV1,
        payload: BTreeMap<String, Vec<u8>>,
        cleanup_inventory_sha256: DiagnosticSha256,
        sealed_monotonic_ns: u64,
    ) -> Result<(
        AuthenticatedSealedLiveObserverSessionV1,
        CustodianReadbackV1,
    )> {
        let expected = lease.descriptor.subject.clone();
        let readback = self.seal(lease, cleanup_inventory_sha256, sealed_monotonic_ns)?;
        self.validate_descriptor(&readback.descriptor, &expected)?;
        if readback.upload.is_some() {
            return fail("live seal cannot claim a future upload");
        }
        let key: [u8; 32] = hex::decode(&self.policy.transport_public_key)
            .map_err(|_| CiError::Message("custodian key encoding differs".into()))?
            .try_into()
            .map_err(|_| CiError::Message("custodian key size differs".into()))?;
        let (_, commitment, receipt) = verify_origin_layers(
            &readback.descriptor,
            &payload,
            &readback.payload_index,
            &readback.origin_commitment,
            &readback.origin_receipt,
            &key,
        )?;
        if receipt.custodian_id != self.policy.custodian_id {
            return fail("live seal custodian differs");
        }
        let inner = AuthenticatedObserverSessionV1 {
            views: crate::private_candidate_replay::expand_replay_payload(&payload)?,
            descriptor: readback.descriptor.clone(),
            payload,
            payload_index_sha256: hash_bytes(&readback.payload_index),
            origin_commitment_sha256: hash_bytes(&readback.origin_commitment),
            receipt_sha256: hash_bytes(&readback.origin_receipt),
            generation_timeline_sha256: commitment.generation_timeline_sha256,
            upload: None,
        };
        Ok((AuthenticatedSealedLiveObserverSessionV1 { inner }, readback))
    }
    fn require_lease(&self, lease: &AuthenticatedLiveObserverLeaseV1) -> Result<()> {
        if self.policy_sha256 != lease.policy_sha256 {
            return fail("observer lease controller policy differs");
        }
        Ok(())
    }
}

/// Runs the explicitly provisioned persistent controller. Credential bytes
/// enter only through an inherited protected descriptor, never argv/env or
/// evidence output. This function performs no enrollment or key generation.
#[cfg(target_os = "linux")]
pub fn serve_custodian_controller(config_path: &Path, credential_fd: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let config: ProtectedControllerConfigV1 = strict_json(
        &crate::private_protected_readback::read_protected_raw_case_file(config_path)?,
        MAX_ORIGIN_BYTES,
    )?;
    if config.schema_version != 1
        || credential_fd < 3
        || !config.socket.is_absolute()
        || !config.storage.is_absolute()
        || config.supervisor.sha256 == config.verifier.sha256
        || config.supervisor.sha256 == config.uploader.sha256
        || config.verifier.sha256 == config.uploader.sha256
    {
        return fail("custodian controller provisioned role separation differs");
    }
    let storage = std::fs::symlink_metadata(&config.storage)?;
    if !storage.is_dir()
        || storage.uid() != 0
        || storage.mode() & 0o7777 != 0o700
        || config.socket.exists()
    {
        return fail("custodian storage/socket is not protected and fresh");
    }
    let credential_path = Path::new("/proc/self/fd").join(credential_fd.to_string());
    let mut credential = std::fs::File::open(credential_path)?;
    let metadata = credential.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() != 32
    {
        return fail("custodian inherited credential protection differs");
    }
    let mut secret = [0; 32];
    credential.read_exact(&mut secret)?;
    let signing_key = SigningKey::from_bytes(&secret);
    secret.fill(0);
    if hex::encode(signing_key.verifying_key().to_bytes()) != config.transport_public_key {
        return fail("custodian transport credential differs from protected enrollment");
    }
    let mut controller = CustodianControllerV1::new(
        config.custodian_id,
        config.approved_subjects,
        config.enrolled_hosts,
        signing_key,
    )?;
    let (mut durable_sequence, mut durable_chain) =
        recover_controller(&mut controller, &config.storage)?;
    let listener = std::os::unix::net::UnixListener::bind(&config.socket)?;
    std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
        if peer.uid.as_raw() != 0 {
            continue;
        }
        let executable = Path::new("/proc")
            .join(peer.pid.as_raw_nonzero().get().to_string())
            .join("exe");
        let peer_path = std::fs::read_link(&executable)?;
        let image = read_bounded_file(&executable, 256 * 1024 * 1024)?;
        let image_hash = hash_bytes(&image);
        let role = [
            (CustodianPeerRoleV1::Supervisor, &config.supervisor),
            (CustodianPeerRoleV1::Verifier, &config.verifier),
            (CustodianPeerRoleV1::Uploader, &config.uploader),
        ]
        .into_iter()
        .find(|(_, expected)| expected.executable == peer_path && expected.sha256 == image_hash)
        .map(|(role, _)| role);
        let Some(role) = role else {
            continue;
        };
        let mut owned_nonce = None;
        loop {
            let raw = match read_controller_frame(&mut stream) {
                Ok(raw) => raw,
                Err(_) => break,
            };
            let request: CustodianRequestV1 = strict_json(&raw, MAX_CONTROLLER_FRAME)?;
            let readback = controller.handle(role, request.clone())?;
            if role == CustodianPeerRoleV1::Supervisor {
                owned_nonce = Some(readback.descriptor.session_nonce.clone());
            }
            // Ack follows file + directory sync of the exact replayable
            // operation, including all appended bytes and admission nonce.
            let state = canonical_bytes(&readback)?;
            persist_controller_operation(
                &config.storage,
                &mut durable_sequence,
                &mut durable_chain,
                role,
                request,
                readback,
            )?;
            write_controller_frame(&mut stream, &state)?;
        }
        if let Some(nonce) = owned_nonce {
            if controller
                .sessions
                .get(&nonce)
                .is_some_and(|journal| !journal.sealed)
            {
                let request = CustodianRequestV1::Disconnect {
                    session_nonce: nonce,
                };
                let reply = controller.handle(role, request.clone())?;
                persist_controller_operation(
                    &config.storage,
                    &mut durable_sequence,
                    &mut durable_chain,
                    role,
                    request,
                    reply,
                )?;
            }
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub fn serve_custodian_controller(_config_path: &Path, _credential_fd: u32) -> Result<()> {
    fail("custodian controller requires an enrolled Linux host")
}

pub(crate) fn read_bounded_file(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > bound {
        return fail("custodian executable file bound differs");
    }
    let mut bytes = Vec::new();
    (&mut file).take(bound + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let path_after = std::fs::symlink_metadata(path)?;
    #[cfg(unix)]
    let identity_changed = {
        use std::os::unix::fs::MetadataExt;
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.uid(),
            after.mode(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
        ) || (metadata.dev(), metadata.ino()) != (path_after.dev(), path_after.ino())
    };
    #[cfg(not(unix))]
    let identity_changed = !path_after.is_file() || after.len() != metadata.len();
    if bytes.len() as u64 != metadata.len() || identity_changed {
        return fail("custodian executable changed during read");
    }
    Ok(bytes)
}

pub fn write_controller_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_CONTROLLER_FRAME {
        return fail("custodian frame exceeds bound");
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| CiError::Message("custodian frame length overflow".into()))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}
pub fn read_controller_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0; std::mem::size_of::<u32>()];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_CONTROLLER_FRAME {
        return fail("custodian frame length differs");
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn nonzero(digest: &DiagnosticSha256) -> bool {
    digest.bytes() != &[0; 32] && digest != &hash_bytes(&[])
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
