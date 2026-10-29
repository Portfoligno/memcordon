//! Current typed documents over the unchanged bounded one-level byte store.
use super::{EvidenceIndexV2, ProducerManifestV2, ProductObservationV2};
use crate::{
    Artifact, VerificationResult,
    storage::{ArtifactBinding, StoragePlan},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackedProducerManifestV2 {
    pub format: String,
    pub revision: u32,
    pub producer: ProducerManifestV2,
    pub objects: Vec<Artifact>,
    pub bindings: Vec<ArtifactBinding>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackedEvidenceIndexV2 {
    pub format: String,
    pub revision: u32,
    pub evidence: EvidenceIndexV2,
    pub objects: Vec<Artifact>,
    pub bindings: Vec<ArtifactBinding>,
}
fn header(format: &str, revision: u32, expected: &str) -> VerificationResult<()> {
    if format != expected || revision != 2 {
        return Err("current evidence format/revision differs".into());
    }
    Ok(())
}
pub fn decode_producer(bytes: &[u8]) -> VerificationResult<(ProducerManifestV2, StoragePlan)> {
    if bytes.len() > crate::MAX_INDEX_BYTES {
        return Err("current producer exceeds metadata bound".into());
    }
    let value: serde_json::Value = crate::wire::decode(bytes)?;
    if value["format"].as_str() == Some("memcordon.consumer-readiness.producer") {
        let producer: ProducerManifestV2 = crate::wire::decode(bytes)?;
        header(
            &producer.format,
            producer.revision,
            "memcordon.consumer-readiness.producer",
        )?;
        let storage = StoragePlan::direct(&producer.artifacts)?;
        storage.check_budget(bytes.len() as u64)?;
        return Ok((producer, storage));
    }
    let packed: PackedProducerManifestV2 = crate::wire::decode(bytes)?;
    header(
        &packed.format,
        packed.revision,
        "memcordon.consumer-readiness.packed-producer",
    )?;
    header(
        &packed.producer.format,
        packed.producer.revision,
        "memcordon.consumer-readiness.producer",
    )?;
    let total = packed.producer.artifacts.iter().try_fold(0u64, |n, a| {
        n.checked_add(a.length)
            .ok_or("current logical producer byte overflow")
    })?;
    if total > crate::MAX_PRODUCER_BYTES {
        return Err("current logical producer exceeds bound".into());
    }
    let storage = StoragePlan::packed(
        &packed.producer.artifacts,
        &packed.objects,
        &packed.bindings,
        &BTreeSet::new(),
    )?;
    storage.check_budget(bytes.len() as u64)?;
    Ok((packed.producer, storage))
}
pub fn decode_evidence(bytes: &[u8]) -> VerificationResult<(EvidenceIndexV2, StoragePlan)> {
    if bytes.len() > crate::MAX_INDEX_BYTES {
        return Err("current index exceeds metadata bound".into());
    }
    let value: serde_json::Value = crate::wire::decode(bytes)?;
    if value["format"].as_str() == Some("memcordon.consumer-readiness.evidence") {
        let evidence: EvidenceIndexV2 = crate::wire::decode(bytes)?;
        header(
            &evidence.format,
            evidence.revision,
            "memcordon.consumer-readiness.evidence",
        )?;
        if evidence.profile != super::PROFILE {
            return Err("current evidence profile differs".into());
        }
        let storage = StoragePlan::direct(&evidence.artifacts)?;
        storage.check_budget(bytes.len() as u64)?;
        return Ok((evidence, storage));
    }
    let packed: PackedEvidenceIndexV2 = crate::wire::decode(bytes)?;
    header(
        &packed.format,
        packed.revision,
        "memcordon.consumer-readiness.packed-evidence",
    )?;
    header(
        &packed.evidence.format,
        packed.evidence.revision,
        "memcordon.consumer-readiness.evidence",
    )?;
    if packed.evidence.profile != super::PROFILE {
        return Err("current evidence profile differs".into());
    }
    let archives = packed
        .evidence
        .producer_origins
        .iter()
        .map(|o| o.bundle_artifact.clone())
        .collect();
    let storage = StoragePlan::packed(
        &packed.evidence.artifacts,
        &packed.objects,
        &packed.bindings,
        &archives,
    )?;
    storage.check_budget(bytes.len() as u64)?;
    Ok((packed.evidence, storage))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    run_id: String,
    source_commit: String,
    source_tree_sha256: String,
    version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cell {
    format: String,
    revision: u32,
    identity: Source,
    key: crate::ProductKey,
    product: Option<ProductObservationV2>,
    component_build: Option<crate::ComponentBuild>,
    records: Vec<crate::CaseRecord>,
    artifacts: Vec<Artifact>,
    cleanup_failures: Vec<String>,
    cache_quiescent: bool,
}
pub fn validate_cell(producer: &ProducerManifestV2, bytes: &[u8]) -> VerificationResult<()> {
    if bytes.len() > crate::MAX_INDEX_BYTES * 2 {
        return Err("current cell exceeds bound".into());
    }
    let cell: Cell = crate::wire::decode(bytes)?;
    header(
        &cell.format,
        cell.revision,
        "memcordon.consumer-readiness.cell",
    )?;
    if cell.identity.run_id != producer.run_id
        || cell.identity.source_commit != producer.source_commit
        || cell.identity.source_tree_sha256 != producer.source_tree_sha256
        || cell.identity.version != producer.version
        || cell.product.as_ref().is_some_and(|p| p.key != cell.key)
        || cell
            .component_build
            .as_ref()
            .is_some_and(|b| b.target != cell.key.target)
        || cell.records.iter().any(|r| {
            r.key.target != cell.key.target
                || r.run_id != cell.identity.run_id
                || r.key
                    .channel
                    .as_ref()
                    .is_some_and(|c| c != &cell.key.channel)
        })
        || ((!cell.cleanup_failures.is_empty() || !cell.cache_quiescent)
            && cell
                .records
                .iter()
                .any(|r| r.state != crate::CaseState::Failed))
    {
        return Err("current producer original cell association differs".into());
    }
    let pairs = [
        (
            serde_json::to_value(&cell.artifacts),
            serde_json::to_value(&producer.artifacts),
        ),
        (
            serde_json::to_value(&cell.records),
            serde_json::to_value(&producer.records),
        ),
        (
            serde_json::to_value(cell.product.into_iter().collect::<Vec<_>>()),
            serde_json::to_value(&producer.products),
        ),
        (
            serde_json::to_value(cell.component_build.into_iter().collect::<Vec<_>>()),
            serde_json::to_value(&producer.component_builds),
        ),
    ];
    for (left, right) in pairs {
        if left.map_err(|e| e.to_string())? != right.map_err(|e| e.to_string())? {
            return Err("current producer differs from original immutable cell".into());
        }
    }
    Ok(())
}
