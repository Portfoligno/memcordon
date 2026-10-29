//! Explicit current evidence ledger. Historical records cannot deserialize here.
use crate::readiness_identity::{LedgerResult, SourceIdentity};
use memcordon_readiness_verifier::current::{
    EvidenceIndexV2, ProductObservationV2, ReadinessManifestV2,
};
use memcordon_readiness_verifier::{Artifact, CaseRecord, CaseState, ComponentBuild, ProductKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellEvidenceV2 {
    pub format: String,
    pub revision: u32,
    pub identity: SourceIdentity,
    pub key: ProductKey,
    pub product: Option<ProductObservationV2>,
    pub component_build: Option<ComponentBuild>,
    pub records: Vec<CaseRecord>,
    pub artifacts: Vec<Artifact>,
    pub cleanup_failures: Vec<String>,
    pub cache_quiescent: bool,
}

pub fn initialize(path: &Path, identity: SourceIdentity) -> LedgerResult<EvidenceIndexV2> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let keys = memcordon_readiness_verifier::current::validate_manifest(&bytes)?;
    let manifest: ReadinessManifestV2 =
        toml::from_str(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let cells = manifest
        .targets
        .iter()
        .flat_map(|target| {
            manifest.channels.iter().map(move |channel| ProductKey {
                target: target.clone(),
                channel: channel.clone(),
            })
        })
        .collect();
    let records = keys
        .iter()
        .map(|key| CaseRecord {
            key: key.clone(),
            run_id: identity.run_id.clone(),
            state: CaseState::NotRun,
            reason: Some("acquisition not run".into()),
            evidence: None,
        })
        .collect();
    Ok(EvidenceIndexV2 {
        format: "memcordon.consumer-readiness.evidence".into(),
        revision: 2,
        profile: manifest.profile,
        run_id: identity.run_id,
        source_commit: identity.source_commit,
        source_tree_sha256: identity.source_tree_sha256,
        version: identity.version,
        manifest_sha256: hex::encode(Sha256::digest(&bytes)),
        repository: None,
        products: Vec::new(),
        component_builds: Vec::new(),
        workflow_cells: cells,
        fixture_cases: keys.into_iter().collect(),
        artifacts: Vec::new(),
        records,
        producer_origins: Vec::new(),
        job_outcomes: Vec::new(),
        assessment_failures: Vec::new(),
    })
}

pub fn ingest_resolved(
    index: &mut EvidenceIndexV2,
    cell: CellEvidenceV2,
    mut retain: impl FnMut(&Artifact) -> LedgerResult<()>,
) -> LedgerResult<()> {
    let target_job = match cell.key.target.as_str() {
        "x86_64-unknown-linux-gnu" => "linux-x64",
        "aarch64-unknown-linux-gnu" => "linux-arm64",
        "x86_64-pc-windows-msvc" => "windows-x64",
        "aarch64-pc-windows-msvc" => "windows-arm64",
        _ => return Err("unsupported current cell target".into()),
    };
    let job = if cell.component_build.is_some() {
        format!("native-{target_job}")
    } else {
        let (source, route) = cell
            .key
            .channel
            .split_once('-')
            .ok_or("invalid current source/channel")?;
        format!("{source}-{target_job}-{route}")
    };
    let original_run = cell.identity.run_id == index.run_id
        || index.producer_origins.iter().any(|origin| {
            origin.job == job
                && origin.run_id == cell.identity.run_id
                && origin.source_commit == cell.identity.source_commit
                && origin.source_tree_sha256 == cell.identity.source_tree_sha256
                && origin.version == cell.identity.version
        });
    if index.revision != 2
        || index.profile != memcordon_readiness_verifier::current::PROFILE
        || cell.format != "memcordon.consumer-readiness.cell"
        || cell.revision != 2
        || !original_run
        || cell.identity.source_commit != index.source_commit
        || cell.identity.source_tree_sha256 != index.source_tree_sha256
        || cell.identity.version != index.version
        || !index.workflow_cells.contains(&cell.key)
        || index.products.iter().any(|p| p.key == cell.key)
    {
        return Err(
            "current cell identity/version/source differs or acquisition duplicated".into(),
        );
    }
    if cell.product.as_ref().is_some_and(|p| {
        p.key != cell.key
            || p.source_commit != index.source_commit
            || p.source_tree_sha256 != index.source_tree_sha256
            || p.version != index.version
    }) {
        return Err("current selected product binding differs".into());
    }
    if let Some(product) = &cell.product {
        memcordon_readiness_verifier::current::validate_product_protocols(product)?;
    }
    if cell.component_build.as_ref().is_some_and(|b| {
        b.target != cell.key.target
            || b.source_commit != index.source_commit
            || b.source_tree_sha256 != index.source_tree_sha256
            || index
                .component_builds
                .iter()
                .any(|old| old.target == b.target)
    }) {
        return Err("current component build binding differs or duplicated".into());
    }
    let mut rows = BTreeSet::new();
    for row in &cell.records {
        if row.run_id != cell.identity.run_id
            || row.key.target != cell.key.target
            || row
                .key
                .channel
                .as_ref()
                .is_some_and(|c| c != &cell.key.channel)
            || !rows.insert(row.key.clone())
            || !index
                .records
                .iter()
                .any(|old| old.key == row.key && old.state == CaseState::NotRun)
        {
            return Err("current cell row unplanned/reassociated/already observed".into());
        }
    }
    let prefix = format!("{}/{}/", cell.key.target, cell.key.channel);
    let mut paths = BTreeSet::new();
    for artifact in &cell.artifacts {
        if !artifact.path.starts_with(&prefix)
            || Path::new(&artifact.path)
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
            || !paths.insert(&artifact.path)
            || index.artifacts.iter().any(|old| old.path == artifact.path)
        {
            return Err("current artifact path duplicate/foreign/unsafe".into());
        }
    }
    // Validate the whole mutation before retaining bytes or replacing any row.
    for artifact in &cell.artifacts {
        retain(artifact)?;
    }
    let clean = cell.cleanup_failures.is_empty() && cell.cache_quiescent;
    for mut row in cell.records {
        if !clean {
            row.state = CaseState::Failed;
            row.reason = Some(format!(
                "cleanup/cache quiescence failed: {:?}",
                cell.cleanup_failures
            ));
        }
        let planned = index
            .records
            .iter_mut()
            .find(|old| old.key == row.key)
            .ok_or("planned current row absent")?;
        *planned = row;
    }
    if let Some(product) = cell.product {
        index.products.push(product);
    }
    if let Some(build) = cell.component_build {
        index.component_builds.push(build);
    }
    index.artifacts.extend(cell.artifacts);
    Ok(())
}

#[derive(Default)]
pub struct PackedLedger {
    objects: std::collections::BTreeMap<String, Artifact>,
    bindings:
        std::collections::BTreeMap<String, memcordon_readiness_verifier::storage::ArtifactBinding>,
}
impl PackedLedger {
    pub fn check_archive(&self, index: &EvidenceIndexV2, archive: &Artifact) -> LedgerResult<()> {
        let mut logical = index.artifacts.clone();
        logical.push(archive.clone());
        let mut archives: BTreeSet<_> = index
            .producer_origins
            .iter()
            .map(|o| o.bundle_artifact.clone())
            .collect();
        archives.insert(archive.path.clone());
        memcordon_readiness_verifier::storage::StoragePlan::packed(
            &logical,
            &self.objects.values().cloned().collect::<Vec<_>>(),
            &self.bindings.values().cloned().collect::<Vec<_>>(),
            &archives,
        )
        .map(|_| ())
    }
    pub fn ingest(
        &mut self,
        index: &mut EvidenceIndexV2,
        cell: CellEvidenceV2,
        source: &Path,
        destination: &Path,
        storage: &memcordon_readiness_verifier::storage::StoragePlan,
    ) -> LedgerResult<()> {
        use memcordon_readiness_verifier::{
            read_artifact_bytes, retain_artifact_bytes,
            storage::{ArtifactBinding, StoragePlan, object_path},
        };
        let previous = index.artifacts.clone();
        let archives = index
            .producer_origins
            .iter()
            .map(|o| o.bundle_artifact.clone())
            .collect();
        let mut captured = Vec::new();
        let result = ingest_resolved(index, cell, |logical| {
            let bytes = read_artifact_bytes(source, storage.resolve(&logical.path)?)?;
            if bytes.len() as u64 != logical.length
                || hex::encode(Sha256::digest(&bytes)) != logical.sha256
            {
                return Err("current producer physical/logical bytes differ".into());
            }
            let object = Artifact {
                path: object_path(&logical.sha256)?,
                length: logical.length,
                sha256: logical.sha256.clone(),
            };
            let binding = ArtifactBinding {
                logical_path: logical.path.clone(),
                object_path: object.path.clone(),
            };
            let mut objects = self.objects.clone();
            if objects
                .get(&object.path)
                .is_some_and(|old| old.length != object.length || old.sha256 != object.sha256)
            {
                return Err("current object digest key conflicts".into());
            }
            objects.insert(object.path.clone(), object.clone());
            let mut bindings = self.bindings.clone();
            if bindings
                .insert(logical.path.clone(), binding.clone())
                .is_some()
            {
                return Err("current logical binding duplicated".into());
            }
            let plan: Vec<_> = previous
                .iter()
                .chain(&captured)
                .chain(std::iter::once(logical))
                .cloned()
                .collect();
            StoragePlan::packed(
                &plan,
                &objects.into_values().collect::<Vec<_>>(),
                &bindings.into_values().collect::<Vec<_>>(),
                &archives,
            )?;
            retain_artifact_bytes(
                destination,
                &object,
                &bytes,
                self.objects.contains_key(&object.path),
            )?;
            self.objects.insert(object.path.clone(), object);
            self.bindings.insert(logical.path.clone(), binding);
            captured.push(logical.clone());
            Ok(())
        });
        if result.is_err() {
            index.artifacts.extend(captured);
        }
        result
    }
    pub fn persist(
        &self,
        index: &EvidenceIndexV2,
        path: &Path,
        artifact_root: &Path,
    ) -> LedgerResult<()> {
        use memcordon_readiness_verifier::current::storage::{
            PackedEvidenceIndexV2, decode_evidence,
        };
        use std::io::Write;
        let envelope = PackedEvidenceIndexV2 {
            format: "memcordon.consumer-readiness.packed-evidence".into(),
            revision: 2,
            evidence: index.clone(),
            objects: self.objects.values().cloned().collect(),
            bindings: self.bindings.values().cloned().collect(),
        };
        let mut bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let (_, storage) = decode_evidence(&bytes)?;
        storage.validate_directory(artifact_root)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        output
            .write_all(&bytes)
            .and_then(|_| output.sync_all())
            .map_err(|e| e.to_string())
    }
}

pub fn record_origin(
    index: &mut EvidenceIndexV2,
    origin: memcordon_readiness_verifier::ProducerOrigin,
) -> LedgerResult<()> {
    if origin.run_id.is_empty()
        || origin.run_attempt == 0
        || origin
            .artifact_id
            .parse::<u64>()
            .ok()
            .is_none_or(|id| id == 0)
        || origin.source_commit != index.source_commit
        || origin.source_tree_sha256 != index.source_tree_sha256
        || origin.version != index.version
        || origin.manifest_sha256 != index.manifest_sha256
        || index
            .producer_origins
            .iter()
            .any(|old| old.job == origin.job)
    {
        return Err("current producer origin invalid/duplicate".into());
    }
    index.producer_origins.push(origin);
    Ok(())
}

pub fn record_job_outcomes(
    index: &mut EvidenceIndexV2,
    outcomes: Vec<memcordon_readiness_verifier::JobOutcome>,
) -> LedgerResult<()> {
    if !index.job_outcomes.is_empty()
        || outcomes
            .iter()
            .map(|o| o.job.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != outcomes.len()
        || outcomes.iter().any(|o| o.job.is_empty())
    {
        return Err("current job outcomes duplicate/invalid".into());
    }
    index.job_outcomes = outcomes;
    Ok(())
}

pub fn persist(index: &EvidenceIndexV2, path: &Path) -> LedgerResult<()> {
    use std::io::Write;
    let mut bytes = serde_json::to_vec_pretty(index).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    memcordon_readiness_verifier::current::storage::decode_evidence(&bytes)?;
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    output
        .write_all(&bytes)
        .and_then(|_| output.sync_all())
        .map_err(|e| e.to_string())
}

pub use crate::readiness_identity::parse_job_outcomes;
