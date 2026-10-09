//! Producer bookkeeping. Acceptance belongs to the separate verifier executable.
use memcordon_readiness_verifier::{
    Artifact, CaseKey, CaseRecord, CaseState, ComponentBuild, EvidenceClass, EvidenceIndex,
    JobOutcome, JobResult, Manifest, ProducerOrigin, ProductKey, ProductObservation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub type LedgerResult<T> = Result<T, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExclusiveAccount {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub intent: std::path::PathBuf,
    pub native_readback: std::path::PathBuf,
    pub group_readback: std::path::PathBuf,
}

pub fn validate_account_creation_paths(
    output: &Path,
    account: &ExclusiveAccount,
) -> LedgerResult<()> {
    if account.intent != output.join("exclusive-account-intent.json")
        || account.native_readback != output.join("exclusive-account-getent.bin")
        || account.group_readback != output.join("exclusive-group-getent.bin")
    {
        return Err("original account creation readback paths differ from owned output".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellEvidence {
    pub format: String,
    pub revision: u32,
    pub identity: SourceIdentity,
    pub key: ProductKey,
    pub product: Option<ProductObservation>,
    pub component_build: Option<ComponentBuild>,
    pub records: Vec<CaseRecord>,
    pub artifacts: Vec<Artifact>,
    pub cleanup_failures: Vec<String>,
    pub cache_quiescent: bool,
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn initialize(manifest_path: &Path, identity: SourceIdentity) -> LedgerResult<EvidenceIndex> {
    let bytes = fs::read(manifest_path).map_err(|e| e.to_string())?;
    let manifest: Manifest =
        toml::from_str(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let mut cells = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for target in &manifest.targets {
        for channel in &manifest.channels {
            if !cells.insert(ProductKey {
                target: target.clone(),
                channel: channel.clone(),
            }) {
                return Err("duplicate producer workflow cell".into());
            }
        }
        for case in &manifest.cases {
            let applicable = match case.platform.as_str() {
                "both" => true,
                "linux" => target.contains("linux"),
                "windows" => target.contains("windows"),
                _ => return Err("unknown producer platform".into()),
            };
            if !applicable {
                continue;
            }
            let channels: Vec<Option<String>> = match case.evidence_class {
                EvidenceClass::InstalledProduct => {
                    manifest.channels.iter().cloned().map(Some).collect()
                }
                EvidenceClass::NativeComponentRegression => vec![None],
            };
            for channel in channels {
                for scenario in &case.scenarios {
                    if !keys.insert(CaseKey {
                        target: target.clone(),
                        channel: channel.clone(),
                        evidence_class: case.evidence_class,
                        family: case.family.clone(),
                        scenario: scenario.clone(),
                    }) {
                        return Err("duplicate producer case".into());
                    }
                }
            }
        }
    }
    let fixture_cases: Vec<_> = keys.into_iter().collect();
    let records = fixture_cases
        .iter()
        .cloned()
        .map(|key| CaseRecord {
            key,
            run_id: identity.run_id.clone(),
            state: CaseState::NotRun,
            reason: Some("acquisition not run".into()),
            evidence: None,
        })
        .collect();
    Ok(EvidenceIndex {
        format: "memcordon.consumer-readiness.evidence".into(),
        revision: 1,
        profile: manifest.profile,
        run_id: identity.run_id,
        source_commit: identity.source_commit,
        source_tree_sha256: identity.source_tree_sha256,
        version: identity.version,
        manifest_sha256: hash(&bytes),
        repository: None,
        products: vec![],
        component_builds: vec![],
        workflow_cells: cells.into_iter().collect(),
        fixture_cases,
        artifacts: vec![],
        records,
        producer_origins: vec![],
        job_outcomes: vec![],
        assessment_failures: vec![],
    })
}

fn safe_relative(path: &str) -> LedgerResult<()> {
    if path.is_empty()
        || path.contains(['\\', ':', '\0'])
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err("artifact path escapes cell custody".into());
    }
    Ok(())
}

/// Copies only independently named regular artifacts into a fresh evidence root.
/// Every row remains visible even if acquisition or cleanup failed.
pub fn ingest(
    index: &mut EvidenceIndex,
    cell: CellEvidence,
    source: &Path,
    destination: &Path,
) -> LedgerResult<()> {
    if cell.format != "memcordon.consumer-readiness.cell"
        || cell.revision != 1
        || cell.identity.run_id.is_empty()
        || cell.identity.source_commit != index.source_commit
        || cell.identity.source_tree_sha256 != index.source_tree_sha256
        || cell.identity.version != index.version
        || !index.workflow_cells.contains(&cell.key)
    {
        return Err("cell identity/source/channel is not planned".into());
    }
    if index.products.iter().any(|p| p.key == cell.key) {
        return Err("duplicate product acquisition".into());
    }
    if cell.product.as_ref().is_some_and(|p| {
        p.key != cell.key
            || p.source_commit != index.source_commit
            || p.source_tree_sha256 != index.source_tree_sha256
            || p.version != index.version
    }) {
        return Err("product identity differs from cell/source".into());
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
        return Err("component target/source duplicate/reassociated".into());
    }
    let mut updates = BTreeSet::new();
    for record in &cell.records {
        if record.run_id != cell.identity.run_id
            || record.key.target != cell.key.target
            || (record.key.channel.is_some()
                && record.key.channel.as_ref() != Some(&cell.key.channel))
            || !index.fixture_cases.contains(&record.key)
            || !updates.insert(record.key.clone())
        {
            return Err("cell row duplicate/unplanned/reassociated".into());
        }
        let old = index
            .records
            .iter()
            .find(|r| r.key == record.key)
            .ok_or("planned row absent")?;
        if old.state != CaseState::NotRun {
            return Err("cell attempts to replace an observed row".into());
        }
    }
    let mut artifacts = Vec::new();
    for artifact in &cell.artifacts {
        safe_relative(&artifact.path)?;
        let prefix = format!("{}/{}/", cell.key.target, cell.key.channel);
        if !artifact.path.starts_with(&prefix) {
            return Err("cell artifact omits target/channel custody namespace".into());
        }
        if index.artifacts.iter().any(|a| a.path == artifact.path)
            || artifacts.iter().any(|a: &Artifact| a.path == artifact.path)
        {
            return Err("duplicate persisted artifact".into());
        }
        let mut current = source.to_path_buf();
        for part in artifact.path.split('/') {
            current.push(part);
            if fs::symlink_metadata(&current)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("artifact contains symlink".into());
            }
        }
        let metadata = fs::metadata(&current).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
            return Err("artifact is not bounded regular file".into());
        }
        let bytes = fs::read(&current).map_err(|e| e.to_string())?;
        if bytes.len() as u64 != artifact.length || hash(&bytes) != artifact.sha256 {
            return Err("acquired artifact changed before ledger custody".into());
        }
        let target = destination.join(&artifact.path);
        fs::create_dir_all(target.parent().ok_or("artifact parent absent")?)
            .map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        artifacts.push(Artifact {
            path: artifact.path.clone(),
            length: bytes.len() as u64,
            sha256: hash(&bytes),
        });
    }
    let cleanup_ok = cell.cleanup_failures.is_empty() && cell.cache_quiescent;
    for mut record in cell.records {
        if !cleanup_ok {
            record.state = CaseState::Failed;
            record.reason = Some(format!(
                "cleanup/cache quiescence failed: {:?}",
                cell.cleanup_failures
            ));
        }
        let row = index
            .records
            .iter_mut()
            .find(|r| r.key == record.key)
            .ok_or("planned row absent")?;
        *row = record;
    }
    if let Some(product) = cell.product {
        if product.key != cell.key {
            return Err("product key differs from cell".into());
        }
        index.products.push(product);
    }
    if let Some(build) = cell.component_build {
        if build.target != cell.key.target
            || index
                .component_builds
                .iter()
                .any(|b| b.target == build.target)
        {
            return Err("component target duplicate/reassociated".into());
        }
        index.component_builds.push(build);
    }
    index.artifacts.extend(artifacts);
    Ok(())
}

pub fn persist(index: &EvidenceIndex, path: &Path) -> LedgerResult<()> {
    let bytes = serde_json::to_vec_pretty(index).map_err(|e| e.to_string())?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    output
        .write_all(&bytes)
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.sync_all())
        .map_err(|e| e.to_string())
}

/// The aggregator receives actual upload IDs and producer attempts from the
/// selected workflow transport. It does not rewrite raw earlier-run evidence.
pub fn record_origin(index: &mut EvidenceIndex, origin: ProducerOrigin) -> LedgerResult<()> {
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
        return Err("duplicate/invalid selected producer origin".into());
    }
    index.producer_origins.push(origin);
    Ok(())
}

/// Records every scheduled expected job including failure, cancellation, skip
/// and missing output. Independent verification checks the required key set.
pub fn record_job_outcomes(
    index: &mut EvidenceIndex,
    outcomes: Vec<JobOutcome>,
) -> LedgerResult<()> {
    let keys = outcomes
        .iter()
        .map(|outcome| outcome.job.as_str())
        .collect::<BTreeSet<_>>();
    if keys.len() != outcomes.len() || !index.job_outcomes.is_empty() {
        return Err("duplicate producer job outcome".into());
    }
    for outcome in &outcomes {
        if outcome.result != JobResult::Success {
            // A failed workflow producer cannot substantiate passed rows.
            // Row custody and required finite job keys are assessed separately.
            if outcome.job.is_empty() {
                return Err("missing producer job key".into());
            }
        }
    }
    index.job_outcomes = outcomes;
    Ok(())
}

pub fn parse_job_outcomes(arguments: &[String]) -> LedgerResult<Vec<JobOutcome>> {
    if arguments.is_empty() || arguments.len() > 32 {
        return Err("finite job outcome input is empty/oversized".into());
    }
    let allowed = ["linux-x64", "linux-arm64", "windows-x64", "windows-arm64"]
        .into_iter()
        .flat_map(|label| {
            [
                format!("native-{label}"),
                format!("candidate-{label}-native"),
                format!("candidate-{label}-cargo"),
                format!("public-{label}-native"),
                format!("public-{label}-cargo"),
            ]
        })
        .collect::<BTreeSet<_>>();
    let mut keys = BTreeSet::new();
    arguments
        .iter()
        .map(|argument| {
            let (job, result) = argument
                .split_once('=')
                .ok_or("job outcome requires one name=value operand")?;
            if !allowed.contains(job) || !keys.insert(job.to_owned()) {
                return Err("duplicate/malformed producer job operand".into());
            }
            let result = match result {
                "success" => JobResult::Success,
                "failure" => JobResult::Failure,
                "cancelled" => JobResult::Cancelled,
                "skipped" => JobResult::Skipped,
                "missing" => JobResult::Missing,
                _ => return Err("unknown job outcome enum".into()),
            };
            Ok(JobOutcome {
                job: job.to_owned(),
                result,
            })
        })
        .collect()
}
