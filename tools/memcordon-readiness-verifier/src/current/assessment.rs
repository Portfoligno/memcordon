//! Current source/provenance/custody checks shared by independent native validators.
use super::*;
use crate::{CaseState, ComponentBuild, ProducerOrigin, ProductKey, Verdict, VerificationScope};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

pub type CaseVerifier = dyn Fn(
    &CaseEvidenceV2,
    &serde_json::Value,
    Option<&ProductObservationV2>,
    Option<&ComponentBuild>,
    &str,
    Option<&str>,
    &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()>;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeComponent {
    id: String,
    path: String,
    role: String,
    size: u64,
    mode: u32,
    sha256: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IncludedRuntime {
    selection: String,
    agent_component: String,
    native_protocols: NativeProviderProtocolsV2,
    mechanism: String,
    workload_request: WireVersion,
    result: WireVersion,
    profile: String,
    profile_revision: u32,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeInventory {
    format: String,
    revision: u32,
    project: String,
    version: String,
    source_commit: String,
    target: String,
    components: Vec<RuntimeComponent>,
    sealed: IncludedRuntime,
}

fn original_producer(
    index: &EvidenceIndexV2,
    origin: &ProducerOrigin,
    custody: &crate::custody::Custody,
) -> VerificationResult<BTreeSet<String>> {
    if origin.repository != index.repository
        || custody.hash(&origin.bundle_artifact)? != origin.artifact_sha256
    {
        return Err("current producer repository/archive digest differs".into());
    }
    let mut archive = zip::ZipArchive::new(custody.archive(&origin.bundle_artifact)?)
        .map_err(|e| e.to_string())?;
    if archive.len() > crate::MAX_PRODUCER_ARTIFACTS {
        return Err("current producer archive member bound".into());
    }
    let mut members = Vec::new();
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for ordinal in 0..archive.len() {
        let member = archive.by_index(ordinal).map_err(|e| e.to_string())?;
        let name = member.name().map_err(|e| e.to_string())?.into_owned();
        crate::custody::validate_path(name.strip_suffix('/').unwrap_or(&name))?;
        if !names.insert(name.clone()) || member.size() > crate::MAX_ARTIFACT_BYTES {
            return Err("current producer member duplicate/oversized".into());
        }
        if let Some(mode) = member.unix_mode() {
            let kind = mode & 0o170000;
            if ![0, 0o100000, 0o040000].contains(&kind)
                || (kind == 0o040000 && !member.is_dir())
                || (kind == 0o100000 && member.is_dir())
            {
                return Err("current producer archive contains special member".into());
            }
        }
        total = total
            .checked_add(member.size())
            .ok_or("current archive total overflow")?;
        if total > crate::MAX_PRODUCER_BYTES {
            return Err("current archive decompressed total bound".into());
        }
        members.push(crate::storage::ZipMember {
            name,
            length: member.size(),
            directory: member.is_dir(),
        });
    }
    let read_member = |archive: &mut zip::ZipArchive<std::fs::File>,
                       name: &str,
                       maximum: u64|
     -> VerificationResult<Vec<u8>> {
        let member = archive.by_name(name).map_err(|e| e.to_string())?;
        let size = member.size();
        if member.is_dir() || size > maximum {
            return Err("current producer metadata bound/type differs".into());
        }
        let mut bytes = Vec::new();
        member
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 != size {
            return Err("current producer member decoded length differs".into());
        }
        Ok(bytes)
    };
    let bytes = read_member(
        &mut archive,
        "producer-manifest.json",
        crate::MAX_INDEX_BYTES as u64,
    )?;
    let (manifest, storage) = super::storage::decode_producer(&bytes)?;
    let length = index
        .artifacts
        .iter()
        .find(|a| a.path == origin.bundle_artifact)
        .ok_or("current archive not indexed")?
        .length;
    storage.validate_zip(&members, length)?;
    let cell = read_member(
        &mut archive,
        "cell.json",
        (crate::MAX_INDEX_BYTES * 2) as u64,
    )?;
    super::storage::validate_cell(&manifest, &cell)?;
    if manifest.job != origin.job
        || manifest.run_id != origin.run_id
        || manifest.run_attempt != origin.run_attempt
        || manifest.source_commit != origin.source_commit
        || manifest.source_tree_sha256 != origin.source_tree_sha256
        || manifest.version != origin.version
        || manifest.manifest_sha256 != origin.manifest_sha256
        || manifest.products.len() > 1
        || manifest.component_builds.len() > 1
        || manifest.records.len() > 16384
    {
        return Err("current original producer identity/inventory differs".into());
    }
    let original_keys = manifest
        .records
        .iter()
        .map(|row| row.key.clone())
        .collect::<BTreeSet<_>>();
    let indexed_keys = index
        .records
        .iter()
        .filter_map(|row| {
            crate::producer_job(&row.key.target, row.key.channel.as_deref())
                .ok()
                .filter(|job| job == &origin.job)
                .map(|_| row.key.clone())
        })
        .collect::<BTreeSet<_>>();
    if original_keys.len() != manifest.records.len() || original_keys != indexed_keys {
        return Err("current original producer row inventory was omitted or expanded".into());
    }
    if index
        .products
        .iter()
        .filter(|product| {
            crate::producer_job(&product.key.target, Some(&product.key.channel))
                .ok()
                .as_ref()
                == Some(&origin.job)
        })
        .count()
        != manifest.products.len()
        || index
            .component_builds
            .iter()
            .filter(|build| {
                crate::producer_job(&build.target, None).ok().as_ref() == Some(&origin.job)
            })
            .count()
            != manifest.component_builds.len()
    {
        return Err(
            "current original producer product/build inventory was omitted or expanded".into(),
        );
    }
    let mut seen = BTreeSet::new();
    for artifact in &manifest.artifacts {
        if !seen.insert(&artifact.path)
            || artifact.path == origin.bundle_artifact
            || artifact.path == "producer-manifest.json"
        {
            return Err("current original producer logical names differ".into());
        }
        let indexed = index
            .artifacts
            .iter()
            .find(|a| a.path == artifact.path)
            .ok_or("current original artifact not indexed")?;
        if indexed.length != artifact.length || indexed.sha256 != artifact.sha256 {
            return Err("current indexed capture differs from original producer".into());
        }
        let physical = storage.resolve(&artifact.path)?;
        let mut member = archive.by_name(&physical.path).map_err(|e| e.to_string())?;
        if member.is_dir() || member.size() != physical.length {
            return Err("current original physical member length/type differs".into());
        }
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        let mut length = 0u64;
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let count = member.read(&mut chunk).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .ok_or("current original member byte overflow")?;
            if length > artifact.length {
                return Err("current original member exceeds declared bytes".into());
            }
            hash.update(&chunk[..count]);
        }
        if length != artifact.length
            || hex::encode(hash.finalize()) != artifact.sha256
            || custody.hash(&artifact.path)? != artifact.sha256
        {
            return Err("current original producer bytes differ".into());
        }
    }
    for record in &manifest.records {
        if record.run_id != origin.run_id
            || crate::producer_job(&record.key.target, record.key.channel.as_deref())? != origin.job
        {
            return Err("current original producer row crosses job/run".into());
        }
        let indexed = index
            .records
            .iter()
            .find(|r| r.key == record.key)
            .ok_or("current original row absent from index")?;
        if record
            .evidence
            .as_ref()
            .is_some_and(|path| !manifest.artifacts.iter().any(|a| &a.path == path))
        {
            return Err("current original row evidence omitted from original capture".into());
        }
        if serde_json::to_value(indexed).map_err(|e| e.to_string())?
            != serde_json::to_value(record).map_err(|e| e.to_string())?
        {
            return Err("current report rewrote original producer row".into());
        }
    }
    for product in &manifest.products {
        for path in product
            .components
            .iter()
            .map(|component| component.artifact.as_str())
            .chain([
                product.materialization.as_str(),
                product.runtime_manifest.as_str(),
                product.lifecycle.journal.as_str(),
                product.lifecycle.receipt.as_str(),
            ])
            .chain(product.registry_graph.as_deref())
        {
            if !manifest
                .artifacts
                .iter()
                .any(|artifact| artifact.path == path)
            {
                return Err("current product references another producer capture".into());
            }
        }
        let indexed = index
            .products
            .iter()
            .find(|p| p.key == product.key)
            .ok_or("current original product absent")?;
        if crate::producer_job(&product.key.target, Some(&product.key.channel))? != origin.job
            || serde_json::to_value(indexed).map_err(|e| e.to_string())?
                != serde_json::to_value(product).map_err(|e| e.to_string())?
        {
            return Err("current selected product differs from immutable producer".into());
        }
    }
    for build in &manifest.component_builds {
        let indexed = index
            .component_builds
            .iter()
            .find(|b| b.target == build.target)
            .ok_or("current original component build absent")?;
        if crate::producer_job(&build.target, None)? != origin.job
            || serde_json::to_value(indexed).map_err(|e| e.to_string())?
                != serde_json::to_value(build).map_err(|e| e.to_string())?
        {
            return Err("current component build differs from immutable producer".into());
        }
    }
    Ok(manifest
        .artifacts
        .into_iter()
        .map(|artifact| artifact.path)
        .collect())
}

fn product(
    index: &EvidenceIndexV2,
    product: &ProductObservationV2,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    validate_product_protocols(product)?;
    crate::host(&product.host, &product.key.target)?;
    if product.source_commit != index.source_commit
        || product.source_tree_sha256 != index.source_tree_sha256
        || product.version != index.version
    {
        return Err("current product source differs".into());
    }
    let linux = product.key.target.ends_with("linux-gnu");
    crate::exact_strings(
        &product.features,
        if linux {
            vec!["private-tcp", "sealed-runtime"]
        } else {
            vec!["sealed-runtime", "windows-sealed-runtime"]
        },
    )?;
    crate::exact_strings(
        &product
            .components
            .iter()
            .map(|c| c.role.clone())
            .collect::<Vec<_>>(),
        if linux {
            vec!["public-cli", "sealed-agent"]
        } else {
            vec![
                "public-cli",
                "sealed-agent",
                "desktop-bootstrap",
                "session-broker",
            ]
        },
    )?;
    for component in &product.components {
        if custody.hash(&component.artifact)? != component.installed_sha256 {
            return Err("current selected/installed byte digest differs".into());
        }
        crate::custody::executable_target(
            custody.bytes(&component.artifact)?,
            &product.key.target,
        )?;
    }
    if custody.hash(&product.materialization)? != product.package_sha256 {
        return Err("current package byte digest differs".into());
    }
    let manifest: RuntimeInventory =
        crate::wire::decode(custody.bytes(&product.runtime_manifest)?)?;
    if manifest.format != "memcordon.runtime-manifest"
        || manifest.project != "memcordon"
        || manifest.revision != 2
        || manifest.source_commit != index.source_commit
        || manifest.version != index.version
        || manifest.target != product.key.target
        || manifest.sealed.selection != "included"
        || manifest.sealed.agent_component != "sealed-agent"
        || manifest.sealed.profile_revision != 1
        || manifest.sealed.mechanism
            != if linux {
                "linux-private-workload-v1"
            } else {
                "windows-job-object-v2"
            }
        || manifest.sealed.profile != product.runtime_profile
        || manifest.sealed.workload_request != product.request
        || manifest.sealed.result != product.result
        || manifest.sealed.native_protocols != product.native_protocols
    {
        return Err("current measured runtime manifest interface differs".into());
    }
    if manifest.components.len() != product.components.len() {
        return Err("current manifest component inventory differs".into());
    }
    for component in &product.components {
        let expected_id = if component.role == "desktop-bootstrap" {
            "target-desktop-bootstrap"
        } else {
            component.role.as_str()
        };
        let entries: Vec<_> = manifest
            .components
            .iter()
            .filter(|entry| entry.id == expected_id)
            .collect();
        if entries.len() != 1 {
            return Err("current manifest component duplicate/omitted".into());
        }
        let entry = entries[0];
        if entry.role != component.role
            || entry.sha256 != component.installed_sha256
            || entry.size != custody.bytes(&component.artifact)?.len() as u64
            || entry.mode != 0o755
            || Path::new(&entry.path).components().count() != 1
            || !matches!(
                Path::new(&entry.path).components().next(),
                Some(std::path::Component::Normal(_))
            )
            || Path::new(&component.artifact).file_name() != Some(std::ffi::OsStr::new(&entry.path))
        {
            return Err("current manifest component byte/role/path/mode binding differs".into());
        }
    }
    if product.key.channel.ends_with("cargo") {
        crate::registry_graph_document(
            product
                .registry_graph
                .as_deref()
                .ok_or("current Cargo graph absent")?,
            product
                .registry_graph_sha256
                .as_deref()
                .ok_or("current Cargo graph digest absent")?,
            custody,
        )?;
    } else if product.registry_graph.is_some() || product.registry_graph_sha256.is_some() {
        return Err("native current product substitutes registry graph".into());
    }
    let lease = &product.lifecycle;
    let journal: crate::InstalledLifecycleJournal =
        crate::wire::decode(custody.bytes(&lease.journal)?)?;
    let receipt: InstalledLifecycleReceiptV2 = crate::wire::decode(custody.bytes(&lease.receipt)?)?;
    if journal.format != "memcordon.consumer-readiness.installed-journal"
        || journal.revision != 1
        || receipt.format != "memcordon.installed-lifecycle.receipt"
        || receipt.revision != 2
        || journal.key != product.key
        || receipt.key != product.key
        || receipt.lease_id != lease.lease_id
        || journal.lease_id != lease.lease_id
        || receipt.journal_sha256 != custody.hash(&lease.journal)?
        || journal.source_commit != index.source_commit
        || journal.source_tree_sha256 != index.source_tree_sha256
        || receipt.run_id != journal.run_id
        || receipt.final_sequence != journal.events.last().map_or(0, |e| e.sequence)
        || receipt.explicit_finalization_count != 1
        || lease.finalization_records != 1
        || !receipt.package_absent
        || !receipt.cache_quiescent
        || !receipt.cleanup_failures.is_empty()
        || !receipt.outstanding.is_empty()
        || !lease.cleanup_failures.is_empty()
        || !lease.outstanding.is_empty()
        || !lease.journal_before_mutation
        || !lease.installed_verified
        || !lease.all_cases_inside_lease
        || !lease.explicit_finalization
        || !lease.package_absent
        || serde_json::to_value(&receipt.native).map_err(|e| e.to_string())?
            != serde_json::to_value(&lease.native).map_err(|e| e.to_string())?
    {
        return Err("current outer lifecycle native receipt association/inventory differs".into());
    }
    validate_native_inventory(&product.key.target, &receipt.native)?;
    for (index, event) in journal.events.iter().enumerate() {
        if event.sequence != index as u64 + 1 || event.native_receipt.is_empty() {
            return Err("current outer journal sequence/native receipt absent".into());
        }
        custody.bytes(&event.native_receipt)?;
    }
    for native in &receipt.native {
        custody.bytes(&native.evidence)?;
    }
    Ok(())
}

pub fn verify_scoped(
    manifest_path: &Path,
    report_path: &Path,
    artifact_root: &Path,
    scope: VerificationScope,
    case_verifier: &CaseVerifier,
    lifecycle_verifier: &dyn Fn(
        &ProductObservationV2,
        &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
    ) -> VerificationResult<()>,
) -> VerificationResult<Verdict> {
    let manifest_bytes = crate::custody::read_external(manifest_path, 1024 * 1024)?;
    let index_bytes = crate::custody::read_external(report_path, crate::MAX_INDEX_BYTES as u64)?;
    let (index, storage) = super::storage::decode_evidence(&index_bytes)?;
    super::parsers::validate_index_inventory(&manifest_bytes, &index)?;
    if index.manifest_sha256 != crate::sha256(&manifest_bytes)
        || index.run_id.is_empty()
        || index.source_commit.len() != 40
        || !index
            .source_commit
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err("current index source/manifest binding differs".into());
    }
    crate::digest(&index.source_tree_sha256)?;
    let products_expected: BTreeSet<_> = crate::anchors::TARGETS
        .into_iter()
        .flat_map(|target| {
            crate::anchors::CHANNELS
                .into_iter()
                .map(move |channel| ProductKey {
                    target: target.into(),
                    channel: channel.into(),
                })
        })
        .collect();
    if index
        .workflow_cells
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != products_expected
        || index.workflow_cells.len() != products_expected.len()
    {
        return Err("current matrix/fixture/row inventory differs".into());
    }
    let jobs = crate::expected_producer_jobs(scope);
    if index
        .job_outcomes
        .iter()
        .map(|o| o.job.clone())
        .collect::<BTreeSet<_>>()
        != jobs
        || index.job_outcomes.len() != jobs.len()
    {
        return Err("current producer job inventory differs".into());
    }
    let custody = crate::custody::Custody::for_storage(
        artifact_root,
        &index.artifacts,
        &index.producer_origins,
        &storage,
        index_bytes.len() as u64,
    )?;
    let mut origins = BTreeMap::new();
    let mut ownership = BTreeMap::new();
    for origin in &index.producer_origins {
        if !jobs.contains(&origin.job)
            || origins.insert(origin.job.clone(), origin).is_some()
            || origin.run_attempt == 0
            || !origin.artifact_id.bytes().all(|byte| byte.is_ascii_digit())
            || origin
                .artifact_id
                .parse::<u64>()
                .ok()
                .is_none_or(|id| id == 0)
            || origin.source_commit != index.source_commit
            || origin.source_tree_sha256 != index.source_tree_sha256
            || origin.version != index.version
            || origin.manifest_sha256 != index.manifest_sha256
        {
            return Err("current producer immutable origin differs".into());
        }
        crate::identifier(&origin.run_id)?;
        crate::digest(&origin.artifact_sha256)?;
        ownership.insert(
            origin.job.clone(),
            original_producer(&index, origin, &custody)?,
        );
    }
    let mut failures = index.assessment_failures.clone();
    if failures.len() > 64 || failures.iter().any(|f| f.is_empty() || f.len() > 4096) {
        return Err("current assessment failures exceed bound".into());
    }
    for outcome in &index.job_outcomes {
        if outcome.result != crate::JobResult::Success || !origins.contains_key(&outcome.job) {
            failures.push(format!(
                "{}: actual producer outcome {:?} or immutable origin missing",
                outcome.job, outcome.result
            ));
        }
    }
    let assessed: BTreeSet<_> = products_expected
        .into_iter()
        .filter(|key| {
            scope == VerificationScope::CompleteProfile || key.channel.starts_with("candidate-")
        })
        .collect();
    if index.products.len() != assessed.len()
        || index
            .products
            .iter()
            .map(|product| product.key.clone())
            .collect::<BTreeSet<_>>()
            != assessed
    {
        return Err("current selected product matrix differs from scope".into());
    }
    let mut products = BTreeMap::new();
    for value in &index.products {
        if products.insert(value.key.clone(), value).is_some() {
            return Err("duplicate current product".into());
        }
        let job = crate::producer_job(&value.key.target, Some(&value.key.channel))?;
        let owned = ownership
            .get(&job)
            .ok_or("current product original capture owner missing")?;
        let checked = product(&index, value, &custody).and_then(|_| {
            lifecycle_verifier(value, &|path| {
                if !owned.contains(path) {
                    return Err("current lifecycle references another original capture".into());
                }
                custody.bytes(path).map(<[u8]>::to_vec)
            })
        });
        if let Err(error) = checked {
            failures.push(format!(
                "{:?}: {}",
                value.key,
                error.chars().take(1024).collect::<String>()
            ));
        }
    }
    let mut builds = BTreeMap::new();
    for build in &index.component_builds {
        if builds.insert(build.target.clone(), build).is_some()
            || build.source_commit != index.source_commit
            || build.source_tree_sha256 != index.source_tree_sha256
        {
            return Err("current component source/target duplicate".into());
        }
        crate::host(&build.host, &build.target)?;
        crate::identifier(&build.recipe_id)?;
        crate::digest(&build.recipe_sha256)?;
        crate::custody::executable_target(custody.bytes(&build.executable)?, &build.target)?;
        for other in [
            &build.actor_executable,
            &build.frontend_wrapper_executable,
            &build.parser_executable,
        ]
        .into_iter()
        .flatten()
        {
            if other == &build.executable {
                return Err("current native actor role reused harness executable".into());
            }
            crate::custody::executable_target(custody.bytes(other)?, &build.target)?;
        }
    }
    if builds.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != crate::anchors::TARGETS.into_iter().collect()
    {
        return Err("current native component build matrix differs".into());
    }
    for row in &index.records {
        if scope == VerificationScope::CandidateBeforePublication
            && row
                .key
                .channel
                .as_ref()
                .is_some_and(|c| c.starts_with("public-"))
        {
            if !matches!(row.state, CaseState::NotRun | CaseState::Blocked)
                || row.reason.as_deref() != Some("publication-pending")
                || row.evidence.is_some()
            {
                failures.push(format!(
                    "{:?}: public acquisition is not explicitly publication-pending",
                    row.key
                ));
            }
            continue;
        }
        let result = (|| {
            if row.state != CaseState::Passed || row.reason.is_some() {
                return Err("current required native row did not run successfully".into());
            }
            let job = crate::producer_job(&row.key.target, row.key.channel.as_deref())?;
            let origin = origins
                .get(&job)
                .ok_or("current original producer missing")?;
            let owned = ownership
                .get(&job)
                .ok_or("current case original capture owner missing")?;
            let resolver = |path: &str| {
                if !owned.contains(path) {
                    return Err("current case references another producer capture".into());
                }
                custody.bytes(path).map(<[u8]>::to_vec)
            };
            let evidence: CaseEvidenceV2 = crate::wire::decode(
                custody.bytes(
                    row.evidence
                        .as_deref()
                        .ok_or("current row evidence absent")?,
                )?,
            )?;
            for path in [
                &evidence.fixture,
                &evidence.fixture_source,
                &evidence.input,
                &evidence.invocation,
                &evidence.stdout,
                &evidence.stderr,
                &evidence.native_observation,
                &evidence.retirement,
                &evidence.semantic_observation,
            ]
            .into_iter()
            .chain(evidence.outputs.iter())
            .chain(
                [
                    &evidence.request,
                    &evidence.raw_result,
                    &evidence.attempt_observation,
                    &evidence.authenticated_terminal,
                    &evidence.recovery,
                ]
                .into_iter()
                .flatten(),
            ) {
                if !owned.contains(path) {
                    return Err("current case artifact crosses original producer custody".into());
                }
            }
            if evidence.format != "memcordon.consumer-readiness.case"
                || evidence.revision != 2
                || evidence.key != row.key
                || evidence.run_id != origin.run_id
                || row.run_id != origin.run_id
                || evidence.source_commit != index.source_commit
                || evidence.source_tree_sha256 != index.source_tree_sha256
                || custody.hash(&evidence.fixture)? != evidence.fixture_sha256
                || custody.hash(&evidence.fixture_source)? != evidence.fixture_source_sha256
                || evidence.fixture_source_sha256 != index.source_tree_sha256
                || custody.hash(&evidence.input)? != evidence.input_sha256
            {
                return Err("current case source/artifact/original-run association differs".into());
            }
            let product = row
                .key
                .channel
                .as_ref()
                .map(|channel| {
                    products
                        .get(&ProductKey {
                            target: row.key.target.clone(),
                            channel: channel.clone(),
                        })
                        .copied()
                        .ok_or("current selected case product absent")
                })
                .transpose()?;
            let build = if row.key.channel.is_none() {
                Some(
                    *builds
                        .get(&row.key.target)
                        .ok_or("current native component build absent")?,
                )
            } else {
                None
            };
            if let Some(product) = product {
                if evidence.lease_id.as_ref() != Some(&product.lifecycle.lease_id) {
                    return Err("current case crossed original installed lease".into());
                }
            }
            if let Some(build) = build {
                if evidence.component_recipe_id.as_ref() != Some(&build.recipe_id)
                    || evidence.lease_id.is_some()
                {
                    return Err("current component recipe/source role differs".into());
                }
            }
            let input = crate::wire::decode(custody.bytes(&evidence.input)?)?;
            case_verifier(
                &evidence,
                &input,
                product,
                build,
                &index.version,
                index.repository.as_deref(),
                &resolver,
            )
        })();
        if let Err(error) = result {
            failures.push(format!(
                "{:?}: {}",
                row.key,
                error.chars().take(1024).collect::<String>()
            ));
        }
    }
    if scope == VerificationScope::CompleteProfile {
        for target in crate::anchors::TARGETS {
            let get = |channel: &str| {
                products
                    .get(&ProductKey {
                        target: target.into(),
                        channel: channel.into(),
                    })
                    .copied()
                    .ok_or("current delivery lineage product absent")
            };
            if get("candidate-native")?.package_sha256 != get("public-native")?.package_sha256 {
                failures.push(format!("{target}: actual native delivered bytes differ"));
            }
            let graph = |value: &ProductObservationV2| {
                crate::registry_graph_document(
                    value
                        .registry_graph
                        .as_deref()
                        .ok_or("current graph absent")?,
                    value
                        .registry_graph_sha256
                        .as_deref()
                        .ok_or("current graph hash absent")?,
                    &custody,
                )
            };
            if graph(get("candidate-cargo")?)? != graph(get("public-cargo")?)? {
                failures.push(format!("{target}: actual Cargo delivery graph differs"));
            }
        }
    }
    Ok(Verdict {
        format: "memcordon.consumer-readiness.verdict".into(),
        revision: 2,
        profile: PROFILE.into(),
        run_id: index.run_id,
        manifest_sha256: crate::sha256(&manifest_bytes),
        evidence_index_sha256: crate::sha256(&index_bytes),
        scope,
        profile_ready: scope == VerificationScope::CompleteProfile && failures.is_empty(),
        accepted: failures.is_empty(),
        checked_records: index.records.len(),
        failures,
    })
}
