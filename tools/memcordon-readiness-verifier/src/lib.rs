//! Independent current consumer-readiness observations and semantic checks.
mod anchors;
mod behavior;
pub mod current;
mod custody;
mod filter_anchor;
mod linux_component;
pub mod storage;
pub mod windows_control_site;
pub mod windows_guardian_cause;
mod windows_toolchain;
mod wire;
pub use filter_anchor::frozen_linux_filter_program;
pub use linux_component::{
    FilterObservation, FilterVector, Instruction, LinuxFilterReceipt, validate_linux_filter_receipt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

pub const MAX_PRODUCER_ARTIFACTS: usize = 131_072;

pub const MAX_PRODUCER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Encoded producer containers share the existing total evidence custody budget.
pub const MAX_PRODUCER_ARCHIVE_BYTES: u64 = MAX_PRODUCER_BYTES;

pub type VerificationResult<T> = Result<T, String>;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct CaseKey {
    pub target: String,
    pub channel: Option<String>,
    pub evidence_class: EvidenceClass,
    pub family: String,
    pub scenario: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    InstalledProduct,
    NativeComponentRegression,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct ProductKey {
    pub target: String,
    pub channel: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCase {
    pub family: String,
    pub platform: String,
    pub evidence_class: EvidenceClass,
    pub scenarios: Vec<String>,
    pub requirements: Vec<String>,
}

/// CI transport provenance. This data is never supplied to product admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerOrigin {
    pub job: String,
    pub run_id: String,
    pub run_attempt: u64,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub bundle_artifact: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
    pub manifest_sha256: String,
    #[serde(default)]
    pub repository: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum JobResult {
    Success,
    Failure,
    Cancelled,
    Skipped,
    Missing,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobOutcome {
    pub job: String,
    pub result: JobResult,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    pub kernel: String,
    pub native_target: String,
    pub executable_target: String,
    pub emulated: bool,
    pub toolchain_identity: String,
    pub toolchain_sha256: String,
    pub lockfile_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub role: String,
    pub artifact: String,
    pub installed_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledLifecycleJournal {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub lease_id: String,
    pub key: ProductKey,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub events: Vec<InstalledLifecycleEvent>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledLifecycleEvent {
    pub sequence: u64,
    pub phase: String,
    pub operation: String,
    pub succeeded: bool,
    pub native_receipt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentBuild {
    pub target: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub host: HostObservation,
    pub recipe_id: String,
    pub recipe_sha256: String,
    pub executable: String,
    pub instrumented: bool,
    pub actor_executable: Option<String>,
    pub frontend_wrapper_executable: Option<String>,
    pub parser_executable: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaseState {
    NotRun,
    Blocked,
    Failed,
    Passed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRecord {
    pub key: CaseKey,
    pub run_id: String,
    pub state: CaseState,
    pub reason: Option<String>,
    pub evidence: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLossEvidence {
    pub action: String,
    pub live_observation: String,
    pub original_result: Option<String>,
    pub native_family_retirement: String,
    pub recovery: String,
    pub stdout: String,
    pub stderr: String,
    pub capture_failure: Option<String>,
    pub recovery_invocation: String,
    pub recovery_process: String,
    pub recovery_stderr: String,
    pub original_lease_owner: String,
    pub original_deadlines: String,
    pub recovery_creation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInvocation {
    pub format: String,
    pub revision: u32,
    pub arguments: NativeArguments,
    pub executable_sha256: String,
    pub environment: String,
    pub environment_sha256: String,
    pub association_sha256: String,
    pub budget_tokens: Vec<BudgetToken>,
    pub memory_token: Option<String>,
    pub deadline_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetToken {
    pub kind: String,
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureInput {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub key: CaseKey,
    pub challenge_sha256: String,
    pub binary: Vec<u8>,
    pub target_argv: NativeArguments,
    pub deadline_millis: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub toolchain_identity: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "encoding",
    content = "values",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NativeArguments {
    UnixBytes(Vec<Vec<u8>>),
    WindowsUtf16(Vec<Vec<u16>>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "encoding",
    content = "values",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NativeEnvironment {
    UnixBytes(Vec<UnixEnvironmentVariable>),
    WindowsUtf16(Vec<WindowsEnvironmentVariable>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixEnvironmentVariable {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEnvironmentVariable {
    pub name: Vec<u16>,
    pub value: Vec<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservation {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub lease_id: Option<String>,
    pub target: String,
    pub executable_sha256: String,
    pub invocation_sha256: String,
    pub execution_invocation_sha256: Option<String>,
    pub request_sha256: Option<String>,
    pub provider_sha256: Option<String>,
    pub provider_generation: Option<String>,
    pub runtime_manifest_sha256: Option<String>,
    pub attempt_id: Option<String>,
    pub root_pid: Option<u32>,
    pub root_birth: Option<u64>,
    pub attempt_nonce: Option<String>,
    pub held_processes: Vec<HeldProcessIdentity>,
    pub frontend_status: i32,
    pub origin: OutcomeOrigin,
    pub target_status: Option<i32>,
    pub authenticated_provider_exchange: bool,
    pub relay_complete: bool,
    pub result_named_identity_verified: bool,
    pub result_readback_verified: bool,
    pub application_stage: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeldProcessIdentity {
    pub pid: u32,
    pub birth: u64,
    pub parent_pid: Option<u32>,
    pub parent_birth: Option<u64>,
    pub retirement_observed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeOrigin {
    Target,
    Deadline,
    Memory,
    Interrupted,
    AdmissionRefusal,
    ProviderFailure,
    ApplicationRefusal,
    ComponentRegression,
    PackageOperation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementObservation {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub attempt_id: Option<String>,
    pub root_pid: Option<u32>,
    pub root_birth: Option<u64>,
    pub target_reaped_or_absent: bool,
    pub aggregate_empty: bool,
    pub relays_retired: bool,
    pub guardian_retired: bool,
    pub native_handles_closed: bool,
    pub independently_observed: bool,
    pub namespace_init_reaped: Option<bool>,
    pub private_root_closed: Option<bool>,
    pub exports_finalized: Option<bool>,
    pub final_job_handles_closed: Option<bool>,
    pub active_processes_zero: Option<bool>,
    pub outstanding: Vec<String>,
    pub failed_operations: Vec<String>,
}

/// Operations are native/controller observations, not fixture success strings.
/// Byte comparisons reference independently collected peer/controller products.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticObservation {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub key: CaseKey,
    pub challenge: String,
    pub operations: Vec<OperationObservation>,
    pub comparisons: Vec<ByteComparison>,
    pub counters: BTreeMap<String, u64>,
    pub negative_probe: Option<NegativeProbe>,
    pub component_test: Option<ComponentTest>,
    pub component_actors: Option<Vec<ComponentActor>>,
    pub windows_capacity: Option<WindowsCapacityEvidence>,
    pub fixture_behavior: Option<FixtureBehavior>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCapacityEvidence {
    pub attempts: Vec<String>,
    pub inventories: Vec<String>,
    pub overlap_live_association: Option<String>,
    pub overlap_held_guardian: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureBehavior {
    pub descriptor: String,
    pub transcript: String,
    pub expected_token: Option<String>,
    pub peer_artifacts: Vec<BehaviorArtifact>,
    pub native_binding: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorArtifact {
    pub role: String,
    pub path: String,
}

/// Actual support actors are separate from Rust test-harness executions.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentActor {
    pub provider_request: String,
    pub recipe_id: String,
    pub selection_kind: String,
    pub selection: String,
    pub invocation: String,
    pub exit: String,
    pub observation: String,
    pub stdout: String,
    pub stderr: String,
    pub actor_held: String,
    pub native_retirement: String,
    pub settlement_inventory: String,
    pub settlement_invocation: String,
    pub settlement_exit: String,
    pub settlement_stderr: String,
    pub settlement_deadline: String,
    pub held_before: Option<String>,
    pub held_after: Option<String>,
    pub worker_exit: Option<String>,
    pub frontend_exit: Option<String>,
    pub recovery: Option<String>,
    pub recovery_invocation: Option<String>,
    pub recovery_exit: Option<String>,
    pub recovery_stderr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extinction_recovery: Option<ComponentExtinctionRecovery>,
    pub control_worker_site: Option<String>,
    pub control_worker_held: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentExtinctionRecovery {
    pub staging_invocation: String,
    pub staging_exit: String,
    pub staging_stdout: String,
    pub staging_stderr: String,
    pub terminal_invocation: String,
    pub terminal_exit: String,
    pub terminal_stdout: String,
    pub terminal_authority: String,
    pub terminal_stderr: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationObservation {
    pub operation: String,
    pub attempt_id: Option<String>,
    pub root_pid: Option<u32>,
    pub observer: String,
    pub native_receipt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub operation: String,
    pub attempt_id: Option<String>,
    pub root_pid: Option<u32>,
    pub root_birth: Option<u64>,
    pub observer_pid: u32,
    pub observer_birth: u64,
    pub challenge_sha256: String,
    pub native_domain: String,
    pub native_code: i64,
    pub observed_value: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ByteComparison {
    pub role: String,
    pub actual: String,
    pub expected: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeProbe {
    pub stage: String,
    pub domain: String,
    pub native_code: i64,
    pub receipt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentTest {
    pub recipe_id: String,
    pub test_name: String,
    pub native_exit: i32,
    pub tests_executed: u64,
    pub tests_failed: u64,
    pub tests_ignored: u64,
    pub raw_test_output: String,
    pub native_receipt: String,
    pub native_retirement: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub format: String,
    pub revision: u32,
    pub profile: String,
    pub run_id: String,
    pub manifest_sha256: String,
    pub evidence_index_sha256: String,
    pub scope: VerificationScope,
    pub profile_ready: bool,
    pub accepted: bool,
    pub checked_records: usize,
    pub failures: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationScope {
    CompleteProfile,
    CandidateBeforePublication,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackage {
    pub name: String,
    pub version: String,
    pub crate_sha256: String,
    pub crate_artifact: String,
    pub features: Vec<String>,
    pub dependencies: Vec<RegistryDependency>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct RegistryDependency {
    pub name: String,
    pub version: String,
    pub kind: Option<String>,
    pub target: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryGraph {
    pub format: String,
    pub revision: u32,
    pub packages: Vec<RegistryPackage>,
    pub raw_metadata: String,
    pub raw_lock: String,
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn validate_json_document(bytes: &[u8]) -> VerificationResult<serde_json::Value> {
    wire::json(bytes)
}

pub fn reconstruct_invocation_sha256(invocation: &NativeInvocation) -> VerificationResult<String> {
    wire::invocation_digest(invocation)
}

pub fn validate_artifact_custody(root: &Path, artifacts: &[Artifact]) -> VerificationResult<()> {
    custody::Custody::new(root, artifacts).map(|_| ())
}

/// Read one independently held, named, ordinary evidence member with full custody.
pub fn read_artifact_bytes(root: &Path, artifact: &Artifact) -> VerificationResult<Vec<u8>> {
    let custody = custody::Custody::new(root, std::slice::from_ref(artifact))?;
    Ok(custody.bytes(&artifact.path)?.to_vec())
}

pub fn retain_artifact_bytes(
    root: &Path,
    artifact: &Artifact,
    bytes: &[u8],
    existing: bool,
) -> VerificationResult<()> {
    custody::retain_bytes(root, artifact, bytes, existing)
}

/// Independent raw behavioral decoder entrypoint. Success proves only these
/// supplied artifact associations, never installation or native retirement.
pub fn validate_fixture_behavior(
    semantic: &SemanticObservation,
    native: &NativeObservation,
    input: &FixtureInput,
    artifacts: &[Artifact],
    root: &Path,
) -> VerificationResult<()> {
    let behavior = semantic
        .fixture_behavior
        .as_ref()
        .ok_or("raw fixture behavior absent")?;
    let facts = behavior::validate(
        behavior,
        semantic,
        native,
        input,
        &custody::Custody::new(root, artifacts)?,
    )?;
    for operation in &semantic.operations {
        if !facts.operations.contains(&operation.operation) {
            return Err("requested behavioral fact absent from raw decoder".into());
        }
    }
    Ok(())
}

fn digest(value: &str) -> VerificationResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected lowercase SHA-256".into());
    }
    Ok(())
}

fn identifier(value: &str) -> VerificationResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("invalid bounded identifier".into());
    }
    Ok(())
}

fn exact_strings(
    values: &[String],
    expected: impl IntoIterator<Item = impl AsRef<str>>,
) -> VerificationResult<()> {
    let actual: BTreeSet<_> = values.iter().map(String::as_str).collect();
    let required: BTreeSet<String> = expected
        .into_iter()
        .map(|v| v.as_ref().to_owned())
        .collect();
    if actual.len() != values.len()
        || actual
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            != required
    {
        return Err("required finite set differs or contains duplicates".into());
    }
    Ok(())
}

fn header(format: &str, revision: u32, expected: &str) -> VerificationResult<()> {
    if format != expected || revision != 1 {
        return Err(format!("unsupported {expected} format/revision"));
    }
    Ok(())
}

fn host(host: &HostObservation, target: &str) -> VerificationResult<()> {
    if host.native_target != target
        || host.executable_target != target
        || host.emulated
        || host.kernel.is_empty()
        || host.kernel.len() > 512
        || host.toolchain_identity.is_empty()
        || host.toolchain_identity.len() > 512
    {
        return Err("native host/executable/toolchain observation differs".into());
    }
    digest(&host.toolchain_sha256)?;
    digest(&host.lockfile_sha256)
}

fn producer_job(target: &str, channel: Option<&str>) -> VerificationResult<String> {
    let label = anchors::PRODUCER_JOBS
        .iter()
        .find_map(|(native, label)| (*native == target).then_some(*label))
        .ok_or("unknown native producer target")?;
    match channel {
        None => Ok(format!("native-{label}")),
        Some(channel) => {
            let (stage, kind) = channel.split_once('-').ok_or("unknown producer channel")?;
            if !["candidate", "public"].contains(&stage) || !["native", "cargo"].contains(&kind) {
                return Err("unknown producer channel".into());
            }
            Ok(format!("{stage}-{label}-{kind}"))
        }
    }
}

fn expected_producer_jobs(scope: VerificationScope) -> BTreeSet<String> {
    anchors::PRODUCER_JOBS
        .into_iter()
        .flat_map(|(_, label)| {
            let mut jobs = vec![
                format!("native-{label}"),
                format!("candidate-{label}-native"),
                format!("candidate-{label}-cargo"),
            ];
            if scope == VerificationScope::CompleteProfile {
                jobs.extend([
                    format!("public-{label}-native"),
                    format!("public-{label}-cargo"),
                ]);
            }
            jobs
        })
        .collect()
}

/// Structural Cargo graph custody/metadata checking for independent mutation
/// tests and tooling. This never returns a profile or native execution verdict.
pub fn validate_cargo_graph_artifacts(
    root: &Path,
    artifacts: &[Artifact],
    path: &str,
    digest: &str,
) -> VerificationResult<Vec<RegistryPackage>> {
    registry_graph_document(path, digest, &custody::Custody::new(root, artifacts)?)
}

fn registry_graph_document(
    path: &str,
    expected_digest: &str,
    custody: &custody::Custody,
) -> VerificationResult<Vec<RegistryPackage>> {
    if expected_digest != custody.hash(path)? {
        return Err("Cargo graph persisted digest differs".into());
    }
    let graph: RegistryGraph = wire::decode(custody.bytes(path)?)?;
    header(
        &graph.format,
        graph.revision,
        "memcordon.consumer-readiness.registry-graph",
    )?;
    let metadata: serde_json::Value = wire::decode(custody.bytes(&graph.raw_metadata)?)?;
    let lock: toml::Value = toml::from_str(
        std::str::from_utf8(custody.bytes(&graph.raw_lock)?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let raw_packages = metadata["packages"]
        .as_array()
        .ok_or("actual Cargo metadata packages absent")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("actual Cargo metadata resolved nodes absent")?;
    if raw_packages.len() > 4096 || nodes.len() > 4096 {
        return Err("actual Cargo metadata graph exceeds bound".into());
    }
    let mut by_id = BTreeMap::new();
    for package in raw_packages {
        let id = package["id"]
            .as_str()
            .ok_or("actual Cargo package id absent")?;
        if by_id.insert(id, package).is_some() {
            return Err("actual Cargo metadata duplicate package id".into());
        }
    }
    let root = metadata["resolve"]["root"]
        .as_str()
        .ok_or("actual selected Cargo root absent")?;
    let mut reachable = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(id) = pending.pop() {
        if reachable.insert(id) {
            let node = nodes
                .iter()
                .find(|node| node["id"].as_str() == Some(id))
                .ok_or("actual reachable Cargo node absent")?;
            for edge in node["deps"]
                .as_array()
                .ok_or("actual reachable Cargo edges absent")?
            {
                pending.push(
                    edge["pkg"]
                        .as_str()
                        .ok_or("actual reachable Cargo edge id absent")?,
                );
            }
        }
    }
    let mut raw_nodes = BTreeMap::new();
    for node in nodes {
        if !reachable.contains(node["id"].as_str().ok_or("actual Cargo node id absent")?) {
            continue;
        }
        let package = by_id
            .get(node["id"].as_str().ok_or("actual Cargo node id absent")?)
            .ok_or("actual Cargo node package absent")?;
        let name = package["name"]
            .as_str()
            .ok_or("actual Cargo package name absent")?;
        let version = package["version"]
            .as_str()
            .ok_or("actual Cargo package version absent")?;
        if raw_nodes.insert((name, version), node).is_some() {
            return Err("actual Cargo node identity ambiguous".into());
        }
    }
    if graph.packages.is_empty() || graph.packages.len() > 4096 {
        return Err("Cargo graph cardinality differs".into());
    }
    let mut identities = BTreeSet::new();
    let mut packages = graph.packages;
    for package in &mut packages {
        identifier(&package.name)?;
        semver::Version::parse(&package.version).map_err(|e| e.to_string())?;
        digest(&package.crate_sha256)?;
        let raw = raw_nodes
            .remove(&(package.name.as_str(), package.version.as_str()))
            .ok_or("summarized graph node absent from actual Cargo metadata")?;
        let raw_features: Vec<String> =
            serde_json::from_value(raw["features"].clone()).map_err(|e| e.to_string())?;
        if raw_features.iter().collect::<BTreeSet<_>>()
            != package.features.iter().collect::<BTreeSet<_>>()
        {
            return Err("Cargo feature summary differs from actual metadata".into());
        }
        let mut raw_edges = BTreeSet::new();
        for dependency in raw["deps"]
            .as_array()
            .ok_or("actual Cargo dependency edges absent")?
        {
            let target = by_id
                .get(
                    dependency["pkg"]
                        .as_str()
                        .ok_or("actual Cargo edge id absent")?,
                )
                .ok_or("actual Cargo edge package absent")?;
            for kind in dependency["dep_kinds"]
                .as_array()
                .ok_or("actual Cargo dependency kind/target absent")?
            {
                raw_edges.insert(RegistryDependency {
                    name: target["name"]
                        .as_str()
                        .ok_or("actual Cargo edge name absent")?
                        .into(),
                    version: target["version"]
                        .as_str()
                        .ok_or("actual Cargo edge version absent")?
                        .into(),
                    kind: serde_json::from_value(kind["kind"].clone())
                        .map_err(|e| e.to_string())?,
                    target: serde_json::from_value(kind["target"].clone())
                        .map_err(|e| e.to_string())?,
                });
            }
        }
        if raw_edges != package.dependencies.iter().cloned().collect() {
            return Err("Cargo edge summary differs from actual kind/target metadata".into());
        }
        let locked = lock["package"]
            .as_array()
            .ok_or("actual packaged Cargo lock entries absent")?
            .iter()
            .filter(|entry| {
                entry.get("name").and_then(toml::Value::as_str) == Some(package.name.as_str())
                    && entry.get("version").and_then(toml::Value::as_str)
                        == Some(package.version.as_str())
            })
            .collect::<Vec<_>>();
        if locked.len() != 1
            || locked[0]
                .get("checksum")
                .and_then(toml::Value::as_str)
                .is_some_and(|checksum| checksum != package.crate_sha256)
        {
            return Err(
                "consumed Cargo crate differs from actual packaged/test lock checksum".into(),
            );
        }
        if custody.hash(&package.crate_artifact)? != package.crate_sha256 {
            return Err("Cargo graph crate bytes differ from persisted package".into());
        }
        // Collection paths vary by channel; compare the delivered package
        // identity, bytes and graph edges after independently hashing each.
        package.crate_artifact.clear();
        if !identities.insert((package.name.clone(), package.version.clone())) {
            return Err("Cargo graph duplicate package identity".into());
        }
        if package.features.len() > 4096
            || package
                .features
                .iter()
                .any(|feature| feature.is_empty() || feature.len() > 128)
        {
            return Err("Cargo graph feature set exceeds finite bound".into());
        }
        let features = package.features.iter().cloned().collect::<BTreeSet<_>>();
        if features.len() != package.features.len() {
            return Err("Cargo graph duplicate selected feature".into());
        }
        package.features = features.into_iter().collect();
        if package.dependencies.len() > 16_384
            || package.dependencies.iter().any(|edge| {
                edge.kind
                    .as_deref()
                    .is_some_and(|kind| !matches!(kind, "dev" | "build"))
                    || edge
                        .target
                        .as_ref()
                        .is_some_and(|target| target.is_empty() || target.len() > 4096)
            })
        {
            return Err("Cargo graph dependency kind/target differs or exceeds bound".into());
        }
        let dependencies: BTreeSet<_> = package.dependencies.iter().cloned().collect();
        if dependencies.len() != package.dependencies.len() {
            return Err("Cargo graph duplicate edge".into());
        }
        package.dependencies = dependencies.into_iter().collect();
    }
    if !raw_nodes.is_empty() {
        return Err("summarized Cargo graph omits actual reachable selected node".into());
    }
    for package in &packages {
        for dependency in &package.dependencies {
            if !identities.contains(&(dependency.name.clone(), dependency.version.clone())) {
                return Err("Cargo graph edge refers to absent package".into());
            }
        }
    }
    packages.sort();
    Ok(packages)
}

/// The finite vector describes every invocation, including the overlapping
/// invocation whose global image census cannot yet be empty.
pub fn validate_windows_capacity_shape(
    vector: &WindowsCapacityEvidence,
    key: &CaseKey,
) -> VerificationResult<()> {
    if key.family != "W-CAPACITY"
        || !key.target.ends_with("windows-msvc")
        || key.evidence_class != EvidenceClass::InstalledProduct
    {
        return Err("Windows capacity vector is outside its installed case".into());
    }
    let (attempts, inventories, overlap) = match key.scenario.as_str() {
        "serial-retirement" => (3, 4, false),
        "bounded-concurrency" => (2, 2, true),
        "fresh-positive-after-recovery" => (1, 2, false),
        _ => return Err("unknown Windows capacity scenario".into()),
    };
    if vector.attempts.len() != attempts
        || vector.inventories.len() != inventories
        || vector.overlap_live_association.is_some() != overlap
        || vector.overlap_held_guardian.is_some() != overlap
    {
        return Err("Windows capacity vector omits or adds a constituent".into());
    }
    let mut paths = BTreeSet::new();
    for path in vector
        .attempts
        .iter()
        .chain(vector.inventories.iter())
        .chain(vector.overlap_live_association.iter())
        .chain(vector.overlap_held_guardian.iter())
    {
        if path.is_empty() || path.len() > 4096 || !paths.insert(path) {
            return Err("Windows capacity raw constituent path is absent or reused".into());
        }
    }
    Ok(())
}

/// Decode the actual unwrapped recovery response. Completed tombstones retain
/// no workload authority; all six authority-bearing counters must be zero.
pub fn validate_windows_capacity_inventory(
    raw: &serde_json::Value,
    generation: &str,
) -> VerificationResult<()> {
    let fields = [
        "schema_version",
        "challenge",
        "provider_generation",
        "current_boot_identity",
        "executing",
        "incomplete_proof",
        "unacknowledged_outboxes",
        "ack_retirement_in_progress",
        "completed_tombstones",
        "active_admissions",
        "quarantined",
    ];
    if raw.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || raw["schema_version"] != 1
        || raw["provider_generation"].as_str() != Some(generation)
        || generation.is_empty()
    {
        return Err("capacity inventory schema or selected provider generation differs".into());
    }
    for field in ["challenge", "current_boot_identity"] {
        if raw[field]
            .as_str()
            .is_none_or(|value| value.is_empty() || value.len() > 4096)
        {
            return Err("capacity inventory native challenge/boot identity absent".into());
        }
    }
    let mut total = 0u64;
    for field in [
        "executing",
        "incomplete_proof",
        "unacknowledged_outboxes",
        "ack_retirement_in_progress",
        "completed_tombstones",
        "active_admissions",
        "quarantined",
    ] {
        let count = raw[field]
            .as_u64()
            .filter(|count| *count <= u64::from(u32::MAX))
            .ok_or("capacity inventory counter is not bounded native u32")?;
        total = total
            .checked_add(count)
            .ok_or("capacity inventory total overflow")?;
        if field != "completed_tombstones" && count != 0 {
            return Err("capacity inventory retains workload or outbox authority".into());
        }
    }
    if total > u64::from(u32::MAX) {
        return Err("capacity inventory counters exceed native total bound".into());
    }
    Ok(())
}
