//! Qualification-only projection of native Windows inputs. This module never
//! creates or activates a production compilation context or a cache key.
mod storage;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::build_context::{BuildInputSnapshot, Input, environment};
use crate::{CiError, Result};

const CONTRACT: &str = "windows-staged-native-qualification-v1";
const SPECIFICATION: &str = "specification.json";
const EVIDENCE: &str = "evidence.json";

/// Acquisition checkpoints for bounded supervisors and deterministic drift
/// qualification. Returning an error cancels without publishing evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QualificationStage {
    SourceCaptured,
    Copied,
    Published,
    SourceVerified,
    DestinationMeasured,
    SourceRechecked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Architecture {
    X64,
    Arm64,
}

impl Architecture {
    fn name(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }

    fn msvc(self) -> environment::msvc::Architecture {
        match self {
            Self::X64 => environment::msvc::Architecture::X64,
            Self::Arm64 => environment::msvc::Architecture::Arm64,
        }
    }
}

/// Explicit selectors, not a file-access whitelist. Whole selected SDK, Git,
/// LLVM and MSVC support trees are expanded by code, not caller exclusions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub architecture: Architecture,
    pub installation: PathBuf,
    pub toolset_version: String,
    pub sdk: PathBuf,
    pub sdk_version: String,
    pub git: PathBuf,
    pub llvm: PathBuf,
    pub rustup_bin: PathBuf,
    pub system_root: PathBuf,
    /// Additional complete support trees identified during closure research.
    pub additional_support: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: u32,
    contract: String,
    qualification_only: bool,
    recipes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Root {
    source: PathBuf,
    destination: PathBuf,
}

/// Frozen declaration. Derived inventory, completion status and digests are
/// deliberately separate. Native staging and control metadata are siblings.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Specification {
    schema: u32,
    contract: String,
    qualification_only: bool,
    policy: Policy,
    architecture: Architecture,
    active: PathBuf,
    copied: Vec<Root>,
    external: Vec<PathBuf>,
    native_environment: BTreeMap<String, String>,
    absent_sources: Vec<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    root: PathBuf,
    entries: Vec<Input>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: u32,
    contract: String,
    qualification_only: bool,
    specification_sha256: String,
    inventories: Vec<Inventory>,
    stages_ms: BTreeMap<String, u128>,
    /// Copy integrity is established; native recipe closure is NOT certified.
    outcome: String,
}

fn reject(message: &str) -> CiError {
    CiError::Message(message.into())
}

fn parse<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn policy(path: &Path) -> Result<Policy> {
    let policy: Policy = parse(path)?;
    validate_policy(&policy)?;
    Ok(policy)
}

fn validate_policy(policy: &Policy) -> Result<()> {
    if policy.schema != 1 || policy.contract != CONTRACT || !policy.qualification_only {
        return Err(reject(
            "native profile production admission is not qualified",
        ));
    }
    let recipes: BTreeSet<_> = policy.recipes.iter().map(String::as_str).collect();
    if recipes.len() != policy.recipes.len()
        || recipes
            != BTreeSet::from([
                "controller",
                "release-native",
                "backend-windows-job",
                "windows-loader-production",
                "windows-provider-lifecycle",
                "windows-package-channel",
            ])
    {
        return Err(reject(
            "native qualification requires the complete recipe review set",
        ));
    }
    Ok(())
}

fn version(value: &str) -> Result<()> {
    if value.is_empty()
        || value
            .split('.')
            .any(|part| part.is_empty() || part.parse::<u32>().is_err())
    {
        return Err(reject("invalid explicit native version"));
    }
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    storage::validate_ancestors(path)?;
    let path = path.canonicalize()?;
    if path.to_str().is_none() {
        return Err(reject(
            "native qualification requires lossless Unicode paths",
        ));
    }
    Ok(path)
}

fn string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| reject("native qualification requires lossless Unicode paths"))
}

fn expand(selection: &Selection, active: &Path, policy: Policy) -> Result<Specification> {
    version(&selection.toolset_version)?;
    version(&selection.sdk_version)?;
    let installation = absolute(&selection.installation)?;
    let sdk = absolute(&selection.sdk)?;
    let git = absolute(&selection.git)?;
    let llvm = absolute(&selection.llvm)?;
    let rustup_bin = absolute(&selection.rustup_bin)?;
    let system_root = environment::command_path(&absolute(&selection.system_root)?)?;
    let vc = installation.join("VC");
    let mut copied = vec![
        Root {
            source: vc
                .join("Tools")
                .join("MSVC")
                .join(&selection.toolset_version),
            destination: active
                .join("vs")
                .join("VC")
                .join("Tools")
                .join("MSVC")
                .join(&selection.toolset_version),
        },
        Root {
            source: vc.join("Auxiliary").join("Build"),
            destination: active.join("vs").join("VC").join("Auxiliary").join("Build"),
        },
        Root {
            source: sdk,
            destination: active.join("sdk"),
        },
        Root {
            source: git,
            destination: active.join("git"),
        },
        Root {
            source: llvm,
            destination: active.join("llvm"),
        },
    ];
    let redist = vc.join("Redist");
    let mut absent_sources = Vec::new();
    match fs::symlink_metadata(&redist) {
        Ok(_) => copied.push(Root {
            source: redist,
            destination: active.join("vs").join("VC").join("Redist"),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => absent_sources.push(redist),
        Err(error) => return Err(error.into()),
    }
    let mut support = selection.additional_support.clone();
    support.sort();
    if support.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(reject("duplicate additional support root"));
    }
    for (index, source) in support.into_iter().enumerate() {
        copied.push(Root {
            source: absolute(&source)?,
            destination: active.join("support").join(index.to_string()),
        });
    }
    for root in &mut copied {
        root.source = absolute(&root.source)?;
        if !root.source.is_dir() {
            return Err(reject("native support root must be a complete directory"));
        }
    }
    let mut external = vec![rustup_bin.clone()];
    let system = system_root.join("System32");
    for name in [
        "kernel32.dll",
        "ntdll.dll",
        "ucrtbase.dll",
        "msvcp_win.dll",
        "cmd.exe",
        "ping.exe",
    ] {
        external.push(absolute(&system.join(name))?);
    }
    let mut env = BTreeMap::from([
        (
            OsString::from("WindowsSdkDir"),
            active.join("sdk").into_os_string(),
        ),
        (
            OsString::from("WindowsSDKVersion"),
            OsString::from(&selection.sdk_version),
        ),
        (
            OsString::from("VCToolsVersion"),
            OsString::from(&selection.toolset_version),
        ),
        (OsString::from("SystemRoot"), system_root.into_os_string()),
    ]);
    // Configuration requires staged paths to exist. The initial specification
    // is finished after publication, before any inventory/evidence is emitted.
    env.insert(
        OsString::from("PATH"),
        std::env::join_paths([
            rustup_bin,
            active.join("git").join("cmd"),
            active.join("llvm").join("bin"),
        ])
        .map_err(std::io::Error::other)?,
    );
    Ok(Specification {
        schema: 1,
        contract: CONTRACT.into(),
        qualification_only: true,
        policy,
        architecture: selection.architecture,
        active: active.to_path_buf(),
        copied,
        external,
        native_environment: env
            .into_iter()
            .map(|(key, value)| Ok((string(Path::new(&key))?, string(Path::new(&value))?)))
            .collect::<Result<_>>()?,
        absent_sources,
    })
}

fn configure(specification: &mut Specification) -> Result<()> {
    let mut env: BTreeMap<OsString, OsString> = specification
        .native_environment
        .iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    let linker = environment::msvc::configure(
        &mut env,
        &specification.active.join("vs"),
        specification.architecture.msvc(),
    )?;
    environment::windows_compiler::admit(&mut env, &linker, specification.architecture.msvc())?;
    // Both conventional native ancestors and environment-derived roots refer
    // to the staged runtime. Production windows_native_roots is untouched.
    let active_identity = specification.active.canonicalize()?;
    for root in crate::build_context::native_environment_roots(&env)? {
        if !root.starts_with(&active_identity) {
            return Err(reject("native environment escaped qualification tree"));
        }
    }
    specification.native_environment = env
        .into_iter()
        .map(|(key, value)| Ok((string(Path::new(&key))?, string(Path::new(&value))?)))
        .collect::<Result<_>>()?;
    Ok(())
}

fn capture(root: &Path) -> Result<Inventory> {
    storage::validate_tree(root)?;
    let snapshot = BuildInputSnapshot::capture(root)?;
    storage::validate_tree(root)?;
    Ok(Inventory {
        root: root.to_path_buf(),
        entries: snapshot.inputs().to_vec(),
    })
}

fn projected(inventory: &Inventory) -> Result<BTreeMap<PathBuf, (String, u32, String)>> {
    let root = inventory.root.canonicalize()?;
    inventory
        .entries
        .iter()
        .map(|entry| {
            let path = PathBuf::from(
                String::from_utf8(
                    hex::decode(&entry.path).map_err(|error| reject(&error.to_string()))?,
                )
                .map_err(|error| reject(&error.to_string()))?,
            );
            let relative = path
                .strip_prefix(&root)
                .map_err(|_| reject("inventory escaped declared root"))?;
            Ok((
                relative.to_path_buf(),
                (entry.kind.clone(), entry.mode, entry.digest.clone()),
            ))
        })
        .collect()
}

fn verify_projection(
    specification: &Specification,
    sources: &[Inventory],
) -> Result<Vec<Inventory>> {
    let mut inventories = Vec::new();
    for (root, source) in specification.copied.iter().zip(sources) {
        let destination = capture(&root.destination)?;
        if projected(source)? != projected(&destination)? {
            return Err(reject("native source and staged projection differ"));
        }
        inventories.push(destination);
    }
    // Capture staged ancestors too: additions between selected subtrees are
    // runtime inputs, including the broad VSINSTALLDIR/VCINSTALLDIR routes.
    inventories.push(capture(&specification.active)?);
    for root in &specification.external {
        inventories.push(capture(root)?);
    }
    Ok(inventories)
}

fn check_absence(specification: &Specification) -> Result<()> {
    for path in &specification.absent_sources {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(reject(
                    "optional native support appeared during acquisition",
                ));
            }
        }
    }
    Ok(())
}

/// Construct and verify an isolated candidate. Success certifies copy integrity
/// only. It cannot enable selected inputs in production or populate a cache.
pub fn qualify(policy_path: &Path, selection_path: &Path, destination: &Path) -> Result<()> {
    qualify_with_observer(policy_path, selection_path, destination, |_| Ok(()))
}

/// The observer runs synchronously at phase boundaries. It is not an OS I/O
/// cancellation primitive; a process supervisor must enforce hard deadlines.
pub fn qualify_with_observer(
    policy_path: &Path,
    selection_path: &Path,
    destination: &Path,
    mut observer: impl FnMut(QualificationStage) -> Result<()>,
) -> Result<()> {
    if crate::build_context::active().is_some() {
        return Err(reject(
            "native qualification cannot run inside a production build context",
        ));
    }
    let policy = policy(policy_path)?;
    let selection: Selection = parse(selection_path)?;
    // Keep command/environment paths usable by MSVC; canonical Input identities
    // remain unchanged and are compared separately from invocation spelling.
    let destination = environment::command_path(&absolute(destination)?)?;
    let destination_identity = destination.canonicalize()?;
    let mut owner =
        storage::Publication::new(&destination, CONTRACT, selection.architecture.name())?;
    let mut specification = expand(&selection, owner.active(), policy)?;
    for root in &specification.copied {
        if destination_identity.starts_with(&root.source)
            || root.source.starts_with(&destination_identity)
        {
            return Err(reject(
                "source and qualification control directories overlap",
            ));
        }
    }
    for root in &specification.external {
        if destination_identity.starts_with(root) || root.starts_with(&destination_identity) {
            return Err(reject(
                "external inputs and qualification control directories overlap",
            ));
        }
    }
    let mut stages_ms = BTreeMap::new();
    let begin = Instant::now();
    let before = specification
        .copied
        .iter()
        .map(|root| capture(&root.source))
        .collect::<Result<Vec<_>>>()?;
    stages_ms.insert("source_before_copy".into(), begin.elapsed().as_millis());
    observer(QualificationStage::SourceCaptured)?;
    let begin = Instant::now();
    for root in &specification.copied {
        let relative = root
            .destination
            .strip_prefix(owner.active())
            .map_err(|_| reject("invalid staged root"))?;
        storage::copy_tree(&root.source, &owner.incoming().join(relative))?;
    }
    stages_ms.insert("copy_and_byte_compare".into(), begin.elapsed().as_millis());
    observer(QualificationStage::Copied)?;
    owner.publish()?;
    observer(QualificationStage::Published)?;
    configure(&mut specification)?;
    let bytes = serde_json::to_vec_pretty(&specification)?;
    storage::write_new(&owner.control().join(SPECIFICATION), &bytes)?;
    let begin = Instant::now();
    let sources = specification
        .copied
        .iter()
        .map(|root| capture(&root.source))
        .collect::<Result<Vec<_>>>()?;
    for (before, after) in before.iter().zip(&sources) {
        if before.entries != after.entries {
            return Err(reject("native sources changed during copying"));
        }
    }
    stages_ms.insert("source_s1".into(), begin.elapsed().as_millis());
    observer(QualificationStage::SourceVerified)?;
    let begin = Instant::now();
    let inventories = verify_projection(&specification, &sources)?;
    stages_ms.insert(
        "destination_and_external_inventory".into(),
        begin.elapsed().as_millis(),
    );
    observer(QualificationStage::DestinationMeasured)?;
    let begin = Instant::now();
    for source in &sources {
        if capture(&source.root)?.entries != source.entries {
            return Err(reject("native sources changed during verification"));
        }
    }
    check_absence(&specification)?;
    stages_ms.insert("source_s2".into(), begin.elapsed().as_millis());
    observer(QualificationStage::SourceRechecked)?;
    let begin = Instant::now();
    for inventory in &inventories {
        if capture(&inventory.root)?.entries != inventory.entries {
            return Err(reject(
                "native destination changed before evidence publication",
            ));
        }
    }
    stages_ms.insert(
        "destination_publication_audit".into(),
        begin.elapsed().as_millis(),
    );
    if fs::read(owner.control().join(SPECIFICATION))? != bytes_with_newline(&bytes) {
        return Err(reject("native specification changed during verification"));
    }
    let evidence = Evidence {
        schema: 1,
        contract: CONTRACT.into(),
        qualification_only: true,
        specification_sha256: hex::encode(Sha256::digest(bytes_with_newline(&bytes))),
        inventories,
        stages_ms,
        outcome: "copy-verified-closure-unqualified".into(),
    };
    storage::write_new(
        &owner.control().join(EVIDENCE),
        &serde_json::to_vec_pretty(&evidence)?,
    )?;
    Ok(())
}

fn bytes_with_newline(bytes: &[u8]) -> Vec<u8> {
    let mut result = bytes.to_vec();
    result.push(b'\n');
    result
}

/// Freshly audit every staged and external byte against completed evidence.
/// Original copied source paths are provenance, not runtime audit inputs.
pub fn audit(specification_path: &Path) -> Result<()> {
    if specification_path.file_name() != Some(OsStr::new(SPECIFICATION)) {
        return Err(reject("native audit requires specification.json"));
    }
    storage::validate_ancestors(specification_path)?;
    let bytes = fs::read(specification_path)?;
    let specification: Specification = serde_json::from_slice(&bytes)?;
    validate_policy(&specification.policy)?;
    if specification.schema != 1
        || specification.contract != CONTRACT
        || !specification.qualification_only
    {
        return Err(reject("invalid qualification specification"));
    }
    let parent = specification_path
        .parent()
        .ok_or_else(|| reject("specification parent missing"))?;
    let evidence_path = parent.join(EVIDENCE);
    storage::validate_ancestors(&evidence_path)?;
    let evidence_bytes = fs::read(&evidence_path)?;
    let evidence: Evidence = serde_json::from_slice(&evidence_bytes)?;
    if evidence.schema != 1
        || evidence.contract != CONTRACT
        || !evidence.qualification_only
        || evidence.outcome != "copy-verified-closure-unqualified"
        || evidence.specification_sha256 != hex::encode(Sha256::digest(&bytes))
    {
        return Err(reject("incomplete or mismatched qualification evidence"));
    }
    let expected: BTreeSet<_> = specification
        .copied
        .iter()
        .map(|root| root.destination.clone())
        .chain(specification.external.iter().cloned())
        .chain([specification.active.clone()])
        .collect();
    let actual: BTreeSet<_> = evidence
        .inventories
        .iter()
        .map(|record| record.root.clone())
        .collect();
    if expected != actual || actual.len() != evidence.inventories.len() {
        return Err(reject(
            "qualification evidence omits or duplicates declared roots",
        ));
    }
    let parent_identity = parent.canonicalize()?;
    let active_identity = specification.active.canonicalize()?;
    if parent_identity.starts_with(&active_identity)
        || active_identity.starts_with(&parent_identity)
    {
        return Err(reject("qualification metadata and runtime roots overlap"));
    }
    for root in &specification.copied {
        let destination_identity = root.destination.canonicalize()?;
        if !destination_identity.starts_with(&active_identity)
            || destination_identity == active_identity
        {
            return Err(reject("qualification projection escaped its active tree"));
        }
    }
    for root in &expected {
        if !root.is_absolute() {
            return Err(reject("qualification runtime roots must be absolute"));
        }
        let identity = root.canonicalize()?;
        if identity.starts_with(&parent_identity) || parent_identity.starts_with(&identity) {
            return Err(reject("qualification evidence overlaps a runtime input"));
        }
    }
    let mut reconfigured = specification.clone();
    configure(&mut reconfigured)?;
    if reconfigured != specification {
        return Err(reject(
            "qualification environment no longer matches native selection",
        ));
    }
    for inventory in evidence.inventories {
        if capture(&inventory.root)?.entries != inventory.entries {
            return Err(reject("qualified native inputs changed"));
        }
    }
    if fs::read(specification_path)? != bytes || fs::read(evidence_path)? != evidence_bytes {
        return Err(reject("native specification changed during audit"));
    }
    Ok(())
}
