//! Source-bound Cargo target ownership. Descriptive receipts never replace product authority.
use crate::release::{artifacts, source::BuildSourceIdentity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageIdentity {
    pub source: BuildSourceIdentity,
    pub source_tree_sha256: String,
    pub lock_sha256: String,
    pub configuration_sha256: String,
    pub toolchain: String,
    pub cargo_version: String,
    pub rustc_verbose_sha256: String,
    pub host: String,
    pub target: String,
    pub profile: String,
    pub all_features: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TargetKind {
    Lib,
    ProcMacro,
    Bin,
    Test,
    Bench,
    Example,
    CustomBuild,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSpec {
    /// Workspace-relative Cargo.toml path, never a checkout-absolute package id.
    pub package: String,
    pub name: String,
    pub kind: TargetKind,
    pub source: String,
    pub required_features: Vec<String>,
    pub harness: bool,
    pub test: bool,
    pub expected_profile: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSpec {
    pub identity: CoverageIdentity,
    pub packages: Vec<String>,
    pub package_features: BTreeMap<String, Vec<String>>,
    pub targets: Vec<TargetSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Selector {
    Lib,
    Bin(String),
    Test(String),
    Bench(String),
    Example(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Variant {
    Test,
    OrdinaryBinarySupport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub id: String,
    pub target: TargetSpec,
    pub variant: Variant,
    pub executable_required: bool,
    pub execution_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub selector: Selector,
    pub requirements: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shard {
    pub id: usize,
    pub groups: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub spec: WorkspaceSpec,
    pub requirements: Vec<Requirement>,
    pub groups: Vec<Group>,
    pub shards: Vec<Shard>,
    pub sha256: String,
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_vec(value)
        .map(|bytes| artifacts::checksum(&bytes))
        .map_err(|error| error.to_string())
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn relative(value: &str) -> Result<()> {
    artifacts::safe_relative(Path::new(value))
        .map(|_| ())
        .map_err(|error| error.to_string())
}
fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1]) && values.iter().all(|value| !value.is_empty())
}
pub fn target_kind(kinds: &[String]) -> Result<TargetKind> {
    if !kinds.is_empty()
        && kinds.iter().all(|kind| {
            matches!(
                kind.as_str(),
                "lib" | "rlib" | "dylib" | "cdylib" | "staticlib"
            )
        })
    {
        return Ok(TargetKind::Lib);
    }
    match kinds
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["proc-macro"] => Ok(TargetKind::ProcMacro),
        ["bin"] => Ok(TargetKind::Bin),
        ["test"] => Ok(TargetKind::Test),
        ["bench"] => Ok(TargetKind::Bench),
        ["example"] => Ok(TargetKind::Example),
        ["custom-build"] => Ok(TargetKind::CustomBuild),
        _ => Err("native coverage Cargo target kind is unsupported or ambiguous".into()),
    }
}
impl CoverageIdentity {
    pub fn validate(&self) -> Result<()> {
        self.source.validate().map_err(|error| error.to_string())?;
        let mut cargo_version = self.cargo_version.split_whitespace();
        let pinned_cargo =
            cargo_version.next() == Some("cargo") && cargo_version.next() == Some("1.97.1");
        if [
            &self.source_tree_sha256,
            &self.lock_sha256,
            &self.configuration_sha256,
            &self.rustc_verbose_sha256,
        ]
        .into_iter()
        .any(|value| !sha(value))
            || self.toolchain != "1.97.1"
            || !pinned_cargo
            || self.host.is_empty()
            || self.host != self.target
            || self.profile != "release"
            || !self.all_features
        {
            return Err(
                "native coverage source/toolchain/target/profile selection is invalid".into(),
            );
        }
        Ok(())
    }
}

impl Plan {
    pub fn build(mut spec: WorkspaceSpec, shard_count: usize) -> Result<Self> {
        spec.identity.validate()?;
        if serde_json::to_vec(&spec)
            .map_err(|error| error.to_string())?
            .len()
            > memcordon_readiness_verifier::MAX_INDEX_BYTES
        {
            return Err("native coverage source plan exceeds index bound".into());
        }
        if shard_count == 0 || spec.packages.is_empty() || spec.targets.is_empty() {
            return Err(
                "native coverage requires packages, targets and positive shard count".into(),
            );
        }
        spec.packages.sort();
        if !sorted_unique(&spec.packages) {
            return Err("native coverage repeats a workspace package".into());
        }
        for package in &spec.packages {
            relative(package)?;
        }
        if spec.package_features.keys().cloned().collect::<Vec<_>>() != spec.packages {
            return Err(
                "native coverage feature selection omits or substitutes a workspace package".into(),
            );
        }
        for features in spec.package_features.values_mut() {
            features.sort();
            if !sorted_unique(features) {
                return Err("native coverage repeats or empties a selected feature".into());
            }
        }
        for target in &mut spec.targets {
            relative(&target.source)?;
            if !spec.package_features.contains_key(&target.package)
                || target.name.is_empty()
                || target.name.starts_with('-')
                || target.name.chars().any(char::is_control)
            {
                return Err("native coverage target package/name/source is invalid".into());
            }
            if (target.kind == TargetKind::Bin && !target.name.is_ascii())
                || (target.kind == TargetKind::Lib && !target.test)
            {
                return Err(
                    "native coverage target naming or library test mode is not admitted".into(),
                );
            }
            target.required_features.sort();
            if !target.expected_profile.is_object() || target.expected_profile["test"] != true {
                return Err("native coverage target lacks its admitted Cargo test profile".into());
            }
            if !sorted_unique(&target.required_features)
                || target
                    .required_features
                    .iter()
                    .any(|feature| !spec.package_features[&target.package].contains(feature))
            {
                return Err("native coverage required feature is absent or duplicated".into());
            }
            // Bench semantics have not yet been admitted by the pinned adapter.
            if matches!(
                target.kind,
                TargetKind::Bench | TargetKind::ProcMacro | TargetKind::CustomBuild
            ) {
                return Err(
                    "native coverage target is not an admitted independent selector obligation"
                        .into(),
                );
            }
        }
        spec.targets.sort_by(|a, b| {
            (&a.package, a.kind, &a.name, &a.source).cmp(&(&b.package, b.kind, &b.name, &b.source))
        });
        let mut keys = BTreeSet::new();
        let mut binary_names = BTreeSet::new();
        let mut requirements = Vec::new();
        let mut grouped: BTreeMap<Selector, Vec<String>> = BTreeMap::new();
        for target in &spec.targets {
            if target.kind == TargetKind::Bin
                && !binary_names.insert(target.name.to_ascii_lowercase())
            {
                return Err(
                    "native coverage ordinary executable output names collide across packages"
                        .into(),
                );
            }
            if !keys.insert((target.package.clone(), target.kind, target.name.clone())) {
                return Err("native coverage repeats a target".into());
            }
            let selector = match target.kind {
                TargetKind::Lib | TargetKind::ProcMacro => Selector::Lib,
                TargetKind::Bin => Selector::Bin(target.name.clone()),
                TargetKind::Test => Selector::Test(target.name.clone()),
                TargetKind::Bench => Selector::Bench(target.name.clone()),
                TargetKind::Example => Selector::Example(target.name.clone()),
                TargetKind::CustomBuild => {
                    return Err("custom build scripts are supporting units, not selectors".into());
                }
            };
            let id = digest(&(target, Variant::Test))?;
            requirements.push(Requirement {
                id: id.clone(),
                target: target.clone(),
                variant: Variant::Test,
                executable_required: true,
                execution_required: target.kind != TargetKind::Example || target.test,
            });
            grouped.entry(selector.clone()).or_default().push(id);
            // A binary harness may launch its ordinary sibling even without an
            // integration target. Its own selector owns that prerequisite.
            if target.kind == TargetKind::Bin {
                let id = digest(&(target, Variant::OrdinaryBinarySupport))?;
                requirements.push(Requirement {
                    id: id.clone(),
                    target: target.clone(),
                    variant: Variant::OrdinaryBinarySupport,
                    executable_required: true,
                    execution_required: false,
                });
                grouped.entry(selector).or_default().push(id);
            }
        }
        let groups: Vec<_> = grouped
            .into_iter()
            .map(|(selector, mut requirements)| {
                requirements.sort();
                Group {
                    selector,
                    requirements,
                }
            })
            .collect();
        let count = shard_count.min(groups.len());
        let mut shards: Vec<_> = (0..count)
            .map(|id| Shard {
                id,
                groups: Vec::new(),
            })
            .collect();
        for index in 0..groups.len() {
            shards[index % count].groups.push(index);
        }
        let mut plan = Self {
            schema_version: 1,
            spec,
            requirements,
            groups,
            shards,
            sha256: String::new(),
        };
        plan.sha256 = digest(&(
            &plan.schema_version,
            &plan.spec,
            &plan.requirements,
            &plan.groups,
            &plan.shards,
        ))?;
        Ok(plan)
    }
    pub fn validate(&self) -> Result<()> {
        let expected = Self::build(self.spec.clone(), self.shards.len())?;
        if expected != *self {
            return Err("native coverage plan is not its canonical source-bound projection".into());
        }
        Ok(())
    }
    pub fn selectors(&self, shard: usize) -> Result<Vec<String>> {
        let shard = self
            .shards
            .get(shard)
            .filter(|entry| entry.id == shard)
            .ok_or("native coverage shard is absent")?;
        let mut arguments = vec![
            "--workspace".into(),
            "--all-features".into(),
            "--locked".into(),
            "--release".into(),
        ];
        for index in &shard.groups {
            match &self
                .groups
                .get(*index)
                .ok_or("native coverage group is absent")?
                .selector
            {
                Selector::Lib => arguments.push("--lib".into()),
                Selector::Bin(name) => arguments.extend(["--bin".into(), name.clone()]),
                Selector::Test(name) => arguments.extend(["--test".into(), name.clone()]),
                Selector::Bench(name) => arguments.extend(["--bench".into(), name.clone()]),
                Selector::Example(name) => arguments.extend(["--example".into(), name.clone()]),
            }
        }
        Ok(arguments)
    }
    pub fn selection_sha256(&self, shard: usize) -> Result<String> {
        digest(&(
            &self.sha256,
            self.selectors(shard)?,
            self.support_selectors(shard)?,
        ))
    }
    pub fn support_selectors(&self, shard: usize) -> Result<Vec<String>> {
        let shard = self
            .shards
            .get(shard)
            .filter(|entry| entry.id == shard)
            .ok_or("native coverage shard is absent")?;
        let owned: BTreeSet<_> = shard
            .groups
            .iter()
            .flat_map(|index| self.groups[*index].requirements.iter())
            .collect();
        let names: BTreeSet<_> = self
            .requirements
            .iter()
            .filter(|requirement| {
                requirement.variant == Variant::OrdinaryBinarySupport
                    && owned.contains(&requirement.id)
            })
            .map(|requirement| requirement.target.name.clone())
            .collect();
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut arguments = vec![
            "--workspace".into(),
            "--all-features".into(),
            "--locked".into(),
            "--release".into(),
        ];
        for name in names {
            arguments.extend(["--bin".into(), name]);
        }
        Ok(arguments)
    }
}

/// Merge real Cargo phase observations, admitting repeated identical supporting
/// units but rejecting divergent executable bytes for the same compiler unit.
pub fn merge_units(
    first: Vec<UnitObservation>,
    second: Vec<UnitObservation>,
) -> Result<Vec<UnitObservation>> {
    let mut merged = BTreeMap::new();
    for units in [first, second] {
        if !units.is_empty() {
            unit_inventory(&units)?;
        }
        for unit in units {
            let key = digest(&(
                &unit.package,
                &unit.target_name,
                &unit.target_kind,
                &unit.source,
                &unit.raw_target,
                &unit.profile,
                &unit.features,
            ))?;
            if let Some(existing) = merged.get(&key) {
                if existing != &unit {
                    return Err("native coverage supporting unit observations conflict".into());
                }
            } else {
                merged.insert(key, unit);
            }
            if merged.len() > memcordon_readiness_verifier::MAX_PRODUCER_ARTIFACTS {
                return Err("native coverage merged unit inventory exceeds bound".into());
            }
        }
    }
    let units: Vec<_> = merged.into_values().collect();
    unit_inventory(&units)?;
    Ok(units)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableRecord {
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitObservation {
    /// Workspace manifest-relative key, or a stable dependency source identity.
    pub package: String,
    pub target_name: String,
    pub target_kind: TargetKind,
    pub source: String,
    /// Cargo target object with checkout/registry paths normalized by the owner.
    pub raw_target: Value,
    pub profile: Value,
    pub features: Vec<String>,
    pub executable: Option<ExecutableRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseReceipt {
    pub selection_sha256: String,
    pub success: bool,
    pub writers_settled: bool,
    pub completed_before_deadline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardReceipt {
    pub schema_version: u32,
    pub identity: CoverageIdentity,
    pub plan_sha256: String,
    pub shard_id: usize,
    pub compile: PhaseReceipt,
    pub execute: PhaseReceipt,
    pub compiled_units: Vec<UnitObservation>,
    pub executed_units: Vec<UnitObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aggregate {
    pub schema_version: u32,
    pub plan_sha256: String,
    pub identity: CoverageIdentity,
    pub shard_receipts: Vec<String>,
    pub covered_requirements: Vec<String>,
}

fn unit_inventory(units: &[UnitObservation]) -> Result<BTreeMap<String, &UnitObservation>> {
    if units.is_empty() || units.len() > memcordon_readiness_verifier::MAX_PRODUCER_ARTIFACTS {
        return Err("native coverage compiler unit inventory is empty or exceeds its bound".into());
    }
    let mut inventory = BTreeMap::new();
    for unit in units {
        relative(&unit.source)?;
        if unit.package.is_empty()
            || unit.target_name.is_empty()
            || !unit.profile.is_object()
            || !unit.profile["test"].is_boolean()
            || !sorted_unique(&unit.features)
            || !unit.raw_target.is_object()
            || unit.raw_target["name"] != unit.target_name
            || unit.raw_target["src_path"] != unit.source
        {
            return Err("native coverage unit identity/profile/features are malformed".into());
        }
        let kinds: Vec<String> = serde_json::from_value(unit.raw_target["kind"].clone())
            .map_err(|_| "native coverage raw Cargo target kinds are absent")?;
        if target_kind(&kinds)? != unit.target_kind {
            return Err("native coverage typed and raw Cargo target kind differ".into());
        }
        if let Some(executable) = &unit.executable
            && (executable.length == 0
                || executable.length > memcordon_readiness_verifier::MAX_PRODUCER_BYTES
                || !sha(&executable.sha256))
        {
            return Err("native coverage executable identity is malformed or exceeds bound".into());
        }
        if inventory.insert(digest(unit)?, unit).is_some() {
            return Err("native coverage unit inventory repeats a record".into());
        }
    }
    Ok(inventory)
}

impl Plan {
    fn receipt_requirements(&self, receipt: &ShardReceipt) -> Result<BTreeSet<String>> {
        let mut covered = BTreeSet::new();
        if receipt.schema_version != 1
            || receipt.identity != self.spec.identity
            || receipt.plan_sha256 != self.sha256
        {
            return Err("native coverage receipt source/plan/schema/ownership differs".into());
        }
        let shard = self
            .shards
            .get(receipt.shard_id)
            .ok_or("native coverage receipt names an unknown shard")?;
        let owned: BTreeSet<_> = shard
            .groups
            .iter()
            .flat_map(|index| self.groups[*index].requirements.iter())
            .collect();
        let selection = self.selection_sha256(receipt.shard_id)?;
        for phase in [&receipt.compile, &receipt.execute] {
            if phase.selection_sha256 != selection
                || !phase.success
                || !phase.writers_settled
                || !phase.completed_before_deadline
            {
                return Err("native coverage compile/execution selection failed, expired or remains unsettled".into());
            }
        }
        let compiled = unit_inventory(&receipt.compiled_units)?;
        let executed = unit_inventory(&receipt.executed_units)?;
        if compiled.keys().ne(executed.keys()) {
            return Err(
                "native coverage execution did not consume the same compiled unit inventory".into(),
            );
        }
        // Profile/features are checked only for top-level obligations. Host/build
        // dependency variants remain distinct supporting observations.
        for requirement in &self.requirements {
            for unit in compiled.values().filter(|unit| {
                unit.package == requirement.target.package
                    && unit.target_name == requirement.target.name
                    && unit.target_kind == requirement.target.kind
                    && unit.source == requirement.target.source
                    && unit.profile["test"] == (requirement.variant == Variant::Test)
            }) {
                if requirement.variant == Variant::Test && !owned.contains(&requirement.id) {
                    return Err(
                        "native coverage receipt contains another shard's selected target variant"
                            .into(),
                    );
                }
                let mut expected_profile = requirement.target.expected_profile.clone();
                expected_profile["test"] = Value::Bool(requirement.variant == Variant::Test);
                if unit.profile != expected_profile
                    || unit.features != self.spec.package_features[&unit.package]
                {
                    return Err(
                        "native coverage top-level profile or selected features diverged".into(),
                    );
                }
            }
        }
        for unit in compiled.values() {
            if self.spec.package_features.contains_key(&unit.package)
                && unit.profile["test"] == true
                && !self.requirements.iter().any(|requirement| {
                    requirement.variant == Variant::Test
                        && unit.package == requirement.target.package
                        && unit.target_name == requirement.target.name
                        && unit.target_kind == requirement.target.kind
                        && unit.source == requirement.target.source
                })
            {
                return Err(
                    "native coverage receipt contains an unplanned workspace test target".into(),
                );
            }
        }
        for group in &shard.groups {
            for id in &self.groups[*group].requirements {
                let requirement = self
                    .requirements
                    .iter()
                    .find(|item| &item.id == id)
                    .ok_or("native coverage requirement is absent")?;
                let matches: Vec<_> = compiled
                    .values()
                    .filter(|unit| {
                        unit.package == requirement.target.package
                            && unit.target_name == requirement.target.name
                            && unit.target_kind == requirement.target.kind
                            && unit.source == requirement.target.source
                            && unit.profile["test"] == (requirement.variant == Variant::Test)
                    })
                    .collect();
                if matches.len() != 1
                    || (requirement.executable_required && matches[0].executable.is_none())
                {
                    return Err("native coverage owning shard omitted or duplicated an expected executable unit".into());
                }
                if !covered.insert(id.clone()) {
                    return Err("native coverage target has duplicate completion owners".into());
                }
            }
        }
        Ok(covered)
    }
    pub fn validate_receipt(&self, receipt: &ShardReceipt) -> Result<()> {
        self.validate()?;
        self.receipt_requirements(receipt).map(|_| ())
    }
    pub fn aggregate(&self, receipts: &[ShardReceipt]) -> Result<Aggregate> {
        self.validate()?;
        if receipts.len() != self.shards.len() {
            return Err("native coverage receipt set is incomplete or oversized".into());
        }
        let mut selected = BTreeMap::new();
        let mut covered = BTreeSet::new();
        for receipt in receipts {
            if selected
                .insert(receipt.shard_id, digest(receipt)?)
                .is_some()
            {
                return Err("native coverage receipt set repeats an owner".into());
            }
            for requirement in self.receipt_requirements(receipt)? {
                if !covered.insert(requirement) {
                    return Err("native coverage target has duplicate completion owners".into());
                }
            }
        }
        if covered
            != self
                .requirements
                .iter()
                .map(|item| item.id.clone())
                .collect()
        {
            return Err(
                "native coverage aggregate does not cover the original full requirement union"
                    .into(),
            );
        }
        Ok(Aggregate {
            schema_version: 1,
            plan_sha256: self.sha256.clone(),
            identity: self.spec.identity.clone(),
            shard_receipts: selected.into_values().collect(),
            covered_requirements: covered.into_iter().collect(),
        })
    }
}
