//! Preserve Cargo's default test-target selection while bounding each Miri process tree.
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::{CiError, Result};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MiriTarget {
    Library,
    Binary(String),
    Integration(String),
    Example(String),
    Bench(String),
    Documentation,
}

impl MiriTarget {
    pub fn arguments(&self) -> Vec<&str> {
        match self {
            Self::Library => vec!["--lib"],
            Self::Binary(name) => vec!["--bin", name],
            Self::Integration(name) => vec!["--test", name],
            Self::Example(name) => vec!["--example", name],
            Self::Bench(name) => vec!["--bench", name],
            Self::Documentation => vec!["--doc"],
        }
    }
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    features: BTreeMap<String, Vec<String>>,
    targets: Vec<Target>,
}

#[derive(Deserialize)]
struct Target {
    name: String,
    kind: Vec<String>,
    test: bool,
    doctest: bool,
    #[serde(default, rename = "required-features")]
    required_features: Vec<String>,
}

/// Plan the same package/default-feature coverage as an unfiltered Cargo test.
/// Each target retains its entire harness; individual tests are never partitioned.
pub fn plan(metadata: &[u8], package_name: &str) -> Result<Vec<MiriTarget>> {
    let metadata: Metadata = serde_json::from_slice(metadata)?;
    let mut packages = metadata
        .packages
        .into_iter()
        .filter(|p| p.name == package_name);
    let package = packages
        .next()
        .ok_or_else(|| CiError::Message(format!("Miri package is absent: {package_name}")))?;
    if packages.next().is_some() {
        return Err(CiError::Message(format!(
            "Miri package is ambiguous: {package_name}"
        )));
    }
    let mut enabled = BTreeSet::new();
    let mut pending = vec!["default".to_owned()];
    while let Some(feature) = pending.pop() {
        if let Some(dependencies) = package.features.get(&feature)
            && enabled.insert(feature)
        {
            if dependencies
                .iter()
                .any(|dependency| dependency.contains('/'))
            {
                return Err(CiError::Message(
                        "Miri default-feature selection does not yet support dependency feature forwarding".to_owned(),
                    ));
            }
            // Dependency features do not enable package-local target gates.
            pending.extend(
                dependencies
                    .iter()
                    .filter(|f| package.features.contains_key(*f))
                    .cloned(),
            );
        }
    }
    let mut selected = BTreeSet::new();
    for target in package.targets {
        if !target.required_features.iter().all(|f| enabled.contains(f)) {
            continue;
        }
        let kind = match target.kind.as_slice() {
            [kind] => kind.as_str(),
            _ => {
                return Err(CiError::Message(format!(
                    "unsupported Miri target kinds: {:?}",
                    target.kind
                )));
            }
        };
        if target.doctest {
            if kind != "lib" {
                return Err(CiError::Message(format!(
                    "unsupported Miri doctest target: {}",
                    target.name
                )));
            }
            selected.insert(MiriTarget::Documentation);
        }
        if !target.test {
            // Custom build scripts are compiled as dependencies of the selected
            // targets. Other compile-only target kinds need an explicit policy.
            if !matches!(kind, "lib" | "bin" | "custom-build" | "bench") {
                return Err(CiError::Message(format!(
                    "unsupported compile-only Miri target: {}",
                    target.name
                )));
            }
            continue;
        }
        let selection = match kind {
            "lib" => MiriTarget::Library,
            "bin" => MiriTarget::Binary(target.name),
            "test" => MiriTarget::Integration(target.name),
            "example" => MiriTarget::Example(target.name),
            "bench" => MiriTarget::Bench(target.name),
            "custom-build" => continue,
            _ => {
                return Err(CiError::Message(format!(
                    "unsupported Miri test target: {} ({kind})",
                    target.name
                )));
            }
        };
        if !selected.insert(selection) {
            return Err(CiError::Message("duplicate Miri test target".to_owned()));
        }
    }
    if selected.is_empty() {
        return Err(CiError::Message("Miri selected no test targets".to_owned()));
    }
    Ok(selected.into_iter().collect())
}
