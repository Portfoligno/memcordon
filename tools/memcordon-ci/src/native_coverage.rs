//! Local Cargo target partitioning. No plan is transported between jobs.
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Selector {
    Lib,
    Bin(String),
    Test(String),
    Bench(String),
    Example(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub package: String,
    pub selector: Selector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    pub selectors: Vec<Selector>,
    pub support_binaries: Vec<String>,
}

/// Group equal workspace selectors together to preserve Cargo feature unification.
pub fn select(targets: &[Target], index: usize, count: usize) -> Result<Selection, String> {
    if count == 0 || index >= count {
        return Err("native shard index/count is invalid".into());
    }
    let mut groups: BTreeMap<Selector, BTreeSet<String>> = BTreeMap::new();
    let mut binaries = BTreeSet::new();
    for target in targets {
        if target.package.is_empty() {
            return Err("native target package is empty".into());
        }
        if let Selector::Bin(name) = &target.selector {
            if !binaries.insert(name.to_ascii_lowercase()) {
                return Err("native ordinary binary output names collide".into());
            }
        }
        if !groups
            .entry(target.selector.clone())
            .or_default()
            .insert(target.package.clone())
        {
            return Err("native target is repeated".into());
        }
    }
    if groups.len() < count {
        return Err("native shard selection would contain an empty shard".into());
    }
    let selectors = groups
        .into_keys()
        .enumerate()
        .filter_map(|(position, selector)| (position % count == index).then_some(selector))
        .collect();
    // A selected integration or bin harness may launch any ordinary sibling.
    Ok(Selection {
        selectors,
        support_binaries: targets
            .iter()
            .filter_map(|target| {
                if let Selector::Bin(name) = &target.selector {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect(),
    })
}

pub fn arguments(selection: &Selection, profile: &str) -> Vec<String> {
    let mut arguments = vec![
        "--workspace".into(),
        "--all-features".into(),
        "--locked".into(),
        "--profile".into(),
        profile.into(),
    ];
    for selector in &selection.selectors {
        match selector {
            Selector::Lib => arguments.push("--lib".into()),
            Selector::Bin(name) => arguments.extend(["--bin".into(), name.clone()]),
            Selector::Test(name) => arguments.extend(["--test".into(), name.clone()]),
            Selector::Bench(name) => arguments.extend(["--bench".into(), name.clone()]),
            Selector::Example(name) => arguments.extend(["--example".into(), name.clone()]),
        }
    }
    arguments
}
