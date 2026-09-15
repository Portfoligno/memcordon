//! Owner: source governance. Incomplete declarations and unsafe paths fail closed.

use std::collections::BTreeSet;

use super::{inventory, schema::Source};
use crate::{CiError, Result};

pub(super) fn validate(records: &[Source], inventory: &BTreeSet<String>) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut replaced = BTreeSet::new();
    for source in records {
        if !ids.insert(source.id.as_str()) || !paths.insert(source.path.clone()) {
            return Err(CiError::Message(format!(
                "duplicate source id or path: {}",
                source.id
            )));
        }
        if !inventory::relative(&source.path) || !inventory.contains(&source.path) {
            return Err(CiError::Message(format!(
                "stale or unsafe source record: {}",
                source.path
            )));
        }
        for (name, value) in [
            ("id", &source.id),
            ("owner", &source.owner),
            ("decision", &source.decision),
        ] {
            if value.trim().is_empty() {
                return Err(CiError::Message(format!(
                    "empty {name} for {}",
                    source.path
                )));
            }
        }
        for (name, values) in [
            ("protected_invariants", &source.protected_invariants),
            ("consumers", &source.consumers),
            ("routes", &source.routes),
            ("platforms", &source.platforms),
            ("work_packages", &source.work_packages),
        ] {
            if values.is_empty()
                || values.iter().any(|value| value.trim().is_empty())
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
            {
                return Err(CiError::Message(format!(
                    "empty or duplicate {name} for {}",
                    source.path
                )));
            }
        }
        for (name, value, allowed) in [
            (
                "kind",
                source.kind.as_str(),
                &[
                    "production",
                    "build",
                    "tooling",
                    "tooling-authority",
                    "test",
                    "fuzz",
                    "fixture",
                    "binary-unit-test",
                ][..],
            ),
            (
                "visibility",
                source.visibility.as_str(),
                &[
                    "stable-public",
                    "versioned-provider-contract",
                    "binary-private",
                    "tooling-only",
                    "test-only",
                    "hidden-native-hook",
                ][..],
            ),
            (
                "disposition",
                source.disposition.as_str(),
                &[
                    "retain",
                    "harden",
                    "extract",
                    "rename",
                    "retire-after-evidence",
                ][..],
            ),
        ] {
            if !allowed.contains(&value) {
                return Err(CiError::Message(format!(
                    "invalid {name} for {}: {value}",
                    source.path
                )));
            }
        }
        for old in &source.replaces {
            if old.trim().is_empty() || old == &source.id || !replaced.insert(old) {
                return Err(CiError::Message(format!(
                    "ambiguous source migration: {old}"
                )));
            }
        }
        if source.platforms.iter().any(|platform| {
            ![
                "portable",
                "linux-x64",
                "linux-arm64",
                "macos-x64",
                "macos-arm64",
                "windows-x64",
                "windows-arm64",
            ]
            .contains(&platform.as_str())
        }) {
            return Err(CiError::Message(format!(
                "unknown source platform: {}",
                source.path
            )));
        }
        if matches!(
            source.kind.as_str(),
            "test" | "fuzz" | "fixture" | "binary-unit-test"
        ) && source.visibility != "test-only"
        {
            return Err(CiError::Message(format!(
                "test/fixture source has production visibility: {}",
                source.path
            )));
        }
        if source.kind == "tooling-authority" && source.visibility != "tooling-only" {
            return Err(CiError::Message(format!(
                "tooling authority has a production or fixture visibility: {}",
                source.path
            )));
        }
    }
    if replaced.iter().any(|old| ids.contains(old.as_str())) {
        return Err(CiError::Message(
            "a replaced source id remains active".into(),
        ));
    }
    let missing: Vec<_> = inventory.difference(&paths).collect();
    if !missing.is_empty() {
        return Err(CiError::Message(format!(
            "unregistered Rust sources: {missing:?}"
        )));
    }
    Ok(())
}
