//! Owner: source governance. Stable identities persist across moves and retirement.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use super::schema::Source;
use crate::{CiError, Result};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    schema: u32,
    identity: Vec<Identity>,
    #[serde(default)]
    retired: Vec<Retired>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    id: String,
    original_path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retired {
    id: String,
    reason: String,
}

pub(super) fn validate(root: &Path, sources: &[Source]) -> Result<()> {
    validate_bytes(
        &fs::read_to_string(root.join("ci/source-history.toml"))?,
        sources,
    )
}

pub(super) fn validate_bytes(bytes: &str, sources: &[Source]) -> Result<()> {
    let history: History = toml::from_str(bytes)?;
    if history.schema != 1 || history.identity.is_empty() {
        return Err(CiError::Message(
            "unsupported or empty source history".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for entry in &history.identity {
        if entry.id.trim().is_empty()
            || !super::inventory::relative(&entry.original_path)
            || !ids.insert(entry.id.as_str())
            || !paths.insert(entry.original_path.as_str())
        {
            return Err(CiError::Message(
                "duplicate or invalid historical source identity".into(),
            ));
        }
    }
    let active: BTreeSet<_> = sources.iter().map(|source| source.id.as_str()).collect();
    let mut accounted = active.clone();
    for source in sources {
        if !ids.contains(source.id.as_str()) {
            return Err(CiError::Message(format!(
                "source identity missing from history: {}",
                source.id
            )));
        }
        for old in &source.replaces {
            if !ids.contains(old.as_str()) || !accounted.insert(old.as_str()) {
                return Err(CiError::Message(format!(
                    "source replacement has no unique historical identity: {old}"
                )));
            }
        }
        if history.identity.iter().any(|entry| {
            entry.original_path == source.path
                && entry.id != source.id
                && !source.replaces.contains(&entry.id)
        }) {
            return Err(CiError::Message(format!(
                "historical source identity changed without migration: {}",
                source.path
            )));
        }
    }
    for retirement in &history.retired {
        if retirement.reason.trim().is_empty()
            || !ids.contains(retirement.id.as_str())
            || !accounted.insert(retirement.id.as_str())
        {
            return Err(CiError::Message(format!(
                "invalid or active source retirement: {}",
                retirement.id
            )));
        }
    }
    let missing: Vec<_> = ids.difference(&accounted).collect();
    if !missing.is_empty() {
        return Err(CiError::Message(format!(
            "source identities vanished without retirement or replacement: {missing:?}"
        )));
    }
    Ok(())
}
