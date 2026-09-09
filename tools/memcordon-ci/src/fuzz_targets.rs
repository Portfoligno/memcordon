use std::collections::BTreeSet;

use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuzzShard {
    First,
    Second,
}

/// Cargo's explicit bin inventory is the single source of fuzz coverage.
pub fn targets(manifest: &str, shard: Option<FuzzShard>) -> Result<Vec<String>> {
    let document: toml::Value = toml::from_str(manifest)?;
    let bins = document
        .get("bin")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| CiError::Message("fuzz manifest has no explicit bin inventory".into()))?;
    let mut names = BTreeSet::new();
    for bin in bins {
        let name = bin
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
            .ok_or_else(|| CiError::Message("fuzz bin has an invalid name".into()))?;
        if !names.insert(name.to_owned()) {
            return Err(CiError::Message(
                "fuzz bin inventory contains duplicate names".into(),
            ));
        }
    }
    let selected: Vec<_> = names
        .into_iter()
        .enumerate()
        .filter_map(|(index, name)| {
            // Sorted alternating targets distribute the observed expensive harnesses.
            let first = index % 2 == 0;
            (shard.is_none() || first == (shard == Some(FuzzShard::First))).then_some(name)
        })
        .collect();
    if selected.is_empty() {
        return Err(CiError::Message("fuzz selection is empty".into()));
    }
    Ok(selected)
}
