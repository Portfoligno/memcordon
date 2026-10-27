use serde::Serialize;
use std::{collections::BTreeMap, ffi::OsString};

use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuzzShard {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum RequiredFeature {
    #[serde(rename = "ci-targets")]
    CiTargets,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TargetPlan {
    pub name: String,
    pub required_features: Vec<RequiredFeature>,
}

impl TargetPlan {
    fn arguments(&self, phase: &'static str) -> Vec<OsString> {
        let mut arguments = vec!["fuzz".into(), phase.into(), OsString::from(&self.name)];
        for feature in &self.required_features {
            match feature {
                RequiredFeature::CiTargets => {
                    arguments.extend(["--features".into(), "ci-targets".into()])
                }
            }
        }
        arguments
    }
    pub fn build_arguments(&self) -> Vec<OsString> {
        self.arguments("build")
    }
    pub fn run_arguments(&self) -> Vec<OsString> {
        let mut arguments = self.arguments("run");
        arguments.extend([
            "--".into(),
            "-max_total_time=30".into(),
            if self.name.starts_with("workload-") {
                "-max_len=1048576".into()
            } else {
                "-max_len=4096".into()
            },
        ]);
        arguments
    }
}

/// Cargo's explicit bin inventory is the single source of fuzz coverage.
pub fn targets(manifest: &str, shard: Option<FuzzShard>) -> Result<Vec<String>> {
    let shard = shard.map(|shard| {
        crate::target_shard::ShardSpec::new(
            usize::from(shard == FuzzShard::Second),
            std::num::NonZeroUsize::new(2).expect("nonzero partition"),
        )
        .expect("valid two-way partition")
    });
    targets_sharded(manifest, shard)
}

pub fn targets_sharded(
    manifest: &str,
    shard: Option<crate::target_shard::ShardSpec>,
) -> Result<Vec<String>> {
    Ok(plans_sharded(manifest, shard)?
        .into_iter()
        .map(|plan| plan.name)
        .collect())
}

pub fn plans_sharded(
    manifest: &str,
    shard: Option<crate::target_shard::ShardSpec>,
) -> Result<Vec<TargetPlan>> {
    let document: toml::Value = toml::from_str(manifest)?;
    let bins = document
        .get("bin")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| CiError::Message("fuzz manifest has no explicit bin inventory".into()))?;
    let mut names = BTreeMap::new();
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
        let required_features = match bin.get("required-features") {
            None => Vec::new(),
            Some(value) => {
                let features = value.as_array().ok_or_else(|| {
                    CiError::Message("fuzz required-features must be an array".into())
                })?;
                let mut parsed = Vec::new();
                for feature in features {
                    let feature = match feature.as_str() {
                        Some("ci-targets") => RequiredFeature::CiTargets,
                        _ => {
                            return Err(CiError::Message(
                                "fuzz required-features contains an unsupported feature".into(),
                            ));
                        }
                    };
                    if parsed.contains(&feature) {
                        return Err(CiError::Message(
                            "fuzz required-features contains a duplicate feature".into(),
                        ));
                    }
                    parsed.push(feature);
                }
                parsed
            }
        };
        let plan = TargetPlan {
            name: name.to_owned(),
            required_features,
        };
        if names.insert(name.to_owned(), plan).is_some() {
            return Err(CiError::Message(
                "fuzz bin inventory contains duplicate names".into(),
            ));
        }
    }
    let selected: Vec<_> = names
        .into_values()
        .enumerate()
        .filter_map(|(index, plan)| {
            shard
                .is_none_or(|shard| shard.selects(index))
                .then_some(plan)
        })
        .collect();
    if selected.is_empty() {
        return Err(CiError::Message("fuzz selection is empty".into()));
    }
    Ok(selected)
}
