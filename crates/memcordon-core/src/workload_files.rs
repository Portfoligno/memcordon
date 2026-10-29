//! Authority-free content and private-root declarations shared by wire readers.
use crate::DiagnosticSha256;
use crate::identifiers::LogicalId;
use serde::{Deserialize, Deserializer, Serialize};

pub fn is_beneath(path: &RootRelativePath, parent: &RootRelativePath) -> bool {
    path.as_str()
        .strip_prefix(parent.as_str())
        .is_some_and(|rest| rest.starts_with('/'))
}
use std::num::NonZeroU64;

/// A path in the constructed target root, distinct from a host pathname.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RootRelativePath(String);
impl RootRelativePath {
    pub fn new(value: String) -> Result<Self, String> {
        if value.is_empty()
            || value.len() > 4096
            || value.starts_with('/')
            || value.as_bytes().contains(&0)
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("invalid target-root-relative path".into());
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for RootRelativePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ImageEntryV1 {
    Regular {
        path: RootRelativePath,
        sha256: DiagnosticSha256,
        size: u64,
        executable: bool,
    },
    /// A manifest-internal target, reconstructed without following a source link.
    Symlink {
        path: RootRelativePath,
        target: RootRelativePath,
    },
}
impl ImageEntryV1 {
    pub fn path(&self) -> &RootRelativePath {
        match self {
            Self::Regular { path, .. } | Self::Symlink { path, .. } => path,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageEntrypointV1 {
    pub id: LogicalId,
    pub path: RootRelativePath,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WritableRootV1 {
    pub id: LogicalId,
    pub path: RootRelativePath,
    pub byte_limit: NonZeroU64,
    pub generated_execution: bool,
}
