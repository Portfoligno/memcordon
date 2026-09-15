//! Identity DTO ownership: prepared environment bytes are constructed elsewhere.
use serde::{Deserialize, Serialize};

/// V1 audit identity for an already prepared environment, never an environment builder.
/// Field names and encoding semantics are pinned by the launch DTO V1 vectors;
/// admission validates the encoding and digest through `ProductionLoaderPlanV1`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEnvironmentIdentityV1 {
    pub encoding: String,
    pub byte_len: u64,
    pub sha256: String,
}
