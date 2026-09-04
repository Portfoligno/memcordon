use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEnvironmentIdentityV1 {
    pub encoding: String,
    pub byte_len: u64,
    pub sha256: String,
}
