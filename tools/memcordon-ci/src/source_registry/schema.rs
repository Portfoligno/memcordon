//! Owner: source governance. Strict declarations carry no execution authority.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Domain {
    pub schema: u32,
    pub source: Vec<Source>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub path: String,
    pub owner: String,
    pub kind: String,
    pub visibility: String,
    pub disposition: String,
    pub protected_invariants: Vec<String>,
    pub consumers: Vec<String>,
    pub routes: Vec<String>,
    pub cfg: Vec<String>,
    pub item_visibility: Vec<String>,
    pub platforms: Vec<String>,
    pub work_packages: Vec<String>,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaces: Vec<String>,
}
