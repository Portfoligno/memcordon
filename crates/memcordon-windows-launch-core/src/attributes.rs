//! Exact handle-role DTOs: representation is distinct from native handle ownership.
use serde::{Deserialize, Serialize};

/// V1 role spellings are audit data, pinned by launch DTO V1 serde vectors.
/// Adding a role requires an explicit compatibility decision; unknown roles fail decoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandleRoleV1 {
    StandardInput,
    StandardOutput,
    StandardError,
    LoaderReady,
}

/// V1 exact role-list DTO. Production plan admission requires this list empty;
/// deserialization alone does not authorize inherited handles. V1 vectors pin its shape.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactHandleListV1 {
    roles: Vec<HandleRoleV1>,
}

impl ExactHandleListV1 {
    #[must_use]
    pub fn none() -> Self {
        Self { roles: Vec::new() }
    }

    #[must_use]
    pub fn roles(&self) -> &[HandleRoleV1] {
        &self.roles
    }
}
