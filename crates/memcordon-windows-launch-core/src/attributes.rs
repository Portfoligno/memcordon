use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandleRoleV1 {
    StandardInput,
    StandardOutput,
    StandardError,
    LoaderReady,
}

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
