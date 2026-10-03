use serde::{Deserialize, Serialize};

const EXPECTED_SCHEMA_VERSION: u8 = 1;
const EXPECTED_SELECTOR: &str = "private_tcp::wrong_grant_profile_and_port_rejected";
const EXPECTED_POSITIVE_CONTROL_SELECTOR: &str = "private_tcp::native_tcp_bind_listen_connect";
const EXPECTED_BRANCH_ORDER: [&str; 4] = [
    "wrong-grant",
    "wrong-profile",
    "unapproved-changed-port-plan",
    "committed-port-tamper",
];

/// Field order is part of the reviewed compact JSON encoding.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewedPolicyFixtureV1 {
    schema_version: u8,
    selector: String,
    positive_control_selector: String,
    branch_order: [String; 4],
    require_frozen_port_binding: bool,
}

impl ReviewedPolicyFixtureV1 {
    pub(crate) fn validate_expected(&self) -> Result<(), &'static str> {
        let branch_order_matches = self
            .branch_order
            .iter()
            .map(String::as_str)
            .eq(EXPECTED_BRANCH_ORDER);

        if self.schema_version != EXPECTED_SCHEMA_VERSION
            || self.selector != EXPECTED_SELECTOR
            || self.positive_control_selector != EXPECTED_POSITIVE_CONTROL_SELECTOR
            || !branch_order_matches
            || !self.require_frozen_port_binding
        {
            return Err("MCSEALED-PRIVATE-RELEASE: reviewed policy fixture differs");
        }
        Ok(())
    }

    #[allow(dead_code)] // The build-script crate shares the schema without using this accessor.
    pub(crate) fn branch_order(&self) -> &[String; 4] {
        &self.branch_order
    }
}
