//! Fixed candidate policy experiment topology embedded into the B-bound
//! sealed-agent executable. This is not a policy registry or a release grant.
//! Dynamic registry, caller, H0 and plan bytes must still be authenticated
//! before invoking the production V2 predicate for any branch.

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

const REVIEWED_BYTES: &[u8] = include_bytes!("fixtures/private_policy_branches_v1.json");

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
    pub(crate) fn digest(&self) -> DiagnosticSha256 {
        hash_bytes(REVIEWED_BYTES)
    }

    pub(crate) fn branch_order(&self) -> &[String; 4] {
        &self.branch_order
    }
}

/// No runtime path, caller-supplied bytes or environment setting is accepted.
/// The agent executable digest in B transitively pins this reviewed fixture.
#[allow(dead_code)] // Producer requires protected H0/registry fixture acquisition.
pub(crate) fn acquire_reviewed_policy_fixture() -> Result<ReviewedPolicyFixtureV1, String> {
    let bytes = REVIEWED_BYTES
        .strip_suffix(b"\n")
        .ok_or("MCSEALED-PRIVATE-RELEASE: policy fixture newline absent")?;
    let fixture: ReviewedPolicyFixtureV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if serde_json::to_vec(&fixture).map_err(|error| error.to_string())? != bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: policy fixture is not canonical".into());
    }
    if fixture.schema_version != 1
        || fixture.selector != "private_tcp::wrong_grant_profile_and_port_rejected"
        || fixture.positive_control_selector != "private_tcp::native_tcp_bind_listen_connect"
        || fixture.branch_order
            != [
                "wrong-grant",
                "wrong-profile",
                "unapproved-changed-port-plan",
                "committed-port-tamper",
            ]
        || !fixture.require_frozen_port_binding
    {
        return Err("MCSEALED-PRIVATE-RELEASE: reviewed policy fixture differs".into());
    }
    Ok(fixture)
}
