//! Probe is a USER/security attestation helper, not the workload initializer.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct ConsolelessProbePolicyV1 {
    schema_version: u32,
    role: &'static str,
    creation_flags: u32,
    job_at_creation: bool,
    inherited_handle_count: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u32,
    role: String,
    creation_flags: u32,
    job_at_creation: bool,
    inherited_handle_count: u32,
}

impl ConsolelessProbePolicyV1 {
    pub const BINDING_SCHEMA_VERSION: u32 = 6;

    pub const fn new() -> Self {
        Self {
            schema_version: 1,
            role: "probe",
            creation_flags: 0x0008_040c,
            job_at_creation: true,
            inherited_handle_count: 0,
        }
    }

    pub const fn creation_flags(&self) -> u32 {
        self.creation_flags
    }
}

impl TryFrom<Wire> for ConsolelessProbePolicyV1 {
    type Error = &'static str;

    fn try_from(wire: Wire) -> Result<Self, Self::Error> {
        let policy = Self::new();
        if wire.schema_version != policy.schema_version
            || wire.role != policy.role
            || wire.creation_flags != policy.creation_flags
            || wire.job_at_creation != policy.job_at_creation
            || wire.inherited_handle_count != policy.inherited_handle_count
        {
            return Err("invalid consoleless Probe creation policy");
        }
        Ok(policy)
    }
}

impl<'de> Deserialize<'de> for ConsolelessProbePolicyV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(Wire::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub(super) fn binding_domain(
    schema_version: u32,
    role: &str,
    policy: Option<&ConsolelessProbePolicyV1>,
) -> Result<&'static [u8], &'static str> {
    match (schema_version, role, policy) {
        (6, "probe", Some(_)) => Ok(b"memcordon-target-desktop-binding-v11\0"),
        // Legacy bindings used the Ready wire schema value 19, despite the V3 type name.
        // Keep that serialized representation and its original digest domain exact.
        (19, "holder" | "loader-control", None) => Ok(b"memcordon-target-desktop-binding-v8\0"),
        _ => Err("bootstrap role, schema and creation policy differ"),
    }
}

pub(super) fn validate_admission_capability(
    schema_version: u32,
    role: &str,
    policy: Option<&ConsolelessProbePolicyV1>,
    present: bool,
) -> Result<(), &'static str> {
    binding_domain(schema_version, role, policy)?;
    if matches!(role, "holder" | "probe") && present {
        Ok(())
    } else {
        Err("bootstrap Admission capability is absent or has an invalid role")
    }
}

pub(super) fn validate_image_capability(
    role: &str,
    has_claim: bool,
    has_handle: bool,
) -> Result<(), &'static str> {
    match (role, has_claim, has_handle) {
        ("probe", true, true) | ("holder" | "loader-control", false, false) => Ok(()),
        _ => Err("bootstrap image capability and identity differ from the exact role"),
    }
}
