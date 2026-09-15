//! Desktop identity DTOs; native object creation and attestation remain separate.
use serde::{Deserialize, Serialize};

/// V1 desktop audit binding with exact names and security material.
/// Launch DTO V1 vectors pin the serde fields; plan and native attestation validate
/// their relationship to actual objects. This record itself owns no desktop handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopBindingV1 {
    pub exact_name: String,
    pub security_descriptor_sha256: String,
    pub window_station_security_descriptor_sddl: String,
    pub desktop_security_descriptor_sddl: String,
}
