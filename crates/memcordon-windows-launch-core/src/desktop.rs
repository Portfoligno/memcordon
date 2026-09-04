use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopBindingV1 {
    pub exact_name: String,
    pub security_descriptor_sha256: String,
    pub window_station_security_descriptor_sddl: String,
    pub desktop_security_descriptor_sddl: String,
}
