//! Actual executable component inventory and native protocol identities.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeComponentRole {
    PublicCli,
    SealedAgent,
    Arm32AbiHelper,
    DesktopBootstrap,
    SessionBroker,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeComponentRecord {
    pub id: String,
    pub path: String,
    pub role: RuntimeComponentRole,
    pub size: u64,
    pub mode: u32,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeProviderProtocols {
    Linux {
        provider_contract: u32,
        launch_wire: u32,
    },
    Windows {
        provider_contract: u32,
        public_wire: u32,
        private_wire: u32,
    },
}
