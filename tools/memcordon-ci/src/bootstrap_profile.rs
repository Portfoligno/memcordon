use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum BootstrapProfile {
    Stable,
    Msrv,
    Miri,
    Fuzz,
    SupplyChain,
    ReleasePreflight,
}

impl BootstrapProfile {
    pub fn satisfies(self, required: Self) -> bool {
        required == Self::Stable
            || self == required
            || (self == Self::ReleasePreflight
                && matches!(required, Self::Msrv | Self::SupplyChain))
    }
}
