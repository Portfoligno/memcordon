use super::source::PUBLIC_PACKAGES;
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Distribution {
    pub format: String,
    pub revision: u32,
    pub packages: Vec<String>,
    pub public_consumer: bool,
    pub targets: Vec<TargetDistribution>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDistribution {
    pub target: String,
    pub features: Vec<String>,
    pub binaries: Vec<String>,
    pub units: Vec<String>,
}

/// Build feature closure, independent of the spelling of transitive features.
/// This selects existing runtime suites; it does not certify consumer readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSelection {
    CliOnly,
    LinuxBaseline,
    LinuxPrivateTcp,
    WindowsSealed,
}

impl Distribution {
    /// Explicit full consumer profile; ordinary distribution defaults stay independent.
    pub fn consumer_readiness(mut self) -> Result<Self> {
        for target in &mut self.targets {
            match target.target.as_str() {
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu" => {
                    target.features = vec!["sealed-runtime".into(), "private-tcp".into()];
                    target.binaries = vec!["memcordon".into(), "memcordon-sealed-agent".into()];
                    target.units = [
                        "memcordon-sealed-agent.service",
                        "memcordon-sealed-agent.socket",
                        "memcordon-sealed-launcher.service",
                        "memcordon-sealed-launcher.socket",
                        "memcordon-sealed-network-launcher.service",
                        "memcordon-sealed-network-launcher.socket",
                        "memcordon.conf",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect();
                }
                "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc" => {
                    target.features =
                        vec!["sealed-runtime".into(), "windows-sealed-runtime".into()];
                    target.binaries = [
                        "memcordon",
                        "memcordon-sealed-agent",
                        "memcordon-target-desktop-bootstrap",
                        "memcordon-session-broker",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect();
                    target.units.clear();
                }
                _ => {}
            }
        }
        self.validate()?;
        Ok(self)
    }

    pub fn read(root: &Path) -> Result<Self> {
        let bytes = super::artifacts::read_file(&root.join("ci").join("distribution.toml"))?;
        let value: Self = toml::from_str(
            std::str::from_utf8(&bytes)
                .map_err(|_| CiError::Message("distribution is not UTF-8".into()))?,
        )?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        let packages: BTreeSet<_> = self.packages.iter().map(String::as_str).collect();
        if self.format != "memcordon.distribution"
            || self.revision != 1
            || packages.len() != self.packages.len()
            || packages != PUBLIC_PACKAGES.into_iter().collect()
            || self.targets.is_empty()
            || self.targets.len() > 6
        {
            return Err(CiError::Message(
                "distribution package/format/target selection differs".into(),
            ));
        }
        let mut targets = BTreeSet::new();
        for target in &self.targets {
            target.validate()?;
            if !targets.insert(&target.target) {
                return Err(CiError::Message("duplicate selected target".into()));
            }
        }
        Ok(())
    }

    pub fn native(&self) -> Result<&TargetDistribution> {
        let expected = native_target()?;
        self.targets
            .iter()
            .find(|target| target.target == expected)
            .ok_or_else(|| CiError::Message("native host is not selected by distribution".into()))
    }
}

pub fn native_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        ("windows", "aarch64") => Ok("aarch64-pc-windows-msvc"),
        _ => Err(CiError::Message("unsupported native release host".into())),
    }
}

impl TargetDistribution {
    pub fn runtime_selection(&self) -> Result<RuntimeSelection> {
        self.validate()?;
        Ok(
            if self
                .features
                .iter()
                .any(|value| value == "windows-sealed-runtime")
            {
                RuntimeSelection::WindowsSealed
            } else if self.features.iter().any(|value| value == "private-tcp") {
                RuntimeSelection::LinuxPrivateTcp
            } else if self.features.iter().any(|value| value == "sealed-runtime") {
                RuntimeSelection::LinuxBaseline
            } else {
                RuntimeSelection::CliOnly
            },
        )
    }

    pub fn validate(&self) -> Result<()> {
        let linux = matches!(
            self.target.as_str(),
            "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
        );
        let windows = matches!(
            self.target.as_str(),
            "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc"
        );
        let macos = matches!(
            self.target.as_str(),
            "x86_64-apple-darwin" | "aarch64-apple-darwin"
        );
        let features: BTreeSet<_> = self.features.iter().map(String::as_str).collect();
        let binaries: BTreeSet<_> = self.binaries.iter().map(String::as_str).collect();
        let units: BTreeSet<_> = self.units.iter().map(String::as_str).collect();
        if !(linux || windows || macos)
            || features.len() != self.features.len()
            || binaries.len() != self.binaries.len()
            || units.len() != self.units.len()
            || !binaries.contains("memcordon")
            || features.iter().any(|feature| {
                !matches!(
                    *feature,
                    "sealed-runtime" | "private-tcp" | "windows-sealed-runtime"
                )
            })
            || features.contains("private-tcp") && !linux
            || features.contains("windows-sealed-runtime") && !windows
            || macos && !features.is_empty()
        {
            return Err(CiError::Message(
                "incompatible platform/features/binaries".into(),
            ));
        }
        let sealed = !features.is_empty();
        let mut expected_bins = BTreeSet::from(["memcordon"]);
        let mut expected_units = BTreeSet::new();
        if sealed {
            expected_bins.insert("memcordon-sealed-agent");
        }
        if windows && sealed {
            if !features.contains("windows-sealed-runtime") {
                return Err(CiError::Message(
                    "Windows sealed companions require explicit Windows feature".into(),
                ));
            }
            expected_bins.extend([
                "memcordon-target-desktop-bootstrap",
                "memcordon-session-broker",
            ]);
        }
        if linux && sealed {
            expected_units.extend([
                "memcordon-sealed-agent.service",
                "memcordon-sealed-agent.socket",
                "memcordon-sealed-launcher.service",
                "memcordon-sealed-launcher.socket",
                "memcordon.conf",
            ]);
            if features.contains("private-tcp") {
                expected_units.extend([
                    "memcordon-sealed-network-launcher.service",
                    "memcordon-sealed-network-launcher.socket",
                ]);
            }
        }
        if binaries != expected_bins || units != expected_units {
            return Err(CiError::Message(
                "selected runtime member inventory is incomplete or contains a fixture".into(),
            ));
        }
        Ok(())
    }
}
