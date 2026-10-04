//! Actual selected runtime components. This inventory grants no release or local permission.
use serde::{Deserialize, Serialize};

pub const RUNTIME_MANIFEST_FORMAT: &str = "memcordon.runtime-manifest";
pub const RUNTIME_MANIFEST_REVISION: u32 = 1;

/// The baseline catalogue describes existing mechanism limits, not a grant.
pub fn baseline_catalog_digest(windows: bool) -> String {
    use crate::workload_registry::BaselineProfile;
    let profile = if windows {
        BaselineProfile::WindowsHostNetworkExternal
    } else {
        BaselineProfile::LinuxUnixCreate
    };
    let mut encoder = crate::workload_codec::Encoder::new(
        b"profile-catalog-v1",
        crate::workload_limits::CONTRACT_BYTES,
    )
    .expect("fixed catalog domain fits");
    encoder.count(1).expect("one profile fits");
    let reference = profile.reference();
    encoder.id(&reference.id).expect("fixed profile id fits");
    encoder
        .digest(&reference.semantic_digest)
        .expect("profile digest fits");
    crate::workload_codec::hash_bytes(&encoder.finish()).into()
}

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "selection", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SealedRuntime {
    Included {
        agent_component: String,
        native_protocols: NativeProviderProtocols,
        mechanism: String,
        workload_contract_schema: u32,
        profile_catalog_sha256: String,
        profiles: Vec<String>,
    },
    NotIncluded,
}

/// Package selection and byte identity. Parsed metadata is never an admission capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifest {
    pub format: String,
    pub revision: u32,
    pub project: String,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub components: Vec<RuntimeComponentRecord>,
    pub sealed: SealedRuntime,
}

/// A fresh administrative observation; never an authorization receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InstalledPolicyObservationV1 {
    Unconfigured,
    Unavailable,
    Active {
        epoch: crate::workload_contract::PolicyEpoch,
        registry_digest: crate::DiagnosticSha256,
        enabled_profiles: crate::BoundedVec<crate::workload_contract::ProfileRef, 16>,
    },
}

impl InstalledPolicyObservationV1 {
    pub fn valid_for(&self, profile: crate::workload_registry::BaselineProfile) -> bool {
        match self {
            Self::Unavailable => false,
            Self::Unconfigured => true,
            Self::Active {
                enabled_profiles, ..
            } => {
                enabled_profiles.as_slice().len() <= 1
                    && enabled_profiles
                        .as_slice()
                        .iter()
                        .all(|reference| *reference == profile.reference())
            }
        }
    }
}

impl RuntimeManifest {
    pub fn linux(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
    ) -> Result<Self, String> {
        Self::linux_selected(version, source_commit, target, components, false)
    }

    pub fn linux_selected(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
        private_tcp: bool,
    ) -> Result<Self, String> {
        if private_tcp
            && !matches!(
                target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
        {
            return Err("private TCP requires a selected native GNU target".into());
        }
        Self::selected(
            version,
            source_commit,
            target,
            components,
            SealedRuntime::Included {
                agent_component: "sealed-agent".into(),
                native_protocols: NativeProviderProtocols::Linux {
                    provider_contract: 3,
                    launch_wire: 3,
                },
                mechanism: "linux-pid-namespace-cgroup-v2".into(),
                workload_contract_schema: if private_tcp { 2 } else { 1 },
                profile_catalog_sha256: if private_tcp {
                    String::from(crate::workload_discovery_v2::profile_catalog_digest_v2())
                } else {
                    baseline_catalog_digest(false)
                },
                profiles: if private_tcp {
                    vec![
                        "linux-unix-create-v1".into(),
                        "linux-tcp4-private-v1".into(),
                    ]
                } else {
                    vec!["linux-unix-create-v1".into()]
                },
            },
        )
    }

    pub fn windows(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
    ) -> Result<Self, String> {
        Self::selected(
            version,
            source_commit,
            target,
            components,
            SealedRuntime::Included {
                agent_component: "sealed-agent".into(),
                native_protocols: NativeProviderProtocols::Windows {
                    provider_contract: 3,
                    public_wire: 3,
                    private_wire: 3,
                },
                mechanism: "windows-job-object-v2".into(),
                workload_contract_schema: 1,
                profile_catalog_sha256: baseline_catalog_digest(true),
                profiles: vec!["windows-host-network-external-v1".into()],
            },
        )
    }

    pub fn cli_only(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
    ) -> Result<Self, String> {
        Self::selected(
            version,
            source_commit,
            target,
            components,
            SealedRuntime::NotIncluded,
        )
    }

    fn selected(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
        sealed: SealedRuntime,
    ) -> Result<Self, String> {
        let manifest = Self {
            format: RUNTIME_MANIFEST_FORMAT.into(),
            revision: RUNTIME_MANIFEST_REVISION,
            project: "memcordon".into(),
            version,
            source_commit,
            target,
            components,
            sealed,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("runtime manifest exceeds bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn public_binding(&self, bytes: &[u8]) -> Result<crate::PublicProviderBindingV1, String> {
        if Self::parse(bytes)? != *self {
            return Err("runtime binding differs from pinned manifest bytes".into());
        }
        let binding = crate::PublicProviderBindingV1 {
            generation: crate::BoundedText::new(&format!(
                "{}:{}",
                self.version, self.source_commit
            ))
            .map_err(str::to_owned)?,
            source_commit: crate::BoundedText::new(&self.source_commit).map_err(str::to_owned)?,
            runtime_manifest_sha256: crate::workload_codec::hash_bytes(bytes),
        };
        if !binding.is_consistent() {
            return Err("invalid runtime provider identity".into());
        }
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), String> {
        use RuntimeComponentRole::*;
        let version = semver::Version::parse(&self.version).map_err(|error| error.to_string())?;
        if self.format != RUNTIME_MANIFEST_FORMAT
            || self.revision != RUNTIME_MANIFEST_REVISION
            || self.project != "memcordon"
            || version.to_string() != self.version
            || self.version.len() > 64
            || !valid_hash(&self.source_commit, std::mem::size_of::<[u8; 20]>())
            || self.components.is_empty()
            || self.components.len() > 5
            || serde_json::to_vec(self).map_or(true, |bytes| {
                bytes.len() > crate::workload_limits::PUBLIC_OBJECT_BYTES
            })
        {
            return Err("runtime manifest format, identity or size differs".into());
        }
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
        if !(linux || windows || macos) {
            return Err("runtime target is outside the selected native set".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        let mut roles = std::collections::BTreeSet::new();
        for component in &self.components {
            let basename = match component.role {
                PublicCli => {
                    if windows {
                        "memcordon.exe"
                    } else {
                        "memcordon"
                    }
                }
                SealedAgent => {
                    if windows {
                        "memcordon-sealed-agent.exe"
                    } else {
                        "memcordon-sealed-agent"
                    }
                }
                DesktopBootstrap => "memcordon-target-desktop-bootstrap.exe",
                SessionBroker => "memcordon-session-broker.exe",
                Arm32AbiHelper => "memcordon-arm32-abi-helper",
            };
            if component.id.is_empty()
                || component.id.len() > 128
                || !component
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                || !ids.insert(&component.id)
                || !paths.insert(component.path.to_ascii_lowercase())
                || !roles.insert(component.role)
                || component.path != basename
                || component.size == 0
                || component.mode != 0o755
                || !valid_hash(&component.sha256, std::mem::size_of::<[u8; 32]>())
            {
                return Err("runtime component identity differs".into());
            }
        }
        match &self.sealed {
            SealedRuntime::NotIncluded
                if roles == std::collections::BTreeSet::from([PublicCli]) => {}
            SealedRuntime::Included {
                agent_component,
                native_protocols,
                mechanism,
                workload_contract_schema,
                profile_catalog_sha256,
                profiles,
            } => {
                let private_tcp = linux
                    && *workload_contract_schema == 2
                    && matches!(
                        self.target.as_str(),
                        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
                    )
                    && profiles.as_slice() == ["linux-unix-create-v1", "linux-tcp4-private-v1"];
                let matching_protocol = match native_protocols {
                    NativeProviderProtocols::Linux {
                        provider_contract: 3,
                        launch_wire: 3,
                    } => {
                        linux
                            && mechanism == "linux-pid-namespace-cgroup-v2"
                            && (profiles.as_slice() == ["linux-unix-create-v1"] || private_tcp)
                    }
                    NativeProviderProtocols::Windows {
                        provider_contract: 3,
                        public_wire: 3,
                        private_wire: 3,
                    } => {
                        windows
                            && mechanism == "windows-job-object-v2"
                            && profiles.as_slice() == ["windows-host-network-external-v1"]
                    }
                    _ => false,
                };
                let expected = if windows {
                    std::collections::BTreeSet::from([
                        PublicCli,
                        SealedAgent,
                        DesktopBootstrap,
                        SessionBroker,
                    ])
                } else {
                    let mut expected = std::collections::BTreeSet::from([PublicCli, SealedAgent]);
                    if self.target == "aarch64-unknown-linux-gnu" && roles.contains(&Arm32AbiHelper)
                    {
                        expected.insert(Arm32AbiHelper);
                    }
                    expected
                };
                if !matching_protocol
                    || !(*workload_contract_schema == 1 || private_tcp)
                    || roles != expected
                    || profile_catalog_sha256
                        != &if private_tcp {
                            String::from(crate::workload_discovery_v2::profile_catalog_digest_v2())
                        } else {
                            baseline_catalog_digest(windows)
                        }
                    || !self.components.iter().any(|component| {
                        component.id == *agent_component && component.role == SealedAgent
                    })
                {
                    return Err("selected provider protocol or actual components differ".into());
                }
            }
            _ => return Err("runtime selection differs from actual components".into()),
        }
        Ok(())
    }
}

fn valid_hash(value: &str, byte_width: usize) -> bool {
    value.len() == byte_width * 2
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
