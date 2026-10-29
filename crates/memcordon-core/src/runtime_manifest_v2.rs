//! Current installed inventory. Describes bytes and supported interfaces, never workload permission.
use crate::runtime_components::{
    NativeProviderProtocols, RuntimeComponentRecord, RuntimeComponentRole,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireVersion {
    pub format: String,
    pub revision: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "selection", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SealedRuntimeV2 {
    CredentialPreservingLinux {
        agent_component: String,
        native_protocols: NativeProviderProtocols,
        mechanism: String,
    },
    Included {
        agent_component: String,
        native_protocols: NativeProviderProtocols,
        mechanism: String,
        workload_request: WireVersion,
        result: WireVersion,
        profile: String,
        profile_revision: u32,
    },
    NotIncluded,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifestV2 {
    pub format: String,
    pub revision: u32,
    pub project: String,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub components: Vec<RuntimeComponentRecord>,
    pub sealed: SealedRuntimeV2,
}
impl RuntimeManifestV2 {
    pub fn cli_only(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
    ) -> Result<Self, String> {
        let manifest = Self {
            format: "memcordon.runtime-manifest".into(),
            revision: 2,
            project: "memcordon".into(),
            version,
            source_commit,
            target,
            components,
            sealed: SealedRuntimeV2::NotIncluded,
        };
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn linux(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
        private: bool,
    ) -> Result<Self, String> {
        let sealed = if private {
            SealedRuntimeV2::Included {
                agent_component: "sealed-agent".into(),
                native_protocols: NativeProviderProtocols::Linux {
                    provider_contract: 3,
                    launch_wire: 5,
                },
                mechanism: "linux-private-workload-v1".into(),
                workload_request: WireVersion {
                    format: "memcordon.workload-request".into(),
                    revision: 1,
                },
                result: WireVersion {
                    format: "memcordon.result".into(),
                    revision: 3,
                },
                profile: "linux-private-workload-v1".into(),
                profile_revision: 1,
            }
        } else {
            SealedRuntimeV2::CredentialPreservingLinux {
                agent_component: "sealed-agent".into(),
                native_protocols: NativeProviderProtocols::Linux {
                    provider_contract: 3,
                    launch_wire: 3,
                },
                mechanism: "linux-pid-namespace-cgroup-v2".into(),
            }
        };
        let manifest = Self {
            format: "memcordon.runtime-manifest".into(),
            revision: 2,
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
    pub fn windows(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
    ) -> Result<Self, String> {
        let manifest = Self {
            format: "memcordon.runtime-manifest".into(),
            revision: 2,
            project: "memcordon".into(),
            version,
            source_commit,
            target,
            components,
            sealed: SealedRuntimeV2::Included {
                agent_component: "sealed-agent".into(),
                native_protocols: NativeProviderProtocols::Windows {
                    provider_contract: 4,
                    public_wire: 4,
                    private_wire: 4,
                },
                mechanism: "windows-job-object-v2".into(),
                workload_request: WireVersion {
                    format: "memcordon.workload-request".into(),
                    revision: 1,
                },
                result: WireVersion {
                    format: "memcordon.result".into(),
                    revision: 3,
                },
                profile: "windows-sealed-current-token-v1".into(),
                profile_revision: 1,
            },
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn public_binding(&self, bytes: &[u8]) -> Result<crate::PublicProviderBindingV1, String> {
        if Self::parse(bytes)? != *self {
            return Err("runtime binding differs from pinned current manifest bytes".into());
        }
        let binding = crate::PublicProviderBindingV1 {
            generation: crate::BoundedText::new(&format!(
                "{}:{}",
                self.version, self.source_commit
            ))
            .map_err(str::to_owned)?,
            source_commit: crate::BoundedText::new(&self.source_commit).map_err(str::to_owned)?,
            runtime_manifest_sha256: crate::hash_bytes(bytes),
        };
        if !binding.is_consistent() {
            return Err("invalid current runtime provider identity".into());
        }
        Ok(binding)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 1024 * 1024 {
            return Err("runtime inventory exceeds byte ceiling".into());
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        fn hash(value: &str) -> bool {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        if self.format != "memcordon.runtime-manifest"
            || self.revision != 2
            || self.project != "memcordon"
            || self.version.is_empty()
            || self.source_commit.len() != 40
            || !self.source_commit.bytes().all(|b| b.is_ascii_hexdigit())
            || self.components.len() > 16
        {
            return Err("invalid runtime manifest header".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        for component in &self.components {
            crate::workload_request::RootRelativePath::new(component.path.clone())?;
            if !ids.insert(&component.id)
                || !paths.insert(&component.path)
                || !hash(&component.sha256)
                || component.size == 0
                || component.mode & !0o777 != 0
            {
                return Err("invalid runtime component".into());
            }
        }
        if !self
            .components
            .iter()
            .any(|c| c.role == RuntimeComponentRole::PublicCli)
        {
            return Err("runtime lacks public CLI".into());
        }
        if let SealedRuntimeV2::CredentialPreservingLinux {
            agent_component,
            native_protocols,
            mechanism,
        } = &self.sealed
        {
            if !self
                .components
                .iter()
                .any(|c| &c.id == agent_component && c.role == RuntimeComponentRole::SealedAgent)
                || !matches!(
                    native_protocols,
                    NativeProviderProtocols::Linux {
                        provider_contract: 3,
                        launch_wire: 3
                    }
                )
                || !self.target.contains("-linux-")
                || mechanism != "linux-pid-namespace-cgroup-v2"
            {
                return Err("invalid ordinary Linux sealed component selection".into());
            }
        }
        if let SealedRuntimeV2::Included {
            agent_component,
            native_protocols,
            workload_request,
            result,
            profile,
            profile_revision,
            mechanism,
        } = &self.sealed
        {
            if !self
                .components
                .iter()
                .any(|c| &c.id == agent_component && c.role == RuntimeComponentRole::SealedAgent)
                || workload_request.format != "memcordon.workload-request"
                || workload_request.revision != 1
                || result.format != "memcordon.result"
                || result.revision != 3
                || *profile_revision != 1
            {
                return Err("invalid installed request/result association".into());
            }
            match native_protocols {
                NativeProviderProtocols::Linux {
                    provider_contract: 3,
                    launch_wire: 5,
                } if profile == "linux-private-workload-v1"
                    && mechanism == "linux-private-workload-v1"
                    && matches!(
                        self.target.as_str(),
                        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
                    ) => {}
                NativeProviderProtocols::Windows {
                    provider_contract: 4,
                    public_wire: 4,
                    private_wire: 4,
                } if profile == "windows-sealed-current-token-v1"
                    && mechanism == "windows-job-object-v2"
                    && matches!(
                        self.target.as_str(),
                        "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc"
                    ) => {}
                _ => return Err("installed profile/provider version mismatch".into()),
            }
        }
        Ok(())
    }
}
