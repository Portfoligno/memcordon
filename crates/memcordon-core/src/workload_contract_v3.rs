//! Combined private TCP/Unix requests. These values describe requests, never live authority.
use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::workload_codec::{Encoder, hash_bytes};
use crate::workload_contract::{
    AuthorizationRef, LogicalId, PolicyEpoch, ProfileRef, reject_duplicate_json_keys,
};
use crate::{BoundedVec, DiagnosticSha256};

pub const PROFILE: &str = "linux-tcp4-unix-private-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ContractVersionThree(u16);

impl ContractVersionThree {
    pub fn new() -> Self {
        Self(3)
    }
}

impl Default for ContractVersionThree {
    fn default() -> Self {
        Self::new()
    }
}

impl<'de> Deserialize<'de> for ContractVersionThree {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if u16::deserialize(deserializer)? == 3 {
            Ok(Self::new())
        } else {
            Err(serde::de::Error::custom(
                "expected workload contract version three",
            ))
        }
    }
}

/// A path in the constructed target root, deliberately distinct from a host path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RootRelativePath(String);

impl RootRelativePath {
    pub fn new(value: String) -> Result<Self, String> {
        if value.is_empty()
            || value.len() > 4096
            || value.starts_with('/')
            || value.as_bytes().contains(&0)
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("invalid target-root-relative path".into());
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RootRelativePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundObjectRef {
    pub id: LogicalId,
    pub digest: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExclusiveAdministratorIdentityRef {
    pub identity: BoundObjectRef,
    pub exclusive_use_policy: BoundObjectRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MixedPrivateCeiling {
    /// All IPv4 TCP addresses reachable in the loopback-only private stack;
    /// Unix streams and descriptor transfer only within the fresh attempt root.
    FreshRootIpv4TcpUnixStreamsIntraAttemptNoGain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    tag = "kind",
    content = "port",
    deny_unknown_fields
)]
pub enum LocalPortV3 {
    KernelAssigned,
    Exact(std::num::NonZeroU16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    tag = "kind",
    content = "port",
    deny_unknown_fields
)]
pub enum PrivatePeerV3 {
    DynamicLoopbackWithinThisAttempt,
    ExactLoopbackEndpoint(std::num::NonZeroU16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeniedOperationV3 {
    HostTcp,
    HostUnixPath,
    HostUnixAbstract,
    OtherAttempt,
    Inet6,
    Udp,
    Raw,
    Packet,
    Netlink,
    NamespaceEntry,
    ProcessImport,
    PrivilegeGain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum RequirementV3 {
    TcpListener {
        id: LogicalId,
        local_port: LocalPortV3,
        peer: PrivatePeerV3,
    },
    UnixStreamPair {
        id: LogicalId,
    },
    UnixPathStream {
        id: LogicalId,
        writable_root: LogicalId,
    },
    UnixAbstractStream {
        id: LogicalId,
    },
    IntraAttemptDescriptorTransfer {
        id: LogicalId,
    },
    GeneratedExecutable {
        id: LogicalId,
        writable_root: LogicalId,
    },
    ExpectedDenial {
        id: LogicalId,
        operation: DeniedOperationV3,
    },
}

impl RequirementV3 {
    pub fn id(&self) -> &LogicalId {
        match self {
            Self::TcpListener { id, .. }
            | Self::UnixStreamPair { id }
            | Self::UnixPathStream { id, .. }
            | Self::UnixAbstractStream { id }
            | Self::IntraAttemptDescriptorTransfer { id }
            | Self::GeneratedExecutable { id, .. }
            | Self::ExpectedDenial { id, .. } => id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageLaunchV1 {
    pub entrypoint: LogicalId,
    pub working_directory: RootRelativePath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadContractV3 {
    pub schema_version: ContractVersionThree,
    pub workload_plan_digest: DiagnosticSha256,
    pub authorized_profile: ProfileRef,
    pub authorization: AuthorizationRef,
    pub ceiling: MixedPrivateCeiling,
    pub requirements: BoundedVec<RequirementV3, 64>,
    pub execution_identity: ExclusiveAdministratorIdentityRef,
    pub runtime_image: BoundObjectRef,
    pub input_image: BoundObjectRef,
    pub root_layout: BoundObjectRef,
    pub launch: ImageLaunchV1,
    pub expected_epoch: PolicyEpoch,
}

impl WorkloadContractV3 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::workload_limits::CONTRACT_BYTES {
            return Err("workload contract exceeds byte limit".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.workload_plan_digest != self.authorization.approved_plan_digest {
            return Err("workload plan differs from the authorized plan".into());
        }
        if self.schema_version != ContractVersionThree::new()
            || self.authorized_profile.id.as_str() != PROFILE
        {
            return Err("V3 requires the exact combined profile version".into());
        }
        let mut ids = BTreeSet::new();
        for requirement in self.requirements.as_slice() {
            if !ids.insert(requirement.id()) {
                return Err("duplicate V3 requirement id".into());
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut encoder = Encoder::new(
            b"memcordon.workload-contract/version3",
            crate::workload_limits::CONTRACT_BYTES,
        )?;
        encoder.u16(3)?;
        encoder.digest(&self.workload_plan_digest)?;
        encoder.id(&self.authorized_profile.id)?;
        encoder.digest(&self.authorized_profile.semantic_digest)?;
        encoder.id(&self.authorization.grant_id)?;
        encoder.u64(self.authorization.grant_revision.get())?;
        encoder.digest(&self.authorization.approved_plan_digest)?;
        encoder.byte(1)?;
        for object in [
            &self.execution_identity.identity,
            &self.execution_identity.exclusive_use_policy,
            &self.runtime_image,
            &self.input_image,
            &self.root_layout,
        ] {
            encoder.id(&object.id)?;
            encoder.digest(&object.digest)?;
        }
        encoder.id(&self.launch.entrypoint)?;
        encode_text(&mut encoder, self.launch.working_directory.as_str())?;
        encoder.raw(&self.expected_epoch.service_instance.0)?;
        encoder.u64(self.expected_epoch.revision.get())?;
        let mut requirements: Vec<_> = self.requirements.as_slice().iter().collect();
        requirements.sort_by_key(|item| item.id());
        encoder.count(requirements.len())?;
        for requirement in requirements {
            encoder.id(requirement.id())?;
            match requirement {
                RequirementV3::TcpListener {
                    local_port, peer, ..
                } => {
                    encoder.byte(1)?;
                    match local_port {
                        LocalPortV3::KernelAssigned => encoder.byte(1)?,
                        LocalPortV3::Exact(port) => {
                            encoder.byte(2)?;
                            encoder.u16(port.get())?;
                        }
                    }
                    match peer {
                        PrivatePeerV3::DynamicLoopbackWithinThisAttempt => encoder.byte(1)?,
                        PrivatePeerV3::ExactLoopbackEndpoint(port) => {
                            encoder.byte(2)?;
                            encoder.u16(port.get())?;
                        }
                    }
                }
                RequirementV3::UnixStreamPair { .. } => encoder.byte(2)?,
                RequirementV3::UnixPathStream { writable_root, .. } => {
                    encoder.byte(3)?;
                    encoder.id(writable_root)?;
                }
                RequirementV3::UnixAbstractStream { .. } => encoder.byte(4)?,
                RequirementV3::IntraAttemptDescriptorTransfer { .. } => encoder.byte(5)?,
                RequirementV3::GeneratedExecutable { writable_root, .. } => {
                    encoder.byte(6)?;
                    encoder.id(writable_root)?;
                }
                RequirementV3::ExpectedDenial { operation, .. } => {
                    encoder.byte(7)?;
                    encoder.byte(match operation {
                        DeniedOperationV3::HostTcp => 1,
                        DeniedOperationV3::HostUnixPath => 2,
                        DeniedOperationV3::HostUnixAbstract => 3,
                        DeniedOperationV3::OtherAttempt => 4,
                        DeniedOperationV3::Inet6 => 5,
                        DeniedOperationV3::Udp => 6,
                        DeniedOperationV3::Raw => 7,
                        DeniedOperationV3::Packet => 8,
                        DeniedOperationV3::Netlink => 9,
                        DeniedOperationV3::NamespaceEntry => 10,
                        DeniedOperationV3::ProcessImport => 11,
                        DeniedOperationV3::PrivilegeGain => 12,
                    })?;
                }
            }
        }
        Ok(encoder.finish())
    }
    pub fn digest(&self) -> Result<DiagnosticSha256, String> {
        Ok(hash_bytes(&self.canonical_bytes()?))
    }
}

pub fn encode_text(encoder: &mut Encoder, text: &str) -> Result<(), String> {
    encoder.count(text.len())?;
    encoder.raw(text.as_bytes())
}
