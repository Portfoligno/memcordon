//! Exact workload functionality and independent administrator authority.
use std::num::{NonZeroU16, NonZeroU64};

use crate::workload_limits as limits;
use crate::{BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LogicalId(String);
impl LogicalId {
    pub fn new(value: String) -> Result<Self, String> {
        if value.is_empty()
            || value.len() > limits::IDENTIFIER_BYTES
            || value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("invalid workload logical identifier".into());
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for LogicalId {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let text = crate::BoundedText::<{ limits::IDENTIFIER_BYTES }>::deserialize(decoder)?;
        Self::new(text.as_str().to_owned()).map_err(serde::de::Error::custom)
    }
}

pub type ProfileId = LogicalId;
pub type RequirementId = LogicalId;
pub type EndpointId = LogicalId;
pub type GrantId = LogicalId;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce128(pub [u8; 16]);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEpoch {
    pub service_instance: Nonce128,
    pub revision: NonZeroU64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRef {
    pub id: ProfileId,
    pub semantic_digest: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRef {
    pub grant_id: GrantId,
    pub grant_revision: NonZeroU64,
    pub approved_plan_digest: DiagnosticSha256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirectSocketCeiling {
    PinnedLegacySocketFilterAccepted,
    NoNewInetSockets,
    AttemptPrivateIpv4StackAllPorts,
    ExternalHostPolicyAccepted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnixAuthorityCeiling {
    NoNamedEndpointsSocketPairsOnly,
    ExistingHostUnixAuthorityAccepted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalSocketCeiling {
    NoSocketAtTargetEntry,
    ExistingStdioAuthorityAccepted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialGainCeiling {
    NoGain,
    ExistingCallerEnvelopeAccepted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MediatedCommunicationCeiling {
    ExternalFilesystemAndStdioPolicyAccepted,
    RequireNoExternalCommunication,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCeilingV1 {
    pub direct_socket_authority: DirectSocketCeiling,
    pub unix_authority: UnixAuthorityCeiling,
    pub external_socket_custody: ExternalSocketCeiling,
    pub credential_gains: CredentialGainCeiling,
    pub mediated_communication: MediatedCommunicationCeiling,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnixSocketKind {
    Stream,
    Datagram,
    SeqPacket,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpFamily {
    V4,
    V6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpScope {
    AttemptPrivateStack,
    HostSharedLoopback,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpOperation {
    Create,
    Bind,
    Listen,
    Accept,
    Connect,
    StreamRead,
    StreamWrite,
}
impl TcpOperation {
    pub fn tag(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::Bind => 2,
            Self::Listen => 3,
            Self::Accept => 4,
            Self::Connect => 5,
            Self::StreamRead => 6,
            Self::StreamWrite => 7,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TcpOperations(BoundedVec<TcpOperation, 7>);
impl TcpOperations {
    pub fn new(operations: BoundedVec<TcpOperation, 7>) -> Result<Self, String> {
        let values = operations.as_slice();
        let has = |operation| values.contains(&operation);
        if values.is_empty()
            || values
                .iter()
                .enumerate()
                .any(|(index, value)| values[..index].contains(value))
            || (has(TcpOperation::Listen) && !has(TcpOperation::Bind))
            || (has(TcpOperation::Accept) && !has(TcpOperation::Listen))
            || ((has(TcpOperation::StreamRead) || has(TcpOperation::StreamWrite))
                && !(has(TcpOperation::Accept) || has(TcpOperation::Connect)))
        {
            return Err("contradictory or duplicate TCP operation set".into());
        }
        Ok(Self(operations))
    }
    pub fn as_slice(&self) -> &[TcpOperation] {
        self.0.as_slice()
    }
}
impl<'de> Deserialize<'de> for TcpOperations {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        Self::new(BoundedVec::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LocalPortRequirement {
    KernelAssigned,
    Exact { port: NonZeroU16 },
    InclusiveRange { first: NonZeroU16, last: NonZeroU16 },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TcpEndpoint {
    V4 { address: [u8; 4], port: NonZeroU16 },
    V6 { address: [u8; 16], port: NonZeroU16 },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TcpPeerRequirement {
    SameAttemptEndpoint { endpoint: EndpointId },
    ExactAddress { endpoint: TcpEndpoint },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeniedOperation {
    InetSocketCreation,
    NamedUnixSocketCreation,
    ExternalSocketImport,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RequirementV1 {
    UnixSocketCreation {
        id: RequirementId,
        socket_kind: UnixSocketKind,
    },
    UnixSocketPair {
        id: RequirementId,
        socket_kind: UnixSocketKind,
    },
    Tcp {
        id: RequirementId,
        family: IpFamily,
        operations: TcpOperations,
        scope: TcpScope,
        local_ports: LocalPortRequirement,
        peer: TcpPeerRequirement,
    },
    SuppliedTcpListener {
        id: RequirementId,
        endpoint: EndpointId,
        scope: TcpScope,
    },
    DenialExercise {
        id: RequirementId,
        operation: DeniedOperation,
    },
}
impl RequirementV1 {
    pub fn id(&self) -> &RequirementId {
        match self {
            Self::UnixSocketCreation { id, .. }
            | Self::UnixSocketPair { id, .. }
            | Self::Tcp { id, .. }
            | Self::SuppliedTcpListener { id, .. }
            | Self::DenialExercise { id, .. } => id,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointDeclarationV1 {
    pub id: EndpointId,
    pub requirement: RequirementId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ContractVersionOne(u16);
impl Default for ContractVersionOne {
    fn default() -> Self {
        Self(1)
    }
}
impl<'de> Deserialize<'de> for ContractVersionOne {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        if u16::deserialize(decoder)? != 1 {
            return Err(serde::de::Error::custom(
                "unsupported workload contract version",
            ));
        }
        Ok(Self::default())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadContractV1 {
    pub schema_version: ContractVersionOne,
    pub workload_plan_digest: DiagnosticSha256,
    pub authorized_profile: ProfileRef,
    pub authorization: AuthorizationRef,
    pub ceiling: NetworkCeilingV1,
    pub requirements: BoundedVec<RequirementV1, { limits::REQUIREMENTS }>,
    pub endpoints: BoundedVec<EndpointDeclarationV1, { limits::ENDPOINTS }>,
    pub expected_epoch: PolicyEpoch,
}

impl WorkloadContractV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > limits::CONTRACT_BYTES {
            return Err("workload contract exceeds byte limit".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let request: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.workload_plan_digest != self.authorization.approved_plan_digest {
            return Err("authorization and workload plan digests differ".into());
        }
        let requirements = self.requirements.as_slice();
        let endpoints = self.endpoints.as_slice();
        for (index, requirement) in requirements.iter().enumerate() {
            if requirements[..index]
                .iter()
                .any(|prior| prior.id() == requirement.id())
            {
                return Err("duplicate workload requirement identifier".into());
            }
            if let RequirementV1::Tcp {
                local_ports: LocalPortRequirement::InclusiveRange { first, last },
                ..
            } = requirement
            {
                if first > last {
                    return Err("inverted TCP port range".into());
                }
            }
            if let RequirementV1::Tcp {
                family,
                peer: TcpPeerRequirement::ExactAddress { endpoint },
                ..
            } = requirement
            {
                if !matches!(
                    (family, endpoint),
                    (IpFamily::V4, TcpEndpoint::V4 { .. }) | (IpFamily::V6, TcpEndpoint::V6 { .. })
                ) {
                    return Err("TCP family differs from exact peer family".into());
                }
            }
            let referenced = match requirement {
                RequirementV1::Tcp {
                    peer: TcpPeerRequirement::SameAttemptEndpoint { endpoint },
                    ..
                }
                | RequirementV1::SuppliedTcpListener { endpoint, .. } => Some(endpoint),
                _ => None,
            };
            if let Some(reference) = referenced {
                if !endpoints.iter().any(|endpoint| &endpoint.id == reference) {
                    return Err("unresolved workload endpoint".into());
                }
            }
        }
        for (index, endpoint) in endpoints.iter().enumerate() {
            if endpoints[..index]
                .iter()
                .any(|prior| prior.id == endpoint.id)
                || !requirements
                    .iter()
                    .any(|requirement| requirement.id() == &endpoint.requirement)
            {
                return Err("duplicate or unresolved endpoint declaration".into());
            }
            let owner = requirements
                .iter()
                .find(|requirement| requirement.id() == &endpoint.requirement)
                .ok_or("unresolved endpoint owner")?;
            let RequirementV1::Tcp {
                family: owner_family,
                scope: owner_scope,
                operations,
                ..
            } = owner
            else {
                return Err("declared endpoint owner is not a TCP listener".into());
            };
            if !operations.as_slice().contains(&TcpOperation::Listen) {
                return Err("declared endpoint owner does not require listen".into());
            }
            for requirement in requirements {
                if let RequirementV1::Tcp {
                    family,
                    scope,
                    peer:
                        TcpPeerRequirement::SameAttemptEndpoint {
                            endpoint: reference,
                        },
                    ..
                } = requirement
                {
                    if reference == &endpoint.id && (family != owner_family || scope != owner_scope)
                    {
                        return Err("endpoint peer family or scope differs".into());
                    }
                }
            }
            let mut visited = Vec::with_capacity(limits::ENDPOINTS);
            let mut current = endpoint;
            loop {
                if visited.contains(&current.id) {
                    return Err("cyclic endpoint dependencies".into());
                }
                visited.push(current.id.clone());
                let requirement = requirements
                    .iter()
                    .find(|requirement| requirement.id() == &current.requirement)
                    .ok_or("unresolved endpoint owner")?;
                let next = match requirement {
                    RequirementV1::Tcp {
                        peer: TcpPeerRequirement::SameAttemptEndpoint { endpoint },
                        ..
                    } => endpoint,
                    _ => break,
                };
                current = endpoints
                    .iter()
                    .find(|endpoint| &endpoint.id == next)
                    .ok_or("unresolved endpoint dependency")?;
            }
        }
        Ok(())
    }
}

/// A bounded first pass rejects duplicates even inside internally tagged enums,
/// whose serde buffering otherwise loses duplicate unknown-key information.
pub fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<(), String> {
    use serde::de::{MapAccess, SeqAccess, Visitor};
    struct Unique;
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            struct Check;
            impl<'de> Visitor<'de> for Check {
                type Value = Unique;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("JSON with unique object keys")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                    let mut keys = std::collections::BTreeSet::new();
                    while let Some(key) = map.next_key::<crate::BoundedText<256>>()? {
                        if keys.len() >= 256 {
                            return Err(serde::de::Error::custom(
                                "JSON object key count exceeds bound",
                            ));
                        }
                        if !keys.insert(key.as_str().to_owned()) {
                            return Err(serde::de::Error::custom("duplicate JSON key"));
                        }
                        map.next_value::<Unique>()?;
                    }
                    Ok(Unique)
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Unique, A::Error> {
                    while sequence.next_element::<Unique>()?.is_some() {}
                    Ok(Unique)
                }
                fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique)
                }
            }
            decoder.deserialize_any(Check)
        }
    }
    serde_json::from_slice::<Unique>(bytes)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
