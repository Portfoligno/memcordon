//! V1 canonical bytes: explicit domains/tags and big-endian lengths and integers.
use crate::DiagnosticSha256;
use crate::workload_contract::*;
use sha2::{Digest, Sha256};

pub struct Encoder {
    bytes: Vec<u8>,
    limit: usize,
}
impl Encoder {
    pub fn new(domain: &[u8], limit: usize) -> Result<Self, String> {
        let mut encoder = Self {
            bytes: Vec::new(),
            limit,
        };
        encoder.raw(domain)?;
        encoder.byte(0)?;
        encoder.u16(1)?;
        Ok(encoder)
    }
    pub fn raw(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err("canonical workload value exceeds limit".into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub fn byte(&mut self, value: u8) -> Result<(), String> {
        self.raw(&[value])
    }
    pub fn u16(&mut self, value: u16) -> Result<(), String> {
        self.raw(&value.to_be_bytes())
    }
    pub fn u64(&mut self, value: u64) -> Result<(), String> {
        self.raw(&value.to_be_bytes())
    }
    pub fn count(&mut self, value: usize) -> Result<(), String> {
        self.u16(u16::try_from(value).map_err(|_| "canonical count exceeds u16")?)
    }
    pub fn id(&mut self, value: &LogicalId) -> Result<(), String> {
        self.count(value.as_str().len())?;
        self.raw(value.as_str().as_bytes())
    }
    pub fn digest(&mut self, value: &DiagnosticSha256) -> Result<(), String> {
        self.raw(value.bytes())
    }
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub fn encode_ceiling(encoder: &mut Encoder, ceiling: &NetworkCeilingV1) -> Result<(), String> {
    encoder.byte(match ceiling.direct_socket_authority {
        DirectSocketCeiling::PinnedLegacySocketFilterAccepted => 1,
        DirectSocketCeiling::NoNewInetSockets => 2,
        DirectSocketCeiling::AttemptPrivateIpv4StackAllPorts => 3,
        DirectSocketCeiling::ExternalHostPolicyAccepted => 4,
    })?;
    encoder.byte(match ceiling.unix_authority {
        UnixAuthorityCeiling::NoNamedEndpointsSocketPairsOnly => 1,
        UnixAuthorityCeiling::ExistingHostUnixAuthorityAccepted => 2,
    })?;
    encoder.byte(match ceiling.external_socket_custody {
        ExternalSocketCeiling::NoSocketAtTargetEntry => 1,
        ExternalSocketCeiling::ExistingStdioAuthorityAccepted => 2,
    })?;
    encoder.byte(match ceiling.credential_gains {
        CredentialGainCeiling::NoGain => 1,
        CredentialGainCeiling::ExistingCallerEnvelopeAccepted => 2,
    })?;
    encoder.byte(match ceiling.mediated_communication {
        MediatedCommunicationCeiling::ExternalFilesystemAndStdioPolicyAccepted => 1,
        MediatedCommunicationCeiling::RequireNoExternalCommunication => 2,
    })
}

fn scope(encoder: &mut Encoder, value: TcpScope) -> Result<(), String> {
    encoder.byte(match value {
        TcpScope::AttemptPrivateStack => 1,
        TcpScope::HostSharedLoopback => 2,
    })
}
fn unix_kind(encoder: &mut Encoder, value: UnixSocketKind) -> Result<(), String> {
    encoder.byte(match value {
        UnixSocketKind::Stream => 1,
        UnixSocketKind::Datagram => 2,
        UnixSocketKind::SeqPacket => 3,
    })
}
fn requirement(encoder: &mut Encoder, value: &RequirementV1) -> Result<(), String> {
    encoder.byte(match value {
        RequirementV1::UnixSocketCreation { .. } => 1,
        RequirementV1::UnixSocketPair { .. } => 2,
        RequirementV1::Tcp { .. } => 3,
        RequirementV1::SuppliedTcpListener { .. } => 4,
        RequirementV1::DenialExercise { .. } => 5,
    })?;
    encoder.id(value.id())?;
    match value {
        RequirementV1::UnixSocketCreation { socket_kind, .. }
        | RequirementV1::UnixSocketPair { socket_kind, .. } => unix_kind(encoder, *socket_kind),
        RequirementV1::Tcp {
            family,
            operations,
            scope: tcp_scope,
            local_ports,
            peer,
            ..
        } => {
            encoder.byte(match family {
                IpFamily::V4 => 1,
                IpFamily::V6 => 2,
            })?;
            let mut operations = operations.as_slice().to_vec();
            operations.sort_by_key(|operation| operation.tag());
            encoder.count(operations.len())?;
            for operation in operations {
                encoder.byte(operation.tag())?;
            }
            scope(encoder, *tcp_scope)?;
            match local_ports {
                LocalPortRequirement::KernelAssigned => encoder.byte(1)?,
                LocalPortRequirement::Exact { port } => {
                    encoder.byte(2)?;
                    encoder.u16(port.get())?;
                }
                LocalPortRequirement::InclusiveRange { first, last } => {
                    encoder.byte(3)?;
                    encoder.u16(first.get())?;
                    encoder.u16(last.get())?;
                }
            }
            match peer {
                TcpPeerRequirement::SameAttemptEndpoint { endpoint } => {
                    encoder.byte(1)?;
                    encoder.id(endpoint)
                }
                TcpPeerRequirement::ExactAddress { endpoint } => {
                    encoder.byte(2)?;
                    match endpoint {
                        TcpEndpoint::V4 { address, port } => {
                            encoder.byte(1)?;
                            encoder.raw(address)?;
                            encoder.u16(port.get())
                        }
                        TcpEndpoint::V6 { address, port } => {
                            encoder.byte(2)?;
                            encoder.raw(address)?;
                            encoder.u16(port.get())
                        }
                    }
                }
            }
        }
        RequirementV1::SuppliedTcpListener {
            endpoint,
            scope: tcp_scope,
            ..
        } => {
            encoder.id(endpoint)?;
            scope(encoder, *tcp_scope)
        }
        RequirementV1::DenialExercise { operation, .. } => encoder.byte(match operation {
            DeniedOperation::InetSocketCreation => 1,
            DeniedOperation::NamedUnixSocketCreation => 2,
            DeniedOperation::ExternalSocketImport => 3,
        }),
    }
}

pub fn encode_contract(request: &WorkloadContractV1) -> Result<Vec<u8>, String> {
    request.validate()?;
    let mut encoder = Encoder::new(
        b"memcordon-workload-contract-v1",
        crate::workload_limits::CONTRACT_BYTES,
    )?;
    encoder.digest(&request.workload_plan_digest)?;
    encoder.id(&request.authorized_profile.id)?;
    encoder.digest(&request.authorized_profile.semantic_digest)?;
    encoder.id(&request.authorization.grant_id)?;
    encoder.u64(request.authorization.grant_revision.get())?;
    encoder.digest(&request.authorization.approved_plan_digest)?;
    encode_ceiling(&mut encoder, &request.ceiling)?;
    let mut requirements: Vec<_> = request.requirements.as_slice().iter().collect();
    requirements.sort_by_key(|value| value.id());
    encoder.count(requirements.len())?;
    for value in requirements {
        requirement(&mut encoder, value)?;
    }
    let mut endpoints: Vec<_> = request.endpoints.as_slice().iter().collect();
    endpoints.sort_by_key(|value| &value.id);
    encoder.count(endpoints.len())?;
    for endpoint in endpoints {
        encoder.id(&endpoint.id)?;
        encoder.id(&endpoint.requirement)?;
    }
    encoder.raw(&request.expected_epoch.service_instance.0)?;
    encoder.u64(request.expected_epoch.revision.get())?;
    Ok(encoder.finish())
}

pub fn hash_bytes(bytes: &[u8]) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes(Sha256::digest(bytes).into())
}

pub fn contract_digest(request: &WorkloadContractV1) -> Result<DiagnosticSha256, String> {
    encode_contract(request).map(|bytes| hash_bytes(&bytes))
}

struct Decoder<'a> {
    remaining: &'a [u8],
}
impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(count)
            .ok_or("truncated canonical workload")?;
        self.remaining = remaining;
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "invalid fixed canonical field".into())
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn id(&mut self) -> Result<LogicalId, String> {
        let count = usize::from(self.u16()?);
        LogicalId::new(
            std::str::from_utf8(self.take(count)?)
                .map_err(|_| "canonical id is not UTF-8")?
                .to_owned(),
        )
    }
    fn digest(&mut self) -> Result<DiagnosticSha256, String> {
        Ok(DiagnosticSha256::from_bytes(self.fixed()?))
    }
    fn port(&mut self) -> Result<std::num::NonZeroU16, String> {
        std::num::NonZeroU16::new(self.u16()?).ok_or("canonical port is zero".into())
    }
    fn revision(&mut self) -> Result<std::num::NonZeroU64, String> {
        std::num::NonZeroU64::new(self.u64()?).ok_or("canonical revision is zero".into())
    }
    fn unix_kind(&mut self) -> Result<UnixSocketKind, String> {
        match self.byte()? {
            1 => Ok(UnixSocketKind::Stream),
            2 => Ok(UnixSocketKind::Datagram),
            3 => Ok(UnixSocketKind::SeqPacket),
            _ => Err("unknown canonical UNIX kind".into()),
        }
    }
    fn scope(&mut self) -> Result<TcpScope, String> {
        match self.byte()? {
            1 => Ok(TcpScope::AttemptPrivateStack),
            2 => Ok(TcpScope::HostSharedLoopback),
            _ => Err("unknown canonical TCP scope".into()),
        }
    }
    fn ceiling(&mut self) -> Result<NetworkCeilingV1, String> {
        Ok(NetworkCeilingV1 {
            direct_socket_authority: match self.byte()? {
                1 => DirectSocketCeiling::PinnedLegacySocketFilterAccepted,
                2 => DirectSocketCeiling::NoNewInetSockets,
                3 => DirectSocketCeiling::AttemptPrivateIpv4StackAllPorts,
                4 => DirectSocketCeiling::ExternalHostPolicyAccepted,
                _ => return Err("unknown direct socket ceiling".into()),
            },
            unix_authority: match self.byte()? {
                1 => UnixAuthorityCeiling::NoNamedEndpointsSocketPairsOnly,
                2 => UnixAuthorityCeiling::ExistingHostUnixAuthorityAccepted,
                _ => return Err("unknown UNIX ceiling".into()),
            },
            external_socket_custody: match self.byte()? {
                1 => ExternalSocketCeiling::NoSocketAtTargetEntry,
                2 => ExternalSocketCeiling::ExistingStdioAuthorityAccepted,
                _ => return Err("unknown socket custody ceiling".into()),
            },
            credential_gains: match self.byte()? {
                1 => CredentialGainCeiling::NoGain,
                2 => CredentialGainCeiling::ExistingCallerEnvelopeAccepted,
                _ => return Err("unknown credential ceiling".into()),
            },
            mediated_communication: match self.byte()? {
                1 => MediatedCommunicationCeiling::ExternalFilesystemAndStdioPolicyAccepted,
                2 => MediatedCommunicationCeiling::RequireNoExternalCommunication,
                _ => return Err("unknown mediated communication ceiling".into()),
            },
        })
    }
    fn requirement(&mut self) -> Result<RequirementV1, String> {
        let tag = self.byte()?;
        let id = self.id()?;
        Ok(match tag {
            1 => RequirementV1::UnixSocketCreation {
                id,
                socket_kind: self.unix_kind()?,
            },
            2 => RequirementV1::UnixSocketPair {
                id,
                socket_kind: self.unix_kind()?,
            },
            3 => {
                let family = match self.byte()? {
                    1 => IpFamily::V4,
                    2 => IpFamily::V6,
                    _ => return Err("unknown canonical IP family".into()),
                };
                let count = usize::from(self.u16()?);
                if count > 7 {
                    return Err("canonical TCP operation count exceeds bound".into());
                }
                let mut operations = crate::BoundedVec::default();
                for _ in 0..count {
                    let operation = match self.byte()? {
                        1 => TcpOperation::Create,
                        2 => TcpOperation::Bind,
                        3 => TcpOperation::Listen,
                        4 => TcpOperation::Accept,
                        5 => TcpOperation::Connect,
                        6 => TcpOperation::StreamRead,
                        7 => TcpOperation::StreamWrite,
                        _ => return Err("unknown canonical TCP operation".into()),
                    };
                    operations
                        .try_push(operation)
                        .map_err(|_| "canonical operation count exceeds bound")?;
                }
                let operations = TcpOperations::new(operations)?;
                let scope = self.scope()?;
                let local_ports = match self.byte()? {
                    1 => LocalPortRequirement::KernelAssigned,
                    2 => LocalPortRequirement::Exact { port: self.port()? },
                    3 => LocalPortRequirement::InclusiveRange {
                        first: self.port()?,
                        last: self.port()?,
                    },
                    _ => return Err("unknown canonical port selector".into()),
                };
                let peer = match self.byte()? {
                    1 => TcpPeerRequirement::SameAttemptEndpoint {
                        endpoint: self.id()?,
                    },
                    2 => TcpPeerRequirement::ExactAddress {
                        endpoint: match self.byte()? {
                            1 => TcpEndpoint::V4 {
                                address: self.fixed()?,
                                port: self.port()?,
                            },
                            2 => TcpEndpoint::V6 {
                                address: self.fixed()?,
                                port: self.port()?,
                            },
                            _ => return Err("unknown canonical peer address family".into()),
                        },
                    },
                    _ => return Err("unknown canonical peer selector".into()),
                };
                RequirementV1::Tcp {
                    id,
                    family,
                    operations,
                    scope,
                    local_ports,
                    peer,
                }
            }
            4 => RequirementV1::SuppliedTcpListener {
                id,
                endpoint: self.id()?,
                scope: self.scope()?,
            },
            5 => RequirementV1::DenialExercise {
                id,
                operation: match self.byte()? {
                    1 => DeniedOperation::InetSocketCreation,
                    2 => DeniedOperation::NamedUnixSocketCreation,
                    3 => DeniedOperation::ExternalSocketImport,
                    _ => return Err("unknown canonical denial operation".into()),
                },
            },
            _ => return Err("unknown canonical requirement".into()),
        })
    }
}

/// Strict inverse of the V1 semantic byte format, including canonical set order.
pub fn decode_contract(bytes: &[u8]) -> Result<WorkloadContractV1, String> {
    if bytes.len() > crate::workload_limits::CONTRACT_BYTES {
        return Err("canonical workload exceeds byte limit".into());
    }
    const DOMAIN: &[u8] = b"memcordon-workload-contract-v1\0";
    let mut decoder = Decoder { remaining: bytes };
    if decoder.take(DOMAIN.len())? != DOMAIN || decoder.u16()? != 1 {
        return Err("canonical workload domain or version differs".into());
    }
    let workload_plan_digest = decoder.digest()?;
    let authorized_profile = ProfileRef {
        id: decoder.id()?,
        semantic_digest: decoder.digest()?,
    };
    let authorization = AuthorizationRef {
        grant_id: decoder.id()?,
        grant_revision: decoder.revision()?,
        approved_plan_digest: decoder.digest()?,
    };
    let ceiling = decoder.ceiling()?;
    let count = usize::from(decoder.u16()?);
    if count > crate::workload_limits::REQUIREMENTS {
        return Err("canonical requirement count exceeds bound".into());
    }
    let mut requirements = crate::BoundedVec::default();
    for _ in 0..count {
        requirements
            .try_push(decoder.requirement()?)
            .map_err(|_| "canonical requirement count exceeds bound")?;
    }
    let count = usize::from(decoder.u16()?);
    if count > crate::workload_limits::ENDPOINTS {
        return Err("canonical endpoint count exceeds bound".into());
    }
    let mut endpoints = crate::BoundedVec::default();
    for _ in 0..count {
        endpoints
            .try_push(EndpointDeclarationV1 {
                id: decoder.id()?,
                requirement: decoder.id()?,
            })
            .map_err(|_| "canonical endpoint count exceeds bound")?;
    }
    let expected_epoch = PolicyEpoch {
        service_instance: Nonce128(decoder.fixed()?),
        revision: decoder.revision()?,
    };
    if !decoder.remaining.is_empty() {
        return Err("unknown trailing canonical bytes".into());
    }
    let request = WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest,
        authorized_profile,
        authorization,
        ceiling,
        requirements,
        endpoints,
        expected_epoch,
    };
    request.validate()?;
    if encode_contract(&request)?.as_slice() != bytes {
        return Err("noncanonical workload set order".into());
    }
    Ok(request)
}
