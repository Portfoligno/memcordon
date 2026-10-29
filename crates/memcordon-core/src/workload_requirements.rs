//! Closed behavior requirements; none supplies permission or an execution identity.
use crate::identifiers::LogicalId;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    tag = "kind",
    content = "port",
    deny_unknown_fields
)]
pub enum LocalPortRequestV1 {
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
pub enum PrivatePeerRequestV1 {
    DynamicLoopbackWithinThisAttempt,
    ExactLoopbackEndpoint(std::num::NonZeroU16),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeniedOperationRequestV1 {
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
pub enum RequirementRequestV1 {
    TcpListener {
        id: LogicalId,
        local_port: LocalPortRequestV1,
        peer: PrivatePeerRequestV1,
    },
    UnixStreamPair {
        id: LogicalId,
    },
    UnixSeqpacketPair {
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
        operation: DeniedOperationRequestV1,
    },
}
impl RequirementRequestV1 {
    pub fn id(&self) -> &LogicalId {
        match self {
            Self::TcpListener { id, .. }
            | Self::UnixStreamPair { id }
            | Self::UnixSeqpacketPair { id }
            | Self::UnixPathStream { id, .. }
            | Self::UnixAbstractStream { id }
            | Self::IntraAttemptDescriptorTransfer { id }
            | Self::GeneratedExecutable { id, .. }
            | Self::ExpectedDenial { id, .. } => id,
        }
    }
}
