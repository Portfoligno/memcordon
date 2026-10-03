//! Pure fixture operands used by sealed workload experiments. These functions
//! neither parse release evidence nor confer any release or admission authority.

use crate::workload_codec::hash_bytes;
use crate::workload_contract::{
    RequirementV1, TcpEndpoint, TcpPeerRequirement, WorkloadContractV2,
};

/// Derive the two distinct operands for a concurrent private workload probe.
/// The domain string is retained for byte compatibility with the installed
/// fixture protocol; it is not a release proof protocol identifier.
pub fn dual_fixture_challenge(base: &[u8; 32], ordinal: u8) -> Result<[u8; 32], &'static str> {
    if *base == [0; 32] || ordinal > 1 {
        return Err("dual fixture challenge identity differs");
    }
    let mut bytes = b"memcordon-final-public-dual-challenge-v1\0".to_vec();
    bytes.extend_from_slice(base);
    bytes.push(ordinal);
    Ok(*hash_bytes(&bytes).bytes())
}

/// Check that exactly one TCP port operand changed while every binding and
/// non-port requirement stayed byte-for-byte identical.
pub fn one_workload_port_changed(
    original: &WorkloadContractV2,
    changed: &WorkloadContractV2,
) -> bool {
    if original.requirements.as_slice().len() != changed.requirements.as_slice().len()
        || original.workload_plan_digest == changed.workload_plan_digest
        || original.authorization.grant_id != changed.authorization.grant_id
        || original.authorization.grant_revision != changed.authorization.grant_revision
        || original.authorized_profile != changed.authorized_profile
        || original.expected_epoch != changed.expected_epoch
        || original.execution_identity != changed.execution_identity
        || original.ceiling != changed.ceiling
        || original.endpoints != changed.endpoints
        || original.schema_version != changed.schema_version
    {
        return false;
    }
    let mut changed_ports = 0;
    for (left, right) in original
        .requirements
        .as_slice()
        .iter()
        .zip(changed.requirements.as_slice())
    {
        match (left, right) {
            (
                RequirementV1::Tcp {
                    id: lid,
                    family: lf,
                    operations: lo,
                    scope: ls,
                    local_ports: lp,
                    peer: lpeer,
                },
                RequirementV1::Tcp {
                    id: rid,
                    family: rf,
                    operations: ro,
                    scope: rs,
                    local_ports: rp,
                    peer: rpeer,
                },
            ) if lid == rid && lf == rf && lo == ro && ls == rs => {
                if lp != rp {
                    changed_ports += 1;
                }
                if lpeer != rpeer {
                    match (lpeer, rpeer) {
                        (
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V4 {
                                        address: la,
                                        port: lp,
                                    },
                            },
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V4 {
                                        address: ra,
                                        port: rp,
                                    },
                            },
                        ) if la == ra && lp != rp => changed_ports += 1,
                        (
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V6 {
                                        address: la,
                                        port: lp,
                                    },
                            },
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V6 {
                                        address: ra,
                                        port: rp,
                                    },
                            },
                        ) if la == ra && lp != rp => changed_ports += 1,
                        _ => return false,
                    }
                }
            }
            _ if left == right => {}
            _ => return false,
        }
    }
    changed_ports == 1
}
