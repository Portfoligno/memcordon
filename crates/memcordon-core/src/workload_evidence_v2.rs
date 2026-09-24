//! Closed claims for the optional Linux private-TCP workload path.
//!
//! These types do not certify a native provider by themselves. A consumer must
//! authenticate the provider record, verify its attempt binding, and compare
//! the canonical digests to the independently observed lifecycle.

use std::num::NonZeroU64;

use serde::{Deserialize, Deserializer, Serialize};

use crate::workload_codec::{Encoder, hash_bytes};
use crate::workload_contract::{ExecutionIdentityRefV2, Nonce128, ProfileRef};
use crate::{DiagnosticSha256, workload_limits};

/// A claimed native observation is never inferred from a missing field or a
/// deserialized `false`. The authenticated producer must still prove the fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VerifiedTrue(bool);

impl VerifiedTrue {
    pub fn observed(value: bool) -> Result<Self, &'static str> {
        value
            .then_some(Self(true))
            .ok_or("required native fact was not observed")
    }
}

impl<'de> Deserialize<'de> for VerifiedTrue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::observed(bool::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QualifiedNativeAbiV2 {
    #[serde(rename = "x86_64-unknown-linux-gnu")]
    X86_64LinuxGnu,
    #[serde(rename = "aarch64-unknown-linux-gnu")]
    Aarch64LinuxGnu,
}

impl QualifiedNativeAbiV2 {
    fn tag(self) -> u8 {
        match self {
            Self::X86_64LinuxGnu => 1,
            Self::Aarch64LinuxGnu => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TargetIdentityKindV2 {
    PreserveCaller,
    AdministratorProfile { reference: ExecutionIdentityRefV2 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetIdentityObservationV2 {
    pub kind: TargetIdentityKindV2,
    /// Digest of the actual pinned ELF object, not a re-opened pathname.
    pub entrypoint_digest: DiagnosticSha256,
    pub exact_credentials_verified: VerifiedTrue,
    pub no_new_privileges_verified: VerifiedTrue,
    pub capability_sets_empty: VerifiedTrue,
    pub bounding_set_empty: VerifiedTrue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "NamespaceWireV2")]
pub struct NamespaceObservationV2 {
    pub caller_network_inode: NonZeroU64,
    pub target_network_inode: NonZeroU64,
    pub loopback_only: VerifiedTrue,
    pub ipv6_disabled: VerifiedTrue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceWireV2 {
    caller_network_inode: NonZeroU64,
    target_network_inode: NonZeroU64,
    loopback_only: VerifiedTrue,
    ipv6_disabled: VerifiedTrue,
}

impl TryFrom<NamespaceWireV2> for NamespaceObservationV2 {
    type Error = &'static str;

    fn try_from(value: NamespaceWireV2) -> Result<Self, Self::Error> {
        if value.caller_network_inode == value.target_network_inode {
            return Err("private target network namespace equals caller namespace");
        }
        Ok(Self {
            caller_network_inode: value.caller_network_inode,
            target_network_inode: value.target_network_inode,
            loopback_only: value.loopback_only,
            ipv6_disabled: value.ipv6_disabled,
        })
    }
}

impl NamespaceObservationV2 {
    pub fn observed(
        caller_network_inode: NonZeroU64,
        target_network_inode: NonZeroU64,
        loopback_only: bool,
        ipv6_disabled: bool,
    ) -> Result<Self, &'static str> {
        NamespaceWireV2 {
            caller_network_inode,
            target_network_inode,
            loopback_only: VerifiedTrue::observed(loopback_only)?,
            ipv6_disabled: VerifiedTrue::observed(ipv6_disabled)?,
        }
        .try_into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PortPolicyWireV1")]
pub struct PrivatePortPolicyV1 {
    pub unprivileged_port_start: u16,
    pub ephemeral_first: u16,
    pub ephemeral_last: u16,
    pub reserved_ports_empty: VerifiedTrue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortPolicyWireV1 {
    unprivileged_port_start: u16,
    ephemeral_first: u16,
    ephemeral_last: u16,
    reserved_ports_empty: VerifiedTrue,
}

impl TryFrom<PortPolicyWireV1> for PrivatePortPolicyV1 {
    type Error = &'static str;

    fn try_from(value: PortPolicyWireV1) -> Result<Self, Self::Error> {
        if (
            value.unprivileged_port_start,
            value.ephemeral_first,
            value.ephemeral_last,
        ) != (0, 32768, 60999)
        {
            return Err("private TCP port policy differs from immutable profile");
        }
        Ok(Self {
            unprivileged_port_start: value.unprivileged_port_start,
            ephemeral_first: value.ephemeral_first,
            ephemeral_last: value.ephemeral_last,
            reserved_ports_empty: value.reserved_ports_empty,
        })
    }
}

impl PrivatePortPolicyV1 {
    pub fn observed(
        unprivileged_port_start: u16,
        ephemeral_first: u16,
        ephemeral_last: u16,
        reserved_ports_empty: bool,
    ) -> Result<Self, &'static str> {
        PortPolicyWireV1 {
            unprivileged_port_start,
            ephemeral_first,
            ephemeral_last,
            reserved_ports_empty: VerifiedTrue::observed(reserved_ports_empty)?,
        }
        .try_into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "EntryResourceWireV2")]
pub struct EntryResourceObservationV2 {
    pub gated_descriptor_count: u8,
    pub post_exec_descriptor_count: u8,
    pub anonymous_pipe_stdio: VerifiedTrue,
    pub control_and_elf_cloexec: VerifiedTrue,
    pub no_candidate_socket: VerifiedTrue,
    pub no_imported_descriptor: VerifiedTrue,
    pub no_other_descriptor: VerifiedTrue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryResourceWireV2 {
    gated_descriptor_count: u8,
    post_exec_descriptor_count: u8,
    anonymous_pipe_stdio: VerifiedTrue,
    control_and_elf_cloexec: VerifiedTrue,
    no_candidate_socket: VerifiedTrue,
    no_imported_descriptor: VerifiedTrue,
    no_other_descriptor: VerifiedTrue,
}

impl TryFrom<EntryResourceWireV2> for EntryResourceObservationV2 {
    type Error = &'static str;

    fn try_from(value: EntryResourceWireV2) -> Result<Self, Self::Error> {
        if (
            value.gated_descriptor_count,
            value.post_exec_descriptor_count,
        ) != (5, 3)
        {
            return Err("private TCP entry descriptor inventory differs");
        }
        Ok(Self {
            gated_descriptor_count: value.gated_descriptor_count,
            post_exec_descriptor_count: value.post_exec_descriptor_count,
            anonymous_pipe_stdio: value.anonymous_pipe_stdio,
            control_and_elf_cloexec: value.control_and_elf_cloexec,
            no_candidate_socket: value.no_candidate_socket,
            no_imported_descriptor: value.no_imported_descriptor,
            no_other_descriptor: value.no_other_descriptor,
        })
    }
}

impl EntryResourceObservationV2 {
    pub fn observed(
        gated_descriptor_count: u8,
        post_exec_descriptor_count: u8,
        anonymous_pipe_stdio: bool,
        control_and_elf_cloexec: bool,
        no_candidate_socket: bool,
        no_imported_descriptor: bool,
        no_other_descriptor: bool,
    ) -> Result<Self, &'static str> {
        EntryResourceWireV2 {
            gated_descriptor_count,
            post_exec_descriptor_count,
            anonymous_pipe_stdio: VerifiedTrue::observed(anonymous_pipe_stdio)?,
            control_and_elf_cloexec: VerifiedTrue::observed(control_and_elf_cloexec)?,
            no_candidate_socket: VerifiedTrue::observed(no_candidate_socket)?,
            no_imported_descriptor: VerifiedTrue::observed(no_imported_descriptor)?,
            no_other_descriptor: VerifiedTrue::observed(no_other_descriptor)?,
        }
        .try_into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTcpCheckpointV2 {
    pub attempt_binding: DiagnosticSha256,
    pub profile: ProfileRef,
    pub identity: TargetIdentityObservationV2,
    pub caller_envelope_reference: Nonce128,
    pub target_network_namespace: NamespaceObservationV2,
    pub topology_digest: DiagnosticSha256,
    pub filter_digest: DiagnosticSha256,
    pub native_abi: QualifiedNativeAbiV2,
    pub port_policy: PrivatePortPolicyV1,
    pub resources: EntryResourceObservationV2,
    pub guardian_verified: VerifiedTrue,
    pub epoch_revalidated: VerifiedTrue,
    pub checkpoint_durable: VerifiedTrue,
}

impl PrivateTcpCheckpointV2 {
    /// Authentication and observation provenance must be checked outside this
    /// value; a structurally valid JSON claim is not an authorization token.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.profile.id.as_str() != "linux-tcp4-private-v1" {
            return Err("checkpoint names a non-private profile");
        }
        if self.target_network_namespace.caller_network_inode
            == self.target_network_namespace.target_network_inode
        {
            return Err("private target network namespace equals caller namespace");
        }
        if (
            self.port_policy.unprivileged_port_start,
            self.port_policy.ephemeral_first,
            self.port_policy.ephemeral_last,
        ) != (0, 32768, 60999)
            || (
                self.resources.gated_descriptor_count,
                self.resources.post_exec_descriptor_count,
            ) != (5, 3)
        {
            return Err("private TCP immutable entry semantics differ");
        }
        Ok(())
    }

    pub fn canonical_preimage(&self) -> Result<Vec<u8>, String> {
        self.validate().map_err(str::to_owned)?;
        let mut out = Encoder::new(
            b"private-tcp-checkpoint-v2",
            workload_limits::PUBLIC_OBJECT_BYTES,
        )?;
        out.digest(&self.attempt_binding)?;
        out.id(&self.profile.id)?;
        out.digest(&self.profile.semantic_digest)?;
        match &self.identity.kind {
            TargetIdentityKindV2::PreserveCaller => out.byte(1)?,
            TargetIdentityKindV2::AdministratorProfile { reference } => {
                out.byte(2)?;
                out.id(&reference.id)?;
                out.digest(&reference.semantic_digest)?;
            }
        }
        out.digest(&self.identity.entrypoint_digest)?;
        out.raw(&[1, 1, 1, 1])?;
        out.raw(&self.caller_envelope_reference.0)?;
        out.u64(self.target_network_namespace.caller_network_inode.get())?;
        out.u64(self.target_network_namespace.target_network_inode.get())?;
        out.raw(&[1, 1])?;
        out.digest(&self.topology_digest)?;
        out.digest(&self.filter_digest)?;
        out.byte(self.native_abi.tag())?;
        out.u16(self.port_policy.unprivileged_port_start)?;
        out.u16(self.port_policy.ephemeral_first)?;
        out.u16(self.port_policy.ephemeral_last)?;
        out.byte(1)?;
        out.byte(self.resources.gated_descriptor_count)?;
        out.byte(self.resources.post_exec_descriptor_count)?;
        out.raw(&[1, 1, 1, 1, 1])?;
        out.raw(&[1, 1, 1])?;
        Ok(out.finish())
    }

    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        Ok(hash_bytes(&self.canonical_preimage()?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTcpRetiredV2 {
    pub attempt_binding: DiagnosticSha256,
    pub checkpoint_digest: DiagnosticSha256,
    pub workload_empty: VerifiedTrue,
    pub required_helpers_reaped: VerifiedTrue,
    pub cgroup_retired: VerifiedTrue,
    pub provider_network_references_closed: VerifiedTrue,
    pub stdio_and_setup_resources_closed: VerifiedTrue,
    pub policy_snapshot_released: VerifiedTrue,
}

impl PrivateTcpRetiredV2 {
    /// The observed facts must be supplied by the native cleanup ledger; a
    /// failed or missing fact cannot be converted into terminal success.
    #[allow(clippy::too_many_arguments)]
    pub fn observed(
        checkpoint: &PrivateTcpCheckpointV2,
        workload_empty: bool,
        required_helpers_reaped: bool,
        cgroup_retired: bool,
        provider_network_references_closed: bool,
        stdio_and_setup_resources_closed: bool,
        policy_snapshot_released: bool,
    ) -> Result<Self, String> {
        checkpoint.validate().map_err(str::to_owned)?;
        Ok(Self {
            attempt_binding: checkpoint.attempt_binding.clone(),
            checkpoint_digest: checkpoint.canonical_digest()?,
            workload_empty: VerifiedTrue::observed(workload_empty).map_err(str::to_owned)?,
            required_helpers_reaped: VerifiedTrue::observed(required_helpers_reaped)
                .map_err(str::to_owned)?,
            cgroup_retired: VerifiedTrue::observed(cgroup_retired).map_err(str::to_owned)?,
            provider_network_references_closed: VerifiedTrue::observed(
                provider_network_references_closed,
            )
            .map_err(str::to_owned)?,
            stdio_and_setup_resources_closed: VerifiedTrue::observed(
                stdio_and_setup_resources_closed,
            )
            .map_err(str::to_owned)?,
            policy_snapshot_released: VerifiedTrue::observed(policy_snapshot_released)
                .map_err(str::to_owned)?,
        })
    }

    pub fn terminal_success(&self, checkpoint: &PrivateTcpCheckpointV2) -> bool {
        checkpoint.validate().is_ok()
            && self.attempt_binding == checkpoint.attempt_binding
            && checkpoint
                .canonical_digest()
                .is_ok_and(|digest| digest == self.checkpoint_digest)
    }

    pub fn canonical_preimage(&self) -> Result<Vec<u8>, String> {
        let mut out = Encoder::new(
            b"private-tcp-terminal-v2",
            workload_limits::PUBLIC_OBJECT_BYTES,
        )?;
        out.digest(&self.attempt_binding)?;
        out.digest(&self.checkpoint_digest)?;
        out.raw(&[1, 1, 1, 1, 1, 1])?;
        Ok(out.finish())
    }

    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        Ok(hash_bytes(&self.canonical_preimage()?))
    }
}
