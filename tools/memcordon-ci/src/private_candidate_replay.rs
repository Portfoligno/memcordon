//! Portable, origin-bound native proof construction. Serialized facts are raw
//! measurements, not capabilities. Every consumed byte is obtained from the
//! immutable enrolled observer session, and syscall obligations are compiled
//! from the closed selector table.

pub use crate::private_candidate_causal_facts::{
    UncertainCheckpointOperandsV1, validate_uncertain_checkpoint_capture,
};
pub use crate::private_candidate_network_facts::{
    ParsedTcpRowV1, parse_held_tcp_table, validate_private_loopback_dump_v1,
};
use crate::private_case_semantics::{
    CaseFactKindV1, ClosedCaseSpecV1, ExecRequirementV1, NativeOperationV1, closed_case_spec,
    native_syscall_number,
};
use crate::private_kernel_replay::{
    CaptureStageV2, KernelEventRecordV2, ParsedKernelCaptureV2, parse_capture_v2_with_budget,
};
use crate::private_observer_session::{
    ObserverEvidenceV1, ObserverIntervalRecordV1, ObserverStageV1, strict_json,
};
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseCaseResultV1, PrivateReleaseStageV1, private_release_case_key_v1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
const BUNDLE_MAGIC: &[u8] = b"MCRB\x01\0\0\0";

/// Deterministic identity only: this does not assert that a policy request
/// was observed, accepted or rejected. Each of the five native requests has
/// its own derived challenge/key and physical ordinal beneath one base case.
pub fn candidate_policy_interval_identity_v1(
    session_nonce: &str,
    generation: u32,
    base_challenge: &[u8; 32],
    branch: memcordon_core::private_release_branch_v1::PolicyOperationBranchV1,
) -> Result<(DiagnosticSha256, DiagnosticSha256)> {
    let nonce: [u8; 32] = hex::decode(session_nonce)
        .map_err(|_| CiError::Message("candidate policy nonce is not hex".into()))?
        .try_into()
        .map_err(|_| CiError::Message("candidate policy nonce size differs".into()))?;
    if nonce == [0; 32] || hex::encode(nonce) != session_nonce || base_challenge == &[0; 32] {
        return fail("candidate policy fresh identity inputs differ");
    }
    let branches = memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::ALL;
    let ordinal = branches
        .iter()
        .position(|value| *value == branch)
        .expect("closed policy operation") as u32;
    let challenge = memcordon_core::private_release_branch_v1::policy_branch_challenge_v1(
        base_challenge,
        branch,
    )
    .map_err(|error| CiError::Message(error.into()))?;
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        "private_tcp::wrong_grant_profile_and_port_rejected",
        &challenge,
    )
    .map_err(CiError::Message)?;
    let physical = crate::private_kernel_replay::IntervalIdV1 {
        session_nonce: nonce,
        generation,
        logical_case_key: key.clone(),
        purpose: crate::private_kernel_replay::IntervalPurposeV1::Policy,
        ordinal,
    };
    Ok((key, physical.storage_sha256()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u16)]
pub enum ReplayLeafRoleV1 {
    Request = 1,
    Attempt = 2,
    Checkpoint = 3,
    Terminal = 4,
    Fault = 5,
    Gate = 6,
    Stdio = 7,
    Facts = 8,
    Controls = 9,
    Clock = 10,
    Capture = 11,
    Historical = 12,
    Retirement = 13,
    Installation = 14,
}
impl ReplayLeafRoleV1 {
    fn from_wire(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Attempt),
            3 => Ok(Self::Checkpoint),
            4 => Ok(Self::Terminal),
            5 => Ok(Self::Fault),
            6 => Ok(Self::Gate),
            7 => Ok(Self::Stdio),
            8 => Ok(Self::Facts),
            9 => Ok(Self::Controls),
            10 => Ok(Self::Clock),
            11 => Ok(Self::Capture),
            12 => Ok(Self::Historical),
            13 => Ok(Self::Retirement),
            14 => Ok(Self::Installation),
            _ => fail("unknown replay leaf role"),
        }
    }
}

pub struct ReplayLeafV1 {
    pub role: ReplayLeafRoleV1,
    pub ordinal: u16,
    pub bytes: Vec<u8>,
}

pub fn replay_role_path(bundle_path: &str, role: ReplayLeafRoleV1, ordinal: u16) -> Result<String> {
    let prefix = bundle_path
        .strip_suffix("/replay-bundle.v1.bin")
        .ok_or_else(|| CiError::Message("replay bundle path differs".into()))?;
    let role = match role {
        ReplayLeafRoleV1::Request => "request",
        ReplayLeafRoleV1::Attempt => "attempt",
        ReplayLeafRoleV1::Checkpoint => "checkpoint",
        ReplayLeafRoleV1::Terminal => "terminal",
        ReplayLeafRoleV1::Fault => "fault",
        ReplayLeafRoleV1::Gate => "gate",
        ReplayLeafRoleV1::Stdio => "stdio",
        ReplayLeafRoleV1::Facts => "facts",
        ReplayLeafRoleV1::Controls => "controls",
        ReplayLeafRoleV1::Clock => "clock",
        ReplayLeafRoleV1::Capture => "capture",
        ReplayLeafRoleV1::Historical => "historical",
        ReplayLeafRoleV1::Retirement => "retirement",
        ReplayLeafRoleV1::Installation => "installation",
    };
    Ok(format!("{prefix}/replay/{role}/{ordinal}.bin"))
}

/// Inner views are addressed only by the closed role/ordinal mapping. They
/// inherit the authenticated outer bundle commitment and are never I leaves.
pub fn expand_replay_payload(
    payload: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut expanded = crate::private_source_carrier::expand_source_payload(payload)?;
    for (path, bytes) in payload
        .iter()
        .filter(|(path, _)| path.ends_with("/replay-bundle.v1.bin"))
    {
        for leaf in parse_replay_bundle(bytes)? {
            let inner = replay_role_path(path, leaf.role, leaf.ordinal)?;
            if expanded.insert(inner, leaf.bytes).is_some() {
                return fail("replay inner view aliases a transport leaf");
            }
        }
    }
    Ok(expanded)
}

pub fn encode_replay_bundle(leaves: &[ReplayLeafV1]) -> Result<Vec<u8>> {
    if leaves.is_empty() || leaves.len() > 256 {
        return fail("replay bundle leaf count differs");
    }
    let mut bytes = BUNDLE_MAGIC.to_vec();
    bytes.extend_from_slice(&(leaves.len() as u16).to_be_bytes());
    let mut identities = BTreeSet::new();
    for leaf in leaves {
        if leaf.bytes.is_empty() || !identities.insert((leaf.role, leaf.ordinal)) {
            return fail("replay leaf empty or duplicated");
        }
        bytes.extend_from_slice(&(leaf.role as u16).to_be_bytes());
        bytes.extend_from_slice(&leaf.ordinal.to_be_bytes());
        let size = u32::try_from(leaf.bytes.len())
            .map_err(|_| CiError::Message("replay leaf size overflow".into()))?;
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(hash_bytes(&leaf.bytes).bytes());
        bytes.extend_from_slice(&leaf.bytes);
        if bytes.len() > MAX_BUNDLE_BYTES {
            return fail("replay bundle budget exhausted");
        }
    }
    Ok(bytes)
}

pub fn parse_replay_bundle(bytes: &[u8]) -> Result<Vec<ReplayLeafV1>> {
    if bytes.len() > MAX_BUNDLE_BYTES || !bytes.starts_with(BUNDLE_MAGIC) {
        return fail("replay bundle magic/bound differs");
    }
    let mut cursor = BUNDLE_MAGIC.len();
    let count = u16::from_be_bytes(take::<2>(bytes, &mut cursor)?) as usize;
    if count == 0 || count > 256 {
        return fail("replay bundle count differs");
    }
    let mut leaves = Vec::with_capacity(count);
    let mut identities = BTreeSet::new();
    for _ in 0..count {
        let role = ReplayLeafRoleV1::from_wire(u16::from_be_bytes(take::<2>(bytes, &mut cursor)?))?;
        let ordinal = u16::from_be_bytes(take::<2>(bytes, &mut cursor)?);
        let size = u32::from_be_bytes(take::<4>(bytes, &mut cursor)?) as usize;
        let digest = take::<32>(bytes, &mut cursor)?;
        let end = cursor
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| CiError::Message("replay leaf truncated/overflow".into()))?;
        if size == 0
            || !identities.insert((role, ordinal))
            || hash_bytes(&bytes[cursor..end]).bytes() != &digest
        {
            return fail("replay leaf duplicate/hash differs");
        }
        leaves.push(ReplayLeafV1 {
            role,
            ordinal,
            bytes: bytes[cursor..end].to_vec(),
        });
        cursor = end;
    }
    if cursor != bytes.len() {
        return fail("replay bundle trailing bytes");
    }
    Ok(leaves)
}
fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| CiError::Message("replay header truncated".into()))?;
    let value = bytes[*cursor..end]
        .try_into()
        .map_err(|_| CiError::Message("replay header truncated".into()))?;
    *cursor = end;
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayTaskV1 {
    pub tid: u32,
    pub tgid: u32,
    pub start_boottime_ns: u64,
    pub cgroup_inode: u64,
    pub time_ns_inode: u64,
}
impl ReplayTaskV1 {
    fn matches(&self, event: &KernelEventRecordV2) -> bool {
        self.tid == event.task.tid
            && self.tgid == event.task.tgid
            && self.start_boottime_ns == event.task.start_boottime_ns
            && self.cgroup_inode == event.task.cgroup_inode
            && self.time_ns_inode == event.task.time_ns_inode
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRetirementV1 {
    pub task: ReplayTaskV1,
    pub role: String,
    pub live_monotonic_ns: u64,
    pub exit_sequence: u64,
    pub reap_sequence: u64,
    /// Dual root roles are pinned to their real child journal, never an
    /// aggregate record coerced into a single-attempt terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_source_path: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceRetirementV1 {
    pub inode: u64,
    pub owning_tids: Vec<u32>,
    pub observer_close_sequences: Vec<u64>,
    pub last_holder_close_monotonic_ns: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupRetirementV1 {
    pub inode: u64,
    pub last_members: Vec<u32>,
    pub empty_monotonic_ns: u64,
    pub removed_monotonic_ns: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorV1 {
    pub fd: u32,
    pub kind: String,
    pub object_inode: u64,
    pub flags: u64,
    pub access: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketV1 {
    pub task: ReplayTaskV1,
    pub socket_inode: u64,
    pub netns_inode: u64,
    pub address: String,
    pub port: u16,
    pub state: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FacilityControlV1 {
    pub operation: String,
    pub outer_capture_path: String,
    pub private_capture_path: String,
    pub outer_task: ReplayTaskV1,
    pub private_task: ReplayTaskV1,
    pub outer_occurrence: u64,
    pub private_occurrence: u64,
    /// Held initialized operand bytes; never a userspace pointer value alone.
    pub operand_path: String,
    pub operand_sha256: DiagnosticSha256,
    pub source_descriptor: Option<u32>,
    pub source_inode: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbiBranchV1 {
    pub branch: String,
    pub task: ReplayTaskV1,
    pub capture_path: String,
    pub executable_sha256: DiagnosticSha256,
    pub executable_dev: u64,
    pub executable_inode: u64,
    pub wait_status: i32,
    pub occurrence: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBranchV1 {
    pub branch: String,
    pub capture_path: String,
    pub request_path: String,
    pub response_path: String,
    pub caller_uid: u32,
    pub caller_task: ReplayTaskV1,
    pub rejection_predicate: Option<String>,
    pub registry_sha256: DiagnosticSha256,
    pub fixture_sha256: DiagnosticSha256,
    pub raw_path: String,
}

/// Exact independently captured values. Presence of a variant never suffices;
/// every variant has a closed predicate below and joins kernel/raw evidence.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CaseFactV1 {
    Retirement {
        tasks: Vec<TaskRetirementV1>,
        cgroups: Vec<CgroupRetirementV1>,
        namespaces: Vec<NamespaceRetirementV1>,
        terminal_path: String,
    },
    ExecImage {
        task: ReplayTaskV1,
        dev: u64,
        inode: u64,
        sha256: DiagnosticSha256,
        argv: Vec<String>,
        response_path: String,
    },
    Descriptors {
        task: ReplayTaskV1,
        before: Vec<DescriptorV1>,
        after: Vec<DescriptorV1>,
        before_monotonic_ns: u64,
        after_monotonic_ns: u64,
    },
    Credentials {
        task: ReplayTaskV1,
        uids: [u32; 4],
        gids: [u32; 4],
        groups: Vec<u32>,
        capabilities: [u64; 5],
        no_new_privs: u32,
        securebits: u32,
        userns_inode: u64,
    },
    Topology {
        host_netns: u64,
        pidns: u64,
        netns: u64,
        mountns: u64,
        init_pid: u32,
        target_pid: u32,
        interfaces: Vec<String>,
        addresses: Vec<String>,
        routes: Vec<String>,
        sysctls: BTreeMap<String, String>,
    },
    Filter {
        instruction_path: String,
        installed_instruction_sha256: DiagnosticSha256,
        audit_arch: u32,
        count_before: u32,
        count_after: u32,
        no_new_privs: u32,
        controls: Vec<FacilityControlV1>,
    },
    NativeFilterV1 {
        sources: crate::private_candidate_filter_facility_facts::NativeFilterSourcesV1,
    },
    PublicFilterV1 {
        sources: crate::private_candidate_filter_facility_facts::NativeFilterSourcesV1,
    },
    Tcp {
        listener: SocketV1,
        connector: SocketV1,
        response_path: String,
        request_path: String,
    },
    Collision {
        listener: SocketV1,
        competitor: ReplayTaskV1,
        bind_occurrence: u64,
        free_bind_occurrence: u64,
        response_path: String,
    },
    UnixIntent {
        task: ReplayTaskV1,
        netns: u64,
        pathname_intent: Vec<u8>,
        abstract_intent: Vec<u8>,
        namespace_unix_table_path: String,
        pathname_directory_path: String,
        planted_control_table_path: String,
    },
    FacilityControls {
        controls: Vec<FacilityControlV1>,
    },
    NativeFacilityV1 {
        sources: crate::private_candidate_facility_replay::NativeFacilitySourcesV1,
    },
    PublicFacilityV1 {
        sources: crate::private_candidate_facility_replay::NativeFacilitySourcesV1,
    },
    AuthorizationLoss {
        task: ReplayTaskV1,
        checkpoint_path: String,
        release_intent_sequence: u64,
        transport_loss_sequence: u64,
        gate_failure_sequence: u64,
        transport_errno: u32,
        phase: u32,
        stdout_path: String,
        stderr_path: String,
    },
    CallerEpoch {
        e0_generation: u32,
        e1_generation: u32,
        e0_request_path: String,
        replay_request_path: String,
        stale_response_path: String,
        spoof_response_path: String,
        spoof_uid: u32,
        e0_capture_path: String,
        replay_capture_path: String,
        spoof_capture_path: String,
        e1_capture_path: String,
    },
    NativeCallerEpochV1 {
        sources: crate::private_candidate_caller_facts::NativeCallerEpochSourcesV1,
    },
    PublicCallerEpochV1 {
        static_intent_path: String,
    },
    PublicTopologyV1 {
        case_prefix: String,
    },
    NativeUnixV1 {
        sources: crate::private_candidate_unix_facts::NativeUnixSourcesV1,
    },
    Checkpoint {
        checkpoint_path: String,
        file_dev: u64,
        file_inode: u64,
        owner: ReplayTaskV1,
        fd: u32,
        directory_fd: u32,
        file_sync_sequence: u64,
        directory_sync_sequence: u64,
        release_sequence: u64,
    },
    Descendants {
        parent: ReplayTaskV1,
        child: ReplayTaskV1,
        thread: ReplayTaskV1,
        simultaneously_live_monotonic_ns: u64,
    },
    Dual {
        first: ReplayTaskV1,
        second: ReplayTaskV1,
        first_netns: u64,
        second_netns: u64,
        first_port: u16,
        second_port: u16,
        overlap_monotonic_ns: u64,
        first_retirement_monotonic_ns: u64,
        second_response_monotonic_ns: u64,
        first_response_path: String,
        second_response_path: String,
    },
    NativeDualV1 {
        sources: crate::private_candidate_causal_facts::NativeDualPathsV1,
    },
    NativeCausalV1 {
        family: CaseFactKindV1,
        sources: crate::private_candidate_causal_facts::NativeCausalJoinV1,
        measurement: Box<CaseFactV1>,
    },
    NativeUncertainCheckpointV1 {
        sources: crate::private_candidate_causal_facts::NativeCausalJoinV1,
        measurement: Box<CaseFactV1>,
    },
    PublicUncertainCheckpointV1 {
        case_prefix: String,
    },
    PublicFaultDualV1 {
        family: CaseFactKindV1,
        case_prefix: String,
    },
    PublicUnixV1 {
        held_sample_path: String,
    },
    NativeNetworkV1 {
        family: CaseFactKindV1,
        sources: crate::private_candidate_network_facts::NativeNetworkSourcesV1,
    },
    ElfAncestors {
        dev: u64,
        inode: u64,
        image_path: String,
        before_metadata_path: String,
        after_metadata_path: String,
    },
    FrontendLoss {
        target: ReplayTaskV1,
        victim: ReplayTaskV1,
        target_live_monotonic_ns: u64,
        signal_monotonic_ns: u64,
        victim_exit_sequence: u64,
        recovery_path: String,
    },
    FrontendSupervisorWaitV1 {
        target: ReplayTaskV1,
        victim: ReplayTaskV1,
        victim_start_time_ticks: u64,
        target_live_monotonic_ns: u64,
        signal_monotonic_ns: u64,
        checkpoint_path: String,
        wait_path: String,
        stdout_path: String,
        stderr_path: String,
    },
    GuardianLoss {
        target: ReplayTaskV1,
        victim: ReplayTaskV1,
        target_live_monotonic_ns: u64,
        signal_monotonic_ns: u64,
        victim_exit_sequence: u64,
        recovery_path: String,
    },
    HostState {
        before_path: String,
        after_path: String,
        change_stream_path: String,
        interval_begin_ns: u64,
        interval_end_ns: u64,
    },
    NativeHostV1 {
        sources: crate::private_candidate_host_facts::NativeHostSourcesV1,
    },
    PublicHostV1 {
        sources: crate::private_candidate_host_facts::NativeHostSourcesV1,
    },
    Terminal {
        checkpoint_path: String,
        midpoint_path: String,
        terminal_path: String,
        attempt_id: String,
        midpoint_knowledge: String,
        terminal_knowledge: String,
    },
    NativeTerminalV1 {
        result_path: String,
        request_path: String,
        midpoint_path: String,
        terminal_path: String,
        clock_path: String,
        attempt_id: String,
    },
    PublicTerminalV1 {
        checkpoint_path: String,
        midpoint_path: String,
        midpoint_metadata_path: String,
        terminal_source_path: String,
        held_path: String,
        frame_path: String,
    },
    NativeReuseV1 {
        sources: crate::private_candidate_reuse_facts::NativeReuseSourcesV1,
    },
    Reuse {
        mechanism: String,
        first_failure_path: String,
        blocked_request_path: String,
        blocked_response_path: String,
        recovered_path: String,
        first_capture_path: String,
        blocked_capture_path: String,
        recovery_capture_path: String,
    },
    Abi {
        branches: Vec<AbiBranchV1>,
    },
    NativeAbiV1 {
        sources: crate::private_candidate_abi_facts::NativeAbiSourcesV1,
    },
    Policy {
        branches: Vec<PolicyBranchV1>,
        accepted_registry_path: String,
        fixture_path: String,
    },
}
impl CaseFactV1 {
    pub fn kind(&self) -> CaseFactKindV1 {
        use CaseFactKindV1 as K;
        match self {
            Self::NativeCausalV1 { family, .. } | Self::NativeNetworkV1 { family, .. } => *family,
            Self::NativeUncertainCheckpointV1 { .. } => K::Checkpoint,
            Self::PublicUncertainCheckpointV1 { .. } => K::Checkpoint,
            Self::PublicFaultDualV1 { family, .. } => *family,
            Self::PublicUnixV1 { .. } => K::UnixIntent,
            Self::Retirement { .. } => K::Retirement,
            Self::ExecImage { .. } => K::ExecImage,
            Self::Descriptors { .. } => K::Descriptors,
            Self::Credentials { .. } => K::Credentials,
            Self::Topology { .. } | Self::PublicTopologyV1 { .. } => K::Topology,
            Self::Filter { .. } | Self::NativeFilterV1 { .. } | Self::PublicFilterV1 { .. } => {
                K::Filter
            }
            Self::Tcp { .. } => K::Tcp,
            Self::Collision { .. } => K::Collision,
            Self::UnixIntent { .. } | Self::NativeUnixV1 { .. } => K::UnixIntent,
            Self::FacilityControls { .. }
            | Self::NativeFacilityV1 { .. }
            | Self::PublicFacilityV1 { .. } => K::FacilityControls,
            Self::AuthorizationLoss { .. } => K::AuthorizationLoss,
            Self::CallerEpoch { .. }
            | Self::NativeCallerEpochV1 { .. }
            | Self::PublicCallerEpochV1 { .. } => K::CallerEpoch,
            Self::Checkpoint { .. } => K::Checkpoint,
            Self::Descendants { .. } => K::Descendants,
            Self::Dual { .. } | Self::NativeDualV1 { .. } => K::Dual,
            Self::ElfAncestors { .. } => K::ElfAncestors,
            Self::FrontendLoss { .. } | Self::FrontendSupervisorWaitV1 { .. } => K::FrontendLoss,
            Self::GuardianLoss { .. } => K::GuardianLoss,
            Self::HostState { .. } => K::HostState,
            Self::NativeHostV1 { .. } | Self::PublicHostV1 { .. } => K::HostState,
            Self::Terminal { .. }
            | Self::NativeTerminalV1 { .. }
            | Self::PublicTerminalV1 { .. } => K::Terminal,
            Self::Reuse { .. } | Self::NativeReuseV1 { .. } => K::Reuse,
            Self::Abi { .. } | Self::NativeAbiV1 { .. } => K::Abi,
            Self::Policy { .. } => K::Policy,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseReplayFactsV1 {
    pub schema_version: u8,
    pub selector: String,
    pub result_key: DiagnosticSha256,
    pub generation: u32,
    pub interval_id: DiagnosticSha256,
    pub target: ReplayTaskV1,
    pub facts: Vec<CaseFactV1>,
    pub clock_path: String,
    pub held_sample_paths: Vec<String>,
}

pub struct ExpectedCaseSubjectV1<'a> {
    pub selector: &'a str,
    pub result_key: &'a DiagnosticSha256,
    pub fixture_sha256: &'a DiagnosticSha256,
    pub filter_sha256: &'a DiagnosticSha256,
    pub fixture_argv: &'a [String],
    pub uid: u32,
    pub gid: u32,
    pub groups: &'a [u32],
    pub port: u16,
    pub challenge: &'a [u8],
    pub auxiliary_semantics_sha256: Option<&'a DiagnosticSha256>,
    pub filter_install_source_sha256: Option<&'a DiagnosticSha256>,
    pub facility_source_sha256: Option<&'a DiagnosticSha256>,
    pub host_preservation_source_sha256: Option<&'a DiagnosticSha256>,
    pub reuse_source_sha256: Option<&'a DiagnosticSha256>,
    /// Derived by the reviewed fixture recipe from the fresh challenge.
    /// It is not a digest copied from a producer report.
    pub exact_response: &'a [u8],
}

/// Events are structural until joined to an authenticated immutable session,
/// exact interval descriptor and the closed known-action controls.
pub(crate) struct OriginBoundKernelIntervalV1 {
    parsed: ParsedKernelCaptureV2,
    record: ObserverIntervalRecordV1,
    origin_commitment_sha256: DiagnosticSha256,
}
impl OriginBoundKernelIntervalV1 {
    pub(crate) fn events(&self) -> &[KernelEventRecordV2] {
        self.parsed.events()
    }
    pub(crate) fn capture_sha256(&self) -> &DiagnosticSha256 {
        self.parsed.digest()
    }
}

pub(crate) fn replay_observer_interval(
    session: &impl ObserverEvidenceV1,
    capture_path: &str,
) -> Result<OriginBoundKernelIntervalV1> {
    let matches: Vec<_> = session
        .descriptor()
        .intervals
        .iter()
        .filter(|record| record.capture_path == capture_path)
        .collect();
    let [record] = matches.as_slice() else {
        return fail("origin interval is absent or ambiguous");
    };
    let stage = capture_stage(session);
    let parsed =
        parse_capture_v2_with_budget(session.leaf(capture_path)?, &record.logical_case_key, stage)?;
    if parsed.digest() != &record.capture_sha256
        || parsed.events().first().map(|event| event.sequence) != Some(record.first_sequence)
        || parsed.events().last().map(|event| event.sequence) != Some(record.last_sequence)
        || parsed.events().iter().any(|event| {
            event.monotonic_ns < record.arm_monotonic_ns
                || event.monotonic_ns > record.detach_monotonic_ns
        })
    {
        return fail("origin capture bounds differ from enrolled observation");
    }
    // Known controls must be complete independent captures, not verdict JSON.
    let mut actions = BTreeSet::new();
    let (native_arch, getpid_nr, socketpair_nr, compat_arch, compat_nr) =
        if session.descriptor().subject.target == "x86_64-unknown-linux-gnu" {
            (0xc000003e, 39, 53, 0xc000003e, 0x40000027)
        } else {
            (0xc00000b7, 172, 199, 0x40000028, 20)
        };
    for path in &record.controls_paths {
        let control_record = session
            .descriptor()
            .intervals
            .iter()
            .find(|interval| interval.capture_path == *path)
            .ok_or_else(|| CiError::Message("origin control interval absent".into()))?;
        if control_record.generation != record.generation || control_record.purpose != "controls" {
            return fail("origin controls generation differs");
        }
        let controls = parse_capture_v2_with_budget(
            session.leaf(path)?,
            &control_record.logical_case_key,
            stage,
        )?;
        let mut ordinary_task = None;
        let mut killed_task = None;
        for event in controls.events().iter().filter(|event| {
            event.kind == 4 && (event.seccomp_action != 0x7fff0000 || event.syscall_nr == getpid_nr)
        }) {
            if event.seccomp_action == 0x80000000 {
                if event.syscall_arch != compat_arch
                    || event.syscall_nr != compat_nr
                    || !controls.events().iter().any(|exit| {
                        exit.kind == 8
                            && same_task(event, exit)
                            && exit.syscall_result == 31
                            && exit.sequence > event.sequence
                    })
                    || !controls.events().iter().any(|reap| {
                        is_reap_of(reap, &event.task)
                            && controls.events().iter().any(|exit| {
                                exit.kind == 8
                                    && same_task(event, exit)
                                    && exit.sequence > event.sequence
                                    && exit.sequence < reap.sequence
                            })
                    })
                    || controls.events().iter().any(|returned| {
                        returned.kind == 5
                            && same_task(event, returned)
                            && returned.syscall_occurrence == event.syscall_occurrence
                    })
                {
                    return fail("known compat KILL control syscall/task/retirement differs");
                }
                if killed_task
                    .replace(event.task.tid)
                    .is_some_and(|tid| tid != event.task.tid)
                {
                    return fail("known KILL control has ambiguous task");
                }
            } else {
                let returned = syscall_return(controls.events(), event)?;
                if event.syscall_arch != native_arch
                    || event.seccomp_action == 0x00050000
                        && (event.syscall_nr != socketpair_nr
                            || event.args[0] != 1
                            || event.args[1] != 1
                            || event.args[2] != 0
                            || event.syscall_result != 1
                            || returned.syscall_result != -1)
                    || event.seccomp_action == 0x7fff0000
                        && (event.syscall_nr != getpid_nr
                            || returned.syscall_result != i64::from(event.task.tgid))
                    || !matches!(event.seccomp_action, 0x00050000 | 0x7fff0000)
                {
                    return fail(
                        "known ordinary ALLOW/ERRNO control syscall/operand/value differs",
                    );
                }
                if ordinary_task
                    .replace(event.task.tid)
                    .is_some_and(|tid| tid != event.task.tid)
                {
                    return fail("known ordinary control has ambiguous task");
                }
            }
            actions.insert(event.seccomp_action);
        }
        if let (Some(ordinary), Some(killed)) = (ordinary_task, killed_task) {
            if ordinary == killed {
                return fail("known controls did not use separate children");
            }
            let parents: Vec<_> = controls
                .events()
                .iter()
                .filter(|event| {
                    event.kind == 7
                        && matches!(event.other_tid,tid if tid == ordinary || tid == killed)
                })
                .collect();
            if parents.len() != 2
                || !same_task(parents[0], parents[1])
                || parents.iter().any(|parent| {
                    !controls.events().iter().any(|exit| {
                        exit.kind == 8
                            && exit.task.tid == parent.other_tid
                            && exit.sequence > parent.sequence
                    }) || !controls.events().iter().any(|reap| {
                        controls.events().iter().any(|exit| {
                            exit.kind == 8
                                && exit.task.tid == parent.other_tid
                                && is_reap_of(reap, &exit.task)
                                && parent.syscall_result > 0
                                && u64::try_from(parent.syscall_result).ok()
                                    == Some(exit.task.start_boottime_ns)
                                && exit.sequence > parent.sequence
                                && exit.sequence < reap.sequence
                        })
                    })
                })
            {
                return fail("known controls exact sibling lineage/retirement differs");
            }
        } else {
            return fail("known controls are not a complete same-parent calibration interval");
        }
    }
    if actions != BTreeSet::from([0x7fff0000_u32, 0x00050000, 0x80000000]) {
        return fail("known ALLOW/ERRNO/KILL controls incomplete");
    }
    Ok(OriginBoundKernelIntervalV1 {
        parsed,
        record: (*record).clone(),
        origin_commitment_sha256: session.origin_commitment_sha256().clone(),
    })
}

/// Private proof binds the complete raw inventory, not only the result.
pub(crate) struct VerifiedNativeCaseV1 {
    pub(crate) selector: String,
    pub(crate) result_sha256: DiagnosticSha256,
    pub(crate) inventory_sha256: DiagnosticSha256,
    pub(crate) generation: u32,
    pub(crate) origin_commitment_sha256: DiagnosticSha256,
    result_key: DiagnosticSha256,
    stage: ObserverStageV1,
    branches: Vec<String>,
}
impl VerifiedNativeCaseV1 {
    pub(crate) fn selector(&self) -> &str {
        &self.selector
    }
    pub(crate) fn result_hash(&self) -> &DiagnosticSha256 {
        &self.result_sha256
    }
    pub(crate) fn result_key(&self) -> &DiagnosticSha256 {
        &self.result_key
    }
    pub(crate) fn generation(&self) -> u32 {
        self.generation
    }
    pub(crate) fn branch_set(&self) -> &[String] {
        &self.branches
    }
    pub(crate) fn raw_commitment(&self) -> &DiagnosticSha256 {
        &self.inventory_sha256
    }
    pub(crate) fn stage(&self) -> ObserverStageV1 {
        self.stage
    }
}

pub(crate) fn verify_origin_bound_case(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    facts_path: &str,
    result_bytes: &[u8],
    capture_path: &str,
) -> Result<VerifiedNativeCaseV1> {
    let spec = if session.descriptor().subject.stage == ObserverStageV1::Candidate {
        crate::private_case_semantics::closed_candidate_case_spec(
            expected.selector,
            &session.descriptor().subject.target,
        )?
    } else {
        closed_case_spec(expected.selector, &session.descriptor().subject.target)?
    };
    let facts_bytes = session.leaf(facts_path)?;
    let facts: CaseReplayFactsV1 = strict_json(facts_bytes, MAX_BUNDLE_BYTES)?;
    let interval = replay_observer_interval(session, capture_path)?;
    let primary_key = if session.descriptor().subject.stage == ObserverStageV1::Candidate
        && expected.selector == "private_tcp::wrong_grant_profile_and_port_rejected"
    {
        let challenge: [u8; 32] = expected
            .challenge
            .try_into()
            .map_err(|_| CiError::Message("candidate policy base challenge size differs".into()))?;
        let accepted = memcordon_core::private_release_branch_v1::policy_branch_challenge_v1(
            &challenge,
            memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::AcceptedControl,
        )
        .map_err(|message| CiError::Message(message.into()))?;
        private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            expected.selector,
            &accepted,
        )
        .map_err(CiError::Message)?
    } else {
        expected.result_key.clone()
    };
    if facts.schema_version != 1
        || facts.selector != expected.selector
        || &facts.result_key != expected.result_key
        || facts.interval_id != interval.record.interval_id
        || facts.generation != interval.record.generation
        || interval.record.logical_case_key != primary_key
        || expected.uid == 0
        || expected.port == 0
        || expected.challenge.is_empty()
        || expected.exact_response.is_empty()
            && spec.exec == ExecRequirementV1::ExactTargetSucceeded
        || facts.facts.iter().map(CaseFactV1::kind).collect::<Vec<_>>() != spec.facts
    {
        return fail("origin case subject/exhaustive fact set differs");
    }
    verify_held_raw_samples(session, expected, &facts, &interval, &spec)?;
    verify_syscalls(
        &spec,
        expected,
        &facts,
        interval.events(),
        &session.descriptor().subject.target,
    )?;
    for fact in &facts.facts {
        if session.descriptor().subject.stage == ObserverStageV1::Candidate
            && matches!(
                fact.kind(),
                CaseFactKindV1::Checkpoint
                    | CaseFactKindV1::Tcp
                    | CaseFactKindV1::Collision
                    | CaseFactKindV1::Topology
                    | CaseFactKindV1::AuthorizationLoss
                    | CaseFactKindV1::FrontendLoss
                    | CaseFactKindV1::GuardianLoss
                    | CaseFactKindV1::Descendants
                    | CaseFactKindV1::Terminal
                    | CaseFactKindV1::Dual
                    | CaseFactKindV1::Abi
                    | CaseFactKindV1::CallerEpoch
                    | CaseFactKindV1::UnixIntent
                    | CaseFactKindV1::HostState
                    | CaseFactKindV1::FacilityControls
                    | CaseFactKindV1::Reuse
            )
            && !matches!(
                fact,
                CaseFactV1::NativeCausalV1 { .. }
                    | CaseFactV1::NativeUncertainCheckpointV1 { .. }
                    | CaseFactV1::NativeNetworkV1 { .. }
                    | CaseFactV1::NativeTerminalV1 { .. }
                    | CaseFactV1::NativeDualV1 { .. }
                    | CaseFactV1::NativeAbiV1 { .. }
                    | CaseFactV1::NativeCallerEpochV1 { .. }
                    | CaseFactV1::NativeUnixV1 { .. }
                    | CaseFactV1::NativeHostV1 { .. }
                    | CaseFactV1::NativeFacilityV1 { .. }
                    | CaseFactV1::NativeReuseV1 { .. }
            )
        {
            return fail(
                "candidate causal family requires versioned original native wire conjunction",
            );
        }
        verify_fact(session, expected, &facts, &interval, fact)?;
    }
    let execs: Vec<_> = interval
        .events()
        .iter()
        .filter(|event| event.kind == 6 && facts.target.matches(event))
        .collect();
    match spec.exec {
        ExecRequirementV1::ExactTargetSucceeded if execs.len() != 1 => {
            return fail("exact target exec is absent or duplicated");
        }
        ExecRequirementV1::PreExecAuthorizationRejected if !execs.is_empty() => {
            return fail("pre-exec uncertainty unexpectedly executed target");
        }
        _ => (),
    }
    let mut inventory = b"memcordon/origin-bound-native-case/v1\0".to_vec();
    inventory.extend_from_slice(session.payload_index_sha256().bytes());
    inventory.extend_from_slice(session.origin_commitment_sha256().bytes());
    inventory.extend_from_slice(hash_bytes(facts_bytes).bytes());
    inventory.extend_from_slice(interval.capture_sha256().bytes());
    inventory.extend_from_slice(hash_bytes(result_bytes).bytes());
    inventory.extend_from_slice(&facts.generation.to_be_bytes());
    Ok(VerifiedNativeCaseV1 {
        selector: expected.selector.into(),
        result_sha256: hash_bytes(result_bytes),
        inventory_sha256: hash_bytes(&inventory),
        generation: facts.generation,
        origin_commitment_sha256: interval.origin_commitment_sha256,
        result_key: expected.result_key.clone(),
        stage: session.descriptor().subject.stage,
        branches: spec
            .branches
            .iter()
            .map(|branch| (*branch).to_owned())
            .collect(),
    })
}

fn status_field<'a>(text: &'a str, name: &str) -> Result<&'a str> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(name));
    let value = values
        .next()
        .ok_or_else(|| CiError::Message("raw status field absent".into()))?;
    if values.next().is_some() {
        return fail("raw status field duplicated");
    }
    Ok(value.trim())
}

fn status_numbers(text: &str, name: &str) -> Result<Vec<u64>> {
    status_field(text, name)?
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| CiError::Message("raw status scalar differs".into()))
        })
        .collect()
}

fn verify_held_raw_samples(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    facts: &CaseReplayFactsV1,
    interval: &OriginBoundKernelIntervalV1,
    spec: &ClosedCaseSpecV1,
) -> Result<()> {
    let inputs: crate::private_process_clock::ProcClockInputsV1 =
        strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
    let clock = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(&inputs)?;
    if !interval.record.sample_paths.contains(&facts.clock_path)
        || facts.held_sample_paths.len() > 256
        || facts
            .held_sample_paths
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != facts.held_sample_paths.len()
    {
        return fail("raw clock/sample inventory differs from physical interval");
    }
    let requires_exact_target = spec.exec == ExecRequirementV1::ExactTargetSucceeded
        || (session.descriptor().subject.stage == ObserverStageV1::Candidate
            && expected.selector == "private_tcp::abi_alternate_entry_denied");
    if requires_exact_target && facts.held_sample_paths.is_empty() {
        return fail("successful target lacks independent held raw process sample");
    }
    let mut exact_target_seen = false;
    for path in &facts.held_sample_paths {
        if !interval.record.sample_paths.contains(path) {
            return fail("held raw sample is not in physical interval inventory");
        }
        let sample =
            crate::private_source_carrier::decode_held_source(session.leaf(path)?, |image_path| {
                session.leaf(image_path).map(ToOwned::to_owned)
            })?;
        if sample.schema_version != 1
            || sample.begin_monotonic_ns < interval.record.begin_monotonic_ns
            || sample.end_monotonic_ns > interval.record.end_monotonic_ns
            || sample.begin_monotonic_ns > sample.end_monotonic_ns
            || sample.tasks.is_empty()
            || sample.tasks.len() > 1024
            || sample.leaves.len() > 16384
        {
            return fail("held raw sample identity/time/bound differs");
        }
        let leaf = |key: &str| {
            sample
                .leaves
                .get(key)
                .map(Vec::as_slice)
                .ok_or_else(|| CiError::Message("held raw sample required leaf absent".into()))
        };
        for name in ["stat-before.raw", "stat-after.raw"] {
            let stat = std::str::from_utf8(leaf(name)?)
                .map_err(|_| CiError::Message("raw proc stat not text".into()))?;
            if crate::private_supervisor::parse_linux_child_stat(stat, sample.pid)?.start_time_ticks
                != sample.start_time_ticks
            {
                return fail("held raw process identity changed");
            }
        }
        let target_exec = interval
            .events()
            .iter()
            .find(|event| {
                event.kind == 6
                    && event.task.tgid == sample.pid
                    && event.image_dev == sample.executable_device
                    && event.image_inode == sample.executable_inode
                    && event.monotonic_ns <= sample.begin_monotonic_ns
            })
            .ok_or_else(|| {
                CiError::Message("held raw sample has no matching kernel exec".into())
            })?;
        if !clock.matches(
            crate::private_kernel_observer::KernelTaskIdentityV1 {
                pid: target_exec.task.tid,
                start_time: target_exec.task.start_boottime_ns,
                cgroup_inode: target_exec.task.cgroup_inode,
                time_ns_inode: target_exec.task.time_ns_inode,
            },
            sample.start_time_ticks,
        ) {
            return fail(
                "raw process start ticks differ from calibrated original reader/kernel start",
            );
        }
        let status = std::str::from_utf8(leaf("status.raw")?)
            .map_err(|_| CiError::Message("raw target status not text".into()))?;
        if status_numbers(status, "Tgid:")? != vec![u64::from(sample.pid)]
            || status_numbers(status, "Uid:")? != vec![u64::from(expected.uid); 4]
            || status_numbers(status, "Gid:")? != vec![u64::from(expected.gid); 4]
            || status_numbers(status, "Groups:")?
                != expected
                    .groups
                    .iter()
                    .map(|group| u64::from(*group))
                    .collect::<Vec<_>>()
            || status_numbers(status, "NoNewPrivs:")? != vec![1]
            || status_numbers(status, "Seccomp:")? != vec![2]
            || ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
                .iter()
                .any(|name| {
                    status_field(status, name)
                        .ok()
                        .and_then(|value| u64::from_str_radix(value, 16).ok())
                        != Some(0)
                })
        {
            return fail("held raw complete credentials/filter state differs");
        }
        let mut argv = leaf("cmdline.raw")?
            .split(|byte| *byte == 0)
            .collect::<Vec<_>>();
        if argv.last() == Some(&&[][..]) {
            argv.pop();
        }
        if sample.executable_sha256 != *expected.fixture_sha256
            || argv
                != expected
                    .fixture_argv
                    .iter()
                    .map(|argument| argument.as_bytes())
                    .collect::<Vec<_>>()
            || hash_bytes(leaf("image.raw")?) != *expected.fixture_sha256
        {
            return fail("held raw exact image/argv differs");
        }
        let mut tids = BTreeSet::new();
        for task in &sample.tasks {
            if task.tgid != sample.pid || !tids.insert(task.tid) {
                return fail("held raw task membership differs");
            }
            let prefix = std::path::Path::new("tasks").join(task.tid.to_string());
            let key = |name: &str| prefix.join(name).to_string_lossy().into_owned();
            for name in ["stat.raw", "stat-after.raw"] {
                let stat = std::str::from_utf8(leaf(&key(name))?)
                    .map_err(|_| CiError::Message("raw task stat not text".into()))?;
                if crate::private_supervisor::parse_linux_child_stat(stat, task.tid)?
                    .start_time_ticks
                    != task.start_time_ticks
                {
                    return fail("held raw task start identity changed");
                }
            }
            let namespaces: BTreeMap<String, u64> =
                strict_json(leaf(&key("namespaces.json"))?, 4096)?;
            if namespaces != task.namespace_inodes
                || namespaces.len() != 8
                || namespaces.values().any(|inode| *inode == 0)
                || namespaces.get("time") != Some(&target_exec.task.time_ns_inode)
            {
                return fail("held raw namespaces differ from enrolled kernel identity");
            }
            let fd_prefix = prefix.join("fds");
            let fd_prefix = fd_prefix.to_string_lossy();
            let mut fds = BTreeSet::new();
            for (key, bytes) in &sample.leaves {
                let Some(rest) = key
                    .strip_prefix(fd_prefix.as_ref())
                    .and_then(|rest| rest.strip_prefix('/'))
                else {
                    continue;
                };
                let Some((number, name)) = rest.split_once('/') else {
                    return fail("raw descriptor path differs");
                };
                if name != "identity.json" {
                    continue;
                }
                let number = number
                    .parse::<u32>()
                    .map_err(|_| CiError::Message("raw descriptor number differs".into()))?;
                let identity: RawDescriptorIdentityV1 = strict_json(bytes, 4096)?;
                if identity.fd != number
                    || identity.inode == 0
                    || !identity.link.starts_with("pipe:[")
                    || !identity.link.ends_with(']')
                    || identity.mode & 0o170000 != 0o010000
                    || !fds.insert(number)
                {
                    return fail("held target descriptor object/type differs");
                }
                let info_path = std::path::Path::new(key)
                    .parent()
                    .ok_or_else(|| CiError::Message("raw fd parent absent".into()))?
                    .join("fdinfo.raw");
                let info = std::str::from_utf8(leaf(&info_path.to_string_lossy())?)
                    .map_err(|_| CiError::Message("raw fdinfo not text".into()))?;
                let flags = u64::from_str_radix(status_field(info, "flags:")?, 8)
                    .map_err(|_| CiError::Message("raw fd flags differ".into()))?;
                if flags & 3 != if number == 0 { 0 } else { 1 }
                    || status_numbers(info, "ino:")? != vec![identity.inode]
                {
                    return fail("raw stdio descriptor direction/inode differs");
                }
            }
            if fds != BTreeSet::from([0, 1, 2]) {
                return fail("held post-exec descriptor inventory is not exact stdio");
            }
        }
        exact_target_seen |= facts.target.matches(target_exec);
    }
    if requires_exact_target && !exact_target_seen {
        return fail("held raw sample did not identify exact case target");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDescriptorIdentityV1 {
    fd: u32,
    link: String,
    device: u64,
    inode: u64,
    mode: u32,
}

fn verify_syscalls(
    spec: &ClosedCaseSpecV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    facts: &CaseReplayFactsV1,
    events: &[KernelEventRecordV2],
    target: &str,
) -> Result<()> {
    let arch = if target == "x86_64-unknown-linux-gnu" {
        0xc000003e
    } else {
        0xc00000b7
    };
    for required in &spec.syscalls {
        let nr = native_syscall_number(target, required.operation)?;
        let mut occurrences = BTreeSet::new();
        for decision in events.iter().filter(|event| {
            event.kind == 4
                && facts.target.matches(event)
                && event.syscall_nr == nr
                && event.syscall_arch == arch
        }) {
            if !valid_scalar_operands(required.operation, &decision.args) {
                continue;
            }
            let returned = syscall_return(events, decision)?;
            match required.errno {
                Some(errno)
                    if decision.seccomp_action == 0x00050000
                        && decision.syscall_result == i64::from(errno)
                        && returned.syscall_result == -i64::from(errno) =>
                {
                    ()
                }
                // EADDRINUSE is the kernel's actual collision, not a filter errno.
                Some(98)
                    if decision.seccomp_action == 0x7fff0000 && returned.syscall_result == -98 =>
                {
                    ()
                }
                None if decision.seccomp_action == 0x7fff0000 && returned.syscall_result >= 0 => (),
                _ => continue,
            }
            occurrences.insert(decision.syscall_occurrence);
        }
        // Descriptor-sensitive valid auxiliaries have separate captures; the
        // exact facility verifier joins those under the same enrolled session.
        if occurrences.len() < required.minimum_occurrences
            && !matches!(
                required.operation,
                NativeOperationV1::Sendmsg | NativeOperationV1::PidfdGetfd
            )
        {
            return fail("closed exact syscall/errno/operand obligation absent");
        }
    }
    let _ = expected;
    Ok(())
}

fn valid_scalar_operands(operation: NativeOperationV1, args: &[u64; 6]) -> bool {
    use NativeOperationV1 as O;
    match operation {
        O::Socket | O::Socketpair => args[0] == 1 && args[1] & 0xf == 1 && args[2] == 0,
        O::IoUringSetup => args[0] > 0 && args[1] != 0,
        O::PidfdGetfd => args[0] <= i32::MAX as u64 && args[1] <= i32::MAX as u64 && args[2] == 0,
        O::Setns => args[0] <= i32::MAX as u64 && args[1] == 0x40000000,
        O::Unshare => args[0] == 0x40000000,
        O::Sendmsg => args[0] <= i32::MAX as u64 && args[1] != 0,
        O::Bind | O::Connect => args[0] <= i32::MAX as u64 && args[1] != 0 && args[2] == 16,
        O::Listen => args[0] <= i32::MAX as u64 && args[1] > 0,
        O::Getpid => true,
    }
}

fn typed_unfiltered_entry<'a>(
    events: &'a [KernelEventRecordV2],
    returned: &KernelEventRecordV2,
) -> Result<&'a KernelEventRecordV2> {
    let entries = events
        .iter()
        .filter(|entry| {
            entry.kind == 11
                && entry.sequence < returned.sequence
                && entry.task == returned.task
                && entry.syscall_occurrence == returned.syscall_occurrence
                && entry.syscall_nr == returned.syscall_nr
                && entry.syscall_arch == returned.syscall_arch
                && entry.args == returned.args
        })
        .collect::<Vec<_>>();
    match entries.as_slice() {
        [entry] => Ok(*entry),
        _ => fail("causal proof lacks exact versioned unfiltered entry/return occurrence"),
    }
}

pub(crate) fn verify_candidate_native_binding(
    session: &impl ObserverEvidenceV1,
    facts: &CaseReplayFactsV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    result: &memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1,
) -> Result<()> {
    use memcordon_core::private_release_case_v1::PrivateReleaseInstalledBindingV1;
    let generation = session
        .descriptor()
        .generations
        .iter()
        .find(|generation| generation.generation == facts.generation)
        .ok_or_else(|| {
            CiError::Message("native causal original installed generation absent".into())
        })?;
    if session.descriptor().subject.stage != ObserverStageV1::Candidate
        || result.target != session.descriptor().subject.target
        || result.selector != expected.selector
        || result.result_key().map_err(CiError::Message)? != *expected.result_key
        || result
            .challenge_bytes()
            .map_err(CiError::Message)?
            .as_slice()
            != expected.challenge
    {
        return fail("native causal protected target/key/challenge/stage differs");
    }
    match &result.installed {
        PrivateReleaseInstalledBindingV1::CandidateCapability {
            installation_epoch,
            candidate_manifest_sha256,
            installed_inspection_sha256,
        } if installation_epoch == &generation.installation_epoch
            && candidate_manifest_sha256 == &generation.installed_manifest_sha256
            && installed_inspection_sha256 == &generation.installed_receipt_sha256 =>
        {
            Ok(())
        }
        _ => fail("native causal original installed authority generation differs"),
    }
}

fn verify_fact(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    facts: &CaseReplayFactsV1,
    interval: &OriginBoundKernelIntervalV1,
    fact: &CaseFactV1,
) -> Result<()> {
    let events = interval.events();
    match fact {
        CaseFactV1::NativeHostV1 { sources } => {
            if session.descriptor().subject.stage != ObserverStageV1::Candidate {
                return fail("candidate host source used outside candidate stage");
            }
            if sources.schema_version!=1 || expected.host_preservation_source_sha256!=Some(&crate::private_candidate_host_facts::host_preservation_source_revision_sha256()) || !interval.record.sample_paths.contains(&sources.source_path) {return fail("host continuity source revision/enrollment differs");}
            let map = crate::private_source_carrier::parse_source_carrier(
                session.leaf(&sources.source_path)?,
            )?;
            crate::private_candidate_host_facts::verify_host_sources(
                &map,
                events,
                interval.record.arm_monotonic_ns,
                interval.record.detach_monotonic_ns,
            )?;
            let clock = strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
            crate::private_candidate_host_facts::verify_host_reader_clock(&map, events, &clock)?;
        }
        CaseFactV1::PublicHostV1 { sources } => {
            if session.descriptor().subject.stage!=ObserverStageV1::Public
                || expected.selector!="private_tcp::host_namespace_and_sysctl_unchanged"
                || sources.schema_version!=1
                || expected.host_preservation_source_sha256!=Some(&crate::private_candidate_host_facts::host_preservation_source_revision_sha256())
                || !interval.record.sample_paths.contains(&sources.source_path) {
                return fail("public host continuity stage/selector/revision/enrollment differs");
            }
            let map = crate::private_source_carrier::parse_source_carrier(
                session.leaf(&sources.source_path)?,
            )?;
            crate::private_candidate_host_facts::verify_host_sources(
                &map,
                events,
                interval.record.arm_monotonic_ns,
                interval.record.detach_monotonic_ns,
            )?;
            let clock = strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
            crate::private_candidate_host_facts::verify_host_reader_clock(&map, events, &clock)?;
        }
        CaseFactV1::PublicUnixV1 { held_sample_path } => {
            if session.descriptor().subject.stage != ObserverStageV1::Public
                || expected.selector != "private_tcp::af_unix_abstract_and_pathname_denied"
                || !interval.record.sample_paths.contains(held_sample_path)
            {
                return fail("public Unix versioned source stage/selector/enrollment differs");
            }
            let sample = crate::private_source_carrier::decode_held_source(
                session.leaf(held_sample_path)?,
                |path| session.leaf(path).map(ToOwned::to_owned),
            )?;
            let clock = strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
            let challenge: [u8; 32] = expected
                .challenge
                .try_into()
                .map_err(|_| CiError::Message("public Unix challenge length differs".into()))?;
            crate::private_candidate_unix_facts::verify_held_unix_sources(
                &sample,
                interval.events(),
                &clock,
                &facts.target,
                &session.descriptor().subject.target,
                &challenge,
            )?;
        }
        CaseFactV1::PublicUncertainCheckpointV1 { case_prefix } => {
            crate::private_public_fault_dual_replay::verify_public_fault_dual_family_sources(
                session,
                expected,
                facts,
                case_prefix,
                CaseFactKindV1::Checkpoint,
            )?;
        }
        CaseFactV1::PublicFaultDualV1 {
            family,
            case_prefix,
        } => {
            crate::private_public_fault_dual_replay::verify_public_fault_dual_family_sources(
                session,
                expected,
                facts,
                case_prefix,
                *family,
            )?;
        }
        CaseFactV1::NativeNetworkV1 { family, sources } => {
            let challenge: [u8; 32] = expected.challenge.try_into().map_err(|_| {
                CiError::Message("network expected challenge length differs".into())
            })?;
            if session.descriptor().subject.stage != ObserverStageV1::Candidate {
                return fail("candidate network source used outside reviewed stage");
            }
            if expected.port
                != memcordon_core::private_release_case_v1::candidate_fixture_port_v1(&challenge)
            {
                return fail(
                    "actual challenge-bound network port differs from protected prepared recipe",
                );
            }
            let clock = crate::private_observer_session::strict_json(
                session.leaf(&facts.clock_path)?,
                64 * 1024,
            )?;
            let result = crate::private_candidate_network_facts::verify_native_network_sources(
                sources,
                *family,
                &facts.target,
                events,
                &clock,
                |path| session.leaf(path),
            )?;
            verify_candidate_native_binding(session, facts, expected, &result)?;
        }
        CaseFactV1::NativeUnixV1 { sources } => {
            if session.descriptor().subject.stage != ObserverStageV1::Candidate {
                return fail("candidate Unix sources used outside reviewed stage");
            }
            let clock = strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
            let result = crate::private_candidate_unix_facts::verify_native_unix_sources(
                sources,
                &facts.target,
                events,
                &clock,
                |path| session.leaf(path),
            )?;
            verify_candidate_native_binding(session, facts, expected, &result)?;
        }
        CaseFactV1::NativeUncertainCheckpointV1 {
            sources,
            measurement,
        } => {
            if !matches!(measurement.as_ref(), CaseFactV1::AuthorizationLoss { .. })
                || facts.selector != "private_tcp::authorization_uncertainty_retired"
            {
                return fail("uncertain checkpoint source family/selector differs");
            }
            verify_fact(
                session,
                expected,
                facts,
                interval,
                &CaseFactV1::NativeCausalV1 {
                    family: CaseFactKindV1::AuthorizationLoss,
                    sources: sources.clone(),
                    measurement: measurement.clone(),
                },
            )?;
            crate::private_candidate_causal_facts::verify_uncertain_checkpoint_source(
                sources,
                measurement,
                events,
                |path| session.leaf(path),
            )?;
        }
        CaseFactV1::NativeCausalV1 {
            family,
            sources,
            measurement,
        } => {
            if !matches!(
                measurement.as_ref(),
                CaseFactV1::Checkpoint { .. }
                    | CaseFactV1::AuthorizationLoss { .. }
                    | CaseFactV1::FrontendLoss { .. }
                    | CaseFactV1::GuardianLoss { .. }
                    | CaseFactV1::Descendants { .. }
            ) || measurement.kind() != *family
            {
                return fail("native causal wrapper does not contain a closed original family");
            }
            let raw = crate::private_candidate_causal_facts::replay_native_causal_join(
                sources,
                |path| session.leaf(path),
            )?;
            verify_candidate_native_binding(session, facts, expected, &raw.result)?;
            crate::private_candidate_causal_facts::verify_reopened_causal_source(
                sources,
                measurement,
                events,
                &crate::private_observer_session::strict_json::<
                    crate::private_process_clock::ProcClockInputsV1,
                >(session.leaf(&facts.clock_path)?, 64 * 1024)?,
                |path| session.leaf(path),
            )?;
            let attempt = raw
                .attempt_record
                .as_ref()
                .ok_or_else(|| CiError::Message("native causal terminal absent".into()))?;
            if attempt.checkpoint_filter_sha256() != Some(expected.filter_sha256) {
                return fail(
                    "native causal durable filter differs from independently prepared recipe",
                );
            }
            match measurement.as_ref() {
                CaseFactV1::Checkpoint {
                    checkpoint_path, ..
                }
                | CaseFactV1::AuthorizationLoss {
                    checkpoint_path, ..
                } => attempt.validate_prior_release_intent(session.leaf(checkpoint_path)?)?,
                CaseFactV1::FrontendLoss { victim, .. }
                | CaseFactV1::GuardianLoss { victim, .. } => {
                    let identity = if *family == CaseFactKindV1::FrontendLoss {
                        attempt.frontend_identity()
                    } else {
                        attempt.guardian_identity()
                    }
                    .ok_or_else(|| CiError::Message("native fault exact victim absent".into()))?;
                    let clock: crate::private_process_clock::ProcClockInputsV1 =
                        strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
                    let clock =
                        crate::private_process_clock::ParsedProcClockCalibrationV1::parse(&clock)?;
                    if identity.pid != victim.tid
                        || !clock.matches(
                            crate::private_kernel_observer::KernelTaskIdentityV1 {
                                pid: victim.tid,
                                start_time: victim.start_boottime_ns,
                                cgroup_inode: victim.cgroup_inode,
                                time_ns_inode: victim.time_ns_inode,
                            },
                            identity.start_time,
                        )
                    {
                        return fail("native causal pinned victim original clock identity differs");
                    }
                }
                _ => {}
            }
            verify_fact(session, expected, facts, interval, measurement)?;
        }
        CaseFactV1::Retirement {
            tasks,
            cgroups,
            namespaces,
            terminal_path,
        } => {
            if tasks.iter().any(|task| {
                task.terminal_source_path.is_some()
                    && (session.descriptor().subject.stage != ObserverStageV1::Candidate
                        || expected.selector != "private_tcp::dual_attempt_namespace_isolation"
                        || !matches!(task.role.as_str(), "guardian" | "frontend"))
            }) {
                return fail("per-task terminal source is not an admitted dual root role");
            }
            if tasks.is_empty()
                || cgroups.is_empty()
                || namespaces.is_empty()
                || session.leaf(terminal_path)?.is_empty()
            {
                return fail("retirement inventory incomplete");
            }
            let mut identities = BTreeSet::new();
            for retired in tasks {
                if !identities.insert((retired.task.tid, retired.task.start_boottime_ns))
                    || !matches!(
                        retired.role.as_str(),
                        "target"
                            | "child"
                            | "thread"
                            | "guardian"
                            | "frontend"
                            | "namespace-init"
                            | "helper"
                    )
                    || retired.live_monotonic_ns < interval.record.begin_monotonic_ns
                    || retired.live_monotonic_ns > interval.record.end_monotonic_ns
                {
                    return fail("retirement task identity/live boundary differs");
                }
                let exit = at(events, retired.exit_sequence)?;
                if exit.kind != 8 || !retired.task.matches(exit) {
                    return fail("retirement exact exit absent");
                }
                let reap = at(events, retired.reap_sequence)?;
                if !is_reap_of(reap, &exit.task) || reap.sequence <= exit.sequence {
                    return fail("retirement exact reap/task-free absent");
                }
            }
            if !tasks
                .iter()
                .any(|task| task.task == facts.target && task.role == "target")
            {
                return fail("target omitted from complete retirement");
            }
            for fork in events.iter().filter(|event| {
                event.kind == 7 && tasks.iter().any(|task| task.task.matches(event))
            }) {
                if !tasks.iter().any(|task| task.task.tid == fork.other_tid) {
                    return fail("observed descendant omitted from retirement");
                }
            }
            for cgroup in cgroups {
                if cgroup.inode == 0
                    || !cgroup.last_members.is_empty()
                    || cgroup.empty_monotonic_ns == 0
                    || cgroup.removed_monotonic_ns < cgroup.empty_monotonic_ns
                    || cgroup.removed_monotonic_ns > interval.record.end_monotonic_ns
                    || tasks
                        .iter()
                        .filter(|task| task.task.cgroup_inode == cgroup.inode)
                        .any(|task| {
                            at(events, task.exit_sequence)
                                .map_or(true, |exit| exit.monotonic_ns > cgroup.empty_monotonic_ns)
                        })
                {
                    return fail("owned cgroup empty/removal order differs");
                }
            }
            // The root guardian is deliberately outside the attempt cgroup.
            // Its exact native journal identity still needs exit/reap proof;
            // deleting a persistent host/service cgroup is not retirement.
            for outside_role in ["guardian", "frontend"] {
                if tasks.iter().any(|task| {
                    task.role == outside_role
                        && !cgroups
                            .iter()
                            .any(|group| group.inode == task.task.cgroup_inode)
                }) {
                    if session.descriptor().subject.stage == ObserverStageV1::Public {
                        let roles = tasks
                            .iter()
                            .filter(|task| task.role == outside_role)
                            .collect::<Vec<_>>();
                        if roles.is_empty() {
                            return fail("public outside-cgroup role inventory is empty");
                        }
                        let clock_inputs =
                            strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
                        let clock =
                            crate::private_process_clock::ParsedProcClockCalibrationV1::parse(
                                &clock_inputs,
                            )?;
                        for task in roles {
                            let identity =
                                crate::private_public_fault::public_retirement_role_from_source(
                                    session.leaf(terminal_path)?,
                                    expected.result_key,
                                    expected.selector,
                                    outside_role,
                                    task.task.tid,
                                    &session.descriptor().boot_id,
                                )?;
                            if !clock.matches(
                                crate::private_kernel_observer::KernelTaskIdentityV1 {
                                    pid: task.task.tid,
                                    start_time: task.task.start_boottime_ns,
                                    cgroup_inode: task.task.cgroup_inode,
                                    time_ns_inode: task.task.time_ns_inode,
                                },
                                identity.start_time,
                            ) {
                                return fail(
                                    "public outside-cgroup role differs from actual durable provider identity/clock",
                                );
                            }
                        }
                        continue;
                    }
                    for outside_task in tasks.iter().filter(|task| task.role == outside_role) {
                        let terminal_path = outside_task
                            .terminal_source_path
                            .as_ref()
                            .unwrap_or(terminal_path);
                        let terminal: crate::private_protected_readback::ProtectedCandidateAttemptV1 =
                        strict_json(session.leaf(terminal_path)?, 16 * 1024)?;
                        let raw: serde_json::Value =
                            strict_json(session.leaf(terminal_path)?, 16 * 1024)?;
                        let clock_inputs =
                            strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
                        let clock =
                            crate::private_process_clock::ParsedProcClockCalibrationV1::parse(
                                &clock_inputs,
                            )?;
                        let guardian = if outside_role == "guardian" {
                            terminal.guardian_identity()
                        } else {
                            terminal.frontend_identity()
                        }
                        .ok_or_else(|| {
                            CiError::Message("native terminal outside-cgroup role absent".into())
                        })?;
                        let terminal_key = if outside_task.terminal_source_path.is_some() {
                            if expected.selector != "private_tcp::dual_attempt_namespace_isolation"
                            {
                                return fail("per-task child terminal used outside dual case");
                            }
                            let tag = if terminal_path.ends_with("/journal/dual-first/attempt.json")
                            {
                                1u8
                            } else if terminal_path.ends_with("/journal/dual-second/attempt.json") {
                                2u8
                            } else {
                                return fail("dual terminal does not use exact child journal path");
                            };
                            let mut bytes =
                                b"memcordon-private-release-dual-subattempt-v1\0".to_vec();
                            bytes.extend_from_slice(expected.result_key.bytes());
                            bytes.push(tag);
                            hash_bytes(&bytes)
                        } else {
                            expected.result_key.clone()
                        };
                        if terminal.canonical_digest()? != *terminal.terminal_record_digest()
                            || raw.get("result_key") != Some(&serde_json::to_value(&terminal_key)?)
                            || raw.get("selector").and_then(serde_json::Value::as_str)
                                != Some(expected.selector)
                            || tasks
                                .iter()
                                .filter(|task| {
                                    task.role == outside_role
                                        && task.terminal_source_path.as_ref()
                                            == outside_task.terminal_source_path.as_ref()
                                })
                                .count()
                                != 1
                            || !(outside_task.task.tid == guardian.pid
                                && clock.matches(
                                    crate::private_kernel_observer::KernelTaskIdentityV1 {
                                        pid: outside_task.task.tid,
                                        start_time: outside_task.task.start_boottime_ns,
                                        cgroup_inode: outside_task.task.cgroup_inode,
                                        time_ns_inode: outside_task.task.time_ns_inode,
                                    },
                                    guardian.start_time,
                                ))
                        {
                            return fail(
                                "outside-cgroup guardian differs from exact native terminal/clock identity",
                            );
                        }
                    }
                }
            }
            if tasks
                .iter()
                .filter(|task| !matches!(task.role.as_str(), "guardian" | "frontend"))
                .any(|task| {
                    !cgroups
                        .iter()
                        .any(|group| group.inode == task.task.cgroup_inode)
                })
            {
                return fail("retirement task cgroup omitted");
            }
            for namespace in namespaces {
                if namespace.inode == 0
                    || namespace.owning_tids.is_empty()
                    || namespace.observer_close_sequences.is_empty()
                    || namespace
                        .owning_tids
                        .iter()
                        .any(|tid| !tasks.iter().any(|task| task.task.tid == *tid))
                {
                    return fail("namespace holder inventory incomplete");
                }
                for sequence in &namespace.observer_close_sequences {
                    let closed = at(events, *sequence)?;
                    if closed.kind != 10
                        || closed.image_inode != namespace.inode
                        || closed.monotonic_ns > namespace.last_holder_close_monotonic_ns
                    {
                        return fail("observer namespace fd close absent");
                    }
                }
                if namespace.last_holder_close_monotonic_ns > interval.record.end_monotonic_ns {
                    return fail("namespace closure after observation end");
                }
            }
        }
        CaseFactV1::ExecImage {
            task,
            dev,
            inode,
            sha256,
            argv,
            response_path,
        } => {
            if task != &facts.target
                || sha256 != expected.fixture_sha256
                || argv != expected.fixture_argv
                || !events.iter().any(|event| {
                    event.kind == 6
                        && task.matches(event)
                        && event.image_dev == *dev
                        && event.image_inode == *inode
                })
                || session.leaf(response_path)? != expected.exact_response
            {
                return fail("exact exec image/invocation/challenge differs");
            }
        }
        CaseFactV1::Descriptors {
            task,
            before,
            after,
            before_monotonic_ns,
            after_monotonic_ns,
        } => {
            if task != &facts.target
                || before.iter().map(|fd| fd.fd).collect::<Vec<_>>() != vec![0, 1, 2, 3, 4]
                || after.iter().map(|fd| fd.fd).collect::<Vec<_>>() != vec![0, 1, 2]
                || before.iter().chain(after).any(|fd| fd.object_inode == 0)
                || before[..3].iter().chain(after).any(|fd| fd.kind != "pipe")
                || before[3].kind != "unix-seqpacket"
                || before[4].kind != "regular-pinned-image"
                || before[..3] != after[..]
                || before[0].access != "read"
                || before[1].access != "write"
                || before[2].access != "write"
                || before[3..].iter().any(|fd| fd.flags & 0x80000 == 0)
                || !events.iter().any(|event| {
                    event.kind == 6
                        && task.matches(event)
                        && event.monotonic_ns > *before_monotonic_ns
                        && event.monotonic_ns < *after_monotonic_ns
                })
            {
                return fail("pre/post descriptor objects/directions/CLOEXEC differ");
            }
        }
        CaseFactV1::Credentials {
            task,
            uids,
            gids,
            groups,
            capabilities,
            no_new_privs,
            securebits,
            userns_inode,
        } => {
            if task != &facts.target
                || uids != &[expected.uid; 4]
                || gids != &[expected.gid; 4]
                || groups != expected.groups
                || capabilities != &[0; 5]
                || *no_new_privs != 1
                || *securebits & 0x3 != 0x3
                || *userns_inode == 0
                || !events.iter().any(|event| {
                    let (arch, nr) = match session.descriptor().subject.target.as_str() {
                        "x86_64-unknown-linux-gnu" => (0xc000003e, 157),
                        "aarch64-unknown-linux-gnu" => (0xc00000b7, 167),
                        _ => return false,
                    };
                    event.kind == 5
                        && task.matches(event)
                        && event.syscall_arch == arch
                        && event.syscall_nr == nr
                        && event.args[0] == 27
                        && event.syscall_result == i64::from(*securebits)
                })
            {
                return fail("target complete credential projection differs");
            }
        }
        CaseFactV1::Topology {
            host_netns,
            pidns,
            netns,
            mountns,
            init_pid,
            target_pid,
            interfaces,
            addresses,
            routes,
            sysctls,
        } => {
            if *host_netns == 0
                || *netns == 0
                || host_netns == netns
                || *pidns == 0
                || *mountns == 0
                || *init_pid == 0
                || *target_pid != facts.target.tgid
                || init_pid == target_pid
                || interfaces != &["lo".to_owned()]
                || addresses != &["127.0.0.1/8".to_owned()]
                || routes != &["local 127.0.0.0/8 dev lo".to_owned()]
                || sysctls
                    .get("net.ipv4.ip_unprivileged_port_start")
                    .map(String::as_str)
                    != Some("0")
                || sysctls.get("net.ipv4.ip_forward").map(String::as_str) != Some("0")
                || sysctls.len() != 2
            {
                return fail("private namespace exact topology differs");
            }
        }
        CaseFactV1::NativeFilterV1 { sources } => {
            if session.descriptor().subject.stage != ObserverStageV1::Candidate {
                return fail("candidate installed-filter source used outside candidate stage");
            }
            crate::private_candidate_filter_facility_facts::verify_native_filter_source(
                sources,
                &facts.target,
                events,
                &strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?,
                expected.filter_sha256,
                expected.filter_install_source_sha256,
                |path| Ok(session.leaf(path)?.to_vec()),
            )?;
        }
        CaseFactV1::PublicFilterV1 { sources } => {
            if session.descriptor().subject.stage != ObserverStageV1::Public
                || expected.selector != "private_tcp::native_filter_digest_and_abi_bound"
                || [
                    &sources.pre_path,
                    &sources.baseline_path,
                    &sources.instruction_path,
                ]
                .iter()
                .any(|path| !interval.record.sample_paths.contains(path))
            {
                return fail("public installed-filter stage/selector/source enrollment differs");
            }
            crate::private_candidate_filter_facility_facts::verify_native_filter_source(
                sources,
                &facts.target,
                events,
                &strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?,
                expected.filter_sha256,
                expected.filter_install_source_sha256,
                |path| Ok(session.leaf(path)?.to_vec()),
            )?;
        }
        CaseFactV1::Filter {
            instruction_path,
            installed_instruction_sha256,
            audit_arch,
            count_before,
            count_after,
            no_new_privs,
            controls,
        } => {
            let arch = if session.descriptor().subject.target == "x86_64-unknown-linux-gnu" {
                0xc000003e
            } else {
                0xc00000b7
            };
            if hash_bytes(session.leaf(instruction_path)?) != *expected.filter_sha256
                || installed_instruction_sha256 != expected.filter_sha256
                || *audit_arch != arch
                || count_before.checked_add(1) != Some(*count_after)
                || *no_new_privs != 1
                || controls.is_empty()
            {
                return fail("installed filter bytes/ABI/install projection differs");
            }
            verify_facility_controls(session, expected, controls)?;
        }
        CaseFactV1::Tcp {
            listener,
            connector,
            response_path,
            request_path,
        } => {
            if listener.socket_inode == 0
                || connector.socket_inode == 0
                || listener.socket_inode == connector.socket_inode
                || listener.netns_inode == 0
                || listener.netns_inode != connector.netns_inode
                || listener.port != expected.port
                || connector.port != expected.port
                || listener.address != "127.0.0.1"
                || connector.address != "127.0.0.1"
                || listener.state != "listen"
                || connector.state != "established"
                || session.leaf(response_path)? != expected.exact_response
                || session.leaf(request_path)? != expected.challenge
            {
                return fail("native TCP endpoint/challenge exchange differs");
            }
        }
        CaseFactV1::Collision {
            listener,
            competitor,
            bind_occurrence,
            free_bind_occurrence,
            response_path,
        } => {
            let denied = occurrence(events, competitor, *bind_occurrence)?;
            let free = occurrence(events, competitor, *free_bind_occurrence)?;
            if listener.state != "listen"
                || listener.port != expected.port
                || listener.netns_inode == 0
                || listener.socket_inode == 0
                || denied.syscall_nr
                    != native_syscall_number(
                        &session.descriptor().subject.target,
                        NativeOperationV1::Bind,
                    )?
                || denied.seccomp_action != 0x7fff0000
                || syscall_return(events, denied)?.syscall_result != -98
                || syscall_return(events, free)?.syscall_result != 0
                || session.leaf(response_path)? != expected.exact_response
            {
                return fail("same namespace live collision/free control differs");
            }
        }
        CaseFactV1::UnixIntent {
            task,
            netns,
            pathname_intent,
            abstract_intent,
            namespace_unix_table_path,
            pathname_directory_path,
            planted_control_table_path,
        } => {
            if task != &facts.target
                || *netns == 0
                || pathname_intent.first() != Some(&b'/')
                || abstract_intent.first() != Some(&0)
                || !contains(pathname_intent, expected.challenge)
                || !contains(abstract_intent, expected.challenge)
                || contains(
                    session.leaf(namespace_unix_table_path)?,
                    &abstract_intent[1..],
                )
                || contains(session.leaf(pathname_directory_path)?, pathname_intent)
                || !contains(
                    session.leaf(planted_control_table_path)?,
                    &abstract_intent[1..],
                )
                || events.iter().any(|event| {
                    event.kind == 4
                        && task.matches(event)
                        && event.syscall_nr
                            == native_syscall_number(
                                &session.descriptor().subject.target,
                                NativeOperationV1::Bind,
                            )
                            .unwrap_or(-1)
                })
            {
                return fail("two fresh Unix creation-denied intents/absence/control differ");
            }
        }
        CaseFactV1::NativeFacilityV1 { sources } => {
            if session.descriptor().subject.stage != ObserverStageV1::Candidate {
                return fail("candidate Facility source used outside candidate stage");
            }
            crate::private_candidate_facility_replay::verify_facility_source(
                session,
                expected,
                &facts.target,
                &interval.record.capture_path,
                facts.generation,
                sources,
            )?;
        }
        CaseFactV1::PublicFacilityV1 { sources } => {
            if session.descriptor().subject.stage != ObserverStageV1::Public
                || !matches!(
                    expected.selector,
                    "private_tcp::af_unix_abstract_and_pathname_denied"
                        | "private_tcp::af_unix_socketpair_denied"
                        | "private_tcp::io_uring_and_pidfd_import_denied"
                        | "private_tcp::namespace_reentry_denied"
                        | "private_tcp::scm_rights_and_precreated_socket_denied"
                )
            {
                return fail("public Facility source stage or reviewed selector differs");
            }
            crate::private_candidate_facility_replay::verify_facility_source(
                session,
                expected,
                &facts.target,
                &interval.record.capture_path,
                facts.generation,
                sources,
            )?;
        }
        CaseFactV1::FacilityControls { controls } => {
            verify_facility_controls(session, expected, controls)?
        }
        CaseFactV1::AuthorizationLoss {
            task,
            checkpoint_path,
            release_intent_sequence,
            transport_loss_sequence,
            gate_failure_sequence,
            transport_errno,
            phase,
            stdout_path,
            stderr_path,
        } => {
            if task != &facts.target
                || *phase != 4
                || *transport_errno != 32
                || *release_intent_sequence >= *transport_loss_sequence
                || *transport_loss_sequence >= *gate_failure_sequence
                || session.leaf(checkpoint_path)?.is_empty()
                || session.leaf(stdout_path)? != 0_u64.to_be_bytes()
                || session.leaf(stderr_path)? != 0_u64.to_be_bytes()
                || events
                    .iter()
                    .any(|event| event.kind == 6 && task.matches(event))
            {
                return fail("deterministic pre-exec authorization-loss transcript differs");
            }
            let intent = at(events, *release_intent_sequence)?;
            let lost = at(events, *transport_loss_sequence)?;
            let gate = at(events, *gate_failure_sequence)?;
            if intent.kind != 5
                || !matches!(intent.syscall_nr, 74 | 82)
                || intent.syscall_result != 0
                || lost.kind != 5
                || !matches!(lost.syscall_nr, 44 | 206)
                || lost.args[2] != 1
                || lost.args[3] != 0x4000 // Reviewed Linux UAPI MSG_NOSIGNAL.
                || lost.syscall_result != -32
                || intent.task != lost.task
                || gate.kind != 5
                || !task.matches(gate)
                || !matches!(gate.syscall_nr, 45 | 207)
                || gate.args[0] != 3
                || gate.args[2] != 2
                || gate.args[3] != 0
                || gate.syscall_result != 0
            {
                return fail("actual authorization fsync/EPIPE/closed-gate occurrences differ");
            }
            typed_unfiltered_entry(events, intent)?;
            typed_unfiltered_entry(events, lost)?;
            let decision = occurrence(events, task, gate.syscall_occurrence)?;
            if syscall_return(events, decision)?.sequence != gate.sequence {
                return fail("closed gate read entry/return differs");
            }
        }
        CaseFactV1::NativeCallerEpochV1 { sources } => {
            crate::private_candidate_caller_facts::verify_native_caller_epoch(
                session, expected, facts, sources,
            )?;
        }
        CaseFactV1::PublicCallerEpochV1 { static_intent_path } => {
            if session.descriptor().subject.stage != ObserverStageV1::Public
                || expected.selector != "private_tcp::caller_identity_and_epoch_bound"
                || static_intent_path != "installed/static-suite-intent.json"
            {
                return fail("public caller/history source stage or reviewed role differs");
            }
            let intent: crate::private_public_plan::StaticPublicSuiteIntentV1 =
                crate::private_observer_session::strict_json(
                    session.leaf(static_intent_path)?,
                    1024 * 1024,
                )?;
            intent.validate()?;
            if intent.observer_subject != session.descriptor().subject {
                return fail("public caller/history static intent differs from enrolled subject");
            }
            crate::private_public_specialist_replay::replay_public_history_origin(
                &intent, session,
            )?;
        }
        CaseFactV1::PublicTopologyV1 { case_prefix } => {
            if session.descriptor().subject.stage != ObserverStageV1::Public
                || !matches!(
                    expected.selector,
                    "private_tcp::namespace_reentry_denied"
                        | "private_tcp::private_namespace_topology_exact"
                )
            {
                return fail("public topology source stage or reviewed selector differs");
            }
            crate::private_public_source_facts::verify_public_topology_source(
                session,
                expected,
                facts,
                case_prefix,
            )?;
        }
        CaseFactV1::CallerEpoch {
            e0_generation,
            e1_generation,
            e0_request_path,
            replay_request_path,
            stale_response_path,
            spoof_response_path,
            spoof_uid,
            e0_capture_path,
            replay_capture_path,
            spoof_capture_path,
            e1_capture_path,
        } => {
            let timeline = &session.descriptor().generations;
            if e0_generation.checked_add(1) != Some(*e1_generation)
                || *e1_generation != facts.generation
                || *spoof_uid == expected.uid
                || *spoof_uid == 0
                || timeline.get(*e0_generation as usize).is_none()
                || timeline.get(*e1_generation as usize).is_none()
                || session.leaf(e0_request_path)? != session.leaf(replay_request_path)?
                || parse_rejection(session.leaf(stale_response_path)?, expected.result_key)?
                    .predicate
                    != "installation-epoch"
                || parse_rejection(session.leaf(spoof_response_path)?, expected.result_key)?
                    .predicate
                    != "grant-caller"
            {
                return fail("historical exact E0/E1 request/caller transition differs");
            }
            let e0 = replay_observer_interval(session, e0_capture_path)?;
            let e1 = replay_observer_interval(session, e1_capture_path)?;
            if e0.record.generation != *e0_generation
                || e1.record.generation != *e1_generation
                || !e0.events().iter().any(|event| event.kind == 6)
                || !e1.events().iter().any(|event| event.kind == 6)
            {
                return fail("historical positive controls absent");
            }
            verify_no_allocation(&replay_observer_interval(session, replay_capture_path)?)?;
            verify_no_allocation(&replay_observer_interval(session, spoof_capture_path)?)?;
        }
        CaseFactV1::Checkpoint {
            checkpoint_path,
            file_dev,
            file_inode,
            owner,
            fd,
            directory_fd,
            file_sync_sequence,
            directory_sync_sequence,
            release_sequence,
        } => {
            let checkpoint = session.leaf(checkpoint_path)?;
            let file_sync = at(events, *file_sync_sequence)?;
            let directory_sync = at(events, *directory_sync_sequence)?;
            let fsync_nr = if session.descriptor().subject.target == "x86_64-unknown-linux-gnu" {
                74
            } else {
                82
            };
            if checkpoint.is_empty()
                || *file_dev == 0
                || *file_inode == 0
                || file_sync.kind != 5
                || directory_sync.kind != 5
                || !owner.matches(file_sync)
                || !owner.matches(directory_sync)
                || file_sync.syscall_nr != fsync_nr
                || directory_sync.syscall_nr != fsync_nr
                || file_sync.args[0] != u64::from(*fd)
                || directory_sync.args[0] != u64::from(*directory_fd)
                || file_sync.syscall_result != 0
                || directory_sync.syscall_result != 0
                || *file_sync_sequence >= *directory_sync_sequence
                || *directory_sync_sequence >= *release_sequence
                || events.iter().any(|event| {
                    event.kind == 6
                        && facts.target.matches(event)
                        && event.sequence <= *release_sequence
                })
            {
                return fail("held checkpoint durability-before-release differs");
            }
            let file_entry = typed_unfiltered_entry(events, file_sync)?;
            typed_unfiltered_entry(events, directory_sync)?;
            let release = at(events, *release_sequence)?;
            typed_unfiltered_entry(events, release)?;
            if file_entry.image_dev != *file_dev
                || file_entry.image_inode != *file_inode
                || release.kind != 5
                || !owner.matches(release)
                || !matches!(release.syscall_nr, 1 | 64)
                || release.args[2] != 1
                || release.syscall_result != 1
            {
                return fail(
                    "checkpoint exact fsynced object or successful authorization send differs",
                );
            }
        }
        CaseFactV1::Descendants {
            parent,
            child,
            thread,
            simultaneously_live_monotonic_ns,
        } => {
            if parent != &facts.target
                || child.tid == parent.tid
                || child.tgid == parent.tgid
                || thread.tid == parent.tid
                || thread.tgid != parent.tgid
                || child.cgroup_inode != parent.cgroup_inode
                || thread.cgroup_inode != parent.cgroup_inode
                || !events.iter().any(|event| {
                    event.kind == 7
                        && parent.matches(event)
                        && event.other_tid == child.tid
                        && event.monotonic_ns < *simultaneously_live_monotonic_ns
                })
                || !events.iter().any(|event| {
                    event.kind == 7
                        && parent.matches(event)
                        && event.other_tid == thread.tid
                        && event.monotonic_ns < *simultaneously_live_monotonic_ns
                })
                || events
                    .iter()
                    .filter(|event| {
                        event.kind == 8
                            && (parent.matches(event)
                                || child.matches(event)
                                || thread.matches(event))
                    })
                    .any(|event| event.monotonic_ns <= *simultaneously_live_monotonic_ns)
            {
                return fail("actual simultaneous child/thread lifecycle differs");
            }
        }
        CaseFactV1::Dual {
            first,
            second,
            first_netns,
            second_netns,
            first_port,
            second_port,
            overlap_monotonic_ns,
            first_retirement_monotonic_ns,
            second_response_monotonic_ns,
            first_response_path,
            second_response_path,
        } => {
            if first.tgid == second.tgid
                || first.cgroup_inode == second.cgroup_inode
                || *first_netns == 0
                || *second_netns == 0
                || first_netns == second_netns
                || *first_port != expected.port
                || *second_port != expected.port
                || *overlap_monotonic_ns >= *first_retirement_monotonic_ns
                || *first_retirement_monotonic_ns >= *second_response_monotonic_ns
                || session.leaf(first_response_path)? == session.leaf(second_response_path)?
                || !contains(session.leaf(first_response_path)?, expected.challenge)
                || !contains(session.leaf(second_response_path)?, expected.challenge)
                || !events.iter().any(|event| {
                    is_reap_of(
                        event,
                        &crate::private_kernel_replay::KernelTaskIdentityV2 {
                            tid: first.tid,
                            tgid: first.tgid,
                            start_boottime_ns: first.start_boottime_ns,
                            cgroup_inode: first.cgroup_inode,
                            time_ns_inode: first.time_ns_inode,
                        },
                    ) && event.monotonic_ns <= *first_retirement_monotonic_ns
                        && events.iter().any(|exit| {
                            exit.kind == 8 && first.matches(exit) && exit.sequence < event.sequence
                        })
                })
                || events.iter().any(|event| {
                    event.kind == 8
                        && second.matches(event)
                        && event.monotonic_ns <= *second_response_monotonic_ns
                })
            {
                return fail("concurrent namespace isolation/first-retired-second-usable differs");
            }
        }
        CaseFactV1::NativeDualV1 { sources } => {
            if session.descriptor().subject.stage != ObserverStageV1::Candidate {
                return fail("native candidate dual branch used outside reviewed stage");
            }
            let result =
                memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1::parse(
                    session.leaf(&sources.result_path)?,
                )
                .map_err(CiError::Message)?;
            verify_candidate_native_binding(session, facts, expected, &result)?;
            if sources.clock_path != facts.clock_path {
                return fail("native dual substituted original enrolled clock source");
            }
            if result.selector != expected.selector
                || result.result_key().map_err(CiError::Message)? != *expected.result_key
                || result
                    .challenge_bytes()
                    .map_err(CiError::Message)?
                    .as_slice()
                    != expected.challenge
            {
                return fail("native dual result differs from protected recipe");
            }
            let request = crate::private_protected_readback::parse_protected_candidate_request(
                session.leaf(&sources.request_path)?,
                expected.selector,
                result.challenge_bytes().map_err(CiError::Message)?,
                expected.result_key,
            )?;
            let raw = crate::private_protected_readback::StructuralProtectedNativeCaseV1 {
                result,
                candidate_request: request,
                candidate_request_bytes: session.leaf(&sources.request_path)?.to_vec(),
                attempt_record: None,
                attempt_record_bytes: None,
                fault_marker_bytes: None,
                checkpoint_gate_bytes: None,
                attachments: Vec::new(),
            };
            let clock: crate::private_process_clock::ProcClockInputsV1 =
                strict_json(session.leaf(&sources.clock_path)?, 128 * 1024)?;
            crate::private_candidate_causal_facts::verify_native_dual_sources(
                &raw,
                events,
                &clock,
                sources,
                |path| session.leaf(path),
            )?;
        }
        CaseFactV1::ElfAncestors {
            dev,
            inode,
            image_path,
            before_metadata_path,
            after_metadata_path,
        } => {
            let before: Vec<ProtectedAncestorV1> =
                strict_json(session.leaf(before_metadata_path)?, MAX_BUNDLE_BYTES)?;
            let after: Vec<ProtectedAncestorV1> =
                strict_json(session.leaf(after_metadata_path)?, MAX_BUNDLE_BYTES)?;
            if before.is_empty()
                || before != after
                || before.iter().any(|entry| {
                    entry.uid != 0 || entry.mode & 0o022 != 0 || entry.kind != "directory"
                })
                || hash_bytes(session.leaf(image_path)?) != *expected.fixture_sha256
                || !events.iter().any(|event| {
                    event.kind == 6
                        && facts.target.matches(event)
                        && event.image_dev == *dev
                        && event.image_inode == *inode
                })
            {
                return fail("held ELF/protected unchanged ancestors differ");
            }
        }
        CaseFactV1::FrontendLoss {
            target,
            victim,
            target_live_monotonic_ns,
            signal_monotonic_ns,
            victim_exit_sequence,
            recovery_path,
        }
        | CaseFactV1::GuardianLoss {
            target,
            victim,
            target_live_monotonic_ns,
            signal_monotonic_ns,
            victim_exit_sequence,
            recovery_path,
        } => {
            let exit = at(events, *victim_exit_sequence)?;
            if target != &facts.target
                || target.tgid == victim.tgid
                || *target_live_monotonic_ns >= *signal_monotonic_ns
                || exit.kind != 8
                || !victim.matches(exit)
                || exit.monotonic_ns < *signal_monotonic_ns
                || session.leaf(recovery_path)?.is_empty()
                || !events.iter().any(|event| {
                    event.kind == 6
                        && target.matches(event)
                        && event.monotonic_ns < *target_live_monotonic_ns
                })
            {
                return fail("pinned live fault/recovery ordering differs");
            }
            if exit.syscall_result & 127 != 9 {
                return fail("fault victim did not exit from actual SIGKILL");
            }
            let signals = events
                .iter()
                .filter(|event| {
                    event.kind == 5
                        && event.syscall_nr == 424
                        && event.args[1] == 9
                        && event.syscall_result == 0
                        && event.monotonic_ns == *signal_monotonic_ns
                        && event.sequence < exit.sequence
                })
                .collect::<Vec<_>>();
            let [signal] = signals.as_slice() else {
                return fail("pinned fault has no unique successful pidfd SIGKILL occurrence");
            };
            typed_unfiltered_entry(events, signal)?;
        }
        CaseFactV1::FrontendSupervisorWaitV1 {
            target,
            victim,
            victim_start_time_ticks,
            target_live_monotonic_ns,
            signal_monotonic_ns,
            checkpoint_path,
            wait_path,
            stdout_path,
            stderr_path,
        } => {
            if session.descriptor().subject.stage != ObserverStageV1::Public
                || target != &facts.target
                || target.tgid == victim.tgid
                || *victim_start_time_ticks == 0
                || *target_live_monotonic_ns >= *signal_monotonic_ns
            {
                return fail(
                    "frontend supervisor wait is not an admitted public pinned live fault",
                );
            }
            let wait: crate::private_public_live::PublicFrontendSupervisorWaitV1 =
                strict_json(session.leaf(wait_path)?, 4096)?;
            if wait.schema_version != 1
                || wait.pid != victim.tgid
                || wait.start_time_ticks != *victim_start_time_ticks
                || wait.signal != 9
                || wait.raw_wait_status & 0x7f != 9
                || wait.raw_wait_status & 0xff00 != 0
                || wait.stdout_sha256 != hash_bytes(session.leaf(stdout_path)?)
                || wait.stderr_sha256 != hash_bytes(session.leaf(stderr_path)?)
                || wait.wait_observed_monotonic_ns < *signal_monotonic_ns
                || wait.wait_observed_monotonic_ns > interval.record.detach_monotonic_ns
                || *signal_monotonic_ns < interval.record.arm_monotonic_ns
                || !events.iter().any(|event| {
                    event.kind == 6
                        && target.matches(event)
                        && event.monotonic_ns < *target_live_monotonic_ns
                })
            {
                return fail(
                    "actual frontend owner wait signal/stdio/timestamp/exec binding differs",
                );
            }
            let clock_inputs: crate::private_process_clock::ProcClockInputsV1 =
                strict_json(session.leaf(&facts.clock_path)?, 64 * 1024)?;
            let clock =
                crate::private_process_clock::ParsedProcClockCalibrationV1::parse(&clock_inputs)?;
            if !clock.matches(
                crate::private_kernel_observer::KernelTaskIdentityV1 {
                    pid: victim.tid,
                    start_time: victim.start_boottime_ns,
                    cgroup_inode: victim.cgroup_inode,
                    time_ns_inode: victim.time_ns_inode,
                },
                *victim_start_time_ticks,
            ) {
                return fail("frontend wait ticks differ from original-reader pinned identity");
            }
            crate::private_public_fault::validate_frontend_wait_checkpoint(
                session.leaf(checkpoint_path)?,
                &crate::private_public_fault::FaultProcessV1 {
                    pid: target.tgid,
                    start_time: facts
                        .held_sample_paths
                        .iter()
                        .find_map(|path| {
                            crate::private_source_carrier::decode_held_source(
                                session.leaf(path).ok()?,
                                |image_path| session.leaf(image_path).map(ToOwned::to_owned),
                            )
                            .ok()
                            .filter(|sample| sample.pid == target.tgid)
                        })
                        .map(|sample| sample.start_time_ticks)
                        .ok_or_else(|| {
                            CiError::Message("frontend fault held target sample absent".into())
                        })?,
                },
                &crate::private_public_fault::FaultProcessV1 {
                    pid: victim.tgid,
                    start_time: *victim_start_time_ticks,
                },
                &session.descriptor().boot_id,
            )?;
        }
        CaseFactV1::HostState {
            before_path,
            after_path,
            change_stream_path,
            interval_begin_ns,
            interval_end_ns,
        } => {
            if session.leaf(before_path)? != session.leaf(after_path)?
                || *interval_begin_ns > interval.record.begin_monotonic_ns
                || *interval_end_ns < interval.record.end_monotonic_ns
            {
                return fail("host before/after state or continuous boundaries differ");
            }
            let changes: Vec<HostChangeV1> =
                strict_json(session.leaf(change_stream_path)?, MAX_BUNDLE_BYTES)?;
            if changes.iter().any(|change| {
                change.monotonic_ns >= *interval_begin_ns
                    && change.monotonic_ns <= *interval_end_ns
                    && change.before != change.after
            }) {
                return fail("transient host namespace/sysctl mutation observed");
            }
        }
        CaseFactV1::Terminal {
            checkpoint_path,
            midpoint_path,
            terminal_path,
            attempt_id,
            midpoint_knowledge,
            terminal_knowledge,
        } => {
            let checkpoint: CausalStateSnapshotV1 =
                strict_json(session.leaf(checkpoint_path)?, MAX_BUNDLE_BYTES)?;
            let midpoint: CausalStateSnapshotV1 =
                strict_json(session.leaf(midpoint_path)?, MAX_BUNDLE_BYTES)?;
            let terminal: CausalStateSnapshotV1 =
                strict_json(session.leaf(terminal_path)?, MAX_BUNDLE_BYTES)?;
            if attempt_id.is_empty()
                || [&checkpoint, &midpoint, &terminal].iter().any(|snapshot| {
                    snapshot.schema_version != 1
                        || snapshot.attempt_id != *attempt_id
                        || snapshot.target != facts.target
                        || snapshot.result_key != *expected.result_key
                        || snapshot.generation != facts.generation
                })
                || midpoint.checkpoint_sha256 != hash_bytes(session.leaf(checkpoint_path)?)
                || terminal.checkpoint_sha256 != midpoint.checkpoint_sha256
                || midpoint.knowledge != *midpoint_knowledge
                || terminal.knowledge != *terminal_knowledge
                || terminal.phase != "retired"
                || knowledge_rank(midpoint_knowledge)? > knowledge_rank(terminal_knowledge)?
            {
                return fail("exact checkpoint/midpoint/terminal identity or knowledge regressed");
            }
        }
        CaseFactV1::PublicTerminalV1 {
            checkpoint_path,
            midpoint_path,
            midpoint_metadata_path,
            terminal_source_path,
            held_path,
            frame_path,
        } => {
            if session.descriptor().subject.stage != ObserverStageV1::Public
                || expected.selector != "private_tcp::release_checkpoint_terminal_joined"
            {
                return fail("public terminal source used outside reviewed public stage/selector");
            }
            let held = crate::private_source_carrier::decode_held_source(
                session.leaf(held_path)?,
                |path: &str| Ok(session.leaf(path)?.to_vec()),
            )?;
            let clock: crate::private_process_clock::ProcClockInputsV1 =
                strict_json(session.leaf(&facts.clock_path)?, 128 * 1024)?;
            let boot = session.descriptor().boot_id.as_str();
            crate::private_public_source_facts::validate_public_terminal_source(
                session.leaf(checkpoint_path)?,
                session.leaf(midpoint_path)?,
                session.leaf(midpoint_metadata_path)?,
                session.leaf(terminal_source_path)?,
                &held,
                session.leaf(frame_path)?,
                expected.result_key,
                &facts.target,
                expected.challenge.try_into().map_err(|_| {
                    CiError::Message("public terminal challenge width differs".into())
                })?,
                boot,
                interval.events(),
                &clock,
            )?;
        }
        CaseFactV1::NativeTerminalV1 {
            result_path,
            request_path,
            midpoint_path,
            terminal_path,
            clock_path,
            attempt_id,
        } => {
            if session.descriptor().subject.stage != ObserverStageV1::Candidate {
                return fail(
                    "candidate native terminal branch used outside reviewed candidate stage",
                );
            }
            let result =
                memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1::parse(
                    session.leaf(result_path)?,
                )
                .map_err(CiError::Message)?;
            verify_candidate_native_binding(session, facts, expected, &result)?;
            if clock_path != &facts.clock_path {
                return fail("native terminal substituted original enrolled clock source");
            }
            let clock: crate::private_process_clock::ProcClockInputsV1 =
                strict_json(session.leaf(clock_path)?, 128 * 1024)?;
            crate::private_candidate_causal_facts::verify_native_terminal_v1(
                session.leaf(result_path)?,
                session.leaf(request_path)?,
                session.leaf(midpoint_path)?,
                session.leaf(terminal_path)?,
                &clock,
                &facts.target,
                expected.result_key,
                expected.challenge,
                attempt_id,
            )?;
        }
        CaseFactV1::NativeReuseV1 { sources } => {
            if sources.first_capture_path != interval.record.capture_path {
                return fail("Reuse substitutes original first physical interval");
            }
            let result =
                memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1::parse(
                    session.leaf(&sources.result_path)?,
                )
                .map_err(CiError::Message)?;
            verify_candidate_native_binding(session, facts, expected, &result)?;
            crate::private_candidate_reuse_facts::verify_native_reuse_source(
                session,
                expected,
                facts.generation,
                sources,
            )?;
        }
        CaseFactV1::Reuse {
            mechanism,
            first_failure_path,
            blocked_request_path,
            blocked_response_path,
            recovered_path,
            first_capture_path,
            blocked_capture_path,
            recovery_capture_path,
        } => {
            let expected_mechanism =
                if session.descriptor().subject.stage == ObserverStageV1::Candidate {
                    "durable-retired-write-conflict"
                } else {
                    "held-namespace-fd"
                };
            if mechanism != expected_mechanism
                || session.leaf(first_failure_path)?.is_empty()
                || session.leaf(blocked_request_path)?.is_empty()
                || parse_rejection(session.leaf(blocked_response_path)?, expected.result_key)?
                    .predicate
                    != "reuse-blocked"
                || session.leaf(recovered_path)?.is_empty()
                || session.leaf(first_failure_path)? == session.leaf(recovered_path)?
            {
                return fail("retirement failure/actual blocked reuse/recovery differs");
            }
            let first = replay_observer_interval(session, first_capture_path)?;
            let blocked = replay_observer_interval(session, blocked_capture_path)?;
            let recovered = replay_observer_interval(session, recovery_capture_path)?;
            if first.record.interval_id == blocked.record.interval_id
                || blocked.record.interval_id == recovered.record.interval_id
                || first.record.end_monotonic_ns >= blocked.record.begin_monotonic_ns
                || blocked.record.end_monotonic_ns >= recovered.record.begin_monotonic_ns
            {
                return fail("reuse distinct first/blocked/recovery chronology differs");
            }
            verify_no_allocation(&blocked)?;
        }
        CaseFactV1::NativeAbiV1 { sources } => {
            if session.descriptor().subject.stage != ObserverStageV1::Candidate {
                return fail("candidate native ABI source used outside reviewed stage");
            }
            let clock = crate::private_observer_session::strict_json(
                session.leaf(&facts.clock_path)?,
                64 * 1024,
            )?;
            let result = crate::private_candidate_abi_facts::verify_native_abi_sources(
                sources,
                events,
                &clock,
                &facts.target,
                expected.filter_sha256,
                interval.capture_sha256(),
                |path| session.leaf(path),
            )?;
            verify_candidate_native_binding(session, facts, expected, &result)?;
        }
        CaseFactV1::Abi { branches } => verify_abi(session, expected, branches)?,
        CaseFactV1::Policy {
            branches,
            accepted_registry_path,
            fixture_path,
        } => {
            let spec = closed_case_spec(expected.selector, &session.descriptor().subject.target)?;
            if branches
                .iter()
                .map(|branch| branch.branch.as_str())
                .collect::<Vec<_>>()
                != spec.branches
            {
                return fail("policy exact five distinct branches absent");
            }
            let registry_bytes = session.leaf(accepted_registry_path)?;
            let parsed_registry =
                memcordon_core::workload_registry_v2::PolicyRegistryV2::parse(registry_bytes)
                    .map_err(CiError::Message)?;
            let registry = parsed_registry
                .canonical_digest()
                .map_err(CiError::Message)?;
            let fixture = hash_bytes(session.leaf(fixture_path)?);
            for branch in branches {
                if branch.registry_sha256 != registry
                    || branch.fixture_sha256 != fixture
                    || branch.caller_uid != expected.uid
                    || branch.caller_task.tid == 0
                    || session.leaf(&branch.request_path)?.is_empty()
                    || session.leaf(&branch.response_path)?.is_empty()
                {
                    return fail("policy authenticated fixture/caller/requests differ");
                }
                let predicate = match branch.branch.as_str() {
                    "accepted" => None,
                    "wrong-grant" => Some("grant-caller"),
                    "wrong-profile" => Some("profile-digest"),
                    "unapproved-port" => Some("plan-membership"),
                    "frozen-tamper" => Some("frozen-binding"),
                    _ => unreachable!(),
                };
                if branch.rejection_predicate.as_deref() != predicate {
                    return fail("policy exact admission predicate differs");
                }
                if session.descriptor().subject.stage == ObserverStageV1::Candidate {
                    verify_candidate_policy_resolution(
                        session,
                        expected,
                        branch,
                        &parsed_registry,
                        fixture_path,
                    )?;
                } else if let Some(predicate) = predicate {
                    if parse_rejection(
                        session.leaf(&branch.response_path)?,
                        &branch_interval_key(session, &branch.capture_path)?,
                    )?
                    .predicate
                        != predicate
                    {
                        return fail("policy actual rejection response predicate differs");
                    }
                }
                let branch_interval = replay_observer_interval(session, &branch.capture_path)?;
                if session.descriptor().subject.stage == ObserverStageV1::Candidate
                    || branch.branch != "accepted"
                {
                    verify_no_allocation(&branch_interval)?;
                } else if !branch_interval.events().iter().any(|event| event.kind == 6) {
                    return fail("public accepted policy control did not execute target");
                }
            }
        }
    }
    Ok(())
}

fn verify_candidate_policy_resolution(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    branch: &PolicyBranchV1,
    registry: &memcordon_core::workload_registry_v2::PolicyRegistryV2,
    fixture_path: &str,
) -> Result<()> {
    use memcordon_core::private_release_branch_v1::{
        PolicyOperationBranchV1, PolicyOperationOutcomeV1, PrivatePolicyAgentFixtureV1,
        ProtectedPolicyBranchRawV1,
    };
    use memcordon_core::workload_registry_v2::{ProfileKindV2, resolve_v2};
    let base: [u8; 32] = expected
        .challenge
        .try_into()
        .map_err(|_| CiError::Message("candidate policy base challenge size differs".into()))?;
    let fixture: PrivatePolicyAgentFixtureV1 =
        strict_json(session.leaf(fixture_path)?, 512 * 1024)?;
    fixture.validate().map_err(CiError::Message)?;
    let raw = ProtectedPolicyBranchRawV1::parse(session.leaf(&branch.raw_path)?, &base)
        .map_err(CiError::Message)?;
    let operation = match branch.branch.as_str() {
        "accepted" => PolicyOperationBranchV1::AcceptedControl,
        "wrong-grant" => PolicyOperationBranchV1::WrongGrant,
        "wrong-profile" => PolicyOperationBranchV1::WrongProfile,
        "unapproved-port" => PolicyOperationBranchV1::UnapprovedChangedPortPlan,
        "frozen-tamper" => PolicyOperationBranchV1::CommittedPortTamper,
        _ => return fail("candidate policy operation differs"),
    };
    let record = session
        .descriptor()
        .intervals
        .iter()
        .find(|record| record.capture_path == branch.capture_path)
        .ok_or_else(|| CiError::Message("candidate policy physical interval absent".into()))?;
    let (key, physical) = candidate_policy_interval_identity_v1(
        &session.descriptor().session_nonce,
        record.generation,
        &base,
        operation,
    )?;
    if record.logical_case_key != key
        || record.interval_id != physical
        || record.purpose != "policy"
    {
        return fail("candidate policy exact branch physical interval identity differs");
    }
    let generation = session
        .descriptor()
        .generations
        .iter()
        .find(|generation| generation.installation_epoch == raw.installation_epoch_sha256)
        .ok_or_else(|| CiError::Message("candidate policy installed generation absent".into()))?;
    let branch_challenge =
        memcordon_core::private_release_branch_v1::policy_branch_challenge_v1(&base, operation)
            .map_err(|error| CiError::Message(error.into()))?;
    let request = crate::private_protected_readback::parse_protected_candidate_request(
        session.leaf(&branch.request_path)?,
        expected.selector,
        branch_challenge,
        &raw.result_key,
    )?;
    let clock_paths: Vec<_> = record
        .sample_paths
        .iter()
        .filter(|path| path.ends_with("/clock.json"))
        .collect();
    let [clock_path] = clock_paths.as_slice() else {
        return fail("candidate policy original clock inventory differs");
    };
    let inputs: crate::private_process_clock::ProcClockInputsV1 =
        strict_json(session.leaf(clock_path)?, 128 * 1024)?;
    let clock = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(&inputs)?;
    let interval = replay_observer_interval(session, &branch.capture_path)?;
    let callers: Vec<_> = interval
        .events()
        .iter()
        .filter(|event| event.kind == 1 && branch.caller_task.matches(event))
        .collect();
    let [caller] = callers.as_slice() else {
        return fail("candidate policy actual original caller request differs");
    };
    if caller.task.tid != request.coordinator.pid
        || !clock.matches(
            crate::private_kernel_observer::KernelTaskIdentityV1 {
                pid: caller.task.tid,
                start_time: caller.task.start_boottime_ns,
                cgroup_inode: caller.task.cgroup_inode,
                time_ns_inode: caller.task.time_ns_inode,
            },
            request.coordinator.start_time,
        )
        || request.installation_epoch != generation.installation_epoch
        || request.candidate_manifest_sha256 != generation.installed_manifest_sha256
        || record.generation != generation.generation
    {
        return fail("candidate policy enrolled generation/request/clock caller join differs");
    }
    if raw.branch != operation
        || raw.authenticated_caller_uid != expected.uid
        || raw.fixture_sha256 != branch.fixture_sha256
        || raw.registry_sha256 != branch.registry_sha256
        || raw.installed_inspection_sha256 != generation.installed_receipt_sha256
        || fixture.base_challenge != base
        || fixture.accepted != raw.accepted
        || fixture.changed_port != raw.changed_port
        || fixture.committed_tamper != raw.committed_tamper
        || fixture.authenticated_caller_uid != expected.uid
        || raw.result_key != branch_interval_key(session, &branch.capture_path)?
    {
        return fail("candidate policy exact frozen fixture/installed/caller/branch differs");
    }
    let resolved = resolve_v2(
        registry,
        &raw.frozen.epoch,
        &raw.exact_branch_request,
        &memcordon_core::workload_registry::CallerSelector::Linux { uid: expected.uid },
        ProfileKindV2::LinuxTcp4PrivateV1,
        &generation.installed_receipt_sha256,
    );
    match (&raw.outcome, resolved) {
        (PolicyOperationOutcomeV1::AcceptedControl, Ok(grant)) if grant == &raw.frozen.grant => (),
        (PolicyOperationOutcomeV1::Admission(code), Err(rejected)) if *code == rejected.code => (),
        (PolicyOperationOutcomeV1::FrozenBindingMismatch, _)
            if operation == PolicyOperationBranchV1::CommittedPortTamper
                && raw.exact_branch_request != raw.frozen.request
                && memcordon_core::workload_codec::contract_digest_v2(
                    &raw.exact_branch_request,
                )
                .map_err(CiError::Message)?
                    != raw.frozen.request_digest =>
        {
            ()
        }
        _ => return fail("candidate policy actual V2 resolution/frozen predicate differs"),
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedAncestorV1 {
    uid: u32,
    mode: u32,
    kind: String,
    dev: u64,
    inode: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostChangeV1 {
    monotonic_ns: u64,
    before: String,
    after: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CausalStateSnapshotV1 {
    schema_version: u8,
    attempt_id: String,
    result_key: DiagnosticSha256,
    generation: u32,
    target: ReplayTaskV1,
    checkpoint_sha256: DiagnosticSha256,
    knowledge: String,
    phase: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactRejectionV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    predicate: String,
}
fn parse_rejection(bytes: &[u8], key: &DiagnosticSha256) -> Result<ExactRejectionV1> {
    let rejection: ExactRejectionV1 = strict_json(bytes, 64 * 1024)?;
    if rejection.schema_version != 1 || &rejection.result_key != key {
        return fail("exact rejection request identity differs");
    }
    Ok(rejection)
}
fn branch_interval_key(session: &impl ObserverEvidenceV1, path: &str) -> Result<DiagnosticSha256> {
    session
        .descriptor()
        .intervals
        .iter()
        .find(|record| record.capture_path == path)
        .map(|record| record.logical_case_key.clone())
        .ok_or_else(|| CiError::Message("branch interval identity absent".into()))
}

fn verify_facility_controls(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    controls: &[FacilityControlV1],
) -> Result<()> {
    if controls.is_empty() {
        return fail("valid facility controls absent");
    }
    let mut operations = BTreeSet::new();
    for control in controls {
        if !operations.insert(control.operation.as_str())
            || hash_bytes(session.leaf(&control.operand_path)?) != control.operand_sha256
        {
            return fail("facility operand/control duplicated or substituted");
        }
        let operation = match control.operation.as_str() {
            "socket" => NativeOperationV1::Socket,
            "socketpair" => NativeOperationV1::Socketpair,
            "sendmsg" => NativeOperationV1::Sendmsg,
            "io-uring-setup" => NativeOperationV1::IoUringSetup,
            "pidfd-getfd" => NativeOperationV1::PidfdGetfd,
            "setns" => NativeOperationV1::Setns,
            "unshare" => NativeOperationV1::Unshare,
            _ => return fail("unknown facility operation"),
        };
        if matches!(
            operation,
            NativeOperationV1::Sendmsg | NativeOperationV1::PidfdGetfd
        ) && (control.source_descriptor.is_none()
            || control.source_inode.is_none_or(|inode| inode == 0))
        {
            return fail("valid source descriptor context absent");
        }
        if session.descriptor().subject.stage == ObserverStageV1::Public
            && matches!(
                operation,
                NativeOperationV1::Sendmsg | NativeOperationV1::PidfdGetfd
            )
            && expected.auxiliary_semantics_sha256
                != Some(&crate::private_case_semantics::semantics_revision_sha256())
        {
            return fail("public valid auxiliary semantics lack protected opt-in");
        }
        let outer = replay_observer_interval(session, &control.outer_capture_path)?;
        let private = replay_observer_interval(session, &control.private_capture_path)?;
        let outer_decision = occurrence(
            outer.events(),
            &control.outer_task,
            control.outer_occurrence,
        )?;
        let private_decision = occurrence(
            private.events(),
            &control.private_task,
            control.private_occurrence,
        )?;
        let nr = native_syscall_number(&session.descriptor().subject.target, operation)?;
        let errno = if operation == NativeOperationV1::Socket {
            97
        } else {
            1
        };
        if outer_decision.syscall_nr != nr
            || private_decision.syscall_nr != nr
            || !valid_scalar_operands(operation, &outer_decision.args)
            || !valid_scalar_operands(operation, &private_decision.args)
            || outer_decision.seccomp_action != 0x7fff0000
            || syscall_return(outer.events(), outer_decision)?.syscall_result < 0
            || private_decision.seccomp_action != 0x00050000
            || private_decision.syscall_result != errno
            || syscall_return(private.events(), private_decision)?.syscall_result != -errno
        {
            return fail("valid outer facility/private exact denial differs");
        }
    }
    Ok(())
}

fn verify_abi(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    branches: &[AbiBranchV1],
) -> Result<()> {
    let spec = closed_case_spec(expected.selector, &session.descriptor().subject.target)?;
    if branches
        .iter()
        .map(|branch| branch.branch.as_str())
        .collect::<Vec<_>>()
        != spec.branches
    {
        return fail("ABI exact required branches absent");
    }
    for branch in branches {
        let interval = replay_observer_interval(session, &branch.capture_path)?;
        let decision = occurrence(interval.events(), &branch.task, branch.occurrence)?;
        let (arch, nr) = if branch.branch.starts_with("i386") {
            (0x40000003, 20)
        } else if branch.branch.starts_with("x32") {
            (0xc000003e, 0x40000027)
        } else if branch.branch.starts_with("arm32") {
            (0x40000028, 20)
        } else {
            (
                if session.descriptor().subject.target == "x86_64-unknown-linux-gnu" {
                    0xc000003e
                } else {
                    0xc00000b7
                },
                native_syscall_number(
                    &session.descriptor().subject.target,
                    NativeOperationV1::Getpid,
                )?,
            )
        };
        if decision.syscall_arch != arch || decision.syscall_nr != nr {
            return fail("ABI entry arch/syscall differs");
        }
        if branch.branch.ends_with("filtered") {
            if decision.seccomp_action != 0x80000000
                || branch.wait_status != 31
                || interval.events().iter().any(|event| {
                    event.kind == 5 && event.syscall_occurrence == decision.syscall_occurrence
                })
                || !interval.events().iter().any(|event| {
                    event.kind == 8
                        && branch.task.matches(event)
                        && event.sequence > decision.sequence
                })
                || !interval.events().iter().any(|event| {
                    is_reap_of(event, &decision.task)
                        && interval.events().iter().any(|exit| {
                            exit.kind == 8
                                && branch.task.matches(exit)
                                && exit.sequence > decision.sequence
                                && exit.sequence < event.sequence
                        })
                })
            {
                return fail("ABI exact KILL-before-return/SIGSYS/reap differs");
            }
        } else {
            let returned = syscall_return(interval.events(), decision)?.syscall_result;
            if decision.seccomp_action != 0x7fff0000
                || branch.wait_status != 0
                || (returned != i64::from(branch.task.tgid)
                    && !(branch.branch == "x32-outer" && returned == -38))
            {
                return fail("ABI actual native/outer compat availability control differs");
            }
        }
        if branch.branch.starts_with("arm32")
            && (!interval.events().iter().any(|event| {
                event.kind == 6
                    && branch.task.matches(event)
                    && event.image_dev == branch.executable_dev
                    && event.image_inode == branch.executable_inode
                    && event.sequence < decision.sequence
            }) || branch.executable_sha256.bytes() == &[0; 32])
        {
            return fail("genuine pinned ARM32 helper exec absent");
        }
    }
    Ok(())
}

pub(crate) fn verify_no_allocation(interval: &OriginBoundKernelIntervalV1) -> Result<()> {
    no_allocation_events(interval.events())
}
/// Diagnostic only: this checks raw event predicates but carries no origin,
/// known-control, generation or completed-producer authority.
pub fn diagnostic_candidate_no_allocation_v1(bytes: &[u8], key: &DiagnosticSha256) -> Result<()> {
    let parsed = parse_capture_v2_with_budget(bytes, key, CaptureStageV2::Candidate)?;
    no_allocation_events(parsed.events())
}
fn no_allocation_events(events: &[KernelEventRecordV2]) -> Result<()> {
    let enters = events
        .iter()
        .filter(|event| event.kind == 1)
        .collect::<Vec<_>>();
    let exits = events
        .iter()
        .filter(|event| event.kind == 2)
        .collect::<Vec<_>>();
    let ([enter], [exit]) = (enters.as_slice(), exits.as_slice()) else {
        return fail("rejection interval does not have exactly one complete request span");
    };
    // A supervised argv driver necessarily forks and execs before entering
    // the request. Those events are retained, not confused with workload
    // allocation. No Allocate may occur anywhere in this complete interval,
    // and no target fork/exec may occur during its exact request bracket.
    if !same_task(enter, exit)
        || enter.sequence >= exit.sequence
        || events.iter().any(|event| {
            event.kind == 3 // Native wire MC_ALLOCATE.
                || (matches!(event.kind, 6 | 7) // MC_EXEC / MC_FORK.
                    && event.sequence > enter.sequence
                    && event.sequence < exit.sequence)
        })
    {
        return fail("complete rejection interval allocated or has incomplete request brackets");
    }
    Ok(())
}
fn capture_stage(session: &impl ObserverEvidenceV1) -> CaptureStageV2 {
    match session.descriptor().subject.stage {
        ObserverStageV1::Candidate => CaptureStageV2::Candidate,
        ObserverStageV1::Public => CaptureStageV2::FinalPublic,
    }
}
fn same_task(first: &KernelEventRecordV2, second: &KernelEventRecordV2) -> bool {
    first.task == second.task
}
fn is_reap_of(
    reap: &KernelEventRecordV2,
    victim: &crate::private_kernel_replay::KernelTaskIdentityV2,
) -> bool {
    reap.kind == 9
        && reap.other_tid == victim.tid
        && u64::try_from(reap.syscall_result).ok() == Some(victim.start_boottime_ns)
}
fn syscall_return<'a>(
    events: &'a [KernelEventRecordV2],
    decision: &KernelEventRecordV2,
) -> Result<&'a KernelEventRecordV2> {
    let returns: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == 5
                && same_task(decision, event)
                && event.syscall_occurrence == decision.syscall_occurrence
                && event.syscall_nr == decision.syscall_nr
                && event.syscall_arch == decision.syscall_arch
                && event.args == decision.args
                && event.sequence > decision.sequence
        })
        .collect();
    let [returned] = returns.as_slice() else {
        return fail("exact syscall occurrence return absent/duplicated");
    };
    Ok(*returned)
}
fn occurrence<'a>(
    events: &'a [KernelEventRecordV2],
    task: &ReplayTaskV1,
    occurrence: u64,
) -> Result<&'a KernelEventRecordV2> {
    let values: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == 4 && task.matches(event) && event.syscall_occurrence == occurrence
        })
        .collect();
    let [value] = values.as_slice() else {
        return fail("exact task/syscall occurrence absent/duplicated");
    };
    Ok(*value)
}
fn at(events: &[KernelEventRecordV2], sequence: u64) -> Result<&KernelEventRecordV2> {
    events
        .iter()
        .find(|event| event.sequence == sequence)
        .ok_or_else(|| CiError::Message("required causal event absent".into()))
}
fn contains(bytes: &[u8], value: &[u8]) -> bool {
    !value.is_empty() && bytes.windows(value.len()).any(|window| window == value)
}
fn knowledge_rank(value: &str) -> Result<u8> {
    match value {
        "not-released" => Ok(0),
        "possibly-released" => Ok(1),
        "exec-observed" => Ok(2),
        _ => fail("unknown authorization knowledge"),
    }
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

pub(crate) fn parse_candidate_result_key(
    bytes: &[u8],
) -> Result<(PrivateReleaseCaseResultV1, DiagnosticSha256)> {
    let result = PrivateReleaseCaseResultV1::parse(bytes).map_err(CiError::Message)?;
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        &result.selector,
        &result.challenge_bytes().map_err(CiError::Message)?,
    )
    .map_err(CiError::Message)?;
    Ok((result, key))
}
