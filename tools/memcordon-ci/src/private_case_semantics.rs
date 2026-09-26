//! Closed selector contracts shared by candidate and installed public replay.
//! Expected operations come from this table, never from uploaded decisions.

use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecRequirementV1 {
    ExactTargetSucceeded,
    PreExecAuthorizationRejected,
    BranchSpecific,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseFactKindV1 {
    Retirement,
    ExecImage,
    Descriptors,
    Credentials,
    Topology,
    Filter,
    Tcp,
    Collision,
    UnixIntent,
    FacilityControls,
    AuthorizationLoss,
    CallerEpoch,
    Checkpoint,
    Descendants,
    Dual,
    ElfAncestors,
    FrontendLoss,
    GuardianLoss,
    HostState,
    Terminal,
    Reuse,
    Abi,
    Policy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOperationV1 {
    Socket,
    Socketpair,
    Sendmsg,
    IoUringSetup,
    PidfdGetfd,
    Setns,
    Unshare,
    Bind,
    Listen,
    Connect,
    Getpid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredSyscallV1 {
    pub operation: NativeOperationV1,
    pub errno: Option<u16>,
    pub minimum_occurrences: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedCaseSpecV1 {
    pub selector: &'static str,
    pub exec: ExecRequirementV1,
    pub facts: Vec<CaseFactKindV1>,
    pub syscalls: Vec<RequiredSyscallV1>,
    pub branches: Vec<&'static str>,
}

pub fn closed_case_spec(selector: &str, target: &str) -> Result<ClosedCaseSpecV1> {
    if !matches!(
        target,
        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
    ) {
        return Err(CiError::Message(
            "case semantics target is not native GNU".into(),
        ));
    }
    let selector = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .into_iter()
        .find(|value| *value == selector)
        .ok_or_else(|| CiError::Message("selector has no closed semantic contract".into()))?;
    use CaseFactKindV1 as F;
    use NativeOperationV1 as O;
    let mut facts = vec![F::Retirement];
    let mut syscalls = Vec::new();
    let mut branches = vec!["ordinary"];
    let exec = match selector {
        "private_tcp::authorization_uncertainty_retired" => {
            ExecRequirementV1::PreExecAuthorizationRejected
        }
        "private_tcp::abi_alternate_entry_denied"
        | "private_tcp::wrong_grant_profile_and_port_rejected" => ExecRequirementV1::BranchSpecific,
        _ => ExecRequirementV1::ExactTargetSucceeded,
    };
    if exec == ExecRequirementV1::ExactTargetSucceeded {
        facts.push(F::ExecImage);
    }
    let mut syscall = |operation, errno, minimum_occurrences| {
        syscalls.push(RequiredSyscallV1 {
            operation,
            errno,
            minimum_occurrences,
        });
    };
    match selector {
        "private_tcp::abi_alternate_entry_denied" => {
            facts.push(F::Abi);
            branches = if target == "x86_64-unknown-linux-gnu" {
                vec![
                    "native-positive",
                    "x32-outer",
                    "x32-filtered",
                    "i386-outer",
                    "i386-filtered",
                ]
            } else {
                vec!["native-positive", "arm32-outer", "arm32-filtered"]
            };
        }
        "private_tcp::af_unix_abstract_and_pathname_denied" => {
            facts.extend([F::UnixIntent, F::Descriptors, F::FacilityControls]);
            syscall(O::Socket, Some(97), 2);
        }
        "private_tcp::af_unix_socketpair_denied" => {
            facts.push(F::FacilityControls);
            syscall(O::Socket, Some(97), 1);
            syscall(O::Socketpair, Some(1), 1);
        }
        "private_tcp::authorization_uncertainty_retired" => {
            facts.extend([F::AuthorizationLoss, F::Checkpoint]);
        }
        "private_tcp::caller_identity_and_epoch_bound" => {
            facts.push(F::CallerEpoch);
            branches = vec![
                "ordinary",
                "e0-positive",
                "caller-spoof",
                "stale-epoch",
                "e1-positive",
            ];
        }
        "private_tcp::checkpoint_persisted_before_release" => {
            facts.push(F::Checkpoint);
        }
        "private_tcp::child_runtime_and_threads_retired" => {
            facts.push(F::Descendants);
        }
        "private_tcp::descriptor_table_and_stdio_bound" => {
            facts.push(F::Descriptors);
        }
        "private_tcp::dual_attempt_namespace_isolation" => {
            facts.extend([F::Dual, F::Collision]);
            branches = vec!["first", "second", "first-retired-second-live"];
        }
        "private_tcp::elf_ancestor_and_identity_pinned" => {
            facts.push(F::ElfAncestors);
        }
        "private_tcp::frontend_loss_retired" => {
            facts.extend([F::FrontendLoss, F::Checkpoint]);
        }
        "private_tcp::guardian_loss_retired" => {
            facts.extend([F::GuardianLoss, F::Checkpoint]);
        }
        "private_tcp::host_namespace_and_sysctl_unchanged" => {
            facts.push(F::HostState);
        }
        "private_tcp::io_uring_and_pidfd_import_denied" => {
            facts.push(F::FacilityControls);
            syscall(O::IoUringSetup, Some(1), 1);
            syscall(O::PidfdGetfd, Some(1), 1);
            branches = vec!["ordinary", "valid-import-auxiliary"];
        }
        "private_tcp::namespace_reentry_denied" => {
            facts.extend([F::Topology, F::FacilityControls]);
            syscall(O::Setns, Some(1), 1);
            syscall(O::Unshare, Some(1), 1);
        }
        "private_tcp::native_filter_digest_and_abi_bound" => {
            facts.push(F::Filter);
        }
        "private_tcp::native_tcp_bind_listen_connect" => {
            facts.push(F::Tcp);
            syscall(O::Bind, None, 1);
            syscall(O::Listen, None, 1);
            syscall(O::Connect, None, 1);
        }
        "private_tcp::port_collision_same_namespace" => {
            facts.extend([F::Tcp, F::Collision]);
            syscall(O::Bind, Some(98), 1);
        }
        "private_tcp::private_namespace_topology_exact" => {
            facts.extend([F::Topology, F::Tcp]);
        }
        "private_tcp::release_checkpoint_terminal_joined" => {
            facts.extend([F::Checkpoint, F::Terminal]);
        }
        "private_tcp::retirement_failure_blocks_reuse" => {
            facts.push(F::Reuse);
            branches = vec!["first", "blocked", "recovered"];
        }
        "private_tcp::scm_rights_and_precreated_socket_denied" => {
            facts.extend([F::Descriptors, F::FacilityControls, F::Tcp]);
            syscall(O::Sendmsg, Some(1), 1);
            branches = vec!["ordinary", "valid-scm-auxiliary"];
        }
        "private_tcp::target_credentials_and_capabilities_dropped" => {
            facts.push(F::Credentials);
        }
        "private_tcp::target_exec_and_fd_leak_observed" => {
            facts.extend([F::Descriptors, F::ElfAncestors]);
        }
        "private_tcp::wrong_grant_profile_and_port_rejected" => {
            facts = vec![F::Policy];
            branches = vec![
                "accepted",
                "wrong-grant",
                "wrong-profile",
                "unapproved-port",
                "frozen-tamper",
            ];
        }
        _ => unreachable!("closed catalogue selector must have reviewed obligations"),
    }
    facts.sort();
    facts.dedup();
    Ok(ClosedCaseSpecV1 {
        selector,
        exec,
        facts,
        syscalls,
        branches,
    })
}

/// Explicit target ABI numbers; never the collector host's libc SYS values.
/// Candidate policy is five authenticated decisions, including its accepted
/// baseline. No branch allocates a target, so resource retirement is not a
/// fact in that stage. Public policy has its distinct real-launch composite.
pub fn closed_candidate_case_spec(selector: &str, target: &str) -> Result<ClosedCaseSpecV1> {
    let mut spec = closed_case_spec(selector, target)?;
    if selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
        spec.facts
            .retain(|kind| *kind != CaseFactKindV1::Retirement);
    }
    Ok(spec)
}

pub fn native_syscall_number(target: &str, operation: NativeOperationV1) -> Result<i64> {
    use NativeOperationV1 as O;
    let value = match (target, operation) {
        ("x86_64-unknown-linux-gnu", O::Socket) => 41,
        ("x86_64-unknown-linux-gnu", O::Socketpair) => 53,
        ("x86_64-unknown-linux-gnu", O::Sendmsg) => 46,
        ("x86_64-unknown-linux-gnu", O::IoUringSetup) => 425,
        ("x86_64-unknown-linux-gnu", O::PidfdGetfd) => 438,
        ("x86_64-unknown-linux-gnu", O::Setns) => 308,
        ("x86_64-unknown-linux-gnu", O::Unshare) => 272,
        ("x86_64-unknown-linux-gnu", O::Bind) => 49,
        ("x86_64-unknown-linux-gnu", O::Listen) => 50,
        ("x86_64-unknown-linux-gnu", O::Connect) => 42,
        ("x86_64-unknown-linux-gnu", O::Getpid) => 39,
        ("aarch64-unknown-linux-gnu", O::Socket) => 198,
        ("aarch64-unknown-linux-gnu", O::Socketpair) => 199,
        ("aarch64-unknown-linux-gnu", O::Sendmsg) => 211,
        ("aarch64-unknown-linux-gnu", O::IoUringSetup) => 425,
        ("aarch64-unknown-linux-gnu", O::PidfdGetfd) => 438,
        ("aarch64-unknown-linux-gnu", O::Setns) => 268,
        ("aarch64-unknown-linux-gnu", O::Unshare) => 97,
        ("aarch64-unknown-linux-gnu", O::Bind) => 200,
        ("aarch64-unknown-linux-gnu", O::Listen) => 201,
        ("aarch64-unknown-linux-gnu", O::Connect) => 203,
        ("aarch64-unknown-linux-gnu", O::Getpid) => 172,
        _ => {
            return Err(CiError::Message(
                "unreviewed native syscall table target".into(),
            ));
        }
    };
    Ok(value)
}

pub fn semantics_revision_sha256() -> DiagnosticSha256 {
    // Frozen source includes exact facts, syscall numbers and branch grammar.
    hash_bytes(include_bytes!("private_case_semantics.rs"))
}
