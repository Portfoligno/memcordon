//! Versioned native release semantics. A structural artifact is never an
//! independent observation, and an absent kernel interval is a failed case.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseCaseResultV1, PrivateReleaseObservationV1, PrivateReleaseStageV1,
    REQUIRED_PRIVATE_RELEASE_SELECTORS_V1, private_release_case_key_v1,
};
use memcordon_core::workload_codec::hash_bytes;
use std::collections::BTreeSet;

use crate::private_kernel_observer::{
    AllocationBoundaryKindV1, KernelEventV1, VerifiedKernelIntervalV1,
};
use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseEvidenceFamilyV1 {
    AlternateAbi,
    UnixIntent,
    SyscallDenial,
    Authorization,
    HistoricalEpoch,
    Lifecycle,
    ChildCustody,
    DescriptorCustody,
    DualAttempt,
    ExecutableIdentity,
    HostState,
    NetworkSocket,
    NamespaceTopology,
    Terminal,
    RetirementFailure,
    Credentials,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredDispositionV1 {
    PreallocationDenied,
    PolicyComposite,
    AllocatedAndRetired,
    DualAllocatedAndRetired,
    ReuseBlockedThenRetired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseEvidenceRequirementsV1 {
    pub family: CaseEvidenceFamilyV1,
    pub disposition: RequiredDispositionV1,
    pub requires_kernel_interval: bool,
    pub requires_exec_event: bool,
    pub requires_live_barrier: bool,
}

/// The exact 25-name table is a semantics revision, not a claim that the
/// current candidate producer has physical coverage for every row.
pub fn case_evidence_requirements_v1(selector: &str) -> Option<CaseEvidenceRequirementsV1> {
    use CaseEvidenceFamilyV1 as F;
    use RequiredDispositionV1 as D;
    let (family, disposition, exec, live) = match selector {
        "private_tcp::abi_alternate_entry_denied" => {
            (F::AlternateAbi, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::af_unix_abstract_and_pathname_denied" => {
            (F::UnixIntent, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::af_unix_socketpair_denied" => {
            (F::SyscallDenial, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::authorization_uncertainty_retired" => {
            (F::Authorization, D::AllocatedAndRetired, true, true)
        }
        // V1 describes the positive/retired branch. The E0->E1 stale
        // preallocation rejection requires a new typed subrecord; this row
        // must remain unqualified until that physical branch is joined.
        "private_tcp::caller_identity_and_epoch_bound" => {
            (F::HistoricalEpoch, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::checkpoint_persisted_before_release" => {
            (F::Lifecycle, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::child_runtime_and_threads_retired" => {
            (F::ChildCustody, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::descriptor_table_and_stdio_bound" => {
            (F::DescriptorCustody, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::dual_attempt_namespace_isolation" => {
            (F::DualAttempt, D::DualAllocatedAndRetired, true, true)
        }
        "private_tcp::elf_ancestor_and_identity_pinned" => {
            (F::ExecutableIdentity, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::frontend_loss_retired" => (F::Lifecycle, D::AllocatedAndRetired, true, true),
        "private_tcp::guardian_loss_retired" => (F::Lifecycle, D::AllocatedAndRetired, true, true),
        "private_tcp::host_namespace_and_sysctl_unchanged" => {
            (F::HostState, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::io_uring_and_pidfd_import_denied" => {
            (F::SyscallDenial, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::namespace_reentry_denied" => {
            (F::SyscallDenial, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::native_filter_digest_and_abi_bound" => {
            (F::SyscallDenial, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::native_tcp_bind_listen_connect" => {
            (F::NetworkSocket, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::port_collision_same_namespace" => {
            (F::NetworkSocket, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::private_namespace_topology_exact" => {
            (F::NamespaceTopology, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::release_checkpoint_terminal_joined" => {
            (F::Terminal, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::retirement_failure_blocks_reuse" => {
            (F::RetirementFailure, D::ReuseBlockedThenRetired, true, true)
        }
        "private_tcp::scm_rights_and_precreated_socket_denied" => {
            (F::SyscallDenial, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::target_credentials_and_capabilities_dropped" => {
            (F::Credentials, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::target_exec_and_fd_leak_observed" => {
            (F::DescriptorCustody, D::AllocatedAndRetired, true, true)
        }
        "private_tcp::wrong_grant_profile_and_port_rejected" => {
            (F::Authorization, D::PolicyComposite, false, true)
        }
        _ => return None,
    };
    Some(CaseEvidenceRequirementsV1 {
        family,
        disposition,
        requires_kernel_interval: true,
        requires_exec_event: exec,
        requires_live_barrier: live,
    })
}

/// An observer record is deliberately not Deserialize. Only the reviewed
/// independent kernel/host adapter may eventually construct it; no current
/// artifact reader can do so. Its fields are private to the verifier module.
pub(crate) struct IndependentCaseObservationV1 {
    selector: String,
    result_sha256: DiagnosticSha256,
    kernel_interval: VerifiedKernelIntervalV1,
    required_decisions: Vec<crate::private_kernel_observer::KnownActionTupleV1>,
    live_barrier_observed: bool,
    retirement_complete: bool,
}

pub(crate) struct VerifiedCandidateSemanticsV2 {
    pub(crate) result_digests: Vec<DiagnosticSha256>,
}

/// Checks detached result identity and interval-level independent facts. The
/// family-specific kernel adapter must also check syscall tuples, endpoint
/// identities, ordering and controls before it can supply its private sample.
pub(crate) fn verify_candidate_semantics(
    results: &[(Vec<u8>, PrivateReleaseCaseResultV1)],
    independent: &[IndependentCaseObservationV1],
) -> Result<VerifiedCandidateSemanticsV2> {
    if results.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
        || independent.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
    {
        return Err(CiError::Message(
            "native 25-case evidence is incomplete".into(),
        ));
    }
    let mut digests = Vec::with_capacity(results.len());
    let mut boots = BTreeSet::new();
    for ((bytes, result), (selector, sample)) in results.iter().zip(
        REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
            .iter()
            .zip(independent),
    ) {
        let requirements = case_evidence_requirements_v1(selector)
            .ok_or_else(|| CiError::Message("native selector has no semantic contract".into()))?;
        let parsed = PrivateReleaseCaseResultV1::parse(bytes).map_err(CiError::Message)?;
        let challenge = result.challenge_bytes().map_err(CiError::Message)?;
        let result_key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            selector,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let events = sample.kernel_interval.events();
        let allocated = events.iter().any(|event| {
            matches!(event,
            KernelEventV1::AllocationBoundary {
                request_key,
                kind: AllocationBoundaryKindV1::Allocate,
                ..
            } if *request_key == result_key)
        });
        let decisions_required = matches!(
            requirements.family,
            CaseEvidenceFamilyV1::SyscallDenial | CaseEvidenceFamilyV1::AlternateAbi
        );
        let decisions_joined = (!decisions_required || !sample.required_decisions.is_empty())
            && sample.required_decisions.iter().all(|decision| {
                sample.kernel_interval.seccomp_decision(
                    decision.task,
                    decision.arch,
                    decision.syscall,
                    decision.action,
                )
            });
        let exec = events
            .iter()
            .any(|event| matches!(event, KernelEventV1::Exec { .. }));
        let policy_decision_only =
            requirements.disposition == RequiredDispositionV1::PolicyComposite;
        if parsed != *result
            || result.selector != *selector
            || sample.selector != *selector
            || sample.result_sha256 != hash_bytes(bytes)
            || sample.kernel_interval.boot_id().is_empty()
            || sample.kernel_interval.trace_sha256() == &hash_bytes(&[])
            || sample.kernel_interval.result_key() != &result_key
            || !decisions_joined && !policy_decision_only
            || !sample.kernel_interval.has_allocation_boundary()
            || requirements.requires_exec_event && !exec
            || requirements.requires_live_barrier && !sample.live_barrier_observed
            || !sample.retirement_complete
                && !policy_decision_only
                && requirements.disposition != RequiredDispositionV1::PreallocationDenied
            || ((requirements.disposition == RequiredDispositionV1::PreallocationDenied
                || policy_decision_only)
                && !sample.kernel_interval.no_allocation())
            || (requirements.disposition != RequiredDispositionV1::PreallocationDenied
                && !policy_decision_only
                && !allocated)
            || !matches!(result.installed, memcordon_core::private_release_case_v1::PrivateReleaseInstalledBindingV1::CandidateCapability { .. })
        {
            return Err(CiError::Message("native independent case semantics differ".into()));
        }
        let actual_disposition = match result.observation {
            PrivateReleaseObservationV1::PreallocationRejected { .. } => {
                RequiredDispositionV1::PreallocationDenied
            }
            PrivateReleaseObservationV1::PolicyComposite { .. } => {
                RequiredDispositionV1::PolicyComposite
            }
            PrivateReleaseObservationV1::AllocatedRetired { .. } => {
                RequiredDispositionV1::AllocatedAndRetired
            }
            PrivateReleaseObservationV1::AbiComposite { .. } => {
                RequiredDispositionV1::AllocatedAndRetired
            }
            PrivateReleaseObservationV1::DualAttemptsRetired { .. } => {
                RequiredDispositionV1::DualAllocatedAndRetired
            }
            PrivateReleaseObservationV1::RetirementFailureBlockedReuse { .. } => {
                RequiredDispositionV1::ReuseBlockedThenRetired
            }
        };
        if actual_disposition != requirements.disposition {
            return Err(CiError::Message("native case disposition differs".into()));
        }
        if matches!(
            requirements.family,
            CaseEvidenceFamilyV1::AlternateAbi | CaseEvidenceFamilyV1::HistoricalEpoch
        ) || *selector == "private_tcp::wrong_grant_profile_and_port_rejected"
        {
            return Err(CiError::Message(format!(
                "native {selector} lacks a joined independent branch transcript and complete kernel interval"
            )));
        }
        boots.insert(sample.kernel_interval.boot_id());
        digests.push(hash_bytes(bytes));
    }
    if boots.len() != 1 {
        return Err(CiError::Message(
            "native host session differs across cases".into(),
        ));
    }
    Ok(VerifiedCandidateSemanticsV2 {
        result_digests: digests,
    })
}
