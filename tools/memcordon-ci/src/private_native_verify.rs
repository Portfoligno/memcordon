//! Versioned native release semantics. A structural artifact is never an
//! independent observation, and an absent kernel interval is a failed case.

use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseCaseResultV1, PrivateReleaseStageV1, REQUIRED_PRIVATE_RELEASE_SELECTORS_V1,
    private_release_case_key_v1,
};
use memcordon_core::workload_codec::hash_bytes;

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
            (F::Authorization, D::AllocatedAndRetired, false, true)
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
pub(crate) struct VerifiedCandidateSemanticsV2 {
    pub(crate) result_digests: Vec<DiagnosticSha256>,
    pub(crate) inventory_digests: Vec<DiagnosticSha256>,
    pub(crate) subject: crate::private_observer_session::ObserverSubjectV1,
    pub(crate) payload_index_sha256: DiagnosticSha256,
    pub(crate) origin_commitment_sha256: DiagnosticSha256,
    pub(crate) generation_timeline_sha256: DiagnosticSha256,
    pub(crate) completed_origin: bool,
}

/// Aggregates only closed family proofs reconstructed from exact enrolled
/// observer custody. No booleans, caller-chosen decisions or JSON token can
/// enter this boundary. Candidate and public capabilities remain distinct.
pub(crate) fn verify_candidate_semantics(
    session: &impl crate::private_observer_session::ObserverEvidenceV1,
    results: &[(Vec<u8>, PrivateReleaseCaseResultV1)],
    independent: &[crate::private_candidate_replay::VerifiedNativeCaseV1],
) -> Result<VerifiedCandidateSemanticsV2> {
    use crate::private_observer_session::ObserverStageV1;
    if session.descriptor().subject.stage != ObserverStageV1::Candidate
        || results.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
        || independent.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
    {
        return Err(CiError::Message(
            "native 25-case origin/semantic inventory is incomplete".into(),
        ));
    }
    let mut result_digests = Vec::with_capacity(results.len());
    let mut inventory_digests = Vec::with_capacity(results.len());
    for ((bytes, result), (selector, proof)) in results.iter().zip(
        REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
            .iter()
            .zip(independent),
    ) {
        let parsed = PrivateReleaseCaseResultV1::parse(bytes).map_err(CiError::Message)?;
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            selector,
            &result.challenge_bytes().map_err(CiError::Message)?,
        )
        .map_err(CiError::Message)?;
        let spec = crate::private_case_semantics::closed_candidate_case_spec(
            selector,
            &session.descriptor().subject.target,
        )?;
        let generation = session
            .descriptor()
            .generations
            .get(proof.generation() as usize)
            .ok_or_else(|| CiError::Message("native case generation is absent".into()))?;
        let installed = match &result.installed {
            memcordon_core::private_release_case_v1::PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch,candidate_manifest_sha256,installed_inspection_sha256 } =>
                installation_epoch == &generation.installation_epoch
                    && candidate_manifest_sha256 == &generation.installed_manifest_sha256
                    && installed_inspection_sha256 == &generation.installed_receipt_sha256,
            _ => false,
        };
        if parsed != *result
            || result.selector != *selector
            || proof.selector() != *selector
            || result.target != session.descriptor().subject.target
            || proof.result_key() != &key
            || proof.result_hash() != &hash_bytes(bytes)
            || proof.stage() != ObserverStageV1::Candidate
            || proof.origin_commitment_sha256 != *session.origin_commitment_sha256()
            || proof
                .branch_set()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != spec.branches
            || !installed
        {
            return Err(CiError::Message(
                "native all-25 exact family proof/installed subject differs".into(),
            ));
        }
        result_digests.push(hash_bytes(bytes));
        inventory_digests.push(proof.raw_commitment().clone());
    }
    Ok(VerifiedCandidateSemanticsV2 {
        result_digests,
        inventory_digests,
        subject: session.descriptor().subject.clone(),
        payload_index_sha256: session.payload_index_sha256().clone(),
        origin_commitment_sha256: session.origin_commitment_sha256().clone(),
        generation_timeline_sha256: session.generation_timeline_sha256().clone(),
        completed_origin: session.completed(),
    })
}
