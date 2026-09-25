//! Protected release-case run custody, distinct from the installed H1 canary.
//! A directory and request record are never case completion or Q provenance.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Instant;

use memcordon_core::DiagnosticSha256;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_case::{ReleaseCaseRequestV1, ReleaseStageV1};

const ROOT_LEAF: &str = "private-release-cases";
const REQUEST_LEAF: &str = "request.json";
const REQUEST_TEMP: &str = "request.json.new";
const MAX_REQUEST_BYTES: usize = 4096;

pub(crate) struct PreparedReleaseCandidateRunV1 {
    pub(crate) directory: File,
    pub(crate) request: ReleaseCaseRequestV1,
}

/// The detached service owns this after independently rechecking process
/// exit, cgroup removal, exact selector output, and protected raw bytes. It
/// is not Q provenance; CI must independently join the full native suite.
pub(crate) struct DetachedCandidateReadbackV1 {
    pub(crate) root: File,
    pub(crate) package: crate::package::VerifiedReleaseCandidatePackageLease,
    pub(crate) selector: &'static str,
    pub(crate) challenge: [u8; 32],
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) service_generation_sha256: DiagnosticSha256,
    pub(crate) coordinator: ProcessIdentityV4,
    pub(crate) native: super::private_release_attempt::RetiredCandidateNativeIdentitiesV1,
    pub(crate) journal: super::private_release_attempt::ReadbackRetiredCandidateAttemptV1,
    pub(crate) installed_inspection_sha256: DiagnosticSha256,
    pub(crate) attachment_inventory:
        Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>,
}

/// Two independently retired candidate attempts under one release-case key.
/// This cannot be projected into a single-attempt result observation.
#[allow(dead_code)] // Enabled only with the distinct dual result constructor.
pub(crate) struct DetachedDualCandidateReadbackV1 {
    pub(crate) root: File,
    pub(crate) package: crate::package::VerifiedReleaseCandidatePackageLease,
    pub(crate) challenge: [u8; 32],
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) service_generation_sha256: DiagnosticSha256,
    pub(crate) coordinator: ProcessIdentityV4,
    pub(crate) worker: ProcessIdentityV4,
    pub(crate) first_native: super::private_release_attempt::RetiredCandidateNativeIdentitiesV1,
    pub(crate) second_native: super::private_release_attempt::RetiredCandidateNativeIdentitiesV1,
    pub(crate) first_journal: super::private_release_attempt::ReadbackRetiredCandidateAttemptV1,
    pub(crate) second_journal: super::private_release_attempt::ReadbackRetiredCandidateAttemptV1,
    pub(crate) installed_inspection_sha256: DiagnosticSha256,
    pub(crate) attachment_inventory:
        Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>,
}

/// Separate from ordinary completed-target readback: the protected
/// pre-release gate witness is mandatory and bound to the final journal.
#[allow(dead_code)]
pub(crate) struct DetachedCheckpointGateReadbackV1 {
    pub(crate) ordinary: DetachedCandidateReadbackV1,
    pub(crate) gate_sha256: DiagnosticSha256,
}

/// A distinct post-coordinator-exit child/thread readback. The target's
/// reported IDs are joined to worker pidfd/proc observations and independently
/// rechecked for retirement before this type can be constructed.
#[allow(dead_code)]
pub(crate) struct DetachedChildReadbackV1 {
    pub(crate) ordinary: DetachedCandidateReadbackV1,
}

/// Separate detached readback for the sealed precreated-socket case. Its
/// protected gate and CI acknowledgment are mandatory before authorization.
pub(crate) struct DetachedSocketReadbackV1 {
    pub(crate) ordinary: DetachedCandidateReadbackV1,
}

/// The detached reader independently joins the persisted live ExecObserved
/// midpoint, CI acknowledgment, final terminal journal and cleanup evidence.
pub(crate) struct DetachedTerminalJoinReadbackV1 {
    pub(crate) ordinary: DetachedCandidateReadbackV1,
}

/// A separate detached readback for the conservative transport-loss branch.
/// It is not convertible into a normal completed-target result or Q token.
#[allow(dead_code)] // Consumed after the coordinator uncertainty route lands.
pub(crate) struct DetachedUncertainCandidateReadbackV1 {
    pub(crate) root: File,
    pub(crate) package: crate::package::VerifiedReleaseCandidatePackageLease,
    pub(crate) selector: &'static str,
    pub(crate) challenge: [u8; 32],
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) service_generation_sha256: DiagnosticSha256,
    pub(crate) coordinator: ProcessIdentityV4,
    pub(crate) native: super::private_release_attempt::RetiredCandidateNativeIdentitiesV1,
    pub(crate) journal: super::private_release_attempt::ReadbackRetiredCandidateAttemptV1,
    pub(crate) installed_inspection_sha256: DiagnosticSha256,
    pub(crate) attachment_inventory:
        Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>,
}

/// The fault branch proves physical workload settlement while deliberately
/// retaining a nonterminal durable journal. The exact same-key allocator
/// rejection is re-executed during detached readback.
#[allow(dead_code)] // Result constructor is not connected yet.
pub(crate) struct DetachedBlockedRetirementReadbackV1 {
    pub(crate) root: File,
    pub(crate) package: crate::package::VerifiedReleaseCandidatePackageLease,
    pub(crate) selector: &'static str,
    pub(crate) challenge: [u8; 32],
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) service_generation_sha256: DiagnosticSha256,
    pub(crate) coordinator: ProcessIdentityV4,
    pub(crate) native: super::private_release_attempt::RetiredCandidateNativeIdentitiesV1,
    pub(crate) blocked: super::private_release_attempt::ReadbackBlockedCandidateAttemptV1,
    pub(crate) installed_inspection_sha256: DiagnosticSha256,
    pub(crate) attachment_inventory:
        Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>,
}

/// A post-coordinator-exit guardian-loss readback. The owner trace alone is
/// insufficient: service-owned process/cgroup and protected byte joins must
/// also succeed before a fault result may be constructed.
pub(crate) struct DetachedGuardianLossReadbackV1 {
    pub(crate) root: File,
    pub(crate) package: crate::package::VerifiedReleaseCandidatePackageLease,
    pub(crate) selector: &'static str,
    pub(crate) challenge: [u8; 32],
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) service_generation_sha256: DiagnosticSha256,
    pub(crate) coordinator: ProcessIdentityV4,
    pub(crate) native: super::private_release_attempt::RetiredCandidateNativeIdentitiesV1,
    pub(crate) journal: super::private_release_attempt::ReadbackRetiredCandidateAttemptV1,
    pub(crate) installed_inspection_sha256: DiagnosticSha256,
    pub(crate) attachment_inventory:
        Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>,
}

/// Service-owned post-coordinator-exit frontend-loss readback. A retained
/// release-domain proxy identity and guardian terminal are required; H1 loss
/// records cannot inhabit this type.
pub(crate) struct DetachedFrontendLossReadbackV1 {
    pub(crate) root: File,
    pub(crate) package: crate::package::VerifiedReleaseCandidatePackageLease,
    pub(crate) selector: &'static str,
    pub(crate) challenge: [u8; 32],
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) service_generation_sha256: DiagnosticSha256,
    pub(crate) coordinator: ProcessIdentityV4,
    pub(crate) native: super::private_release_attempt::RetiredCandidateNativeIdentitiesV1,
    pub(crate) journal: super::private_release_attempt::ReadbackRetiredCandidateAttemptV1,
    pub(crate) installed_inspection_sha256: DiagnosticSha256,
    pub(crate) attachment_inventory:
        Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>,
}

pub(crate) fn verify_detached_frontend_loss_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedFrontendLossReadbackV1, String> {
    if unsafe { libc::geteuid() } != 0
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != super::private_release_frontend_loss::SELECTOR
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached frontend-loss authority differs".into());
    }
    let package = crate::package::acquire_verified_release_candidate_package_lease()?;
    let service = super::private_host_prerequisites::observe_service_generation()?;
    if service.main().pid != unsafe { libc::getppid() } as u32 {
        return Err(
            "MCSEALED-PRIVATE-RELEASE: detached frontend-loss reader not service-owned".into(),
        );
    }
    super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
    let root = open_or_create_root()?;
    let directory = open_case_directory(&root, &request.result_key(), 0)?;
    let recorded = read_request(&directory, 0)?;
    let expected = protected_request(
        request,
        &package,
        service.digest()?,
        recorded.coordinator.clone(),
    );
    if recorded != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss protected request differs".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    let expected_journal = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
        result_key: &recorded.result_key,
        selector: &recorded.selector,
        challenge: &request.challenge,
        installation_epoch: &recorded.installation_epoch,
        candidate_manifest_sha256: &recorded.candidate_manifest_sha256,
        service_generation_sha256: &recorded.service_generation_sha256,
        coordinator: &recorded.coordinator,
    };
    let journal = super::private_release_attempt::read_retired_frontend_loss_candidate_journal(
        &directory,
        &expected_journal,
    )?;
    let native = journal.native_identities()?;
    let frontend = native
        .frontend_proxy
        .as_ref()
        .ok_or("MCSEALED-PRIVATE-RELEASE: frontend-loss proxy absent")?;
    if frontend == &recorded.coordinator {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss proxy is coordinator".into());
    }
    for process in [
        frontend,
        &native.guardian,
        &native.namespace_init,
        &native.target,
    ] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&journal.attempt_id)?;
    let inspection = package.installed_inspection_bytes()?;
    let response = super::private_release_frontend_loss::armed_response(&request.challenge);
    let attachment_inventory = super::private_release_raw::readback_frontend_loss_raw(
        super::private_release_raw::CandidateRawContextV1 {
            directory: &directory,
            selector: request.selector,
            result_key: &recorded.result_key,
            challenge: &request.challenge,
            expected_response: &response,
            installed_inspection_bytes: &inspection,
            agent_path_snapshot: None,
        },
        &journal,
        &recorded.coordinator,
        &recorded.service_generation_sha256,
    )?;
    let journal_again =
        super::private_release_attempt::read_retired_frontend_loss_candidate_journal(
            &directory,
            &expected_journal,
        )?;
    if journal_again.terminal_bytes != journal.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss journal changed".into());
    }
    let current_service = super::private_host_prerequisites::observe_service_generation()?;
    super::private_host_prerequisites::require_current_worker_cgroup(&current_service)?;
    if current_service.digest()? != recorded.service_generation_sha256
        || crate::package::installed_generation_epoch()? != recorded.installation_epoch
        || read_request(&directory, 0)? != recorded
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached frontend-loss host changed".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    for process in [
        frontend,
        &native.guardian,
        &native.namespace_init,
        &native.target,
    ] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&journal.attempt_id)?;
    Ok(DetachedFrontendLossReadbackV1 {
        root,
        package,
        selector: request.selector,
        challenge: request.challenge,
        result_key: recorded.result_key,
        service_generation_sha256: recorded.service_generation_sha256,
        coordinator: recorded.coordinator,
        native,
        journal,
        installed_inspection_sha256: memcordon_core::workload_codec::hash_bytes(&inspection),
        attachment_inventory,
    })
}

pub(crate) fn verify_detached_guardian_loss_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedGuardianLossReadbackV1, String> {
    if unsafe { libc::geteuid() } != 0
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != super::private_release_guardian_loss::SELECTOR
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached guardian-loss authority differs".into());
    }
    let package = crate::package::acquire_verified_release_candidate_package_lease()?;
    let service = super::private_host_prerequisites::observe_service_generation()?;
    if service.main().pid != unsafe { libc::getppid() } as u32 {
        return Err(
            "MCSEALED-PRIVATE-RELEASE: detached guardian-loss reader not service-owned".into(),
        );
    }
    super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
    let root = open_or_create_root()?;
    let directory = open_case_directory(&root, &request.result_key(), 0)?;
    let recorded = read_request(&directory, 0)?;
    let expected = protected_request(
        request,
        &package,
        service.digest()?,
        recorded.coordinator.clone(),
    );
    if recorded != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss protected request differs".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    let expected_journal = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
        result_key: &recorded.result_key,
        selector: &recorded.selector,
        challenge: &request.challenge,
        installation_epoch: &recorded.installation_epoch,
        candidate_manifest_sha256: &recorded.candidate_manifest_sha256,
        service_generation_sha256: &recorded.service_generation_sha256,
        coordinator: &recorded.coordinator,
    };
    let journal = super::private_release_attempt::read_retired_guardian_loss_candidate_journal(
        &directory,
        &expected_journal,
    )?;
    let native = journal.native_identities()?;
    for process in [&native.guardian, &native.namespace_init, &native.target] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&journal.attempt_id)?;
    let inspection = package.installed_inspection_bytes()?;
    let response = super::private_release_guardian_loss::armed_response(&request.challenge);
    let attachment_inventory = super::private_release_raw::readback_guardian_loss_raw(
        super::private_release_raw::CandidateRawContextV1 {
            directory: &directory,
            selector: request.selector,
            result_key: &recorded.result_key,
            challenge: &request.challenge,
            expected_response: &response,
            installed_inspection_bytes: &inspection,
            agent_path_snapshot: None,
        },
        &journal,
        &recorded.coordinator,
        &recorded.service_generation_sha256,
    )?;
    let journal_again =
        super::private_release_attempt::read_retired_guardian_loss_candidate_journal(
            &directory,
            &expected_journal,
        )?;
    if journal_again.terminal_bytes != journal.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss journal changed".into());
    }
    let current_service = super::private_host_prerequisites::observe_service_generation()?;
    super::private_host_prerequisites::require_current_worker_cgroup(&current_service)?;
    if current_service.digest()? != recorded.service_generation_sha256
        || crate::package::installed_generation_epoch()? != recorded.installation_epoch
        || read_request(&directory, 0)? != recorded
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached guardian-loss host changed".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    for process in [&native.guardian, &native.namespace_init, &native.target] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&journal.attempt_id)?;
    Ok(DetachedGuardianLossReadbackV1 {
        root,
        package,
        selector: request.selector,
        challenge: request.challenge,
        result_key: recorded.result_key,
        service_generation_sha256: recorded.service_generation_sha256,
        coordinator: recorded.coordinator,
        native,
        journal,
        installed_inspection_sha256: memcordon_core::workload_codec::hash_bytes(&inspection),
        attachment_inventory,
    })
}

#[allow(dead_code)] // Service finalizer route remains closed until result semantics join.
pub(crate) fn verify_detached_blocked_retirement_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedBlockedRetirementReadbackV1, String> {
    if unsafe { libc::geteuid() } != 0
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != super::private_release_case::RETIREMENT_FAULT_SELECTOR
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached blocked authority differs".into());
    }
    let package = crate::package::acquire_verified_release_candidate_package_lease()?;
    let service = super::private_host_prerequisites::observe_service_generation()?;
    if service.main().pid != unsafe { libc::getppid() } as u32 {
        return Err("MCSEALED-PRIVATE-RELEASE: detached blocked reader not service-owned".into());
    }
    super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
    let root = open_or_create_root()?;
    let directory = open_case_directory(&root, &request.result_key(), 0)?;
    let recorded = read_request(&directory, 0)?;
    let expected = protected_request(
        request,
        &package,
        service.digest()?,
        recorded.coordinator.clone(),
    );
    if recorded != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked protected request differs".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    let expected_journal = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
        result_key: &recorded.result_key,
        selector: &recorded.selector,
        challenge: &request.challenge,
        installation_epoch: &recorded.installation_epoch,
        candidate_manifest_sha256: &recorded.candidate_manifest_sha256,
        service_generation_sha256: &recorded.service_generation_sha256,
        coordinator: &recorded.coordinator,
    };
    let blocked = super::private_release_attempt::read_blocked_retirement_candidate_journal(
        &directory,
        &expected_journal,
    )?;
    let native = blocked.native_identities()?;
    for process in [&native.guardian, &native.namespace_init, &native.target] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&blocked.journal.attempt_id)?;
    let inspection = package.installed_inspection_bytes()?;
    let response = super::private_release_case::candidate_fixture_output_with_native(
        request.selector,
        &request.challenge,
        native.network_namespace_inode,
        package.agent_file_identity()?,
    )?;
    let attachment_inventory = super::private_release_raw::readback_blocked_retirement_raw(
        super::private_release_raw::CandidateRawContextV1 {
            directory: &directory,
            selector: request.selector,
            result_key: &recorded.result_key,
            challenge: &request.challenge,
            expected_response: &response,
            installed_inspection_bytes: &inspection,
            agent_path_snapshot: None,
        },
        &blocked,
        &recorded.coordinator,
        &recorded.service_generation_sha256,
    )?;
    let blocked_again = super::private_release_attempt::read_blocked_retirement_candidate_journal(
        &directory,
        &expected_journal,
    )?;
    if blocked_again.journal.terminal_bytes != blocked.journal.terminal_bytes
        || blocked_again.fault_marker_bytes != blocked.fault_marker_bytes
        || blocked_again.detached_reuse_error != blocked.detached_reuse_error
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked journal changed".into());
    }
    let current_service = super::private_host_prerequisites::observe_service_generation()?;
    super::private_host_prerequisites::require_current_worker_cgroup(&current_service)?;
    if current_service.digest()? != recorded.service_generation_sha256
        || crate::package::installed_generation_epoch()? != recorded.installation_epoch
        || read_request(&directory, 0)? != recorded
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached blocked host changed".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    for process in [&native.guardian, &native.namespace_init, &native.target] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&blocked.journal.attempt_id)?;
    Ok(DetachedBlockedRetirementReadbackV1 {
        root,
        package,
        selector: request.selector,
        challenge: request.challenge,
        result_key: recorded.result_key,
        service_generation_sha256: recorded.service_generation_sha256,
        coordinator: recorded.coordinator,
        native,
        blocked,
        installed_inspection_sha256: memcordon_core::workload_codec::hash_bytes(&inspection),
        attachment_inventory,
    })
}

/// The service calls this only after its coordinator child has exited. The
/// protected worker trace remains diagnostic until this independent process,
/// cgroup, request and raw-byte join succeeds.
#[allow(dead_code)] // Result publication remains closed until stage semantics join.
pub(crate) fn verify_detached_uncertain_candidate_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedUncertainCandidateReadbackV1, String> {
    if unsafe { libc::geteuid() } != 0
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached uncertainty authority differs".into());
    }
    let package = crate::package::acquire_verified_release_candidate_package_lease()?;
    let service = super::private_host_prerequisites::observe_service_generation()?;
    if service.main().pid != unsafe { libc::getppid() } as u32 {
        return Err(
            "MCSEALED-PRIVATE-RELEASE: detached uncertainty reader not service-owned".into(),
        );
    }
    super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
    let root = open_or_create_root()?;
    let directory = open_case_directory(&root, &request.result_key(), 0)?;
    let recorded = read_request(&directory, 0)?;
    let expected = protected_request(
        request,
        &package,
        service.digest()?,
        recorded.coordinator.clone(),
    );
    if recorded != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain protected request differs".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    let expected_journal = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
        result_key: &recorded.result_key,
        selector: &recorded.selector,
        challenge: &request.challenge,
        installation_epoch: &recorded.installation_epoch,
        candidate_manifest_sha256: &recorded.candidate_manifest_sha256,
        service_generation_sha256: &recorded.service_generation_sha256,
        coordinator: &recorded.coordinator,
    };
    let journal = super::private_release_attempt::read_retired_uncertain_candidate_journal(
        &directory,
        &expected_journal,
    )?;
    let native = journal.native_identities()?;
    for process in [&native.guardian, &native.namespace_init, &native.target] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&journal.attempt_id)?;
    let inspection = package.installed_inspection_bytes()?;
    let attachment_inventory = super::private_release_raw::readback_uncertain_candidate_raw(
        super::private_release_raw::CandidateRawContextV1 {
            directory: &directory,
            selector: request.selector,
            result_key: &recorded.result_key,
            challenge: &request.challenge,
            expected_response: b"",
            installed_inspection_bytes: &inspection,
            agent_path_snapshot: None,
        },
        &journal,
        &recorded.coordinator,
        &recorded.service_generation_sha256,
    )?;
    let journal_again = super::private_release_attempt::read_retired_uncertain_candidate_journal(
        &directory,
        &expected_journal,
    )?;
    if journal_again.terminal_bytes != journal.terminal_bytes
        || journal_again.terminal_record_digest != journal.terminal_record_digest
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached uncertainty journal changed".into());
    }
    let current_service = super::private_host_prerequisites::observe_service_generation()?;
    super::private_host_prerequisites::require_current_worker_cgroup(&current_service)?;
    if current_service.digest()? != recorded.service_generation_sha256
        || crate::package::installed_generation_epoch()? != recorded.installation_epoch
        || read_request(&directory, 0)? != recorded
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached uncertainty host changed".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    for process in [&native.guardian, &native.namespace_init, &native.target] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&journal.attempt_id)?;
    Ok(DetachedUncertainCandidateReadbackV1 {
        root,
        package,
        selector: request.selector,
        challenge: request.challenge,
        result_key: recorded.result_key,
        service_generation_sha256: recorded.service_generation_sha256,
        coordinator: recorded.coordinator,
        native,
        journal,
        installed_inspection_sha256: memcordon_core::workload_codec::hash_bytes(&inspection),
        attachment_inventory,
    })
}

pub(crate) fn verify_detached_candidate_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedCandidateReadbackV1, String> {
    verify_detached_completed_case(request, CompletedReadbackKindV1::Ordinary)
        .map(|(readback, _)| readback)
}

#[allow(dead_code)]
pub(crate) fn verify_detached_checkpoint_gate_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedCheckpointGateReadbackV1, String> {
    let (ordinary, gate_sha256) =
        verify_detached_completed_case(request, CompletedReadbackKindV1::CheckpointGate)?;
    Ok(DetachedCheckpointGateReadbackV1 {
        ordinary,
        gate_sha256: gate_sha256.ok_or_else(|| {
            "MCSEALED-PRIVATE-RELEASE: checkpoint-gate detached witness absent".to_owned()
        })?,
    })
}

#[allow(dead_code)] // Enabled with the fixed child/thread finalizer.
pub(crate) fn verify_detached_child_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedChildReadbackV1, String> {
    let (ordinary, gate_sha256) =
        verify_detached_completed_case(request, CompletedReadbackKindV1::ChildRuntime)?;
    if gate_sha256.is_some() {
        return Err("MCSEALED-PRIVATE-RELEASE: child readback reused gate witness".into());
    }
    Ok(DetachedChildReadbackV1 { ordinary })
}

pub(crate) fn verify_detached_socket_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedSocketReadbackV1, String> {
    let (ordinary, gate_sha256) =
        verify_detached_completed_case(request, CompletedReadbackKindV1::PrecreatedSocket)?;
    if gate_sha256.is_some() {
        return Err("MCSEALED-PRIVATE-RELEASE: socket readback reused checkpoint gate".into());
    }
    Ok(DetachedSocketReadbackV1 { ordinary })
}

pub(crate) fn verify_detached_terminal_join_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedTerminalJoinReadbackV1, String> {
    let (ordinary, gate_sha256) =
        verify_detached_completed_case(request, CompletedReadbackKindV1::TerminalJoin)?;
    if gate_sha256.is_some() {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join reused checkpoint gate".into());
    }
    Ok(DetachedTerminalJoinReadbackV1 { ordinary })
}

#[derive(Clone, Copy)]
enum CompletedReadbackKindV1 {
    Ordinary,
    ClosedUnixIntent,
    CheckpointGate,
    ChildRuntime,
    PrecreatedSocket,
    TerminalJoin,
}

/// Detached protected readback only. This deliberately does not construct a
/// publishable release result or make the AF_UNIX selector suite-eligible.
pub(crate) fn verify_detached_closed_unix_intent(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedCandidateReadbackV1, String> {
    let (readback, gate) =
        verify_detached_completed_case(request, CompletedReadbackKindV1::ClosedUnixIntent)?;
    if gate.is_some() {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix intent reused checkpoint gate".into());
    }
    Ok(readback)
}

fn verify_detached_completed_case(
    request: &ReleaseCaseRequestV1,
    kind: CompletedReadbackKindV1,
) -> Result<(DetachedCandidateReadbackV1, Option<DiagnosticSha256>), String> {
    let checkpoint_gate = matches!(kind, CompletedReadbackKindV1::CheckpointGate);
    if unsafe { libc::geteuid() } != 0
        || request.stage != ReleaseStageV1::CandidateCapability
        || match kind {
            CompletedReadbackKindV1::Ordinary => {
                !super::private_release_case::candidate_fixture_supported(request.selector)
            }
            CompletedReadbackKindV1::ClosedUnixIntent => {
                request.selector != super::private_release_unix_intent::SELECTOR
            }
            CompletedReadbackKindV1::CheckpointGate => {
                request.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR
            }
            CompletedReadbackKindV1::ChildRuntime => {
                request.selector != super::private_release_children::SELECTOR
            }
            CompletedReadbackKindV1::PrecreatedSocket => {
                request.selector != super::private_release_socket_launder::SELECTOR
            }
            CompletedReadbackKindV1::TerminalJoin => {
                request.selector != super::private_release_terminal_join::SELECTOR
            }
        }
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached selector authority differs".into());
    }
    let package = crate::package::acquire_verified_release_candidate_package_lease()?;
    let service = super::private_host_prerequisites::observe_service_generation()?;
    if service.main().pid != unsafe { libc::getppid() } as u32 {
        return Err("MCSEALED-PRIVATE-RELEASE: detached reader is not service-owned".into());
    }
    super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
    let root = open_or_create_root()?;
    let directory = open_case_directory(&root, &request.result_key(), 0)?;
    let recorded = read_request(&directory, 0)?;
    let expected = protected_request(
        request,
        &package,
        service.digest()?,
        recorded.coordinator.clone(),
    );
    if recorded != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: detached protected request differs".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    let expected_journal = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
        result_key: &recorded.result_key,
        selector: &recorded.selector,
        challenge: &request.challenge,
        installation_epoch: &recorded.installation_epoch,
        candidate_manifest_sha256: &recorded.candidate_manifest_sha256,
        service_generation_sha256: &recorded.service_generation_sha256,
        coordinator: &recorded.coordinator,
    };
    let journal = super::private_release_attempt::read_retired_candidate_journal(
        &directory,
        &expected_journal,
    )?;
    let native = journal.native_identities()?;
    let terminal_join_gate = if matches!(kind, CompletedReadbackKindV1::TerminalJoin) {
        Some(super::private_release_terminal_gate::readback_gate_and_ack(
            &directory,
            &expected_journal,
            &native.target,
            &journal.checkpoint_digest,
            &journal.filter_digest()?,
        )?)
    } else {
        None
    };
    let gate_sha256 = if checkpoint_gate {
        let witness = super::private_release_gate::CheckpointGateWitnessV1::readback(
            &directory,
            &expected_journal,
        )?;
        if witness.checkpoint_digest() != &journal.checkpoint_digest
            || witness.target() != &native.target
        {
            return Err("MCSEALED-PRIVATE-RELEASE: detached checkpoint gate differs".into());
        }
        Some(witness.digest()?)
    } else {
        None
    };
    for process in [&native.guardian, &native.namespace_init, &native.target] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&journal.attempt_id)?;
    let inspection = package.installed_inspection_bytes()?;
    let response = if matches!(kind, CompletedReadbackKindV1::ClosedUnixIntent) {
        super::private_release_unix_intent::expected_observation_bytes(&request.challenge)?
    } else if matches!(
        kind,
        CompletedReadbackKindV1::ChildRuntime | CompletedReadbackKindV1::TerminalJoin
    ) {
        Vec::new()
    } else if checkpoint_gate {
        super::private_release_case::candidate_fixture_response(
            request.selector,
            &request.challenge,
        )
        .to_vec()
    } else {
        super::private_release_case::candidate_fixture_output_with_native(
            request.selector,
            &request.challenge,
            native.network_namespace_inode,
            package.agent_file_identity()?,
        )?
    };
    let agent_path_snapshot = (request.selector == super::private_release_ancestor::SELECTOR)
        .then(|| super::private_release_ancestor::ProtectedAgentPathV1::capture(&package))
        .transpose()?;
    let raw_context = super::private_release_raw::CandidateRawContextV1 {
        directory: &directory,
        selector: request.selector,
        result_key: &recorded.result_key,
        challenge: &request.challenge,
        expected_response: &response,
        installed_inspection_bytes: &inspection,
        agent_path_snapshot: agent_path_snapshot.as_ref(),
    };
    let attachment_inventory = match kind {
        CompletedReadbackKindV1::CheckpointGate => {
            super::private_release_raw::readback_checkpoint_gate_raw(
                raw_context,
                &journal,
                &recorded.coordinator,
                &recorded.service_generation_sha256,
            )?
        }
        CompletedReadbackKindV1::ChildRuntime => super::private_release_raw::readback_child_raw(
            raw_context,
            &journal,
            &recorded.coordinator,
            &recorded.service_generation_sha256,
        )?,
        CompletedReadbackKindV1::PrecreatedSocket => {
            super::private_release_socket_raw::readback_raw(
                raw_context,
                &journal,
                &recorded.coordinator,
                &recorded.service_generation_sha256,
            )?
        }
        CompletedReadbackKindV1::TerminalJoin => {
            let (gate, midflight) = terminal_join_gate
                .as_ref()
                .ok_or("MCSEALED-PRIVATE-RELEASE: terminal-join midpoint absent")?;
            super::private_release_terminal_raw::readback_raw(
                raw_context,
                &journal,
                &recorded.coordinator,
                &recorded.service_generation_sha256,
                gate,
                midflight,
            )?
        }
        CompletedReadbackKindV1::Ordinary | CompletedReadbackKindV1::ClosedUnixIntent => {
            super::private_release_raw::readback_candidate_raw(
                raw_context,
                &journal,
                &recorded.coordinator,
                &recorded.service_generation_sha256,
            )?
        }
    };
    let journal_again = super::private_release_attempt::read_retired_candidate_journal(
        &directory,
        &expected_journal,
    )?;
    if journal_again.terminal_bytes != journal.terminal_bytes
        || journal_again.terminal_record_digest != journal.terminal_record_digest
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached journal changed during readback".into());
    }
    if checkpoint_gate {
        let witness = super::private_release_gate::CheckpointGateWitnessV1::readback(
            &directory,
            &expected_journal,
        )?;
        if Some(witness.digest()?) != gate_sha256 {
            return Err("MCSEALED-PRIVATE-RELEASE: detached gate leaf changed".into());
        }
    }
    let current_service = super::private_host_prerequisites::observe_service_generation()?;
    super::private_host_prerequisites::require_current_worker_cgroup(&current_service)?;
    if current_service.digest()? != recorded.service_generation_sha256
        || crate::package::installed_generation_epoch()? != recorded.installation_epoch
        || read_request(&directory, 0)? != recorded
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached host generation changed".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    for process in [&native.guardian, &native.namespace_init, &native.target] {
        require_recorded_process_exited(process)?;
    }
    require_candidate_cgroup_absent(&journal.attempt_id)?;
    if matches!(kind, CompletedReadbackKindV1::ChildRuntime)
        && super::private_release_raw::readback_child_raw(
            raw_context,
            &journal,
            &recorded.coordinator,
            &recorded.service_generation_sha256,
        )? != attachment_inventory
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached child evidence changed".into());
    }
    if matches!(kind, CompletedReadbackKindV1::PrecreatedSocket)
        && super::private_release_socket_raw::readback_raw(
            raw_context,
            &journal,
            &recorded.coordinator,
            &recorded.service_generation_sha256,
        )? != attachment_inventory
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached socket evidence changed".into());
    }
    if matches!(kind, CompletedReadbackKindV1::TerminalJoin) {
        let current_midpoint = super::private_release_terminal_gate::readback_gate_and_ack(
            &directory,
            &expected_journal,
            &native.target,
            &journal.checkpoint_digest,
            &journal.filter_digest()?,
        )?;
        if terminal_join_gate.as_ref() != Some(&current_midpoint)
            || super::private_release_terminal_raw::readback_raw(
                raw_context,
                &journal,
                &recorded.coordinator,
                &recorded.service_generation_sha256,
                &current_midpoint.0,
                &current_midpoint.1,
            )? != attachment_inventory
        {
            return Err("MCSEALED-PRIVATE-RELEASE: detached terminal-join evidence changed".into());
        }
    }
    Ok((
        DetachedCandidateReadbackV1 {
            root,
            package,
            selector: request.selector,
            challenge: request.challenge,
            result_key: recorded.result_key,
            service_generation_sha256: recorded.service_generation_sha256,
            coordinator: recorded.coordinator,
            native,
            journal,
            installed_inspection_sha256: memcordon_core::workload_codec::hash_bytes(&inspection),
            attachment_inventory,
        },
        gate_sha256,
    ))
}

/// Only the detached service may construct two-sided diagnostic readback.
/// It reopens both separate retired journals after the coordinator has exited
/// and checks process/cgroup absence before and after protected raw readback.
#[allow(dead_code)] // Dual selector dispatch remains closed until its result route is connected.
pub(crate) fn verify_detached_dual_candidate_case(
    request: &ReleaseCaseRequestV1,
) -> Result<DetachedDualCandidateReadbackV1, String> {
    if unsafe { libc::geteuid() } != 0
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != super::private_release_dual_attempt::SELECTOR
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached dual authority differs".into());
    }
    let package = crate::package::acquire_verified_release_candidate_package_lease()?;
    let service = super::private_host_prerequisites::observe_service_generation()?;
    if service.main().pid != unsafe { libc::getppid() } as u32 {
        return Err("MCSEALED-PRIVATE-RELEASE: detached dual reader not service-owned".into());
    }
    super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
    let root = open_or_create_root()?;
    let directory = open_case_directory(&root, &request.result_key(), 0)?;
    let recorded = read_request(&directory, 0)?;
    let expected = protected_request(
        request,
        &package,
        service.digest()?,
        recorded.coordinator.clone(),
    );
    if recorded != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: detached dual request differs".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    let first_key = super::private_release_dual_attempt::subattempt_key(
        &recorded.result_key,
        super::private_release_dual_attempt::DualAttemptRoleV1::First,
    );
    let second_key = super::private_release_dual_attempt::subattempt_key(
        &recorded.result_key,
        super::private_release_dual_attempt::DualAttemptRoleV1::Second,
    );
    let first_expected = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
        result_key: &first_key,
        selector: request.selector,
        challenge: &request.challenge,
        installation_epoch: &recorded.installation_epoch,
        candidate_manifest_sha256: &recorded.candidate_manifest_sha256,
        service_generation_sha256: &recorded.service_generation_sha256,
        coordinator: &recorded.coordinator,
    };
    let second_expected = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
        result_key: &second_key,
        selector: request.selector,
        challenge: &request.challenge,
        installation_epoch: &recorded.installation_epoch,
        candidate_manifest_sha256: &recorded.candidate_manifest_sha256,
        service_generation_sha256: &recorded.service_generation_sha256,
        coordinator: &recorded.coordinator,
    };
    let first_directory = super::private_release_dual_attempt::open_child(
        &directory,
        super::private_release_dual_attempt::DualAttemptRoleV1::First,
    )?;
    let second_directory = super::private_release_dual_attempt::open_child(
        &directory,
        super::private_release_dual_attempt::DualAttemptRoleV1::Second,
    )?;
    let gate = super::private_release_dual_gate::readback_gate_and_ack(
        &directory,
        &recorded.result_key,
        &request.challenge,
        &first_expected,
        &second_expected,
    )?;
    let first = super::private_release_attempt::read_retired_candidate_journal(
        &first_directory,
        &first_expected,
    )?;
    let second = super::private_release_attempt::read_retired_candidate_journal(
        &second_directory,
        &second_expected,
    )?;
    let first_native = first.native_identities()?;
    let second_native = second.native_identities()?;
    if first.attempt_id == second.attempt_id
        || first_native.target == second_native.target
        || first_native.network_namespace_inode == second_native.network_namespace_inode
        || gate.gate.first.target != first_native.target
        || gate.gate.second.target != second_native.target
        || gate.gate.first.network_namespace_inode != first_native.network_namespace_inode
        || gate.gate.second.network_namespace_inode != second_native.network_namespace_inode
        || first_native.candidate_exit_code != Some(0)
        || second_native.candidate_exit_code != Some(0)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached dual branch differs".into());
    }
    for native in [&first_native, &second_native] {
        for process in [&native.guardian, &native.namespace_init, &native.target] {
            require_recorded_process_exited(process)?;
        }
        if let Some(frontend) = &native.frontend_proxy {
            require_recorded_process_exited(frontend)?;
        }
    }
    require_candidate_cgroup_absent(&first.attempt_id)?;
    require_candidate_cgroup_absent(&second.attempt_id)?;
    let inspection = package.installed_inspection_bytes()?;
    let raw_context = super::private_release_dual_raw::DualRawContextV1 {
        directory: &directory,
        result_key: &recorded.result_key,
        challenge: &request.challenge,
        installed_inspection_bytes: &inspection,
    };
    let (_, cleanup, attachment_inventory) = super::private_release_dual_raw::readback_dual_raw(
        raw_context,
        &gate,
        &first,
        &second,
        &recorded.coordinator,
        &recorded.service_generation_sha256,
    )?;
    require_recorded_process_exited(&cleanup.worker)?;
    let current_service = super::private_host_prerequisites::observe_service_generation()?;
    super::private_host_prerequisites::require_current_worker_cgroup(&current_service)?;
    if current_service.digest()? != recorded.service_generation_sha256
        || crate::package::installed_generation_epoch()? != recorded.installation_epoch
        || read_request(&directory, 0)? != recorded
        || super::private_release_dual_gate::readback_gate_and_ack(
            &directory,
            &recorded.result_key,
            &request.challenge,
            &first_expected,
            &second_expected,
        )?
        .gate_sha256
            != gate.gate_sha256
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached dual generation changed".into());
    }
    let first_again = super::private_release_attempt::read_retired_candidate_journal(
        &first_directory,
        &first_expected,
    )?;
    let second_again = super::private_release_attempt::read_retired_candidate_journal(
        &second_directory,
        &second_expected,
    )?;
    if first_again.terminal_bytes != first.terminal_bytes
        || second_again.terminal_bytes != second.terminal_bytes
        || super::private_release_dual_raw::readback_dual_raw(
            raw_context,
            &gate,
            &first,
            &second,
            &recorded.coordinator,
            &recorded.service_generation_sha256,
        )?
        .2 != attachment_inventory
    {
        return Err("MCSEALED-PRIVATE-RELEASE: detached dual evidence changed".into());
    }
    require_recorded_process_exited(&recorded.coordinator)?;
    require_recorded_process_exited(&cleanup.worker)?;
    for native in [&first_native, &second_native] {
        for process in [&native.guardian, &native.namespace_init, &native.target] {
            require_recorded_process_exited(process)?;
        }
        if let Some(frontend) = &native.frontend_proxy {
            require_recorded_process_exited(frontend)?;
        }
    }
    require_candidate_cgroup_absent(&first.attempt_id)?;
    require_candidate_cgroup_absent(&second.attempt_id)?;
    Ok(DetachedDualCandidateReadbackV1 {
        root,
        package,
        challenge: request.challenge,
        result_key: recorded.result_key,
        service_generation_sha256: recorded.service_generation_sha256,
        coordinator: recorded.coordinator,
        worker: cleanup.worker,
        first_native,
        second_native,
        first_journal: first,
        second_journal: second,
        installed_inspection_sha256: memcordon_core::workload_codec::hash_bytes(&inspection),
        attachment_inventory,
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerReleaseCandidateRequestV1 {
    schema_version: u8,
    stage: String,
    selector: String,
    challenge: [u8; 32],
    result_key: DiagnosticSha256,
}

impl PreparedReleaseCandidateRunV1 {
    pub(crate) fn encode_broker_request(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&BrokerReleaseCandidateRequestV1 {
            schema_version: 1,
            stage: "candidate-capability".into(),
            selector: self.request.selector.into(),
            challenge: self.request.challenge,
            result_key: self.request.result_key(),
        })
        .map_err(|error| error.to_string())
    }

    /// Coordinator-only diagnostic settlement for the distinct two-attempt
    /// release case. This does not authorize result or Q publication.
    #[allow(dead_code)] // Routed only after detached two-sided retirement is implemented.
    pub(crate) fn persist_control_dual_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector != super::private_release_dual_attempt::SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual control authority differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: dual coordinator not service-owned".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: dual case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: dual request differs".into());
        }
        let first_key = super::private_release_dual_attempt::subattempt_key(
            &expected.result_key,
            super::private_release_dual_attempt::DualAttemptRoleV1::First,
        );
        let second_key = super::private_release_dual_attempt::subattempt_key(
            &expected.result_key,
            super::private_release_dual_attempt::DualAttemptRoleV1::Second,
        );
        let first_expected =
            super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &first_key,
                selector: self.request.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            };
        let second_expected =
            super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &second_key,
                selector: self.request.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            };
        let gate = super::private_release_dual_gate::readback_gate_and_ack(
            &self.directory,
            &expected.result_key,
            &self.request.challenge,
            &first_expected,
            &second_expected,
        )?;
        let first_directory = super::private_release_dual_attempt::open_child(
            &self.directory,
            super::private_release_dual_attempt::DualAttemptRoleV1::First,
        )?;
        let second_directory = super::private_release_dual_attempt::open_child(
            &self.directory,
            super::private_release_dual_attempt::DualAttemptRoleV1::Second,
        )?;
        let first = super::private_release_attempt::read_retired_candidate_journal(
            &first_directory,
            &first_expected,
        )?;
        let second = super::private_release_attempt::read_retired_candidate_journal(
            &second_directory,
            &second_expected,
        )?;
        let inspection = package.installed_inspection_bytes()?;
        super::private_release_dual_raw::persist_dual_coordinator_cleanup(
            super::private_release_dual_raw::DualCoordinatorCleanupContextV1 {
                raw: super::private_release_dual_raw::DualRawContextV1 {
                    directory: &self.directory,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    installed_inspection_bytes: &inspection,
                },
                gate: &gate,
                first_journal: &first,
                second_journal: &second,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
        )
    }

    pub(crate) fn persist_control_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        self.persist_control_cleanup_with_kind(worker, worker_pidfd, false)
    }

    pub(crate) fn persist_control_unix_intent_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        self.persist_control_cleanup_with_kind(worker, worker_pidfd, true)
    }

    fn persist_control_cleanup_with_kind(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
        closed_unix_intent: bool,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || if closed_unix_intent {
                self.request.selector != super::private_release_unix_intent::SELECTOR
            } else {
                !super::private_release_case::candidate_fixture_supported(self.request.selector)
            }
        {
            return Err("MCSEALED-PRIVATE-RELEASE: control cleanup authority differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: cleanup coordinator not service-owned".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: cleanup case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: cleanup request differs".into());
        }
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            },
        )?;
        let inspection = package.installed_inspection_bytes()?;
        let response = if closed_unix_intent {
            super::private_release_unix_intent::expected_observation_bytes(&self.request.challenge)?
        } else {
            super::private_release_case::candidate_fixture_output_with_native(
                self.request.selector,
                &self.request.challenge,
                journal.native_identities()?.network_namespace_inode,
                package.agent_file_identity()?,
            )?
        };
        let agent_path_snapshot = (self.request.selector
            == super::private_release_ancestor::SELECTOR)
            .then(|| super::private_release_ancestor::ProtectedAgentPathV1::capture(&package))
            .transpose()?;
        let inventory = super::private_release_raw::persist_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: &response,
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: agent_path_snapshot.as_ref(),
                },
                journal: &journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
        )?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: control cleanup inventory differs".into());
        }
        Ok(inventory)
    }

    #[allow(dead_code)] // Enabled with the checkpoint-gate coordinator route.
    pub(crate) fn persist_control_checkpoint_gate_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate coordinator differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate service owner differs".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate request differs".into());
        }
        let expected_journal =
            super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            };
        let witness = super::private_release_gate::CheckpointGateWitnessV1::readback(
            &self.directory,
            &expected_journal,
        )?;
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.directory,
            &expected_journal,
        )?;
        let native = journal.native_identities()?;
        if witness.checkpoint_digest() != &journal.checkpoint_digest
            || witness.target() != &native.target
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate retirement differs".into());
        }
        let inspection = package.installed_inspection_bytes()?;
        let response = super::private_release_case::candidate_fixture_response(
            self.request.selector,
            &self.request.challenge,
        );
        super::private_release_raw::persist_checkpoint_gate_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: &response,
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: None,
                },
                journal: &journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
        )
    }

    #[allow(dead_code)] // Enabled with the fixed child/thread coordinator route.
    pub(crate) fn persist_control_child_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector != super::private_release_children::SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: child coordinator differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: child service owner differs".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: child case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: child request differs".into());
        }
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            },
        )?;
        let inspection = package.installed_inspection_bytes()?;
        super::private_release_raw::persist_child_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: b"",
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: None,
                },
                journal: &journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
        )
    }

    pub(crate) fn persist_control_socket_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector != super::private_release_socket_launder::SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: socket coordinator differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: socket service owner differs".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: socket case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: socket request differs".into());
        }
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            },
        )?;
        let inspection = package.installed_inspection_bytes()?;
        let response = super::private_release_case::candidate_fixture_response(
            self.request.selector,
            &self.request.challenge,
        );
        super::private_release_socket_raw::persist_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: &response,
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: None,
                },
                journal: &journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
        )
    }

    pub(crate) fn persist_control_terminal_join_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector != super::private_release_terminal_join::SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join coordinator differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join service owner differs".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join request differs".into());
        }
        let expected_journal =
            super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            };
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.directory,
            &expected_journal,
        )?;
        let native = journal.native_identities()?;
        let (gate_sha256, midflight_record_digest) =
            super::private_release_terminal_gate::readback_gate_and_ack(
                &self.directory,
                &expected_journal,
                &native.target,
                &journal.checkpoint_digest,
                &journal.filter_digest()?,
            )?;
        let inspection = package.installed_inspection_bytes()?;
        super::private_release_terminal_raw::persist_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: b"",
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: None,
                },
                journal: &journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
            &gate_sha256,
            &midflight_record_digest,
        )
    }

    #[allow(dead_code)] // Routed only after the uncertainty worker exchange is enabled.
    pub(crate) fn persist_control_uncertain_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector
                != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain cleanup authority differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain coordinator not service-owned".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain request differs".into());
        }
        let journal = super::private_release_attempt::read_retired_uncertain_candidate_journal(
            &self.directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            },
        )?;
        let inspection = package.installed_inspection_bytes()?;
        let inventory = super::private_release_raw::persist_uncertain_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: b"",
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: None,
                },
                journal: &journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
        )?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain inventory differs".into());
        }
        Ok(inventory)
    }

    #[allow(dead_code)] // The fixed retirement-fault coordinator is not connected yet.
    pub(crate) fn persist_control_blocked_retirement_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector != super::private_release_case::RETIREMENT_FAULT_SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked cleanup authority differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked coordinator not service-owned".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked request differs".into());
        }
        let blocked = super::private_release_attempt::read_blocked_retirement_candidate_journal(
            &self.directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            },
        )?;
        let inspection = package.installed_inspection_bytes()?;
        let response = super::private_release_case::candidate_fixture_output_with_native(
            self.request.selector,
            &self.request.challenge,
            blocked.native_identities()?.network_namespace_inode,
            package.agent_file_identity()?,
        )?;
        let inventory = super::private_release_raw::persist_blocked_retirement_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: &response,
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: None,
                },
                journal: &blocked.journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
            &blocked,
        )?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked inventory differs".into());
        }
        Ok(inventory)
    }

    pub(crate) fn persist_control_guardian_loss_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector != super::private_release_guardian_loss::SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss cleanup authority differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err(
                "MCSEALED-PRIVATE-RELEASE: guardian-loss coordinator not service-owned".into(),
            );
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss request differs".into());
        }
        let journal = super::private_release_attempt::read_retired_guardian_loss_candidate_journal(
            &self.directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            },
        )?;
        let inspection = package.installed_inspection_bytes()?;
        let response =
            super::private_release_guardian_loss::armed_response(&self.request.challenge);
        let inventory = super::private_release_raw::persist_guardian_loss_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: &response,
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: None,
                },
                journal: &journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
        )?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss inventory differs".into());
        }
        Ok(inventory)
    }

    pub(crate) fn persist_control_frontend_loss_cleanup(
        &self,
        worker: &ProcessIdentityV4,
        worker_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if unsafe { libc::geteuid() } != 0
            || self.request.stage != ReleaseStageV1::CandidateCapability
            || self.request.selector != super::private_release_frontend_loss::SELECTOR
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss cleanup authority differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err(
                "MCSEALED-PRIVATE-RELEASE: frontend-loss coordinator not service-owned".into(),
            );
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let self_pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator =
            ProcessIdentityV4::observe(unsafe { libc::getpid() }, self_pidfd.as_fd())?;
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.request.result_key(), 0)?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss case handle changed".into());
        }
        let expected = protected_request(
            &self.request,
            &package,
            service.digest()?,
            coordinator.clone(),
        );
        if read_request(&self.directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss request differs".into());
        }
        let journal = super::private_release_attempt::read_retired_frontend_loss_candidate_journal(
            &self.directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &expected.result_key,
                selector: &expected.selector,
                challenge: &self.request.challenge,
                installation_epoch: &expected.installation_epoch,
                candidate_manifest_sha256: &expected.candidate_manifest_sha256,
                service_generation_sha256: &expected.service_generation_sha256,
                coordinator: &coordinator,
            },
        )?;
        let inspection = package.installed_inspection_bytes()?;
        let response =
            super::private_release_frontend_loss::armed_response(&self.request.challenge);
        let inventory = super::private_release_raw::persist_frontend_loss_coordinator_cleanup(
            super::private_release_raw::CandidateCoordinatorCleanupContextV1 {
                raw: super::private_release_raw::CandidateRawContextV1 {
                    directory: &self.directory,
                    selector: self.request.selector,
                    result_key: &expected.result_key,
                    challenge: &self.request.challenge,
                    expected_response: &response,
                    installed_inspection_bytes: &inspection,
                    agent_path_snapshot: None,
                },
                journal: &journal,
                coordinator: &coordinator,
                worker,
                worker_pidfd,
                service_generation_sha256: &expected.service_generation_sha256,
            },
        )?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss inventory differs".into());
        }
        Ok(inventory)
    }
}

pub(crate) fn encode_control_request(request: &ReleaseCaseRequestV1) -> Result<Vec<u8>, String> {
    if request.stage != ReleaseStageV1::CandidateCapability {
        return Err("MCSEALED-PRIVATE-RELEASE: only candidate control route exists".into());
    }
    serde_json::to_vec(&BrokerReleaseCandidateRequestV1 {
        schema_version: 1,
        stage: "candidate-capability".into(),
        selector: request.selector.into(),
        challenge: request.challenge,
        result_key: request.result_key(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn decode_broker_request(bytes: &[u8]) -> Result<ReleaseCaseRequestV1, String> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: broker request byte bound differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let raw: BrokerReleaseCandidateRequestV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let selector = super::private_release_case::REQUIRED_SELECTORS
        .into_iter()
        .find(|fixed| *fixed == raw.selector)
        .ok_or("MCSEALED-PRIVATE-RELEASE: broker selector differs")?;
    if raw.schema_version != 1 || raw.stage != "candidate-capability" || raw.challenge == [0; 32] {
        return Err("MCSEALED-PRIVATE-RELEASE: broker request differs".into());
    }
    let request = ReleaseCaseRequestV1 {
        stage: ReleaseStageV1::CandidateCapability,
        selector,
        challenge: raw.challenge,
    };
    if request.result_key() != raw.result_key {
        return Err("MCSEALED-PRIVATE-RELEASE: broker result key differs".into());
    }
    Ok(request)
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedReleaseRequestV1 {
    schema_version: u8,
    stage: String,
    selector: String,
    challenge: String,
    result_key: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    candidate_manifest_sha256: DiagnosticSha256,
    service_generation_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
}

/// This capability owns a package lock and a pinned, never-reused release
/// directory. It is neither serializable nor convertible into an H1 or
/// production authority. A future physical candidate case runner must borrow
/// it and persist raw native observations before any result can be published.
#[allow(dead_code)]
pub(crate) struct ReleaseCandidateRunAuthorityV1 {
    package: crate::package::VerifiedReleaseCandidatePackageLease,
    coordinator_pidfd: OwnedFd,
    coordinator: ProcessIdentityV4,
    case_directory: File,
    result_key: DiagnosticSha256,
    selector: &'static str,
    challenge: [u8; 32],
    installation_epoch: DiagnosticSha256,
    service_generation_digest: DiagnosticSha256,
    deadline: Instant,
}

#[allow(dead_code)]
impl ReleaseCandidateRunAuthorityV1 {
    /// A negative caller-authentication subcase must not allocate a second
    /// protected release run, even when it names another fixed challenge.
    #[allow(dead_code)] // Consumed by the closed caller/epoch physical witness.
    pub(crate) fn require_unallocated_result_key(
        &self,
        key: &DiagnosticSha256,
    ) -> Result<(), String> {
        self.revalidate()?;
        if key == &self.result_key {
            return Err("MCSEALED-PRIVATE-RELEASE: spoof key aliases live case".into());
        }
        let root = open_or_create_root()?;
        let leaf: String = key.clone().into();
        let name = CString::new(leaf).map_err(|_| "MCSEALED-PRIVATE-RELEASE: spoof key NUL")?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstatat writes a complete stat on success and resolves only
        // one digest-derived leaf beneath the pinned protected root.
        let status = unsafe {
            libc::fstatat(
                root.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status == 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: spoof allocated protected case".into());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE: spoof protected case lookup: {error}"
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_control(
        request: ReleaseCaseRequestV1,
    ) -> Result<PreparedReleaseCandidateRunV1, String> {
        if unsafe { libc::geteuid() } != 0 || request.stage != ReleaseStageV1::CandidateCapability {
            return Err("MCSEALED-PRIVATE-RELEASE: coordinator authority differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: coordinator is not owned by service".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let pidfd = super::private_execution::pidfd_for_self()?;
        let coordinator = ProcessIdentityV4::observe(unsafe { libc::getpid() }, pidfd.as_fd())?;
        let result_key = request.result_key();
        let root = open_or_create_root()?;
        let directory = create_case_directory(&root, &result_key, 0)?;
        let record = protected_request(&request, &package, service.digest()?, coordinator);
        let bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
        persist_request(&directory, &bytes, 0)?;
        Ok(PreparedReleaseCandidateRunV1 { directory, request })
    }

    pub(crate) fn begin(
        request: &ReleaseCaseRequestV1,
        coordinator_pid: libc::pid_t,
        coordinator_pidfd: OwnedFd,
        deadline: Instant,
        case_directory: File,
    ) -> Result<Self, String> {
        // SAFETY: these scalar observations have no pointer arguments.
        if unsafe { libc::geteuid() } != 0
            || request.stage != ReleaseStageV1::CandidateCapability
            || deadline <= Instant::now()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: candidate authority differs".into());
        }
        let package = crate::package::acquire_verified_release_candidate_package_lease()?;
        let service = super::private_host_prerequisites::observe_service_generation()?;
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-RELEASE: worker is not owned by launcher service".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        let coordinator = ProcessIdentityV4::observe(coordinator_pid, coordinator_pidfd.as_fd())?;
        let result_key = request.result_key();
        let root = open_or_create_root()?;
        protected_directory(&case_directory, 0)?;
        let reopened = open_case_directory(&root, &result_key, 0)?;
        let pinned = case_directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: coordinator case handle differs".into());
        }
        let expected = protected_request(request, &package, service.digest()?, coordinator.clone());
        if read_request(&case_directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: protected coordinator request differs".into());
        }
        let installation_epoch = package.installation_epoch.clone();
        let service_generation_digest = service.digest()?;
        Ok(Self {
            package,
            coordinator_pidfd,
            coordinator,
            case_directory,
            result_key,
            selector: request.selector,
            challenge: request.challenge,
            installation_epoch,
            service_generation_digest,
            deadline,
        })
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline {
            return Err("MCSEALED-PRIVATE-RELEASE: candidate deadline expired".into());
        }
        let observed = ProcessIdentityV4::observe(
            self.coordinator.pid as libc::pid_t,
            self.coordinator_pidfd.as_fd(),
        )?;
        if observed != self.coordinator {
            return Err("MCSEALED-PRIVATE-RELEASE: coordinator identity changed".into());
        }
        let mut pollfd = libc::pollfd {
            fd: self.coordinator_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll observes only the retained coordinator pidfd.
        if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 0 || pollfd.revents != 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: coordinator exited".into());
        }
        let service = super::private_host_prerequisites::observe_service_generation()?;
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        crate::package::verify()?;
        let current_epoch = crate::package::installed_generation_epoch()?;
        let (_, current_manifest) =
            super::runtime_manifest::source_v3(Path::new("/usr/libexec/memcordon-sealed-agent"))?
                .ok_or("MCSEALED-PRIVATE-RELEASE: installed M0 changed")?;
        if current_epoch != self.installation_epoch
            || service.digest()? != self.service_generation_digest
            || memcordon_core::workload_codec::hash_bytes(&current_manifest)
                != self.package.runtime_manifest_sha256
        {
            return Err("MCSEALED-PRIVATE-RELEASE: installed prerequisites changed".into());
        }
        let root = open_or_create_root()?;
        let reopened = open_case_directory(&root, &self.result_key, 0)?;
        let pinned = self
            .case_directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let current = reopened.metadata().map_err(|error| error.to_string())?;
        if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err("MCSEALED-PRIVATE-RELEASE: case directory replaced".into());
        }
        let request = ReleaseCaseRequestV1 {
            stage: ReleaseStageV1::CandidateCapability,
            selector: self.selector,
            challenge: self.challenge,
        };
        let expected = protected_request(
            &request,
            &self.package,
            self.service_generation_digest.clone(),
            self.coordinator.clone(),
        );
        if read_request(&self.case_directory, 0)? != expected {
            return Err("MCSEALED-PRIVATE-RELEASE: protected request changed".into());
        }
        Ok(())
    }

    /// Allocate a distinct release-domain native journal. The eight-case H1
    /// journal is not accepted here; this owner cannot release a target until
    /// a typed release-case checkpoint is added and independently verified.
    pub(crate) fn begin_native_owner(
        &self,
    ) -> Result<
        super::private_lifecycle::PrivateAttemptOwner<
            super::private_release_attempt::DurableReleaseCandidateAttemptV1,
        >,
        String,
    > {
        self.revalidate()?;
        let mut journal =
            super::private_release_attempt::DurableReleaseCandidateAttemptV1::allocate(
                self.case_directory
                    .try_clone()
                    .map_err(|error| error.to_string())?,
                self.result_key.clone(),
                self.selector,
                &self.challenge,
                self.installation_epoch.clone(),
                self.package.runtime_manifest_sha256.clone(),
                self.service_generation_digest.clone(),
                self.coordinator.clone(),
            )?;
        journal.freeze()?;
        super::private_lifecycle::PrivateAttemptOwner::new(journal)
    }

    /// Allocate both isolated candidate journals before either target can be
    /// released. This is custody only; it is not a two-target observation.
    pub(crate) fn begin_dual_native_owners(
        &self,
    ) -> Result<super::private_release_dual_attempt::DualCandidateJournalPairV1, String> {
        if self.selector != super::private_release_dual_attempt::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: dual selector differs".into());
        }
        self.revalidate()?;
        super::private_release_dual_attempt::allocate_pair(
            super::private_release_dual_attempt::DualCandidateJournalBindingsV1 {
                parent_directory: &self.case_directory,
                parent_key: &self.result_key,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )
    }

    pub(crate) fn begin_frontend_loss_native_owner(
        &self,
        frontend: &ProcessIdentityV4,
        frontend_pidfd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<
        super::private_lifecycle::PrivateAttemptOwner<
            super::private_release_attempt::DurableReleaseCandidateAttemptV1,
        >,
        String,
    > {
        if self.selector != super::private_release_frontend_loss::SELECTOR
            || frontend == &self.coordinator
            || frontend.pid == unsafe { libc::getpid() } as u32
            || ProcessIdentityV4::observe(frontend.pid as libc::pid_t, frontend_pidfd)? != *frontend
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend loss proxy authority differs".into());
        }
        self.revalidate()?;
        let mut journal =
            super::private_release_attempt::DurableReleaseCandidateAttemptV1::allocate_frontend_loss(
                self.case_directory
                    .try_clone()
                    .map_err(|error| error.to_string())?,
                self.result_key.clone(),
                self.selector,
                &self.challenge,
                self.installation_epoch.clone(),
                self.package.runtime_manifest_sha256.clone(),
                self.service_generation_digest.clone(),
                self.coordinator.clone(),
                frontend.clone(),
            )?;
        journal.freeze()?;
        super::private_lifecycle::PrivateAttemptOwner::new(journal)
    }

    pub(crate) fn persist_checkpoint_gate(
        &self,
        target: &ProcessIdentityV4,
    ) -> Result<super::private_release_gate::CheckpointGateWitnessV1, String> {
        if self.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate selector differs".into());
        }
        self.revalidate()?;
        let expected = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
            result_key: &self.result_key,
            selector: self.selector,
            challenge: &self.challenge,
            installation_epoch: &self.installation_epoch,
            candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
            service_generation_sha256: &self.service_generation_digest,
            coordinator: &self.coordinator,
        };
        let intent = super::private_release_attempt::read_checkpoint_gate_candidate_journal(
            &self.case_directory,
            &expected,
        )?;
        let witness = super::private_release_gate::CheckpointGateWitnessV1::persist(
            &self.case_directory,
            &expected,
            intent,
            target,
        )?;
        self.revalidate()?;
        Ok(witness)
    }

    pub(crate) fn require_persisted_checkpoint_gate(
        &self,
        checkpoint: &DiagnosticSha256,
        target: &ProcessIdentityV4,
    ) -> Result<(), String> {
        if self.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate selector differs".into());
        }
        self.revalidate()?;
        let expected = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
            result_key: &self.result_key,
            selector: self.selector,
            challenge: &self.challenge,
            installation_epoch: &self.installation_epoch,
            candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
            service_generation_sha256: &self.service_generation_digest,
            coordinator: &self.coordinator,
        };
        let journal = super::private_release_attempt::read_checkpoint_gate_candidate_journal(
            &self.case_directory,
            &expected,
        )?;
        let witness = super::private_release_gate::CheckpointGateWitnessV1::readback(
            &self.case_directory,
            &expected,
        )?;
        if witness.checkpoint_digest() != checkpoint
            || witness.target() != target
            || witness.checkpoint_digest() != &journal.checkpoint_digest
            || witness.target() != &journal.target
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate changed".into());
        }
        Ok(())
    }

    pub(crate) fn target_ids(&self) -> Result<(u32, u32), String> {
        self.revalidate()?;
        super::private_qualification::fixed_probe_account()
    }

    pub(crate) fn native_abi(&self) -> Result<super::network_filter::NativeAbi, String> {
        self.revalidate()?;
        if self.package.target != super::runtime_manifest::target()? {
            return Err("MCSEALED-PRIVATE-RELEASE: candidate target ABI differs".into());
        }
        match self.package.target.as_str() {
            "x86_64-unknown-linux-gnu" => Ok(super::network_filter::NativeAbi::X86_64),
            "aarch64-unknown-linux-gnu" => Ok(super::network_filter::NativeAbi::Aarch64),
            _ => Err("MCSEALED-PRIVATE-RELEASE: candidate target ABI differs".into()),
        }
    }

    pub(crate) fn filter_digest(&self) -> &DiagnosticSha256 {
        &self.package.filter_sha256
    }

    pub(crate) fn fixture_digest(&self) -> &DiagnosticSha256 {
        &self.package.agent_sha256
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn coordinator_pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.coordinator_pidfd.as_fd()
    }

    pub(crate) fn attempt_bytes(&self) -> [u8; 16] {
        super::private_release_attempt::candidate_attempt_bytes(&self.result_key)
    }

    pub(crate) fn challenge_bytes(&self) -> [u8; 32] {
        self.challenge
    }

    pub(crate) fn persist_child_live_gate(
        &self,
        live: &super::private_release_child_owner::LiveDescendantWitnessV1,
    ) -> Result<DiagnosticSha256, String> {
        if self.selector != super::private_release_children::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: child live gate selector differs".into());
        }
        self.revalidate()?;
        super::private_release_child_gate::persist_gate(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            live,
        )
    }

    pub(crate) fn wait_child_live_ack(
        &self,
        gate_sha256: &DiagnosticSha256,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.selector != super::private_release_children::SELECTOR {
            return Err(
                "MCSEALED-PRIVATE-RELEASE: child live acknowledgment selector differs".into(),
            );
        }
        self.revalidate()?;
        super::private_release_child_gate::wait_for_ack(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            gate_sha256,
            deadline.min(self.deadline),
        )?;
        self.revalidate()
    }

    pub(crate) fn persist_socket_gate(
        &self,
        witness: &super::private_release_socket_launder::PrecreatedSocketGatedWitnessV1,
    ) -> Result<DiagnosticSha256, String> {
        if self.selector != super::private_release_socket_launder::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: socket gate selector differs".into());
        }
        self.revalidate()?;
        super::private_release_socket_gate::persist_gate(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            &super::private_release_attempt::candidate_attempt_id(&self.result_key),
            witness,
        )
    }

    pub(crate) fn wait_socket_ack(
        &self,
        gate_sha256: &DiagnosticSha256,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.selector != super::private_release_socket_launder::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: socket acknowledgment selector differs".into());
        }
        self.revalidate()?;
        super::private_release_socket_gate::wait_for_ack(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            gate_sha256,
            deadline.min(self.deadline),
        )?;
        self.revalidate()
    }

    pub(crate) fn read_terminal_join_midflight(
        &self,
    ) -> Result<super::private_release_attempt::MidflightTerminalJoinReadbackV1, String> {
        if self.selector != super::private_release_terminal_join::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join selector differs".into());
        }
        self.revalidate()?;
        super::private_release_attempt::read_midflight_terminal_join_journal(
            &self.case_directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &self.result_key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )
    }

    pub(crate) fn read_dual_midflight(
        &self,
        role: super::private_release_dual_attempt::DualAttemptRoleV1,
    ) -> Result<super::private_release_attempt::MidflightTerminalJoinReadbackV1, String> {
        if self.selector != super::private_release_dual_attempt::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: dual midflight selector differs".into());
        }
        self.revalidate()?;
        let directory =
            super::private_release_dual_attempt::open_child(&self.case_directory, role)?;
        let key = super::private_release_dual_attempt::subattempt_key(&self.result_key, role);
        super::private_release_attempt::read_midflight_dual_journal(
            &directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )
    }

    pub(crate) fn persist_dual_live_gate(
        &self,
        first: &super::private_release_dual_gate::DualLiveHostObservationV1,
        second: &super::private_release_dual_gate::DualLiveHostObservationV1,
    ) -> Result<DiagnosticSha256, String> {
        if self.selector != super::private_release_dual_attempt::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: dual gate selector differs".into());
        }
        self.revalidate()?;
        let first_midflight = self
            .read_dual_midflight(super::private_release_dual_attempt::DualAttemptRoleV1::First)?;
        let second_midflight = self
            .read_dual_midflight(super::private_release_dual_attempt::DualAttemptRoleV1::Second)?;
        super::private_release_dual_gate::persist_gate(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            super::private_release_dual_gate::DualLiveWitnessV1 {
                target: &first.target,
                network_namespace_inode: first.network_namespace_inode,
                listener_socket_inode: first.listener_socket_inode,
                midflight: &first_midflight,
            },
            super::private_release_dual_gate::DualLiveWitnessV1 {
                target: &second.target,
                network_namespace_inode: second.network_namespace_inode,
                listener_socket_inode: second.listener_socket_inode,
                midflight: &second_midflight,
            },
        )
    }

    pub(crate) fn wait_dual_live_ack(
        &self,
        gate_sha256: &DiagnosticSha256,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.selector != super::private_release_dual_attempt::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: dual ack selector differs".into());
        }
        self.revalidate()?;
        super::private_release_dual_gate::wait_for_ack(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            gate_sha256,
            deadline,
        )?;
        self.revalidate()
    }

    pub(crate) fn read_dual_retired(
        &self,
        role: super::private_release_dual_attempt::DualAttemptRoleV1,
    ) -> Result<super::private_release_attempt::ReadbackRetiredCandidateAttemptV1, String> {
        if self.selector != super::private_release_dual_attempt::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: dual retired selector differs".into());
        }
        self.revalidate()?;
        let directory =
            super::private_release_dual_attempt::open_child(&self.case_directory, role)?;
        let key = super::private_release_dual_attempt::subattempt_key(&self.result_key, role);
        super::private_release_attempt::read_retired_candidate_journal(
            &directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )
    }

    pub(crate) fn read_dual_live_gate_and_ack(
        &self,
    ) -> Result<super::private_release_dual_gate::DualLiveGateReadbackV1, String> {
        if self.selector != super::private_release_dual_attempt::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: dual gate selector differs".into());
        }
        self.revalidate()?;
        let first_key = super::private_release_dual_attempt::subattempt_key(
            &self.result_key,
            super::private_release_dual_attempt::DualAttemptRoleV1::First,
        );
        let second_key = super::private_release_dual_attempt::subattempt_key(
            &self.result_key,
            super::private_release_dual_attempt::DualAttemptRoleV1::Second,
        );
        let first_expected =
            super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &first_key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            };
        let second_expected =
            super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &second_key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            };
        super::private_release_dual_gate::readback_gate_and_ack(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            &first_expected,
            &second_expected,
        )
    }

    pub(crate) fn persist_dual_worker_raw(
        &self,
        observed: &super::private_release_dual_execution::DualCandidateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_dual_attempt::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: dual raw selector differs".into());
        }
        self.revalidate()?;
        let gate = self.read_dual_live_gate_and_ack()?;
        let first =
            self.read_dual_retired(super::private_release_dual_attempt::DualAttemptRoleV1::First)?;
        let second =
            self.read_dual_retired(super::private_release_dual_attempt::DualAttemptRoleV1::Second)?;
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_dual_raw::persist_dual_worker_raw(
            super::private_release_dual_raw::DualRawContextV1 {
                directory: &self.case_directory,
                result_key: &self.result_key,
                challenge: &self.challenge,
                installed_inspection_bytes: &inspection,
            },
            observed,
            &gate,
            &first,
            &second,
        )
    }

    pub(crate) fn persist_terminal_join_gate(
        &self,
        midflight: &super::private_release_attempt::MidflightTerminalJoinReadbackV1,
        target: &ProcessIdentityV4,
    ) -> Result<DiagnosticSha256, String> {
        if self.selector != super::private_release_terminal_join::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join gate selector differs".into());
        }
        self.revalidate()?;
        super::private_release_terminal_gate::persist_gate(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            midflight,
            target,
        )
    }

    pub(crate) fn wait_terminal_join_ack(
        &self,
        gate_sha256: &DiagnosticSha256,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.selector != super::private_release_terminal_join::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join ack selector differs".into());
        }
        self.revalidate()?;
        super::private_release_terminal_gate::wait_for_ack(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            gate_sha256,
            deadline.min(self.deadline),
        )?;
        self.revalidate()
    }

    pub(crate) fn selector(&self) -> &'static str {
        self.selector
    }

    pub(crate) fn expected_fixture_output(&self, namespace_inode: u64) -> Result<Vec<u8>, String> {
        super::private_release_case::candidate_fixture_output_with_native(
            self.selector,
            &self.challenge,
            namespace_inode,
            self.package.agent_file_identity()?,
        )
    }

    pub(crate) fn protected_agent_path_snapshot(
        &self,
    ) -> Result<super::private_release_ancestor::ProtectedAgentPathV1, String> {
        self.revalidate()?;
        super::private_release_ancestor::ProtectedAgentPathV1::capture(&self.package)
    }

    pub(crate) fn retired_native_namespace_inode(&self) -> Result<u64, String> {
        self.revalidate()?;
        super::private_release_attempt::read_retired_candidate_journal(
            &self.case_directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &self.result_key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )?
        .native_identities()
        .map(|native| native.network_namespace_inode)
    }

    pub(crate) fn work_directory(&self) -> Result<File, String> {
        self.revalidate()?;
        self.case_directory
            .try_clone()
            .map_err(|error| error.to_string())
    }

    /// Closed physical subwitnesses borrow this pinned directory only after
    /// revalidating the live candidate authority. This does not make their
    /// selectors eligible for release result publication.
    pub(crate) fn protected_case_directory(&self) -> Result<&File, String> {
        self.revalidate()?;
        Ok(&self.case_directory)
    }

    pub(crate) fn protected_result_key(&self) -> Result<&DiagnosticSha256, String> {
        self.revalidate()?;
        Ok(&self.result_key)
    }

    pub(crate) fn installed_inspection_bytes(&self) -> Result<Vec<u8>, String> {
        self.revalidate()?;
        self.package.installed_inspection_bytes()
    }

    pub(crate) fn prepare_native_prelaunch(
        &self,
    ) -> Result<super::launch::PrivateGatedPrelaunch, String> {
        self.revalidate()?;
        let (uid, gid) = self.target_ids()?;
        let identity =
            super::execution_identity::ResolvedTargetIdentity::for_probe_account(uid, gid)?;
        let abi = self.native_abi()?;
        let entrypoint = self.package.pinned_fixture_entrypoint()?;
        let command = super::private_target::PrivateExecArguments::for_release_candidate_fixture(
            self.selector,
        )?;
        super::launch::prepare_probe_gated_prelaunch(
            identity,
            entrypoint,
            self.package.agent_sha256.clone(),
            command,
            abi,
            *self.package.filter_sha256.bytes(),
        )
    }

    pub(crate) fn prepare_closed_unix_intent_prelaunch(
        &self,
    ) -> Result<super::launch::PrivateGatedPrelaunch, String> {
        if self.selector != super::private_release_unix_intent::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: Unix intent selector differs".into());
        }
        self.revalidate()?;
        let (uid, gid) = self.target_ids()?;
        let identity =
            super::execution_identity::ResolvedTargetIdentity::for_probe_account(uid, gid)?;
        let abi = self.native_abi()?;
        let entrypoint = self.package.pinned_fixture_entrypoint()?;
        super::launch::prepare_probe_gated_prelaunch(
            identity,
            entrypoint,
            self.package.agent_sha256.clone(),
            super::private_target::PrivateExecArguments::for_closed_unix_intent(),
            abi,
            *self.package.filter_sha256.bytes(),
        )
    }

    pub(crate) fn expected_closed_unix_intent_output(&self) -> Result<Vec<u8>, String> {
        if self.selector != super::private_release_unix_intent::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: Unix intent selector differs".into());
        }
        self.revalidate()?;
        super::private_release_unix_intent::expected_observation_bytes(&self.challenge)
    }

    pub(crate) fn persist_native_raw_observation(
        &self,
        observed: &super::private_release_execution::CandidateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        self.revalidate()?;
        let inspection = self.package.installed_inspection_bytes()?;
        let namespace_inode = self.retired_native_namespace_inode()?;
        if observed.network_namespace_inode != namespace_inode {
            return Err("MCSEALED-PRIVATE-RELEASE: observed namespace inode differs".into());
        }
        let expected_response = self.expected_fixture_output(namespace_inode)?;
        let agent_path_snapshot = (self.selector == super::private_release_ancestor::SELECTOR)
            .then(|| self.protected_agent_path_snapshot())
            .transpose()?;
        super::private_release_raw::persist_candidate_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: &expected_response,
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: agent_path_snapshot.as_ref(),
            },
            observed,
        )
    }

    pub(crate) fn persist_closed_unix_intent_raw_observation(
        &self,
        observed: &super::private_release_execution::CandidateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_unix_intent::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: Unix intent raw selector differs".into());
        }
        self.revalidate()?;
        let namespace_inode = self.retired_native_namespace_inode()?;
        if observed.network_namespace_inode != namespace_inode {
            return Err("MCSEALED-PRIVATE-RELEASE: Unix intent namespace inode differs".into());
        }
        let expected_response = self.expected_closed_unix_intent_output()?;
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_raw::persist_closed_unix_intent_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: &expected_response,
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    #[allow(dead_code)] // Enabled with the checkpoint-gate worker route.
    pub(crate) fn persist_checkpoint_gate_raw_observation(
        &self,
        observed: &super::private_release_gate::CheckpointGateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate raw selector differs".into());
        }
        self.revalidate()?;
        let expected = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
            result_key: &self.result_key,
            selector: self.selector,
            challenge: &self.challenge,
            installation_epoch: &self.installation_epoch,
            candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
            service_generation_sha256: &self.service_generation_digest,
            coordinator: &self.coordinator,
        };
        let witness = super::private_release_gate::CheckpointGateWitnessV1::readback(
            &self.case_directory,
            &expected,
        )?;
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.case_directory,
            &expected,
        )?;
        let native = journal.native_identities()?;
        let candidate = &observed.candidate;
        let response =
            super::private_release_case::candidate_fixture_response(self.selector, &self.challenge);
        if candidate.attempt_id != journal.attempt_id
            || candidate.checkpoint_digest != journal.checkpoint_digest
            || candidate.terminal_record_digest != journal.terminal_record_digest
            || candidate.terminal_bytes != journal.terminal_bytes
            || candidate.network_namespace_inode != native.network_namespace_inode
            || candidate.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&self.challenge)
            || candidate.response_bytes != response
            || candidate.response_sha256 != memcordon_core::workload_codec::hash_bytes(&response)
            || observed.gate_sha256 != witness.digest()?
            || witness.checkpoint_digest() != &journal.checkpoint_digest
            || witness.target() != &native.target
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate native join differs".into());
        }
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_raw::persist_checkpoint_gate_worker_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: &response,
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    #[allow(dead_code)] // Enabled with the fixed child/thread worker route.
    pub(crate) fn persist_child_raw_observation(
        &self,
        observed: &super::private_release_child_execution::ChildCandidateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_children::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: child raw selector differs".into());
        }
        self.revalidate()?;
        let expected = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
            result_key: &self.result_key,
            selector: self.selector,
            challenge: &self.challenge,
            installation_epoch: &self.installation_epoch,
            candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
            service_generation_sha256: &self.service_generation_digest,
            coordinator: &self.coordinator,
        };
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.case_directory,
            &expected,
        )?;
        let native = journal.native_identities()?;
        let candidate = &observed.candidate;
        if candidate.attempt_id != journal.attempt_id
            || candidate.checkpoint_digest != journal.checkpoint_digest
            || candidate.terminal_record_digest != journal.terminal_record_digest
            || candidate.terminal_bytes != journal.terminal_bytes
            || candidate.network_namespace_inode != native.network_namespace_inode
            || candidate.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&self.challenge)
            || candidate.candidate_exit_code != 0
            || observed.live.target != native.target
            || observed.live.challenge_sha256 != candidate.challenge_sha256
        {
            return Err("MCSEALED-PRIVATE-RELEASE: child native journal differs".into());
        }
        super::private_release_child_owner::verify_retired_witness(
            &observed.live,
            &journal.attempt_id,
        )?;
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_raw::persist_child_worker_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: b"",
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    pub(crate) fn persist_socket_raw_observation(
        &self,
        observed: &super::private_release_socket_execution::SocketLaunderNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_socket_launder::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: socket raw selector differs".into());
        }
        self.revalidate()?;
        let expected = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
            result_key: &self.result_key,
            selector: self.selector,
            challenge: &self.challenge,
            installation_epoch: &self.installation_epoch,
            candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
            service_generation_sha256: &self.service_generation_digest,
            coordinator: &self.coordinator,
        };
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.case_directory,
            &expected,
        )?;
        let native = journal.native_identities()?;
        let candidate = &observed.candidate;
        let response =
            super::private_release_case::candidate_fixture_response(self.selector, &self.challenge);
        if candidate.attempt_id != journal.attempt_id
            || candidate.checkpoint_digest != journal.checkpoint_digest
            || candidate.terminal_record_digest != journal.terminal_record_digest
            || candidate.terminal_bytes != journal.terminal_bytes
            || candidate.network_namespace_inode != native.network_namespace_inode
            || candidate.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&self.challenge)
            || candidate.response_bytes != response
            || candidate.response_sha256 != memcordon_core::workload_codec::hash_bytes(&response)
            || observed.gated_witness.target != native.target
            || observed.gated_witness.filter_sha256 != journal.filter_digest()?
        {
            return Err("MCSEALED-PRIVATE-RELEASE: socket native journal differs".into());
        }
        if super::private_release_socket_gate::readback_gate_and_ack(
            &self.case_directory,
            &self.result_key,
            &self.challenge,
            &journal.attempt_id,
            &observed.gated_witness,
        )? != observed.socket_gate_sha256
        {
            return Err("MCSEALED-PRIVATE-RELEASE: socket gate changed".into());
        }
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_socket_raw::persist_worker_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: &response,
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    pub(crate) fn persist_terminal_join_raw_observation(
        &self,
        observed: &super::private_release_terminal_execution::TerminalJoinNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_terminal_join::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join raw selector differs".into());
        }
        self.revalidate()?;
        let expected = super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
            result_key: &self.result_key,
            selector: self.selector,
            challenge: &self.challenge,
            installation_epoch: &self.installation_epoch,
            candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
            service_generation_sha256: &self.service_generation_digest,
            coordinator: &self.coordinator,
        };
        let journal = super::private_release_attempt::read_retired_candidate_journal(
            &self.case_directory,
            &expected,
        )?;
        let native = journal.native_identities()?;
        let candidate = &observed.candidate;
        let (gate_sha256, midflight_record_digest) =
            super::private_release_terminal_gate::readback_gate_and_ack(
                &self.case_directory,
                &expected,
                &native.target,
                &journal.checkpoint_digest,
                &journal.filter_digest()?,
            )?;
        if candidate.attempt_id != journal.attempt_id
            || candidate.checkpoint_digest != journal.checkpoint_digest
            || candidate.terminal_record_digest != journal.terminal_record_digest
            || candidate.terminal_bytes != journal.terminal_bytes
            || candidate.network_namespace_inode != native.network_namespace_inode
            || candidate.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&self.challenge)
            || candidate.candidate_exit_code != 0
            || observed.terminal_join_gate_sha256 != gate_sha256
            || observed.midflight_record_digest != midflight_record_digest
        {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join native journal differs".into());
        }
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_terminal_raw::persist_worker_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: b"",
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    #[allow(dead_code)] // The uncertainty broker dispatch is not connected yet.
    pub(crate) fn persist_uncertain_native_raw_observation(
        &self,
        observed: &super::private_release_execution::UncertainCandidateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertainty raw selector differs".into());
        }
        self.revalidate()?;
        let journal = super::private_release_attempt::read_retired_uncertain_candidate_journal(
            &self.case_directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &self.result_key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )?;
        if observed.attempt_id != journal.attempt_id
            || observed.checkpoint_digest != journal.checkpoint_digest
            || observed.terminal_record_digest != journal.terminal_record_digest
            || observed.terminal_bytes != journal.terminal_bytes
            || observed.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&self.challenge)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertainty native journal differs".into());
        }
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_raw::persist_uncertain_candidate_worker_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: b"",
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    #[allow(dead_code)] // The fixed retirement-fault worker dispatch is not connected yet.
    pub(crate) fn persist_blocked_retirement_raw_observation(
        &self,
        observed: &super::private_release_execution::BlockedCandidateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_case::RETIREMENT_FAULT_SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked raw selector differs".into());
        }
        self.revalidate()?;
        let blocked = super::private_release_attempt::read_blocked_retirement_candidate_journal(
            &self.case_directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &self.result_key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )?;
        let native = blocked.native_identities()?;
        let expected_response = self.expected_fixture_output(native.network_namespace_inode)?;
        if observed.attempt_id != blocked.journal.attempt_id
            || observed.checkpoint_digest != blocked.journal.checkpoint_digest
            || observed.terminal_record_digest != blocked.journal.terminal_record_digest
            || observed.terminal_bytes != blocked.journal.terminal_bytes
            || observed.fault_marker_bytes != blocked.fault_marker_bytes
            || observed.reuse_error != blocked.detached_reuse_error
            || observed.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&self.challenge)
            || observed.network_namespace_inode != native.network_namespace_inode
            || observed.response_bytes != expected_response
        {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked native journal differs".into());
        }
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_raw::persist_blocked_retirement_worker_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: &expected_response,
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    pub(crate) fn persist_guardian_loss_raw_observation(
        &self,
        observed: &super::private_release_guardian_loss::GuardianLossCandidateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_guardian_loss::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss raw selector differs".into());
        }
        self.revalidate()?;
        let journal = super::private_release_attempt::read_retired_guardian_loss_candidate_journal(
            &self.case_directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &self.result_key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )?;
        let native = journal.native_identities()?;
        let expected_response =
            super::private_release_guardian_loss::armed_response(&self.challenge);
        if observed.attempt_id != journal.attempt_id
            || observed.checkpoint_digest != journal.checkpoint_digest
            || observed.terminal_record_digest != journal.terminal_record_digest
            || observed.terminal_bytes != journal.terminal_bytes
            || observed.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&self.challenge)
            || observed.armed_response_sha256
                != memcordon_core::workload_codec::hash_bytes(&expected_response)
            || observed.network_namespace_inode != native.network_namespace_inode
            || observed.settlement.guardian != native.guardian
            || observed.settlement.guardian_signal != libc::SIGKILL
            || observed.settlement.candidate_exit_code == Some(0)
            || observed.settlement.candidate_exit_code != native.candidate_exit_code
        {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss native journal differs".into());
        }
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_raw::persist_guardian_loss_worker_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: &expected_response,
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    pub(crate) fn persist_frontend_loss_raw_observation(
        &self,
        observed: &super::private_release_frontend_loss::FrontendLossCandidateNativeObservationV1,
    ) -> Result<Vec<memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1>, String>
    {
        if self.selector != super::private_release_frontend_loss::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss raw selector differs".into());
        }
        self.revalidate()?;
        let journal = super::private_release_attempt::read_retired_frontend_loss_candidate_journal(
            &self.case_directory,
            &super::private_release_attempt::ReleaseCandidateReadbackExpectationV1 {
                result_key: &self.result_key,
                selector: self.selector,
                challenge: &self.challenge,
                installation_epoch: &self.installation_epoch,
                candidate_manifest_sha256: &self.package.runtime_manifest_sha256,
                service_generation_sha256: &self.service_generation_digest,
                coordinator: &self.coordinator,
            },
        )?;
        let native = journal.native_identities()?;
        let expected_response =
            super::private_release_frontend_loss::armed_response(&self.challenge);
        if observed.attempt_id != journal.attempt_id
            || observed.checkpoint_digest != journal.checkpoint_digest
            || observed.terminal_record_digest != journal.terminal_record_digest
            || observed.terminal_bytes != journal.terminal_bytes
            || observed.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&self.challenge)
            || observed.armed_response_sha256
                != memcordon_core::workload_codec::hash_bytes(&expected_response)
            || observed.network_namespace_inode != native.network_namespace_inode
            || native.frontend_proxy.as_ref() != Some(&observed.settlement.frontend)
            || observed.settlement.frontend_signal != libc::SIGKILL
            || observed.settlement.candidate_exit_code != native.candidate_exit_code
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss native journal differs".into());
        }
        let inspection = self.package.installed_inspection_bytes()?;
        super::private_release_raw::persist_frontend_loss_worker_raw(
            super::private_release_raw::CandidateRawContextV1 {
                directory: &self.case_directory,
                selector: self.selector,
                result_key: &self.result_key,
                challenge: &self.challenge,
                expected_response: &expected_response,
                installed_inspection_bytes: &inspection,
                agent_path_snapshot: None,
            },
            observed,
        )
    }

    /// Seal physical gated-target observations to this M0 release case. The
    /// checkpoint is distinct from H1 and production grant bindings.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind_native_checkpoint(
        &self,
        guardian: ProcessIdentityV4,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
        target_uid: u32,
        target_gid: u32,
        observed_filter: [u8; 32],
        topology_sha256: DiagnosticSha256,
        native_readback_sha256: DiagnosticSha256,
    ) -> Result<super::private_release_attempt::ReleaseCandidateCheckpointV1, String> {
        self.bind_native_checkpoint_for_key(
            &self.result_key,
            guardian,
            namespace_init,
            target,
            network_namespace_inode,
            target_uid,
            target_gid,
            observed_filter,
            topology_sha256,
            native_readback_sha256,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind_dual_native_checkpoint(
        &self,
        role: super::private_release_dual_attempt::DualAttemptRoleV1,
        guardian: ProcessIdentityV4,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
        target_uid: u32,
        target_gid: u32,
        observed_filter: [u8; 32],
        topology_sha256: DiagnosticSha256,
        native_readback_sha256: DiagnosticSha256,
    ) -> Result<super::private_release_attempt::ReleaseCandidateCheckpointV1, String> {
        if self.selector != super::private_release_dual_attempt::SELECTOR {
            return Err("MCSEALED-PRIVATE-RELEASE: dual checkpoint selector differs".into());
        }
        let key = super::private_release_dual_attempt::subattempt_key(&self.result_key, role);
        self.bind_native_checkpoint_for_key(
            &key,
            guardian,
            namespace_init,
            target,
            network_namespace_inode,
            target_uid,
            target_gid,
            observed_filter,
            topology_sha256,
            native_readback_sha256,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn bind_native_checkpoint_for_key(
        &self,
        result_key: &DiagnosticSha256,
        guardian: ProcessIdentityV4,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
        target_uid: u32,
        target_gid: u32,
        observed_filter: [u8; 32],
        topology_sha256: DiagnosticSha256,
        native_readback_sha256: DiagnosticSha256,
    ) -> Result<super::private_release_attempt::ReleaseCandidateCheckpointV1, String> {
        self.revalidate()?;
        if (target_uid, target_gid) != self.target_ids()?
            || observed_filter != *self.package.filter_sha256.bytes()
            || network_namespace_inode == 0
        {
            return Err("MCSEALED-PRIVATE-RELEASE: native checkpoint differs from case".into());
        }
        Ok(
            super::private_release_attempt::ReleaseCandidateCheckpointV1 {
                schema_version: 1,
                result_key: result_key.clone(),
                selector: self.selector.to_owned(),
                challenge_sha256: memcordon_core::workload_codec::hash_bytes(&self.challenge),
                attempt_id: super::private_release_attempt::candidate_attempt_id(result_key),
                installation_epoch: self.installation_epoch.clone(),
                candidate_manifest_sha256: self.package.runtime_manifest_sha256.clone(),
                service_generation_sha256: self.service_generation_digest.clone(),
                fixture_sha256: self.package.agent_sha256.clone(),
                filter_sha256: self.package.filter_sha256.clone(),
                target_uid,
                target_gid,
                guardian,
                namespace_init,
                target,
                network_namespace_inode,
                topology_sha256,
                native_readback_sha256,
            },
        )
    }
}

fn protected_request(
    request: &ReleaseCaseRequestV1,
    package: &crate::package::VerifiedReleaseCandidatePackageLease,
    service_generation_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
) -> ProtectedReleaseRequestV1 {
    ProtectedReleaseRequestV1 {
        schema_version: 1,
        stage: "candidate-capability".into(),
        selector: request.selector.into(),
        challenge: request
            .challenge
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        result_key: request.result_key(),
        installation_epoch: package.installation_epoch.clone(),
        candidate_manifest_sha256: package.runtime_manifest_sha256.clone(),
        service_generation_sha256,
        coordinator,
    }
}

fn read_request(directory: &File, uid: u32) -> Result<ProtectedReleaseRequestV1, String> {
    let name = CString::new(REQUEST_LEAF).expect("fixed request leaf");
    // SAFETY: openat resolves only the fixed leaf beneath the retained dir.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: protected request open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_REQUEST_BYTES as u64
    {
        return Err("MCSEALED-PRIVATE-RELEASE: protected request metadata differs".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let record: ProtectedReleaseRequestV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if record.schema_version != 1
        || record.stage != "candidate-capability"
        || record.challenge.len() != [0_u8; 32].len() * 2
        || !record
            .challenge
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("MCSEALED-PRIVATE-RELEASE: protected request shape differs".into());
    }
    Ok(record)
}

pub(crate) fn require_recorded_process_exited(recorded: &ProcessIdentityV4) -> Result<(), String> {
    let pid = recorded.pid as libc::pid_t;
    // SAFETY: pidfd_open observes only the recorded positive PID. An absent
    // process or a different start-time identity cannot be the coordinator.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if raw == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: detached coordinator pidfd: {error}"
        ));
    }
    // SAFETY: successful pidfd_open returned one unique owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let current = ProcessIdentityV4::observe(pid, pidfd.as_fd())?;
    if current != *recorded {
        return Ok(());
    }
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll reads the retained coordinator pidfd only.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } == 1 && pollfd.revents & libc::POLLIN != 0 {
        return Ok(());
    }
    Err("MCSEALED-PRIVATE-RELEASE: coordinator is still live".into())
}

pub(crate) fn require_candidate_cgroup_absent(attempt_id: &str) -> Result<(), String> {
    if !super::cgroup::valid_attempt_identity(attempt_id) {
        return Err("MCSEALED-PRIVATE-RELEASE: candidate cgroup identity differs".into());
    }
    let root_name = CString::new(super::CGROUP_ROOT).expect("fixed cgroup root has no NUL");
    // SAFETY: the fixed cgroup root is opened as a directory without following
    // its final component; subsequent lookup is relative to this pinned fd.
    let fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: candidate cgroup root: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful open returned one owned directory descriptor.
    let root = unsafe { File::from_raw_fd(fd) };
    let metadata = root.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: candidate cgroup root identity differs".into());
    }
    // SAFETY: fstatfs initializes the writable statfs slot for this pinned fd.
    let mut filesystem = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::fstatfs(root.as_raw_fd(), &raw mut filesystem) } != 0
        || filesystem.f_type as u64 != 0x6367_7270
    {
        return Err("MCSEALED-PRIVATE-RELEASE: candidate cgroup filesystem differs".into());
    }
    require_candidate_cgroup_leaf_absent(&root, attempt_id)
}

fn require_candidate_cgroup_leaf_absent(root: &File, attempt_id: &str) -> Result<(), String> {
    if !super::cgroup::valid_attempt_identity(attempt_id) {
        return Err("MCSEALED-PRIVATE-RELEASE: candidate cgroup identity differs".into());
    }
    let leaf =
        CString::new(attempt_id).map_err(|_| "MCSEALED-PRIVATE-RELEASE: unsafe cgroup leaf")?;
    // SAFETY: fstatat probes one checked child below the pinned cgroup root.
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    let status = unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            leaf.as_ptr(),
            &raw mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: candidate cgroup still exists".into());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOENT) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: candidate cgroup readback: {error}"
        ));
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(crate) fn require_candidate_cgroup_leaf_absent_for_test(
    root: &File,
    attempt_id: &str,
) -> Result<(), String> {
    require_candidate_cgroup_leaf_absent(root, attempt_id)
}

#[cfg(feature = "test-support")]
pub(crate) fn require_coordinator_exited_for_test(
    recorded: &ProcessIdentityV4,
) -> Result<(), String> {
    require_recorded_process_exited(recorded)
}

fn protected_directory(file: &File, uid: u32) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-RELEASE: protected directory differs".into());
    }
    Ok(())
}

fn open_or_create_root() -> Result<File, String> {
    super::attempt::secure_state_root()?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(super::STATE_ROOT)
        .map_err(|error| error.to_string())?;
    protected_directory(&parent, 0)?;
    let name = CString::new(ROOT_LEAF).expect("fixed release root name");
    // SAFETY: mkdirat uses one fixed leaf under a pinned root-owned directory.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: root creation: {}",
            std::io::Error::last_os_error()
        ));
    }
    parent.sync_all().map_err(|error| error.to_string())?;
    // SAFETY: openat retains the already-validated parent descriptor and
    // rejects a symlink for the fixed release-root leaf.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: root open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned directory descriptor.
    let root = unsafe { File::from_raw_fd(fd) };
    protected_directory(&root, 0)?;
    Ok(root)
}

fn key_name(key: &DiagnosticSha256) -> CString {
    CString::new(String::from(key.clone())).expect("digest is fixed lower-hex")
}

fn open_case_directory(root: &File, key: &DiagnosticSha256, uid: u32) -> Result<File, String> {
    let name = key_name(key);
    // SAFETY: openat is relative to the retained root; O_NOFOLLOW rejects a
    // substituted symlink or path selected outside the fixed digest domain.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: case directory open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat transferred one owned directory descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    protected_directory(&directory, uid)?;
    Ok(directory)
}

fn create_case_directory(root: &File, key: &DiagnosticSha256, uid: u32) -> Result<File, String> {
    let name = key_name(key);
    // SAFETY: mkdirat creates one never-reused digest leaf under the retained
    // protected root. An existing case, including incomplete, blocks replay.
    if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: case already exists or cannot be created: {}",
            std::io::Error::last_os_error()
        ));
    }
    root.sync_all().map_err(|error| error.to_string())?;
    open_case_directory(root, key, uid)
}

fn persist_request(directory: &File, bytes: &[u8], uid: u32) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: request record byte bound differs".into());
    }
    let name = CString::new(REQUEST_LEAF).expect("fixed request leaf");
    let temporary = CString::new(REQUEST_TEMP).expect("fixed request temp leaf");
    // SAFETY: openat creates one protected fixed leaf beneath the pinned case
    // directory; O_EXCL prevents replacing a prior request after a crash.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: request record creation: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned regular-file descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    // SAFETY: renameat2 publishes the fsynced fixed temporary leaf only if a
    // canonical request has never been published in this case directory.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.as_raw_fd(),
            temporary.as_ptr(),
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: request rename: {}",
            std::io::Error::last_os_error()
        ));
    }
    directory.sync_all().map_err(|error| error.to_string())?;
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: request readback open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned descriptor.
    let reopened = unsafe { File::from_raw_fd(raw) };
    let metadata = reopened.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("MCSEALED-PRIVATE-RELEASE: request protection differs".into());
    }
    let mut observed = Vec::new();
    reopened
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut observed)
        .map_err(|error| error.to_string())?;
    if observed != bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: request readback differs".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(crate) fn create_case_directory_for_test(
    root: &File,
    key: &DiagnosticSha256,
) -> Result<File, String> {
    let owner = root.metadata().map_err(|error| error.to_string())?.uid();
    create_case_directory(root, key, owner)
}

#[cfg(feature = "test-support")]
pub(crate) fn persist_request_for_test(directory: &File, bytes: &[u8]) -> Result<(), String> {
    let owner = directory
        .metadata()
        .map_err(|error| error.to_string())?
        .uid();
    persist_request(directory, bytes, owner)
}
