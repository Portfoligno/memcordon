//! Crash-atomic native release-result storage. No production constructor for
//! the completion token exists yet: owner-authored raw bytes and a detached
//! readback do not prove independent supervisor facts or all selector semantics.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    MAX_PRIVATE_RELEASE_RESULT_BYTES_V1, PrivateReleaseAllocatedOutcomeV1,
    PrivateReleaseAttachmentRoleV1, PrivateReleaseCaseResultV1, PrivateReleaseDualRetiredBranchV1,
    PrivateReleaseExecV1, PrivateReleaseInstalledBindingV1, PrivateReleaseKnowledgeV1,
    PrivateReleaseObservationV1, PrivateReleaseStageV1,
};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_attempt::RetiredCandidateNativeIdentitiesV1;
use super::private_release_run::DetachedBlockedRetirementReadbackV1;
use super::private_release_run::DetachedCandidateReadbackV1;
use super::private_release_run::DetachedDualCandidateReadbackV1;
use super::private_release_run::DetachedFrontendLossReadbackV1;
use super::private_release_run::DetachedGuardianLossReadbackV1;
use super::private_release_run::DetachedUncertainCandidateReadbackV1;

pub(crate) struct VerifiedCandidateCaseCompletion {
    root: File,
    result: PrivateReleaseCaseResultV1,
    key: DiagnosticSha256,
    package: crate::package::VerifiedReleaseCandidatePackageLease,
    service_generation_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    native: RetiredCandidateNativeIdentitiesV1,
    attempt_id: String,
}

/// Move-only, two-sided result authority. It cannot be constructed from the
/// ordinary single-attempt detached reader or from owner-authored raw JSON.
#[allow(dead_code)] // Enabled only after protected dual selector dispatch is connected.
pub(crate) struct VerifiedDualCandidateCaseCompletion {
    root: File,
    result: PrivateReleaseCaseResultV1,
    key: DiagnosticSha256,
    package: crate::package::VerifiedReleaseCandidatePackageLease,
    service_generation_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    first_native: RetiredCandidateNativeIdentitiesV1,
    second_native: RetiredCandidateNativeIdentitiesV1,
    first_attempt_id: String,
    second_attempt_id: String,
}

#[allow(dead_code)] // Enabled only after protected dual selector dispatch is connected.
impl VerifiedDualCandidateCaseCompletion {
    pub(crate) fn from_detached(readback: DetachedDualCandidateReadbackV1) -> Result<Self, String> {
        let DetachedDualCandidateReadbackV1 {
            root,
            package,
            challenge,
            result_key,
            service_generation_sha256,
            coordinator,
            worker,
            first_native,
            second_native,
            first_journal,
            second_journal,
            installed_inspection_sha256,
            attachment_inventory,
        } = readback;
        if attachment_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len()
            || attachment_inventory
                .iter()
                .map(|attachment| attachment.role)
                .ne(PrivateReleaseAttachmentRoleV1::ALL)
            || first_journal.attempt_id == second_journal.attempt_id
            || first_native.network_namespace_inode == second_native.network_namespace_inode
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual result evidence differs".into());
        }
        let native_machine = match package.target.as_str() {
            "x86_64-unknown-linux-gnu" => "x86_64",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => return Err("MCSEALED-PRIVATE-RELEASE: dual target differs".into()),
        };
        let first_attempt_id = first_journal.attempt_id.clone();
        let second_attempt_id = second_journal.attempt_id.clone();
        let branch =
            |journal: super::private_release_attempt::ReadbackRetiredCandidateAttemptV1| {
                PrivateReleaseDualRetiredBranchV1 {
                    attempt_id: journal.attempt_id,
                    checkpoint_sha256: journal.checkpoint_digest,
                    terminal_sha256: memcordon_core::workload_codec::hash_bytes(
                        &journal.terminal_bytes,
                    ),
                    // The journal's validated record digest is the durable,
                    // per-attempt retirement identity. The shared cleanup.bin
                    // separately binds coordinator-observed worker exit.
                    retirement_sha256: journal.terminal_record_digest,
                    release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                    exec: PrivateReleaseExecV1::Succeeded,
                }
            };
        let result = PrivateReleaseCaseResultV1 {
            schema_version: 1,
            selector: super::private_release_dual_attempt::SELECTOR.into(),
            challenge: lower_hex(&challenge),
            target: package.target.clone(),
            native_machine: native_machine.into(),
            installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch: package.installation_epoch.clone(),
                candidate_manifest_sha256: package.runtime_manifest_sha256.clone(),
                installed_inspection_sha256,
            },
            observation: PrivateReleaseObservationV1::DualAttemptsRetired {
                first: branch(first_journal),
                second: branch(second_journal),
                native_observer_sha256: attachment_inventory[3].sha256.clone(),
            },
            attachments: attachment_inventory,
        };
        result.validate()?;
        if result.result_key()? != result_key {
            return Err("MCSEALED-PRIVATE-RELEASE: dual result key differs".into());
        }
        Ok(Self {
            root,
            result,
            key: result_key,
            package,
            service_generation_sha256,
            coordinator,
            worker,
            first_native,
            second_native,
            first_attempt_id,
            second_attempt_id,
        })
    }

    pub(crate) fn publish(self) -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0
            || self.result.installed.stage() != PrivateReleaseStageV1::CandidateCapability
            || self.result.result_key()? != self.key
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual result authority differs".into());
        }
        let metadata = self.root.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err("MCSEALED-PRIVATE-RELEASE: dual result root unprotected".into());
        }
        self.revalidate_current_os()?;
        let bytes = serde_json::to_vec(&self.result).map_err(|error| error.to_string())?;
        self.result.validate()?;
        publish_result_bytes(&self.root, &self.key, &bytes, 0)?;
        self.revalidate_current_os()
    }

    fn revalidate_current_os(&self) -> Result<(), String> {
        let service = super::private_host_prerequisites::observe_service_generation()?;
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        if service.main().pid != unsafe { libc::getppid() } as u32
            || service.digest()? != self.service_generation_sha256
            || crate::package::installed_generation_epoch()? != self.package.installation_epoch
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual host generation changed".into());
        }
        for process in [&self.coordinator, &self.worker] {
            super::private_release_run::require_recorded_process_exited(process)?;
        }
        for (native, attempt_id) in [
            (&self.first_native, &self.first_attempt_id),
            (&self.second_native, &self.second_attempt_id),
        ] {
            for process in [&native.guardian, &native.namespace_init, &native.target] {
                super::private_release_run::require_recorded_process_exited(process)?;
            }
            if let Some(frontend) = &native.frontend_proxy {
                super::private_release_run::require_recorded_process_exited(frontend)?;
            }
            super::private_release_run::require_candidate_cgroup_absent(attempt_id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CompletedResultKindV1 {
    Ordinary,
    ClosedUnixIntent,
    CheckpointGate,
    ChildRuntime,
    PrecreatedSocket,
    TerminalJoin,
}

impl VerifiedCandidateCaseCompletion {
    pub(crate) fn from_detached(readback: DetachedCandidateReadbackV1) -> Result<Self, String> {
        Self::from_completed_detached(readback, CompletedResultKindV1::Ordinary)
    }

    /// Builds a candidate projection after detached AF_UNIX socket-stage
    /// readback. The result is evidence for CI, not release-Q authority.
    pub(crate) fn from_closed_unix_intent_detached(
        readback: DetachedCandidateReadbackV1,
    ) -> Result<Self, String> {
        Self::from_completed_detached(readback, CompletedResultKindV1::ClosedUnixIntent)
    }

    #[allow(dead_code)] // Enabled with the fixed checkpoint-gate finalizer.
    pub(crate) fn from_checkpoint_gate_detached(
        readback: super::private_release_run::DetachedCheckpointGateReadbackV1,
    ) -> Result<Self, String> {
        // The opaque detached reader independently parsed the protected
        // pre-release intent and rechecked the gate leaf after raw readback.
        let _gate_sha256 = readback.gate_sha256;
        Self::from_completed_detached(readback.ordinary, CompletedResultKindV1::CheckpointGate)
    }

    #[allow(dead_code)] // Enabled with the fixed child/thread finalizer.
    pub(crate) fn from_child_detached(
        readback: super::private_release_run::DetachedChildReadbackV1,
    ) -> Result<Self, String> {
        Self::from_completed_detached(readback.ordinary, CompletedResultKindV1::ChildRuntime)
    }

    pub(crate) fn from_socket_detached(
        readback: super::private_release_run::DetachedSocketReadbackV1,
    ) -> Result<Self, String> {
        Self::from_completed_detached(readback.ordinary, CompletedResultKindV1::PrecreatedSocket)
    }

    pub(crate) fn from_terminal_join_detached(
        readback: super::private_release_run::DetachedTerminalJoinReadbackV1,
    ) -> Result<Self, String> {
        Self::from_completed_detached(readback.ordinary, CompletedResultKindV1::TerminalJoin)
    }

    fn from_completed_detached(
        readback: DetachedCandidateReadbackV1,
        kind: CompletedResultKindV1,
    ) -> Result<Self, String> {
        let DetachedCandidateReadbackV1 {
            root,
            package,
            selector,
            challenge,
            result_key,
            service_generation_sha256,
            coordinator,
            native,
            journal,
            installed_inspection_sha256,
            attachment_inventory,
        } = readback;
        if match kind {
            CompletedResultKindV1::Ordinary => {
                !super::private_release_case::candidate_fixture_supported(selector)
            }
            CompletedResultKindV1::ClosedUnixIntent => {
                selector != super::private_release_unix_intent::SELECTOR
            }
            CompletedResultKindV1::CheckpointGate => {
                selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR
            }
            CompletedResultKindV1::ChildRuntime => {
                selector != super::private_release_children::SELECTOR
            }
            CompletedResultKindV1::PrecreatedSocket => {
                selector != super::private_release_socket_launder::SELECTOR
            }
            CompletedResultKindV1::TerminalJoin => {
                selector != super::private_release_terminal_join::SELECTOR
            }
        } || attachment_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len()
            || attachment_inventory[3].role != PrivateReleaseAttachmentRoleV1::Observer
            || attachment_inventory[4].role != PrivateReleaseAttachmentRoleV1::Cleanup
        {
            return Err("MCSEALED-PRIVATE-RELEASE: detached case semantics differ".into());
        }
        let native_machine = match package.target.as_str() {
            "x86_64-unknown-linux-gnu" => "x86_64",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => return Err("MCSEALED-PRIVATE-RELEASE: detached target differs".into()),
        };
        let result = PrivateReleaseCaseResultV1 {
            schema_version: 1,
            selector: selector.into(),
            challenge: lower_hex(&challenge),
            target: package.target.clone(),
            native_machine: native_machine.into(),
            installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch: package.installation_epoch.clone(),
                candidate_manifest_sha256: package.runtime_manifest_sha256.clone(),
                installed_inspection_sha256,
            },
            observation: PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
                attempt_id: journal.attempt_id.clone(),
                checkpoint_sha256: journal.checkpoint_digest,
                terminal_sha256: memcordon_core::workload_codec::hash_bytes(
                    &journal.terminal_bytes,
                ),
                // The coordinator-authored cleanup attachment is the durable
                // retirement projection; CI must reopen and join its bytes.
                retirement_sha256: attachment_inventory[4].sha256.clone(),
                release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                exec: PrivateReleaseExecV1::Succeeded,
                native_observer_sha256: attachment_inventory[3].sha256.clone(),
            },
            attachments: attachment_inventory,
        };
        result.validate()?;
        if result.result_key()? != result_key {
            return Err("MCSEALED-PRIVATE-RELEASE: detached result key differs".into());
        }
        Ok(Self {
            root,
            result,
            key: result_key,
            package,
            service_generation_sha256,
            coordinator,
            native,
            attempt_id: journal.attempt_id,
        })
    }

    /// The only uncertainty result path consumes the distinct post-exit
    /// reader. It cannot be reached from a normal completed-target readback.
    #[allow(dead_code)] // Service finalizer dispatch is not connected yet.
    pub(crate) fn from_uncertain_detached(
        readback: DetachedUncertainCandidateReadbackV1,
    ) -> Result<Self, String> {
        let DetachedUncertainCandidateReadbackV1 {
            root,
            package,
            selector,
            challenge,
            result_key,
            service_generation_sha256,
            coordinator,
            native,
            journal,
            installed_inspection_sha256,
            attachment_inventory,
        } = readback;
        if selector != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
            || attachment_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len()
            || attachment_inventory[3].role != PrivateReleaseAttachmentRoleV1::Observer
            || attachment_inventory[4].role != PrivateReleaseAttachmentRoleV1::Cleanup
        {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain detached semantics differ".into());
        }
        let native_machine = match package.target.as_str() {
            "x86_64-unknown-linux-gnu" => "x86_64",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => return Err("MCSEALED-PRIVATE-RELEASE: uncertain target differs".into()),
        };
        let result = PrivateReleaseCaseResultV1 {
            schema_version: 1,
            selector: selector.into(),
            challenge: lower_hex(&challenge),
            target: package.target.clone(),
            native_machine: native_machine.into(),
            installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch: package.installation_epoch.clone(),
                candidate_manifest_sha256: package.runtime_manifest_sha256.clone(),
                installed_inspection_sha256,
            },
            observation: PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain,
                attempt_id: journal.attempt_id.clone(),
                checkpoint_sha256: journal.checkpoint_digest,
                terminal_sha256: memcordon_core::workload_codec::hash_bytes(
                    &journal.terminal_bytes,
                ),
                retirement_sha256: attachment_inventory[4].sha256.clone(),
                release_knowledge: PrivateReleaseKnowledgeV1::PossiblyReleased,
                exec: PrivateReleaseExecV1::NotObserved,
                native_observer_sha256: attachment_inventory[3].sha256.clone(),
            },
            attachments: attachment_inventory,
        };
        result.validate()?;
        if result.result_key()? != result_key {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain result key differs".into());
        }
        Ok(Self {
            root,
            result,
            key: result_key,
            package,
            service_generation_sha256,
            coordinator,
            native,
            attempt_id: journal.attempt_id,
        })
    }

    /// A blocked retirement is a failure result, not a retired attempt. The
    /// detached reader has independently retried the actual same-key allocator
    /// and proven that both protected journal leaves remain unchanged.
    #[allow(dead_code)] // Service finalizer dispatch is not connected yet.
    pub(crate) fn from_blocked_retirement_detached(
        readback: DetachedBlockedRetirementReadbackV1,
    ) -> Result<Self, String> {
        let DetachedBlockedRetirementReadbackV1 {
            root,
            package,
            selector,
            challenge,
            result_key,
            service_generation_sha256,
            coordinator,
            native,
            blocked,
            installed_inspection_sha256,
            attachment_inventory,
        } = readback;
        if selector != super::private_release_case::RETIREMENT_FAULT_SELECTOR
            || attachment_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len()
            || attachment_inventory[3].role != PrivateReleaseAttachmentRoleV1::Observer
            || attachment_inventory[4].role != PrivateReleaseAttachmentRoleV1::Cleanup
        {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked result semantics differ".into());
        }
        let native_machine = match package.target.as_str() {
            "x86_64-unknown-linux-gnu" => "x86_64",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => return Err("MCSEALED-PRIVATE-RELEASE: blocked result target differs".into()),
        };
        let result = PrivateReleaseCaseResultV1 {
            schema_version: 1,
            selector: selector.into(),
            challenge: lower_hex(&challenge),
            target: package.target.clone(),
            native_machine: native_machine.into(),
            installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch: package.installation_epoch.clone(),
                candidate_manifest_sha256: package.runtime_manifest_sha256.clone(),
                installed_inspection_sha256,
            },
            observation: PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
                attempt_id: blocked.journal.attempt_id.clone(),
                checkpoint_sha256: blocked.journal.checkpoint_digest.clone(),
                terminal_sha256: memcordon_core::workload_codec::hash_bytes(
                    &blocked.journal.terminal_bytes,
                ),
                // The marker is the protected O_EXCL conflict at the exact
                // Retired transition; neither this nor the result converts
                // the still-Retiring journal into a successful retirement.
                cleanup_failure_sha256: memcordon_core::workload_codec::hash_bytes(
                    &blocked.fault_marker_bytes,
                ),
                reuse_rejection_sha256: memcordon_core::workload_codec::hash_bytes(
                    blocked.detached_reuse_error.as_bytes(),
                ),
                release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                exec: PrivateReleaseExecV1::Succeeded,
                native_observer_sha256: attachment_inventory[3].sha256.clone(),
            },
            attachments: attachment_inventory,
        };
        result.validate()?;
        if result.result_key()? != result_key {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked result key differs".into());
        }
        Ok(Self {
            root,
            result,
            key: result_key,
            package,
            service_generation_sha256,
            coordinator,
            native,
            attempt_id: blocked.journal.attempt_id,
        })
    }

    /// A guardian-loss result can be constructed only from the distinct
    /// release-domain attempt and post-coordinator-exit service readback.
    /// The target's armed response is not a successful workload exit.
    pub(crate) fn from_guardian_loss_detached(
        readback: DetachedGuardianLossReadbackV1,
    ) -> Result<Self, String> {
        let DetachedGuardianLossReadbackV1 {
            root,
            package,
            selector,
            challenge,
            result_key,
            service_generation_sha256,
            coordinator,
            native,
            journal,
            installed_inspection_sha256,
            attachment_inventory,
        } = readback;
        if selector != super::private_release_guardian_loss::SELECTOR
            || attachment_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len()
            || attachment_inventory[3].role != PrivateReleaseAttachmentRoleV1::Observer
            || attachment_inventory[4].role != PrivateReleaseAttachmentRoleV1::Cleanup
        {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss result semantics differ".into());
        }
        let native_machine = match package.target.as_str() {
            "x86_64-unknown-linux-gnu" => "x86_64",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss target differs".into()),
        };
        let result = PrivateReleaseCaseResultV1 {
            schema_version: 1,
            selector: selector.into(),
            challenge: lower_hex(&challenge),
            target: package.target.clone(),
            native_machine: native_machine.into(),
            installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch: package.installation_epoch.clone(),
                candidate_manifest_sha256: package.runtime_manifest_sha256.clone(),
                installed_inspection_sha256,
            },
            observation: PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::GuardianLost,
                attempt_id: journal.attempt_id.clone(),
                checkpoint_sha256: journal.checkpoint_digest,
                terminal_sha256: memcordon_core::workload_codec::hash_bytes(
                    &journal.terminal_bytes,
                ),
                retirement_sha256: attachment_inventory[4].sha256.clone(),
                release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                exec: PrivateReleaseExecV1::Succeeded,
                native_observer_sha256: attachment_inventory[3].sha256.clone(),
            },
            attachments: attachment_inventory,
        };
        result.validate()?;
        if result.result_key()? != result_key {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss result key differs".into());
        }
        Ok(Self {
            root,
            result,
            key: result_key,
            package,
            service_generation_sha256,
            coordinator,
            native,
            attempt_id: journal.attempt_id,
        })
    }

    pub(crate) fn from_frontend_loss_detached(
        readback: DetachedFrontendLossReadbackV1,
    ) -> Result<Self, String> {
        let DetachedFrontendLossReadbackV1 {
            root,
            package,
            selector,
            challenge,
            result_key,
            service_generation_sha256,
            coordinator,
            native,
            journal,
            installed_inspection_sha256,
            attachment_inventory,
        } = readback;
        if selector != super::private_release_frontend_loss::SELECTOR
            || native.frontend_proxy.is_none()
            || native.frontend_proxy.as_ref() == Some(&coordinator)
            || attachment_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len()
            || attachment_inventory[3].role != PrivateReleaseAttachmentRoleV1::Observer
            || attachment_inventory[4].role != PrivateReleaseAttachmentRoleV1::Cleanup
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss result semantics differ".into());
        }
        let native_machine = match package.target.as_str() {
            "x86_64-unknown-linux-gnu" => "x86_64",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss target differs".into()),
        };
        let result = PrivateReleaseCaseResultV1 {
            schema_version: 1,
            selector: selector.into(),
            challenge: lower_hex(&challenge),
            target: package.target.clone(),
            native_machine: native_machine.into(),
            installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch: package.installation_epoch.clone(),
                candidate_manifest_sha256: package.runtime_manifest_sha256.clone(),
                installed_inspection_sha256,
            },
            observation: PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::FrontendLost,
                attempt_id: journal.attempt_id.clone(),
                checkpoint_sha256: journal.checkpoint_digest,
                terminal_sha256: memcordon_core::workload_codec::hash_bytes(
                    &journal.terminal_bytes,
                ),
                retirement_sha256: attachment_inventory[4].sha256.clone(),
                release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                exec: PrivateReleaseExecV1::Succeeded,
                native_observer_sha256: attachment_inventory[3].sha256.clone(),
            },
            attachments: attachment_inventory,
        };
        result.validate()?;
        if result.result_key()? != result_key {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss result key differs".into());
        }
        Ok(Self {
            root,
            result,
            key: result_key,
            package,
            service_generation_sha256,
            coordinator,
            native,
            attempt_id: journal.attempt_id,
        })
    }

    pub(crate) fn publish(self) -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0
            || self.result.installed.stage() != PrivateReleaseStageV1::CandidateCapability
            || self.result.result_key()? != self.key
        {
            return Err("MCSEALED-PRIVATE-RELEASE: result authority differs".into());
        }
        let metadata = self.root.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err("MCSEALED-PRIVATE-RELEASE: result root is unprotected".into());
        }
        self.revalidate_current_os()?;
        let bytes = serde_json::to_vec(&self.result).map_err(|error| error.to_string())?;
        self.result.validate()?;
        publish_result_bytes(&self.root, &self.key, &bytes, 0)?;
        self.revalidate_current_os()
    }

    fn revalidate_current_os(&self) -> Result<(), String> {
        let service = super::private_host_prerequisites::observe_service_generation()?;
        super::private_host_prerequisites::require_current_worker_cgroup(&service)?;
        if service.main().pid != unsafe { libc::getppid() } as u32
            || service.digest()? != self.service_generation_sha256
            || crate::package::installed_generation_epoch()? != self.package.installation_epoch
        {
            return Err("MCSEALED-PRIVATE-RELEASE: result host generation changed".into());
        }
        for process in [
            &self.coordinator,
            &self.native.guardian,
            &self.native.namespace_init,
            &self.native.target,
        ] {
            super::private_release_run::require_recorded_process_exited(process)?;
        }
        if let Some(frontend) = &self.native.frontend_proxy {
            super::private_release_run::require_recorded_process_exited(frontend)?;
        }
        super::private_release_run::require_candidate_cgroup_absent(&self.attempt_id)
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn checked_leaf(key: &DiagnosticSha256) -> Result<String, String> {
    let mut leaf: String = key.clone().into();
    if leaf.len() != [0_u8; 32].len() * 2
        || !leaf
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("MCSEALED-PRIVATE-RELEASE: result key syntax differs".into());
    }
    leaf.push_str(".json");
    Ok(leaf)
}

fn read_leaf(root: &File, leaf: &str, expected_uid: u32) -> Result<Option<Vec<u8>>, String> {
    let name = CString::new(leaf).map_err(|_| "MCSEALED-PRIVATE-RELEASE: unsafe result leaf")?;
    // SAFETY: the leaf is a checked digest-derived name and O_NOFOLLOW pins
    // the opened file below the already-pinned directory descriptor.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(format!("MCSEALED-PRIVATE-RELEASE: result open: {error}"))
        };
    }
    // SAFETY: successful openat returned exactly one owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_PRIVATE_RELEASE_RESULT_BYTES_V1 as u64
    {
        return Err("MCSEALED-PRIVATE-RELEASE: result file metadata differs".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_PRIVATE_RELEASE_RESULT_BYTES_V1 as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() != metadata.len() as usize
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
        || after.mode() != metadata.mode()
        || after.uid() != metadata.uid()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: result file changed during readback".into());
    }
    Ok(Some(bytes))
}

fn write_new_or_matching(
    root: &File,
    leaf: &str,
    bytes: &[u8],
    expected_uid: u32,
) -> Result<(), String> {
    if let Some(existing) = read_leaf(root, leaf, expected_uid)? {
        return if existing == bytes {
            Ok(())
        } else {
            Err("MCSEALED-PRIVATE-RELEASE: existing result bytes differ".into())
        };
    }
    let name = CString::new(leaf).map_err(|_| "MCSEALED-PRIVATE-RELEASE: unsafe result leaf")?;
    // SAFETY: O_EXCL refuses replacement of a concurrent or crash-left leaf.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: result create: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned exactly one owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    root.sync_all().map_err(|error| error.to_string())?;
    if read_leaf(root, leaf, expected_uid)?.as_deref() != Some(bytes) {
        return Err("MCSEALED-PRIVATE-RELEASE: result temp readback differs".into());
    }
    Ok(())
}

fn publish_result_bytes(
    root: &File,
    key: &DiagnosticSha256,
    bytes: &[u8],
    expected_uid: u32,
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_PRIVATE_RELEASE_RESULT_BYTES_V1 {
        return Err("MCSEALED-PRIVATE-RELEASE: result byte bound differs".into());
    }
    let parsed = PrivateReleaseCaseResultV1::parse(bytes)?;
    if parsed.installed.stage() != PrivateReleaseStageV1::CandidateCapability
        || parsed.result_key()? != *key
    {
        return Err("MCSEALED-PRIVATE-RELEASE: result identity differs".into());
    }
    let leaf = checked_leaf(key)?;
    let temporary = format!("{leaf}.new");
    if let Some(existing) = read_leaf(root, &leaf, expected_uid)? {
        return if existing == bytes && read_leaf(root, &temporary, expected_uid)?.is_none() {
            Ok(())
        } else {
            Err("MCSEALED-PRIVATE-RELEASE: result replay or temp differs".into())
        };
    }
    write_new_or_matching(root, &temporary, bytes, expected_uid)?;
    let from = CString::new(temporary).map_err(|_| "MCSEALED-PRIVATE-RELEASE: unsafe temp")?;
    let to = CString::new(leaf.as_str()).map_err(|_| "MCSEALED-PRIVATE-RELEASE: unsafe leaf")?;
    // SAFETY: both digest-derived leaves are beneath one pinned protected
    // directory. RENAME_NOREPLACE cannot overwrite an earlier case result.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            root.as_raw_fd(),
            from.as_ptr(),
            root.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: result rename: {}",
            std::io::Error::last_os_error()
        ));
    }
    root.sync_all().map_err(|error| error.to_string())?;
    if read_leaf(root, &leaf, expected_uid)?.as_deref() != Some(bytes) {
        return Err("MCSEALED-PRIVATE-RELEASE: result readback differs".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn publish_storage_for_test(
    root: &File,
    key: &DiagnosticSha256,
    bytes: &[u8],
) -> Result<(), String> {
    // This does not construct VerifiedCandidateCaseCompletion and cannot be
    // reached by the installed production CLI.
    publish_result_bytes(root, key, bytes, unsafe { libc::geteuid() })
}
