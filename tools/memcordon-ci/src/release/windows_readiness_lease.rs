//! One measured predecessor/current installation lifetime on native Windows.
use super::installed_consumer::MaterializedPayload;
use crate::windows_installed_cases::{
    InstalledWindowsPayload, WindowsLeasePhase, WindowsUpgradePredecessor,
};
use crate::windows_readiness_adapter::{WindowsRemovalObservation, WindowsRemovalPlan};
use crate::{CiError, Result, command::CommandSpec, consumer_readiness_ledger::SourceIdentity};
use memcordon_readiness_verifier::{
    InstalledLifecycleEvent, InstalledLifecycleJournal, InstalledLifecycleReceipt, ProductKey,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    format: String,
    revision: u32,
    identity: SourceIdentity,
    key: ProductKey,
    current: InstalledWindowsPayload,
    predecessor: InstalledWindowsPayload,
    binary_root: PathBuf,
    state_root: PathBuf,
    policy_root: PathBuf,
    artifact_root: PathBuf,
    work_deadline_unix_millis: u64,
    cleanup_deadline_unix_millis: u64,
}

pub(crate) fn retain_payload(
    payload: &MaterializedPayload,
    destination: &Path,
) -> Result<(
    Vec<crate::windows_installed_cases::SelectedArtifact>,
    crate::windows_installed_cases::SelectedArtifact,
    Vec<crate::windows_readiness_adapter::HeldWindowsArtifact>,
)> {
    fs::create_dir(destination)?;
    let mut held = Vec::new();
    let mut copy = |source: &Path, destination: &Path, expected: Option<&str>| -> Result<String> {
        let source_custody =
            crate::windows_readiness_adapter::hold_artifact(source, expected, 512 * 1024 * 1024)?;
        let owned = crate::windows_readiness_adapter::copy_owned_artifact(
            source,
            destination,
            &source_custody.sha256,
        )?;
        let hash = owned.sha256.clone();
        held.push(owned);
        Ok(hash)
    };
    let mut artifacts = Vec::new();
    for selected in &payload.artifacts {
        let path = destination.join(
            selected
                .path
                .file_name()
                .ok_or_else(|| CiError::Message("selected artifact filename missing".into()))?,
        );
        copy(&selected.path, &path, Some(&selected.sha256))?;
        artifacts.push(crate::windows_installed_cases::SelectedArtifact {
            path,
            sha256: selected.sha256.clone(),
        });
    }
    let manifest = destination.join("runtime-manifest.json");
    if !manifest.exists() {
        copy(
            &payload.directory.join("runtime-manifest.json"),
            &manifest,
            None,
        )?;
    }
    let path = destination.join("owned-fixture.exe");
    let sha256 = copy(&payload.fixture.path, &path, Some(&payload.fixture.sha256))?;
    Ok((
        artifacts,
        crate::windows_installed_cases::SelectedArtifact { path, sha256 },
        held,
    ))
}

pub struct WindowsLeaseResult {
    pub current: InstalledWindowsPayload,
    pub assessment: crate::windows_installed_cases::InstalledWindowsAssessment,
    pub removal: WindowsRemovalObservation,
    pub journal: InstalledLifecycleJournal,
}

fn event(
    output: &Path,
    artifact_root: &Path,
    journal: &mut InstalledLifecycleJournal,
    phase: &str,
    operation: &str,
    succeeded: bool,
    facts: serde_json::Value,
) -> Result<()> {
    let sequence = journal.events.len() as u64 + 1;
    let path = output.join(format!("native-phase-{sequence}.json"));
    super::source::write_json(&path, &facts)?;
    let relative = path.strip_prefix(artifact_root).map_err(|_| {
        CiError::Message("Windows phase receipt escapes selected artifact root".into())
    })?;
    let native_receipt = relative
        .components()
        .map(|part| match part {
            std::path::Component::Normal(name) => name
                .to_str()
                .ok_or_else(|| CiError::Message("native receipt path is not UTF-8".into())),
            _ => Err(CiError::Message(
                "native receipt path is not confined".into(),
            )),
        })
        .collect::<Result<Vec<_>>>()?
        .join("/");
    journal.events.push(InstalledLifecycleEvent {
        sequence,
        phase: phase.into(),
        operation: operation.into(),
        succeeded,
        native_receipt,
    });
    super::source::write_json(&output.join("installed-journal.json"), journal)
}

pub(crate) fn inspect_removal_plan(
    root: &Path,
    payload: &MaterializedPayload,
    identity: &SourceIdentity,
    output: &Path,
    deadline: Instant,
) -> Result<WindowsRemovalPlan> {
    let agent = payload
        .artifacts
        .iter()
        .find(|artifact| {
            artifact
                .path
                .file_name()
                .is_some_and(|name| name == "memcordon-sealed-agent.exe")
        })
        .ok_or_else(|| CiError::Message("selected Windows agent absent".into()))?;
    inspect_removal_plan_for_agent(
        root,
        &crate::windows_installed_cases::SelectedArtifact {
            path: agent.path.clone(),
            sha256: agent.sha256.clone(),
        },
        identity,
        output,
        deadline,
    )
}

pub(crate) fn inspect_removal_plan_for_agent(
    root: &Path,
    agent: &crate::windows_installed_cases::SelectedArtifact,
    identity: &SourceIdentity,
    output: &Path,
    deadline: Instant,
) -> Result<WindowsRemovalPlan> {
    let held = crate::windows_readiness_adapter::hold_artifact(
        &agent.path,
        Some(&agent.sha256),
        512 * 1024 * 1024,
    )?;
    let inspected = CommandSpec::new(&agent.path, root, Duration::from_secs(30))
        .args(["package", "inspect", "--json"])
        .bounded_until(deadline)
        .output_quiet()?;
    let _retained_agent = held;
    super::source::write_json(
        &output.join("package-inspection-capture.json"),
        &serde_json::json!({"status":inspected.status.code(),"stdout":inspected.stdout,"stderr":inspected.stderr}),
    )?;
    if !inspected.status.success() {
        return Err(CiError::Message(
            "selected Windows package inspection failed before mutation".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&inspected.stdout)
        .map_err(CiError::Message)?;
    let inspection: serde_json::Value = serde_json::from_slice(&inspected.stdout)?;
    if inspection["source_commit"] != identity.source_commit
        || inspection["version"] != identity.version
        || inspection["platform"] != "windows-service"
    {
        return Err(CiError::Message(
            "actual package inspection differs from selected Windows source".into(),
        ));
    }
    let native_path = |field: &str| -> Result<PathBuf> {
        let path =
            PathBuf::from(inspection[field].as_str().ok_or_else(|| {
                CiError::Message(format!("actual package inspection lacks {field}"))
            })?);
        if !path.is_absolute() {
            return Err(CiError::Message(
                "package layout must be an absolute native path".into(),
            ));
        }
        Ok(path)
    };
    let binary = native_path("binary_install_path")?;
    Ok(WindowsRemovalPlan {
        binary_root: binary
            .parent()
            .ok_or_else(|| CiError::Message("native package binary parent absent".into()))?
            .to_owned(),
        state_root: native_path("state_root")?,
        policy_root: native_path("policy_root")?,
    })
}

pub fn run(
    root: &Path,
    payload: &MaterializedPayload,
    predecessor: &MaterializedPayload,
    identity: &SourceIdentity,
    key: &ProductKey,
    output: &Path,
    artifact_root: &Path,
    deadline: Instant,
) -> Result<WindowsLeaseResult> {
    let now = Instant::now();
    let unix = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| CiError::Message(error.to_string()))?
            .as_millis(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let remaining = deadline.checked_duration_since(now).ok_or_else(|| {
        CiError::Message("original Windows cleanup cutoff already exhausted".into())
    })?;
    let cleanup_unix = unix
        .checked_add(
            u64::try_from(remaining.as_millis())
                .map_err(|error| CiError::Message(error.to_string()))?,
        )
        .ok_or_else(|| CiError::Message("Windows native cleanup cutoff overflow".into()))?;
    let work_unix = cleanup_unix
        .checked_sub(15 * 60 * 1000)
        .filter(|work| *work > unix)
        .ok_or_else(|| CiError::Message("original Windows work cutoff unavailable".into()))?;
    let deadlines = crate::windows_installed_cases::WindowsLeaseDeadlines {
        work: deadline
            .checked_sub(Duration::from_secs(15 * 60))
            .ok_or_else(|| CiError::Message("original Windows work cutoff unavailable".into()))?,
        cleanup: deadline,
        work_deadline_unix_millis: work_unix,
        cleanup_deadline_unix_millis: cleanup_unix,
    };
    fs::create_dir(output)?;
    super::source::write_json(
        &output.join("windows-original-deadlines.json"),
        &serde_json::json!({"format":"memcordon.consumer-readiness.windows-original-deadlines","revision":1,
        "identity":identity,"key":key,"artifact_root":artifact_root,"work_deadline_unix_millis":work_unix,"cleanup_deadline_unix_millis":cleanup_unix}),
    )?;
    let plan = inspect_removal_plan(root, payload, identity, output, deadline)?;
    let retained_current = output.join("selected-current-payload");
    let (current_artifacts, current_fixture, _current_custody) =
        retain_payload(payload, &retained_current)?;
    let retained_older = output.join("selected-predecessor-payload");
    let (older_artifacts, older_fixture, _predecessor_custody) =
        retain_payload(predecessor, &retained_older)?;
    let current = InstalledWindowsPayload::from_materialized(
        payload.channel,
        &payload.source,
        &payload.distribution,
        current_artifacts,
        &retained_current,
        current_fixture,
        &plan.binary_root,
        output.join("current"),
    )?;
    let older = InstalledWindowsPayload::from_materialized(
        predecessor.channel,
        &predecessor.source,
        &predecessor.distribution,
        older_artifacts,
        &retained_older,
        older_fixture,
        &plan.binary_root,
        output.join("predecessor"),
    )?;
    fs::create_dir_all(&current.output_directory)?;
    super::source::write_json(&output.join("selected-current.json"), &current)?;
    super::source::write_json(&output.join("selected-predecessor.json"), &older)?;
    super::source::write_json(
        &output.join("windows-lease-owner.json"),
        &Owner {
            format: "memcordon.consumer-readiness.windows-lease-owner".into(),
            revision: 1,
            identity: identity.clone(),
            key: key.clone(),
            current: current.clone(),
            predecessor: older.clone(),
            binary_root: plan.binary_root.clone(),
            state_root: plan.state_root.clone(),
            policy_root: plan.policy_root.clone(),
            artifact_root: artifact_root.to_owned(),
            work_deadline_unix_millis: work_unix,
            cleanup_deadline_unix_millis: cleanup_unix,
        },
    )?;
    super::source::write_json(
        &current
            .output_directory
            .join("windows-upgrade-predecessor.json"),
        &WindowsUpgradePredecessor {
            format: "memcordon.windows-upgrade-predecessor".into(),
            revision: 1,
            payload: older.clone(),
        },
    )?;
    crate::windows_consumer_readiness::provision_from_source_until(root, &current, deadlines.work)?;
    let lease_id = super::artifacts::checksum(&serde_json::to_vec(&(
        identity,
        key,
        "windows-installed-lease",
    ))?);
    let mut journal = InstalledLifecycleJournal {
        format: "memcordon.consumer-readiness.installed-journal".into(),
        revision: 1,
        run_id: identity.run_id.clone(),
        lease_id: lease_id.clone(),
        key: key.clone(),
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        events: Vec::new(),
    };
    let mut recovery_complete = false;
    let mut removal = None;
    let mut failures = Vec::new();
    let assessment = crate::windows_installed_cases::run_with_observer_until(
        &current,
        &mut |observed| {
            let (phase, operation) = match observed.phase {
                WindowsLeasePhase::BeforeOldInstall => (
                    "owned-before-mutation",
                    "original-selected-predecessor-install-intent",
                ),
                WindowsLeasePhase::AfterOldInstall => ("install", "actual-older-install"),
                WindowsLeasePhase::AfterOldVerify => ("verify", "actual-older-verification"),
                WindowsLeasePhase::BeforeCurrentUpgrade => ("upgrade", "current-upgrade-intent"),
                WindowsLeasePhase::AfterCurrentUpgrade => ("upgrade", "actual-current-upgrade"),
                WindowsLeasePhase::BeforeUninstall => {
                    ("finalization", "actual-owned-native-recovery")
                }
                WindowsLeasePhase::AfterUninstall => {
                    ("retired", "actual-package-and-native-removal")
                }
            };
            if observed.phase == WindowsLeasePhase::BeforeUninstall {
                let recovered = crate::windows_readiness_adapter::recover_and_observe_quiescence(
                    observed.subject,
                    &observed.subject.output_directory.join("outer-finalization"),
                    deadline,
                )?;
                super::source::write_json(&output.join("native-finalization.json"), &recovered)?;
                recovery_complete =
                    recovered.recovery.is_ok() && recovered.native_quiescence.is_ok();
                if !recovery_complete {
                    failures.push("native installed recovery or quiescence failed".into());
                }
            }
            if observed.phase == WindowsLeasePhase::AfterUninstall
                && observed.result.is_some_and(|result| result.is_ok())
            {
                removal = Some(crate::windows_readiness_adapter::observe_removed(
                    &current,
                    &plan,
                    &current.output_directory.join("native-removal"),
                    deadline,
                )?);
            }
            event(
                output,
                artifact_root,
                &mut journal,
                phase,
                operation,
                observed.result.is_none_or(|result| result.is_ok()),
                serde_json::json!({"subject":observed.subject,"operation":observed.operation,"result":observed.result,"capture":observed.capture,"stdout":observed.stdout,"stderr":observed.stderr}),
            )?;
            if observed.phase == WindowsLeasePhase::AfterCurrentUpgrade
                && observed.result.is_some_and(|result| result.is_ok())
            {
                let mut binaries = Vec::new();
                for binary in &payload.distribution.binaries {
                    let path = plan
                        .binary_root
                        .join(super::target::binary_name(binary, &key.target));
                    let hash = super::artifacts::checksum(&super::artifacts::read_file(&path)?);
                    let selected = super::installed_consumer::binary_path(
                        &retained_current,
                        binary,
                        &key.target,
                    );
                    if hash != super::artifacts::checksum(&super::artifacts::read_file(&selected)?)
                    {
                        return Err(CiError::Message(
                            "actual installed Windows upgrade bytes differ from selected component"
                                .into(),
                        ));
                    }
                    binaries.push(serde_json::json!({"binary":binary,"path":path,"sha256":hash}));
                }
                event(
                    output,
                    artifact_root,
                    &mut journal,
                    "upgrade",
                    "actual-installed-package-readback",
                    true,
                    serde_json::json!({"binaries":binaries}),
                )?;
                event(
                    output,
                    artifact_root,
                    &mut journal,
                    "cases",
                    "actual-installed-cases-dispatch-intent",
                    true,
                    serde_json::json!({"provider":observed.subject.provider}),
                )?;
            }
            Ok(())
        },
        deadlines,
    )?;
    super::source::write_json(&output.join("windows-assessment.json"), &assessment)?;
    let removed = removal.as_ref().is_some_and(|value| {
        value.installed_image_processes_absent && value.fixture_processes_absent
    });
    let receipt = InstalledLifecycleReceipt {
        format: "memcordon.consumer-readiness.installed-retirement".into(),
        revision: 1,
        run_id: identity.run_id.clone(),
        lease_id,
        key: key.clone(),
        journal_sha256: super::artifacts::checksum(&super::artifacts::read_file(
            &output.join("installed-journal.json"),
        )?),
        final_sequence: journal.events.last().map_or(0, |event| event.sequence),
        explicit_finalization_count: 1,
        package_absent: assessment.package_uninstall.is_ok() && removed,
        policy_retired: removed,
        native_resources_retired: recovery_complete && removed,
        cache_quiescent: recovery_complete && removed,
        cleanup_failures: failures,
        outstanding: if recovery_complete && removed {
            Vec::new()
        } else {
            vec!["Windows native installed lifetime unresolved".into()]
        },
    };
    super::source::write_json(&output.join("installed-retirement.json"), &receipt)?;
    if !assessment.accepted() || !receipt.cache_quiescent || !receipt.cleanup_failures.is_empty() {
        return Err(CiError::Message(
            "actual Windows installed cases or final retirement failed; original facts retained"
                .into(),
        ));
    }
    Ok(WindowsLeaseResult {
        current,
        assessment,
        removal: removal
            .ok_or_else(|| CiError::Message("actual Windows removal observation missing".into()))?,
        journal,
    })
}

pub fn recover(
    root: &Path,
    output: &Path,
    identity: &SourceIdentity,
    key: &ProductKey,
    deadline: Instant,
) -> Result<()> {
    let owner_custody = crate::windows_readiness_adapter::hold_artifact(
        &output.join("windows-lease-owner.json"),
        None,
        16 * 1024 * 1024,
    )?;
    let bytes = &owner_custody.bytes;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(CiError::Message(
            "Windows original installation owner exceeds finite bound".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let owner: Owner = serde_json::from_slice(&bytes)?;
    if owner.format != "memcordon.consumer-readiness.windows-lease-owner"
        || owner.revision != 1
        || serde_json::to_value(&owner.identity)? != serde_json::to_value(identity)?
        || owner.key != *key
        || owner.current.source_commit != identity.source_commit
        || owner.current.version != identity.version
        || owner.current.target != key.target
        || !owner.current.output_directory.starts_with(output)
        || !owner.predecessor.output_directory.starts_with(output)
    {
        return Err(CiError::Message(
            "Windows cleanup cannot reassociate original installation ownership".into(),
        ));
    }
    let plan = WindowsRemovalPlan {
        binary_root: owner.binary_root,
        state_root: owner.state_root,
        policy_root: owner.policy_root,
    };
    let attempt = (0..64)
        .find(|attempt| !output.join(format!("cleanup-attempt-{attempt}")).exists())
        .ok_or_else(|| CiError::Message("Windows cleanup retained retry bound exhausted".into()))?;
    let destination = output.join(format!("cleanup-attempt-{attempt}"));
    fs::create_dir(&destination)?;
    match fs::symlink_metadata(&owner.current.installed_manifest.path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(CiError::Message(
                    "installed Windows manifest custody differs".into(),
                ));
            }
            let manifest_custody = crate::windows_readiness_adapter::hold_artifact(
                &owner.current.installed_manifest.path,
                None,
                4 * 1024 * 1024,
            )?;
            let hash = &manifest_custody.sha256;
            let selected = if hash == &owner.current.installed_manifest.sha256 {
                &owner.current
            } else if hash == &owner.predecessor.installed_manifest.sha256 {
                &owner.predecessor
            } else {
                return Err(CiError::Message(
                    "interrupted Windows installation matches neither measured generation".into(),
                ));
            };
            let mut executable_custody = Vec::new();
            for artifact in [&selected.cli, &selected.agent] {
                if !artifact.path.starts_with(output) {
                    return Err(CiError::Message(
                        "retained Windows cleanup image escapes original lifetime".into(),
                    ));
                }
                executable_custody.push(crate::windows_readiness_adapter::hold_artifact(
                    &artifact.path,
                    Some(&artifact.sha256),
                    512 * 1024 * 1024,
                )?);
            }
            let native = crate::windows_readiness_adapter::recover_and_observe_quiescence(
                selected,
                &selected
                    .output_directory
                    .join(format!("cleanup-recovery-{attempt}")),
                deadline,
            )?;
            super::source::write_json(&destination.join("native-recovery.json"), &native)?;
            if native.recovery.is_err() || native.native_quiescence.is_err() {
                return Err(CiError::Message(
                    "interrupted Windows recovery retains native obligations".into(),
                ));
            }
            drop(manifest_custody);
            let removed = CommandSpec::new(&selected.agent.path, root, Duration::from_secs(120))
                .args(["package", "uninstall"])
                .bounded_until(deadline)
                .output_quiet()?;
            super::source::write_json(
                &destination.join("package-uninstall.json"),
                &serde_json::json!({"status":removed.status.code(),"stdout":removed.stdout,"stderr":removed.stderr}),
            )?;
            if !removed.status.success() {
                return Err(CiError::Message(
                    "interrupted Windows uninstall failed; original images and owner retained"
                        .into(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let current = crate::windows_readiness_adapter::observe_removed(
        &owner.current,
        &plan,
        &owner
            .current
            .output_directory
            .join(format!("cleanup-removal-{attempt}")),
        deadline,
    )?;
    let predecessor = crate::windows_readiness_adapter::observe_removed(
        &owner.predecessor,
        &plan,
        &owner
            .predecessor
            .output_directory
            .join(format!("cleanup-removal-{attempt}")),
        deadline,
    )?;
    super::source::write_json(
        &destination.join("native-removal.json"),
        &serde_json::json!({"identity":identity,"key":key,"current":current,"predecessor":predecessor}),
    )
}
