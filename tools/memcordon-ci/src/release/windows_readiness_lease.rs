//! One measured current installation lifetime on native Windows.
use super::installed_consumer::MaterializedPayload;
use crate::windows_installed_cases::{InstalledWindowsPayload, WindowsLeasePhase};
use crate::windows_readiness_adapter::{WindowsRemovalObservation, WindowsRemovalPlan};
use crate::{CiError, Result, command::CommandSpec, readiness_identity::SourceIdentity};
use memcordon_readiness_verifier::current::{
    InstalledLifecycleReceiptV2, NativeResourceObservationV2, NativeResourceV2,
};
use memcordon_readiness_verifier::{
    InstalledLifecycleEvent, InstalledLifecycleJournal, ProductKey,
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
    binary_root: PathBuf,
    state_root: PathBuf,
    diagnostics_root: PathBuf,
    artifact_root: PathBuf,
    work_deadline_unix_millis: u64,
    cleanup_deadline_unix_millis: u64,
}

fn relative_reference(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| CiError::Message("native Windows evidence escapes artifact root".into()))?;
    let mut parts = Vec::new();
    for part in relative.components() {
        let std::path::Component::Normal(part) = part else {
            return Err(CiError::Message(
                "native Windows evidence reference is not confined".into(),
            ));
        };
        parts.push(
            part.to_str().ok_or_else(|| {
                CiError::Message("native evidence path is not portable text".into())
            })?,
        );
    }
    if parts.is_empty() {
        return Err(CiError::Message(
            "native evidence reference is empty".into(),
        ));
    }
    Ok(parts.join("/"))
}

pub(crate) fn retain_payload(
    payload: &MaterializedPayload,
    destination: &Path,
) -> Result<(
    Vec<crate::windows_installed_cases::SelectedArtifact>,
    crate::windows_installed_cases::SelectedArtifact,
    Option<crate::windows_installed_cases::WorkloadDiagnosticInput>,
    Vec<crate::windows_readiness_adapter::HeldWindowsArtifact>,
)> {
    let selected_count = payload.selected_case_artifacts()?.len();
    let (manifest_selection, components) =
        super::installed_consumer::materialized_windows_components(
            &payload.source,
            &payload.distribution,
            &payload.directory,
        )?;
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
    for (index, selected) in payload.artifacts.iter().enumerate() {
        let path = destination.join(
            selected
                .path
                .file_name()
                .ok_or_else(|| CiError::Message("selected artifact filename missing".into()))?,
        );
        copy(&selected.path, &path, Some(&selected.sha256))?;
        if index < selected_count {
            artifacts.push(crate::windows_installed_cases::SelectedArtifact {
                path,
                sha256: selected.sha256.clone(),
            });
        }
    }
    for component in components {
        let name = component
            .path
            .file_name()
            .ok_or_else(|| CiError::Message("measured Windows component basename absent".into()))?;
        copy(
            &component.path,
            &destination.join(name),
            Some(&component.sha256),
        )?;
    }
    copy(
        &manifest_selection.path,
        &destination.join("runtime-manifest.json"),
        Some(&manifest_selection.sha256),
    )?;
    let path = destination.join("owned-fixture.exe");
    let sha256 = copy(&payload.fixture.path, &path, Some(&payload.fixture.sha256))?;
    let diagnostic = payload
        .workload_diagnostic
        .clone()
        .map(|mut diagnostic| {
            diagnostic.validate_for(&payload.source, &payload.distribution.target)?;
            let path = destination.join("memcordon-windows-loader-lab.exe");
            copy(
                &diagnostic.executable.path,
                &path,
                Some(&diagnostic.executable.sha256),
            )?;
            diagnostic.executable.path = path;
            Ok::<_, CiError>(diagnostic)
        })
        .transpose()?;
    Ok((
        artifacts,
        crate::windows_installed_cases::SelectedArtifact { path, sha256 },
        diagnostic,
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
    let agent = super::installed_consumer::materialized_windows_agent(
        &payload.source,
        &payload.distribution,
        &payload.directory,
    )?;
    inspect_removal_plan_for_agent(
        root,
        &crate::windows_installed_cases::SelectedArtifact {
            path: agent.path,
            sha256: agent.sha256,
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
    inspect_removal_plan_for_source(
        root,
        agent,
        &identity.source_commit,
        &identity.version,
        output,
        deadline,
    )
}

pub(super) fn inspect_removal_plan_for_source(
    root: &Path,
    agent: &crate::windows_installed_cases::SelectedArtifact,
    source_commit: &str,
    version: &str,
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
    if inspection["source_commit"] != source_commit
        || inspection["version"] != version
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
        diagnostics_root: native_path("diagnostics_root")?,
    })
}

fn exercise_interrupted_current(
    current: &InstalledWindowsPayload,
    plan: &WindowsRemovalPlan,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<serde_json::Value> {
    use std::{io::Read, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    let mut subject = current.clone();
    subject.output_directory = current.output_directory.join("interrupted-current-install");
    fs::create_dir(&subject.output_directory)?;
    let mut held = fs::File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current.installed_agent.path)?;
    let original_identity = crate::windows_readiness_adapter::native_file_identity(
        &held,
        false,
        &current.installed_agent.path,
    )?;
    let mut bytes = Vec::new();
    (&mut held)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if crate::windows_causal_acceptance::sha256(&bytes) != current.installed_agent.sha256 {
        return Err(CiError::Message(
            "interruption image differs from genuine selected installation".into(),
        ));
    }
    let result =
        crate::windows_installed_cases::run_current_package(&subject, "upgrade", deadlines.work);
    let stderr = fs::read(subject.output_directory.join("package-upgrade.stderr.bin"))?;
    if result.is_ok()
        || !String::from_utf8_lossy(&stderr).contains("MCSEALED-WINDOWS-UPGRADE-ROLLBACK-FAILED")
    {
        return Err(CiError::Message("native image sharing boundary did not interrupt actual current replacement; retained owner".into()));
    }
    let journal_path = plan.binary_root.join("current-package-state.rollback.json");
    let mut raw = Vec::new();
    fs::File::open(&journal_path)?
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > 128 * 1024 * 1024 {
        return Err(CiError::Message(
            "current package recovery journal exceeds bound".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&raw).map_err(CiError::Message)?;
    let journal: serde_json::Value = serde_json::from_slice(&raw)?;
    if journal["format"] != "memcordon.windows-current-package-state"
        || journal["revision"] != 1
        || journal["operation"] != "upgrade"
    {
        return Err(CiError::Message(
            "interrupted operation lacks its sole current native journal".into(),
        ));
    }
    let (_, services) = crate::windows_readiness_adapter::absent_owned_services(deadlines.work)?;
    let named = fs::File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current.installed_agent.path)?;
    let observed_identity = crate::windows_readiness_adapter::native_file_identity(
        &named,
        false,
        &current.installed_agent.path,
    )?;
    if observed_identity != original_identity {
        return Err(CiError::Message(
            "interruption replaced the original held current image".into(),
        ));
    }
    let facts = serde_json::json!({"path":current.installed_agent.path,"image_sha256":current.installed_agent.sha256,"requested_share_mode":FILE_SHARE_READ,"original_file_identity":original_identity,"observed_file_identity":observed_identity,"journal_path":journal_path,"journal_sha256":crate::windows_causal_acceptance::sha256(&raw),"journal_format":journal["format"],"journal_revision":journal["revision"],"journal_operation":journal["operation"],"runtime_manifest":journal["runtime_manifest"],"artifact_digests":journal["artifact_digests"],"replacement_manifest":journal["replacement_manifest"],"replacement_artifact_digests":journal["replacement_artifact_digests"],"service_observations":services});
    drop(named);
    drop(held);
    let mut recovered = current.clone();
    recovered.output_directory = subject.output_directory.join("recovery");
    fs::create_dir(&recovered.output_directory)?;
    crate::windows_installed_cases::run_current_package(&recovered, "upgrade", deadlines.work)
        .map_err(CiError::Message)?;
    crate::windows_installed_cases::run_current_package(&recovered, "verify", deadlines.work)
        .map_err(CiError::Message)?;
    if journal_path.try_exists()? {
        return Err(CiError::Message(
            "actual current recovery retained its replacement journal".into(),
        ));
    }
    let mut readback = std::collections::BTreeMap::new();
    let mut pins = Vec::new();
    for selected in std::iter::once(&current.installed_agent)
        .chain(std::iter::once(&current.installed_manifest))
        .chain(current.installed_components.iter())
    {
        let held = crate::windows_readiness_adapter::hold_artifact(
            &selected.path,
            Some(&selected.sha256),
            512 * 1024 * 1024,
        )?;
        readback.insert(selected.path.clone(), held.sha256.clone());
        pins.push(held);
    }
    Ok(
        serde_json::json!({"subject":subject,"operation":"upgrade","result":result,"interrupted":facts,"recovered":recovered,"recovered_artifacts":readback,"journal_absent":true}),
    )
}

fn exercise_opaque_refusal(
    current: &InstalledWindowsPayload,
    plan: &WindowsRemovalPlan,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<serde_json::Value> {
    use std::{
        io::{Read, Write},
        os::windows::fs::OpenOptionsExt,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let directory = current.output_directory.join("opaque-state-refused");
    fs::create_dir(&directory)?;
    let before = crate::windows_readiness_adapter::observe_removed(
        current,
        plan,
        &current.output_directory.join("opaque-native-before"),
        deadlines.work,
    )?;
    fs::create_dir(&plan.binary_root)?;
    let root = fs::File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&plan.binary_root)?;
    let root_identity =
        crate::windows_readiness_adapter::native_file_identity(&root, true, &plan.binary_root)?;
    let path = plan.binary_root.join("opaque-current-install-probe.bin");
    let expected = [
        b"\0opaque current install input\xff\0".as_slice(),
        current.provider.generation.as_str().as_bytes(),
    ]
    .concat();
    let mut file = fs::File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)?;
    file.write_all(&expected)?;
    file.sync_all()?;
    let file_identity =
        crate::windows_readiness_adapter::native_file_identity(&file, false, &path)?;
    let mut subject = current.clone();
    subject.output_directory = directory;
    let result =
        crate::windows_installed_cases::run_current_package(&subject, "install", deadlines.work);
    let mut named = fs::File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)?;
    let named_identity =
        crate::windows_readiness_adapter::native_file_identity(&named, false, &path)?;
    let named_root = fs::File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&plan.binary_root)?;
    let named_root_identity = crate::windows_readiness_adapter::native_file_identity(
        &named_root,
        true,
        &plan.binary_root,
    )?;
    let mut actual = Vec::new();
    (&mut named)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut actual)?;
    let entries = fs::read_dir(&plan.binary_root)?.collect::<std::io::Result<Vec<_>>>()?;
    if result.is_ok()
        || actual != expected
        || file_identity != named_identity
        || root_identity != named_root_identity
        || entries.len() != 1
        || entries[0].path() != path
    {
        return Err(CiError::Message("opaque current install was accepted or changed original native objects; owner retained".into()));
    }
    let stderr = fs::read(subject.output_directory.join("package-install.stderr.bin"))?;
    if !String::from_utf8_lossy(&stderr).contains("MCSEALED-WINDOWS-ALREADY-INSTALLED") {
        return Err(CiError::Message(
            "opaque current install failed without actual occupied-state refusal; owner retained"
                .into(),
        ));
    }
    let capture: serde_json::Value = serde_json::from_slice(&fs::read(
        subject
            .output_directory
            .join("package-install.capture.json"),
    )?)?;
    if capture["operation_complete"] != true
        || capture["observed_exit_code"]
            .as_i64()
            .is_none_or(|code| code == 0)
    {
        return Err(CiError::Message(
            "opaque refusal lacks actual terminal package wait".into(),
        ));
    }
    drop(named);
    drop(file);
    drop(named_root);
    drop(root);
    fs::remove_file(&path)?;
    fs::remove_dir(&plan.binary_root)?;
    let after = crate::windows_readiness_adapter::observe_removed(
        current,
        plan,
        &current.output_directory.join("opaque-native-after"),
        deadlines.work,
    )?;
    Ok(
        serde_json::json!({"subject":subject,"operation":"install","result":result,"opaque":{"path":path,"root":plan.binary_root,"expected_bytes":expected,"observed_bytes":actual,"original_file_identity":file_identity,"observed_file_identity":named_identity,"original_root_identity":root_identity,"observed_root_identity":named_root_identity,"native_before_bytes":fs::read(before.receipt.path)?,"native_after_bytes":fs::read(after.receipt.path)?}}),
    )
}

pub fn run(
    root: &Path,
    payload: &MaterializedPayload,
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
    let (current_artifacts, current_fixture, current_diagnostic, _current_custody) =
        retain_payload(payload, &retained_current)?;
    let current = InstalledWindowsPayload::from_materialized(
        payload.channel,
        &payload.source,
        &payload.distribution,
        current_artifacts,
        &retained_current,
        current_fixture,
        current_diagnostic,
        &plan.binary_root,
        output.join("current"),
    )?;
    current.require_workload_diagnostic()?;
    fs::create_dir_all(&current.output_directory)?;
    super::source::write_json(&output.join("selected-current.json"), &current)?;
    super::source::write_json(
        &output.join("windows-lease-owner.json"),
        &Owner {
            format: "memcordon.consumer-readiness.windows-lease-owner".into(),
            revision: 2,
            identity: identity.clone(),
            key: key.clone(),
            current: current.clone(),
            binary_root: plan.binary_root.clone(),
            state_root: plan.state_root.clone(),
            diagnostics_root: plan.diagnostics_root.clone(),
            artifact_root: artifact_root.to_owned(),
            work_deadline_unix_millis: work_unix,
            cleanup_deadline_unix_millis: cleanup_unix,
        },
    )?;
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
    let mut finalization = None;
    let mut removal = None;
    let mut failures = Vec::new();
    let assessment = crate::windows_installed_cases::run_from_source_with_observer_until(
        root,
        &current,
        &mut |observed| {
            let (phase, operation) = match observed.phase {
                WindowsLeasePhase::BeforeFreshInstall => (
                    "owned-before-mutation",
                    "selected-current-fresh-install-intent",
                ),
                WindowsLeasePhase::AfterFreshInstall => {
                    ("fresh-install", "actual-selected-current-fresh-install")
                }
                WindowsLeasePhase::AfterFreshVerify => {
                    ("fresh-verify", "actual-selected-current-fresh-verification")
                }
                WindowsLeasePhase::BeforeCurrentUpgrade => ("upgrade", "current-upgrade-intent"),
                WindowsLeasePhase::AfterCurrentUpgrade => ("upgrade", "actual-current-upgrade"),
                WindowsLeasePhase::AfterCurrentVerify => {
                    ("verify", "actual-selected-current-upgraded-verification")
                }
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
                let references = recovered.artifacts.iter().map(|artifact| {
                    Ok(serde_json::json!({"path":relative_reference(artifact_root, &artifact.path)?,"sha256":artifact.sha256}))
                }).collect::<Result<Vec<_>>>()?;
                finalization = Some(
                    serde_json::json!({"recovery":recovered.recovery,"native_quiescence":recovered.native_quiescence,"native_status":recovered.native_status,"deadline_exhausted":recovered.deadline_exhausted,"artifacts":references}),
                );
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
            if observed.phase == WindowsLeasePhase::BeforeFreshInstall {
                let facts = exercise_opaque_refusal(&current, &plan, deadlines)?;
                event(
                    output,
                    artifact_root,
                    &mut journal,
                    "opaque-state-refused",
                    "actual-opaque-current-state-refusal",
                    true,
                    facts,
                )?;
            }
            if observed.phase == WindowsLeasePhase::AfterFreshVerify
                && observed.result.is_some_and(|result| result.is_ok())
            {
                let facts = exercise_interrupted_current(&current, &plan, deadlines)?;
                event(
                    output,
                    artifact_root,
                    &mut journal,
                    "interrupted-current-install",
                    "actual-interrupted-current-install",
                    true,
                    facts,
                )?;
            }
            if observed.phase == WindowsLeasePhase::AfterCurrentUpgrade
                && observed.result.is_some_and(|result| result.is_ok())
            {
                let binaries = super::windows_component_readback::observe(
                    &current,
                    &plan.binary_root,
                    &retained_current,
                    &payload.distribution.binaries,
                    &key.target,
                )?;
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
    let finalization_path = output.join("windows-finalization-v2.json");
    let removal_reference = removal.as_ref().map(|value| -> Result<serde_json::Value> { Ok(serde_json::json!({"path":relative_reference(artifact_root, &value.receipt.path)?,"sha256":value.receipt.sha256})) }).transpose()?;
    super::source::write_json(
        &finalization_path,
        &serde_json::json!({"format":"memcordon.windows-installed-finalization","revision":2,"run_id":identity.run_id,"lease_id":lease_id,"product":key,"provider":current.provider,"recovery":finalization,"removal":removal_reference}),
    )?;
    let native_evidence = relative_reference(artifact_root, &finalization_path)?;
    let receipt = InstalledLifecycleReceiptV2 {
        format: "memcordon.installed-lifecycle.receipt".into(),
        revision: 2,
        run_id: identity.run_id.clone(),
        lease_id,
        key: key.clone(),
        journal_sha256: super::artifacts::checksum(&super::artifacts::read_file(
            &output.join("installed-journal.json"),
        )?),
        final_sequence: journal.events.last().map_or(0, |event| event.sequence),
        explicit_finalization_count: 1,
        package_absent: assessment.package_uninstall.is_ok() && removed,
        native: [
            NativeResourceV2::WindowsJob,
            NativeResourceV2::WindowsTarget,
            NativeResourceV2::WindowsRelays,
            NativeResourceV2::WindowsControlHandles,
            NativeResourceV2::WindowsDesktop,
            NativeResourceV2::WindowsProcessHandles,
        ]
        .into_iter()
        .map(|resource| NativeResourceObservationV2 {
            resource,
            settled: recovery_complete && removed,
            evidence: native_evidence.clone(),
        })
        .collect(),
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
    let _retirement = crate::cancellation::retirement_scope(deadline);
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
        || owner.revision != 2
        || serde_json::to_value(&owner.identity)? != serde_json::to_value(identity)?
        || owner.key != *key
        || owner.current.source_commit != identity.source_commit
        || owner.current.version != identity.version
        || owner.current.target != key.target
        || !owner.current.output_directory.starts_with(output)
    {
        return Err(CiError::Message(
            "Windows cleanup cannot reassociate original installation ownership".into(),
        ));
    }
    let plan = WindowsRemovalPlan {
        binary_root: owner.binary_root,
        state_root: owner.state_root,
        diagnostics_root: owner.diagnostics_root,
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
            } else {
                return Err(CiError::Message(
                    "interrupted Windows installation differs from current measured bytes".into(),
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
    super::source::write_json(
        &destination.join("native-removal.json"),
        &serde_json::json!({"identity":identity,"key":key,"current":current}),
    )
}
