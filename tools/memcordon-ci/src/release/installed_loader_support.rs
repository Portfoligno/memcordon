//! A diagnostic-only installation after the original production owner retires.
use super::source::BuildSourceIdentity;
use crate::windows_installed_cases::{
    InstalledWindowsAssessment, InstalledWindowsPayload, WindowsLeaseDeadlines,
};
use crate::{CiError, Result};
use memcordon_core::runtime_manifest::{RuntimeComponentRole, RuntimeManifest};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupClock {
    domain: String,
    observed_millis: u64,
    cleanup_millis: u64,
    cleanup_unix_millis: u64,
}

impl CleanupClock {
    fn acquire(
        deadlines: WindowsLeaseDeadlines,
        clock: crate::ci_operation_time::ClockReading,
    ) -> Result<Self> {
        let remaining = u64::try_from(
            deadlines
                .cleanup_budget(std::time::Duration::from_secs(150 * 60))?
                .as_millis(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        Ok(Self {
            domain: clock.domain,
            observed_millis: clock.millis,
            cleanup_millis: clock
                .millis
                .checked_add(remaining)
                .ok_or_else(|| CiError::Message("support cleanup boot cutoff overflow".into()))?,
            cleanup_unix_millis: deadlines.cleanup_deadline_unix_millis,
        })
    }
    fn remaining(
        &self,
        clock: crate::ci_operation_time::ClockReading,
        unix: u64,
    ) -> Result<std::time::Duration> {
        if clock.domain != self.domain
            || clock.millis < self.observed_millis
            || clock.millis >= self.cleanup_millis
            || unix >= self.cleanup_unix_millis
        {
            return Err(CiError::Message(
                "support cleanup original boot/domain/cutoff differs or exhausted".into(),
            ));
        }
        Ok(std::time::Duration::from_millis(
            (self.cleanup_millis - clock.millis).min(self.cleanup_unix_millis - unix),
        ))
    }
}

#[cfg(windows)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    format: String,
    revision: u32,
    source: BuildSourceIdentity,
    association: serde_json::Value,
    origin_sha256: String,
    config: InstalledWindowsPayload,
    removal: crate::windows_readiness_adapter::WindowsRemovalPlan,
    role_origins: Vec<serde_json::Value>,
    clock: CleanupClock,
}

fn admit(
    source: &BuildSourceIdentity,
    original: &InstalledWindowsPayload,
    assessment: &InstalledWindowsAssessment,
    deadlines: WindowsLeaseDeadlines,
) -> Result<()> {
    source.validate()?;
    if source.commit() != original.source_commit
        || source.version().to_string() != original.version
        || assessment.source_commit != original.source_commit
        || assessment.version != original.version
        || assessment.target != original.target
        || assessment.channel != original.channel
        || serde_json::to_vec(&assessment.artifacts)? != serde_json::to_vec(&original.artifacts)?
        || assessment.package_uninstall.is_err()
        || assessment.positive_suite.is_ok()
        || deadlines.work >= deadlines.cleanup
        || deadlines.work_deadline_unix_millis >= deadlines.cleanup_deadline_unix_millis
    {
        return Err(CiError::Message(
            "installed diagnostic source, original retirement or cutoff differs".into(),
        ));
    }
    deadlines.work_budget(std::time::Duration::from_secs(1))?;
    Ok(())
}

fn mixed_manifest(actor: &RuntimeManifest, original_bootstrap: &[u8]) -> Result<RuntimeManifest> {
    let actor = RuntimeManifest::parse(&serde_json::to_vec(actor)?).map_err(CiError::Message)?;
    super::target::validate_executable(original_bootstrap, &actor.target)?;
    let mut mixed = actor.clone();
    let bootstrap = mixed
        .components
        .iter_mut()
        .find(|component| component.role == RuntimeComponentRole::DesktopBootstrap)
        .ok_or_else(|| CiError::Message("measured support actor omits desktop bootstrap".into()))?;
    *bootstrap = super::target::runtime_component(
        RuntimeComponentRole::DesktopBootstrap,
        bootstrap.path.clone(),
        original_bootstrap,
    );
    RuntimeManifest::parse(&serde_json::to_vec(&mixed)?).map_err(CiError::Message)
}

#[cfg(windows)]
pub(super) fn run(
    root: &std::path::Path,
    payload: &super::installed_consumer::MaterializedPayload,
    original: &InstalledWindowsPayload,
    assessment: &InstalledWindowsAssessment,
    deadlines: WindowsLeaseDeadlines,
) -> Result<()> {
    use super::{artifacts, original_native_components as lifetime};
    use crate::windows_installed_cases::SelectedArtifact;
    use std::fs;
    let pending = original.output_directory.join("pending-loader-diagnostic");
    if !pending.try_exists()? {
        return Ok(());
    }
    admit(&payload.source, original, assessment, deadlines)?;
    if payload.distribution.target != original.target {
        return Err(CiError::Message(
            "installed support target differs from original selection".into(),
        ));
    }
    payload.source.recheck(root)?;
    let directory =
        std::path::absolute(&original.output_directory)?.join("separate-loader-support");
    fs::create_dir(&directory)?;
    let persist = |path: &std::path::Path, bytes: &[u8]| -> Result<()> {
        let _receipt = crate::windows_readiness_adapter::publish_receipt(path, bytes)?;
        Ok(())
    };
    let read = |path: &std::path::Path| -> Result<Vec<u8>> {
        Ok(crate::windows_readiness_adapter::hold_artifact(path, None, 512 * 1024 * 1024)?.bytes)
    };
    let retained: InstalledWindowsPayload =
        serde_json::from_slice(&read(&pending.join("original-payload.json"))?)?;
    if serde_json::to_vec(&retained)? != serde_json::to_vec(original)? {
        return Err(CiError::Message(
            "pending diagnostic original payload changed".into(),
        ));
    }
    let association =
        crate::windows_consumer_readiness::installed_loader_diagnostic::association()?;
    if serde_json::from_slice::<serde_json::Value>(&read(&pending.join("association.json"))?)?
        != association
    {
        return Err(CiError::Message(
            "pending diagnostic CI association changed".into(),
        ));
    }
    let job = association["job"]
        .as_str()
        .ok_or_else(|| CiError::Message("support job absent".into()))?;
    let attempt = association["attempt"]
        .as_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| CiError::Message("support attempt absent".into()))?;
    let original_result = read(&pending.join("original-result.json"))?;
    let parsed = memcordon_core::ResultV1::parse(&original_result).map_err(CiError::Message)?;
    if !crate::support_loader_producer::installed_trigger(&parsed, &original.provider)? {
        return Err(CiError::Message(
            "pending diagnostic original refusal changed".into(),
        ));
    }
    let original_bootstrap = original
        .installed_components
        .iter()
        .find(|image| {
            image
                .path
                .file_name()
                .is_some_and(|name| name == "memcordon-target-desktop-bootstrap.exe")
        })
        .ok_or_else(|| CiError::Message("original bootstrap selection absent".into()))?;
    let bootstrap_bytes = read(&pending.join("memcordon-target-desktop-bootstrap.exe"))?;
    if artifacts::checksum(&bootstrap_bytes) != original_bootstrap.sha256 {
        return Err(CiError::Message(
            "retained original bootstrap changed".into(),
        ));
    }
    let removal = super::windows_readiness_lease::inspect_removal_plan_for_source(
        root,
        &original.agent,
        payload.source.commit(),
        &payload.source.version().to_string(),
        &directory,
        deadlines.work,
    )?;
    let mut original_removal_config = original.clone();
    original_removal_config.output_directory = std::path::absolute(&original.output_directory)?;
    let removed = crate::windows_readiness_adapter::observe_removed(
        &original_removal_config,
        &removal,
        &directory.join("original-removal"),
        deadlines.work,
    )?;
    let binding = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.installed-loader-support-origin", "revision":1,
        "diagnostic_only":true,"certification_authority":false,
        "source":payload.source,"original_provider":original.provider,
        "original_target":original.target,"original_channel":original.channel,
        "association":association,
        "original_result_sha256":artifacts::checksum(&original_result),
        "original_input_sha256":artifacts::checksum(&read(&pending.join("original-input.json"))?),
        "original_contract_sha256":artifacts::checksum(&read(&pending.join("original-contract.json"))?),
        "original_bootstrap_sha256":original_bootstrap.sha256,
        "original_assessment_sha256":artifacts::checksum(&serde_json::to_vec(assessment)?),
        "original_removal":removed.receipt,
        "original_work_deadline_unix_millis":deadlines.work_deadline_unix_millis,
        "original_cleanup_deadline_unix_millis":deadlines.cleanup_deadline_unix_millis,
    }))?;
    persist(&directory.join("origin.json"), &binding)?;
    let actor = directory.join("measured-actor");
    super::native_component_harness::build_windows_actor(
        root,
        &payload.source,
        &original.target,
        &actor,
        deadlines.work,
    )?;
    let actor_manifest = RuntimeManifest::parse(&read(&actor.join("runtime-manifest.json"))?)
        .map_err(CiError::Message)?;
    let mixed = mixed_manifest(&actor_manifest, &bootstrap_bytes)?;
    let selected = directory.join("selected-support");
    fs::create_dir(&selected)?;
    let mut custody = Vec::new();
    let mut measured = Vec::new();
    let mut origins = Vec::new();
    for component in &mixed.components {
        let relative = artifacts::safe_relative(std::path::Path::new(&component.path))?;
        if relative.components().count() != 1 {
            return Err(CiError::Message("support component path escaped".into()));
        }
        let is_original = component.role == RuntimeComponentRole::DesktopBootstrap;
        let source = if is_original {
            pending.join("memcordon-target-desktop-bootstrap.exe")
        } else {
            actor.join(&relative)
        };
        let copied = selected.join(&relative);
        custody.push(crate::windows_readiness_adapter::copy_owned_artifact(
            &source,
            &copied,
            &component.sha256,
        )?);
        measured.push(SelectedArtifact {
            path: copied,
            sha256: component.sha256.clone(),
        });
        origins.push(serde_json::json!({"role":component.role,"sha256":component.sha256,
            "origin":if is_original {"original-production-bootstrap"}else{"measured-support-actor"},
            "features":if is_original {payload.distribution.features.clone()}else{vec!["test-support".into(),"windows-sealed-runtime".into()]}}));
    }
    persist(
        &selected.join("runtime-manifest.json"),
        &serde_json::to_vec(&mixed)?,
    )?;
    let (fixture, fixture_custody) = retain_fixture(&selected, &payload.fixture)?;
    custody.push(fixture_custody);
    let config = InstalledWindowsPayload::from_materialized(
        crate::windows_causal_acceptance::InstalledChannel::NativeBundle,
        &payload.source,
        &payload.distribution,
        measured,
        &selected,
        fixture,
        payload.workload_diagnostic.clone(),
        &removal.binary_root,
        directory.join("observations"),
    )?;
    if config.provider == original.provider {
        return Err(CiError::Message(
            "diagnostic provider must be a distinct measured graph".into(),
        ));
    }
    fs::create_dir(&config.output_directory)?;
    crate::windows_readiness_adapter::observe_removed(
        &config,
        &removal,
        &config.output_directory.join("before-install"),
        deadlines.work,
    )?;
    let owner = Owner {
        format: "memcordon.installed-loader-support-owner".into(),
        revision: 1,
        source: payload.source.clone(),
        association: association.clone(),
        origin_sha256: artifacts::checksum(&binding),
        role_origins: origins,
        config: config.clone(),
        removal: removal.clone(),
        clock: CleanupClock::acquire(deadlines, crate::ci_operation_time::clock_reading()?)?,
    };
    persist(&directory.join("owner.json"), &serde_json::to_vec(&owner)?)?;
    let cleanup_directory = config.output_directory.join("cleanup");
    fs::create_dir(&cleanup_directory)?;
    let operation = (|| -> Result<()> {
        lifetime::support_package(&config, job, attempt, "install", deadlines.work)?;
        lifetime::support_package(&config, job, attempt, "verify", deadlines.work)?;
        crate::windows_consumer_readiness::provision_from_source_until(
            root,
            &config,
            deadlines.work,
        )?;
        capture(&config, original, deadlines)
    })();
    let cleanup = retire(&owner, &cleanup_directory, deadlines.cleanup);
    persist(
        &directory.join("outcome.json"),
        &serde_json::to_vec(&serde_json::json!({
            "diagnostic_only":true,"certification_authority":false,"original_failure_unchanged":true,
            "capture":operation.as_ref().map(|_|()).map_err(ToString::to_string),
            "retirement":cleanup.as_ref().map(|_|()).map_err(ToString::to_string),
        }))?,
    )?;
    match (operation, cleanup) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(CiError::Message(format!(
            "{error}; support retirement: {cleanup}"
        ))),
    }
}

#[cfg(windows)]
fn retain_fixture(
    selected: &std::path::Path,
    source: &crate::windows_installed_cases::SelectedArtifact,
) -> Result<(
    crate::windows_installed_cases::SelectedArtifact,
    crate::windows_readiness_adapter::HeldWindowsArtifact,
)> {
    let fixture = crate::windows_installed_cases::SelectedArtifact {
        path: selected.join("memcordon-test-fixture.exe"),
        sha256: source.sha256.clone(),
    };
    let custody = crate::windows_readiness_adapter::copy_owned_artifact(
        &source.path,
        &fixture.path,
        &fixture.sha256,
    )?;
    Ok((fixture, custody))
}

#[cfg(windows)]
fn retire(owner: &Owner, directory: &std::path::Path, deadline: std::time::Instant) -> Result<()> {
    let config = &owner.config;
    let mut custody = Vec::new();
    for image in config
        .components
        .iter()
        .chain(std::iter::once(&config.fixture))
    {
        custody.push(crate::windows_readiness_adapter::hold_artifact(
            &image.path,
            Some(&image.sha256),
            512 * 1024 * 1024,
        )?);
    }
    match std::fs::symlink_metadata(&config.installed_manifest.path) {
        Ok(_) => {
            let installed = crate::windows_readiness_adapter::hold_artifact(
                &config.installed_manifest.path,
                Some(&config.installed_manifest.sha256),
                16 * 1024 * 1024,
            )?;
            let job = owner.association["job"]
                .as_str()
                .ok_or_else(|| CiError::Message("support job absent".into()))?;
            let attempt = owner.association["attempt"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| CiError::Message("support attempt absent".into()))?;
            drop(installed);
            let receipts = super::original_native_components::settle_support(
                config,
                &owner.removal,
                job,
                attempt,
                directory,
                deadline,
            )?;
            let _settlement = crate::windows_readiness_adapter::publish_receipt(
                &directory.join("support-settlement.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.installed-loader-support-settlement","revision":1,
                    "diagnostic_only":true,"certification_authority":false,
                    "owner_sha256":super::artifacts::checksum(&serde_json::to_vec(owner)?),
                    "receipts":receipts,
                }))?,
            )?;
            if std::time::Instant::now() >= deadline {
                return Err(CiError::Message(
                    "support settlement exceeded original cleanup cutoff".into(),
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::windows_readiness_adapter::observe_removed(
                config,
                &owner.removal,
                &directory.join("removal"),
                deadline,
            )?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
pub(super) fn cleanup(root: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    let directory =
        std::path::absolute(destination)?.join("cases/windows-installed/separate-loader-support");
    let path = directory.join("owner.json");
    // Preparation cannot install before the exclusive durable owner publication.
    if !path.try_exists()? {
        return Ok(());
    }
    let held = crate::windows_readiness_adapter::hold_artifact(&path, None, 16 * 1024 * 1024)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&held.bytes)
        .map_err(CiError::Message)?;
    let owner: Owner = serde_json::from_slice(&held.bytes)?;
    let origin = crate::windows_readiness_adapter::hold_artifact(
        &directory.join("origin.json"),
        Some(&owner.origin_sha256),
        16 * 1024 * 1024,
    )?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&origin.bytes)
        .map_err(CiError::Message)?;
    let origin: serde_json::Value = serde_json::from_slice(&origin.bytes)?;
    if owner.format != "memcordon.installed-loader-support-owner"
        || owner.revision != 1
        || owner.association
            != crate::windows_consumer_readiness::installed_loader_diagnostic::association()?
        || owner.config.output_directory != directory.join("observations")
        || owner.config.fixture.path
            != directory.join("selected-support/memcordon-test-fixture.exe")
        || owner.config.source_commit != owner.source.commit()
        || owner.config.version != owner.source.version().to_string()
        || origin["format"] != "memcordon.installed-loader-support-origin"
        || origin["revision"] != 1
        || origin["diagnostic_only"] != true
        || origin["certification_authority"] != false
        || origin["source"] != serde_json::to_value(&owner.source)?
        || origin["association"] != owner.association
        || origin["original_cleanup_deadline_unix_millis"] != owner.clock.cleanup_unix_millis
        || origin["original_provider"] == serde_json::to_value(&owner.config.provider)?
        || owner
            .config
            .components
            .iter()
            .find(|image| {
                image
                    .path
                    .file_name()
                    .is_some_and(|name| name == "memcordon-target-desktop-bootstrap.exe")
            })
            .is_none_or(|image| origin["original_bootstrap_sha256"] != image.sha256)
        || owner
            .config
            .components
            .iter()
            .any(|image| image.path.parent() != Some(directory.join("selected-support").as_path()))
    {
        return Err(CiError::Message(
            "support cleanup cannot reassociate original diagnostic owner".into(),
        ));
    }
    owner.source.recheck(root)?;
    let unix = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| CiError::Message(error.to_string()))?
            .as_millis(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let remaining = owner
        .clock
        .remaining(crate::ci_operation_time::clock_reading()?, unix)?;
    let deadline = std::time::Instant::now() + remaining;
    let _retirement = crate::cancellation::retirement_scope(deadline);
    let attempt = (0..64)
        .find(|attempt| {
            !owner
                .config
                .output_directory
                .join(format!("cleanup-resume-{attempt}"))
                .exists()
        })
        .ok_or_else(|| CiError::Message("support cleanup retry inventory exhausted".into()))?;
    let output = owner
        .config
        .output_directory
        .join(format!("cleanup-resume-{attempt}"));
    std::fs::create_dir(&output)?;
    retire(&owner, &output, deadline)
}

#[cfg(windows)]
fn capture(
    config: &InstalledWindowsPayload,
    original: &InstalledWindowsPayload,
    deadlines: WindowsLeaseDeadlines,
) -> Result<()> {
    use std::time::Duration;
    let input: crate::windows_consumer_readiness::SuiteInput =
        serde_json::from_slice(&super::artifacts::read_file(
            &config.output_directory.join("windows-readiness-input.json"),
        )?)?;
    crate::windows_consumer_readiness::validate_suite(&input)?;
    let mut case = input
        .cases
        .into_iter()
        .find(|case| case.key.family == "W-ENVELOPE" && case.key.scenario == "restricted")
        .ok_or_else(|| CiError::Message("support restricted case absent".into()))?;
    let activation = crate::command::CommandSpec::new(
        &config.installed_agent.path,
        &config.output_directory,
        Duration::from_secs(90),
    )
    .args([
        std::ffi::OsString::from("package"),
        "policy".into(),
        "apply".into(),
        "--file".into(),
        input.local_policy.clone().into_os_string(),
    ])
    .bounded_until(deadlines.work)
    .output_limit(256 * 1024)
    .output_quiet()?;
    crate::command::require_successful_output(
        "installed diagnostic policy activation",
        &activation,
    )?;
    let registry = memcordon_core::workload_registry::RuntimePolicyRegistry::parse(
        &super::artifacts::read_file(&input.local_policy)?,
    )
    .map_err(CiError::Message)?;
    let contract = memcordon_core::workload_contract::WorkloadContractV1::parse(
        &super::artifacts::read_file(&case.workload_contract)?,
    )
    .map_err(CiError::Message)?;
    let activated = crate::windows_policy_activation::refresh_contract(
        &contract,
        &registry,
        &activation.stdout,
    )?;
    let original_contract =
        memcordon_core::workload_contract::WorkloadContractV1::parse(&super::artifacts::read_file(
            &original
                .output_directory
                .join("pending-loader-diagnostic/original-contract.json"),
        )?)
        .map_err(CiError::Message)?;
    if activated.expected_epoch == original_contract.expected_epoch {
        return Err(CiError::Message(
            "support diagnostic must bind a distinct actual policy epoch".into(),
        ));
    }
    case.workload_contract = crate::windows_consumer_readiness::write_activated_contract(
        &config.output_directory,
        &case.key,
        &serde_json::to_vec(&activated)?,
    )?;
    std::fs::create_dir_all(&case.descriptor.output_root)?;
    let _descriptor = crate::windows_readiness_adapter::publish_receipt(
        &case.descriptor_path,
        &serde_json::to_vec(&case.descriptor)?,
    )?;
    let _activation = crate::windows_readiness_adapter::publish_receipt(
        &config
            .output_directory
            .join("diagnostic-policy-activation.json"),
        &activation.stdout,
    )?;
    crate::windows_consumer_readiness::installed_loader_diagnostic::collect(
        config,
        &case,
        original,
        deadlines,
        &case.descriptor.challenge,
        crate::windows_consumer_readiness::installed_loader_diagnostic::execute,
    )
}

#[cfg(test)]
#[path = "../../tests/private/installed_loader_support.rs"]
pub(super) mod tests;
