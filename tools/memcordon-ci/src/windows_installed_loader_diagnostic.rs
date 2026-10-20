//! Separate support evidence for an installed refusal, never readiness authority.
#[cfg(windows)]
use crate::windows_consumer_readiness::CaseInput;
#[cfg(windows)]
use crate::windows_installed_cases::{InstalledWindowsPayload, WindowsLeaseDeadlines};
use crate::{CiError, Result};
#[cfg(windows)]
use std::fs::{self, OpenOptions};
#[cfg(windows)]
use std::io::Write;
#[cfg(windows)]
use std::path::Path;
use std::time::{Duration, Instant};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    if fs::symlink_metadata(path)?.len() > limit as u64 {
        return Err(CiError::Message(
            "installed diagnostic record exceeds bound".into(),
        ));
    }
    let bytes = crate::release::artifacts::read_file(path)?;
    if bytes.len() > limit {
        return Err(CiError::Message(
            "installed diagnostic record grew beyond bound".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(windows)]
fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if read(path, bytes.len())? != bytes {
        return Err(CiError::Message(
            "installed diagnostic readback differs".into(),
        ));
    }
    Ok(())
}

/// Caller has settled the original frontend and checked provider quiescence.
/// The executor retains the existing secret-free native frontend boundary.
#[cfg(windows)]
pub(crate) fn collect(
    config: &InstalledWindowsPayload,
    input: &CaseInput,
    original_provider: &InstalledWindowsPayload,
    deadlines: WindowsLeaseDeadlines,
    challenge: &[u8],
    execute: impl FnOnce(
        crate::command::CommandSpec,
        Instant,
    ) -> Result<memcordon_testkit::ObservedOutput>,
) -> Result<()> {
    let directory = config.output_directory.join("support-loader-diagnostic");
    fs::create_dir(&directory)?;
    let result = (|| -> Result<()> {
        deadlines.work_budget(Duration::from_secs(30))?;
        let original_bytes = read(
            &original_provider
                .output_directory
                .join("pending-loader-diagnostic/original-result.json"),
            crate::windows_causal_acceptance::MAX_REPORT_BYTES,
        )?;
        let original =
            memcordon_core::ResultV1::parse(&original_bytes).map_err(CiError::Message)?;
        if !crate::support_loader_producer::installed_trigger(
            &original,
            &original_provider.provider,
        )? {
            return Err(CiError::Message(
                "installed refusal is not a settled loader-control failure".into(),
            ));
        }
        persist(&directory.join("original-result.json"), &original_bytes)?;
        let bootstrap = config
            .installed_components
            .iter()
            .find(|image| {
                image
                    .path
                    .file_name()
                    .is_some_and(|name| name == "memcordon-target-desktop-bootstrap.exe")
            })
            .ok_or_else(|| CiError::Message("installed diagnostic bootstrap absent".into()))?;
        for image in [
            &config.cli,
            &config.fixture,
            &config.installed_agent,
            &config.installed_manifest,
            bootstrap,
        ] {
            deadlines.work_budget(Duration::from_secs(30))?;
            if crate::windows_causal_acceptance::sha256(&read(&image.path, 512 * 1024 * 1024)?)
                != image.sha256
            {
                return Err(CiError::Message(
                    "installed diagnostic selected image changed".into(),
                ));
            }
        }
        let binding = serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.installed-loader-diagnostic-binding", "revision":1,
            "diagnostic_only":true, "certification_authority":false,
            "source_commit":config.source_commit, "target":config.target,
            "original_provider":original_provider.provider,
            "channel":config.channel, "provider":config.provider,
            "cli":config.cli, "fixture":config.fixture, "bootstrap":bootstrap,
            "installed_agent":config.installed_agent, "installed_manifest":config.installed_manifest,
            "original_result_sha256":crate::windows_causal_acceptance::sha256(&original_bytes),
            "original_work_deadline_unix_millis":deadlines.work_deadline_unix_millis,
            "original_cleanup_deadline_unix_millis":deadlines.cleanup_deadline_unix_millis,
        }))?;
        persist(&directory.join("producer-binding.json"), &binding)?;
        let origin = Instant::now();
        let unix = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| CiError::Message(error.to_string()))?
                .as_millis(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let selection = crate::support_loader_producer::installed_selection(
            challenge,
            &bootstrap.sha256,
            &crate::windows_causal_acceptance::sha256(&binding),
            unix,
            deadlines.work_deadline_unix_millis,
            deadlines.cleanup_deadline_unix_millis,
        )?;
        let cutoff = deadlines
            .work
            .min(origin + Duration::from_millis(selection.work_deadline_unix_ms - unix));
        let candidate = input
            .descriptor
            .output_root
            .join("support-loader-diagnostic");
        fs::create_dir(&candidate)?;
        // Keep the exact already-approved workload arguments and descriptor.
        // Only the separate diagnostic request gets a fresh challenge and paths;
        // this mode cannot authorize or execute the fixture workload.
        let selection_path = candidate.join("selection.json");
        let selected_bytes = serde_json::to_vec(&selection)?;
        persist(&selection_path, &selected_bytes)?;
        persist(&directory.join("selection.json"), &selected_bytes)?;
        let observation_path = candidate.join("observation.json");
        let report = candidate.join("frontend-result.json");
        let command = crate::windows_consumer_readiness::installed_support_loader_command(
            &config.cli.path,
            &config.fixture.path,
            &config.output_directory,
            &report,
            input,
            &selection_path,
            &observation_path,
        )?
        .bounded_until(cutoff);
        let outcome = execute(command, cutoff);
        match &outcome {
            Ok(output) => {
                persist(&directory.join("stdout.bin"), &output.stdout)?;
                persist(&directory.join("stderr.bin"), &output.stderr)?;
                persist(
                    &directory.join("observed-exit.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "status":output.status.code(), "streams_available":true,
                        "observed_elapsed_millis":output.elapsed.as_millis(),
                    }))?,
                )?;
            }
            Err(error) => {
                persist(
                    &directory.join("process-failure.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "error":error.to_string(), "native_status_not_invented":true,
                    }))?,
                )?;
            }
        }
        // Preserve available native evidence even when the owned command failed.
        for (path, name, limit) in [
            (
                &observation_path,
                "frontend-observation.json",
                8 * 1024 * 1024,
            ),
            (&report, "frontend-result.json", 16 * 1024 * 1024),
        ] {
            if path.try_exists()? {
                persist(&directory.join(name), &read(path, limit)?)?;
            }
        }
        let output = outcome?;
        if output.status.success() {
            return Err(CiError::Message(
                "installed diagnostic cannot satisfy the failed positive case".into(),
            ));
        }
        let observed = read(
            &directory.join("frontend-observation.json"),
            8 * 1024 * 1024,
        )?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&observed)
            .map_err(CiError::Message)?;
        let observation: crate::support_loader_producer::FrontendObservation =
            serde_json::from_slice(&observed)?;
        let refusal = crate::support_loader_producer::validate_frontend(
            &observation,
            &selection,
            &config.provider,
        )?;
        persist(
            &directory.join("bound-refusal.json"),
            &serde_json::to_vec(&refusal)?,
        )?;
        for (index, frame) in observation.authenticated_provider_frames.iter().enumerate() {
            persist(
                &directory.join(format!("provider-frame-{index}.bin")),
                frame,
            )?;
        }
        crate::support_loader_producer::require_complete_debug_capture(&refusal)
    })();
    persist(
        &directory.join("capture-outcome.json"),
        &serde_json::to_vec(&serde_json::json!({
            "diagnostic_only":true, "certification_authority":false,
            "capture":result.as_ref().map(|_| ()).map_err(ToString::to_string),
            "original_failure_unchanged":true,
        }))?,
    )?;
    result
}

/// Preserve original authority-free inputs before the production uninstall.
#[cfg(windows)]
pub(crate) fn retain(
    config: &InstalledWindowsPayload,
    input: &CaseInput,
    deadlines: WindowsLeaseDeadlines,
) -> Result<()> {
    deadlines.work_budget(Duration::from_secs(30))?;
    let original = read(
        &input.descriptor.output_root.join("frontend-result.json"),
        crate::windows_causal_acceptance::MAX_REPORT_BYTES,
    )?;
    let parsed = memcordon_core::ResultV1::parse(&original).map_err(CiError::Message)?;
    if !crate::support_loader_producer::installed_trigger(&parsed, &config.provider)? {
        return Err(CiError::Message(
            "pending diagnostic has no settled original refusal".into(),
        ));
    }
    let directory = config.output_directory.join("pending-loader-diagnostic");
    fs::create_dir(&directory)?;
    let bootstrap = config
        .installed_components
        .iter()
        .find(|image| {
            image
                .path
                .file_name()
                .is_some_and(|name| name == "memcordon-target-desktop-bootstrap.exe")
        })
        .ok_or_else(|| CiError::Message("original installed bootstrap absent".into()))?;
    let _held = crate::windows_readiness_adapter::copy_owned_artifact(
        &bootstrap.path,
        &directory.join("memcordon-target-desktop-bootstrap.exe"),
        &bootstrap.sha256,
    )?;
    persist(&directory.join("original-result.json"), &original)?;
    persist(
        &directory.join("original-input.json"),
        &serde_json::to_vec(input)?,
    )?;
    persist(
        &directory.join("original-contract.json"),
        &read(&input.workload_contract, 256 * 1024)?,
    )?;
    persist(
        &directory.join("association.json"),
        &serde_json::to_vec(&association()?)?,
    )?;
    persist(
        &directory.join("original-payload.json"),
        &serde_json::to_vec(config)?,
    )?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn association() -> Result<serde_json::Value> {
    let run =
        std::env::var("GITHUB_RUN_ID").map_err(|error| CiError::Message(error.to_string()))?;
    let job = std::env::var("GITHUB_JOB").map_err(|error| CiError::Message(error.to_string()))?;
    let attempt =
        std::env::var("GITHUB_RUN_ATTEMPT").map_err(|error| CiError::Message(error.to_string()))?;
    if run.parse::<u64>().ok().filter(|value| *value > 0).is_none()
        || attempt
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
        || job.is_empty()
    {
        return Err(CiError::Message(
            "installed support requires its actual CI association".into(),
        ));
    }
    Ok(serde_json::json!({"run":run,"job":job,"attempt":attempt}))
}

/// Keep the actual bounded executor typechecked on every host.
pub(crate) fn execute(
    spec: crate::command::CommandSpec,
    cutoff: Instant,
) -> Result<memcordon_testkit::ObservedOutput> {
    let mut command = spec.materialize()?;
    // Match the actual public readiness frontend's secret-free boundary.
    command.env_clear();
    command.stdin(std::process::Stdio::null());
    let remaining = cutoff.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(CiError::Message(
            "installed diagnostic original work cutoff exhausted".into(),
        ));
    }
    memcordon_testkit::run_with_deadline_output_limit(&mut command, remaining, 1024 * 1024)
        .map_err(|error| CiError::Message(error.to_string()))
}

#[cfg(test)]
#[path = "../tests/private/windows_installed_loader_diagnostic.rs"]
mod tests;
