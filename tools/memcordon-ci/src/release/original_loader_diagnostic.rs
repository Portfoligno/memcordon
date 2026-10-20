//! Separate measured support operation. Nothing here emits readiness rows.
use super::*;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub identity: PathBuf,
    #[arg(
        long,
        required_unless_present = "github_context",
        conflicts_with = "github_context"
    )]
    pub run_attempt: Option<u64>,
    #[arg(long)]
    pub github_context: bool,
    #[arg(long)]
    pub destination: PathBuf,
    #[arg(long)]
    pub cleanup: bool,
}

#[cfg(not(windows))]
pub fn run(_root: &Path, _args: &Args) -> Result<()> {
    Err(CiError::Message(
        "support loader experiment requires its actual Windows producer".into(),
    ))
}

#[cfg(windows)]
pub fn run(root: &Path, args: &Args) -> Result<()> {
    use crate::support_loader_producer::DiagnosticDeadline;
    let root = std::path::absolute(root)?;
    let destination = std::path::absolute(&args.destination)?;
    crate::workflow_output::write(&[
        ("diagnostic-started", "false".into()),
        ("cache-quiescent", "false".into()),
    ])?;
    let identity_record = OwnedRecord::read(&args.identity)?;
    let identity: SourceIdentity = identity_record.parse()?;
    let production = root.join(".release/native-readiness");
    let production_owner_record =
        OwnedRecord::read(&production.join("windows-support-lifetime/owner.json"))?;
    let production_owner: WindowsOriginalOwner = production_owner_record.parse()?;
    let settlement_record = OwnedRecord::read(&production.join("windows-support-settled.json"))?;
    let settlement: WindowsSettlement = settlement_record.parse()?;
    if production_owner.config.output_directory
        != production.join("windows-support-lifetime/observations")
        || serde_json::to_vec(&production_owner.identity)? != serde_json::to_vec(&identity)?
    {
        return Err(CiError::Message(
            "diagnostic prerequisite is not the original native owner".into(),
        ));
    }
    let _settlement_custody = validate_windows_settlement(&production_owner, &settlement)?;
    let deadline_path = destination.join("original-diagnostic-deadline.json");
    let deadline: DiagnosticDeadline = if args.cleanup {
        OwnedRecord::read(&deadline_path)?.parse()?
    } else {
        if destination.try_exists()? {
            return Err(CiError::Message(
                "diagnostic producer cannot reacquire its origin".into(),
            ));
        }
        // Acquire once before any materialization, installation or retention.
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| CiError::Message(error.to_string()))?
                .as_millis(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let acquired = DiagnosticDeadline::at(
            identity.clone(),
            crate::release::distribution::native_target()?.into(),
            artifacts::checksum(&settlement_record.bytes),
            now,
        )?;
        std::fs::create_dir(&destination)?;
        persist(&deadline_path, &serde_json::to_vec(&acquired)?)?;
        acquired
    };
    if deadline.production_settlement_sha256 != artifacts::checksum(&settlement_record.bytes) {
        return Err(CiError::Message(
            "diagnostic settlement prerequisite changed".into(),
        ));
    }
    let original_args = super::Args {
        identity: args.identity.clone(),
        run_attempt: args.run_attempt,
        github_context: args.github_context,
        destination: destination.clone(),
        cleanup: args.cleanup,
    };
    let selection = select_with_diagnostic_deadline(&root, &original_args, Some(&deadline))?;
    if production_owner.job != selection.job
        || production_owner.run_attempt != selection.run_attempt
    {
        return Err(CiError::Message(
            "diagnostic original producer job differs".into(),
        ));
    }
    if args.cleanup {
        return cleanup_windows(&root, &destination, &selection);
    }
    crate::workflow_output::write(&[("diagnostic-started", "true".into())])?;
    let artifacts_directory = destination.join("diagnostic-artifacts");
    std::fs::create_dir(&artifacts_directory)?;
    persist(
        &artifacts_directory.join("original-diagnostic-deadline.json"),
        &serde_json::to_vec(&deadline)?,
    )?;
    let preparation = selection
        .work
        .checked_sub(crate::support_loader_producer::BOOTSTRAP_WORK)
        .ok_or_else(|| CiError::Message("diagnostic preparation cutoff unavailable".into()))?;
    persist(
        &artifacts_directory.join("production-settlement.json"),
        &settlement_record.bytes,
    )?;
    let (owner, _custody) =
        prepare_windows_support_until(&root, &destination, &selection, preparation)?;
    persist(
        &artifacts_directory.join("measured-support-owner.json"),
        &serde_json::to_vec(&owner)?,
    )?;
    crate::windows_readiness_adapter::observe_removed(
        &owner.config,
        &owner.removal,
        &owner.config.output_directory.join("before-install"),
        preparation,
    )?;
    let _intent = crate::windows_readiness_adapter::publish_receipt(
        &owner.config.output_directory.join("install-intent.json"),
        &serde_json::to_vec(&WindowsInstallIntent {
            format: "memcordon.windows-original-install-intent".into(),
            revision: 1,
            owner_sha256: artifacts::checksum(&serde_json::to_vec(&owner)?),
            job: selection.job.clone(),
            run_attempt: selection.run_attempt,
        })?,
    )?;
    let operation = (|| -> Result<()> {
        windows_package(&owner, "install", preparation)?;
        windows_package(&owner, "verify", preparation)?;
        crate::windows_consumer_readiness::provision_from_source_until(
            &root,
            &owner.config,
            preparation,
        )?;
        execute(
            &owner,
            &selection,
            &deadline,
            &deadline_path,
            &artifacts_directory,
        )
    })();
    let cleanup_directory = owner.config.output_directory.join("cleanup-0");
    std::fs::create_dir(&cleanup_directory)?;
    let cleanup = settle_windows_support(&owner, &cleanup_directory, selection.cleanup);
    if let Ok(receipts) = &cleanup {
        let settled = WindowsSettlement {
            format: "memcordon.windows-original-settlement".into(),
            revision: 1,
            owner_sha256: artifacts::checksum(&serde_json::to_vec(&owner)?),
            job: selection.job.clone(),
            run_attempt: selection.run_attempt,
            cleanup_directory: cleanup_directory.clone(),
            receipts: WindowsCleanupReceipts {
                recovery: receipts.recovery.clone(),
                uninstall: receipts.uninstall.clone(),
                removal: receipts.removal.clone(),
            },
        };
        let _custody = validate_windows_settlement(&owner, &settled)?;
        persist(
            &destination.join("windows-support-settled.json"),
            &serde_json::to_vec(&settled)?,
        )?;
        persist(
            &artifacts_directory.join("diagnostic-settlement.json"),
            &serde_json::to_vec(&settled)?,
        )?;
    }
    let exported = export_cleanup(
        &cleanup_directory,
        &artifacts_directory.join("cleanup-native"),
        selection.cleanup,
    );
    persist(
        &artifacts_directory.join("diagnostic-summary.json"),
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.support-loader-diagnostic","revision":1,"diagnostic_only":true,"certification_authority":false,
        "source":identity,"deadline_sha256":artifacts::checksum(&serde_json::to_vec(&deadline)?),
        "collection":operation.as_ref().map(|_|()).map_err(ToString::to_string),
        "cleanup":cleanup.as_ref().map(|_|()).map_err(ToString::to_string),
        "cleanup_export":exported.as_ref().map(|_|()).map_err(ToString::to_string)}))?,
    )?;
    operation?;
    cleanup?;
    exported
}

#[cfg(windows)]
fn export_cleanup(source: &Path, output: &Path, cutoff: Instant) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    let mut pending = vec![(source.to_owned(), output.to_owned(), 0_usize)];
    let mut files = 0_usize;
    let mut total = 0_u64;
    while let Some((directory, destination, depth)) = pending.pop() {
        if depth > 8 || Instant::now() >= cutoff {
            return Err(CiError::Message(
                "diagnostic cleanup export cutoff/depth exhausted".into(),
            ));
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(CiError::Message(
                "diagnostic export refuses redirected directory".into(),
            ));
        }
        std::fs::create_dir(&destination)?;
        for entry in std::fs::read_dir(&directory)? {
            if Instant::now() >= cutoff {
                return Err(CiError::Message(
                    "diagnostic cleanup export cutoff exhausted".into(),
                ));
            }
            files = files
                .checked_add(1)
                .ok_or_else(|| CiError::Message("diagnostic export entry overflow".into()))?;
            if files > 128 {
                return Err(CiError::Message(
                    "diagnostic cleanup export entry bound exceeded".into(),
                ));
            }
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(CiError::Message(
                    "diagnostic export refuses reparse entry".into(),
                ));
            }
            let destination = destination.join(entry.file_name());
            if metadata.is_dir() {
                pending.push((entry.path(), destination, depth + 1));
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| CiError::Message("diagnostic export byte overflow".into()))?;
                if total > 64 * 1024 * 1024 {
                    return Err(CiError::Message(
                        "diagnostic cleanup export byte bound exceeded".into(),
                    ));
                }
                let record = OwnedRecord::read(&entry.path())?;
                persist(&destination, &record.bytes)?;
            } else {
                return Err(CiError::Message(
                    "diagnostic export refuses special entry".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn execute(
    owner: &WindowsOriginalOwner,
    selected: &Selection,
    deadline: &crate::support_loader_producer::DiagnosticDeadline,
    deadline_path: &Path,
    artifacts_directory: &Path,
) -> Result<()> {
    let config = &owner.config;
    let suite: crate::windows_consumer_readiness::SuiteInput =
        OwnedRecord::read(&config.output_directory.join("windows-readiness-input.json"))?
            .parse()?;
    crate::windows_consumer_readiness::validate_suite(&suite)?;
    let mut case = suite
        .cases
        .iter()
        .find(|case| case.key.family == "W-ENVELOPE" && case.key.scenario == "restricted")
        .ok_or_else(|| CiError::Message("diagnostic restricted envelope absent".into()))?
        .clone();
    let apply = crate::command::CommandSpec::new(
        &config.installed_agent.path,
        &config.output_directory,
        Duration::from_secs(90),
    )
    .args([
        std::ffi::OsString::from("package"),
        "policy".into(),
        "apply".into(),
        "--file".into(),
        suite.local_policy.as_os_str().to_owned(),
    ])
    .bounded_until(
        selected
            .work
            .checked_sub(crate::support_loader_producer::BOOTSTRAP_WORK)
            .ok_or_else(|| CiError::Message("diagnostic preparation cutoff unavailable".into()))?,
    )
    .output_limit(256 * 1024)
    .output_quiet()?;
    crate::command::require_successful_output("diagnostic selected policy", &apply)?;
    persist(
        &artifacts_directory.join("policy-activation.json"),
        &apply.stdout,
    )?;
    let configured = memcordon_core::workload_registry::RuntimePolicyRegistry::parse(
        &OwnedRecord::read(&suite.local_policy)?.bytes,
    )
    .map_err(CiError::Message)?;
    let requested_contract = memcordon_core::workload_contract::WorkloadContractV1::parse(
        &OwnedRecord::read(&case.workload_contract)?.bytes,
    )
    .map_err(CiError::Message)?;
    let contract = crate::windows_policy_activation::refresh_contract(
        &requested_contract,
        &configured,
        &apply.stdout,
    )?;
    let requested = artifacts_directory.join("requested-contract.json");
    let contract_bytes = serde_json::to_vec(&contract)?;
    let mut requested_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&requested)?;
    requested_file.write_all(&contract_bytes)?;
    requested_file.sync_all()?;
    if OwnedRecord::read(&requested)?.bytes != contract_bytes {
        return Err(CiError::Message(
            "diagnostic activated contract readback differs".into(),
        ));
    }
    case.workload_contract = requested;
    std::fs::create_dir_all(&case.descriptor.output_root)?;
    persist(
        &case.descriptor_path,
        &serde_json::to_vec(&case.descriptor)?,
    )?;
    let directory = &case.descriptor.output_root;
    let observation_path = directory.join("support-loader-observation.json");
    let report = directory.join("frontend-result.json");
    let bootstrap = config
        .components
        .iter()
        .find(|image| {
            image
                .path
                .file_name()
                .is_some_and(|name| name == "memcordon-target-desktop-bootstrap.exe")
        })
        .ok_or_else(|| CiError::Message("measured support bootstrap absent".into()))?;
    let origin = Instant::now();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CiError::Message(error.to_string()))?
            .as_millis(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let selection = memcordon_core::WindowsLoaderDiagnosticSelectionV1 {
        kind: memcordon_core::WindowsLoaderDiagnosticKindV1::OriginalRestrictedBootstrap,
        challenge: hex::encode(&case.descriptor.challenge),
        support_bootstrap_sha256: bootstrap.sha256.clone(),
        producer_deadline_sha256: artifacts::checksum(&OwnedRecord::read(deadline_path)?.bytes),
        work_deadline_unix_ms: deadline.work_deadline_unix_millis.min(
            now.checked_add(30_000)
                .ok_or_else(|| CiError::Message("diagnostic work overflow".into()))?,
        ),
        cleanup_deadline_unix_ms: deadline.cleanup_deadline_unix_millis.min(
            now.checked_add(60_000)
                .ok_or_else(|| CiError::Message("diagnostic cleanup overflow".into()))?,
        ),
    };
    selection
        .validate_at(now)
        .map_err(|error| CiError::Message(error.into()))?;
    let cutoff = selected
        .work
        .min(origin + Duration::from_millis(selection.work_deadline_unix_ms - now));
    let selection_path = directory.join("support-loader-selection.json");
    persist(&selection_path, &serde_json::to_vec(&selection)?)?;
    persist(
        &artifacts_directory.join("selection.json"),
        &serde_json::to_vec(&selection)?,
    )?;
    let command = crate::windows_consumer_readiness::support_loader_command(
        &config.cli.path,
        &config.fixture.path,
        directory,
        &report,
        &case,
        &selection_path,
        &observation_path,
    )?
    .phase(crate::command::CiPhase::NativeExecute)
    .bounded_until(cutoff)
    .output_limit(1024 * 1024);
    persist(
        &artifacts_directory.join("invocation.json"),
        &serde_json::to_vec(&serde_json::json!({"diagnostic_only":true,
        "selection":selection,"provider":config.provider,"cli":config.cli,"wrapper":config.fixture,
        "requested_contract_sha256":artifacts::checksum(&contract_bytes),
        "policy_activation_sha256":artifacts::checksum(&apply.stdout),
        "deadline_sha256":artifacts::checksum(&OwnedRecord::read(deadline_path)?.bytes)}))?,
    )?;
    let result = command.output_quiet();
    let retained = (|| -> Result<()> {
        match &result {
            Ok(output) => {
                persist(&artifacts_directory.join("stdout.bin"), &output.stdout)?;
                persist(&artifacts_directory.join("stderr.bin"), &output.stderr)?;
                persist(
                    &artifacts_directory.join("observed-exit.json"),
                    &serde_json::to_vec(
                        &serde_json::json!({"status":output.status.code(),"streams_available":true}),
                    )?,
                )?;
            }
            Err(error) => {
                persist(
                    &artifacts_directory.join("process-failure.json"),
                    &serde_json::to_vec(
                        &serde_json::json!({"error":error.to_string(),"native_status_not_invented":true}),
                    )?,
                )?;
            }
        }
        // Retain available native records even when the owned command failed.
        // An absent report is recorded as absent, never as a synthetic exit.
        for (source, name, limit) in [
            (
                &observation_path,
                "frontend-observation.json",
                8 * 1024 * 1024,
            ),
            (&report, "frontend-result.json", 16 * 1024 * 1024),
        ] {
            if source.try_exists()? {
                let record = OwnedRecord::read(source)?;
                if record.bytes.len() > limit {
                    return Err(CiError::Message(
                        "diagnostic native record exceeds bound".into(),
                    ));
                }
                persist(&artifacts_directory.join(name), &record.bytes)?;
            }
        }
        let execution = directory.join("target/ci/reports/execution");
        let available = execution.try_exists()?;
        persist(
            &artifacts_directory.join("native-report-availability.json"),
            &serde_json::to_vec(&serde_json::json!({"available":available,
                "streams":"native report retains bounded excerpts with truncation metadata"}))?,
        )?;
        if available {
            export_cleanup(
                &execution,
                &artifacts_directory.join("native-execution"),
                selected.cleanup,
            )?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        return Err(match retained {
            Ok(()) => error,
            Err(secondary) => {
                CiError::Message(format!("{error}; diagnostic retention failed: {secondary}"))
            }
        });
    }
    retained?;
    let output = result?;
    if output.status.success() {
        return Err(CiError::Message(
            "diagnostic must retain original launch refusal".into(),
        ));
    }
    let raw = OwnedRecord::read(&observation_path)?;
    if raw.bytes.len() > 8 * 1024 * 1024 {
        return Err(CiError::Message(
            "diagnostic observation exceeds bound".into(),
        ));
    }
    let observation: crate::support_loader_producer::FrontendObservation = raw.parse()?;
    let refusal = crate::support_loader_producer::validate_frontend(
        &observation,
        &selection,
        &config.provider,
    )?;
    for (index, frame) in observation.authenticated_provider_frames.iter().enumerate() {
        persist(
            &artifacts_directory.join(format!("provider-frame-{index}.bin")),
            frame,
        )?;
    }
    persist(
        &artifacts_directory.join("bound-refusal.json"),
        &serde_json::to_vec(&refusal)?,
    )?;
    crate::support_loader_producer::require_complete_debug_capture(&refusal)
}
