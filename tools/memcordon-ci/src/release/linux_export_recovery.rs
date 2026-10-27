//! Measures the existing abort-publication recovery boundary for each original
//! export attempt. Recovery never turns refused exports into published output.
#![cfg(target_os = "linux")]
use super::linux_recovery_harness::recovery_io;
#[path = "linux_export_failure.rs"]
mod producer_failure;
use super::{
    linux_mixed_installed::{ExclusiveAccount, InstalledMixedDriverInput},
    linux_readiness_image_cases::ImageCaseReport,
};
use crate::{CiError, Result};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Instant,
};

pub struct RecoveryContext<'a> {
    pub identity: &'a crate::consumer_readiness_ledger::SourceIdentity,
    pub cell: &'a memcordon_readiness_verifier::ProductKey,
    pub lease_id: &'a str,
    pub provider: &'a memcordon_core::PublicProviderBindingV1,
    pub artifact_root: &'a Path,
    pub lease_owner: std::path::PathBuf,
    pub harness_acquisition: std::path::PathBuf,
    pub recovery_harness: &'a super::linux_recovery_harness::HeldRecoveryHarness,
    pub cleanup_deadline: Instant,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

impl<'a> RecoveryContext<'a> {
    pub fn from_input(input: &'a InstalledMixedDriverInput<'_>) -> Result<Self> {
        let original = input
            .output
            .parent()
            .ok_or_else(|| CiError::Message("original export lease parent absent".into()))?;
        Ok(Self {
            identity: &input.identity,
            cell: &input.cell,
            lease_id: &input.lease_id,
            provider: input.provider,
            artifact_root: input.artifact_root,
            lease_owner: original.join("lease-owner.json"),
            harness_acquisition: original.join("recovery-harness-acquisition"),
            recovery_harness: input.recovery_harness,
            cleanup_deadline: input.cleanup_deadline,
            work_deadline_unix_millis: input.work_deadline_unix_millis,
            cleanup_deadline_unix_millis: input.cleanup_deadline_unix_millis,
        })
    }
}

fn retain(path: &Path, bytes: &[u8], files: &mut Vec<File>) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| recovery_io::context("create-retained-evidence", path, error))?;
    files.push(
        file.try_clone()
            .map_err(|error| recovery_io::context("clone-retained-evidence", path, error))?,
    );
    file.write_all(bytes)
        .map_err(|error| recovery_io::context("write-retained-evidence", path, error))?;
    file.sync_all()
        .map_err(|error| recovery_io::context("sync-retained-evidence", path, error))?;
    let parent = path
        .parent()
        .ok_or_else(|| CiError::Message("export recovery parent absent".into()))?;
    File::open(parent)
        .map_err(|error| recovery_io::context("open-evidence-parent", parent, error))?
        .sync_all()
        .map_err(|error| recovery_io::context("sync-evidence-parent", parent, error))?;
    Ok(())
}

pub fn recover_report(
    report: &mut ImageCaseReport,
    input: &RecoveryContext<'_>,
    account: &ExclusiveAccount,
) -> Result<()> {
    for row in &mut report.export_observations {
        if row.recovery.is_some() {
            continue;
        }
        let mut stage = "prepared-capture";
        // A finite prefix of the fixed recovery phases, emitted only on failure.
        let mut completed_boundaries = Vec::new();
        let mut attempt_context = None;
        let outcome = (|| -> Result<()> {
            if Instant::now() >= input.cleanup_deadline {
                return Err(CiError::Message(
                    "original export cleanup cutoff exhausted".into(),
                ));
            }
            let prepared_path = row.prepared.as_ref().ok_or_else(|| {
                CiError::Message("original export prepared custody absent".into())
            })?;
            let prepared: memcordon_core::mixed_observation::MixedPreparedObservationV2 =
                serde_json::from_slice(&super::linux_mixed_installed::read_owned_resource(
                    prepared_path,
                    4 * 1024 * 1024,
                )?)?;
            prepared.validate().map_err(CiError::Message)?;
            let attempt = prepared.admission.attempt_id.as_str();
            attempt_context = Some(attempt.to_owned());
            completed_boundaries.push(stage);
            stage = "reservation-capture";
            let directory = prepared_path.parent().ok_or_else(|| {
                CiError::Message("original export attempt directory absent".into())
            })?;
            let mut reservation_owner = None;
            let mut reservation_before = None;
            let root = Path::new("/var/lib/memcordon/sealed");
            let mut protected_parents = Vec::new();
            let mut parent_path = std::path::PathBuf::from("/");
            protected_parents.push((
                parent_path.clone(),
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
                    .open(&parent_path)
                    .map_err(|error| {
                        recovery_io::context("open-reservation-root", &parent_path, error)
                    })?,
            ));
            for component in ["var", "lib", "memcordon", "sealed"] {
                let next = File::from(
                    rustix::fs::openat(
                        &protected_parents.last().expect("held protected parent").1,
                        component,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|error| {
                        recovery_io::context(
                            "open-reservation-ancestor",
                            &parent_path.join(component),
                            error.into(),
                        )
                    })?,
                );
                parent_path.push(component);
                let metadata = next.metadata().map_err(|error| {
                    recovery_io::context("stat-reservation-ancestor", &parent_path, error)
                })?;
                if !metadata.is_dir()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o022 != 0
                    || metadata.nlink() == 0
                {
                    return Err(CiError::Message(
                        "export reservation ancestry is not protected original root custody".into(),
                    ));
                }
                protected_parents.push((parent_path.clone(), next));
            }
            let expected_reservation = root.join(format!(
                "account-{}-{}-{}.reservation",
                prepared.user_namespace.device, prepared.user_namespace.inode, account.uid
            ));
            let mut entries = 0usize;
            use std::os::fd::AsRawFd;
            for entry in std::fs::read_dir(format!(
                "/proc/self/fd/{}",
                protected_parents
                    .last()
                    .expect("held sealed parent")
                    .1
                    .as_raw_fd()
            ))
            .map_err(|error| recovery_io::context("enumerate-reservations", root, error))?
            {
                entries += 1;
                if entries > 4096 {
                    return Err(CiError::Message(
                        "original protected export reservation census exceeds bound".into(),
                    ));
                }
                let entry = entry
                    .map_err(|error| recovery_io::context("read-reservation-entry", root, error))?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if !name.starts_with("account-") || !name.ends_with(".reservation") {
                    continue;
                }
                let named_path = root.join(name);
                let file = File::from(
                    rustix::fs::openat(
                        &protected_parents
                            .last()
                            .expect("held original reservation parent")
                            .1,
                        name,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|error| {
                        recovery_io::context("open-original-reservation", &named_path, error.into())
                    })?,
                );
                let before = file.metadata().map_err(|error| {
                    recovery_io::context("stat-original-reservation", &named_path, error)
                })?;
                if !before.is_file()
                    || before.uid() != 0
                    || before.mode() & 0o7777 != 0o600
                    || before.nlink() != 1
                    || before.len() > 65536
                {
                    return Err(CiError::Message(
                        "protected reservation native custody differs".into(),
                    ));
                }
                use std::os::unix::fs::FileExt;
                let mut bytes = vec![0u8; before.len() as usize];
                file.read_exact_at(&mut bytes, 0).map_err(|error| {
                    recovery_io::context("read-original-reservation", &named_path, error)
                })?;
                memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
                    .map_err(CiError::Message)?;
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                let original: Vec<u8> = serde_json::from_value(value["attempt"].clone())?;
                if hex::encode(original) != attempt {
                    continue;
                }
                if reservation_owner.is_some()
                    || value["uid"].as_u64() != Some(u64::from(account.uid))
                    || value["format"] != "memcordon.account-reservation"
                    || value["revision"] != 1
                {
                    return Err(CiError::Message(
                        "original export reservation creator/identity differs".into(),
                    ));
                }
                let after = file.metadata().map_err(|error| {
                    recovery_io::context("restat-original-reservation", &named_path, error)
                })?;
                let named = std::fs::symlink_metadata(&named_path).map_err(|error| {
                    recovery_io::context("stat-named-reservation", &named_path, error)
                })?;
                if named_path != expected_reservation
                    || (named.dev(), named.ino()) != (before.dev(), before.ino())
                    || (
                        before.dev(),
                        before.ino(),
                        before.len(),
                        before.ctime(),
                        before.ctime_nsec(),
                    ) != (
                        after.dev(),
                        after.ino(),
                        after.len(),
                        after.ctime(),
                        after.ctime_nsec(),
                    )
                {
                    return Err(CiError::Message(
                        "original export reservation changed during capture".into(),
                    ));
                }
                reservation_before = Some(
                    serde_json::json!({"path":named_path,"device":before.dev(),"inode":before.ino(),"uid":before.uid(),"mode":before.mode(),"nlink":before.nlink(),"bytes":bytes}),
                );
                reservation_owner = Some(file);
            }
            if reservation_owner.is_none() {
                match std::fs::symlink_metadata(&expected_reservation) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                    _ => {
                        return Err(CiError::Message(
                            "original reservation absence is not native ENOENT".into(),
                        ));
                    }
                }
                reservation_before = Some(
                    serde_json::json!({"path":expected_reservation,"native_errno":libc::ENOENT}),
                );
            }
            let journal_path = Path::new("/var/lib/memcordon/sealed").join(attempt);
            completed_boundaries.push(stage);
            stage = "journal-capture";
            let mut before_paths = Vec::new();
            let mut original_directories = Vec::new();
            let journal = match std::fs::symlink_metadata(&journal_path) {
                Ok(_) => {
                    let (bytes, record) =
                        super::linux_readiness_lifecycle_cases::retain_phase_journal(
                            attempt,
                            input.cleanup_deadline,
                            &mut report.file_custody,
                        )?;
                    if record["mixed_admission_metadata"]
                        != serde_json::to_value(&prepared.admission)?
                    {
                        return Err(CiError::Message("original export recovery journal admission differs from held prepared authority".into()));
                    }
                    if let Some(original) = reservation_before
                        .as_ref()
                        .filter(|_| reservation_owner.is_some())
                    {
                        let reservation: Vec<u8> =
                            serde_json::from_value(original["bytes"].clone())?;
                        let reservation: serde_json::Value = serde_json::from_slice(&reservation)?;
                        if reservation["owner_pid"] != record["mixed_worker"]["pid"]
                            || reservation["owner_birth"] != record["mixed_worker"]["start_time"]
                        {
                            return Err(CiError::Message("original account reservation differs from retained native export worker".into()));
                        }
                    }
                    retain(
                        &directory.join("recovery-original-journal.bin"),
                        &bytes,
                        &mut report.file_custody,
                    )?;
                    for (field, identity_field) in [
                        ("mixed_root_staging_intent", "mixed_staging_identity"),
                        ("mixed_export_intent", "mixed_export_identity"),
                    ] {
                        if let Some(path) = record[field].as_str() {
                            let named = Path::new(path);
                            match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_DIRECTORY|libc::O_CLOEXEC).open(named) {
                            Ok(held)=>{let metadata=held.metadata().map_err(|error| recovery_io::context("stat-journal-allocation", named, error))?;
                                if record[identity_field]["device"].as_u64()!=Some(metadata.dev())||record[identity_field]["inode"].as_u64()!=Some(metadata.ino())||metadata.uid()!=0||metadata.mode()&0o022!=0 {
                                    return Err(CiError::Message("original export allocation differs from retained native journal identity".into()));
                                }
                                before_paths.push(serde_json::json!({"field":field,"path":path,"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode()}));
                                original_directories.push((path.to_owned(),held));},
                            Err(error)if error.raw_os_error()==Some(libc::ENOENT)=>before_paths.push(serde_json::json!({"field":field,"path":path,"native_errno":libc::ENOENT})),
                            Err(error)=>return Err(recovery_io::context("open-journal-allocation", named, error).into()),
                        }
                        }
                    }
                    Some(bytes)
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
                Err(error) => {
                    return Err(recovery_io::context(
                        "stat-original-journal",
                        &journal_path,
                        error,
                    )
                    .into());
                }
            };
            if journal.is_some() && reservation_owner.is_none() {
                return Err(CiError::Message(
                    "retained export ownership journal lacks original account reservation".into(),
                ));
            }
            use super::linux_original_recovery::{contract, record};
            completed_boundaries.push(stage);
            stage = "source-contract";
            let reservation_path = directory.join("recovery-original-reservation.json");
            let original_reservation = if let Some(bytes) = reservation_before
                .as_ref()
                .and_then(|value| value.get("bytes"))
            {
                let bytes: Vec<u8> = serde_json::from_value(bytes.clone())?;
                retain(&reservation_path, &bytes, &mut report.file_custody)?;
                Some(record(&reservation_path)?)
            } else {
                None
            };
            let recovery_input = contract::Input {
                format: "memcordon.original-native-recovery-input".into(),
                revision: 1,
                identity: contract::Identity {
                    run_id: input.identity.run_id.clone(),
                    source_commit: input.identity.source_commit.clone(),
                    source_tree_sha256: input.identity.source_tree_sha256.clone(),
                    version: input.identity.version.clone(),
                },
                native_target: input.cell.target.clone(),
                scope_id: input.lease_id.to_owned(),
                artifact_root: directory.to_owned(),
                original_artifact_root: directory.to_owned(),
                origin_sha256: String::new(),
                work_deadline_unix_millis: input.work_deadline_unix_millis,
                cleanup_deadline_unix_millis: input.cleanup_deadline_unix_millis,
                recovery_harness_owner_sha256: input.recovery_harness.owner_sha256()?,
                context: contract::Context::Export {
                    lease_owner: record(&input.lease_owner)?,
                    prepared: record(prepared_path)?,
                    original_journal: if journal.is_some() {
                        Some(record(&directory.join("recovery-original-journal.bin"))?)
                    } else {
                        None
                    },
                    original_reservation,
                },
            };
            completed_boundaries.push(stage);
            stage = "native-recovery";
            let recovery = super::linux_original_recovery::run(
                input.recovery_harness,
                &recovery_input,
                input.cleanup_deadline,
            )?;
            completed_boundaries.push(stage);
            stage = "acquisition-artifacts";
            let mut invocation = recovery.invocation.clone();
            invocation["original_fixture"] = recovery.proof().clone();
            invocation["original_fixture"]["acquisition_artifacts"] =
                super::linux_recovery_harness::acquisition_artifacts(
                    input.artifact_root,
                    &input.harness_acquisition,
                )?;
            let invocation_bytes = serde_json::to_vec(&invocation)?;
            retain(
                &directory.join("recovery-invocation.json"),
                &invocation_bytes,
                &mut report.file_custody,
            )?;
            let process = &recovery.process;
            retain(
                &directory.join("recovery-process.json"),
                &serde_json::to_vec(&process)?,
                &mut report.file_custody,
            )?;
            retain(
                &directory.join("recovery-stdout.bin"),
                &recovery.stdout,
                &mut report.file_custody,
            )?;
            retain(
                &directory.join("recovery-stderr.bin"),
                &recovery.stderr,
                &mut report.file_custody,
            )?;
            completed_boundaries.push(stage);
            stage = "native-absence";
            let mut absence = Vec::new();
            for item in &before_paths {
                let path = item["path"].as_str().ok_or_else(|| {
                    CiError::Message("original export allocation pathname absent".into())
                })?;
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                        absence.push(serde_json::json!({"path":path,"native_errno":libc::ENOENT}))
                    }
                    _ => {
                        return Err(CiError::Message(
                            "original export private allocation remains named after recovery"
                                .into(),
                        ));
                    }
                }
            }
            let mut held_retirement = Vec::new();
            for (path, held) in original_directories {
                let metadata = held.metadata().map_err(|error| {
                    recovery_io::context("stat-retired-allocation", Path::new(&path), error)
                })?;
                if metadata.nlink() != 0 {
                    return Err(CiError::Message(
                        "original held export allocation remains linked after recovery".into(),
                    ));
                }
                let closed = memcordon_platform::linux_checked_close(held.into());
                held_retirement.push(serde_json::json!({"path":path,"device":metadata.dev(),"inode":metadata.ino(),"nlink":metadata.nlink(),"close_native_errno":closed.as_ref().err().and_then(std::io::Error::raw_os_error),"closed":closed.is_ok()}));
                closed.map_err(|error| {
                    recovery_io::context("close-retired-allocation", Path::new(&path), error)
                })?;
            }
            let reservation_after = if let Some(file) = reservation_owner {
                let original = reservation_before
                    .as_ref()
                    .expect("retained original reservation metadata");
                let path = original["path"].as_str().ok_or_else(|| {
                    CiError::Message("original reservation pathname absent".into())
                })?;
                let metadata = file.metadata().map_err(|error| {
                    recovery_io::context("stat-retired-reservation", Path::new(path), error)
                })?;
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                    _ => {
                        return Err(CiError::Message(
                            "original reservation remains named after export recovery".into(),
                        ));
                    }
                }
                if metadata.nlink() != 0 {
                    return Err(CiError::Message(
                        "original held reservation remains linked after export recovery".into(),
                    ));
                }
                let closed = memcordon_platform::linux_checked_close(file.into());
                let receipt = serde_json::json!({"path":path,"device":metadata.dev(),"inode":metadata.ino(),"nlink":metadata.nlink(),"native_errno":libc::ENOENT,"closed":closed.is_ok(),"close_native_errno":closed.as_ref().err().and_then(std::io::Error::raw_os_error)});
                closed.map_err(|error| {
                    recovery_io::context("close-retired-reservation", Path::new(path), error)
                })?;
                Some(receipt)
            } else {
                match std::fs::symlink_metadata(&expected_reservation) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                    _ => {
                        return Err(CiError::Message(
                            "original absent reservation appeared during export recovery".into(),
                        ));
                    }
                }
                Some(serde_json::json!({"path":expected_reservation,"native_errno":libc::ENOENT}))
            };
            let mut reservation_parents = Vec::new();
            for (path, file) in protected_parents {
                let metadata = file.metadata().map_err(|error| {
                    recovery_io::context("restat-protected-parent", &path, error)
                })?;
                let named = std::fs::symlink_metadata(&path).map_err(|error| {
                    recovery_io::context("stat-named-protected-parent", &path, error)
                })?;
                if (metadata.dev(), metadata.ino()) != (named.dev(), named.ino())
                    || !named.is_dir()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o022 != 0
                    || metadata.nlink() == 0
                {
                    return Err(CiError::Message(
                        "original protected reservation parent was rebound during recovery".into(),
                    ));
                }
                let closed = memcordon_platform::linux_checked_close(file.into());
                reservation_parents.push(serde_json::json!({"path":path,"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode(),"nlink":metadata.nlink(),"named_device":named.dev(),"named_inode":named.ino(),"closed":closed.is_ok(),"close_native_errno":closed.as_ref().err().and_then(std::io::Error::raw_os_error)}));
                closed.map_err(|error| {
                    recovery_io::context("close-protected-parent", &path, error)
                })?;
            }
            completed_boundaries.push(stage);
            stage = "read-original-export-result";
            let result_path = row
                .result
                .as_ref()
                .ok_or_else(|| CiError::Message("original export carrier absent".into()))?;
            let producer = original_producer(
                row,
                &report.launches,
                &report.file_custody,
                input,
                Some(attempt),
            )?;
            let result = producer
                .launch
                .read_original_export_output(result_path, attempt, false, input.cleanup_deadline)
                .map_err(|error| match error {
                    CiError::Io(error) => CiError::Io(recovery_io::context(
                        "read-original-export-result",
                        result_path,
                        error,
                    )),
                    other => other,
                })?;
            completed_boundaries.push(stage);
            stage = "read-original-export-request";
            let request_path = row
                .provider_request
                .as_ref()
                .ok_or_else(|| CiError::Message("original export request absent".into()))?;
            let request = producer
                .launch
                .read_original_export_output(request_path, attempt, true, input.cleanup_deadline)
                .map_err(|error| match error {
                    CiError::Io(error) => CiError::Io(recovery_io::context(
                        "read-original-export-request",
                        request_path,
                        error,
                    )),
                    other => other,
                })?;
            completed_boundaries.push(stage);
            stage = "refusal-census";
            super::linux_mixed_installed::persist_policy_refusal_census(
                account,
                input.provider,
                input.identity,
                input.cell,
                input.lease_id,
                &row.scenario,
                attempt,
                &result,
                &request,
                &directory.join("recovery-census.json"),
                input.cleanup_deadline,
            )?;
            completed_boundaries.push(stage);
            stage = "receipt-commit";
            let recovery = directory.join("export-recovery.json");
            retain(
                &recovery,
                &serde_json::to_vec(
                    &serde_json::json!({"format":"memcordon.linux-export-recovery","revision":1,"identity":input.identity,"cell":input.cell,"lease_id":input.lease_id,"scenario":row.scenario,"attempt_id":attempt,
            "original_journal_present":journal.is_some(),"original_journal_sha256":journal.as_ref().map(|bytes|super::artifacts::checksum(bytes)),"before_paths":before_paths,"after_absence":absence,"held_retirement":held_retirement,"reservation_before":reservation_before,"reservation_after":reservation_after,"reservation_parents":reservation_parents,
            "invocation":"recovery-invocation.json","process":"recovery-process.json","stdout":"recovery-stdout.bin","stderr":"recovery-stderr.bin","census":"recovery-census.json",
            "request_sha256":super::artifacts::checksum(&request),"result_sha256":super::artifacts::checksum(&result),"work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis}),
                )?,
                &mut report.file_custody,
            )?;
            row.recovery = Some(recovery);
            Ok(())
        })();
        if outcome.is_err() {
            if stage == "read-original-export-result" {
                let diagnostic = original_producer_evidence(
                    row,
                    &report.launches,
                    &report.file_custody,
                    input,
                    attempt_context.as_deref(),
                );
                let diagnostic = match diagnostic {
                    Ok(value) => value,
                    Err(error) => match error {
                        CiError::Io(error) => {
                            serde_json::json!({"state":"unavailable","kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),"diagnostic_only":true})
                        }
                        _ => {
                            serde_json::json!({"state":"unavailable","reason":"original-producer-binding-or-custody-refused","diagnostic_only":true})
                        }
                    },
                };
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "export-original-producer-failure {}",
                    diagnostic
                );
            }
            let _ = writeln!(
                std::io::stderr().lock(),
                "export-recovery-boundary {}",
                serde_json::json!({"scenario":row.scenario,"attempt_id":attempt_context,"stage":stage,"completed_boundaries":completed_boundaries,"identity":input.identity,"cell":input.cell,"lease_id":input.lease_id,"work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis,"cleanup_cutoff_elapsed":Instant::now()>=input.cleanup_deadline})
            );
        }
        outcome?;
    }
    Ok(())
}

struct OriginalProducer<'a> {
    launch: &'a super::linux_mixed_installed::InstalledMixedLaunch,
    wait_bytes: Vec<u8>,
    wait: serde_json::Value,
    invocation: Vec<u8>,
}

fn original_producer<'a>(
    row: &super::linux_readiness_image_cases::ExportCaseObservation,
    launches: &'a [super::linux_mixed_installed::InstalledMixedLaunch],
    owners: &[File],
    input: &RecoveryContext<'_>,
    attempt: Option<&str>,
) -> Result<OriginalProducer<'a>> {
    let live = || -> Result<()> {
        if Instant::now() >= input.cleanup_deadline {
            Err(CiError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original export producer diagnostic cutoff elapsed",
            )))
        } else {
            Ok(())
        }
    };
    live()?;
    let result = row
        .result
        .as_ref()
        .ok_or_else(|| CiError::Message("original export result path absent".into()))?;
    let mut matches = launches.iter().filter(|launch| &launch.result == result);
    let launch = matches
        .next()
        .ok_or_else(|| CiError::Message("original export launch binding absent".into()))?;
    if matches.next().is_some() || !launch.capture_owners_settled() {
        return Err(CiError::Message(
            "original export launch is ambiguous or capture owners unsettled".into(),
        ));
    }
    let attempt =
        attempt.ok_or_else(|| CiError::Message("original export attempt binding absent".into()))?;
    let request = row
        .provider_request
        .as_ref()
        .ok_or_else(|| CiError::Message("original export request path absent".into()))?;
    producer_failure::binding(attempt, &launch.result, result, request)?;
    if row.stderr.as_ref() != Some(&launch.stderr)
        || request.parent() != Some(launch.observation_directory.as_path())
    {
        return Err(CiError::Message(
            "original export capture/observation directory binding differs".into(),
        ));
    }
    let retained = |path: &Path| -> Result<Vec<u8>> {
        live()?;
        launch.verify_original_output_directory()?;
        let named = std::fs::symlink_metadata(path)?;
        let owner = owners
            .iter()
            .find(|owner| {
                owner
                    .metadata()
                    .is_ok_and(|held| (held.dev(), held.ino()) == (named.dev(), named.ino()))
            })
            .ok_or_else(|| {
                CiError::Message("original export diagnostic file owner absent".into())
            })?;
        let stamp = |metadata: &std::fs::Metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.uid(),
                metadata.mode(),
                metadata.nlink(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        };
        let before = owner.metadata()?;
        if before.uid() != 0 {
            return Err(CiError::Message(
                "original export retained diagnostic owner differs".into(),
            ));
        }
        let bytes = super::linux_mixed_installed::read_policy_observation_file_nonblocking(
            path,
            64 * 1024,
        )?;
        if stamp(&before) != stamp(&owner.metadata()?)
            || stamp(&before) != stamp(&std::fs::symlink_metadata(path)?)
        {
            return Err(CiError::Message(
                "original export diagnostic retained/named stamp differs".into(),
            ));
        }
        live()?;
        launch.verify_original_output_directory()?;
        Ok(bytes)
    };
    let wait_bytes = retained(
        row.native_wait
            .as_ref()
            .ok_or_else(|| CiError::Message("original export native wait absent".into()))?,
    )?;
    let wait = super::linux_mixed_installed::decode_owned_resource_json(&wait_bytes)?;
    if wait != launch.retained_frontend_wait()? {
        return Err(CiError::Message(
            "original export native wait process binding differs".into(),
        ));
    }
    let invocation = launch.retained_frontend_invocation()?;
    let invocation_copy = retained(
        row.native_invocation
            .as_ref()
            .ok_or_else(|| CiError::Message("original export invocation absent".into()))?,
    )?;
    if invocation != invocation_copy
        || wait["invocation_sha256"] != super::artifacts::checksum(&invocation)
    {
        return Err(CiError::Message(
            "original export native wait/invocation content binding differs".into(),
        ));
    }
    live()?;
    Ok(OriginalProducer {
        launch,
        wait_bytes,
        wait,
        invocation,
    })
}

fn original_producer_evidence(
    row: &super::linux_readiness_image_cases::ExportCaseObservation,
    launches: &[super::linux_mixed_installed::InstalledMixedLaunch],
    owners: &[File],
    input: &RecoveryContext<'_>,
    attempt: Option<&str>,
) -> Result<serde_json::Value> {
    let OriginalProducer {
        launch,
        wait_bytes,
        wait,
        invocation,
    } = original_producer(row, launches, owners, input, attempt)?;
    let attempt =
        attempt.ok_or_else(|| CiError::Message("original export attempt absent".into()))?;
    let result = &launch.result;
    let live = || -> Result<()> {
        if Instant::now() >= input.cleanup_deadline {
            return Err(CiError::Message(
                "original producer evidence cutoff elapsed".into(),
            ));
        }
        Ok(())
    };
    let capture = |path: &Path, expected: Option<&str>| -> serde_json::Value {
        let read = (|| -> Result<Vec<u8>> {
            live()?;
            launch.verify_original_output_directory()?;
            let bytes = super::linux_mixed_installed::read_policy_observation_file_nonblocking(
                path,
                16 * 1024 * 1024,
            )?;
            if expected.is_some_and(|expected| super::artifacts::checksum(&bytes) != expected) {
                return Err(CiError::Message(
                    "original export settled capture digest differs".into(),
                ));
            }
            live()?;
            launch.verify_original_output_directory()?;
            Ok(bytes)
        })();
        producer_failure::capture(read.map_err(|error| match error {
            CiError::Io(error) => error,
            _ => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "original export producer custody/readback refused",
            ),
        }))
    };
    let stderr_hash = wait["stderr_sha256"]
        .as_str()
        .ok_or_else(|| CiError::Message("original native wait stderr digest absent".into()))?;
    let stdout_hash = wait["stdout_sha256"]
        .as_str()
        .ok_or_else(|| CiError::Message("original native wait stdout digest absent".into()))?;
    let terminal = launch
        .observation_directory
        .join(Path::new(attempt).with_extension("provider-terminal.json"));
    let delivery = launch
        .observation_directory
        .join("report-delivery-failure.json");
    let evidence = serde_json::json!({"format":"memcordon.original-export-producer-failure","revision":1,"diagnostic_only":true,
        "identity":input.identity,"cell":input.cell,"lease_id":input.lease_id,"scenario":row.scenario,"attempt_id":attempt,
        "required_result":result,"original_frontend_pid":launch.frontend.id(),"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis,
        "native_wait":producer_failure::capture(Ok(wait_bytes)),"invocation":producer_failure::capture(Ok(invocation)),
        "stdout":capture(&launch.stdout,Some(stdout_hash)),"stderr":capture(&launch.stderr,Some(stderr_hash)),"provider_terminal":capture(&terminal,None),"report_delivery_failure":capture(&delivery,None)});
    live()?;
    Ok(evidence)
}
