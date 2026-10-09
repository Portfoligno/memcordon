//! Measures the existing abort-publication recovery boundary for each original
//! export attempt. Recovery never turns refused exports into published output.
#![cfg(target_os = "linux")]
use super::{
    linux_mixed_installed::{ExclusiveAccount, InstalledMixedDriverInput},
    linux_readiness_image_cases::ImageCaseReport,
};
use crate::{CiError, Result};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::ExitStatusExt,
    },
    path::Path,
    time::{Duration, Instant},
};

fn retain(path: &Path, bytes: &[u8], files: &mut Vec<File>) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    files.push(file.try_clone()?);
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| CiError::Message("export recovery parent absent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}

pub fn recover_report(
    report: &mut ImageCaseReport,
    input: &InstalledMixedDriverInput<'_>,
    account: &ExclusiveAccount,
) -> Result<()> {
    let agent = super::linux_mixed_installed::read_owned_resource(
        Path::new("/usr/libexec/memcordon-sealed-agent"),
        512 * 1024 * 1024,
    )?;
    let agent_sha256 = super::artifacts::checksum(&agent);
    for row in &mut report.export_observations {
        if row.recovery.is_some() {
            continue;
        }
        if Instant::now() >= input.cleanup_deadline {
            return Err(CiError::Message(
                "original export cleanup cutoff exhausted".into(),
            ));
        }
        let prepared_path = row
            .prepared
            .as_ref()
            .ok_or_else(|| CiError::Message("original export prepared custody absent".into()))?;
        let prepared: memcordon_core::mixed_observation::MixedPreparedObservationV2 =
            serde_json::from_slice(&super::linux_mixed_installed::read_owned_resource(
                prepared_path,
                4 * 1024 * 1024,
            )?)?;
        prepared.validate().map_err(CiError::Message)?;
        let attempt = prepared.admission.attempt_id.as_str();
        let directory = prepared_path
            .parent()
            .ok_or_else(|| CiError::Message("original export attempt directory absent".into()))?;
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
                .open(&parent_path)?,
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
                .map_err(|error| CiError::Message(error.to_string()))?,
            );
            parent_path.push(component);
            let metadata = next.metadata()?;
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
        ))? {
            entries += 1;
            if entries > 4096 {
                return Err(CiError::Message(
                    "original protected export reservation census exceeds bound".into(),
                ));
            }
            let entry = entry?;
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
                .map_err(|error| CiError::Message(error.to_string()))?,
            );
            let before = file.metadata()?;
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
            file.read_exact_at(&mut bytes, 0)?;
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
            let after = file.metadata()?;
            let named = std::fs::symlink_metadata(&named_path)?;
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
            reservation_before =
                Some(serde_json::json!({"path":expected_reservation,"native_errno":libc::ENOENT}));
        }
        let journal_path = Path::new("/var/lib/memcordon/sealed").join(attempt);
        let mut before_paths = Vec::new();
        let mut original_directories = Vec::new();
        let journal = match std::fs::symlink_metadata(&journal_path) {
            Ok(_) => {
                let (bytes, record) = super::linux_readiness_lifecycle_cases::retain_phase_journal(
                    attempt,
                    input.cleanup_deadline,
                    &mut report.file_custody,
                )?;
                if record["mixed_admission_metadata"] != serde_json::to_value(&prepared.admission)?
                {
                    return Err(CiError::Message("original export recovery journal admission differs from held prepared authority".into()));
                }
                if let Some(original) = reservation_before
                    .as_ref()
                    .filter(|_| reservation_owner.is_some())
                {
                    let reservation: Vec<u8> = serde_json::from_value(original["bytes"].clone())?;
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
                            Ok(held)=>{let metadata=held.metadata()?;
                                if record[identity_field]["device"].as_u64()!=Some(metadata.dev())||record[identity_field]["inode"].as_u64()!=Some(metadata.ino())||metadata.uid()!=0||metadata.mode()&0o022!=0 {
                                    return Err(CiError::Message("original export allocation differs from retained native journal identity".into()));
                                }
                                before_paths.push(serde_json::json!({"field":field,"path":path,"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode()}));
                                original_directories.push((path.to_owned(),held));},
                            Err(error)if error.raw_os_error()==Some(libc::ENOENT)=>before_paths.push(serde_json::json!({"field":field,"path":path,"native_errno":libc::ENOENT})),
                            Err(error)=>return Err(error.into()),
                        }
                    }
                }
                Some(bytes)
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
            Err(error) => return Err(error.into()),
        };
        if journal.is_some() && reservation_owner.is_none() {
            return Err(CiError::Message(
                "retained export ownership journal lacks original account reservation".into(),
            ));
        }
        let invocation = serde_json::json!({"format":"memcordon.linux-export-recovery-invocation","revision":1,"identity":input.identity,"cell":input.cell,"lease_id":input.lease_id,
            "attempt_id":attempt,"program":"/usr/libexec/memcordon-sealed-agent","arguments":["package","policy","recover","--json"],
            "cwd_native_bytes":directory.as_os_str().as_encoded_bytes(),"timeout_millis":60000,"cleared_environment":true,
            "work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis,"selected_agent_sha256":agent_sha256});
        let invocation_bytes = serde_json::to_vec(&invocation)?;
        retain(
            &directory.join("recovery-invocation.json"),
            &invocation_bytes,
            &mut report.file_custody,
        )?;
        let mut creation = None;
        let owner_index = report.export_worker_owners.len();
        let output = crate::command::CommandSpec::new(
            "/usr/libexec/memcordon-sealed-agent",
            directory,
            Duration::from_secs(60),
        )
        .args(["package", "policy", "recover", "--json"])
        .cleared_environment()
        .bounded_until(input.cleanup_deadline)
        .output_quiet_with_creation(|child| {
            let birth = crate::linux_consumer_readiness::process_birth(child.id())
                .map_err(CiError::Message)?;
            let mut held =
                crate::linux_consumer_readiness::HeldLinuxProcess::acquire(child.id(), birth)
                    .map_err(CiError::Message)?;
            let image = held
                .hold_executable_image(input.cleanup_deadline)
                .map_err(CiError::Message)?;
            if image["sha256"] != agent_sha256 {
                return Err(CiError::Message(
                    "original export recovery executable differs".into(),
                ));
            }
            creation = Some((held.retirement_identity().map_err(CiError::Message)?, image));
            report.export_worker_owners.push(held);
            Ok(())
        })?;
        let (preinput, image) = creation
            .ok_or_else(|| CiError::Message("actual export recovery creation absent".into()))?;
        let held = report
            .export_worker_owners
            .get(owner_index)
            .ok_or_else(|| CiError::Message("actual export recovery PIDFD owner absent".into()))?;
        let process = serde_json::json!({"format":"memcordon.linux-export-recovery-process","revision":1,"preinput":preinput,"process":held.retirement_identity().map_err(CiError::Message)?,"native_image":image,
            "invocation_sha256":super::artifacts::checksum(&invocation_bytes),"raw_wait_status":output.status.into_raw(),"native_exit":output.status.code(),"signal":output.status.signal(),
            "stdout_sha256":super::artifacts::checksum(&output.stdout),"stderr_sha256":super::artifacts::checksum(&output.stderr)});
        retain(
            &directory.join("recovery-process.json"),
            &serde_json::to_vec(&process)?,
            &mut report.file_custody,
        )?;
        retain(
            &directory.join("recovery-stdout.bin"),
            &output.stdout,
            &mut report.file_custody,
        )?;
        retain(
            &directory.join("recovery-stderr.bin"),
            &output.stderr,
            &mut report.file_custody,
        )?;
        if !output.status.success() || !held.exited().map_err(CiError::Message)? {
            return Err(CiError::Message(
                "actual export abort-publication recovery remains unsettled".into(),
            ));
        }
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
                        "original export private allocation remains named after recovery".into(),
                    ));
                }
            }
        }
        let mut held_retirement = Vec::new();
        for (path, held) in original_directories {
            let metadata = held.metadata()?;
            if metadata.nlink() != 0 {
                return Err(CiError::Message(
                    "original held export allocation remains linked after recovery".into(),
                ));
            }
            let closed = memcordon_platform::linux_checked_close(held.into());
            held_retirement.push(serde_json::json!({"path":path,"device":metadata.dev(),"inode":metadata.ino(),"nlink":metadata.nlink(),"close_native_errno":closed.as_ref().err().and_then(std::io::Error::raw_os_error),"closed":closed.is_ok()}));
            closed.map_err(|error| {
                CiError::Message(format!(
                    "original export observation descriptor close errno {error}"
                ))
            })?;
        }
        let reservation_after = if let Some(file) = reservation_owner {
            let original = reservation_before
                .as_ref()
                .expect("retained original reservation metadata");
            let path = original["path"]
                .as_str()
                .ok_or_else(|| CiError::Message("original reservation pathname absent".into()))?;
            let metadata = file.metadata()?;
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
                CiError::Message(format!("original reservation descriptor closure: {error}"))
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
            let metadata = file.metadata()?;
            let named = std::fs::symlink_metadata(&path)?;
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
            closed?;
        }
        let result = super::linux_mixed_installed::read_owned_resource(
            row.result
                .as_ref()
                .ok_or_else(|| CiError::Message("original export carrier absent".into()))?,
            16 * 1024 * 1024,
        )?;
        let request = super::linux_mixed_installed::read_owned_resource(
            row.provider_request
                .as_ref()
                .ok_or_else(|| CiError::Message("original export request absent".into()))?,
            4 * 1024 * 1024,
        )?;
        super::linux_mixed_installed::persist_policy_refusal_census(
            account,
            input.provider,
            &input.identity,
            &input.cell,
            &input.lease_id,
            &row.scenario,
            attempt,
            &result,
            &request,
            &directory.join("recovery-census.json"),
            input.cleanup_deadline,
        )?;
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
    }
    Ok(())
}
