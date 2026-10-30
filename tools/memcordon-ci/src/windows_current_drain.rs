//! Cancellation while an actual current package transition excludes admissions.
use super::{HeldProcess, write_new};
use crate::{
    CiError, Result,
    windows_installed_cases::{InstalledWindowsPayload, WindowsLeaseDeadlines},
};
use std::{
    fs, io,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{HANDLE, WAIT_TIMEOUT},
    System::Threading::{
        MUTEX_MODIFY_STATE, OpenMutexW, ReleaseMutex, SYNCHRONIZATION_SYNCHRONIZE,
        WaitForSingleObject,
    },
};
struct MutexObservation(HANDLE);
impl Drop for MutexObservation {
    #[allow(unsafe_code)] // Close only this query/modify reference, never release another thread's ownership.
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
#[allow(unsafe_code)] // Opens the existing code-owned package mutex; no object is created or adopted.
fn package_mutex() -> io::Result<Option<MutexObservation>> {
    let name = r"Global\MemCordonSealedPackageV1"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let raw = unsafe {
        OpenMutexW(
            SYNCHRONIZATION_SYNCHRONIZE | MUTEX_MODIFY_STATE,
            0,
            name.as_ptr(),
        )
    };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(2) {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(MutexObservation(raw)))
}
#[allow(unsafe_code)] // Zero-time native wait observes ownership; accidental acquisition is immediately released.
fn owned_mutex(mutex: &MutexObservation) -> io::Result<u32> {
    let state = unsafe { WaitForSingleObject(mutex.0, 0) };
    if state == WAIT_TIMEOUT {
        return Ok(state);
    }
    if state == 0 || state == windows_sys::Win32::Foundation::WAIT_ABANDONED {
        unsafe { ReleaseMutex(mutex.0) };
    }
    Err(io::Error::other(
        "package transition no longer owns its actual mutex",
    ))
}

pub(super) fn run(
    config: &InstalledWindowsPayload,
    deadlines: WindowsLeaseDeadlines,
    prepared: &memcordon_core::WindowsWorkloadPreparedV1,
    observations: &std::path::Path,
    directory: &std::path::Path,
    cutoff: Instant,
) -> Result<u32> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    let held = fs::File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&config.installed_agent.path)?;
    let image_identity = crate::windows_native_files::native_file_identity(
        &held,
        false,
        &config.installed_agent.path,
    )?;
    let budget = cutoff
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(90));
    if budget.is_zero() {
        return Err(CiError::Message(
            "original package-drain cutoff exhausted".into(),
        ));
    }
    let mut command = std::process::Command::new(&config.agent.path);
    command
        .current_dir(directory)
        .args(["package", "upgrade"])
        .stdin(std::process::Stdio::null());
    let invocation = serde_json::json!({"format":"memcordon.windows-package-invocation","revision":1,"operation":"upgrade","program_utf16":config.agent.path.as_os_str().encode_wide().collect::<Vec<_>>(),"argv_utf16":command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),"cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"image_sha256":config.agent.sha256,"budget_millis":u64::try_from(budget.as_millis()).map_err(|error|CiError::Message(error.to_string()))?});
    write_new(
        &directory.join("package-upgrade.invocation.json"),
        &serde_json::to_vec(&invocation)?,
    )?;
    let callback_directory = directory.to_owned();
    let observations = observations.to_owned();
    let prepared = prepared.clone();
    let image_path = config.agent.path.clone();
    let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
        command,
        budget,
        4 * 1024 * 1024,
        |mut command| command.spawn(),
        move |package_pid, _, _| {
            let worker = HeldProcess::open(package_pid)?;
            let identity = worker.identity(package_pid)?;
            if super::service_restart::image(&worker)?
                != image_path.as_os_str().encode_wide().collect::<Vec<_>>()
            {
                return Err(io::Error::other(
                    "package drain worker differs from selected current image",
                ));
            }
            let target = HeldProcess::open(prepared.target.process_id)?;
            if target.identity(prepared.target.process_id)? != prepared.target {
                return Err(io::Error::other(
                    "drain target differs from original held prepared owner",
                ));
            }
            let mutex = loop {
                if worker.wait()? != WAIT_TIMEOUT || Instant::now() >= cutoff {
                    return Err(io::Error::other(
                        "actual package worker/cutoff ended before drain",
                    ));
                }
                if let Some(mutex) = package_mutex()? {
                    owned_mutex(&mutex)?;
                    break mutex;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let before = owned_mutex(&mutex)?;
            let target_wait = target.wait()?;
            let cancel = memcordon_core::WindowsProviderRequestV4::Cancel {
                schema_version: 4,
                attempt_id: prepared.attempt_id.clone(),
                nonce: prepared.nonce.clone(),
                request_sha256: prepared.request_sha256.clone(),
                signal: 2,
            };
            let bytes = serde_json::to_vec(&cancel).map_err(io::Error::other)?;
            write_new(&callback_directory.join("cancel.json"), &bytes).map_err(io::Error::other)?;
            write_new(
                &observations.join(format!("{}.cancel.json", prepared.attempt_id)),
                &bytes,
            )
            .map_err(io::Error::other)?;
            let sent = loop {
                match fs::read(
                    observations.join(format!("{}.cancel-sent.json", prepared.attempt_id)),
                ) {
                    Ok(bytes) => break bytes,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                if Instant::now() >= cutoff || worker.wait()? != WAIT_TIMEOUT {
                    return Err(io::Error::other(
                        "package drain ended before actual caller cancellation write",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let after = owned_mutex(&mutex)?;
            if sent != bytes || worker.wait()? != WAIT_TIMEOUT {
                return Err(io::Error::other(
                    "actual cancellation did not cross bound caller channel during native package ownership",
                ));
            }
            write_new(&callback_directory.join("cancel-sent.json"), &sent)
                .map_err(io::Error::other)?;
            write_new(&callback_directory.join("drain.json"),&serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-current-package-drain","revision":1,"worker":identity,"worker_image_utf16":image_path.as_os_str().encode_wide().collect::<Vec<_>>(),"worker_wait":worker.wait()?,"mutex_name":"Global\\MemCordonSealedPackageV1","mutex_wait_before":before,"mutex_wait_after":after,"target":prepared.target,"target_wait_at_cancel":target_wait,"cancel_sha256":crate::windows_causal_acceptance::sha256(&bytes),"sent_sha256":crate::windows_causal_acceptance::sha256(&sent)})).map_err(io::Error::other)?).map_err(io::Error::other)?;
            Ok(())
        },
    );
    let result =
        crate::windows_installed_cases::retain_package_operation(directory, "upgrade", output);
    let capture: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("package-upgrade.capture.json"))?)?;
    if result.is_ok()
        || capture["operation_complete"] != true
        || capture["observed_exit_code"] != 125
        || !String::from_utf8_lossy(&fs::read(directory.join("package-upgrade.stderr.bin"))?)
            .contains("MCSEALED-WINDOWS-UPGRADE-ROLLBACK-FAILED")
    {
        return Err(CiError::Message(
            "current drain did not complete its genuine bounded image-sharing interruption".into(),
        ));
    }
    let named = fs::File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&config.installed_agent.path)?;
    if crate::windows_native_files::native_file_identity(
        &named,
        false,
        &config.installed_agent.path,
    )? != image_identity
    {
        return Err(CiError::Message(
            "drain sharing boundary lost original installed native image".into(),
        ));
    }
    drop(named);
    drop(held);
    let mut recovered = config.clone();
    recovered.output_directory = directory.join("package-recovery");
    fs::create_dir(&recovered.output_directory)?;
    crate::windows_installed_cases::run_current_package(&recovered, "upgrade", deadlines.work)
        .map_err(CiError::Message)?;
    crate::windows_installed_cases::run_current_package(&recovered, "verify", deadlines.work)
        .map_err(CiError::Message)?;
    let mut readback = std::collections::BTreeMap::new();
    let mut pins = Vec::new();
    for selected in std::iter::once(&config.installed_agent)
        .chain(std::iter::once(&config.installed_manifest))
        .chain(config.installed_components.iter())
    {
        let held = crate::windows_native_files::hold_artifact(
            &selected.path,
            Some(&selected.sha256),
            512 * 1024 * 1024,
        )?;
        readback.insert(selected.path.clone(), held.sha256.clone());
        pins.push(held);
    }
    let journal = config
        .installed_agent
        .path
        .parent()
        .ok_or_else(|| CiError::Message("installed image root absent".into()))?
        .join("current-package-state.rollback.json");
    if journal.try_exists()? {
        return Err(CiError::Message(
            "drain package recovery retained native current transaction".into(),
        ));
    }
    write_new(
        &directory.join("drain-recovery.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.windows-current-drain-recovery","revision":1,"readback":readback,"journal_path":journal,"journal_absent":true,"work_deadline_unix_millis":deadlines.work_deadline_unix_millis,"cleanup_deadline_unix_millis":deadlines.cleanup_deadline_unix_millis}),
        )?,
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("drain.json"))?)?;
    value["target_wait_at_cancel"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| CiError::Message("actual target wait at drain cancellation absent".into()))
}
