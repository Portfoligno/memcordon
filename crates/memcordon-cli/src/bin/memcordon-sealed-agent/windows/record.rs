use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use memcordon_core::WindowsAttemptStateV1;
use memcordon_core::{WindowsProcessIdentityV1, windows_attempt_transition_allowed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

use super::package;
use super::pipe::OwnedHandle;

const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCleanupStateV1 {
    pub termination_requested: bool,
    pub active_processes_zero: bool,
    pub guardian_reaped: bool,
    pub final_handles_closed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAttemptRecordV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub provider_generation: String,
    pub boot_identity: String,
    pub request_sha256: String,
    pub caller_process_identity: WindowsProcessIdentityV1,
    pub caller_token_sha256: String,
    pub job_identity_sha256: String,
    pub guardian_identity: Option<WindowsProcessIdentityV1>,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub state: WindowsAttemptStateV1,
    pub authorization_unix_millis: Option<u64>,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsCleanupStateV1,
    pub integrity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsGuardianReceiptV1 {
    schema_version: u32,
    attempt_id: String,
    termination_requested: bool,
    active_processes_zero: bool,
    integrity_sha256: String,
}

impl WindowsAttemptRecordV1 {
    pub fn new(
        attempt_id: String,
        request_sha256: String,
        caller_process_identity: WindowsProcessIdentityV1,
        caller_token_sha256: String,
        job_identity_sha256: String,
    ) -> Result<Self, String> {
        Ok(Self {
            schema_version: 1,
            attempt_id,
            provider_generation: provider_generation(),
            boot_identity: boot_identity()?,
            request_sha256,
            caller_process_identity,
            caller_token_sha256,
            job_identity_sha256,
            guardian_identity: None,
            target_identity: None,
            state: WindowsAttemptStateV1::BoundaryCreated,
            authorization_unix_millis: None,
            resume_attempted: false,
            target_released: false,
            cleanup_state: WindowsCleanupStateV1::default(),
            integrity_sha256: String::new(),
        })
    }

    pub fn store(&mut self) -> Result<(), String> {
        self.integrity_sha256.clear();
        self.integrity_sha256 =
            digest(&serde_json::to_vec(self).map_err(|error| error.to_string())?);
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        let path = record_path(&self.attempt_id)?;
        let staged = path.with_extension("json.new");
        fs::write(&staged, bytes).map_err(|error| error.to_string())?;
        replace_atomically(&staged, &path)
    }

    pub fn authorize(&mut self) -> Result<(), String> {
        self.transition(WindowsAttemptStateV1::Authorized)?;
        self.authorization_unix_millis = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_millis()
                .try_into()
                .map_err(|_| "authorization timestamp exceeds record range".to_owned())?,
        );
        self.store()
    }

    pub fn retire(&mut self) -> Result<(), String> {
        self.transition(WindowsAttemptStateV1::Empty)?;
        self.cleanup_state.termination_requested = true;
        self.cleanup_state.active_processes_zero = true;
        self.cleanup_state.guardian_reaped = true;
        self.cleanup_state.final_handles_closed = true;
        self.store()?;
        fs::remove_file(record_path(&self.attempt_id)?).map_err(|error| error.to_string())?;
        remove_guardian_receipt(&self.attempt_id)
    }

    pub fn mark_released(&mut self) -> Result<(), String> {
        self.target_released = true;
        self.store()
    }

    pub fn mark_resume_attempted(&mut self) -> Result<(), String> {
        self.resume_attempted = true;
        self.store()
    }

    pub fn transition(&mut self, state: WindowsAttemptStateV1) -> Result<(), String> {
        if !windows_attempt_transition_allowed(self.state, state) {
            return Err(format!(
                "attempt state transition is invalid: {:?} -> {state:?}",
                self.state
            ));
        }
        self.state = state;
        Ok(())
    }
}

pub fn recover() -> Result<(), String> {
    let attempts = attempts_root();
    fs::create_dir_all(&attempts).map_err(|error| error.to_string())?;
    fs::create_dir_all(quarantine_root()).map_err(|error| error.to_string())?;
    fs::create_dir_all(replay_root()).map_err(|error| error.to_string())?;
    fs::create_dir_all(admissions_root()).map_err(|error| error.to_string())?;
    fs::create_dir_all(guardian_receipts_root()).map_err(|error| error.to_string())?;
    let mut ambiguous = fs::read_dir(quarantine_root())
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| format!("{} (durable quarantine)", entry.path().to_string_lossy()))
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    for entry in fs::read_dir(guardian_receipts_root()).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        let parsed = (|| {
            let attempt_id = record_attempt_id(&path)?;
            read_guardian_receipt(&attempt_id)?;
            Ok::<_, String>(attempt_id)
        })();
        match parsed {
            Ok(attempt_id) if !record_path(&attempt_id)?.exists() => {
                fs::remove_file(path).map_err(|error| error.to_string())?;
            }
            Ok(_) => {}
            Err(error) => {
                let quarantined = quarantine(&path)?;
                ambiguous.push(format!(
                    "{} (invalid guardian terminal receipt: {error})",
                    quarantined.to_string_lossy()
                ));
            }
        }
    }
    for entry in fs::read_dir(admissions_root()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let quarantined = quarantine(&entry.path())?;
        ambiguous.push(format!(
            "{} (abandoned launch admission)",
            quarantined.to_string_lossy()
        ));
    }
    for entry in fs::read_dir(&attempts).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let parsed = (|| {
            let attempt_id = record_attempt_id(&path)?;
            let bytes = fs::read(&path).map_err(|error| error.to_string())?;
            let record: WindowsAttemptRecordV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            authenticate(&record, &attempt_id)?;
            Ok::<_, String>(record)
        })();
        let mut record = match parsed {
            Ok(record) => record,
            Err(error) => {
                let quarantined = quarantine(&path)?;
                ambiguous.push(format!("{} ({error})", quarantined.to_string_lossy()));
                continue;
            }
        };
        let no_live_processes = !record_has_live_process(&record)?;
        let prior_boot = record.boot_identity != boot_identity()?;
        let durably_empty = record.state == WindowsAttemptStateV1::Empty
            && record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.cleanup_state.final_handles_closed;
        let kill_on_close_reconciled = record.state == WindowsAttemptStateV1::Terminating
            && record.cleanup_state.termination_requested
            && record.guardian_identity.is_some()
            && record.target_identity.is_some();
        if no_live_processes && (prior_boot || durably_empty || kill_on_close_reconciled) {
            fs::remove_file(path).map_err(|error| error.to_string())?;
            remove_guardian_receipt(&record.attempt_id)?;
            continue;
        }
        let reconciled = (|| {
            if record.state != WindowsAttemptStateV1::Terminating {
                record.transition(WindowsAttemptStateV1::Terminating)?;
            }
            record.cleanup_state.termination_requested = true;
            record.store()?;
            let deadline = Instant::now() + Duration::from_secs(35);
            while Instant::now() < deadline && record_has_live_process(&record)? {
                std::thread::sleep(Duration::from_millis(100));
            }
            if record_has_live_process(&record)? {
                Err(format!(
                    "guardian authority for live attempt {} did not retire",
                    record.attempt_id
                ))
            } else {
                let receipt = read_guardian_receipt(&record.attempt_id)?;
                if receipt.termination_requested && receipt.active_processes_zero {
                    record.cleanup_state.termination_requested = true;
                    record.cleanup_state.active_processes_zero = true;
                    record.cleanup_state.guardian_reaped = true;
                    record.store()?;
                    Ok(())
                } else {
                    Err(format!(
                        "guardian authority for attempt {} did not durably prove Job zero",
                        record.attempt_id
                    ))
                }
            }
        })();
        if let Err(error) = reconciled {
            let quarantined = quarantine(&path)?;
            ambiguous.push(format!("{} ({error})", quarantined.to_string_lossy(),));
            continue;
        }
        fs::remove_file(path).map_err(|error| error.to_string())?;
        remove_guardian_receipt(&record.attempt_id)?;
    }
    if ambiguous.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "MCSEALED-WINDOWS-RECOVERY-AMBIGUOUS: quarantined records: {}",
            ambiguous.join(", ")
        ))
    }
}

pub fn attempts_empty() -> Result<bool, String> {
    Ok(directory_empty(&attempts_root())?
        && directory_empty(&admissions_root())?
        && directory_empty(&quarantine_root())?
        && directory_empty(&guardian_receipts_root())?)
}

pub fn recovery_clear() -> Result<bool, String> {
    directory_empty(&quarantine_root())
}

pub fn certify_machine_restart_recovery() -> Result<bool, String> {
    if !attempts_empty()? {
        return Err("machine-restart recovery fixture requires idle provider state".to_owned());
    }
    let nonce = format!(
        "machine-restart-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    );
    let attempt_id = digest(nonce.as_bytes());
    let request_sha256 = digest(attempt_id.as_bytes());
    let caller = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    let mut record = WindowsAttemptRecordV1::new(
        attempt_id.clone(),
        request_sha256,
        caller,
        digest(b"machine-restart-token"),
        digest(b"machine-restart-job"),
    )?;
    record.boot_identity = digest(b"certified-prior-native-boot");
    record.store()?;
    recover()?;
    Ok(!record_path(&attempt_id)?.exists() && attempts_empty()?)
}

pub fn remove_empty_attempt_state() -> Result<(), String> {
    if !attempts_empty()? {
        return Err("MCSEALED-WINDOWS-PACKAGE-ACTIVE: attempt state is not empty".to_owned());
    }
    // The replay ledger is intentionally not active-attempt state: completed
    // attempts remain replay-protected for the lifetime of an installation.
    // It is retired only by this authenticated, idle package-cleanup path.
    if replay_retiring_root().exists() {
        return Err("replay ledger retirement is already in progress".to_owned());
    }
    if replay_root().exists() {
        validate_replay_directory(&replay_root())?;
        fs::rename(replay_root(), replay_retiring_root()).map_err(|error| error.to_string())?;
        retire_detached_replay()?;
    }
    for directory in [
        attempts_root(),
        admissions_root(),
        quarantine_root(),
        guardian_receipts_root(),
    ] {
        fs::remove_dir(directory).map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Completes a package-cleanup replay retirement that was atomically detached
/// before a control/package process crash. While the detached directory
/// exists, the required live `replay/` root is absent and every launch fails
/// closed in `reharden_attempt_state`.
pub fn recover_detached_replay() -> Result<(), String> {
    if !replay_retiring_root().exists() {
        return Ok(());
    }
    validate_replay_directory(&replay_retiring_root())?;
    retire_detached_replay()
}

fn retire_detached_replay() -> Result<(), String> {
    for entry in fs::read_dir(replay_retiring_root()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
    }
    fs::remove_dir(replay_retiring_root()).map_err(|error| error.to_string())
}

fn validate_replay_directory(path: &Path) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("replay ledger contains a non-file entry".to_owned());
        }
        let bytes = fs::read(entry.path()).map_err(|error| error.to_string())?;
        let replay: ReplayRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        validate_attempt_id(&replay.attempt_id)?;
        validate_attempt_id(&replay.request_sha256)?;
        let expected_name = format!("{}.json", replay.attempt_id);
        if entry.file_name() != std::ffi::OsStr::new(&expected_name) {
            return Err("replay ledger filename does not match its attempt id".to_owned());
        }
    }
    Ok(())
}

pub fn reharden_attempt_state() -> Result<(), String> {
    let launcher_sddl = super::security::launcher_state_sddl()?;
    let launcher_dacl = launcher_sddl
        .strip_prefix("O:BA")
        .ok_or_else(|| "launcher state policy is missing its fixed owner".to_owned())?;
    let launcher_apply = super::security::SecurityDescriptor::from_sddl(launcher_dacl)?;
    let launcher_verify = super::security::SecurityDescriptor::from_sddl(&launcher_sddl)?;
    for directory in [attempts_root(), quarantine_root(), guardian_receipts_root()] {
        if !directory.exists() {
            return Err("runtime attempt-state directory is absent".to_owned());
        }
        launcher_apply.apply_to_path(&directory)?;
        launcher_verify.verify_path(&directory)?;
    }
    let replay_path = replay_root();
    if !replay_path.exists() {
        return Err("runtime replay directory is absent".to_owned());
    }
    let replay_sddl = super::security::replay_state_sddl()?;
    let replay_dacl = replay_sddl
        .strip_prefix("O:BA")
        .ok_or_else(|| "replay state policy is missing its fixed owner".to_owned())?;
    super::security::SecurityDescriptor::from_sddl(replay_dacl)?.apply_to_path(&replay_path)?;
    super::security::SecurityDescriptor::from_sddl(&replay_sddl)?.verify_path(&replay_path)?;
    let admission_path = admissions_root();
    if !admission_path.exists() {
        return Err("runtime admission directory is absent".to_owned());
    }
    let admission_sddl = super::security::admission_state_sddl()?;
    let admission_dacl = admission_sddl
        .strip_prefix("O:BA")
        .ok_or_else(|| "admission state policy is missing its fixed owner".to_owned())?;
    super::security::SecurityDescriptor::from_sddl(admission_dacl)?
        .apply_to_path(&admission_path)?;
    super::security::SecurityDescriptor::from_sddl(&admission_sddl)?
        .verify_path(&admission_path)?;
    Ok(())
}

pub struct AdmissionLease {
    path: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRecordV1 {
    attempt_id: String,
    request_sha256: String,
    owner_process_identities: Vec<memcordon_core::WindowsProcessIdentityV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayRecordV1 {
    attempt_id: String,
    request_sha256: String,
}

impl Drop for AdmissionLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn reserve_admission(attempt_id: &str, request_sha256: &str) -> Result<AdmissionLease, String> {
    reserve_admission_record(attempt_id, request_sha256, None)
}

fn reserve_admission_record(
    attempt_id: &str,
    request_sha256: &str,
    owner_process_identity: Option<memcordon_core::WindowsProcessIdentityV1>,
) -> Result<AdmissionLease, String> {
    validate_attempt_id(attempt_id)?;
    validate_attempt_id(request_sha256)?;
    fs::create_dir_all(admissions_root()).map_err(|error| error.to_string())?;
    let path = admissions_root().join(format!("{attempt_id}.json"));
    let mut bytes = serde_json::to_vec(&AdmissionRecordV1 {
        attempt_id: attempt_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        owner_process_identities: owner_process_identity.into_iter().collect(),
    })
    .map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, &bytes))
        .map_err(|error| error.to_string())?;
    Ok(AdmissionLease { path })
}

pub fn reserve_attempt(attempt_id: &str, request_sha256: &str) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    validate_attempt_id(request_sha256)?;
    fs::create_dir_all(replay_root()).map_err(|error| error.to_string())?;
    let path = replay_root().join(format!("{attempt_id}.json"));
    let mut bytes = serde_json::to_vec(&ReplayRecordV1 {
        attempt_id: attempt_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
    })
    .map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, &bytes))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "MCSEALED-WINDOWS-REPLAY: attempt id or nonce was already consumed".to_owned()
            } else {
                error.to_string()
            }
        })
}

pub fn validate_admission(attempt_id: &str, request_sha256: &str) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    validate_attempt_id(request_sha256)?;
    let path = admissions_root().join(format!("{attempt_id}.json"));
    let admission: AdmissionRecordV1 =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if admission.attempt_id != attempt_id || admission.request_sha256 != request_sha256 {
        return Err("launch admission does not match the authenticated broker request".to_owned());
    }
    Ok(())
}

pub fn retire_admission(attempt_id: &str) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    let path = admissions_root().join(format!("{attempt_id}.json"));
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

pub fn reserve_qualification_admission_for(
    scope: &str,
    owner: memcordon_core::WindowsProcessIdentityV1,
) -> Result<AdmissionLease, String> {
    let identity = qualification_admission_identity(scope);
    reserve_admission_record(&identity, &identity, Some(owner))
}

pub fn qualification_in_progress() -> bool {
    ["direct", "package"]
        .iter()
        .map(|scope| {
            admissions_root().join(format!("{}.json", qualification_admission_identity(scope)))
        })
        .any(|path| path.is_file())
}

pub fn qualification_allows(
    process_identity: &memcordon_core::WindowsProcessIdentityV1,
) -> Result<bool, String> {
    for scope in ["direct", "package"] {
        let identity = qualification_admission_identity(scope);
        let path = admissions_root().join(format!("{identity}.json"));
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        let admission: AdmissionRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if admission.attempt_id != identity
            || admission.request_sha256 != identity
            || !admission
                .owner_process_identities
                .contains(process_identity)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn authorize_qualification_child_for(
    scope: &str,
    owner: &memcordon_core::WindowsProcessIdentityV1,
    child: memcordon_core::WindowsProcessIdentityV1,
) -> Result<(), String> {
    let identity = qualification_admission_identity(scope);
    let path = admissions_root().join(format!("{identity}.json"));
    let bytes = fs::read(&path).map_err(|error| error.to_string())?;
    let mut admission: AdmissionRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if admission.attempt_id != identity
        || admission.request_sha256 != identity
        || !admission.owner_process_identities.contains(owner)
    {
        return Err("qualification admission is not owned by the authenticated client".to_owned());
    }
    if !admission.owner_process_identities.contains(&child) {
        admission.owner_process_identities.push(child);
    }
    let mut bytes = serde_json::to_vec_pretty(&admission).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let staged = path.with_extension("json.new");
    fs::write(&staged, bytes).map_err(|error| error.to_string())?;
    replace_atomically(&staged, &path)
}

fn qualification_admission_identity(scope: &str) -> String {
    digest(format!("memcordon-windows-qualification-v1:{scope}").as_bytes())
}

pub fn rejection_evidence(
    attempt_id: &str,
    code: &str,
    detail: String,
    phase_override: Option<memcordon_core::BoundarySetupPhase>,
    os_code: Option<i32>,
) -> Result<memcordon_core::ProviderRejectionEvidence, String> {
    let path = match record_path(attempt_id) {
        Ok(path) => path,
        Err(_) => return Ok(pretarget_rejection(code, detail)),
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(pretarget_rejection(code, detail));
        }
        Err(error) => return Err(error.to_string()),
    };
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    let target_created = record.target_identity.is_some();
    let cleanup_attempted = record.cleanup_state.termination_requested;
    let live = record_has_live_process(&record)?;
    if cleanup_attempted
        && record.cleanup_state.active_processes_zero
        && record.cleanup_state.guardian_reaped
        && !live
    {
        record.cleanup_state.final_handles_closed = true;
        record.store()?;
    }
    let safe = cleanup_attempted
        && record.cleanup_state.active_processes_zero
        && record.cleanup_state.guardian_reaped
        && record.cleanup_state.final_handles_closed
        && !live;
    let restart_safety = if safe {
        memcordon_core::RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        }
    } else {
        memcordon_core::RestartSafetyProof {
            errors: vec!["Windows rejection cleanup did not prove complete retirement".to_owned()],
            ..memcordon_core::RestartSafetyProof::default()
        }
    };
    if safe {
        fs::remove_file(path).map_err(|error| error.to_string())?;
        remove_guardian_receipt(attempt_id)?;
    }
    let phase = phase_override.unwrap_or(match record.state {
        WindowsAttemptStateV1::BoundaryCreated | WindowsAttemptStateV1::GuardianReady => {
            memcordon_core::BoundarySetupPhase::BoundaryCreation
        }
        WindowsAttemptStateV1::TargetCreatedSuspended => {
            memcordon_core::BoundarySetupPhase::ResourceVerification
        }
        WindowsAttemptStateV1::Authorized => memcordon_core::BoundarySetupPhase::Authorization,
        WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty => {
            memcordon_core::BoundarySetupPhase::Retirement
        }
    });
    Ok(memcordon_core::ProviderRejectionEvidence {
        schema_version: 1,
        code: code.to_owned(),
        phase,
        detail,
        os_code,
        target_created,
        target_released: record.target_released || record.resume_attempted,
        cleanup_attempted,
        restart_safety,
    })
}

pub fn pretarget_rejection(
    code: &str,
    detail: String,
) -> memcordon_core::ProviderRejectionEvidence {
    pretarget_rejection_at(
        code,
        memcordon_core::BoundarySetupPhase::ProviderConnection,
        detail,
    )
}

pub fn pretarget_rejection_at(
    code: &str,
    phase: memcordon_core::BoundarySetupPhase,
    detail: String,
) -> memcordon_core::ProviderRejectionEvidence {
    memcordon_core::ProviderRejectionEvidence {
        schema_version: 1,
        code: code.to_owned(),
        phase,
        detail,
        os_code: None,
        target_created: false,
        target_released: false,
        cleanup_attempted: false,
        restart_safety: memcordon_core::RestartSafetyProof::default(),
    }
}

pub fn attempts_root() -> PathBuf {
    package::state_root().join("attempts")
}

pub fn quarantine_root() -> PathBuf {
    package::state_root().join("quarantine")
}

pub fn admissions_root() -> PathBuf {
    package::state_root().join("admissions")
}

pub fn replay_root() -> PathBuf {
    package::state_root().join("replay")
}

fn replay_retiring_root() -> PathBuf {
    package::state_root().join("replay-retiring")
}

pub fn guardian_receipts_root() -> PathBuf {
    package::state_root().join("guardian-receipts")
}

fn directory_empty(path: &Path) -> Result<bool, String> {
    match fs::read_dir(path) {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.to_string()),
    }
}

fn quarantine(path: &Path) -> Result<PathBuf, String> {
    let root = quarantine_root();
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unrecognized-attempt");
    let mut identity = path.as_os_str().to_string_lossy().as_bytes().to_vec();
    identity.extend_from_slice(
        &SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
            .to_le_bytes(),
    );
    let destination = root.join(format!("{}-{name}", digest(&identity)));
    fs::rename(path, &destination).map_err(|error| error.to_string())?;
    Ok(destination)
}

fn record_path(attempt_id: &str) -> Result<PathBuf, String> {
    validate_attempt_id(attempt_id)?;
    Ok(attempts_root().join(format!("{attempt_id}.json")))
}

pub fn write_guardian_receipt(attempt_id: &str) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    fs::create_dir_all(guardian_receipts_root()).map_err(|error| error.to_string())?;
    let mut receipt = WindowsGuardianReceiptV1 {
        schema_version: 1,
        attempt_id: attempt_id.to_owned(),
        termination_requested: true,
        active_processes_zero: true,
        integrity_sha256: String::new(),
    };
    receipt.integrity_sha256 = guardian_receipt_digest(&receipt)?;
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let path = guardian_receipt_path(attempt_id)?;
    let staged = path.with_extension("json.new");
    fs::write(&staged, bytes).map_err(|error| error.to_string())?;
    replace_atomically(&staged, &path)
}

fn read_guardian_receipt(attempt_id: &str) -> Result<WindowsGuardianReceiptV1, String> {
    let path = guardian_receipt_path(attempt_id)?;
    let receipt: WindowsGuardianReceiptV1 =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let expected = guardian_receipt_digest(&receipt)?;
    if receipt.schema_version != 1
        || receipt.attempt_id != attempt_id
        || !receipt.termination_requested
        || !receipt.active_processes_zero
        || receipt.integrity_sha256 != expected
    {
        return Err("guardian terminal receipt authentication failed".to_owned());
    }
    Ok(receipt)
}

fn guardian_receipt_digest(receipt: &WindowsGuardianReceiptV1) -> Result<String, String> {
    let mut canonical = receipt.clone();
    canonical.integrity_sha256.clear();
    Ok(digest(
        &serde_json::to_vec(&canonical).map_err(|error| error.to_string())?,
    ))
}

fn guardian_receipt_path(attempt_id: &str) -> Result<PathBuf, String> {
    validate_attempt_id(attempt_id)?;
    Ok(guardian_receipts_root().join(format!("{attempt_id}.json")))
}

fn remove_guardian_receipt(attempt_id: &str) -> Result<(), String> {
    match fs::remove_file(guardian_receipt_path(attempt_id)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn record_attempt_id(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "attempt record name is not UTF-8".to_owned())?;
    let attempt_id = name
        .strip_suffix(".json")
        .ok_or_else(|| "attempt directory contains an unrecognized entry".to_owned())?;
    validate_attempt_id(attempt_id)?;
    Ok(attempt_id.to_owned())
}

pub fn validate_attempt_id(value: &str) -> Result<(), String> {
    let digest_length = digest(&[]).len();
    if value.len() == digest_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("attempt record has an invalid identity".to_owned())
    }
}

fn authenticate(record: &WindowsAttemptRecordV1, file_attempt_id: &str) -> Result<(), String> {
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    memcordon_core::parse_and_authenticate_windows_attempt_record(
        &bytes,
        file_attempt_id,
        &provider_generation(),
    )
    .map(|_| ())
    .map_err(str::to_owned)
}

fn record_has_live_process(record: &WindowsAttemptRecordV1) -> Result<bool, String> {
    [
        record.guardian_identity.clone(),
        record.target_identity.clone(),
    ]
    .into_iter()
    .flatten()
    .try_fold(false, |live, identity| {
        if live {
            Ok(true)
        } else {
            process_identity_is_live(identity)
        }
    })
}

fn process_identity_is_live(expected: WindowsProcessIdentityV1) -> Result<bool, String> {
    // SAFETY: PID comes from an authenticated record and rights are query-only.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            expected.process_id,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        let missing = error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            == Some(ERROR_INVALID_PARAMETER);
        return if missing {
            Ok(false)
        } else {
            Err(error.to_string())
        };
    }
    let handle = OwnedHandle::new(raw)?;
    // SAFETY: handle is live and queried without blocking.
    match unsafe { WaitForSingleObject(handle.raw(), 0) } {
        WAIT_OBJECT_0 => return Ok(false),
        WAIT_FAILED => return Err(std::io::Error::last_os_error().to_string()),
        _ => {}
    }
    Ok(super::process::process_identity(handle.raw())? == expected)
}

pub fn replace_atomically(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are live, NUL-terminated UTF-16 buffers and the flags
    // request an atomic same-volume replacement flushed before return.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

fn provider_generation() -> String {
    format!("{}:{}", env!("CARGO_PKG_VERSION"), crate::SOURCE_COMMIT)
}

fn boot_identity() -> Result<String, String> {
    #[repr(C)]
    struct SystemTimeOfDayInformation {
        boot_time: i64,
        current_time: i64,
        time_zone_bias: i64,
        current_time_zone_id: u32,
        reserved: u32,
        boot_time_bias: u64,
        sleep_time_bias: u64,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    let mut information = std::mem::MaybeUninit::<SystemTimeOfDayInformation>::zeroed();
    let mut returned = 0_u32;
    // SystemTimeOfDayInformation is the native class whose BootTime value is
    // stable for one boot and changes across every reboot. This avoids the
    // collision and clock-skew ambiguity of subtracting GetTickCount64 from
    // wall time.
    let status = unsafe {
        NtQuerySystemInformation(
            3,
            information.as_mut_ptr().cast(),
            u32::try_from(std::mem::size_of::<SystemTimeOfDayInformation>())
                .map_err(|_| "system time-of-day structure exceeds Win32 length".to_owned())?,
            &raw mut returned,
        )
    };
    if status < 0
        || usize::try_from(returned).ok() != Some(std::mem::size_of::<SystemTimeOfDayInformation>())
    {
        Err(format!(
            "NtQuerySystemInformation(SystemTimeOfDayInformation) failed with NTSTATUS {status:#010x} and length {returned}"
        ))
    } else {
        Ok(unsafe { information.assume_init() }.boot_time.to_string())
    }
}

pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
