use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use memcordon_core::{WindowsAttemptStateV1, WindowsAttemptTerminalDispositionV1};
use memcordon_core::{WindowsProcessIdentityV1, windows_attempt_transition_allowed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileIdInfo,
    FileRenameInfo, FileStandardInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, SetFileInformationByHandle,
    VOLUME_NAME_NT,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

use super::package;
use super::pipe::OwnedHandle;

const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const DELETE_ACCESS: u32 = 0x0001_0000;
const GENERIC_WRITE_ACCESS: u32 = 0x4000_0000;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_response_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
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
            terminal_response_json: None,
            terminal_disposition: None,
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

    pub fn complete_retirement(&mut self) -> Result<(), String> {
        self.transition(WindowsAttemptStateV1::Empty)?;
        self.cleanup_state.termination_requested = true;
        self.cleanup_state.active_processes_zero = true;
        self.cleanup_state.guardian_reaped = true;
        self.cleanup_state.final_handles_closed = true;
        self.terminal_disposition = Some(WindowsAttemptTerminalDispositionV1::Posttarget);
        self.store()
    }

    pub fn complete_preauthorization_abort(&mut self) -> Result<(), String> {
        self.transition(WindowsAttemptStateV1::Empty)?;
        self.cleanup_state.termination_requested = true;
        self.cleanup_state.active_processes_zero = true;
        self.cleanup_state.guardian_reaped = true;
        self.cleanup_state.final_handles_closed = true;
        self.terminal_disposition =
            Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
        self.store()
    }

    pub fn stage_terminal_response(
        &mut self,
        response: &memcordon_core::WindowsLauncherResponseV1,
    ) -> Result<(), String> {
        if self.state != WindowsAttemptStateV1::Empty || self.terminal_response_json.is_some() {
            return Err("attempt is not ready for a create-once terminal outbox".to_owned());
        }
        let binding_matches = match response {
            memcordon_core::WindowsLauncherResponseV1::Terminal(receipt) => {
                receipt.attempt_id == self.attempt_id
                    && receipt.request_sha256 == self.request_sha256
            }
            memcordon_core::WindowsLauncherResponseV1::Reject {
                attempt_id,
                request_sha256,
                rejection,
                ..
            } => {
                let terminal_binding_matches =
                    rejection.terminal_receipt.as_ref().is_some_and(|receipt| {
                        receipt.attempt_id == self.attempt_id
                            && receipt.request_sha256 == self.request_sha256
                    });
                let abort_binding_matches = rejection.terminal_receipt.is_none()
                    && rejection.terminal_ack_required
                    && self.terminal_disposition
                        == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
                attempt_id == &self.attempt_id
                    && request_sha256 == &self.request_sha256
                    && (terminal_binding_matches || abort_binding_matches)
            }
            _ => false,
        };
        if !binding_matches {
            return Err("terminal outbox response is not bound to the attempt".to_owned());
        }
        let response_json = serde_json::to_string(response).map_err(|error| error.to_string())?;
        if response_json.len() > memcordon_core::WINDOWS_MAX_FRAME_BYTES / 2 {
            return Err("terminal outbox response exceeds the bounded frame size".to_owned());
        }
        self.terminal_response_json = Some(response_json);
        self.store()
    }

    pub fn acknowledge_terminal_response(&mut self) -> Result<(), String> {
        if self.terminal_response_json.is_none() {
            return Err("attempt has no durable terminal outbox to acknowledge".to_owned());
        }
        remove_guardian_receipt(&self.attempt_id)?;
        fs::remove_file(record_path(&self.attempt_id)?).map_err(|error| error.to_string())
    }

    pub fn terminal_retired_receipt(
        &self,
        nonce: &str,
    ) -> Result<memcordon_core::WindowsTerminalRetiredV1, String> {
        let response_json = self
            .terminal_response_json
            .as_ref()
            .ok_or_else(|| "attempt has no durable terminal outbox".to_owned())?;
        let disposition = self
            .terminal_disposition
            .ok_or_else(|| "attempt terminal disposition is absent".to_owned())?;
        Ok(memcordon_core::WindowsTerminalRetiredV1 {
            schema_version: 1,
            attempt_id: self.attempt_id.clone(),
            nonce: nonce.to_owned(),
            request_sha256: self.request_sha256.clone(),
            terminal_response_sha256: digest(response_json.as_bytes()),
            disposition,
        })
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
        if record.terminal_response_json.is_some() {
            ambiguous.push(format!(
                "{} (unacknowledged durable terminal outbox)",
                path.to_string_lossy()
            ));
            continue;
        }
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
    require_empty_guardian_slot_state()?;
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
    remove_empty_guardian_slot_state()?;
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

fn remove_empty_guardian_slot_state() -> Result<(), String> {
    inspect_guardian_slot_state(true)
}

fn require_empty_guardian_slot_state() -> Result<(), String> {
    inspect_guardian_slot_state(false)
}

fn inspect_guardian_slot_state(remove: bool) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;

    const RESIDUAL_LIMIT: usize = 16;

    let path = package::state_root().join("guardian-slots");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=inspect-guardian-slots path={} error={error}",
                path.display()
            ));
        }
    };
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=inspect-guardian-slots path={} expected=directory actual=reparse",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=inspect-guardian-slots path={} expected=directory actual=non-directory",
            path.display()
        ));
    }

    let mut residuals = Vec::new();
    let mut truncated = false;
    for entry in fs::read_dir(&path).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=enumerate-guardian-slots path={} error={error}",
            path.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=enumerate-guardian-slots path={} error={error}",
                path.display()
            )
        })?;
        if residuals.len() == RESIDUAL_LIMIT {
            truncated = true;
            break;
        }
        let entry_path = entry.path();
        let actual = match fs::symlink_metadata(&entry_path) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                "reparse"
            }
            Ok(metadata) if metadata.is_file() => "file",
            Ok(metadata) if metadata.is_dir() => "directory",
            Ok(_) => "other",
            Err(_) => "unreadable",
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let artifact = guardian_slot_lease_artifact(&name);
        residuals.push(format!(
            "entry={name:?},actual={actual},artifact={artifact}"
        ));
    }
    residuals.sort();
    if !residuals.is_empty() {
        return Err(format!(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=retire-guardian-slots path={} residual_count_at_least={} truncated={truncated} residuals=[{}]",
            path.display(),
            residuals.len(),
            residuals.join("; ")
        ));
    }
    if remove {
        fs::remove_dir(&path).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=remove-guardian-slots path={} error={error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn guardian_slot_lease_artifact(name: &str) -> &'static str {
    let (index, suffix, artifact) = if let Some(index) = name.strip_suffix(".json.new") {
        (index, ".json.new", "GuardianSlotLeaseStaged")
    } else if let Some(index) = name.strip_suffix(".json") {
        (index, ".json", "GuardianSlotLease")
    } else {
        return "Unknown";
    };
    match index.parse::<usize>() {
        Ok(value)
            if value < memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT
                && name == format!("{value:03}{suffix}") =>
        {
            artifact
        }
        _ => "Unknown",
    }
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

/// Restores the fixed runtime skeleton after an authenticated package cleanup
/// was interrupted. This runs only inside the control service, whose service
/// SID carries the authority to create children beneath the sealed root.
pub fn reconcile_attempt_state() -> Result<(), String> {
    recover_detached_replay()?;
    for directory in [
        attempts_root(),
        admissions_root(),
        quarantine_root(),
        guardian_receipts_root(),
        replay_root(),
    ] {
        if !directory.exists() {
            fs::create_dir(&directory).map_err(|error| {
                format!(
                    "MCSEALED-WINDOWS-STATE-RECONCILE: cannot restore {}: {error}",
                    directory.display()
                )
            })?;
        }
    }
    reharden_attempt_state()
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
    for directory in [attempts_root(), quarantine_root(), guardian_receipts_root()] {
        if !directory.exists() {
            return Err(format!(
                "MCSEALED-WINDOWS-STATE-CONVERGENCE: runtime attempt-state directory is absent: {}",
                directory.display()
            ));
        }
        converge_directory_security(&directory, &launcher_sddl, "runtime attempt state")?;
    }
    let replay_path = replay_root();
    if !replay_path.exists() {
        return Err(format!(
            "MCSEALED-WINDOWS-STATE-CONVERGENCE: runtime replay directory is absent: {}",
            replay_path.display()
        ));
    }
    let replay_sddl = super::security::replay_state_sddl()?;
    converge_directory_security(&replay_path, &replay_sddl, "runtime replay state")?;
    let admission_path = admissions_root();
    if !admission_path.exists() {
        return Err(format!(
            "MCSEALED-WINDOWS-STATE-CONVERGENCE: runtime admission directory is absent: {}",
            admission_path.display()
        ));
    }
    let admission_sddl = super::security::admission_state_sddl()?;
    converge_directory_security(&admission_path, &admission_sddl, "runtime admission state")
}

fn converge_directory_security(path: &Path, sddl: &str, phase: &str) -> Result<(), String> {
    let dacl = sddl
        .strip_prefix("O:BA")
        .ok_or_else(|| format!("{phase} policy is missing its fixed owner"))?;
    let expected = super::security::SecurityDescriptor::from_sddl(sddl)?;
    let applied = super::security::SecurityDescriptor::from_sddl(dacl)?;
    expected.converge_path(&applied, path).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-STATE-CONVERGENCE: {phase} at {}: {error}",
            path.display()
        )
    })
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
    terminal_receipt: Option<Box<memcordon_core::WindowsTerminalReceiptV1>>,
) -> Result<memcordon_core::ProviderRejectionEvidence, String> {
    let path = match record_path(attempt_id) {
        Ok(path) => path,
        Err(_) => {
            return Ok(match terminal_receipt {
                Some(terminal) => {
                    posttarget_rejection(code, detail, phase_override, os_code, terminal)
                }
                None => pretarget_rejection(code, detail),
            });
        }
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(match terminal_receipt {
                Some(terminal) => {
                    posttarget_rejection(code, detail, phase_override, os_code, terminal)
                }
                None => pretarget_rejection(code, detail),
            });
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
        terminal_ack_required: record.terminal_disposition.is_some(),
        terminal_receipt,
    })
}

fn posttarget_rejection(
    code: &str,
    detail: String,
    phase: Option<memcordon_core::BoundarySetupPhase>,
    os_code: Option<i32>,
    terminal: Box<memcordon_core::WindowsTerminalReceiptV1>,
) -> memcordon_core::ProviderRejectionEvidence {
    memcordon_core::ProviderRejectionEvidence {
        schema_version: 1,
        code: code.to_owned(),
        phase: phase.unwrap_or(memcordon_core::BoundarySetupPhase::Retirement),
        detail,
        os_code,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety: terminal.restart_safety.clone(),
        terminal_ack_required: true,
        terminal_receipt: Some(terminal),
    }
}

pub fn stage_terminal_response(
    attempt_id: &str,
    response: &memcordon_core::WindowsLauncherResponseV1,
) -> Result<bool, String> {
    let path = record_path(attempt_id)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    record.stage_terminal_response(response)?;
    Ok(true)
}

pub fn pending_terminal_response(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<Option<memcordon_core::WindowsLauncherResponseV1>, String> {
    let path = record_path(attempt_id)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    if record.request_sha256 != request_sha256
        || record.caller_process_identity != *caller_process_identity
        || record.caller_token_sha256 != caller_token_sha256
    {
        return Err(
            "pending terminal replay credentials are not bound to the exact attempt".to_owned(),
        );
    }
    let Some(response_json) = record.terminal_response_json.as_ref() else {
        return Ok(None);
    };
    let response: memcordon_core::WindowsLauncherResponseV1 =
        serde_json::from_str(response_json).map_err(|error| error.to_string())?;
    let binding_matches = match &response {
        memcordon_core::WindowsLauncherResponseV1::Terminal(receipt) => {
            receipt.attempt_id == attempt_id
                && receipt.nonce == nonce
                && receipt.request_sha256 == request_sha256
        }
        memcordon_core::WindowsLauncherResponseV1::Reject {
            attempt_id: response_attempt_id,
            nonce: response_nonce,
            request_sha256: response_request_sha256,
            rejection,
            ..
        } => {
            response_attempt_id == attempt_id
                && response_nonce == nonce
                && response_request_sha256 == request_sha256
                && rejection.terminal_ack_required
        }
        _ => false,
    };
    if !binding_matches {
        return Err("pending terminal response is not bound to the replay request".to_owned());
    }
    Ok(Some(response))
}

pub fn replay_unavailable_evidence(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<memcordon_core::WindowsAttemptRetainedV1, String> {
    let path = record_path(attempt_id)?;
    let record = match fs::read(&path) {
        Ok(bytes) => {
            let record: WindowsAttemptRecordV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            authenticate(&record, attempt_id)?;
            if record.request_sha256 != request_sha256
                || record.caller_process_identity != *caller_process_identity
                || record.caller_token_sha256 != caller_token_sha256
            {
                return Err(
                    "terminal replay credentials are not bound to the retained attempt".to_owned(),
                );
            }
            Some(record)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    let cleanup_complete = record.as_ref().is_some_and(|record| {
        record.state == WindowsAttemptStateV1::Empty
            && record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.cleanup_state.final_handles_closed
    });
    Ok(memcordon_core::WindowsAttemptRetainedV1 {
        schema_version: 1,
        attempt_id: attempt_id.to_owned(),
        nonce: nonce.to_owned(),
        request_sha256: request_sha256.to_owned(),
        relay_phase,
        durable_state: record.as_ref().map(|record| record.state),
        terminal_disposition: record
            .as_ref()
            .and_then(|record| record.terminal_disposition),
        cleanup_complete,
        terminal_replay_available: false,
        authority_retained: true,
        primary_detail: "authenticated durable terminal response is unavailable".to_owned(),
        secondary_failures: Vec::new(),
    })
}

pub fn replay_pending_evidence(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<Option<memcordon_core::WindowsReplayPendingV1>, String> {
    let path = record_path(attempt_id)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    if record.request_sha256 != request_sha256
        || record.caller_process_identity != *caller_process_identity
        || record.caller_token_sha256 != caller_token_sha256
    {
        return Err("terminal replay credentials are not bound to the active attempt".to_owned());
    }
    if record.terminal_response_json.is_some() {
        return Err("terminal replay outbox changed while availability was inspected".to_owned());
    }
    let cleanup_complete = record.state == WindowsAttemptStateV1::Empty
        && record.cleanup_state.termination_requested
        && record.cleanup_state.active_processes_zero
        && record.cleanup_state.guardian_reaped
        && record.cleanup_state.final_handles_closed;
    Ok(Some(memcordon_core::WindowsReplayPendingV1 {
        schema_version: 1,
        attempt_id: attempt_id.to_owned(),
        nonce: nonce.to_owned(),
        request_sha256: request_sha256.to_owned(),
        relay_phase,
        durable_state: record.state,
        cleanup_complete,
        outbox_stage: memcordon_core::WindowsReplayOutboxStageV1::NotStaged,
        detail: "authenticated attempt remains active before durable terminal staging".to_owned(),
    }))
}

pub fn retained_attempt_evidence(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    primary_detail: String,
    secondary_failures: Vec<String>,
) -> Result<memcordon_core::WindowsAttemptRetainedV1, String> {
    let path = record_path(attempt_id)?;
    let record = match fs::read(&path) {
        Ok(bytes) => {
            let record: WindowsAttemptRecordV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            authenticate(&record, attempt_id)?;
            if record.request_sha256 != request_sha256 {
                return Err("retained attempt request digest is not exact".to_owned());
            }
            Some(record)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    let cleanup_complete = record.as_ref().is_some_and(|record| {
        record.state == WindowsAttemptStateV1::Empty
            && record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.cleanup_state.final_handles_closed
    });
    Ok(memcordon_core::WindowsAttemptRetainedV1 {
        schema_version: 1,
        attempt_id: attempt_id.to_owned(),
        nonce: nonce.to_owned(),
        request_sha256: request_sha256.to_owned(),
        relay_phase,
        durable_state: record.as_ref().map(|record| record.state),
        terminal_disposition: record
            .as_ref()
            .and_then(|record| record.terminal_disposition),
        cleanup_complete,
        terminal_replay_available: record
            .as_ref()
            .is_some_and(|record| record.terminal_response_json.is_some()),
        authority_retained: true,
        primary_detail,
        secondary_failures,
    })
}

pub fn terminal_outbox_count() -> Result<u32, String> {
    let mut count = 0_u32;
    let entries = match fs::read_dir(attempts_root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.to_string()),
    };
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let bytes = fs::read(entry.path()).map_err(|error| error.to_string())?;
        let record: WindowsAttemptRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        authenticate(&record, &record.attempt_id)?;
        if record.terminal_response_json.is_some() {
            count = count
                .checked_add(1)
                .ok_or_else(|| "terminal outbox count overflowed".to_owned())?;
        }
    }
    Ok(count)
}

pub fn acknowledge_terminal_response(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
) -> Result<memcordon_core::WindowsTerminalRetiredV1, String> {
    let path = record_path(attempt_id)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("terminal acknowledgment has no retained attempt".to_owned());
        }
        Err(error) => return Err(error.to_string()),
    };
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    if record.request_sha256 != request_sha256 {
        return Err("terminal acknowledgment request digest is not exact".to_owned());
    }
    let receipt = record.terminal_retired_receipt(nonce)?;
    record.acknowledge_terminal_response()?;
    Ok(receipt)
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
        terminal_ack_required: false,
        terminal_receipt: None,
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

pub(crate) struct CreateOnceStagingFile {
    file: fs::File,
    path: PathBuf,
}

impl CreateOnceStagingFile {
    pub(crate) fn create(path: &Path) -> Result<Self, io::Error> {
        use std::os::windows::fs::OpenOptionsExt;

        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_WRITE_ACCESS | DELETE_ACCESS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)?;
        Ok(Self {
            file,
            path: path.to_owned(),
        })
    }

    pub(crate) const fn file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    pub(crate) fn sync_all(&self) -> Result<(), io::Error> {
        self.file.sync_all()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateOncePublicationStage {
    PathValidation,
    DestinationEncoding,
    RenameBufferConstruction,
    SourceNameBeforeRenameReadback,
    SourceNameBeforeRenameParse,
    SourceLeafBeforeRenameVerification,
    SourceIdentityBeforeRename,
    SourceLinkCountBeforeRename,
    SourceLinkCountBeforeRenameVerification,
    Rename,
    FinalNameAfterRenameReadback,
    FinalNameAfterRenameParse,
    SourceIdentityAfterRename,
    FinalLinkCountAfterRename,
    VolumeIdentityVerification,
    FileIdentityVerification,
    FinalLinkCountAfterRenameVerification,
    FinalParentVerification,
    FinalComponentVerification,
    FinalSync,
}

impl CreateOncePublicationStage {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::PathValidation => "path-validation",
            Self::DestinationEncoding => "destination-encoding",
            Self::RenameBufferConstruction => "rename-buffer-construction",
            Self::SourceNameBeforeRenameReadback => "source-name-before-rename-readback",
            Self::SourceNameBeforeRenameParse => "source-name-before-rename-parse",
            Self::SourceLeafBeforeRenameVerification => "source-leaf-before-rename-verification",
            Self::SourceIdentityBeforeRename => "source-identity-before-rename",
            Self::SourceLinkCountBeforeRename => "source-link-count-before-rename",
            Self::SourceLinkCountBeforeRenameVerification => {
                "source-link-count-before-rename-verification"
            }
            Self::Rename => "rename",
            Self::FinalNameAfterRenameReadback => "final-name-after-rename-readback",
            Self::FinalNameAfterRenameParse => "final-name-after-rename-parse",
            Self::SourceIdentityAfterRename => "source-identity-after-rename",
            Self::FinalLinkCountAfterRename => "final-link-count-after-rename",
            Self::VolumeIdentityVerification => "volume-identity-verification",
            Self::FileIdentityVerification => "file-identity-verification",
            Self::FinalLinkCountAfterRenameVerification => {
                "final-link-count-after-rename-verification"
            }
            Self::FinalParentVerification => "final-parent-verification",
            Self::FinalComponentVerification => "final-component-verification",
            Self::FinalSync => "final-sync",
        }
    }

    pub(crate) const fn api(self) -> &'static str {
        match self {
            Self::PathValidation => "Path",
            Self::DestinationEncoding => "OsStrExt::encode_wide",
            Self::RenameBufferConstruction => "FILE_RENAME_INFO",
            Self::SourceNameBeforeRenameReadback | Self::FinalNameAfterRenameReadback => {
                "GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED|VOLUME_NAME_NT)"
            }
            Self::SourceNameBeforeRenameParse | Self::FinalNameAfterRenameParse => {
                "CreateOnceHandleLocation"
            }
            Self::SourceIdentityBeforeRename | Self::SourceIdentityAfterRename => {
                "GetFileInformationByHandleEx(FileIdInfo)"
            }
            Self::SourceLinkCountBeforeRename | Self::FinalLinkCountAfterRename => {
                "GetFileInformationByHandleEx(FileStandardInfo)"
            }
            Self::Rename => "SetFileInformationByHandle(FileRenameInfo)",
            Self::SourceLeafBeforeRenameVerification
            | Self::SourceLinkCountBeforeRenameVerification
            | Self::VolumeIdentityVerification
            | Self::FileIdentityVerification
            | Self::FinalLinkCountAfterRenameVerification
            | Self::FinalParentVerification
            | Self::FinalComponentVerification => "CreateOncePublicationPostcondition",
            Self::FinalSync => "FlushFileBuffers",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreateOnceFileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[derive(Clone, Debug, Default)]
struct CreateOncePublicationEvidence {
    rename_committed: bool,
    observed_source_path: Option<PathBuf>,
    observed_final_path: Option<PathBuf>,
    source_identity: Option<CreateOnceFileIdentity>,
    final_identity: Option<CreateOnceFileIdentity>,
    source_link_count: Option<u32>,
    final_link_count: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct CreateOncePublicationFailure {
    stage: CreateOncePublicationStage,
    source: PathBuf,
    destination: PathBuf,
    requested_access: u32,
    io_error_kind: io::ErrorKind,
    native_code: Option<i32>,
    destination_name_bytes: Option<u32>,
    information_bytes: Option<u32>,
    backing_bytes: Option<u32>,
    rename_committed: bool,
    observed_source_path: Option<PathBuf>,
    observed_final_path: Option<PathBuf>,
    source_identity: Option<CreateOnceFileIdentity>,
    final_identity: Option<CreateOnceFileIdentity>,
    source_link_count: Option<u32>,
    final_link_count: Option<u32>,
    secondary_detail: Option<String>,
    detail: String,
}

impl CreateOncePublicationFailure {
    pub(crate) fn native_code(&self) -> Option<i32> {
        self.native_code
    }

    const fn requested_access() -> u32 {
        GENERIC_WRITE_ACCESS | DELETE_ACCESS
    }

    fn io(
        stage: CreateOncePublicationStage,
        source: &Path,
        destination: &Path,
        layout: Option<&CreateOnceRenameInformation>,
        evidence: &CreateOncePublicationEvidence,
        error: io::Error,
    ) -> Self {
        Self {
            stage,
            source: source.to_owned(),
            destination: destination.to_owned(),
            requested_access: Self::requested_access(),
            io_error_kind: error.kind(),
            native_code: error.raw_os_error(),
            destination_name_bytes: layout.map(|layout| layout.destination_name_bytes),
            information_bytes: layout.map(|layout| layout.information_bytes),
            backing_bytes: layout.map(|layout| layout.backing_bytes),
            rename_committed: evidence.rename_committed,
            observed_source_path: evidence.observed_source_path.clone(),
            observed_final_path: evidence.observed_final_path.clone(),
            source_identity: evidence.source_identity,
            final_identity: evidence.final_identity,
            source_link_count: evidence.source_link_count,
            final_link_count: evidence.final_link_count,
            secondary_detail: None,
            detail: error.to_string(),
        }
    }

    fn semantic(
        stage: CreateOncePublicationStage,
        source: &Path,
        destination: &Path,
        layout: Option<&CreateOnceRenameInformation>,
        evidence: &CreateOncePublicationEvidence,
        detail: impl Into<String>,
    ) -> Self {
        let io_error_kind = match stage {
            CreateOncePublicationStage::PathValidation
            | CreateOncePublicationStage::DestinationEncoding
            | CreateOncePublicationStage::RenameBufferConstruction => io::ErrorKind::InvalidInput,
            _ => io::ErrorKind::InvalidData,
        };
        Self {
            stage,
            source: source.to_owned(),
            destination: destination.to_owned(),
            requested_access: Self::requested_access(),
            io_error_kind,
            native_code: None,
            destination_name_bytes: layout.map(|layout| layout.destination_name_bytes),
            information_bytes: layout.map(|layout| layout.information_bytes),
            backing_bytes: layout.map(|layout| layout.backing_bytes),
            rename_committed: evidence.rename_committed,
            observed_source_path: evidence.observed_source_path.clone(),
            observed_final_path: evidence.observed_final_path.clone(),
            source_identity: evidence.source_identity,
            final_identity: evidence.final_identity,
            source_link_count: evidence.source_link_count,
            final_link_count: evidence.final_link_count,
            secondary_detail: None,
            detail: detail.into(),
        }
    }

    fn with_secondary(mut self, stage: CreateOncePublicationStage, error: io::Error) -> Self {
        self.secondary_detail = Some(format!(
            "stage={} api={} io_kind={:?} native_code={} detail={error}",
            stage.name(),
            stage.api(),
            error.kind(),
            error
                .raw_os_error()
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
        ));
        self
    }

    pub(crate) const fn stage(&self) -> CreateOncePublicationStage {
        self.stage
    }

    pub(crate) const fn kind(&self) -> io::ErrorKind {
        self.io_error_kind
    }

    pub(crate) const fn raw_os_error(&self) -> Option<i32> {
        self.native_code
    }
}

impl std::fmt::Display for CreateOncePublicationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-CREATE-ONCE-PUBLICATION: stage={} api={} staging_path={} final_path={} requested_access=0x{:08x} replace_if_exists=false root_directory=null name_query_flags=FILE_NAME_NORMALIZED|VOLUME_NAME_NT io_kind={:?} native_code={} destination_name_bytes={} information_bytes={} backing_bytes={} rename_committed={} observed_staging_path={} observed_final_path={} source_identity={} final_identity={} source_link_count={} final_link_count={} secondary={} detail={}",
            self.stage.name(),
            self.stage.api(),
            self.source.display(),
            self.destination.display(),
            self.requested_access,
            self.io_error_kind,
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.destination_name_bytes
                .map_or_else(|| "none".to_owned(), |bytes| bytes.to_string()),
            self.information_bytes
                .map_or_else(|| "none".to_owned(), |bytes| bytes.to_string()),
            self.backing_bytes
                .map_or_else(|| "none".to_owned(), |bytes| bytes.to_string()),
            self.rename_committed,
            self.observed_source_path
                .as_deref()
                .map_or_else(|| "none".to_owned(), |path| path.display().to_string()),
            self.observed_final_path
                .as_deref()
                .map_or_else(|| "none".to_owned(), |path| path.display().to_string()),
            self.source_identity
                .map_or_else(|| "none".to_owned(), |identity| format!("{identity:?}"),),
            self.final_identity
                .map_or_else(|| "none".to_owned(), |identity| format!("{identity:?}"),),
            self.source_link_count
                .map_or_else(|| "none".to_owned(), |count| count.to_string()),
            self.final_link_count
                .map_or_else(|| "none".to_owned(), |count| count.to_string()),
            self.secondary_detail.as_deref().unwrap_or("none"),
            self.detail,
        )
    }
}

impl std::error::Error for CreateOncePublicationFailure {}

#[derive(Debug)]
struct CreateOnceRenameInformation {
    words: Vec<usize>,
    destination_name_bytes: u32,
    information_bytes: u32,
    backing_bytes: u32,
}

impl CreateOnceRenameInformation {
    fn new(source: &Path, destination_path: &Path) -> Result<Self, CreateOncePublicationFailure> {
        use std::os::windows::ffi::OsStrExt;

        let evidence = CreateOncePublicationEvidence::default();
        let destination = destination_path
            .as_os_str()
            .encode_wide()
            .collect::<Vec<_>>();
        if destination.is_empty() || destination.contains(&0) {
            return Err(CreateOncePublicationFailure::semantic(
                CreateOncePublicationStage::DestinationEncoding,
                source,
                destination_path,
                None,
                &evidence,
                "create-once destination is empty or contains an embedded NUL",
            ));
        }
        let destination_name_bytes = destination
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::DestinationEncoding,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once destination length is not representable",
                )
            })?;
        let prefix_bytes = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let terminated_tail_bytes = destination
            .len()
            .checked_add(1)
            .and_then(|units| units.checked_mul(std::mem::size_of::<u16>()))
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::RenameBufferConstruction,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once terminated destination length overflowed",
                )
            })?;
        let meaningful_bytes = prefix_bytes
            .checked_add(terminated_tail_bytes)
            .map(|bytes| bytes.max(std::mem::size_of::<FILE_RENAME_INFO>()))
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::RenameBufferConstruction,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once rename information length overflowed",
                )
            })?;
        let aligned_words = meaningful_bytes
            .checked_add(std::mem::size_of::<usize>() - 1)
            .map(|value| value / std::mem::size_of::<usize>())
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::RenameBufferConstruction,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once aligned rename information length overflowed",
                )
            })?;
        let backing_bytes = aligned_words
            .checked_mul(std::mem::size_of::<usize>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::RenameBufferConstruction,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once aligned rename information is not representable",
                )
            })?;
        let information_bytes = u32::try_from(meaningful_bytes).map_err(|_| {
            CreateOncePublicationFailure::semantic(
                CreateOncePublicationStage::RenameBufferConstruction,
                source,
                destination_path,
                None,
                &evidence,
                "create-once rename information is not representable",
            )
        })?;
        let mut layout = Self {
            words: vec![0_usize; aligned_words],
            destination_name_bytes,
            information_bytes,
            backing_bytes,
        };
        let rename = layout.words.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: the native-word allocation is fully zero initialized and
        // covers the declared structure, the complete destination, one
        // explicit UTF-16 NUL, and native alignment padding.
        unsafe {
            (*rename).Anonymous.ReplaceIfExists = false;
            (*rename).RootDirectory = ptr::null_mut();
            (*rename).FileNameLength = destination_name_bytes;
            let filename = ptr::addr_of_mut!((*rename).FileName).cast::<u16>();
            ptr::copy_nonoverlapping(destination.as_ptr(), filename, destination.len());
            *filename.add(destination.len()) = 0;
        }
        Ok(layout)
    }

    fn as_mut_ptr(&mut self) -> *mut FILE_RENAME_INFO {
        self.words.as_mut_ptr().cast()
    }
}

#[derive(Debug)]
struct CreateOncePublicationObservation {
    source_path: PathBuf,
    final_path: PathBuf,
    identity_before: CreateOnceFileIdentity,
    identity_after: CreateOnceFileIdentity,
    source_link_count: u32,
    final_link_count: u32,
    destination_name_bytes: u32,
    information_bytes: u32,
    backing_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CreateOnceHandleLocation {
    path: PathBuf,
    parent_units: Vec<u16>,
    leaf_units: Vec<u16>,
}

impl CreateOnceHandleLocation {
    fn from_normalized_nt_path(path: PathBuf) -> Result<Self, &'static str> {
        use std::os::windows::ffi::OsStrExt;

        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if units.is_empty() || units.contains(&0) {
            return Err("normalized NT handle path is empty or contains an embedded NUL");
        }
        let separator = units
            .iter()
            .rposition(|unit| *unit == u16::from(b'\\'))
            .ok_or("normalized NT handle path has no parent separator")?;
        if separator == 0 || separator + 1 >= units.len() {
            return Err("normalized NT handle path has no complete parent and leaf");
        }
        let parent_units = units[..separator].to_vec();
        let leaf_units = units[separator + 1..].to_vec();
        if is_dot_component(&leaf_units) {
            return Err("normalized NT handle path has a dot leaf");
        }
        Ok(Self {
            path,
            parent_units,
            leaf_units,
        })
    }
}

fn create_once_requested_leaf(path: &Path) -> Result<Vec<u16>, &'static str> {
    use std::os::windows::ffi::OsStrExt;

    let leaf = path
        .file_name()
        .ok_or("create-once path has no final component")?
        .encode_wide()
        .collect::<Vec<_>>();
    if leaf.is_empty()
        || leaf.contains(&0)
        || leaf
            .iter()
            .any(|unit| *unit == u16::from(b'\\') || *unit == u16::from(b'/'))
        || is_dot_component(&leaf)
    {
        return Err("create-once path has an invalid final component");
    }
    Ok(leaf)
}

fn is_dot_component(units: &[u16]) -> bool {
    units == [u16::from(b'.')] || units == [u16::from(b'.'), u16::from(b'.')]
}

pub(crate) fn publish_create_once_atomically(
    source: CreateOnceStagingFile,
    destination: &Path,
) -> Result<(), CreateOncePublicationFailure> {
    publish_create_once_atomically_observed(source, destination).map(|_| ())
}

fn publish_create_once_atomically_observed(
    source: CreateOnceStagingFile,
    destination: &Path,
) -> Result<CreateOncePublicationObservation, CreateOncePublicationFailure> {
    use std::os::windows::io::AsRawHandle;

    let mut evidence = CreateOncePublicationEvidence::default();
    if source.path.parent() != destination.parent() {
        return Err(CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::PathValidation,
            &source.path,
            destination,
            None,
            &evidence,
            "create-once source and destination must have the same parent",
        ));
    }
    if !source.path.is_absolute() || !destination.is_absolute() {
        return Err(CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::PathValidation,
            &source.path,
            destination,
            None,
            &evidence,
            "create-once source and destination must be absolute paths",
        ));
    }
    let mut information = CreateOnceRenameInformation::new(&source.path, destination)?;
    let expected_source_leaf = create_once_requested_leaf(&source.path).map_err(|detail| {
        CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::PathValidation,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            detail,
        )
    })?;
    let expected_final_leaf = create_once_requested_leaf(destination).map_err(|detail| {
        CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::DestinationEncoding,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            detail,
        )
    })?;
    let source_path =
        create_once_normalized_nt_path(source.file.as_raw_handle() as _).map_err(|error| {
            CreateOncePublicationFailure::io(
                CreateOncePublicationStage::SourceNameBeforeRenameReadback,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                error,
            )
        })?;
    evidence.observed_source_path = Some(source_path.clone());
    let source_location =
        CreateOnceHandleLocation::from_normalized_nt_path(source_path).map_err(|detail| {
            CreateOncePublicationFailure::semantic(
                CreateOncePublicationStage::SourceNameBeforeRenameParse,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                detail,
            )
        })?;
    if source_location.leaf_units != expected_source_leaf {
        return Err(CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::SourceLeafBeforeRenameVerification,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            "retained staging handle did not resolve to the exact staging leaf",
        ));
    }
    let identity_before =
        create_once_file_identity(source.file.as_raw_handle() as _).map_err(|error| {
            CreateOncePublicationFailure::io(
                CreateOncePublicationStage::SourceIdentityBeforeRename,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                error,
            )
        })?;
    evidence.source_identity = Some(identity_before);
    let source_link_count =
        create_once_link_count(source.file.as_raw_handle() as _).map_err(|error| {
            CreateOncePublicationFailure::io(
                CreateOncePublicationStage::SourceLinkCountBeforeRename,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                error,
            )
        })?;
    evidence.source_link_count = Some(source_link_count);
    if source_link_count != 1 {
        return Err(CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::SourceLinkCountBeforeRenameVerification,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            format!(
                "retained staging file must have exactly one link before rename; observed {source_link_count}"
            ),
        ));
    }
    let rename = information.as_mut_ptr();
    // SAFETY: the owned CREATE_NEW handle remains live for this synchronous
    // no-replace rename and carries the one-use DELETE access requested when
    // the staging leaf was created. The fully initialized aligned buffer is
    // live and its advertised size includes the explicit NUL and padding.
    if unsafe {
        SetFileInformationByHandle(
            source.file.as_raw_handle() as _,
            FileRenameInfo,
            rename.cast(),
            information.backing_bytes,
        )
    } == 0
    {
        return Err(CreateOncePublicationFailure::io(
            CreateOncePublicationStage::Rename,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            io::Error::last_os_error(),
        ));
    }
    evidence.rename_committed = true;

    // Collect all bounded post-rename evidence before selecting the primary
    // semantic result. No path is reopened: every observation comes from the
    // same authoritative handle that performed the rename.
    let final_path_result = create_once_normalized_nt_path(source.file.as_raw_handle() as _);
    if let Ok(path) = &final_path_result {
        evidence.observed_final_path = Some(path.clone());
    }
    let identity_after_result = create_once_file_identity(source.file.as_raw_handle() as _);
    if let Ok(identity) = &identity_after_result {
        evidence.final_identity = Some(*identity);
    }
    let final_link_count_result = create_once_link_count(source.file.as_raw_handle() as _);
    if let Ok(link_count) = &final_link_count_result {
        evidence.final_link_count = Some(*link_count);
    }

    let verification = verify_create_once_postcondition(
        &source.path,
        destination,
        &information,
        &evidence,
        &source_location,
        &expected_final_leaf,
        identity_before,
        final_path_result,
        identity_after_result,
        final_link_count_result,
    );
    // Once SetFileInformationByHandle commits, always attempt the final
    // durability barrier. A semantic/native proof failure remains primary;
    // a simultaneous flush failure is retained as secondary evidence.
    let final_sync = source.file.sync_all();
    let (final_location, identity_after, final_link_count) = match (verification, final_sync) {
        (Ok(observation), Ok(())) => observation,
        (Ok(_), Err(error)) => {
            return Err(CreateOncePublicationFailure::io(
                CreateOncePublicationStage::FinalSync,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                error,
            ));
        }
        (Err(failure), Ok(())) => return Err(failure),
        (Err(failure), Err(error)) => {
            return Err(failure.with_secondary(CreateOncePublicationStage::FinalSync, error));
        }
    };
    Ok(CreateOncePublicationObservation {
        source_path: source_location.path,
        final_path: final_location.path,
        identity_before,
        identity_after,
        source_link_count,
        final_link_count,
        destination_name_bytes: information.destination_name_bytes,
        information_bytes: information.information_bytes,
        backing_bytes: information.backing_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_create_once_postcondition(
    source: &Path,
    destination: &Path,
    information: &CreateOnceRenameInformation,
    evidence: &CreateOncePublicationEvidence,
    source_location: &CreateOnceHandleLocation,
    expected_final_leaf: &[u16],
    identity_before: CreateOnceFileIdentity,
    final_path_result: Result<PathBuf, io::Error>,
    identity_after_result: Result<CreateOnceFileIdentity, io::Error>,
    final_link_count_result: Result<u32, io::Error>,
) -> Result<(CreateOnceHandleLocation, CreateOnceFileIdentity, u32), CreateOncePublicationFailure> {
    let final_path = final_path_result.map_err(|error| {
        CreateOncePublicationFailure::io(
            CreateOncePublicationStage::FinalNameAfterRenameReadback,
            source,
            destination,
            Some(information),
            evidence,
            error,
        )
    })?;
    let final_location =
        CreateOnceHandleLocation::from_normalized_nt_path(final_path).map_err(|detail| {
            CreateOncePublicationFailure::semantic(
                CreateOncePublicationStage::FinalNameAfterRenameParse,
                source,
                destination,
                Some(information),
                evidence,
                detail,
            )
        })?;
    let identity_after = identity_after_result.map_err(|error| {
        CreateOncePublicationFailure::io(
            CreateOncePublicationStage::SourceIdentityAfterRename,
            source,
            destination,
            Some(information),
            evidence,
            error,
        )
    })?;
    let final_link_count = final_link_count_result.map_err(|error| {
        CreateOncePublicationFailure::io(
            CreateOncePublicationStage::FinalLinkCountAfterRename,
            source,
            destination,
            Some(information),
            evidence,
            error,
        )
    })?;
    verify_create_once_transition(
        source_location,
        &final_location,
        expected_final_leaf,
        identity_before,
        identity_after,
        final_link_count,
    )
    .map_err(|(stage, detail)| {
        CreateOncePublicationFailure::semantic(
            stage,
            source,
            destination,
            Some(information),
            evidence,
            detail,
        )
    })?;
    Ok((final_location, identity_after, final_link_count))
}

fn verify_create_once_transition(
    source_location: &CreateOnceHandleLocation,
    final_location: &CreateOnceHandleLocation,
    expected_final_leaf: &[u16],
    identity_before: CreateOnceFileIdentity,
    identity_after: CreateOnceFileIdentity,
    final_link_count: u32,
) -> Result<(), (CreateOncePublicationStage, String)> {
    if identity_before.volume_serial != identity_after.volume_serial {
        return Err((
            CreateOncePublicationStage::VolumeIdentityVerification,
            format!(
                "retained staging file volume changed across rename: before={} after={}",
                identity_before.volume_serial, identity_after.volume_serial
            ),
        ));
    }
    if identity_before.file_id != identity_after.file_id {
        return Err((
            CreateOncePublicationStage::FileIdentityVerification,
            format!(
                "retained staging file 128-bit identity changed across rename: before={identity_before:?} after={identity_after:?}"
            ),
        ));
    }
    if final_link_count != 1 {
        return Err((
            CreateOncePublicationStage::FinalLinkCountAfterRenameVerification,
            format!(
                "retained final file must have exactly one link after rename; observed {final_link_count}"
            ),
        ));
    }
    if source_location.parent_units != final_location.parent_units {
        return Err((
            CreateOncePublicationStage::FinalParentVerification,
            "retained handle moved outside its canonical pre-rename parent".to_owned(),
        ));
    }
    if final_location.leaf_units != expected_final_leaf {
        return Err((
            CreateOncePublicationStage::FinalComponentVerification,
            "retained handle did not resolve to the exact requested final component".to_owned(),
        ));
    }
    Ok(())
}

fn create_once_file_identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<CreateOnceFileIdentity, io::Error> {
    // SAFETY: zero is a valid initial state for this output-only POD.
    let mut information = unsafe { std::mem::zeroed::<FILE_ID_INFO>() };
    // SAFETY: handle is the live retained staging/final file and information
    // is writable for the documented structure size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FILE_ID_INFO size is not representable",
                )
            })?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(CreateOnceFileIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

fn create_once_link_count(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<u32, io::Error> {
    // SAFETY: zero is a valid initial state for this output-only POD.
    let mut information = unsafe { std::mem::zeroed::<FILE_STANDARD_INFO>() };
    // SAFETY: handle is the live retained staging/final file and information
    // is writable for the documented structure size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FILE_STANDARD_INFO size is not representable",
                )
            })?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(information.NumberOfLinks)
}

fn create_once_normalized_nt_path(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<PathBuf, io::Error> {
    use std::os::windows::ffi::OsStringExt;

    const NAME_QUERY_FLAGS: u32 = FILE_NAME_NORMALIZED | VOLUME_NAME_NT;
    // SAFETY: the sizing form writes no buffer and returns the required UTF-16
    // units, including terminator storage when the supplied buffer is short.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, NAME_QUERY_FLAGS) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let capacity = usize::try_from(required)
        .ok()
        .and_then(|units| units.checked_add(1))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "create-once final path length is not representable",
            )
        })?;
    let capacity_u32 = u32::try_from(capacity).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "create-once final path buffer is not representable",
        )
    })?;
    let mut buffer = vec![0_u16; capacity];
    // SAFETY: buffer is writable for capacity_u32 UTF-16 units and handle is
    // the live authoritative file object retained across rename.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), capacity_u32, NAME_QUERY_FLAGS)
    };
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    if written >= capacity_u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "normalized NT handle path grew during readback: capacity={capacity_u32} required={written}"
            ),
        ));
    }
    buffer.truncate(written as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct CreateOncePublicationObservationForTest {
    pub(crate) source_path: PathBuf,
    pub(crate) final_path: PathBuf,
    pub(crate) identity_unchanged: bool,
    pub(crate) source_link_count: u32,
    pub(crate) final_link_count: u32,
    pub(crate) destination_name_bytes: u32,
    pub(crate) information_bytes: u32,
    pub(crate) backing_bytes: u32,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct CreateOnceRenameLayoutForTest {
    pub(crate) destination_name_bytes: u32,
    pub(crate) information_bytes: u32,
    pub(crate) backing_bytes: u32,
}

#[cfg(test)]
pub(crate) fn create_once_rename_layout_for_test(
    source: &Path,
    destination: &Path,
) -> Result<CreateOnceRenameLayoutForTest, CreateOncePublicationFailure> {
    CreateOnceRenameInformation::new(source, destination).map(|layout| {
        CreateOnceRenameLayoutForTest {
            destination_name_bytes: layout.destination_name_bytes,
            information_bytes: layout.information_bytes,
            backing_bytes: layout.backing_bytes,
        }
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_create_once_transition_for_test(
    observed_source: &Path,
    observed_final: &Path,
    requested_source: &Path,
    requested_final: &Path,
    volume_before: u64,
    volume_after: u64,
    file_id_before: [u8; 16],
    file_id_after: [u8; 16],
    source_link_count: u32,
    final_link_count: u32,
) -> Result<(), CreateOncePublicationStage> {
    let source_location =
        CreateOnceHandleLocation::from_normalized_nt_path(observed_source.to_owned())
            .map_err(|_| CreateOncePublicationStage::SourceNameBeforeRenameParse)?;
    let final_location =
        CreateOnceHandleLocation::from_normalized_nt_path(observed_final.to_owned())
            .map_err(|_| CreateOncePublicationStage::FinalNameAfterRenameParse)?;
    let expected_source_leaf = create_once_requested_leaf(requested_source)
        .map_err(|_| CreateOncePublicationStage::PathValidation)?;
    let expected_final_leaf = create_once_requested_leaf(requested_final)
        .map_err(|_| CreateOncePublicationStage::DestinationEncoding)?;
    if source_location.leaf_units.as_slice() != expected_source_leaf.as_slice() {
        return Err(CreateOncePublicationStage::SourceLeafBeforeRenameVerification);
    }
    if !matches!(source_link_count, 1) {
        return Err(CreateOncePublicationStage::SourceLinkCountBeforeRenameVerification);
    }
    verify_create_once_transition(
        &source_location,
        &final_location,
        &expected_final_leaf,
        CreateOnceFileIdentity {
            volume_serial: volume_before,
            file_id: file_id_before,
        },
        CreateOnceFileIdentity {
            volume_serial: volume_after,
            file_id: file_id_after,
        },
        final_link_count,
    )
    .map_err(|(stage, _)| stage)
}

#[cfg(test)]
pub(crate) fn publish_create_once_atomically_for_test(
    source: CreateOnceStagingFile,
    destination: &Path,
) -> Result<CreateOncePublicationObservationForTest, CreateOncePublicationFailure> {
    publish_create_once_atomically_observed(source, destination).map(|observation| {
        CreateOncePublicationObservationForTest {
            source_path: observation.source_path,
            final_path: observation.final_path,
            identity_unchanged: observation.identity_before == observation.identity_after,
            source_link_count: observation.source_link_count,
            final_link_count: observation.final_link_count,
            destination_name_bytes: observation.destination_name_bytes,
            information_bytes: observation.information_bytes,
            backing_bytes: observation.backing_bytes,
        }
    })
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
