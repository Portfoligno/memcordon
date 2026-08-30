use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use memcordon_core::{WINDOWS_GUARDIAN_PIPE_PREFIX, WINDOWS_GUARDIAN_SLOT_COUNT};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess, SetEvent};

use super::pipe::OwnedHandle;

const STARTUP_ARGUMENTS: u32 = 0x4d43_0401;
const STARTUP_TOKEN_CERTIFICATE: u32 = 0x4d43_0402;
const STARTUP_PROCESS_PROTECTION: u32 = 0x4d43_0403;
const STARTUP_PIPE_CONNECT: u32 = 0x4d43_0404;
const STARTUP_RUNNING: u32 = 0x4d43_0405;
pub(crate) const SERVICE_BINDING_SCHEMA_VERSION: u32 = 1;

pub(crate) const fn startup_diagnostic_from_exit(exit: u32) -> Option<&'static str> {
    match exit {
        STARTUP_ARGUMENTS => Some("arguments"),
        STARTUP_TOKEN_CERTIFICATE => Some("token-certificate"),
        STARTUP_PROCESS_PROTECTION => Some("process-protection"),
        STARTUP_PIPE_CONNECT => Some("pipe-connect"),
        STARTUP_RUNNING => Some("running-publication"),
        _ => None,
    }
}

static CONFIGURED_SLOT: OnceLock<String> = OnceLock::new();

pub fn run(slot: &OsString) -> Result<(), String> {
    let slot = slot
        .to_str()
        .ok_or_else(|| "guardian slot service name is not Unicode".to_owned())?;
    let index = slot_index(slot)?;
    if super::security::guardian_slot_name(index)? != slot {
        return Err("guardian slot service name is not canonical".to_owned());
    }
    CONFIGURED_SLOT
        .set(slot.to_owned())
        .map_err(|_| "guardian slot service dispatch was initialized twice".to_owned())?;
    super::service::dispatch(
        slot,
        u8::try_from(4 + index).expect("slot role fits"),
        service_main,
    )
}

unsafe extern "system" fn service_main(count: u32, arguments: *mut *mut u16) {
    let slot = CONFIGURED_SLOT
        .get()
        .expect("guardian slot set before SCM dispatch");
    if let Err(error) = unsafe { super::service::announce_starting(slot) } {
        eprintln!("{error}");
        return;
    }
    let result = (|| -> Result<(), (u32, String)> {
        let arguments = unsafe { decode_service_arguments(count, arguments) }
            .map_err(|error| (STARTUP_ARGUMENTS, error))?;
        let binding =
            ServiceBinding::parse(slot, &arguments).map_err(|error| (STARTUP_ARGUMENTS, error))?;
        certify_slot_token(slot).map_err(|error| (STARTUP_TOKEN_CERTIFICATE, error))?;
        super::security::converge_current_service_token_peer_query(slot)
            .map_err(|error| (STARTUP_TOKEN_CERTIFICATE, error.to_string()))?;
        super::security::protect_current_guardian()
            .map_err(|error| (STARTUP_PROCESS_PROTECTION, error.to_string()))?;
        let (standard_handles, desktop) = super::process::prepare_service_guardian_context()
            .map_err(|error| (STARTUP_PROCESS_PROTECTION, error))?;
        let connection = super::pipe::connect(&binding.pipe_name)
            .map_err(|error| (STARTUP_PIPE_CONNECT, error))?;
        let mut server_pid = 0_u32;
        // SAFETY: connection is a live connected client pipe and PID storage is writable.
        if unsafe { GetNamedPipeServerProcessId(connection.raw(), &raw mut server_pid) } == 0
            || server_pid
                != binding
                    .launcher_pid
                    .parse::<u32>()
                    .expect("validated launcher PID")
        {
            return Err((
                STARTUP_PIPE_CONNECT,
                "guardian slot pipe server does not match the bound launcher".to_owned(),
            ));
        }
        let connection_read = super::process::duplicate_owned(connection.raw())
            .map_err(|error| (STARTUP_PIPE_CONNECT, error))?;
        let stop_event = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })
            .map_err(|error| (STARTUP_PROCESS_PROTECTION, error))?;
        let stop_for_watcher = super::process::duplicate_owned(stop_event.raw())
            .map_err(|error| (STARTUP_PROCESS_PROTECTION, error))?;
        super::service::announce_running().map_err(|error| (STARTUP_RUNNING, error))?;

        let cancelled = Arc::new(AtomicBool::new(false));
        let watcher_cancelled = Arc::clone(&cancelled);
        let watcher = std::thread::spawn(move || {
            while !watcher_cancelled.load(Ordering::SeqCst) {
                if super::service::stop_requested() {
                    // SAFETY: watcher owns a live duplicate of the local event.
                    unsafe { SetEvent(stop_for_watcher.raw()) };
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });

        let guardian_arguments = binding.guardian_arguments(
            connection_read.raw(),
            connection.raw(),
            standard_handles,
            &desktop,
            stop_event.raw(),
        );
        // guardian::run adopts and closes these exact local handles.
        std::mem::forget(connection_read);
        std::mem::forget(connection);
        std::mem::forget(stop_event);
        let guardian_result = super::guardian::run(&guardian_arguments);
        cancelled.store(true, Ordering::SeqCst);
        let _ = watcher.join();
        guardian_result.map_err(|error| (error.exit_code(), error.to_string()))
    })();
    match result {
        Ok(()) => super::service::announce_stopped(0),
        Err((code, error)) => {
            eprintln!("MCSEALED-WINDOWS-GUARDIAN-SERVICE: slot={slot} {error}");
            super::service::announce_startup_failed(code);
        }
    }
}

struct ServiceBinding {
    slot: String,
    attempt_id: String,
    nonce: String,
    pipe_name: String,
    launcher_pid: String,
    launcher_creation_time: String,
    cleanup_deadline: String,
    readiness_delay: String,
}

impl ServiceBinding {
    fn parse(slot: &str, arguments: &[OsString]) -> Result<Self, String> {
        let [
            service_name,
            schema,
            slot_argument,
            attempt_id,
            nonce,
            pipe_name,
            launcher_pid,
            launcher_creation_time,
            cleanup_deadline,
            readiness_delay,
        ] = arguments
        else {
            return Err("guardian slot start argument count differs".to_owned());
        };
        let text = |value: &OsString| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "guardian slot argument is not Unicode".to_owned())
        };
        if text(service_name)? != slot
            || text(schema)? != SERVICE_BINDING_SCHEMA_VERSION.to_string()
            || text(slot_argument)? != slot
        {
            return Err("guardian slot static and dynamic identity differ".to_owned());
        }
        let attempt_id = text(attempt_id)?;
        let nonce = text(nonce)?;
        super::record::validate_attempt_id(&attempt_id)?;
        super::record::validate_attempt_id(&nonce)?;
        let pipe_name = text(pipe_name)?;
        if pipe_name != format!("{WINDOWS_GUARDIAN_PIPE_PREFIX}{nonce}") {
            return Err("guardian slot pipe name is not nonce-derived".to_owned());
        }
        let launcher_pid = text(launcher_pid)?;
        launcher_pid
            .parse::<u32>()
            .map_err(|_| "guardian slot launcher PID is invalid")?;
        let launcher_creation_time = text(launcher_creation_time)?;
        launcher_creation_time
            .parse::<u64>()
            .map_err(|_| "guardian slot launcher creation time is invalid")?;
        let cleanup_deadline = text(cleanup_deadline)?;
        cleanup_deadline
            .parse::<u64>()
            .map_err(|_| "guardian slot cleanup deadline is invalid")?;
        let readiness_delay = text(readiness_delay)?;
        readiness_delay
            .parse::<u64>()
            .map_err(|_| "guardian slot readiness delay is invalid")?;
        Ok(Self {
            slot: slot.to_owned(),
            attempt_id,
            nonce,
            pipe_name,
            launcher_pid,
            launcher_creation_time,
            cleanup_deadline,
            readiness_delay,
        })
    }

    fn guardian_arguments(
        &self,
        bootstrap_read: windows_sys::Win32::Foundation::HANDLE,
        bootstrap_write: windows_sys::Win32::Foundation::HANDLE,
        standard: [windows_sys::Win32::Foundation::HANDLE; 3],
        desktop: &str,
        stop_event: windows_sys::Win32::Foundation::HANDLE,
    ) -> Vec<OsString> {
        [
            (bootstrap_read as usize as u64).to_string(),
            (bootstrap_write as usize as u64).to_string(),
            (standard[0] as usize as u64).to_string(),
            (standard[1] as usize as u64).to_string(),
            (standard[2] as usize as u64).to_string(),
            self.slot.clone(),
            desktop.to_owned(),
            self.attempt_id.clone(),
            self.nonce.clone(),
            self.cleanup_deadline.clone(),
            self.readiness_delay.clone(),
            self.launcher_pid.clone(),
            self.launcher_creation_time.clone(),
            (stop_event as usize as u64).to_string(),
        ]
        .map(OsString::from)
        .to_vec()
    }
}

fn certify_slot_token(slot: &str) -> Result<(), String> {
    // SAFETY: current process pseudo-handle is live.
    let process = unsafe { GetCurrentProcess() };
    super::process::verify_image_path(process, &super::package::installed_binary())?;
    let token = super::token::process_token(process)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18" {
        return Err("guardian slot is not LocalSystem".to_owned());
    }
    let slot_sid = super::security::service_sid(slot)?;
    if !super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &slot_sid)?
        || !super::token::token_has_restricting_sid(token.raw(), &slot_sid)?
    {
        return Err("guardian slot restricted token certificate mismatch".to_owned());
    }
    Ok(())
}

fn slot_index(slot: &str) -> Result<usize, String> {
    let suffix = slot
        .strip_prefix(memcordon_core::WINDOWS_GUARDIAN_SERVICE_PREFIX)
        .ok_or_else(|| "guardian slot prefix differs".to_owned())?;
    let index = suffix
        .parse::<usize>()
        .map_err(|_| "guardian slot index is invalid".to_owned())?;
    if index >= WINDOWS_GUARDIAN_SLOT_COUNT {
        Err("guardian slot index exceeds pool".to_owned())
    } else {
        Ok(index)
    }
}

unsafe fn decode_service_arguments(
    count: u32,
    arguments: *mut *mut u16,
) -> Result<Vec<OsString>, String> {
    if arguments.is_null() || count > 32 {
        return Err("guardian slot SCM argument vector is invalid".to_owned());
    }
    let mut decoded = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        // SAFETY: SCM supplies count pointers to NUL-terminated UTF-16 strings.
        let pointer = unsafe { *arguments.add(index) };
        if pointer.is_null() {
            return Err("guardian slot SCM argument is null".to_owned());
        }
        let mut length = 0_usize;
        while length < 32 * 1024 {
            // SAFETY: bounded scan of the SCM-owned NUL-terminated string.
            if unsafe { *pointer.add(length) } == 0 {
                break;
            }
            length += 1;
        }
        if length == 32 * 1024 {
            return Err("guardian slot SCM argument is unterminated".to_owned());
        }
        // SAFETY: the bounded scan established this exact live UTF-16 slice.
        decoded.push(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(pointer, length)
        }));
    }
    Ok(decoded)
}

pub(crate) fn certify_slot_contract_negatives() -> Result<(), String> {
    let nonce = "11".repeat(32);
    for index in 0..WINDOWS_GUARDIAN_SLOT_COUNT {
        let name = super::security::guardian_slot_name(index)?;
        if slot_index(&name)? != index {
            return Err("guardian slot identity round trip differs".to_owned());
        }
        let pipe_sddl = super::security::guardian_slot_pipe_sddl(index)?;
        if !pipe_sddl.contains(&super::security::service_sid(&name)?)
            || !super::security::guardian_slot_service_sddl(&name)?.contains("0x00020035")
        {
            return Err("guardian slot ACL contract differs".to_owned());
        }
    }
    if slot_index("MemCordonSealedGuardian-999").is_ok()
        || slot_index("MemCordonSealedLauncher").is_ok()
    {
        return Err("guardian slot invalid identity was accepted".to_owned());
    }
    let name = super::security::guardian_slot_name(0)?;
    let attempt_id = "22".repeat(32);
    let valid = [
        name.clone(),
        SERVICE_BINDING_SCHEMA_VERSION.to_string(),
        name.clone(),
        attempt_id,
        nonce.clone(),
        format!("{WINDOWS_GUARDIAN_PIPE_PREFIX}{nonce}"),
        "42".to_owned(),
        "123456789".to_owned(),
        "30000".to_owned(),
        "0".to_owned(),
    ]
    .map(OsString::from);
    ServiceBinding::parse(&name, &valid)?;
    for index in [1_usize, 2, 4, 5] {
        let mut mutant = valid.clone();
        mutant[index] = OsString::from("mutated");
        if ServiceBinding::parse(&name, &mutant).is_ok() {
            return Err(format!("guardian slot binding mutant {index} was accepted"));
        }
    }
    let mut extra = valid.to_vec();
    extra.push(OsString::from("unexpected"));
    if ServiceBinding::parse(&name, &extra).is_ok() {
        return Err("guardian slot accepted an extra field".to_owned());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_service_arguments_for_test(
    slot: &str,
    arguments: &[String],
) -> Result<(), String> {
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    ServiceBinding::parse(slot, &arguments).map(|_| ())
}
