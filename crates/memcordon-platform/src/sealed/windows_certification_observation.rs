//! Test-support-only native certification routing. Never enabled by production
//! launches, and never a public product readiness observation.
use memcordon_core::{
    WINDOWS_PUBLIC_PROTOCOL_VERSION, WindowsLaunchRequestV1, WindowsProcessIdentityV1,
    WindowsProviderRequestV3, WindowsSealedFault, WindowsSealedMutant,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, marker::PhantomData, rc::Rc};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsCertificationSelection {
    Fault { fault: WindowsSealedFault },
    Mutant { mutant: WindowsSealedMutant },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCertificationObservation {
    pub selection: WindowsCertificationSelection,
    pub launch: Option<WindowsLaunchRequestV1>,
    pub caller: Option<WindowsProcessIdentityV1>,
    pub attempt_id: Option<String>,
    pub request_sha256: Option<String>,
    pub authenticated_provider_frames: Vec<Vec<u8>>,
    pub capture_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_action: Option<WindowsCertificationFrontendAction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCertificationFrontendAction {
    pub format: String,
    pub revision: u32,
    pub kind: String,
    pub process: WindowsProcessIdentityV1,
    pub target_pid: u32,
    pub target_authorization_observed: bool,
    pub controller_release_observed: bool,
    pub requested_exit_status: Option<u32>,
}

thread_local! { static ACTIVE: RefCell<Option<WindowsCertificationObservation>> = const { RefCell::new(None) }; }
thread_local! { static DESTINATION: RefCell<Option<std::path::PathBuf>> = const { RefCell::new(None) }; }
pub struct WindowsCertificationScope {
    _thread: PhantomData<Rc<()>>,
}
impl WindowsCertificationScope {
    pub fn begin_persisted(
        selection: WindowsCertificationSelection,
        path: &std::path::Path,
    ) -> Result<Self, String> {
        if !path.is_absolute() || path.try_exists().map_err(|error| error.to_string())? {
            return Err(
                "native certification publication must be a fresh absolute owned path".into(),
            );
        }
        let scope = Self::begin(selection)?;
        DESTINATION.with(|destination| *destination.borrow_mut() = Some(path.to_owned()));
        ACTIVE.with(|active| {
            publish(
                active
                    .borrow()
                    .as_ref()
                    .expect("new scope owns observation"),
            )
        })?;
        Ok(scope)
    }
    pub fn begin(selection: WindowsCertificationSelection) -> Result<Self, String> {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if active.is_some() {
                return Err("native certification scope already active".into());
            }
            *active = Some(WindowsCertificationObservation {
                selection,
                launch: None,
                caller: None,
                attempt_id: None,
                request_sha256: None,
                authenticated_provider_frames: Vec::new(),
                capture_failure: None,
                frontend_action: None,
            });
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
    pub fn finish(self) -> Result<WindowsCertificationObservation, String> {
        ACTIVE.with(|active| {
            active
                .borrow_mut()
                .take()
                .ok_or_else(|| "native certification ownership lost".into())
        })
    }
}
impl Drop for WindowsCertificationScope {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.borrow_mut().take();
        });
        DESTINATION.with(|destination| {
            destination.borrow_mut().take();
        });
    }
}

fn publish(observation: &WindowsCertificationObservation) -> Result<(), String> {
    DESTINATION.with(|destination| {
        if let Some(path) = destination.borrow().as_ref() {
            let bytes = serde_json::to_vec(observation).map_err(|error| error.to_string())?;
            if bytes.len() > 32 * 1024 * 1024 {
                return Err("native certification publication exceeds bound".into());
            }
            memcordon_core::write_report_bytes_atomic(path, &bytes)
                .map_err(|error| error.to_string())?;
            if std::fs::read(path).map_err(|error| error.to_string())? != bytes {
                return Err("native certification publication named readback differs".into());
            }
        }
        Ok(())
    })
}

pub(super) fn route(launch: WindowsLaunchRequestV1) -> Result<WindowsProviderRequestV3, String> {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let Some(observation) = active.as_mut() else {
            return Ok(WindowsProviderRequestV3::Launch(launch));
        };
        if observation.launch.is_some() {
            return Err("native certification requires exactly one launch".into());
        }
        let caller = caller_identity()?;
        let digest = hex(Sha256::digest(
            serde_json::to_vec(&launch).map_err(|error| error.to_string())?,
        ));
        let mut identity = Sha256::new();
        identity.update(launch.nonce.as_bytes());
        identity.update(caller.process_id.to_le_bytes());
        identity.update(caller.creation_time_100ns.to_le_bytes());
        identity.update(digest.as_bytes());
        let attempt = hex(identity.finalize());
        observation.launch = Some(launch.clone());
        observation.caller = Some(caller.clone());
        observation.attempt_id = Some(attempt.clone());
        observation.request_sha256 = Some(digest.clone());
        publish(observation)?;
        Ok(match observation.selection {
            WindowsCertificationSelection::Fault { fault } => {
                WindowsProviderRequestV3::CertificationFault {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    fault,
                    attempt_id: attempt,
                    request_sha256: digest,
                    caller_process_identity: caller,
                    launch,
                }
            }
            WindowsCertificationSelection::Mutant { mutant } => {
                WindowsProviderRequestV3::CertificationMutant {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                    mutant,
                    attempt_id: attempt,
                    request_sha256: digest,
                    caller_process_identity: caller,
                    launch,
                }
            }
        })
    })
}

pub(super) fn frame(bytes: &[u8]) {
    ACTIVE.with(|active| {
        if let Some(observation) = active.borrow_mut().as_mut() {
            let total: usize = observation
                .authenticated_provider_frames
                .iter()
                .map(Vec::len)
                .sum();
            if observation.authenticated_provider_frames.len() >= 128
                || total.saturating_add(bytes.len()) > 4 * 1024 * 1024
            {
                observation.capture_failure =
                    Some("native certification frame custody bound exceeded".into());
            } else {
                observation
                    .authenticated_provider_frames
                    .push(bytes.to_vec());
            }
            if let Err(error) = publish(observation) {
                observation.capture_failure = Some(error);
            }
        }
    });
}

pub(super) fn after_target_authorized(target_pid: u32) -> Result<bool, String> {
    use std::{
        io::Read,
        os::windows::ffi::OsStringExt,
        time::{Duration, Instant},
    };
    let selected = ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .and_then(|observation| match observation.selection {
                WindowsCertificationSelection::Fault {
                    fault: WindowsSealedFault::FrontendDisconnectedAfterAuthorization,
                } => Some((
                    false,
                    observation.launch.as_ref()?.command.arguments.clone(),
                )),
                WindowsCertificationSelection::Fault {
                    fault: WindowsSealedFault::FrontendKilledAfterAuthorization,
                } => Some((true, observation.launch.as_ref()?.command.arguments.clone())),
                _ => None,
            })
    });
    let Some((kill, arguments)) = selected else {
        return Ok(false);
    };
    if arguments
        .first()
        .and_then(|arg| String::from_utf16(arg).ok())
        .as_deref()
        != Some("consumer-readiness-windows")
    {
        return Err("frontend fault requires its owned readiness fixture barrier".into());
    }
    let descriptor = std::path::PathBuf::from(std::ffi::OsString::from_wide(
        arguments.get(1).ok_or("frontend descriptor absent")?,
    ));
    let mut bytes = Vec::new();
    std::fs::File::open(descriptor)
        .map_err(|error| error.to_string())?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 64 * 1024 {
        return Err("frontend descriptor exceeds bound".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let descriptor: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if !descriptor
        .get("start_gate")
        .is_some_and(|gate| gate.is_string())
    {
        return Err("frontend controller gate absent".into());
    }
    let transcript = std::path::PathBuf::from(
        descriptor
            .get("transcript")
            .and_then(serde_json::Value::as_str)
            .ok_or("frontend transcript absent")?,
    );
    if !transcript.is_absolute() {
        return Err("frontend transcript must be owned absolute path".into());
    }
    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        let mut released = false;
        if let Ok(mut file) = std::fs::File::open(&transcript) {
            for sequence in 0..64_u64 {
                let mut length = [0_u8; 4];
                if file.read_exact(&mut length).is_err() {
                    break;
                }
                let length = u32::from_le_bytes(length) as usize;
                if length > 64 * 1024 {
                    return Err("frontend event exceeds bound".into());
                }
                let mut bytes = vec![0; length];
                if file.read_exact(&mut bytes).is_err() {
                    break;
                }
                memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
                let event: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                if event.get("sequence").and_then(serde_json::Value::as_u64) != Some(sequence)
                    || event.get("pid").and_then(serde_json::Value::as_u64)
                        != Some(u64::from(target_pid))
                    || (sequence == 0
                        && event.get("stage").and_then(serde_json::Value::as_str)
                            != Some("started"))
                {
                    return Err("frontend barrier differs from authorized target".into());
                }
                if event.get("stage").and_then(serde_json::Value::as_str)
                    == Some("controller-released")
                {
                    released = true;
                    break;
                }
            }
        }
        if released {
            break;
        }
        if Instant::now() >= deadline {
            return Err("frontend controller release not observed".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let action = WindowsCertificationFrontendAction {
        format: "memcordon.windows-component-frontend-action".into(),
        revision: 1,
        kind: if kill {
            "exit-process"
        } else {
            "disconnect-public-channel"
        }
        .into(),
        process: caller_identity()?,
        target_pid,
        target_authorization_observed: true,
        controller_release_observed: true,
        requested_exit_status: kill.then_some(0xC000_013A),
    };
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let observation = active.as_mut().ok_or("frontend observation owner lost")?;
        observation.frontend_action = Some(action);
        publish(observation)
    })?;
    if kill {
        // SAFETY: explicit support-only actor exits its own process after its
        // protected native action receipt is published; controller holds it.
        unsafe { windows_sys::Win32::System::Threading::ExitProcess(0xC000_013A) };
    }
    Ok(true)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn caller_identity() -> Result<WindowsProcessIdentityV1, String> {
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes},
    };
    let mut birth = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: current process pseudo-handle and four distinct writable FILETIMEs
    // remain live throughout the native observation.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut birth,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: GetCurrentProcessId has no arguments and identifies this caller.
    Ok(WindowsProcessIdentityV1 {
        process_id: unsafe { GetCurrentProcessId() },
        creation_time_100ns: (u64::from(birth.dwHighDateTime) << 32)
            | u64::from(birth.dwLowDateTime),
    })
}
