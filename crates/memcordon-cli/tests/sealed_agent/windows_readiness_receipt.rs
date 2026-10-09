//! Optional owned receipt publication for the native component driver. Ordinary
//! tests retain their assertions; only an explicit bounded stdin request emits.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{IsTerminal, Read, Write},
    path::PathBuf,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    run_id: String,
    recipe_id: String,
    test_name: String,
    native_target: String,
    executable_sha256: String,
    artifact_root: PathBuf,
    artifact_prefix: PathBuf,
    challenge: [u8; 32],
}
#[derive(Serialize)]
struct Observation {
    phase: String,
    before_record: String,
    after_record: String,
    original: String,
    caller_ack_revision: u64,
    persisted_revision: u64,
    publication_rejected: bool,
    native_code: Option<memcordon_core::NativeFailureCodeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publisher_process: Option<PublisherProcess>,
}
#[derive(Serialize)]
pub struct PublisherProcess {
    pub process_id: u32,
    pub creation_time_100ns: u64,
    pub held_before_input_delivery: bool,
    pub exit_status: u32,
    pub retirement_observed: bool,
}
pub struct HeldNativeProcess {
    handle: std::os::windows::io::OwnedHandle,
    pub identity: memcordon_core::WindowsProcessIdentityV1,
}
impl HeldNativeProcess {
    pub fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle;
        self.handle.as_raw_handle()
    }
    pub fn open(process_id: u32) -> Self {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: OpenProcess receives a PID observed from an owned live Job or
        // Child; the returned handle is immediately owned and retained.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000,
                0,
                process_id,
            )
        };
        assert!(
            !raw.is_null(),
            "native component process identity could not be held"
        );
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
        let mut created = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exited = windows_sys::Win32::Foundation::FILETIME::default();
        let mut kernel = windows_sys::Win32::Foundation::FILETIME::default();
        let mut user = windows_sys::Win32::Foundation::FILETIME::default();
        // SAFETY: retained handle and four initialized writable output buffers.
        assert_ne!(
            unsafe {
                GetProcessTimes(
                    handle.as_raw_handle(),
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            },
            0
        );
        Self {
            handle,
            identity: memcordon_core::WindowsProcessIdentityV1 {
                process_id,
                creation_time_100ns: (u64::from(created.dwHighDateTime) << 32)
                    | u64::from(created.dwLowDateTime),
            },
        }
    }
    pub fn exited(&self) -> bool {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: this object retains ownership of the queried native handle.
        let status = unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                self.handle.as_raw_handle(),
                0,
            )
        };
        assert!(
            status == windows_sys::Win32::Foundation::WAIT_OBJECT_0
                || status == windows_sys::Win32::Foundation::WAIT_TIMEOUT
        );
        status == windows_sys::Win32::Foundation::WAIT_OBJECT_0
    }
}
pub struct Context {
    input: Input,
    test_name: String,
    observations: Vec<Observation>,
}

pub fn begin(test_name: &str) -> Option<Context> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return None;
    }
    let mut bytes = Vec::new();
    stdin.lock().take(4097).read_to_end(&mut bytes).unwrap();
    if bytes.is_empty() {
        return None;
    }
    assert!(bytes.len() <= 4096, "native receipt input exceeds bound");
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes).unwrap();
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(input.test_name, test_name);
    assert!(input.artifact_root.is_absolute());
    assert!(
        !input.artifact_prefix.as_os_str().is_empty()
            && input
                .artifact_prefix
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
    );
    assert!(input.run_id.len() <= 128 && !input.run_id.is_empty());
    assert!(input.recipe_id.len() <= 128 && !input.recipe_id.is_empty());
    assert!(
        input.challenge.iter().any(|byte| *byte != 0),
        "native test controller challenge is empty"
    );
    let native_target = if cfg!(target_arch = "aarch64") {
        "aarch64-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-msvc"
    };
    assert_eq!(input.native_target, native_target);
    let mut file = fs::File::open(std::env::current_exe().unwrap()).unwrap();
    assert!(file.metadata().unwrap().len() <= 512 * 1024 * 1024);
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let actual: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(input.executable_sha256, actual);
    fs::create_dir(&input.artifact_root).unwrap();
    Some(Context {
        input,
        test_name: test_name.into(),
        observations: Vec::new(),
    })
}

impl Context {
    pub fn attempt_id(&self) -> String {
        let bytes =
            serde_json::to_vec(&(&self.input.run_id, &self.input.recipe_id, &self.test_name))
                .unwrap();
        super::record::digest(&bytes)
    }
    pub fn retain(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.input.artifact_root.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        self.input
            .artifact_prefix
            .join(name)
            .to_str()
            .expect("normalized artifact prefix must be Unicode")
            .replace('\\', "/")
    }
    pub fn record(
        &mut self,
        phase: &str,
        before: &[u8],
        after: &[u8],
        original: &memcordon_core::OriginalFailureV1,
        caller_ack_revision: u64,
        persisted_revision: u64,
        publication_rejected: bool,
        native_code: Option<memcordon_core::NativeFailureCodeV1>,
    ) {
        assert!(
            phase
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
        let before_record = self.retain(&format!("{phase}.before.json"), before);
        let after_record = self.retain(&format!("{phase}.after.json"), after);
        let original = self.retain(
            &format!("{phase}.original.json"),
            &serde_json::to_vec(original).unwrap(),
        );
        self.observations.push(Observation {
            phase: phase.into(),
            before_record,
            after_record,
            original,
            caller_ack_revision,
            persisted_revision,
            publication_rejected,
            native_code,
            publisher_process: None,
        });
    }
    pub fn publisher_process(&mut self, process: PublisherProcess) {
        let observation = self
            .observations
            .last_mut()
            .expect("publisher observation requires actual record readback");
        assert!(observation.publisher_process.is_none());
        observation.publisher_process = Some(process);
    }
    pub fn finish(self, kind: &str) {
        assert!(!self.observations.is_empty());
        let payload = serde_json::json!({"kind":kind,"observations":self.observations});
        self.finish_payload(payload);
    }
    pub fn finish_payload(self, payload: serde_json::Value) {
        let receipt = serde_json::json!({"format":"memcordon.windows-native-component", "revision":1,
            "run_id":self.input.run_id, "recipe_id":self.input.recipe_id, "test_name":self.test_name,
            "native_target":self.input.native_target, "executable_sha256":self.input.executable_sha256,
            "payload":payload});
        self.retain(
            "native-receipt.json",
            &serde_json::to_vec(&receipt).unwrap(),
        );
    }
}
