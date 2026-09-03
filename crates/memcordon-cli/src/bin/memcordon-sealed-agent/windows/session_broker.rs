use std::io::{self, Write};
use std::path::PathBuf;
use std::ptr;
use std::sync::{LazyLock, Mutex, TryLockError};
use std::time::{Duration, Instant};

use memcordon_core::{
    WINDOWS_LAUNCHER_SERVICE_NAME, WINDOWS_SESSION_BROKER_PIPE,
    WINDOWS_SESSION_BROKER_SERVICE_NAME, WindowsProcessIdentityV1,
};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS,
    GetHandleInformation, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, GetNamedPipeServerProcessId,
    GetNamedPipeServerSessionId,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY,
    REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW,
    RegFlushKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows_sys::Win32::System::Services::{SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOPPED};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetCurrentThread, GetProcessIdOfThread, OpenProcess,
    OpenThread, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION, ReleaseMutex,
    THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME,
    THREAD_SET_THREAD_TOKEN, WaitForSingleObject,
};

use super::pipe::OwnedHandle;

pub(crate) const SESSION_BROKER_SCHEMA_VERSION: u32 = 6;
const BROKER_ROLE: u8 = 3;
const BROKER_TRANSACTION_DEADLINE: Duration = Duration::from_secs(30);
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const LAUNCHER_PROCESS_BROKER_ACCESS: u32 =
    SYNCHRONIZE_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;
pub(crate) const HOLDER_PROCESS_TRANSFER_ACCESS: u32 = 0x0010_1040;
pub(crate) const HOLDER_THREAD_LAUNCHER_ACCESS: u32 =
    THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;
pub(crate) const HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS: u32 =
    THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN;
pub(crate) const HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS: u32 =
    HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS | THREAD_QUERY_LIMITED_INFORMATION;
pub(crate) const HOLDER_JOB_BROKER_ACCESS: u32 = 0x0000_0005;
pub(crate) const BROKER_PROCESS_LAUNCHER_ACCESS: u32 = 0x0010_1000;
const BROKER_FAILURE_TRANSACTION: u32 = 0x4d43_0701;
pub(crate) const BROKER_FAILURE_ARGUMENTS: u32 = 0x4d43_0711;
const BROKER_FAILURE_PROCESS_PROTECTION: u32 = 0x4d43_0712;
const BROKER_FAILURE_CERTIFICATION: u32 = 0x4d43_0713;
const BROKER_FAILURE_LISTENER_PREPARATION: u32 = 0x4d43_0714;
const BROKER_FAILURE_RUNNING_PUBLICATION: u32 = 0x4d43_0715;
const BROKER_FAILURE_NONCE_VALIDATION: u32 = 0x4d43_0716;
pub(crate) const BROKER_FAILURE_PROCESS_DESCRIPTOR: u32 = 0x4d43_0717;
pub(crate) const BROKER_FAILURE_PROCESS_APPLY: u32 = 0x4d43_0718;
pub(crate) const BROKER_FAILURE_PROCESS_READBACK: u32 = 0x4d43_0719;
pub(crate) const BROKER_FAILURE_TOKEN_OPEN: u32 = 0x4d43_071a;
pub(crate) const BROKER_FAILURE_TOKEN_DESCRIPTOR: u32 = 0x4d43_071b;
pub(crate) const BROKER_FAILURE_TOKEN_DACL_APPLY: u32 = 0x4d43_071c;
pub(crate) const BROKER_FAILURE_TOKEN_READBACK: u32 = 0x4d43_071d;
pub(crate) const BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION: u32 = 0x4d43_071e;
static BROKER_TRANSACTION_LEASE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
const LOADER_SNAPS_SCHEMA_VERSION: u32 = 2;
const TRACE_SESSION_CAPABILITY_SCHEMA_VERSION: u32 = 1;
const TRACE_SESSION_CAPABILITY_DEADLINE: Duration = Duration::from_secs(5);
const LOADER_SNAPS_REGISTRY_PARENT: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const LOADER_SNAPS_IMAGE_NAME: &str = "memcordon-target-desktop-bootstrap.exe";
const LOADER_SNAPS_VALUE_NAME: &str = "GlobalFlag";
const LOADER_SNAPS_FLAG: u32 = 0x0000_0002;
const LOADER_SNAPS_REGISTRY_VALUE_MAX_BYTES: usize = 1_024;
const LOADER_SNAPS_REGISTRY_VIEW: &str = "wow64-64-shared";
const LOADER_SNAPS_MUTEX_NAME: &str = r"Global\MemCordonLoaderSnapsV2";
const LOADER_SNAPS_PARENT_ACCESS: u32 = KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY;
const LOADER_SNAPS_IMAGE_ACCESS: u32 = KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LoaderSnapsStageV2 {
    Authority,
    TransactionLease,
    JournalLoad,
    JournalValidate,
    JournalStageCreate,
    JournalWrite,
    JournalSync,
    JournalPublish,
    ParentOpen,
    ImageOpen,
    ImageCreate,
    PriorQuerySize,
    PriorQueryData,
    AppliedSet,
    AppliedReadback,
    AppliedFlush,
    RestoreCompare,
    RestoreSetOrDelete,
    RestoreReadback,
    RestoreFlush,
    JournalRetire,
    BrokerProtocol,
    BrokerRetire,
}

impl LoaderSnapsStageV2 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::TransactionLease => "transaction-lease",
            Self::JournalLoad => "journal-load",
            Self::JournalValidate => "journal-validate",
            Self::JournalStageCreate => "journal-stage-create",
            Self::JournalWrite => "journal-write",
            Self::JournalSync => "journal-sync",
            Self::JournalPublish => "journal-publish",
            Self::ParentOpen => "parent-open",
            Self::ImageOpen => "image-open",
            Self::ImageCreate => "image-create",
            Self::PriorQuerySize => "prior-query-size",
            Self::PriorQueryData => "prior-query-data",
            Self::AppliedSet => "applied-set",
            Self::AppliedReadback => "applied-readback",
            Self::AppliedFlush => "applied-flush",
            Self::RestoreCompare => "restore-compare",
            Self::RestoreSetOrDelete => "restore-set-or-delete",
            Self::RestoreReadback => "restore-readback",
            Self::RestoreFlush => "restore-flush",
            Self::JournalRetire => "journal-retire",
            Self::BrokerProtocol => "broker-protocol",
            Self::BrokerRetire => "broker-retire",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderSnapsFailureV2 {
    pub(crate) stage: LoaderSnapsStageV2,
    pub(crate) api: String,
    pub(crate) native_code: Option<i32>,
    pub(crate) requested_access: u32,
    pub(crate) transaction_sha256: String,
    pub(crate) journal_state: String,
    pub(crate) mutation_state: String,
    pub(crate) child_launch: String,
    pub(crate) restoration: String,
    pub(crate) detail: String,
}

impl LoaderSnapsFailureV2 {
    fn new(
        stage: LoaderSnapsStageV2,
        api: impl ToString,
        native_code: Option<i32>,
        requested_access: u32,
        transaction_sha256: impl ToString,
        journal_state: impl ToString,
        mutation_state: impl ToString,
        restoration: impl ToString,
        detail: impl ToString,
    ) -> Self {
        Self {
            stage,
            api: api.to_string(),
            native_code,
            requested_access,
            transaction_sha256: transaction_sha256.to_string(),
            journal_state: journal_state.to_string(),
            mutation_state: mutation_state.to_string(),
            child_launch: "not-attempted".to_owned(),
            restoration: restoration.to_string(),
            detail: bounded_broker_detail(detail.to_string()),
        }
    }

    pub(crate) fn diagnostic(&self) -> String {
        format!(
            "loader_snaps_transaction=v2 stage={} api={} native_code={} hive=HKLM parent=Image-File-Execution-Options image={} value={} requested_access={:#010x} registry_view={} authority_service={} authority_user_sid=S-1-5-18 authority_service_sid_type=unrestricted authority_thread_token=absent transaction_sha256={} journal_state={} mutation_state={} child_launch={} restoration={} detail={}",
            self.stage.diagnostic(),
            self.api,
            self.native_code
                .map_or_else(|| "unavailable".to_owned(), |code| code.to_string()),
            LOADER_SNAPS_IMAGE_NAME,
            LOADER_SNAPS_VALUE_NAME,
            self.requested_access,
            LOADER_SNAPS_REGISTRY_VIEW,
            WINDOWS_SESSION_BROKER_SERVICE_NAME,
            self.transaction_sha256,
            self.journal_state,
            self.mutation_state,
            self.child_launch,
            self.restoration,
            self.detail,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LoaderSnapsRegistryValueV2 {
    value_type: u32,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum LoaderSnapsJournalPhaseV2 {
    Prepared,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LoaderSnapsJournalV2 {
    schema_version: u32,
    phase: LoaderSnapsJournalPhaseV2,
    transaction_nonce: String,
    request_binding_sha256: String,
    admission_sha256: String,
    matrix_cell: String,
    target_token_sha256: String,
    association_preflight_sha256: String,
    holder_identity: WindowsProcessIdentityV1,
    owner_broker_identity: WindowsProcessIdentityV1,
    owner_broker_token_sha256: String,
    launcher_identity: WindowsProcessIdentityV1,
    image_name: String,
    image_path_sha256: String,
    image_sha256: String,
    native_machine: u16,
    registry_parent: String,
    registry_view: String,
    prior_key_existed: bool,
    prior_value: Option<LoaderSnapsRegistryValueV2>,
    applied_value: LoaderSnapsRegistryValueV2,
    introduced_loader_snaps_bit: bool,
    integrity_sha256: String,
}

impl LoaderSnapsJournalV2 {
    fn seal(mut self) -> Result<Self, LoaderSnapsFailureV2> {
        self.integrity_sha256.clear();
        let mut canonical = b"memcordon-loader-snaps-journal-v2\0".to_vec();
        canonical.extend(serde_json::to_vec(&self).map_err(|error| {
            LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::JournalValidate,
                "serde_json::to_vec",
                None,
                0,
                &self.request_binding_sha256,
                "constructing",
                "not-started",
                "not-needed",
                error,
            )
        })?);
        self.integrity_sha256 = super::record::digest(&canonical);
        Ok(self)
    }

    fn validate(&self) -> Result<(), LoaderSnapsFailureV2> {
        let failure = |detail: &str| {
            LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::JournalValidate,
                "journal.validate",
                None,
                0,
                &self.request_binding_sha256,
                "present",
                "unknown",
                "recovery-required",
                detail,
            )
        };
        if self.schema_version != LOADER_SNAPS_SCHEMA_VERSION
            || self.phase != LoaderSnapsJournalPhaseV2::Prepared
            || !memcordon_core::windows_service_attestation_challenge_is_valid(
                &self.transaction_nonce,
            )
            || self.image_name != LOADER_SNAPS_IMAGE_NAME
            || self.registry_parent != LOADER_SNAPS_REGISTRY_PARENT
            || self.registry_view != LOADER_SNAPS_REGISTRY_VIEW
            || !self.matrix_cell.ends_with("snaps-on")
            || self.owner_broker_identity.process_id == 0
            || self.owner_broker_identity.creation_time_100ns == 0
            || self.launcher_identity.process_id == 0
            || self.launcher_identity.creation_time_100ns == 0
            || self.holder_identity.process_id == 0
            || self.holder_identity.creation_time_100ns == 0
            || !matches!(
                self.native_machine,
                memcordon_core::WINDOWS_PE_MACHINE_AMD64 | memcordon_core::WINDOWS_PE_MACHINE_ARM64
            )
            || (!self.prior_key_existed && self.prior_value.is_some())
            || self.applied_value.bytes.len() > LOADER_SNAPS_REGISTRY_VALUE_MAX_BYTES
            || self
                .prior_value
                .as_ref()
                .is_some_and(|value| value.bytes.len() > LOADER_SNAPS_REGISTRY_VALUE_MAX_BYTES)
        {
            return Err(failure("loader-snaps V2 journal shape is invalid"));
        }
        for digest in [
            &self.request_binding_sha256,
            &self.admission_sha256,
            &self.target_token_sha256,
            &self.association_preflight_sha256,
            &self.owner_broker_token_sha256,
            &self.image_path_sha256,
            &self.image_sha256,
        ] {
            super::record::validate_attempt_id(digest).map_err(|error| failure(&error))?;
        }
        let prior_flags = self
            .prior_value
            .as_ref()
            .map(parse_loader_global_flag)
            .transpose()?
            .unwrap_or(0);
        let expected = encode_loader_global_flag(
            self.prior_value
                .as_ref()
                .map_or(REG_DWORD, |value| value.value_type),
            prior_flags | LOADER_SNAPS_FLAG,
            &self.request_binding_sha256,
        )?;
        if self.applied_value != expected
            || self.introduced_loader_snaps_bit != (prior_flags & LOADER_SNAPS_FLAG == 0)
        {
            return Err(failure(
                "loader-snaps V2 applied value is not derived from its exact prior value",
            ));
        }
        let expected = self.clone().seal()?;
        if expected.integrity_sha256 != self.integrity_sha256 {
            return Err(failure("loader-snaps V2 journal digest is invalid"));
        }
        Ok(())
    }
}

struct OwnedRegistryKey(HKEY);

impl Drop for OwnedRegistryKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { RegCloseKey(self.0) };
        }
    }
}

struct LoaderSnapsMachineLease {
    handle: OwnedHandle,
}

impl Drop for LoaderSnapsMachineLease {
    fn drop(&mut self) {
        unsafe { ReleaseMutex(self.handle.raw()) };
    }
}

fn loader_snaps_journal_path() -> PathBuf {
    super::package::state_root()
        .join("package")
        .join("loader-snaps-transaction-v2.json")
}

fn loader_snaps_machine_lease(
    transaction_sha256: &str,
) -> Result<LoaderSnapsMachineLease, LoaderSnapsFailureV2> {
    let name = super::pipe::wide_null(LOADER_SNAPS_MUTEX_NAME);
    let security =
        super::security::SecurityDescriptor::from_sddl("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")
            .map_err(|error| {
                LoaderSnapsFailureV2::new(
                    LoaderSnapsStageV2::TransactionLease,
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                    None,
                    0,
                    transaction_sha256,
                    "unknown",
                    "not-started",
                    "not-needed",
                    error,
                )
            })?;
    let attributes = security.attributes(false);
    let raw = unsafe { CreateMutexW(&raw const attributes, 1, name.as_ptr()) };
    let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let handle = OwnedHandle::new(raw).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::TransactionLease,
            "CreateMutexW",
            io::Error::last_os_error().raw_os_error(),
            0,
            transaction_sha256,
            "unknown",
            "not-started",
            "not-needed",
            error,
        )
    })?;
    security
        .verify_kernel_object(handle.raw(), super::security::SecurityObjectKind::Mutex)
        .map_err(|error| {
            LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::TransactionLease,
                "GetSecurityInfo",
                None,
                0,
                transaction_sha256,
                "unknown",
                "not-started",
                "not-needed",
                error,
            )
        })?;
    if already_exists {
        return Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::TransactionLease,
            "CreateMutexW",
            Some(ERROR_ALREADY_EXISTS as i32),
            0,
            transaction_sha256,
            "unknown",
            "not-started",
            "not-needed",
            "another machine-wide loader-snaps transaction exists",
        ));
    }
    Ok(LoaderSnapsMachineLease { handle })
}

fn parse_loader_global_flag(
    value: &LoaderSnapsRegistryValueV2,
) -> Result<u32, LoaderSnapsFailureV2> {
    let failure = |detail: &str| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalValidate,
            "parse-GlobalFlag",
            None,
            0,
            "unbound",
            "unknown",
            "not-started",
            "not-needed",
            detail,
        )
    };
    match value.value_type {
        REG_DWORD if value.bytes.len() == 4 => Ok(u32::from_le_bytes(
            value.bytes.as_slice().try_into().expect("length checked"),
        )),
        REG_SZ if value.bytes.len() % 2 == 0 => {
            let units = value
                .bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>();
            let text = String::from_utf16(&units)
                .map_err(|_| failure("GlobalFlag REG_SZ is invalid UTF-16"))?;
            let digits = text
                .trim()
                .strip_prefix("0x")
                .or_else(|| text.trim().strip_prefix("0X"))
                .unwrap_or(text.trim());
            u32::from_str_radix(digits, 16)
                .map_err(|_| failure("GlobalFlag REG_SZ is not canonical hexadecimal"))
        }
        _ => Err(failure(
            "GlobalFlag has an unsupported registry type or byte length",
        )),
    }
}

fn encode_loader_global_flag(
    value_type: u32,
    flags: u32,
    transaction_sha256: &str,
) -> Result<LoaderSnapsRegistryValueV2, LoaderSnapsFailureV2> {
    let bytes = match value_type {
        REG_DWORD => flags.to_le_bytes().to_vec(),
        REG_SZ => format!("0x{flags:08x}\0")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
        _ => {
            return Err(LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::JournalValidate,
                "encode-GlobalFlag",
                None,
                0,
                transaction_sha256,
                "constructing",
                "not-started",
                "not-needed",
                "GlobalFlag registry type cannot be preserved",
            ));
        }
    };
    Ok(LoaderSnapsRegistryValueV2 { value_type, bytes })
}

fn open_loader_snaps_subkey(
    parent: HKEY,
    name: &str,
    access: u32,
    stage: LoaderSnapsStageV2,
    transaction_sha256: &str,
    journal_state: &str,
    mutation_state: &str,
) -> Result<Option<OwnedRegistryKey>, LoaderSnapsFailureV2> {
    let name = super::pipe::wide_null(name);
    let mut key = ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(parent, name.as_ptr(), 0, access, &raw mut key) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(LoaderSnapsFailureV2::new(
            stage,
            "RegOpenKeyExW",
            Some(status as i32),
            access,
            transaction_sha256,
            journal_state,
            mutation_state,
            "not-needed",
            "registry key open was denied or failed",
        ));
    }
    Ok(Some(OwnedRegistryKey(key)))
}

fn open_loader_snaps_parent(
    transaction_sha256: &str,
    journal_state: &str,
    mutation_state: &str,
) -> Result<OwnedRegistryKey, LoaderSnapsFailureV2> {
    open_loader_snaps_subkey(
        HKEY_LOCAL_MACHINE,
        LOADER_SNAPS_REGISTRY_PARENT,
        LOADER_SNAPS_PARENT_ACCESS,
        LoaderSnapsStageV2::ParentOpen,
        transaction_sha256,
        journal_state,
        mutation_state,
    )?
    .ok_or_else(|| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::ParentOpen,
            "RegOpenKeyExW",
            Some(ERROR_FILE_NOT_FOUND as i32),
            LOADER_SNAPS_PARENT_ACCESS,
            transaction_sha256,
            journal_state,
            mutation_state,
            "not-needed",
            "IFEO registry parent is absent",
        )
    })
}

fn create_loader_snaps_image_key(
    parent: HKEY,
    transaction_sha256: &str,
) -> Result<OwnedRegistryKey, LoaderSnapsFailureV2> {
    let name = super::pipe::wide_null(LOADER_SNAPS_IMAGE_NAME);
    let mut key = ptr::null_mut();
    let mut disposition = 0_u32;
    let status = unsafe {
        RegCreateKeyExW(
            parent,
            name.as_ptr(),
            0,
            ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            LOADER_SNAPS_IMAGE_ACCESS,
            ptr::null(),
            &raw mut key,
            &raw mut disposition,
        )
    };
    if status != ERROR_SUCCESS || disposition != 1 {
        return Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::ImageCreate,
            "RegCreateKeyExW",
            Some(status as i32),
            LOADER_SNAPS_IMAGE_ACCESS,
            transaction_sha256,
            "durable",
            "not-started",
            "recovery-required",
            format!("image-key create failed or raced: disposition={disposition}"),
        ));
    }
    Ok(OwnedRegistryKey(key))
}

fn query_loader_snaps_value(
    key: HKEY,
    transaction_sha256: &str,
    mutation_state: &str,
) -> Result<Option<LoaderSnapsRegistryValueV2>, LoaderSnapsFailureV2> {
    let name = super::pipe::wide_null(LOADER_SNAPS_VALUE_NAME);
    let mut value_type = 0_u32;
    let mut size = 0_u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            &raw mut value_type,
            ptr::null_mut(),
            &raw mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS || size as usize > LOADER_SNAPS_REGISTRY_VALUE_MAX_BYTES {
        return Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::PriorQuerySize,
            "RegQueryValueExW",
            Some(status as i32),
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            transaction_sha256,
            "present",
            mutation_state,
            "recovery-required",
            format!("GlobalFlag size query failed or exceeded bound: size={size}"),
        ));
    }
    let mut bytes = vec![0_u8; size as usize];
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            &raw mut value_type,
            bytes.as_mut_ptr(),
            &raw mut size,
        )
    };
    if status != ERROR_SUCCESS || size as usize != bytes.len() {
        return Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::PriorQueryData,
            "RegQueryValueExW",
            Some(status as i32),
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            transaction_sha256,
            "present",
            mutation_state,
            "recovery-required",
            format!("GlobalFlag data query raced or failed: size={size}"),
        ));
    }
    Ok(Some(LoaderSnapsRegistryValueV2 { value_type, bytes }))
}

fn set_loader_snaps_value(
    key: HKEY,
    value: &LoaderSnapsRegistryValueV2,
    stage: LoaderSnapsStageV2,
    transaction_sha256: &str,
    mutation_state: &str,
) -> Result<(), LoaderSnapsFailureV2> {
    let name = super::pipe::wide_null(LOADER_SNAPS_VALUE_NAME);
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            value.value_type,
            value.bytes.as_ptr(),
            value.bytes.len() as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(LoaderSnapsFailureV2::new(
            stage,
            "RegSetValueExW",
            Some(status as i32),
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            transaction_sha256,
            "durable",
            mutation_state,
            "recovery-required",
            "GlobalFlag set failed",
        ))
    }
}

fn delete_loader_snaps_value(
    key: HKEY,
    transaction_sha256: &str,
    mutation_state: &str,
) -> Result<(), LoaderSnapsFailureV2> {
    let name = super::pipe::wide_null(LOADER_SNAPS_VALUE_NAME);
    let status = unsafe { RegDeleteValueW(key, name.as_ptr()) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::RestoreSetOrDelete,
            "RegDeleteValueW",
            Some(status as i32),
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            transaction_sha256,
            "durable",
            mutation_state,
            "recovery-required",
            "owned GlobalFlag deletion failed",
        ))
    }
}

fn flush_loader_snaps_key(
    key: HKEY,
    stage: LoaderSnapsStageV2,
    transaction_sha256: &str,
    mutation_state: &str,
) -> Result<(), LoaderSnapsFailureV2> {
    let status = unsafe { RegFlushKey(key) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(LoaderSnapsFailureV2::new(
            stage,
            "RegFlushKey",
            Some(status as i32),
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            transaction_sha256,
            "durable",
            mutation_state,
            "recovery-required",
            "registry phase flush failed",
        ))
    }
}

fn store_loader_snaps_journal(journal: &LoaderSnapsJournalV2) -> Result<(), LoaderSnapsFailureV2> {
    let path = loader_snaps_journal_path();
    let transaction_sha256 = &journal.request_binding_sha256;
    super::package::reject_reparse_components(&path).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalStageCreate,
            "reject_reparse_components",
            None,
            0,
            transaction_sha256,
            "absent",
            "not-started",
            "not-needed",
            error,
        )
    })?;
    let staged = path.with_extension(format!("json.{}.new", journal.transaction_nonce));
    super::package::reject_reparse_components(&staged).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalStageCreate,
            "reject_reparse_components",
            None,
            0,
            transaction_sha256,
            "absent",
            "not-started",
            "not-needed",
            error,
        )
    })?;
    let mut bytes = serde_json::to_vec_pretty(journal).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalValidate,
            "serde_json::to_vec_pretty",
            None,
            0,
            transaction_sha256,
            "constructing",
            "not-started",
            "not-needed",
            error,
        )
    })?;
    bytes.push(b'\n');
    let mut file = super::record::CreateOnceStagingFile::create(&staged).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalStageCreate,
            "CreateFileW(CREATE_NEW,GENERIC_WRITE|DELETE)",
            error.raw_os_error(),
            0x4001_0000,
            transaction_sha256,
            "absent",
            "not-started",
            "not-needed",
            error,
        )
    })?;
    file.file_mut().write_all(&bytes).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalWrite,
            "WriteFile",
            error.raw_os_error(),
            0x4001_0000,
            transaction_sha256,
            "staging",
            "not-started",
            "not-needed",
            error,
        )
    })?;
    file.sync_all().map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalSync,
            "FlushFileBuffers",
            error.raw_os_error(),
            0x4001_0000,
            transaction_sha256,
            "staging",
            "not-started",
            "not-needed",
            error,
        )
    })?;
    super::record::publish_create_once_atomically(file, &path).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalPublish,
            "SetFileInformationByHandle(FileRenameInfoEx)",
            error.native_code(),
            0x4001_0000,
            transaction_sha256,
            "staging",
            "not-started",
            "not-needed",
            error,
        )
    })
}

fn load_loader_snaps_journal() -> Result<Option<LoaderSnapsJournalV2>, LoaderSnapsFailureV2> {
    let path = loader_snaps_journal_path();
    super::package::reject_reparse_components(&path).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalLoad,
            "reject_reparse_components",
            None,
            0,
            "recovery",
            "unknown",
            "unknown",
            "recovery-required",
            error,
        )
    })?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::JournalLoad,
                "ReadFile",
                error.raw_os_error(),
                0,
                "recovery",
                "unknown",
                "unknown",
                "recovery-required",
                error,
            ));
        }
    };
    if bytes.len() > 16 * 1024 {
        return Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalValidate,
            "journal-size",
            None,
            0,
            "recovery",
            "present",
            "unknown",
            "recovery-required",
            "loader-snaps V2 journal exceeds its fixed bound",
        ));
    }
    let journal: LoaderSnapsJournalV2 = serde_json::from_slice(&bytes).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalValidate,
            "serde_json::from_slice",
            None,
            0,
            "recovery",
            "present",
            "unknown",
            "recovery-required",
            error,
        )
    })?;
    journal.validate()?;
    Ok(Some(journal))
}

fn retire_loader_snaps_journal(transaction_sha256: &str) -> Result<(), LoaderSnapsFailureV2> {
    let path = loader_snaps_journal_path();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::JournalRetire,
            "DeleteFileW",
            error.raw_os_error(),
            0,
            transaction_sha256,
            "present",
            "restored",
            "attested",
            error,
        )),
    }
}

fn restore_loader_snaps_value(
    image: HKEY,
    journal: &LoaderSnapsJournalV2,
    mutation_state: &str,
) -> Result<(), LoaderSnapsFailureV2> {
    match &journal.prior_value {
        Some(value) => set_loader_snaps_value(
            image,
            value,
            LoaderSnapsStageV2::RestoreSetOrDelete,
            &journal.request_binding_sha256,
            mutation_state,
        ),
        None => delete_loader_snaps_value(image, &journal.request_binding_sha256, mutation_state),
    }
}

fn recover_loader_snaps_journal() -> Result<(), LoaderSnapsFailureV2> {
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::Authority,
            "NtQueryInformationThread(Token)",
            None,
            0,
            "recovery",
            "unknown",
            "unknown",
            "recovery-required",
            error,
        )
    })?;
    let lease = loader_snaps_machine_lease("recovery")?;
    let Some(journal) = load_loader_snaps_journal()? else {
        drop(lease);
        return Ok(());
    };
    let transaction = &journal.request_binding_sha256;
    let parent = open_loader_snaps_parent(transaction, "present", "unknown")?;
    let image = open_loader_snaps_subkey(
        parent.0,
        LOADER_SNAPS_IMAGE_NAME,
        LOADER_SNAPS_IMAGE_ACCESS,
        LoaderSnapsStageV2::ImageOpen,
        transaction,
        "present",
        "unknown",
    )?;
    let Some(image) = image else {
        if !journal.prior_key_existed && journal.prior_value.is_none() {
            retire_loader_snaps_journal(transaction)?;
            return Ok(());
        }
        return Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::RestoreCompare,
            "RegOpenKeyExW",
            Some(ERROR_FILE_NOT_FOUND as i32),
            LOADER_SNAPS_IMAGE_ACCESS,
            transaction,
            "present",
            "ambiguous",
            "refused",
            "recovery found a previously existing image key missing",
        ));
    };
    let observed = query_loader_snaps_value(image.0, transaction, "unknown")?;
    if observed == journal.prior_value {
        flush_loader_snaps_key(
            image.0,
            LoaderSnapsStageV2::RestoreFlush,
            transaction,
            "restored",
        )?;
        retire_loader_snaps_journal(transaction)?;
        return Ok(());
    }
    if observed.as_ref() != Some(&journal.applied_value) {
        return Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::RestoreCompare,
            "RegQueryValueExW",
            None,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            transaction,
            "present",
            "ambiguous",
            "refused",
            "recovery refused an unknown GlobalFlag value",
        ));
    }
    restore_loader_snaps_value(image.0, &journal, "restore-intent")?;
    if query_loader_snaps_value(image.0, transaction, "restore-intent")? != journal.prior_value {
        return Err(LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::RestoreReadback,
            "RegQueryValueExW",
            None,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            transaction,
            "present",
            "restore-intent",
            "recovery-required",
            "recovery exact restoration readback differs",
        ));
    }
    flush_loader_snaps_key(
        image.0,
        LoaderSnapsStageV2::RestoreFlush,
        transaction,
        "restored",
    )?;
    retire_loader_snaps_journal(transaction)
}

fn loader_snaps_value_sha256(value: Option<&LoaderSnapsRegistryValueV2>) -> String {
    let mut canonical = b"memcordon-loader-snaps-registry-value-v2\0".to_vec();
    match value {
        Some(value) => {
            canonical.extend_from_slice(&value.value_type.to_le_bytes());
            canonical.extend_from_slice(&value.bytes);
        }
        None => canonical.extend_from_slice(b"absent"),
    }
    super::record::digest(&canonical)
}

#[cfg(test)]
pub(crate) fn loader_snaps_value_round_trip_for_test(
    value_type: u32,
    bytes: Vec<u8>,
) -> Result<(u32, Vec<u8>), String> {
    let prior = LoaderSnapsRegistryValueV2 { value_type, bytes };
    let flags = parse_loader_global_flag(&prior).map_err(|error| error.diagnostic())?;
    let applied = encode_loader_global_flag(value_type, flags | LOADER_SNAPS_FLAG, "test")
        .map_err(|error| error.diagnostic())?;
    Ok((applied.value_type, applied.bytes))
}

#[cfg(test)]
pub(crate) fn loader_snaps_journal_fixture_for_test() -> Result<Vec<u8>, String> {
    let prior_value = LoaderSnapsRegistryValueV2 {
        value_type: REG_DWORD,
        bytes: 0x40_u32.to_le_bytes().to_vec(),
    };
    let applied_value =
        encode_loader_global_flag(REG_DWORD, 0x40 | LOADER_SNAPS_FLAG, &"11".repeat(32))
            .map_err(|error| error.diagnostic())?;
    let journal = LoaderSnapsJournalV2 {
        schema_version: LOADER_SNAPS_SCHEMA_VERSION,
        phase: LoaderSnapsJournalPhaseV2::Prepared,
        transaction_nonce: "22".repeat(32),
        request_binding_sha256: "11".repeat(32),
        admission_sha256: "33".repeat(32),
        matrix_cell: "explicit-empty-full-observer-snaps-on".to_owned(),
        target_token_sha256: "44".repeat(32),
        association_preflight_sha256: "55".repeat(32),
        holder_identity: WindowsProcessIdentityV1 {
            process_id: 45,
            creation_time_100ns: 46,
        },
        owner_broker_identity: WindowsProcessIdentityV1 {
            process_id: 41,
            creation_time_100ns: 42,
        },
        owner_broker_token_sha256: "66".repeat(32),
        launcher_identity: WindowsProcessIdentityV1 {
            process_id: 43,
            creation_time_100ns: 44,
        },
        image_name: LOADER_SNAPS_IMAGE_NAME.to_owned(),
        image_path_sha256: "77".repeat(32),
        image_sha256: "88".repeat(32),
        native_machine: memcordon_core::WINDOWS_PE_MACHINE_AMD64,
        registry_parent: LOADER_SNAPS_REGISTRY_PARENT.to_owned(),
        registry_view: LOADER_SNAPS_REGISTRY_VIEW.to_owned(),
        prior_key_existed: true,
        prior_value: Some(prior_value),
        applied_value,
        introduced_loader_snaps_bit: true,
        integrity_sha256: String::new(),
    }
    .seal()
    .map_err(|error| error.diagnostic())?;
    serde_json::to_vec(&journal).map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) fn validate_loader_snaps_journal_bytes_for_test(bytes: &[u8]) -> Result<(), String> {
    let journal: LoaderSnapsJournalV2 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    journal.validate().map_err(|error| error.diagnostic())
}

#[cfg(test)]
pub(crate) fn loader_snaps_journal_mutation_for_test(mutation: &str) -> Result<(), String> {
    let bytes = loader_snaps_journal_fixture_for_test()?;
    let mut journal: LoaderSnapsJournalV2 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    match mutation {
        "applied" => journal.applied_value.bytes = 0x44_u32.to_le_bytes().to_vec(),
        "prior-key" => journal.prior_key_existed = false,
        "digest" => {
            journal.integrity_sha256 = "00".repeat(32);
            return journal.validate().map_err(|error| error.diagnostic());
        }
        "registry-view" => journal.registry_view = "process-default".to_owned(),
        "authority" => journal.owner_broker_identity.process_id = 0,
        "holder" => journal.holder_identity.process_id = 0,
        "admission" => journal.admission_sha256 = "not-a-digest".to_owned(),
        "matrix" => journal.matrix_cell = "explicit-empty-full-observer-snaps-off".to_owned(),
        "native-machine" => journal.native_machine = 0x014c,
        _ => return Err("unknown loader-snaps journal test mutation".to_owned()),
    }
    journal = journal.seal().map_err(|error| error.diagnostic())?;
    journal.validate().map_err(|error| error.diagnostic())
}

fn loader_snaps_authority_sha256(
    source: &super::token::TokenAttestationSnapshot,
) -> Result<String, LoaderSnapsFailureV2> {
    let mut canonical = b"memcordon-loader-snaps-authority-v2\0".to_vec();
    canonical.extend(serde_json::to_vec(source).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::Authority,
            "serde_json::to_vec",
            None,
            0,
            "unbound",
            "not-started",
            "not-started",
            "not-needed",
            error,
        )
    })?);
    Ok(super::record::digest(&canonical))
}

struct LoaderSnapsTransactionV2 {
    _lease: LoaderSnapsMachineLease,
    image: OwnedRegistryKey,
    journal: LoaderSnapsJournalV2,
    broker_identity: WindowsProcessIdentityV1,
    restored: bool,
}

impl LoaderSnapsTransactionV2 {
    fn begin(
        request: &LoaderSnapsRequestV2,
        hello: &SessionBrokerHelloV1,
    ) -> Result<(Self, LoaderSnapsArmedReceiptV2), LoaderSnapsFailureV2> {
        super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(
            |error| {
                LoaderSnapsFailureV2::new(
                    LoaderSnapsStageV2::Authority,
                    "NtQueryInformationThread(Token)",
                    None,
                    0,
                    &request.binding_sha256,
                    "not-started",
                    "not-started",
                    "not-needed",
                    error,
                )
            },
        )?;
        let authority_token_sha256 = loader_snaps_authority_sha256(&hello.broker_source)?;
        let lease = loader_snaps_machine_lease(&request.binding_sha256)?;
        if load_loader_snaps_journal()?.is_some() {
            return Err(LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::JournalLoad,
                "loader-snaps-journal-exclusion",
                None,
                0,
                &request.binding_sha256,
                "present",
                "unknown",
                "recovery-required",
                "a prior loader-snaps transaction remains after broker-owned recovery",
            ));
        }
        let parent = open_loader_snaps_parent(&request.binding_sha256, "absent", "not-started")?;
        let existing_image = open_loader_snaps_subkey(
            parent.0,
            LOADER_SNAPS_IMAGE_NAME,
            LOADER_SNAPS_IMAGE_ACCESS,
            LoaderSnapsStageV2::ImageOpen,
            &request.binding_sha256,
            "absent",
            "not-started",
        )?;
        let prior_key_existed = existing_image.is_some();
        let prior_value = existing_image
            .as_ref()
            .map(|image| query_loader_snaps_value(image.0, &request.binding_sha256, "not-started"))
            .transpose()?
            .flatten();
        let prior_flags = prior_value
            .as_ref()
            .map(parse_loader_global_flag)
            .transpose()?
            .unwrap_or(0);
        let applied_value = encode_loader_global_flag(
            prior_value
                .as_ref()
                .map_or(REG_DWORD, |value| value.value_type),
            prior_flags | LOADER_SNAPS_FLAG,
            &request.binding_sha256,
        )?;
        let journal = LoaderSnapsJournalV2 {
            schema_version: LOADER_SNAPS_SCHEMA_VERSION,
            phase: LoaderSnapsJournalPhaseV2::Prepared,
            transaction_nonce: request.transaction_nonce.clone(),
            request_binding_sha256: request.binding_sha256.clone(),
            admission_sha256: request.binding.admission_sha256.clone(),
            matrix_cell: request.binding.matrix_cell.clone(),
            target_token_sha256: request.binding.target_token_sha256.clone(),
            association_preflight_sha256: request.binding.association_preflight_sha256.clone(),
            holder_identity: request.binding.holder_identity.clone(),
            owner_broker_identity: hello.broker_identity.clone(),
            owner_broker_token_sha256: authority_token_sha256.clone(),
            launcher_identity: request.launcher_identity.clone(),
            image_name: LOADER_SNAPS_IMAGE_NAME.to_owned(),
            image_path_sha256: request.binding.image_path_sha256.clone(),
            image_sha256: request.binding.image_sha256.clone(),
            native_machine: request.binding.native_machine,
            registry_parent: LOADER_SNAPS_REGISTRY_PARENT.to_owned(),
            registry_view: LOADER_SNAPS_REGISTRY_VIEW.to_owned(),
            prior_key_existed,
            prior_value,
            applied_value,
            introduced_loader_snaps_bit: prior_flags & LOADER_SNAPS_FLAG == 0,
            integrity_sha256: String::new(),
        }
        .seal()?;
        journal.validate()?;
        store_loader_snaps_journal(&journal)?;
        let image = match existing_image {
            Some(image) => image,
            None => create_loader_snaps_image_key(parent.0, &request.binding_sha256)?,
        };
        set_loader_snaps_value(
            image.0,
            &journal.applied_value,
            LoaderSnapsStageV2::AppliedSet,
            &request.binding_sha256,
            "apply-intent",
        )?;
        if query_loader_snaps_value(image.0, &request.binding_sha256, "applied")?.as_ref()
            != Some(&journal.applied_value)
        {
            return Err(LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::AppliedReadback,
                "RegQueryValueExW",
                None,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &request.binding_sha256,
                "durable",
                "ambiguous",
                "recovery-required",
                "GlobalFlag readback differs after application",
            ));
        }
        flush_loader_snaps_key(
            image.0,
            LoaderSnapsStageV2::AppliedFlush,
            &request.binding_sha256,
            "applied",
        )?;
        let receipt = LoaderSnapsArmedReceiptV2 {
            schema_version: LOADER_SNAPS_SCHEMA_VERSION,
            transaction_nonce: request.transaction_nonce.clone(),
            request_binding_sha256: request.binding_sha256.clone(),
            broker_identity: hello.broker_identity.clone(),
            journal_sha256: journal.integrity_sha256.clone(),
            applied_value_sha256: loader_snaps_value_sha256(Some(&journal.applied_value)),
            registry_view: LOADER_SNAPS_REGISTRY_VIEW.to_owned(),
            authority_token_sha256,
            receipt_sha256: String::new(),
        }
        .seal()
        .map_err(|error| {
            LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::BrokerProtocol,
                "seal-armed-receipt",
                None,
                0,
                &request.binding_sha256,
                "durable",
                "applied",
                "required",
                error,
            )
        })?;
        Ok((
            Self {
                _lease: lease,
                image,
                journal,
                broker_identity: hello.broker_identity.clone(),
                restored: false,
            },
            receipt,
        ))
    }

    fn restore(
        mut self,
        child_outcome_sha256: String,
    ) -> Result<LoaderSnapsRestoredReceiptV2, LoaderSnapsFailureV2> {
        let transaction = &self.journal.request_binding_sha256;
        if query_loader_snaps_value(self.image.0, transaction, "applied")?.as_ref()
            != Some(&self.journal.applied_value)
        {
            return Err(LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::RestoreCompare,
                "RegQueryValueExW",
                None,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                transaction,
                "durable",
                "ambiguous",
                "refused",
                "GlobalFlag changed before transactional restoration",
            ));
        }
        restore_loader_snaps_value(self.image.0, &self.journal, "restore-intent")?;
        if query_loader_snaps_value(self.image.0, transaction, "restore-intent")?
            != self.journal.prior_value
        {
            return Err(LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::RestoreReadback,
                "RegQueryValueExW",
                None,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                transaction,
                "durable",
                "restore-intent",
                "recovery-required",
                "GlobalFlag exact restoration readback differs",
            ));
        }
        flush_loader_snaps_key(
            self.image.0,
            LoaderSnapsStageV2::RestoreFlush,
            transaction,
            "restored",
        )?;
        retire_loader_snaps_journal(transaction)?;
        let receipt = LoaderSnapsRestoredReceiptV2 {
            schema_version: LOADER_SNAPS_SCHEMA_VERSION,
            transaction_nonce: self.journal.transaction_nonce.clone(),
            request_binding_sha256: transaction.clone(),
            broker_identity: self.broker_identity.clone(),
            prior_value_sha256: loader_snaps_value_sha256(self.journal.prior_value.as_ref()),
            registry_view: LOADER_SNAPS_REGISTRY_VIEW.to_owned(),
            created_key_disposition: if self.journal.prior_key_existed {
                "preexisting-key-preserved"
            } else {
                "retained-empty-for-nondestructive-restoration"
            }
            .to_owned(),
            child_outcome_sha256,
            receipt_sha256: String::new(),
        }
        .seal()
        .map_err(|error| {
            LoaderSnapsFailureV2::new(
                LoaderSnapsStageV2::BrokerProtocol,
                "seal-restored-receipt",
                None,
                0,
                transaction,
                "retired",
                "restored",
                "attested",
                error,
            )
        })?;
        self.restored = true;
        Ok(receipt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionBrokerStartupStage {
    Arguments,
    SourcePrivilegeNormalization,
    ProcessProtection(super::security::SessionBrokerProtectionStage),
    Certification,
    ListenerPreparation,
    RunningPublication,
    NonceValidation,
    Transaction,
}

impl SessionBrokerStartupStage {
    const fn service_exit(self) -> u32 {
        match self {
            Self::Arguments => BROKER_FAILURE_ARGUMENTS,
            Self::SourcePrivilegeNormalization => BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION,
            Self::ProcessProtection(stage) => match stage {
                super::security::SessionBrokerProtectionStage::ProcessDescriptor => {
                    BROKER_FAILURE_PROCESS_DESCRIPTOR
                }
                super::security::SessionBrokerProtectionStage::ProcessApply => {
                    BROKER_FAILURE_PROCESS_APPLY
                }
                super::security::SessionBrokerProtectionStage::ProcessReadback => {
                    BROKER_FAILURE_PROCESS_READBACK
                }
                super::security::SessionBrokerProtectionStage::TokenOpen => {
                    BROKER_FAILURE_TOKEN_OPEN
                }
                super::security::SessionBrokerProtectionStage::TokenDescriptor => {
                    BROKER_FAILURE_TOKEN_DESCRIPTOR
                }
                super::security::SessionBrokerProtectionStage::TokenDaclApply => {
                    BROKER_FAILURE_TOKEN_DACL_APPLY
                }
                super::security::SessionBrokerProtectionStage::TokenReadback => {
                    BROKER_FAILURE_TOKEN_READBACK
                }
            },
            Self::Certification => BROKER_FAILURE_CERTIFICATION,
            Self::ListenerPreparation => BROKER_FAILURE_LISTENER_PREPARATION,
            Self::RunningPublication => BROKER_FAILURE_RUNNING_PUBLICATION,
            Self::NonceValidation => BROKER_FAILURE_NONCE_VALIDATION,
            Self::Transaction => BROKER_FAILURE_TRANSACTION,
        }
    }
}

struct SessionBrokerServiceError {
    stage: SessionBrokerStartupStage,
    detail: String,
}

struct LauncherHandleTransferRollback {
    launcher: windows_sys::Win32::Foundation::HANDLE,
    remote_process: Option<u64>,
    remote_close_armed: bool,
}

impl LauncherHandleTransferRollback {
    fn new(launcher: windows_sys::Win32::Foundation::HANDLE) -> Self {
        Self {
            launcher,
            remote_process: None,
            remote_close_armed: true,
        }
    }

    fn record_process(&mut self, remote_process: u64) {
        self.remote_process = Some(remote_process);
    }

    fn revoke_before_delivery(&mut self) -> Result<(), String> {
        if !self.remote_close_armed {
            return Ok(());
        }
        self.remote_close_armed = false;
        if let Some(remote) = self.remote_process.take() {
            super::process::revoke_remote_handle(remote, self.launcher).map_err(|error| {
                format!(
                    "session broker pre-delivery remote-handle rollback failed: holder-process: {error}"
                )
            })?;
        }
        Ok(())
    }

    fn failure_detail(&mut self, primary: impl Into<String>) -> String {
        let primary = primary.into();
        match self.revoke_before_delivery() {
            Ok(()) => primary,
            Err(cleanup) => format!("{primary}; {cleanup}"),
        }
    }

    fn disarm_after_launched_delivery(&mut self) {
        self.remote_close_armed = false;
        self.remote_process = None;
    }
}

impl Drop for LauncherHandleTransferRollback {
    fn drop(&mut self) {
        if let Err(error) = self.revoke_before_delivery() {
            eprintln!("MCSEALED-WINDOWS-SESSION-BROKER: {error}");
        }
    }
}

impl SessionBrokerServiceError {
    fn startup(stage: SessionBrokerStartupStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }

    fn process_protection(error: super::security::SessionBrokerProtectionError) -> Self {
        Self::startup(
            SessionBrokerStartupStage::ProcessProtection(error.stage),
            error.to_string(),
        )
    }
}

impl From<String> for SessionBrokerServiceError {
    fn from(detail: String) -> Self {
        Self::startup(SessionBrokerStartupStage::Transaction, detail)
    }
}

pub(crate) const fn startup_diagnostic_from_exit(
    exit: u32,
) -> Option<(&'static str, Option<&'static str>)> {
    match exit {
        BROKER_FAILURE_ARGUMENTS => Some(("arguments", None)),
        BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION => {
            Some(("source-privilege-normalization", None))
        }
        BROKER_FAILURE_PROCESS_PROTECTION => Some(("process-protection", None)),
        BROKER_FAILURE_PROCESS_DESCRIPTOR => {
            Some(("process-protection", Some("process-descriptor")))
        }
        BROKER_FAILURE_PROCESS_APPLY => Some(("process-protection", Some("process-apply"))),
        BROKER_FAILURE_PROCESS_READBACK => Some(("process-protection", Some("process-readback"))),
        BROKER_FAILURE_TOKEN_OPEN => Some(("process-protection", Some("token-open"))),
        BROKER_FAILURE_TOKEN_DESCRIPTOR => Some(("process-protection", Some("token-descriptor"))),
        BROKER_FAILURE_TOKEN_DACL_APPLY => Some(("process-protection", Some("token-dacl-apply"))),
        BROKER_FAILURE_TOKEN_READBACK => Some(("process-protection", Some("token-readback"))),
        BROKER_FAILURE_CERTIFICATION => Some(("certification", None)),
        BROKER_FAILURE_LISTENER_PREPARATION => Some(("listener-preparation", None)),
        BROKER_FAILURE_RUNNING_PUBLICATION => Some(("running-publication", None)),
        BROKER_FAILURE_NONCE_VALIDATION => Some(("nonce-validation", None)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SessionBrokerStageV1 {
    RequestValidation,
    HolderCreation,
    HandleTransfer,
    Acknowledgement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SessionCreationPhaseV1 {
    WindowStation,
    Desktop,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionBrokerHelloV1 {
    schema_version: u32,
    service_name: String,
    broker_identity: WindowsProcessIdentityV1,
    broker_image_sha256: String,
    broker_source: super::token::TokenAttestationSnapshot,
    challenge: String,
    start_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionBrokerRequestV1 {
    schema_version: u32,
    start_nonce: String,
    challenge: String,
    launcher_identity: WindowsProcessIdentityV1,
    target_session_id: u32,
    holder_pipe_name: String,
    holder_nonce: String,
    launcher_job_handle: u64,
    holder_image_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderSnapsRequestBindingV2 {
    pub(crate) admission_sha256: String,
    pub(crate) matrix_cell: String,
    pub(crate) image_path_sha256: String,
    pub(crate) image_sha256: String,
    pub(crate) native_machine: u16,
    pub(crate) target_token_sha256: String,
    pub(crate) association_preflight_sha256: String,
    pub(crate) holder_identity: WindowsProcessIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LoaderSnapsRequestV2 {
    schema_version: u32,
    start_nonce: String,
    challenge: String,
    transaction_nonce: String,
    launcher_identity: WindowsProcessIdentityV1,
    binding: LoaderSnapsRequestBindingV2,
    binding_sha256: String,
}

impl LoaderSnapsRequestV2 {
    fn calculated_sha256(&self) -> Result<String, String> {
        let mut copy = self.clone();
        copy.binding_sha256.clear();
        let mut canonical = b"memcordon-loader-snaps-request-v2\0".to_vec();
        canonical.extend(serde_json::to_vec(&copy).map_err(|error| error.to_string())?);
        Ok(super::record::digest(&canonical))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TraceSessionCapabilityTriggerReasonV1 {
    StableModuleZeroPrefixNonlocalizing,
}

impl TraceSessionCapabilityTriggerReasonV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::StableModuleZeroPrefixNonlocalizing => "stable-module-zero-prefix-nonlocalizing",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TraceSessionCapabilityRequestV1 {
    capability_schema_version: u32,
    broker_schema_version: u32,
    start_nonce: String,
    challenge: String,
    transaction_nonce: String,
    launcher_identity: WindowsProcessIdentityV1,
    broker_identity: WindowsProcessIdentityV1,
    broker_source_sha256: String,
    trigger_reason: TraceSessionCapabilityTriggerReasonV1,
    trigger_sha256: String,
    ephemeral_ci: bool,
    request_binding_sha256: String,
}

impl TraceSessionCapabilityRequestV1 {
    fn calculated_sha256(&self) -> Result<String, String> {
        let mut copy = self.clone();
        copy.request_binding_sha256.clear();
        let mut canonical = b"memcordon-session-broker-trace-capability-request-v1\0".to_vec();
        canonical.extend(serde_json::to_vec(&copy).map_err(|error| error.to_string())?);
        Ok(super::record::digest(&canonical))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TraceSessionCapabilityStateV1 {
    BrokerSessionAvailable,
    BrokerSessionUnavailable,
    BrokerSessionInvalid,
}

impl TraceSessionCapabilityStateV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::BrokerSessionAvailable => "broker-session-available",
            Self::BrokerSessionUnavailable => "broker-session-unavailable",
            Self::BrokerSessionInvalid => "broker-session-invalid",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TraceSessionCapabilityReceiptV1 {
    capability_schema_version: u32,
    broker_schema_version: u32,
    transaction_sha256: String,
    trigger_reason: TraceSessionCapabilityTriggerReasonV1,
    trigger_sha256: String,
    request_binding_sha256: String,
    broker_identity: WindowsProcessIdentityV1,
    broker_source_sha256: String,
    authority_before_sha256: String,
    authority_after_sha256: String,
    authority_equal: bool,
    session_name_sha256: String,
    state: TraceSessionCapabilityStateV1,
    stage: String,
    start_status: u32,
    session_created: bool,
    stop_attempted: bool,
    stop_status: Option<u32>,
    cleanup_count: u32,
    session_absence_proven: bool,
    elapsed_ms: u64,
    deadline_exceeded: bool,
    provider_enable_attempted: bool,
    consumer_opened: bool,
    process_trace_started: bool,
    child_bound: bool,
    events_collected: u32,
    receipt_sha256: String,
}

impl TraceSessionCapabilityReceiptV1 {
    fn seal(mut self) -> Result<Self, String> {
        self.receipt_sha256.clear();
        let mut canonical = b"memcordon-session-broker-trace-capability-receipt-v1\0".to_vec();
        canonical.extend(serde_json::to_vec(&self).map_err(|error| error.to_string())?);
        self.receipt_sha256 = super::record::digest(&canonical);
        Ok(self)
    }

    fn validate_seal(&self) -> Result<(), String> {
        if self.clone().seal()?.receipt_sha256 != self.receipt_sha256 {
            return Err("trace-session capability receipt seal is invalid".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TraceSessionCapabilityFailureV1 {
    capability_schema_version: u32,
    request_binding_sha256: String,
    stage: String,
    detail_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TraceSessionCapabilityRequestProvenanceV1 {
    request_binding_sha256: String,
    transaction_sha256: String,
    broker_source_sha256: String,
    broker_identity: WindowsProcessIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TraceSessionCapabilityEvidenceV1 {
    receipt: Option<TraceSessionCapabilityReceiptV1>,
    admitted_trigger_sha256: Option<String>,
    request_provenance: Option<TraceSessionCapabilityRequestProvenanceV1>,
    retirement: &'static str,
    failure_stage: Option<&'static str>,
    failure_sha256: Option<String>,
    retirement_failure_sha256: Option<String>,
}

impl TraceSessionCapabilityEvidenceV1 {
    const REDACTION: &'static str = "session_name_redacted=true transaction_nonce_redacted=true broker_source_values_redacted=true token_values_redacted=true object_values_redacted=true";

    pub(crate) fn diagnostic(&self) -> String {
        let Some(receipt) = &self.receipt else {
            let trigger = if self.admitted_trigger_sha256.is_some() {
                TraceSessionCapabilityTriggerReasonV1::StableModuleZeroPrefixNonlocalizing
                    .diagnostic()
            } else {
                "none"
            };
            let trigger_sha256 = self.admitted_trigger_sha256.as_deref().unwrap_or("none");
            let request_binding_sha256 = self
                .request_provenance
                .as_ref()
                .map_or("unavailable", |value| value.request_binding_sha256.as_str());
            let transaction_sha256 = self
                .request_provenance
                .as_ref()
                .map_or("unavailable", |value| value.transaction_sha256.as_str());
            let broker_source_sha256 = self
                .request_provenance
                .as_ref()
                .map_or("unavailable", |value| value.broker_source_sha256.as_str());
            let broker_pid = self
                .request_provenance
                .as_ref()
                .map(|value| value.broker_identity.process_id.to_string())
                .unwrap_or_else(|| "unavailable".to_owned());
            let broker_creation_time_100ns = self
                .request_provenance
                .as_ref()
                .map(|value| value.broker_identity.creation_time_100ns.to_string())
                .unwrap_or_else(|| "unavailable".to_owned());
            return format!(
                "broker_trace_session_capability=v1 state=broker-session-invalid broker_receipt_state=none trigger={} trigger_sha256={} request_binding_sha256={} receipt_sha256=unavailable transaction_sha256={} broker_source_sha256={} broker_pid={} broker_creation_time_100ns={} authority_before_sha256=unavailable authority_after_sha256=unavailable session_name_sha256=unavailable start_status=unavailable session_created=unavailable stop_attempted=unavailable stop_status=unavailable cleanup_count=unavailable session_absence_proven=unavailable retirement={} elapsed_ms=unavailable deadline_exceeded=unavailable failure_stage={} failure_sha256={} retirement_failure_sha256={} provider_enable_attempted=false consumer_opened=false process_trace_started=false child_bound=false events_collected=0 requested_access_available=false exact_resource_identified=false acl_fix_identified=false primary_failure=original-a release_sent=false workload_executed=false qualification_promoted=false {}",
                trigger,
                trigger_sha256,
                request_binding_sha256,
                transaction_sha256,
                broker_source_sha256,
                broker_pid,
                broker_creation_time_100ns,
                self.retirement,
                self.failure_stage.unwrap_or("broker-protocol"),
                self.failure_sha256.as_deref().unwrap_or("none"),
                self.retirement_failure_sha256.as_deref().unwrap_or("none"),
                Self::REDACTION,
            );
        };
        let effective_state = if self.retirement == "retired" {
            receipt.state
        } else {
            TraceSessionCapabilityStateV1::BrokerSessionInvalid
        };
        format!(
            "broker_trace_session_capability=v1 state={} broker_receipt_state={} trigger={} trigger_sha256={} request_binding_sha256={} receipt_sha256={} transaction_sha256={} broker_source_sha256={} broker_pid={} broker_creation_time_100ns={} authority_before_sha256={} authority_after_sha256={} session_name_sha256={} start_status={} session_created={} stop_attempted={} stop_status={} cleanup_count={} session_absence_proven={} retirement={} elapsed_ms={} deadline_exceeded={} failure_stage={} failure_sha256={} retirement_failure_sha256={} provider_enable_attempted=false consumer_opened=false process_trace_started=false child_bound=false events_collected=0 requested_access_available=false exact_resource_identified=false acl_fix_identified=false primary_failure=original-a release_sent=false workload_executed=false qualification_promoted=false {}",
            effective_state.diagnostic(),
            receipt.state.diagnostic(),
            receipt.trigger_reason.diagnostic(),
            receipt.trigger_sha256,
            receipt.request_binding_sha256,
            receipt.receipt_sha256,
            receipt.transaction_sha256,
            receipt.broker_source_sha256,
            receipt.broker_identity.process_id,
            receipt.broker_identity.creation_time_100ns,
            receipt.authority_before_sha256,
            receipt.authority_after_sha256,
            receipt.session_name_sha256,
            receipt.start_status,
            receipt.session_created,
            receipt.stop_attempted,
            receipt
                .stop_status
                .map_or_else(|| "none".to_owned(), |status| status.to_string()),
            receipt.cleanup_count,
            receipt.session_absence_proven,
            self.retirement,
            receipt.elapsed_ms,
            receipt.deadline_exceeded,
            self.failure_stage.unwrap_or("none"),
            self.failure_sha256.as_deref().unwrap_or("none"),
            self.retirement_failure_sha256.as_deref().unwrap_or("none"),
            Self::REDACTION,
        )
    }
}

pub(crate) fn trace_session_capability_not_run_diagnostic() -> &'static str {
    "broker_trace_session_capability=v1 state=not-run broker_receipt_state=none trigger=none trigger_sha256=none request_binding_sha256=none receipt_sha256=none transaction_sha256=none broker_source_sha256=none broker_pid=0 broker_creation_time_100ns=0 authority_before_sha256=none authority_after_sha256=none session_name_sha256=none start_status=none session_created=false stop_attempted=false stop_status=none cleanup_count=0 session_absence_proven=false retirement=not-run elapsed_ms=0 deadline_exceeded=false failure_stage=none failure_sha256=none retirement_failure_sha256=none provider_enable_attempted=false consumer_opened=false process_trace_started=false child_bound=false events_collected=0 requested_access_available=false exact_resource_identified=false acl_fix_identified=false primary_failure=original-a release_sent=false workload_executed=false qualification_promoted=false session_name_redacted=true transaction_nonce_redacted=true broker_source_values_redacted=true token_values_redacted=true object_values_redacted=true"
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderSnapsArmedReceiptV2 {
    schema_version: u32,
    transaction_nonce: String,
    request_binding_sha256: String,
    broker_identity: WindowsProcessIdentityV1,
    journal_sha256: String,
    applied_value_sha256: String,
    registry_view: String,
    authority_token_sha256: String,
    receipt_sha256: String,
}

impl LoaderSnapsArmedReceiptV2 {
    fn seal(mut self) -> Result<Self, String> {
        self.receipt_sha256.clear();
        let mut canonical = b"memcordon-loader-snaps-armed-v2\0".to_vec();
        canonical.extend(serde_json::to_vec(&self).map_err(|error| error.to_string())?);
        self.receipt_sha256 = super::record::digest(&canonical);
        Ok(self)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != LOADER_SNAPS_SCHEMA_VERSION
            || !memcordon_core::windows_service_attestation_challenge_is_valid(
                &self.transaction_nonce,
            )
            || self.registry_view != LOADER_SNAPS_REGISTRY_VIEW
            || self.clone().seal()?.receipt_sha256 != self.receipt_sha256
        {
            return Err("loader-snaps armed receipt is invalid".to_owned());
        }
        Ok(())
    }

    pub(crate) fn diagnostic(&self) -> String {
        format!(
            "loader_snaps_armed=v2 transaction_sha256={} request_binding_sha256={} broker_pid={} broker_creation_time_100ns={} journal_sha256={} applied_value_sha256={} registry_view={} authority_token_sha256={} receipt_sha256={}",
            super::record::digest(self.transaction_nonce.as_bytes()),
            self.request_binding_sha256,
            self.broker_identity.process_id,
            self.broker_identity.creation_time_100ns,
            self.journal_sha256,
            self.applied_value_sha256,
            self.registry_view,
            self.authority_token_sha256,
            self.receipt_sha256,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LoaderSnapsRestoreRequestV2 {
    transaction_nonce: String,
    request_binding_sha256: String,
    armed_receipt_sha256: String,
    child_outcome_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderSnapsRestoredReceiptV2 {
    schema_version: u32,
    transaction_nonce: String,
    request_binding_sha256: String,
    broker_identity: WindowsProcessIdentityV1,
    prior_value_sha256: String,
    registry_view: String,
    created_key_disposition: String,
    child_outcome_sha256: String,
    receipt_sha256: String,
}

impl LoaderSnapsRestoredReceiptV2 {
    fn seal(mut self) -> Result<Self, String> {
        self.receipt_sha256.clear();
        let mut canonical = b"memcordon-loader-snaps-restored-v2\0".to_vec();
        canonical.extend(serde_json::to_vec(&self).map_err(|error| error.to_string())?);
        self.receipt_sha256 = super::record::digest(&canonical);
        Ok(self)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != LOADER_SNAPS_SCHEMA_VERSION
            || !memcordon_core::windows_service_attestation_challenge_is_valid(
                &self.transaction_nonce,
            )
            || self.registry_view != LOADER_SNAPS_REGISTRY_VIEW
            || self.clone().seal()?.receipt_sha256 != self.receipt_sha256
        {
            return Err("loader-snaps restored receipt is invalid".to_owned());
        }
        Ok(())
    }

    pub(crate) fn diagnostic(&self) -> String {
        format!(
            "loader_snaps_restored=v2 transaction_sha256={} request_binding_sha256={} broker_pid={} broker_creation_time_100ns={} prior_value_sha256={} registry_view={} created_key_disposition={} child_outcome_sha256={} receipt_sha256={}",
            super::record::digest(self.transaction_nonce.as_bytes()),
            self.request_binding_sha256,
            self.broker_identity.process_id,
            self.broker_identity.creation_time_100ns,
            self.prior_value_sha256,
            self.registry_view,
            self.created_key_disposition,
            self.child_outcome_sha256,
            self.receipt_sha256,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionBrokerLaunchedV1 {
    schema_version: u32,
    start_nonce: String,
    challenge: String,
    broker_identity: WindowsProcessIdentityV1,
    holder_identity: WindowsProcessIdentityV1,
    broker_source: super::token::TokenAttestationSnapshot,
    holder_effective: super::token::TokenAttestationSnapshot,
    holder_query: super::token::TokenQueryAttestationSnapshot,
    holder_process_handle: u64,
    holder_thread_id: u32,
    binding_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
enum SessionBrokerFrameV1 {
    Hello(SessionBrokerHelloV1),
    Request(SessionBrokerRequestV1),
    LoaderSnapsRequest(LoaderSnapsRequestV2),
    TraceSessionCapabilityRequest(TraceSessionCapabilityRequestV1),
    TraceSessionCapabilityReceipt(TraceSessionCapabilityReceiptV1),
    TraceSessionCapabilityFailed(TraceSessionCapabilityFailureV1),
    Launched(SessionBrokerLaunchedV1),
    Ack {
        binding_sha256: String,
    },
    Arm {
        binding_sha256: String,
        holder_binding_sha256: String,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: super::token::TokenQueryAttestationSnapshot,
    },
    Armed {
        binding_sha256: String,
        holder_binding_sha256: String,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        carrier: super::token::TokenAttestationSnapshot,
    },
    Consumed {
        binding_sha256: String,
        holder_binding_sha256: String,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: super::token::TokenQueryAttestationSnapshot,
        native_code: Option<i32>,
        thread_token_absent: bool,
    },
    Cleared {
        binding_sha256: String,
        holder_binding_sha256: String,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
    },
    FinalAck {
        binding_sha256: String,
        holder_binding_sha256: String,
        completed_phases: u32,
    },
    Done {
        binding_sha256: String,
    },
    LoaderSnapsArmed(LoaderSnapsArmedReceiptV2),
    LoaderSnapsRestore(LoaderSnapsRestoreRequestV2),
    LoaderSnapsRestored(LoaderSnapsRestoredReceiptV2),
    LoaderSnapsFailed(LoaderSnapsFailureV2),
    Failed {
        stage: SessionBrokerStageV1,
        detail: String,
    },
}

pub(crate) struct BrokeredHolder {
    pub process: OwnedHandle,
    pub thread: OwnedHandle,
    pub identity: WindowsProcessIdentityV1,
    pub broker_source: super::token::TokenAttestationSnapshot,
    pub holder_effective: super::token::TokenAttestationSnapshot,
    pub query: super::token::TokenQueryAttestationSnapshot,
    launch_binding_sha256: String,
    pub control: Option<BrokerControlLease>,
}

pub(crate) struct BrokerControlLease {
    pipe: Option<OwnedHandle>,
    service: super::service_manager::ScHandle,
    broker: super::service_manager::PinnedServiceProcess,
    launch_binding_sha256: String,
    holder_binding_sha256: Option<String>,
    completed_phases: u32,
    finalized: bool,
    _transaction_lease: std::sync::MutexGuard<'static, ()>,
}

pub(crate) struct LoaderSnapsControlLease {
    pipe: Option<OwnedHandle>,
    service: super::service_manager::ScHandle,
    broker: super::service_manager::PinnedServiceProcess,
    request: LoaderSnapsRequestV2,
    armed: LoaderSnapsArmedReceiptV2,
    finalized: bool,
    _transaction_lease: std::sync::MutexGuard<'static, ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerClientOperation {
    Holder,
    LoaderSnaps,
    TraceSessionCapability,
}

impl BrokerClientOperation {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Holder => "holder",
            Self::LoaderSnaps => "loader-snaps",
            Self::TraceSessionCapability => "trace-session-capability",
        }
    }

    fn startup_failure(
        self,
        stage: BrokerClientStartupStage,
        detail: impl ToString,
    ) -> BrokerClientStartupError {
        BrokerClientStartupError::new(self, stage, detail)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerClientStartupStage {
    TransactionLease,
    StartNonce,
    ManagerConnect,
    ServiceOpen,
    InitialStatus,
    DemandStart,
    PipeConnect,
    PeerAuthentication,
    ServicePin,
    HelloRead,
    HelloValidation,
    SourceValidation,
    SourceBinding,
}

impl BrokerClientStartupStage {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::TransactionLease => "transaction-lease",
            Self::StartNonce => "start-nonce",
            Self::ManagerConnect => "manager-connect",
            Self::ServiceOpen => "service-open",
            Self::InitialStatus => "initial-status",
            Self::DemandStart => "demand-start",
            Self::PipeConnect => "pipe-connect",
            Self::PeerAuthentication => "peer-authentication",
            Self::ServicePin => "service-pin",
            Self::HelloRead => "hello-read",
            Self::HelloValidation => "hello-validation",
            Self::SourceValidation => "source-validation",
            Self::SourceBinding => "source-binding",
        }
    }
}

#[derive(Debug)]
struct BrokerClientStartupError {
    operation: BrokerClientOperation,
    stage: BrokerClientStartupStage,
    detail: String,
}

impl BrokerClientStartupError {
    fn new(
        operation: BrokerClientOperation,
        stage: BrokerClientStartupStage,
        detail: impl ToString,
    ) -> Self {
        Self {
            operation,
            stage,
            detail: detail.to_string(),
        }
    }

    fn append_retirement(mut self, detail: impl ToString) -> Self {
        self.detail = bounded_broker_detail(format!(
            "{}; exact_broker_retirement_error={}",
            self.detail,
            detail.to_string(),
        ));
        self
    }

    fn holder_diagnostic(self) -> String {
        format!(
            "role=session-broker operation={} stage={} detail={}",
            self.operation.diagnostic(),
            self.stage.diagnostic(),
            self.detail,
        )
    }

    fn loader_snaps_failure(self) -> LoaderSnapsFailureV2 {
        let stage = match self.stage {
            BrokerClientStartupStage::TransactionLease => LoaderSnapsStageV2::TransactionLease,
            BrokerClientStartupStage::SourceValidation
            | BrokerClientStartupStage::SourceBinding => LoaderSnapsStageV2::Authority,
            _ => LoaderSnapsStageV2::BrokerProtocol,
        };
        loader_snaps_client_failure(
            stage,
            "unbound",
            format!(
                "operation={} stage={} detail={}",
                self.operation.diagnostic(),
                self.stage.diagnostic(),
                self.detail,
            ),
        )
    }
}

struct AuthenticatedBrokerClient {
    pipe: Option<OwnedHandle>,
    service: Option<super::service_manager::ScHandle>,
    broker: Option<super::service_manager::PinnedServiceProcess>,
    hello: SessionBrokerHelloV1,
    broker_source_query: super::token::TokenQueryAttestationSnapshot,
    transaction_lease: Option<std::sync::MutexGuard<'static, ()>>,
}

impl AuthenticatedBrokerClient {
    fn pipe(&self) -> &OwnedHandle {
        self.pipe
            .as_ref()
            .expect("authenticated broker client pipe must remain owned")
    }

    fn broker(&self) -> &super::service_manager::PinnedServiceProcess {
        self.broker
            .as_ref()
            .expect("authenticated broker client process must remain owned")
    }

    fn retire(mut self) -> Result<(), String> {
        drop(self.pipe.take());
        let retirement = retire_authenticated_broker(
            self.service
                .as_ref()
                .expect("authenticated broker client service must remain owned"),
            self.broker(),
        );
        drop(self.broker.take());
        drop(self.service.take());
        drop(self.transaction_lease.take());
        retirement
    }

    fn into_holder_control(mut self, launch_binding_sha256: String) -> BrokerControlLease {
        BrokerControlLease {
            pipe: self.pipe.take(),
            service: self
                .service
                .take()
                .expect("authenticated broker client service must transfer"),
            broker: self
                .broker
                .take()
                .expect("authenticated broker client process must transfer"),
            launch_binding_sha256,
            holder_binding_sha256: None,
            completed_phases: 0,
            finalized: false,
            _transaction_lease: self
                .transaction_lease
                .take()
                .expect("authenticated broker transaction lease must transfer"),
        }
    }

    fn into_loader_snaps_control(
        mut self,
        request: LoaderSnapsRequestV2,
        armed: LoaderSnapsArmedReceiptV2,
    ) -> LoaderSnapsControlLease {
        LoaderSnapsControlLease {
            pipe: self.pipe.take(),
            service: self
                .service
                .take()
                .expect("authenticated broker client service must transfer"),
            broker: self
                .broker
                .take()
                .expect("authenticated broker client process must transfer"),
            request,
            armed,
            finalized: false,
            _transaction_lease: self
                .transaction_lease
                .take()
                .expect("authenticated broker transaction lease must transfer"),
        }
    }
}

impl Drop for AuthenticatedBrokerClient {
    fn drop(&mut self) {
        drop(self.pipe.take());
        if let (Some(service), Some(broker)) = (self.service.as_ref(), self.broker.as_ref()) {
            if let Err(error) = retire_authenticated_broker(service, broker) {
                eprintln!(
                    "MCSEALED-WINDOWS-SESSION-BROKER: authenticated bootstrap cleanup failed: {error}"
                );
            }
        }
        drop(self.broker.take());
        drop(self.service.take());
        drop(self.transaction_lease.take());
    }
}

impl LoaderSnapsControlLease {
    pub(crate) fn armed_diagnostic(&self) -> String {
        self.armed.diagnostic()
    }

    pub(crate) fn restore(
        mut self,
        child_outcome_sha256: String,
    ) -> Result<LoaderSnapsRestoredReceiptV2, LoaderSnapsFailureV2> {
        super::record::validate_attempt_id(&child_outcome_sha256).map_err(|error| {
            loader_snaps_client_failure(
                LoaderSnapsStageV2::BrokerProtocol,
                &self.request.binding_sha256,
                error,
            )
        })?;
        let pipe = self.pipe.as_ref().ok_or_else(|| {
            loader_snaps_client_failure(
                LoaderSnapsStageV2::BrokerProtocol,
                &self.request.binding_sha256,
                "loader-snaps control pipe is absent before restoration",
            )
        })?;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsRestoreWrite,
            &SessionBrokerFrameV1::LoaderSnapsRestore(LoaderSnapsRestoreRequestV2 {
                transaction_nonce: self.request.transaction_nonce.clone(),
                request_binding_sha256: self.request.binding_sha256.clone(),
                armed_receipt_sha256: self.armed.receipt_sha256.clone(),
                child_outcome_sha256: child_outcome_sha256.clone(),
            }),
        )
        .map_err(|error| {
            loader_snaps_client_failure(
                LoaderSnapsStageV2::BrokerProtocol,
                &self.request.binding_sha256,
                error,
            )
        })?;
        let restored = match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsRestoredRead,
        )
        .map_err(|error| {
            loader_snaps_client_failure(
                LoaderSnapsStageV2::BrokerProtocol,
                &self.request.binding_sha256,
                error,
            )
        })? {
            SessionBrokerFrameV1::LoaderSnapsRestored(receipt) => receipt,
            SessionBrokerFrameV1::LoaderSnapsFailed(failure) => return Err(failure),
            _ => {
                return Err(loader_snaps_client_failure(
                    LoaderSnapsStageV2::BrokerProtocol,
                    &self.request.binding_sha256,
                    "session broker returned an invalid loader-snaps restore frame",
                ));
            }
        };
        restored.validate().map_err(|error| {
            loader_snaps_client_failure(
                LoaderSnapsStageV2::BrokerProtocol,
                &self.request.binding_sha256,
                error,
            )
        })?;
        if restored.transaction_nonce != self.request.transaction_nonce
            || restored.request_binding_sha256 != self.request.binding_sha256
            || restored.broker_identity != self.broker.identity
            || restored.child_outcome_sha256 != child_outcome_sha256
        {
            return Err(loader_snaps_client_failure(
                LoaderSnapsStageV2::BrokerProtocol,
                &self.request.binding_sha256,
                "loader-snaps restored receipt binding is mismatched",
            ));
        }
        drop(self.pipe.take());
        retire_authenticated_broker(&self.service, &self.broker).map_err(|error| {
            loader_snaps_client_failure(
                LoaderSnapsStageV2::BrokerRetire,
                &self.request.binding_sha256,
                error,
            )
        })?;
        self.finalized = true;
        Ok(restored)
    }
}

impl Drop for LoaderSnapsControlLease {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        drop(self.pipe.take());
        if let Err(error) = retire_authenticated_broker(&self.service, &self.broker) {
            eprintln!(
                "MCSEALED-WINDOWS-SESSION-BROKER: loader-snaps broker retirement failed: {error}"
            );
        }
    }
}

impl BrokerControlLease {
    pub(crate) fn arm(
        &mut self,
        holder_binding_sha256: &str,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: &super::token::TokenQueryAttestationSnapshot,
    ) -> Result<super::token::TokenAttestationSnapshot, String> {
        if ordinal != self.completed_phases + 1 || thread_id == 0 {
            return Err("session broker arm request is out of order or has zero TID".to_owned());
        }
        match &self.holder_binding_sha256 {
            Some(expected) if expected != holder_binding_sha256 => {
                return Err("session broker holder binding changed between phases".to_owned());
            }
            None => self.holder_binding_sha256 = Some(holder_binding_sha256.to_owned()),
            _ => {}
        }
        let pipe = self
            .pipe
            .as_ref()
            .ok_or_else(|| "session broker control pipe is absent".to_owned())?;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerArmWrite,
            &SessionBrokerFrameV1::Arm {
                binding_sha256: self.launch_binding_sha256.clone(),
                holder_binding_sha256: holder_binding_sha256.to_owned(),
                phase,
                ordinal,
                thread_id,
                holder_primary: holder_primary.clone(),
            },
        )
        .map_err(|error| error.to_string())?;
        match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerArmedRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerFrameV1::Armed {
                binding_sha256,
                holder_binding_sha256: observed_holder_binding,
                phase: observed_phase,
                ordinal: observed_ordinal,
                thread_id: observed_thread_id,
                carrier,
            } if binding_sha256 == self.launch_binding_sha256
                && observed_holder_binding == holder_binding_sha256
                && observed_phase == phase
                && observed_ordinal == ordinal
                && observed_thread_id == thread_id =>
            {
                Ok(carrier)
            }
            _ => Err("session broker returned an invalid Armed frame".to_owned()),
        }
    }

    pub(crate) fn consumed(
        &mut self,
        holder_binding_sha256: &str,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: &super::token::TokenQueryAttestationSnapshot,
        native_code: Option<i32>,
        thread_token_absent: bool,
    ) -> Result<(), String> {
        if self.holder_binding_sha256.as_deref() != Some(holder_binding_sha256)
            || ordinal != self.completed_phases + 1
        {
            return Err("session broker Consumed evidence is out of order".to_owned());
        }
        let pipe = self
            .pipe
            .as_ref()
            .ok_or_else(|| "session broker control pipe is absent".to_owned())?;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerConsumedWrite,
            &SessionBrokerFrameV1::Consumed {
                binding_sha256: self.launch_binding_sha256.clone(),
                holder_binding_sha256: holder_binding_sha256.to_owned(),
                phase,
                ordinal,
                thread_id,
                holder_primary: holder_primary.clone(),
                native_code,
                thread_token_absent,
            },
        )
        .map_err(|error| error.to_string())?;
        match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerClearedRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerFrameV1::Cleared {
                binding_sha256,
                holder_binding_sha256: observed_holder_binding,
                phase: observed_phase,
                ordinal: observed_ordinal,
                thread_id: observed_thread_id,
            } if binding_sha256 == self.launch_binding_sha256
                && observed_holder_binding == holder_binding_sha256
                && observed_phase == phase
                && observed_ordinal == ordinal
                && observed_thread_id == thread_id =>
            {
                self.completed_phases = ordinal;
                Ok(())
            }
            _ => Err("session broker returned an invalid Cleared frame".to_owned()),
        }
    }

    pub(crate) fn finish(mut self, holder_binding_sha256: &str) -> Result<(), String> {
        if self.holder_binding_sha256.as_deref() != Some(holder_binding_sha256) {
            return Err("session broker final holder binding is mismatched".to_owned());
        }
        let pipe = self
            .pipe
            .as_ref()
            .ok_or_else(|| "session broker control pipe is absent".to_owned())?;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerFinalAckWrite,
            &SessionBrokerFrameV1::FinalAck {
                binding_sha256: self.launch_binding_sha256.clone(),
                holder_binding_sha256: holder_binding_sha256.to_owned(),
                completed_phases: self.completed_phases,
            },
        )
        .map_err(|error| error.to_string())?;
        match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerDoneRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerFrameV1::Done { binding_sha256 }
                if binding_sha256 == self.launch_binding_sha256 => {}
            _ => return Err("session broker returned an invalid Done frame".to_owned()),
        }
        drop(self.pipe.take());
        retire_authenticated_broker(&self.service, &self.broker)?;
        self.finalized = true;
        Ok(())
    }
}

impl Drop for BrokerControlLease {
    fn drop(&mut self) {
        if !self.finalized {
            drop(self.pipe.take());
            if let Err(error) = retire_authenticated_broker(&self.service, &self.broker) {
                eprintln!("MCSEALED-WINDOWS-SESSION-BROKER: control lease cleanup failed: {error}");
            }
        }
    }
}

pub fn run() -> Result<(), String> {
    super::service::dispatch(
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        BROKER_ROLE,
        service_main,
    )
}

unsafe extern "system" fn service_main(count: u32, arguments: *mut *mut u16) {
    if let Err(error) =
        unsafe { super::service::announce_starting(WINDOWS_SESSION_BROKER_SERVICE_NAME) }
    {
        eprintln!("{error}");
        return;
    }
    let result = unsafe { broker_service_transaction(count, arguments) };
    match result {
        Ok(()) => super::service::announce_stopped(0),
        Err(error) => {
            eprintln!("MCSEALED-WINDOWS-SESSION-BROKER: {}", error.detail);
            super::service::announce_startup_failed(error.stage.service_exit());
        }
    }
}

unsafe fn broker_service_transaction(
    count: u32,
    arguments: *mut *mut u16,
) -> Result<(), SessionBrokerServiceError> {
    let arguments = unsafe { decode_service_arguments(count, arguments) }.map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::Arguments, error)
    })?;
    let start_nonce = validate_broker_service_arguments(&arguments).map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::Arguments, error)
    })?;
    validate_broker_start_nonce(start_nonce).map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::NonceValidation, error)
    })?;
    let normalized_broker_source =
        super::token::normalize_current_session_broker_source_privileges().map_err(|error| {
            SessionBrokerServiceError::startup(
                SessionBrokerStartupStage::SourcePrivilegeNormalization,
                error.to_string(),
            )
        })?;
    super::security::protect_current_session_broker()
        .map_err(SessionBrokerServiceError::process_protection)?;
    certify_current_broker().map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::Certification, error)
    })?;
    recover_loader_snaps_journal().map_err(|error| {
        SessionBrokerServiceError::startup(
            SessionBrokerStartupStage::Transaction,
            error.diagnostic(),
        )
    })?;
    let pipe_security = super::security::session_broker_pipe_sddl()
        .and_then(|sddl| super::security::SecurityDescriptor::from_sddl(&sddl))
        .map_err(|error| {
            SessionBrokerServiceError::startup(
                SessionBrokerStartupStage::ListenerPreparation,
                error,
            )
        })?;
    let listener = super::pipe::PipeListener::new(WINDOWS_SESSION_BROKER_PIPE, pipe_security);
    let prepared = listener.prepare().map_err(|error| {
        SessionBrokerServiceError::startup(
            SessionBrokerStartupStage::ListenerPreparation,
            error.to_string(),
        )
    })?;
    super::service::announce_running().map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::RunningPublication, error)
    })?;
    let pipe = listener.accept_prepared(prepared)?;
    if super::service::stop_requested() {
        return Ok(());
    }
    let (launcher_process, launcher_identity) = authenticate_launcher_client(pipe.raw())?;
    let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
    let broker_identity = super::process::process_identity(unsafe { GetCurrentProcess() })?;
    let challenge = super::token::service_attestation_challenge("session-broker")
        .map_err(|error| error.to_string())?;
    let hello = SessionBrokerHelloV1 {
        schema_version: SESSION_BROKER_SCHEMA_VERSION,
        service_name: WINDOWS_SESSION_BROKER_SERVICE_NAME.to_owned(),
        broker_identity: broker_identity.clone(),
        broker_image_sha256: super::package::validate_installed_session_broker()?,
        broker_source: normalized_broker_source.clone(),
        challenge: challenge.clone(),
        start_nonce: start_nonce.to_owned(),
    };
    super::pipe::write_frame_bounded(
        pipe.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerHelloWrite,
        &SessionBrokerFrameV1::Hello(hello.clone()),
    )
    .map_err(|error| error.to_string())?;
    let request_frame = super::pipe::read_frame_bounded(
        pipe.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerRequestRead,
    )
    .map_err(|error| error.to_string())?;
    let request = match request_frame {
        SessionBrokerFrameV1::Request(request) => request,
        SessionBrokerFrameV1::LoaderSnapsRequest(request) => {
            return run_loader_snaps_authority_transaction(
                pipe.raw(),
                launcher_process.raw(),
                &hello,
                &launcher_identity,
                request,
            )
            .map_err(|error| {
                SessionBrokerServiceError::startup(SessionBrokerStartupStage::Transaction, error)
            });
        }
        SessionBrokerFrameV1::TraceSessionCapabilityRequest(request) => {
            return run_trace_session_capability_authority_transaction(
                pipe.raw(),
                launcher_process.raw(),
                &hello,
                &launcher_identity,
                request,
            )
            .map_err(|error| {
                SessionBrokerServiceError::startup(SessionBrokerStartupStage::Transaction, error)
            });
        }
        _ => {
            return Err("session broker expected Request after Hello"
                .to_owned()
                .into());
        }
    };
    if let Err(error) = validate_request(&request, &hello, &launcher_identity) {
        let _ = super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(launcher_process.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
            &SessionBrokerFrameV1::Failed {
                stage: SessionBrokerStageV1::RequestValidation,
                detail: bounded_broker_detail(error.clone()),
            },
        );
        return Err(error.into());
    }
    let mut holder = match super::process::create_session_broker_holder(
        request.target_session_id,
        &request.holder_pipe_name,
        &request.holder_nonce,
        launcher_process.raw(),
        request.launcher_job_handle,
    ) {
        Ok(holder) if holder.broker_source == normalized_broker_source => holder,
        Ok(mut holder) => {
            holder.terminate();
            let error =
                "session broker source changed between startup normalization and holder derivation"
                    .to_owned();
            let _ = super::pipe::write_frame_bounded(
                pipe.raw(),
                Some(launcher_process.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
                &SessionBrokerFrameV1::Failed {
                    stage: SessionBrokerStageV1::HolderCreation,
                    detail: bounded_broker_detail(error.clone()),
                },
            );
            return Err(error.into());
        }
        Err(error) => {
            let detail = bounded_broker_detail(error.clone());
            let _ = super::pipe::write_frame_bounded(
                pipe.raw(),
                Some(launcher_process.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
                &SessionBrokerFrameV1::Failed {
                    stage: SessionBrokerStageV1::HolderCreation,
                    detail,
                },
            );
            return Err(error.into());
        }
    };
    let mut transfer_rollback = LauncherHandleTransferRollback::new(launcher_process.raw());
    let remote_process = match duplicate_into_launcher(
        holder.process.raw(),
        launcher_process.raw(),
        HOLDER_PROCESS_TRANSFER_ACCESS,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            holder.terminate();
            let _ = super::pipe::write_frame_bounded(
                pipe.raw(),
                Some(launcher_process.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
                &SessionBrokerFrameV1::Failed {
                    stage: SessionBrokerStageV1::HandleTransfer,
                    detail: bounded_broker_detail(error.clone()),
                },
            );
            return Err(error.into());
        }
    };
    transfer_rollback.record_process(remote_process);
    let mut launched = SessionBrokerLaunchedV1 {
        schema_version: SESSION_BROKER_SCHEMA_VERSION,
        start_nonce: start_nonce.to_owned(),
        challenge,
        broker_identity,
        holder_identity: holder.identity.clone(),
        broker_source: holder.broker_source.clone(),
        holder_effective: holder.holder_effective.clone(),
        holder_query: holder.query.clone(),
        holder_process_handle: remote_process,
        holder_thread_id: holder.primary_thread_id,
        binding_sha256: String::new(),
    };
    launched.binding_sha256 = match launched_binding_sha256(&request, &launched) {
        Ok(binding) => binding,
        Err(error) => {
            holder.terminate();
            return Err(transfer_rollback.failure_detail(error).into());
        }
    };
    if let Err(error) = super::pipe::write_frame_bounded(
        pipe.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
        &SessionBrokerFrameV1::Launched(launched.clone()),
    ) {
        holder.terminate();
        return Err(transfer_rollback.failure_detail(error.to_string()).into());
    }
    transfer_rollback.disarm_after_launched_delivery();
    let acknowledgement = super::pipe::read_frame_bounded(
        pipe.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerAckRead,
    );
    match acknowledgement {
        Ok(SessionBrokerFrameV1::Ack { binding_sha256 })
            if binding_sha256 == launched.binding_sha256 => {}
        Ok(_) => {
            holder.terminate();
            return Err("session broker received an invalid holder acknowledgement"
                .to_owned()
                .into());
        }
        Err(error) => {
            holder.terminate();
            return Err(error.to_string().into());
        }
    }
    run_creation_authority_transaction(pipe.raw(), launcher_process.raw(), &launched, &mut holder)?;
    Ok(())
}

fn validate_loader_snaps_request(
    request: &LoaderSnapsRequestV2,
    hello: &SessionBrokerHelloV1,
    launcher_identity: &WindowsProcessIdentityV1,
) -> Result<(), LoaderSnapsFailureV2> {
    let failure = |detail: &str| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::BrokerProtocol,
            "validate-loader-snaps-request",
            None,
            0,
            &request.binding_sha256,
            "not-started",
            "not-started",
            "not-needed",
            detail,
        )
    };
    let contract = super::package::installed_target_desktop_bootstrap_contract()
        .map_err(|error| failure(&error))?;
    let expected_path_sha256 = super::record::digest(
        super::package::installed_target_desktop_bootstrap()
            .to_string_lossy()
            .to_ascii_lowercase()
            .as_bytes(),
    );
    if request.schema_version != LOADER_SNAPS_SCHEMA_VERSION
        || request.start_nonce != hello.start_nonce
        || request.challenge != hello.challenge
        || &request.launcher_identity != launcher_identity
        || request
            .calculated_sha256()
            .map_err(|error| failure(&error))?
            != request.binding_sha256
        || request.binding.image_path_sha256 != expected_path_sha256
        || request.binding.image_sha256 != contract.sha256
        || request.binding.native_machine != contract.imports.machine
        || !request.binding.matrix_cell.ends_with("snaps-on")
    {
        return Err(failure(
            "loader-snaps request admission/image/view binding is mismatched",
        ));
    }
    for digest in [
        &request.binding_sha256,
        &request.binding.admission_sha256,
        &request.binding.target_token_sha256,
        &request.binding.association_preflight_sha256,
    ] {
        super::record::validate_attempt_id(digest).map_err(|error| failure(&error))?;
    }
    if !memcordon_core::windows_service_attestation_challenge_is_valid(&request.transaction_nonce) {
        return Err(failure("loader-snaps transaction nonce is invalid"));
    }
    if request.binding.holder_identity.process_id == 0
        || request.binding.holder_identity.creation_time_100ns == 0
        || request.binding.holder_identity == *launcher_identity
        || request.binding.holder_identity == hello.broker_identity
    {
        return Err(failure(
            "loader-snaps same-basename holder identity is invalid",
        ));
    }
    let holder_access = SYNCHRONIZE_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION;
    let raw_holder =
        unsafe { OpenProcess(holder_access, 0, request.binding.holder_identity.process_id) };
    let holder_open_native = io::Error::last_os_error().raw_os_error();
    let holder = OwnedHandle::new(raw_holder).map_err(|error| {
        LoaderSnapsFailureV2::new(
            LoaderSnapsStageV2::Authority,
            "OpenProcess(holder)",
            holder_open_native,
            holder_access,
            &request.binding_sha256,
            "not-started",
            "not-started",
            "not-needed",
            error,
        )
    })?;
    verify_exact_handle(
        holder.raw(),
        holder_access,
        holder_access,
        "loader-snaps-holder-process",
        "same-basename-live-proof",
    )
    .map_err(|error| failure(&error))?;
    if super::process::process_identity(holder.raw()).map_err(|error| failure(&error))?
        != request.binding.holder_identity
        || unsafe { WaitForSingleObject(holder.raw(), 0) } != WAIT_TIMEOUT
    {
        return Err(failure(
            "loader-snaps same-basename holder is not the exact live admitted process",
        ));
    }
    super::process::verify_image_path(
        holder.raw(),
        &super::package::installed_target_desktop_bootstrap(),
    )
    .map_err(|error| failure(&error))?;
    Ok(())
}

fn run_loader_snaps_authority_transaction(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    launcher_process: windows_sys::Win32::Foundation::HANDLE,
    hello: &SessionBrokerHelloV1,
    launcher_identity: &WindowsProcessIdentityV1,
    request: LoaderSnapsRequestV2,
) -> Result<(), String> {
    let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
    if let Err(failure) = validate_loader_snaps_request(&request, hello, launcher_identity) {
        let _ = super::pipe::write_frame_bounded(
            pipe,
            Some(launcher_process),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsArmedWrite,
            &SessionBrokerFrameV1::LoaderSnapsFailed(failure.clone()),
        );
        return Err(failure.diagnostic());
    }
    let (transaction, armed) = match LoaderSnapsTransactionV2::begin(&request, hello) {
        Ok(value) => value,
        Err(mut failure) => {
            if let Err(recovery) = recover_loader_snaps_journal() {
                failure.detail = bounded_broker_detail(format!(
                    "{}; broker_owned_recovery_failure={}",
                    failure.detail,
                    recovery.diagnostic()
                ));
                failure.restoration = "recovery-failed".to_owned();
            }
            let _ = super::pipe::write_frame_bounded(
                pipe,
                Some(launcher_process),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsArmedWrite,
                &SessionBrokerFrameV1::LoaderSnapsFailed(failure.clone()),
            );
            return Err(failure.diagnostic());
        }
    };
    if let Err(error) = super::pipe::write_frame_bounded(
        pipe,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsArmedWrite,
        &SessionBrokerFrameV1::LoaderSnapsArmed(armed.clone()),
    ) {
        let primary = error.to_string();
        let child = super::record::digest(b"armed-receipt-delivery-failed");
        return match transaction.restore(child) {
            Ok(_) => Err(primary),
            Err(restoration) => Err(format!(
                "{primary}; mandatory_restoration_failure={}",
                restoration.diagnostic()
            )),
        };
    }
    let restore_frame: SessionBrokerFrameV1 = match super::pipe::read_frame_bounded(
        pipe,
        Some(launcher_process),
        Instant::now() + BROKER_TRANSACTION_DEADLINE,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsRestoreRead,
    ) {
        Ok(frame) => frame,
        Err(error) => {
            let primary = error.to_string();
            let child = super::record::digest(b"restore-request-delivery-failed");
            return match transaction.restore(child) {
                Ok(_) => Err(primary),
                Err(restoration) => Err(format!(
                    "{primary}; mandatory_restoration_failure={}",
                    restoration.diagnostic()
                )),
            };
        }
    };
    let child_outcome_sha256 = match restore_frame {
        SessionBrokerFrameV1::LoaderSnapsRestore(restore)
            if restore.transaction_nonce == request.transaction_nonce
                && restore.request_binding_sha256 == request.binding_sha256
                && restore.armed_receipt_sha256 == armed.receipt_sha256
                && super::record::validate_attempt_id(&restore.child_outcome_sha256).is_ok() =>
        {
            restore.child_outcome_sha256
        }
        _ => {
            let child = super::record::digest(b"invalid-restore-request");
            let restoration = transaction.restore(child);
            return Err(match restoration {
                Ok(_) => "loader-snaps broker rejected an invalid restore request".to_owned(),
                Err(error) => format!(
                    "loader-snaps broker rejected an invalid restore request; mandatory_restoration_failure={}",
                    error.diagnostic()
                ),
            });
        }
    };
    let restored = match transaction.restore(child_outcome_sha256) {
        Ok(receipt) => receipt,
        Err(failure) => {
            let _ = super::pipe::write_frame_bounded(
                pipe,
                Some(launcher_process),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsRestoredWrite,
                &SessionBrokerFrameV1::LoaderSnapsFailed(failure.clone()),
            );
            return Err(failure.diagnostic());
        }
    };
    super::pipe::write_frame_bounded(
        pipe,
        Some(launcher_process),
        Instant::now() + BROKER_TRANSACTION_DEADLINE,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsRestoredWrite,
        &SessionBrokerFrameV1::LoaderSnapsRestored(restored),
    )
    .map_err(|error| error.to_string())
}

fn trace_session_capability_source_sha256(
    identity: &WindowsProcessIdentityV1,
    source: &super::token::TokenAttestationSnapshot,
    query: &super::token::TokenQueryAttestationSnapshot,
) -> Result<String, String> {
    let mut canonical = b"memcordon-session-broker-trace-capability-authority-v1\0".to_vec();
    canonical
        .extend(serde_json::to_vec(&(identity, source, query)).map_err(|error| error.to_string())?);
    Ok(super::record::digest(&canonical))
}

fn attest_trace_session_capability_authority(
    hello: &SessionBrokerHelloV1,
) -> Result<String, String> {
    if !super::package::ephemeral_ci_enabled() {
        return Err("trace-session capability requires ephemeral qualification mode".to_owned());
    }
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() })?;
    let identity = super::process::process_identity(unsafe { GetCurrentProcess() })?;
    if identity != hello.broker_identity {
        return Err("trace-session capability broker process identity changed".to_owned());
    }
    let token = super::token::current_process_token_for_attestation()?;
    let source = super::token::token_attestation_snapshot(token.raw())?;
    super::token::validate_normalized_session_broker_source_snapshot(&source)
        .map_err(|error| error.to_string())?;
    if source != hello.broker_source {
        return Err("trace-session capability normalized broker source changed".to_owned());
    }
    let query = super::token::process_token_query_attestation(unsafe { GetCurrentProcess() })?;
    super::token::require_same_process_token_query(
        "trace-session-capability-live-source",
        &source.query_evidence(),
        &query,
    )
    .map_err(|error| error.to_string())?;
    trace_session_capability_source_sha256(&identity, &source, &query)
}

fn trace_session_capability_failure(
    request_binding_sha256: &str,
    stage: &'static str,
    detail: impl ToString,
) -> TraceSessionCapabilityFailureV1 {
    TraceSessionCapabilityFailureV1 {
        capability_schema_version: TRACE_SESSION_CAPABILITY_SCHEMA_VERSION,
        request_binding_sha256: request_binding_sha256.to_owned(),
        stage: stage.to_owned(),
        detail_sha256: super::record::digest(detail.to_string().as_bytes()),
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_trace_session_capability_native(
    authority_equal: bool,
    deadline_exceeded: bool,
    start_status: u32,
    session_created: bool,
    stop_attempted: bool,
    stop_status: Option<u32>,
    cleanup_count: u32,
    session_absence_proven: bool,
) -> TraceSessionCapabilityStateV1 {
    if authority_equal
        && !deadline_exceeded
        && start_status == ERROR_SUCCESS
        && session_created
        && stop_attempted
        && stop_status == Some(ERROR_SUCCESS)
        && cleanup_count == 1
        && session_absence_proven
    {
        TraceSessionCapabilityStateV1::BrokerSessionAvailable
    } else if authority_equal
        && !deadline_exceeded
        && start_status != ERROR_SUCCESS
        && start_status != ERROR_ALREADY_EXISTS
        && !session_created
        && !stop_attempted
        && stop_status.is_none()
        && cleanup_count == 0
        && session_absence_proven
    {
        TraceSessionCapabilityStateV1::BrokerSessionUnavailable
    } else {
        TraceSessionCapabilityStateV1::BrokerSessionInvalid
    }
}

fn validate_trace_session_capability_request(
    request: &TraceSessionCapabilityRequestV1,
    hello: &SessionBrokerHelloV1,
    launcher_identity: &WindowsProcessIdentityV1,
) -> Result<(), String> {
    if request.capability_schema_version != TRACE_SESSION_CAPABILITY_SCHEMA_VERSION
        || request.broker_schema_version != SESSION_BROKER_SCHEMA_VERSION
        || request.start_nonce != hello.start_nonce
        || request.challenge != hello.challenge
        || &request.launcher_identity != launcher_identity
        || request.broker_identity != hello.broker_identity
        || request.trigger_reason
            != TraceSessionCapabilityTriggerReasonV1::StableModuleZeroPrefixNonlocalizing
        || !request.ephemeral_ci
        || !super::package::ephemeral_ci_enabled()
        || request.calculated_sha256()? != request.request_binding_sha256
    {
        return Err("trace-session capability request binding is invalid".to_owned());
    }
    if request.launcher_identity.process_id == 0
        || request.launcher_identity.creation_time_100ns == 0
        || request.broker_identity.process_id == 0
        || request.broker_identity.creation_time_100ns == 0
        || request.launcher_identity == request.broker_identity
    {
        return Err("trace-session capability process identities are invalid".to_owned());
    }
    if !memcordon_core::windows_service_attestation_challenge_is_valid(&request.transaction_nonce) {
        return Err("trace-session capability transaction nonce is invalid".to_owned());
    }
    for digest in [
        &request.broker_source_sha256,
        &request.trigger_sha256,
        &request.request_binding_sha256,
    ] {
        super::record::validate_attempt_id(digest)?;
    }
    Ok(())
}

fn run_trace_session_capability_authority_transaction(
    pipe: HANDLE,
    launcher_process: HANDLE,
    hello: &SessionBrokerHelloV1,
    launcher_identity: &WindowsProcessIdentityV1,
    request: TraceSessionCapabilityRequestV1,
) -> Result<(), String> {
    let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
    let send_failure = |stage: &'static str, detail: &str| {
        let _ = super::pipe::write_frame_bounded(
            pipe,
            Some(launcher_process),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerTraceSessionCapabilityReceiptWrite,
            &SessionBrokerFrameV1::TraceSessionCapabilityFailed(
                trace_session_capability_failure(&request.request_binding_sha256, stage, detail),
            ),
        );
    };
    if let Err(error) =
        validate_trace_session_capability_request(&request, hello, launcher_identity)
    {
        send_failure("request-validation", &error);
        return Err(error);
    }
    let expected_source = trace_session_capability_source_sha256(
        &hello.broker_identity,
        &hello.broker_source,
        &hello.broker_source.query_evidence(),
    )?;
    if request.broker_source_sha256 != expected_source {
        let error = "trace-session capability Hello source binding is invalid".to_owned();
        send_failure("source-binding", &error);
        return Err(error);
    }
    let authority_before_sha256 = match attest_trace_session_capability_authority(hello) {
        Ok(value) => value,
        Err(error) => {
            send_failure("authority-before", &error);
            return Err(error);
        }
    };
    if authority_before_sha256 != request.broker_source_sha256 {
        let error = "trace-session capability before-authority binding is invalid".to_owned();
        send_failure("authority-before", &error);
        return Err(error);
    }
    let started = Instant::now();
    let native = super::access_trace::run_trace_session_capability(
        &request.start_nonce,
        &request.transaction_nonce,
        hello.broker_identity.process_id,
        hello.broker_identity.creation_time_100ns,
    )?;
    let authority_after_sha256 =
        attest_trace_session_capability_authority(hello).unwrap_or_else(|error| {
            let mut material =
                b"memcordon-session-broker-trace-capability-authority-error-v1\0".to_vec();
            material.extend_from_slice(error.as_bytes());
            super::record::digest(&material)
        });
    let authority_equal = authority_before_sha256 == authority_after_sha256;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let deadline_exceeded = trace_session_capability_deadline_exceeded(elapsed_ms);
    let state = classify_trace_session_capability_native(
        authority_equal,
        deadline_exceeded,
        native.start_status,
        native.session_created,
        native.stop_attempted,
        native.stop_status,
        native.cleanup_count,
        native.session_absence_proven,
    );
    let receipt = TraceSessionCapabilityReceiptV1 {
        capability_schema_version: TRACE_SESSION_CAPABILITY_SCHEMA_VERSION,
        broker_schema_version: SESSION_BROKER_SCHEMA_VERSION,
        transaction_sha256: super::record::digest(request.transaction_nonce.as_bytes()),
        trigger_reason: request.trigger_reason,
        trigger_sha256: request.trigger_sha256.clone(),
        request_binding_sha256: request.request_binding_sha256.clone(),
        broker_identity: hello.broker_identity.clone(),
        broker_source_sha256: request.broker_source_sha256.clone(),
        authority_before_sha256,
        authority_after_sha256,
        authority_equal,
        session_name_sha256: native.session_name_sha256,
        state,
        stage: native.stage.diagnostic().to_owned(),
        start_status: native.start_status,
        session_created: native.session_created,
        stop_attempted: native.stop_attempted,
        stop_status: native.stop_status,
        cleanup_count: native.cleanup_count,
        session_absence_proven: native.session_absence_proven,
        elapsed_ms,
        deadline_exceeded,
        provider_enable_attempted: false,
        consumer_opened: false,
        process_trace_started: false,
        child_bound: false,
        events_collected: 0,
        receipt_sha256: String::new(),
    }
    .seal()?;
    super::pipe::write_frame_bounded(
        pipe,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerTraceSessionCapabilityReceiptWrite,
        &SessionBrokerFrameV1::TraceSessionCapabilityReceipt(receipt),
    )
    .map_err(|error| error.to_string())
}

fn run_creation_authority_transaction(
    pipe: HANDLE,
    launcher_process: HANDLE,
    launched: &SessionBrokerLaunchedV1,
    holder: &mut super::process::SessionBrokerCreatedHolder,
) -> Result<(), String> {
    let mut completed = 0_u32;
    let mut holder_binding: Option<String> = None;
    let mut failed = false;
    let mut station_tid = None;
    loop {
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        let frame: SessionBrokerFrameV1 = super::pipe::read_frame_bounded(
            pipe,
            Some(launcher_process),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerArmRead,
        )
        .map_err(|error| error.to_string())?;
        match frame {
            SessionBrokerFrameV1::Arm {
                binding_sha256,
                holder_binding_sha256,
                phase,
                ordinal,
                thread_id,
                holder_primary,
            } => {
                let expected_phase = match completed {
                    0 => SessionCreationPhaseV1::WindowStation,
                    1 => SessionCreationPhaseV1::Desktop,
                    _ => return Err("session broker rejected a third creation arm".to_owned()),
                };
                if failed
                    || binding_sha256 != launched.binding_sha256
                    || ordinal != completed + 1
                    || phase != expected_phase
                    || thread_id == 0
                    || holder_primary != holder.query
                    || holder_binding
                        .as_ref()
                        .is_some_and(|expected| expected != &holder_binding_sha256)
                {
                    return Err("session broker Arm evidence is mismatched or reordered".to_owned());
                }
                if completed == 0 {
                    if thread_id != holder.primary_thread_id {
                        return Err(
                            "station arm did not name the authenticated primary TID".to_owned()
                        );
                    }
                    holder_binding = Some(holder_binding_sha256.clone());
                    station_tid = Some(thread_id);
                } else if station_tid == Some(thread_id) {
                    return Err("desktop arm reused the station creator TID".to_owned());
                }
                // SAFETY: the digest-bound TID is opened only for exact remote
                // SetThreadToken and independent token readback.
                let thread = OwnedHandle::new(unsafe {
                    OpenThread(HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS, 0, thread_id)
                })?;
                verify_exact_handle(
                    thread.raw(),
                    HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,
                    HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,
                    "creator-thread",
                    "open",
                )?;
                if unsafe { GetProcessIdOfThread(thread.raw()) } != holder.identity.process_id {
                    return Err("creation TID is not owned by the authenticated holder".to_owned());
                }
                super::token::require_thread_token_absent(thread.raw())?;
                let (carrier, expected_evidence) = match phase {
                    SessionCreationPhaseV1::WindowStation => (
                        holder.station_creation_carrier.raw(),
                        &holder.station_creation_evidence,
                    ),
                    SessionCreationPhaseV1::Desktop => (
                        holder.desktop_creation_carrier.raw(),
                        &holder.desktop_creation_evidence,
                    ),
                };
                let attached =
                    super::token::attach_creation_carrier_to_thread(thread.raw(), carrier)?;
                if &attached != expected_evidence {
                    return Err("attached creation carrier evidence is mismatched".to_owned());
                }
                super::pipe::write_frame_bounded(
                    pipe,
                    Some(launcher_process),
                    deadline,
                    super::pipe::TargetDesktopBootstrapPipeOperation::BrokerArmedWrite,
                    &SessionBrokerFrameV1::Armed {
                        binding_sha256: launched.binding_sha256.clone(),
                        holder_binding_sha256: holder_binding_sha256.clone(),
                        phase,
                        ordinal,
                        thread_id,
                        carrier: attached,
                    },
                )
                .map_err(|error| error.to_string())?;
                let consumed: SessionBrokerFrameV1 = super::pipe::read_frame_bounded(
                    pipe,
                    Some(launcher_process),
                    Instant::now() + BROKER_TRANSACTION_DEADLINE,
                    super::pipe::TargetDesktopBootstrapPipeOperation::BrokerConsumedRead,
                )
                .map_err(|error| error.to_string())?;
                let native_code = match consumed {
                    SessionBrokerFrameV1::Consumed {
                        binding_sha256: consumed_binding,
                        holder_binding_sha256: consumed_holder_binding,
                        phase: consumed_phase,
                        ordinal: consumed_ordinal,
                        thread_id: consumed_thread,
                        holder_primary: consumed_primary,
                        native_code,
                        thread_token_absent,
                    } if consumed_binding == launched.binding_sha256
                        && consumed_holder_binding == holder_binding_sha256
                        && consumed_phase == phase
                        && consumed_ordinal == ordinal
                        && consumed_thread == thread_id
                        && consumed_primary == holder.query
                        && thread_token_absent =>
                    {
                        native_code
                    }
                    _ => return Err("session broker Consumed evidence is invalid".to_owned()),
                };
                super::token::require_thread_token_absent(thread.raw())?;
                completed = ordinal;
                failed = native_code.is_some();
                super::pipe::write_frame_bounded(
                    pipe,
                    Some(launcher_process),
                    Instant::now() + BROKER_TRANSACTION_DEADLINE,
                    super::pipe::TargetDesktopBootstrapPipeOperation::BrokerClearedWrite,
                    &SessionBrokerFrameV1::Cleared {
                        binding_sha256: launched.binding_sha256.clone(),
                        holder_binding_sha256,
                        phase,
                        ordinal,
                        thread_id,
                    },
                )
                .map_err(|error| error.to_string())?;
            }
            SessionBrokerFrameV1::FinalAck {
                binding_sha256,
                holder_binding_sha256,
                completed_phases,
            } if binding_sha256 == launched.binding_sha256
                && holder_binding.as_deref() == Some(holder_binding_sha256.as_str())
                && completed_phases == completed
                && (completed == 2 || failed) =>
            {
                holder.disarm();
                super::pipe::write_frame_bounded(
                    pipe,
                    Some(launcher_process),
                    deadline,
                    super::pipe::TargetDesktopBootstrapPipeOperation::BrokerDoneWrite,
                    &SessionBrokerFrameV1::Done {
                        binding_sha256: launched.binding_sha256.clone(),
                    },
                )
                .map_err(|error| error.to_string())?;
                return Ok(());
            }
            _ => {
                return Err(
                    "session broker creation authority state machine rejected a frame".to_owned(),
                );
            }
        }
    }
}

fn loader_snaps_client_failure(
    stage: LoaderSnapsStageV2,
    transaction_sha256: &str,
    detail: impl ToString,
) -> LoaderSnapsFailureV2 {
    LoaderSnapsFailureV2::new(
        stage,
        "authenticated-session-broker",
        None,
        0,
        transaction_sha256,
        "remote-owned",
        "remote-owned",
        "mandatory",
        detail,
    )
}

fn start_authenticated_broker(
    operation: BrokerClientOperation,
) -> Result<AuthenticatedBrokerClient, BrokerClientStartupError> {
    let transaction_lease = match BROKER_TRANSACTION_LEASE.try_lock() {
        Ok(lease) => lease,
        Err(TryLockError::WouldBlock) => {
            return Err(operation.startup_failure(
                BrokerClientStartupStage::TransactionLease,
                "result=busy another authenticated one-shot transaction owns the broker lifecycle",
            ));
        }
        Err(TryLockError::Poisoned(_)) => {
            return Err(operation.startup_failure(
                BrokerClientStartupStage::TransactionLease,
                "result=poisoned one-shot transaction serialization invariant failed",
            ));
        }
    };
    let start_nonce = super::token::service_attestation_challenge("session-broker-start")
        .map_err(|error| operation.startup_failure(BrokerClientStartupStage::StartNonce, error))?;
    let manager = super::service_manager::manager_connect().map_err(|error| {
        operation.startup_failure(BrokerClientStartupStage::ManagerConnect, error)
    })?;
    let service = super::service_manager::open(
        &manager,
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        SERVICE_START | SERVICE_QUERY_STATUS,
    )
    .map_err(|error| operation.startup_failure(BrokerClientStartupStage::ServiceOpen, error))?;
    let initial_status = super::service_manager::status_process(&service).map_err(|error| {
        operation.startup_failure(BrokerClientStartupStage::InitialStatus, error)
    })?;
    if initial_status.dwCurrentState != SERVICE_STOPPED {
        return Err(operation.startup_failure(
            BrokerClientStartupStage::InitialStatus,
            format!(
                "expected_state=stopped actual_state={} process_id={} win32_exit={} service_exit={}",
                initial_status.dwCurrentState,
                initial_status.dwProcessId,
                initial_status.dwWin32ExitCode,
                initial_status.dwServiceSpecificExitCode,
            ),
        ));
    }
    super::service_manager::start_with_arguments(
        &service,
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        &[
            SESSION_BROKER_SCHEMA_VERSION.to_string(),
            start_nonce.clone(),
        ],
    )
    .map_err(|error| operation.startup_failure(BrokerClientStartupStage::DemandStart, error))?;
    let pipe = match super::pipe::connect_session_broker_pipe(
        WINDOWS_SESSION_BROKER_PIPE,
        Instant::now() + BROKER_TRANSACTION_DEADLINE,
    ) {
        Ok(pipe) => pipe,
        Err(endpoint_error) => {
            let detail = match super::service_manager::status_process(&service) {
                Ok(status) => format!(
                    "service_state={} process_id={} win32_exit={} service_exit={} endpoint_error={endpoint_error}",
                    status.dwCurrentState,
                    status.dwProcessId,
                    status.dwWin32ExitCode,
                    status.dwServiceSpecificExitCode,
                ),
                Err(status_error) => format!(
                    "service_state=query-failed status_error={status_error} endpoint_error={endpoint_error}"
                ),
            };
            return Err(operation.startup_failure(BrokerClientStartupStage::PipeConnect, detail));
        }
    };
    let (broker_process, broker_identity) =
        authenticate_broker_server(pipe.raw()).map_err(|error| {
            operation.startup_failure(BrokerClientStartupStage::PeerAuthentication, error)
        })?;
    let pinned_broker = super::service_manager::PinnedServiceProcess {
        handle: broker_process,
        identity: broker_identity,
    };
    let authenticated = (|| {
        let broker_source_query =
            super::token::process_token_query_attestation(pinned_broker.handle.raw()).map_err(
                |error| operation.startup_failure(BrokerClientStartupStage::SourceBinding, error),
            )?;
        let status = super::service_manager::status_process(&service).map_err(|error| {
            operation.startup_failure(BrokerClientStartupStage::ServicePin, error)
        })?;
        if status.dwCurrentState != windows_sys::Win32::System::Services::SERVICE_RUNNING
            || status.dwProcessId != pinned_broker.identity.process_id
        {
            return Err(operation.startup_failure(
                BrokerClientStartupStage::ServicePin,
                format!(
                    "pipe peer is not the SCM-pinned broker instance: service_state={} service_pid={} peer_pid={}",
                    status.dwCurrentState, status.dwProcessId, pinned_broker.identity.process_id,
                ),
            ));
        }
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        let hello = match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(pinned_broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerHelloRead,
        )
        .map_err(|error| operation.startup_failure(BrokerClientStartupStage::HelloRead, error))?
        {
            SessionBrokerFrameV1::Hello(hello) => hello,
            _ => {
                return Err(operation.startup_failure(
                    BrokerClientStartupStage::HelloRead,
                    "session broker did not send Hello first",
                ));
            }
        };
        if hello.schema_version != SESSION_BROKER_SCHEMA_VERSION
            || hello.service_name != WINDOWS_SESSION_BROKER_SERVICE_NAME
            || hello.start_nonce != start_nonce
            || hello.broker_identity != pinned_broker.identity
            || hello.broker_image_sha256
                != super::package::validate_installed_session_broker().map_err(|error| {
                    operation.startup_failure(BrokerClientStartupStage::HelloValidation, error)
                })?
            || !memcordon_core::windows_service_attestation_challenge_is_valid(&hello.challenge)
        {
            return Err(operation.startup_failure(
                BrokerClientStartupStage::HelloValidation,
                "session broker Hello evidence is mismatched",
            ));
        }
        super::token::validate_normalized_session_broker_source_snapshot(&hello.broker_source)
            .map_err(|error| {
                operation.startup_failure(BrokerClientStartupStage::SourceValidation, error)
            })?;
        super::token::require_same_process_token_query(
            "session-broker-hello-source-to-authenticated-process",
            &hello.broker_source.query_evidence(),
            &broker_source_query,
        )
        .map_err(|error| {
            operation.startup_failure(BrokerClientStartupStage::SourceBinding, error)
        })?;
        Ok::<_, BrokerClientStartupError>((hello, broker_source_query))
    })();
    match authenticated {
        Ok((hello, broker_source_query)) => Ok(AuthenticatedBrokerClient {
            pipe: Some(pipe),
            service: Some(service),
            broker: Some(pinned_broker),
            hello,
            broker_source_query,
            transaction_lease: Some(transaction_lease),
        }),
        Err(primary) => {
            drop(pipe);
            match retire_authenticated_broker(&service, &pinned_broker) {
                Ok(()) => Err(primary),
                Err(retirement) => Err(primary.append_retirement(retirement)),
            }
        }
    }
}

pub(crate) fn request_loader_snaps(
    binding: LoaderSnapsRequestBindingV2,
) -> Result<LoaderSnapsControlLease, LoaderSnapsFailureV2> {
    let authenticated = start_authenticated_broker(BrokerClientOperation::LoaderSnaps)
        .map_err(BrokerClientStartupError::loader_snaps_failure)?;
    let result =
        (|| -> Result<(LoaderSnapsRequestV2, LoaderSnapsArmedReceiptV2), LoaderSnapsFailureV2> {
            let pipe = authenticated.pipe();
            let broker = authenticated.broker();
            let hello = &authenticated.hello;
            let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
            let launcher_identity =
                super::process::process_identity(unsafe { GetCurrentProcess() }).map_err(
                    |error| {
                        loader_snaps_client_failure(
                            LoaderSnapsStageV2::BrokerProtocol,
                            "unbound",
                            error,
                        )
                    },
                )?;
            let transaction_nonce = super::token::service_attestation_challenge(
                "loader-snaps-transaction",
            )
            .map_err(|error| {
                loader_snaps_client_failure(LoaderSnapsStageV2::BrokerProtocol, "unbound", error)
            })?;
            let mut request = LoaderSnapsRequestV2 {
                schema_version: LOADER_SNAPS_SCHEMA_VERSION,
                start_nonce: hello.start_nonce.clone(),
                challenge: hello.challenge.clone(),
                transaction_nonce,
                launcher_identity,
                binding,
                binding_sha256: String::new(),
            };
            request.binding_sha256 = request.calculated_sha256().map_err(|error| {
                loader_snaps_client_failure(LoaderSnapsStageV2::BrokerProtocol, "unbound", error)
            })?;
            super::pipe::write_frame_bounded(
                pipe.raw(),
                Some(broker.handle.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsRequestWrite,
                &SessionBrokerFrameV1::LoaderSnapsRequest(request.clone()),
            )
            .map_err(|error| {
                loader_snaps_client_failure(
                    LoaderSnapsStageV2::BrokerProtocol,
                    &request.binding_sha256,
                    error,
                )
            })?;
            let armed = match super::pipe::read_frame_bounded(
                pipe.raw(),
                Some(broker.handle.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLoaderSnapsArmedRead,
            )
            .map_err(|error| {
                loader_snaps_client_failure(
                    LoaderSnapsStageV2::BrokerProtocol,
                    &request.binding_sha256,
                    error,
                )
            })? {
                SessionBrokerFrameV1::LoaderSnapsArmed(receipt) => receipt,
                SessionBrokerFrameV1::LoaderSnapsFailed(failure) => return Err(failure),
                _ => {
                    return Err(loader_snaps_client_failure(
                        LoaderSnapsStageV2::BrokerProtocol,
                        &request.binding_sha256,
                        "loader-snaps broker returned an invalid armed frame",
                    ));
                }
            };
            armed.validate().map_err(|error| {
                loader_snaps_client_failure(
                    LoaderSnapsStageV2::BrokerProtocol,
                    &request.binding_sha256,
                    error,
                )
            })?;
            if armed.transaction_nonce != request.transaction_nonce
                || armed.request_binding_sha256 != request.binding_sha256
                || armed.broker_identity != broker.identity
                || armed.authority_token_sha256
                    != loader_snaps_authority_sha256(&hello.broker_source).map_err(|error| {
                        loader_snaps_client_failure(
                            LoaderSnapsStageV2::Authority,
                            &request.binding_sha256,
                            error.diagnostic(),
                        )
                    })?
            {
                return Err(loader_snaps_client_failure(
                    LoaderSnapsStageV2::BrokerProtocol,
                    &request.binding_sha256,
                    "loader-snaps armed receipt binding is mismatched",
                ));
            }
            Ok((request, armed))
        })();
    match result {
        Ok((request, armed)) => Ok(authenticated.into_loader_snaps_control(request, armed)),
        Err(mut primary) => match authenticated.retire() {
            Ok(()) => Err(primary),
            Err(error) => {
                primary.detail = bounded_broker_detail(format!(
                    "{}; exact_broker_retirement_error={error}",
                    primary.detail
                ));
                Err(primary)
            }
        },
    }
}

fn trace_session_capability_receipt_valid(
    receipt: &TraceSessionCapabilityReceiptV1,
    request: &TraceSessionCapabilityRequestV1,
    hello: &SessionBrokerHelloV1,
) -> Result<bool, String> {
    trace_session_capability_receipt_valid_for_binding(receipt, request, &hello.broker_identity)
}

fn trace_session_capability_receipt_valid_for_binding(
    receipt: &TraceSessionCapabilityReceiptV1,
    request: &TraceSessionCapabilityRequestV1,
    broker_identity: &WindowsProcessIdentityV1,
) -> Result<bool, String> {
    receipt.validate_seal()?;
    for digest in [
        &receipt.transaction_sha256,
        &receipt.trigger_sha256,
        &receipt.request_binding_sha256,
        &receipt.broker_source_sha256,
        &receipt.authority_before_sha256,
        &receipt.authority_after_sha256,
        &receipt.session_name_sha256,
        &receipt.receipt_sha256,
    ] {
        super::record::validate_attempt_id(digest)?;
    }
    let expected_session_name_sha256 = super::access_trace::trace_session_capability_name_sha256(
        &request.start_nonce,
        &request.transaction_nonce,
        broker_identity.process_id,
        broker_identity.creation_time_100ns,
    );
    let common = receipt.capability_schema_version == TRACE_SESSION_CAPABILITY_SCHEMA_VERSION
        && receipt.broker_schema_version == SESSION_BROKER_SCHEMA_VERSION
        && receipt.transaction_sha256
            == super::record::digest(request.transaction_nonce.as_bytes())
        && receipt.trigger_reason == request.trigger_reason
        && receipt.trigger_sha256 == request.trigger_sha256
        && receipt.request_binding_sha256 == request.request_binding_sha256
        && &receipt.broker_identity == broker_identity
        && receipt.broker_source_sha256 == request.broker_source_sha256
        && receipt.authority_before_sha256 == request.broker_source_sha256
        && receipt.session_name_sha256 == expected_session_name_sha256
        && !receipt.provider_enable_attempted
        && !receipt.consumer_opened
        && !receipt.process_trace_started
        && !receipt.child_bound
        && receipt.events_collected == 0;
    Ok(common
        && trace_session_capability_receipt_state_relation(receipt, &request.broker_source_sha256))
}

fn trace_session_capability_deadline_exceeded(elapsed_ms: u64) -> bool {
    u128::from(elapsed_ms) > TRACE_SESSION_CAPABILITY_DEADLINE.as_millis()
}

fn trace_session_capability_native_shape(receipt: &TraceSessionCapabilityReceiptV1) -> bool {
    if receipt.start_status == ERROR_SUCCESS {
        receipt.stage == "session-stop"
            && receipt.session_created
            && receipt.stop_attempted
            && receipt.stop_status.is_some()
            && receipt.cleanup_count == 1
            && receipt.session_absence_proven == (receipt.stop_status == Some(ERROR_SUCCESS))
    } else {
        receipt.stage == "session-start"
            && !receipt.session_created
            && !receipt.stop_attempted
            && receipt.stop_status.is_none()
            && receipt.cleanup_count == 0
            && receipt.session_absence_proven == (receipt.start_status != ERROR_ALREADY_EXISTS)
    }
}

fn trace_session_capability_receipt_state_relation(
    receipt: &TraceSessionCapabilityReceiptV1,
    expected_broker_source_sha256: &str,
) -> bool {
    let authority_digest_equal = receipt.authority_before_sha256 == receipt.authority_after_sha256
        && receipt.authority_before_sha256 == expected_broker_source_sha256;
    let authority_relation = receipt.authority_equal == authority_digest_equal;
    let deadline_relation =
        receipt.deadline_exceeded == trace_session_capability_deadline_exceeded(receipt.elapsed_ms);
    let recomputed_state = classify_trace_session_capability_native(
        receipt.authority_equal,
        receipt.deadline_exceeded,
        receipt.start_status,
        receipt.session_created,
        receipt.stop_attempted,
        receipt.stop_status,
        receipt.cleanup_count,
        receipt.session_absence_proven,
    );
    let accepted_state_relation = match receipt.state {
        TraceSessionCapabilityStateV1::BrokerSessionAvailable
        | TraceSessionCapabilityStateV1::BrokerSessionUnavailable => {
            authority_digest_equal && receipt.authority_equal && !receipt.deadline_exceeded
        }
        TraceSessionCapabilityStateV1::BrokerSessionInvalid => true,
    };
    authority_relation
        && deadline_relation
        && trace_session_capability_native_shape(receipt)
        && receipt.state == recomputed_state
        && accepted_state_relation
}

pub(crate) fn request_trace_session_capability(
    trigger_sha256: String,
) -> TraceSessionCapabilityEvidenceV1 {
    if super::record::validate_attempt_id(&trigger_sha256).is_err() {
        return TraceSessionCapabilityEvidenceV1 {
            receipt: None,
            admitted_trigger_sha256: None,
            request_provenance: None,
            retirement: "not-started",
            failure_stage: Some("typed-gate"),
            failure_sha256: Some(super::record::digest(b"invalid-typed-trigger")),
            retirement_failure_sha256: None,
        };
    }
    let admitted_trigger_sha256 = trigger_sha256.clone();
    if !super::package::ephemeral_ci_enabled() {
        return TraceSessionCapabilityEvidenceV1 {
            receipt: None,
            admitted_trigger_sha256: Some(admitted_trigger_sha256),
            request_provenance: None,
            retirement: "not-started",
            failure_stage: Some("ephemeral-gate"),
            failure_sha256: Some(super::record::digest(b"ephemeral-ci-disabled")),
            retirement_failure_sha256: None,
        };
    }
    let authenticated =
        match start_authenticated_broker(BrokerClientOperation::TraceSessionCapability) {
            Ok(value) => value,
            Err(error) => {
                return TraceSessionCapabilityEvidenceV1 {
                    receipt: None,
                    admitted_trigger_sha256: Some(admitted_trigger_sha256),
                    request_provenance: None,
                    retirement: "startup-failed",
                    failure_stage: Some(error.stage.diagnostic()),
                    failure_sha256: Some(super::record::digest(error.detail.as_bytes())),
                    retirement_failure_sha256: None,
                };
            }
        };
    let mut request_provenance = None;
    let result = (|| -> Result<TraceSessionCapabilityReceiptV1, String> {
        let pipe = authenticated.pipe();
        let broker = authenticated.broker();
        let hello = &authenticated.hello;
        let launcher_identity = super::process::process_identity(unsafe { GetCurrentProcess() })?;
        let transaction_nonce =
            super::token::service_attestation_challenge("trace-session-capability-transaction")
                .map_err(|error| error.to_string())?;
        let broker_source_sha256 = trace_session_capability_source_sha256(
            &hello.broker_identity,
            &hello.broker_source,
            &authenticated.broker_source_query,
        )?;
        let mut request = TraceSessionCapabilityRequestV1 {
            capability_schema_version: TRACE_SESSION_CAPABILITY_SCHEMA_VERSION,
            broker_schema_version: SESSION_BROKER_SCHEMA_VERSION,
            start_nonce: hello.start_nonce.clone(),
            challenge: hello.challenge.clone(),
            transaction_nonce,
            launcher_identity,
            broker_identity: hello.broker_identity.clone(),
            broker_source_sha256,
            trigger_reason:
                TraceSessionCapabilityTriggerReasonV1::StableModuleZeroPrefixNonlocalizing,
            trigger_sha256,
            ephemeral_ci: true,
            request_binding_sha256: String::new(),
        };
        request.request_binding_sha256 = request.calculated_sha256()?;
        request_provenance = Some(TraceSessionCapabilityRequestProvenanceV1 {
            request_binding_sha256: request.request_binding_sha256.clone(),
            transaction_sha256: super::record::digest(request.transaction_nonce.as_bytes()),
            broker_source_sha256: request.broker_source_sha256.clone(),
            broker_identity: request.broker_identity.clone(),
        });
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerTraceSessionCapabilityRequestWrite,
            &SessionBrokerFrameV1::TraceSessionCapabilityRequest(request.clone()),
        )
        .map_err(|error| error.to_string())?;
        let receipt = match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerTraceSessionCapabilityReceiptRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerFrameV1::TraceSessionCapabilityReceipt(receipt) => receipt,
            SessionBrokerFrameV1::TraceSessionCapabilityFailed(failure)
                if failure.capability_schema_version
                    == TRACE_SESSION_CAPABILITY_SCHEMA_VERSION
                    && failure.request_binding_sha256 == request.request_binding_sha256
                    && super::record::validate_attempt_id(&failure.detail_sha256).is_ok() =>
            {
                return Err(format!(
                    "capability-failed stage={} detail_sha256={}",
                    bounded_broker_detail(failure.stage),
                    failure.detail_sha256,
                ));
            }
            _ => return Err("session broker returned an invalid capability frame".to_owned()),
        };
        if !trace_session_capability_receipt_valid(&receipt, &request, hello)? {
            return Err("trace-session capability receipt relation is invalid".to_owned());
        }
        Ok(receipt)
    })();
    match result {
        Ok(receipt) => match authenticated.retire() {
            Ok(()) => TraceSessionCapabilityEvidenceV1 {
                receipt: Some(receipt),
                admitted_trigger_sha256: Some(admitted_trigger_sha256.clone()),
                request_provenance: request_provenance.clone(),
                retirement: "retired",
                failure_stage: None,
                failure_sha256: None,
                retirement_failure_sha256: None,
            },
            Err(error) => TraceSessionCapabilityEvidenceV1 {
                receipt: Some(receipt),
                admitted_trigger_sha256: Some(admitted_trigger_sha256.clone()),
                request_provenance: request_provenance.clone(),
                retirement: "retirement-failed",
                failure_stage: Some("broker-retire"),
                failure_sha256: None,
                retirement_failure_sha256: Some(super::record::digest(error.as_bytes())),
            },
        },
        Err(error) => {
            let (retirement, retirement_failure) = match authenticated.retire() {
                Ok(()) => ("retired", None),
                Err(retirement) => (
                    "retirement-failed",
                    Some(super::record::digest(retirement.as_bytes())),
                ),
            };
            TraceSessionCapabilityEvidenceV1 {
                receipt: None,
                admitted_trigger_sha256: Some(admitted_trigger_sha256),
                request_provenance,
                retirement,
                failure_stage: Some("broker-protocol"),
                failure_sha256: Some(super::record::digest(error.as_bytes())),
                retirement_failure_sha256: retirement_failure,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn trace_session_capability_state_for_test(
    authority_equal: bool,
    deadline_exceeded: bool,
    start_status: u32,
    session_created: bool,
    stop_attempted: bool,
    stop_status: Option<u32>,
    cleanup_count: u32,
    session_absence_proven: bool,
) -> &'static str {
    classify_trace_session_capability_native(
        authority_equal,
        deadline_exceeded,
        start_status,
        session_created,
        stop_attempted,
        stop_status,
        cleanup_count,
        session_absence_proven,
    )
    .diagnostic()
}

#[cfg(test)]
pub(crate) fn trace_session_capability_schema_versions_for_test() -> (u32, u32) {
    (
        SESSION_BROKER_SCHEMA_VERSION,
        TRACE_SESSION_CAPABILITY_SCHEMA_VERSION,
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceSessionCapabilityReceiptMutationForTest {
    Available,
    Unavailable,
    ClosedInvalidStopFailure,
    ContradictoryInvalid,
    WrongAfterAuthority,
    AuthorityEqualFalse,
    DeadlineExceeded,
    ElapsedPastDeadline,
    WrongTransaction,
    WrongTrigger,
    WrongRequestBinding,
    WrongBrokerSource,
    WrongBrokerIdentity,
    WrongSessionName,
    CorruptSeal,
    RetirementFailure,
}

#[cfg(test)]
pub(crate) fn trace_session_capability_receipt_for_test(
    mutation: TraceSessionCapabilityReceiptMutationForTest,
) -> (bool, bool, String) {
    let launcher_identity = WindowsProcessIdentityV1 {
        process_id: 41,
        creation_time_100ns: 42,
    };
    let broker_identity = WindowsProcessIdentityV1 {
        process_id: 43,
        creation_time_100ns: 44,
    };
    let broker_source_sha256 = super::record::digest(b"test-normalized-broker-source");
    let mut request = TraceSessionCapabilityRequestV1 {
        capability_schema_version: TRACE_SESSION_CAPABILITY_SCHEMA_VERSION,
        broker_schema_version: SESSION_BROKER_SCHEMA_VERSION,
        start_nonce: "test-start-nonce-not-rendered".to_owned(),
        challenge: "test-challenge-not-rendered".to_owned(),
        transaction_nonce: "test-transaction-nonce-not-rendered".to_owned(),
        launcher_identity,
        broker_identity: broker_identity.clone(),
        broker_source_sha256: broker_source_sha256.clone(),
        trigger_reason: TraceSessionCapabilityTriggerReasonV1::StableModuleZeroPrefixNonlocalizing,
        trigger_sha256: super::record::digest(b"test-typed-trigger"),
        ephemeral_ci: true,
        request_binding_sha256: String::new(),
    };
    request.request_binding_sha256 = request
        .calculated_sha256()
        .expect("synthetic capability request must seal");
    let mut receipt = TraceSessionCapabilityReceiptV1 {
        capability_schema_version: TRACE_SESSION_CAPABILITY_SCHEMA_VERSION,
        broker_schema_version: SESSION_BROKER_SCHEMA_VERSION,
        transaction_sha256: super::record::digest(request.transaction_nonce.as_bytes()),
        trigger_reason: request.trigger_reason,
        trigger_sha256: request.trigger_sha256.clone(),
        request_binding_sha256: request.request_binding_sha256.clone(),
        broker_identity: broker_identity.clone(),
        broker_source_sha256: broker_source_sha256.clone(),
        authority_before_sha256: broker_source_sha256.clone(),
        authority_after_sha256: broker_source_sha256.clone(),
        authority_equal: true,
        session_name_sha256: super::access_trace::trace_session_capability_name_sha256(
            &request.start_nonce,
            &request.transaction_nonce,
            broker_identity.process_id,
            broker_identity.creation_time_100ns,
        ),
        state: TraceSessionCapabilityStateV1::BrokerSessionAvailable,
        stage: "session-stop".to_owned(),
        start_status: ERROR_SUCCESS,
        session_created: true,
        stop_attempted: true,
        stop_status: Some(ERROR_SUCCESS),
        cleanup_count: 1,
        session_absence_proven: true,
        elapsed_ms: 1,
        deadline_exceeded: false,
        provider_enable_attempted: false,
        consumer_opened: false,
        process_trace_started: false,
        child_bound: false,
        events_collected: 0,
        receipt_sha256: String::new(),
    };
    match mutation {
        TraceSessionCapabilityReceiptMutationForTest::Available
        | TraceSessionCapabilityReceiptMutationForTest::RetirementFailure
        | TraceSessionCapabilityReceiptMutationForTest::CorruptSeal => {}
        TraceSessionCapabilityReceiptMutationForTest::Unavailable => {
            receipt.state = TraceSessionCapabilityStateV1::BrokerSessionUnavailable;
            receipt.stage = "session-start".to_owned();
            receipt.start_status = 5;
            receipt.session_created = false;
            receipt.stop_attempted = false;
            receipt.stop_status = None;
            receipt.cleanup_count = 0;
        }
        TraceSessionCapabilityReceiptMutationForTest::ClosedInvalidStopFailure => {
            receipt.state = TraceSessionCapabilityStateV1::BrokerSessionInvalid;
            receipt.stop_status = Some(5);
            receipt.session_absence_proven = false;
        }
        TraceSessionCapabilityReceiptMutationForTest::ContradictoryInvalid => {
            receipt.state = TraceSessionCapabilityStateV1::BrokerSessionInvalid;
        }
        TraceSessionCapabilityReceiptMutationForTest::WrongAfterAuthority => {
            receipt.authority_after_sha256 = super::record::digest(b"changed-authority");
        }
        TraceSessionCapabilityReceiptMutationForTest::AuthorityEqualFalse => {
            receipt.authority_equal = false;
        }
        TraceSessionCapabilityReceiptMutationForTest::DeadlineExceeded => {
            receipt.deadline_exceeded = true;
        }
        TraceSessionCapabilityReceiptMutationForTest::ElapsedPastDeadline => {
            receipt.elapsed_ms = u64::try_from(TRACE_SESSION_CAPABILITY_DEADLINE.as_millis())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
        }
        TraceSessionCapabilityReceiptMutationForTest::WrongTransaction => {
            receipt.transaction_sha256 = super::record::digest(b"wrong-transaction");
        }
        TraceSessionCapabilityReceiptMutationForTest::WrongTrigger => {
            receipt.trigger_sha256 = super::record::digest(b"wrong-trigger");
        }
        TraceSessionCapabilityReceiptMutationForTest::WrongRequestBinding => {
            receipt.request_binding_sha256 = super::record::digest(b"wrong-request");
        }
        TraceSessionCapabilityReceiptMutationForTest::WrongBrokerSource => {
            receipt.broker_source_sha256 = super::record::digest(b"wrong-source");
        }
        TraceSessionCapabilityReceiptMutationForTest::WrongBrokerIdentity => {
            receipt.broker_identity.process_id += 1;
        }
        TraceSessionCapabilityReceiptMutationForTest::WrongSessionName => {
            receipt.session_name_sha256 = super::record::digest(b"wrong-session-name");
        }
    }
    receipt = receipt
        .seal()
        .expect("synthetic capability receipt must seal");
    if mutation == TraceSessionCapabilityReceiptMutationForTest::CorruptSeal {
        receipt.receipt_sha256 = super::record::digest(b"corrupt-receipt-seal");
    }
    let seal_valid = receipt.validate_seal().is_ok();
    let admission_valid =
        trace_session_capability_receipt_valid_for_binding(&receipt, &request, &broker_identity)
            .unwrap_or(false);
    let retirement_failed =
        mutation == TraceSessionCapabilityReceiptMutationForTest::RetirementFailure;
    let evidence = TraceSessionCapabilityEvidenceV1 {
        receipt: Some(receipt),
        admitted_trigger_sha256: Some(request.trigger_sha256.clone()),
        request_provenance: Some(TraceSessionCapabilityRequestProvenanceV1 {
            request_binding_sha256: request.request_binding_sha256.clone(),
            transaction_sha256: super::record::digest(request.transaction_nonce.as_bytes()),
            broker_source_sha256: request.broker_source_sha256.clone(),
            broker_identity: request.broker_identity.clone(),
        }),
        retirement: if retirement_failed {
            "retirement-failed"
        } else {
            "retired"
        },
        failure_stage: retirement_failed.then_some("broker-retire"),
        failure_sha256: None,
        retirement_failure_sha256: retirement_failed
            .then(|| super::record::digest(b"test-retirement-failure")),
    };
    (admission_valid, seal_valid, evidence.diagnostic())
}

#[cfg(test)]
pub(crate) fn trace_session_capability_no_receipt_diagnostics_for_test() -> (String, String, String)
{
    let admitted_trigger_sha256 = super::record::digest(b"test-typed-trigger");
    let request_provenance = TraceSessionCapabilityRequestProvenanceV1 {
        request_binding_sha256: super::record::digest(b"test-request-binding"),
        transaction_sha256: super::record::digest(b"test-transaction-nonce-not-rendered"),
        broker_source_sha256: super::record::digest(b"test-normalized-broker-source"),
        broker_identity: WindowsProcessIdentityV1 {
            process_id: 43,
            creation_time_100ns: 44,
        },
    };
    let startup = TraceSessionCapabilityEvidenceV1 {
        receipt: None,
        admitted_trigger_sha256: Some(admitted_trigger_sha256.clone()),
        request_provenance: None,
        retirement: "startup-failed",
        failure_stage: Some("broker-start"),
        failure_sha256: Some(super::record::digest(b"test-startup-failure")),
        retirement_failure_sha256: None,
    }
    .diagnostic();
    let protocol = TraceSessionCapabilityEvidenceV1 {
        receipt: None,
        admitted_trigger_sha256: Some(admitted_trigger_sha256.clone()),
        request_provenance: Some(request_provenance.clone()),
        retirement: "retired",
        failure_stage: Some("broker-protocol"),
        failure_sha256: Some(super::record::digest(b"test-primary-protocol-failure")),
        retirement_failure_sha256: None,
    }
    .diagnostic();
    let dual_failure = TraceSessionCapabilityEvidenceV1 {
        receipt: None,
        admitted_trigger_sha256: Some(admitted_trigger_sha256),
        request_provenance: Some(request_provenance),
        retirement: "retirement-failed",
        failure_stage: Some("broker-protocol"),
        failure_sha256: Some(super::record::digest(b"test-primary-protocol-failure")),
        retirement_failure_sha256: Some(super::record::digest(b"test-retirement-failure")),
    }
    .diagnostic();
    (startup, protocol, dual_failure)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_holder(
    job: &super::job::Job,
    target_session_id: u32,
    holder_pipe_name: &str,
    holder_nonce: &str,
) -> Result<BrokeredHolder, String> {
    let authenticated = start_authenticated_broker(BrokerClientOperation::Holder)
        .map_err(BrokerClientStartupError::holder_diagnostic)?;
    let transaction_result = (|| -> Result<BrokeredHolder, String> {
        let pipe = authenticated.pipe();
        let broker = authenticated.broker();
        let hello = &authenticated.hello;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        job.verify_session_holder_configuration()?;
        if job.active_processes()? != 0 {
            return Err("session-holder Job is not empty before broker request".to_owned());
        }
        let launcher_identity = super::process::process_identity(unsafe { GetCurrentProcess() })?;
        let request = SessionBrokerRequestV1 {
            schema_version: SESSION_BROKER_SCHEMA_VERSION,
            start_nonce: hello.start_nonce.clone(),
            challenge: hello.challenge.clone(),
            launcher_identity,
            target_session_id,
            holder_pipe_name: holder_pipe_name.to_owned(),
            holder_nonce: holder_nonce.to_owned(),
            launcher_job_handle: encode_protocol_handle(job.handle(), "launcher-job")?,
            holder_image_sha256: super::package::validate_installed_target_desktop_bootstrap()?,
        };
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerRequestWrite,
            &SessionBrokerFrameV1::Request(request.clone()),
        )
        .map_err(|error| error.to_string())?;
        let launched = match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerFrameV1::Launched(launched) => launched,
            SessionBrokerFrameV1::Failed { stage, detail } => {
                return Err(format!(
                    "session broker failed: stage={stage:?} detail={detail}"
                ));
            }
            _ => return Err("session broker returned an invalid launch frame".to_owned()),
        };
        if launched.schema_version != SESSION_BROKER_SCHEMA_VERSION
            || launched.start_nonce != request.start_nonce
            || launched.challenge != request.challenge
            || launched.broker_identity != broker.identity
            || launched.broker_source != hello.broker_source
            || launched.binding_sha256 != launched_binding_sha256(&request, &launched)?
        {
            return Err("session broker launch binding is mismatched".to_owned());
        }
        let process = OwnedHandle::new(decode_protocol_handle(
            launched.holder_process_handle,
            "holder-process",
        )?)?;
        if launched.holder_thread_id == 0 {
            return Err("session broker returned a zero holder primary thread id".to_owned());
        }
        // SAFETY: the digest-bound nonzero TID names the broker-retained,
        // still-suspended primary thread. The protected thread DACL performs
        // the launcher access check and the resulting handle is local and
        // explicitly non-inheritable.
        let thread = OwnedHandle::new(unsafe {
            OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 0, launched.holder_thread_id)
        })?;
        verify_exact_handle(
            process.raw(),
            HOLDER_PROCESS_TRANSFER_ACCESS,
            HOLDER_PROCESS_TRANSFER_ACCESS,
            "holder-process",
            "protocol-receive",
        )?;
        verify_exact_handle(
            thread.raw(),
            HOLDER_THREAD_LAUNCHER_ACCESS,
            HOLDER_THREAD_LAUNCHER_ACCESS,
            "holder-thread",
            "open",
        )?;
        // SAFETY: thread is the locally opened primary-thread capability and
        // carries THREAD_QUERY_LIMITED_INFORMATION for this association check.
        let actual_thread_process_id = unsafe { GetProcessIdOfThread(thread.raw()) };
        if actual_thread_process_id != launched.holder_identity.process_id {
            return Err(format!(
                "role=holder-thread operation=associate expected_pid={} actual_pid={} primary_thread_id={}",
                launched.holder_identity.process_id,
                actual_thread_process_id,
                launched.holder_thread_id,
            ));
        }
        if super::process::process_identity(process.raw())? != launched.holder_identity
            || super::token::process_token_query_attestation(process.raw())?
                != launched.holder_query
            || !job.contains(process.raw())?
            || job.active_processes()? != 1
            || job.total_processes()? != 1
            || job.process_ids()? != [launched.holder_identity.process_id]
        {
            return Err(
                "session broker holder evidence failed independent launcher readback".to_owned(),
            );
        }
        super::token::validate_normalized_session_broker_source_snapshot(&launched.broker_source)
            .map_err(|error| error.to_string())?;
        super::token::require_same_process_token_query(
            "session-broker-launched-source-to-authenticated-process",
            &launched.broker_source.query_evidence(),
            &authenticated.broker_source_query,
        )
        .map_err(|error| error.to_string())?;
        if launched.holder_effective.lineage.user_sid != "S-1-5-18"
            || launched.holder_effective.lineage.session_id != target_session_id
            || launched.holder_effective.behavior.token_is_restricted
            || !launched
                .holder_effective
                .behavior
                .restricting_sids
                .is_empty()
            || !snapshot_has_enabled_group(
                &launched.holder_effective,
                &super::security::service_sid(WINDOWS_SESSION_BROKER_SERVICE_NAME)?,
            )
        {
            return Err("session broker source or holder authority evidence is invalid".to_owned());
        }
        super::token::require_assigned_process_authority(
            "session-broker-holder-evidence-to-process",
            &launched.holder_effective,
            &launched.holder_query,
        )
        .map_err(|error| error.to_string())?;
        super::process::verify_image_path(
            process.raw(),
            &super::package::installed_target_desktop_bootstrap(),
        )?;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerAckWrite,
            &SessionBrokerFrameV1::Ack {
                binding_sha256: launched.binding_sha256.clone(),
            },
        )
        .map_err(|error| error.to_string())?;
        Ok(BrokeredHolder {
            process,
            thread,
            identity: launched.holder_identity,
            broker_source: launched.broker_source,
            holder_effective: launched.holder_effective,
            query: launched.holder_query,
            launch_binding_sha256: launched.binding_sha256,
            control: None,
        })
    })();
    match transaction_result {
        Ok(mut holder) => {
            holder.control =
                Some(authenticated.into_holder_control(holder.launch_binding_sha256.clone()));
            Ok(holder)
        }
        Err(transaction) => match authenticated.retire() {
            Ok(()) => Err(transaction),
            Err(retirement) => Err(format!(
                "{transaction}; exact_broker_retirement_error={retirement}"
            )),
        },
    }
}

fn retire_authenticated_broker(
    service: &super::service_manager::ScHandle,
    broker: &super::service_manager::PinnedServiceProcess,
) -> Result<(), String> {
    super::service_manager::wait_stopped(service, WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    let status = super::service_manager::status_process(service)?;
    if status.dwCurrentState != SERVICE_STOPPED || status.dwProcessId != 0 {
        return Err(format!(
            "role=session-broker operation=retire phase=scm-stopped expected_state={SERVICE_STOPPED} actual_state={} expected_pid=0 actual_pid={} pinned_pid={} pinned_creation_time_100ns={} win32_exit={} service_exit={}",
            status.dwCurrentState,
            status.dwProcessId,
            broker.identity.process_id,
            broker.identity.creation_time_100ns,
            status.dwWin32ExitCode,
            status.dwServiceSpecificExitCode,
        ));
    }
    super::service_manager::wait_service_process_exit(
        broker,
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        BROKER_TRANSACTION_DEADLINE,
    )?;
    let started = Instant::now();
    loop {
        if !super::pipe::endpoint_exists(WINDOWS_SESSION_BROKER_PIPE)? {
            return Ok(());
        }
        if started.elapsed() >= BROKER_TRANSACTION_DEADLINE {
            return Err(format!(
                "role=session-broker operation=retire phase=endpoint-disappearance pinned_pid={} pinned_creation_time_100ns={} elapsed_ms={} timed_out=true",
                broker.identity.process_id,
                broker.identity.creation_time_100ns,
                started.elapsed().as_millis(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn validate_request(
    request: &SessionBrokerRequestV1,
    hello: &SessionBrokerHelloV1,
    launcher_identity: &WindowsProcessIdentityV1,
) -> Result<(), String> {
    if request.schema_version != SESSION_BROKER_SCHEMA_VERSION
        || request.start_nonce != hello.start_nonce
        || request.challenge != hello.challenge
        || &request.launcher_identity != launcher_identity
        || request.target_session_id == 0
        || request.holder_image_sha256
            != super::package::validate_installed_target_desktop_bootstrap()?
    {
        return Err("session broker request evidence is mismatched".to_owned());
    }
    super::record::validate_attempt_id(&request.holder_nonce)?;
    let expected_pipe = format!(
        "{}{}",
        super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
        request.holder_nonce
    );
    if request.holder_pipe_name != expected_pipe || request.launcher_job_handle == 0 {
        return Err("session broker request surface is not canonical".to_owned());
    }
    Ok(())
}

fn authenticate_launcher_client(
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(OwnedHandle, WindowsProcessIdentityV1), String> {
    let mut pid = 0_u32;
    let mut session = u32::MAX;
    // SAFETY: pipe is connected and outputs are writable.
    if unsafe { GetNamedPipeClientProcessId(pipe, &raw mut pid) } == 0
        || unsafe { GetNamedPipeClientSessionId(pipe, &raw mut session) } == 0
        || session != 0
    {
        return Err("session broker launcher pipe identity query failed".to_owned());
    }
    let process = OwnedHandle::new(unsafe { OpenProcess(LAUNCHER_PROCESS_BROKER_ACCESS, 0, pid) })?;
    verify_exact_handle(
        process.raw(),
        LAUNCHER_PROCESS_BROKER_ACCESS,
        LAUNCHER_PROCESS_BROKER_ACCESS,
        "launcher-process",
        "open",
    )?;
    let identity = super::process::process_identity(process.raw())?;
    super::process::verify_image_path(process.raw(), &super::package::installed_binary())?;
    let token = super::token::process_token(process.raw())?;
    let launcher_sid = super::security::service_sid(WINDOWS_LAUNCHER_SERVICE_NAME)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18"
        || !super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &launcher_sid)?
        || !super::token::token_has_restricting_sid(token.raw(), &launcher_sid)?
    {
        return Err("session broker pipe client is not the restricted launcher".to_owned());
    }
    Ok((process, identity))
}

fn authenticate_broker_server(
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(OwnedHandle, WindowsProcessIdentityV1), String> {
    let mut pid = 0_u32;
    let mut session = u32::MAX;
    // SAFETY: pipe is connected and outputs are writable.
    if unsafe { GetNamedPipeServerProcessId(pipe, &raw mut pid) } == 0
        || unsafe { GetNamedPipeServerSessionId(pipe, &raw mut session) } == 0
        || session != 0
    {
        return Err("session broker server pipe identity query failed".to_owned());
    }
    let process = OwnedHandle::new(unsafe { OpenProcess(BROKER_PROCESS_LAUNCHER_ACCESS, 0, pid) })?;
    verify_exact_handle(
        process.raw(),
        BROKER_PROCESS_LAUNCHER_ACCESS,
        BROKER_PROCESS_LAUNCHER_ACCESS,
        "broker-process",
        "open",
    )?;
    super::process::verify_image_path(process.raw(), &super::package::installed_session_broker())?;
    let token = super::token::process_token(process.raw())?;
    let broker_sid = super::security::service_sid(WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18"
        || super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &broker_sid)?
        || super::token::token_has_restricting_sid(token.raw(), &broker_sid)?
    {
        return Err(
            "session broker server token is not unrestricted broker LocalSystem".to_owned(),
        );
    }
    let identity = super::process::process_identity(process.raw())?;
    Ok((process, identity))
}

fn certify_current_broker() -> Result<(), String> {
    let process = unsafe { GetCurrentProcess() };
    super::process::verify_image_path(process, &super::package::installed_session_broker())?;
    let token = super::token::process_token(process)?;
    let broker_sid = super::security::service_sid(WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18"
        || super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &broker_sid)?
        || super::token::token_has_restricting_sid(token.raw(), &broker_sid)?
    {
        return Err("session broker live token certificate is invalid".to_owned());
    }
    Ok(())
}

fn duplicate_into_launcher(
    source: windows_sys::Win32::Foundation::HANDLE,
    launcher: windows_sys::Win32::Foundation::HANDLE,
    access: u32,
) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: both processes and source are pinned; desired access is exact and
    // the launcher copy is explicitly noninheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            launcher,
            &raw mut remote,
            access,
            0,
            0,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        match encode_protocol_handle(remote, "transferred-holder") {
            Ok(remote) => Ok(remote),
            Err(error) => {
                let cleanup = super::process::revoke_remote_native_handle(remote, launcher);
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        Err(format!("{error}; remote-handle rollback failed: {cleanup}"))
                    }
                }
            }
        }
    }
}

fn encode_protocol_handle(handle: HANDLE, role: &str) -> Result<u64, String> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!("{role} protocol handle is invalid"));
    }
    u64::try_from(handle as usize)
        .map_err(|_| format!("{role} protocol handle is not representable as u64"))
}

pub(crate) fn decode_protocol_handle(value: u64, role: &str) -> Result<HANDLE, String> {
    let native = usize::try_from(value)
        .map_err(|_| format!("{role} protocol handle exceeds native pointer width"))?;
    let handle = native as HANDLE;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!("{role} protocol handle is invalid"));
    }
    Ok(handle)
}

fn verify_exact_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
    requested_access: u32,
    expected_granted_access: u32,
    role: &str,
    operation: &str,
) -> Result<(), String> {
    let mut flags = 0_u32;
    // SAFETY: handle is live and flags is writable.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let inherited = flags & HANDLE_FLAG_INHERIT != 0;
    let actual_granted_access = super::token::granted_handle_access(handle)?;
    if inherited || actual_granted_access != expected_granted_access {
        return Err(format!(
            "role={role} operation={operation} requested_access={requested_access:#010x} expected_granted_access={expected_granted_access:#010x} actual_granted_access={actual_granted_access:#010x} flags={flags:#010x} inherited={inherited}"
        ));
    }
    Ok(())
}

fn launched_binding_sha256(
    request: &SessionBrokerRequestV1,
    launched: &SessionBrokerLaunchedV1,
) -> Result<String, String> {
    let mut launched = launched.clone();
    launched.binding_sha256.clear();
    let bytes = serde_json::to_vec(&(request, launched)).map_err(|error| error.to_string())?;
    let mut domain = b"memcordon-session-broker-binding-v5\0".to_vec();
    domain.extend(bytes);
    Ok(super::record::digest(&domain))
}

fn snapshot_has_enabled_group(
    snapshot: &super::token::TokenAttestationSnapshot,
    sid: &str,
) -> bool {
    snapshot.behavior.groups.iter().any(|entry| {
        entry
            .split_once('@')
            .is_some_and(|(observed_sid, attributes)| {
                observed_sid == sid
                    && u32::from_str_radix(attributes, 16)
                        .is_ok_and(|attributes| attributes & 0x0000_0004 != 0)
            })
    })
}

fn bounded_broker_detail(mut detail: String) -> String {
    const LIMIT: usize = 1_024;
    if detail.len() > LIMIT {
        let mut boundary = LIMIT;
        while !detail.is_char_boundary(boundary) {
            boundary -= 1;
        }
        detail.truncate(boundary);
    }
    detail
}

pub(crate) fn validate_broker_service_arguments(arguments: &[String]) -> Result<&str, String> {
    let [service_name, schema, start_nonce] = arguments else {
        return Err("session broker received an unexpected service argument count".to_owned());
    };
    if service_name != WINDOWS_SESSION_BROKER_SERVICE_NAME
        || schema != &SESSION_BROKER_SCHEMA_VERSION.to_string()
    {
        return Err("session broker service identity or schema argument differs".to_owned());
    }
    Ok(start_nonce)
}

pub(crate) fn validate_broker_start_nonce(start_nonce: &str) -> Result<(), String> {
    super::record::validate_attempt_id(start_nonce)
}

unsafe fn decode_service_arguments(
    count: u32,
    arguments: *mut *mut u16,
) -> Result<Vec<String>, String> {
    if arguments.is_null() {
        return Err("session broker service argument vector is null".to_owned());
    }
    let mut decoded = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let value = unsafe { *arguments.add(index) };
        if value.is_null() {
            return Err("session broker service argument is null".to_owned());
        }
        let mut length = 0_usize;
        while unsafe { *value.add(length) } != 0 {
            length = length
                .checked_add(1)
                .ok_or_else(|| "session broker service argument overflowed".to_owned())?;
        }
        decoded.push(
            String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
                .map_err(|_| "session broker service argument is not Unicode".to_owned())?,
        );
    }
    Ok(decoded)
}
