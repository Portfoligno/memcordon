//! Optional documented object-directory observations; never a gate capability.
#![allow(unsafe_code)]
use super::Proof;
use serde_json::{Value, json};
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CompareObjectHandles, FreeLibrary, GetLastError, HANDLE, HMODULE, OBJ_DONT_REPARSE,
        UNICODE_STRING,
    },
    System::{
        LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        Threading::OpenEventW,
    },
};

const SYNCHRONIZE: u32 = 0x0010_0000;

#[repr(C)]
struct Attributes {
    length: u32,
    root: HANDLE,
    name: *const UNICODE_STRING,
    attributes: u32,
    descriptor: *const std::ffi::c_void,
    quality: *const std::ffi::c_void,
}
type Open = unsafe extern "system" fn(*mut HANDLE, u32, *const Attributes) -> i32;
struct Module(HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
pub struct Api {
    _module: Module,
    directory: Open,
    event: Open,
}
#[derive(Clone, Copy)]
pub struct Failure {
    pub operation: &'static str,
    pub reason: &'static str,
    pub status: Option<i32>,
    pub win32: Option<u32>,
}
pub fn refused(operation: &'static str, reason: &'static str) -> Failure {
    Failure {
        operation,
        reason,
        status: None,
        win32: None,
    }
}
fn win32(operation: &'static str) -> Failure {
    Failure {
        operation,
        reason: "native-unavailable",
        status: None,
        win32: Some(unsafe { GetLastError() }),
    }
}
pub fn live(check: &impl Fn() -> io::Result<()>) -> Result<(), Failure> {
    check().map_err(|_| refused("original-work-clock", "refused"))
}
impl Api {
    pub fn load(check: &impl Fn() -> io::Result<()>) -> Result<Self, Failure> {
        live(check)?;
        let name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
        let raw =
            unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if raw.is_null() {
            return Err(win32("LoadLibraryExW-system32-ntdll"));
        }
        let module = Module(raw);
        live(check)?;
        let directory = unsafe { GetProcAddress(raw, c"NtOpenDirectoryObject".as_ptr().cast()) }
            .ok_or_else(|| win32("GetProcAddress-NtOpenDirectoryObject"))?;
        live(check)?;
        let event = unsafe { GetProcAddress(raw, c"NtOpenEvent".as_ptr().cast()) }
            .ok_or_else(|| win32("GetProcAddress-NtOpenEvent"))?;
        live(check)?;
        Ok(Self {
            _module: module,
            directory: unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Open>(directory)
            },
            event: unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Open>(event)
            },
        })
    }
    pub fn open_recorded(
        &self,
        event: bool,
        root: HANDLE,
        name: &[u16],
        access: u32,
        check: &impl Fn() -> io::Result<()>,
        observed_status: &mut Option<i32>,
    ) -> Result<OwnedHandle, Failure> {
        live(check)?;
        if (event && access != SYNCHRONIZE) || (!event && !matches!(access, 2 | 3)) {
            return Err(refused(
                "native-diagnostic-access",
                "outside-closed-query-contract",
            ));
        }
        if root.is_null() {
            if name.first() != Some(&u16::from(b'\\')) {
                return Err(refused("native-diagnostic-name", "absolute-root-required"));
            }
        } else {
            super::component(name)
                .map_err(|_| refused("native-diagnostic-name", "relative-component-invalid"))?;
        }
        let bytes = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| refused("native-counted-name", "bound"))?;
        if name.is_empty() || name.contains(&0) {
            return Err(refused("native-counted-name", "invalid"));
        }
        let string = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: name.as_ptr().cast_mut(),
        };
        let attributes = Attributes {
            length: size_of::<Attributes>() as u32,
            root,
            name: &string,
            attributes: OBJ_DONT_REPARSE,
            descriptor: ptr::null(),
            quality: ptr::null(),
        };
        let mut raw = ptr::null_mut();
        let status = unsafe {
            (if event { self.event } else { self.directory })(&mut raw, access, &attributes)
        };
        *observed_status = Some(status);
        // Only documented STATUS_SUCCESS transfers a reference. Own it before
        // any subsequent clock/refusal path; failed opens transfer none.
        if status != 0 {
            return Err(Failure {
                operation: if event {
                    "NtOpenEvent"
                } else {
                    "NtOpenDirectoryObject"
                },
                reason: "native-refusal",
                status: Some(status),
                win32: None,
            });
        }
        if raw.is_null() {
            return Err(refused("native-open", "success-without-handle"));
        }
        let owner = unsafe { OwnedHandle::from_raw_handle(raw) };
        live(check)?;
        Ok(owner)
    }
}
pub fn failure_value(error: Failure) -> Value {
    json!({"state":"unavailable","operation":error.operation,"reason":error.reason,"ntstatus":error.status,"raw_os_error":error.win32,"diagnostic_only":true})
}

fn unprefixed_observation(reason: &'static str) -> Value {
    json!({"diagnostic_only":true,"acceptance_authority":false,"name_kind":"unprefixed-original-leaf",
        "desired_access":SYNCHRONIZE,"attempted":false,"open_succeeded":null,"raw_os_error":null,
        "comparison_attempted":false,"same_native_reference":null,"comparison_raw_os_error":null,
        "work_confirmed":false,"source_confirmed":null,
        "completion":{"state":"unavailable","reason":reason},
        "interpretation":"fixture-local reference equality only; controller original identity and denied Local resolution unproved"})
}

fn compare_reference(
    native: &OwnedHandle,
    named: &OwnedHandle,
    check: &impl Fn() -> io::Result<()>,
    observation: &mut Value,
) -> Result<(), Failure> {
    live(check)?;
    observation["comparison_attempted"] = json!(true);
    let same = unsafe { CompareObjectHandles(native.as_raw_handle(), named.as_raw_handle()) } != 0;
    let error = if same {
        None
    } else {
        Some(unsafe { GetLastError() })
    };
    observation["same_native_reference"] = json!(same);
    observation["comparison_raw_os_error"] = json!(error);
    live(check)
}

fn unprefixed_comparison(
    native: &OwnedHandle,
    leaf: &[u16],
    check: &impl Fn() -> io::Result<()>,
) -> Value {
    let mut observation = unprefixed_observation("comparison-not-started");
    let mut run = || -> Result<(), Failure> {
        live(check)?;
        super::component(leaf)
            .map_err(|_| refused("unprefixed-original-leaf", "invalid-component"))?;
        if leaf
            .len()
            .checked_add(1)
            .and_then(|units| units.checked_mul(size_of::<u16>()))
            .is_none_or(|bytes| bytes > super::MAX_PATH_BYTES)
        {
            return Err(refused("unprefixed-original-leaf", "extent-bound"));
        }
        let terminated: Vec<u16> = leaf.iter().copied().chain(Some(0)).collect();
        live(check)?;
        observation["attempted"] = json!(true);
        let raw = unsafe { OpenEventW(SYNCHRONIZE, 0, terminated.as_ptr()) };
        let error = if raw.is_null() {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        // Adopt the one successful named reference before any post-call check.
        let named = if raw.is_null() {
            None
        } else {
            Some(unsafe { OwnedHandle::from_raw_handle(raw) })
        };
        observation["open_succeeded"] = json!(named.is_some());
        observation["raw_os_error"] = json!(error);
        live(check)?;
        if let Some(named) = named.as_ref() {
            compare_reference(native, named, check, &mut observation)?;
        }
        live(check)?;
        observation["work_confirmed"] = json!(true);
        Ok(())
    };
    observation["completion"] = match run() {
        Ok(()) => json!({"state":"observed"}),
        Err(error) => failure_value(error),
    };
    observation
}
pub fn probe(proof: &Proof, check: impl Fn() -> io::Result<()>) -> Value {
    let mut observation = json!({"diagnostic_only":true,"attempted":false,"native_event_status":null,
        "native_event_opened":null,"prefixes":[],"path_sha256":proof.path_sha256,
        "same_original_event_identity_proved":false,"acceptance_authority":false,
        "interpretation":"fixture native-path observation only; original event identity and Win32 mapping unproved"});
    observation["unprefixed_win32_comparison"] =
        unprefixed_observation("native-reference-unavailable");
    let mut run = || -> Result<(), Failure> {
        let api = Api::load(&check)?;
        let path = super::rooted_path(&proof.components)
            .map_err(|_| refused("fixture-native-path", "invalid-proof"))?;
        live(&check)?;
        observation["attempted"] = json!(true);
        let mut native_status = None;
        let opened = api.open_recorded(
            true,
            ptr::null_mut(),
            &path,
            SYNCHRONIZE,
            &check,
            &mut native_status,
        );
        observation["native_event_status"] = json!(native_status);
        observation["native_event_opened"] = json!(native_status.map(|status| status == 0));
        match opened {
            Ok(event) => {
                observation["native_event_status"] = json!(0);
                observation["native_event_opened"] = json!(true);
                let leaf = proof
                    .event_leaf()
                    .map_err(|_| refused("unprefixed-original-leaf", "invalid-proof"))?;
                observation["unprefixed_win32_comparison"] =
                    unprefixed_comparison(&event, leaf, &check);
                drop(event);
            }
            Err(error) if error.status.is_some() => {
                observation["unprefixed_win32_comparison"] =
                    unprefixed_observation("native-reference-not-opened");
                observation["native_event_status"] = json!(error.status);
                observation["native_event_opened"] = json!(false);
                let mut prefixes = Vec::new();
                for count in 1..proof.components.len() {
                    let prefix = super::rooted_path(&proof.components[..count])
                        .map_err(|_| refused("fixture-prefix", "invalid-proof"))?;
                    let mut prefix_status = None;
                    match api.open_recorded(
                        false,
                        ptr::null_mut(),
                        &prefix,
                        2,
                        &check,
                        &mut prefix_status,
                    ) {
                        Ok(owner) => {
                            drop(owner);
                            prefixes.push(json!({"component_count":count,"ntstatus":0,"traverse_opened":true}));
                        }
                        Err(error) => {
                            prefixes.push(json!({"component_count":count,"ntstatus":prefix_status,"attempted":prefix_status.is_some(),"traverse_opened":prefix_status.map(|status|status==0),"reason":error.reason}));
                            observation["prefixes"] = json!(prefixes);
                            return Err(error);
                        }
                    }
                }
                observation["prefixes"] = json!(prefixes);
            }
            Err(error) => return Err(error),
        }
        live(&check)?;
        Ok(())
    };
    observation["completion"] = match run() {
        Ok(()) => json!({"state":"observed"}),
        Err(error) => failure_value(error),
    };
    observation
}

#[cfg(test)]
#[path = "../../../tests/private/windows_gate_namespace.rs"]
mod native_tests;
