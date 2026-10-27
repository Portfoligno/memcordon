//! Bounded controller-only original-event namespace discovery.
#![allow(unsafe_code)]
use crate::windows_consumer_readiness::descriptor::gate_access::{
    self as access, namespace as namespace_input,
};
use namespace_input::{
    Proof,
    native::{Api, Failure, failure_value, live, refused},
};
#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/controller_gate_namespace_directory.rs"]
mod directory;
use directory::Counted;
use serde_json::{Value, json};
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CompareObjectHandles, FreeLibrary, HANDLE, HMODULE, STATUS_NO_MORE_ENTRIES, UNICODE_STRING,
    },
    System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
};
const BUFFER_BYTES: usize = directory::MAX_BUFFER_BYTES;
const DIRECTORY_BOUND: usize = 256;
const ENTRY_BOUND: usize = 4096;
const DIRECTORY_DEPTH: usize = namespace_input::MAX_COMPONENTS - 1;
const SYNCHRONIZE: u32 = 0x0010_0000;
#[repr(C)]
#[derive(Clone, Copy)]
struct DirectoryEntry {
    name: UNICODE_STRING,
    kind: UNICODE_STRING,
}
type Query = unsafe extern "system" fn(
    HANDLE,
    *mut std::ffi::c_void,
    u32,
    u8,
    u8,
    *mut u32,
    *mut u32,
) -> i32;
struct QueryOwner {
    module: HMODULE,
    function: Query,
}
impl Drop for QueryOwner {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}
impl QueryOwner {
    fn load(check: &impl Fn() -> io::Result<()>) -> Result<Self, Failure> {
        live(check)?;
        let name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
        let module =
            unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(Failure {
                operation: "LoadLibraryExW-query-ntdll",
                reason: "unavailable",
                status: None,
                win32: Some(unsafe { windows_sys::Win32::Foundation::GetLastError() }),
            });
        }
        // Own module before clock checks or symbol lookup can fail.
        struct Pending(HMODULE);
        impl Drop for Pending {
            fn drop(&mut self) {
                unsafe {
                    FreeLibrary(self.0);
                }
            }
        }
        let pending = Pending(module);
        live(check)?;
        let function = unsafe { GetProcAddress(module, c"NtQueryDirectoryObject".as_ptr().cast()) }
            .ok_or_else(|| Failure {
                operation: "GetProcAddress-NtQueryDirectoryObject",
                reason: "unavailable",
                status: None,
                win32: Some(unsafe { windows_sys::Win32::Foundation::GetLastError() }),
            })?;
        live(check)?;
        let owner = Self {
            module,
            function: unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Query>(function)
            },
        };
        std::mem::forget(pending);
        Ok(owner)
    }
}
fn open(
    api: &Api,
    event: bool,
    root: HANDLE,
    name: &[u16],
    access: u32,
    check: &impl Fn() -> io::Result<()>,
) -> Result<OwnedHandle, Failure> {
    api.open_recorded(event, root, name, access, check, &mut None)
}
struct Frame {
    owner: OwnedHandle,
    component: Vec<u16>,
    context: u32,
    restart: bool,
}
pub struct Discovery {
    pub proof: Option<Proof>,
    pub observation: Value,
    _ancestors: Vec<OwnedHandle>,
}
impl Discovery {
    pub fn recheck(&self, original: &OwnedHandle, check: impl Fn() -> io::Result<()>) -> Value {
        let run = || -> Result<Value, Failure> {
            let proof = self
                .proof
                .as_ref()
                .ok_or_else(|| refused("controller-path-readback", "no-original-proof"))?;
            let api = Api::load(&check)?;
            let path = namespace_input::rooted_path(&proof.components)
                .map_err(|_| refused("controller-path-readback", "invalid-proof-path"))?;
            let reopened = open(&api, true, ptr::null_mut(), &path, SYNCHRONIZE, &check)?;
            live(&check)?;
            let same =
                unsafe { CompareObjectHandles(original.as_raw_handle(), reopened.as_raw_handle()) }
                    != 0;
            live(&check)?;
            Ok(
                json!({"state":if same {"observed"} else {"unavailable"},"reason":if same {None} else {Some("inconclusive: original path join changed")},"diagnostic_only":true,"controller_same_original":same,"path_sha256":proof.path_sha256,
                "interpretation":"controller-context equality only; fixture identity and Win32 mapping unproved"}),
            )
        };
        run().unwrap_or_else(failure_value)
    }
}

pub fn discover(
    original: &OwnedHandle,
    name: &[u16],
    binding: &access::Input,
    check: impl Fn() -> io::Result<()>,
) -> Discovery {
    let mut directories = 0_usize;
    let mut entries = 0_usize;
    let mut parser_failure = None;
    let run = || -> Result<(Proof, Vec<OwnedHandle>), Failure> {
        live(&check)?;
        let prefix: Vec<u16> = "Local\\".encode_utf16().collect();
        let leaf = name
            .strip_prefix(prefix.as_slice())
            .ok_or_else(|| refused("owned-gate-leaf-hint", "unsupported-win32-name"))?;
        if leaf.is_empty() || leaf.iter().any(|unit| matches!(*unit, 0 | 0x2f | 0x5c)) {
            return Err(refused("owned-gate-leaf-hint", "invalid"));
        }
        let api = Api::load(&check)?;
        let query = QueryOwner::load(&check)?;
        let root_name = [u16::from(b'\\')];
        let root = open(&api, false, ptr::null_mut(), &root_name, 3, &check)?;
        directories += 1;
        let mut stack = vec![Frame {
            owner: root,
            component: Vec::new(),
            context: 0,
            restart: true,
        }];
        let mut buffer = vec![0usize; BUFFER_BYTES.div_ceil(size_of::<usize>())];
        while !stack.is_empty() {
            live(&check)?;
            if entries >= ENTRY_BOUND {
                return Err(refused("directory-discovery", "entry-bound"));
            }
            let directory_depth = stack.len() - 1;
            let frame = stack.last_mut().expect("nonempty traversal");
            let before = frame.context;
            let mut returned = 0;
            buffer.fill(0);
            let status = unsafe {
                (query.function)(
                    frame.owner.as_raw_handle(),
                    buffer.as_mut_ptr().cast(),
                    BUFFER_BYTES as u32,
                    1,
                    u8::from(frame.restart),
                    &mut frame.context,
                    &mut returned,
                )
            };
            frame.restart = false;
            live(&check)?;
            if status == STATUS_NO_MORE_ENTRIES {
                stack.pop();
                continue;
            }
            if status != 0 {
                return Err(Failure {
                    operation: "NtQueryDirectoryObject",
                    reason: "native-refusal",
                    status: Some(status),
                    win32: None,
                });
            }
            if frame.context == before
                || returned as usize > BUFFER_BYTES
                || (returned as usize) < size_of::<DirectoryEntry>()
            {
                return Err(refused(
                    "NtQueryDirectoryObject",
                    "no-progress-or-invalid-extent",
                ));
            }
            entries += 1;
            let header = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<DirectoryEntry>()) };
            let bytes = unsafe {
                std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize)
            };
            let counted = |s: UNICODE_STRING| Counted {
                length: s.Length,
                maximum_length: s.MaximumLength,
                address: s.Buffer as usize,
            };
            let entry = directory::entry(
                bytes,
                buffer.as_ptr() as usize,
                counted(header.name),
                counted(header.kind),
                size_of::<DirectoryEntry>(),
            )
            .and_then(|entry| {
                let class = entry.classify(leaf)?;
                Ok((entry, class))
            })
            .map_err(|error| {
                let relative = |value: UNICODE_STRING| {
                    let offset = (value.Buffer as usize).checked_sub(buffer.as_ptr() as usize);
                    json!({"length":value.Length,"maximum_length":value.MaximumLength,
                        "relative_offset":offset,"address_aligned":(value.Buffer as usize) & (align_of::<u16>() - 1) == 0,
                        "checked_extent":offset.and_then(|start|start.checked_add(usize::from(value.MaximumLength)))})
                };
                parser_failure = Some(json!({
                    "failure":error.get_ref().and_then(|source|source.downcast_ref::<directory::ParseFailure>()),
                    "returned_bytes":returned,"allocation_bytes":BUFFER_BYTES,"header_bytes":size_of::<DirectoryEntry>(),
                    "name":relative(header.name),"kind":relative(header.kind),"entry_ordinal":entries,
                    "directory_depth":directory_depth,"context_before":before,"context_after":frame.context,
                    "query_ntstatus":status
                }));
                refused("native-directory-entry", "malformed")
            })?;
            let (entry, class) = entry;
            if class == directory::EntryClass::Directory {
                if stack.len() > DIRECTORY_DEPTH || directories >= DIRECTORY_BOUND {
                    return Err(refused(
                        "directory-discovery",
                        "directory-depth-or-count-bound",
                    ));
                }
                let path_bytes = stack
                    .iter()
                    .map(|frame| (frame.component.len() + 1) * size_of::<u16>())
                    .sum::<usize>();
                if path_bytes
                    .checked_add((entry.name.len() + 1) * size_of::<u16>())
                    .is_none_or(|size| size > namespace_input::MAX_PATH_BYTES)
                {
                    return Err(refused("directory-discovery", "path-storage-bound"));
                }
                let child = open(
                    &api,
                    false,
                    stack.last().expect("parent retained").owner.as_raw_handle(),
                    &entry.name,
                    3,
                    &check,
                )?;
                directories += 1;
                stack.push(Frame {
                    owner: child,
                    component: entry.name,
                    context: 0,
                    restart: true,
                });
            } else if class == directory::EntryClass::SelectedEvent {
                let candidate = open(
                    &api,
                    true,
                    stack.last().expect("parent retained").owner.as_raw_handle(),
                    &entry.name,
                    SYNCHRONIZE,
                    &check,
                )?;
                live(&check)?;
                let same = unsafe {
                    CompareObjectHandles(original.as_raw_handle(), candidate.as_raw_handle())
                } != 0;
                live(&check)?;
                if !same {
                    continue;
                }
                let mut components: Vec<Vec<u16>> = stack
                    .iter()
                    .skip(1)
                    .map(|frame| frame.component.clone())
                    .collect();
                components.push(entry.name);
                let path = namespace_input::rooted_path(&components)
                    .map_err(|_| refused("owned-gate-path", "bound"))?;
                let absolute = open(&api, true, ptr::null_mut(), &path, SYNCHRONIZE, &check)?;
                live(&check)?;
                let absolute_same = unsafe {
                    CompareObjectHandles(original.as_raw_handle(), absolute.as_raw_handle())
                } != 0;
                live(&check)?;
                if !absolute_same {
                    return Err(refused(
                        "controller-absolute-path",
                        "original-object-differs",
                    ));
                }
                let proof = Proof {
                    revision: 1,
                    components,
                    path_sha256: access::name_sha256(&path),
                    name_utf16_sha256: binding.name_utf16_sha256.clone(),
                    challenge_sha256: binding.challenge_sha256.clone(),
                    descriptor_sha256: binding.descriptor_sha256.clone(),
                    work_cutoff_qpc: binding.work_cutoff_qpc,
                    qpc_frequency: binding.qpc_frequency,
                    controller_same_original: true,
                    controller_absolute_same_original: true,
                    complete: true,
                };
                live(&check)?;
                return Ok((proof, stack.into_iter().map(|frame| frame.owner).collect()));
            }
        }
        Err(refused("directory-discovery", "owned-gate-not-found"))
    };
    let mut run = run;
    let (proof, ancestors, mut observation) = match run() {
        Ok((proof, ancestors)) => {
            let observation = json!({"state":"observed","diagnostic_only":true,"path_sha256":proof.path_sha256,
                "controller_same_original":true,"controller_absolute_same_original":true,"complete":true,
                "interpretation":"enumerated original controller event only; no fixture identity or Win32 mapping proof"});
            (Some(proof), ancestors, observation)
        }
        Err(error) => (None, Vec::new(), failure_value(error)),
    };
    observation["directories_opened"] = json!(directories);
    observation["entries_observed"] = json!(entries);
    if let Some(failure) = parser_failure {
        observation["parser_failure"] = failure;
    }
    Discovery {
        proof,
        observation,
        _ancestors: ancestors,
    }
}
