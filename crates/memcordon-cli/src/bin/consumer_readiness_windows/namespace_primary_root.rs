//! Public namespace-handle facts only; no wrapper/private-layout interpretation.
use super::namespace_primary_worker::{protocol, remaining};
#[path = "../../../tests/private/fixture_namespace_root_bounds.rs"]
mod bounds;
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::io::{FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Wdk::Foundation::{ObjectBasicInformation, ObjectTypeInformation};
use windows_sys::Win32::{
    Foundation::{FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE, UNICODE_STRING},
    System::{
        LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        Threading::SYNCHRONIZATION_SYNCHRONIZE,
    },
};

// These are exactly Microsoft's documented PUBLIC_* structures. Reserved
// storage is never read or interpreted.
#[repr(C)]
struct PublicType {
    name: UNICODE_STRING,
    reserved: [u32; 22],
}
#[repr(C)]
struct PublicBasic {
    attributes: u32,
    granted: u32,
    handles: u32,
    pointers: u32,
    reserved: [u32; 10],
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: HANDLE,
    name: *const UNICODE_STRING,
    attributes: u32,
    descriptor: *const c_void,
    quality: *const c_void,
}
type Query = unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32, *mut u32) -> i32;
type Open = unsafe extern "system" fn(*mut HANDLE, u32, *const Attributes) -> i32;
struct Module(HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

pub(super) fn observe(
    root: HANDLE,
    request: &protocol::Request,
) -> (protocol::NativeRoot, Option<OwnedHandle>) {
    let mut record = protocol::NativeRoot {
        root_handle: root as usize as u64,
        type_status: None,
        basic_status: None,
        type_name: None,
        granted_access: None,
        handle_attributes: None,
        leaf_utf16: request.event.encode_utf16().collect(),
        desired_access: SYNCHRONIZATION_SYNCHRONIZE,
        object_attributes: 0,
        open_status: None,
        handle: None,
        unavailable: None,
        reason: None,
        deadline: false,
        native_error: None,
    };
    let mut stage = "load-system-ntdll";
    let result = (|| -> io::Result<Option<OwnedHandle>> {
        remaining(request)?;
        let name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
        // SAFETY: load only the documented system module, retained through all calls.
        let raw =
            unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let module = Module(raw);
        remaining(request)?;
        stage = "resolve-public-query";
        let query = unsafe { GetProcAddress(module.0, c"NtQueryObject".as_ptr().cast()) }
            .ok_or_else(io::Error::last_os_error)?;
        // SAFETY: exact documented NtQueryObject ABI from winternl.h.
        let query =
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, Query>(query) };
        stage = "query-type";
        remaining(request)?;
        const BUFFER_BYTES: usize = 8192;
        let mut buffer = vec![0usize; BUFFER_BYTES.div_ceil(size_of::<usize>())];
        let mut returned = 0;
        // SAFETY: exact original held namespace value, aligned bounded output.
        let status = unsafe {
            query(
                root,
                ObjectTypeInformation,
                buffer.as_mut_ptr().cast(),
                u32::try_from(BUFFER_BYTES).unwrap(),
                &mut returned,
            )
        };
        record.type_status = Some(status);
        remaining(request)?;
        if status < 0 {
            record.unavailable = Some("type-query-status".into());
            return Ok(None);
        }
        if returned as usize > BUFFER_BYTES || (returned as usize) < size_of::<PublicType>() {
            return Err(io::Error::other("public type extent"));
        }
        // SAFETY: aligned buffer covers the entire public prefix; no Reserved member is read.
        let name =
            unsafe { ptr::read(ptr::addr_of!((*buffer.as_ptr().cast::<PublicType>()).name)) };
        if !bounds::native_type_name_extent(
            buffer.as_ptr() as usize,
            returned as usize,
            name.Buffer as usize,
            name.Length,
            name.MaximumLength,
        ) {
            return Err(io::Error::other("public type name extent"));
        }
        let offset = (name.Buffer as usize)
            .checked_sub(buffer.as_ptr() as usize)
            .ok_or_else(|| io::Error::other("public name address"))?;
        if offset < size_of::<PublicType>() {
            return Err(io::Error::other("type name overlaps public header"));
        }
        // SAFETY: checked alignment and complete counted extent, buffer remains owned.
        let units = unsafe {
            std::slice::from_raw_parts(name.Buffer, usize::from(name.Length) / size_of::<u16>())
        };
        record.type_name = Some(String::from_utf16(units).map_err(io::Error::other)?);
        stage = "query-basic";
        remaining(request)?;
        let mut basic = PublicBasic {
            attributes: 0,
            granted: 0,
            handles: 0,
            pointers: 0,
            reserved: [0; 10],
        };
        returned = 0;
        // SAFETY: only documented public basic structure, exact owned root value.
        let status = unsafe {
            query(
                root,
                ObjectBasicInformation,
                ptr::from_mut(&mut basic).cast(),
                u32::try_from(size_of::<PublicBasic>()).unwrap(),
                &mut returned,
            )
        };
        record.basic_status = Some(status);
        remaining(request)?;
        if status < 0 {
            record.unavailable = Some("basic-query-status".into());
            return Ok(None);
        }
        if returned as usize != size_of::<PublicBasic>() {
            return Err(io::Error::other("public basic extent"));
        }
        record.granted_access = Some(basic.granted);
        record.handle_attributes = Some(basic.attributes);
        if record.type_name.as_deref() != Some("Directory") {
            record.unavailable = Some("not-directory".into());
            return Ok(None);
        }
        stage = "resolve-native-event";
        remaining(request)?;
        let open = unsafe { GetProcAddress(module.0, c"NtOpenEvent".as_ptr().cast()) }
            .ok_or_else(io::Error::last_os_error)?;
        // SAFETY: exact documented NtOpenEvent ABI and OBJECT_ATTRIBUTES layout.
        let open =
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, Open>(open) };
        let bytes = record
            .leaf_utf16
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| io::Error::other("counted leaf bound"))?;
        let name = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: record.leaf_utf16.as_mut_ptr(),
        };
        let attributes = Attributes {
            length: u32::try_from(size_of::<Attributes>()).unwrap(),
            root,
            name: &name,
            attributes: 0,
            descriptor: ptr::null(),
            quality: ptr::null(),
        };
        stage = "native-relative-open";
        remaining(request)?;
        let mut handle = ptr::null_mut();
        // SAFETY: SAME unchanged held namespace root, canonical counted leaf,
        // exactly SYNCHRONIZE, Attributes=0 (not OBJ_DONT_REPARSE), no SD/QOS.
        let status = unsafe { open(&mut handle, SYNCHRONIZATION_SYNCHRONIZE, &attributes) };
        record.open_status = Some(status);
        if status < 0 {
            record.unavailable = Some("native-open-status".into());
            return Ok(None);
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("native success without owned handle"));
        }
        // SAFETY: valid successful return transfers the one native handle.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
        remaining(request)?;
        record.handle = Some(handle as usize as u64);
        Ok(Some(owned))
    })();
    match result {
        Ok(handle) => (record, handle),
        Err(error) => {
            record.unavailable = Some(stage.into());
            record.reason = Some(
                memcordon_core::BoundedText::new(&error.to_string()).unwrap_or_else(|_| {
                    memcordon_core::BoundedText::new("diagnostic reason exceeds bound")
                        .expect("fixed reason fits")
                }),
            );
            record.deadline = error.kind() == io::ErrorKind::TimedOut;
            record.native_error = error.raw_os_error();
            (record, None)
        }
    }
}
