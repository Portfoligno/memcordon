use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HANDLE, HMODULE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

type CloseDesktopFn = unsafe extern "system" fn(HANDLE) -> i32;
type CloseWindowStationFn = unsafe extern "system" fn(HANDLE) -> i32;
type CreateDesktopWFn = unsafe extern "system" fn(
    *const u16,
    *const u16,
    *const c_void,
    u32,
    u32,
    *const SECURITY_ATTRIBUTES,
) -> HANDLE;
type CreateWindowStationWFn =
    unsafe extern "system" fn(*const u16, u32, u32, *const SECURITY_ATTRIBUTES) -> HANDLE;
type EnumDesktopsWFn = unsafe extern "system" fn(
    HANDLE,
    Option<unsafe extern "system" fn(*const u16, isize) -> i32>,
    isize,
) -> i32;
type GetProcessWindowStationFn = unsafe extern "system" fn() -> HANDLE;
type GetThreadDesktopFn = unsafe extern "system" fn(u32) -> HANDLE;
type GetUserObjectInformationWFn =
    unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32, *mut u32) -> i32;
type GetUserObjectSecurityFn =
    unsafe extern "system" fn(HANDLE, *const u32, *mut c_void, u32, *mut u32) -> i32;
type OpenDesktopWFn = unsafe extern "system" fn(*const u16, u32, i32, u32) -> HANDLE;
type OpenWindowStationWFn = unsafe extern "system" fn(*const u16, i32, u32) -> HANDLE;
type SetProcessWindowStationFn = unsafe extern "system" fn(HANDLE) -> i32;
type SetThreadDesktopFn = unsafe extern "system" fn(HANDLE) -> i32;

struct UserApi {
    _module: HMODULE,
    close_desktop: CloseDesktopFn,
    close_window_station: CloseWindowStationFn,
    create_desktop_w: CreateDesktopWFn,
    create_window_station_w: CreateWindowStationWFn,
    enum_desktops_w: EnumDesktopsWFn,
    get_process_window_station: GetProcessWindowStationFn,
    get_thread_desktop: GetThreadDesktopFn,
    get_user_object_information_w: GetUserObjectInformationWFn,
    get_user_object_security: GetUserObjectSecurityFn,
    open_desktop_w: OpenDesktopWFn,
    open_window_station_w: OpenWindowStationWFn,
    set_process_window_station: SetProcessWindowStationFn,
    set_thread_desktop: SetThreadDesktopFn,
}

unsafe impl Send for UserApi {}
unsafe impl Sync for UserApi {}

static USER_API: OnceLock<UserApi> = OnceLock::new();

fn system_user32_path() -> Result<Vec<u16>, String> {
    let required = unsafe { GetSystemDirectoryW(ptr::null_mut(), 0) };
    if required == 0 {
        return Err(format!(
            "cannot size the trusted System32 path: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut directory = vec![0_u16; required as usize];
    let written = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), required) };
    if written == 0 || written >= required {
        return Err(format!(
            "cannot capture the trusted System32 path: {}",
            std::io::Error::last_os_error()
        ));
    }
    directory.truncate(written as usize);
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let directory = std::ffi::OsString::from_wide(&directory);
    let module = PathBuf::from(directory).join("user32.dll");
    let mut wide = module.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    Ok(wide)
}

unsafe fn address(module: HMODULE, name: &'static [u8]) -> Result<*const c_void, String> {
    let procedure = unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or_else(|| {
        format!(
            "System32 user32 export is absent: {}",
            String::from_utf8_lossy(name)
        )
    })?;
    Ok(procedure as *const () as *const c_void)
}

impl UserApi {
    fn load() -> Result<Self, String> {
        let path = system_user32_path()?;
        let module = unsafe { LoadLibraryExW(path.as_ptr(), ptr::null_mut(), 0) };
        if module.is_null() {
            return Err(format!(
                "cannot load trusted System32 user32.dll: {}",
                std::io::Error::last_os_error()
            ));
        }
        macro_rules! resolve {
            ($name:literal, $ty:ty) => {{
                let address = unsafe { address(module, concat!($name, "\0").as_bytes())? };
                unsafe { std::mem::transmute::<*const c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            _module: module,
            close_desktop: resolve!("CloseDesktop", CloseDesktopFn),
            close_window_station: resolve!("CloseWindowStation", CloseWindowStationFn),
            create_desktop_w: resolve!("CreateDesktopW", CreateDesktopWFn),
            create_window_station_w: resolve!("CreateWindowStationW", CreateWindowStationWFn),
            enum_desktops_w: resolve!("EnumDesktopsW", EnumDesktopsWFn),
            get_process_window_station: resolve!(
                "GetProcessWindowStation",
                GetProcessWindowStationFn
            ),
            get_thread_desktop: resolve!("GetThreadDesktop", GetThreadDesktopFn),
            get_user_object_information_w: resolve!(
                "GetUserObjectInformationW",
                GetUserObjectInformationWFn
            ),
            get_user_object_security: resolve!("GetUserObjectSecurity", GetUserObjectSecurityFn),
            open_desktop_w: resolve!("OpenDesktopW", OpenDesktopWFn),
            open_window_station_w: resolve!("OpenWindowStationW", OpenWindowStationWFn),
            set_process_window_station: resolve!(
                "SetProcessWindowStation",
                SetProcessWindowStationFn
            ),
            set_thread_desktop: resolve!("SetThreadDesktop", SetThreadDesktopFn),
        })
    }
}

pub fn load() -> Result<(), String> {
    if USER_API.get().is_some() {
        return Ok(());
    }
    let api = UserApi::load()?;
    let _ = USER_API.set(api);
    Ok(())
}

fn api() -> &'static UserApi {
    load().unwrap_or_else(|error| panic!("USER API contract failed: {error}"));
    USER_API.get().expect("USER API must be initialized")
}

pub unsafe fn close_desktop(handle: HANDLE) -> i32 {
    unsafe { (api().close_desktop)(handle) }
}
pub unsafe fn close_window_station(handle: HANDLE) -> i32 {
    unsafe { (api().close_window_station)(handle) }
}
pub unsafe fn create_desktop_w(
    name: *const u16,
    device: *const u16,
    device_mode: *const c_void,
    flags: u32,
    access: u32,
    attributes: *const SECURITY_ATTRIBUTES,
) -> HANDLE {
    unsafe { (api().create_desktop_w)(name, device, device_mode, flags, access, attributes) }
}
pub unsafe fn create_window_station_w(
    name: *const u16,
    flags: u32,
    access: u32,
    attributes: *const SECURITY_ATTRIBUTES,
) -> HANDLE {
    unsafe { (api().create_window_station_w)(name, flags, access, attributes) }
}
pub unsafe fn enum_desktops_w(
    station: HANDLE,
    callback: Option<unsafe extern "system" fn(*const u16, isize) -> i32>,
    state: isize,
) -> i32 {
    unsafe { (api().enum_desktops_w)(station, callback, state) }
}
pub unsafe fn get_process_window_station() -> HANDLE {
    unsafe { (api().get_process_window_station)() }
}
pub unsafe fn get_thread_desktop(thread_id: u32) -> HANDLE {
    unsafe { (api().get_thread_desktop)(thread_id) }
}
pub unsafe fn get_user_object_information_w(
    handle: HANDLE,
    index: i32,
    information: *mut c_void,
    length: u32,
    needed: *mut u32,
) -> i32 {
    unsafe { (api().get_user_object_information_w)(handle, index, information, length, needed) }
}
pub unsafe fn get_user_object_security(
    handle: HANDLE,
    requested: *const u32,
    descriptor: *mut c_void,
    length: u32,
    needed: *mut u32,
) -> i32 {
    unsafe { (api().get_user_object_security)(handle, requested, descriptor, length, needed) }
}
pub unsafe fn open_desktop_w(name: *const u16, flags: u32, inherit: i32, access: u32) -> HANDLE {
    unsafe { (api().open_desktop_w)(name, flags, inherit, access) }
}
pub unsafe fn open_window_station_w(name: *const u16, inherit: i32, access: u32) -> HANDLE {
    unsafe { (api().open_window_station_w)(name, inherit, access) }
}
pub unsafe fn set_process_window_station(handle: HANDLE) -> i32 {
    unsafe { (api().set_process_window_station)(handle) }
}
pub unsafe fn set_thread_desktop(handle: HANDLE) -> i32 {
    unsafe { (api().set_thread_desktop)(handle) }
}
