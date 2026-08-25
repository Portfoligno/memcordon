use std::io;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatusEx, SC_ACTION, SC_ACTION_RESTART,
    SC_HANDLE, SC_MANAGER_ALL_ACCESS, SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL,
    SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_RUNNING, SERVICE_SID_INFO, SERVICE_START,
    SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS, StartServiceW,
};

use super::pipe::wide_null;

const SERVICE_SID_TYPE_RESTRICTED: u32 = 3;
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;

pub struct ScHandle(SC_HANDLE);

struct ServiceQueryBuffer {
    words: Vec<usize>,
    byte_length: usize,
}

impl ServiceQueryBuffer {
    fn with_byte_length(byte_length: usize) -> Self {
        let word_size = std::mem::size_of::<usize>();
        Self {
            words: vec![0; byte_length.div_ceil(word_size)],
            byte_length,
        }
    }

    fn as_ptr<T>(&self) -> *const T {
        self.words.as_ptr().cast()
    }

    fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.words.as_mut_ptr().cast()
    }

    fn contains<T>(&self, pointer: *const T, count: usize) -> bool {
        let start = self.words.as_ptr() as usize;
        let Some(end) = start.checked_add(self.byte_length) else {
            return false;
        };
        let pointer = pointer as usize;
        let Some(pointer_end) = count
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|bytes| pointer.checked_add(bytes))
        else {
            return false;
        };
        pointer >= start && pointer_end <= end
    }
}

impl ScHandle {
    pub const fn raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper owns the exact SCM handle and closes it once.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

pub fn manager() -> Result<ScHandle, String> {
    // SAFETY: null names select the local active SCM database; returned handle
    // is transferred into ScHandle.
    let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if handle.is_null() {
        Err(format!(
            "MCSEALED-WINDOWS-ELEVATION: cannot open the service manager: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(ScHandle(handle))
    }
}

pub struct ServiceConfig<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
    pub binary_command: &'a str,
    pub account: Option<&'a str>,
    pub dependencies: &'a [&'a str],
    pub required_privileges: &'a [&'a str],
}

pub fn create(manager: &ScHandle, config: &ServiceConfig<'_>) -> Result<ScHandle, String> {
    let name = wide_null(config.name);
    let display = wide_null(config.display_name);
    let command = wide_null(config.binary_command);
    let account = config.account.map(wide_null);
    let dependencies = dependency_multistring(config.dependencies);
    // SAFETY: every supplied UTF-16 pointer is NUL-terminated and lives through
    // the call. SCM owns its copied configuration; the handle is locally owned.
    let handle = unsafe {
        CreateServiceW(
            manager.raw(),
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            dependencies
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
            ptr::null_mut(),
            ptr::null(),
            account.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            ptr::null(),
        )
    };
    if handle.is_null() {
        return Err(format!(
            "cannot create fresh service {}: {}",
            config.name,
            io::Error::last_os_error()
        ));
    }
    let service = ScHandle(handle);
    update_base_configuration(&service, config)?;
    configure_restrictions(&service, config.required_privileges)?;
    configure_failure_actions(&service)?;
    super::security::SecurityDescriptor::from_sddl(super::security::SERVICE_CONTROL_SDDL)?
        .apply_to_service(service.raw())?;
    Ok(service)
}

pub fn reconcile(manager: &ScHandle, config: &ServiceConfig<'_>) -> Result<ScHandle, String> {
    let service = if exists(manager, config.name)? {
        open(manager, config.name, SERVICE_ALL_ACCESS)?
    } else {
        return create(manager, config);
    };
    update_base_configuration(&service, config)?;
    configure_restrictions(&service, config.required_privileges)?;
    configure_failure_actions(&service)?;
    super::security::SecurityDescriptor::from_sddl(super::security::SERVICE_CONTROL_SDDL)?
        .apply_to_service(service.raw())?;
    Ok(service)
}

fn update_base_configuration(service: &ScHandle, config: &ServiceConfig<'_>) -> Result<(), String> {
    let command = wide_null(config.binary_command);
    let display = wide_null(config.display_name);
    let account = config.account.map(wide_null);
    let dependencies = dependency_multistring(config.dependencies);
    // SAFETY: all optional strings are NUL-terminated and live through the
    // synchronous update. Numeric fields replace the exact base configuration.
    if unsafe {
        ChangeServiceConfigW(
            service.raw(),
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            dependencies
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
            ptr::null_mut(),
            ptr::null(),
            account.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            ptr::null(),
            display.as_ptr(),
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

pub fn open(manager: &ScHandle, name: &str, access: u32) -> Result<ScHandle, String> {
    let name = wide_null(name);
    // SAFETY: name is a live NUL-terminated string and the returned handle is
    // transferred into ScHandle.
    let handle = unsafe { OpenServiceW(manager.raw(), name.as_ptr(), access) };
    if handle.is_null() {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(ScHandle(handle))
    }
}

pub fn exists(manager: &ScHandle, name: &str) -> Result<bool, String> {
    let name = wide_null(name);
    // SAFETY: name is a live NUL-terminated service name and the returned
    // handle, when present, transfers to ScHandle.
    let handle = unsafe { OpenServiceW(manager.raw(), name.as_ptr(), SERVICE_QUERY_STATUS) };
    if !handle.is_null() {
        drop(ScHandle(handle));
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error
        .raw_os_error()
        .and_then(|value| u32::try_from(value).ok())
        == Some(ERROR_SERVICE_DOES_NOT_EXIST)
    {
        Ok(false)
    } else {
        Err(error.to_string())
    }
}

pub fn verify(manager: &ScHandle, config: &ServiceConfig<'_>) -> Result<(), String> {
    let service = open(
        manager,
        config.name,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL_ACCESS,
    )?;
    let base = query_base(&service)?;
    // SAFETY: query_base allocated native-aligned storage for this header.
    let base_header = unsafe { ptr::read(base.as_ptr::<QUERY_SERVICE_CONFIGW>()) };
    if base_header.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || base_header.dwStartType != SERVICE_AUTO_START
        || base_header.dwErrorControl != SERVICE_ERROR_NORMAL
        || !wide_pointer_string(&base, base_header.lpBinaryPathName)?
            .eq_ignore_ascii_case(config.binary_command)
        || !wide_pointer_string(&base, base_header.lpServiceStartName)?
            .eq_ignore_ascii_case(config.account.unwrap_or("LocalSystem"))
        || wide_pointer_multistring(&base, base_header.lpDependencies)?
            != config
                .dependencies
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
    {
        return Err(format!(
            "Windows sealed service base configuration differs: {}",
            config.name
        ));
    }
    let required_buffer = query_config2(&service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)?;
    // SAFETY: buffer contains the requested fixed header and embedded string.
    let required =
        unsafe { ptr::read(required_buffer.as_ptr::<SERVICE_REQUIRED_PRIVILEGES_INFOW>()) };
    if wide_pointer_multistring(&required_buffer, required.pmszRequiredPrivileges)?
        != config
            .required_privileges
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    {
        return Err(format!(
            "Windows sealed service privilege inventory differs: {}",
            config.name
        ));
    }
    let sid = query_config2(&service, SERVICE_CONFIG_SERVICE_SID_INFO)?;
    // SAFETY: buffer contains a SERVICE_SID_INFO fixed structure.
    if unsafe { ptr::read(sid.as_ptr::<SERVICE_SID_INFO>()) }.dwServiceSidType
        != SERVICE_SID_TYPE_RESTRICTED
    {
        return Err(format!(
            "Windows sealed service SID type differs: {}",
            config.name
        ));
    }
    let failures_buffer = query_config2(&service, SERVICE_CONFIG_FAILURE_ACTIONS)?;
    // SAFETY: buffer contains SERVICE_FAILURE_ACTIONSW and cActions embedded
    // actions returned by SCM.
    let failures = unsafe { ptr::read(failures_buffer.as_ptr::<SERVICE_FAILURE_ACTIONSW>()) };
    if failures.cActions != 0
        && (failures.lpsaActions.is_null()
            || !failures_buffer.contains(failures.lpsaActions, failures.cActions as usize))
    {
        return Err(format!(
            "Windows sealed service failure-action buffer is invalid: {}",
            config.name
        ));
    }
    let actions = (0..failures.cActions as usize)
        .map(|index| unsafe { ptr::read_unaligned(failures.lpsaActions.add(index)) })
        .collect::<Vec<_>>();
    if failures.dwResetPeriod != 24 * 60 * 60
        || actions.len() != 2
        || actions[0].Type != SC_ACTION_RESTART
        || actions[0].Delay != 1_000
        || actions[1].Type != SC_ACTION_RESTART
        || actions[1].Delay != 5_000
    {
        return Err(format!(
            "Windows sealed service failure actions differ: {}",
            config.name
        ));
    }
    super::security::SecurityDescriptor::from_sddl(super::security::SERVICE_CONTROL_SDDL)?
        .verify_service(service.raw())?;
    Ok(())
}

fn dependency_multistring(dependencies: &[&str]) -> Option<Vec<u16>> {
    if dependencies.is_empty() {
        return None;
    }
    let mut multistring = Vec::new();
    for dependency in dependencies {
        multistring.extend(dependency.encode_utf16());
        multistring.push(0);
    }
    multistring.push(0);
    Some(multistring)
}

fn query_base(service: &ScHandle) -> Result<ServiceQueryBuffer, String> {
    let mut needed = 0_u32;
    // SAFETY: null-buffer query writes only the required size.
    unsafe { QueryServiceConfigW(service.raw(), ptr::null_mut(), 0, &raw mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut bytes = ServiceQueryBuffer::with_byte_length(needed as usize);
    // SAFETY: bytes has the exact requested capacity and remains live.
    if unsafe { QueryServiceConfigW(service.raw(), bytes.as_mut_ptr(), needed, &raw mut needed) }
        == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(bytes)
    }
}

fn query_config2(service: &ScHandle, level: u32) -> Result<ServiceQueryBuffer, String> {
    let mut needed = 0_u32;
    // SAFETY: null-buffer query writes only the required size.
    unsafe { QueryServiceConfig2W(service.raw(), level, ptr::null_mut(), 0, &raw mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut bytes = ServiceQueryBuffer::with_byte_length(needed as usize);
    // SAFETY: bytes has the exact requested capacity and remains live.
    if unsafe {
        QueryServiceConfig2W(
            service.raw(),
            level,
            bytes.as_mut_ptr(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(bytes)
    }
}

fn wide_pointer_string(buffer: &ServiceQueryBuffer, pointer: *const u16) -> Result<String, String> {
    if pointer.is_null() {
        return Ok(String::new());
    }
    let mut length = 0_usize;
    while buffer.contains(unsafe { pointer.add(length) }, 1) {
        // SAFETY: the range check proves the current element is readable.
        if unsafe { ptr::read_unaligned(pointer.add(length)) } == 0 {
            let value = (0..length)
                .map(|index| unsafe { ptr::read_unaligned(pointer.add(index)) })
                .collect::<Vec<_>>();
            return Ok(String::from_utf16_lossy(&value));
        }
        length += 1;
    }
    Err("SCM returned an unterminated string outside its query buffer".to_owned())
}

fn wide_pointer_multistring(
    buffer: &ServiceQueryBuffer,
    pointer: *const u16,
) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    if pointer.is_null() {
        return Ok(values);
    }
    let mut offset = 0_usize;
    loop {
        if !buffer.contains(unsafe { pointer.add(offset) }, 1) {
            return Err("SCM returned a multistring outside its query buffer".to_owned());
        }
        if unsafe { ptr::read_unaligned(pointer.add(offset)) } == 0 {
            return Ok(values);
        }
        let start = offset;
        loop {
            if !buffer.contains(unsafe { pointer.add(offset) }, 1) {
                return Err("SCM returned an unterminated multistring".to_owned());
            }
            if unsafe { ptr::read_unaligned(pointer.add(offset)) } == 0 {
                break;
            }
            offset += 1;
        }
        let entry = (start..offset)
            .map(|index| unsafe { ptr::read_unaligned(pointer.add(index)) })
            .collect::<Vec<_>>();
        values.push(String::from_utf16_lossy(&entry));
        offset += 1;
    }
}

fn configure_restrictions(service: &ScHandle, privileges: &[&str]) -> Result<(), String> {
    let mut multistring = Vec::new();
    for privilege in privileges {
        multistring.extend(privilege.encode_utf16());
        multistring.push(0);
    }
    multistring.push(0);
    let required = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: multistring.as_mut_ptr(),
    };
    // SAFETY: the info structure and multistring remain valid for the call and
    // SCM copies their values into service configuration.
    if unsafe {
        ChangeServiceConfig2W(
            service.raw(),
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&raw const required).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let sid = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_RESTRICTED,
    };
    // SAFETY: sid remains live for the call and SCM copies the scalar value.
    if unsafe {
        ChangeServiceConfig2W(
            service.raw(),
            SERVICE_CONFIG_SERVICE_SID_INFO,
            (&raw const sid).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn configure_failure_actions(service: &ScHandle) -> Result<(), String> {
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 1_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
    ];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 24 * 60 * 60,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: u32::try_from(actions.len()).expect("fixed action inventory fits"),
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: failure and its action array remain live for the synchronous call
    // and SCM copies the complete configuration.
    if unsafe {
        ChangeServiceConfig2W(
            service.raw(),
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&raw const failure).cast(),
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

pub fn start(service: &ScHandle) -> Result<(), String> {
    // SAFETY: service is live; zero arguments permits a null argument vector.
    if unsafe { StartServiceW(service.raw(), 0, ptr::null()) } == 0 {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            != Some(ERROR_SERVICE_ALREADY_RUNNING)
        {
            return Err(error.to_string());
        }
    }
    wait_state(service, SERVICE_RUNNING, Duration::from_secs(30))
}

pub fn stop(service: &ScHandle) -> Result<(), String> {
    let mut status = SERVICE_STATUS::default();
    // SAFETY: status points to writable storage and service carries stop rights.
    if unsafe { ControlService(service.raw(), SERVICE_CONTROL_STOP, &raw mut status) } == 0 {
        let current = query_status(service)?;
        if current.dwCurrentState != SERVICE_STOPPED {
            return Err(io::Error::last_os_error().to_string());
        }
        return Ok(());
    }
    wait_state(service, SERVICE_STOPPED, Duration::from_secs(30))
}

pub fn remove(manager: &ScHandle, name: &str) -> Result<(), String> {
    let service = match open_for_remove(manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS) {
        Ok(Some(service)) => service,
        Ok(None) => return Ok(()),
        Err(error) => return Err(error),
    };
    stop(&service)?;
    // SAFETY: service carries DELETE access and remains live for the call.
    if unsafe { DeleteService(service.raw()) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    drop(service);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match open_for_remove(manager, name, 0) {
            Ok(Some(service)) => drop(service),
            Ok(None) => return Ok(()),
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(format!("service deletion did not complete: {name}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn open_for_remove(
    manager: &ScHandle,
    name: &str,
    additional_access: u32,
) -> Result<Option<ScHandle>, String> {
    let name = wide_null(name);
    // SAFETY: the name is NUL-terminated and the returned handle is adopted.
    let handle = unsafe {
        OpenServiceW(
            manager.raw(),
            name.as_ptr(),
            SERVICE_QUERY_STATUS | 0x0001_0000 | additional_access,
        )
    };
    if !handle.is_null() {
        return Ok(Some(ScHandle(handle)));
    }
    let error = io::Error::last_os_error();
    if error
        .raw_os_error()
        .and_then(|value| u32::try_from(value).ok())
        == Some(ERROR_SERVICE_DOES_NOT_EXIST)
    {
        Ok(None)
    } else {
        Err(error.to_string())
    }
}

pub fn query_status(service: &ScHandle) -> Result<SERVICE_STATUS_PROCESS, String> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0_u32;
    // SAFETY: the output buffer is exactly SERVICE_STATUS_PROCESS sized and
    // stays valid for the synchronous call.
    if unsafe {
        QueryServiceStatusEx(
            service.raw(),
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &raw mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(status)
}

fn wait_state(service: &ScHandle, expected: u32, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = query_status(service)?;
        if status.dwCurrentState == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("service did not reach state {expected}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn is_running(manager: &ScHandle, name: &str) -> Result<bool, String> {
    let service = open(manager, name, SERVICE_QUERY_STATUS | SERVICE_START)?;
    Ok(query_status(&service)?.dwCurrentState == SERVICE_RUNNING)
}

pub fn running_process_id(manager: &ScHandle, name: &str) -> Result<u32, String> {
    let service = open(manager, name, SERVICE_QUERY_STATUS)?;
    let status = query_status(&service)?;
    if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
        return Err(format!("Windows sealed service is not running: {name}"));
    }
    Ok(status.dwProcessId)
}
