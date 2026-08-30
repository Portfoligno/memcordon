use std::io;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatusEx, SC_ACTION, SC_ACTION_RESTART,
    SC_HANDLE, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP,
    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_RUNNING, SERVICE_SID_INFO,
    SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS, StartServiceW,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

use super::pipe::{OwnedHandle, wide_null};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSidType {
    Unrestricted,
    Restricted,
}

impl ServiceSidType {
    const fn native(self) -> u32 {
        match self {
            Self::Unrestricted => 1,
            Self::Restricted => 3,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::Restricted => "restricted",
        }
    }
}
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const SERVICE_PROCESS_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum ServiceStatePhase {
    Start,
    DemandStart,
    Stop,
    OneShotRetirement,
}

impl ServiceStatePhase {
    const fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::DemandStart => "demand-start",
            Self::Stop => "stop",
            Self::OneShotRetirement => "one-shot-retirement",
        }
    }
}

pub(crate) struct PinnedServiceProcess {
    pub(crate) handle: OwnedHandle,
    pub(crate) identity: memcordon_core::WindowsProcessIdentityV1,
}

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

pub fn manager_connect() -> Result<ScHandle, String> {
    // SAFETY: null names select the local active SCM database. Runtime obtains
    // only connection authority and can never create or reconfigure services.
    let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if handle.is_null() {
        Err(io::Error::last_os_error().to_string())
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
    pub sid_type: ServiceSidType,
}

pub struct GuardianSlotConfig<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
    pub binary_command: &'a str,
}

pub struct SessionBrokerConfig<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
    pub binary_command: &'a str,
    pub required_privileges: &'a [&'a str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionBrokerConfigurationFault {
    AfterRequiredPrivileges,
    AfterSidType,
    AfterFailureActions,
    AfterSecurityApply,
}

impl SessionBrokerConfigurationFault {
    fn reject(self, expected: Self) -> Result<(), String> {
        if self == expected {
            Err(format!(
                "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected session-broker configuration fault after {expected:?}"
            ))
        } else {
            Ok(())
        }
    }
}

pub fn create_session_broker(
    manager: &ScHandle,
    config: &SessionBrokerConfig<'_>,
) -> Result<ScHandle, String> {
    let service = create_demand_start_registration(
        manager,
        config.name,
        config.display_name,
        config.binary_command,
    )?;
    if let Err(error) = configure_session_broker_handle(&service, config) {
        drop(service);
        return match remove(manager, config.name) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "session broker creation and cleanup failed: create={error}; cleanup={cleanup}"
            )),
        };
    }
    Ok(service)
}

pub fn create_session_broker_registration(
    manager: &ScHandle,
    config: &SessionBrokerConfig<'_>,
) -> Result<ScHandle, String> {
    create_demand_start_registration(
        manager,
        config.name,
        config.display_name,
        config.binary_command,
    )
}

pub fn configure_created_session_broker(
    service: &ScHandle,
    config: &SessionBrokerConfig<'_>,
) -> Result<(), String> {
    configure_session_broker_handle(service, config)
}

pub fn configure_created_session_broker_with_fault(
    service: &ScHandle,
    config: &SessionBrokerConfig<'_>,
    fault: SessionBrokerConfigurationFault,
) -> Result<(), String> {
    configure_session_broker_handle_with_fault(service, config, Some(fault))
}

pub fn reconcile_session_broker(
    manager: &ScHandle,
    config: &SessionBrokerConfig<'_>,
) -> Result<ScHandle, String> {
    let service = if exists(manager, config.name)? {
        open(manager, config.name, SERVICE_ALL_ACCESS)?
    } else {
        return create_session_broker(manager, config);
    };
    update_demand_start_base(
        &service,
        config.name,
        config.display_name,
        config.binary_command,
    )?;
    configure_session_broker_handle(&service, config)?;
    Ok(service)
}

pub fn verify_session_broker(
    manager: &ScHandle,
    config: &SessionBrokerConfig<'_>,
) -> Result<(), String> {
    let service = open(
        manager,
        config.name,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL_ACCESS,
    )?;
    verify_session_broker_handle(&service, config)
}

fn create_demand_start_registration(
    manager: &ScHandle,
    name: &str,
    display_name: &str,
    binary_command: &str,
) -> Result<ScHandle, String> {
    let name_wide = wide_null(name);
    let display = wide_null(display_name);
    let command = wide_null(binary_command);
    let account = wide_null("LocalSystem");
    // SAFETY: fixed strings remain live and SCM copies the configuration.
    let raw = unsafe {
        CreateServiceW(
            manager.raw(),
            name_wide.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            account.as_ptr(),
            ptr::null(),
        )
    };
    if raw.is_null() {
        Err(format!(
            "cannot create demand-start service {name}: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(ScHandle(raw))
    }
}

fn update_demand_start_base(
    service: &ScHandle,
    name: &str,
    display_name: &str,
    binary_command: &str,
) -> Result<(), String> {
    let display = wide_null(display_name);
    let command = wide_null(binary_command);
    let account = wide_null("LocalSystem");
    let clear = [0_u16];
    // SAFETY: all fixed canonical strings remain live for the update.
    if unsafe {
        ChangeServiceConfigW(
            service.raw(),
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            clear.as_ptr(),
            ptr::null_mut(),
            clear.as_ptr(),
            account.as_ptr(),
            ptr::null(),
            display.as_ptr(),
        )
    } == 0
    {
        Err(format!(
            "cannot update demand-start service {name}: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn configure_session_broker_handle(
    service: &ScHandle,
    config: &SessionBrokerConfig<'_>,
) -> Result<(), String> {
    configure_session_broker_handle_with_fault(service, config, None)
}

fn configure_session_broker_handle_with_fault(
    service: &ScHandle,
    config: &SessionBrokerConfig<'_>,
    fault: Option<SessionBrokerConfigurationFault>,
) -> Result<(), String> {
    update_demand_start_base(
        service,
        config.name,
        config.display_name,
        config.binary_command,
    )?;
    configure_required_privileges(service, config.required_privileges)?;
    if let Some(fault) = fault {
        fault.reject(SessionBrokerConfigurationFault::AfterRequiredPrivileges)?;
    }
    configure_sid_type(service, ServiceSidType::Unrestricted)?;
    if let Some(fault) = fault {
        fault.reject(SessionBrokerConfigurationFault::AfterSidType)?;
    }
    configure_no_failure_actions(service)?;
    if let Some(fault) = fault {
        fault.reject(SessionBrokerConfigurationFault::AfterFailureActions)?;
    }
    let descriptor = super::security::SecurityDescriptor::from_sddl(
        &super::security::session_broker_service_sddl()?,
    )?;
    super::token::with_scoped_service_owner_restore_privilege(|| {
        descriptor.apply_owner_group_dacl_to_service(service.raw())
    })?;
    if let Some(fault) = fault {
        fault.reject(SessionBrokerConfigurationFault::AfterSecurityApply)?;
    }
    verify_session_broker_handle(service, config)
}

fn verify_session_broker_handle(
    service: &ScHandle,
    config: &SessionBrokerConfig<'_>,
) -> Result<(), String> {
    let base = read_base_configuration(service)?;
    if base.service_type != SERVICE_WIN32_OWN_PROCESS
        || base.start_type != SERVICE_DEMAND_START
        || base.error_control != SERVICE_ERROR_NORMAL
        || base.binary_path != config.binary_command
        || !base.dependencies.is_empty()
        || !base.service_start_name.eq_ignore_ascii_case("localsystem")
        || base.display_name != config.display_name
    {
        return Err("session broker base configuration differs".to_owned());
    }
    let required_buffer = query_config2(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)?;
    let required =
        unsafe { ptr::read(required_buffer.as_ptr::<SERVICE_REQUIRED_PRIVILEGES_INFOW>()) };
    if wide_pointer_multistring(&required_buffer, required.pmszRequiredPrivileges)?
        != config
            .required_privileges
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    {
        return Err("session broker required privilege inventory differs".to_owned());
    }
    let sid = query_config2(service, SERVICE_CONFIG_SERVICE_SID_INFO)?;
    if unsafe { ptr::read(sid.as_ptr::<SERVICE_SID_INFO>()) }.dwServiceSidType
        != ServiceSidType::Unrestricted.native()
    {
        return Err("session broker service SID type differs".to_owned());
    }
    let failure = query_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS)?;
    if unsafe { ptr::read(failure.as_ptr::<SERVICE_FAILURE_ACTIONSW>()) }.cActions != 0 {
        return Err("session broker unexpectedly has failure restart actions".to_owned());
    }
    super::security::SecurityDescriptor::from_sddl(
        &super::security::session_broker_service_sddl()?,
    )?
    .verify_service(service.raw())
}

pub fn create_guardian_slot(
    manager: &ScHandle,
    config: &GuardianSlotConfig<'_>,
) -> Result<ScHandle, String> {
    let service = create_guardian_slot_registration(manager, config)?;
    if let Err(error) = configure_created_guardian_slot(&service, config) {
        drop(service);
        return match remove(manager, config.name) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "guardian slot creation failed and registration cleanup failed: create={error}; cleanup={cleanup}"
            )),
        };
    }
    Ok(service)
}

pub fn create_guardian_slot_registration(
    manager: &ScHandle,
    config: &GuardianSlotConfig<'_>,
) -> Result<ScHandle, String> {
    let name = wide_null(config.name);
    let display = wide_null(config.display_name);
    let command = wide_null(config.binary_command);
    let account = wide_null("LocalSystem");
    // SAFETY: all strings are NUL-terminated and SCM copies the fixed slot
    // configuration. Slots are demand-start own-process services.
    let raw = unsafe {
        CreateServiceW(
            manager.raw(),
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            account.as_ptr(),
            ptr::null(),
        )
    };
    if raw.is_null() {
        return Err(format!(
            "cannot create guardian slot {}: {}",
            config.name,
            io::Error::last_os_error()
        ));
    }
    Ok(ScHandle(raw))
}

pub fn configure_created_guardian_slot(
    service: &ScHandle,
    config: &GuardianSlotConfig<'_>,
) -> Result<(), String> {
    configure_restrictions(service, &[], ServiceSidType::Restricted)?;
    configure_no_failure_actions(service)?;
    super::security::SecurityDescriptor::from_sddl(&super::security::guardian_slot_service_sddl(
        config.name,
    )?)?
    .apply_dacl_to_service(service.raw())?;
    verify_guardian_slot_handle(service, config)
}

pub fn reconcile_guardian_slot(
    manager: &ScHandle,
    config: &GuardianSlotConfig<'_>,
) -> Result<ScHandle, String> {
    if exists(manager, config.name)? {
        let service = open(manager, config.name, SERVICE_ALL_ACCESS)?;
        let command = wide_null(config.binary_command);
        let display = wide_null(config.display_name);
        let account = wide_null("LocalSystem");
        let clear = [0_u16];
        // SAFETY: fixed canonical strings live through the synchronous update.
        if unsafe {
            ChangeServiceConfigW(
                service.raw(),
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                command.as_ptr(),
                clear.as_ptr(),
                ptr::null_mut(),
                clear.as_ptr(),
                account.as_ptr(),
                ptr::null(),
                display.as_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        configure_restrictions(&service, &[], ServiceSidType::Restricted)?;
        configure_no_failure_actions(&service)?;
        super::security::SecurityDescriptor::from_sddl(
            &super::security::guardian_slot_service_sddl(config.name)?,
        )?
        .apply_dacl_to_service(service.raw())?;
        verify_guardian_slot_handle(&service, config)?;
        Ok(service)
    } else {
        create_guardian_slot(manager, config)
    }
}

pub fn verify_guardian_slot(
    manager: &ScHandle,
    config: &GuardianSlotConfig<'_>,
) -> Result<(), String> {
    let service = open(
        manager,
        config.name,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL_ACCESS,
    )?;
    verify_guardian_slot_handle(&service, config)
}

fn verify_guardian_slot_handle(
    service: &ScHandle,
    config: &GuardianSlotConfig<'_>,
) -> Result<(), String> {
    let base = read_base_configuration(service)?;
    if base.service_type != SERVICE_WIN32_OWN_PROCESS
        || base.start_type != SERVICE_DEMAND_START
        || base.error_control != SERVICE_ERROR_NORMAL
        || base.binary_path != config.binary_command
        || !base.dependencies.is_empty()
        || !base.service_start_name.eq_ignore_ascii_case("localsystem")
        || base.display_name != config.display_name
    {
        return Err(format!(
            "guardian slot base configuration differs: {}",
            config.name
        ));
    }
    let required_buffer = query_config2(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)?;
    let required =
        unsafe { ptr::read(required_buffer.as_ptr::<SERVICE_REQUIRED_PRIVILEGES_INFOW>()) };
    if !wide_pointer_multistring(&required_buffer, required.pmszRequiredPrivileges)?.is_empty() {
        return Err(format!(
            "guardian slot privilege inventory differs: {}",
            config.name
        ));
    }
    let sid = query_config2(service, SERVICE_CONFIG_SERVICE_SID_INFO)?;
    if unsafe { ptr::read(sid.as_ptr::<SERVICE_SID_INFO>()) }.dwServiceSidType
        != ServiceSidType::Restricted.native()
    {
        return Err(format!("guardian slot SID type differs: {}", config.name));
    }
    let failure = query_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS)?;
    let failure = unsafe { ptr::read(failure.as_ptr::<SERVICE_FAILURE_ACTIONSW>()) };
    if failure.cActions != 0 {
        return Err(format!(
            "guardian slot has automatic restart actions: {}",
            config.name
        ));
    }
    super::security::SecurityDescriptor::from_sddl(&super::security::guardian_slot_service_sddl(
        config.name,
    )?)?
    .verify_service(service.raw())
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ServiceBaseSnapshot {
    pub(crate) service_type: u32,
    pub(crate) start_type: u32,
    pub(crate) error_control: u32,
    pub(crate) binary_path: String,
    pub(crate) load_order_group: String,
    pub(crate) tag_id: u32,
    pub(crate) dependencies: Vec<String>,
    pub(crate) service_start_name: String,
    pub(crate) display_name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DependencyIntent<'a> {
    Preserve,
    Clear,
    Replace(&'a [&'a str]),
}

pub fn create(manager: &ScHandle, config: &ServiceConfig<'_>) -> Result<ScHandle, String> {
    let service = create_registration(manager, config)?;
    if let Err(error) = configure_created(&service, config) {
        drop(service);
        return match remove(manager, config.name) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "service creation failed and registration cleanup failed: create={error}; cleanup={cleanup}"
            )),
        };
    }
    Ok(service)
}

pub fn create_registration(
    manager: &ScHandle,
    config: &ServiceConfig<'_>,
) -> Result<ScHandle, String> {
    let name = wide_null(config.name);
    let display = wide_null(config.display_name);
    let command = wide_null(config.binary_command);
    let account = config.account.map(wide_null);
    let dependency_intent = if config.dependencies.is_empty() {
        DependencyIntent::Preserve
    } else {
        DependencyIntent::Replace(config.dependencies)
    };
    let dependencies = dependency_multistring(dependency_intent);
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
            /* lpLoadOrderGroup */ ptr::null(),
            /* lpdwTagId */ ptr::null_mut(),
            /* lpDependencies */
            dependencies
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
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
    Ok(ScHandle(handle))
}

pub fn configure_created(service: &ScHandle, config: &ServiceConfig<'_>) -> Result<(), String> {
    verify_base_configuration(service, config)?;
    update_base_configuration(service, config)?;
    configure_restrictions(service, config.required_privileges, config.sid_type)?;
    configure_failure_actions(service)?;
    super::security::SecurityDescriptor::from_sddl(super::security::SERVICE_CONTROL_SDDL)?
        .apply_dacl_to_service(service.raw())
}

pub fn reconcile(manager: &ScHandle, config: &ServiceConfig<'_>) -> Result<ScHandle, String> {
    let service = if exists(manager, config.name)? {
        open(manager, config.name, SERVICE_ALL_ACCESS)?
    } else {
        return create(manager, config);
    };
    update_base_configuration(&service, config)?;
    configure_restrictions(&service, config.required_privileges, config.sid_type)?;
    configure_failure_actions(&service)?;
    super::security::SecurityDescriptor::from_sddl(super::security::SERVICE_CONTROL_SDDL)?
        .apply_dacl_to_service(service.raw())?;
    Ok(service)
}

fn update_base_configuration(service: &ScHandle, config: &ServiceConfig<'_>) -> Result<(), String> {
    let command = wide_null(config.binary_command);
    let display = wide_null(config.display_name);
    let account = config.account.map(wide_null);
    let clear_load_order_group = [0_u16];
    let dependency_intent = if config.dependencies.is_empty() {
        DependencyIntent::Clear
    } else {
        DependencyIntent::Replace(config.dependencies)
    };
    let dependencies = dependency_multistring(dependency_intent)
        .expect("clear and replace dependency intents always carry a multistring");
    // SAFETY: all optional strings are NUL-terminated and live through the
    // synchronous update. Numeric fields replace the exact base configuration.
    if unsafe {
        ChangeServiceConfigW(
            service.raw(),
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            /* lpLoadOrderGroup */ clear_load_order_group.as_ptr(),
            /* lpdwTagId */ ptr::null_mut(),
            /* lpDependencies */ dependencies.as_ptr(),
            account.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            ptr::null(),
            display.as_ptr(),
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        verify_base_configuration(service, config)
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
    verify_base_configuration(&service, config)?;
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
        != config.sid_type.native()
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

pub(crate) fn dependency_multistring(intent: DependencyIntent<'_>) -> Option<Vec<u16>> {
    let dependencies = match intent {
        DependencyIntent::Preserve => return None,
        DependencyIntent::Clear => return Some(vec![0, 0]),
        DependencyIntent::Replace(dependencies) => dependencies,
    };
    assert!(
        !dependencies.is_empty(),
        "replacement dependency inventory must not be empty"
    );
    let mut multistring = Vec::new();
    for dependency in dependencies {
        multistring.extend(dependency.encode_utf16());
        multistring.push(0);
    }
    multistring.push(0);
    Some(multistring)
}

fn read_base_configuration(service: &ScHandle) -> Result<ServiceBaseSnapshot, String> {
    let base = query_base(service)?;
    if !base.contains(base.as_ptr::<QUERY_SERVICE_CONFIGW>(), 1) {
        return Err("SCM returned a truncated service base configuration header".to_owned());
    }
    // SAFETY: query_base allocated native-aligned storage for this header.
    let header = unsafe { ptr::read(base.as_ptr::<QUERY_SERVICE_CONFIGW>()) };
    Ok(ServiceBaseSnapshot {
        service_type: header.dwServiceType,
        start_type: header.dwStartType,
        error_control: header.dwErrorControl,
        binary_path: wide_pointer_string(&base, header.lpBinaryPathName)?,
        load_order_group: wide_pointer_string(&base, header.lpLoadOrderGroup)?,
        tag_id: header.dwTagId,
        dependencies: wide_pointer_multistring(&base, header.lpDependencies)?,
        service_start_name: wide_pointer_string(&base, header.lpServiceStartName)?,
        display_name: wide_pointer_string(&base, header.lpDisplayName)?,
    })
}

pub(crate) fn base_configuration_mismatches(
    actual: &ServiceBaseSnapshot,
    config: &ServiceConfig<'_>,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    if actual.service_type != SERVICE_WIN32_OWN_PROCESS {
        mismatches.push(format!(
            "service_type expected=0x{SERVICE_WIN32_OWN_PROCESS:08x} actual=0x{:08x}",
            actual.service_type
        ));
    }
    if actual.start_type != SERVICE_AUTO_START {
        mismatches.push(format!(
            "start_type expected=0x{SERVICE_AUTO_START:08x} actual=0x{:08x}",
            actual.start_type
        ));
    }
    if actual.error_control != SERVICE_ERROR_NORMAL {
        mismatches.push(format!(
            "error_control expected=0x{SERVICE_ERROR_NORMAL:08x} actual=0x{:08x}",
            actual.error_control
        ));
    }
    if !actual
        .binary_path
        .eq_ignore_ascii_case(config.binary_command)
    {
        mismatches.push(format!(
            "binary_path expected={:?} actual={:?}",
            config.binary_command, actual.binary_path
        ));
    }
    if !actual
        .service_start_name
        .eq_ignore_ascii_case(config.account.unwrap_or("LocalSystem"))
    {
        mismatches.push(format!(
            "service_start_name expected={:?} actual={:?}",
            config.account.unwrap_or("LocalSystem"),
            actual.service_start_name
        ));
    }
    let expected_dependencies = config
        .dependencies
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if actual.dependencies != expected_dependencies {
        mismatches.push(format!(
            "dependencies expected={expected_dependencies:?} actual={:?}",
            actual.dependencies
        ));
    }
    if !actual.load_order_group.is_empty() {
        mismatches.push(format!(
            "load_order_group expected=\"\" actual={:?}",
            actual.load_order_group
        ));
    }
    if actual.tag_id != 0 {
        mismatches.push(format!("tag_id expected=0 actual={}", actual.tag_id));
    }
    if actual.display_name != config.display_name {
        mismatches.push(format!(
            "display_name expected={:?} actual={:?}",
            config.display_name, actual.display_name
        ));
    }
    mismatches
}

fn verify_base_configuration(service: &ScHandle, config: &ServiceConfig<'_>) -> Result<(), String> {
    let actual = read_base_configuration(service)?;
    let mismatches = base_configuration_mismatches(&actual, config);
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "MCSEALED-WINDOWS-SERVICE-BASE-MISMATCH: service={} mismatches=[{}]",
            config.name,
            mismatches.join(", ")
        ))
    }
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

fn configure_restrictions(
    service: &ScHandle,
    privileges: &[&str],
    sid_type: ServiceSidType,
) -> Result<(), String> {
    configure_required_privileges(service, privileges)?;
    configure_sid_type(service, sid_type)
}

fn configure_required_privileges(service: &ScHandle, privileges: &[&str]) -> Result<(), String> {
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
    Ok(())
}

fn configure_sid_type(service: &ScHandle, sid_type: ServiceSidType) -> Result<(), String> {
    let sid = SERVICE_SID_INFO {
        dwServiceSidType: sid_type.native(),
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

fn configure_no_failure_actions(service: &ScHandle) -> Result<(), String> {
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 0,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: 0,
        lpsaActions: ptr::null_mut(),
    };
    // SAFETY: the empty failure-action configuration lives through the call.
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

pub fn start(service: &ScHandle, name: &str) -> Result<(), String> {
    // SAFETY: service is live; zero arguments permits a null argument vector.
    if unsafe { StartServiceW(service.raw(), 0, ptr::null()) } == 0 {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            != Some(ERROR_SERVICE_ALREADY_RUNNING)
        {
            return Err(format!("cannot start Windows service {name}: {error}"));
        }
    }
    wait_state(
        service,
        name,
        SERVICE_RUNNING,
        Duration::from_secs(30),
        ServiceStatePhase::Start,
    )
}

pub fn start_with_arguments(
    service: &ScHandle,
    name: &str,
    additional_arguments: &[String],
) -> Result<(), String> {
    let wide = service_start_argument_values(name, additional_arguments)?;
    let pointers = wide.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    let pointer = if pointers.is_empty() {
        ptr::null()
    } else {
        pointers.as_ptr()
    };
    // SAFETY: each argument is NUL-terminated and all storage lives through
    // the synchronous call. StartServiceW accepts only additional arguments;
    // SCM supplies the service identity as ServiceMain argv[0].
    if unsafe {
        StartServiceW(
            service.raw(),
            u32::try_from(pointers.len()).map_err(|_| "too many service arguments")?,
            pointer,
        )
    } == 0
    {
        return Err(format!(
            "cannot start demand-start service {name}: {}",
            io::Error::last_os_error()
        ));
    }
    wait_state(
        service,
        name,
        SERVICE_RUNNING,
        Duration::from_secs(30),
        ServiceStatePhase::DemandStart,
    )
}

pub(crate) fn service_start_argument_values(
    name: &str,
    additional_arguments: &[String],
) -> Result<Vec<Vec<u16>>, String> {
    if name.is_empty() {
        return Err("service name is empty".to_owned());
    }
    // Validate the diagnostic identity independently. SCM, not this caller,
    // inserts it at ServiceMain argv[0].
    service_start_argument(name, "service name")?;
    let mut values = Vec::with_capacity(additional_arguments.len());
    for (index, argument) in additional_arguments.iter().enumerate() {
        values.push(service_start_argument(
            argument,
            &format!("service argument {index}"),
        )?);
    }
    Ok(values)
}

fn service_start_argument(value: &str, role: &str) -> Result<Vec<u16>, String> {
    if value.contains('\0') {
        return Err(format!("{role} contains an embedded NUL"));
    }
    Ok(wide_null(value))
}

pub fn status_process(service: &ScHandle) -> Result<SERVICE_STATUS_PROCESS, String> {
    query_status(service)
}

pub fn wait_stopped(service: &ScHandle, name: &str) -> Result<(), String> {
    wait_state(
        service,
        name,
        SERVICE_STOPPED,
        Duration::from_secs(30),
        ServiceStatePhase::OneShotRetirement,
    )
}

pub fn stop(service: &ScHandle, name: &str) -> Result<(), String> {
    let mut status = SERVICE_STATUS::default();
    // SAFETY: status points to writable storage and service carries stop rights.
    if unsafe { ControlService(service.raw(), SERVICE_CONTROL_STOP, &raw mut status) } == 0 {
        let current = query_status(service)?;
        if current.dwCurrentState != SERVICE_STOPPED {
            return Err(format!(
                "cannot stop Windows service {name}: {}",
                io::Error::last_os_error()
            ));
        }
        return Ok(());
    }
    wait_state(
        service,
        name,
        SERVICE_STOPPED,
        Duration::from_secs(30),
        ServiceStatePhase::Stop,
    )
}

pub fn remove(manager: &ScHandle, name: &str) -> Result<(), String> {
    let service = match open_for_remove(manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS) {
        Ok(Some(service)) => service,
        Ok(None) => return Ok(()),
        Err(error) => return Err(error),
    };
    let process = capture_service_process(&service, name, Duration::from_secs(2))?;
    stop(&service, name)?;
    if let Some(process) = process {
        wait_service_process_exit(&process, name, SERVICE_PROCESS_WAIT)?;
    }
    // SAFETY: service carries DELETE access and remains live for the call.
    if unsafe { DeleteService(service.raw()) } == 0 {
        let error = io::Error::last_os_error();
        return Err(format!(
            "MCSEALED-WINDOWS-SERVICE-REMOVE: service={name} phase=delete-registration native_code={:?}: {error}",
            error.raw_os_error()
        ));
    }
    drop(service);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match open_for_remove(manager, name, 0) {
            Ok(Some(service)) => drop(service),
            Ok(None) => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "MCSEALED-WINDOWS-SERVICE-REMOVE: service={name} phase=wait-registration-gone: {error}"
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "MCSEALED-WINDOWS-SERVICE-REMOVE: service={name} phase=wait-registration-gone elapsed_ms=30000"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn capture_service_process(
    service: &ScHandle,
    name: &str,
    timeout: Duration,
) -> Result<Option<PinnedServiceProcess>, String> {
    let started = Instant::now();
    loop {
        let status = query_status(service).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=capture-status: {error}"
            )
        })?;
        let process_id = status.dwProcessId;
        if process_id == 0 {
            if status.dwCurrentState == SERVICE_STOPPED {
                return Ok(None);
            }
            if started.elapsed() >= timeout {
                return Err(format!(
                    "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=capture-process elapsed_ms={} state={} pid=0",
                    started.elapsed().as_millis(),
                    status.dwCurrentState
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }

        // SAFETY: the PID was read from the retained SCM service handle. The
        // returned process object is immediately adopted and pinned across stop.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
                0,
                process_id,
            )
        };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            if error
                .raw_os_error()
                .and_then(|value| u32::try_from(value).ok())
                == Some(ERROR_INVALID_PARAMETER)
            {
                let after = query_status(service).map_err(|status_error| {
                    format!(
                        "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=recapture-status pid={process_id}: {status_error}"
                    )
                })?;
                if after.dwCurrentState == SERVICE_STOPPED && after.dwProcessId == 0 {
                    return Ok(None);
                }
                if started.elapsed() < timeout {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
            }
            return Err(format!(
                "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=open-process pid={process_id} native_code={:?}: {error}",
                error.raw_os_error()
            ));
        }
        let handle = OwnedHandle::new(raw).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=own-process pid={process_id}: {error}"
            )
        })?;
        let identity = super::process::process_identity(handle.raw()).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=capture-identity pid={process_id}: {error}"
            )
        })?;
        if identity.process_id != process_id {
            return Err(format!(
                "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=capture-identity expected_pid={process_id} actual_pid={} creation_time_100ns={}",
                identity.process_id, identity.creation_time_100ns
            ));
        }
        let confirmed = query_status(service).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=confirm-process pid={process_id} creation_time_100ns={}: {error}",
                identity.creation_time_100ns
            )
        })?;
        if confirmed.dwProcessId != process_id {
            if confirmed.dwCurrentState == SERVICE_STOPPED && confirmed.dwProcessId == 0 {
                return Ok(None);
            }
            if started.elapsed() < timeout {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            return Err(format!(
                "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=confirm-process expected_pid={process_id} actual_pid={} state={} elapsed_ms={}",
                confirmed.dwProcessId,
                confirmed.dwCurrentState,
                started.elapsed().as_millis()
            ));
        }
        return Ok(Some(PinnedServiceProcess { handle, identity }));
    }
}

pub(crate) fn wait_service_process_exit(
    process: &PinnedServiceProcess,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    let started = Instant::now();
    // SAFETY: process owns the exact process object captured before stop.
    let result = unsafe { WaitForSingleObject(process.handle.raw(), timeout_ms) };
    match result {
        WAIT_OBJECT_0 => {
            let observed = super::process::process_identity(process.handle.raw()).map_err(|error| {
                format!(
                    "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=verify-exited-identity pid={} creation_time_100ns={}: {error}",
                    process.identity.process_id, process.identity.creation_time_100ns
                )
            })?;
            if observed != process.identity {
                return Err(format!(
                    "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=verify-exited-identity expected_pid={} expected_creation_time_100ns={} actual_pid={} actual_creation_time_100ns={}",
                    process.identity.process_id,
                    process.identity.creation_time_100ns,
                    observed.process_id,
                    observed.creation_time_100ns
                ));
            }
            Ok(())
        }
        WAIT_TIMEOUT => Err(format!(
            "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=wait-process-exit pid={} creation_time_100ns={} elapsed_ms={} result=timeout",
            process.identity.process_id,
            process.identity.creation_time_100ns,
            started.elapsed().as_millis()
        )),
        WAIT_FAILED => {
            let error = io::Error::last_os_error();
            Err(format!(
                "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=wait-process-exit pid={} creation_time_100ns={} elapsed_ms={} result=failed native_code={:?}: {error}",
                process.identity.process_id,
                process.identity.creation_time_100ns,
                started.elapsed().as_millis(),
                error.raw_os_error()
            ))
        }
        other => Err(format!(
            "MCSEALED-WINDOWS-SERVICE-PROCESS-WAIT: service={name} phase=wait-process-exit pid={} creation_time_100ns={} elapsed_ms={} result={other}",
            process.identity.process_id,
            process.identity.creation_time_100ns,
            started.elapsed().as_millis()
        )),
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

fn startup_diagnostic(service_exit: u32) -> String {
    if let Some((role, component)) =
        super::security::pipe_mismatch_diagnostic_from_exit(service_exit)
    {
        format!(
            "; startup_diagnostic=pipe_role={role} operation=security-mismatch component={component}"
        )
    } else if let Some((role, subphase)) =
        super::security::token_dacl_diagnostic_from_exit(service_exit)
    {
        format!(
            "; startup_diagnostic=service_role={role} operation=token-policy subphase={subphase}"
        )
    } else if let Some(subphase) =
        super::control_service::control_authentication_diagnostic_from_exit(service_exit)
    {
        format!("; startup_diagnostic=operation=control-authentication subphase={subphase}")
    } else if let Some(subphase) =
        super::control_service::launcher_authentication_diagnostic_from_exit(service_exit)
    {
        format!("; startup_diagnostic=operation=launcher-authentication subphase={subphase}")
    } else if let Some(stage) = super::guardian_service::startup_diagnostic_from_exit(service_exit)
    {
        format!("; startup_diagnostic=role=guardian operation=startup stage={stage}")
    } else if let Some((stage, subphase)) =
        super::session_broker::startup_diagnostic_from_exit(service_exit)
    {
        match subphase {
            Some(subphase) => format!(
                "; startup_diagnostic=role=session-broker operation=startup stage={stage} subphase={subphase}"
            ),
            None => {
                format!("; startup_diagnostic=role=session-broker operation=startup stage={stage}")
            }
        }
    } else {
        String::new()
    }
}

fn stopped_before_running_diagnostic(
    name: &str,
    status: &SERVICE_STATUS_PROCESS,
    phase: ServiceStatePhase,
    elapsed_millis: u128,
) -> String {
    format!(
        "role=windows-service operation=state-convergence phase={} service={name} expected_state={SERVICE_RUNNING} last_state={} process_id={} win32_exit={} service_exit={} elapsed_ms={elapsed_millis}{}",
        phase.label(),
        status.dwCurrentState,
        status.dwProcessId,
        status.dwWin32ExitCode,
        status.dwServiceSpecificExitCode,
        startup_diagnostic(status.dwServiceSpecificExitCode),
    )
}

#[cfg(test)]
pub(crate) fn demand_start_stopped_diagnostic_for_test(
    name: &str,
    status: &SERVICE_STATUS_PROCESS,
    elapsed_millis: u128,
) -> String {
    stopped_before_running_diagnostic(name, status, ServiceStatePhase::DemandStart, elapsed_millis)
}

fn wait_state(
    service: &ScHandle,
    name: &str,
    expected: u32,
    timeout: Duration,
    phase: ServiceStatePhase,
) -> Result<(), String> {
    let started = Instant::now();
    let deadline = started + timeout;
    loop {
        let status = query_status(service).map_err(|error| {
            format!(
                "role=windows-service operation=state-convergence phase={} service={name} query_error={error} elapsed_ms={}",
                phase.label(),
                started.elapsed().as_millis(),
            )
        })?;
        if status.dwCurrentState == expected {
            if expected == SERVICE_RUNNING && status.dwProcessId == 0 {
                return Err(format!(
                    "role=windows-service operation=state-convergence phase={} service={name} expected_state={expected} last_state={} process_id=0 win32_exit={} service_exit={} elapsed_ms={} invariant=running-service-has-no-process",
                    phase.label(),
                    status.dwCurrentState,
                    status.dwWin32ExitCode,
                    status.dwServiceSpecificExitCode,
                    started.elapsed().as_millis(),
                ));
            }
            return Ok(());
        }
        if expected == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED {
            return Err(stopped_before_running_diagnostic(
                name,
                &status,
                phase,
                started.elapsed().as_millis(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "role=windows-service operation=state-convergence phase={} service={name} expected_state={expected} last_state={} process_id={} win32_exit={} service_exit={} elapsed_ms={} timed_out=true",
                phase.label(),
                status.dwCurrentState,
                status.dwProcessId,
                status.dwWin32ExitCode,
                status.dwServiceSpecificExitCode,
                started.elapsed().as_millis(),
            ));
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
