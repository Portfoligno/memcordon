use super::*;

pub(super) struct GuardianDesktopContext {
    window_station: HANDLE,
    desktop: HANDLE,
    window_station_name: String,
    desktop_name: String,
    exact_name: String,
    startup_name: Vec<u16>,
}

impl GuardianDesktopContext {
    fn capture() -> Result<Self, GuardianLoaderPreparationError> {
        // These assigned USER handles are borrowed and remain pinned by the
        // launcher process/current thread. They must not be closed as ordinary
        // kernel handles or replaced by a guessed interactive station.
        let window_station = unsafe { GetProcessWindowStation() };
        if window_station.is_null() {
            return Err(GuardianLoaderPreparationError::native(
                GuardianLoaderPreparationSubphase::DesktopStationCapture,
                "cannot capture launcher window station",
            ));
        }
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        if desktop.is_null() {
            return Err(GuardianLoaderPreparationError::native(
                GuardianLoaderPreparationSubphase::DesktopCapture,
                "cannot capture launcher thread desktop",
            ));
        }
        let window_station_name = user_object_name(window_station).map_err(|error| {
            GuardianLoaderPreparationError::from_user_object(
                GuardianLoaderPreparationSubphase::DesktopNameReadback,
                error,
            )
        })?;
        let desktop_name = user_object_name(desktop).map_err(|error| {
            GuardianLoaderPreparationError::from_user_object(
                GuardianLoaderPreparationSubphase::DesktopNameReadback,
                error,
            )
        })?;
        let receives_input = desktop_receives_input(desktop).map_err(|error| {
            GuardianLoaderPreparationError::from_user_object(
                GuardianLoaderPreparationSubphase::DesktopAttestation,
                error,
            )
        })?;
        validate_guardian_desktop_binding(&window_station_name, &desktop_name, receives_input)?;
        let exact_name = format!("{window_station_name}\\{desktop_name}");
        let mut startup_name = exact_name.encode_utf16().collect::<Vec<_>>();
        startup_name.push(0);
        let context = Self {
            window_station,
            desktop,
            window_station_name,
            desktop_name,
            exact_name,
            startup_name,
        };
        context.attest()?;
        Ok(context)
    }

    fn attest(&self) -> Result<(), GuardianLoaderPreparationError> {
        if unsafe { GetProcessWindowStation() } != self.window_station
            || unsafe { GetThreadDesktop(GetCurrentThreadId()) } != self.desktop
            || user_object_name(self.window_station).map_err(|error| {
                GuardianLoaderPreparationError::from_user_object(
                    GuardianLoaderPreparationSubphase::DesktopNameReadback,
                    error,
                )
            })? != self.window_station_name
            || user_object_name(self.desktop).map_err(|error| {
                GuardianLoaderPreparationError::from_user_object(
                    GuardianLoaderPreparationSubphase::DesktopNameReadback,
                    error,
                )
            })? != self.desktop_name
        {
            return Err(GuardianLoaderPreparationError::contract(
                GuardianLoaderPreparationSubphase::DesktopAttestation,
                "launcher window-station/desktop binding changed during guardian creation",
            ));
        }
        validate_guardian_desktop_binding(
            &self.window_station_name,
            &self.desktop_name,
            desktop_receives_input(self.desktop).map_err(|error| {
                GuardianLoaderPreparationError::from_user_object(
                    GuardianLoaderPreparationSubphase::DesktopAttestation,
                    error,
                )
            })?,
        )
    }

    fn exact_name(&self) -> &str {
        &self.exact_name
    }
}

pub(super) fn user_object_name(handle: HANDLE) -> Result<String, UserObjectQueryError> {
    let mut needed = 0_u32;
    // SAFETY: this size query supplies no output buffer and writes the required
    // byte count for the live assigned USER object.
    let sized =
        unsafe { GetUserObjectInformationW(handle, UOI_NAME, ptr::null_mut(), 0, &raw mut needed) };
    let sizing_error = io::Error::last_os_error();
    if sized != 0 {
        return Err(UserObjectQueryError::contract(
            "USER object name sizing unexpectedly succeeded without a buffer",
        ));
    }
    let unit_bytes = std::mem::size_of::<u16>() as u32;
    if needed < unit_bytes || needed % unit_bytes != 0 {
        if sizing_error.raw_os_error().is_some_and(|code| code != 0) {
            return Err(UserObjectQueryError::from_io(
                "cannot size USER object name",
                sizing_error,
            ));
        }
        return Err(UserObjectQueryError::contract(format!(
            "USER object name sizing returned an invalid byte count without a native failure: {needed}"
        )));
    }
    let capacity_bytes = needed;
    let mut value = vec![0_u16; needed as usize / std::mem::size_of::<u16>()];
    // SAFETY: value has the exact API-requested byte capacity and the USER
    // object remains pinned by its process/thread assignment.
    if unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            value.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err(UserObjectQueryError::native("cannot read USER object name"));
    }
    if needed < unit_bytes || needed > capacity_bytes || needed % unit_bytes != 0 {
        return Err(UserObjectQueryError::contract(format!(
            "USER object name read returned an invalid byte count: capacity={capacity_bytes} actual={needed}"
        )));
    }
    let returned_units = needed as usize / std::mem::size_of::<u16>();
    if value.get(returned_units - 1) != Some(&0) {
        return Err(UserObjectQueryError::contract(
            "USER object name read omitted its UTF-16 terminator",
        ));
    }
    String::from_utf16(&value[..returned_units - 1])
        .map_err(|_| UserObjectQueryError::contract("USER object name is not valid UTF-16"))
}

pub(super) fn desktop_receives_input(desktop: HANDLE) -> Result<bool, UserObjectQueryError> {
    let mut receives_input = 0_i32;
    let mut needed = 0_u32;
    // SAFETY: receives_input is writable and desktop is the pinned current
    // thread desktop. UOI_IO returns a BOOL-sized observation.
    if unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_IO,
            (&raw mut receives_input).cast(),
            std::mem::size_of_val(&receives_input) as u32,
            &raw mut needed,
        )
    } == 0
    {
        return Err(UserObjectQueryError::native(
            "cannot query whether desktop receives interactive input",
        ));
    }
    Ok(receives_input != 0)
}

pub(super) fn desktop_heap_kb(desktop: HANDLE) -> Result<u32, UserObjectQueryError> {
    let mut heap_kb = 0_u32;
    let mut needed = 0_u32;
    // SAFETY: heap_kb is a writable ULONG-sized buffer and desktop remains
    // pinned by the retained Holder handle. UOI_HEAPSIZE is read-only.
    if unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_HEAPSIZE_CLASS,
            (&raw mut heap_kb).cast(),
            std::mem::size_of_val(&heap_kb) as u32,
            &raw mut needed,
        )
    } == 0
    {
        return Err(UserObjectQueryError::native(
            "cannot query private desktop heap size",
        ));
    }
    if needed != std::mem::size_of_val(&heap_kb) as u32 || heap_kb == 0 {
        return Err(UserObjectQueryError::contract(format!(
            "private desktop heap query returned an invalid result: bytes={needed} heap_kb={heap_kb}"
        )));
    }
    Ok(heap_kb)
}

#[cfg(test)]
pub(crate) fn attest_current_user_binding_duplicates_for_test() -> Result<(), String> {
    let window_station = unsafe { GetProcessWindowStation() };
    let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    if window_station.is_null() || desktop.is_null() {
        return Err("test process has no Windows-provisioned USER binding".to_owned());
    }
    let expected_station = user_object_name(window_station).map_err(|error| error.to_string())?;
    let expected_desktop = user_object_name(desktop).map_err(|error| error.to_string())?;
    let duplicates = TargetUserBindingReadHandles::duplicate(window_station, desktop)
        .map_err(|error| error.to_string())?;
    if user_object_name(duplicates.window_station.raw()).map_err(|error| error.to_string())?
        != expected_station
        || user_object_name(duplicates.desktop.raw()).map_err(|error| error.to_string())?
            != expected_desktop
    {
        return Err("reduced-access USER duplicates changed object identity".to_owned());
    }
    desktop_receives_input(duplicates.desktop.raw()).map_err(|error| error.to_string())?;
    SecurityDescriptor::user_object_security_equality_fingerprint(duplicates.window_station.raw())?;
    SecurityDescriptor::user_object_security_equality_fingerprint(duplicates.desktop.raw())?;
    let station_access = super::token::granted_handle_access(duplicates.window_station.raw())?;
    let desktop_access = super::token::granted_handle_access(duplicates.desktop.raw())?;
    if station_access != TARGET_STATION_ATTEST_ACCESS
        || desktop_access != TARGET_DESKTOP_ATTEST_ACCESS
    {
        return Err(format!(
            "USER duplicate access mismatch: station_expected={TARGET_STATION_ATTEST_ACCESS:#x} station_actual={station_access:#x} desktop_expected={TARGET_DESKTOP_ATTEST_ACCESS:#x} desktop_actual={desktop_access:#x}"
        ));
    }
    let TargetUserBindingReadHandles {
        window_station: station_duplicate,
        desktop: desktop_duplicate,
    } = duplicates;
    station_duplicate
        .close()
        .map_err(|error| format!("cannot close station attestation duplicate: {error}"))?;
    desktop_duplicate
        .close()
        .map_err(|error| format!("cannot close desktop attestation duplicate: {error}"))?;
    if user_object_name(window_station).map_err(|error| error.to_string())? != expected_station
        || user_object_name(desktop).map_err(|error| error.to_string())? != expected_desktop
    {
        return Err("closing USER duplicates changed the assigned binding handles".to_owned());
    }
    Ok(())
}

pub(super) fn validate_desktop_binding_names(
    window_station: &str,
    desktop: &str,
) -> Result<(), String> {
    if window_station.is_empty()
        || desktop.is_empty()
        || window_station.contains('\\')
        || desktop.contains('\\')
    {
        Err("desktop names are empty or structurally ambiguous".to_owned())
    } else {
        Ok(())
    }
}

pub(crate) fn validate_guardian_desktop_binding(
    window_station: &str,
    desktop: &str,
    receives_input: bool,
) -> Result<(), GuardianLoaderPreparationError> {
    validate_desktop_binding_names(window_station, desktop).map_err(|error| {
        GuardianLoaderPreparationError::contract(
            GuardianLoaderPreparationSubphase::DesktopAttestation,
            format!("launcher {error}"),
        )
    })?;
    if window_station.eq_ignore_ascii_case("WinSta0") || receives_input {
        return Err(GuardianLoaderPreparationError::contract(
            GuardianLoaderPreparationSubphase::DesktopAttestation,
            "launcher desktop is interactive; refusing to broaden guardian UI reachability",
        ));
    }
    Ok(())
}

pub(super) struct GuardianStandardHandles {
    input: OwnedHandle,
    output: OwnedHandle,
    error: OwnedHandle,
}

impl GuardianStandardHandles {
    fn prepare() -> Result<Self, GuardianLoaderPreparationError> {
        Ok(Self {
            input: open_guardian_null_handle(
                GENERIC_READ,
                GuardianLoaderPreparationSubphase::StandardInput,
            )?,
            output: open_guardian_null_handle(
                GENERIC_WRITE,
                GuardianLoaderPreparationSubphase::StandardOutput,
            )?,
            error: open_guardian_null_handle(
                GENERIC_WRITE,
                GuardianLoaderPreparationSubphase::StandardError,
            )?,
        })
    }

    const fn raw(&self) -> [HANDLE; 3] {
        [self.input.raw(), self.output.raw(), self.error.raw()]
    }
}

pub(super) fn open_guardian_null_handle(
    access: u32,
    subphase: GuardianLoaderPreparationSubphase,
) -> Result<OwnedHandle, GuardianLoaderPreparationError> {
    let nul = super::pipe::wide_null("NUL");
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: NUL is a live NUL-terminated device name and attributes requests
    // inheritance while retaining the creator token's default descriptor.
    let raw = unsafe {
        CreateFileW(
            nul.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw const attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    let handle = OwnedHandle::new(raw)
        .map_err(|_| GuardianLoaderPreparationError::native(subphase, "cannot open NUL"))?;
    verify_inheritable(handle.raw())
        .map_err(|error| GuardianLoaderPreparationError::contract(subphase, error))?;
    // SAFETY: handle is a live NUL device handle.
    if unsafe { GetFileType(handle.raw()) } != FILE_TYPE_CHAR {
        return Err(GuardianLoaderPreparationError::contract(
            subphase,
            "NUL standard handle did not attest as a character device",
        ));
    }
    Ok(handle)
}

pub(super) fn validate_guardian_loader_handle_list(
    handles: &[HANDLE],
) -> Result<(), GuardianLoaderPreparationError> {
    if handles.len() != 5 {
        return Err(GuardianLoaderPreparationError::contract(
            GuardianLoaderPreparationSubphase::HandleList,
            "guardian loader list must contain three standard handles and two bootstrap endpoints",
        ));
    }
    for (index, handle) in handles.iter().copied().enumerate() {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(GuardianLoaderPreparationError::contract(
                GuardianLoaderPreparationSubphase::HandleList,
                format!("guardian loader handle {index} is invalid"),
            ));
        }
        if handles[..index].contains(&handle) {
            return Err(GuardianLoaderPreparationError::contract(
                GuardianLoaderPreparationSubphase::HandleList,
                format!("guardian loader handle {index} aliases an earlier role"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn attest_current_guardian_desktop(
    expected: &str,
) -> Result<(), GuardianLoaderPreparationError> {
    let context = GuardianDesktopContext::capture()?;
    if context.exact_name() != expected {
        return Err(GuardianLoaderPreparationError::contract(
            GuardianLoaderPreparationSubphase::DesktopAttestation,
            "guardian desktop readback differs from launcher capture",
        ));
    }
    Ok(())
}

pub(crate) fn prepare_service_guardian_context() -> Result<([HANDLE; 3], String), String> {
    let desktop = GuardianDesktopContext::capture().map_err(|error| error.to_string())?;
    let handles = GuardianStandardHandles::prepare().map_err(|error| error.to_string())?;
    let raw = handles.raw();
    for (kind, handle) in [
        (STD_INPUT_HANDLE, raw[0]),
        (STD_OUTPUT_HANDLE, raw[1]),
        (STD_ERROR_HANDLE, raw[2]),
    ] {
        // SAFETY: the exact live NUL handle becomes the SCM guardian's loader
        // compatibility standard handle and remains owned until guardian::run.
        if unsafe { SetStdHandle(kind, handle) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
    }
    let exact_name = desktop.exact_name().to_owned();
    std::mem::forget(handles);
    Ok((raw, exact_name))
}

pub fn certify_guardian_loader_context_negatives() -> Result<(), String> {
    let handles = [
        1_usize as HANDLE,
        2_usize as HANDLE,
        3_usize as HANDLE,
        4_usize as HANDLE,
        5_usize as HANDLE,
    ];
    if validate_guardian_loader_handle_list(&handles).is_err()
        || validate_guardian_loader_handle_list(&handles[..4]).is_ok()
        || validate_guardian_loader_handle_list(&[
            handles[0], handles[1], handles[1], handles[3], handles[4],
        ])
        .is_ok()
        || validate_guardian_loader_handle_list(&[
            handles[0],
            ptr::null_mut(),
            handles[2],
            handles[3],
            handles[4],
        ])
        .is_ok()
        || validate_guardian_desktop_binding("Service-0x0-3e7$", "Default", false).is_err()
        || validate_guardian_desktop_binding("WinSta0", "Default", false).is_ok()
        || validate_guardian_desktop_binding("Service-0x0-3e7$", "Default", true).is_ok()
    {
        Err("guardian loader-context negative certification failed".to_owned())
    } else {
        Ok(())
    }
}

pub(super) static LEASED_GUARDIAN_SLOTS: LazyLock<Mutex<HashSet<usize>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn recover_guardian_slots() -> Result<(), String> {
    let manager = super::service_manager::manager_connect()?;
    for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
        let name = super::security::guardian_slot_name(index)?;
        let service = super::service_manager::open(
            &manager,
            &name,
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | READ_CONTROL_ACCESS,
        )?;
        let status = super::service_manager::status_process(&service)?;
        if status.dwCurrentState != SERVICE_STOPPED || status.dwProcessId != 0 {
            super::service_manager::stop(&service, &name)?;
        }
        let durable = super::package::state_root()
            .join("guardian-slots")
            .join(format!("{index:03}.json"));
        if durable.exists() {
            std::fs::remove_file(&durable).map_err(|error| {
                format!(
                    "cannot retire stale guardian slot lease {}: {error}",
                    durable.display()
                )
            })?;
        }
    }
    Ok(())
}

pub(super) struct GuardianSlotLease {
    index: usize,
    name: String,
    service: super::service_manager::ScHandle,
    durable: Option<GuardianSlotLeaseV1>,
    durable_path: Option<PathBuf>,
}

#[derive(Clone, Serialize)]
pub(super) struct GuardianSlotLeaseV1 {
    schema_version: u32,
    slot_index: usize,
    service_name: String,
    attempt_id: String,
    nonce_sha256: String,
    launcher_identity: WindowsProcessIdentityV1,
    phase: &'static str,
}

impl GuardianSlotLease {
    fn bind(
        &mut self,
        attempt_id: &str,
        nonce: &str,
        launcher_identity: &WindowsProcessIdentityV1,
    ) -> Result<(), String> {
        let durable = GuardianSlotLeaseV1 {
            schema_version: 1,
            slot_index: self.index,
            service_name: self.name.clone(),
            attempt_id: attempt_id.to_owned(),
            nonce_sha256: super::record::digest(nonce.as_bytes()),
            launcher_identity: launcher_identity.clone(),
            phase: "reserved",
        };
        let path = super::package::state_root()
            .join("guardian-slots")
            .join(format!("{:03}.json", self.index));
        self.durable = Some(durable);
        self.durable_path = Some(path);
        self.store_phase("reserved")
    }

    fn store_phase(&mut self, phase: &'static str) -> Result<(), String> {
        let record = self
            .durable
            .as_mut()
            .ok_or_else(|| "guardian slot durable binding is absent".to_owned())?;
        record.phase = phase;
        let path = self
            .durable_path
            .as_ref()
            .ok_or_else(|| "guardian slot durable path is absent".to_owned())?;
        let staged = path.with_extension("json.new");
        std::fs::write(
            &staged,
            serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        super::record::replace_atomically(&staged, path)
    }
}

impl Drop for GuardianSlotLease {
    fn drop(&mut self) {
        let _ = super::service_manager::stop(&self.service, &self.name);
        if let Some(path) = self.durable_path.as_ref() {
            let _ = std::fs::remove_file(path);
        }
        LEASED_GUARDIAN_SLOTS
            .lock()
            .expect("guardian slot lease mutex")
            .remove(&self.index);
    }
}

pub struct GuardianProcess {
    process: OwnedHandle,
    _slot: GuardianSlotLease,
}

impl GuardianProcess {
    pub const fn raw(&self) -> HANDLE {
        self.process.raw()
    }
}

pub(super) fn acquire_guardian_slot() -> Result<GuardianSlotLease, String> {
    let manager = super::service_manager::manager_connect()?;
    let mut leased = LEASED_GUARDIAN_SLOTS
        .lock()
        .map_err(|_| "guardian slot lease mutex poisoned".to_owned())?;
    for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
        if leased.contains(&index) {
            continue;
        }
        let name = super::security::guardian_slot_name(index)?;
        let durable_path = super::package::state_root()
            .join("guardian-slots")
            .join(format!("{index:03}.json"));
        if durable_path.exists() {
            continue;
        }
        let service = super::service_manager::open(
            &manager,
            &name,
            SERVICE_START
                | SERVICE_STOP
                | SERVICE_QUERY_STATUS
                | SERVICE_QUERY_CONFIG
                | READ_CONTROL_ACCESS,
        )?;
        let status = super::service_manager::status_process(&service)?;
        if status.dwCurrentState == SERVICE_STOPPED && status.dwProcessId == 0 {
            leased.insert(index);
            return Ok(GuardianSlotLease {
                index,
                name,
                service,
                durable: None,
                durable_path: None,
            });
        }
    }
    Err(
        "MCSEALED-WINDOWS-GUARDIAN-CAPACITY: every canonical guardian slot is leased or active"
            .to_owned(),
    )
}

pub(super) fn guardian_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    // SAFETY: system-preferred CNG fills the exact mutable byte array and uses
    // no caller-provided algorithm handle.
    if unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
    {
        return Err("Windows CSPRNG failed for guardian slot nonce".to_owned());
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[allow(clippy::too_many_arguments)]
pub fn create_guardian(
    job: HANDLE,
    frontend: HANDLE,
    worker: HANDLE,
    disarm: HANDLE,
    ready: HANDLE,
    attempt_id: &str,
    cleanup_deadline_millis: u64,
    readiness_delay_millis: u64,
) -> Result<(GuardianProcess, u32), GuardianBootstrapError> {
    let mut slot = acquire_guardian_slot().map_err(GuardianBootstrapError::from)?;
    let launcher_identity = process_identity(unsafe { GetCurrentProcess() })?;
    let nonce = guardian_nonce()?;
    slot.bind(attempt_id, &nonce, &launcher_identity)?;
    let pipe_name = format!("{}{}", memcordon_core::WINDOWS_GUARDIAN_PIPE_PREFIX, nonce);
    let listener = PipeListener::new(
        &pipe_name,
        SecurityDescriptor::from_sddl(&super::security::guardian_slot_pipe_sddl(slot.index)?)?,
    );
    let prepared = listener
        .prepare()
        .map_err(|error| GuardianBootstrapError::from(error.to_string()))?;
    let start_arguments = vec![
        super::guardian_service::SERVICE_BINDING_SCHEMA_VERSION.to_string(),
        slot.name.clone(),
        attempt_id.to_owned(),
        nonce.clone(),
        pipe_name,
        launcher_identity.process_id.to_string(),
        launcher_identity.creation_time_100ns.to_string(),
        cleanup_deadline_millis.to_string(),
        readiness_delay_millis.to_string(),
    ];
    super::service_manager::start_with_arguments(&slot.service, &slot.name, &start_arguments)?;
    slot.store_phase("starting")?;
    let bootstrap = listener.accept_prepared(prepared)?;
    let bootstrap_read = duplicate_owned(bootstrap.raw())?;
    let mut scm_status = super::service_manager::status_process(&slot.service)?;
    let status_deadline = Instant::now() + Duration::from_secs(10);
    while scm_status.dwCurrentState != SERVICE_RUNNING && Instant::now() < status_deadline {
        std::thread::sleep(Duration::from_millis(10));
        scm_status = super::service_manager::status_process(&slot.service)?;
    }
    if scm_status.dwCurrentState != SERVICE_RUNNING || scm_status.dwProcessId == 0 {
        return Err(GuardianBootstrapError::from(
            "guardian slot did not converge to RUNNING with a nonzero PID".to_owned(),
        ));
    }
    let mut pipe_pid = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(bootstrap.raw(), &raw mut pipe_pid) } == 0
        || pipe_pid != scm_status.dwProcessId
    {
        return Err(GuardianBootstrapError::from(
            "guardian slot SCM and pipe process identities differ".to_owned(),
        ));
    }
    let process_handle = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | 0x0040 | SYNCHRONIZE_ACCESS,
            0,
            pipe_pid,
        )
    })?;
    let guardian_identity = process_identity(process_handle.raw())?;
    authenticate_guardian_slot_process(process_handle.raw(), &slot.name, &guardian_identity)?;
    let binding = super::guardian::GuardianBootstrapBindingV1 {
        schema_version: super::guardian::GUARDIAN_BOOTSTRAP_SCHEMA_VERSION,
        attempt_id: attempt_id.to_owned(),
        nonce,
        guardian_service_name: slot.name.clone(),
        launcher_identity,
        guardian_identity: guardian_identity.clone(),
    };
    let mut cleanup = GuardianBootstrapCleanup::new(process_handle.raw());
    let hardened = read_guardian_bootstrap_frame(
        bootstrap_read.raw(),
        process_handle.raw(),
        &guardian_identity,
        &binding,
    )?;
    match hardened {
        super::guardian::GuardianBootstrapMessageV1::Hardened {
            binding: observed,
            process_policy_attested: true,
            thread_policy_attested: true,
        } if observed == binding => {}
        _ => {
            return Err(GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::ProtocolViolation,
                &guardian_identity,
                Instant::now(),
                "guardian slot Hardened binding is invalid",
            ));
        }
    }
    slot.store_phase("hardened")?;
    let sources = [job, frontend, worker, disarm, ready];
    let expected = super::guardian::guardian_manifest_contract();
    let mut manifest = Vec::with_capacity(expected.len());
    for ((role, access), source) in expected.into_iter().zip(sources) {
        let remote = duplicate_remote_with_access(source, process_handle.raw(), access)?;
        cleanup.transferred.push(remote);
        manifest.push(super::guardian::GuardianCapabilityV1 {
            role: role.to_owned(),
            handle: remote,
            access,
        });
    }
    super::pipe::write_frame(
        bootstrap.raw(),
        &super::guardian::GuardianBootstrapMessageV1::Capabilities {
            binding: binding.clone(),
            manifest,
        },
    )?;
    let ready_attestation = read_guardian_bootstrap_frame(
        bootstrap_read.raw(),
        process_handle.raw(),
        &guardian_identity,
        &binding,
    )?;
    match ready_attestation {
        super::guardian::GuardianBootstrapMessageV1::Ready {
            binding: observed,
            roles,
            outside_target_job: true,
        } if observed == binding
            && roles
                == super::guardian::guardian_manifest_contract()
                    .map(|(role, _)| role.to_owned()) =>
        {
            cleanup.disarm();
            slot.store_phase("ready")?;
        }
        _ => {
            return Err(GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::ProtocolViolation,
                &guardian_identity,
                Instant::now(),
                "guardian slot Ready binding is invalid",
            ));
        }
    }
    let process_id = guardian_identity.process_id;
    Ok((
        GuardianProcess {
            process: process_handle,
            _slot: slot,
        },
        process_id,
    ))
}

pub(super) fn authenticate_guardian_slot_process(
    process: HANDLE,
    slot_name: &str,
    expected_identity: &WindowsProcessIdentityV1,
) -> Result<(), String> {
    if process_identity(process)? != *expected_identity {
        return Err("guardian slot process identity changed".to_owned());
    }
    verify_image_path(process, &super::package::installed_binary())?;
    let token = super::token::process_token(process)?;
    let slot_sid = super::security::service_sid(slot_name)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18"
        || !super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &slot_sid)?
        || !super::token::token_has_restricting_sid(token.raw(), &slot_sid)?
    {
        return Err("guardian slot token envelope is not canonical".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // The five exact inherited handles stay individually visible.
pub fn create_guardian_direct_negative(
    job: HANDLE,
    frontend: HANDLE,
    worker: HANDLE,
    disarm: HANDLE,
    ready: HANDLE,
    attempt_id: &str,
    cleanup_deadline_millis: u64,
    readiness_delay_millis: u64,
) -> Result<(OwnedHandle, u32), GuardianBootstrapError> {
    // Only three inert NUL standard handles and two bounded bootstrap-pipe
    // endpoints cross the loader boundary.
    // The five privileged workload capabilities are transferred after the
    // child has self-hardened and mutually authenticated this launcher.
    let mut desktop = GuardianDesktopContext::capture().map_err(GuardianBootstrapError::loader)?;
    let standard_handles =
        GuardianStandardHandles::prepare().map_err(GuardianBootstrapError::loader)?;
    let (child_read, parent_write) = pipe_pair(true)?;
    let (parent_read, child_write) = pipe_pair(true)?;
    clear_inherit(parent_write.raw())?;
    clear_inherit(parent_read.raw())?;
    let [standard_input, standard_output, standard_error] = standard_handles.raw();
    let inherited = [
        standard_input,
        standard_output,
        standard_error,
        child_read.raw(),
        child_write.raw(),
    ];
    validate_guardian_loader_handle_list(&inherited).map_err(GuardianBootstrapError::loader)?;
    for handle in inherited {
        verify_inheritable(handle)?;
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let launcher_identity = process_identity(unsafe { GetCurrentProcess() })?;
    let mut nonce_material = attempt_id.as_bytes().to_vec();
    nonce_material.extend_from_slice(&launcher_identity.process_id.to_le_bytes());
    nonce_material.extend_from_slice(&launcher_identity.creation_time_100ns.to_le_bytes());
    nonce_material.extend_from_slice(
        &unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }.to_le_bytes(),
    );
    let nonce = super::record::digest(&nonce_material);
    use std::os::windows::ffi::OsStrExt;
    let mut application_name = executable.as_os_str().encode_wide().collect::<Vec<_>>();
    application_name.push(0);
    let arguments = vec![
        executable.as_os_str().encode_wide().collect(),
        "windows-guardian".encode_utf16().collect(),
        (child_read.raw() as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (child_write.raw() as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (standard_input as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (standard_output as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (standard_error as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        "direct-launch-negative".encode_utf16().collect(),
        desktop.exact_name().encode_utf16().collect(),
        attempt_id.encode_utf16().collect(),
        nonce.encode_utf16().collect(),
        cleanup_deadline_millis.to_string().encode_utf16().collect(),
        readiness_delay_millis.to_string().encode_utf16().collect(),
        launcher_identity
            .process_id
            .to_string()
            .encode_utf16()
            .collect(),
        launcher_identity
            .creation_time_100ns
            .to_string()
            .encode_utf16()
            .collect(),
        "0".encode_utf16().collect(),
    ];
    let mut command_line = encode_command_line(&arguments);
    command_line.push(0);
    let attributes = AttributeList::new(
        &[Attribute::new(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited.as_ptr().cast(),
            std::mem::size_of_val(&inherited),
        )],
        None,
    )?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = standard_input;
    startup.StartupInfo.hStdOutput = standard_output;
    startup.StartupInfo.hStdError = standard_error;
    startup.StartupInfo.lpDesktop = desktop.startup_name.as_mut_ptr();
    startup.lpAttributeList = attributes.raw();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: command, exact captured desktop, and attribute list remain live;
    // the exact five-handle loader list is inheritable; default process/thread
    // descriptors keep native startup OS-compatible. Guardian is outside the
    // target Job and no console creation/detachment mode is combined here.
    if unsafe {
        create_process_native(
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            ptr::null(),
            &raw const startup.StartupInfo,
            &raw mut process,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string().into());
    }
    let thread = OwnedHandle::new(process.hThread)?;
    let process_handle = OwnedHandle::new(process.hProcess)?;
    drop(thread);
    if let Err(error) = desktop.attest() {
        // SAFETY: process is the just-created owned guardian. A changed parent
        // desktop binding invalidates the exact launch contract before trust.
        unsafe { TerminateProcess(process_handle.raw(), 125) };
        let _ = unsafe { WaitForSingleObject(process_handle.raw(), 5_000) };
        return Err(GuardianBootstrapError::loader(error));
    }
    // Close the launcher's copies of child endpoints before any blocking read,
    // so pre-main child death produces EOF rather than an indefinite wait.
    drop(child_read);
    drop(child_write);
    // The child's three inherited copies exist only for native loader startup;
    // these launcher copies are revoked immediately after successful creation.
    drop(standard_handles);

    let guardian_identity = process_identity(process_handle.raw())?;
    let binding = super::guardian::GuardianBootstrapBindingV1 {
        schema_version: super::guardian::GUARDIAN_BOOTSTRAP_SCHEMA_VERSION,
        attempt_id: attempt_id.to_owned(),
        nonce,
        guardian_service_name: "direct-launch-negative".to_owned(),
        launcher_identity,
        guardian_identity: guardian_identity.clone(),
    };
    let mut cleanup = GuardianBootstrapCleanup::new(process_handle.raw());
    let hardened = read_guardian_bootstrap_frame(
        parent_read.raw(),
        process_handle.raw(),
        &guardian_identity,
        &binding,
    )?;
    match hardened {
        super::guardian::GuardianBootstrapMessageV1::Hardened {
            binding: observed,
            process_policy_attested: true,
            thread_policy_attested: true,
        } if observed == binding => {}
        _ => {
            return Err(GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::ProtocolViolation,
                &guardian_identity,
                Instant::now(),
                "guardian bootstrap hardening attestation is invalid",
            ));
        }
    }
    authenticate_guardian_process(process_handle.raw(), &executable, &guardian_identity)?;

    let sources = [job, frontend, worker, disarm, ready];
    let expected = super::guardian::guardian_manifest_contract();
    let mut manifest = Vec::with_capacity(expected.len());
    for ((role, access), source) in expected.into_iter().zip(sources) {
        let remote = duplicate_remote_with_access(source, process_handle.raw(), access)?;
        cleanup.transferred.push(remote);
        manifest.push(super::guardian::GuardianCapabilityV1 {
            role: role.to_owned(),
            handle: remote,
            access,
        });
    }
    super::pipe::write_frame(
        parent_write.raw(),
        &super::guardian::GuardianBootstrapMessageV1::Capabilities {
            binding: binding.clone(),
            manifest,
        },
    )?;
    let ready_attestation = read_guardian_bootstrap_frame(
        parent_read.raw(),
        process_handle.raw(),
        &guardian_identity,
        &binding,
    )?;
    match ready_attestation {
        super::guardian::GuardianBootstrapMessageV1::Ready {
            binding: observed,
            roles,
            outside_target_job: true,
        } if observed == binding
            && roles
                == super::guardian::guardian_manifest_contract()
                    .map(|(role, _)| role.to_owned()) =>
        {
            cleanup.disarm();
        }
        _ => {
            return Err(GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::ProtocolViolation,
                &guardian_identity,
                Instant::now(),
                "guardian bootstrap Ready attestation is invalid",
            ));
        }
    }
    Ok((process_handle, process.dwProcessId))
}

pub(super) fn read_guardian_bootstrap_frame(
    pipe: HANDLE,
    process: HANDLE,
    guardian_identity: &WindowsProcessIdentityV1,
    expected_binding: &super::guardian::GuardianBootstrapBindingV1,
) -> Result<super::guardian::GuardianBootstrapMessageV1, GuardianBootstrapError> {
    let started = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // SAFETY: process is the pinned guardian process. Observe it before
        // peeking the channel so an already-complete typed exit is authoritative.
        match unsafe { WaitForSingleObject(process, 0) } {
            WAIT_OBJECT_0 => {
                return Err(guardian_bootstrap_exit(
                    process,
                    guardian_identity,
                    started,
                    "process-signaled-before-frame",
                ));
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                let mut error = GuardianBootstrapError::observed(
                    GuardianBootstrapOutcome::WaitFailed,
                    guardian_identity,
                    started,
                    "guardian process wait failed",
                );
                error.native_code = io::Error::last_os_error().raw_os_error();
                return Err(error);
            }
            result => {
                return Err(GuardianBootstrapError::observed(
                    GuardianBootstrapOutcome::ProtocolViolation,
                    guardian_identity,
                    started,
                    format!("unexpected guardian wait result {result}"),
                ));
            }
        }

        match super::pipe::frame_available_detailed(pipe) {
            Ok(true) => match super::pipe::read_frame_detailed(pipe) {
                Ok(super::guardian::GuardianBootstrapMessageV1::Rejected {
                    binding,
                    subphase,
                    role,
                    native_code,
                    detail_class,
                }) => {
                    if binding
                        .as_ref()
                        .is_some_and(|value| value != expected_binding)
                    {
                        return Err(GuardianBootstrapError::observed(
                            GuardianBootstrapOutcome::ProtocolViolation,
                            guardian_identity,
                            started,
                            "guardian rejection binding mismatch",
                        ));
                    }
                    let mut error = GuardianBootstrapError::observed(
                        GuardianBootstrapOutcome::ChildRejected,
                        guardian_identity,
                        started,
                        detail_class,
                    );
                    error.subphase = subphase;
                    error.role = role;
                    error.native_code = native_code;
                    return Err(error);
                }
                Ok(frame) => return Ok(frame),
                Err(error) if error.peer_closed => {
                    return Err(guardian_bootstrap_after_channel_close(
                        process,
                        guardian_identity,
                        started,
                        format!("partial-frame: {error}"),
                    ));
                }
                Err(error) => {
                    let mut failure = GuardianBootstrapError::observed(
                        GuardianBootstrapOutcome::ProtocolViolation,
                        guardian_identity,
                        started,
                        error.to_string(),
                    );
                    failure.native_code = error.native_code.map(|code| code as i32);
                    return Err(failure);
                }
            },
            Ok(false) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(false) => {
                return Err(GuardianBootstrapError::observed(
                    GuardianBootstrapOutcome::Timeout,
                    guardian_identity,
                    started,
                    "guardian bootstrap frame timed out",
                ));
            }
            Err(super::pipe::FrameAvailabilityError::PeerClosed) => {
                return Err(guardian_bootstrap_after_channel_close(
                    process,
                    guardian_identity,
                    started,
                    "peer-closed-before-frame",
                ));
            }
            Err(super::pipe::FrameAvailabilityError::Native { code, detail }) => {
                let mut error = GuardianBootstrapError::observed(
                    GuardianBootstrapOutcome::ProtocolViolation,
                    guardian_identity,
                    started,
                    detail,
                );
                error.native_code = code;
                return Err(error);
            }
        }
    }
}

pub(super) fn guardian_bootstrap_after_channel_close(
    process: HANDLE,
    guardian_identity: &WindowsProcessIdentityV1,
    started: Instant,
    observation: impl Into<String>,
) -> GuardianBootstrapError {
    let observation = observation.into();
    // SAFETY: process is pinned and the grace is deliberately bounded. Pipe
    // closure can precede process signaling by a few scheduler instructions.
    match unsafe { WaitForSingleObject(process, GUARDIAN_PIPE_CLOSE_EXIT_GRACE_MILLIS) } {
        WAIT_OBJECT_0 => guardian_bootstrap_exit(
            process,
            guardian_identity,
            started,
            format!("{observation}; process-signaled-after-close"),
        ),
        WAIT_TIMEOUT => GuardianBootstrapError::observed(
            GuardianBootstrapOutcome::ChannelClosedWhileLive,
            guardian_identity,
            started,
            observation,
        ),
        WAIT_FAILED => {
            let mut error = GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::WaitFailed,
                guardian_identity,
                started,
                format!("{observation}; process-wait-failed-after-close"),
            );
            error.native_code = io::Error::last_os_error().raw_os_error();
            error
        }
        result => GuardianBootstrapError::observed(
            GuardianBootstrapOutcome::ProtocolViolation,
            guardian_identity,
            started,
            format!("{observation}; unexpected-process-wait-result={result}"),
        ),
    }
}

pub(super) fn guardian_bootstrap_exit(
    process: HANDLE,
    guardian_identity: &WindowsProcessIdentityV1,
    started: Instant,
    observation: impl Into<String>,
) -> GuardianBootstrapError {
    let mut error = GuardianBootstrapError::observed(
        GuardianBootstrapOutcome::ChildRejected,
        guardian_identity,
        started,
        observation,
    );
    let mut exit_code = 0_u32;
    // SAFETY: the process is signaled and exit_code is writable.
    if unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
        error.outcome = GuardianBootstrapOutcome::WaitFailed;
        error.native_code = io::Error::last_os_error().raw_os_error();
        error.detail = format!("{}; exit-code-read-failed", error.detail);
        return error;
    }
    let (subphase, role, native_code) = super::guardian::startup_detail_for_exit_code(exit_code);
    error.subphase = subphase;
    error.role = role;
    error.native_code = native_code;
    error.exit_code = Some(exit_code);
    error
}

#[cfg(test)]
pub(crate) fn guardian_bootstrap_frame_for_test(
    pipe: HANDLE,
    process: HANDLE,
    guardian_identity: &WindowsProcessIdentityV1,
) -> Result<super::guardian::GuardianBootstrapMessageV1, GuardianBootstrapError> {
    let binding = super::guardian::GuardianBootstrapBindingV1 {
        schema_version: super::guardian::GUARDIAN_BOOTSTRAP_SCHEMA_VERSION,
        attempt_id: "test-attempt".to_owned(),
        nonce: "test-nonce".to_owned(),
        guardian_service_name: "test-guardian-slot".to_owned(),
        launcher_identity: guardian_identity.clone(),
        guardian_identity: guardian_identity.clone(),
    };
    read_guardian_bootstrap_frame(pipe, process, guardian_identity, &binding)
}

#[cfg(test)]
pub(crate) fn guardian_bootstrap_pipe_pair_for_test() -> Result<(OwnedHandle, OwnedHandle), String>
{
    pipe_pair(false)
}

#[cfg(test)]
pub(crate) fn guardian_bootstrap_cleanup_for_test(process: HANDLE) {
    drop(GuardianBootstrapCleanup::new(process));
}

pub(super) struct GuardianBootstrapCleanup {
    process: HANDLE,
    transferred: Vec<u64>,
    armed: bool,
}

impl GuardianBootstrapCleanup {
    const fn new(process: HANDLE) -> Self {
        Self {
            process,
            transferred: Vec::new(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.transferred.clear();
    }
}

impl Drop for GuardianBootstrapCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for handle in self.transferred.drain(..).rev() {
            let _ = close_remote(handle, self.process);
        }
        // SAFETY: the process handle stays live for this guard's scope. A
        // failed or partial bootstrap must not leave an authority helper alive.
        unsafe { TerminateProcess(self.process, 0xED13_0000) };
    }
}

pub(super) fn duplicate_remote_with_access(
    handle: HANDLE,
    process: HANDLE,
    access: u32,
) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: both processes and source are pinned; desired access is the
    // typed manifest contract and the duplicate is explicitly non-inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            access,
            0,
            0,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(remote as usize as u64)
    }
}

pub(super) fn authenticate_guardian_process(
    process: HANDLE,
    executable: &Path,
    expected_identity: &WindowsProcessIdentityV1,
) -> Result<(), String> {
    if process_identity(process)? != *expected_identity {
        return Err("guardian bootstrap process identity changed".to_owned());
    }
    verify_image_path(process, executable)?;
    let child_token = super::token::process_token(process)?;
    let launcher_token = super::token::process_token(unsafe { GetCurrentProcess() })?;
    if super::token::envelope(child_token.raw())? != super::token::envelope(launcher_token.raw())? {
        return Err("guardian bootstrap token envelope differs from launcher".to_owned());
    }
    Ok(())
}

pub(super) fn duplicate_local_inheritable(handle: HANDLE) -> Result<OwnedHandle, String> {
    let mut duplicate = ptr::null_mut();
    // SAFETY: current process and source handle are live; output receives an
    // independently owned inheritable duplicate for the exact guardian list.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &raw mut duplicate,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        OwnedHandle::new(duplicate)
    }
}

pub fn duplicate_owned(handle: HANDLE) -> Result<OwnedHandle, String> {
    let mut duplicate = ptr::null_mut();
    // SAFETY: source/current handles are live and output receives a
    // non-inheritable same-access duplicate owned by the returned wrapper.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &raw mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        OwnedHandle::new(duplicate)
    }
}
