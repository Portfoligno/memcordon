use super::*;

pub struct SuspendedTarget {
    pub(super) process: OwnedHandle,
    pub(super) thread: OwnedHandle,
    pub(super) process_snapshot: Option<super::token::TokenQueryAttestationSnapshot>,
    pub(super) _desktop_lease: Option<TargetDesktopLease>,
    pub(super) desktop_binding: String,
    pub process_id: u32,
    pub creation_observation: TargetCreationObservation,
}

pub(crate) struct NestedSuspendedTarget {
    pub target: SuspendedTarget,
    pub initial: super::token::InstalledThreadTokenAttestation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetCreationObservation {
    pub used_create_process_as_user: bool,
    pub job_list_present: bool,
    pub handle_list_present: bool,
    pub post_create_job_assignment: bool,
    pub unexpected_handle_count: usize,
    pub loader_qualification: Option<memcordon_core::WindowsLoaderQualificationOutcomeV2>,
}

pub struct TargetCreateError {
    pub detail: String,
    pub os_code: Option<i32>,
    pub loader_context: bool,
    pub loader_qualification: Option<memcordon_core::WindowsLoaderQualificationOutcomeV2>,
}

pub(super) enum TargetObjectSecurity {
    LauncherService,
    NestedCanaryCreator,
}

pub(super) struct OwnedDesktop {
    handle: HANDLE,
    assigned: bool,
}

pub(super) struct BootstrapWindowStation {
    handle: HANDLE,
    assigned: bool,
    closed: bool,
}

pub(super) struct OwnedUserObjectDuplicate(HANDLE);

// SAFETY: an opened desktop handle is process-scoped. The creator thread exits
// before ownership moves back to the bootstrap thread, quarantining any
// creator-thread binding side effect.
unsafe impl Send for OwnedDesktop {}

impl OwnedDesktop {
    const fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            assigned: false,
        }
    }

    pub(super) const fn raw(&self) -> HANDLE {
        self.handle
    }

    fn mark_assigned(&mut self) {
        self.assigned = true;
    }
}

impl BootstrapWindowStation {
    const fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            assigned: false,
            closed: false,
        }
    }

    const fn raw(&self) -> HANDLE {
        self.handle
    }

    fn mark_assigned(&mut self) {
        self.assigned = true;
    }

    fn restore_and_close(
        &mut self,
        source: HANDLE,
        expected_source_name: &str,
    ) -> Result<(), String> {
        if !self.assigned {
            return Err("private window station is not assigned during restoration".to_owned());
        }
        if unsafe { SetProcessWindowStation(source) } == 0 {
            return Err(format!(
                "cannot restore source process window station: {}",
                io::Error::last_os_error()
            ));
        }
        self.assigned = false;
        let restored = unsafe { GetProcessWindowStation() };
        if restored.is_null()
            || user_object_name(restored).map_err(|error| error.to_string())?
                != expected_source_name
        {
            return Err("source process window station restoration did not persist".to_owned());
        }
        if unsafe { CloseWindowStation(self.handle) } == 0 {
            return Err(format!(
                "cannot close restored private window station: {}",
                io::Error::last_os_error()
            ));
        }
        self.closed = true;
        Ok(())
    }
}

impl Drop for BootstrapWindowStation {
    fn drop(&mut self) {
        if !self.assigned && !self.closed {
            // SAFETY: before assignment this wrapper exclusively owns the
            // CreateWindowStationW result and CloseWindowStation is permitted.
            unsafe { CloseWindowStation(self.handle) };
        }
        // An assigned process window-station handle cannot be closed. The
        // dedicated bootstrap retains it until process exit tears down the
        // complete private USER namespace.
    }
}

impl Drop for OwnedDesktop {
    fn drop(&mut self) {
        if !self.assigned && !self.handle.is_null() {
            // SAFETY: this wrapper exclusively owns a CreateDesktopW or
            // OpenDesktopW result and no live thread is assigned through it.
            unsafe { CloseDesktop(self.handle) };
        }
        // An assigned desktop handle cannot be closed. The dedicated
        // bootstrap retains it until process exit tears down the complete
        // private USER namespace.
    }
}

pub(super) struct DesktopEnumerationState {
    expected_name: *const u16,
    expected_name_len: usize,
    expected_count: usize,
    unexpected_name: bool,
}

unsafe extern "system" fn enumerate_private_desktop(name: *const u16, state: isize) -> i32 {
    let state = unsafe { &mut *(state as *mut DesktopEnumerationState) };
    if name.is_null() {
        state.unexpected_name = true;
        return 1;
    }
    let mut name_len = 0;
    while unsafe { *name.add(name_len) } != 0 {
        name_len += 1;
    }
    let name = unsafe { std::slice::from_raw_parts(name, name_len) };
    let expected =
        unsafe { std::slice::from_raw_parts(state.expected_name, state.expected_name_len) };
    if name == expected {
        state.expected_count += 1;
    } else {
        state.unexpected_name = true;
    }
    1
}

pub(super) fn verify_private_desktop_containment(
    window_station: HANDLE,
    desktop_wide: &[u16],
) -> Result<(), String> {
    let expected_name = desktop_wide
        .strip_suffix(&[0])
        .ok_or_else(|| "private desktop name is not NUL-terminated".to_owned())?;
    let mut state = DesktopEnumerationState {
        expected_name: expected_name.as_ptr(),
        expected_name_len: expected_name.len(),
        expected_count: 0,
        unexpected_name: false,
    };
    if unsafe {
        EnumDesktopsW(
            window_station,
            Some(enumerate_private_desktop),
            (&raw mut state) as isize,
        )
    } == 0
    {
        return Err(format!(
            "EnumDesktopsW failed for nonce private window station: {}",
            io::Error::last_os_error()
        ));
    }
    if state.expected_count != 1 || state.unexpected_name {
        return Err(format!(
            "nonce private window station desktop containment mismatch: expected_count={} unexpected_name={}",
            state.expected_count, state.unexpected_name
        ));
    }
    Ok(())
}

impl OwnedUserObjectDuplicate {
    fn duplicate(source: HANDLE, desired_access: u32) -> Result<Self, io::Error> {
        let mut duplicate = ptr::null_mut();
        // SAFETY: source is a live process/thread-assigned USER handle. The
        // target is this process, desired_access is role-specific, and the
        // duplicate is deliberately non-inheritable.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &raw mut duplicate,
                desired_access,
                0,
                0,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else if duplicate.is_null() || duplicate == INVALID_HANDLE_VALUE {
            Err(io::Error::other(
                "DuplicateHandle returned an invalid USER-object handle",
            ))
        } else {
            Ok(Self(duplicate))
        }
    }

    pub(super) const fn raw(&self) -> HANDLE {
        self.0
    }

    fn close_checked(&mut self) -> Result<(), io::Error> {
        if self.0.is_null() || self.0 == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(
                "duplicated USER-object handle is already closed",
            ));
        }
        let source = std::mem::replace(&mut self.0, ptr::null_mut());
        // SAFETY: source was exclusively owned by this wrapper. Microsoft
        // documents DUPLICATE_CLOSE_SOURCE as closing it even if the operation
        // subsequently reports failure, so ownership is cleared before the call.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                0,
                DUPLICATE_CLOSE_SOURCE,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn close(mut self) -> Result<(), io::Error> {
        self.close_checked()
    }
}

impl Drop for OwnedUserObjectDuplicate {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            let _ = self.close_checked();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TargetUserBindingReadRole {
    WindowStation,
    Desktop,
}

#[derive(Debug)]
pub(super) struct TargetUserBindingReadError {
    role: TargetUserBindingReadRole,
    native_code: Option<i32>,
    detail: String,
}

impl TargetUserBindingReadError {
    fn native(role: TargetUserBindingReadRole, detail: &'static str, error: io::Error) -> Self {
        Self {
            role,
            native_code: error.raw_os_error(),
            detail: format!("{detail}: {error}"),
        }
    }

    fn from_user_object(role: TargetUserBindingReadRole, error: UserObjectQueryError) -> Self {
        Self {
            role,
            native_code: error.native_code,
            detail: error.detail,
        }
    }

    fn contract(role: TargetUserBindingReadRole, detail: impl Into<String>) -> Self {
        Self {
            role,
            native_code: None,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for TargetUserBindingReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "role={:?} native_code={:?} detail={}",
            self.role, self.native_code, self.detail,
        )
    }
}

pub(super) struct TargetUserBindingReadHandles {
    pub(super) window_station: OwnedUserObjectDuplicate,
    pub(super) desktop: OwnedUserObjectDuplicate,
}

impl TargetUserBindingReadHandles {
    pub(super) fn duplicate(
        window_station: HANDLE,
        desktop: HANDLE,
    ) -> Result<Self, TargetUserBindingReadError> {
        let window_station =
            OwnedUserObjectDuplicate::duplicate(window_station, TARGET_STATION_ATTEST_ACCESS)
                .map_err(|error| {
                    TargetUserBindingReadError::native(
                        TargetUserBindingReadRole::WindowStation,
                        "cannot duplicate current target window station for attestation",
                        error,
                    )
                })?;
        user_object_name(window_station.raw()).map_err(|error| {
            TargetUserBindingReadError::from_user_object(
                TargetUserBindingReadRole::WindowStation,
                error,
            )
        })?;

        let desktop = OwnedUserObjectDuplicate::duplicate(desktop, TARGET_DESKTOP_ATTEST_ACCESS)
            .map_err(|error| {
                TargetUserBindingReadError::native(
                    TargetUserBindingReadRole::Desktop,
                    "cannot duplicate current target desktop for attestation",
                    error,
                )
            })?;
        user_object_name(desktop.raw()).map_err(|error| {
            TargetUserBindingReadError::from_user_object(TargetUserBindingReadRole::Desktop, error)
        })?;
        verify_user_object_not_inheritable(window_station.raw()).map_err(|error| {
            TargetUserBindingReadError::contract(TargetUserBindingReadRole::WindowStation, error)
        })?;
        verify_user_object_not_inheritable(desktop.raw()).map_err(|error| {
            TargetUserBindingReadError::contract(TargetUserBindingReadRole::Desktop, error)
        })?;
        Ok(Self {
            window_station,
            desktop,
        })
    }
}

pub(super) fn creation_failure_phase(
    phase: super::session_broker::SessionCreationPhaseV1,
) -> TargetDesktopBootstrapPhaseV1 {
    match phase {
        super::session_broker::SessionCreationPhaseV1::WindowStation => {
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation
        }
        super::session_broker::SessionCreationPhaseV1::Desktop => {
            TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation
        }
    }
}

pub(super) fn fail_stop_uncertain_creation_arm(
    phase: super::session_broker::SessionCreationPhaseV1,
    detail: impl std::fmt::Display,
) -> ! {
    eprintln!(
        "target creator authority became uncertain after readiness: phase={phase:?} detail={detail}"
    );
    // SAFETY: continuing after the broker may have attached a privileged
    // impersonation token would execute ordinary holder code with uncertain
    // authority. The launcher-owned Job remains the outer cleanup boundary.
    unsafe { TerminateProcess(GetCurrentProcess(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS) };
    std::process::abort();
}

pub(super) fn request_creator_arm(
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    phase: super::session_broker::SessionCreationPhaseV1,
    ordinal: u32,
    thread_id: u32,
    holder_primary: &super::token::TokenQueryAttestationSnapshot,
) -> Result<super::token::AttachedCreationCarrierGuard, TargetDesktopBootstrapFailure> {
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(creation_failure_phase(phase), error)
    })?;
    if holder_primary != &binding.holder_process_snapshot {
        return Err(TargetDesktopBootstrapFailure::contract(
            creation_failure_phase(phase),
            "holder primary changed before creation readiness",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    super::pipe::write_frame_bounded(
        connection,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::CreationReadyWrite,
        &TargetDesktopBootstrapMessageV1::CreationReady {
            binding: binding.clone(),
            phase,
            ordinal,
            thread_id,
            holder_primary: holder_primary.clone(),
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(creation_failure_phase(phase), error)
    })?;
    let armed = match super::pipe::read_frame_bounded(
        connection,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::CreationArmedRead,
    ) {
        Ok(armed) => armed,
        Err(error) => fail_stop_uncertain_creation_arm(phase, error),
    };
    match armed {
        TargetDesktopBootstrapMessageV1::CreationArmed {
            binding: observed_binding,
            phase: observed_phase,
            ordinal: observed_ordinal,
            thread_id: observed_thread,
            carrier,
        } if observed_binding == *binding
            && observed_phase == phase
            && observed_ordinal == ordinal
            && observed_thread == thread_id =>
        {
            let (guard, attached) = match super::token::AttachedCreationCarrierGuard::adopt() {
                Ok(attached) => attached,
                Err(error) => fail_stop_uncertain_creation_arm(phase, error),
            };
            if attached != carrier {
                return Err(TargetDesktopBootstrapFailure::contract(
                    creation_failure_phase(phase),
                    "attached creator carrier differs from authenticated Armed evidence",
                ));
            }
            Ok(guard)
        }
        _ => fail_stop_uncertain_creation_arm(
            phase,
            "launcher returned invalid creation Armed evidence",
        ),
    }
}

pub(super) fn consume_creator_arm(
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    phase: super::session_broker::SessionCreationPhaseV1,
    ordinal: u32,
    thread_id: u32,
    native_code: Option<i32>,
    holder_primary: &super::token::TokenQueryAttestationSnapshot,
) -> Result<(), TargetDesktopBootstrapFailure> {
    if holder_primary != &binding.holder_process_snapshot {
        return Err(TargetDesktopBootstrapFailure::contract(
            creation_failure_phase(phase),
            "holder primary changed while a creation carrier was attached",
        ));
    }
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(creation_failure_phase(phase), error)
    })?;
    let deadline = Instant::now() + Duration::from_secs(30);
    super::pipe::write_frame_bounded(
        connection,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::CreationConsumedWrite,
        &TargetDesktopBootstrapMessageV1::CreationConsumed {
            binding: binding.clone(),
            phase,
            ordinal,
            thread_id,
            holder_primary: holder_primary.clone(),
            native_code,
            thread_token_absent: true,
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(creation_failure_phase(phase), error)
    })?;
    match super::pipe::read_frame_bounded(
        connection,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::CreationClearedRead,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(creation_failure_phase(phase), error)
    })? {
        TargetDesktopBootstrapMessageV1::CreationCleared {
            binding: observed_binding,
            phase: observed_phase,
            ordinal: observed_ordinal,
            thread_id: observed_thread,
        } if observed_binding == *binding
            && observed_phase == phase
            && observed_ordinal == ordinal
            && observed_thread == thread_id =>
        {
            Ok(())
        }
        _ => Err(TargetDesktopBootstrapFailure::contract(
            creation_failure_phase(phase),
            "launcher returned invalid creation Cleared evidence",
        )),
    }
}

pub(super) fn create_target_desktop_on_creator_thread(
    desktop_wide: Vec<u16>,
    creation_security: super::security::AbsoluteSecurityDescriptor,
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: TargetDesktopBootstrapBindingV3,
) -> Result<OwnedDesktop, TargetDesktopBootstrapFailure> {
    let connection_value = connection as usize;
    let launcher_process_value = launcher_process as usize;
    std::thread::Builder::new()
        .name("memcordon-target-desktop-creator".to_owned())
        .spawn(move || {
            let connection = connection_value as HANDLE;
            let launcher_process = launcher_process_value as HANDLE;
            let attributes = creation_security.attributes(false);
            let thread_id = unsafe { GetCurrentThreadId() };
            let primary_before =
                super::token::process_token_query_attestation(unsafe { GetCurrentProcess() })
                    .map_err(|error| {
                        TargetDesktopBootstrapFailure::contract(
                            TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                            error,
                        )
                    })?;
            let carrier_guard = request_creator_arm(
                connection,
                launcher_process,
                &binding,
                super::session_broker::SessionCreationPhaseV1::Desktop,
                2,
                thread_id,
                &primary_before,
            )?;
            // SAFETY: desktop_wide is NUL-terminated, attributes owns a live
            // absolute descriptor, and the requested rights are the exact
            // private-desktop policy rights. The worker quarantines any
            // OS-dependent creator-thread binding side effect; object
            // attestation uses the returned handle after this worker exits.
            let desktop = unsafe {
                CreateDesktopW(
                    desktop_wide.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
                    &raw const attributes,
                )
            };
            let create_error = desktop.is_null().then(|| io::Error::last_os_error());
            if let Err(error) = carrier_guard.revert() {
                eprintln!("desktop creator carrier reversion failed: {error}");
                unsafe {
                    TerminateProcess(GetCurrentProcess(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)
                };
                std::process::abort();
            }
            let primary_after =
                super::token::process_token_query_attestation(unsafe { GetCurrentProcess() })
                    .map_err(|error| {
                        TargetDesktopBootstrapFailure::contract(
                            TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                            error,
                        )
                    })?;
            consume_creator_arm(
                connection,
                launcher_process,
                &binding,
                super::session_broker::SessionCreationPhaseV1::Desktop,
                2,
                thread_id,
                create_error.as_ref().and_then(io::Error::raw_os_error),
                &primary_after,
            )?;
            if let Some(error) = create_error {
                return Err(TargetDesktopBootstrapFailure::captured_native(
                    TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                    error.raw_os_error().unwrap_or_default(),
                    format!("CreateDesktopW failed in target-token bootstrap station: {error}"),
                ));
            }
            Ok(OwnedDesktop::new(desktop))
        })
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                format!("cannot start private desktop creator thread: {error}"),
            )
        })?
        .join()
        .map_err(|_| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                "private desktop creator thread panicked",
            )
        })?
}

pub(super) struct TargetDesktopLease {
    pub(super) bootstrap_process: OwnedHandle,
    bootstrap_job: Job,
    connection_lease: Option<OwnedHandle>,
    bootstrap_identity: WindowsProcessIdentityV1,
    holder_envelope: WindowsCallerTokenEnvelopeV1,
    broker_source_snapshot: super::token::TokenAttestationSnapshot,
    holder_launch_snapshot: super::token::TokenAttestationSnapshot,
    holder_process_snapshot: super::token::TokenQueryAttestationSnapshot,
    holder_binding: TargetDesktopBootstrapBindingV3,
    window_station_name: String,
    desktop_name: String,
    window_station_policy_sha256: String,
    desktop_policy_sha256: String,
    window_station_live_equality_sha256: String,
    desktop_live_equality_sha256: String,
    pub(super) exact_name: String,
    pub(super) startup_name: Vec<u16>,
    loader_qualification: Option<memcordon_core::WindowsLoaderQualificationOutcomeV2>,
}

#[derive(Clone)]
pub(super) struct LoaderReadyQualificationV1 {
    evidence: LoaderReadyEvidenceV1,
    plan_json: String,
}

impl LoaderReadyQualificationV1 {
    fn to_wire(&self) -> memcordon_core::WindowsLoaderQualificationOutcomeV2 {
        let mut outcome = LaunchQualificationOutcomeV2::Ready(self.evidence.clone()).to_wire();
        outcome.set_launch_plan_json(self.plan_json.clone());
        outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LoaderLaunchFailurePhaseV1 {
    PreCreate,
    CreateProcessReturn,
    PreResumeAttestation,
    Resume,
    PostResumePreLoaderReady,
    PostLoaderReadyContainment,
    ExitDrain,
    Unknown,
}

impl LoaderLaunchFailurePhaseV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::PreCreate => "pre-create",
            Self::CreateProcessReturn => "create-process-return",
            Self::PreResumeAttestation => "pre-resume-attestation",
            Self::Resume => "resume",
            Self::PostResumePreLoaderReady => "post-resume-pre-loader-ready",
            Self::PostLoaderReadyContainment => "post-loader-ready-containment",
            Self::ExitDrain => "exit-drain",
            Self::Unknown => "unclassified",
        }
    }
}

pub(super) struct TargetDesktopLeaseCreateError {
    pub(super) detail: String,
    pub(super) os_code: Option<i32>,
    loader_phase: LoaderLaunchFailurePhaseV1,
    native_status: Option<NativeStatusV1>,
    pub(super) loader_qualification: Option<memcordon_core::WindowsLoaderQualificationOutcomeV2>,
}

impl TargetDesktopLeaseCreateError {
    fn at_loader_phase(mut self, loader_phase: LoaderLaunchFailurePhaseV1) -> Self {
        if self.loader_phase == LoaderLaunchFailurePhaseV1::Unknown {
            self.loader_phase = loader_phase;
        }
        self
    }

    fn with_native_status(mut self, native_status: NativeStatusV1) -> Self {
        self.native_status = Some(native_status);
        self
    }

    fn with_loader_qualification(
        mut self,
        outcome: memcordon_core::WindowsLoaderQualificationOutcomeV2,
    ) -> Self {
        self.loader_qualification = Some(outcome);
        self
    }
}

#[derive(Clone)]
pub(super) struct TargetDesktopBootstrapLaunchContext {
    policy_role: super::security::TargetUserObjectPolicyRoleV1,
    scenario: &'static str,
    target_token_restricted: bool,
    target_token_write_restricted: bool,
    target_integrity: String,
    target_restricting_sid_sha256: String,
}

impl TargetDesktopBootstrapLaunchContext {
    fn capture(
        token: HANDLE,
        snapshot: &super::token::TokenAttestationSnapshot,
        policy_role: super::security::TargetUserObjectPolicyRoleV1,
    ) -> Result<Self, TargetDesktopLeaseCreateError> {
        let target_token_write_restricted =
            super::security::write_restricted_behavior_attested(token)?;
        let administrator_deny_only = snapshot.behavior.groups.iter().any(|entry| {
            entry
                .strip_prefix("S-1-5-32-544@")
                .and_then(|attributes| u32::from_str_radix(attributes, 16).ok())
                .is_some_and(|attributes| attributes & 0x10 != 0)
        });
        let scenario = if target_token_write_restricted {
            "write-restricted"
        } else if administrator_deny_only {
            "deny-only-admin"
        } else if snapshot.behavior.token_is_restricted {
            "restricted"
        } else if snapshot.behavior.envelope.integrity_level == "S-1-16-4096" {
            "low-integrity"
        } else if snapshot.behavior.envelope.elevated {
            "elevated-admin"
        } else {
            "ordinary-user"
        };
        Ok(Self {
            policy_role,
            scenario,
            target_token_restricted: snapshot.behavior.token_is_restricted,
            target_token_write_restricted,
            target_integrity: snapshot.behavior.envelope.integrity_level.clone(),
            target_restricting_sid_sha256: super::record::digest(
                snapshot.behavior.restricting_sids.join("\n").as_bytes(),
            ),
        })
    }

    fn accept_error(
        &self,
        role: TargetDesktopBootstrapRoleV1,
        bootstrap_pid: u32,
        bootstrap_image_sha256: &str,
        desktop_mode: &str,
        evidence: &str,
        error: super::pipe::TargetDesktopBootstrapPipeError,
    ) -> TargetDesktopLeaseCreateError {
        TargetDesktopLeaseCreateError {
            os_code: error.native_code(),
            native_status: error
                .native_code()
                .map(|code| NativeStatusV1::Win32 { code: code as u32 }),
            loader_phase: LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
            loader_qualification: None,
            detail: format!(
                "bootstrap_role={} policy_role={} scenario={} launch_phase=resumed bootstrap_pid={bootstrap_pid} bootstrap_image_sha256={bootstrap_image_sha256} target_token_restricted={} target_token_write_restricted={} target_integrity={} target_restricting_sid_sha256={} desktop_mode={desktop_mode} {evidence} detail={error}",
                role.diagnostic(),
                self.policy_role.diagnostic(),
                self.scenario,
                self.target_token_restricted,
                self.target_token_write_restricted,
                self.target_integrity,
                self.target_restricting_sid_sha256,
            ),
        }
    }
}

impl From<String> for TargetDesktopLeaseCreateError {
    fn from(detail: String) -> Self {
        Self {
            detail,
            os_code: None,
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
            native_status: None,
            loader_qualification: None,
        }
    }
}

impl From<super::token::LauncherHolderTokenDerivationError> for TargetDesktopLeaseCreateError {
    fn from(error: super::token::LauncherHolderTokenDerivationError) -> Self {
        Self {
            os_code: error.native_code,
            detail: error.to_string(),
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
            native_status: error
                .native_code
                .map(|code| NativeStatusV1::Win32 { code: code as u32 }),
            loader_qualification: None,
        }
    }
}

impl From<super::security::TargetUserObjectPolicyError> for TargetDesktopLeaseCreateError {
    fn from(error: super::security::TargetUserObjectPolicyError) -> Self {
        Self {
            os_code: None,
            detail: error.to_string(),
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
            native_status: None,
            loader_qualification: None,
        }
    }
}

impl From<super::token::TokenAttestationRelationError> for TargetDesktopLeaseCreateError {
    fn from(error: super::token::TokenAttestationRelationError) -> Self {
        Self {
            os_code: None,
            detail: error.to_string(),
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
            native_status: None,
            loader_qualification: None,
        }
    }
}

#[cfg(test)]
pub(crate) fn holder_derivation_error_mapping_for_test(
    error: super::token::LauncherHolderTokenDerivationError,
) -> (String, Option<i32>) {
    let mapped = TargetDesktopLeaseCreateError::from(error);
    (mapped.detail, mapped.os_code)
}

impl From<super::pipe::TargetDesktopBootstrapPipeError> for TargetDesktopLeaseCreateError {
    fn from(error: super::pipe::TargetDesktopBootstrapPipeError) -> Self {
        Self {
            os_code: error.native_code(),
            detail: error.to_string(),
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
            native_status: error
                .native_code()
                .map(|code| NativeStatusV1::Win32 { code: code as u32 }),
            loader_qualification: None,
        }
    }
}

pub(super) struct CapturedTargetDesktop {
    read_handles: TargetUserBindingReadHandles,
    pub(super) window_station_name: String,
    window_station_security_sha256: String,
    pub(super) desktop_name: String,
    desktop_security_sha256: String,
    pub(super) exact_name: String,
    pub(super) startup_name: Vec<u16>,
    window_station_security: SecurityDescriptor,
    desktop_security: SecurityDescriptor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TargetDesktopBootstrapPhaseV1 {
    EndpointCreation,
    EndpointAdmission,
    AdmissionRead,
    ServerProcessAuthentication,
    ServerTokenAuthentication,
    StartedPublication,
    LauncherAuthentication,
    ResultEndpointAdmission,
    LifetimeEndpointAdmission,
    TargetTokenCapture,
    UserBindingAcquisition,
    UserBindingAttestation,
    StationReadHandle,
    StationSecurityReadback,
    DefaultDesktopReadHandle,
    DefaultDesktopSecurityReadback,
    DesktopNonceGeneration,
    WindowStationPolicyConstruction,
    PrivateWindowStationCreation,
    PrivateWindowStationBinding,
    PrivateWindowStationAttestation,
    DesktopPolicyConstruction,
    PrivateDesktopCreation,
    PrivateDesktopAttestation,
    SharedBindingPostAttestation,
    UserModuleResolution,
    ProcessIdentityCapture,
    ResultPublication,
    LifetimeHold,
    SessionGate,
    RestrictedProbeCreation,
    RestrictedProbeAuthentication,
    RestrictedProbeAttestation,
    TargetAssociationPreflight,
    TargetNativeLoaderAccessPreflight,
    LoaderControl,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TargetAssociationPreflightStageV1 {
    RetainedNamespaceBefore,
    SourceBootstrap,
    SourceSystemAncestry,
    SourceLoaderGraph,
    SourceKnownDlls,
    TargetTokenInstallation,
    TargetWindowStation,
    TargetDesktop,
    TargetBootstrap,
    TargetKnownDlls,
    TargetModules,
    RevertAndFinalization,
}

impl TargetAssociationPreflightStageV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::RetainedNamespaceBefore => "retained-namespace-before",
            Self::SourceBootstrap => "source-bootstrap",
            Self::SourceSystemAncestry => "source-system-ancestry",
            Self::SourceLoaderGraph => "source-loader-graph",
            Self::SourceKnownDlls => "source-known-dlls",
            Self::TargetTokenInstallation => "target-token-installation",
            Self::TargetWindowStation => "target-window-station",
            Self::TargetDesktop => "target-desktop",
            Self::TargetBootstrap => "target-bootstrap",
            Self::TargetKnownDlls => "target-known-dlls",
            Self::TargetModules => "target-modules",
            Self::RevertAndFinalization => "revert-and-finalization",
        }
    }

    const fn successor(self) -> Option<Self> {
        match self {
            Self::RetainedNamespaceBefore => Some(Self::SourceBootstrap),
            Self::SourceBootstrap => Some(Self::SourceSystemAncestry),
            Self::SourceSystemAncestry => Some(Self::SourceLoaderGraph),
            Self::SourceLoaderGraph => Some(Self::SourceKnownDlls),
            Self::SourceKnownDlls => Some(Self::TargetTokenInstallation),
            Self::TargetTokenInstallation => Some(Self::TargetWindowStation),
            Self::TargetWindowStation => Some(Self::TargetDesktop),
            Self::TargetDesktop => Some(Self::TargetBootstrap),
            Self::TargetBootstrap => Some(Self::TargetKnownDlls),
            Self::TargetKnownDlls => Some(Self::TargetModules),
            Self::TargetModules => Some(Self::RevertAndFinalization),
            Self::RevertAndFinalization => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TargetDesktopBootstrapRoleV1 {
    Holder,
    LoaderControl,
    Probe,
}

impl TargetDesktopBootstrapRoleV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Holder => "holder",
            Self::LoaderControl => "loader-control",
            Self::Probe => "probe",
        }
    }
}

pub(crate) use self::TargetDesktopBootstrapRoleV1 as TargetDesktopBootstrapRole;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetDesktopBootstrapBindingV3 {
    schema_version: u32,
    role: TargetDesktopBootstrapRoleV1,
    target_user_object_policy_role: super::security::TargetUserObjectPolicyRoleV1,
    nonce: String,
    binding_sha256: String,
    bootstrap_image_sha256: String,
    launcher_identity: WindowsProcessIdentityV1,
    launcher_session_id: u32,
    launcher_envelope: WindowsCallerTokenEnvelopeV1,
    launcher_process_snapshot: super::token::TokenAttestationSnapshot,
    broker_source_snapshot: super::token::TokenAttestationSnapshot,
    holder_launch_snapshot: super::token::TokenAttestationSnapshot,
    holder_assignment: super::token::AssignedProcessTokenEvidenceV1,
    bootstrap_identity: WindowsProcessIdentityV1,
    bootstrap_envelope: WindowsCallerTokenEnvelopeV1,
    bootstrap_process_snapshot: super::token::TokenQueryAttestationSnapshot,
    bootstrap_assignment: super::token::AssignedProcessTokenEvidenceV1,
    holder_process_snapshot: super::token::TokenQueryAttestationSnapshot,
    target_envelope: WindowsCallerTokenEnvelopeV1,
    target_request_snapshot: super::token::TokenAttestationSnapshot,
}

impl TargetDesktopBootstrapBindingV3 {
    fn seal(mut self) -> Result<Self, String> {
        self.binding_sha256 = self.calculated_sha256()?;
        Ok(self)
    }

    fn verify_digest(&self) -> Result<(), String> {
        if self.binding_sha256 != self.calculated_sha256()? {
            Err("target desktop bootstrap binding digest is mismatched".to_owned())
        } else {
            Ok(())
        }
    }

    fn calculated_sha256(&self) -> Result<String, String> {
        let mut claims = serde_json::to_value(self).map_err(|error| error.to_string())?;
        claims
            .as_object_mut()
            .ok_or_else(|| "target desktop bootstrap binding is not an object".to_owned())?
            .remove("binding_sha256")
            .ok_or_else(|| "target desktop bootstrap binding digest field is absent".to_owned())?;
        let mut canonical = b"memcordon-target-desktop-binding-v8\0".to_vec();
        canonical.extend(serde_json::to_vec(&claims).map_err(|error| error.to_string())?);
        Ok(super::record::digest(&canonical))
    }
}

impl TargetDesktopBootstrapPhaseV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::EndpointCreation => "endpoint-creation",
            Self::EndpointAdmission => "endpoint-admission",
            Self::AdmissionRead => "admission-read",
            Self::ServerProcessAuthentication => "server-process-authentication",
            Self::ServerTokenAuthentication => "server-token-authentication",
            Self::StartedPublication => "started-publication",
            Self::LauncherAuthentication => "launcher-authentication",
            Self::ResultEndpointAdmission => "result-endpoint-admission",
            Self::LifetimeEndpointAdmission => "lifetime-endpoint-admission",
            Self::TargetTokenCapture => "target-token-capture",
            Self::UserBindingAcquisition => "user-binding-acquisition",
            Self::UserBindingAttestation => "user-binding-attestation",
            Self::StationReadHandle => "station-read-handle",
            Self::StationSecurityReadback => "station-security-readback",
            Self::DefaultDesktopReadHandle => "default-desktop-read-handle",
            Self::DefaultDesktopSecurityReadback => "default-desktop-security-readback",
            Self::DesktopNonceGeneration => "desktop-nonce-generation",
            Self::WindowStationPolicyConstruction => "window-station-policy-construction",
            Self::PrivateWindowStationCreation => "private-window-station-creation",
            Self::PrivateWindowStationBinding => "private-window-station-binding",
            Self::PrivateWindowStationAttestation => "private-window-station-attestation",
            Self::DesktopPolicyConstruction => "desktop-policy-construction",
            Self::PrivateDesktopCreation => "private-desktop-creation",
            Self::PrivateDesktopAttestation => "private-desktop-attestation",
            Self::SharedBindingPostAttestation => "shared-binding-post-attestation",
            Self::UserModuleResolution => "user-module-resolution",
            Self::ProcessIdentityCapture => "process-identity-capture",
            Self::ResultPublication => "result-publication",
            Self::LifetimeHold => "lifetime-hold",
            Self::SessionGate => "session-gate",
            Self::RestrictedProbeCreation => "restricted-probe-creation",
            Self::RestrictedProbeAuthentication => "restricted-probe-authentication",
            Self::RestrictedProbeAttestation => "restricted-probe-attestation",
            Self::TargetAssociationPreflight => "target-association-preflight",
            Self::TargetNativeLoaderAccessPreflight => "target-native-loader-access-preflight",
            Self::LoaderControl => "loader-control",
        }
    }
}

#[derive(Debug)]
pub(super) struct TargetDesktopBootstrapFailure {
    phase: TargetDesktopBootstrapPhaseV1,
    native_code: Option<i32>,
    detail: String,
    started_publication_bytes_transferred: usize,
}

impl TargetDesktopBootstrapFailure {
    fn contract(phase: TargetDesktopBootstrapPhaseV1, detail: impl ToString) -> Self {
        Self {
            phase,
            native_code: None,
            detail: bounded_target_desktop_bootstrap_detail(detail.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn native(phase: TargetDesktopBootstrapPhaseV1, detail: &'static str) -> Self {
        let error = io::Error::last_os_error();
        Self {
            phase,
            native_code: error.raw_os_error(),
            detail: bounded_target_desktop_bootstrap_detail(format!("{detail}: {error}")),
            started_publication_bytes_transferred: 0,
        }
    }

    fn captured_native(
        phase: TargetDesktopBootstrapPhaseV1,
        native_code: i32,
        detail: impl ToString,
    ) -> Self {
        Self {
            phase,
            native_code: Some(native_code),
            detail: bounded_target_desktop_bootstrap_detail(detail.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn observed_native(phase: TargetDesktopBootstrapPhaseV1, detail: impl ToString) -> Self {
        let native_code = io::Error::last_os_error().raw_os_error();
        Self {
            phase,
            native_code,
            detail: bounded_target_desktop_bootstrap_detail(detail.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn from_pipe(
        phase: TargetDesktopBootstrapPhaseV1,
        error: super::pipe::TargetDesktopBootstrapPipeError,
    ) -> Self {
        Self {
            phase,
            native_code: error.native_code(),
            detail: bounded_target_desktop_bootstrap_detail(error.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn from_user_object(phase: TargetDesktopBootstrapPhaseV1, error: UserObjectQueryError) -> Self {
        Self {
            phase,
            native_code: error.native_code,
            detail: bounded_target_desktop_bootstrap_detail(error.detail),
            started_publication_bytes_transferred: 0,
        }
    }

    fn from_native_loader(error: super::loader_access::NativeLoaderAccessFailureV1) -> Self {
        Self {
            phase: TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
            native_code: error.native_code,
            detail: bounded_target_desktop_bootstrap_detail(error.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn from_binding_read(error: TargetUserBindingReadError) -> Self {
        let phase = match error.role {
            TargetUserBindingReadRole::WindowStation => {
                TargetDesktopBootstrapPhaseV1::StationReadHandle
            }
            TargetUserBindingReadRole::Desktop => {
                TargetDesktopBootstrapPhaseV1::DefaultDesktopReadHandle
            }
        };
        Self {
            phase,
            native_code: error.native_code,
            detail: bounded_target_desktop_bootstrap_detail(error.detail),
            started_publication_bytes_transferred: 0,
        }
    }

    fn after_started_publication_error(mut self, bytes_transferred: usize) -> Self {
        self.started_publication_bytes_transferred = bytes_transferred;
        self
    }
}

impl std::fmt::Display for TargetDesktopBootstrapFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "phase={} native_code={:?} detail={}",
            self.phase.diagnostic(),
            self.native_code,
            self.detail,
        )
    }
}

pub(super) fn bounded_target_desktop_bootstrap_detail(mut detail: String) -> String {
    if detail.len() > TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES {
        let mut boundary = TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES;
        while !detail.is_char_boundary(boundary) {
            boundary -= 1;
        }
        detail.truncate(boundary);
    }
    detail
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetDesktopBootstrapFrameV1 {
    schema_version: u32,
    bootstrap_identity: WindowsProcessIdentityV1,
    target_envelope: WindowsCallerTokenEnvelopeV1,
    window_station_name: String,
    desktop_name: String,
    window_station_policy_sha256: String,
    desktop_policy_sha256: String,
    window_station_live_equality_sha256: String,
    desktop_live_equality_sha256: String,
    source_objects_unmodified: bool,
    private_station_assigned: bool,
    private_desktop_assigned: bool,
    desktop_containment_verified: bool,
    window_station_policy_verified: bool,
    desktop_policy_verified: bool,
    window_station_not_inheritable: bool,
    desktop_not_inheritable: bool,
    noninteractive: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetUserObjectOpenPreflightV1 {
    window_station_granted_access: u32,
    desktop_granted_access: u32,
    desktop_heap_kb: u32,
    window_station_policy_sha256: String,
    desktop_policy_sha256: String,
    window_station_live_equality_sha256: String,
    desktop_live_equality_sha256: String,
    window_station_policy_verified_after_open: bool,
    desktop_policy_verified_after_open: bool,
    creator_live_baselines_unchanged: bool,
    target_snapshot_before: super::token::TokenAttestationSnapshot,
    target_snapshot_after: super::token::TokenAttestationSnapshot,
    thread_token_absent: bool,
    native_loader_access: super::loader_access::NativeLoaderAccessEvidenceV2,
}

impl TargetUserObjectOpenPreflightV1 {
    fn diagnostic(&self) -> String {
        format!(
            "association_preflight=passed station_requested={:#010x} station_granted={:#010x} desktop_requested={:#010x} desktop_granted={:#010x} desktop_heap_kb={}",
            super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            self.window_station_granted_access,
            super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
            self.desktop_granted_access,
            self.desktop_heap_kb,
        ) + " "
            + &self.native_loader_access.diagnostic()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderDesktopBindingV1 {
    pub(crate) window_station_name: String,
    pub(crate) desktop_name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LoaderDesktopBindingReadFailureKindV1 {
    WindowStationHandle,
    WindowStationName,
    DesktopHandle,
    DesktopName,
}

impl LoaderDesktopBindingReadFailureKindV1 {
    const fn loader_control_stable_code(self) -> &'static str {
        match self {
            Self::WindowStationHandle | Self::WindowStationName => {
                "loader-control-window-station-binding-readback"
            }
            Self::DesktopHandle | Self::DesktopName => "loader-control-desktop-binding-readback",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderDesktopBindingReadFailureV1 {
    pub(crate) kind: LoaderDesktopBindingReadFailureKindV1,
    pub(crate) native_code: Option<i32>,
    pub(crate) detail: String,
}

impl LoaderDesktopBindingReadFailureV1 {
    fn native(kind: LoaderDesktopBindingReadFailureKindV1, detail: &'static str) -> Self {
        let error = io::Error::last_os_error();
        Self {
            kind,
            native_code: error.raw_os_error(),
            detail: format!("{detail}: {error}"),
        }
    }

    fn from_user_object(
        kind: LoaderDesktopBindingReadFailureKindV1,
        error: UserObjectQueryError,
    ) -> Self {
        Self {
            kind,
            native_code: error.native_code,
            detail: error.detail,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoaderControlDesktopEvidenceV1 {
    Observed(LoaderDesktopBindingV1),
    ReadFailed(LoaderDesktopBindingReadFailureV1),
}

pub(crate) fn validate_loader_control_desktop_evidence(
    expected_exact_desktop: &str,
    evidence: &LoaderControlDesktopEvidenceV1,
) -> Result<(), ProcessCreateFailure> {
    let (expected_window_station, expected_desktop) = expected_exact_desktop
        .split_once('\\')
        .ok_or_else(|| ProcessCreateFailure {
            stable_code: String::from("loader-control-ready-frame-invalid"),
            native_status: None,
            detail: String::from("production desktop binding is not fully qualified"),
        })?;
    match evidence {
        LoaderControlDesktopEvidenceV1::Observed(binding)
            if binding.window_station_name == expected_window_station
                && binding.desktop_name == expected_desktop =>
        {
            Ok(())
        }
        LoaderControlDesktopEvidenceV1::Observed(_) => Err(ProcessCreateFailure {
            stable_code: String::from("loader-control-desktop-binding-mismatch"),
            native_status: None,
            detail: String::from(
                "running loader-control USER binding differs from the production plan",
            ),
        }),
        LoaderControlDesktopEvidenceV1::ReadFailed(failure)
            if !failure.detail.is_empty()
                && failure.detail.len() <= TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES =>
        {
            Err(ProcessCreateFailure {
                stable_code: String::from(failure.kind.loader_control_stable_code()),
                native_status: failure
                    .native_code
                    .map(|code| NativeStatusV1::Win32 { code: code as u32 }),
                detail: failure.detail.clone(),
            })
        }
        LoaderControlDesktopEvidenceV1::ReadFailed(_) => Err(ProcessCreateFailure {
            stable_code: String::from("loader-control-ready-frame-invalid"),
            native_status: None,
            detail: String::from("loader-control desktop readback failure is malformed"),
        }),
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
pub(super) enum TargetDesktopBootstrapMessageV1 {
    LoaderReady {
        schema_version: u32,
        nonce: String,
        expected_desktop: Option<String>,
        observed_desktop_binding: Option<LoaderDesktopBindingV1>,
        bootstrap_identity: WindowsProcessIdentityV1,
        process_envelope: WindowsCallerTokenEnvelopeV1,
        process_snapshot: super::token::TokenQueryAttestationSnapshot,
    },
    LoaderReadyFailed {
        schema_version: u32,
        nonce: String,
        role: TargetDesktopBootstrapRoleV1,
        failure: LoaderDesktopBindingReadFailureV1,
    },
    LoaderControlRelease {
        schema_version: u32,
        nonce: String,
        expected_desktop: String,
    },
    Admission {
        binding: TargetDesktopBootstrapBindingV3,
        launcher_process_query_handle: u64,
        launcher_token_query_handle: u64,
        target_token_capability_handle: Option<u64>,
    },
    Started {
        binding: TargetDesktopBootstrapBindingV3,
        phase: TargetDesktopBootstrapPhaseV1,
    },
    CreationReady {
        binding: TargetDesktopBootstrapBindingV3,
        phase: super::session_broker::SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: super::token::TokenQueryAttestationSnapshot,
    },
    CreationArmed {
        binding: TargetDesktopBootstrapBindingV3,
        phase: super::session_broker::SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        carrier: super::token::TokenAttestationSnapshot,
    },
    CreationConsumed {
        binding: TargetDesktopBootstrapBindingV3,
        phase: super::session_broker::SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: super::token::TokenQueryAttestationSnapshot,
        native_code: Option<i32>,
        thread_token_absent: bool,
    },
    CreationCleared {
        binding: TargetDesktopBootstrapBindingV3,
        phase: super::session_broker::SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
    },
    Ready {
        binding: TargetDesktopBootstrapBindingV3,
        attestation: TargetDesktopBootstrapFrameV1,
    },
    AssociationPreflight {
        binding: TargetDesktopBootstrapBindingV3,
    },
    AssociationPreflightProgress {
        binding: TargetDesktopBootstrapBindingV3,
        sequence: u32,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    },
    AssociationPreflightReady {
        binding: TargetDesktopBootstrapBindingV3,
        evidence: Box<TargetUserObjectOpenPreflightV1>,
    },
    Failed {
        binding: TargetDesktopBootstrapBindingV3,
        phase: TargetDesktopBootstrapPhaseV1,
        native_code: Option<i32>,
        detail: String,
    },
}

impl TargetDesktopLease {
    pub(super) fn loader_qualification(
        &self,
    ) -> Option<memcordon_core::WindowsLoaderQualificationOutcomeV2> {
        self.loader_qualification.clone()
    }

    pub(super) fn create(
        token: HANDLE,
        policy_role: super::security::TargetUserObjectPolicyRoleV1,
    ) -> Result<Self, TargetDesktopLeaseCreateError> {
        let target_envelope = super::token::envelope(token)?;
        let target_snapshot = super::token::token_attestation_snapshot(token)?;
        let launch_context =
            TargetDesktopBootstrapLaunchContext::capture(token, &target_snapshot, policy_role)?;
        let target_user_object_policy =
            super::security::target_user_object_policy(token, policy_role)?;
        let launcher_token = super::token::current_process_token_for_attestation()?;
        let launcher_envelope = super::token::envelope(launcher_token.raw())?;
        let launcher_snapshot = super::token::token_attestation_snapshot(launcher_token.raw())?;
        let launcher_identity = process_identity(unsafe { GetCurrentProcess() })?;
        if launcher_envelope.session_id != 0 {
            return Err("launcher service token is outside session 0"
                .to_owned()
                .into());
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let expected_window_station_sddl = target_user_object_policy.window_station_sddl();
        let expected_window_station_policy_sha256 =
            SecurityDescriptor::from_sddl(&expected_window_station_sddl)?
                .user_object_policy_fingerprint(
                    super::security::SecurityObjectKind::WindowStation,
                )?;
        let expected_desktop_sddl = target_user_object_policy.desktop_sddl();
        let expected_desktop_policy_sha256 = SecurityDescriptor::from_sddl(&expected_desktop_sddl)?
            .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)?;
        let nonce = target_desktop_nonce()?;
        validate_target_desktop_bootstrap_nonce(&nonce)?;
        let pipe_name = format!(
            "{}{}",
            super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
            nonce
        );
        let pipe_security =
            SecurityDescriptor::from_sddl(&super::security::holder_bootstrap_pipe_sddl()?)?;
        let prepared_pipe =
            super::pipe::prepare_target_desktop_bootstrap_pipe(&pipe_name, &pipe_security)?;
        clear_inherit(prepared_pipe.raw())?;
        verify_not_inheritable(prepared_pipe.raw())?;
        let bootstrap_job = Job::create_session_holder()?;
        let executable = super::package::installed_target_desktop_bootstrap();
        let bootstrap_image_sha256 = super::package::validate_installed_target_desktop_bootstrap()?;
        let mut brokered = super::session_broker::request_holder(
            &bootstrap_job,
            target_envelope.session_id,
            &pipe_name,
            &nonce,
        )?;
        let mut broker_control = brokered
            .control
            .take()
            .ok_or_else(|| "session broker control lease is absent".to_owned())?;
        let bootstrap_process = brokered.process;
        let bootstrap_thread = brokered.thread;
        if !bootstrap_job.contains(bootstrap_process.raw())? {
            return Err("target desktop bootstrap is absent from its atomic Job"
                .to_owned()
                .into());
        }
        let observed_holder_snapshot = brokered.query;
        let broker_source_snapshot = brokered.broker_source;
        let holder_launch_snapshot = brokered.holder_effective;
        let holder_assignment = super::token::require_assigned_process_authority(
            "session-broker-holder-to-process",
            &holder_launch_snapshot,
            &observed_holder_snapshot,
        )?;
        let holder_envelope = observed_holder_snapshot.behavior.envelope.clone();
        let bootstrap_identity = brokered.identity;
        verify_image_path(bootstrap_process.raw(), &executable)?;
        let launcher_process_handle = duplicate_remote_process_query(
            unsafe { GetCurrentProcess() },
            bootstrap_process.raw(),
        )?;
        let launcher_token_handle =
            duplicate_remote_token_query(launcher_token.raw(), bootstrap_process.raw())?;
        let target_token_handle =
            duplicate_remote_target_token_capability(token, bootstrap_process.raw())?;
        let binding = TargetDesktopBootstrapBindingV3 {
            schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
            role: TargetDesktopBootstrapRoleV1::Holder,
            target_user_object_policy_role: policy_role,
            nonce,
            binding_sha256: String::new(),
            bootstrap_image_sha256: bootstrap_image_sha256.clone(),
            launcher_identity: launcher_identity.clone(),
            launcher_session_id: launcher_envelope.session_id,
            launcher_envelope: launcher_envelope.clone(),
            launcher_process_snapshot: launcher_snapshot.clone(),
            broker_source_snapshot: broker_source_snapshot.clone(),
            holder_launch_snapshot: holder_launch_snapshot.clone(),
            holder_assignment: holder_assignment.clone(),
            bootstrap_identity: bootstrap_identity.clone(),
            bootstrap_envelope: holder_envelope.clone(),
            bootstrap_process_snapshot: observed_holder_snapshot.clone(),
            bootstrap_assignment: holder_assignment,
            holder_process_snapshot: observed_holder_snapshot.clone(),
            target_envelope: target_envelope.clone(),
            target_request_snapshot: target_snapshot.clone(),
        }
        .seal()?;
        if unsafe { ResumeThread(bootstrap_thread.raw()) } != 1 {
            return Err(format!(
                "target desktop bootstrap primary thread did not resume exactly once: {}",
                io::Error::last_os_error()
            )
            .into());
        }
        drop(bootstrap_thread);
        let connection = super::pipe::accept_target_desktop_bootstrap_pipe(
            prepared_pipe,
            bootstrap_process.raw(),
            deadline,
        )
        .map_err(|error| {
            launch_context.accept_error(
                TargetDesktopBootstrapRoleV1::Holder,
                bootstrap_identity.process_id,
                &bootstrap_image_sha256,
                "empty-default-selection",
                "loader_control=not-run association_preflight=not-run",
                error,
            )
        })?;
        authenticate_target_desktop_bootstrap_client(
            connection.raw(),
            bootstrap_process.raw(),
            &bootstrap_job,
            &bootstrap_identity,
            &holder_envelope,
            &observed_holder_snapshot,
            &executable,
        )?;
        let loader_ready: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
            connection.raw(),
            Some(bootstrap_process.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
        )?;
        match loader_ready {
            TargetDesktopBootstrapMessageV1::LoaderReady {
                schema_version,
                nonce: observed_nonce,
                expected_desktop: observed_desktop,
                observed_desktop_binding,
                bootstrap_identity: observed_identity,
                process_envelope: observed_envelope,
                process_snapshot: observed_snapshot,
            } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                && observed_nonce == binding.nonce
                && observed_desktop.is_none()
                && observed_desktop_binding.is_none()
                && observed_identity == bootstrap_identity
                && observed_envelope == holder_envelope
                && observed_snapshot == observed_holder_snapshot => {}
            _ => {
                return Err("target desktop bootstrap LoaderReady frame is invalid"
                    .to_owned()
                    .into());
            }
        }
        super::pipe::write_frame_bounded(
            connection.raw(),
            Some(bootstrap_process.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::AdmissionWrite,
            &TargetDesktopBootstrapMessageV1::Admission {
                binding: binding.clone(),
                launcher_process_query_handle: launcher_process_handle,
                launcher_token_query_handle: launcher_token_handle,
                target_token_capability_handle: Some(target_token_handle),
            },
        )?;
        let frame = read_target_desktop_bootstrap_attestation(
            connection.raw(),
            bootstrap_process.raw(),
            Instant::now() + Duration::from_secs(30),
            &binding,
            Some(&mut broker_control),
        )?;
        if frame.schema_version != TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
            || frame.bootstrap_identity != bootstrap_identity
            || frame.target_envelope != target_envelope
            || frame.target_envelope.session_id != target_envelope.session_id
            || frame.window_station_policy_sha256 != expected_window_station_policy_sha256
            || frame.desktop_policy_sha256 != expected_desktop_policy_sha256
            || !frame.source_objects_unmodified
            || !frame.private_station_assigned
            || !frame.private_desktop_assigned
            || !frame.desktop_containment_verified
            || !frame.window_station_policy_verified
            || !frame.desktop_policy_verified
            || !frame.window_station_not_inheritable
            || !frame.desktop_not_inheritable
            || !frame.noninteractive
        {
            return Err(
                "target desktop bootstrap attestation is incomplete or mismatched"
                    .to_owned()
                    .into(),
            );
        }
        validate_target_desktop_binding(&frame.window_station_name, &frame.desktop_name)?;
        broker_control.finish(&binding.binding_sha256)?;
        let exact_name = format!("{}\\{}", frame.window_station_name, frame.desktop_name);
        let mut startup_name = exact_name.encode_utf16().collect::<Vec<_>>();
        startup_name.push(0);
        let mut lease = Self {
            bootstrap_process,
            bootstrap_job,
            connection_lease: Some(connection),
            bootstrap_identity,
            holder_envelope,
            broker_source_snapshot,
            holder_launch_snapshot,
            holder_process_snapshot: observed_holder_snapshot,
            holder_binding: binding,
            window_station_name: frame.window_station_name,
            desktop_name: frame.desktop_name,
            window_station_policy_sha256: frame.window_station_policy_sha256,
            desktop_policy_sha256: frame.desktop_policy_sha256,
            window_station_live_equality_sha256: frame.window_station_live_equality_sha256,
            desktop_live_equality_sha256: frame.desktop_live_equality_sha256,
            exact_name,
            startup_name,
            loader_qualification: None,
        };
        lease.attest_live()?;
        let loader_ready_qualification = launch_target_desktop_probe(
            token,
            &target_envelope,
            &launcher_token,
            &launcher_envelope,
            &launcher_snapshot,
            &lease.broker_source_snapshot,
            &lease.holder_launch_snapshot,
            &lease.holder_process_snapshot,
            &target_snapshot,
            &launcher_identity,
            policy_role,
            &lease.exact_name,
            &expected_window_station_policy_sha256,
            &expected_desktop_policy_sha256,
            &launch_context,
            &lease,
        )?;
        lease.loader_qualification = Some(loader_ready_qualification.to_wire());
        lease.attest_live().map_err(|detail| {
            let mut error = TargetDesktopLeaseCreateError::from(detail);
            error.loader_qualification = lease.loader_qualification.clone();
            error
        })?;
        Ok(lease)
    }

    pub(super) fn attest_live(&self) -> Result<(), String> {
        validate_target_desktop_binding(&self.window_station_name, &self.desktop_name)?;
        if self.broker_source_snapshot.lineage.user_sid != "S-1-5-18"
            || self.broker_source_snapshot.lineage.session_id != 0
            || self.broker_source_snapshot.behavior.token_is_restricted
            || !self
                .broker_source_snapshot
                .behavior
                .restricting_sids
                .is_empty()
        {
            return Err("retained session-broker source evidence is invalid".to_owned());
        }
        if unsafe { WaitForSingleObject(self.bootstrap_process.raw(), 0) } != WAIT_TIMEOUT {
            return Err(
                "target desktop bootstrap exited while its desktop lease was live".to_owned(),
            );
        }
        if process_identity(self.bootstrap_process.raw())? != self.bootstrap_identity {
            return Err("target desktop bootstrap process identity changed".to_owned());
        }
        let observed = super::token::process_token_query_attestation(self.bootstrap_process.raw())?;
        super::token::require_same_process_token_query(
            "holder-process-live",
            &self.holder_process_snapshot,
            &observed,
        )
        .map_err(|error| error.to_string())?;
        if observed.behavior.envelope != self.holder_envelope {
            return Err("target desktop holder token envelope changed".to_owned());
        }
        super::token::require_assigned_process_authority(
            "holder-launch-to-live-process",
            &self.holder_launch_snapshot,
            &observed,
        )
        .map_err(|error| error.to_string())?;
        if !self.bootstrap_job.contains(self.bootstrap_process.raw())? {
            return Err("target desktop bootstrap left its atomic Job".to_owned());
        }
        let connection = self
            .connection_lease
            .as_ref()
            .ok_or_else(|| "target desktop bootstrap connection lease is absent".to_owned())?;
        let (pipe_pid, pipe_session_id) =
            target_desktop_bootstrap_client_identity(connection.raw())?;
        if pipe_pid != self.bootstrap_identity.process_id
            || pipe_session_id != self.holder_envelope.session_id
        {
            return Err("target desktop bootstrap pipe peer identity changed".to_owned());
        }
        if !super::pipe::target_desktop_bootstrap_pipe_is_quiet(connection.raw())? {
            return Err("target desktop bootstrap sent data after Ready".to_owned());
        }
        Ok(())
    }
}

impl Drop for TargetDesktopLease {
    fn drop(&mut self) {
        drop(self.connection_lease.take());
        if unsafe { WaitForSingleObject(self.bootstrap_process.raw(), 5_000) } == WAIT_TIMEOUT {
            let _ = self
                .bootstrap_job
                .terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS);
            let _ = unsafe { WaitForSingleObject(self.bootstrap_process.raw(), 5_000) };
        }
    }
}

pub(super) fn validate_target_association_preflight_grants(
    window_station_granted_access: u32,
    desktop_granted_access: u32,
    thread_token_absent: bool,
) -> Result<(), String> {
    if window_station_granted_access & super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
        != super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
        || desktop_granted_access & super::security::TARGET_PRIVATE_DESKTOP_ACCESS
            != super::security::TARGET_PRIVATE_DESKTOP_ACCESS
        || !thread_token_absent
    {
        Err(format!(
            "station_requested={:#010x} station_granted={window_station_granted_access:#010x} desktop_requested={:#010x} desktop_granted={desktop_granted_access:#010x} thread_token_absent={thread_token_absent}",
            super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn target_association_preflight_grants_for_test(
    window_station_granted_access: u32,
    desktop_granted_access: u32,
    thread_token_absent: bool,
) -> Result<(), String> {
    validate_target_association_preflight_grants(
        window_station_granted_access,
        desktop_granted_access,
        thread_token_absent,
    )
}

pub(crate) fn target_association_preflight_progress_for_test(
    last_sequence: u32,
    last_stage_ordinal: Option<u32>,
    last_completed: u32,
    last_total: Option<u32>,
    sequence: u32,
    stage_ordinal: u32,
    completed: u32,
    total: Option<u32>,
) -> Result<(), String> {
    let stage = target_association_preflight_stage_from_ordinal(stage_ordinal)?;
    let last_stage = last_stage_ordinal
        .map(target_association_preflight_stage_from_ordinal)
        .transpose()?;
    let mut cursor = AssociationPreflightProgressCursor {
        sequence: last_sequence,
        stage: last_stage,
        completed: last_completed,
        total: last_total,
    };
    cursor
        .advance(sequence, stage, completed, total)
        .map(|_| ())
}

pub(super) fn target_association_preflight_stage_from_ordinal(
    ordinal: u32,
) -> Result<TargetAssociationPreflightStageV1, String> {
    match ordinal {
        0 => Ok(TargetAssociationPreflightStageV1::RetainedNamespaceBefore),
        1 => Ok(TargetAssociationPreflightStageV1::SourceBootstrap),
        2 => Ok(TargetAssociationPreflightStageV1::SourceSystemAncestry),
        3 => Ok(TargetAssociationPreflightStageV1::SourceLoaderGraph),
        4 => Ok(TargetAssociationPreflightStageV1::SourceKnownDlls),
        5 => Ok(TargetAssociationPreflightStageV1::TargetTokenInstallation),
        6 => Ok(TargetAssociationPreflightStageV1::TargetWindowStation),
        7 => Ok(TargetAssociationPreflightStageV1::TargetDesktop),
        8 => Ok(TargetAssociationPreflightStageV1::TargetBootstrap),
        9 => Ok(TargetAssociationPreflightStageV1::TargetKnownDlls),
        10 => Ok(TargetAssociationPreflightStageV1::TargetModules),
        11 => Ok(TargetAssociationPreflightStageV1::RevertAndFinalization),
        _ => Err(format!(
            "association-preflight stage ordinal is unknown: {ordinal}"
        )),
    }
}

pub(super) fn request_holder_target_association_preflight(
    holder_lease: &TargetDesktopLease,
    expected_target_snapshot: &super::token::TokenAttestationSnapshot,
    expected_station_policy_sha256: &str,
    expected_desktop_policy_sha256: &str,
) -> Result<TargetUserObjectOpenPreflightV1, TargetDesktopLeaseCreateError> {
    let connection = holder_lease
        .connection_lease
        .as_ref()
        .ok_or_else(|| "target desktop holder connection lease is absent".to_owned())?;
    let started = Instant::now();
    let overall_deadline = started + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT;
    let mut progress = AssociationPreflightProgressCursor::default();
    let result = (|| {
        super::pipe::write_frame_bounded(
            connection.raw(),
            Some(holder_lease.bootstrap_process.raw()),
            (Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(overall_deadline),
            super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightWrite,
            &TargetDesktopBootstrapMessageV1::AssociationPreflight {
                binding: holder_lease.holder_binding.clone(),
            },
        )?;
        loop {
            let response: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
                connection.raw(),
                Some(holder_lease.bootstrap_process.raw()),
                (Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(overall_deadline),
                super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightReadyRead,
            )?;
            match response {
                TargetDesktopBootstrapMessageV1::AssociationPreflightProgress {
                    binding,
                    sequence,
                    stage,
                    completed,
                    total,
                } if binding == holder_lease.holder_binding => {
                    progress
                        .advance(sequence, stage, completed, total)
                        .map_err(TargetDesktopLeaseCreateError::from)?;
                    continue;
                }
                TargetDesktopBootstrapMessageV1::AssociationPreflightReady {
                    binding,
                    evidence,
                } if binding == holder_lease.holder_binding => {
                    if !progress.is_terminal() {
                        return Err(TargetDesktopLeaseCreateError::from(
                            "target desktop holder association-preflight Ready arrived before final progress"
                                .to_owned(),
                        ));
                    }
                    validate_target_association_preflight_grants(
                        evidence.window_station_granted_access,
                        evidence.desktop_granted_access,
                        evidence.thread_token_absent,
                    )
                    .map_err(|detail| {
                        TargetDesktopLeaseCreateError::from(format!(
                            "holder target-association preflight access evidence is incomplete: {detail}"
                        ))
                    })?;
                    if evidence.window_station_policy_sha256 != expected_station_policy_sha256
                        || evidence.desktop_policy_sha256 != expected_desktop_policy_sha256
                        || evidence.window_station_policy_sha256
                            != holder_lease.window_station_policy_sha256
                        || evidence.desktop_policy_sha256 != holder_lease.desktop_policy_sha256
                        || evidence.window_station_live_equality_sha256
                            != holder_lease.window_station_live_equality_sha256
                        || evidence.desktop_live_equality_sha256
                            != holder_lease.desktop_live_equality_sha256
                        || !evidence.window_station_policy_verified_after_open
                        || !evidence.desktop_policy_verified_after_open
                        || !evidence.creator_live_baselines_unchanged
                    {
                        return Err(TargetDesktopLeaseCreateError::from(
                            "holder target-association preflight policy or live-equality evidence is incomplete"
                                .to_owned(),
                        ));
                    }
                    super::token::require_same_token_instance(
                        "holder-association-preflight-before",
                        expected_target_snapshot,
                        &evidence.target_snapshot_before,
                    )?;
                    super::token::require_same_token_instance(
                        "holder-association-preflight-after",
                        expected_target_snapshot,
                        &evidence.target_snapshot_after,
                    )?;
                    evidence.native_loader_access.validate().map_err(|detail| {
                        TargetDesktopLeaseCreateError::from(format!(
                            "holder native loader access evidence is invalid: {detail}"
                        ))
                    })?;
                    return Ok(*evidence);
                }
                TargetDesktopBootstrapMessageV1::Failed {
                    binding,
                    phase,
                    native_code,
                    detail,
                } => {
                    return Err(validate_target_desktop_bootstrap_failure(
                        "association-preflight",
                        binding,
                        &holder_lease.holder_binding,
                        phase,
                        native_code,
                        detail,
                    ));
                }
                _ => return Err(TargetDesktopLeaseCreateError::from(
                    "target desktop holder association-preflight frame is invalid or out of order"
                        .to_owned(),
                )),
            }
        }
    })();
    match result {
        Ok(evidence) => Ok(evidence),
        Err(mut error) => {
            let cleanup = terminate_and_drain_failed_association_preflight(holder_lease);
            error.detail = format!(
                "{} last_stage={} sequence={} completed={} total={} elapsed_ms={} idle_timeout_ms={} overall_timeout_ms={} {cleanup}",
                error.detail,
                progress
                    .stage
                    .map_or("none", TargetAssociationPreflightStageV1::diagnostic),
                progress.sequence,
                progress.completed,
                progress
                    .total
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                started.elapsed().as_millis(),
                TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT.as_millis(),
                TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT.as_millis(),
            );
            Err(error)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct AssociationPreflightProgressCursor {
    sequence: u32,
    stage: Option<TargetAssociationPreflightStageV1>,
    completed: u32,
    total: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AssociationPreflightProgressTransition {
    StageEntered,
    UnitAdvanced,
    StageClosed,
}

impl AssociationPreflightProgressCursor {
    fn validate_next(
        &self,
        sequence: u32,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) -> Result<AssociationPreflightProgressTransition, String> {
        validate_target_association_preflight_progress(self, sequence, stage, completed, total)
    }

    fn commit(
        &mut self,
        sequence: u32,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) {
        self.sequence = sequence;
        self.stage = Some(stage);
        self.completed = completed;
        self.total = total;
    }

    fn advance(
        &mut self,
        sequence: u32,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) -> Result<AssociationPreflightProgressTransition, String> {
        let transition = self.validate_next(sequence, stage, completed, total)?;
        self.commit(sequence, stage, completed, total);
        Ok(transition)
    }

    fn is_terminal(&self) -> bool {
        self.stage == Some(TargetAssociationPreflightStageV1::RevertAndFinalization)
            && self.completed == 1
            && self.total == Some(1)
    }
}

pub(super) fn validate_target_association_preflight_progress(
    cursor: &AssociationPreflightProgressCursor,
    sequence: u32,
    stage: TargetAssociationPreflightStageV1,
    completed: u32,
    total: Option<u32>,
) -> Result<AssociationPreflightProgressTransition, String> {
    let invalid_reason = if sequence == 0 {
        Some("sequence is zero")
    } else if sequence > TARGET_ASSOCIATION_PREFLIGHT_MAX_PROGRESS_FRAMES {
        Some("sequence exceeds the progress-frame bound")
    } else if cursor.sequence.checked_add(1) != Some(sequence) {
        Some("sequence is not the exact successor")
    } else if total.is_some_and(|total| completed > total) {
        Some("completed exceeds total")
    } else if cursor.stage.is_none()
        && (cursor.sequence != 0 || cursor.completed != 0 || cursor.total.is_some())
    {
        Some("initial progress history is inconsistent")
    } else if cursor.stage.is_some() && cursor.sequence == 0 {
        Some("established progress history has a zero sequence")
    } else if cursor.stage.is_none()
        && stage != TargetAssociationPreflightStageV1::RetainedNamespaceBefore
    {
        Some("first progress stage is not retained-namespace-before")
    } else if cursor.stage.is_none() && completed != 0 {
        Some("first progress stage has a nonzero completed count")
    } else if let Some(last_stage) = cursor.stage {
        if stage == last_stage {
            if cursor.total == Some(cursor.completed) {
                Some("closed stage emitted another frame")
            } else if completed < cursor.completed {
                Some("completed regressed within the stage")
            } else if cursor.total.is_some() && total.is_none() {
                Some("known total became unknown within the stage")
            } else if cursor.total.is_some() && cursor.total != total {
                Some("known total mutated within the stage")
            } else if completed == cursor.completed
                && !(cursor.total.is_none() && total == Some(completed))
            {
                Some("frame carries no meaningful forward progress")
            } else {
                None
            }
        } else if last_stage.successor() != Some(stage) {
            Some("stage is not the exact successor")
        } else if cursor.total != Some(cursor.completed) {
            Some("previous stage has no exact completion frame")
        } else if completed != 0 {
            Some("new stage has a nonzero completed count")
        } else {
            None
        }
    } else {
        None
    };
    if let Some(reason) = invalid_reason {
        return Err(format!(
            "association-preflight progress is invalid: reason={reason} last_sequence={} sequence={sequence} last_stage={} last_completed={} last_total={} stage={} completed={completed} total={}",
            cursor.sequence,
            cursor
                .stage
                .map_or("none", TargetAssociationPreflightStageV1::diagnostic),
            cursor.completed,
            cursor
                .total
                .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
            stage.diagnostic(),
            total.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        ));
    }
    if cursor.stage != Some(stage) {
        Ok(AssociationPreflightProgressTransition::StageEntered)
    } else if completed == cursor.completed {
        Ok(AssociationPreflightProgressTransition::StageClosed)
    } else if total == Some(completed) {
        Ok(AssociationPreflightProgressTransition::StageClosed)
    } else {
        Ok(AssociationPreflightProgressTransition::UnitAdvanced)
    }
}

pub(super) fn terminate_and_drain_failed_association_preflight(
    holder_lease: &TargetDesktopLease,
) -> String {
    let peer_state = match unsafe { WaitForSingleObject(holder_lease.bootstrap_process.raw(), 0) } {
        WAIT_OBJECT_0 => "exited",
        WAIT_TIMEOUT => "live",
        _ => "wait-failed",
    };
    let holder_job = &holder_lease.bootstrap_job;
    let terminate = super::job::Job::terminate(holder_job, TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)
        .map_or_else(|error| format!("error:{error}"), |()| "ok".to_owned());
    let drain = holder_job
        .wait_empty(Instant::now() + Duration::from_secs(5))
        .map_or_else(
            |error| format!("error:{error}"),
            |empty| format!("empty={empty}"),
        );
    format!("peer_state={peer_state} cleanup_terminate={terminate} cleanup_drain={drain}")
}

pub(super) struct SystemEnvironmentBlock(*mut c_void);

impl Drop for SystemEnvironmentBlock {
    fn drop(&mut self) {
        // SAFETY: the pointer is returned by CreateEnvironmentBlock and this
        // owner releases it exactly once after copying its bounded contents.
        unsafe { DestroyEnvironmentBlock(self.0) };
    }
}

pub(super) fn system_environment_entries()
-> Result<BTreeMap<String, Vec<u16>>, TargetDesktopLeaseCreateError> {
    let mut raw = ptr::null_mut();
    // SAFETY: a null token requests the system-only environment, inherit is FALSE, and raw
    // receives an allocation owned by DestroyEnvironmentBlock.
    if unsafe { CreateEnvironmentBlock(&raw mut raw, ptr::null_mut(), 0) } == 0 {
        return Err(format!(
            "CreateEnvironmentBlock failed for canonical loader environment: {}",
            io::Error::last_os_error()
        )
        .into());
    }
    let block = SystemEnvironmentBlock(raw);
    let pointer = block.0.cast::<u16>();
    let mut length = None;
    for index in 0..LOADER_ENVIRONMENT_MAX_UNITS.saturating_sub(1) {
        // SAFETY: CreateEnvironmentBlock returns a double-NUL-terminated Unicode block. Reads are
        // bounded by the native environment limit and stop at the first double NUL.
        let current = unsafe { *pointer.add(index) };
        let next = unsafe { *pointer.add(index + 1) };
        if current == 0 && next == 0 {
            length = Some(index + 2);
            break;
        }
    }
    let length = length.ok_or_else(|| {
        TargetDesktopLeaseCreateError::from(
            "system environment block is not double-NUL terminated within its native bound"
                .to_owned(),
        )
    })?;
    // SAFETY: the preceding bounded scan proved every unit through length is readable and includes
    // the terminal double NUL; the slice is copied before block is released.
    let units = unsafe { std::slice::from_raw_parts(pointer, length) };
    let mut entries = BTreeMap::new();
    let mut start = 0_usize;
    while start + 1 < units.len() && units[start] != 0 {
        let end = units[start..]
            .iter()
            .position(|unit| *unit == 0)
            .map(|offset| start + offset)
            .ok_or_else(|| {
                TargetDesktopLeaseCreateError::from(
                    "system environment entry is unterminated".to_owned(),
                )
            })?;
        let entry = &units[start..end];
        let separator = entry.iter().position(|unit| *unit == b'=' as u16);
        if let Some(separator) = separator.filter(|separator| *separator != 0) {
            let name = String::from_utf16(&entry[..separator]).map_err(|_| {
                TargetDesktopLeaseCreateError::from(
                    "system environment name is not valid UTF-16".to_owned(),
                )
            })?;
            let value = entry[separator + 1..].to_vec();
            if entries.insert(name.to_ascii_uppercase(), value).is_some() {
                return Err(
                    "system environment contains a duplicate case-insensitive key"
                        .to_owned()
                        .into(),
                );
            }
        }
        start = end + 1;
    }
    Ok(entries)
}

pub(super) fn store_production_loader_plan(
    plan: &ProductionLoaderPlan,
) -> Result<(), TargetDesktopLeaseCreateError> {
    let path = super::package::state_root()
        .join("package")
        .join("production-loader-plan-v1.json");
    let staged = path.with_extension("json.new");
    let mut bytes = serde_json::to_vec_pretty(plan)
        .map_err(|error| TargetDesktopLeaseCreateError::from(error.to_string()))?;
    bytes.push(b'\n');
    std::fs::write(&staged, bytes)
        .map_err(|error| TargetDesktopLeaseCreateError::from(error.to_string()))?;
    super::record::replace_atomically(&staged, &path).map_err(TargetDesktopLeaseCreateError::from)
}

pub(super) fn store_production_loader_outcome(
    outcome: &memcordon_core::WindowsLoaderQualificationOutcomeV2,
) -> Result<(), TargetDesktopLeaseCreateError> {
    let path = super::package::state_root()
        .join("package")
        .join("production-loader-result-v2.json");
    let staged = path.with_extension("json.new");
    let mut bytes = serde_json::to_vec_pretty(outcome)
        .map_err(|error| TargetDesktopLeaseCreateError::from(error.to_string()))?;
    bytes.push(b'\n');
    std::fs::write(&staged, bytes)
        .map_err(|error| TargetDesktopLeaseCreateError::from(error.to_string()))?;
    super::record::replace_atomically(&staged, &path).map_err(TargetDesktopLeaseCreateError::from)
}

pub(super) fn launch_target_desktop_loader_control(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    window_station_security_descriptor_sddl: &str,
    desktop_security_descriptor_sddl: &str,
) -> Result<LoaderReadyQualificationV1, TargetDesktopLeaseCreateError> {
    let started = Instant::now();
    let mut result = launch_target_desktop_loader_control_inner(
        target_token,
        target_envelope,
        target_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        window_station_security_descriptor_sddl,
        desktop_security_descriptor_sddl,
    );
    if let Err(error) = &mut result {
        attach_preplan_loader_failure(
            error,
            memcordon_core::WindowsLoaderQualificationStageV2::PlanValidation,
            started,
            exact_desktop,
        );
    }
    result
}

pub(super) fn bounded_utf8_detail(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].to_owned()
}

pub(super) fn attach_preplan_loader_failure(
    error: &mut TargetDesktopLeaseCreateError,
    stage: memcordon_core::WindowsLoaderQualificationStageV2,
    started: Instant,
    identity_seed: &str,
) {
    if error.loader_qualification.is_some() {
        return;
    }
    let native_status = match error.native_status.clone() {
        Some(NativeStatusV1::Win32 { code }) => {
            Some(memcordon_core::WindowsLoaderNativeStatusV1::Win32 { code })
        }
        Some(NativeStatusV1::NtStatus { code }) => {
            Some(memcordon_core::WindowsLoaderNativeStatusV1::NtStatus { code })
        }
        Some(NativeStatusV1::TargetExit { code }) => {
            Some(memcordon_core::WindowsLoaderNativeStatusV1::TargetExit { code })
        }
        Some(NativeStatusV1::Stable { code }) => {
            Some(memcordon_core::WindowsLoaderNativeStatusV1::Stable { code })
        }
        None => error
            .os_code
            .map(|code| memcordon_core::WindowsLoaderNativeStatusV1::Win32 { code: code as u32 }),
    };
    let stable_code = match &native_status {
        Some(memcordon_core::WindowsLoaderNativeStatusV1::Stable { code }) => code.clone(),
        _ => String::from("production-loader-preparation-failed"),
    };
    let mut identity = Vec::new();
    identity.extend_from_slice(identity_seed.as_bytes());
    identity.extend_from_slice(&std::process::id().to_le_bytes());
    identity.extend_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let outcome = memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(
        memcordon_core::WindowsLoaderQualificationFailureV2 {
            schema_version: 2,
            stable_code,
            stage,
            native_status,
            elapsed_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            launch_plan_sha256: None,
            launch_plan_json: None,
            qualification_id: super::record::digest(&identity),
            cleanup: memcordon_core::WindowsLoaderCleanupOutcomeV1 {
                status: memcordon_core::WindowsLoaderCleanupStatusV1::Complete,
                stable_code: None,
            },
            diagnostic_id: None,
            detail: bounded_utf8_detail(
                &error.detail,
                memcordon_windows_launch_core::MAX_FAILURE_DETAIL_BYTES,
            ),
        },
    );
    error.loader_qualification = Some(outcome.clone());
    if let Err(persistence) = store_production_loader_outcome(&outcome) {
        eprintln!(
            "secondary production loader preparation outcome persistence failure: {}",
            persistence.detail
        );
    }
}

struct PackageLoaderProcess {
    native: memcordon_windows_launch_core::SuspendedNativeProcessV1,
    identity: RefCell<Option<WindowsProcessIdentityV1>>,
    snapshot: RefCell<Option<super::token::TokenQueryAttestationSnapshot>>,
    job_empty: Cell<bool>,
}

struct PackageLoaderFactory<'a> {
    target_token: HANDLE,
    job: &'a Job,
    application: &'a [u16],
    command: RefCell<&'a mut PreparedLoaderCommandV1>,
    environment: RefCell<&'a mut PreparedLoaderEnvironmentV1>,
    current_directory: &'a PreparedCurrentDirectoryV1,
    desktop: RefCell<&'a mut [u16]>,
    process_security: &'a NativeSecurityDescriptorV1,
    thread_security: &'a NativeSecurityDescriptorV1,
}

impl SuspendedProcessFactory for PackageLoaderFactory<'_> {
    type Process = PackageLoaderProcess;

    fn desktop_preflight(&self, _plan: &ProductionLoaderPlan) -> Result<(), ProcessCreateFailure> {
        Ok(())
    }

    fn create(&self, plan: &ProductionLoaderPlan) -> Result<Self::Process, ProcessCreateFailure> {
        let mut command = self.command.borrow_mut();
        let mut environment = self.environment.borrow_mut();
        let mut desktop = self.desktop.borrow_mut();
        let native = create_suspended_in_job(ProductionNativeCreateRequestV1 {
            plan,
            target_token: self.target_token,
            job: self.job.handle(),
            application: self.application,
            command: &mut command,
            environment: &mut environment,
            current_directory: self.current_directory,
            desktop: &mut desktop,
            process_security: Some(self.process_security),
            thread_security: Some(self.thread_security),
        })
        .map_err(|error| ProcessCreateFailure {
            stable_code: error.stable_code.to_owned(),
            native_status: error.win32_error.map(|code| NativeStatusV1::Win32 { code }),
            detail: error.detail,
        })?;
        Ok(PackageLoaderProcess {
            native,
            identity: RefCell::new(None),
            snapshot: RefCell::new(None),
            job_empty: Cell::new(false),
        })
    }

    fn cleanup(&self, _process: &mut Self::Process) -> CleanupOutcomeV1 {
        if _process.job_empty.get() {
            return CleanupOutcomeV1::complete();
        }
        let termination = self.job.terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS);
        let drain = self
            .job
            .wait_empty(Instant::now() + Duration::from_secs(30));
        match (termination, drain) {
            (Ok(()), Ok(true)) => CleanupOutcomeV1::complete(),
            (Err(_), Err(_)) => CleanupOutcomeV1::failed("job-terminate-and-drain-failed"),
            (Err(_), _) => CleanupOutcomeV1::failed("job-terminate-failed"),
            (_, Ok(false)) => CleanupOutcomeV1::failed("job-drain-incomplete"),
            (_, Err(_)) => CleanupOutcomeV1::failed("job-drain-failed"),
        }
    }
}

fn package_process_failure(
    stable_code: impl Into<String>,
    error: TargetDesktopLeaseCreateError,
) -> ProcessCreateFailure {
    ProcessCreateFailure {
        stable_code: stable_code.into(),
        native_status: error.native_status.or_else(|| {
            error
                .os_code
                .map(|code| NativeStatusV1::Win32 { code: code as u32 })
        }),
        detail: error.detail,
    }
}

struct PackageLoaderAttestor<'a> {
    target_token: HANDLE,
    target_envelope: &'a WindowsCallerTokenEnvelopeV1,
    target_snapshot: &'a super::token::TokenAttestationSnapshot,
    target_source_before: &'a super::token::TokenAttestationSnapshot,
    process_security: &'a SecurityDescriptor,
    thread_security: &'a SecurityDescriptor,
    executable: &'a Path,
}

impl SuspendedProcessAttestor<PackageLoaderProcess> for PackageLoaderAttestor<'_> {
    fn attest(
        &self,
        process: &PackageLoaderProcess,
        plan: &ProductionLoaderPlan,
    ) -> Result<SuspendedProcessEvidenceV1, ProcessCreateFailure> {
        self.process_security
            .verify_kernel_object(
                process.native.process_handle(),
                super::security::SecurityObjectKind::Process,
            )
            .map_err(|detail| {
                package_process_failure(
                    "loader-control-process-security-readback",
                    TargetDesktopLeaseCreateError::from(detail),
                )
            })?;
        self.thread_security
            .verify_kernel_object(
                process.native.thread_handle(),
                super::security::SecurityObjectKind::Thread,
            )
            .map_err(|detail| {
                package_process_failure(
                    "loader-control-thread-security-readback",
                    TargetDesktopLeaseCreateError::from(detail),
                )
            })?;
        let observed =
            super::token::process_token_query_attestation(process.native.process_handle())
                .map_err(|detail| {
                    package_process_failure(
                        "loader-control-token-readback",
                        TargetDesktopLeaseCreateError::from(detail),
                    )
                })?;
        let target_source_after = super::token::token_attestation_snapshot(self.target_token)
            .map_err(|detail| {
                package_process_failure(
                    "loader-control-source-token-readback",
                    TargetDesktopLeaseCreateError::from(detail),
                )
            })?;
        super::token::require_same_token_instance(
            "loader-control-target-request-invariance",
            self.target_source_before,
            &target_source_after,
        )
        .map_err(|error| {
            package_process_failure(
                "loader-control-source-token-changed",
                TargetDesktopLeaseCreateError::from(error.to_string()),
            )
        })?;
        super::token::require_assigned_process_authority(
            "target-request-to-loader-control-process",
            self.target_source_before,
            &observed,
        )
        .map_err(|error| {
            package_process_failure(
                "loader-control-token-authority",
                TargetDesktopLeaseCreateError::from(error.to_string()),
            )
        })?;
        if observed.behavior.envelope != *self.target_envelope {
            return Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-token-envelope-changed"),
                native_status: None,
                detail: String::from("loader-control token envelope changed"),
            });
        }
        let identity = process_identity(process.native.process_handle()).map_err(|detail| {
            package_process_failure(
                "loader-control-process-identity",
                TargetDesktopLeaseCreateError::from(detail),
            )
        })?;
        verify_image_path(process.native.process_handle(), self.executable).map_err(|detail| {
            package_process_failure(
                "loader-control-image-readback",
                TargetDesktopLeaseCreateError::from(detail),
            )
        })?;
        let target_pre_resume = super::token::token_attestation_snapshot(self.target_token)
            .map_err(|detail| {
                package_process_failure(
                    "loader-control-pre-resume-token-readback",
                    TargetDesktopLeaseCreateError::from(detail),
                )
            })?;
        super::token::require_same_token_instance(
            "loader-control-target-request-pre-resume",
            self.target_snapshot,
            &target_pre_resume,
        )
        .map_err(|error| {
            package_process_failure(
                "loader-control-pre-resume-token-changed",
                TargetDesktopLeaseCreateError::from(error.to_string()),
            )
        })?;
        let handle_count = memcordon_windows_launch_core::query_process_handle_count(
            &process.native,
        )
        .map_err(|error| ProcessCreateFailure {
            stable_code: String::from(error.stable_code),
            native_status: error.win32_error.map(|code| NativeStatusV1::Win32 { code }),
            detail: error.detail,
        })?;
        if handle_count != plan.inherited_handles().roles().len() {
            return Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-inherited-handle-mismatch"),
                native_status: None,
                detail: format!(
                    "suspended loader-control handle table contains {handle_count} handles; expected {}",
                    plan.inherited_handles().roles().len()
                ),
            });
        }
        let token_envelope_sha256 =
            memcordon_windows_launch_core::token_envelope_sha256(&observed.behavior.envelope)
                .map_err(|detail| ProcessCreateFailure {
                    stable_code: String::from("loader-control-token-envelope-digest"),
                    native_status: None,
                    detail,
                })?;
        process.identity.replace(Some(identity));
        process.snapshot.replace(Some(observed));
        Ok(SuspendedProcessEvidenceV1 {
            image_sha256: String::from(plan.executable_sha256()),
            token_envelope_sha256,
            job_membership_attested: true,
            desktop_binding_attested: true,
            exact_handle_list_attested: true,
        })
    }
}

struct PackageLoaderChannel<'a> {
    prepared_pipe: RefCell<Option<OwnedHandle>>,
    launch_context: &'a TargetDesktopBootstrapLaunchContext,
    control_job: &'a Job,
    target_envelope: &'a WindowsCallerTokenEnvelopeV1,
    executable: &'a Path,
    nonce: &'a str,
    exact_desktop: &'a str,
}

impl LoaderReadyChannel<PackageLoaderProcess> for PackageLoaderChannel<'_> {
    fn resume(
        &self,
        process: &mut PackageLoaderProcess,
        _plan: &ProductionLoaderPlan,
    ) -> Result<(), ProcessCreateFailure> {
        process
            .native
            .resume_once()
            .map_err(|error| ProcessCreateFailure {
                stable_code: String::from("loader-control-resume"),
                native_status: error.win32_error.map(|code| NativeStatusV1::Win32 { code }),
                detail: error.detail,
            })
    }

    fn await_ready(
        &self,
        process: &mut PackageLoaderProcess,
        plan: &ProductionLoaderPlan,
    ) -> Result<memcordon_windows_launch_core::HandshakeOutcomeV1, ProcessCreateFailure> {
        let identity = process
            .identity
            .borrow()
            .clone()
            .ok_or_else(|| ProcessCreateFailure {
                stable_code: String::from("loader-control-identity-missing"),
                native_status: None,
                detail: String::from("suspended attestation did not retain process identity"),
            })?;
        let snapshot = process
            .snapshot
            .borrow()
            .clone()
            .ok_or_else(|| ProcessCreateFailure {
                stable_code: String::from("loader-control-token-snapshot-missing"),
                native_status: None,
                detail: String::from("suspended attestation did not retain token snapshot"),
            })?;
        let prepared_pipe =
            self.prepared_pipe
                .borrow_mut()
                .take()
                .ok_or_else(|| ProcessCreateFailure {
                    stable_code: String::from("loader-control-pipe-already-consumed"),
                    native_status: None,
                    detail: String::from("loader-ready pipe was consumed more than once"),
                })?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let connection = super::pipe::accept_target_desktop_bootstrap_pipe(
            prepared_pipe,
            process.native.process_handle(),
            deadline,
        )
        .map_err(|error| {
            let error = self.launch_context.accept_error(
                TargetDesktopBootstrapRoleV1::LoaderControl,
                identity.process_id,
                plan.executable_sha256(),
                plan.desktop().security_descriptor_sha256.as_str(),
                "unobserved-production-loader-control",
                error,
            );
            package_process_failure("loader-control-pipe-accept", error)
        })?;
        authenticate_target_desktop_bootstrap_client(
            connection.raw(),
            process.native.process_handle(),
            self.control_job,
            &identity,
            self.target_envelope,
            &snapshot,
            self.executable,
        )
        .map_err(|detail| {
            package_process_failure(
                "loader-control-client-authentication",
                TargetDesktopLeaseCreateError::from(detail),
            )
        })?;
        let loader_ready: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
            connection.raw(),
            Some(process.native.process_handle()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
        )
        .map_err(|detail| {
            package_process_failure(
                "loader-control-ready-read",
                TargetDesktopLeaseCreateError::from(detail),
            )
        })?;
        let desktop_evidence = match loader_ready {
            TargetDesktopBootstrapMessageV1::LoaderReady {
                schema_version,
                nonce: observed_nonce,
                expected_desktop: observed_desktop,
                observed_desktop_binding: Some(observed_desktop_binding),
                bootstrap_identity,
                process_envelope,
                process_snapshot,
            } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                && observed_nonce == self.nonce
                && observed_desktop.as_deref() == Some(self.exact_desktop)
                && bootstrap_identity == identity
                && process_envelope == *self.target_envelope
                && process_snapshot == snapshot =>
            {
                LoaderControlDesktopEvidenceV1::Observed(observed_desktop_binding)
            }
            TargetDesktopBootstrapMessageV1::LoaderReadyFailed {
                schema_version,
                nonce: observed_nonce,
                role: TargetDesktopBootstrapRoleV1::LoaderControl,
                failure,
            } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                && observed_nonce == self.nonce =>
            {
                LoaderControlDesktopEvidenceV1::ReadFailed(failure)
            }
            _ => {
                return Err(ProcessCreateFailure {
                    stable_code: String::from("loader-control-ready-frame-invalid"),
                    native_status: None,
                    detail: String::from("loader-control LoaderReady frame is invalid"),
                });
            }
        };
        validate_loader_control_desktop_evidence(self.exact_desktop, &desktop_evidence)?;
        super::pipe::write_frame_bounded(
            connection.raw(),
            Some(process.native.process_handle()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::LoaderControlReleaseWrite,
            &TargetDesktopBootstrapMessageV1::LoaderControlRelease {
                schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
                nonce: self.nonce.to_owned(),
                expected_desktop: self.exact_desktop.to_owned(),
            },
        )
        .map_err(|detail| {
            package_process_failure(
                "loader-control-release-write",
                TargetDesktopLeaseCreateError::from(detail),
            )
        })?;
        Ok(
            memcordon_windows_launch_core::HandshakeOutcomeV1::Authenticated {
                protocol_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
            },
        )
    }

    fn attest_containment(
        &self,
        process: &PackageLoaderProcess,
        _plan: &ProductionLoaderPlan,
    ) -> Result<(), ProcessCreateFailure> {
        match self.control_job.contains(process.native.process_handle()) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-containment-mismatch"),
                native_status: None,
                detail: String::from("loader-control escaped the production Job"),
            }),
            Err(detail) => Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-containment-readback"),
                native_status: None,
                detail,
            }),
        }
    }

    fn drain_exit(
        &self,
        process: &mut PackageLoaderProcess,
        _plan: &ProductionLoaderPlan,
    ) -> Result<(), ProcessCreateFailure> {
        if unsafe { WaitForSingleObject(process.native.process_handle(), 30_000) } != WAIT_OBJECT_0
        {
            return Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-exit-timeout"),
                native_status: None,
                detail: String::from("loader-control did not exit after release"),
            });
        }
        let mut exit_code = 0_u32;
        if unsafe { GetExitCodeProcess(process.native.process_handle(), &raw mut exit_code) } == 0 {
            let error = io::Error::last_os_error();
            return Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-exit-readback"),
                native_status: error
                    .raw_os_error()
                    .map(|code| NativeStatusV1::Win32 { code: code as u32 }),
                detail: error.to_string(),
            });
        }
        if exit_code != 0 {
            return Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-exit-status"),
                native_status: Some(NativeStatusV1::TargetExit { code: exit_code }),
                detail: format!("loader-control exited unsuccessfully: {exit_code:#010x}"),
            });
        }
        match self
            .control_job
            .wait_empty(Instant::now() + Duration::from_secs(30))
        {
            Ok(true) => {
                process.job_empty.set(true);
                Ok(())
            }
            Ok(false) => Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-job-drain-incomplete"),
                native_status: None,
                detail: String::from("loader-control Job did not become empty"),
            }),
            Err(detail) => Err(ProcessCreateFailure {
                stable_code: String::from("loader-control-job-drain"),
                native_status: None,
                detail,
            }),
        }
    }
}

pub(super) fn launch_target_desktop_loader_control_inner(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    window_station_security_descriptor_sddl: &str,
    desktop_security_descriptor_sddl: &str,
) -> Result<LoaderReadyQualificationV1, TargetDesktopLeaseCreateError> {
    use std::os::windows::ffi::OsStrExt;

    let target_source_before = super::token::token_attestation_snapshot(target_token)?;
    super::token::require_same_token_instance(
        "loader-control-target-request-preflight",
        target_snapshot,
        &target_source_before,
    )?;
    let nonce = target_desktop_nonce()?;
    let qualification_id = super::record::digest(nonce.as_bytes());
    let endpoint = LoaderReadyEndpointV1::new(nonce.clone())
        .map_err(|detail| TargetDesktopLeaseCreateError::from(detail.to_owned()))?;
    let pipe_name = endpoint.name().to_owned();
    let pipe_sddl = super::security::target_desktop_bootstrap_pipe_sddl(target_token)?;
    let pipe_security = SecurityDescriptor::from_sddl(&pipe_sddl)?;
    let prepared_pipe =
        super::pipe::prepare_target_desktop_bootstrap_pipe(&pipe_name, &pipe_security)?;
    clear_inherit(prepared_pipe.raw())?;
    verify_not_inheritable(prepared_pipe.raw())?;
    let control_job = Job::create(None, None, None)?;
    let job_sddl = super::security::launcher_job_sddl()?;
    let process_sddl = super::security::launcher_process_sddl()?;
    let thread_sddl = super::security::launcher_thread_sddl()?;
    let process_security = SecurityDescriptor::from_sddl(&process_sddl)?;
    let thread_security = SecurityDescriptor::from_sddl(&thread_sddl)?;
    let native_process_security = NativeSecurityDescriptorV1::from_sddl(&process_sddl)
        .map_err(|error| TargetDesktopLeaseCreateError::from(error.detail))?;
    let native_thread_security = NativeSecurityDescriptorV1::from_sddl(&thread_sddl)
        .map_err(|error| TargetDesktopLeaseCreateError::from(error.detail))?;
    let executable = super::package::installed_target_desktop_bootstrap();
    let executable_sha256 =
        super::package::validate_installed_target_desktop_bootstrap_loader_control()?;
    let application_units = executable.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut application = application_units.clone();
    application.push(0);
    let mut command = PreparedLoaderCommandV1::loader_control(
        &application_units,
        &endpoint,
        &exact_desktop.encode_utf16().collect::<Vec<_>>(),
    )
    .map_err(|detail| TargetDesktopLeaseCreateError::from(detail.to_owned()))?;
    let system_environment = system_environment_entries()?;
    let required_environment = LOADER_REQUIRED_ENVIRONMENT_KEYS.map(|key| {
        system_environment
            .get(&key.to_ascii_uppercase())
            .cloned()
            .ok_or_else(|| {
                TargetDesktopLeaseCreateError::from(format!(
                    "canonical loader environment is missing required system variable {key}"
                ))
            })
    });
    let [system_drive, system_root, windir] = required_environment;
    let mut prepared_environment = PreparedLoaderEnvironmentV1::canonical_minimal_system([
        system_drive?,
        system_root?,
        windir?,
    ])
    .map_err(|detail| TargetDesktopLeaseCreateError::from(detail.to_owned()))?;
    let current_directory = super::package::install_root();
    let current_directory =
        PreparedCurrentDirectoryV1::new(current_directory.as_os_str().encode_wide().collect())
            .map_err(|detail| TargetDesktopLeaseCreateError::from(detail.to_owned()))?;
    let mut loader_control_desktop = exact_desktop.encode_utf16().collect::<Vec<_>>();
    loader_control_desktop.push(0);

    let target_envelope_sha256 =
        memcordon_windows_launch_core::token_envelope_sha256(target_envelope)
            .map_err(TargetDesktopLeaseCreateError::from)?;
    let production = build_package_loader_plan(ProductionLoaderPlanInputV1 {
        executable_path_utf16: executable.as_os_str().encode_wide().collect(),
        executable_sha256,
        command_line_sha256: String::from(command.semantic_sha256()),
        environment: prepared_environment.identity().clone(),
        current_directory_sha256: String::from(current_directory.sha256()),
        desktop: DesktopBindingV1 {
            exact_name: exact_desktop.to_owned(),
            security_descriptor_sha256: association_preflight.desktop_live_equality_sha256.clone(),
            window_station_security_descriptor_sddl: window_station_security_descriptor_sddl
                .to_owned(),
            desktop_security_descriptor_sddl: desktop_security_descriptor_sddl.to_owned(),
        },
        process_security_descriptor_sddl: process_sddl,
        thread_security_descriptor_sddl: thread_sddl,
        job_security_descriptor_sddl: job_sddl,
        loader_ready_pipe_security_descriptor_sddl: pipe_sddl,
        target_token: TargetTokenIdentityV1 {
            envelope_sha256: target_envelope_sha256,
            authentication_id: target_envelope.authentication_id,
            session_id: target_envelope.session_id,
        },
        inherited_handles: ExactHandleListV1::none(),
        job_at_creation: true,
    })
    .map_err(|error| TargetDesktopLeaseCreateError::from(error.to_string()))?;
    if let Err(error) = store_production_loader_plan(&production) {
        eprintln!(
            "secondary production loader plan artifact persistence failure: {}",
            error.detail
        );
    }
    let factory = PackageLoaderFactory {
        target_token,
        job: &control_job,
        application: &application,
        command: RefCell::new(&mut command),
        environment: RefCell::new(&mut prepared_environment),
        current_directory: &current_directory,
        desktop: RefCell::new(&mut loader_control_desktop),
        process_security: &native_process_security,
        thread_security: &native_thread_security,
    };
    let attestor = PackageLoaderAttestor {
        target_token,
        target_envelope,
        target_snapshot,
        target_source_before: &target_source_before,
        process_security: &process_security,
        thread_security: &thread_security,
        executable: &executable,
    };
    let channel = PackageLoaderChannel {
        prepared_pipe: RefCell::new(Some(prepared_pipe)),
        launch_context,
        control_job: &control_job,
        target_envelope,
        executable: &executable,
        nonce: &nonce,
        exact_desktop,
    };
    let outcome = ProductionQualificationDriver::new(factory, attestor, channel)
        .qualify(&production, &qualification_id);
    let mut result = match &outcome {
        LaunchQualificationOutcomeV2::Ready(evidence) => Ok(evidence.clone()),
        LaunchQualificationOutcomeV2::Failed(failure) => {
            let (loader_phase, native_status, os_code) = match failure.stage {
                LaunchQualificationStageV2::PlanValidation
                | LaunchQualificationStageV2::DesktopPreflight => {
                    (LoaderLaunchFailurePhaseV1::PreCreate, None, None)
                }
                LaunchQualificationStageV2::ProcessCreate => (
                    LoaderLaunchFailurePhaseV1::CreateProcessReturn,
                    failure
                        .win32_error
                        .map(|code| NativeStatusV1::Win32 { code }),
                    failure.win32_error.map(|code| code as i32),
                ),
                LaunchQualificationStageV2::SuspendedAttestation => (
                    LoaderLaunchFailurePhaseV1::PreResumeAttestation,
                    failure
                        .win32_error
                        .map(|code| NativeStatusV1::Win32 { code }),
                    failure.win32_error.map(|code| code as i32),
                ),
                LaunchQualificationStageV2::Resume => (
                    LoaderLaunchFailurePhaseV1::Resume,
                    failure
                        .win32_error
                        .map(|code| NativeStatusV1::Win32 { code }),
                    failure.win32_error.map(|code| code as i32),
                ),
                LaunchQualificationStageV2::LoaderReadyHandshake => (
                    LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
                    failure
                        .win32_error
                        .map(|code| NativeStatusV1::Win32 { code }),
                    failure.win32_error.map(|code| code as i32),
                ),
                LaunchQualificationStageV2::ContainmentReadback => (
                    LoaderLaunchFailurePhaseV1::PostLoaderReadyContainment,
                    failure
                        .win32_error
                        .map(|code| NativeStatusV1::Win32 { code }),
                    failure.win32_error.map(|code| code as i32),
                ),
                LaunchQualificationStageV2::ExitDrain => (
                    LoaderLaunchFailurePhaseV1::ExitDrain,
                    failure
                        .target_exit_code
                        .map(|code| NativeStatusV1::TargetExit { code })
                        .or_else(|| {
                            failure
                                .win32_error
                                .map(|code| NativeStatusV1::Win32 { code })
                        }),
                    failure
                        .target_exit_code
                        .or(failure.win32_error)
                        .map(|code| code as i32),
                ),
            };
            Err(TargetDesktopLeaseCreateError {
                detail: failure.detail.clone(),
                os_code,
                loader_phase,
                native_status: native_status.or_else(|| {
                    Some(NativeStatusV1::Stable {
                        code: failure.stable_code.clone(),
                    })
                }),
                loader_qualification: None,
            })
        }
    };
    let plan_json = serde_json::to_string(&production)
        .map_err(|error| TargetDesktopLeaseCreateError::from(error.to_string()))?;
    let mut wire_outcome = outcome.to_wire();
    wire_outcome.set_launch_plan_json(plan_json.clone());
    if !wire_outcome.is_consistent() {
        return Err(TargetDesktopLeaseCreateError::from(
            "production loader outcome and serialized plan are inconsistent".to_owned(),
        ));
    }
    if let Err(primary) = &mut result {
        primary.loader_qualification = Some(wire_outcome.clone());
    }
    let mut persisted_outcome = wire_outcome.clone();
    persisted_outcome.clear_launch_plan_json();
    if let Err(error) = store_production_loader_outcome(&persisted_outcome) {
        eprintln!(
            "secondary production loader outcome artifact persistence failure: {}",
            error.detail
        );
    }
    result.map(|evidence| LoaderReadyQualificationV1 {
        evidence,
        plan_json,
    })
}

#[cfg(test)]
pub(crate) const fn production_loader_creation_flags_for_test() -> u32 {
    ProductionLoaderPlan::CREATION_FLAGS
}

#[allow(clippy::too_many_arguments)]
pub(super) fn launch_target_desktop_probe(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    launcher_token: &OwnedHandle,
    launcher_envelope: &WindowsCallerTokenEnvelopeV1,
    launcher_process_snapshot: &super::token::TokenAttestationSnapshot,
    broker_source_snapshot: &super::token::TokenAttestationSnapshot,
    holder_launch_snapshot: &super::token::TokenAttestationSnapshot,
    holder_process_snapshot: &super::token::TokenQueryAttestationSnapshot,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    launcher_identity: &WindowsProcessIdentityV1,
    policy_role: super::security::TargetUserObjectPolicyRoleV1,
    exact_desktop: &str,
    expected_station_policy_sha256: &str,
    expected_desktop_policy_sha256: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    holder_lease: &TargetDesktopLease,
) -> Result<LoaderReadyQualificationV1, TargetDesktopLeaseCreateError> {
    let preflight_started = Instant::now();
    let preflight = (|| {
        let target_source_before = super::token::token_attestation_snapshot(target_token)?;
        super::token::require_same_token_instance(
            "probe-target-request-preflight",
            target_snapshot,
            &target_source_before,
        )?;
        holder_lease
            .attest_live()
            .map_err(TargetDesktopLeaseCreateError::from)?;
        let association_preflight = request_holder_target_association_preflight(
            holder_lease,
            target_snapshot,
            expected_station_policy_sha256,
            expected_desktop_policy_sha256,
        )?;
        holder_lease
            .attest_live()
            .map_err(TargetDesktopLeaseCreateError::from)?;
        let target_user_object_policy =
            super::security::target_user_object_policy(target_token, policy_role)?;
        Ok((
            target_source_before,
            association_preflight,
            target_user_object_policy,
        ))
    })();
    let (target_source_before, association_preflight, target_user_object_policy) = match preflight {
        Ok(preflight) => preflight,
        Err(mut error) => {
            attach_preplan_loader_failure(
                &mut error,
                memcordon_core::WindowsLoaderQualificationStageV2::DesktopPreflight,
                preflight_started,
                exact_desktop,
            );
            return Err(error);
        }
    };
    let loader_ready_qualification = launch_target_desktop_loader_control(
        target_token,
        target_envelope,
        target_snapshot,
        exact_desktop,
        launch_context,
        &association_preflight,
        &target_user_object_policy.window_station_sddl(),
        &target_user_object_policy.desktop_sddl(),
    )?;
    let probe_result = (|| -> Result<(), TargetDesktopLeaseCreateError> {
        holder_lease
            .attest_live()
            .map_err(TargetDesktopLeaseCreateError::from)?;
        let nonce = target_desktop_nonce()?;
        let pipe_name = format!(
            "{}{}",
            super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
            nonce,
        );
        let pipe_security = SecurityDescriptor::from_sddl(
            &super::security::target_desktop_bootstrap_pipe_sddl(target_token)?,
        )?;
        let prepared_pipe =
            super::pipe::prepare_target_desktop_bootstrap_pipe(&pipe_name, &pipe_security)?;
        clear_inherit(prepared_pipe.raw())?;
        verify_not_inheritable(prepared_pipe.raw())?;
        let probe_job = Job::create(None, None, None)?;
        let jobs = [probe_job.handle()];
        let attributes = AttributeList::new(
            &[Attribute::new(
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                std::mem::size_of_val(&jobs),
            )],
            None,
        )?;
        let process_security =
            SecurityDescriptor::from_sddl(&super::security::launcher_process_sddl()?)?;
        let process_attributes = process_security.attributes(false);
        let thread_security =
            SecurityDescriptor::from_sddl(&super::security::launcher_thread_sddl()?)?;
        let thread_attributes = thread_security.attributes(false);
        let executable = super::package::installed_target_desktop_bootstrap();
        let bootstrap_image_sha256 = super::package::validate_installed_target_desktop_bootstrap()?;
        use std::os::windows::ffi::OsStrExt;
        let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
        application.push(0);
        let mut command_line = encode_command_line(&[
            executable.as_os_str().encode_wide().collect(),
            "probe".encode_utf16().collect(),
            pipe_name.encode_utf16().collect(),
            nonce.encode_utf16().collect(),
            exact_desktop.encode_utf16().collect(),
        ]);
        command_line.push(0);
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        let mut startup_desktop = exact_desktop.encode_utf16().collect::<Vec<_>>();
        startup_desktop.push(0);
        startup.StartupInfo.lpDesktop = startup_desktop.as_mut_ptr();
        startup.lpAttributeList = attributes.raw();
        let mut environment = [0_u16, 0_u16];
        let install_root = super::package::install_root();
        let mut current_directory = install_root.as_os_str().encode_wide().collect::<Vec<_>>();
        current_directory.push(0);
        let mut process = PROCESS_INFORMATION::default();
        if unsafe {
            create_process_as_user_native(
                target_token,
                application.as_ptr(),
                command_line.as_mut_ptr(),
                &raw const process_attributes,
                &raw const thread_attributes,
                0,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_mut_ptr().cast(),
                current_directory.as_ptr(),
                &raw const startup.StartupInfo,
                &raw mut process,
            )
        } == 0
        {
            return Err(format!(
                "CreateProcessAsUserW failed for exact-token desktop probe: {}",
                io::Error::last_os_error(),
            )
            .into());
        }
        let probe_process = OwnedHandle::new(process.hProcess)?;
        let probe_thread = OwnedHandle::new(process.hThread)?;
        if !probe_job.contains(probe_process.raw())? {
            return Err("restricted desktop probe is absent from its atomic Job"
                .to_owned()
                .into());
        }
        process_security.verify_kernel_object(
            probe_process.raw(),
            super::security::SecurityObjectKind::Process,
        )?;
        thread_security.verify_kernel_object(
            probe_thread.raw(),
            super::security::SecurityObjectKind::Thread,
        )?;
        let observed_probe_snapshot =
            super::token::process_token_query_attestation(probe_process.raw())?;
        let target_source_after = super::token::token_attestation_snapshot(target_token)?;
        super::token::require_same_token_instance(
            "probe-target-request-invariance",
            &target_source_before,
            &target_source_after,
        )?;
        let probe_assignment = super::token::require_assigned_process_authority(
            "target-request-to-probe-process",
            &target_source_before,
            &observed_probe_snapshot,
        )?;
        if observed_probe_snapshot.behavior.envelope != *target_envelope {
            return Err("restricted desktop probe token envelope changed"
                .to_owned()
                .into());
        }
        let probe_identity = process_identity(probe_process.raw())?;
        verify_image_path(probe_process.raw(), &executable)?;
        let launcher_process_handle =
            duplicate_remote_process_query(unsafe { GetCurrentProcess() }, probe_process.raw())?;
        let launcher_token_handle =
            duplicate_remote_token_query(launcher_token.raw(), probe_process.raw())?;
        let binding = TargetDesktopBootstrapBindingV3 {
            schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
            role: TargetDesktopBootstrapRoleV1::Probe,
            target_user_object_policy_role: policy_role,
            nonce: nonce.clone(),
            binding_sha256: String::new(),
            bootstrap_image_sha256: bootstrap_image_sha256.clone(),
            launcher_identity: launcher_identity.clone(),
            launcher_session_id: launcher_envelope.session_id,
            launcher_envelope: launcher_envelope.clone(),
            launcher_process_snapshot: launcher_process_snapshot.clone(),
            broker_source_snapshot: broker_source_snapshot.clone(),
            holder_launch_snapshot: holder_launch_snapshot.clone(),
            holder_assignment: super::token::require_assigned_process_authority(
                "holder-launch-to-process",
                holder_launch_snapshot,
                holder_process_snapshot,
            )?,
            bootstrap_identity: probe_identity.clone(),
            bootstrap_envelope: target_envelope.clone(),
            bootstrap_process_snapshot: observed_probe_snapshot.clone(),
            bootstrap_assignment: probe_assignment,
            holder_process_snapshot: holder_process_snapshot.clone(),
            target_envelope: target_envelope.clone(),
            target_request_snapshot: target_snapshot.clone(),
        }
        .seal()?;
        let target_pre_resume = super::token::token_attestation_snapshot(target_token)?;
        super::token::require_same_token_instance(
            "probe-target-request-pre-resume",
            target_snapshot,
            &target_pre_resume,
        )?;
        let deadline = Instant::now() + Duration::from_secs(30);
        if unsafe { ResumeThread(probe_thread.raw()) } != 1 {
            return Err(format!(
                "restricted desktop probe primary thread did not resume exactly once: {}",
                io::Error::last_os_error(),
            )
            .into());
        }
        drop(probe_thread);
        let connection = super::pipe::accept_target_desktop_bootstrap_pipe(
            prepared_pipe,
            probe_process.raw(),
            deadline,
        )
        .map_err(|error| {
            launch_context.accept_error(
                TargetDesktopBootstrapRoleV1::Probe,
                probe_identity.process_id,
                &bootstrap_image_sha256,
                &format!(
                    "nonce-private-sha256:{}",
                    super::record::digest(exact_desktop.as_bytes())
                ),
                &format!(
                    "loader_control=loader-ready loader_control_desktop_sha256={} {}",
                    super::record::digest(exact_desktop.as_bytes()),
                    association_preflight.diagnostic()
                ),
                error,
            )
        })?;
        authenticate_target_desktop_bootstrap_client(
            connection.raw(),
            probe_process.raw(),
            &probe_job,
            &probe_identity,
            target_envelope,
            &observed_probe_snapshot,
            &executable,
        )?;
        let loader_ready: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
            connection.raw(),
            Some(probe_process.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
        )?;
        let (expected_station, expected_desktop) =
            exact_desktop.split_once('\\').ok_or_else(|| {
                TargetDesktopLeaseCreateError::from("probe desktop is not qualified".to_owned())
            })?;
        match loader_ready {
            TargetDesktopBootstrapMessageV1::LoaderReady {
                schema_version,
                nonce: observed_nonce,
                expected_desktop: observed_desktop,
                observed_desktop_binding: Some(observed_desktop_binding),
                bootstrap_identity,
                process_envelope,
                process_snapshot,
            } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                && observed_nonce == nonce
                && observed_desktop.as_deref() == Some(exact_desktop)
                && observed_desktop_binding.window_station_name == expected_station
                && observed_desktop_binding.desktop_name == expected_desktop
                && bootstrap_identity == probe_identity
                && process_envelope == *target_envelope
                && process_snapshot == observed_probe_snapshot => {}
            TargetDesktopBootstrapMessageV1::LoaderReadyFailed {
                schema_version,
                nonce: observed_nonce,
                role: TargetDesktopBootstrapRoleV1::Probe,
                failure,
            } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                && observed_nonce == nonce
                && !failure.detail.is_empty()
                && failure.detail.len() <= TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES =>
            {
                return Err(TargetDesktopLeaseCreateError {
                    detail: failure.detail,
                    os_code: failure.native_code,
                    loader_phase: LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
                    native_status: failure
                        .native_code
                        .map(|code| NativeStatusV1::Win32 { code: code as u32 }),
                    loader_qualification: None,
                });
            }
            _ => {
                return Err("restricted desktop probe LoaderReady frame is invalid"
                    .to_owned()
                    .into());
            }
        }
        super::pipe::write_frame_bounded(
            connection.raw(),
            Some(probe_process.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::AdmissionWrite,
            &TargetDesktopBootstrapMessageV1::Admission {
                binding: binding.clone(),
                launcher_process_query_handle: launcher_process_handle,
                launcher_token_query_handle: launcher_token_handle,
                target_token_capability_handle: None,
            },
        )?;
        let frame = read_target_desktop_bootstrap_attestation(
            connection.raw(),
            probe_process.raw(),
            deadline,
            &binding,
            None,
        )?;
        if frame.bootstrap_identity != probe_identity
            || frame.target_envelope != *target_envelope
            || frame.window_station_name != expected_station
            || frame.desktop_name != expected_desktop
            || frame.window_station_policy_sha256 != expected_station_policy_sha256
            || frame.desktop_policy_sha256 != expected_desktop_policy_sha256
            || frame.window_station_policy_sha256 != holder_lease.window_station_policy_sha256
            || frame.desktop_policy_sha256 != holder_lease.desktop_policy_sha256
            || frame.window_station_live_equality_sha256
                != holder_lease.window_station_live_equality_sha256
            || frame.desktop_live_equality_sha256 != holder_lease.desktop_live_equality_sha256
            || !frame.private_station_assigned
            || !frame.private_desktop_assigned
            || !frame.window_station_policy_verified
            || !frame.desktop_policy_verified
            || !frame.noninteractive
        {
            return Err(
                "restricted desktop probe attestation is incomplete or mismatched"
                    .to_owned()
                    .into(),
            );
        }
        drop(connection);
        if unsafe { WaitForSingleObject(probe_process.raw(), 30_000) } != WAIT_OBJECT_0 {
            return Err("restricted desktop probe did not exit after attestation"
                .to_owned()
                .into());
        }
        let mut exit_code = 0_u32;
        if unsafe { GetExitCodeProcess(probe_process.raw(), &raw mut exit_code) } == 0
            || exit_code != 0
        {
            return Err(format!(
                "restricted desktop probe exited unsuccessfully: {exit_code:#010x}"
            )
            .into());
        }
        if !probe_job.wait_empty(Instant::now() + Duration::from_secs(30))? {
            return Err("restricted desktop probe Job did not become empty"
                .to_owned()
                .into());
        }
        Ok(())
    })();
    match probe_result {
        Ok(()) => Ok(loader_ready_qualification),
        Err(mut error) => {
            error.loader_qualification = Some(loader_ready_qualification.to_wire());
            Err(error)
        }
    }
}

pub(super) fn read_target_desktop_bootstrap_attestation(
    pipe: HANDLE,
    process: HANDLE,
    deadline: Instant,
    expected_binding: &TargetDesktopBootstrapBindingV3,
    mut broker_control: Option<&mut super::session_broker::BrokerControlLease>,
) -> Result<TargetDesktopBootstrapFrameV1, TargetDesktopLeaseCreateError> {
    let first = super::pipe::read_frame_bounded(
        pipe,
        Some(process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::StartedRead,
    )
    .map_err(TargetDesktopLeaseCreateError::from)?;
    match first {
        TargetDesktopBootstrapMessageV1::Failed {
            binding,
            phase,
            native_code,
            detail,
        } => Err(validate_target_desktop_bootstrap_failure(
            "await-started",
            binding,
            expected_binding,
            phase,
            native_code,
            detail,
        )),
        TargetDesktopBootstrapMessageV1::Started {
            binding,
            phase: TargetDesktopBootstrapPhaseV1::EndpointAdmission,
        } if binding == *expected_binding => {
            let mut pending = None;
            let mut completed = 0_u32;
            loop {
                match super::pipe::read_frame_bounded(
                    pipe,
                    Some(process),
                    Instant::now() + Duration::from_secs(30),
                    super::pipe::TargetDesktopBootstrapPipeOperation::TerminalRead,
                )
                .map_err(TargetDesktopLeaseCreateError::from)?
                {
                    TargetDesktopBootstrapMessageV1::Ready {
                        binding,
                        attestation,
                    } if binding == *expected_binding && pending.is_none() => {
                        if broker_control.is_some() && completed != 2 {
                            return Err(TargetDesktopLeaseCreateError::from(
                                "holder published Ready before both broker Cleared proofs"
                                    .to_owned(),
                            ));
                        }
                        return Ok(attestation);
                    }
                    TargetDesktopBootstrapMessageV1::Failed {
                        binding,
                        phase,
                        native_code,
                        detail,
                    } if pending.is_none() => {
                        return Err(validate_target_desktop_bootstrap_failure(
                            "after-started",
                            binding,
                            expected_binding,
                            phase,
                            native_code,
                            detail,
                        ));
                    }
                    TargetDesktopBootstrapMessageV1::CreationReady {
                        binding,
                        phase,
                        ordinal,
                        thread_id,
                        holder_primary,
                    } if binding == *expected_binding
                        && pending.is_none()
                        && target_desktop_creation_transition_is_expected(
                            completed, phase, ordinal, thread_id,
                        )
                        && holder_primary == expected_binding.holder_process_snapshot =>
                    {
                        let control = broker_control.as_deref_mut().ok_or_else(|| {
                            TargetDesktopLeaseCreateError::from(
                                "probe attempted a broker creation-arm transition".to_owned(),
                            )
                        })?;
                        let carrier = control.arm(
                            &expected_binding.binding_sha256,
                            phase,
                            ordinal,
                            thread_id,
                            &holder_primary,
                        )?;
                        super::pipe::write_frame_bounded(
                            pipe,
                            Some(process),
                            Instant::now() + Duration::from_secs(30),
                            super::pipe::TargetDesktopBootstrapPipeOperation::CreationArmedWrite,
                            &TargetDesktopBootstrapMessageV1::CreationArmed {
                                binding: expected_binding.clone(),
                                phase,
                                ordinal,
                                thread_id,
                                carrier,
                            },
                        )?;
                        pending = Some((phase, ordinal, thread_id));
                    }
                    TargetDesktopBootstrapMessageV1::CreationConsumed {
                        binding,
                        phase,
                        ordinal,
                        thread_id,
                        holder_primary,
                        native_code,
                        thread_token_absent,
                    } if binding == *expected_binding
                        && pending == Some((phase, ordinal, thread_id))
                        && holder_primary == expected_binding.holder_process_snapshot =>
                    {
                        let control = broker_control.as_deref_mut().ok_or_else(|| {
                            TargetDesktopLeaseCreateError::from(
                                "probe attempted a broker creation-consume transition".to_owned(),
                            )
                        })?;
                        control.consumed(
                            &expected_binding.binding_sha256,
                            phase,
                            ordinal,
                            thread_id,
                            &holder_primary,
                            native_code,
                            thread_token_absent,
                        )?;
                        super::pipe::write_frame_bounded(
                            pipe,
                            Some(process),
                            Instant::now() + Duration::from_secs(30),
                            super::pipe::TargetDesktopBootstrapPipeOperation::CreationClearedWrite,
                            &TargetDesktopBootstrapMessageV1::CreationCleared {
                                binding: expected_binding.clone(),
                                phase,
                                ordinal,
                                thread_id,
                            },
                        )?;
                        pending = None;
                        completed = ordinal;
                    }
                    _ => {
                        return Err(TargetDesktopLeaseCreateError::from(
                            "target desktop bootstrap frame is invalid or out of order".to_owned(),
                        ));
                    }
                }
            }
        }
        _ => Err(TargetDesktopLeaseCreateError::from(
            "target desktop bootstrap Started frame is invalid or out of order".to_owned(),
        )),
    }
}

pub(super) fn target_desktop_creation_transition_is_expected(
    completed: u32,
    phase: super::session_broker::SessionCreationPhaseV1,
    ordinal: u32,
    thread_id: u32,
) -> bool {
    thread_id != 0
        && matches!(
            (completed, phase, ordinal),
            (
                0,
                super::session_broker::SessionCreationPhaseV1::WindowStation,
                1
            ) | (1, super::session_broker::SessionCreationPhaseV1::Desktop, 2)
        )
}

#[cfg(test)]
pub(crate) fn target_desktop_creation_transition_for_test(
    completed: u32,
    desktop: bool,
    ordinal: u32,
    thread_id: u32,
) -> bool {
    target_desktop_creation_transition_is_expected(
        completed,
        if desktop {
            super::session_broker::SessionCreationPhaseV1::Desktop
        } else {
            super::session_broker::SessionCreationPhaseV1::WindowStation
        },
        ordinal,
        thread_id,
    )
}

pub(super) fn validate_target_desktop_bootstrap_failure(
    state: &'static str,
    binding: TargetDesktopBootstrapBindingV3,
    expected_binding: &TargetDesktopBootstrapBindingV3,
    phase: TargetDesktopBootstrapPhaseV1,
    native_code: Option<i32>,
    detail: String,
) -> TargetDesktopLeaseCreateError {
    validate_target_desktop_bootstrap_failure_evidence(
        state,
        binding == *expected_binding,
        phase,
        native_code,
        detail,
    )
}

pub(super) fn validate_target_desktop_bootstrap_failure_evidence(
    state: &'static str,
    binding_matches: bool,
    phase: TargetDesktopBootstrapPhaseV1,
    native_code: Option<i32>,
    detail: String,
) -> TargetDesktopLeaseCreateError {
    if !binding_matches
        || detail.is_empty()
        || detail.len() > TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES
    {
        return TargetDesktopLeaseCreateError::from(
            "target desktop bootstrap failure frame is invalid".to_owned(),
        );
    }
    TargetDesktopLeaseCreateError {
        detail: format!(
            "target desktop bootstrap rejected: state={state} phase={} native_code={native_code:?} detail={detail}",
            phase.diagnostic(),
        ),
        os_code: native_code,
        loader_phase: LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
        native_status: native_code.map(|code| NativeStatusV1::Win32 { code: code as u32 }),
        loader_qualification: None,
    }
}

#[cfg(test)]
pub(crate) fn target_desktop_bootstrap_failure_transition_for_test(
    state: &'static str,
    binding_matches: bool,
    native_code: Option<i32>,
    detail: String,
) -> (String, Option<i32>) {
    let error = validate_target_desktop_bootstrap_failure_evidence(
        state,
        binding_matches,
        TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
        native_code,
        detail,
    );
    (error.detail, error.os_code)
}

pub(super) fn target_desktop_bootstrap_client_identity(pipe: HANDLE) -> Result<(u32, u32), String> {
    let mut process_id = 0_u32;
    let mut session_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &raw mut process_id) } == 0
        || unsafe { GetNamedPipeClientSessionId(pipe, &raw mut session_id) } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok((process_id, session_id))
}

pub(super) fn authenticate_target_desktop_bootstrap_client(
    pipe: HANDLE,
    process: HANDLE,
    job: &Job,
    expected_identity: &WindowsProcessIdentityV1,
    expected_envelope: &WindowsCallerTokenEnvelopeV1,
    expected_snapshot: &super::token::TokenQueryAttestationSnapshot,
    executable: &Path,
) -> Result<(), String> {
    let before = target_desktop_bootstrap_client_identity(pipe)?;
    if before != (expected_identity.process_id, expected_envelope.session_id)
        || process_identity(process)? != *expected_identity
        || !job.contains(process)?
    {
        return Err("target desktop bootstrap pipe client identity is mismatched".to_owned());
    }
    let token = super::token::process_token(process)?;
    if super::token::envelope(token.raw())? != *expected_envelope
        || super::token::token_query_attestation_snapshot(token.raw())? != *expected_snapshot
    {
        return Err("target desktop bootstrap pipe client token is mismatched".to_owned());
    }
    verify_image_path(process, executable)?;
    if target_desktop_bootstrap_client_identity(pipe)? != before
        || process_identity(process)? != *expected_identity
        || !job.contains(process)?
    {
        return Err(
            "target desktop bootstrap pipe client changed during authentication".to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn validate_target_desktop_binding(
    window_station: &str,
    desktop: &str,
) -> Result<(), String> {
    validate_desktop_binding_names(window_station, desktop)?;
    let nonce = window_station
        .strip_prefix("MemCordonTarget-")
        .ok_or_else(|| "private target window station has the wrong role prefix".to_owned())?;
    if nonce.len() != TARGET_DESKTOP_NONCE_BYTES * 2
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("private target window station nonce is not 256-bit lowercase hex".to_owned());
    }
    if desktop != "Restricted" {
        return Err("private target desktop has the wrong fixed role name".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_target_desktop_input_state(receives_input: bool) -> Result<(), String> {
    if receives_input {
        Err("private target desktop unexpectedly receives interactive input".to_owned())
    } else {
        Ok(())
    }
}

fn observe_current_loader_desktop_binding()
-> Result<LoaderDesktopBindingV1, LoaderDesktopBindingReadFailureV1> {
    let window_station = unsafe { GetProcessWindowStation() };
    if window_station.is_null() {
        return Err(LoaderDesktopBindingReadFailureV1::native(
            LoaderDesktopBindingReadFailureKindV1::WindowStationHandle,
            "read running loader process window station",
        ));
    }
    let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    if desktop.is_null() {
        return Err(LoaderDesktopBindingReadFailureV1::native(
            LoaderDesktopBindingReadFailureKindV1::DesktopHandle,
            "read running loader thread desktop",
        ));
    }
    let window_station_name = user_object_name(window_station).map_err(|error| {
        LoaderDesktopBindingReadFailureV1::from_user_object(
            LoaderDesktopBindingReadFailureKindV1::WindowStationName,
            error,
        )
    })?;
    let desktop_name = user_object_name(desktop).map_err(|error| {
        LoaderDesktopBindingReadFailureV1::from_user_object(
            LoaderDesktopBindingReadFailureKindV1::DesktopName,
            error,
        )
    })?;
    Ok(LoaderDesktopBindingV1 {
        window_station_name,
        desktop_name,
    })
}

pub(crate) fn target_desktop_bootstrap(
    pipe_name: &std::ffi::OsStr,
    nonce: &std::ffi::OsStr,
    role: TargetDesktopBootstrapRoleV1,
    expected_desktop: Option<&std::ffi::OsStr>,
) -> Result<(), String> {
    let pipe_name = pipe_name
        .to_str()
        .ok_or_else(|| "target desktop bootstrap pipe name is not UTF-8".to_owned())?;
    let nonce = nonce
        .to_str()
        .ok_or_else(|| "target desktop bootstrap nonce is not UTF-8".to_owned())?;
    validate_target_desktop_bootstrap_nonce(nonce)?;
    if pipe_name
        != format!(
            "{}{}",
            super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
            nonce
        )
    {
        return Err("target desktop bootstrap pipe name is not canonical".to_owned());
    }
    let expected_desktop_name = match (role, expected_desktop) {
        (TargetDesktopBootstrapRoleV1::Holder, None) => None,
        (
            TargetDesktopBootstrapRoleV1::LoaderControl | TargetDesktopBootstrapRoleV1::Probe,
            Some(exact_desktop),
        ) => {
            let exact_desktop = exact_desktop.to_str().ok_or_else(|| {
                "target desktop bootstrap expected desktop is not UTF-8".to_owned()
            })?;
            let (window_station, desktop) = exact_desktop.split_once('\\').ok_or_else(|| {
                "target desktop bootstrap expected desktop is not qualified".to_owned()
            })?;
            validate_target_desktop_binding(window_station, desktop)?;
            Some(exact_desktop.to_owned())
        }
        _ => {
            return Err(
                "target desktop bootstrap role has an invalid desktop selection".to_owned(),
            );
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let process_token = match role {
        TargetDesktopBootstrapRoleV1::Holder => {
            super::token::current_process_token_for_access_check()
        }
        TargetDesktopBootstrapRoleV1::LoaderControl => {
            super::token::current_process_token_for_attestation_and_access_check()
        }
        TargetDesktopBootstrapRoleV1::Probe => {
            super::token::current_process_token_for_attestation_and_access_check()
        }
    }?;
    let connection = super::pipe::connect_target_desktop_bootstrap_pipe(pipe_name, deadline)?;
    clear_inherit(connection.raw())?;
    verify_not_inheritable(connection.raw())?;
    let bootstrap_identity = process_identity(unsafe { GetCurrentProcess() })?;
    let process_envelope = super::token::envelope(process_token.raw())?;
    let process_snapshot = super::token::token_query_attestation_snapshot(process_token.raw())?;
    let observed_desktop_binding = match role {
        TargetDesktopBootstrapRoleV1::Holder => None,
        TargetDesktopBootstrapRoleV1::LoaderControl | TargetDesktopBootstrapRoleV1::Probe => {
            match observe_current_loader_desktop_binding() {
                Ok(binding) => Some(binding),
                Err(failure) => {
                    let primary_detail = failure.detail.clone();
                    super::pipe::write_frame_bounded(
                        connection.raw(),
                        None,
                        deadline,
                        super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyWrite,
                        &TargetDesktopBootstrapMessageV1::LoaderReadyFailed {
                            schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
                            nonce: nonce.to_owned(),
                            role,
                            failure,
                        },
                    )
                    .map_err(|error| {
                        format!(
                            "{primary_detail}; additionally cannot send typed LoaderReady failure: {error}"
                        )
                    })?;
                    return Err(primary_detail);
                }
            }
        }
    };
    super::pipe::write_frame_bounded(
        connection.raw(),
        None,
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyWrite,
        &TargetDesktopBootstrapMessageV1::LoaderReady {
            schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
            nonce: nonce.to_owned(),
            expected_desktop: expected_desktop_name.clone(),
            observed_desktop_binding,
            bootstrap_identity,
            process_envelope: process_envelope.clone(),
            process_snapshot: process_snapshot.clone(),
        },
    )
    .map_err(|error| error.to_string())?;
    if role == TargetDesktopBootstrapRoleV1::LoaderControl {
        let release: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
            connection.raw(),
            None,
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::LoaderControlReleaseRead,
        )
        .map_err(|error| error.to_string())?;
        return match release {
            TargetDesktopBootstrapMessageV1::LoaderControlRelease {
                schema_version,
                nonce: observed_nonce,
                expected_desktop: observed_desktop,
            } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                && observed_nonce == nonce
                && Some(observed_desktop.as_str()) == expected_desktop_name.as_deref() =>
            {
                Ok(())
            }
            _ => Err("loader-control received an invalid or out-of-order release frame".to_owned()),
        };
    }
    let admission: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
        connection.raw(),
        None,
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::AdmissionRead,
    )
    .map_err(|error| error.to_string())?;
    let (binding, launcher_process_handle, launcher_token_handle, target_token_handle) =
        match admission {
            TargetDesktopBootstrapMessageV1::Admission {
                binding,
                launcher_process_query_handle,
                launcher_token_query_handle,
                target_token_capability_handle,
            } => (
                binding,
                launcher_process_query_handle,
                launcher_token_query_handle,
                target_token_capability_handle,
            ),
            _ => return Err("target desktop bootstrap did not receive Admission first".to_owned()),
        };
    let target_token_handle = match (role, target_token_handle) {
        (TargetDesktopBootstrapRoleV1::Holder, Some(handle)) => Some(handle),
        (TargetDesktopBootstrapRoleV1::Probe, None) => None,
        (TargetDesktopBootstrapRoleV1::LoaderControl, _) => unreachable!(),
        _ => {
            return Err(
                "target desktop bootstrap admission capability shape is invalid".to_owned(),
            );
        }
    };
    if launcher_process_handle == launcher_token_handle
        || target_token_handle.is_some_and(|target_token_handle| {
            target_token_handle == launcher_process_handle
                || target_token_handle == launcher_token_handle
        })
    {
        return Err(
            "target desktop bootstrap Admission reused one handle value across capability roles"
                .to_owned(),
        );
    }
    binding.verify_digest()?;
    if binding.bootstrap_image_sha256
        != super::package::validate_installed_target_desktop_bootstrap()?
        || binding.role != role
        || binding.bootstrap_envelope != process_envelope
        || binding.bootstrap_process_snapshot != process_snapshot
    {
        return Err("target desktop bootstrap role or process envelope is mismatched".to_owned());
    }
    let launcher_process = OwnedHandle::new(launcher_process_handle as usize as HANDLE)?;
    let launcher_token = OwnedHandle::new(launcher_token_handle as usize as HANDLE)?;
    verify_not_inheritable(launcher_process.raw())?;
    verify_not_inheritable(launcher_token.raw())?;

    let target_token = target_token_handle
        .map(|handle| OwnedHandle::new(handle as usize as HANDLE))
        .transpose()?;
    if let Some(target_token) = &target_token {
        verify_not_inheritable(target_token.raw())?;
    }
    let authenticated_target_token = target_token
        .as_ref()
        .map_or(process_token.raw(), |token| token.raw());
    let bootstrap_pipe_sddl = match role {
        TargetDesktopBootstrapRoleV1::Holder => super::security::holder_bootstrap_pipe_sddl()?,
        TargetDesktopBootstrapRoleV1::LoaderControl => {
            super::security::target_desktop_bootstrap_pipe_sddl(authenticated_target_token)?
        }
        TargetDesktopBootstrapRoleV1::Probe => {
            super::security::target_desktop_bootstrap_pipe_sddl(authenticated_target_token)?
        }
    };
    SecurityDescriptor::from_sddl(&bootstrap_pipe_sddl)?
        .verify_named_pipe(connection.raw())
        .map_err(|error| error.to_string())?;
    match run_admitted_target_desktop_bootstrap(
        &connection,
        &launcher_process,
        &launcher_token,
        authenticated_target_token,
        &binding,
        nonce,
        role,
        expected_desktop,
        deadline,
    ) {
        Ok(()) => Ok(()),
        Err(failure) => {
            if !started_failure_frame_publication_is_safe(
                failure.started_publication_bytes_transferred,
            ) {
                drop(connection);
                return Err(format!(
                    "{failure}; failure-frame-publication=abandoned started_bytes_transferred={}",
                    failure.started_publication_bytes_transferred,
                ));
            }
            let publication = publish_target_desktop_bootstrap_failure(
                connection.raw(),
                launcher_process.raw(),
                &binding,
                &failure,
            );
            drop(connection);
            match publication {
                Ok(()) => Err(failure.to_string()),
                Err(error) => Err(format!(
                    "{failure}; failure-frame-publication-error={error}"
                )),
            }
        }
    }
}

pub(super) fn started_failure_frame_publication_is_safe(bytes_transferred: usize) -> bool {
    bytes_transferred == 0
}

#[cfg(test)]
pub(crate) fn started_failure_frame_publication_is_safe_for_test(bytes_transferred: usize) -> bool {
    started_failure_frame_publication_is_safe(bytes_transferred)
}

pub(super) fn validate_target_desktop_bootstrap_nonce(nonce: &str) -> Result<(), String> {
    if nonce.len() != TARGET_DESKTOP_NONCE_BYTES * 2
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("target desktop bootstrap nonce is not 256-bit lowercase hex".to_owned());
    }
    Ok(())
}

pub(super) fn run_admitted_target_desktop_bootstrap(
    connection: &OwnedHandle,
    launcher_process: &OwnedHandle,
    launcher_token: &OwnedHandle,
    target_token: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    expected_nonce: &str,
    role: TargetDesktopBootstrapRoleV1,
    expected_desktop: Option<&std::ffi::OsStr>,
    deadline: Instant,
) -> Result<(), TargetDesktopBootstrapFailure> {
    authenticate_target_desktop_bootstrap_server(
        connection.raw(),
        launcher_process.raw(),
        launcher_token.raw(),
        binding,
        expected_nonce,
        target_token,
    )?;
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::StartedWrite,
        &TargetDesktopBootstrapMessageV1::Started {
            binding: binding.clone(),
            phase: TargetDesktopBootstrapPhaseV1::EndpointAdmission,
        },
    )
    .map_err(|error| {
        let bytes_transferred = error.bytes_transferred();
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::StartedPublication,
            error,
        )
        .after_started_publication_error(bytes_transferred)
    })?;
    match role {
        TargetDesktopBootstrapRoleV1::Holder => {
            run_target_desktop_bootstrap(connection, launcher_process, binding, target_token)
        }
        TargetDesktopBootstrapRoleV1::Probe => serve_target_desktop_probe(
            connection,
            launcher_process,
            binding,
            target_token,
            expected_desktop.ok_or_else(|| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                    "restricted probe desktop argument is absent",
                )
            })?,
        ),
        TargetDesktopBootstrapRoleV1::LoaderControl => {
            Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::LoaderControl,
                "loader-control cannot enter admitted bootstrap service logic",
            ))
        }
    }
}

pub(super) fn authenticate_target_desktop_bootstrap_server(
    pipe: HANDLE,
    launcher_process: HANDLE,
    launcher_token: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    expected_nonce: &str,
    target_token: HANDLE,
) -> Result<(), TargetDesktopBootstrapFailure> {
    binding.verify_digest().map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            error,
        )
    })?;
    let installed_bootstrap_sha256 = super::package::validate_installed_target_desktop_bootstrap()
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
                error,
            )
        })?;
    let bootstrap_token =
        super::token::process_token(unsafe { GetCurrentProcess() }).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    let bootstrap_envelope = super::token::envelope(bootstrap_token.raw()).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            error,
        )
    })?;
    let bootstrap_snapshot = super::token::token_query_attestation_snapshot(bootstrap_token.raw())
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    let target_snapshot =
        super::token::token_attestation_snapshot(target_token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    let target_binding_matches = match binding.role {
        TargetDesktopBootstrapRoleV1::Holder => {
            super::token::require_same_token_instance(
                "target-request-to-holder-capability",
                &binding.target_request_snapshot,
                &target_snapshot,
            )
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            })?;
            true
        }
        TargetDesktopBootstrapRoleV1::Probe => {
            let target_assignment = super::token::require_assigned_token_authority(
                "target-request-to-probe-self",
                &binding.target_request_snapshot,
                &target_snapshot,
            )
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            })?;
            target_snapshot.query_evidence() == binding.bootstrap_process_snapshot
                && target_assignment == binding.bootstrap_assignment
        }
        TargetDesktopBootstrapRoleV1::LoaderControl => false,
    };
    let holder_assignment = super::token::require_assigned_process_authority(
        "holder-launch-to-process",
        &binding.holder_launch_snapshot,
        &binding.holder_process_snapshot,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            error,
        )
    })?;
    let bootstrap_assignment = match binding.role {
        TargetDesktopBootstrapRoleV1::Holder => super::token::require_assigned_process_authority(
            "holder-launch-to-process",
            &binding.holder_launch_snapshot,
            &binding.bootstrap_process_snapshot,
        ),
        TargetDesktopBootstrapRoleV1::Probe => super::token::require_assigned_process_authority(
            "target-request-to-probe-process",
            &binding.target_request_snapshot,
            &binding.bootstrap_process_snapshot,
        ),
        TargetDesktopBootstrapRoleV1::LoaderControl => {
            super::token::require_assigned_process_authority(
                "target-request-to-loader-control-process",
                &binding.target_request_snapshot,
                &binding.bootstrap_process_snapshot,
            )
        }
    }
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            error,
        )
    })?;
    if binding.schema_version != TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
        || binding.nonce != expected_nonce
        || binding.bootstrap_image_sha256 != installed_bootstrap_sha256
        || binding.launcher_session_id != 0
        || binding.bootstrap_identity
            != process_identity(unsafe { GetCurrentProcess() }).map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
                    error,
                )
            })?
        || binding.bootstrap_envelope != bootstrap_envelope
        || binding.bootstrap_process_snapshot != bootstrap_snapshot
        || binding.holder_assignment != holder_assignment
        || binding.bootstrap_assignment != bootstrap_assignment
        || (binding.role == TargetDesktopBootstrapRoleV1::Holder
            && binding.bootstrap_process_snapshot != binding.holder_process_snapshot)
        || binding.target_envelope
            != super::token::envelope(target_token).map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            })?
        || !target_binding_matches
        || binding.broker_source_snapshot.lineage.user_sid != "S-1-5-18"
        || binding.broker_source_snapshot.lineage.session_id != 0
        || binding.broker_source_snapshot.behavior.token_is_restricted
        || !binding
            .broker_source_snapshot
            .behavior
            .restricting_sids
            .is_empty()
        || binding.holder_launch_snapshot.lineage.user_sid != "S-1-5-18"
        || binding.holder_launch_snapshot.lineage.session_id != binding.target_envelope.session_id
        || binding.holder_launch_snapshot.behavior.token_is_restricted
        || !binding
            .holder_launch_snapshot
            .behavior
            .restricting_sids
            .is_empty()
        || binding
            .holder_launch_snapshot
            .behavior
            .enabled_sensitive_privilege_count
            != 0
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            "target desktop bootstrap Admission binding is mismatched",
        ));
    }
    let mut server_pid = 0_u32;
    let mut server_session_id = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &raw mut server_pid) } == 0
        || unsafe { GetNamedPipeServerSessionId(pipe, &raw mut server_session_id) } == 0
    {
        return Err(TargetDesktopBootstrapFailure::native(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            "target desktop bootstrap pipe server identity query failed",
        ));
    }
    if unsafe { GetProcessId(launcher_process) } != server_pid
        || server_pid != binding.launcher_identity.process_id
        || server_session_id != binding.launcher_session_id
        || process_identity(launcher_process).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
                error,
            )
        })? != binding.launcher_identity
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            "target desktop bootstrap pipe server identity is mismatched",
        ));
    }
    let launcher_executable = super::package::installed_binary();
    verify_image_path(launcher_process, &launcher_executable).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            error,
        )
    })?;
    let launcher_envelope = super::token::envelope(launcher_token).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            error,
        )
    })?;
    let launcher_snapshot =
        super::token::token_attestation_snapshot(launcher_token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    let launcher_sid = super::security::service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    if launcher_envelope != binding.launcher_envelope
        || launcher_snapshot != binding.launcher_process_snapshot
        || launcher_envelope.session_id != binding.launcher_session_id
        || super::token::token_user_sid(launcher_token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })? != "S-1-5-18"
        || !super::token::token_is_restricted(launcher_token)
        || !super::token::token_has_enabled_group(launcher_token, &launcher_sid).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            },
        )?
        || !super::token::token_has_restricting_sid(launcher_token, &launcher_sid).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            },
        )?
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            "target desktop bootstrap pipe server token is not the sealed launcher",
        ));
    }
    let mut server_pid_after = 0_u32;
    let mut server_session_id_after = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &raw mut server_pid_after) } == 0
        || unsafe { GetNamedPipeServerSessionId(pipe, &raw mut server_session_id_after) } == 0
        || server_pid_after != server_pid
        || server_session_id_after != server_session_id
        || process_identity(launcher_process).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
                error,
            )
        })? != binding.launcher_identity
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            "target desktop bootstrap pipe server changed during authentication",
        ));
    }
    Ok(())
}

pub(super) fn publish_target_desktop_bootstrap_failure(
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    failure: &TargetDesktopBootstrapFailure,
) -> Result<(), String> {
    super::pipe::write_frame_bounded(
        connection,
        Some(launcher_process),
        Instant::now() + Duration::from_secs(30),
        super::pipe::TargetDesktopBootstrapPipeOperation::FailureWrite,
        &TargetDesktopBootstrapMessageV1::Failed {
            binding: binding.clone(),
            phase: failure.phase,
            native_code: failure.native_code,
            detail: failure.detail.clone(),
        },
    )
    .map_err(|error| error.to_string())
}

pub(super) fn run_target_desktop_bootstrap(
    connection: &OwnedHandle,
    launcher_process: &OwnedHandle,
    binding: &TargetDesktopBootstrapBindingV3,
    target_token: HANDLE,
) -> Result<(), TargetDesktopBootstrapFailure> {
    let holder_token = super::token::current_process_token_for_access_check().map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::TargetTokenCapture,
            error,
        )
    })?;
    let target_envelope = super::token::envelope(target_token).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetTokenCapture,
            error,
        )
    })?;
    if target_envelope != binding.target_envelope {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetTokenCapture,
            "target desktop bootstrap token changed after Admission",
        ));
    }
    let target_user_object_policy = super::security::target_user_object_policy(
        target_token,
        binding.target_user_object_policy_role,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::WindowStationPolicyConstruction,
            error,
        )
    })?;

    // LoaderReady and authenticated Started have already crossed the nonce
    // pipe without any USER32/GDI32 call. Do not inspect an implicit source
    // station here: even GetProcessWindowStation would trigger the ambient
    // binding whose restricted-token access check this helper exists to avoid.

    let window_station_name = format!("MemCordonTarget-{}", binding.nonce);
    let desktop_name = "Restricted".to_owned();
    validate_target_desktop_binding(&window_station_name, &desktop_name).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::WindowStationPolicyConstruction,
            error,
        )
    })?;

    let window_station_sddl = target_user_object_policy.window_station_sddl();
    let window_station_security =
        SecurityDescriptor::from_sddl(&window_station_sddl).map_err(|error| {
            TargetDesktopBootstrapFailure::observed_native(
                TargetDesktopBootstrapPhaseV1::WindowStationPolicyConstruction,
                format!("cannot convert target window-station SDDL: {error}"),
            )
        })?;
    let window_station_creation_security = window_station_security
        .absolute_for_user_object_creation()
        .map_err(|error| {
            TargetDesktopBootstrapFailure::observed_native(
                TargetDesktopBootstrapPhaseV1::WindowStationPolicyConstruction,
                format!("cannot prepare target window-station creation policy: {error}"),
            )
        })?;
    super::user_api::load().map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::UserModuleResolution,
            error,
        )
    })?;
    let window_station_wide = super::pipe::wide_null(&window_station_name);
    let window_station_attributes = window_station_creation_security.attributes(false);
    let station_thread_id = unsafe { GetCurrentThreadId() };
    let station_primary_before =
        super::token::process_token_query_attestation(unsafe { GetCurrentProcess() }).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation,
                    error,
                )
            },
        )?;
    let station_carrier_guard = request_creator_arm(
        connection.raw(),
        launcher_process.raw(),
        binding,
        super::session_broker::SessionCreationPhaseV1::WindowStation,
        1,
        station_thread_id,
        &station_primary_before,
    )?;
    let private_window_station = unsafe {
        CreateWindowStationW(
            window_station_wide.as_ptr(),
            CWF_CREATE_ONLY_FLAG,
            super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            &raw const window_station_attributes,
        )
    };
    let station_error = private_window_station
        .is_null()
        .then(|| io::Error::last_os_error());
    if let Err(error) = station_carrier_guard.revert() {
        eprintln!("station creator carrier reversion failed: {error}");
        unsafe { TerminateProcess(GetCurrentProcess(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS) };
        std::process::abort();
    }
    let station_primary_after =
        super::token::process_token_query_attestation(unsafe { GetCurrentProcess() }).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation,
                    error,
                )
            },
        )?;
    consume_creator_arm(
        connection.raw(),
        launcher_process.raw(),
        binding,
        super::session_broker::SessionCreationPhaseV1::WindowStation,
        1,
        station_thread_id,
        station_error.as_ref().and_then(io::Error::raw_os_error),
        &station_primary_after,
    )?;
    if let Some(error) = station_error {
        return Err(TargetDesktopBootstrapFailure::captured_native(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation,
            error.raw_os_error().unwrap_or_default(),
            format!("CreateWindowStationW failed in target-token bootstrap: {error}"),
        ));
    }
    let mut private_window_station = BootstrapWindowStation::new(private_window_station);
    verify_user_object_not_inheritable(private_window_station.raw()).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation,
            error,
        )
    })?;
    if unsafe { SetProcessWindowStation(private_window_station.raw()) } == 0 {
        return Err(TargetDesktopBootstrapFailure::native(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationBinding,
            "SetProcessWindowStation failed in dedicated target-token bootstrap",
        ));
    }
    private_window_station.mark_assigned();
    let current_private_window_station = unsafe { GetProcessWindowStation() };
    let private_station_assigned = !current_private_window_station.is_null()
        && user_object_name(current_private_window_station).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::PrivateWindowStationBinding,
                error,
            )
        })? == window_station_name;
    if !private_station_assigned {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationBinding,
            "target-token bootstrap did not retain the nonce private window station",
        ));
    }
    attest_target_user_object(
        private_window_station.raw(),
        &window_station_name,
        &window_station_security,
        super::security::SecurityObjectKind::WindowStation,
        holder_token.raw(),
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationAttestation,
            format!("holder station attestation failed: {error}"),
        )
    })?;
    attest_target_user_object(
        private_window_station.raw(),
        &window_station_name,
        &window_station_security,
        super::security::SecurityObjectKind::WindowStation,
        target_token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationAttestation,
            error,
        )
    })?;

    let desktop_sddl = target_user_object_policy.desktop_sddl();
    let desktop_security = SecurityDescriptor::from_sddl(&desktop_sddl).map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::DesktopPolicyConstruction,
            format!("cannot convert target desktop SDDL: {error}"),
        )
    })?;
    let desktop_creation_security = desktop_security
        .absolute_for_user_object_creation()
        .map_err(|error| {
            TargetDesktopBootstrapFailure::observed_native(
                TargetDesktopBootstrapPhaseV1::DesktopPolicyConstruction,
                format!("cannot prepare target desktop creation policy: {error}"),
            )
        })?;
    let desktop_wide = super::pipe::wide_null(&desktop_name);
    let mut desktop = create_target_desktop_on_creator_thread(
        desktop_wide.clone(),
        desktop_creation_security,
        connection.raw(),
        launcher_process.raw(),
        binding.clone(),
    )?;
    if unsafe { SetThreadDesktop(desktop.raw()) } == 0 {
        return Err(TargetDesktopBootstrapFailure::native(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
            "SetThreadDesktop failed for nonce private desktop",
        ));
    }
    let private_desktop_assigned =
        unsafe { GetThreadDesktop(GetCurrentThreadId()) } == desktop.raw();
    if !private_desktop_assigned {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
            "target desktop bootstrap thread did not retain the nonce private desktop",
        ));
    }
    desktop.mark_assigned();
    attest_target_user_object(
        desktop.raw(),
        &desktop_name,
        &desktop_security,
        super::security::SecurityObjectKind::Desktop,
        holder_token.raw(),
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
            format!("holder desktop attestation failed: {error}"),
        )
    })?;
    attest_target_user_object(
        desktop.raw(),
        &desktop_name,
        &desktop_security,
        super::security::SecurityObjectKind::Desktop,
        target_token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
            error,
        )
    })?;
    validate_target_desktop_input_state(desktop_receives_input(desktop.raw()).map_err(
        |error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
                error,
            )
        },
    )?)
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
            error,
        )
    })?;
    verify_private_desktop_containment(private_window_station.raw(), &desktop_wide).map_err(
        |error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
                error,
            )
        },
    )?;
    // No ambient station or desktop handle was requested before the nonce-
    // private station was created. Every subsequent USER-object observation
    // refers to the explicitly bound private station or its Restricted desktop,
    // so this proof is constructional rather than a shared-object fingerprint.
    let source_objects_unmodified = true;
    let window_station_policy_sha256 = window_station_security
        .user_object_policy_fingerprint(super::security::SecurityObjectKind::WindowStation)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateWindowStationAttestation,
                error,
            )
        })?;
    let desktop_policy_sha256 = desktop_security
        .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
                error,
            )
        })?;
    // Capture one final same-domain namespace baseline only after both USER
    // objects have completed creation, binding, semantic attestation, carrier
    // clearing, non-input validation, and containment validation.
    let window_station_live_equality_sha256 =
        SecurityDescriptor::user_object_security_equality_fingerprint(private_window_station.raw())
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::PrivateWindowStationAttestation,
                    error,
                )
            })?;
    let desktop_live_equality_sha256 =
        SecurityDescriptor::user_object_security_equality_fingerprint(desktop.raw()).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
                    error,
                )
            },
        )?;

    let frame = TargetDesktopBootstrapFrameV1 {
        schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
        bootstrap_identity: process_identity(unsafe { GetCurrentProcess() }).map_err(|error| {
            TargetDesktopBootstrapFailure::observed_native(
                TargetDesktopBootstrapPhaseV1::ProcessIdentityCapture,
                error,
            )
        })?,
        target_envelope,
        window_station_name,
        desktop_name,
        window_station_policy_sha256,
        desktop_policy_sha256,
        window_station_live_equality_sha256,
        desktop_live_equality_sha256,
        source_objects_unmodified,
        private_station_assigned,
        private_desktop_assigned,
        desktop_containment_verified: true,
        window_station_policy_verified: true,
        desktop_policy_verified: true,
        window_station_not_inheritable: true,
        desktop_not_inheritable: true,
        noninteractive: true,
    };
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        Instant::now() + Duration::from_secs(30),
        super::pipe::TargetDesktopBootstrapPipeOperation::ReadyWrite,
        &TargetDesktopBootstrapMessageV1::Ready {
            binding: binding.clone(),
            attestation: frame.clone(),
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::ResultPublication,
            error,
        )
    })?;

    let native_loader_access_lease = serve_holder_target_association_preflight(
        connection,
        launcher_process,
        binding,
        target_token,
        &frame.window_station_name,
        &frame.desktop_name,
        private_window_station.raw(),
        desktop.raw(),
        &window_station_security,
        &desktop_security,
        &frame.window_station_live_equality_sha256,
        &frame.desktop_live_equality_sha256,
    )?;

    // The USER-object handles and native-loader lease (source pins, exact-target
    // files, KnownDll directory, and present sections) remain live through this
    // wait. The launcher performs both child loader qualifications before it
    // releases the holder, closing the preflight-to-create mutation window.
    let wait_result = super::pipe::wait_for_target_desktop_bootstrap_release(
        connection.raw(),
        launcher_process.raw(),
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(TargetDesktopBootstrapPhaseV1::LifetimeHold, error)
    });
    wait_result?;
    drop(native_loader_access_lease);
    drop(desktop);
    drop(private_window_station);
    Ok(())
}

pub(super) fn serve_target_desktop_probe(
    connection: &OwnedHandle,
    launcher_process: &OwnedHandle,
    binding: &TargetDesktopBootstrapBindingV3,
    target_token: HANDLE,
    expected_desktop: &std::ffi::OsStr,
) -> Result<(), TargetDesktopBootstrapFailure> {
    let target_user_object_policy = super::security::target_user_object_policy(
        target_token,
        binding.target_user_object_policy_role,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    let exact_name = expected_desktop.to_str().ok_or_else(|| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            "restricted probe desktop is not UTF-8",
        )
    })?;
    let (window_station_name, desktop_name) = exact_name.split_once('\\').ok_or_else(|| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            "restricted probe desktop is not fully qualified",
        )
    })?;
    validate_target_desktop_binding(window_station_name, desktop_name).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    super::user_api::load().map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::UserModuleResolution,
            error,
        )
    })?;
    let current_station = unsafe { GetProcessWindowStation() };
    let current_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    if current_station.is_null()
        || current_desktop.is_null()
        || user_object_name(current_station).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        })? != window_station_name
        || user_object_name(current_desktop).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        })? != desktop_name
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            "restricted probe did not initialize on the admitted private desktop",
        ));
    }
    let window_station_sddl = target_user_object_policy.window_station_sddl();
    let desktop_sddl = target_user_object_policy.desktop_sddl();
    let window_station_security =
        SecurityDescriptor::from_sddl(&window_station_sddl).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        })?;
    let desktop_security = SecurityDescriptor::from_sddl(&desktop_sddl).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    attest_target_user_object(
        current_station,
        window_station_name,
        &window_station_security,
        super::security::SecurityObjectKind::WindowStation,
        target_token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    attest_target_user_object(
        current_desktop,
        desktop_name,
        &desktop_security,
        super::security::SecurityObjectKind::Desktop,
        target_token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    verify_private_desktop_containment(current_station, &super::pipe::wide_null(desktop_name))
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        })?;
    validate_target_desktop_input_state(desktop_receives_input(current_desktop).map_err(
        |error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        },
    )?)
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    let frame =
        TargetDesktopBootstrapFrameV1 {
            schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
            bootstrap_identity: binding.bootstrap_identity.clone(),
            target_envelope: binding.target_envelope.clone(),
            window_station_name: window_station_name.to_owned(),
            desktop_name: desktop_name.to_owned(),
            window_station_policy_sha256: window_station_security
                .user_object_policy_fingerprint(super::security::SecurityObjectKind::WindowStation)
                .map_err(|error| {
                    TargetDesktopBootstrapFailure::contract(
                        TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                        error,
                    )
                })?,
            desktop_policy_sha256: desktop_security
                .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)
                .map_err(|error| {
                    TargetDesktopBootstrapFailure::contract(
                        TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                        error,
                    )
                })?,
            window_station_live_equality_sha256:
                SecurityDescriptor::user_object_security_equality_fingerprint(current_station)
                    .map_err(|error| {
                        TargetDesktopBootstrapFailure::contract(
                            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                            error,
                        )
                    })?,
            desktop_live_equality_sha256:
                SecurityDescriptor::user_object_security_equality_fingerprint(current_desktop)
                    .map_err(|error| {
                        TargetDesktopBootstrapFailure::contract(
                            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                            error,
                        )
                    })?,
            source_objects_unmodified: true,
            private_station_assigned: true,
            private_desktop_assigned: true,
            desktop_containment_verified: true,
            window_station_policy_verified: true,
            desktop_policy_verified: true,
            window_station_not_inheritable: true,
            desktop_not_inheritable: true,
            noninteractive: true,
        };
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        Instant::now() + Duration::from_secs(30),
        super::pipe::TargetDesktopBootstrapPipeOperation::ReadyWrite,
        &TargetDesktopBootstrapMessageV1::Ready {
            binding: binding.clone(),
            attestation: frame,
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })
}

impl CapturedTargetDesktop {
    pub(super) fn capture(token: HANDLE) -> Result<Self, String> {
        let window_station = unsafe { GetProcessWindowStation() };
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        if window_station.is_null() || desktop.is_null() {
            return Err("cannot capture nested target USER binding".to_owned());
        }
        let window_station_name =
            user_object_name(window_station).map_err(|error| error.to_string())?;
        let desktop_name = user_object_name(desktop).map_err(|error| error.to_string())?;
        validate_target_desktop_binding(&window_station_name, &desktop_name)?;
        validate_target_desktop_input_state(
            desktop_receives_input(desktop).map_err(|error| error.to_string())?,
        )?;
        let read_handles = TargetUserBindingReadHandles::duplicate(window_station, desktop)
            .map_err(|error| {
                format!("cannot duplicate nested target USER readback handles: {error}")
            })?;
        let window_station_security_sha256 =
            SecurityDescriptor::user_object_security_equality_fingerprint(
                read_handles.window_station.raw(),
            )?;
        let desktop_security_sha256 =
            SecurityDescriptor::user_object_security_equality_fingerprint(
                read_handles.desktop.raw(),
            )?;
        let exact_name = format!("{window_station_name}\\{desktop_name}");
        let mut startup_name = exact_name.encode_utf16().collect::<Vec<_>>();
        startup_name.push(0);
        let context = Self {
            read_handles,
            window_station_name,
            window_station_security_sha256,
            desktop_name,
            desktop_security_sha256,
            exact_name,
            startup_name,
            window_station_security: SecurityDescriptor::from_sddl(
                &super::security::target_window_station_sddl(token)?,
            )?,
            desktop_security: SecurityDescriptor::from_sddl(
                &super::security::target_desktop_sddl(token)?,
            )?,
        };
        context.attest(token)?;
        Ok(context)
    }

    pub(super) fn attest(&self, token: HANDLE) -> Result<(), String> {
        let current_window_station = unsafe { GetProcessWindowStation() };
        let current_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        if current_window_station.is_null()
            || current_desktop.is_null()
            || user_object_name(current_window_station).map_err(|error| error.to_string())?
                != self.window_station_name
            || user_object_name(current_desktop).map_err(|error| error.to_string())?
                != self.desktop_name
        {
            return Err("nested target USER binding changed during child creation".to_owned());
        }
        let current_read_handles =
            TargetUserBindingReadHandles::duplicate(current_window_station, current_desktop)
                .map_err(|error| {
                    format!("cannot refresh nested target USER readback handles: {error}")
                })?;
        if SecurityDescriptor::user_object_security_equality_fingerprint(
            current_read_handles.window_station.raw(),
        )? != self.window_station_security_sha256
            || SecurityDescriptor::user_object_security_equality_fingerprint(
                self.read_handles.window_station.raw(),
            )? != self.window_station_security_sha256
        {
            return Err(
                "nested target private window-station binding changed during child creation"
                    .to_owned(),
            );
        }
        attest_target_user_object(
            current_read_handles.window_station.raw(),
            &self.window_station_name,
            &self.window_station_security,
            super::security::SecurityObjectKind::WindowStation,
            token,
        )
        .map_err(|error| format!("nested target window-station preflight failed: {error}"))?;
        if SecurityDescriptor::user_object_security_equality_fingerprint(
            current_read_handles.desktop.raw(),
        )? != self.desktop_security_sha256
            || SecurityDescriptor::user_object_security_equality_fingerprint(
                self.read_handles.desktop.raw(),
            )? != self.desktop_security_sha256
        {
            return Err(
                "nested target private desktop binding changed during child creation".to_owned(),
            );
        }
        attest_target_user_object(
            current_read_handles.desktop.raw(),
            &self.desktop_name,
            &self.desktop_security,
            super::security::SecurityObjectKind::Desktop,
            token,
        )
        .map_err(|error| format!("nested target desktop preflight failed: {error}"))?;
        let mut progress = NullAssociationPreflightProgress;
        let (_evidence, _native_loader_access_lease) = attest_target_user_object_opens_as_token(
            token,
            &self.window_station_name,
            &self.desktop_name,
            self.read_handles.window_station.raw(),
            self.read_handles.desktop.raw(),
            &self.window_station_security,
            &self.desktop_security,
            &self.window_station_security_sha256,
            &self.desktop_security_sha256,
            Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT,
            &mut progress,
        )
        .map_err(|error| {
            format!("nested target explicit-binding open preflight failed: {error}")
        })?;
        validate_target_desktop_input_state(
            desktop_receives_input(current_desktop).map_err(|error| error.to_string())?,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn serve_holder_target_association_preflight(
    connection: &OwnedHandle,
    launcher_process: &OwnedHandle,
    binding: &TargetDesktopBootstrapBindingV3,
    target_token: HANDLE,
    window_station_name: &str,
    desktop_name: &str,
    retained_window_station: HANDLE,
    retained_desktop: HANDLE,
    window_station_security: &SecurityDescriptor,
    desktop_security: &SecurityDescriptor,
    expected_window_station_live_equality_sha256: &str,
    expected_desktop_live_equality_sha256: &str,
) -> Result<super::loader_access::NativeLoaderAccessLeaseV1, TargetDesktopBootstrapFailure> {
    let request: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        Instant::now() + Duration::from_secs(30),
        super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightRead,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    match request {
        TargetDesktopBootstrapMessageV1::AssociationPreflight {
            binding: observed_binding,
        } if observed_binding == *binding => {}
        _ => {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "holder association-preflight request is invalid or out of order",
            ));
        }
    }
    let overall_deadline = Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT;
    let mut progress = AssociationPreflightProgressPublisher {
        connection: connection.raw(),
        launcher_process: launcher_process.raw(),
        binding,
        overall_deadline,
        cursor: AssociationPreflightProgressCursor::default(),
    };
    let (evidence, native_loader_access_lease) = attest_target_user_object_opens_as_token(
        target_token,
        window_station_name,
        desktop_name,
        retained_window_station,
        retained_desktop,
        window_station_security,
        desktop_security,
        expected_window_station_live_equality_sha256,
        expected_desktop_live_equality_sha256,
        overall_deadline,
        &mut progress,
    )?;
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        (Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(overall_deadline),
        super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightReadyWrite,
        &TargetDesktopBootstrapMessageV1::AssociationPreflightReady {
            binding: binding.clone(),
            evidence: Box::new(evidence),
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    Ok(native_loader_access_lease)
}

pub(super) struct AssociationPreflightProgressPublisher<'a> {
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: &'a TargetDesktopBootstrapBindingV3,
    overall_deadline: Instant,
    cursor: AssociationPreflightProgressCursor,
}

pub(super) trait AssociationPreflightProgressSink {
    fn publish(
        &mut self,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) -> Result<(), TargetDesktopBootstrapFailure>;
}

pub(super) struct NullAssociationPreflightProgress;

impl AssociationPreflightProgressSink for NullAssociationPreflightProgress {
    fn publish(
        &mut self,
        _stage: TargetAssociationPreflightStageV1,
        _completed: u32,
        _total: Option<u32>,
    ) -> Result<(), TargetDesktopBootstrapFailure> {
        Ok(())
    }
}

impl AssociationPreflightProgressSink for AssociationPreflightProgressPublisher<'_> {
    fn publish(
        &mut self,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) -> Result<(), TargetDesktopBootstrapFailure> {
        if Instant::now() >= self.overall_deadline {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                format!(
                    "stage={} completed={completed} total={} overall association-preflight deadline elapsed",
                    stage.diagnostic(),
                    total.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                ),
            ));
        }
        let sequence = self.cursor.sequence.checked_add(1).ok_or_else(|| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                "association-preflight progress sequence overflowed",
            )
        })?;
        self.cursor
            .validate_next(sequence, stage, completed, total)
            .map_err(|detail| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                    detail,
                )
            })?;
        super::pipe::write_frame_bounded(
            self.connection,
            Some(self.launcher_process),
            (Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(self.overall_deadline),
            super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightProgressWrite,
            &TargetDesktopBootstrapMessageV1::AssociationPreflightProgress {
                binding: self.binding.clone(),
                sequence,
                stage,
                completed,
                total,
            },
        )
        .map_err(|error| {
            TargetDesktopBootstrapFailure::from_pipe(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                error,
            )
        })?;
        self.cursor.commit(sequence, stage, completed, total);
        Ok(())
    }
}

pub(super) fn association_stage_from_native_loader(
    stage: super::loader_access::NativeLoaderProgressStage,
) -> TargetAssociationPreflightStageV1 {
    match stage {
        super::loader_access::NativeLoaderProgressStage::SourceBootstrap => {
            TargetAssociationPreflightStageV1::SourceBootstrap
        }
        super::loader_access::NativeLoaderProgressStage::SourceSystemAncestry => {
            TargetAssociationPreflightStageV1::SourceSystemAncestry
        }
        super::loader_access::NativeLoaderProgressStage::SourceLoaderGraph => {
            TargetAssociationPreflightStageV1::SourceLoaderGraph
        }
        super::loader_access::NativeLoaderProgressStage::SourceKnownDlls => {
            TargetAssociationPreflightStageV1::SourceKnownDlls
        }
        super::loader_access::NativeLoaderProgressStage::TargetBootstrap => {
            TargetAssociationPreflightStageV1::TargetBootstrap
        }
        super::loader_access::NativeLoaderProgressStage::TargetKnownDlls => {
            TargetAssociationPreflightStageV1::TargetKnownDlls
        }
        super::loader_access::NativeLoaderProgressStage::TargetModules => {
            TargetAssociationPreflightStageV1::TargetModules
        }
    }
}

pub(super) fn attest_target_user_object_opens_as_token(
    token: HANDLE,
    window_station_name: &str,
    desktop_name: &str,
    retained_window_station: HANDLE,
    retained_desktop: HANDLE,
    window_station_security: &SecurityDescriptor,
    desktop_security: &SecurityDescriptor,
    expected_window_station_live_equality_sha256: &str,
    expected_desktop_live_equality_sha256: &str,
    overall_deadline: Instant,
    progress: &mut dyn AssociationPreflightProgressSink,
) -> Result<
    (
        TargetUserObjectOpenPreflightV1,
        super::loader_access::NativeLoaderAccessLeaseV1,
    ),
    TargetDesktopBootstrapFailure,
> {
    progress.publish(
        TargetAssociationPreflightStageV1::RetainedNamespaceBefore,
        0,
        Some(1),
    )?;
    let desktop_heap_kb = desktop_heap_kb(retained_desktop).map_err(|error| {
        TargetDesktopBootstrapFailure::from_user_object(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    if user_object_name(unsafe { GetProcessWindowStation() }).map_err(|error| {
        TargetDesktopBootstrapFailure::from_user_object(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })? != window_station_name
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            "explicit-binding open preflight is not running in the expected station",
        ));
    }
    let expected_window_station_policy_sha256 = window_station_security
        .user_object_policy_fingerprint(super::security::SecurityObjectKind::WindowStation)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })?;
    let expected_desktop_policy_sha256 = desktop_security
        .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })?;
    attest_retained_target_user_object_namespace(
        token,
        window_station_name,
        desktop_name,
        retained_window_station,
        retained_desktop,
        window_station_security,
        desktop_security,
        expected_window_station_live_equality_sha256,
        expected_desktop_live_equality_sha256,
    )?;
    progress.publish(
        TargetAssociationPreflightStageV1::RetainedNamespaceBefore,
        1,
        Some(1),
    )?;
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    // Resolve paths, PE imports, API-set hosts, and source identity/mutation
    // pins under the holder primary token before installing exact-target
    // impersonation. The effective-token phase performs only final-file and
    // native-object authorization opens; it never opens an ancestor directory.
    let native_loader_resources = {
        let mut publish = |native: super::loader_access::NativeLoaderProgress| {
            progress
                .publish(
                    association_stage_from_native_loader(native.stage),
                    native.completed,
                    native.total,
                )
                .map_err(|error| error.to_string())
        };
        let mut budget = super::loader_access::NativeLoaderAttestationBudget::new(
            overall_deadline,
            &mut publish,
        );
        super::loader_access::resolve_native_loader_resources(
            &super::package::installed_target_desktop_bootstrap(),
            &mut budget,
        )
        .map_err(TargetDesktopBootstrapFailure::from_native_loader)?
    };
    progress.publish(
        TargetAssociationPreflightStageV1::TargetTokenInstallation,
        0,
        Some(1),
    )?;
    let target_snapshot_before =
        super::token::token_attestation_snapshot(token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })?;
    let impersonation = duplicate_explicit_impersonation_token(token).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    let impersonation_snapshot = super::token::token_attestation_snapshot(impersonation.raw())
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                error,
            )
        })?;
    super::token::require_primary_to_impersonation_authority(
        "holder-native-loader-preflight-impersonation",
        &target_snapshot_before,
        &impersonation_snapshot,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
            error,
        )
    })?;
    let guard = ThreadImpersonationGuard::install(impersonation.raw()).map_err(|error| {
        TargetDesktopBootstrapFailure::captured_native(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error.raw_os_error().unwrap_or_default(),
            format!(
                "object_kind=thread-token api=SetThreadToken desired_mode=security-impersonation detail={error}"
            ),
        )
    })?;
    progress.publish(
        TargetAssociationPreflightStageV1::TargetTokenInstallation,
        1,
        Some(1),
    )?;

    let open_result = (|| {
        progress.publish(
            TargetAssociationPreflightStageV1::TargetWindowStation,
            0,
            Some(1),
        )?;
        let window_station_wide = super::pipe::wide_null(window_station_name);
        let window_station =
            unsafe { OpenWindowStationW(window_station_wide.as_ptr(), 0, MAXIMUM_ALLOWED_ACCESS) };
        if window_station.is_null() {
            let error = io::Error::last_os_error();
            return Err(TargetDesktopBootstrapFailure::captured_native(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error.raw_os_error().unwrap_or_default(),
                format!(
                    "object_kind=window-station api=OpenWindowStationW desired_mode=maximum-allowed requested={MAXIMUM_ALLOWED_ACCESS:#010x} required={:#010x} detail={error}",
                    super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
                ),
            ));
        }
        let mut window_station = BootstrapWindowStation::new(window_station);
        let window_station_granted_access =
            super::token::granted_handle_access(window_station.raw()).map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=window-station api=NtQueryObject desired_mode=maximum-allowed detail={error}"
                    ),
                )
            })?;
        if window_station_granted_access & super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
            != super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
        {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                format!(
                    "object_kind=window-station api=NtQueryObject desired_mode=maximum-allowed required={:#010x} granted={window_station_granted_access:#010x}",
                    super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
                ),
            ));
        }
        if user_object_name(window_station.raw()).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })? != window_station_name
        {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=window-station api=GetUserObjectInformationW resolved the wrong object",
            ));
        }
        let window_station_live_equality_sha256 =
            SecurityDescriptor::user_object_security_equality_fingerprint(window_station.raw())
                .map_err(|error| {
                    TargetDesktopBootstrapFailure::contract(
                        TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                        format!(
                            "object_kind=window-station api=GetUserObjectSecurity detail={error}"
                        ),
                    )
                })?;
        if window_station_live_equality_sha256 != expected_window_station_live_equality_sha256 {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=window-station api=GetUserObjectSecurity live equality fingerprint changed",
            ));
        }
        let window_station_policy_sha256 = window_station_security
            .user_object_resultant_fingerprint(
                window_station.raw(),
                super::security::SecurityObjectKind::WindowStation,
            )
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=window-station api=GetUserObjectSecurity policy detail={error}"
                    ),
                )
            })?;
        if window_station_policy_sha256 != expected_window_station_policy_sha256 {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=window-station api=GetUserObjectSecurity policy fingerprint changed",
            ));
        }
        // The opened handle names the process's currently assigned station, so
        // CloseWindowStation is forbidden. Retain this independently proven
        // access handle until the dedicated process exits.
        window_station.mark_assigned();
        progress.publish(
            TargetAssociationPreflightStageV1::TargetWindowStation,
            1,
            Some(1),
        )?;

        progress.publish(TargetAssociationPreflightStageV1::TargetDesktop, 0, Some(1))?;
        let desktop_wide = super::pipe::wide_null(desktop_name);
        let desktop = unsafe { OpenDesktopW(desktop_wide.as_ptr(), 0, 0, MAXIMUM_ALLOWED_ACCESS) };
        if desktop.is_null() {
            let error = io::Error::last_os_error();
            return Err(TargetDesktopBootstrapFailure::captured_native(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error.raw_os_error().unwrap_or_default(),
                format!(
                    "object_kind=desktop api=OpenDesktopW desired_mode=maximum-allowed requested={MAXIMUM_ALLOWED_ACCESS:#010x} required={:#010x} detail={error}",
                    super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
                ),
            ));
        }
        let mut desktop = OwnedDesktop::new(desktop);
        let desktop_granted_access =
            super::token::granted_handle_access(desktop.raw()).map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=desktop api=NtQueryObject desired_mode=maximum-allowed detail={error}"
                    ),
                )
            })?;
        if desktop_granted_access & super::security::TARGET_PRIVATE_DESKTOP_ACCESS
            != super::security::TARGET_PRIVATE_DESKTOP_ACCESS
        {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                format!(
                    "object_kind=desktop api=NtQueryObject desired_mode=maximum-allowed required={:#010x} granted={desktop_granted_access:#010x}",
                    super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
                ),
            ));
        }
        if user_object_name(desktop.raw()).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })? != desktop_name
        {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=desktop api=GetUserObjectInformationW resolved the wrong object",
            ));
        }
        let desktop_live_equality_sha256 =
            SecurityDescriptor::user_object_security_equality_fingerprint(desktop.raw()).map_err(
                |error| {
                    TargetDesktopBootstrapFailure::contract(
                        TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                        format!("object_kind=desktop api=GetUserObjectSecurity detail={error}"),
                    )
                },
            )?;
        if desktop_live_equality_sha256 != expected_desktop_live_equality_sha256 {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=desktop api=GetUserObjectSecurity live equality fingerprint changed",
            ));
        }
        let desktop_policy_sha256 = desktop_security
            .user_object_resultant_fingerprint(
                desktop.raw(),
                super::security::SecurityObjectKind::Desktop,
            )
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!("object_kind=desktop api=GetUserObjectSecurity policy detail={error}"),
                )
            })?;
        if desktop_policy_sha256 != expected_desktop_policy_sha256 {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=desktop api=GetUserObjectSecurity policy fingerprint changed",
            ));
        }
        desktop.mark_assigned();
        progress.publish(TargetAssociationPreflightStageV1::TargetDesktop, 1, Some(1))?;
        let native_loader_access_lease = {
            let mut publish = |native: super::loader_access::NativeLoaderProgress| {
                progress
                    .publish(
                        association_stage_from_native_loader(native.stage),
                        native.completed,
                        native.total,
                    )
                    .map_err(|error| error.to_string())
            };
            let mut budget = super::loader_access::NativeLoaderAttestationBudget::new(
                overall_deadline,
                &mut publish,
            );
            super::loader_access::probe_native_loader_access_as_effective_thread(
                native_loader_resources,
                &mut budget,
            )
            .map_err(TargetDesktopBootstrapFailure::from_native_loader)?
        };
        Ok((
            window_station_granted_access,
            desktop_granted_access,
            window_station_policy_sha256,
            desktop_policy_sha256,
            window_station_live_equality_sha256,
            desktop_live_equality_sha256,
            native_loader_access_lease,
        ))
    })();

    if open_result.is_ok() {
        progress.publish(
            TargetAssociationPreflightStageV1::RevertAndFinalization,
            0,
            Some(1),
        )?;
    }
    guard.revert().map_err(|error| {
        TargetDesktopBootstrapFailure::captured_native(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error.raw_os_error().unwrap_or_default(),
            format!(
                "object_kind=thread-token api=RevertToSelf desired_mode=remove-impersonation detail={error}"
            ),
        )
    })?;
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    let (
        window_station_granted_access,
        desktop_granted_access,
        window_station_policy_sha256,
        desktop_policy_sha256,
        window_station_live_equality_sha256,
        desktop_live_equality_sha256,
        native_loader_access_lease,
    ) = open_result?;
    let target_snapshot_after =
        super::token::token_attestation_snapshot(token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })?;
    super::token::require_same_token_instance(
        "holder-target-association-preflight",
        &target_snapshot_before,
        &target_snapshot_after,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    attest_retained_target_user_object_namespace(
        token,
        window_station_name,
        desktop_name,
        retained_window_station,
        retained_desktop,
        window_station_security,
        desktop_security,
        expected_window_station_live_equality_sha256,
        expected_desktop_live_equality_sha256,
    )?;
    let native_loader_access_lease = native_loader_access_lease
        .mark_reverted_and_seal()
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                error,
            )
        })?;
    progress.publish(
        TargetAssociationPreflightStageV1::RevertAndFinalization,
        1,
        Some(1),
    )?;
    let native_loader_access = native_loader_access_lease.evidence().clone();
    Ok((
        TargetUserObjectOpenPreflightV1 {
            window_station_granted_access,
            desktop_granted_access,
            desktop_heap_kb,
            window_station_policy_sha256,
            desktop_policy_sha256,
            window_station_live_equality_sha256,
            desktop_live_equality_sha256,
            window_station_policy_verified_after_open: true,
            desktop_policy_verified_after_open: true,
            creator_live_baselines_unchanged: true,
            target_snapshot_before,
            target_snapshot_after,
            thread_token_absent: true,
            native_loader_access,
        },
        native_loader_access_lease,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn attest_retained_target_user_object_namespace(
    token: HANDLE,
    window_station_name: &str,
    desktop_name: &str,
    retained_window_station: HANDLE,
    retained_desktop: HANDLE,
    window_station_security: &SecurityDescriptor,
    desktop_security: &SecurityDescriptor,
    expected_window_station_live_equality_sha256: &str,
    expected_desktop_live_equality_sha256: &str,
) -> Result<(), TargetDesktopBootstrapFailure> {
    let window_station_live_equality_sha256 =
        SecurityDescriptor::user_object_security_equality_fingerprint(retained_window_station)
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=retained-window-station api=GetUserObjectSecurity detail={error}"
                    ),
                )
            })?;
    let desktop_live_equality_sha256 =
        SecurityDescriptor::user_object_security_equality_fingerprint(retained_desktop).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=retained-desktop api=GetUserObjectSecurity detail={error}"
                    ),
                )
            },
        )?;
    if window_station_live_equality_sha256 != expected_window_station_live_equality_sha256
        || desktop_live_equality_sha256 != expected_desktop_live_equality_sha256
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            "retained USER-object live equality baseline changed",
        ));
    }
    attest_target_user_object(
        retained_window_station,
        window_station_name,
        window_station_security,
        super::security::SecurityObjectKind::WindowStation,
        token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            format!("retained window-station semantic reattestation failed: {error}"),
        )
    })?;
    attest_target_user_object(
        retained_desktop,
        desktop_name,
        desktop_security,
        super::security::SecurityObjectKind::Desktop,
        token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            format!("retained desktop semantic reattestation failed: {error}"),
        )
    })
}

pub(super) fn duplicate_explicit_impersonation_token(token: HANDLE) -> Result<OwnedHandle, String> {
    let mut impersonation = ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_IMPERSONATE,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut impersonation,
        )
    } == 0
    {
        return Err(format!(
            "cannot duplicate explicit-binding preflight token: {}",
            io::Error::last_os_error()
        ));
    }
    OwnedHandle::new(impersonation)
}

#[cfg(test)]
pub(crate) fn attest_target_token_capability_for_test(token: HANDLE) -> Result<(), String> {
    let transferred =
        duplicate_remote_target_token_capability(token, unsafe { GetCurrentProcess() })?;
    let transferred = OwnedHandle::new(transferred as usize as HANDLE)?;
    verify_not_inheritable(transferred.raw())?;
    super::token::token_attestation_snapshot(transferred.raw())?;
    let _impersonation = duplicate_explicit_impersonation_token(transferred.raw())?;
    Ok(())
}

pub(super) fn attest_target_user_object(
    handle: HANDLE,
    expected_name: &str,
    security: &SecurityDescriptor,
    kind: super::security::SecurityObjectKind,
    token: HANDLE,
) -> Result<(), String> {
    verify_user_object_not_inheritable(handle)?;
    if user_object_name(handle).map_err(|error| error.to_string())? != expected_name {
        return Err("private target USER-object name changed".to_owned());
    }
    security
        .verify_user_object(handle, kind)
        .map_err(|error| format!("private target USER-object readback failed: {error}"))?;
    let expected_policy_sha256 = security.user_object_policy_fingerprint(kind)?;
    let actual_policy_sha256 = security.user_object_resultant_fingerprint(handle, kind)?;
    if actual_policy_sha256 != expected_policy_sha256 {
        return Err("private target USER-object canonical policy fingerprint changed".to_owned());
    }
    let requested = match kind {
        super::security::SecurityObjectKind::WindowStation => {
            super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
        }
        super::security::SecurityObjectKind::Desktop => {
            super::security::TARGET_PRIVATE_DESKTOP_ACCESS
        }
        _ => {
            return Err(
                "target USER-object attestation requires a private station or desktop".to_owned(),
            );
        }
    };
    let (allowed, granted) = match kind {
        super::security::SecurityObjectKind::WindowStation => {
            security.private_window_station_access_check(token)?
        }
        super::security::SecurityObjectKind::Desktop => {
            security.private_desktop_access_check(token)?
        }
        _ => unreachable!(),
    };
    if !allowed || granted & requested != requested {
        return Err(format!(
            "private target {kind:?} AccessCheck failed: requested={requested:#010x} granted={granted:#010x} allowed={allowed}"
        ));
    }
    Ok(())
}

pub(super) fn verify_user_object_not_inheritable(handle: HANDLE) -> Result<(), String> {
    // SAFETY: zero is a valid initial representation for this output-only POD.
    let mut flags = unsafe { std::mem::zeroed::<USEROBJECTFLAGS>() };
    let mut needed = 0_u32;
    let expected = std::mem::size_of::<USEROBJECTFLAGS>() as u32;
    // SAFETY: handle denotes a live window station or desktop, flags is an
    // exact-sized writable output, and needed records the provider byte count.
    if unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_FLAGS,
            (&raw mut flags).cast(),
            expected,
            &raw mut needed,
        )
    } == 0
    {
        return Err(format!(
            "cannot read private target USER-object flags: {}",
            io::Error::last_os_error()
        ));
    }
    if needed != expected {
        return Err(format!(
            "private target USER-object flags have unexpected size: expected={expected} actual={needed}"
        ));
    }
    if flags.fInherit != 0 {
        return Err("private target USER-object handle is inheritable".to_owned());
    }
    Ok(())
}
