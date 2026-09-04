use super::*;

pub(super) fn target_desktop_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; TARGET_DESKTOP_NONCE_BYTES];
    // SAFETY: system-preferred CNG fills the exact mutable byte array.
    if unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
    {
        return Err("Windows CSPRNG failed for target desktop nonce".to_owned());
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn attest_current_target_desktop() -> Result<(String, String), String> {
    let mut token = ptr::null_mut();
    // SAFETY: the current process is live and output receives one owned token
    // handle used only for exact USER-object policy and AccessCheck readback.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE,
            &raw mut token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = OwnedHandle::new(token)?;
    let context = CapturedTargetDesktop::capture(token.raw())?;
    Ok((context.window_station_name, context.desktop_name))
}

impl From<String> for TargetCreateError {
    fn from(detail: String) -> Self {
        Self {
            detail,
            os_code: None,
            loader_context: false,
            loader_qualification: None,
        }
    }
}

impl TargetCreateError {
    fn loader_context(detail: String) -> Self {
        Self::loader_context_with_os(detail, None)
    }

    fn loader_context_with_os(detail: String, os_code: Option<i32>) -> Self {
        Self {
            detail,
            os_code,
            loader_context: true,
            loader_qualification: None,
        }
    }

    fn from_loader_error(error: TargetDesktopLeaseCreateError) -> Self {
        Self {
            detail: error.detail,
            os_code: error.os_code,
            loader_context: true,
            loader_qualification: error.loader_qualification,
        }
    }
}

impl SuspendedTarget {
    #[allow(clippy::too_many_arguments)] // Native creation requires each authority input explicitly.
    pub fn create(
        token: HANDLE,
        job: &Job,
        command: &NativeWindowsCommandV1,
        environment: &[WindowsEnvironmentEntryV1],
        current_directory: &[u16],
        streams: &StreamSet,
        launcher_pipe: HANDLE,
        certification_fault: Option<WindowsSealedFault>,
        certification_mutant: Option<WindowsSealedMutant>,
    ) -> Result<Self, TargetCreateError> {
        Self::create_with_object_security(
            token,
            job,
            command,
            environment,
            current_directory,
            streams,
            launcher_pipe,
            certification_fault,
            certification_mutant,
            TargetObjectSecurity::LauncherService,
        )
    }

    pub(crate) fn create_nested_canary(
        token: HANDLE,
        initial_thread_token: HANDLE,
        job: &Job,
        command: &NativeWindowsCommandV1,
        environment: &[WindowsEnvironmentEntryV1],
        current_directory: &[u16],
        streams: &StreamSet,
    ) -> Result<NestedSuspendedTarget, TargetCreateError> {
        verify_not_inheritable(initial_thread_token).map_err(TargetCreateError::from)?;
        let requested_before_install =
            super::token::token_attestation_snapshot(initial_thread_token)
                .map_err(TargetCreateError::from)?;
        let target = Self::create_with_object_security(
            token,
            job,
            command,
            environment,
            current_directory,
            streams,
            ptr::null_mut(),
            None,
            None,
            TargetObjectSecurity::NestedCanaryCreator,
        )?;
        let installed =
            super::token::install_thread_token(target.thread.raw(), initial_thread_token)
                .map_err(TargetCreateError::from)?;
        let requested_before_failures =
            super::token::nested_loader_behavior_failures(&requested_before_install.behavior);
        let requested_after_failures = super::token::nested_loader_behavior_failures(
            &installed.requested_after_install.behavior,
        );
        let observed_failures =
            super::token::nested_loader_behavior_failures(&installed.observed_thread.behavior);
        let requested_transition_fields = super::token::envelope_mismatch_fields(
            &requested_before_install.behavior.envelope,
            &installed.requested_after_install.behavior.envelope,
        );
        let observed_transition_fields = super::token::envelope_mismatch_fields(
            &requested_before_install.behavior.envelope,
            &installed.observed_thread.behavior.envelope,
        );
        if requested_before_install.instance.token_id == 0
            || installed.requested_after_install.instance.token_id == 0
            || installed.observed_thread.instance.token_id == 0
            || requested_before_install.instance != installed.requested_after_install.instance
            || requested_before_install.instance != installed.observed_thread.instance
            || requested_before_install.lineage != installed.requested_after_install.lineage
            || requested_before_install.lineage != installed.observed_thread.lineage
            || requested_before_install.behavior != installed.requested_after_install.behavior
            || requested_before_install.behavior != installed.observed_thread.behavior
            || !requested_before_failures.is_empty()
            || !requested_after_failures.is_empty()
            || !observed_failures.is_empty()
        {
            return Err(TargetCreateError::from(format!(
                "nested initial thread token attestation failed: requested_transition_fields=[{}] observed_transition_fields=[{}] requested_before_invariant_failures=[{}] requested_after_invariant_failures=[{}] observed_invariant_failures=[{}] requested_before={requested_before_install:?} requested_after={:?} observed_thread={:?}",
                requested_transition_fields.join(", "),
                observed_transition_fields.join(", "),
                requested_before_failures.join(", "),
                requested_after_failures.join(", "),
                observed_failures.join(", "),
                installed.requested_after_install,
                installed.observed_thread,
            )));
        }
        Ok(NestedSuspendedTarget {
            target,
            initial: installed,
        })
    }

    #[allow(clippy::too_many_arguments)] // Native creation requires each authority input explicitly.
    fn create_with_object_security(
        token: HANDLE,
        job: &Job,
        command: &NativeWindowsCommandV1,
        environment: &[WindowsEnvironmentEntryV1],
        current_directory: &[u16],
        streams: &StreamSet,
        launcher_pipe: HANDLE,
        certification_fault: Option<WindowsSealedFault>,
        certification_mutant: Option<WindowsSealedMutant>,
        object_security: TargetObjectSecurity,
    ) -> Result<Self, TargetCreateError> {
        validate_native_command(command)?;
        let requested_process_snapshot =
            super::token::token_attestation_snapshot(token).map_err(TargetCreateError::from)?;
        let mut desktop_lease = None;
        let mut captured_desktop = None;
        match object_security {
            TargetObjectSecurity::LauncherService => {
                let policy_role = target_user_object_policy_role(command);
                desktop_lease = Some(
                    TargetDesktopLease::create(token, policy_role)
                        .map_err(TargetCreateError::from_loader_error)?,
                );
            }
            TargetObjectSecurity::NestedCanaryCreator => {
                captured_desktop = Some(
                    CapturedTargetDesktop::capture(token)
                        .map_err(TargetCreateError::loader_context)?,
                );
            }
        }
        let desktop_binding = desktop_lease
            .as_ref()
            .map(|desktop| desktop.exact_name.clone())
            .or_else(|| {
                captured_desktop
                    .as_ref()
                    .map(|desktop| desktop.exact_name.clone())
            })
            .ok_or_else(|| {
                TargetCreateError::from("target desktop binding is absent".to_owned())
            })?;
        let mut effective_command = command.clone();
        let mut mutant_inheritable_handles = Vec::new();
        if let Some(kind) = match certification_mutant {
            Some(WindowsSealedMutant::LeakJobHandleToTarget) => Some("job"),
            Some(WindowsSealedMutant::LeakLauncherPipe) => Some("pipe"),
            _ => None,
        } {
            let source = if kind == "job" {
                job.handle()
            } else {
                launcher_pipe
            };
            let inherited = duplicate_local_inheritable(source)?;
            effective_command
                .arguments
                .push("windows-mutant-leaked-handle".encode_utf16().collect());
            effective_command
                .arguments
                .push(kind.encode_utf16().collect());
            effective_command.arguments.push(
                (inherited.raw() as usize as u64)
                    .to_string()
                    .encode_utf16()
                    .collect(),
            );
            mutant_inheritable_handles.push(inherited);
        }
        let mut command_line = encode_command_line(
            &std::iter::once(effective_command.program.clone())
                .chain(effective_command.arguments.iter().cloned())
                .collect::<Vec<_>>(),
        );
        command_line.push(0);
        let mut application = command.program.clone();
        application.push(0);
        let environment = encode_environment(environment)?;
        let process_sddl = match object_security {
            TargetObjectSecurity::LauncherService => super::security::launcher_process_sddl()?,
            TargetObjectSecurity::NestedCanaryCreator => {
                super::security::nested_canary_process_sddl()?
            }
        };
        let process_security = super::security::SecurityDescriptor::from_sddl(&process_sddl)?;
        let process_attributes = process_security.attributes(false);
        let thread_sddl = match object_security {
            TargetObjectSecurity::LauncherService => super::security::launcher_thread_sddl()?,
            TargetObjectSecurity::NestedCanaryCreator => {
                super::security::nested_canary_thread_sddl()?
            }
        };
        let thread_security = super::security::SecurityDescriptor::from_sddl(&thread_sddl)?;
        let thread_attributes = thread_security.attributes(false);
        let mut current_directory = current_directory.to_vec();
        if current_directory.last().copied() != Some(0) {
            current_directory.push(0);
        }
        let mut handles = streams.target_handles().to_vec();
        handles.extend(mutant_inheritable_handles.iter().map(|handle| handle.raw()));
        if !matches!(
            certification_mutant,
            Some(
                WindowsSealedMutant::LeakJobHandleToTarget | WindowsSealedMutant::LeakLauncherPipe
            )
        ) {
            validate_target_handle_list(&handles)?;
        }
        let jobs = [job.handle()];
        let mut process_attributes_manifest = Vec::new();
        if !matches!(
            certification_mutant,
            Some(
                WindowsSealedMutant::AssignJobAfterCreate
                    | WindowsSealedMutant::OmitJobList
                    | WindowsSealedMutant::SkipJobMembershipReadback
            )
        ) {
            process_attributes_manifest.push(Attribute::new(
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                std::mem::size_of_val(&jobs),
            ));
        }
        if certification_mutant != Some(WindowsSealedMutant::OmitHandleList) {
            process_attributes_manifest.push(Attribute::new(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles.as_slice()),
            ));
        }
        let attributes = AttributeList::new(&process_attributes_manifest, certification_fault)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.StartupInfo.lpDesktop = desktop_lease.as_mut().map_or_else(
            || {
                captured_desktop
                    .as_mut()
                    .expect("captured target desktop must exist for nested creation")
                    .startup_name
                    .as_mut_ptr()
            },
            |desktop| desktop.startup_name.as_mut_ptr(),
        );
        startup.lpAttributeList = attributes.raw();
        let mut process = PROCESS_INFORMATION::default();
        reject_fault(certification_fault, WindowsSealedFault::CreateProcessAsUser)?;
        if let Some(lease) = desktop_lease.as_ref() {
            lease
                .attest_live()
                .map_err(TargetCreateError::loader_context)?;
        }
        // SAFETY: all UTF-16 buffers are NUL-terminated; environment is
        // double-NUL-terminated; startup attributes and referenced handle arrays
        // remain live through process creation; output handles become owned.
        let mut service_token = ptr::null_mut();
        let service_token =
            if certification_mutant == Some(WindowsSealedMutant::CreateUnderServiceToken) {
                if unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                        &raw mut service_token,
                    )
                } == 0
                {
                    return Err(TargetCreateError::from(
                        io::Error::last_os_error().to_string(),
                    ));
                }
                Some(OwnedHandle::new(service_token).map_err(TargetCreateError::from)?)
            } else {
                None
            };
        let process_source_before =
            super::token::token_attestation_snapshot(token).map_err(TargetCreateError::from)?;
        super::token::require_same_token_instance(
            "real-target-request-preflight",
            &requested_process_snapshot,
            &process_source_before,
        )
        .map_err(|error| TargetCreateError::from(error.to_string()))?;
        let created = if matches!(
            certification_mutant,
            Some(
                WindowsSealedMutant::UseCreateProcessW
                    | WindowsSealedMutant::SkipTargetTokenReadback
            )
        ) {
            unsafe {
                create_process_native(
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    &raw const process_attributes,
                    &raw const thread_attributes,
                    1,
                    CREATE_SUSPENDED
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_NEW_PROCESS_GROUP,
                    environment.as_ptr().cast::<c_void>(),
                    current_directory.as_ptr(),
                    &raw const startup.StartupInfo,
                    &raw mut process,
                )
            }
        } else {
            unsafe {
                create_process_as_user_native(
                    service_token.as_ref().map_or(token, OwnedHandle::raw),
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    &raw const process_attributes,
                    &raw const thread_attributes,
                    1,
                    CREATE_SUSPENDED
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_NEW_PROCESS_GROUP,
                    environment.as_ptr().cast::<c_void>(),
                    current_directory.as_ptr(),
                    &raw const startup.StartupInfo,
                    &raw mut process,
                )
            }
        };
        if created == 0 {
            let error = io::Error::last_os_error();
            return Err(TargetCreateError {
                detail: error.to_string(),
                os_code: error.raw_os_error(),
                loader_context: false,
                loader_qualification: None,
            });
        }
        let process_handle = OwnedHandle::new(process.hProcess).map_err(TargetCreateError::from)?;
        let thread_handle = OwnedHandle::new(process.hThread).map_err(TargetCreateError::from)?;
        let mut observed_process_snapshot = None;
        if !matches!(
            certification_mutant,
            Some(
                WindowsSealedMutant::UseCreateProcessW
                    | WindowsSealedMutant::CreateUnderServiceToken
                    | WindowsSealedMutant::TrustClientToken
                    | WindowsSealedMutant::SkipTargetTokenReadback
            )
        ) {
            let observed_snapshot =
                super::token::process_token_query_attestation(process_handle.raw())
                    .map_err(TargetCreateError::from)?;
            let process_source_after =
                super::token::token_attestation_snapshot(token).map_err(TargetCreateError::from)?;
            let relation = super::token::require_same_token_instance(
                "real-target-request-invariance",
                &process_source_before,
                &process_source_after,
            )
            .and_then(|()| {
                super::token::require_assigned_process_authority(
                    "target-request-to-real-process",
                    &process_source_before,
                    &observed_snapshot,
                )
                .map(|_| ())
            });
            if let Err(error) = relation {
                unsafe {
                    TerminateProcess(
                        process_handle.raw(),
                        TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS,
                    )
                };
                let _ = unsafe { WaitForSingleObject(process_handle.raw(), 5_000) };
                return Err(TargetCreateError::from(error.to_string()));
            }
            observed_process_snapshot = Some(observed_snapshot);
        }
        let desktop_attestation = desktop_lease.as_ref().map_or_else(
            || captured_desktop.as_ref().unwrap().attest(token),
            TargetDesktopLease::attest_live,
        );
        if let Err(error) = desktop_attestation {
            unsafe {
                TerminateProcess(
                    process_handle.raw(),
                    TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS,
                )
            };
            let _ = unsafe { WaitForSingleObject(process_handle.raw(), 5_000) };
            return Err(TargetCreateError::loader_context(error));
        }
        if certification_mutant == Some(WindowsSealedMutant::AssignJobAfterCreate)
            && unsafe { AssignProcessToJobObject(job.handle(), process_handle.raw()) } == 0
        {
            return Err(TargetCreateError::from(
                io::Error::last_os_error().to_string(),
            ));
        }
        process_security
            .verify_kernel_object(
                process_handle.raw(),
                super::security::SecurityObjectKind::Process,
            )
            .map_err(TargetCreateError::from)?;
        thread_security
            .verify_kernel_object(
                thread_handle.raw(),
                super::security::SecurityObjectKind::Thread,
            )
            .map_err(TargetCreateError::from)?;
        let loader_qualification = desktop_lease
            .as_ref()
            .and_then(TargetDesktopLease::loader_qualification);
        Ok(Self {
            process: process_handle,
            thread: thread_handle,
            process_snapshot: observed_process_snapshot,
            _desktop_lease: desktop_lease,
            desktop_binding,
            process_id: process.dwProcessId,
            creation_observation: TargetCreationObservation {
                used_create_process_as_user: !matches!(
                    certification_mutant,
                    Some(
                        WindowsSealedMutant::UseCreateProcessW
                            | WindowsSealedMutant::SkipTargetTokenReadback
                    )
                ),
                job_list_present: !matches!(
                    certification_mutant,
                    Some(
                        WindowsSealedMutant::AssignJobAfterCreate
                            | WindowsSealedMutant::OmitJobList
                            | WindowsSealedMutant::SkipJobMembershipReadback
                    )
                ),
                handle_list_present: certification_mutant
                    != Some(WindowsSealedMutant::OmitHandleList),
                post_create_job_assignment: certification_mutant
                    == Some(WindowsSealedMutant::AssignJobAfterCreate),
                unexpected_handle_count: mutant_inheritable_handles.len(),
                loader_qualification,
            },
        })
    }

    pub const fn handle(&self) -> HANDLE {
        self.process.raw()
    }

    pub fn desktop_binding(&self) -> &str {
        &self.desktop_binding
    }

    pub fn attest_process_token_snapshot(
        &self,
        observed: &super::token::TokenQueryAttestationSnapshot,
    ) -> Result<(), String> {
        let expected = self.process_snapshot.as_ref().ok_or_else(|| {
            "real-target process snapshot is absent from its creation transcript".to_owned()
        })?;
        super::token::require_same_process_token_query(
            "real-target-process-live",
            expected,
            observed,
        )
        .map_err(|error| error.to_string())
    }

    pub fn desktop_authority_live(&self) -> Result<bool, String> {
        match &self._desktop_lease {
            Some(lease) => match lease.attest_live() {
                Ok(()) => Ok(true),
                Err(_)
                    if unsafe { WaitForSingleObject(lease.bootstrap_process.raw(), 0) }
                        == WAIT_OBJECT_0 =>
                {
                    Ok(false)
                }
                Err(error) => Err(error),
            },
            None => Ok(true),
        }
    }

    pub fn resume(&self, certification_fault: Option<WindowsSealedFault>) -> Result<(), String> {
        reject_fault(certification_fault, WindowsSealedFault::Resume)?;
        if let Some(expected) = self.process_snapshot.as_ref() {
            let observed = super::token::process_token_query_attestation(self.process.raw())?;
            super::token::require_same_process_token_query(
                "real-target-process-before-resume",
                expected,
                &observed,
            )
            .map_err(|error| error.to_string())?;
        }
        if !self.desktop_authority_live()? {
            return Err("target desktop bootstrap exited before workload resume".to_owned());
        }
        // SAFETY: the primary thread is live and has not previously been resumed.
        let previous = unsafe { ResumeThread(self.thread.raw()) };
        if previous == u32::MAX {
            Err(io::Error::last_os_error().to_string())
        } else if previous != 1 {
            Err(format!(
                "target primary thread suspend count was {previous}, expected 1"
            ))
        } else {
            Ok(())
        }
    }

    pub fn wait(&self, duration: Duration) -> Result<bool, String> {
        let timeout = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: process handle remains live for the wait.
        match unsafe { WaitForSingleObject(self.process.raw(), timeout) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error().to_string()),
        }
    }

    pub fn exit_status(&self) -> Result<u32, String> {
        let mut status = 0_u32;
        // SAFETY: process is signaled before this query and output is writable.
        if unsafe { GetExitCodeProcess(self.process.raw(), &raw mut status) } == 0 {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(status)
        }
    }
}

pub(super) fn validate_target_handle_list(handles: &[HANDLE]) -> Result<(), String> {
    if handles.len() != 3 {
        return Err("target handle list must contain exactly stdin, stdout, and stderr".to_owned());
    }
    for (index, handle) in handles.iter().copied().enumerate() {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!("target handle list entry {index} is invalid"));
        }
        if handles[..index].contains(&handle) {
            return Err(format!("target handle list entry {index} is duplicated"));
        }
    }
    Ok(())
}

pub fn certify_target_handle_list_negatives() -> Result<(), String> {
    let first = 1_usize as HANDLE;
    let second = 2_usize as HANDLE;
    let third = 3_usize as HANDLE;
    let omitted_rejected = validate_target_handle_list(&[first, second]).is_err();
    let duplicate_rejected = validate_target_handle_list(&[first, second, second]).is_err();
    let invalid_rejected = validate_target_handle_list(&[first, ptr::null_mut(), third]).is_err()
        && validate_target_handle_list(&[first, INVALID_HANDLE_VALUE, third]).is_err();
    if omitted_rejected && duplicate_rejected && invalid_rejected {
        Ok(())
    } else {
        Err("target HANDLE_LIST negative-shape certification failed".to_owned())
    }
}

pub(super) struct Attribute {
    kind: usize,
    value: *const c_void,
    size: usize,
}

impl Attribute {
    pub(super) const fn new(kind: usize, value: *const c_void, size: usize) -> Self {
        Self { kind, value, size }
    }
}

pub(super) struct AttributeList {
    raw: LPPROC_THREAD_ATTRIBUTE_LIST,
    layout: Layout,
}

impl AttributeList {
    pub(super) fn new(
        attributes: &[Attribute],
        certification_fault: Option<WindowsSealedFault>,
    ) -> Result<Self, String> {
        reject_fault(certification_fault, WindowsSealedFault::AttributeList)?;
        let count = u32::try_from(attributes.len())
            .map_err(|_| "too many process attributes".to_owned())?;
        let mut size = 0_usize;
        // SAFETY: documented size-query call uses a null list and writes size.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &raw mut size) };
        let layout = Layout::from_size_align(size, std::mem::align_of::<usize>())
            .map_err(|error| error.to_string())?;
        // SAFETY: layout has nonzero API-supplied size and native pointer alignment.
        let allocation = unsafe { alloc_zeroed(layout) };
        if allocation.is_null() {
            return Err("process attribute-list allocation failed".to_owned());
        }
        let raw = allocation.cast();
        // SAFETY: allocation has API-requested size and remains owned by Self.
        if unsafe { InitializeProcThreadAttributeList(raw, count, 0, &raw mut size) } == 0 {
            // SAFETY: allocation/layout are the exact pair returned above.
            unsafe { dealloc(allocation, layout) };
            return Err(io::Error::last_os_error().to_string());
        }
        let list = Self { raw, layout };
        for attribute in attributes {
            let fault = if attribute.kind == PROC_THREAD_ATTRIBUTE_JOB_LIST as usize {
                Some(WindowsSealedFault::JobList)
            } else if attribute.kind == PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize {
                Some(WindowsSealedFault::HandleList)
            } else if attribute.kind == PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize {
                None
            } else {
                return Err("unsupported process attribute in sealed target manifest".to_owned());
            };
            if let Some(fault) = fault {
                reject_fault(certification_fault, fault)?;
            }
            // SAFETY: list is initialized; each referenced structured value
            // remains live through the subsequent process-creation call.
            if unsafe {
                UpdateProcThreadAttribute(
                    list.raw,
                    0,
                    attribute.kind,
                    attribute.value,
                    attribute.size,
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
        }
        Ok(list)
    }

    pub(super) const fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.raw
    }
}

pub(super) fn reject_fault(
    actual: Option<WindowsSealedFault>,
    expected: WindowsSealedFault,
) -> Result<(), String> {
    if actual == Some(expected) {
        Err(format!(
            "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected {expected:?}"
        ))
    } else {
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: raw is initialized and allocation/layout remain the exact
        // ownership pair until this single teardown.
        unsafe {
            DeleteProcThreadAttributeList(self.raw);
            dealloc(self.raw.cast(), self.layout);
        }
    }
}

pub fn encode_command_line(arguments: &[Vec<u16>]) -> Vec<u16> {
    memcordon_core::encode_windows_command_line(arguments)
}

pub(super) struct AppContainerProfile {
    name: Vec<u16>,
    sid: *mut c_void,
    active: bool,
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        // SAFETY: name remains NUL-terminated and sid is the exact allocation
        // returned by CreateAppContainerProfile.
        unsafe {
            if self.active {
                DeleteAppContainerProfile(self.name.as_ptr());
            }
            FreeSid(self.sid);
        }
    }
}

impl AppContainerProfile {
    fn delete_and_verify(mut self) -> Result<(), String> {
        // SAFETY: name remains a live NUL-terminated profile name.
        let deleted = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        if deleted < 0 {
            return Err(format!(
                "cannot delete AppContainer qualification profile: HRESULT {deleted:#x}"
            ));
        }
        self.active = false;
        // Re-create the exact same profile name. Fresh creation succeeding is
        // the native absence readback (DeleteAppContainerProfile itself is
        // intentionally idempotent and also succeeds for an absent profile).
        let display = super::pipe::wide_null("MemCordon sealed AppContainer absence readback");
        let description = super::pipe::wide_null("Ephemeral native qualification fixture");
        let mut proof_sid = ptr::null_mut();
        let recreated = unsafe {
            CreateAppContainerProfile(
                self.name.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                ptr::null(),
                0,
                &raw mut proof_sid,
            )
        };
        if recreated < 0 || proof_sid.is_null() {
            return Err(format!(
                "AppContainer qualification profile absence readback returned HRESULT {recreated:#x}"
            ));
        }
        let proof_deleted = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        unsafe { FreeSid(proof_sid) };
        if proof_deleted < 0 {
            return Err(format!(
                "cannot delete AppContainer absence-readback profile: HRESULT {proof_deleted:#x}"
            ));
        }
        Ok(())
    }
}

pub fn run_appcontainer_rejection_client() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let profile_name = format!(
        "memcordon.certification.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    );
    let name = super::pipe::wide_null(&profile_name);
    let display = super::pipe::wide_null("MemCordon sealed AppContainer rejection canary");
    let description = super::pipe::wide_null("Ephemeral native qualification fixture");
    let mut sid = ptr::null_mut();
    // SAFETY: all strings are NUL-terminated, the empty capability inventory
    // permits a null pointer, and sid receives a FreeSid-owned allocation.
    let result = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            description.as_ptr(),
            ptr::null(),
            0,
            &raw mut sid,
        )
    };
    if result < 0 || sid.is_null() {
        return Err(format!(
            "cannot create AppContainer qualification profile: HRESULT {result:#x}"
        ));
    }
    let profile = AppContainerProfile {
        name,
        sid,
        active: true,
    };
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let attributes = AttributeList::new(
        &[Attribute::new(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&raw const capabilities).cast(),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
        )],
        None,
    )?;
    let executable = crate::windows::package::installed_binary();
    let mut command_line = encode_command_line(&[
        executable.as_os_str().encode_wide().collect(),
        "windows-certification-appcontainer"
            .encode_utf16()
            .collect(),
    ]);
    command_line.push(0);
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.raw();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: command line and attribute list remain live for the synchronous
    // call; no handles are inherited into the AppContainer fixture.
    if unsafe {
        create_process_native(
            ptr::null(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            ptr::null(),
            &raw const startup.StartupInfo,
            &raw mut process,
        )
    } == 0
    {
        return Err(format!(
            "cannot create AppContainer qualification client: {}",
            io::Error::last_os_error()
        ));
    }
    let thread = OwnedHandle::new(process.hThread)?;
    let process = OwnedHandle::new(process.hProcess)?;
    drop(thread);
    match unsafe { WaitForSingleObject(process.raw(), 30_000) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => {
            // SAFETY: process is live and owned; forced termination bounds the
            // native rejection fixture without granting it target authority.
            unsafe { TerminateProcess(process.raw(), 125) };
            let _ = unsafe { WaitForSingleObject(process.raw(), 5_000) };
            return Err("AppContainer rejection client timed out".to_owned());
        }
        _ => return Err(io::Error::last_os_error().to_string()),
    }
    let mut exit_code = 0_u32;
    // SAFETY: the process is signaled and the output is writable.
    if unsafe { GetExitCodeProcess(process.raw(), &raw mut exit_code) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if exit_code != 0 {
        return Err(format!(
            "AppContainer rejection client failed with status {exit_code:#x}"
        ));
    }
    profile.delete_and_verify()
}

pub(super) fn target_user_object_policy_role(
    command: &NativeWindowsCommandV1,
) -> super::security::TargetUserObjectPolicyRoleV1 {
    if command.arguments.first().is_some_and(|mode| {
        mode.iter()
            .copied()
            .eq("windows-certification-nested-target".encode_utf16())
    }) {
        super::security::TargetUserObjectPolicyRoleV1::NestedWriteRestrictedDelegation
    } else {
        super::security::TargetUserObjectPolicyRoleV1::DirectTarget
    }
}

pub(super) fn validate_native_command(command: &NativeWindowsCommandV1) -> Result<(), String> {
    if command.program.is_empty()
        || command.program.contains(&0)
        || command.arguments.iter().any(|value| value.contains(&0))
    {
        return Err("native Windows command contains an empty program or NUL".to_owned());
    }
    Ok(())
}

pub fn encode_environment(entries: &[WindowsEnvironmentEntryV1]) -> Result<Vec<u16>, String> {
    memcordon_core::encode_windows_environment_block(entries).map_err(str::to_owned)
}

pub fn process_identity(process: HANDLE) -> Result<WindowsProcessIdentityV1, String> {
    let process_id = unsafe { GetProcessId(process) };
    if process_id == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: process is live and all FILETIME outputs are writable.
    if unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(WindowsProcessIdentityV1 {
        process_id,
        creation_time_100ns: (u64::from(creation.dwHighDateTime) << 32)
            | u64::from(creation.dwLowDateTime),
    })
}

pub fn process_identity_for_pid(
    process_id: u32,
) -> Result<Option<WindowsProcessIdentityV1>, String> {
    // SAFETY: the PID came from a Job process-list kernel readback and the
    // returned handle is adopted immediately.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        return if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            == Some(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)
        {
            Ok(None)
        } else {
            Err(error.to_string())
        };
    }
    let process = OwnedHandle::new(raw)?;
    process_identity(process.raw()).map(Some)
}

#[derive(Debug)]
pub(crate) struct ProcessIdentityObservationError {
    process_id: u32,
    subphase: &'static str,
    service_os_code: Option<i32>,
    retry_os_code: Option<i32>,
    detail: String,
}

impl ProcessIdentityObservationError {
    fn new(
        process_id: u32,
        subphase: &'static str,
        service_os_code: Option<i32>,
        retry_os_code: Option<i32>,
        detail: impl std::fmt::Display,
    ) -> Self {
        Self {
            process_id,
            subphase,
            service_os_code,
            retry_os_code,
            detail: detail.to_string(),
        }
    }

    pub(crate) const fn os_code(&self) -> Option<i32> {
        match self.retry_os_code {
            Some(code) => Some(code),
            None => self.service_os_code,
        }
    }
}

impl std::fmt::Display for ProcessIdentityObservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "subphase={} process_id={} service_os_code={} retry_os_code={} detail={}",
            self.subphase,
            self.process_id,
            self.service_os_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.retry_os_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail,
        )
    }
}

pub(crate) fn process_identity_for_pid_as_authenticated_caller(
    process_id: u32,
    authenticated_primary: HANDLE,
    job: &Job,
) -> Result<Option<WindowsProcessIdentityV1>, ProcessIdentityObservationError> {
    let mut service_os_code = None;
    let mut retry_os_code = None;
    // SAFETY: the PID came from a Job process-list kernel readback and the
    // returned handle is adopted immediately.
    let mut raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if raw.is_null() {
        let service_error = io::Error::last_os_error();
        service_os_code = service_error.raw_os_error();
        let service_code = service_os_code.and_then(|value| u32::try_from(value).ok());
        if service_code == Some(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER) {
            return Ok(None);
        }
        if service_code != Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED) {
            return Err(ProcessIdentityObservationError::new(
                process_id,
                "service-context-process-open",
                service_os_code,
                None,
                service_error,
            ));
        }

        let mut impersonation = ptr::null_mut();
        // SAFETY: authenticated_primary is the launcher-owned primary token
        // admitted from the authenticated caller. The duplicate is local and
        // receives only query and thread-impersonation rights.
        if unsafe {
            DuplicateTokenEx(
                authenticated_primary,
                TOKEN_IMPERSONATE,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &raw mut impersonation,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return Err(ProcessIdentityObservationError::new(
                process_id,
                "caller-impersonation-token-duplicate",
                service_os_code,
                error.raw_os_error(),
                error,
            ));
        }
        let impersonation = OwnedHandle::new(impersonation).map_err(|detail| {
            ProcessIdentityObservationError::new(
                process_id,
                "caller-impersonation-token-adopt",
                service_os_code,
                None,
                detail,
            )
        })?;
        let impersonation_guard =
            ThreadImpersonationGuard::install(impersonation.raw()).map_err(|error| {
                ProcessIdentityObservationError::new(
                    process_id,
                    "caller-thread-impersonation",
                    service_os_code,
                    error.raw_os_error(),
                    error,
                )
            })?;
        // SAFETY: only this process-object open occurs under caller
        // impersonation. Identity query and every service operation execute
        // after the immediate RevertToSelf below.
        raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        let retry_error = raw.is_null().then(io::Error::last_os_error);
        retry_os_code = retry_error.as_ref().and_then(io::Error::raw_os_error);
        if let Err(error) = impersonation_guard.revert() {
            if !raw.is_null() {
                // Adopt the successful retry before returning so it is closed.
                drop(OwnedHandle::new(raw));
            }
            return Err(ProcessIdentityObservationError::new(
                process_id,
                "caller-thread-revert",
                service_os_code,
                retry_os_code.or_else(|| error.raw_os_error()),
                error,
            ));
        }
        drop(impersonation);
        if let Some(error) = retry_error {
            let retry_os_code = error.raw_os_error();
            if retry_os_code.and_then(|value| u32::try_from(value).ok())
                == Some(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)
            {
                return Ok(None);
            }
            return Err(ProcessIdentityObservationError::new(
                process_id,
                "authenticated-caller-process-open",
                service_os_code,
                retry_os_code,
                error,
            ));
        }
    }

    let process = OwnedHandle::new(raw).map_err(|detail| {
        ProcessIdentityObservationError::new(
            process_id,
            "process-handle-adopt",
            service_os_code,
            retry_os_code,
            detail,
        )
    })?;
    let identity = process_identity(process.raw()).map_err(|detail| {
        ProcessIdentityObservationError::new(
            process_id,
            "process-identity-readback",
            service_os_code,
            retry_os_code,
            detail,
        )
    })?;
    if identity.process_id != process_id {
        return Err(ProcessIdentityObservationError::new(
            process_id,
            "process-identity-pid-mismatch",
            service_os_code,
            retry_os_code,
            format!("opened_process_id={}", identity.process_id),
        ));
    }
    let still_contained = job.contains(process.raw()).map_err(|detail| {
        ProcessIdentityObservationError::new(
            process_id,
            "process-job-membership-readback",
            service_os_code,
            retry_os_code,
            detail,
        )
    })?;
    if !still_contained {
        return Ok(None);
    }
    Ok(Some(identity))
}

pub fn verify_image_path(process: HANDLE, expected: &Path) -> Result<(), String> {
    let mut path = vec![0_u16; 32 * 1024];
    let mut length = path.len() as u32;
    // SAFETY: path provides writable storage and length contains its capacity.
    if unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &raw mut length) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    path.truncate(length as usize);
    let actual = PathBuf::from(String::from_utf16_lossy(&path));
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(
            "authenticated service process does not use the installed agent image".to_owned(),
        );
    }
    Ok(())
}
