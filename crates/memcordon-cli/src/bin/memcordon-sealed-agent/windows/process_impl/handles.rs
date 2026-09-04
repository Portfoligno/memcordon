use super::*;

pub struct StreamSet {
    target_stdin: OwnedHandle,
    target_stdout: OwnedHandle,
    target_stderr: OwnedHandle,
    pub remote: Vec<WindowsRemoteStreamV1>,
    relay_retired_event: OwnedHandle,
    pub remote_relay_retired_event: u64,
    frontend_process: HANDLE,
    remote_lease_armed: bool,
}

impl StreamSet {
    pub fn create(
        frontend_process: HANDLE,
        certification_fault: Option<WindowsSealedFault>,
    ) -> Result<Self, String> {
        reject_fault(certification_fault, WindowsSealedFault::StreamCreate)?;
        let (stdin_target, stdin_relay) = pipe_pair(true)?;
        let (stdout_relay, stdout_target) = pipe_pair(true)?;
        let (stderr_relay, stderr_target) = pipe_pair(true)?;
        clear_inherit(stdin_relay.raw())?;
        clear_inherit(stdout_relay.raw())?;
        clear_inherit(stderr_relay.raw())?;
        let mut remote = Vec::new();
        for (role, handle) in [
            (WindowsStreamRoleV1::Stdin, stdin_relay.raw()),
            (WindowsStreamRoleV1::Stdout, stdout_relay.raw()),
            (WindowsStreamRoleV1::Stderr, stderr_relay.raw()),
        ] {
            reject_fault(
                certification_fault,
                WindowsSealedFault::RelayHandleDuplicate,
            )?;
            match duplicate_remote(handle, frontend_process) {
                Ok(remote_handle) => remote.push(WindowsRemoteStreamV1 {
                    role,
                    remote_handle,
                }),
                Err(error) => {
                    for transferred in &remote {
                        let _ = close_remote(transferred.remote_handle, frontend_process);
                    }
                    return Err(error);
                }
            }
        }
        // SAFETY: null security/name create one private, noninheritable,
        // manual-reset event owned by this attempt.
        let relay_retired_event =
            match OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) }) {
                Ok(event) => event,
                Err(error) => {
                    for transferred in &remote {
                        let _ = close_remote(transferred.remote_handle, frontend_process);
                    }
                    return Err(error);
                }
            };
        let remote_relay_retired_event =
            match duplicate_remote(relay_retired_event.raw(), frontend_process) {
                Ok(handle) => handle,
                Err(error) => {
                    for transferred in &remote {
                        let _ = close_remote(transferred.remote_handle, frontend_process);
                    }
                    return Err(error);
                }
            };
        Ok(Self {
            target_stdin: stdin_target,
            target_stdout: stdout_target,
            target_stderr: stderr_target,
            remote,
            relay_retired_event,
            remote_relay_retired_event,
            frontend_process,
            remote_lease_armed: true,
        })
    }

    pub(super) fn target_handles(&self) -> [HANDLE; 3] {
        [
            self.target_stdin.raw(),
            self.target_stdout.raw(),
            self.target_stderr.raw(),
        ]
    }

    pub fn certification_target_handle_values(&self) -> [u64; 3] {
        self.target_handles().map(|handle| handle as usize as u64)
    }

    pub fn accept_remote_handles(&mut self) {
        self.remote_lease_armed = false;
    }

    pub fn relay_retired_event(&self) -> HANDLE {
        self.relay_retired_event.raw()
    }
}

impl Drop for StreamSet {
    fn drop(&mut self) {
        if self.remote_lease_armed {
            for transferred in &self.remote {
                if transferred.remote_handle != 0 {
                    let _ = close_remote(transferred.remote_handle, self.frontend_process);
                }
            }
            if self.remote_relay_retired_event != 0 {
                let _ = close_remote(self.remote_relay_retired_event, self.frontend_process);
            }
        }
    }
}

pub(super) fn pipe_pair(inherit: bool) -> Result<(OwnedHandle, OwnedHandle), String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: i32::from(inherit),
    };
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    // SAFETY: both output pointers and security attributes remain live; each
    // returned handle transfers into an independent OwnedHandle.
    if unsafe {
        CreatePipe(
            &raw mut read,
            &raw mut write,
            &raw const attributes,
            64 * 1024,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok((OwnedHandle::new(read)?, OwnedHandle::new(write)?))
}

pub(super) fn clear_inherit(handle: HANDLE) -> Result<(), String> {
    // SAFETY: handle is live and the call changes only its inherit flag.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

pub fn verify_not_inheritable(handle: HANDLE) -> Result<(), String> {
    let mut flags = 0_u32;
    // SAFETY: handle is owned by the caller and flags is writable output.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else if flags & HANDLE_FLAG_INHERIT != 0 {
        Err("transferred privileged-boundary handle is inheritable".to_owned())
    } else {
        Ok(())
    }
}

pub(super) fn verify_inheritable(handle: HANDLE) -> Result<(), String> {
    let mut flags = 0_u32;
    // SAFETY: handle is owned by the caller and flags is writable output.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else if flags & HANDLE_FLAG_INHERIT == 0 {
        Err("guardian manifest handle is not inheritable".to_owned())
    } else {
        Ok(())
    }
}

pub fn mark_certification_handle_inheritable(handle: HANDLE) -> Result<(), String> {
    // SAFETY: this is called only for certification canaries after privileged
    // boundary adoption; the exact handle list must prove they remain excluded.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

pub(super) fn duplicate_remote(handle: HANDLE, process: HANDLE) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: source/current and target process handles are live; output receives
    // a target-process handle value without making it inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(remote as usize as u64)
    }
}

pub fn duplicate_remote_process_query(handle: HANDLE, process: HANDLE) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: source and target process handles are live; the target receives
    // only query/synchronize rights and the duplicate is non-inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
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

pub(super) fn duplicate_remote_token_query(handle: HANDLE, process: HANDLE) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: handle is a live launcher token-attestation capability and process is
    // the suspended authenticated bootstrap. The remote copy receives exactly
    // the exact query rights needed for TokenSource evidence and is deliberately
    // non-inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            TOKEN_ATTESTATION_QUERY_ACCESS,
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

pub(super) fn duplicate_remote_target_token_capability(
    handle: HANDLE,
    process: HANDLE,
) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: the target token and suspended authenticated holder are live.
    // The holder receives only the rights needed for envelope inspection,
    // AccessCheck, and duplication of its own explicit impersonation token.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            TARGET_TOKEN_CAPABILITY_ACCESS,
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

pub fn revoke_remote_handle(remote_handle: u64, process: HANDLE) -> Result<(), String> {
    close_remote(remote_handle, process)
}

pub(super) fn close_remote(handle: u64, process: HANDLE) -> Result<(), String> {
    close_remote_native(
        super::session_broker::decode_protocol_handle(handle, "remote-revocation")?,
        process,
    )
}

pub(crate) fn revoke_remote_native_handle(
    remote_handle: HANDLE,
    process: HANDLE,
) -> Result<(), String> {
    if remote_handle.is_null() || remote_handle == INVALID_HANDLE_VALUE {
        return Err("remote-revocation native handle is invalid".to_owned());
    }
    close_remote_native(remote_handle, process)
}

pub(super) fn close_remote_native(handle: HANDLE, process: HANDLE) -> Result<(), String> {
    let mut local = ptr::null_mut();
    // SAFETY: process is the live recipient process and handle is a value that
    // this process transferred into it. CLOSE_SOURCE revokes that exact
    // pre-delivery value; the returned local duplicate is immediately owned
    // and closed.
    if unsafe {
        DuplicateHandle(
            process,
            handle,
            GetCurrentProcess(),
            &raw mut local,
            0,
            0,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        drop(OwnedHandle::new(local)?);
        Ok(())
    }
}

pub(super) fn duplicate_local_handle_with_access(
    source: HANDLE,
    requested_access: u32,
    expected_granted_access: u32,
    role: &str,
) -> Result<OwnedHandle, String> {
    let mut duplicate = ptr::null_mut();
    // SAFETY: source is live; the current process receives a non-inheritable
    // duplicate with the exact requested access.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &raw mut duplicate,
            requested_access,
            0,
            0,
        )
    } == 0
    {
        return Err(format!(
            "cannot narrow {role} handle: {}",
            io::Error::last_os_error()
        ));
    }
    let duplicate = OwnedHandle::new(duplicate)?;
    let mut flags = 0_u32;
    // SAFETY: duplicate is live and flags is writable output.
    if unsafe { GetHandleInformation(duplicate.raw(), &raw mut flags) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let inherited = flags & HANDLE_FLAG_INHERIT != 0;
    let actual_granted_access = super::token::granted_handle_access(duplicate.raw())?;
    if inherited || actual_granted_access != expected_granted_access {
        return Err(format!(
            "role={role} operation=duplicate requested_access={requested_access:#010x} expected_granted_access={expected_granted_access:#010x} actual_granted_access={actual_granted_access:#010x} flags={flags:#010x} inherited={inherited}"
        ));
    }
    Ok(duplicate)
}

pub(crate) struct SessionBrokerCreatedHolder {
    _job: OwnedHandle,
    pub process: OwnedHandle,
    pub thread: OwnedHandle,
    pub primary_thread_id: u32,
    pub identity: WindowsProcessIdentityV1,
    pub query: super::token::TokenQueryAttestationSnapshot,
    pub broker_source: super::token::TokenAttestationSnapshot,
    pub holder_effective: super::token::TokenAttestationSnapshot,
    pub station_creation_carrier: OwnedHandle,
    pub station_creation_evidence: super::token::TokenAttestationSnapshot,
    pub desktop_creation_carrier: OwnedHandle,
    pub desktop_creation_evidence: super::token::TokenAttestationSnapshot,
    armed: bool,
}

impl SessionBrokerCreatedHolder {
    pub(crate) fn terminate(&mut self) {
        if self.armed {
            // SAFETY: process is the broker-created suspended holder. Failure
            // paths must not leave it alive in the launcher-owned Job.
            unsafe {
                TerminateProcess(self.process.raw(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)
            };
            self.armed = false;
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SessionBrokerCreatedHolder {
    fn drop(&mut self) {
        self.terminate();
    }
}

pub(crate) fn create_session_broker_holder(
    target_session_id: u32,
    holder_pipe_name: &str,
    holder_nonce: &str,
    launcher_process: HANDLE,
    launcher_job_handle: u64,
) -> Result<SessionBrokerCreatedHolder, String> {
    validate_target_desktop_bootstrap_nonce(holder_nonce)?;
    let expected_pipe_name = format!(
        "{}{}",
        super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
        holder_nonce,
    );
    if target_session_id == 0 || holder_pipe_name != expected_pipe_name || launcher_job_handle == 0
    {
        return Err("session-broker holder launch request is not canonical".to_owned());
    }

    let mut local_job = ptr::null_mut();
    // SAFETY: launcher_process was authenticated with PROCESS_DUP_HANDLE and
    // launcher_job_handle is treated only as a value in that process. The
    // broker receives the exact minimal assignment/query capability.
    if unsafe {
        DuplicateHandle(
            launcher_process,
            super::session_broker::decode_protocol_handle(launcher_job_handle, "launcher-job")?,
            GetCurrentProcess(),
            &raw mut local_job,
            super::session_broker::HOLDER_JOB_BROKER_ACCESS,
            0,
            0,
        )
    } == 0
    {
        return Err(format!(
            "cannot adopt launcher session-holder Job capability: {}",
            io::Error::last_os_error(),
        ));
    }
    let local_job = OwnedHandle::new(local_job)?;
    verify_not_inheritable(local_job.raw())?;
    if super::token::granted_handle_access(local_job.raw())?
        != super::session_broker::HOLDER_JOB_BROKER_ACCESS
    {
        return Err("session-broker Job capability access differs from contract".to_owned());
    }
    Job::verify_session_holder_handle(local_job.raw())?;
    Job::verify_session_holder_empty_handle(local_job.raw())?;

    let holder_token = super::token::derive_session_broker_holder_primary(target_session_id)?;
    let holder_launch_before =
        super::token::token_attestation_snapshot(holder_token.launch_token.raw())?;
    super::token::require_same_token_instance(
        "session-broker-holder-final-to-launch",
        &holder_token.holder_effective,
        &holder_launch_before,
    )
    .map_err(|error| error.to_string())?;
    let executable = super::package::installed_target_desktop_bootstrap();
    let _image_sha256 = super::package::validate_installed_target_desktop_bootstrap()?;
    use std::os::windows::ffi::OsStrExt;
    let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
    application.push(0);
    let mut command_line = encode_command_line(&[
        executable.as_os_str().encode_wide().collect(),
        "holder".encode_utf16().collect(),
        holder_pipe_name.encode_utf16().collect(),
        holder_nonce.encode_utf16().collect(),
    ]);
    command_line.push(0);
    let jobs = [local_job.raw()];
    let attributes = AttributeList::new(
        &[Attribute::new(
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            jobs.as_ptr().cast(),
            std::mem::size_of_val(&jobs),
        )],
        None,
    )?;
    let process_security =
        SecurityDescriptor::from_sddl(&super::security::session_holder_process_sddl()?)?;
    let process_attributes = process_security.attributes(false);
    let thread_security =
        SecurityDescriptor::from_sddl(&super::security::session_holder_thread_sddl()?)?;
    let thread_attributes = thread_security.attributes(false);
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    // Empty, rather than NULL, prevents the target-session holder from
    // inheriting the session-0 broker's USER objects. The nonce-private
    // station does not exist yet: after admission the holder must create it
    // before observing any ambient station or desktop binding.
    let mut empty_desktop = [0_u16];
    startup.StartupInfo.lpDesktop = empty_desktop.as_mut_ptr();
    startup.lpAttributeList = attributes.raw();
    let mut environment = [0_u16, 0_u16];
    let mut current_directory = super::package::install_root()
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    current_directory.push(0);
    let mut created = PROCESS_INFORMATION::default();
    super::token::with_session_broker_launch_privileges(|| {
        // SAFETY: all inputs are fixed, NUL-terminated, and remain live. The
        // Job attribute assigns the suspended process atomically; no handle
        // inherits. The disposable thread token scopes the two privileges
        // required only while assigning the primary token and quota.
        if unsafe {
            create_process_as_user_native(
                holder_token.launch_token.raw(),
                application.as_ptr(),
                command_line.as_mut_ptr(),
                &raw const process_attributes,
                &raw const thread_attributes,
                0,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_mut_ptr().cast(),
                current_directory.as_ptr(),
                &raw const startup.StartupInfo,
                &raw mut created,
            )
        } == 0
        {
            Err(format!(
                "CreateProcessAsUserW failed for brokered session holder: {}",
                io::Error::last_os_error(),
            ))
        } else {
            Ok(())
        }
    })?;
    let process = OwnedHandle::new(created.hProcess)?;
    let thread = OwnedHandle::new(created.hThread)?;
    let result = (|| {
        if created.dwProcessId == 0 || created.dwThreadId == 0 {
            return Err(format!(
                "brokered holder creation returned a zero identity: process_id={} primary_thread_id={}",
                created.dwProcessId, created.dwThreadId,
            ));
        }
        // SAFETY: thread is the still-live creator handle for the suspended
        // primary thread.
        let thread_process_id = unsafe { GetProcessIdOfThread(thread.raw()) };
        if thread_process_id != created.dwProcessId {
            return Err(format!(
                "brokered holder primary-thread association differs: expected_pid={} actual_pid={} primary_thread_id={}",
                created.dwProcessId, thread_process_id, created.dwThreadId,
            ));
        }
        let mut in_job = 0_i32;
        // SAFETY: process and local_job are live; output is writable.
        if unsafe {
            windows_sys::Win32::System::JobObjects::IsProcessInJob(
                process.raw(),
                local_job.raw(),
                &raw mut in_job,
            )
        } == 0
            || in_job == 0
        {
            return Err("brokered holder is absent from the launcher-owned Job".to_owned());
        }
        process_security
            .verify_kernel_object(process.raw(), super::security::SecurityObjectKind::Process)?;
        thread_security
            .verify_kernel_object(thread.raw(), super::security::SecurityObjectKind::Thread)?;
        verify_image_path(process.raw(), &executable)?;
        let identity = process_identity(process.raw())?;
        if identity.process_id != created.dwProcessId {
            return Err(format!(
                "brokered holder process identity differs: expected_pid={} actual_pid={}",
                created.dwProcessId, identity.process_id,
            ));
        }
        let query = super::token::process_token_query_attestation(process.raw())?;
        let holder_launch_after =
            super::token::token_attestation_snapshot(holder_token.launch_token.raw())?;
        super::token::require_same_token_instance(
            "session-broker-holder-launch-invariance",
            &holder_launch_before,
            &holder_launch_after,
        )
        .map_err(|error| error.to_string())?;
        super::token::require_assigned_process_authority(
            "session-broker-holder-launch-to-process",
            &holder_launch_before,
            &query,
        )
        .map_err(|error| error.to_string())?;
        Ok((identity, query))
    })();
    let (identity, query) = match result {
        Ok(evidence) => evidence,
        Err(error) => {
            // SAFETY: the process is still suspended and private to this call.
            unsafe { TerminateProcess(process.raw(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS) };
            return Err(error);
        }
    };
    let broker_source = holder_token.broker_source.clone();
    let holder_effective = holder_token.holder_effective.clone();
    drop(holder_token.launch_token);
    let broker_thread = duplicate_local_handle_with_access(
        thread.raw(),
        super::session_broker::HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,
        super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,
        "broker-holder-thread",
    )?;
    drop(thread);
    Ok(SessionBrokerCreatedHolder {
        _job: local_job,
        process,
        thread: broker_thread,
        primary_thread_id: created.dwThreadId,
        identity,
        query,
        broker_source,
        holder_effective,
        station_creation_carrier: holder_token.station_creation_carrier,
        station_creation_evidence: holder_token.station_creation_evidence,
        desktop_creation_carrier: holder_token.desktop_creation_carrier,
        desktop_creation_evidence: holder_token.desktop_creation_evidence,
        armed: true,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteHandleObjectIdentity {
    Absent,
    DifferentObject,
    SameObject,
}

pub(crate) fn compare_remote_handle_object(
    source_process: HANDLE,
    remote_value: HANDLE,
    expected_local: HANDLE,
) -> Result<RemoteHandleObjectIdentity, String> {
    let mut snapshot = ptr::null_mut();
    // SAFETY: source_process is a live process handle with PROCESS_DUP_HANDLE;
    // remote_value is deliberately interpreted in that process's namespace,
    // and the current process receives an independently owned snapshot.
    if unsafe {
        DuplicateHandle(
            source_process,
            remote_value,
            GetCurrentProcess(),
            &raw mut snapshot,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) {
            Ok(RemoteHandleObjectIdentity::Absent)
        } else {
            Err(format!(
                "duplicate remote handle candidate for object identity: native_code={:?} detail={error}",
                error.raw_os_error()
            ))
        };
    }
    let snapshot = OwnedHandle::new(snapshot)?;
    // SAFETY: both arguments are live local handles. A false result is the
    // expected different-object collision classification, not an API failure.
    if unsafe { CompareObjectHandles(snapshot.raw(), expected_local) } != 0 {
        Ok(RemoteHandleObjectIdentity::SameObject)
    } else {
        Ok(RemoteHandleObjectIdentity::DifferentObject)
    }
}
