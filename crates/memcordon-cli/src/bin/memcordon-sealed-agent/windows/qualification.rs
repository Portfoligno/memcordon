use memcordon_core::{
    BoundaryMechanismEvidence, ChildTermination, NativeWindowsCommandV1, RestartSafetyProof,
    RunOutcome, WINDOWS_CONTROL_PIPE, WINDOWS_PREAUTHORIZATION_FAULTS,
    WINDOWS_PUBLIC_PROTOCOL_VERSION, WINDOWS_QUALIFICATION_SCHEMA_VERSION,
    WINDOWS_RETIREMENT_FAULTS, WindowsCertificationObservationsV1,
    WindowsFaultRejectionObservationV1, WindowsLaunchPolicyV1, WindowsLaunchRequestV1,
    WindowsLifetimeV1, WindowsPreauthorizationFaultMatrixEvidenceV1, WindowsProviderRequestV1,
    WindowsProviderResponseV1, WindowsQualificationReceiptV1,
    WindowsRetirementFaultMatrixEvidenceV1, WindowsSealedEvidenceV2, WindowsSealedFault,
    WindowsSealedMutant, WindowsTokenMatrixEvidenceV1, WindowsTokenScenarioEvidenceV1,
};

struct NativeCanary {
    evidence: WindowsSealedEvidenceV2,
    exact_handle_inheritance_verified: bool,
    public_pipe_security_verified: bool,
    private_pipe_security_verified: bool,
    nested_alternate_token_verified: bool,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct NestedChildObservationV1 {
    schema_version: u32,
    child_identity: memcordon_core::WindowsProcessIdentityV1,
}

struct TokenFixtureObservation {
    envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,
    restricted_sid_count: u32,
    token_is_restricted: bool,
    enabled_sensitive_privilege_count: u32,
    administrator_deny_only: bool,
}

impl TokenFixtureObservation {
    fn current(administrator_deny_only: bool) -> Result<Self, String> {
        Ok(Self {
            envelope: super::token::current_thread_envelope()?,
            restricted_sid_count: super::token::current_thread_restricted_sid_count()?,
            token_is_restricted: super::token::current_thread_is_restricted()?,
            enabled_sensitive_privilege_count:
                super::token::current_thread_enabled_sensitive_privilege_count()?,
            administrator_deny_only,
        })
    }

    fn scenario(
        self,
        name: &str,
        initial_target_token_matches_caller: bool,
    ) -> WindowsTokenScenarioEvidenceV1 {
        WindowsTokenScenarioEvidenceV1 {
            name: name.to_owned(),
            caller_envelope: self.envelope,
            restricted_sid_count: self.restricted_sid_count,
            token_is_restricted: self.token_is_restricted,
            enabled_sensitive_privilege_count: self.enabled_sensitive_privilege_count,
            administrator_deny_only: self.administrator_deny_only,
            initial_target_token_matches_caller,
        }
    }
}

struct RemoveFileGuard(std::path::PathBuf);

impl Drop for RemoveFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct CleanupCreationMarkerGuard(std::path::PathBuf);

impl Drop for CleanupCreationMarkerGuard {
    fn drop(&mut self) {
        for extension in ["ready", "start", "result"] {
            let _ = std::fs::remove_file(self.0.with_extension(extension));
        }
    }
}

pub(super) struct QualificationAdmission {
    pipe: super::pipe::OwnedHandle,
    ended: bool,
}

impl QualificationAdmission {
    pub(super) fn begin(
        scope: &str,
        _package_lease: &crate::windows::package::PackageLease,
    ) -> Result<Self, String> {
        let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
        super::pipe::write_frame(
            pipe.raw(),
            &WindowsProviderRequestV1::QualificationBegin {
                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                scope: scope.to_owned(),
            },
        )?;
        match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
            WindowsProviderResponseV1::QualificationAuthenticated { schema_version }
                if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION => {}
            WindowsProviderResponseV1::Reject { rejection, .. } => {
                return Err(format!("{}: {}", rejection.code, rejection.detail));
            }
            _ => {
                return Err(
                    "control service did not authenticate the qualification admission".to_owned(),
                );
            }
        }
        super::pipe::write_frame(
            pipe.raw(),
            &WindowsProviderRequestV1::QualificationAcquire {
                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            },
        )?;
        match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
            WindowsProviderResponseV1::QualificationReady { schema_version }
                if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
            {
                Ok(Self { pipe, ended: false })
            }
            WindowsProviderResponseV1::Reject { rejection, .. } => {
                Err(format!("{}: {}", rejection.code, rejection.detail))
            }
            _ => Err("control service returned an invalid qualification admission".to_owned()),
        }
    }

    fn authorize_child(
        &mut self,
        child_process: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), String> {
        super::pipe::write_frame(
            self.pipe.raw(),
            &WindowsProviderRequestV1::QualificationAuthorizeChild {
                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                child_process_identity: super::process::process_identity(child_process)?,
            },
        )?;
        match super::pipe::read_frame::<WindowsProviderResponseV1>(self.pipe.raw())? {
            WindowsProviderResponseV1::QualificationChildAuthorized { schema_version }
                if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
            {
                Ok(())
            }
            _ => Err("control service did not authorize the qualification child".to_owned()),
        }
    }

    fn finish(mut self) -> Result<(), String> {
        super::pipe::write_frame(
            self.pipe.raw(),
            &WindowsProviderRequestV1::QualificationEnd {
                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            },
        )?;
        match super::pipe::read_frame::<WindowsProviderResponseV1>(self.pipe.raw())? {
            WindowsProviderResponseV1::QualificationEnded { schema_version }
                if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
            {
                self.ended = true;
                Ok(())
            }
            _ => Err("control service did not retire qualification admission".to_owned()),
        }
    }
}

impl Drop for QualificationAdmission {
    fn drop(&mut self) {
        if !self.ended {
            let _ = super::pipe::write_frame(
                self.pipe.raw(),
                &WindowsProviderRequestV1::QualificationEnd {
                    schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                },
            );
        }
    }
}

fn signal_relay_retirement(event: &mut Option<super::pipe::OwnedHandle>) -> Result<(), String> {
    let event = event
        .take()
        .ok_or_else(|| "relay-retirement event was not transferred".to_owned())?;
    // SAFETY: event is the launcher-created handle adopted from the complete
    // StreamsPrepared frame and remains live through this signal.
    if unsafe { windows_sys::Win32::System::Threading::SetEvent(event.raw()) } == 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

impl std::ops::Deref for NativeCanary {
    type Target = WindowsSealedEvidenceV2;

    fn deref(&self) -> &Self::Target {
        &self.evidence
    }
}

pub fn local_receipt() -> Result<WindowsQualificationReceiptV1, String> {
    let path = qualification_path();
    let bytes = std::fs::read(&path).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-UNQUALIFIED: {}: {error}; run package verify and qualify from an elevated terminal",
            path.display()
        )
    })?;
    let receipt: WindowsQualificationReceiptV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if !receipt.qualified || !receipt.is_consistent() {
        return Err(
            "stored Windows qualification receipt is incomplete or inconsistent".to_owned(),
        );
    }
    Ok(receipt)
}

pub fn token_observations() -> Result<WindowsTokenMatrixEvidenceV1, String> {
    let path = crate::windows::package::state_root()
        .join("package")
        .join("token-matrix.json");
    let observations: WindowsTokenMatrixEvidenceV1 = serde_json::from_slice(
        &std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .map_err(|error| error.to_string())?;
    if observations.is_complete() {
        Ok(observations)
    } else {
        Err("stored Windows token-matrix evidence is incomplete".to_owned())
    }
}

pub fn probe() -> Result<WindowsQualificationReceiptV1, String> {
    let pipe = super::pipe::connect(memcordon_core::WINDOWS_CONTROL_PIPE)?;
    super::pipe::write_frame(
        pipe.raw(),
        &memcordon_core::WindowsProviderRequestV1::Probe {
            schema_version: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
        },
    )?;
    match super::pipe::read_frame::<memcordon_core::WindowsProviderResponseV1>(pipe.raw())? {
        memcordon_core::WindowsProviderResponseV1::Probe { qualification, .. }
            if qualification.qualified && qualification.is_consistent() =>
        {
            Ok(qualification)
        }
        memcordon_core::WindowsProviderResponseV1::Reject { rejection, .. } => {
            Err(format!("{}: {}", rejection.code, rejection.detail))
        }
        _ => Err("Windows sealed control service returned an invalid probe receipt".to_owned()),
    }
}

pub fn qualify_and_store() -> Result<WindowsQualificationReceiptV1, String> {
    let lease = crate::windows::package::PackageLease::acquire()?;
    let (result, _lease) = qualify_and_store_for_scope("direct", lease)?;
    result
}

pub(super) fn qualify_and_store_for_scope(
    scope: &str,
    lease: crate::windows::package::PackageLease,
) -> Result<
    (
        Result<WindowsQualificationReceiptV1, String>,
        crate::windows::package::PackageLease,
    ),
    String,
> {
    let mut admission = match QualificationAdmission::begin(scope, &lease) {
        Ok(admission) => admission,
        Err(error) => return Ok((Err(error), lease)),
    };
    let result = qualify_and_store_admitted(&mut admission);
    let finish = admission.finish();
    let result = match (result, finish) {
        (Ok(receipt), Ok(())) => Ok(receipt),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(finish)) => Err(format!(
            "{error}; qualification admission retirement failed: {finish}"
        )),
    };
    Ok((result, lease))
}

fn qualify_and_store_admitted(
    admission: &mut QualificationAdmission,
) -> Result<WindowsQualificationReceiptV1, String> {
    crate::windows::package::verify_installed()?;
    let manager = super::service_manager::manager()?;
    let control_process_id = super::service_manager::running_process_id(
        &manager,
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,
    )?;
    let launcher_process_id = super::service_manager::running_process_id(
        &manager,
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
    )?;
    let control_service_privileges_observed =
        super::token::process_has_privileges(control_process_id, &["SeImpersonatePrivilege"])?;
    let launcher_service_privileges_observed = super::token::process_has_privileges(
        launcher_process_id,
        &["SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"],
    )?;
    super::security::prepare_current_process_for_restricted_broker()?;
    let elevated_observation = TokenFixtureObservation::current(false)?;
    if !elevated_observation.envelope.elevated {
        return Err("elevated-admin qualification fixture is not elevated".to_owned());
    }
    let native = native_public_canary("windows-certification-nested-target")?;
    let (restricted_observation, restricted_native) = {
        let _restricted = super::token::impersonate_restricted_current_thread()?;
        if super::token::current_thread_restricted_sid_count()? == 0 {
            return Err("restricted-token fixture has no restricting SID".to_owned());
        }
        (
            TokenFixtureObservation::current(false)?,
            native_public_canary("windows-certification-target")?,
        )
    };
    let (ordinary_observation, ordinary_native) = {
        let _ordinary = super::token::impersonate_ordinary_current_thread()?;
        let observation = TokenFixtureObservation::current(false)?;
        if observation.envelope.elevated {
            return Err("ordinary-token fixture remained elevated".to_owned());
        }
        (
            observation,
            native_public_canary("windows-certification-target")?,
        )
    };
    let (write_restricted_observation, write_restricted_native) = {
        let _restricted = super::token::impersonate_write_restricted_current_thread()?;
        if super::token::current_thread_restricted_sid_count()? == 0 {
            return Err("write-restricted fixture has no restricting SID".to_owned());
        }
        (
            TokenFixtureObservation::current(false)?,
            native_public_canary("windows-certification-target")?,
        )
    };
    let (low_integrity_observation, low_integrity_native) = {
        let _restricted = super::token::impersonate_low_integrity_current_thread()?;
        let observation = TokenFixtureObservation::current(false)?;
        if observation.envelope.integrity_level != "S-1-16-4096" {
            return Err("low-integrity fixture did not acquire the low mandatory label".to_owned());
        }
        (
            observation,
            native_public_canary("windows-certification-target")?,
        )
    };
    let (deny_only_observation, deny_only_native) = {
        let _restricted = super::token::impersonate_deny_only_admin_current_thread()?;
        const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
        if !super::token::current_thread_group_has_attributes(
            "S-1-5-32-544",
            SE_GROUP_USE_FOR_DENY_ONLY,
        )? || super::token::current_thread_restricted_sid_count()? == 0
        {
            return Err(
                "deny-only fixture lacks its deny-only administrator/restricting SID".to_owned(),
            );
        }
        (
            TokenFixtureObservation::current(true)?,
            native_public_canary("windows-certification-target")?,
        )
    };
    super::process::run_appcontainer_rejection_client()?;
    let launcher_session = super::token::process_envelope(launcher_process_id)?.session_id;
    let different_session_supported = elevated_observation.envelope.session_id != launcher_session;
    let token_matrix = WindowsTokenMatrixEvidenceV1 {
        schema_version: 1,
        scenarios: vec![
            elevated_observation
                .scenario("elevated-admin", native.initial_target_token_matches_caller),
            ordinary_observation.scenario(
                "ordinary-user",
                ordinary_native.initial_target_token_matches_caller,
            ),
            restricted_observation.scenario(
                "restricted",
                restricted_native.initial_target_token_matches_caller,
            ),
            TokenFixtureObservation {
                envelope: write_restricted_observation.envelope.clone(),
                restricted_sid_count: write_restricted_observation.restricted_sid_count,
                token_is_restricted: write_restricted_observation.token_is_restricted,
                enabled_sensitive_privilege_count: write_restricted_observation
                    .enabled_sensitive_privilege_count,
                administrator_deny_only: false,
            }
            .scenario(
                "write-restricted",
                write_restricted_native.initial_target_token_matches_caller,
            ),
            write_restricted_observation.scenario(
                "disabled-privileges",
                write_restricted_native.initial_target_token_matches_caller,
            ),
            deny_only_observation.scenario(
                "deny-only-admin",
                deny_only_native.initial_target_token_matches_caller,
            ),
            low_integrity_observation.scenario(
                "low-integrity",
                low_integrity_native.initial_target_token_matches_caller,
            ),
        ],
        appcontainer_rejected_before_target: true,
        different_session_supported,
        different_session_verified: different_session_supported
            && native.initial_target_token_matches_caller,
    };
    if !token_matrix.is_complete() {
        return Err("native Windows token-matrix evidence is incomplete".to_owned());
    }
    let frontend_loss_cleanup_verified = frontend_loss_canary(admission)?;
    let recursive_provider_request_denied = recursive_provider_canary().map(|()| true)?;
    super::process::certify_target_handle_list_negatives()?;
    let nested_alternate_token = native.nested_alternate_token_verified
        && native.active_processes_zero
        && native.job_membership_independent_of_token;
    if crate::windows::package::certification_faults_enabled() {
        preauthorization_fault_matrix()?;
        retirement_fault_matrix()?;
    }
    let mut receipt = WindowsQualificationReceiptV1 {
        schema_version: WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        provider_identity: format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        ),
        control_service_identity: "MemCordonSealedControl:LocalService:restricted".to_owned(),
        launcher_service_identity: "MemCordonSealedLauncher:LocalSystem:restricted".to_owned(),
        package_verified: crate::windows::package::verify_installed().is_ok(),
        public_pipe_security_verified: native.public_pipe_security_verified,
        private_pipe_security_verified: native.private_pipe_security_verified,
        control_service_privileges_verified: control_service_privileges_observed,
        launcher_service_privileges_verified: launcher_service_privileges_observed,
        caller_token_authentication_verified: native.caller_token_authenticated,
        restricted_caller_token_verified: restricted_native.caller_token_authenticated
            && restricted_native.initial_target_token_matches_caller
            && restricted_native.job_membership_independent_of_token
            && write_restricted_native.caller_token_authenticated
            && write_restricted_native.initial_target_token_matches_caller
            && write_restricted_native.job_membership_independent_of_token
            && low_integrity_native.caller_token_authenticated
            && low_integrity_native.initial_target_token_matches_caller
            && low_integrity_native.job_membership_independent_of_token
            && deny_only_native.caller_token_authenticated
            && deny_only_native.initial_target_token_matches_caller
            && deny_only_native.job_membership_independent_of_token
            && ordinary_native.caller_token_authenticated
            && ordinary_native.initial_target_token_matches_caller
            && ordinary_native.job_membership_independent_of_token,
        primary_token_duplication_verified: native.initial_target_token_matches_caller,
        create_process_as_user_verified: native.target_created_suspended,
        job_list_supported: native.job_list_applied_at_creation,
        handle_list_supported: native.handle_list_applied_at_creation,
        nested_host_job_supported: native.job_list_applied_at_creation,
        kill_on_close_verified: native.kill_on_close_verified,
        breakaway_denied: native.breakaway_denied,
        completion_port_verified: native.completion_port_associated,
        guardian_verified: native.guardian_ready && native.guardian_reaped,
        frontend_loss_cleanup_verified,
        alternate_token_child_contained: nested_alternate_token,
        nested_child_job_contained: nested_alternate_token,
        recursive_provider_request_denied,
        exact_handle_inheritance_verified: native.exact_handle_inheritance_verified
            && native.inherited_handles_verified,
        active_processes_zero_verified: native.active_processes_zero,
        relays_retired_verified: native.relays_retired,
        recovery_complete: recovery_complete()?,
        qualified: false,
    };
    receipt.qualified = receipt.is_consistent_if_qualified();
    if !receipt.is_consistent() {
        return Err("native Windows qualification produced an inconsistent receipt".to_owned());
    }
    store_package_evidence("token-matrix.json", &token_matrix)?;
    let path = qualification_path();
    let parent = path
        .parent()
        .ok_or_else(|| "qualification path has no parent".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let staged = path.with_extension("json.new");
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    std::fs::write(&staged, bytes).map_err(|error| error.to_string())?;
    super::record::replace_atomically(&staged, &path)?;
    Ok(receipt)
}

fn store_package_evidence<T: serde::Serialize>(name: &str, value: &T) -> Result<(), String> {
    let path = crate::windows::package::state_root()
        .join("package")
        .join(name);
    let staged = path.with_extension("json.new");
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    std::fs::write(&staged, bytes).map_err(|error| error.to_string())?;
    super::record::replace_atomically(&staged, &path)
}

fn preauthorization_fault_matrix() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let marker_root = crate::windows::package::state_root()
        .join("package")
        .join("certification-markers");
    std::fs::create_dir_all(&marker_root).map_err(|error| error.to_string())?;
    let mut rejections = Vec::with_capacity(WINDOWS_PREAUTHORIZATION_FAULTS.len());
    for (index, fault) in WINDOWS_PREAUTHORIZATION_FAULTS.iter().copied().enumerate() {
        let marker = marker_root.join(format!(
            "{}-{}-{}.marker",
            std::process::id(),
            index,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos()
        ));
        let _marker_cleanup = RemoveFileGuard(marker.clone());
        let request = WindowsLaunchRequestV1 {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            nonce: format!(
                "qualification-fault-{}-{}-{}",
                std::process::id(),
                index,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|error| error.to_string())?
                    .as_nanos()
            ),
            command: NativeWindowsCommandV1 {
                program: crate::windows::package::installed_binary()
                    .as_os_str()
                    .encode_wide()
                    .collect(),
                arguments: vec![
                    "windows-certification-marker".encode_utf16().collect(),
                    marker.as_os_str().encode_wide().collect(),
                ],
            },
            environment: Vec::new(),
            current_directory: crate::windows::package::install_root()
                .as_os_str()
                .encode_wide()
                .collect(),
            policy: WindowsLaunchPolicyV1 {
                memory_limit_bytes: None,
                absolute_deadline_millis: None,
                lifetime: WindowsLifetimeV1::Command,
                poll_interval_millis: 10,
                signal_grace_millis: 1_000,
                command_exit_grace_millis: 0,
                limit_grace_millis: 0,
            },
        };
        rejections.push(WindowsFaultRejectionObservationV1 {
            fault,
            rejection: run_certification_fault(fault, request, &marker, false)?,
        });
    }
    let evidence = WindowsPreauthorizationFaultMatrixEvidenceV1 {
        schema_version: 1,
        faults: WINDOWS_PREAUTHORIZATION_FAULTS.to_vec(),
        first_instruction_markers_absent: true,
        recovery_clear_after_each_fault: true,
        rejections,
        terminal_frame_truncation_rejected: terminal_frame_truncation_canary()?,
    };
    let path = crate::windows::package::state_root()
        .join("package")
        .join("preauthorization-fault-matrix.json");
    let mut bytes = serde_json::to_vec_pretty(&evidence).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    std::fs::write(path, bytes).map_err(|error| error.to_string())
}

fn terminal_frame_truncation_canary() -> Result<bool, String> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    let mut reader = std::ptr::null_mut();
    let mut writer = std::ptr::null_mut();
    // SAFETY: both outputs are writable and null attributes create a private,
    // synchronous anonymous pipe.
    if unsafe { CreatePipe(&raw mut reader, &raw mut writer, std::ptr::null(), 0) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let reader = super::pipe::OwnedHandle::new(reader)?;
    let writer = super::pipe::OwnedHandle::new(writer)?;
    let payload = br#"{"kind":"terminal"}"#;
    let declared = u32::try_from(payload.len()).map_err(|error| error.to_string())?;
    let mut frame = declared.to_le_bytes().to_vec();
    frame.extend_from_slice(
        payload
            .strip_suffix(b"}")
            .ok_or_else(|| "terminal-frame canary payload has no suffix".to_owned())?,
    );
    let writer_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut written = 0_u32;
        // SAFETY: frame and output storage remain live for the synchronous write.
        if unsafe {
            WriteFile(
                writer.raw(),
                frame.as_ptr(),
                u32::try_from(frame.len()).map_err(|error| error.to_string())?,
                &raw mut written,
                std::ptr::null_mut(),
            )
        } == 0
            || usize::try_from(written).ok() != Some(frame.len())
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    });
    let rejected = super::pipe::read_frame::<WindowsProviderResponseV1>(reader.raw()).is_err();
    writer_thread
        .join()
        .map_err(|_| "terminal-frame writer panicked".to_owned())??;
    Ok(rejected)
}

fn retirement_fault_matrix() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let marker_root = crate::windows::package::state_root()
        .join("package")
        .join("certification-markers");
    let mut rejections = Vec::with_capacity(WINDOWS_RETIREMENT_FAULTS.len());
    for (index, fault) in WINDOWS_RETIREMENT_FAULTS.iter().copied().enumerate() {
        let marker = marker_root.join(format!(
            "retirement-{}-{}-{}.marker",
            std::process::id(),
            index,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos()
        ));
        let _marker_cleanup = RemoveFileGuard(marker.clone());
        let request = WindowsLaunchRequestV1 {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            nonce: format!(
                "qualification-retirement-fault-{}-{}-{}",
                std::process::id(),
                index,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|error| error.to_string())?
                    .as_nanos()
            ),
            command: NativeWindowsCommandV1 {
                program: crate::windows::package::installed_binary()
                    .as_os_str()
                    .encode_wide()
                    .collect(),
                arguments: vec![
                    if fault == memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization
                    {
                        "windows-certification-marker-hold".encode_utf16().collect()
                    } else {
                        "windows-certification-marker".encode_utf16().collect()
                    },
                    marker.as_os_str().encode_wide().collect(),
                ],
            },
            environment: Vec::new(),
            current_directory: crate::windows::package::install_root()
                .as_os_str()
                .encode_wide()
                .collect(),
            policy: WindowsLaunchPolicyV1 {
                memory_limit_bytes: None,
                absolute_deadline_millis: None,
                lifetime: WindowsLifetimeV1::Command,
                poll_interval_millis: 10,
                signal_grace_millis: 1_000,
                command_exit_grace_millis: 0,
                limit_grace_millis: 0,
            },
        };
        rejections.push(WindowsFaultRejectionObservationV1 {
            fault,
            rejection: run_certification_fault(fault, request, &marker, true)?,
        });
    }
    let path = crate::windows::package::state_root()
        .join("package")
        .join("retirement-fault-matrix.json");
    let evidence = WindowsRetirementFaultMatrixEvidenceV1 {
        schema_version: 1,
        faults: WINDOWS_RETIREMENT_FAULTS.to_vec(),
        first_instruction_markers_observed: true,
        recovery_clear_after_each_fault: true,
        rejections,
    };
    let mut bytes = serde_json::to_vec_pretty(&evidence).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    std::fs::write(path, bytes).map_err(|error| error.to_string())
}

pub fn certification_observations() -> Result<WindowsCertificationObservationsV1, String> {
    let package = crate::windows::package::state_root().join("package");
    let preauthorization: WindowsPreauthorizationFaultMatrixEvidenceV1 = serde_json::from_slice(
        &std::fs::read(package.join("preauthorization-fault-matrix.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let retirement: WindowsRetirementFaultMatrixEvidenceV1 = serde_json::from_slice(
        &std::fs::read(package.join("retirement-fault-matrix.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let evidence = WindowsCertificationObservationsV1 {
        schema_version: 1,
        preauthorization,
        retirement,
    };
    if evidence.is_complete() {
        Ok(evidence)
    } else {
        Err("Windows certification fault-matrix observations are incomplete".to_owned())
    }
}

fn run_certification_fault(
    fault: memcordon_core::WindowsSealedFault,
    request: WindowsLaunchRequestV1,
    marker: &std::path::Path,
    expect_release: bool,
) -> Result<memcordon_core::ProviderRejectionEvidence, String> {
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let nonce = request.nonce.clone();
    let request_sha256 =
        super::record::digest(&serde_json::to_vec(&request).map_err(|error| error.to_string())?);
    let caller_process_identity = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    let mut attempt_identity = request.nonce.as_bytes().to_vec();
    attempt_identity.extend_from_slice(&caller_process_identity.process_id.to_le_bytes());
    attempt_identity.extend_from_slice(&caller_process_identity.creation_time_100ns.to_le_bytes());
    attempt_identity.extend_from_slice(request_sha256.as_bytes());
    let expected_attempt_id = super::record::digest(&attempt_identity);
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::CertificationFault {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            fault,
            attempt_id: expected_attempt_id.clone(),
            request_sha256: request_sha256.clone(),
            caller_process_identity,
            launch: request,
        },
    )?;
    let mut attempt_id = None;
    let mut streams = Vec::new();
    let mut relay_retired_event = None;
    let mut authorized = false;
    loop {
        match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
            WindowsProviderResponseV1::StreamsPrepared {
                schema_version,
                attempt_id: received,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                streams: remote,
                relay_retired_event_handle,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned_nonce == nonce
                && returned_digest == request_sha256
                && received == expected_attempt_id
                && attempt_id.is_none() =>
            {
                memcordon_core::validate_windows_stream_manifest(&remote).map_err(str::to_owned)?;
                streams = remote
                    .into_iter()
                    .map(|stream| {
                        super::pipe::OwnedHandle::new(
                            stream.remote_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                relay_retired_event = Some(super::pipe::OwnedHandle::new(
                    relay_retired_event_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                )?);
                attempt_id = Some(received.clone());
                super::pipe::write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::RelaysReady {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: received,
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
            }
            WindowsProviderResponseV1::RelaysAbort {
                schema_version,
                attempt_id: received,
                nonce: returned_nonce,
                request_sha256: returned_digest,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && attempt_id.as_deref() == Some(received.as_str())
                && returned_nonce == nonce
                && returned_digest == request_sha256
                && !authorized =>
            {
                streams.clear();
                signal_relay_retirement(&mut relay_retired_event)?;
                super::pipe::write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::RelaysRetired {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: received,
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
            }
            WindowsProviderResponseV1::Reject {
                schema_version,
                attempt_id: received,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                rejection,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned_nonce == nonce
                && returned_digest == request_sha256
                && received == expected_attempt_id
                && attempt_id
                    .as_ref()
                    .is_none_or(|expected| expected == &received) =>
            {
                drop(streams);
                drop(relay_retired_event);
                if rejection.code != "MCSEALED-WINDOWS-CERTIFICATION-FAULT"
                    || rejection.target_released != expect_release
                    || authorized != expect_release
                    || !rejection.is_consistent()
                    || (rejection.cleanup_attempted
                        && !rejection
                            .restart_safety
                            .is_safe_for(memcordon_core::BoundaryRequirement::Sealed))
                    || marker.exists() != expect_release
                    || !recovery_status()?
                {
                    return Err(format!(
                        "fault {fault:?} failed preauthorization, marker, cleanup, or recovery proof"
                    ));
                }
                if marker.exists() {
                    std::fs::remove_file(marker).map_err(|error| error.to_string())?;
                }
                return Ok(rejection);
            }
            WindowsProviderResponseV1::TargetAuthorized {
                schema_version,
                attempt_id: received,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                child_pid: _,
            } if expect_release
                && !authorized
                && schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && received == expected_attempt_id
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                authorized = true;
            }
            WindowsProviderResponseV1::TargetRetired {
                schema_version,
                attempt_id: received,
                nonce: returned_nonce,
                request_sha256: returned_digest,
            } if expect_release
                && authorized
                && schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && received == expected_attempt_id
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                streams.clear();
                signal_relay_retirement(&mut relay_retired_event)?;
                super::pipe::write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::RelaysRetired {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: received,
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
            }
            WindowsProviderResponseV1::Terminal(_) => {
                return Err(format!(
                    "fault {fault:?} returned terminal success instead of the injected rejection"
                ));
            }
            _ => return Err(format!("fault {fault:?} returned an unbound response")),
        }
    }
}

fn frontend_loss_canary(admission: &mut QualificationAdmission) -> Result<bool, String> {
    use std::os::windows::io::AsRawHandle;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let marker_root = crate::windows::package::state_root()
        .join("package")
        .join("certification-markers");
    std::fs::create_dir_all(&marker_root).map_err(|error| error.to_string())?;
    let release_marker = marker_root.join(format!(
        "frontend-release-{}-{}.marker",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    ));
    let _release_marker_cleanup = RemoveFileGuard(release_marker.clone());
    let mut frontend = Command::new(executable)
        .arg("windows-certification-frontend")
        .arg(&release_marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    admission.authorize_child(frontend.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE)?;
    std::fs::write(&release_marker, b"authorized\n").map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = frontend.try_wait().map_err(|error| error.to_string())? {
            if status.success() {
                break;
            }
            return Err(format!(
                "frontend-loss qualification client failed: {status}"
            ));
        }
        if Instant::now() >= deadline {
            let _ = frontend.kill();
            let _ = frontend.wait();
            return Err("frontend-loss qualification attempt was not observed".to_owned());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let deadline = Instant::now() + Duration::from_secs(45);
    while !recovery_status()? {
        if Instant::now() >= deadline {
            return Err("frontend-loss qualification record did not retire".to_owned());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(true)
}

fn verify_target_process_is_protected(process_id: u32) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE};

    let _restricted = super::token::impersonate_restricted_current_thread()?;
    // SAFETY: the PID is authenticated from the durable authorized-attempt
    // record and the probe requests no inherited handle.
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, process_id) };
    if handle.is_null() {
        Ok(())
    } else {
        drop(super::pipe::OwnedHandle::new(handle)?);
        Err("restricted frontend retained target process termination access".to_owned())
    }
}

pub fn frontend_loss_client(release_marker: &std::ffi::OsStr) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    let release_marker = std::path::Path::new(release_marker);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !release_marker.is_file() {
        if Instant::now() >= deadline {
            return Err("frontend-loss qualification release was not authorized".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let executable = crate::windows::package::installed_binary();
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        nonce: format!("frontend-loss-{}", std::process::id()),
        command: NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec!["windows-certification-hold".encode_utf16().collect()],
        },
        environment: Vec::new(),
        current_directory: crate::windows::package::install_root()
            .as_os_str()
            .encode_wide()
            .collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: None,
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 1_000,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    let nonce = request.nonce.clone();
    let request_sha256 =
        super::record::digest(&serde_json::to_vec(&request).map_err(|error| error.to_string())?);
    super::pipe::write_frame(pipe.raw(), &WindowsProviderRequestV1::Launch(request))?;
    let mut streams = Vec::new();
    let mut relay_retired_event = None;
    let mut active_attempt_id = None;
    loop {
        match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
            WindowsProviderResponseV1::StreamsPrepared {
                attempt_id,
                schema_version,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                streams: received,
                relay_retired_event_handle,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                for stream in received {
                    streams.push(super::pipe::OwnedHandle::new(
                        stream.remote_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                    )?);
                }
                relay_retired_event = Some(super::pipe::OwnedHandle::new(
                    relay_retired_event_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                )?);
                super::pipe::write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::RelaysReady {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: attempt_id.clone(),
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
                active_attempt_id = Some(attempt_id);
            }
            WindowsProviderResponseV1::TargetAuthorized {
                schema_version,
                attempt_id,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                child_pid,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && active_attempt_id.as_deref() == Some(attempt_id.as_str())
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                verify_target_process_is_protected(child_pid)?;
                drop(relay_retired_event);
                return Ok(());
            }
            WindowsProviderResponseV1::Reject { rejection, .. } => {
                return Err(format!("{}: {}", rejection.code, rejection.detail));
            }
            _ => {
                return Err(
                    "frontend-loss client reached terminal state before external loss".to_owned(),
                );
            }
        }
    }
}

fn authority_fault_name(fault: WindowsSealedFault) -> &'static str {
    match fault {
        WindowsSealedFault::FrontendDisconnectedAfterAuthorization => "frontend-disconnected",
        WindowsSealedFault::FrontendKilledAfterAuthorization => "frontend-killed",
        WindowsSealedFault::ControlWorkerKilledAfterAuthorization => "control-worker-killed",
        WindowsSealedFault::ControlServiceKilledAfterAuthorization => "control-service-killed",
        WindowsSealedFault::LauncherWorkerKilledAfterAuthorization => "launcher-worker-killed",
        WindowsSealedFault::LauncherServiceKilledAfterAuthorization => "launcher-service-killed",
        WindowsSealedFault::AllJobOwnersClosedAfterAuthorization => "all-job-owners-closed",
        _ => "unsupported",
    }
}

fn parse_authority_fault(value: &std::ffi::OsStr) -> Result<WindowsSealedFault, String> {
    match value.to_string_lossy().as_ref() {
        "frontend-disconnected" => Ok(WindowsSealedFault::FrontendDisconnectedAfterAuthorization),
        "frontend-killed" => Ok(WindowsSealedFault::FrontendKilledAfterAuthorization),
        "control-worker-killed" => Ok(WindowsSealedFault::ControlWorkerKilledAfterAuthorization),
        "control-service-killed" => Ok(WindowsSealedFault::ControlServiceKilledAfterAuthorization),
        "launcher-worker-killed" => Ok(WindowsSealedFault::LauncherWorkerKilledAfterAuthorization),
        "launcher-service-killed" => {
            Ok(WindowsSealedFault::LauncherServiceKilledAfterAuthorization)
        }
        "all-job-owners-closed" => Ok(WindowsSealedFault::AllJobOwnersClosedAfterAuthorization),
        _ => Err("unknown Windows authority-loss scenario".to_owned()),
    }
}

pub fn authority_loss_client(
    fault: &std::ffi::OsStr,
    marker: &std::ffi::OsStr,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let fault = parse_authority_fault(fault)?;
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let executable = crate::windows::package::installed_binary();
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        nonce: format!(
            "authority-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos()
        ),
        command: NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec![
                "windows-certification-marker-hold".encode_utf16().collect(),
                marker.encode_wide().collect(),
            ],
        },
        environment: Vec::new(),
        current_directory: crate::windows::package::install_root()
            .as_os_str()
            .encode_wide()
            .collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: None,
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 1_000,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    let nonce = request.nonce.clone();
    let request_sha256 =
        super::record::digest(&serde_json::to_vec(&request).map_err(|error| error.to_string())?);
    let caller = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    let mut identity = Vec::new();
    identity.extend_from_slice(nonce.as_bytes());
    identity.extend_from_slice(&caller.process_id.to_le_bytes());
    identity.extend_from_slice(&caller.creation_time_100ns.to_le_bytes());
    identity.extend_from_slice(request_sha256.as_bytes());
    let attempt_id = super::record::digest(&identity);
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::CertificationFault {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            fault,
            attempt_id: attempt_id.clone(),
            request_sha256: request_sha256.clone(),
            caller_process_identity: caller,
            launch: request,
        },
    )?;
    let mut stream_handles = Vec::new();
    let mut relay_event = None;
    loop {
        let response = match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw()) {
            Ok(response) => response,
            Err(_)
                if fault == WindowsSealedFault::ControlWorkerKilledAfterAuthorization
                    && std::path::Path::new(marker).is_file() =>
            {
                let worker_lost =
                    std::path::Path::new(marker).with_extension("control-worker-lost");
                let release = std::path::Path::new(marker).with_extension("frontend-release");
                std::fs::write(&worker_lost, b"control worker retired\n")
                    .map_err(|error| error.to_string())?;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while !release.is_file() {
                    if std::time::Instant::now() >= deadline {
                        return Err(
                            "control-worker fixture did not receive frontend release".to_owned()
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                return Ok(());
            }
            Err(_) if std::path::Path::new(marker).is_file() => return Ok(()),
            Err(error) => return Err(error),
        };
        match response {
            WindowsProviderResponseV1::StreamsPrepared {
                schema_version,
                attempt_id: returned,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                streams,
                relay_retired_event_handle,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned == attempt_id
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                stream_handles = streams
                    .into_iter()
                    .map(|stream| {
                        super::pipe::OwnedHandle::new(
                            stream.remote_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                relay_event = Some(super::pipe::OwnedHandle::new(
                    relay_retired_event_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                )?);
                super::pipe::write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::RelaysReady {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: returned,
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
            }
            WindowsProviderResponseV1::TargetAuthorized {
                schema_version,
                attempt_id: returned,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                child_pid: _,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned == attempt_id
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                if fault == WindowsSealedFault::FrontendDisconnectedAfterAuthorization {
                    drop(stream_handles);
                    drop(relay_event);
                    return Ok(());
                }
                if fault == WindowsSealedFault::FrontendKilledAfterAuthorization {
                    std::thread::sleep(std::time::Duration::from_secs(5 * 60));
                    return Err("frontend-kill fixture was not externally terminated".to_owned());
                }
            }
            WindowsProviderResponseV1::Reject { rejection, .. } => {
                return Err(format!("{}: {}", rejection.code, rejection.detail));
            }
            _ => {}
        }
    }
}

pub fn authority_loss_observations()
-> Result<memcordon_core::WindowsAuthorityLossEvidenceV1, String> {
    use std::os::windows::io::AsRawHandle;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if !crate::windows::package::certification_faults_enabled() {
        return Err("authority-loss certification requires ephemeral CI installation".to_owned());
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let marker_root = crate::windows::package::state_root()
        .join("package")
        .join("certification-markers");
    std::fs::create_dir_all(&marker_root).map_err(|error| error.to_string())?;
    let scenarios = [
        WindowsSealedFault::FrontendDisconnectedAfterAuthorization,
        WindowsSealedFault::FrontendKilledAfterAuthorization,
        WindowsSealedFault::ControlWorkerKilledAfterAuthorization,
        WindowsSealedFault::ControlServiceKilledAfterAuthorization,
        WindowsSealedFault::LauncherWorkerKilledAfterAuthorization,
        WindowsSealedFault::LauncherServiceKilledAfterAuthorization,
        WindowsSealedFault::AllJobOwnersClosedAfterAuthorization,
    ];
    let mut observed = Vec::with_capacity(scenarios.len());
    for (index, fault) in scenarios.into_iter().enumerate() {
        let marker = marker_root.join(format!(
            "authority-{}-{}-{}.marker",
            std::process::id(),
            index,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos()
        ));
        let _marker_cleanup = RemoveFileGuard(marker.clone());
        let worker_lost = marker.with_extension("control-worker-lost");
        let _worker_lost_cleanup = RemoveFileGuard(worker_lost.clone());
        let frontend_release = marker.with_extension("frontend-release");
        let _frontend_release_cleanup = RemoveFileGuard(frontend_release.clone());
        let mut frontend = Command::new(&executable)
            .arg("windows-certification-authority-frontend")
            .arg(authority_fault_name(fault))
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.is_file() {
            if let Some(status) = frontend.try_wait().map_err(|error| error.to_string())? {
                return Err(format!(
                    "authority-loss frontend exited before authorization for {fault:?}: {status}"
                ));
            }
            if Instant::now() >= deadline {
                let _ = frontend.kill();
                let _ = frontend.wait();
                return Err(format!(
                    "authority-loss target did not authorize for {fault:?}"
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if fault == WindowsSealedFault::FrontendKilledAfterAuthorization {
            // SAFETY: child is the exact frontend spawned above and this native
            // scenario deliberately removes it after the target marker exists.
            if unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(
                    frontend.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                    0xC000_013A,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        if fault == WindowsSealedFault::ControlWorkerKilledAfterAuthorization {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !worker_lost.is_file() {
                if let Some(status) = frontend.try_wait().map_err(|error| error.to_string())? {
                    return Err(format!(
                        "control-worker fixture lost frontend authority early: {status}"
                    ));
                }
                if Instant::now() >= deadline {
                    let _ = frontend.kill();
                    let _ = frontend.wait();
                    return Err("control worker did not retire after authorization".to_owned());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            // Keep the authenticated frontend and all adopted relay handles
            // alive after the isolated worker has gone. The launcher and
            // guardian must not retire a healthy workload merely because the
            // private control path disappeared.
            let read_heartbeat = || -> Result<(u32, u64), String> {
                let value = std::fs::read_to_string(&marker).map_err(|error| error.to_string())?;
                let mut fields = value.split_whitespace();
                let process_id = fields
                    .next()
                    .ok_or_else(|| "authority target process id is absent".to_owned())?
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?;
                let heartbeat = fields
                    .next()
                    .ok_or_else(|| "authority target heartbeat is absent".to_owned())?
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?;
                if fields.next().is_some() {
                    return Err("authority target marker has extra fields".to_owned());
                }
                Ok((process_id, heartbeat))
            };
            let heartbeat_deadline = Instant::now() + Duration::from_secs(5);
            let (target_pid, heartbeat_before) = loop {
                if let Ok(value) = read_heartbeat() {
                    break value;
                }
                if Instant::now() >= heartbeat_deadline {
                    return Err(
                        "target heartbeat was not readable after control-worker loss".to_owned(),
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            loop {
                if frontend
                    .try_wait()
                    .map_err(|error| error.to_string())?
                    .is_some()
                    || super::process::process_identity_for_pid(target_pid)?.is_none()
                {
                    return Err(
                        "control-worker loss retired live frontend or target authority prematurely"
                            .to_owned(),
                    );
                }
                match read_heartbeat() {
                    Ok((observed_pid, heartbeat_after))
                        if observed_pid == target_pid && heartbeat_after > heartbeat_before =>
                    {
                        break;
                    }
                    Ok(_) | Err(_) => {}
                }
                if Instant::now() >= heartbeat_deadline {
                    return Err(
                        "target did not execute after isolated control-worker loss".to_owned()
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            std::fs::write(&frontend_release, b"remove frontend authority\n")
                .map_err(|error| error.to_string())?;
        }
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if frontend
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = frontend.kill();
                let _ = frontend.wait();
                return Err(format!(
                    "authority-loss frontend did not retire for {fault:?}"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        restart_provider_for_authority_fault(fault)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        while !recovery_status()? {
            if Instant::now() >= deadline {
                return Err(format!(
                    "authority-loss record did not recover for {fault:?}"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        observed.push(fault);
    }
    let machine_restart_recovery_exercised = certify_machine_restart_through_provider()?;
    let fault_matrix = certification_observations()?;
    let evidence = memcordon_core::WindowsAuthorityLossEvidenceV1 {
        schema_version: 1,
        frontend_killed: observed.contains(&WindowsSealedFault::FrontendKilledAfterAuthorization),
        frontend_disconnected: observed
            .contains(&WindowsSealedFault::FrontendDisconnectedAfterAuthorization),
        control_worker_lost: observed
            .contains(&WindowsSealedFault::ControlWorkerKilledAfterAuthorization),
        control_service_lost: observed
            .contains(&WindowsSealedFault::ControlServiceKilledAfterAuthorization),
        launcher_worker_lost: observed
            .contains(&WindowsSealedFault::LauncherWorkerKilledAfterAuthorization),
        launcher_service_lost: observed
            .contains(&WindowsSealedFault::LauncherServiceKilledAfterAuthorization),
        guardian_killed_before_authorization: fault_matrix
            .preauthorization
            .faults
            .contains(&WindowsSealedFault::GuardianKilledBeforeAuthorization),
        guardian_killed_after_authorization: fault_matrix
            .retirement
            .faults
            .contains(&WindowsSealedFault::GuardianKilledAfterAuthorization),
        all_job_owners_closed: observed
            .contains(&WindowsSealedFault::AllJobOwnersClosedAfterAuthorization),
        durable_service_restart_recovered: observed
            .contains(&WindowsSealedFault::LauncherWorkerKilledAfterAuthorization)
            && observed.contains(&WindowsSealedFault::LauncherServiceKilledAfterAuthorization),
        machine_restart_recovery_exercised,
        active_processes_zero_after_each: observed.len() == scenarios.len(),
        relays_retired_after_each: observed.len() == scenarios.len(),
        records_retired_after_each: observed.len() == scenarios.len(),
    };
    if !evidence.is_complete() {
        return Err("native Windows authority-loss evidence is incomplete".to_owned());
    }
    store_package_evidence("authority-loss.json", &evidence)?;
    Ok(evidence)
}

pub fn runtime_mutant_observations() -> Result<memcordon_core::WindowsMutantKillEvidenceV1, String>
{
    if !crate::windows::package::certification_faults_enabled() {
        return Err("mutant certification requires ephemeral CI installation".to_owned());
    }
    let runtime_count = memcordon_core::WINDOWS_RELEASE_MUTANT_VARIANTS
        .iter()
        .position(|mutant| *mutant == WindowsSealedMutant::FallBackToStandard)
        .ok_or_else(|| "runtime mutant boundary is absent".to_owned())?;
    let mut observations = Vec::with_capacity(runtime_count);
    for (mutant, (_, mapped_test)) in memcordon_core::WINDOWS_RELEASE_MUTANT_VARIANTS
        [..runtime_count]
        .iter()
        .copied()
        .zip(&memcordon_core::WINDOWS_RELEASE_MUTANTS[..runtime_count])
    {
        let native_observation = run_provider_mutant(mutant)?;
        if !native_observation.rejects(mutant) {
            return Err(format!(
                "runtime mutant {} survived its external checker",
                mutant.as_str()
            ));
        }
        observations.push(memcordon_core::WindowsMutantObservationV1 {
            mutant,
            mapped_test: (*mapped_test).to_owned(),
            native_observation,
        });
    }
    for mutant in [
        WindowsSealedMutant::FallBackToStandard,
        WindowsSealedMutant::AdvertiseWithoutCertificate,
    ] {
        let mapped_test = memcordon_core::WINDOWS_RELEASE_MUTANTS
            .iter()
            .find_map(|(name, mapped_test)| (*name == mutant.as_str()).then_some(*mapped_test))
            .ok_or_else(|| format!("mutant {} has no mapped test", mutant.as_str()))?;
        let native_observation = memcordon_platform::certify_windows_platform_mutant(mutant)
            .ok_or_else(|| format!("platform mutant {} was not observed", mutant.as_str()))?;
        if !native_observation.rejects(mutant) {
            return Err(format!(
                "platform mutant {} survived its external checker",
                mutant.as_str()
            ));
        }
        observations.push(memcordon_core::WindowsMutantObservationV1 {
            mutant,
            mapped_test: mapped_test.to_owned(),
            native_observation,
        });
    }
    let evidence = memcordon_core::WindowsMutantKillEvidenceV1 {
        schema_version: 1,
        observations,
    };
    store_package_evidence("runtime-mutants.json", &evidence)?;
    Ok(evidence)
}

fn run_provider_mutant(
    mutant: WindowsSealedMutant,
) -> Result<memcordon_core::WindowsMutantNativeObservationV1, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Threading::SetEvent;

    let marker = crate::windows::package::state_root()
        .join("package")
        .join("certification-markers")
        .join(format!(
            "mutant-{}-{}.marker",
            std::process::id(),
            mutant.as_str()
        ));
    let _marker_cleanup = RemoveFileGuard(marker.clone());
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let executable = crate::windows::package::installed_binary();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    let target_mode = if mutant == WindowsSealedMutant::AcceptRecursiveProvider {
        "windows-certification-recursive-mutant"
    } else {
        "windows-certification-marker-hold"
    };
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        nonce: format!("mutant-{}-{}", std::process::id(), now.as_nanos()),
        command: NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec![
                target_mode.encode_utf16().collect(),
                marker.as_os_str().encode_wide().collect(),
            ],
        },
        environment: Vec::new(),
        current_directory: crate::windows::package::install_root()
            .as_os_str()
            .encode_wide()
            .collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: Some(
                u64::try_from(now.as_millis())
                    .map_err(|error| error.to_string())?
                    .saturating_add(5_000),
            ),
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 100,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    let nonce = request.nonce.clone();
    let request_sha256 =
        super::record::digest(&serde_json::to_vec(&request).map_err(|error| error.to_string())?);
    let caller = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    let mut identity = Vec::new();
    identity.extend_from_slice(nonce.as_bytes());
    identity.extend_from_slice(&caller.process_id.to_le_bytes());
    identity.extend_from_slice(&caller.creation_time_100ns.to_le_bytes());
    identity.extend_from_slice(request_sha256.as_bytes());
    let attempt_id = super::record::digest(&identity);
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::CertificationMutant {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            mutant,
            attempt_id: attempt_id.clone(),
            request_sha256: request_sha256.clone(),
            caller_process_identity: caller,
            launch: request,
        },
    )?;
    let mut streams = Vec::new();
    let mut relay_event = None;
    let mut relays_ready = false;
    let mut external_observation = None;
    let mut hook_observation = None;
    let mut hook_process = None;
    loop {
        match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
            WindowsProviderResponseV1::CertificationMutantHookObserved(receipt) => {
                let remote = receipt.remote_observation_handle.ok_or_else(|| {
                    "mutant hook omitted its query-only process handle".to_owned()
                })?;
                let process = super::pipe::OwnedHandle::new(
                    remote as usize as windows_sys::Win32::Foundation::HANDLE,
                )?;
                if !receipt.binding_matches(&attempt_id, &nonce, &request_sha256)
                    || receipt.mutant != mutant
                    || receipt.terminal_candidate.is_some()
                {
                    return Err("mutant hook receipt binding is invalid".to_owned());
                }
                if hook_observation.replace(receipt.hook_observation).is_some()
                    || hook_process.replace(process).is_some()
                {
                    return Err("mutant hook emitted more than one native receipt".to_owned());
                }
            }
            WindowsProviderResponseV1::StreamsPrepared {
                schema_version,
                attempt_id: returned,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                streams: remote_streams,
                relay_retired_event_handle,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned == attempt_id
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                streams = remote_streams
                    .into_iter()
                    .map(|stream| {
                        super::pipe::OwnedHandle::new(
                            stream.remote_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                relay_event = Some(super::pipe::OwnedHandle::new(
                    relay_retired_event_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                )?);
                if mutant != WindowsSealedMutant::ResumeBeforeRelays {
                    super::pipe::write_frame(
                        pipe.raw(),
                        &WindowsProviderRequestV1::RelaysReady {
                            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                            attempt_id: attempt_id.clone(),
                            nonce: nonce.clone(),
                            request_sha256: request_sha256.clone(),
                        },
                    )?;
                    relays_ready = true;
                }
            }
            WindowsProviderResponseV1::TargetAuthorized {
                schema_version,
                attempt_id: returned,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                child_pid,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned == attempt_id
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                if mutant == WindowsSealedMutant::ResumeBeforeRelays && !relays_ready {
                    external_observation = Some(
                        memcordon_core::WindowsMutantNativeObservationV1::PrematureAuthorization {
                            guardian_ready: true,
                            relays_ready: false,
                            target_marker_observed: true,
                        },
                    );
                    super::pipe::write_frame(
                        pipe.raw(),
                        &WindowsProviderRequestV1::Cancel {
                            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                            attempt_id: attempt_id.clone(),
                            nonce: nonce.clone(),
                            request_sha256: request_sha256.clone(),
                            signal: 15,
                        },
                    )?;
                }
                if mutant == WindowsSealedMutant::SkipTargetTokenReadback {
                    if !matches!(
                        hook_observation.as_ref(),
                        Some(memcordon_core::WindowsMutantHookObservationV1::TargetTokenReadbackSkipped {
                            child_pid: hooked_pid,
                        }) if *hooked_pid == child_pid
                    ) {
                        return Err(
                            "target-token hook receipt child identity is invalid".to_owned()
                        );
                    }
                    let process = hook_process.as_ref().ok_or_else(|| {
                        "target-token mutant omitted its adopted query handle".to_owned()
                    })?;
                    let target_token = super::token::process_token(process.raw())?;
                    let target_envelope = super::token::envelope(target_token.raw())?;
                    let authenticated_envelope = super::token::current_thread_envelope()?;
                    if target_envelope == authenticated_envelope {
                        return Err(
                            "target-token readback mutant did not change the target envelope"
                                .to_owned(),
                        );
                    }
                    external_observation = Some(
                        memcordon_core::WindowsMutantNativeObservationV1::ExternalTargetTokenMismatch {
                            authenticated_envelope_sha256: super::record::digest(
                                &serde_json::to_vec(&authenticated_envelope)
                                    .map_err(|error| error.to_string())?,
                            ),
                            target_envelope_sha256: super::record::digest(
                                &serde_json::to_vec(&target_envelope)
                                    .map_err(|error| error.to_string())?,
                            ),
                        },
                    );
                    super::pipe::write_frame(
                        pipe.raw(),
                        &WindowsProviderRequestV1::Cancel {
                            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                            attempt_id: attempt_id.clone(),
                            nonce: nonce.clone(),
                            request_sha256: request_sha256.clone(),
                            signal: 15,
                        },
                    )?;
                }
                if mutant == WindowsSealedMutant::SkipJobMembershipReadback {
                    if !matches!(
                        hook_observation.as_ref(),
                        Some(memcordon_core::WindowsMutantHookObservationV1::JobMembershipReadbackSkipped {
                            child_pid: hooked_pid,
                        }) if *hooked_pid == child_pid
                    ) {
                        return Err(
                            "Job-membership hook receipt child identity is invalid".to_owned()
                        );
                    }
                    let process = hook_process.as_ref().ok_or_else(|| {
                        "Job-membership mutant omitted its adopted query handle".to_owned()
                    })?;
                    if !super::job::Job::process_is_in_any_job(process.raw())? {
                        external_observation = Some(
                            memcordon_core::WindowsMutantNativeObservationV1::ExternalJobMembershipMissing {
                                process_in_any_job: false,
                            },
                        );
                        super::pipe::write_frame(
                            pipe.raw(),
                            &WindowsProviderRequestV1::Cancel {
                                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                                attempt_id: attempt_id.clone(),
                                nonce: nonce.clone(),
                                request_sha256: request_sha256.clone(),
                                signal: 15,
                            },
                        )?;
                    }
                }
                if matches!(
                    mutant,
                    WindowsSealedMutant::LeakJobHandleToTarget
                        | WindowsSealedMutant::LeakLauncherPipe
                ) {
                    wait_for_marker(&marker, std::time::Duration::from_secs(10))?;
                    let kind = if mutant == WindowsSealedMutant::LeakJobHandleToTarget {
                        "job"
                    } else {
                        "pipe"
                    };
                    let expected = format!("leaked-{kind}-handle-observed\n");
                    if std::fs::read_to_string(&marker).map_err(|error| error.to_string())?
                        != expected
                    {
                        return Err("target leaked-handle receipt is invalid".to_owned());
                    }
                    external_observation = Some(
                        memcordon_core::WindowsMutantNativeObservationV1::LeakedHandleObserved {
                            kind: kind.to_owned(),
                        },
                    );
                    super::pipe::write_frame(
                        pipe.raw(),
                        &WindowsProviderRequestV1::Cancel {
                            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                            attempt_id: attempt_id.clone(),
                            nonce: nonce.clone(),
                            request_sha256: request_sha256.clone(),
                            signal: 15,
                        },
                    )?;
                }
            }
            WindowsProviderResponseV1::TargetRetired {
                schema_version,
                attempt_id: returned,
                nonce: returned_nonce,
                request_sha256: returned_digest,
            }
            | WindowsProviderResponseV1::RelaysAbort {
                schema_version,
                attempt_id: returned,
                nonce: returned_nonce,
                request_sha256: returned_digest,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned == attempt_id
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                drop(streams);
                streams = Vec::new();
                if let Some(event) = relay_event.take() {
                    if unsafe { SetEvent(event.raw()) } == 0 {
                        return Err(std::io::Error::last_os_error().to_string());
                    }
                }
                if mutant != WindowsSealedMutant::SkipRelayAck {
                    super::pipe::write_frame(
                        pipe.raw(),
                        &WindowsProviderRequestV1::RelaysRetired {
                            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                            attempt_id: attempt_id.clone(),
                            nonce: nonce.clone(),
                            request_sha256: request_sha256.clone(),
                        },
                    )?;
                }
            }
            WindowsProviderResponseV1::CertificationMutantObserved(receipt)
                if receipt.binding_matches(&attempt_id, &nonce, &request_sha256)
                    && receipt.mutant == mutant =>
            {
                let observation = match &receipt.hook_observation {
                    memcordon_core::WindowsMutantHookObservationV1::Native { observation }
                        if observation.rejects(mutant) =>
                    {
                        observation
                    }
                    _ => {
                        return Err("terminal mutant receipt lacks a native observation".to_owned());
                    }
                };
                let retirement_candidate_required = matches!(
                    mutant,
                    WindowsSealedMutant::AcceptCompletionWithoutAccounting
                        | WindowsSealedMutant::SuccessBeforeActiveZero
                        | WindowsSealedMutant::SkipRelayAck
                        | WindowsSealedMutant::CloseJobBeforeEvidence
                );
                if retirement_candidate_required != receipt.terminal_candidate.is_some() {
                    return Err("mutant receipt candidate cardinality is invalid".to_owned());
                }
                if let Some(candidate) = receipt.terminal_candidate.as_deref()
                    && !mapped_checker_rejects_terminal_candidate(mutant, observation, candidate)
                {
                    return Err(
                        "mapped external checker accepted a forbidden mutant terminal candidate"
                            .to_owned(),
                    );
                }
                return match receipt.hook_observation {
                    memcordon_core::WindowsMutantHookObservationV1::Native { observation } => {
                        Ok(observation)
                    }
                    _ => Err(
                        "terminal mutant receipt used a nonterminal hook observation".to_owned(),
                    ),
                };
            }
            WindowsProviderResponseV1::Reject { rejection, .. } => {
                return Err(format!(
                    "mutant operation failed without its native observation receipt: {}: {}",
                    rejection.code, rejection.detail
                ));
            }
            WindowsProviderResponseV1::Terminal(receipt)
                if receipt.schema_version == 1
                    && receipt.attempt_id == attempt_id
                    && receipt.nonce == nonce
                    && receipt.request_sha256 == request_sha256
                    && receipt.process_identity_inventory_is_bounded() =>
            {
                if let Some(observation) = external_observation {
                    match (mutant, hook_observation.as_ref()) {
                        (
                            WindowsSealedMutant::SkipTargetTokenReadback,
                            Some(memcordon_core::WindowsMutantHookObservationV1::TargetTokenReadbackSkipped { child_pid }),
                        )
                        | (
                            WindowsSealedMutant::SkipJobMembershipReadback,
                            Some(memcordon_core::WindowsMutantHookObservationV1::JobMembershipReadbackSkipped { child_pid }),
                        ) if *child_pid != 0 => {}
                        (
                            WindowsSealedMutant::SkipTargetTokenReadback
                            | WindowsSealedMutant::SkipJobMembershipReadback,
                            _,
                        ) => {
                            return Err(
                                "external mutant rejection lacks its exact hook receipt"
                                    .to_owned(),
                            );
                        }
                        _ => {}
                    }
                    return if observation.rejects(mutant) {
                        Ok(observation)
                    } else {
                        Err("external mutant observation did not reject its selector".to_owned())
                    };
                }
                if mutant == WindowsSealedMutant::AcceptRecursiveProvider && marker.is_file() {
                    return Ok(
                        memcordon_core::WindowsMutantNativeObservationV1::RecursiveLaunchAccepted,
                    );
                }
                if matches!(
                    mutant,
                    WindowsSealedMutant::LeakJobHandleToTarget
                        | WindowsSealedMutant::LeakLauncherPipe
                ) {
                    let expected = match mutant {
                        WindowsSealedMutant::LeakJobHandleToTarget => {
                            "leaked-job-handle-observed\n"
                        }
                        WindowsSealedMutant::LeakLauncherPipe => "leaked-pipe-handle-observed\n",
                        _ => unreachable!(),
                    };
                    if std::fs::read_to_string(&marker).map_err(|error| error.to_string())?
                        == expected
                    {
                        return Ok(memcordon_core::WindowsMutantNativeObservationV1::LeakedHandleObserved {
                            kind: if mutant == WindowsSealedMutant::LeakJobHandleToTarget {
                                "job"
                            } else {
                                "pipe"
                            }
                            .to_owned(),
                        });
                    }
                }
                return Err(
                    "mutant reached an ordinary terminal without a rejecting observation"
                        .to_owned(),
                );
            }
            _ => return Err("mutant runner received an invalid bound provider frame".to_owned()),
        }
    }
}

fn mapped_checker_rejects_terminal_candidate(
    mutant: WindowsSealedMutant,
    observation: &memcordon_core::WindowsMutantNativeObservationV1,
    candidate: &memcordon_core::WindowsTerminalReceiptV1,
) -> bool {
    let BoundaryMechanismEvidence::WindowsJobObjectV2(evidence) = &candidate.boundary_detail else {
        return false;
    };
    match (mutant, observation) {
        (
            WindowsSealedMutant::SuccessBeforeActiveZero,
            memcordon_core::WindowsMutantNativeObservationV1::SuccessBeforeActiveZero {
                active_processes,
            },
        ) => *active_processes != 0 && !evidence.active_processes_zero,
        (
            WindowsSealedMutant::AcceptCompletionWithoutAccounting,
            memcordon_core::WindowsMutantNativeObservationV1::CompletionAcceptedWithoutAccounting {
                completion_zero_observed: true,
                active_process_query_performed: false,
            },
        ) => {
            evidence.active_processes_zero
                && candidate.restart_safety == RestartSafetyProof::default()
        }
        (
            WindowsSealedMutant::SkipRelayAck,
            memcordon_core::WindowsMutantNativeObservationV1::RelayAckSkipped {
                target_retired_sent: true,
                relays_retired_received: false,
            },
        ) => evidence.relays_retired,
        (
            WindowsSealedMutant::CloseJobBeforeEvidence,
            memcordon_core::WindowsMutantNativeObservationV1::EvidenceAfterFinalHandleClose {
                final_handles_closed: true,
                evidence_constructed_after_close: true,
            },
        ) => evidence.final_job_handles_closed,
        _ => false,
    }
}

fn wait_for_marker(path: &std::path::Path, timeout: std::time::Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    while !path.is_file() {
        if std::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Ok(())
}

pub fn recursive_mutant_target(marker: &std::ffi::OsStr) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let executable = crate::windows::package::installed_binary();
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        nonce: format!("recursive-mutant-{}", std::process::id()),
        command: NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec!["--version".encode_utf16().collect()],
        },
        environment: Vec::new(),
        current_directory: crate::windows::package::install_root()
            .as_os_str()
            .encode_wide()
            .collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: None,
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 100,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    let nonce = request.nonce.clone();
    let request_sha256 =
        super::record::digest(&serde_json::to_vec(&request).map_err(|error| error.to_string())?);
    let caller = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    let mut identity = Vec::new();
    identity.extend_from_slice(nonce.as_bytes());
    identity.extend_from_slice(&caller.process_id.to_le_bytes());
    identity.extend_from_slice(&caller.creation_time_100ns.to_le_bytes());
    identity.extend_from_slice(request_sha256.as_bytes());
    let attempt_id = super::record::digest(&identity);
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::CertificationMutant {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            mutant: WindowsSealedMutant::AcceptRecursiveProvider,
            attempt_id: attempt_id.clone(),
            request_sha256: request_sha256.clone(),
            caller_process_identity: caller,
            launch: request,
        },
    )?;
    match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
        WindowsProviderResponseV1::StreamsPrepared {
            schema_version,
            attempt_id: returned_attempt,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            streams,
            relay_retired_event_handle,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && returned_attempt == attempt_id
            && returned_nonce == nonce
            && returned_digest == request_sha256 =>
        {
            let mut adopted = streams
                .into_iter()
                .map(|stream| {
                    super::pipe::OwnedHandle::new(
                        stream.remote_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            adopted.push(super::pipe::OwnedHandle::new(
                relay_retired_event_handle as usize as windows_sys::Win32::Foundation::HANDLE,
            )?);
            std::fs::write(marker, b"recursive request accepted\n")
                .map_err(|error| error.to_string())?;
            drop(adopted);
            Ok(())
        }
        WindowsProviderResponseV1::Reject {
            schema_version,
            attempt_id: returned_attempt,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            rejection,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && returned_attempt == attempt_id
            && returned_nonce == nonce
            && returned_digest == request_sha256 =>
        {
            Err(format!(
                "recursive mutant did not change the membership decision: {}",
                rejection.code
            ))
        }
        _ => Err("recursive mutant received an invalid provider response".to_owned()),
    }
}

pub fn leaked_handle_mutant_target(
    marker: &std::ffi::OsStr,
    kind: &std::ffi::OsStr,
    raw_handle: &std::ffi::OsStr,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let raw_handle = String::from_utf16(&raw_handle.encode_wide().collect::<Vec<_>>())
        .map_err(|error| error.to_string())?
        .parse::<u64>()
        .map_err(|error| format!("invalid leaked-handle value: {error}"))?
        as usize as windows_sys::Win32::Foundation::HANDLE;
    let kind = String::from_utf16(&kind.encode_wide().collect::<Vec<_>>())
        .map_err(|error| error.to_string())?;
    let observed = match kind.as_str() {
        "job" => {
            let mut inside = 0_i32;
            (unsafe { IsProcessInJob(GetCurrentProcess(), raw_handle, &raw mut inside) }) != 0
                && inside != 0
        }
        "pipe" => (unsafe { GetFileType(raw_handle) }) == FILE_TYPE_PIPE,
        _ => return Err("unknown leaked-handle mutant kind".to_owned()),
    };
    if !observed {
        return Err(format!(
            "target did not observe the inherited {kind} handle mutant"
        ));
    }
    std::fs::write(marker, format!("leaked-{kind}-handle-observed\n"))
        .map_err(|error| error.to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Ok(())
}

fn certify_machine_restart_through_provider() -> Result<bool, String> {
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::CertificationMachineRestart {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        },
    )?;
    match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
        WindowsProviderResponseV1::CertificationMachineRestart {
            schema_version,
            recovered,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION => Ok(recovered),
        _ => Err("provider returned invalid machine-restart evidence".to_owned()),
    }
}

fn restart_provider_for_authority_fault(fault: WindowsSealedFault) -> Result<(), String> {
    use windows_sys::Win32::System::Services::{SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP};

    let manager = super::service_manager::manager()?;
    let access = SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP;
    let control = super::service_manager::open(
        &manager,
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,
        access,
    )?;
    let launcher = super::service_manager::open(
        &manager,
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
        access,
    )?;
    match fault {
        WindowsSealedFault::FrontendDisconnectedAfterAuthorization
        | WindowsSealedFault::FrontendKilledAfterAuthorization
        | WindowsSealedFault::ControlWorkerKilledAfterAuthorization => {}
        WindowsSealedFault::ControlServiceKilledAfterAuthorization => {
            super::service_manager::start(&control)?;
        }
        WindowsSealedFault::LauncherWorkerKilledAfterAuthorization
        | WindowsSealedFault::LauncherServiceKilledAfterAuthorization
        | WindowsSealedFault::AllJobOwnersClosedAfterAuthorization => {
            let _ = super::service_manager::stop(&control);
            let _ = super::service_manager::stop(&launcher);
            super::service_manager::start(&launcher)?;
            super::service_manager::start(&control)?;
        }
        _ => return Err("unsupported authority-loss service recovery".to_owned()),
    }
    Ok(())
}

pub fn appcontainer_rejection_client() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
    };

    if !super::token::current_thread_envelope()?.appcontainer {
        return Err("AppContainer rejection fixture is not running in an AppContainer".to_owned());
    }
    let pipe_name = super::pipe::wide_null(WINDOWS_CONTROL_PIPE);
    // AppContainer processes cannot use the global named-pipe namespace. A
    // kernel access denial is itself the production endpoint's pretarget
    // policy rejection; if the kernel admits the connection, the provider
    // must instead return its typed AppContainer rejection below.
    let raw_pipe = unsafe {
        CreateFileW(
            pipe_name.as_ptr(),
            0x0012_019b,
            FILE_SHARE_NONE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw_pipe == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        return if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            == Some(ERROR_ACCESS_DENIED)
        {
            Ok(())
        } else {
            Err(format!(
                "AppContainer public-pipe rejection had the wrong kernel status: {error}"
            ))
        };
    }
    let pipe = super::pipe::OwnedHandle::new(raw_pipe)?;
    let executable = crate::windows::package::installed_binary();
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        nonce: format!("appcontainer-rejection-{}", std::process::id()),
        command: NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec!["--version".encode_utf16().collect()],
        },
        environment: Vec::new(),
        current_directory: crate::windows::package::install_root()
            .as_os_str()
            .encode_wide()
            .collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: Some(30_000),
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 1_000,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    super::pipe::write_frame(pipe.raw(), &WindowsProviderRequestV1::Launch(request))?;
    match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
        WindowsProviderResponseV1::Reject { rejection, .. }
            if rejection.code == "MCSEALED-WINDOWS-APPCONTAINER-UNSUPPORTED"
                && !rejection.target_created
                && !rejection.target_released =>
        {
            Ok(())
        }
        response => Err(format!(
            "AppContainer launch did not produce the typed pretarget rejection: {response:?}"
        )),
    }
}

fn native_public_canary(target_mode: &str) -> Result<NativeCanary, String> {
    use std::os::windows::ffi::OsStrExt;

    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    super::security::SecurityDescriptor::from_sddl(&super::security::public_pipe_sddl()?)?
        .verify_kernel_object(pipe.raw())?;
    let executable = crate::windows::package::installed_binary();
    let mut arguments = vec![target_mode.encode_utf16().collect()];
    let nested_marker = if target_mode == "windows-certification-nested-target" {
        Some(
            crate::windows::package::state_root()
                .join("package")
                .join("certification-markers")
                .join(format!(
                    "nested-child-{}-{}.json",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|error| error.to_string())?
                        .as_nanos()
                )),
        )
    } else {
        None
    };
    let _nested_marker_cleanup = nested_marker.clone().map(RemoveFileGuard);
    if let Some(marker) = &nested_marker {
        arguments.push(marker.as_os_str().encode_wide().collect());
    }
    let cleanup_marker = crate::windows::package::state_root()
        .join("package")
        .join("certification-markers")
        .join(format!(
            "cleanup-creation-{}-{}.marker",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos()
        ));
    let _cleanup_marker_cleanup = CleanupCreationMarkerGuard(cleanup_marker.clone());
    arguments.push(cleanup_marker.as_os_str().encode_wide().collect());
    // These six unrelated inheritable objects originate in the real frontend.
    // Control duplicates them into the launcher for the certification-only
    // omission oracle; the owners remain live through the complete attempt.
    let frontend_canaries = inheritable_canary_handles()?;
    arguments.extend(frontend_canaries.raw_values().into_iter().map(|handle| {
        (handle as usize as u64)
            .to_string()
            .encode_utf16()
            .collect()
    }));
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        nonce: format!(
            "qualification-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos()
        ),
        command: NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments,
        },
        environment: Vec::new(),
        current_directory: crate::windows::package::install_root()
            .as_os_str()
            .encode_wide()
            .collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: None,
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 1_000,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    let nonce = request.nonce.clone();
    let request_sha256 =
        super::record::digest(&serde_json::to_vec(&request).map_err(|error| error.to_string())?);
    super::pipe::write_frame(pipe.raw(), &WindowsProviderRequestV1::Launch(request))?;
    let mut streams = Vec::new();
    let mut relay_retired_event = None;
    let mut attempt_id = None;
    loop {
        match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
            WindowsProviderResponseV1::StreamsPrepared {
                attempt_id: received,
                schema_version,
                nonce: returned_nonce,
                request_sha256: returned_digest,
                streams: received_streams,
                relay_retired_event_handle,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                if attempt_id.is_some() || received_streams.len() != 3 {
                    return Err(
                        "qualification canary received an invalid stream manifest".to_owned()
                    );
                }
                for stream in received_streams {
                    streams.push(super::pipe::OwnedHandle::new(
                        stream.remote_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                    )?);
                }
                relay_retired_event = Some(super::pipe::OwnedHandle::new(
                    relay_retired_event_handle as usize as windows_sys::Win32::Foundation::HANDLE,
                )?);
                attempt_id = Some(received.clone());
                super::pipe::write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::RelaysReady {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: received,
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
            }
            WindowsProviderResponseV1::TargetRetired {
                attempt_id: received,
                schema_version,
                nonce: returned_nonce,
                request_sha256: returned_digest,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && attempt_id.as_deref() == Some(received.as_str())
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                streams.clear();
                signal_relay_retirement(&mut relay_retired_event)?;
                super::pipe::write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::RelaysRetired {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: received,
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
            }
            WindowsProviderResponseV1::RelaysAbort {
                attempt_id: received,
                schema_version,
                nonce: returned_nonce,
                request_sha256: returned_digest,
            } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                && attempt_id.as_deref() == Some(received.as_str())
                && returned_nonce == nonce
                && returned_digest == request_sha256 =>
            {
                streams.clear();
                signal_relay_retirement(&mut relay_retired_event)?;
                super::pipe::write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::RelaysRetired {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: received,
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                    },
                )?;
            }
            WindowsProviderResponseV1::Terminal(terminal)
                if attempt_id.as_deref() == Some(terminal.attempt_id.as_str())
                    && terminal.nonce == nonce
                    && terminal.request_sha256 == request_sha256
                    && terminal.process_identity_inventory_is_bounded() =>
            {
                if !terminal
                    .restart_safety
                    .is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
                    || !terminal.cleanup_process_creation.as_ref().is_some_and(
                        memcordon_core::WindowsCleanupProcessCreationEvidenceV1::is_consistent,
                    )
                    || terminal.job_total_processes < 18
                    || !matches!(
                        terminal.outcome,
                        RunOutcome::Exited {
                            child: ChildTermination::ExitCode { code: 0 },
                            ..
                        }
                    )
                {
                    return Err(
                        "qualification canary did not prove success and terminal cleanup"
                            .to_owned(),
                    );
                }
                let nested_alternate_token_verified = if let Some(marker) = &nested_marker {
                    let observation: NestedChildObservationV1 = serde_json::from_slice(
                        &std::fs::read(marker).map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                    observation.schema_version == 1
                        && terminal
                            .job_process_identities
                            .contains(&observation.child_identity)
                } else {
                    false
                };
                return match terminal.boundary_detail {
                    BoundaryMechanismEvidence::WindowsJobObjectV2(evidence) => Ok(NativeCanary {
                        // The public client reads back the exact public pipe
                        // DACL and mandatory label above. Control verifies the
                        // exact private descriptor on its launcher connection
                        // before forwarding this attempt.
                        public_pipe_security_verified: true,
                        private_pipe_security_verified: true,
                        evidence,
                        // This target exits zero only after proving the
                        // unrelated inheritable frontend handle was absent.
                        exact_handle_inheritance_verified: true,
                        nested_alternate_token_verified,
                    }),
                    _ => Err("qualification canary returned the wrong native evidence".to_owned()),
                };
            }
            WindowsProviderResponseV1::Reject { rejection, .. } => {
                return Err(format!("{}: {}", rejection.code, rejection.detail));
            }
            _ => return Err("qualification canary received an invalid response".to_owned()),
        }
    }
}

pub fn certification_target_canary(canary_handles: &[std::ffi::OsString]) -> Result<(), String> {
    let (cleanup_marker, canary_handles) = canary_handles
        .split_first()
        .ok_or_else(|| "cleanup-creation marker path is absent".to_owned())?;
    let (expected_streams, canary_handles) = split_stream_identity(canary_handles)?;
    reject_inherited_canary_handles(canary_handles)?;
    verify_standard_streams(expected_streams)?;
    process_tree_canary(std::path::Path::new(cleanup_marker))
}

pub fn certification_nested_target_canary(
    canary_handles: &[std::ffi::OsString],
) -> Result<(), String> {
    let (marker, canary_handles) = canary_handles
        .split_first()
        .ok_or_else(|| "nested certification marker path is absent".to_owned())?;
    let (cleanup_marker, canary_handles) = canary_handles
        .split_first()
        .ok_or_else(|| "cleanup-creation marker path is absent".to_owned())?;
    let (expected_streams, canary_handles) = split_stream_identity(canary_handles)?;
    reject_inherited_canary_handles(canary_handles)?;
    verify_standard_streams(expected_streams)?;
    process_tree_canary(std::path::Path::new(cleanup_marker))?;
    nested_alternate_token_target_canary(std::path::Path::new(marker))
}

fn split_stream_identity(
    arguments: &[std::ffi::OsString],
) -> Result<(&[std::ffi::OsString], &[std::ffi::OsString]), String> {
    let expected_count = [
        windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
        windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
        windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
    ]
    .len();
    if arguments.len() < expected_count {
        return Err("configured standard-stream identity is absent".to_owned());
    }
    Ok(arguments.split_at(expected_count))
}

fn verify_standard_streams(expected_streams: &[std::ffi::OsString]) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    let handles = [
        unsafe { GetStdHandle(STD_INPUT_HANDLE) },
        unsafe { GetStdHandle(STD_OUTPUT_HANDLE) },
        unsafe { GetStdHandle(STD_ERROR_HANDLE) },
    ];
    let expected = expected_streams
        .iter()
        .map(|value| {
            String::from_utf16(&value.encode_wide().collect::<Vec<_>>())
                .map_err(|error| error.to_string())?
                .parse::<u64>()
                .map(|handle| handle as usize as windows_sys::Win32::Foundation::HANDLE)
                .map_err(|error| format!("invalid configured stream identity: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if handles.as_slice() != expected {
        return Err("target standard handles differ from the configured provider pipes".to_owned());
    }
    for (index, handle) in handles.iter().copied().enumerate() {
        if handle.is_null()
            || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
            || unsafe { GetFileType(handle) } != FILE_TYPE_PIPE
            || handles[..index].contains(&handle)
        {
            return Err(
                "target standard handles are not three distinct provider pipe objects".to_owned(),
            );
        }
    }
    Ok(())
}

fn reject_inherited_canary_handles(canary_handles: &[std::ffi::OsString]) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    if canary_handles.len() != 6 {
        return Err("exactly six unrelated handle kinds are required".to_owned());
    }
    for canary_handle in canary_handles {
        let handle = String::from_utf16(&canary_handle.encode_wide().collect::<Vec<_>>())
            .map_err(|error| error.to_string())?
            .parse::<u64>()
            .map_err(|error| format!("invalid inherited-handle canary: {error}"))?;
        let mut flags = 0_u32;
        // SAFETY: the numeric value is deliberately probed only as a handle; a
        // successful query proves an unrelated inheritable object leaked.
        if unsafe {
            windows_sys::Win32::Foundation::GetHandleInformation(
                handle as usize as windows_sys::Win32::Foundation::HANDLE,
                &raw mut flags,
            )
        } != 0
        {
            return Err("unrelated frontend handle was inherited by the target".to_owned());
        }
    }
    Ok(())
}

fn process_tree_canary(cleanup_marker: &std::path::Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };

    let executable = crate::windows::package::installed_binary();
    let status = Command::new(&executable)
        .arg("windows-certification-grandchild")
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("child/grandchild containment canary failed".to_owned());
    }
    let status = Command::new(&executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS)
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("detached new-process-group descendant canary failed".to_owned());
    }
    match Command::new(&executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
    {
        Err(_) => {}
        Ok(mut child) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("descendant escaped with CREATE_BREAKAWAY_FROM_JOB".to_owned());
        }
    }
    for _ in 0..16 {
        let status = Command::new(&executable)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err("rapid descendant churn canary failed".to_owned());
        }
    }
    let ready = cleanup_marker.with_extension("ready");
    Command::new(&executable)
        .arg("windows-certification-cleanup-churn")
        .arg(cleanup_marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !ready.is_file() {
        if std::time::Instant::now() >= deadline {
            return Err("cleanup-time process-creation canary did not become active".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}

pub fn grandchild_parent_canary() -> Result<(), String> {
    let status = std::process::Command::new(crate::windows::package::installed_binary())
        .arg("--version")
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("grandchild containment canary failed".to_owned())
    }
}

pub fn cleanup_churn_canary(marker: &std::ffi::OsStr) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let executable = crate::windows::package::installed_binary();
    let marker = std::path::Path::new(marker);
    std::fs::write(marker.with_extension("ready"), b"ready\n")
        .map_err(|error| error.to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
    while !marker.with_extension("start").is_file() {
        if std::time::Instant::now() >= deadline {
            return Err("cleanup-creation start signal was not observed".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let child = Command::new(&executable)
        .arg("windows-certification-hold")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    std::fs::write(marker.with_extension("result"), format!("{}\n", child.id()))
        .map_err(|error| error.to_string())?;
    std::thread::sleep(std::time::Duration::from_secs(5 * 60));
    Ok(())
}

pub fn orphan_descendant_canary() -> Result<(), String> {
    std::process::Command::new(crate::windows::package::installed_binary())
        .arg("windows-certification-hold")
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(super) struct InheritableCanaryHandles {
    _owners: Vec<super::pipe::OwnedHandle>,
    values: Vec<windows_sys::Win32::Foundation::HANDLE>,
    registry: windows_sys::Win32::System::Registry::HKEY,
}

impl InheritableCanaryHandles {
    pub(super) fn raw_values(&self) -> Vec<windows_sys::Win32::Foundation::HANDLE> {
        let mut values = self.values.clone();
        values.push(self.registry as windows_sys::Win32::Foundation::HANDLE);
        values
    }
}

impl Drop for InheritableCanaryHandles {
    fn drop(&mut self) {
        // SAFETY: registry is the one independently opened HKEY not owned by
        // the ordinary CloseHandle wrappers.
        unsafe { windows_sys::Win32::System::Registry::RegCloseKey(self.registry) };
    }
}

pub(super) fn inheritable_canary_handles() -> Result<InheritableCanaryHandles, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, GENERIC_READ, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, KEY_READ, RegOpenKeyExW};
    use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};

    let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut owners = Vec::new();
    let mut values = Vec::new();

    let file_path = crate::windows::package::installed_binary()
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: path is NUL-terminated and attributes requests inheritance.
    let file = super::pipe::OwnedHandle::new(unsafe {
        CreateFileW(
            file_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            &raw const attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    })?;
    values.push(file.raw());
    owners.push(file);

    // SAFETY: attributes remains live and requests an unnamed private event.
    let event = super::pipe::OwnedHandle::new(unsafe {
        CreateEventW(&raw const attributes, 1, 0, std::ptr::null())
    })?;
    values.push(event.raw());
    owners.push(event);

    let mut pipe_read = std::ptr::null_mut();
    let mut pipe_write = std::ptr::null_mut();
    // SAFETY: both outputs and the inheritable attributes remain live.
    if unsafe {
        CreatePipe(
            &raw mut pipe_read,
            &raw mut pipe_write,
            &raw const attributes,
            0,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let pipe_read = super::pipe::OwnedHandle::new(pipe_read)?;
    let pipe_write = super::pipe::OwnedHandle::new(pipe_write)?;
    values.push(pipe_read.raw());
    owners.push(pipe_read);
    owners.push(pipe_write);

    let mut process = std::ptr::null_mut();
    // SAFETY: both pseudo handles are live; output receives an inheritable real
    // handle to the current frontend process.
    if unsafe {
        windows_sys::Win32::Foundation::DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            GetCurrentProcess(),
            &raw mut process,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let process = super::pipe::OwnedHandle::new(process)?;
    values.push(process.raw());
    owners.push(process);

    // SAFETY: INVALID_HANDLE_VALUE requests a pagefile-backed unnamed section.
    let section = super::pipe::OwnedHandle::new(unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            &raw const attributes,
            PAGE_READWRITE,
            0,
            4_096,
            std::ptr::null(),
        )
    })?;
    values.push(section.raw());
    owners.push(section);

    let software = super::pipe::wide_null("Software");
    let mut registry = std::ptr::null_mut();
    // SAFETY: subkey is NUL-terminated and output receives one owned HKEY.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            software.as_ptr(),
            0,
            KEY_READ,
            &raw mut registry,
        )
    };
    if status != 0 {
        return Err(format!("cannot open inheritable registry canary: {status}"));
    }
    // SAFETY: registry is a live kernel handle and only its inherit flag changes.
    if unsafe {
        SetHandleInformation(
            registry as windows_sys::Win32::Foundation::HANDLE,
            windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
            windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
        )
    } == 0
    {
        unsafe { windows_sys::Win32::System::Registry::RegCloseKey(registry) };
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(InheritableCanaryHandles {
        _owners: owners,
        values,
        registry,
    })
}

fn recursive_provider_canary() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let executable = crate::windows::package::installed_binary();
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        nonce: format!("recursive-{}", std::process::id()),
        command: NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec!["--version".encode_utf16().collect()],
        },
        environment: Vec::new(),
        current_directory: crate::windows::package::install_root()
            .as_os_str()
            .encode_wide()
            .collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: None,
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 1_000,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    let nonce = request.nonce.clone();
    let request_sha256 =
        super::record::digest(&serde_json::to_vec(&request).map_err(|error| error.to_string())?);
    super::pipe::write_frame(pipe.raw(), &WindowsProviderRequestV1::Launch(request))?;
    match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
        WindowsProviderResponseV1::Reject {
            schema_version,
            attempt_id,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            rejection,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && !attempt_id.is_empty()
            && returned_nonce == nonce
            && returned_digest == request_sha256
            && rejection.code == "MCSEALED-WINDOWS-RECURSIVE-PROVIDER"
            && !rejection.target_created
            && !rejection.target_released =>
        {
            Ok(())
        }
        _ => Err("recursive provider qualification request was not denied".to_owned()),
    }
}

fn nested_alternate_token_target_canary(marker: &std::path::Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    // SAFETY: the pseudo-handle denotes this live sealed target. This check is
    // performed before the inner Job exists, so the observed membership can
    // only be the outer MemCordon Job.
    if !super::job::Job::process_is_in_any_job(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })? {
        return Err("nested fixture target is not in the outer sealed Job".to_owned());
    }
    let token = super::token::restricted_current_primary()?;
    let expected_envelope = super::token::envelope(token.raw())?;
    let job = super::job::Job::create(None, None, None)?;
    let mut streams = super::process::StreamSet::create(
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() },
        None,
    )?;
    let mut transferred_handles = streams
        .remote
        .iter()
        .map(|stream| stream.remote_handle)
        .collect::<Vec<_>>();
    transferred_handles.push(streams.remote_relay_retired_event);
    if transferred_handles.iter().any(|handle| {
        let handle = *handle as usize as windows_sys::Win32::Foundation::HANDLE;
        handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
    }) {
        return Err("nested stream transfer contained an invalid handle".to_owned());
    }
    streams.accept_remote_handles();
    let remote_handles = transferred_handles
        .into_iter()
        .map(|handle| {
            super::pipe::OwnedHandle::new(handle as usize as windows_sys::Win32::Foundation::HANDLE)
                .expect("validated nested stream handle must remain nonzero")
        })
        .collect::<Vec<_>>();
    let executable = crate::windows::package::installed_binary();
    let current_directory = crate::windows::package::install_root()
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    let target = super::process::SuspendedTarget::create(
        token.raw(),
        &job,
        &NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec!["windows-certification-delay".encode_utf16().collect()],
        },
        &[],
        &current_directory,
        &streams,
        std::ptr::null_mut(),
        None,
        None,
    )
    .map_err(|error| error.detail)?;
    let target_token = super::token::process_token(target.handle())?;
    if !job.contains(target.handle())?
        || super::token::envelope(target_token.raw())? != expected_envelope
    {
        return Err("nested alternate-token child failed preauthorization readback".to_owned());
    }
    let observation = NestedChildObservationV1 {
        schema_version: 1,
        child_identity: super::process::process_identity(target.handle())?,
    };
    let mut bytes = serde_json::to_vec(&observation).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .and_then(|mut file| std::io::Write::write_all(&mut file, &bytes))
        .map_err(|error| error.to_string())?;
    drop(streams);
    target.resume(None)?;
    if !target.wait(Duration::from_secs(30))? || target.exit_status()? != 0 {
        return Err("nested alternate-token child did not exit successfully".to_owned());
    }
    drop(remote_handles);
    if !job.wait_empty(Instant::now() + Duration::from_secs(30))? {
        return Err("nested alternate-token child Job did not become empty".to_owned());
    }
    Ok(())
}

fn recovery_complete() -> Result<bool, String> {
    recovery_status()
}

pub fn recovery_status() -> Result<bool, String> {
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::RecoveryStatus {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        },
    )?;
    match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
        WindowsProviderResponseV1::RecoveryStatus {
            schema_version,
            attempts_empty,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION => Ok(attempts_empty),
        _ => Err("control service returned an invalid recovery status".to_owned()),
    }
}

pub fn prepare_package_cleanup() -> Result<(), String> {
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::PackageCleanup {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        },
    )?;
    match super::pipe::read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
        WindowsProviderResponseV1::PackageCleanupReady { schema_version }
            if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION =>
        {
            Ok(())
        }
        WindowsProviderResponseV1::Reject { rejection, .. } => {
            Err(format!("{}: {}", rejection.code, rejection.detail))
        }
        _ => Err("control service returned an invalid package cleanup response".to_owned()),
    }
}

fn qualification_path() -> std::path::PathBuf {
    crate::windows::package::state_root()
        .join("package")
        .join("qualification.json")
}
