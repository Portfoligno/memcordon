fn normalize_windows_source(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

const REMOTE_SNAPSHOT_DUPLICATE: &str = "DuplicateHandle(\n            source_process,\n            remote_value,\n            GetCurrentProcess(),\n            &raw mut snapshot,\n            0,\n            0,\n            DUPLICATE_SAME_ACCESS,\n        )";
const REMOTE_SNAPSHOT_CALLER: &str =
    "match super::process::compare_remote_handle_object(target.handle(), raw, raw)";
const TARGET_TOKEN_REMOTE_DUPLICATE: &str = "DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            process,\n            &raw mut remote,\n            TARGET_TOKEN_CAPABILITY_ACCESS,\n            0,\n            0,\n        )";
const BROKER_TRANSFER_DUPLICATE: &str = "DuplicateHandle(\n            GetCurrentProcess(),\n            source,\n            launcher,\n            &raw mut remote,\n            access,\n            0,\n            0,\n        )";

struct RawDuplicateRole<'a> {
    name: &'a str,
    start: &'a str,
    end: &'a str,
    call: &'a str,
    ownership: &'a str,
}

fn bounded_region<'a>(source: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let (_, tail) = source.split_once(start)?;
    if end.is_empty() {
        Some(tail)
    } else {
        tail.split_once(end).map(|(region, _)| region)
    }
}

fn raw_duplicate_inventory_holds(process: &str) -> bool {
    let roles = [
        RawDuplicateRole {
            name: "frontend-relay-transfer",
            start: "fn duplicate_remote(handle: HANDLE, process: HANDLE)",
            end: "pub fn duplicate_remote_process_query(",
            call: "DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            process,\n            &raw mut remote,\n            0,\n            0,\n            DUPLICATE_SAME_ACCESS,\n        )",
            ownership: "Ok(remote as usize as u64)",
        },
        RawDuplicateRole {
            name: "remote-process-query-transfer",
            start: "pub fn duplicate_remote_process_query(",
            end: "fn duplicate_remote_token_query(",
            call: "DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            process,\n            &raw mut remote,\n            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,\n            0,\n            0,\n        )",
            ownership: "launcher_process_query_handle: launcher_process_handle",
        },
        RawDuplicateRole {
            name: "launcher-token-query-transfer",
            start: "fn duplicate_remote_token_query(",
            end: "fn duplicate_remote_target_token_capability(",
            call: "DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            process,\n            &raw mut remote,\n            TOKEN_ATTESTATION_QUERY_ACCESS,\n            0,\n            0,\n        )",
            ownership: "let launcher_token = OwnedHandle::new(launcher_token_handle as usize as HANDLE)?;",
        },
        RawDuplicateRole {
            name: "holder-target-token-capability-transfer",
            start: "fn duplicate_remote_target_token_capability(",
            end: "pub fn revoke_remote_handle(",
            call: TARGET_TOKEN_REMOTE_DUPLICATE,
            ownership: ".map(|handle| OwnedHandle::new(handle as usize as HANDLE))",
        },
        RawDuplicateRole {
            name: "remote-revocation",
            start: "fn close_remote_native(handle: HANDLE, process: HANDLE)",
            end: "fn duplicate_local_handle_with_access(",
            call: "DuplicateHandle(\n            process,\n            handle,\n            GetCurrentProcess(),\n            &raw mut local,\n            0,\n            0,\n            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,\n        )",
            ownership: "drop(OwnedHandle::new(local)?);",
        },
        RawDuplicateRole {
            name: "broker-primary-thread-local-narrowing",
            start: "fn duplicate_local_handle_with_access(",
            end: "pub(crate) struct SessionBrokerCreatedHolder",
            call: "DuplicateHandle(\n            GetCurrentProcess(),\n            source,\n            GetCurrentProcess(),\n            &raw mut duplicate,\n            requested_access,\n            0,\n            0,\n        )",
            ownership: "let duplicate = OwnedHandle::new(duplicate)?;",
        },
        RawDuplicateRole {
            name: "launcher-job-to-session-broker",
            start: "pub(crate) fn create_session_broker_holder(",
            end: "pub(crate) enum RemoteHandleObjectIdentity",
            call: "DuplicateHandle(\n            launcher_process,\n            super::session_broker::decode_protocol_handle(launcher_job_handle, \"launcher-job\")?,\n            GetCurrentProcess(),\n            &raw mut local_job,\n            super::session_broker::HOLDER_JOB_BROKER_ACCESS,\n            0,\n            0,\n        )",
            ownership: "_job: local_job",
        },
        RawDuplicateRole {
            name: "remote-object-snapshot",
            start: "pub(crate) fn compare_remote_handle_object(",
            end: "pub struct SuspendedTarget",
            call: REMOTE_SNAPSHOT_DUPLICATE,
            ownership: "let snapshot = OwnedHandle::new(snapshot)?;",
        },
        RawDuplicateRole {
            name: "user-object-attestation-duplicate",
            start: "fn duplicate(source: HANDLE, desired_access: u32)",
            end: "fn close_checked(&mut self)",
            call: "DuplicateHandle(\n                GetCurrentProcess(),\n                source,\n                GetCurrentProcess(),\n                &raw mut duplicate,\n                desired_access,\n                0,\n                0,\n            )",
            ownership: "Ok(Self(duplicate))",
        },
        RawDuplicateRole {
            name: "user-object-generic-close",
            start: "fn close_checked(&mut self)",
            end: "fn close(mut self)",
            call: "DuplicateHandle(\n                GetCurrentProcess(),\n                source,\n                ptr::null_mut(),\n                ptr::null_mut(),\n                0,\n                0,\n                DUPLICATE_CLOSE_SOURCE,\n            )",
            ownership: "std::mem::replace(&mut self.0, ptr::null_mut())",
        },
        RawDuplicateRole {
            name: "guardian-authority-transfer",
            start: "fn duplicate_remote_with_access(",
            end: "fn authenticate_guardian_process(",
            call: "DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            process,\n            &raw mut remote,\n            access,\n            0,\n            0,\n        )",
            ownership: "GuardianBootstrapCleanup",
        },
        RawDuplicateRole {
            name: "local-inheritable-certification-duplicate",
            start: "fn duplicate_local_inheritable(",
            end: "pub fn duplicate_owned(",
            call: "DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            GetCurrentProcess(),\n            &raw mut duplicate,\n            0,\n            1,\n            DUPLICATE_SAME_ACCESS,\n        )",
            ownership: "OwnedHandle::new(duplicate)",
        },
        RawDuplicateRole {
            name: "local-owned-duplicate",
            start: "pub fn duplicate_owned(",
            end: "",
            call: "DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            GetCurrentProcess(),\n            &raw mut duplicate,\n            0,\n            0,\n            DUPLICATE_SAME_ACCESS,\n        )",
            ownership: "OwnedHandle::new(duplicate)",
        },
    ];
    if process.matches("DuplicateHandle(").count() != roles.len() {
        return false;
    }
    if !roles.iter().all(|role| {
        let Some(region) = bounded_region(process, role.start, role.end) else {
            return false;
        };
        !role.name.is_empty()
            && region.matches("DuplicateHandle(").count() == 1
            && region.matches(role.call).count() == 1
            && process.contains(role.ownership)
    }) {
        return false;
    }
    let Some(narrowing) = bounded_region(
        process,
        "fn duplicate_local_handle_with_access(",
        "pub(crate) struct SessionBrokerCreatedHolder",
    ) else {
        return false;
    };
    fragments_are_ordered(
        narrowing,
        &[
            "requested_access: u32,",
            "expected_granted_access: u32,",
            "DuplicateHandle(",
            "requested_access,",
            "0,",
            "0,",
            "let duplicate = OwnedHandle::new(duplicate)?;",
            "GetHandleInformation(duplicate.raw(), &raw mut flags)",
            "let inherited = flags & HANDLE_FLAG_INHERIT != 0;",
            "let actual_granted_access = super::token::granted_handle_access(duplicate.raw())?;",
            "inherited || actual_granted_access != expected_granted_access",
            "requested_access={requested_access:#010x}",
            "expected_granted_access={expected_granted_access:#010x}",
            "actual_granted_access={actual_granted_access:#010x}",
            "inherited={inherited}",
        ],
    ) && process.contains(
        "super::session_broker::HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,\n        super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,",
    )
}

fn broker_raw_duplicate_inventory_holds(session_broker: &str) -> bool {
    let Some(duplicate) = bounded_region(
        session_broker,
        "fn duplicate_into_launcher(",
        "fn encode_protocol_handle(",
    ) else {
        return false;
    };
    if session_broker.matches("DuplicateHandle(").count() != 1
        || duplicate.matches("DuplicateHandle(").count() != 1
        || duplicate.matches(BROKER_TRANSFER_DUPLICATE).count() != 1
        || !fragments_are_ordered(
            duplicate,
            &[
                "encode_protocol_handle(remote, \"transferred-holder\")",
                "revoke_remote_native_handle(remote, launcher)",
            ],
        )
    {
        return false;
    }

    let Some(rollback) = bounded_region(
        session_broker,
        "struct LauncherHandleTransferRollback {",
        "impl Drop for LauncherHandleTransferRollback",
    ) else {
        return false;
    };
    if !fragments_are_ordered(
        rollback,
        &[
            "remote_close_armed: bool,",
            "fn record_process(&mut self, remote_process: u64)",
            "self.remote_process = Some(remote_process);",
            "fn revoke_before_delivery(&mut self) -> Result<(), String>",
            "if !self.remote_close_armed {",
            "self.remote_close_armed = false;",
            "if let Some(remote) = self.remote_process.take() {",
            "super::process::revoke_remote_handle(remote, self.launcher)",
            "fn disarm_after_launched_delivery(&mut self)",
            "self.remote_close_armed = false;",
        ],
    ) || !session_broker.contains(
        "impl Drop for LauncherHandleTransferRollback {\n    fn drop(&mut self) {\n        if let Err(error) = self.revoke_before_delivery() {\n            eprintln!(\"MCSEALED-WINDOWS-SESSION-BROKER: {error}\");",
    ) {
        return false;
    }
    if rollback.contains("remote_thread") || rollback.contains("record_thread") {
        return false;
    }

    let Some(server) = bounded_region(
        session_broker,
        "unsafe fn broker_service_transaction(",
        "#[allow(clippy::too_many_arguments)]",
    ) else {
        return false;
    };
    if !fragments_are_ordered(
        server,
        &[
            "LauncherHandleTransferRollback::new(launcher_process.raw())",
            "HOLDER_PROCESS_TRANSFER_ACCESS,",
            "transfer_rollback.record_process(remote_process);",
            "holder_thread_id: holder.primary_thread_id,",
            "launched_binding_sha256(&request, &launched)",
            "SessionBrokerFrameV1::Launched(launched.clone())",
            "transfer_rollback.disarm_after_launched_delivery();",
            "SessionBrokerFrameV1::Ack { binding_sha256 }",
            "run_creation_authority_transaction(",
            "holder.disarm();",
        ],
    ) || server.matches("transfer_rollback.failure_detail(").count() != 2
        || server
            .split_once("transfer_rollback.disarm_after_launched_delivery();")
            .is_some_and(|(_, delivered)| delivered.contains("revoke_remote_handle(remote_"))
    {
        return false;
    }

    let Some(client) = bounded_region(
        session_broker,
        "pub(crate) fn request_holder(",
        "fn retire_authenticated_broker(",
    ) else {
        return false;
    };
    if !fragments_are_ordered(
        client,
        &[
            "if launched.holder_thread_id == 0 {",
            "OwnedHandle::new(unsafe {",
            "OpenThread(",
            "HOLDER_THREAD_LAUNCHER_ACCESS,",
            "0,",
            "launched.holder_thread_id",
            "verify_exact_handle(",
            "thread.raw(),",
            "HOLDER_THREAD_LAUNCHER_ACCESS,",
            "let actual_thread_process_id = unsafe { GetProcessIdOfThread(thread.raw()) };",
            "actual_thread_process_id != launched.holder_identity.process_id",
            "SessionBrokerFrameV1::Ack {",
        ],
    ) {
        return false;
    }

    session_broker.contains("pub(crate) const SESSION_BROKER_SCHEMA_VERSION: u32 = 5;")
        && session_broker.contains(
        "const LAUNCHER_PROCESS_BROKER_ACCESS: u32 =\n    SYNCHRONIZE_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;",
    )
        && session_broker
        .contains("pub(crate) const HOLDER_PROCESS_TRANSFER_ACCESS: u32 = 0x0010_1040;")
        && session_broker
            .contains("pub(crate) const HOLDER_THREAD_LAUNCHER_ACCESS: u32 =\n    THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;")
        && session_broker
            .contains("pub(crate) const HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS: u32 =\n    THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN;")
        && session_broker.contains(
            "pub(crate) const HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS: u32 =\n    HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS | THREAD_QUERY_LIMITED_INFORMATION;",
        )
        && session_broker.contains(
            "OpenThread(HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS, 0, thread_id)",
        )
        && session_broker.contains(
            "verify_exact_handle(\n                    thread.raw(),\n                    HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,\n                    HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,\n                    \"creator-thread\",\n                    \"open\",",
        )
        && session_broker.contains("actual_granted_access != expected_granted_access")
        && session_broker.contains("requested_access={requested_access:#010x}")
        && session_broker
            .contains("expected_granted_access={expected_granted_access:#010x}")
        && session_broker.contains("actual_granted_access={actual_granted_access:#010x}")
        && session_broker.contains("inherited={inherited}")
        && session_broker.contains("OpenProcess(LAUNCHER_PROCESS_BROKER_ACCESS, 0, pid)")
        && session_broker.contains(
            "OwnedHandle::new(decode_protocol_handle(\n            launched.holder_process_handle,",
        )
        && session_broker.contains("holder_thread_id: u32,")
        && session_broker.contains("memcordon-session-broker-binding-v5")
        && !session_broker.contains("holder_thread_handle")
        && !session_broker.contains("launched.holder_thread_id = 0;")
}

struct WindowsHandleOwnershipSources {
    control: String,
    launcher: String,
    process: String,
    qualification: String,
    token: String,
    guardian: String,
    session_broker: String,
    backend: String,
}

impl WindowsHandleOwnershipSources {
    fn load() -> Self {
        Self {
            control: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/control_service.rs"
            )),
            launcher: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/launcher_service.rs"
            )),
            process: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process.rs"
            )),
            qualification: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/qualification.rs"
            )),
            token: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/token.rs"
            )),
            guardian: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/guardian.rs"
            )),
            session_broker: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/session_broker.rs"
            )),
            backend: normalize_windows_source(include_str!(
                "../../../.github/workflows/backend-certification.yml"
            )),
        }
    }

    fn convert_line_endings_to_crlf(&mut self) {
        self.control = self.control.replace('\n', "\r\n");
        self.launcher = self.launcher.replace('\n', "\r\n");
        self.process = self.process.replace('\n', "\r\n");
        self.qualification = self.qualification.replace('\n', "\r\n");
        self.token = self.token.replace('\n', "\r\n");
        self.guardian = self.guardian.replace('\n', "\r\n");
        self.session_broker = self.session_broker.replace('\n', "\r\n");
        self.backend = self.backend.replace('\n', "\r\n");
    }

    fn normalize_line_endings(&mut self) {
        self.control = normalize_windows_source(&self.control);
        self.launcher = normalize_windows_source(&self.launcher);
        self.process = normalize_windows_source(&self.process);
        self.qualification = normalize_windows_source(&self.qualification);
        self.token = normalize_windows_source(&self.token);
        self.guardian = normalize_windows_source(&self.guardian);
        self.session_broker = normalize_windows_source(&self.session_broker);
        self.backend = normalize_windows_source(&self.backend);
    }
}

fn assert_control_transfer_contract(control: &str) {
    assert!(control.contains("fn duplicate_between(\n    source_process: HANDLE,\n    source_handle: HANDLE,\n    target_process: HANDLE,"));
    assert!(!control.contains("fn duplicate_into("));
    assert!(!control.contains("fn duplicate_into_with_fault("));
    assert!(control.contains(
        "certification_frontend_handles(&launch, qualification_in_progress, frontend_namespace)"
    ));
    assert!(control.contains("Ok(ProcessRelativeHandle {\n                owner,"));
    assert!(control.contains("source.owner.process, source.raw, target.process"));
    assert!(control.contains("role: \"authenticated-frontend\""));
    assert!(control.contains("role: \"control\""));
    assert!(control.contains("source_pid="));
    assert!(control.contains("destination_pid="));
    assert!(control.contains("inventory_index="));
    assert!(control.contains("struct LauncherTransferRollback"));
    assert!(control.contains("target_duplicates_revoked=true"));
}

fn assert_raw_duplicate_contract(
    control: &str,
    process: &str,
    qualification: &str,
    token: &str,
    session_broker: &str,
) {
    assert_eq!(control.matches("DuplicateHandle(").count(), 2);
    assert!(control.contains(
        "DuplicateHandle(\n            source_process,\n            source_handle,\n            target_process,"
    ));
    assert!(control.contains(
        "DuplicateHandle(\n            source_process,\n            remote as usize as HANDLE,\n            windows_sys::Win32::System::Threading::GetCurrentProcess(),"
    ));

    assert!(raw_duplicate_inventory_holds(process));
    assert_eq!(
        process
            .matches("DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            process,")
            .count(),
        5
    );
    assert!(process.contains(
        "DuplicateHandle(\n            process,\n            handle,\n            GetCurrentProcess(),"
    ));
    assert_eq!(
        process
            .matches("DuplicateHandle(\n            GetCurrentProcess(),\n            handle,\n            GetCurrentProcess(),")
            .count(),
        2
    );
    assert_eq!(qualification.matches("DuplicateHandle(").count(), 1);
    assert!(qualification.contains(
        "DuplicateHandle(\n            GetCurrentProcess(),\n            GetCurrentProcess(),\n            GetCurrentProcess(),"
    ));

    assert_eq!(token.matches("DuplicateHandle(").count(), 1);
    let token_duplicate = token
        .split_once("fn duplicate_handle_with_access(")
        .and_then(|(_, tail)| tail.split_once("\nfn reject_fault("))
        .map(|(region, _)| region)
        .expect("token duplicate helper region must be present");
    assert_eq!(token_duplicate.matches("DuplicateHandle(").count(), 1);
    assert_eq!(
        token_duplicate
            .matches("DuplicateHandle(\n            GetCurrentProcess(),\n            source,\n            GetCurrentProcess(),\n            &raw mut duplicate,\n            desired_access,\n            0,\n            0,\n        )")
            .count(),
        1
    );
    assert!(token_duplicate.contains("OwnedHandle::new(duplicate)"));
    assert!(broker_raw_duplicate_inventory_holds(session_broker));
}

fn fragments_are_ordered(source: &str, fragments: &[&str]) -> bool {
    let mut remainder = source;
    for fragment in fragments {
        let Some((_, tail)) = remainder.split_once(fragment) else {
            return false;
        };
        remainder = tail;
    }
    true
}

fn target_token_capability_contract_holds(process: &str) -> bool {
    if !raw_duplicate_inventory_holds(process) {
        return false;
    }
    let Some(duplicate) = bounded_region(
        process,
        "fn duplicate_remote_target_token_capability(",
        "pub fn revoke_remote_handle(",
    ) else {
        return false;
    };
    if process
        .matches("const TARGET_TOKEN_CAPABILITY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE;")
        .count()
        != 1
        || duplicate.matches("DuplicateHandle(").count() != 1
        || duplicate.matches(TARGET_TOKEN_REMOTE_DUPLICATE).count() != 1
        || duplicate.contains("TOKEN_IMPERSONATE")
    {
        return false;
    }

    let Some(holder) = bounded_region(
        process,
        "impl TargetDesktopLease {",
        "fn launch_target_desktop_probe(",
    ) else {
        return false;
    };
    if !fragments_are_ordered(
        holder,
        &[
            "let bootstrap_job = Job::create_session_holder()?;",
            "bootstrap_job.contains(bootstrap_process.raw())?",
            "duplicate_remote_process_query(",
            "duplicate_remote_token_query(launcher_token.raw(), bootstrap_process.raw())?",
            "duplicate_remote_target_token_capability(token, bootstrap_process.raw())?",
            "let binding = TargetDesktopBootstrapBindingV3 {",
            ".seal()?;",
            "ResumeThread(bootstrap_thread.raw())",
            "TargetDesktopBootstrapPipeOperation::LoaderReadyRead",
            "target_token_capability_handle: Some(target_token_handle),",
            "read_target_desktop_bootstrap_attestation(",
        ],
    ) || !process.contains("TargetDesktopBootstrapPipeOperation::StartedRead")
    {
        return false;
    }

    let Some(receiver) = bounded_region(
        process,
        "pub(super) fn target_desktop_bootstrap(",
        "fn validate_target_desktop_bootstrap_nonce(",
    ) else {
        return false;
    };
    fragments_are_ordered(
        receiver,
        &[
            "TargetDesktopBootstrapMessageV1::Admission {",
            "(TargetDesktopBootstrapRoleV1::Holder, Some(handle)) => Some(handle),",
            "(TargetDesktopBootstrapRoleV1::Probe, None) => None,",
            "launcher_process_handle == launcher_token_handle",
            "target_token_handle == launcher_process_handle",
            "target_token_handle == launcher_token_handle",
            "binding.verify_digest()?;",
            "let launcher_process = OwnedHandle::new(launcher_process_handle as usize as HANDLE)?;",
            "let launcher_token = OwnedHandle::new(launcher_token_handle as usize as HANDLE)?;",
            ".map(|handle| OwnedHandle::new(handle as usize as HANDLE))",
            "verify_not_inheritable(target_token.raw())?;",
        ],
    )
}

fn assert_target_token_capability_contract(process: &str) {
    assert!(target_token_capability_contract_holds(process));
}

fn remote_snapshot_contract_holds(process: &str, launcher: &str) -> bool {
    let Some((_, tail)) = process.split_once("pub(crate) fn compare_remote_handle_object(") else {
        return false;
    };
    let Some((identity, _)) = tail.split_once("\npub struct SuspendedTarget") else {
        return false;
    };
    let Some(duplicate_offset) = identity.find(REMOTE_SNAPSHOT_DUPLICATE) else {
        return false;
    };
    let owner = "let snapshot = OwnedHandle::new(snapshot)?;";
    let immediate_owner = "    }\n    let snapshot = OwnedHandle::new(snapshot)?;";
    let comparison = "CompareObjectHandles(snapshot.raw(), expected_local)";
    let Some(owner_offset) = identity.find(owner) else {
        return false;
    };
    let Some(comparison_offset) = identity.find(comparison) else {
        return false;
    };
    if identity.matches("DuplicateHandle(").count() != 1
        || identity.matches(REMOTE_SNAPSHOT_DUPLICATE).count() != 1
        || identity.matches(owner).count() != 1
        || identity.matches(immediate_owner).count() != 1
        || identity.matches(comparison).count() != 1
        || !(duplicate_offset < owner_offset && owner_offset < comparison_offset)
    {
        return false;
    }

    let Some(target_offset) = launcher.find("let target = match target_result {") else {
        return false;
    };
    let Some(caller_offset) = launcher.find(REMOTE_SNAPSHOT_CALLER) else {
        return false;
    };
    let Some(authorize_offset) = launcher.find("cleanup_guard.record.authorize()") else {
        return false;
    };
    let Some(resume_tail_offset) = launcher[authorize_offset..].find("target.resume(None)") else {
        return false;
    };
    let resume_offset = authorize_offset + resume_tail_offset;
    launcher.matches(REMOTE_SNAPSHOT_CALLER).count() == 1
        && target_offset < caller_offset
        && caller_offset < authorize_offset
        && authorize_offset < resume_offset
}

fn assert_remote_snapshot_contract(process: &str, launcher: &str) {
    assert!(remote_snapshot_contract_holds(process, launcher));
}

fn assert_user_object_duplicate_contract(process: &str) {
    assert!(process.contains(
        "const TARGET_STATION_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | WINSTA_READATTRIBUTES_ACCESS;"
    ));
    assert!(process.contains(
        "const TARGET_DESKTOP_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | DESKTOP_READOBJECTS_ACCESS;"
    ));
    assert!(process.contains(
        "DuplicateHandle(\n                GetCurrentProcess(),\n                source,\n                GetCurrentProcess(),\n                &raw mut duplicate,\n                desired_access,\n                0,\n                0,"
    ));
    assert!(process.contains(
        "DuplicateHandle(\n                GetCurrentProcess(),\n                source,\n                ptr::null_mut(),\n                ptr::null_mut(),\n                0,\n                0,\n                DUPLICATE_CLOSE_SOURCE,"
    ));
    assert!(process.contains("std::mem::replace(&mut self.0, ptr::null_mut())"));
    assert!(process.contains("station_duplicate\n        .close()"));
    assert!(process.contains("desktop_duplicate\n        .close()"));
    assert!(process.contains(
        "OwnedUserObjectDuplicate::duplicate(window_station, TARGET_STATION_ATTEST_ACCESS)"
    ));
    assert!(
        process
            .contains("OwnedUserObjectDuplicate::duplicate(desktop, TARGET_DESKTOP_ATTEST_ACCESS)")
    );
    assert!(!process.contains("OpenWindowStationW(station_name.as_ptr()"));
    assert!(!process.contains("OpenDesktopW(desktop_name_wide.as_ptr()"));
}

fn assert_guardian_loader_contract(process: &str, guardian: &str, backend: &str) {
    assert!(process.contains("GetProcessWindowStation()"));
    assert!(process.contains("GetThreadDesktop(GetCurrentThreadId())"));
    assert!(process.contains("GetUserObjectInformationW"));
    assert!(process.contains("TARGET_STATION_ATTEST_ACCESS"));
    assert!(process.contains("TARGET_DESKTOP_ATTEST_ACCESS"));
    assert!(process.contains("SecurityDescriptor::user_object_security_equality_fingerprint("));
    let guardian_policy = process
        .split_once("pub(crate) fn validate_guardian_desktop_binding(")
        .and_then(|(_, tail)| tail.split_once("\nstruct GuardianStandardHandles"))
        .map(|(region, _)| region)
        .expect("guardian desktop policy region must be present");
    assert!(guardian_policy.contains("window_station.eq_ignore_ascii_case(\"WinSta0\")"));
    let target_bootstrap = bounded_region(
        process,
        "fn run_target_desktop_bootstrap(",
        "impl CapturedTargetDesktop {",
    )
    .expect("target desktop bootstrap region must be present");
    let private_station_create = target_bootstrap
        .find("CreateWindowStationW(")
        .expect("target bootstrap private station creation must be present");
    let pre_private_station = &target_bootstrap[..private_station_create];
    for forbidden in [
        "GetProcessWindowStation(",
        "GetThreadDesktop(",
        "GetUserObjectInformation",
        "GetUserObjectSecurity",
        "SetUserObjectSecurity",
        "SetUserObjectInformation",
        "OpenWindowStationW(",
        "OpenDesktopW(",
        "desktop_receives_input(",
        "WinSta0",
    ] {
        assert!(
            !pre_private_station.contains(forbidden),
            "target bootstrap observed ambient USER binding before private creation: {forbidden}"
        );
    }
    assert!(fragments_are_ordered(
        target_bootstrap,
        &[
            "super::user_api::load()",
            "CreateWindowStationW(",
            "SetProcessWindowStation(private_window_station.raw())",
            "private_window_station.mark_assigned();",
            "GetProcessWindowStation()",
            "create_target_desktop_on_creator_thread(",
            "SetThreadDesktop(desktop.raw())",
            "GetThreadDesktop(GetCurrentThreadId())",
            "desktop_receives_input(desktop.raw())",
            "verify_private_desktop_containment(",
        ],
    ));
    let loader_control = bounded_region(
        process,
        "fn launch_target_desktop_loader_control(",
        "#[allow(clippy::too_many_arguments)]",
    )
    .expect("loader-control launch region must be present");
    assert!(fragments_are_ordered(
        loader_control,
        &[
            "\"loader-control\".encode_utf16().collect(),",
            "exact_desktop.encode_utf16().collect(),",
            "let mut loader_control_desktop = exact_desktop.encode_utf16().collect::<Vec<_>>();",
            "loader_control_desktop.push(0);",
            "startup.StartupInfo.lpDesktop = loader_control_desktop.as_mut_ptr();",
            "CreateProcessAsUserW(",
            "ResumeThread(control_thread.raw())",
            "TargetDesktopBootstrapPipeOperation::LoaderReadyRead",
            "observed_desktop.as_deref() == Some(exact_desktop)",
            "TargetDesktopBootstrapPipeOperation::LoaderControlReleaseWrite",
            "control_job.wait_empty(",
        ],
    ));
    assert!(!loader_control.contains("let mut loader_control_desktop = [0_u16];"));
    assert!(!loader_control.contains("startup.StartupInfo.lpDesktop = ptr::null_mut();"));
    let bootstrap_entry = bounded_region(
        process,
        "pub(super) fn target_desktop_bootstrap(",
        "fn validate_target_desktop_bootstrap_nonce(",
    )
    .expect("target desktop bootstrap entry region must be present");
    let pre_loader_ready = bootstrap_entry
        .split_once("TargetDesktopBootstrapPipeOperation::LoaderReadyWrite")
        .map(|(prefix, _)| prefix)
        .expect("LoaderReady publication must be present");
    for forbidden in [
        "super::user_api::load()",
        "GetProcessWindowStation(",
        "GetThreadDesktop(",
        "OpenWindowStationW(",
        "OpenDesktopW(",
        "SetProcessWindowStation(",
        "SetThreadDesktop(",
    ] {
        assert!(
            !pre_loader_ready.contains(forbidden),
            "loader-control performs explicit USER/GDI work before LoaderReady: {forbidden}"
        );
    }
    assert!(process.contains("startup.StartupInfo.lpDesktop = desktop.startup_name.as_mut_ptr()"));
    assert!(process.contains("startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES"));
    assert!(process.contains("let inherited = [\n        standard_input,\n        standard_output,\n        standard_error,\n        child_read.raw(),\n        child_write.raw(),\n    ]"));
    assert!(process.contains("ptr::null(),\n            ptr::null(),\n            1,"));
    assert!(guardian.contains("retire_loader_standard_handles(&mut loader_standard_handles)?"));
    assert!(guardian.contains("attest_current_guardian_desktop(&launcher_desktop)"));
    assert!(backend.contains(
        "          - id: x64\n            runner: windows-2025\n          - id: arm64\n            runner: windows-11-arm\n"
    ));
}

fn assert_certification_handle_layout_contract(
    control: &str,
    launcher: &str,
    process: &str,
    qualification: &str,
) {
    assert!(control.contains(
        "memcordon_core::parse_windows_certification_frontend_handle_values(\n        &launch.command.arguments,"
    ));
    assert!(control.contains("WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT"));
    assert!(launcher.contains(
        ".and_then(|argument| memcordon_core::windows_certification_argument_prelude_len(argument))"
    ));
    assert!(launcher.contains(
        "frontend_canaries.len() != memcordon_core::WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT"
    ));
    assert!(launcher.contains("target_command.arguments.truncate(retained_arguments)"));
    assert!(launcher.contains("streams\n                .certification_target_handle_values()"));
    assert!(process.contains("fn target_handles(&self) -> [HANDLE; 3]"));
    assert!(process.contains("pub fn certification_target_handle_values(&self) -> [u64; 3]"));
    assert!(qualification.contains("pub(crate) struct PreparedFrontendCanaries"));
    assert!(qualification.contains(
        ") -> [windows_sys::Win32::Foundation::HANDLE;\n        memcordon_core::WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT]"
    ));
    assert!(qualification.contains("frontend_canaries: &PreparedFrontendCanaries"));
    assert!(!qualification.contains("let frontend_canaries = inheritable_canary_handles()"));
    for (scenario, constructor) in [
        ("restricted", "impersonate_restricted_current_thread"),
        ("ordinary-user", "impersonate_ordinary_current_thread"),
        (
            "write-restricted",
            "impersonate_write_restricted_current_thread",
        ),
        ("low-integrity", "impersonate_low_integrity_current_thread"),
        (
            "deny-only-admin",
            "impersonate_deny_only_admin_current_thread",
        ),
    ] {
        let preparation = format!("prepare_frontend_canaries(\"{scenario}\")");
        assert!(
            frontend_canary_precedes_fixture(qualification, &preparation, constructor),
            "{scenario} canaries must be prepared before fixture impersonation"
        );
    }
}

fn frontend_canary_precedes_fixture(
    qualification: &str,
    preparation: &str,
    constructor: &str,
) -> bool {
    qualification.find(preparation).is_some_and(|preparation| {
        qualification
            .find(constructor)
            .is_some_and(|constructor| preparation < constructor)
    })
}

fn assert_full_handle_ownership_contract(sources: &WindowsHandleOwnershipSources) {
    assert_control_transfer_contract(&sources.control);
    assert_certification_handle_layout_contract(
        &sources.control,
        &sources.launcher,
        &sources.process,
        &sources.qualification,
    );
    assert_raw_duplicate_contract(
        &sources.control,
        &sources.process,
        &sources.qualification,
        &sources.token,
        &sources.session_broker,
    );
    assert_target_token_capability_contract(&sources.process);
    assert_remote_snapshot_contract(&sources.process, &sources.launcher);
    assert_user_object_duplicate_contract(&sources.process);
    assert_guardian_loader_contract(&sources.process, &sources.guardian, &sources.backend);
}

fn replace_once(source: &mut String, from: &str, to: &str) {
    assert_eq!(
        source.matches(from).count(),
        1,
        "mutation selector must be unique: {from}"
    );
    *source = source.replacen(from, to, 1);
}

fn assert_remote_snapshot_mutant_rejected(
    mut mutate: impl FnMut(&mut WindowsHandleOwnershipSources),
) {
    for normalize_crlf in [false, true] {
        let mut sources = WindowsHandleOwnershipSources::load();
        if normalize_crlf {
            sources.convert_line_endings_to_crlf();
            sources.normalize_line_endings();
        }
        mutate(&mut sources);
        assert!(!remote_snapshot_contract_holds(
            &sources.process,
            &sources.launcher
        ));
    }
}

fn assert_target_token_capability_mutant_rejected(mut mutate: impl FnMut(&mut String)) {
    for normalize_crlf in [false, true] {
        let mut sources = WindowsHandleOwnershipSources::load();
        if normalize_crlf {
            sources.convert_line_endings_to_crlf();
            sources.normalize_line_endings();
        }
        mutate(&mut sources.process);
        assert!(!target_token_capability_contract_holds(&sources.process));
    }
}

fn assert_broker_raw_duplicate_mutant_rejected(
    mut mutate: impl FnMut(&mut WindowsHandleOwnershipSources),
) {
    for normalize_crlf in [false, true] {
        let mut sources = WindowsHandleOwnershipSources::load();
        if normalize_crlf {
            sources.convert_line_endings_to_crlf();
            sources.normalize_line_endings();
        }
        mutate(&mut sources);
        assert!(!broker_raw_duplicate_inventory_holds(
            &sources.session_broker
        ));
    }
}

fn assert_broker_primary_thread_narrowing_mutant_rejected(mut mutate: impl FnMut(&mut String)) {
    for normalize_crlf in [false, true] {
        let mut sources = WindowsHandleOwnershipSources::load();
        if normalize_crlf {
            sources.convert_line_endings_to_crlf();
            sources.normalize_line_endings();
        }
        mutate(&mut sources.process);
        assert!(!raw_duplicate_inventory_holds(&sources.process));
    }
}

#[test]
fn broker_primary_thread_narrowing_rejects_request_grant_and_diagnostic_mutants() {
    assert_broker_primary_thread_narrowing_mutant_rejected(|process| {
        replace_once(
            process,
            "&raw mut duplicate,\n            requested_access,\n            0,\n            0,",
            "&raw mut duplicate,\n            expected_granted_access,\n            0,\n            0,",
        );
    });
    assert_broker_primary_thread_narrowing_mutant_rejected(|process| {
        replace_once(
            process,
            "&raw mut duplicate,\n            requested_access,\n            0,\n            0,",
            "&raw mut duplicate,\n            requested_access,\n            1,\n            0,",
        );
    });
    assert_broker_primary_thread_narrowing_mutant_rejected(|process| {
        replace_once(
            process,
            "actual_granted_access != expected_granted_access",
            "actual_granted_access & expected_granted_access != expected_granted_access",
        );
    });
    assert_broker_primary_thread_narrowing_mutant_rejected(|process| {
        replace_once(
            process,
            "requested_access={requested_access:#010x}",
            "requested_access=omitted",
        );
    });
    assert_broker_primary_thread_narrowing_mutant_rejected(|process| {
        replace_once(
            process,
            "super::session_broker::HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,\n        super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,",
            "super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,\n        super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,",
        );
    });
}

#[test]
fn broker_handle_transfer_contract_rejects_namespace_and_ownership_mutants() {
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "DuplicateHandle(\n            GetCurrentProcess(),\n            source,\n            launcher,",
            "DuplicateHandle(\n            launcher,\n            source,\n            GetCurrentProcess(),",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "if let Err(error) = self.revoke_before_delivery() {",
            "if let Err(error) = Ok(()) {",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "super::process::revoke_remote_handle(remote, self.launcher)",
            "Ok(())",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "self.remote_process.take()",
            "self.remote_process",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "source,\n            launcher,\n            &raw mut remote,",
            "source,\n            GetCurrentProcess(),\n            &raw mut remote,",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "&raw mut remote,\n            access,\n            0,\n            0,",
            "&raw mut remote,\n            0,\n            0,\n            0,",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "&raw mut remote,\n            access,\n            0,\n            0,",
            "&raw mut remote,\n            access,\n            1,\n            0,",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "&raw mut remote,\n            access,\n            0,\n            0,",
            "&raw mut remote,\n            0,\n            0,\n            DUPLICATE_SAME_ACCESS,",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "match encode_protocol_handle(remote, \"transferred-holder\") {",
            "match Ok(remote as usize as u64) {",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "transfer_rollback.record_process(remote_process);",
            "let _ = remote_process;",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        let launch = "&SessionBrokerFrameV1::Launched(launched.clone()),";
        let disarm = "transfer_rollback.disarm_after_launched_delivery();";
        replace_once(&mut sources.session_broker, launch, "__LAUNCHED_SENTINEL__");
        replace_once(&mut sources.session_broker, disarm, launch);
        replace_once(&mut sources.session_broker, "__LAUNCHED_SENTINEL__", disarm);
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        sources.session_broker.push_str("\nDuplicateHandle(");
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "OwnedHandle::new(decode_protocol_handle(\n            launched.holder_process_handle,",
            "OwnedHandle::new(launched.holder_process_handle as usize as HANDLE /*",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "holder_thread_id: u32,",
            "holder_thread_handle: u64,",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "pub(crate) const SESSION_BROKER_SCHEMA_VERSION: u32 = 5;",
            "pub(crate) const SESSION_BROKER_SCHEMA_VERSION: u32 = 4;",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;",
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME | 0x0002;",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN;",
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_THREAD_TOKEN;",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS | THREAD_QUERY_LIMITED_INFORMATION;",
            "HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS;",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "OpenThread(HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS, 0, thread_id)",
            "OpenThread(HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS, 0, thread_id)",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "actual_granted_access != expected_granted_access",
            "actual_granted_access & expected_granted_access != expected_granted_access",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "actual_granted_access={actual_granted_access:#010x}",
            "actual_granted_access=omitted",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 0, launched.holder_thread_id)",
            "OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 1, launched.holder_thread_id)",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "if launched.holder_thread_id == 0 {",
            "if false {",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "holder_thread_id: holder.primary_thread_id,",
            "holder_thread_id: 1,",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "launched.binding_sha256.clear();",
            "launched.binding_sha256.clear();\n    launched.holder_thread_id = 0;",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "actual_thread_process_id != launched.holder_identity.process_id",
            "false",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "&SessionBrokerFrameV1::Ack {",
            "&SessionBrokerFrameV1::Failed { /* Ack moved before attestation */",
        );
    });
    assert_broker_raw_duplicate_mutant_rejected(|sources| {
        replace_once(
            &mut sources.session_broker,
            "let thread = OwnedHandle::new(unsafe {\n            OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 0, launched.holder_thread_id)\n        })?;",
            "let thread = unsafe {\n            OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 0, launched.holder_thread_id)\n        }?;",
        );
    });
}

#[test]
fn checked_launcher_job_decode_is_part_of_raw_handle_inventory() {
    for normalize_crlf in [false, true] {
        let mut sources = WindowsHandleOwnershipSources::load();
        if normalize_crlf {
            sources.convert_line_endings_to_crlf();
            sources.normalize_line_endings();
        }
        replace_once(
            &mut sources.process,
            "super::session_broker::decode_protocol_handle(launcher_job_handle, \"launcher-job\")?",
            "launcher_job_handle as usize as HANDLE",
        );
        assert!(!raw_duplicate_inventory_holds(&sources.process));
    }
}

#[test]
fn target_token_capability_contract_rejects_namespace_rights_and_ownership_mutants() {
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "const TARGET_TOKEN_CAPABILITY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE;",
            "const TARGET_TOKEN_CAPABILITY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_IMPERSONATE;",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            TARGET_TOKEN_REMOTE_DUPLICATE,
            "DuplicateHandle(\n            process,\n            handle,\n            process,\n            &raw mut remote,\n            TARGET_TOKEN_CAPABILITY_ACCESS,\n            0,\n            0,\n        )",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "process,\n            &raw mut remote,\n            TARGET_TOKEN_CAPABILITY_ACCESS,\n            0,\n            0,",
            "GetCurrentProcess(),\n            &raw mut remote,\n            TARGET_TOKEN_CAPABILITY_ACCESS,\n            0,\n            0,",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "TARGET_TOKEN_CAPABILITY_ACCESS,\n            0,\n            0,",
            "TARGET_TOKEN_CAPABILITY_ACCESS,\n            1,\n            0,",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "TARGET_TOKEN_CAPABILITY_ACCESS,\n            0,\n            0,",
            "TARGET_TOKEN_CAPABILITY_ACCESS,\n            0,\n            DUPLICATE_SAME_ACCESS,",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            ".map(|handle| OwnedHandle::new(handle as usize as HANDLE))",
            ".map(|handle| handle as usize as HANDLE)",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "verify_not_inheritable(target_token.raw())?;",
            "let _ = target_token.raw();",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "target_token_capability_handle: Some(target_token_handle),",
            "target_token_capability_handle: None,",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "(TargetDesktopBootstrapRoleV1::Probe, None) => None,",
            "(TargetDesktopBootstrapRoleV1::Probe, Some(handle)) => Some(handle),",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "target_token_handle == launcher_process_handle",
            "false",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        replace_once(
            process,
            "bootstrap_job.contains(bootstrap_process.raw())?",
            "bootstrap_job.handle() == bootstrap_process.raw()",
        );
    });
    assert_target_token_capability_mutant_rejected(|process| {
        process.push_str("\nDuplicateHandle(");
    });
}

#[test]
fn remote_snapshot_contract_rejects_count_preserving_and_inventory_mutants() {
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            "DuplicateHandle(\n            source_process,\n            remote_value,",
            "DuplicateHandle(\n            GetCurrentProcess(),\n            remote_value,",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            "source_process,\n            remote_value,\n            GetCurrentProcess(),",
            "source_process,\n            expected_local,\n            GetCurrentProcess(),",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            "remote_value,\n            GetCurrentProcess(),\n            &raw mut snapshot,",
            "remote_value,\n            source_process,\n            &raw mut snapshot,",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            "GetCurrentProcess(),\n            &raw mut snapshot,\n            0,",
            "GetCurrentProcess(),\n            ptr::null_mut(),\n            0,",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            "&raw mut snapshot,\n            0,\n            0,\n            DUPLICATE_SAME_ACCESS,",
            "&raw mut snapshot,\n            0,\n            1,\n            DUPLICATE_SAME_ACCESS,",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            "&raw mut snapshot,\n            0,\n            0,\n            DUPLICATE_SAME_ACCESS,",
            "&raw mut snapshot,\n            0,\n            0,\n            0,",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            "let snapshot = OwnedHandle::new(snapshot)?;",
            "let snapshot = snapshot;",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            "CompareObjectHandles(snapshot.raw(), expected_local)",
            "CompareObjectHandles(remote_value, expected_local)",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.launcher,
            REMOTE_SNAPSHOT_CALLER,
            "match super::process::compare_remote_handle_object(GetCurrentProcess(), raw, raw)",
        );
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        let authorization = "if let Err(detail) = cleanup_guard.record.authorize() {";
        let sentinel = "if let Err(detail) = __REMOTE_SNAPSHOT_AUTHORIZATION_SENTINEL__ {";
        replace_once(&mut sources.launcher, REMOTE_SNAPSHOT_CALLER, sentinel);
        replace_once(&mut sources.launcher, authorization, REMOTE_SNAPSHOT_CALLER);
        replace_once(&mut sources.launcher, sentinel, authorization);
    });
    assert_remote_snapshot_mutant_rejected(|sources| {
        replace_once(
            &mut sources.process,
            REMOTE_SNAPSHOT_DUPLICATE,
            "DuplicateHandle_removed()",
        );
    });
}

#[test]
fn control_handle_transfers_name_source_process_ownership_explicitly() {
    let sources = WindowsHandleOwnershipSources::load();
    assert_control_transfer_contract(&sources.control);
}

#[test]
fn every_raw_duplicate_handle_call_has_a_declared_process_namespace() {
    let sources = WindowsHandleOwnershipSources::load();
    assert_raw_duplicate_contract(
        &sources.control,
        &sources.process,
        &sources.qualification,
        &sources.token,
        &sources.session_broker,
    );
    assert_target_token_capability_contract(&sources.process);
    assert_remote_snapshot_contract(&sources.process, &sources.launcher);
}

#[test]
fn assigned_user_objects_are_pinned_by_exact_reduced_owned_duplicates() {
    let sources = WindowsHandleOwnershipSources::load();
    assert_user_object_duplicate_contract(&sources.process);
}

#[test]
fn guardian_loader_context_is_exact_and_runs_in_both_native_windows_lanes() {
    let sources = WindowsHandleOwnershipSources::load();
    assert_guardian_loader_contract(&sources.process, &sources.guardian, &sources.backend);
}

#[test]
fn handle_ownership_contract_is_identical_after_crlf_checkout_normalization() {
    let lf = WindowsHandleOwnershipSources::load();
    assert_full_handle_ownership_contract(&lf);

    let mut crlf = WindowsHandleOwnershipSources::load();
    crlf.convert_line_endings_to_crlf();
    crlf.normalize_line_endings();
    assert_full_handle_ownership_contract(&crlf);
}

#[test]
fn certification_handle_layout_is_coordinated_across_control_and_launcher() {
    let sources = WindowsHandleOwnershipSources::load();
    assert_certification_handle_layout_contract(
        &sources.control,
        &sources.launcher,
        &sources.process,
        &sources.qualification,
    );
}

#[test]
fn certification_handle_order_contract_rejects_post_impersonation_preparation() {
    let preparation = "prepare_frontend_canaries(\"restricted\")";
    let constructor = "impersonate_restricted_current_thread";
    let intended = format!("{preparation}\n{constructor}");
    let mutant = format!("{constructor}\n{preparation}");
    assert!(frontend_canary_precedes_fixture(
        &intended,
        preparation,
        constructor
    ));
    assert!(!frontend_canary_precedes_fixture(
        &mutant,
        preparation,
        constructor
    ));
}
