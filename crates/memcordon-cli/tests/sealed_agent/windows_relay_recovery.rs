use super::*;

#[test]
fn startup_recovery_keeps_admission_closed_until_exact_ack_retirement() {
    let gate = StartupRecoveryAdmission::new(true);
    assert!(gate.require_clear(|| Ok(false)).is_err());
    let failure = gate
        .require_clear(|| Err("authenticated retirement could not be read".into()))
        .unwrap_err();
    assert_eq!(failure, "authenticated retirement could not be read");
    assert!(gate.require_clear(|| Ok(false)).is_err());
    gate.require_clear(|| Ok(true)).unwrap();
    gate.require_clear(|| {
        panic!("settled startup bindings must not inspect unrelated later live attempts")
    })
    .unwrap();
}

#[test]
fn clean_startup_admits_work_without_recovery_or_global_idle_requirement() {
    let gate = StartupRecoveryAdmission::new(false);
    gate.require_clear(|| panic!("clean startup must permit ordinary concurrent admission"))
        .unwrap();
}

fn anonymous_control_pipe() -> (OwnedHandle, OwnedHandle) {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    // SAFETY: initialized output handles; no inherited handles.
    assert_ne!(
        unsafe {
            windows_sys::Win32::System::Pipes::CreatePipe(
                &raw mut read,
                &raw mut write,
                ptr::null(),
                0,
            )
        },
        0
    );
    (
        OwnedHandle::new(read).unwrap(),
        OwnedHandle::new(write).unwrap(),
    )
}

#[test]
fn actual_late_write_loss_preserves_original_and_requires_channel_close() {
    use memcordon_core::*;
    let _scope = super::super::diagnostics::AttemptDiagnosticScope::enter();
    super::super::diagnostics::capture_native(
        FailureOperationV1::QueryPeakMemory,
        Some(5),
        FailureCodeV1::JobQuery,
    );
    let (read, write) = anonymous_control_pipe();
    drop(read);
    let mut pending = Some(LaunchAttemptError::from(
        "earlier original failure".to_owned(),
    ));
    let mut before = WindowsCausalDiagnosticsV1::default();
    super::super::diagnostics::merge_into(&mut before);
    let delivered = pipe::write_frame_detailed(write.raw(), &"retired");
    assert!(
        !observe_control_delivery(delivered, "TargetRetired", &mut pending, None)
            .unwrap_or_else(|failure| panic!("{}", failure.detail))
    );
    let retained = pending.unwrap();
    assert_eq!(retained.detail, "earlier original failure");
    assert!(retained.connection_must_close);
    assert!(retained.terminal_candidate.is_none());
    let mut after = WindowsCausalDiagnosticsV1::default();
    super::super::diagnostics::merge_into(&mut after);
    assert_eq!(before.original, after.original);
    assert_eq!(
        after.secondary.as_slice().len(),
        before.secondary.as_slice().len() + 1
    );
    assert_eq!(
        &after.secondary.as_slice()[..before.secondary.as_slice().len()],
        before.secondary.as_slice()
    );
    let late = after.secondary.as_slice().last().unwrap();
    assert_eq!(late.operation, FailureOperationV1::DeliverResponse);
    assert_eq!(late.category, FailureCategoryV1::Transport);
    let child = ChildTermination::WindowsStatus { status: 0 };
    let outcome = failed_retirement_outcome(&retained, child.clone());
    assert!(
        matches!(outcome, RunOutcome::MonitorFailed { error, child_after_termination: Some(observed), cleanup }
        if error == "earlier original failure" && observed == child && cleanup.direct_child_reaped && cleanup.workload_empty == Some(true))
    );
}

#[test]
fn first_late_native_loss_replaces_natural_outcome_before_terminal_seed() {
    use memcordon_core::*;
    let _scope = super::super::diagnostics::AttemptDiagnosticScope::enter();
    // Run the existing test executable's listing mode: a real child with no
    // recursive test execution, shell interpretation, or fabricated status.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    let child = ChildTermination::WindowsStatus {
        status: u32::try_from(status.code().unwrap()).unwrap(),
    };
    for selected in [
        None,
        Some(WindowsSealedFault::FrontendDisconnectedAfterAuthorization),
    ] {
        let _scope = super::super::diagnostics::AttemptDiagnosticScope::enter();
        let (read, write) = anonymous_control_pipe();
        drop(read);
        let mut pending = None;
        let observed = pipe::write_frame_detailed(write.raw(), &"retired").unwrap_err();
        assert_eq!(observed.phase, pipe::FrameWritePhase::Length);
        assert_eq!(observed.transferred_bytes, 0);
        assert!(observed.peer_closed);
        let source_code = observed
            .native_code
            .expect("native closed-reader write code");
        assert!(matches!(
            source_code,
            windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE
                | windows_sys::Win32::Foundation::ERROR_NO_DATA
        ));
        assert!(
            !observe_control_delivery(Err(observed), "TargetRetired", &mut pending, selected)
                .unwrap_or_else(|failure| panic!("{}", failure.detail))
        );
        let failure = pending.unwrap();
        assert!(failure.connection_must_close);
        let mut journal = WindowsCausalDiagnosticsV1::default();
        super::super::diagnostics::merge_into(&mut journal);
        let OriginalFailureV1::Observed { event } = journal.original else {
            panic!("late native failure was not observed")
        };
        assert_eq!(event.category, FailureCategoryV1::Transport);
        assert_eq!(event.operation, FailureOperationV1::DeliverResponse);
        assert_eq!(event.observed_phase, AttemptObservationPhaseV1::Cleaning);
        assert_eq!(
            event.native_code,
            Some(NativeFailureCodeV1::Win32(source_code))
        );
        match selected {
            Some(fault) => assert_eq!(
                event.safe_detail,
                SafeDiagnosticDetailV1::InjectedWindowsFault { fault }
            ),
            None => assert_eq!(
                event.safe_detail,
                SafeDiagnosticDetailV1::NoAdditionalDetail
            ),
        }
        assert!(
            matches!(failed_retirement_outcome(&failure, child.clone()), RunOutcome::MonitorFailed { child_after_termination: Some(observed), .. } if observed == child)
        );
    }
}

#[test]
fn closed_control_channel_does_not_replace_relay_retirement_proof() {
    let (read, write) = anonymous_control_pipe();
    drop(write);
    // SAFETY: unnamed event output is independently owned; current process stays live.
    let event = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) }).unwrap();
    let frontend = unsafe { GetCurrentProcess() };
    assert!(matches!(
        wait_for_relays_retired(read.raw(), "attempt", "nonce", "request", frontend).unwrap(),
        RelayRetirementAcknowledgment::PeerLost(_)
    ));
    assert!(wait_for_relay_retirement_proof(event.raw(), frontend, Instant::now()).is_err());
    // SAFETY: signaling the exact held relay event supplies the independent proof.
    assert_ne!(unsafe { SetEvent(event.raw()) }, 0);
    wait_for_relay_retirement_proof(event.raw(), frontend, Instant::now()).unwrap();
}

#[test]
fn partial_acknowledgment_peer_loss_is_not_a_bound_acknowledgment() {
    for bytes in [vec![20, 0], vec![20, 0, 0, 0, b'{', b'"']] {
        let (read, write) = anonymous_control_pipe();
        let mut written = 0;
        // SAFETY: synchronous write borrows the complete live byte slice.
        assert_ne!(
            unsafe {
                windows_sys::Win32::Storage::FileSystem::WriteFile(
                    write.raw(),
                    bytes.as_ptr(),
                    u32::try_from(bytes.len()).unwrap(),
                    &raw mut written,
                    ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(written as usize, bytes.len());
        drop(write);
        // SAFETY: current process remains live and unsignaled during this call.
        let result = wait_for_relays_retired(read.raw(), "attempt", "nonce", "request", unsafe {
            GetCurrentProcess()
        })
        .unwrap();
        let RelayRetirementAcknowledgment::PeerLost(loss) = result else {
            panic!("partial frame became a bound acknowledgment");
        };
        assert_eq!(
            loss.operation,
            memcordon_core::FailureOperationV1::ReadControlFrame
        );
        assert_eq!(
            loss.native_code,
            Some(windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE)
        );
        assert!(loss.detail.contains("transferred_bytes="));
    }
}

#[test]
fn complete_wrong_binding_acknowledgment_remains_a_refusal() {
    let (read, write) = anonymous_control_pipe();
    let writer = std::thread::spawn(move || {
        pipe::write_frame(
            write.raw(),
            &WindowsLauncherRequestV4::RelaysRetired {
                schema_version: WINDOWS_CURRENT_PRIVATE_PROTOCOL_VERSION,
                attempt_id: "wrong".into(),
                nonce: "nonce".into(),
                request_sha256: "request".into(),
            },
        )
    });
    // SAFETY: current process is a live synchronization handle.
    let result = wait_for_relays_retired(read.raw(), "attempt", "nonce", "request", unsafe {
        GetCurrentProcess()
    });
    if !matches!(&result, Err(detail) if detail == "invalid relay-retirement message") {
        drop(read);
    }
    writer.join().expect("writer settled").unwrap();
    assert!(matches!(result, Err(detail) if detail == "invalid relay-retirement message"));
}

#[test]
fn service_relay_event_survives_worker_handle_and_requires_exact_signal() {
    let event_name = format!(
        "Local\\MemCordonSealedRelayRetirement-Test-{}",
        std::process::id()
    );
    let wide_name = pipe::wide_null(&event_name);
    // SAFETY: private named event with no inherited handle.
    let worker_event =
        OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, wide_name.as_ptr()) })
            .expect("create relay event");
    let frontend_event = super::super::process::duplicate_owned(worker_event.raw())
        .expect("duplicate frontend event");
    let attempt_id = format!("{:064x}", std::process::id());
    let nonce = "relay-recovery-nonce";
    let request_sha256 = "relay-recovery-request";
    let frontend = memcordon_core::WindowsProcessIdentityV1 {
        process_id: std::process::id(),
        creation_time_100ns: 1,
    };
    register_relay_retirement_event(
        &attempt_id,
        nonce,
        request_sha256,
        &frontend,
        &event_name,
        worker_event.raw(),
    )
    .expect("register service proof handle");
    drop(worker_event);
    assert!(
        !frontend_relay_retired_for_recovery(
            &attempt_id,
            nonce,
            request_sha256,
            &frontend,
            &event_name
        )
        .expect("unsignaled event")
    );
    assert!(
        frontend_relay_retired_for_recovery(
            &attempt_id,
            "wrong-nonce",
            request_sha256,
            &frontend,
            &event_name
        )
        .is_err()
    );
    // SAFETY: the test owns a second handle to the exact event object.
    assert_ne!(unsafe { SetEvent(frontend_event.raw()) }, 0);
    assert!(
        frontend_relay_retired_for_recovery(
            &attempt_id,
            nonce,
            request_sha256,
            &frontend,
            &event_name
        )
        .expect("signaled event")
    );
    retire_relay_retirement_event(&attempt_id).expect("close service proof handle");
    assert!(
        frontend_relay_retired_for_recovery(
            &attempt_id,
            nonce,
            request_sha256,
            &frontend,
            &event_name
        )
        .expect("named event survives service duplicate closure")
    );
    drop(frontend_event);
    assert!(
        !frontend_relay_retired_for_recovery(
            &attempt_id,
            nonce,
            request_sha256,
            &frontend,
            &event_name
        )
        .expect("event vanished after last owner closed")
    );
}
