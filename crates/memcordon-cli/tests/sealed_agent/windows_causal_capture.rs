use super::*;
use memcordon_core::*;

#[test]
fn native_invalid_handle_capture_preserves_first_cause_across_phase_change() {
    let evidence = crate::windows::readiness_receipt::begin(
        "windows::diagnostics::causal_capture_tests::native_invalid_handle_capture_preserves_first_cause_across_phase_change",
    );
    let _scope = AttemptDiagnosticScope::enter();
    set_phase(AttemptObservationPhaseV1::AuthorizedBeforeResume);
    let mut created = windows_sys::Win32::Foundation::FILETIME::default();
    let mut exited = windows_sys::Win32::Foundation::FILETIME::default();
    let mut kernel = windows_sys::Win32::Foundation::FILETIME::default();
    let mut user = windows_sys::Win32::Foundation::FILETIME::default();
    // SAFETY: this deliberately invalid null handle references no process; all
    // output buffers are initialized writable values. Capture last-error before
    // any other OS operation can overwrite it.
    let first_return = unsafe {
        windows_sys::Win32::System::Threading::GetProcessTimes(
            std::ptr::null_mut(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    };
    let first_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    assert_eq!(first_return, 0);
    assert_eq!(first_code, 6);
    capture_native(
        FailureOperationV1::ReadTargetExit,
        Some(first_code as i32),
        FailureCodeV1::TargetQuery,
    );
    let mut before = WindowsCausalDiagnosticsV1::default();
    merge_into(&mut before);
    set_phase(AttemptObservationPhaseV1::Monitoring);
    let mut status = 0;
    // SAFETY: again no process is accessed, and the exit-code buffer is writable.
    let second_return = unsafe {
        windows_sys::Win32::System::Threading::GetExitCodeProcess(std::ptr::null_mut(), &mut status)
    };
    let second_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    assert_eq!(second_return, 0);
    assert_eq!(second_code, 6);
    capture_native(
        FailureOperationV1::PollTarget,
        Some(second_code as i32),
        FailureCodeV1::TargetQuery,
    );
    let mut after = WindowsCausalDiagnosticsV1::default();
    merge_into(&mut after);
    assert_eq!(before.original, after.original);
    assert_eq!(before.sequence, 1);
    assert_eq!(after.sequence, 2);
    assert_eq!(after.secondary.as_slice().len(), 1);
    assert!(after.is_consistent());
    if let Some(evidence) = evidence {
        let before_journal =
            evidence.retain("before-journal.json", &serde_json::to_vec(&before).unwrap());
        let after_journal =
            evidence.retain("after-journal.json", &serde_json::to_vec(&after).unwrap());
        evidence.finish_payload(serde_json::json!({"kind":"causal-capture","before_journal":before_journal,
            "after_journal":after_journal,"first_api":"GetProcessTimes","first_return":first_return,
            "first_win32_code":first_code,"second_api":"GetExitCodeProcess","second_return":second_return,
            "second_win32_code":second_code,"invalid_handle_was_null":true}));
    }
}

fn failure(code: u32) -> CausalEventV1 {
    CausalEventV1 {
        sequence: 0,
        origin: DiagnosticOriginV1::Launcher,
        category: FailureCategoryV1::Monitor,
        operation: FailureOperationV1::QueryPeakMemory,
        code: FailureCodeV1::JobQuery,
        native_code: Some(NativeFailureCodeV1::Win32(code)),
        observed_phase: AttemptObservationPhaseV1::Monitoring,
        safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    }
}

#[test]
fn source_capture_and_record_cleanup_share_one_ordered_journal() {
    let _scope = AttemptDiagnosticScope::enter();
    capture(failure(1234));
    let mut record = WindowsCausalDiagnosticsV1::default();
    observe_record(&mut record, failure(4321), true);
    capture(failure(5678));
    merge_into(&mut record);
    assert_eq!(record.sequence, 3);
    assert!(
        matches!(record.original, OriginalFailureV1::Observed { ref event } if event.native_code == Some(NativeFailureCodeV1::Win32(1234)))
    );
    assert_eq!(
        record
            .secondary
            .as_slice()
            .iter()
            .map(|event| event.native_code.clone())
            .collect::<Vec<_>>(),
        vec![
            Some(NativeFailureCodeV1::Win32(4321)),
            Some(NativeFailureCodeV1::Win32(5678))
        ]
    );
    assert!(record.is_consistent());
}

#[test]
fn unwinding_and_reentrant_capture_preserve_original_and_expose_loss() {
    let _scope = AttemptDiagnosticScope::enter();
    capture(failure(1234));
    let _ = std::panic::catch_unwind(|| panic!("injected owner unwind"));
    CURRENT.with(|current| {
        let current = current.borrow();
        let _busy = current.as_ref().unwrap().borrow_mut();
        capture(failure(9999));
    });
    let mut record = WindowsCausalDiagnosticsV1::default();
    observe_record(&mut record, failure(4321), true);
    assert!(record.loss.writer_unavailable);
    assert!(
        matches!(record.original, OriginalFailureV1::Observed { ref event } if event.native_code == Some(NativeFailureCodeV1::Win32(1234)))
    );
    assert_eq!(record.sequence, 2);
}
