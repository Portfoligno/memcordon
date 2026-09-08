use super::*;
use memcordon_core::*;

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
