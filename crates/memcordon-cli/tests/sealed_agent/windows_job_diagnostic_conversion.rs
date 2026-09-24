use super::*;
use memcordon_core::{
    AttemptObservationPhaseV1 as Phase, FailureCategoryV1 as Category, FailureCodeV1 as Code,
    FailureOperationV1 as Operation, NativeFailureCodeV1, OriginalFailureV1,
    WindowsCausalDiagnosticsV1,
};
use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, SetLastError};

fn observed(journal: &WindowsCausalDiagnosticsV1) -> &memcordon_core::CausalEventV1 {
    match &journal.original {
        OriginalFailureV1::Observed { event } => event,
        other => panic!("expected observed original, got {other:?}"),
    }
}

fn journal() -> WindowsCausalDiagnosticsV1 {
    let mut result = WindowsCausalDiagnosticsV1::default();
    super::super::diagnostics::merge_into(&mut result);
    result
}

fn error(operation: Operation, native: Option<i32>) -> super::super::job::JobObservationError {
    super::super::job::JobObservationError {
        operation,
        source: native.map_or_else(
            || io::Error::other("semantic test failure"),
            io::Error::from_raw_os_error,
        ),
    }
}

#[test]
fn job_accounting_conversion_preserves_monitor_classification() {
    let _scope = super::super::diagnostics::AttemptDiagnosticScope::enter();
    super::super::diagnostics::set_phase(Phase::Monitoring);
    let native = super::super::job::wrong_object_accounting_error();
    assert_eq!(native.operation, Operation::QueryJobAccounting);
    assert_eq!(
        native.source.raw_os_error(),
        Some(ERROR_INVALID_HANDLE as i32)
    );
    // Changing the thread-local last-error slot must not change the captured value.
    unsafe { SetLastError(1234) };
    let failure = LaunchAttemptError::from(native);
    let snapshot = journal();
    let original = observed(&snapshot);
    assert_eq!(snapshot.sequence, 1);
    assert_eq!(original.category, Category::Monitor);
    assert_eq!(original.operation, Operation::QueryJobAccounting);
    assert_eq!(original.code, Code::JobQuery);
    assert_eq!(original.observed_phase, Phase::Monitoring);
    assert_eq!(
        original.native_code,
        Some(NativeFailureCodeV1::Win32(ERROR_INVALID_HANDLE))
    );
    assert_eq!(failure.observation().operation, original.operation);
    assert_eq!(failure.observation().category, original.category);
    assert_eq!(failure.observation().code, original.code);
    let original_sequence = original.sequence;
    super::super::diagnostics::capture(memcordon_core::CausalEventV1 {
        operation: Operation::ValidateTerminalResponse,
        code: Code::TerminalBinding,
        ..super::super::job_diagnostics::event(Operation::QueryJobAccounting, None)
    });
    let later = journal();
    assert_eq!(observed(&later).sequence, original_sequence);
    assert_eq!(later.secondary.as_slice().len(), 1);
    assert!(later.secondary.as_slice()[0].sequence > original_sequence);
}

#[test]
fn job_observation_mapping_covers_emitted_operations() {
    let cases = [
        (
            Operation::QueryJobAccounting,
            Category::Monitor,
            Code::JobQuery,
            "MCSEALED-WINDOWS-JOB-QUERY",
        ),
        (
            Operation::QueryJobProcessIds,
            Category::Monitor,
            Code::JobQuery,
            "MCSEALED-WINDOWS-JOB-PROCESS-IDS",
        ),
        (
            Operation::QueryPeakMemory,
            Category::Monitor,
            Code::JobQuery,
            "MCSEALED-WINDOWS-JOB-PEAK-MEMORY",
        ),
        (
            Operation::ReadJobNotification,
            Category::Monitor,
            Code::JobQuery,
            "MCSEALED-WINDOWS-JOB-NOTIFICATION",
        ),
        (
            Operation::ResumeTarget,
            Category::Launch,
            Code::TargetResume,
            "MCSEALED-WINDOWS-TARGET-RESUME",
        ),
        (
            Operation::VerifySuspendedTarget,
            Category::Launch,
            Code::PolicyReadback,
            "MCSEALED-WINDOWS-JOB-QUERY",
        ),
        (
            Operation::PollTarget,
            Category::Monitor,
            Code::TargetQuery,
            "MCSEALED-WINDOWS-TARGET-POLL",
        ),
        (
            Operation::ReadTargetExit,
            Category::Monitor,
            Code::TargetQuery,
            "MCSEALED-WINDOWS-TARGET-EXIT",
        ),
        (
            Operation::CheckGuardian,
            Category::Monitor,
            Code::GuardianLoss,
            "MCSEALED-WINDOWS-JOB-QUERY",
        ),
        (
            Operation::TerminateJob,
            Category::Cleanup,
            Code::UnexpectedProviderFailure,
            "MCSEALED-WINDOWS-JOB-QUERY",
        ),
    ];
    for (operation, category, code, display) in cases {
        assert_eq!(
            super::super::job_diagnostics::public_code(operation),
            display
        );
        let event = super::super::job_diagnostics::event(operation, Some(i32::MIN));
        assert_eq!(
            (event.category, event.code, event.operation),
            (category, code, operation)
        );
        assert_eq!(
            event.native_code,
            Some(NativeFailureCodeV1::Win32(0x8000_0000))
        );
        assert_eq!(
            super::super::job_diagnostics::event(operation, None).native_code,
            None
        );
        let _scope = super::super::diagnostics::AttemptDiagnosticScope::enter();
        let phase = match operation {
            Operation::ResumeTarget => Phase::ResumeAttempted,
            Operation::TerminateJob => Phase::Cleaning,
            _ => Phase::Monitoring,
        };
        super::super::diagnostics::set_phase(phase);
        let failure = LaunchAttemptError::from(error(operation, Some(i32::MIN)));
        assert_eq!(failure.code, display);
        let snapshot = journal();
        let original = observed(&snapshot);
        assert_eq!(
            (original.category, original.code, original.operation),
            (category, code, operation)
        );
        assert_eq!(original.observed_phase, phase);
        assert_eq!(
            original.native_code,
            Some(NativeFailureCodeV1::Win32(0x8000_0000))
        );
        assert_eq!(failure.observation().operation, operation);
        drop(_scope);
        let _string_scope = super::super::diagnostics::AttemptDiagnosticScope::enter();
        super::super::diagnostics::set_phase(phase);
        let _detail = String::from(error(operation, None));
        let string_snapshot = journal();
        let string_original = observed(&string_snapshot);
        assert_eq!(
            (
                string_original.category,
                string_original.code,
                string_original.operation,
            ),
            (category, code, operation)
        );
        assert_eq!(string_original.observed_phase, phase);
        assert_eq!(string_original.native_code, None);
    }
    let unexpected = Operation::UnclassifiedProviderOperation;
    let event = super::super::job_diagnostics::event(unexpected, Some(1234));
    assert_eq!(event.category, Category::Launch);
    assert_eq!(event.code, Code::UnexpectedProviderFailure);
    assert_eq!(event.operation, unexpected);
    assert_eq!(event.native_code, Some(NativeFailureCodeV1::Win32(1234)));
}

#[test]
fn job_string_conversion_preserves_semantics() {
    for (operation, category, code, phase) in [
        (
            Operation::ResumeTarget,
            Category::Launch,
            Code::TargetResume,
            Phase::ResumeAttempted,
        ),
        (
            Operation::VerifySuspendedTarget,
            Category::Launch,
            Code::PolicyReadback,
            Phase::ResumeAttempted,
        ),
        (
            Operation::PollTarget,
            Category::Monitor,
            Code::TargetQuery,
            Phase::Monitoring,
        ),
        (
            Operation::ReadTargetExit,
            Category::Monitor,
            Code::TargetQuery,
            Phase::Monitoring,
        ),
        (
            Operation::CheckGuardian,
            Category::Monitor,
            Code::GuardianLoss,
            Phase::Monitoring,
        ),
        (
            Operation::TerminateJob,
            Category::Cleanup,
            Code::UnexpectedProviderFailure,
            Phase::Cleaning,
        ),
    ] {
        let _scope = super::super::diagnostics::AttemptDiagnosticScope::enter();
        super::super::diagnostics::set_phase(phase);
        let detail = String::from(error(operation, None));
        let _outer = LaunchAttemptError::from(detail);
        let snapshot = journal();
        let original = observed(&snapshot);
        assert_eq!(
            (original.category, original.code, original.operation),
            (category, code, operation)
        );
        assert_eq!(original.native_code, None);
        assert_eq!(original.observed_phase, phase);
        assert_eq!(snapshot.secondary.as_slice().len(), 1);
        assert!(snapshot.secondary.as_slice()[0].sequence > original.sequence);
    }
}

#[test]
fn job_diagnostic_reconstruction_preserves_operation() {
    for operation in [
        Operation::QueryJobAccounting,
        Operation::CheckGuardian,
        Operation::VerifySuspendedTarget,
    ] {
        let _scope = super::super::diagnostics::AttemptDiagnosticScope::enter();
        let failure = LaunchAttemptError::from(error(operation, None));
        let original = journal();
        assert_eq!(failure.observation().operation, operation);
        assert_eq!(failure.observation().category, observed(&original).category);
        assert_eq!(failure.observation().code, observed(&original).code);
    }
}
