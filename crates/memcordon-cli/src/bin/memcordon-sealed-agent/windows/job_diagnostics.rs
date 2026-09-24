//! Private, typed classification for errors emitted by Job and target wrappers.
use memcordon_core::{
    AttemptObservationPhaseV1, CausalEventV1, DiagnosticOriginV1, FailureCategoryV1, FailureCodeV1,
    FailureOperationV1, NativeFailureCodeV1, SafeDiagnosticDetailV1,
};

pub(super) fn event(operation: FailureOperationV1, captured_native: Option<i32>) -> CausalEventV1 {
    use FailureCategoryV1 as Category;
    use FailureCodeV1 as Code;
    use FailureOperationV1 as Operation;

    let (category, code) = match operation {
        Operation::QueryJobAccounting
        | Operation::QueryJobProcessIds
        | Operation::QueryPeakMemory
        | Operation::ReadJobNotification => (Category::Monitor, Code::JobQuery),
        Operation::ResumeTarget => (Category::Launch, Code::TargetResume),
        Operation::VerifySuspendedTarget => (Category::Launch, Code::PolicyReadback),
        Operation::PollTarget | Operation::ReadTargetExit => (Category::Monitor, Code::TargetQuery),
        Operation::CheckGuardian => (Category::Monitor, Code::GuardianLoss),
        Operation::TerminateJob => (Category::Cleanup, Code::UnexpectedProviderFailure),
        _ => (Category::Launch, Code::UnexpectedProviderFailure),
    };
    CausalEventV1 {
        sequence: 0,
        origin: DiagnosticOriginV1::Launcher,
        category,
        operation,
        code,
        native_code: captured_native
            .map(|value| NativeFailureCodeV1::Win32(u32::from_ne_bytes(value.to_ne_bytes()))),
        // The attempt-local capture owner replaces this with its active phase.
        observed_phase: AttemptObservationPhaseV1::Monitoring,
        safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    }
}

pub(super) fn public_code(operation: FailureOperationV1) -> &'static str {
    use FailureOperationV1 as Operation;
    match operation {
        Operation::QueryJobProcessIds => "MCSEALED-WINDOWS-JOB-PROCESS-IDS",
        Operation::QueryPeakMemory => "MCSEALED-WINDOWS-JOB-PEAK-MEMORY",
        Operation::ReadJobNotification => "MCSEALED-WINDOWS-JOB-NOTIFICATION",
        Operation::ResumeTarget => "MCSEALED-WINDOWS-TARGET-RESUME",
        Operation::PollTarget => "MCSEALED-WINDOWS-TARGET-POLL",
        Operation::ReadTargetExit => "MCSEALED-WINDOWS-TARGET-EXIT",
        _ => "MCSEALED-WINDOWS-JOB-QUERY",
    }
}
