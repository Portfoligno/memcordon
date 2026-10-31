//! Corrupt-snapshot report shape and independently recovered original terminal.
use memcordon_core::{
    DiagnosticSha256,
    execution_facts::CleanupStateV1,
    result_v3::{LinuxWorkloadTerminalV1, NativeWorkloadOutcomeV1, ReleaseKnowledgeV3, ResultV3},
    workload_request::WorkloadAttemptAssociationV1,
};

pub fn validate(
    report: &ResultV3,
    terminal: &LinuxWorkloadTerminalV1,
    association: &WorkloadAttemptAssociationV1,
    request: &DiagnosticSha256,
    original_frontend: (u32, u64),
    original_status: Option<i32>,
) -> Result<(), String> {
    report.validate()?;
    terminal.validate()?;
    crate::linux_result_publication::publication_writer(report.delivery, original_frontend)?;
    crate::linux_result_publication::wrapper_status(
        original_status,
        report.outcome.wrapper_status,
    )?;
    crate::linux_result_publication::intake_report(
        report,
        terminal,
        association,
        request,
        original_frontend,
        original_status,
    )?;
    if report.release != ReleaseKnowledgeV3::NotReleased {
        return Err("corrupt snapshot report release differs".into());
    }
    if report.provider.as_ref() != Some(&association.provider)
        || report.workload_attempt.as_ref() != Some(association)
        || report.request.as_ref().map(|value| &value.request_sha256) != Some(request)
    {
        return Err("corrupt snapshot report original request/provider/attempt differs".into());
    }
    if terminal.association != *association || terminal.request.request_sha256 != *request {
        return Err("corrupt snapshot recovery original request/provider/attempt differs".into());
    }
    if terminal.release != ReleaseKnowledgeV3::NotReleased
        || terminal.native.is_some()
        || terminal.outcome != NativeWorkloadOutcomeV1::SetupFailure
    {
        return Err("corrupt snapshot recovery reached execution or lost setup failure".into());
    }
    // Allocated report cleanup must agree with the authenticated recovery.
    if terminal.cleanup.state != CleanupStateV1::Complete {
        return Err("corrupt snapshot authenticated recovery cleanup is not complete".into());
    }
    if !terminal
        .failures
        .as_slice()
        .iter()
        .any(|failure| failure.as_str().contains("member content digest differs"))
    {
        return Err("corrupt snapshot recovery lacks member-content digest refusal".into());
    }
    Ok(())
}
