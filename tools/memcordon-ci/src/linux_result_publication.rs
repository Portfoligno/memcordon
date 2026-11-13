//! Publication facts checked against the original held frontend and its sole wait.
use memcordon_core::{
    DiagnosticSha256,
    execution_facts::{CleanupStateV1, NativeProcessV2, OutcomeKindV1},
    result_v3::{
        CleanupResourceV3, CleanupV3, DeliveryStateV3, LinuxWorkloadTerminalV1,
        NativeWorkloadOutcomeV1, ReleaseKnowledgeV3, ResultV3, RuntimeExecutionV3,
    },
    workload_request::{WorkloadAttemptAssociationV1, WorkloadRejectionCodeV1},
};

/// The writer PID is serialized; birth remains bound by the original held owner.
pub fn publication_writer(delivery: DeliveryStateV3, original: (u32, u64)) -> Result<(), String> {
    if original.0 == 0 {
        return Err("persisted result original writer identity is absent".into());
    }
    match delivery {
        DeliveryStateV3::PreparedBy { writer_pid } if writer_pid.get() == original.0 => Ok(()),
        _ => Err(format!(
            "persisted result delivery differs: expected prepared-by original writer {}; observed {delivery:?}",
            original.0
        )),
    }
}

pub fn writer(
    delivery: DeliveryStateV3,
    caller: &NativeProcessV2,
    original: (u32, u64),
) -> Result<(), String> {
    if original.0 == 0 || (caller.pid, caller.birth) != original {
        return Err("result native caller differs from original held frontend".into());
    }
    publication_writer(delivery, original)
}

fn preparation_report(report: &ResultV3) -> Result<(), String> {
    report.validate()?;
    if !matches!(&report.runtime, RuntimeExecutionV3::PreparationFailed { profile } if profile.as_str() == "linux-private-workload-v1")
        || report.release != ReleaseKnowledgeV3::NotReleased
        || report.outcome.kind != OutcomeKindV1::LaunchFailure
        || report.outcome.wrapper_status != 125
        || report.outcome.native_termination.is_some()
    {
        return Err("preparation-failure runtime/profile/release/outcome differs".into());
    }
    Ok(())
}

/// Preallocation report only; allocation absence/settlement remain native obligations.
pub fn preallocation_report(
    report: &ResultV3,
    request: &DiagnosticSha256,
    original: (u32, u64),
    status: Option<i32>,
) -> Result<(), String> {
    preparation_report(report)?;
    publication_writer(report.delivery, original)?;
    wrapper_status(status, report.outcome.wrapper_status)?;
    if report.cleanup.state != CleanupStateV1::Unknown
        || !report.cleanup.obligations.as_slice().is_empty()
        || report.workload_attempt.is_some()
        || report.request.as_ref().map(|value| &value.request_sha256) != Some(request)
        || !report.request_rejection.as_ref().is_some_and(|rejection| {
            rejection.code == WorkloadRejectionCodeV1::UnsupportedRequirement
                && rejection
                    .detail
                    .as_str()
                    .contains("initial loader environment")
        })
    {
        return Err(
            "preallocation loader rejection/report cleanup/request/association differs".into(),
        );
    }
    Ok(())
}

fn intake_cleanup(
    cleanup: &CleanupV3,
) -> Result<std::collections::BTreeMap<CleanupResourceV3, bool>, String> {
    let expected = [
        CleanupResourceV3::Staging,
        CleanupResourceV3::Footprint,
        CleanupResourceV3::Record,
        CleanupResourceV3::ControlHandles,
    ];
    let mut observed = std::collections::BTreeMap::new();
    for obligation in cleanup.obligations.as_slice() {
        if !expected.contains(&obligation.resource)
            || !obligation.settled
            || observed
                .insert(obligation.resource, obligation.settled)
                .is_some()
        {
            return Err("allocated intake cleanup has extra/duplicate/unsettled resources".into());
        }
    }
    if cleanup.state != CleanupStateV1::Complete || observed.len() != expected.len() {
        return Err(
            "allocated intake cleanup is not the exact complete four-resource inventory".into(),
        );
    }
    Ok(observed)
}

/// Requires the existing authenticated terminal; command success is checked separately.
pub fn intake_report(
    report: &ResultV3,
    terminal: &LinuxWorkloadTerminalV1,
    association: &WorkloadAttemptAssociationV1,
    request: &DiagnosticSha256,
    original: (u32, u64),
    status: Option<i32>,
) -> Result<(), String> {
    preparation_report(report)?;
    terminal.validate()?;
    publication_writer(report.delivery, original)?;
    wrapper_status(status, report.outcome.wrapper_status)?;
    if report.request_rejection.is_some()
        || report.workload_attempt.as_ref() != Some(association)
        || report.provider.as_ref() != Some(&association.provider)
        || terminal.association != *association
        || report.request.as_ref() != Some(&terminal.request)
        || terminal.request.request_sha256 != *request
        || terminal.release != ReleaseKnowledgeV3::NotReleased
        || terminal.native.is_some()
        || terminal.outcome != NativeWorkloadOutcomeV1::SetupFailure
    {
        return Err(
            "allocated intake report/terminal original binding or no-execution outcome differs"
                .into(),
        );
    }
    if intake_cleanup(&report.cleanup)? != intake_cleanup(&terminal.cleanup)? {
        return Err("allocated intake report/recovery cleanup mappings differ".into());
    }
    Ok(())
}

pub fn wrapper_status(observed: Option<i32>, reported: i32) -> Result<(), String> {
    match observed {
        Some(status) if status == reported => Ok(()),
        _ => Err(format!(
            "original frontend wrapper status differs: observed={observed:?}; reported={reported}"
        )),
    }
}

pub fn stderr_detail(bytes: &[u8]) -> String {
    let limit = 2048;
    let (head, tail, omitted) = if bytes.len() <= limit {
        (bytes, &[][..], 0)
    } else {
        let section = limit / 2;
        (
            &bytes[..section],
            &bytes[bytes.len() - section..],
            bytes.len() - limit,
        )
    };
    format!(
        "bytes={}; omitted={omitted}; head={:?}; tail={:?}",
        bytes.len(),
        String::from_utf8_lossy(head),
        String::from_utf8_lossy(tail)
    )
}
