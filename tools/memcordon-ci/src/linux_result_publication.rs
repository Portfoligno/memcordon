//! Publication facts checked against the original held frontend and its sole wait.
use memcordon_core::{
    execution_facts::{CleanupStateV1, NativeProcessV2, OutcomeKindV1, OutcomeV1},
    result_v3::{CleanupV3, DeliveryStateV3, RuntimeExecutionV3},
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

/// Conservative report shape only. Actual native cleanup must be proved separately.
pub fn preparation_report(
    runtime: &RuntimeExecutionV3,
    cleanup: &CleanupV3,
    outcome: &OutcomeV1,
) -> Result<(), String> {
    if !matches!(runtime, RuntimeExecutionV3::PreparationFailed { .. })
        || cleanup.state != CleanupStateV1::Unknown
        || !cleanup.obligations.as_slice().is_empty()
        || outcome.kind != OutcomeKindV1::LaunchFailure
        || outcome.wrapper_status != 125
        || outcome.native_termination.is_some()
    {
        return Err(format!(
            "preparation-failure report shape differs; preparation-failed={}; cleanup-state={:?}; cleanup-obligations={}; outcome-kind={:?}; wrapper-status={}; native-termination-present={}",
            matches!(runtime, RuntimeExecutionV3::PreparationFailed { .. }),
            cleanup.state,
            cleanup.obligations.as_slice().len(),
            outcome.kind,
            outcome.wrapper_status,
            outcome.native_termination.is_some()
        ));
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
