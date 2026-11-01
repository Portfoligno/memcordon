//! Export refusal is a frontend failure while the original target can exit normally.
use memcordon_core::{
    BoundedText, ChildTermination,
    execution_facts::{OutcomeKindV1, OutcomeV1},
    result_v3::OutputDeliveryStateV3,
};

pub fn validate(
    scenario: &str,
    outcome: &OutcomeV1,
    delivery: Option<OutputDeliveryStateV3>,
    diagnostics: &[BoundedText<4096>],
    captured_status: Option<i32>,
) -> Result<(), String> {
    let refused = match scenario {
        "export-symlink" | "export-fifo" | "export-device" | "export-socket"
        | "export-traversal" => true,
        "export-concurrent-writer" => false,
        _ => return Err("unknown required export outcome scenario".into()),
    };
    let expected_status = if refused { 125 } else { 0 };
    let expected_delivery = if refused {
        OutputDeliveryStateV3::Incomplete
    } else {
        OutputDeliveryStateV3::Complete
    };
    let target_zero = matches!(
        outcome.native_termination,
        Some(ChildTermination::ExitCode { code: 0 })
    );
    let failure_present = diagnostics
        .iter()
        .any(|value| value.as_str() == "output delivery is incomplete");
    if outcome.kind != OutcomeKindV1::Completed
        || !target_zero
        || outcome.wrapper_status != expected_status
        || captured_status != Some(expected_status)
        || delivery != Some(expected_delivery)
        || refused && !failure_present
    {
        return Err(format!(
            "export outcome differs; scenario={scenario}; completed={}; target-exit-zero={target_zero}; wrapper-status={}; captured-status={captured_status:?}; delivery={delivery:?}; incomplete-delivery-diagnostic={failure_present}",
            outcome.kind == OutcomeKindV1::Completed,
            outcome.wrapper_status
        ));
    }
    Ok(())
}
