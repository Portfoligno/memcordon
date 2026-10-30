#[path = "private/fixture_namespace_debug_context.rs"]
mod context;
use context::*;

fn call(purpose: Purpose, stage: Stage, success: bool) -> Call {
    Call {
        purpose,
        stage,
        flags: 0x100010,
        size: 1232,
        alignment: 16,
        address_mod_16: 0,
        success,
        raw_error: (!success).then_some(998),
    }
}

#[test]
fn failures_retain_exact_stage_and_buffer_facts() {
    for purpose in [Purpose::PreCallArm, Purpose::PostCallCoverage] {
        let mut trace = Trace::default();
        trace.record(call(purpose, Stage::GetContext, false));
        assert_eq!(trace.calls.len(), 1);
        assert_eq!(trace.write_attempted, 0);
    }
    for stage in [Stage::GetContext, Stage::SetRegisters, Stage::GetReadback] {
        let mut trace = Trace::default();
        trace.record(call(Purpose::PreCallArm, stage, false));
        let value = serde_json::to_value(&trace).unwrap();
        assert_eq!(value["first_failure"]["raw_error"], 998);
        assert_eq!(value["first_failure"]["flags"], 0x100010);
        assert_eq!(value["first_failure"]["size"], 1232);
        assert_eq!(value["first_failure"]["alignment"], 16);
        assert_eq!(value["first_failure"]["address_mod_16"], 0);
        assert_eq!(value["first_failure"]["stage"], value["calls"][0]["stage"]);
        assert_eq!(trace.verified, 0);
        assert_eq!(trace.set_succeeded, 0);
    }
}

#[test]
fn successful_mutation_with_failed_readback_is_not_verified() {
    let mut trace = Trace::default();
    trace.record(call(Purpose::Hit, Stage::GetContext, true));
    trace.record(call(Purpose::Hit, Stage::SetRegisters, true));
    trace.record(call(Purpose::Hit, Stage::GetReadback, false));
    assert_eq!(trace.write_attempted, 1);
    assert_eq!(trace.set_succeeded, 1);
    assert_eq!(trace.verified, 0);
    trace.record(call(Purpose::Restore, Stage::SetRegisters, false));
    assert_eq!(trace.write_attempted, 2);
    assert_eq!(trace.set_succeeded, 1);
    assert_eq!(trace.verified, 0);
    trace.record(call(Purpose::Restore, Stage::SetRegisters, true));
    trace.record(call(Purpose::Restore, Stage::GetReadback, true));
    assert_eq!(trace.verified, 0);
    trace.verified();
    assert_eq!(trace.verified, 1);
}

#[test]
fn full_log_still_retains_first_failure_and_mutation_counts() {
    let mut trace = Trace::default();
    for _ in 0..CALL_LIMIT {
        trace.record(call(Purpose::PreCallArm, Stage::GetContext, true));
    }
    trace.record(call(Purpose::Hit, Stage::SetRegisters, true));
    trace.record(call(Purpose::Hit, Stage::GetReadback, false));
    let mut later = call(Purpose::Restore, Stage::SetRegisters, false);
    later.raw_error = Some(5);
    trace.record(later);
    assert_eq!(trace.calls.len(), CALL_LIMIT);
    assert_eq!(trace.omitted, 3);
    assert_eq!(trace.first_failure.unwrap().raw_error, Some(998));
    assert_eq!(trace.write_attempted, 2);
    assert_eq!(trace.set_succeeded, 1);
    assert_eq!(trace.verified, 0);
}
