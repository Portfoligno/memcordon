use super::super::{
    report::classify_report,
    scenario::{ObservedLifecycle, SCENARIOS},
};
use serde_json::{Value, json};

fn report(authorized: bool) -> Value {
    json!({"schema_version":10,"invocation":{"deadline_token":"+250ms"},"policy":{"effective":{"deadline":{"duration_ms":250,"scope":"attempt","origin":"before-helper-setup"}}},"supervision":{"phase":"completed","wrapper_exit_code":123,"targets_authorized":u64::from(authorized),"attempt_records_created":1},"error":null,"attempts":[{
        "phase":"completed","target_pid":if authorized {Some(42)} else {None},"authorized_offset_ms":if authorized {Some(10)} else {None},"error":null,
        "runtime":{"schema_version":1,"release":if authorized {json!({"state":"issued","at":100,"exec_confirmed":true})} else {json!({"state":"not-issued"})},"target_pid":if authorized {Some(42)} else {None},"retirement":{"state":"complete","at":200,"target_reaped_or_absent":true,"group_reconciled":true,"detached_identities_discharged":true,"native_obligations_settled":true,"policy_retired":true}},
        "outcome":{"outcome":"deadline-exceeded","deadline":{"duration_ms":250,"origin":"pre-spawn","scope":"attempt","expires_offset_ms":250,"observed_offset_ms":251,"overshoot_ms":1},"cleanup":{"errors":[],"direct_child_reaped":true,"workload_empty":true}},
        "launch":{"target_released":authorized,"guardian_started_before_authorization":authorized,"target_spawn_error_reported":false},"restart_safety":{"errors":[],"direct_child_reaped":true,"helpers_reaped":true,"workload_empty":true}
    }]})
}
#[test]
fn coherent_deadline_paths_classify() {
    for (authorized, expected) in [
        (false, ObservedLifecycle::PreAuthorizationExpired),
        (true, ObservedLifecycle::AuthorizedExpired),
    ] {
        let proof = classify_report(
            &serde_json::to_vec(&report(authorized)).unwrap(),
            SCENARIOS[0],
        )
        .unwrap();
        assert_eq!(proof.lifecycle, expected);
        assert_eq!(proof.target_pid, authorized.then_some(42));
    }
}
#[test]
fn not_issued_release_rejects_issued_only_fields() {
    for (field, supplied) in [("at", json!(100)), ("exec_confirmed", json!(true))] {
        let mut value = report(false);
        value["attempts"][0]["runtime"]["release"]
            .as_object_mut()
            .unwrap()
            .insert(field.into(), supplied);
        assert!(classify_report(&serde_json::to_vec(&value).unwrap(), SCENARIOS[0]).is_err());
    }
}
#[test]
fn blocked_stderr_preserves_deadline_supervision_before_delivery_failure() {
    let mut value = report(true);
    value["invocation"]["deadline_token"] = json!("+3s");
    value["policy"]["effective"]["deadline"]["duration_ms"] = json!(3000);
    value["attempts"][0]["outcome"]["deadline"]["duration_ms"] = json!(3000);
    value["attempts"][0]["outcome"]["deadline"]["expires_offset_ms"] = json!(3000);
    value["attempts"][0]["outcome"]["deadline"]["observed_offset_ms"] = json!(3001);
    assert_eq!(
        SCENARIOS[5].expected_exit,
        super::super::scenario::ExpectedExit::Code(125)
    );
    classify_report(&serde_json::to_vec(&value).unwrap(), SCENARIOS[5]).unwrap();
    for wrong_code in [0, 125] {
        value["supervision"]["wrapper_exit_code"] = json!(wrong_code);
        assert!(classify_report(&serde_json::to_vec(&value).unwrap(), SCENARIOS[5]).is_err());
    }
}
#[test]
fn contradictory_report_mutations_fail_closed() {
    let mutations = [
        (false, "/attempts/0/target_pid", json!(42)),
        (
            true,
            "/attempts/0/runtime/release/exec_confirmed",
            json!(false),
        ),
        (false, "/attempts/0/launch/target_released", json!(true)),
        (true, "/attempts/0/authorized_offset_ms", Value::Null),
        (true, "/attempts/0/runtime/target_pid", json!(43)),
        (true, "/supervision/wrapper_exit_code", json!(0)),
        (true, "/attempts/0/outcome/outcome", json!("exited")),
        (
            true,
            "/attempts/0/outcome/cleanup/errors",
            json!([{"error":"failure"}]),
        ),
        (
            true,
            "/attempts/0/runtime/retirement/state",
            json!("pending"),
        ),
        (
            true,
            "/attempts/0/runtime/retirement/policy_retired",
            json!(false),
        ),
        (true, "/error", json!({"error":"failure"})),
        (true, "/attempts/0/error", json!({"error":"failure"})),
        (true, "/schema_version", json!(11)),
        (true, "/attempts", json!([])),
        (
            true,
            "/attempts/0/outcome/deadline/overshoot_ms",
            json!(999),
        ),
        (
            true,
            "/attempts/0/outcome/deadline/origin",
            json!("post-spawn"),
        ),
        (
            true,
            "/attempts/0/outcome/deadline/scope",
            json!("supervision"),
        ),
        (
            true,
            "/policy/effective/deadline/origin",
            json!("after-helper-setup"),
        ),
        (true, "/attempts/0/authorized_offset_ms", json!(999)),
        (
            true,
            "/attempts/0/restart_safety/workload_empty",
            Value::Null,
        ),
        (true, "/attempts/0/runtime/schema_version", json!(2)),
        (true, "/supervision/phase", json!("cleanup")),
        (true, "/supervision/attempt_records_created", json!(2)),
        (true, "/supervision/targets_authorized", json!(0)),
        (false, "/attempts/0/runtime/target_pid", json!(42)),
        (
            true,
            "/attempts/0/launch/guardian_started_before_authorization",
            json!(false),
        ),
        (
            false,
            "/attempts/0/launch/guardian_started_before_authorization",
            json!(true),
        ),
        (
            true,
            "/attempts/0/launch/target_spawn_error_reported",
            json!(true),
        ),
        (
            true,
            "/attempts/0/outcome/cleanup/direct_child_reaped",
            json!(false),
        ),
        (
            true,
            "/attempts/0/restart_safety/direct_child_reaped",
            json!(false),
        ),
        (
            true,
            "/attempts/0/restart_safety/helpers_reaped",
            json!(false),
        ),
        (
            true,
            "/attempts/0/runtime/retirement/target_reaped_or_absent",
            json!(false),
        ),
        (
            true,
            "/attempts/0/runtime/retirement/group_reconciled",
            json!(false),
        ),
        (
            true,
            "/attempts/0/runtime/retirement/detached_identities_discharged",
            json!(false),
        ),
        (
            true,
            "/attempts/0/runtime/retirement/native_obligations_settled",
            json!(false),
        ),
        (true, "/attempts/0/runtime/release/at", json!(999)),
        (true, "/attempts/0/outcome/deadline/duration_ms", json!(999)),
        (true, "/invocation/deadline_token", json!("+3s")),
    ];
    for (authorized, path, value) in mutations {
        let mut mutated = report(authorized);
        *mutated.pointer_mut(path).unwrap() = value;
        assert!(
            classify_report(&serde_json::to_vec(&mutated).unwrap(), SCENARIOS[0]).is_err(),
            "accepted mutation {path}"
        );
    }
    let mut multiple = report(true);
    let attempt = multiple["attempts"][0].clone();
    multiple["attempts"].as_array_mut().unwrap().push(attempt);
    assert!(classify_report(&serde_json::to_vec(&multiple).unwrap(), SCENARIOS[0]).is_err());
}
#[test]
fn supervision_setup_offset_does_not_change_work_budget() {
    let mut value = report(true);
    value["attempts"][0]["outcome"]["deadline"]["expires_offset_ms"] = json!(260);
    value["attempts"][0]["outcome"]["deadline"]["observed_offset_ms"] = json!(261);
    classify_report(&serde_json::to_vec(&value).unwrap(), SCENARIOS[0]).unwrap();
}
#[test]
fn required_lifecycle_matrix_rejects_unexercised_paths() {
    use super::super::scenario::RequiredLifecycle::*;
    for (required, pre, authorized) in [
        (PreAuthorization, true, false),
        (Authorized, false, true),
        (EitherDeadlinePath, true, true),
    ] {
        assert_eq!(
            required.accepts(ObservedLifecycle::PreAuthorizationExpired),
            pre
        );
        assert_eq!(
            required.accepts(ObservedLifecycle::AuthorizedExpired),
            authorized
        );
    }
}
