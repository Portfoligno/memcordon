#[path = "../../../crates/memcordon-core/tests/support/windows_current_frontend_guardian.rs"]
mod support;
use memcordon_readiness_verifier::windows_guardian_cause::frontend_path;
use serde_json::{Value, json};

#[test]
fn independently_checks_native_cause_and_binary_diagnostic_integrity() {
    let (rejection, live, action, exit) = support::fixture();
    let terminal = serde_json::to_value(rejection.terminal_receipt().unwrap()).unwrap();
    let rejection = serde_json::to_value(rejection).unwrap();
    let observation = json!({"frontend_action":action,"launch":{"expected_provider_binding":live.association.provider}});
    let held = serde_json::to_value(live).unwrap();
    let accepts = |value: &Value| {
        frontend_path(value, &terminal, &observation, &held, &exit).unwrap_or(false)
    };
    assert!(accepts(&rejection));
    for (pointer, replacement) in [
        (
            "/provider_failure/projection_sha256",
            json!("99".repeat(32)),
        ),
        ("/provider_failure/secondary/0/sequence", json!(3)),
        (
            "/provider_failure/secondary/0/observed_phase",
            json!("monitoring"),
        ),
        ("/provider_failure/secondary/0/native_code/win32", json!(5)),
        (
            "/provider_failure/secondary/0/detail_truncated",
            json!(true),
        ),
        (
            "/provider_failure/secondary/0/safe_detail",
            json!("no-additional-detail"),
        ),
        ("/provider_failure/durable_through_sequence", json!(3)),
        ("/provider_failure/loss/writer_unavailable", json!(true)),
        ("/guardian_causal_receipt/nonce", json!("")),
        ("/guardian_causal_receipt/provider_generation", json!("")),
        ("/guardian_causal_receipt/launch_incarnation", json!("")),
        ("/guardian_causal_receipt/original_boot_id", json!("")),
        ("/guardian_causal_receipt", Value::Null),
    ] {
        let mut changed = rejection.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert_ne!(changed, rejection);
        assert!(!accepts(&changed), "accepted {pointer}");
    }
    let mut duplicate = rejection.clone();
    let event = duplicate["provider_failure"]["secondary"][0].clone();
    duplicate["provider_failure"]["secondary"]
        .as_array_mut()
        .unwrap()
        .push(event);
    assert!(!accepts(&duplicate));
    for (pointer, replacement) in [
        (
            "/cleanup_trigger/frontend/creation_time_100ns",
            json!(134364958296860015_u64),
        ),
        (
            "/guardian_identity/creation_time_100ns",
            json!(134364958304946299_u64),
        ),
        ("/worker_identity/process_id", json!(8)),
        ("/cleanup_trigger/native_exit_status", json!(1)),
        ("/cleanup_trigger", Value::Null),
        ("/cleanup_trigger", json!({"trigger":"worker-lost"})),
    ] {
        let mut changed = rejection.clone();
        let cause = &mut changed["guardian_causal_receipt"];
        *cause.pointer_mut(pointer).unwrap() = replacement;
        let mut typed: memcordon_core::WindowsGuardianReceiptV2 =
            serde_json::from_value(cause.clone()).unwrap();
        typed.integrity_sha256 = typed.canonical_sha256().unwrap();
        *cause = serde_json::to_value(typed).unwrap();
        assert!(!accepts(&changed), "accepted resealed {pointer}");
    }
    for (pointer, replacement) in [
        ("/frontend_action/process/creation_time_100ns", json!(1)),
        ("/frontend_action/requested_exit_status", json!(1)),
        ("/frontend_action/controller_release_observed", json!(false)),
    ] {
        let mut changed = observation.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(!frontend_path(&rejection, &terminal, &changed, &held, &exit).unwrap_or(false));
    }
    for (pointer, replacement) in [
        ("/creation_time_100ns", json!(1)),
        ("/native_status", json!(1)),
        ("/held_before_fault", json!(false)),
        ("/retirement_observed", json!(false)),
    ] {
        let mut changed = exit.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            !frontend_path(&rejection, &terminal, &observation, &held, &changed).unwrap_or(false)
        );
    }
    let mut incomplete = terminal.clone();
    incomplete["retirement_proof"]["owner_capabilities_closed"] = json!(false);
    assert!(frontend_path(&rejection, &incomplete, &observation, &held, &exit).is_err());
}
