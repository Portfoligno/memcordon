#![cfg(windows)]
#[path = "../src/bin/consumer_readiness_windows/controller_gate_diagnostic.rs"]
mod controller_gate_diagnostic;
#[path = "../src/bin/consumer_readiness_windows/controller_gate_access_input.rs"]
pub mod gate_access;
mod descriptor {
    pub use super::gate_access;
}
#[path = "../src/bin/consumer_readiness_windows/controller_gate_access.rs"]
mod controller_gate_access;
#[path = "../src/bin/consumer_readiness_windows/controller_gate_control_publication.rs"]
mod controller_gate_control_publication;
#[path = "../src/bin/consumer_readiness_windows/controller_gate_thread_control.rs"]
mod controller_gate_thread_control;
#[path = "../src/bin/consumer_readiness_windows/controller_gate_token.rs"]
mod controller_gate_token;

#[test]
fn actual_current_effective_token_is_bounded_and_primary_level_is_not_queried() {
    let captured = controller_gate_token::capture(None);
    assert_eq!(captured["observed"], true, "{captured}");
    assert_eq!(captured["query_complete"], true, "{captured}");
    assert_eq!(captured["process"]["pid"], std::process::id());
    assert!(
        captured["process"]["birth"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    assert!(
        captured["groups"]["value"].as_array().unwrap().len()
            <= controller_gate_diagnostic::GROUP_BOUND
    );
    if captured["token_type"]["value"] == 1 {
        assert_eq!(captured["impersonation_level"]["applicable"], false);
        assert!(captured["impersonation_level"].get("value").is_none());
    }
    assert!(
        controller_gate_diagnostic::encode(&captured).unwrap().len()
            < controller_gate_diagnostic::RECORD_BOUND
    );
}
