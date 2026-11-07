#[path = "../src/bin/consumer_readiness_windows/provider_loader_policy.rs"]
mod policy;
use policy::{Observation, Policy, bind, diagnostic};

#[test]
fn successful_zero_flags_differ_from_unavailable_and_preserve_unknown_bits() {
    let mut observed = Observation {
        attempted: true,
        started_qpc: Some(1),
        finished_qpc: Some(2),
        success: Some(true),
        flags: Some(0),
        ..Observation::default()
    };
    assert_eq!(diagnostic(Policy::ImageLoad, &observed)["raw_flags"], 0);
    assert_eq!(
        diagnostic(Policy::ImageLoad, &observed)["available_before_original_cutoff"],
        true
    );
    observed.success = Some(false);
    observed.flags = None;
    observed.native_error = Some(5);
    let unavailable = diagnostic(Policy::Signature, &observed);
    assert!(unavailable["raw_flags"].is_null());
    assert!(unavailable["decoded"]["microsoft_signed_only"].is_null());
    assert_eq!(unavailable["native_error"], 5);
    assert_eq!(unavailable["available_before_original_cutoff"], false);
    observed.success = Some(true);
    observed.flags = Some(0x8000001f);
    observed.native_error = None;
    for policy in [Policy::ImageLoad, Policy::Signature] {
        let value = diagnostic(policy, &observed);
        assert_eq!(value["unknown_flag_bits"], 0x80000000u32);
        assert!(
            value["decoded"]
                .as_object()
                .unwrap()
                .values()
                .all(|value| value == true)
        );
        assert_eq!(value["loader_policy_precedence_or_cause_proved"], false);
    }
}

#[test]
fn cutoff_clock_failure_and_reversed_intervals_do_not_become_available() {
    for state in 0..4 {
        let mut observation = Observation {
            attempted: true,
            started_qpc: Some(10),
            finished_qpc: Some(11),
            success: Some(true),
            flags: Some(4),
            ..Observation::default()
        };
        match state {
            0 => observation.cutoff_reached = true,
            1 => observation.clock_error = Some(5),
            2 => observation.finished_qpc = Some(9),
            _ => observation.attempted = false,
        };
        let value = diagnostic(Policy::ImageLoad, &observation);
        assert_eq!(value["available_before_original_cutoff"], false);
        assert_eq!(value["acceptance_authority"], false);
        assert!(serde_json::to_vec(&value).unwrap().len() < 2048);
    }
    let snapshot = serde_json::json!({"actual_self":{"pid":4,"creation_time_100ns":7,"available_before_original_cutoff":true}});
    assert_eq!(
        bind(snapshot.clone(), 4, 7)["matches_authenticated_original_identity"],
        true
    );
    assert_eq!(
        bind(snapshot.clone(), 5, 7)["matches_authenticated_original_identity"],
        false
    );
    assert_eq!(
        bind(snapshot, 4, 8)["matches_authenticated_original_identity"],
        false
    );
}
