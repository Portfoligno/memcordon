#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process_impl/bootstrap_probe_policy.rs"]
mod probe_policy;

use probe_policy::{
    ConsolelessProbePolicyV1, binding_domain, validate_admission_capability,
    validate_image_capability,
};

#[test]
fn probe_policy_round_trips_only_the_fixed_creation_contract() {
    let policy = ConsolelessProbePolicyV1::new();
    let json = serde_json::to_value(&policy).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "schema_version":1,"role":"probe","creation_flags":525324,
            "job_at_creation":true,"inherited_handle_count":0,
        })
    );
    assert_eq!(
        serde_json::from_value::<ConsolelessProbePolicyV1>(json).unwrap(),
        policy
    );
    assert_eq!(policy.creation_flags(), 0x8040c);
}

#[test]
fn probe_policy_rejects_foreign_missing_and_unknown_claims() {
    let original = serde_json::to_value(ConsolelessProbePolicyV1::new()).unwrap();
    for (field, value) in [
        ("schema_version", serde_json::json!(2)),
        ("role", serde_json::json!("holder")),
        ("creation_flags", serde_json::json!(0x80404)),
        ("job_at_creation", serde_json::json!(false)),
        ("inherited_handle_count", serde_json::json!(1)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            serde_json::from_value::<ConsolelessProbePolicyV1>(changed).is_err(),
            "{field}"
        );
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<ConsolelessProbePolicyV1>(missing).is_err(),
            "missing {field}"
        );
    }
    let mut unknown = original;
    unknown["allow_fallback"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ConsolelessProbePolicyV1>(unknown).is_err());
}

#[test]
fn binding_versions_join_exact_role_and_policy_without_changing_legacy_domain() {
    let policy = ConsolelessProbePolicyV1::new();
    let current = binding_domain(
        ConsolelessProbePolicyV1::BINDING_SCHEMA_VERSION,
        "probe",
        Some(&policy),
    )
    .unwrap();
    assert_eq!(current, b"memcordon-target-desktop-binding-v11\0");
    for role in ["holder", "loader-control"] {
        assert_eq!(
            binding_domain(19, role, None).unwrap(),
            b"memcordon-target-desktop-binding-v8\0"
        );
        assert!(binding_domain(19, role, Some(&policy)).is_err());
        assert!(binding_domain(3, role, None).is_err());
        assert!(binding_domain(4, role, Some(&policy)).is_err());
    }
    assert!(binding_domain(3, "probe", None).is_err());
    assert!(binding_domain(3, "probe", Some(&policy)).is_err());
    assert!(binding_domain(4, "probe", None).is_err());
    assert!(binding_domain(4, "probe", Some(&policy)).is_err());
    assert!(binding_domain(5, "probe", None).is_err());
    assert!(binding_domain(5, "probe", Some(&policy)).is_err());
    assert!(binding_domain(4, "target", Some(&policy)).is_err());
}

#[test]
fn admission_requires_explicit_capability_for_holder_and_probe_only() {
    let policy = ConsolelessProbePolicyV1::new();
    for (version, role, selected) in [(19, "holder", None), (6, "probe", Some(&policy))] {
        assert!(validate_admission_capability(version, role, selected, true).is_ok());
        assert!(validate_admission_capability(version, role, selected, false).is_err());
    }
    for role in ["loader-control", "target", "", "Probe"] {
        for present in [true, false] {
            assert!(validate_admission_capability(19, role, None, present).is_err());
            assert!(validate_admission_capability(6, role, Some(&policy), present).is_err());
        }
    }
    for (version, role, selected) in [
        (4, "probe", Some(&policy)),
        (19, "probe", None),
        (5, "holder", Some(&policy)),
        (5, "probe", None),
        (5, "probe", Some(&policy)),
        (19, "holder", Some(&policy)),
    ] {
        assert!(validate_admission_capability(version, role, selected, true).is_err());
    }
}

#[test]
fn image_identity_and_handle_are_required_together_for_probe_only() {
    for role in ["probe", "holder", "loader-control", "target", "", "Probe"] {
        for claim in [false, true] {
            for handle in [false, true] {
                let expected = match role {
                    "probe" => claim && handle,
                    "holder" | "loader-control" => !claim && !handle,
                    _ => false,
                };
                assert_eq!(
                    validate_image_capability(role, claim, handle).is_ok(),
                    expected,
                    "{role} claim={claim} handle={handle}",
                );
            }
        }
    }
}
