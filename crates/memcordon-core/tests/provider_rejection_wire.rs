use memcordon_core::provider_rejection_wire::RejectionWireV1;

fn raw_rejection(target_created: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "code": "MCSEALED-TEST-REJECTION",
        "phase": "request-validation",
        "detail": "refused",
        "os_code": null,
        "target_created": target_created,
        "target_released": false,
        "cleanup": {
            "attempted": false,
            "direct_child_reaped": false,
            "workload_empty": null,
            "helpers_reaped": false,
            "containment_removed": false,
            "sealed_boundary_retired": false,
            "errors": []
        }
    }))
    .unwrap()
}

#[test]
fn native_rejection_projects_actual_bounded_fields() {
    for target_created in [false, true] {
        let raw = raw_rejection(target_created);
        let evidence = RejectionWireV1::parse_evidence(&raw).unwrap();
        assert_eq!(evidence.target_created, target_created);
        assert!(!evidence.target_released);
        assert_eq!(evidence.detail, "refused");
        assert_eq!(
            evidence.phase,
            memcordon_core::BoundarySetupPhase::RequestValidation
        );
        assert!(evidence.is_consistent());
        let wire = RejectionWireV1::parse(&raw).unwrap();
        assert_eq!(
            RejectionWireV1::parse(&serde_json::to_vec(&wire).unwrap()).unwrap(),
            wire
        );
    }
}

#[test]
fn raw_rejection_rejects_ambiguous_and_extra_fields() {
    let raw = raw_rejection(false);
    let mut duplicate = String::from_utf8(raw.clone()).unwrap();
    duplicate = duplicate.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(RejectionWireV1::parse_evidence(duplicate.as_bytes()).is_err());

    let mut extra = serde_json::from_slice::<serde_json::Value>(&raw).unwrap();
    extra["provider_failure"] = serde_json::json!({});
    assert!(RejectionWireV1::parse_evidence(&serde_json::to_vec(&extra).unwrap()).is_err());
}
