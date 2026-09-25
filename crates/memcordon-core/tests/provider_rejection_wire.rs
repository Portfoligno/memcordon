use memcordon_core::provider_rejection_wire::RejectionWireV1;
use memcordon_core::report_v11::{
    PRIVATE_EXECUTION_REPORT_SCHEMA_V11, PrivatePublicOutcomeV11, PrivatePublicResultV11,
};

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
fn public_rejections_bind_exact_typed_raw_evidence() {
    for target_created in [false, true] {
        let raw = raw_rejection(target_created);
        let evidence = RejectionWireV1::parse_evidence(&raw).unwrap();
        let result = if target_created {
            PrivatePublicOutcomeV11::AllocatedUnverified {
                rejection: Box::new(evidence.clone()),
                raw_response: raw.clone(),
            }
        } else {
            PrivatePublicOutcomeV11::PreallocationRejected {
                rejection: Box::new(evidence.clone()),
                raw_response: raw.clone(),
            }
        };
        let mut public = PrivatePublicResultV11 {
            schema_version: PRIVATE_EXECUTION_REPORT_SCHEMA_V11,
            result,
        };
        public.validate_structure().unwrap();

        let mut other = serde_json::from_slice::<serde_json::Value>(&raw).unwrap();
        other["detail"] = serde_json::json!("different refusal");
        let mismatched = serde_json::to_vec(&other).unwrap();
        match &mut public.result {
            PrivatePublicOutcomeV11::PreallocationRejected { raw_response, .. }
            | PrivatePublicOutcomeV11::AllocatedUnverified { raw_response, .. } => {
                *raw_response = mismatched;
            }
            _ => unreachable!(),
        }
        assert!(public.validate_structure().is_err());
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
