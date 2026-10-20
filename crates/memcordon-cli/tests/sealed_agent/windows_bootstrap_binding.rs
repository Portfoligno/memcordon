use super::*;
use sha2::{Digest, Sha256};

/// Actual current-process snapshots exercise the full binding codec; this does
/// not assert that this process is an admitted SYSTEM desktop Holder.
fn binding_fixture() -> TargetDesktopBootstrapBindingV3 {
    let token = crate::windows::token::current_process_token_for_attestation().unwrap();
    let snapshot = crate::windows::token::token_attestation_snapshot(token.raw()).unwrap();
    let query = snapshot.query_evidence();
    let assignment = crate::windows::token::require_assigned_process_authority(
        "binding-codec-fixture",
        &snapshot,
        &query,
    )
    .unwrap();
    let identity = process_identity(unsafe { GetCurrentProcess() }).unwrap();
    TargetDesktopBootstrapBindingV3 {
        schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
        role: TargetDesktopBootstrapRoleV1::Holder,
        probe_creation_policy: None,
        target_user_object_policy_role:
            crate::windows::security::TargetUserObjectPolicyRoleV1::DirectTarget,
        nonce: "11".repeat(32),
        binding_sha256: String::new(),
        bootstrap_image_sha256: "22".repeat(32),
        launcher_identity: identity.clone(),
        launcher_session_id: snapshot.lineage.session_id,
        launcher_envelope: snapshot.behavior.envelope.clone(),
        launcher_process_snapshot: snapshot.clone(),
        broker_source_snapshot: snapshot.clone(),
        holder_launch_snapshot: snapshot.clone(),
        holder_assignment: assignment.clone(),
        bootstrap_identity: identity,
        bootstrap_envelope: snapshot.behavior.envelope.clone(),
        bootstrap_process_snapshot: query.clone(),
        bootstrap_assignment: assignment,
        holder_process_snapshot: query,
        target_envelope: snapshot.behavior.envelope.clone(),
        target_request_snapshot: snapshot,
    }
}

#[test]
fn holder_full_binding_preserves_historical_schema19_claims_and_v8_digest() {
    let binding = binding_fixture();
    assert_eq!(binding.schema_version, 19);
    assert_eq!(
        memcordon_windows_launch_core::PRODUCTION_LOADER_READY_SCHEMA_VERSION,
        19
    );
    // Exact pre-policy-field representation, independently listed rather than
    // serializing the current type and deleting the new field after the fact.
    let legacy_claims = serde_json::json!({
        "schema_version":19,"role":"holder",
        "target_user_object_policy_role":binding.target_user_object_policy_role,
        "nonce":binding.nonce,"bootstrap_image_sha256":binding.bootstrap_image_sha256,
        "launcher_identity":binding.launcher_identity,"launcher_session_id":binding.launcher_session_id,
        "launcher_envelope":binding.launcher_envelope,"launcher_process_snapshot":binding.launcher_process_snapshot,
        "broker_source_snapshot":binding.broker_source_snapshot,"holder_launch_snapshot":binding.holder_launch_snapshot,
        "holder_assignment":binding.holder_assignment,"bootstrap_identity":binding.bootstrap_identity,
        "bootstrap_envelope":binding.bootstrap_envelope,"bootstrap_process_snapshot":binding.bootstrap_process_snapshot,
        "bootstrap_assignment":binding.bootstrap_assignment,"holder_process_snapshot":binding.holder_process_snapshot,
        "target_envelope":binding.target_envelope,"target_request_snapshot":binding.target_request_snapshot
    });
    let legacy_bytes = serde_json::to_vec(&legacy_claims).unwrap();
    let mut canonical = b"memcordon-target-desktop-binding-v8\0".to_vec();
    canonical.extend(&legacy_bytes);
    let expected: String = Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let sealed = binding.seal().unwrap();
    assert_eq!(sealed.binding_sha256, expected);
    let wire = serde_json::to_value(&sealed).unwrap();
    assert!(
        !wire
            .as_object()
            .unwrap()
            .contains_key("probe_creation_policy")
    );
    let mut current_claims = wire.clone();
    current_claims
        .as_object_mut()
        .unwrap()
        .remove("binding_sha256");
    assert_eq!(serde_json::to_vec(&current_claims).unwrap(), legacy_bytes);
    let parsed: TargetDesktopBootstrapBindingV3 = serde_json::from_value(wire).unwrap();
    assert_eq!(parsed, sealed);
    parsed.verify_digest().unwrap();
}

#[test]
fn full_binding_rejects_cross_role_schema_and_policy_mixtures() {
    let holder = binding_fixture();
    for mutation in 0..6 {
        let mut altered = holder.clone();
        match mutation {
            0 => altered.schema_version = 3,
            1 => altered.schema_version = 4,
            2 => {
                altered.probe_creation_policy =
                    Some(bootstrap_probe_policy::ConsolelessProbePolicyV1::new())
            }
            3 => altered.role = TargetDesktopBootstrapRoleV1::Probe,
            4 => altered.schema_version = 20,
            5 => {
                altered.role = TargetDesktopBootstrapRoleV1::Probe;
                altered.schema_version = 4;
            }
            _ => unreachable!(),
        }
        assert!(altered.seal().is_err(), "mutation {mutation}");
    }
    let mut probe = holder;
    probe.role = TargetDesktopBootstrapRoleV1::Probe;
    probe.schema_version = 4;
    probe.probe_creation_policy = Some(bootstrap_probe_policy::ConsolelessProbePolicyV1::new());
    let probe = probe.seal().unwrap();
    let mut claims = serde_json::to_value(&probe).unwrap();
    claims.as_object_mut().unwrap().remove("binding_sha256");
    let mut canonical = b"memcordon-target-desktop-binding-v9\0".to_vec();
    canonical.extend(serde_json::to_vec(&claims).unwrap());
    let expected: String = Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(probe.binding_sha256, expected);
    let mut wire = serde_json::to_value(&probe).unwrap();
    wire["probe_creation_policy"]["creation_flags"] = serde_json::json!(0x80404);
    assert!(serde_json::from_value::<TargetDesktopBootstrapBindingV3>(wire).is_err());
    let mut changed = probe.clone();
    changed.nonce = "33".repeat(32);
    assert!(changed.verify_digest().is_err());
    let parsed: TargetDesktopBootstrapBindingV3 =
        serde_json::from_slice(&serde_json::to_vec(&probe).unwrap()).unwrap();
    parsed.verify_digest().unwrap();
}
