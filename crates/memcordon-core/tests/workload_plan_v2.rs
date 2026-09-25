use std::num::NonZeroU64;

use memcordon_core::workload_contract::{
    AuthorizationRef, ContractVersionTwo, ExecutionIdentityRequestV2, LogicalId, Nonce128,
    PolicyEpoch, WorkloadContractV2,
};
use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
use memcordon_core::workload_plan_v2::{
    PrivateDoctorReportV7, PrivatePlanAvailabilityV2, PrivatePlanReceiptV2, PrivatePlanReportV10,
};
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedVec, DiagnosticSha256};

fn contract() -> WorkloadContractV2 {
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    WorkloadContractV2 {
        schema_version: ContractVersionTwo::default(),
        workload_plan_digest: digest.clone(),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: LogicalId::new("private-grant".into()).unwrap(),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest,
        },
        ceiling: profile.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
        execution_identity: ExecutionIdentityRequestV2::PreserveCaller,
    }
}

#[test]
fn private_plan_receipt_binds_exact_v2_contract_and_rejects_swaps() {
    let request = contract();
    let receipt = PrivatePlanReceiptV2 {
        schema_version: 2,
        contract_digest: memcordon_core::workload_codec::contract_digest_v2(&request).unwrap(),
        registry_digest: DiagnosticSha256::from_bytes([4; 32]),
        installed_qualification_sha256: DiagnosticSha256::from_bytes([5; 32]),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([6; 32]),
        generation_digest: DiagnosticSha256::from_bytes([8; 32]),
        source_commit: "a".into(),
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
    };
    let bytes = serde_json::to_vec(&receipt).unwrap();
    assert_eq!(
        PrivatePlanReceiptV2::parse_for_contract(&bytes, &request).unwrap(),
        receipt
    );

    let mut swapped = request.clone();
    swapped.expected_epoch.service_instance = Nonce128([9; 16]);
    assert!(PrivatePlanReceiptV2::parse_for_contract(&bytes, &swapped).is_err());

    let mut changed = serde_json::to_value(&receipt).unwrap();
    changed["schema_version"] = serde_json::json!(3);
    assert!(
        PrivatePlanReceiptV2::parse_for_contract(&serde_json::to_vec(&changed).unwrap(), &request)
            .is_err()
    );

    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"schema_version\":2",
        "\"schema_version\":2,\"schema_version\":2",
        1,
    );
    assert!(PrivatePlanReceiptV2::parse_for_contract(duplicate.as_bytes(), &request).is_err());
}

#[test]
fn private_plan_and_doctor_schemas_cannot_claim_launch_or_probe_execution() {
    let request = contract();
    let digest = memcordon_core::workload_codec::contract_digest_v2(&request).unwrap();
    let availability = PrivatePlanAvailabilityV2::Unavailable {
        reason: "protected installed qualification unavailable".into(),
    };
    let mut plan = PrivatePlanReportV10 {
        schema_version: 10,
        contract_digest: digest.clone(),
        availability: availability.clone(),
        launch_proof: false,
    };
    plan.validate_for_contract(&request).unwrap();
    plan.launch_proof = true;
    assert!(plan.validate_for_contract(&request).is_err());

    let mut doctor = PrivateDoctorReportV7 {
        schema_version: 7,
        contract_digest: digest,
        host_os: "linux".into(),
        architecture: "x86_64".into(),
        availability,
        execution_probe_performed: false,
    };
    doctor.validate_for_contract(&request).unwrap();
    doctor.execution_probe_performed = true;
    assert!(doctor.validate_for_contract(&request).is_err());
}
