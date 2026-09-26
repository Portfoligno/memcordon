use std::num::NonZeroU64;

use memcordon_core::workload_contract::{
    AuthorizationRef, ContractVersionTwo, ExecutionIdentityRequestV2, LogicalId, Nonce128,
    PolicyEpoch, WorkloadContractV2,
};
use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
use memcordon_core::workload_plan_v2::{
    PrivateDoctorReportV7, PrivatePlanAvailabilityV2, PrivatePlanPreconditionV1,
    PrivatePlanReceiptV2, PrivatePlanReportV10,
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
        schema_version: 3,
        contract_digest: memcordon_core::workload_codec::contract_digest_v2(&request).unwrap(),
        registry_digest: DiagnosticSha256::from_bytes([4; 32]),
        installed_qualification_sha256: DiagnosticSha256::from_bytes([5; 32]),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([6; 32]),
        generation_digest: DiagnosticSha256::from_bytes([8; 32]),
        caller_uid: 1000,
        policy_epoch: request.expected_epoch.clone(),
        source_commit: "a".into(),
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
    };
    let bytes = serde_json::to_vec(&receipt).unwrap();
    assert_eq!(
        PrivatePlanReceiptV2::parse_for_contract(&bytes, &request).unwrap(),
        receipt
    );
    receipt.validate_for_caller(1000).unwrap();
    assert!(receipt.validate_for_caller(1001).is_err());

    let mut swapped = request.clone();
    swapped.expected_epoch.service_instance = Nonce128([9; 16]);
    assert!(PrivatePlanReceiptV2::parse_for_contract(&bytes, &swapped).is_err());
    let mut wrong_epoch = receipt.clone();
    wrong_epoch.policy_epoch.service_instance = Nonce128([9; 16]);
    assert!(wrong_epoch.validate_for_contract(&request).is_err());

    let mut changed = serde_json::to_value(&receipt).unwrap();
    changed["schema_version"] = serde_json::json!(2);
    assert!(
        PrivatePlanReceiptV2::parse_for_contract(&serde_json::to_vec(&changed).unwrap(), &request)
            .is_err()
    );

    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"schema_version\":3",
        "\"schema_version\":3,\"schema_version\":3",
        1,
    );
    assert!(PrivatePlanReceiptV2::parse_for_contract(duplicate.as_bytes(), &request).is_err());
}

#[test]
fn expected_private_plan_distinguishes_contract_tamper_from_installation_change() {
    let request = contract();
    let generation = DiagnosticSha256::from_bytes([8; 32]);
    let receipt = PrivatePlanReceiptV2 {
        schema_version: 3,
        contract_digest: memcordon_core::workload_codec::contract_digest_v2(&request).unwrap(),
        registry_digest: DiagnosticSha256::from_bytes([4; 32]),
        installed_qualification_sha256: DiagnosticSha256::from_bytes([5; 32]),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([6; 32]),
        generation_digest: generation.clone(),
        caller_uid: 1000,
        policy_epoch: request.expected_epoch.clone(),
        source_commit: "a".into(),
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
    };
    let expected = PrivatePlanPreconditionV1::from_receipt(&receipt).unwrap();
    assert_eq!(expected.verify_current(&request, &generation), Ok(()));
    let mut changed = request.clone();
    changed.expected_epoch.service_instance = Nonce128([9; 16]);
    assert_eq!(
        expected.verify_current(&changed, &generation),
        Err("ContractBindingMismatch")
    );
    assert_eq!(
        expected.verify_current(&request, &DiagnosticSha256::from_bytes([9; 32])),
        Err("InstallationGenerationStale")
    );
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
