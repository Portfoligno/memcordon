//! Test-support parity evidence for independently linked shipped helper binaries.
use sha2::{Digest, Sha256};

/// Reports versions, canonical encoder output, and the reviewed compilation context.
/// This fingerprint is evidence of contract agreement and grants no provider authority.
pub fn provider_contract_fingerprint() -> serde_json::Value {
    let frame = super::protocol::Frame {
        kind: super::protocol::MessageKind::Probe,
        nonce: [0; 16],
        attempt_id: [0; 16],
        payload: Vec::new(),
    };
    let mut bytes = Vec::new();
    super::protocol::write_frame(&mut bytes, &frame).expect("canonical probe frame is encodable");
    serde_json::json!({
        "schema_version": 1,
        "package_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": super::protocol::PROTOCOL_VERSION,
        "launch_request_version": super::request::LAUNCH_REQUEST_VERSION,
        "broker_request_version": super::request::LAUNCH_BROKER_REQUEST_VERSION,
        "inspection_schema_version": super::inspection::INSPECTION_SCHEMA_VERSION,
        "linux_qualification_schema_version": super::qualification::QUALIFICATION_SCHEMA_VERSION,
        "canonical_launch_request_sha256": digest(&canonical_launch_request()),
        "canonical_inspection_sha256": digest(&canonical_inspection()),
        "canonical_incomplete_qualification_sha256": digest(&canonical_incomplete_qualification()),
        "canonical_probe_frame_sha256": Sha256::digest(&bytes).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "compilation_context": {
            "target_os": std::env::consts::OS,
            "target_arch": std::env::consts::ARCH,
            "test_support": true,
            "contract_owner": "memcordon-core::sealed_provider"
        }
    })
}

fn canonical_launch_request() -> Vec<u8> {
    use super::request::*;
    encode_launch_request(&LaunchRequestV2 {
        restart_attempt: 0,
        workload_contract: None,
        program: b"/canonical/provider-probe".to_vec(),
        arguments: vec![b"--contract".to_vec()],
        environment: vec![(b"LANG".to_vec(), b"C".to_vec())],
        policy: LaunchPolicyV2 {
            memory_limit_bytes: Some(4096),
            swap_limit: SwapLimit::Host,
            absolute_deadline_millis: None,
            deadline_scope: DeadlineScope::Attempt,
            lifetime: Lifetime::Workload,
            poll_interval_millis: 10,
            signal_grace_millis: 20,
            command_exit_grace_millis: 30,
            limit_grace_millis: 40,
        },
        descriptors: vec![
            DescriptorPurpose::CurrentDirectory,
            DescriptorPurpose::Stdin,
            DescriptorPurpose::Stdout,
            DescriptorPurpose::Stderr,
            DescriptorPurpose::FrontendLiveness,
        ],
    })
    .expect("canonical request is encodable")
}

fn canonical_inspection() -> Vec<u8> {
    use super::inspection::*;
    let digest = "00".repeat(<Sha256 as sha2::digest::OutputSizeUser>::output_size());
    let inspection = AgentPackageInspectionV5 {
        schema_version: INSPECTION_SCHEMA_VERSION,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        source_commit: String::new(),
        executable_sha256: digest.clone(),
        provider_protocol: u32::from(super::protocol::PROTOCOL_VERSION),
        native_protocols: crate::runtime_manifest::NativeProviderProtocols::Linux {
            provider_contract: 3,
            launch_wire: u32::from(super::protocol::PROTOCOL_VERSION),
        },
        runtime_manifest_schema: 2,
        workload_contract_schema: 1,
        profile_catalog_sha256: crate::runtime_manifest::baseline_catalog_digest(false),
        mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        execution_report_schema: crate::EXECUTION_REPORT_SCHEMA_VERSION,
        plan_report_schema: crate::PLAN_REPORT_SCHEMA_VERSION,
        doctor_report_schema: crate::DOCTOR_REPORT_SCHEMA_VERSION,
        platform: ProviderPackageMetadataV4::LinuxSystemd {
            control_service_sha256: digest.clone(),
            control_socket_sha256: digest.clone(),
            launcher_service_sha256: digest.clone(),
            launcher_socket_sha256: digest.clone(),
            tmpfiles_sha256: digest,
        },
        compiled_metadata_valid: false,
    };
    serde_json::to_vec(&inspection).expect("canonical inspection is serializable")
}

fn canonical_incomplete_qualification() -> Vec<u8> {
    let receipt = super::qualification::QualificationReceipt {
        schema_version: super::qualification::QUALIFICATION_SCHEMA_VERSION,
        workload_profile: crate::workload_registry::BaselineProfile::LinuxUnixCreate.reference(),
        workload_profile_probe_verified: false,
        version: String::new(),
        mechanism: String::new(),
        provider_identity: String::new(),
        control_service_identity: String::new(),
        launcher_service_identity: String::new(),
        receipt_digest: String::new(),
        unified_cgroup_v2: false,
        private_cgroup_subtree: false,
        clone3: false,
        clone3_into_cgroup: false,
        pid_namespace: false,
        mount_namespace: false,
        cgroup_namespace: false,
        pidfd: false,
        close_range: false,
        guardian_outside_boundary: false,
        target_gated: false,
        assignment_verified: false,
        inherited_descriptors_verified: false,
        spawn_error_reporting_verified: false,
        frontend_loss_authority_verified: false,
        cgroup_kill: false,
        workload_empty: false,
        helpers_reaped: false,
        boundary_retired: false,
        recovery_complete: false,
        split_control_and_launcher_services: false,
        launcher_no_new_privs_disabled: false,
        caller_mount_namespace_reproduction_verified: false,
        caller_no_new_privs_reproduction_verified: false,
        caller_capability_bounding_set_reproduction_verified: false,
        initial_provider_capabilities_absent: false,
        credential_transition_disposition: String::new(),
        setid_transition_certification_digest: String::new(),
        sudo_transition_certification_digest: String::new(),
        post_transition_cgroup_membership_verified: false,
        post_transition_pid_namespace_verified: false,
        post_transition_cleanup_verified: false,
        recursive_provider_request_rejected: false,
    };
    assert!(
        !receipt.complete(),
        "canonical negative vector grants no qualification"
    );
    receipt.render().into_bytes()
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
