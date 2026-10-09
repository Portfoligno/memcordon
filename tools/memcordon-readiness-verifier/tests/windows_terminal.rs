//! Retained decoder oracle vectors, not installed or native execution evidence.
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

fn key() -> CaseKey {
    CaseKey {
        target: "x86_64-pc-windows-msvc".into(),
        channel: Some("candidate-native".into()),
        evidence_class: EvidenceClass::InstalledProduct,
        family: "W-JOINT".into(),
        scenario: "ordinary".into(),
    }
}

fn vector() -> (Value, NativeObservation) {
    let provider = json!({"generation":"native-generation", "source_commit":"1".repeat(40), "runtime_manifest_sha256":"2".repeat(64)});
    let request = json!({"restart_attempt":1, "schema_version":3, "expected_provider_binding":provider,
        "workload_contract":null, "nonce":"owned-nonce", "command":{"program":[67,58,92,102,46,101,120,101],"arguments":[]},
        "environment":[], "current_directory":[67,58,92,119], "policy":{"memory_limit_bytes":null,"absolute_deadline_millis":null,
            "lifetime":"workload","poll_interval_millis":10,"signal_grace_millis":0,"command_exit_grace_millis":0,"limit_grace_millis":0}});
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let request_sha256 = sha256(&request_bytes);
    let native = NativeObservation {
        format: "memcordon.consumer-readiness.native".into(),
        revision: 1,
        run_id: "oracle-vector".into(),
        lease_id: Some("lease".into()),
        target: "x86_64-pc-windows-msvc".into(),
        executable_sha256: "3".repeat(64),
        invocation_sha256: "4".repeat(64),
        execution_invocation_sha256: None,
        request_sha256: Some(request_sha256.clone()),
        provider_sha256: Some("5".repeat(64)),
        provider_generation: Some("native-generation".into()),
        runtime_manifest_sha256: Some("2".repeat(64)),
        attempt_id: Some("6".repeat(64)),
        attempt_nonce: Some("owned-nonce".into()),
        root_pid: Some(10),
        root_birth: Some(100),
        held_processes: vec![
            HeldProcessIdentity {
                pid: 10,
                birth: 100,
                parent_pid: None,
                parent_birth: None,
                retirement_observed: true,
            },
            HeldProcessIdentity {
                pid: 11,
                birth: 110,
                parent_pid: Some(10),
                parent_birth: Some(100),
                retirement_observed: true,
            },
        ],
        frontend_status: 0,
        origin: OutcomeOrigin::Target,
        target_status: Some(0),
        authenticated_provider_exchange: true,
        relay_complete: true,
        result_named_identity_verified: true,
        result_readback_verified: true,
        application_stage: None,
    };
    let terminal = json!({"schema_version":2, "attempt_id":"6".repeat(64), "nonce":"owned-nonce", "request_sha256":request_sha256,
        "payload":{"kind":"execution","child_pid":10,"duration_millis":20,"authorization_offset_millis":1,
            "outcome":{"outcome":"exited","child":{"kind":"exit-code","code":0},"peak":null,
                "cleanup":{"graceful_attempted":false,"force_attempted":false,"direct_child_reaped":true,"workload_empty":true,"errors":[]}},"boundary_detail":{}},
        "restart_safety":{"direct_child_reaped":true,"workload_empty":true,"helpers_reaped":true,"containment_removed":true,
            "containment_incapable_of_live_members":true,"sealed_boundary_retired":true,"errors":[]},
        "retirement_proof":{"schema_version":2,"source":"live-native","attempt_id":"6".repeat(64),"nonce":"owned-nonce","request_sha256":request_sha256,
            "provider_generation":"native-generation","launch_incarnation":"launch","original_boot_id":"boot","job_identity":"job","owner_manifest_sha256":"7".repeat(64),
            "target_completion_observed":true,"native_job_empty_observed":true,"relay_closure_observed":true,"guardian_completion_observed":true,
            "owner_capabilities_closed":true,"launch_gate_closed":true,"policy_reference_bound":true},
        "process_observation":{"schema_version":2,"root_identity":{"process_id":10,"creation_time_100ns":100},"required_witness":null,
            "final_accounting":{"total_processes_native_u32":2,"active_processes_native_u32":0,"observed_after_target_retirement":true,"counter_regression_observed":false},
            "coverage":{"coverage":"sampled","policy":{"snapshot_storage_bytes":262144,"sample_storage_bytes":24576,"serialized_field_bytes":131072,
                "snapshot_queries_per_tick":2,"identity_queries_per_tick":64,"sample_interval_millis":100},
                "counters":{"polls_attempted":2,"snapshots_obtained":2,"identity_queries_attempted":2,"identity_observations_verified":2,
                    "vanished_or_not_member":0,"sample_evictions":0,"counter_saturated":false},
                "omissions":{"snapshot_byte_budget":0,"snapshot_race_or_retry_budget":0,"per_tick_query_budget":0,"allocation_unavailable":0,"sample_eviction":0},
                "sample":[{"identity":{"process_id":10,"creation_time_100ns":100},"last_observation_sequence":1},
                    {"identity":{"process_id":11,"creation_time_100ns":110},"last_observation_sequence":2}]}}});
    (
        json!({"format":"memcordon.windows-terminal-observation","revision":1,"provider":provider,"terminal":terminal,"provider_request":request_bytes,
        "frontend_delivery":{"schema_version":1,"attempt_id":"6".repeat(64),"nonce":"owned-nonce","request_sha256":request_sha256,
            "authority_sha256":"8".repeat(64),"retired_sha256":"9".repeat(64),"retired_confirmed":true}}),
        native,
    )
}

#[test]
fn independently_decodes_delivery_root_ancestry_sample_and_authoritative_retirement_vector() {
    let (sidecar, native) = vector();
    validate_windows_terminal_observation(&serde_json::to_vec(&sidecar).unwrap(), &native, &key())
        .unwrap();
}

#[test]
fn retirement_source_payload_matrix_is_closed_and_preserves_prior_boot_uncertainty() {
    let (base, native) = vector();
    for source in ["guardian-recovery", "prior-boot"] {
        let mut wrong = base.clone();
        wrong["terminal"]["retirement_proof"]["source"] = json!(source);
        assert!(
            validate_windows_terminal_observation(
                &serde_json::to_vec(&wrong).unwrap(),
                &native,
                &key()
            )
            .is_err()
        );
    }
    let mut recovery_native = native.clone();
    recovery_native.origin = OutcomeOrigin::ProviderFailure;
    recovery_native.target_status = None;
    let mut recovery = base;
    recovery["terminal"]["payload"] = json!({"kind":"recovered-closure","primary_failure":{"unavailable":{"reason":"worker-lost-before-observation"}},"target_creation_observed":true,"resume_attempted":true});
    let proof = &mut recovery["terminal"]["retirement_proof"];
    proof["source"] = json!("prior-boot");
    proof["current_boot_id"] = json!("new-boot");
    for field in [
        "target_completion_observed",
        "native_job_empty_observed",
        "relay_closure_observed",
        "guardian_completion_observed",
    ] {
        proof[field] = json!(false);
    }
    validate_windows_terminal_observation(
        &serde_json::to_vec(&recovery).unwrap(),
        &recovery_native,
        &key(),
    )
    .unwrap();
    let mut invented = recovery.clone();
    invented["terminal"]["retirement_proof"]["native_job_empty_observed"] = json!(true);
    assert!(
        validate_windows_terminal_observation(
            &serde_json::to_vec(&invented).unwrap(),
            &recovery_native,
            &key()
        )
        .is_err()
    );
    recovery["terminal"]["retirement_proof"]["source"] = json!("guardian-recovery");
    recovery["terminal"]["retirement_proof"]
        .as_object_mut()
        .unwrap()
        .remove("current_boot_id");
    recovery["terminal"]["retirement_proof"]["guardian_receipt_sha256"] = json!("a".repeat(64));
    recovery["terminal"]["retirement_proof"]["native_job_empty_observed"] = json!(true);
    recovery["terminal"]["retirement_proof"]["guardian_completion_observed"] = json!(true);
    validate_windows_terminal_observation(
        &serde_json::to_vec(&recovery).unwrap(),
        &recovery_native,
        &key(),
    )
    .unwrap();
}

#[test]
fn delivery_generation_sample_policy_and_nested_retirement_mutants_are_rejected() {
    for mutation in 0..11 {
        let (mut sidecar, native) = vector();
        match mutation {
            0 => sidecar["frontend_delivery"]["retired_confirmed"] = json!(false),
            1 => sidecar["frontend_delivery"]["nonce"] = json!("other-nonce"),
            2 => {
                sidecar["terminal"]["retirement_proof"]["provider_generation"] =
                    json!("different-provider")
            }
            3 => {
                sidecar["terminal"]["process_observation"]["coverage"]["sample"][1]["identity"]["process_id"] =
                    json!(777)
            }
            4 => {
                sidecar["terminal"]["process_observation"]["root_identity"]["creation_time_100ns"] =
                    json!(101)
            }
            5 => {
                sidecar["terminal"]["process_observation"]["coverage"]["counters"]["sample_evictions"] =
                    json!(1)
            }
            6 => {
                sidecar["terminal"]["process_observation"]["coverage"]["policy"]["sample_storage_bytes"] =
                    json!(16)
            }
            7 => {
                sidecar["terminal"]["process_observation"]["coverage"]["coverage"] =
                    json!("complete")
            }
            8 => {
                sidecar["terminal"]["retirement_proof"]["owner_capabilities_closed"] = json!(false)
            }
            9 => sidecar["provider_request"][0] = json!(0),
            _ => {
                sidecar["terminal"]["process_observation"]["coverage"]["sample"][1] =
                    sidecar["terminal"]["process_observation"]["coverage"]["sample"][0].clone()
            }
        }
        let result = validate_windows_terminal_observation(
            &serde_json::to_vec(&sidecar).unwrap(),
            &native,
            &key(),
        );
        assert!(result.is_err(), "mutation {mutation} was accepted");
    }
}

#[test]
fn missing_or_reused_held_ancestor_cannot_certify_sample_provenance() {
    let (sidecar, mut native) = vector();
    native.held_processes[1].parent_birth = Some(120);
    assert!(
        validate_windows_terminal_observation(
            &serde_json::to_vec(&sidecar).unwrap(),
            &native,
            &key()
        )
        .is_err()
    );
    native.held_processes[1].parent_birth = Some(100);
    native.held_processes[1].retirement_observed = false;
    assert!(
        validate_windows_terminal_observation(
            &serde_json::to_vec(&sidecar).unwrap(),
            &native,
            &key()
        )
        .is_err()
    );
}

#[test]
fn worker_loss_unavailable_coverage_is_exactly_scoped_and_never_invents_final_accounting() {
    let (mut sidecar, mut native) = vector();
    native.origin = OutcomeOrigin::ProviderFailure;
    native.target_status = None;
    sidecar["terminal"]["payload"] = json!({"kind":"recovered-closure","primary_failure":{"unavailable":{"reason":"worker-lost-before-observation"}},
        "target_creation_observed":true,"resume_attempted":true});
    sidecar["terminal"]["process_observation"] = json!({"schema_version":2,"coverage":{"coverage":"unavailable","reason":"worker-lost-before-freeze"},
        "root_identity":null,"final_accounting":null,"required_witness":null});
    sidecar["terminal"]["retirement_proof"]["source"] = json!("guardian-recovery");
    sidecar["terminal"]["retirement_proof"]["guardian_receipt_sha256"] = json!("a".repeat(64));
    assert!(
        validate_windows_terminal_observation(
            &serde_json::to_vec(&sidecar).unwrap(),
            &native,
            &key()
        )
        .is_err()
    );
    let mut fault = key();
    fault.family = "W-RETIREMENT".into();
    fault.scenario = "attempt-worker-loss".into();
    validate_windows_terminal_observation(&serde_json::to_vec(&sidecar).unwrap(), &native, &fault)
        .unwrap();
    sidecar["terminal"]["process_observation"]["final_accounting"] = json!({"total_processes_native_u32":2,"active_processes_native_u32":0,
        "observed_after_target_retirement":true,"counter_regression_observed":false});
    assert!(
        validate_windows_terminal_observation(
            &serde_json::to_vec(&sidecar).unwrap(),
            &native,
            &fault
        )
        .is_err()
    );
}

#[test]
fn native_nul_facade_receipt_cannot_substitute_allowed_arguments_or_authorization() {
    let (_, mut native) = vector();
    native.origin = OutcomeOrigin::AdmissionRefusal;
    native.root_pid = None;
    native.root_birth = None;
    native.target_status = None;
    let receipt = json!({"format":"memcordon.windows-native-argv-refusal","revision":1,"argument_utf16":[97,0,98],
        "code":"MCSEALED-WINDOWS-REQUEST","category":"Usage","target_pid":null,"target_released":false,
        "provider_association":null,"detail":"argument contains NUL"});
    validate_windows_native_argument_refusal(&serde_json::to_vec(&receipt).unwrap(), &native)
        .unwrap();
    for field in [
        "argument_utf16",
        "code",
        "target_pid",
        "target_released",
        "provider_association",
    ] {
        let mut mutant = receipt.clone();
        mutant[field] = match field {
            "argument_utf16" => json!([97, 98]),
            "code" => json!("other"),
            "target_pid" => json!(10),
            "target_released" => json!(true),
            _ => json!({}),
        };
        assert!(
            validate_windows_native_argument_refusal(
                &serde_json::to_vec(&mutant).unwrap(),
                &native
            )
            .is_err()
        );
    }
}
