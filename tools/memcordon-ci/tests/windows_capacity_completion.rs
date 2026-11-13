use memcordon_ci::windows_consumer_readiness::{
    descriptor::{self, Case, Descriptor},
    validate_capacity_completion,
};
use serde_json::{Value, json};

fn descriptor(held: bool) -> Descriptor {
    let root = std::env::temp_dir().join("memcordon-finite-capacity-model");
    Descriptor {
        matched_control: None,
        format: "memcordon.fixture-workload".into(),
        revision: descriptor::DESCRIPTOR_REVISION,
        case: Case::CapacityCompletion,
        output_root: root.clone(),
        transcript: root.join("events.bin"),
        challenge: vec![0, 255, 128, 1],
        stdout: Vec::new(),
        stderr: Vec::new(),
        arguments: Vec::new(),
        application_status: 0,
        churn_creations: 0,
        churn_live: 0,
        denied_write_paths: Vec::new(),
        sentinel_handles: Vec::new(),
        descendant_gate: None,
        start_gate: Some("Local\\memcordon-readiness-capacity-model-start".into()),
        start_transport: descriptor::StartTransport::NamedEvent,
        control_clock: None,
        winsock_registry: None,
        provider_input_experiment: false,
        provider_input_paths: Vec::new(),
        provider_input_binding: None,
        gate_access_diagnostic: None,
        gate_precondition: None,
        completion_gate: held
            .then(|| "Local\\memcordon-readiness-capacity-model-completion".into()),
        cohort_gate: Some("Local\\memcordon-readiness-capacity-model-child".into()),
        generation_gate: None,
        toolchain: None,
    }
}

fn events(d: &Descriptor) -> Vec<Value> {
    let mut events = vec![
        json!({"stage":"started","pid":10,"ordinal":null,"value":d.challenge}),
        json!({"stage":"native-argv-observed","pid":10,"ordinal":null,"value":serde_json::to_vec(&json!({"encoding":"windows_utf16","values":Vec::<Vec<u16>>::new()})).unwrap()}),
        json!({"stage":"sentinel-handles-excluded","pid":10,"ordinal":null,"value":0u32.to_le_bytes()}),
        json!({"stage":"token-envelope","pid":10,"ordinal":null,"value":serde_json::to_vec(&json!({"user_sid":[1,1,0,0,0,0,0,5,21,0,0,0],"restricted":false,"integrity_rid":8192,"elevated":false,"restricting_sids":[]})).unwrap()}),
        json!({"stage":"controller-released","pid":10,"ordinal":null,"value":d.challenge}),
        json!({"stage":"capacity-child-created","pid":10,"ordinal":0,
            "value":serde_json::to_vec(&json!({"process_id":11,"creation_time_100ns":21})).unwrap()}),
    ];
    if d.completion_gate.is_some() {
        events.push(json!({"stage":"capacity-live-before-natural-completion","pid":10,"ordinal":null,"value":d.challenge}));
    }
    events.push(json!({"stage":"capacity-child-completed","pid":10,"ordinal":0,"value":[]}));
    events.push(json!({"stage":"finished","pid":10,"ordinal":null,"value":d.challenge}));
    events
}

fn encode(events: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let mut event = event.clone();
        event["sequence"] = (index as u32).into();
        let frame = serde_json::to_vec(&event).unwrap();
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend(frame);
    }
    bytes
}

#[test]
fn finite_serial_and_held_completion_keep_actual_child_identity_without_tcp_claims() {
    for held in [false, true] {
        let d = descriptor(held);
        d.validate().unwrap();
        let child = validate_capacity_completion(&d, &encode(&events(&d)), 10).unwrap();
        assert_eq!(child.process_id, 11);
        assert_eq!(child.creation_time_100ns, 21);
    }
}

#[test]
fn missing_duplicate_wrong_ordinal_identity_or_root_cannot_establish_a_capacity_child() {
    let d = descriptor(true);
    let original = events(&d);
    for field in [
        "missing",
        "duplicate",
        "ordinal",
        "root",
        "zero_pid",
        "same_pid",
        "zero_birth",
        "extra_identity",
    ] {
        let mut events = original.clone();
        match field {
            "missing" => {
                events.remove(5);
            }
            "duplicate" => events.insert(6, events[5].clone()),
            "ordinal" => events[5]["ordinal"] = 1.into(),
            "root" => events[5]["pid"] = 12.into(),
            _ => {
                let mut identity = json!({"process_id":11,"creation_time_100ns":21});
                match field {
                    "zero_pid" => identity["process_id"] = 0.into(),
                    "same_pid" => identity["process_id"] = 10.into(),
                    "zero_birth" => identity["creation_time_100ns"] = 0.into(),
                    "extra_identity" => identity["parent"] = 10.into(),
                    _ => unreachable!(),
                }
                events[5]["value"] =
                    serde_json::to_value(serde_json::to_vec(&identity).unwrap()).unwrap();
            }
        }
        assert!(
            validate_capacity_completion(&d, &encode(&events), 10).is_err(),
            "{field}"
        );
    }
}

#[test]
fn held_and_finished_markers_require_exact_order_challenge_and_complete_frames() {
    let d = descriptor(true);
    let original = events(&d);
    for field in [
        "missing_hold",
        "duplicate_hold",
        "hold_ordinal",
        "hold_challenge",
        "hold_before_child",
        "completed_before_child",
        "duplicate_completed",
        "completed_extra_output",
        "missing_finished",
        "finished_challenge",
        "wrong_root",
        "missing_native_prefix",
        "reordered_native_prefix",
        "repeated_native_prefix",
    ] {
        let mut events = original.clone();
        match field {
            "missing_hold" => {
                events.remove(6);
            }
            "duplicate_hold" => events.insert(7, events[6].clone()),
            "hold_ordinal" => events[6]["ordinal"] = 0.into(),
            "hold_challenge" => events[6]["value"] = json!([99]),
            "hold_before_child" => events.swap(5, 6),
            "completed_before_child" => events.swap(5, 7),
            "duplicate_completed" => events.insert(8, events[7].clone()),
            "completed_extra_output" => events[7]["value"] = json!([1]),
            "missing_finished" => {
                events.pop();
            }
            "finished_challenge" => events[8]["value"] = json!([99]),
            "wrong_root" => events[8]["pid"] = 12.into(),
            "missing_native_prefix" => {
                events.remove(1);
            }
            "reordered_native_prefix" => events.swap(1, 2),
            "repeated_native_prefix" => events.insert(2, events[1].clone()),
            _ => unreachable!(),
        }
        assert!(
            validate_capacity_completion(&d, &encode(&events), 10).is_err(),
            "{field}"
        );
    }
    let bytes = encode(&original);
    assert!(validate_capacity_completion(&d, &bytes[..bytes.len() - 1], 10).is_err());
    assert!(validate_capacity_completion(&descriptor(false), &bytes, 10).is_err());
}

#[test]
fn tcp_compiler_demand_and_unrelated_suffixes_are_not_finite_capacity_evidence() {
    let d = descriptor(false);
    for stage in [
        "tcp-listener-owned",
        "tcp-peer-created",
        "tcp-peer-complete",
        "named-pipe-while-tcp-owned",
        "toolchain-compiled",
        "toolchain-test-child-dll-complete",
        "policy-demand-started",
        "churn-complete",
    ] {
        let mut events = events(&d);
        events.insert(6, json!({"stage":stage,"pid":10,"ordinal":null,"value":[]}));
        assert!(
            validate_capacity_completion(&d, &encode(&events), 10).is_err(),
            "{stage}"
        );
    }
}

#[test]
fn finite_capacity_descriptor_never_admits_an_infinite_or_composite_operation() {
    let d = descriptor(false);
    let mutations: &[fn(&mut Descriptor)] = &[
        |d| d.cohort_gate = None,
        |d| d.cohort_gate = d.start_gate.clone(),
        |d| d.completion_gate = d.cohort_gate.clone(),
        |d| d.generation_gate = Some("Local\\memcordon-readiness-extra".into()),
        |d| d.case = Case::HeldDemand,
        |d| d.case = Case::Joint,
        |d| d.churn_creations = 4096,
        |d| d.application_status = 2,
        |d| d.stdout.push(1),
        |d| d.stderr.push(1),
    ];
    for mutate in mutations {
        let mut changed = d.clone();
        mutate(&mut changed);
        assert!(validate_capacity_completion(&changed, &encode(&events(&d)), 10).is_err());
    }
}

// Aggregation fixtures establish only consistency of collected metadata; the
// installed native runner must supply the actual original owners and captures.
fn capacity_records() -> Vec<memcordon_ci::windows_readiness_capacity::CapacityAssessment> {
    use memcordon_ci::{
        windows_consumer_readiness::{CASE_ASSESSMENT_REVISION, CaseAssessment},
        windows_readiness_capacity::{CapacityAssessment, planned_attempt_count, required_keys},
    };
    required_keys().into_iter().enumerate().map(|(group, key)| {
        let attempts = (0..planned_attempt_count(&key).unwrap()).map(|ordinal| {
            let unique = 100 + group * 10 + ordinal;
            let hash = |byte: u8| format!("{byte:02x}").repeat(32);
            serde_json::from_value::<CaseAssessment>(json!({"revision":CASE_ASSESSMENT_REVISION,"key":key,
                "contract":{"intrinsic":"validated","comparison":"not-measured","execution":{"kind":"completed"},
                    "evidence":{"association":{"provider":{"generation":"fixture-capacity","source_commit":"ab".repeat(20),
                        "runtime_manifest_sha256":hash(90)},"attempt_id":hash(unique as u8),"request_sha256":hash(1)},
                        "workload_request_sha256":hash(2),"root":{"pid":unique+1000,"birth":unique+10000},
                        "descriptor_sha256":hash(3),"result_sha256":hash(4),"stdout_sha256":hash(5),"stderr_sha256":hash(6),
                        "transcript_sha256":hash(7),"terminal_observation_sha256":hash(8)}},
                "behavior":Ok::<(),String>(()),"collection":Ok::<(),String>(()),"retirement":Ok::<(),String>(()),
                "descriptor_sha256":hash(3),"request_sha256":hash(2),"provider_request_sha256":hash(1),
                "result_sha256":hash(4),"stdout_sha256":hash(5),"stderr_sha256":hash(6),
                "transcript_sha256":hash(7),"terminal_observation_sha256":hash(8)})).unwrap()
        }).collect();
        CapacityAssessment { key, attempts, behavior: Ok(()), collection: Ok(()), retirement: Ok(()),
            artifacts: vec![memcordon_ci::windows_installed_cases::SelectedArtifact {
                path: std::env::temp_dir().join("capacity-aggregation-fixture.json"), sha256: "aa".repeat(32) }] }
    }).collect()
}

#[test]
fn capacity_aggregation_requires_each_bounded_attempt_and_fresh_original_evidence() {
    use memcordon_ci::windows_readiness_capacity::{accepted, planned_attempt_count};
    use memcordon_ci::windows_readiness_policy::{
        CaseContract, ComparisonStatus, ExecutionDisposition, IntrinsicContract,
    };
    let records = capacity_records();
    assert_eq!(
        records
            .iter()
            .map(|r| planned_attempt_count(&r.key).unwrap())
            .collect::<Vec<_>>(),
        [3, 2, 1]
    );
    assert!(accepted(&records));
    let mutations: &[fn(&mut Vec<memcordon_ci::windows_readiness_capacity::CapacityAssessment>)] =
        &[
            |r| {
                r.pop();
            },
            |r| {
                r[0].attempts.pop();
            },
            |r| {
                let extra = r[0].attempts[0].clone();
                r[0].attempts.push(extra);
            },
            |r| r[0].attempts[0].key.family = "W-JOINT".into(),
            |r| r[0].attempts[0].contract = CaseContract::not_run(),
            |r| r[0].attempts[0].contract.intrinsic = IntrinsicContract::Invalid,
            |r| r[0].attempts[0].contract.execution = ExecutionDisposition::Unvalidated,
            |r| {
                r[0].attempts[0].contract.execution =
                    ExecutionDisposition::OriginalListenerRefusal {
                        raw_os_error: 10106,
                    }
            },
            |r| r[0].attempts[0].contract.comparison = ComparisonStatus::MatchedSuccess,
            |r| r[0].attempts[0].contract.evidence = None,
            |r| r[0].attempts[0].retirement = Err("native child unproved".into()),
            |r| r[0].attempts[0].collection = Err("capture absent".into()),
            |r| r[0].attempts[0].result_sha256 = None,
            |r| r[0].attempts[0].provider_request_sha256 = r[0].attempts[0].request_sha256.clone(),
            |r| r[0].attempts[1] = r[0].attempts[0].clone(),
            |r| {
                let origin = r[0].attempts[0].contract.evidence.as_ref().unwrap().clone();
                let other = r[1].attempts[0].contract.evidence.as_mut().unwrap();
                other.root = origin.root;
            },
            |r| {
                let origin = r[0].attempts[0].contract.evidence.as_ref().unwrap().clone();
                let other = r[1].attempts[0].contract.evidence.as_mut().unwrap();
                other.association.attempt_id = origin.association.attempt_id;
            },
            |r| r[0].artifacts.clear(),
        ];
    for mutate in mutations {
        let mut changed = records.clone();
        mutate(&mut changed);
        assert!(!accepted(&changed));
    }
}
