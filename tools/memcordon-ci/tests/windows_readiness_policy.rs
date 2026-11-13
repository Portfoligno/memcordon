use memcordon_ci::{
    windows_consumer_readiness::descriptor::matched::{
        Comparison, ComparisonOutcome, NativeStatusDomain, Scope,
    },
    windows_provider_projection_record::{
        BindingExpectation, OriginalSelection, PrivateInput, observe_original_selection,
    },
    windows_readiness_policy::*,
};
use serde_json::json;

fn key(family: &str, scenario: &str) -> memcordon_ci::windows_consumer_readiness::CaseKey {
    memcordon_ci::windows_consumer_readiness::CaseKey {
        family: family.into(),
        scenario: scenario.into(),
    }
}

// Pure assessment fixtures: native execution/ownership is supplied only by the
// real runtime adapter, never established by constructing these wire values.
fn complete_suite() -> Vec<memcordon_ci::windows_consumer_readiness::CaseAssessment> {
    use memcordon_ci::windows_consumer_readiness::{CASE_ASSESSMENT_REVISION, CaseAssessment};
    use memcordon_core::execution_facts::{NativeProcessV2, ProviderAttemptAssociationV1};
    use memcordon_core::{BoundedText, DiagnosticSha256, PublicProviderBindingV1};
    required_case_keys()
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            let digest = |value| DiagnosticSha256::from_bytes([value; 32]);
            let evidence = ExecutionEvidence {
                association: ProviderAttemptAssociationV1 {
                    provider: PublicProviderBindingV1 {
                        generation: BoundedText::new("fixture-provider").unwrap(),
                        source_commit: BoundedText::new(&"ab".repeat(20)).unwrap(),
                        runtime_manifest_sha256: digest(90),
                    },
                    attempt_id: digest(index as u8 + 1),
                    request_sha256: digest(91),
                },
                workload_request_sha256: digest(1),
                root: NativeProcessV2 {
                    pid: index as u32 + 100,
                    birth: index as u64 + 1000,
                },
                descriptor_sha256: digest(2),
                result_sha256: digest(3),
                stdout_sha256: digest(4),
                stderr_sha256: digest(5),
                transcript_sha256: digest(6),
                terminal_observation_sha256: digest(7),
            };
            CaseAssessment {
                revision: CASE_ASSESSMENT_REVISION,
                key,
                contract: CaseContract {
                    intrinsic: IntrinsicContract::Validated,
                    comparison: ComparisonStatus::NotMeasured,
                    execution: ExecutionDisposition::Completed,
                    evidence: Some(evidence.clone()),
                },
                behavior: Ok(()),
                collection: Ok(()),
                retirement: Ok(()),
                descriptor_sha256: String::from(evidence.descriptor_sha256),
                result_sha256: Some(String::from(evidence.result_sha256)),
                stdout_sha256: Some(String::from(evidence.stdout_sha256)),
                stderr_sha256: Some(String::from(evidence.stderr_sha256)),
                transcript_sha256: Some(String::from(evidence.transcript_sha256)),
                request_sha256: Some(String::from(evidence.workload_request_sha256)),
                provider_request_sha256: Some(String::from(evidence.association.request_sha256)),
                terminal_observation_sha256: Some(String::from(
                    evidence.terminal_observation_sha256,
                )),
            }
        })
        .collect()
}

#[test]
fn finite_catalogue_classifies_real_validation_obligations_not_a_blanket_zero_exit() {
    let keys = required_case_keys();
    assert_eq!(keys.len(), 62);
    assert_eq!(
        keys,
        memcordon_ci::windows_consumer_readiness::positive_keys()
    );
    assert_eq!(
        keys.iter()
            .filter(|key| requirement_class(key) == Some(RequirementClass::ContextualWorkload))
            .count(),
        9
    );
    assert_eq!(
        keys.iter()
            .filter(|key| supports_listener_refusal(key))
            .count(),
        6
    );
    assert_eq!(
        keys.iter()
            .filter(|key| core_obligation(key).is_some())
            .count(),
        53
    );
    for (case, obligation) in [
        (key("C-IO", "empty-input"), CoreObligation::PreparedStdio),
        (key("C-IO", "binary-file"), CoreObligation::PreparedFileIo),
        (
            key("W-IO", "argv-backslashes"),
            CoreObligation::NativeInvocation,
        ),
        (
            key("W-STATUS", "exit-127"),
            CoreObligation::ApplicationStatusForwarding,
        ),
        (
            key("C-STATUS", "deadline"),
            CoreObligation::LimitEnforcement,
        ),
        (
            key("C-PARSER", "valid-current-result"),
            CoreObligation::Admission,
        ),
        (
            key("W-ENVELOPE", "restricted"),
            CoreObligation::CallerEnvelope,
        ),
        (
            key("W-DESCENDANT", "breakaway-denial"),
            CoreObligation::DescendantContainment,
        ),
        (
            key("W-RETIREMENT", "output-backpressure"),
            CoreObligation::NativeRetirement,
        ),
    ] {
        assert_eq!(core_obligation(&case), Some(obligation));
    }
    assert_eq!(
        requirement_class(&key("W-TOOLCHAIN", "restricted")),
        Some(RequirementClass::ContextualWorkload)
    );
    assert!(!supports_listener_refusal(&key(
        "W-TOOLCHAIN",
        "restricted"
    )));
    assert!(!supports_listener_refusal(&key(
        "W-DESCENDANT",
        "allowed-token-change"
    )));
    assert_eq!(
        requirement_class(&key("W-STATUS", "arbitrary-native-error")),
        None
    );
}

#[test]
fn settled_unavailable_case_preserves_unmeasured_suffix_and_all_other_required_evidence() {
    let mut records = complete_suite();
    assert!(assess_suite(&records).is_validated());
    for record in &mut records {
        if supports_listener_refusal(&record.key) {
            record.contract.execution = ExecutionDisposition::OriginalListenerRefusal {
                raw_os_error: 10106,
            };
        }
    }
    let decision = assess_suite(&records);
    let SuiteDecision::Validated {
        coverage,
        unavailable_cases,
    } = &decision
    else {
        panic!("actual complete core fixture evidence should validate its scope")
    };
    assert_eq!(unavailable_cases.len(), 6);
    for row in coverage {
        let original = records.iter().find(|record| record.key == row.key).unwrap();
        assert_eq!(row.evidence, original.contract.evidence);
    }
    for row in coverage
        .iter()
        .filter(|row| row.kind == CoverageKind::ObservedListenerPrefix)
    {
        assert_eq!(
            row.capabilities.listener,
            CapabilityAvailability::Unavailable
        );
        for later in [
            row.capabilities.tcp_exchange,
            row.capabilities.pipe_message,
            row.capabilities.compiler,
            row.capabilities.provider_selection,
            row.capabilities.descendants,
            row.capabilities.full_joint,
        ] {
            assert_eq!(later, CapabilityAvailability::Unobserved);
        }
    }
    assert_eq!(
        serde_json::from_slice::<SuiteDecision>(&serde_json::to_vec(&decision).unwrap()).unwrap(),
        decision
    );
    let endpoint = coverage
        .iter()
        .find(|row| row.key == key("W-JOINT", "endpoint-mismatch"))
        .unwrap();
    assert_ne!(endpoint.kind, CoverageKind::ContextualCompleted);
    // A genuinely completed endpoint-negative case has a listener prerequisite,
    // but still cannot claim the intentionally refused exchange or full Joint.
    let endpoint_record = records.iter_mut().find(|r| r.key == endpoint.key).unwrap();
    endpoint_record.contract.execution = ExecutionDisposition::Completed;
    let SuiteDecision::Validated { coverage, .. } = assess_suite(&records) else {
        panic!("completed endpoint fixture")
    };
    let row = coverage.iter().find(|r| r.key == endpoint.key).unwrap();
    assert_eq!(row.capabilities.listener, CapabilityAvailability::Available);
    assert_eq!(
        row.capabilities.tcp_exchange,
        CapabilityAvailability::Unobserved
    );
    assert_eq!(
        row.capabilities.full_joint,
        CapabilityAvailability::Unobserved
    );
}

#[test]
fn missing_duplicate_unknown_and_reused_native_origins_cannot_fill_the_catalogue() {
    let complete = complete_suite();
    let mut missing = complete.clone();
    missing.pop();
    assert!(!assess_suite(&missing).is_validated());
    let mut duplicate = complete.clone();
    duplicate.push(duplicate[0].clone());
    assert!(!assess_suite(&duplicate).is_validated());
    let mut unknown = complete.clone();
    unknown[0].key.scenario = "unknown".into();
    assert!(!assess_suite(&unknown).is_validated());
    let mut reused = complete.clone();
    let original_key = reused[1].key.clone();
    reused[1] = reused[0].clone();
    reused[1].key = original_key;
    assert!(!assess_suite(&reused).is_validated());
    let pending = CaseContract::not_run();
    assert_eq!(pending.intrinsic, IntrinsicContract::Unobserved);
    assert_eq!(pending.execution, ExecutionDisposition::NotRun);
    assert!(pending.evidence.is_none());
}

#[test]
fn all_refusal_and_partial_positive_sets_fail_the_required_core_evidence_floor() {
    for retained_family in [
        None,
        Some("W-ENVELOPE"),
        Some("W-STATUS"),
        Some("contextual"),
    ] {
        let mut records = complete_suite();
        for record in &mut records {
            let keep = retained_family == Some(record.key.family.as_str())
                || retained_family == Some("contextual")
                    && requirement_class(&record.key) == Some(RequirementClass::ContextualWorkload);
            if !keep {
                record.contract.execution = if retained_family.is_none() {
                    ExecutionDisposition::OriginalListenerRefusal {
                        raw_os_error: 10106,
                    }
                } else {
                    ExecutionDisposition::NotRun
                };
            }
        }
        let SuiteDecision::Rejected {
            missing_core_coverage,
            ..
        } = assess_suite(&records)
        else {
            panic!("partial evidence cannot qualify")
        };
        assert!(!missing_core_coverage.is_empty());
    }
}

#[test]
fn forged_contract_tags_capture_associations_and_comparisons_do_not_create_coverage() {
    let records = complete_suite();
    let mutations: &[fn(&mut memcordon_ci::windows_consumer_readiness::CaseAssessment)] = &[
        |r| r.revision = 1,
        |r| r.behavior = Err("prepared operation failed".into()),
        |r| r.collection = Err("stream capture incomplete".into()),
        |r| r.retirement = Err("native owner uncertain".into()),
        |r| r.contract.intrinsic = IntrinsicContract::Invalid,
        |r| r.contract.intrinsic = IntrinsicContract::Unobserved,
        |r| r.contract.execution = ExecutionDisposition::Unvalidated,
        |r| r.contract.comparison = ComparisonStatus::Different,
        |r| r.contract.comparison = ComparisonStatus::MatchedRefusal,
        |r| r.contract.evidence = None,
        |r| {
            // A complete provider request and its embedded workload contract
            // are distinct hash domains, even in an otherwise valid case.
            r.request_sha256 = Some(String::from(
                r.contract
                    .evidence
                    .as_ref()
                    .unwrap()
                    .association
                    .request_sha256
                    .clone(),
            ));
        },
        |r| r.result_sha256 = None,
        |r| r.stdout_sha256 = None,
        |r| r.stderr_sha256 = None,
        |r| r.transcript_sha256 = None,
        |r| r.request_sha256 = None,
        |r| r.terminal_observation_sha256 = None,
        |r| r.descriptor_sha256 = "ff".repeat(32),
        |r| r.contract.evidence.as_mut().unwrap().root.pid = 0,
        |r| r.contract.evidence.as_mut().unwrap().root.birth = 0,
        |r| {
            r.contract
                .evidence
                .as_mut()
                .unwrap()
                .association
                .provider
                .source_commit = memcordon_core::BoundedText::new("unknown").unwrap()
        },
        |r| {
            r.contract
                .evidence
                .as_mut()
                .unwrap()
                .association
                .request_sha256 = memcordon_core::DiagnosticSha256::from_bytes([99; 32])
        },
        |r| {
            r.contract.evidence.as_mut().unwrap().result_sha256 =
                memcordon_core::DiagnosticSha256::from_bytes([99; 32])
        },
        |r| {
            r.contract.evidence.as_mut().unwrap().transcript_sha256 =
                memcordon_core::DiagnosticSha256::from_bytes([99; 32])
        },
        |r| {
            r.contract
                .evidence
                .as_mut()
                .unwrap()
                .terminal_observation_sha256 =
                memcordon_core::DiagnosticSha256::from_bytes([99; 32])
        },
    ];
    for mutate in mutations {
        let mut changed = records.clone();
        mutate(&mut changed[0]);
        assert!(!assess_suite(&changed).is_validated());
    }
    for field in ["revision", "contract"] {
        let mut wire = serde_json::to_value(&records[0]).unwrap();
        wire.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<memcordon_ci::windows_consumer_readiness::CaseAssessment>(
                wire
            )
            .is_err()
        );
    }
    let mut forged = serde_json::to_value(&records[0]).unwrap();
    forged["contract"]["coverage"] = json!("full-joint");
    assert!(
        serde_json::from_value::<memcordon_ci::windows_consumer_readiness::CaseAssessment>(forged)
            .is_err()
    );
}

#[test]
fn listener_refusal_support_is_closed_and_a_measured_comparison_must_agree() {
    let mut records = complete_suite();
    for case in [
        key("W-TOOLCHAIN", "restricted"),
        key("W-DESCENDANT", "allowed-token-change"),
        key("W-ENVELOPE", "restricted"),
    ] {
        let row = records.iter_mut().find(|r| r.key == case).unwrap();
        row.contract.execution = ExecutionDisposition::OriginalListenerRefusal {
            raw_os_error: 10106,
        };
    }
    assert!(!assess_suite(&records).is_validated());
    let mut records = complete_suite();
    let row = records
        .iter_mut()
        .find(|r| r.key == key("W-JOINT", "restricted"))
        .unwrap();
    row.contract.execution = ExecutionDisposition::OriginalListenerRefusal { raw_os_error: 5 };
    row.contract.comparison = ComparisonStatus::MatchedRefusal;
    assert!(assess_suite(&records).is_validated());
    let row = records
        .iter_mut()
        .find(|r| r.key == key("W-JOINT", "restricted"))
        .unwrap();
    row.contract.comparison = ComparisonStatus::MatchedSuccess;
    assert!(!assess_suite(&records).is_validated());
}

fn selection(pid: u32, private: bool, file_index: u64, base: u64) -> OriginalSelection {
    let input = PrivateInput {
        original_path: "C:\\Windows\\provider.dll".encode_utf16().collect(),
        private_native_path: "\\Device\\Volume\\owned\\provider.dll"
            .encode_utf16()
            .collect(),
        volume_serial: 7,
        file_index,
        bytes: 4096,
        sha256: "ab".repeat(32),
    };
    let expected = BindingExpectation {
        pid,
        birth: 100 + u64::from(pid),
        descriptor_sha256: [1; 32],
        challenge_sha256: [2; 32],
        token_sha256: [3; 32],
        peer: false,
    };
    let load = json!({"complete":true,"operation_code":12,"sequence":2,"thread_id":pid,
        "raw_root":0,"raw_flags":0,"raw_output":base,"name_utf16":input.original_path,
        "name_flags":1,"reported_name_bytes":input.original_path.len()*2,"copied_name_units":input.original_path.len(),
        "entered":1,"returned":1,"output_flags":3,"native_status_or_adapter_marker":0});
    let mapped = if private {
        input.private_native_path.clone()
    } else {
        "\\Device\\Volume\\Windows\\provider.dll"
            .encode_utf16()
            .collect()
    };
    let wire = json!({"format":"memcordon.original-rust-listener-trace","original_binding":{
        "pid":pid,"creation_time_100ns":expected.birth,"descriptor_sha256":expected.descriptor_sha256,
        "challenge_sha256":expected.challenge_sha256,"prior_token_observation_sha256":expected.token_sha256,
        "prior_token_observation_scope":"root-admitted-token-envelope","prior_admitted_token_envelope_sha256":expected.token_sha256,
        "current_process_token":{"sha256":expected.token_sha256,"error":null},"current_effective_token":{"sha256":expected.token_sha256,"error":null}},
        "trace":{"invalid_packet":false,"original_rust_operation":"TcpListener::bind","original_thread":pid,"cutoff_qpc":100,
            "returned_images":{"complete":true,"rows":[{"complete":true,"invalid_row":false,"original_load":load,
                "dependency_sequence":2,"original_thread":pid,"returned_base":base,"allocation_base":base,"memory_type":0x01000000,
                "domain":0,"state":1,"flags":7,"virtual_query_error":0,"mapped_name_error":0,"started_qpc":3,"finished_qpc":4,
                "mapped_path_utf16":mapped}]}}});
    observe_original_selection(&wire, &expected, &[input]).unwrap()
}
fn comparison(outcome: ComparisonOutcome) -> Comparison {
    Comparison {
        outcome,
        scope: Scope::ProviderListenerSelection,
        native_status_domain: NativeStatusDomain::PerOperation,
    }
}

#[test]
fn root_selection_availability_is_independent_from_listener_and_never_full_joint() {
    for private in [false, true] {
        let direct = selection(10, private, 42, 65536);
        let installed = selection(11, private, 42, 131072);
        let result = assess_root_pair(RootPairEvidence {
            listener: &comparison(ComparisonOutcome::ScopeSuccess),
            direct_selection: Some(&direct),
            installed_selection: Some(&installed),
            closure: RootPairClosure::Settled,
        })
        .unwrap();
        assert_eq!(
            result.contract_validation,
            RootContractValidation::Validated
        );
        assert_eq!(
            result.listener_availability,
            CapabilityAvailability::Available
        );
        assert_eq!(
            result.private_selection_availability,
            if private {
                CapabilityAvailability::Available
            } else {
                CapabilityAvailability::Unavailable
            }
        );
        assert_eq!(result.coverage, RootCoverage::ListenerAndObservedSelection);
        assert_eq!(result.peer_spawn_coverage, UnmeasuredCoverage::Unmeasured);
        assert_eq!(result.full_joint_coverage, UnmeasuredCoverage::Unmeasured);
        assert_ne!(
            direct.rows()[0].returned_base,
            installed.rows()[0].returned_base
        );
    }
}

#[test]
fn precise_matching_refusal_preserves_unavailability_but_cannot_supply_positive_coverage() {
    let measured = comparison(ComparisonOutcome::SameObservedFailure);
    let result = assess_root_pair(RootPairEvidence {
        listener: &measured,
        direct_selection: None,
        installed_selection: None,
        closure: RootPairClosure::Settled,
    })
    .unwrap();
    assert_eq!(
        result.listener_availability,
        CapabilityAvailability::Unavailable
    );
    assert_eq!(
        result.private_selection_availability,
        CapabilityAvailability::Unobserved
    );
    assert_eq!(result.coverage, RootCoverage::PreciseNativeRefusal);
    assert_eq!(result.full_joint_coverage, UnmeasuredCoverage::Unmeasured);
    let incomplete = selection(10, true, 42, 65536);
    assert!(
        assess_root_pair(RootPairEvidence {
            listener: &measured,
            direct_selection: Some(&incomplete),
            installed_selection: None,
            closure: RootPairClosure::Settled
        })
        .is_err()
    );
    for closure in [
        RootPairClosure::SetupInvalid,
        RootPairClosure::CaptureIncomplete,
        RootPairClosure::OwnershipUncertain,
    ] {
        assert!(
            assess_root_pair(RootPairEvidence {
                listener: &measured,
                direct_selection: None,
                installed_selection: None,
                closure
            })
            .is_err()
        );
    }
}

#[test]
fn mismatch_missing_observation_or_equal_bytes_from_different_held_inputs_never_validate() {
    let direct = selection(10, true, 42, 65536);
    let installed = selection(11, true, 43, 131072);
    let success = comparison(ComparisonOutcome::ScopeSuccess);
    for other in [&installed, &direct, &selection(11, false, 42, 131072)] {
        assert!(
            assess_root_pair(RootPairEvidence {
                listener: &success,
                direct_selection: Some(&direct),
                installed_selection: Some(other),
                closure: RootPairClosure::Settled
            })
            .is_err()
        );
    }
    assert!(
        assess_root_pair(RootPairEvidence {
            listener: &success,
            direct_selection: Some(&direct),
            installed_selection: None,
            closure: RootPairClosure::Settled
        })
        .is_err()
    );
    assert!(
        assess_root_pair(RootPairEvidence {
            listener: &comparison(ComparisonOutcome::DifferentOutcome),
            direct_selection: None,
            installed_selection: None,
            closure: RootPairClosure::Settled
        })
        .is_err()
    );
    let mut wrong_scope = success;
    wrong_scope.scope = Scope::JointListenerPrefix;
    assert!(
        assess_root_pair(RootPairEvidence {
            listener: &wrong_scope,
            direct_selection: None,
            installed_selection: None,
            closure: RootPairClosure::Settled
        })
        .is_err()
    );
}

#[test]
fn original_application_refusal_keeps_actual_selection_facts_without_positive_listener_claim() {
    let measured = comparison(ComparisonOutcome::SameOriginalApplicationFailure);
    for private in [false, true] {
        let direct = selection(10, private, 42, 65536);
        let installed = selection(11, private, 42, 131072);
        let result = assess_root_pair(RootPairEvidence {
            listener: &measured,
            direct_selection: Some(&direct),
            installed_selection: Some(&installed),
            closure: RootPairClosure::Settled,
        })
        .unwrap();
        assert_eq!(
            result.contract_validation,
            RootContractValidation::Validated
        );
        assert_eq!(
            result.listener_availability,
            CapabilityAvailability::Unavailable
        );
        assert_eq!(
            result.private_selection_availability,
            if private {
                CapabilityAvailability::Available
            } else {
                CapabilityAvailability::Unavailable
            }
        );
        assert_eq!(result.coverage, RootCoverage::OriginalApplicationRefusal);
        assert_eq!(result.peer_spawn_coverage, UnmeasuredCoverage::Unmeasured);
        assert_eq!(result.full_joint_coverage, UnmeasuredCoverage::Unmeasured);
        for (left, right) in [
            (Some(&direct), None),
            (None, Some(&installed)),
            (Some(&direct), Some(&direct)),
            (Some(&direct), Some(&selection(11, private, 43, 131072))),
            (Some(&direct), Some(&selection(11, !private, 42, 131072))),
        ] {
            assert!(
                assess_root_pair(RootPairEvidence {
                    listener: &measured,
                    direct_selection: left,
                    installed_selection: right,
                    closure: RootPairClosure::Settled
                })
                .is_err()
            );
        }
    }
    let missing = assess_root_pair(RootPairEvidence {
        listener: &measured,
        direct_selection: None,
        installed_selection: None,
        closure: RootPairClosure::Settled,
    })
    .unwrap();
    assert_eq!(
        missing.private_selection_availability,
        CapabilityAvailability::Unobserved
    );
    assert_eq!(
        missing.listener_availability,
        CapabilityAvailability::Unavailable
    );
    for closure in [
        RootPairClosure::SetupInvalid,
        RootPairClosure::CaptureIncomplete,
        RootPairClosure::OwnershipUncertain,
    ] {
        assert!(
            assess_root_pair(RootPairEvidence {
                listener: &measured,
                direct_selection: None,
                installed_selection: None,
                closure
            })
            .is_err()
        );
    }
}
