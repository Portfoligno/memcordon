use memcordon_ci::linux_snapshot_rejection::validate;
use memcordon_core::{
    BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1,
    execution_facts::{
        CleanupStateV1, NativeProcessV2, OperationalToolV1, OutcomeKindV1, OutcomeV1,
    },
    result_v3::*,
    workload_request::WorkloadAttemptAssociationV1,
};
use std::num::NonZeroU32;

fn fixture() -> (ResultV3, LinuxWorkloadTerminalV1) {
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let source = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let association = WorkloadAttemptAssociationV1 {
        format: "memcordon.workload-attempt".into(),
        revision: 1,
        attempt: [1; 16],
        challenge: [2; 16],
        request_sha256: digest.clone(),
        boot_id: BoundedText::new("actual-boot").unwrap(),
        provider: PublicProviderBindingV1 {
            generation: BoundedText::new(&format!("0.5.8-dev:{source}")).unwrap(),
            source_commit: BoundedText::new(source).unwrap(),
            runtime_manifest_sha256: digest.clone(),
        },
        control: NativeProcessV2 { pid: 10, birth: 0 },
    };
    let request = WorkloadRequestAssociationV1 {
        request_sha256: digest.clone(),
        invocation_sha256: digest.clone(),
        resource_policy_sha256: digest,
        runtime_sha256: None,
        input_sha256: None,
    };
    let mut report = ResultV3 {
        format: "memcordon.result".into(),
        revision: 3,
        tool: OperationalToolV1 {
            name: "memcordon".into(),
            version: "test".into(),
            os: "linux".into(),
            architecture: "aarch64".into(),
            runtime_features: vec![],
        },
        invocation: memcordon_core::InvocationReport {
            syntax: "plus-budgets-v1".into(),
            budget_tokens: vec![],
            memory_token: None,
            deadline_token: None,
            argv: vec![memcordon_core::NativeArgument::from_os(
                std::ffi::OsStr::new("program"),
            )],
        },
        request: Some(request.clone()),
        provider: Some(association.provider.clone()),
        workload_attempt: Some(association.clone()),
        release: ReleaseKnowledgeV3::NotReleased,
        outcome: OutcomeV1 {
            kind: OutcomeKindV1::LaunchFailure,
            native_termination: None,
            wrapper_status: 125,
        },
        cleanup: CleanupV3 {
            state: CleanupStateV1::Unknown,
            obligations: BoundedVec::default(),
        },
        delivery: DeliveryStateV3::PreparedBy {
            writer_pid: NonZeroU32::new(42).unwrap(),
        },
        output_delivery: None,
        diagnostics: BoundedVec::default(),
        provider_failure: None,
        request_rejection: None,
        windows_rejection: None,
        windows_attempt: None,
        runtime: RuntimeExecutionV3::PreparationFailed {
            profile: BoundedText::new("linux-private-workload-v1").unwrap(),
        },
    };
    let mut obligations = BoundedVec::default();
    for resource in [
        CleanupResourceV3::ControlHandles,
        CleanupResourceV3::Staging,
        CleanupResourceV3::Footprint,
        CleanupResourceV3::Record,
    ] {
        obligations
            .try_push(CleanupObligationV3 {
                resource,
                settled: true,
            })
            .unwrap();
    }
    let mut failures = BoundedVec::default();
    failures
        .try_push(BoundedText::new("member content digest differs").unwrap())
        .unwrap();
    let terminal = LinuxWorkloadTerminalV1 {
        format: LINUX_WORKLOAD_TERMINAL_FORMAT.into(),
        revision: LINUX_WORKLOAD_TERMINAL_REVISION,
        association,
        request,
        release: ReleaseKnowledgeV3::NotReleased,
        native: None,
        outcome: NativeWorkloadOutcomeV1::SetupFailure,
        cleanup: CleanupV3 {
            state: CleanupStateV1::Complete,
            obligations,
        },
        output_delivery: OutputDeliveryStateV3::Unknown,
        failures,
    };
    report.cleanup = terminal.cleanup.clone();
    (report, terminal)
}

fn mark_outstanding(terminal: &mut LinuxWorkloadTerminalV1) {
    let mut obligations = BoundedVec::default();
    for (index, obligation) in terminal.cleanup.obligations.as_slice().iter().enumerate() {
        obligations
            .try_push(CleanupObligationV3 {
                resource: obligation.resource,
                settled: index != 0 && obligation.settled,
            })
            .unwrap();
    }
    terminal.cleanup.obligations = obligations;
}

#[test]
fn allocated_preparation_report_requires_exact_complete_original_recovery() {
    let (report, terminal) = fixture();
    let report = ResultV3::parse(&serde_json::to_vec(&report).unwrap()).unwrap();
    let terminal = LinuxWorkloadTerminalV1::parse(&serde_json::to_vec(&terminal).unwrap()).unwrap();
    assert!(matches!(
        report.runtime,
        RuntimeExecutionV3::PreparationFailed { .. }
    ));
    assert!(terminal.native.is_none());
    validate(
        &report,
        &terminal,
        &terminal.association,
        &terminal.request.request_sha256,
        (42, 0),
        Some(125),
    )
    .unwrap();
    for state in [CleanupStateV1::Unknown, CleanupStateV1::Incomplete] {
        let mut unsettled = terminal.clone();
        unsettled.cleanup.state = state;
        mark_outstanding(&mut unsettled);
        assert!(
            validate(
                &report,
                &unsettled,
                &terminal.association,
                &terminal.request.request_sha256,
                (42, 0),
                Some(125)
            )
            .is_err()
        );
    }
    let mut unsettled = terminal.clone();
    mark_outstanding(&mut unsettled);
    assert!(
        validate(
            &report,
            &unsettled,
            &terminal.association,
            &terminal.request.request_sha256,
            (42, 0),
            Some(125)
        )
        .is_err()
    );
}

#[test]
fn wrong_writer_wait_and_self_claimed_cleanup_cannot_pass_snapshot_rejection() {
    let (report, terminal) = fixture();
    for delivery in [
        DeliveryStateV3::Complete,
        DeliveryStateV3::Unknown,
        DeliveryStateV3::Incomplete,
        DeliveryStateV3::PreparedBy {
            writer_pid: NonZeroU32::new(43).unwrap(),
        },
    ] {
        let mut changed = report.clone();
        changed.delivery = delivery;
        assert!(
            validate(
                &changed,
                &terminal,
                &terminal.association,
                &terminal.request.request_sha256,
                (42, 0),
                Some(125)
            )
            .is_err()
        );
    }
    for status in [None, Some(0), Some(124), Some(130)] {
        assert!(
            validate(
                &report,
                &terminal,
                &terminal.association,
                &terminal.request.request_sha256,
                (42, 0),
                status
            )
            .is_err()
        );
    }
    assert!(
        validate(
            &report,
            &terminal,
            &terminal.association,
            &terminal.request.request_sha256,
            (0, 0),
            Some(125)
        )
        .is_err()
    );
    for state in [CleanupStateV1::Unknown, CleanupStateV1::Incomplete] {
        let mut changed = report.clone();
        changed.cleanup.state = state;
        assert!(
            validate(
                &changed,
                &terminal,
                &terminal.association,
                &terminal.request.request_sha256,
                (42, 0),
                Some(125)
            )
            .is_err()
        );
    }
    let mut changed = report.clone();
    changed
        .cleanup
        .obligations
        .try_push(CleanupObligationV3 {
            resource: CleanupResourceV3::Staging,
            settled: true,
        })
        .unwrap();
    assert!(
        validate(
            &changed,
            &terminal,
            &terminal.association,
            &terminal.request.request_sha256,
            (42, 0),
            Some(125)
        )
        .is_err()
    );
}

#[test]
fn foreign_terminal_request_provider_release_or_missing_digest_refusal_stays_fatal() {
    let (report, terminal) = fixture();
    let original = serde_json::to_value(&terminal).unwrap();
    for (pointer, value) in [
        ("/association/challenge", serde_json::json!(vec![3; 16])),
        (
            "/association/provider/runtime_manifest_sha256",
            serde_json::json!(String::from(DiagnosticSha256::from_bytes([9; 32]))),
        ),
        (
            "/request/request_sha256",
            serde_json::json!(String::from(DiagnosticSha256::from_bytes([9; 32]))),
        ),
        ("/release", serde_json::json!("released")),
        ("/outcome/kind", serde_json::json!("unknown")),
        ("/failures", serde_json::json!([])),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed: LinuxWorkloadTerminalV1 = serde_json::from_value(changed).unwrap();
        assert!(
            validate(
                &report,
                &changed,
                &terminal.association,
                &terminal.request.request_sha256,
                (42, 0),
                Some(125)
            )
            .is_err(),
            "{pointer}"
        );
    }
    let mut missing = report.clone();
    missing.workload_attempt = None;
    assert!(
        validate(
            &missing,
            &terminal,
            &terminal.association,
            &terminal.request.request_sha256,
            (42, 0),
            Some(125)
        )
        .is_err()
    );
    let mut wrong_request = report.clone();
    wrong_request.request.as_mut().unwrap().request_sha256 = DiagnosticSha256::from_bytes([9; 32]);
    assert!(
        validate(
            &wrong_request,
            &terminal,
            &terminal.association,
            &terminal.request.request_sha256,
            (42, 0),
            Some(125)
        )
        .is_err()
    );
}

#[test]
fn preallocation_refusal_uses_publication_and_conservative_shape_without_native_caller() {
    use memcordon_ci::linux_result_publication::{preallocation_report, publication_writer};
    use memcordon_core::workload_request::{WorkloadRejectionCodeV1, WorkloadRejectionV1};
    let (mut report, _) = fixture();
    report.cleanup = CleanupV3 {
        state: CleanupStateV1::Unknown,
        obligations: BoundedVec::default(),
    };
    report.workload_attempt = None;
    report.request_rejection = Some(WorkloadRejectionV1 {
        format: "memcordon.workload-rejection".into(),
        revision: 1,
        code: WorkloadRejectionCodeV1::UnsupportedRequirement,
        detail: BoundedText::new("initial loader environment is not supported").unwrap(),
    });
    let report = ResultV3::parse(&serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(report.workload_attempt.is_none());
    assert!(matches!(
        report.runtime,
        RuntimeExecutionV3::PreparationFailed { .. }
    ));
    assert!(report.outcome.native_termination.is_none());
    publication_writer(report.delivery, (42, 0)).unwrap();
    let request = report.request.as_ref().unwrap().request_sha256.clone();
    preallocation_report(&report, &request, (42, 0), Some(125)).unwrap();
    // No terminal or allocation observation is supplied here: this accepts
    // only the conservative report shape, never native cleanup success.
    assert_eq!(report.cleanup.state, CleanupStateV1::Unknown);
    for delivery in [
        DeliveryStateV3::Complete,
        DeliveryStateV3::Unknown,
        DeliveryStateV3::PreparedBy {
            writer_pid: NonZeroU32::new(43).unwrap(),
        },
    ] {
        assert!(publication_writer(delivery, (42, 0)).is_err());
    }
    assert!(publication_writer(report.delivery, (0, 0)).is_err());
    let mut changed = report.clone();
    changed.cleanup.state = CleanupStateV1::Complete;
    assert!(preallocation_report(&changed, &request, (42, 0), Some(125)).is_err());
    changed.cleanup.state = CleanupStateV1::Unknown;
    changed
        .cleanup
        .obligations
        .try_push(CleanupObligationV3 {
            resource: CleanupResourceV3::Staging,
            settled: true,
        })
        .unwrap();
    assert!(preallocation_report(&changed, &request, (42, 0), Some(125)).is_err());
    let mut associated = report.clone();
    associated.workload_attempt = Some(fixture().1.association);
    assert!(preallocation_report(&associated, &request, (42, 0), Some(125)).is_err());
    let mut no_rejection = report.clone();
    no_rejection.request_rejection = None;
    assert!(preallocation_report(&no_rejection, &request, (42, 0), Some(125)).is_err());
    assert!(preallocation_report(&report, &request, (42, 0), Some(0)).is_err());
}

#[test]
fn allocated_cleanup_is_an_exact_semantic_mapping_not_an_arbitrary_settled_list() {
    let (report, terminal) = fixture();
    let check = |report: &ResultV3, terminal: &LinuxWorkloadTerminalV1| {
        validate(
            report,
            terminal,
            &terminal.association,
            &terminal.request.request_sha256,
            (42, 0),
            Some(125),
        )
    };
    let mut reordered = terminal.clone();
    let mut obligations = terminal.cleanup.obligations.as_slice().to_vec();
    obligations.reverse();
    reordered.cleanup.obligations =
        serde_json::from_value(serde_json::to_value(obligations).unwrap()).unwrap();
    check(&report, &reordered).unwrap();
    for resource in [CleanupResourceV3::Target, CleanupResourceV3::Staging] {
        let mut changed = report.clone();
        changed
            .cleanup
            .obligations
            .try_push(CleanupObligationV3 {
                resource,
                settled: true,
            })
            .unwrap();
        assert!(check(&changed, &terminal).is_err());
    }
    let mut missing = report.clone();
    missing.cleanup.obligations = serde_json::from_value(
        serde_json::to_value(&report.cleanup.obligations.as_slice()[..3]).unwrap(),
    )
    .unwrap();
    assert!(check(&missing, &terminal).is_err());
    let mut wrong_request = report.clone();
    wrong_request.request.as_mut().unwrap().invocation_sha256 =
        DiagnosticSha256::from_bytes([8; 32]);
    assert!(check(&wrong_request, &terminal).is_err());
    let mut fallback = report.clone();
    fallback.cleanup = CleanupV3 {
        state: CleanupStateV1::Unknown,
        obligations: BoundedVec::default(),
    };
    assert!(check(&fallback, &terminal).is_err());
    let mut wrong_branch = report.clone();
    wrong_branch.request_rejection = Some(memcordon_core::workload_request::WorkloadRejectionV1 {
        format: "memcordon.workload-rejection".into(),
        revision: 1,
        code: memcordon_core::workload_request::WorkloadRejectionCodeV1::UnsupportedRequirement,
        detail: BoundedText::new("initial loader environment").unwrap(),
    });
    assert!(check(&wrong_branch, &terminal).is_err());
    let mut native_report = report.clone();
    native_report.outcome.native_termination =
        Some(memcordon_core::ChildTermination::ExitCode { code: 0 });
    assert!(check(&native_report, &terminal).is_err());
    let mut released = report.clone();
    released.release = ReleaseKnowledgeV3::Released;
    assert!(check(&released, &terminal).is_err());
    let mut profile = report.clone();
    profile.runtime = RuntimeExecutionV3::PreparationFailed {
        profile: BoundedText::new("another-profile").unwrap(),
    };
    assert!(check(&profile, &terminal).is_err());
}
