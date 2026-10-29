use memcordon_core::execution_facts::{
    CleanupStateV1, OperationalToolV1, OutcomeKindV1, OutcomeV1,
};
use memcordon_core::result_v3::*;
use memcordon_core::*;
#[path = "support/windows_current_postauthorization.rs"]
mod fixture;

fn report() -> ResultV3 {
    let provider = fixture::rejection()
        .provider_failure
        .unwrap()
        .provider_binding;
    let accepted = WindowsWorkloadAcceptedV1 {
        format: "memcordon.windows-workload-accepted".into(),
        revision: 1,
        provider: provider.clone(),
        frontend: WindowsProcessIdentityV1 {
            process_id: 9431,
            creation_time_100ns: 0,
        },
        attempt_id: "ab".repeat(32),
        nonce: "native accepted nonce".into(),
        request_sha256: "cd".repeat(32),
        setup_deadline_millis: 30_000,
    };
    let cancellation = WindowsPreallocationCancellationV1 {
        format: "memcordon.windows-preallocation-cancellation".into(),
        revision: 1,
        accepted,
        signal: 2,
        primary_token_closed: true,
        frontend_process_handle_closed: true,
    };
    ResultV3 {
        format: "memcordon.result".into(),
        revision: 3,
        tool: OperationalToolV1 {
            name: "memcordon".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            os: "windows".into(),
            architecture: "aarch64".into(),
            runtime_features: vec!["windows-sealed-runtime".into()],
        },
        invocation: InvocationReport {
            syntax: "plus-budgets-v1".into(),
            budget_tokens: vec![],
            memory_token: None,
            deadline_token: None,
            argv: vec![NativeArgument {
                display: "fixture.exe".into(),
                raw: None,
            }],
        },
        request: None,
        provider: Some(provider.clone()),
        workload_attempt: None,
        release: ReleaseKnowledgeV3::NotReleased,
        outcome: OutcomeV1 {
            kind: OutcomeKindV1::Interrupted,
            native_termination: None,
            wrapper_status: 130,
        },
        cleanup: CleanupV3 {
            state: CleanupStateV1::Complete,
            obligations: Default::default(),
        },
        delivery: DeliveryStateV3::Unknown,
        output_delivery: None,
        diagnostics: Default::default(),
        provider_failure: None,
        request_rejection: None,
        windows_rejection: None,
        windows_attempt: Some(execution_facts::ProviderAttemptAssociationV1 {
            provider,
            attempt_id: DiagnosticSha256::try_from(
                BoundedText::new(&cancellation.accepted.attempt_id).unwrap(),
            )
            .unwrap(),
            request_sha256: DiagnosticSha256::try_from(
                BoundedText::new(&cancellation.accepted.request_sha256).unwrap(),
            )
            .unwrap(),
        }),
        runtime: RuntimeExecutionV3::WindowsPreallocationCancelled {
            profile: workload_request::WindowsCurrentTokenProfileV1::WindowsSealedCurrentToken,
            cancellation: Box::new(cancellation),
        },
    }
}

#[test]
fn actual_preallocation_cancellation_has_no_target_wait_or_invented_native_job() {
    let valid = report();
    valid.validate().unwrap();
    ResultV3::parse(&serde_json::to_vec(&valid).unwrap()).unwrap();
    let mut wait = valid.clone();
    wait.outcome.native_termination = Some(ChildTermination::WindowsStatus { status: 0 });
    assert!(wait.validate().is_err());
    let mut released = valid.clone();
    released.release = ReleaseKnowledgeV3::Released;
    assert!(released.validate().is_err());
    let mut job = valid.clone();
    job.cleanup
        .obligations
        .try_push(CleanupObligationV3 {
            resource: CleanupResourceV3::Job,
            settled: true,
        })
        .unwrap();
    assert!(job.validate().is_err());
    let mut wrong_provider = valid.clone();
    wrong_provider.provider.as_mut().unwrap().generation =
        BoundedText::new("foreign provider").unwrap();
    assert!(wrong_provider.validate().is_err());
    for field in 0..3 {
        let mut changed = valid.clone();
        let RuntimeExecutionV3::WindowsPreallocationCancelled { cancellation, .. } =
            &mut changed.runtime
        else {
            unreachable!()
        };
        match field {
            0 => cancellation.primary_token_closed = false,
            1 => cancellation.frontend_process_handle_closed = false,
            _ => cancellation.signal = 0,
        }
        assert!(changed.validate().is_err());
    }
}
