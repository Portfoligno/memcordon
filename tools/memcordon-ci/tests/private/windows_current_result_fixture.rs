use memcordon_core::execution_facts::{
    CleanupStateV1, OperationalToolV1, OutcomeKindV1, OutcomeV1, ProviderAttemptAssociationV1,
};
use memcordon_core::result_v3::*;
use memcordon_core::*;
#[path = "../../../../crates/memcordon-core/tests/support/windows_current_postauthorization.rs"]
mod native_fixture;

pub fn completed_loader_failure() -> ResultV3 {
    let rejection = native_fixture::rejection();
    let failure = rejection.provider_failure.as_ref().unwrap();
    let association = ProviderAttemptAssociationV1 {
        provider: failure.provider_binding.clone(),
        attempt_id: failure.attempt_id.clone(),
        request_sha256: failure.request_sha256.clone(),
    };
    let terminal = rejection.terminal_receipt().unwrap();
    let (_, _, BoundaryMechanismEvidence::WindowsJobObjectV3(native)) =
        terminal.execution().unwrap()
    else {
        panic!("current native fixture missing");
    };
    let mut native = native.as_ref().clone();
    native.frontend_provider_association = Some(association.clone());
    native.retirement = Some(Box::new(terminal.retirement_proof.clone()));
    native.frontend_delivery = Some(WindowsFrontendDeliveryV3 {
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        terminal_sha256: String::from(DiagnosticSha256::from_bytes([7; 32])),
        retired_sha256: String::from(DiagnosticSha256::from_bytes([8; 32])),
        terminal_validated: true,
        acknowledgement_observed: true,
    });
    let mut obligations = BoundedVec::default();
    for resource in [
        CleanupResourceV3::Target,
        CleanupResourceV3::Aggregate,
        CleanupResourceV3::Job,
        CleanupResourceV3::Guardian,
        CleanupResourceV3::Relays,
        CleanupResourceV3::Record,
    ] {
        obligations
            .try_push(CleanupObligationV3 {
                resource,
                settled: true,
            })
            .unwrap();
    }
    let result=ResultV3{format:"memcordon.result".into(),revision:3,tool:OperationalToolV1{name:"memcordon".into(),version:"0.5.8-dev".into(),os:"windows".into(),architecture:"aarch64".into(),runtime_features:vec!["windows-sealed-runtime".into()]},invocation:InvocationReport{syntax:"plus-budgets-v1".into(),budget_tokens:Vec::new(),memory_token:None,deadline_token:None,argv:Vec::new()},request:None,provider:Some(association.provider.clone()),workload_attempt:None,release:ReleaseKnowledgeV3::Released,outcome:OutcomeV1{kind:OutcomeKindV1::Completed,native_termination:Some(ChildTermination::WindowsStatus{status:0xC0000142}),wrapper_status:125},cleanup:CleanupV3{state:CleanupStateV1::Complete,obligations},delivery:DeliveryStateV3::Complete,output_delivery:None,diagnostics:BoundedVec::default(),provider_failure:None,request_rejection:None,windows_rejection:None,windows_attempt:Some(association),runtime:RuntimeExecutionV3::WindowsSealed{profile:memcordon_core::workload_request::WindowsCurrentTokenProfileV1::WindowsSealedCurrentToken,native:Box::new(native)}};
    result.validate().unwrap();
    result
}

pub fn launch_failure() -> ResultV3 {
    let mut result = completed_loader_failure();
    result.release = ReleaseKnowledgeV3::NotReleased;
    result.outcome.kind = OutcomeKindV1::LaunchFailure;
    result.outcome.native_termination = None;
    result.windows_attempt = None;
    result.runtime = RuntimeExecutionV3::PreparationFailed {
        profile: BoundedText::new("windows-sealed-current-token-v1").unwrap(),
    };
    result.cleanup.obligations = BoundedVec::default();
    let mut rejection = native_fixture::rejection();
    rejection.code = "MCSPAWN-FAILED".into();
    rejection.detail = "suspended target loader failed with status 0xC0000142".into();
    rejection.phase = BoundarySetupPhase::TargetCreation;
    rejection.target_created = false;
    rejection.target_released = false;
    rejection.provider_failure = None;
    rejection.disposition = WindowsProviderRejectionDispositionV3::Preauthorization {
        terminal_ack_required: false,
    };
    assert!(rejection.is_consistent());
    result.windows_rejection = Some(Box::new(rejection));
    result.validate().unwrap();
    result
}
