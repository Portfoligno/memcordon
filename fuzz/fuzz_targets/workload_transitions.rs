#![no_main]
//! Abstract evidence transitions only: no authenticated native handles are fuzz input.
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_contract::{Nonce128, reject_duplicate_json_keys};
use memcordon_core::workload_evidence::*;

fuzz_target!(|data: &[u8]| {
    if data.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
        || reject_duplicate_json_keys(data).is_err()
    {
        return;
    }
    let Ok(receipt) = serde_json::from_slice::<AttemptPolicyEnforcementV1>(data) else {
        return;
    };
    if !receipt.terminal_success() {
        return;
    }
    let AttemptPolicyEnforcementV1::Authorized {
        admission,
        before_authorization,
        ..
    } = receipt
    else {
        unreachable!()
    };
    // Every terminal fact remains required; successful admission never supplies it.
    for (preserved, closed) in [(false, false), (false, true), (true, false)] {
        assert!(
            AttemptPolicyEnforcementV1::retired(
                admission.as_ref().clone(),
                before_authorization.clone(),
                preserved,
                closed
            )
            .is_err()
        );
    }
    let mut restarted = admission.clone();
    let mut nonce = restarted.admission_nonce.0;
    nonce[0] ^= 1;
    restarted.admission_nonce = Nonce128(nonce);
    assert!(!before_authorization.matches_binding(&restarted));
    assert!(
        AttemptPolicyEnforcementV1::retired(*restarted, before_authorization, true, true).is_err()
    );
    let uncertain = AttemptPolicyEnforcementV1::AuthorizationUncertain {
        request: Some(admission.plan.request),
        failure: AdmissionAvailabilityFailure::TransportLost,
    };
    assert!(!uncertain.terminal_success());
    assert!(matches!(
        uncertain.resolution(),
        Some(WorkloadResolutionReportV1::Unavailable {
            authorization: AuthorizationKnowledge::Unknown,
            ..
        })
    ));
});
