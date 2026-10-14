//! Finite diagnostics from an already parsed mixed carrier, never acceptance.
use memcordon_core::result_v2::{MixedRuntimeOutcomeV2, OutstandingMixedRetirementV2};

pub fn refused_carrier_detail(outcome: &MixedRuntimeOutcomeV2) -> String {
    let (kind, metadata, retained): (&str, String, &OutstandingMixedRetirementV2) = match outcome {
        MixedRuntimeOutcomeV2::RejectedIngress {
            reason, allocation, ..
        } => ("rejected-ingress", format!("reason={reason:?}"), allocation),
        MixedRuntimeOutcomeV2::RejectedBeforeAuthorization {
            reason, allocation, ..
        } => (
            "rejected-before-authorization",
            format!("reason={reason:?}"),
            allocation,
        ),
        MixedRuntimeOutcomeV2::Indeterminate {
            attempt_id,
            retained_obligations,
            ..
        } => (
            "indeterminate",
            format!("attempt={:?}", attempt_id.as_str()),
            retained_obligations,
        ),
        MixedRuntimeOutcomeV2::Executed { .. } => return "outcome=executed".into(),
    };
    let obligations = retained.obligations.as_slice();
    let first = obligations.len().min(4);
    let last = obligations.len().saturating_sub(first).min(2);
    let mut detail = format!(
        "outcome={kind}; {metadata}; authorization={:?}; obligations={}; omitted={}",
        retained.authorization,
        obligations.len(),
        obligations.len() - first - last
    );
    for index in (0..first).chain(obligations.len() - last..obligations.len()) {
        // Each already validated wire obligation has at most 256 bytes. Debug
        // escaping preserves control-byte safety without exposing request data.
        detail.push_str(&format!(
            "; obligation[{index}]={:?}",
            obligations[index].as_str()
        ));
    }
    detail
}
