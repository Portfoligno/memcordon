//! Partial independent policy-branch join. This binds protected four-branch
//! transcript claims to five separate loss-free kernel intervals. It does
//! not authenticate the source of fixture requests or the frozen snapshot;
//! those joins remain mandatory before candidate qualification.

use std::collections::BTreeSet;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_branch_v1::PolicyFourBranchTranscriptV1;

use crate::private_kernel_observer::VerifiedNoAllocationIntervalV1;
use crate::{CiError, Result};

pub(crate) struct PartialPolicyKernelJoinV1 {
    positive_capture_sha256: DiagnosticSha256,
    negative_capture_sha256: [DiagnosticSha256; 4],
}

impl PartialPolicyKernelJoinV1 {
    pub(crate) fn positive_capture_sha256(&self) -> &DiagnosticSha256 {
        &self.positive_capture_sha256
    }
    pub(crate) fn negative_capture_sha256(&self) -> &[DiagnosticSha256; 4] {
        &self.negative_capture_sha256
    }
}

/// Expected identities are sourced from protected collector intent, not
/// candidate-authored C or the transcript itself. A positive interval and
/// four *different* negative intervals are all required.
pub(crate) fn join_policy_kernel_intervals(
    transcript: &PolicyFourBranchTranscriptV1,
    challenge_sha256: &DiagnosticSha256,
    accepted_request_sha256: &DiagnosticSha256,
    registry_sha256: &DiagnosticSha256,
    caller_sha256: &DiagnosticSha256,
    positive_key: &DiagnosticSha256,
    negative_keys: &[DiagnosticSha256; 4],
    positive: &VerifiedNoAllocationIntervalV1,
    negatives: [&VerifiedNoAllocationIntervalV1; 4],
) -> Result<PartialPolicyKernelJoinV1> {
    transcript
        .validate_structure()
        .map_err(|error| CiError::Message(error.into()))?;
    if &transcript.challenge_sha256 != challenge_sha256
        || &transcript.accepted_control_request_sha256 != accepted_request_sha256
        || &transcript.accepted_control_registry_sha256 != registry_sha256
        || &transcript.authenticated_caller_sha256 != caller_sha256
        || positive.result_key() != positive_key
    {
        return Err(CiError::Message("policy independent origin differs".into()));
    }
    let mut keys = BTreeSet::new();
    let mut captures = BTreeSet::new();
    keys.insert(String::from(positive_key.clone()));
    captures.insert(String::from(positive.capture_sha256().clone()));
    for (index, ((claim, key), interval)) in transcript
        .rejected
        .iter()
        .zip(negative_keys)
        .zip(negatives)
        .enumerate()
    {
        if interval.result_key() != key
            || &claim.independent_interval_sha256 != interval.capture_sha256()
            || !keys.insert(String::from(key.clone()))
            || !captures.insert(String::from(interval.capture_sha256().clone()))
            || claim.exact_request_sha256 == *accepted_request_sha256
        {
            return Err(CiError::Message(format!(
                "policy branch {index} independent interval differs"
            )));
        }
    }
    Ok(PartialPolicyKernelJoinV1 {
        positive_capture_sha256: positive.capture_sha256().clone(),
        negative_capture_sha256: negatives.map(|interval| interval.capture_sha256().clone()),
    })
}
