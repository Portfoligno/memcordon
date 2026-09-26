use memcordon_core::private_release_branch_v1::{
    HistoricalEpochTranscriptV1, PolicyBranchOutcomeV1, PolicyBranchV1,
    PolicyFourBranchTranscriptV1, RejectedPolicyBranchV1,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_registry_v2::AdmissionCodeV2;

fn digest(value: u8) -> memcordon_core::DiagnosticSha256 {
    hash_bytes(&[value])
}

#[test]
fn policy_requires_four_distinct_ordered_negative_requests() {
    let caller = digest(1);
    let branches = [
        PolicyBranchV1::WrongGrant,
        PolicyBranchV1::WrongProfile,
        PolicyBranchV1::UnapprovedChangedPortPlan,
        PolicyBranchV1::CommittedPortTamper,
    ];
    let mut transcript = PolicyFourBranchTranscriptV1 {
        schema_version: 1,
        challenge_sha256: digest(2),
        accepted_control_request_sha256: digest(3),
        accepted_control_registry_sha256: digest(4),
        authenticated_caller_sha256: caller.clone(),
        rejected: std::array::from_fn(|index| RejectedPolicyBranchV1 {
            branch: branches[index],
            exact_request_sha256: digest(index as u8 + 5),
            exact_registry_sha256: digest(4),
            authenticated_caller_sha256: caller.clone(),
            outcome: match branches[index] {
                PolicyBranchV1::WrongGrant => {
                    PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::ProfileNotAuthorized)
                }
                PolicyBranchV1::UnapprovedChangedPortPlan => {
                    PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::PlanNotApproved)
                }
                PolicyBranchV1::WrongProfile => {
                    PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::ProfileDigestMismatch)
                }
                PolicyBranchV1::CommittedPortTamper => PolicyBranchOutcomeV1::FrozenBindingMismatch,
            },
            independent_interval_sha256: digest(index as u8 + 9),
        }),
    };
    assert!(transcript.validate_structure().is_ok());
    transcript.rejected[3].exact_request_sha256 =
        transcript.rejected[2].exact_request_sha256.clone();
    assert!(transcript.validate_structure().is_err());
    transcript.rejected[3].exact_request_sha256 = digest(8);
    transcript.rejected[3].outcome =
        PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::ProfileNotAuthorized);
    assert!(transcript.validate_structure().is_err());
    transcript.rejected[3].outcome = PolicyBranchOutcomeV1::FrozenBindingMismatch;
    transcript.rejected.swap(2, 3);
    assert!(transcript.validate_structure().is_err());
}

#[test]
fn historical_epoch_requires_true_generation_change_and_original_request_replay() {
    let mut transcript = HistoricalEpochTranscriptV1 {
        schema_version: 1,
        challenge_sha256: digest(1),
        e0_installation_epoch_sha256: digest(2),
        e1_installation_epoch_sha256: digest(3),
        e0_accepted_request_sha256: digest(4),
        e0_accepted_result_sha256: digest(5),
        package_mutation_journal_sha256: digest(6),
        original_replay_request_sha256: digest(4),
        stale_rejection_sha256: digest(7),
        stale_interval_sha256: digest(8),
        fresh_e1_request_sha256: digest(9),
        fresh_e1_result_sha256: digest(10),
        caller_rejection_sha256: digest(11),
    };
    assert!(transcript.validate_structure().is_ok());
    transcript.e1_installation_epoch_sha256 = transcript.e0_installation_epoch_sha256.clone();
    assert!(transcript.validate_structure().is_err());
    transcript.e1_installation_epoch_sha256 = digest(3);
    transcript.original_replay_request_sha256 = digest(12);
    assert!(transcript.validate_structure().is_err());
}
