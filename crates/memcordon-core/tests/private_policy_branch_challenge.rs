use std::collections::BTreeSet;

use memcordon_core::private_release_branch_v1::{
    PolicyOperationBranchV1, policy_branch_challenge_v1,
};

#[test]
fn five_policy_branches_have_distinct_challenges_and_reject_zero_base() {
    let base = [0x51; 32];
    let mut challenges = BTreeSet::new();
    for branch in PolicyOperationBranchV1::ALL {
        let challenge = policy_branch_challenge_v1(&base, branch).unwrap();
        assert_ne!(challenge, base);
        assert_ne!(challenge, [0; 32]);
        assert!(challenges.insert(challenge));
    }
    assert_eq!(challenges.len(), 5);
    assert!(
        policy_branch_challenge_v1(&[0; 32], PolicyOperationBranchV1::AcceptedControl).is_err()
    );
}
