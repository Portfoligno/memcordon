use memcordon_ci::private_candidate_replay::candidate_policy_interval_identity_v1;
use memcordon_core::private_release_branch_v1::PolicyOperationBranchV1;
use std::collections::BTreeSet;

#[test]
fn policy_five_physical_identities_are_distinct_and_epoch_nonce_bound() {
    let nonce = "01".repeat(32);
    let other_nonce = "02".repeat(32);
    let challenge = [3; 32];
    let mut keys = BTreeSet::new();
    let mut intervals = BTreeSet::new();
    for branch in PolicyOperationBranchV1::ALL {
        let (key, id) =
            candidate_policy_interval_identity_v1(&nonce, 1, &challenge, branch).unwrap();
        assert!(keys.insert(*key.bytes()));
        assert!(intervals.insert(*id.bytes()));
        let (e0_key, e0_id) =
            candidate_policy_interval_identity_v1(&nonce, 0, &challenge, branch).unwrap();
        assert_eq!(key, e0_key);
        assert_ne!(id, e0_id);
        let (other_key, other_id) =
            candidate_policy_interval_identity_v1(&other_nonce, 1, &challenge, branch).unwrap();
        assert_eq!(key, other_key);
        assert_ne!(id, other_id);
        let (fresh_key, fresh_id) =
            candidate_policy_interval_identity_v1(&nonce, 1, &[4; 32], branch).unwrap();
        assert_ne!(key, fresh_key);
        assert_ne!(id, fresh_id);
    }
    assert_eq!(keys.len(), 5);
    assert_eq!(intervals.len(), 5);
}

#[test]
fn policy_identity_rejects_zero_noncanonical_or_truncated_nonce() {
    let branch = PolicyOperationBranchV1::AcceptedControl;
    for nonce in [
        "00".repeat(32),
        "A0".repeat(32),
        "01".repeat(31),
        "zz".repeat(32),
    ] {
        assert!(candidate_policy_interval_identity_v1(&nonce, 1, &[3; 32], branch).is_err());
    }
    assert!(candidate_policy_interval_identity_v1(&"01".repeat(32), 1, &[0; 32], branch).is_err());
}
