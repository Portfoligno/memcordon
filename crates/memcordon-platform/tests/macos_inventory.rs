#![cfg(all(target_os = "macos", feature = "test-support"))]

use memcordon_platform::test_support::macos_inventory_reconciliation as reconcile;

#[test]
fn pending_metric_query_is_answered_before_empty_inspector_retirement() {
    use memcordon_core::Metric;
    use memcordon_platform::test_support::{
        macos_empty_inventory_query_transition as empty,
        macos_nonempty_inventory_query_transition as nonempty,
    };
    for requested in [
        Some(Metric::Rss),
        Some(Metric::PhysicalFootprint),
        Some(Metric::Virtual),
        None,
    ] {
        let (answered, sample) = empty(requested, None, true);
        assert!(
            answered,
            "a queued metric query must settle on authoritative empty inventory"
        );
        assert_eq!(
            sample,
            Some(Ok(0)),
            "the prepared wire payload must contain zero usage"
        );
        assert!(
            !empty(requested, None, false).0,
            "late normal inventory cannot replace emergency authority"
        );
    }
    assert!(!nonempty(Some(Metric::Rss), None, false));
    assert!(!nonempty(Some(Metric::Rss), Some(Metric::Virtual), true));
    assert!(!nonempty(Some(Metric::Rss), Some(Metric::Rss), false));
    assert!(nonempty(Some(Metric::Rss), Some(Metric::Rss), true));
    assert!(nonempty(None, None, false));
}

#[test]
fn malformed_native_pid_listings_never_certify_absence() {
    use memcordon_platform::test_support::macos_pid_inventory_reply as decode;
    let width = i32::try_from(std::mem::size_of::<i32>()).unwrap();
    assert!(
        decode(1, vec![1, 2], width * 2, 0)
            .unwrap_err()
            .contains("saturated")
    );
    assert!(
        decode(1, vec![1, 2], width - 1, 0)
            .unwrap_err()
            .contains("byte count")
    );
    assert!(decode(1, vec![0, 0], 0, 0).is_err());
    for error in [libc::EPERM, libc::EINTR, libc::ESRCH] {
        assert!(
            decode(2, vec![0, 0], 0, error)
                .unwrap_err()
                .contains("failed")
        );
    }
    assert_eq!(decode(1, vec![42, 0], width, 0).unwrap(), vec![42]);
    assert!(decode(2, vec![0, 0], 0, 0).unwrap().is_empty());
}

#[test]
fn unresolved_known_identity_is_retained_even_after_root_exit() {
    let (result, known) = reconcile(&[(101, 4)], &[], &[101], &[101]);
    assert!(result.is_err());
    assert_eq!(known, vec![(101, 4)]);
}

#[test]
fn mutation_unknown_member_dropping_is_detected() {
    let observed = reconcile(&[(101, 4)], &[], &[101], &[101]);
    let accepts_observation = |result: &Result<Vec<i32>, String>, known: &[(i32, u64)]| {
        result.is_err() && known == [(101, 4)]
    };
    assert!(accepts_observation(&observed.0, &observed.1));
    // The historical lossy adapter converts unreadable metadata to absence.
    // Feed that deliberate mutant through the same independently expected facts.
    let dropped_member = (Ok(Vec::new()), Vec::new());
    assert!(!accepts_observation(&dropped_member.0, &dropped_member.1));
}

#[test]
fn unrelated_inaccessible_process_does_not_poison_scoped_absence() {
    let (result, known) = reconcile(&[], &[], &[999], &[100]);
    assert!(result.unwrap().is_empty());
    assert!(known.is_empty());
}

#[test]
fn unresolved_new_group_member_prevents_false_empty_inventory() {
    let (result, _) = reconcile(&[], &[], &[102], &[100, 102]);
    assert!(result.is_err());
}

#[test]
fn positively_observed_pid_replacement_discharges_only_old_identity() {
    let (result, known) = reconcile(&[(101, 4)], &[(101, 5, 1, 101, false)], &[], &[101]);
    assert!(result.unwrap().is_empty());
    assert!(known.is_empty());
}

#[test]
fn detached_child_survives_root_exit_and_group_change() {
    let (result, known) = reconcile(&[(101, 4)], &[(101, 4, 1, 101, false)], &[], &[101]);
    assert_eq!(result.unwrap(), vec![101]);
    assert_eq!(known, vec![(101, 4)]);
}

#[test]
fn new_confirmed_members_survive_a_concurrent_metadata_failure() {
    let (result, known) = reconcile(
        &[(101, 4)],
        &[(102, 5, 101, 100, false)],
        &[101],
        &[100, 101],
    );
    assert!(result.is_err());
    assert_eq!(known, vec![(101, 4), (102, 5)]);
}
