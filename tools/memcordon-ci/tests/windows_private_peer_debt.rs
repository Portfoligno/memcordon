#[path = "../src/windows_private_peer_debt.rs"]
mod debt;

use debt::PeerDebt;
use memcordon_platform::test_support::ProcessIdentity;
use std::time::{Duration, Instant};

const GRANT: [u8; 32] = [7; 32];

fn complete_grant(debt: &mut PeerDebt) {
    let completed = Instant::now();
    debt.complete_grant(GRANT, completed, completed + Duration::from_secs(1))
        .unwrap();
}

#[test]
fn spawn_uncertainty_survives_missing_publication_and_rejected_admission() {
    let peer = ProcessIdentity { pid: 10, birth: 20 };
    let mut debt = PeerDebt::default();
    debt.begin_grant(GRANT).unwrap();
    assert!(debt.release_barrier().is_err());
    assert!(debt.require_admitted(peer).is_err());
    assert!(debt.release_barrier().is_err());
    assert!(debt.begin_admission().is_err());
    // A partial native transfer or failed identity query leaves the barrier.
    debt.record_metadata(1);
    assert!(debt.release_barrier().is_err());
    assert!(debt.begin_admission().is_err());
    assert!(debt.release_barrier().is_err());
    let mut out_of_order = PeerDebt::default();
    assert!(out_of_order.admitted(peer).is_err());
    assert!(out_of_order.release_barrier().is_err());
}

#[test]
fn exact_admission_is_required_before_publication_and_replay_recharges_debt() {
    let peer = ProcessIdentity { pid: 10, birth: 20 };
    let mut debt = PeerDebt::default();
    debt.begin_grant(GRANT).unwrap();
    complete_grant(&mut debt);
    debt.begin_admission().unwrap();
    debt.admitted(peer).unwrap();
    debt.require_admitted(peer).unwrap();
    debt.release_barrier().unwrap(); // native owners STILL must prove exit.
    assert!(
        debt.require_admitted(ProcessIdentity { birth: 21, ..peer })
            .is_err()
    );
    assert!(debt.release_barrier().is_err());
    assert!(debt.require_admitted(peer).is_err());
    debt.mark_unknown();
    assert!(debt.release_barrier().is_err());
}

#[test]
fn every_partial_metadata_ordinal_is_one_shot_and_never_erases_spawn_debt() {
    let max = memcordon_platform::windows_private_fixture_binding::MAX_DIRECTORY_REFERENCES as u32;
    for ordinal in 0..=max {
        let mut debt = PeerDebt::default();
        debt.begin_metadata().unwrap();
        debt.record_metadata(ordinal);
        debt.begin_grant(GRANT).unwrap();
        assert!(debt.begin_metadata().is_err());
        assert!(debt.release_barrier().is_err());
    }
    let mut oversized = PeerDebt::default();
    oversized.begin_metadata().unwrap();
    oversized.record_metadata(max + 1);
    assert!(oversized.release_barrier().is_err());
}

#[test]
fn job_proof_can_retire_only_one_completed_grant_with_zero_peer_admission() {
    let mut debt = PeerDebt::default();
    debt.release_barrier().unwrap();
    debt.begin_metadata().unwrap(); // The original root's initial START transfer is allowed.
    debt.record_metadata(3);
    debt.begin_grant(GRANT).unwrap();
    complete_grant(&mut debt);
    assert!(debt.release_barrier().is_err());
    debt.require_unadmitted_grant(GRANT).unwrap();
    debt.settle_extinct_job(GRANT).unwrap();
    debt.release_barrier().unwrap();
    assert!(debt.begin_grant(GRANT).is_err());
    assert!(debt.release_barrier().is_err());

    for transition in 0..7 {
        let mut denied = PeerDebt::default();
        denied.begin_grant(GRANT).unwrap();
        if (1..6).contains(&transition) {
            complete_grant(&mut denied);
        }
        match transition {
            0 => {} // A failed or partial write never completed authorization.
            1 => assert!(denied.begin_grant(GRANT).is_err()),
            2 => assert!(denied.settle_extinct_job([8; 32]).is_err()),
            3 => denied.begin_admission().unwrap(),
            4 => denied.mark_unknown(),
            5 => assert!(denied.begin_metadata().is_err()),
            6 => {
                let cutoff = Instant::now();
                assert!(denied.complete_grant(GRANT, cutoff, cutoff).is_err());
                assert!(
                    denied
                        .complete_grant(GRANT, cutoff, cutoff + Duration::from_secs(1))
                        .is_err()
                );
            }
            _ => unreachable!(),
        }
        assert!(denied.settle_extinct_job(GRANT).is_err(), "{transition}");
        assert!(denied.release_barrier().is_err(), "{transition}");
    }
}
