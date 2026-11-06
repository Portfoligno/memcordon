#[path = "../src/windows_private_peer_debt.rs"]
mod debt;

use debt::PeerDebt;
use memcordon_platform::test_support::ProcessIdentity;

#[test]
fn spawn_uncertainty_survives_missing_publication_and_rejected_admission() {
    let peer = ProcessIdentity { pid: 10, birth: 20 };
    let mut debt = PeerDebt::default();
    debt.note_spawn();
    assert!(debt.release_barrier().is_err());
    assert!(debt.require_admitted(peer).is_err());
    assert!(debt.release_barrier().is_err());
    debt.begin_admission().unwrap();
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
    debt.note_spawn();
    debt.begin_admission().unwrap();
    debt.admitted(peer).unwrap();
    debt.note_spawn();
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
        debt.note_spawn();
        debt.begin_metadata().unwrap();
        debt.record_metadata(ordinal);
        assert!(debt.begin_metadata().is_err());
        assert!(debt.release_barrier().is_err());
    }
    let mut oversized = PeerDebt::default();
    oversized.begin_metadata().unwrap();
    oversized.record_metadata(max + 1);
    assert!(oversized.release_barrier().is_err());
}
