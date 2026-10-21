#![deny(unsafe_code, dead_code)]

#[path = "../src/release/linux_owner_cutoffs.rs"]
mod owner_cutoffs;

use std::time::{Duration, Instant};

#[test]
fn native_owner_authority_retains_exact_original_cutoffs() {
    let work = Instant::now();
    let cleanup = work + Duration::from_secs(1);
    let mut original_work = None;
    let mut original_cleanup = None;
    owner_cutoffs::bind(&mut original_work, &mut original_cleanup, work, cleanup).unwrap();
    owner_cutoffs::bind(&mut original_work, &mut original_cleanup, work, cleanup).unwrap();
    assert_eq!(
        (original_work, original_cleanup),
        (Some(work), Some(cleanup))
    );
}

#[test]
fn renewed_work_or_cleanup_authority_is_rejected_without_mutation() {
    let work = Instant::now();
    let cleanup = work + Duration::from_secs(2);
    for (requested_work, requested_cleanup) in [
        (work + Duration::from_secs(1), cleanup),
        (work, cleanup + Duration::from_secs(1)),
    ] {
        let mut original_work = Some(work);
        let mut original_cleanup = Some(cleanup);
        assert!(
            owner_cutoffs::bind(
                &mut original_work,
                &mut original_cleanup,
                requested_work,
                requested_cleanup,
            )
            .is_err()
        );
        assert_eq!(
            (original_work, original_cleanup),
            (Some(work), Some(cleanup))
        );
    }
}

#[test]
fn invalid_cutoff_order_cannot_create_partial_authority() {
    let work = Instant::now();
    for cleanup in [work, work - Duration::from_secs(1)] {
        let mut original_work = None;
        let mut original_cleanup = None;
        assert!(
            owner_cutoffs::bind(&mut original_work, &mut original_cleanup, work, cleanup).is_err()
        );
        assert_eq!((original_work, original_cleanup), (None, None));
    }
}

#[test]
fn incomplete_authority_cannot_be_reconstructed_from_a_later_context() {
    let work = Instant::now();
    let cleanup = work + Duration::from_secs(1);
    for originals in [(Some(work), None), (None, Some(cleanup))] {
        let (mut original_work, mut original_cleanup) = originals;
        assert!(
            owner_cutoffs::bind(&mut original_work, &mut original_cleanup, work, cleanup).is_err()
        );
        assert_eq!((original_work, original_cleanup), originals);
    }
}
