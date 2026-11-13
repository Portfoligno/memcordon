#[path = "../src/bin/consumer_readiness_windows/peer_retirement.rs"]
mod retirement;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
struct Owner(Arc<AtomicUsize>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn only_native_exit_proof_releases_the_original_owner_regardless_of_kill_result() {
    for (kill_ok, wait) in [(true, 0), (false, 0), (true, 1), (false, 2)] {
        let dropped = Arc::new(AtomicUsize::new(0));
        let original = Owner(Arc::clone(&dropped));
        let result = retirement::settle(
            original,
            io::Error::from_raw_os_error(5),
            Instant::now(),
            |_| {
                if kill_ok {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(6))
                }
            },
            |_| match wait {
                0 => Ok(true),
                1 => Ok(false),
                _ => Err(io::Error::from_raw_os_error(87)),
            },
        );
        match result {
            retirement::Outcome::Retired(error) => {
                assert_eq!(wait, 0);
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
                assert!(error.to_string().contains("5"));
                if !kill_ok {
                    assert!(error.to_string().contains("6"));
                }
            }
            retirement::Outcome::Unsettled { owner, error } => {
                assert_ne!(wait, 0);
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                assert!(error.to_string().contains("5"));
                drop(owner);
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
            }
        }
    }
}
