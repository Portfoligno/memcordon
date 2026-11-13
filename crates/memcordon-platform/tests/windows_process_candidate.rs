#![cfg(feature = "test-support")]

use memcordon_platform::windows_process_candidate::{Acquisition, classify};

#[test]
fn unavailable_is_local_to_the_exact_unheld_query_candidate() {
    assert_eq!(
        classify(1236, true, false, false, Some(87)),
        Acquisition::CandidateUnavailable
    );
    for (pid, query_only, inherit, code) in [
        (0, true, false, Some(87)),
        (1236, false, false, Some(87)),
        (1236, true, true, Some(87)),
        (1236, true, false, Some(5)),
        (1236, true, false, Some(6)),
        (1236, true, false, None),
    ] {
        assert_eq!(
            classify(pid, query_only, inherit, false, code),
            Acquisition::Error
        );
    }
    let generic_invalid_input =
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a native code");
    assert_eq!(
        classify(
            1236,
            true,
            false,
            false,
            generic_invalid_input.raw_os_error()
        ),
        Acquisition::Error
    );
}

#[test]
fn acquired_handle_wins_over_stale_last_error_without_claiming_identity() {
    for code in [None, Some(5), Some(87)] {
        assert_eq!(classify(1236, true, false, true, code), Acquisition::Held);
        assert_eq!(classify(1236, false, false, true, code), Acquisition::Held);
    }
}
