#![cfg(unix)]
#[path = "../src/bin/memcordon-sealed-agent/linux/private_relay_state.rs"]
mod state;
use state::{Endpoint, Lane, PollAction, WriteFailure};

#[test]
fn only_target_stdin_broken_pipe_retires_input() {
    assert_eq!(
        state::write_failure(Lane::Stdin, Some(libc::EPIPE)),
        WriteFailure::CloseInput
    );
    for lane in [Lane::Stdout, Lane::Stderr] {
        assert_eq!(
            state::write_failure(lane, Some(libc::EPIPE)),
            WriteFailure::Fatal
        );
    }
    for lane in [Lane::Stdin, Lane::Stdout, Lane::Stderr] {
        assert!(!lane.label().is_empty());
        for errno in [Some(libc::EAGAIN), Some(libc::EINTR)] {
            assert_eq!(state::write_failure(lane, errno), WriteFailure::Retry);
            assert!(state::retryable(errno));
        }
        for errno in [None, Some(libc::EIO), Some(libc::EBADF), Some(libc::ENOSPC)] {
            assert_eq!(state::write_failure(lane, errno), WriteFailure::Fatal);
            assert!(!state::retryable(errno));
        }
    }
    assert!(
        !state::retryable(Some(libc::EPIPE)),
        "read-side EPIPE is not input closure"
    );
}

#[test]
fn poll_errors_are_bound_to_the_owned_input_writer_and_invalidity_always_wins() {
    for lane in [Lane::Stdin, Lane::Stdout, Lane::Stderr] {
        for endpoint in [Endpoint::Source, Endpoint::Destination] {
            assert!(!endpoint.label().is_empty());
            let expected = if lane == Lane::Stdin && endpoint == Endpoint::Destination {
                PollAction::CloseInput
            } else {
                PollAction::FatalEndpoint
            };
            assert_eq!(state::poll_action(lane, endpoint, libc::POLLERR), expected);
            assert_eq!(
                state::poll_action(lane, endpoint, libc::POLLERR | libc::POLLHUP),
                expected
            );
            for revents in [libc::POLLNVAL, libc::POLLNVAL | libc::POLLERR] {
                assert_eq!(
                    state::poll_action(lane, endpoint, revents),
                    PollAction::InvalidDescriptor
                );
            }
            for revents in [0, libc::POLLIN, libc::POLLOUT, libc::POLLHUP] {
                assert_eq!(
                    state::poll_action(lane, endpoint, revents),
                    PollAction::Continue
                );
            }
        }
    }
}
