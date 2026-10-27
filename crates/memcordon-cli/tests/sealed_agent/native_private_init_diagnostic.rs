use super::{Phase, channel};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

#[test]
fn diagnostic_records_are_bounded_utf8_and_do_not_renew_or_retry() {
    let (provider, init) = channel().unwrap();
    let detail = format!("head-{}-native-errno=13", "界".repeat(1024));
    init.record(1, 1, &detail).unwrap();
    init.record(2, 1, "publication refused").unwrap();
    assert!(init.record(2, 1, "third attempt").is_err());
    let context = provider.context();
    assert!(context.contains("truncated=true"));
    assert!(context.contains("head-"));
    assert!(context.contains("native-errno=13"));
    assert!(context.contains("publication refused"));
    assert!(context.len() < 4096);
    assert!(provider.context().contains("record-absent"));
}

#[test]
fn diagnostic_closed_and_full_peers_fail_without_blocking_or_sigpipe() {
    let (provider, init) = channel().unwrap();
    drop(provider);
    assert!(init.record(1, 1, "original").is_err());
    let (provider, init) = channel().unwrap();
    let packet = [0_u8; 1024];
    let cutoff = Instant::now() + Duration::from_secs(1);
    loop {
        assert!(
            Instant::now() < cutoff,
            "nonblocking socket never reached its finite capacity"
        );
        // SAFETY: one bounded packet is sent nonblocking through the actual diagnostic endpoint.
        let count = unsafe {
            libc::send(
                init.as_fd().as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if count < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
    }
    assert!(init.record(1, 1, "original").is_err());
    drop(provider);
}

#[test]
fn malformed_and_oversized_diagnostics_are_never_interpreted_as_original_errors() {
    for packet in [b"not-a-record".to_vec(), vec![0_u8; 2048]] {
        let (provider, init) = channel().unwrap();
        // SAFETY: bounded hostile packets exercise the actual production nonblocking decoder.
        assert_eq!(
            unsafe {
                libc::send(
                    init.as_fd().as_raw_fd(),
                    packet.as_ptr().cast(),
                    packet.len(),
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            },
            packet.len() as isize
        );
        let context = provider.context();
        assert!(context.contains("malformed-or-oversized-record"));
        assert!(!context.contains("original-failure"));
    }
}

#[test]
fn dropping_init_owner_closes_its_diagnostic_endpoint() {
    let (provider, init) = channel().unwrap();
    drop(init);
    let mut byte = 0_u8;
    // SAFETY: read from the actual retained provider endpoint into one writable byte.
    assert_eq!(
        unsafe {
            libc::recv(
                provider.as_fd().as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        },
        0
    );
    assert!(provider.context().contains("record-absent"));
}

fn raw_packet(init: &super::Init, sequence: u8, dropped: u8, kind: u8, phase: u8, detail: &[u8]) {
    let mut bytes = super::HEADER.to_vec();
    bytes.extend_from_slice(&[sequence, dropped, kind, phase, 0]);
    bytes.extend_from_slice(detail);
    // SAFETY: a finite hostile packet goes only to this owned diagnostic peer.
    assert_eq!(
        unsafe {
            libc::send(
                init.as_fd().as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        },
        bytes.len() as isize
    );
}

#[test]
fn finite_progress_prefix_preserves_both_original_and_publication_failures() {
    let (provider, init) = channel().unwrap();
    for phase in [
        Phase::ChildClosureEntered,
        Phase::NetworkPrepareBefore,
        Phase::NetworkPrepareAfter,
        Phase::RootEnterBefore,
    ] {
        init.progress(phase);
    }
    init.record(1, 1, "controlled pre-root publication failure")
        .unwrap();
    init.record(2, 1, "authenticated publication unavailable")
        .unwrap();
    let context = provider.context();
    assert!(context.contains("progress seq=3 phase=RootEnterBefore"));
    assert!(!context.contains("phase=RootEnterAfter"));
    assert!(context.contains("original-failure phase=1"));
    assert!(context.contains("publication-failure phase=1"));
    assert!(
        context.find("original-failure").unwrap() < context.find("publication-failure").unwrap()
    );
}

#[test]
fn full_finite_phase_list_fits_without_displacing_failure_records() {
    let (provider, init) = channel().unwrap();
    for phase in [
        Phase::ChildClosureEntered,
        Phase::NetworkPrepareBefore,
        Phase::NetworkPrepareAfter,
        Phase::RootEnterBefore,
        Phase::RootEnterAfter,
        Phase::WorkingDirectoryBefore,
        Phase::WorkingDirectoryAfter,
        Phase::EntrypointBefore,
        Phase::EntrypointAfter,
        Phase::FilterAndIdentityBefore,
        Phase::FilterAndIdentityAfter,
        Phase::RootPublishBefore,
        Phase::RootPublishAfter,
        Phase::TargetForkBefore,
    ] {
        init.progress(phase);
    }
    init.record(1, 2, "target fork refusal").unwrap();
    init.record(2, 2, "publication refusal").unwrap();
    let context = provider.context();
    assert!(context.contains("phase=TargetForkBefore"));
    assert!(context.contains("original-failure phase=2"));
    assert!(context.contains("publication-failure phase=2"));
    assert!(!context.contains("malformed"));
    assert!(!context.contains("exceeded"));
}

#[test]
fn decoder_rejects_unknown_duplicate_backward_and_extra_packets() {
    for (phase, sequence, message) in [
        (u8::MAX, 1, "unknown-progress-phase"),
        (
            Phase::ChildClosureEntered as u8,
            1,
            "inconsistent-progress-record",
        ),
        (
            Phase::NetworkPrepareBefore as u8,
            0,
            "duplicate-backward-or-inconsistent-sequence",
        ),
    ] {
        let (provider, init) = channel().unwrap();
        init.progress(Phase::ChildClosureEntered);
        raw_packet(&init, sequence, 0, 3, phase, &[]);
        assert!(provider.context().contains(message));
    }
    let (provider, init) = channel().unwrap();
    for phase in 1..=Phase::TargetForkBefore as u8 {
        raw_packet(&init, phase - 1, 0, 3, phase, &[]);
    }
    raw_packet(&init, Phase::TargetForkBefore as u8, 0, 1, 1, b"original");
    raw_packet(
        &init,
        Phase::TargetForkBefore as u8 + 1,
        0,
        2,
        1,
        b"publication",
    );
    raw_packet(&init, super::MAX_RECORDS, 0, 2, 1, b"extra");
    assert!(provider.context().contains("extra-record-cap-exceeded"));
}

#[test]
fn missing_marker_and_reported_send_loss_remain_explicitly_incomplete() {
    let (provider, init) = channel().unwrap();
    raw_packet(&init, 1, 1, 3, Phase::NetworkPrepareBefore as u8, &[]);
    let context = provider.context();
    assert!(context.contains("missing-records=1,reported-send-failures=1"));
    assert!(context.contains("entered-marker-missing"));
    let (provider, init) = channel().unwrap();
    raw_packet(&init, 1, 0, 3, Phase::NetworkPrepareBefore as u8, &[]);
    assert!(provider.context().contains("inconsistent-sequence"));
}
