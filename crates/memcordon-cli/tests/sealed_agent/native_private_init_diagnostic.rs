use super::channel;
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
