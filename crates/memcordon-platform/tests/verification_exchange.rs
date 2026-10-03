#![cfg(unix)]

#[path = "../src/sealed/verification_exchange.rs"]
mod verification_exchange;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use verification_exchange::{DeadlineStream, VERIFIED_EXCHANGE_BUDGET, remaining_budget};

#[test]
fn verification_budget_includes_registry_and_fresh_validation() {
    assert_eq!(VERIFIED_EXCHANGE_BUDGET, Duration::from_secs(60));
    let start = Instant::now();
    let deadline = start + VERIFIED_EXCHANGE_BUDGET;
    assert_eq!(
        remaining_budget(deadline, start).unwrap(),
        VERIFIED_EXCHANGE_BUDGET
    );
    assert_eq!(
        remaining_budget(deadline, start + Duration::from_secs(30)).unwrap(),
        Duration::from_secs(30)
    );
    assert!(remaining_budget(deadline, deadline).is_err());
    assert!(remaining_budget(deadline, deadline + Duration::from_secs(1)).is_err());
    assert_eq!(
        remaining_budget(deadline, deadline - Duration::from_nanos(1)).unwrap(),
        Duration::from_nanos(1)
    );
}

#[test]
fn partial_reads_never_renew_the_exchange_deadline() {
    let (mut client, mut provider) = UnixStream::pair().unwrap();
    provider.write_all(b"AB").unwrap();
    let mut byte = [0];
    {
        let mut bounded = DeadlineStream::new(&mut client, VERIFIED_EXCHANGE_BUDGET).unwrap();
        let deadline = bounded.deadline();
        assert_eq!(
            bounded
                .test_read_at(&mut byte, deadline - Duration::from_secs(10))
                .unwrap(),
            1
        );
        assert_eq!(byte, *b"A");
        assert_eq!(
            bounded
                .test_read_at(&mut byte, deadline)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(bounded.deadline(), deadline);
    }
    client.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"B");
}

#[test]
fn request_write_and_response_read_share_one_deadline() {
    let (mut client, mut provider) = UnixStream::pair().unwrap();
    let mut bounded = DeadlineStream::new(&mut client, VERIFIED_EXCHANGE_BUDGET).unwrap();
    let deadline = bounded.deadline();
    assert_eq!(
        bounded
            .test_write_at(b"Q", deadline - Duration::from_secs(10))
            .unwrap(),
        1
    );
    let mut request = [0];
    provider.read_exact(&mut request).unwrap();
    assert_eq!(request, *b"Q");
    provider.write_all(b"R").unwrap();
    assert_eq!(
        bounded
            .test_read_at(&mut request, deadline)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(
        bounded.test_write_at(b"X", deadline).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(bounded.deadline(), deadline);
}

#[test]
fn ordinary_read_write_and_flush_use_the_bounded_adapter() {
    let (mut client, mut provider) = UnixStream::pair().unwrap();
    provider.write_all(b"receipt").unwrap();
    let mut bounded = DeadlineStream::new(&mut client, VERIFIED_EXCHANGE_BUDGET).unwrap();
    let mut receipt = [0; b"receipt".len()];
    bounded.read_exact(&mut receipt).unwrap();
    assert_eq!(&receipt, b"receipt");
    bounded.write_all(b"request").unwrap();
    bounded.flush().unwrap();
    let mut request = [0; b"request".len()];
    provider.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"request");
}

#[test]
fn zero_budget_never_performs_io_and_overflow_is_rejected() {
    let (mut client, mut provider) = UnixStream::pair().unwrap();
    provider.write_all(b"untouched").unwrap();
    let mut byte = [0];
    {
        let mut bounded = DeadlineStream::new(&mut client, Duration::ZERO).unwrap();
        assert_eq!(
            bounded.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            bounded.write(b"unsubmitted").unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            bounded.flush().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
    client.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"u");
    assert!(DeadlineStream::new(&mut client, Duration::MAX).is_err());
}
