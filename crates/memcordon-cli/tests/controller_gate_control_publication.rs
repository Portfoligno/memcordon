#[path = "../src/bin/consumer_readiness_windows/controller_gate_control_publication.rs"]
mod publication;
use std::io::{self, Write};

#[test]
fn original_failure_is_bounded_and_flushed_before_a_permit_exists() {
    let original = io::Error::from_raw_os_error(5);
    let mut bytes = Vec::new();
    let _permit=publication::publish(&original,&serde_json::json!({"case":"envelope","name_sha256":"bound-name","challenge_sha256":"bound-challenge"}),&mut bytes).unwrap();
    assert!(bytes.len() < 2048);
    let record: serde_json::Value = serde_json::from_slice(
        bytes
            .strip_prefix(b"original-gate-failure-before-control ")
            .unwrap()
            .strip_suffix(b"\n")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(record["original_raw_os_error"], 5);
    assert_eq!(record["desired_access"], 0x0010_0000);
    assert_eq!(record["control"], "pending");
    assert_eq!(original.raw_os_error(), Some(5));
}

#[test]
fn write_flush_or_extent_failure_never_issues_a_permit_or_replaces_original_error() {
    struct Sink {
        remaining: usize,
        fail_flush: bool,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let count = bytes.len().min(self.remaining);
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            }
        }
    }
    let original = io::Error::from_raw_os_error(5);
    for mut sink in [
        Sink {
            remaining: 0,
            fail_flush: false,
        },
        Sink {
            remaining: 32,
            fail_flush: false,
        },
        Sink {
            remaining: usize::MAX,
            fail_flush: true,
        },
    ] {
        assert!(
            publication::publish(
                &original,
                &serde_json::json!({"case":"envelope"}),
                &mut sink
            )
            .is_err()
        );
        assert_eq!(original.raw_os_error(), Some(5));
    }
    let mut writer = Vec::new();
    assert!(
        publication::publish(
            &original,
            &serde_json::json!(vec![0u8; 4 * 1024]),
            &mut writer
        )
        .is_err()
    );
    assert!(writer.is_empty());
}
