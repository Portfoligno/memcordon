use memcordon_ci::CiError;
use memcordon_ci::linux_relay_sample::read_native_text;
use memcordon_ci::linux_relay_sample::{WriteSample, combine};

#[test]
fn native_read_is_bounded_and_preserves_read_failures() {
    use std::io::{Cursor, Read};
    let mut exact = Cursor::new(vec![b'x'; 4096]);
    assert_eq!(read_native_text(&mut exact).unwrap().len(), 4096);
    assert_eq!(exact.position(), 4096);
    let mut oversized = Cursor::new(vec![b'x'; 8192]);
    assert!(read_native_text(&mut oversized).is_err());
    assert_eq!(oversized.position(), 4097);
    let invalid = read_native_text(Cursor::new([0xff])).unwrap_err();
    assert_eq!(invalid.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        invalid
            .get_ref()
            .unwrap()
            .is::<std::string::FromUtf8Error>()
    );
    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(5))
        }
    }
    let original = std::io::Error::from_raw_os_error(5);
    let failed = read_native_text(Failed).unwrap_err();
    assert_eq!(failed.raw_os_error(), original.raw_os_error());
    assert_eq!(failed.kind(), original.kind());
}

#[test]
fn exact_native_write_and_each_pressure_condition_are_required() {
    let sample = WriteSample::parse("64 0x2 0x1234 0x100 0x0\n", " pipe_write\n");
    assert_eq!(
        (sample.number, sample.descriptor, sample.length),
        (Some(64), Some(2), Some(256))
    );
    assert!(sample.matches(2, 8192, 8192, 64));
    assert!(sample.matches(2, 4097, 8192, 64));
    for (descriptor, queued, capacity, number) in [
        (1, 8192, 8192, 64),
        (2, 0, 8192, 64),
        (2, 8193, 8192, 64),
        (2, 4096, 8192, 64),
        (2, 8192, 8192, 1),
        (2, u64::MAX, 1, 64),
    ] {
        assert!(!sample.matches(descriptor, queued, capacity, number));
        assert!(
            sample
                .predicates(descriptor, queued, capacity, number)
                .as_object()
                .unwrap()
                .values()
                .any(|value| value == false)
        );
    }
    let predicates = sample.predicates(2, 8192, 8192, 64);
    assert_eq!(predicates.as_object().unwrap().len(), 7);
    assert!(
        predicates
            .as_object()
            .unwrap()
            .values()
            .all(|value| value == true)
    );
}

#[test]
fn malformed_fields_and_kernel_aliases_never_match() {
    for raw in [
        "running",
        "",
        "64 2 0x1234 256",
        "64 0x2 0x1234",
        "64 0x2 0x1234 0x101",
        "0x40 0x2 0x1234 0x100",
        "64 0x10000000000000000 0x0 0x100",
    ] {
        assert!(
            !WriteSample::parse(raw, "pipe_write").matches(2, 8192, 8192, 64),
            "{raw}"
        );
    }
    for channel in [
        "fifo_pipe_write",
        "pipe_write_suffix",
        "anon_pipe_write_suffix",
        "prefixpipe_write",
        "pipe_write anon_pipe_write",
        "running",
        "",
        "0",
    ] {
        assert!(!WriteSample::parse("64 0x2 0x0 0x100", channel).matches(2, 8192, 8192, 64));
    }
    assert_eq!(WriteSample::parse("-1", "0").number, Some(-1));
}

#[test]
fn supported_native_symbols_preserve_every_other_pressure_condition() {
    for (number, raw) in [(64, "64 0x1 0x1234 0x100"), (1, "1 0x1 0x1234 0x100")] {
        for channel in ["pipe_write", "anon_pipe_write"] {
            let sample = WriteSample::parse(raw, channel);
            assert!(sample.matches(1, 65536, 65536, number));
            assert_eq!(sample.wait_channel, channel);
            assert!(!sample.wait_channel_truncated);
            assert_eq!(
                sample.predicates(1, 65536, 65536, number)["supported_pipe_writer"],
                true
            );
            for (fd, queued, capacity, syscall) in [
                (2, 65536, 65536, number),
                (1, 0, 65536, number),
                (1, 65537, 65536, number),
                (1, 61440, 65536, number),
                (1, 65536, 65536, number + 1),
            ] {
                assert!(!sample.matches(fd, queued, capacity, syscall));
            }
            for count in ["0xff", "bad"] {
                let wrong = format!("{number} 0x1 0x1234 {count}");
                assert!(!WriteSample::parse(&wrong, channel).matches(1, 65536, 65536, number));
            }
            let padded = format!(" \n{channel}\t");
            assert!(WriteSample::parse(raw, &padded).matches(1, 65536, 65536, number));
            let overlong = format!("{channel}{}", "x".repeat(256));
            let sample = WriteSample::parse(raw, &overlong);
            assert!(sample.wait_channel_truncated);
            assert!(!sample.matches(1, 65536, 65536, number));
        }
    }
}

#[test]
fn bounded_rendering_does_not_change_full_observation_classification() {
    let raw = format!("64 0x2 0x0 0x100 {}", "界".repeat(200));
    let channel = format!("pipe_write{}", "界".repeat(200));
    let sample = WriteSample::parse(&raw, &channel);
    assert!(sample.raw_syscall.len() <= 128 && sample.wait_channel.len() <= 128);
    assert!(sample.raw_syscall_truncated && sample.wait_channel_truncated);
    assert!(!sample.matches(2, 8192, 8192, 64));
    let sample = WriteSample::parse(&raw, "pipe_write");
    assert!(sample.matches(2, 8192, 8192, 64));
    assert!(!sample.wait_channel_truncated);
    assert!(serde_json::to_string(&sample).unwrap().len() < 1200);
}

#[test]
fn typed_primary_and_multiple_cleanup_errors_keep_their_order() {
    let cleanup = combine(
        Err(CiError::Io(std::io::Error::from_raw_os_error(2))),
        Err(CiError::Cancelled("target resume".into())),
    );
    let error = combine(Err(CiError::NotStartedAfterFailure), cleanup).unwrap_err();
    let CiError::LaneFailures { primary, secondary } = error else {
        panic!("primary envelope lost")
    };
    assert!(matches!(*primary, CiError::NotStartedAfterFailure));
    let CiError::LaneFailures { primary, secondary } = *secondary else {
        panic!("cleanup envelope lost")
    };
    assert!(matches!(*primary,CiError::Io(ref error) if error.raw_os_error()==Some(2)));
    assert!(matches!(*secondary,CiError::Cancelled(ref value) if value=="target resume"));
    assert!(combine(Ok(()), Ok(())).is_ok());
    assert!(matches!(
        combine(Ok(()), Err(CiError::NotStartedAfterFailure)),
        Err(CiError::NotStartedAfterFailure)
    ));
    assert!(matches!(
        combine(Err(CiError::NotStartedAfterFailure), Ok(())),
        Err(CiError::NotStartedAfterFailure)
    ));
}
