#[path = "../src/bin/consumer_readiness_windows/controller_start.rs"]
mod start;
use start::{Binding, Receiver};
use std::io::{self, Cursor, Read, Write};

fn binding() -> Binding {
    Binding {
        challenge: vec![0, 0xff, b'R', 17],
        descriptor_sha256: start::descriptor_digest(b"{\"case\":\"envelope\"}\n"),
        pid: 9001,
        birth: 134_379_920_909_214_884,
    }
}
fn frame(binding: &Binding) -> Vec<u8> {
    let mut bytes = Vec::new();
    start::send(&mut bytes, binding, || Ok(())).unwrap();
    bytes
}
struct Split<R> {
    inner: R,
    maximum: usize,
}
impl<R: Read> Read for Split<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let size = out.len().min(self.maximum);
        self.inner.read(&mut out[..size])
    }
}

#[test]
fn exact_wire_and_split_reads_leave_following_binary_application_bytes_untouched() {
    let binding = binding();
    let bytes = frame(&binding);
    let mut expected = b"MCSTART\0".to_vec();
    expected.extend(1_u32.to_le_bytes());
    expected.extend(4_u32.to_le_bytes());
    expected.extend(binding.descriptor_sha256);
    expected.extend(9001_u32.to_le_bytes());
    expected.extend(134_379_920_909_214_884_u64.to_le_bytes());
    expected.extend([0, 255, b'R', 17]);
    assert_eq!(bytes, expected);
    let application = [0, 255, b'R', b'\n', 128];
    let mut stream = bytes;
    stream.extend(application);
    let mut reader = Split {
        inner: Cursor::new(stream),
        maximum: 3,
    };
    let mut receiver = Receiver::default();
    receiver.receive(&mut reader, &binding, || Ok(())).unwrap();
    assert_eq!(reader.inner.position(), expected.len() as u64);
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, application);
    let position = reader.inner.position();
    assert_eq!(
        receiver
            .receive(&mut reader, &binding, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(reader.inner.position(), position);
    assert_eq!(
        start::descriptor_digest(b""),
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ]
    );
    assert_ne!(
        start::descriptor_digest(b"{\"case\":\"envelope\"}"),
        binding.descriptor_sha256
    );
}

#[test]
fn cross_case_wrong_identity_unknown_version_and_invalid_extents_never_release() {
    let binding = binding();
    let bytes = frame(&binding);
    for offset in [0, 8, 12, 16, 48, 52, 60] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let mut receiver = Receiver::default();
        assert_eq!(
            receiver
                .receive(&mut Cursor::new(changed), &binding, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
            "offset={offset}"
        );
        assert!(
            receiver
                .receive(&mut Cursor::new(&bytes), &binding, || Ok(()))
                .is_err()
        );
    }
    let mut oversized = bytes.clone();
    oversized[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut reader = Cursor::new(oversized);
    assert!(
        Receiver::default()
            .receive(&mut reader, &binding, || Ok(()))
            .is_err()
    );
    assert_eq!(reader.position(), 60);
    for length in 0..bytes.len() {
        assert_eq!(
            Receiver::default()
                .receive(&mut Cursor::new(&bytes[..length]), &binding, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof,
            "length={length}"
        );
    }
    for invalid in [
        Binding {
            pid: 0,
            ..self::binding()
        },
        Binding {
            birth: 0,
            ..self::binding()
        },
        Binding {
            challenge: Vec::new(),
            ..self::binding()
        },
        Binding {
            challenge: vec![0; start::MAX_CHALLENGE + 1],
            ..self::binding()
        },
    ] {
        let mut destination = Vec::new();
        assert_eq!(
            start::send(&mut destination, &invalid, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(destination.is_empty());
    }
}

#[test]
fn exact_io_admission_deadlines_and_original_native_failures_are_retained() {
    let binding = binding();
    let bytes = frame(&binding);
    let mut reader = Cursor::new(&bytes);
    assert_eq!(
        Receiver::default()
            .receive(&mut reader, &binding, || Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original cutoff"
            )))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(reader.position(), 0);
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(109))
        }
    }
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(232))
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("failed writer must not flush")
        }
    }
    assert_eq!(
        Receiver::default()
            .receive(&mut Broken, &binding, || Ok(()))
            .unwrap_err()
            .raw_os_error(),
        Some(109)
    );
    assert_eq!(
        start::send(&mut Broken, &binding, || Ok(()))
            .unwrap_err()
            .raw_os_error(),
        Some(232)
    );
    let mut calls = 0;
    let mut partial = Split {
        inner: Cursor::new(&bytes),
        maximum: 1,
    };
    let result = Receiver::default().receive(&mut partial, &binding, || {
        calls += 1;
        if calls >= 2 {
            Err(io::Error::new(io::ErrorKind::TimedOut, "same cutoff"))
        } else {
            Ok(())
        }
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(partial.inner.position(), 1);
    struct Partial(Vec<u8>);
    impl Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend(&bytes[..bytes.len().min(2)]);
            Ok(bytes.len().min(2))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Partial(Vec::new());
    start::send(&mut output, &binding, || Ok(())).unwrap();
    assert_eq!(output.0, bytes);
}

#[test]
fn interrupted_native_io_retains_its_cause_at_cutoff_and_retries_only_while_live() {
    struct Interrupted<R> {
        inner: R,
        once: bool,
    }
    impl<R: Read> Read for Interrupted<R> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if !std::mem::replace(&mut self.once, true) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    io::Error::from_raw_os_error(995),
                ));
            }
            self.inner.read(bytes)
        }
    }
    let binding = binding();
    let bytes = frame(&binding);
    let mut reader = Interrupted {
        inner: Cursor::new(&bytes),
        once: false,
    };
    let mut checks = 0;
    let error = Receiver::default()
        .receive(&mut reader, &binding, || {
            checks += 1;
            if checks == 1 {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "retained cutoff observation",
                ))
            }
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(reader.inner.position(), 0);
    let primary = error
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(primary.kind(), io::ErrorKind::Interrupted);
    assert_eq!(
        primary
            .get_ref()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(995)
    );
    assert!(error.to_string().contains("retained cutoff observation"));
    let mut reader = Interrupted {
        inner: Cursor::new(&bytes),
        once: false,
    };
    Receiver::default()
        .receive(&mut reader, &binding, || Ok(()))
        .unwrap();
    assert_eq!(reader.inner.position(), bytes.len() as u64);
}
