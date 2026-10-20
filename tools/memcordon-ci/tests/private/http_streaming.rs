use super::copy_bounded_body;
use std::{
    io::{self, Cursor, Read},
    time::{Duration, Instant},
};

fn cutoff() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn inclusive_stream_bound_never_retains_the_overrun_byte() {
    for bytes in [b"".as_slice(), b"abc".as_slice()] {
        let mut file = tempfile::tempfile().unwrap();
        assert_eq!(
            copy_bounded_body(
                &mut Cursor::new(bytes),
                &mut file,
                bytes.len() as u64,
                cutoff()
            )
            .unwrap(),
            bytes.len() as u64
        );
        assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64);
    }
    let mut file = tempfile::tempfile().unwrap();
    let error = copy_bounded_body(&mut Cursor::new(b"abcd"), &mut file, 3, cutoff()).unwrap_err();
    assert!(error.to_string().contains("exceeds bound"));
    assert!(file.metadata().unwrap().len() <= 3);
}

#[test]
fn generated_stream_is_copied_in_fixed_chunks_without_archive_buffer() {
    struct Generated {
        remaining: u64,
        largest_read: usize,
    }
    impl Read for Generated {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.largest_read = self.largest_read.max(buffer.len());
            let count = usize::try_from(self.remaining).unwrap().min(buffer.len());
            buffer[..count].fill(17);
            self.remaining -= count as u64;
            Ok(count)
        }
    }
    let length = 2 * 1024 * 1024;
    let mut source = Generated {
        remaining: length,
        largest_read: 0,
    };
    let mut file = tempfile::tempfile().unwrap();
    assert_eq!(
        copy_bounded_body(&mut source, &mut file, length, cutoff()).unwrap(),
        length
    );
    assert_eq!(file.metadata().unwrap().len(), length);
    assert!(source.largest_read <= 64 * 1024);
}

#[test]
fn stream_read_failure_and_expired_deadline_remain_distinct_from_overrun() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("sensitive URL must not escape"))
        }
    }
    let mut file = tempfile::tempfile().unwrap();
    let error = copy_bounded_body(&mut Broken, &mut file, 8, cutoff())
        .unwrap_err()
        .to_string();
    assert!(error.contains("body read failed"));
    assert!(!error.contains("sensitive"));
    assert!(!error.contains("exceeds bound"));
    let error =
        copy_bounded_body(&mut Cursor::new(b"payload"), &mut file, 8, Instant::now()).unwrap_err();
    assert!(error.to_string().contains("deadline expired"));
    assert_eq!(file.metadata().unwrap().len(), 0);
}

#[test]
fn streaming_redirect_strips_credentials_and_replaces_redirect_body() {
    use super::{ReadBudget, Response, StreamedResponse, StreamingTransport, Transport};
    use std::{
        collections::BTreeMap,
        io::{Seek, SeekFrom, Write},
        sync::Mutex,
    };
    struct Redirect {
        calls: Mutex<Vec<Vec<(String, String)>>>,
    }
    impl Transport for Redirect {
        fn request(
            &self,
            _: &str,
            _: &url::Url,
            _: &[(String, String)],
            _: &[u8],
            _: Instant,
            _: u64,
        ) -> crate::Result<Response> {
            panic!("streaming must never fall back to a buffered request");
        }
    }
    impl StreamingTransport for Redirect {
        fn request_to(
            &self,
            url: &url::Url,
            headers: &[(String, String)],
            _: Instant,
            _: u64,
            destination: &mut dyn Write,
        ) -> crate::Result<StreamedResponse> {
            self.calls.lock().unwrap().push(headers.to_vec());
            let redirected = url.host_str() == Some("storage.example");
            let body = if redirected {
                b"payload".as_slice()
            } else {
                b"redirect-body".as_slice()
            };
            destination.write_all(body)?;
            Ok(StreamedResponse {
                status: if redirected { 200 } else { 302 },
                headers: if redirected {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([("location".into(), "https://storage.example/selected".into())])
                },
                length: body.len() as u64,
            })
        }
    }
    let transport = Redirect {
        calls: Mutex::new(Vec::new()),
    };
    let mut destination = tempfile::tempfile().unwrap();
    let length = super::download_to_file(
        &transport,
        &ReadBudget::new(cutoff()),
        &url::Url::parse("https://api.example/selected").unwrap(),
        &[("Authorization".into(), "fixture-token".into())],
        32,
        &mut destination,
    )
    .unwrap();
    assert_eq!(length, b"payload".len() as u64);
    destination.seek(SeekFrom::Start(0)).unwrap();
    let mut actual = Vec::new();
    destination.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, b"payload");
    let calls = transport.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], [("Authorization".into(), "fixture-token".into())]);
    assert!(calls[1].is_empty());
}
