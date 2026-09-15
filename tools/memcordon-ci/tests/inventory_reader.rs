use memcordon_ci::build_context::BuildInputSnapshot;
use memcordon_ci::inventory_progress::InventoryProgress;
use memcordon_ci::inventory_reader::{BUFFER_SIZE, digest_reader, open_sequential};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read};
use std::path::Path;

fn counter(progress: &InventoryProgress, name: &str) -> u64 {
    progress
        .snapshot()
        .split_whitespace()
        .filter_map(|field| field.split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.parse().unwrap()))
        .unwrap()
}

fn bytes(length: usize) -> Vec<u8> {
    (u8::MIN..=u8::MAX).cycle().take(length).collect()
}

#[test]
fn eof_and_buffer_boundaries_hash_every_byte_with_one_reusable_buffer() {
    let progress = InventoryProgress::new(Path::new("buffer boundaries"));
    let mut buffer = vec![0; BUFFER_SIZE];
    let allocation = buffer.as_ptr();
    let mut expected_calls = 0;
    let mut expected_bytes = 0;
    for length in [
        0,
        BUFFER_SIZE - 1,
        BUFFER_SIZE,
        BUFFER_SIZE + 1,
        BUFFER_SIZE * 2 + 37,
    ] {
        let input = bytes(length);
        let digest = digest_reader(&mut Cursor::new(&input), &mut buffer, &progress).unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(&input)));
        expected_calls += length.div_ceil(BUFFER_SIZE) as u64 + 1;
        expected_bytes += length as u64;
        assert_eq!(counter(&progress, "read_calls"), expected_calls);
        assert_eq!(counter(&progress, "bytes"), expected_bytes);
        assert_eq!(buffer.as_ptr(), allocation);
    }
}

struct ShortReader {
    data: Cursor<Vec<u8>>,
    maximum: usize,
    calls: usize,
    failure: Option<io::ErrorKind>,
    requested: Vec<usize>,
}

impl Read for ShortReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        self.requested.push(output.len());
        if self.calls == 3
            && let Some(kind) = self.failure
        {
            return Err(io::Error::new(kind, "original read failure"));
        }
        let available = output.len().min(self.maximum);
        self.data.read(&mut output[..available])
    }
}

#[test]
fn short_reads_continue_until_eof_without_hashing_stale_buffer_bytes() {
    let input = bytes(257);
    let progress = InventoryProgress::new(Path::new("short reads"));
    let mut buffer = vec![u8::MAX; BUFFER_SIZE];
    let mut reader = ShortReader {
        data: Cursor::new(input.clone()),
        maximum: 7,
        calls: 0,
        failure: None,
        requested: Vec::new(),
    };
    assert_eq!(
        digest_reader(&mut reader, &mut buffer, &progress).unwrap(),
        hex::encode(Sha256::digest(&input))
    );
    assert_eq!(counter(&progress, "bytes"), input.len() as u64);
    assert_eq!(
        counter(&progress, "read_calls"),
        input.len().div_ceil(reader.maximum) as u64 + 1
    );
    assert!(reader.requested.iter().all(|length| *length == BUFFER_SIZE));
}

#[test]
fn errors_after_partial_content_preserve_the_original_error_and_attempt_count() {
    for kind in [
        io::ErrorKind::Interrupted,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::UnexpectedEof,
    ] {
        let progress = InventoryProgress::new(Path::new("failed read"));
        let mut buffer = vec![0; BUFFER_SIZE];
        let mut reader = ShortReader {
            data: Cursor::new(bytes(257)),
            maximum: 7,
            calls: 0,
            failure: Some(kind),
            requested: Vec::new(),
        };
        let error = digest_reader(&mut reader, &mut buffer, &progress).unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), "original read failure");
        assert_eq!(counter(&progress, "bytes"), (reader.maximum * 2) as u64);
        assert_eq!(counter(&progress, "read_calls"), reader.calls as u64);
        assert_eq!(reader.calls, 3);
    }
}

#[test]
fn sequential_file_open_preserves_content_identity_and_tail_drift_detection() {
    use std::fs;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("native input with spaces.bin");
    let mut input = bytes(BUFFER_SIZE + 37);
    fs::write(&path, &input).unwrap();
    let progress = InventoryProgress::new(&path);
    let mut buffer = vec![0; BUFFER_SIZE];
    let digest =
        digest_reader(&mut open_sequential(&path).unwrap(), &mut buffer, &progress).unwrap();
    assert_eq!(digest, hex::encode(Sha256::digest(&input)));
    let snapshot = BuildInputSnapshot::capture(root.path()).unwrap();
    snapshot.audit().unwrap();
    *input.last_mut().unwrap() ^= u8::MAX;
    fs::write(&path, &input).unwrap();
    assert!(snapshot.audit().is_err());
    assert_ne!(
        snapshot.digest().unwrap(),
        BuildInputSnapshot::capture(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );
    assert_eq!(
        open_sequential(&root.path().join("missing"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}
