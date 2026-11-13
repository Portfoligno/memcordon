#[path = "../src/bin/consumer_readiness_linux/binary_streams.rs"]
mod emitter;
use std::io::{self, Write};

#[test]
fn actual_raw_emitter_writes_distinct_exact_byte_products() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    emitter::raw(&mut stdout, &mut stderr).unwrap();
    assert_eq!(stdout.len(), 256);
    assert_eq!(stderr.len(), 256);
    for index in 0..256 {
        assert_eq!(usize::from(stdout[index]), index);
        assert_eq!(usize::from(stderr[index]), 255 - index);
    }
    assert_ne!(stdout, stderr);
}

struct Sink {
    descending: bool,
    writes: usize,
    total: usize,
    flushes: usize,
    fail_write: bool,
    fail_flush: bool,
}
impl Sink {
    fn new(descending: bool) -> Self {
        Self {
            descending,
            writes: 0,
            total: 0,
            flushes: 0,
            fail_write: false,
            fail_flush: false,
        }
    }
}
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        assert_eq!(bytes.len(), 256);
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(
                usize::from(*byte),
                if self.descending { 255 - index } else { index }
            );
        }
        self.writes += 1;
        self.total += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        } else {
            Ok(())
        }
    }
}

#[test]
fn actual_large_emitter_preserves_block_cadence_counts_and_separate_products() {
    let mut stdout = Sink::new(false);
    let mut stderr = Sink::new(true);
    emitter::large(&mut stdout, &mut stderr).unwrap();
    assert_eq!(emitter::LARGE_BLOCKS, 8192);
    assert_eq!((stdout.writes, stderr.writes), (8192, 8192));
    assert_eq!(
        (stdout.total, stderr.total),
        (2 * 1024 * 1024, 2 * 1024 * 1024)
    );
    assert_eq!((stdout.flushes, stderr.flushes), (1, 1));
}

#[test]
fn independent_write_and_flush_failures_remain_errors_without_merging_streams() {
    for large in [false, true] {
        for stderr_failure in [false, true] {
            let mut stdout = Sink::new(false);
            let mut stderr = Sink::new(true);
            if stderr_failure {
                stderr.fail_write = true;
            } else {
                stdout.fail_write = true;
            }
            let error = if large {
                emitter::large(&mut stdout, &mut stderr)
            } else {
                emitter::raw(&mut stdout, &mut stderr)
            }
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            if stderr_failure {
                assert_eq!(stdout.writes, 1);
                assert_eq!(stderr.writes, 0);
                assert_eq!(stdout.flushes, usize::from(!large));
            } else {
                assert_eq!((stdout.writes, stderr.writes), (0, 0));
            }
        }
    }
    let mut stdout = Sink::new(false);
    let mut stderr = Sink::new(true);
    stdout.fail_flush = true;
    assert_eq!(
        emitter::raw(&mut stdout, &mut stderr).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(stderr.writes, 0);
    let mut stdout = Sink::new(false);
    let mut stderr = Sink::new(true);
    stderr.fail_flush = true;
    assert_eq!(
        emitter::raw(&mut stdout, &mut stderr).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!((stdout.writes, stderr.writes), (1, 1));
}
