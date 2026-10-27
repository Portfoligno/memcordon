#[path = "../src/release/linux_image_capture.rs"]
mod capture;

use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::time::{Duration, Instant};

#[test]
fn evidence_containment_requires_original_normalized_absolute_strict_descendants() {
    use std::path::Path;
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("image-cases");
    let descendant = base.join("neighbor-import").join("baseline.bin");
    capture::normalized_descendant(&base, &descendant).unwrap();
    capture::normalized_descendant(root.path(), &base).unwrap();
    for (parent, child) in [
        (base.as_path(), base.as_path()),
        (descendant.as_path(), base.as_path()),
        (Path::new("relative"), descendant.as_path()),
        (base.as_path(), Path::new("relative/output")),
        (base.as_path(), root.path()),
    ] {
        assert_eq!(
            capture::normalized_descendant(parent, child)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert!(
        capture::normalized_descendant(
            &base,
            &root.path().join("image-cases-other").join("baseline.bin")
        )
        .is_err()
    );
    for aliased in [
        base.join(".").join("baseline.bin"),
        base.join("neighbor-import").join("..").join("baseline.bin"),
    ] {
        assert!(capture::normalized_descendant(&base, &aliased).is_err());
        assert!(capture::normalized_descendant(&aliased, &aliased.join("child")).is_err());
    }
}

#[cfg(unix)]
#[test]
fn evidence_containment_refuses_separator_and_dot_aliases_without_resolving_them() {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    let base = Path::new("/evidence/image-cases");
    for alias in [
        b"/evidence//image-cases/baseline.bin".as_slice(),
        b"/evidence/image-cases/./baseline.bin",
        b"/evidence/image-cases/baseline.bin/",
        b"//evidence/image-cases/baseline.bin",
    ] {
        let alias = Path::new(std::ffi::OsStr::from_bytes(alias));
        assert!(capture::normalized_descendant(base, alias).is_err());
    }
    for alias in [
        "/evidence//image-cases",
        "/evidence/./image-cases",
        "/evidence/image-cases/",
    ] {
        assert!(
            capture::normalized_descendant(Path::new(alias), &base.join("baseline.bin")).is_err()
        );
    }
    let non_unicode = Path::new(std::ffi::OsStr::from_bytes(
        b"/evidence/image-cases/\xff.bin",
    ));
    capture::normalized_descendant(base, non_unicode).unwrap();
}

#[test]
fn streams_an_image_above_the_old_limit_with_fixed_read_buffers() {
    struct Zeros(u64);
    impl Read for Zeros {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            assert!(bytes.len() <= 64 * 1024);
            let count = self.0.min(bytes.len() as u64) as usize;
            bytes[..count].fill(0);
            self.0 -= count as u64;
            Ok(count)
        }
    }
    let size = 64 * 1024 * 1024 + 1;
    let digest = capture::transfer(
        &mut Zeros(size),
        &mut io::sink(),
        size,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let mut reference = Sha256::new();
    io::copy(
        &mut io::repeat(0).take(size),
        &mut HashWriter(&mut reference),
    )
    .unwrap();
    assert_eq!(digest.as_slice(), reference.finalize().as_slice());
}

struct HashWriter<'a>(&'a mut Sha256);
impl io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn rejects_short_long_and_expired_sources_and_preserves_io_errors() {
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(capture::transfer(&mut &b"short"[..], &mut io::sink(), 6, deadline).is_err());
    assert!(capture::transfer(&mut &b"long"[..], &mut io::sink(), 3, deadline).is_err());
    assert_eq!(
        capture::transfer(&mut &b""[..], &mut io::sink(), 0, Instant::now())
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained output refused",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        capture::transfer(&mut &b"x"[..], &mut Broken, 1, deadline)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}
