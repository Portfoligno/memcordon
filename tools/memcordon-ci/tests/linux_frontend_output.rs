#![cfg(unix)]
#[path = "../src/release/linux_frontend_output.rs"]
mod output;
use std::{
    ffi::OsStr,
    fs::{self, File},
    io,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    time::{Duration, Instant},
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn held_directory_reader_checks_exact_caller_custody() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("result.json");
    fs::write(&path, b"original frontend bytes").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let directory = File::open(root.path()).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    let read = |uid, gid, bound, cutoff| {
        output::read(
            &directory,
            OsStr::new("result.json"),
            uid,
            gid,
            bound,
            cutoff,
        )
    };
    assert_eq!(
        read(metadata.uid(), metadata.gid(), metadata.len(), deadline()).unwrap(),
        b"original frontend bytes"
    );
    for (uid, gid) in [
        (metadata.uid() ^ 1, metadata.gid()),
        (metadata.uid(), metadata.gid() ^ 1),
    ] {
        assert_eq!(
            read(uid, gid, metadata.len(), deadline())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    assert!(
        read(
            metadata.uid(),
            metadata.gid(),
            metadata.len() - 1,
            deadline()
        )
        .is_err()
    );
    assert_eq!(
        read(
            metadata.uid(),
            metadata.gid(),
            metadata.len(),
            Instant::now()
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
    for leaf in ["", ".", "..", "../result.json", "/result.json", "bad\0leaf"] {
        assert_eq!(
            output::read(
                &directory,
                OsStr::new(leaf),
                metadata.uid(),
                metadata.gid(),
                1024,
                deadline()
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(
        output::read(
            &directory,
            OsStr::new("missing"),
            metadata.uid(),
            metadata.gid(),
            1024,
            deadline()
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotFound
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
    assert!(read(metadata.uid(), metadata.gid(), 1024, deadline()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.path().join("another-link");
    fs::hard_link(&path, &link).unwrap();
    assert!(read(metadata.uid(), metadata.gid(), 1024, deadline()).is_err());
    fs::remove_file(&link).unwrap();
    let alias = root.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(
        output::read(
            &directory,
            OsStr::new("alias"),
            metadata.uid(),
            metadata.gid(),
            1024,
            deadline()
        )
        .is_err()
    );
    fs::create_dir(root.path().join("directory")).unwrap();
    assert!(
        output::read(
            &directory,
            OsStr::new("directory"),
            metadata.uid(),
            metadata.gid(),
            1024,
            deadline()
        )
        .is_err()
    );
    use std::os::unix::ffi::OsStrExt;
    let fifo = std::ffi::CString::new(root.path().join("fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: the owned CString is terminated and live; this creates only the
    // fresh FIFO inside this test's exclusively owned temporary directory.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(
        output::read(
            &directory,
            OsStr::new("fifo"),
            metadata.uid(),
            metadata.gid(),
            1024,
            deadline()
        )
        .is_err()
    );
    assert!(
        output::read(
            &File::open(&path).unwrap(),
            OsStr::new("result.json"),
            metadata.uid(),
            metadata.gid(),
            1024,
            deadline()
        )
        .is_err()
    );
}

#[test]
fn positional_chunks_and_empty_output_preserve_exact_bytes() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    for bytes in [Vec::new(), vec![0x96; 2 * 64 * 1024 + 7]] {
        let path = root.path().join("result.json");
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        for _ in 0..2 {
            assert_eq!(
                output::read(
                    &directory,
                    OsStr::new("result.json"),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.len(),
                    deadline()
                )
                .unwrap(),
                bytes
            );
        }
    }
}
