#![cfg(unix)]

#[path = "../src/release/native_executable.rs"]
mod native_executable;

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[test]
fn executable_identity_is_retained_without_writable_descriptor() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("executable");
    let mut writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    writer
        .write_all(b"original measured executable bytes")
        .unwrap();
    writer
        .set_permissions(std::fs::Permissions::from_mode(0o555))
        .unwrap();
    writer.sync_all().unwrap();
    let original = writer.metadata().unwrap();
    let mut retained = native_executable::retain_readonly(&path, writer).unwrap();
    let current = retained.metadata().unwrap();
    assert_eq!(
        (original.dev(), original.ino()),
        (current.dev(), current.ino())
    );
    // SAFETY: both commands inspect this live owned descriptor, without mutation.
    let access = unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(access, -1);
    assert_eq!(access & libc::O_ACCMODE, libc::O_RDONLY);
    // SAFETY: F_GETFD inspects the same live descriptor.
    let flags = unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags, -1);
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
    let mut bytes = Vec::new();
    retained.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"original measured executable bytes");
    assert_eq!(current.mode() & 0o777, 0o555);
}

#[test]
fn read_only_handoff_refuses_replaced_inode_and_symlink() {
    let root = tempfile::tempdir().unwrap();
    for symlink in [false, true] {
        let path = root
            .path()
            .join(if symlink { "link" } else { "replacement" });
        let writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let original = path.with_extension("original");
        std::fs::rename(&path, &original).unwrap();
        if symlink {
            std::os::unix::fs::symlink(&original, &path).unwrap();
        } else {
            std::fs::write(&path, b"foreign bytes").unwrap();
        }
        let error = native_executable::retain_readonly(&path, writer).unwrap_err();
        if !symlink {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("identity differs"));
        }
    }
}
