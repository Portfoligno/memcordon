#![cfg(unix)]
#[path = "../src/release/linux_capture_record.rs"]
mod capture;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{FileExt, MetadataExt, PermissionsExt},
    time::{Duration, Instant},
};
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, File) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("capture");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    (directory, path, file)
}
#[test]
fn chunks_publish_only_flushed_newline_and_allow_later_append() {
    let (_directory, path, mut file) = fixture();
    let (mut publisher, receiver) = capture::channel();
    for part in [b"{\"a\":".as_slice(), b"1}"] {
        file.write_all(part).unwrap();
        file.flush().unwrap();
        publisher.flushed(&file, &path, part).unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }
    file.write_all(b"\nmore").unwrap();
    file.flush().unwrap();
    publisher.flushed(&file, &path, b"\nmore").unwrap();
    let record = receiver.try_recv().unwrap().unwrap();
    file.write_all(b" later").unwrap();
    file.flush().unwrap();
    assert_eq!(
        record
            .read(
                Instant::now() + Duration::from_secs(2),
                file.metadata().unwrap().uid()
            )
            .unwrap(),
        b"{\"a\":1}\n"
    );
}
#[test]
fn committed_prefix_rejects_overwrite_truncation_replacement_and_policy_change() {
    for change in 0..7 {
        let (_directory, path, mut file) = fixture();
        let (mut publisher, receiver) = capture::channel();
        file.write_all(b"record\n").unwrap();
        file.flush().unwrap();
        publisher.flushed(&file, &path, b"record\n").unwrap();
        let record = receiver.try_recv().unwrap().unwrap();
        match change {
            0 => file.write_all_at(b"X", 0).unwrap(),
            1 => file.set_len(1).unwrap(),
            2 => {
                std::fs::rename(&path, path.with_extension("old")).unwrap();
                std::fs::write(&path, b"record\n").unwrap();
            }
            3 => file
                .set_permissions(std::fs::Permissions::from_mode(0o666))
                .unwrap(),
            4 => {
                std::fs::hard_link(&path, path.with_extension("link")).unwrap();
            }
            5 => {
                std::fs::rename(&path, path.with_extension("old")).unwrap();
                std::os::unix::fs::symlink(path.with_extension("old"), &path).unwrap();
            }
            _ => {
                assert!(
                    record
                        .read(
                            Instant::now() + Duration::from_secs(2),
                            file.metadata().unwrap().uid().checked_add(1).unwrap()
                        )
                        .is_err()
                );
                continue;
            }
        }
        assert!(
            record
                .read(
                    Instant::now() + Duration::from_secs(2),
                    file.metadata().unwrap().uid()
                )
                .is_err()
        );
    }
}
#[test]
fn eof_bound_expiration_and_receiver_loss_never_publish_success() {
    let (_directory, path, mut file) = fixture();
    let (mut publisher, receiver) = capture::channel();
    publisher.eof();
    assert!(receiver.try_recv().unwrap().is_err());
    let (mut publisher, receiver) = capture::channel();
    assert!(
        publisher
            .flushed(&file, &path, &vec![b'x'; capture::RECORD_BOUND + 1])
            .is_err()
    );
    drop(receiver);
    let (mut publisher, receiver) = capture::channel();
    file.write_all(b"ok\n").unwrap();
    file.flush().unwrap();
    publisher.flushed(&file, &path, b"ok\n").unwrap();
    let record = receiver.try_recv().unwrap().unwrap();
    assert_eq!(
        record
            .read(Instant::now(), file.metadata().unwrap().uid())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    let (mut publisher, receiver) = capture::channel();
    drop(receiver);
    assert!(publisher.flushed(&file, &path, b"ok\n").is_err());
}

#[test]
fn original_io_failure_and_wrong_native_writer_are_refused() {
    let (_directory, path, mut file) = fixture();
    let (mut publisher, receiver) = capture::channel();
    publisher.fail(std::io::Error::from_raw_os_error(libc::EIO));
    assert_eq!(
        receiver.try_recv().unwrap().err().unwrap().raw_os_error(),
        Some(libc::EIO)
    );
    file.write_all(b"ok\n").unwrap();
    file.flush().unwrap();
    let (_other_directory, _other_path, other) = fixture();
    let (mut publisher, _receiver) = capture::channel();
    assert!(publisher.flushed(&other, &path, b"ok\n").is_err());
}
