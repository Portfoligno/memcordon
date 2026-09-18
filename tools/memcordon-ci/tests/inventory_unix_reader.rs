#![cfg(unix)]

use memcordon_ci::inventory_progress::InventoryProgress;
use memcordon_ci::inventory_reader::{BUFFER_SIZE, NativeFilePhase, digest_unix_file};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;

#[cfg(target_os = "linux")]
#[test]
fn virtual_regular_file_contents_are_read_beyond_metadata_length() {
    let path = std::path::Path::new("/proc/version");
    let expected = fs::symlink_metadata(path).unwrap();
    assert!(expected.is_file());
    assert_eq!(expected.len(), 0);
    let contents = fs::read(path).unwrap();
    assert!(!contents.is_empty());
    let progress = InventoryProgress::new(path);
    let result = digest_unix_file(
        path,
        &expected,
        &mut vec![0; BUFFER_SIZE],
        &progress,
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result.bytes, contents.len() as u64);
    assert_eq!(result.digest, hex::encode(Sha256::digest(&contents)));
}

#[test]
fn fifo_replacement_before_open_or_reopen_fails_without_waiting_for_a_writer() {
    for boundary in [NativeFilePhase::BeforeOpen, NativeFilePhase::BeforeReopen] {
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("input");
            fs::write(&path, b"original").unwrap();
            let expected = fs::symlink_metadata(&path).unwrap();
            let progress = InventoryProgress::new(&path);
            let result = digest_unix_file(
                &path,
                &expected,
                &mut vec![0; BUFFER_SIZE],
                &progress,
                |phase| {
                    if phase == boundary {
                        fs::remove_file(&path)?;
                        let native = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                        // SAFETY: native is a valid, live NUL-terminated pathname.
                        if unsafe { libc::mkfifo(native.as_ptr(), 0o600) } != 0 {
                            return Err(std::io::Error::last_os_error().into());
                        }
                    }
                    Ok(())
                },
            );
            send.send(result.is_err()).unwrap();
        });
        assert!(
            receive
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("native FIFO replacement must not block opening the file")
        );
        worker.join().unwrap();
    }
}

#[test]
fn stable_empty_and_multibuffer_files_return_complete_digests() {
    let root = tempfile::tempdir().unwrap();
    for bytes in [Vec::new(), vec![0x5a; BUFFER_SIZE + 17]] {
        let path = root.path().join("input");
        fs::write(&path, &bytes).unwrap();
        let expected = fs::symlink_metadata(&path).unwrap();
        let progress = InventoryProgress::new(&path);
        let result = digest_unix_file(
            &path,
            &expected,
            &mut vec![0; BUFFER_SIZE],
            &progress,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(result.bytes, bytes.len() as u64);
        assert_eq!(result.digest, hex::encode(Sha256::digest(&bytes)));
    }
}

#[test]
fn preopen_mutation_and_postopen_truncation_are_rejected() {
    for phase in [NativeFilePhase::BeforeOpen, NativeFilePhase::Prechecked] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input");
        fs::write(&path, b"original bytes").unwrap();
        let expected = fs::symlink_metadata(&path).unwrap();
        let progress = InventoryProgress::new(&path);
        assert!(
            digest_unix_file(
                &path,
                &expected,
                &mut vec![0; BUFFER_SIZE],
                &progress,
                |current| {
                    if current == phase {
                        fs::write(&path, b"short")?;
                    }
                    Ok(())
                }
            )
            .is_err()
        );
    }
}

#[test]
fn same_content_path_replacement_or_symlink_substitution_is_rejected() {
    for replace_with_symlink in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input");
        let old = root.path().join("old");
        fs::write(&path, b"same bytes").unwrap();
        let expected = fs::symlink_metadata(&path).unwrap();
        let progress = InventoryProgress::new(&path);
        assert!(
            digest_unix_file(
                &path,
                &expected,
                &mut vec![0; BUFFER_SIZE],
                &progress,
                |phase| {
                    if phase == NativeFilePhase::BeforeReopen {
                        fs::rename(&path, &old)?;
                        if replace_with_symlink {
                            symlink(&old, &path)?;
                        } else {
                            fs::write(&path, b"same bytes")?;
                        }
                    }
                    Ok(())
                }
            )
            .is_err()
        );
    }
}

#[test]
fn persistent_same_length_mutation_after_read_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("input");
    fs::write(&path, b"original").unwrap();
    let expected = fs::symlink_metadata(&path).unwrap();
    let progress = InventoryProgress::new(&path);
    assert!(
        digest_unix_file(
            &path,
            &expected,
            &mut vec![0; BUFFER_SIZE],
            &progress,
            |phase| {
                if phase == NativeFilePhase::ReadComplete {
                    fs::write(&path, b"modified")?;
                    fs::File::options().write(true).open(&path)?.set_times(
                        fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH),
                    )?;
                }
                Ok(())
            }
        )
        .is_err()
    );
}

#[test]
fn cancellation_at_every_validation_boundary_rejects_empty_file() {
    for boundary in [
        NativeFilePhase::BeforeOpen,
        NativeFilePhase::Prechecked,
        NativeFilePhase::ReadComplete,
        NativeFilePhase::BeforeReopen,
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("empty");
        fs::write(&path, []).unwrap();
        let expected = fs::symlink_metadata(&path).unwrap();
        let progress = InventoryProgress::new(&path);
        let cancellation = progress.cancellation();
        assert!(
            digest_unix_file(
                &path,
                &expected,
                &mut vec![0; BUFFER_SIZE],
                &progress,
                |phase| {
                    if phase == boundary {
                        cancellation.cancel();
                    }
                    Ok(())
                }
            )
            .is_err()
        );
    }
}
