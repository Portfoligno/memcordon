#![cfg(unix)]

#[path = "../src/bin/memcordon-sealed-agent/linux/image_copy.rs"]
mod image_copy;

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn files() -> (std::path::PathBuf, std::fs::File, std::fs::File) {
    let directory = std::env::temp_dir().join(format!(
        "memcordon-image-copy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory).unwrap();
    let source = directory.join("source");
    fs::write(&source, b"held executable bytes").unwrap();
    let source = OpenOptions::new().read(true).open(source).unwrap();
    let destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("destination"))
        .unwrap();
    (directory, source, destination)
}

#[test]
fn positional_copy_preserves_shared_offset_after_entrypoint_hashing() {
    let (directory, source, mut destination) = files();
    let mut duplicate = source.try_clone().unwrap();
    let size = duplicate.seek(SeekFrom::End(0)).unwrap();
    image_copy::copy_exact(&source, &mut destination, size).unwrap();
    assert_eq!(duplicate.stream_position().unwrap(), size);
    assert_eq!(
        fs::read(directory.join("destination")).unwrap(),
        b"held executable bytes"
    );
    drop(destination);
    drop(duplicate);
    drop(source);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn positional_copy_refuses_short_long_and_overflowing_declared_size() {
    for adjustment in [-1_i64, 1] {
        let (directory, source, mut destination) = files();
        let actual = source.metadata().unwrap().len();
        let declared = actual.checked_add_signed(adjustment).unwrap();
        assert!(image_copy::copy_exact(&source, &mut destination, declared).is_err());
        assert!(image_copy::copy_exact(&source, &mut destination, u64::MAX).is_err());
        drop(destination);
        drop(source);
        fs::remove_dir_all(directory).unwrap();
    }
}
