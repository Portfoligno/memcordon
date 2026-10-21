use super::*;
use std::time::Duration;
use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn readonly_pin_preserves_native_identity_bytes_and_shared_cursor_readback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image.exe");
    let original = b"native file bytes; this fixture does not claim a valid PE image";
    std::fs::write(&path, original).unwrap();
    let file = open_read_pin(&path).unwrap();
    let identity = native_identity(&file).unwrap();
    verify_file_path(&file, &path).unwrap();
    assert_eq!(read_bytes(&file, &identity, deadline()).unwrap(), original);
    // A second read must rewind the actual shared kernel cursor.
    assert_eq!(read_bytes(&file, &identity, deadline()).unwrap(), original);
    assert!(super::super::package::verify_native_target_desktop_bootstrap_pe(original).is_err());
    assert_eq!(
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap_err()
            .raw_os_error(),
        Some(32),
        "the actual pinned object denies a concurrent writer",
    );
    assert!(std::fs::remove_file(&path).is_err());
    drop(file);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn foreign_identity_path_and_expired_cutoff_never_supply_image_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image.exe");
    let other = directory.path().join("other.exe");
    std::fs::write(&path, b"same bytes").unwrap();
    std::fs::write(&other, b"same bytes").unwrap();
    let file = open_read_pin(&path).unwrap();
    let other_file = open_read_pin(&other).unwrap();
    let identity = native_identity(&file).unwrap();
    let foreign = native_identity(&other_file).unwrap();
    assert_ne!(identity, foreign);
    assert!(read_bytes(&file, &foreign, deadline()).is_err());
    assert!(read_bytes(&file, &identity, Instant::now()).is_err());
    assert!(verify_file_path(&file, &other).is_err());
    assert!(verify_self_path(&path).is_err());
}

#[test]
fn writable_and_inheritable_capabilities_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image.exe");
    std::fs::write(&path, b"fixture").unwrap();
    let mutable = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(native_identity(&mutable).is_err());
    drop(mutable);
    let file = open_read_pin(&path).unwrap();
    let raw = file.as_raw_handle() as HANDLE;
    // SAFETY: this test owns the exact file and restores its flag before drop.
    assert_ne!(
        unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
        0
    );
    assert!(native_identity(&file).is_err());
    assert_ne!(
        unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) },
        0
    );
    native_identity(&file).unwrap();
}

#[test]
fn multiple_links_and_nonfile_objects_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image.exe");
    let alias = directory.path().join("alias.exe");
    std::fs::write(&path, b"fixture").unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    let file = open_read_pin(&path).unwrap();
    assert!(native_identity(&file).is_err());
    let event = unsafe {
        windows_sys::Win32::System::Threading::CreateEventW(
            std::ptr::null(),
            0,
            0,
            std::ptr::null(),
        )
    };
    assert!(!event.is_null());
    // SAFETY: the fresh event is exclusively owned here; File's drop closes
    // the native handle even though validation must reject this object type.
    let nonfile = unsafe { File::from_raw_handle(event) };
    assert!(native_identity(&nonfile).is_err());
}
