#![cfg(windows)]

use memcordon_platform::WindowsTerminalObservationScope;

#[test]
fn request_capture_reservation_blocks_named_mutation_and_absence_is_not_success() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("request.bin");
    let scope = WindowsTerminalObservationScope::begin_with_request_path(&path).unwrap();
    let write = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap_err();
    assert_eq!(write.raw_os_error(), Some(32));
    let removal = std::fs::remove_file(&path).unwrap_err();
    assert_eq!(removal.raw_os_error(), Some(32));
    assert!(scope.finish_request().unwrap_err().contains("unavailable"));
    assert_eq!(std::fs::read(&path).unwrap(), Vec::<u8>::new());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn existing_request_destination_is_preserved_and_failed_reservation_releases_scope() {
    let directory = tempfile::tempdir().unwrap();
    let prior = directory.path().join("prior.bin");
    let original = [0, 255, 128, 9];
    std::fs::write(&prior, original).unwrap();
    assert!(WindowsTerminalObservationScope::begin_with_request_path(&prior).is_err());
    assert_eq!(std::fs::read(prior).unwrap(), original);
    let next = directory.path().join("next.bin");
    let scope = WindowsTerminalObservationScope::begin_with_request_path(&next).unwrap();
    assert!(scope.finish_request().is_err());
}

#[test]
fn request_only_scope_cannot_supply_an_authenticated_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("request.bin");
    let scope = WindowsTerminalObservationScope::begin_with_request_path(&path).unwrap();
    assert!(scope.finish().unwrap_err().contains("unavailable"));
}
