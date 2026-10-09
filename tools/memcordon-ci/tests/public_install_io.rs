#[path = "../src/release/public_install_io.rs"]
mod public_install_io;

#[test]
fn actual_io_preserves_success_and_identifies_missing_operand() {
    let owner = std::env::temp_dir().join(format!(
        "public-install-io-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&owner).unwrap();
    let path = owner.join("actual-executable");
    std::fs::write(&path, b"actual bytes").unwrap();
    assert_eq!(
        public_install_io::contextualize(
            "read emitted build executable",
            &path,
            std::fs::read(&path)
        )
        .unwrap(),
        b"actual bytes"
    );
    let missing = owner.join("missing-executable");
    let error = public_install_io::contextualize(
        "read emitted build executable",
        &missing,
        std::fs::read(&missing),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    let text = error.to_string();
    assert!(text.contains("read emitted build executable"));
    assert!(text.contains("missing-executable"));
    assert!(text.contains("path-truncated=false"));
    std::fs::remove_dir_all(owner).unwrap();
}

#[test]
fn paths_are_byte_bounded_and_control_escaped() {
    let path = std::path::PathBuf::from(format!("secret\n{}end-marker", "é".repeat(512)));
    let error = public_install_io::error(
        "read installed executable",
        &path,
        std::io::Error::from(std::io::ErrorKind::NotFound),
    );
    let text = error.to_string();
    assert!(text.contains("secret\\n"));
    assert!(!text.contains('\n'));
    assert!(!text.contains("end-marker"));
    assert!(text.contains("path-truncated=true"));
    assert!(text.len() < 1200);
}
