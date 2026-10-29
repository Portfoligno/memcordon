use super::*;

#[test]
fn original_startup_cause_round_trips_with_code_and_process_identity() {
    let bytes = encode_failure(19, "policy startup lease: access denied", 2000).unwrap();
    let rendered = decode_failure(&bytes, 19, 100, 2100).unwrap();
    let failure: Failure = serde_json::from_str(&rendered).unwrap();
    assert_eq!(failure.detail, "policy startup lease: access denied");
    assert_eq!(failure.process_id, std::process::id());
    assert!(!failure.truncated);
    assert!(decode_failure(&bytes, 20, 100, 2100).is_err());
    assert!(decode_failure(&bytes, 19, 100, 5000).is_err());
    assert!(decode_failure(&bytes, 19, 100, 1999).is_err());
}

#[test]
fn original_startup_cause_is_utf8_and_json_escape_bounded() {
    for detail in ["界".repeat(DETAIL_BYTES), "\0".repeat(DETAIL_BYTES + 1)] {
        let bytes = encode_failure(19, &detail, 2000).unwrap();
        assert!(bytes.len() <= RECORD_BYTES);
        let rendered = decode_failure(&bytes, 19, 0, 2000).unwrap();
        let failure: Failure = serde_json::from_str(&rendered).unwrap();
        assert!(failure.detail.len() <= DETAIL_BYTES);
        assert!(detail.starts_with(&failure.detail));
        assert!(failure.truncated);
    }
    assert!(decode_failure(&vec![b' '; RECORD_BYTES + 1], 19, 0, 2000).is_err());
}

#[test]
#[ignore = "requires an installed Windows provider and administrative package access"]
fn diagnostic_retirement_preserves_unrecognized_objects_and_original_bytes() {
    let _package = super::super::package::PackageLease::acquire().unwrap();
    let original = capture_current()
        .unwrap()
        .expect("installed diagnostic directory");
    let unexpected = root().join("unexpected-diagnostic-object");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&unexpected)
        .unwrap();
    let mut cleanup = RemoveUnexpectedDiagnostic {
        path: unexpected.clone(),
        file: Some(file),
    };
    cleanup
        .file
        .as_mut()
        .unwrap()
        .write_all(b"retain this unrelated object\n")
        .unwrap();
    cleanup.file.as_ref().unwrap().sync_all().unwrap();
    drop(cleanup.file.take());
    assert!(remove_current().unwrap_err().contains("unexpected"));
    assert_eq!(
        std::fs::read(&unexpected).unwrap(),
        b"retain this unrelated object\n"
    );
    drop(cleanup);
    assert_eq!(capture_current().unwrap(), Some(original));
}

struct RemoveUnexpectedDiagnostic {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
}

#[test]
fn restored_diagnostic_inventory_cannot_supply_paths_duplicates_or_excess_bytes() {
    for entries in [
        vec![(std::ffi::OsString::from("..\\foreign"), Vec::new())],
        vec![
            (std::ffi::OsString::from(FILE_NAME), Vec::new()),
            (std::ffi::OsString::from(FILE_NAME), Vec::new()),
        ],
        vec![(
            std::ffi::OsString::from(FILE_NAME),
            vec![0; RECORD_BYTES + 1],
        )],
    ] {
        let bytes = serde_json::to_vec(&serde_json::json!({"entries":entries})).unwrap();
        let snapshot: DiagnosticsSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert!(snapshot.validate_for_restore().is_err());
    }
}
impl Drop for RemoveUnexpectedDiagnostic {
    fn drop(&mut self) {
        drop(self.file.take());
        std::fs::remove_file(&self.path).expect("remove only the diagnostic test's own object");
    }
}
