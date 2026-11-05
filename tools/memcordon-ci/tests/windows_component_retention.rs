use memcordon_ci::{
    CiError,
    windows_component_retention::{after, export},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
}

fn fixture(root: &Path) -> Vec<(String, Value)> {
    let selection = json!({"kind":"fault","fault":memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization});
    let case = root.join("fault-0");
    fs::create_dir_all(&case).unwrap();
    fs::write(
        case.join("selection.json"),
        serde_json::to_vec(&selection).unwrap(),
    )
    .unwrap();
    fs::write(case.join("component-case-assessment.json"),serde_json::to_vec(&json!({"selected_fault":memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization,"collection_ok":false,"retirement_ok":true})).unwrap()).unwrap();
    vec![("fault-0".into(), selection)]
}

#[test]
fn finite_failed_case_projection_survives_owner_without_private_files() {
    let source = tempdir();
    let destination = tempdir();
    let selectors = fixture(source.path());
    let bytes = br#"{"process_id":7,"native_exit_status":3221225786,"nonce":"private-value"}"#;
    fs::write(
        source.path().join("fault-0/held-control-worker-exit.json"),
        bytes,
    )
    .unwrap();
    fs::write(
        source.path().join("fault-0/challenge.bin"),
        b"private-value",
    )
    .unwrap();
    export(
        source.path(),
        destination.path(),
        &selectors,
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    drop(source);
    let retained = fs::read(
        destination
            .path()
            .join("fault-0/held-control-worker-exit.diagnostic.json"),
    )
    .unwrap();
    assert!(!String::from_utf8_lossy(&retained).contains("private-value"));
    let value: Value = serde_json::from_slice(&retained).unwrap();
    assert_eq!(value["source_bytes"], bytes.len());
    assert_eq!(
        value["source_sha256"],
        memcordon_ci::windows_causal_acceptance::sha256(bytes)
    );
    assert_eq!(value["acceptance_authority"], false);
    assert!(!destination.path().join("fault-0/challenge.bin").exists());
    let manifest: Value = serde_json::from_slice(
        &fs::read(destination.path().join("component-diagnostics.json")).unwrap(),
    )
    .unwrap();
    assert!(
        manifest["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["state"] == "missing")
    );
}

#[test]
fn retention_error_and_panic_cannot_replace_original_result_or_payload() {
    let error = after::<()>(
        || Err(CiError::Io(std::io::Error::from_raw_os_error(87))),
        || Err(CiError::Message("export failed".into())),
    )
    .unwrap_err();
    assert!(
        matches!(error,CiError::LaneFailures{primary,..} if matches!(&*primary,CiError::Io(error) if error.raw_os_error()==Some(87)))
    );
    assert_eq!(
        after(|| Ok(7), || Err(CiError::Message("export failed".into()))).unwrap(),
        7
    );
    let payload = std::panic::catch_unwind(|| {
        after::<()>(
            || std::panic::panic_any(1234u32),
            || panic!("diagnostic panic"),
        )
        .unwrap();
    })
    .unwrap_err();
    assert_eq!(*payload.downcast::<u32>().unwrap(), 1234);
}

#[test]
fn escaped_selector_and_oversized_sources_never_export_raw_content() {
    let source = tempdir();
    let destination = tempdir();
    let selectors = fixture(source.path());
    let file = fs::File::create(source.path().join("fault-0/native-observation.json")).unwrap();
    file.set_len(memcordon_ci::windows_component_diagnostics::INPUT_BYTES as u64 + 1)
        .unwrap();
    export(
        source.path(),
        destination.path(),
        &selectors,
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    assert!(
        !destination
            .path()
            .join("fault-0/native-observation.diagnostic.json")
            .exists()
    );
    assert!(
        export(
            source.path(),
            destination.path(),
            &[("../escape".into(), json!({}))],
            Instant::now() + Duration::from_secs(3)
        )
        .is_err()
    );
    let absent = destination.path().join("expired");
    assert!(export(source.path(), &absent, &selectors, Instant::now()).is_err());
    assert!(!absent.exists());
}

#[cfg(unix)]
#[test]
fn symlinked_source_and_output_ancestors_are_rejected() {
    use std::os::unix::fs::symlink;
    let source = tempdir();
    let destination = tempdir();
    let outside = tempdir();
    let selectors = fixture(source.path());
    fs::write(outside.path().join("secret"), b"secret").unwrap();
    symlink(
        outside.path().join("secret"),
        source.path().join("fault-0/native-observation.json"),
    )
    .unwrap();
    export(
        source.path(),
        destination.path(),
        &selectors,
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    assert!(
        !destination
            .path()
            .join("fault-0/native-observation.diagnostic.json")
            .exists()
    );
    symlink(outside.path(), destination.path().join("linked")).unwrap();
    assert!(
        export(
            source.path(),
            &destination.path().join("linked/child"),
            &selectors,
            Instant::now() + Duration::from_secs(3)
        )
        .is_err()
    );
    assert!(!outside.path().join("child").exists());
}
