use super::super::{
    inventory::{ProcessIdentity, ProcessObservation},
    marker::{MarkerState, TargetMarker, read_marker, validate_marker, write_json_atomic},
};
use std::{fs, path::Path};
fn marker() -> TargetMarker {
    let observation = |pid, parent_pid| ProcessObservation {
        identity: ProcessIdentity {
            pid,
            birth_seconds: 1,
            birth_microseconds: 2,
        },
        state: 2,
        parent_pid,
        process_group: 40,
        session_id: 40,
    };
    TargetMarker {
        schema_version: 2,
        target: observation(42, 41),
        guardian: observation(41, 40),
    }
}
#[test]
fn atomic_marker_roundtrip_preserves_identities_and_newline() {
    let directory = Path::new("/tmp").join(format!("memcordon-marker-test-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("target-identity.json");
    assert!(matches!(read_marker(&path).unwrap(), MarkerState::Missing));
    write_json_atomic(&path, &marker()).unwrap();
    assert_eq!(fs::read(&path).unwrap().last(), Some(&b'\n'));
    assert!(!path.with_extension("tmp").exists());
    let MarkerState::Valid(actual) = read_marker(&path).unwrap() else {
        panic!("valid marker rejected")
    };
    assert_eq!(actual.target.identity, marker().target.identity);
    validate_marker(&actual, 40).unwrap();
    fs::remove_dir_all(directory).unwrap();
}
#[test]
fn malformed_and_unsupported_markers_are_not_missing() {
    let path = Path::new("/tmp").join(format!(
        "memcordon-malformed-marker-{}.json",
        std::process::id()
    ));
    fs::write(&path, b"{broken\n").unwrap();
    assert!(matches!(
        read_marker(&path).unwrap(),
        MarkerState::Malformed(_)
    ));
    let mut value = marker();
    value.schema_version = 1;
    write_json_atomic(&path, &value).unwrap();
    assert!(matches!(
        read_marker(&path).unwrap(),
        MarkerState::Malformed(_)
    ));
    fs::remove_file(path).unwrap();
}
#[test]
fn marker_session_and_parent_contradictions_fail() {
    let mut value = marker();
    value.target.session_id = 99;
    assert!(validate_marker(&value, 40).is_err());
    value = marker();
    value.target.parent_pid = 99;
    assert!(validate_marker(&value, 40).is_err());
    value = marker();
    value.guardian.identity = value.target.identity;
    assert!(validate_marker(&value, 40).is_err());
}
