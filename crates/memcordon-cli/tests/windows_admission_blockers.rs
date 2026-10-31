#[path = "../src/bin/memcordon-sealed-agent/windows/admission_blockers.rs"]
mod blockers;

use std::{
    ffi::OsString,
    io,
    time::{Duration, Instant},
};

fn cutoff() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn ordinary_fixture_names_are_sampled_without_claiming_record_authority() {
    let directory = tempfile::tempdir().unwrap();
    let identity = String::from(memcordon_core::hash_bytes(b"original-attempt"));
    for suffix in [".json", ".reader.json", ".writer.json"] {
        std::fs::write(
            directory.path().join(format!("{identity}{suffix}")),
            b"not authenticated record bytes",
        )
        .unwrap();
    }
    std::fs::write(directory.path().join("unknown.json"), b"unknown").unwrap();
    let observation = blockers::observe_names(
        std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.map(|entry| entry.file_name())),
        cutoff(),
    );
    assert_eq!(
        (
            observation.launch_names,
            observation.reader_names,
            observation.writer_names,
            observation.unknown_names
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(observation.sampled, 4);
    assert!(!observation.truncated);
    assert!(observation.unavailable.is_none());
    let detail = observation.detail();
    assert!(detail.contains("filename-shape-only"));
    assert!(detail.contains("record-binding=unavailable-before-exclusive-settlement"));
    assert!(!detail.contains(&identity));
    assert!(
        directory
            .path()
            .join(format!("{identity}.writer.json"))
            .is_file()
    );
}

#[test]
fn malformed_shapes_stay_unknown_and_enumeration_has_a_hard_bound() {
    let identity = String::from(memcordon_core::hash_bytes(b"original-attempt"));
    let names = [
        format!("{}.json", identity.to_ascii_uppercase()),
        "short.writer.json".into(),
        format!("{identity}.writer.json.extra"),
    ];
    let observation =
        blockers::observe_names(names.into_iter().map(|name| Ok(name.into())), cutoff());
    assert_eq!(observation.unknown_names, 3);
    let calls = std::cell::Cell::new(0);
    let observation = blockers::observe_names(
        std::iter::from_fn(|| {
            let next = calls.get() + 1;
            assert!(next <= blockers::MAX_ENTRIES, "read beyond bounded sample");
            calls.set(next);
            Some(Ok(OsString::from("unknown")))
        }),
        cutoff(),
    );
    assert_eq!(calls.get(), blockers::MAX_ENTRIES);
    assert_eq!(observation.sampled, blockers::MAX_ENTRIES);
    assert!(observation.truncated);
}

#[test]
fn native_inspection_error_and_original_cutoff_are_explicitly_unavailable() {
    let observation = blockers::observe_names([Err(io::Error::from_raw_os_error(5))], cutoff());
    assert!(matches!(
        observation.unavailable,
        Some(blockers::Unavailable::Io {
            native_code: Some(5),
            ..
        })
    ));
    assert!(observation.detail().contains("native-code=Some(5)"));
    let observation = blockers::observe_names(
        std::iter::from_fn(|| -> Option<io::Result<OsString>> {
            panic!("expired inspection enumerated a directory")
        }),
        Instant::now(),
    );
    assert!(matches!(
        observation.unavailable,
        Some(blockers::Unavailable::OriginalCutoff)
    ));
    assert_eq!(observation.sampled, 0);
    let observation = blockers::Observation::unavailable(blockers::Unavailable::UnsafeRoot);
    assert!(observation.detail().contains("unsafe-root"));
    assert!(observation.detail().len() < 1024);
}
