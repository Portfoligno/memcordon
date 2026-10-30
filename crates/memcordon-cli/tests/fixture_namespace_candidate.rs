#[path = "private/fixture_namespace_candidate.rs"]
mod candidate;
use candidate::*;

fn entry() -> Candidate {
    Candidate::new((1, 7, 9, 4096), HandleState::Present, true)
}

#[test]
fn existing_false_filters_have_distinct_outcomes_and_unchanged_decisions() {
    assert_eq!(
        Candidate::new((1, 7, 9, 4096), HandleState::Null, true).stage,
        Stage::MissingHandle
    );
    assert_eq!(
        Candidate::new((2, 7, 9, 8192), HandleState::Invalid, true).stage,
        Stage::MissingHandle
    );
    assert_eq!(
        Candidate::new((3, 7, 9, 8192), HandleState::Present, false).stage,
        Stage::Inactive
    );
    let mut value = entry();
    assert!(!value.length_matches(42, 100));
    assert_eq!(value.stage, Stage::LengthMismatch);
    assert_eq!(value.length, Some(42));
    for (separator, parent, basename, stage) in [
        (false, false, false, Stage::MissingSeparator),
        (true, false, true, Stage::ParentMismatch),
        (true, true, false, Stage::BasenameMismatch),
        (true, false, false, Stage::ParentMismatch),
        (true, true, true, Stage::FileIdentityBefore),
    ] {
        let mut value = entry();
        assert!(value.length_matches(100, 100));
        assert_eq!(
            value.predicates(separator, parent, basename),
            separator && parent && basename
        );
        assert_eq!(value.stage, stage);
        assert_eq!(value.parent_matches, separator.then_some(parent));
        assert_eq!(value.basename_matches, separator.then_some(basename));
    }
}

#[test]
fn full_paths_are_hashed_and_bounded_prefixes_never_become_predicates() {
    let mut value = entry();
    let mut full = vec![65u16; 32767];
    value.final_path(&full);
    value.system_directory(&full);
    let first = value.final_path.as_ref().unwrap().utf16le_sha256.clone();
    full[32766] = 66;
    value.final_path(&full);
    let evidence = value.final_path.as_ref().unwrap();
    assert_eq!(evidence.units.len(), 256);
    assert_eq!(evidence.total_units, 32767);
    assert!(evidence.truncated);
    assert_ne!(first, evidence.utf16le_sha256);
    assert_eq!(value.parent_matches, None);
    assert_eq!(value.basename_matches, None);
}

#[test]
fn failures_keep_stage_native_error_and_deadline_separate() {
    for stage in [
        Stage::NotProcessed,
        Stage::MappedBase,
        Stage::MappedName,
        Stage::MappedBasenameMismatch,
        Stage::MappedSystemDirectory,
        Stage::MappedRootOpen,
        Stage::MappedRootIdentity,
        Stage::MappedRootPath,
        Stage::MappedRootMismatch,
        Stage::MappedFileOpen,
        Stage::MappedFilePath,
        Stage::MappedFileMismatch,
        Stage::MappedRecheck,
        Stage::FileMetadata,
        Stage::FinalPath,
        Stage::SystemDirectory,
        Stage::FileIdentityBefore,
        Stage::Read,
        Stage::FileMetadataAfter,
        Stage::FileProfile,
        Stage::FileIdentityAfter,
        Stage::RuntimeHeader,
        Stage::Mapping,
        Stage::RuntimeBytes,
    ] {
        let mut value = entry();
        value.stage = stage;
        value.failed(&std::io::Error::from_raw_os_error(5));
        assert_eq!(value.stage, stage);
        assert_eq!(value.raw_error, Some(5));
        assert!(!value.deadline);
        value.failed(&std::io::Error::new(std::io::ErrorKind::TimedOut, "cutoff"));
        assert!(value.deadline);
        assert_eq!(value.raw_error, None);
    }
}

#[test]
fn mixed_rejections_and_all_existing_event_limits_retain_bounded_summary() {
    let mut log = Candidates::default();
    log.push(Candidate::new((1, 7, 9, 4096), HandleState::Null, true))
        .unwrap();
    let mut mismatch = entry();
    mismatch.length_matches(42, 100);
    log.push(mismatch).unwrap();
    assert_eq!(log.classification(), "no-length-match");
    for ordinal in 2..256 {
        let mut value = Candidate::new((ordinal, 7, 9, 4096), HandleState::Present, ordinal < 128);
        value.event.0 = ordinal;
        if ordinal < 128 {
            value.length_matches(100, 100);
            value.final_path(&[65535; 1000]);
            value.system_directory(&[65535; 1000]);
            value.predicates(true, false, true);
        }
        log.push(value).unwrap();
    }
    assert_eq!(log.classification(), "path-candidates-rejected");
    assert_eq!(log.events.len(), 256);
    assert!(
        log.events
            .iter()
            .any(|event| event.paths_omitted_for_record_bound)
    );
    assert!(serde_json::to_vec(&log).unwrap().len() < 65536);
    assert_eq!(log.summary()["stages"]["missing-handle"], 1);
    assert_eq!(log.summary()["stages"]["parent-mismatch"], 126);
    assert_eq!(log.summary()["stages"]["inactive"], 128);
    for event in &log.events {
        if event.paths_omitted_for_record_bound {
            let path = event.final_path.as_ref().unwrap();
            assert!(path.units.is_empty());
            assert_eq!(path.total_units, 1000);
            assert_eq!(path.utf16le_sha256.len(), 64);
        }
    }
    assert!(log.push(entry()).is_err());
    let mut accepted = entry();
    accepted.stage = Stage::Accepted;
    let mut valid = Candidates::default();
    valid.push(accepted).unwrap();
    assert_eq!(valid.classification(), "accepted-candidate");
}

#[test]
fn evidence_overflow_never_replaces_original_native_failure() {
    let mut log = Candidates::default();
    for ordinal in 0..256 {
        log.push(Candidate::new(
            (ordinal, 7, 9, 4096),
            HandleState::Present,
            false,
        ))
        .unwrap();
    }
    let error = log
        .retain(entry(), Err::<(), _>(std::io::Error::from_raw_os_error(5)))
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(5));
    assert_eq!(log.omitted_for_record_bound, 1);
    assert!(
        log.retain(entry(), Ok(()))
            .unwrap_err()
            .to_string()
            .contains("event bound")
    );
    assert_eq!(log.omitted_for_record_bound, 2);
    assert_eq!(log.classification(), "candidate-evidence-limit");
    assert!(serde_json::to_vec(&log).unwrap().len() < 65536);
}

#[test]
fn mapped_provider_keeps_null_source_and_bounded_path_evidence_distinct() {
    assert_eq!(
        Provider::for_handle(HandleState::Present),
        Provider::EventFile
    );
    assert_eq!(
        Provider::for_handle(HandleState::Null),
        Provider::MappedImageFile
    );
    assert_eq!(
        Provider::for_handle(HandleState::Invalid),
        Provider::MappedImageFile
    );
    let mut log = Candidates::default();
    for ordinal in 0..128 {
        let mut value = Candidate::new((ordinal, 7, 9, 4096), HandleState::Null, true);
        value.provider = Some(Provider::for_handle(value.handle));
        value.stage = Stage::MappedBasenameMismatch;
        value.mapped = Some(MappedEvidence {
            before: Some(PathEvidence::new(&[65535; 1000])),
            ..Default::default()
        });
        log.push(value).unwrap();
    }
    for ordinal in 128..256 {
        log.push(Candidate::new(
            (ordinal, 7, 9, 4096),
            HandleState::Null,
            false,
        ))
        .unwrap();
    }
    assert!(serde_json::to_vec(&log).unwrap().len() < 65536);
    for value in &log.events[..128] {
        assert_eq!(value.handle, HandleState::Null);
        assert_eq!(value.provider, Some(Provider::MappedImageFile));
        let evidence = value.mapped.as_ref().unwrap();
        assert!(!evidence.selected);
        assert_eq!(evidence.before.as_ref().unwrap().total_units, 1000);
        assert_eq!(evidence.before.as_ref().unwrap().utf16le_sha256.len(), 64);
        assert_eq!(evidence.opened_matches, None);
    }
    let wire = serde_json::to_value(&log).unwrap();
    assert_eq!(wire["events"][0]["handle"], "null");
    assert_eq!(wire["events"][0]["provider"], "mapped-image-file");
    let mut selected = entry();
    selected.stage = Stage::LengthMismatch;
    selected.mapped = Some(MappedEvidence {
        selected: true,
        ..Default::default()
    });
    assert!(selected.selected_result(false).is_err());
    assert_eq!(selected.stage, Stage::LengthMismatch);
    assert!(selected.selected_result(true).unwrap());
    selected.mapped.as_mut().unwrap().selected = false;
    assert!(!selected.selected_result(false).unwrap());
}
