use super::finalize_with;
use crate::{CiError, work_outcome::WorkOutcome};

#[test]
fn action_cache_paths_present_verbatim_drives_and_unc_without_namespace_globs() {
    use std::path::{Path, PathBuf};
    for (native, expected) in [
        (
            r"\\?\C:\a\memcordon\target\ci-transfer\out\archives",
            "C:/a/memcordon/target/ci-transfer/out/archives",
        ),
        (r"\\?\d:\with space\café\index", "d:/with space/café/index"),
        (
            r"\\?\UNC\server\share\target\archives",
            "//server/share/target/archives",
        ),
        (r"C:\ordinary\target", r"C:\ordinary\target"),
        (r"\\server\share\ordinary", r"\\server\share\ordinary"),
        ("/tmp/native/target", "/tmp/native/target"),
        ("target/relative", "target/relative"),
    ] {
        let path = Path::new(native);
        assert_eq!(super::action_path(path).unwrap(), expected);
        assert_eq!(path.as_os_str(), native);
    }
    for unsupported in [
        r"\\?\GLOBALROOT\Device\HarddiskVolume1",
        r"\\?\C:relative",
        r"\\?\UNC\server",
        r"\\?\UNC\\share",
    ] {
        assert!(super::action_path(Path::new(unsupported)).is_err());
    }
    let native = [
        PathBuf::from(r"\\?\C:\a\archives"),
        PathBuf::from(r"\\?\C:\a\index"),
    ];
    assert_eq!(
        super::action_paths(&native).unwrap(),
        "C:/a/archives\nC:/a/index"
    );
    let temp = tempfile::NamedTempFile::new().unwrap();
    super::write_to(
        Some(temp.path()),
        &[("archives-path", super::action_path(&native[0]).unwrap())],
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(temp.path()).unwrap(),
        "archives-path=C:/a/archives\n"
    );
}

#[test]
fn optional_projection_preserves_only_actual_unresolved_owner_evidence() {
    use crate::work_outcome::{WriterSettlement, has_unresolved_owner};
    let unknown = WorkOutcome::<()>::observed(
        Err(CiError::Message("native reader did not settle".into())),
        WriterSettlement::Unknown,
    )
    .into_result()
    .unwrap_err();
    assert!(has_unresolved_owner(&unknown));
    let nested = CiError::LaneFailures {
        primary: Box::new(CiError::Message("unavailable input".into())),
        secondary: Box::new(unknown),
    };
    assert!(has_unresolved_owner(&nested));
    assert!(!has_unresolved_owner(&CiError::Message(
        "unavailable optional input".into()
    )));
    assert!(!has_unresolved_owner(&CiError::SettledCommandFailure(
        "probe exited".into()
    )));
}

#[test]
fn download_context_adapter_never_turns_an_unresolved_reader_into_quiescence() {
    use crate::{
        cache::OptionalCache,
        download_cache::{DownloadFamily, optional_context_result},
        work_outcome::WriterSettlement,
    };
    let unresolved = || {
        WorkOutcome::<crate::cache::CacheEntry>::observed(
            Err(CiError::Message("reader owner unresolved".into())),
            WriterSettlement::Unknown,
        )
        .into_result()
        .unwrap_err()
    };
    for error in [
        unresolved(),
        CiError::LaneFailures {
            primary: Box::new(CiError::Message("optional metadata absent".into())),
            secondary: Box::new(unresolved()),
        },
    ] {
        let selected = optional_context_result(DownloadFamily::Workspace, Err(error));
        let mut groups = Vec::new();
        let result = finalize_with(
            WorkOutcome::from_result(selected.map(|_| ())),
            || Ok(()),
            |values| {
                groups.extend(
                    values
                        .iter()
                        .map(|(key, value)| (key.to_string(), value.clone())),
                );
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(groups.contains(&("cache-quiescent".into(), "false".into())));
        assert!(!groups.iter().any(|(key, _)| key.ends_with("-populated")));
    }
    for error in [
        CiError::SettledCommandFailure("reader unavailable".into()),
        CiError::Message("unmodeled configuration".into()),
    ] {
        assert!(matches!(
            optional_context_result(DownloadFamily::Workspace, Err(error)).unwrap(),
            OptionalCache::Unavailable { .. }
        ));
    }
}

#[test]
fn completion_facts_can_be_revoked_before_a_later_writer() {
    let mut facts = crate::work_outcome::CompilationFacts::default();
    facts.establish("compiled-native-complete");
    assert_eq!(
        facts.outputs(),
        [("compiled-native-complete", "true".into())]
    );
    facts.revoke("compiled-native-complete");
    assert!(facts.outputs().is_empty());
}

#[test]
fn failed_population_append_still_attempts_settlement_and_facts() {
    struct PartialWriter(Vec<u8>);
    impl std::io::Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.0.is_empty() {
                return Err(std::io::Error::other("injected append failure"));
            }
            let prefix = bytes.split_at(bytes.len() / 2).0;
            self.0.extend_from_slice(prefix);
            Ok(prefix.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut partial = PartialWriter(Vec::new());
    let mut groups = Vec::new();
    let outcome = WorkOutcome::from_result(Ok(())).fact("compiled-native-complete");
    let result = finalize_with(
        outcome,
        || super::append_records(&mut partial, b"source-populated=true\n"),
        |values| {
            groups.push(
                values
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.clone()))
                    .collect::<Vec<_>>(),
            );
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!partial.0.is_empty());
    assert!(!partial.0.ends_with(b"\n"));
    assert_ne!(partial.0, b"source-populated=true\n");
    assert_eq!(groups[0], [("cache-quiescent".into(), "true".into())]);
    assert_eq!(
        groups[1],
        [("compiled-native-complete".into(), "true".into())]
    );
}

#[test]
fn independent_emission_keeps_failed_work_primary() {
    let mut attempts = 0;
    let outcome = WorkOutcome::from_result(Err(CiError::SettledCommandFailure(
        "actual compile failure".into(),
    )));
    let error = finalize_with(
        outcome,
        || Ok(()),
        |_| {
            attempts += 1;
            Err(CiError::Message("output append failed".into()))
        },
    )
    .unwrap_err();
    assert_eq!(attempts, 2);
    assert!(
        error
            .to_string()
            .starts_with("primary lane: primary lane: actual compile failure")
    );
}
