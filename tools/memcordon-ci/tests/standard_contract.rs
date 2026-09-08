use memcordon_ci::standard_contract::{LINUX, WINDOWS};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Floor {
    source_revision: String,
    scenarios: Vec<[String; 7]>,
}

#[test]
fn historical_standard_floor_is_an_independent_ordered_prefix() {
    let floor: Floor = toml::from_str(include_str!(
        "fixtures/standard-contract-floor-4589774.toml"
    ))
    .unwrap();
    assert_eq!(
        floor.source_revision,
        "458977466aeb36b47a51e002f06aa5c6bb9eb3a7"
    );
    assert_eq!(floor.scenarios.len(), 39);
    for (contract, baseline, total, ignored) in [(LINUX, 22, 23, 19), (WINDOWS, 17, 17, 12)] {
        let expected: Vec<_> = floor
            .scenarios
            .iter()
            .filter(|row| row[0] == contract.backend_name)
            .collect();
        assert_eq!(expected.len(), baseline);
        let actual = contract.results();
        assert_eq!(actual.len(), total);
        assert_eq!(
            actual.iter().filter(|row| row.ignored_selected).count(),
            ignored
        );
        let unique: std::collections::BTreeSet<_> = actual.iter().map(|row| &row.name).collect();
        assert_eq!(unique.len(), actual.len());
        for (old, new) in expected.into_iter().zip(&actual) {
            assert_eq!(new.name, old[1]);
            assert_eq!(new.package, old[2]);
            assert_eq!(new.required_features, [old[3].clone()]);
            assert_eq!(new.test_binary, old[4]);
            assert_eq!(new.exact_name, old[5]);
            assert_eq!(new.ignored_selected.to_string(), old[6]);
        }
        if total != baseline {
            assert_eq!(
                actual[baseline].name,
                "linux_standard_success_reports_guardian_started_before_authorization"
            );
        }
    }
}

#[test]
fn exact_standard_parser_rejects_missing_wrong_duplicate_and_ignored_tests() {
    use memcordon_ci::capability::require_exact_standard_test_success as parse;
    let good = "\nrunning 1 test\ntest actual ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 0.01s\n\n";
    assert!(parse(good.as_bytes(), "actual").is_ok());
    assert!(parse(good.replace('\n', "\r\n").as_bytes(), "actual").is_ok());
    assert!(parse(good.as_bytes(), "wrong").is_err());
    for bad in [
        good.replace("running 1 test", "running 0 tests"),
        good.replace("0 ignored", "1 ignored"),
        good.repeat(2),
        good.replace("test actual ... ok", "test actual ... ignored"),
        good.replace(
            "test actual ... ok",
            "test actual ... ok\ntest other ... ok",
        ),
        good.replace("test result: ok.", "test result: FAILED."),
        good.replace("0.01s", "NaNs"),
    ] {
        assert!(parse(bad.as_bytes(), "actual").is_err(), "{bad}");
    }
    assert!(parse(&[255], "actual").is_err());
}

#[test]
fn unit_state_and_atomic_promotion_fail_closed() {
    use memcordon_ci::standard_runner::{publish_candidate, read_bounded_regular, retired_state};
    assert!(retired_state(b"LoadState=not-found\nActiveState=inactive\n").unwrap());
    assert!(!retired_state(b"LoadState=loaded\nActiveState=active\n").unwrap());
    for invalid in [
        b"".as_slice(),
        b"ActiveState=inactive\n",
        b"LoadState=not-found\nActiveState=active\n",
        b"LoadState=loaded\nActiveState=inactive\nActiveState=inactive\n",
    ] {
        assert!(retired_state(invalid).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    let candidate = dir.path().join("candidate.json");
    let final_path = dir.path().join("report.json");
    std::fs::write(&candidate, b"checked\n").unwrap();
    let validated = read_bounded_regular(&candidate).unwrap();
    std::fs::write(&candidate, b"replacement\n").unwrap();
    publish_candidate(&candidate, &final_path, &validated).unwrap();
    assert_eq!(std::fs::read(&final_path).unwrap(), b"checked\n");
    assert!(!candidate.exists());
    std::fs::write(&candidate, b"new\n").unwrap();
    assert!(publish_candidate(&candidate, &final_path, b"new\n").is_err());
    assert_eq!(std::fs::read(&final_path).unwrap(), b"checked\n");
    let absent = dir.path().join("absent.json");
    let forbidden_final = dir.path().join("never.json");
    assert!(publish_candidate(&absent, &forbidden_final, b"new\n").is_err());
    assert!(!forbidden_final.exists());
}
