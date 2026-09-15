#![cfg(all(target_os = "macos", feature = "test-support"))]

use memcordon_platform::test_support::macos_retirement_mutation_probe as probe;
use std::time::Duration;

#[test]
fn production_deadline_arithmetic_matches_independent_data_vectors() {
    use memcordon_platform::test_support::{
        macos_deadline_add_fixture, macos_retirement_remaining_fixture,
        macos_timebase_conversion_fixture,
    };
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../../spec/vectors/macos-deadline-v1.json")).unwrap();
    assert_eq!(data["schema_version"], 1);
    for case in data["timebase"].as_array().unwrap() {
        let actual = macos_timebase_conversion_fixture(
            case["ticks"].as_u64().unwrap(),
            u32::try_from(case["numerator"].as_u64().unwrap()).unwrap(),
            u32::try_from(case["denominator"].as_u64().unwrap()).unwrap(),
        );
        assert_eq!(actual.ok(), case["expected"].as_u64(), "{}", case["name"]);
    }
    for case in data["addition"].as_array().unwrap() {
        let actual = macos_deadline_add_fixture(
            case["origin"].as_u64().unwrap(),
            case["budget"].as_u64().unwrap(),
        );
        assert_eq!(actual.ok(), case["expected"].as_u64(), "{}", case["name"]);
    }
    for case in data["remaining"].as_array().unwrap() {
        let actual = macos_retirement_remaining_fixture(
            case["force"].as_u64().unwrap(),
            case["observed"].as_u64().unwrap(),
            case["reserve"].as_u64().unwrap(),
        );
        assert_eq!(actual.ok(), case["expected"].as_u64(), "{}", case["name"]);
    }
}

#[test]
fn mutation_expired_work_cleanup_clamp_is_detected() {
    // Detection is delayed by one second after work/force expiry. The original
    // retirement reserve still has two seconds; it cannot become zero or renew.
    let work = 10_000_000_000;
    let observed = 11_000_000_000;
    let expected = Duration::from_secs(2);
    assert_eq!(probe(work, observed, work, false).unwrap(), expected);
    assert_ne!(probe(work, observed, work, true).unwrap(), expected);
    assert_eq!(
        probe(work, 13_000_000_000, work, false).unwrap(),
        Duration::ZERO
    );
    assert!(probe(u64::MAX, observed, work, false).is_err());
}
