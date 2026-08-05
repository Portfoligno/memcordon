use memcordon_core::BackoffMultiplier;
use memcordon_core::test_support::logistic_scenario;

#[test]
fn multiplier_is_exact_reduced_and_bounded() {
    let multiplier: BackoffMultiplier = "2.50".parse().expect("valid multiplier");
    assert_eq!(multiplier.numerator(), 5);
    assert_eq!(multiplier.denominator(), 2);
    for invalid in ["", "1", "0.9", "100.1", "2e1", "+2", "-2", "2."] {
        assert!(invalid.parse::<BackoffMultiplier>().is_err(), "{invalid}");
    }
    assert!(BackoffMultiplier::new(2, 0).is_err());
}

#[test]
fn invalid_and_constant_logistic_policies_are_certified_through_the_facade() {
    let multiplier = "2".parse().expect("multiplier");
    assert!(logistic_scenario(0, multiplier, 30_000, 1).is_err());
    assert!(logistic_scenario(1_000, multiplier, 999, 1).is_err());
    assert_eq!(
        logistic_scenario(10, multiplier, 10, 4)
            .expect("constant sequence")
            .scheduled_millis,
        [10, 10, 10, 10]
    );
}
