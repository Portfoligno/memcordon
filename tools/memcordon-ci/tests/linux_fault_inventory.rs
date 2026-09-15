use memcordon_core::linux_fault_contract::{LINUX_FAULT_SCENARIOS, expected_fault_evidence};

#[test]
fn every_linux_fault_is_exactly_once_in_release_certification() {
    for scenario in LINUX_FAULT_SCENARIOS {
        assert_eq!(
            memcordon_ci::release_evidence::LINUX_SEALED_TESTS
                .iter()
                .filter(|selector| **selector == scenario.selector)
                .count(),
            1,
            "fault {} must have exactly one release execution route",
            scenario.id
        );
        assert!(expected_fault_evidence(scenario.selector).is_some());
    }
}
