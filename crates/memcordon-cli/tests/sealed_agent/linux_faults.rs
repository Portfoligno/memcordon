use memcordon_core::linux_fault_contract::{
    FaultPoint, LINUX_FAULT_SCENARIOS, expected_fault_evidence,
};
use std::collections::BTreeSet;

#[test]
fn linux_fault_inventory_is_unique_complete_and_names_real_tests() {
    for point in [
        FaultPoint::FrontendLossBeforeAuthorization,
        FaultPoint::FrontendLossAfterAuthorization,
        FaultPoint::ProviderWorkerLossAfterGuardianCreation,
        FaultPoint::GuardianLossBeforeAuthorization,
        FaultPoint::GuardianLossAfterAuthorization,
        FaultPoint::NamespaceInitFailureBeforeTarget,
        FaultPoint::CgroupKillFailureAfterAuthorization,
        FaultPoint::PersistentPopulatedAfterAuthorization,
        FaultPoint::NamespaceInitReapDelayAfterAuthorization,
        FaultPoint::GuardianReapFailureAfterAuthorization,
    ] {
        assert_eq!(
            LINUX_FAULT_SCENARIOS
                .iter()
                .filter(|scenario| scenario.point == Some(point))
                .count(),
            1,
            "missing or duplicate provider fault: {point:?}"
        );
    }
    let source = include_str!("linux_sealed.rs");
    let functions: BTreeSet<_> = source
        .lines()
        .filter_map(|line| {
            line.strip_prefix("fn ")
                .and_then(|rest| rest.split_once('('))
                .map(|(name, _)| name)
        })
        .collect();
    let mut ids = BTreeSet::new();
    let mut selectors = BTreeSet::new();
    for scenario in LINUX_FAULT_SCENARIOS {
        assert!(
            ids.insert(scenario.id),
            "duplicate fault id: {}",
            scenario.id
        );
        assert!(
            selectors.insert(scenario.selector),
            "duplicate fault selector: {}",
            scenario.selector
        );
        assert!(
            functions.contains(scenario.selector),
            "missing Linux test: {}",
            scenario.selector
        );
        assert!(scenario.release_blocking);
        let expected = expected_fault_evidence(scenario.selector).expect("typed outcome contract");
        assert!(!expected.code.is_empty());
        assert!(!expected.phase.is_empty());
        if let Some(point) = scenario.point {
            // Exhaustiveness makes a newly introduced provider fault a compile error here
            // until it has a reviewed certification mapping.
            let expected_id = match point {
                FaultPoint::FrontendLossBeforeAuthorization => "FrontendLossBeforeAuthorization",
                FaultPoint::FrontendLossAfterAuthorization => "FrontendLossAfterAuthorization",
                FaultPoint::ProviderWorkerLossAfterGuardianCreation => {
                    "ProviderWorkerLossAfterGuardianCreation"
                }
                FaultPoint::GuardianLossBeforeAuthorization => "GuardianLossBeforeAuthorization",
                FaultPoint::GuardianLossAfterAuthorization => "GuardianLossAfterAuthorization",
                FaultPoint::NamespaceInitFailureBeforeTarget => "NamespaceInitFailureBeforeTarget",
                FaultPoint::CgroupKillFailureAfterAuthorization => {
                    "CgroupKillFailureAfterAuthorization"
                }
                FaultPoint::PersistentPopulatedAfterAuthorization => {
                    "PersistentPopulatedAfterAuthorization"
                }
                FaultPoint::NamespaceInitReapDelayAfterAuthorization => {
                    "NamespaceInitReapDelayAfterAuthorization"
                }
                FaultPoint::GuardianReapFailureAfterAuthorization => {
                    "GuardianReapFailureAfterAuthorization"
                }
            };
            assert_eq!(scenario.id, expected_id);
            #[cfg(all(target_os = "linux", feature = "test-support"))]
            {
                let provider_point: crate::linux::launch::FaultPoint = point;
                assert_eq!(provider_point.scenario().selector, scenario.selector);
            }
        }
    }
    assert!(expected_fault_evidence("unknown-fault").is_none());
}
