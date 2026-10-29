#[path = "../src/native_acceptance_catalogue.rs"]
mod catalogue;

use std::collections::BTreeSet;

#[test]
fn macos_native_catalogue_is_complete_and_unambiguous() {
    let macos = catalogue::macos_scenarios();
    let unique: BTreeSet<_> = macos.iter().copied().collect();
    assert_eq!(unique.len(), macos.len());
    assert!(unique.contains("installed_package_execution_probe_and_deadline"));
    assert!(unique.contains("public_frontend_preserves_sigterm_exec_policy"));
    assert_eq!(catalogue::MACOS_MUTATION_SCENARIOS.len(), 6);
    assert_eq!(catalogue::MACOS_ADMISSION_SCENARIOS.len(), 8);
}
