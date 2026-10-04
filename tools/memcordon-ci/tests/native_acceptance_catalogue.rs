#[path = "../src/native_acceptance_catalogue.rs"]
mod catalogue;

use std::collections::BTreeSet;

#[test]
fn product_native_catalogue_is_complete_and_unambiguous() {
    let linux: BTreeSet<_> = catalogue::LINUX_SEALED_TESTS.iter().copied().collect();
    assert_eq!(linux.len(), catalogue::LINUX_SEALED_TESTS.len());
    assert!(linux.contains("sealed_package_uninstall_refuses_live_authenticated_attempt"));
    assert!(linux.contains("sealed_guardian_loss_after_authorization_cannot_report_success"));

    let macos = catalogue::macos_scenarios();
    let unique: BTreeSet<_> = macos.iter().copied().collect();
    assert_eq!(unique.len(), macos.len());
    assert!(unique.contains("installed_package_execution_probe_and_deadline"));
    assert!(unique.contains("public_frontend_preserves_sigterm_exec_policy"));
    assert_eq!(catalogue::MACOS_MUTATION_SCENARIOS.len(), 6);
    assert_eq!(catalogue::MACOS_ADMISSION_SCENARIOS.len(), 8);
}
