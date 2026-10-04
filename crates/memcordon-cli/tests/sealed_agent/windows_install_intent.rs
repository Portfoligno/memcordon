use crate::windows::package::{InstallIntent, InstallSessionBrokerFault};
use crate::windows::service_manager::SessionBrokerConfigurationFault;

fn broker_faults() -> [InstallSessionBrokerFault; 5] {
    [
        InstallSessionBrokerFault::AfterRegistration,
        InstallSessionBrokerFault::Configuration(
            SessionBrokerConfigurationFault::AfterRequiredPrivileges,
        ),
        InstallSessionBrokerFault::Configuration(SessionBrokerConfigurationFault::AfterSidType),
        InstallSessionBrokerFault::Configuration(
            SessionBrokerConfigurationFault::AfterFailureActions,
        ),
        InstallSessionBrokerFault::Configuration(
            SessionBrokerConfigurationFault::AfterSecurityApply,
        ),
    ]
}

#[test]
fn test_owned_install_fault_preserves_exact_native_transition() {
    for fault in broker_faults() {
        assert_eq!(
            InstallIntent::NativeFault(fault).session_broker_fault(),
            Some(fault)
        );
    }
}

#[test]
fn ordinary_install_has_no_native_fault() {
    assert_eq!(InstallIntent::Normal.session_broker_fault(), None);
}
