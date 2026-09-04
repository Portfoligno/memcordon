use std::cell::RefCell;

use crate::windows::package::{
    InstallIntent, InstallSessionBrokerFault, establish_ephemeral_marker,
};
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
fn fresh_certification_requires_explicit_ephemeral_admission() {
    for fault in broker_faults() {
        let error = InstallIntent::ephemeral_certification(false, fault).unwrap_err();
        assert!(error.contains("MCSEALED-WINDOWS-CERTIFICATION-ADMISSION"));

        let intent = InstallIntent::ephemeral_certification(true, fault).unwrap();
        assert_eq!(
            intent.authorized_session_broker_fault(true).unwrap(),
            Some(fault)
        );
    }
}

#[test]
fn ordinary_install_intents_cannot_carry_a_broker_fault() {
    for intent in [InstallIntent::Normal, InstallIntent::Ephemeral] {
        assert_eq!(intent.authorized_session_broker_fault(true).unwrap(), None);
    }
}

#[test]
fn certification_marker_is_created_before_it_is_verified() {
    let events = RefCell::new(Vec::new());
    let intent =
        InstallIntent::ephemeral_certification(true, InstallSessionBrokerFault::AfterRegistration)
            .unwrap();

    establish_ephemeral_marker(
        intent,
        || {
            events.borrow_mut().push("create");
            Ok(())
        },
        || {
            events.borrow_mut().push("verify");
            true
        },
    )
    .unwrap();

    assert_eq!(*events.borrow(), ["create", "verify"]);
}

#[test]
fn invalidated_certification_marker_prevents_fault_injection() {
    let intent =
        InstallIntent::ephemeral_certification(true, InstallSessionBrokerFault::AfterRegistration)
            .unwrap();
    let preparation_error = establish_ephemeral_marker(intent, || Ok(()), || false).unwrap_err();
    assert!(preparation_error.contains("MCSEALED-WINDOWS-CERTIFICATION-AUTHORIZATION"));

    let injection_error = intent.authorized_session_broker_fault(false).unwrap_err();
    assert!(injection_error.contains("MCSEALED-WINDOWS-CERTIFICATION-AUTHORIZATION"));
}

#[test]
fn normal_install_does_not_create_or_verify_a_certification_marker() {
    establish_ephemeral_marker(
        InstallIntent::Normal,
        || panic!("normal install attempted to create an ephemeral marker"),
        || panic!("normal install attempted to verify an ephemeral marker"),
    )
    .unwrap();
}
