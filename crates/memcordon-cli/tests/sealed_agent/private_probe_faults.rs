#![cfg(target_os = "linux")]

use crate::linux::private_probe_faults::{
    RequiredFaultObservationV1 as Proof, required_fault_observations,
};
use crate::linux::private_qualification::ProbeFixtureKindV1 as Case;

#[test]
fn frontend_and_guardian_loss_each_need_native_terminal_and_retirement() {
    assert_eq!(
        required_fault_observations(Case::FrontendGuardianLossRetirement).unwrap(),
        &[
            Proof::FrontendLossNativeTerminal,
            Proof::FrontendLossRetirement,
            Proof::GuardianLossNativeTerminal,
            Proof::GuardianLossRetirement,
        ]
    );
}

#[test]
fn target_exec_failure_cannot_be_replaced_by_fixture_exit_failure() {
    assert_eq!(
        required_fault_observations(Case::TargetExecFailureRetirement).unwrap(),
        &[
            Proof::RejectedTargetExecveat,
            Proof::FailedExecNativeTerminal,
            Proof::FailedExecRetirement,
        ]
    );
}

#[test]
fn baseline_unix_case_requires_v1_owner_not_private_v4_success() {
    assert_eq!(
        required_fault_observations(Case::BaselineUnixSuccessRetirement).unwrap(),
        &[Proof::BaselineV1UnixExecution, Proof::BaselineV1Retirement]
    );
}

#[test]
fn successful_private_cases_cannot_enter_fault_adapter() {
    for case in [
        Case::DescriptorIdentityFilterNamespace,
        Case::NamespacePortSysctlIsolation,
        Case::TcpListenerClientCompetitor,
        Case::UnixCreationSocketpairDenial,
        Case::WrongFamilyProtocolDenial,
    ] {
        assert!(required_fault_observations(case).is_err());
    }
}
