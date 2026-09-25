//! Proof requirements for host cases that cannot yet complete through the
//! protected native probe owner. No fault is simulated and no receipt is made.

use std::convert::Infallible;

use super::private_qualification::{ProbeCaseAuthority, ProbeFixtureKindV1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequiredFaultObservationV1 {
    FrontendLossNativeTerminal,
    FrontendLossRetirement,
    GuardianLossNativeTerminal,
    GuardianLossRetirement,
    RejectedTargetExecveat,
    FailedExecNativeTerminal,
    FailedExecRetirement,
    BaselineV1UnixExecution,
    BaselineV1Retirement,
}

const LOSS_PROOF: &[RequiredFaultObservationV1] = &[
    RequiredFaultObservationV1::FrontendLossNativeTerminal,
    RequiredFaultObservationV1::FrontendLossRetirement,
    RequiredFaultObservationV1::GuardianLossNativeTerminal,
    RequiredFaultObservationV1::GuardianLossRetirement,
];
const EXEC_FAILURE_PROOF: &[RequiredFaultObservationV1] = &[
    RequiredFaultObservationV1::RejectedTargetExecveat,
    RequiredFaultObservationV1::FailedExecNativeTerminal,
    RequiredFaultObservationV1::FailedExecRetirement,
];
const BASELINE_PROOF: &[RequiredFaultObservationV1] = &[
    RequiredFaultObservationV1::BaselineV1UnixExecution,
    RequiredFaultObservationV1::BaselineV1Retirement,
];

/// Exact native observations needed before these cases can produce a positive
/// protected completion. A fixture's own exit status is not any of this proof.
pub(crate) fn required_fault_observations(
    kind: ProbeFixtureKindV1,
) -> Result<&'static [RequiredFaultObservationV1], String> {
    match kind {
        ProbeFixtureKindV1::FrontendGuardianLossRetirement => Ok(LOSS_PROOF),
        ProbeFixtureKindV1::TargetExecFailureRetirement => Ok(EXEC_FAILURE_PROOF),
        ProbeFixtureKindV1::BaselineUnixSuccessRetirement => Ok(BASELINE_PROOF),
        _ => Err("MCSEALED-PRIVATE-PROBE-FAULT: case is not a fault or baseline case".into()),
    }
}

/// A move-only case authority is required even to reach this denial. Until
/// the protected owner exposes real loss/exec-failure and baseline V1 terminal
/// observations, the uninhabited success type makes a green completion
/// impossible. The caller must retain and recover any prior native state.
pub(crate) fn execute_unavailable_fault_case(
    case: &ProbeCaseAuthority<'_>,
) -> Result<Infallible, String> {
    case.revalidate()?;
    let required = required_fault_observations(case.kind())?;
    let unavailable = match case.kind() {
        ProbeFixtureKindV1::FrontendGuardianLossRetirement => {
            "protected frontend and guardian loss injection with two native terminal/retirement proofs"
        }
        ProbeFixtureKindV1::TargetExecFailureRetirement => {
            "protected rejected target execveat with native terminal and retirement proof"
        }
        ProbeFixtureKindV1::BaselineUnixSuccessRetirement => {
            "separate baseline V1 UNIX owner with native execution and retirement proof"
        }
        _ => unreachable!("required_fault_observations selected a closed fault case"),
    };
    if required.is_empty() {
        panic!("closed private fault case has no proof requirements");
    }
    Err(format!(
        "MCSEALED-PRIVATE-PROBE-FAULT: {} unavailable: {unavailable}",
        case.name()
    ))
}
