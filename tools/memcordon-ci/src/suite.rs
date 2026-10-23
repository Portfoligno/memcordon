use crate::{CiError, Result, failure_mode::FailureMode};

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum Suite {
    WorkspaceFetch,
    FuzzFetch,
    PrepareTools,
    PrepareFuzz,
    PrepareMiriComponents,
    MiriSetup,
    ReleaseBuild,
    ReleaseCompile,
    ReleaseValidatePackage,
    ReleaseReadiness,
    WorkingWindowsPrepare,
    RehearsalToolBuild,
    Policy,
    Quality,
    QualityCompile,
    QualityCompiler,
    ReleaseQualityCompiler,
    QualityDocumentation,
    Msrv,
    Native,
    NativeCompile,
    NativeExecute,
    SupplyChain,
    SupplyAudit,
    SupplyDeny,
    SupplyAuditPrepare,
    SupplyAuditCheck,
    SupplyDenyPrepare,
    SupplyDenyCheck,
    Miri,
    MiriFirst,
    MiriSecond,
    MiriQuarterOne,
    MiriQuarterTwo,
    MiriQuarterThree,
    MiriQuarterFour,
    Fuzz,
    FuzzFirst,
    FuzzSecond,
    FuzzQuarterOne,
    FuzzQuarterTwo,
    FuzzQuarterThree,
    FuzzQuarterFour,
    FuzzCompileFirst,
    FuzzCompileSecond,
    FuzzCompileQuarterOne,
    FuzzCompileQuarterTwo,
    FuzzCompileQuarterThree,
    FuzzCompileQuarterFour,
    FuzzExecuteFirst,
    FuzzExecuteSecond,
    FuzzExecuteQuarterOne,
    FuzzExecuteQuarterTwo,
    FuzzExecuteQuarterThree,
    FuzzExecuteQuarterFour,
    Stress,
    StressPackages,
    StressLifecycle,
    BackendLinuxCgroup,
    BackendLinuxPrivate,
    BackendLinuxPrivatePrepare,
    BackendLinuxPrivateRuntime,
    BackendWindowsJob,
    BackendWindowsSealed,
    BackendMacosWatchdog,
    ReleaseMacosNative,
    ReleaseMacosAcceptance,
    MacosDeadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuiteFailurePolicy {
    FixedStop,
    Adaptive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeRequest {
    Workflow(FailureMode),
    Explicit(FailureMode),
}

impl Suite {
    pub const fn failure_policy(self) -> SuiteFailurePolicy {
        use Suite::*;
        match self {
            WorkspaceFetch
            | FuzzFetch
            | PrepareMiriComponents
            | MiriSetup
            | WorkingWindowsPrepare
            | RehearsalToolBuild
            | Policy
            | Stress
            | StressPackages
            | StressLifecycle
            | BackendLinuxCgroup
            | BackendLinuxPrivate
            | BackendLinuxPrivatePrepare
            | BackendLinuxPrivateRuntime
            | BackendWindowsJob
            | BackendWindowsSealed
            | BackendMacosWatchdog
            | ReleaseMacosNative
            | ReleaseMacosAcceptance
            | MacosDeadline => SuiteFailurePolicy::FixedStop,
            PrepareTools
            | PrepareFuzz
            | ReleaseBuild
            | ReleaseCompile
            | ReleaseValidatePackage
            | ReleaseReadiness
            | Quality
            | QualityCompile
            | QualityCompiler
            | ReleaseQualityCompiler
            | QualityDocumentation
            | Msrv
            | Native
            | NativeCompile
            | NativeExecute
            | SupplyChain
            | SupplyAudit
            | SupplyDeny
            | SupplyAuditPrepare
            | SupplyAuditCheck
            | SupplyDenyPrepare
            | SupplyDenyCheck
            | Miri
            | MiriFirst
            | MiriSecond
            | MiriQuarterOne
            | MiriQuarterTwo
            | MiriQuarterThree
            | MiriQuarterFour
            | Fuzz
            | FuzzFirst
            | FuzzSecond
            | FuzzQuarterOne
            | FuzzQuarterTwo
            | FuzzQuarterThree
            | FuzzQuarterFour
            | FuzzCompileFirst
            | FuzzCompileSecond
            | FuzzCompileQuarterOne
            | FuzzCompileQuarterTwo
            | FuzzCompileQuarterThree
            | FuzzCompileQuarterFour
            | FuzzExecuteFirst
            | FuzzExecuteSecond
            | FuzzExecuteQuarterOne
            | FuzzExecuteQuarterTwo
            | FuzzExecuteQuarterThree
            | FuzzExecuteQuarterFour => SuiteFailurePolicy::Adaptive,
        }
    }

    pub fn resolve_failure_mode(self, request: ModeRequest) -> Result<FailureMode> {
        match (self.failure_policy(), request) {
            (SuiteFailurePolicy::Adaptive, ModeRequest::Workflow(mode))
            | (SuiteFailurePolicy::Adaptive, ModeRequest::Explicit(mode)) => Ok(mode),
            (SuiteFailurePolicy::FixedStop, ModeRequest::Workflow(_))
            | (
                SuiteFailurePolicy::FixedStop,
                ModeRequest::Explicit(FailureMode::StopAfterFailure),
            ) => Ok(FailureMode::StopAfterFailure),
            (SuiteFailurePolicy::FixedStop, ModeRequest::Explicit(FailureMode::CollectAll)) => Err(
                CiError::Message(format!("suite {self:?} requires stop-after-failure")),
            ),
        }
    }
}
