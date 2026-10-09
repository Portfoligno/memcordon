use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum RequiredLifecycle {
    PreAuthorization,
    Authorized,
    EitherDeadlinePath,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ObservedLifecycle {
    PreAuthorizationExpired,
    AuthorizedExpired,
    AuthorizedBeforeFrontendLoss,
}
impl RequiredLifecycle {
    pub(super) fn accepts(self, observed: ObservedLifecycle) -> bool {
        matches!(
            (self, observed),
            (
                Self::EitherDeadlinePath,
                ObservedLifecycle::PreAuthorizationExpired | ObservedLifecycle::AuthorizedExpired
            ) | (
                Self::PreAuthorization,
                ObservedLifecycle::PreAuthorizationExpired
            ) | (
                Self::Authorized,
                ObservedLifecycle::AuthorizedExpired
                    | ObservedLifecycle::AuthorizedBeforeFrontendLoss
            )
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum WorkBudget {
    Unbounded,
    Zero,
    Tight,
    StartupQualified,
}
impl WorkBudget {
    pub(super) fn token(self) -> Option<&'static str> {
        match self {
            Self::Unbounded => None,
            Self::Zero => Some("+0ms"),
            Self::Tight => Some("+250ms"),
            Self::StartupQualified => Some("+3s"),
        }
    }
    pub(super) fn duration(self) -> Option<Duration> {
        match self {
            Self::Unbounded => None,
            Self::Zero => Some(Duration::ZERO),
            Self::Tight => Some(Duration::from_millis(250)),
            Self::StartupQualified => Some(Duration::from_secs(3)),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub(super) enum ExpectedExit {
    Code(i32),
    Signal(i32),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FixtureMode {
    Ordinary,
    BlockedStderr,
}
impl FixtureMode {
    pub(super) fn argument(self) -> &'static str {
        match self {
            Self::Ordinary => "sleep",
            Self::BlockedStderr => "blocked-stderr",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InjectedFault {
    StopFrontend,
    KillFrontend,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct ScenarioSpec {
    pub(super) name: &'static str,
    pub(super) fixture: FixtureMode,
    pub(super) budget: WorkBudget,
    pub(super) required_lifecycle: RequiredLifecycle,
    pub(super) startup_gate: Option<Duration>,
    pub(super) outer_bound: Duration,
    pub(super) expected_exit: ExpectedExit,
    pub(super) injected_fault: Option<InjectedFault>,
}
pub(super) const SCENARIOS: &[ScenarioSpec] = &[
    ScenarioSpec {
        name: "deadline",
        fixture: FixtureMode::Ordinary,
        budget: WorkBudget::Tight,
        required_lifecycle: RequiredLifecycle::EitherDeadlinePath,
        startup_gate: None,
        outer_bound: Duration::from_secs(8),
        expected_exit: ExpectedExit::Code(123),
        injected_fault: None,
    },
    ScenarioSpec {
        name: "deadline-authorized",
        fixture: FixtureMode::Ordinary,
        budget: WorkBudget::StartupQualified,
        required_lifecycle: RequiredLifecycle::Authorized,
        startup_gate: Some(Duration::from_secs(2)),
        outer_bound: Duration::from_secs(8),
        expected_exit: ExpectedExit::Code(123),
        injected_fault: None,
    },
    ScenarioSpec {
        name: "zero-budget",
        fixture: FixtureMode::Ordinary,
        budget: WorkBudget::Zero,
        required_lifecycle: RequiredLifecycle::PreAuthorization,
        startup_gate: None,
        outer_bound: Duration::from_secs(8),
        expected_exit: ExpectedExit::Code(123),
        injected_fault: None,
    },
    ScenarioSpec {
        name: "frontend-stopped",
        fixture: FixtureMode::Ordinary,
        budget: WorkBudget::StartupQualified,
        required_lifecycle: RequiredLifecycle::Authorized,
        startup_gate: Some(Duration::from_secs(2)),
        outer_bound: Duration::from_secs(8),
        expected_exit: ExpectedExit::Code(123),
        injected_fault: Some(InjectedFault::StopFrontend),
    },
    ScenarioSpec {
        name: "frontend-loss",
        fixture: FixtureMode::Ordinary,
        budget: WorkBudget::Unbounded,
        required_lifecycle: RequiredLifecycle::Authorized,
        startup_gate: Some(Duration::from_secs(2)),
        outer_bound: Duration::from_secs(8),
        expected_exit: ExpectedExit::Signal(libc::SIGKILL),
        injected_fault: Some(InjectedFault::KillFrontend),
    },
    ScenarioSpec {
        name: "blocked-stderr",
        fixture: FixtureMode::BlockedStderr,
        budget: WorkBudget::StartupQualified,
        required_lifecycle: RequiredLifecycle::Authorized,
        startup_gate: Some(Duration::from_secs(2)),
        outer_bound: Duration::from_secs(12),
        expected_exit: ExpectedExit::Code(125),
        injected_fault: None,
    },
];
