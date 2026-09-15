//! Production fault injection and certification share this exact selector contract.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    FrontendLossBeforeAuthorization,
    FrontendLossAfterAuthorization,
    ProviderWorkerLossAfterGuardianCreation,
    GuardianLossBeforeAuthorization,
    GuardianLossAfterAuthorization,
    NamespaceInitFailureBeforeTarget,
    CgroupKillFailureAfterAuthorization,
    PersistentPopulatedAfterAuthorization,
    NamespaceInitReapDelayAfterAuthorization,
    GuardianReapFailureAfterAuthorization,
}

#[derive(Clone, Copy)]
pub struct ExpectedFaultEvidence {
    pub code: &'static str,
    pub phase: &'static str,
    pub target_created: bool,
    pub target_released: bool,
    pub cleanup_retired: bool,
    pub retirement_owner: &'static str,
    pub guardian_reaped: bool,
}

pub fn expected_fault_evidence(selector: &str) -> Option<ExpectedFaultEvidence> {
    let expected = match selector {
        "sealed_frontend_loss_before_authorization_never_runs_target" => ExpectedFaultEvidence {
            code: "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION",
            phase: "authorization",
            target_created: true,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "guardian",
            guardian_reaped: true,
        },
        "sealed_frontend_loss_after_authorization_triggers_guardian" => ExpectedFaultEvidence {
            code: "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION",
            phase: "monitoring",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "guardian",
            guardian_reaped: true,
        },
        "sealed_provider_worker_loss_triggers_guardian" => ExpectedFaultEvidence {
            code: "MCSEALED-PROVIDER-WORKER-LOSS",
            phase: "guardian-startup",
            target_created: false,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "guardian",
            guardian_reaped: true,
        },
        "sealed_guardian_loss_before_authorization_fails_closed" => ExpectedFaultEvidence {
            code: "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION",
            phase: "authorization",
            target_created: true,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_guardian_loss_after_authorization_cannot_report_success" => ExpectedFaultEvidence {
            code: "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION",
            phase: "monitoring",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_faults_before_authorization_never_create_marker" => ExpectedFaultEvidence {
            code: "MCSEALED-LAUNCH-DESCRIPTOR-SET",
            phase: "request-validation",
            target_created: false,
            target_released: false,
            cleanup_retired: false,
            retirement_owner: "provider",
            guardian_reaped: false,
        },
        "sealed_namespace_init_failure_is_typed_prompt_and_retired" => ExpectedFaultEvidence {
            code: "MCSEALED-NAMESPACE-INIT-TARGET-FORK",
            phase: "target-creation",
            target_created: false,
            target_released: false,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_cgroup_kill_failure_never_reports_retirement" => ExpectedFaultEvidence {
            code: "MCSEALED-CGROUP-KILL-FAILURE",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_persistent_populated_state_blocks_restart" => ExpectedFaultEvidence {
            code: "MCSEALED-CGROUP-NOT-EMPTY",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_namespace_init_reap_delay_blocks_result" => ExpectedFaultEvidence {
            code: "MCSEALED-NAMESPACE-INIT-REAP-DELAY",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        "sealed_guardian_reap_failure_blocks_result" => ExpectedFaultEvidence {
            code: "MCSEALED-GUARDIAN-REAP-FAILURE",
            phase: "retirement",
            target_created: true,
            target_released: true,
            cleanup_retired: true,
            retirement_owner: "provider",
            guardian_reaped: true,
        },
        _ => return None,
    };
    Some(expected)
}

#[derive(Clone, Copy, Debug)]
pub struct LinuxFaultScenario {
    pub id: &'static str,
    pub point: Option<FaultPoint>,
    pub selector: &'static str,
    pub class: &'static str,
    pub release_blocking: bool,
}

impl FaultPoint {
    pub const fn scenario(self) -> LinuxFaultScenario {
        match self {
            Self::FrontendLossBeforeAuthorization => LinuxFaultScenario {
                id: "FrontendLossBeforeAuthorization",
                point: Some(self),
                selector: "sealed_frontend_loss_before_authorization_never_runs_target",
                class: "crash",
                release_blocking: true,
            },
            Self::FrontendLossAfterAuthorization => LinuxFaultScenario {
                id: "FrontendLossAfterAuthorization",
                point: Some(self),
                selector: "sealed_frontend_loss_after_authorization_triggers_guardian",
                class: "crash",
                release_blocking: true,
            },
            Self::ProviderWorkerLossAfterGuardianCreation => LinuxFaultScenario {
                id: "ProviderWorkerLossAfterGuardianCreation",
                point: Some(self),
                selector: "sealed_provider_worker_loss_triggers_guardian",
                class: "crash",
                release_blocking: true,
            },
            Self::GuardianLossBeforeAuthorization => LinuxFaultScenario {
                id: "GuardianLossBeforeAuthorization",
                point: Some(self),
                selector: "sealed_guardian_loss_before_authorization_fails_closed",
                class: "crash",
                release_blocking: true,
            },
            Self::GuardianLossAfterAuthorization => LinuxFaultScenario {
                id: "GuardianLossAfterAuthorization",
                point: Some(self),
                selector: "sealed_guardian_loss_after_authorization_cannot_report_success",
                class: "crash",
                release_blocking: true,
            },
            Self::NamespaceInitFailureBeforeTarget => LinuxFaultScenario {
                id: "NamespaceInitFailureBeforeTarget",
                point: Some(self),
                selector: "sealed_namespace_init_failure_is_typed_prompt_and_retired",
                class: "fault",
                release_blocking: true,
            },
            Self::CgroupKillFailureAfterAuthorization => LinuxFaultScenario {
                id: "CgroupKillFailureAfterAuthorization",
                point: Some(self),
                selector: "sealed_cgroup_kill_failure_never_reports_retirement",
                class: "fault",
                release_blocking: true,
            },
            Self::PersistentPopulatedAfterAuthorization => LinuxFaultScenario {
                id: "PersistentPopulatedAfterAuthorization",
                point: Some(self),
                selector: "sealed_persistent_populated_state_blocks_restart",
                class: "fault",
                release_blocking: true,
            },
            Self::NamespaceInitReapDelayAfterAuthorization => LinuxFaultScenario {
                id: "NamespaceInitReapDelayAfterAuthorization",
                point: Some(self),
                selector: "sealed_namespace_init_reap_delay_blocks_result",
                class: "fault",
                release_blocking: true,
            },
            Self::GuardianReapFailureAfterAuthorization => LinuxFaultScenario {
                id: "GuardianReapFailureAfterAuthorization",
                point: Some(self),
                selector: "sealed_guardian_reap_failure_blocks_result",
                class: "fault",
                release_blocking: true,
            },
        }
    }
}

pub const DESCRIPTOR_SET_SCENARIO: LinuxFaultScenario = LinuxFaultScenario {
    id: "DescriptorSetBeforeAuthorization",
    point: None,
    selector: "sealed_faults_before_authorization_never_create_marker",
    class: "fault",
    release_blocking: true,
};

pub const LINUX_FAULT_SCENARIOS: &[LinuxFaultScenario] = &[
    FaultPoint::FrontendLossBeforeAuthorization.scenario(),
    FaultPoint::FrontendLossAfterAuthorization.scenario(),
    FaultPoint::ProviderWorkerLossAfterGuardianCreation.scenario(),
    FaultPoint::GuardianLossBeforeAuthorization.scenario(),
    FaultPoint::GuardianLossAfterAuthorization.scenario(),
    FaultPoint::NamespaceInitFailureBeforeTarget.scenario(),
    FaultPoint::CgroupKillFailureAfterAuthorization.scenario(),
    FaultPoint::PersistentPopulatedAfterAuthorization.scenario(),
    FaultPoint::NamespaceInitReapDelayAfterAuthorization.scenario(),
    FaultPoint::GuardianReapFailureAfterAuthorization.scenario(),
    DESCRIPTOR_SET_SCENARIO,
];
