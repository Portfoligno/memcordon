//! Separate decisions for provider-root controls and finite readiness coverage.
//! Native callers must establish original process/input association and closure;
//! serialized observations cannot create that ownership or replace those checks.
use crate::{
    windows_consumer_readiness::descriptor::matched::{
        Comparison, ComparisonOutcome, NativeStatusDomain, Scope,
    },
    windows_provider_projection_record::{OriginalSelection, OriginalSelectionState},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootPairClosure {
    Settled,
    SetupInvalid,
    CaptureIncomplete,
    OwnershipUncertain,
}

pub struct RootPairEvidence<'a> {
    pub listener: &'a Comparison,
    pub direct_selection: Option<&'a OriginalSelection>,
    pub installed_selection: Option<&'a OriginalSelection>,
    pub closure: RootPairClosure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootContractValidation {
    Validated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityAvailability {
    Available,
    Unavailable,
    Unobserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootCoverage {
    ListenerAndObservedSelection,
    PreciseNativeRefusal,
    OriginalApplicationRefusal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnmeasuredCoverage {
    Unmeasured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RootAssessment {
    pub contract_validation: RootContractValidation,
    pub listener_availability: CapabilityAvailability,
    /// Only the supplied, validated original mapping rows. This is neither
    /// private-listener feasibility nor full Joint coverage; absent rows are
    /// unobserved even when the original application refusal is validated.
    pub private_selection_availability: CapabilityAvailability,
    pub coverage: RootCoverage,
    pub peer_spawn_coverage: UnmeasuredCoverage,
    pub full_joint_coverage: UnmeasuredCoverage,
}

/// Prepared validation obligations, not universal host workload availability or
/// an assertion that the original application's native status must be zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoreObligation {
    PreparedStdio,
    PreparedFileIo,
    NativeInvocation,
    ApplicationStatusForwarding,
    LimitEnforcement,
    Admission,
    CallerEnvelope,
    DescendantContainment,
    NativeRetirement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementClass {
    CorePositive,
    ContextualWorkload,
}

pub fn required_case_keys() -> std::collections::BTreeSet<crate::windows_consumer_readiness::CaseKey>
{
    crate::windows_consumer_readiness::positive_keys()
}

pub fn core_obligation(key: &crate::windows_consumer_readiness::CaseKey) -> Option<CoreObligation> {
    use CoreObligation::*;
    match (key.family.as_str(), key.scenario.as_str()) {
        ("C-IO", "empty-input" | "binary-streams" | "bounded-large-output")
        | (
            "W-IO",
            "empty-stdout-stderr"
            | "embedded-nul"
            | "all-bytes"
            | "invalid-utf8"
            | "final-fragment"
            | "backpressure-separated-streams",
        ) => Some(PreparedStdio),
        ("C-IO", "binary-file") | ("W-IO", "empty-file" | "binary-file") => Some(PreparedFileIo),
        ("C-IO", "native-argv")
        | (
            "W-IO",
            "argv-empty" | "argv-whitespace" | "argv-quotes" | "argv-backslashes" | "argv-unicode"
            | "argv-path",
        ) => Some(NativeInvocation),
        (
            "C-STATUS",
            "zero" | "nonzero" | "exit-123" | "exit-124" | "exit-125" | "exit-126" | "exit-127",
        )
        | (
            "W-STATUS",
            "zero" | "nonzero" | "exit-123" | "exit-124" | "exit-125" | "exit-126" | "exit-127"
            | "target-failure",
        ) => Some(ApplicationStatusForwarding),
        ("C-STATUS" | "W-STATUS", "deadline" | "memory") => Some(LimitEnforcement),
        ("C-PARSER", "valid-current-result")
        | ("C-ADMISSION", "positive")
        | ("W-UPGRADE", "fresh-positive") => Some(Admission),
        ("W-BINDING", "effective-caller-token" | "restricted-token-preserved")
        | ("W-ENVELOPE", "ordinary" | "restricted" | "sentinel-handles") => Some(CallerEnvelope),
        ("C-LIFETIME", "root-first")
        | (
            "W-DESCENDANT",
            "root-first" | "intermediate-parent-first" | "nested-job" | "breakaway-denial",
        ) => Some(DescendantContainment),
        ("W-RETIREMENT", "natural" | "output-backpressure") => Some(NativeRetirement),
        _ => None,
    }
}

pub fn requirement_class(
    key: &crate::windows_consumer_readiness::CaseKey,
) -> Option<RequirementClass> {
    if core_obligation(key).is_some() {
        return Some(RequirementClass::CorePositive);
    }
    match (key.family.as_str(), key.scenario.as_str()) {
        ("C-IO" | "W-IO", "empty-message")
        | ("W-JOINT", "ordinary" | "restricted" | "endpoint-mismatch")
        | ("W-TOOLCHAIN", "ordinary" | "restricted")
        | ("W-CHURN", "natural-4096-three-generations")
        | ("W-DESCENDANT", "allowed-token-change") => Some(RequirementClass::ContextualWorkload),
        _ => None,
    }
}

pub fn supports_listener_refusal(key: &crate::windows_consumer_readiness::CaseKey) -> bool {
    matches!(
        (key.family.as_str(), key.scenario.as_str()),
        ("C-IO" | "W-IO", "empty-message")
            | ("W-JOINT", "ordinary" | "restricted" | "endpoint-mismatch")
            | ("W-CHURN", "natural-4096-three-generations")
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntrinsicContract {
    Unobserved,
    Validated,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonStatus {
    NotMeasured,
    MatchedSuccess,
    MatchedRefusal,
    Different,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExecutionDisposition {
    NotRun,
    /// Setup/execution was attempted without a completed validated outcome.
    /// This does not assert that a native target actually ran.
    Unvalidated,
    Completed,
    OriginalListenerRefusal {
        raw_os_error: i32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidence {
    pub association: memcordon_core::execution_facts::ProviderAttemptAssociationV1,
    /// Canonical workload contract digest; the association separately binds
    /// the complete native provider launch request.
    pub workload_request_sha256: memcordon_core::DiagnosticSha256,
    pub root: memcordon_core::execution_facts::NativeProcessV2,
    pub descriptor_sha256: memcordon_core::DiagnosticSha256,
    pub result_sha256: memcordon_core::DiagnosticSha256,
    pub stdout_sha256: memcordon_core::DiagnosticSha256,
    pub stderr_sha256: memcordon_core::DiagnosticSha256,
    pub transcript_sha256: memcordon_core::DiagnosticSha256,
    pub terminal_observation_sha256: memcordon_core::DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseContract {
    pub intrinsic: IntrinsicContract,
    pub comparison: ComparisonStatus,
    pub execution: ExecutionDisposition,
    pub evidence: Option<ExecutionEvidence>,
}

impl CaseContract {
    pub fn not_run() -> Self {
        Self {
            intrinsic: IntrinsicContract::Unobserved,
            comparison: ComparisonStatus::NotMeasured,
            execution: ExecutionDisposition::NotRun,
            evidence: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageKind {
    CoreCompleted,
    ContextualCompleted,
    ObservedListenerPrefix,
    Unmeasured,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub listener: CapabilityAvailability,
    pub tcp_exchange: CapabilityAvailability,
    pub pipe_message: CapabilityAvailability,
    pub compiler: CapabilityAvailability,
    pub provider_selection: CapabilityAvailability,
    pub descendants: CapabilityAvailability,
    pub full_joint: CapabilityAvailability,
}

impl Capabilities {
    fn unobserved() -> Self {
        Self {
            listener: CapabilityAvailability::Unobserved,
            tcp_exchange: CapabilityAvailability::Unobserved,
            pipe_message: CapabilityAvailability::Unobserved,
            compiler: CapabilityAvailability::Unobserved,
            provider_selection: CapabilityAvailability::Unobserved,
            descendants: CapabilityAvailability::Unobserved,
            full_joint: CapabilityAvailability::Unobserved,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseCoverage {
    pub key: crate::windows_consumer_readiness::CaseKey,
    pub kind: CoverageKind,
    pub obligation: Option<CoreObligation>,
    pub capabilities: Capabilities,
    pub evidence: Option<ExecutionEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseFailure {
    pub key: Option<crate::windows_consumer_readiness::CaseKey>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SuiteDecision {
    Validated {
        coverage: Vec<CaseCoverage>,
        unavailable_cases: Vec<crate::windows_consumer_readiness::CaseKey>,
    },
    Rejected {
        coverage: Vec<CaseCoverage>,
        failures: Vec<CaseFailure>,
        missing_core_coverage: Vec<crate::windows_consumer_readiness::CaseKey>,
    },
}

impl SuiteDecision {
    pub fn is_validated(&self) -> bool {
        matches!(self, Self::Validated { .. })
    }
}

fn derived_coverage(
    key: &crate::windows_consumer_readiness::CaseKey,
    execution: ExecutionDisposition,
) -> CaseCoverage {
    let obligation = core_obligation(key);
    let mut result = CaseCoverage {
        key: key.clone(),
        kind: CoverageKind::Unmeasured,
        obligation,
        capabilities: Capabilities::unobserved(),
        evidence: None,
    };
    match execution {
        ExecutionDisposition::NotRun | ExecutionDisposition::Unvalidated => {}
        ExecutionDisposition::OriginalListenerRefusal { .. } => {
            result.kind = CoverageKind::ObservedListenerPrefix;
            result.capabilities.listener = CapabilityAvailability::Unavailable;
        }
        ExecutionDisposition::Completed => {
            result.kind = if obligation.is_some() {
                CoverageKind::CoreCompleted
            } else {
                CoverageKind::ContextualCompleted
            };
            match (key.family.as_str(), key.scenario.as_str()) {
                ("C-IO" | "W-IO", "empty-message")
                | ("W-JOINT", "ordinary" | "restricted")
                | ("W-CHURN", "natural-4096-three-generations") => {
                    result.capabilities.listener = CapabilityAvailability::Available;
                    result.capabilities.tcp_exchange = CapabilityAvailability::Available;
                    result.capabilities.pipe_message = CapabilityAvailability::Available;
                    result.capabilities.compiler = CapabilityAvailability::Available;
                    result.capabilities.descendants = CapabilityAvailability::Available;
                    result.capabilities.full_joint = CapabilityAvailability::Available;
                }
                ("W-JOINT", "endpoint-mismatch") => {
                    result.capabilities.listener = CapabilityAvailability::Available
                }
                ("W-TOOLCHAIN", "ordinary" | "restricted") => {
                    result.capabilities.compiler = CapabilityAvailability::Available
                }
                ("C-LIFETIME", "root-first")
                | (
                    "W-DESCENDANT",
                    "root-first" | "intermediate-parent-first" | "allowed-token-change",
                ) => result.capabilities.descendants = CapabilityAvailability::Available,
                _ => {}
            }
        }
    }
    result
}

/// The native adapter must construct Validated only after its original owned
/// result, context, complete capture and settlement checks. These digest joins
/// preserve that association; this pure assessment cannot create native owners.
fn validate_case(
    record: &crate::windows_consumer_readiness::CaseAssessment,
) -> Result<CaseCoverage, &'static str> {
    use crate::windows_consumer_readiness::CASE_ASSESSMENT_REVISION;
    let class = requirement_class(&record.key).ok_or("unknown readiness catalogue identity")?;
    let contract = &record.contract;
    if record.revision != CASE_ASSESSMENT_REVISION
        || record.behavior.is_err()
        || record.collection.is_err()
        || record.retirement.is_err()
        || contract.intrinsic != IntrinsicContract::Validated
    {
        return Err("case validation, collection or ownership is incomplete");
    }
    let evidence = contract
        .evidence
        .as_ref()
        .ok_or("case original execution association absent")?;
    if !evidence.association.provider.is_consistent()
        || evidence.root.pid == 0
        || evidence.root.birth == 0
    {
        return Err("case original provider or root identity invalid");
    }
    let joins = [
        (
            &evidence.association.request_sha256,
            record.provider_request_sha256.as_deref(),
        ),
        (
            &evidence.descriptor_sha256,
            Some(record.descriptor_sha256.as_str()),
        ),
        (
            &evidence.workload_request_sha256,
            record.request_sha256.as_deref(),
        ),
        (&evidence.result_sha256, record.result_sha256.as_deref()),
        (&evidence.stdout_sha256, record.stdout_sha256.as_deref()),
        (&evidence.stderr_sha256, record.stderr_sha256.as_deref()),
        (
            &evidence.transcript_sha256,
            record.transcript_sha256.as_deref(),
        ),
        (
            &evidence.terminal_observation_sha256,
            record.terminal_observation_sha256.as_deref(),
        ),
    ];
    if joins.iter().any(|(expected, actual)| {
        actual.is_none_or(|actual| actual != String::from((*expected).clone()))
    }) {
        return Err("case original execution evidence digest differs or capture absent");
    }
    match (contract.execution, contract.comparison) {
        (
            ExecutionDisposition::Completed,
            ComparisonStatus::NotMeasured | ComparisonStatus::MatchedSuccess,
        ) => {}
        (
            ExecutionDisposition::OriginalListenerRefusal { .. },
            ComparisonStatus::NotMeasured | ComparisonStatus::MatchedRefusal,
        ) if class == RequirementClass::ContextualWorkload
            && supports_listener_refusal(&record.key) => {}
        _ => return Err("case execution or scheduled comparison is unvalidated"),
    }
    Ok(derived_coverage(&record.key, contract.execution))
}

pub fn assess_suite(
    records: &[crate::windows_consumer_readiness::CaseAssessment],
) -> SuiteDecision {
    use std::collections::BTreeSet;
    let required = required_case_keys();
    let mut seen = BTreeSet::new();
    let mut origins = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut core = BTreeSet::new();
    let mut coverage = Vec::new();
    let mut unavailable_cases = Vec::new();
    let mut failures = Vec::new();
    for record in records {
        let result = if !required.contains(&record.key) {
            Err("unknown readiness catalogue identity")
        } else if !seen.insert(record.key.clone()) {
            Err("duplicate readiness catalogue identity")
        } else {
            validate_case(record)
        };
        match result {
            Ok(mut measured) => {
                let evidence = record
                    .contract
                    .evidence
                    .as_ref()
                    .expect("validated case has original evidence");
                let provider = serde_json::to_string(&evidence.association.provider)
                    .expect("fixed provider fields serialize");
                let fresh_origin =
                    origins.insert((provider, *evidence.association.attempt_id.bytes()));
                let fresh_root = roots.insert((evidence.root.pid, evidence.root.birth));
                if !fresh_origin || !fresh_root {
                    failures.push(CaseFailure {
                        key: Some(record.key.clone()),
                        reason: "original attempt or root reused as another case witness".into(),
                    });
                    coverage.push(derived_coverage(&record.key, ExecutionDisposition::NotRun));
                    continue;
                }
                measured.evidence = Some(evidence.clone());
                if measured.kind == CoverageKind::CoreCompleted {
                    core.insert(record.key.clone());
                }
                if measured.kind == CoverageKind::ObservedListenerPrefix {
                    unavailable_cases.push(record.key.clone());
                }
                coverage.push(measured);
            }
            Err(reason) => {
                failures.push(CaseFailure {
                    key: Some(record.key.clone()),
                    reason: reason.into(),
                });
                coverage.push(derived_coverage(&record.key, ExecutionDisposition::NotRun));
            }
        }
    }
    for key in required.difference(&seen) {
        failures.push(CaseFailure {
            key: Some(key.clone()),
            reason: "required readiness case not assessed".into(),
        });
        coverage.push(derived_coverage(key, ExecutionDisposition::NotRun));
    }
    let missing_core_coverage = required
        .iter()
        .filter(|key| core_obligation(key).is_some() && !core.contains(*key))
        .cloned()
        .collect::<Vec<_>>();
    if failures.is_empty() && missing_core_coverage.is_empty() {
        SuiteDecision::Validated {
            coverage,
            unavailable_cases,
        }
    } else {
        SuiteDecision::Rejected {
            coverage,
            failures,
            missing_core_coverage,
        }
    }
}

/// A validated refusal preserves an unavailable operation; it does not rewrite
/// application status or establish positive listener, child or full-Joint work.
pub fn assess_root_pair(evidence: RootPairEvidence<'_>) -> Result<RootAssessment, String> {
    if evidence.closure != RootPairClosure::Settled {
        return Err("provider root setup, capture or native ownership is unproved".into());
    }
    if evidence.listener.scope != Scope::ProviderListenerSelection
        || evidence.listener.native_status_domain != NativeStatusDomain::PerOperation
    {
        return Err("provider root assessment requires its exact measured scope".into());
    }
    let (listener_availability, private_selection_availability, coverage) =
        match evidence.listener.outcome {
            ComparisonOutcome::DifferentOutcome => {
                return Err("provider root native behavior differs".into());
            }
            ComparisonOutcome::SameObservedFailure => {
                if evidence.direct_selection.is_some() || evidence.installed_selection.is_some() {
                    return Err(
                        "stopped provider root cannot assert complete selection coverage".into(),
                    );
                }
                (
                    CapabilityAvailability::Unavailable,
                    CapabilityAvailability::Unobserved,
                    RootCoverage::PreciseNativeRefusal,
                )
            }
            ComparisonOutcome::SameOriginalApplicationFailure
                if evidence.direct_selection.is_none()
                    && evidence.installed_selection.is_none() =>
            {
                (
                    CapabilityAvailability::Unavailable,
                    CapabilityAvailability::Unobserved,
                    RootCoverage::OriginalApplicationRefusal,
                )
            }
            ComparisonOutcome::ScopeSuccess | ComparisonOutcome::SameOriginalApplicationFailure => {
                let direct = evidence
                    .direct_selection
                    .ok_or("direct original provider selection absent")?;
                let installed = evidence
                    .installed_selection
                    .ok_or("installed original provider selection absent")?;
                if direct.peer()
                    || installed.peer()
                    || (direct.pid(), direct.birth()) == (installed.pid(), installed.birth())
                {
                    return Err(
                        "provider root observations do not identify distinct original roots".into(),
                    );
                }
                let mut left = direct.rows().iter().collect::<Vec<_>>();
                let mut right = installed.rows().iter().collect::<Vec<_>>();
                left.sort_by(|a, b| {
                    a.private_input
                        .original_path
                        .cmp(&b.private_input.original_path)
                });
                right.sort_by(|a, b| {
                    a.private_input
                        .original_path
                        .cmp(&b.private_input.original_path)
                });
                if left.is_empty()
                    || left.len() != right.len()
                    || left.iter().zip(&right).any(|(a, b)| {
                        a.private_input != b.private_input
                            || a.state != b.state
                            || a.mapped_path_utf16 != b.mapped_path_utf16
                    })
                {
                    return Err(
                        "provider root selection or exact shared input observation differs".into(),
                    );
                }
                // Bases, thread ids and sequence numbers remain per-lane facts.
                // Matching native path text does not prove host-file identity.
                let private = left
                    .iter()
                    .all(|row| row.state == OriginalSelectionState::PrivateSelected);
                (
                    if evidence.listener.outcome == ComparisonOutcome::ScopeSuccess {
                        CapabilityAvailability::Available
                    } else {
                        CapabilityAvailability::Unavailable
                    },
                    if private {
                        CapabilityAvailability::Available
                    } else {
                        CapabilityAvailability::Unavailable
                    },
                    if evidence.listener.outcome == ComparisonOutcome::ScopeSuccess {
                        RootCoverage::ListenerAndObservedSelection
                    } else {
                        RootCoverage::OriginalApplicationRefusal
                    },
                )
            }
        };
    Ok(RootAssessment {
        contract_validation: RootContractValidation::Validated,
        listener_availability,
        private_selection_availability,
        coverage,
        peer_spawn_coverage: UnmeasuredCoverage::Unmeasured,
        full_joint_coverage: UnmeasuredCoverage::Unmeasured,
    })
}
