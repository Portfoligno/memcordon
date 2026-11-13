//! Complete retained evidence for one paired owned-file measurement.
use super::{
    descriptor::{
        matched,
        matched_plan::{DirectoryRole, Plan},
    },
    matched_control_input_record as input,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_BYTES: usize = 64 * 1024;
pub const REVISION: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimScope {
    OwnedFileOperationsAndSelectedToken,
    ListenerPrefix,
    ProviderListenerPrefixWithSharedInputs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeValidation {
    MatchedSuccess,
    MatchedNativeRefusal,
    MatchedApplicationRefusal,
    Mismatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeAvailability {
    Available,
    Unavailable,
    Unestablished,
}

pub fn scoped_assessment(
    comparison: &matched::Comparison,
) -> (ScopeValidation, NativeAvailability) {
    match (comparison.scope, comparison.outcome) {
        (_, matched::ComparisonOutcome::ScopeSuccess) => (
            ScopeValidation::MatchedSuccess,
            NativeAvailability::Available,
        ),
        (
            matched::Scope::JointListenerPrefix | matched::Scope::ProviderListenerSelection,
            matched::ComparisonOutcome::SameObservedFailure,
        ) => (
            ScopeValidation::MatchedNativeRefusal,
            NativeAvailability::Unavailable,
        ),
        (
            matched::Scope::JointListenerPrefix | matched::Scope::ProviderListenerSelection,
            matched::ComparisonOutcome::SameOriginalApplicationFailure,
        ) if comparison.native_status_domain == matched::NativeStatusDomain::PerOperation => (
            ScopeValidation::MatchedApplicationRefusal,
            NativeAvailability::Unavailable,
        ),
        _ => (ScopeValidation::Mismatch, NativeAvailability::Unestablished),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PairedStdioCoverage {
    NotAssessed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PositiveCoverage {
    Complete,
    Unestablished,
}

pub fn positive_coverage(comparison: &matched::Comparison) -> PositiveCoverage {
    if matches!(comparison.outcome, matched::ComparisonOutcome::ScopeSuccess) {
        PositiveCoverage::Complete
    } else {
        PositiveCoverage::Unestablished
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub source: input::TokenDetails,
    pub selected: input::TokenDetails,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Direct {
    pub pid: u32,
    pub birth: u64,
    pub native_status: u32,
    pub job_active_processes: u32,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: [u8; 32],
    pub stderr_sha256: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frontend {
    pub pid: u32,
    pub birth: u64,
    pub native_status: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub pid: u32,
    pub birth: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportOutcome {
    ScopeSuccess,
    SameObservedFailure,
    SameOriginalApplicationFailure,
    DifferentOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportComparison {
    pub outcome: ReportOutcome,
    pub scope: matched::Scope,
    pub native_status_domain: matched::NativeStatusDomain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub revision: u32,
    pub claim_scope: ClaimScope,
    pub validation: ScopeValidation,
    pub native_availability: NativeAvailability,
    pub paired_stdio: PairedStdioCoverage,
    pub positive_coverage: PositiveCoverage,
    pub physical_stream_security_equal: bool,
    pub scope: matched::Scope,
    pub pair_sha256: [u8; 32],
    pub broker: Actor,
    pub caller: Caller,
    pub direct: Direct,
    pub installed_frontend: Frontend,
    pub comparison: ReportComparison,
    pub direct_input: input::Readback,
    pub installed_input: input::Readback,
    pub direct_record: matched::Observation,
    pub installed_record: matched::Observation,
}

pub struct StreamEvidence {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

pub struct Expected {
    pub broker: (u32, u64),
    pub direct_target: Option<(u32, u64)>,
    pub direct_descriptor_sha256: [u8; 32],
    pub installed_descriptor_sha256: [u8; 32],
    pub installed_target: (u32, u64),
    pub frontend: (u32, u64),
    pub direct_stdout: StreamEvidence,
    pub direct_stderr: StreamEvidence,
}

pub fn decode(bytes: &[u8]) -> Result<Report, String> {
    if bytes.len() > MAX_BYTES {
        return Err("matched broker report exceeds64KiB".into());
    }
    let report: Report = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let wire: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if wire != serde_json::to_value(&report).map_err(|error| error.to_string())? {
        return Err("matched broker report has an unexpected or missing field".into());
    }
    if report.revision != REVISION {
        return Err("matched broker report revision differs".into());
    }
    Ok(report)
}

fn token_digest(token: &input::TokenDetails) -> Result<[u8; 32], String> {
    Ok(
        Sha256::digest(serde_json::to_vec(&token.envelope).map_err(|error| error.to_string())?)
            .into(),
    )
}

fn same_token_inputs(left: &input::TokenDetails, right: &input::TokenDetails) -> bool {
    left.envelope == right.envelope
        && left.expiration == right.expiration
        && left.group_count == right.group_count
        && left.privilege_count == right.privilege_count
        && left.default_acl_bytes == right.default_acl_bytes
        && left.default_acl_sha256 == right.default_acl_sha256
}

fn fixture_status(record: &matched::Observation) -> u32 {
    match record.terminal {
        matched::Terminal::CompletedScope => 0,
        matched::Terminal::FirstFailure { .. } => 2,
    }
}

/// Checks retained data against the original plan and independently held IDs and
/// streams. Runtime owners still perform direct Job and installed ACK settlement.
pub fn validate(
    report: &Report,
    plan: &Plan,
    expected: &Expected,
) -> Result<matched::Comparison, String> {
    match (&plan.provider, plan.scope) {
        (Some(provider), matched::Scope::ProviderListenerSelection) => {
            let output = |role| {
                plan.directories
                    .iter()
                    .find(|directory| directory.role == role)
                    .map(|directory| directory.path.as_path())
                    .ok_or("provider report output role absent")
            };
            provider.validate(
                output(DirectoryRole::DirectOutput)?,
                output(DirectoryRole::InstalledOutput)?,
            )?;
        }
        (None, scope) if scope != matched::Scope::ProviderListenerSelection => {}
        _ => return Err("provider report requires its exact shared input witnesses".into()),
    }
    if report.revision != REVISION
        || (plan.scope == matched::Scope::ProviderListenerSelection)
            != expected.direct_target.is_some()
        || expected
            .direct_target
            .is_some_and(|identity| identity != (report.direct.pid, report.direct.birth))
        || report.scope != plan.scope
        || report.pair_sha256 != plan.pair_sha256
        || report.direct.pid == 0
        || report.direct.birth == 0
        || expected.frontend.0 == 0
        || expected.frontend.1 == 0
        || expected.installed_target.0 == 0
        || expected.installed_target.1 == 0
        || expected.broker.0 == 0
        || expected.broker.1 == 0
        || (report.broker.pid, report.broker.birth) != expected.broker
        || (report.direct.pid, report.direct.birth) == expected.broker
        || expected.frontend == expected.broker
        || expected.installed_target == expected.broker
        || (report.direct.pid, report.direct.birth) == expected.frontend
        || expected.frontend == expected.installed_target
        || (
            report.installed_frontend.pid,
            report.installed_frontend.birth,
        ) != expected.frontend
        || report.direct.job_active_processes != 0
        || report.direct.native_status != fixture_status(&report.direct_record)
        || report.installed_frontend.native_status != fixture_status(&report.installed_record)
        || serde_json::to_vec(report)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_BYTES
    {
        return Err(
            "matched broker identities, status, scope or native Job observation differ".into(),
        );
    }
    for (length, hash, stream) in [
        (
            report.direct.stdout_bytes,
            report.direct.stdout_sha256,
            &expected.direct_stdout,
        ),
        (
            report.direct.stderr_bytes,
            report.direct.stderr_sha256,
            &expected.direct_stderr,
        ),
    ] {
        if length > MAX_BYTES as u64
            || stream.bytes > MAX_BYTES as u64
            || length != stream.bytes
            || hash != stream.sha256
        {
            return Err(
                "matched direct stream bytes/hash differ from complete retained capture".into(),
            );
        }
    }
    let selected = &report.caller.selected;
    if selected.default_acl_bytes == 0
        || selected.default_acl_bytes > MAX_BYTES
        || report.caller.source.default_acl_bytes == 0
        || report.caller.source.default_acl_bytes > MAX_BYTES
        || (!plan.restricted && !same_token_inputs(&report.caller.source, selected))
    {
        return Err("matched held caller token/default ACL inputs differ".into());
    }
    let token_sha256 = token_digest(selected)?;
    for (observed, record, lane, digest, identity) in [
        (
            &report.direct_input,
            &report.direct_record,
            matched::Lane::Direct,
            expected.direct_descriptor_sha256,
            (report.direct.pid, report.direct.birth),
        ),
        (
            &report.installed_input,
            &report.installed_record,
            matched::Lane::Installed,
            expected.installed_descriptor_sha256,
            expected.installed_target,
        ),
    ] {
        let binding = matched::Binding {
            pair_sha256: plan.pair_sha256,
            lane,
            scope: plan.scope,
            input_sha256: plan.input_sha256,
        };
        input::validate(
            observed,
            &input::Expected {
                binding: binding.clone(),
                descriptor_sha256: digest,
                token_sha256,
                default_acl_bytes: selected.default_acl_bytes,
                default_acl_sha256: selected.default_acl_sha256,
                qpc_frequency: plan.work_clock.qpc_frequency,
                cutoff_qpc: plan.work_clock.work_cutoff_qpc,
                identity: Some(identity),
            },
        )?;
        if !same_token_inputs(&observed.token, selected) {
            return Err(
                "matched running workload token differs from the original selected caller".into(),
            );
        }
        matched::validate(
            record,
            &binding,
            plan.restricted && plan.scope == matched::Scope::Envelope,
        )
        .map_err(|error| error.to_string())?;
        if (record.pid, record.birth) != identity
            || record.descriptor_sha256 != digest
            || record.token_sha256 != token_sha256
            || record.qpc_frequency != plan.work_clock.qpc_frequency
            || record.cutoff_qpc != plan.work_clock.work_cutoff_qpc
            || record.started_qpc < observed.finished_qpc
        {
            return Err(
                "matched application record differs from original inputs/identity/clock".into(),
            );
        }
    }
    let assessment =
        input::assess_inputs(plan.scope, &report.direct_input, &report.installed_input)?;
    let claim = match plan.scope {
        matched::Scope::JointListenerPrefix => ClaimScope::ListenerPrefix,
        matched::Scope::ProviderListenerSelection => {
            ClaimScope::ProviderListenerPrefixWithSharedInputs
        }
        _ => ClaimScope::OwnedFileOperationsAndSelectedToken,
    };
    if report.claim_scope != claim {
        return Err("matched report claim differs from scope".into());
    }
    if report.physical_stream_security_equal != assessment.physical_stream_security_equal {
        return Err("matched physical stream security fact differs".into());
    }
    let cwd = plan
        .directories
        .iter()
        .find(|directory| directory.role == DirectoryRole::Cwd)
        .ok_or("matched original cwd directory role absent")?;
    if (
        report.direct_input.cwd_identity.volume_serial,
        report.direct_input.cwd_identity.file_index,
        report.direct_input.cwd_identity.attributes,
    ) != (cwd.volume_serial, cwd.file_index, cwd.attributes)
        || memcordon_core::encode_windows_environment_block(&report.direct_input.environment)
            .map_err(str::to_owned)?
            != memcordon_core::encode_windows_environment_block(&plan.environment)
                .map_err(str::to_owned)?
    {
        return Err("matched retained cwd or environment differs from declared input".into());
    }
    let comparison = matched::compare(
        &report.direct_record,
        &report.installed_record,
        plan.restricted && plan.scope == matched::Scope::Envelope,
    )
    .map_err(|error| error.to_string())?;
    if serde_json::to_value(comparison).map_err(|error| error.to_string())?
        != serde_json::to_value(&report.comparison).map_err(|error| error.to_string())?
    {
        return Err("matched reported comparison differs from original operation records".into());
    }
    if report.positive_coverage != positive_coverage(&comparison) {
        return Err("matched positive coverage differs from operation records".into());
    }
    if (report.validation, report.native_availability) != scoped_assessment(&comparison) {
        return Err(
            "matched validation or native availability differs from original records".into(),
        );
    }
    Ok(comparison)
}
