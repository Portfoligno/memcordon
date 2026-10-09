//! Ordinary installed case results and bounded fixture identities.

use crate::{CiError, Result};
use memcordon_core::{FailureCategoryV1, FailureCodeV1, FailureOperationV1, OriginalFailureV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STREAM_BYTES: usize = 256 * 1024;
pub const MAX_SUMMARY_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 128 * 1024;
/// Fixture size is independent of the production observer capacity.
pub const WINDOWS_CAUSAL_CONCURRENT_CHILDREN: usize = 256;

#[derive(Clone, Debug)]
pub struct ObservationExpectation {
    pub root: memcordon_core::WindowsProcessIdentityV1,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub worker_loss_before_freeze: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SamplingAssessment {
    pub capacity: Option<usize>,
    pub sampled: usize,
    pub independently_held: usize,
    pub omissions_preserved: bool,
}

/// Sampling is diagnostic coverage, never a workload population or retirement
/// quota. The native held identities are supplied by the trusted controller.
pub fn validate_process_observation(
    observation: &memcordon_core::WindowsProcessObservationV2,
    independently_held: &[memcordon_core::WindowsProcessIdentityV1],
    expected: &ObservationExpectation,
) -> Result<SamplingAssessment> {
    use memcordon_core::{ProcessObservationCoverageV1, ProcessObservationUnavailableReasonV1};
    observation
        .validate(
            &expected.attempt_id,
            &expected.nonce,
            &expected.request_sha256,
        )
        .map_err(|error| CiError::Message(error.into()))?;
    let unavailable_worker = matches!(
        &observation.coverage,
        ProcessObservationCoverageV1::Unavailable {
            reason: ProcessObservationUnavailableReasonV1::WorkerLostBeforeFreeze
        }
    );
    if observation
        .root_identity
        .as_ref()
        .is_some_and(|root| root != &expected.root)
        || observation.root_identity.is_none() && !unavailable_worker
        || !independently_held.contains(&expected.root)
        || independently_held
            .iter()
            .enumerate()
            .any(|(index, identity)| independently_held[..index].contains(identity))
    {
        return Err(CiError::Message(
            "sample root/family differs from independently retained identities".into(),
        ));
    }
    if unavailable_worker {
        if !expected.worker_loss_before_freeze {
            return Err(CiError::Message(
                "orderly case cannot substitute unavailable process coverage".into(),
            ));
        }
        // A killed observer cannot invent its final diagnostic accounting. The
        // caller separately validates authenticated retirement authority and
        // independently held process/guardian retirement; coverage stays unavailable.
        match &observation.final_accounting {
            Some(accounting)
                if !accounting.observed_after_target_retirement
                    || accounting.active_processes_native_u32 != 0
                    || accounting.counter_regression_observed =>
            {
                return Err(CiError::Message(
                    "unavailable observer retained contradictory native accounting".into(),
                ));
            }
            _ => {}
        }
        return Ok(SamplingAssessment {
            capacity: None,
            sampled: 0,
            independently_held: independently_held.len(),
            omissions_preserved: true,
        });
    }
    let accounting = observation
        .final_accounting
        .as_ref()
        .ok_or_else(|| CiError::Message("native final Job accounting unavailable".into()))?;
    if !accounting.observed_after_target_retirement
        || accounting.active_processes_native_u32 != 0
        || accounting.counter_regression_observed
        || (accounting.total_processes_native_u32 as usize) < independently_held.len()
    {
        return Err(CiError::Message(
            "native final Job accounting contradicts held family or retirement".into(),
        ));
    }
    match &observation.coverage {
        ProcessObservationCoverageV1::Unavailable { reason } => {
            if !expected.worker_loss_before_freeze
                || *reason != ProcessObservationUnavailableReasonV1::WorkerLostBeforeFreeze
            {
                return Err(CiError::Message(
                    "orderly case cannot substitute unavailable process coverage".into(),
                ));
            }
            Ok(SamplingAssessment {
                capacity: None,
                sampled: 0,
                independently_held: independently_held.len(),
                omissions_preserved: true,
            })
        }
        ProcessObservationCoverageV1::Sampled {
            policy,
            counters,
            omissions,
            sample,
        } => {
            if sample
                .0
                .iter()
                .any(|entry| !independently_held.contains(&entry.identity))
                || counters.identity_observations_verified < sample.0.len() as u64
            {
                return Err(CiError::Message(
                    "sample contains an unheld identity or impossible verified count".into(),
                ));
            }
            Ok(SamplingAssessment {
                capacity: Some(policy.sample_slots()),
                sampled: sample.0.len(),
                independently_held: independently_held.len(),
                omissions_preserved: omissions.sample_eviction == counters.sample_evictions,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstalledChannel {
    NativeBundle,
    CargoPackage,
}
impl InstalledChannel {
    pub const fn name(self) -> &'static str {
        match self {
            Self::NativeBundle => "native-bundle",
            Self::CargoPackage => "cargo-package",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstalledCase {
    SamplingPopulation,
    GuardianLossAfterRelease,
}
impl InstalledCase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SamplingPopulation => "sampling-population",
            Self::GuardianLossAfterRelease => "guardian-loss-after-release",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseFailure {
    pub reason: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionFailure {
    pub reason: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupFailure {
    pub reason: String,
}

/// Hashes identify actual retained bytes and do not approve releases.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedFailure {
    pub report_sha256: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub provider_failure: Option<memcordon_core::ProviderFailureDiagnosticV1>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledCaseResult {
    pub case: InstalledCase,
    pub behavior: std::result::Result<(), CaseFailure>,
    pub collection: std::result::Result<CollectedFailure, CollectionFailure>,
    pub workload_cleanup: std::result::Result<(), CleanupFailure>,
    pub package_cleanup: std::result::Result<(), CleanupFailure>,
}
impl InstalledCaseResult {
    pub fn accepted(&self) -> bool {
        self.behavior.is_ok()
            && self.workload_cleanup.is_ok()
            && self.package_cleanup.is_ok()
            && self.collection.as_ref().is_ok_and(|collection| {
                [
                    &collection.report_sha256,
                    &collection.stdout_sha256,
                    &collection.stderr_sha256,
                ]
                .into_iter()
                .all(|digest| valid_sha256(digest))
                    && match self.case {
                        InstalledCase::SamplingPopulation => collection.provider_failure.is_none(),
                        InstalledCase::GuardianLossAfterRelease => collection
                            .provider_failure
                            .as_ref()
                            .is_some_and(|projection| {
                                projection.is_consistent()
                                    && projection.canonical_digest() == projection.projection_sha256
                                    && guardian_original(projection)
                            }),
                    }
            })
    }
}
fn guardian_original(projection: &memcordon_core::ProviderFailureDiagnosticV1) -> bool {
    matches!(&projection.original, OriginalFailureV1::Observed { event }
        if event.category == FailureCategoryV1::Monitor
            && event.operation == FailureOperationV1::CheckGuardian
            && event.code == FailureCodeV1::GuardianLoss
            && event.native_code.is_none()
            && event.observed_phase == memcordon_core::AttemptObservationPhaseV1::Monitoring)
}
/// Require independently observed authenticated provider/attempt/request values.
pub fn validate_guardian_failure_projection(
    bytes: &[u8],
    provider: &memcordon_core::PublicProviderBindingV1,
    attempt: &memcordon_core::DiagnosticSha256,
    request: &memcordon_core::DiagnosticSha256,
) -> Result<memcordon_core::ProviderFailureDiagnosticV1> {
    let projection =
        memcordon_core::ProviderFailureDiagnosticV1::parse_bound(bytes, provider, attempt, request)
            .map_err(failure)?
            .into_projection();
    if !guardian_original(&projection) {
        return Err(failure(
            "installed causal original is not the observed semantic guardian loss",
        ));
    }
    Ok(projection)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureProcessIdentityV1 {
    pub ordinal: Option<usize>,
    pub pid: u32,
    pub birth: u128,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryReadiness {
    kind: String,
    ordinal: Option<usize>,
    pid: u32,
    birth: u128,
}
pub fn parse_fixture_readiness(stdout: &[u8]) -> Result<Vec<FixtureProcessIdentityV1>> {
    const MARKER: &[u8] = b"MEMCORDON-INVENTORY-READY:";
    if stdout.len() > MAX_STREAM_BYTES {
        return Err(failure(
            "inventory fixture readiness stream exceeds byte bound",
        ));
    }
    let mut identities = Vec::new();
    let mut ordinals = BTreeSet::new();
    let mut process_identities = BTreeSet::new();
    let mut root_count = 0;
    for line in stdout.split(|byte| *byte == b'\n') {
        let Some(value) = line.strip_prefix(MARKER) else {
            continue;
        };
        let value: InventoryReadiness = serde_json::from_slice(value)?;
        let valid = match (value.kind.as_str(), value.ordinal) {
            ("inventory-root-ready", None) => {
                root_count += 1;
                true
            }
            ("inventory-leaf-ready", Some(ordinal))
                if ordinal < WINDOWS_CAUSAL_CONCURRENT_CHILDREN =>
            {
                ordinals.insert(ordinal)
            }
            _ => false,
        };
        if !valid
            || root_count > 1
            || value.pid == 0
            || value.birth == 0
            || !process_identities.insert((value.pid, value.birth))
        {
            return Err(failure(
                "inventory fixture readiness is malformed or duplicated",
            ));
        }
        identities.push(FixtureProcessIdentityV1 {
            ordinal: value.ordinal,
            pid: value.pid,
            birth: value.birth,
        });
        if identities.len() > WINDOWS_CAUSAL_CONCURRENT_CHILDREN + 1 {
            return Err(failure(
                "inventory fixture readiness exceeds the family bound",
            ));
        }
    }
    if root_count != 1 {
        return Err(failure("inventory fixture root readiness was not observed"));
    }
    Ok(identities)
}
/// Reconcile held native identities with the fixture's original readiness stream.
pub fn validate_fixture_family(stdout: &[u8], family: &[FixtureProcessIdentityV1]) -> Result<()> {
    let expected_len = WINDOWS_CAUSAL_CONCURRENT_CHILDREN
        .checked_add(1)
        .ok_or_else(|| failure("inventory fixture family bound overflow"))?;
    if family.len() != expected_len {
        return Err(failure("installed fixture family is incomplete"));
    }
    let mut ordinals = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut roots = 0;
    for member in family {
        if member.pid == 0 || member.birth == 0 || !identities.insert((member.pid, member.birth)) {
            return Err(failure("installed fixture identity is invalid"));
        }
        match member.ordinal {
            None => roots += 1,
            Some(ordinal) if ordinal < WINDOWS_CAUSAL_CONCURRENT_CHILDREN => {
                if !ordinals.insert(ordinal) {
                    return Err(failure("installed fixture ordinal is duplicated"));
                }
            }
            _ => return Err(failure("installed fixture ordinal is out of range")),
        }
    }
    if roots != 1
        || ordinals.len() != WINDOWS_CAUSAL_CONCURRENT_CHILDREN
        || !ordinals
            .iter()
            .copied()
            .eq(0..WINDOWS_CAUSAL_CONCURRENT_CHILDREN)
    {
        return Err(failure("installed fixture family is incomplete"));
    }
    let reported: BTreeSet<_> = parse_fixture_readiness(stdout)?
        .into_iter()
        .map(|identity| (identity.ordinal, identity.pid, identity.birth))
        .collect();
    let retained: BTreeSet<_> = family
        .iter()
        .map(|identity| (identity.ordinal, identity.pid, identity.birth))
        .collect();
    if reported != retained {
        return Err(failure(
            "installed fixture family differs from retained readiness",
        ));
    }
    Ok(())
}
fn failure(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Compare report facts to the separately queried, authenticated live native
/// association. A self-consistent report from another invocation is insufficient.
pub fn validate_live_guardian_association(
    reported: &memcordon_core::result_v1::ProviderAttemptAssociationV1,
    observed: &memcordon_core::WindowsGuardianAttemptObservation,
    provider: &memcordon_core::PublicProviderBindingV1,
) -> Result<()> {
    if !observed.is_consistent()
        || &observed.association.provider != provider
        || reported != &observed.association
    {
        return Err(failure(
            "report differs from independently observed live guardian invocation",
        ));
    }
    Ok(())
}
fn valid_sha256(value: &str) -> bool {
    value.len() == Sha256::output_size() * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
