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
                let unheld: Vec<_> = sample
                    .0
                    .iter()
                    .filter(|entry| !independently_held.contains(&entry.identity))
                    .take(8)
                    .map(|entry| {
                        (
                            entry.identity.process_id,
                            entry.identity.creation_time_100ns,
                            entry.last_observation_sequence,
                        )
                    })
                    .collect();
                let unheld_count = sample
                    .0
                    .iter()
                    .filter(|entry| !independently_held.contains(&entry.identity))
                    .count();
                return Err(CiError::Message(format!(
                    "sample contains an unheld identity or impossible verified count; root-pid={}; root-birth={}; sampled={}; independently-held={}; verified={}; total-native={}; unheld-count={unheld_count}; unheld-pid-birth-sequence={unheld:?}; unheld-truncated={}",
                    expected.root.process_id,
                    expected.root.creation_time_100ns,
                    sample.0.len(),
                    independently_held.len(),
                    counters.identity_observations_verified,
                    accounting.total_processes_native_u32,
                    unheld_count > unheld.len(),
                )));
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
    GuardianLossLifetime,
}
impl InstalledCase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SamplingPopulation => "sampling-population",
            Self::GuardianLossAfterRelease => "guardian-loss-after-release",
            Self::GuardianLossLifetime => "guardian-loss-lifetime",
        }
    }
    pub const fn is_guardian_loss(self) -> bool {
        matches!(
            self,
            Self::GuardianLossAfterRelease | Self::GuardianLossLifetime
        )
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_execution: Option<SamplingExecutionEvidence>,
}

/// Diagnostic-only projection of the original command owner result. No stream
/// bytes, paths, process identities, or cleanup error strings enter this field.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingExecutionEvidence {
    pub outcome: SamplingCommandOutcome,
    /// Status observed before cleanup, not the status reaped after termination.
    pub observed_status: Option<i32>,
    pub termination_status: Option<i32>,
    /// Command-boundary cleanup, not independent fixture-family retirement.
    pub command_cleanup_succeeded: Option<bool>,
    /// True only when the command owner supplied both complete bounded streams.
    pub complete_capture: bool,
    /// The command owner's capture, which may include bytes read during cleanup.
    pub output: Option<SamplingOutputEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_at_deadline: Option<SamplingReadinessDeadlineEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SamplingCommandOutcome {
    Exited,
    ReadinessDeadline,
    CallbackFailed,
    Deadline,
    Cancelled,
    OutputLimit,
    SpawnFailed,
    WaitFailed,
    CaptureFailed,
    ApplicationEnded,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingOutputEvidence {
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    /// Includes a possible final partial record in a bounded snapshot.
    pub readiness_marker_lines: usize,
    /// Structural readiness parsed from this capture, not matched native identities.
    pub parsed_readiness_members: Option<usize>,
    /// Relative native process-birth distribution of the announced members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_birth_timeline: Option<SamplingBirthTimeline>,
}

/// Number of fixed-width relative buckets retained in compact evidence.
pub const SAMPLING_BIRTH_BUCKETS: usize = 24;
/// Bucket width in native process-birth ticks (100 ns units): ten seconds.
pub const SAMPLING_BIRTH_BUCKET_TICKS: u128 = 100_000_000;
const SAMPLING_BIRTH_TICKS_PER_MILLISECOND: u128 = 10_000;

/// Native process-birth spacing of members announced in the completed capture.
/// Births are measured only between the members' own native creation times and
/// are relative to the earliest announced birth. They are neither announcement
/// times, proof that a member was alive at any instant, nor a spawn-rate
/// measurement. No identities or absolute timestamps enter this projection.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingBirthTimeline {
    /// Distinct announced native births, including the root.
    pub observed_births: usize,
    /// Whole milliseconds between the earliest and latest announced birth.
    pub birth_span_ms: u64,
    /// Announced births per ten-second bucket from the earliest birth; trailing
    /// empty buckets are omitted. At most `SAMPLING_BIRTH_BUCKETS` entries.
    pub births_per_10s: Vec<usize>,
    /// Announced births at or after the final bucket boundary.
    pub births_after_window: usize,
}

impl SamplingBirthTimeline {
    /// Derive from complete (newline-terminated) readiness records only.
    /// Malformed, duplicated, rootless or over-bound streams yield `None`.
    #[cfg(any(windows, test))]
    fn from_readiness(stdout: &[u8]) -> Option<Self> {
        let complete = &stdout[..stdout.iter().rposition(|byte| *byte == b'\n')? + 1];
        let rows = parse_fixture_readiness(complete).ok()?;
        let earliest = rows.iter().map(|row| row.birth).min()?;
        let latest = rows.iter().map(|row| row.birth).max()?;
        let mut births_per_10s = vec![0_usize; SAMPLING_BIRTH_BUCKETS];
        let mut births_after_window = 0;
        for row in &rows {
            let bucket = (row.birth - earliest) / SAMPLING_BIRTH_BUCKET_TICKS;
            match usize::try_from(bucket)
                .ok()
                .and_then(|bucket| births_per_10s.get_mut(bucket))
            {
                Some(count) => *count += 1,
                None => births_after_window += 1,
            }
        }
        while births_per_10s.last() == Some(&0) {
            births_per_10s.pop();
        }
        Some(Self {
            observed_births: rows.len(),
            birth_span_ms: u64::try_from(
                (latest - earliest) / SAMPLING_BIRTH_TICKS_PER_MILLISECOND,
            )
            .unwrap_or(u64::MAX),
            births_per_10s,
            births_after_window,
        })
    }
}

/// Raw streams owned by a failed original callback command. The shared output
/// snapshot is drained by the reader join, so these bytes are the only raw copy.
#[cfg(any(windows, test))]
pub(crate) fn owned_callback_streams(
    error: &memcordon_testkit::ProcessTestError,
) -> Option<(&[u8], &[u8])> {
    match error {
        memcordon_testkit::ProcessTestError::Callback { stdout, stderr, .. } => {
            Some((stdout, stderr))
        }
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingReadinessDeadlineEvidence {
    pub stdout_bytes: usize,
    /// None means the existing reader buffer could not be inspected immediately.
    pub stderr_bytes: Option<usize>,
    pub parsed_readiness_members: Option<usize>,
}

#[cfg(any(windows, test))]
#[derive(Debug)]
pub(crate) struct FixtureReadinessDeadline(pub SamplingReadinessDeadlineEvidence);

#[cfg(any(windows, test))]
impl std::fmt::Display for FixtureReadinessDeadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("trusted fixture readiness was not observed before deadline")
    }
}

#[cfg(any(windows, test))]
impl std::error::Error for FixtureReadinessDeadline {}

#[cfg(any(windows, test))]
impl SamplingExecutionEvidence {
    pub(crate) fn from_execution(
        execution: &std::result::Result<
            memcordon_testkit::ObservedOutput,
            memcordon_testkit::ProcessTestError,
        >,
    ) -> Self {
        use memcordon_testkit::ProcessTestError as Error;

        let mut evidence = Self {
            outcome: SamplingCommandOutcome::Exited,
            observed_status: None,
            termination_status: None,
            command_cleanup_succeeded: None,
            complete_capture: false,
            output: None,
            readiness_at_deadline: None,
        };
        let output = match execution {
            Ok(output) => {
                evidence.observed_status = output.status.code();
                evidence.complete_capture = true;
                Some((&output.stdout, &output.stderr))
            }
            Err(Error::Callback {
                error,
                stdout,
                stderr,
                capture_complete,
                observed_status,
                termination,
                cleanup,
            }) => {
                let deadline = error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<FixtureReadinessDeadline>());
                evidence.outcome = if let Some(deadline) = deadline {
                    evidence.readiness_at_deadline = Some(deadline.0.clone());
                    SamplingCommandOutcome::ReadinessDeadline
                } else {
                    SamplingCommandOutcome::CallbackFailed
                };
                evidence.observed_status = observed_status.and_then(|status| status.code());
                evidence.termination_status = termination.and_then(|status| status.code());
                evidence.command_cleanup_succeeded = Some(cleanup.is_ok());
                evidence.complete_capture = *capture_complete;
                Some((stdout, stderr))
            }
            Err(Error::Timeout {
                stdout,
                stderr,
                cleanup,
                observation,
                ..
            }) => {
                evidence.outcome = SamplingCommandOutcome::Deadline;
                evidence.observed_status =
                    observation.observed_status.and_then(|status| status.code());
                evidence.command_cleanup_succeeded = Some(cleanup.is_ok());
                Some((stdout, stderr))
            }
            Err(Error::Cancelled {
                stdout,
                stderr,
                cleanup,
                termination,
                observation,
            }) => {
                evidence.outcome = SamplingCommandOutcome::Cancelled;
                evidence.observed_status =
                    observation.observed_status.and_then(|status| status.code());
                evidence.termination_status = termination.and_then(|status| status.code());
                evidence.command_cleanup_succeeded = Some(cleanup.is_ok());
                Some((stdout, stderr))
            }
            Err(Error::OutputLimit {
                stdout,
                stderr,
                cleanup,
                termination,
            }) => {
                evidence.outcome = SamplingCommandOutcome::OutputLimit;
                evidence.termination_status = termination.and_then(|status| status.code());
                evidence.command_cleanup_succeeded = Some(cleanup.is_ok());
                Some((stdout, stderr))
            }
            Err(
                error @ (Error::Spawn(_)
                | Error::Wait(_)
                | Error::Output(_)
                | Error::ApplicationEnded { .. }),
            ) => {
                evidence.outcome = match error {
                    Error::Spawn(_) => SamplingCommandOutcome::SpawnFailed,
                    Error::Wait(_) => SamplingCommandOutcome::WaitFailed,
                    Error::Output(_) => SamplingCommandOutcome::CaptureFailed,
                    _ => SamplingCommandOutcome::ApplicationEnded,
                };
                None
            }
        };
        evidence.output = output.map(|(stdout, stderr)| SamplingOutputEvidence {
            stdout_bytes: stdout.len(),
            stderr_bytes: stderr.len(),
            readiness_marker_lines: stdout
                .split(|byte| *byte == b'\n')
                .filter(|line| line.starts_with(INVENTORY_READINESS_MARKER))
                .count(),
            parsed_readiness_members: parse_fixture_readiness(stdout).ok().map(|rows| rows.len()),
            observed_birth_timeline: SamplingBirthTimeline::from_readiness(stdout),
        });
        evidence
    }
}

#[cfg(test)]
mod sampling_execution_tests {
    use super::*;
    use memcordon_testkit::ProcessTestError;
    use std::{io, process::ExitStatus};

    fn exit_status(code: u8) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(i32::from(code) << 8)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(u32::from(code))
        }
    }

    #[test]
    fn readiness_deadline_uses_completed_owner_capture_without_exporting_raw_output() {
        let stdout = b"MEMCORDON-INVENTORY-READY:{\"kind\":\"inventory-root-ready\",\"ordinal\":null,\"pid\":875431,\"birth\":987654321}\n".to_vec();
        let stderr = b"private stderr contents".to_vec();
        let (stdout_bytes, stderr_bytes) = (stdout.len(), stderr.len());
        let evidence =
            SamplingExecutionEvidence::from_execution(&Err(ProcessTestError::Callback {
                error: io::Error::other(FixtureReadinessDeadline(
                    SamplingReadinessDeadlineEvidence {
                        stdout_bytes: 0,
                        stderr_bytes: None,
                        parsed_readiness_members: None,
                    },
                )),
                stdout,
                stderr,
                capture_complete: true,
                observed_status: None,
                termination: Some(exit_status(137)),
                cleanup: Ok(()),
            }));
        assert_eq!(evidence.outcome, SamplingCommandOutcome::ReadinessDeadline);
        assert_eq!(evidence.observed_status, None);
        assert_eq!(evidence.termination_status, Some(137));
        assert_eq!(evidence.command_cleanup_succeeded, Some(true));
        assert!(evidence.complete_capture);
        assert_eq!(
            evidence.readiness_at_deadline,
            Some(SamplingReadinessDeadlineEvidence {
                stdout_bytes: 0,
                stderr_bytes: None,
                parsed_readiness_members: None,
            })
        );
        assert_eq!(
            evidence.output,
            Some(SamplingOutputEvidence {
                stdout_bytes,
                stderr_bytes,
                readiness_marker_lines: 1,
                parsed_readiness_members: Some(1),
                observed_birth_timeline: Some(SamplingBirthTimeline {
                    observed_births: 1,
                    birth_span_ms: 0,
                    births_per_10s: vec![1],
                    births_after_window: 0,
                }),
            })
        );
        let wire = serde_json::to_string(&evidence).unwrap();
        for omitted in [
            "private stderr",
            "inventory-root-ready",
            "875431",
            "987654321",
        ] {
            assert!(!wire.contains(omitted), "{wire}");
        }
        assert!(wire.len() < 512, "{wire}");
    }

    fn leaf_readiness_stream(births: &[u128]) -> Vec<u8> {
        let mut stdout = Vec::new();
        for (index, birth) in births.iter().enumerate() {
            let record = if index == 0 {
                serde_json::json!({"kind":"inventory-root-ready","ordinal":null,"pid":700,"birth":birth})
            } else {
                serde_json::json!({"kind":"inventory-leaf-ready","ordinal":index - 1,"pid":700 + index,"birth":birth})
            };
            stdout.extend_from_slice(INVENTORY_READINESS_MARKER);
            stdout.extend_from_slice(record.to_string().as_bytes());
            stdout.push(b'\n');
        }
        stdout
    }

    #[test]
    fn birth_timeline_separates_steady_slowing_and_stopped_birth_distributions() {
        const BASE: u128 = 133_000_000_000_000_000;
        const SECOND: u128 = 10_000_000;
        let timeline = |offsets: &[u128]| {
            let births = offsets
                .iter()
                .map(|offset| BASE + offset)
                .collect::<Vec<_>>();
            SamplingBirthTimeline::from_readiness(&leaf_readiness_stream(&births)).unwrap()
        };
        // Root plus 30 leaves: three per second for ten seconds.
        let steady = (0..31).map(|index| index * SECOND / 3).collect::<Vec<_>>();
        assert_eq!(timeline(&steady).births_per_10s, vec![30, 1]);
        // Root plus 20 leaves: births become sparser each ten seconds.
        let slowing = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 29,
        ]
        .map(|second| second * SECOND);
        assert_eq!(timeline(&slowing).births_per_10s, vec![10, 5, 6]);
        // Root plus 8 leaves, then nothing more is announced.
        let stopped = (0..9).map(|index| index * SECOND).collect::<Vec<_>>();
        let stopped = timeline(&stopped);
        assert_eq!(stopped.observed_births, 9);
        assert_eq!(stopped.birth_span_ms, 8_000);
        assert_eq!(stopped.births_per_10s, vec![9]);
        assert_eq!(stopped.births_after_window, 0);
    }

    #[test]
    fn birth_timeline_is_bounded_relative_and_omits_native_identities() {
        const BASE: u128 = 133_123_456_789_012_345;
        const SECOND: u128 = 10_000_000;
        // Full family spread past the retained window.
        let births = (0..=WINDOWS_CAUSAL_CONCURRENT_CHILDREN as u128)
            .map(|index| BASE + index * SECOND)
            .collect::<Vec<_>>();
        let stdout = leaf_readiness_stream(&births);
        let evidence =
            SamplingExecutionEvidence::from_execution(&Err(ProcessTestError::Callback {
                error: io::Error::other(FixtureReadinessDeadline(
                    SamplingReadinessDeadlineEvidence {
                        stdout_bytes: stdout.len(),
                        stderr_bytes: Some(0),
                        parsed_readiness_members: Some(births.len()),
                    },
                )),
                stdout,
                stderr: Vec::new(),
                capture_complete: true,
                observed_status: None,
                termination: Some(exit_status(1)),
                cleanup: Ok(()),
            }));
        let timeline = evidence.output.unwrap().observed_birth_timeline.unwrap();
        assert_eq!(timeline.observed_births, births.len());
        assert_eq!(timeline.births_per_10s.len(), SAMPLING_BIRTH_BUCKETS);
        assert_eq!(timeline.births_per_10s.iter().sum::<usize>(), 240);
        assert_eq!(timeline.births_after_window, births.len() - 240);
        assert_eq!(
            timeline.birth_span_ms,
            u64::try_from(WINDOWS_CAUSAL_CONCURRENT_CHILDREN).unwrap() * 1_000
        );
        let wire = serde_json::to_string(&timeline).unwrap();
        assert!(wire.len() < 256, "{wire}");
        for omitted in ["133123456789012345", "700", "pid", "ordinal"] {
            assert!(!wire.contains(omitted), "{wire}");
        }
    }

    #[test]
    fn birth_timeline_ignores_partial_tail_and_rejects_unreliable_streams() {
        let mut stdout = leaf_readiness_stream(&[100, 50_000_000, 150_000_000]);
        let complete = SamplingBirthTimeline::from_readiness(&stdout).unwrap();
        assert_eq!(complete.births_per_10s, vec![2, 1]);
        stdout.extend_from_slice(b"MEMCORDON-INVENTORY-READY:{\"kind\":\"inventory-leaf-r");
        assert_eq!(
            SamplingBirthTimeline::from_readiness(&stdout),
            Some(complete)
        );
        // No complete record, a leaf without the root, and duplicate births yield no timeline.
        assert_eq!(SamplingBirthTimeline::from_readiness(b""), None);
        assert_eq!(
            SamplingBirthTimeline::from_readiness(b"MEMCORDON-INVENTORY-READY:{"),
            None
        );
        let rootless = leaf_readiness_stream(&[100, 200])
            .split(|byte| *byte == b'\n')
            .skip(1)
            .collect::<Vec<_>>()
            .join(&b'\n');
        assert_eq!(SamplingBirthTimeline::from_readiness(&rootless), None);
        let mut duplicate = leaf_readiness_stream(&[100]);
        duplicate.extend_from_slice(&duplicate.clone());
        assert_eq!(SamplingBirthTimeline::from_readiness(&duplicate), None);
    }

    #[test]
    fn only_callback_errors_expose_owned_raw_streams_for_sampling() {
        let callback = ProcessTestError::Callback {
            error: io::Error::other("callback"),
            stdout: b"owned stdout".to_vec(),
            stderr: b"owned stderr".to_vec(),
            capture_complete: true,
            observed_status: None,
            termination: None,
            cleanup: Ok(()),
        };
        assert_eq!(
            owned_callback_streams(&callback),
            Some((&b"owned stdout"[..], &b"owned stderr"[..]))
        );
        assert_eq!(
            owned_callback_streams(&ProcessTestError::Spawn(io::Error::other("spawn"))),
            None
        );
    }

    #[test]
    fn callback_failure_and_spawn_failure_do_not_invent_complete_readiness_or_cleanup() {
        let execution =
            SamplingExecutionEvidence::from_execution(&Err(ProcessTestError::Callback {
                error: io::Error::other("unrelated confidential callback failure"),
                stdout: b"MEMCORDON-INVENTORY-READY:{".to_vec(),
                stderr: Vec::new(),
                capture_complete: false,
                observed_status: Some(exit_status(23)),
                termination: None,
                cleanup: Err("confidential cleanup detail".into()),
            }));
        assert_eq!(execution.outcome, SamplingCommandOutcome::CallbackFailed);
        assert_eq!(execution.observed_status, Some(23));
        assert_eq!(execution.termination_status, None);
        assert_eq!(execution.command_cleanup_succeeded, Some(false));
        assert!(!execution.complete_capture);
        assert_eq!(execution.readiness_at_deadline, None);
        let output = execution.output.as_ref().unwrap();
        assert_eq!(output.readiness_marker_lines, 1);
        assert_eq!(output.parsed_readiness_members, None);
        assert!(
            !serde_json::to_string(&execution)
                .unwrap()
                .contains("confidential")
        );

        let spawn = SamplingExecutionEvidence::from_execution(&Err(ProcessTestError::Spawn(
            io::Error::other("spawn failed"),
        )));
        assert_eq!(spawn.outcome, SamplingCommandOutcome::SpawnFailed);
        assert_eq!(spawn.output, None);
        assert_eq!(spawn.command_cleanup_succeeded, None);
    }
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
                        InstalledCase::GuardianLossAfterRelease
                        | InstalledCase::GuardianLossLifetime => collection
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
const INVENTORY_READINESS_MARKER: &[u8] = b"MEMCORDON-INVENTORY-READY:";

pub fn parse_fixture_readiness(stdout: &[u8]) -> Result<Vec<FixtureProcessIdentityV1>> {
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
        let Some(value) = line.strip_prefix(INVENTORY_READINESS_MARKER) else {
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
    reported: &memcordon_core::execution_facts::ProviderAttemptAssociationV1,
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
