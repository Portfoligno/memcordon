//! Capacity observations retain each constituent natural attempt and each
//! authenticated public recovery inventory; bounded samples are not quotas.
use crate::windows_consumer_readiness::{CaseAssessment, CaseKey, TokenObservation};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityAssessment {
    pub key: CaseKey,
    pub behavior: std::result::Result<(), String>,
    pub collection: std::result::Result<(), String>,
    pub retirement: std::result::Result<(), String>,
    pub attempts: Vec<CaseAssessment>,
    pub artifacts: Vec<crate::windows_installed_cases::SelectedArtifact>,
}

pub fn required_keys() -> Vec<CaseKey> {
    [
        "serial-retirement",
        "bounded-concurrency",
        "fresh-positive-after-recovery",
    ]
    .into_iter()
    .map(|scenario| CaseKey {
        family: "W-CAPACITY".into(),
        scenario: scenario.into(),
    })
    .collect()
}

pub fn accepted(records: &[CapacityAssessment]) -> bool {
    let mut attempts = std::collections::BTreeSet::new();
    let mut roots = std::collections::BTreeSet::new();
    records.len() == required_keys().len()
        && required_keys()
            .iter()
            .all(|key| records.iter().filter(|record| &record.key == key).count() == 1)
        && records.iter().all(|record| {
            record.behavior.is_ok()
                && record.collection.is_ok()
                && record.retirement.is_ok()
                && Some(record.attempts.len()) == planned_attempt_count(&record.key)
                && record.attempts.iter().all(|attempt| {
                    use crate::windows_readiness_policy::{
                        ExecutionDisposition, IntrinsicContract,
                    };
                    let Some(evidence) = &attempt.contract.evidence else {
                        return false;
                    };
                    let joins = [
                        (
                            &evidence.association.request_sha256,
                            attempt.provider_request_sha256.as_deref(),
                        ),
                        (
                            &evidence.workload_request_sha256,
                            attempt.request_sha256.as_deref(),
                        ),
                        (
                            &evidence.descriptor_sha256,
                            Some(attempt.descriptor_sha256.as_str()),
                        ),
                        (&evidence.result_sha256, attempt.result_sha256.as_deref()),
                        (&evidence.stdout_sha256, attempt.stdout_sha256.as_deref()),
                        (&evidence.stderr_sha256, attempt.stderr_sha256.as_deref()),
                        (
                            &evidence.transcript_sha256,
                            attempt.transcript_sha256.as_deref(),
                        ),
                        (
                            &evidence.terminal_observation_sha256,
                            attempt.terminal_observation_sha256.as_deref(),
                        ),
                    ];
                    let Ok(origin) = serde_json::to_string(&(
                        &evidence.association.provider,
                        &evidence.association.attempt_id,
                    )) else {
                        return false;
                    };
                    attempt.key == record.key
                        && attempt.revision
                            == crate::windows_consumer_readiness::CASE_ASSESSMENT_REVISION
                        && attempt.behavior.is_ok()
                        && attempt.collection.is_ok()
                        && attempt.retirement.is_ok()
                        && attempt.contract.intrinsic == IntrinsicContract::Validated
                        && attempt.contract.execution == ExecutionDisposition::Completed
                        && attempt.contract.comparison
                            == crate::windows_readiness_policy::ComparisonStatus::NotMeasured
                        && evidence.association.provider.is_consistent()
                        && evidence.root.pid != 0
                        && evidence.root.birth != 0
                        && joins.iter().all(|(expected, actual)| {
                            actual.is_some_and(|actual| actual == String::from((*expected).clone()))
                        })
                        && attempts.insert(origin)
                        && roots.insert((evidence.root.pid, evidence.root.birth))
                })
                && !record.artifacts.is_empty()
        })
}

/// Bound of the independently observed native caller token snapshot.
pub const TOKEN_SNAPSHOT_BYTES: usize = 16 * 1024;

/// Leaf name of the native caller token snapshot that the original suite
/// published at its output root and every gate input reads from its own root.
pub fn token_snapshot_leaf(restricted: bool) -> &'static str {
    if restricted {
        "windows-restricted-token.json"
    } else {
        "windows-ordinary-token.json"
    }
}

/// Carry the exact original token snapshot bytes from the suite root into a
/// disjoint attempt root. The bytes are never synthesized from `expected`;
/// they must parse and equal `expected` before the attempt may consume them,
/// and publication must create a new file.
pub fn propagate_token_snapshot(
    suite_root: &Path,
    attempt_root: &Path,
    expected: &TokenObservation,
    read: impl FnOnce(&Path, usize) -> Result<Vec<u8>>,
    publish: impl FnOnce(&Path, &[u8]) -> Result<()>,
) -> Result<PathBuf> {
    let leaf = token_snapshot_leaf(expected.restricted);
    if suite_root == attempt_root {
        return Err(CiError::Message(format!(
            "capacity attempt root {} is not disjoint from the suite root",
            attempt_root.display()
        )));
    }
    let source = suite_root.join(leaf);
    let destination = attempt_root.join(leaf);
    let bytes = read(&source, TOKEN_SNAPSHOT_BYTES).map_err(|error| {
        error.context(format!(
            "original native caller token snapshot {} for capacity attempt {}",
            source.display(),
            attempt_root.display()
        ))
    })?;
    let observed: TokenObservation = serde_json::from_slice(&bytes).map_err(|error| {
        CiError::from(error).context(format!(
            "original native caller token snapshot {} does not parse",
            source.display()
        ))
    })?;
    if observed != *expected {
        return Err(CiError::Message(format!(
            "original native caller token snapshot {} differs from the capacity base expectation",
            source.display()
        )));
    }
    publish(&destination, &bytes).map_err(|error| {
        error.context(format!(
            "capacity attempt token snapshot publication {}",
            destination.display()
        ))
    })?;
    Ok(destination)
}

/// Completeness of these bounded CI samples, never a product concurrency quota.
pub fn planned_attempt_count(key: &CaseKey) -> Option<usize> {
    if key.family != "W-CAPACITY" {
        return None;
    }
    match key.scenario.as_str() {
        "serial-retirement" => Some(3),
        "bounded-concurrency" => Some(2),
        "fresh-positive-after-recovery" => Some(1),
        _ => None,
    }
}

/// Truthful scenario execution disposition. Once a capacity scenario's
/// attempt(s) have run, its summary must never claim "not executed": a failed
/// execution records the real failure, and a successful execution stays a
/// non-accepting failure until post-execution collection and retirement
/// complete. The original outcome is always returned unchanged.
pub fn record_execution_outcome(
    record: &mut CapacityAssessment,
    outcome: Result<()>,
) -> Result<()> {
    record.behavior = Err(match &outcome {
        Ok(()) => "executed; post-execution inventory pending".to_owned(),
        Err(error) => format!("executed and failed: {error}"),
    });
    outcome
}

#[cfg(windows)]
pub(crate) fn run(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &std::path::Path,
    records: &mut Vec<CapacityAssessment>,
) -> Result<()> {
    run_until(
        config,
        input_path,
        records,
        std::time::Instant::now() + std::time::Duration::from_secs(660),
    )
}

#[cfg(windows)]
pub(crate) fn run_until(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &std::path::Path,
    records: &mut Vec<CapacityAssessment>,
    work_deadline: std::time::Instant,
) -> Result<()> {
    native::run(config, input_path, records, work_deadline)
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::command::CommandSpec;
    use crate::windows_consumer_readiness::{
        SuiteInput,
        native::{execute_until, read},
    };
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::time::Duration;

    fn retain(path: &std::path::Path, bytes: &[u8], record: &mut CapacityAssessment) -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if read(path, bytes.len())? != bytes {
            return Err(CiError::Message("capacity record readback differs".into()));
        }
        record
            .artifacts
            .push(crate::windows_installed_cases::SelectedArtifact {
                path: path.to_owned(),
                sha256: crate::windows_causal_acceptance::sha256(bytes),
            });
        Ok(())
    }

    fn inventory(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        directory: &std::path::Path,
        ordinal: usize,
        record: &mut CapacityAssessment,
        work_deadline: std::time::Instant,
    ) -> Result<()> {
        let budget = work_deadline
            .saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_secs(90));
        if budget.is_zero() {
            return Err(CiError::Message(
                "original Windows work deadline exhausted before capacity recovery".into(),
            ));
        }
        let millis = budget.as_millis().max(1).to_string();
        let mut command = CommandSpec::new(&config.cli.path, directory, budget)
            .args(["windows-recover", "converge", millis.as_str()])
            .materialize()?;
        command.env_clear();
        let output =
            memcordon_testkit::run_with_deadline_output_limit(&mut command, budget, 256 * 1024)
                .map_err(|error| CiError::Message(error.to_string()))?;
        retain(
            &directory.join(format!("inventory-{ordinal}.json")),
            &output.stdout,
            record,
        )?;
        retain(
            &directory.join(format!("inventory-{ordinal}.stderr.bin")),
            &output.stderr,
            record,
        )?;
        if !output.status.success() {
            return Err(CiError::Message(
                "capacity public recovery convergence failed".into(),
            ));
        }
        let inventory: memcordon_core::WindowsRecoveryInventoryV1 =
            serde_json::from_slice(&output.stdout)?;
        if !inventory.is_consistent()
            || inventory.authority_unsettled()
            || inventory.provider_generation != config.provider.generation.as_str()
        {
            return Err(CiError::Message(
                "capacity inventory retained unsettled authority or a substituted generation"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Every rebased attempt root receives the suite's original token bytes.
    fn attempt_token(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        owned: &crate::windows_installed_cases::InstalledWindowsPayload,
        base: &crate::windows_consumer_readiness::CaseInput,
    ) -> Result<()> {
        super::propagate_token_snapshot(
            &config.output_directory,
            &owned.output_directory,
            &base.expected_token,
            read,
            |path, bytes| {
                drop(crate::windows_native_files::publish_owned_file(
                    path, bytes,
                )?);
                Ok(())
            },
        )
        .map(drop)
    }

    fn blank(key: CaseKey) -> CaseAssessment {
        CaseAssessment {
            revision: crate::windows_consumer_readiness::CASE_ASSESSMENT_REVISION,
            contract: crate::windows_readiness_policy::CaseContract::not_run(),
            key,
            behavior: Err("not executed".into()),
            collection: Err("not collected".into()),
            retirement: Err("not observed".into()),
            descriptor_sha256: String::new(),
            result_sha256: None,
            stdout_sha256: None,
            stderr_sha256: None,
            transcript_sha256: None,
            request_sha256: None,
            provider_request_sha256: None,
            terminal_observation_sha256: None,
        }
    }

    pub fn run(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input_path: &std::path::Path,
        records: &mut Vec<CapacityAssessment>,
        work_deadline: std::time::Instant,
    ) -> Result<()> {
        let suite: SuiteInput = serde_json::from_slice(&read(input_path, 4 * 1024 * 1024)?)?;
        crate::windows_consumer_readiness::validate_suite(&suite)?;
        let ordinary = suite
            .cases
            .iter()
            .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
            .ok_or_else(|| {
                CiError::Message("capacity lacks original ordinary invocation".into())
            })?;
        let base = crate::windows_consumer_readiness::prepare_capacity_completion(
            ordinary,
            &required_keys()[0],
        )?;
        for key in required_keys() {
            records.push(CapacityAssessment {
                key: key.clone(),
                behavior: Err("not executed".into()),
                collection: Err("not collected".into()),
                retirement: Err("not observed".into()),
                attempts: Vec::new(),
                artifacts: Vec::new(),
            });
            let record = records.last_mut().expect("owned capacity record");
            let directory = config
                .output_directory
                .join(&key.family)
                .join(&key.scenario);
            fs::create_dir_all(&directory)?;
            inventory(config, &directory, 0, record, work_deadline)?;
            if key.scenario == "bounded-concurrency" {
                let outcome = overlap(config, &base, &directory, record, work_deadline);
                record_execution_outcome(record, outcome)?;
                inventory(config, &directory, 1, record, work_deadline)?;
                record.behavior = Ok(());
                record.collection = Ok(());
                record.retirement = Ok(());
                continue;
            }
            let count = planned_attempt_count(&key).expect("finite capacity identity");
            for ordinal in 0..count {
                let mut owned = config.clone();
                owned.output_directory = directory.join(format!("attempt-{ordinal}"));
                fs::create_dir(&owned.output_directory)?;
                attempt_token(config, &owned, &base)?;
                let mut input = base.clone();
                input.key = key.clone();
                input.descriptor.challenge =
                    crate::windows_consumer_readiness::native::random_challenge()?.to_vec();
                input.descriptor.output_root = base
                    .descriptor
                    .output_root
                    .parent()
                    .ok_or_else(|| CiError::Message("candidate parent absent".into()))?
                    .join(format!("{}-{ordinal}", key.scenario));
                input.descriptor.transcript =
                    input.descriptor.output_root.join("fixture-events.bin");
                input.descriptor_path = owned.output_directory.join("input.json");
                input.descriptor.start_gate = Some(format!(
                    "{}-{}-{ordinal}",
                    base.descriptor
                        .start_gate
                        .as_ref()
                        .ok_or_else(|| CiError::Message(
                            "capacity native start gate absent".into()
                        ))?,
                    key.scenario
                ));
                input.descriptor.cohort_gate = Some(format!(
                    "{}-child",
                    input
                        .descriptor
                        .start_gate
                        .as_ref()
                        .expect("prepared capacity start")
                ));
                input.workload_request = base.workload_request.clone();
                let contract = read(&input.workload_request, 256 * 1024)?;
                memcordon_core::workload_request::WorkloadRequestV1::parse(&contract)
                    .map_err(|error| CiError::Message(error.to_string()))?;
                let mut attempt = blank(key.clone());
                attempt.request_sha256 = Some(crate::windows_causal_acceptance::sha256(&contract));
                let result = execute_until(&owned, &input, &mut attempt, work_deadline);
                let retained = serde_json::to_vec(&attempt)
                    .map_err(CiError::from)
                    .and_then(|bytes| {
                        retain(
                            &directory.join(format!("attempt-{ordinal}.json")),
                            &bytes,
                            record,
                        )
                    });
                record.attempts.push(attempt);
                let outcome = match (result, retained) {
                    (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                        primary: Box::new(primary),
                        secondary: Box::new(secondary.context("capacity observation publication")),
                    }),
                    (Err(primary), _) => Err(primary),
                    (Ok(()), retained) => retained,
                };
                record_execution_outcome(record, outcome)?;
                inventory(config, &directory, ordinal + 1, record, work_deadline)?;
            }
            record.behavior = Ok(());
            record.collection = Ok(());
            record.retirement = Ok(());
        }
        if !accepted(records) {
            return Err(CiError::Message(
                "Windows capacity suite incomplete or failed".into(),
            ));
        }
        Ok(())
    }

    fn overlap(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        base: &crate::windows_consumer_readiness::CaseInput,
        directory: &std::path::Path,
        record: &mut CapacityAssessment,
        work_deadline: std::time::Instant,
    ) -> Result<()> {
        use crate::windows_consumer_readiness::native::{
            HeldFixtureExclusion, event_create, execute_with_baseline_until, process_parents,
            signal,
        };
        use crate::windows_owned_guardian::{GuardianAssociationIdentity, GuardianBaseline};
        let baseline = || {
            GuardianBaseline::quiescent(
                &config.installed_agent.path,
                &config.installed_manifest.path,
                &config.installed_agent.sha256,
                &config.installed_manifest.sha256,
            )
        };
        let first_baseline = baseline()?;
        let second_baseline = baseline()?;
        let prepare = |ordinal: usize| -> Result<_> {
            let mut owned = config.clone();
            owned.output_directory = directory.join(format!("attempt-{ordinal}"));
            fs::create_dir(&owned.output_directory)?;
            attempt_token(config, &owned, base)?;
            let mut input = base.clone();
            input.key = record.key.clone();
            input.descriptor.challenge =
                crate::windows_consumer_readiness::native::random_challenge()?.to_vec();
            input.descriptor.output_root = base
                .descriptor
                .output_root
                .parent()
                .ok_or_else(|| CiError::Message("capacity candidate parent missing".into()))?
                .join(format!("bounded-concurrency-{ordinal}"));
            input.descriptor.transcript = input.descriptor.output_root.join("fixture-events.bin");
            input.descriptor_path = owned.output_directory.join("input.json");
            input.descriptor.start_gate = Some(format!(
                "{}-overlap-{ordinal}",
                base.descriptor
                    .start_gate
                    .as_ref()
                    .ok_or_else(|| CiError::Message("capacity start gate missing".into()))?
            ));
            input.descriptor.cohort_gate = Some(format!(
                "{}-child",
                input
                    .descriptor
                    .start_gate
                    .as_ref()
                    .expect("prepared capacity start")
            ));
            input.workload_request = base.workload_request.clone();
            let mut assessment = blank(record.key.clone());
            assessment.request_sha256 = Some(crate::windows_causal_acceptance::sha256(&read(
                &input.workload_request,
                256 * 1024,
            )?));
            Ok((owned, input, assessment))
        };
        let (first_config, mut first_input, mut first_record) = prepare(0)?;
        let (second_config, second_input, mut second_record) = prepare(1)?;
        let completion_name = format!(
            "{}-completion",
            first_input
                .descriptor
                .start_gate
                .as_ref()
                .expect("prepared start gate")
        );
        let completion = event_create(&completion_name)?;
        first_input.descriptor.completion_gate = Some(completion_name);
        let first_case_directory = first_config
            .output_directory
            .join(&first_input.key.family)
            .join(&first_input.key.scenario);
        let observation_path = first_case_directory.join("live-held-guardian.json");
        let transcript = first_input.descriptor.transcript.clone();
        let first = std::thread::spawn(move || {
            let result = execute_with_baseline_until(
                &first_config,
                &first_input,
                &mut first_record,
                first_baseline,
                Vec::new(),
                None,
                work_deadline,
            );
            (first_record, result)
        });
        let second = (|| -> Result<()> {
            let deadline = work_deadline.min(std::time::Instant::now() + Duration::from_secs(90));
            loop {
                if observation_path.is_file()
                    && transcript.is_file()
                    && crate::windows_consumer_readiness::live_capacity_completion(&read(
                        &transcript,
                        16 * 1024 * 1024,
                    )?)?
                {
                    break;
                }
                // The owned first attempt waits on the completion gate, so an
                // exited worker can never reach held completion. Stop polling
                // now; the unconditional signal/join below surfaces its own
                // error as the primary failure.
                if first.is_finished() {
                    return Err(CiError::Message(
                        "first capacity attempt exited before held natural completion".into(),
                    ));
                }
                if std::time::Instant::now() >= deadline {
                    return Err(CiError::Message(
                        "first capacity attempt did not reach held natural completion".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let identity_bytes = read(&observation_path, 32 * 1024)?;
            let identity: GuardianAssociationIdentity = serde_json::from_slice(&identity_bytes)?;
            retain(
                &directory.join("overlap-held-guardian.json"),
                &identity_bytes,
                record,
            )?;
            let live_bytes = read(
                &first_case_directory.join("live-observation.json"),
                32 * 1024,
            )?;
            let observed: memcordon_core::WindowsGuardianAttemptObservation =
                serde_json::from_slice(&live_bytes)?;
            let root = observed
                .live_target_identity
                .as_ref()
                .ok_or_else(|| CiError::Message("capacity first held target missing".into()))?;
            let child_bytes = read(
                &first_case_directory.join("native-capacity-child.json"),
                16 * 1024,
            )?;
            let peer: serde_json::Value = serde_json::from_slice(&child_bytes)?;
            let peer_pid = u32::try_from(
                peer["pid"]
                    .as_u64()
                    .ok_or_else(|| CiError::Message("capacity child PID missing".into()))?,
            )
            .map_err(|_| CiError::Message("capacity child PID exceeds native width".into()))?;
            let peer_birth = peer["birth"]
                .as_u64()
                .ok_or_else(|| CiError::Message("capacity child birth missing".into()))?;
            let parents = process_parents()?;
            let first_family: Vec<_> = memcordon_testkit::windows_processes_for_image_until(
                &config.fixture.path,
                deadline,
            )?
            .into_iter()
            .filter(|process| {
                (process.identity.pid == root.process_id
                    && process.identity.birth == u128::from(root.creation_time_100ns))
                    || (process.identity.pid == peer_pid
                        && process.identity.birth == u128::from(peer_birth))
            })
            .collect();
            if !observed.is_consistent()
                || peer["format"] != "memcordon.windows-native-capacity-child"
                || peer["revision"].as_u64() != Some(1)
                || peer["native_parent_edge_observed"].as_bool() != Some(true)
                || peer["parent_and_child_held_live"].as_bool() != Some(true)
                || peer_pid == root.process_id
                || peer_birth == 0
                || observed.association.provider != config.provider
                || first_family.len() != 2
                || first_family
                    .iter()
                    .any(|process| !matches!(process.has_exited(), Ok(false)))
                || parents.get(&peer_pid) != Some(&root.process_id)
                || root.creation_time_100ns > peer_birth
                || peer["parent_pid"].as_u64() != Some(u64::from(root.process_id))
                || peer["parent_birth"].as_u64() != Some(root.creation_time_100ns)
            {
                return Err(CiError::Message(
                    "capacity first family lacks exact held live native ancestry".into(),
                ));
            }
            retain(
                &directory.join("overlap-held-native-child.json"),
                &child_bytes,
                record,
            )?;
            retain(
                &directory.join("overlap-live-association.json"),
                &live_bytes,
                record,
            )?;
            execute_with_baseline_until(
                &second_config,
                &second_input,
                &mut second_record,
                second_baseline,
                vec![identity],
                Some(HeldFixtureExclusion {
                    observation: observed,
                    family: first_family,
                }),
                work_deadline,
            )
        })();
        // Release the owned first attempt even when the second fails; joining is
        // mandatory before returning an error or claiming native retirement.
        let release = signal(&completion).map_err(CiError::from);
        let (first_record, first_result) = first
            .join()
            .map_err(|_| CiError::Message("owned capacity controller panicked".into()))?;
        let first_retained = serde_json::to_vec(&first_record)
            .map_err(CiError::from)
            .and_then(|bytes| retain(&directory.join("attempt-0.json"), &bytes, record));
        let second_retained = serde_json::to_vec(&second_record)
            .map_err(CiError::from)
            .and_then(|bytes| retain(&directory.join("attempt-1.json"), &bytes, record));
        let retained = match (first_retained, second_retained) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary.context("second capacity observation publication")),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(()), result) => result,
        };
        record.attempts.extend([first_record, second_record]);
        let first_result = match (release, first_result) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary.context("first capacity attempt")),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(()), result) => result,
        };
        let executed = match (first_result, second) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary.context("second capacity attempt")),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(()), result) => result,
        };
        match (executed, retained) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary.context("capacity observations publication")),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(()), result) => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn token(restricted: bool) -> TokenObservation {
        TokenObservation {
            user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0],
            restricted,
            integrity_rid: 8192,
            elevated: false,
            restricting_sids: if restricted {
                vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]]
            } else {
                Vec::new()
            },
        }
    }

    fn bounded_read(path: &Path, bound: usize) -> Result<Vec<u8>> {
        let bytes = fs::read(path)?;
        if bytes.len() > bound {
            return Err(CiError::Message("token snapshot exceeds bound".into()));
        }
        Ok(bytes)
    }

    fn create_new(path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
            .write_all(bytes)?;
        Ok(())
    }

    fn suite(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "memcordon-capacity-token-{name}-{}",
            std::process::id()
        ));
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn serial_and_overlap_attempt_roots_receive_exact_original_bytes() {
        for restricted in [false, true] {
            let root = suite(if restricted { "restricted" } else { "ordinary" });
            let expected = token(restricted);
            // Pretty-printed original bytes prove byte-for-byte copy, not re-encoding.
            let original = serde_json::to_vec_pretty(&expected).unwrap();
            fs::write(root.join(token_snapshot_leaf(restricted)), &original).unwrap();
            let family = root.join("W-CAPACITY");
            let mut published = Vec::new();
            for scenario in ["serial-retirement", "bounded-concurrency"] {
                for ordinal in 0..2 {
                    let attempt = family.join(scenario).join(format!("attempt-{ordinal}"));
                    fs::create_dir_all(&attempt).unwrap();
                    let path = propagate_token_snapshot(
                        &root,
                        &attempt,
                        &expected,
                        bounded_read,
                        create_new,
                    )
                    .unwrap();
                    assert_eq!(path, attempt.join(token_snapshot_leaf(restricted)));
                    assert_eq!(fs::read(&path).unwrap(), original);
                    published.push(path);
                }
            }
            let distinct: std::collections::BTreeSet<_> = published.iter().collect();
            assert_eq!(distinct.len(), published.len());
            // Create-new semantics: a second propagation into the same root fails.
            let attempt = family.join("serial-retirement").join("attempt-0");
            assert!(
                propagate_token_snapshot(&root, &attempt, &expected, bounded_read, create_new)
                    .is_err()
            );
            fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn executed_capacity_failure_is_never_summarized_as_not_executed() {
        let mut record = CapacityAssessment {
            key: required_keys()[1].clone(),
            behavior: Err("not executed".into()),
            collection: Err("not collected".into()),
            retirement: Err("not observed".into()),
            attempts: Vec::new(),
            artifacts: Vec::new(),
        };
        let error = record_execution_outcome(
            &mut record,
            Err(CiError::Message("second capacity attempt refused".into())),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("second capacity attempt refused"), "{error}");
        let behavior = record.behavior.clone().unwrap_err();
        assert!(behavior.starts_with("executed and failed: "), "{behavior}");
        assert!(
            behavior.contains("second capacity attempt refused"),
            "{behavior}"
        );
        assert!(!behavior.contains("not executed"), "{behavior}");
        assert!(!accepted(std::slice::from_ref(&record)));
        record_execution_outcome(&mut record, Ok(())).unwrap();
        let behavior = record.behavior.clone().unwrap_err();
        assert!(!behavior.contains("not executed"), "{behavior}");
        assert!(record.collection.is_err() && record.retirement.is_err());
        assert!(!accepted(std::slice::from_ref(&record)));
    }

    #[test]
    fn missing_original_token_fails_with_self_describing_path() {
        let root = suite("missing");
        let attempt = root.join("attempt-0");
        fs::create_dir_all(&attempt).unwrap();
        let error =
            propagate_token_snapshot(&root, &attempt, &token(false), bounded_read, create_new)
                .unwrap_err()
                .to_string();
        assert!(error.contains("windows-ordinary-token.json"), "{error}");
        assert!(!attempt.join("windows-ordinary-token.json").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn mismatched_or_unparseable_original_token_is_never_published() {
        let root = suite("mismatch");
        let attempt = root.join("attempt-0");
        fs::create_dir_all(&attempt).unwrap();
        let mut other = token(false);
        other.integrity_rid = 12288;
        fs::write(
            root.join("windows-ordinary-token.json"),
            serde_json::to_vec(&other).unwrap(),
        )
        .unwrap();
        assert!(
            propagate_token_snapshot(&root, &attempt, &token(false), bounded_read, create_new)
                .is_err()
        );
        assert!(!attempt.join("windows-ordinary-token.json").exists());
        fs::write(root.join("windows-restricted-token.json"), b"not json").unwrap();
        assert!(
            propagate_token_snapshot(&root, &attempt, &token(true), bounded_read, create_new)
                .is_err()
        );
        assert!(!attempt.join("windows-restricted-token.json").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn suite_root_is_never_its_own_attempt_root() {
        let root = suite("same");
        let original = serde_json::to_vec(&token(false)).unwrap();
        fs::write(root.join("windows-ordinary-token.json"), &original).unwrap();
        assert!(
            propagate_token_snapshot(&root, &root, &token(false), bounded_read, create_new)
                .is_err()
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
