//! Capacity observations retain each constituent natural attempt and each
//! authenticated public recovery inventory; bounded samples are not quotas.
use crate::windows_consumer_readiness::{CaseAssessment, CaseKey};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};

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
    records.len() == required_keys().len()
        && required_keys()
            .iter()
            .all(|key| records.iter().filter(|record| &record.key == key).count() == 1)
        && records.iter().all(|record| {
            record.behavior.is_ok()
                && record.collection.is_ok()
                && record.retirement.is_ok()
                && !record.attempts.is_empty()
                && !record.artifacts.is_empty()
        })
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

    fn blank(key: CaseKey) -> CaseAssessment {
        CaseAssessment {
            key,
            behavior: Err("not executed".into()),
            collection: Err("not collected".into()),
            retirement: Err("not observed".into()),
            descriptor_sha256: String::new(),
            result_sha256: None,
            stdout_sha256: None,
            stderr_sha256: None,
            transcript_sha256: None,
            contract_sha256: None,
            policy_activation_sha256: None,
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
        let base = suite
            .cases
            .iter()
            .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
            .ok_or_else(|| CiError::Message("capacity lacks owned finite joint workload".into()))?;
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
                overlap(config, base, &directory, record, work_deadline)?;
                inventory(config, &directory, 1, record, work_deadline)?;
                record.behavior = Ok(());
                record.collection = Ok(());
                record.retirement = Ok(());
                continue;
            }
            let count = if key.scenario == "serial-retirement" {
                3
            } else {
                1
            };
            for ordinal in 0..count {
                let mut owned = config.clone();
                owned.output_directory = directory.join(format!("attempt-{ordinal}"));
                fs::create_dir(&owned.output_directory)?;
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
                input.workload_contract = config
                    .output_directory
                    .join("W-JOINT")
                    .join("ordinary")
                    .join("requested-contract.json");
                let contract = read(&input.workload_contract, 256 * 1024)?;
                memcordon_core::workload_contract::WorkloadContractV1::parse(&contract)
                    .map_err(CiError::Message)?;
                let mut attempt = blank(key.clone());
                attempt.contract_sha256 = Some(crate::windows_causal_acceptance::sha256(&contract));
                let activation = read(
                    &config
                        .output_directory
                        .join("windows-policy-activation.json"),
                    256 * 1024,
                )?;
                attempt.policy_activation_sha256 =
                    Some(crate::windows_causal_acceptance::sha256(&activation));
                let result = execute_until(&owned, &input, &mut attempt, work_deadline);
                retain(
                    &directory.join(format!("attempt-{ordinal}.json")),
                    &serde_json::to_vec(&attempt)?,
                    record,
                )?;
                record.attempts.push(attempt);
                result?;
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
            input.workload_contract = config
                .output_directory
                .join("W-JOINT")
                .join("ordinary")
                .join("requested-contract.json");
            let mut assessment = blank(record.key.clone());
            assessment.contract_sha256 = Some(crate::windows_causal_acceptance::sha256(&read(
                &input.workload_contract,
                256 * 1024,
            )?));
            assessment.policy_activation_sha256 =
                Some(crate::windows_causal_acceptance::sha256(&read(
                    &config
                        .output_directory
                        .join("windows-policy-activation.json"),
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
            let peer: serde_json::Value = serde_json::from_slice(&read(
                &first_case_directory.join("native-tcp-peer.json"),
                16 * 1024,
            )?)?;
            let peer_pid = u32::try_from(
                peer["pid"]
                    .as_u64()
                    .ok_or_else(|| CiError::Message("capacity TCP peer PID missing".into()))?,
            )
            .map_err(|_| CiError::Message("capacity TCP peer PID exceeds native width".into()))?;
            let peer_birth = peer["birth"]
                .as_u64()
                .ok_or_else(|| CiError::Message("capacity TCP peer birth missing".into()))?;
            let parents = process_parents()?;
            let first_family: Vec<_> =
                memcordon_testkit::windows_processes_for_image(&config.fixture.path)?
                    .into_iter()
                    .filter(|process| {
                        (process.identity.pid == root.process_id
                            && process.identity.birth == u128::from(root.creation_time_100ns))
                            || (process.identity.pid == peer_pid
                                && process.identity.birth == u128::from(peer_birth))
                    })
                    .collect();
            if !observed.is_consistent()
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
        retain(
            &directory.join("attempt-0.json"),
            &serde_json::to_vec(&first_record)?,
            record,
        )?;
        retain(
            &directory.join("attempt-1.json"),
            &serde_json::to_vec(&second_record)?,
            record,
        )?;
        record.attempts.extend([first_record, second_record]);
        release?;
        first_result?;
        second
    }
}
