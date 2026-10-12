//! Genuine preauthorization refusals preserve the original public result and
//! native argument diagnostics without inventing a target terminal receipt.
#[cfg(windows)]
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalAssessment {
    pub key: crate::windows_consumer_readiness::CaseKey,
    pub behavior: std::result::Result<(), String>,
    pub collection: std::result::Result<(), String>,
    pub retirement: std::result::Result<(), String>,
    pub artifacts: Vec<crate::windows_installed_cases::SelectedArtifact>,
}
pub fn required_keys() -> Vec<crate::windows_consumer_readiness::CaseKey> {
    [
        ("W-IO", "argv-nul-rejection"),
        ("W-STATUS", "admission-refusal"),
        ("W-BINDING", "stale-policy-epoch"),
        ("W-BINDING", "revoked-grant"),
        ("W-BINDING", "wrong-authorized-caller"),
        ("W-BINDING", "unsupported-public-request"),
        ("W-BINDING", "component-substitution"),
    ]
    .into_iter()
    .map(
        |(family, scenario)| crate::windows_consumer_readiness::CaseKey {
            family: family.into(),
            scenario: scenario.into(),
        },
    )
    .collect()
}
pub fn accepted(records: &[RefusalAssessment]) -> bool {
    records.len() == required_keys().len()
        && required_keys()
            .iter()
            .all(|key| records.iter().filter(|row| row.key == *key).count() == 1)
        && records.iter().all(|row| {
            row.behavior.is_ok()
                && row.collection.is_ok()
                && row.retirement.is_ok()
                && !row.artifacts.is_empty()
        })
}
#[cfg(windows)]
pub(crate) fn run(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &std::path::Path,
    records: &mut Vec<RefusalAssessment>,
) -> Result<()> {
    run_until(
        config,
        input_path,
        records,
        crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default(),
    )
}

#[cfg(windows)]
pub(crate) fn run_until(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &std::path::Path,
    records: &mut Vec<RefusalAssessment>,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<()> {
    native::run(config, input_path, records, deadlines)
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::windows_consumer_readiness::{SuiteInput, native::read, public_refusal_command};
    use crate::{command::CommandSpec, windows_owned_guardian::GuardianBaseline};
    use std::{
        ffi::OsString,
        fs::{self, OpenOptions},
        io::Write,
        time::Duration,
    };
    fn retain(path: &std::path::Path, bytes: &[u8], row: &mut RefusalAssessment) -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if read(path, bytes.len())? != bytes {
            return Err(CiError::Message(
                "refusal named artifact readback differs".into(),
            ));
        }
        row.artifacts
            .push(crate::windows_installed_cases::SelectedArtifact {
                path: path.to_owned(),
                sha256: crate::windows_causal_acceptance::sha256(bytes),
            });
        Ok(())
    }
    fn capture_invocation(
        command: &std::process::Command,
        directory: &std::path::Path,
        executable_sha256: &str,
        row: &mut RefusalAssessment,
    ) -> Result<()> {
        use std::os::windows::ffi::OsStrExt;
        retain(
            &directory.join("native-invocation.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-native-refusal-invocation","revision":1,
                "executable_sha256":executable_sha256,"public_executable_sha256":executable_sha256,
                "program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
                "public_program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
                "argv_utf16":command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                "cwd_utf16":command.get_current_dir().ok_or_else(||CiError::Message("refusal native cwd absent".into()))?.as_os_str().encode_wide().collect::<Vec<_>>(),
                "environment_cleared":true
            }))?,
            row,
        )
    }
    fn capture_exit(
        output: &memcordon_testkit::ObservedOutput,
        directory: &std::path::Path,
        executable_sha256: &str,
        row: &mut RefusalAssessment,
    ) -> Result<()> {
        retain(
            &directory.join("native-exit.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-native-refusal-exit","revision":1,"executable_sha256":executable_sha256,
                "native_status":output.status.code(),"capture_complete":true
            }))?,
            row,
        )
    }

    fn capture_owned_frontend(
        command: std::process::Command,
        budget: Duration,
        image_sha256: &str,
        directory: &std::path::Path,
        row: &mut RefusalAssessment,
    ) -> Result<memcordon_testkit::ObservedOutput> {
        use std::sync::{Arc, Mutex};
        let image_path = std::path::PathBuf::from(command.get_program());
        let image = crate::windows_readiness_adapter::hold_artifact(
            &image_path,
            Some(image_sha256),
            512 * 1024 * 1024,
        )?;
        let held = Arc::new(Mutex::new(None));
        let spawning = Arc::clone(&held);
        let output = memcordon_testkit::run_with_deadline_owned_spawn_after_output_limit(
            command,
            budget,
            256 * 1024,
            move |mut command| {
                let mut child = command.spawn()?;
                match owned_frontend_birth(&child) {
                    Ok(birth) => {
                        *spawning.lock().expect("frontend identity mutex poisoned") =
                            Some((child.id(), birth));
                        Ok(child)
                    }
                    Err(original) => {
                        let signal = child.kill();
                        let wait = child.wait();
                        Err(std::io::Error::other(format!(
                            "{original}; owned frontend signal={signal:?}; wait={wait:?}"
                        )))
                    }
                }
            },
            |_| Ok(()),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        crate::windows_readiness_adapter::verify_named_artifact(&image, &image_path)?;
        let (pid, birth) = held
            .lock()
            .expect("frontend identity mutex poisoned")
            .ok_or_else(|| CiError::Message("actual owned frontend identity absent".into()))?;
        retain(
            &directory.join("native-frontend.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-native-refusal-frontend","revision":1,
                "process_id":pid,"creation_time_100ns":birth,"image_sha256":image_sha256,
                "held_before_wait":true,"native_wait_completed":true,"native_status":output.status.code(),
                "stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),
                "stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr)
            }))?,
            row,
        )?;
        Ok(output)
    }

    #[allow(unsafe_code)]
    fn owned_frontend_birth(child: &std::process::Child) -> std::io::Result<u64> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: Child retains the exact process handle, including for a fast
        // exit; all four outputs are initialized writable FILETIME structures.
        if unsafe {
            GetProcessTimes(
                child.as_raw_handle(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let birth = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if birth == 0 {
            return Err(std::io::Error::other(
                "owned frontend creation time is zero",
            ));
        }
        Ok(birth)
    }
    fn apply(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        path: &std::path::Path,
        prefix: &str,
        directory: &std::path::Path,
        row: &mut RefusalAssessment,
        cutoff: std::time::Instant,
    ) -> Result<memcordon_core::workload_contract::PolicyEpoch> {
        let configured = memcordon_core::workload_registry::RuntimePolicyRegistry::parse(&read(
            path,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        let budget = cutoff
            .saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_secs(90));
        if budget.is_zero() {
            return Err(CiError::Message(
                "original Windows policy-operation deadline exhausted".into(),
            ));
        }
        let mut command = CommandSpec::new(&config.installed_agent.path, directory, budget)
            .args([
                OsString::from("package"),
                "policy".into(),
                "apply".into(),
                "--file".into(),
                path.as_os_str().to_owned(),
            ])
            .materialize()?;
        command.env_clear();
        let output =
            memcordon_testkit::run_with_deadline_output_limit(&mut command, budget, 256 * 1024)
                .map_err(|error| CiError::Message(error.to_string()))?;
        let stdout_name = std::path::PathBuf::from(prefix).with_extension("stdout.json");
        let stderr_name = std::path::PathBuf::from(prefix).with_extension("stderr.bin");
        retain(&directory.join(stdout_name), &output.stdout, row)?;
        retain(&directory.join(stderr_name), &output.stderr, row)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Activation {
            format: String,
            revision: u32,
            registry: memcordon_core::workload_registry::RuntimePolicyRegistry,
            registry_digest: memcordon_core::DiagnosticSha256,
            epoch: memcordon_core::workload_contract::PolicyEpoch,
            revoked_admissions:
                memcordon_core::BoundedVec<memcordon_core::workload_contract::Nonce128, 256>,
        }
        let activation: Activation = serde_json::from_slice(&output.stdout)?;
        if !output.status.success()
            || activation.format != "memcordon.local-activation"
            || activation.revision != 1
            || activation.registry != configured
            || activation.registry_digest
                != configured.canonical_digest().map_err(CiError::Message)?
            || !activation.revoked_admissions.as_slice().is_empty()
        {
            return Err(CiError::Message(
                "owned refusal policy activation differs from exact V1 definition/quiescent state"
                    .into(),
            ));
        }
        Ok(activation.epoch)
    }
    pub fn run(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input_path: &std::path::Path,
        records: &mut Vec<RefusalAssessment>,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<()> {
        let suite: SuiteInput = serde_json::from_slice(&read(input_path, 4 * 1024 * 1024)?)?;
        let base = suite
            .cases
            .iter()
            .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
            .ok_or_else(|| CiError::Message("refusal driver baseline absent".into()))?;
        let active_path = config
            .output_directory
            .join("W-JOINT")
            .join("ordinary")
            .join("requested-contract.json");
        let active = memcordon_core::workload_contract::WorkloadContractV1::parse(&read(
            &active_path,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        let stale = memcordon_core::workload_contract::WorkloadContractV1::parse(&read(
            &base.workload_contract,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        if stale.expected_epoch == active.expected_epoch {
            return Err(CiError::Message(
                "refusal driver lacks actually stale policy epoch".into(),
            ));
        }
        let mut first_error = None;
        for key in required_keys() {
            records.push(RefusalAssessment {
                key: key.clone(),
                behavior: Err("not observed".into()),
                collection: Err("not collected".into()),
                retirement: Err("not observed".into()),
                artifacts: Vec::new(),
            });
            let row = records.last_mut().expect("owned refusal row");
            let directory = config
                .output_directory
                .join(&key.family)
                .join(&key.scenario);
            fs::create_dir_all(&directory)?;
            let challenge = crate::windows_consumer_readiness::native::random_challenge()?.to_vec();
            retain(&directory.join("challenge.bin"), &challenge, row)?;
            let changes_policy =
                ["revoked-grant", "wrong-authorized-caller"].contains(&key.scenario.as_str());
            let result = (|| -> Result<()> {
                GuardianBaseline::quiescent(
                    &config.installed_agent.path,
                    &config.installed_manifest.path,
                    &config.installed_agent.sha256,
                    &config.installed_manifest.sha256,
                )?;
                if key.scenario == "component-substitution" {
                    crate::windows_installed_cases::validate_installed_selection(config)?;
                    let mut substituted = config.clone();
                    if config.fixture.sha256 == config.installed_agent.sha256 {
                        return Err(CiError::Message(
                            "component substitution lacks a distinct measured fixture image".into(),
                        ));
                    }
                    substituted.installed_agent = config.fixture.clone();
                    retain(
                        &directory.join("original-acquisition.json"),
                        &serde_json::to_vec(config)?,
                        row,
                    )?;
                    retain(
                        &directory.join("substituted-acquisition.json"),
                        &serde_json::to_vec(&substituted)?,
                        row,
                    )?;
                    let refusal =
                        crate::windows_installed_cases::validate_installed_selection(&substituted)
                            .expect_err(
                                "distinct fixture cannot be accepted as installed selected agent",
                            );
                    if refusal.to_string() != "selected installed channel identity differs" {
                        return Err(CiError::Message("component substitution did not reach exact selected image binding check".into()));
                    }
                    retain(
                        &directory.join("acquisition-refusal.json"),
                        &serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-acquisition-refusal","revision":1,
                            "operation":"validate-installed-selection","original_accepted":true,
                            "changed_component":"installed-agent","refusal":refusal.to_string(),
                            "installation_mutated":false,"target_released":false
                        }))?,
                        row,
                    )?;
                } else if key.scenario == "argv-nul-rejection" {
                    let report = directory.join("native-argument-refusal.json");
                    let budget = deadlines.work_budget(Duration::from_secs(90))?;
                    let mut command = CommandSpec::new(&config.fixture.path, &directory, budget)
                        .args([
                            OsString::from("consumer-readiness-windows"),
                            "argv-nul-refusal".into(),
                            config.fixture.path.clone().into_os_string(),
                            active_path.clone().into_os_string(),
                            report.clone().into_os_string(),
                        ])
                        .materialize()?;
                    command.env_clear();
                    capture_invocation(&command, &directory, &config.fixture.sha256, row)?;
                    let output = capture_owned_frontend(
                        command,
                        budget,
                        &config.fixture.sha256,
                        &directory,
                        row,
                    )?;
                    capture_exit(&output, &directory, &config.fixture.sha256, row)?;
                    retain(&directory.join("stdout.bin"), &output.stdout, row)?;
                    retain(&directory.join("stderr.bin"), &output.stderr, row)?;
                    let bytes = read(&report, 64 * 1024)?;
                    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                    row.artifacts
                        .push(crate::windows_installed_cases::SelectedArtifact {
                            path: report,
                            sha256: crate::windows_causal_acceptance::sha256(&bytes),
                        });
                    if !output.status.success()
                        || value.get("code").and_then(serde_json::Value::as_str)
                            != Some("MCSEALED-WINDOWS-REQUEST")
                        || value.get("category").and_then(serde_json::Value::as_str)
                            != Some("Usage")
                        || value.get("argument_utf16") != Some(&serde_json::json!([97, 0, 98]))
                        || !value
                            .get("target_pid")
                            .is_some_and(serde_json::Value::is_null)
                        || value.get("target_released") != Some(&serde_json::Value::Bool(false))
                    {
                        return Err(CiError::Message(
                            "actual native NUL refusal origin/bytes/authorization differs".into(),
                        ));
                    }
                } else {
                    let mut case = base.clone();
                    case.key = key.clone();
                    case.descriptor.challenge = challenge.clone();
                    case.descriptor_path = directory.join("never-authorized-input.json");
                    case.descriptor.output_root = base
                        .descriptor
                        .output_root
                        .parent()
                        .ok_or_else(|| CiError::Message("refusal candidate parent absent".into()))?
                        .join(&key.scenario);
                    case.descriptor.transcript = case
                        .descriptor
                        .output_root
                        .join("never-authorized-events.bin");
                    let mut requested = if key.scenario == "unsupported-public-request" {
                        active.clone()
                    } else {
                        stale.clone()
                    };
                    if changes_policy {
                        let mut registry =
                            memcordon_core::workload_registry::RuntimePolicyRegistry::parse(&read(
                                &suite.local_policy,
                                256 * 1024,
                            )?)
                            .map_err(CiError::Message)?;
                        let mut grants = memcordon_core::BoundedVec::default();
                        for grant in registry.grants.as_slice() {
                            let mut grant = grant.clone();
                            if key.scenario == "revoked-grant" {
                                grant.enabled = false;
                            } else {
                                use memcordon_core::workload_registry::CallerSelector;
                                let sid = if grant.callers.as_slice().iter().any(|caller| {
                                    matches!(caller,
                                    CallerSelector::Windows { sid } if sid.as_str() == "S-1-5-19")
                                }) {
                                    "S-1-5-20"
                                } else {
                                    "S-1-5-19"
                                };
                                let mut callers = memcordon_core::BoundedVec::default();
                                callers
                                    .try_push(CallerSelector::Windows {
                                        sid: memcordon_core::BoundedText::new(sid)
                                            .map_err(|error| CiError::Message(error.to_string()))?,
                                    })
                                    .map_err(|_| {
                                        CiError::Message("owned caller bound exceeded".into())
                                    })?;
                                grant.callers = callers;
                            }
                            grants.try_push(grant).map_err(|_| {
                                CiError::Message("owned grant bound exceeded".into())
                            })?;
                        }
                        registry.grants = grants;
                        registry.validate().map_err(CiError::Message)?;
                        let policy_path = directory.join("changed-policy.json");
                        retain(&policy_path, &serde_json::to_vec(&registry)?, row)?;
                        requested = active.clone();
                        requested.expected_epoch = apply(
                            config,
                            &policy_path,
                            "policy-apply",
                            &directory,
                            row,
                            deadlines.work,
                        )?;
                    }
                    case.workload_contract = directory.join("requested-contract.json");
                    retain(
                        &case.workload_contract,
                        &serde_json::to_vec(&requested)?,
                        row,
                    )?;
                    retain(
                        &case.descriptor_path,
                        &serde_json::to_vec(&case.descriptor)?,
                        row,
                    )?;
                    let report = directory.join("result.json");
                    let mut command = public_refusal_command(
                        &config.cli.path,
                        &config.fixture.path,
                        &directory,
                        &report,
                        &case,
                    )?
                    .materialize()?;
                    command.env_clear();
                    capture_invocation(&command, &directory, &config.cli.sha256, row)?;
                    let budget = deadlines.work_budget(Duration::from_secs(90))?;
                    let output = capture_owned_frontend(
                        command,
                        budget,
                        &config.cli.sha256,
                        &directory,
                        row,
                    )?;
                    capture_exit(&output, &directory, &config.cli.sha256, row)?;
                    retain(&directory.join("stdout.bin"), &output.stdout, row)?;
                    retain(&directory.join("stderr.bin"), &output.stderr, row)?;
                    let bytes = read(&report, 2 * 1024 * 1024)?;
                    let result =
                        memcordon_core::ResultV1::parse(&bytes).map_err(CiError::Message)?;
                    row.artifacts
                        .push(crate::windows_installed_cases::SelectedArtifact {
                            path: report,
                            sha256: crate::windows_causal_acceptance::sha256(&bytes),
                        });
                    let expected_authorization = if key.scenario == "unsupported-public-request" {
                        memcordon_core::result_v1::AuthorizationV1::NotRequiredForStandard
                    } else {
                        memcordon_core::result_v1::AuthorizationV1::RejectedBeforeRelease
                    };
                    if result.authorization != expected_authorization
                        || result.launch.target_pid.is_some()
                        || result.launch.state
                            != memcordon_core::result_v1::LaunchStateV1::NotCreated
                        || result.outcome.kind
                            == memcordon_core::result_v1::OutcomeKindV1::Completed
                        || output.status.code() != Some(result.outcome.wrapper_status)
                        || case.descriptor.transcript.try_exists()?
                    {
                        return Err(CiError::Message(
                            "stale admission request authorized target or replaced refusal origin"
                                .into(),
                        ));
                    }
                    if key.scenario == "unsupported-public-request"
                        && (result.provider_association.is_some()
                            || !matches!(
                                &result.runtime,
                                memcordon_core::result_v1::RuntimeV1::Standard {
                                    observation: None
                                }
                            )
                            || !result.error.as_ref().is_some_and(|error| {
                                error.code == "MCUNSUPPORTED-WORKLOAD-CONTRACT"
                                    && error.category == "unsupported"
                            }))
                    {
                        return Err(CiError::Message(
                            "unsupported public contract did not retain exact typed refusal".into(),
                        ));
                    }
                    if key.scenario != "unsupported-public-request" {
                        let request_path = directory.join("provider-request.bin");
                        let request_bytes =
                            read(&request_path, memcordon_core::WINDOWS_MAX_FRAME_BYTES)?;
                        let request_sha256 =
                            crate::windows_causal_acceptance::sha256(&request_bytes);
                        let association=result.provider_association.as_ref()
                            .ok_or_else(||CiError::Message("authenticated admission refusal has no provider request association".into()))?;
                        if association.provider != config.provider
                            || String::from(association.request_sha256.clone()) != request_sha256
                        {
                            return Err(CiError::Message("actual admission refusal request bytes differ from authenticated selected provider association".into()));
                        }
                        row.artifacts
                            .push(crate::windows_installed_cases::SelectedArtifact {
                                path: request_path,
                                sha256: request_sha256,
                            });
                        let rejection = result
                            .error
                            .as_ref()
                            .and_then(|error| error.windows_provider_rejection_v2.as_ref())
                            .ok_or_else(|| {
                                CiError::Message(
                                    "policy refusal lacks actual typed Windows rejection".into(),
                                )
                            })?;
                        let admission = rejection.workload_admission.as_ref().ok_or_else(|| {
                            CiError::Message(
                                "policy refusal lacks actual workload admission cause".into(),
                            )
                        })?;
                        let expected = if changes_policy {
                            memcordon_core::workload_registry::AdmissionCode::ProfileNotAuthorized
                        } else {
                            memcordon_core::workload_registry::AdmissionCode::PolicyEpochStale
                        };
                        if rejection.code!="MCSEALED-POLICY-ADMISSION" || rejection.target_created || rejection.target_released
                            || admission.rejection.code!=expected
                            || admission.request!=memcordon_core::workload_evidence::RequestBindingV1::from_contract(&requested).map_err(CiError::Message)?
                            || !matches!(rejection.disposition,memcordon_core::WindowsProviderRejectionDispositionV2::Preauthorization {terminal_ack_required:false}) {
                            return Err(CiError::Message("policy refusal does not retain exact selected admission cause and request binding".into()));
                        }
                    }
                }
                row.behavior = Ok(());
                row.collection = Ok(());
                Ok(())
            })();
            let restored = if changes_policy {
                apply(
                    config,
                    &suite.local_policy,
                    "policy-restore",
                    &directory,
                    row,
                    deadlines.cleanup,
                )
                .map(|_| ())
            } else {
                Ok(())
            };
            let retirement = restored.and_then(|_| {
                GuardianBaseline::quiescent(
                    &config.installed_agent.path,
                    &config.installed_manifest.path,
                    &config.installed_agent.sha256,
                    &config.installed_manifest.sha256,
                )
                .and_then(|_| {
                    if memcordon_testkit::windows_processes_for_image(&config.fixture.path)?
                        .is_empty()
                    {
                        Ok(())
                    } else {
                        Err(CiError::Message(
                            "preauthorization refusal retained native fixture process".into(),
                        ))
                    }
                })
            });
            let retirement = retirement.and_then(|_| {
                let baseline = GuardianBaseline::quiescent(
                    &config.installed_agent.path,
                    &config.installed_manifest.path,
                    &config.installed_agent.sha256,
                    &config.installed_manifest.sha256,
                )?;
                retain(
                    &directory.join("native-guardian-quiescence.json"),
                    &baseline.quiescence_receipt()?,
                    row,
                )?;
                retain(
                    &directory.join("native-quiescence.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-native-refusal-quiescence","revision":1,"provider":config.provider,
                        "installed_agent_sha256":config.installed_agent.sha256,"runtime_manifest_sha256":config.installed_manifest.sha256,
                        "guardian_native_quiescence":true,"fixture_processes_absent":true,
                        "owned_policy_restoration_required":changes_policy,"owned_policy_restoration_completed":changes_policy
                    }))?,
                    row,
                )?;
                Ok(())
            });
            row.retirement = retirement.as_ref().map(|_| ()).map_err(ToString::to_string);
            if let Err(error) = result {
                row.behavior = Err(error.to_string());
                row.collection = Err(error.to_string());
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            if retirement.is_err() {
                if first_error.is_none() {
                    first_error = retirement.err();
                }
                break;
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else if accepted(records) {
            Ok(())
        } else {
            Err(CiError::Message(
                "Windows preauthorization refusal suite incomplete".into(),
            ))
        }
    }
}
