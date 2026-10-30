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
        ("C-ADMISSION", "unsupported-profile"),
        ("C-ADMISSION", "malformed-request"),
        ("C-ADMISSION", "unsupported-format"),
        ("C-ADMISSION", "identity-override-rejected"),
        ("W-BINDING", "request-token-override-rejected"),
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
        let image = crate::windows_native_files::hold_artifact(
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
        crate::windows_native_files::verify_named_artifact(&image, &image_path)?;
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
    pub fn run(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input_path: &std::path::Path,
        records: &mut Vec<RefusalAssessment>,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<()> {
        let suite: SuiteInput = serde_json::from_slice(&read(input_path, 4 * 1024 * 1024)?)?;
        crate::windows_consumer_readiness::validate_suite(&suite)?;
        let base = suite
            .cases
            .iter()
            .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
            .ok_or_else(|| CiError::Message("ordinary refusal fixture absent".into()))?;
        let original = read(
            &base.workload_request,
            memcordon_core::workload_limits::REQUEST_BYTES,
        )?;
        memcordon_core::workload_request::WorkloadRequestV1::parse(&original)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let mut first_error = None;
        for key in required_keys() {
            records.push(RefusalAssessment {
                key: key.clone(),
                behavior: Err("not run".into()),
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
                            "substitution fixture is not distinct".into(),
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
                    let failure =
                        crate::windows_installed_cases::validate_installed_selection(&substituted)
                            .expect_err("substituted image cannot match selected acquisition");
                    retain(
                        &directory.join("acquisition-refusal.json"),
                        &serde_json::to_vec(
                            &serde_json::json!({"format":"memcordon.windows-acquisition-refusal","revision":2,"changed_component":"installed-agent","refusal":failure.to_string(),"installation_mutated":false,"target_released":false}),
                        )?,
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
                            base.workload_request.clone().into_os_string(),
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
                    if !output.status.success()
                        || value["code"] != "MCSEALED-WINDOWS-REQUEST"
                        || value["category"] != "Usage"
                        || value["argument_utf16"] != serde_json::json!([97, 0, 98])
                        || !value["target_pid"].is_null()
                        || value["target_released"] != false
                    {
                        return Err(CiError::Message("actual native NUL refusal differs".into()));
                    }
                    retain(
                        &directory.join("native-argument-observation.json"),
                        &bytes,
                        row,
                    )?;
                } else {
                    let mut case = base.clone();
                    case.key = key.clone();
                    case.descriptor.challenge =
                        crate::windows_consumer_readiness::native::random_challenge()?.to_vec();
                    case.descriptor_path = directory.join("input.json");
                    case.descriptor.output_root = base
                        .descriptor
                        .output_root
                        .parent()
                        .ok_or_else(|| CiError::Message("candidate parent absent".into()))?
                        .join(&key.family)
                        .join(&key.scenario);
                    fs::create_dir_all(&case.descriptor.output_root)?;
                    case.descriptor.transcript = case.descriptor.output_root.join("events.bin");
                    retain(
                        &case.descriptor_path,
                        &serde_json::to_vec(&case.descriptor)?,
                        row,
                    )?;
                    let mut value: serde_json::Value = serde_json::from_slice(&original)?;
                    let request = match key.scenario.as_str() {
                        "unsupported-format" => {
                            br#"{"format":"unsupported-request","revision":99}"#.to_vec()
                        }
                        "malformed-request" => {
                            br#"{"format":"memcordon.workload-request","revision":1,"revision":1}"#
                                .to_vec()
                        }
                        "identity-override-rejected" | "request-token-override-rejected" => {
                            value["runtime"]["target_sid"] = serde_json::json!("S-1-5-18");
                            serde_json::to_vec(&value)?
                        }
                        "unsupported-profile" | "admission-refusal" => {
                            value["runtime"]["profile"] = serde_json::json!("unsupported-profile");
                            serde_json::to_vec(&value)?
                        }
                        "unsupported-public-request" => original.clone(),
                        _ => {
                            return Err(CiError::Message(
                                "undeclared current refusal scenario".into(),
                            ));
                        }
                    };
                    case.workload_request = directory.join("workload-request.json");
                    retain(&case.workload_request, &request, row)?;
                    let report = directory.join("result.json");
                    let budget = deadlines.work_budget(Duration::from_secs(90))?;
                    let mut command = public_refusal_command(
                        &config.cli.path,
                        &config.fixture.path,
                        &directory,
                        &report,
                        &case,
                    )?
                    .bounded_until(deadlines.work)
                    .materialize()?;
                    command.env_clear();
                    capture_invocation(&command, &directory, &config.cli.sha256, row)?;
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
                    let detail = String::from_utf8_lossy(&output.stderr);
                    let expected = if key.scenario == "unsupported-public-request" {
                        "MCUSAGE-WORKLOAD-BOUNDARY"
                    } else {
                        "MCUSAGE-WORKLOAD-REQUEST"
                    };
                    if output.status.code() != Some(2)
                        || !detail.contains(expected)
                        || case.descriptor.transcript.try_exists()?
                        || report.try_exists()?
                    {
                        return Err(CiError::Message(format!(
                            "current request refusal did not preserve typed preallocation failure: {detail}"
                        )));
                    }
                    retain(
                        &directory.join("request-refusal.json"),
                        &serde_json::to_vec(
                            &serde_json::json!({"format":"memcordon.windows-request-refusal","revision":2,"scenario":key.scenario,"native_status":output.status.code(),"expected_diagnostic":expected,"target_transcript_absent":true,"report_absent":true}),
                        )?,
                        row,
                    )?;
                }
                row.collection = Ok(());
                row.behavior = Ok(());
                Ok(())
            })();
            let retirement = (|| -> Result<()> {
                let baseline = GuardianBaseline::quiescent(
                    &config.installed_agent.path,
                    &config.installed_manifest.path,
                    &config.installed_agent.sha256,
                    &config.installed_manifest.sha256,
                )?;
                if !memcordon_testkit::windows_processes_for_image_until(
                    &config.fixture.path,
                    deadlines.cleanup,
                )?
                .is_empty()
                {
                    return Err(CiError::Message(
                        "refusal retained native fixture process".into(),
                    ));
                }
                retain(
                    &directory.join("native-guardian-quiescence.json"),
                    &baseline.quiescence_receipt()?,
                    row,
                )?;
                retain(
                    &directory.join("native-quiescence.json"),
                    &serde_json::to_vec(
                        &serde_json::json!({"format":"memcordon.windows-native-refusal-quiescence","revision":2,"provider":config.provider,"guardian_native_quiescence":true,"fixture_processes_absent":true}),
                    )?,
                    row,
                )?;
                Ok(())
            })();
            row.retirement = retirement.as_ref().map(|_| ()).map_err(ToString::to_string);
            if let Err(error) = result {
                row.behavior = Err(error.to_string());
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            if let Err(error) = retirement {
                if first_error.is_none() {
                    first_error = Some(error);
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
                "current Windows refusal suite incomplete".into(),
            ))
        }
    }
}
