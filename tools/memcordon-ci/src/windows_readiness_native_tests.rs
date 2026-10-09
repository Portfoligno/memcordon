//! Exact native component test execution with explicit stdin receipt requests.
//! Test harness success and native operation observations are separate facts.
#[cfg(windows)]
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTestInput {
    pub run_id: String,
    pub recipe_id: String,
    pub native_target: String,
    pub executable: crate::windows_installed_cases::SelectedArtifact,
    pub output_directory: std::path::PathBuf,
    pub artifact_prefix: std::path::PathBuf,
    /// Original producer cutoff, owned by the native job rather than its fixtures.
    #[serde(skip)]
    pub work_deadline: Option<std::time::Instant>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTestAssessment {
    pub test_name: String,
    pub family: String,
    pub scenarios: Vec<String>,
    pub behavior: std::result::Result<(), String>,
    pub collection: std::result::Result<(), String>,
    pub retirement: std::result::Result<(), String>,
    pub artifacts: Vec<crate::windows_installed_cases::SelectedArtifact>,
}
pub const WRITER_MATRIX: &str = "windows::record::record_fault_tests::native_publication_fault_matrix_preserves_original_and_honest_commit_boundary";
pub const WRITER_NATIVE_RENAME: &str = "windows::record::record_fault_tests::native_rename_sharing_failure_retains_typed_code_and_original";
pub const WRITER_CRASH: &str = "windows::record::record_fault_tests::native_publisher_process_exit_preserves_atomic_old_or_new_record";
pub const WRITER_FROZEN: &str = "windows::record::record_fault_tests::frozen_native_publication_does_not_own_workload_job_cleanup";
pub const WRITER_RESERVATION: &str = "windows::record::record_fault_tests::native_settlement_reservation_requires_local_writer_retirement";
pub const RETAINED_BINDING: &str = "windows::control_service::retained_binding_tests::authenticated_retained_binding_rejects_other_attempt_request_process_creation_and_token";
pub const BINDING_SEED: &str = "windows_postauthorization_retirement::terminal_seed_freezes_before_proof_and_rejects_replacement";
pub const BINDING_PROOF: &str = "windows_postauthorization_retirement::frozen_seed_accepts_only_matching_later_retirement_proof";
pub const BINDING_RECEIPTLESS: &str = "windows_postauthorization_retirement::receiptless_posttarget_rejection_cannot_bypass_terminal_binding";
pub const BINDING_GENERATION: &str = "windows::record::record_fault_tests::native_durable_record_rejects_provider_generation_substitution";
pub const BINDING_PROJECTION: &str = "windows::record::record_fault_tests::native_provider_projection_preserves_original_and_reports_bounded_loss";
pub const OWNED_OUTBOX_REPLAY: &str = "windows_postauthorization_retirement::suspended_postauthorization_rejection_stages_replays_and_retires_bound_outbox";
pub const NATIVE_CAUSAL_CAPTURE: &str = "windows::diagnostics::causal_capture_tests::native_invalid_handle_capture_preserves_first_cause_across_phase_change";
pub const INDEX_PARSER: &str = "native_index_mutations_emit_actual_parser_receipts";
pub const OPERATIONAL_PARSER: &str =
    "operational_parser_receipts::native_operational_parser_mutations_emit_actual_receipts";

#[cfg(windows)]
pub fn run_parser(input: &NativeTestInput, records: &mut Vec<NativeTestAssessment>) -> Result<()> {
    native::run_parser(input, records)
}

#[cfg(windows)]
pub fn run(input: &NativeTestInput, records: &mut Vec<NativeTestAssessment>) -> Result<()> {
    native::run(input, records)
}

#[cfg(windows)]
mod native {
    use super::*;
    pub fn run_parser(
        input: &NativeTestInput,
        records: &mut Vec<NativeTestAssessment>,
    ) -> Result<()> {
        run_named(
            input,
            records,
            "index-parser",
            INDEX_PARSER,
            "C-PARSER",
            &["omitted-case", "duplicate-case", "wrong-product"],
        )?;
        run_named(
            input,
            records,
            "operational-parser",
            OPERATIONAL_PARSER,
            "C-PARSER",
            &[
                "duplicate-key",
                "wrong-format",
                "wrong-revision",
                "unknown-authority-variant",
                "oversized-record",
                "stale-attempt",
                "forged-cleanup",
            ],
        )
    }
    use crate::windows_consumer_readiness::native::read;
    use std::{
        fs::{self, OpenOptions},
        io::{self, Write},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    #[allow(unsafe_code)]
    fn fresh_challenge() -> Result<[u8; 32]> {
        let mut challenge = [0u8; 32];
        // SAFETY: the system-preferred RNG writes only this initialized owned
        // buffer. This challenge is test input, never operational authority.
        if unsafe {
            windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
                std::ptr::null_mut(),
                challenge.as_mut_ptr(),
                challenge.len() as u32,
                windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } != 0
            || challenge.iter().all(|byte| *byte == 0)
        {
            return Err(CiError::Message(
                "native component controller challenge acquisition failed".into(),
            ));
        }
        Ok(challenge)
    }
    fn retain(
        path: &std::path::Path,
        bytes: &[u8],
        record: &mut NativeTestAssessment,
    ) -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if read(path, bytes.len())? != bytes {
            return Err(CiError::Message(
                "native test output named readback differs".into(),
            ));
        }
        record
            .artifacts
            .push(crate::windows_installed_cases::SelectedArtifact {
                path: path.to_owned(),
                sha256: crate::windows_causal_acceptance::sha256(bytes),
            });
        Ok(())
    }
    pub fn run(input: &NativeTestInput, records: &mut Vec<NativeTestAssessment>) -> Result<()> {
        run_one(
            input,
            records,
            "writer-matrix",
            WRITER_MATRIX,
            &[
                "serialization-error",
                "write-error",
                "rename-error",
                "readback-error",
            ],
        )?;
        run_one(
            input,
            records,
            "writer-native-rename",
            WRITER_NATIVE_RENAME,
            &["rename-error"],
        )?;
        run_one(
            input,
            records,
            "writer-crash",
            WRITER_CRASH,
            &["crash-before-durable", "crash-after-durable"],
        )?;
        run_one(
            input,
            records,
            "writer-frozen",
            WRITER_FROZEN,
            &["frozen-live"],
        )?;
        run_one(
            input,
            records,
            "writer-reservation",
            WRITER_RESERVATION,
            &["settlement-reservation"],
        )?;
        run_named(
            input,
            records,
            "retained-binding",
            RETAINED_BINDING,
            "W-BINDING",
            &[
                "caller-substitution",
                "attempt-substitution",
                "request-substitution",
            ],
        )?;
        run_named(
            input,
            records,
            "binding-seed",
            BINDING_SEED,
            "W-BINDING",
            &["seed-replacement"],
        )?;
        run_named(
            input,
            records,
            "binding-proof",
            BINDING_PROOF,
            "W-BINDING",
            &["proof-mismatch"],
        )?;
        run_named(
            input,
            records,
            "binding-receiptless",
            BINDING_RECEIPTLESS,
            "W-BINDING",
            &["receiptless-posttarget"],
        )?;
        run_named(
            input,
            records,
            "causal-receiptless",
            BINDING_RECEIPTLESS,
            "W-CAUSAL",
            &["receiptless-first-cause"],
        )?;
        run_named(
            input,
            records,
            "binding-generation",
            BINDING_GENERATION,
            "W-BINDING",
            &["generation-substitution"],
        )?;
        run_named(
            input,
            records,
            "binding-projection",
            BINDING_PROJECTION,
            "W-BINDING",
            &["projection-bounds"],
        )?;
        run_named(
            input,
            records,
            "owned-outbox-replay",
            OWNED_OUTBOX_REPLAY,
            "W-REPLAY",
            &[
                "durable-replay",
                "lost-publication-response",
                "lost-acknowledgement",
                "expiry-authority",
            ],
        )?;
        run_named(
            input,
            records,
            "native-causal-capture",
            NATIVE_CAUSAL_CAPTURE,
            "W-CAUSAL",
            &["native-code-capture"],
        )
    }
    fn run_one(
        input: &NativeTestInput,
        records: &mut Vec<NativeTestAssessment>,
        directory_name: &str,
        test_name: &'static str,
        scenarios: &[&str],
    ) -> Result<()> {
        run_named(
            input,
            records,
            directory_name,
            test_name,
            "W-WRITER",
            scenarios,
        )
    }
    fn run_named(
        input: &NativeTestInput,
        records: &mut Vec<NativeTestAssessment>,
        directory_name: &str,
        test_name: &'static str,
        family: &str,
        scenarios: &[&str],
    ) -> Result<()> {
        if !input.output_directory.is_absolute()
            || !input.executable.path.is_absolute()
            || !matches!(
                input.native_target.as_str(),
                "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc"
            )
            || crate::windows_causal_acceptance::sha256(&read(
                &input.executable.path,
                512 * 1024 * 1024,
            )?) != input.executable.sha256
        {
            return Err(CiError::Message(
                "native test driver requires measured absolute native support executable/input"
                    .into(),
            ));
        }
        fs::create_dir_all(&input.output_directory)?;
        let directory = input.output_directory.join(directory_name);
        fs::create_dir(&directory)?;
        let artifact_root = directory.join("authority");
        let challenge = fresh_challenge()?;
        let parser = [INDEX_PARSER, OPERATIONAL_PARSER].contains(&test_name);
        let request = if parser {
            fs::create_dir(&artifact_root)?;
            let prefix = input.artifact_prefix.join(directory_name).join("authority");
            let prefix = prefix
                .components()
                .map(|component| match component {
                    std::path::Component::Normal(value) => value.to_str().ok_or_else(|| {
                        CiError::Message("parser artifact prefix encoding differs".into())
                    }),
                    _ => Err(CiError::Message(
                        "parser artifact prefix is not confined".into(),
                    )),
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            serde_json::to_vec(
                &serde_json::json!({"run_id":input.run_id,"recipe_id":input.recipe_id,
                "native_target":input.native_target,"artifact_root":artifact_root,"artifact_prefix":prefix,"challenge":challenge}),
            )?
        } else {
            serde_json::to_vec(
                &serde_json::json!({"run_id":input.run_id,"recipe_id":input.recipe_id,
            "test_name":test_name,"native_target":input.native_target,"executable_sha256":input.executable.sha256,
            "artifact_root":artifact_root,"artifact_prefix":input.artifact_prefix.join(directory_name).join("authority"),"challenge":challenge}),
            )?
        };
        if request.len() > 4096 {
            return Err(CiError::Message(
                "native test stdin request exceeds controlled pipe bound".into(),
            ));
        }
        records.push(NativeTestAssessment {
            test_name: test_name.into(),
            family: family.into(),
            scenarios: scenarios
                .iter()
                .map(|scenario| (*scenario).to_owned())
                .collect(),
            behavior: Err("not observed".into()),
            collection: Err("not collected".into()),
            retirement: Err("not observed".into()),
            artifacts: Vec::new(),
        });
        let record = records.last_mut().expect("owned native test observation");
        retain(&directory.join("challenge.bin"), &challenge, record)?;
        retain(&directory.join("stdin.json"), &request, record)?;
        let held = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&held);
        let pre_input = Arc::new(Mutex::new(None));
        let pre_input_capture = Arc::clone(&pre_input);
        let image_sha256 = input.executable.sha256.clone();
        let image = input.executable.path.clone();
        let work_deadline = input
            .work_deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(180));
        let budget = work_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(180));
        if budget.is_zero() {
            return Err(CiError::Message(
                "original native component work cutoff exhausted; observations retained".into(),
            ));
        }
        let mut specification = crate::command::CommandSpec::new(&image, &directory, budget)
            .bounded_until(work_deadline)
            .args(["--exact", test_name, "--nocapture", "--test-threads", "1"]);
        if parser || [WRITER_RESERVATION, BINDING_PROJECTION].contains(&test_name) {
            specification = specification.args(["--ignored"]);
        }
        let mut command = specification.materialize()?;
        command.env_clear();
        command.stdin(std::process::Stdio::piped());
        use std::os::windows::ffi::OsStrExt;
        let invocation = serde_json::json!({
            "format":"memcordon.windows-native-test-invocation","revision":1,
            "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
            "executable_sha256":input.executable.sha256,
            "program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
            "argv_utf16":command.get_args().map(|argument| argument.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
            "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),
            "environment_cleared":true,
        });
        retain(
            &directory.join("native-invocation.json"),
            &serde_json::to_vec(&invocation)?,
            record,
        )?;
        let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
            command,
            budget,
            4 * 1024 * 1024,
            move |mut command| {
                let mut child = command.spawn()?;
                let setup = (|| -> io::Result<()> {
                    let deadline = work_deadline.min(Instant::now() + Duration::from_secs(10));
                    loop {
                        let mut processes = memcordon_testkit::windows_processes_for_image(&image)?;
                        processes.retain(|process| process.identity.pid == child.id());
                        if processes.len() == 1 && !processes[0].has_exited()? {
                            *capture.lock().map_err(|_| {
                                io::Error::other("native test ownership poisoned")
                            })? = processes;
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(
                                "native test root identity could not be held",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    let mut stdin = child
                        .stdin
                        .take()
                        .ok_or_else(|| io::Error::other("native test stdin owner missing"))?;
                    let identities = capture
                        .lock()
                        .map_err(|_| io::Error::other("native pre-input ownership poisoned"))?;
                    if identities.len() != 1 || identities[0].has_exited()? {
                        return Err(io::Error::other(
                            "native root did not remain held before input",
                        ));
                    }
                    *pre_input_capture
                        .lock()
                        .map_err(|_| io::Error::other("native pre-input observation poisoned"))? =
                        Some(serde_json::json!({
                        "format":"memcordon.windows-native-test-pre-input","revision":1,
                        "process_id":identities[0].identity.pid,"creation_time_100ns":u64::try_from(identities[0].identity.birth).map_err(|_|io::Error::other("native creation time exceeds FILETIME"))?,
                        "image_sha256":image_sha256,"held_before_input_delivery":true,"live_before_input_delivery":true}));
                    drop(identities);
                    stdin.write_all(&request)?;
                    drop(stdin);
                    Ok(())
                })();
                if let Err(error) = setup {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
                Ok(child)
            },
            |_, _, _| Ok(()),
        );
        match &output {
            Err(memcordon_testkit::ProcessTestError::Timeout { stdout, stderr, .. })
            | Err(memcordon_testkit::ProcessTestError::OutputLimit { stdout, stderr, .. }) => {
                retain(&directory.join("partial.stdout.bin"), stdout, record)?;
                retain(&directory.join("partial.stderr.bin"), stderr, record)?;
            }
            _ => {}
        }
        if let Err(error) = &output {
            retain(
                &directory.join("capture-failure.txt"),
                error.to_string().as_bytes(),
                record,
            )?;
        }
        if let Some(observation) = pre_input
            .lock()
            .map_err(|_| CiError::Message("native pre-input observation poisoned".into()))?
            .as_ref()
        {
            retain(
                &directory.join("native-pre-input.json"),
                &serde_json::to_vec(observation)?,
                record,
            )?;
        }
        let collection = (|| -> Result<()> {
            let output = output
                .as_ref()
                .map_err(|error| CiError::Message(error.to_string()))?;
            let exit = serde_json::json!({"format":"memcordon.windows-native-test-exit","revision":1,
                "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                "executable_sha256":input.executable.sha256,"native_status":output.status.code(),"capture_complete":true,"input_delivered":true});
            retain(
                &directory.join("native-exit.json"),
                &serde_json::to_vec(&exit)?,
                record,
            )?;
            retain(&directory.join("stdout.bin"), &output.stdout, record)?;
            retain(&directory.join("stderr.bin"), &output.stderr, record)?;
            let text = std::str::from_utf8(&output.stdout)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let expected_test = format!("test {test_name} ... ok");
            let summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ";
            if !output.status.success()
                || text
                    .lines()
                    .filter(|line| *line == "running 1 test")
                    .count()
                    != 1
                || text.lines().filter(|line| *line == expected_test).count() != 1
                || text
                    .lines()
                    .filter(|line| line.starts_with(summary))
                    .count()
                    != 1
                || text
                    .lines()
                    .filter(|line| line.starts_with("running "))
                    .count()
                    != 1
                || text
                    .lines()
                    .filter(|line| line.starts_with("test result:"))
                    .count()
                    != 1
            {
                return Err(CiError::Message(
                    "exact native component test did not execute exactly one passing test".into(),
                ));
            }
            let receipt_path = artifact_root.join("native-receipt.json");
            let bytes = read(&receipt_path, 256 * 1024)?;
            let receipt: serde_json::Value = serde_json::from_slice(&bytes)?;
            if receipt.get("test_name").and_then(serde_json::Value::as_str) != Some(test_name)
                || receipt.get("run_id").and_then(serde_json::Value::as_str)
                    != Some(input.run_id.as_str())
                || receipt
                    .get("executable_sha256")
                    .and_then(serde_json::Value::as_str)
                    != Some(input.executable.sha256.as_str())
            {
                return Err(CiError::Message(
                    "actual native test receipt binding differs".into(),
                ));
            }
            record
                .artifacts
                .push(crate::windows_installed_cases::SelectedArtifact {
                    path: receipt_path,
                    sha256: crate::windows_causal_acceptance::sha256(&bytes),
                });
            for entry in fs::read_dir(&artifact_root)? {
                let path = entry?.path();
                if path
                    .file_name()
                    .is_some_and(|name| name != "native-receipt.json")
                {
                    let bytes = read(&path, 256 * 1024)?;
                    record
                        .artifacts
                        .push(crate::windows_installed_cases::SelectedArtifact {
                            path,
                            sha256: crate::windows_causal_acceptance::sha256(&bytes),
                        });
                }
            }
            record.behavior = Ok(());
            record.collection = Ok(());
            Ok(())
        })();
        let retirement = (|| -> Result<()> {
            let held = held
                .lock()
                .map_err(|_| CiError::Message("native test ownership poisoned".into()))?;
            if held.len() != 1
                || !held[0].has_exited()?
                || !memcordon_testkit::windows_processes_for_image(&input.executable.path)?
                    .is_empty()
            {
                return Err(CiError::Message(
                    "native component root/helpers failed to retire".into(),
                ));
            }
            let observation = serde_json::json!({"format":"memcordon.windows-native-test-retirement", "revision":1,
                "process_id":held[0].identity.pid, "creation_time_100ns":u64::try_from(held[0].identity.birth)
                    .map_err(|_| CiError::Message("native test birth exceeds FILETIME width".into()))?,
                "image_sha256":input.executable.sha256,"held_before_input_delivery":true,"retirement_observed":true,
                "same_image_helpers_absent":true});
            retain(
                &directory.join("native-retirement.json"),
                &serde_json::to_vec(&observation)?,
                record,
            )?;
            Ok(())
        })();
        record.retirement = retirement.as_ref().map(|_| ()).map_err(ToString::to_string);
        if let Err(error) = &collection {
            record.behavior = Err(error.to_string());
            record.collection = Err(error.to_string());
        }
        collection?;
        retirement
    }
}
