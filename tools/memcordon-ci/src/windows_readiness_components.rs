//! Native certification observations are collected from a separately measured
//! test-support installation, never from the selected production distribution.
#[cfg(windows)]
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentInput {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub source_commit: String,
    pub native_target: String,
    pub features: Vec<String>,
    pub selected_components: Vec<crate::windows_installed_cases::SelectedArtifact>,
    pub suite_input: PathBuf,
    pub artifact_prefix: PathBuf,
    pub original_work_deadline_unix_millis: u64,
    pub original_cleanup_deadline_unix_millis: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentAssessment {
    pub selector: serde_json::Value,
    pub behavior: std::result::Result<(), String>,
    pub collection: std::result::Result<(), String>,
    pub retirement: std::result::Result<(), String>,
    pub artifacts: Vec<crate::windows_installed_cases::SelectedArtifact>,
}

/// These are actual native injection points, not installed-product case rows.
pub fn fault_selectors() -> Vec<memcordon_core::WindowsSealedFault> {
    use memcordon_core::WindowsSealedFault::*;
    vec![
        PublicPipeCreate,
        CallerPidLookup,
        CallerTokenImpersonation,
        PrimaryTokenDuplicate,
        PrivatePipeConnect,
        LauncherPeerVerify,
        TokenHandleDuplicate,
        JobCreate,
        JobConfigure,
        CompletionPort,
        GuardianCreate,
        GuardianKilledBeforeAuthorization,
        GuardianKilledAfterAuthorization,
        FrontendDisconnectedAfterAuthorization,
        FrontendKilledAfterAuthorization,
        ControlWorkerKilledAfterAuthorization,
        ControlServiceKilledAfterAuthorization,
        LauncherWorkerKilledAfterAuthorization,
        LauncherServiceKilledAfterAuthorization,
        AllJobOwnersClosedAfterAuthorization,
        StreamCreate,
        RelayHandleDuplicate,
        RelayReady,
        AttributeList,
        JobList,
        HandleList,
        CreateProcessAsUser,
        TargetTokenReadback,
        JobMembershipReadback,
        BeforeResume,
        Resume,
        TerminateJob,
        ActiveProcessQuery,
        RelayRetire,
        GuardianReap,
        FinalHandleClose,
        RecordRetire,
    ]
}

pub fn envelope_mutants() -> Vec<memcordon_core::WindowsSealedMutant> {
    use memcordon_core::WindowsSealedMutant::*;
    vec![
        OmitJobList,
        ResumeBeforeGuardian,
        CreateUnderServiceToken,
        OmitHandleList,
    ]
}

#[cfg(windows)]
pub fn run_installed(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input: &ComponentInput,
    records: &mut Vec<ComponentAssessment>,
) -> Result<()> {
    run_installed_until(
        config,
        input,
        records,
        crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default(),
    )
}

#[cfg(windows)]
pub fn run_installed_until(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input: &ComponentInput,
    records: &mut Vec<ComponentAssessment>,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<()> {
    native::run(config, input, records, deadlines)
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::windows_consumer_readiness::{SuiteInput, native::read, public_component_command};
    use crate::windows_owned_guardian::GuardianBaseline;
    use std::{
        ffi::OsString,
        fs::{self, OpenOptions},
        io::{self, Write},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    struct HeldWorker {
        thread: std::os::windows::io::OwnedHandle,
        process: memcordon_testkit::WindowsImageProcess,
        identity: memcordon_core::WindowsWorkerThreadIdentityV1,
    }
    #[allow(unsafe_code)] // Query-only held thread is joined to authenticated native process birth.
    fn hold_worker(
        observed: &memcordon_core::WindowsGuardianAttemptObservation,
        image: &std::path::Path,
    ) -> io::Result<HeldWorker> {
        let expected = observed
            .worker_process_identity
            .as_ref()
            .ok_or_else(|| io::Error::other("component worker process absent"))?;
        let identity = observed
            .worker_thread_identity
            .as_ref()
            .ok_or_else(|| io::Error::other("component worker thread absent"))?;
        hold_worker_identity(expected, identity, image)
    }
    #[allow(unsafe_code)] // Retains exact observed process/thread native births before the owned actor barrier release.
    fn hold_worker_identity(
        expected: &memcordon_core::WindowsProcessIdentityV1,
        identity: &memcordon_core::WindowsWorkerThreadIdentityV1,
        image: &std::path::Path,
    ) -> io::Result<HeldWorker> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::System::Threading::{
            GetProcessIdOfThread, GetThreadTimes, OpenThread, THREAD_QUERY_LIMITED_INFORMATION,
            WaitForSingleObject,
        };
        let identity = identity.clone();
        let process = memcordon_testkit::windows_processes_for_image(image)?
            .into_iter()
            .find(|held| {
                held.identity.pid == expected.process_id
                    && held.identity.birth == u128::from(expected.creation_time_100ns)
            })
            .ok_or_else(|| {
                io::Error::other("component worker process differs from held selected image")
            })?;
        if process.has_exited()? {
            return Err(io::Error::other("component worker process already retired"));
        }
        // SAFETY: the explicit query-only handle is owned until observed native retirement.
        let raw = unsafe {
            OpenThread(
                THREAD_QUERY_LIMITED_INFORMATION | 0x00100000,
                0,
                identity.thread_id,
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let thread = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        let mut birth = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exit = birth;
        let mut kernel = birth;
        let mut user = birth;
        if unsafe { GetThreadTimes(raw, &mut birth, &mut exit, &mut kernel, &mut user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = u64::from(birth.dwLowDateTime) | (u64::from(birth.dwHighDateTime) << 32);
        if actual != identity.creation_time_100ns
            || unsafe { GetProcessIdOfThread(raw) } != expected.process_id
            || unsafe { WaitForSingleObject(raw, 0) }
                != windows_sys::Win32::Foundation::WAIT_TIMEOUT
        {
            return Err(io::Error::other(
                "component worker thread birth/owner/liveness differs",
            ));
        }
        Ok(HeldWorker {
            thread,
            process,
            identity,
        })
    }
    #[allow(unsafe_code)] // Same retained query/synchronization handle, no reopened numeric thread id.
    fn worker_exit(worker: &HeldWorker) -> io::Result<u32> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::{GetExitCodeThread, WaitForSingleObject};
        let raw = worker.thread.as_raw_handle();
        if unsafe { WaitForSingleObject(raw, 0) } != windows_sys::Win32::Foundation::WAIT_OBJECT_0 {
            return Err(io::Error::other(
                "component held worker thread has not retired",
            ));
        }
        let mut status = 0;
        if unsafe { GetExitCodeThread(raw, &mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(status)
    }

    fn retain(
        path: &std::path::Path,
        bytes: &[u8],
        record: &mut ComponentAssessment,
    ) -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if read(path, bytes.len())? != bytes {
            return Err(CiError::Message(
                "component named artifact readback differs".into(),
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

    pub fn run(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &ComponentInput,
        records: &mut Vec<ComponentAssessment>,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<()> {
        if input.format != "memcordon.windows-readiness-component"
            || input.revision != 1
            || input.artifact_prefix.as_os_str().is_empty()
            || input
                .artifact_prefix
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || input.run_id.is_empty()
            || input.run_id.len() > 128
            || input.recipe_id.is_empty()
            || input.recipe_id.len() > 128
            || input.source_commit != config.provider.source_commit.as_str()
            || !matches!(
                input.native_target.as_str(),
                "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc"
            )
            || input.features != ["test-support", "windows-sealed-runtime"]
            || serde_json::to_vec(&input.selected_components)?
                != serde_json::to_vec(&config.components)?
        {
            return Err(CiError::Message(
                "component runner requires exact separately measured support package descriptor"
                    .into(),
            ));
        }
        for artifact in &input.selected_components {
            if crate::windows_causal_acceptance::sha256(&read(&artifact.path, 512 * 1024 * 1024)?)
                != artifact.sha256
            {
                return Err(CiError::Message(
                    "component package bytes differ from explicit selected measurement".into(),
                ));
            }
        }
        let suite: SuiteInput =
            serde_json::from_slice(&read(&input.suite_input, 4 * 1024 * 1024)?)?;
        let base = suite
            .cases
            .iter()
            .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
            .ok_or_else(|| {
                CiError::Message("component runner finite joint fixture absent".into())
            })?;
        let policy_budget = deadlines.work_budget(Duration::from_secs(90))?;
        let mut apply = crate::command::CommandSpec::new(
            &config.installed_agent.path,
            &config.output_directory,
            policy_budget,
        )
        .args([
            OsString::from("package"),
            "policy".into(),
            "apply".into(),
            "--file".into(),
            suite.local_policy.clone().into_os_string(),
        ])
        .materialize()?;
        apply.env_clear();
        let activated = memcordon_testkit::run_with_deadline_output_limit(
            &mut apply,
            policy_budget,
            256 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let activation: serde_json::Value = serde_json::from_slice(&activated.stdout)?;
        let configured = memcordon_core::workload_registry::RuntimePolicyRegistry::parse(&read(
            &suite.local_policy,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        let registry: memcordon_core::workload_registry::RuntimePolicyRegistry =
            serde_json::from_value(activation.get("registry").cloned().ok_or_else(|| {
                CiError::Message("component activation omitted registry".into())
            })?)?;
        if !activated.status.success()
            || configured != registry
            || activation.get("format").and_then(serde_json::Value::as_str)
                != Some("memcordon.local-activation")
            || activation
                .get("revision")
                .and_then(serde_json::Value::as_u64)
                != Some(1)
            || activation
                .get("registry_digest")
                .and_then(serde_json::Value::as_str)
                != Some(
                    String::from(registry.canonical_digest().map_err(CiError::Message)?).as_str(),
                )
        {
            return Err(CiError::Message(
                "native component policy activation differs from exact configured registry".into(),
            ));
        }
        let epoch = serde_json::from_value(
            activation
                .get("epoch")
                .cloned()
                .ok_or_else(|| CiError::Message("component activation epoch absent".into()))?,
        )?;
        let mut contract = memcordon_core::workload_contract::WorkloadContractV1::parse(&read(
            &base.workload_contract,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        contract.expected_epoch = epoch;
        let contract_directory = config.output_directory.join("W-JOINT").join("ordinary");
        fs::create_dir_all(&contract_directory)?;
        let bytes = serde_json::to_vec(&contract)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(contract_directory.join("requested-contract.json"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if read(
            &contract_directory.join("requested-contract.json"),
            256 * 1024,
        )? != bytes
        {
            return Err(CiError::Message(
                "component activated request readback differs".into(),
            ));
        }
        let mut first_error = None;
        for (ordinal, fault) in fault_selectors().into_iter().enumerate() {
            let selector = serde_json::json!({"kind":"fault", "fault":fault});
            records.push(ComponentAssessment {
                selector: selector.clone(),
                behavior: Err("not observed".into()),
                collection: Err("not collected".into()),
                retirement: Err("not observed".into()),
                artifacts: Vec::new(),
            });
            let record = records.last_mut().expect("owned component row");
            let directory = config
                .output_directory
                .join("native-components")
                .join(format!("fault-{ordinal}"));
            fs::create_dir_all(&directory)?;
            let result = exercise(
                config,
                input,
                base,
                Some(fault),
                None,
                &selector,
                &directory,
                record,
                deadlines,
            );
            if let Err(error) = result {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            if record.retirement.is_err() {
                break;
            }
        }
        if records
            .last()
            .is_some_and(|record| record.retirement.is_err())
        {
            return Err(first_error.unwrap_or_else(|| {
                CiError::Message("component fault retirement unresolved".into())
            }));
        }
        for (ordinal, mutant) in envelope_mutants().into_iter().enumerate() {
            let selector = serde_json::json!({"kind":"mutant", "mutant":mutant});
            records.push(ComponentAssessment {
                selector: selector.clone(),
                behavior: Err("not observed".into()),
                collection: Err("not collected".into()),
                retirement: Err("not observed".into()),
                artifacts: Vec::new(),
            });
            let record = records.last_mut().expect("owned native mutant row");
            let directory = config
                .output_directory
                .join("native-components")
                .join(format!("mutant-{ordinal}"));
            fs::create_dir_all(&directory)?;
            if let Err(error) = exercise(
                config,
                input,
                base,
                None,
                Some(mutant),
                &selector,
                &directory,
                record,
                deadlines,
            ) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            if record.retirement.is_err() {
                break;
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if records.len() != fault_selectors().len() + envelope_mutants().len()
            || records.iter().any(|row| {
                row.behavior.is_err() || row.collection.is_err() || row.retirement.is_err()
            })
        {
            return Err(CiError::Message(
                "native component fault observations incomplete".into(),
            ));
        }
        Ok(())
    }

    fn exercise(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &ComponentInput,
        base: &crate::windows_consumer_readiness::CaseInput,
        fault: Option<memcordon_core::WindowsSealedFault>,
        mutant: Option<memcordon_core::WindowsSealedMutant>,
        selector: &serde_json::Value,
        directory: &std::path::Path,
        record: &mut ComponentAssessment,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<()> {
        let baseline = GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )?;
        let mut case = base.clone();
        case.descriptor.start_gate = None;
        case.descriptor.challenge =
            crate::windows_consumer_readiness::native::random_challenge()?.to_vec();
        retain(
            &directory.join("challenge.bin"),
            &case.descriptor.challenge,
            record,
        )?;
        let held_phase =
            fault.is_some_and(|fault| {
                matches!(fault,
            memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::FrontendDisconnectedAfterAuthorization
            | memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::ControlWorkerKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::LauncherServiceKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
            });
        if held_phase {
            let name = format!(
                "memcordon-component-{}",
                crate::windows_causal_acceptance::sha256(&serde_json::to_vec(selector)?)
            );
            case.descriptor.start_gate = Some(name);
        }
        case.descriptor.output_root = base
            .descriptor
            .output_root
            .parent()
            .ok_or_else(|| CiError::Message("component candidate parent absent".into()))?
            .join(directory.file_name().expect("component ordinal directory"));
        case.descriptor.transcript = case.descriptor.output_root.join("fixture-events.bin");
        case.descriptor_path = directory.join("input.json");
        fs::create_dir_all(&case.descriptor.output_root)?;
        case.workload_contract = config
            .output_directory
            .join("W-JOINT")
            .join("ordinary")
            .join("requested-contract.json");
        retain(
            &case.descriptor_path,
            &serde_json::to_vec(&case.descriptor)?,
            record,
        )?;
        let selection_path = directory.join("selection.json");
        retain(&selection_path, &serde_json::to_vec(selector)?, record)?;
        let observation_path = directory.join("native-observation.json");
        let report = directory.join("result.json");
        let execution = public_component_command(
            &config.cli.path,
            &config.fixture.path,
            directory,
            &report,
            &case,
        )?;
        let execution = execution.materialize()?;
        let mut arguments: Vec<OsString> = vec![
            "__windows-certification".into(),
            selection_path.into_os_string(),
            observation_path.clone().into_os_string(),
        ];
        let frontend_gate_name = format!(
            "Local\\MemcordonComponentFrontend{}",
            crate::windows_causal_acceptance::sha256(&case.descriptor.challenge)
        );
        let frontend_gate =
            crate::windows_consumer_readiness::native::event_create(&frontend_gate_name)?;
        arguments.extend([
            OsString::from("--controller-start-gate"),
            OsString::from(frontend_gate_name),
        ]);
        arguments.extend(execution.get_args().map(std::ffi::OsStr::to_os_string));
        let actor_budget = deadlines.work_budget(Duration::from_secs(90))?;
        let mut command =
            crate::command::CommandSpec::new(&config.cli.path, directory, actor_budget)
                .args(arguments)
                .materialize()?;
        command.env_clear();
        use std::os::windows::ffi::OsStrExt;
        let invocation_path = directory.join("actor-invocation.json");
        retain(
            &invocation_path,
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-native-component-invocation","revision":1,
                "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                "executable_sha256":config.cli.sha256,
                "program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
                "argv_utf16":command.get_args().map(|arg| arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),
                "environment_cleared":true
            }))?,
            record,
        )?;
        let gate = case
            .descriptor
            .start_gate
            .as_ref()
            .map(|name| crate::windows_consumer_readiness::native::event_create(name))
            .transpose()?;
        let family = Arc::new(Mutex::new(Vec::new()));
        let held_family = Arc::clone(&family);
        let guardian = Arc::new(Mutex::new(None));
        let held_guardian = Arc::clone(&guardian);
        let live = Arc::new(Mutex::new(None));
        let held_live = Arc::clone(&live);
        let worker = Arc::new(Mutex::new(None));
        let held_worker = Arc::clone(&worker);
        let control_worker = Arc::new(Mutex::new(None));
        let held_control_worker = Arc::clone(&control_worker);
        let frontend = Arc::new(Mutex::new(None));
        let held_frontend = Arc::clone(&frontend);
        let fixture = config.fixture.path.clone();
        let cli = config.cli.path.clone();
        let cwd = directory.to_owned();
        let transcript = case.descriptor.transcript.clone();
        let provider = config.provider.clone();
        let worker_image = config.installed_agent.path.clone();
        let worker_loss = matches!(
            fault,
            Some(
                memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization
                    | memcordon_core::WindowsSealedFault::LauncherServiceKilledAfterAuthorization
                    | memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization
            )
        );
        let launcher_process_loss = matches!(
            fault,
            Some(
                memcordon_core::WindowsSealedFault::LauncherServiceKilledAfterAuthorization
                    | memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization
            )
        );
        let control_loss = matches!(
            fault,
            Some(
                memcordon_core::WindowsSealedFault::ControlWorkerKilledAfterAuthorization
                    | memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization
            )
        );
        let control_process_loss = fault
            == Some(memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization);
        let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
            command,
            actor_budget,
            4 * 1024 * 1024,
            |mut command| command.spawn(),
            move |frontend_pid, _, _| {
                let held = memcordon_testkit::windows_processes_for_image(&cli)?
                    .into_iter()
                    .find(|held| held.identity.pid == frontend_pid)
                    .ok_or_else(|| {
                        io::Error::other("component frontend image/identity could not be held")
                    })?;
                if held.has_exited()? {
                    return Err(io::Error::other(
                        "component frontend already exited before fault",
                    ));
                }
                let bytes = serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-component-frontend-held","revision":1,
                    "process_id":held.identity.pid,"creation_time_100ns":held.identity.birth,
                    "held_before_execution":true,"native_live_before_release":true
                }))
                .map_err(io::Error::other)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(cwd.join("held-frontend-before.json"))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                *held_frontend
                    .lock()
                    .map_err(|_| io::Error::other("frontend ownership poisoned"))? = Some(held);
                crate::windows_consumer_readiness::native::signal(&frontend_gate)?;
                let Some(gate) = gate else {
                    return Ok(());
                };
                let deadline = deadlines.work.min(Instant::now() + Duration::from_secs(30));
                let roots = loop {
                    let roots = memcordon_testkit::windows_processes_for_image(&fixture)?;
                    if transcript.is_file() && roots.len() == 1 && !roots[0].has_exited()? {
                        break roots;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(
                            "component target did not reach owned native barrier",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                let guardian = baseline.hold_new_guardian().map_err(io::Error::other)?;
                let query_budget = deadlines
                    .work_budget(Duration::from_secs(30))
                    .map_err(io::Error::other)?;
                let mut query = crate::command::CommandSpec::new(&cli, &cwd, query_budget)
                    .args([
                        OsString::from("__observe-windows-guardian"),
                        guardian.identity.process_id.to_string().into(),
                        guardian.identity.creation_time_100ns.to_string().into(),
                    ])
                    .materialize()
                    .map_err(io::Error::other)?;
                query.env_clear();
                let observation = memcordon_testkit::run_with_deadline_output_limit(
                    &mut query,
                    query_budget,
                    memcordon_core::WindowsGuardianAttemptObservation::MAX_FRAME_BYTES,
                )
                .map_err(io::Error::other)?;
                let observation: memcordon_core::WindowsGuardianAttemptObservation =
                    if observation.status.success() {
                        serde_json::from_slice(&observation.stdout).map_err(io::Error::other)?
                    } else {
                        return Err(io::Error::other("component live association query failed"));
                    };
                let target = observation
                    .live_target_identity
                    .as_ref()
                    .ok_or_else(|| io::Error::other("component released target absent"))?
                    .clone();
                if !observation.is_consistent()
                    || observation.association.provider != provider
                    || observation.guardian_identity.process_id != guardian.identity.process_id
                    || observation.guardian_identity.creation_time_100ns
                        != guardian.identity.creation_time_100ns
                    || roots[0].identity.pid != target.process_id
                    || roots[0].identity.birth != u128::from(target.creation_time_100ns)
                {
                    return Err(io::Error::other(
                        "component native held root/guardian association differs",
                    ));
                }
                *held_family
                    .lock()
                    .map_err(|_| io::Error::other("component ownership poisoned"))? = roots;
                *held_guardian
                    .lock()
                    .map_err(|_| io::Error::other("component guardian ownership poisoned"))? =
                    Some(guardian);
                *held_live
                    .lock()
                    .map_err(|_| io::Error::other("component association poisoned"))? =
                    Some(observation);
                if worker_loss {
                    let observed = held_live
                        .lock()
                        .map_err(|_| io::Error::other("component association poisoned"))?;
                    *held_worker
                        .lock()
                        .map_err(|_| io::Error::other("component worker ownership poisoned"))? =
                        Some(hold_worker(
                            observed.as_ref().expect("captured association"),
                            &worker_image,
                        )?);
                }
                if control_loss {
                    let path = cwd.join("control-worker-native.json");
                    while !path.try_exists()? {
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(
                                "actual control worker site did not publish before barrier deadline",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let bytes = read(&path, 64 * 1024).map_err(io::Error::other)?;
                    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                        .map_err(io::Error::other)?;
                    let observed: serde_json::Value =
                        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                    if observed["format"] != "memcordon.windows-component-control-worker-site"
                        || observed["revision"] != 1
                        || observed["fault"]
                            != serde_json::to_value(fault).map_err(io::Error::other)?
                        || observed["target_pid"] != target.process_id
                        || observed["target_authorization_observed"] != true
                    {
                        return Err(io::Error::other(
                            "control worker site differs from actual selected target/fault",
                        ));
                    }
                    let process: memcordon_core::WindowsProcessIdentityV1 =
                        serde_json::from_value(observed["process"].clone())
                            .map_err(io::Error::other)?;
                    let thread: memcordon_core::WindowsWorkerThreadIdentityV1 =
                        serde_json::from_value(observed["thread"].clone())
                            .map_err(io::Error::other)?;
                    let scm = crate::windows_readiness_faults::observe_running_control_service()?;
                    if scm["process_id"] != process.process_id {
                        return Err(io::Error::other(
                            "held control worker does not belong to actual running SCM service",
                        ));
                    }
                    let held = hold_worker_identity(&process, &thread, &worker_image)?;
                    if crate::windows_readiness_faults::observe_running_control_service()? != scm {
                        return Err(io::Error::other(
                            "SCM control service changed during native worker acquisition",
                        ));
                    }
                    let bytes=serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-component-control-worker-held","revision":1,
                        "process":process,"thread":thread,"target_pid":target.process_id,"held_before_fault":true,"control_service":scm})).map_err(io::Error::other)?;
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(cwd.join("held-control-worker-before.json"))?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    *held_control_worker
                        .lock()
                        .map_err(|_| io::Error::other("control worker ownership poisoned"))? =
                        Some(held);
                }
                crate::windows_consumer_readiness::native::signal(&gate)
            },
        );
        if let Some(live) = live
            .lock()
            .map_err(|_| CiError::Message("component observation poisoned".into()))?
            .as_ref()
        {
            retain(
                &directory.join("held-before-fault.json"),
                &serde_json::to_vec(live)?,
                record,
            )?;
        }
        if let Err(error) = &output {
            match error {
                memcordon_testkit::ProcessTestError::Timeout { stdout, stderr, .. }
                | memcordon_testkit::ProcessTestError::OutputLimit { stdout, stderr, .. } => {
                    retain(&directory.join("partial-stdout.bin"), stdout, record)?;
                    retain(&directory.join("partial-stderr.bin"), stderr, record)?;
                }
                _ => {}
            }
            retain(
                &directory.join("capture-failure.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-native-component-capture-failure","revision":1,
                    "run_id":input.run_id,"recipe_id":input.recipe_id,"failure":error.to_string(),
                    "capture_complete":false
                }))?,
                record,
            )?;
        }
        let collection = (|| -> Result<()> {
            let output = output
                .as_ref()
                .map_err(|error| CiError::Message(error.to_string()))?;
            let before = read(&directory.join("held-frontend-before.json"), 4096)?;
            record
                .artifacts
                .push(crate::windows_installed_cases::SelectedArtifact {
                    path: directory.join("held-frontend-before.json"),
                    sha256: crate::windows_causal_acceptance::sha256(&before),
                });
            {
                let held = frontend.lock().map_err(|_| {
                    CiError::Message("component frontend ownership poisoned".into())
                })?;
                let held = held.as_ref().ok_or_else(|| {
                    CiError::Message("component frontend was not held before execution".into())
                })?;
                if !held.has_exited()?
                    || held.native_exit_status()?
                        != output.status.code().map(|status| status as u32)
                {
                    return Err(CiError::Message(
                        "actual component frontend did not retire with captured native status"
                            .into(),
                    ));
                }
                retain(
                    &directory.join("native-actor-retirement.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-actor-retirement","revision":1,
                        "process_id":held.identity.pid,"creation_time_100ns":held.identity.birth,
                        "image_sha256":config.cli.sha256,"held_before_execution":true,
                        "retirement_observed":true,"native_status":held.native_exit_status()?
                    }))?,
                    record,
                )?;
            }
            retain(
                &directory.join("actor-exit.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-native-component-exit","revision":1,
                    "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                    "executable_sha256":config.cli.sha256,"native_status":output.status.code(),
                    "capture_complete":true
                }))?,
                record,
            )?;
            retain(&directory.join("stdout.bin"), &output.stdout, record)?;
            retain(&directory.join("stderr.bin"), &output.stderr, record)?;
            let raw = read(&observation_path, 32 * 1024 * 1024)?;
            record
                .artifacts
                .push(crate::windows_installed_cases::SelectedArtifact {
                    path: observation_path.clone(),
                    sha256: crate::windows_causal_acceptance::sha256(&raw),
                });
            let observed: serde_json::Value = serde_json::from_slice(&raw)?;
            if observed.get("selection") != Some(selector)
                || !observed
                    .get("capture_failure")
                    .is_some_and(serde_json::Value::is_null)
            {
                return Err(CiError::Message(
                    "native component selection/custody differs".into(),
                ));
            }
            let actual_request: memcordon_core::WindowsLaunchRequestV1 =
                serde_json::from_value(observed["launch"].clone())?;
            retain(
                &directory.join("provider-request.bin"),
                &serde_json::to_vec(&actual_request)?,
                record,
            )?;
            let attempt = observed
                .get("attempt_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CiError::Message("actual component attempt absent".into()))?;
            let request = observed
                .get("request_sha256")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CiError::Message("actual component request absent".into()))?;
            let nonce = observed
                .pointer("/launch/nonce")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CiError::Message("component launch nonce absent".into()))?;
            if fault.is_some_and(|fault| {
                matches!(
                    fault,
                    memcordon_core::WindowsSealedFault::FrontendDisconnectedAfterAuthorization
                        | memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization
                )
            }) {
                let frontend = frontend
                    .lock()
                    .map_err(|_| CiError::Message("frontend ownership poisoned".into()))?;
                let frontend = frontend.as_ref().ok_or_else(|| {
                    CiError::Message("component frontend not held before release".into())
                })?;
                let action = observed.get("frontend_action").ok_or_else(|| {
                    CiError::Message("selected frontend fault has no actual action".into())
                })?;
                let kill = fault
                    == Some(memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization);
                if action.get("format").and_then(serde_json::Value::as_str)
                    != Some("memcordon.windows-component-frontend-action")
                    || action.get("revision").and_then(serde_json::Value::as_u64) != Some(1)
                    || action.get("kind").and_then(serde_json::Value::as_str)
                        != Some(if kill {
                            "exit-process"
                        } else {
                            "disconnect-public-channel"
                        })
                    || action
                        .pointer("/process/process_id")
                        .and_then(serde_json::Value::as_u64)
                        != Some(u64::from(frontend.identity.pid))
                    || action
                        .pointer("/process/creation_time_100ns")
                        .and_then(serde_json::Value::as_u64)
                        .map(u128::from)
                        != Some(frontend.identity.birth)
                    || action.get("target_authorization_observed")
                        != Some(&serde_json::Value::Bool(true))
                    || action.get("controller_release_observed")
                        != Some(&serde_json::Value::Bool(true))
                    || !frontend.has_exited()?
                    || output.status.success()
                    || frontend.native_exit_status()?
                        != output.status.code().map(|status| status as u32)
                    || (kill && frontend.native_exit_status()? != Some(0xC000_013A))
                {
                    return Err(CiError::Message(
                        "actual frontend action/status differs from held selected process".into(),
                    ));
                }
                retain(
                    &directory.join("held-frontend-exit.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-frontend-exit","revision":1,
                        "process_id":frontend.identity.pid,"creation_time_100ns":frontend.identity.birth,
                        "held_before_fault":true,"retirement_observed":true,"native_status":frontend.native_exit_status()?
                    }))?,
                    record,
                )?;
            }
            if held_phase {
                let held = live
                    .lock()
                    .map_err(|_| CiError::Message("component association poisoned".into()))?;
                let held = held.as_ref().ok_or_else(|| {
                    CiError::Message("component native held association absent".into())
                })?;
                if String::from(held.association.attempt_id.clone()) != attempt
                    || String::from(held.association.request_sha256.clone()) != request
                    || held.live_nonce.as_deref() != Some(nonce)
                {
                    return Err(CiError::Message(
                        "component native held phase belongs to another actual request".into(),
                    ));
                }
            }
            let frames = observed
                .get("authenticated_provider_frames")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| CiError::Message("component native frames absent".into()))?;
            let mut rejected = false;
            for raw in frames {
                let bytes: Vec<u8> = serde_json::from_value(raw.clone())?;
                let response: memcordon_core::WindowsProviderResponseV3 =
                    serde_json::from_slice(&bytes)?;
                if let memcordon_core::WindowsProviderResponseV3::CertificationMutantObserved(
                    ref receipt,
                ) = response
                {
                    if let Some(expected) = mutant {
                        if receipt.mutant == expected
                            && receipt.binding_matches(attempt, nonce, request)
                            && matches!(&receipt.hook_observation, memcordon_core::WindowsMutantHookObservationV1::Native { observation }
                                if observation.rejects(expected))
                        {
                            rejected = true;
                        }
                    }
                }
                if let memcordon_core::WindowsProviderResponseV3::Reject {
                    attempt_id,
                    nonce: actual_nonce,
                    request_sha256,
                    rejection,
                    ..
                } = response
                {
                    if attempt_id == attempt && actual_nonce == nonce && request_sha256 == request
                        && rejection.code == "MCSEALED-WINDOWS-CERTIFICATION-FAULT"
                        && fault.is_some_and(|fault| {
                            rejection.detail == format!("MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected {fault:?}")
                                || serde_json::to_value(fault).is_ok_and(|rendered|
                                    rejection.detail == format!("injected certification fault: {rendered}"))
                        })
                        && rejection.provider_failure.as_ref().is_some_and(|failure| {
                            failure.is_consistent()&&failure.provider_binding==config.provider
                                && String::from(failure.attempt_id.clone())==attempt
                                && String::from(failure.request_sha256.clone())==request
                                && matches!(&failure.original,memcordon_core::OriginalFailureV1::Observed {event}
                                    if fault.is_some_and(|selected|event.safe_detail==memcordon_core::SafeDiagnosticDetailV1::InjectedWindowsFault {fault:selected}))
                        }) {
                        rejected = true;
                    }
                }
            }
            if !rejected && fault.is_some() {
                let recovery_budget = deadlines.cleanup_budget(Duration::from_secs(90))?;
                let mut recovery =
                    crate::command::CommandSpec::new(&config.cli.path, directory, recovery_budget)
                        .args(["windows-recover", "attempt", attempt, nonce, request])
                        .materialize()?;
                recovery.env_clear();
                retain(
                    &directory.join("terminal-recovery-invocation.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-recovery-command","revision":1,
                        "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                        "executable_sha256":config.cli.sha256,
                        "program_utf16":recovery.get_program().encode_wide().collect::<Vec<_>>(),
                        "argv_utf16":recovery.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                        "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"environment_cleared":true,
                    }))?,
                    record,
                )?;
                let output = memcordon_testkit::run_with_deadline_output_limit(
                    &mut recovery,
                    recovery_budget,
                    2 * 1024 * 1024,
                )
                .map_err(|error| CiError::Message(error.to_string()))?;
                retain(
                    &directory.join("terminal-recovery.json"),
                    &output.stdout,
                    record,
                )?;
                retain(
                    &directory.join("terminal-recovery.stderr.bin"),
                    &output.stderr,
                    record,
                )?;
                retain(
                    &directory.join("terminal-recovery-exit.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-recovery-exit","revision":1,
                        "invocation_sha256":crate::windows_causal_acceptance::sha256(&read(&directory.join("terminal-recovery-invocation.json"),256*1024)?),
                        "stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),
                        "stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr),"native_status":output.status.code(),
                    }))?,
                    record,
                )?;
                if output.status.success() || (fault==Some(memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
                    &&output.status.code()==Some(1)) {
                    let recovered: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                    let response: memcordon_core::WindowsProviderResponseV3 = serde_json::from_value(recovered.get("provider_response").cloned()
                        .ok_or_else(|| CiError::Message("component recovery omitted actual provider response".into()))?)?;
                    if fault==Some(memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
                        &&recovered.get("schema_version")==Some(&serde_json::json!(1))
                        &&recovered.get("frontend_delivery").is_some_and(serde_json::Value::is_null)
                        &&matches!(&response,memcordon_core::WindowsProviderResponseV3::RecoveryAttemptUnavailable {
                            schema_version,attempt_id,challenge,detail } if *schema_version==memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
                                &&attempt_id==attempt&&!challenge.is_empty()
                                &&detail=="exact recovery authority remains retained pending checked closure") {
                        // Exact authenticated uncertainty is the expected
                        // first observation. The later native convergence and
                        // retained process waits must independently settle
                        // physical ownership; this is never a terminal ACK.
                        rejected=true;
                    }
                    let receipt = match &response {
                        memcordon_core::WindowsProviderResponseV3::Terminal(receipt) => Some(receipt),
                        memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } => rejection.terminal_receipt(),
                        _ => None,
                    };
                    let selected_transport_original = fault.is_some_and(|selected| {
                        use memcordon_core::WindowsSealedFault::*;
                        matches!(selected, FrontendDisconnectedAfterAuthorization | FrontendKilledAfterAuthorization
                            | ControlWorkerKilledAfterAuthorization | ControlServiceKilledAfterAuthorization)
                            && matches!(&response, memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. }
                                if rejection.provider_failure.as_ref().is_some_and(|failure|
                                    matches!(&failure.original, memcordon_core::OriginalFailureV1::Observed { event }
                                        if event.sequence > 0
                                            && event.category == memcordon_core::FailureCategoryV1::Transport
                                            && event.operation == memcordon_core::FailureOperationV1::ReadControlFrame
                                            && event.code == memcordon_core::FailureCodeV1::ControlTransport
                                            && event.observed_phase == memcordon_core::AttemptObservationPhaseV1::Monitoring
                                            && event.safe_detail == (memcordon_core::SafeDiagnosticDetailV1::InjectedWindowsFault { fault:selected })
                                            && matches!(event.native_code, None | Some(memcordon_core::NativeFailureCodeV1::Win32(1..=u32::MAX))))))
                    });
                    if let Some(receipt) = receipt {
                        receipt.validate_for_attempt().map_err(|error| CiError::Message(error.into()))?;
                        if receipt.attempt_id == attempt && receipt.nonce == nonce && receipt.request_sha256 == request
                            && receipt.retirement_proof.provider_generation == config.provider.generation.as_str()
                            && ((fault == Some(memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization)
                            && matches!(&receipt.payload, memcordon_core::WindowsTerminalPayloadV2::RecoveredClosure {
                                primary_failure: memcordon_core::OriginalFailureV1::Observed { event }, .. }
                                if event.sequence != 0 && event.operation == memcordon_core::FailureOperationV1::CheckGuardian
                                    && event.code == memcordon_core::FailureCodeV1::GuardianLoss
                                    && event.observed_phase == memcordon_core::AttemptObservationPhaseV1::Monitoring
                                    && event.native_code.is_none()))
                                || (selected_transport_original && receipt.execution().is_some_and(|(_, outcome, _)|
                                    matches!(outcome, memcordon_core::RunOutcome::MonitorFailed { .. })))
                                || (worker_loss && fault!=Some(memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization) && matches!(&receipt.payload,
                                    memcordon_core::WindowsTerminalPayloadV2::RecoveredClosure {
                                        primary_failure: memcordon_core::OriginalFailureV1::Unavailable {
                                            reason: memcordon_core::OriginalUnavailableReasonV1::WorkerLostBeforeObservation }, .. }))
                                || fault.is_some_and(|selected| {
                                    use memcordon_core::WindowsSealedFault::*;
                                    matches!(selected, Resume | TerminateJob | ActiveProcessQuery | RelayRetire | GuardianReap | FinalHandleClose)
                                        && matches!(&receipt.payload, memcordon_core::WindowsTerminalPayloadV2::RecoveredClosure {
                                            primary_failure: memcordon_core::OriginalFailureV1::Observed { event }, .. }
                                            if event.sequence > 0
                                                && event.operation == memcordon_core::FailureOperationV1::UnclassifiedProviderOperation
                                                && event.code == memcordon_core::FailureCodeV1::UnexpectedProviderFailure
                                                && event.category == memcordon_core::FailureCategoryV1::Launch
                                                && event.native_code.is_none()
                                                && event.safe_detail == (memcordon_core::SafeDiagnosticDetailV1::InjectedWindowsFault { fault: selected })
                                                && event.observed_phase == if selected == Resume {
                                                    memcordon_core::AttemptObservationPhaseV1::AuthorizedBeforeResume
                                                } else { memcordon_core::AttemptObservationPhaseV1::Cleaning })
                                })) {
                            rejected = true;
                        }
                    }
                }
            }
            if !rejected {
                return Err(CiError::Message("native injected fault lacks bound failure authority; natural/policy completion cannot substitute".into()));
            }
            record.collection = Ok(());
            record.behavior = Ok(());
            Ok(())
        })();
        let retirement = (|| -> Result<()> {
            let recovery_budget = deadlines.cleanup_budget(Duration::from_secs(90))?;
            let recovery_millis = recovery_budget.as_millis().min(90000).to_string();
            let mut converge =
                crate::command::CommandSpec::new(&config.cli.path, directory, recovery_budget)
                    .args(["windows-recover", "converge", recovery_millis.as_str()])
                    .materialize()?;
            converge.env_clear();
            retain(
                &directory.join("recovery-invocation.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-component-settlement-command","revision":1,
                    "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                    "source_commit":input.source_commit,"executable_sha256":config.cli.sha256,
                    "program_utf16":converge.get_program().encode_wide().collect::<Vec<_>>(),
                    "argv_utf16":converge.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                    "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"environment_cleared":true,
                    "work_deadline_unix_millis":input.original_work_deadline_unix_millis,
                    "cleanup_deadline_unix_millis":input.original_cleanup_deadline_unix_millis
                }))?,
                record,
            )?;
            let output = memcordon_testkit::run_with_deadline_output_limit(
                &mut converge,
                recovery_budget,
                256 * 1024,
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            retain(&directory.join("recovery.json"), &output.stdout, record)?;
            retain(
                &directory.join("recovery.stderr.bin"),
                &output.stderr,
                record,
            )?;
            retain(
                &directory.join("recovery-exit.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-component-settlement-exit","revision":1,
                    "invocation_sha256":crate::windows_causal_acceptance::sha256(&read(&directory.join("recovery-invocation.json"),256*1024)?),
                    "stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),
                    "stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr),"native_status":output.status.code()
                }))?,
                record,
            )?;
            let inventory: memcordon_core::WindowsRecoveryInventoryV1 =
                serde_json::from_slice(&output.stdout)?;
            if !output.status.success()
                || !inventory.is_consistent()
                || inventory.authority_unsettled()
                || inventory.provider_generation != config.provider.generation.as_str()
                || !memcordon_testkit::windows_processes_for_image(&config.fixture.path)?.is_empty()
            {
                return Err(CiError::Message(
                    "component native recovery retained authority or live fixture family".into(),
                ));
            }
            GuardianBaseline::quiescent(
                &config.installed_agent.path,
                &config.installed_manifest.path,
                &config.installed_agent.sha256,
                &config.installed_manifest.sha256,
            )?;
            if held_phase {
                let family = family
                    .lock()
                    .map_err(|_| CiError::Message("component family ownership poisoned".into()))?;
                let guardian = guardian.lock().map_err(|_| {
                    CiError::Message("component guardian ownership poisoned".into())
                })?;
                if family.len() != 1
                    || !family[0].has_exited()?
                    || !guardian
                        .as_ref()
                        .is_some_and(|guardian| guardian.has_retired().unwrap_or(false))
                {
                    return Err(CiError::Message(
                        "component held native family did not retire after fault".into(),
                    ));
                }
                let guardian_status = guardian
                    .as_ref()
                    .expect("checked held guardian")
                    .native_exit_status()?;
                if matches!(fault,Some(memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization
                    |memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization))&&guardian_status!=Some(0xC000_013A) {
                    return Err(CiError::Message("actual held guardian exit differs from selected native termination".into()));
                }
                retain(
                    &directory.join("held-after-fault.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-held-retirement","revision":1,
                        "target_process_id":family[0].identity.pid,"target_creation_time_100ns":family[0].identity.birth,
                        "guardian":guardian.as_ref().expect("checked held guardian").identity,
                        "held_before_fault":true,"target_retired":true,"guardian_retired":true,"guardian_native_exit_status":guardian_status,
                        "target_native_exit_status":family[0].native_exit_status()?
                    }))?,
                    record,
                )?;
                if worker_loss {
                    let worker = worker.lock().map_err(|_| {
                        CiError::Message("component worker ownership poisoned".into())
                    })?;
                    let worker = worker.as_ref().ok_or_else(|| {
                        CiError::Message("component worker was not retained before release".into())
                    })?;
                    let status = worker_exit(worker)?;
                    if status != 0xC000_013A {
                        return Err(CiError::Message(
                            "component worker exit did not match selected native fault".into(),
                        ));
                    }
                    let process_retired = worker.process.has_exited()?;
                    if process_retired != launcher_process_loss {
                        return Err(CiError::Message("component launcher process retirement differs from selected thread/process action".into()));
                    }
                    if process_retired && worker.process.native_exit_status()? != Some(0xC000_013A)
                    {
                        return Err(CiError::Message(
                            "held launcher process status differs from actual selected termination"
                                .into(),
                        ));
                    }
                    retain(
                        &directory.join("held-worker-exit.json"),
                        &serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-component-worker-exit","revision":1,
                            "process_id":worker.process.identity.pid,"process_creation_time_100ns":worker.process.identity.birth,
                            "thread":worker.identity,"held_before_fault":true,"exit_observed":true,"native_exit_status":status,
                            "process_retirement_observed":process_retired,"process_native_exit_status":worker.process.native_exit_status()?
                        }))?,
                        record,
                    )?;
                }
                if control_loss {
                    let worker = control_worker.lock().map_err(|_| {
                        CiError::Message("control worker ownership poisoned".into())
                    })?;
                    let worker = worker.as_ref().ok_or_else(|| {
                        CiError::Message("actual control worker was not held before release".into())
                    })?;
                    let status = worker_exit(worker)?;
                    let process_retired = worker.process.has_exited()?;
                    if process_retired != control_process_loss
                        || status != if control_process_loss { 0xC000_013A } else { 0 }
                    {
                        return Err(CiError::Message("actual control worker thread/process exit differs from selected action".into()));
                    }
                    if process_retired && worker.process.native_exit_status()? != Some(0xC000_013A)
                    {
                        return Err(CiError::Message(
                            "actual held control service status differs".into(),
                        ));
                    }
                    retain(
                        &directory.join("held-control-worker-exit.json"),
                        &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-control-worker-exit","revision":1,"process_id":worker.process.identity.pid,
                        "process_creation_time_100ns":worker.process.identity.birth,"thread":worker.identity,"held_before_fault":true,
                        "exit_observed":true,"native_exit_status":status,"process_retirement_observed":process_retired,
                        "process_native_exit_status":worker.process.native_exit_status()?}))?,
                        record,
                    )?;
                }
            }
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
