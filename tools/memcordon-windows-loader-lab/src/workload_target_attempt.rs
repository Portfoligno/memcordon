//! A single retained diagnostic target and its unconditional native settlement.
use super::*;
use memcordon_windows_loader_lab::default_dacl_counterfactual as contract;

#[derive(Default)]
pub(super) struct Aggregate {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_omitted: u64,
    pub stderr_omitted: u64,
    pub events: usize,
    pub event_bytes: usize,
}

pub(super) struct Spec<'a> {
    pub input: &'a Request,
    pub source: HANDLE,
    pub token: HANDLE,
    pub digest: &'a str,
    pub image_path: &'a Path,
    pub image_pin: &'a File,
    pub source_default_dacl: &'a Value,
    pub changed: Option<&'a default_dacl_counterfactual_native::Duplicate>,
    pub work: Instant,
    pub cleanup: Instant,
}

pub(super) struct Attempt {
    pub observation: Value,
    pub debug: Value,
    pub operation: Result<(), String>,
    pub cleanup_errors: Vec<String>,
    pub work_exit: Option<u32>,
    pub fixture_entry: bool,
    pub default_acl_equal: Option<bool>,
    pub omissions: u64,
    pub forced: bool,
    pub settled: bool,
}

fn executing_image(process: &Process, expected: &File, path: &Path) -> Result<Value, String> {
    if birth(process.process.0)? != process.birth {
        return Err("actual target held birth changed".into());
    }
    let mut native = vec![0_u16; 32768];
    let mut length = u32::try_from(native.len()).map_err(|error| error.to_string())?;
    if unsafe { QueryFullProcessImageNameW(process.process.0, 0, native.as_mut_ptr(), &mut length) }
        == 0
        || length as usize > native.len()
    {
        return Err(error("QueryFullProcessImageNameW owned diagnostic target"));
    }
    let observed = PathBuf::from(OsString::from_wide(&native[..length as usize]));
    if observed.canonicalize().map_err(|error| error.to_string())?
        != path.canonicalize().map_err(|error| error.to_string())?
    {
        return Err("actual diagnostic target path differs from pinned original image".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&observed)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let held = file_identity(expected.as_raw_handle());
    let actual = file_identity(file.as_raw_handle());
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || held["native_identity_measured"] != true
        || actual["native_identity_measured"] != true
        || held["volume_serial"] != actual["volume_serial"]
        || held["file_id"] != actual["file_id"]
    {
        return Err(
            "executing target image differs from original held native file identity".into(),
        );
    }
    Ok(actual)
}

fn entry_bytes(path: &Path) -> Result<Vec<u8>, String> {
    // The fresh fixture still owns its append stream while stopped at the
    // unreleased gate. Permit that writer, but deny deletion/replacement for
    // the duration of this held read; ordinary immutable input reads differ.
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let mut identity = BY_HANDLE_FILE_INFORMATION::default();
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > LIMIT as u64
        || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut identity) } == 0
        || identity.nNumberOfLinks != 1
    {
        return Err(
            "counterfactual transcript is not a bounded retained single-link regular file".into(),
        );
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > LIMIT {
        return Err("counterfactual transcript grew beyond shared finite bound".into());
    }
    Ok(bytes)
}

pub(super) fn observe(spec: Spec<'_>, aggregate: &mut Aggregate) -> Attempt {
    let Spec {
        input,
        source,
        token,
        digest,
        image_path,
        image_pin,
        source_default_dacl,
        changed,
        work,
        cleanup,
    } = spec;
    let mut process: Option<Process> = None;
    let mut job: Option<Job> = None;
    let mut debugger: Option<DebugOwner> = None;
    let mut streams: Option<(Handle, Handle, Handle)> = None;
    let mut observation = json!({});
    let mut default_acl_equal = None;
    let mut fixture_entry = false;
    let mut accepted_work_exit = None;
    let operation = (|| -> Result<(), String> {
        live(work)?;
        job = Some(
            Job::create(input.reference_plan.job_security_descriptor_sddl())
                .map_err(|error| format!("target Job: {error:?}"))?,
        );
        let (stdin_read, stdin_write) = pipe()?;
        clear(stdin_write.0)?;
        let (stdout_read, stdout_write) = pipe()?;
        clear(stdout_read.0)?;
        let (stderr_read, stderr_write) = pipe()?;
        clear(stderr_read.0)?;
        streams = Some((stdin_write, stdout_read, stderr_read));
        live(work)?;
        let spawned = spawn(SpawnSpec {
            token,
            command: &input.command,
            environment: &input.original_request.environment,
            cwd: &input.original_request.current_directory,
            desktop: Some(&desktop_name(input)),
            job: job.as_ref().expect("stored target Job"),
            handles: &[stdin_read.0, stdout_write.0, stderr_write.0],
            standard: true,
            descriptors: Some((
                input.reference_plan.process_security_descriptor_sddl(),
                input.reference_plan.thread_security_descriptor_sddl(),
            )),
            cleanup,
            debug: DebugCreation::OnlyThisProcess(
                &input.output_directory,
                EVENT_LIMIT.saturating_sub(aggregate.events),
                LIMIT.saturating_sub(aggregate.event_bytes),
            ),
        });
        process = Some(match spawned {
            Ok(value) => value,
            Err(primary) => {
                observation["target_post_create_rollback"] = match read(
                    &input.output_directory.join("post-create-rollback.json"),
                    LIMIT * 2,
                )
                .and_then(|bytes| {
                    serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())
                }) {
                    Ok(value) => value,
                    Err(error) => {
                        json!({"retention_error":error,"meaning":"no rollback authority inferred"})
                    }
                };
                return Err(primary);
            }
        });
        debugger = process.as_mut().expect("stored target").debugger.take();
        if let Some(owner) = debugger.as_mut() {
            owner.event_limit = EVENT_LIMIT.saturating_sub(aggregate.events);
            owner.byte_limit = LIMIT.saturating_sub(aggregate.event_bytes);
        }
        drop((stdin_read, stdout_write, stderr_write));
        let target = process.as_mut().expect("stored target");
        observation["target"] = json!({"pid":target.pid,"birth":target.birth,"creation_flags":target.creation_flags,"debug_creation":"only-this-process","debugger_perturbation":true,"post_create_image_and_token_checks":"not yet complete"});
        let identity = executing_image(target, image_pin, image_path)?;
        let actual_token = process_token(target.process.0)?;
        let envelope = memcordon_windows_launch_core::query_token_envelope(actual_token.0)?;
        if memcordon_windows_launch_core::token_envelope_sha256(&envelope)? != digest {
            return Err("actual process primary token envelope differs".into());
        }
        observation["target"] = json!({"pid":target.pid,"birth":target.birth,"new_identity":true,"creation_flags":target.creation_flags,
            "debug_creation":"only-this-process","stdio_roles":["stdin","stdout","stderr"],"stdin":"empty-live-pipe","actual_envelope":envelope,
            "desktop":desktop_name(input),"debugger_perturbation":true,"image_native_identity":identity});
        live(work)?;
        let actual_dacl = startup_access_probes::default_dacl(actual_token.0);
        default_acl_equal =
            memcordon_windows_loader_lab::startup_probe_contract::default_dacl_equality(
                source_default_dacl,
                &actual_dacl,
            );
        observation["default_dacl_comparison"] = json!({"actual_suspended_primary":actual_dacl,"exact_null_and_raw_bytes_equal":default_acl_equal,
            "actual_target":{"pid":target.pid,"birth":target.birth},"actual_target_token_envelope_sha256":digest,"before_resume":true,"diagnostic_only":true,"inconclusive":true});
        if let Some(duplicate) = changed {
            observation["counterfactual_token_attestation"] =
                duplicate.attest(source, actual_token.0, work)?;
            if default_acl_equal != Some(true) {
                return Err(
                    "actual changed-arm default ACL differs from retained duplicate".into(),
                );
            }
        }
        live(work)?;
        let resumed = resume(
            target,
            "actual-workload-target",
            "debug-at-creation-before-single-resume",
            true,
        )?;
        observation["target_resume"] =
            serde_json::to_value(&resumed).map_err(|error| error.to_string())?;
        resumed.result.require_exact_one()?;
        loop {
            live(work)?;
            let (_, output, errors) = streams.as_ref().expect("retained target streams");
            drain(
                output.0,
                &mut aggregate.stdout,
                &mut aggregate.stdout_omitted,
            )?;
            drain(
                errors.0,
                &mut aggregate.stderr,
                &mut aggregate.stderr_omitted,
            )?;
            if aggregate.stdout_omitted != 0 || aggregate.stderr_omitted != 0 {
                return Err("shared diagnostic output byte bound exhausted; inconclusive".into());
            }
            let owner = debugger.as_mut().expect("retained debug owner");
            owner.poll(target.process.0, work, DebugPhase::Work)?;
            // A bounded native wait/read may return at or after its cutoff.
            // Keep raw events, but accept no work-phase fact after expiry.
            live(work)?;
            accepted_work_exit = matches!(owner.exit_phase, Some(DebugPhase::Work))
                .then_some(owner.exit)
                .flatten();
            if owner.omitted != 0 {
                return Err("shared diagnostic event bound exhausted; inconclusive".into());
            }
            let transcript = input.descriptor["transcript"]
                .as_str()
                .ok_or("diagnostic transcript absent")?;
            if Path::new(transcript)
                .try_exists()
                .map_err(|error| error.to_string())?
            {
                let bytes = if changed.is_some() {
                    entry_bytes(Path::new(transcript))?
                } else {
                    read(Path::new(transcript), LIMIT)?
                };
                if changed.is_some() {
                    let entered = unsafe { WaitForSingleObject(target.process.0, 0) }
                        == WAIT_TIMEOUT
                        && birth(target.process.0)? == target.birth
                        && contract::bound_entry(
                            &bytes,
                            target.pid,
                            &serde_json::from_value::<Vec<u8>>(
                                input.descriptor["challenge"].clone(),
                            )
                            .map_err(|error| error.to_string())?,
                            LIMIT,
                        )?;
                    live(work)?;
                    if entered {
                        fixture_entry = true;
                    }
                } else {
                    live(work)?;
                    fixture_entry = !bytes.is_empty();
                }
                if fixture_entry {
                    observation["fixture_entry"] = json!({"observed":true,"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),
                        "authenticated_started_frame":changed.is_some(),"pid":target.pid,"birth":target.birth,"gate_released":false});
                    break;
                }
            }
            if owner.exit.is_some() {
                break;
            }
        }
        observation["image_pin_held_during_observation"] = json!(true);
        Ok(())
    })();
    let work_exit = accepted_work_exit;
    let forced = work_exit.is_none();
    let mut cleanup_errors = Vec::new();
    if forced {
        if let Some(job) = job.as_ref() {
            observation["target_termination_request"] = json!({"requested":true,"phase":"cleanup","reason":"diagnostic cleanup","code":FAILURE,
                "target":process.as_ref().map(|target|json!({"pid":target.pid,"birth":target.birth})),"meaning":"not a natural startup exit"});
            if let Err(error) = job.terminate(FAILURE) {
                cleanup_errors.push(format!("target Job termination: {error:?}"));
            }
        }
    }
    if let (Some(owner), Some(target)) = (debugger.as_mut(), process.as_ref()) {
        if let Err(error) = owner.settle(target.process.0, cleanup) {
            cleanup_errors.push(error);
        }
    }
    if let Some(target) = process.as_ref() {
        if let Err(error) = wait(target.process.0, cleanup) {
            cleanup_errors.push(error);
        }
    }
    if let Some(job) = job.as_ref() {
        match job.wait_empty(cleanup) {
            Ok(true) => {}
            other => cleanup_errors.push(format!("target Job empty: {other:?}")),
        }
    }
    if let Some((_, output, errors)) = streams.as_ref() {
        if let Err(error) = drain(
            output.0,
            &mut aggregate.stdout,
            &mut aggregate.stdout_omitted,
        ) {
            cleanup_errors.push(error);
        }
        if let Err(error) = drain(
            errors.0,
            &mut aggregate.stderr,
            &mut aggregate.stderr_omitted,
        ) {
            cleanup_errors.push(error);
        }
    }
    if debugger
        .as_ref()
        .is_some_and(|owner| owner.attached || owner.pending.is_some())
    {
        cleanup_errors
            .push("original diagnostic debug owner remains attached or has a pending event".into());
    }
    let settled = cleanup_errors.is_empty();
    let omissions = debugger.as_ref().map_or(0, |owner| owner.omitted);
    let debug=debugger.as_ref().map_or(Value::Null,|owner|{
        aggregate.events=aggregate.events.saturating_add(owner.events.len());
        aggregate.event_bytes=aggregate.event_bytes.saturating_add(owner.event_bytes);
        json!({"events":owner.events,"encoded_event_bytes":owner.event_bytes,"encoded_event_limit":owner.byte_limit,"event_count_limit":owner.event_limit,
            "omitted":owner.omitted,"module_coverage":owner.module_coverage(),"native_exit":owner.exit,"exit_observation_phase":owner.exit_phase,
            "creator_thread":owner.creator,"attached":owner.attached,"pending":owner.pending.is_some()})
    });
    observation["native_retirement"] = json!({"complete":settled,"forced":forced,"errors":cleanup_errors,
        "target":process.as_ref().map(|target|json!({"pid":target.pid,"birth":target.birth}))});
    Attempt {
        observation,
        debug,
        operation,
        cleanup_errors,
        work_exit,
        fixture_entry,
        default_acl_equal,
        omissions,
        forced,
        settled,
    }
}
