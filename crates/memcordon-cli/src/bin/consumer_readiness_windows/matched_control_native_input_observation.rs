//! One selected-owner diagnostic exchange without authority or acknowledgement.
use super::*;
use memcordon_core::{
    WindowsLaunchRequestV2, WindowsProcessIdentityV1, WindowsProviderRequestV4,
    WindowsProviderResponseV4, WindowsWorkloadAcceptedV1,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn custody(path: &Path, bound: usize, cutoff: Instant) -> io::Result<(File, Vec<u8>)> {
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
    native::live(cutoff)?;
    // The frontend still owns the original write handle. Permit that handle,
    // while retaining a no-delete read owner through the diagnostic exchange.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let info = memcordon_platform::test_support::windows_held_file_metadata(&file)?;
    if info.attributes & (0x400 | 0x10 | 0x40) != 0
        || info.links != 1
        || file.metadata()?.len() > bound as u64
    {
        return Err(io::Error::other("input observation custody differs"));
    }
    let mut bytes = Vec::new();
    (&file).take((bound + 1) as u64).read_to_end(&mut bytes)?;
    native::live(cutoff)?;
    if bytes.len() > bound {
        return Err(io::Error::other("input observation custody exceeds bound"));
    }
    Ok((file, bytes))
}

fn unchanged(
    path: &Path,
    original: &(File, Vec<u8>),
    bound: usize,
    cutoff: Instant,
) -> io::Result<()> {
    let (named, bytes) = custody(path, bound, cutoff)?;
    let held = memcordon_platform::test_support::windows_held_file_metadata(&original.0)?;
    let named = memcordon_platform::test_support::windows_held_file_metadata(&named)?;
    if (held.volume_serial, held.file_index) != (named.volume_serial, named.file_index)
        || bytes != original.1
    {
        return Err(io::Error::other("input observation named custody changed"));
    }
    Ok(())
}

pub(super) fn observe(
    caller: Arc<Caller>,
    plan: &Plan,
    installed: &descriptor::Descriptor,
    fixture: &Path,
    frontend: &Process,
    work: Instant,
    cleanup: Instant,
) -> io::Result<Value> {
    native::live(work)?;
    let terminal = installed
        .output_root
        .join("frontend-result.terminal-observation.json");
    let accepted_path = terminal.with_extension("accepted-observation.json");
    let request_path = terminal.with_extension("provider-request.bin");
    let accepted_custody = custody(
        &accepted_path,
        memcordon_core::MAX_WINDOWS_ACCEPTED_OBSERVATION_BYTES,
        work,
    )?;
    let request_custody = custody(&request_path, memcordon_core::WINDOWS_MAX_FRAME_BYTES, work)?;
    let accepted_bytes = &accepted_custody.1;
    let request_bytes = &request_custody.1;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&accepted_bytes)
        .map_err(io::Error::other)?;
    let accepted: WindowsWorkloadAcceptedV1 =
        serde_json::from_slice(&accepted_bytes).map_err(io::Error::other)?;
    let original: WindowsLaunchRequestV2 =
        serde_json::from_slice(&request_bytes).map_err(io::Error::other)?;
    let provider = original.expected_provider_binding;
    memcordon_core::validate_windows_accepted_observation(
        &accepted,
        &request_bytes,
        &provider,
        &WindowsProcessIdentityV1 {
            process_id: frontend.pid,
            creation_time_100ns: frontend.birth,
        },
    )
    .map_err(io::Error::other)?;
    native::live(work)?;
    let mut challenge = Sha256::new();
    challenge.update(b"memcordon.matched-native-input-observation.v1");
    challenge.update(&installed.challenge);
    challenge.update(accepted.attempt_id.as_bytes());
    let challenge = hex(&challenge.finalize());
    let request = WindowsProviderRequestV4::ObserveAttemptDiagnostics {
        schema_version: memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
        attempt_id: accepted.attempt_id.clone(),
        nonce: accepted.nonce.clone(),
        request_sha256: accepted.request_sha256.clone(),
        challenge: challenge.clone(),
    };
    let argument = serde_json::to_string(&request).map_err(io::Error::other)?;
    let argv = [
        fixture.as_os_str().to_owned(),
        OsString::from("consumer-readiness-windows"),
        OsString::from("owner-request-probe"),
        OsString::from(argument),
    ];
    let stdin = Pipe::create(caller.default_acl()?, true, work)?;
    let stdout = Pipe::create(caller.default_acl()?, false, work)?;
    let stderr = Pipe::create(caller.default_acl()?, false, work)?;
    let job = Job::create(work)?;
    let mut process = Process::create(
        caller,
        Launch {
            image_role: native::Image::Fixture,
            image: fixture,
            argv: &argv,
            environment: &plan.environment,
            cwd: &plan.cwd,
            stdio: [
                stdin.read.as_raw_handle(),
                stdout.write.as_raw_handle(),
                stderr.write.as_raw_handle(),
            ],
            job: Some(job),
            work,
            cleanup,
        },
    )?;
    drop(stdin);
    drop(stdout.write);
    drop(stderr.write);
    let mut stdout = Capture::start(stdout.read, work);
    let mut stderr = Capture::start(stderr.read, work);
    let retired = process.resume(work).and_then(|()| process.settle(work));
    let retired = retired.map_err(|primary| {
        if process.needs_settlement() {
            process.fail(primary, cleanup)
        } else {
            primary
        }
    });
    // Both real reader obligations are attempted even if native settlement fails.
    let output = stdout.finish(cleanup);
    let errors = stderr.finish(cleanup);
    let mut primary = None;
    let status = match retired {
        Ok(status) => Some(status),
        Err(error) => {
            primary = Some(error);
            None
        }
    };
    let mut collect = |result: io::Result<Vec<u8>>| match result {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            primary = Some(match primary.take() {
                Some(first) => native::combine(first, Err(error)),
                None => error,
            });
            None
        }
    };
    let output = collect(output);
    let errors = collect(errors);
    if let Some(primary) = primary {
        return Err(primary);
    }
    let output = output.expect("successful capture");
    let errors = errors.expect("successful capture");
    let mut retained = json!({
        "revision":1,"request":request,
        "helper":{"pid":process.pid,"birth":process.birth,
            "before_resume":process.input_observation,"native_status":status,
            "stdout_bytes":output.len(),"stdout_sha256":hex(&Sha256::digest(&output)),
            "stderr_bytes":errors.len(),"stderr_sha256":hex(&Sha256::digest(&errors))},
        "status":"protocol_gap"
    });
    // The legacy probe includes raw token/SID facts. Parse only to select the
    // bounded reply; never copy that object or its errors into retained output.
    memcordon_core::canonical_json::reject_duplicate_json_keys(&output)
        .map_err(io::Error::other)?;
    let observed: Value = serde_json::from_slice(&output).map_err(io::Error::other)?;
    if observed.get("format").and_then(Value::as_str)
        != Some("memcordon.windows-current-foreign-owner-probe")
        || observed.get("revision").and_then(Value::as_u64) != Some(1)
        || observed.get("process_id").and_then(Value::as_u64) != Some(u64::from(process.pid))
        || observed.get("request")
            != Some(&serde_json::to_value(&request).map_err(io::Error::other)?)
        || status != Some(0)
        || !errors.is_empty()
    {
        return Ok(retained);
    }
    let Some(raw) = observed
        .get("response_bytes")
        .filter(|value| !value.is_null())
    else {
        return Ok(retained);
    };
    let bytes: Vec<u8> = serde_json::from_value(raw.clone()).map_err(io::Error::other)?;
    if bytes.len() > memcordon_core::MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES {
        return Ok(retained);
    }
    retained["response_bytes"] = json!(bytes.len());
    retained["response_sha256"] = json!(hex(&Sha256::digest(&bytes)));
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(io::Error::other)?;
    let response: WindowsProviderResponseV4 =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    retained["response_kind"] = json!(match &response {
        WindowsProviderResponseV4::AttemptDiagnostics(_) => "attempt-diagnostics",
        WindowsProviderResponseV4::Terminal(_) => "terminal",
        WindowsProviderResponseV4::Reject { .. } => "reject",
        _ => "other",
    });
    if let WindowsProviderResponseV4::AttemptDiagnostics(observed) = response {
        observed
            .validate_bound(
                memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
                &challenge,
                &accepted.attempt_id,
                &accepted.request_sha256,
                &provider,
            )
            .map_err(io::Error::other)?;
        retained["status"] = json!(match observed
            .provider_failure
            .as_deref()
            .and_then(|projection| projection.native_inputs.as_ref())
        {
            None => "native_input_observation_unavailable",
            Some(inputs)
                if inputs.is_bound_to(
                    &accepted.attempt_id,
                    &accepted.request_sha256,
                    &WindowsProcessIdentityV1 {
                        process_id: frontend.pid,
                        creation_time_100ns: frontend.birth,
                    },
                ) =>
                "validated_frontend_input_observation",
            Some(_) => "native_input_frontend_binding_differs",
        });
        retained["response"] = serde_json::to_value(observed).map_err(io::Error::other)?;
    }
    unchanged(
        &accepted_path,
        &accepted_custody,
        memcordon_core::MAX_WINDOWS_ACCEPTED_OBSERVATION_BYTES,
        work,
    )?;
    unchanged(
        &request_path,
        &request_custody,
        memcordon_core::WINDOWS_MAX_FRAME_BYTES,
        work,
    )?;
    Ok(retained)
}
