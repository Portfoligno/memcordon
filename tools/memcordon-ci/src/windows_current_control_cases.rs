//! Current native control exercises. Every process observation uses the
//! original held handle and every control message names the prepared attempt.
#![cfg(windows)]
use crate::windows_installed_cases::{InstalledWindowsPayload, WindowsLeaseDeadlines};
use crate::{CiError, Result};
use crate::{current_command_evidence, windows_current_arguments as arguments};
use memcordon_core::{
    WindowsProcessIdentityV1, WindowsProviderRequestV4, WindowsWorkloadPreparedV1,
};
use std::{
    fs, io,
    path::Path,
    time::{Duration, Instant},
};

#[path = "windows_current_drain.rs"]
mod drain;
#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/fixture_environment.rs"]
mod fixture_environment;
#[path = "windows_current_service_restart.rs"]
mod service_restart;

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.try_exists()? {
        return Err(CiError::Message(
            "current control artifact already exists".into(),
        ));
    }
    memcordon_core::write_report_bytes_atomic(path, bytes)
        .map_err(|error| CiError::Message(error.to_string()))?;
    if fs::read(path)? != bytes {
        return Err(CiError::Message(
            "current control artifact readback differs".into(),
        ));
    }
    Ok(())
}

struct HeldProcess(windows_sys::Win32::Foundation::HANDLE);
impl HeldProcess {
    #[allow(unsafe_code)] // Query/synchronize access only; this never signals a process.
    fn open(pid: u32) -> io::Result<Self> {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        };
        // SAFETY: the process is opened query/synchronize-only, without mutation rights.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
    #[allow(unsafe_code)] // Reads the native birth from the original held handle.
    fn identity(&self, pid: u32) -> io::Result<WindowsProcessIdentityV1> {
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let (mut birth, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: the held process handle and distinct output FILETIMEs remain live.
        if unsafe { GetProcessTimes(self.0, &mut birth, &mut exit, &mut kernel, &mut user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(WindowsProcessIdentityV1 {
            process_id: pid,
            creation_time_100ns: u64::from(birth.dwLowDateTime)
                | (u64::from(birth.dwHighDateTime) << 32),
        })
    }
    #[allow(unsafe_code)] // Zero-time query on the original synchronize handle.
    fn wait(&self) -> io::Result<u32> {
        // SAFETY: this is the original held query/synchronize handle.
        let wait = unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(self.0, 0) };
        if wait == windows_sys::Win32::Foundation::WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(wait)
    }
}
impl Drop for HeldProcess {
    #[allow(unsafe_code)] // Closes exactly the native handle owned by this object.
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

pub(super) fn run(
    config: &InstalledWindowsPayload,
    deadlines: WindowsLeaseDeadlines,
) -> Result<()> {
    run_preallocation(config, deadlines)?;
    run_held(config, deadlines, false, false)?;
    run_held(config, deadlines, true, false)?;
    run_held(config, deadlines, false, true)?;
    service_restart::run(config, deadlines)
}

fn run_preallocation(
    config: &InstalledWindowsPayload,
    deadlines: WindowsLeaseDeadlines,
) -> Result<()> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let directory = config
        .output_directory
        .join("current-controls/before-preparation");
    fs::create_dir_all(&directory)?;
    let observations = directory.join("observations");
    fs::create_dir(&observations)?;
    let request = directory.join("request.json");
    let report = directory.join("result.json");
    write_new(&request,br#"{"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}"#)?;
    let budget = deadlines
        .work
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(90));
    if budget.is_zero() {
        return Err(CiError::Message(
            "original preallocation actor cutoff exhausted".into(),
        ));
    }
    let frontend_environment = fixture_environment::entries()?
        .into_iter()
        .filter(|entry| entry.name.first() != Some(&u16::from(b'=')))
        .collect::<Vec<_>>();
    let mut command = std::process::Command::new(&config.cli.path);
    command.current_dir(&directory).env_clear();
    for entry in &frontend_environment {
        command.env(
            std::ffi::OsString::from_wide(&entry.name),
            std::ffi::OsString::from_wide(&entry.value),
        );
    }
    command
        .args(arguments::preallocation(
            &arguments::Paths {
                request: &request,
                report: &report,
                fixture: &config.fixture.path,
            },
            &observations,
        ))
        .stdin(std::process::Stdio::null());
    let invocation = serde_json::json!({"format":"memcordon.windows-current-control-invocation","revision":1,"scenario":"before-preparation","program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),"argv_utf16":command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),"cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"cli_sha256":config.cli.sha256,"fixture_sha256":config.fixture.sha256,"work_deadline_unix_millis":deadlines.work_deadline_unix_millis,"cleanup_deadline_unix_millis":deadlines.cleanup_deadline_unix_millis,"environment_cleared":true,"frontend_environment":frontend_environment});
    write_new(
        &directory.join("invocation.json"),
        &serde_json::to_vec(&invocation)?,
    )?;
    let original_cutoff = deadlines.work.min(Instant::now() + budget);
    let callback_directory = directory.clone();
    let output=memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(command,budget,4*1024*1024,|mut command|command.spawn(),move |frontend_pid,_,_| {
        let frontend=HeldProcess::open(frontend_pid)?;let identity=frontend.identity(frontend_pid)?;
        let accepted=loop {
            let entries=fs::read_dir(&observations)?.collect::<io::Result<Vec<_>>>()?;
            if entries.len()>2{return Err(io::Error::other("unexpected preallocation artifact before cancellation"));}
            let entries=entries.iter().filter(|entry|entry.file_name().to_string_lossy().ends_with(".accepted.json")).collect::<Vec<_>>();
            if entries.len()>1{return Err(io::Error::other("multiple preallocation native associations"));}
            if let Some(entry)=entries.first(){
                let bytes=fs::read(entry.path())?;if bytes.len()>64*1024{return Err(io::Error::other("preallocation association exceeds bound"));}
                memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(io::Error::other)?;
                let accepted:memcordon_core::WindowsWorkloadAcceptedV1=serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                accepted.validate().map_err(io::Error::other)?;
                if accepted.frontend!=identity{return Err(io::Error::other("preallocation frontend identity differs from original child handle"));}
                write_new(&callback_directory.join("accepted.json"),&bytes).map_err(io::Error::other)?;break accepted;
            }
            current_command_evidence::require_frontend_pending("preallocation association",Instant::now()>=original_cutoff,||frontend.wait())?;
            std::thread::sleep(Duration::from_millis(5));
        };
        let native_request=fs::read(observations.join(format!("{}.request.json",accepted.attempt_id)))?;
        if native_request.len()>memcordon_core::WINDOWS_MAX_FRAME_BYTES||crate::windows_causal_acceptance::sha256(&native_request)!=accepted.request_sha256{return Err(io::Error::other("preallocation original request differs"));}
        write_new(&callback_directory.join("native-launch.json"),&native_request).map_err(io::Error::other)?;
        let cancel=WindowsProviderRequestV4::Cancel {schema_version:memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,attempt_id:accepted.attempt_id.clone(),nonce:accepted.nonce.clone(),request_sha256:accepted.request_sha256.clone(),signal:2};
        let cancel=serde_json::to_vec(&cancel).map_err(io::Error::other)?;
        write_new(&callback_directory.join("cancel.json"),&cancel).map_err(io::Error::other)?;
        write_new(&observations.join(format!("{}.cancel.json",accepted.attempt_id)),&cancel).map_err(io::Error::other)?;
        let raw=loop {
            match fs::read(observations.join(format!("{}.cancelled.json",accepted.attempt_id))){Ok(bytes)=>break bytes,Err(error) if error.kind()==io::ErrorKind::NotFound=>{},Err(error)=>return Err(error)}
            if Instant::now()>=original_cutoff{return Err(io::Error::other("original cancellation receipt cutoff exhausted"));}
            std::thread::sleep(Duration::from_millis(5));
        };
        if raw.len()>memcordon_core::WINDOWS_MAX_FRAME_BYTES{return Err(io::Error::other("preallocation cancellation receipt exceeds bound"));}
        let response:memcordon_core::WindowsProviderResponseV4=serde_json::from_slice(&raw).map_err(io::Error::other)?;
        let memcordon_core::WindowsProviderResponseV4::PreallocationCancelled(cancellation)=response else{return Err(io::Error::other("native preallocation cancellation carrier absent"));};
        cancellation.validate().map_err(io::Error::other)?;
        if cancellation.accepted!=accepted||cancellation.signal!=2{return Err(io::Error::other("native preallocation cancellation binding differs"));}
        write_new(&callback_directory.join("native-cancellation.json"),&raw).map_err(io::Error::other)?;
        write_new(&callback_directory.join("native.json"),&serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-current-preallocation-native","revision":1,"frontend":identity,"accepted_sha256":accepted.canonical_sha256().map_err(io::Error::other)?,"cancel_sha256":crate::windows_causal_acceptance::sha256(&cancel),"cancellation_sha256":crate::windows_causal_acceptance::sha256(&raw)})).map_err(io::Error::other)?).map_err(io::Error::other)?;
        Ok(())
    }).map_err(|error|current_command_evidence::into_ci_error(&directory,error,4*1024*1024))?;
    write_new(&directory.join("stdout.bin"), &output.stdout)?;
    write_new(&directory.join("stderr.bin"), &output.stderr)?;
    let native_status = output
        .status
        .code()
        .ok_or_else(|| CiError::Message("native preallocation frontend wait missing".into()))?
        as u32;
    write_new(
        &directory.join("wait.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.windows-current-control-wait","revision":1,"native_status":native_status,"stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),"stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr)}),
        )?,
    )?;
    let result = memcordon_core::ResultV3::parse(&fs::read(report)?)
        .map_err(|error| CiError::Message(error.to_string()))?;
    if native_status != 130
        || result.release != memcordon_core::result_v3::ReleaseKnowledgeV3::NotReleased
        || result.outcome.native_termination.is_some()
        || result.outcome.kind != memcordon_core::execution_facts::OutcomeKindV1::Interrupted
        || !matches!(
            result.runtime,
            memcordon_core::result_v3::RuntimeExecutionV3::WindowsPreallocationCancelled { .. }
        )
        || !output.stdout.is_empty()
    {
        return Err(CiError::Message(
            "preallocation actor lacks actual interrupted/no-target native receipt".into(),
        ));
    }
    Ok(())
}

fn run_held(
    config: &InstalledWindowsPayload,
    deadlines: WindowsLeaseDeadlines,
    after_release: bool,
    during_drain: bool,
) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let directory = config
        .output_directory
        .join("current-controls")
        .join(if during_drain {
            "during-drain"
        } else if after_release {
            "after-release"
        } else {
            "held-before-release"
        });
    fs::create_dir_all(&directory)?;
    let observation_directory = directory.join("prepared");
    fs::create_dir(&observation_directory)?;
    let request = directory.join("request.json");
    let report = directory.join("result.json");
    let terminal = directory.join("terminal.json");
    write_new(&request, br#"{"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}"#)?;
    let budget = deadlines
        .work
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(90));
    if budget.is_zero() {
        return Err(CiError::Message(
            "original control-case deadline exhausted".into(),
        ));
    }
    let mut command = std::process::Command::new(&config.cli.path);
    use std::os::windows::ffi::OsStringExt;
    let frontend_environment = fixture_environment::entries()?
        .into_iter()
        .filter(|entry| entry.name.first() != Some(&u16::from(b'=')))
        .collect::<Vec<_>>();
    command.env_clear();
    for entry in &frontend_environment {
        command.env(
            std::ffi::OsString::from_wide(&entry.name),
            std::ffi::OsString::from_wide(&entry.value),
        );
    }
    let pid_file = directory.join("target-started.json");
    command
        .current_dir(&directory)
        .args(arguments::held(
            &arguments::Paths {
                request: &request,
                report: &report,
                fixture: &config.fixture.path,
            },
            &observation_directory,
            &terminal,
            after_release.then_some(pid_file.as_path()),
        ))
        .stdin(std::process::Stdio::null());
    let invocation = serde_json::json!({"format":"memcordon.windows-current-control-invocation","revision":1,"scenario":if during_drain {"during-drain"} else if after_release {"after-release"} else {"held-before-release"},"program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),"argv_utf16":command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),"cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"cli_sha256":config.cli.sha256,"fixture_sha256":config.fixture.sha256,"work_deadline_unix_millis":deadlines.work_deadline_unix_millis,"cleanup_deadline_unix_millis":deadlines.cleanup_deadline_unix_millis,"environment_cleared":true,"frontend_environment":frontend_environment});
    write_new(
        &directory.join("invocation.json"),
        &serde_json::to_vec(&invocation)?,
    )?;
    let original_cutoff = deadlines.work.min(Instant::now() + budget);
    let callback_directory = directory.clone();
    let probe_fixture = config.fixture.path.clone();
    let drain_config = config.clone();
    let prior_directory = directory
        .parent()
        .ok_or_else(|| CiError::Message("current control parent absent".into()))?
        .join("held-before-release");
    let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(command, budget, 4 * 1024 * 1024, |mut command| command.spawn(), move |frontend_pid, _, _| {
        let frontend = HeldProcess::open(frontend_pid)?;
        let frontend_identity = frontend.identity(frontend_pid)?;
        let accepted=loop {
            let entries=fs::read_dir(&observation_directory)?.collect::<io::Result<Vec<_>>>()?;
            if entries.len()>2 { return Err(io::Error::other("preallocation observation directory has unexpected entries")); }
            let accepted=entries.iter().filter(|entry|entry.file_name().to_string_lossy().ends_with(".accepted.json")).collect::<Vec<_>>();
            if accepted.len()>1 { return Err(io::Error::other("multiple native preallocation associations")); }
            if let Some(entry)=accepted.first() {
                let bytes=fs::read(entry.path())?;
                if bytes.len()>64*1024 { return Err(io::Error::other("native preallocation observation exceeds bound")); }
                memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(io::Error::other)?;
                let accepted:memcordon_core::WindowsWorkloadAcceptedV1=serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                accepted.validate().map_err(io::Error::other)?;
                if accepted.frontend!=frontend_identity { return Err(io::Error::other("preallocation association differs from original held frontend")); }
                write_new(&callback_directory.join("accepted.json"),&bytes).map_err(io::Error::other)?;
                break accepted;
            }
            current_command_evidence::require_frontend_pending("preallocation association",Instant::now()>=original_cutoff,||frontend.wait())?;
            std::thread::sleep(Duration::from_millis(5));
        };
        let preparation_ack=WindowsProviderRequestV4::PreparationAcknowledged { schema_version:memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,attempt_id:accepted.attempt_id.clone(),nonce:accepted.nonce.clone(),request_sha256:accepted.request_sha256.clone(),accepted_sha256:accepted.canonical_sha256().map_err(io::Error::other)? };
        let preparation_ack=serde_json::to_vec(&preparation_ack).map_err(io::Error::other)?;
        write_new(&callback_directory.join("accepted-ack.json"),&preparation_ack).map_err(io::Error::other)?;
        write_new(&observation_directory.join(format!("{}.accepted-ack.json",accepted.attempt_id)),&preparation_ack).map_err(io::Error::other)?;
        let prepared = loop {
            let mut entries = fs::read_dir(&observation_directory)?.collect::<io::Result<Vec<_>>>()?;
            if entries.len() > 4 { return Err(io::Error::other("prepared control directory has unexpected entries")); }
            entries.retain(|entry|entry.file_name().to_string_lossy().ends_with(".prepared.json"));
            if entries.len() > 1 { return Err(io::Error::other("prepared control has multiple attempts")); }
            if let Some(entry) = entries.first() {
                let bytes = fs::read(entry.path())?;
                if bytes.len() > 64 * 1024 { return Err(io::Error::other("prepared native carrier exceeds bound")); }
                memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(io::Error::other)?;
                let prepared: WindowsWorkloadPreparedV1 = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                prepared.validate().map_err(io::Error::other)?;
                write_new(&callback_directory.join("prepared.json"), &bytes).map_err(io::Error::other)?;
                break prepared;
            }
            current_command_evidence::require_frontend_pending("workload preparation",Instant::now()>=original_cutoff,||frontend.wait())?;
            std::thread::sleep(Duration::from_millis(5));
        };
        let target = HeldProcess::open(prepared.target.process_id)?;
        let target_identity = target.identity(prepared.target.process_id)?;
        if target_identity != prepared.target || target.wait()? != windows_sys::Win32::Foundation::WAIT_TIMEOUT { return Err(io::Error::other("original prepared target identity/liveness differs")); }
        use std::io::Read;
        let mut native_bytes=Vec::new();
        fs::File::open(observation_directory.join(format!("{}.request.json",prepared.attempt_id)))?
            .take(memcordon_core::WINDOWS_MAX_FRAME_BYTES as u64 + 1).read_to_end(&mut native_bytes)?;
        if native_bytes.len()>memcordon_core::WINDOWS_MAX_FRAME_BYTES || crate::windows_causal_acceptance::sha256(&native_bytes)!=prepared.request_sha256 { return Err(io::Error::other("original prepared native request binding differs")); }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&native_bytes).map_err(io::Error::other)?;
        let native_launch:memcordon_core::WindowsLaunchRequestV2=serde_json::from_slice(&native_bytes).map_err(io::Error::other)?;
        native_launch.validate_workload().map_err(io::Error::other)?;
        write_new(&callback_directory.join("native-launch.json"),&native_bytes).map_err(io::Error::other)?;
        if after_release {
            let prior_prepared_bytes=fs::read(prior_directory.join("prepared.json"))?;
            let prior_prepared:WindowsWorkloadPreparedV1=serde_json::from_slice(&prior_prepared_bytes).map_err(io::Error::other)?;
            prior_prepared.validate().map_err(io::Error::other)?;
            if prior_prepared.attempt_id==prepared.attempt_id||prior_prepared.nonce==prepared.nonce{return Err(io::Error::other("fresh current attempt reused prior association"));}
            let before=target.wait()?;
            let (response,delivery,request)=memcordon_platform::recover_windows_attempt_with_request(&prior_prepared.attempt_id,&prior_prepared.nonce,&prior_prepared.request_sha256).map_err(io::Error::other)?;
            let after=target.wait()?;
            if delivery.is_some()||!matches!(&response,memcordon_core::WindowsProviderResponseV4::TerminalRetiredV2(retired) if retired.attempt_id==prior_prepared.attempt_id)||before!=windows_sys::Win32::Foundation::WAIT_TIMEOUT||after!=windows_sys::Win32::Foundation::WAIT_TIMEOUT{return Err(io::Error::other("prior current association acquired fresh attempt authority or lost its genuine retirement"));}
            write_new(&callback_directory.join("stale-attempt.json"),&serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-current-stale-owner-operation","revision":1,"prior_prepared_bytes":prior_prepared_bytes,"prior_result_bytes":fs::read(prior_directory.join("result.json"))?,"prior_terminal_bytes":fs::read(prior_directory.join("terminal.json"))?,"request":request,"response":response,"delivery":delivery,"target":target_identity,"target_wait_before":before,"target_wait_after":after})).map_err(io::Error::other)?).map_err(io::Error::other)?;
            let acknowledgment=WindowsProviderRequestV4::PreparedAcknowledged {schema_version:memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,attempt_id:prepared.attempt_id.clone(),nonce:prepared.nonce.clone(),request_sha256:prepared.request_sha256.clone(),prepared_sha256:prepared.canonical_sha256().map_err(io::Error::other)?};
            let acknowledgment=serde_json::to_vec(&acknowledgment).map_err(io::Error::other)?;
            write_new(&callback_directory.join("prepared-ack.json"),&acknowledgment).map_err(io::Error::other)?;
            write_new(&observation_directory.join(format!("{}.prepared-ack.json",prepared.attempt_id)),&acknowledgment).map_err(io::Error::other)?;
            loop {
                match fs::read(callback_directory.join("target-started.json")) {
                    Ok(bytes)=>{
                        if bytes.len()>4096 {return Err(io::Error::other("actual started target identity exceeds bound"));}
                        let text=std::str::from_utf8(&bytes).map_err(io::Error::other)?;
                        let mut values=text.split_whitespace();
                        let pid=values.next().and_then(|value|value.parse::<u32>().ok()).ok_or_else(||io::Error::other("actual started PID absent"))?;
                        let birth=values.next().and_then(|value|value.parse::<u128>().ok()).ok_or_else(||io::Error::other("actual started birth absent"))?;
                        if values.next().is_some()||pid!=target_identity.process_id||birth!=u128::from(target_identity.creation_time_100ns)||target.wait()?!=windows_sys::Win32::Foundation::WAIT_TIMEOUT {return Err(io::Error::other("actual running target differs from original prepared handle"));}
                        break;
                    },
                    Err(error)if error.kind()==io::ErrorKind::NotFound=>{},
                    Err(error)=>return Err(error),
                }
                if Instant::now()>=original_cutoff||frontend.wait()?!=windows_sys::Win32::Foundation::WAIT_TIMEOUT{return Err(io::Error::other("original started-target cutoff exhausted"));}
                std::thread::sleep(Duration::from_millis(5));
            }
        } else if !during_drain {
        let mut original_token_command=std::process::Command::new(&probe_fixture);
        let probe_environment=fixture_environment::entries()?;
        original_token_command.env_clear();for entry in &probe_environment {if entry.name.first()!=Some(&u16::from(b'=')){original_token_command.env(std::ffi::OsString::from_wide(&entry.name),std::ffi::OsString::from_wide(&entry.value));}}
        original_token_command.args(["consumer-readiness-windows","token-snapshot"]).stdin(std::process::Stdio::null());
        let token_output=memcordon_testkit::run_with_deadline_output_limit(&mut original_token_command,original_cutoff.saturating_duration_since(Instant::now()),64*1024).map_err(|error|io::Error::other(error.to_string()))?;
        let original_token:serde_json::Value=serde_json::from_slice(&token_output.stdout).map_err(io::Error::other)?;
        if !token_output.status.success()||!token_output.stderr.is_empty()||original_token["restricted"]!=false{return Err(io::Error::other("original ordinary caller token probe failed or was restricted"));}
        let caller_sid:Vec<u8>=serde_json::from_value(original_token["user_sid"].clone()).map_err(io::Error::other)?;
        crate::windows_consumer_readiness::native::prepare_owned_probe_image(&probe_fixture,&caller_sid).map_err(io::Error::other)?;
        for scenario in ["foreign-inspect","foreign-cancel","foreign-recover"] {
            let challenge=crate::windows_causal_acceptance::sha256(format!("memcordon.current-owner-probe\0{}\0{scenario}",prepared.nonce).as_bytes());
            let request=match scenario {
                "foreign-inspect"=>WindowsProviderRequestV4::ReplayTerminal {schema_version:memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,attempt_id:prepared.attempt_id.clone(),nonce:prepared.nonce.clone(),request_sha256:prepared.request_sha256.clone(),relay_phase:memcordon_core::WindowsRelayPhaseV1::AwaitTerminal},
                "foreign-cancel"=>WindowsProviderRequestV4::Cancel {schema_version:memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,attempt_id:prepared.attempt_id.clone(),nonce:prepared.nonce.clone(),request_sha256:prepared.request_sha256.clone(),signal:2},
                _=>WindowsProviderRequestV4::RecoverAttempt {schema_version:memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,attempt_id:prepared.attempt_id.clone(),nonce:prepared.nonce.clone(),request_sha256:prepared.request_sha256.clone(),challenge},
            };
            let mut command=std::process::Command::new(&probe_fixture);
            command.env_clear();for entry in &probe_environment {if entry.name.first()!=Some(&u16::from(b'=')){command.env(std::ffi::OsString::from_wide(&entry.name),std::ffi::OsString::from_wide(&entry.value));}}
            command.args(["consumer-readiness-windows","restricted-frontend"]).arg(&probe_fixture).args(["consumer-readiness-windows","owner-request-probe"]).arg(serde_json::to_string(&request).map_err(io::Error::other)?).stdin(std::process::Stdio::null());
            let argv=command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>();
            let before=target.wait()?;
            let remaining=original_cutoff.saturating_duration_since(Instant::now());
            if remaining.is_zero(){return Err(io::Error::other("original foreign-probe cutoff exhausted"));}
            let output=memcordon_testkit::run_with_deadline_output_limit(&mut command,remaining,256*1024).map_err(|error|io::Error::other(error.to_string()))?;
            let after=target.wait()?;
            if !output.status.success()||!output.stderr.is_empty()||before!=windows_sys::Win32::Foundation::WAIT_TIMEOUT||after!=windows_sys::Win32::Foundation::WAIT_TIMEOUT{return Err(io::Error::other("foreign actor failed or changed original held target"));}
            let probe:serde_json::Value=serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
            if probe["token"]["restricted"]!=true||probe["request"]!=serde_json::to_value(&request).map_err(io::Error::other)?{return Err(io::Error::other("foreign actor did not use its actual restricted token and original attempt operands"));}
            if let Some(bytes)=probe["response_bytes"].as_array(){
                let bytes=bytes.iter().map(|value|value.as_u64().and_then(|value|u8::try_from(value).ok()).ok_or_else(||io::Error::other("foreign raw reply byte invalid"))).collect::<io::Result<Vec<_>>>()?;
                let response:memcordon_core::WindowsProviderResponseV4=serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                if matches!(response,memcordon_core::WindowsProviderResponseV4::Terminal(_)|memcordon_core::WindowsProviderResponseV4::Reject{..}|memcordon_core::WindowsProviderResponseV4::AttemptRetainedV2(_)|memcordon_core::WindowsProviderResponseV4::TerminalRetiredV2(_)){return Err(io::Error::other("foreign actor acquired original attempt authority"));}
            } else if probe["exchange_error"].as_str().is_none_or(|error|!error.starts_with("response: PeerClosed(")){return Err(io::Error::other("foreign actor did not reach actual authenticated provider request handling and native closure"));}
            write_new(&callback_directory.join(format!("{scenario}.json")),&serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-current-foreign-owner-operation","revision":1,"scenario":scenario,"program_utf16":probe_fixture.as_os_str().encode_wide().collect::<Vec<_>>(),"argv_utf16":argv,"native_status":output.status.code(),"stdout_bytes":output.stdout,"stderr_bytes":output.stderr,"original_token_status":token_output.status.code(),"original_token_stdout":token_output.stdout,"original_token_stderr":token_output.stderr,"target":target_identity,"target_wait_before":before,"target_wait_after":after})).map_err(io::Error::other)?).map_err(io::Error::other)?;
        }
        let mut substituted=native_launch.clone();
        let last=substituted.command.arguments.last_mut().ok_or_else(||io::Error::other("original target exit argument absent"))?;
        *last="1".encode_utf16().collect();
        let substitution_bytes=serde_json::to_vec(&substituted).map_err(io::Error::other)?;
        let substitution_sha256=crate::windows_causal_acceptance::sha256(&substitution_bytes);
        if substitution_sha256==prepared.request_sha256 { return Err(io::Error::other("request substitution did not change actual operand")); }
        write_new(&callback_directory.join("substitution-launch.json"),&substitution_bytes).map_err(io::Error::other)?;
        let before_probe=target.wait()?;
        let (probe_response,probe_delivery,probe_request)=memcordon_platform::recover_windows_attempt_with_request(&prepared.attempt_id,&prepared.nonce,&substitution_sha256).map_err(io::Error::other)?;
        let after_probe=target.wait()?;
        if probe_delivery.is_some() || !matches!(probe_response,memcordon_core::WindowsProviderResponseV4::RecoveryAttemptUnavailable { .. }) || before_probe != windows_sys::Win32::Foundation::WAIT_TIMEOUT || after_probe != windows_sys::Win32::Foundation::WAIT_TIMEOUT { return Err(io::Error::other("substituted request gained authority or changed original held target")); }
        write_new(&callback_directory.join("request-substitution-probe.json"),&serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-current-owner-probe","revision":1,"scenario":"request-substitution","request":probe_request,"response":probe_response,"delivery":probe_delivery,"target":target_identity,"target_wait_before":before_probe,"target_wait_after":after_probe,"substituted_launch_sha256":substitution_sha256})).map_err(io::Error::other)?).map_err(io::Error::other)?;
        }
        let cancellation = WindowsProviderRequestV4::Cancel { schema_version:memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,attempt_id:prepared.attempt_id.clone(),nonce:prepared.nonce.clone(),request_sha256:prepared.request_sha256.clone(),signal:2 };
        let cancellation_bytes = serde_json::to_vec(&cancellation).map_err(io::Error::other)?;
        let before_cancel=if during_drain {drain::run(&drain_config,deadlines,&prepared,&observation_directory,&callback_directory,original_cutoff).map_err(io::Error::other)?} else {target.wait()?};
        if !during_drain {
        write_new(&callback_directory.join("cancel.json"), &cancellation_bytes).map_err(io::Error::other)?;
        let publication = observation_directory.join(format!("{}.cancel.json",prepared.attempt_id));
        write_new(&publication, &cancellation_bytes).map_err(io::Error::other)?;
        }
        let mut target_wait = target.wait()?;
        while target_wait == windows_sys::Win32::Foundation::WAIT_TIMEOUT {
            if Instant::now() >= original_cutoff { return Err(io::Error::other("original target retirement cutoff exhausted")); }
            std::thread::sleep(Duration::from_millis(5));
            target_wait = target.wait()?;
        }
        write_new(&callback_directory.join("native.json"), &serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-current-control-native","revision":1,"frontend":frontend_identity,"target":target_identity,"target_wait_before_cancel":before_cancel,"target_wait_after_cancel":target_wait,"prepared_sha256":prepared.canonical_sha256().map_err(io::Error::other)?,"cancel_sha256":crate::windows_causal_acceptance::sha256(&cancellation_bytes)})).map_err(io::Error::other)?).map_err(io::Error::other)?;
        Ok(())
    }).map_err(|error|current_command_evidence::into_ci_error(&directory,error,4*1024*1024))?;
    write_new(&directory.join("stdout.bin"), &output.stdout)?;
    write_new(&directory.join("stderr.bin"), &output.stderr)?;
    let native_status = output
        .status
        .code()
        .ok_or_else(|| CiError::Message("native frontend wait status absent".into()))?
        as u32;
    write_new(
        &directory.join("wait.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.windows-current-control-wait","revision":1,"native_status":native_status,"stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),"stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr)}),
        )?,
    )?;
    let scenario = if during_drain {
        "during-drain"
    } else if after_release {
        "after-release"
    } else {
        "held-before-release"
    };
    let expected_status = if during_drain {
        matches!(native_status, 125 | 130)
    } else {
        native_status == 130
    };
    if !expected_status {
        return Err(CiError::Message(format!(
            "Windows control scenario={scenario} result={} unexpected frontend status={native_status}; native={:?}; stdout-bytes={}; stderr-bytes={}; stderr={:?}",
            report.display(),
            output.status,
            output.stdout.len(),
            output.stderr.len(),
            crate::command::bounded_excerpt(&output.stderr),
        )));
    }
    let bytes = fs::read(&report).map_err(|error| {
        CiError::from(error).context(format!(
            "Windows control scenario={scenario} expected frontend status={native_status} result read {}",
            report.display(),
        ))
    })?;
    let result = memcordon_core::ResultV3::parse(&bytes).map_err(|error| {
        CiError::Message(error.to_string()).context(format!(
            "Windows control scenario={scenario} result parse {}",
            report.display(),
        ))
    })?;
    if result.release
        != if after_release {
            memcordon_core::result_v3::ReleaseKnowledgeV3::Released
        } else {
            memcordon_core::result_v3::ReleaseKnowledgeV3::NotReleased
        }
        || if during_drain {
            ![
                memcordon_core::execution_facts::OutcomeKindV1::Interrupted,
                memcordon_core::execution_facts::OutcomeKindV1::ProviderFailure,
            ]
            .contains(&result.outcome.kind)
        } else {
            result.outcome.kind != memcordon_core::execution_facts::OutcomeKindV1::Interrupted
        }
        || if during_drain {
            ![125, 130].contains(&result.outcome.wrapper_status)
        } else {
            result.outcome.wrapper_status != 130
        }
        || result.outcome.native_termination.is_some() != after_release
        || native_status != result.outcome.wrapper_status as u32
        || result.cleanup.state != memcordon_core::execution_facts::CleanupStateV1::Complete
        || !output.stdout.is_empty()
    {
        return Err(CiError::Message(
            "held cancellation lacks actual no-release/full native cleanup/empty target output"
                .into(),
        ));
    }
    Ok(())
}
