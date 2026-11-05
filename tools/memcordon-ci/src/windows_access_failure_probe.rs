//! Isolated feasibility collection, never a product capability or caller authority.
use memcordon_platform::windows_access_failure_record::{
    ConsumerSpec, Observation, Ready, StopRecord,
};
use serde_json::{Value, json};
use std::io;

pub const STREAM_BYTES: usize = 64 * 1024;
pub const FRAME_BYTES: usize = 8 * 1024;

#[derive(Debug)]
struct ProbeSecondary {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for ProbeSecondary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; probe secondary: {}", self.primary, self.secondary)
    }
}
impl std::error::Error for ProbeSecondary {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
pub fn preserve(primary: io::Result<()>, secondary: io::Result<()>) -> io::Result<()> {
    match (primary, secondary) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(primary), Err(secondary)) => Err(io::Error::new(
            primary.kind(),
            ProbeSecondary { primary, secondary },
        )),
    }
}

pub fn checked_attempt(value: &Value) -> io::Result<Value> {
    let fields = [
        "pid",
        "thread_id",
        "started_qpc",
        "finished_qpc",
        "frequency",
        "requested_win32_access",
        "native_open_error",
        "denial_observed",
        "ordinary_rc_profile_verified",
        "token_execution",
        "fresh_primary_execution_coverage",
        "dacl_scope",
        "host_policy_modified",
        "thread_token_restored",
    ];
    let object = value
        .as_object()
        .ok_or_else(|| io::Error::other("calibration attempt is not a record"))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(io::Error::other("calibration attempt schema differs"));
    }
    for field in [
        "pid",
        "thread_id",
        "started_qpc",
        "finished_qpc",
        "frequency",
        "requested_win32_access",
    ] {
        if value[field].as_u64().is_none() {
            return Err(io::Error::other("calibration numeric fact unavailable"));
        }
    }
    for field in [
        "denial_observed",
        "ordinary_rc_profile_verified",
        "fresh_primary_execution_coverage",
        "host_policy_modified",
        "thread_token_restored",
    ] {
        if !value[field].is_boolean() {
            return Err(io::Error::other("calibration boolean fact unavailable"));
        }
    }
    if !(value["native_open_error"].is_null() || value["native_open_error"].as_i64().is_some())
        || value["token_execution"] != "effective-thread-impersonation"
        || value["fresh_primary_execution_coverage"] != false
        || value["dacl_scope"] != "newly owned calibration file only"
        || value["host_policy_modified"] != false
    {
        return Err(io::Error::other("calibration scope differs"));
    }
    Ok(value.clone())
}

pub fn first_frame(bytes: &[u8]) -> io::Result<Option<Value>> {
    let Some(end) = bytes.iter().position(|byte| *byte == b'\n') else {
        return if bytes.len() > FRAME_BYTES {
            Err(io::Error::other("probe readiness exceeds bound"))
        } else {
            Ok(None)
        };
    };
    if end > FRAME_BYTES {
        return Err(io::Error::other("probe readiness exceeds bound"));
    }
    serde_json::from_slice(&bytes[..end])
        .map(Some)
        .map_err(io::Error::other)
}

pub fn consumer_output(bytes: &[u8], expected: &ConsumerSpec) -> io::Result<Observation> {
    finish_consumer(bytes, expected, true)?
        .ok_or_else(|| io::Error::other("native access consumer unavailable"))
}

/// Only an explicit native OpenTrace failure is optional. Protocol/invariant failures are errors.
pub fn finish_consumer(
    bytes: &[u8],
    expected: &ConsumerSpec,
    status_success: bool,
) -> io::Result<Option<Observation>> {
    if bytes.len() > STREAM_BYTES {
        return Err(io::Error::other("probe consumer output exceeds bound"));
    }
    let ready: Ready = serde_json::from_value(
        first_frame(bytes)?.ok_or_else(|| io::Error::other("probe consumer readiness absent"))?,
    )
    .map_err(io::Error::other)?;
    if ready.spec != *expected {
        return Err(io::Error::other("probe consumer readiness foreign"));
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("validated first frame");
    if !ready.open_trace_succeeded {
        if ready.native_error.is_none_or(|code| code == 0)
            || status_success
            || bytes[end + 1..]
                .iter()
                .any(|byte| !byte.is_ascii_whitespace())
        {
            return Err(io::Error::other(
                "OpenTrace failure contradicts consumer result or lacks native status",
            ));
        }
        return Ok(None);
    }
    if ready.native_error.is_some() || !status_success {
        return Err(io::Error::other(
            "ready consumer execution failed or readiness contradicts status",
        ));
    }
    let observation: Observation =
        serde_json::from_slice(&bytes[end + 1..]).map_err(io::Error::other)?;
    observation.validate().map_err(io::Error::other)?;
    if observation.spec != *expected {
        return Err(io::Error::other("probe consumer session differs"));
    }
    if !observation.consumer_completed
        || observation.process_trace_status != 0
        || observation.close_trace_status != 0
    {
        return Err(io::Error::other(format!(
            "consumer execution/cleanup incomplete; completed={}; ProcessTrace={}; CloseTrace={}",
            observation.consumer_completed,
            observation.process_trace_status,
            observation.close_trace_status
        )));
    }
    Ok(Some(observation))
}

/// Execution success and optional event coverage are deliberately separate.
pub fn assessment(
    attempt: &Value,
    calibration_settled: bool,
    calibration_cleanup: bool,
    consumer_settled: bool,
    spec: Option<&ConsumerSpec>,
    observation: Option<&Observation>,
    stop: Option<&StopRecord>,
) -> Value {
    let attempt = checked_attempt(attempt).unwrap_or(Value::Null);
    let execution = calibration_settled
        && calibration_cleanup
        && attempt["denial_observed"] == true
        && attempt["ordinary_rc_profile_verified"] == true
        && attempt["thread_token_restored"] == true
        && attempt["native_open_error"] == 5;
    let loss_free = stop.is_some_and(|stop| {
        stop.stopped
            && stop.status == 0
            && stop.disable_status == 0
            && !stop.late
            && stop.events_lost == 0
            && stop.log_buffers_lost == 0
            && stop.realtime_buffers_lost == 0
    });
    let coverage = (|| -> Result<(), String> {
        if !execution || !consumer_settled || !loss_free {
            return Err("probe execution or observation lifecycle incomplete".into());
        }
        let spec = spec.ok_or("access-failure session unavailable")?;
        let observation = observation.ok_or("access-failure consumer unavailable")?;
        let number = |field: &str| {
            attempt[field]
                .as_u64()
                .ok_or_else(|| format!("calibration field {field} unavailable"))
        };
        if number("pid")? != u64::from(spec.pid) || number("frequency")? != spec.binding.frequency {
            return Err("calibration identity or clock differs".into());
        }
        let tid =
            u32::try_from(number("thread_id")?).map_err(|_| "calibration thread exceeds DWORD")?;
        observation.probe_match(
            spec,
            tid,
            number("started_qpc")?,
            number("finished_qpc")?,
            &spec.object_name,
            1,
        )?;
        Ok(())
    })();
    json!({"format":"memcordon.ordinary-rc-access-failure-calibration","revision":1,"diagnostic_only":true,"acceptance_authority":false,"product_capability":false,"probe_execution_verified":execution,"calibration_helper_settled":calibration_settled,"calibration_cleanup_verified":calibration_cleanup,"consumer_helper_settled":consumer_settled,"coverage_validated":coverage.is_ok(),"coverage_state":if coverage.is_ok(){"observed-effective-impersonation-calibration"}else{"unsupported-or-inconclusive"},"coverage_detail":coverage.err(),"fresh_primary_execution_coverage":false,"installed_original_call_coverage":false,"full_semantic_token_sd_interpretation":false,"access_mask_is_original_syscall_desired_access":false,"raw_sensitive_bytes_exported":false,"absence_proves_access_succeeded":false,"attempt":attempt,"session":spec,"observation":observation,"stop":stop})
}

#[cfg(windows)]
mod native {
    use super::*;
    use memcordon_platform::test_support::windows_access_failure::OwnedAccessFailureSession;
    use memcordon_platform::test_support::windows_access_failure_probe::Calibration;
    use memcordon_platform::windows_access_failure_record::Binding;
    use memcordon_testkit::ObservedOutput;
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, Read, Write};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    fn detail(error: impl std::fmt::Display) -> String {
        error.to_string().chars().take(1024).collect()
    }
    fn native_code(error: &io::Error) -> Option<i32> {
        let mut current: &(dyn std::error::Error + 'static) = error;
        for _ in 0..8 {
            if let Some(error) = current.downcast_ref::<io::Error>() {
                if let Some(code) = error.raw_os_error() {
                    return Some(code);
                }
            }
            current = current.source()?;
        }
        None
    }
    fn line(value: &Value) -> io::Result<()> {
        let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
        if bytes.len() > FRAME_BYTES {
            return Err(io::Error::other("calibration frame exceeds bound"));
        }
        let mut out = io::stdout().lock();
        out.write_all(&bytes)?;
        out.write_all(b"\n")?;
        out.flush()
    }
    fn config_line() -> io::Result<Value> {
        let mut bytes = Vec::new();
        io::stdin()
            .lock()
            .take((FRAME_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)?;
        if bytes.len() > FRAME_BYTES {
            return Err(io::Error::other("calibration setup exceeds bound"));
        }
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }
    fn deadline(config: &Value) -> io::Result<Instant> {
        let before = Instant::now();
        let (now, frequency) = memcordon_testkit::windows_performance_counter()?;
        let cutoff = config["cutoff_qpc"]
            .as_u64()
            .ok_or_else(|| io::Error::other("probe cutoff absent"))?;
        if config["frequency"] != frequency || cutoff <= now {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original probe cutoff unavailable",
            ));
        }
        let nanos = u128::from(cutoff - now) * 1_000_000_000 / u128::from(frequency);
        before
            .checked_add(Duration::from_nanos(
                u64::try_from(nanos).map_err(io::Error::other)?,
            ))
            .ok_or_else(|| io::Error::other("probe deadline overflow"))
    }

    pub fn calibration_stdio() -> io::Result<()> {
        let config = config_line()?;
        let work = deadline(&config)?;
        let directory = config["directory"]
            .as_str()
            .ok_or_else(|| io::Error::other("owned calibration namespace absent"))?;
        let mut calibration = match Calibration::prepare(Path::new(directory), work) {
            Ok(calibration) => calibration,
            Err(error) => {
                let record = json!({"format":"memcordon.access-calibration-ready","prepared":false,"pid":std::process::id(),"native_error":native_code(&error)});
                return preserve(Err(error), line(&record));
            }
        };
        let image = std::env::current_exe()?;
        let candidate = memcordon_testkit::windows_process_candidate_for_image_until(
            &image,
            std::process::id(),
            work,
        )?;
        let memcordon_testkit::WindowsProcessCandidate::Held(held) = candidate else {
            return Err(io::Error::other("calibration self identity unavailable"));
        };
        let prepared = line(
            &json!({"format":"memcordon.access-calibration-ready","prepared":true,"pid":held.identity.pid,"birth":held.identity.birth.to_string(),"object_name":calibration.object_name()}),
        );
        let attempted = prepared.and_then(|_| {
            let start = config_line()?;
            if start != json!({"start":true}) {
                return Err(io::Error::other("calibration START differs"));
            }
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| calibration.run(work)))
                .map_err(|_| io::Error::other("calibration panicked after mandatory restoration"))?
        });
        let cleanup = calibration.finish();
        let record = json!({"format":"memcordon.access-calibration-result","attempt":attempted.as_ref().ok(),"operation_error":attempted.as_ref().err().map(detail),"operation_native_error":attempted.as_ref().err().and_then(native_code),"cleanup_ok":cleanup.is_ok(),"cleanup_error":cleanup.as_ref().err().map(detail),"cleanup_native_error":cleanup.as_ref().err().and_then(native_code)});
        let required = preserve(attempted.map(|_| ()), cleanup);
        preserve(required, line(&record))
    }

    pub fn consumer_stdio() -> io::Result<()> {
        let spec: ConsumerSpec =
            serde_json::from_value(config_line()?).map_err(io::Error::other)?;
        spec.validate().map_err(io::Error::other)?;
        let observation =
            memcordon_platform::test_support::windows_access_failure::consume(&spec, |result| {
                let ready = Ready {
                    spec: spec.clone(),
                    open_trace_succeeded: result.is_ok(),
                    native_error: result
                        .as_ref()
                        .err()
                        .and_then(|error| error.raw_os_error())
                        .map(|code| code as u32),
                };
                line(&serde_json::to_value(ready).map_err(io::Error::other)?)
            })?;
        let bytes = serde_json::to_vec(&observation).map_err(io::Error::other)?;
        if bytes.len() > memcordon_platform::windows_access_failure_record::RECORD_BYTES {
            return Err(io::Error::other("access observation exceeds bound"));
        }
        let mut out = io::stdout().lock();
        out.write_all(&bytes)?;
        out.write_all(b"\n")?;
        out.flush()
    }

    struct Helper {
        ready: mpsc::Receiver<Result<(u32, Value), String>>,
        action: Option<mpsc::Sender<()>>,
        abort: Arc<AtomicBool>,
        worker: Option<JoinHandle<io::Result<ObservedOutput>>>,
        interrupt: memcordon_platform::test_support::CiInterruptToken,
        cleanup: Instant,
    }
    impl Helper {
        fn spawn(
            mode: &str,
            config: Value,
            work: Instant,
            cleanup: Instant,
            interrupt: memcordon_platform::test_support::CiInterruptToken,
        ) -> io::Result<Self> {
            let mut command = Command::new(std::env::current_exe()?);
            command.arg(mode).stdin(Stdio::piped());
            let consumer = mode == "access-failure-consumer";
            let abort = Arc::new(AtomicBool::new(false));
            let worker_abort = Arc::clone(&abort);
            let (ready_tx, ready) = mpsc::sync_channel(1);
            let (action, action_rx) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("owned-access-probe-helper".into())
                .spawn(move || {
                    memcordon_testkit::run_until_owned_spawn_with_io_controlled_output_limit(
                        command,
                        cleanup,
                        STREAM_BYTES,
                        Some(worker_abort),
                        |mut command| command.spawn(),
                        move |child_pid, input, snapshot| {
                            let prepared = (|| -> io::Result<_> {
                                let mut input = Some(
                                    input.ok_or_else(|| io::Error::other("probe input absent"))?,
                                );
                                let mut bytes =
                                    serde_json::to_vec(&config).map_err(io::Error::other)?;
                                if bytes.len() > FRAME_BYTES {
                                    return Err(io::Error::other("probe config exceeds bound"));
                                }
                                bytes.push(b'\n');
                                input.as_mut().expect("held input").write_all(&bytes)?;
                                if consumer {
                                    drop(input.take());
                                }
                                loop {
                                    if Instant::now() >= work {
                                        return Err(io::Error::new(
                                            io::ErrorKind::TimedOut,
                                            "original probe readiness cutoff",
                                        ));
                                    }
                                    if let Some(value) = first_frame(&snapshot.stdout()?)? {
                                        return Ok((value, input));
                                    }
                                    thread::sleep(Duration::from_millis(10));
                                }
                            })();
                            match prepared {
                                Ok((value, mut input)) => {
                                    let completed_unavailable = value["prepared"] == false
                                        || value["open_trace_succeeded"] == false;
                                    let _ = ready_tx.send(Ok((child_pid, value)));
                                    if completed_unavailable {
                                        return Ok(());
                                    }
                                    action_rx
                                        .recv_timeout(
                                            if consumer { cleanup } else { work }
                                                .saturating_duration_since(Instant::now()),
                                        )
                                        .map_err(io::Error::other)?;
                                    if let Some(input) = input.as_mut() {
                                        input.write_all(b"{\"start\":true}\n")?;
                                    }
                                    Ok(())
                                }
                                Err(error) => {
                                    let _ = ready_tx.send(Err(detail(&error)));
                                    Err(error)
                                }
                            }
                        },
                    )
                    .map_err(|error| io::Error::other(detail(error)))
                })?;
            Ok(Self {
                ready,
                action: Some(action),
                abort,
                worker: Some(worker),
                interrupt,
                cleanup,
            })
        }
        fn ready(&self, work: Instant) -> io::Result<(u32, Value)> {
            loop {
                if self.interrupt.observed().is_some() {
                    self.abort.store(true, Ordering::Release);
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "access calibration interrupted",
                    ));
                }
                if Instant::now() >= work {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "original probe readiness cutoff",
                    ));
                }
                match self.ready.recv_timeout(
                    Duration::from_millis(10).min(work.saturating_duration_since(Instant::now())),
                ) {
                    Ok(result) => return result.map_err(io::Error::other),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(error) => return Err(io::Error::other(error)),
                }
            }
        }
        fn release(&mut self) {
            if let Some(action) = self.action.take() {
                let _ = action.send(());
            }
        }
        fn finish(&mut self) -> io::Result<ObservedOutput> {
            self.release();
            while self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
            {
                if self.interrupt.observed().is_some() || Instant::now() >= self.cleanup {
                    self.abort.store(true, Ordering::Release);
                }
                thread::sleep(Duration::from_millis(10));
            }
            self.worker
                .take()
                .ok_or_else(|| io::Error::other("helper joined twice"))?
                .join()
                .map_err(|_| io::Error::other("probe supervisor panicked; settlement unproved"))?
        }
    }
    impl Drop for Helper {
        fn drop(&mut self) {
            if self.worker.is_some() {
                self.abort.store(true, Ordering::Release);
                let _ = self.finish();
            }
        }
    }

    pub fn collect(output: &Path) -> io::Result<()> {
        let interruption = memcordon_platform::test_support::CiInterruptRegistration::install()?;
        // A new isolated calibration owns these absolute bounds; original consumers are untouched.
        let started = Instant::now();
        let work = started + Duration::from_secs(30);
        let cleanup = work + Duration::from_secs(10);
        let (cutoff_qpc, frequency) = memcordon_testkit::windows_native_work_cutoff(work)?;
        let directory = tempfile::Builder::new()
            .prefix("memcordon-access-calibration-")
            .tempdir()?;
        let path = directory
            .path()
            .to_str()
            .ok_or_else(|| io::Error::other("calibration namespace is not Unicode"))?;
        let mut calibration = Helper::spawn(
            "access-failure-calibration",
            json!({"directory":path,"cutoff_qpc":cutoff_qpc,"frequency":frequency}),
            work,
            cleanup,
            interruption.token(),
        )?;
        let mut session = None;
        let mut consumer = None;
        let mut spec = None;
        let mut observation = None;
        let mut stop = None;
        let mut setup_error = None;
        let mut session_start_cleanup_failed = false;
        let mut consumer_settled = false;
        let mut consumer_failure = None;
        let mut calibration_settled = false;
        let mut calibration_cleanup = false;
        let mut attempt = Value::Null;
        let mut calibration_native_error = None;
        let execution = (|| -> io::Result<()> {
            let (owned_pid, ready) = calibration.ready(work)?;
            if ready["format"] != "memcordon.access-calibration-ready" {
                return Err(io::Error::other("calibration readiness format differs"));
            }
            let pid = ready["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or_else(|| io::Error::other("calibration PID absent"))?;
            if pid != owned_pid {
                return Err(io::Error::other(
                    "calibration readiness differs from original owned child",
                ));
            }
            if ready["prepared"] != true {
                calibration_native_error = ready["native_error"].as_i64();
                return Err(calibration_native_error
                    .and_then(|code| i32::try_from(code).ok())
                    .map(io::Error::from_raw_os_error)
                    .unwrap_or_else(|| {
                        io::Error::other(
                            "owned calibration preparation failed without native status",
                        )
                    }));
            }
            let candidate = memcordon_testkit::windows_process_candidate_for_image_until(
                &std::env::current_exe()?,
                pid,
                work,
            )?;
            let memcordon_testkit::WindowsProcessCandidate::Held(held) = candidate else {
                return Err(io::Error::other("calibration held identity unavailable"));
            };
            if ready["birth"] != held.identity.birth.to_string() {
                return Err(io::Error::other("calibration birth differs"));
            }
            let object_name: Vec<u16> =
                serde_json::from_value(ready["object_name"].clone()).map_err(io::Error::other)?;
            let binding = Binding {
                cutoff_qpc,
                frequency,
                attempt_sha256: Sha256::digest(
                    serde_json::to_vec(&ready).map_err(io::Error::other)?,
                )
                .into(),
            };
            let prepared =
                OwnedAccessFailureSession::prepare(&held, binding, object_name, work, cleanup);
            match prepared.and_then(|prepared| prepared.start()) {
                Ok(owned) => {
                    spec = Some(owned.consumer_spec().clone());
                    session = Some(owned);
                }
                Err(error) => {
                    if let Some(failed)=error.get_ref().and_then(|error|error.downcast_ref::<memcordon_platform::test_support::windows_access_failure::StartupCleanupFailure>()){stop=Some(failed.stop.clone());session_start_cleanup_failed=true;}
                    setup_error = Some(detail(error));
                }
            }
            if let Some(expected) = spec.as_ref() {
                match Helper::spawn(
                    "access-failure-consumer",
                    serde_json::to_value(expected).map_err(io::Error::other)?,
                    work,
                    cleanup,
                    interruption.token(),
                ) {
                    Ok(helper) => {
                        consumer = Some(helper);
                        let (_, value) = consumer.as_ref().unwrap().ready(work)?;
                        let ready: Ready =
                            serde_json::from_value(value).map_err(io::Error::other)?;
                        if ready.spec != *expected
                            || (ready.open_trace_succeeded && ready.native_error.is_some())
                        {
                            consumer_failure = Some(io::Error::other(
                                "consumer readiness session or invariant differs",
                            ));
                            consumer
                                .as_ref()
                                .unwrap()
                                .abort
                                .store(true, Ordering::Release);
                        } else if !ready.open_trace_succeeded {
                            setup_error = Some(format!(
                                "access consumer unavailable; native-error={:?}",
                                ready.native_error
                            ));
                        }
                    }
                    Err(error) => consumer_failure = Some(error),
                }
            }
            calibration.release();
            let result = calibration.finish()?;
            calibration_settled = true;
            let end = result
                .stdout
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or_else(|| io::Error::other("calibration ready frame absent"))?;
            let final_record: Value =
                serde_json::from_slice(&result.stdout[end + 1..]).map_err(io::Error::other)?;
            if final_record["format"] == "memcordon.access-calibration-fatal"
                && final_record["restoration_failed"] == true
            {
                calibration_native_error = final_record["native_error"].as_i64();
                return Err(calibration_native_error
                    .and_then(|code| i32::try_from(code).ok())
                    .map(io::Error::from_raw_os_error)
                    .unwrap_or_else(|| {
                        io::Error::other(
                            "calibration mandatory restoration failed without native status",
                        )
                    }));
            }
            if final_record["format"] != "memcordon.access-calibration-result" {
                return Err(io::Error::other("calibration result differs"));
            }
            calibration_cleanup = final_record["cleanup_ok"] == true;
            calibration_native_error = final_record["operation_native_error"]
                .as_i64()
                .or_else(|| final_record["cleanup_native_error"].as_i64());
            if !result.status.success() || final_record["operation_error"].is_string() {
                return Err(calibration_native_error
                    .and_then(|code| i32::try_from(code).ok())
                    .map(io::Error::from_raw_os_error)
                    .unwrap_or_else(|| {
                        io::Error::other(
                            "calibration native execution failed without native status",
                        )
                    }));
            }
            attempt = checked_attempt(&final_record["attempt"])?;
            if attempt["pid"] != pid
                || attempt["frequency"] != frequency
                || attempt["requested_win32_access"] != 1
                || attempt["thread_id"]
                    .as_u64()
                    .is_none_or(|tid| tid == 0 || tid > u64::from(u32::MAX))
                || attempt["started_qpc"].as_u64().is_none_or(|start| {
                    start == 0
                        || attempt["finished_qpc"]
                            .as_u64()
                            .is_none_or(|end| end <= start || end > cutoff_qpc)
                })
            {
                return Err(io::Error::other(
                    "calibration original caller or clock scope differs",
                ));
            }
            Ok(())
        })();
        let consumer_started = consumer.is_some();
        if let Some(mut owned) = session.take() {
            stop = Some(owned.stop());
        }
        if let Some(mut helper) = consumer.take() {
            match helper.finish() {
                Ok(result) => {
                    consumer_settled = true;
                    if let Some(expected) = spec.as_ref() {
                        match finish_consumer(&result.stdout, expected, result.status.success()) {
                            Ok(value) => observation = value,
                            Err(error) => {
                                if consumer_failure.is_none() {
                                    consumer_failure = Some(error)
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    if consumer_failure.is_none() {
                        consumer_failure = Some(error)
                    }
                }
            }
        }
        if !calibration_settled {
            calibration.abort.store(true, Ordering::Release);
            if calibration.worker.is_some() {
                calibration_settled = calibration.finish().is_ok();
            }
        }
        let directory_cleanup = if calibration_settled {
            directory.close()
        } else {
            let _retained = directory.keep();
            Err(io::Error::other(
                "calibration helper settlement unproved; namespace retained",
            ))
        };
        calibration_cleanup &= directory_cleanup.is_ok();
        let mut report = assessment(
            &attempt,
            calibration_settled,
            calibration_cleanup,
            consumer_settled,
            spec.as_ref(),
            observation.as_ref(),
            stop.as_ref(),
        );
        report["setup_error"] = json!(setup_error);
        report["calibration_native_error"] = json!(calibration_native_error);
        report["consumer_execution_error"] = json!(consumer_failure.as_ref().map(detail));
        report["token_profile_construction"] = json!({"source":"owned calibration helper process primary","disable_max_privilege":true,"restricting_sid":"RestrictedCode","restricting_sid_input_attributes":0,"disabled_sid_count":0,"explicitly_deleted_privileges":0,"required_effective_token_type":"TokenImpersonation","required_effective_impersonation_level":"SecurityImpersonation","source_compared_with_installed_caller":false});
        report["event_counter_scope"] = json!(
            "matched_events counts provider/event/heldPID headers; filtered_objects discards other names; unsupported may lack a decoded name; only validated rows match the selected object"
        );
        report["session_start_cleanup_failed"] = json!(session_start_cleanup_failed);
        report["mask_relationship"] = json!(
            "event access-check mask contains calibration denied READ_DATA; not original syscall DesiredAccess"
        );
        report["execution_error"] = json!(execution.as_ref().err().map(detail));
        report["namespace_cleanup_error"] = json!(directory_cleanup.as_ref().err().map(detail));
        report["namespace_cleanup_verified"] = json!(directory_cleanup.is_ok());
        let mut required = preserve(execution, directory_cleanup);
        if let Some(error) = consumer_failure {
            required = preserve(required, Err(error));
        }
        if session_start_cleanup_failed {
            required = preserve(
                required,
                Err(io::Error::other(
                    "created access session startup cleanup failed",
                )),
            );
        }
        if interruption.token().observed().is_some() {
            required = preserve(
                required,
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "access calibration interrupted after owned cleanup",
                )),
            );
        }
        if consumer_started && !consumer_settled {
            required = preserve(
                required,
                Err(io::Error::other(
                    "access consumer helper settlement unproved",
                )),
            );
        }
        if report["probe_execution_verified"] != true {
            required = preserve(
                required,
                Err(io::Error::other(
                    "ordinary RC calibration denial/restoration/cleanup not verified",
                )),
            );
        }
        if stop.as_ref().is_some_and(|stop| {
            !stop.stopped || stop.status != 0 || stop.disable_status != 0 || stop.late
        }) {
            required = preserve(
                required,
                Err(io::Error::other(
                    "owned access session cleanup failed or exceeded original cutoff",
                )),
            );
        }
        if consumer.is_some() {
            required = preserve(required, Err(io::Error::other("consumer owner remains")));
        }
        let publication = (|| -> io::Result<()> {
            let bytes = serde_json::to_vec(&report).map_err(io::Error::other)?;
            if bytes.len() + 1 > STREAM_BYTES {
                return Err(io::Error::other("calibration report exceeds bound"));
            }
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(output)?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()
        })();
        let _ = writeln!(
            io::stderr().lock(),
            "[access-failure calibration] execution={}; coverage_validated={}; report={}",
            report["probe_execution_verified"],
            report["coverage_validated"],
            output.display()
        );
        preserve(required, publication)
    }
}

#[cfg(windows)]
pub use native::{calibration_stdio, collect, consumer_stdio};
