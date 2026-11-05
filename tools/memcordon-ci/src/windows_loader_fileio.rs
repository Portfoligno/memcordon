//! Optional, owned FileIo observation; never positive workload authority.
use memcordon_platform::windows_fileio_record::{ConsumerSpec, Observation, Window};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io;

pub const CONFIG_BYTES: usize = 8 * 1024;
pub const RECORD_BYTES: usize = 64 * 1024;
pub const STREAM_BYTES: usize = CONFIG_BYTES + RECORD_BYTES + 2;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    format: String,
    version: u32,
    ready: bool,
    error: Option<String>,
    spec: ConsumerSpec,
}

#[cfg(windows)]
fn detail(error: impl std::fmt::Display) -> String {
    error.to_string().chars().take(1024).collect()
}

fn readiness(bytes: &[u8]) -> io::Result<Option<Ready>> {
    let Some(end) = bytes.iter().position(|byte| *byte == b'\n') else {
        return if bytes.len() > CONFIG_BYTES {
            Err(io::Error::other("FileIo readiness frame exceeds bound"))
        } else {
            Ok(None)
        };
    };
    if end > CONFIG_BYTES {
        return Err(io::Error::other("FileIo readiness frame exceeds bound"));
    }
    let ready: Ready = serde_json::from_slice(&bytes[..end]).map_err(io::Error::other)?;
    if ready.format != "memcordon.fileio-consumer-ready" || ready.version != 1 {
        return Err(io::Error::other("FileIo readiness format differs"));
    }
    Ok(Some(ready))
}

pub fn decode_output(bytes: &[u8], expected: &ConsumerSpec) -> io::Result<Observation> {
    if bytes.len() > STREAM_BYTES {
        return Err(io::Error::other("FileIo consumer stream exceeds bound"));
    }
    let ready = readiness(bytes)?
        .filter(|value| value.ready)
        .ok_or_else(|| io::Error::other("FileIo consumer was not ready"))?;
    if ready.error.is_some() {
        return Err(io::Error::other("FileIo readiness contradicts its error"));
    }
    if &ready.spec != expected {
        return Err(io::Error::other("FileIo readiness session binding differs"));
    }
    let start = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let body = &bytes[start..];
    if body.len() > RECORD_BYTES + 1 {
        return Err(io::Error::other("FileIo observation frame exceeds bound"));
    }
    let observation: Observation = serde_json::from_slice(body).map_err(io::Error::other)?;
    observation.validate().map_err(io::Error::other)?;
    if &observation.spec != expected {
        return Err(io::Error::other("FileIo consumer session binding differs"));
    }
    Ok(observation)
}

/// Extract only actual, retained original-call windows from the bound sidecar.
pub fn listener_windows(bytes: &[u8], expected: &ConsumerSpec) -> io::Result<(u32, Vec<Window>)> {
    if bytes.len() > RECORD_BYTES {
        return Err(io::Error::other("original listener carrier exceeds bound"));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    let binding = &value["original_binding"];
    let trace = &value["trace"];
    if value["format"] != "memcordon.original-rust-listener-trace"
        || value["revision"] != 1
        || binding["pid"] != expected.pid
        || binding["creation_time_100ns"] != expected.birth
        || binding["descriptor_sha256"] != json!(expected.binding.descriptor_sha256)
        || binding["challenge_sha256"] != json!(expected.binding.challenge_sha256)
        || binding["cutoff_qpc"] != expected.binding.cutoff_qpc
        || binding["qpc_frequency"] != expected.binding.frequency
        || trace["packet_version"] != 4
        || trace["invalid_packet"] != false
        || trace["frequency"] != expected.binding.frequency
        || trace["cutoff_qpc"] != expected.binding.cutoff_qpc
        || trace["loader_owner"]["version"] != 2
        || trace["loader_owner"]["invalid_scope"] != false
    {
        return Err(io::Error::other(
            "original FileIo/listener binding is unavailable",
        ));
    }
    let thread = trace["original_thread"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| io::Error::other("original listener thread unavailable"))?;
    let scope = &trace["loader_owner"];
    let recent = scope["windows"]
        .as_array()
        .filter(|values| values.len() <= 16)
        .ok_or_else(|| io::Error::other("original loader windows unavailable"))?;
    let mut windows = Vec::with_capacity(17);
    let first = scope
        .get("first_failure_window")
        .filter(|value| !value.is_null());
    for value in first.into_iter().chain(recent.iter()) {
        if value["namespace"] != "loader_owner"
            || value["operation"] != "LdrLoadDll"
            || value["clock_domain"] != "original-QPC"
            || value["thread_id"] != thread
            || value["invalid_window"] != false
            || value["observation_incomplete"] != false
        {
            continue;
        }
        let read = |name| {
            value[name]
                .as_u64()
                .ok_or_else(|| io::Error::other("original loader window field unavailable"))
        };
        let window = Window {
            dependency_sequence: read("dependency_sequence")?,
            loader_dependency_sequence: read("loader_dependency_sequence")?,
            parent_listener_sequence: read("parent_listener_sequence")?,
            started_qpc: read("started_qpc")?,
            finished_qpc: read("finished_qpc")?,
        };
        if window.dependency_sequence == 0
            || window.loader_dependency_sequence == 0
            || window.parent_listener_sequence == 0
            || window.started_qpc == 0
            || window.finished_qpc < window.started_qpc
            || window.finished_qpc >= expected.binding.cutoff_qpc
        {
            continue;
        }
        if !windows.iter().any(|prior: &Window| {
            prior.dependency_sequence == window.dependency_sequence
                && prior.loader_dependency_sequence == window.loader_dependency_sequence
                && prior.parent_listener_sequence == window.parent_listener_sequence
                && prior.started_qpc == window.started_qpc
                && prior.finished_qpc == window.finished_qpc
        }) {
            windows.push(window);
        }
    }
    Ok((thread, windows))
}

#[cfg(windows)]
mod native {
    use super::*;
    use memcordon_platform::test_support::windows_fileio::{
        OwnedFileIoSession, PreparedFileIoSession,
    };
    use memcordon_platform::windows_fileio_record::StopRecord;
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    #[derive(Default)]
    pub struct Captured {
        pub spec: Option<ConsumerSpec>,
        pub ready: bool,
        pub stop: Option<StopRecord>,
        pub helper_settled: bool,
        pub error: Option<String>,
        pub observation: Option<Observation>,
    }
    pub type Shared = Arc<Mutex<Captured>>;

    fn update(state: &Shared, write: impl FnOnce(&mut Captured)) {
        match state.lock() {
            Ok(mut state) => write(&mut state),
            Err(poisoned) => write(&mut poisoned.into_inner()),
        }
    }

    pub fn unavailable(state: &Shared, error: impl std::fmt::Display) {
        update(state, |state| state.error = Some(detail(error)));
    }

    pub struct Capture {
        session: Option<OwnedFileIoSession>,
        stop_callback: Option<mpsc::Sender<()>>,
        worker: Option<JoinHandle<()>>,
        abort_helper: Arc<AtomicBool>,
        state: Shared,
    }
    pub type OwnedCapture = Arc<Mutex<Option<Capture>>>;
    struct CallbackGuard(OwnedCapture);
    impl Drop for CallbackGuard {
        fn drop(&mut self) {
            stop_collection(&self.0);
        }
    }
    pub fn callback_guard(owner: OwnedCapture) -> impl Drop + Send {
        CallbackGuard(owner)
    }
    pub fn stop_collection(owner: &OwnedCapture) {
        let mut owner = owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(capture) = owner.as_mut() {
            capture.stop_collection();
        }
    }
    pub fn finish(owner: &OwnedCapture) {
        let capture = owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(mut capture) = capture {
            capture.finish();
        }
    }
    impl Capture {
        pub fn begin(
            prepared: PreparedFileIoSession,
            work: Instant,
            cleanup: Instant,
            state: Shared,
        ) -> Self {
            let mut owned = Self {
                session: None,
                stop_callback: None,
                worker: None,
                abort_helper: Arc::new(AtomicBool::new(false)),
                state,
            };
            let session = match prepared.start() {
                Ok(value) => value,
                Err(error) => {
                    unavailable(&owned.state, error);
                    return owned;
                }
            };
            let spec = session.consumer_spec().clone();
            update(&owned.state, |state| state.spec = Some(spec.clone()));
            owned.session = Some(session);
            let command = (|| -> io::Result<Command> {
                let mut command = Command::new(std::env::current_exe()?);
                command.arg("loader-fileio-consumer").stdin(Stdio::piped());
                Ok(command)
            })();
            let command = match command {
                Ok(value) => value,
                Err(error) => {
                    unavailable(&owned.state, error);
                    owned.stop_collection();
                    return owned;
                }
            };
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let (stop_tx, stop_rx) = mpsc::channel();
            let result_state = Arc::clone(&owned.state);
            let expected = spec.clone();
            let abort = Arc::clone(&owned.abort_helper);
            let worker = thread::Builder::new()
                .name("owned-fileio-consumer".into())
                .spawn(move || {
                    let output =
                        memcordon_testkit::run_until_owned_spawn_with_io_controlled_output_limit(
                            command,
                            cleanup,
                            STREAM_BYTES,
                            Some(abort),
                            |mut command| command.spawn(),
                            move |_, input, snapshot| {
                                let prepared = (|| -> io::Result<()> {
                                    let bytes =
                                        serde_json::to_vec(&spec).map_err(io::Error::other)?;
                                    if bytes.len() > CONFIG_BYTES {
                                        return Err(io::Error::other("FileIo setup exceeds bound"));
                                    }
                                    let mut input = input.ok_or_else(|| {
                                        io::Error::other("FileIo setup pipe absent")
                                    })?;
                                    input.write_all(&bytes)?;
                                    drop(input);
                                    loop {
                                        if Instant::now() >= work {
                                            return Err(io::Error::new(
                                                io::ErrorKind::TimedOut,
                                                "original FileIo setup cutoff",
                                            ));
                                        }
                                        if let Some(value) = readiness(&snapshot.stdout()?)? {
                                            return if value.ready
                                                && value.error.is_none()
                                                && value.spec == spec
                                            {
                                                Ok(())
                                            } else {
                                                Err(io::Error::other(value.error.unwrap_or_else(
                                                    || "FileIo consumer unavailable".into(),
                                                )))
                                            };
                                        }
                                        thread::sleep(Duration::from_millis(10));
                                    }
                                })();
                                let _ =
                                    ready_tx.send(prepared.as_ref().map(|_| ()).map_err(detail));
                                prepared?;
                                let _ = stop_rx.recv_timeout(
                                    cleanup.saturating_duration_since(Instant::now()),
                                );
                                Ok(())
                            },
                        );
                    match output {
                        Ok(output) => update(&result_state, |state| {
                            state.helper_settled = true;
                            match decode_output(&output.stdout, &expected) {
                                Ok(value) => state.observation = Some(value),
                                Err(error) => state.error = Some(detail(error)),
                            }
                        }),
                        Err(error) => update(&result_state, |state| {
                            // The testkit reports unproved cleanup explicitly;
                            // an error alone never establishes helper settlement.
                            state.error = Some(detail(error));
                            state.helper_settled = false;
                        }),
                    }
                });
            match worker {
                Ok(worker) => {
                    owned.stop_callback = Some(stop_tx);
                    owned.worker = Some(worker);
                    match ready_rx.recv_timeout(work.saturating_duration_since(Instant::now())) {
                        Ok(Ok(())) => update(&owned.state, |state| state.ready = true),
                        Ok(Err(error)) => {
                            unavailable(&owned.state, error);
                            owned.abort_helper.store(true, Ordering::Release);
                            owned.stop_collection();
                        }
                        Err(error) => {
                            unavailable(&owned.state, error);
                            owned.abort_helper.store(true, Ordering::Release);
                            owned.stop_collection();
                        }
                    }
                }
                Err(error) => {
                    unavailable(&owned.state, error);
                    owned.stop_collection();
                }
            }
            owned
        }

        fn stop_collection(&mut self) {
            if let Some(mut session) = self.session.take() {
                let stopped = session.stop();
                if !stopped.stopped {
                    self.abort_helper.store(true, Ordering::Release);
                }
                update(&self.state, |state| state.stop = Some(stopped));
            }
            if let Some(stop) = self.stop_callback.take() {
                let _ = stop.send(());
            }
        }
        pub fn finish(&mut self) {
            self.stop_collection();
            if self
                .worker
                .take()
                .is_some_and(|worker| worker.join().is_err())
            {
                unavailable(
                    &self.state,
                    "FileIo helper supervisor panicked; settlement unproved",
                );
            }
        }
    }
    impl Drop for Capture {
        fn drop(&mut self) {
            self.finish();
        }
    }

    pub fn consume_stdio() -> io::Result<()> {
        let mut bytes = Vec::new();
        io::stdin()
            .lock()
            .take((CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > CONFIG_BYTES {
            return Err(io::Error::other("FileIo setup exceeds bound"));
        }
        let spec: ConsumerSpec = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        spec.validate().map_err(io::Error::other)?;
        let observation =
            memcordon_platform::test_support::windows_fileio::consume(&spec, |result| {
                let record = Ready {
                    format: "memcordon.fileio-consumer-ready".into(),
                    version: 1,
                    ready: result.is_ok(),
                    error: result.as_ref().err().map(detail),
                    spec: spec.clone(),
                };
                let mut output = io::stdout().lock();
                serde_json::to_writer(&mut output, &record).map_err(io::Error::other)?;
                output.write_all(b"\n")?;
                output.flush()
            })?;
        let bytes = serde_json::to_vec(&observation).map_err(io::Error::other)?;
        if bytes.len() > RECORD_BYTES {
            return Err(io::Error::other("FileIo observation exceeds bound"));
        }
        let mut output = io::stdout().lock();
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        output.flush()
    }

    pub fn record(state: &Shared, listener: io::Result<Vec<u8>>) -> Value {
        let state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut value = json!({"format":"memcordon.original-loader-fileio","revision":1,"diagnostic_only":true,"acceptance_authority":false,"global_routes_complete":false,"denied_object_proved":false,"spec":state.spec,"ready":state.ready,"stop":state.stop,"helper_settled":state.helper_settled,"error":state.error});
        value["observation"] = match (&state.spec, &state.observation, listener) {
            (Some(spec), Some(observation), Ok(bytes)) => {
                value["listener_sha256"] = json!(hex::encode(sha2::Sha256::digest(&bytes)));
                let loss_free = state.helper_settled
                    && observation.consumer_completed
                    && observation.process_trace_status == 0
                    && observation.close_trace_status == 0
                    && !observation.cutoff_reached
                    && state.stop.as_ref().is_some_and(|stop| {
                        stop.stopped
                            && stop.events_lost == 0
                            && stop.log_buffers_lost == 0
                            && stop.realtime_buffers_lost == 0
                    });
                if !loss_free {
                    json!({"state":"incomplete-unassociated","reason":"session loss, cutoff or consumer retirement is unproved","counters":observation.counters,"candidate_records":observation.rows,"acceptance_authority":false,"global_routes_complete":false,"denied_object_proved":false})
                } else {
                    match listener_windows(&bytes, spec) {
                        Ok((thread, windows)) => {
                            memcordon_platform::windows_fileio_record::correlate(
                                observation,
                                spec,
                                thread,
                                &windows,
                            )
                        }
                        Err(error) => {
                            json!({"state":"unavailable","error":detail(error),"acceptance_authority":false})
                        }
                    }
                }
            }
            (_, _, Err(error)) => {
                json!({"state":"unavailable","error":detail(error),"acceptance_authority":false})
            }
            _ => {
                json!({"state":"unavailable","error":"consumer/session observation unavailable","acceptance_authority":false})
            }
        };
        if serde_json::to_vec(&value).map_or(true, |bytes| bytes.len() > RECORD_BYTES) {
            value["observation"] =
                json!({"state":"omitted-for-envelope-bound","acceptance_authority":false});
        }
        value
    }
    use sha2::Digest;
}

#[cfg(windows)]
pub use native::{
    Capture, Captured, OwnedCapture, Shared, callback_guard, consume_stdio, finish, record,
    stop_collection, unavailable,
};
