//! The bootstrap parent owns recording independently of the inventory child.
use super::super::bounded;
use super::{Recording, WprOperation, copy_bounded};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

#[path = "ci-trace-volume.rs"]
mod volume;

const COMMAND_BUDGET: Duration = Duration::from_secs(30);
const EXPORT_LIMIT: u64 = 512 * 1024 * 1024;
const LOG_LIMIT: u64 = 65536;

type Configure = fn(&mut Command, &BTreeMap<OsString, OsString>, Option<&Path>);

/// Run the production volume path before any expensive inventory. The parent
/// contains every synchronous native operation and retains its exact outcome.
pub fn qualify_volume(
    workspace: &Path,
    output: &Path,
    environment: &BTreeMap<OsString, OsString>,
    configure: Configure,
) -> io::Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--internal-trace-volume-qualification")
        .arg(workspace)
        .arg(output)
        .current_dir(workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure(&mut command, environment, None);
    let completion = bounded::auxiliary(&mut command, COMMAND_BUDGET);
    fs::write(
        output.join("phase-volume-qualification-parent.json"),
        format!(
            "{{\"schema\":1,\"inventory_admission\":false,\"result\":{}}}\n",
            match &completion {
                Ok(value) => bounded::completion_json(value),
                Err(error) => bounded::error_json(error),
            }
        ),
    )?;
    completion?.result()
}

pub fn qualify_volume_worker(
    workspace: &Path,
    output: &Path,
    configure: Configure,
) -> io::Result<()> {
    let mut worker = Worker::new(
        workspace,
        output,
        &std::env::vars_os().collect(),
        configure,
        OsString::new(),
    );
    let result = (|| {
        worker.volume = Some(worker.provision_volume()?);
        worker
            .volume
            .as_ref()
            .expect("provisioned volume")
            .verify_write_read()
    })();
    worker.observe("volume_qualification", &result);
    let cleanup = worker.detach();
    worker.observe("volume_qualification_cleanup", &cleanup);
    result.and(cleanup)
}

pub struct Session {
    workspace: PathBuf,
    output: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    configure: Configure,
    instance: String,
    child: Option<bounded::AuxiliaryProcess>,
    cleanup_attempted: bool,
    events: Vec<String>,
}
impl Session {
    pub fn new(
        workspace: &Path,
        output: &Path,
        environment: &BTreeMap<OsString, OsString>,
        configure: Configure,
    ) -> Self {
        Self {
            workspace: workspace.into(),
            output: output.into(),
            environment: environment.clone(),
            configure,
            instance: String::new(),
            child: None,
            cleanup_attempted: false,
            events: Vec::new(),
        }
    }
}
impl Recording for Session {
    fn start(&mut self) -> io::Result<()> {
        #[link(name = "bcrypt")]
        unsafe extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut std::ffi::c_void,
                buffer: *mut u8,
                length: u32,
                flags: u32,
            ) -> i32;
        }
        let mut random = [0_u8; 16];
        // System-preferred RNG; the instance is known before helper creation.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                random.as_mut_ptr(),
                random.len() as u32,
                2,
            )
        };
        if status < 0 {
            return Err(io::Error::other(format!(
                "recorder identity RNG failed: {status}"
            )));
        }
        self.instance = format!(
            "memcordon-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--internal-inventory-trace-worker")
            .arg(&self.workspace)
            .arg(&self.output)
            .arg(&self.instance)
            .current_dir(&self.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        (self.configure)(&mut command, &self.environment, None);
        self.child = Some(bounded::AuxiliaryProcess::spawn(&mut command)?);
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() >= COMMAND_BUDGET {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recorder readiness deadline",
                ));
            }
            if let Some(status) = self.child.as_mut().expect("spawned recorder").status()? {
                return Err(io::Error::other(format!(
                    "recorder exited before readiness: {status}"
                )));
            }
            if super::ready(&self.output.join("trace-ready"), self.instance.as_bytes())? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn finish(&mut self) -> io::Result<()> {
        super::signal(&self.output.join("trace-finish"), self.instance.as_bytes())?;
        let completion = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("recorder absent"))?
            .wait(COMMAND_BUDGET * 4);
        self.events.push(format!(
            "{{\"command\":\"recorder_finish\",\"completion\":{}}}",
            bounded::completion_json(&completion)
        ));
        completion.result()
    }
    fn cancel(&mut self) -> io::Result<()> {
        if self.cleanup_attempted {
            return Ok(());
        }
        self.cleanup_attempted = true;
        let termination = self
            .child
            .as_mut()
            .map_or(Ok(()), bounded::AuxiliaryProcess::terminate);
        // The helper may have started WPR before readiness. Cancel only the
        // independently generated name, even after helper termination.
        let cancellation = if self.instance.is_empty() {
            Ok(())
        } else {
            let system = self
                .environment
                .get(OsStr::new("SystemRoot"))
                .ok_or_else(|| io::Error::other("SystemRoot unavailable"))?;
            let mut command = Command::new(Path::new(system).join("System32/wpr.exe"));
            let invocation =
                WprOperation::Cancel.invocation(OsStr::new(&self.instance), &self.output)?;
            command
                .args(invocation.arguments())
                // The helper's owned VHD is released when helper termination is
                // observed. Keep fallback WPR artifacts in the bounded journal,
                // never in the measured workspace.
                .current_dir(invocation.working_directory())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            (self.configure)(&mut command, &self.environment, None);
            let result = bounded::auxiliary(&mut command, COMMAND_BUDGET);
            self.events.push(format!(
                "{{\"command\":\"fallback_cancel\",\"result\":{}}}",
                match &result {
                    Ok(completion) => bounded::completion_json(completion),
                    Err(error) => bounded::error_json(error),
                }
            ));
            result.and_then(|completion| completion.result())
        };
        termination.and(cancellation)
    }
    fn observe(&mut self, phase: &str, result: &io::Result<()>) {
        self.events.push(format!(
            "{{\"phase\":{},\"error\":{}}}",
            bounded::json_string(phase),
            result
                .as_ref()
                .err()
                .map_or("null".into(), bounded::error_json)
        ));
        let document = format!(
            "{{\"schema\":1,\"diagnostic_only\":true,\"instance\":{},\"events\":[{}]}}\n",
            bounded::json_string(&self.instance),
            self.events.join(",")
        );
        if document.len() <= LOG_LIMIT as usize {
            let _ = fs::write(self.output.join("phase-trace-supervisor.json"), document);
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if self.child.is_some() && !self.cleanup_attempted {
            // A successful worker has already canceled/stopped and detached.
            if self
                .child
                .as_mut()
                .is_some_and(|child| matches!(child.status(), Ok(Some(status)) if status.success()))
            {
                return;
            }
            let result = self.cancel();
            self.observe("drop_cancel", &result);
        }
    }
}

pub fn worker(
    workspace: &Path,
    output: &Path,
    instance: &OsStr,
    configure: Configure,
) -> io::Result<()> {
    let instance = instance
        .to_str()
        .ok_or_else(|| io::Error::other("invalid recorder identity"))?;
    if !instance.starts_with("memcordon-") || instance.len() > 128 {
        return Err(io::Error::other("invalid recorder identity"));
    }
    let mut worker = Worker::new(
        workspace,
        output,
        &std::env::vars_os().collect(),
        configure,
        instance.into(),
    );
    let start = worker.start();
    worker.observe("start", &start);
    if let Err(error) = start {
        let cleanup = worker.cancel();
        worker.observe("cancel", &cleanup);
        return Err(error);
    }
    let result = (|| {
        super::signal(&output.join("trace-ready"), instance.as_bytes())?;
        let start = std::time::Instant::now();
        loop {
            if start.elapsed()
                >= bounded::CHILD_BUDGET + bounded::TERMINATION_BUDGET + COMMAND_BUDGET
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recorder finish signal deadline",
                ));
            }
            if super::ready(&output.join("trace-finish"), instance.as_bytes())? {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        worker.finish()
    })();
    worker.observe("finish", &result);
    if result.is_err() {
        let cleanup = worker.cancel();
        worker.observe("cancel", &cleanup);
    }
    result
}

struct Worker {
    workspace: PathBuf,
    output: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    configure: Configure,
    volume: Option<volume::Volume>,
    wpr: Option<PathBuf>,
    instance: OsString,
    active: bool,
    cleanup_attempted: bool,
    events: Vec<String>,
}
impl Worker {
    fn new(
        workspace: &Path,
        output: &Path,
        environment: &BTreeMap<OsString, OsString>,
        configure: Configure,
        instance: OsString,
    ) -> Self {
        Self {
            workspace: workspace.into(),
            output: output.into(),
            environment: environment.clone(),
            configure,
            volume: None,
            wpr: None,
            instance,
            active: false,
            cleanup_attempted: false,
            events: Vec::new(),
        }
    }
    fn invoke(&mut self, operation: WprOperation) -> io::Result<()> {
        let label = operation.label();
        let directory = self
            .volume
            .as_ref()
            .ok_or_else(|| io::Error::other("trace volume absent"))?
            .directory();
        let invocation = operation.invocation(&self.instance, directory)?;
        let log_path = directory.join(label).with_extension("log");
        let log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&log_path)?;
        let mut command = Command::new(
            self.wpr
                .as_ref()
                .ok_or_else(|| io::Error::other("WPR absent"))?,
        );
        command
            .args(invocation.arguments())
            // WPR can leave a partial `.etl` beside its current directory when
            // export fails (for example, after exhausting the bounded volume).
            // Keep every recorder-created path on the owned volume so optional
            // diagnostics cannot mutate the measured workspace.
            .current_dir(invocation.working_directory())
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        (self.configure)(&mut command, &self.environment, Some(directory));
        let result = bounded::auxiliary(&mut command, COMMAND_BUDGET);
        // Logs consume only bounded volume space during execution. Retain a
        // bounded prefix outside that volume before it is detached.
        let retained = self
            .output
            .join("inventory-wpr")
            .with_file_name(format!("inventory-wpr-{label}.log"));
        let log_truncated = fs::metadata(&log_path).map(|metadata| metadata.len() > LOG_LIMIT);
        let log_result = copy_bounded(&log_path, &retained, LOG_LIMIT, false);
        self.events.push(format!(
            "{{\"command\":{},\"result\":{},\"log_truncated\":{},\"log_error\":{}}}",
            bounded::json_string(label),
            match &result {
                Ok(value) => bounded::completion_json(value),
                Err(error) => bounded::error_json(error),
            },
            log_truncated.map_or("null".into(), |value| value.to_string()),
            log_result
                .as_ref()
                .err()
                .map_or("null".into(), bounded::error_json)
        ));
        result?.result()
    }
    fn provision_volume(&mut self) -> io::Result<volume::Volume> {
        let system = Path::new(
            self.environment
                .get(OsStr::new("SystemRoot"))
                .ok_or_else(|| io::Error::other("SystemRoot unavailable"))?,
        )
        .join("System32");
        let environment = self.environment.clone();
        volume::Volume::create(
            &self.output.join("trace-volume"),
            &system.join("format.com"),
            |command| {
                command.stdin(Stdio::null());
                (self.configure)(command, &environment, None);
                let result = bounded::auxiliary_capture(command, COMMAND_BUDGET);
                match result {
                    Ok(capture) => {
                        self.events
                            .push(bounded::retain_capture(&self.output, "format", &capture));
                        self.observe("format_completed", &Ok(()));
                        capture.completion.result()
                    }
                    Err(error) => {
                        self.events.push(format!(
                            "{{\"command\":\"format\",\"spawn_error\":{}}}",
                            bounded::error_json(&error)
                        ));
                        self.observe(
                            "format_spawn_failed",
                            &Err(io::Error::new(error.kind(), error.to_string())),
                        );
                        Err(error)
                    }
                }
            },
        )
    }

    fn detach(&mut self) -> io::Result<()> {
        if let Some(volume) = self.volume.take() {
            volume.close()
        } else {
            Ok(())
        }
    }
}
impl Recording for Worker {
    fn start(&mut self) -> io::Result<()> {
        let system_root = self
            .environment
            .get(OsStr::new("SystemRoot"))
            .ok_or_else(|| io::Error::other("SystemRoot unavailable for WPR"))?;
        let system = Path::new(system_root).join("System32");
        let wpr = fs::canonicalize(system.join("wpr.exe"))?;
        let profile = self.workspace.join("ci/inventory.wprp");
        let profile_digest = bounded::sha256::digest(&mut File::open(&profile)?)?;
        if profile_digest
            != bounded::sha256::digest(&mut &include_bytes!("../ci/inventory.wprp")[..])?
        {
            return Err(io::Error::other(
                "WPR profile differs from compiled recording recipe",
            ));
        }
        let wpr_digest = bounded::sha256::digest(&mut File::open(&wpr)?)?;
        let owned = self.provision_volume()?;
        let directory = owned.directory().to_path_buf();
        self.events.push(format!("{{\"profile_sha256\":{},\"wpr_sha256\":{},\"instance\":{},\"coverage\":\"rolling_memory_window\",\"buffer_budget_bytes\":50331648}}",
            bounded::json_string(&profile_digest), bounded::json_string(&wpr_digest), bounded::json_string(&self.instance.to_string_lossy())));
        self.volume = Some(owned);
        self.wpr = Some(wpr);
        // Publish the owned instance before start; ambiguous start is canceled
        // using only this unique name, never a global WPR cancellation.
        self.observe("prepared", &Ok(()));
        self.active = true;
        self.invoke(WprOperation::Start(directory))
    }
    fn finish(&mut self) -> io::Result<()> {
        let status = self.invoke(WprOperation::Status);
        let trace = self
            .volume
            .as_ref()
            .ok_or_else(|| io::Error::other("trace volume absent"))?
            .directory()
            .join("inventory.etl");
        self.invoke(WprOperation::Stop(trace.clone()))?;
        self.active = false;
        let destination = self.output.join("inventory-trace.etl");
        let provisional = self.output.join("inventory-trace.partial");
        let bytes = copy_bounded(&trace, &provisional, EXPORT_LIMIT, true)?;
        let digest = bounded::sha256::digest(&mut File::open(&provisional)?)?;
        fs::hard_link(&provisional, &destination)?;
        let _ = fs::remove_file(&provisional);
        self.events.push(format!(
            "{{\"trace_bytes\":{bytes},\"trace_sha256\":{},\"loss_evidence\":{}}}",
            bounded::json_string(&digest),
            bounded::json_string(if status.is_ok() {
                "inspect retained collector status and ETL"
            } else {
                "collector status unavailable; do not infer complete coverage"
            })
        ));
        let detach = self.detach();
        status?;
        detach
    }
    fn cancel(&mut self) -> io::Result<()> {
        let cancel = if self.active && !self.cleanup_attempted {
            self.cleanup_attempted = true;
            let result = self.invoke(WprOperation::Cancel);
            if result.is_ok() {
                self.active = false;
            }
            result
        } else {
            Ok(())
        };
        let detach = self.detach();
        cancel?;
        detach
    }
    fn observe(&mut self, phase: &str, result: &io::Result<()>) {
        self.events.push(format!(
            "{{\"phase\":{},\"error\":{}}}",
            bounded::json_string(phase),
            result
                .as_ref()
                .err()
                .map_or("null".into(), bounded::error_json)
        ));
        let document = format!(
            "{{\"schema\":1,\"diagnostic_only\":true,\"session_may_be_active\":{},\"events\":[{}]}}\n",
            self.active,
            self.events.join(",")
        );
        if document.len() <= LOG_LIMIT as usize {
            // Optional evidence cannot replace the already-authoritative child
            // result or block on a synchronous stderr fallback.
            let _ = fs::write(self.output.join("phase-trace.json"), document);
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if self.active && !self.cleanup_attempted {
            let result = self.cancel();
            self.observe("drop_cancel", &result);
        }
    }
}
