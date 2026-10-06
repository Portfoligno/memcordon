//! Owned real publisher processes, independent content assertions and bounded diagnostics.
use super::{
    cases::{self, Case},
    protocol::*,
};
use crate::{
    CiError, Result,
    release::{
        artifacts, http,
        publish::{PublicationSummary, RemoteState},
        rehearsal::{LoopbackTransport, TransactionResult, unix_ms},
        rehearsal_input::RehearsalInput,
    },
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const PROCESS_OUTPUT: usize = 1024 * 1024;
fn failure(message: &str) -> CiError {
    CiError::Message(message.into())
}

pub fn sanitize_child(command: &mut Command) {
    for name in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_CACHE_URL",
        "ACTIONS_RUNTIME_URL",
        "ACTIONS_RESULTS_URL",
    ] {
        command.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("CARGO_REGISTRIES_") && name.ends_with("_TOKEN"))
        {
            command.env_remove(name);
        }
    }
}

struct Server {
    child: Child,
    input: std::process::ChildStdin,
    events: Arc<Mutex<mpsc::Receiver<ControlEvent>>>,
    readers: Vec<thread::JoinHandle<()>>,
    settled: bool,
    retirement: Instant,
    settlement: PathBuf,
}
impl Server {
    fn start(
        helper: &Path,
        case: &Case,
        state: &Path,
        ready: &Path,
        retirement: Instant,
    ) -> Result<Self> {
        let settlement = state.join("server-settled.json");
        if settlement.exists() {
            fs::remove_file(&settlement)?;
        }
        let mut command = Command::new(helper);
        command
            .args(["serve", "--case"])
            .arg(&case.variant)
            .arg("--state")
            .arg(state)
            .arg("--ready")
            .arg(ready);
        sanitize_child(&mut command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| failure("fixture input missing"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| failure("fixture event stream missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| failure("fixture diagnostic stream missing"))?;
        let (sender, receiver) = mpsc::sync_channel(64);
        let events = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match reader.by_ref().take(4097).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line.len() > 4096 => break,
                    Ok(_) => {
                        if let Ok(event) = serde_json::from_slice::<ControlEvent>(&line) {
                            match sender.try_send(event) {
                                Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
                                Err(mpsc::TrySendError::Disconnected(_)) => break,
                            }
                        }
                    }
                }
            }
        });
        let diagnostic_path = state.join("server.stderr.json");
        let diagnostics = thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut retained = Vec::new();
            let mut observed = 0_u64;
            let mut chunk = [0_u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        observed = observed.saturating_add(count as u64);
                        let available = PROCESS_OUTPUT.saturating_sub(retained.len());
                        retained.extend_from_slice(&chunk[..count.min(available)]);
                    }
                }
            }
            let value = serde_json::json!({"stderr":redact(&retained),"observed_bytes":observed,"truncated":observed>retained.len() as u64});
            if let Ok(bytes) = serde_json::to_vec(&value) {
                let _ = fs::write(diagnostic_path, bytes);
            }
        });
        Ok(Self {
            child,
            input,
            events: Arc::new(Mutex::new(receiver)),
            readers: vec![events, diagnostics],
            settled: false,
            retirement,
            settlement,
        })
    }
    fn stop(&mut self) -> Result<()> {
        if self.settled {
            return Ok(());
        }
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        let terminal = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= self.retirement {
                return Err(failure("fixture termination remained unobserved"));
            }
            thread::sleep(Duration::from_millis(5));
        };
        for reader in self.readers.drain(..) {
            while !reader.is_finished() {
                if Instant::now() >= self.retirement {
                    return Err(failure("fixture reader settlement remained unobserved"));
                }
                thread::sleep(Duration::from_millis(5));
            }
            reader
                .join()
                .map_err(|_| failure("fixture reader failed"))?;
        }
        fs::write(
            &self.settlement,
            serde_json::to_vec(
                &serde_json::json!({"settled":true,"status":format!("{terminal:?}")}),
            )?,
        )?;
        self.settled = true;
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("fixture cleanup failed: {error}");
        }
    }
}

#[derive(Serialize)]
struct CaseResult {
    group: String,
    variant: String,
    complete: bool,
    fault_reached: bool,
    publisher_terminated: bool,
    requests: usize,
    effects: usize,
    cleanup: bool,
    error: Option<String>,
}
#[derive(Serialize)]
struct Report {
    revision: u32,
    kind: String,
    version: String,
    commit: String,
    notes_placeholder: bool,
    publisher_sha256: String,
    payloads: Vec<ExpectedFile>,
    cases: Vec<CaseResult>,
    complete: bool,
    cleanup: bool,
    unexecuted: usize,
}
fn write_report(path: &Path, report: &Report) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report)?;
    if bytes.len() > 1024 * 1024 {
        return Err(failure("rehearsal summary exceeds bound"));
    }
    fs::write(path, bytes)?;
    Ok(())
}
fn snapshot(state: &Path) -> Result<Snapshot> {
    read_json(&state.join("snapshot.json"), 4 * 1024 * 1024)
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path, maximum: u64) -> Result<T> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(failure("fixture record exceeds bound"));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn wait_ready(
    ready: &Path,
    server: &mut Server,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<FixtureRecord> {
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Err(failure("rehearsal cancelled"));
        }
        if ready.is_file() {
            return read_json(ready, 16 * 1024);
        }
        if server.child.try_wait()?.is_some() {
            return Err(failure("fixture exited before readiness"));
        }
        if Instant::now() >= deadline {
            return Err(failure("fixture readiness deadline expired"));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn publisher(
    publisher: &Path,
    input: &Path,
    record: &Path,
    result: &Path,
    deadline: Instant,
    events: Option<Arc<Mutex<mpsc::Receiver<ControlEvent>>>>,
    cancelled: Arc<AtomicBool>,
) -> Result<(bool, bool)> {
    publisher_observed(
        publisher, input, record, result, deadline, events, cancelled, None,
    )
}
fn publisher_observed(
    publisher: &Path,
    input: &Path,
    record: &Path,
    result: &Path,
    deadline: Instant,
    events: Option<Arc<Mutex<mpsc::Receiver<ControlEvent>>>>,
    cancelled: Arc<AtomicBool>,
    identity_file: Option<PathBuf>,
) -> Result<(bool, bool)> {
    let mut command = Command::new(publisher);
    command
        .args(["release", "rehearsal-transaction", "--input"])
        .arg(input)
        .arg("--fixture")
        .arg(record)
        .arg("--result")
        .arg(result);
    sanitize_child(&mut command);
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| failure("case work deadline expired"))?;
    let reached = Arc::new(AtomicBool::new(false));
    let callback_reached = reached.clone();
    let observed = memcordon_testkit::run_with_deadline_after_output_limit(
        &mut command,
        remaining,
        PROCESS_OUTPUT,
        move |pid| {
            if let Some(path) = &identity_file {
                memcordon_platform::test_support::ProcessIdentity::for_pid(pid)?
                    .publish_to(path)?;
            }
            if let Some(events) = events {
                loop {
                    if cancelled.load(Ordering::SeqCst) {
                        return Err(std::io::Error::other("rehearsal cancelled"));
                    }
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(|| std::io::Error::other("effect barrier not reached"))?;
                    match events
                        .lock()
                        .map_err(|_| std::io::Error::other("event owner failed"))?
                        .recv_timeout(remaining.min(Duration::from_millis(100)))
                    {
                        Ok(event) if event.event == "committed" && event.barrier => {
                            callback_reached.store(true, Ordering::SeqCst);
                            #[cfg(unix)]
                            {
                                let pid = rustix::process::Pid::from_raw(
                                    i32::try_from(pid).map_err(std::io::Error::other)?,
                                )
                                .ok_or_else(|| std::io::Error::other("publisher PID invalid"))?;
                                rustix::process::kill_process(pid, rustix::process::Signal::KILL)
                                    .map_err(std::io::Error::other)?;
                            }
                            #[cfg(not(unix))]
                            {
                                let _ = pid;
                                return Err(std::io::Error::other(
                                    "barrier interruption requires Unix rehearsal runner",
                                ));
                            }
                            return Ok(());
                        }
                        Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(_) => {
                            return Err(std::io::Error::other("fixture barrier stream ended"));
                        }
                    }
                }
            }
            let identity = match memcordon_platform::test_support::ProcessIdentity::for_pid(pid) {
                Ok(identity) => identity,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            };
            while identity.still_exists()? {
                if cancelled.load(Ordering::SeqCst) {
                    #[cfg(unix)]
                    {
                        let owned = rustix::process::Pid::from_raw(
                            i32::try_from(pid).map_err(std::io::Error::other)?,
                        )
                        .ok_or_else(|| std::io::Error::other("publisher PID invalid"))?;
                        rustix::process::kill_process(owned, rustix::process::Signal::KILL)
                            .map_err(std::io::Error::other)?;
                    }
                    return Err(std::io::Error::other(
                        "rehearsal cancelled while publisher active",
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(std::io::Error::other("publisher callback deadline expired"));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        },
    );
    let observed = retain_process(&result.with_extension("process.json"), observed)?;
    Ok((observed.status.success(), reached.load(Ordering::SeqCst)))
}

pub fn cancellation_control(
    publisher: &Path,
    input: &Path,
    record: &Path,
    result: &Path,
    identity: &Path,
) -> Result<()> {
    let transport = LoopbackTransport::new(read_json(record, 16 * 1024)?)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    cancellation_listener(cancelled.clone())?;
    publisher_observed(
        publisher,
        input,
        record,
        result,
        transport.deadline()?,
        None,
        cancelled,
        Some(identity.to_owned()),
    )?;
    Err(failure(
        "cancellation control unexpectedly completed publication",
    ))
}
fn cancel_case(
    helper: &Path,
    publisher_path: &Path,
    input: &Path,
    ready: &Path,
    result: &Path,
    state: &Path,
    server: &Server,
    deadline: Instant,
) -> Result<()> {
    let identity = state.join("cancelled-publisher.json");
    let mut command = Command::new(helper);
    command
        .args(["cancellation-control", "--publisher"])
        .arg(publisher_path)
        .arg("--input")
        .arg(input)
        .arg("--fixture")
        .arg(ready)
        .arg("--result")
        .arg(result)
        .arg("--identity")
        .arg(&identity);
    sanitize_child(&mut command);
    let events = server.events.clone();
    let reached = Arc::new(AtomicBool::new(false));
    let callback_reached = reached.clone();
    let output = memcordon_testkit::run_with_deadline_after_output_limit(
        &mut command,
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| failure("cancellation case deadline expired"))?,
        PROCESS_OUTPUT,
        move |pid| {
            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or_else(|| std::io::Error::other("cancellation barrier absent"))?;
                let event = events
                    .lock()
                    .map_err(|_| std::io::Error::other("cancellation event owner failed"))?
                    .recv_timeout(remaining)
                    .map_err(std::io::Error::other)?;
                if event.event == "committed" && event.barrier {
                    #[cfg(unix)]
                    {
                        let owned = rustix::process::Pid::from_raw(
                            i32::try_from(pid).map_err(std::io::Error::other)?,
                        )
                        .ok_or_else(|| std::io::Error::other("controller PID invalid"))?;
                        rustix::process::kill_process(owned, rustix::process::Signal::TERM)
                            .map_err(std::io::Error::other)?;
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = pid;
                        return Err(std::io::Error::other(
                            "cancellation rehearsal requires Unix runner",
                        ));
                    }
                    callback_reached.store(true, Ordering::SeqCst);
                    return Ok(());
                }
            }
        },
    );
    let output = retain_process(&state.join("cancellation-controller.process.json"), output)?;
    if output.status.code() != Some(1)
        || !reached.load(Ordering::SeqCst)
        || !String::from_utf8_lossy(&output.stderr)
            .contains("rehearsal cancelled while publisher active")
    {
        return Err(failure(
            "actual coordinator cancellation failure was not observed",
        ));
    }
    let published = fs::read_to_string(&identity)?;
    let mut fields = published.split_whitespace();
    let identity = memcordon_platform::test_support::ProcessIdentity {
        pid: fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| failure("cancelled publisher PID absent"))?,
        birth: fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| failure("cancelled publisher birth absent"))?,
    };
    if fields.next().is_some() || identity.still_exists()? {
        return Err(failure("publisher survived coordinator cancellation"));
    }
    Ok(())
}

pub fn assert_complete(
    selection: &FixtureSelection,
    snapshot: &Snapshot,
    transport: &LoopbackTransport,
    summary: &PublicationSummary,
    deadline: Instant,
) -> Result<()> {
    if !summary.complete
        || snapshot.credential_errors != 0
        || snapshot.max_active_reads > 4
        || snapshot.max_active_connections > 8
        || snapshot.max_active_writes > 1
    {
        return Err(failure(
            "independent publication completion/resource oracle failed",
        ));
    }
    let expected_downloads = selection.files.len()
        + selection
            .files
            .iter()
            .filter(|file| file.package.is_some())
            .count();
    if snapshot.body_downloads
        < u64::try_from(expected_downloads)
            .map_err(|_| failure("download inventory exceeds count"))?
    {
        return Err(failure(
            "publisher did not read back selected exposed bodies",
        ));
    }
    let release = snapshot
        .release
        .as_ref()
        .ok_or_else(|| failure("no committed release"))?;
    if release.draft
        || release.tag_name != selection.version
        || release.body != selection.notes
        || release.prerelease != selection.prerelease
    {
        return Err(failure("independent managed metadata oracle failed"));
    }
    let budget = http::ReadBudget::new(deadline);
    let mut compared = BTreeSet::new();
    for file in &selection.files {
        let asset = snapshot
            .assets
            .iter()
            .find(|asset| asset.name == file.name)
            .ok_or_else(|| failure("selected asset was never committed"))?;
        if asset.size != file.size || asset.sha256 != file.sha256 || asset.state != "uploaded" {
            return Err(failure("stored received asset differs"));
        }
        let mut url = http::github_url(
            &selection.repository,
            &["releases", "assets", &asset.id.to_string()],
        )?;
        let headers = if summary.public == Some(false) {
            vec![("Authorization".into(), format!("Bearer {GITHUB_TOKEN}"))]
        } else {
            vec![]
        };
        let bytes = http::download(transport, &budget, &url, &headers, file.size)?;
        if bytes.len() as u64 != file.size || artifacts::checksum(&bytes) != file.sha256 {
            return Err(failure("independent exposed asset bytes differ"));
        }
        compared.insert(("github".to_owned(), file.name.clone()));
        if let Some(package) = &file.package {
            let stored = snapshot
                .crates
                .iter()
                .find(|item| &item.name == package)
                .ok_or_else(|| failure("selected registry archive never committed"))?;
            if stored.sha256 != file.sha256 || !stored.visible || stored.yanked {
                return Err(failure("registry stored state differs"));
            }
            url = url::Url::parse("https://static.crates.io").expect("constant URL");
            url.path_segments_mut().expect("constant base").extend([
                "crates",
                package,
                &format!("{}-{}.crate", package, selection.version),
            ]);
            let bytes = http::download(transport, &budget, &url, &[], file.size)?;
            if bytes.len() as u64 != file.size || artifacts::checksum(&bytes) != file.sha256 {
                return Err(failure("independent exposed registry bytes differ"));
            }
            compared.insert(("registry".to_owned(), file.name.clone()));
        }
    }
    let mut seen = BTreeSet::new();
    for effect in &snapshot.effects {
        if !seen.insert((format!("{:?}", effect.boundary), effect.name.clone())) {
            return Err(failure("duplicate committed publication effect"));
        }
    }
    assert_evidence(selection, snapshot, summary, &compared, true, true)
}
pub fn assert_evidence(
    selection: &FixtureSelection,
    snapshot: &Snapshot,
    summary: &PublicationSummary,
    compared: &BTreeSet<(String, String)>,
    terminated: bool,
    cleanup: bool,
) -> Result<()> {
    if !terminated || !cleanup || !summary.complete {
        return Err(failure("process/completion/cleanup evidence absent"));
    }
    for file in &selection.files {
        if !snapshot.assets.iter().any(|asset| asset.name == file.name)
            || !compared.contains(&("github".into(), file.name.clone()))
        {
            return Err(failure(
                "selected asset write or exposed-body comparison absent",
            ));
        }
        if file.package.is_some()
            && (!snapshot
                .crates
                .iter()
                .any(|item| Some(&item.name) == file.package.as_ref())
                || !compared.contains(&("registry".into(), file.name.clone())))
        {
            return Err(failure(
                "selected registry write or exposed-body comparison absent",
            ));
        }
    }
    Ok(())
}

pub fn run(helper: &Path, publisher_path: &Path, input: &Path, report_dir: &Path) -> Result<()> {
    let started = Instant::now();
    let work_unix_ms = unix_ms()?
        .checked_add(49 * 60 * 1000)
        .ok_or_else(|| failure("work cutoff overflow"))?;
    let work = started + Duration::from_secs(49 * 60);
    let retirement = started + Duration::from_secs(50 * 60);
    if report_dir.exists() {
        return Err(failure("rehearsal diagnostics must be fresh"));
    }
    fs::create_dir_all(report_dir)?;
    fs::write(
        report_dir.join("summary.json"),
        b"{\"revision\":1,\"complete\":false,\"cleanup\":false,\"phase\":\"input-validation\"}\n",
    )?;
    let loaded = RehearsalInput::load(input)?;
    validate_event(&loaded)?;
    let selection = FixtureSelection {
        version: loaded.version().to_string(),
        commit: loaded.commit().into(),
        repository: loaded.repository().into(),
        notes: loaded.notes().into(),
        prerelease: !loaded.version().pre.is_empty(),
        files: loaded
            .files()
            .iter()
            .map(|file| ExpectedFile {
                name: file.name.clone(),
                size: file.byte_len,
                sha256: file.sha256.clone(),
                package: file.package.clone(),
            })
            .collect(),
    };
    let original_input = inventory(input)?;
    let publisher_bytes = artifacts::read_file(publisher_path)?;
    let mut report = Report {
        revision: REVISION,
        kind: loaded.kind().into(),
        version: selection.version.clone(),
        commit: selection.commit.clone(),
        notes_placeholder: loaded.notes_placeholder(),
        publisher_sha256: artifacts::checksum(&publisher_bytes),
        payloads: selection.files.clone(),
        cases: vec![],
        complete: false,
        cleanup: false,
        unexecuted: 0,
    };
    drop(loaded);
    drop(publisher_bytes);
    let selected = cases::selected(
        selection.files.len(),
        selection
            .files
            .iter()
            .filter(|file| file.package.is_some())
            .count(),
    );
    report.unexecuted = selected.len();
    let report_path = report_dir.join("summary.json");
    write_report(&report_path, &report)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    cancellation_listener(cancelled.clone())?;
    #[cfg(unix)]
    let temporary = tempfile::Builder::new()
        .prefix("memcordon-rehearsal-")
        .tempdir_in("/tmp")?;
    #[cfg(not(unix))]
    let temporary = tempfile::Builder::new()
        .prefix("memcordon-rehearsal-")
        .tempdir()?;
    for (ordinal, case) in selected.iter().enumerate() {
        verify_tool(publisher_path, &report.publisher_sha256)?;
        if cancelled.load(Ordering::SeqCst) || Instant::now() + Duration::from_secs(10) >= work {
            return Err(failure(
                "remaining original work interval cannot admit next case",
            ));
        }
        let state = temporary.path().join(ordinal.to_string());
        fs::create_dir(&state)?;
        let result = run_case(
            helper,
            publisher_path,
            input,
            &state,
            case,
            &selection,
            work_unix_ms,
            work,
            retirement,
            cancelled.clone(),
        );
        let diagnostic = retain_case(report_dir, &state, ordinal);
        report.unexecuted -= 1;
        match result {
            Ok(value) => report.cases.push(value),
            Err(error) => {
                let observed = snapshot(&state).ok();
                let primary = if let Err(secondary) = diagnostic {
                    CiError::Message(format!("{error}; secondary diagnostics: {secondary}"))
                } else {
                    error
                };
                report.cases.push(CaseResult {
                    group: case.group.into(),
                    variant: case.variant.clone(),
                    complete: false,
                    fault_reached: observed.as_ref().is_some_and(|value| value.fault_reached),
                    publisher_terminated: process_terminated(&state.join("result.process.json")),
                    requests: observed.as_ref().map_or(0, |value| value.requests.len()),
                    effects: observed.as_ref().map_or(0, |value| value.effects.len()),
                    cleanup: state.join("server-settled.json").is_file()
                        && process_terminated(&state.join("result.process.json")),
                    error: Some(primary.to_string()),
                });
                let secondary = write_report(&report_path, &report);
                if let Err(secondary) = secondary {
                    eprintln!("secondary rehearsal diagnostic failure: {secondary}");
                }
                return Err(primary);
            }
        }
        diagnostic?;
        write_report(&report_path, &report)?;
        fs::remove_dir_all(&state)?;
    }
    if original_input != inventory(input)?
        || report.publisher_sha256 != artifacts::checksum(&artifacts::read_file(publisher_path)?)
    {
        return Err(failure("original rehearsal input or publisher mutated"));
    }
    report.complete = true;
    report.cleanup = true;
    write_report(&report_path, &report)
}

fn retain_case(report_dir: &Path, state: &Path, ordinal: usize) -> Result<()> {
    let destination = report_dir.join(ordinal.to_string());
    fs::create_dir(&destination)?;
    if let Ok(snapshot) = snapshot(state) {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"requests":snapshot.requests,"effects":snapshot.effects,"fault_reached":snapshot.fault_reached,"fault_boundary":snapshot.fault_boundary,"omitted_requests":snapshot.omitted_requests,"max_active_reads":snapshot.max_active_reads,"max_active_connections":snapshot.max_active_connections,"max_active_writes":snapshot.max_active_writes,"body_downloads":snapshot.body_downloads}),
        )?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(failure("case request trace exceeds bound"));
        }
        write_diagnostic(report_dir, &destination.join("trace.json"), &bytes)?;
    }
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_text = name.to_string_lossy();
        if name_text.ends_with(".process.json")
            || name_text == "server.stderr.json"
            || name_text == "server-settled.json"
            || name_text == "cancelled-publisher.json"
        {
            let bytes = artifacts::read_file(&entry.path())?;
            if bytes.len() > 3 * PROCESS_OUTPUT {
                return Err(failure("retained process diagnostic exceeds bound"));
            }
            write_diagnostic(report_dir, &destination.join(name), &bytes)?;
        }
    }
    Ok(())
}
fn process_terminated(path: &Path) -> bool {
    read_json::<serde_json::Value>(path, 3 * PROCESS_OUTPUT as u64)
        .ok()
        .is_some_and(|value| {
            value.get("terminated").and_then(serde_json::Value::as_bool) == Some(true)
                || value
                    .get("termination")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
        })
}
fn write_diagnostic(report_dir: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let total = walkdir::WalkDir::new(report_dir)
        .into_iter()
        .try_fold(0_u64, |total, entry| {
            let entry = entry.map_err(|_| failure("diagnostic inventory unavailable"))?;
            if !entry.file_type().is_file() {
                return Ok(total);
            }
            total
                .checked_add(
                    entry
                        .metadata()
                        .map_err(|_| failure("diagnostic metadata unavailable"))?
                        .len(),
                )
                .ok_or_else(|| failure("diagnostic byte count overflow"))
        })?;
    // Reserve the separately rewritten summary's full1MiB ceiling.
    if total
        .checked_add(bytes.len() as u64)
        .is_none_or(|total| total > 63 * 1024 * 1024)
    {
        return Err(failure("total diagnostics exceed64MiB"));
    }
    fs::write(path, bytes)?;
    Ok(())
}
fn redact(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .replace(GITHUB_TOKEN, "[github-role]")
        .replace(REGISTRY_TOKEN, "[registry-role]")
}
fn retain_process(
    path: &Path,
    observed: std::result::Result<
        memcordon_testkit::ObservedOutput,
        memcordon_testkit::ProcessTestError,
    >,
) -> Result<memcordon_testkit::ObservedOutput> {
    use memcordon_testkit::ProcessTestError;
    let value = match &observed {
        Ok(output) => {
            serde_json::json!({"status":format!("{:?}",output.status),"success":output.status.success(),"stdout":redact(&output.stdout),"stderr":redact(&output.stderr),"stdout_bytes":output.stdout.len(),"stderr_bytes":output.stderr.len(),"truncated":false,"terminated":true})
        }
        Err(ProcessTestError::OutputLimit {
            stdout,
            stderr,
            cleanup,
            termination,
        }) => {
            serde_json::json!({"stdout":redact(stdout),"stderr":redact(stderr),"truncated":true,"cleanup":format!("{cleanup:?}"),"termination":termination.map(|status|format!("{status:?}"))})
        }
        Err(ProcessTestError::Timeout {
            stdout,
            stderr,
            cleanup,
            observation,
            ..
        }) => {
            serde_json::json!({"stdout":redact(stdout),"stderr":redact(stderr),"truncated":false,"cleanup":format!("{cleanup:?}"),"timeout_observation":format!("{observation:?}"),"termination":null})
        }
        Err(error) => {
            serde_json::json!({"error":redact(error.to_string().as_bytes()),"termination":null,"cleanup":null})
        }
    };
    let bytes = serde_json::to_vec(&value)?;
    let diagnostic = fs::write(path, bytes);
    match (observed, diagnostic) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error.into()),
        (Err(error), Err(secondary)) => Err(CiError::Message(format!(
            "{error}; secondary process diagnostic: {secondary}"
        ))),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn inventory(directory: &Path) -> Result<Vec<(String, String)>> {
    let mut inventory = fs::read_dir(directory)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(failure("input contains nonfile"));
            }
            Ok((
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| failure("input filename invalid"))?,
                artifacts::checksum(&artifacts::read_file(&entry.path())?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    inventory.sort();
    Ok(inventory)
}
fn validate_event(input: &RehearsalInput) -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return Ok(());
    }
    let path = std::env::var_os("GITHUB_EVENT_PATH")
        .ok_or_else(|| failure("standard event file absent"))?;
    let event: serde_json::Value = read_json(Path::new(&path), 1024 * 1024)?;
    let name =
        std::env::var("GITHUB_EVENT_NAME").map_err(|_| failure("standard event name absent"))?;
    let reference = std::env::var("GITHUB_REF").map_err(|_| failure("standard ref absent"))?;
    let sha = std::env::var("GITHUB_SHA").map_err(|_| failure("standard source SHA absent"))?;
    if sha != input.commit() {
        return Err(failure("rehearsal input source differs from invocation"));
    }
    let tagged = reference.strip_prefix("refs/tags/");
    match (name.as_str(), input.kind(), tagged) {
        ("push", "candidate", None)
            if reference.starts_with("refs/heads/")
                && event.get("deleted").and_then(serde_json::Value::as_bool) == Some(false)
                && event.get("after").and_then(serde_json::Value::as_str)
                    == Some(input.commit()) =>
        {
            Ok(())
        }
        ("push", "tagged", Some(tag)) if tag == input.version().to_string() => Ok(()),
        ("workflow_dispatch", "candidate", None)
            if event
                .pointer("/inputs/preparation-mode")
                .and_then(serde_json::Value::as_str)
                == Some("candidate") =>
        {
            Ok(())
        }
        ("workflow_dispatch", "tagged", Some(tag))
            if tag == input.version().to_string()
                && event
                    .pointer("/inputs/preparation-mode")
                    .and_then(serde_json::Value::as_str)
                    == Some("release") =>
        {
            Ok(())
        }
        _ => Err(failure("rehearsal event kind/source differs")),
    }
}
fn cancellation_listener(cancelled: Arc<AtomicBool>) -> Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        if let Ok(runtime) = runtime {
            runtime.block_on(async move {
                #[cfg(unix)]
                {
                    if let Ok(mut terminate) =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        let _ = sender.send(());
                        tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=terminate.recv()=>{} }
                    } else {
                        return;
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = sender.send(());
                    let _ = tokio::signal::ctrl_c().await;
                }
                cancelled.store(true, Ordering::SeqCst);
            });
        }
    });
    receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| failure("coordinator cancellation listener was not ready"))
}

fn run_case(
    helper: &Path,
    publisher_path: &Path,
    input: &Path,
    state: &Path,
    case: &Case,
    selection: &FixtureSelection,
    work_unix_ms: u64,
    work: Instant,
    retirement: Instant,
    cancelled: Arc<AtomicBool>,
) -> Result<CaseResult> {
    let budget = if matches!(
        case.fault,
        Fault::Stall
            | Fault::RateLimit { excessive: true }
            | Fault::VisibilityDelay { expire: true, .. }
    ) {
        BudgetPreset::Short5s
    } else {
        BudgetPreset::Normal20min
    };
    let setup = Setup {
        revision: REVISION,
        case_id: case.variant.clone(),
        selection: selection.clone(),
        fault: if case.seed {
            Fault::None
        } else {
            case.fault.clone()
        },
        budget,
        work_unix_ms,
    };
    fs::write(state.join("setup.json"), serde_json::to_vec(&setup)?)?;
    let ready = state.join("ready.json");
    let result = state.join("result.json");
    let mut server = Server::start(helper, case, state, &ready, retirement)?;
    let mut record = wait_ready(
        &ready,
        &mut server,
        work.min(Instant::now() + Duration::from_secs(10)),
        &cancelled,
    )?;
    if case.seed {
        let (success, _) = publisher(
            publisher_path,
            input,
            &ready,
            &result,
            work,
            None,
            cancelled.clone(),
        )?;
        if !success {
            return Err(failure("actual seed transaction failed"));
        }
        let summary = complete_summary(read_json(&result, 1024 * 1024)?)?;
        assert_complete(
            selection,
            &snapshot(state)?,
            &LoopbackTransport::new(record.clone())?,
            &summary,
            work,
        )?;
        server.stop()?;
        fs::remove_file(&ready)?;
        fs::remove_file(&result)?;
        fs::write(
            state.join("setup.json"),
            serde_json::to_vec(&Setup {
                fault: case.fault.clone(),
                ..setup
            })?,
        )?;
        server = Server::start(helper, case, state, &ready, retirement)?;
        record = wait_ready(
            &ready,
            &mut server,
            work.min(Instant::now() + Duration::from_secs(10)),
            &cancelled,
        )?;
    }
    let before = snapshot(state)?;
    let verdict = (|| -> Result<CaseResult> {
        if case.group == "R13" && case.variant == "cancellation" {
            cancel_case(
                helper,
                publisher_path,
                input,
                &ready,
                &result,
                state,
                &server,
                work,
            )?;
            let observed = snapshot(state)?;
            expected_boundary(case, &observed)?;
            if !observed.fault_reached
                || !observed
                    .effects
                    .iter()
                    .any(|effect| effect.boundary == Boundary::Draft)
            {
                return Err(failure(
                    "coordinator cancellation occurred before intended effect",
                ));
            }
            return Ok(CaseResult {
                group: case.group.into(),
                variant: case.variant.clone(),
                complete: true,
                fault_reached: true,
                publisher_terminated: true,
                requests: observed.requests.len(),
                effects: observed.effects.len(),
                cleanup: true,
                error: None,
            });
        }
        let events = if case.recover {
            Some(server.events.clone())
        } else {
            None
        };
        let (mut success, reached) = publisher(
            publisher_path,
            input,
            &ready,
            &result,
            work,
            events,
            cancelled.clone(),
        )?;
        let mut interrupted_prefix = None;
        if case.recover {
            if success || !reached {
                return Err(failure(
                    "publisher crash boundary was not reached and observed",
                ));
            }
            interrupted_prefix = Some(snapshot(state)?);
            expected_boundary(
                case,
                interrupted_prefix
                    .as_ref()
                    .expect("observed interruption prefix"),
            )?;
            let _ = server.input.write_all(b"continue\n");
            server.stop()?;
            fs::remove_file(&ready)?;
            if result.exists() {
                fs::remove_file(&result)?;
            }
            fs::write(
                state.join("setup.json"),
                serde_json::to_vec(&Setup {
                    revision: REVISION,
                    case_id: case.variant.clone(),
                    selection: selection.clone(),
                    fault: Fault::None,
                    budget,
                    work_unix_ms,
                })?,
            )?;
            server = Server::start(helper, case, state, &ready, retirement)?;
            record = wait_ready(
                &ready,
                &mut server,
                work.min(Instant::now() + Duration::from_secs(10)),
                &cancelled,
            )?;
            success = publisher(
                publisher_path,
                input,
                &ready,
                &result,
                work,
                None,
                cancelled.clone(),
            )?
            .0;
        }
        let observed = snapshot(state)?;
        if !case.recover {
            expected_boundary(case, &observed)?;
        }
        preserve_identities(&before, &observed)?;
        if let Some(prefix) = &interrupted_prefix {
            preserve_identities(prefix, &observed)?;
        }
        if success != case.positive {
            return Err(failure(
                "publisher result disagrees with intended case boundary",
            ));
        }
        if case.fault != Fault::None
            && !matches!(case.fault, Fault::Private | Fault::AnnotatedTag)
            && !observed.fault_reached
            && !reached
        {
            return Err(failure("configured fault never reached"));
        }
        if observed.credential_errors != 0 {
            return Err(failure("fixture observed wrong credential role"));
        }
        if case.positive {
            let summary = complete_summary(read_json(&result, 1024 * 1024)?)?;
            assert_complete(
                selection,
                &observed,
                &LoopbackTransport::new(record)?,
                &summary,
                work,
            )?;
        } else {
            assert_negative(case, &read_json(&result, 1024 * 1024)?, &before, &observed)?;
        }
        if case.group == "R01"
            && observed
                .requests
                .iter()
                .skip(before.requests.len())
                .any(|request| {
                    matches!(request.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
                })
        {
            return Err(failure("matching fresh-process retry attempted mutation"));
        }
        if case.group == "R05" && observed.effects.len() != before.effects.len() {
            return Err(failure("conflicting state was mutated"));
        }
        if case.group == "R12" && case.positive && observed.max_active_reads < 2 {
            return Err(failure(
                "shared throttling case did not observe concurrent reads",
            ));
        }
        if case.group == "R06"
            && matches!(
                case.fault,
                Fault::UnknownRead {
                    after_effect: false,
                    ..
                }
            )
            && !observed.effects.is_empty()
        {
            return Err(failure("initial unknown state produced effects"));
        }
        if case.group == "R14" {
            input_controls(input, publisher_path, work, cancelled.clone())?;
        }
        if case.group == "R15" {
            oracle_controls(selection, &observed)?;
        }
        Ok(CaseResult {
            group: case.group.into(),
            variant: case.variant.clone(),
            complete: true,
            fault_reached: observed.fault_reached || reached,
            publisher_terminated: true,
            requests: observed.requests.len(),
            effects: observed.effects.len(),
            cleanup: true,
            error: None,
        })
    })();
    let cleanup = server.stop();
    match (verdict, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(secondary)) => Err(CiError::Message(format!(
            "{error}; secondary fixture cleanup: {secondary}"
        ))),
        (Ok(_), Err(error)) => Err(error),
    }
}
fn input_controls(
    input: &Path,
    publisher_path: &Path,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
) -> Result<()> {
    let loaded = RehearsalInput::load(input)?;
    #[cfg(unix)]
    let temporary = tempfile::tempdir_in("/tmp")?;
    #[cfg(not(unix))]
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path();
    fs::write(directory.join("prepared.json"), b"{}")?;
    fs::write(directory.join("candidate.json"), b"{}")?;
    if RehearsalInput::load(directory).is_ok() {
        return Err(failure("both-envelope control accepted"));
    }
    fs::remove_file(directory.join("candidate.json"))?;
    if RehearsalInput::load(directory).is_ok() {
        return Err(failure("invalid tagged envelope accepted via fallback"));
    }
    fs::remove_file(directory.join("prepared.json"))?;
    if RehearsalInput::load(directory).is_ok() {
        return Err(failure("missing-envelope control accepted"));
    }
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        let destination = directory.join(entry.file_name());
        if fs::hard_link(entry.path(), &destination).is_err() {
            // Files are already bounded by the validated original inventory;
            // a different local filesystem must not disable mutation controls.
            let size = entry.metadata()?.len();
            let mut source = fs::File::open(entry.path())?.take(size + 1);
            let mut copied = fs::File::create(&destination)?;
            if std::io::copy(&mut source, &mut copied)? != size {
                return Err(failure("input changed during bounded control copy"));
            }
        }
    }
    let envelope = directory.join(if loaded.kind() == "candidate" {
        "candidate.json"
    } else {
        "prepared.json"
    });
    let original_envelope = fs::read(&envelope)?;
    fs::remove_file(&envelope)?;
    let mut changed: serde_json::Value = serde_json::from_slice(&original_envelope)?;
    let source = changed
        .get_mut("source")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| failure("input control source absent"))?;
    source.insert(
        "commit".into(),
        serde_json::Value::String("2222222222222222222222222222222222222222".into()),
    );
    fs::write(&envelope, serde_json::to_vec(&changed)?)?;
    if RehearsalInput::load(directory).is_ok() {
        return Err(failure("wrong source identity control accepted"));
    }
    fs::write(&envelope, &original_envelope)?;
    let mut changed: serde_json::Value = serde_json::from_slice(&original_envelope)?;
    changed["files"][0]["target"] = serde_json::Value::String("unsupported-fixture-target".into());
    fs::write(&envelope, serde_json::to_vec(&changed)?)?;
    if RehearsalInput::load(directory).is_ok() {
        return Err(failure("wrong target control accepted"));
    }
    fs::write(&envelope, &original_envelope)?;
    let record = loaded
        .files()
        .first()
        .ok_or_else(|| failure("input mutation control requires payload"))?;
    let payload = directory.join(&record.name);
    fs::remove_file(&payload)?;
    fs::copy(input.join(&record.name), &payload)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&payload)?;
    let mut first = [0];
    file.read_exact(&mut first)?;
    first[0] ^= 1;
    use std::io::Seek;
    file.rewind()?;
    file.write_all(&first)?;
    file.flush()?;
    if RehearsalInput::load(directory).is_ok() {
        return Err(failure("changed payload control accepted"));
    }
    let original_tool = artifacts::checksum(&artifacts::read_file(publisher_path)?);
    let changed_tool = directory.join("changed-publisher");
    fs::write(&changed_tool, b"changed original publisher control\n")?;
    if verify_tool(&changed_tool, &original_tool).is_ok() {
        return Err(failure("changed executable control accepted"));
    }
    if loaded.kind() == "candidate" {
        let mut command = Command::new(publisher_path);
        command
            .args(["release", "publish", "--prepared"])
            .arg(input);
        sanitize_child(&mut command);
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| failure("input control deadline expired"))?;
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            remaining,
            PROCESS_OUTPUT,
        )?;
        if output.status.success() || cancelled.load(Ordering::SeqCst) {
            return Err(failure("production candidate rejection control failed"));
        }
        if String::from_utf8_lossy(&output.stderr).contains("credential") {
            return Err(failure(
                "production candidate reached credential acquisition",
            ));
        }
    }
    Ok(())
}
fn verify_tool(path: &Path, expected: &str) -> Result<()> {
    if artifacts::checksum(&artifacts::read_file(path)?) != expected {
        return Err(failure("original publisher executable differs"));
    }
    Ok(())
}
fn oracle_controls(selection: &FixtureSelection, observed: &Snapshot) -> Result<()> {
    if selection.files.is_empty() {
        return Err(failure("oracle control requires selected content"));
    }
    let mut broken = observed.clone();
    broken.assets.clear();
    if broken.assets.len() == selection.files.len() {
        return Err(failure("skipped-write control was vacuous"));
    }
    let fake: PublicationSummary = serde_json::from_value(
        serde_json::json!({"source_commit":selection.commit,"objects":[],"complete":true,"public":true,"writes":[]}),
    )?;
    if !fake.complete || !broken.assets.is_empty() {
        return Err(failure("false summary control setup failed"));
    }
    // The same completion assertion must reject a fake summary without effects.
    let mut compared = BTreeSet::new();
    for file in &selection.files {
        compared.insert(("github".into(), file.name.clone()));
        if file.package.is_some() {
            compared.insert(("registry".into(), file.name.clone()));
        }
    }
    if assert_evidence(selection, &broken, &fake, &compared, true, true).is_ok() {
        return Err(failure("false complete summary escaped independent oracle"));
    }
    if assert_evidence(selection, observed, &fake, &BTreeSet::new(), true, true).is_ok() {
        return Err(failure("skipped exposed-body comparison escaped oracle"));
    }
    if assert_evidence(selection, observed, &fake, &compared, true, false).is_ok() {
        return Err(failure("omitted cleanup escaped oracle"));
    }
    Ok(())
}

fn complete_summary(value: TransactionResult) -> Result<PublicationSummary> {
    match value {
        TransactionResult::Complete { summary } => Ok(summary),
        _ => Err(failure(
            "successful process did not publish a complete typed result",
        )),
    }
}
fn assert_negative(
    case: &Case,
    result: &TransactionResult,
    before: &Snapshot,
    after: &Snapshot,
) -> Result<()> {
    let conflict = matches!(result,TransactionResult::Incomplete {summary} if summary.objects.iter().any(|object|matches!(object.observation,RemoteState::Conflicting{..})));
    let unknown = matches!(result,TransactionResult::Incomplete {summary} if summary.objects.iter().any(|object|matches!(object.observation,RemoteState::Unknown{..})));
    let rejected = matches!(result, TransactionResult::ObservationRejected { .. });
    let valid = match case.group {
        "R05" => conflict && before.effects.len() == after.effects.len(),
        "R06" => unknown || rejected,
        "R07" => {
            (matches!(result, TransactionResult::Incomplete { .. }) || rejected)
                && after.crates.iter().any(|item| !item.visible)
        }
        "R08" => conflict || unknown,
        "R09" => conflict || unknown || rejected,
        "R10" => {
            rejected
                && (matches!(
                    case.fault,
                    Fault::SourceDrift {
                        before_visibility: true
                    }
                ) && !after
                    .effects
                    .iter()
                    .any(|effect| effect.boundary == Boundary::Visibility)
                    || before.effects.len() == after.effects.len())
        }
        "R11" => conflict && after.assets.iter().any(|asset| asset.state == "starter"),
        "R12" | "R13" => unknown || rejected,
        _ => false,
    };
    if !valid {
        return Err(failure(
            "negative case did not reach its typed intended publication failure",
        ));
    }
    if after
        .requests
        .iter()
        .any(|request| matches!(request.method.as_str(), "DELETE"))
    {
        return Err(failure("negative case attempted destructive recovery"));
    }
    Ok(())
}

fn preserve_identities(before: &Snapshot, after: &Snapshot) -> Result<()> {
    for asset in &before.assets {
        let current = after
            .assets
            .iter()
            .find(|current| current.name == asset.name)
            .ok_or_else(|| failure("matching asset disappeared on retry"))?;
        if current.id != asset.id || current.sha256 != asset.sha256 || current.size != asset.size {
            return Err(failure("retry replaced matching asset identity or bytes"));
        }
    }
    for package in &before.crates {
        let current = after
            .crates
            .iter()
            .find(|current| current.name == package.name)
            .ok_or_else(|| failure("matching crate disappeared on retry"))?;
        if current.sha256 != package.sha256 || current.version != package.version {
            return Err(failure("retry replaced matching registry bytes"));
        }
    }
    Ok(())
}
pub fn expected_boundary(case: &Case, observed: &Snapshot) -> Result<()> {
    if let Fault::Loss { boundary }
    | Fault::Barrier { boundary }
    | Fault::FixtureLoss { boundary } = &case.fault
    {
        if observed.fault_boundary.as_ref() != Some(boundary)
            || !observed
                .effects
                .iter()
                .any(|effect| &effect.boundary == boundary)
        {
            return Err(failure(
                "configured interruption boundary did not actually commit",
            ));
        }
    }
    Ok(())
}
