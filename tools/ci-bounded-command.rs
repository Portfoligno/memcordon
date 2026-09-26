//! Dependency-free parent supervision. Deadlines never renew on activity.
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[path = "ci-content-sha256.rs"]
pub mod sha256;
#[path = "ci-process-usage.rs"]
pub mod usage;
#[cfg(windows)]
#[path = "ci-bootstrap-windows.rs"]
mod windows;

pub const CHILD_BUDGET: Duration = Duration::from_secs(1800);
pub const TERMINATION_BUDGET: Duration = Duration::from_secs(5);
pub trait Clock {
    fn elapsed(&self) -> Duration;
    fn tick(&mut self);
}
pub trait Process {
    fn status(&mut self) -> io::Result<Option<ExitStatus>>;
    fn terminate(&mut self) -> io::Result<()>;
    fn usage(&mut self) -> Option<usage::Counters> {
        None
    }
}
struct WallClock(Instant);
impl Clock for WallClock {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn tick(&mut self) {
        std::thread::sleep(Duration::from_millis(10));
    }
}
impl Process for Child {
    fn status(&mut self) -> io::Result<Option<ExitStatus>> {
        self.try_wait()
    }
    fn terminate(&mut self) -> io::Result<()> {
        self.kill()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    ExitFailure,
    Deadline,
    PollFailure,
    SpawnFailure,
}
#[derive(Clone, Debug)]
pub struct Completion {
    pub outcome: Outcome,
    pub elapsed: Duration,
    pub exit_code: Option<i32>,
    pub kill_error: Option<String>,
    pub termination_observed: bool,
}
impl Completion {
    pub fn admitted(&self) -> bool {
        self.outcome == Outcome::Success && self.termination_observed && self.kill_error.is_none()
    }
    pub fn result(&self) -> io::Result<()> {
        if self.admitted() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "managed bootstrap {:?}; exit_code={:?} elapsed_ms={} termination_observed={} kill_error={:?}",
                self.outcome,
                self.exit_code,
                self.elapsed.as_millis(),
                self.termination_observed,
                self.kill_error
            )))
        }
    }
}
pub fn supervise(
    process: &mut impl Process,
    clock: &mut impl Clock,
    budget: Duration,
    termination_budget: Duration,
) -> Completion {
    supervise_with_usage(process, clock, budget, termination_budget).0
}
pub fn supervise_with_usage(
    process: &mut impl Process,
    clock: &mut impl Clock,
    budget: Duration,
    termination_budget: Duration,
) -> (Completion, usage::History) {
    let mut history = usage::History::default();
    let completion = supervise_inner(process, clock, budget, termination_budget, &mut history);
    (completion, history)
}
fn supervise_inner(
    process: &mut impl Process,
    clock: &mut impl Clock,
    budget: Duration,
    termination_budget: Duration,
    history: &mut usage::History,
) -> Completion {
    let failure = loop {
        if clock.elapsed() >= budget {
            break Outcome::Deadline;
        }
        match process.status() {
            Ok(Some(status)) => {
                if clock.elapsed() >= budget {
                    break Outcome::Deadline;
                }
                return Completion {
                    outcome: if status.success() {
                        Outcome::Success
                    } else {
                        Outcome::ExitFailure
                    },
                    elapsed: clock.elapsed(),
                    exit_code: status.code(),
                    kill_error: None,
                    termination_observed: true,
                };
            }
            Ok(None) => {
                let elapsed = clock.elapsed();
                if elapsed < budget && history.due(elapsed) {
                    let counters = process.usage();
                    history.observe(elapsed, clock.elapsed(), counters);
                }
                if clock.elapsed() >= budget {
                    break Outcome::Deadline;
                }
                clock.tick();
            }
            Err(_) => break Outcome::PollFailure,
        }
    };
    let kill_error = process.terminate().err().map(|error| error.to_string());
    let end = clock.elapsed().saturating_add(termination_budget);
    loop {
        if let Ok(Some(status)) = process.status() {
            return Completion {
                outcome: failure,
                elapsed: clock.elapsed(),
                exit_code: status.code(),
                kill_error,
                termination_observed: true,
            };
        }
        if clock.elapsed() >= end {
            return Completion {
                outcome: failure,
                elapsed: clock.elapsed(),
                exit_code: None,
                kill_error,
                termination_observed: false,
            };
        }
        clock.tick();
    }
}

pub fn abort_spawn(
    process: &mut impl Process,
    clock: &mut impl Clock,
    error: &io::Error,
) -> io::Error {
    let cleanup = supervise(process, clock, Duration::ZERO, TERMINATION_BUDGET);
    io::Error::other(format!(
        "spawn admission failed: {error}; termination_observed={} kill_error={:?}",
        cleanup.termination_observed, cleanup.kill_error
    ))
}

pub struct Journal {
    directory: PathBuf,
    sequence: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum TaskKind {
    Controller,
    Auxiliary,
    CargoAudit,
    CargoDeny,
    CargoFuzz,
    MiriSysroot,
}

impl TaskKind {
    fn directory(self) -> &'static str {
        match self {
            Self::Controller => "000-controller",
            Self::Auxiliary => "001-auxiliary",
            Self::CargoAudit => "000-cargo-audit",
            Self::CargoDeny => "001-cargo-deny",
            Self::CargoFuzz => "000-cargo-fuzz",
            Self::MiriSysroot => "000-miri-sysroot",
        }
    }
}

/// One immutable group deadline is copied into each lane; task creation cannot
/// renew the parent budget. Parallel scheduling remains a measured rollout.
#[derive(Clone, Copy)]
pub struct GroupDeadline(Instant);

impl GroupDeadline {
    pub fn new(budget: Duration) -> io::Result<Self> {
        Instant::now()
            .checked_add(budget)
            .map(Self)
            .ok_or_else(|| io::Error::other("bootstrap group deadline overflow"))
    }

    pub fn remaining(self) -> io::Result<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::other("bootstrap group budget exhausted"))
    }
}
impl Journal {
    pub fn create(base: &Path) -> io::Result<Self> {
        fs::create_dir_all(base)?;
        if fs::read_dir(base)?.take(64).count() >= 64 {
            return Err(io::Error::other(
                "bootstrap journal retention limit reached; archive prior evidence",
            ));
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let directory = base.join(format!("{}-{stamp}", std::process::id()));
        fs::create_dir(&directory)?;
        let journal = Self {
            directory,
            sequence: 0,
        };
        journal.write(
            "run-start.json",
            b"{\"schema\":1,\"outcome\":\"incomplete_unknown_termination\"}\n",
        )?;
        Ok(journal)
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn task(&self, kind: TaskKind) -> io::Result<Self> {
        let directory = self.directory.join("tasks").join(kind.directory());
        fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            sequence: 0,
        })
    }

    pub fn group_outcome(&self, results: &[io::Result<()>]) -> io::Result<()> {
        let failures: Vec<_> = results
            .iter()
            .enumerate()
            .filter_map(|(ordinal, result)| {
                result.as_ref().err().map(|error| {
                    format!(
                        "{{\"ordinal\":{ordinal},\"error\":{}}}",
                        json_string(&error.to_string())
                    )
                })
            })
            .collect();
        let record = format!(
            "{{\"schema\":1,\"outcome\":{},\"failures\":[{}]}}\n",
            json_string(if failures.is_empty() {
                "passed"
            } else {
                "failed"
            }),
            failures.join(",")
        );
        self.write("phase-bootstrap-group.json", record.as_bytes())
    }
    pub fn group_start(&self, deadline: GroupDeadline) -> io::Result<()> {
        let record = format!(
            "{{\"schema\":1,\"outcome\":\"incomplete\",\"remaining_ms\":{}}}\n",
            deadline.remaining()?.as_millis()
        );
        self.write("phase-bootstrap-group.json", record.as_bytes())
    }
    fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > 65536 {
            return Err(io::Error::other("bootstrap journal record limit"));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.directory.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()
    }
    pub fn start(&mut self, label: &str) -> io::Result<()> {
        self.start_with_budget(label, CHILD_BUDGET)
    }
    fn start_with_budget(&mut self, label: &str, budget: Duration) -> io::Result<()> {
        self.sequence += 1;
        let record = format!(
            "{{\"schema\":1,\"sequence\":{},\"phase\":{},\"outcome\":\"running\",\"budget_ms\":{}}}\n",
            self.sequence,
            json_string(label),
            budget.as_millis()
        );
        self.write("phase-start.json", record.as_bytes())
    }
    pub fn complete(&self, label: &str, completion: &Completion) -> io::Result<()> {
        let record = format!(
            "{{\"schema\":1,\"sequence\":{},\"phase\":{},\"outcome\":\"{:?}\",\"elapsed_ms\":{},\"exit_code\":{},\"termination_observed\":{},\"kill_error\":{},\"cache_eligible\":false}}\n",
            self.sequence,
            json_string(label),
            completion.outcome,
            completion.elapsed.as_millis(),
            completion
                .exit_code
                .map_or("null".to_owned(), |code| code.to_string()),
            completion.termination_observed,
            completion
                .kill_error
                .as_ref()
                .map_or("null".to_owned(), |s| json_string(s))
        );
        self.write("phase-end.json", record.as_bytes())
    }
    pub fn process_usage(&self, label: &str, history: &usage::History) -> io::Result<()> {
        let record = format!(
            "{{\"schema\":1,\"sequence\":{},\"phase\":{},\"process_usage\":{}}}\n",
            self.sequence,
            json_string(label),
            history.json()
        );
        self.write("phase-process-usage.json", record.as_bytes())
    }
    fn process_usage_error(&self, label: &str, error: &io::Error) -> io::Result<()> {
        let record = format!(
            "{{\"schema\":1,\"sequence\":{},\"phase\":{},\"process_usage_error\":{}}}\n",
            self.sequence,
            json_string(label),
            json_string(&error.to_string())
        );
        self.write("phase-process-usage-error.json", record.as_bytes())
    }
}
pub(crate) fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for c in value.chars().take(4096) {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            c if c < ' ' => output.push_str(&format!("\\u{:04x}", c as u32)),
            c => output.push(c),
        }
    }
    output.push('"');
    output
}
pub fn run(command: &mut Command, label: &str, journal: &mut Journal) -> io::Result<Completion> {
    run_with_budget(command, label, journal, CHILD_BUDGET)
}

pub fn run_in_group(
    command: &mut Command,
    label: &str,
    journal: &mut Journal,
    deadline: GroupDeadline,
) -> io::Result<Completion> {
    run_with_budget(
        command,
        label,
        journal,
        deadline.remaining()?.min(CHILD_BUDGET),
    )
}

pub fn run_two_lanes<C, A>(
    journal: &Journal,
    deadline: GroupDeadline,
    controller: C,
    auxiliary: A,
) -> io::Result<()>
where
    C: FnOnce(&mut Journal, GroupDeadline) -> io::Result<()> + Send,
    A: FnOnce(&mut Journal, GroupDeadline) -> io::Result<()> + Send,
{
    let mut controller_journal = journal.task(TaskKind::Controller)?;
    let mut auxiliary_journal = journal.task(TaskKind::Auxiliary)?;
    journal.group_start(deadline)?;
    let results = std::thread::scope(|scope| {
        let controller = std::thread::Builder::new()
            .name("bootstrap-controller".into())
            .spawn_scoped(scope, move || controller(&mut controller_journal, deadline));
        let auxiliary = std::thread::Builder::new()
            .name("bootstrap-auxiliary".into())
            .spawn_scoped(scope, move || auxiliary(&mut auxiliary_journal, deadline));
        let settle = |handle: io::Result<std::thread::ScopedJoinHandle<'_, io::Result<()>>>,
                      name: &str| {
            match handle {
                Ok(handle) => handle
                    .join()
                    .unwrap_or_else(|_| Err(io::Error::other(format!("{name} lane panicked")))),
                Err(error) => Err(io::Error::other(format!("starting {name} lane: {error}"))),
            }
        };
        // Both started lanes settle before fixed-ordinal errors or evidence are
        // returned, including an OS failure to start either controller thread.
        [
            settle(controller, "controller"),
            settle(auxiliary, "auxiliary"),
        ]
    });
    let [controller, auxiliary] = results;
    // Validation or promotion performed after a child settles still belongs to
    // the original deadline. Budget failure follows lane failures by ordinal.
    let results = [controller, auxiliary, deadline.remaining().map(|_| ())];
    let observation = journal.group_outcome(&results);
    for result in results {
        result?;
    }
    observation
}

fn run_with_budget(
    command: &mut Command,
    label: &str,
    journal: &mut Journal,
    budget: Duration,
) -> io::Result<Completion> {
    journal.start_with_budget(label, budget)?;
    let mut clock = WallClock(Instant::now());
    #[cfg(windows)]
    let spawned = windows::spawn(command);
    #[cfg(not(windows))]
    let spawned = command.spawn();
    let (completion, history) = match spawned {
        Ok(mut child) => supervise_with_usage(&mut child, &mut clock, budget, TERMINATION_BUDGET),
        Err(error) => {
            let completion = Completion {
                outcome: Outcome::SpawnFailure,
                elapsed: clock.elapsed(),
                exit_code: None,
                kill_error: Some(error.to_string()),
                termination_observed: false,
            };
            journal.complete(label, &completion)?;
            return Err(completion
                .result()
                .expect_err("spawn failure cannot be admitted"));
        }
    };
    // Preserve the authoritative outcome before attempting optional diagnostics.
    let journal_result = journal.complete(label, &completion);
    if let Err(error) = journal.process_usage(label, &history) {
        // Missing optional evidence is unavailable, never a zero measurement.
        // Failure of both diagnostic destinations must not rewrite the outcome
        // or introduce a blocking stderr fallback.
        let _ = journal.process_usage_error(label, &error);
    }
    completion.result()?;
    journal_result?;
    Ok(completion)
}
/// Execute an auxiliary diagnostic command without changing the managed phase
/// journal. It uses the same process containment and finite termination policy.
pub fn auxiliary(command: &mut Command, budget: Duration) -> io::Result<Completion> {
    let mut clock = WallClock(Instant::now());
    #[cfg(windows)]
    let mut child = windows::spawn(command)?;
    #[cfg(not(windows))]
    let mut child = command.spawn()?;
    Ok(supervise(
        &mut child,
        &mut clock,
        budget,
        TERMINATION_BUDGET,
    ))
}

#[derive(Debug)]
pub struct CapturedStream {
    pub prefix: Vec<u8>,
    pub bytes: u64,
    pub truncated: bool,
    pub error: Option<io::Error>,
}

/// Retain a bounded prefix while draining excess so observation does not cause
/// the producer to fail with a full/closed pipe. The caller owns the lifetime
/// boundary for a reader that never returns.
pub fn drain_prefix(mut reader: impl io::Read, limit: usize) -> CapturedStream {
    let mut result = CapturedStream {
        prefix: Vec::new(),
        bytes: 0,
        truncated: false,
        error: None,
    };
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes) => {
                result.bytes = result.bytes.saturating_add(bytes as u64);
                let retained = bytes.min(limit.saturating_sub(result.prefix.len()));
                result.prefix.extend_from_slice(&buffer[..retained]);
                result.truncated |= retained != bytes;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                result.error = Some(error);
                break;
            }
        }
    }
    result
}

pub struct CapturedCompletion {
    pub completion: Completion,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
}

/// Only called inside the separately contained recorder helper: its parent's
/// deadline bounds synchronous reader joins even if OS termination is unknown.
#[cfg(windows)]
pub fn auxiliary_capture(
    command: &mut Command,
    budget: Duration,
) -> io::Result<CapturedCompletion> {
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut clock = WallClock(Instant::now());
    let mut child = windows::spawn(command)?;
    let (stdout, stderr) = child.take_output();
    Ok(std::thread::scope(|scope| {
        let stdout = scope.spawn(|| drain_prefix(stdout, 65536));
        let stderr = scope.spawn(|| drain_prefix(stderr, 65536));
        let completion = supervise(&mut child, &mut clock, budget, TERMINATION_BUDGET);
        CapturedCompletion {
            completion,
            stdout: stdout.join().expect("formatter stdout reader panicked"),
            stderr: stderr.join().expect("formatter stderr reader panicked"),
        }
    }))
}

/// Stable diagnostic fields; unlike result(), this preserves the child code.
pub fn completion_json(completion: &Completion) -> String {
    format!(
        "{{\"outcome\":{},\"elapsed_ms\":{},\"exit_code\":{},\"termination_observed\":{},\"kill_error\":{}}}",
        json_string(&format!("{:?}", completion.outcome)),
        completion.elapsed.as_millis(),
        completion
            .exit_code
            .map_or("null".into(), |code| code.to_string()),
        completion.termination_observed,
        completion
            .kill_error
            .as_ref()
            .map_or("null".into(), |error| json_string(error))
    )
}

pub fn error_json(error: &io::Error) -> String {
    format!(
        "{{\"kind\":{},\"os_code\":{},\"message\":{}}}",
        json_string(&format!("{:?}", error.kind())),
        error
            .raw_os_error()
            .map_or("null".into(), |code| code.to_string()),
        json_string(&error.to_string())
    )
}

pub fn retain_capture(output: &Path, label: &str, capture: &CapturedCompletion) -> String {
    let streams: Vec<_> = [("stdout", &capture.stdout), ("stderr", &capture.stderr)].into_iter().map(|(name, stream)| {
        let path = output.join(format!("inventory-wpr-{label}-{name}.log"));
        let retained = OpenOptions::new().create_new(true).write(true).open(&path).and_then(|mut file| file.write_all(&stream.prefix));
        format!("{{\"stream\":{},\"bytes\":{},\"retained_bytes\":{},\"truncated\":{},\"read_error\":{},\"retention_error\":{}}}",
            json_string(name), stream.bytes, stream.prefix.len(), stream.truncated,
            stream.error.as_ref().map_or("null".into(), error_json),
            retained.as_ref().err().map_or("null".into(), error_json))
    }).collect();
    format!(
        "{{\"command\":{},\"completion\":{},\"streams\":[{}]}}",
        json_string(label),
        completion_json(&capture.completion),
        streams.join(",")
    )
}
#[cfg(windows)]
pub struct AuxiliaryProcess {
    child: windows::Contained,
    settled: bool,
}
#[cfg(windows)]
impl AuxiliaryProcess {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        Ok(Self {
            child: windows::spawn(command)?,
            settled: false,
        })
    }
    pub fn status(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.status()?;
        self.settled = status.is_some();
        Ok(status)
    }
    pub fn wait(&mut self, budget: Duration) -> Completion {
        let completion = supervise(
            &mut self.child,
            &mut WallClock(Instant::now()),
            budget,
            TERMINATION_BUDGET,
        );
        self.settled = completion.termination_observed;
        completion
    }
    pub fn terminate(&mut self) -> io::Result<()> {
        if self.settled {
            return Ok(());
        }
        let completion = self.wait(Duration::ZERO);
        if completion.termination_observed && completion.kill_error.is_none() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "recorder cleanup unknown: {completion:?}"
            )))
        }
    }
}
pub fn admission_path(output: &Path) -> PathBuf {
    output.with_extension("admission.json")
}
pub fn revoke(output: &Path) -> io::Result<()> {
    for path in [admission_path(output), output.to_path_buf()] {
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
pub fn publish(
    candidate: &Path,
    output: &Path,
    journal: &Journal,
    completion: &Completion,
) -> io::Result<()> {
    completion.result()?;
    let digest = sha256::digest(&mut fs::File::open(candidate)?)?;
    let nonce = journal
        .directory
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::other("invalid run nonce"))?;
    if output.exists() || admission_path(output).exists() {
        return Err(io::Error::other(
            "bootstrap admission destination already exists",
        ));
    }
    let record = format!(
        "{{\"schema\":1,\"nonce\":{},\"sha256\":{},\"parent_outcome\":\"success\",\"run_id\":{},\"run_attempt\":{},\"job\":{}}}\n",
        json_string(nonce),
        json_string(&digest),
        json_string(&std::env::var("GITHUB_RUN_ID").unwrap_or_default()),
        json_string(&std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_default()),
        json_string(&std::env::var("GITHUB_JOB").unwrap_or_default())
    );
    // Final file existence alone is insufficient: consumers require matching
    // admission, published last. A crash between these writes fails closed.
    let provisional = journal.directory.join("parent-admission.json");
    let mut admission = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&provisional)?;
    admission.write_all(record.as_bytes())?;
    admission.sync_all()?;
    drop(admission);
    fs::rename(candidate, output)?;
    // No-clobber atomic admission is the final fallible operation. In particular,
    // a flush error cannot leave a readable successful final admission.
    fs::hard_link(provisional, admission_path(output))
}
