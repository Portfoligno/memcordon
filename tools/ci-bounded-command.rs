//! Dependency-free parent supervision. Deadlines never renew on activity.
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[path = "ci-content-sha256.rs"]
pub mod sha256;
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
                "managed bootstrap {:?}; termination_observed={} kill_error={:?}",
                self.outcome, self.termination_observed, self.kill_error
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
            Ok(None) => clock.tick(),
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
        self.sequence += 1;
        let record = format!(
            "{{\"schema\":1,\"sequence\":{},\"phase\":{},\"outcome\":\"running\",\"budget_ms\":{}}}\n",
            self.sequence,
            json_string(label),
            CHILD_BUDGET.as_millis()
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
}
fn json_string(value: &str) -> String {
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
    journal.start(label)?;
    let mut clock = WallClock(Instant::now());
    #[cfg(windows)]
    let spawned = windows::spawn(command);
    #[cfg(not(windows))]
    let spawned = command.spawn();
    let completion = match spawned {
        Ok(mut child) => supervise(&mut child, &mut clock, CHILD_BUDGET, TERMINATION_BUDGET),
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
    let journal_result = journal.complete(label, &completion);
    completion.result()?;
    journal_result?;
    Ok(completion)
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
