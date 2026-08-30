use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::linux::launch::{self, TargetExecStatus};
use crate::request::Lifetime;
use serde::{Deserialize, Serialize};

use super::support;

const WORKER_REQUEST: &str = "worker-request";
pub(super) const WORKER_TEST_NAME: &str =
    "linux_sealed::sealed_simultaneous_attempts_have_disjoint_boundaries";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const OVERLAP_TIMEOUT: Duration = Duration::from_secs(5);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const TARGET_READY: &[u8] = b"concurrency-ready\n";
const TARGET_OUTPUT: &[u8] = b"concurrency-ready\nconcurrency-release\n";
const CONCURRENCY_EVIDENCE_PREFIX: &str = "MCSEALED-CONCURRENCY-EVIDENCE:";

#[derive(Debug, Deserialize, Serialize)]
struct WorkerReady {
    identity: String,
    fixture_directory: PathBuf,
    target_gate: PathBuf,
    output_file: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
struct WorkerResult {
    identity: String,
    target_pid: u32,
    started_monotonic_millis: u64,
    authorized_monotonic_millis: u64,
    terminal_monotonic_millis: u64,
    child_status: i32,
    exec_succeeded: bool,
    record_absent: bool,
    cgroup_absent: bool,
    fixture_absent: bool,
    boundary_retired: bool,
}

struct WorkerChild {
    label: &'static str,
    directory: PathBuf,
    child: Option<Child>,
}

impl WorkerChild {
    fn spawn(root: &Path, label: &'static str) -> Result<Self, String> {
        let directory = root.join(label);
        fs::create_dir(&directory).map_err(|error| error.to_string())?;
        fs::write(directory.join(WORKER_REQUEST), b"worker\n")
            .map_err(|error| error.to_string())?;
        let executable = std::env::args_os()
            .next()
            .ok_or_else(|| "concurrency test executable path is unavailable".to_owned())?;
        let executable = fs::canonicalize(executable).map_err(|error| error.to_string())?;
        let child = Command::new(executable)
            .args([
                OsStr::new("--exact"),
                OsStr::new(WORKER_TEST_NAME),
                OsStr::new("--ignored"),
                OsStr::new("--nocapture"),
                OsStr::new("--test-threads=1"),
            ])
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            label,
            directory,
            child: Some(child),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn status(&mut self) -> Result<Option<ExitStatus>, String> {
        self.child
            .as_mut()
            .expect("worker child must remain owned until collection")
            .try_wait()
            .map_err(|error| error.to_string())
    }

    fn collect(&mut self, status: ExitStatus) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut child = self
            .child
            .take()
            .expect("worker child must be collected exactly once");
        let waited = child.wait().map_err(|error| error.to_string())?;
        if waited != status {
            return Err(format!(
                "{} worker status changed from {status} to {waited}",
                self.label
            ));
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        child
            .stdout
            .take()
            .expect("worker stdout must be captured")
            .read_to_end(&mut stdout)
            .map_err(|error| error.to_string())?;
        child
            .stderr
            .take()
            .expect("worker stderr must be captured")
            .read_to_end(&mut stderr)
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!(
                "{} worker failed with {status}; stdout={}; stderr={}",
                self.label,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            ));
        }
        Ok((stdout, stderr))
    }
}

impl Drop for WorkerChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Serialize)]
struct AttemptEvidence<'a> {
    identity: &'a str,
    target_pid: u32,
    live_cgroup_member_pids: &'a [i32],
    started_monotonic_millis: u64,
    authorized_monotonic_millis: u64,
    terminal_monotonic_millis: u64,
    record_absent: bool,
    cgroup_absent: bool,
    fixture_absent: bool,
    boundary_retired: bool,
}

#[derive(Serialize)]
struct ConcurrencyEvidence<'a> {
    schema_version: u32,
    overlap: bool,
    attempts: [AttemptEvidence<'a>; 2],
}

pub fn run() {
    let directory = std::env::current_dir().expect("concurrency process directory must be known");
    if directory.join(WORKER_REQUEST).is_file() {
        run_worker(&directory);
    } else {
        run_parent();
    }
}

fn run_parent() {
    let root = tempfile::Builder::new()
        .prefix("memcordon-sealed-concurrency-")
        .tempdir_in("/tmp")
        .expect("concurrency coordination root must be created");
    let mut workers = [
        WorkerChild::spawn(root.path(), "left").expect("left worker must start"),
        WorkerChild::spawn(root.path(), "right").expect("right worker must start"),
    ];
    let ready = wait_for_ready(&mut workers).expect("both isolated workers must become ready");
    validate_ready(&ready);

    for worker in &workers {
        fs::write(worker.path("launch-release"), b"release\n")
            .expect("worker launch barrier must be released");
    }
    let live_members = wait_for_overlap(&mut workers, &ready)
        .expect("both authenticated attempt boundaries must overlap after target authorization");
    for item in &ready {
        fs::write(&item.target_gate, b"release\n").expect("target barrier must be released");
    }

    wait_for_completion(&mut workers).expect("both isolated workers must complete");
    let results = read_results(&workers).expect("both worker results must be valid");
    validate_results(&ready, &results, &live_members);

    let evidence = ConcurrencyEvidence {
        schema_version: 1,
        overlap: true,
        attempts: [
            attempt_evidence(&results[0], &live_members[0]),
            attempt_evidence(&results[1], &live_members[1]),
        ],
    };
    let payload = serde_json::to_string(&evidence).expect("concurrency evidence must serialize");
    let framed = frame_evidence(&payload);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all(framed.as_bytes())
        .expect("concurrency evidence must be written to stdout");
    stdout
        .flush()
        .expect("concurrency evidence stdout must flush");
}

pub fn frame_evidence(payload: &str) -> String {
    format!("\n{CONCURRENCY_EVIDENCE_PREFIX}{payload}\n")
}

fn run_worker(directory: &Path) {
    let fixture = support::StagedFixture::new().expect("worker fixture must stage");
    let fixture_directory = fixture.directory().to_owned();
    let target_gate = fixture.directory().join("concurrency-gate");
    fs::write(&target_gate, b"hold\n").expect("target gate must be created");
    fs::set_permissions(&target_gate, fs::Permissions::from_mode(0o644))
        .expect("target gate must be readable by the reduced target identity");

    let output_file = directory.join("target-output");
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_file)
        .expect("target output must be created");
    let stderr = OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("target stderr sink must open");
    let frontend_pid = unsafe { libc::getpid() };
    let (descriptors, attempt) =
        support::resources_with_outputs(frontend_pid, stdout.into(), stderr.into())
            .expect("worker launch resources must be created");
    let identity = attempt_identity(&attempt);
    let mut request = fixture
        .request("concurrency-gate", Lifetime::Workload)
        .expect("worker launch request must be created");
    request
        .arguments
        .push(target_gate.as_os_str().as_bytes().to_vec());

    let ready = WorkerReady {
        identity: identity.clone(),
        fixture_directory: fixture_directory.clone(),
        target_gate,
        output_file: output_file.clone(),
    };
    write_json(&directory.join("ready.json"), &ready).expect("worker readiness must be published");
    wait_for_path(&directory.join("launch-release"), READY_TIMEOUT)
        .expect("parent must release worker launch barrier");

    let started_monotonic_millis =
        crate::linux::clock::monotonic_millis().expect("worker start time must be available");
    let facts = launch::execute(
        request,
        descriptors,
        attempt,
        frontend_pid,
        65_534,
        65_534,
        Vec::new(),
    )
    .expect("isolated worker launch must complete");
    let terminal_monotonic_millis =
        crate::linux::clock::monotonic_millis().expect("worker terminal time must be available");

    assert_eq!(facts.child_status, 0);
    assert_eq!(facts.exec_status, TargetExecStatus::Succeeded);
    assert!(facts.spawn_error_reported);
    assert!(!facts.deadline_exceeded);
    assert!(!facts.memory_limit_exceeded);
    support::assert_retired(&facts);
    assert_eq!(
        fs::read(&output_file).expect("target output must remain readable"),
        TARGET_OUTPUT
    );
    drop(fixture);

    let record_absent = !Path::new(crate::linux::STATE_ROOT).join(&identity).exists();
    let cgroup_absent = !Path::new(crate::linux::CGROUP_ROOT)
        .join(&identity)
        .exists();
    let fixture_absent = !fixture_directory.exists();
    assert!(record_absent);
    assert!(cgroup_absent);
    assert!(fixture_absent);
    let result = WorkerResult {
        identity,
        target_pid: facts.target_pid,
        started_monotonic_millis,
        authorized_monotonic_millis: started_monotonic_millis
            .saturating_add(facts.authorization_offset_millis),
        terminal_monotonic_millis,
        child_status: facts.child_status,
        exec_succeeded: facts.exec_status == TargetExecStatus::Succeeded,
        record_absent,
        cgroup_absent,
        fixture_absent,
        boundary_retired: facts.boundary_retired,
    };
    write_json(&directory.join("result.json"), &result).expect("worker result must be published");
}

fn wait_for_ready(workers: &mut [WorkerChild; 2]) -> Result<[WorkerReady; 2], String> {
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut ready = [None, None];
    loop {
        for (index, worker) in workers.iter_mut().enumerate() {
            if ready[index].is_none() {
                let path = worker.path("ready.json");
                if path.exists() {
                    ready[index] = Some(read_json(&path)?);
                } else if let Some(status) = worker.status()? {
                    let (stdout, stderr) = worker.collect(status)?;
                    return Err(format!(
                        "{} worker exited before readiness: {status}; stdout={}; stderr={}",
                        worker.label,
                        String::from_utf8_lossy(&stdout),
                        String::from_utf8_lossy(&stderr)
                    ));
                }
            }
        }
        if ready.iter().all(Option::is_some) {
            return Ok(ready.map(|item| item.expect("readiness was checked")));
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for both worker readiness records".to_owned());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn validate_ready(ready: &[WorkerReady; 2]) {
    for item in ready {
        assert!(is_attempt_identity(&item.identity));
        assert!(item.fixture_directory.is_dir());
        assert!(item.target_gate.is_file());
        assert!(item.output_file.is_file());
        assert!(item.target_gate.starts_with(&item.fixture_directory));
    }
    assert_ne!(ready[0].identity, ready[1].identity);
    assert_ne!(ready[0].fixture_directory, ready[1].fixture_directory);
    assert_ne!(ready[0].target_gate, ready[1].target_gate);
    assert_ne!(ready[0].output_file, ready[1].output_file);
}

fn wait_for_overlap(
    workers: &mut [WorkerChild; 2],
    ready: &[WorkerReady; 2],
) -> Result<[Vec<i32>; 2], String> {
    let deadline = Instant::now() + OVERLAP_TIMEOUT;
    loop {
        for worker in workers.iter_mut() {
            if let Some(status) = worker.status()? {
                return Err(format!(
                    "{} worker exited before overlap: {status}",
                    worker.label
                ));
            }
        }
        let records_live = ready.iter().all(|item| {
            Path::new(crate::linux::STATE_ROOT)
                .join(&item.identity)
                .is_file()
        });
        let targets_ready = ready
            .iter()
            .all(|item| fs::read(&item.output_file).is_ok_and(|output| output == TARGET_READY));
        let members = std::array::from_fn(|index| read_cgroup_members(&ready[index].identity));
        if records_live && targets_ready {
            if let [Ok(left), Ok(right)] = &members {
                if !left.is_empty()
                    && !right.is_empty()
                    && left.iter().all(|pid| !right.contains(pid))
                {
                    return Ok([left.clone(), right.clone()]);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out proving simultaneous authenticated boundaries: records_live={records_live}, targets_ready={targets_ready}, members={members:?}"
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_completion(workers: &mut [WorkerChild; 2]) -> Result<(), String> {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    let mut statuses = [None, None];
    loop {
        for (index, worker) in workers.iter_mut().enumerate() {
            if statuses[index].is_none() {
                statuses[index] = worker.status()?;
            }
        }
        if statuses.iter().all(Option::is_some) {
            break;
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for both isolated workers to retire".to_owned());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    for (worker, status) in workers.iter_mut().zip(statuses) {
        worker.collect(status.expect("worker completion was checked"))?;
    }
    Ok(())
}

fn read_results(workers: &[WorkerChild; 2]) -> Result<[WorkerResult; 2], String> {
    Ok([
        read_json(&workers[0].path("result.json"))?,
        read_json(&workers[1].path("result.json"))?,
    ])
}

fn validate_results(
    ready: &[WorkerReady; 2],
    results: &[WorkerResult; 2],
    live_members: &[Vec<i32>; 2],
) {
    for ((ready, result), members) in ready.iter().zip(results).zip(live_members) {
        assert_eq!(result.identity, ready.identity);
        assert_eq!(result.child_status, 0);
        assert!(result.exec_succeeded);
        assert!(result.record_absent);
        assert!(result.cgroup_absent);
        assert!(result.fixture_absent);
        assert!(result.boundary_retired);
        assert!(
            !Path::new(crate::linux::STATE_ROOT)
                .join(&result.identity)
                .exists()
        );
        assert!(
            !Path::new(crate::linux::CGROUP_ROOT)
                .join(&result.identity)
                .exists()
        );
        assert!(!ready.fixture_directory.exists());
        assert!(result.started_monotonic_millis <= result.authorized_monotonic_millis);
        assert!(result.authorized_monotonic_millis <= result.terminal_monotonic_millis);
        assert!(members.contains(&(result.target_pid as i32)));
    }
    assert_ne!(results[0].target_pid, results[1].target_pid);
}

fn attempt_evidence<'a>(
    result: &'a WorkerResult,
    live_cgroup_member_pids: &'a [i32],
) -> AttemptEvidence<'a> {
    AttemptEvidence {
        identity: &result.identity,
        target_pid: result.target_pid,
        live_cgroup_member_pids,
        started_monotonic_millis: result.started_monotonic_millis,
        authorized_monotonic_millis: result.authorized_monotonic_millis,
        terminal_monotonic_millis: result.terminal_monotonic_millis,
        record_absent: result.record_absent,
        cgroup_absent: result.cgroup_absent,
        fixture_absent: result.fixture_absent,
        boundary_retired: result.boundary_retired,
    }
}

fn read_cgroup_members(identity: &str) -> Result<Vec<i32>, String> {
    fs::read_to_string(
        Path::new(crate::linux::CGROUP_ROOT)
            .join(identity)
            .join("cgroup.procs"),
    )
    .map_err(|error| error.to_string())?
    .lines()
    .map(|line| line.parse::<i32>().map_err(|error| error.to_string()))
    .collect()
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let temporary = path.with_extension("new");
    fs::write(
        &temporary,
        serde_json::to_vec(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::rename(temporary, path).map_err(|error| error.to_string())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

fn attempt_identity(attempt: &[u8; 16]) -> String {
    attempt.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_attempt_identity(identity: &str) -> bool {
    identity.len() == [0_u8; 16].len() * 2
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
