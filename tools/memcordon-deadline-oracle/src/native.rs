use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct FrontendOwner {
    child: Child,
    known: Vec<Identity>,
}

impl std::ops::Deref for FrontendOwner {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for FrontendOwner {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for FrontendOwner {
    fn drop(&mut self) {
        // An oracle I/O or decoding failure must still request native cleanup.
        for known in &self.known {
            if same_identity(*known).unwrap_or(false) {
                unsafe {
                    libc::kill(known.pid, libc::SIGKILL);
                }
            }
        }
        let _ = self.child.kill();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if !matches!(self.child.try_wait(), Ok(None)) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
struct Identity {
    pid: i32,
    state: u32,
    birth_seconds: u64,
    birth_microseconds: u64,
}

fn observe_children(parent: i32, known: &mut Vec<Identity>) -> io::Result<()> {
    unsafe extern "C" {
        fn proc_listchildpids(parent: i32, buffer: *mut std::ffi::c_void, bytes: i32) -> i32;
    }
    let mut pids = [0_i32; 1024];
    let bytes = i32::try_from(std::mem::size_of_val(&pids)).expect("bounded native inventory");
    let count = unsafe { proc_listchildpids(parent, pids.as_mut_ptr().cast(), bytes) };
    if count < 0 || count >= bytes {
        return Err(io::Error::other("independent child inventory incomplete"));
    }
    let count = usize::try_from(count).map_err(io::Error::other)? / std::mem::size_of::<i32>();
    for pid in pids.into_iter().take(count) {
        if pid > 0 && !known.iter().any(|value| value.pid == pid) {
            if let Some(value) = identity(pid)? {
                known.push(value);
            }
        }
    }
    Ok(())
}

fn identity(pid: i32) -> io::Result<Option<Identity>> {
    // Independent libproc adapter, deliberately not production inspection.
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    let count = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(size).expect("native structure size"),
        )
    };
    if count == 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ESRCH)) {
            return Ok(None);
        }
        return Err(error);
    }
    if usize::try_from(count).ok() != Some(size) {
        return Err(io::Error::other("partial native identity"));
    }
    let info = unsafe { info.assume_init() };
    Ok(Some(Identity {
        pid,
        state: info.pbi_status,
        birth_seconds: info.pbi_start_tvsec,
        birth_microseconds: info.pbi_start_tvusec,
    }))
}

fn same_identity(expected: Identity) -> io::Result<bool> {
    Ok(identity(expected.pid)?.is_some_and(|actual| {
        actual.birth_seconds == expected.birth_seconds
            && actual.birth_microseconds == expected.birth_microseconds
    }))
}

fn convert_clock_ticks(ticks: u64, numerator: u32, denominator: u32) -> io::Result<u64> {
    let wide = u128::from(ticks) * u128::from(numerator);
    let nanos = wide
        .checked_div(u128::from(denominator))
        .ok_or_else(|| io::Error::other("Mach timebase unavailable"))?;
    u64::try_from(nanos).map_err(io::Error::other)
}

fn validate_deadline_vectors() -> Result<Vec<serde_json::Value>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Conversion {
        name: String,
        ticks: u64,
        numerator: u32,
        denominator: u32,
        expected: Option<u64>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Addition {
        name: String,
        origin: u64,
        budget: u64,
        expected: Option<u64>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Remaining {
        name: String,
        force: u64,
        observed: u64,
        reserve: u64,
        expected: Option<u64>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Vectors {
        schema_version: u32,
        timebase: Vec<Conversion>,
        addition: Vec<Addition>,
        remaining: Vec<Remaining>,
    }
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../../spec/vectors/macos-deadline-v1.json"))?;
    if vectors.schema_version != 1
        || vectors.timebase.is_empty()
        || vectors.addition.is_empty()
        || vectors.remaining.is_empty()
    {
        return Err("invalid independent deadline vector inventory".into());
    }
    let mut observations = Vec::new();
    let mut record = |name: String, actual: Option<u64>, expected: Option<u64>| -> Result<()> {
        if actual != expected {
            return Err(format!("independent deadline vector mismatch: {name}").into());
        }
        observations
            .push(serde_json::json!({"name": name, "actual": actual, "expected": expected}));
        Ok(())
    };
    for case in vectors.timebase {
        record(
            case.name,
            convert_clock_ticks(case.ticks, case.numerator, case.denominator).ok(),
            case.expected,
        )?;
    }
    for case in vectors.addition {
        record(
            case.name,
            case.origin.checked_add(case.budget),
            case.expected,
        )?;
    }
    for case in vectors.remaining {
        let actual = case
            .force
            .checked_add(case.reserve)
            .map(|expiry| expiry.saturating_sub(case.observed));
        record(case.name, actual, case.expected)?;
    }
    Ok(observations)
}

fn clock() -> io::Result<u64> {
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> i32;
        fn mach_continuous_time() -> u64;
    }
    let mut info = Timebase { numer: 0, denom: 0 };
    if unsafe { mach_timebase_info(&mut info) } != 0 || info.denom == 0 {
        return Err(io::Error::other("Mach timebase unavailable"));
    }
    let ticks = unsafe { mach_continuous_time() };
    convert_clock_ticks(ticks, info.numer, info.denom)
}

#[derive(Serialize)]
struct Observation {
    schema_version: u32,
    scenario: &'static str,
    frontend_status: Option<i32>,
    frontend_signal: Option<i32>,
    elapsed_milliseconds: u64,
    outer_expired: bool,
    independently_confirmed_cleanup: bool,
    observed_helper_identities: Vec<Identity>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_retained: Vec<u8>,
    stderr_retained: Vec<u8>,
    passed: bool,
}

struct Capture<R> {
    reader: R,
    count: u64,
    head: Vec<u8>,
}

impl<R: Read + AsRawFd> Capture<R> {
    fn new(reader: R) -> io::Result<Self> {
        let fd = reader.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            reader,
            count: 0,
            head: Vec::new(),
        })
    }
    fn drain(&mut self) -> io::Result<()> {
        let mut buffer = [0; 8192];
        // A perpetually readable stream cannot starve the outer clock.
        for _ in 0..8 {
            match self.reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    self.count = self
                        .count
                        .saturating_add(u64::try_from(size).expect("buffer length"));
                    let retain = size.min(16_384_usize.saturating_sub(self.head.len()));
                    self.head.extend_from_slice(&buffer[..retain]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn create_before_deadline(mut command: Command, deadline: u64) -> Result<Child> {
    let (sender, receiver) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        if let Err(mpsc::SendError(Ok(mut child))) = sender.send(command.spawn()) {
            let _ = child.kill();
            let _ = child.wait();
        }
    });
    Ok(receiver.recv_timeout(Duration::from_nanos(deadline.saturating_sub(clock()?)))??)
}

fn scenario(
    executable: &Path,
    evidence: &Path,
    name: &'static str,
    fixture: &str,
    expected: i32,
) -> Result<bool> {
    let directory = evidence.join(name);
    fs::create_dir(&directory)?;
    let marker = directory.join("target-identity.json");
    let report = directory.join("execution.json");
    let started = clock()?;
    let deadline = started
        .checked_add(8_000_000_000)
        .ok_or("oracle clock overflow")?;
    let mut command = Command::new(executable);
    let zero_budget = fixture == "zero-budget";
    let loss = fixture == "frontend-loss";
    let stopped = fixture == "frontend-stopped";
    command
        .args([
            if zero_budget { "+0ms" } else { "+250ms" },
            "--summary",
            "--report",
        ])
        .arg(&report)
        .arg("--")
        .arg(std::env::current_exe()?)
        .arg("--fixture")
        .arg(if fixture == "blocked-stderr" {
            fixture
        } else {
            "sleep"
        })
        .arg(&marker)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = FrontendOwner {
        child: create_before_deadline(command, deadline)?,
        known: Vec::new(),
    };
    let mut stdout = Capture::new(child.stdout.take().ok_or("stdout pipe absent")?)?;
    let mut stderr = Capture::new(child.stderr.take().ok_or("stderr pipe absent")?)?;
    let mut status = None;
    let mut target = None;
    let mut guardian = None;
    let mut helper_identities = Vec::new();
    let mut fault_issued = false;
    let mut stopped_deadline_proved = !stopped;
    while clock()? < deadline {
        observe_children(i32::try_from(child.id())?, &mut helper_identities)?;
        for known in helper_identities.clone() {
            if same_identity(known)? {
                observe_children(known.pid, &mut helper_identities)?;
            }
        }
        if helper_identities.len() > 1024 {
            return Err("independent helper identity capacity exhausted".into());
        }
        child.known.clone_from(&helper_identities);
        stdout.drain()?;
        if fixture != "blocked-stderr" {
            stderr.drain()?;
        }
        if target.is_none() {
            if let Ok(bytes) = fs::read(&marker) {
                if let Ok(identities) = serde_json::from_slice::<[Identity; 2]>(&bytes) {
                    target = Some(identities[0]);
                    guardian = Some(identities[1]);
                    child.known.extend(identities);
                }
            }
        }
        if target.is_some() && !fault_issued && (loss || stopped) {
            let signal = if loss { libc::SIGKILL } else { libc::SIGSTOP };
            if unsafe { libc::kill(i32::try_from(child.id())?, signal) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            fault_issued = true;
        }
        if stopped
            && fault_issued
            && !stopped_deadline_proved
            && clock()?.saturating_sub(started) >= 500_000_000
        {
            stopped_deadline_proved = target.is_some_and(|known| {
                identity(known.pid).is_ok_and(|actual| {
                    actual.is_none_or(|actual| {
                        actual.birth_seconds != known.birth_seconds
                            || actual.birth_microseconds != known.birth_microseconds
                            || actual.state == libc::SZOMB
                    })
                })
            });
            unsafe {
                libc::kill(i32::try_from(child.id())?, libc::SIGCONT);
            }
            if !stopped_deadline_proved {
                break;
            }
        }
        if let Some(value) = child.try_wait()? {
            status = Some(value);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let elapsed = clock()?.saturating_sub(started);
    let expired = status.is_none();
    helper_identities.extend([target, guardian].into_iter().flatten());
    if loss && status.is_some() {
        let cleanup_boundary = started
            .checked_add(4_250_000_000)
            .ok_or("cleanup clock overflow")?;
        while clock()? < cleanup_boundary
            && helper_identities
                .iter()
                .any(|known| same_identity(*known).unwrap_or(true))
        {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let observed_target = if zero_budget {
        target.is_none() && !marker.exists()
    } else {
        target.is_some() && guardian.is_some()
    };
    let native_retired = observed_target
        && helper_identities
            .iter()
            .all(|known| same_identity(*known).is_ok_and(|present| !present));
    if expired {
        let _ = child.kill();
    }
    let teardown = clock()?
        .checked_add(2_000_000_000)
        .ok_or("teardown clock overflow")?;
    // Evidence identities are independently checked against native birth times
    // before signalling. Unavailable identity never means an empty workload.
    for known in helper_identities.iter().copied() {
        if same_identity(known)? {
            unsafe {
                libc::kill(known.pid, libc::SIGKILL);
            }
        }
    }
    while status.is_none() && clock()? < teardown {
        status = child.try_wait()?;
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut cleanup = observed_target && status.is_some();
    for known in helper_identities.iter().copied() {
        while same_identity(known)? && clock()? < teardown {
            std::thread::sleep(Duration::from_millis(5));
        }
        cleanup &= !same_identity(known)?;
    }
    stdout.drain()?;
    stderr.drain()?;
    let passed = !expired
        && elapsed <= 5_250_000_000
        && status.is_some_and(|value| {
            if loss {
                value.signal() == Some(libc::SIGKILL)
            } else {
                value.code() == Some(expected)
            }
        })
        && stopped_deadline_proved
        && (!(loss || stopped) || fault_issued)
        && cleanup
        && native_retired;
    let observation = Observation {
        schema_version: 1,
        scenario: name,
        frontend_status: status.and_then(|value| value.code()),
        frontend_signal: status.and_then(|value| value.signal()),
        elapsed_milliseconds: elapsed / 1_000_000,
        outer_expired: expired,
        independently_confirmed_cleanup: cleanup,
        observed_helper_identities: helper_identities,
        stdout_bytes: stdout.count,
        stderr_bytes: stderr.count,
        stdout_retained: stdout.head,
        stderr_retained: stderr.head,
        passed,
    };
    let mut bytes = serde_json::to_vec_pretty(&observation)?;
    bytes.push(b'\n');
    fs::write(directory.join("oracle.json"), bytes)?;
    Ok(passed)
}

fn fixture(mode: &str, marker: &Path) -> Result<()> {
    let own = identity(unsafe { libc::getpid() })?.ok_or("fixture identity unavailable")?;
    let parent = identity(unsafe { libc::getppid() })?.ok_or("custodian identity unavailable")?;
    fs::write(marker, serde_json::to_vec(&[own, parent])?)?;
    match mode {
        "sleep" => loop {
            std::thread::sleep(Duration::from_secs(1));
        },
        "blocked-stderr" => {
            let buffer = [b'x'; 8192];
            loop {
                io::stderr().write_all(&buffer)?;
            }
        }
        _ => Err("unknown oracle fixture".into()),
    }
}

pub(super) fn run() -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments.as_slice() == [OsString::from("--deadline-vectors")] {
        let observations = validate_deadline_vectors()?;
        serde_json::to_writer(std::io::stdout(), &observations)?;
        println!();
        return Ok(());
    }
    if arguments.first().is_some_and(|value| value == "--fixture") && arguments.len() == 3 {
        return fixture(
            arguments[1].to_str().ok_or("invalid fixture mode")?,
            Path::new(&arguments[2]),
        );
    }
    if arguments.len() != 2 {
        return Err("usage: memcordon-deadline-oracle MEMCORDON EVIDENCE-DIRECTORY".into());
    }
    let executable = PathBuf::from(&arguments[0]);
    let evidence = PathBuf::from(&arguments[1]);
    fs::create_dir_all(&evidence)?;
    fs::write(
        evidence.join("deadline-vectors.json"),
        serde_json::to_vec_pretty(&validate_deadline_vectors()?)?,
    )?;
    fs::write(
        evidence.join("begin.json"),
        b"{\"schema_version\":1,\"status\":\"started\"}\n",
    )?;
    let mut passed = true;
    for (name, fixture, expected) in [
        ("deadline", "sleep", 123),
        ("blocked-stderr", "blocked-stderr", 125),
        ("zero-budget", "zero-budget", 123),
        ("frontend-stopped", "frontend-stopped", 123),
        ("frontend-loss", "frontend-loss", 125),
    ] {
        passed &= scenario(&executable, &evidence, name, fixture, expected)?;
    }
    fs::write(
        evidence.join("final.json"),
        if passed {
            b"{\"passed\":true}\n".as_slice()
        } else {
            b"{\"passed\":false}\n".as_slice()
        },
    )?;
    if passed {
        Ok(())
    } else {
        Err("independent deadline contract failed; inspect oracle evidence".into())
    }
}
