use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Serialize;

mod evidence;
mod inventory;
mod marker;
mod process_fixture;
mod report;
mod scenario;
mod session;

use evidence::{FailureReason, SnapshotSummary};
use inventory::{NativeProcessApi, ProcessApi, ProcessIdentity, ProcessObservation, StableEmpty};
use marker::{MarkerState, TargetMarker};
use scenario::{ExpectedExit, ObservedLifecycle, RequiredLifecycle, SCENARIOS, ScenarioSpec};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(test)]
#[path = "../tests/native/mod.rs"]
mod tests;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const TEARDOWN_BOUND: Duration = Duration::from_secs(3);
const STOPPED_OBSERVATION_GRACE: Duration = Duration::from_millis(500);

struct FrontendOwner {
    child: Child,
    session_id: i32,
    session_confirmed: bool,
    known: BTreeSet<ProcessIdentity>,
    native_observations: BTreeMap<ProcessIdentity, ProcessObservation>,
    reaped: bool,
    teardown_done: bool,
}

impl FrontendOwner {
    fn confirm_session(&mut self, deadline: u64) -> Result<()> {
        if self.session_confirmed {
            return Ok(());
        }
        while clock()? < deadline {
            if let Some(frontend) = NativeProcessApi.observation(self.session_id)? {
                if frontend.session_id == self.session_id && frontend.state == libc::SSTOP {
                    self.known.insert(frontend.identity);
                    self.native_observations.insert(frontend.identity, frontend);
                    self.signal(frontend.identity, libc::SIGCONT)?;
                    self.session_confirmed = true;
                    return Ok(());
                }
            }
            if self.poll_status()?.is_some() {
                return Err("session launcher exited before native confirmation".into());
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        Err("dedicated frontend session was not established".into())
    }

    fn snapshot(&mut self) -> io::Result<inventory::SessionSnapshot> {
        self.snapshot_with(&NativeProcessApi)
    }

    fn snapshot_with(&mut self, api: &impl ProcessApi) -> io::Result<inventory::SessionSnapshot> {
        let snapshot = inventory::session_snapshot(api, self.session_id)?;
        self.known
            .extend(snapshot.members.iter().map(|value| value.identity));
        for member in &snapshot.members {
            self.native_observations
                .entry(member.identity)
                .or_insert(*member);
        }
        Ok(snapshot)
    }

    fn poll_status(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    fn signal(&self, identity: ProcessIdentity, signal: i32) -> io::Result<()> {
        self.signal_with(&NativeProcessApi, identity, signal)
    }

    fn signal_with(
        &self,
        api: &impl ProcessApi,
        identity: ProcessIdentity,
        signal: i32,
    ) -> io::Result<()> {
        if inventory::same_identity(api, identity)?
            && unsafe { libc::kill(identity.pid, signal) } != 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn teardown(&mut self) -> (bool, Vec<FailureReason>) {
        self.teardown_with(&NativeProcessApi)
    }

    fn teardown_with(&mut self, api: &impl ProcessApi) -> (bool, Vec<FailureReason>) {
        let mut failures = Vec::new();
        let boundary = Instant::now() + TEARDOWN_BOUND;
        // The child handle is still owned until reaped, so its PID cannot be reused.
        if !self.reaped {
            unsafe {
                libc::kill(self.session_id, libc::SIGCONT);
            }
            if let Err(error) = self.child.kill() {
                failures.push(FailureReason::new("teardown-frontend", error));
            }
        }
        let mut empty = StableEmpty::default();
        while Instant::now() < boundary {
            if let Err(error) = self.poll_status() {
                failures.push(FailureReason::new("teardown-wait", error));
            }
            let snapshot = match self.snapshot_with(api) {
                Ok(snapshot) => Some(snapshot),
                Err(error) => {
                    failures.push(FailureReason::new("teardown-inventory", error));
                    None
                }
            };
            let mut live = false;
            for identity in self.known.iter().copied() {
                match inventory::same_identity(api, identity) {
                    Ok(true) => {
                        live = true;
                        if let Err(error) = self.signal_with(api, identity, libc::SIGKILL) {
                            failures.push(FailureReason::new("teardown-signal", error));
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        live = true;
                        failures.push(FailureReason::new("teardown-identity", error));
                    }
                }
            }
            let stable = snapshot
                .as_ref()
                .is_some_and(|snapshot| empty.observe(snapshot, Instant::now()));
            if snapshot.is_none() {
                empty = StableEmpty::default();
            }
            if stable && !live && self.reaped {
                self.teardown_done = true;
                return (failures.is_empty(), failures);
            }
            // Bound repeated native errors while preserving each distinct failure.
            failures.dedup_by(|left, right| left.kind == right.kind && left.detail == right.detail);
            failures.truncate(64);
            std::thread::sleep(POLL_INTERVAL);
        }
        failures.push(FailureReason::new(
            "teardown-incomplete",
            "bounded native cleanup did not complete",
        ));
        (false, failures)
    }
}

impl Drop for FrontendOwner {
    fn drop(&mut self) {
        if !self.teardown_done {
            let _ = self.teardown();
        }
    }
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
    u64::try_from(u128::from(ticks) * u128::from(info.numer) / u128::from(info.denom))
        .map_err(io::Error::other)
}

#[derive(Serialize)]
struct Observation {
    schema_version: u32,
    scenario: &'static str,
    required_lifecycle: RequiredLifecycle,
    observed_lifecycle: Option<ObservedLifecycle>,
    scenario_exercised: bool,
    work_budget: Option<&'static str>,
    startup_gate_milliseconds: Option<u64>,
    marker_observed_offset_milliseconds: Option<u64>,
    session_id: Option<i32>,
    session_snapshots: Vec<SnapshotSummary>,
    stable_empty_snapshots: usize,
    marker_state: &'static str,
    marker_native_identities_confirmed: bool,
    report_proof: Option<report::ReportProof>,
    pre_intervention_retirement_confirmed: bool,
    live_identities_before_teardown: Vec<ProcessIdentity>,
    teardown_complete: bool,
    failure_reasons: Vec<FailureReason>,
    frontend_status: Option<i32>,
    frontend_signal: Option<i32>,
    elapsed_milliseconds: u64,
    outer_expired: bool,
    independently_confirmed_cleanup: bool,
    observed_helper_identities: Vec<ProcessIdentity>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_retained: Vec<u8>,
    stderr_retained: Vec<u8>,
    fault_issued: bool,
    stopped_deadline_proved: bool,
    proof_scope: &'static str,
    passed: bool,
}

impl Observation {
    fn finish(&mut self) {
        self.independently_confirmed_cleanup = self.pre_intervention_retirement_confirmed;
        self.passed = self.failure_reasons.is_empty()
            && self.scenario_exercised
            && self.pre_intervention_retirement_confirmed
            && self.teardown_complete
            && self.stopped_deadline_proved;
    }

    fn new(spec: ScenarioSpec) -> Self {
        Self {
            schema_version: 2,
            scenario: spec.name,
            required_lifecycle: spec.required_lifecycle,
            observed_lifecycle: None,
            scenario_exercised: false,
            work_budget: spec.budget.token(),
            startup_gate_milliseconds: spec.startup_gate.map(duration_ms),
            marker_observed_offset_milliseconds: None,
            session_id: None,
            session_snapshots: Vec::new(),
            stable_empty_snapshots: 0,
            marker_state: "missing",
            marker_native_identities_confirmed: false,
            report_proof: None,
            pre_intervention_retirement_confirmed: false,
            live_identities_before_teardown: Vec::new(),
            teardown_complete: false,
            failure_reasons: Vec::new(),
            frontend_status: None,
            frontend_signal: None,
            elapsed_milliseconds: 0,
            outer_expired: false,
            independently_confirmed_cleanup: false,
            observed_helper_identities: Vec::new(),
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_retained: Vec::new(),
            stderr_retained: Vec::new(),
            fault_issued: false,
            stopped_deadline_proved: true,
            proof_scope: "complete native session snapshots plus known PID/birth identities; not sealed containment",
            passed: false,
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).expect("bounded oracle duration")
}

fn stopped_checkpoint_after_marker(marker_observed: u64, spec: ScenarioSpec) -> Result<u64> {
    let budget = spec
        .budget
        .duration()
        .ok_or("stopped scenario requires budget")?;
    let delay = budget
        .checked_add(STOPPED_OBSERVATION_GRACE)
        .ok_or("stopped checkpoint duration overflow")?;
    marker_observed
        .checked_add(u64::try_from(delay.as_nanos())?)
        .ok_or_else(|| "stopped checkpoint clock overflow".into())
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
        if let Err(mpsc::SendError(Ok(child))) = sender.send(command.spawn()) {
            let session_id = i32::try_from(child.id()).expect("native PID fits i32");
            let mut owner = FrontendOwner {
                child,
                session_id,
                session_confirmed: false,
                known: BTreeSet::new(),
                native_observations: BTreeMap::new(),
                reaped: false,
                teardown_done: false,
            };
            let _ = owner.teardown();
        }
    });
    Ok(receiver.recv_timeout(Duration::from_nanos(deadline.saturating_sub(clock()?)))??)
}

fn scenario_command(
    executable: &Path,
    spec: ScenarioSpec,
    report: &Path,
    marker: &Path,
) -> Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg(session::CONFIRMED_SESSION_EXEC_MODE)
        .arg(executable);
    if let Some(budget) = spec.budget.token() {
        command.arg(budget);
    }
    command
        .args(["--summary", "--report"])
        .arg(report)
        .arg("--")
        .arg(std::env::current_exe()?)
        .arg("--fixture")
        .arg(spec.fixture.argument())
        .arg(marker)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(command)
}

fn record_snapshot(
    owner: &mut FrontendOwner,
    started: u64,
    observation: &mut Observation,
) -> Result<inventory::SessionSnapshot> {
    let snapshot = owner.snapshot()?;
    observation.session_snapshots.push(SnapshotSummary {
        elapsed_milliseconds: clock()?.saturating_sub(started) / 1_000_000,
        complete: snapshot.complete,
        member_count: snapshot.members.len(),
        raced_pids: snapshot.raced_pids,
    });
    Ok(snapshot)
}

fn validate_native_marker(marker: &TargetMarker, owner: &mut FrontendOwner) -> Result<()> {
    marker::validate_marker(marker, owner.session_id).map_err(io::Error::other)?;
    for expected in [marker.target, marker.guardian] {
        let actual = NativeProcessApi.observation(expected.identity.pid)?;
        let historical = owner.native_observations.get(&expected.identity).copied();
        if !actual
            .is_some_and(|actual| marker_observation_matches(expected, actual, owner.session_id))
            && !historical.is_some_and(|actual| {
                marker_observation_matches(expected, actual, owner.session_id)
            })
        {
            return Err("marker native identity, session or parent mismatch".into());
        }
        if let Some(actual) =
            actual.filter(|actual| marker_observation_matches(expected, *actual, owner.session_id))
        {
            owner
                .native_observations
                .entry(actual.identity)
                .or_insert(actual);
        }
        owner.known.insert(expected.identity);
    }
    Ok(())
}

fn marker_observation_matches(
    expected: ProcessObservation,
    actual: ProcessObservation,
    session: i32,
) -> bool {
    actual.identity == expected.identity
        && actual.session_id == session
        && actual.parent_pid == expected.parent_pid
}

fn marker_read(path: &Path, observation: &mut Observation) -> Result<MarkerState> {
    let marker = marker::read_marker(path)?;
    observation.marker_state = match &marker {
        MarkerState::Missing => "missing",
        MarkerState::Valid(_) => "valid",
        MarkerState::Malformed(detail) => {
            observation
                .failure_reasons
                .push(FailureReason::new("marker-malformed", detail));
            "malformed"
        }
    };
    Ok(marker)
}

fn run_frontend(
    owner: &mut FrontendOwner,
    started: u64,
    deadline: u64,
    spec: ScenarioSpec,
    marker_path: &Path,
    report_path: &Path,
    observation: &mut Observation,
) -> Result<()> {
    let mut stdout = Capture::new(owner.child.stdout.take().ok_or("stdout pipe absent")?)?;
    let mut stderr = Capture::new(owner.child.stderr.take().ok_or("stderr pipe absent")?)?;
    let stopped = spec.injected_fault == Some(scenario::InjectedFault::StopFrontend);
    let loss = spec.injected_fault == Some(scenario::InjectedFault::KillFrontend);
    let blocked = spec.fixture == scenario::FixtureMode::BlockedStderr;
    observation.stopped_deadline_proved = !stopped;
    let mut status = None;
    let mut valid_marker = None;
    let mut stopped_checkpoint = None;
    let execution = (|| -> Result<()> {
        owner.confirm_session(deadline)?;
        while clock()? < deadline {
            record_snapshot(owner, started, observation)?;
            stdout.drain()?;
            if !blocked {
                stderr.drain()?;
            }
            if valid_marker.is_none() {
                match marker_read(marker_path, observation)? {
                    MarkerState::Valid(value) => {
                        validate_native_marker(&value, owner)?;
                        observation.marker_native_identities_confirmed = true;
                        let marker_observed = clock()?;
                        observation.marker_observed_offset_milliseconds =
                            Some(marker_observed.saturating_sub(started) / 1_000_000);
                        let marker_elapsed =
                            Duration::from_nanos(marker_observed.saturating_sub(started));
                        if spec.startup_gate.is_some_and(|gate| marker_elapsed > gate) {
                            observation.failure_reasons.push(FailureReason::new(
                                "scenario-not-exercised",
                                "valid marker arrived after startup qualification gate",
                            ));
                            return Ok(());
                        }
                        if stopped {
                            // Marker observation follows the product deadline
                            // origin; avoid guessing exec/CLI scheduling latency.
                            stopped_checkpoint =
                                Some(stopped_checkpoint_after_marker(marker_observed, spec)?);
                        }
                        valid_marker = Some(value);
                    }
                    MarkerState::Malformed(_) => return Ok(()),
                    MarkerState::Missing => {}
                }
            }
            if let Some(marker) = valid_marker
                .as_ref()
                .filter(|_| !observation.fault_issued && (loss || stopped))
            {
                for identity in [marker.target.identity, marker.guardian.identity] {
                    if !inventory::same_identity(&NativeProcessApi, identity)? {
                        return Err("target or guardian retired before fault injection".into());
                    }
                }
                let frontend = NativeProcessApi
                    .observation(owner.session_id)?
                    .ok_or("frontend absent before fault")?;
                owner.signal(
                    frontend.identity,
                    if loss { libc::SIGKILL } else { libc::SIGSTOP },
                )?;
                observation.fault_issued = true;
            }
            let now = clock()?;
            let elapsed = Duration::from_nanos(now.saturating_sub(started));
            if spec.startup_gate.is_some_and(|gate| elapsed >= gate) && valid_marker.is_none() {
                observation.failure_reasons.push(FailureReason::new(
                    "scenario-not-exercised",
                    "startup qualification marker gate missed",
                ));
                return Ok(());
            }
            if stopped
                && observation.fault_issued
                && !observation.stopped_deadline_proved
                && stopped_checkpoint.is_some_and(|checkpoint| now >= checkpoint)
            {
                let frontend = NativeProcessApi
                    .observation(owner.session_id)?
                    .ok_or("stopped frontend disappeared")?;
                if frontend.state != libc::SSTOP {
                    return Err("frontend was not stopped at deadline checkpoint".into());
                }
                let target = valid_marker
                    .as_ref()
                    .ok_or("stopped target marker missing")?
                    .target
                    .identity;
                observation.stopped_deadline_proved = NativeProcessApi
                    .observation(target.pid)?
                    .is_none_or(|actual| actual.identity != target || actual.state == libc::SZOMB);
                owner.signal(frontend.identity, libc::SIGCONT)?;
                if !observation.stopped_deadline_proved {
                    observation.failure_reasons.push(FailureReason::new(
                        "stopped-deadline-not-proved",
                        "target still running at budget plus grace",
                    ));
                    return Ok(());
                }
            }
            if let Some(value) = owner.poll_status()? {
                status = Some(value);
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        observation.elapsed_milliseconds = clock()?.saturating_sub(started) / 1_000_000;
        observation.outer_expired = status.is_none();
        if status.is_none() {
            observation.failure_reasons.push(FailureReason::new(
                "outer-deadline-expired",
                "frontend did not finish within scenario outer bound",
            ));
            return Ok(());
        }
        observation.frontend_status = status.and_then(|value| value.code());
        observation.frontend_signal = status.and_then(|value| value.signal());
        let exit_ok = status.is_some_and(|value| match spec.expected_exit {
            ExpectedExit::Code(code) => value.code() == Some(code),
            ExpectedExit::Signal(signal) => value.signal() == Some(signal),
        });
        if !exit_ok {
            observation.failure_reasons.push(FailureReason::new(
                "unexpected-exit",
                "frontend exit differs from scenario contract",
            ));
        }
        // Re-read the final marker: malformed or changed evidence is never missing.
        let final_marker = marker_read(marker_path, observation)?;
        match (&valid_marker, &final_marker) {
            (Some(prior), MarkerState::Valid(current))
                if prior.target == current.target && prior.guardian == current.guardian => {}
            (None, MarkerState::Missing) => {}
            (_, MarkerState::Malformed(_)) => {}
            _ => observation.failure_reasons.push(FailureReason::new(
                "marker-changed-or-unconfirmed",
                "final marker was not natively confirmed during execution",
            )),
        }
        if !loss {
            let bytes = fs::read(report_path)?;
            match report::classify_report(&bytes, spec) {
                Ok(proof) => {
                    observation.observed_lifecycle = Some(proof.lifecycle);
                    if !spec.required_lifecycle.accepts(proof.lifecycle) {
                        observation.failure_reasons.push(FailureReason::new(
                            "lifecycle-mismatch",
                            "observed lifecycle does not satisfy scenario requirement",
                        ));
                    }
                    match proof.lifecycle {
                        ObservedLifecycle::PreAuthorizationExpired => {
                            if !matches!(final_marker, MarkerState::Missing) {
                                observation.failure_reasons.push(FailureReason::new(
                                    "pre-authorization-marker-present",
                                    "pre-authorization path requires absent marker",
                                ));
                            }
                            observation.scenario_exercised =
                                spec.required_lifecycle != RequiredLifecycle::Authorized;
                        }
                        _ => {
                            observation.scenario_exercised =
                                observation.marker_native_identities_confirmed;
                            if valid_marker
                                .as_ref()
                                .map(|marker| marker.target.identity.pid)
                                != proof.target_pid
                            {
                                observation.failure_reasons.push(FailureReason::new(
                                    "marker-report-pid-mismatch",
                                    "authorized target PID differs from marker",
                                ));
                            }
                        }
                    }
                    observation.report_proof = Some(proof);
                }
                Err(detail) => observation
                    .failure_reasons
                    .push(FailureReason::new("report-invalid", detail)),
            }
        } else {
            observation.scenario_exercised =
                observation.marker_native_identities_confirmed && observation.fault_issued;
            observation.observed_lifecycle = observation
                .scenario_exercised
                .then_some(ObservedLifecycle::AuthorizedBeforeFrontendLoss);
        }
        if !observation.scenario_exercised {
            observation.failure_reasons.push(FailureReason::new(
                "scenario-not-exercised",
                "required lifecycle was not exercised",
            ));
        }
        if (loss || stopped) && !observation.fault_issued {
            observation.failure_reasons.push(FailureReason::new(
                "fault-not-issued",
                "required fault was not injected",
            ));
        }
        let mut empty = StableEmpty::default();
        while clock()? < deadline {
            let snapshot = record_snapshot(owner, started, observation)?;
            let mut live = Vec::new();
            for identity in owner.known.iter().copied() {
                if inventory::same_identity(&NativeProcessApi, identity)? {
                    live.push(identity);
                }
            }
            let stable = empty.observe(&snapshot, Instant::now());
            observation.stable_empty_snapshots = empty.count;
            observation.live_identities_before_teardown = live;
            if stable && observation.live_identities_before_teardown.is_empty() {
                observation.pre_intervention_retirement_confirmed = true;
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        if !observation.pre_intervention_retirement_confirmed {
            observation.failure_reasons.push(FailureReason::new(
                "pre-intervention-retirement-failed",
                "native session or known identities remained live",
            ));
        }
        Ok(())
    })();
    // Retain output even when session establishment, inventory or decoding fails.
    let stdout_result = stdout.drain();
    let stderr_result = stderr.drain();
    observation.stdout_bytes = stdout.count;
    observation.stderr_bytes = stderr.count;
    observation.stdout_retained = stdout.head;
    observation.stderr_retained = stderr.head;
    execution?;
    stdout_result?;
    stderr_result?;
    if blocked && observation.stderr_bytes < 8192 {
        observation.failure_reasons.push(FailureReason::new(
            "stderr-backpressure-not-exercised",
            "fixture did not fill its stderr pipe",
        ));
    }
    Ok(())
}

fn scenario(executable: &Path, evidence: &Path, spec: ScenarioSpec) -> Result<(bool, bool)> {
    let directory = evidence.join(spec.name);
    fs::create_dir(&directory)?;
    let mut observation = Observation::new(spec);
    let marker = directory.join("target-identity.json");
    let report = directory.join("execution.json");
    let started = clock()?;
    let deadline = started
        .checked_add(u64::try_from(spec.outer_bound.as_nanos())?)
        .ok_or("oracle clock overflow")?;
    let launch = scenario_command(executable, spec, &report, &marker)
        .and_then(|command| create_before_deadline(command, deadline));
    match launch {
        Ok(child) => {
            let session_id = i32::try_from(child.id())?;
            observation.session_id = Some(session_id);
            let mut owner = FrontendOwner {
                child,
                session_id,
                session_confirmed: false,
                known: BTreeSet::new(),
                native_observations: BTreeMap::new(),
                reaped: false,
                teardown_done: false,
            };
            if let Err(error) = run_frontend(
                &mut owner,
                started,
                deadline,
                spec,
                &marker,
                &report,
                &mut observation,
            ) {
                observation
                    .failure_reasons
                    .push(FailureReason::new("oracle-operation-failed", error));
            }
            // Freeze proof before ANY cleanup intervention. Teardown never promotes it.
            observation.independently_confirmed_cleanup =
                observation.pre_intervention_retirement_confirmed;
            observation.observed_helper_identities = owner.known.iter().copied().collect();
            let (complete, failures) = owner.teardown();
            observation.teardown_complete = complete;
            observation.failure_reasons.extend(failures);
        }
        Err(error) => observation
            .failure_reasons
            .push(FailureReason::new("launch-failed", error)),
    }
    observation.elapsed_milliseconds = clock()?.saturating_sub(started) / 1_000_000;
    observation.finish();
    marker::write_json_atomic(&directory.join("oracle.json"), &observation)?;
    Ok((observation.passed, observation.teardown_complete))
}

fn fixture(mode: &str, path: &Path) -> Result<()> {
    let own = NativeProcessApi
        .observation(unsafe { libc::getpid() })?
        .ok_or("fixture identity unavailable")?;
    let parent = NativeProcessApi
        .observation(unsafe { libc::getppid() })?
        .ok_or("custodian identity unavailable")?;
    marker::write_json_atomic(
        path,
        &TargetMarker {
            schema_version: 2,
            target: own,
            guardian: parent,
        },
    )?;
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

fn run_catalogue(executable: &Path, evidence: &Path) -> Result<bool> {
    fs::create_dir_all(evidence)?;
    marker::write_json_atomic(
        &evidence.join("begin.json"),
        &serde_json::json!({"schema_version":2,"status":"started"}),
    )?;
    let mut passed = true;
    let mut errors = Vec::new();
    for spec in SCENARIOS.iter().copied() {
        match scenario(executable, evidence, spec) {
            Ok((value, safe)) => {
                passed &= value;
                if !safe {
                    break;
                }
            }
            Err(error) => {
                passed = false;
                errors.push(FailureReason::new("scenario-evidence-error", error));
                break;
            }
        }
    }
    marker::write_json_atomic(
        &evidence.join("final.json"),
        &serde_json::json!({"schema_version":2,"passed":passed,"errors":errors}),
    )?;
    Ok(passed)
}

pub(super) fn run() -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|value| value == session::SESSION_EXEC_MODE)
    {
        return session::exec_in_new_session(&arguments[1..]);
    }
    if arguments
        .first()
        .is_some_and(|value| value == session::CONFIRMED_SESSION_EXEC_MODE)
    {
        return session::exec_confirmed_session(&arguments[1..]);
    }
    if arguments
        .first()
        .is_some_and(|value| value == "--native-fixture")
    {
        return process_fixture::run(&arguments[1..]);
    }
    if arguments.first().is_some_and(|value| value == "--fixture") && arguments.len() == 3 {
        return fixture(
            arguments[1].to_str().ok_or("invalid fixture mode")?,
            Path::new(&arguments[2]),
        );
    }
    if arguments.first().is_some_and(|value| value == "--soak") && arguments.len() == 4 {
        let count: u32 = arguments[1].to_str().ok_or("invalid soak count")?.parse()?;
        if !(1..=30).contains(&count) {
            return Err("soak count must be between one and thirty".into());
        }
        let executable = Path::new(&arguments[2]);
        let evidence = Path::new(&arguments[3]);
        fs::create_dir(evidence)?;
        let mut iterations = Vec::new();
        for iteration in 1..=count {
            let directory = evidence.join(format!("iteration-{iteration:04}"));
            let passed = run_catalogue(executable, &directory)?;
            iterations.push(serde_json::json!({"iteration":iteration,"passed":passed}));
            marker::write_json_atomic(
                &evidence.join("soak.json"),
                &serde_json::json!({"schema_version":2,"requested_iterations":count,"iterations":iterations}),
            )?;
            // Preserve the first failing iteration; no automatic retry can hide it.
            if !passed {
                return Err("deadline soak iteration failed; inspect retained evidence".into());
            }
        }
        return Ok(());
    }
    if arguments.len() != 2 {
        return Err("usage: memcordon-deadline-oracle MEMCORDON EVIDENCE-DIRECTORY".into());
    }
    let executable = PathBuf::from(&arguments[0]);
    let evidence = PathBuf::from(&arguments[1]);
    let passed = run_catalogue(&executable, &evidence)?;
    if passed {
        Ok(())
    } else {
        Err("independent deadline contract failed; inspect oracle evidence".into())
    }
}
