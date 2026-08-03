use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use memcordon_core::{
    ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary, CommandSpec, Enforcement,
    Error, ErrorCategory, Interruption, Lifetime, LimitEvidence, Policy, RunOutcome, SwapPolicy,
};

use crate::backend::{BackendInfo, Execution, ProbeReport, UnavailableBackend};
use crate::guardian::Guardian;
use crate::signal::SignalSource;

const CLEANUP_DEADLINE: Duration = Duration::from_secs(5);

pub fn probe() -> ProbeReport {
    match delegated_parent() {
        Ok(path) => {
            if let Err(error) = probe_delegated_parent(&path) {
                return unavailable(error);
            }
            let backend = info();
            ProbeReport {
                selected: Some(backend.clone()),
                available: vec![backend],
                unavailable: Vec::new(),
            }
        }
        Err(error) => unavailable(error),
    }
}

fn probe_delegated_parent(parent: &Path) -> Result<(), String> {
    let child = create_cgroup(parent).map_err(|error| {
        format!(
            "cannot create a probe cgroup under {}: {error}",
            parent.display()
        )
    })?;
    let controls = check_probe_cgroup(&child);
    let removal = fs::remove_dir(&child).map_err(|error| {
        format!(
            "cannot remove the empty probe cgroup {}: {error}",
            child.display()
        )
    });
    match (controls, removal) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(check_error), Err(removal_error)) => Err(format!("{check_error}; {removal_error}")),
    }
}

fn check_probe_cgroup(path: &Path) -> Result<(), String> {
    let required = [
        "cgroup.procs",
        "cgroup.events",
        "cgroup.kill",
        "memory.current",
        "memory.events",
        "memory.max",
        "memory.swap.max",
    ];
    if let Some(missing) = required.iter().find(|name| !path.join(name).exists()) {
        return Err(format!("probe cgroup {} lacks {missing}", path.display()));
    }
    for readable in [
        "cgroup.procs",
        "cgroup.events",
        "memory.current",
        "memory.events",
        "memory.max",
    ] {
        fs::read_to_string(path.join(readable)).map_err(|error| {
            format!(
                "cannot read {readable} in probe cgroup {}: {error}",
                path.display()
            )
        })?;
    }
    fs::write(path.join("memory.max"), "max\n").map_err(|error| {
        format!(
            "cannot write memory.max in probe cgroup {}: {error}",
            path.display()
        )
    })?;
    let memory_max = fs::read_to_string(path.join("memory.max")).map_err(|error| {
        format!(
            "cannot read back memory.max in probe cgroup {}: {error}",
            path.display()
        )
    })?;
    if memory_max.trim() != "max" {
        return Err(format!(
            "memory.max read-back in probe cgroup {} was {memory_max:?}",
            path.display()
        ));
    }
    fs::write(path.join("memory.swap.max"), "0\n").map_err(|error| {
        format!(
            "cannot write memory.swap.max in probe cgroup {}: {error}",
            path.display()
        )
    })?;
    let memory_swap_max = fs::read_to_string(path.join("memory.swap.max")).map_err(|error| {
        format!(
            "cannot read back memory.swap.max in probe cgroup {}: {error}",
            path.display()
        )
    })?;
    if memory_swap_max.trim() != "0" {
        return Err(format!(
            "memory.swap.max read-back in probe cgroup {} was {memory_swap_max:?}",
            path.display()
        ));
    }
    Ok(())
}

fn unavailable(reason: String) -> ProbeReport {
    ProbeReport {
        selected: None,
        available: Vec::new(),
        unavailable: vec![UnavailableBackend {
            name: "linux-cgroup-v2",
            reason,
        }],
    }
}

pub fn cleanup_stale(dry_run: bool) -> Result<Vec<String>, Error> {
    let parent = delegated_parent().map_err(|message| {
        Error::new(
            ErrorCategory::Setup,
            "MCSETUP-CGROUP-NOT-DELEGATED",
            message,
        )
    })?;
    // SAFETY: geteuid has no preconditions.
    let prefix = format!("memcordon-{}-", unsafe { libc::geteuid() });
    let entries = fs::read_dir(&parent).map_err(setup_io)?;
    let mut cleaned = Vec::new();
    for entry in entries {
        let entry = entry.map_err(setup_io)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(&prefix) || !entry.file_type().map_err(setup_io)?.is_dir() {
            continue;
        }
        let path = entry.path();
        if !path.join("memory.max").exists() || !path.join("cgroup.events").exists() {
            continue;
        }
        let populated =
            parse_key_values(&fs::read_to_string(path.join("cgroup.events")).map_err(setup_io)?)
                .map_err(setup_io)?
                .get("populated")
                .copied()
                .unwrap_or(0)
                != 0;
        if populated {
            // Cleanup never kills or removes a live cgroup merely because its name matches.
            continue;
        }
        if !dry_run {
            fs::remove_dir(&path).map_err(setup_io)?;
        }
        cleaned.push(path.display().to_string());
    }
    Ok(cleaned)
}

fn info() -> BackendInfo {
    BackendInfo {
        name: "linux-cgroup-v2",
        class: "hard",
        metric: "linux-cgroup-memory",
        hard_limit: true,
        startup_containment: "gated launcher assigned to cgroup before target exec",
        limitations: vec![
            "requires delegated cgroup v2 memory controller",
            "kernel may temporarily report memory.current above memory.max",
            "swap accounting is a separate policy",
        ],
    }
}

pub fn run(policy: Policy, command: &CommandSpec) -> Result<Execution, Error> {
    if policy.enforcement == Enforcement::Watchdog {
        return Err(Error::new(
            ErrorCategory::Unsupported,
            "MCUNSUPPORTED-LINUX-WATCHDOG",
            "the Linux sampled watchdog is not enabled; no target was launched",
        ));
    }
    let started = Instant::now();
    let signal_source = SignalSource::install().map_err(setup_io)?;
    let parent = delegated_parent().map_err(|message| {
        Error::new(
            ErrorCategory::Setup,
            "MCSETUP-CGROUP-NOT-DELEGATED",
            message,
        )
    })?;
    let path = create_cgroup(&parent).map_err(setup_io)?;
    let mut cgroup = Cgroup { path };
    cgroup.configure(&policy).map_err(setup_io)?;
    let baseline = cgroup.memory_events().map_err(setup_io)?;
    let (mut child, release_fd) = spawn_gated(command)?;
    let child_pid = i32::try_from(child.id()).map_err(|_| {
        Error::new(
            ErrorCategory::Spawn,
            "MCSPAWN-PID-RANGE",
            "child PID cannot be represented by native APIs",
        )
    })?;
    if let Err(error) = cgroup
        .assign(child_pid)
        .and_then(|()| cgroup.verify(child_pid))
    {
        abort_gated(&mut child, release_fd);
        return Err(setup_io(error));
    }
    let guardian = match Guardian::spawn(child_pid) {
        Ok(guardian) => guardian,
        Err(error) => {
            abort_gated(&mut child, release_fd);
            return Err(setup_io(error));
        }
    };
    if let Err(error) = release_launcher(release_fd) {
        let mut stored = None;
        let _ = cgroup.cleanup_workload(&mut child, &mut stored, true);
        let _ = guardian.disarm();
        return Err(setup_io(error));
    }
    let monitor_failure_ready = monitor_failure_ready_file(command);
    let mut stored = None;
    let mut peak = 0_u64;
    let mut outcome = loop {
        let direct_status = match try_reap(&mut child, &mut stored) {
            Ok(status) => status,
            Err(error) => {
                let cleanup = cgroup.cleanup_workload(&mut child, &mut stored, true);
                break RunOutcome::MonitorFailed {
                    error: format!("direct-child wait failed: {error}"),
                    child_after_termination: stored.clone(),
                    cleanup,
                };
            }
        };

        let events = match cgroup.memory_events() {
            Ok(events) => events,
            Err(error) => {
                let cleanup = cgroup.cleanup_workload(&mut child, &mut stored, true);
                break RunOutcome::MonitorFailed {
                    error: format!("memory.events read failed: {error}"),
                    child_after_termination: stored.clone(),
                    cleanup,
                };
            }
        };
        // A cgroup OOM can reap the direct child before the next monitor pass. Collect the
        // authoritative kernel event before classifying that stored SIGKILL as an ordinary exit.
        if let Some(mut detail) = limit_delta(&baseline, &events) {
            let observed = match cgroup.current(monitor_failure_ready.as_deref()) {
                Ok(usage) => {
                    peak = peak.max(usage);
                    Some(ByteSize::from_bytes(usage))
                }
                Err(error) => {
                    detail.push_str("; memory.current unavailable after confirmed limit: ");
                    detail.push_str(&error.to_string());
                    None
                }
            };
            if !policy.limit_grace.is_zero() {
                cgroup.signal_group(child_pid, libc::SIGTERM);
                thread::sleep(policy.limit_grace);
            }
            let cleanup = cgroup.cleanup_workload(&mut child, &mut stored, true);
            break RunOutcome::LimitExceeded {
                limit: policy.memory,
                observed,
                peak: Some(ByteSize::from_bytes(
                    cgroup.peak().unwrap_or(peak).max(peak),
                )),
                evidence: LimitEvidence {
                    backend: "linux-cgroup-v2".to_owned(),
                    metric: "linux-cgroup-memory".to_owned(),
                    detail,
                },
                child_after_termination: stored.clone(),
                cleanup,
            };
        }

        match direct_status {
            Some(status)
                if policy.lifetime == Lifetime::Command || !cgroup.populated().unwrap_or(true) =>
            {
                let cleanup = if policy.lifetime == Lifetime::Workload {
                    CleanupSummary {
                        direct_child_reaped: true,
                        workload_empty: Some(true),
                        ..CleanupSummary::default()
                    }
                } else {
                    cgroup.cleanup_workload(&mut child, &mut stored, false)
                };
                break RunOutcome::Exited {
                    child: status,
                    peak: Some(ByteSize::from_bytes(
                        cgroup.peak().unwrap_or(peak).max(peak),
                    )),
                    cleanup,
                };
            }
            _ => {}
        }

        if let Some(signal) = signal_source.take() {
            cgroup.signal_group(child_pid, signal);
            if !policy.signal_grace.is_zero() {
                thread::sleep(policy.signal_grace);
            }
            let cleanup = cgroup.cleanup_workload(&mut child, &mut stored, true);
            break RunOutcome::Interrupted {
                signal: Interruption { signal },
                child_after_termination: stored.clone(),
                cleanup,
            };
        }

        let usage = match cgroup.current(monitor_failure_ready.as_deref()) {
            Ok(usage) => usage,
            Err(error) => {
                let cleanup = cgroup.cleanup_workload(&mut child, &mut stored, true);
                break RunOutcome::MonitorFailed {
                    error: format!("memory.current read failed: {error}"),
                    child_after_termination: stored.clone(),
                    cleanup,
                };
            }
        };
        peak = peak.max(usage);
        thread::sleep(policy.poll_interval);
    };

    if let Err(error) = guardian.disarm() {
        outcome.cleanup_mut().errors.push(CleanupErrorRecord {
            operation: "guardian-disarm".to_owned(),
            message: error.to_string(),
        });
    }
    if let Err(error) = cgroup.remove() {
        outcome.cleanup_mut().errors.push(CleanupErrorRecord {
            operation: "remove-cgroup".to_owned(),
            message: error.to_string(),
        });
    }
    Ok(Execution {
        outcome,
        backend: info(),
        child_pid: u32::try_from(child_pid).unwrap_or_default(),
        duration: started.elapsed(),
    })
}

fn delegated_parent() -> Result<PathBuf, String> {
    let mount = Path::new("/sys/fs/cgroup");
    fs::read_to_string(mount.join("cgroup.controllers"))
        .map_err(|error| format!("cgroup v2 unified hierarchy unavailable: {error}"))?;
    let membership = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("cannot read process cgroup membership: {error}"))?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "process is not in a unified cgroup v2 hierarchy".to_owned())?;
    let current = mount.join(relative.trim_start_matches('/'));
    let mut ancestor = current.parent();
    while let Some(candidate) = ancestor {
        if candidate == mount {
            break;
        }
        if has_systemd_delegate_marker(candidate)? {
            prepare_delegated_root(candidate)?;
            return Ok(candidate.to_path_buf());
        }
        ancestor = candidate.parent();
    }
    Err(format!(
        "process cgroup {} is not below a marked systemd delegation boundary",
        current.display()
    ))
}

fn has_systemd_delegate_marker(path: &Path) -> Result<bool, String> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "cgroup path {} contains an interior NUL byte",
            path.display()
        )
    })?;
    let mut value = [0_u8; 16];
    // SAFETY: both C strings are NUL-terminated and `value` is writable for its full length.
    let length = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"user.delegate".as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENODATA) {
            return Ok(false);
        }
        return Err(format!(
            "cannot inspect systemd delegation marker on {}: {error}",
            path.to_string_lossy()
        ));
    }
    let length = usize::try_from(length)
        .map_err(|_| "systemd delegation marker length is invalid".to_owned())?;
    Ok(value.get(..length) == Some(b"1"))
}

fn prepare_delegated_root(path: &Path) -> Result<(), String> {
    let members = fs::read_to_string(path.join("cgroup.procs")).map_err(|error| {
        format!(
            "cannot read delegation-root membership at {}: {error}",
            path.display()
        )
    })?;
    if !members.trim().is_empty() {
        return Err(format!(
            "systemd delegation root {} contains processes",
            path.display()
        ));
    }
    let controllers = fs::read_to_string(path.join("cgroup.controllers")).map_err(|error| {
        format!(
            "cannot read delegated controllers at {}: {error}",
            path.display()
        )
    })?;
    if !controllers.split_whitespace().any(|item| item == "memory") {
        return Err(format!(
            "systemd delegation root {} does not delegate the memory controller",
            path.display()
        ));
    }
    let subtree_control = path.join("cgroup.subtree_control");
    let enabled = fs::read_to_string(&subtree_control).map_err(|error| {
        format!(
            "cannot read cgroup.subtree_control at {}: {error}",
            path.display()
        )
    })?;
    if !enabled.split_whitespace().any(|item| item == "memory") {
        fs::write(&subtree_control, "+memory\n").map_err(|error| {
            format!(
                "cannot enable memory controller at systemd delegation root {}: {error}",
                path.display()
            )
        })?;
    }
    let enabled = fs::read_to_string(&subtree_control).map_err(|error| {
        format!(
            "cannot verify cgroup.subtree_control at {}: {error}",
            path.display()
        )
    })?;
    if !enabled.split_whitespace().any(|item| item == "memory") {
        return Err(format!(
            "memory controller did not remain enabled at systemd delegation root {}",
            path.display()
        ));
    }
    Ok(())
}

fn create_cgroup(parent: &Path) -> io::Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let path = parent.join(format!(
        "memcordon-{uid}-{}-{:x}",
        std::process::id(),
        nonce
    ));
    fs::create_dir(&path)?;
    Ok(path)
}

struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    fn configure(&self, policy: &Policy) -> io::Result<()> {
        let oom_group = self.path.join("memory.oom.group");
        if oom_group.exists() {
            fs::write(oom_group, "1\n")?;
        }
        fs::write(
            self.path.join("memory.max"),
            format!("{}\n", policy.memory.bytes()),
        )?;
        match policy.swap {
            SwapPolicy::Bytes(bytes) => {
                let swap = self.path.join("memory.swap.max");
                if !swap.exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "resolved swap policy requires memory.swap.max",
                    ));
                }
                fs::write(swap, format!("{}\n", bytes.bytes()))?;
            }
            SwapPolicy::Unlimited => {
                fs::write(self.path.join("memory.swap.max"), "max\n")?;
            }
            SwapPolicy::Host => {}
        }
        Ok(())
    }

    fn assign(&self, pid: i32) -> io::Result<()> {
        fs::write(self.path.join("cgroup.procs"), format!("{pid}\n"))
    }

    fn verify(&self, pid: i32) -> io::Result<()> {
        let members = fs::read_to_string(self.path.join("cgroup.procs"))?;
        if members.lines().any(|line| line.trim() == pid.to_string()) {
            Ok(())
        } else {
            Err(io::Error::other(
                "gated launcher cgroup assignment did not persist",
            ))
        }
    }

    fn memory_events(&self) -> io::Result<HashMap<String, u64>> {
        parse_key_values(&fs::read_to_string(self.path.join("memory.events"))?)
    }

    fn current(&self, monitor_failure_ready: Option<&Path>) -> io::Result<u64> {
        if monitor_failure_ready.is_some_and(Path::exists) {
            return Err(io::Error::other(
                "certification fixture induced a supervisor monitor read failure",
            ));
        }
        parse_u64_file(&self.path.join("memory.current"))
    }

    fn peak(&self) -> io::Result<u64> {
        parse_u64_file(&self.path.join("memory.peak"))
    }

    fn populated(&self) -> io::Result<bool> {
        Ok(
            parse_key_values(&fs::read_to_string(self.path.join("cgroup.events"))?)?
                .get("populated")
                .copied()
                .unwrap_or(0)
                != 0,
        )
    }

    fn signal_group(&self, process_group: i32, signal: i32) {
        // SAFETY: the process group was created for the gated launcher.
        unsafe {
            libc::kill(-process_group, signal);
        }
    }

    fn kill_all(&self, summary: &mut CleanupSummary) {
        let kill_file = self.path.join("cgroup.kill");
        if kill_file.exists() {
            if let Err(error) = fs::write(kill_file, "1\n") {
                summary.errors.push(cleanup_error("cgroup.kill", error));
            }
            return;
        }
        for _ in 0..20 {
            let members = match fs::read_to_string(self.path.join("cgroup.procs")) {
                Ok(members) => members,
                Err(error) => {
                    summary
                        .errors
                        .push(cleanup_error("read-cgroup.procs", error));
                    return;
                }
            };
            if members.trim().is_empty() {
                return;
            }
            for pid in members
                .lines()
                .filter_map(|line| line.trim().parse::<i32>().ok())
            {
                // SAFETY: PIDs came directly from this package-owned cgroup.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn cleanup_workload(
        &self,
        child: &mut Child,
        stored: &mut Option<ChildTermination>,
        force: bool,
    ) -> CleanupSummary {
        let mut summary = CleanupSummary {
            force_attempted: force,
            ..CleanupSummary::default()
        };
        if self.populated().unwrap_or(true) {
            summary.force_attempted = true;
            self.kill_all(&mut summary);
        }
        let deadline = Instant::now() + CLEANUP_DEADLINE;
        let mut empty = false;
        while Instant::now() < deadline {
            match self.populated() {
                Ok(false) => {
                    empty = true;
                    break;
                }
                Ok(true) => self.kill_all(&mut summary),
                Err(error) => {
                    summary
                        .errors
                        .push(cleanup_error("verify-cgroup-empty", error));
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        summary.workload_empty = Some(empty);
        if stored.is_none() {
            match child.wait() {
                Ok(status) => *stored = Some(termination(status)),
                Err(error) => summary
                    .errors
                    .push(cleanup_error("reap-direct-child", error)),
            }
        }
        summary.direct_child_reaped = stored.is_some();
        summary
    }

    fn remove(&mut self) -> io::Result<()> {
        fs::remove_dir(&self.path)
    }
}

#[cfg(feature = "test-support")]
fn monitor_failure_ready_file(command: &CommandSpec) -> Option<PathBuf> {
    if Path::new(command.program()).file_name()?.to_str()? != "memcordon-test-fixture"
        || command.arguments().first()?.to_str()? != "monitor-failure"
        || command.arguments().get(1)?.to_str()? != "--pid-file"
    {
        return None;
    }
    command.arguments().get(2).map(PathBuf::from)
}

#[cfg(not(feature = "test-support"))]
fn monitor_failure_ready_file(_command: &CommandSpec) -> Option<PathBuf> {
    None
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if self.path.exists() {
            let mut summary = CleanupSummary::default();
            self.kill_all(&mut summary);
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn spawn_gated(command: &CommandSpec) -> Result<(Child, RawFd), Error> {
    let mut descriptors = [0_i32; 2];
    // SAFETY: storage is valid for two descriptors.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(setup_io(io::Error::last_os_error()));
    }
    // The launcher must not retain the parent's write end after exec.
    // SAFETY: the descriptor came from `pipe`.
    if unsafe { libc::fcntl(descriptors[1], libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        let error = io::Error::last_os_error();
        close_pair(descriptors);
        return Err(setup_io(error));
    }
    let mut builder = Command::new(std::env::current_exe().map_err(setup_io)?);
    // Establish the launcher's process group in the child before exec. A parent-side setpgid
    // after Command::spawn returns is too late because the launcher executable has already run.
    builder
        .process_group(0)
        .arg("__launcher")
        .arg(descriptors[0].to_string())
        .arg("--")
        .arg(command.program())
        .args(command.arguments());
    match builder.spawn() {
        Ok(child) => {
            // SAFETY: only the child uses the read end after successful spawn.
            unsafe {
                libc::close(descriptors[0]);
            }
            Ok((child, descriptors[1]))
        }
        Err(error) => {
            close_pair(descriptors);
            Err(spawn_error(error, command))
        }
    }
}

fn release_launcher(descriptor: RawFd) -> io::Result<()> {
    let marker = 1_u8;
    // SAFETY: descriptor is the owned write end and marker is readable for one byte.
    let result = unsafe { libc::write(descriptor, (&raw const marker).cast(), 1) };
    // SAFETY: release descriptor is consumed exactly once.
    unsafe {
        libc::close(descriptor);
    }
    if result == 1 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn abort_gated(child: &mut Child, release_fd: RawFd) {
    // SAFETY: closing without a release byte makes the launcher exit without target exec.
    unsafe {
        libc::close(release_fd);
        libc::kill(i32::try_from(child.id()).unwrap_or_default(), libc::SIGKILL);
    }
    let _ = child.wait();
}

fn close_pair(descriptors: [RawFd; 2]) {
    // SAFETY: both descriptors came from the same successful pipe call.
    unsafe {
        libc::close(descriptors[0]);
        libc::close(descriptors[1]);
    }
}

fn try_reap(
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
) -> io::Result<Option<ChildTermination>> {
    if let Some(status) = stored.clone() {
        return Ok(Some(status));
    }
    child.try_wait().map(|status| {
        status.map(|status| {
            let status = termination(status);
            *stored = Some(status.clone());
            status
        })
    })
}

fn termination(status: ExitStatus) -> ChildTermination {
    if let Some(code) = status.code() {
        ChildTermination::ExitCode { code }
    } else if let Some(signal) = status.signal() {
        ChildTermination::UnixSignal { signal }
    } else {
        ChildTermination::Unavailable
    }
}

fn limit_delta(baseline: &HashMap<String, u64>, current: &HashMap<String, u64>) -> Option<String> {
    ["max", "oom", "oom_kill", "oom_group_kill"]
        .into_iter()
        .find(|key| {
            current.get(*key).copied().unwrap_or(0) > baseline.get(*key).copied().unwrap_or(0)
        })
        .map(|key| {
            format!(
                "memory.events {key} increased from {} to {}",
                baseline.get(key).copied().unwrap_or(0),
                current.get(key).copied().unwrap_or(0)
            )
        })
}

fn parse_key_values(input: &str) -> io::Result<HashMap<String, u64>> {
    input
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields
                .next()
                .ok_or_else(|| io::Error::other("missing cgroup counter name"))?;
            let value = fields
                .next()
                .ok_or_else(|| io::Error::other("missing cgroup counter value"))?
                .parse()
                .map_err(|error| io::Error::other(format!("invalid cgroup counter: {error}")))?;
            Ok((key.to_owned(), value))
        })
        .collect()
}

fn parse_u64_file(path: &Path) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|error| io::Error::other(format!("invalid value in {}: {error}", path.display())))
}

fn setup_io(error: io::Error) -> Error {
    Error::new(ErrorCategory::Setup, "MCSETUP-CGROUP", error.to_string()).with_os_error(&error)
}

fn spawn_error(error: io::Error, command: &CommandSpec) -> Error {
    Error::new(
        ErrorCategory::Spawn,
        if error.kind() == io::ErrorKind::NotFound {
            "MCSPAWN-NOT-FOUND"
        } else if error.kind() == io::ErrorKind::PermissionDenied {
            "MCSPAWN-NOT-EXECUTABLE"
        } else {
            "MCSPAWN-FAILED"
        },
        format!(
            "could not launch gated command {}: {error}",
            command.program().to_string_lossy()
        ),
    )
    .with_os_error(&error)
}

fn cleanup_error(operation: &str, error: io::Error) -> CleanupErrorRecord {
    CleanupErrorRecord {
        operation: operation.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use memcordon_core::{ByteSize, Policy};
    use tempfile::TempDir;

    use super::{Cgroup, limit_delta};

    #[test]
    fn limit_evidence_requires_counter_delta() {
        let baseline = HashMap::from([("max".to_owned(), 4)]);
        assert!(limit_delta(&baseline, &baseline).is_none());
        let current = HashMap::from([("max".to_owned(), 5)]);
        assert!(limit_delta(&baseline, &current).is_some());
    }

    #[test]
    fn cgroup_controls_are_written_exactly() {
        let temporary = TempDir::new().expect("temporary cgroup should exist");
        for control in ["memory.oom.group", "memory.max", "memory.swap.max"] {
            fs::write(temporary.path().join(control), b"").expect("control should exist");
        }
        let cgroup = Cgroup {
            path: temporary.path().to_path_buf(),
        };
        let expected_limit = ByteSize::from_bytes(192 * 1024 * 1024);
        let policy = Policy::new(expected_limit);
        cgroup
            .configure(&policy)
            .expect("controls should configure");
        assert_eq!(
            fs::read_to_string(temporary.path().join("memory.max")).expect("memory.max"),
            format!("{}\n", expected_limit.bytes())
        );
        assert_eq!(
            fs::read_to_string(temporary.path().join("memory.swap.max")).expect("memory.swap.max"),
            "0\n"
        );
        assert_eq!(
            fs::read_to_string(temporary.path().join("memory.oom.group"))
                .expect("memory.oom.group"),
            "1\n"
        );
    }

    #[test]
    fn monitor_file_errors_are_reported_instead_of_treated_as_success() {
        let temporary = TempDir::new().expect("temporary cgroup should exist");
        let cgroup = Cgroup {
            path: temporary.path().to_path_buf(),
        };
        assert!(cgroup.current(None).is_err());
        assert!(cgroup.memory_events().is_err());
        assert!(cgroup.populated().is_err());
    }

    #[test]
    fn cgroup_identity_verification_rejects_the_wrong_process() {
        let temporary = TempDir::new().expect("temporary cgroup should exist");
        fs::write(temporary.path().join("cgroup.procs"), "41\n42\n")
            .expect("membership should write");
        let cgroup = Cgroup {
            path: temporary.path().to_path_buf(),
        };
        cgroup.verify(42).expect("member should verify");
        assert!(cgroup.verify(43).is_err());
    }
}
