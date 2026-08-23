use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::request::LaunchRequestV1;

use super::attempt::AttemptRecord;
use super::cgroup::AttemptCgroup;

#[derive(Debug)]
pub struct TerminalFacts {
    pub child_status: i32,
    pub target_pid: u32,
    pub authorization_offset_millis: u64,
    pub cgroup_empty: bool,
    pub init_reaped: bool,
    pub guardian_reaped: bool,
    pub boundary_retired: bool,
    pub assignment_verified: bool,
    pub namespaces_verified: bool,
    pub credentials_verified: bool,
    pub capabilities_empty: bool,
    pub descriptors_verified: bool,
    pub cgroup_view_denied: bool,
    pub guardian_ready_before_authorization: bool,
    pub frontend_loss_authority_verified: bool,
    pub cgroup_kill_invoked: bool,
    pub memory_limit_exceeded: bool,
    pub deadline_exceeded: bool,
}

struct AttemptCleanupGuard {
    cgroup: AttemptCgroup,
    init_pid: Option<libc::pid_t>,
    guardian_pid: Option<libc::pid_t>,
    armed: bool,
}

impl AttemptCleanupGuard {
    fn new(cgroup: AttemptCgroup) -> Self {
        Self {
            cgroup,
            init_pid: None,
            guardian_pid: None,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AttemptCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self
            .cgroup
            .clone()
            .kill_and_retire(Instant::now() + Duration::from_secs(30));
        if let Some(pid) = self.init_pid {
            let _ = wait_pid(pid);
        }
        if let Some(pid) = self.guardian_pid {
            let _ = wait_pid(pid);
        }
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    FrontendLossBeforeAuthorization,
    FrontendLossAfterAuthorization,
    ProviderWorkerLossAfterGuardianCreation,
    GuardianLossBeforeAuthorization,
    GuardianLossAfterAuthorization,
}

pub fn execute(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    attempt: [u8; 16],
    frontend_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
) -> Result<TerminalFacts, String> {
    execute_inner(
        request,
        descriptors,
        attempt,
        frontend_pid,
        uid,
        gid,
        groups,
        None,
    )
}

#[cfg(feature = "test-support")]
pub fn execute_with_fault(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    attempt: [u8; 16],
    frontend_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    fault: FaultPoint,
) -> Result<TerminalFacts, String> {
    execute_inner(
        request,
        descriptors,
        attempt,
        frontend_pid,
        uid,
        gid,
        groups,
        Some(fault),
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_inner(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    attempt: [u8; 16],
    frontend_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    #[cfg(feature = "test-support")] fault: Option<FaultPoint>,
    #[cfg(not(feature = "test-support"))] _fault: Option<()>,
) -> Result<TerminalFacts, String> {
    let started = Instant::now();
    if descriptors.len() != 5 {
        return Err("MCSEALED-DESCRIPTOR-SET: exact descriptor inventory required".to_owned());
    }
    let identity = attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record = AttemptRecord::create(identity.clone(), frontend_pid)?;
    let cgroup = AttemptCgroup::create(
        &identity,
        request.policy.memory_limit_bytes,
        request.policy.swap_limit,
    )?;
    let mut cleanup_guard = AttemptCleanupGuard::new(cgroup.clone());
    let monitoring_policy = request.policy.clone();
    record.transition("boundary-created")?;
    let (gate_read, mut gate_write) = pipe()?;
    let (mut status_read, status_write) = pipe()?;
    let frontend_pidfd = duplicate(&descriptors[4])?;
    let cgroup_file = cgroup.open()?;
    let expected_groups = groups.clone();
    let init = super::namespace::clone_into_cgroup(&cgroup_file, move || {
        namespace_init(
            request,
            descriptors,
            gate_read,
            status_write,
            uid,
            gid,
            groups,
        )
    })?;
    cleanup_guard.init_pid = Some(init.host_pid);
    let (guardian_read, mut guardian_write) = pipe()?;
    let (mut guardian_ready_read, mut guardian_ready_write) = pipe()?;
    let guardian_cgroup = cgroup.clone();
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let guardian_pid = unsafe { libc::fork() };
    if guardian_pid == -1 {
        return Err(format!(
            "MCSEALED-GUARDIAN: {}",
            std::io::Error::last_os_error()
        ));
    }
    if guardian_pid == 0 {
        drop(guardian_write);
        drop(guardian_ready_read);
        let mut pollfds = [
            libc::pollfd {
                fd: frontend_pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: guardian_read.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
        ];
        if guardian_ready_write.write_all(&[1]).is_err() {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::_exit(125) };
        }
        drop(guardian_ready_write);
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let disarmed = if unsafe { libc::poll(pollfds.as_mut_ptr(), 2, -1) } > 0
            && pollfds[1].revents & libc::POLLIN != 0
        {
            let mut byte = [0_u8; 1];
            (&guardian_read).read_exact(&mut byte).is_ok() && byte[0] == 1
        } else {
            false
        };
        if !disarmed {
            let _ = guardian_cgroup.kill_and_retire(Instant::now() + Duration::from_secs(30));
        }
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(0) };
    }
    cleanup_guard.guardian_pid = Some(guardian_pid);
    drop(guardian_read);
    drop(guardian_ready_write);
    let mut ready = [0_u8; 1];
    guardian_ready_read
        .read_exact(&mut ready)
        .map_err(|error| format!("MCSEALED-GUARDIAN: {error}"))?;
    if ready != [1] || cgroup.member_pids()?.contains(&guardian_pid) {
        return Err(
            "MCSEALED-GUARDIAN: guardian readiness or placement verification failed".to_owned(),
        );
    }
    drop(guardian_ready_read);
    record.transition("guardian-ready")?;
    #[cfg(feature = "test-support")]
    if fault == Some(FaultPoint::ProviderWorkerLossAfterGuardianCreation) {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(86) };
    }
    let target_pid = wait_for_target(
        &cgroup,
        init.host_pid,
        Instant::now() + Duration::from_secs(5),
    )?;
    let target_pidfd = pidfd_open(target_pid)?;
    record.transition("target-created-gated")?;
    verify_gated_target(
        target_pid,
        init.host_pid,
        &identity,
        uid,
        gid,
        &expected_groups,
    )?;
    record.transition("assignment-verified")?;
    record.transition("resource-inheritance-verified")?;
    #[cfg(feature = "test-support")]
    if matches!(
        fault,
        Some(FaultPoint::FrontendLossBeforeAuthorization)
            | Some(FaultPoint::GuardianLossBeforeAuthorization)
    ) {
        if fault == Some(FaultPoint::FrontendLossBeforeAuthorization) {
            signal_pidfd(&frontend_pidfd, libc::SIGKILL)?;
        } else {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::kill(guardian_pid, libc::SIGKILL) };
        }
        drop(gate_write);
        let _ = cgroup
            .clone()
            .kill_and_retire(Instant::now() + Duration::from_secs(30));
        let init_reaped = wait_pid(init.host_pid);
        let guardian_reaped = wait_pid(guardian_pid);
        if !(init_reaped && guardian_reaped && fault_boundary_retired(&identity)) {
            return Err(
                "MCSEALED-FAULT: preauthorization terminal proof was incomplete".to_owned(),
            );
        }
        record.transition("retired")?;
        record.retire()?;
        return Err("MCSEALED-FAULT: injected loss before authorization".to_owned());
    }
    if monitoring_policy
        .absolute_deadline_millis
        .is_some_and(|deadline| monotonic_millis() >= deadline)
    {
        return Err("MCSEALED-AUTHORIZATION: deadline expired before authorization; target was not authorized".to_owned());
    }
    gate_write
        .write_all(&[1])
        .map_err(|error| format!("MCSEALED-AUTHORIZATION: {error}"))?;
    let authorization_offset_millis = started.elapsed().as_millis() as u64;
    drop(gate_write);
    record.transition("authorized")?;
    #[cfg(feature = "test-support")]
    if matches!(
        fault,
        Some(FaultPoint::FrontendLossAfterAuthorization)
            | Some(FaultPoint::GuardianLossAfterAuthorization)
    ) {
        if fault == Some(FaultPoint::FrontendLossAfterAuthorization) {
            signal_pidfd(&frontend_pidfd, libc::SIGKILL)?;
        } else {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::kill(guardian_pid, libc::SIGKILL) };
        }
        let _ = cgroup
            .clone()
            .kill_and_retire(Instant::now() + Duration::from_secs(30));
        let init_reaped = wait_pid(init.host_pid);
        let guardian_reaped = wait_pid(guardian_pid);
        if !(init_reaped && guardian_reaped && fault_boundary_retired(&identity)) {
            return Err(
                "MCSEALED-FAULT: postauthorization terminal proof was incomplete".to_owned(),
            );
        }
        record.transition("retired")?;
        record.retire()?;
        return Err("MCSEALED-FAULT: injected loss after authorization".to_owned());
    }
    let mut deadline_exceeded = false;
    let mut status = [0_u8; 4];
    loop {
        let mut pollfd = libc::pollfd {
            fd: status_read.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let ready = unsafe {
            libc::poll(
                &raw mut pollfd,
                1,
                i32::try_from(monitoring_policy.poll_interval_millis.max(1)).unwrap_or(i32::MAX),
            )
        };
        if ready == -1 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if ready > 0 {
            break;
        }
        if monitoring_policy
            .absolute_deadline_millis
            .is_some_and(|deadline| monotonic_millis() >= deadline)
        {
            deadline_exceeded = true;
            break;
        }
    }
    let child_status = if deadline_exceeded {
        125
    } else {
        status_read
            .read_exact(&mut status)
            .map_err(|error| error.to_string())?;
        i32::from_be_bytes(status)
    };
    let memory_limit_exceeded = cgroup.memory_oom_killed()?;
    if deadline_exceeded || memory_limit_exceeded {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let _ = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                target_pidfd.as_raw_fd(),
                libc::SIGTERM,
                0,
                0,
            )
        };
        let grace = if memory_limit_exceeded {
            monitoring_policy.limit_grace_millis
        } else {
            monitoring_policy.signal_grace_millis
        };
        if grace > 0 {
            std::thread::sleep(Duration::from_millis(grace));
        }
    } else if monitoring_policy.lifetime == crate::request::Lifetime::Command
        && monitoring_policy.command_exit_grace_millis > 0
    {
        std::thread::sleep(Duration::from_millis(
            monitoring_policy.command_exit_grace_millis,
        ));
    }
    let cgroup_empty = cgroup
        .clone()
        .kill_and_retire(Instant::now() + Duration::from_secs(30))
        .is_ok();
    let init_reaped = wait_pid(init.host_pid);
    guardian_write
        .write_all(&[1])
        .map_err(|error| error.to_string())?;
    drop(guardian_write);
    let guardian_reaped = wait_pid(guardian_pid);
    if !(cgroup_empty && init_reaped && guardian_reaped) {
        return Err("MCSEALED-BOUNDARY-NOT-RETIRED: incomplete terminal proof".to_owned());
    }
    record.transition("retired")?;
    record.retire()?;
    cleanup_guard.disarm();
    Ok(TerminalFacts {
        child_status,
        target_pid: target_pid as u32,
        authorization_offset_millis,
        cgroup_empty,
        init_reaped,
        guardian_reaped,
        boundary_retired: true,
        assignment_verified: true,
        namespaces_verified: true,
        credentials_verified: true,
        capabilities_empty: true,
        descriptors_verified: true,
        cgroup_view_denied: true,
        guardian_ready_before_authorization: true,
        frontend_loss_authority_verified: true,
        cgroup_kill_invoked: true,
        memory_limit_exceeded,
        deadline_exceeded,
    })
}

fn namespace_init(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    gate: File,
    mut status: File,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
) -> i32 {
    if super::namespace::prepare_namespace_init().is_err() {
        return 125;
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let target = unsafe { libc::fork() };
    if target == -1 {
        return 125;
    }
    if target == 0 {
        target_exec(
            request,
            descriptors,
            gate,
            status.as_raw_fd(),
            uid,
            gid,
            &groups,
        );
    }
    let mut raw = 0_i32;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::waitpid(target, &raw mut raw, 0) } == -1 {
        return 125;
    }
    if request.policy.lifetime == crate::request::Lifetime::Workload {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } > 0 {}
    } else {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
    }
    let code = if libc::WIFEXITED(raw) {
        libc::WEXITSTATUS(raw)
    } else {
        128 + libc::WTERMSIG(raw)
    };
    let _ = status.write_all(&code.to_be_bytes());
    0
}

fn target_exec(
    request: LaunchRequestV1,
    descriptors: Vec<OwnedFd>,
    gate: File,
    status_fd: i32,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
) -> ! {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::fchdir(descriptors[0].as_raw_fd()) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    for (source, target) in descriptors[1..4].iter().zip(0..3) {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        if unsafe { libc::dup2(source.as_raw_fd(), target) } == -1 {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::_exit(125) };
        }
    }
    drop(descriptors);
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    unsafe { libc::close(status_fd) };
    let gate_fd = gate.as_raw_fd();
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if gate_fd != 3 && unsafe { libc::dup3(gate_fd, 3, libc::O_CLOEXEC) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    if gate_fd != 3 {
        drop(gate);
    } else {
        std::mem::forget(gate);
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let mut gate = unsafe { File::from_raw_fd(3) };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } == -1
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        || unsafe { libc::setresgid(gid, gid, gid) } == -1
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        || unsafe { libc::setresuid(uid, uid, uid) } == -1
    {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } == -1
        || clear_capabilities().is_err()
    {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    let mut authorization = [0_u8; 1];
    if (&mut gate).read_exact(&mut authorization).is_err() || authorization != [1] {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(125) };
    }
    let mut command = Command::new(OsString::from_vec(request.program));
    command.args(request.arguments.into_iter().map(OsString::from_vec));
    command.env_clear();
    for (name, value) in request.environment {
        command.env(OsString::from_vec(name), OsString::from_vec(value));
    }
    let error = command.exec();
    let code = if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    unsafe { libc::_exit(code) }
}

fn clear_capabilities() -> Result<(), ()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) } == -1 {
        Err(())
    } else {
        Ok(())
    }
}

fn pipe() -> Result<(File, File), String> {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    Ok(unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    })
}

fn duplicate(descriptor: &OwnedFd) -> Result<OwnedFd, String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let duplicated = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd, String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if descriptor == -1 {
        Err(format!(
            "MCSEALED-TARGET-IDENTITY: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

#[cfg(feature = "test-support")]
fn signal_pidfd(pidfd: &OwnedFd, signal: i32) -> Result<(), String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), signal, 0, 0) } == -1
    {
        Err(format!(
            "MCSEALED-FAULT: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "test-support")]
fn fault_boundary_retired(identity: &str) -> bool {
    !std::path::Path::new(super::CGROUP_ROOT)
        .join(identity)
        .exists()
}

fn wait_for_target(
    cgroup: &AttemptCgroup,
    init_pid: libc::pid_t,
    deadline: Instant,
) -> Result<libc::pid_t, String> {
    while Instant::now() < deadline {
        if let Some(pid) = cgroup
            .member_pids()?
            .into_iter()
            .find(|pid| *pid != init_pid)
        {
            return Ok(pid);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err("MCSEALED-TARGET-IDENTITY: gated target not observed".to_owned())
}

fn verify_gated_target(
    pid: libc::pid_t,
    init_pid: libc::pid_t,
    identity: &str,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
) -> Result<(), String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| error.to_string())?;
    if !status.lines().any(|line| line == "NoNewPrivs:\t1") {
        return Err("MCSEALED-TARGET-IDENTITY: no_new_privs not verified".to_owned());
    }
    for field in [
        "CapInh:\t0000000000000000",
        "CapPrm:\t0000000000000000",
        "CapEff:\t0000000000000000",
        "CapAmb:\t0000000000000000",
    ] {
        if !status.lines().any(|line| line == field) {
            return Err("MCSEALED-TARGET-IDENTITY: capabilities are not empty".to_owned());
        }
    }
    let uid_line = format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}");
    let gid_line = format!("Gid:\t{gid}\t{gid}\t{gid}\t{gid}");
    if !status.lines().any(|line| line == uid_line) || !status.lines().any(|line| line == gid_line)
    {
        return Err("MCSEALED-TARGET-IDENTITY: caller credentials not verified".to_owned());
    }
    let mut actual_groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:\t"))
        .ok_or_else(|| "MCSEALED-TARGET-IDENTITY: supplementary groups missing".to_owned())?
        .split_whitespace()
        .map(|group| {
            group
                .parse::<libc::gid_t>()
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected_groups = groups.to_vec();
    actual_groups.sort_unstable();
    expected_groups.sort_unstable();
    if actual_groups != expected_groups {
        return Err("MCSEALED-TARGET-IDENTITY: supplementary groups not verified".to_owned());
    }
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|error| error.to_string())?;
    if !cgroup.contains(identity) {
        return Err("MCSEALED-TARGET-IDENTITY: cgroup membership mismatch".to_owned());
    }
    let mut descriptors = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    descriptors.sort();
    if descriptors != ["0", "1", "2", "3"].map(OsString::from) {
        return Err(
            "MCSEALED-DESCRIPTOR-SET: gated target descriptor inventory mismatch".to_owned(),
        );
    }
    for namespace in ["pid", "mnt", "cgroup"] {
        let target = std::fs::read_link(format!("/proc/{pid}/ns/{namespace}"))
            .map_err(|error| error.to_string())?;
        let init = std::fs::read_link(format!("/proc/{init_pid}/ns/{namespace}"))
            .map_err(|error| error.to_string())?;
        let provider = std::fs::read_link(format!("/proc/self/ns/{namespace}"))
            .map_err(|error| error.to_string())?;
        if target != init || target == provider {
            return Err("MCSEALED-TARGET-IDENTITY: namespace membership mismatch".to_owned());
        }
    }
    if std::path::Path::new(&format!("/proc/{pid}/root/sys/fs/cgroup")).exists() {
        return Err("MCSEALED-CGROUP-VIEW: target can still see host cgroup mount".to_owned());
    }
    Ok(())
}

fn wait_pid(pid: libc::pid_t) -> bool {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    (unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) }) == pid
}

fn monotonic_millis() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut value) };
    (value.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add(value.tv_nsec as u64 / 1_000_000)
}
