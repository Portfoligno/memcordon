#![cfg(target_os = "linux")]

use std::os::fd::{FromRawFd, OwnedFd};

#[cfg(feature = "test-support")]
use memcordon_sealed_agent::linux::launch::FaultPoint;
use memcordon_sealed_agent::linux::launch::TerminalFacts;
use memcordon_sealed_agent::request::{
    DeadlineScope, DescriptorPurpose, LaunchPolicyV1, LaunchRequestV1, Lifetime,
};

pub fn fixture() -> &'static str {
    env!("CARGO_BIN_EXE_memcordon-sealed-test-fixture")
}

pub fn execute(mode: &str, lifetime: Lifetime) -> Result<TerminalFacts, String> {
    let request = request(mode, lifetime);
    let (descriptors, attempt) = resources(unsafe { libc::getpid() })?;
    memcordon_sealed_agent::linux::launch::execute(
        request,
        descriptors,
        attempt,
        unsafe { libc::getpid() },
        65_534,
        65_534,
        Vec::new(),
    )
}

#[cfg(feature = "test-support")]
pub fn execute_fault(mode: &str, fault: FaultPoint) -> Result<TerminalFacts, String> {
    let frontend = unsafe { libc::fork() };
    assert!(frontend >= 0);
    if frontend == 0 {
        loop {
            unsafe { libc::pause() };
        }
    }
    let (descriptors, attempt) = resources(frontend)?;
    let result = memcordon_sealed_agent::linux::launch::execute_with_fault(
        request(mode, Lifetime::Command),
        descriptors,
        attempt,
        frontend,
        65_534,
        65_534,
        Vec::new(),
        fault,
    );
    unsafe {
        libc::kill(frontend, libc::SIGKILL);
        libc::waitpid(frontend, std::ptr::null_mut(), 0);
    }
    result
}

#[cfg(feature = "test-support")]
pub fn exit_as_provider_worker() -> ! {
    let frontend = unsafe { libc::getppid() };
    let (descriptors, _) = resources(frontend).unwrap();
    let _ = memcordon_sealed_agent::linux::launch::execute_with_fault(
        request("child", Lifetime::Command),
        descriptors,
        [0x44; 16],
        frontend,
        65_534,
        65_534,
        Vec::new(),
        FaultPoint::ProviderWorkerLossAfterGuardianCreation,
    );
    unsafe { libc::_exit(87) }
}

fn resources(frontend_pid: libc::pid_t) -> Result<(Vec<OwnedFd>, [u8; 16]), String> {
    let directory = std::fs::File::open("/").map_err(|error| error.to_string())?;
    let stdin = std::fs::File::open("/dev/null").map_err(|error| error.to_string())?;
    let stdout = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|error| error.to_string())?;
    let stderr = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|error| error.to_string())?;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, frontend_pid, 0) } as i32;
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut attempt = [0_u8; 16];
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .map_err(|error| error.to_string())?
        .read_exact(&mut attempt)
        .map_err(|error| error.to_string())?;
    Ok((
        vec![
            directory.into(),
            stdin.into(),
            stdout.into(),
            stderr.into(),
            unsafe { OwnedFd::from_raw_fd(pidfd) },
        ],
        attempt,
    ))
}

pub fn request(mode: &str, lifetime: Lifetime) -> LaunchRequestV1 {
    LaunchRequestV1 {
        program: fixture().as_bytes().to_vec(),
        arguments: vec![mode.as_bytes().to_vec()],
        environment: Vec::new(),
        policy: LaunchPolicyV1 {
            memory_limit_bytes: None,
            swap_limit: memcordon_sealed_agent::request::SwapLimit::Bytes(0),
            absolute_deadline_millis: Some(30_000),
            deadline_scope: DeadlineScope::Attempt,
            lifetime,
            poll_interval_millis: 5,
            signal_grace_millis: 0,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
        descriptors: vec![
            DescriptorPurpose::CurrentDirectory,
            DescriptorPurpose::Stdin,
            DescriptorPurpose::Stdout,
            DescriptorPurpose::Stderr,
            DescriptorPurpose::FrontendLiveness,
        ],
    }
}

pub fn assert_retired(facts: &TerminalFacts) {
    assert!(facts.assignment_verified);
    assert!(facts.namespaces_verified);
    assert!(facts.credentials_verified);
    assert!(facts.capabilities_empty);
    assert!(facts.descriptors_verified);
    assert!(facts.cgroup_view_denied);
    assert!(facts.guardian_ready_before_authorization);
    assert!(facts.frontend_loss_authority_verified);
    assert!(facts.cgroup_kill_invoked);
    assert!(facts.cgroup_empty);
    assert!(facts.init_reaped);
    assert!(facts.guardian_reaped);
    assert!(facts.boundary_retired);
}
