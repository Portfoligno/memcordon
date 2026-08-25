#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::linux::launch::TerminalFacts;
use crate::request::{DeadlineScope, DescriptorPurpose, LaunchPolicyV2, LaunchRequestV2, Lifetime};

pub fn fixture() -> &'static str {
    env!("CARGO_BIN_EXE_memcordon-sealed-test-fixture")
}

pub struct StagedFixture {
    directory: tempfile::TempDir,
    program: PathBuf,
}

pub struct CapturedExecution {
    pub facts: TerminalFacts,
    pub attempt: [u8; 16],
}

impl CapturedExecution {
    pub fn identity(&self) -> String {
        attempt_identity(self.attempt)
    }
}

impl StagedFixture {
    pub fn new() -> Result<Self, String> {
        let source = Path::new(fixture());
        let source_metadata =
            std::fs::symlink_metadata(source).map_err(|error| error.to_string())?;
        if !source_metadata.file_type().is_file() {
            return Err("sealed fixture source is not a regular file".to_owned());
        }
        // SAFETY: geteuid has no pointer arguments and returns the caller's effective uid.
        if unsafe { libc::geteuid() } != 0 {
            return Err("sealed fixture staging requires root ownership".to_owned());
        }
        let directory = tempfile::Builder::new()
            .prefix("memcordon-sealed-fixture-")
            .tempdir_in("/tmp")
            .map_err(|error| error.to_string())?;
        let program = directory.path().join("fixture");
        let mut input = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(source)
            .map_err(|error| error.to_string())?;
        if !input
            .metadata()
            .map_err(|error| error.to_string())?
            .file_type()
            .is_file()
        {
            return Err("sealed fixture source changed before staging".to_owned());
        }
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&program)
            .map_err(|error| error.to_string())?;
        std::io::copy(&mut input, &mut output).map_err(|error| error.to_string())?;
        output.flush().map_err(|error| error.to_string())?;
        output.sync_all().map_err(|error| error.to_string())?;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o555))
            .map_err(|error| error.to_string())?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
        let directory_metadata =
            std::fs::symlink_metadata(directory.path()).map_err(|error| error.to_string())?;
        let program_metadata =
            std::fs::symlink_metadata(&program).map_err(|error| error.to_string())?;
        if directory_metadata.uid() != 0
            || directory_metadata.permissions().mode() & 0o777 != 0o755
            || !program_metadata.file_type().is_file()
            || program_metadata.uid() != 0
            || program_metadata.permissions().mode() & 0o777 != 0o555
        {
            return Err("sealed fixture staging identity or permissions are unsafe".to_owned());
        }
        Ok(Self { directory, program })
    }

    pub fn directory(&self) -> &Path {
        self.directory.path()
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn request(&self, mode: &str, lifetime: Lifetime) -> Result<LaunchRequestV2, String> {
        let deadline = crate::linux::clock::monotonic_millis()?.saturating_add(30_000);
        Ok(self.request_with_deadline(mode, lifetime, deadline))
    }

    pub fn request_with_deadline(
        &self,
        mode: &str,
        lifetime: Lifetime,
        absolute_deadline_millis: u64,
    ) -> LaunchRequestV2 {
        request_for_program(self.program(), mode, lifetime, absolute_deadline_millis)
    }
}

pub fn execute(mode: &str, lifetime: Lifetime) -> Result<TerminalFacts, String> {
    execute_captured(mode, lifetime).map(|captured| captured.facts)
}

pub fn execute_captured(mode: &str, lifetime: Lifetime) -> Result<CapturedExecution, String> {
    let fixture = StagedFixture::new()?;
    if !fixture.directory().is_dir() {
        return Err("sealed fixture directory disappeared before launch".to_owned());
    }
    let request = fixture.request(mode, lifetime)?;
    execute_request_captured(request)
}

pub fn execute_request(request: LaunchRequestV2) -> Result<TerminalFacts, String> {
    execute_request_captured(request).map(|captured| captured.facts)
}

pub fn execute_request_as(
    request: LaunchRequestV2,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
) -> Result<TerminalFacts, String> {
    let (descriptors, attempt) = resources(unsafe { libc::getpid() })?;
    crate::linux::launch::execute(
        request,
        descriptors,
        attempt,
        unsafe { libc::getpid() },
        uid,
        gid,
        groups,
    )
}

pub fn execute_request_captured(request: LaunchRequestV2) -> Result<CapturedExecution, String> {
    let (descriptors, attempt) = resources(unsafe { libc::getpid() })?;
    let facts = crate::linux::launch::execute(
        request,
        descriptors,
        attempt,
        unsafe { libc::getpid() },
        65_534,
        65_534,
        Vec::new(),
    )?;
    Ok(CapturedExecution { facts, attempt })
}

pub(crate) fn resources(frontend_pid: libc::pid_t) -> Result<(Vec<OwnedFd>, [u8; 16]), String> {
    let stdout = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|error| error.to_string())?;
    let stderr = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|error| error.to_string())?;
    resources_with_outputs(frontend_pid, stdout.into(), stderr.into())
}

pub(crate) fn resources_with_outputs(
    frontend_pid: libc::pid_t,
    stdout: OwnedFd,
    stderr: OwnedFd,
) -> Result<(Vec<OwnedFd>, [u8; 16]), String> {
    let directory = std::fs::File::open("/").map_err(|error| error.to_string())?;
    let stdin = std::fs::File::open("/dev/null").map_err(|error| error.to_string())?;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, frontend_pid, 0) } as i32;
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut attempt = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .map_err(|error| error.to_string())?
        .read_exact(&mut attempt)
        .map_err(|error| error.to_string())?;
    Ok((
        vec![directory.into(), stdin.into(), stdout, stderr, unsafe {
            OwnedFd::from_raw_fd(pidfd)
        }],
        attempt,
    ))
}

pub fn request(mode: &str, lifetime: Lifetime) -> Result<LaunchRequestV2, String> {
    let deadline = crate::linux::clock::monotonic_millis()?.saturating_add(30_000);
    Ok(request_with_deadline(mode, lifetime, deadline))
}

pub fn request_with_deadline(
    mode: &str,
    lifetime: Lifetime,
    absolute_deadline_millis: u64,
) -> LaunchRequestV2 {
    request_for_program(
        Path::new(fixture()),
        mode,
        lifetime,
        absolute_deadline_millis,
    )
}

fn request_for_program(
    program: &Path,
    mode: &str,
    lifetime: Lifetime,
    absolute_deadline_millis: u64,
) -> LaunchRequestV2 {
    LaunchRequestV2 {
        program: program.as_os_str().as_encoded_bytes().to_vec(),
        arguments: vec![mode.as_bytes().to_vec()],
        environment: Vec::new(),
        policy: LaunchPolicyV2 {
            memory_limit_bytes: None,
            swap_limit: crate::request::SwapLimit::Bytes(0),
            absolute_deadline_millis: Some(absolute_deadline_millis),
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
    assert!(facts.target_initial_credentials_verified);
    assert!(facts.initial_provider_capabilities_absent);
    assert!(facts.target_no_new_privs_matched);
    assert!(facts.target_capability_bounding_set_matched);
    assert!(facts.target_mount_context_derived_from_caller);
    assert!(facts.boundary_independent_of_credentials);
    assert!(facts.descriptors_verified);
    assert!(facts.writable_ancestor_cgroup_denied);
    assert!(facts.parent_namespace_handles_denied);
    assert!(facts.recursive_provider_request_denied);
    assert!(facts.guardian_ready_before_authorization);
    assert!(facts.frontend_loss_authority_verified);
    assert!(facts.cgroup_kill_invoked);
    assert!(facts.cgroup_empty);
    assert!(facts.init_reaped);
    assert!(facts.guardian_reaped);
    assert!(facts.boundary_retired);
}

pub fn assert_attempt_retired(attempt: [u8; 16]) {
    let identity = attempt_identity(attempt);
    for path in [
        std::path::Path::new(crate::linux::STATE_ROOT).join(&identity),
        std::path::Path::new(crate::linux::CGROUP_ROOT).join(&identity),
    ] {
        assert!(
            matches!(
                std::fs::symlink_metadata(&path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "sealed attempt residue remained at {}",
            path.display()
        );
    }
}

pub fn attempt_identity(attempt: [u8; 16]) -> String {
    attempt.iter().map(|byte| format!("{byte:02x}")).collect()
}
