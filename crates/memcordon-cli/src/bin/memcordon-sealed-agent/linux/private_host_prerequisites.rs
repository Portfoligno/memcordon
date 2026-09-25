//! Fresh systemd manager generation for a candidate private host receipt.
//! This is kernel/manager readback, not a receipt or production authority.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::Serialize;

use super::CGROUP_ROOT;
use super::private_attempt::ProcessIdentityV4;

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const UNIT: &str = "memcordon-sealed-network-launcher.service";
const FRAGMENT: &str = "/usr/lib/systemd/system/memcordon-sealed-network-launcher.service";
const OUTPUT_LIMIT: usize = 16 * 1024;
const QUERY_DEADLINE: Duration = Duration::from_secs(5);
const KERNEL_READ_LIMIT: u64 = 4096;
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const PROPERTIES: [&str; 9] = [
    "InvocationID",
    "MainPID",
    "ActiveState",
    "SubState",
    "NeedDaemonReload",
    "FragmentPath",
    "DropInPaths",
    "ControlGroup",
    "Delegate",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceGenerationV1 {
    invocation_id: String,
    main: ProcessIdentityV4,
    control_group: String,
}

impl ServiceGenerationV1 {
    pub(crate) fn digest(&self) -> Result<DiagnosticSha256, String> {
        let mut bytes = b"memcordon-private-service-generation-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hash_bytes(&bytes))
    }

    pub(crate) fn main(&self) -> &ProcessIdentityV4 {
        &self.main
    }

    pub(crate) fn control_group(&self) -> &str {
        &self.control_group
    }
}

/// Independently sampled mutable host facts. A caller must resample and
/// compare the digest before treating any future host receipt as current.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostPrerequisitesV1 {
    boot_id: String,
    kernel_release: String,
    native_abi: String,
    service_generation: ServiceGenerationV1,
    cgroup_root_device: u64,
    cgroup_root_inode: u64,
    cgroup_controllers: Vec<String>,
    cgroup_subtree_control: Vec<String>,
    syscall_observations: SyscallObservationsV1,
    target_uid: u32,
    target_gid: u32,
    installation_epoch: DiagnosticSha256,
    source_commit: String,
    target: String,
    runtime_manifest_sha256: DiagnosticSha256,
    release_qualification_sha256: DiagnosticSha256,
    agent_sha256: DiagnosticSha256,
    units: memcordon_core::package_inspection_v6::LinuxUnitHashesV6,
    filter_sha256: DiagnosticSha256,
    catalogue_sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SyscallObservationsV1 {
    clone3_errno: i32,
    openat2_errno: i32,
    close_range_errno: i32,
    execveat_errno: i32,
    pidfd_send_signal_errno: i32,
    no_new_privs: i32,
}

impl HostPrerequisitesV1 {
    pub(crate) fn digest(&self) -> Result<DiagnosticSha256, String> {
        let mut bytes = b"memcordon-private-host-prerequisites-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hash_bytes(&bytes))
    }

    pub(crate) fn service_generation(&self) -> &ServiceGenerationV1 {
        &self.service_generation
    }

    pub(crate) fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub(crate) fn target_ids(&self) -> (u32, u32) {
        (self.target_uid, self.target_gid)
    }

    pub(crate) fn installation_epoch(&self) -> &DiagnosticSha256 {
        &self.installation_epoch
    }
}

/// This readback deliberately does not create a receipt or authority. It may
/// be hashed into one only after a separate protected eight-case run joins it.
pub(crate) fn observe_host_prerequisites(
    package: &crate::package::VerifiedProbePackageLease,
) -> Result<HostPrerequisitesV1, String> {
    let installation_epoch = crate::package::installed_generation_epoch()?;
    let service_generation = observe_service_generation()?;
    let main_pidfd = pin_service_main(&service_generation)?;
    let main_cgroup_path = Path::new("/proc")
        .join(service_generation.main().pid.to_string())
        .join("cgroup");
    let cgroup_bytes = read_bounded_kernel(&main_cgroup_path)?;
    let current_cgroup = parse_proc_cgroup(&cgroup_bytes)?;
    if current_cgroup != service_generation.control_group() {
        return Err("MCSEALED-PRIVATE-HOST: service cgroup membership differs".into());
    }
    let root = Path::new(CGROUP_ROOT);
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|error| format!("MCSEALED-PRIVATE-HOST: cgroup root metadata: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.ino() == 0 {
        return Err("MCSEALED-PRIVATE-HOST: cgroup root identity differs".into());
    }
    let root_c = CString::new(CGROUP_ROOT).expect("fixed cgroup root has no NUL");
    // SAFETY: statfs writes only to the live output and does not retain pointers.
    let mut stat = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::statfs(root_c.as_ptr(), &raw mut stat) } != 0
        || stat.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err("MCSEALED-PRIVATE-HOST: cgroup v2 filesystem differs".into());
    }
    let controllers = parse_control_tokens(&read_bounded_kernel(
        root.join("cgroup.controllers")
            .to_str()
            .ok_or("MCSEALED-PRIVATE-HOST: cgroup control path differs")?,
    )?)?;
    let subtree = parse_control_tokens(&read_bounded_kernel(
        root.join("cgroup.subtree_control")
            .to_str()
            .ok_or("MCSEALED-PRIVATE-HOST: cgroup control path differs")?,
    )?)?;
    if !controllers.iter().any(|control| control == "memory")
        || !subtree.iter().any(|control| control == "memory")
    {
        return Err("MCSEALED-PRIVATE-HOST: memory controller not delegated".into());
    }
    let boot_id = String::from_utf8(read_bounded_kernel("/proc/sys/kernel/random/boot_id")?)
        .map_err(|_| "MCSEALED-PRIVATE-HOST: boot identity is not UTF-8")?
        .trim()
        .to_owned();
    if boot_id.is_empty() || boot_id.len() > 64 {
        return Err("MCSEALED-PRIVATE-HOST: boot identity differs".into());
    }
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uname initializes the complete utsname output on success.
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return Err("MCSEALED-PRIVATE-HOST: kernel release unavailable".into());
    }
    // SAFETY: uname succeeded and initialized utsname.
    let uts = unsafe { uts.assume_init() };
    let kernel_release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }
        .to_str()
        .map_err(|_| "MCSEALED-PRIVATE-HOST: kernel release is not UTF-8")?
        .to_owned();
    if kernel_release.is_empty() || kernel_release.len() > 256 {
        return Err("MCSEALED-PRIVATE-HOST: kernel release differs".into());
    }
    let (target_uid, target_gid) = super::private_qualification::fixed_probe_account()?;
    let syscall_observations = observe_syscalls()?;
    let mut pollfd = libc::pollfd {
        fd: main_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll only observes the retained service MainPID descriptor.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 0 || pollfd.revents != 0 {
        return Err("MCSEALED-PRIVATE-HOST: service MainPID exited during readback".into());
    }
    let second_service = observe_service_generation()?;
    if second_service != service_generation {
        return Err("MCSEALED-PRIVATE-HOST: service generation changed during readback".into());
    }
    if crate::package::installed_generation_epoch()? != installation_epoch {
        return Err("MCSEALED-PRIVATE-HOST: installation epoch changed during readback".into());
    }
    Ok(HostPrerequisitesV1 {
        boot_id,
        kernel_release,
        native_abi: std::env::consts::ARCH.into(),
        service_generation,
        cgroup_root_device: metadata.dev(),
        cgroup_root_inode: metadata.ino(),
        cgroup_controllers: controllers,
        cgroup_subtree_control: subtree,
        syscall_observations,
        target_uid,
        target_gid,
        installation_epoch,
        source_commit: package.source_commit.clone(),
        target: package.target.clone(),
        runtime_manifest_sha256: package.runtime_manifest_sha256.clone(),
        release_qualification_sha256: package.release_qualification_sha256.clone(),
        agent_sha256: package.agent_sha256.clone(),
        units: package.units.clone(),
        filter_sha256: package.filter_sha256.clone(),
        catalogue_sha256: super::private_qualification::catalogue_digest(),
    })
}

fn pin_service_main(service: &ServiceGenerationV1) -> Result<OwnedFd, String> {
    // SAFETY: pidfd_open receives the independently observed positive systemd
    // MainPID. The process identity is then checked against the first sample.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, service.main().pid, 0) } as i32;
    if raw == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-HOST: pin service MainPID: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open transferred a unique descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    if ProcessIdentityV4::observe(service.main().pid as libc::pid_t, pidfd.as_fd())?
        != *service.main()
    {
        return Err("MCSEALED-PRIVATE-HOST: service MainPID identity changed".into());
    }
    Ok(pidfd)
}

fn read_bounded_kernel(path: impl AsRef<Path>) -> Result<Vec<u8>, String> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|error| {
        format!(
            "MCSEALED-PRIVATE-HOST: kernel readback {}: {error}",
            path.display()
        )
    })?;
    let mut bytes = Vec::new();
    file.take(KERNEL_READ_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!(
                "MCSEALED-PRIVATE-HOST: kernel readback {}: {error}",
                path.display()
            )
        })?;
    if bytes.is_empty() || bytes.len() as u64 > KERNEL_READ_LIMIT {
        return Err("MCSEALED-PRIVATE-HOST: kernel readback bound differs".into());
    }
    Ok(bytes)
}

pub(crate) fn require_current_worker_cgroup(service: &ServiceGenerationV1) -> Result<(), String> {
    let bytes = read_bounded_kernel("/proc/self/cgroup")?;
    if parse_proc_cgroup(&bytes)? != service.control_group() {
        return Err("MCSEALED-PRIVATE-HOST: worker cgroup membership differs".into());
    }
    Ok(())
}

fn parse_proc_cgroup(bytes: &[u8]) -> Result<&str, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "MCSEALED-PRIVATE-HOST: process cgroup is not UTF-8")?;
    let mut lines = text.lines();
    let path = lines
        .next()
        .and_then(|line| line.strip_prefix("0::"))
        .ok_or("MCSEALED-PRIVATE-HOST: process cgroup v2 entry absent")?;
    if lines.next().is_some() || !path.starts_with('/') || path.contains("//") {
        return Err("MCSEALED-PRIVATE-HOST: process cgroup inventory differs".into());
    }
    Ok(path)
}

fn parse_control_tokens(bytes: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "MCSEALED-PRIVATE-HOST: cgroup control is not UTF-8")?;
    let mut controls = Vec::new();
    for token in text.split_whitespace() {
        if !token.bytes().all(|byte| byte.is_ascii_lowercase())
            || controls.iter().any(|existing| existing == token)
        {
            return Err("MCSEALED-PRIVATE-HOST: cgroup controller inventory differs".into());
        }
        controls.push(token.to_owned());
    }
    controls.sort();
    if controls.is_empty() {
        return Err("MCSEALED-PRIVATE-HOST: cgroup controller inventory empty".into());
    }
    Ok(controls)
}

fn syscall_errno(number: libc::c_long, args: [libc::c_long; 6]) -> Result<i32, String> {
    // SAFETY: every probe supplies intentionally invalid scalar/pointer values,
    // so no successful operation or process replacement can occur.
    let result =
        unsafe { libc::syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result != -1 {
        return Err("MCSEALED-PRIVATE-HOST: invalid syscall probe unexpectedly succeeded".into());
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == 0 || errno == libc::ENOSYS || errno == libc::EPERM || errno == libc::EACCES {
        return Err("MCSEALED-PRIVATE-HOST: required syscall unavailable".into());
    }
    Ok(errno)
}

fn observe_syscalls() -> Result<SyscallObservationsV1, String> {
    // SAFETY: PR_GET_NO_NEW_PRIVS has no pointer arguments.
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs != 0 {
        return Err("MCSEALED-PRIVATE-HOST: launcher no-new-privileges differs".into());
    }
    Ok(SyscallObservationsV1 {
        clone3_errno: syscall_errno(libc::SYS_clone3, [0, 0, 0, 0, 0, 0])?,
        openat2_errno: syscall_errno(libc::SYS_openat2, [-1, 0, 0, 0, 0, 0])?,
        close_range_errno: syscall_errno(libc::SYS_close_range, [1, 0, 0, 0, 0, 0])?,
        execveat_errno: syscall_errno(libc::SYS_execveat, [-1, 0, 0, 0, 0, 0])?,
        pidfd_send_signal_errno: syscall_errno(libc::SYS_pidfd_send_signal, [-1, 0, 0, 0, 0, 0])?,
        no_new_privs,
    })
}

struct ManagerProperties<'a> {
    invocation_id: &'a str,
    main_pid: libc::pid_t,
    control_group: &'a str,
}

fn parse_manager_properties(bytes: &[u8]) -> Result<ManagerProperties<'_>, String> {
    if bytes.is_empty() || bytes.len() > OUTPUT_LIMIT {
        return Err("MCSEALED-PRIVATE-HOST: manager property output bound differs".into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "MCSEALED-PRIVATE-HOST: manager properties are not UTF-8")?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or("MCSEALED-PRIVATE-HOST: malformed manager property")?;
        if !PROPERTIES.contains(&name) || fields.insert(name, value).is_some() {
            return Err("MCSEALED-PRIVATE-HOST: unknown or duplicate manager property".into());
        }
    }
    if fields.len() != PROPERTIES.len() {
        return Err("MCSEALED-PRIVATE-HOST: manager property inventory differs".into());
    }
    let value = |key: &str| -> Result<&str, String> {
        fields
            .get(key)
            .copied()
            .ok_or_else(|| "MCSEALED-PRIVATE-HOST: manager property absent".into())
    };
    let invocation_id = value("InvocationID")?;
    let main_pid = value("MainPID")?
        .parse::<libc::pid_t>()
        .map_err(|_| "MCSEALED-PRIVATE-HOST: manager MainPID differs")?;
    let control_group = value("ControlGroup")?;
    if invocation_id.len() != 32
        || !invocation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || invocation_id.bytes().all(|byte| byte == b'0')
        || main_pid <= 1
        || value("ActiveState")? != "active"
        || value("SubState")? != "running"
        || value("NeedDaemonReload")? != "no"
        || value("FragmentPath")? != FRAGMENT
        || !value("DropInPaths")?.is_empty()
        || value("Delegate")? != "yes"
        || !control_group.starts_with('/')
        || control_group.len() > 512
        || control_group
            .split('/')
            .any(|part| part == "." || part == "..")
    {
        return Err("MCSEALED-PRIVATE-HOST: manager service state differs".into());
    }
    Ok(ManagerProperties {
        invocation_id,
        main_pid,
        control_group,
    })
}

fn query_manager() -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(Path::new(SYSTEMCTL))
        .map_err(|error| format!("MCSEALED-PRIVATE-HOST: systemctl metadata: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err("MCSEALED-PRIVATE-HOST: systemctl executable is not protected".into());
    }
    let mut child = Command::new(SYSTEMCTL)
        .args([
            "--system",
            "--all",
            "--no-pager",
            "--property=InvocationID",
            "--property=MainPID",
            "--property=ActiveState",
            "--property=SubState",
            "--property=NeedDaemonReload",
            "--property=FragmentPath",
            "--property=DropInPaths",
            "--property=ControlGroup",
            "--property=Delegate",
            "show",
            UNIT,
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("MCSEALED-PRIVATE-HOST: systemctl show: {error}"))?;
    let result = read_bounded_manager_output(&mut child);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|error| format!("MCSEALED-PRIVATE-HOST: systemctl wait: {error}"))?;
    let bytes = result?;
    if !status.success() {
        return Err("MCSEALED-PRIVATE-HOST: systemd manager rejected unit query".into());
    }
    Ok(bytes)
}

fn read_bounded_manager_output(child: &mut std::process::Child) -> Result<Vec<u8>, String> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or("MCSEALED-PRIVATE-HOST: manager stdout pipe absent")?;
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err("MCSEALED-PRIVATE-HOST: cannot bound manager read".into());
    }
    let deadline = Instant::now() + QUERY_DEADLINE;
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        if Instant::now() >= deadline {
            return Err("MCSEALED-PRIVATE-HOST: manager query exceeded deadline".into());
        }
        match stdout.read(&mut buffer) {
            Ok(0) => {
                if child
                    .try_wait()
                    .map_err(|error| format!("MCSEALED-PRIVATE-HOST: manager status: {error}"))?
                    .is_some()
                {
                    return Ok(output);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(count) => {
                if output.len() + count > OUTPUT_LIMIT {
                    return Err("MCSEALED-PRIVATE-HOST: manager output exceeds bound".into());
                }
                output.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let mut pollfd = libc::pollfd {
                    fd: stdout.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                let timeout = remaining.as_millis().min(100) as i32;
                // SAFETY: pollfd is initialized with a live owned stdout fd.
                let status = unsafe { libc::poll(&mut pollfd, 1, timeout) };
                if status < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    return Err("MCSEALED-PRIVATE-HOST: manager output poll failed".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("MCSEALED-PRIVATE-HOST: manager output: {error}")),
        }
    }
}

/// Query systemd twice around an independently observed live MainPID pidfd.
/// A manager restart or unit replacement during readback is unavailable.
pub(crate) fn observe_service_generation() -> Result<ServiceGenerationV1, String> {
    let first = query_manager()?;
    let selected = parse_manager_properties(&first)?;
    // SAFETY: pidfd_open receives a positive manager-supplied PID; it does
    // not grant authority until ProcessIdentityV4 independently checks fdinfo
    // and the kernel process start time.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, selected.main_pid, 0) } as i32;
    if raw == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-HOST: service pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open transferred a unique owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let main = ProcessIdentityV4::observe(selected.main_pid, pidfd.as_fd())?;
    let second = query_manager()?;
    if second != first {
        return Err("MCSEALED-PRIVATE-HOST: service generation changed during readback".into());
    }
    let selected = parse_manager_properties(&second)?;
    Ok(ServiceGenerationV1 {
        invocation_id: selected.invocation_id.into(),
        main,
        control_group: selected.control_group.into(),
    })
}

#[cfg(feature = "test-support")]
pub(crate) fn parse_manager_properties_for_test(bytes: &[u8]) -> Result<(), String> {
    parse_manager_properties(bytes).map(|_| ())
}

#[cfg(feature = "test-support")]
pub(crate) fn parse_proc_cgroup_for_test(bytes: &[u8]) -> Result<String, String> {
    parse_proc_cgroup(bytes).map(str::to_owned)
}

#[cfg(feature = "test-support")]
pub(crate) fn parse_control_tokens_for_test(bytes: &[u8]) -> Result<Vec<String>, String> {
    parse_control_tokens(bytes)
}
