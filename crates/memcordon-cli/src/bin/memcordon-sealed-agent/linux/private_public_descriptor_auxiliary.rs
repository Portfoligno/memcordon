//! Versioned, default-disabled valid-context controls. These exceptional
//! descriptors belong to a sacrificial helper, never to a public target entry.
use memcordon_core::DiagnosticSha256;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

const POLICY: &str = "/etc/memcordon/release-trust/final-public-auxiliary.v1.json";
const IMPORT: &str = "private_tcp::io_uring_and_pidfd_import_denied";
const SCM: &str = "private_tcp::scm_rights_and_precreated_socket_denied";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedAuxiliaryPolicyV1 {
    schema_version: u8,
    stage_semantics_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    runtime_manifest_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    outer_cgroup_inode: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DescriptorAuxiliaryObservationV1 {
    schema_version: u8,
    stage_semantics_version: u8,
    evidence_scope: &'static str,
    selector: String,
    result_key: DiagnosticSha256,
    protected_policy_bytes: Vec<u8>,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    runtime_manifest_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    boot_id: String,
    parent_pid: u32,
    parent_start_ticks: u64,
    source_pid: u32,
    source_start_ticks: u64,
    source_fd: i32,
    source_device: u64,
    source_inode: u64,
    helper_pid: u32,
    helper_start_ticks: u64,
    outer_result: i64,
    filtered_result: i64,
    filtered_errno: i32,
    source_wait_status: i32,
    helper_wait_status: i32,
}

struct ChildOwner(libc::pid_t);
impl ChildOwner {
    fn reap(&mut self) -> Result<i32, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut status = 0;
            let observed = unsafe { libc::waitpid(self.0, &mut status, libc::WNOHANG) };
            if observed == self.0 {
                self.0 = 0;
                return Ok(status);
            }
            if observed < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if Instant::now() >= deadline {
                return Err("descriptor auxiliary child deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.0 > 0 {
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                libc::waitpid(self.0, std::ptr::null_mut(), 0);
            }
        }
    }
}

fn pipe() -> Result<[OwnedFd; 2], String> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { [OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])] })
}

/// The ancillary buffer is naturally cmsghdr-aligned. Both calls use a real
/// open descriptor, a real socketpair and identical valid SCM_RIGHTS payload.
fn send_rights(socket: i32, source: i32) -> Result<(i64, i32), String> {
    let mut payload = [0x51_u8];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let control_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut control = vec![0_usize; control_len.div_ceil(std::mem::size_of::<usize>())];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control_len;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        if header.is_null() {
            return Err("descriptor auxiliary cmsg absent".into());
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
        *libc::CMSG_DATA(header).cast::<i32>() = source;
    }
    let result = unsafe { libc::sendmsg(socket, &msg, libc::MSG_NOSIGNAL) };
    Ok((
        result as i64,
        if result < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        },
    ))
}

fn receive_rights(socket: i32, expected: &std::fs::Metadata) -> Result<(), String> {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let length = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut control = vec![0_usize; length.div_ceil(std::mem::size_of::<usize>())];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = length;
    if unsafe {
        libc::recvmsg(
            socket,
            &mut msg,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
        )
    } != 1
        || byte != [0x51]
        || msg.msg_flags != 0
    {
        return Err("descriptor auxiliary outer receive differs".into());
    }
    let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if header.is_null()
        || unsafe {
            (*header).cmsg_level != libc::SOL_SOCKET
                || (*header).cmsg_type != libc::SCM_RIGHTS
                || (*header).cmsg_len != libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize
        }
    {
        return Err("descriptor auxiliary outer cmsg differs".into());
    }
    let received = unsafe { OwnedFd::from_raw_fd(*libc::CMSG_DATA(header).cast::<i32>()) };
    let metadata = File::from(received)
        .metadata()
        .map_err(|error| error.to_string())?;
    if (metadata.dev(), metadata.ino()) != (expected.dev(), expected.ino()) {
        return Err("descriptor auxiliary transferred object differs".into());
    }
    Ok(())
}

pub(crate) fn run(selector: &str, key: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 || !matches!(selector, IMPORT | SCM) {
        return Err("descriptor auxiliary requires root closed selector".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(POLICY)
        .map_err(|error| error.to_string())?;
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o7777 != 0o600
        || meta.len() > 16384
    {
        return Err("descriptor auxiliary opt-in policy protection differs".into());
    }
    for ancestor in Path::new(POLICY)
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
    {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("descriptor auxiliary policy ancestor mutable".into());
        }
    }
    let mut policy_bytes = Vec::new();
    file.take(16385)
        .read_to_end(&mut policy_bytes)
        .map_err(|error| error.to_string())?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&policy_bytes)?;
    let policy: ProtectedAuxiliaryPolicyV1 =
        serde_json::from_slice(&policy_bytes).map_err(|error| error.to_string())?;
    if policy.schema_version != 1
        || policy.stage_semantics_version != 3
        || policy.selector != selector
        || String::from(policy.result_key.clone()) != key
    {
        return Err("descriptor auxiliary opt-in semantics/key differs".into());
    }
    let installed = crate::package::acquire_verified_private_qualification_lease()?;
    if policy.installation_epoch != *installed.generation_digest()
        || policy.active_h1_receipt_sha256 != *installed.active_host_receipt_sha256()
        || policy.runtime_manifest_sha256 != *installed.runtime_manifest_sha256()
        || policy.filter_sha256 != *installed.filter_digest()
    {
        return Err("descriptor auxiliary installed subject differs".into());
    }
    let membership =
        std::fs::read_to_string("/proc/self/cgroup").map_err(|error| error.to_string())?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .ok_or("descriptor auxiliary unified cgroup absent")?;
    let cgroup = Path::new("/sys/fs/cgroup").join(relative);
    if policy.outer_cgroup_inode == 0
        || std::fs::metadata(cgroup)
            .map_err(|error| error.to_string())?
            .ino()
            != policy.outer_cgroup_inode
    {
        return Err("descriptor auxiliary approved outer cgroup differs".into());
    }
    let parent = unsafe { libc::getpid() };
    let parent_start = super::envelope::process_start_time(parent)?;
    let source = File::open("/dev/null").map_err(|error| error.to_string())?;
    let source_fd = source.as_raw_fd();
    let source_meta = source.metadata().map_err(|error| error.to_string())?;
    let [source_read, source_write] = pipe()?;
    let source_pid = unsafe { libc::fork() };
    if source_pid < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if source_pid == 0 {
        drop(source_write);
        let mut byte = [0_u8];
        let count = unsafe {
            libc::read(
                source_read.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                byte.len(),
            )
        };
        unsafe { libc::_exit(if count == 1 && byte == [0x5a] { 0 } else { 125 }) };
    }
    let mut source_child = ChildOwner(source_pid);
    drop(source_read);
    let source_start = super::envelope::process_start_time(source_pid)?;
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, source_pid, 0) } as i32;
    if raw_pidfd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    let mut socket_fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            socket_fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let pair = unsafe {
        [
            OwnedFd::from_raw_fd(socket_fds[0]),
            OwnedFd::from_raw_fd(socket_fds[1]),
        ]
    };
    let outer = if selector == IMPORT {
        let imported = unsafe {
            libc::syscall(
                libc::SYS_pidfd_getfd,
                pidfd.as_raw_fd(),
                source.as_raw_fd(),
                0,
            )
        };
        if imported < 0 {
            return Err(format!(
                "valid outer pidfd import prerequisite: {}",
                std::io::Error::last_os_error()
            ));
        }
        let imported = File::from(unsafe { OwnedFd::from_raw_fd(imported as i32) });
        let m = imported.metadata().map_err(|error| error.to_string())?;
        if (m.dev(), m.ino()) != (source_meta.dev(), source_meta.ino()) {
            return Err("outer pidfd source object differs".into());
        }
        imported.as_raw_fd() as i64
    } else {
        let (result, errno) = send_rights(pair[0].as_raw_fd(), source.as_raw_fd())?;
        if result != 1 || errno != 0 {
            return Err("valid outer SCM transfer prerequisite failed".into());
        }
        receive_rights(pair[1].as_raw_fd(), &source_meta)?;
        result
    };
    let [report_read, report_write] = pipe()?;
    let [go_read, go_write] = pipe()?;
    let helper_pid = unsafe { libc::fork() };
    if helper_pid < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if helper_pid == 0 {
        drop(report_read);
        drop(go_write);
        drop(source_write);
        let result = (|| -> Result<(i64, i32), String> {
            let mut byte = [0_u8];
            if unsafe { libc::read(go_read.as_raw_fd(), byte.as_mut_ptr().cast(), byte.len()) } != 1
                || byte != [0xa5]
            {
                return Err("auxiliary parent gate".into());
            }
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err("auxiliary NNP".into());
            }
            super::network_filter::install_gated_private_filter(
                installed.filter_abi(),
                *installed.filter_digest().bytes(),
            )?;
            if selector == IMPORT {
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_getfd,
                        pidfd.as_raw_fd(),
                        source.as_raw_fd(),
                        0,
                    )
                };
                Ok((
                    result,
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                ))
            } else {
                send_rights(pair[0].as_raw_fd(), source.as_raw_fd())
            }
        })();
        let mut raw = [0_u8; 12];
        let good = if let Ok((result, errno)) = result {
            raw[..8].copy_from_slice(&result.to_le_bytes());
            raw[8..].copy_from_slice(&errno.to_le_bytes());
            result == -1 && errno == libc::EPERM
        } else {
            false
        };
        let written =
            unsafe { libc::write(report_write.as_raw_fd(), raw.as_ptr().cast(), raw.len()) };
        unsafe {
            libc::_exit(if good && written == raw.len() as isize {
                0
            } else {
                125
            })
        };
    }
    let mut helper = ChildOwner(helper_pid);
    drop(report_write);
    drop(go_read);
    let helper_start = super::envelope::process_start_time(helper_pid)?;
    File::from(go_write)
        .write_all(&[0xa5])
        .map_err(|error| error.to_string())?;
    let mut poll = libc::pollfd {
        fd: report_read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, 10000) } != 1 || poll.revents & libc::POLLIN == 0 {
        return Err("descriptor auxiliary report deadline".into());
    }
    let mut raw = [0_u8; 12];
    File::from(report_read)
        .read_exact(&mut raw)
        .map_err(|error| error.to_string())?;
    let filtered_result = i64::from_le_bytes(raw[..8].try_into().expect("eight bytes"));
    let filtered_errno = i32::from_le_bytes(raw[8..].try_into().expect("four bytes"));
    let helper_status = helper.reap()?;
    File::from(source_write)
        .write_all(&[0x5a])
        .map_err(|error| error.to_string())?;
    let source_status = source_child.reap()?;
    if helper_status != 0
        || source_status != 0
        || filtered_result != -1
        || filtered_errno != libc::EPERM
    {
        return Err("descriptor auxiliary actual outcome differs".into());
    }
    drop(pair);
    drop(pidfd);
    drop(source);
    installed.revalidate_release_boundary()?;
    let observation = DescriptorAuxiliaryObservationV1 {
        schema_version: 1,
        stage_semantics_version: 3,
        evidence_scope: "clean-entry-plus-valid-context-auxiliary",
        selector: selector.into(),
        result_key: policy.result_key.clone(),
        protected_policy_bytes: policy_bytes,
        installation_epoch: policy.installation_epoch,
        active_h1_receipt_sha256: policy.active_h1_receipt_sha256,
        runtime_manifest_sha256: policy.runtime_manifest_sha256,
        filter_sha256: policy.filter_sha256,
        boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?,
        parent_pid: parent as u32,
        parent_start_ticks: parent_start,
        source_pid: source_pid as u32,
        source_start_ticks: source_start,
        source_fd,
        source_device: source_meta.dev(),
        source_inode: source_meta.ino(),
        helper_pid: helper_pid as u32,
        helper_start_ticks: helper_start,
        outer_result: outer,
        filtered_result,
        filtered_errno,
        source_wait_status: source_status,
        helper_wait_status: helper_status,
    };
    super::private_public_provider::retain_descriptor_auxiliary(
        selector,
        &policy.result_key,
        &serde_json::to_vec(&observation).map_err(|error| error.to_string())?,
    )
}
