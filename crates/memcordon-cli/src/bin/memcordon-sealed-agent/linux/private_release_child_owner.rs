//! OS-owned live descendant observation for the fixed child/thread case.
//! Target-reported IDs are selectors only: pidfd, proc task identity and the
//! attempt cgroup are independently read before the release acknowledgement.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Instant;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_children::{LIVE_BYTES, TargetLiveChildrenV1};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveDescendantWitnessV1 {
    pub(crate) schema_version: u8,
    pub(crate) target: ProcessIdentityV4,
    pub(crate) child: ProcessIdentityV4,
    pub(crate) thread_tid: u32,
    pub(crate) thread_start_time: u64,
    pub(crate) target_namespace_pid: u32,
    pub(crate) child_namespace_pid: u32,
    pub(crate) thread_namespace_tid: u32,
    pub(crate) target_pid_chain: Vec<u32>,
    pub(crate) child_pid_chain: Vec<u32>,
    pub(crate) thread_tid_chain: Vec<u32>,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) cgroup_procs_sha256: DiagnosticSha256,
    pub(crate) cgroup_threads_sha256: DiagnosticSha256,
}

impl LiveDescendantWitnessV1 {
    pub(crate) fn live_frame(&self) -> [u8; LIVE_BYTES] {
        let mut bytes = [0_u8; LIVE_BYTES];
        let mut offset = 0;
        let mut append = |part: &[u8]| {
            bytes[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        };
        append(super::private_release_children::LIVE_PREFIX);
        append(&self.target_namespace_pid.to_le_bytes());
        append(&self.child_namespace_pid.to_le_bytes());
        append(&self.thread_namespace_tid.to_le_bytes());
        append(self.challenge_sha256.bytes());
        bytes
    }
}

pub(crate) struct LiveDescendantCustodyV1 {
    pub(crate) witness: LiveDescendantWitnessV1,
    child_pidfd: OwnedFd,
}

impl LiveDescendantCustodyV1 {
    pub(crate) fn capture(
        target: &ProcessIdentityV4,
        target_pidfd: BorrowedFd<'_>,
        attempt_id: &str,
        challenge: &[u8; 32],
        frame: &[u8],
    ) -> Result<Self, String> {
        let decoded = TargetLiveChildrenV1::decode(frame, challenge)?;
        let target_pid_chain = read_namespace_chain(
            &Path::new("/proc")
                .join(target.pid.to_string())
                .join("status"),
        )?;
        if ProcessIdentityV4::observe(target.pid as libc::pid_t, target_pidfd)? != *target
            || !super::cgroup::valid_attempt_identity(attempt_id)
            || !chain_matches(&target_pid_chain, target.pid, decoded.target_pid)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: live descendant target differs".into());
        }
        let cgroup = Path::new(super::CGROUP_ROOT).join(attempt_id);
        let procs = read_bounded(&cgroup.join("cgroup.procs"))?;
        let threads = read_bounded(&cgroup.join("cgroup.threads"))?;
        let child_host_pid = find_child_host_pid(&procs, target.pid, decoded.child_pid)?;
        let child_pidfd = open_live_pidfd(child_host_pid)?;
        let child = ProcessIdentityV4::observe(child_host_pid as libc::pid_t, child_pidfd.as_fd())?;
        let child_pid_chain = read_namespace_chain(
            &Path::new("/proc")
                .join(child_host_pid.to_string())
                .join("status"),
        )?;
        let (child_tgid, child_parent) = read_status_ids(
            &Path::new("/proc")
                .join(child_host_pid.to_string())
                .join("status"),
        )?;
        let thread_host_tid = find_thread_host_tid(target.pid, decoded.thread_tid)?;
        let task = Path::new("/proc")
            .join(target.pid.to_string())
            .join("task")
            .join(thread_host_tid.to_string());
        let thread_tid_chain = read_namespace_chain(&task.join("status"))?;
        let (thread_tgid, thread_parent) = read_status_ids(&task.join("status"))?;
        let thread_start_time = read_start_time(&task.join("stat"))?;
        if child_tgid != child.pid
            || child_parent != target.pid
            || thread_tgid != target.pid
            || thread_parent == 0
            || thread_start_time == 0
            || !chain_matches(&child_pid_chain, child.pid, decoded.child_pid)
            || !chain_matches(&thread_tid_chain, thread_host_tid, decoded.thread_tid)
            || !has_decimal_id(&procs, target.pid)?
            || !has_decimal_id(&procs, child.pid)?
            || !has_decimal_id(&threads, target.pid)?
            || !has_decimal_id(&threads, thread_host_tid)?
            || !has_decimal_id(&threads, child.pid)?
        {
            return Err("MCSEALED-PRIVATE-RELEASE: live descendant kernel join differs".into());
        }
        let custody = Self {
            witness: LiveDescendantWitnessV1 {
                schema_version: 1,
                target: target.clone(),
                child,
                thread_tid: thread_host_tid,
                thread_start_time,
                target_namespace_pid: decoded.target_pid,
                child_namespace_pid: decoded.child_pid,
                thread_namespace_tid: decoded.thread_tid,
                target_pid_chain,
                child_pid_chain,
                thread_tid_chain,
                challenge_sha256: decoded.challenge_sha256,
                cgroup_procs_sha256: hash_bytes(&procs),
                cgroup_threads_sha256: hash_bytes(&threads),
            },
            child_pidfd,
        };
        custody.revalidate_live(target_pidfd, attempt_id)?;
        Ok(custody)
    }

    pub(crate) fn revalidate_live(
        &self,
        target_pidfd: BorrowedFd<'_>,
        attempt_id: &str,
    ) -> Result<(), String> {
        let target = &self.witness.target;
        let child = &self.witness.child;
        if ProcessIdentityV4::observe(target.pid as libc::pid_t, target_pidfd)? != *target
            || ProcessIdentityV4::observe(child.pid as libc::pid_t, self.child_pidfd.as_fd())?
                != *child
            || read_namespace_chain(
                &Path::new("/proc")
                    .join(target.pid.to_string())
                    .join("status"),
            )? != self.witness.target_pid_chain
            || read_namespace_chain(
                &Path::new("/proc")
                    .join(child.pid.to_string())
                    .join("status"),
            )? != self.witness.child_pid_chain
        {
            return Err("MCSEALED-PRIVATE-RELEASE: live descendant identity changed".into());
        }
        let task = Path::new("/proc")
            .join(target.pid.to_string())
            .join("task")
            .join(self.witness.thread_tid.to_string());
        let (tgid, _) = read_status_ids(&task.join("status"))?;
        if tgid != target.pid
            || read_namespace_chain(&task.join("status"))? != self.witness.thread_tid_chain
            || read_start_time(&task.join("stat"))? != self.witness.thread_start_time
        {
            return Err("MCSEALED-PRIVATE-RELEASE: live thread changed".into());
        }
        let cgroup = Path::new(super::CGROUP_ROOT).join(attempt_id);
        if !has_decimal_id(&read_bounded(&cgroup.join("cgroup.procs"))?, child.pid)?
            || !has_decimal_id(
                &read_bounded(&cgroup.join("cgroup.threads"))?,
                self.witness.thread_tid,
            )?
        {
            return Err("MCSEALED-PRIVATE-RELEASE: live cgroup changed".into());
        }
        Ok(())
    }

    pub(crate) fn verify_retired(
        self,
        attempt_id: &str,
    ) -> Result<LiveDescendantWitnessV1, String> {
        let mut polled = libc::pollfd {
            fd: self.child_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: this observes the exact child pidfd retained since the live readback.
        if unsafe { libc::poll(&raw mut polled, 1, 0) } != 1
            || polled.revents & libc::POLLIN == 0
            || polled.revents & (libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Err("MCSEALED-PRIVATE-RELEASE: child pidfd retirement absent".into());
        }
        verify_retired_witness(&self.witness, attempt_id)?;
        Ok(self.witness)
    }
}

pub(crate) fn verify_retired_witness(
    witness: &LiveDescendantWitnessV1,
    attempt_id: &str,
) -> Result<(), String> {
    if witness.schema_version != 1
        || witness.target.pid == 0
        || witness.child.pid == 0
        || witness.child.pid == witness.target.pid
        || witness.thread_tid == 0
        || witness.thread_tid == witness.target.pid
        || witness.thread_tid == witness.child.pid
        || witness.thread_start_time == 0
        || witness.target_namespace_pid == 0
        || witness.child_namespace_pid == 0
        || witness.thread_namespace_tid == 0
        || witness.target_namespace_pid == witness.child_namespace_pid
        || witness.target_namespace_pid == witness.thread_namespace_tid
        || witness.child_namespace_pid == witness.thread_namespace_tid
        || !chain_matches(
            &witness.target_pid_chain,
            witness.target.pid,
            witness.target_namespace_pid,
        )
        || !chain_matches(
            &witness.child_pid_chain,
            witness.child.pid,
            witness.child_namespace_pid,
        )
        || !chain_matches(
            &witness.thread_tid_chain,
            witness.thread_tid,
            witness.thread_namespace_tid,
        )
    {
        return Err("MCSEALED-PRIVATE-RELEASE: retired child witness differs".into());
    }
    let task = Path::new("/proc")
        .join(witness.target.pid.to_string())
        .join("task")
        .join(witness.thread_tid.to_string());
    match fs::symlink_metadata(task) {
        Ok(_) => return Err("MCSEALED-PRIVATE-RELEASE: thread task remains live".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE: thread task readback: {error}"
            ));
        }
    }
    super::private_release_run::require_recorded_process_exited(&witness.child)?;
    super::private_release_run::require_candidate_cgroup_absent(attempt_id)
}

pub(crate) fn read_live_frame(
    fd: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<[u8; LIVE_BYTES], String> {
    let mut bytes = [0_u8; LIVE_BYTES];
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("MCSEALED-PRIVATE-RELEASE: child live frame timed out")?;
        let timeout = i32::try_from(remaining.as_millis().min(i32::MAX as u128))
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child live deadline differs")?;
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows only the fixed target stdout descriptor.
        if unsafe { libc::poll(&raw mut pollfd, 1, timeout) } != 1
            || pollfd.revents & libc::POLLIN == 0
            || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Err("MCSEALED-PRIVATE-RELEASE: child live frame unavailable".into());
        }
        // SAFETY: the destination is the still-unwritten suffix of a fixed buffer.
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count <= 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: child live frame truncated".into());
        }
        offset += usize::try_from(count)
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child live count differs")?;
    }
    Ok(bytes)
}

fn open_live_pidfd(pid: u32) -> Result<OwnedFd, String> {
    if pid == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: child pid is zero".into());
    }
    // SAFETY: pidfd_open returns an owned descriptor for this exact PID.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as i32;
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: child pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open transferred one unique descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: child kernel read: {error}"))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("MCSEALED-PRIVATE-RELEASE: child kernel byte bound differs".into());
    }
    Ok(bytes)
}

fn read_status_ids(path: &Path) -> Result<(u32, u32), String> {
    let bytes = read_bounded(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child status is not UTF-8")?;
    parse_status_ids(text)
}

fn parse_status_ids(text: &str) -> Result<(u32, u32), String> {
    let mut tgid = None;
    let mut parent = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            if tgid.replace(parse_decimal(value.trim())?).is_some() {
                return Err("MCSEALED-PRIVATE-RELEASE: duplicate Tgid".into());
            }
        }
        if let Some(value) = line.strip_prefix("PPid:") {
            if parent.replace(parse_decimal(value.trim())?).is_some() {
                return Err("MCSEALED-PRIVATE-RELEASE: duplicate PPid".into());
            }
        }
    }
    match (tgid, parent) {
        (Some(tgid), Some(parent)) => Ok((tgid, parent)),
        _ => Err("MCSEALED-PRIVATE-RELEASE: child status identity absent".into()),
    }
}

pub(crate) fn read_namespace_chain(path: &Path) -> Result<Vec<u32>, String> {
    let bytes = read_bounded(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: namespace status is not UTF-8")?;
    parse_namespace_chain(text)
}

fn parse_namespace_chain(text: &str) -> Result<Vec<u32>, String> {
    let mut namespace_ids = None;
    for line in text.lines() {
        if let Some(chain) = line.strip_prefix("NSpid:") {
            if namespace_ids.is_some() {
                return Err("MCSEALED-PRIVATE-RELEASE: duplicate NSpid chain".into());
            }
            let mut ids = Vec::new();
            for value in chain.split_ascii_whitespace() {
                let value = parse_decimal(value)?;
                if value == 0 || ids.len() >= 8 {
                    return Err("MCSEALED-PRIVATE-RELEASE: namespace PID chain invalid".into());
                }
                ids.push(value);
            }
            namespace_ids = Some(ids);
        }
    }
    namespace_ids
        .filter(|ids| !ids.is_empty())
        .ok_or("MCSEALED-PRIVATE-RELEASE: namespace PID absent".into())
}

pub(crate) fn chain_matches(chain: &[u32], host: u32, namespace: u32) -> bool {
    chain.first() == Some(&host) && chain.last() == Some(&namespace)
}

#[cfg(feature = "test-support")]
pub(crate) fn chain_matches_for_test(chain: &[u32], host: u32, namespace: u32) -> bool {
    chain_matches(chain, host, namespace)
}

#[cfg(feature = "test-support")]
pub(crate) fn parse_namespace_chain_for_test(text: &str) -> Result<Vec<u32>, String> {
    parse_namespace_chain(text)
}

fn find_child_host_pid(
    cgroup_procs: &[u8],
    target_host_pid: u32,
    child_namespace_pid: u32,
) -> Result<u32, String> {
    let text = std::str::from_utf8(cgroup_procs)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: cgroup procs are not UTF-8")?;
    let mut selected = None;
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        if seen.len() >= 256 {
            return Err("MCSEALED-PRIVATE-RELEASE: cgroup process count differs".into());
        }
        let pid = parse_decimal(line)?;
        if !seen.insert(pid) {
            return Err("MCSEALED-PRIVATE-RELEASE: duplicate cgroup process".into());
        }
        if pid == target_host_pid {
            continue;
        }
        let status = Path::new("/proc").join(pid.to_string()).join("status");
        let (tgid, parent) = read_status_ids(&status)?;
        if tgid == pid
            && parent == target_host_pid
            && chain_matches(&read_namespace_chain(&status)?, pid, child_namespace_pid)
            && selected.replace(pid).is_some()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: multiple child PID mappings".into());
        }
    }
    selected.ok_or("MCSEALED-PRIVATE-RELEASE: child host PID absent".into())
}

fn find_thread_host_tid(target_host_pid: u32, thread_namespace_tid: u32) -> Result<u32, String> {
    let tasks = Path::new("/proc")
        .join(target_host_pid.to_string())
        .join("task");
    let mut selected = None;
    let mut count = 0;
    for entry in fs::read_dir(tasks).map_err(|error| error.to_string())? {
        count += 1;
        if count > 256 {
            return Err("MCSEALED-PRIVATE-RELEASE: target thread count differs".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let tid = parse_decimal(
            entry
                .file_name()
                .to_str()
                .ok_or("MCSEALED-PRIVATE-RELEASE: non-UTF-8 thread ID")?,
        )?;
        if tid == target_host_pid {
            continue;
        }
        let status = entry.path().join("status");
        let (tgid, _) = read_status_ids(&status)?;
        if tgid == target_host_pid
            && chain_matches(&read_namespace_chain(&status)?, tid, thread_namespace_tid)
            && selected.replace(tid).is_some()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: multiple thread ID mappings".into());
        }
    }
    selected.ok_or("MCSEALED-PRIVATE-RELEASE: thread host TID absent".into())
}

#[cfg(feature = "test-support")]
pub(crate) fn parse_status_ids_for_test(text: &str) -> Result<(u32, u32), String> {
    parse_status_ids(text)
}

#[cfg(feature = "test-support")]
pub(crate) fn has_decimal_id_for_test(bytes: &[u8], expected: u32) -> Result<bool, String> {
    has_decimal_id(bytes, expected)
}

fn read_start_time(path: &Path) -> Result<u64, String> {
    let bytes = read_bounded(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: thread stat is not UTF-8")?;
    let (_, fields) = text
        .rsplit_once(") ")
        .ok_or("MCSEALED-PRIVATE-RELEASE: thread stat shape differs")?;
    fields
        .split_ascii_whitespace()
        .nth(19)
        .ok_or("MCSEALED-PRIVATE-RELEASE: thread start absent")?
        .parse::<u64>()
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: thread start invalid".into())
}

fn parse_decimal(value: &str) -> Result<u32, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("MCSEALED-PRIVATE-RELEASE: child decimal field invalid".into());
    }
    value
        .parse()
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child decimal overflow".into())
}

fn has_decimal_id(bytes: &[u8], expected: u32) -> Result<bool, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: cgroup IDs are not UTF-8")?;
    let mut found = false;
    for line in text.lines() {
        if parse_decimal(line)? == expected {
            if found {
                return Err("MCSEALED-PRIVATE-RELEASE: duplicate cgroup ID".into());
            }
            found = true;
        }
    }
    Ok(found)
}
