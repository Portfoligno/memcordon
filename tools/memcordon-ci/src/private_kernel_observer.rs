//! Independent Linux qualification observer. The private tracefs instance is
//! armed before a case and read after it is disarmed. Ordinary syscall
//! tracepoints alone cannot prove a seccomp-suppressed call: a reviewed,
//! kernel-specific seccomp-decision probe and allocation-boundary uprobe are
//! mandatory. Unknown kernels, missing probes and ring-buffer loss fail shut.

use memcordon_core::DiagnosticSha256;
#[cfg(unix)]
use memcordon_core::workload_codec::hash_bytes;

use crate::{CiError, Result};

const MAX_TRACE_BYTES: usize = 8 * 1024 * 1024;
const REQUIRED_EVENTS: [&str; 13] = [
    "sched:sched_process_fork",
    "sched:sched_process_exec",
    "sched:sched_process_exit",
    "raw_syscalls:sys_enter",
    "raw_syscalls:sys_exit",
    "memcordon_private:mc_seccomp_decision",
    "memcordon_private:mc_allocation_boundary",
    "memcordon_private:mc_exec_identity",
    "memcordon_private:mc_task_exit",
    "memcordon_private:mc_syscall_return",
    "memcordon_private:mc_task_fork",
    "memcordon_private:mc_task_reap",
    "memcordon_private:mc_nsfd_closed",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelTaskIdentityV1 {
    pub(crate) pid: u32,
    pub(crate) start_time: u64,
    pub(crate) cgroup_inode: u64,
    pub(crate) time_ns_inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeccompActionV1 {
    Allow,
    Errno,
    KillProcess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllocationBoundaryKindV1 {
    Enter,
    Allocate,
    Exit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KernelEventV1 {
    Fork {
        parent: KernelTaskIdentityV1,
        child: KernelTaskIdentityV1,
    },
    ForkObserved {
        parent: KernelTaskIdentityV1,
        child_pid: u32,
    },
    Exec {
        task: KernelTaskIdentityV1,
        image_dev: u64,
        image_inode: u64,
        abi: u32,
    },
    Exit {
        task: KernelTaskIdentityV1,
        signal: i32,
    },
    Reap {
        task: KernelTaskIdentityV1,
    },
    NamespaceFdClosed {
        task: KernelTaskIdentityV1,
        namespace_inode: u64,
    },
    SeccompDecision {
        task: KernelTaskIdentityV1,
        arch: u32,
        syscall: i64,
        action: SeccompActionV1,
        errno: i32,
    },
    SyscallReturn {
        task: KernelTaskIdentityV1,
        arch: u32,
        syscall: i64,
        value: i64,
    },
    AllocationBoundary {
        task: KernelTaskIdentityV1,
        request_key: DiagnosticSha256,
        kind: AllocationBoundaryKindV1,
    },
}

/// All expectations originate from the reviewed CI release intent, never the
/// candidate artifact. The event probe-map digest includes the exact kernel
/// event formats and installed kprobe/uprobe definitions.
#[derive(Clone, Debug)]
pub(crate) struct ExpectedKernelAdapterV1 {
    pub(crate) boot_id: String,
    pub(crate) kernel_release: String,
    pub(crate) btf_sha256: DiagnosticSha256,
    pub(crate) probe_map_sha256: DiagnosticSha256,
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) coordinator_pid: u32,
    /// Exact BPF start-boottime nanoseconds for a detached fixture, or zero
    /// for live mode, which verifies `coordinator_start_ticks` with a reader
    /// time-namespace calibration while the coordinator remains alive.
    pub(crate) coordinator_start_time: u64,
    pub(crate) coordinator_start_ticks: u64,
    pub(crate) cgroup_inode: u64,
    /// Independently observed network-launch broker. Request hooks run in the
    /// sealed service cgroup; clone3 runs in this distinct systemd cgroup.
    pub(crate) broker_pid: u32,
    pub(crate) broker_start_ticks: u64,
    pub(crate) broker_cgroup_inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveKernelSubjectV1 {
    pub(crate) pid: u32,
    pub(crate) start_ticks: u64,
    pub(crate) cgroup_inode: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum InstalledObserverRoleV1 {
    SealedService,
    NetworkBroker,
}

/// The network broker is socket-activated. This preflight performs only a
/// zero-byte connection to its fixed root-owned socket, before any interval
/// is armed, then waits for the independently observed systemd MainPID.
/// It neither sends a launch frame nor counts as release-case evidence.
#[cfg(target_os = "linux")]
pub(crate) fn activate_installed_network_broker_for_observation() -> Result<LiveKernelSubjectV1> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};
    const SOCKET: &str = "/run/memcordon/sealed-network-launcher.sock";
    if !rustix::process::geteuid().is_root() {
        return Err(fail("broker observer preflight requires root"));
    }
    let metadata = std::fs::symlink_metadata(SOCKET)?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o600
    {
        return Err(fail("broker activation socket protection differs"));
    }
    let stream = UnixStream::connect(SOCKET)?;
    drop(stream);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(subject) =
            observe_installed_observer_subject(InstalledObserverRoleV1::NetworkBroker)
        {
            return Ok(subject);
        }
        if Instant::now() >= deadline {
            return Err(fail(
                "socket-activated broker did not establish exact MainPID",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn activate_installed_network_broker_for_observation() -> Result<LiveKernelSubjectV1> {
    Err(fail("broker observer preflight requires Linux"))
}

#[cfg(target_os = "linux")]
pub(crate) fn observe_installed_observer_subject(
    role: InstalledObserverRoleV1,
) -> Result<LiveKernelSubjectV1> {
    let (unit, argument) = match role {
        InstalledObserverRoleV1::SealedService => ("memcordon-sealed-agent.service", "serve"),
        InstalledObserverRoleV1::NetworkBroker => (
            "memcordon-sealed-network-launcher.service",
            "network-launch-broker",
        ),
    };
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", "--property=MainPID", "--value", unit])
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(fail("installed observer systemd unit lookup failed"));
    }
    let pid_text = std::str::from_utf8(&output.stdout)
        .map_err(|_| fail("installed observer MainPID encoding differs"))?
        .trim_end_matches('\n');
    if pid_text.is_empty() || !pid_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(fail("installed observer MainPID differs"));
    }
    let pid: u32 = pid_text
        .parse()
        .map_err(|_| fail("installed observer MainPID invalid"))?;
    if pid == 0 {
        return Err(fail("installed observer service is not running"));
    }
    let before = observe_live_kernel_subject(pid)?;
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    let expected = format!("/usr/libexec/memcordon-sealed-agent\0{argument}\0");
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    let membership = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let cgroup_path = membership
        .strip_prefix("0::")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| fail("installed observer unified cgroup differs"))?;
    if cmdline != expected.as_bytes()
        || executable != std::path::Path::new("/usr/libexec/memcordon-sealed-agent")
        || !cgroup_path.ends_with(&format!("/{unit}"))
        || observe_live_kernel_subject(pid)? != before
    {
        return Err(fail("installed observer unit process identity differs"));
    }
    Ok(before)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn observe_installed_observer_subject(
    _role: InstalledObserverRoleV1,
) -> Result<LiveKernelSubjectV1> {
    Err(fail("installed observer service requires Linux"))
}

/// Read an already-live PID twice around its unified cgroup membership.
/// The resulting cgroup inode is only an expectation: a BPF event must still
/// report the same kernel cgroup ID before an interval can be verified.
#[cfg(target_os = "linux")]
pub(crate) fn observe_live_kernel_subject(pid: u32) -> Result<LiveKernelSubjectV1> {
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};
    if pid == 0 {
        return Err(fail("kernel subject PID absent"));
    }
    let first = crate::private_process_clock::read_live_start_ticks(pid)?;
    let membership = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let mut lines = membership.lines();
    let relative = lines
        .next()
        .and_then(|line| line.strip_prefix("0::"))
        .ok_or_else(|| fail("kernel subject unified cgroup absent"))?;
    if lines.next().is_some()
        || !relative.starts_with('/')
        || Path::new(relative)
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(fail("kernel subject cgroup path differs"));
    }
    let cgroup = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let inode = std::fs::metadata(cgroup)?.ino();
    let second = crate::private_process_clock::read_live_start_ticks(pid)?;
    if first == 0
        || first != second
        || inode == 0
        || membership != std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?
    {
        return Err(fail("kernel subject changed during cgroup observation"));
    }
    Ok(LiveKernelSubjectV1 {
        pid,
        start_ticks: first,
        cgroup_inode: inode,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn observe_live_kernel_subject(_pid: u32) -> Result<LiveKernelSubjectV1> {
    Err(fail("kernel subject requires Linux"))
}

pub(crate) struct VerifiedKernelIntervalV1 {
    pub(crate) boot_id: String,
    pub(crate) kernel_release: String,
    pub(crate) btf_sha256: DiagnosticSha256,
    pub(crate) probe_map_sha256: DiagnosticSha256,
    pub(crate) trace_sha256: DiagnosticSha256,
    pub(crate) coordinator_pid: u32,
    pub(crate) coordinator_start_time: u64,
    pub(crate) cgroup_inode: u64,
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) events: Vec<KernelEventV1>,
    pub(crate) capture_bytes: Option<Vec<u8>>,
    pub(crate) physical_interval_id: Option<crate::private_kernel_replay::IntervalIdV1>,
    pub(crate) raw_candidate_only: bool,
    pub(crate) clock_inputs: Option<crate::private_process_clock::ProcClockInputsV1>,
    pub(crate) original_clock: Option<crate::private_process_clock::VerifiedProcClockCalibrationV1>,
    pub(crate) loader_stderr: Option<Vec<u8>>,
    pub(crate) observation_timing: Option<KernelObservationTimingV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KernelObservationTimingV1 {
    pub(crate) armed_monotonic_ns: u64,
    pub(crate) operation_begin_monotonic_ns: u64,
    pub(crate) operation_end_monotonic_ns: u64,
    pub(crate) detached_monotonic_ns: u64,
    pub(crate) drained_monotonic_ns: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KernelIntervalReplayMetadataV1 {
    pub(crate) schema_version: u8,
    pub(crate) kernel_release: String,
    pub(crate) probe_map_sha256: DiagnosticSha256,
    pub(crate) coordinator_pid: u32,
    pub(crate) coordinator_start_time: u64,
    pub(crate) cgroup_inode: u64,
    pub(crate) observation_timing: Option<KernelObservationTimingV1>,
}

pub(crate) struct VerifiedNoAllocationIntervalV1 {
    result_key: DiagnosticSha256,
    capture_sha256: DiagnosticSha256,
}

pub(crate) struct VerifiedAllocationIntervalV1 {
    result_key: DiagnosticSha256,
    capture_sha256: DiagnosticSha256,
}

impl VerifiedAllocationIntervalV1 {
    pub(crate) fn result_key(&self) -> &DiagnosticSha256 {
        &self.result_key
    }
    pub(crate) fn capture_sha256(&self) -> &DiagnosticSha256 {
        &self.capture_sha256
    }
}

impl VerifiedNoAllocationIntervalV1 {
    pub(crate) fn result_key(&self) -> &DiagnosticSha256 {
        &self.result_key
    }
    pub(crate) fn capture_sha256(&self) -> &DiagnosticSha256 {
        &self.capture_sha256
    }
}

#[allow(dead_code)] // Consumed by the semantic verifier when the host adapter is provisioned.
impl VerifiedKernelIntervalV1 {
    pub(crate) fn replay_metadata(&self) -> KernelIntervalReplayMetadataV1 {
        KernelIntervalReplayMetadataV1 {
            schema_version: 1,
            kernel_release: self.kernel_release.clone(),
            probe_map_sha256: self.probe_map_sha256.clone(),
            coordinator_pid: self.coordinator_pid,
            coordinator_start_time: self.coordinator_start_time,
            cgroup_inode: self.cgroup_inode,
            observation_timing: self.observation_timing.clone(),
        }
    }
    pub(crate) fn clock_inputs(&self) -> Option<&crate::private_process_clock::ProcClockInputsV1> {
        self.clock_inputs.as_ref()
    }
    pub(crate) fn original_clock(
        &self,
    ) -> Option<&crate::private_process_clock::VerifiedProcClockCalibrationV1> {
        self.original_clock.as_ref()
    }
    pub(crate) fn loader_stderr(&self) -> Option<&[u8]> {
        self.loader_stderr.as_deref()
    }
    pub(crate) fn observation_timing(&self) -> Option<&KernelObservationTimingV1> {
        self.observation_timing.as_ref()
    }
    pub(crate) fn physical_interval_id(
        &self,
    ) -> Option<&crate::private_kernel_replay::IntervalIdV1> {
        self.physical_interval_id.as_ref()
    }
    pub(crate) fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub(crate) fn kernel_release(&self) -> &str {
        &self.kernel_release
    }
    pub(crate) fn btf_sha256(&self) -> &DiagnosticSha256 {
        &self.btf_sha256
    }
    pub(crate) fn probe_map_sha256(&self) -> &DiagnosticSha256 {
        &self.probe_map_sha256
    }
    pub(crate) fn trace_sha256(&self) -> &DiagnosticSha256 {
        &self.trace_sha256
    }
    pub(crate) fn coordinator_pid(&self) -> u32 {
        self.coordinator_pid
    }
    pub(crate) fn coordinator_start_time(&self) -> u64 {
        self.coordinator_start_time
    }
    pub(crate) fn cgroup_inode(&self) -> u64 {
        self.cgroup_inode
    }
    pub(crate) fn result_key(&self) -> &DiagnosticSha256 {
        &self.result_key
    }
    pub(crate) fn events(&self) -> &[KernelEventV1] {
        &self.events
    }
    /// Exact zero-loss binary capture for C V3. A legacy tracefs interval
    /// cannot issue this byte-level evidence and is nonqualifying.
    pub(crate) fn capture_bytes(&self) -> Result<&[u8]> {
        self.capture_bytes
            .as_deref()
            .ok_or_else(|| fail("kernel interval lacks qualifying binary capture"))
    }
    /// A capture must contain the exact enter/exit pair and zero Allocate
    /// events under the branch's protected result key. The binary parser has
    /// already rejected sequence gaps, kernel loss and escaped allocations.
    pub(crate) fn verify_no_allocation(
        &self,
        expected_result_key: &DiagnosticSha256,
    ) -> Result<VerifiedNoAllocationIntervalV1> {
        self.capture_bytes()?;
        if self.raw_candidate_only {
            return Err(fail(
                "raw candidate projection cannot issue a legacy allocation capability",
            ));
        }
        if &self.result_key != expected_result_key
            || !self.has_allocation_boundary()
            || !self.no_allocation()
        {
            return Err(fail("kernel observer negative branch allocated a target"));
        }
        Ok(VerifiedNoAllocationIntervalV1 {
            result_key: self.result_key.clone(),
            capture_sha256: self.trace_sha256.clone(),
        })
    }
    pub(crate) fn verify_allocation(
        &self,
        expected_result_key: &DiagnosticSha256,
    ) -> Result<VerifiedAllocationIntervalV1> {
        self.capture_bytes()?;
        if self.raw_candidate_only {
            return Err(fail(
                "raw candidate projection cannot issue a legacy allocation capability",
            ));
        }
        if &self.result_key != expected_result_key
            || !self.has_allocation_boundary()
            || self.no_allocation()
        {
            return Err(fail("kernel observer positive control lacked allocation"));
        }
        Ok(VerifiedAllocationIntervalV1 {
            result_key: self.result_key.clone(),
            capture_sha256: self.trace_sha256.clone(),
        })
    }
    pub(crate) fn seccomp_decision(
        &self,
        task: KernelTaskIdentityV1,
        arch: u32,
        syscall: i64,
        action: SeccompActionV1,
    ) -> bool {
        self.events.iter().any(|event| {
            matches!(event, KernelEventV1::SeccompDecision {
                task: observed_task,
                arch: observed_arch,
                syscall: observed_syscall,
                action: observed_action,
                ..
            } if *observed_task == task && *observed_arch == arch
                && *observed_syscall == syscall && *observed_action == action)
        })
    }
    pub(crate) fn exec_identity(
        &self,
        task: KernelTaskIdentityV1,
        dev: u64,
        inode: u64,
        abi: u32,
    ) -> bool {
        self.events.iter().any(|event| {
            matches!(event, KernelEventV1::Exec {
                task: observed_task,
                image_dev,
                image_inode,
                abi: observed_abi,
            } if *observed_task == task && *image_dev == dev
                && *image_inode == inode && *observed_abi == abi)
        })
    }
    pub(crate) fn no_allocation(&self) -> bool {
        !self.events.iter().any(|event| {
            matches!(event, KernelEventV1::AllocationBoundary {
                request_key,
                kind: AllocationBoundaryKindV1::Allocate,
                ..
            } if request_key == &self.result_key)
        })
    }
    pub(crate) fn has_allocation_boundary(&self) -> bool {
        self.events.iter().any(|event| {
            matches!(event, KernelEventV1::AllocationBoundary { request_key, .. }
                if request_key == &self.result_key)
        })
    }
    pub(crate) fn retired_task(&self, task: KernelTaskIdentityV1) -> bool {
        self.events.iter().any(|event| {
            matches!(event, KernelEventV1::Exit { task: observed, .. }
                if *observed == task)
        }) && self.events.iter().any(|event| {
            matches!(event, KernelEventV1::Reap { task: observed }
                    if *observed == task)
        })
    }
    pub(crate) fn namespace_fd_closed(
        &self,
        task: KernelTaskIdentityV1,
        namespace_inode: u64,
    ) -> bool {
        self.events.iter().any(|event| {
            matches!(event, KernelEventV1::NamespaceFdClosed {
                task: observed,
                namespace_inode: observed_inode,
            } if *observed == task && *observed_inode == namespace_inode)
        })
    }
}

#[cfg(test)]
impl VerifiedKernelIntervalV1 {
    pub(crate) fn from_events_for_test(events: Vec<KernelEventV1>, cgroup_inode: u64) -> Self {
        Self::from_events_with_ids_for_test(
            events,
            cgroup_inode,
            DiagnosticSha256::from_bytes([5; 32]),
            DiagnosticSha256::from_bytes([4; 32]),
        )
    }

    pub(crate) fn from_events_with_ids_for_test(
        events: Vec<KernelEventV1>,
        cgroup_inode: u64,
        result_key: DiagnosticSha256,
        trace_sha256: DiagnosticSha256,
    ) -> Self {
        Self {
            boot_id: "test-boot".into(),
            kernel_release: "test-kernel".into(),
            btf_sha256: DiagnosticSha256::from_bytes([2; 32]),
            probe_map_sha256: DiagnosticSha256::from_bytes([3; 32]),
            trace_sha256,
            coordinator_pid: 1,
            coordinator_start_time: 1,
            cgroup_inode,
            result_key,
            events,
            capture_bytes: Some(vec![1]),
            physical_interval_id: None,
            raw_candidate_only: false,
            clock_inputs: None,
            original_clock: None,
            loader_stderr: None,
            observation_timing: None,
        }
    }
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

/// Strictly parses only the fixed dedicated probe payloads. `tracefs` prefix
/// fields are ignored; they are not treated as authority. Unrecognized lines
/// are harmless only for unrelated tasks; malformed required events fail.
fn parse_dedicated_event(line: &str) -> Result<Option<KernelEventV1>> {
    let Some((name, payload)) = line.rsplit_once(": ") else {
        return Ok(None);
    };
    let name = name.rsplit(' ').next().unwrap_or("");
    let fields: Vec<(&str, &str)> = payload
        .split_ascii_whitespace()
        .filter_map(|field| field.split_once('='))
        .collect();
    let value = |key: &str| -> Result<&str> {
        fields
            .iter()
            .find_map(|(found, value)| (*found == key).then_some(*value))
            .ok_or_else(|| fail("kernel observer required event field absent"))
    };
    let u32_field = |key| -> Result<u32> {
        value(key)?
            .parse()
            .map_err(|_| fail("kernel observer numeric event field invalid"))
    };
    let u64_field = |key| -> Result<u64> {
        value(key)?
            .parse()
            .map_err(|_| fail("kernel observer numeric event field invalid"))
    };
    let i64_field = |key| -> Result<i64> {
        value(key)?
            .parse()
            .map_err(|_| fail("kernel observer numeric event field invalid"))
    };
    let task = || -> Result<KernelTaskIdentityV1> {
        let task = KernelTaskIdentityV1 {
            pid: u32_field("pid")?,
            start_time: u64_field("start")?,
            cgroup_inode: u64_field("cgroup")?,
            time_ns_inode: 0,
        };
        if task.pid == 0 || task.start_time == 0 || task.cgroup_inode == 0 {
            return Err(fail("kernel observer task identity invalid"));
        }
        Ok(task)
    };
    let event = match name {
        "mc_seccomp_decision" => {
            let action = match value("action")? {
                "allow" => SeccompActionV1::Allow,
                "errno" => SeccompActionV1::Errno,
                "kill-process" => SeccompActionV1::KillProcess,
                _ => return Err(fail("kernel observer seccomp action unknown")),
            };
            Some(KernelEventV1::SeccompDecision {
                task: task()?,
                arch: u32_field("arch")?,
                syscall: i64_field("nr")?,
                action,
                errno: i64_field("errno")?
                    .try_into()
                    .map_err(|_| fail("kernel observer seccomp errno invalid"))?,
            })
        }
        "mc_allocation_boundary" => {
            let key = value("request_key")?;
            let bounded = memcordon_core::BoundedText::new(key)
                .map_err(|_| fail("kernel observer request key invalid"))?;
            let request_key = DiagnosticSha256::try_from(bounded)
                .map_err(|_| fail("kernel observer request key invalid"))?;
            let kind = match value("kind")? {
                "allocate" => AllocationBoundaryKindV1::Allocate,
                "enter" => AllocationBoundaryKindV1::Enter,
                "exit" => AllocationBoundaryKindV1::Exit,
                _ => return Err(fail("kernel observer allocation kind unknown")),
            };
            Some(KernelEventV1::AllocationBoundary {
                task: task()?,
                request_key,
                kind,
            })
        }
        "mc_task_fork" => {
            let parent = KernelTaskIdentityV1 {
                pid: u32_field("parent_pid")?,
                start_time: u64_field("parent_start")?,
                cgroup_inode: u64_field("cgroup")?,
                time_ns_inode: 0,
            };
            let child = KernelTaskIdentityV1 {
                pid: u32_field("child_pid")?,
                start_time: u64_field("child_start")?,
                cgroup_inode: u64_field("cgroup")?,
                time_ns_inode: 0,
            };
            if parent.pid == 0
                || parent.start_time == 0
                || child.pid == 0
                || child.start_time == 0
                || parent == child
                || parent.cgroup_inode == 0
            {
                return Err(fail("kernel observer fork identity invalid"));
            }
            Some(KernelEventV1::Fork { parent, child })
        }
        "mc_exec_identity" => Some(KernelEventV1::Exec {
            task: task()?,
            image_dev: u64_field("dev")?,
            image_inode: u64_field("ino")?,
            abi: u32_field("abi")?,
        }),
        "mc_task_exit" => Some(KernelEventV1::Exit {
            task: task()?,
            signal: i64_field("signal")?
                .try_into()
                .map_err(|_| fail("kernel observer exit signal invalid"))?,
        }),
        "mc_task_reap" => Some(KernelEventV1::Reap { task: task()? }),
        "mc_nsfd_closed" => Some(KernelEventV1::NamespaceFdClosed {
            task: task()?,
            namespace_inode: u64_field("ns_inode")?,
        }),
        "mc_syscall_return" => Some(KernelEventV1::SyscallReturn {
            task: task()?,
            arch: u32_field("arch")?,
            syscall: i64_field("nr")?,
            value: i64_field("ret")?,
        }),
        _ => None,
    };
    Ok(event)
}

/// Detached parser used only after a live adapter has armed, disarmed, read
/// every per-CPU loss counter and checked the host intent hashes. It is kept
/// private so artifact bytes cannot manufacture a verified interval.
fn parse_trace(trace: &[u8]) -> Result<Vec<KernelEventV1>> {
    if trace.is_empty() || trace.len() > MAX_TRACE_BYTES {
        return Err(fail("kernel observer trace bound differs"));
    }
    let text =
        std::str::from_utf8(trace).map_err(|_| fail("kernel observer trace is not UTF-8"))?;
    let mut events = Vec::new();
    for line in text.lines() {
        if let Some(event) = parse_dedicated_event(line)? {
            events.push(event);
        }
    }
    if events.is_empty() {
        return Err(fail("kernel observer produced no typed events"));
    }
    Ok(events)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KnownActionTupleV1 {
    pub(crate) task: KernelTaskIdentityV1,
    pub(crate) arch: u32,
    pub(crate) syscall: i64,
    pub(crate) action: SeccompActionV1,
}

pub(crate) struct VerifiedKnownActionControlsV1 {
    boot_id: String,
    btf_sha256: DiagnosticSha256,
    probe_map_sha256: DiagnosticSha256,
}

impl VerifiedKernelIntervalV1 {
    /// Three actual independent kernel decisions are required before a case
    /// interval can use this adapter. A fixture's expected errno alone is not
    /// a seccomp decision and cannot supply the control token.
    pub(crate) fn verify_known_action_controls(
        &self,
        allow: KnownActionTupleV1,
        errno: KnownActionTupleV1,
        kill: KnownActionTupleV1,
    ) -> Result<VerifiedKnownActionControlsV1> {
        self.capture_bytes()?;
        if allow.action != SeccompActionV1::Allow
            || errno.action != SeccompActionV1::Errno
            || kill.action != SeccompActionV1::KillProcess
            || [allow, errno, kill].iter().any(|tuple| {
                tuple.task.pid == 0
                    || !self.seccomp_decision(tuple.task, tuple.arch, tuple.syscall, tuple.action)
            })
        {
            return Err(fail("kernel observer known-action controls differ"));
        }
        Ok(VerifiedKnownActionControlsV1 {
            boot_id: self.boot_id.clone(),
            btf_sha256: self.btf_sha256.clone(),
            probe_map_sha256: self.probe_map_sha256.clone(),
        })
    }
}

#[cfg(unix)]
mod live {
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    use super::*;

    const TRACEFS: &str = "/sys/kernel/tracing";
    const BTF: &str = "/sys/kernel/btf/vmlinux";
    const MAX_BTF_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_PROBE_BYTES: u64 = 1024 * 1024;

    fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                CiError::Message(format!("kernel observer open {}: {error}", path.display()))
            })?;
        let metadata = file
            .metadata()
            .map_err(|error| CiError::Message(error.to_string()))?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.len() > maximum {
            return Err(fail("kernel observer protected source differs"));
        }
        let mut bytes = Vec::new();
        file.take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if bytes.is_empty() || bytes.len() as u64 > maximum {
            return Err(fail("kernel observer source length differs"));
        }
        Ok(bytes)
    }

    fn write_control(path: &Path, bytes: &[u8]) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            CiError::Message(format!(
                "kernel observer control {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.is_file() || metadata.uid() != 0 {
            return Err(fail("kernel observer control protection differs"));
        }
        fs::write(path, bytes).map_err(|error| {
            CiError::Message(format!(
                "kernel observer control {}: {error}",
                path.display()
            ))
        })
    }

    fn event_format(root: &Path, event: &str) -> Result<Vec<u8>> {
        let (group, name) = event
            .split_once(':')
            .ok_or_else(|| fail("kernel observer event identifier invalid"))?;
        read_bounded(
            &root.join("events").join(group).join(name).join("format"),
            MAX_PROBE_BYTES,
        )
    }

    fn probe_map_digest(root: &Path) -> Result<DiagnosticSha256> {
        let mut map = Vec::new();
        for event in REQUIRED_EVENTS {
            let bytes = event_format(root, event)?;
            map.extend_from_slice(event.as_bytes());
            map.push(0);
            map.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            map.extend_from_slice(&bytes);
        }
        for leaf in ["kprobe_events", "uprobe_events"] {
            let bytes = read_bounded(&Path::new(TRACEFS).join(leaf), MAX_PROBE_BYTES)?;
            map.extend_from_slice(leaf.as_bytes());
            map.push(0);
            map.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            map.extend_from_slice(&bytes);
        }
        Ok(hash_bytes(&map))
    }

    fn read_current_host(expected: &ExpectedKernelAdapterV1) -> Result<()> {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| CiError::Message(error.to_string()))?;
        let release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|error| CiError::Message(error.to_string()))?;
        if boot.trim() != expected.boot_id
            || release.trim() != expected.kernel_release
            || hash_bytes(&read_bounded(Path::new(BTF), MAX_BTF_BYTES)?) != expected.btf_sha256
            || probe_map_digest(Path::new(TRACEFS))? != expected.probe_map_sha256
        {
            return Err(fail("kernel observer host adapter differs from CI intent"));
        }
        Ok(())
    }

    fn effective_uid() -> Result<u32> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|error| CiError::Message(error.to_string()))?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .ok_or_else(|| fail("kernel observer effective UID unavailable"))?
            .parse()
            .map_err(|_| fail("kernel observer effective UID invalid"))
    }

    fn require_zero_loss(root: &Path) -> Result<()> {
        let cpu_root = root.join("per_cpu");
        let mut observed_cpu = false;
        for entry in fs::read_dir(cpu_root).map_err(|error| CiError::Message(error.to_string()))? {
            let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
            if !entry.file_name().to_string_lossy().starts_with("cpu") {
                continue;
            }
            observed_cpu = true;
            let bytes = read_bounded(&entry.path().join("stats"), 64 * 1024)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| fail("kernel observer CPU stats invalid"))?;
            for label in ["overrun", "commit overrun", "dropped events"] {
                let value = text
                    .lines()
                    .find_map(|line| line.trim().strip_prefix(label))
                    .and_then(|tail| tail.trim_start().strip_prefix(':'))
                    .ok_or_else(|| fail("kernel observer loss counter unavailable"))?
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| fail("kernel observer loss counter invalid"))?;
                if value != 0 {
                    return Err(fail("kernel observer dropped events"));
                }
            }
        }
        if !observed_cpu {
            return Err(fail("kernel observer CPU coverage absent"));
        }
        Ok(())
    }

    pub(crate) struct ArmedTracefsIntervalV1 {
        root: PathBuf,
        expected: ExpectedKernelAdapterV1,
        active: bool,
    }

    impl ArmedTracefsIntervalV1 {
        pub(crate) fn arm_control_preflight(expected: ExpectedKernelAdapterV1) -> Result<Self> {
            Self::arm_inner(expected, None)
        }

        pub(crate) fn arm_case(
            expected: ExpectedKernelAdapterV1,
            controls: &VerifiedKnownActionControlsV1,
        ) -> Result<Self> {
            Self::arm_inner(expected, Some(controls))
        }

        fn arm_inner(
            expected: ExpectedKernelAdapterV1,
            controls: Option<&VerifiedKnownActionControlsV1>,
        ) -> Result<Self> {
            if !cfg!(target_os = "linux")
                || effective_uid()? != 0
                || expected.coordinator_pid == 0
                || expected.coordinator_start_time == 0
                || expected.cgroup_inode == 0
                || controls.is_some_and(|controls| {
                    expected.boot_id != controls.boot_id
                        || expected.btf_sha256 != controls.btf_sha256
                        || expected.probe_map_sha256 != controls.probe_map_sha256
                })
            {
                return Err(fail("kernel observer control authority differs"));
            }
            read_current_host(&expected)?;
            let key = String::from(expected.result_key.clone());
            let root = Path::new(TRACEFS)
                .join("instances")
                .join(format!("memcordon-{}", &key[..24]));
            fs::create_dir(&root).map_err(|error| {
                CiError::Message(format!("kernel observer instance create: {error}"))
            })?;
            let mut interval = Self {
                root,
                expected,
                active: false,
            };
            write_control(&interval.root.join("tracing_on"), b"0")?;
            write_control(&interval.root.join("options/event-fork"), b"1")?;
            write_control(
                &interval.root.join("set_event_pid"),
                interval.expected.coordinator_pid.to_string().as_bytes(),
            )?;
            write_control(&interval.root.join("buffer_size_kb"), b"8192")?;
            let mut events = REQUIRED_EVENTS.join("\n");
            events.push('\n');
            write_control(&interval.root.join("set_event"), events.as_bytes())?;
            write_control(&interval.root.join("trace"), b"")?;
            require_zero_loss(&interval.root)?;
            write_control(&interval.root.join("tracing_on"), b"1")?;
            interval.active = true;
            Ok(interval)
        }

        pub(crate) fn finish(mut self) -> Result<VerifiedKernelIntervalV1> {
            write_control(&self.root.join("tracing_on"), b"0")?;
            self.active = false;
            require_zero_loss(&self.root)?;
            read_current_host(&self.expected)?;
            let trace = read_bounded(&self.root.join("trace"), MAX_TRACE_BYTES as u64)?;
            let events = parse_trace(&trace)?;
            let mut entry = None;
            let mut exit = None;
            for (index, event) in events.iter().enumerate() {
                if let KernelEventV1::AllocationBoundary {
                    task,
                    request_key,
                    kind,
                } = event
                {
                    if request_key != &self.expected.result_key {
                        continue;
                    }
                    if task.cgroup_inode != self.expected.cgroup_inode {
                        return Err(fail("kernel observer request cgroup differs"));
                    }
                    match kind {
                        AllocationBoundaryKindV1::Enter if entry.replace(index).is_some() => {
                            return Err(fail("kernel observer duplicate request entry"));
                        }
                        AllocationBoundaryKindV1::Exit if exit.replace(index).is_some() => {
                            return Err(fail("kernel observer duplicate request exit"));
                        }
                        _ => {}
                    }
                }
            }
            let (Some(entry), Some(exit)) = (entry, exit) else {
                return Err(fail("kernel observer request interval incomplete"));
            };
            if entry >= exit
                || events[..entry]
                    .iter()
                    .chain(&events[exit + 1..])
                    .any(|event| {
                        matches!(event, KernelEventV1::AllocationBoundary {
                        request_key,
                        kind: AllocationBoundaryKindV1::Allocate,
                        ..
                    } if request_key == &self.expected.result_key)
                    })
            {
                return Err(fail("kernel observer allocation escaped request interval"));
            }
            Ok(VerifiedKernelIntervalV1 {
                boot_id: self.expected.boot_id.clone(),
                kernel_release: self.expected.kernel_release.clone(),
                btf_sha256: self.expected.btf_sha256.clone(),
                probe_map_sha256: self.expected.probe_map_sha256.clone(),
                trace_sha256: hash_bytes(&trace),
                coordinator_pid: self.expected.coordinator_pid,
                coordinator_start_time: self.expected.coordinator_start_time,
                cgroup_inode: self.expected.cgroup_inode,
                result_key: self.expected.result_key.clone(),
                events,
                capture_bytes: None,
                physical_interval_id: None,
                raw_candidate_only: false,
                clock_inputs: None,
                original_clock: None,
                loader_stderr: None,
                observation_timing: None,
            })
        }
    }

    impl Drop for ArmedTracefsIntervalV1 {
        fn drop(&mut self) {
            if self.active {
                let _ = write_control(&self.root.join("tracing_on"), b"0");
            }
            let _ = fs::remove_dir(&self.root);
        }
    }

    pub(crate) use ArmedTracefsIntervalV1 as Armed;
}

#[cfg(unix)]
pub(crate) use live::Armed as ArmedTracefsIntervalV1;

#[cfg(unix)]
mod probe_bundle_live {
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::private_probe_bundle::VerifiedProbeBundleV1;

    const CAPTURE_ROOT: &str = "/run/memcordon-private-observer";
    struct SupervisedLoader {
        child: std::process::Child,
        stdout: Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
        stderr: Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    }
    impl std::ops::Deref for SupervisedLoader {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            &self.child
        }
    }
    impl std::ops::DerefMut for SupervisedLoader {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.child
        }
    }
    impl Drop for SupervisedLoader {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(reader) = self.stdout.take() {
                let _ = reader.join();
            }
            if let Some(reader) = self.stderr.take() {
                let _ = reader.join();
            }
        }
    }
    fn read_bounded_loader_stream(stream: impl Read) -> std::io::Result<Vec<u8>> {
        let limit = 64 * 1024;
        let mut bytes = Vec::new();
        stream.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit as usize {
            return Err(std::io::Error::other("kernel loader stream overflow"));
        }
        Ok(bytes)
    }
    fn join_loader_reader(reader: thread::JoinHandle<std::io::Result<Vec<u8>>>) -> Result<Vec<u8>> {
        reader
            .join()
            .map_err(|_| fail("kernel loader reader panicked"))?
            .map_err(CiError::Io)
    }
    const CAPTURE_MAGIC: u32 = 0x4d434b31;
    const HEADER_BYTES: usize = 24;
    const EVENT_BYTES: usize = 128;
    const MAX_EVENTS: usize = 100_000;

    fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or_else(|| fail("kernel probe capture truncated"))?
                .try_into()
                .map_err(|_| fail("kernel probe capture truncated"))?,
        ))
    }
    fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(
            bytes
                .get(offset..offset + 8)
                .ok_or_else(|| fail("kernel probe capture truncated"))?
                .try_into()
                .map_err(|_| fail("kernel probe capture truncated"))?,
        ))
    }
    fn i64_at(bytes: &[u8], offset: usize) -> Result<i64> {
        Ok(i64::from_le_bytes(
            bytes
                .get(offset..offset + 8)
                .ok_or_else(|| fail("kernel probe capture truncated"))?
                .try_into()
                .map_err(|_| fail("kernel probe capture truncated"))?,
        ))
    }

    pub(crate) fn parse_capture(
        bytes: &[u8],
        expected: &ExpectedKernelAdapterV1,
    ) -> Result<Vec<KernelEventV1>> {
        parse_capture_scope(bytes, expected, false)
    }

    fn parse_capture_scope(
        bytes: &[u8],
        expected: &ExpectedKernelAdapterV1,
        raw_candidate: bool,
    ) -> Result<Vec<KernelEventV1>> {
        let projection;
        let bytes = if bytes.len() >= 8 && u32_at(bytes, 4)? == 2 {
            projection = crate::private_kernel_replay::diagnostic_v1_projection(
                bytes,
                &expected.result_key,
            )?;
            projection.as_slice()
        } else {
            bytes
        };
        if bytes.len() < HEADER_BYTES
            || u32_at(bytes, 0)? != CAPTURE_MAGIC
            || u32_at(bytes, 4)? != 1
            || u64_at(bytes, 16)? != 0
        {
            return Err(fail("kernel probe capture header or loss differs"));
        }
        let count = usize::try_from(u64_at(bytes, 8)?)
            .map_err(|_| fail("kernel probe event count invalid"))?;
        if count == 0 || count > MAX_EVENTS || bytes.len() != HEADER_BYTES + count * EVENT_BYTES {
            return Err(fail("kernel probe capture length differs"));
        }
        let mut sequences = Vec::with_capacity(count);
        let mut events = Vec::with_capacity(count);
        let mut descendants = std::collections::BTreeMap::<u32, u64>::new();
        let mut seen_starts = std::collections::BTreeMap::<u32, u64>::new();
        let mut saw_coordinator = false;
        for index in 0..count {
            let raw = &bytes[HEADER_BYTES + index * EVENT_BYTES..][..EVENT_BYTES];
            let sequence = u64_at(raw, 0)?;
            let monotonic_ns = u64_at(raw, 8)?;
            let cgroup_id = u64_at(raw, 16)?;
            let task = KernelTaskIdentityV1 {
                pid: u32_at(raw, 64)?,
                start_time: u64_at(raw, 24)?,
                cgroup_inode: cgroup_id,
                time_ns_inode: u64_at(raw, 120)?,
            };
            if sequence == 0
                || monotonic_ns == 0
                || task.pid == 0
                || task.start_time == 0
                || task.time_ns_inode == 0
                || cgroup_id == 0
                || raw[84..116] != *expected.result_key.bytes()
            {
                return Err(fail("kernel probe event identity differs"));
            }
            if seen_starts
                .insert(task.pid, task.start_time)
                .is_some_and(|previous| previous != task.start_time)
            {
                return Err(fail("kernel probe PID reused in interval"));
            }
            // release_task runs in the reaper's context, possibly outside all
            // selected cgroups. Its victim is joined to an exact prior exit.
            if !matches!(u32_at(raw, 80)?, 7 | 9 | 10)
                && cgroup_id != expected.cgroup_inode
                && cgroup_id != expected.broker_cgroup_inode
            {
                let Some(known_start) = descendants.get_mut(&task.pid) else {
                    return Err(fail("kernel probe subject escaped known fork lineage"));
                };
                if *known_start != 0 && *known_start != task.start_time {
                    return Err(fail("kernel probe descendant start differs"));
                }
                *known_start = task.start_time;
            }
            if task.pid == expected.coordinator_pid
                && (expected.coordinator_start_time == 0
                    || task.start_time == expected.coordinator_start_time)
                && cgroup_id == expected.cgroup_inode
            {
                saw_coordinator = true;
            }
            if sequence != index as u64 + 1 {
                return Err(fail("kernel probe event sequence/order differs"));
            }
            sequences.push(sequence);
            let event = match u32_at(raw, 80)? {
                1 => {
                    if !raw_candidate && task.cgroup_inode != expected.cgroup_inode {
                        return Err(fail("kernel probe request entry cgroup differs"));
                    }
                    KernelEventV1::AllocationBoundary {
                        task,
                        request_key: expected.result_key.clone(),
                        kind: AllocationBoundaryKindV1::Enter,
                    }
                }
                2 => {
                    if !raw_candidate && task.cgroup_inode != expected.cgroup_inode {
                        return Err(fail("kernel probe request exit cgroup differs"));
                    }
                    KernelEventV1::AllocationBoundary {
                        task,
                        request_key: expected.result_key.clone(),
                        kind: AllocationBoundaryKindV1::Exit,
                    }
                }
                3 => {
                    if !raw_candidate && task.cgroup_inode != expected.broker_cgroup_inode {
                        return Err(fail(
                            "kernel allocation did not run in pinned broker cgroup",
                        ));
                    }
                    KernelEventV1::AllocationBoundary {
                        task,
                        request_key: expected.result_key.clone(),
                        kind: AllocationBoundaryKindV1::Allocate,
                    }
                }
                4 => {
                    let action = match u32_at(raw, 76)? {
                        0x7fff0000 => SeccompActionV1::Allow,
                        0x00050000 => SeccompActionV1::Errno,
                        0x80000000 => SeccompActionV1::KillProcess,
                        _ => return Err(fail("kernel probe seccomp action unsupported")),
                    };
                    KernelEventV1::SeccompDecision {
                        task,
                        arch: u32_at(raw, 72)?,
                        syscall: i64_at(raw, 48)?,
                        action,
                        errno: i64_at(raw, 56)?
                            .try_into()
                            .map_err(|_| fail("kernel probe seccomp errno invalid"))?,
                    }
                }
                5 => KernelEventV1::SyscallReturn {
                    task,
                    arch: u32_at(raw, 72)?,
                    syscall: i64_at(raw, 48)?,
                    value: i64_at(raw, 56)?,
                },
                6 => KernelEventV1::Exec {
                    task,
                    image_dev: u64_at(raw, 32)?,
                    image_inode: u64_at(raw, 40)?,
                    abi: u32_at(raw, 72)?,
                },
                7 => {
                    let child_pid = u32_at(raw, 68)?;
                    if child_pid == 0
                        || child_pid == task.pid
                        || descendants.insert(child_pid, 0).is_some()
                    {
                        return Err(fail("kernel probe fork lineage differs"));
                    }
                    KernelEventV1::ForkObserved {
                        parent: task,
                        child_pid,
                    }
                }
                8 => KernelEventV1::Exit {
                    task,
                    signal: i64_at(raw, 56)?
                        .try_into()
                        .map_err(|_| fail("kernel probe exit status invalid"))?,
                },
                9 => {
                    let victim_pid = u32_at(raw, 68)?;
                    let victim_start = u64::try_from(i64_at(raw, 56)?)
                        .map_err(|_| fail("kernel probe reap start invalid"))?;
                    let victims: Vec<_> = events
                        .iter()
                        .filter_map(|prior| match prior {
                            KernelEventV1::Exit { task: exited, .. }
                                if exited.pid == victim_pid
                                    && exited.start_time == victim_start =>
                            {
                                Some(*exited)
                            }
                            _ => None,
                        })
                        .collect();
                    if victims.len() != 1 || victim_pid == 0 || victim_pid == task.pid {
                        return Err(fail("kernel probe reap lacks unique prior exit"));
                    }
                    KernelEventV1::Reap { task: victims[0] }
                }
                10 => {
                    let namespace_inode = u64_at(raw, 40)?;
                    if namespace_inode == 0 || i64_at(raw, 56)? != 0 {
                        return Err(fail("kernel probe namespace fd close differs"));
                    }
                    KernelEventV1::NamespaceFdClosed {
                        task,
                        namespace_inode,
                    }
                }
                _ => return Err(fail("kernel probe event kind unsupported")),
            };
            events.push(event);
        }
        if sequences
            .iter()
            .enumerate()
            .any(|(index, value)| *value != index as u64 + 1)
        {
            return Err(fail("kernel probe event sequence has a gap"));
        }
        if !saw_coordinator {
            return Err(fail("kernel probe coordinator absent"));
        }
        if !raw_candidate {
            validate_request_pairs(&events, expected)?;
        }
        Ok(events)
    }

    /// A public case can comprise PrivatePlan followed by PrivateLaunch.
    /// Each socket exchange runs in a distinct service-forked worker, so
    /// identity is exact within a pair, not across pairs. A denial/control
    /// has one pair. More than two, nesting, a missing exit, or an allocation
    /// outside a pair is never qualifying evidence.
    fn validate_request_pairs(
        events: &[KernelEventV1],
        expected: &ExpectedKernelAdapterV1,
    ) -> Result<()> {
        let mut workers = std::collections::BTreeSet::new();
        let mut open: Option<KernelTaskIdentityV1> = None;
        let mut closed_tasks = Vec::new();
        let mut pairs = 0_u8;
        for event in events {
            match event {
                KernelEventV1::ForkObserved { parent, child_pid }
                    if parent.pid == expected.coordinator_pid
                        && parent.cgroup_inode == expected.cgroup_inode
                        && (expected.coordinator_start_time == 0
                            || parent.start_time == expected.coordinator_start_time) =>
                {
                    workers.insert(*child_pid);
                }
                KernelEventV1::AllocationBoundary {
                    task,
                    request_key,
                    kind,
                } => {
                    if request_key != &expected.result_key {
                        return Err(fail("kernel probe request key differs"));
                    }
                    match kind {
                        AllocationBoundaryKindV1::Enter => {
                            if open.is_some()
                                || pairs == 2
                                || closed_tasks.contains(task)
                                || task.cgroup_inode != expected.cgroup_inode
                                || task.pid != expected.coordinator_pid
                                    && !workers.contains(&task.pid)
                            {
                                return Err(fail(
                                    "kernel probe request entry overlaps or lacks service lineage",
                                ));
                            }
                            open = Some(*task);
                        }
                        AllocationBoundaryKindV1::Exit => {
                            if open.take() != Some(*task) {
                                return Err(fail(
                                    "kernel probe request exit task or order differs",
                                ));
                            }
                            closed_tasks.push(*task);
                            pairs += 1;
                        }
                        AllocationBoundaryKindV1::Allocate => {
                            if open.is_none() {
                                return Err(fail(
                                    "kernel probe allocation escaped request interval",
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if open.is_some() || !(1..=2).contains(&pairs) {
            return Err(fail(
                "kernel probe request interval count or closure differs",
            ));
        }
        Ok(())
    }

    fn host_preflight(
        expected: &ExpectedKernelAdapterV1,
        bundle: &VerifiedProbeBundleV1,
    ) -> Result<()> {
        if !cfg!(target_os = "linux")
            || expected.boot_id
                != fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .trim()
            || expected.kernel_release
                != fs::read_to_string("/proc/sys/kernel/osrelease")
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .trim()
            || expected.probe_map_sha256 != bundle.attestation_digest()
        {
            return Err(fail("kernel probe host or bundle differs from intent"));
        }
        let mut btf = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/sys/kernel/btf/vmlinux")
            .map_err(|error| CiError::Message(error.to_string()))?
            .take(128 * 1024 * 1024 + 1);
        let mut bytes = Vec::new();
        btf.read_to_end(&mut bytes)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if bytes.is_empty()
            || bytes.len() > 128 * 1024 * 1024
            || hash_bytes(&bytes) != expected.btf_sha256
        {
            return Err(fail("kernel probe BTF differs from intent"));
        }
        bundle.revalidate()
    }

    fn read_root_capture(
        path: &Path,
        stage: crate::private_kernel_replay::CaptureStageV2,
    ) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| CiError::Message(error.to_string()))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() > stage.max_capture_bytes() as u64
        {
            return Err(fail("kernel probe capture protection differs"));
        }
        let mut bytes = Vec::new();
        file.take((stage.max_capture_bytes() + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| CiError::Message(error.to_string()))?;
        Ok(bytes)
    }

    fn signal_interrupt(pid: u32) -> Result<()> {
        let status = Command::new("/bin/kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .map_err(|error| CiError::Message(error.to_string()))?;
        if !status.success() {
            return Err(fail("kernel probe loader interrupt failed"));
        }
        Ok(())
    }

    fn run_interval(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: Option<&VerifiedKnownActionControlsV1>,
        supplied_interval_id: Option<crate::private_kernel_replay::IntervalIdV1>,
        stage: crate::private_kernel_replay::CaptureStageV2,
        raw_candidate: bool,
        filter_sources: bool,
        host_pins: Option<&[(u64, u64); 4]>,
        reuse_pins: Option<&[(u64, u64); 3]>,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        if controls.is_some_and(|control| {
            control.boot_id != expected.boot_id
                || control.btf_sha256 != expected.btf_sha256
                || control.probe_map_sha256 != expected.probe_map_sha256
        }) {
            return Err(fail("kernel probe known-action control differs"));
        }
        if expected.coordinator_pid == 0
            || expected.cgroup_inode == 0
            || expected.broker_pid == 0
            || expected.broker_start_ticks == 0
            || expected.broker_cgroup_inode == 0
            || expected.broker_cgroup_inode == expected.cgroup_inode
            || expected.coordinator_start_time != 0
            || expected.coordinator_start_ticks == 0
        {
            return Err(fail("kernel probe live coordinator expectation differs"));
        }
        let clock =
            crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
                std::process::id(),
                crate::private_process_clock::read_live_start_ticks(std::process::id())?,
            )?;
        crate::private_process_clock::require_live_start_ticks(
            expected.coordinator_pid,
            expected.coordinator_start_ticks,
        )?;
        crate::private_process_clock::require_live_start_ticks(
            expected.broker_pid,
            expected.broker_start_ticks,
        )?;
        let service = observe_live_kernel_subject(expected.coordinator_pid)?;
        let broker = observe_live_kernel_subject(expected.broker_pid)?;
        if service.start_ticks != expected.coordinator_start_ticks
            || service.cgroup_inode != expected.cgroup_inode
            || broker.start_ticks != expected.broker_start_ticks
            || broker.cgroup_inode != expected.broker_cgroup_inode
        {
            return Err(fail(
                "kernel probe installed service/broker identity differs",
            ));
        }
        host_preflight(&expected, bundle)?;
        let key = String::from(expected.result_key.clone());
        // A logical key intentionally repeats across controls, epoch replay
        // and recovery. A fresh physical storage scope preserves every file.
        let mut storage_nonce = [0_u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut storage_nonce)?;
        let interval_id =
            supplied_interval_id.unwrap_or(crate::private_kernel_replay::IntervalIdV1 {
                session_nonce: storage_nonce,
                generation: 0,
                logical_case_key: expected.result_key.clone(),
                purpose: if controls.is_some() {
                    crate::private_kernel_replay::IntervalPurposeV1::Ordinary
                } else {
                    crate::private_kernel_replay::IntervalPurposeV1::KnownControls
                },
                ordinal: 0,
            });
        if interval_id.session_nonce == [0; 32]
            || interval_id.logical_case_key != expected.result_key
        {
            return Err(fail(
                "physical interval identity differs from logical request",
            ));
        }
        let capture = PathBuf::from(CAPTURE_ROOT)
            .join(String::from(interval_id.storage_sha256()))
            .with_extension("capture.bin");
        let mut loader_command = Command::new(bundle.loader_path());
        loader_command
            .arg(bundle.object_path())
            .arg(bundle.agent_path())
            .arg(bundle.request_entry_offset().to_string())
            .arg(bundle.request_exit_offset().to_string())
            .arg(bundle.allocation_entry_offset().to_string())
            .arg(expected.cgroup_inode.to_string())
            .arg(expected.broker_cgroup_inode.to_string())
            .arg(&key)
            .arg(&capture)
            .arg(match stage {
                crate::private_kernel_replay::CaptureStageV2::Candidate => "candidate-v2",
                crate::private_kernel_replay::CaptureStageV2::FinalPublic => "final-public-v2",
            })
            .arg(std::process::id().to_string());
        if filter_sources {
            loader_command.arg("filter-install-v1");
        }
        if let Some(pins) = host_pins {
            loader_command.arg("host-sysctl-watch-v1");
            for (device, inode) in pins {
                loader_command
                    .arg(device.to_string())
                    .arg(inode.to_string());
            }
        }
        if let Some(pins) = reuse_pins {
            if stage != crate::private_kernel_replay::CaptureStageV2::Candidate
                || pins.iter().any(|(dev, ino)| *dev == 0 || *ino == 0)
                || pins[1] == pins[2]
            {
                return Err(fail(
                    "reuse source stage or independently held object pins differ",
                ));
            }
            loader_command.arg("reuse-journal-source-v1");
            for (device, inode) in pins {
                loader_command
                    .arg(device.to_string())
                    .arg(inode.to_string());
            }
        }
        let loader_child = loader_command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| CiError::Message(error.to_string()))?;
        let mut child = SupervisedLoader {
            child: loader_child,
            stdout: None,
            stderr: None,
        };
        let stdout = child
            .child
            .stdout
            .take()
            .ok_or_else(|| fail("kernel probe READY pipe absent"))?;
        let (sender, receiver) = mpsc::channel();
        child.stdout = Some(thread::spawn(move || {
            let mut stdout = stdout;
            let mut ready = [0_u8; b"READY\n".len()];
            let result = stdout.read_exact(&mut ready).map(|()| ready == *b"READY\n");
            let _ = sender.send(result);
            read_bounded_loader_stream(stdout)
        }));
        let stderr = child
            .child
            .stderr
            .take()
            .ok_or_else(|| fail("kernel probe stderr pipe absent"))?;
        child.stderr = Some(thread::spawn(move || read_bounded_loader_stream(stderr)));
        match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(true)) => {}
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail("kernel probe loader did not arm before case"));
            }
        }
        let operation_begin_monotonic_ns =
            memcordon_platform::test_support::private_observer_monotonic_ns()?;
        let operation_result = operation();
        let operation_end_monotonic_ns =
            memcordon_platform::test_support::private_observer_monotonic_ns()?;
        let interrupt_result = signal_interrupt(child.id());
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| CiError::Message(error.to_string()))?
            {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail("kernel probe loader did not disarm"));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let trailing_stdout = join_loader_reader(
            child
                .stdout
                .take()
                .ok_or_else(|| fail("kernel loader stdout reader absent"))?,
        )?;
        let loader_stderr = join_loader_reader(
            child
                .stderr
                .take()
                .ok_or_else(|| fail("kernel loader stderr reader absent"))?,
        )?;
        if !trailing_stdout.is_empty() {
            return Err(fail("kernel loader emitted undeclared stdout"));
        }
        operation_result?;
        interrupt_result?;
        if !status.success() {
            return Err(fail("kernel probe loader failed or lost events"));
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LoaderTiming {
            armed_monotonic_ns: u64,
            detached_monotonic_ns: u64,
            drained_monotonic_ns: u64,
        }
        let timing_line = loader_stderr
            .strip_suffix(b"\n")
            .and_then(|bytes| bytes.rsplit(|byte| *byte == b'\n').next())
            .and_then(|line| line.strip_prefix(b"MC_TIMING_V1 "))
            .ok_or_else(|| fail("kernel loader original timing absent"))?;
        memcordon_core::workload_contract::reject_duplicate_json_keys(timing_line)
            .map_err(CiError::Message)?;
        let native_timing: LoaderTiming = serde_json::from_slice(timing_line)?;
        let observation_timing = KernelObservationTimingV1 {
            armed_monotonic_ns: native_timing.armed_monotonic_ns,
            operation_begin_monotonic_ns,
            operation_end_monotonic_ns,
            detached_monotonic_ns: native_timing.detached_monotonic_ns,
            drained_monotonic_ns: native_timing.drained_monotonic_ns,
        };
        if observation_timing.armed_monotonic_ns == 0
            || observation_timing.armed_monotonic_ns > operation_begin_monotonic_ns
            || operation_begin_monotonic_ns >= operation_end_monotonic_ns
            || operation_end_monotonic_ns > observation_timing.detached_monotonic_ns
            || observation_timing.detached_monotonic_ns > observation_timing.drained_monotonic_ns
        {
            return Err(fail("kernel loader original timing order differs"));
        }
        let bytes = read_root_capture(&capture, stage)?;
        let projection = crate::private_kernel_replay::diagnostic_v1_projection_with_stage(
            &bytes,
            &expected.result_key,
            stage,
        )?;
        if raw_candidate
            && stage == crate::private_kernel_replay::CaptureStageV2::Candidate
            && expected.coordinator_pid != std::process::id()
        {
            return Err(fail(
                "raw candidate projection requires the actually held observer root process",
            ));
        }
        let events = parse_capture_scope(&projection, &expected, raw_candidate)?;
        let coordinator = events
            .iter()
            .find_map(|event| {
                let task = match event {
                    KernelEventV1::Fork { parent, .. }
                    | KernelEventV1::ForkObserved { parent, .. } => *parent,
                    KernelEventV1::Exec { task, .. }
                    | KernelEventV1::Exit { task, .. }
                    | KernelEventV1::Reap { task }
                    | KernelEventV1::NamespaceFdClosed { task, .. }
                    | KernelEventV1::SeccompDecision { task, .. }
                    | KernelEventV1::SyscallReturn { task, .. }
                    | KernelEventV1::AllocationBoundary { task, .. } => *task,
                };
                (task.pid == expected.coordinator_pid).then_some(task)
            })
            .ok_or_else(|| fail("kernel probe coordinator event absent"))?;
        if !clock.matches(coordinator, expected.coordinator_start_ticks) {
            return Err(fail(
                "kernel probe coordinator start differs from live proc",
            ));
        }
        crate::private_process_clock::require_live_start_ticks(
            expected.coordinator_pid,
            expected.coordinator_start_ticks,
        )?;
        crate::private_process_clock::require_live_start_ticks(
            expected.broker_pid,
            expected.broker_start_ticks,
        )?;
        let service = observe_live_kernel_subject(expected.coordinator_pid)?;
        let broker = observe_live_kernel_subject(expected.broker_pid)?;
        if service.start_ticks != expected.coordinator_start_ticks
            || service.cgroup_inode != expected.cgroup_inode
            || broker.start_ticks != expected.broker_start_ticks
            || broker.cgroup_inode != expected.broker_cgroup_inode
        {
            return Err(fail(
                "kernel probe installed service/broker changed during interval",
            ));
        }
        bundle.revalidate()?;
        Ok(VerifiedKernelIntervalV1 {
            boot_id: expected.boot_id,
            kernel_release: expected.kernel_release,
            btf_sha256: expected.btf_sha256,
            probe_map_sha256: expected.probe_map_sha256,
            trace_sha256: hash_bytes(&bytes),
            coordinator_pid: expected.coordinator_pid,
            coordinator_start_time: coordinator.start_time,
            cgroup_inode: expected.cgroup_inode,
            result_key: expected.result_key,
            events,
            capture_bytes: Some(bytes),
            physical_interval_id: Some(interval_id),
            raw_candidate_only: raw_candidate,
            clock_inputs: clock.inputs().cloned(),
            original_clock: Some(clock.clone()),
            loader_stderr: Some(loader_stderr),
            observation_timing: Some(observation_timing),
        })
    }

    pub(crate) fn run_control_interval(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        run_interval(
            bundle,
            expected,
            None,
            None,
            crate::private_kernel_replay::CaptureStageV2::Candidate,
            false,
            false,
            None,
            None,
            operation,
        )
    }

    pub(crate) fn run_case_interval(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: &VerifiedKnownActionControlsV1,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        run_interval(
            bundle,
            expected,
            Some(controls),
            None,
            crate::private_kernel_replay::CaptureStageV2::Candidate,
            false,
            false,
            None,
            None,
            operation,
        )
    }

    pub(crate) fn run_interval_with_id(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: Option<&VerifiedKnownActionControlsV1>,
        interval_id: crate::private_kernel_replay::IntervalIdV1,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        run_interval(
            bundle,
            expected,
            controls,
            Some(interval_id),
            crate::private_kernel_replay::CaptureStageV2::Candidate,
            false,
            false,
            None,
            None,
            operation,
        )
    }

    pub(crate) fn run_interval_with_stage(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: Option<&VerifiedKnownActionControlsV1>,
        interval_id: crate::private_kernel_replay::IntervalIdV1,
        stage: crate::private_kernel_replay::CaptureStageV2,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        run_interval(
            bundle,
            expected,
            controls,
            Some(interval_id),
            stage,
            false,
            false,
            None,
            None,
            operation,
        )
    }

    /// Retains bounded, loss-free raw events for concurrent authenticated
    /// public attempts without applying the V1 scalar request grammar. This
    /// diagnostic projection cannot mint the legacy allocation capabilities.
    pub(crate) fn run_interval_raw_with_stage(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: &VerifiedKnownActionControlsV1,
        interval_id: crate::private_kernel_replay::IntervalIdV1,
        stage: crate::private_kernel_replay::CaptureStageV2,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        if stage != crate::private_kernel_replay::CaptureStageV2::FinalPublic {
            return Err(fail(
                "raw public interval requires explicit final-public stage",
            ));
        }
        run_interval(
            bundle,
            expected,
            Some(controls),
            Some(interval_id),
            stage,
            true,
            false,
            None,
            None,
            operation,
        )
    }

    /// Retains a real candidate interval whose root fixture/request owner is
    /// an explicitly observer-forked helper. The V1 projection is diagnostic;
    /// only the authenticated V2 raw replay may interpret these roles.
    /// Explicit protected source opt-in; legacy callers retain header15.
    pub(crate) fn run_interval_raw_with_filter_sources(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: &VerifiedKnownActionControlsV1,
        interval_id: crate::private_kernel_replay::IntervalIdV1,
        stage: crate::private_kernel_replay::CaptureStageV2,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        run_interval(
            bundle,
            expected,
            Some(controls),
            Some(interval_id),
            stage,
            true,
            true,
            None,
            None,
            operation,
        )
    }

    pub(crate) fn run_interval_raw_with_id(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: &VerifiedKnownActionControlsV1,
        interval_id: crate::private_kernel_replay::IntervalIdV1,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        run_interval(
            bundle,
            expected,
            Some(controls),
            Some(interval_id),
            crate::private_kernel_replay::CaptureStageV2::Candidate,
            true,
            false,
            None,
            None,
            operation,
        )
    }

    pub(crate) fn run_interval_raw_with_host_sources(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: &VerifiedKnownActionControlsV1,
        interval_id: crate::private_kernel_replay::IntervalIdV1,
        stage: crate::private_kernel_replay::CaptureStageV2,
        filter_sources: bool,
        pins: &[(u64, u64); 4],
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        run_interval(
            bundle,
            expected,
            Some(controls),
            Some(interval_id),
            stage,
            true,
            filter_sources,
            Some(pins),
            None,
            operation,
        )
    }

    /// Explicit, bounded candidate journal source; the supplied objects were
    /// held independently before arm and are checked again in kernel records.
    pub(crate) fn run_interval_raw_with_reuse_sources(
        bundle: &VerifiedProbeBundleV1,
        expected: ExpectedKernelAdapterV1,
        controls: &VerifiedKnownActionControlsV1,
        interval_id: crate::private_kernel_replay::IntervalIdV1,
        pins: &[(u64, u64); 3],
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<VerifiedKernelIntervalV1> {
        run_interval(
            bundle,
            expected,
            Some(controls),
            Some(interval_id),
            crate::private_kernel_replay::CaptureStageV2::Candidate,
            true,
            false,
            None,
            Some(pins),
            operation,
        )
    }
}

#[cfg(all(unix, test))]
pub(crate) use probe_bundle_live::parse_capture as parse_probe_capture_for_test;
#[cfg(unix)]
pub(crate) use probe_bundle_live::{
    run_case_interval as run_probe_case_interval,
    run_control_interval as run_probe_control_interval,
    run_interval_raw_with_filter_sources as run_probe_interval_raw_with_filter_sources,
    run_interval_raw_with_host_sources as run_probe_interval_raw_with_host_sources,
    run_interval_raw_with_id as run_probe_interval_raw_with_id,
    run_interval_raw_with_reuse_sources as run_probe_interval_raw_with_reuse_sources,
    run_interval_raw_with_stage as run_probe_interval_raw_with_stage,
    run_interval_with_id as run_probe_interval_with_id,
    run_interval_with_stage as run_probe_interval_with_stage,
};
