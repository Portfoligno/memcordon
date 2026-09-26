//! Real pinned-agent seccomp coverage control. The agent command reports two
//! child PIDs, but only fork lineage and three BPF decisions issue the token.

use std::process::{Command, Stdio};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::Deserialize;

use crate::private_kernel_observer::{
    ExpectedKernelAdapterV1, KernelEventV1, KernelTaskIdentityV1, KnownActionTupleV1,
    SeccompActionV1, VerifiedKernelIntervalV1, VerifiedKnownActionControlsV1,
    run_probe_control_interval,
};
use crate::private_probe_bundle::VerifiedProbeBundleV1;
use crate::{CiError, Result};

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ChildPidsV1 {
    schema_version: u8,
    ordinary_pid: u32,
    killed_pid: u32,
}

pub(crate) struct VerifiedFixedProbeControlsV1 {
    interval: VerifiedKernelIntervalV1,
    controls: VerifiedKnownActionControlsV1,
    command_output_sha256: DiagnosticSha256,
}

impl VerifiedFixedProbeControlsV1 {
    pub(crate) fn interval(&self) -> &VerifiedKernelIntervalV1 {
        &self.interval
    }
    pub(crate) fn controls(&self) -> &VerifiedKnownActionControlsV1 {
        &self.controls
    }
    pub(crate) fn command_output_sha256(&self) -> &DiagnosticSha256 {
        &self.command_output_sha256
    }
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

fn exact_child(
    interval: &VerifiedKernelIntervalV1,
    parent_pid: u32,
    child_pid: u32,
) -> Result<KernelTaskIdentityV1> {
    let forks = interval
        .events()
        .iter()
        .filter(|event| {
            matches!(event,
        KernelEventV1::ForkObserved { parent, child_pid: observed }
            if parent.pid == parent_pid && *observed == child_pid)
        })
        .count();
    if forks != 1 {
        return Err(fail("probe control child lacks exact fork lineage"));
    }
    let mut identity = None;
    for event in interval.events() {
        if let KernelEventV1::SeccompDecision { task, .. } = event {
            if task.pid == child_pid {
                if identity.is_some_and(|prior| prior != *task) {
                    return Err(fail("probe control child identity changed"));
                }
                identity = Some(*task);
            }
        }
    }
    identity.ok_or_else(|| fail("probe control child seccomp event absent"))
}

/// `expected` is a protected CI-origin expectation for the current CI
/// process/cgroup, not an agent-authored claim. Loader READY precedes spawning
/// the exact installed agent command. Unknown ABI or absent compat KILL
/// rejects; no synthetic control tuple can be substituted.
pub(crate) fn run_fixed_known_action_controls(
    bundle: &VerifiedProbeBundleV1,
    expected: ExpectedKernelAdapterV1,
) -> Result<VerifiedFixedProbeControlsV1> {
    let mut observed = None;
    let interval = run_probe_control_interval(bundle, expected, || {
        let child = Command::new(bundle.agent_path())
            .args(["package", "private-kernel-known-actions"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let parent_pid = child.id();
        let output = child.wait_with_output()?;
        if !output.status.success() || output.stdout.len() > 256 || !output.stderr.is_empty() {
            return Err(fail("installed probe control command failed"));
        }
        let pids: ChildPidsV1 = serde_json::from_slice(&output.stdout)?;
        if pids.schema_version != 1
            || pids.ordinary_pid == 0
            || pids.killed_pid == 0
            || pids.ordinary_pid == pids.killed_pid
            || output.stdout != [serde_json::to_vec(&pids)?, b"\n".to_vec()].concat()
        {
            return Err(fail("installed probe control output differs"));
        }
        observed = Some((parent_pid, pids, hash_bytes(&output.stdout)));
        Ok(())
    })?;
    let (parent_pid, pids, output_sha) =
        observed.ok_or_else(|| fail("probe control command absent"))?;
    let ordinary = exact_child(&interval, parent_pid, pids.ordinary_pid)?;
    let killed = exact_child(&interval, parent_pid, pids.killed_pid)?;
    if ordinary == killed || !interval.retired_task(ordinary) || !interval.retired_task(killed) {
        return Err(fail("probe control child retirement differs"));
    }
    #[cfg(target_arch = "x86_64")]
    let (arch, getpid, socketpair, kill_arch, kill_getpid) =
        (0xc000_003e, 39, 53, 0xc000_003e, 0x4000_0027);
    #[cfg(target_arch = "aarch64")]
    let (arch, getpid, socketpair, kill_arch, kill_getpid) =
        (0xc000_00b7, 172, 199, 0x4000_0028, 20);
    if !interval.events().iter().any(|event| {
        matches!(event,
        KernelEventV1::SeccompDecision {
            task, arch: observed_arch, syscall, action: SeccompActionV1::Errno, errno,
        } if *task == ordinary && *observed_arch == arch
            && *syscall == socketpair && *errno == libc::EPERM)
    }) {
        return Err(fail("probe control exact ERRNO decision differs"));
    }
    let controls = interval.verify_known_action_controls(
        KnownActionTupleV1 {
            task: ordinary,
            arch,
            syscall: getpid,
            action: SeccompActionV1::Allow,
        },
        KnownActionTupleV1 {
            task: ordinary,
            arch,
            syscall: socketpair,
            action: SeccompActionV1::Errno,
        },
        KnownActionTupleV1 {
            task: killed,
            arch: kill_arch,
            syscall: kill_getpid,
            action: SeccompActionV1::KillProcess,
        },
    )?;
    Ok(VerifiedFixedProbeControlsV1 {
        interval,
        controls,
        command_output_sha256: output_sha,
    })
}
