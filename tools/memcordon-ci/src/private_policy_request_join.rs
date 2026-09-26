//! Independent decision-only request custody for the candidate policy case.
//! A protected request record is not its own service-generation or worker
//! identity proof; systemd/proc and the armed kernel interval supply both.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::Serialize;

use crate::private_kernel_observer::{
    AllocationBoundaryKindV1, KernelEventV1, LiveKernelSubjectV1, VerifiedKernelIntervalV1,
};
use crate::private_process_clock::VerifiedProcClockCalibrationV1;
use crate::private_protected_readback::ProtectedCandidateReleaseRequestV1;
use crate::{CiError, Result};

const UNIT: &str = "memcordon-sealed-agent.service";
const FRAGMENT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.service";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
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

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

#[derive(Serialize)]
struct ProcessIdentity {
    pid: u32,
    start_time: u64,
}

#[derive(Serialize)]
struct ServiceGeneration<'a> {
    invocation_id: &'a str,
    main: ProcessIdentity,
    control_group: &'a str,
}

pub(crate) struct VerifiedPolicyDecisionRequestV1 {
    request_sha256: DiagnosticSha256,
    service_generation_sha256: DiagnosticSha256,
    coordinator_pid: u32,
    coordinator_start_ticks: u64,
    capture_sha256: DiagnosticSha256,
}

impl VerifiedPolicyDecisionRequestV1 {
    pub(crate) fn request_sha256(&self) -> &DiagnosticSha256 {
        &self.request_sha256
    }
    pub(crate) fn service_generation_sha256(&self) -> &DiagnosticSha256 {
        &self.service_generation_sha256
    }
    pub(crate) fn coordinator(&self) -> (u32, u64) {
        (self.coordinator_pid, self.coordinator_start_ticks)
    }
    pub(crate) fn capture_sha256(&self) -> &DiagnosticSha256 {
        &self.capture_sha256
    }
}

fn manager_snapshot(root: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(SYSTEMCTL)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(fail("policy manager executable protection differs"));
    }
    let mut command = std::process::Command::new(SYSTEMCTL);
    command
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
        .current_dir(root)
        .env_clear();
    let output = memcordon_testkit::run_with_deadline(&mut command, Duration::from_secs(5))
        .map_err(|error| CiError::Message(error.to_string()))?;
    if !output.status.success() || !output.stderr.is_empty() || output.stdout.len() > 16 * 1024 {
        return Err(fail("policy manager query differs"));
    }
    Ok(output.stdout)
}

fn parse_manager(bytes: &[u8], service: &LiveKernelSubjectV1) -> Result<DiagnosticSha256> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| fail("policy manager output encoding differs"))?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| fail("policy manager field malformed"))?;
        if !PROPERTIES.contains(&name) || fields.insert(name, value).is_some() {
            return Err(fail("policy manager field inventory differs"));
        }
    }
    if fields.len() != PROPERTIES.len() {
        return Err(fail("policy manager fields absent"));
    }
    let value = |key| {
        fields
            .get(key)
            .copied()
            .ok_or_else(|| fail("policy manager field absent"))
    };
    let invocation = value("InvocationID")?;
    let pid: u32 = value("MainPID")?
        .parse()
        .map_err(|_| fail("policy manager MainPID differs"))?;
    let cgroup = value("ControlGroup")?;
    let membership = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    if invocation.len() != 32
        || !invocation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || invocation.bytes().all(|byte| byte == b'0')
        || pid != service.pid
        || value("ActiveState")? != "active"
        || value("SubState")? != "running"
        || value("NeedDaemonReload")? != "no"
        || value("FragmentPath")? != FRAGMENT
        || !value("DropInPaths")?.is_empty()
        || value("Delegate")? != "no"
        || !cgroup.starts_with('/')
        || cgroup.len() > 512
        || !cgroup.ends_with(&format!("/{UNIT}"))
        || cgroup.split('/').any(|part| part == "." || part == "..")
        || membership != format!("0::{cgroup}\n")
        || crate::private_kernel_observer::observe_live_kernel_subject(pid)? != *service
    {
        return Err(fail("policy sealed-service generation differs"));
    }
    let serialized = serde_json::to_vec(&ServiceGeneration {
        invocation_id: invocation,
        main: ProcessIdentity {
            pid,
            start_time: service.start_ticks,
        },
        control_group: cgroup,
    })?;
    let mut domain = b"memcordon-private-service-generation-v1\0".to_vec();
    domain.extend_from_slice(&serialized);
    Ok(hash_bytes(&domain))
}

/// Reusable exact installed service-generation readback. A root-owned request
/// file alone cannot authenticate this invocation against systemd/proc.
pub(crate) fn verify_sealed_service_generation(
    root: &Path,
    service: &LiveKernelSubjectV1,
) -> Result<DiagnosticSha256> {
    let first = manager_snapshot(root)?;
    let generation = parse_manager(&first, service)?;
    let second = manager_snapshot(root)?;
    if first != second || parse_manager(&second, service)? != generation {
        return Err(fail(
            "sealed service generation changed during detached readback",
        ));
    }
    Ok(generation)
}

/// Joins exact protected request bytes and kernel-observed service worker.
/// `service` is independently read from systemd/proc before the interval;
/// this function re-reads it and its invocation generation after disarm.
pub(crate) fn join_policy_decision_request(
    root: &Path,
    bytes: &[u8],
    request: &ProtectedCandidateReleaseRequestV1,
    interval: &VerifiedKernelIntervalV1,
    clock: &VerifiedProcClockCalibrationV1,
    service: &LiveKernelSubjectV1,
    expected_manifest: &DiagnosticSha256,
    expected_epoch: &DiagnosticSha256,
    expected_challenge: &[u8; 32],
    expected_key: &DiagnosticSha256,
) -> Result<VerifiedPolicyDecisionRequestV1> {
    interval.capture_bytes()?;
    let generation = verify_sealed_service_generation(root, service)?;
    if request.schema_version != 1
        || request.stage != "candidate-capability"
        || request.selector != "private_tcp::wrong_grant_profile_and_port_rejected"
        || request.challenge != hex::encode(expected_challenge)
        || &request.result_key != expected_key
        || &request.candidate_manifest_sha256 != expected_manifest
        || &request.installation_epoch != expected_epoch
        || request.service_generation_sha256 != generation
        || request.coordinator.pid == 0
        || request.coordinator.start_time == 0
        || interval.result_key() != expected_key
        || interval.cgroup_inode() != service.cgroup_inode
    {
        return Err(fail("policy protected request origin differs"));
    }
    let mut fork = false;
    let mut enter = None;
    let mut exit = None;
    for event in interval.events() {
        match event {
            KernelEventV1::ForkObserved { parent, child_pid }
                if parent.pid == service.pid
                    && parent.cgroup_inode == service.cgroup_inode
                    && clock.matches(*parent, service.start_ticks)
                    && *child_pid == request.coordinator.pid =>
            {
                fork = true
            }
            KernelEventV1::AllocationBoundary {
                task,
                request_key,
                kind,
            } if request_key == expected_key
                && task.pid == request.coordinator.pid
                && task.cgroup_inode == service.cgroup_inode
                && clock.matches(*task, request.coordinator.start_time) =>
            {
                match kind {
                    AllocationBoundaryKindV1::Enter => enter = Some(*task),
                    AllocationBoundaryKindV1::Exit => exit = Some(*task),
                    AllocationBoundaryKindV1::Allocate => {
                        return Err(fail("policy decision allocated a target"));
                    }
                }
            }
            _ => {}
        }
    }
    if !fork || enter.is_none() || enter != exit {
        return Err(fail("policy service worker/request interval differs"));
    }
    Ok(VerifiedPolicyDecisionRequestV1 {
        request_sha256: hash_bytes(bytes),
        service_generation_sha256: generation,
        coordinator_pid: request.coordinator.pid,
        coordinator_start_ticks: request.coordinator.start_time,
        capture_sha256: interval.trace_sha256().clone(),
    })
}
