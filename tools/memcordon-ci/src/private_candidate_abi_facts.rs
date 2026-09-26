//! Candidate ABI conjunction over original native records and original V2
//! events. A producer branch label or a generic claimed ABI fact is not proof.
use crate::private_abi_raw_readback::{AbiProcessIdentityV1, VerifiedAbiRawV1};
use crate::private_candidate_replay::{CaseFactV1, ReplayTaskV1};
use crate::private_kernel_replay::{KernelEventRecordV2, KernelTaskIdentityV2};
use crate::private_process_clock::{ParsedProcClockCalibrationV1, ProcClockInputsV1};
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseCaseResultV1, PrivateReleaseInstalledBindingV1, PrivateReleaseObservationV1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

const SELECTOR: &str = "private_tcp::abi_alternate_entry_denied";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "architecture", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeAbiBranchesV1 {
    X86 {
        x32_path: String,
        i386_path: String,
    },
    Arm64 {
        arm32_path: String,
        helper_bytes_path: String,
        helper_metadata_path: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAbiSourcesV1 {
    pub(crate) result_path: String,
    pub(crate) request_path: String,
    pub(crate) attempt_path: String,
    pub(crate) attachments: [String; 5],
    pub(crate) branches: NativeAbiBranchesV1,
}

/// Root observer measurements of one held file before and after native exec.
/// The image hash alone cannot establish the executable dev/inode identity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArmHelperMeasurementV1 {
    pub(crate) schema_version: u8,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) uid: u32,
    pub(crate) mode: u32,
    pub(crate) nlink: u64,
    pub(crate) size: u64,
    pub(crate) sha256: DiagnosticSha256,
    pub(crate) begin_monotonic_ns: u64,
    pub(crate) end_monotonic_ns: u64,
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn identity(task: KernelTaskIdentityV2) -> crate::private_kernel_observer::KernelTaskIdentityV1 {
    crate::private_kernel_observer::KernelTaskIdentityV1 {
        pid: task.tid,
        start_time: task.start_boottime_ns,
        cgroup_inode: task.cgroup_inode,
        time_ns_inode: task.time_ns_inode,
    }
}
fn joined_task(
    events: &[KernelEventRecordV2],
    clock: &ParsedProcClockCalibrationV1,
    producer: &AbiProcessIdentityV1,
) -> Result<KernelTaskIdentityV2> {
    if producer.pid == 0 || producer.start_time == 0 {
        return fail("ABI source process identity absent");
    }
    let mut task = None;
    for event in events.iter().filter(|event| event.task.tid == producer.pid) {
        if event.task.tgid != producer.pid
            || !clock.matches(identity(event.task), producer.start_time)
            || task.is_some_and(|prior| prior != event.task)
        {
            return fail("ABI original task/start/cgroup/time namespace aliases");
        }
        task = Some(event.task);
    }
    task.ok_or_else(|| CiError::Message("ABI original task absent".into()))
}
fn child(
    events: &[KernelEventRecordV2],
    clock: &ParsedProcClockCalibrationV1,
    producer: &AbiProcessIdentityV1,
    parent: KernelTaskIdentityV2,
) -> Result<KernelTaskIdentityV2> {
    let task = joined_task(events, clock, producer)?;
    let forks = events
        .iter()
        .filter(|event| event.kind == 7 && event.other_tid == producer.pid)
        .collect::<Vec<_>>();
    let [fork] = forks.as_slice() else {
        return fail("ABI child fork absent or ambiguous");
    };
    if fork.task != parent
        || task == parent
        || events
            .iter()
            .filter(|event| event.task == task)
            .any(|event| event.sequence <= fork.sequence)
    {
        return fail("ABI fork parent or causal child ordering differs");
    }
    Ok(task)
}

/// Linux task->exit_code is a wait status, including the optional core flag.
/// Host libc wait macros and host signal numbers must not interpret this wire.
pub fn linux_abi_wait_matches(status: i64, signal: u32) -> bool {
    if signal == 0 {
        return status == 0;
    }
    signal < 127 && (0..=255).contains(&status) && status as u32 & 0x7f == signal
}
fn retirement(
    events: &[KernelEventRecordV2],
    task: KernelTaskIdentityV2,
    signal: u32,
    after_sequence: u64,
) -> Result<u64> {
    let exits = events
        .iter()
        .filter(|event| event.kind == 8 && event.task == task)
        .collect::<Vec<_>>();
    let [exit] = exits.as_slice() else {
        return fail("ABI exact helper/worker exit absent or ambiguous");
    };
    let reaps = events
        .iter()
        .filter(|event| {
            event.kind == 9
                && event.other_tid == task.tid
                && u64::try_from(event.syscall_result).ok() == Some(task.start_boottime_ns)
        })
        .collect::<Vec<_>>();
    let [reap] = reaps.as_slice() else {
        return fail("ABI exact helper/worker reap absent or ambiguous");
    };
    if exit.sequence <= after_sequence
        || reap.sequence <= exit.sequence
        || !linux_abi_wait_matches(exit.syscall_result, signal)
    {
        return fail("ABI helper/worker wait status or exit/reap order differs");
    }
    // Preserve the raw reaper actor: it is not relabelled as the victim task.
    Ok(reap.sequence)
}
fn branch(
    events: &[KernelEventRecordV2],
    task: KernelTaskIdentityV2,
    arch: u32,
    nr: i64,
    action: u32,
    result: Option<i64>,
) -> Result<u64> {
    let decisions = events
        .iter()
        .filter(|event| {
            event.kind == 4
                && event.task == task
                && event.syscall_arch == arch
                && event.syscall_nr == nr
                && event.seccomp_action == action
        })
        .collect::<Vec<_>>();
    if decisions.is_empty() {
        return fail("ABI exact entry/architecture/action absent");
    }
    if action == 0x80000000 && decisions.len() != 1 {
        return fail("ABI killed entry aliases");
    }
    let mut last = 0;
    for entry in decisions {
        if entry.syscall_occurrence == 0 {
            return fail("ABI entry occurrence absent");
        }
        let returns = events
            .iter()
            .filter(|event| {
                event.kind == 5
                    && event.task == task
                    && event.syscall_arch == arch
                    && event.syscall_nr == nr
                    && event.syscall_occurrence == entry.syscall_occurrence
            })
            .collect::<Vec<_>>();
        match result {
            Some(value) => {
                let [returned] = returns.as_slice() else {
                    return fail("ABI matching syscall return absent or ambiguous");
                };
                if returned.sequence <= entry.sequence
                    || returned.args != entry.args
                    || returned.syscall_result != value
                {
                    return fail("ABI actual syscall result/occurrence differs");
                }
                last = last.max(returned.sequence);
            }
            None => {
                if !returns.is_empty() {
                    return fail("ABI killed entry has a syscall return");
                }
                last = last.max(entry.sequence);
            }
        }
    }
    retirement(events, task, if result.is_none() { 31 } else { 0 }, last)
}

pub(crate) fn verify_native_abi_sources<'a>(
    sources: &NativeAbiSourcesV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    target: &ReplayTaskV1,
    filter: &DiagnosticSha256,
    capture_sha256: &DiagnosticSha256,
    leaf: impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<PrivateReleaseCaseResultV1> {
    let result =
        PrivateReleaseCaseResultV1::parse(leaf(&sources.result_path)?).map_err(CiError::Message)?;
    if result.selector != SELECTOR {
        return fail("native ABI original selector differs");
    }
    let (epoch, manifest, receipt) = match &result.installed {
        PrivateReleaseInstalledBindingV1::CandidateCapability {
            installation_epoch,
            candidate_manifest_sha256,
            installed_inspection_sha256,
        } => (
            installation_epoch,
            candidate_manifest_sha256,
            installed_inspection_sha256,
        ),
        _ => return fail("native ABI source is not candidate stage"),
    };
    let key = result.result_key().map_err(CiError::Message)?;
    let challenge = result.challenge_bytes().map_err(CiError::Message)?;
    let request = crate::private_protected_readback::parse_protected_candidate_request(
        leaf(&sources.request_path)?,
        SELECTOR,
        challenge,
        &key,
    )?;
    if &request.installation_epoch != epoch || &request.candidate_manifest_sha256 != manifest {
        return fail("ABI original request installed binding differs");
    }
    let mut attachments = Vec::new();
    for (path, expected) in sources.attachments.iter().zip(&result.attachments) {
        let bytes = leaf(path)?;
        if bytes.len() as u64 != expected.size || hash_bytes(bytes) != expected.sha256 {
            return fail("ABI original attachment digest differs");
        }
        attachments.push(bytes);
    }
    let attachments: [&[u8]; 5] = attachments
        .try_into()
        .map_err(|_| CiError::Message("ABI attachment count differs".into()))?;
    let positive = crate::private_abi_raw_readback::readback_abi_positive_raw(
        &request,
        &challenge,
        receipt,
        filter,
        attachments,
        leaf(&sources.attempt_path)?,
    )?;
    let PrivateReleaseObservationV1::AbiComposite {
        attempt_id,
        checkpoint_sha256,
        terminal_sha256,
        retirement_sha256,
        abi_raw,
        independent_interval_sha256,
        native_observer_sha256,
    } = &result.observation
    else {
        return fail("ABI original composite observation absent");
    };
    if attempt_id != &positive.attempt_id
        || checkpoint_sha256 != &positive.checkpoint_sha256
        || terminal_sha256 != &positive.terminal_sha256
        || retirement_sha256 != &positive.retirement_sha256
        || native_observer_sha256 != &positive.observer_sha256
        || independent_interval_sha256 != capture_sha256
    {
        return fail("ABI positive lifecycle or physical interval binding differs");
    }
    let mut helper = None;
    let raw = match (&sources.branches, result.target.as_str()) {
        (
            NativeAbiBranchesV1::X86 {
                x32_path,
                i386_path,
            },
            "x86_64-unknown-linux-gnu",
        ) => {
            if abi_raw != &(memcordon_core::private_release_case_v1::PrivateReleaseAbiRawInventoryV1::X86_64 {
                x32_sha256: hash_bytes(leaf(x32_path)?), i386_sha256: hash_bytes(leaf(i386_path)?) }) {
                return fail("ABI original x86 raw inventory differs");
            }
            crate::private_abi_raw_readback::readback_x86_abi_raw(
                &request,
                &challenge,
                receipt,
                filter,
                leaf(x32_path)?,
                leaf(i386_path)?,
            )?
        }
        (
            NativeAbiBranchesV1::Arm64 {
                arm32_path,
                helper_bytes_path,
                helper_metadata_path,
            },
            "aarch64-unknown-linux-gnu",
        ) => {
            if abi_raw != &(memcordon_core::private_release_case_v1::PrivateReleaseAbiRawInventoryV1::Aarch64 {
                arm32_sha256: hash_bytes(leaf(arm32_path)?) }) {
                return fail("ABI original ARM raw inventory differs");
            }
            let bytes = leaf(helper_bytes_path)?;
            let metadata: ArmHelperMeasurementV1 = crate::private_observer_session::strict_json(
                leaf(helper_metadata_path)?,
                16 * 1024,
            )?;
            let reviewed = hash_bytes(&crate::arm32_abi_helper::static_aarch32_helper());
            if metadata.schema_version != 1
                || metadata.inode == 0
                || metadata.uid != 0
                || metadata.mode & 0o170000 != 0o100000
                || metadata.mode & 0o022 != 0
                || metadata.nlink != 1
                || metadata.size != bytes.len() as u64
                || bytes.len() > 1024 * 1024
                || metadata.sha256 != hash_bytes(bytes)
                || metadata.sha256 != reviewed
                || metadata.begin_monotonic_ns == 0
                || metadata.end_monotonic_ns < metadata.begin_monotonic_ns
            {
                return fail("ABI independently held reviewed ARM helper differs");
            }
            helper = Some(metadata);
            crate::private_abi_raw_readback::readback_arm64_abi_raw(
                &request,
                &challenge,
                receipt,
                filter,
                &reviewed,
                leaf(arm32_path)?,
            )?
        }
        _ => return fail("ABI architecture-specific original inventory differs"),
    };
    let calibrated = ParsedProcClockCalibrationV1::parse(clock)?;
    let coordinator = joined_task(
        events,
        &calibrated,
        &AbiProcessIdentityV1 {
            pid: request.coordinator.pid,
            start_time: request.coordinator.start_time,
        },
    )?;
    let (worker, branches) = match &raw {
        VerifiedAbiRawV1::X86 {
            worker,
            native,
            x32_control,
            x32_result,
            x32_filtered,
            i386_control,
            i386_filtered,
            ..
        } => {
            let worker_task = child(events, &calibrated, worker, coordinator)?;
            let native_task = child(events, &calibrated, native, worker_task)?;
            let x32_control_task = child(events, &calibrated, x32_control, worker_task)?;
            let x32_filtered_task = child(events, &calibrated, x32_filtered, worker_task)?;
            let i386_control_task = child(events, &calibrated, i386_control, worker_task)?;
            let i386_filtered_task = child(events, &calibrated, i386_filtered, worker_task)?;
            let x32_return = match x32_result {
                crate::private_abi_composite::X32ControlResultV1::Pid => i64::from(x32_control.pid),
                crate::private_abi_composite::X32ControlResultV1::Enosys => -38,
            };
            (
                worker_task,
                vec![
                    branch(
                        events,
                        native_task,
                        0xc000003e,
                        39,
                        0x7fff0000,
                        Some(i64::from(native.pid)),
                    )?,
                    branch(
                        events,
                        x32_control_task,
                        0xc000003e,
                        0x40000027,
                        0x7fff0000,
                        Some(x32_return),
                    )?,
                    branch(
                        events,
                        x32_filtered_task,
                        0xc000003e,
                        0x40000027,
                        0x80000000,
                        None,
                    )?,
                    branch(
                        events,
                        i386_control_task,
                        0x40000003,
                        20,
                        0x7fff0000,
                        Some(i64::from(i386_control.pid)),
                    )?,
                    branch(events, i386_filtered_task, 0x40000003, 20, 0x80000000, None)?,
                ],
            )
        }
        VerifiedAbiRawV1::Arm64 {
            worker,
            native,
            arm32_control,
            arm32_filtered,
            ..
        } => {
            let worker_task = child(events, &calibrated, worker, coordinator)?;
            let native_task = child(events, &calibrated, native, worker_task)?;
            let control_task = child(events, &calibrated, arm32_control, worker_task)?;
            let filtered_task = child(events, &calibrated, arm32_filtered, worker_task)?;
            let metadata = helper
                .as_ref()
                .ok_or_else(|| CiError::Message("ABI held ARM helper absent".into()))?;
            for task in [control_task, filtered_task] {
                let execs = events
                    .iter()
                    .filter(|event| event.kind == 6 && event.task == task)
                    .collect::<Vec<_>>();
                let [exec] = execs.as_slice() else {
                    return fail("ABI exact ARM helper exec absent or ambiguous");
                };
                if exec.image_dev != metadata.device
                    || exec.image_inode != metadata.inode
                    || exec.monotonic_ns < metadata.begin_monotonic_ns
                    || exec.monotonic_ns > metadata.end_monotonic_ns
                {
                    return fail("ABI actual ARM helper image/timing differs");
                }
            }
            (
                worker_task,
                vec![
                    branch(
                        events,
                        native_task,
                        0xc00000b7,
                        172,
                        0x7fff0000,
                        Some(i64::from(native.pid)),
                    )?,
                    branch(
                        events,
                        control_task,
                        0x40000028,
                        20,
                        0x7fff0000,
                        Some(i64::from(arm32_control.pid)),
                    )?,
                    branch(events, filtered_task, 0x40000028, 20, 0x80000000, None)?,
                ],
            )
        }
    };
    if worker.tid != positive.worker.pid
        || !calibrated.matches(identity(worker), positive.worker.start_time)
        || joined_task(events, &calibrated, &positive.target)?
            != (crate::private_kernel_replay::KernelTaskIdentityV2 {
                tid: target.tid,
                tgid: target.tgid,
                start_boottime_ns: target.start_boottime_ns,
                cgroup_inode: target.cgroup_inode,
                time_ns_inode: target.time_ns_inode,
            })
    {
        return fail("ABI positive target/worker source identity differs");
    }
    retirement(
        events,
        worker,
        0,
        *branches
            .iter()
            .max()
            .ok_or_else(|| CiError::Message("ABI branches absent".into()))?,
    )?;
    Ok(result)
}

pub(crate) fn record_candidate_abi_fact<'a>(
    sources: NativeAbiSourcesV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    target: &ReplayTaskV1,
    filter: &DiagnosticSha256,
    capture_sha256: &DiagnosticSha256,
    leaf: impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<CaseFactV1> {
    verify_native_abi_sources(
        &sources,
        events,
        clock,
        target,
        filter,
        capture_sha256,
        leaf,
    )?;
    Ok(CaseFactV1::NativeAbiV1 { sources })
}
