//! Cleanup-only recovery reacquires exact native owners. Serialized locators
//! select no execution identity, release gate, host source or output destination.
use super::native_process::{PrivateAttemptPhase, ProcessIdentityV4};
use super::workload_attempt::{
    DirectoryIdentity, RecoveryJournal, RecoveryJournalError, WorkloadAttemptRecordV1,
};
use crate::protocol::{Frame, MessageKind};
use memcordon_core::execution_facts::CleanupStateV1;
use memcordon_core::result_v3::{
    CleanupObligationV3, CleanupResourceV3, CleanupV3, LinuxWorkloadTerminalV1,
    NativeWorkloadOutcomeV1, OutputDeliveryStateV3,
};
use memcordon_core::workload_request::{
    WorkloadAttemptAssociationV1, WorkloadRejectionCodeV1, WorkloadRejectionV1,
};
use memcordon_core::{BoundedText, BoundedVec};
use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerRecovery {
    format: String,
    revision: u32,
    association: WorkloadAttemptAssociationV1,
    caller: ProcessIdentityV4,
    caller_uid: u32,
    caller_gid: u32,
}

struct HeldProcess {
    identity: ProcessIdentityV4,
    descriptor: OwnedFd,
}
impl HeldProcess {
    fn acquire(identity: &ProcessIdentityV4) -> Result<Option<Self>, String> {
        let pid = i32::try_from(identity.pid).map_err(|_| "recovery PID exceeds native range")?;
        if pid <= 0 {
            return Err("invalid native recovery PID".into());
        }
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error.to_string())
            };
        }
        let held = Self {
            identity: identity.clone(),
            descriptor: unsafe { OwnedFd::from_raw_fd(raw) },
        };
        if held.exited()? {
            return Ok(None);
        }
        let birth = super::envelope::process_start_time(pid)?;
        if birth > identity.start_time {
            // Kernel PID reuse proves the old process is extinct. The newly
            // acquired foreign pidfd is dropped without ever being signaled.
            return Ok(None);
        }
        if birth != identity.start_time {
            return Err("recovery process birth substitution".into());
        }
        if held.exited()? {
            return Ok(None);
        }
        Ok(Some(held))
    }
    fn exited(&self) -> Result<bool, String> {
        let mut poll = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&raw mut poll, 1, 0) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if poll.revents & !(libc::POLLIN | libc::POLLHUP) != 0 {
            return Err("native recovery pidfd poll failed".into());
        }
        Ok(result != 0)
    }
    fn terminate(&self) -> Result<(), String> {
        if self.exited()? {
            return Ok(());
        }
        if super::envelope::process_start_time(self.identity.pid as i32)?
            != self.identity.start_time
        {
            return Err("native recovery process changed before signal".into());
        }
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.descriptor.as_raw_fd(),
                libc::SIGTERM,
                0,
                0,
            )
        } < 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.to_string());
            }
        }
        Ok(())
    }
    fn wait(&self, cutoff: Instant) -> Result<(), String> {
        while !self.exited()? {
            remaining(cutoff)?;
            std::thread::sleep(Duration::from_millis(10).min(remaining(cutoff)?));
        }
        Ok(())
    }
}

fn remaining(cutoff: Instant) -> Result<Duration, String> {
    cutoff
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| "original workload cleanup cutoff exhausted".into())
}

fn rejection(frame: &Frame, code: WorkloadRejectionCodeV1, detail: &str) -> Result<Frame, String> {
    let detail = bounded_text(detail)?;
    Ok(Frame {
        kind: MessageKind::WorkloadRejected,
        nonce: frame.nonce,
        attempt_id: frame.attempt_id,
        payload: serde_json::to_vec(&WorkloadRejectionV1 {
            format: "memcordon.workload-rejection".into(),
            revision: 1,
            code,
            detail,
        })
        .map_err(|error| error.to_string())?,
    })
}

fn bounded_text(detail: &str) -> Result<BoundedText<4096>, String> {
    let end = detail
        .char_indices()
        .map(|(index, character)| index + character.len_utf8())
        .take_while(|end| *end <= 4096)
        .last()
        .unwrap_or(0);
    BoundedText::new(&detail[..end]).map_err(str::to_owned)
}

fn parse_association(frame: &Frame) -> Result<WorkloadAttemptAssociationV1, String> {
    if frame.payload.len() > 64 * 1024 {
        return Err("workload recovery locator exceeds ceiling".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&frame.payload)?;
    let association: WorkloadAttemptAssociationV1 =
        serde_json::from_slice(&frame.payload).map_err(|error| error.to_string())?;
    association.validate().map_err(|error| error.to_string())?;
    if frame.attempt_id != association.attempt || frame.nonce != association.challenge {
        return Err("workload recovery frame/locator binding differs".into());
    }
    Ok(association)
}

pub(super) fn recover_public(
    stream: &mut UnixStream,
    frame: &Frame,
    descriptors: Vec<OwnedFd>,
    caller_pid: i32,
    caller_uid: u32,
    caller_gid: u32,
) -> Result<Frame, String> {
    forward_public(
        stream,
        frame,
        descriptors,
        caller_pid,
        caller_uid,
        caller_gid,
        false,
    )
}

pub(super) fn acknowledge_public(
    stream: &mut UnixStream,
    frame: &Frame,
    descriptors: Vec<OwnedFd>,
    caller_pid: i32,
    caller_uid: u32,
    caller_gid: u32,
) -> Result<Frame, String> {
    forward_public(
        stream,
        frame,
        descriptors,
        caller_pid,
        caller_uid,
        caller_gid,
        true,
    )
}

fn forward_public(
    _stream: &mut UnixStream,
    frame: &Frame,
    descriptors: Vec<OwnedFd>,
    caller_pid: i32,
    caller_uid: u32,
    caller_gid: u32,
    acknowledgment: bool,
) -> Result<Frame, String> {
    if !cfg!(feature = "private-tcp")
        || frame.kind
            != if acknowledgment {
                MessageKind::WorkloadAcknowledge
            } else {
                MessageKind::WorkloadRecover
            }
        || !descriptors.is_empty()
    {
        return rejection(
            frame,
            WorkloadRejectionCodeV1::MalformedRequest,
            "cleanup-only workload recovery accepts zero descriptors",
        );
    }
    let association = match parse_association(frame) {
        Ok(value) => value,
        Err(error) => return rejection(frame, WorkloadRejectionCodeV1::MalformedRequest, &error),
    };
    let _package = super::service::acquire_shared_package_lease()?;
    let caller = ProcessIdentityV4 {
        pid: u32::try_from(caller_pid).map_err(|_| "invalid authenticated recovery caller")?,
        start_time: super::envelope::process_start_time(caller_pid)?,
    };
    let _caller =
        HeldProcess::acquire(&caller)?.ok_or("authenticated recovery caller already exited")?;
    let payload = serde_json::to_vec(&BrokerRecovery {
        format: if acknowledgment {
            "memcordon.workload-broker-acknowledgment"
        } else {
            "memcordon.workload-broker-recovery"
        }
        .into(),
        revision: 1,
        association,
        caller,
        caller_uid,
        caller_gid,
    })
    .map_err(|error| error.to_string())?;
    let cutoff = Instant::now() + Duration::from_secs(10);
    let mut broker =
        super::launcher::connect_workload_until(frame.attempt_id, frame.nonce, cutoff)?;
    broker
        .set_read_timeout(Some(remaining(cutoff)?))
        .map_err(|error| error.to_string())?;
    broker
        .set_write_timeout(Some(remaining(cutoff)?))
        .map_err(|error| error.to_string())?;
    crate::protocol::write_frame(
        &mut broker,
        &Frame {
            kind: if acknowledgment {
                MessageKind::WorkloadBrokerAcknowledge
            } else {
                MessageKind::WorkloadBrokerRecover
            },
            nonce: frame.nonce,
            attempt_id: frame.attempt_id,
            payload,
        },
    )
    .map_err(|error| error.to_string())?;
    let (response, descriptors, version) = super::transport::receive_public(&broker)?;
    if version != crate::protocol::WORKLOAD_PROTOCOL_VERSION
        || !descriptors.is_empty()
        || response.attempt_id != frame.attempt_id
        || response.nonce != frame.nonce
        || !(response.kind == MessageKind::WorkloadRejected
            || response.kind
                == if acknowledgment {
                    MessageKind::WorkloadAcknowledgment
                } else {
                    MessageKind::WorkloadRecovery
                })
    {
        return Err("native recovery response association or phase differs".into());
    }
    Ok(response)
}

pub(super) fn recover_brokered(
    _stream: &mut UnixStream,
    frame: &Frame,
    descriptors: Vec<OwnedFd>,
    control_pid: i32,
    control_birth: u64,
) -> Result<Frame, String> {
    if !cfg!(feature = "private-tcp")
        || frame.kind != MessageKind::WorkloadBrokerRecover
        || !descriptors.is_empty()
        || frame.payload.len() > 64 * 1024
    {
        return rejection(
            frame,
            WorkloadRejectionCodeV1::MalformedRequest,
            "invalid native recovery inventory",
        );
    }
    let _package = super::service::acquire_shared_package_lease()?;
    let control = ProcessIdentityV4 {
        pid: u32::try_from(control_pid).map_err(|_| "invalid native control PID")?,
        start_time: control_birth,
    };
    let _control = HeldProcess::acquire(&control)?.ok_or("authenticated native control exited")?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&frame.payload)?;
    let request: BrokerRecovery =
        serde_json::from_slice(&frame.payload).map_err(|error| error.to_string())?;
    if request.format != "memcordon.workload-broker-recovery"
        || request.revision != 1
        || request.association.attempt != frame.attempt_id
        || request.association.challenge != frame.nonce
    {
        return rejection(
            frame,
            WorkloadRejectionCodeV1::MalformedRequest,
            "native recovery request binding differs",
        );
    }
    request
        .association
        .validate()
        .map_err(|error| error.to_string())?;
    let _caller = HeldProcess::acquire(&request.caller)?
        .ok_or("original authenticated recovery requester exited")?;
    let mut journal = match RecoveryJournal::acquire(&request.association, request.caller_uid) {
        Ok(journal) => journal,
        Err(RecoveryJournalError::CallerMismatch) => {
            return rejection(
                frame,
                WorkloadRejectionCodeV1::CallerIdentityMismatch,
                "recovery caller or original association differs",
            );
        }
        Err(RecoveryJournalError::NativeState(error)) => {
            return rejection(frame, WorkloadRejectionCodeV1::NativeUnavailable, &error);
        }
    };
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    let same_boot = journal.record().boot_id.as_str() == boot.trim();
    if same_boot {
        if HeldProcess::acquire(&journal.record().worker)?.is_some() {
            return rejection(
                frame,
                WorkloadRejectionCodeV1::NativeUnavailable,
                "original native worker remains live",
            );
        }
        if HeldProcess::acquire(&journal.record().frontend)?.is_some()
            && journal.record().frontend != request.caller
        {
            return rejection(
                frame,
                WorkloadRejectionCodeV1::CallerIdentityMismatch,
                "another live original frontend owns this attempt",
            );
        }
    }
    if let Some(terminal) = &journal.record().terminal {
        if journal.record().phase == PrivateAttemptPhase::Retired
            && terminal.cleanup.state == CleanupStateV1::Complete
            && (!same_boot || HeldProcess::acquire(&journal.record().control)?.is_none())
        {
            // Native retirement cannot certify the still-independent public
            // control's forwarded handles. Observe that exact process absent
            // before reporting their already-completed closure on a retry.
            let mut observed = terminal.clone();
            let mut obligations = BoundedVec::default();
            for obligation in observed.cleanup.obligations.as_slice() {
                if obligation.resource != CleanupResourceV3::ControlHandles {
                    obligations
                        .try_push(obligation.clone())
                        .map_err(|_| "cleanup obligation ceiling")?;
                }
            }
            obligations
                .try_push(CleanupObligationV3 {
                    resource: CleanupResourceV3::ControlHandles,
                    settled: true,
                })
                .map_err(|_| "cleanup obligation ceiling")?;
            observed.cleanup.obligations = obligations;
            observed.validate()?;
            return terminal_frame(frame, &observed);
        }
    }
    let cutoff = recovery_cutoff(&mut journal, boot.trim(), same_boot)?;
    let mut settled = std::collections::BTreeSet::new();
    let result = settle(journal.record(), same_boot, cutoff, &mut settled);
    let mut next = journal.record().clone();
    if let Err(error) = &result {
        let detail = bounded_text(error)?;
        if !next.errors.as_slice().contains(&detail) {
            next.errors
                .try_push(detail)
                .map_err(|_| "recovery causal-error inventory exhausted")?;
        }
    }
    let resources = [
        CleanupResourceV3::Aggregate,
        CleanupResourceV3::Target,
        CleanupResourceV3::NamespaceInit,
        CleanupResourceV3::Guardian,
        CleanupResourceV3::Relays,
        CleanupResourceV3::RootReferences,
        CleanupResourceV3::Staging,
        CleanupResourceV3::Footprint,
        CleanupResourceV3::ControlHandles,
    ];
    let mut obligations = BoundedVec::default();
    next.outstanding = BoundedVec::default();
    for resource in resources {
        let complete = settled.contains(&resource);
        obligations
            .try_push(CleanupObligationV3 {
                resource,
                settled: complete,
            })
            .map_err(|_| "cleanup obligation ceiling")?;
        if !complete {
            next.outstanding
                .try_push(resource)
                .map_err(|_| "cleanup outstanding ceiling")?;
        }
    }
    let terminal = LinuxWorkloadTerminalV1 {
        format: "memcordon.linux-workload-terminal".into(),
        revision: 1,
        association: next.association.clone(),
        request: next.request.clone(),
        release: next.release,
        native: next.native.clone(),
        outcome: next
            .outcome
            .clone()
            .unwrap_or(NativeWorkloadOutcomeV1::Unknown),
        cleanup: CleanupV3 {
            state: if result.is_ok() {
                CleanupStateV1::Complete
            } else {
                CleanupStateV1::Incomplete
            },
            obligations,
        },
        output_delivery: if next.output_files.as_slice().is_empty() {
            OutputDeliveryStateV3::Complete
        } else {
            OutputDeliveryStateV3::Incomplete
        },
        failures: next.errors.clone(),
    };
    terminal.validate()?;
    next.phase = if result.is_ok() {
        PrivateAttemptPhase::Retired
    } else {
        PrivateAttemptPhase::CleanupIncomplete
    };
    next.terminal = Some(terminal.clone());
    journal.update(next)?;
    terminal_frame(frame, &terminal)
}

pub(super) fn acknowledge_brokered(
    _stream: &mut UnixStream,
    frame: &Frame,
    descriptors: Vec<OwnedFd>,
    control_pid: i32,
    control_birth: u64,
) -> Result<Frame, String> {
    if !cfg!(feature = "private-tcp")
        || frame.kind != MessageKind::WorkloadBrokerAcknowledge
        || !descriptors.is_empty()
        || frame.payload.len() > 64 * 1024
    {
        return rejection(
            frame,
            WorkloadRejectionCodeV1::MalformedRequest,
            "invalid acknowledgment inventory",
        );
    }
    let _package = super::service::acquire_shared_package_lease()?;
    let _control = HeldProcess::acquire(&ProcessIdentityV4 {
        pid: u32::try_from(control_pid).map_err(|_| "invalid acknowledgment control PID")?,
        start_time: control_birth,
    })?
    .ok_or("authenticated acknowledgment control exited")?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&frame.payload)?;
    let request: BrokerRecovery =
        serde_json::from_slice(&frame.payload).map_err(|e| e.to_string())?;
    if request.format != "memcordon.workload-broker-acknowledgment"
        || request.revision != 1
        || request.association.attempt != frame.attempt_id
        || request.association.challenge != frame.nonce
    {
        return rejection(
            frame,
            WorkloadRejectionCodeV1::MalformedRequest,
            "acknowledgment binding differs",
        );
    }
    request.association.validate().map_err(|e| e.to_string())?;
    let _caller =
        HeldProcess::acquire(&request.caller)?.ok_or("acknowledgment requester exited")?;
    let mut journal = match RecoveryJournal::acquire(&request.association, request.caller_uid) {
        Ok(value) => value,
        Err(RecoveryJournalError::CallerMismatch) => {
            return rejection(
                frame,
                WorkloadRejectionCodeV1::CallerIdentityMismatch,
                "acknowledgment caller differs",
            );
        }
        Err(RecoveryJournalError::NativeState(error)) => {
            return rejection(frame, WorkloadRejectionCodeV1::NativeUnavailable, &error);
        }
    };
    let boot =
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| e.to_string())?;
    if journal.record().boot_id.as_str() == boot.trim() {
        if HeldProcess::acquire(&journal.record().worker)?.is_some()
            || HeldProcess::acquire(&journal.record().control)?.is_some()
        {
            return rejection(
                frame,
                WorkloadRejectionCodeV1::NativeUnavailable,
                "original native worker or control remains live",
            );
        }
        if HeldProcess::acquire(&journal.record().frontend)?.is_some()
            && journal.record().frontend != request.caller
        {
            return rejection(
                frame,
                WorkloadRejectionCodeV1::CallerIdentityMismatch,
                "original frontend remains live",
            );
        }
    }
    let mut next = journal.record().clone();
    if next.boot_id.as_str() == boot.trim() {
        for (intended, identity) in [
            (next.intents.guardian, next.guardian.as_ref()),
            (next.intents.namespace_init, next.namespace_init.as_ref()),
            (next.intents.target, next.target.as_ref()),
        ] {
            if intended && identity.is_none() {
                return rejection(
                    frame,
                    WorkloadRejectionCodeV1::NativeUnavailable,
                    "native acquisition intent has no matched process identity",
                );
            }
            if identity
                .map(HeldProcess::acquire)
                .transpose()?
                .flatten()
                .is_some()
            {
                return rejection(
                    frame,
                    WorkloadRejectionCodeV1::NativeUnavailable,
                    "original native process remains live",
                );
            }
        }
    }
    let terminal = next
        .terminal
        .as_mut()
        .ok_or("acknowledgment requires a retained native terminal")?;
    terminal.validate()?;
    if terminal
        .cleanup
        .obligations
        .as_slice()
        .iter()
        .any(|o| !o.settled && o.resource != CleanupResourceV3::ControlHandles)
    {
        return rejection(
            frame,
            WorkloadRejectionCodeV1::NativeUnavailable,
            "native cleanup obligations remain outstanding",
        );
    }
    require_absent(&Path::new(super::CGROUP_ROOT).join(next.attempt_id.as_str()))?;
    require_absent(&super::workload_attempt::input_path(
        next.attempt_id.as_str(),
    )?)?;
    require_absent(&super::private_root::NativeRootStaging::intended_path(
        next.attempt_id.as_str(),
    )?)?;
    require_absent(
        &Path::new(super::workload_resources::RESOURCE_ROOT).join(next.attempt_id.as_str()),
    )?;
    let mut obligations = BoundedVec::default();
    for obligation in terminal.cleanup.obligations.as_slice() {
        obligations
            .try_push(CleanupObligationV3 {
                resource: obligation.resource,
                settled: obligation.settled
                    || obligation.resource == CleanupResourceV3::ControlHandles,
            })
            .map_err(|_| "acknowledgment obligation ceiling")?;
    }
    terminal.cleanup.obligations = obligations;
    terminal.cleanup.state = CleanupStateV1::Complete;
    terminal.validate()?;
    next.outstanding = BoundedVec::default();
    next.phase = PrivateAttemptPhase::Retired;
    journal.update(next)?;
    journal.retire_acknowledged(&request.association)?;
    let acknowledgment = memcordon_core::workload_request::WorkloadAcknowledgmentV1 {
        format: "memcordon.workload-acknowledgment".into(),
        revision: 1,
        association: request.association,
        record_retired: true,
    };
    Ok(Frame {
        kind: MessageKind::WorkloadAcknowledgment,
        nonce: frame.nonce,
        attempt_id: frame.attempt_id,
        payload: serde_json::to_vec(&acknowledgment).map_err(|e| e.to_string())?,
    })
}

fn terminal_frame(request: &Frame, terminal: &LinuxWorkloadTerminalV1) -> Result<Frame, String> {
    terminal.validate()?;
    Ok(Frame {
        kind: MessageKind::WorkloadRecovery,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(terminal).map_err(|error| error.to_string())?,
    })
}

fn recovery_cutoff(
    journal: &mut RecoveryJournal,
    boot: &str,
    same_boot: bool,
) -> Result<Instant, String> {
    if !same_boot {
        require_absent(&Path::new(super::CGROUP_ROOT).join(journal.record().attempt_id.as_str()))?;
    }
    let now = super::clock::monotonic_nanos()?;
    if same_boot
        && journal
            .record()
            .cleanup_boot_id
            .as_ref()
            .is_some_and(|id| id.as_str() != boot)
    {
        return Err("original cleanup clock boot binding differs".into());
    }
    let cutoff = if journal
        .record()
        .cleanup_boot_id
        .as_ref()
        .is_some_and(|id| id.as_str() == boot)
    {
        journal
            .record()
            .cleanup_cutoff_nanos
            .ok_or("cleanup clock association is incomplete")?
    } else {
        let cutoff = now
            .checked_add(10_000_000_000)
            .ok_or("recovery clock overflow")?;
        let mut next = journal.record().clone();
        next.cleanup_boot_id = Some(BoundedText::new(boot).map_err(str::to_owned)?);
        next.cleanup_cutoff_nanos = Some(cutoff);
        journal.update(next)?;
        cutoff
    };
    let instant = Instant::now();
    let sampled = super::clock::monotonic_nanos()?;
    let remaining = cutoff
        .checked_sub(sampled)
        .filter(|value| *value != 0)
        .ok_or("original persisted cleanup cutoff exhausted")?;
    instant
        .checked_add(Duration::from_nanos(remaining))
        .ok_or_else(|| "recovery instant overflow".into())
}

fn settle(
    record: &WorkloadAttemptRecordV1,
    same_boot: bool,
    cutoff: Instant,
    settled: &mut std::collections::BTreeSet<CleanupResourceV3>,
) -> Result<(), String> {
    remaining(cutoff)?;
    if same_boot {
        if let Some(control) = HeldProcess::acquire(&record.control)? {
            control.wait(cutoff)?;
        }
    }
    settled.insert(CleanupResourceV3::Relays);
    settled.insert(CleanupResourceV3::ControlHandles);
    let target = if same_boot {
        record
            .target
            .as_ref()
            .map(HeldProcess::acquire)
            .transpose()?
            .flatten()
    } else {
        None
    };
    let init = if same_boot {
        record
            .namespace_init
            .as_ref()
            .map(HeldProcess::acquire)
            .transpose()?
            .flatten()
    } else {
        None
    };
    let guardian = if same_boot {
        record
            .guardian
            .as_ref()
            .map(HeldProcess::acquire)
            .transpose()?
            .flatten()
    } else {
        None
    };
    let cgroup_path = Path::new(super::CGROUP_ROOT).join(record.attempt_id.as_str());
    if !same_boot {
        require_absent(&cgroup_path)?;
    }
    match &record.cgroup {
        Some(identity) => retire_cgroup(&cgroup_path, identity, cutoff)?,
        None => require_absent(&cgroup_path)?,
    }
    settled.insert(CleanupResourceV3::Aggregate);
    if let Some(target) = &target {
        target.wait(cutoff)?;
    }
    if let Some(init) = &init {
        init.wait(cutoff)?;
    }
    if let Some(guardian) = &guardian {
        guardian.terminate()?;
        guardian.wait(cutoff)?;
    }
    // None is not evidence of closure across an unpublished native acquisition.
    // Stable pre-creation intents survive mutable retirement phases and retries.
    if same_boot {
        if record.guardian.is_none() && record.intents.guardian {
            return Err("original guardian allocation identity was not published".into());
        }
        if (record.namespace_init.is_none() && record.intents.namespace_init)
            || (record.target.is_none() && record.intents.target)
        {
            return Err("original init/target allocation identity was not published".into());
        }
    }
    drop(target);
    drop(init);
    drop(guardian);
    settled.insert(CleanupResourceV3::Target);
    settled.insert(CleanupResourceV3::NamespaceInit);
    settled.insert(CleanupResourceV3::Guardian);
    let root_path =
        super::private_root::NativeRootStaging::intended_path(record.attempt_id.as_str())?;
    retire_staging(&root_path, record.staging.as_ref(), false, cutoff)?;
    let input = super::workload_attempt::input_path(record.attempt_id.as_str())?;
    retire_staging(&input, record.input_staging.as_ref(), true, cutoff)?;
    // All original pin owners are now extinct and every native staging inode
    // has been observed absent. Recovery never recreates lost filesystem pins.
    settled.insert(CleanupResourceV3::RootReferences);
    settled.insert(CleanupResourceV3::Staging);
    retire_charge(record, cutoff)?;
    settled.insert(CleanupResourceV3::Footprint);
    Ok(())
}

fn open_at(parent: &File, name: &OsStr, flags: i32) -> Result<File, std::io::Error> {
    let name = CString::new(name.as_bytes()).map_err(std::io::Error::other)?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn parent_name(path: &Path) -> Result<(File, OsString), String> {
    let parent = super::workload_attempt::protected_directory_path(
        path.parent().ok_or("recovery path has no parent")?,
    )?;
    Ok((
        parent,
        path.file_name()
            .ok_or("recovery path has no name")?
            .to_owned(),
    ))
}

fn directory_matches(file: &File, identity: &DirectoryIdentity) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || (metadata.dev(), metadata.ino()) != (identity.device, identity.inode)
    {
        return Err("recovery native directory identity substitution".into());
    }
    Ok(())
}

fn require_absent(path: &Path) -> Result<(), String> {
    // Walk each existing ancestor without following a link. A missing ancestor
    // proves this exact protected allocation path is absent, not a new owner.
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| error.to_string())?;
    let parts: Vec<_> = path
        .components()
        .filter(|part| *part != std::path::Component::RootDir)
        .collect();
    if !path.is_absolute() || parts.is_empty() {
        return Err("invalid recovery absence path".into());
    }
    for (index, part) in parts.iter().enumerate() {
        let std::path::Component::Normal(name) = part else {
            return Err("unnormalized recovery absence path".into());
        };
        match open_at(&directory, name, libc::O_PATH) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(error) => return Err(error.to_string()),
            Ok(file) => {
                let metadata = file.metadata().map_err(|error| error.to_string())?;
                if index + 1 == parts.len() {
                    return Err("unobserved native recovery allocation remains present".into());
                }
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return Err("recovery absence ancestry is not protected".into());
                }
                directory = file;
            }
        }
    }
    Err("native recovery allocation remains present".into())
}

fn remove_directory(
    parent: &File,
    name: &OsStr,
    held: &File,
    identity: &DirectoryIdentity,
    durable: bool,
) -> Result<(), String> {
    match open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(named) => directory_matches(&named, identity)?,
        Err(error)
            if error.raw_os_error() == Some(libc::ENOENT)
                && held.metadata().map_err(|error| error.to_string())?.nlink() == 0 =>
        {
            return Ok(());
        }
        Err(error) => return Err(error.to_string()),
    }
    let name = CString::new(name.as_bytes()).map_err(|error| error.to_string())?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if held.metadata().map_err(|error| error.to_string())?.nlink() != 0 {
        return Err("retired native directory remains linked".into());
    }
    if durable {
        parent.sync_all().map_err(|error| error.to_string())
    } else {
        Ok(())
    }
}

fn retire_cgroup(path: &Path, identity: &DirectoryIdentity, cutoff: Instant) -> Result<(), String> {
    remaining(cutoff)?;
    let (parent, name) = match parent_name(path) {
        Ok(value) => value,
        Err(_error) => {
            require_absent(path)?;
            return Ok(());
        }
    };
    let held = match open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    directory_matches(&held, identity)?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(held.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if unsafe { filesystem.assume_init() }.f_type as u64 != 0x6367_7270 {
        return Err("recovery boundary is not native cgroup2".into());
    }
    open_at(&held, OsStr::new("cgroup.kill"), libc::O_WRONLY)
        .map_err(|error| error.to_string())?
        .write_all(b"1")
        .map_err(|error| error.to_string())?;
    loop {
        remaining(cutoff)?;
        let mut events = String::new();
        open_at(&held, OsStr::new("cgroup.events"), libc::O_RDONLY)
            .map_err(|error| error.to_string())?
            .take(4097)
            .read_to_string(&mut events)
            .map_err(|error| error.to_string())?;
        if events.len() > 4096 {
            return Err("native recovered cgroup events exceed ceiling".into());
        }
        match events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => {
                let mut members = Vec::new();
                open_at(&held, OsStr::new("cgroup.procs"), libc::O_RDONLY)
                    .map_err(|error| error.to_string())?
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut members)
                    .map_err(|error| error.to_string())?;
                if members.iter().any(|byte| !byte.is_ascii_whitespace()) {
                    return Err("recovered cgroup membership disagrees with emptiness".into());
                }
                return remove_directory(&parent, &name, &held, identity, false);
            }
            Some("1") => std::thread::sleep(Duration::from_millis(10).min(remaining(cutoff)?)),
            _ => return Err("native recovered cgroup population is malformed".into()),
        }
    }
}

fn retire_staging(
    path: &Path,
    identity: Option<&DirectoryIdentity>,
    clear: bool,
    cutoff: Instant,
) -> Result<(), String> {
    remaining(cutoff)?;
    let Some(identity) = identity else {
        return require_absent(path);
    };
    let (parent, name) = match parent_name(path) {
        Ok(value) => value,
        Err(_) => {
            require_absent(path)?;
            return Ok(());
        }
    };
    let held = match open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    directory_matches(&held, identity)?;
    if clear {
        clear_input_tree(&held, cutoff)?;
    }
    remove_directory(&parent, &name, &held, identity, true)
}

fn mount_id(file: &File) -> Result<u64, String> {
    let mut text = String::new();
    File::open(Path::new("/proc/self/fdinfo").join(file.as_raw_fd().to_string()))
        .map_err(|error| error.to_string())?
        .take(8193)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    if text.len() > 8192 {
        return Err("native descriptor observation exceeds ceiling".into());
    }
    text.lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .ok_or("native descriptor mount identity absent")?
        .trim()
        .parse::<u64>()
        .map_err(|error| error.to_string())
}

fn relative_directory(root: &File, path: &Path, mount: u64) -> Result<File, String> {
    let mut directory = root.try_clone().map_err(|error| error.to_string())?;
    for part in path.components() {
        let std::path::Component::Normal(name) = part else {
            return Err("input retirement path is not normalized".into());
        };
        let next = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|error| error.to_string())?;
        let metadata = next.metadata().map_err(|error| error.to_string())?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || mount_id(&next)? != mount {
            return Err("input retirement ancestry or mount identity differs".into());
        }
        directory = next;
    }
    Ok(directory)
}

fn clear_input_tree(root: &File, cutoff: Instant) -> Result<(), String> {
    let mount = mount_id(root)?;
    let metadata = root.metadata().map_err(|error| error.to_string())?;
    let root_identity = DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let mut actions = vec![(PathBuf::new(), root_identity, false)];
    // Every implicit directory component consumes bytes in a bounded manifest.
    // Use an iterative traversal so a valid deep path does not exhaust FDs.
    let mut remaining_nodes = memcordon_core::workload_bundle::MANIFEST_BYTES
        .checked_mul(2)
        .ok_or("input inventory ceiling overflow")?;
    while let Some((relative, identity, retire)) = actions.pop() {
        remaining(cutoff)?;
        let directory = relative_directory(root, &relative, mount)?;
        directory_matches(&directory, &identity)?;
        if retire {
            let parent =
                relative_directory(root, relative.parent().ok_or("input parent absent")?, mount)?;
            remove_directory(
                &parent,
                relative.file_name().ok_or("input filename absent")?,
                &directory,
                &identity,
                true,
            )?;
            continue;
        }
        if !relative.as_os_str().is_empty() {
            actions.push((relative.clone(), identity, true));
        }
        for entry in
            std::fs::read_dir(Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string()))
                .map_err(|error| error.to_string())?
        {
            remaining(cutoff)?;
            remaining_nodes = remaining_nodes
                .checked_sub(1)
                .ok_or("input retirement inventory exceeds ceiling")?;
            let name = entry.map_err(|error| error.to_string())?.file_name();
            let held =
                open_at(&directory, &name, libc::O_PATH).map_err(|error| error.to_string())?;
            let metadata = held.metadata().map_err(|error| error.to_string())?;
            if metadata.uid() != 0
                || metadata.dev() != root.metadata().map_err(|error| error.to_string())?.dev()
                || mount_id(&held)? != mount
            {
                return Err("input retirement object custody or mount differs".into());
            }
            if metadata.is_dir() {
                if metadata.mode() & 0o022 != 0 {
                    return Err("input retirement directory is writable outside owner".into());
                }
                actions.push((
                    relative.join(&name),
                    DirectoryIdentity {
                        device: metadata.dev(),
                        inode: metadata.ino(),
                    },
                    false,
                ));
            } else if (metadata.is_file() || metadata.file_type().is_symlink())
                && metadata.nlink() == 1
            {
                if metadata.is_file() && metadata.mode() & 0o022 != 0 {
                    return Err("input retirement file is writable outside owner".into());
                }
                let named =
                    open_at(&directory, &name, libc::O_PATH).map_err(|error| error.to_string())?;
                let current = named.metadata().map_err(|error| error.to_string())?;
                if (metadata.dev(), metadata.ino()) != (current.dev(), current.ino()) {
                    return Err("input retirement object was substituted".into());
                }
                let name = CString::new(name.as_bytes()).map_err(|error| error.to_string())?;
                if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                if held.metadata().map_err(|error| error.to_string())?.nlink() != 0 {
                    return Err("retired input inode remains linked".into());
                }
            } else {
                return Err("input retirement contains an unexpected object kind".into());
            }
        }
        directory.sync_all().map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn retire_charge(record: &WorkloadAttemptRecordV1, cutoff: Instant) -> Result<(), String> {
    remaining(cutoff)?;
    let path = Path::new(super::workload_resources::RESOURCE_ROOT).join(record.attempt_id.as_str());
    let (directory, name) = match parent_name(&path) {
        Ok(value) => value,
        Err(_) => {
            require_absent(&path)?;
            return Ok(());
        }
    };
    let charge = match open_at(&directory, &name, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    if !record.intents.footprint {
        return Err("unobserved footprint allocation is present".into());
    }
    let metadata = charge.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != std::mem::size_of::<u64>() as u64
    {
        return Err("recovered footprint charge custody differs".into());
    }
    let lock = open_at(
        &directory,
        OsStr::new("allocator.lock"),
        libc::O_RDWR | libc::O_CREAT,
    )
    .map_err(|error| error.to_string())?;
    let lock_metadata = lock.metadata().map_err(|error| error.to_string())?;
    if !lock_metadata.is_file()
        || lock_metadata.uid() != 0
        || lock_metadata.mode() & 0o777 != 0o600
        || lock_metadata.nlink() != 1
    {
        return Err("footprint allocator lock custody differs".into());
    }
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(std::io::Error::last_os_error().to_string());
        }
        std::thread::sleep(Duration::from_millis(10).min(remaining(cutoff)?));
    }
    let named = open_at(&directory, &name, libc::O_RDONLY).map_err(|error| error.to_string())?;
    let current = named.metadata().map_err(|error| error.to_string())?;
    if (metadata.dev(), metadata.ino()) != (current.dev(), current.ino()) {
        return Err("footprint charge was substituted".into());
    }
    require_absent(&Path::new(super::CGROUP_ROOT).join(record.attempt_id.as_str()))?;
    require_absent(&super::workload_attempt::input_path(
        record.attempt_id.as_str(),
    )?)?;
    require_absent(&super::private_root::NativeRootStaging::intended_path(
        record.attempt_id.as_str(),
    )?)?;
    let name = CString::new(name.as_bytes()).map_err(|error| error.to_string())?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    directory.sync_all().map_err(|error| error.to_string())
}

/// Explicit machine maintenance has a separate bounded allowance, held by the
/// real exclusive package leases. It grants no new request or execution time.
pub(crate) fn drain_for_package_until(
    guard: &crate::package::PackageDrainGuard<'_>,
    cutoff: Instant,
) -> Result<(), String> {
    guard.validate()?;
    remaining(cutoff)?;
    let root = Path::new(super::workload_attempt::JOURNAL_ROOT);
    let directory = match super::workload_attempt::protected_directory_path(root) {
        Ok(directory) => Some(directory),
        Err(_) => {
            require_absent(root)?;
            None
        }
    };
    if let Some(directory) = &directory {
        if directory
            .metadata()
            .map_err(|error| error.to_string())?
            .mode()
            & 0o777
            != 0o700
        {
            return Err("current journal root protection differs during package drain".into());
        }
        let capacity_name = OsStr::new(super::workload_attempt::CAPACITY_LOCK_NAME);
        let capacity = open_at(directory, capacity_name, libc::O_RDWR | libc::O_CREAT)
            .map_err(|error| error.to_string())?;
        protected_auxiliary(&capacity)?;
        if capacity
            .metadata()
            .map_err(|error| error.to_string())?
            .len()
            != 0
            || unsafe { libc::flock(capacity.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
        {
            return Err("current journal allocator remains live or has unexpected contents".into());
        }
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?;
        for entry in
            std::fs::read_dir(Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string()))
                .map_err(|error| error.to_string())?
        {
            remaining(cutoff)?;
            guard.validate()?;
            let name = entry.map_err(|error| error.to_string())?.file_name();
            let text = name.to_str().ok_or("non-UTF8 current journal entry")?;
            if text == super::workload_attempt::CAPACITY_LOCK_NAME {
                continue;
            }
            if !super::cgroup::valid_attempt_identity(text) {
                if recognized_journal_auxiliary(text).is_some() {
                    continue;
                }
                return Err("unrecognized current journal object retained by package drain".into());
            }
            let record = super::workload_attempt::recovery_read_record(directory, text)?;
            let mut journal = RecoveryJournal::acquire(&record.association, record.caller_uid)
                .map_err(|error| match error {
                    RecoveryJournalError::CallerMismatch => {
                        "current package journal association changed".into()
                    }
                    RecoveryJournalError::NativeState(detail) => detail,
                })?;
            let same_boot = record.boot_id.as_str() == boot.trim();
            if same_boot {
                if let Some(worker) = HeldProcess::acquire(&record.worker)? {
                    worker.wait(cutoff)?;
                }
                if let Some(control) = HeldProcess::acquire(&record.control)? {
                    control.wait(cutoff)?;
                }
            }
            let mut settled = std::collections::BTreeSet::new();
            let result = settle(journal.record(), same_boot, cutoff, &mut settled);
            let mut next = journal.record().clone();
            if let Err(error) = &result {
                let detail = bounded_text(error)?;
                if !next.errors.as_slice().contains(&detail) {
                    next.errors
                        .try_push(detail)
                        .map_err(|_| "package cleanup causal-error inventory exhausted")?;
                }
            }
            let mut obligations = BoundedVec::default();
            next.outstanding = BoundedVec::default();
            for resource in [
                CleanupResourceV3::Aggregate,
                CleanupResourceV3::Target,
                CleanupResourceV3::NamespaceInit,
                CleanupResourceV3::Guardian,
                CleanupResourceV3::Relays,
                CleanupResourceV3::ControlHandles,
                CleanupResourceV3::RootReferences,
                CleanupResourceV3::Staging,
                CleanupResourceV3::Footprint,
            ] {
                let complete = settled.contains(&resource);
                obligations
                    .try_push(CleanupObligationV3 {
                        resource,
                        settled: complete,
                    })
                    .map_err(|_| "package cleanup obligation ceiling")?;
                if !complete {
                    next.outstanding
                        .try_push(resource)
                        .map_err(|_| "package cleanup outstanding ceiling")?;
                }
            }
            let terminal = LinuxWorkloadTerminalV1 {
                format: "memcordon.linux-workload-terminal".into(),
                revision: 1,
                association: next.association.clone(),
                request: next.request.clone(),
                release: next.release,
                native: next.native.clone(),
                outcome: next
                    .outcome
                    .clone()
                    .unwrap_or(NativeWorkloadOutcomeV1::Unknown),
                cleanup: CleanupV3 {
                    state: if result.is_ok() {
                        CleanupStateV1::Complete
                    } else {
                        CleanupStateV1::Incomplete
                    },
                    obligations,
                },
                output_delivery: if next.output_files.as_slice().is_empty() {
                    OutputDeliveryStateV3::Complete
                } else {
                    OutputDeliveryStateV3::Incomplete
                },
                failures: next.errors.clone(),
            };
            terminal.validate()?;
            next.terminal = Some(terminal);
            next.phase = if result.is_ok() {
                PrivateAttemptPhase::Retired
            } else {
                PrivateAttemptPhase::CleanupIncomplete
            };
            journal.update(next)?;
            result?;
            remaining(cutoff)?;
            journal.retire_completed(guard)?;
        }
        // A previous cleanup may have removed its complete record immediately
        // before losing the response. Only unlocked, protected reserved lock
        // files may remain without a record; unknown scratch is retained.
        for entry in
            std::fs::read_dir(Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string()))
                .map_err(|error| error.to_string())?
        {
            remaining(cutoff)?;
            let name = entry.map_err(|error| error.to_string())?.file_name();
            let text = name.to_str().ok_or("non-UTF8 current journal residual")?;
            if text == super::workload_attempt::CAPACITY_LOCK_NAME {
                continue;
            }
            let Some(attempt) = text
                .strip_suffix(".recovery-lock")
                .filter(|attempt| super::cgroup::valid_attempt_identity(attempt))
            else {
                return Err("current journal retains unsettled or unknown objects".into());
            };
            match open_at(directory, OsStr::new(attempt), libc::O_RDONLY) {
                Ok(_) => return Err("current package journal remains unretired".into()),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => (),
                Err(error) => return Err(error.to_string()),
            }
            let file =
                open_at(directory, &name, libc::O_RDWR).map_err(|error| error.to_string())?;
            protected_auxiliary(&file)?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err("current recovery lock remains live".into());
            }
            let name = CString::new(name.as_bytes()).map_err(|error| error.to_string())?;
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        let named =
            open_at(directory, capacity_name, libc::O_RDONLY).map_err(|error| error.to_string())?;
        let before = capacity.metadata().map_err(|error| error.to_string())?;
        let after = named.metadata().map_err(|error| error.to_string())?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err("current journal capacity lock was substituted".into());
        }
        let name = CString::new(capacity_name.as_bytes()).map_err(|error| error.to_string())?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        directory.sync_all().map_err(|error| error.to_string())?;
    }
    audit_empty_current_inputs(cutoff)?;
    retire_idle_resource_metadata(cutoff)?;
    guard.validate()
}

fn recognized_journal_auxiliary(name: &str) -> Option<&str> {
    [".recovery-lock", ".recovery-update", ".update"]
        .into_iter()
        .find_map(|suffix| {
            name.strip_suffix(suffix)
                .filter(|attempt| super::cgroup::valid_attempt_identity(attempt))
        })
}

/// Only the authenticated uninstall owner may retire these drained roots.
/// Upgrade retains its existing directory and coordination lifetime.
pub(crate) fn retire_empty_roots_for_uninstall(
    guard: &crate::package::PackageDrainGuard<'_>,
    cutoff: Instant,
) -> Result<(), String> {
    guard.validate()?;
    for path in [
        super::workload_attempt::JOURNAL_ROOT,
        super::workload_attempt::INPUT_ROOT,
        super::workload_resources::RESOURCE_ROOT,
    ] {
        remaining(cutoff)?;
        let path = Path::new(path);
        let (parent, name) = match parent_name(path) {
            Ok(value) => value,
            Err(error) => {
                require_absent(path).map_err(|absence| {
                    format!("current root parent custody: {error}; absence check: {absence}")
                })?;
                continue;
            }
        };
        let held = match open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(held) => held,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                require_absent(path)?;
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        super::empty_runtime_directory::retire(&parent, &name, &held, 0, cutoff).map_err(
            |error| format!("current empty root retirement {}: {error}", path.display()),
        )?;
    }
    guard.validate()
}
fn protected_auxiliary(file: &File) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > super::workload_attempt::MAX_RECORD_BYTES as u64
    {
        return Err("current package auxiliary custody differs".into());
    }
    Ok(())
}
fn audit_empty_current_inputs(cutoff: Instant) -> Result<(), String> {
    remaining(cutoff)?;
    let path = Path::new(super::workload_attempt::INPUT_ROOT);
    let directory = match super::workload_attempt::protected_directory_path(path) {
        Ok(directory) => directory,
        Err(_) => {
            require_absent(path)?;
            return Ok(());
        }
    };
    if std::fs::read_dir(Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string()))
        .map_err(|error| error.to_string())?
        .next()
        .is_some()
    {
        return Err("current input allocations remain without a retired journal".into());
    }
    Ok(())
}
fn retire_idle_resource_metadata(cutoff: Instant) -> Result<(), String> {
    remaining(cutoff)?;
    let path = Path::new(super::workload_resources::RESOURCE_ROOT);
    let directory = match super::workload_attempt::protected_directory_path(path) {
        Ok(directory) => directory,
        Err(_) => {
            require_absent(path)?;
            return Ok(());
        }
    };
    let mut held = Vec::new();
    for entry in
        std::fs::read_dir(Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string()))
            .map_err(|error| error.to_string())?
    {
        remaining(cutoff)?;
        let name = entry.map_err(|error| error.to_string())?.file_name();
        let text = name.to_str().ok_or("non-UTF8 current resource object")?;
        if text != "allocator.lock"
            && !(0..super::workload_resources::SLOT_COUNT).any(|index| {
                Path::new("intake")
                    .with_extension(index.to_string())
                    .as_os_str()
                    == name.as_os_str()
            })
        {
            return Err("current footprint charge or unknown resource remains".into());
        }
        if held.len() > super::workload_resources::SLOT_COUNT {
            return Err("current resource metadata inventory exceeds ceiling".into());
        }
        let file = open_at(&directory, &name, libc::O_RDWR).map_err(|error| error.to_string())?;
        protected_auxiliary(&file)?;
        if file.metadata().map_err(|error| error.to_string())?.len() != 0 {
            return Err("current resource lock contains unexpected bytes".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("current receiver or allocator remains live".into());
        }
        held.push((name, file));
    }
    for (name, _file) in &held {
        remaining(cutoff)?;
        let name = CString::new(name.as_bytes()).map_err(|error| error.to_string())?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    directory.sync_all().map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "../../../../tests/sealed_agent/linux_workload_recovery.rs"]
mod tests;
