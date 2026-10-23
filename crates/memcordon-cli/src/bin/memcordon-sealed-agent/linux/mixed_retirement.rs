//! One optional observation owned by the original native retirement attempt.
#[cfg(test)]
#[path = "../../../../tests/sealed_agent/mixed_retirement_transport.rs"]
mod transport_tests;
use crate::protocol::{Frame, MessageKind};
use memcordon_core::mixed_observation::*;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub(super) fn boot_identity() -> Result<String, String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}
pub(super) fn local_cutoff(absolute: u64) -> Result<Instant, String> {
    let sampled = Instant::now();
    let remaining = absolute
        .checked_sub(super::clock::monotonic_millis()?)
        .ok_or("original retirement cutoff expired")?;
    if remaining == 0 {
        return Err("original retirement cutoff expired".into());
    }
    sampled
        .checked_add(Duration::from_millis(remaining))
        .ok_or("retirement cutoff overflow".into())
}

struct BoundedSocket<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}
impl BoundedSocket<'_> {
    fn ready(&self, events: i16) -> std::io::Result<()> {
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            let mut fd = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events,
                revents: 0,
            };
            let millis = i32::try_from(remaining.as_millis())
                .unwrap_or(i32::MAX)
                .max(1);
            // SAFETY: poll borrows exactly one valid descriptor and initialized row.
            let result = unsafe { libc::poll(&raw mut fd, 1, millis) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 {
                continue;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}
impl Read for BoundedSocket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.ready(libc::POLLIN)?;
            let mut control = [0_usize; 32];
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: all message storage is initialized and lives through recvmsg.
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &raw mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = std::mem::size_of_val(&control);
            // SAFETY: recvmsg borrows the live buffers above; no blocking wait is requested.
            let count = unsafe {
                libc::recvmsg(
                    self.stream.as_raw_fd(),
                    &raw mut message,
                    libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Err(error);
            }
            let mut ancillary = false;
            // SAFETY: the kernel initialized the control region and lengths.
            let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
            while !header.is_null() {
                ancillary = true;
                // SAFETY: header is a complete kernel-supplied ancillary record.
                let row = unsafe { &*header };
                if row.cmsg_level == libc::SOL_SOCKET && row.cmsg_type == libc::SCM_RIGHTS {
                    let base = unsafe { libc::CMSG_LEN(0) } as usize;
                    let count =
                        row.cmsg_len.saturating_sub(base) / std::mem::size_of::<libc::c_int>();
                    let descriptors = unsafe { libc::CMSG_DATA(header).cast::<libc::c_int>() };
                    for index in 0..count {
                        // SAFETY: each complete transferred descriptor is owned exactly once.
                        drop(unsafe { OwnedFd::from_raw_fd(*descriptors.add(index)) });
                    }
                }
                header = unsafe { libc::CMSG_NXTHDR(&message, header) };
            }
            if ancillary || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
                return Err(std::io::Error::other(
                    "retirement exchange forbids ancillary data",
                ));
            }
            if Instant::now() >= self.deadline {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            return Ok(count as usize);
        }
    }
}
impl Write for BoundedSocket<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            self.ready(libc::POLLOUT)?;
            // SAFETY: send borrows the valid payload; flags prohibit blocking and SIGPIPE.
            let count = unsafe {
                libc::send(
                    self.stream.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return Err(error);
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) fn send_until(
    stream: &UnixStream,
    frame: &Frame,
    deadline: Instant,
) -> Result<(), String> {
    crate::protocol::write_frame(&mut BoundedSocket { stream, deadline }, frame)
        .map_err(|error| error.to_string())
}
pub(super) fn receive_until(stream: &UnixStream, deadline: Instant) -> Result<Frame, String> {
    crate::protocol::read_frame_version(
        &mut BoundedSocket { stream, deadline },
        crate::protocol::MIXED_PROTOCOL_VERSION,
    )
    .map_err(|error| error.to_string())
}

pub(super) struct RetirementObservationChannel<'a> {
    stream: &'a UnixStream,
    nonce: [u8; 16],
    attempt: [u8; 16],
    pub(super) prepared: MixedPreparedObservationV2,
    pub(super) enrollment: MixedRetirementEnrollmentV1,
    pub(super) enrollment_sha256: memcordon_core::DiagnosticSha256,
    witness_sha256: Option<memcordon_core::DiagnosticSha256>,
    outcome: MixedRetirementOutcomeV1,
    observed: bool,
    window: Option<Result<(u64, u64, Instant), String>>,
}
impl<'a> RetirementObservationChannel<'a> {
    pub(super) fn enroll(
        stream: &'a UnixStream,
        request: &Frame,
        prepared: MixedPreparedObservationV2,
        prepared_bytes: &[u8],
        ack: &Frame,
        deadline: Instant,
    ) -> Result<Self, String> {
        let enrollment: MixedRetirementEnrollmentV1 = parse_retirement(&ack.payload)?;
        enrollment.observer.validate()?;
        if ack.kind != MessageKind::MixedPreparedRetirementAck
            || ack.nonce != request.nonce
            || ack.attempt_id != request.attempt_id
            || enrollment.format != "memcordon.mixed-retirement-enrollment"
            || enrollment.revision != 1
            || !enrollment.binding.matches(&prepared, prepared_bytes)
            || enrollment.observer.boot_identity.as_str() != boot_identity()?
            || super::clock::monotonic_millis()?
                >= enrollment.observer.observer_work_deadline_monotonic_millis
        {
            return Err("retirement enrollment association/cutoff differs".into());
        }
        let enrollment_sha256 = retirement_digest(&ack.payload);
        let receipt = MixedRetirementEnrolledV1 {
            format: "memcordon.mixed-retirement-enrolled".into(),
            revision: 1,
            binding: enrollment.binding.clone(),
            enrollment_sha256: enrollment_sha256.clone(),
            phase: MixedRetirementPhaseV1::Retiring,
        };
        send_until(
            stream,
            &Frame {
                kind: MessageKind::MixedRetirementEnrolled,
                nonce: request.nonce,
                attempt_id: request.attempt_id,
                payload: encode_retirement(&receipt)?,
            },
            deadline,
        )?;
        Ok(Self {
            stream,
            nonce: request.nonce,
            attempt: request.attempt_id,
            prepared,
            enrollment,
            enrollment_sha256,
            witness_sha256: None,
            outcome: failed(
                MixedRetirementFailureStageV1::IneligiblePhase,
                "native attempt did not reach an eligible retiring checkpoint",
            ),
            observed: false,
            window: None,
        })
    }
    pub(super) fn capture_window(&mut self, deadline: Instant) {
        self.window = Some((|| {
            let now = super::clock::monotonic_millis()?;
            let sampled = Instant::now();
            let remaining = u64::try_from(deadline.saturating_duration_since(sampled).as_millis())
                .map_err(|e| e.to_string())?;
            let cleanup = now
                .checked_add(remaining)
                .ok_or("retirement clock overflow")?;
            let observation = now
                .checked_add(remaining / 2)
                .ok_or("retirement clock overflow")?
                .min(
                    self.enrollment
                        .observer
                        .observer_work_deadline_monotonic_millis,
                )
                .min(
                    self.enrollment
                        .observer
                        .observer_cleanup_deadline_monotonic_millis,
                );
            Ok((
                cleanup,
                observation,
                local_cutoff(observation)?.min(deadline),
            ))
        })());
    }
    pub(super) fn observe(
        &mut self,
        owner: &super::private_lifecycle::PrivateAttemptOwner,
        admission: &super::mixed_admission::MixedOperationalAdmission,
        deadline: Instant,
    ) {
        if self.observed {
            self.outcome = failed(
                MixedRetirementFailureStageV1::AcknowledgementAssociation,
                "retirement observation repeated",
            );
            return;
        }
        self.observed = true;
        self.outcome = match self.observe_inner(owner, admission, deadline) {
            Ok(()) => MixedRetirementOutcomeV1::Acknowledged,
            Err((stage, detail)) => failed(stage, &detail),
        };
    }
    fn observe_inner(
        &mut self,
        owner: &super::private_lifecycle::PrivateAttemptOwner,
        admission: &super::mixed_admission::MixedOperationalAdmission,
        deadline: Instant,
    ) -> Result<(), (MixedRetirementFailureStageV1, String)> {
        use MixedRetirementFailureStageV1 as Stage;
        // Capture the existing allowance once. Hashing/publication consumes its
        // first-half scheduling slice; blocking I/O can overrun, never renew it.
        let (cleanup, observation, cutoff) = self
            .window
            .as_ref()
            .ok_or((
                Stage::ObservationDeadline,
                "original cleanup window absent".into(),
            ))?
            .clone()
            .map_err(|e| (Stage::ObservationDeadline, e))?;
        let cutoff = cutoff.min(deadline);
        if Instant::now() >= cutoff {
            return Err((
                Stage::ObservationDeadline,
                "retirement publication exhausted original observation slice".into(),
            ));
        }
        let (_held, journal, worker) = owner
            .retirement_observation_snapshot(&self.prepared, admission)
            .map_err(|e| (Stage::JournalSnapshot, e))?;
        if Instant::now() >= cutoff {
            return Err((
                Stage::ObservationDeadline,
                "retirement snapshot exhausted original observation slice".into(),
            ));
        }
        let witness = MixedRetirementObservationV1 {
            format: "memcordon.mixed-retirement-observation".into(),
            revision: 1,
            binding: self.enrollment.binding.clone(),
            enrollment_sha256: self.enrollment_sha256.clone(),
            boot_identity: self.enrollment.observer.boot_identity.clone(),
            caller: self.prepared.caller.clone(),
            target: self.prepared.target.clone(),
            namespace_init: self.prepared.namespace_init.clone(),
            guardian: self.prepared.guardian.clone(),
            worker,
            phase: MixedRetirementPhaseV1::Retiring,
            release_knowledge: MixedRetirementKnowledgeV1::ExecObserved,
            journal,
            cleanup_deadline_monotonic_millis: cleanup,
            observation_deadline_monotonic_millis: observation,
            authorizes_launch: false,
            retirement_completed: false,
        };
        witness
            .validate()
            .map_err(|e| (Stage::JournalSnapshot, e))?;
        let payload = encode_retirement(&witness).map_err(|e| (Stage::WitnessWrite, e))?;
        send_until(
            self.stream,
            &Frame {
                kind: MessageKind::MixedRetirementObservation,
                nonce: self.nonce,
                attempt_id: self.attempt,
                payload: payload.clone(),
            },
            cutoff,
        )
        .map_err(|e| (Stage::WitnessWrite, e))?;
        self.witness_sha256 = Some(retirement_digest(&payload));
        let frame =
            receive_until(self.stream, cutoff).map_err(|e| (Stage::AcknowledgementRead, e))?;
        let ack: MixedRetirementAcknowledgmentV1 =
            parse_retirement(&frame.payload).map_err(|e| (Stage::AcknowledgementAssociation, e))?;
        if frame.kind != MessageKind::MixedRetirementAck
            || frame.nonce != self.nonce
            || frame.attempt_id != self.attempt
            || ack.format != "memcordon.mixed-retirement-acknowledgment"
            || ack.revision != 1
            || ack.binding != self.enrollment.binding
            || ack.enrollment_sha256 != self.enrollment_sha256
            || Some(ack.witness_sha256) != self.witness_sha256
        {
            return Err((
                Stage::AcknowledgementAssociation,
                "retirement acknowledgement association differs".into(),
            ));
        }
        match ack.disposition {
            MixedRetirementDispositionV1::Completed => Ok(()),
            MixedRetirementDispositionV1::Aborted { detail } => {
                Err((Stage::ObserverAborted, detail.as_str().into()))
            }
        }
    }
    pub(super) fn finish(&self, deadline: Instant) -> Result<(), String> {
        let result = MixedRetirementObserverResultV1 {
            format: "memcordon.mixed-retirement-observer-result".into(),
            revision: 1,
            binding: self.enrollment.binding.clone(),
            enrollment_sha256: self.enrollment_sha256.clone(),
            witness_sha256: self.witness_sha256.clone(),
            outcome: self.outcome.clone(),
        };
        result.validate()?;
        send_until(
            self.stream,
            &Frame {
                kind: MessageKind::MixedRetirementObserverResult,
                nonce: self.nonce,
                attempt_id: self.attempt,
                payload: encode_retirement(&result)?,
            },
            deadline,
        )
    }
}
fn failed(stage: MixedRetirementFailureStageV1, detail: &str) -> MixedRetirementOutcomeV1 {
    MixedRetirementOutcomeV1::Failed {
        stage,
        detail: memcordon_core::BoundedText::new(detail).unwrap_or_else(|_| {
            memcordon_core::BoundedText::new("retirement observation failed; detail exceeds bound")
                .expect("fixed detail")
        }),
    }
}

/// Launcher custody for one enrolled exchange. It never invents an enrollment
/// receipt or native result, and forwards at most one completion/abort.
pub(super) struct RetirementRelay {
    enrollment: MixedRetirementEnrollmentV1,
    enrollment_sha256: memcordon_core::DiagnosticSha256,
    prepared: MixedPreparedObservationV2,
    accepted: bool,
    witness: Option<memcordon_core::DiagnosticSha256>,
    acknowledged: bool,
    result: bool,
    pub(super) deadline: Instant,
}
impl RetirementRelay {
    pub(super) fn enroll(prepared_frame: &Frame, ack: &Frame) -> Result<Self, String> {
        let prepared: MixedPreparedObservationV2 =
            serde_json::from_slice(&prepared_frame.payload).map_err(|e| e.to_string())?;
        prepared.validate()?;
        let enrollment: MixedRetirementEnrollmentV1 = parse_retirement(&ack.payload)?;
        enrollment.observer.validate()?;
        if enrollment.format != "memcordon.mixed-retirement-enrollment"
            || enrollment.revision != 1
            || !enrollment
                .binding
                .matches(&prepared, &prepared_frame.payload)
            || enrollment.observer.boot_identity.as_str() != boot_identity()?
        {
            return Err("launcher retirement enrollment association differs".into());
        }
        let deadline = local_cutoff(
            enrollment
                .observer
                .observer_cleanup_deadline_monotonic_millis,
        )?;
        Ok(Self {
            enrollment,
            enrollment_sha256: retirement_digest(&ack.payload),
            prepared,
            accepted: false,
            witness: None,
            acknowledged: false,
            result: false,
            deadline,
        })
    }
    pub(super) fn release_allowed(&self) -> bool {
        self.accepted
    }
    pub(super) fn forward(
        &mut self,
        frontend: &UnixStream,
        worker: &UnixStream,
        frame: &Frame,
    ) -> Result<bool, String> {
        match frame.kind {
            MessageKind::MixedRetirementEnrolled => {
                let receipt: MixedRetirementEnrolledV1 = parse_retirement(&frame.payload)?;
                if self.accepted
                    || receipt.format != "memcordon.mixed-retirement-enrolled"
                    || receipt.revision != 1
                    || receipt.binding != self.enrollment.binding
                    || receipt.enrollment_sha256 != self.enrollment_sha256
                {
                    return Err("launcher retirement acceptance association/order differs".into());
                }
                send_until(frontend, frame, self.deadline)?;
                self.accepted = true;
            }
            MessageKind::MixedRetirementObservation => {
                let witness: MixedRetirementObservationV1 = parse_retirement(&frame.payload)?;
                witness.validate()?;
                if !self.accepted
                    || self.witness.is_some()
                    || self.result
                    || witness.binding != self.enrollment.binding
                    || witness.enrollment_sha256 != self.enrollment_sha256
                    || witness.boot_identity != self.enrollment.observer.boot_identity
                    || witness.caller != self.prepared.caller
                    || witness.target != self.prepared.target
                    || witness.namespace_init != self.prepared.namespace_init
                    || witness.guardian != self.prepared.guardian
                    || witness.observation_deadline_monotonic_millis
                        > self
                            .enrollment
                            .observer
                            .observer_work_deadline_monotonic_millis
                    || witness.cleanup_deadline_monotonic_millis
                        > self
                            .enrollment
                            .observer
                            .observer_cleanup_deadline_monotonic_millis
                {
                    return Err("launcher retirement witness association/order differs".into());
                }
                self.deadline = self
                    .deadline
                    .min(local_cutoff(witness.cleanup_deadline_monotonic_millis)?);
                let cutoff = self
                    .deadline
                    .min(local_cutoff(witness.observation_deadline_monotonic_millis)?);
                let digest = retirement_digest(&frame.payload);
                self.witness = Some(digest.clone());
                if send_until(frontend, frame, cutoff).is_err() {
                    // No trustworthy frontend continuation remains. EOF releases
                    // the original worker into its already bounded cleanup.
                    let _ = worker.shutdown(std::net::Shutdown::Write);
                    return Ok(true);
                }
                let response = match receive_until(frontend, cutoff) {
                    Ok(response) => response,
                    Err(_) => {
                        // Never scan/resynchronize a partial or malformed frame.
                        let _ = worker.shutdown(std::net::Shutdown::Write);
                        return Ok(true);
                    }
                };
                let parsed = parse_retirement::<MixedRetirementAcknowledgmentV1>(&response.payload);
                let valid = parsed.as_ref().is_ok_and(|ack| {
                    response.kind == MessageKind::MixedRetirementAck
                        && response.nonce == frame.nonce
                        && response.attempt_id == frame.attempt_id
                        && ack.format == "memcordon.mixed-retirement-acknowledgment"
                        && ack.revision == 1
                        && ack.binding == self.enrollment.binding
                        && ack.enrollment_sha256 == self.enrollment_sha256
                        && ack.witness_sha256 == digest
                });
                if self.acknowledged {
                    return Err("launcher retirement acknowledgement repeated".into());
                }
                self.acknowledged = true;
                let forwarded = if valid {
                    response
                } else {
                    Frame {
                        kind: MessageKind::MixedRetirementAck,
                        nonce: frame.nonce,
                        attempt_id: frame.attempt_id,
                        payload: encode_retirement(&MixedRetirementAcknowledgmentV1 {
                            format: "memcordon.mixed-retirement-acknowledgment".into(),
                            revision: 1,
                            binding: self.enrollment.binding.clone(),
                            enrollment_sha256: self.enrollment_sha256.clone(),
                            witness_sha256: digest,
                            disposition: MixedRetirementDispositionV1::Aborted {
                                detail: memcordon_core::BoundedText::new(
                                    "frontend retirement acknowledgement association differs",
                                )
                                .expect("fixed detail"),
                            },
                        })?,
                    }
                };
                send_until(worker, &forwarded, cutoff)?;
            }
            MessageKind::MixedRetirementObserverResult => {
                let result: MixedRetirementObserverResultV1 = parse_retirement(&frame.payload)?;
                result.validate()?;
                if !self.accepted
                    || self.result
                    || result.format != "memcordon.mixed-retirement-observer-result"
                    || result.revision != 1
                    || result.binding != self.enrollment.binding
                    || result.enrollment_sha256 != self.enrollment_sha256
                    || result.witness_sha256 != self.witness
                    || (matches!(result.outcome, MixedRetirementOutcomeV1::Acknowledged)
                        && self.witness.is_none())
                {
                    return Err(
                        "launcher retirement observer result association/order differs".into(),
                    );
                }
                // Even a lost frontend cannot prevent draining this worker's
                // native terminal under the original cleanup cutoff.
                let _ = send_until(frontend, frame, self.deadline);
                self.result = true;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
