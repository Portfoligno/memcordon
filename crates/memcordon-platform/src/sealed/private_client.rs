//! Actual private invocation frontend. Saved plans and terminal documents are
//! diagnostic values; only the installed service authenticates and grants work.
use super::*;
use std::time::Instant;

const PRIVATE_LAUNCH_KIND: u16 = 10;
const PRIVATE_TERMINAL_KIND: u16 = 110;

enum PrivateFrontendFailure {
    Transport(String),
    Rejected(Box<memcordon_core::private_runtime::PrivateRuntimeRejection>),
}

impl From<String> for PrivateFrontendFailure {
    fn from(detail: String) -> Self {
        Self::Transport(detail)
    }
}

impl From<&str> for PrivateFrontendFailure {
    fn from(detail: &str) -> Self {
        Self::Transport(detail.into())
    }
}

impl std::fmt::Display for PrivateFrontendFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(detail) => formatter.write_str(detail),
            Self::Rejected(rejection) => formatter.write_str(rejection.detail.as_str()),
        }
    }
}

pub fn private_discovery()
-> Result<memcordon_core::workload_discovery_v2::PrivateWorkloadDiscovery, String> {
    verify_endpoint()?;
    let provider = super::super::linux_runtime::installed_binding()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    let mut stream = super::super::verification_exchange::DeadlineStream::new(
        &mut stream,
        super::super::verification_exchange::VERIFIED_EXCHANGE_BUDGET,
    )
    .map_err(|error| error.to_string())?;
    let challenge = nonce()?;
    write_frame(&mut stream, 13, challenge, [0; 16], &[])?;
    let response = read_frame(&mut stream)?;
    if response.kind != 112
        || response.nonce != challenge
        || response.attempt != [0; 16]
        || response.payload.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
    {
        return Err("private discovery frame differs from authenticated exchange".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&response.payload)?;
    let value: memcordon_core::workload_discovery_v2::PrivateWorkloadDiscovery =
        serde_json::from_slice(&response.payload).map_err(|error| error.to_string())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    if !value.validate()
        || value.provider != provider
        || value.boot_identity.as_str() != boot.trim()
    {
        return Err("private discovery actual provider/boot/catalogue differs".into());
    }
    super::super::linux_runtime::verify(&provider)?;
    Ok(value)
}

pub fn private_plan(
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
) -> Result<memcordon_core::private_runtime::PrivateRuntimePlan, String> {
    contract.validate()?;
    verify_endpoint()?;
    let provider = super::super::linux_runtime::installed_binding()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    let mut stream = super::super::verification_exchange::DeadlineStream::new(
        &mut stream,
        super::super::verification_exchange::VERIFIED_EXCHANGE_BUDGET,
    )
    .map_err(|error| error.to_string())?;
    let challenge = nonce()?;
    let bytes = serde_json::to_vec(contract).map_err(|error| error.to_string())?;
    if bytes.len() > memcordon_core::workload_limits::CONTRACT_BYTES {
        return Err("private plan request exceeds contract bound".into());
    }
    write_frame(&mut stream, 12, challenge, [0; 16], &bytes)?;
    let response = read_frame(&mut stream)?;
    if response.kind != 111 || response.nonce != challenge || response.attempt != [0; 16] {
        return Err("private plan response differs from authenticated exchange".into());
    }
    let value = memcordon_core::private_runtime::PrivateRuntimePlan::parse_bound(
        &response.payload,
        &provider,
        contract,
    )?;
    super::super::linux_runtime::verify(&provider)?;
    Ok(value)
}

pub struct PrivateFrontendExecution {
    pub terminal: memcordon_core::private_runtime::PrivateRuntimeTerminal,
    pub relay_drained: bool,
    pub interruption: Option<i32>,
    pub relay_error: Option<String>,
}

#[allow(
    clippy::result_large_err,
    reason = "the backend boundary preserves the public categorized Error contract"
)]
pub(crate) fn private_backend_run(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
    context: crate::supervisor::AttemptContext,
    signal: &crate::signal::SignalSource,
) -> Result<crate::backend::Execution, memcordon_core::Error> {
    use memcordon_core::result_v1::{CleanupStateV1, OutcomeKindV1};
    use memcordon_core::{
        BoundaryClass, BoundaryMechanismEvidence, BoundaryRequirement, Error, ErrorCategory,
        LaunchEvidence, RestartSafetyProof, RunOutcome,
    };
    let started = Instant::now();
    let monotonic_origin = monotonic_millis()
        .map_err(|detail| Error::new(ErrorCategory::Setup, "MCSEALED-PRIVATE-CLOCK", detail))?;
    let live = probe()
        .map_err(|detail| Error::new(ErrorCategory::Setup, "MCSEALED-PRIVATE-PROVIDER", detail))?;
    let receipt = private_run_at(policy, command, contract, context, started, || {
        signal.take()
    })
    .map_err(|failure| {
        let mut error = Error::new(
            ErrorCategory::Monitor,
            "MCSEALED-PRIVATE-TRANSACTION",
            failure.to_string(),
        );
        // Without an authenticated bound terminal, transfer/provider loss
        // cannot establish that no target was created or that it was retired.
        error.backend = Some("linux-private-tcp4".into());
        error.workload_may_be_alive = true;
        if let PrivateFrontendFailure::Rejected(rejection) = failure {
            error.category = ErrorCategory::Setup;
            error.code = "MCSEALED-PRIVATE-ADMISSION";
            error.workload_may_be_alive = false;
            error.private_rejection = Some(rejection);
        }
        error
    })?;
    let relay_error = receipt.relay_error;
    let private = memcordon_core::private_runtime::PrivateRuntimeExecution {
        terminal: receipt.terminal,
        frontend_relay_drained: receipt.relay_drained,
        frontend_interruption: receipt.interruption,
    };
    let terminal = &private.terminal;
    let complete = private.cleanup_state() == CleanupStateV1::Complete;
    let mut errors = Vec::new();
    if let Some(error) = &relay_error {
        errors.push(error.clone());
    }
    if let Some(error) = &terminal.error {
        errors.push(error.as_str().to_owned());
    }
    if !private.frontend_relay_drained {
        errors.push("frontend byte relay output was not drained".into());
    }
    let cleanup = private.cleanup_summary(relay_error.as_deref());
    let outcome = match terminal.outcome {
        OutcomeKindV1::Completed => RunOutcome::Exited {
            child: terminal.native_termination.clone().ok_or_else(|| {
                Error::new(
                    ErrorCategory::Monitor,
                    "MCSEALED-PRIVATE-STATUS",
                    "completed target native status absent",
                )
            })?,
            peak: None,
            cleanup,
        },
        OutcomeKindV1::ConfirmedMemoryLimit => RunOutcome::LimitExceeded {
            limit: policy.memory.ok_or_else(|| {
                Error::new(
                    ErrorCategory::Monitor,
                    "MCSEALED-PRIVATE-LIMIT",
                    "native memory event has no requested limit",
                )
            })?,
            observed: None,
            peak: None,
            evidence: memcordon_core::LimitEvidence {
                backend: "linux-tcp4-private-v1".into(),
                metric: "memory.events".into(),
                detail: "native cgroup oom_kill incremented".into(),
            },
            child_after_termination: terminal.native_termination.clone(),
            cleanup,
        },
        OutcomeKindV1::Deadline => {
            let configured = policy.deadline.ok_or_else(|| {
                Error::new(
                    ErrorCategory::Monitor,
                    "MCSEALED-PRIVATE-DEADLINE",
                    "native deadline event has no requested deadline",
                )
            })?;
            let budget_millis = effective_deadline_duration(policy, context, Duration::ZERO)
                .expect("configured deadline exists")
                .as_millis();
            let expires = if configured.scope() == memcordon_core::DeadlineScope::Attempt {
                let authorized = terminal
                    .authorization_monotonic_millis
                    .and_then(|absolute| absolute.checked_sub(monotonic_origin))
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCategory::Monitor,
                            "MCSEALED-PRIVATE-DEADLINE",
                            "attempt deadline lacks actual authorization clock association",
                        )
                    })?;
                u128::from(authorized)
                    .checked_add(budget_millis)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCategory::Monitor,
                            "MCSEALED-PRIVATE-DEADLINE",
                            "attempt deadline offset overflow",
                        )
                    })?
            } else {
                budget_millis
            };
            let observed = monotonic_millis()
                .map_err(|detail| {
                    Error::new(ErrorCategory::Monitor, "MCSEALED-PRIVATE-DEADLINE", detail)
                })?
                .checked_sub(monotonic_origin)
                .ok_or_else(|| {
                    Error::new(
                        ErrorCategory::Monitor,
                        "MCSEALED-PRIVATE-DEADLINE",
                        "native observation clock precedes frontend origin",
                    )
                })?;
            if u128::from(observed) < expires {
                return Err(Error::new(
                    ErrorCategory::Monitor,
                    "MCSEALED-PRIVATE-DEADLINE",
                    "native deadline outcome precedes its actual expiration",
                ));
            }
            let deadline = memcordon_core::DeadlineEvidence::new(
                u64::try_from(configured.duration().as_millis()).map_err(|_| {
                    Error::new(
                        ErrorCategory::Monitor,
                        "MCSEALED-PRIVATE-DEADLINE",
                        "configured deadline range differs",
                    )
                })?,
                configured.scope(),
                "provider-absolute-deadline".into(),
                u64::try_from(expires).map_err(|_| {
                    Error::new(
                        ErrorCategory::Monitor,
                        "MCSEALED-PRIVATE-DEADLINE",
                        "deadline offset range differs",
                    )
                })?,
                observed,
                0,
                0,
                None,
                None,
            )
            .map_err(|error| {
                Error::new(
                    ErrorCategory::Monitor,
                    "MCSEALED-PRIVATE-DEADLINE",
                    error.to_string(),
                )
            })?;
            RunOutcome::DeadlineExceeded {
                deadline,
                child_after_termination: terminal.native_termination.clone(),
                peak: None,
                cleanup,
            }
        }
        OutcomeKindV1::Interrupted if private.frontend_interruption.is_some() => {
            RunOutcome::Interrupted {
                signal: memcordon_core::Interruption {
                    signal: private
                        .frontend_interruption
                        .expect("observed native interruption"),
                },
                child_after_termination: terminal.native_termination.clone(),
                cleanup,
            }
        }
        _ => RunOutcome::MonitorFailed {
            error: terminal
                .error
                .as_ref()
                .map(|error| error.as_str().to_owned())
                .unwrap_or_else(|| format!("private native attempt ended {:?}", terminal.outcome)),
            child_after_termination: terminal.native_termination.clone(),
            cleanup,
        },
    };
    let released = terminal.authorization_offset_millis.is_some();
    let restart_safety = RestartSafetyProof {
        direct_child_reaped: complete,
        workload_empty: complete.then_some(true),
        helpers_reaped: complete,
        containment_removed: complete,
        containment_incapable_of_live_members: complete,
        sealed_boundary_retired: complete,
        errors,
    };
    let mut backend = crate::linux_cgroup::sealed_info(live);
    if let crate::backend::SealedAvailability::Available { capability, .. } =
        &mut backend.boundary_support.sealed
    {
        capability.mechanism = "linux-tcp4-private-v1".into();
    }
    Ok(crate::backend::Execution {
        private_execution: Some(private.clone()),
        policy_enforcement: Default::default(),
        outcome,
        backend,
        child_pid: terminal.target_pid,
        runtime: None,
        duration: started.elapsed(),
        authorization_offset: terminal
            .authorization_monotonic_millis
            .map(|at| {
                at.checked_sub(monotonic_origin)
                    .map(Duration::from_millis)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCategory::Monitor,
                            "MCSEALED-PRIVATE-CLOCK",
                            "release observation precedes frontend native invocation",
                        )
                    })
            })
            .transpose()?,
        launch: LaunchEvidence {
            mechanism: "linux-tcp4-private-v1".into(),
            target_released: released,
            containment_verified_before_authorization: released,
            guardian_started_before_authorization: released,
            target_spawn_error_reported: terminal.launch
                == memcordon_core::result_v1::LaunchStateV1::ExecFailed,
            boundary_requested: BoundaryRequirement::Sealed,
            boundary_effective: if released {
                BoundaryClass::Sealed
            } else {
                BoundaryClass::Unavailable
            },
            boundary_assignment_verified: released,
            boundary_reconfiguration_denied: released,
            inherited_resources_restricted: released,
            frontend_loss_cleanup_authority_verified: released,
        },
        restart_safety,
        boundary_detail: BoundaryMechanismEvidence::LinuxPrivateTcp4(Box::new(private)),
    })
}

fn private_run_at(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
    context: crate::supervisor::AttemptContext,
    started: Instant,
    mut interrupted: impl FnMut() -> Option<i32>,
) -> Result<PrivateFrontendExecution, PrivateFrontendFailure> {
    let deadline_budget = effective_deadline_duration(policy, context, Duration::ZERO);
    let attempt_scoped = policy
        .deadline
        .is_some_and(|deadline| deadline.scope() == memcordon_core::DeadlineScope::Attempt);
    let attempt_deadline_millis = if attempt_scoped {
        deadline_budget
            .map(|duration| {
                u64::try_from(duration.as_millis())
                    .map_err(|_| "private attempt deadline exceeds finite clock range")
            })
            .transpose()?
    } else {
        None
    };
    // The provider starts an Attempt timer once at real release. This outer
    // bound includes the fixed setup allowance without moving that timer.
    // A Supervision timer keeps its original absolute invocation deadline.
    let transport_budget = if attempt_scoped {
        deadline_budget
            .map(|duration| {
                duration
                    .checked_add(Duration::from_secs(30))
                    .ok_or("private setup plus attempt deadline overflow")
            })
            .transpose()?
    } else {
        deadline_budget
    };
    let deadline = transport_budget
        .map(|budget| {
            started
                .checked_add(budget)
                .ok_or("private invocation deadline is not representable")
        })
        .transpose()?;
    let cleanup_budget = policy.limit_grace.max(Duration::from_secs(5));
    let mut return_deadline = deadline
        .map(|end| {
            end.checked_add(cleanup_budget)
                .ok_or("private cleanup deadline is not representable")
        })
        .transpose()?;
    contract.validate()?;
    verify_endpoint()?;
    let provider = super::super::linux_runtime::installed_binding()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let attempt = nonce()?;
    let challenge = nonce()?;
    let native_launch = encode_launch(
        policy,
        command,
        if attempt_scoped {
            None
        } else {
            deadline.map(|end| end.saturating_duration_since(Instant::now()))
        },
        context.restart_attempt,
    )?;
    let invocation_sha256 =
        memcordon_core::DiagnosticSha256::from_bytes(Sha256::digest(&native_launch).into());
    let request = memcordon_core::private_runtime::PrivateRuntimeRequest {
        format: "memcordon.private-runtime-request".into(),
        revision: 1,
        contract: contract.clone(),
        native_launch,
        attempt_deadline_millis,
    };
    let payload = request.encode()?;
    let request_sha256 =
        memcordon_core::DiagnosticSha256::from_bytes(Sha256::digest(&payload).into());
    let frame = encoded_frame(PRIVATE_LAUNCH_KIND, challenge, attempt, &payload)?;
    let cwd = fs::File::open(".").map_err(|error| error.to_string())?;
    let frontend = pidfd_self()?;
    let (mut relay, channels) =
        super::private_relay::ByteRelay::new().map_err(|error| error.to_string())?;
    let descriptors = [
        cwd.as_raw_fd(),
        channels[0].as_raw_fd(),
        channels[1].as_raw_fd(),
        channels[2].as_raw_fd(),
        frontend.as_raw_fd(),
    ];
    send_nonblocking(&stream, &frame, &descriptors, deadline)?;
    // The local copies must close after the transfer: otherwise output EOF and
    // loss of frontend input could be falsely kept alive by this process.
    drop(channels);
    drop(cwd);
    let mut incoming = Incoming::new();
    let mut interruption = None;
    let mut cancel_pending = false;
    let mut relay_error = None;
    loop {
        if return_deadline.is_some_and(|end| Instant::now() >= end) {
            return Err("private frontend original deadline elapsed; provider retirement must be observed independently".into());
        }
        if deadline.is_some_and(|end| Instant::now() >= end) {
            relay.close_input();
        }
        if relay_error.is_none() {
            if let Err(error) = relay.step() {
                relay_error = Some(format!("private frontend byte relay: {error}"));
                let _ = relay.finish();
                cancel_pending = true;
                let cancelled_until = Instant::now()
                    .checked_add(cleanup_budget)
                    .ok_or("private relay cleanup deadline is not representable")?;
                return_deadline = Some(
                    return_deadline
                        .map_or(cancelled_until, |original| original.min(cancelled_until)),
                );
            }
        }
        if let Some(response) = incoming.read(&mut stream)? {
            if response.nonce != challenge || response.attempt != attempt {
                return Err("private terminal frame differs from actual invocation".into());
            }
            if response.kind == 106 {
                let rejected = parse_rejection(&response.payload)?;
                return Err(format!(
                    "private launch rejected [{}]: {}",
                    rejected.code, rejected.detail
                )
                .into());
            }
            if response.kind == 113 {
                let rejection =
                    memcordon_core::private_runtime::PrivateRuntimeRejection::parse_bound(
                        &response.payload,
                        &provider,
                        attempt,
                        &request_sha256,
                        contract,
                        &invocation_sha256,
                    )?;
                super::super::linux_runtime::verify(&provider)?;
                relay.finish().map_err(|error| error.to_string())?;
                return Err(PrivateFrontendFailure::Rejected(Box::new(rejection)));
            }
            if response.kind != PRIVATE_TERMINAL_KIND {
                return Err("private provider omitted named terminal".into());
            }
            let terminal = memcordon_core::private_runtime::PrivateRuntimeTerminal::parse_bound(
                &response.payload,
                &provider,
                attempt,
                &request_sha256,
                contract,
                &invocation_sha256,
            )?;
            super::super::linux_runtime::verify(&provider)?;
            relay.close_input();
            // Draining never renews the original budget. With no requested
            // deadline the explicit native setup/cleanup allowance is finite.
            let drain_until = return_deadline.unwrap_or_else(|| Instant::now() + cleanup_budget);
            while relay_error.is_none() && !relay.outputs_drained() && Instant::now() < drain_until
            {
                if let Err(error) = relay.step() {
                    relay_error = Some(format!("private output drain: {error}"));
                    break;
                }
                poll(&stream, &relay, Some(drain_until), false)?;
            }
            let drained = relay_error.is_none() && relay.outputs_drained();
            if let Err(error) = relay.finish() {
                relay_error = Some(format!("private stdio restoration: {error}"));
            }
            return Ok(PrivateFrontendExecution {
                terminal,
                relay_drained: drained && relay_error.is_none(),
                interruption,
                relay_error,
            });
        }
        if interruption.is_none() {
            if let Some(signal) = interrupted() {
                interruption = Some(signal);
                cancel_pending = true;
                relay.close_input();
                let cancelled_until = Instant::now()
                    .checked_add(cleanup_budget)
                    .ok_or("private cancellation cleanup deadline is not representable")?;
                return_deadline = Some(
                    return_deadline
                        .map_or(cancelled_until, |original| original.min(cancelled_until)),
                );
            }
        }
        if cancel_pending {
            let cancel = [1_u8];
            // SAFETY: one cancellation byte for this authenticated exchange;
            // no new request, descriptor, grant or native target operation.
            match unsafe {
                native_send(libc::send(
                    stream.as_raw_fd(),
                    cancel.as_ptr().cast(),
                    cancel.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                ))
            } {
                Ok(1) => cancel_pending = false,
                Ok(_) => return Err("private cancellation channel closed".into()),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(format!("private cancellation transport: {error}").into()),
            }
        }
        poll(&stream, &relay, return_deadline, true)?;
    }
}

fn poll(
    stream: &UnixStream,
    relay: &super::private_relay::ByteRelay,
    deadline: Option<Instant>,
    read_control: bool,
) -> Result<(), String> {
    let mut descriptors = Vec::with_capacity(4);
    if read_control {
        descriptors.push(libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    relay.poll_descriptors(&mut descriptors);
    let timeout = deadline.map_or(20, |end| {
        i32::try_from(
            end.saturating_duration_since(Instant::now())
                .as_millis()
                .min(20),
        )
        .unwrap_or(20)
    });
    // SAFETY: every polled descriptor is held by stream/relay and the vector is writable.
    let result = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            timeout,
        )
    };
    if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn send_nonblocking(
    stream: &UnixStream,
    frame: &[u8],
    descriptors: &[RawFd],
    deadline: Option<Instant>,
) -> Result<(), String> {
    let mut sent = 0;
    let send_until = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(5));
    while sent < frame.len() {
        if Instant::now() >= send_until {
            return Err("private request transfer deadline elapsed".into());
        }
        let result = if sent == 0 {
            let mut iovec = libc::iovec {
                iov_base: frame.as_ptr().cast_mut().cast(),
                iov_len: frame.len(),
            };
            // SAFETY: ABI size derives from the actual bounded descriptor array.
            let mut control = vec![
                0_u8;
                unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) }
                    as usize
            ];
            // SAFETY: zero is the initial empty msghdr before filling its buffers.
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &raw mut iovec;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = control.len();
            // SAFETY: the CMSG_SPACE-sized buffer holds this exact descriptor copy.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    descriptors.as_ptr(),
                    libc::CMSG_DATA(header).cast(),
                    descriptors.len(),
                );
                native_send(libc::sendmsg(
                    stream.as_raw_fd(),
                    &raw const message,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                ))
            }
        } else {
            // SAFETY: held stream and remaining immutable frame bytes remain valid.
            unsafe {
                native_send(libc::send(
                    stream.as_raw_fd(),
                    frame[sent..].as_ptr().cast(),
                    frame.len() - sent,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                ))
            }
        };
        match result {
            Ok(0) => return Err("private request transfer closed".into()),
            Ok(count) => sent += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                let mut descriptor = libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one held stream descriptor and one writable pollfd.
                unsafe {
                    libc::poll(&raw mut descriptor, 1, 10);
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn native_send(count: isize) -> std::io::Result<usize> {
    if count < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        usize::try_from(count).map_err(|_| std::io::Error::other("native transfer count overflow"))
    }
}

struct Incoming {
    bytes: Vec<u8>,
    total: Option<usize>,
}
impl Incoming {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(HEADER_LENGTH),
            total: None,
        }
    }
    fn read(&mut self, stream: &mut UnixStream) -> Result<Option<WireFrame>, String> {
        let wanted = self.total.unwrap_or(HEADER_LENGTH);
        let mut chunk = [0; 8192];
        let length = chunk.len().min(wanted - self.bytes.len());
        match stream.read(&mut chunk[..length]) {
            Ok(0) => return Err("private provider closed before complete terminal".into()),
            Ok(count) => self.bytes.extend_from_slice(&chunk[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.to_string()),
        }
        if self.total.is_none() && self.bytes.len() == HEADER_LENGTH {
            let total =
                u32::from_be_bytes(self.bytes[4..8].try_into().expect("fixed native header"))
                    as usize;
            if !(HEADER_LENGTH
                ..=HEADER_LENGTH + memcordon_core::workload_limits::CONTRACT_ENVELOPE_BYTES)
                .contains(&total)
            {
                return Err("private terminal frame exceeds finite bounds".into());
            }
            self.total = Some(total);
        }
        if self.total == Some(self.bytes.len()) {
            return read_frame(&mut self.bytes.as_slice()).map(Some);
        }
        Ok(None)
    }
}
