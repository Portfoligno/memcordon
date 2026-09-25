use std::io::{self, Read};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::protocol::{
    Frame, MessageKind, NETWORK_PROTOCOL_VERSION, PROTOCOL_VERSION, read_network_frame,
    write_frame, write_network_frame,
};
use crate::rejection::RejectionV1;

pub fn serve() -> Result<(), String> {
    super::startup::clear()?;
    crate::policy_registry::start_service_instance()?;
    configure_subreaper()?;
    let qualification = super::launcher::probe().map_err(|error| {
        record_startup_failure(super::startup::StartupPhase::Qualification, &error)
    })?;
    let listener = activated_listener().map_err(|error| {
        let error = format!("MCSEALED-SOCKET-ACTIVATION: {error}");
        record_startup_failure(super::startup::StartupPhase::SocketActivation, &error)
    })?;
    super::startup::clear()?;
    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                reap_workers();
                wait_for_connection(&listener)?;
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let worker = unsafe { libc::fork() };
        if worker == -1 {
            return Err(format!(
                "MCSEALED-PROVIDER-WORKER: {}",
                io::Error::last_os_error()
            ));
        }
        if worker == 0 {
            drop(listener);
            if let Err(error) = stream.set_nonblocking(false) {
                eprintln!("sealed provider worker could not configure stream: {error}");
                // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
                unsafe { libc::_exit(125) };
            }
            let code = match handle(&mut stream, &qualification) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("sealed provider rejected request: {error}");
                    125
                }
            };
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::_exit(code) };
        }
        drop(stream);
        reap_workers();
    }
}

/// Administrator entrypoint for the distinct host-qualification operation.
/// No response can be reported as successful until a trusted V4 host receipt
/// producer and verifier are wired to the protected run ledger.
pub(crate) fn request_private_host_qualification() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-PROBE: root administrator required".into());
    }
    let mut stream = UnixStream::connect(super::SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: control connection: {error}"))?;
    super::launcher::authenticate_control_service(&stream)?;
    let nonce = super::launcher::nonce()?;
    let attempt_id = super::launcher::nonce()?;
    if attempt_id == [0; 16] {
        return Err("MCSEALED-PRIVATE-PROBE: zero administrator attempt".into());
    }
    let request = Frame {
        kind: MessageKind::QualifyPrivateHost,
        nonce,
        attempt_id,
        payload: Vec::new(),
    };
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &request).map_err(|error| error.to_string())?;
    super::transport::send(&stream, &bytes, &[])?;
    let response = read_network_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.nonce != nonce || response.attempt_id != attempt_id {
        return Err("MCSEALED-PRIVATE-PROBE: control response binding differs".into());
    }
    let run_nonce = match response.kind {
        MessageKind::Rejected => {
            let rejection: RejectionV1 =
                serde_json::from_slice(&response.payload).map_err(|error| error.to_string())?;
            rejection.validate()?;
            return Err(format!("{}: {}", rejection.code, rejection.detail));
        }
        MessageKind::PrivateProbeRunCompleted
            if response.payload.len() == [0_u8; 32].len()
                && response.payload.iter().any(|byte| *byte != 0) =>
        {
            response.payload
        }
        _ => return Err("MCSEALED-PRIVATE-PROBE: control completion differs".into()),
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    let mut unexpected = [0_u8; 1];
    if stream
        .read(&mut unexpected)
        .map_err(|error| error.to_string())?
        != 0
    {
        return Err("MCSEALED-PRIVATE-PROBE: first coordinator remained open".into());
    }
    drop(stream);
    let mut final_stream = UnixStream::connect(super::SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: finalizer connection: {error}"))?;
    super::launcher::authenticate_control_service(&final_stream)?;
    let final_nonce = super::launcher::nonce()?;
    let final_attempt = super::launcher::nonce()?;
    let finalize = Frame {
        kind: MessageKind::FinalizePrivateHost,
        nonce: final_nonce,
        attempt_id: final_attempt,
        payload: run_nonce,
    };
    let mut encoded = Vec::new();
    write_network_frame(&mut encoded, &finalize).map_err(|error| error.to_string())?;
    super::transport::send(&final_stream, &encoded, &[])?;
    let finalized = read_network_frame(&mut final_stream).map_err(|error| error.to_string())?;
    if finalized.nonce != final_nonce || finalized.attempt_id != final_attempt {
        return Err("MCSEALED-PRIVATE-PROBE: finalizer response binding differs".into());
    }
    match finalized.kind {
        MessageKind::Rejected => {
            let rejection: RejectionV1 =
                serde_json::from_slice(&finalized.payload).map_err(|error| error.to_string())?;
            rejection.validate()?;
            Err(format!("{}: {}", rejection.code, rejection.detail))
        }
        _ => Err("MCSEALED-PRIVATE-PROBE: trusted H1 publication unavailable".into()),
    }
}

pub(crate) fn request_release_candidate_case(
    case: &super::private_release_case::ReleaseCaseRequestV1,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: root administrator required".into());
    }
    let mut stream = UnixStream::connect(super::SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: control connection: {error}"))?;
    super::launcher::authenticate_control_service(&stream)?;
    let nonce = super::launcher::nonce()?;
    let attempt_id = super::launcher::nonce()?;
    if attempt_id == [0; 16] {
        return Err("MCSEALED-PRIVATE-RELEASE: zero administrator attempt".into());
    }
    let request = Frame {
        kind: MessageKind::ReleaseCase,
        nonce,
        attempt_id,
        payload: super::private_release_run::encode_control_request(case)?,
    };
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &request).map_err(|error| error.to_string())?;
    super::transport::send(&stream, &bytes, &[])?;
    let response = read_network_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.nonce != nonce || response.attempt_id != attempt_id {
        return Err("MCSEALED-PRIVATE-RELEASE: control response binding differs".into());
    }
    match response.kind {
        MessageKind::ReleaseCaseIncomplete if response.payload.is_empty() => {}
        MessageKind::Rejected => {
            let rejection: RejectionV1 =
                serde_json::from_slice(&response.payload).map_err(|error| error.to_string())?;
            rejection.validate()?;
            return Err(format!("{}: {}", rejection.code, rejection.detail));
        }
        _ => return Err("MCSEALED-PRIVATE-RELEASE: control completion unavailable".into()),
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    let mut unexpected = [0_u8; 1];
    if stream
        .read(&mut unexpected)
        .map_err(|error| error.to_string())?
        != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: first coordinator remained open".into());
    }
    drop(stream);
    let mut final_stream = UnixStream::connect(super::SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: finalizer connection: {error}"))?;
    super::launcher::authenticate_control_service(&final_stream)?;
    let final_nonce = super::launcher::nonce()?;
    let final_attempt = super::launcher::nonce()?;
    let finalize = Frame {
        kind: MessageKind::FinalizeReleaseCase,
        nonce: final_nonce,
        attempt_id: final_attempt,
        payload: super::private_release_run::encode_control_request(case)?,
    };
    let mut encoded = Vec::new();
    write_network_frame(&mut encoded, &finalize).map_err(|error| error.to_string())?;
    super::transport::send(&final_stream, &encoded, &[])?;
    let finalized = read_network_frame(&mut final_stream).map_err(|error| error.to_string())?;
    if finalized.nonce != final_nonce || finalized.attempt_id != final_attempt {
        return Err("MCSEALED-PRIVATE-RELEASE: finalizer response binding differs".into());
    }
    match finalized.kind {
        MessageKind::ReleaseCaseCompleted if finalized.payload.is_empty() => Ok(()),
        MessageKind::ReleaseCaseIncomplete if finalized.payload.is_empty() => Err(
            "MCSEALED-PRIVATE-RELEASE: detached finalizer reported incomplete; no completed result was acknowledged"
                .into(),
        ),
        MessageKind::Rejected => {
            let rejection: RejectionV1 =
                serde_json::from_slice(&finalized.payload).map_err(|error| error.to_string())?;
            rejection.validate()?;
            Err(format!("{}: {}", rejection.code, rejection.detail))
        }
        _ => Err("MCSEALED-PRIVATE-RELEASE: finalizer completion unavailable".into()),
    }
}

fn configure_subreaper() -> Result<(), String> {
    // SAFETY: prctl receives the documented scalar PR_SET_CHILD_SUBREAPER arguments.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(format!(
            "MCSEALED-PROVIDER-SUBREAPER: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn record_startup_failure(phase: super::startup::StartupPhase, error: &str) -> String {
    match super::startup::record(phase, error) {
        Ok(()) => error.to_owned(),
        Err(record_error) => format!("{error}; {record_error}"),
    }
}

fn reap_workers() {
    loop {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if result <= 0 {
            break;
        }
    }
}

fn wait_for_connection(listener: &UnixListener) -> Result<(), String> {
    let mut pollfd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let status = unsafe { libc::poll(&raw mut pollfd, 1, 1_000) };
    if status == -1 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.to_string());
        }
    }
    Ok(())
}

fn activated_listener() -> Result<UnixListener, String> {
    const SYSTEMD_LISTEN_FD: RawFd = 3;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    Ok(listener)
}

fn handle(
    stream: &mut UnixStream,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<(), String> {
    let credentials = peer_credentials(stream)?;
    if credentials.uid == u32::MAX {
        return Err("MCSEALED-PIPE-AUTH: invalid peer credentials".to_owned());
    }
    let groups = peer_groups(credentials.pid)?;
    authorize_peer(credentials, &groups)?;
    let (request, descriptors, version) = super::transport::receive_public(stream)?;
    let response = match (version, request.kind) {
        (PROTOCOL_VERSION, MessageKind::Probe) => {
            probe_response(&request, descriptors.len(), qualification)?
        }
        (PROTOCOL_VERSION, MessageKind::WorkloadDiscovery) => workload_discovery_response(
            &request,
            descriptors.len(),
            credentials.uid,
            qualification,
        )?,
        (PROTOCOL_VERSION, MessageKind::WorkloadPlan) => {
            workload_plan_response(&request, descriptors.len(), credentials.uid, qualification)?
        }
        (PROTOCOL_VERSION, MessageKind::Launch) => {
            match launch_response(request.clone(), descriptors, credentials, groups) {
                Ok(response) => response,
                Err(rejection) => {
                    journal_rejection(request.attempt_id, &rejection);
                    rejected(&request, &rejection)?
                }
            }
        }
        (NETWORK_PROTOCOL_VERSION, MessageKind::ReleaseCase) => {
            if credentials.uid != 0 || !descriptors.is_empty() || request.attempt_id == [0; 16] {
                rejected_text(
                    &request,
                    "MCSEALED-PRIVATE-RELEASE-AUTHORIZATION",
                    "root-only release case requires no descriptors and a live attempt",
                )?
            } else {
                let fixed = super::private_release_run::decode_broker_request(&request.payload)?;
                let prepared =
                    super::private_release_run::ReleaseCandidateRunAuthorityV1::prepare_control(
                        fixed,
                    )?;
                super::launcher::execute_release_candidate_case(&request, &prepared)?
            }
        }
        (NETWORK_PROTOCOL_VERSION, MessageKind::FinalizeReleaseCase) => {
            if credentials.uid != 0 || !descriptors.is_empty() || request.attempt_id == [0; 16] {
                rejected_text(
                    &request,
                    "MCSEALED-PRIVATE-RELEASE-FINALIZER-AUTHORIZATION",
                    "root-only release finalizer requires no descriptors and a live attempt",
                )?
            } else {
                let fixed = super::private_release_run::decode_broker_request(&request.payload)?;
                if fixed.selector == super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR {
                    let readback =
                        super::private_release_run::verify_detached_uncertain_candidate_case(
                            &fixed,
                        )?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_uncertain_detached(
                        readback,
                    )?
                    .publish()?;
                } else if fixed.selector == super::private_release_case::RETIREMENT_FAULT_SELECTOR {
                    let readback =
                        super::private_release_run::verify_detached_blocked_retirement_case(
                            &fixed,
                        )?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_blocked_retirement_detached(
                        readback,
                    )?
                    .publish()?;
                } else if fixed.selector == super::private_release_guardian_loss::SELECTOR {
                    let readback =
                        super::private_release_run::verify_detached_guardian_loss_case(&fixed)?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_guardian_loss_detached(
                        readback,
                    )?
                    .publish()?;
                } else if fixed.selector == super::private_release_frontend_loss::SELECTOR {
                    let readback =
                        super::private_release_run::verify_detached_frontend_loss_case(&fixed)?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_frontend_loss_detached(
                        readback,
                    )?
                    .publish()?;
                } else if fixed.selector == super::private_release_case::CHECKPOINT_GATE_SELECTOR {
                    let readback =
                        super::private_release_run::verify_detached_checkpoint_gate_case(&fixed)?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_checkpoint_gate_detached(
                        readback,
                    )?
                    .publish()?;
                } else if fixed.selector == super::private_release_children::SELECTOR {
                    let readback = super::private_release_run::verify_detached_child_case(&fixed)?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_child_detached(
                        readback,
                    )?
                    .publish()?;
                } else if fixed.selector == super::private_release_socket_launder::SELECTOR {
                    let readback = super::private_release_run::verify_detached_socket_case(&fixed)?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_socket_detached(
                        readback,
                    )?
                    .publish()?;
                } else if fixed.selector == super::private_release_terminal_join::SELECTOR {
                    let readback =
                        super::private_release_run::verify_detached_terminal_join_case(&fixed)?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_terminal_join_detached(
                        readback,
                    )?
                    .publish()?;
                } else if fixed.selector == super::private_release_dual_attempt::SELECTOR {
                    let readback =
                        super::private_release_run::verify_detached_dual_candidate_case(&fixed)?;
                    super::private_release_result::VerifiedDualCandidateCaseCompletion::from_detached(
                        readback,
                    )?
                    .publish()?;
                } else {
                    let readback =
                        super::private_release_run::verify_detached_candidate_case(&fixed)?;
                    super::private_release_result::VerifiedCandidateCaseCompletion::from_detached(
                        readback,
                    )?
                    .publish()?;
                }
                Frame {
                    kind: MessageKind::ReleaseCaseCompleted,
                    nonce: request.nonce,
                    attempt_id: request.attempt_id,
                    payload: Vec::new(),
                }
            }
        }
        (NETWORK_PROTOCOL_VERSION, MessageKind::PrivatePlan) => {
            private_plan_response(&request, descriptors.len(), credentials.uid)?
        }
        (NETWORK_PROTOCOL_VERSION, MessageKind::PrivateLaunch) => {
            match launch_private_response(request.clone(), descriptors, credentials, groups) {
                Ok(response) => response,
                Err(PrivateLaunchFailure::PreAdmission(rejection)) => {
                    journal_rejection(request.attempt_id, &rejection);
                    rejected(&request, &rejection)?
                }
                Err(PrivateLaunchFailure::AfterBroker(error)) => {
                    eprintln!("sealed private terminal indeterminate: {error}");
                    private_indeterminate_response(&request)?
                }
            }
        }
        (NETWORK_PROTOCOL_VERSION, MessageKind::QualifyPrivateHost) => {
            if credentials.uid != 0
                || !descriptors.is_empty()
                || !request.payload.is_empty()
                || request.attempt_id == [0; 16]
            {
                rejected_text(
                    &request,
                    "MCSEALED-PRIVATE-PROBE-AUTHORIZATION",
                    "root-only qualification requires no public descriptors or payload",
                )?
            } else {
                let prepared = super::private_qualification::prepare_control_run()?;
                super::launcher::qualify_private_host(&request, &prepared)?
            }
        }
        (NETWORK_PROTOCOL_VERSION, MessageKind::FinalizePrivateHost) => {
            if credentials.uid != 0
                || !descriptors.is_empty()
                || request.payload.len() != [0_u8; 32].len()
                || request.payload.iter().all(|byte| *byte == 0)
                || request.attempt_id == [0; 16]
            {
                rejected_text(
                    &request,
                    "MCSEALED-PRIVATE-PROBE-FINALIZE-AUTHORIZATION",
                    "root-only finalization requires one fixed run selector and no descriptors",
                )?
            } else {
                let mut run_nonce = [0_u8; 32];
                run_nonce.copy_from_slice(&request.payload);
                match super::private_host_receipt::verify_detached_candidate(&run_nonce) {
                    Ok(_candidate) => rejected_text(
                        &request,
                        "MCSEALED-PRIVATE-RELEASE-Q-UNVERIFIED",
                        "detached native host run verified, but independent release Q provenance is unavailable",
                    )?,
                    Err(error) => {
                        rejected_text(&request, "MCSEALED-PRIVATE-PROBE-FINALIZE-REJECTED", &error)?
                    }
                }
            }
        }
        _ => rejected_text(
            &request,
            "MCSEALED-AUTHORIZATION",
            "MCSEALED-AUTHORIZATION: launch protocol requires the native descriptor transaction",
        )?,
    };
    if version == NETWORK_PROTOCOL_VERSION {
        write_network_frame(stream, &response).map_err(|error| error.to_string())
    } else {
        write_frame(stream, &response).map_err(|error| error.to_string())
    }
}

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateIndeterminateV11<'a> {
    schema_version: u32,
    attempt_id: String,
    release_knowledge: &'a str,
    retirement_knowledge: &'a str,
    replay_disposition: &'a str,
    reason_code: &'a str,
}

/// This is a failure envelope, never a V11 execution report. In particular,
/// transport loss or terminal-verification failure cannot establish whether
/// the release byte was sent, whether the target ran, or whether cleanup held.
pub(crate) fn private_indeterminate_response(request: &Frame) -> Result<Frame, String> {
    if request.kind != MessageKind::PrivateLaunch {
        return Err("MCSEALED-PRIVATE-INDETERMINATE: request kind differs".into());
    }
    let envelope = PrivateIndeterminateV11 {
        schema_version: 11,
        attempt_id: request
            .attempt_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        release_knowledge: "possibly-released",
        retirement_knowledge: "unverified",
        replay_disposition: "do-not-replay",
        reason_code: "MCSEALED-PRIVATE-TERMINAL-UNVERIFIED",
    };
    Ok(Frame {
        kind: MessageKind::PrivateIndeterminate,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&envelope).map_err(|error| error.to_string())?,
    })
}

fn workload_discovery_response(
    request: &Frame,
    descriptor_count: usize,
    uid: u32,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<Frame, String> {
    if descriptor_count != 0 || request.attempt_id != [0; 16] || !request.payload.is_empty() {
        return Err("workload discovery must not carry resources or an attempt".into());
    }
    let lease = crate::policy_registry::native::Lease::acquire()?;
    let activation = lease.read()?;
    let qualification_digest = memcordon_core::DiagnosticSha256::try_from(
        memcordon_core::BoundedText::new(&qualification.receipt_digest).map_err(str::to_owned)?,
    )
    .map_err(str::to_owned)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    let discovery = memcordon_core::workload_discovery::WorkloadDiscoveryV1::authenticated(
        activation
            .as_ref()
            .map(|activation| (&activation.registry, &activation.epoch)),
        &memcordon_core::workload_registry::CallerSelector::Linux { uid },
        memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate,
        qualification_digest,
        super::runtime_manifest::installed_binding()?,
        memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
    )?;
    Ok(Frame {
        kind: MessageKind::WorkloadDiscoveryReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&discovery).map_err(|error| error.to_string())?,
    })
}

fn workload_plan_response(
    request: &Frame,
    descriptor_count: usize,
    uid: u32,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<Frame, String> {
    use memcordon_core::workload_evidence::*;
    use memcordon_core::workload_registry::*;
    if descriptor_count != 0 || request.attempt_id != [0; 16] {
        return Err("workload plan must not allocate an attempt or carry descriptors".into());
    }
    let contract = match memcordon_core::workload_contract::WorkloadContract::parse(
        &request.payload,
    )? {
        memcordon_core::workload_contract::WorkloadContract::V1(contract) => contract,
        memcordon_core::workload_contract::WorkloadContract::V2(contract) => {
            let rejection = crate::admission::plan_linux_v2_rejection(&contract, uid);
            return rejected_text(
                request,
                "MCSEALED-WORKLOAD-V2-UNAVAILABLE",
                &format!(
                    "MCSEALED-WORKLOAD-V2-UNAVAILABLE: {:?}; native V4 qualification is not installed",
                    rejection.code
                ),
            );
        }
    };
    let binding = RequestBindingV1::from_contract(&contract)?;
    let result = (|| -> Result<WorkloadResolutionReportV1, String> {
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let activation = lease.read()?.ok_or("policy activation absent")?;
        let qualification_digest = memcordon_core::DiagnosticSha256::try_from(
            memcordon_core::BoundedText::new(&qualification.receipt_digest)
                .map_err(str::to_owned)?,
        )
        .map_err(str::to_owned)?;
        if let Err(rejection) = resolve(
            &activation.registry,
            &activation.epoch,
            &contract,
            &CallerSelector::Linux { uid },
            BaselineProfile::LinuxUnixCreate,
            &qualification_digest,
        ) {
            return Ok(WorkloadResolutionReportV1::Rejected {
                binding: binding.clone(),
                rejection,
                target_authorized: False::default(),
            });
        }
        let provider = super::runtime_manifest::installed_binding()?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?;
        let plan = PlanBindingV1::from_authorized(
            &contract,
            activation.registry_digest,
            qualification_digest,
            provider,
            memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
        )?;
        let mut pending = memcordon_core::BoundedVec::default();
        for check in [
            PrelaunchCheck::CallerIdentity,
            PrelaunchCheck::InvocationIdentity,
            PrelaunchCheck::DescriptorCustody,
            PrelaunchCheck::NativeControls,
            PrelaunchCheck::Guardian,
            PrelaunchCheck::CurrentEpoch,
            PrelaunchCheck::DurableCheckpoint,
        ] {
            pending
                .try_push(check)
                .expect("fixed prelaunch check inventory fits");
        }
        Ok(WorkloadResolutionReportV1::Planned { binding: plan, effective: EffectiveWorkloadPolicyV1 {
            profile: BaselineProfile::LinuxUnixCreate, ceiling: BaselineProfile::LinuxUnixCreate.ceiling(),
            restriction: BaselineRestrictionObservationV1::LinuxUnixOnlySocketSyscallFilterAlternatePathsUnknown,
        }, pending })
    })();
    let response = result.unwrap_or(WorkloadResolutionReportV1::Unavailable {
        request: Some(binding),
        reason: AdmissionAvailabilityFailure::BindingUnavailable,
        authorization: AuthorizationKnowledge::NotAuthorized,
    });
    Ok(Frame {
        kind: MessageKind::WorkloadPlanReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&response).map_err(|error| error.to_string())?,
    })
}

/// V2 planning is a non-allocating snapshot of the actual current installed
/// generation and policy grant. A later launch repeats admission; neither
/// this receipt nor a release-case selector can authorize target release.
fn private_plan_response(
    request: &Frame,
    descriptor_count: usize,
    uid: u32,
) -> Result<Frame, String> {
    use memcordon_core::workload_contract::WorkloadContract;
    use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
    use memcordon_core::workload_registry::CallerSelector;
    use memcordon_core::workload_registry_v2::{ProfileKindV2, resolve_v2};

    if descriptor_count != 0 || request.attempt_id != [0; 16] || request.nonce == [0; 16] {
        return rejected_text(
            request,
            "MCSEALED-PRIVATE-PLAN-FRAME",
            "V2 plan requires no descriptors, no attempt and a nonzero nonce",
        );
    }
    let contract = match WorkloadContract::parse(&request.payload) {
        Ok(WorkloadContract::V2(contract)) => contract,
        Ok(WorkloadContract::V1(_)) => {
            return rejected_text(
                request,
                "MCSEALED-PRIVATE-PLAN-VERSION",
                "private plan requires an exact V2 contract",
            );
        }
        Err(error) => {
            return rejected_text(request, "MCSEALED-PRIVATE-PLAN-DECODE", &error);
        }
    };
    let installed = match crate::package::acquire_verified_private_qualification_lease() {
        Ok(installed) => installed,
        Err(error) => {
            return rejected_text(
                request,
                "MCSEALED-PRIVATE-QUALIFICATION-UNAVAILABLE",
                &error,
            );
        }
    };
    let policy = match crate::policy_registry::native::Lease::acquire() {
        Ok(policy) => policy,
        Err(error) => {
            return rejected_text(request, "MCSEALED-PRIVATE-POLICY-UNAVAILABLE", &error);
        }
    };
    let activation = match policy.read_v2() {
        Ok(Some(activation)) => activation,
        Ok(None) => {
            return rejected_text(
                request,
                "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED",
                "active V2 grant registry absent",
            );
        }
        Err(error) => {
            return rejected_text(request, "MCSEALED-PRIVATE-POLICY-UNAVAILABLE", &error);
        }
    };
    if let Err(rejection) = resolve_v2(
        &activation.registry,
        &activation.epoch,
        &contract,
        &CallerSelector::Linux { uid },
        ProfileKindV2::LinuxTcp4PrivateV1,
        installed.qualification_digest(),
    ) {
        return rejected_text(
            request,
            "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED",
            &format!("current public V2 grant rejected: {:?}", rejection.code),
        );
    }
    let native_abi = match installed.filter_abi() {
        super::network_filter::NativeAbi::X86_64 => QualifiedNativeAbiV2::X86_64LinuxGnu,
        super::network_filter::NativeAbi::Aarch64 => QualifiedNativeAbiV2::Aarch64LinuxGnu,
    };
    let receipt = memcordon_core::workload_plan_v2::PrivatePlanReceiptV2 {
        schema_version: 2,
        contract_digest: memcordon_core::workload_codec::contract_digest_v2(&contract)?,
        registry_digest: activation.registry_digest,
        installed_qualification_sha256: installed.qualification_digest().clone(),
        runtime_manifest_sha256: installed.runtime_manifest_sha256().clone(),
        generation_digest: installed.generation_digest().clone(),
        source_commit: installed.source_commit().to_owned(),
        native_abi,
    };
    receipt.validate_for_contract(&contract)?;
    Ok(Frame {
        kind: MessageKind::PrivatePlanReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&receipt).map_err(|error| error.to_string())?,
    })
}

#[cfg(feature = "test-support")]
pub(crate) fn private_plan_response_for_test(
    request: &Frame,
    descriptor_count: usize,
    uid: libc::uid_t,
) -> Result<Frame, String> {
    private_plan_response(request, descriptor_count, uid)
}

fn probe_response(
    request: &Frame,
    descriptor_count: usize,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<Frame, String> {
    if descriptor_count != 0 {
        return rejected_text(
            request,
            "MCSEALED-PROVIDER-REJECTION",
            "MCSEALED-PROVIDER-REJECTION: probe must not carry descriptors",
        );
    }
    Ok(Frame {
        kind: MessageKind::ProbeReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: qualification.render().into_bytes(),
    })
}

#[cfg(feature = "test-support")]
pub fn cached_probe_response_for_test(
    request: &Frame,
    descriptor_count: usize,
    qualification: &super::qualification::QualificationReceipt,
) -> Frame {
    probe_response(request, descriptor_count, qualification)
        .expect("fixed probe rejection must fit the bounded protocol")
}

fn launch_response(
    request: Frame,
    descriptors: Vec<std::os::fd::OwnedFd>,
    credentials: PeerCredentials,
    groups: Vec<libc::gid_t>,
) -> Result<Frame, RejectionV1> {
    let _launch_lease = acquire_shared_package_lease()
        .map_err(|error| RejectionV1::request_error("MCSEALED-PACKAGE-LEASE", &error))?;
    let launch = crate::request::decode_launch_request(&request.payload).map_err(|error| {
        RejectionV1::request_error(
            "MCSEALED-LAUNCH-DECODE",
            &format!("invalid launch request: {error:?}"),
        )
    })?;
    if descriptors.len() != 5 {
        return Err(RejectionV1::request_error(
            "MCSEALED-LAUNCH-DESCRIPTOR-SET",
            "exact public descriptor inventory required",
        ));
    }
    if peer_inside_active_attempt(credentials.pid).map_err(|error| {
        RejectionV1::request_error("MCSEALED-RECURSIVE-PROVIDER-REQUEST", &error)
    })? {
        return Err(RejectionV1::request_error(
            "MCSEALED-RECURSIVE-PROVIDER-REQUEST",
            "caller is already inside an active sealed attempt",
        ));
    }
    let captured = super::envelope::capture(
        credentials.pid,
        credentials.uid,
        credentials.gid,
        &groups,
        descriptors[0].as_fd(),
    )
    .map_err(|error| RejectionV1::request_error("MCSEALED-CALLER-ENVELOPE-CAPTURE", &error))?;
    // SAFETY: getpid returns this single request worker's positive process id.
    let control_process_id = unsafe { libc::getpid() };
    let control_process_start_time = super::envelope::process_start_time(control_process_id)
        .map_err(|error| {
            RejectionV1::request_error("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION", &error)
        })?;
    let request_digest: [u8; 32] = Sha256::digest(&request.payload).into();
    let broker = crate::request::LaunchBrokerRequestV2::authenticated(
        request.attempt_id,
        request_digest,
        control_process_id,
        control_process_start_time,
        launch,
        captured.envelope,
        super::launcher::broker_descriptor_manifest(),
    )
    .map_err(|error| {
        RejectionV1::request_error(
            "MCSEALED-LAUNCHER-REQUEST-BINDING",
            &format!("could not bind broker request: {error:?}"),
        )
    })?;
    let record_identity = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let _durable_record = super::attempt::AttemptRecord::create_v2(
        record_identity,
        credentials.pid,
        broker.caller.digest_hex(),
    )
    .map_err(|error| RejectionV1::request_error("MCSEALED-RECORD-ALLOCATE", &error))?;
    let descriptor_fds = descriptors
        .iter()
        .map(AsRawFd::as_raw_fd)
        .chain([
            captured.mount_namespace.as_raw_fd(),
            captured.root.as_raw_fd(),
        ])
        .collect::<Vec<_>>();
    super::launcher::launch(&request, &broker, &descriptor_fds).map_err(|error| {
        RejectionV1::request_error("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION", &error)
    })
}

enum PrivateLaunchFailure {
    PreAdmission(RejectionV1),
    AfterBroker(String),
}

impl From<RejectionV1> for PrivateLaunchFailure {
    fn from(rejection: RejectionV1) -> Self {
        Self::PreAdmission(rejection)
    }
}

/// V4 public requests use the native private broker's durable attempt owner.
/// The control worker retains its own installed-generation lease until the
/// authenticated broker terminal has been checked and projected.
fn launch_private_response(
    request: Frame,
    descriptors: Vec<std::os::fd::OwnedFd>,
    credentials: PeerCredentials,
    groups: Vec<libc::gid_t>,
) -> Result<Frame, PrivateLaunchFailure> {
    let installed = crate::package::acquire_verified_private_qualification_lease()
        .map_err(|error| RejectionV1::request_error("MCSEALED-PRIVATE-QUALIFICATION", &error))?;
    let launch =
        crate::request::decode_network_launch_request(&request.payload).map_err(|error| {
            RejectionV1::request_error(
                "MCSEALED-PRIVATE-LAUNCH-DECODE",
                &format!("invalid private launch request: {error:?}"),
            )
        })?;
    if launch.qualification_digest != *installed.qualification_digest() {
        return Err(RejectionV1::request_error(
            "MCSEALED-PRIVATE-QUALIFICATION",
            "private request names a different installed qualification",
        )
        .into());
    }
    if descriptors.len() != 5 || request.attempt_id == [0; 16] {
        return Err(RejectionV1::request_error(
            "MCSEALED-PRIVATE-DESCRIPTOR-SET",
            "exact five public descriptors and a nonzero attempt are required",
        )
        .into());
    }
    if peer_inside_active_attempt(credentials.pid).map_err(|error| {
        RejectionV1::request_error("MCSEALED-RECURSIVE-PROVIDER-REQUEST", &error)
    })? {
        return Err(RejectionV1::request_error(
            "MCSEALED-RECURSIVE-PROVIDER-REQUEST",
            "caller is already inside an active sealed attempt",
        )
        .into());
    }
    let captured = super::envelope::capture(
        credentials.pid,
        credentials.uid,
        credentials.gid,
        &groups,
        descriptors[0].as_fd(),
    )
    .map_err(|error| RejectionV1::request_error("MCSEALED-CALLER-ENVELOPE-CAPTURE", &error))?;
    // SAFETY: getpid returns this request worker's positive process id.
    let control_process_id = unsafe { libc::getpid() };
    let control_process_start_time = super::envelope::process_start_time(control_process_id)
        .map_err(|error| {
            RejectionV1::request_error("MCSEALED-NETWORK-LAUNCHER-AUTHENTICATION", &error)
        })?;
    let broker = crate::request::NetworkLaunchBrokerRequestV4::authenticated(
        request.attempt_id,
        installed.generation_digest().clone(),
        control_process_id,
        control_process_start_time,
        launch,
        captured.envelope,
    )
    .map_err(|error| {
        RejectionV1::request_error(
            "MCSEALED-PRIVATE-REQUEST-BINDING",
            &format!("could not bind private broker request: {error:?}"),
        )
    })?;
    // The V4 broker transport retains an eighth ELF-purpose slot. The broker
    // discards it before independently pinning the granted target executable.
    let compatibility_image = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/libexec/memcordon-sealed-agent")
        .map_err(|error| {
            RejectionV1::request_error("MCSEALED-PRIVATE-IMAGE-READBACK", &error.to_string())
        })?;
    let descriptor_fds = descriptors
        .iter()
        .map(AsRawFd::as_raw_fd)
        .chain([
            captured.mount_namespace.as_raw_fd(),
            captured.root.as_raw_fd(),
            compatibility_image.as_raw_fd(),
        ])
        .collect::<Vec<_>>();
    let response = super::launcher::launch_network(&request, &broker, &descriptor_fds)
        .map_err(PrivateLaunchFailure::AfterBroker)?;
    if response.kind == MessageKind::Rejected {
        return Ok(response);
    }
    let binding = installed.into_report_binding();
    let terminal = super::private_lifecycle::PrivateTerminalReceiptV4::parse_verified(
        &response.payload,
        request.attempt_id,
    )
    .map_err(PrivateLaunchFailure::AfterBroker)?;
    terminal
        .verify_broker_binding(&broker)
        .map_err(PrivateLaunchFailure::AfterBroker)?;
    let report = terminal
        .project_v11(&binding)
        .map_err(PrivateLaunchFailure::AfterBroker)?;
    Ok(Frame {
        kind: MessageKind::Terminal,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&report)
            .map_err(|error| PrivateLaunchFailure::AfterBroker(error.to_string()))?,
    })
}

pub(crate) fn terminal_payload(facts: &super::launch::TerminalFacts) -> Vec<u8> {
    let (exec_status, exec_os_code) = match facts.exec_status {
        super::launch::TargetExecStatus::Succeeded => ("success", "none".to_owned()),
        super::launch::TargetExecStatus::Failed { class, os_code } => {
            (class.receipt_name(), os_code.to_string())
        }
    };
    let mut payload = format!(
        "schema-version=2\nmechanism=linux-pid-namespace-cgroup-v2\nstatus={}\nexec-status={}\nexec-os-code={}\nspawn-error-reported={}\ntarget-pid={}\nauthorization-offset-millis={}\nmemory-limit-exceeded={}\ndeadline-exceeded={}\nassignment-verified={}\nnamespaces-verified={}\ntarget-initial-credentials-verified={}\ninitial-provider-capabilities-absent={}\ncaller-envelope-digest={}\ncaller-no-new-privs={}\ntarget-no-new-privs-matched={}\ncaller-capability-bounding-set-digest={}\ntarget-capability-bounding-set-matched={}\ncaller-mount-namespace-digest={}\ntarget-mount-context-derived-from-caller={}\ncredential-transition-disposition=preserve-caller-envelope\nboundary-independent-of-credentials={}\ndescriptors-verified={}\nwritable-ancestor-cgroup-denied={}\nparent-namespace-handles-denied={}\nrecursive-provider-request-denied={}\nguardian-ready-before-authorization={}\nfrontend-loss-authority-verified={}\ncgroup-kill-invoked={}\ncgroup-empty={}\ninit-reaped={}\nguardian-reaped={}\nboundary-retired={}\n",
        facts.child_status.map_or_else(|| "none".to_owned(), |status| status.to_string()),
        exec_status,
        exec_os_code,
        facts.spawn_error_reported,
        facts.target_pid,
        facts.authorization_offset_millis,
        facts.memory_limit_exceeded,
        facts.deadline_exceeded,
        facts.assignment_verified,
        facts.namespaces_verified,
        facts.target_initial_credentials_verified,
        facts.initial_provider_capabilities_absent,
        facts.caller_envelope_digest,
        facts.caller_no_new_privs,
        facts.target_no_new_privs_matched,
        facts.caller_capability_bounding_set_digest,
        facts.target_capability_bounding_set_matched,
        facts.caller_mount_namespace_digest,
        facts.target_mount_context_derived_from_caller,
        facts.boundary_independent_of_credentials,
        facts.descriptors_verified,
        facts.writable_ancestor_cgroup_denied,
        facts.parent_namespace_handles_denied,
        facts.recursive_provider_request_denied,
        facts.guardian_ready_before_authorization,
        facts.frontend_loss_authority_verified,
        facts.cgroup_kill_invoked,
        facts.cgroup_empty,
        facts.init_reaped,
        facts.guardian_reaped,
        facts.boundary_retired
    )
    .into_bytes();
    if facts.policy_revoked {
        payload.extend_from_slice(b"policy-revoked=true\n");
    }
    payload.extend_from_slice(b"policy-enforcement=");
    payload.extend_from_slice(
        &serde_json::to_vec(&facts.policy_enforcement)
            .expect("typed policy enforcement serializes"),
    );
    payload.push(b'\n');
    payload
}

#[cfg(feature = "test-support")]
pub fn terminal_payload_for_test(facts: &super::launch::TerminalFacts) -> Vec<u8> {
    terminal_payload(facts)
}

fn rejected(request: &Frame, rejection: &RejectionV1) -> Result<Frame, String> {
    Ok(Frame {
        kind: MessageKind::Rejected,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: rejection.encode()?,
    })
}

fn rejected_text(request: &Frame, code: &str, detail: &str) -> Result<Frame, String> {
    rejected(request, &RejectionV1::request_error(code, detail))
}

fn journal_rejection(attempt_id: [u8; 16], rejection: &RejectionV1) {
    let attempt = attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let diagnostic = serde_json::json!({
        "schema_version": 1,
        "event": "sealed-launch-rejected",
        "attempt_id": attempt,
        "code": rejection.code,
        "phase": rejection.phase,
        "target_created": rejection.target_created,
        "target_released": rejection.target_released,
        "cleanup_attempted": rejection.cleanup.attempted,
        "workload_empty": rejection.cleanup.workload_empty,
        "helpers_reaped": rejection.cleanup.helpers_reaped,
        "boundary_retired": rejection.cleanup.sealed_boundary_retired,
    });
    eprintln!("sealed provider launch rejection: {diagnostic}");
}

pub(crate) const PACKAGE_LEASE: &str = "/run/memcordon-sealed-package.lock";
const LEGACY_PACKAGE_LEASE: &str = "/run/memcordon/sealed-package.lock";

#[derive(Clone, Copy)]
enum LeaseAccess {
    SharedExisting,
    ExclusiveCreate,
}

pub fn acquire_shared_package_lease() -> Result<std::fs::File, String> {
    acquire_lease(PACKAGE_LEASE, LeaseAccess::SharedExisting)
}

pub fn acquire_package_lease() -> Result<std::fs::File, String> {
    acquire_lease(PACKAGE_LEASE, LeaseAccess::ExclusiveCreate)
}

pub fn acquire_legacy_package_lease() -> Result<std::fs::File, String> {
    acquire_lease(LEGACY_PACKAGE_LEASE, LeaseAccess::ExclusiveCreate)
}

pub fn acquire_qualification_lease() -> Result<std::fs::File, String> {
    acquire_lease(PACKAGE_LEASE, LeaseAccess::ExclusiveCreate).map_err(|error| {
        format!("MCSEALED-QUALIFICATION-LEASE: provider attempt is active: {error}")
    })
}

fn acquire_lease(path: &str, access: LeaseAccess) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let operation = match access {
        LeaseAccess::SharedExisting => libc::LOCK_SH | libc::LOCK_NB,
        LeaseAccess::ExclusiveCreate => {
            options.write(true).create(true).truncate(false).mode(0o600);
            libc::LOCK_EX | libc::LOCK_NB
        }
    };
    let file = options
        .open(path)
        .map_err(|error| format!("MCSEALED-PACKAGE-LEASE: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("MCSEALED-PACKAGE-LEASE: {error}"))?;
    if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o600 {
        return Err("MCSEALED-PACKAGE-LEASE: unsafe lock-file identity or mode".to_owned());
    }
    // SAFETY: `file` owns a live descriptor for the duration of the advisory lock; flock has no
    // pointer arguments and reports contention/error without changing Rust ownership.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == -1 {
        return Err(format!(
            "MCSEALED-PACKAGE-LEASE: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

#[derive(Clone, Copy)]
struct PeerCredentials {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, String> {
    let mut value = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>())
        .map_err(|_| "credential size overflow".to_owned())?;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    if status == -1 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(PeerCredentials {
        pid: value.pid,
        uid: value.uid,
        gid: value.gid,
    })
}

fn peer_groups(pid: libc::pid_t) -> Result<Vec<libc::gid_t>, String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| error.to_string())?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:\t"))
        .ok_or_else(|| "peer groups unavailable".to_owned())?
        .split_ascii_whitespace()
        .map(|value| value.parse().map_err(|_| "invalid peer group".to_owned()))
        .collect()
}

pub fn cgroup_membership_is_sealed(input: &str) -> Result<bool, String> {
    super::cgroup_membership::is_sealed(input)
}

pub fn namespace_membership_matches(
    peer: [crate::request::NamespaceIdentity; 3],
    member: [crate::request::NamespaceIdentity; 3],
) -> bool {
    peer == member
}

fn namespace_identity(metadata: &std::fs::Metadata) -> crate::request::NamespaceIdentity {
    crate::request::NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn peer_inside_active_attempt(pid: libc::pid_t) -> Result<bool, String> {
    peer_inside_active_attempt_at(
        pid,
        std::path::Path::new("/proc"),
        std::path::Path::new(super::CGROUP_ROOT),
    )
}

#[cfg(feature = "test-support")]
pub fn peer_inside_active_attempt_for_test(
    pid: libc::pid_t,
    proc_root: &std::path::Path,
    cgroup_root: &std::path::Path,
) -> Result<bool, String> {
    peer_inside_active_attempt_at(pid, proc_root, cgroup_root)
}

fn peer_inside_active_attempt_at(
    pid: libc::pid_t,
    proc_root: &std::path::Path,
    cgroup_root: &std::path::Path,
) -> Result<bool, String> {
    let process = proc_root.join(pid.to_string());
    let cgroup = std::fs::read_to_string(process.join("cgroup"))
        .map_err(|error| format!("recursive provider cgroup readback failed: {error}"))?;
    if cgroup_membership_is_sealed(&cgroup)? {
        return Ok(true);
    }
    let peer_namespaces = ["pid", "mnt", "cgroup"]
        .map(|kind| std::fs::metadata(process.join("ns").join(kind)))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("recursive provider namespace readback failed: {error}"))?;
    let peer_namespaces = std::array::from_fn(|index| {
        namespace_identity(
            peer_namespaces
                .get(index)
                .expect("three peer namespaces were captured"),
        )
    });
    match std::fs::symlink_metadata(cgroup_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(
                "recursive provider inventory root is not a no-follow directory".to_owned(),
            );
        }
        Err(error) => return Err(format!("recursive provider inventory root failed: {error}")),
    }
    let attempts = std::fs::read_dir(cgroup_root)
        .map_err(|error| format!("recursive provider inventory failed: {error}"))?;
    for attempt in attempts {
        let attempt = match attempt {
            Ok(attempt) => attempt,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "recursive provider inventory entry failed: {error}"
                ));
            }
        };
        let attempt = match super::cgroup::classify_attempt_root_entry(&attempt) {
            Ok(super::cgroup::AttemptRootEntry::KernelControl) => continue,
            Ok(super::cgroup::AttemptRootEntry::Attempt { path, .. }) => path,
            Ok(super::cgroup::AttemptRootEntry::InvalidDirectory(name)) => {
                return Err(format!(
                    "recursive provider inventory contained invalid attempt directory {}",
                    name.to_string_lossy()
                ));
            }
            Ok(super::cgroup::AttemptRootEntry::Unsafe(name)) => {
                return Err(format!(
                    "recursive provider inventory contained unsafe entry {}",
                    name.to_string_lossy()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "recursive provider inventory entry classification failed: {error}"
                ));
            }
        };
        let members = match std::fs::read_to_string(attempt.join("cgroup.procs")) {
            Ok(members) => members,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "recursive provider attempt membership readback failed: {error}"
                ));
            }
        };
        for member in members.lines() {
            let member = member
                .parse::<libc::pid_t>()
                .map_err(|_| "recursive provider inventory contained an invalid pid".to_owned())?;
            let member = proc_root.join(member.to_string());
            let mut metadata = Vec::with_capacity(3);
            for kind in ["pid", "mnt", "cgroup"] {
                match std::fs::metadata(member.join("ns").join(kind)) {
                    Ok(value) => metadata.push(value),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        metadata.clear();
                        break;
                    }
                    Err(error) => {
                        return Err(format!(
                            "recursive provider member namespace readback failed: {error}"
                        ));
                    }
                }
            }
            if metadata.len() == 3 {
                let member_namespaces =
                    std::array::from_fn(|index| namespace_identity(&metadata[index]));
                if namespace_membership_matches(peer_namespaces, member_namespaces) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn authorize_peer(credentials: PeerCredentials, groups: &[libc::gid_t]) -> Result<(), String> {
    let endpoint = std::fs::symlink_metadata(crate::linux::SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-PIPE-AUTH: endpoint metadata unavailable: {error}"))?;
    if !endpoint.file_type().is_socket()
        || endpoint.uid() != 0
        || endpoint.gid() == 0
        || endpoint.mode() & 0o007 != 0
    {
        return Err("MCSEALED-PIPE-AUTH: endpoint authorization identity is unsafe".to_owned());
    }
    if peer_is_authorized(credentials.uid, credentials.gid, groups, endpoint.gid()) {
        Ok(())
    } else {
        Err("MCSEALED-PIPE-AUTH: caller is not in the provider access group".to_owned())
    }
}

fn peer_is_authorized(
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
    allowed_gid: libc::gid_t,
) -> bool {
    uid == 0 || gid == allowed_gid || groups.contains(&allowed_gid)
}

#[cfg(feature = "test-support")]
pub fn peer_is_authorized_for_test(
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
    allowed_gid: libc::gid_t,
) -> bool {
    peer_is_authorized(uid, gid, groups, allowed_gid)
}
