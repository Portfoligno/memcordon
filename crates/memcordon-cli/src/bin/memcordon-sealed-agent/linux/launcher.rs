use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};

use crate::protocol::{
    Frame, MessageKind, read_frame, read_network_frame, write_frame, write_network_frame,
};
use crate::rejection::RejectionV1;
use crate::request::{
    DescriptorPurpose, LaunchBrokerRequestV2, NetworkBrokerExchangeError,
    NetworkLaunchBrokerRequestV4, decode_launch_broker_request, encode_launch_broker_request,
    encode_network_launch_broker_request, parse_network_broker_exchange,
};

pub const SOCKET_PATH: &str = "/run/memcordon/sealed-launcher.sock";
pub const NETWORK_SOCKET_PATH: &str = "/run/memcordon/sealed-network-launcher.sock";
const CONTROL_UNIT: &str = "memcordon-sealed-agent.service";
const LAUNCHER_UNIT: &str = "memcordon-sealed-launcher.service";
const NETWORK_LAUNCHER_UNIT: &str = "memcordon-sealed-network-launcher.service";
const INSTALLED_BINARY: &str = "/usr/libexec/memcordon-sealed-agent";

struct AllocatedRecordGuard(Option<super::attempt::AttemptRecord>);

impl AllocatedRecordGuard {
    fn take(&mut self) -> super::attempt::AttemptRecord {
        self.0
            .take()
            .expect("allocated broker record remains owned before bootstrap")
    }
}

impl Drop for AllocatedRecordGuard {
    fn drop(&mut self) {
        if let Some(record) = self.0.take() {
            let _ = record.retire();
        }
    }
}

pub fn serve() -> Result<(), String> {
    let qualification = super::qualification::qualify()?;
    let listener = activated_listener()?;
    loop {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        // SAFETY: launcher is single-threaded at this bounded per-connection fork point.
        let worker = unsafe { libc::fork() };
        if worker == -1 {
            return Err(format!(
                "MCSEALED-LAUNCHER-WORKER: {}",
                io::Error::last_os_error()
            ));
        }
        if worker == 0 {
            drop(listener);
            let code = match handle(&mut stream, &qualification) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("sealed launcher rejected request: {error}");
                    125
                }
            };
            // SAFETY: worker owns no Rust runtime state that may be unwound after fork.
            unsafe { libc::_exit(code) };
        }
        drop(stream);
        reap_workers();
    }
}

/// The optional unit has an authenticated V4 endpoint, but does not advertise
/// or execute the private profile until native preparation and qualification
/// can supply a verified release checkpoint.
pub fn serve_network() -> Result<(), String> {
    let listener = activated_listener()?;
    loop {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        // SAFETY: this is the single-threaded, bounded per-connection fork point.
        let worker = unsafe { libc::fork() };
        if worker == -1 {
            return Err(format!(
                "MCSEALED-NETWORK-LAUNCHER-WORKER: {}",
                io::Error::last_os_error()
            ));
        }
        if worker == 0 {
            drop(listener);
            let code = match handle_network(&mut stream) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("sealed network launcher rejected request: {error}");
                    125
                }
            };
            // SAFETY: the worker does not unwind after fork.
            unsafe { libc::_exit(code) };
        }
        drop(stream);
        reap_workers();
    }
}

fn handle_network(stream: &mut UnixStream) -> Result<(), String> {
    let peer = authenticate_peer(stream, CONTROL_UNIT)?;
    let (authentication, descriptors) = super::transport::receive_network(stream)?;
    if authentication.kind != MessageKind::BrokerAuthenticate
        || !authentication.payload.is_empty()
        || !descriptors.is_empty()
    {
        return Err("MCSEALED-NETWORK-LAUNCHER-AUTHENTICATION: invalid handshake".to_owned());
    }
    let authenticated = Frame {
        kind: MessageKind::BrokerAuthenticated,
        nonce: authentication.nonce,
        attempt_id: authentication.attempt_id,
        payload: Vec::new(),
    };
    let mut encoded = Vec::new();
    write_network_frame(&mut encoded, &authenticated).map_err(|error| error.to_string())?;
    // A single credential-bearing sendmsg binds the response to this worker.
    super::transport::send(stream, &encoded, &[])?;

    let (request, descriptors) = super::transport::receive_network(stream)?;
    let rejection = if request.nonce != authentication.nonce
        || request.attempt_id != authentication.attempt_id
    {
        RejectionV1::request_error(
            "MCSEALED-NETWORK-LAUNCHER-REQUEST-BINDING",
            "network broker request does not match authenticated exchange",
        )
    } else if request.kind == MessageKind::BrokerQualifyPrivateHost {
        let response = match validate_private_probe_operation(&request, descriptors, peer) {
            Ok(()) => Frame {
                kind: MessageKind::PrivateProbeRunCompleted,
                nonce: request.nonce,
                attempt_id: request.attempt_id,
                payload: Vec::new(),
            },
            Err(error) => rejected(
                &request,
                &RejectionV1::request_error("MCSEALED-PRIVATE-QUALIFICATION-REJECTED", &error),
            )?,
        };
        let mut encoded = Vec::new();
        write_network_frame(&mut encoded, &response).map_err(|error| error.to_string())?;
        return super::transport::send(stream, &encoded, &[]);
    } else if request.kind == MessageKind::BrokerReleaseCase {
        // Broker observation alone is incomplete. Only a later, separately
        // service-owned post-exit finalizer can publish the protected result.
        if let Err(error) = validate_release_candidate_operation(&request, descriptors, peer) {
            eprintln!("sealed release candidate incomplete: {error}");
        }
        let response = Frame {
            kind: MessageKind::ReleaseCaseIncomplete,
            nonce: request.nonce,
            attempt_id: request.attempt_id,
            payload: Vec::new(),
        };
        let mut encoded = Vec::new();
        write_network_frame(&mut encoded, &response).map_err(|error| error.to_string())?;
        return super::transport::send(stream, &encoded, &[]);
    } else if request.kind != MessageKind::BrokerLaunch {
        RejectionV1::request_error(
            "MCSEALED-NETWORK-LAUNCHER-AUTHORIZATION",
            "network launcher accepts only a V4 broker launch request",
        )
    } else {
        match parse_network_broker_exchange(
            &request.payload,
            request.attempt_id,
            peer.pid,
            peer.process_start_time,
            descriptors.len(),
        ) {
            Err(NetworkBrokerExchangeError::Decode(_)) => RejectionV1::request_error(
                "MCSEALED-NETWORK-LAUNCHER-DECODE",
                "invalid network broker request",
            ),
            Err(NetworkBrokerExchangeError::AttemptBinding) => RejectionV1::request_error(
                "MCSEALED-NETWORK-LAUNCHER-ATTEMPT-BINDING",
                "network broker attempt differs from authenticated frame",
            ),
            Err(NetworkBrokerExchangeError::ControlPeerBinding) => RejectionV1::request_error(
                "MCSEALED-NETWORK-LAUNCHER-PEER-BINDING",
                "network broker control process differs from authenticated peer",
            ),
            Err(NetworkBrokerExchangeError::DescriptorInventory) => RejectionV1::request_error(
                "MCSEALED-NETWORK-LAUNCHER-DESCRIPTOR-SET",
                "network broker descriptor inventory differs from transferred descriptors",
            ),
            Ok(broker) => match super::private_execution::execute_private_broker(
                broker,
                descriptors,
                request.nonce,
            ) {
                Ok(payload) => {
                    let response = Frame {
                        kind: MessageKind::Terminal,
                        nonce: request.nonce,
                        attempt_id: request.attempt_id,
                        payload,
                    };
                    return write_network_frame(stream, &response)
                        .map_err(|error| error.to_string());
                }
                Err(error) => {
                    let response = Frame {
                        kind: MessageKind::Rejected,
                        nonce: request.nonce,
                        attempt_id: request.attempt_id,
                        payload: error.encode(request.attempt_id)?,
                    };
                    return write_network_frame(stream, &response)
                        .map_err(|error| error.to_string());
                }
            },
        }
    };
    let response = rejected(&request, &rejection)?;
    write_network_frame(stream, &response).map_err(|error| error.to_string())
}

fn validate_release_candidate_operation(
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    peer: AuthenticatedPeer,
) -> Result<(), String> {
    if request.attempt_id == [0; 16] || descriptors.len() != 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: exact coordinator handle required".into());
    }
    let fixed = super::private_release_run::decode_broker_request(&request.payload)?;
    let directory = File::from(
        descriptors
            .into_iter()
            .next()
            .expect("exact release handle count was checked"),
    );
    // SAFETY: pidfd_open pins the authenticated control-service peer.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, peer.pid, 0) } as i32;
    if raw < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: coordinator pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open returned one owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let observed = super::private_attempt::ProcessIdentityV4::observe(peer.pid, pidfd.as_fd())?;
    if observed.start_time != peer.process_start_time {
        return Err("MCSEALED-PRIVATE-RELEASE: coordinator start identity changed".into());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
    let case = super::private_release_run::ReleaseCandidateRunAuthorityV1::begin(
        &fixed, peer.pid, pidfd, deadline, directory,
    )?;
    if fixed.selector == super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR {
        let observed = super::private_release_execution::execute_uncertain_candidate_case(&case)?;
        if observed.attempt_id.is_empty()
            || observed.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || observed.terminal_record_digest
                == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || observed.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
            || observed.authorization_failure_phase != 4
            || observed.authorization_failure_detail != "authorization packet invalid"
        {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertainty observation differs".into());
        }
        let inventory = case.persist_uncertain_native_raw_observation(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertainty inventory differs".into());
        }
        return Err("MCSEALED-PRIVATE-RELEASE: awaiting uncertainty coordinator cleanup".into());
    }
    if fixed.selector == super::private_release_case::RETIREMENT_FAULT_SELECTOR {
        let observed =
            super::private_release_execution::execute_blocked_retirement_candidate_case(&case)?;
        if observed.attempt_id.is_empty()
            || observed.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || observed.terminal_record_digest
                == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || observed.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked retirement observation differs".into());
        }
        let inventory = case.persist_blocked_retirement_raw_observation(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked retirement inventory differs".into());
        }
        return Err(
            "MCSEALED-PRIVATE-RELEASE: awaiting blocked-retirement coordinator cleanup".into(),
        );
    }
    if fixed.selector == super::private_release_guardian_loss::SELECTOR {
        let observed =
            super::private_release_guardian_loss::execute_guardian_loss_candidate_case(&case)?;
        if observed.attempt_id.is_empty()
            || observed.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || observed.terminal_record_digest
                == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || observed.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
            || observed.armed_response_sha256
                != memcordon_core::workload_codec::hash_bytes(
                    &super::private_release_guardian_loss::armed_response(&fixed.challenge),
                )
            || observed.settlement.guardian_signal != libc::SIGKILL
        {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss observation differs".into());
        }
        let inventory = case.persist_guardian_loss_raw_observation(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss inventory differs".into());
        }
        return Err("MCSEALED-PRIVATE-RELEASE: awaiting guardian-loss coordinator cleanup".into());
    }
    if fixed.selector == super::private_release_frontend_loss::SELECTOR {
        let observed =
            super::private_release_frontend_loss::execute_frontend_loss_candidate_case(&case)?;
        if observed.attempt_id.is_empty()
            || observed.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || observed.terminal_record_digest
                == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || observed.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
            || observed.armed_response_sha256
                != memcordon_core::workload_codec::hash_bytes(
                    &super::private_release_frontend_loss::armed_response(&fixed.challenge),
                )
            || observed.settlement.frontend_signal != libc::SIGKILL
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss observation differs".into());
        }
        let inventory = case.persist_frontend_loss_raw_observation(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss inventory differs".into());
        }
        return Err("MCSEALED-PRIVATE-RELEASE: awaiting frontend-loss coordinator cleanup".into());
    }
    if fixed.selector == super::private_release_case::CHECKPOINT_GATE_SELECTOR {
        let observed = super::private_release_gate::execute_checkpoint_gate_case(&case)?;
        let candidate = &observed.candidate;
        if candidate.attempt_id.is_empty()
            || candidate.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || candidate.terminal_record_digest
                == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || candidate.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
            || candidate.candidate_exit_code != 0
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate observation differs".into());
        }
        let inventory = case.persist_checkpoint_gate_raw_observation(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate raw inventory differs".into());
        }
        return Err(
            "MCSEALED-PRIVATE-RELEASE: awaiting checkpoint-gate coordinator cleanup".into(),
        );
    }
    if fixed.selector == super::private_release_children::SELECTOR {
        let observed = super::private_release_child_execution::execute_child_candidate_case(&case)?;
        let candidate = &observed.candidate;
        if candidate.attempt_id.is_empty()
            || candidate.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || candidate.terminal_record_digest
                == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || candidate.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
            || candidate.candidate_exit_code != 0
            || observed.live.challenge_sha256 != candidate.challenge_sha256
        {
            return Err("MCSEALED-PRIVATE-RELEASE: child observation differs".into());
        }
        let inventory = case.persist_child_raw_observation(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: child raw inventory differs".into());
        }
        return Err("MCSEALED-PRIVATE-RELEASE: awaiting child coordinator cleanup".into());
    }
    if fixed.selector == super::private_release_socket_launder::SELECTOR {
        let observed =
            super::private_release_socket_execution::execute_socket_launder_candidate_case(&case)?;
        let candidate = &observed.candidate;
        if candidate.attempt_id.is_empty()
            || candidate.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || candidate.terminal_record_digest
                == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || candidate.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
            || candidate.candidate_exit_code != 0
            || observed.gated_witness.sendmsg_errno != libc::EPERM
        {
            return Err("MCSEALED-PRIVATE-RELEASE: socket observation differs".into());
        }
        let inventory = case.persist_socket_raw_observation(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: socket raw inventory differs".into());
        }
        return Err("MCSEALED-PRIVATE-RELEASE: awaiting socket coordinator cleanup".into());
    }
    if fixed.selector == super::private_release_terminal_join::SELECTOR {
        let observed =
            super::private_release_terminal_execution::execute_terminal_join_candidate_case(&case)?;
        let candidate = &observed.candidate;
        if candidate.attempt_id.is_empty()
            || candidate.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || candidate.terminal_record_digest
                == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
            || candidate.challenge_sha256
                != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
            || candidate.candidate_exit_code != 0
            || observed.target_namespace_pid == 0
        {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join observation differs".into());
        }
        let inventory = case.persist_terminal_join_raw_observation(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join raw inventory differs".into());
        }
        return Err("MCSEALED-PRIVATE-RELEASE: awaiting terminal-join coordinator cleanup".into());
    }
    if fixed.selector == super::private_release_dual_attempt::SELECTOR {
        let observed = super::private_release_dual_execution::execute_dual_candidate_case(&case)?;
        if observed.first.attempt_id == observed.second.attempt_id
            || observed.first_namespace_inode == observed.second_namespace_inode
            || observed.first_listener_inode == observed.second_listener_inode
            || observed.first.candidate_exit_code != Some(0)
            || observed.second.candidate_exit_code != Some(0)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual native observation differs".into());
        }
        let inventory = case.persist_dual_worker_raw(&observed)?;
        if inventory.len()
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len()
                - 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual worker inventory differs".into());
        }
        return Err("MCSEALED-PRIVATE-RELEASE: awaiting dual coordinator cleanup".into());
    }
    let observed = super::private_release_execution::execute_candidate_fixture_case(&case)?;
    let namespace_inode = case.retired_native_namespace_inode()?;
    let expected_response = case.expected_fixture_output(namespace_inode)?;
    if observed.attempt_id.is_empty()
        || observed.checkpoint_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
        || observed.terminal_record_digest == memcordon_core::DiagnosticSha256::from_bytes([0; 32])
        || observed.challenge_sha256 != memcordon_core::workload_codec::hash_bytes(&fixed.challenge)
        || observed.network_namespace_inode != namespace_inode
        || observed.response_sha256
            != memcordon_core::workload_codec::hash_bytes(&expected_response)
        || observed.candidate_exit_code != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: native candidate observation differs".into());
    }
    let inventory = case.persist_native_raw_observation(&observed)?;
    if inventory.len()
        != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL.len() - 1
    {
        return Err("MCSEALED-PRIVATE-RELEASE: raw attachment inventory differs".into());
    }
    Err("MCSEALED-PRIVATE-RELEASE: awaiting independent coordinator cleanup".into())
}

fn validate_private_probe_operation(
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    peer: AuthenticatedPeer,
) -> Result<(), String> {
    if request.attempt_id == [0; 16] || descriptors.len() != 1 {
        return Err("MCSEALED-PRIVATE-PROBE: exact run handle and attempt required".into());
    }
    let nonce = super::private_qualification::decode_broker_request(&request.payload)?;
    let directory = std::fs::File::from(
        descriptors
            .into_iter()
            .next()
            .expect("exact descriptor count was checked"),
    );
    // SAFETY: pidfd_open binds to the authenticated live control-service peer,
    // not a numeric PID chosen in the broker request.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, peer.pid, 0) } as i32;
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: coordinator pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open returned one owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    let observed = super::private_attempt::ProcessIdentityV4::observe(peer.pid, pidfd.as_fd())?;
    if observed.start_time != peer.process_start_time {
        return Err("MCSEALED-PRIVATE-PROBE: coordinator start identity changed".into());
    }
    let package = crate::package::acquire_verified_probe_package_lease()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
    let run = super::private_qualification::ProbeRunAuthority::begin(
        package, peer.pid, pidfd, deadline, nonce, directory,
    )?;
    // The coordinator retains the package lease and pidfd while every fixed
    // native subattempt executes. A failure leaves protected records in place
    // for explicit recovery; it never skips ahead or issues a host receipt.
    for index in 0..super::qualification::HOST_PROBE_CATALOG_V1.len() {
        let case = run.case(index)?;
        match case.kind() {
            super::private_qualification::ProbeFixtureKindV1::FrontendGuardianLossRetirement => {
                let frontend = super::private_probe_loss::execute_loss_subattempt(
                    &case,
                    super::private_qualification::ProbeLossKindV1::Frontend,
                )?;
                let guardian = super::private_probe_loss::execute_loss_subattempt(
                    &case,
                    super::private_qualification::ProbeLossKindV1::Guardian,
                )?;
                case.persist_loss_completion(&[frontend, guardian])?;
            }
            super::private_qualification::ProbeFixtureKindV1::TargetExecFailureRetirement => {
                super::private_probe_execution::execute_failed_exec_fixture(&case)?;
            }
            super::private_qualification::ProbeFixtureKindV1::BaselineUnixSuccessRetirement => {
                super::private_probe_baseline::execute_baseline_unix_fixture(&case)?;
            }
            _ => {
                super::private_probe_execution::execute_success_fixture(&case)?;
            }
        }
        case.verify_persisted_completion()?;
    }
    let live = run.verify_complete_run()?;
    let stored = run.verify_independent_readback()?;
    if live.native_run_digest() != stored.native_run_digest() || live.probes() != stored.probes() {
        return Err("MCSEALED-PRIVATE-PROBE: independent run readback differs".into());
    }
    Ok(())
}

pub fn probe() -> Result<super::qualification::QualificationReceipt, String> {
    let request = Frame {
        kind: MessageKind::BrokerProbe,
        nonce: nonce()?,
        attempt_id: [0; 16],
        payload: Vec::new(),
    };
    let mut stream = connect_authenticated(request.nonce, request.attempt_id)?;
    write_frame(&mut stream, &request).map_err(|error| error.to_string())?;
    let response = read_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.kind != MessageKind::ProbeReceipt
        || response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
    {
        return Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: invalid probe response".to_owned());
    }
    let qualification: super::qualification::QualificationReceipt =
        serde_json::from_slice(&response.payload).map_err(|error| error.to_string())?;
    if qualification.complete() {
        Ok(qualification)
    } else {
        Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: incomplete qualification".to_owned())
    }
}

pub fn launch(
    request: &Frame,
    broker_request: &LaunchBrokerRequestV2,
    descriptors: &[RawFd],
) -> Result<Frame, String> {
    if descriptors.len() != 7 {
        return Err(
            "MCSEALED-LAUNCHER-DESCRIPTOR-SET: exact descriptor inventory required".to_owned(),
        );
    }
    let mut stream = connect_authenticated(request.nonce, request.attempt_id)?;
    let broker_frame = Frame {
        kind: MessageKind::BrokerLaunch,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: encode_launch_broker_request(broker_request)
            .map_err(|error| format!("MCSEALED-LAUNCHER-ENCODE: {error:?}"))?,
    };
    let mut encoded = Vec::new();
    write_frame(&mut encoded, &broker_frame).map_err(|error| error.to_string())?;
    super::transport::send(&stream, &encoded, descriptors)?;
    let response = read_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
        || !matches!(response.kind, MessageKind::Terminal | MessageKind::Rejected)
    {
        return Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: invalid launch response".to_owned());
    }
    Ok(response)
}

pub fn launch_network(
    request: &Frame,
    broker_request: &NetworkLaunchBrokerRequestV4,
    descriptors: &[RawFd],
) -> Result<Frame, String> {
    if descriptors.len() != crate::request::network_broker_descriptor_manifest().len() {
        return Err(
            "MCSEALED-NETWORK-LAUNCHER-DESCRIPTOR-SET: exact inventory required".to_owned(),
        );
    }
    let mut stream = connect_network_authenticated(request.nonce, request.attempt_id)?;
    let broker_frame = Frame {
        kind: MessageKind::BrokerLaunch,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: encode_network_launch_broker_request(broker_request)
            .map_err(|error| format!("MCSEALED-NETWORK-LAUNCHER-ENCODE: {error:?}"))?,
    };
    let mut encoded = Vec::new();
    write_network_frame(&mut encoded, &broker_frame).map_err(|error| error.to_string())?;
    super::transport::send(&stream, &encoded, descriptors)?;
    let response = read_network_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
        || !matches!(response.kind, MessageKind::Terminal | MessageKind::Rejected)
    {
        return Err(
            "MCSEALED-NETWORK-LAUNCHER-SERVICE-AUTHENTICATION: invalid response".to_owned(),
        );
    }
    match response.kind {
        MessageKind::Terminal => {
            let terminal = super::private_lifecycle::PrivateTerminalReceiptV4::parse_verified(
                &response.payload,
                request.attempt_id,
            )?;
            terminal.verify_broker_binding(broker_request)?;
        }
        MessageKind::Rejected => {
            let value: serde_json::Value = serde_json::from_slice(&response.payload)
                .map_err(|error| format!("MCSEALED-NETWORK-LAUNCHER-REJECTION: {error}"))?;
            match value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
            {
                Some(4) => super::private_execution::validate_broker_rejection(
                    &response.payload,
                    request.attempt_id,
                )?,
                Some(1) => {
                    let rejection: RejectionV1 = serde_json::from_slice(&response.payload)
                        .map_err(|error| error.to_string())?;
                    rejection.validate()?;
                    if rejection.target_created
                        || rejection.target_released
                        || rejection.cleanup.attempted
                    {
                        return Err(
                            "MCSEALED-NETWORK-LAUNCHER-REJECTION: V1 post-allocation claim".into(),
                        );
                    }
                }
                _ => return Err("MCSEALED-NETWORK-LAUNCHER-REJECTION: unknown schema".into()),
            }
        }
        _ => unreachable!("validated network broker response kind"),
    }
    Ok(response)
}

pub(crate) fn qualify_private_host(
    request: &Frame,
    prepared: &super::private_qualification::PreparedProbeRunV1,
) -> Result<Frame, String> {
    let (stream, worker) = connect_network_authenticated_peer(request.nonce, request.attempt_id)?;
    // SAFETY: pidfd_open pins the authenticated worker PID; native identity
    // readback below rejects reuse between the credential frame and open.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, worker.pid, 0) } as i32;
    if raw == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: worker pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open transferred one unique descriptor.
    let worker_pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let worker_identity =
        super::private_attempt::ProcessIdentityV4::observe(worker.pid, worker_pidfd.as_fd())?;
    if worker_identity.start_time != worker.process_start_time {
        return Err("MCSEALED-PRIVATE-PROBE: authenticated worker identity changed".into());
    }
    let broker = Frame {
        kind: MessageKind::BrokerQualifyPrivateHost,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: prepared.encode_broker_request()?,
    };
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &broker).map_err(|error| error.to_string())?;
    set_receive_credentials(&stream, true)?;
    super::transport::send(&stream, &bytes, &[prepared.directory.as_raw_fd()])?;
    let (response, descriptors, credentials) =
        super::transport::receive_network_with_credentials(&stream)?;
    if !descriptors.is_empty() {
        return Err("MCSEALED-PRIVATE-PROBE: worker returned unexpected descriptors".into());
    }
    let credentials =
        credentials.ok_or("MCSEALED-PRIVATE-PROBE: worker completion credentials absent")?;
    if response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
        || credentials.pid != worker.pid
        || credentials.uid != 0
        || credentials.gid != 0
    {
        return Err("MCSEALED-PRIVATE-PROBE: worker completion binding differs".into());
    }
    if response.kind == MessageKind::Rejected {
        let rejection: RejectionV1 =
            serde_json::from_slice(&response.payload).map_err(|error| error.to_string())?;
        rejection.validate()?;
        return Ok(response);
    }
    if response.kind != MessageKind::PrivateProbeRunCompleted || !response.payload.is_empty() {
        return Err("MCSEALED-PRIVATE-PROBE: worker completion format differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll observes only the retained authenticated worker pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 30_000) } != 1 || pollfd.revents & libc::POLLIN == 0
    {
        return Err("MCSEALED-PRIVATE-PROBE: worker did not exit after completion".into());
    }
    let package = crate::package::acquire_verified_probe_package_lease()?;
    let stored = super::private_qualification::verify_completed_run_after_exit(
        &prepared.nonce,
        &prepared.directory,
        &package,
    )?;
    if stored.probes().len() != super::qualification::HOST_PROBE_CATALOG_V1.len() {
        return Err("MCSEALED-PRIVATE-PROBE: post-exit run inventory differs".into());
    }
    Ok(Frame {
        kind: MessageKind::PrivateProbeRunCompleted,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: prepared.nonce.to_vec(),
    })
}

pub(crate) fn execute_release_candidate_case(
    request: &Frame,
    prepared: &super::private_release_run::PreparedReleaseCandidateRunV1,
) -> Result<Frame, String> {
    let (stream, worker) = connect_network_authenticated_peer(request.nonce, request.attempt_id)?;
    // SAFETY: pidfd_open pins the authenticated worker during the exchange.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, worker.pid, 0) } as i32;
    if raw < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: worker pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open returned one owned descriptor.
    let worker_pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let worker_identity =
        super::private_attempt::ProcessIdentityV4::observe(worker.pid, worker_pidfd.as_fd())?;
    if worker_identity.start_time != worker.process_start_time {
        return Err("MCSEALED-PRIVATE-RELEASE: authenticated worker changed".into());
    }
    let broker = Frame {
        kind: MessageKind::BrokerReleaseCase,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: prepared.encode_broker_request()?,
    };
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &broker).map_err(|error| error.to_string())?;
    set_receive_credentials(&stream, true)?;
    super::transport::send(&stream, &bytes, &[prepared.directory.as_raw_fd()])?;
    let (response, descriptors, credentials) =
        super::transport::receive_network_with_credentials(&stream)?;
    if !descriptors.is_empty() {
        return Err("MCSEALED-PRIVATE-RELEASE: worker returned descriptors".into());
    }
    let credentials = credentials.ok_or("MCSEALED-PRIVATE-RELEASE: worker credentials absent")?;
    if response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
        || response.kind != MessageKind::ReleaseCaseIncomplete
        || !response.payload.is_empty()
        || credentials.pid != worker.pid
        || credentials.uid != 0
        || credentials.gid != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: worker response binding differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll observes only the retained authenticated worker pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 30_000) } != 1 || pollfd.revents & libc::POLLIN == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: worker did not exit after observation".into());
    }
    if prepared.request.selector == super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR {
        prepared.persist_control_uncertain_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else if prepared.request.selector == super::private_release_case::RETIREMENT_FAULT_SELECTOR {
        prepared
            .persist_control_blocked_retirement_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else if prepared.request.selector == super::private_release_guardian_loss::SELECTOR {
        prepared.persist_control_guardian_loss_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else if prepared.request.selector == super::private_release_frontend_loss::SELECTOR {
        prepared.persist_control_frontend_loss_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else if prepared.request.selector == super::private_release_case::CHECKPOINT_GATE_SELECTOR {
        prepared.persist_control_checkpoint_gate_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else if prepared.request.selector == super::private_release_children::SELECTOR {
        prepared.persist_control_child_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else if prepared.request.selector == super::private_release_socket_launder::SELECTOR {
        prepared.persist_control_socket_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else if prepared.request.selector == super::private_release_terminal_join::SELECTOR {
        prepared.persist_control_terminal_join_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else if prepared.request.selector == super::private_release_dual_attempt::SELECTOR {
        prepared.persist_control_dual_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    } else {
        prepared.persist_control_cleanup(&worker_identity, worker_pidfd.as_fd())?;
    }
    Ok(response)
}

fn handle(
    stream: &mut UnixStream,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<(), String> {
    let peer = authenticate_peer(stream, CONTROL_UNIT)?;
    // The listener belongs to systemd, so the client authenticates this accepted-stream worker
    // from kernel-supplied message credentials before it sends the broker request.
    let (authentication, authentication_descriptors) = super::transport::receive(stream)?;
    if authentication.kind != MessageKind::BrokerAuthenticate
        || !authentication.payload.is_empty()
        || !authentication_descriptors.is_empty()
    {
        let response = rejected(
            &authentication,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION",
                "launcher authentication request is invalid",
            ),
        )?;
        return write_authentication_response(stream, &response);
    }
    let authenticated = Frame {
        kind: MessageKind::BrokerAuthenticated,
        nonce: authentication.nonce,
        attempt_id: authentication.attempt_id,
        payload: Vec::new(),
    };
    write_authentication_response(stream, &authenticated)?;
    let (request, descriptors) = super::transport::receive(stream)?;
    let response = if request.nonce != authentication.nonce
        || request.attempt_id != authentication.attempt_id
    {
        rejected(
            &request,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-REQUEST-BINDING",
                "broker request does not match authenticated launcher exchange",
            ),
        )?
    } else {
        match request.kind {
            MessageKind::BrokerProbe if descriptors.is_empty() && request.payload.is_empty() => {
                Frame {
                    kind: MessageKind::ProbeReceipt,
                    nonce: request.nonce,
                    attempt_id: request.attempt_id,
                    payload: qualification.render().into_bytes(),
                }
            }
            MessageKind::BrokerLaunch => {
                launch_response(&request, descriptors, peer, qualification)?
            }
            _ => rejected(
                &request,
                &RejectionV1::request_error(
                    "MCSEALED-LAUNCHER-AUTHORIZATION",
                    "private launcher accepts only bounded broker protocol v2 requests",
                ),
            )?,
        }
    };
    write_frame(stream, &response).map_err(|error| error.to_string())
}

fn launch_response(
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    peer: AuthenticatedPeer,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<Frame, String> {
    let broker = match decode_launch_broker_request(&request.payload) {
        Ok(broker) => broker,
        Err(error) => {
            return rejected(
                request,
                &RejectionV1::request_error(
                    "MCSEALED-LAUNCHER-DECODE",
                    &format!("invalid broker request: {error:?}"),
                ),
            );
        }
    };
    if broker.attempt_id != request.attempt_id
        || broker.control_process_id != peer.pid
        || broker.control_process_start_time != peer.process_start_time
    {
        return rejected(
            request,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-REQUEST-BINDING",
                "broker request does not match authenticated control peer or frame",
            ),
        );
    }
    let record_identity = broker
        .record_identity
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record_digest = broker
        .record_identity
        .caller_envelope_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut record = AllocatedRecordGuard(Some(super::attempt::AttemptRecord::adopt_v2(
        record_identity,
        broker.caller.pid,
        record_digest,
    )?));
    if descriptors.len() != broker.descriptor_manifest.len() || descriptors.len() != 7 {
        return rejected(
            request,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-DESCRIPTOR-SET",
                "broker descriptor manifest does not match transferred descriptors",
            ),
        );
    }
    super::envelope::verify_live(&broker.caller)?;
    if !super::envelope::descriptor_matches(
        descriptors[0].as_fd(),
        broker.caller.current_directory_identity,
    )? || !super::envelope::namespace_descriptor_matches(
        descriptors[5].as_fd(),
        broker.caller.mount_namespace_identity,
    )? || !super::envelope::descriptor_matches(
        descriptors[6].as_fd(),
        broker.caller.root_identity,
    )? {
        return rejected(
            request,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-DESCRIPTOR-IDENTITY",
                "caller descriptor identity changed before launch",
            ),
        );
    }
    let mut descriptors = descriptors.into_iter();
    let workload = descriptors.by_ref().take(5).collect::<Vec<_>>();
    let mount_namespace = descriptors
        .next()
        .ok_or_else(|| "launcher mount namespace descriptor missing".to_owned())?;
    let root = descriptors
        .next()
        .ok_or_else(|| "launcher root descriptor missing".to_owned())?;
    if descriptors.next().is_some() {
        return Err("launcher descriptor inventory exceeded manifest".to_owned());
    }
    match super::launch::execute_brokered_typed(
        broker.launch,
        workload,
        request.attempt_id,
        broker.caller,
        mount_namespace,
        root,
        record.take(),
        &qualification.receipt_digest,
    ) {
        Ok(facts) => Ok(Frame {
            kind: MessageKind::Terminal,
            nonce: request.nonce,
            attempt_id: request.attempt_id,
            payload: super::service::terminal_payload(&facts),
        }),
        Err(rejection) => rejected(request, &rejection),
    }
}

fn rejected(request: &Frame, rejection: &RejectionV1) -> Result<Frame, String> {
    Ok(Frame {
        kind: MessageKind::Rejected,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: rejection.encode()?,
    })
}

fn connect_authenticated(nonce: [u8; 16], attempt_id: [u8; 16]) -> Result<UnixStream, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-LAUNCHER-CONNECTION: {error}"))?;
    // SO_PEERCRED identifies systemd for an activation-owned listener. SCM_CREDENTIALS on the
    // response instead identifies the launcher worker that holds this accepted connection.
    set_receive_credentials(&stream, true)?;
    let authentication = Frame {
        kind: MessageKind::BrokerAuthenticate,
        nonce,
        attempt_id,
        payload: Vec::new(),
    };
    write_frame(&mut stream, &authentication).map_err(|error| error.to_string())?;
    let credentials = receive_authentication_response(&stream, &authentication)?;
    let _ = authenticate_credentials(credentials, LAUNCHER_UNIT)?;
    set_receive_credentials(&stream, false)?;
    Ok(stream)
}

fn connect_network_authenticated(
    nonce: [u8; 16],
    attempt_id: [u8; 16],
) -> Result<UnixStream, String> {
    connect_network_authenticated_peer(nonce, attempt_id).map(|(stream, _)| stream)
}

fn connect_network_authenticated_peer(
    nonce: [u8; 16],
    attempt_id: [u8; 16],
) -> Result<(UnixStream, AuthenticatedPeer), String> {
    let mut stream = UnixStream::connect(NETWORK_SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-NETWORK-LAUNCHER-CONNECTION: {error}"))?;
    set_receive_credentials(&stream, true)?;
    let authentication = Frame {
        kind: MessageKind::BrokerAuthenticate,
        nonce,
        attempt_id,
        payload: Vec::new(),
    };
    write_network_frame(&mut stream, &authentication).map_err(|error| error.to_string())?;
    let (response, descriptors, credentials) =
        super::transport::receive_network_with_credentials(&stream)?;
    if response.kind != MessageKind::BrokerAuthenticated
        || response.nonce != nonce
        || response.attempt_id != attempt_id
        || !response.payload.is_empty()
        || !descriptors.is_empty()
    {
        return Err(
            "MCSEALED-NETWORK-LAUNCHER-SERVICE-AUTHENTICATION: invalid handshake response"
                .to_owned(),
        );
    }
    let credentials = credentials.ok_or_else(|| {
        "MCSEALED-NETWORK-LAUNCHER-SERVICE-AUTHENTICATION: credentials missing".to_owned()
    })?;
    let peer = authenticate_credentials(credentials, NETWORK_LAUNCHER_UNIT)?;
    set_receive_credentials(&stream, false)?;
    Ok((stream, peer))
}

fn write_authentication_response(stream: &UnixStream, response: &Frame) -> Result<(), String> {
    let mut encoded = Vec::new();
    write_frame(&mut encoded, response).map_err(|error| error.to_string())?;
    // One sendmsg transaction keeps the kernel credential record aligned with the complete frame.
    super::transport::send(stream, &encoded, &[])
}

fn receive_authentication_response(
    stream: &UnixStream,
    request: &Frame,
) -> Result<libc::ucred, String> {
    let (response, descriptors, credentials) = super::transport::receive_with_credentials(stream)?;
    if response.kind != MessageKind::BrokerAuthenticated
        || response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
        || !response.payload.is_empty()
        || !descriptors.is_empty()
    {
        return Err(
            "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: invalid authentication response".to_owned(),
        );
    }
    credentials.ok_or_else(|| {
        "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: authenticated credentials missing".to_owned()
    })
}

fn set_receive_credentials(stream: &UnixStream, enabled: bool) -> Result<(), String> {
    let value: libc::c_int = i32::from(enabled);
    // SAFETY: setsockopt reads one initialized integer through a live socket descriptor.
    let status = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&raw const value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if status == -1 {
        return Err(format!(
            "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AuthenticatedPeer {
    pid: libc::pid_t,
    process_start_time: u64,
}

fn authenticate_peer(
    stream: &UnixStream,
    expected_unit: &str,
) -> Result<AuthenticatedPeer, String> {
    let credentials = peer_credentials(stream)?;
    authenticate_credentials(credentials, expected_unit)
}

pub(crate) fn authenticate_control_service(stream: &UnixStream) -> Result<(), String> {
    authenticate_peer(stream, CONTROL_UNIT).map(|_| ())
}

fn authenticate_credentials(
    credentials: libc::ucred,
    expected_unit: &str,
) -> Result<AuthenticatedPeer, String> {
    if credentials.uid != 0 || credentials.pid <= 0 {
        return Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: peer uid is not root".to_owned());
    }
    let process = std::path::Path::new("/proc").join(credentials.pid.to_string());
    let executable = std::fs::metadata(process.join("exe"))
        .map_err(|error| format!("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {error}"))?;
    let installed = std::fs::metadata(INSTALLED_BINARY)
        .map_err(|error| format!("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {error}"))?;
    if executable.dev() != installed.dev() || executable.ino() != installed.ino() {
        return Err(
            "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: executable identity mismatch".to_owned(),
        );
    }
    let cgroup = std::fs::read_to_string(process.join("cgroup"))
        .map_err(|error| format!("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {error}"))?;
    let expected_unit = std::ffi::OsStr::new(expected_unit);
    let matches_unit = cgroup.lines().any(|line| {
        line.split_once("::").is_some_and(|(_, path)| {
            std::path::Path::new(path)
                .components()
                .any(|component| component.as_os_str() == expected_unit)
        })
    });
    if !matches_unit {
        return Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: unit identity mismatch".to_owned());
    }
    let process_start_time = super::envelope::process_start_time(credentials.pid)?;
    Ok(AuthenticatedPeer {
        pid: credentials.pid,
        process_start_time,
    })
}

#[cfg(feature = "test-support")]
pub fn set_receive_credentials_for_test(stream: &UnixStream, enabled: bool) -> Result<(), String> {
    set_receive_credentials(stream, enabled)
}

#[cfg(feature = "test-support")]
pub fn write_authentication_response_for_test(
    stream: &UnixStream,
    response: &Frame,
) -> Result<(), String> {
    write_authentication_response(stream, response)
}

#[cfg(feature = "test-support")]
pub fn receive_authentication_response_for_test(
    stream: &UnixStream,
    request: &Frame,
) -> Result<libc::pid_t, String> {
    receive_authentication_response(stream, request).map(|credentials| credentials.pid)
}

#[cfg(feature = "test-support")]
pub fn socket_peer_pid_for_test(stream: &UnixStream) -> Result<libc::pid_t, String> {
    peer_credentials(stream).map(|credentials| credentials.pid)
}

fn peer_credentials(stream: &UnixStream) -> Result<libc::ucred, String> {
    let mut value = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| "credential size overflow".to_owned())?;
    // SAFETY: SO_PEERCRED writes a libc::ucred into live initialized storage.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    if status == -1 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(format!(
            "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(value)
}

fn activated_listener() -> Result<UnixListener, String> {
    const SYSTEMD_LISTEN_FD: RawFd = 3;
    // SAFETY: systemd socket activation transfers ownership of descriptor 3 to this process.
    Ok(unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) })
}

fn reap_workers() {
    loop {
        // SAFETY: WNOHANG reaps any completed direct launcher worker without blocking.
        if unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } <= 0 {
            break;
        }
    }
}

pub(crate) fn nonce() -> Result<[u8; 16], String> {
    let mut nonce = [0_u8; 16];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|error| error.to_string())?,
        &mut nonce,
    )
    .map_err(|error| error.to_string())?;
    Ok(nonce)
}

pub fn broker_descriptor_manifest() -> Vec<DescriptorPurpose> {
    vec![
        DescriptorPurpose::CurrentDirectory,
        DescriptorPurpose::Stdin,
        DescriptorPurpose::Stdout,
        DescriptorPurpose::Stderr,
        DescriptorPurpose::FrontendLiveness,
        DescriptorPurpose::CallerMountNamespace,
        DescriptorPurpose::CallerRoot,
    ]
}
