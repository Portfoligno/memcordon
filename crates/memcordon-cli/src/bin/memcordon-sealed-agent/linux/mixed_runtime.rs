//! Installed revision-two image-only execution. Public descriptions never
//! substitute for the account, namespace, cgroup or release owners below.
use super::mixed_admission::MixedOperationalAdmission;
use super::private_lifecycle::{
    PrivateAttemptOwner, PrivateExecObservation, PrivateMonitorOutcome,
};
use crate::protocol::{Frame, MessageKind};
use memcordon_core::result_v2::*;
use serde::{Deserialize, Serialize};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MixedBrokerEnvelope {
    format: String,
    revision: u32,
    contract: memcordon_core::workload_contract_v3::WorkloadContractV3,
    native_broker: Vec<u8>,
    public_request_sha256: memcordon_core::DiagnosticSha256,
    attempt_deadline_millis: Option<u64>,
}

pub(super) fn forward_public(
    frontend: &std::os::unix::net::UnixStream,
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    pid: i32,
    uid: u32,
    gid: u32,
    groups: &[u32],
) -> Result<Frame, String> {
    if !cfg!(feature = "private-tcp")
        || request.kind != MessageKind::MixedLaunch
        || descriptors.len() != 5
        || request.attempt_id == [0; 16]
    {
        return Err("mixed ingress requires selected runtime and exact native resources".into());
    }
    let _package = super::service::acquire_shared_package_lease()?;
    let public = memcordon_core::mixed_runtime::MixedRuntimeRequest::parse(&request.payload)?;
    let semantic_request_sha256 = public.contract.digest()?;
    let launch = crate::request::decode_launch_request(&public.native_launch)
        .map_err(|error| format!("mixed launch codec: {error:?}"))?;
    if launch.workload_contract.is_some()
        || launch.descriptors != super::launcher::broker_descriptor_manifest()[..5]
    {
        return Err("mixed native contract/descriptor inventory differs".into());
    }
    let captured = super::envelope::capture(pid, uid, gid, groups, descriptors[0].as_fd())?;
    let held_frontend =
        super::private_attempt::ProcessIdentityV4::observe(pid, descriptors[4].as_fd())?;
    if held_frontend.start_time != captured.envelope.process_start_time {
        return Err("mixed frontend lifetime handle differs".into());
    }
    let control = unsafe { libc::getpid() };
    let (broker, public_request_sha256) =
        crate::request::LaunchBrokerRequestV2::authenticated_private(
            request.attempt_id,
            &request.payload,
            control,
            super::envelope::process_start_time(control)?,
            launch,
            captured.envelope,
            super::launcher::broker_descriptor_manifest(),
        )
        .map_err(|error| format!("mixed native broker binding: {error:?}"))?;
    let envelope = MixedBrokerEnvelope {
        format: "memcordon.mixed-runtime-broker".into(),
        revision: 2,
        contract: public.contract,
        native_broker: crate::request::encode_launch_broker_request(&broker)
            .map_err(|error| format!("mixed broker codec: {error:?}"))?,
        public_request_sha256,
        attempt_deadline_millis: public.attempt_deadline_millis,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
    if bytes.len() > memcordon_core::workload_limits::CONTRACT_ENVELOPE_BYTES {
        return Err("mixed broker envelope exceeds finite bound".into());
    }
    let fds = descriptors
        .iter()
        .map(AsRawFd::as_raw_fd)
        .chain([
            captured.mount_namespace.as_raw_fd(),
            captured.root.as_raw_fd(),
        ])
        .collect::<Vec<_>>();
    match super::launcher::forward_private(frontend, request, bytes, &fds) {
        Ok(response) => Ok(response),
        Err(error) => {
            let attempt = request
                .attempt_id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            terminal(request,MixedRuntimeOutcomeV2::Indeterminate{
                attempt_id:memcordon_core::BoundedText::new(&attempt).expect("fixed attempt id bound"),
                request_sha256:semantic_request_sha256,
                retained_obligations:outstanding(MixedAuthorizationKnowledgeV2::Unknown,[error,"native broker exchange failed after dispatch; protected attempt ownership requires recovery".into()]),
            })
        }
    }
}

fn terminal(request: &Frame, outcome: MixedRuntimeOutcomeV2) -> Result<Frame, String> {
    let carrier = MixedRuntimeCarrierV2 {
        kind: "linux-mixed-private".into(),
        carrier_revision: 2,
        provider_contract: 4,
        launch_wire: 4,
        outcome,
    };
    Ok(Frame {
        kind: MessageKind::MixedTerminal,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&carrier).map_err(|error| error.to_string())?,
    })
}
#[cfg(test)]
pub(crate) fn component_terminal(
    request: &Frame,
    outcome: MixedRuntimeOutcomeV2,
) -> Result<Frame, String> {
    terminal(request, outcome)
}
fn rejection_detail(detail: &str) -> memcordon_core::BoundedText<4096> {
    let mut end = detail.len().min(4096);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    memcordon_core::BoundedText::new(&detail[..end]).expect("bounded rejection detail")
}
pub(super) fn rejected_ingress(
    request: &Frame,
    reason: MixedAdmissionRejectionV2,
    detail: &str,
) -> Result<Frame, String> {
    let mut response = terminal(
        request,
        MixedRuntimeOutcomeV2::RejectedIngress {
            request_bytes_sha256: memcordon_core::workload_codec::hash_bytes(&request.payload),
            reason,
            detail: rejection_detail(detail),
            allocation: outstanding(MixedAuthorizationKnowledgeV2::NeverAuthorized, Vec::new()),
        },
    )?;
    response.kind = MessageKind::MixedRejected;
    Ok(response)
}
fn outstanding(
    authorization: MixedAuthorizationKnowledgeV2,
    details: impl IntoIterator<Item = String>,
) -> OutstandingMixedRetirementV2 {
    let mut obligations = memcordon_core::BoundedVec::default();
    for detail in details {
        let bounded = memcordon_core::BoundedText::new(if detail.len() <= 256 {
            &detail
        } else {
            "native mixed ownership remains unresolved; inspect retained protected journal"
        })
        .expect("bounded native obligation");
        if obligations.try_push(bounded).is_err() {
            break;
        }
    }
    OutstandingMixedRetirementV2 {
        authorization,
        obligations,
    }
}
pub(super) fn execute_brokered(
    stream: &std::os::unix::net::UnixStream,
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    control_pid: i32,
    control_birth: u64,
) -> Result<Frame, String> {
    if !cfg!(feature = "private-tcp")
        || request.kind != MessageKind::MixedBrokerLaunch
        || request.payload.len() > memcordon_core::workload_limits::CONTRACT_ENVELOPE_BYTES
    {
        return Err("mixed broker runtime/envelope differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&request.payload)?;
    let envelope: MixedBrokerEnvelope =
        serde_json::from_slice(&request.payload).map_err(|error| error.to_string())?;
    if envelope.format != "memcordon.mixed-runtime-broker" || envelope.revision != 2 {
        return Err("mixed named broker revision differs".into());
    }
    let broker = crate::request::decode_launch_broker_request(&envelope.native_broker)
        .map_err(|error| format!("mixed broker codec: {error:?}"))?;
    if broker.attempt_id != request.attempt_id
        || broker.control_process_id != control_pid
        || broker.control_process_start_time != control_birth
        || descriptors.len() != 7
        || broker.descriptor_manifest != super::launcher::broker_descriptor_manifest()
    {
        return Err("mixed actual broker peer/resource association differs".into());
    }
    let _package = super::service::acquire_shared_package_lease()?;
    crate::package::verify()?;
    let provider = super::runtime_manifest::installed_binding()?;
    super::envelope::verify_live(&broker.caller)?;
    let captured = super::envelope::capture(
        broker.caller.pid,
        broker.caller.uid,
        broker.caller.gid,
        &broker.caller.supplementary_groups,
        descriptors[0].as_fd(),
    )?;
    if captured.envelope != broker.caller
        || !super::envelope::namespace_descriptor_matches(
            descriptors[5].as_fd(),
            broker.caller.mount_namespace_identity,
        )?
        || !super::envelope::descriptor_matches(
            descriptors[6].as_fd(),
            broker.caller.root_identity,
        )?
    {
        return Err("mixed held authenticated caller changed".into());
    }
    let request_digest = envelope.contract.digest()?;
    let attempt = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let started = Instant::now();
    let setup_deadline = started + Duration::from_secs(30);
    let preallocation = (|| {
        let execution_deadline = broker
            .launch
            .policy
            .absolute_deadline_millis
            .map(|absolute| {
                super::clock::monotonic_millis().and_then(|now| {
                    started
                        .checked_add(Duration::from_millis(absolute.saturating_sub(now)))
                        .ok_or("mixed deadline exceeds native range".into())
                })
            })
            .transpose()?;
        if envelope.attempt_deadline_millis.is_some()
            && (broker.launch.policy.deadline_scope != crate::request::DeadlineScope::Attempt
                || execution_deadline.is_some())
        {
            return Err("mixed deadline scope conflicts".into());
        }
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?;
        let frontend = super::private_attempt::ProcessIdentityV4::observe(
            broker.caller.pid,
            descriptors[4].as_fd(),
        )?;
        if frontend.start_time != broker.caller.process_start_time {
            return Err("mixed supplied frontend pidfd birth differs".into());
        }
        let record = super::private_attempt::PrivateAttemptRecordV4::allocated(
            memcordon_core::BoundedText::new(&attempt).map_err(str::to_owned)?,
            memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
            frontend,
            memcordon_core::DiagnosticSha256::from_bytes(captured.envelope.digest()),
        )?;
        let pid = unsafe { libc::getpid() };
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let held = unsafe { OwnedFd::from_raw_fd(raw) };
        let worker = super::private_attempt::ProcessIdentityV4::observe(pid, held.as_fd())?;
        Ok::<_, String>((execution_deadline, record, worker, held))
    })();
    let (mut execution_deadline, record, worker, _held_worker) = match preallocation {
        Ok(value) => value,
        Err(error) => {
            return terminal(
                request,
                MixedRuntimeOutcomeV2::RejectedBeforeAuthorization {
                    request_sha256: request_digest,
                    request_bytes_sha256: envelope.public_request_sha256,
                    detail: rejection_detail(&error),
                    reason: MixedAdmissionRejectionV2::NativeSetupFailed,
                    allocation: outstanding(
                        MixedAuthorizationKnowledgeV2::NeverAuthorized,
                        Vec::new(),
                    ),
                },
            );
        }
    };
    let mut retained_journal = None;
    let mut admission = match MixedOperationalAdmission::authenticate(
        envelope.contract,
        broker.launch,
        captured,
        request.attempt_id,
        |metadata| {
            retained_journal = Some(super::private_attempt::DurablePrivateAttempt::create(
                record,
            )?);
            retained_journal
                .as_mut()
                .expect("original mixed ownership journal retained")
                .attach_mixed_admission_metadata(metadata.clone())?;
            retained_journal
                .as_mut()
                .expect("original mixed ownership journal retained")
                .record_mixed_worker(worker)?;
            Ok(())
        },
    ) {
        Ok(admission) => admission,
        Err(mut failure) => {
            let mut details = Vec::new();
            if let Err(error) = failure.cleanup_before_allocation() {
                details.push(error);
            }
            if failure.reservation_may_remain {
                details.push("exclusive account reservation remains protected for recovery".into());
            }
            if let Some(journal) = retained_journal.take() {
                if details.is_empty() {
                    if let Err(error) = journal.retire_unallocated() {
                        details.push(error);
                    }
                } else {
                    details.push(
                        "original mixed ownership journal remains protected for recovery".into(),
                    );
                }
            }
            return terminal(
                request,
                MixedRuntimeOutcomeV2::RejectedBeforeAuthorization {
                    request_sha256: request_digest,
                    request_bytes_sha256: envelope.public_request_sha256,
                    detail: rejection_detail(&failure.detail),
                    reason: failure.reason,
                    allocation: outstanding(
                        MixedAuthorizationKnowledgeV2::NeverAuthorized,
                        details,
                    ),
                },
            );
        }
    };
    let metadata = admission.metadata().clone();
    let indeterminate = |details: Vec<String>, authorization| {
        terminal(
            request,
            MixedRuntimeOutcomeV2::Indeterminate {
                attempt_id: memcordon_core::BoundedText::new(&attempt).map_err(str::to_owned)?,
                request_sha256: request_digest.clone(),
                retained_obligations: outstanding(authorization, details),
            },
        )
    };
    let journal = retained_journal
        .take()
        .expect("successful mixed admission published original ownership before reservation");
    let mut owner = match PrivateAttemptOwner::new(journal) {
        Ok(owner) => owner,
        Err(error) => {
            return indeterminate(
                vec![
                    error,
                    "protected mixed journal/admission/account requires recovery".into(),
                ],
                MixedAuthorizationKnowledgeV2::NeverAuthorized,
            );
        }
    };
    let mut descriptors = descriptors.into_iter();
    let cwd = descriptors
        .next()
        .expect("validated seven native descriptors");
    let streams = [
        descriptors.next().expect("validated stdin"),
        descriptors.next().expect("validated stdout"),
        descriptors.next().expect("validated stderr"),
    ];
    let frontend = descriptors.next().expect("validated frontend");
    let mount = descriptors.next().expect("validated mount");
    let root = descriptors.next().expect("validated root");
    // Caller cwd/root are authentication inputs only. They cannot reach the
    // namespace child or survive the image-only root transition.
    drop((cwd, mount, root, frontend));
    let mut release = None;
    let mut release_millis = None;
    let mut executed = false;
    let mut origin = MixedOutcomeOriginV2::NativeExit;
    let mut setup_rejection = MixedAdmissionRejectionV2::NativeSetupFailed;
    let setup = (|| -> Result<(), String> {
        owner.create_boundary(
            admission.launch.policy.memory_limit_bytes,
            admission.launch.policy.swap_limit,
        )?;
        let target_identity = admission.identity.clone();
        let prepared = owner.prepare_mixed_launch(&mut admission, request.attempt_id)?;
        use std::os::unix::fs::MetadataExt;
        let network = std::fs::metadata("/proc/self/ns/net").map_err(|error| error.to_string())?;
        let provider_namespace = crate::request::NamespaceIdentity {
            device: network.dev(),
            inode: network.ino(),
        };
        owner.spawn_mixed_namespace(
            prepared.prelaunch,
            prepared.preparation,
            prepared.provider_root_channel,
            admission.caller.envelope.network_namespace_identity,
            provider_namespace,
            admission.launch.policy.lifetime,
            setup_deadline,
        )?;
        let worker_pid = unsafe { libc::getpid() };
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, worker_pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let worker = unsafe { OwnedFd::from_raw_fd(raw) };
        owner.start_guardian(
            request.attempt_id,
            admission.frontend_pidfd.as_fd(),
            worker.as_fd(),
            setup_deadline,
        )?;
        let observed = owner.observe_gated_target(
            admission.caller.envelope.network_namespace_identity,
            provider_namespace,
            &target_identity,
            prepared.abi,
            prepared.filter,
            setup_deadline,
        )?;
        owner.capture_mixed_gated_facts(&admission, &observed)?;
        owner.prepare_relay(streams)?;
        owner.prepare_operational_release(&observed)?;
        let observation = owner.mixed_prepared_observation(&admission, provider.clone())?;
        let frame = Frame {
            kind: MessageKind::MixedPreparedObservation,
            nonce: request.nonce,
            attempt_id: request.attempt_id,
            payload: serde_json::to_vec(&observation).map_err(|error| error.to_string())?,
        };
        crate::protocol::write_frame(&mut &*stream, &frame).map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(
                setup_deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1)),
            ))
            .map_err(|error| error.to_string())?;
        let acknowledged = super::transport::receive_public(stream);
        let restore = stream
            .set_read_timeout(None)
            .map_err(|error| error.to_string());
        let (ack, ack_fds, version) = acknowledged?;
        restore?;
        if version != crate::protocol::MIXED_PROTOCOL_VERSION
            || ack.kind != MessageKind::MixedPreparedAck
            || ack.nonce != request.nonce
            || ack.attempt_id != request.attempt_id
            || !ack.payload.is_empty()
            || !ack_fds.is_empty()
        {
            return Err("mixed observation barrier acknowledgement association differs".into());
        }
        if super::private_runtime::cancellation_requested(stream)? {
            origin = MixedOutcomeOriginV2::ControlledCancellation;
            return Err("mixed cancelled before native release".into());
        }
        let release_observation = memcordon_core::mixed_observation::MixedReleaseObservationV2 {
            format: "memcordon.mixed-release-observation".into(),
            revision: 2,
            prepared: owner.mixed_prepared_observation(&admission, provider.clone())?,
            authorizes_launch: false,
        };
        release_observation.validate()?;
        crate::protocol::write_frame(
            &mut &*stream,
            &Frame {
                kind: MessageKind::MixedReleaseObservation,
                nonce: request.nonce,
                attempt_id: request.attempt_id,
                payload: serde_json::to_vec(&release_observation)
                    .map_err(|error| error.to_string())?,
            },
        )
        .map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(
                setup_deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1)),
            ))
            .map_err(|error| error.to_string())?;
        let acknowledged = super::transport::receive_public(stream);
        let restore = stream
            .set_read_timeout(None)
            .map_err(|error| error.to_string());
        let (ack, ack_fds, version) = acknowledged?;
        restore?;
        if version != crate::protocol::MIXED_PROTOCOL_VERSION
            || ack.kind != MessageKind::MixedReleaseAck
            || ack.nonce != request.nonce
            || ack.attempt_id != request.attempt_id
            || !ack.payload.is_empty()
            || !ack_fds.is_empty()
        {
            return Err("mixed final policy-check observation acknowledgement differs".into());
        }
        if super::private_runtime::cancellation_requested(stream)? {
            origin = MixedOutcomeOriginV2::ControlledCancellation;
            return Err("mixed cancelled before final policy check".into());
        }
        owner
            .release_mixed(&mut admission, &observed, &mut release, &mut release_millis)
            .map_err(|failure| {
                setup_rejection = failure.reason;
                failure.detail
            })?;
        if let Some(duration) = envelope.attempt_deadline_millis {
            execution_deadline = Some(
                release
                    .ok_or("mixed release instant absent")?
                    .checked_add(Duration::from_millis(duration))
                    .ok_or("mixed release deadline exceeds native range")?,
            );
        }
        match owner.observe_exec(
            execution_deadline.map_or(setup_deadline, |deadline| deadline.min(setup_deadline)),
        )? {
            PrivateExecObservation::ExecObservedAndDetached => executed = true,
            PrivateExecObservation::Failed { phase, detail } => {
                return Err(format!("mixed native exec phase {phase}: {detail}"));
            }
        }
        origin = match owner.monitor_mixed(&mut admission, execution_deadline, stream)? {
            PrivateMonitorOutcome::Completed => MixedOutcomeOriginV2::NativeExit,
            PrivateMonitorOutcome::DeadlineExceeded => MixedOutcomeOriginV2::Deadline,
            PrivateMonitorOutcome::MemoryOom => MixedOutcomeOriginV2::MemoryOom,
            PrivateMonitorOutcome::ControlledCancellation => {
                MixedOutcomeOriginV2::ControlledCancellation
            }
            PrivateMonitorOutcome::FrontendLost => MixedOutcomeOriginV2::FrontendLost,
            PrivateMonitorOutcome::Revoked => MixedOutcomeOriginV2::Revoked,
        };
        Ok(())
    })();
    let cleanup_budget =
        Duration::from_millis(admission.launch.policy.limit_grace_millis.max(5000));
    let authorization = if release.is_some() {
        MixedAuthorizationKnowledgeV2::Authorized
    } else if owner.possibly_released() {
        MixedAuthorizationKnowledgeV2::Unknown
    } else {
        MixedAuthorizationKnowledgeV2::NeverAuthorized
    };
    if !owner.has_mixed_root()
        && matches!(
            authorization,
            MixedAuthorizationKnowledgeV2::NeverAuthorized
        )
    {
        return match owner
            .retire_mixed_unreleased_without_root(&mut admission, Instant::now() + cleanup_budget)
        {
            Ok(()) => terminal(
                request,
                MixedRuntimeOutcomeV2::RejectedBeforeAuthorization {
                    request_sha256: request_digest,
                    request_bytes_sha256: envelope.public_request_sha256,
                    detail: rejection_detail(
                        setup
                            .as_ref()
                            .err()
                            .map_or("native target was not authorized", String::as_str),
                    ),
                    reason: if matches!(origin, MixedOutcomeOriginV2::ControlledCancellation) {
                        MixedAdmissionRejectionV2::ControlledCancellation
                    } else {
                        setup_rejection
                    },
                    allocation: outstanding(
                        MixedAuthorizationKnowledgeV2::NeverAuthorized,
                        Vec::new(),
                    ),
                },
            ),
            Err(error) => indeterminate(
                setup.err().into_iter().chain([error]).collect(),
                MixedAuthorizationKnowledgeV2::NeverAuthorized,
            ),
        };
    }
    let cleanup = owner.retire_mixed(&mut admission, Instant::now() + cleanup_budget);
    match (setup, cleanup) {
        (Err(error), Ok(_))
            if matches!(
                authorization,
                MixedAuthorizationKnowledgeV2::NeverAuthorized
            ) =>
        {
            terminal(
                request,
                MixedRuntimeOutcomeV2::RejectedBeforeAuthorization {
                    request_sha256: request_digest,
                    request_bytes_sha256: envelope.public_request_sha256,
                    detail: rejection_detail(&error),
                    reason: if matches!(origin, MixedOutcomeOriginV2::ControlledCancellation) {
                        MixedAdmissionRejectionV2::ControlledCancellation
                    } else {
                        setup_rejection
                    },
                    allocation: outstanding(
                        MixedAuthorizationKnowledgeV2::NeverAuthorized,
                        Vec::new(),
                    ),
                },
            )
        }
        (Ok(()), Ok(retired)) if executed => {
            if retired
                .native
                .native_wait_status()
                .is_some_and(|status| libc::WIFSIGNALED(status))
                && matches!(origin, MixedOutcomeOriginV2::NativeExit)
            {
                origin = MixedOutcomeOriginV2::NativeSignal;
            }
            let execution = owner.mixed_execution_after_retirement(
                &admission,
                &retired,
                origin,
                release_millis.ok_or("mixed native release clock absent")?,
            )?;
            terminal(
                request,
                MixedRuntimeOutcomeV2::Executed {
                    admission: metadata,
                    request_bytes_sha256: envelope.public_request_sha256,
                    provider,
                    execution,
                    retirement: retired.retirement,
                },
            )
        }
        (setup, cleanup) => {
            let mut details = Vec::new();
            if let Err(error) = setup {
                details.push(error);
            }
            if let Err(error) = cleanup {
                details.push(error);
            }
            if details.is_empty() {
                details.push("native mixed execution was not observed".into());
            }
            indeterminate(details, authorization)
        }
    }
}
