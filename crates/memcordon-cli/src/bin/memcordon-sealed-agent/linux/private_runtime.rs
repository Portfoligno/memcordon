//! Normal installed private network launcher. Authentication, local grants,
//! native ownership and retirement are checked on every invocation.

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use memcordon_core::private_runtime::{PrivateRuntimeRequest, PrivateRuntimeTerminal};
use memcordon_core::result_v1::{CleanupStateV1, LaunchStateV1, OutcomeKindV1};
use serde::{Deserialize, Serialize};

use crate::protocol::{Frame, MessageKind};
use crate::request::{
    NativePrivateLaunchInput, decode_launch_broker_request, decode_launch_request,
    encode_launch_broker_request,
};

use super::operational_admission::OperationalAdmission;
use super::private_attempt::{DurablePrivateAttempt, PrivateAttemptRecordV4};
use super::private_lifecycle::{
    PrivateAttemptOwner, PrivateExecObservation, PrivateMonitorOutcome,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateBrokerEnvelope {
    format: String,
    revision: u32,
    contract: memcordon_core::workload_contract::WorkloadContractV2,
    native_broker: Vec<u8>,
    public_request_sha256: memcordon_core::DiagnosticSha256,
    attempt_deadline_millis: Option<u64>,
}

pub(super) fn discovery(
    request: &Frame,
    descriptor_count: usize,
    uid: u32,
) -> Result<Frame, String> {
    use memcordon_core::workload_discovery_v2::{
        PrivateWorkloadDiscovery, ProfilePackageStateV2, ProviderProfileStateV2,
    };
    use memcordon_core::workload_registry_v2::ProfileKindV2;
    if descriptor_count != 0 || request.attempt_id != [0; 16] || !request.payload.is_empty() {
        return Err("private discovery cannot carry attempt resources".into());
    }
    let _package = super::service::acquire_shared_package_lease()?;
    let provider = super::runtime_manifest::installed_binding()?;
    let package_valid = crate::package::verify().is_ok();
    let private_supported = cfg!(feature = "private-tcp")
        && cfg!(target_env = "gnu")
        && matches!(std::env::consts::ARCH, "x86_64" | "aarch64");
    let private_enabled =
        private_supported && package_valid && super::launcher::check_network_endpoint().is_ok();
    let states = [
        ProviderProfileStateV2 {
            profile: ProfileKindV2::LinuxUnixCreateV1,
            supported: true,
            package_state: if package_valid {
                ProfilePackageStateV2::InstalledEnabled
            } else {
                ProfilePackageStateV2::Unavailable
            },
        },
        ProviderProfileStateV2 {
            profile: ProfileKindV2::LinuxTcp4PrivateV1,
            supported: private_supported,
            package_state: if private_enabled {
                ProfilePackageStateV2::InstalledEnabled
            } else if package_valid {
                ProfilePackageStateV2::InstalledDisabled
            } else {
                ProfilePackageStateV2::Unavailable
            },
        },
    ];
    let lease = crate::policy_registry::native::Lease::acquire()?;
    let activation = lease.read_v2()?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    let value = PrivateWorkloadDiscovery::authenticated(
        activation
            .as_ref()
            .map(|value| (&value.registry, &value.epoch)),
        &memcordon_core::workload_registry::CallerSelector::Linux { uid },
        &states,
        provider,
        memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
    )?;
    Ok(Frame {
        kind: MessageKind::PrivateDiscoveryReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&value).map_err(|error| error.to_string())?,
    })
}

pub(super) fn plan(request: &Frame, descriptor_count: usize, uid: u32) -> Result<Frame, String> {
    use memcordon_core::workload_registry_v2::{
        AdmissionCodeV2, AdmissionRejectionV2, ProfileKindV2, resolve_v2,
    };
    if descriptor_count != 0 || request.attempt_id != [0; 16] {
        return Err(
            "MCSEALED-PRIVATE-PLAN: advisory request must carry no native resources".into(),
        );
    }
    let contract =
        match memcordon_core::workload_contract::WorkloadContract::parse(&request.payload)? {
            memcordon_core::workload_contract::WorkloadContract::V2(value) => value,
            _ => return Err("MCSEALED-PRIVATE-PLAN: exact V2 request required".into()),
        };
    let provider = super::runtime_manifest::installed_binding()?;
    let resolved = (|| -> Result<(), AdmissionRejectionV2> {
        let unavailable =
            || AdmissionRejectionV2::single(AdmissionCodeV2::HostPrerequisiteUnavailable);
        if !cfg!(feature = "private-tcp") || !cfg!(target_env = "gnu") {
            return Err(unavailable());
        }
        let lease = crate::policy_registry::native::Lease::acquire().map_err(|_| unavailable())?;
        let activation = lease
            .read_v2()
            .map_err(|_| unavailable())?
            .ok_or_else(|| AdmissionRejectionV2::single(AdmissionCodeV2::ProfileNotAuthorized))?;
        resolve_v2(
            &activation.registry,
            &activation.epoch,
            &contract,
            &memcordon_core::workload_registry::CallerSelector::Linux { uid },
            ProfileKindV2::LinuxTcp4PrivateV1,
        )?;
        drop(lease);
        crate::package::verify().map_err(|_| unavailable())?;
        super::launcher::check_network_endpoint().map_err(|_| unavailable())?;
        Ok(())
    })();
    let value = memcordon_core::private_runtime::PrivateRuntimePlan {
        format: "memcordon.private-runtime-plan".into(),
        revision: 1,
        provider,
        request_sha256: memcordon_core::workload_codec::contract_digest_v2(&contract)?,
        request: contract,
        available_for_preparation: resolved.is_ok(),
        conflicts: resolved.err(),
        pending: [
            "authenticate-live-caller",
            "pin-native-entrypoint",
            "reserve-target-account",
            "allocate-native-boundary",
            "observe-private-topology",
            "check-target-credentials-and-filter",
            "recheck-local-epoch-and-revoke",
            "observe-exec-event-and-detach",
            "retire-all-native-resources",
        ]
        .iter()
        .map(|value| (*value).to_owned())
        .collect(),
        authorizes_launch: false,
    };
    value.validate()?;
    Ok(Frame {
        kind: MessageKind::PrivatePlanReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&value).map_err(|error| error.to_string())?,
    })
}

pub(super) fn forward_public(
    frontend_stream: &std::os::unix::net::UnixStream,
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    pid: i32,
    uid: u32,
    gid: u32,
    groups: &[u32],
) -> Result<Frame, String> {
    if !cfg!(feature = "private-tcp") || descriptors.len() != 5 || request.attempt_id == [0; 16] {
        return Err(
            "MCSEALED-PRIVATE-INGRESS: selected runtime and exact public resources required".into(),
        );
    }
    let _package = super::service::acquire_shared_package_lease()?;
    let public = PrivateRuntimeRequest::parse(&request.payload)?;
    let launch = decode_launch_request(&public.native_launch)
        .map_err(|error| format!("private launch codec: {error:?}"))?;
    if launch.workload_contract.is_some()
        || launch.descriptors != super::launcher::broker_descriptor_manifest()[..5]
    {
        return Err("MCSEALED-PRIVATE-INGRESS: mixed contract or descriptor inventory".into());
    }
    let captured = super::envelope::capture(pid, uid, gid, groups, descriptors[0].as_fd())?;
    let frontend = super::private_attempt::ProcessIdentityV4::observe(pid, descriptors[4].as_fd())?;
    if frontend.start_time != captured.envelope.process_start_time {
        return Err("MCSEALED-PRIVATE-INGRESS: frontend lifetime handle differs".into());
    }
    let control_pid = unsafe { libc::getpid() };
    let (broker, public_request_sha256) =
        crate::request::LaunchBrokerRequestV2::authenticated_private(
            request.attempt_id,
            &request.payload,
            control_pid,
            super::envelope::process_start_time(control_pid)?,
            launch,
            captured.envelope,
            super::launcher::broker_descriptor_manifest(),
        )
        .map_err(|error| format!("private native broker binding: {error:?}"))?;
    let envelope = PrivateBrokerEnvelope {
        format: "memcordon.private-runtime-broker".into(),
        revision: 2,
        contract: public.contract,
        attempt_deadline_millis: public.attempt_deadline_millis,
        public_request_sha256,
        native_broker: encode_launch_broker_request(&broker)
            .map_err(|error| format!("private native broker codec: {error:?}"))?,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
    if bytes.len() > memcordon_core::workload_limits::CONTRACT_ENVELOPE_BYTES {
        return Err("MCSEALED-PRIVATE-INGRESS: broker envelope exceeds bound".into());
    }
    let fds = descriptors
        .iter()
        .map(AsRawFd::as_raw_fd)
        .chain([
            captured.mount_namespace.as_raw_fd(),
            captured.root.as_raw_fd(),
        ])
        .collect::<Vec<_>>();
    super::launcher::forward_private(frontend_stream, request, bytes, &fds)
}

pub(super) fn execute_brokered(
    broker_stream: &std::os::unix::net::UnixStream,
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    control_pid: i32,
    control_birth: u64,
) -> Result<Frame, String> {
    if !cfg!(feature = "private-tcp")
        || request.payload.len() > memcordon_core::workload_limits::CONTRACT_ENVELOPE_BYTES
    {
        return Err(
            "MCSEALED-PRIVATE-BROKER: private runtime unavailable or oversized envelope".into(),
        );
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&request.payload)?;
    let envelope: PrivateBrokerEnvelope =
        serde_json::from_slice(&request.payload).map_err(|error| error.to_string())?;
    if envelope.format != "memcordon.private-runtime-broker" || envelope.revision != 2 {
        return Err("MCSEALED-PRIVATE-BROKER: unsupported named envelope".into());
    }
    let broker = decode_launch_broker_request(&envelope.native_broker)
        .map_err(|error| format!("private broker codec: {error:?}"))?;
    if broker.attempt_id != request.attempt_id
        || broker.control_process_id != control_pid
        || broker.control_process_start_time != control_birth
        || descriptors.len() != 7
        || broker.descriptor_manifest != super::launcher::broker_descriptor_manifest()
    {
        return Err(
            "MCSEALED-PRIVATE-BROKER: actual control peer/frame/resources association differs"
                .into(),
        );
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
        return Err("MCSEALED-PRIVATE-BROKER: held authenticated caller context changed".into());
    }
    let input = NativePrivateLaunchInput {
        contract: envelope.contract,
        launch: broker.launch,
    };
    let started = Instant::now();
    if let Some(duration) = envelope.attempt_deadline_millis {
        let total = Duration::from_millis(duration)
            .checked_add(Duration::from_secs(30))
            .ok_or("MCSEALED-PRIVATE-DEADLINE: attempt setup budget exceeds native range")?;
        started.checked_add(total).ok_or(
            "MCSEALED-PRIVATE-DEADLINE: attempt deadline exceeds native range before allocation",
        )?;
    }
    if envelope.attempt_deadline_millis.is_some()
        && (input.launch.policy.deadline_scope != crate::request::DeadlineScope::Attempt
            || input.launch.policy.absolute_deadline_millis.is_some())
    {
        return Err("MCSEALED-PRIVATE-DEADLINE: attempt duration conflicts with absolute supervision deadline".into());
    }
    if input.launch.policy.deadline_scope == crate::request::DeadlineScope::Attempt
        && input.launch.policy.absolute_deadline_millis.is_some()
    {
        return Err(
            "MCSEALED-PRIVATE-DEADLINE: attempt timer requires explicit release-started duration"
                .into(),
        );
    }
    let mut execution_deadline = input
        .launch
        .policy
        .absolute_deadline_millis
        .map(|absolute| {
            super::clock::monotonic_millis()
                .map(|now| started + Duration::from_millis(absolute.saturating_sub(now)))
        })
        .transpose()?;
    if execution_deadline.is_some_and(|deadline| deadline <= started) {
        return Err(
            "MCSEALED-PRIVATE-DEADLINE: invocation budget expired before allocation".into(),
        );
    }
    let setup_deadline = execution_deadline.map_or(started + Duration::from_secs(30), |deadline| {
        deadline.min(started + Duration::from_secs(30))
    });
    let cleanup_budget = Duration::from_millis(input.launch.policy.limit_grace_millis.max(5_000));
    let rejection_contract = input.contract.clone();
    let rejection_invocation = memcordon_core::workload_codec::hash_bytes(
        &crate::request::encode_launch_request(&input.launch)
            .map_err(|error| format!("private native invocation codec: {error:?}"))?,
    );
    let mut admission =
        match OperationalAdmission::authenticate(input, captured, request.attempt_id) {
            Ok(admission) => admission,
            Err(failure) => {
                let rejection = memcordon_core::private_runtime::PrivateRuntimeRejection {
                    format: "memcordon.private-runtime-rejection".into(),
                    revision: 1,
                    provider,
                    attempt_id: request.attempt_id,
                    request_sha256: envelope.public_request_sha256.clone(),
                    invocation_sha256: rejection_invocation,
                    contract: rejection_contract,
                    boundary_allocated: false,
                    reservation_may_remain: failure.reservation_may_remain,
                    detail: memcordon_core::BoundedText::new(if failure.detail.len() <= 4096 {
                        &failure.detail
                    } else {
                        "private preallocation rejection exceeded diagnostic bound"
                    })
                    .map_err(str::to_owned)?,
                };
                rejection.validate()?;
                return Ok(Frame {
                    kind: MessageKind::PrivateRejected,
                    nonce: request.nonce,
                    attempt_id: request.attempt_id,
                    payload: serde_json::to_vec(&rejection).map_err(|error| error.to_string())?,
                });
            }
        };
    let metadata = admission.metadata()?;
    let identity = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    let record = PrivateAttemptRecordV4::allocated(
        memcordon_core::BoundedText::new(&identity).map_err(str::to_owned)?,
        memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
        admission.frontend.clone(),
        memcordon_core::DiagnosticSha256::from_bytes(admission.caller.envelope.digest()),
    )?;
    let mut journal = DurablePrivateAttempt::create(record)?;
    journal.attach_admission_metadata(metadata.clone())?;
    let mut owner = PrivateAttemptOwner::new(journal)?;
    let mut state = LaunchStateV1::NotCreated;
    let mut release_observed = None;
    let mut release_monotonic_millis = None;
    let mut target_pid = None;
    let mut network_namespace = None;
    let mut exec_observed = false;
    let mut outcome = OutcomeKindV1::LaunchFailure;
    let mut fds = descriptors.into_iter();
    let cwd = fds.next().ok_or("private caller cwd absent")?;
    let streams = [
        fds.next().ok_or("private stdin absent")?,
        fds.next().ok_or("private stdout absent")?,
        fds.next().ok_or("private stderr absent")?,
    ];
    let supplied_frontend = fds.next().ok_or("private frontend pidfd absent")?;
    let mount = fds.next().ok_or("private caller mount absent")?;
    let root = fds.next().ok_or("private caller root absent")?;
    if super::private_attempt::ProcessIdentityV4::observe(
        admission.caller.envelope.pid,
        supplied_frontend.as_fd(),
    )? != admission.frontend
    {
        return Err("MCSEALED-PRIVATE-BROKER: supplied frontend pidfd differs".into());
    }
    let setup = (|| -> Result<(), String> {
        let abi = match (std::env::consts::ARCH, cfg!(target_env = "gnu")) {
            ("x86_64", true) => super::network_filter::NativeAbi::X86_64,
            ("aarch64", true) => super::network_filter::NativeAbi::Aarch64,
            _ => return Err("MCSEALED-PRIVATE-ABI: native GNU target required".into()),
        };
        let filter = super::network_filter::filter_instruction_digest(
            &super::network_filter::compile_initial_closed_filter(abi),
        )
        .map_err(str::to_owned)?;
        let prelaunch = admission.take_prelaunch()?;
        let target_identity = prelaunch.target_identity().clone();
        let prelaunch = super::launch::prepare_private_gated_prelaunch(
            prelaunch,
            &admission.input,
            abi,
            filter,
        )?;
        owner.create_boundary(
            admission.input.launch.policy.memory_limit_bytes,
            admission.input.launch.policy.swap_limit,
        )?;
        state = LaunchStateV1::Unknown;
        let net = std::fs::metadata("/proc/self/ns/net").map_err(|error| error.to_string())?;
        use std::os::unix::fs::MetadataExt;
        let provider_network = crate::request::NamespaceIdentity {
            device: net.dev(),
            inode: net.ino(),
        };
        owner.spawn_namespace(
            prelaunch,
            super::namespace::CallerMountContext {
                mount_namespace: mount,
                root,
                mount_namespace_identity: admission.caller.envelope.mount_namespace_identity,
                root_identity: admission.caller.envelope.root_identity,
            },
            cwd,
            admission.caller.envelope.network_namespace_identity,
            provider_network,
            admission.input.launch.policy.lifetime,
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
            provider_network,
            &target_identity,
            abi,
            filter,
            setup_deadline,
        )?;
        target_pid = std::num::NonZeroU32::new(observed.target_identity().pid);
        let namespace = observed.network_namespace_identity();
        network_namespace = Some(
            memcordon_core::private_runtime::PrivateNetworkNamespaceIdentity {
                device: namespace.device,
                inode: namespace.inode,
            },
        );
        state = LaunchStateV1::GatedUnreleased;
        owner.prepare_relay(streams)?;
        owner.prepare_operational_release(&observed)?;
        if cancellation_requested(broker_stream)? {
            outcome = OutcomeKindV1::Interrupted;
            return Err("MCSEALED-PRIVATE-CANCELLED: frontend cancelled before release".into());
        }
        let release = owner.release_operational(
            &mut admission,
            &observed,
            &mut release_observed,
            &mut release_monotonic_millis,
        );
        if release_observed.is_some() {
            state = LaunchStateV1::ReleaseIssued;
        }
        release?;
        if let Some(duration) = envelope.attempt_deadline_millis {
            execution_deadline = Some(
                release_observed
                    .ok_or("MCSEALED-PRIVATE-DEADLINE: successful release has no native instant")?
                    .checked_add(Duration::from_millis(duration))
                    .ok_or(
                        "MCSEALED-PRIVATE-DEADLINE: released attempt deadline exceeds native range",
                    )?,
            );
        }
        let exec_deadline =
            execution_deadline.map_or(setup_deadline, |deadline| deadline.min(setup_deadline));
        if execution_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            outcome = OutcomeKindV1::Deadline;
            return Ok(());
        }
        match owner.observe_exec(exec_deadline) {
            Ok(PrivateExecObservation::ExecObservedAndDetached) => {
                exec_observed = true;
                state = LaunchStateV1::ExecObserved;
                outcome = OutcomeKindV1::ProviderFailure;
            }
            Ok(PrivateExecObservation::Failed { phase, detail }) => {
                state = LaunchStateV1::ExecFailed;
                if execution_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    outcome = OutcomeKindV1::Deadline;
                }
                return Err(format!("MCSEALED-PRIVATE-EXEC: phase {phase}: {detail}"));
            }
            Err(error) => {
                if execution_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    outcome = OutcomeKindV1::Deadline;
                }
                return Err(error);
            }
        }
        outcome =
            match owner.monitor_operational(&mut admission, execution_deadline, broker_stream)? {
                PrivateMonitorOutcome::Completed => OutcomeKindV1::Completed,
                PrivateMonitorOutcome::DeadlineExceeded => OutcomeKindV1::Deadline,
                PrivateMonitorOutcome::MemoryOom => OutcomeKindV1::ConfirmedMemoryLimit,
                PrivateMonitorOutcome::ControlledCancellation
                | PrivateMonitorOutcome::FrontendLost
                | PrivateMonitorOutcome::Revoked => OutcomeKindV1::Interrupted,
            };
        Ok(())
    })();
    let cleanup_deadline = execution_deadline.map_or_else(
        || Instant::now() + cleanup_budget,
        |deadline| {
            if deadline > Instant::now() {
                Instant::now() + cleanup_budget
            } else {
                deadline + cleanup_budget
            }
        },
    );
    let retired = owner.retire(cleanup_deadline);
    let mut errors = setup.err().into_iter().collect::<Vec<_>>();
    let mut native_termination = None;
    let mut cleanup = CleanupStateV1::Incomplete;
    let mut account_retired = false;
    let mut namespace_closed = false;
    match retired {
        Ok(retired) => {
            namespace_closed = true;
            native_termination = retired.native_wait_status().and_then(|raw| {
                if libc::WIFEXITED(raw) {
                    Some(memcordon_core::ChildTermination::ExitCode {
                        code: libc::WEXITSTATUS(raw),
                    })
                } else if libc::WIFSIGNALED(raw) {
                    Some(memcordon_core::ChildTermination::UnixSignal {
                        signal: libc::WTERMSIG(raw),
                    })
                } else {
                    None
                }
            });
            match admission.retire_account(&retired) {
                Ok(()) => {
                    account_retired = true;
                    cleanup = CleanupStateV1::Complete;
                }
                Err(error) => errors.push(error),
            }
        }
        Err(error) => errors.push(error),
    }
    if !errors.is_empty() && outcome == OutcomeKindV1::Completed {
        outcome = OutcomeKindV1::ProviderFailure;
    }
    let error = if errors.is_empty() {
        None
    } else {
        let detail = errors.join("; ");
        Some(
            memcordon_core::BoundedText::new(if detail.len() <= 4096 {
                &detail
            } else {
                "private runtime failure detail exceeded diagnostic bound"
            })
            .map_err(str::to_owned)?,
        )
    };
    let terminal = PrivateRuntimeTerminal {
        format: "memcordon.private-runtime-terminal".into(),
        revision: 1,
        provider,
        native_abi: match std::env::consts::ARCH {
            "x86_64" => "x86_64-unknown-linux-gnu",
            "aarch64" => "aarch64-unknown-linux-gnu",
            _ => return Err("private native ABI unsupported".into()),
        }
        .into(),
        attempt_id: request.attempt_id,
        request_sha256: envelope.public_request_sha256,
        admission_metadata: metadata,
        launch: state,
        authorization_offset_millis: release_observed
            .map(|at| u64::try_from(at.duration_since(started).as_millis()).unwrap_or(u64::MAX)),
        authorization_monotonic_millis: release_monotonic_millis,
        target_pid,
        network_namespace,
        exec_observed,
        post_exec_descriptor_count: exec_observed.then_some(3),
        outcome,
        native_termination,
        cleanup,
        account_reservation_retired: account_retired,
        namespace_references_closed: namespace_closed,
        error,
    };
    terminal.validate()?;
    Ok(Frame {
        kind: MessageKind::PrivateTerminal,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&terminal).map_err(|error| error.to_string())?,
    })
}

pub(super) use super::private_cancellation::cancellation_requested;
