//! Qualified V4 broker transaction. A parsed frame is only a transport
//! envelope; this worker independently rebinds live caller descriptors,
//! installed package authority, frozen V2 policy, and the native attempt.

use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use memcordon_core::workload_admission_v2::AttemptBindingV2;
use memcordon_core::workload_contract::Nonce128;
use memcordon_core::{BoundedText, DiagnosticSha256};
use serde::{Deserialize, Serialize};

use super::envelope;
use super::launch::{pin_private_prelaunch_authority, prepare_private_gated_prelaunch};
use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_attempt::{DurablePrivateAttempt, PrivateAttemptRecordV4, ProcessIdentityV4};
use super::private_lifecycle::{
    PrivateAttemptOwner, PrivateExecObservation, PrivateTerminalReceiptV4,
};
use crate::request::{
    LaunchPolicyV2, NetworkLaunchBrokerRequestV4, encode_network_launch_request,
    network_broker_descriptor_manifest,
};

pub struct PrivateExecutionError {
    detail: String,
    possibly_released: bool,
    cleanup_complete: bool,
    reason_code: &'static str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateBrokerRejectionV4 {
    schema_version: u8,
    attempt_id: String,
    code: String,
    detail: String,
    possibly_released: bool,
    cleanup_complete: bool,
}

impl PrivateExecutionError {
    fn pre_release(detail: String, cleanup_complete: bool) -> Self {
        Self {
            detail,
            possibly_released: false,
            cleanup_complete,
            reason_code: "MCSEALED-NETWORK-LAUNCHER-PRE-RELEASE-REJECTED",
        }
    }

    pub fn code(&self) -> &'static str {
        if self.possibly_released {
            "MCSEALED-NETWORK-LAUNCHER-POSSIBLY-RELEASED"
        } else if !self.cleanup_complete {
            "MCSEALED-NETWORK-LAUNCHER-CLEANUP-INCOMPLETE"
        } else {
            self.reason_code
        }
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn encode(&self, attempt_id: [u8; 16]) -> Result<Vec<u8>, String> {
        let identity = attempt_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        serde_json::to_vec(&PrivateBrokerRejectionV4 {
            schema_version: 4,
            attempt_id: identity,
            code: self.code().into(),
            detail: self.detail.clone(),
            possibly_released: self.possibly_released,
            cleanup_complete: self.cleanup_complete,
        })
        .map_err(|error| error.to_string())
    }
}

pub fn validate_broker_rejection(bytes: &[u8], expected_attempt: [u8; 16]) -> Result<(), String> {
    let rejection: PrivateBrokerRejectionV4 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let identity = expected_attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let expected_code = if rejection.possibly_released {
        "MCSEALED-NETWORK-LAUNCHER-POSSIBLY-RELEASED"
    } else if !rejection.cleanup_complete {
        "MCSEALED-NETWORK-LAUNCHER-CLEANUP-INCOMPLETE"
    } else {
        match rejection.code.as_str() {
            "MCSEALED-NETWORK-LAUNCHER-UNQUALIFIED" => "MCSEALED-NETWORK-LAUNCHER-UNQUALIFIED",
            "MCSEALED-NETWORK-LAUNCHER-NATIVE-FAILURE" => {
                "MCSEALED-NETWORK-LAUNCHER-NATIVE-FAILURE"
            }
            _ => "MCSEALED-NETWORK-LAUNCHER-PRE-RELEASE-REJECTED",
        }
    };
    if rejection.schema_version != 4
        || rejection.attempt_id != identity
        || rejection.detail.is_empty()
        || rejection.code != expected_code
    {
        return Err("MCSEALED-PRIVATE-BROKER: internal rejection binding differs".into());
    }
    Ok(())
}

pub(super) fn validate_reuse_obstruction_rejection(
    bytes: &[u8],
    expected_attempt: [u8; 16],
) -> Result<(), String> {
    validate_broker_rejection(bytes, expected_attempt)?;
    let rejection: PrivateBrokerRejectionV4 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if rejection.code != "MCSEALED-NETWORK-LAUNCHER-POSSIBLY-RELEASED"
        || !rejection.possibly_released
        || rejection.cleanup_complete
        || !rejection
            .detail
            .contains("MCSEALED-PUBLIC-REUSE-HELD-NAMESPACE-FD")
    {
        return Err("MCSEALED-PUBLIC-REUSE: broker obstruction cause differs".into());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn execute_private_broker(
    broker: NetworkLaunchBrokerRequestV4,
    descriptors: Vec<OwnedFd>,
    frame_nonce: [u8; 16],
) -> Result<Vec<u8>, PrivateExecutionError> {
    let fail = |error: String| PrivateExecutionError::pre_release(error, true);
    if broker.descriptor_manifest != network_broker_descriptor_manifest()
        || descriptors.len() != broker.descriptor_manifest.len()
    {
        return Err(fail(
            "MCSEALED-PRIVATE-BROKER: descriptor manifest differs".into(),
        ));
    }
    let [
        cwd,
        stdin,
        stdout,
        stderr,
        frontend_pidfd,
        mount_namespace,
        root,
        untrusted_elf,
    ]: [OwnedFd; 8] = descriptors
        .try_into()
        .map_err(|_| fail("MCSEALED-PRIVATE-BROKER: exact eight descriptors required".into()))?;
    // The transport carries this historical purpose, but no consumer-held ELF
    // descriptor can become execution authority. The provider pins its own
    // approved object under the authenticated caller root below.
    drop(untrusted_elf);
    let caller = broker.caller;
    let frontend = ProcessIdentityV4::observe(caller.pid, frontend_pidfd.as_fd()).map_err(fail)?;
    if frontend.start_time != caller.process_start_time {
        return Err(fail(
            "MCSEALED-PRIVATE-BROKER: frontend start identity changed".into(),
        ));
    }
    envelope::verify_live(&caller).map_err(fail)?;
    if !envelope::descriptor_matches(cwd.as_fd(), caller.current_directory_identity)
        .map_err(fail)?
        || !envelope::namespace_descriptor_matches(
            mount_namespace.as_fd(),
            caller.mount_namespace_identity,
        )
        .map_err(fail)?
        || !envelope::descriptor_matches(root.as_fd(), caller.root_identity).map_err(fail)?
    {
        return Err(fail(
            "MCSEALED-PRIVATE-BROKER: caller descriptor identity differs".into(),
        ));
    }
    if ProcessIdentityV4::observe(caller.pid, frontend_pidfd.as_fd()).map_err(fail)? != frontend {
        return Err(fail(
            "MCSEALED-PRIVATE-BROKER: frontend changed during capture".into(),
        ));
    }
    let installed =
        crate::package::acquire_verified_private_qualification_lease().map_err(|detail| {
            PrivateExecutionError {
                detail,
                possibly_released: false,
                cleanup_complete: true,
                reason_code: "MCSEALED-NETWORK-LAUNCHER-UNQUALIFIED",
            }
        })?;
    let installed_generation_digest = installed.generation_digest().clone();
    let installed_qualification_digest = installed.qualification_digest().clone();
    if broker.installed_generation_digest != installed_generation_digest {
        return Err(fail(
            "MCSEALED-PRIVATE-BROKER: installed generation differs from authenticated control request"
                .into(),
        ));
    }
    let launch = broker.launch;
    let invocation = encode_network_launch_request(&launch).map_err(|error| {
        fail(format!(
            "MCSEALED-PRIVATE-BROKER: invocation encoding: {error:?}"
        ))
    })?;
    let (admission, policy_lease) = crate::admission::plan_linux_v2(
        &launch.contract,
        caller.uid,
        Nonce128(frame_nonce),
        DiagnosticSha256::from_bytes(caller.digest()),
        memcordon_core::workload_codec::hash_bytes(&invocation),
        &installed,
    )
    .map_err(|error| {
        fail(format!(
            "MCSEALED-PRIVATE-BROKER: V2 admission: {:?}",
            error.code
        ))
    })?;
    if launch.registry_digest != admission.registry_digest
        || launch.qualification_digest != admission.qualification_digest
        || admission.package_generation_digest != installed_generation_digest
    {
        return Err(fail(
            "MCSEALED-PRIVATE-BROKER: public request and frozen authority differ".into(),
        ));
    }
    let provider_uid = unsafe { libc::getuid() };
    let guardian_uid = unsafe { libc::geteuid() };
    let pinned = pin_private_prelaunch_authority(
        &launch,
        Some(&admission.identity),
        &caller,
        root.as_fd(),
        provider_uid,
        guardian_uid,
    )
    .map_err(fail)?;
    let target_identity = pinned.target_identity().clone();
    let prelaunch = prepare_private_gated_prelaunch(
        pinned,
        &launch,
        installed.filter_abi(),
        *installed.filter_digest().bytes(),
    )
    .map_err(fail)?;
    let attempt_deadline = attempt_deadline(&launch.launch.policy)?;
    let startup_deadline = short_deadline(attempt_deadline)?;
    let provider_namespace = current_network_namespace().map_err(fail)?;
    let worker_pidfd = pidfd_for_self().map_err(fail)?;
    let attempt_id = broker.attempt_id;
    let identity = attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| fail(error.to_string()))?;
    let allocated = PrivateAttemptRecordV4::allocated(
        BoundedText::new(&identity).map_err(|error| fail(error.to_owned()))?,
        BoundedText::new(boot.trim()).map_err(|error| fail(error.to_owned()))?,
        frontend,
        DiagnosticSha256::from_bytes(caller.digest()),
    )
    .map_err(fail)?;
    let attempt_binding =
        AttemptBindingV2::from_admission(allocated.attempt_id.clone(), &admission).map_err(fail)?;
    let mut record = DurablePrivateAttempt::create(allocated)
        .map_err(|error| PrivateExecutionError::pre_release(error, false))?;
    if let Err(error) = record.freeze_authority(admission) {
        let cleanup_complete = record.retire_unallocated().is_ok();
        return Err(PrivateExecutionError::pre_release(error, cleanup_complete));
    }
    drop(policy_lease);
    let mut owner = match PrivateAttemptOwner::new(record) {
        Ok(owner) => owner,
        Err(error) => return Err(PrivateExecutionError::pre_release(error, false)),
    };
    let mount_context = CallerMountContext {
        mount_namespace,
        root,
        mount_namespace_identity: caller.mount_namespace_identity,
        root_identity: caller.root_identity,
    };
    let run = (|| -> Result<_, String> {
        owner.create_boundary(
            launch.launch.policy.memory_limit_bytes,
            launch.launch.policy.swap_limit,
        )?;
        owner.spawn_namespace(
            prelaunch,
            mount_context,
            cwd,
            caller.network_namespace_identity,
            provider_namespace,
        )?;
        owner.start_guardian(
            attempt_id,
            frontend_pidfd.as_fd(),
            worker_pidfd.as_fd(),
            startup_deadline,
        )?;
        let observed = owner.observe_gated_target(
            caller.network_namespace_identity,
            provider_namespace,
            &target_identity,
            installed.filter_abi(),
            *installed.filter_digest().bytes(),
            startup_deadline,
        )?;
        owner.prepare_relay([stdin, stdout, stderr])?;
        let checkpoint = owner.commit_and_release(observed, &installed)?;
        drop(installed);
        let exec = owner.observe_exec(startup_deadline)?;
        let monitor = if matches!(exec, PrivateExecObservation::ArmedAndControlClosed) {
            Some(owner.monitor(frontend_pidfd.as_fd(), attempt_deadline)?)
        } else {
            None
        };
        Ok((checkpoint, exec, monitor))
    })();
    let retirement_deadline = Instant::now() + Duration::from_secs(30);
    match run {
        Ok((checkpoint, exec, monitor)) => {
            let retired =
                owner
                    .retire(retirement_deadline)
                    .map_err(|error| PrivateExecutionError {
                        detail: error,
                        possibly_released: true,
                        cleanup_complete: false,
                        reason_code: "MCSEALED-NETWORK-LAUNCHER-NATIVE-FAILURE",
                    })?;
            PrivateTerminalReceiptV4::observed(
                installed_generation_digest,
                installed_qualification_digest,
                attempt_binding,
                checkpoint,
                exec,
                monitor,
                retired,
            )
            .and_then(|receipt| receipt.encode())
            .map_err(|detail| PrivateExecutionError {
                detail,
                possibly_released: true,
                cleanup_complete: true,
                reason_code: "MCSEALED-NETWORK-LAUNCHER-NATIVE-FAILURE",
            })
        }
        Err(detail) => {
            let possibly_released = owner.possibly_released();
            let cleanup = owner.retire(retirement_deadline);
            let (detail, cleanup_complete) = match cleanup {
                Ok(_) => (detail, true),
                Err(cleanup) => (format!("{detail}; cleanup: {cleanup}"), false),
            };
            Err(PrivateExecutionError {
                detail,
                possibly_released,
                cleanup_complete,
                reason_code: "MCSEALED-NETWORK-LAUNCHER-NATIVE-FAILURE",
            })
        }
    }
}

pub(super) fn pidfd_for_self() -> Result<OwnedFd, String> {
    // SAFETY: getpid names only this one accepted broker worker.
    let pid = unsafe { libc::getpid() };
    // SAFETY: pidfd_open returns an owned descriptor bound to the live worker.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-BROKER: worker pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open returned a unique owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    ProcessIdentityV4::observe(pid, pidfd.as_fd())?;
    Ok(pidfd)
}

fn attempt_deadline(policy: &LaunchPolicyV2) -> Result<Option<Instant>, PrivateExecutionError> {
    let Some(absolute) = policy.absolute_deadline_millis else {
        return Ok(None);
    };
    let now = super::clock::monotonic_millis()
        .map_err(|error| PrivateExecutionError::pre_release(error.to_string(), true))?;
    if now >= absolute {
        return Err(PrivateExecutionError::pre_release(
            "MCSEALED-PRIVATE-BROKER: deadline expired before candidate allocation".into(),
            true,
        ));
    }
    Instant::now()
        .checked_add(Duration::from_millis(absolute - now))
        .map(Some)
        .ok_or_else(|| {
            PrivateExecutionError::pre_release(
                "MCSEALED-PRIVATE-BROKER: deadline overflow".into(),
                true,
            )
        })
}

fn short_deadline(attempt: Option<Instant>) -> Result<Instant, PrivateExecutionError> {
    let normal = Instant::now() + Duration::from_secs(5);
    let deadline = attempt.map_or(normal, |attempt| attempt.min(normal));
    if deadline <= Instant::now() {
        return Err(PrivateExecutionError::pre_release(
            "MCSEALED-PRIVATE-BROKER: startup deadline expired".into(),
            true,
        ));
    }
    Ok(deadline)
}
